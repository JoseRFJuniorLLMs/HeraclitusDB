//! Regressão CRÍTICA: bit rot num segmento selado não pode truncar o histórico.

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;

/// PERDA DE DADOS SILENCIOSA + DESTRUIÇÃO DE PROVA (corrigida).
///
/// `Log::open` corria a reparação física em TODOS os segmentos, incluindo os
/// SELADOS. Um único bit invertido (bit rot) a meio de um segmento antigo fazia:
///   1. `set_len(valid_len)` → todos os registos a seguir ao ponto corrompido
///      APAGADOS para sempre (o log é a "fonte única de verdade");
///   2. re-selagem com uma raiz Merkle NOVA, calculada só sobre os sobreviventes
///      → `verify_segment` passava a responder `valid: true`, ou seja, a prova
///      blake3 de adulteração era DESTRUÍDA em vez de reportada;
///   3. uma LACUNA de LSN (o segmento seguinte mantém o seu `base_lsn`), pelo que
///      views reconstruídas do LSN 0 e leituras AS OF viam um histórico com buraco;
///   4. `Log::open` devolvia `Ok(())` — sem erro, sem métrica, sem tracing.
///
/// A cauda torn só é legítima no segmento ATIVO (crash a meio de uma escrita).
/// Num segmento anterior tem de falhar alto e preservar o ficheiro — a mesma
/// política já aplicada ao WAL do raft.
#[test]
fn bitrot_em_segmento_selado_recusa_abrir_em_vez_de_truncar() {
    let dir = tempfile::tempdir().unwrap();

    // Segmentos pequenos → vários selados + um ativo.
    {
        let log = Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
        for i in 0..120 {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("evento {i} {}", "x".repeat(60)).into_bytes(),
            ))
            .unwrap();
        }
        assert!(
            log.sealed_segments().len() >= 2,
            "o teste precisa de segmentos selados"
        );
    }

    // Escolhe um segmento SELADO (não o último) e inverte UM bit no meio.
    let mut segs: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "hrkl").unwrap_or(false))
        .collect();
    segs.sort();
    assert!(segs.len() >= 2, "esperava vários segmentos");
    let alvo = segs[segs.len() / 2].clone(); // um do meio: selado e não-último

    let antes = std::fs::metadata(&alvo).unwrap().len();
    {
        let mut bytes = std::fs::read(&alvo).unwrap();
        let meio = bytes.len() / 2;
        bytes[meio] ^= 0x01; // um único bit
        std::fs::write(&alvo, &bytes).unwrap();
    }

    // Tem de RECUSAR abrir — e não tocar no ficheiro.
    let r = Log::open(dir.path(), 4096, FsyncPolicy::Always);
    assert!(
        r.is_err(),
        "abriu apesar do bit rot num segmento selado (ia truncar o histórico)"
    );
    assert_eq!(
        std::fs::metadata(&alvo).unwrap().len(),
        antes,
        "o segmento corrompido foi truncado — a evidência tem de ser preservada"
    );
}

/// A cauda torn no segmento ATIVO continua a ser recuperada (comportamento
/// legítimo pós-crash): não se pode ter partido a recuperação normal.
#[test]
fn cauda_torn_no_segmento_ativo_continua_a_recuperar() {
    let dir = tempfile::tempdir().unwrap();
    {
        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..10 {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("e{i}").into_bytes(),
            ))
            .unwrap();
        }
    }
    // Acrescenta lixo ao ÚNICO segmento (o ativo): simula um crash a meio da escrita.
    let seg = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "hrkl").unwrap_or(false))
        .unwrap();
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(&[0xAB; 37]).unwrap();
        f.sync_all().unwrap();
    }

    let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always)
        .expect("cauda torn no segmento ativo tem de ser recuperada");
    assert_eq!(log.head(), 10, "os 10 registos bons têm de sobreviver");
}

/// Auditoria 2026-10-16, B1 (o mesmo padrão do HRKL v6): o segmento ATIVO
/// também não pode ser truncado por bit rot. Um bit trocado a 1/3 do único
/// segmento, com os 100 registos confirmados com `fsync = Always`, fazia a
/// abertura cortar tudo a partir do registo estragado e reatribuir os LSN —
/// a guarda acima só valia para os segmentos não-últimos.
#[test]
fn bitrot_no_meio_do_segmento_ativo_recusa_abrir_em_vez_de_truncar() {
    let dir = tempfile::tempdir().unwrap();
    {
        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..100 {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("evento {i} {}", "y".repeat(40)).into_bytes(),
            ))
            .unwrap();
        }
    }
    let seg = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "hrkl").unwrap_or(false))
        .unwrap();
    let antes = std::fs::metadata(&seg).unwrap().len();
    let inverter = || {
        let mut bytes = std::fs::read(&seg).unwrap();
        let alvo = bytes.len() / 3;
        bytes[alvo] ^= 0x01;
        std::fs::write(&seg, &bytes).unwrap();
    };
    inverter();

    match Log::open(dir.path(), 1 << 20, FsyncPolicy::Always) {
        Ok(log) => panic!(
            "abriu com head {} (antes 100): truncou registos confirmados",
            log.head()
        ),
        Err(e) => assert!(e.to_string().contains("Recuso truncar"), "{e}"),
    }
    assert_eq!(
        std::fs::metadata(&seg).unwrap().len(),
        antes,
        "o segmento ativo foi truncado — a evidência tem de ser preservada"
    );

    // Nada se perdeu: desfeita a corrupção, os 100 registos estão lá.
    inverter();
    let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    assert_eq!(log.head(), 100);
}

/// Auditoria 2026-10-16, B1/B5 — o veto do footer, no legado. Quando o último
/// segmento está selado (aqui: o ativo vazio a seguir a ele desapareceu), um
/// bit trocado no comprimento do seu ÚLTIMO registo faz o frame "passar do
/// EOF" como uma escrita interrompida, sem registo nenhum depois. O rodapé no
/// EOF declara esse LSN: o registo estava completo quando o segmento foi
/// selado, e a abertura tem de recusar em vez de o cortar com o rodapé.
#[test]
fn comprimento_estragado_no_ultimo_registo_de_um_selado_recusa_abrir() {
    const HEADER_LEN: usize = 22;
    const RECORD_HEADER_LEN: usize = 24;
    const FOOTER_LEN: usize = 60;
    let dir = tempfile::tempdir().unwrap();
    {
        let log = Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
        for i in 0..120 {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("evento {i} {}", "x".repeat(60)).into_bytes(),
            ))
            .unwrap();
        }
    }
    let mut segs: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "hrkl").unwrap_or(false))
        .collect();
    segs.sort();
    assert!(segs.len() >= 2, "o teste precisa de um segmento selado");
    std::fs::remove_file(segs.pop().unwrap()).unwrap();
    let selado = segs.pop().unwrap();

    // Contraprova: sem a corrupção, um último segmento selado abre.
    let head_selado = Log::open(dir.path(), 4096, FsyncPolicy::Always)
        .expect("ultimo segmento selado tem de abrir")
        .head();
    let segs_depois: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "hrkl").unwrap_or(false) && *p > selado)
        .collect();
    for p in segs_depois {
        std::fs::remove_file(p).unwrap(); // o ativo novo, vazio, que a abertura criou
    }

    let mut bytes = std::fs::read(&selado).unwrap();
    let fim_dos_registos = bytes.len() - FOOTER_LEN;
    let (mut pos, mut ultimo) = (HEADER_LEN, HEADER_LEN);
    while pos < fim_dos_registos {
        ultimo = pos;
        let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += RECORD_HEADER_LEN + len;
    }
    assert_eq!(pos, fim_dos_registos, "setup: percurso dos registos");
    bytes[ultimo + 3] ^= 0x10; // byte alto do comprimento: ~256 MiB, além do EOF
    std::fs::write(&selado, &bytes).unwrap();

    match Log::open(dir.path(), 4096, FsyncPolicy::Always) {
        Ok(log) => panic!(
            "abriu com head {} (antes {head_selado}): cortou o ultimo registo e o rodape",
            log.head()
        ),
        Err(e) => assert!(e.to_string().contains("valid footer at EOF"), "{e}"),
    }
    assert_eq!(
        std::fs::read(&selado).unwrap(),
        bytes,
        "o segmento foi alterado — a evidência tem de ficar intacta"
    );
}
