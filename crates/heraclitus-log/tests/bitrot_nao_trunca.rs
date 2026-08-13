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
