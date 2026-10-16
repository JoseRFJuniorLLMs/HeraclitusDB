//! Auditoria 2026-10-16 — regressões de B1, B2, B5 e B6 no HRKL v6.
//!
//! Cada teste nasceu de uma sonda da auditoria
//! (`docs/auditoria-2026-10-16-sondas/heraclitus-log_tests_sonda_auditoria_v6.rs`)
//! que PASSAVA enquanto o defeito existia; aqui a asserção está invertida. São o
//! equivalente v6 de `bitrot_nao_trunca.rs` e `crc_nao_e_engolido.rs`, que
//! cobriam só o log legado — e o v6 é o formato por omissão.
//!
//! Só usam API pública que já existia antes da correcção, de propósito: o
//! mesmo ficheiro, posto sobre o código antigo, tem de falhar nos quatro.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusError};
use heraclitus_log::v6::hrki::{IndexPolicy, IndexPolicySet};
use heraclitus_log::v6::{FooterV6, PackingProfile, V6Log};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

fn segmentos_com_sufixo(dir: &Path, sufixo: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir.join("segments"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(sufixo))
        .collect();
    v.sort();
    v
}

fn selados(dir: &Path) -> Vec<PathBuf> {
    segmentos_com_sufixo(dir, ".raw.hrkl")
}

fn activo(dir: &Path) -> PathBuf {
    let mut v = segmentos_com_sufixo(dir, ".active.hrkl");
    assert_eq!(v.len(), 1, "esperava exactamente uma cauda activa");
    v.remove(0)
}

/// Os nomes são `{id:020}.…`.
fn id_do_segmento(path: &Path) -> u64 {
    path.file_name().unwrap().to_string_lossy()[..20]
        .parse()
        .unwrap()
}

fn inverter_byte(path: &Path, off: u64) {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut b = [0u8; 1];
    f.seek(SeekFrom::Start(off)).unwrap();
    f.read_exact(&mut b).unwrap();
    b[0] ^= 0x01;
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(&b).unwrap();
    f.sync_all().unwrap();
}

fn encher(log: &V6Log, n: usize, enchimento: &str) {
    for i in 0..n {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("evento {i} {enchimento}").into_bytes(),
        ))
        .unwrap();
    }
}

/// B2 — um bit trocado num RAW selado. `scan(0, 200)` devolvia `Ok` com 187
/// linhas e `read` devolvia `Ok(None)` para 13 LSN confirmados, porque o
/// percurso em streaming parava no CRC falhado como se o segmento tivesse
/// acabado. `catch_up`, `rebuild`, o índice de atributos, o `Subscribe`, o
/// snapshot Raft e o relatório do titular avançam todos por linha: os eventos
/// perdiam-se das views sem erro nenhum.
#[test]
fn bitrot_em_raw_selado_falha_alto_no_scan_e_no_read() {
    let dir = tempfile::tempdir().unwrap();
    let log = V6Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
    encher(&log, 200, &"x".repeat(60));
    let head = log.head();
    assert_eq!(log.scan(0, head).unwrap().len() as u64, head, "setup");
    let segs = selados(dir.path());
    assert!(segs.len() >= 3, "o teste precisa de vários RAW selados");
    let alvo = segs[segs.len() / 2].clone();
    let len = std::fs::metadata(&alvo).unwrap().len();
    inverter_byte(&alvo, len / 2);

    match log.scan(0, head) {
        Ok(v) => panic!("scan devolveu Ok com {} de {head} linhas", v.len()),
        Err(HeraclitusError::Corruption { .. }) => {}
        Err(e) => panic!("esperava Corruption, veio {e}"),
    }

    let mut corrompidos = 0;
    for lsn in 0..head {
        match log.read(lsn) {
            Ok(Some((l, _))) => assert_eq!(l, lsn),
            Ok(None) => panic!("read({lsn}) devolveu Ok(None) com o LSN abaixo do head {head}"),
            Err(HeraclitusError::Corruption { .. }) => corrompidos += 1,
            Err(e) => panic!("read({lsn}): esperava Corruption, veio {e}"),
        }
    }
    assert!(corrompidos > 0, "nenhum read acusou o registo corrompido");

    // O diário administrativo recupera-se por `scan_builtin_eq_capped`, cujo
    // ramo RAW também parava no rasgo e ignorava o `torn_at`.
    assert!(
        log.scan_builtin_eq_capped("agent_id", "a", 0, head, usize::MAX)
            .is_err(),
        "varredura podada devolveu Ok sem os registos depois do corrompido"
    );

    // Uma janela que não toca no segmento estragado continua a responder.
    assert_eq!(log.scan(0, 1).unwrap().len(), 1);
}

/// B1 — um bit trocado a 1/3 da cauda activa, com os 100 registos confirmados
/// com `fsync = Always`. O arranque tratava o CRC falhado como cauda rasgada:
/// `head` passava de 100 para 33, os 67 registos seguintes eram apagados e os
/// LSN 33.. voltavam a ser atribuídos aos próximos appends.
#[test]
fn bitrot_no_meio_da_cauda_activa_nao_trunca_confirmados() {
    let dir = tempfile::tempdir().unwrap();
    let a;
    let alvo;
    {
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        encher(&log, 100, &"y".repeat(40));
        assert_eq!(log.head(), 100);
        a = activo(dir.path());
        alvo = std::fs::metadata(&a).unwrap().len() / 3;
        inverter_byte(&a, alvo);
        // Com o log aberto, a cauda tem de acusar o buraco (B2, ramo da cauda).
        assert!(
            log.scan(0, 100).is_err(),
            "scan da cauda devolveu Ok com o registo corrompido"
        );
    }
    let antes = std::fs::metadata(&a).unwrap().len();

    match V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always) {
        Ok(log) => panic!(
            "o arranque aceitou a cauda corrompida com head {} (antes 100)",
            log.head()
        ),
        Err(HeraclitusError::Corruption { detail, .. }) => {
            assert!(detail.contains("refusing to truncate"), "{detail}")
        }
        Err(e) => panic!("esperava Corruption, veio {e}"),
    }
    assert_eq!(
        std::fs::metadata(&a).unwrap().len(),
        antes,
        "a cauda foi truncada — a evidência tinha de ficar intacta"
    );

    // Nada foi destruído: desfeita a corrupção, os 100 registos voltam todos.
    inverter_byte(&a, alvo);
    let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    assert_eq!(log.head(), 100);
    assert_eq!(log.scan(0, 100).unwrap().len(), 100);
}

/// B5 — escrita interrompida (SIGKILL a meio de um `write` grande, que o Linux
/// corta em fronteira de página) de um registo cujo payload — conteúdo do
/// cliente — traz uma imagem de footer válida mesmo antes do corte. O CRC do
/// footer não tem chave, e o arranque via um footer depois do rasgo e recusava
/// abrir para sempre ("refusing to truncate a sealed segment").
#[test]
fn cauda_rasgada_com_imagem_de_footer_no_payload_recupera() {
    let dir = tempfile::tempdir().unwrap();
    let imagem = FooterV6 {
        record_count: 0,
        min_lsn: 0,
        max_lsn: 0,
        min_hlc: 0,
        max_hlc: 0,
        block_count: 0,
        flags: 0,
        block_directory_offset: 0,
        block_directory_len: 0,
        logical_root: [0u8; 32],
    }
    .encode();
    {
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            b"primeiro".to_vec(),
        ))
        .unwrap();
        let mut conteudo = vec![b'x'; 300];
        conteudo.extend_from_slice(&imagem);
        conteudo.extend_from_slice(&[b'y'; 5000]);
        log.append(Episode::new("a", EventKind::Observation, conteudo))
            .unwrap();
    }
    let a = activo(dir.path());
    let bytes = std::fs::read(&a).unwrap();
    let pos = bytes
        .windows(imagem.len())
        .position(|w| w == &imagem[..])
        .expect("imagem no ficheiro");
    // O corte do `write` a meio do 2.º registo, logo a seguir à imagem.
    let f = std::fs::OpenOptions::new().write(true).open(&a).unwrap();
    f.set_len((pos + imagem.len()) as u64).unwrap();
    drop(f);

    let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always)
        .expect("a cauda rasgada tem de ser recuperada, não recusada para sempre");
    assert_eq!(log.head(), 1, "só o registo completo sobrevive ao corte");
    let linhas = log.scan(0, 1).unwrap();
    assert_eq!(linhas[0].1.content, b"primeiro");
    let novo = log
        .append(Episode::new(
            "a",
            EventKind::Observation,
            b"depois".to_vec(),
        ))
        .unwrap();
    assert_eq!(novo, 1, "o LSN do registo cortado é o próximo a atribuir");
    drop(log);
    let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    assert_eq!(log.head(), 2);
}

/// B6 — um único RAW selado corrompido travava o packing de todos os
/// segmentos seguintes (e, por arrasto, HRKI, Parquet e GC), com a mensagem
/// enganosa "refusing to pack an unsealed segment" para um segmento que está
/// selado.
#[test]
fn um_raw_corrompido_nao_trava_a_fila_de_packing() {
    let dir = tempfile::tempdir().unwrap();
    let log = V6Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
    encher(&log, 200, &"x".repeat(60));
    let segs = selados(dir.path());
    assert!(segs.len() >= 3, "o teste precisa de vários RAW selados");
    let alvo = segs[1].clone();
    let id_alvo = id_do_segmento(&alvo);
    let len = std::fs::metadata(&alvo).unwrap().len();
    inverter_byte(&alvo, len / 2);

    for passagem in 0..2 {
        let Err(err) = log.pack_pending(PackingProfile::Balanced) else {
            panic!("passagem {passagem}: o segmento corrompido tem de ser reportado, não engolido");
        };
        let msg = err.to_string();
        assert!(
            matches!(err, HeraclitusError::Corruption { .. }),
            "passagem {passagem}: {msg}"
        );
        assert!(!msg.contains("unsealed"), "passagem {passagem}: {msg}");
        assert!(msg.contains("offset"), "passagem {passagem}: {msg}");
        assert_eq!(
            log.manifest().packing_queue(),
            vec![id_alvo],
            "passagem {passagem}: a fila tem de ficar só com o segmento corrompido ({msg})"
        );
    }
}

/// B6, a outra fila do mesmo padrão: um PACKED ilegível não pode impedir os
/// outros segmentos de ganharem sidecar HRKI.
#[test]
fn um_packed_corrompido_nao_trava_a_fila_de_hrki() {
    let dir = tempfile::tempdir().unwrap();
    let log = V6Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
    encher(&log, 200, &"x".repeat(60));
    let empacotados = log.pack_pending(PackingProfile::Balanced).unwrap();
    assert!(empacotados.len() >= 3, "o teste precisa de vários PACKED");
    let packed = segmentos_com_sufixo(dir.path(), ".packed.hrkl");
    let alvo = packed[1].clone();
    let id_alvo = id_do_segmento(&alvo);
    let len = std::fs::metadata(&alvo).unwrap().len();
    inverter_byte(&alvo, len / 2);

    let policy = IndexPolicySet::new().com("agent_id", IndexPolicy::PublicTechnical);
    assert!(
        log.build_pending_hrki(&policy, None, 0.01).is_err(),
        "o PACKED corrompido tem de ser reportado"
    );
    assert_eq!(
        log.manifest().sidecar_queue(),
        vec![id_alvo],
        "só o segmento corrompido pode ficar sem sidecar"
    );
}
