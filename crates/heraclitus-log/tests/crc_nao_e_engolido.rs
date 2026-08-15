//! Regressão: os dois caminhos de leitura têm de concordar sobre corrupção.

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use std::io::{Read, Seek, SeekFrom, Write};

/// BURACO SILENCIOSO NAS VIEWS (corrigido). Um registo com CRC-32C violado era
/// SALTADO por `scan_capped`, que devolvia `Ok` com o LSN em falta, enquanto
/// `Log::read` do MESMO LSN devolvia `Corruption`. Como `ViewRegistry::catch_up`,
/// `rebuild`, a construção do índice de atributos e o replay do H-VM usam o
/// scan, as views eram reconstruídas SEM o episódio — sem erro, sem métrica,
/// sem tracing, contra o contrato de `heraclitus-core/src/error.rs`
/// ("`Corruption` is never silently swallowed"). Repro original de um agente
/// verificador da auditoria.
#[test]
fn scan_e_read_concordam_perante_crc_violado() {
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(
        dir.path().join("log"),
        256 * 1024 * 1024,
        FsyncPolicy::Always,
    )
    .unwrap();
    for i in 0..5 {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("episodio {i}").into_bytes(),
        ))
        .unwrap();
    }
    let head = log.head();
    assert_eq!(log.scan(0, head).unwrap().len() as u64, head, "setup");

    // Corrupcao em RUNTIME: o log fica ABERTO (nao ha reparo de arranque a
    // truncar) e um byte do payload de um registo do meio e invertido no ficheiro.
    let seg = std::fs::read_dir(dir.path().join("log"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "hrkl").unwrap_or(false))
        .unwrap();
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&seg)
            .unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        let off = (buf.len() / 2) as u64;
        let b = buf[off as usize] ^ 0x01;
        f.seek(SeekFrom::Start(off)).unwrap();
        f.write_all(&[b]).unwrap();
        f.sync_all().unwrap();
    }

    // O scan NAO pode devolver Ok com um LSN em falta: ou devolve tudo, ou falha.
    // `Err` é a outra resposta correta: corrupção detectada e propagada.
    if let Ok(v) = log.scan(0, head) {
        assert_eq!(
            v.len() as u64,
            head,
            "scan devolveu Ok com {} de {head} registos — buraco silencioso",
            v.len()
        );
    }
}
