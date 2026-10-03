//! Um segmento em falta no meio do log tem de fazer `Log::open` falhar alto.
//!
//! Auditoria recursiva 2026-10-03, iteração 1: o `Log::open` aceitava os
//! segmentos tal como os encontrava, sem comparar o primeiro LSN de cada um
//! com o último recuperado do anterior. Com o segmento 1 apagado (restauro ou
//! cópia incompleta), a abertura devolvia `Ok`, o `scan` saltava o buraco em
//! silêncio e o `read` de um LSN abaixo do head devolvia `Ok(None)` — as views
//! eram reconstruídas sem esses eventos e ninguém dava por isso.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusError};
use heraclitus_log::Log;

fn evento(i: usize) -> Episode {
    Episode::new(
        "teste",
        EventKind::Observation,
        format!("registo-{i}-{}", "x".repeat(200)).into_bytes(),
    )
}

fn povoar(dir: &std::path::Path) -> Vec<heraclitus_log::SegmentMeta> {
    let log = Log::open(dir, 16 * 1024, FsyncPolicy::Always).unwrap();
    for i in 0..400 {
        log.append(evento(i)).unwrap();
    }
    log.flush().unwrap();
    let selados = log.sealed_segments();
    assert!(
        selados.len() >= 3,
        "o teste precisa de pelo menos 3 segmentos selados; houve {}",
        selados.len()
    );
    selados
}

#[test]
fn segmento_do_meio_em_falta_recusa_abrir() {
    let dir = tempfile::tempdir().unwrap();
    let selados = povoar(dir.path());

    // Simula a perda de um segmento do meio (nem o primeiro nem o activo).
    std::fs::remove_file(&selados[1].path).unwrap();

    match Log::open(dir.path(), 16 * 1024, FsyncPolicy::Always) {
        Err(HeraclitusError::Corruption { detail, .. }) => {
            assert!(
                detail.contains("lacuna de LSN"),
                "erro inesperado: {detail}"
            );
        }
        Err(outro) => panic!("esperava Corruption por lacuna de LSN, veio {outro:?}"),
        Ok(log) => panic!(
            "Log::open aceitou um histórico com buraco (head = {})",
            log.head()
        ),
    }
}

#[test]
fn primeiro_segmento_em_falta_recusa_abrir() {
    let dir = tempfile::tempdir().unwrap();
    let selados = povoar(dir.path());

    // O log começa sempre no LSN 0: faltar o segmento inicial também é lacuna.
    std::fs::remove_file(&selados[0].path).unwrap();

    assert!(matches!(
        Log::open(dir.path(), 16 * 1024, FsyncPolicy::Always),
        Err(HeraclitusError::Corruption { .. })
    ));
}

#[test]
fn log_intacto_reabre_com_o_mesmo_head() {
    let dir = tempfile::tempdir().unwrap();
    povoar(dir.path());

    let log = Log::open(dir.path(), 16 * 1024, FsyncPolicy::Always).unwrap();
    assert_eq!(log.head(), 400);
    assert_eq!(log.scan(0, 400).unwrap().len(), 400);
}
