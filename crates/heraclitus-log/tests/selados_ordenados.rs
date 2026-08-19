//! O vetor de segmentos SELADOS tem de ficar ordenado por `base_lsn`.
//!
//! Porque é que isto merece um teste próprio: `Log::read` e `Log::scan_capped`
//! localizam o segmento de um LSN com `binary_search_by_key(base_lsn)`. Uma
//! busca binária sobre um vetor desordenado não devolve erro — devolve o
//! **segmento errado**, em silêncio, e a leitura cai no fallback lento ou
//! falha a encontrar um registo que existe.
//!
//! Até 2026-08-19 essa ordem era garantida por um `sort_by_key` dentro do
//! `roll_segment`, executado a **cada selagem** (1 164 vezes na carga de 20M)
//! sobre um vetor que já estava ordenado — os segmentos nascem por ordem
//! monotónica de `base_lsn` e o `push` preserva-a. O sort foi removido; este
//! teste é o que passa a fixar a invariante, em vez de a pagar em runtime.

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use std::sync::Arc;

fn evento(i: usize) -> Episode {
    Episode::new(
        "teste",
        EventKind::Observation,
        format!("registo-{i}-{}", "x".repeat(200)).into_bytes(),
    )
}

/// Escritor único: o caminho simples, muitas selagens.
#[test]
fn selados_ficam_ordenados_por_base_lsn() {
    let dir = tempfile::tempdir().unwrap();
    // Segmento minúsculo de propósito: força dezenas de selagens.
    let log = Log::open(dir.path(), 16 * 1024, FsyncPolicy::GroupCommit { interval_ms: 50 }).unwrap();

    for i in 0..2_000 {
        log.append(evento(i)).unwrap();
    }
    log.flush().unwrap();

    let selados = log.sealed_segments();
    assert!(
        selados.len() > 5,
        "o teste precisa de várias selagens para ter valor; houve {}",
        selados.len()
    );

    for par in selados.windows(2) {
        assert!(
            par[0].base_lsn <= par[1].base_lsn,
            "segmentos selados fora de ordem: base_lsn {} (id {}) veio antes de {} (id {})",
            par[0].base_lsn,
            par[0].id,
            par[1].base_lsn,
            par[1].id
        );
    }
}

/// Escritores concorrentes: é aqui que uma ordem acidental se desfaria, porque
/// os appends chegam ao worker intercalados. O roll continua a ser serial (só
/// o worker rola), mas o teste tem de o provar, não assumir.
#[test]
fn selados_ordenados_sob_escrita_concorrente() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(
        Log::open(dir.path(), 16 * 1024, FsyncPolicy::GroupCommit { interval_ms: 50 }).unwrap(),
    );

    let hs: Vec<_> = (0..8)
        .map(|t| {
            let l = log.clone();
            std::thread::spawn(move || {
                for i in 0..300 {
                    l.append(evento(t * 1000 + i)).unwrap();
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    log.flush().unwrap();

    let selados = log.sealed_segments();
    assert!(selados.len() > 5, "poucas selagens: {}", selados.len());

    for par in selados.windows(2) {
        assert!(
            par[0].base_lsn <= par[1].base_lsn,
            "ordem quebrada com 8 escritores: {} antes de {}",
            par[0].base_lsn,
            par[1].base_lsn
        );
    }

    // A consequência prática da invariante: cada LSN tem de ser encontrado.
    // Sem a ordem, a busca binária escolheria o container errado.
    let head = log.head();
    for lsn in [0u64, head / 4, head / 2, head - 1] {
        assert!(
            log.read(lsn).unwrap().is_some(),
            "LSN {lsn} não foi encontrado (head={head})"
        );
    }
}
