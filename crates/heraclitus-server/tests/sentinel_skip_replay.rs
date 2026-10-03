//! Regressão (auditoria recursiva 2026-10-03, iteração 2): a iteração 1 passou
//! a recusar TODO o append idempotente enquanto o índice de atributos tem um
//! buraco (`HERACLITUS_SKIP_VIEW_REPLAY`). O Sentinel interno grava todos os
//! eventos derivados por esse mesmo caminho (`DerivedEventSink for Engine` →
//! `append_sentinel_derived`), por isso sob SKIP_VIEW_REPLAY o pipeline de
//! segurança inteiro parava: o `worker_loop` repetia o mesmo LSN para sempre,
//! sem SecurityEvent, sinal, incidente, acção L4 nem checkpoint.
//!
//! O Sentinel deduplica pelo seu próprio estado reconstruído do log, logo
//! continua a poder escrever; a recusa mantém-se para os clientes externos.
//!
//! Binário de teste próprio de propósito: mexe em variáveis de ambiente
//! (processo inteiro) e tem de correr sozinho.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusConfig};
use heraclitus_sentinel::DerivedEventSink;
use heraclitus_server::engine::Engine;

fn abrir(dir: &std::path::Path) -> Engine {
    let cfg = HeraclitusConfig {
        data_dir: dir.to_path_buf(),
        fsync: FsyncPolicy::Always,
        ..HeraclitusConfig::default()
    };
    Engine::open(&cfg).unwrap()
}

fn derivado() -> Episode {
    let mut e = Episode::new(
        "sentinel",
        EventKind::Custom("SecurityEvent".into()),
        b"{}".to_vec(),
    );
    e.attrs.insert("sentinel.generated".into(), "true".into());
    e
}

#[test]
fn sentinel_continua_a_escrever_com_o_replay_saltado() {
    let dir = tempfile::tempdir().unwrap();

    // Sessão normal com checkpoint, para o arranque seguinte ter de onde partir.
    {
        let engine = abrir(dir.path());
        for i in 0..5 {
            engine
                .append(Episode::new(
                    "ana",
                    EventKind::Observation,
                    format!("registo {i}").into_bytes(),
                ))
                .unwrap();
        }
        engine.checkpoint_views().unwrap();
    }

    // Arranque degradado (SKIP sozinho não liga LOG_ONLY: escritas permitidas).
    std::env::set_var("HERACLITUS_SKIP_VIEW_REPLAY", "1");
    let engine = abrir(dir.path());
    std::env::remove_var("HERACLITUS_SKIP_VIEW_REPLAY");
    let head_antes = engine.head();

    // O cliente externo continua recusado (iteração 1 inalterada).
    assert!(
        engine
            .append_idempotent(
                Episode::new("ana", EventKind::Observation, b"x".to_vec()),
                "cliente-k"
            )
            .is_err(),
        "append idempotente de cliente devia continuar recusado com o índice parcial"
    );
    assert_eq!(engine.head(), head_antes);

    // O Sentinel escreve — antes da correcção dava Config(IDEMPOTENCIA_SEM_INDICE).
    let lsn = DerivedEventSink::append(&engine, derivado(), "e:v1:0")
        .expect("o Sentinel tem de conseguir gravar eventos derivados sob SKIP_VIEW_REPLAY");
    assert_eq!(engine.head(), head_antes + 1);

    // E o retry da mesma chave, gravada nesta sessão, deduplica pelo índice.
    let retry = DerivedEventSink::append(&engine, derivado(), "e:v1:0").unwrap();
    assert_eq!(
        retry, lsn,
        "retry do Sentinel na mesma sessão não deduplicou"
    );
    assert_eq!(engine.head(), head_antes + 1);
}
