//! Auditoria 2026-09-05, A50 (retrabalho pós-revisão): num processo arrancado
//! com o replay saltado, o crypto-shred TEM de reescrever os snapshots das
//! views.
//!
//! `Engine::shred` (§3.10) destrói a chave da titular e a seguir reconstrói
//! TODO o estado derivado a partir do LSN 0 — `views.rebuild(&log, None)` +
//! `views.checkpoint()` — precisamente para que o plaintext que estava nas
//! views deixe de existir também em disco. Esse `views.checkpoint()` chama o
//! `ViewRegistry` DIRECTAMENTE, sem passar por `Engine::checkpoint_views`.
//!
//! Se a marca de "views não materializadas" (levantada no arranque com
//! `HERACLITUS_SKIP_VIEW_REPLAY` / `HERACLITUS_LOG_ONLY`, que é um modo que
//! ACEITA escritas e onde o shred está exposto por gRPC) continuasse de pé
//! depois do rebuild integral, esse checkpoint virava um no-op SILENCIOSO: os
//! snapshots PRÉ-shred ficavam em disco com o plaintext derivado da titular, e
//! logo a seguir o `shred` apaga o marcador `privacy-rebuild-required` — a
//! única pista que faria o arranque seguinte reconstruir. O boot normal a
//! seguir restaura esses snapshots e o plaintext RESSUSCITA depois de a chave
//! ter sido destruída. É por isso que `ViewRegistry::rebuild` com
//! `view_name == None` baixa a marca.
//!
//! Binário de teste próprio de propósito: mexe numa variável de ambiente, que é
//! global ao processo, por isso este é o ÚNICO teste do binário.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusConfig};
use heraclitus_server::engine::Engine;

/// O prefixo é o que o keystore por agente usa para derivar a chave da titular.
const TITULAR: &str = "titular:hmac-sha256:carlos";
/// Termo raro: procurá-lo nos bytes do snapshot não dá falsos positivos.
const SEGREDO: &str = "hipopotamo";

fn config(dir: &std::path::Path) -> HeraclitusConfig {
    HeraclitusConfig {
        data_dir: dir.to_path_buf(),
        fsync: FsyncPolicy::Always,
        encryption_at_rest: true,
        ..HeraclitusConfig::default()
    }
}

/// A asserção é sobre os BYTES do snapshot das views, não sobre o que o índice
/// responde em RAM: o que o crypto-shred promete é que o plaintext derivado
/// deixa de existir em DISCO. O snapshot do índice de texto é um `bincode` sem
/// compressão de `HashMap<String, ...>` — os termos aparecem literais lá
/// dentro, e é esse o dado que não pode sobreviver à destruição da chave.
fn plaintext_no_snapshot(dir: &std::path::Path) -> bool {
    let bytes = std::fs::read(dir.join("views").join("text.ckpt")).unwrap_or_default();
    bytes
        .windows(SEGREDO.len())
        .any(|janela| janela == SEGREDO.as_bytes())
}

#[test]
fn shred_com_replay_saltado_reescreve_os_snapshots_das_views() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());

    // 1) Sessão normal: o plaintext da titular entra nas views e o checkpoint
    //    (periódico ou de shutdown) grava-o em disco.
    {
        let engine = Engine::open(&cfg).unwrap();
        engine
            .append(Episode::new(
                TITULAR,
                EventKind::Observation,
                format!("o {SEGREDO} bebeu do rio").into_bytes(),
            ))
            .unwrap();
        engine.checkpoint_views().unwrap();
    }
    assert!(
        plaintext_no_snapshot(dir.path()),
        "montagem: o snapshot das views tinha de conter o plaintext antes do shred"
    );

    // 2) Sessão com o replay SALTADO — o modo que este achado assume em uso, e
    //    onde o `crypto_shred` continua exposto por gRPC.
    {
        std::env::set_var("HERACLITUS_SKIP_VIEW_REPLAY", "1");
        let engine = Engine::open(&cfg).unwrap();
        std::env::remove_var("HERACLITUS_SKIP_VIEW_REPLAY");
        assert!(
            engine.shred(TITULAR).unwrap(),
            "montagem: o shred tinha de destruir a chave da titular"
        );
        assert!(
            !dir.path()
                .join("views")
                .join("privacy-rebuild-required")
                .exists(),
            "montagem: o shred apaga o marcador no fim — depois disto, o único \
             sítio onde o plaintext ainda pode estar é o snapshot"
        );
    }
    assert!(
        !plaintext_no_snapshot(dir.path()),
        "o crypto-shred não reescreveu o snapshot das views: o plaintext derivado \
         da titular continua em disco depois de a chave ter sido destruída"
    );

    // 3) Arranque NORMAL seguinte: `catch_up` restaura os snapshots do disco e
    //    volta a gravá-los (fast boot). O plaintext não pode reaparecer em
    //    nenhum dos dois passos.
    {
        let _engine = Engine::open(&cfg).unwrap();
    }
    assert!(
        !plaintext_no_snapshot(dir.path()),
        "o plaintext RESSUSCITOU no arranque seguinte: o snapshot PRÉ-shred foi \
         restaurado depois de a chave ter sido destruída"
    );
}
