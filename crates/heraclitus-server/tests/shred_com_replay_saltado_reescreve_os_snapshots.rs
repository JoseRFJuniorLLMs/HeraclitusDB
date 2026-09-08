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

/// Lê os bytes do snapshot canónico das views EXIGINDO que ele exista.
///
/// Auditoria 2026-09-05, vaga 2 (R124): a versão anterior fazia
/// `read(...).unwrap_or_default()`, e por isso um `views/text.ckpt` AUSENTE
/// era indistinguível de "snapshot sem plaintext". As duas asserções
/// NEGATIVAS deste teste (a do pós-shred e a do arranque seguinte) ficavam
/// verdes por VACUIDADE no dia em que o caminho de escrita pós-shred
/// divergisse do pré-shred e deixasse de produzir o ficheiro — verdes sem
/// observar nada sobre aquilo que o teste existe para provar. Um ficheiro
/// ausente NUNCA prova que o plaintext saiu do disco. `TextIndex::checkpoint`
/// chama `ckpt::save` incondicionalmente (mesmo com estado vazio), portanto o
/// snapshot existe em TODOS os pontos de observação: exigi-lo aqui não é uma
/// exigência a mais, é o invariante que dá sentido às asserções.
fn bytes_do_snapshot(dir: &std::path::Path) -> Vec<u8> {
    let p = dir.join("views").join("text.ckpt");
    std::fs::read(&p)
        .unwrap_or_else(|e| panic!("{} tinha de existir neste ponto: {e}", p.display()))
}

/// A asserção é sobre os BYTES em disco, não sobre o que o índice responde em
/// RAM: o que o crypto-shred promete é que o plaintext derivado deixa de
/// existir em DISCO. O snapshot do índice de texto é um `bincode` sem
/// compressão de `HashMap<String, ...>` — os termos aparecem literais lá
/// dentro, e é esse o dado que não pode sobreviver à destruição da chave.
///
/// Auditoria 2026-09-05, vaga 2 (R124): a varredura é a TODOS os ficheiros
/// regulares de `views/`, e não só ao `text.ckpt` de hoje, para que o
/// plaintext não possa escapar para um ficheiro irmão (um `.tmp` órfão, uma
/// rotação de backup, um formato segmentado futuro) e continuar a dar o teste
/// por verde.
fn plaintext_nas_views(dir: &std::path::Path) -> bool {
    // Impõe primeiro a existência do snapshot canónico: sem isto a varredura
    // de um directório vazio responderia "sem plaintext" com toda a calma.
    let _ = bytes_do_snapshot(dir);
    std::fs::read_dir(dir.join("views"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .any(|e| {
            // `unwrap_or_default` é legítimo AQUI: varredura best-effort de
            // ficheiros que podem desaparecer sob concorrência, e o invariante
            // de existência já foi imposto acima.
            let bytes = std::fs::read(e.path()).unwrap_or_default();
            bytes
                .windows(SEGREDO.len())
                .any(|janela| janela == SEGREDO.as_bytes())
        })
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
        plaintext_nas_views(dir.path()),
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
        !plaintext_nas_views(dir.path()),
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
        !plaintext_nas_views(dir.path()),
        "o plaintext RESSUSCITOU no arranque seguinte: o snapshot PRÉ-shred foi \
         restaurado depois de a chave ter sido destruída"
    );
}
