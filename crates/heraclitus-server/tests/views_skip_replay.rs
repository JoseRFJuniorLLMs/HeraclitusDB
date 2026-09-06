//! Regressão: arrancar com o replay SALTADO não pode consolidar views vazias
//! sob o watermark da cauda.
//!
//! Binário de teste próprio de propósito: mexe em variáveis de ambiente
//! (processo inteiro) e tem de correr sozinho.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusConfig};
use heraclitus_server::engine::Engine;

fn abrir(dir: &std::path::Path) -> Engine {
    let cfg = HeraclitusConfig {
        data_dir: dir.to_path_buf(),
        fsync: FsyncPolicy::Always,
        ..HeraclitusConfig::default()
    };
    Engine::open(&cfg).unwrap()
}

fn episodio(i: usize) -> Episode {
    Episode::new(
        "ana",
        EventKind::Observation,
        format!("rio caudaloso numero {i}").into_bytes(),
    )
}

fn indexados(engine: &Engine) -> u64 {
    engine.stats()["text_indexed"].as_u64().unwrap()
}

/// PERDA DE DADOS SILENCIOSA (auditoria 2026-09-05, A46): no arranque com
/// HERACLITUS_SKIP_VIEW_REPLAY as views nascem VAZIAS e a única defesa era
/// zerar os watermarks do registry. Isso é INERTE assim que a sessão receber
/// uma escrita: quem manda no arranque seguinte é o watermark INTERNO de cada
/// view (`catch_up` adopta o do snapshot como autoridade) e `View::apply`
/// sobe-o incondicionalmente. Como SKIP_VIEW_REPLAY sozinho não liga
/// `log_only`, o primeiro append repõe o watermark da cauda sobre uma view
/// vazia, e o checkpoint que se segue (periódico — 300 s por omissão — ou o de
/// shutdown) grava esse par mentiroso. O arranque normal a seguir replaya só
/// `(watermark, head]` e o histórico fica órfão PARA SEMPRE.
///
/// A asserção é sobre o que a view indexou, nunca sobre o watermark — é o
/// watermark que mente.
#[test]
fn skip_replay_com_escrita_ao_vivo_nao_orfana_as_views() {
    let dir = tempfile::tempdir().unwrap();

    // 1) Sessão normal: 30 episódios materializados e checkpoint gravado.
    {
        let engine = abrir(dir.path());
        for i in 0..30 {
            engine.append(episodio(i)).unwrap();
        }
        engine.checkpoint_views().unwrap();
        assert_eq!(
            indexados(&engine),
            30,
            "montagem: os 30 têm de estar na view"
        );
    }

    // 2) Sessão degradada: UMA escrita ao vivo (que empurra o watermark interno
    //    de cada view para 31, sobre views vazias) e o checkpoint que se segue.
    {
        std::env::set_var("HERACLITUS_SKIP_VIEW_REPLAY", "1");
        let engine = abrir(dir.path());
        assert_eq!(indexados(&engine), 0, "montagem: as views arrancam vazias");
        engine.append(episodio(30)).unwrap();
        engine.checkpoint_views().unwrap();
        drop(engine);
        std::env::remove_var("HERACLITUS_SKIP_VIEW_REPLAY");
    }

    // 3) Arranque normal seguinte: a view TEM de voltar a conter o log inteiro.
    let engine = abrir(dir.path());
    let vistos = indexados(&engine);
    assert_eq!(
        vistos, 31,
        "views órfãs: só {vistos} de 31 episódios ficaram indexados"
    );
}
