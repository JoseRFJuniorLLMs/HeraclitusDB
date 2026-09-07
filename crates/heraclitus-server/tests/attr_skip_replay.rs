//! Regressão: arrancar com o replay SALTADO não pode consolidar um buraco
//! PERMANENTE no índice de atributos.
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
    let mut e = Episode::new(
        "ana",
        EventKind::Observation,
        format!("registo {i}").into_bytes(),
    );
    e.attrs.insert("dossie".into(), "alfa".into());
    e
}

fn quantos(engine: &Engine) -> usize {
    let v =
        heraclitus_query::execute("MATCH (n) WHERE n.dossie = \"alfa\" RETURN n", engine).unwrap();
    v.as_array().map(|a| a.len()).unwrap_or(0)
}

/// PERDA DE DADOS SILENCIOSA (auditoria 2026-09-05, A47): o ramo skip_replay do
/// arranque carrega o checkpoint do índice de atributos (`AttrIndex::open`, com
/// o watermark antigo) mas salta o catch-up. As escritas ao vivo da sessão
/// empurram o watermark do índice para além do buraco
/// (`watermark = max(watermark, lsn)`) e o `checkpoint_attr` seguinte consolida
/// esse estado em disco. No arranque normal a seguir, `cur = idx.watermark()`
/// faz saltar o intervalo perdido — e ele nunca mais é indexado: um
/// `WHERE n.<campo> = "<valor>"` devolve zero/parciais linhas sobre episódios
/// que estão no log, sem erro nem aviso. `Engine::rebuild` NÃO repara isto (só
/// mexe nas views), portanto o remédio documentado não chega ao índice.
///
/// A asserção é sobre o que o índice responde, nunca sobre o watermark — é o
/// watermark que mente.
#[test]
fn skip_replay_nao_deixa_buraco_permanente_no_indice_de_atributos() {
    let dir = tempfile::tempdir().unwrap();

    // 1) Sessão normal: 30 episódios indexados e checkpoint gravado (attr @30).
    {
        let engine = abrir(dir.path());
        for i in 0..30 {
            engine.append(episodio(i)).unwrap();
        }
        engine.checkpoint_views().unwrap();
        assert_eq!(
            quantos(&engine),
            30,
            "montagem: os 30 têm de estar no índice"
        );
    }

    // 2) Mais 30 episódios que o índice NUNCA viu (carga em bulk / crash sem
    //    checkpoint). Em disco: attr @30, log com 60.
    {
        std::env::set_var("HERACLITUS_LOG_ONLY", "1");
        let engine = abrir(dir.path());
        for i in 30..60 {
            engine.append(episodio(i)).unwrap();
        }
        drop(engine);
        std::env::remove_var("HERACLITUS_LOG_ONLY");
    }

    // 3) Sessão degradada: uma escrita ao vivo (que empurra o watermark do
    //    índice para 61) e o checkpoint periódico/de shutdown.
    {
        std::env::set_var("HERACLITUS_SKIP_VIEW_REPLAY", "1");
        let engine = abrir(dir.path());
        engine.append(episodio(60)).unwrap();
        engine.checkpoint_views().unwrap();
        drop(engine);
        std::env::remove_var("HERACLITUS_SKIP_VIEW_REPLAY");
    }

    // 4) Arranque normal seguinte: o índice TEM de conhecer os 61.
    let engine = abrir(dir.path());
    let vistos = quantos(&engine);
    assert_eq!(
        vistos, 61,
        "buraco permanente no índice de atributos: só {vistos} de 61 episódios respondem"
    );
}
