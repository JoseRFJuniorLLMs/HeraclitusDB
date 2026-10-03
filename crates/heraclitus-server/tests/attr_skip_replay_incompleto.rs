//! Regressão (auditoria recursiva 2026-10-03, iteração 1): com o replay
//! SALTADO no arranque (`HERACLITUS_SKIP_VIEW_REPLAY`), o índice de atributos
//! carrega o checkpoint antigo e nunca vê a cauda `(watermark, head]`. A
//! bandeira `attr_nao_materializado` só travava o checkpoint; quem RESPONDE a
//! partir do índice tratava-o como completo:
//!
//! 1. idempotência — o retry de uma chave gravada no buraco era gravado OUTRA
//!    vez no log imutável (duplicado permanente);
//! 2. `MATCH (n:Foo)` / `WHERE n.campo = "v"` — o planner tomava o `Some` do
//!    índice como resposta final e largava em silêncio as linhas do buraco;
//! 3. `titular` — contagem por baixo com `indexado: true`.
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
        EventKind::Custom("Foo".into()),
        format!("registo {i}").into_bytes(),
    );
    e.attrs.insert("dossie".into(), "alfa".into());
    e
}

/// Payload fixo: o retry tem de ser byte-equivalente (só o `EventId`/`ts_hlc`
/// mudam, e esses não entram no hash canónico).
fn idempotente() -> Episode {
    Episode::new("ana", EventKind::Observation, b"pedido unico".to_vec())
}

fn linhas(engine: &Engine, gql: &str) -> usize {
    let v = heraclitus_query::execute(gql, engine).unwrap();
    v.as_array().map(|a| a.len()).unwrap_or(0)
}

#[test]
fn indice_de_atributos_com_buraco_nao_responde_como_se_fosse_completo() {
    let dir = tempfile::tempdir().unwrap();
    const CHAVE: &str = "pedido-k";

    // 1) Sessão normal: 10 episódios + checkpoint (attr @10). Depois, SEM
    //    checkpoint (crash), a chave idempotente e mais 5 episódios — o buraco.
    let lsn_original = {
        let engine = abrir(dir.path());
        for i in 0..10 {
            engine.append(episodio(i)).unwrap();
        }
        engine.checkpoint_views().unwrap();
        let (lsn, dedup, _) = engine.append_idempotent(idempotente(), CHAVE).unwrap();
        assert!(!dedup, "montagem: a primeira escrita não é um retry");
        for i in 10..15 {
            engine.append(episodio(i)).unwrap();
        }
        lsn
    };

    // 2) Arranque degradado (escritas permitidas: SKIP sozinho não liga LOG_ONLY).
    std::env::set_var("HERACLITUS_SKIP_VIEW_REPLAY", "1");
    let engine = abrir(dir.path());
    std::env::remove_var("HERACLITUS_SKIP_VIEW_REPLAY");
    let head_antes = engine.head();

    // (1) O retry NÃO pode gravar um segundo evento: ou deduplica para o LSN
    //     original, ou é recusado.
    if let Ok((lsn, dedup, _)) = engine.append_idempotent(idempotente(), CHAVE) {
        assert!(
            dedup && lsn == lsn_original,
            "retry idempotente gravado OUTRA vez (lsn {lsn}, original {lsn_original})"
        );
    }
    assert_eq!(
        engine.head(),
        head_antes,
        "o retry acrescentou um duplicado permanente ao log"
    );

    // (2) As queries servidas pelo índice não podem largar as linhas do buraco.
    let por_attr = linhas(&engine, "MATCH (n) WHERE n.dossie = \"alfa\" RETURN n");
    assert_eq!(
        por_attr, 15,
        "WHERE por atributo devolveu {por_attr} de 15 linhas"
    );
    let por_kind = linhas(&engine, "MATCH (n:Foo) RETURN n");
    assert_eq!(
        por_kind, 15,
        "MATCH por kind devolveu {por_kind} de 15 linhas"
    );

    // (3) O titular não pode apresentar uma contagem parcial como fidedigna.
    let t = engine.titular("ana", 0);
    assert!(
        t["indexado"] == serde_json::Value::Bool(false) || t["eventos"] == 16,
        "titular com contagem parcial marcada como indexada: {t}"
    );
}
