//! Regressões G1/G2/G5/G6/G7 no Engine real.
use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusConfig, ProductPoint};
use heraclitus_query::execute;
use heraclitus_server::Engine;

fn open(dir: &std::path::Path) -> Engine {
    Engine::open(&HeraclitusConfig {
        data_dir: dir.to_path_buf(),
        fsync: FsyncPolicy::Always,
        ..Default::default()
    })
    .unwrap()
}
fn count(e: &Engine, q: &str) -> usize {
    execute(q, e).unwrap().as_array().unwrap().len()
}
fn edge(op: &str, valid: Option<(u64, u64)>) -> Episode {
    let mut e = Episode::new("audit", EventKind::Observation, vec![]);
    for (k, v) in [
        ("edge_from", "a"),
        ("edge_to", "b"),
        ("edge_type", "pagou"),
        ("edge_op", op),
    ] {
        e.attrs.insert(k.into(), v.into());
    }
    if let Some((a, b)) = valid {
        e.valid_from = Some(a);
        e.valid_to = Some(b);
    }
    e
}

#[test]
fn regressao_g1_duas_relacoes_validas_colapsam_no_engine() {
    let dir = tempfile::tempdir().unwrap();
    let e = open(dir.path());
    let mut a = edge("assert", None);
    a.attrs.insert("edge_from".into(), "a->b".into());
    a.attrs.insert("edge_to".into(), "c".into());
    let mut b = edge("assert", None);
    b.attrs.insert("edge_from".into(), "a".into());
    b.attrs.insert("edge_to".into(), "b->c".into());
    e.append(a).unwrap();
    e.append(b).unwrap();
    let rows = count(&e, "MATCH (a)-[r:pagou]->(b) RETURN a,b,r");
    eprintln!("G1 Engine: log={}, relações={rows}", e.head());
    assert_eq!(e.head(), 2);
    assert_eq!(rows, 2, "sonda: dois appends legítimos viraram uma relação");
}

#[test]
fn regressao_g2_mesma_query_historica_muda_com_append_futuro() {
    let dir = tempfile::tempdir().unwrap();
    let e = open(dir.path());
    e.append(edge("assert", Some((100, 200)))).unwrap();
    let q = "MATCH (a)-[r:pagou]->(b) VALID AT 150 AS OF LSN 1 RETURN r";
    assert_eq!(count(&e, q), 1);
    e.append(edge("retract", None)).unwrap();
    e.append(edge("assert", Some((300, 400)))).unwrap();
    eprintln!(
        "G2 Engine: query histórica antes=1, depois={}",
        count(&e, q)
    );
    assert_eq!(
        count(&e, q),
        1,
        "sonda: futuro alterou a resposta histórica"
    );
    assert_eq!(
        count(&e, "MATCH (a)-[r:pagou]->(b) VALID AT 350 RETURN r"),
        1
    );
    assert_eq!(
        count(
            &e,
            "MATCH (a)-[r:pagou]->(b) VALID AT 350 AS OF LSN 1 RETURN r"
        ),
        0
    );
    e.checkpoint_views().unwrap();
    drop(e);
    let e = open(dir.path());
    assert_eq!(count(&e, q), 1);
    assert_eq!(
        count(&e, "MATCH (a)-[r:pagou]->(b) VALID AT 350 RETURN r"),
        1
    );
    e.rebuild(None).unwrap();
    assert_eq!(count(&e, q), 1);
}

#[test]
fn regressao_g5_igualdade_indexada_diverge_de_or_falso() {
    let dir = tempfile::tempdir().unwrap();
    let e = open(dir.path());
    let mut ep = Episode::new("audit", EventKind::Observation, vec![]);
    ep.attrs.insert("ref".into(), " xyz ".into());
    e.append(ep).unwrap();
    let indexed = count(&e, "MATCH (n) WHERE n.ref = \" xyz \" RETURN n");
    let scan = count(
        &e,
        "MATCH (n) WHERE n.ref = \" xyz \" OR n.lsn < 0 RETURN n",
    );
    eprintln!("G5: mesmo predicado, indexado={indexed}, OR falso={scan}");
    assert_eq!(
        (indexed, scan),
        (1, 1),
        "sonda: índice perdeu o valor original"
    );
}

#[test]
fn regressao_g6_atributo_de_cliente_contamina_relatorio_de_outro_titular() {
    let dir = tempfile::tempdir().unwrap();
    let e = open(dir.path());
    let mut ep = Episode::new("ana", EventKind::Observation, b"evento da ana".to_vec());
    ep.attrs.insert("_agent".into(), "bia".into());
    assert!(e.validar_append(&ep, "").is_err());
    assert!(e.append(ep).is_err());
    let report = e.titular("bia", 10);
    let real = count(&e, "MATCH (n) WHERE n.agent_id = \"bia\" RETURN n");
    eprintln!("G6: eventos com agent_id=bia: {real}; relatório={report}");
    assert_eq!(real, 0);
    assert_eq!(
        report["eventos"], 0,
        "sonda: relatório atribui evento de ana a bia"
    );
    assert_eq!(e.head(), 0);
}

#[test]
fn regressao_g7_nearest_ressuscita_tombstone_na_memtable_ate_reiniciar() {
    let dir = tempfile::tempdir().unwrap();
    let query = "NEAREST([0.1,0.2], 1)";
    {
        let e = open(dir.path());
        let mut ep = Episode::new("audit", EventKind::Observation, b"vetor retirado".to_vec());
        ep.embedding = Some(ProductPoint {
            hyp: vec![0.1, 0.2],
            sph: vec![],
            euc: vec![],
        });
        let target = ep.id;
        e.append(ep).unwrap();
        assert_eq!(count(&e, query), 1);
        assert_eq!(
            count(&e, "NEAREST([0.1,0.2], 1) AS OF LSN 1"),
            1,
            "controle: o snapshot anterior à retirada contém o vetor"
        );
        let mut tombstone = Episode::new("audit", EventKind::Observation, vec![]);
        tombstone
            .attrs
            .insert("tombstone_of".into(), target.to_string());
        e.append(tombstone).unwrap();
        eprintln!(
            "G7: após tombstone, NEAREST ainda retorna {} vetor(es)",
            count(&e, query)
        );
        assert_eq!(
            count(&e, query),
            0,
            "sonda: merge da memtable devolveu vetor tombstoned"
        );
        assert_eq!(count(&e, "NEAREST([0.1,0.2], 1) AS OF LSN 1"), 1);
        assert_eq!(count(&e, "NEAREST([0.1,0.2], 1) AS OF LSN 2"), 0);
        e.checkpoint_views().unwrap();
    }
    let reopened = open(dir.path());
    eprintln!(
        "G7: mesmo log após restart, NEAREST retorna {} vetor(es)",
        count(&reopened, query)
    );
    assert_eq!(
        count(&reopened, query),
        0,
        "sonda: resultado muda quando a memtable esvazia"
    );
    eprintln!(
        "G7: AS OF LSN 1 antes do tombstone=1; após restart={}",
        count(&reopened, "NEAREST([0.1,0.2], 1) AS OF LSN 1")
    );
    assert_eq!(
        count(&reopened, "NEAREST([0.1,0.2], 1) AS OF LSN 1"),
        1,
        "sonda: tombstone futuro também oculta o histórico"
    );
    assert_eq!(count(&reopened, "NEAREST([0.1,0.2], 1) AS OF LSN 2"), 0);
    reopened.rebuild(None).unwrap();
    assert_eq!(count(&reopened, query), 0);
    assert_eq!(count(&reopened, "NEAREST([0.1,0.2], 1) AS OF LSN 1"), 1);
}

#[test]
fn igualdade_indexada_e_scan_concordam_em_valores_aparados_e_vazios() {
    let dir = tempfile::tempdir().unwrap();
    let values = [
        "xyz",
        " xyz",
        "xyz ",
        " xyz ",
        "",
        "  ",
        "sim",
        "\u{2003}xyz\u{2003}",
    ];
    let e = open(dir.path());
    for value in values {
        let mut ep = Episode::new("audit", EventKind::Observation, vec![]);
        ep.attrs.insert("ref".into(), value.into());
        e.append(ep).unwrap();
    }
    let verify = |engine: &Engine| {
        for value in values {
            let indexed = execute(
                &format!("MATCH (n) WHERE n.ref = \"{value}\" RETURN n"),
                engine,
            )
            .unwrap();
            let scan = execute(
                &format!("MATCH (n) WHERE n.ref = \"{value}\" OR n.lsn < 0 RETURN n"),
                engine,
            )
            .unwrap();
            assert_eq!(indexed, scan, "literal={value:?}");
            assert_eq!(indexed.as_array().unwrap().len(), 1);
        }
    };
    verify(&e);
    e.checkpoint_views().unwrap();
    drop(e);
    let reopened = open(dir.path());
    verify(&reopened);
}

#[test]
fn pseudocampos_sao_recusados_em_append_batch_e_idempotente() {
    let dir = tempfile::tempdir().unwrap();
    let e = open(dir.path());
    for key in ["_agent", "_kind"] {
        let mut ep = Episode::new("ana", EventKind::Observation, vec![]);
        ep.attrs.insert(key.into(), "bia".into());
        assert!(e.validar_append(&ep, "retry").is_err());
        assert!(e.append(ep.clone()).is_err());
        assert!(e.append_idempotent(ep, "retry").is_err());
    }
    assert_eq!(e.head(), 0);
    e.append(Episode::new("ana", EventKind::Observation, vec![]))
        .unwrap();
    assert_eq!(e.titular("ana", 10)["eventos"], 1);
    assert_eq!(e.titular("bia", 10)["eventos"], 0);
    assert_eq!(e.titular("bia", 10)["agentes_indexados"], 1);
}
