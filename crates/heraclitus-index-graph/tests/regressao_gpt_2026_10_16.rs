//! Regressões G1/G2/G3: identidade e snapshots temporais.
use heraclitus_core::{Episode, EventKind};
use heraclitus_index_graph::temporal::{EdgeType, TemporalGraph};
use heraclitus_views::View;

fn episode(from: &str, to: &str, op: &str, valid: Option<(u64, u64)>) -> Episode {
    let mut e = Episode::new("audit", EventKind::Observation, vec![]);
    for (k, v) in [
        ("edge_from", from),
        ("edge_to", to),
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
fn ids_compostos_sao_injetivos_com_delimitadores_e_unicode() {
    let fields = ["", "a", "a->b", "b->c", "#", ":", "é", "🦀#->:"];
    let types = [
        EdgeType::Pagou,
        EdgeType::Custom("pagou".into()),
        EdgeType::Custom("x#->:é".into()),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for from in fields {
        for to in fields {
            for kind in &types {
                assert!(seen.insert(TemporalGraph::edge_id(from, to, kind)));
            }
        }
    }
    let mut g = TemporalGraph::new();
    g.apply_episode(0, &episode("a->b", "c", "assert", None));
    g.apply_episode(1, &episode("a", "b->c", "assert", None));
    g.close_edge(&TemporalGraph::edge_id("a", "b->c", &EdgeType::Pagou), 2);
    assert_eq!(g.neighbors(&"a->b".into(), None, 2, 0.0, 0.0).len(), 1);
    assert!(g.neighbors(&"a".into(), None, 2, 0.0, 0.0).is_empty());
    let dir = tempfile::tempdir().unwrap();
    g.checkpoint(dir.path()).unwrap();
    let mut restored = TemporalGraph::new();
    assert!(restored.restore(dir.path()).unwrap());
    assert_eq!(g.state_hash(), restored.state_hash());
    assert_eq!(restored.match_edges(None, None, None, 1, 0.0).len(), 2);
}

#[test]
fn periodos_bitemporais_sobrevivem_a_checkpoint_e_replay() {
    let events = [
        episode("a", "b", "assert", Some((100, 200))),
        episode("a", "b", "retract", None),
        episode("a", "b", "assert", Some((300, 400))),
        episode("a", "b", "retract", None),
        episode("a", "b", "assert", Some((500, 600))),
    ];
    let mut g = TemporalGraph::new();
    for (lsn, e) in events.iter().enumerate() {
        g.apply_episode(lsn as u64, e);
    }
    let dir = tempfile::tempdir().unwrap();
    g.checkpoint(dir.path()).unwrap();
    let mut restored = TemporalGraph::new();
    assert!(restored.restore(dir.path()).unwrap());
    for graph in [&g, &restored] {
        for (lsn, world) in [(0, 100), (2, 300), (4, 500)] {
            let rows = graph.match_edges(None, None, None, lsn, 0.0);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].world_valid_from, Some(world));
            assert_eq!(rows[0].world_valid_to, Some(world + 100));
            assert_eq!(
                graph.neighbors(&"a".into(), None, lsn, 0.0, 0.1)[0].lsn,
                lsn
            );
        }
        for lsn in [1, 3] {
            assert!(graph.match_edges(None, None, None, lsn, 0.0).is_empty());
        }
    }
    let mut replay = TemporalGraph::new();
    for (lsn, e) in events.iter().enumerate() {
        replay.apply_episode(lsn as u64, e);
    }
    assert_eq!(g.state_hash(), replay.state_hash());
    // O formato sem versão não pode ser confundido com o schema corrigido.
    heraclitus_views::ckpt::save(dir.path(), "tgraph", &g).unwrap();
    assert!(!TemporalGraph::new().restore(dir.path()).unwrap());
}

#[test]
fn fingerprint_distingue_option_e_validades_arquivadas() {
    let mut g = TemporalGraph::new();
    g.apply_episode(0, &episode("a", "b", "assert", None));
    let base = g.state_hash();
    let mut bounded = g.clone();
    bounded.edges.values_mut().next().unwrap().valid_to_lsn = Some(u64::MAX);
    assert_ne!(base, bounded.state_hash());
    bounded = g.clone();
    bounded.edges.values_mut().next().unwrap().world_valid_to = Some(u64::MAX);
    assert_ne!(base, bounded.state_hash());
    g.apply_episode(1, &episode("a", "b", "retract", None));
    g.apply_episode(2, &episode("a", "b", "assert", None));
    let mut different = g.clone();
    different
        .edges
        .values_mut()
        .next()
        .unwrap()
        .closed_intervals[0]
        .world_valid_from = Some(10);
    assert_ne!(g.state_hash(), different.state_hash());
}

#[test]
fn regressao_g1_colisao_de_identidade_apaga_uma_relacao() {
    let a = TemporalGraph::edge_id("a->b", "c", &EdgeType::Pagou);
    let b = TemporalGraph::edge_id("a", "b->c", &EdgeType::Pagou);
    assert_ne!(a, b, "relações diferentes precisam de IDs diferentes");
    let mut graph = TemporalGraph::new();
    graph.apply_episode(0, &episode("a->b", "c", "assert", None));
    graph.apply_episode(1, &episode("a", "b->c", "assert", None));
    let rows = graph.match_edges(None, None, None, 1, 0.0);
    eprintln!(
        "G1: ids={a:?}; relações escritas=2, relações visíveis={}; segunda origem={:?}",
        rows.len(),
        graph.match_edges(Some("a"), None, None, 1, 0.0)
    );
    assert_eq!(rows.len(), 2);
    assert_eq!(graph.match_edges(Some("a"), None, None, 1, 0.0).len(), 1);
}

#[test]
fn regressao_g2_reassert_altera_validade_do_passado() {
    let mut graph = TemporalGraph::new();
    graph.apply_episode(0, &episode("a", "b", "assert", Some((100, 200))));
    let old = graph.match_edges(None, None, None, 0, 0.0);
    assert_eq!(old[0].world_valid_from, Some(100));
    graph.apply_episode(1, &episode("a", "b", "retract", None));
    graph.apply_episode(2, &episode("a", "b", "assert", Some((300, 400))));
    let past = graph.match_edges(None, None, None, 0, 0.0);
    assert_eq!(past.len(), 1);
    eprintln!(
        "G2: mesmo AS OF=0: validade anterior={:?}..{:?}, depois={:?}..{:?}",
        old[0].world_valid_from,
        old[0].world_valid_to,
        past[0].world_valid_from,
        past[0].world_valid_to
    );
    assert_eq!(
        past[0].world_valid_from,
        Some(100),
        "o passado deve manter a validade original"
    );
}

#[test]
fn regressao_g3_hash_ignora_validade_do_mundo() {
    let original = episode("a", "b", "assert", Some((100, 200)));
    let mut alterado = original.clone();
    alterado.valid_from = Some(300);
    alterado.valid_to = Some(400);
    let mut a = TemporalGraph::new();
    let mut b = TemporalGraph::new();
    a.apply_episode(0, &original);
    b.apply_episode(0, &alterado);
    assert_ne!(
        a.edges.values().next().unwrap().world_valid_at(150),
        b.edges.values().next().unwrap().world_valid_at(150)
    );
    eprintln!(
        "G3: respostas VALID AT 150 diferentes, hashes iguais={}",
        a.state_hash() == b.state_hash()
    );
    assert_ne!(
        a.state_hash(),
        b.state_hash(),
        "sonda: divergência semântica não detectada pelo fingerprint"
    );
}
