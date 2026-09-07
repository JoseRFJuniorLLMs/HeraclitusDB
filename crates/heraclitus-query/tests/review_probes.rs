//! Guardas de regressão da revisão de código 2026-07-16 (docs/md/falta.md,
//! secção "REVISÃO DE CÓDIGO RUST"). Cada teste nasceu como sonda que FALHAVA
//! (confirmando o bug) e passou a verde com a correção correspondente.

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use heraclitus_query::backend::LogBackend;
use heraclitus_query::execute;
use std::sync::Arc;

fn edge_ep(from: &str, to: &str, etype: &str) -> Episode {
    let mut e = Episode::new("ag", EventKind::Observation, vec![]);
    e.attrs.insert("edge_from".into(), from.into());
    e.attrs.insert("edge_to".into(), to.into());
    e.attrs.insert("edge_type".into(), etype.into());
    e.attrs.insert("edge_op".into(), "assert".into());
    e
}

/// SONDA 1 — sync_bundle off-by-one: um evento appendado DEPOIS do primeiro
/// sync tem de aparecer nas queries de grafo seguintes.
#[test]
fn probe_sync_bundle_sees_appends_after_first_sync() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    log.append(edge_ep("A", "B", "liga")).unwrap(); // lsn 0

    let be = LogBackend::new(log.clone());
    let v = execute("MATCH (a)-[r]->(b) RETURN *", &be).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1, "aresta inicial visível");

    // Appende uma segunda aresta DEPOIS do primeiro sync.
    log.append(edge_ep("C", "D", "liga")).unwrap(); // lsn 1
    let v = execute("MATCH (a)-[r]->(b) RETURN *", &be).unwrap();
    assert_eq!(
        v.as_array().unwrap().len(),
        2,
        "aresta appendada após o 1º sync tem de ficar visível"
    );

    // E uma terceira — a do lsn 1 não pode desaparecer.
    log.append(edge_ep("E", "F", "liga")).unwrap(); // lsn 2
    let v = execute("MATCH (a)-[r]->(b) RETURN *", &be).unwrap();
    assert_eq!(
        v.as_array().unwrap().len(),
        3,
        "todas as 3 arestas visíveis (nenhum lsn saltado pelo bundle)"
    );
}

/// SONDA 2 — ORDER BY numérico: n.lsn ASC tem de sair em ordem numérica
/// (0,1,2,...,11), não lexicográfica (0,1,10,11,2,...).
#[test]
fn probe_order_by_lsn_is_numeric() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    for i in 0..12 {
        log.append(Episode::new(
            "ag",
            EventKind::Observation,
            format!("e{i}").into_bytes(),
        ))
        .unwrap();
    }
    let be = LogBackend::new(log);
    let v = execute("MATCH (n) RETURN n ORDER BY n.lsn ASC", &be).unwrap();
    let lsns: Vec<u64> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["lsn"].as_u64().unwrap())
        .collect();
    let expected: Vec<u64> = (0..12).collect();
    assert_eq!(lsns, expected, "ORDER BY n.lsn ASC deve ser numérico");
}

/// SONDA 3 — GraphMatch: condições WHERE que não são igualdades empurráveis
/// (src/dst/etype) têm de ser aplicadas na mesma (pós-filtro), nunca ignoradas.
#[test]
fn probe_graph_match_applies_non_pushdown_where() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    log.append(edge_ep("Alfa", "Maria", "socio_de")).unwrap();
    log.append(edge_ep("Alfa", "Beto", "pagou")).unwrap();
    let be = LogBackend::new(log);

    // b != "Maria" deve excluir a aresta para Maria.
    let v = execute("MATCH (a)-[r]->(b) WHERE b != \"Maria\" RETURN *", &be).unwrap();
    let rows = v.as_array().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "WHERE b != \"Maria\" tem de filtrar: {rows:?}"
    );
    assert_eq!(rows[0]["to"].as_str().unwrap(), "Beto");
}

/// GUARDA R1 (pushdown sob OR): a igualdade `b = "Maria"` só vale num ramo do
/// OR — empurrá-la ao match_edges perderia a aresta do outro ramo.
#[test]
fn probe_graph_match_or_does_not_overpush() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    log.append(edge_ep("Alfa", "Maria", "socio_de")).unwrap();
    log.append(edge_ep("Alfa", "Beto", "pagou")).unwrap();
    let be = LogBackend::new(log);

    let v = execute(
        "MATCH (a)-[r]->(b) WHERE b = \"Maria\" OR r.type = \"pagou\" RETURN *",
        &be,
    )
    .unwrap();
    assert_eq!(
        v.as_array().unwrap().len(),
        2,
        "OR não pode restringir o match ao pushdown de um só ramo"
    );
}

/// GUARDA R19 (precedência SQL): `A OR B AND C` = `A OR (B AND C)`, não
/// `(A OR B) AND C` como na avaliação esquerda→direita antiga.
#[test]
fn probe_and_binds_tighter_than_or() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    let mut e = Episode::new("alice", EventKind::Observation, b"x".to_vec());
    e.attrs.insert("cor".into(), "azul".into());
    log.append(e).unwrap(); // alice/azul
    let mut e = Episode::new("bob", EventKind::Observation, b"x".to_vec());
    e.attrs.insert("cor".into(), "verde".into());
    log.append(e).unwrap(); // bob/verde
    let be = LogBackend::new(log);

    // alice OR (cor=verde AND agent=carol) → só a alice casa.
    // Com (alice OR cor=verde) AND agent=carol → nada casaria.
    let v = execute(
        "MATCH (n) WHERE n.agent_id = \"alice\" OR n.cor = \"verde\" AND n.agent_id = \"carol\" RETURN n",
        &be,
    )
    .unwrap();
    let rows = v.as_array().unwrap();
    assert_eq!(rows.len(), 1, "AND liga mais forte que OR: {rows:?}");
    assert_eq!(rows[0]["agent_id"].as_str().unwrap(), "alice");
}

/// GUARDA R12: assert → retract → assert reabre a aresta num novo intervalo,
/// preservando a história (AS OF entre o retract e o re-assert não a vê).
#[test]
fn probe_edge_reassert_after_retract_revives() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    let mk = |op: &str| {
        let mut e = Episode::new("ag", EventKind::Observation, vec![]);
        e.attrs.insert("edge_from".into(), "Alfa".into());
        e.attrs.insert("edge_to".into(), "Maria".into());
        e.attrs.insert("edge_type".into(), "socio_de".into());
        e.attrs.insert("edge_op".into(), op.into());
        e
    };
    log.append(mk("assert")).unwrap(); // lsn 0: nasce
    log.append(mk("retract")).unwrap(); // lsn 1: fecha
    log.append(mk("assert")).unwrap(); // lsn 2: renasce
    let be = LogBackend::new(log);

    // Agora: viva de novo.
    let v = execute("MATCH (a)-[r]->(b) RETURN *", &be).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1, "re-assert reabre a aresta");

    // AS OF LSN 2 = snapshot após o retract, antes do re-assert: morta.
    let v = execute("MATCH (a)-[r]->(b) AS OF LSN 2 RETURN *", &be).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 0, "período fechado preservado");

    // AS OF LSN 1 = só o primeiro assert: viva no primeiro intervalo.
    let v = execute("MATCH (a)-[r]->(b) AS OF LSN 1 RETURN *", &be).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1, "história antiga intacta");
}

/// Auditoria recursiva 2026-09-05 (A23): a forma NUA de uma variável de padrão
/// (`r`, sem `.campo`) resolve para o `edge_id` no pós-filtro, mas o pushdown
/// empurrava-a como TIPO da aresta. Um `edge_id` nunca é igual a uma chave de
/// tipo, portanto `match_edges` devolvia vazio e o pós-filtro — que teria
/// aceite a linha — nunca a via: o pushdown era DISJUNTO, não superconjunto.
#[test]
fn padrao_de_relacao_aceita_r_nu_igual_ao_edge_id() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    log.append(edge_ep("alice", "bob", "socio_de")).unwrap();
    log.append(edge_ep("alice", "carla", "pagou")).unwrap();
    let be = LogBackend::new(log);

    let linhas = |q: &str| -> Vec<serde_json::Value> {
        execute(q, &be).unwrap().as_array().unwrap().clone()
    };

    // O `edge_id` vem do próprio RETURN — se o formato mudar, o teste morre.
    let todas = linhas("MATCH (a)-[r]->(b) RETURN *");
    assert_eq!(todas.len(), 2);
    let edge_id = todas.iter().find(|r| r["to"] == "bob").unwrap()["edge_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Reutilizar o valor devolvido tem de casar a MESMA aresta. Antes: 0 linhas.
    let v = linhas(&format!(
        "MATCH (a)-[r]->(b) WHERE r = \"{edge_id}\" RETURN *"
    ));
    assert_eq!(v.len(), 1, "`r = <edge_id>` tem de casar a aresta: {v:?}");
    assert_eq!(v[0]["to"].as_str().unwrap(), "bob");

    // NÃO REGRIDE: a forma nua de um nó continua a ser empurrada como id (o
    // slot pedido é "id"), e filtra mesmo — com 2 arestas, devolve 1.
    let v = linhas("MATCH (a)-[r]->(b) WHERE b = \"bob\" RETURN *");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0]["to"].as_str().unwrap(), "bob");

    // NÃO REGRIDE: `r.type` (Prop com o campo certo) continua empurrado.
    assert_eq!(
        linhas("MATCH (a)-[r]->(b) WHERE r.type = \"pagou\" RETURN *").len(),
        1
    );
    assert_eq!(
        linhas("MATCH (a)-[r]->(b) WHERE r.type = \"inexistente\" RETURN *").len(),
        0
    );
    // NÃO REGRIDE: `r.id` já funcionava (o slot "type" não casava o campo).
    assert_eq!(
        linhas(&format!(
            "MATCH (a)-[r]->(b) WHERE r.id = \"{edge_id}\" RETURN *"
        ))
        .len(),
        1
    );
}
