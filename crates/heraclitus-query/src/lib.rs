//! heraclitus-query — Cypher/GQL subset + temporal AS OF (§3.12).
//!
//! We do not invent a language. The parser is pest-based and fuzzed from
//! day one; the planner is rule-based (v0) and `EXPLAIN` is available from
//! v0.1. `CREATE` lowers to a log append; reads carry an optional snapshot
//! (`AS OF LSN n` / `AS OF TIMESTAMP t`).

pub mod ast;
pub mod backend;
pub mod fusion;
pub mod plan;

use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "gql.pest"]
pub struct GqlParser;

use ast::*;
use heraclitus_core::HeraclitusError;

/// Parse a query string into the AST. Never panics on any input — fuzz gate.
pub fn parse(input: &str) -> Result<Query, HeraclitusError> {
    let mut pairs =
        GqlParser::parse(Rule::query, input).map_err(|e| HeraclitusError::Query(e.to_string()))?;
    let query = pairs
        .next()
        .ok_or_else(|| HeraclitusError::Query("empty parse".into()))?;
    ast::build_query(query)
}

/// Parse, plan, and render the plan — `EXPLAIN <stmt>` entry point.
pub fn explain(input: &str) -> Result<String, HeraclitusError> {
    let q = parse(input)?;
    let p = plan::plan(&q.stmt);
    Ok(plan::render(&p))
}

/// Parse and execute against a backend. If the query was prefixed with
/// EXPLAIN, returns the plan text instead of rows.
pub fn execute(
    input: &str,
    be: &dyn backend::QueryBackend,
) -> Result<serde_json::Value, HeraclitusError> {
    let q = parse(input)?;
    let p = plan::plan(&q.stmt);
    if q.explain {
        return Ok(serde_json::Value::String(plan::render(&p)));
    }
    // M18: the consistency contract is enforced before any rows are produced —
    // a query that demands more freshness than the backend can serve fails
    // explicitly instead of returning stale data.
    if let Some(required) = q.require_lsn {
        let head = be.head()?;
        if head < required {
            return Err(HeraclitusError::Query(format!(
                "consistency requirement not met: REQUIRE LSN >= {required}, but head is {head}"
            )));
        }
    }
    plan::execute(&p, be)
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend::LogBackend;
    use heraclitus_core::{Episode, EventKind, FsyncPolicy};
    use heraclitus_log::Log;
    use proptest::prelude::*;
    use std::sync::Arc;

    fn seeded_backend() -> (tempfile::TempDir, LogBackend) {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        for i in 0..10 {
            let mut e = Episode::new(
                if i % 2 == 0 { "alice" } else { "bob" },
                EventKind::Observation,
                format!("the river event {i}").into_bytes(),
            );
            e.attrs.insert("topic".into(), "rivers".into());
            log.append(e).unwrap();
        }
        (dir, LogBackend::new(log))
    }

    #[test]
    fn explain_works() {
        let s =
            explain("MATCH (n) WHERE n.agent_id = \"alice\" RETURN n ORDER BY n.lsn DESC LIMIT 3")
                .unwrap();
        assert!(s.contains("ScanFilter"), "{s}");
        assert!(s.contains("Limit(3)"), "{s}");
        // EXPLAIN prefix goes through execute() too.
        let (_d, be) = seeded_backend();
        let v = execute("EXPLAIN MATCH (n) RETURN n", &be).unwrap();
        assert!(v.as_str().unwrap().contains("ScanFilter"));
    }

    #[test]
    fn match_where_filters() {
        let (_d, be) = seeded_backend();
        let v = execute("MATCH (n) WHERE n.agent_id = \"alice\" RETURN n", &be).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 5);
        let v = execute("MATCH (n) WHERE n.topic = \"rivers\" RETURN n LIMIT 4", &be).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 4);
    }

    #[test]
    fn match_agent_id_pushes_down_to_zone_map_skip() {
        // SPEC-010 pushdown at the query layer: `WHERE agent_id = "alice"` routes
        // through `scan_agent`, which prunes bob-only sealed segments (skip-I/O)
        // — yet the result is exactly alice's events (post-filter revalidates).
        let dir = tempfile::tempdir().unwrap();
        // Small segments + grouped agents ⇒ whole segments are single-agent and
        // therefore skippable.
        let log = Arc::new(Log::open(dir.path(), 2048, FsyncPolicy::Always).unwrap());
        for i in 0..60 {
            log.append(Episode::new(
                "alice",
                EventKind::Observation,
                format!("alice-{i:04}-xxxxxxxxxxxxxxxxxxxx").into_bytes(),
            ))
            .unwrap();
        }
        for i in 0..60 {
            log.append(Episode::new(
                "bob",
                EventKind::Observation,
                format!("bob-{i:04}-xxxxxxxxxxxxxxxxxxxx").into_bytes(),
            ))
            .unwrap();
        }
        assert!(
            log.sealed_segments().len() >= 3,
            "need multiple sealed segments so pruning has something to skip"
        );

        let be = LogBackend::new(log);
        let v = execute("MATCH (n) WHERE n.agent_id = \"alice\" RETURN n", &be).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 60, "exactly alice's 60 events, none dropped, no bob");
        assert!(
            rows.iter().all(|r| r["agent_id"].as_str() == Some("alice")),
            "pruning + post-filter must yield only alice"
        );
    }

    #[test]
    fn match_session_id_pushes_down_to_zone_map_skip() {
        // SPEC-010 pushdown generalized to `session_id` — the core "load this
        // session" query for agentic memory. Segments of other sessions are
        // pruned, yet the result is exactly session "s-A".
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 2048, FsyncPolicy::Always).unwrap());
        let push = |session: &str, i: usize| {
            let mut e = Episode::new(
                "agent",
                EventKind::Observation,
                format!("{session}-{i:04}-xxxxxxxxxxxxxxxxxxxx").into_bytes(),
            );
            e.session_id = session.to_string();
            log.append(e).unwrap();
        };
        for i in 0..60 {
            push("s-A", i);
        }
        for i in 0..60 {
            push("s-B", i);
        }
        assert!(log.sealed_segments().len() >= 3);

        let be = LogBackend::new(log);
        let v = execute("MATCH (n) WHERE n.session_id = \"s-A\" RETURN n", &be).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 60, "exactly session s-A, none dropped, no s-B");
        assert!(rows
            .iter()
            .all(|r| r["session_id"].as_str() == Some("s-A")));
    }

    #[test]
    fn spec028_zone_maps_are_registered_and_reused_across_queries() {
        // SPEC-028/031 wired: o scanner é persistente no backend; a 1ª query
        // regista os zone maps no ArtifactRegistry e a 2ª reutiliza-os do cache
        // em RAM (sem rebuild) — o registry cataloga cada um.
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 2048, FsyncPolicy::Always).unwrap());
        for i in 0..90 {
            log.append(Episode::new(
                if i % 2 == 0 { "alice" } else { "bob" },
                EventKind::Observation,
                format!("e{i:04}-xxxxxxxxxxxxxxxxxxxxxxxx").into_bytes(),
            ))
            .unwrap();
        }
        let n_sealed = log.sealed_segments().len();
        assert!(n_sealed >= 2);
        let be = LogBackend::new(log);

        let q = "MATCH (n) WHERE n.agent_id = \"alice\" RETURN n";
        let v1 = execute(q, &be).unwrap();
        let (artifacts, cached) = be.artifact_stats();
        assert_eq!(artifacts, n_sealed, "um artefacto por zone map de segmento");
        assert_eq!(cached, n_sealed, "zone maps vivos em RAM entre queries");

        // 2ª query: mesmos resultados, cache persistente (nada rebuildado).
        let v2 = execute(q, &be).unwrap();
        assert_eq!(v1, v2);
        assert_eq!(be.artifact_stats(), (n_sealed, n_sealed));
    }

    #[test]
    fn spec032_adaptive_fallback_when_skip_scan_proves_slow() {
        // SPEC-032 wired: se o EMA diz que o skip-scan é >20% mais lento que o
        // window-scan, scan_builtin_eq devolve None (fallback) — e a query
        // continua CORRETA pelo window scan + pós-filtro.
        use backend::QueryBackend as _;
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        for i in 0..10 {
            log.append(Episode::new(
                if i % 2 == 0 { "alice" } else { "bob" },
                EventKind::Observation,
                format!("e{i}").into_bytes(),
            ))
            .unwrap();
        }
        let be = LogBackend::new(log);

        // Histórico: skip lento (1ms) vs window rápido (0.1ms) → fallback.
        for _ in 0..5 {
            be.observe_access_path("skip", 1_000_000.0);
            be.observe_access_path("window", 100_000.0);
        }
        let hint = be.scan_builtin_eq("agent_id", "alice", None).unwrap();
        assert!(hint.is_none(), "EMA manda cair para o window scan");
        // A query continua correta (planner usa o scan + pós-filtro).
        let v = execute("MATCH (n) WHERE n.agent_id = \"alice\" RETURN n", &be).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 5);

        // Histórico invertido: skip rápido → o hint volta a existir.
        for _ in 0..50 {
            be.observe_access_path("skip", 10_000.0);
        }
        let hint = be.scan_builtin_eq("agent_id", "alice", None).unwrap();
        assert!(hint.is_some(), "skip volta a ser o caminho preferido");
    }

    #[test]
    fn why_until_returns_minimal_causal_chain() {
        // SPEC-014: WHY(effect) UNTIL "cause" returns the shortest path in the
        // parent DAG, not the full ancestor trace.
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());

        let mk = |body: &[u8], parents: &[heraclitus_core::EventId]| {
            let mut e = Episode::new("a", EventKind::Observation, body.to_vec());
            e.parents = parents.to_vec();
            e
        };
        let e0 = mk(b"e0", &[]);
        let (id0,) = (e0.id,);
        let e1 = mk(b"e1", &[id0]);
        let id1 = e1.id;
        let e2 = mk(b"e2", &[id1]);
        let id2 = e2.id;
        // e3 has two parents: e2 (long path) and e0 (direct shortcut).
        let e3 = mk(b"e3", &[id2, id0]);
        let id3 = e3.id;
        for e in [e0, e1, e2, e3] {
            log.append(e).unwrap();
        }
        let be = LogBackend::new(log);

        let chain_of = |v: &serde_json::Value| -> Vec<String> {
            v["minimal_chain"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect()
        };

        // WHY(e3) UNTIL e0 → shortest is the direct shortcut edge [e3, e0].
        let v = execute(&format!("WHY(\"{id3}\") UNTIL \"{id0}\""), &be).unwrap();
        assert_eq!(v["linked"].as_bool(), Some(true));
        assert_eq!(chain_of(&v), vec![id3.to_string(), id0.to_string()]);

        // WHY(e3) UNTIL e1 → must go through e2: [e3, e2, e1].
        let v = execute(&format!("WHY(\"{id3}\") UNTIL \"{id1}\""), &be).unwrap();
        assert_eq!(chain_of(&v), vec![id3.to_string(), id2.to_string(), id1.to_string()]);

        // A cause that is not an ancestor → not linked, empty chain.
        let stranger = mk(b"s", &[]);
        let v = execute(&format!("WHY(\"{id3}\") UNTIL \"{}\"", stranger.id), &be).unwrap();
        assert_eq!(v["linked"].as_bool(), Some(false));
        assert!(chain_of(&v).is_empty());
    }

    #[test]
    fn temporal_as_of_lsn() {
        // M4 acceptance gate: temporal query test.
        let (_d, be) = seeded_backend();
        let all = execute("MATCH (n) RETURN n", &be).unwrap();
        assert_eq!(all.as_array().unwrap().len(), 10);
        let v = execute("MATCH (n) AS OF LSN 5 RETURN n", &be).unwrap();
        let rows = v.as_array().unwrap();
        // AS OF LSN 5 = snapshot containing lsn < 5
        assert_eq!(rows.len(), 5);
        assert!(rows.iter().all(|r| r["lsn"].as_u64().unwrap() < 5));
    }

    #[test]
    fn temporal_as_of_timestamp_resolves_to_lsn() {
        // Audit #4 regression: TIMESTAMP must be resolved via the backend,
        // never reinterpreted as a raw LSN bound.
        let (_d, be) = seeded_backend();
        let first_ts = {
            use backend::QueryBackend as _;
            let (_, e) = &be.scan(None).unwrap()[0];
            e.ts_hlc >> 16
        };
        // Before the first event existed: snapshot must be empty.
        let v = execute(
            &format!(
                "MATCH (n) AS OF TIMESTAMP {} RETURN n",
                first_ts.saturating_sub(10)
            ),
            &be,
        )
        .unwrap();
        assert_eq!(
            v.as_array().unwrap().len(),
            0,
            "pre-history snapshot must be empty"
        );
        // Far in the future: everything is visible.
        let v = execute(
            &format!(
                "MATCH (n) AS OF TIMESTAMP {} RETURN n",
                first_ts + 1_000_000
            ),
            &be,
        )
        .unwrap();
        assert_eq!(v.as_array().unwrap().len(), 10);
    }

    #[test]
    fn create_appends_to_log() {
        let (_d, be) = seeded_backend();
        let v = execute("CREATE (n:Observation {note: \"fresh\", weight: 2})", &be).unwrap();
        assert_eq!(v["lsn"].as_u64().unwrap(), 10);
        let back = execute("MATCH (n) WHERE n.note = \"fresh\" RETURN n", &be).unwrap();
        assert_eq!(back.as_array().unwrap().len(), 1);
    }

    /// Seeds a small provenance chain a←b←c plus a distilled fact f from {a,b},
    /// returning the backend and the string ids of a/b/c/f.
    fn graph_backend() -> (tempfile::TempDir, LogBackend, [String; 4]) {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let mut a = Episode::new("ag", EventKind::Observation, b"a".to_vec());
        a.attrs.insert("edge_type".into(), "socio_de".into());
        let mut b = Episode::new("ag", EventKind::Observation, b"b".to_vec());
        b.attrs.insert("edge_type".into(), "pagou".into());
        b.parents.push(a.id);
        let mut c = Episode::new("ag", EventKind::Observation, b"c".to_vec());
        c.parents.push(b.id);
        let mut f = Episode::new("distill", EventKind::FactDerived, b"f".to_vec());
        f.attrs.insert("edge_type".into(), "similar_a".into());
        f.parents.push(a.id);
        f.parents.push(b.id);
        let ids = [
            a.id.to_string(),
            b.id.to_string(),
            c.id.to_string(),
            f.id.to_string(),
        ];
        for e in [a, b, c, f] {
            log.append(e).unwrap();
        }
        (dir, LogBackend::new(log), ids)
    }

    #[test]
    fn neighbors_and_traverse() {
        let (_d, be, [a, b, _c, f]) = graph_backend();
        // a was referenced by b (pagou) and f (similar_a) -> 2 out-neighbors.
        let v = execute(&format!("NEIGHBORS (\"{a}\")"), &be).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let tos: std::collections::BTreeSet<&str> =
            rows.iter().map(|r| r["to"].as_str().unwrap()).collect();
        assert!(tos.contains(b.as_str()) && tos.contains(f.as_str()));

        // Edge-type filter narrows to just the `similar_a` link (the fact).
        let v = execute(&format!("NEIGHBORS (\"{a}\", \"similar_a\")"), &be).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["to"].as_str().unwrap(), f);

        // TRAVERSE from a reaches b and c (a→b→c provenance chain) and f.
        let v = execute(&format!("TRAVERSE (\"{a}\", 3)"), &be).unwrap();
        let reached: std::collections::BTreeSet<&str> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["node"].as_str().unwrap())
            .collect();
        assert!(reached.contains(b.as_str()));
        assert!(reached.contains(_c.as_str()));
        assert!(reached.contains(f.as_str()));
    }

    #[test]
    fn neighbors_explain_and_as_of() {
        let (_d, be, [a, _b, _c, _f]) = graph_backend();
        let s = explain(&format!("NEIGHBORS (\"{a}\")")).unwrap();
        assert!(s.contains("GraphNeighbors"), "{s}");
        // AS OF LSN 1 hides edges created at lsn >= 1: b (lsn 1) and f (lsn 3)
        // both reference a but neither edge is alive yet at as_of=1.
        let v = execute(&format!("NEIGHBORS (\"{a}\") AS OF LSN 1"), &be).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 0);
    }

    /// Seeds explicit, mutable edges: Alfa-socio-Maria asserted @0 then retracted
    /// @2; Alfa-pagou-Beto asserted @1 (stays open).
    fn edge_backend() -> (tempfile::TempDir, LogBackend) {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let mk = |from: &str, to: &str, etype: &str, op: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), from.into());
            e.attrs.insert("edge_to".into(), to.into());
            e.attrs.insert("edge_type".into(), etype.into());
            e.attrs.insert("edge_op".into(), op.into());
            e
        };
        log.append(mk("Alfa", "Maria", "socio_de", "assert"))
            .unwrap(); // lsn 0
        log.append(mk("Alfa", "Beto", "pagou", "assert")).unwrap(); // lsn 1
        log.append(mk("Alfa", "Maria", "socio_de", "retract"))
            .unwrap(); // lsn 2
        (dir, LogBackend::new(log))
    }

    #[test]
    fn edge_match_time_travels() {
        let (_d, be) = edge_backend();
        // Now (no AS OF): the socio edge was retracted @2, only pagou survives.
        let v = execute("MATCH (a)-[r]->(b) RETURN *", &be).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["to"].as_str().unwrap(), "Beto");

        // AS OF LSN 2 = snapshot just before the retract: both edges alive.
        let v = execute("MATCH (a)-[r]->(b) AS OF LSN 2 RETURN *", &be).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);

        // AS OF LSN 1 = only the socio edge exists yet (pagou is asserted @1).
        let v = execute("MATCH (a)-[r]->(b) AS OF LSN 1 RETURN *", &be).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["to"].as_str().unwrap(), "Maria");
    }

    #[test]
    fn edge_match_filters_and_projection() {
        let (_d, be) = edge_backend();
        // Inline type label filters to pagou; project just b.id and r.type.
        let v = execute("MATCH (a)-[r:pagou]->(b) RETURN b.id, r.type", &be).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["b.id"].as_str().unwrap(), "Beto");
        assert_eq!(rows[0]["r.type"].as_str().unwrap(), "pagou");

        // WHERE constraint on the destination var + AS OF before the retract.
        let v = execute(
            "MATCH (a)-[r]->(b) WHERE b = \"Maria\" AS OF LSN 2 RETURN *",
            &be,
        )
        .unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);

        // EXPLAIN shows the new graph-match operator.
        let s = explain("MATCH (a)-[r:socio_de]->(b) RETURN *").unwrap();
        assert!(s.contains("GraphMatch"), "{s}");
    }

    /// Builds a tiny fraud-style dataset anchored on event A. Four candidates,
    /// each child of A, are designed so that each single channel is topped by a
    /// *different* candidate, while the consensus candidate X (strong on all
    /// three, top on none) only wins under fusion. Returns (backend, A id, X id).
    fn fraud_backend() -> (tempfile::TempDir, LogBackend, String, String) {
        use heraclitus_core::ProductPoint;
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());

        let anchor = Episode::new("ag", EventKind::Observation, b"anchor".to_vec());
        let a_id = anchor.id;
        log.append(anchor).unwrap();

        let child = |conf: &str, hyp: f32, text: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, text.as_bytes().to_vec());
            e.parents.push(a_id);
            e.attrs.insert("confidence".into(), conf.into());
            e.embedding = Some(ProductPoint {
                hyp: vec![hyp],
                sph: vec![],
                euc: vec![],
            });
            e
        };
        // X: middle on all three (graph .7, vector near, text present).
        let x = child("0.7", 0.65, "fraude");
        let x_id = x.id;
        // W: graph-only winner (conf 1.0, far vector, no text).
        let w = child("1.0", 0.0, "pagamento rotineiro");
        // Y: vector-only winner (embedding == query, low graph, no text).
        let y = child("0.2", 0.5, "transferencia comum");
        // Z: text-only winner (tf 2, low graph, far vector).
        let z = child("0.2", 0.95, "fraude fraude");
        for e in [x, w, y, z] {
            log.append(e).unwrap();
        }
        (
            dir,
            LogBackend::new(log),
            a_id.to_string(),
            x_id.to_string(),
        )
    }

    #[test]
    fn fusion_beats_single_channels_on_fraud_dataset() {
        // THE M10 GATE: fused top-1 is the consensus candidate X, which no single
        // channel ranks first. The query also exercises the FUSE grammar.
        let (_d, be, a_id, x_id) = fraud_backend();
        let q = format!("FUSE (\"fraude\", [0.5], \"{a_id}\", 10)");
        let v = execute(&q, &be).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 4, "all four candidates surface");

        // Rows are returned already sorted by fused score: the winner is X.
        assert_eq!(rows[0]["id"].as_str().unwrap(), x_id, "fusion must pick X");

        // Each single channel is topped by someone *other* than X — that is the
        // whole point of fusing.
        let top_by = |field: &str| -> String {
            rows.iter()
                .max_by(|a, b| {
                    a[field]
                        .as_f64()
                        .unwrap()
                        .total_cmp(&b[field].as_f64().unwrap())
                })
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_ne!(top_by("graph_score"), x_id, "graph-only would miss X");
        assert_ne!(top_by("vector_score"), x_id, "vector-only would miss X");
        assert_ne!(top_by("text_score"), x_id, "text-only would miss X");

        // Reproducible: same query, identical scores.
        let v2 = execute(&q, &be).unwrap();
        assert_eq!(v, v2, "fused scores must be reproducible");
    }

    #[test]
    fn decide_emits_actions_and_is_idempotent() {
        // M15: rules fire Action events into the log; a second DECIDE emits
        // nothing new (idempotent via content-addressed action_id).
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let edge = |from: &str, to: &str, etype: &str, conf: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), from.into());
            e.attrs.insert("edge_to".into(), to.into());
            e.attrs.insert("edge_type".into(), etype.into());
            e.attrs.insert("confidence".into(), conf.into());
            e
        };
        for leaf in ["L1", "L2", "L3", "L4"] {
            log.append(edge("H", leaf, "socio_de", "1.0")).unwrap();
        }
        log.append(edge("X", "Y", "fraud_partner", "0.9")).unwrap();
        let be = LogBackend::new(log);

        // First DECIDE: the hub and the fraud edge are flagged as Action events.
        let v = execute("DECIDE ()", &be).unwrap();
        let fired: Vec<&str> = v["fired"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["action_id"].as_str().unwrap())
            .collect();
        assert!(fired.contains(&"flag_anomaly:H"), "fired: {fired:?}");
        assert!(fired.contains(&"flag_fraud:X->Y"), "fired: {fired:?}");
        assert!(v["skipped"].as_array().unwrap().is_empty());

        // Decision = event: the actions are now in the log.
        let actions = execute("MATCH (n:Action) RETURN n", &be).unwrap();
        assert_eq!(actions.as_array().unwrap().len(), fired.len());

        // Second DECIDE: idempotent — nothing new, everything skipped.
        let v2 = execute("DECIDE ()", &be).unwrap();
        assert!(
            v2["fired"].as_array().unwrap().is_empty(),
            "no duplicate actions"
        );
        assert_eq!(v2["skipped"].as_array().unwrap().len(), fired.len());

        assert!(explain("DECIDE ()").unwrap().contains("DecisionEngine"));
    }

    #[test]
    fn require_lsn_enforces_consistency() {
        // M18: REQUIRE LSN >= X passes when the backend has reached X and fails
        // explicitly (not stale data) when it has not.
        let (_d, be) = seeded_backend(); // 10 events ⇒ head = 10
        use backend::QueryBackend as _;
        assert_eq!(be.head().unwrap(), 10);

        // Satisfied: head (10) >= 10.
        let ok = execute("REQUIRE LSN >= 10 MATCH (n) RETURN n", &be).unwrap();
        assert_eq!(ok.as_array().unwrap().len(), 10);

        // Unmet: requiring a future LSN fails explicitly with a clear message.
        let err = execute("REQUIRE LSN >= 11 MATCH (n) RETURN n", &be).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("consistency requirement not met"), "{msg}");
        assert!(msg.contains("head is 10"), "{msg}");

        // Composes with EXPLAIN (no execution ⇒ no enforcement) and with AS OF.
        assert!(parse("REQUIRE LSN >= 5 MATCH (n) AS OF LSN 3 RETURN n").is_ok());
        let ok2 = execute("REQUIRE LSN >= 5 RECALL (\"river\", 2)", &be).unwrap();
        assert_eq!(ok2.as_array().unwrap().len(), 2);
    }

    #[test]
    fn adapt_learns_threshold_from_feedback() {
        // M17: feedback events label past flags; ADAPT learns a threshold with
        // measurably better precision than the default.
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let feedback = |score: &str, verdict: &str| {
            let mut e = Episode::new("analyst", EventKind::Observation, vec![]);
            e.attrs
                .insert("feedback_rule".into(), "flag_anomaly".into());
            e.attrs.insert("score".into(), score.into());
            e.attrs.insert("verdict".into(), verdict.into());
            e
        };
        // Confirms well above 1.5; a reject sits at 1.6 (default would flag it).
        for (score, verdict) in [
            ("3.0", "confirm"),
            ("2.5", "confirm"),
            ("2.0", "confirm"),
            ("1.6", "reject"),
            ("1.0", "reject"),
        ] {
            log.append(feedback(score, verdict)).unwrap();
        }
        let be = LogBackend::new(log);

        let v = execute("ADAPT ()", &be).unwrap();
        assert_eq!(v["samples"].as_u64().unwrap(), 5);
        let def_f1 = v["default"]["f1"].as_f64().unwrap();
        let adp_f1 = v["adapted"]["f1"].as_f64().unwrap();
        assert!(
            adp_f1 > def_f1,
            "learning improves F1: {adp_f1} vs {def_f1}"
        );
        assert!(
            (v["adapted"]["precision"].as_f64().unwrap() - 1.0).abs() < 1e-6,
            "learned precision perfect"
        );
        let learned = v["learned_threshold"].as_f64().unwrap();
        assert!(
            learned > 1.6 && learned <= 2.0,
            "learned threshold: {learned}"
        );

        assert!(explain("ADAPT ()").unwrap().contains("AdaptiveLearner"));
        // No feedback ⇒ keep the default (1.5), no crash.
        let empty = execute("ADAPT () AS OF LSN 0", &be).unwrap();
        assert_eq!(empty["samples"].as_u64().unwrap(), 0);
        assert!((empty["learned_threshold"].as_f64().unwrap() - 1.5).abs() < 1e-6);
    }

    #[test]
    fn fused_lsn_is_real_for_graph_only_candidate() {
        // Audit bug C: a candidate that surfaces only via the graph channel must
        // carry its real lsn, not 0. Anchor A at lsn 0; child B (parent A) at
        // lsn 1 has no embedding/text, so it is a graph-only fusion candidate.
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let a = Episode::new("ag", EventKind::Observation, b"anchor".to_vec());
        let a_id = a.id;
        log.append(a).unwrap(); // lsn 0
        let mut b = Episode::new("ag", EventKind::Observation, b"child".to_vec());
        b.parents.push(a_id);
        let b_id = b.id.to_string();
        log.append(b).unwrap(); // lsn 1
        let be = LogBackend::new(log);

        // NEIGHBORS now reports the edge's lsn (= the candidate's lsn).
        let n = execute(&format!("NEIGHBORS (\"{a_id}\")"), &be).unwrap();
        let row = &n.as_array().unwrap()[0];
        assert_eq!(row["to"].as_str().unwrap(), b_id);
        assert_eq!(row["lsn"].as_u64().unwrap(), 1, "real lsn, not 0");

        // FUSE: B is graph-only (no embedding/text) yet gets lsn 1, not 0.
        let f = execute(&format!("FUSE (\"nothing\", [9.9], \"{a_id}\", 5)"), &be).unwrap();
        let hit = f
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["id"] == b_id)
            .unwrap();
        assert_eq!(
            hit["lsn"].as_u64().unwrap(),
            1,
            "graph-only candidate keeps its real lsn"
        );
    }

    #[test]
    fn as_of_lsn_zero_is_empty_snapshot() {
        // Audit bug A: AS OF LSN 0 means "lsn < 0" = empty, for graph and entity
        // reads too — not just MATCH/scan. (Regression: as_of_point(0) used to
        // keep valid_from==0 edges.)
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let mut edge = Episode::new("ag", EventKind::Observation, vec![]);
        edge.attrs.insert("edge_from".into(), "A".into());
        edge.attrs.insert("edge_to".into(), "B".into());
        edge.attrs.insert("edge_type".into(), "socio_de".into());
        log.append(edge).unwrap(); // lsn 0
        let mut mention = Episode::new("ag", EventKind::Observation, vec![]);
        mention.attrs.insert("entity_key".into(), "CPF:1".into());
        log.append(mention).unwrap(); // lsn 1
        let be = LogBackend::new(log);

        // The baseline everyone agrees on: MATCH (n) AS OF LSN 0 is empty.
        assert!(execute("MATCH (n) AS OF LSN 0 RETURN n", &be)
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        // Graph + entity reads must agree.
        assert!(execute("NEIGHBORS (\"A\") AS OF LSN 0", &be)
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        assert!(execute("MATCH (a)-[r]->(b) AS OF LSN 0 RETURN *", &be)
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        assert!(execute("TRAVERSE (\"A\", 3) AS OF LSN 0", &be)
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        assert!(execute("COMMUNITY (\"A\") AS OF LSN 0", &be)
            .unwrap()
            .is_null());
        assert!(execute("METRICS (\"A\") AS OF LSN 0", &be)
            .unwrap()
            .is_null());
        assert!(
            execute("HYPOTHESES (\"A\", \"B\", \"socio_de\") AS OF LSN 0", &be)
                .unwrap()
                .is_null()
        );
        assert!(execute("RESOLVE (\"CPF:1\") AS OF LSN 0", &be).unwrap()["entity_id"].is_null());
        assert!(execute("CLUSTER (\"CPF:1\") AS OF LSN 0", &be)
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());

        // Sanity: AS OF LSN 1 already sees the edge (lsn 0 < 1).
        assert_eq!(
            execute("NEIGHBORS (\"A\") AS OF LSN 1", &be)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn nested_simulate_composes_mutations() {
        // Audit bug B: an inner SIMULATE must see the outer SIMULATE's edge, not
        // rebuild from the real log. Three separate triangles; two nested ADDs
        // bridge A→B→C, so A1's community spans all nine.
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let edge = |from: &str, to: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), from.into());
            e.attrs.insert("edge_to".into(), to.into());
            e.attrs.insert("edge_type".into(), "socio_de".into());
            e
        };
        for ring in [["A1", "A2", "A3"], ["B1", "B2", "B3"], ["C1", "C2", "C3"]] {
            for i in 0..3 {
                log.append(edge(ring[i], ring[(i + 1) % 3])).unwrap();
            }
        }
        let be = LogBackend::new(log);

        // Reality: A1's community is just triangle A.
        assert_eq!(
            execute("COMMUNITY (\"A1\")", &be).unwrap()["members"]
                .as_array()
                .unwrap()
                .len(),
            3
        );

        // Nested counterfactual: bridge A-B (outer) and B-C (inner) compose, so
        // all three triangles join.
        let q = "SIMULATE ADD EDGE (\"A1\", \"B1\", \"socio_de\") \
                 THEN SIMULATE ADD EDGE (\"B1\", \"C1\", \"socio_de\") \
                 THEN COMMUNITY (\"A1\")";
        let v = execute(q, &be).unwrap();
        assert_eq!(
            v["members"].as_array().unwrap().len(),
            9,
            "nested mutations must compose"
        );

        // Reality unchanged.
        assert_eq!(
            execute("COMMUNITY (\"A1\")", &be).unwrap()["members"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn simulate_counterfactual_isolates_divergence() {
        // M16: two triangles joined by a bridge edge A1-B1 form one community.
        // SIMULATE REMOVE EDGE THEN COMMUNITY splits them — without touching the
        // base graph or the log.
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let edge = |from: &str, to: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), from.into());
            e.attrs.insert("edge_to".into(), to.into());
            e.attrs.insert("edge_type".into(), "socio_de".into());
            e
        };
        for (a, b) in [
            ("A1", "A2"),
            ("A2", "A3"),
            ("A3", "A1"), // triangle A
            ("B1", "B2"),
            ("B2", "B3"),
            ("B3", "B1"), // triangle B
            ("A1", "B1"), // bridge
        ] {
            log.append(edge(a, b)).unwrap();
        }
        let be = LogBackend::new(log);
        let head_before = {
            use backend::QueryBackend as _;
            be.scan(None).unwrap().len()
        };

        // Reality: all six nodes are one community (joined by the bridge).
        let real = execute("COMMUNITY (\"A1\")", &be).unwrap();
        assert_eq!(real["members"].as_array().unwrap().len(), 6);

        // Counterfactual: remove the bridge → A1's community shrinks to {A1,A2,A3}.
        let cf = execute(
            "SIMULATE REMOVE EDGE (\"A1\", \"B1\", \"socio_de\") THEN COMMUNITY (\"A1\")",
            &be,
        )
        .unwrap();
        let mut members: Vec<&str> = cf["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        members.sort();
        assert_eq!(
            members,
            vec!["A1", "A2", "A3"],
            "removing the bridge splits the ring"
        );

        // Divergence isolated: reality is unchanged and the log did not grow.
        let real_again = execute("COMMUNITY (\"A1\")", &be).unwrap();
        assert_eq!(
            real_again["members"].as_array().unwrap().len(),
            6,
            "base graph untouched"
        );
        let head_after = {
            use backend::QueryBackend as _;
            be.scan(None).unwrap().len()
        };
        assert_eq!(head_before, head_after, "the log was not altered");

        // ADD also works: a new edge can merge what was apart.
        let add = execute(
            "SIMULATE ADD EDGE (\"A2\", \"B2\", \"socio_de\") THEN NEIGHBORS (\"A2\")",
            &be,
        )
        .unwrap();
        let tos: Vec<&str> = add
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["to"].as_str().unwrap())
            .collect();
        assert!(
            tos.contains(&"B2"),
            "the simulated edge is visible: {tos:?}"
        );

        assert!(
            explain("SIMULATE ADD EDGE (\"x\",\"y\",\"socio_de\") THEN COMMUNITY (\"x\")")
                .unwrap()
                .contains("Counterfactual")
        );
    }

    #[test]
    fn graph_analytics_via_gql() {
        // M14: two fraud rings; COMMUNITY/METRICS detect and score them.
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let edge = |from: &str, to: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), from.into());
            e.attrs.insert("edge_to".into(), to.into());
            e.attrs.insert("edge_type".into(), "socio_de".into());
            e
        };
        for (a, b) in [("A1", "A2"), ("A2", "A3"), ("A3", "A1"), ("B1", "B2")] {
            log.append(edge(a, b)).unwrap();
        }
        let be = LogBackend::new(log);

        let v = execute("COMMUNITY (\"A1\")", &be).unwrap();
        assert_eq!(v["community"].as_str().unwrap(), "A1", "id = min node");
        let mut members: Vec<&str> = v["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        members.sort();
        assert_eq!(members, vec!["A1", "A2", "A3"]);
        // B-ring is a different community.
        let vb = execute("COMMUNITY (\"B1\")", &be).unwrap();
        assert_ne!(vb["community"], v["community"]);

        let m = execute("METRICS (\"A1\")", &be).unwrap();
        assert_eq!(m["degree"].as_u64().unwrap(), 2);
        assert_eq!(m["community"].as_str().unwrap(), "A1");
        assert!(m["centrality"].is_number() && m["anomaly_score"].is_number());

        assert!(explain("COMMUNITY (\"A1\")")
            .unwrap()
            .contains("GraphCommunity"));
        // A node in no edge is null, not an error.
        assert!(execute("COMMUNITY (\"ZZ\")", &be).unwrap().is_null());
    }

    #[test]
    fn why_traces_causal_chain() {
        // M13: WHY walks the provenance DAG. Chain: root obs a, b -> distilled
        // fact f (parents a,b) -> decision d (parent f). WHY(d) = the whole chain
        // back to the root observations; and it matches raw provenance.
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let a = Episode::new("ag", EventKind::Observation, b"obs a".to_vec());
        let b = Episode::new("ag", EventKind::Observation, b"obs b".to_vec());
        let mut f = Episode::new("distill", EventKind::FactDerived, b"fact".to_vec());
        f.parents = vec![a.id, b.id]; // distill provenance
        let mut d = Episode::new("ag", EventKind::Action, b"decision".to_vec());
        d.parents = vec![f.id];
        let (aid, bid, fid, did) = (
            a.id.to_string(),
            b.id.to_string(),
            f.id.to_string(),
            d.id.to_string(),
        );
        for e in [a, b, f, d] {
            log.append(e).unwrap();
        }
        let be = LogBackend::new(log);

        let v = execute(&format!("WHY (\"{did}\")"), &be).unwrap();
        assert_eq!(v["target"].as_str().unwrap(), did);
        // Root causes are the two original observations.
        let mut roots: Vec<&str> = v["roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        roots.sort();
        let mut want = vec![aid.as_str(), bid.as_str()];
        want.sort();
        assert_eq!(roots, want);
        // The whole chain is present (d, f, a, b) = 4 steps.
        assert_eq!(v["steps"].as_array().unwrap().len(), 4);

        // Consistency contract: f's causes in the trace ARE its provenance.
        let step_f = v["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == fid)
            .unwrap();
        let mut causes: Vec<&str> = step_f["causes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        causes.sort();
        let prov = execute(&format!("PROVENANCE (\"{fid}\")"), &be).unwrap();
        let mut prov_ids: Vec<&str> = prov
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        prov_ids.sort();
        assert_eq!(causes, prov_ids, "WHY causes must match raw provenance");

        // Depth budget 1: only d and its direct cause f.
        let v1 = execute(&format!("WHY (\"{did}\", 1)"), &be).unwrap();
        assert_eq!(v1["steps"].as_array().unwrap().len(), 2);
        assert!(explain(&format!("WHY (\"{did}\")"))
            .unwrap()
            .contains("CausalTrace"));
    }

    #[test]
    fn hypothesis_graph_via_gql() {
        // M12 through GQL: two conflicting rules on the same edge coexist;
        // HYPOTHESES lists both and the aggregated belief; AS OF time-travels.
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let hyp = |hid: &str, conf: &str, stance: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), "X".into());
            e.attrs.insert("edge_to".into(), "Y".into());
            e.attrs.insert("edge_type".into(), "fraud_partner".into());
            e.attrs.insert("hypothesis".into(), hid.into());
            e.attrs.insert("confidence".into(), conf.into());
            e.attrs.insert("stance".into(), stance.into());
            e
        };
        log.append(hyp("R1", "0.8", "support")).unwrap(); // lsn 0
        log.append(hyp("R2", "0.6", "refute")).unwrap(); // lsn 1
        let be = LogBackend::new(log);

        let v = execute("HYPOTHESES (\"X\", \"Y\", \"fraud_partner\")", &be).unwrap();
        assert_eq!(v["hypotheses"].as_array().unwrap().len(), 2, "both coexist");
        let belief_both = v["belief"].as_f64().unwrap();

        // AS OF LSN 1 = only R1 (support) has been asserted yet → higher belief.
        let v1 = execute(
            "HYPOTHESES (\"X\", \"Y\", \"fraud_partner\") AS OF LSN 1",
            &be,
        )
        .unwrap();
        assert_eq!(v1["hypotheses"].as_array().unwrap().len(), 1);
        assert!(
            v1["belief"].as_f64().unwrap() > belief_both,
            "refutation lowers belief"
        );

        // A never-asserted edge is null, not an error.
        let none = execute("HYPOTHESES (\"X\", \"Z\", \"pagou\")", &be).unwrap();
        assert!(none.is_null());
        assert!(explain("HYPOTHESES (\"X\",\"Y\",\"pagou\")")
            .unwrap()
            .contains("HypothesisGraph"));
    }

    #[test]
    fn entity_resolution_via_gql() {
        // M11 through GQL: duplicates collapse, a merge unifies temporally, and
        // RESOLVE/CLUSTER honor AS OF.
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let mention = |key: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("entity_key".into(), key.into());
            e
        };
        let merge = |a: &str, b: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("er_op".into(), "merge".into());
            e.attrs.insert("er_a".into(), a.into());
            e.attrs.insert("er_b".into(), b.into());
            e
        };
        log.append(mention("CPF:111")).unwrap(); // lsn 0
        log.append(mention("CPF:222")).unwrap(); // lsn 1
        log.append(merge("CPF:222", "CPF:111")).unwrap(); // lsn 2
        let be = LogBackend::new(log);

        // Now they are one entity (survivor = the min canonical id).
        let v = execute("RESOLVE (\"CPF:222\")", &be).unwrap();
        assert_eq!(v["entity_id"].as_str().unwrap(), "CPF:111");

        // AS OF before the merge, they are still distinct.
        let v = execute("RESOLVE (\"CPF:222\") AS OF LSN 2", &be).unwrap();
        assert_eq!(v["entity_id"].as_str().unwrap(), "CPF:222");

        // CLUSTER now holds both keys.
        let v = execute("CLUSTER (\"CPF:111\")", &be).unwrap();
        let mut keys: Vec<&str> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        keys.sort();
        assert_eq!(keys, vec!["CPF:111", "CPF:222"]);

        // EXPLAIN renders the new operators.
        assert!(explain("RESOLVE (\"x\")")
            .unwrap()
            .contains("EntityResolve"));
    }

    #[test]
    fn native_valid_time_and_leiden_in_gql() {
        // V2.4: (a) valid time NATIVO (FORMAT v4) alimenta o VALID AT — em nós
        // E em arestas; (b) COMMUNITY ("n", LEIDEN) separa sub-comunidades.
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());

        // Nó com valid time nos CAMPOS NATIVOS (sem attrs).
        let mut n = Episode::new("ag", EventKind::Observation, b"mandato".to_vec());
        n.valid_from = Some(1000);
        n.valid_to = Some(2000);
        log.append(n).unwrap();

        // Aresta societária cujo FACTO valia no mundo de 1000 a 2000.
        let mut edge = Episode::new("ag", EventKind::Observation, vec![]);
        edge.attrs.insert("edge_from".into(), "Alfa".into());
        edge.attrs.insert("edge_to".into(), "Maria".into());
        edge.attrs.insert("edge_type".into(), "socio_de".into());
        edge.valid_from = Some(1000);
        edge.valid_to = Some(2000);
        log.append(edge).unwrap();

        // Duas cliques + ponte fraca (para o LEIDEN separar).
        let mk = |f: &str, t: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), f.into());
            e.attrs.insert("edge_to".into(), t.into());
            e.attrs.insert("edge_type".into(), "socio_de".into());
            e
        };
        for (f, t) in [
            ("A1", "A2"),
            ("A2", "A3"),
            ("A3", "A1"),
            ("A1", "A3"),
            ("B1", "B2"),
            ("B2", "B3"),
            ("B3", "B1"),
            ("B1", "B3"),
            ("A1", "B1"), // ponte
        ] {
            log.append(mk(f, t)).unwrap();
        }
        let be = LogBackend::new(log);

        // Nó: campos nativos filtram sem attrs nenhum.
        let v = execute("MATCH (n) VALID AT 1500 RETURN n", &be).unwrap();
        assert!(v
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["content"] == "mandato"));
        let v = execute(
            "MATCH (n) WHERE n.agent_id = \"ag\" VALID AT 2500 RETURN n",
            &be,
        )
        .unwrap();
        assert!(
            v.as_array()
                .unwrap()
                .iter()
                .all(|r| r["content"] != "mandato"),
            "fora do intervalo [1000, 2000) o mandato não é válido"
        );

        // Aresta: VALID AT em edge match usa o valid time herdado do assert.
        let v = execute(
            "MATCH (a)-[r:socio_de]->(b) WHERE b = \"Maria\" VALID AT 1500 RETURN *",
            &be,
        )
        .unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1, "válida em 1500");
        let v = execute(
            "MATCH (a)-[r:socio_de]->(b) WHERE b = \"Maria\" VALID AT 2500 RETURN *",
            &be,
        )
        .unwrap();
        assert_eq!(v.as_array().unwrap().len(), 0, "expirada em 2500");

        // COMMUNITY clássico funde tudo; com LEIDEN as cliques separam-se.
        let cc = execute("COMMUNITY (\"A2\")", &be).unwrap();
        assert!(
            cc["members"].as_array().unwrap().len() >= 6,
            "componente única"
        );
        let leiden = execute("COMMUNITY (\"A2\", LEIDEN)", &be).unwrap();
        let members: Vec<&str> = leiden["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m.as_str().unwrap())
            .collect();
        assert!(
            members.iter().all(|m| m.starts_with('A')),
            "só a clique A: {members:?}"
        );
        assert!(explain("COMMUNITY (\"A2\", LEIDEN)")
            .unwrap()
            .contains("Leiden"));
    }

    #[test]
    fn valid_time_bitemporal_filter() {
        // C2.2 (SQL:2011/XTDB): VALID AT filtra pelo tempo de VALIDADE do
        // facto no mundo real (attrs valid_from/valid_to, [from, to)),
        // ortogonal ao AS OF (transaction time = quando foi GRAVADO).
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let fact = |name: &str, from: Option<&str>, to: Option<&str>| {
            let mut e = Episode::new("ag", EventKind::Observation, name.as_bytes().to_vec());
            if let Some(f) = from {
                e.attrs.insert("valid_from".into(), f.into());
            }
            if let Some(t) = to {
                e.attrs.insert("valid_to".into(), t.into());
            }
            e
        };
        // Sócio de 1000 a 2000; sócio desde 1500 (aberto); facto atemporal.
        log.append(fact("socio_antigo", Some("1000"), Some("2000")))
            .unwrap(); // lsn 0
        log.append(fact("socio_atual", Some("1500"), None)).unwrap(); // lsn 1
        log.append(fact("atemporal", None, None)).unwrap(); // lsn 2
        let be = LogBackend::new(log);

        let names = |v: &serde_json::Value| -> Vec<String> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|r| r["content"].as_str().unwrap().to_string())
                .collect()
        };

        // Em t=1200 só o sócio antigo é válido (o atual ainda não começou).
        let v = execute("MATCH (n) VALID AT 1200 RETURN n", &be).unwrap();
        assert_eq!(names(&v), vec!["socio_antigo", "atemporal"]);

        // Em t=1700 ambos os sócios são válidos.
        let v = execute("MATCH (n) VALID AT 1700 RETURN n", &be).unwrap();
        assert_eq!(names(&v), vec!["socio_antigo", "socio_atual", "atemporal"]);

        // Em t=2000 o intervalo [1000, 2000) já fechou — o antigo sai.
        let v = execute("MATCH (n) VALID AT 2000 RETURN n", &be).unwrap();
        assert_eq!(names(&v), vec!["socio_atual", "atemporal"]);

        // Bi-temporal de verdade: VALID AT + AS OF compõem — em transaction
        // time LSN 1 só o sócio antigo tinha sido GRAVADO.
        let v = execute("MATCH (n) VALID AT 1700 AS OF LSN 1 RETURN n", &be).unwrap();
        assert_eq!(names(&v), vec!["socio_antigo"]);

        // EXPLAIN mostra a fase de valid time.
        let s = explain("MATCH (n) VALID AT 1700 RETURN n").unwrap();
        assert!(s.contains("ValidAt(1700)"), "{s}");
    }

    #[test]
    fn numeric_range_filter_on_attrs() {
        // C1.6: WHERE n.<campo> >/< número — resolvido pelo índice (hint de
        // range) e revalidado pelo pós-filtro com coerção numérica (attrs são
        // strings no Episode; antes disto a comparação devolvia sempre false).
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        for v in ["5", "50", "150", "3000"] {
            let mut e = Episode::new("etl", EventKind::Observation, v.as_bytes().to_vec());
            e.attrs.insert("valor".into(), v.into());
            log.append(e).unwrap();
        }
        let be = LogBackend::new(log);

        let v = execute(
            "MATCH (n) WHERE n.valor > 10 AND n.valor < 200 RETURN n",
            &be,
        )
        .unwrap();
        let got: Vec<&str> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["content"].as_str().unwrap())
            .collect();
        assert_eq!(got, vec!["50", "150"]);

        // Bounds inclusivos e um só lado.
        let v = execute("MATCH (n) WHERE n.valor >= 150 RETURN n", &be).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);

        // AS OF corta o range temporalmente (lsn < 2 ⇒ só "5" e "50").
        let v = execute("MATCH (n) WHERE n.valor > 1 AS OF LSN 2 RETURN n", &be).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);

        // Igualdade em string continua lexicográfica (zeros à esquerda intactos).
        let v = execute("MATCH (n) WHERE n.valor = \"50\" RETURN n", &be).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);
    }

    #[test]
    fn dist_operators_filter_and_order() {
        // C1.4 (padrão pgvector): DIST_* como operando do WHERE e chave do
        // ORDER BY, avaliado sobre o embedding do episódio.
        use heraclitus_core::ProductPoint;
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        for (name, hyp) in [("perto", 0.10f32), ("meio", 0.50), ("longe", 0.90)] {
            let mut e = Episode::new("ag", EventKind::Observation, name.as_bytes().to_vec());
            e.embedding = Some(ProductPoint {
                hyp: vec![hyp],
                sph: vec![],
                euc: vec![],
            });
            log.append(e).unwrap();
        }
        // Sem embedding: nunca casa um filtro DIST_* e vai para o fim no ORDER BY.
        log.append(Episode::new(
            "ag",
            EventKind::Observation,
            b"sem embedding".to_vec(),
        ))
        .unwrap();
        let be = LogBackend::new(log);

        // WHERE: só o vizinho hiperbólico próximo de 0.1 passa o corte.
        let v = execute("MATCH (n) WHERE DIST_HYP([0.12]) < 0.1 RETURN n", &be).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["content"].as_str().unwrap(), "perto");

        // ORDER BY: mais próximo primeiro; o episódio sem embedding vai para o fim.
        let v = execute("MATCH (n) RETURN n ORDER BY DIST_HYP([0.12]) ASC", &be).unwrap();
        let contents: Vec<&str> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["content"].as_str().unwrap())
            .collect();
        assert_eq!(contents, vec!["perto", "meio", "longe", "sem embedding"]);

        // DESC inverte (o sem-embedding continua tratado como infinito → primeiro).
        let v = execute(
            "MATCH (n) RETURN n ORDER BY DIST_HYP([0.12]) DESC LIMIT 1",
            &be,
        )
        .unwrap();
        assert_eq!(
            v.as_array().unwrap()[0]["content"].as_str().unwrap(),
            "sem embedding"
        );

        // EXPLAIN mostra a chave de ordenação por distância.
        let s = explain("MATCH (n) RETURN n ORDER BY DIST_PRODUCT([0.1, 0.2])").unwrap();
        assert!(s.contains("DIST_"), "{s}");
    }

    #[test]
    fn recall_and_provenance() {
        let (_d, be) = seeded_backend();
        let v = execute("RECALL (\"river\", 3)", &be).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 3);
        // Provenance of a root event is empty but must not error.
        let id = v.as_array().unwrap()[0]["id"].as_str().unwrap().to_string();
        let p = execute(&format!("PROVENANCE (\"{id}\")"), &be).unwrap();
        assert!(p.as_array().unwrap().is_empty());
    }

    proptest! {
        /// Fuzz gate (local approximation; CI runs cargo-fuzz 10 min):
        /// the parser must never panic, on any input.
        #[test]
        fn parser_never_panics(input in ".{0,200}") {
            let _ = parse(&input);
        }

        #[test]
        fn parser_never_panics_on_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            let s = String::from_utf8_lossy(&bytes);
            let _ = parse(&s);
        }

        /// Valid queries parse and survive EXPLAIN.
        #[test]
        fn valid_queries_roundtrip(agent in "[a-z]{1,8}", k in 1u32..50, lsn in 0u64..1000) {
            let q1 = format!("MATCH (n) WHERE n.agent_id = \"{agent}\" AS OF LSN {lsn} RETURN n LIMIT {k}");
            prop_assert!(parse(&q1).is_ok(), "{q1}");
            prop_assert!(explain(&q1).is_ok());
            let q2 = format!("RECALL (\"{agent}\", {k})");
            prop_assert!(parse(&q2).is_ok(), "{q2}");
        }
    }
}
