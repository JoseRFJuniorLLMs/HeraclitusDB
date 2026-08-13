//! decision.rs — M15: the graph that acts.
//!
//! Rules evaluate the deterministic graph state (M14 analytics + M12 belief) and
//! propose **actions**. A decision is not a side effect hidden in the engine —
//! it becomes an `Action` **event in the log**, so it is auditable and replayed
//! like everything else. Each decision carries a content-addressed `action_id`
//! (`rule:subject`) that is stable across evaluations: that is the idempotency
//! key — re-evaluating never emits a duplicate.
//!
//! The rules here are intentionally boring and deterministic. The intelligence
//! still lives in the agent; the database only proposes what its own metrics
//! make undeniable.

use crate::temporal::{EdgeType, Lsn, TemporalGraph};

/// Versioned decision policy (auditable, reproducible). Thresholds are explicit
/// so a fired action can always be re-derived.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionPolicy {
    pub version: u32,
    /// Flag a node whose degree z-score is at least this (a hub / "laranja").
    pub anomaly_threshold: f32,
    /// Flag a `fraud_partner` edge whose aggregated belief is at least this.
    pub fraud_belief_threshold: f32,
}

impl Default for DecisionPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            anomaly_threshold: 1.5,
            fraud_belief_threshold: 0.7,
        }
    }
}

/// A proposed action. `action_id` is the stable idempotency key.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub action_id: String,
    pub rule: String,
    pub subject: String,
    pub reason: String,
}

/// Evaluate the policy over the graph as of `as_of`, returning the proposed
/// actions in a deterministic order (by `action_id`). Pure — no I/O, no clock.
pub fn evaluate(g: &TemporalGraph, as_of: Lsn, policy: &DecisionPolicy) -> Vec<Decision> {
    let mut out: Vec<Decision> = Vec::new();

    // Rule "flag_anomaly": a node whose degree is far above the mean.
    let analytics = g.analyze(as_of, 0.0);
    for (node, m) in &analytics.metrics {
        if m.anomaly_score >= policy.anomaly_threshold {
            out.push(Decision {
                action_id: format!("flag_anomaly:{node}"),
                rule: "flag_anomaly".into(),
                subject: node.clone(),
                reason: format!("anomaly_score={:.3} degree={}", m.anomaly_score, m.degree),
            });
        }
    }

    // Rule "flag_fraud": a fraud_partner edge believed above threshold.
    for e in g.match_edges(
        None,
        Some(&EdgeType::FraudPartner),
        None,
        as_of,
        policy.fraud_belief_threshold,
    ) {
        out.push(Decision {
            action_id: format!("flag_fraud:{}->{}", e.from, e.to),
            rule: "flag_fraud".into(),
            subject: e.from.clone(),
            reason: format!("fraud_partner belief={:.3}", e.belief),
        });
    }

    out.sort_by(|x, y| x.action_id.cmp(&y.action_id));
    out.dedup_by(|x, y| x.action_id == y.action_id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind};

    fn edge(from: &str, to: &str, etype: &str, conf: f32) -> Episode {
        let mut e = Episode::new("ag", EventKind::Observation, vec![]);
        e.attrs.insert("edge_from".into(), from.into());
        e.attrs.insert("edge_to".into(), to.into());
        e.attrs.insert("edge_type".into(), etype.into());
        e.attrs.insert("confidence".into(), conf.to_string());
        e
    }

    #[test]
    fn flags_hub_and_fraud_deterministically() {
        let mut g = TemporalGraph::new();
        // Star: H is a hub (high anomaly).
        for (i, leaf) in ["L1", "L2", "L3", "L4"].iter().enumerate() {
            g.apply_episode(i as Lsn + 1, &edge("H", leaf, "socio_de", 1.0));
        }
        // A believed fraud edge.
        g.apply_episode(10, &edge("X", "Y", "fraud_partner", 0.9));

        let ds = evaluate(&g, u64::MAX, &DecisionPolicy::default());
        let ids: Vec<&str> = ds.iter().map(|d| d.action_id.as_str()).collect();
        assert!(ids.contains(&"flag_anomaly:H"), "hub flagged: {ids:?}");
        assert!(ids.contains(&"flag_fraud:X->Y"), "fraud flagged: {ids:?}");
        // Deterministic: a second evaluation is identical.
        assert_eq!(ds, evaluate(&g, u64::MAX, &DecisionPolicy::default()));
    }

    #[test]
    fn low_belief_fraud_is_not_flagged() {
        let mut g = TemporalGraph::new();
        g.apply_episode(1, &edge("X", "Y", "fraud_partner", 0.5)); // below 0.7
        let ds = evaluate(&g, u64::MAX, &DecisionPolicy::default());
        assert!(ds.iter().all(|d| d.rule != "flag_fraud"));
    }
}
