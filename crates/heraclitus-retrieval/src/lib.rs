//! heraclitus-retrieval — two stages (§3.8).
//!
//! 1. **Recall**: ANN top-N ∥ BM25 top-N ∥ activation top-N, fused with RRF.
//! 2. **Rerank**: pluggable [`Reranker`]; default is a calibrated linear
//!    blend. Feedback is persisted as ordinary log events
//!    (`kind = RetrievalFeedback`) so rerankers can be retrained offline
//!    from the log itself.

use heraclitus_core::{Episode, EventId, EventKind, HeraclitusError, Lsn};
use heraclitus_log::Log;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const RRF_K: f64 = 60.0;
pub const RECALL_N: usize = 200;

/// One fused candidate after recall.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: EventId,
    pub lsn: Lsn,
    pub rrf: f64,
    /// Raw per-channel signals for the reranker.
    pub vec_dist: Option<f32>,
    pub bm25: Option<f32>,
    pub activation: Option<f32>,
}

/// Reciprocal Rank Fusion over ranked id lists (k = 60).
pub fn rrf_fuse(lists: &[Vec<EventId>]) -> Vec<(EventId, f64)> {
    let mut scores: HashMap<EventId, f64> = HashMap::new();
    for list in lists {
        for (rank, id) in list.iter().enumerate() {
            *scores.entry(*id).or_default() += 1.0 / (RRF_K + rank as f64 + 1.0);
        }
    }
    let mut out: Vec<(EventId, f64)> = scores.into_iter().collect();
    // Desempate determinístico por EventId: os candidatos vêm de um HashMap, e
    // empates de RRF (comuns) ficariam em ordem de iteração não-determinística
    // (seed do SipHash) ⇒ o corte RECALL_N e o top-k variavam entre execuções.
    out.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

/// Stage-2 scorer. Implementations must be deterministic given the same
/// model state.
pub trait Reranker: Send + Sync {
    fn score(&self, query: &str, candidate: &Candidate) -> f32;
    /// Feedback hook; implementations may buffer for offline retraining.
    fn observe(&mut self, _query_id: &str, _chosen: &EventId, _outcome: f32) {}
}

/// Default: calibrated linear blend of (manifold distance, BM25, activation,
/// recency-by-lsn). Weights are deliberately boring and inspectable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearReranker {
    pub w_vec: f32,
    pub w_bm25: f32,
    pub w_act: f32,
    pub w_recency: f32,
    pub head_lsn: Lsn,
}

impl Default for LinearReranker {
    fn default() -> Self {
        Self {
            w_vec: 1.0,
            w_bm25: 0.5,
            w_act: 0.3,
            w_recency: 0.1,
            head_lsn: 0,
        }
    }
}

impl Reranker for LinearReranker {
    fn score(&self, _query: &str, c: &Candidate) -> f32 {
        let vec_sim = c.vec_dist.map(|d| 1.0 / (1.0 + d)).unwrap_or(0.0);
        let bm25 = c.bm25.unwrap_or(0.0).tanh();
        let act = c.activation.map(|a| a.max(-5.0) / 5.0).unwrap_or(0.0);
        let recency = if self.head_lsn > 0 {
            (c.lsn as f32) / (self.head_lsn as f32)
        } else {
            0.0
        };
        self.w_vec * vec_sim + self.w_bm25 * bm25 + self.w_act * act + self.w_recency * recency
    }
}

/// Feedback payload persisted to the log (kind = RetrievalFeedback).
#[derive(Debug, Serialize, Deserialize)]
pub struct RetrievalFeedback {
    pub query_id: String,
    pub chosen: EventId,
    pub outcome: f32,
}

/// Append a feedback event to the log so rerankers can be retrained offline.
pub fn log_feedback(
    log: &Log,
    agent_id: &str,
    fb: &RetrievalFeedback,
) -> Result<Lsn, HeraclitusError> {
    let payload =
        serde_json::to_vec(fb).map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
    log.append(Episode::new(
        agent_id,
        EventKind::RetrievalFeedback,
        payload,
    ))
}

/// Inputs to the recall stage: pre-ranked channel results.
pub struct RecallInputs {
    pub vector: Vec<(EventId, Lsn, f32)>, // (id, lsn, dist)
    pub text: Vec<(EventId, Lsn, f32)>,   // (id, lsn, bm25)
    pub activation: Vec<(EventId, f32)>,  // (id, score)
}

/// Full two-stage retrieval over pre-fetched channel results.
pub fn retrieve(
    query: &str,
    inputs: RecallInputs,
    reranker: &dyn Reranker,
    k: usize,
) -> Vec<(Candidate, f32)> {
    let lists: Vec<Vec<EventId>> = vec![
        inputs.vector.iter().map(|(id, _, _)| *id).collect(),
        inputs.text.iter().map(|(id, _, _)| *id).collect(),
        inputs.activation.iter().map(|(id, _)| *id).collect(),
    ];
    let fused = rrf_fuse(&lists);

    let vec_by: HashMap<EventId, (Lsn, f32)> = inputs
        .vector
        .into_iter()
        .map(|(i, l, d)| (i, (l, d)))
        .collect();
    let txt_by: HashMap<EventId, (Lsn, f32)> = inputs
        .text
        .into_iter()
        .map(|(i, l, s)| (i, (l, s)))
        .collect();
    let act_by: HashMap<EventId, f32> = inputs.activation.into_iter().collect();

    let mut out: Vec<(Candidate, f32)> = fused
        .into_iter()
        .take(RECALL_N)
        .map(|(id, rrf)| {
            let lsn = vec_by
                .get(&id)
                .map(|(l, _)| *l)
                .or_else(|| txt_by.get(&id).map(|(l, _)| *l))
                .unwrap_or(0);
            let c = Candidate {
                id,
                lsn,
                rrf,
                vec_dist: vec_by.get(&id).map(|(_, d)| *d),
                bm25: txt_by.get(&id).map(|(_, s)| *s),
                activation: act_by.get(&id).copied(),
            };
            let s = reranker.score(query, &c);
            (c, s)
        })
        .collect();
    out.sort_by(|a, b| b.1.total_cmp(&a.1));
    out.truncate(k);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrf_rewards_cross_channel_agreement() {
        let a = EventId::new();
        let b = EventId::new();
        let c = EventId::new();
        // `a` appears in two channels at modest rank; `b` tops one channel only.
        let fused = rrf_fuse(&[vec![b, a], vec![a, c]]);
        assert_eq!(fused[0].0, a);
    }

    #[test]
    fn two_stage_end_to_end() {
        let target = EventId::new();
        let noise = EventId::new();
        let inputs = RecallInputs {
            vector: vec![(target, 5, 0.1), (noise, 3, 2.0)],
            text: vec![(target, 5, 7.0)],
            activation: vec![(noise, 0.2), (target, 1.5)],
        };
        let reranker = LinearReranker {
            head_lsn: 10,
            ..Default::default()
        };
        let out = retrieve("river", inputs, &reranker, 2);
        assert_eq!(out[0].0.id, target);
        assert!(out[0].1 > out[1].1);
    }

    #[test]
    fn feedback_is_a_log_event() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, heraclitus_core::FsyncPolicy::Always).unwrap();
        let fb = RetrievalFeedback {
            query_id: "q1".into(),
            chosen: EventId::new(),
            outcome: 1.0,
        };
        let lsn = log_feedback(&log, "agent-1", &fb).unwrap();
        let (_, ep) = log.read(lsn).unwrap().unwrap();
        assert_eq!(ep.kind, EventKind::RetrievalFeedback);
    }
}
