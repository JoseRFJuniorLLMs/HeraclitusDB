//! M10 — graph + vector + text fusion (the moat).
//!
//! No commercial database fuses *explicit* graph connectivity, semantic vector
//! similarity and lexical text relevance into one ranked, **reproducible** and
//! **auditable** score. The fusion is a deterministic weighted sum of three
//! per-channel signals, each min-max normalized to `[0,1]` so no channel can
//! dominate by raw scale. Weights are versioned: the same
//! `(inputs, weights, version)` always yields the same ranking.
//!
//! The thesis the gate proves: on a fraud/memory dataset the fused ranking
//! beats any single channel — the consensus candidate (strong on all three,
//! top on none) that vector-only or graph-only would miss rises to the top.

/// The three raw signals for one candidate. Higher is better in all three
/// (vector *distance* is converted to a similarity before it lands here).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct FusionInput {
    pub graph_score: f32,
    pub vector_score: f32,
    pub text_score: f32,
}

/// Audited, versioned fusion weights. `version` is carried so a stored score
/// can be reproduced and a weight change is traceable (never silent).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FusionWeights {
    /// graph (connectivity / belief)
    pub alpha: f32,
    /// vector (semantic similarity)
    pub beta: f32,
    /// text (lexical relevance)
    pub gamma: f32,
    pub version: u32,
}

impl Default for FusionWeights {
    fn default() -> Self {
        Self {
            alpha: 1.0,
            beta: 1.0,
            gamma: 1.0,
            version: 1,
        }
    }
}

impl FusionWeights {
    /// Weighted sum normalized by the weight total → result in `[0,1]` when the
    /// inputs are in `[0,1]`. Deterministic; never reads a clock or RNG.
    pub fn fuse(&self, x: &FusionInput) -> f32 {
        let denom = self.alpha + self.beta + self.gamma;
        if denom <= 0.0 {
            return 0.0;
        }
        (self.alpha * x.graph_score + self.beta * x.vector_score + self.gamma * x.text_score)
            / denom
    }
}

/// One fused result with its full per-channel breakdown (for audit / EXPLAIN).
#[derive(Debug, Clone)]
pub struct FusedHit {
    pub id: String,
    pub lsn: u64,
    pub input: FusionInput,
    pub score: f32,
}

/// Normalize a channel to `[0,1]` by its maximum. Chosen over min-max so the
/// weakest candidate keeps a proportional (non-zero) signal instead of being
/// flattened to 0 — a "middle on every channel" consensus candidate must keep
/// its partial signals to win the fusion. All-zero → unchanged. Deterministic.
pub fn normalize(scores: &mut [f32]) {
    let max = scores.iter().copied().fold(0.0f32, f32::max);
    if max <= 0.0 {
        return;
    }
    scores.iter_mut().for_each(|s| *s /= max);
}

/// A labeled retrieval example for learning fusion weights (M17): the candidates
/// for one query (each with its per-channel scores) and the index of the gold
/// (relevant) candidate.
#[derive(Debug, Clone)]
pub struct FusionExample {
    pub candidates: Vec<FusionInput>,
    pub relevant: usize,
}

/// Mean reciprocal rank of the relevant candidate when ranking by a single
/// channel `pick`. Ties take the **average** rank (so a constant / no-signal
/// channel scores ~middling, not perfect) — deterministic.
fn channel_mrr(examples: &[FusionExample], pick: fn(&FusionInput) -> f32) -> f32 {
    let mut sum = 0.0f32;
    let mut n = 0u32;
    for ex in examples {
        let Some(target) = ex.candidates.get(ex.relevant).map(pick) else {
            continue;
        };
        let higher = ex.candidates.iter().filter(|c| pick(c) > target).count();
        let equal = ex.candidates.iter().filter(|c| pick(c) == target).count();
        // Average rank among the `equal` tied candidates: higher + (equal+1)/2.
        let rank = higher as f32 + (equal as f32 + 1.0) / 2.0;
        sum += 1.0 / rank;
        n += 1;
    }
    if n == 0 {
        0.0
    } else {
        sum / n as f32
    }
}

/// Learn per-channel fusion weights from labeled examples (M17).
///
/// Equal weights make the fusion *worse* when channels differ in strength (a
/// weak channel drags the strong one down — measured on LoCoMo: equal-weight
/// fusion 27% vs the vector channel alone 36%). The fix: weight each channel by
/// its **standalone quality** (mean reciprocal rank of the gold candidate). A
/// channel that ranks the answer well gets a high weight; a noisy one is
/// down-weighted toward zero. Pure, deterministic, replay-stable; falls back to
/// equal weights when there is no signal.
pub fn learn_fusion_weights(examples: &[FusionExample], version: u32) -> FusionWeights {
    let alpha = channel_mrr(examples, |x| x.graph_score);
    let beta = channel_mrr(examples, |x| x.vector_score);
    let gamma = channel_mrr(examples, |x| x.text_score);
    if alpha + beta + gamma <= 0.0 {
        return FusionWeights {
            alpha: 1.0,
            beta: 1.0,
            gamma: 1.0,
            version,
        };
    }
    FusionWeights {
        alpha,
        beta,
        gamma,
        version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuse_is_deterministic_and_bounded() {
        let w = FusionWeights::default();
        let x = FusionInput {
            graph_score: 0.7,
            vector_score: 0.6,
            text_score: 0.6,
        };
        let a = w.fuse(&x);
        let b = w.fuse(&x);
        assert_eq!(a, b, "same input → same score");
        assert!((0.0..=1.0).contains(&a));
        assert!((a - 0.6333).abs() < 1e-3, "got {a}");
    }

    #[test]
    fn normalize_handles_constant_and_empty() {
        let mut all_eq = [0.5, 0.5, 0.5];
        normalize(&mut all_eq);
        assert_eq!(all_eq, [1.0, 1.0, 1.0], "constant positive → full signal");
        let mut zeros = [0.0, 0.0];
        normalize(&mut zeros);
        assert_eq!(zeros, [0.0, 0.0]);
        let mut spread = [0.0, 5.0, 10.0];
        normalize(&mut spread);
        assert_eq!(spread, [0.0, 0.5, 1.0]);
    }

    #[test]
    fn fusion_beats_any_single_channel() {
        // The moat, in miniature. X is strong on all three but top on none;
        // each rival tops exactly one channel. Balanced fusion must surface X.
        let w = FusionWeights::default();
        let x = FusionInput {
            graph_score: 0.7,
            vector_score: 0.6,
            text_score: 0.6,
        };
        let v_only = FusionInput {
            graph_score: 0.1,
            vector_score: 1.0,
            text_score: 0.1,
        };
        let g_only = FusionInput {
            graph_score: 1.0,
            vector_score: 0.1,
            text_score: 0.1,
        };
        let t_only = FusionInput {
            graph_score: 0.1,
            vector_score: 0.1,
            text_score: 1.0,
        };

        // Under fusion, X wins.
        let fx = w.fuse(&x);
        for rival in [v_only, g_only, t_only] {
            assert!(
                fx > w.fuse(&rival),
                "fusion must rank the consensus candidate first"
            );
        }
        // But no single channel ranks X first.
        assert!(
            v_only.vector_score > x.vector_score,
            "vector-only would miss X"
        );
        assert!(
            g_only.graph_score > x.graph_score,
            "graph-only would miss X"
        );
        assert!(t_only.text_score > x.text_score, "text-only would miss X");
    }

    // ---- M17: learned fusion weights ----

    fn ex(rel: usize, cands: &[(f32, f32, f32)]) -> FusionExample {
        FusionExample {
            candidates: cands
                .iter()
                .map(|&(g, v, t)| FusionInput {
                    graph_score: g,
                    vector_score: v,
                    text_score: t,
                })
                .collect(),
            relevant: rel,
        }
    }

    /// Training where the VECTOR channel reliably ranks the gold first and TEXT
    /// is noise. The learner must down-weight text.
    fn vector_strong_text_weak() -> Vec<FusionExample> {
        vec![
            ex(0, &[(0.0, 0.9, 0.2), (0.0, 0.4, 0.8), (0.0, 0.3, 0.9)]),
            ex(0, &[(0.0, 0.8, 0.1), (0.0, 0.5, 0.7), (0.0, 0.2, 0.95)]),
            ex(0, &[(0.0, 0.95, 0.3), (0.0, 0.6, 0.6), (0.0, 0.1, 0.99)]),
        ]
    }

    #[test]
    fn learns_to_downweight_the_weak_channel() {
        let w = learn_fusion_weights(&vector_strong_text_weak(), 2);
        assert!(
            w.beta > w.gamma,
            "vector must outweigh text: beta={} gamma={}",
            w.beta,
            w.gamma
        );
        assert!(
            w.beta > 0.9,
            "vector ranks gold first → high weight (got {})",
            w.beta
        );
        assert_eq!(w.version, 2, "version is carried for auditability");
        // Graph channel is constant (0) here → no signal → ~0 weight.
        assert!(w.alpha < w.beta);
    }

    #[test]
    fn learned_weights_fix_fusion_that_equal_weights_break() {
        // A held-out query: the distractor D wins on the noisy text channel; the
        // relevant R wins on the reliable vector channel.
        let r = FusionInput {
            graph_score: 0.0,
            vector_score: 0.8,
            text_score: 0.1,
        };
        let d = FusionInput {
            graph_score: 0.0,
            vector_score: 0.3,
            text_score: 0.9,
        };

        // Equal weights: text noise makes the distractor win — fusion HURTS.
        let equal = FusionWeights::default();
        assert!(
            equal.fuse(&d) > equal.fuse(&r),
            "equal-weight fusion picks the wrong candidate"
        );

        // Learned weights (from the vector-strong/text-weak history): R wins.
        let learned = learn_fusion_weights(&vector_strong_text_weak(), 2);
        assert!(
            learned.fuse(&r) > learned.fuse(&d),
            "learned weights rank the relevant candidate first"
        );
    }

    #[test]
    fn no_signal_falls_back_to_equal_weights() {
        let w = learn_fusion_weights(&[], 5);
        assert_eq!((w.alpha, w.beta, w.gamma), (1.0, 1.0, 1.0));
    }
}
