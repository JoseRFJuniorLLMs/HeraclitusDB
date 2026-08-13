//! adaptive.rs — M17: the graph learns its own rules.
//!
//! Feedback is data, and data lives in the log. When an analyst reviews a flag,
//! they append a feedback event: the signal value the flag fired on plus a
//! verdict (confirmed / rejected). The adaptive worker is then a **pure,
//! deterministic** function of those labeled examples — it tunes the decision
//! threshold to maximize F1, and the improvement over the default is measurable
//! in precision/recall. No daemon mutates anything; the new rule is just the
//! best threshold derivable from the feedback so far, recomputed by replay.

/// One labeled example: the signal the flag fired on, and whether the human
/// confirmed it.
#[derive(Debug, Clone, Copy)]
pub struct LabeledFlag {
    pub score: f32,
    pub confirmed: bool,
}

/// How a threshold scores against the labeled set (a node is predicted positive
/// iff `score >= threshold`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PolicyEval {
    pub threshold: f32,
    pub precision: f32,
    pub recall: f32,
    pub f1: f32,
}

/// Evaluate a threshold against the labeled examples (precision/recall/F1).
pub fn evaluate_threshold(samples: &[LabeledFlag], threshold: f32) -> PolicyEval {
    let predicted = samples.iter().filter(|s| s.score >= threshold);
    let mut tp = 0.0f32;
    let mut predicted_n = 0.0f32;
    for s in predicted {
        predicted_n += 1.0;
        if s.confirmed {
            tp += 1.0;
        }
    }
    let total_pos = samples.iter().filter(|s| s.confirmed).count() as f32;
    let precision = if predicted_n > 0.0 {
        tp / predicted_n
    } else {
        0.0
    };
    let recall = if total_pos > 0.0 { tp / total_pos } else { 0.0 };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    PolicyEval {
        threshold,
        precision,
        recall,
        f1,
    }
}

/// Learn the threshold that maximizes F1 over the labeled examples (M17).
/// Candidates are the distinct observed scores; ties resolve to the lowest
/// threshold (more recall). Deterministic. Falls back to `default` with no data.
pub fn learn_threshold(samples: &[LabeledFlag], default: f32) -> f32 {
    if samples.is_empty() {
        return default;
    }
    let mut candidates: Vec<f32> = samples.iter().map(|s| s.score).collect();
    candidates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    candidates.dedup();

    let mut best_t = candidates[0];
    let mut best_f1 = -1.0f32;
    for &t in &candidates {
        let f1 = evaluate_threshold(samples, t).f1;
        // Strict improvement only ⇒ first (lowest) threshold wins a tie.
        if f1 > best_f1 + 1e-9 {
            best_f1 = f1;
            best_t = t;
        }
    }
    best_t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(score: f32, confirmed: bool) -> LabeledFlag {
        LabeledFlag { score, confirmed }
    }

    #[test]
    fn learns_threshold_that_beats_default() {
        // Confirms at 3.0/2.5/2.0, rejects at 1.6/1.0. Default 1.5 wrongly flags
        // the 1.6 reject; the learned threshold excludes it.
        let samples = [
            s(3.0, true),
            s(2.5, true),
            s(2.0, true),
            s(1.6, false),
            s(1.0, false),
        ];
        let default = evaluate_threshold(&samples, 1.5);
        let learned_t = learn_threshold(&samples, 1.5);
        let learned = evaluate_threshold(&samples, learned_t);

        assert!(learned.f1 > default.f1, "learning must improve F1");
        assert!(
            (learned.precision - 1.0).abs() < 1e-6,
            "learned precision is perfect"
        );
        assert!(
            learned_t > 1.6 && learned_t <= 2.0,
            "threshold lands above the reject: {learned_t}"
        );
        // The reject below default (1.0) was never flagged — default precision < 1.
        assert!(default.precision < 1.0);
    }

    #[test]
    fn deterministic_and_handles_empty() {
        let samples = [s(2.0, true), s(1.0, false)];
        assert_eq!(
            learn_threshold(&samples, 1.5),
            learn_threshold(&samples, 1.5)
        );
        assert_eq!(learn_threshold(&[], 1.5), 1.5, "no data ⇒ keep the default");
    }
}
