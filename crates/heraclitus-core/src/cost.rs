//! SPEC-012 cost model + SPEC-032 adaptive feedback calibration.
//!
//! A multidimensional physical cost estimate, plus an exponential-moving-average
//! calibrator that learns each operator's *real* latency from execution
//! feedback — pure statistics, no ML. If the planner keeps under-estimating a
//! sparse-matrix operator, its smoothed cost inflates and the planner starts
//! preferring the imperative fallback for that query fingerprint.

use crate::ir::PhysicalIr;
use std::collections::HashMap;

/// Multidimensional physical cost. Optional fields are calibration extras filled
/// in post-benchmark on real microarchitectures.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostEstimate {
    pub cpu_cycles: u64,
    pub memory_bytes: u64,
    pub io_pages: u64,
    pub network_bytes: u64,
    pub cache_misses: Option<u64>,
    pub branch_mispredictions: Option<u64>,
}

impl CostEstimate {
    pub fn zero() -> Self {
        Self {
            cpu_cycles: 0,
            memory_bytes: 0,
            io_pages: 0,
            network_bytes: 0,
            cache_misses: None,
            branch_mispredictions: None,
        }
    }

    pub fn weighted_score(&self, io_weight: f64, cpu_weight: f64) -> f64 {
        (self.io_pages as f64 * io_weight) + (self.cpu_cycles as f64 * cpu_weight)
    }
}

/// Estimates a physical operator's cost against a segment/cardinality profile.
pub trait CostModel: Send + Sync {
    fn estimate(&self, op: &PhysicalIr) -> CostEstimate;
}

/// SPEC-032 — EMA calibrator keyed by query fingerprint. `observe` folds the
/// measured latency into a smoothed estimate; `predicted` reads it back.
pub struct EmaCalibrator {
    alpha: f64,
    smoothed_ns: HashMap<[u8; 32], f64>,
}

impl EmaCalibrator {
    /// `alpha` ∈ (0,1]: higher = react faster to recent measurements.
    pub fn new(alpha: f64) -> Self {
        assert!(alpha > 0.0 && alpha <= 1.0, "alpha must be in (0,1]");
        Self { alpha, smoothed_ns: HashMap::new() }
    }

    /// Fold a measured latency for `fingerprint`; returns the new smoothed value.
    pub fn observe(&mut self, fingerprint: [u8; 32], actual_ns: f64) -> f64 {
        let e = self.smoothed_ns.entry(fingerprint).or_insert(actual_ns);
        *e = self.alpha * actual_ns + (1.0 - self.alpha) * *e;
        *e
    }

    pub fn predicted(&self, fingerprint: &[u8; 32]) -> Option<f64> {
        self.smoothed_ns.get(fingerprint).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_score_combines_dimensions() {
        let c = CostEstimate { cpu_cycles: 100, io_pages: 10, ..CostEstimate::zero() };
        assert_eq!(c.weighted_score(2.0, 0.5), 10.0 * 2.0 + 100.0 * 0.5);
    }

    #[test]
    fn ema_converges_toward_repeated_observations() {
        let mut cal = EmaCalibrator::new(0.5);
        let fp = [7u8; 32];
        // First observation seeds the estimate exactly.
        assert_eq!(cal.observe(fp, 10.0), 10.0);
        // Repeatedly observing 200ns drags the estimate up toward 200.
        let mut last = 10.0;
        for _ in 0..20 {
            last = cal.observe(fp, 200.0);
        }
        assert!(last > 199.0 && last <= 200.0, "EMA should converge, got {last}");
        assert_eq!(cal.predicted(&fp), Some(last));
        assert_eq!(cal.predicted(&[0u8; 32]), None);
    }
}
