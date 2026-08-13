//! Curvature/signature estimation (§3.3).
//!
//! Given a sample of (graph distance, embedding pair) observations, score
//! candidate signatures by average relative distortion and return the best.
//! Used offline by `heraclitus-distill` during compaction; a re-fit never
//! mutates data in place — it versions a new derived view.

use crate::{ProductMetric, Signature};
use heraclitus_core::ProductPoint;

/// One observation: the "true" structural distance (e.g. shortest-path hops
/// in the provenance graph) and the two embedded points.
pub struct DistortionSample {
    pub graph_dist: f64,
    pub a: ProductPoint,
    pub b: ProductPoint,
}

/// Average relative distortion of a metric over a sample.
pub fn distortion(metric: &ProductMetric, sample: &[DistortionSample]) -> f64 {
    if sample.is_empty() {
        return 0.0;
    }
    let mut acc = 0.0;
    let mut n = 0usize;
    for s in sample {
        if s.graph_dist <= 0.0 {
            continue;
        }
        let d = metric.dist(&s.a, &s.b);
        acc += (d - s.graph_dist).abs() / s.graph_dist;
        n += 1;
    }
    if n == 0 {
        0.0
    } else {
        acc / n as f64
    }
}

/// Grid-search curvatures and component weights; return the signature with
/// the lowest distortion. Dimensions (a, b, c) are taken from the data.
pub fn fit_signature(sample: &[DistortionSample]) -> Signature {
    let (a, b, c) = sample.first().map(|s| s.a.dims()).unwrap_or((0, 0, 0));

    let curvatures = [-0.5, -1.0, -2.0];
    let k2s = [0.5, 1.0, 2.0];
    let weight_grid = [
        [1.0, 1.0, 1.0],
        [2.0, 1.0, 0.5],
        [1.0, 0.5, 0.0],
        [1.0, 0.0, 1.0],
    ];

    let mut best = Signature {
        a,
        b,
        c,
        ..Signature::default()
    };
    let mut best_score = f64::INFINITY;

    for &k1 in &curvatures {
        for &k2 in &k2s {
            for &weights in &weight_grid {
                let sig = Signature {
                    a,
                    b,
                    c,
                    k1,
                    k2,
                    weights,
                };
                let m = ProductMetric { sig: sig.clone() };
                let score = distortion(&m, sample);
                if score < best_score {
                    best_score = score;
                    best = sig;
                }
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_prefers_lower_distortion() {
        // Hierarchy-shaped sample: hyperbolic distances should win weight.
        let mk = |h: Vec<f32>| ProductPoint {
            hyp: h,
            sph: vec![],
            euc: vec![],
        };
        let sample = vec![
            DistortionSample {
                graph_dist: 0.97,
                a: mk(vec![0.2, 0.0]),
                b: mk(vec![0.6, 0.0]),
            },
            DistortionSample {
                graph_dist: 1.56,
                a: mk(vec![0.6, 0.0]),
                b: mk(vec![0.9, 0.0]),
            },
        ];
        let sig = fit_signature(&sample);
        let m = ProductMetric { sig };
        assert!(distortion(&m, &sample) < 0.2);
    }
}
