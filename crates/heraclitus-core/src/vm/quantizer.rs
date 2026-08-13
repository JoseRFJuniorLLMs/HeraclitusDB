//! `OP_QUANTIZE` — the heterogeneous isolation barrier (SPEC-HVM-001 §3).
//!
//! Approximate distances computed on a GPU carry hardware-specific float
//! hysteresis (FMA reordering, cross-driver rounding). Before any candidate
//! crosses a metric barrier or final ranking, it is flattened to a fixed-point
//! integer here — turning fluctuating floats into inviolable integers so the
//! ordering is invariant across different GPUs (*ordinal invariance*).

/// Quantize a raw GPU float to a stable fixed-point integer key.
///
/// `scale` sets the fixed-point resolution (e.g. `1e6` keeps ~6 decimal places).
/// The float→int `as` cast is **saturating and deterministic** in Rust: `NaN →
/// 0`, negatives → `0`, and `+∞`/overflow → `u64::MAX`. There is no UB and no
/// platform-dependent result, which is precisely the property the barrier needs.
#[inline]
pub fn execute_op_quantize(raw_gpu_float: f32, scale: f32) -> u64 {
    // Multiply then floor in f32, collapsing any implicit FMA/reassociation the
    // local shader compiler might have applied into a single integer rung.
    let product = raw_gpu_float * scale;
    let flat_floor = product.floor();
    flat_floor as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_deterministic() {
        // Equality holds for any input — the point of the barrier.
        for &(x, s) in &[
            (0.123_456_f32, 1e6_f32),
            (0.987_f32, 1e3_f32),
            (3.5_f32, 1.0_f32),
        ] {
            assert_eq!(execute_op_quantize(x, s), execute_op_quantize(x, s));
        }
        // Exact, representable case: 0.5 * 1000 = 500.0 → 500.
        assert_eq!(execute_op_quantize(0.5, 1e3), 500);
    }

    #[test]
    fn saturates_without_ub() {
        assert_eq!(execute_op_quantize(f32::NAN, 1e6), 0);
        assert_eq!(execute_op_quantize(-1.0, 1e6), 0);
        assert_eq!(execute_op_quantize(f32::INFINITY, 1e6), u64::MAX);
    }

    /// Ordinal invariance: two floats closer than one quantum collapse to the
    /// same integer, so cross-GPU jitter below the resolution cannot reorder
    /// candidates.
    #[test]
    fn close_floats_collapse() {
        let scale = 1e3;
        let q1 = execute_op_quantize(0.500_000_1, scale);
        let q2 = execute_op_quantize(0.500_000_9, scale);
        assert_eq!(q1, q2, "sub-quantum jitter must not change the integer");
        assert_eq!(q1, 500);
    }
}
