//! SPEC-009 — Canonical key codec.
//!
//! Order-preserving `i64`/`f64` → `u64` encoding so that unsigned binary
//! (lexicographic) ordering of the encoded keys matches the numeric ordering
//! of the source values, including negatives and IEEE-754 floats. This is the
//! total-order trick used by column indexes / B-trees.
//!
//! Note on placement: SPEC-009 named `heraclitus-core/src/vm/codec.rs`, but
//! that file is the H-VM *instruction* codec (a different thing). The canonical
//! key codec lives here in its own module to avoid conflating the two.
//!
//! Invariants (property-tested below):
//! - `decode(encode(x)) == x` for all finite `i64`/`f64` (NaN collapses).
//! - `a <= b  ⇔  encode(a) <= encode(b)` for all non-NaN values.
//! - all NaN bit-patterns collapse to `u64::MAX`; `-0.0` normalizes to `+0.0`.

/// Stateless order-preserving codec (SPEC-009).
pub struct CanonicalKeyCodec;

impl CanonicalKeyCodec {
    /// High bit — the IEEE-754 / two's-complement sign position.
    pub const SIGN_BIT_MASK: u64 = 0x8000_0000_0000_0000;

    /// `i64 → u64` by flipping the sign bit, so negatives sort below positives.
    #[inline]
    pub fn encode_i64(v: i64) -> u64 {
        (v as u64) ^ Self::SIGN_BIT_MASK
    }

    /// Inverse of [`encode_i64`].
    #[inline]
    pub fn decode_i64(v: u64) -> i64 {
        (v ^ Self::SIGN_BIT_MASK) as i64
    }

    /// `f64 → u64` total order. All NaNs collapse to `u64::MAX` (sort last);
    /// `-0.0` is normalized to `+0.0` so the two neutral zeros share one key.
    #[inline]
    pub fn encode_f64(v: f64) -> u64 {
        if v.is_nan() {
            return u64::MAX;
        }
        // Collapse -0.0 into +0.0 (they are numerically equal).
        let normalized = if v == 0.0 { 0.0 } else { v };
        let bits = normalized.to_bits();
        if (bits >> 63) == 0 {
            // Positive (incl. +0.0, +inf): set the high bit → above negatives.
            bits ^ Self::SIGN_BIT_MASK
        } else {
            // Negative: invert every bit → larger magnitude sorts lower.
            !bits
        }
    }

    /// Inverse of [`encode_f64`]. `u64::MAX` decodes to a canonical quiet NaN.
    #[inline]
    pub fn decode_f64(v: u64) -> f64 {
        if v == u64::MAX {
            return f64::NAN;
        }
        if (v & Self::SIGN_BIT_MASK) != 0 {
            // High bit set → originally positive.
            f64::from_bits(v ^ Self::SIGN_BIT_MASK)
        } else {
            // High bit clear → originally negative.
            f64::from_bits(!v)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i64_roundtrip_and_order() {
        let mut xs = [i64::MIN, -1_000_000, -1, 0, 1, 42, 1_000_000, i64::MAX];
        for &x in &xs {
            assert_eq!(CanonicalKeyCodec::decode_i64(CanonicalKeyCodec::encode_i64(x)), x);
        }
        // Encoded keys must be monotonic in the source order.
        xs.sort();
        let keys: Vec<u64> = xs.iter().map(|&x| CanonicalKeyCodec::encode_i64(x)).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "encoded i64 keys must preserve order");
    }

    #[test]
    fn f64_roundtrip() {
        for &x in &[
            f64::NEG_INFINITY,
            f64::MIN,
            -1.5,
            -1.0,
            -f64::MIN_POSITIVE,
            0.0,
            f64::MIN_POSITIVE,
            1.0,
            1.5,
            f64::MAX,
            f64::INFINITY,
        ] {
            let back = CanonicalKeyCodec::decode_f64(CanonicalKeyCodec::encode_f64(x));
            assert_eq!(back, x, "roundtrip failed for {x}");
        }
    }

    #[test]
    fn f64_total_order() {
        let mut xs = [
            f64::NEG_INFINITY,
            f64::MIN,
            -1000.0,
            -1.5,
            -0.0,
            0.0,
            1.5,
            1000.0,
            f64::MAX,
            f64::INFINITY,
        ];
        xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let keys: Vec<u64> = xs.iter().map(|&x| CanonicalKeyCodec::encode_f64(x)).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "encoded f64 keys must preserve numeric order");
    }

    #[test]
    fn nan_collapses_and_neg_zero_normalizes() {
        // Every NaN bit-pattern maps to the same ceiling key.
        let q = f64::NAN;
        let s = f64::from_bits(0x7FF0_0000_0000_0001); // a signaling NaN
        assert!(s.is_nan());
        assert_eq!(CanonicalKeyCodec::encode_f64(q), u64::MAX);
        assert_eq!(CanonicalKeyCodec::encode_f64(s), u64::MAX);
        assert!(CanonicalKeyCodec::decode_f64(u64::MAX).is_nan());
        // -0.0 and +0.0 share one key.
        assert_eq!(
            CanonicalKeyCodec::encode_f64(-0.0),
            CanonicalKeyCodec::encode_f64(0.0)
        );
    }
}
