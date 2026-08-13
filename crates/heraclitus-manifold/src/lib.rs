//! heraclitus-manifold — learned product geometry.
//!
//! `P = H^a(k1) x S^b(k2) x E^c`. Distances aggregate as
//! `dist(a,b) = sqrt(w1*d_H^2 + w2*d_S^2 + w3*d_E^2)` (standard for product
//! manifolds). All hyperbolic math promotes to f64 internally and clamps
//! norms near the Poincaré boundary (documented epsilons).

pub mod estimate;

use heraclitus_core::ProductPoint;
use serde::{Deserialize, Serialize};

/// Norms are clamped to `1 - BALL_EPS` before any hyperbolic operation.
pub const BALL_EPS: f64 = 1e-5;
/// Sphere normalization tolerance.
pub const SPHERE_EPS: f64 = 1e-6;

/// The learned signature of the product manifold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    pub a: usize,
    pub b: usize,
    pub c: usize,
    /// Hyperbolic curvature, k1 < 0 (we store |k1| as `c1 > 0`).
    pub k1: f64,
    /// Spherical curvature, k2 > 0.
    pub k2: f64,
    pub weights: [f64; 3],
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            a: 32,
            b: 8,
            c: 8,
            k1: -1.0,
            k2: 1.0,
            weights: [1.0, 1.0, 1.0],
        }
    }
}

/// The metric: distances and maps over [`ProductPoint`]s.
#[derive(Debug, Clone, Default)]
pub struct ProductMetric {
    pub sig: Signature,
}

// ---------- f64 vector helpers ----------

fn to64(v: &[f32]) -> Vec<f64> {
    v.iter().map(|x| *x as f64).collect()
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn norm(a: &[f64]) -> f64 {
    dot(a, a).sqrt()
}

fn scale(a: &[f64], s: f64) -> Vec<f64> {
    a.iter().map(|x| x * s).collect()
}

fn add(a: &[f64], b: &[f64]) -> Vec<f64> {
    a.iter().zip(b).map(|(x, y)| x + y).collect()
}

// ---------- allocation-free f32 helpers (hot path) ----------
// The component-distance functions run once per neighbour visit during an HNSW
// search. Promoting each element to f64 inline (instead of materializing two
// `Vec<f64>` via `to64` on every call) keeps the math identical while removing
// the per-call heap traffic that dominated the ANN hot path.

fn dot_f32(a: &[f32], b: &[f32]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(x, y)| (*x as f64) * (*y as f64))
        .sum()
}

fn norm_f32(a: &[f32]) -> f64 {
    dot_f32(a, a).sqrt()
}

/// Clamp a point strictly inside the unit ball.
pub fn project_to_ball(x: &mut [f32]) {
    let n = norm(&to64(x));
    let max = 1.0 - BALL_EPS;
    if n > max {
        let s = (max / n) as f32;
        for v in x.iter_mut() {
            *v *= s;
        }
    }
}

/// Normalize a point onto the unit sphere.
pub fn project_to_sphere(x: &mut [f32]) {
    let n = norm(&to64(x));
    if n > 0.0 {
        let s = (1.0 / n) as f32;
        for v in x.iter_mut() {
            *v *= s;
        }
    }
}

// ---------- component distances ----------

/// Poincaré-ball geodesic distance (curvature -c, c > 0).
///
/// The ball of curvature -c has radius `1/sqrt(c)`. Points are clamped strictly
/// inside *that* radius (not the unit ball) so `1 - c*n^2` is always > 0 — for
/// `c > 1` a unit-ball point can sit outside the c-ball, and masking the
/// resulting negative denominator (the old `denom.max(1e-15)`) produced garbage
/// distances. Clamping to `(1/sqrt(c))*(1-BALL_EPS)` keeps the denominator
/// positive by construction and makes the metric correct for any `c > 0`.
pub fn dist_hyp(u: &[f32], v: &[f32], c: f64) -> f64 {
    if u.is_empty() {
        return 0.0;
    }
    let max_norm = (1.0 - BALL_EPS) / c.sqrt(); // boundary of the curvature-c ball
                                                // Fold the boundary clamp into per-element scale factors instead of
                                                // materializing clamped vectors: a point whose norm exceeds `max_norm` is
                                                // scaled by `max_norm / n` (n > max_norm >= 0 implies n > 0), otherwise 1.
    let nu_raw = norm_f32(u);
    let nv_raw = norm_f32(v);
    let su = if nu_raw > max_norm {
        max_norm / nu_raw
    } else {
        1.0
    };
    let sv = if nv_raw > max_norm {
        max_norm / nv_raw
    } else {
        1.0
    };
    let nu = su * nu_raw; // norm(scale(u, su)) == su * norm(u)
    let nv = sv * nv_raw;
    let mut diff2 = 0.0f64; // |su*u - sv*v|^2 in a single pass
    for (x, y) in u.iter().zip(v) {
        let t = su * (*x as f64) - sv * (*y as f64);
        diff2 += t * t;
    }
    let denom = (1.0 - c * nu * nu) * (1.0 - c * nv * nv); // > 0 by the clamp above
    let arg = 1.0 + (2.0 * c * diff2 / denom);
    // Guarda anti-NaN: um embedding com NaN dava arg=NaN, e NaN.max(1.0) == 1.0
    // em Rust → acosh(1) = 0 → o vetor corrompido ficava a distância ZERO de
    // tudo (vizinho mais próximo universal). Não-finito = infinitamente longe.
    if !arg.is_finite() {
        return f64::INFINITY;
    }
    (1.0 / c.sqrt()) * arg.max(1.0).acosh()
}

/// Spherical geodesic distance (radius 1/sqrt(k2)).
pub fn dist_sph(u: &[f32], v: &[f32], k2: f64) -> f64 {
    if u.is_empty() {
        return 0.0;
    }
    let (nu, nv) = (norm_f32(u), norm_f32(v));
    if nu == 0.0 || nv == 0.0 {
        return 0.0;
    }
    let cos = (dot_f32(u, v) / (nu * nv)).clamp(-1.0, 1.0);
    cos.acos() / k2.sqrt()
}

/// Euclidean distance.
pub fn dist_euc(u: &[f32], v: &[f32]) -> f64 {
    if u.is_empty() {
        return 0.0;
    }
    let mut s = 0.0f64;
    for (x, y) in u.iter().zip(v) {
        let t = *x as f64 - *y as f64;
        s += t * t;
    }
    s.sqrt()
}

impl ProductMetric {
    /// Product-manifold distance: sqrt of weighted squared component distances.
    pub fn dist(&self, a: &ProductPoint, b: &ProductPoint) -> f64 {
        let c1 = -self.sig.k1; // store curvature as k1 < 0
        let dh = dist_hyp(&a.hyp, &b.hyp, c1);
        let ds = dist_sph(&a.sph, &b.sph, self.sig.k2);
        let de = dist_euc(&a.euc, &b.euc);
        let [w1, w2, w3] = self.sig.weights;
        (w1 * dh * dh + w2 * ds * ds + w3 * de * de).sqrt()
    }
}

// ---------- hyperbolic operations (curvature -1 convention helpers) ----------

/// Möbius addition on the Poincaré ball (c = 1).
pub fn mobius_add(x: &[f32], y: &[f32]) -> Vec<f32> {
    let (x, y) = (to64(x), to64(y));
    let xy = dot(&x, &y);
    let nx2 = dot(&x, &x);
    let ny2 = dot(&y, &y);
    let denom = 1.0 + 2.0 * xy + nx2 * ny2;
    let a = scale(&x, 1.0 + 2.0 * xy + ny2);
    let b = scale(&y, 1.0 - nx2);
    let mut out: Vec<f32> = add(&a, &b)
        .iter()
        .map(|v| (v / denom.max(1e-15)) as f32)
        .collect();
    project_to_ball(&mut out);
    out
}

/// Exponential map at the origin: tangent vector -> ball point.
pub fn exp_map0(v: &[f32]) -> Vec<f32> {
    let v64 = to64(v);
    let n = norm(&v64);
    if n < 1e-12 {
        return v.to_vec();
    }
    let s = n.tanh() / n;
    let mut out: Vec<f32> = v64.iter().map(|x| (x * s) as f32).collect();
    project_to_ball(&mut out);
    out
}

/// Logarithmic map at the origin: ball point -> tangent vector.
pub fn log_map0(y: &[f32]) -> Vec<f32> {
    let y64 = to64(y);
    let n = norm(&y64).min(1.0 - BALL_EPS);
    if n < 1e-12 {
        return y.to_vec();
    }
    let s = n.atanh() / n;
    y64.iter().map(|x| (x * s) as f32).collect()
}

/// Exponential map at x (via Möbius gyro-translation).
pub fn exp_map(x: &[f32], v: &[f32]) -> Vec<f32> {
    let x64 = to64(x);
    let nx2 = dot(&x64, &x64).min(1.0 - BALL_EPS);
    let lambda = 2.0 / (1.0 - nx2);
    let v64 = to64(v);
    let nv = norm(&v64);
    if nv < 1e-12 {
        return x.to_vec();
    }
    let s = (lambda * nv / 2.0).tanh() / nv;
    let step: Vec<f32> = v64.iter().map(|t| (t * s) as f32).collect();
    mobius_add(x, &step)
}

/// Logarithmic map at x.
pub fn log_map(x: &[f32], y: &[f32]) -> Vec<f32> {
    let neg_x: Vec<f32> = x.iter().map(|v| -v).collect();
    let d = mobius_add(&neg_x, y);
    let d64 = to64(&d);
    let nd = norm(&d64).min(1.0 - BALL_EPS);
    if nd < 1e-12 {
        return d;
    }
    let x64 = to64(x);
    let nx2 = dot(&x64, &x64).min(1.0 - BALL_EPS);
    let lambda = 2.0 / (1.0 - nx2);
    let s = (2.0 / lambda) * nd.atanh() / nd;
    d64.iter().map(|t| (t * s) as f32).collect()
}

/// Spherical midpoint (slerp at t=0.5), renormalized.
pub fn sph_midpoint(u: &[f32], v: &[f32]) -> Vec<f32> {
    let mut mid: Vec<f32> = u.iter().zip(v).map(|(a, b)| (a + b) / 2.0).collect();
    project_to_sphere(&mut mid);
    mid
}

/// Einstein-style weighted midpoint on the ball (used by distill).
pub fn hyp_centroid(points: &[Vec<f32>]) -> Vec<f32> {
    if points.is_empty() {
        return Vec::new();
    }
    let dim = points[0].len();
    let mut acc = vec![0.0f64; dim];
    let mut wsum = 0.0f64;
    for p in points {
        let p64 = to64(p);
        let n2 = dot(&p64, &p64).min(1.0 - BALL_EPS);
        let gamma = 1.0 / (1.0 - n2).sqrt();
        for (a, x) in acc.iter_mut().zip(&p64) {
            *a += gamma * x;
        }
        wsum += gamma;
    }
    let mut out: Vec<f32> = acc.iter().map(|x| (x / wsum) as f32).collect();
    project_to_ball(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ball_vec(dim: usize) -> impl Strategy<Value = Vec<f32>> {
        proptest::collection::vec(-0.6f32..0.6, dim).prop_map(|mut v| {
            project_to_ball(&mut v);
            v
        })
    }

    #[test]
    fn known_poincare_distance() {
        // Same-ray points at norms 0.2 and 0.6 (NietzscheDB book example):
        let u = vec![0.2f32, 0.0];
        let v = vec![0.6f32, 0.0];
        // arg = 1 + 2*0.16/((1-0.04)(1-0.36)) = 1.520833; acosh = 0.980829
        let d = dist_hyp(&u, &v, 1.0);
        assert!((d - 0.980829f64).abs() < 1e-4, "d = {d}");
    }

    #[test]
    fn curvature_gt_one_is_not_garbage() {
        // Regression (auditoria02 #1): with c>1 a unit-ball point can sit
        // outside the curvature-c ball; the old code masked the negative
        // denominator and returned ~24 for points 0.3 apart. After the fix the
        // boundary clamp keeps it finite and geometrically sane (a near-boundary
        // point is genuinely far, but nowhere near the old garbage value).
        let u = vec![0.6f32, 0.0];
        let v = vec![0.9f32, 0.0];
        let d2 = dist_hyp(&u, &v, 2.0);
        assert!(d2.is_finite(), "c=2 distance must be finite");
        assert!(
            d2 < 12.0,
            "c=2 distance must not blow up (was ~24.19), got {d2}"
        );
        // monotonic & symmetric still hold under c>1
        assert!((dist_hyp(&u, &v, 2.0) - dist_hyp(&v, &u, 2.0)).abs() < 1e-9);
        assert!(dist_hyp(&u, &u, 2.0) < 1e-9);
    }

    #[test]
    fn product_distance_zero_iff_equal() {
        let m = ProductMetric::default();
        let p = ProductPoint {
            hyp: vec![0.1, 0.2],
            sph: vec![1.0, 0.0],
            euc: vec![3.0],
        };
        assert!(m.dist(&p, &p) < 1e-9);
    }

    proptest! {
        #[test]
        fn ball_invariant_after_ops(x in ball_vec(8), y in ball_vec(8)) {
            let s = mobius_add(&x, &y);
            prop_assert!(norm(&to64(&s)) < 1.0);
        }

        #[test]
        fn exp_log_roundtrip(x in ball_vec(8)) {
            // 10 chained roundtrips must stay within 1e-4 (spec §3.3).
            let mut p = x.clone();
            for _ in 0..10 {
                p = exp_map0(&log_map0(&p));
            }
            let err: f64 = p.iter().zip(&x).map(|(a, b)| ((a - b) as f64).abs()).fold(0.0, f64::max);
            prop_assert!(err < 1e-4, "roundtrip drift {err}");
        }

        #[test]
        fn distance_symmetry(x in ball_vec(8), y in ball_vec(8)) {
            let d1 = dist_hyp(&x, &y, 1.0);
            let d2 = dist_hyp(&y, &x, 1.0);
            prop_assert!((d1 - d2).abs() < 1e-9);
        }

        #[test]
        fn triangle_inequality_sampled(x in ball_vec(6), y in ball_vec(6), z in ball_vec(6)) {
            let dxy = dist_hyp(&x, &y, 1.0);
            let dyz = dist_hyp(&y, &z, 1.0);
            let dxz = dist_hyp(&x, &z, 1.0);
            prop_assert!(dxz <= dxy + dyz + 1e-7);
        }

        #[test]
        fn sphere_norm_invariant(v in proptest::collection::vec(-1.0f32..1.0, 8)) {
            prop_assume!(v.iter().any(|x| x.abs() > 1e-3));
            let mut s = v.clone();
            project_to_sphere(&mut s);
            let n = norm(&to64(&s));
            prop_assert!((n - 1.0).abs() < SPHERE_EPS * 10.0);
        }
    }
}
