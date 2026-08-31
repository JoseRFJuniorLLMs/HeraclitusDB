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


// ---------------------------------------------------------------------------
// SPEC-otimizacao itens 1--3: consulta preparada, normas pre-calculadas, e
// ranking por distancia AO QUADRADO.
// ---------------------------------------------------------------------------

/// Uma consulta com tudo o que depende SÓ dela já calculado.
///
/// # O que se repetia por candidato
///
/// `ProductMetric::dist` é chamada uma vez por candidato visitado — centenas ou
/// milhares por busca — e cada chamada refazia, para a MESMA consulta:
///
/// - `max_norm = (1 - BALL_EPS) / sqrt(c)` e `1/sqrt(c)`: constantes da
///   curvatura, nada a ver com o candidato;
/// - `1/sqrt(k2)`: idem, na esfera;
/// - `norm(consulta)` na componente hiperbólica **e** na esférica: duas
///   passagens completas pelo vector mais duas raízes, idênticas em todas as
///   chamadas;
/// - a raiz euclidiana, imediatamente elevada ao quadrado a seguir;
/// - a raiz final do produto, que não muda a ORDEM de nada.
///
/// Aqui isso é feito uma vez. O que sobra por candidato é o trabalho que
/// depende mesmo do candidato.
///
/// # O que NÃO muda
///
/// [`ProductMetric::dist`] continua a ser a matemática canónica e não foi
/// tocada. [`PreparedQuery::dist2`] devolve o QUADRADO da mesma distância, e
/// como a raiz é monótona nos não-negativos a ordem é idêntica — quem precisa
/// do valor tira a raiz no fim, sobre os `k` resultados em vez de sobre todos
/// os candidatos. Há um teste que confronta as duas sobre milhares de pontos.
#[derive(Debug, Clone)]
pub struct PreparedQuery {
    hyp: Vec<f32>,
    sph: Vec<f32>,
    euc: Vec<f32>,
    /// Curvatura hiperbólica positiva (`c = -k1`).
    c: f64,
    max_norm_h: f64,
    inv_sqrt_c: f64,
    /// Escala de recorte da consulta.
    escala_h: f64,
    /// `1 - c·‖q‖²` já com a norma escalada: o factor da consulta no
    /// denominador, que é a única forma em que a norma é usada.
    denom_h: f64,
    /// Norma esférica da consulta; zero significa "componente degenerada".
    norma_sph: f64,
    inv_sqrt_k2: f64,
    pesos: [f64; 3],
}

impl PreparedQuery {
    /// Prepara `q` para ser comparada muitas vezes sob `metric`.
    pub fn new(metric: &ProductMetric, q: &ProductPoint) -> Self {
        let c = -metric.sig.k1;
        let max_norm_h = (1.0 - BALL_EPS) / c.sqrt();
        let bruto = norm_f32(&q.hyp);
        let escala_h = if bruto > max_norm_h {
            max_norm_h / bruto
        } else {
            1.0
        };
        let norma_h = escala_h * bruto;
        Self {
            hyp: q.hyp.clone(),
            sph: q.sph.clone(),
            euc: q.euc.clone(),
            c,
            max_norm_h,
            inv_sqrt_c: 1.0 / c.sqrt(),
            escala_h,
            denom_h: 1.0 - c * norma_h * norma_h,
            norma_sph: norm_f32(&q.sph),
            inv_sqrt_k2: 1.0 / metric.sig.k2.sqrt(),
            pesos: metric.sig.weights,
        }
    }

    /// Distância do produto **ao quadrado** entre a consulta e `b`.
    ///
    /// Mesma ordem que [`ProductMetric::dist`], sem a raiz final e sem
    /// recalcular nada que dependa só da consulta.
    pub fn dist2(&self, b: &ProductPoint) -> f64 {
        let dh = self.dist_hyp(&b.hyp);
        if !dh.is_finite() {
            return f64::INFINITY;
        }
        let ds = self.dist_sph(&b.sph);
        let de2 = dist_euc2(&self.euc, &b.euc);
        let [w1, w2, w3] = self.pesos;
        w1 * dh * dh + w2 * ds * ds + w3 * de2
    }

    fn dist_hyp(&self, v: &[f32]) -> f64 {
        if self.hyp.is_empty() {
            return 0.0;
        }
        let nv_raw = norm_f32(v);
        let sv = if nv_raw > self.max_norm_h {
            self.max_norm_h / nv_raw
        } else {
            1.0
        };
        let nv = sv * nv_raw;
        let mut diff2 = 0.0f64;
        for (x, y) in self.hyp.iter().zip(v) {
            let t = self.escala_h * (*x as f64) - sv * (*y as f64);
            diff2 += t * t;
        }
        let denom = self.denom_h * (1.0 - self.c * nv * nv);
        let arg = 1.0 + (2.0 * self.c * diff2 / denom);
        if !arg.is_finite() {
            return f64::INFINITY;
        }
        self.inv_sqrt_c * arg.max(1.0).acosh()
    }

    fn dist_sph(&self, v: &[f32]) -> f64 {
        if self.sph.is_empty() {
            return 0.0;
        }
        let nv = norm_f32(v);
        if self.norma_sph == 0.0 || nv == 0.0 {
            return 0.0;
        }
        let cos = (dot_f32(&self.sph, v) / (self.norma_sph * nv)).clamp(-1.0, 1.0);
        cos.acos() * self.inv_sqrt_k2
    }
}

/// Distância euclidiana **ao quadrado** — a raiz de [`dist_euc`] só existia
/// para ser desfeita a seguir pelo quadrado do produto.
pub fn dist_euc2(u: &[f32], v: &[f32]) -> f64 {
    if u.is_empty() {
        return 0.0;
    }
    let mut s = 0.0f64;
    for (x, y) in u.iter().zip(v) {
        let t = *x as f64 - *y as f64;
        s += t * t;
    }
    s
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

#[cfg(test)]
mod testes_prepared {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn proximo(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn f32(&mut self, amp: f32) -> f32 {
            let u = (self.proximo() % 20_001) as f32 / 10_000.0 - 1.0;
            u * amp
        }
    }

    fn ponto(rng: &mut Rng, d: usize, amp: f32) -> ProductPoint {
        ProductPoint {
            hyp: (0..d).map(|_| rng.f32(amp)).collect(),
            sph: (0..d).map(|_| rng.f32(1.0)).collect(),
            euc: (0..d).map(|_| rng.f32(5.0)).collect(),
        }
    }

    /// A prova de que a consulta preparada nao mudou a matematica.
    #[test]
    fn a_consulta_preparada_concorda_com_a_metrica_canonica() {
        let mut rng = Rng(0x1234_5678_9abc_def0);
        let metric = ProductMetric::default();
        for caso in 0..2_000 {
            let d = 1 + (rng.proximo() % 8) as usize;
            let amp = match caso % 4 {
                0 => 0.1,
                1 => 0.6,
                2 => 0.99,
                _ => 3.0,
            };
            let q = ponto(&mut rng, d, amp);
            let b = ponto(&mut rng, d, amp);
            let canonica = metric.dist(&q, &b);
            let preparada = PreparedQuery::new(&metric, &q).dist2(&b);
            if !canonica.is_finite() {
                assert!(!preparada.is_finite(), "caso {caso}");
                continue;
            }
            let esperado = canonica * canonica;
            let tol = 1e-9 * esperado.abs().max(1.0);
            assert!(
                (preparada - esperado).abs() <= tol,
                "caso {caso} (d={d}, amp={amp}): {preparada} vs {esperado}"
            );
        }
    }

    /// O que interessa para o HNSW: a ORDEM.
    #[test]
    fn a_ordem_dos_candidatos_e_a_mesma() {
        let mut rng = Rng(0xfeed_beef);
        let metric = ProductMetric::default();
        let q = ponto(&mut rng, 6, 0.5);
        let cands: Vec<ProductPoint> = (0..200).map(|_| ponto(&mut rng, 6, 0.5)).collect();
        let mut a: Vec<usize> = (0..cands.len()).collect();
        a.sort_by(|&x, &y| metric.dist(&q, &cands[x]).total_cmp(&metric.dist(&q, &cands[y])));
        let pq = PreparedQuery::new(&metric, &q);
        let mut b: Vec<usize> = (0..cands.len()).collect();
        b.sort_by(|&x, &y| pq.dist2(&cands[x]).total_cmp(&pq.dist2(&cands[y])));
        assert_eq!(a, b);
    }

    /// Componentes vazias sao uma configuracao legitima.
    #[test]
    fn componentes_vazias_comportam_se_como_na_canonica() {
        let metric = ProductMetric::default();
        let so_euc = |v: Vec<f32>| ProductPoint { hyp: vec![], sph: vec![], euc: v };
        let q = so_euc(vec![1.0, 2.0]);
        let b = so_euc(vec![4.0, 6.0]);
        let c = metric.dist(&q, &b);
        let p = PreparedQuery::new(&metric, &q).dist2(&b);
        assert!((p - c * c).abs() < 1e-9);
        let vazio = ProductPoint { hyp: vec![], sph: vec![], euc: vec![] };
        assert_eq!(PreparedQuery::new(&metric, &vazio).dist2(&vazio), 0.0);
    }

    /// Um NaN continua infinitamente distante, e nao vizinho universal.
    #[test]
    fn um_nan_continua_infinitamente_distante() {
        let metric = ProductMetric::default();
        let q = ProductPoint { hyp: vec![0.1, 0.2], sph: vec![], euc: vec![] };
        let mau = ProductPoint { hyp: vec![f32::NAN, 0.2], sph: vec![], euc: vec![] };
        assert!(!PreparedQuery::new(&metric, &q).dist2(&mau).is_finite());
    }
}
