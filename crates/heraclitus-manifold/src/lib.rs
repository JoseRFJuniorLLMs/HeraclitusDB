//! heraclitus-manifold — learned product geometry.
//!
//! `P = H^a(k1) x S^b(k2) x E^c`. Distances aggregate as
//! `dist(a,b) = sqrt(w1*d_H^2 + w2*d_S^2 + w3*d_E^2)` (standard for product
//! manifolds). All hyperbolic math promotes to f64 internally and clamps
//! norms near the Poincaré boundary (documented epsilons).

pub mod estimate;

use heraclitus_core::ProductPoint;
use serde::{Deserialize, Serialize};

#[cfg(test)]
thread_local! {
    /// Instrumentacao de testes: permite provar que o caminho
    /// `dist2_prepared` nao volta a percorrer os vetores residentes para obter
    /// as suas normas. E thread-local para os testes paralelos nao interferirem
    /// uns com os outros.
    static NORM_F32_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

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
    #[cfg(test)]
    NORM_F32_CALLS.with(|calls| calls.set(calls.get() + 1));
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
    // Auditoria 2026-09-05 (A03): o `zip` abaixo TRUNCA em silencio pelo mais
    // curto dos dois vectores. Um candidato com menos dimensoes do que a
    // consulta dava diff2 = 0 -> arg = 1.0 (FINITO, portanto a guarda anti-NaN
    // mais abaixo nao dispara) -> acosh(1) = 0: ficava a distancia ZERO de toda
    // a gente e dominava a busca vectorial (HNSW e knn exacto do memtable) a
    // partir de um unico append. Nenhum caminho do servidor valida a dimensao
    // do embedding, por isso a recusa tem de viver aqui. Mesma politica ja
    // adoptada para o NaN: informacao incomparavel = infinitamente longe.
    // A guarda de vazio acima corre PRIMEIRO de proposito: uma consulta
    // parcial (so `hyp` preenchido, como a que `engine::nearest` constroi) e
    // legitima e continua a nao contribuir com as componentes que nao tem.
    if u.len() != v.len() {
        return f64::INFINITY;
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
    // Auditoria 2026-09-05 (A03): ver `dist_hyp` — comprimentos diferentes sao
    // incomparaveis, nao "iguais na parte comum".
    if u.len() != v.len() {
        return f64::INFINITY;
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
    // Auditoria 2026-09-05 (A03): ver `dist_hyp` — o `zip` truncava pelo mais
    // curto e um candidato mais curto ficava a distancia zero de tudo.
    if u.len() != v.len() {
        return f64::INFINITY;
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
        // Auditoria 2026-09-05 (A03): propagar o nao-finito ANTES de aplicar os
        // pesos. Com um peso a 0.0, `0.0 * inf` daria NaN e o candidato recusado
        // voltava a ordenar como plausivel — exactamente o defeito que a recusa
        // por dimensao existe para fechar.
        if !dh.is_finite() || !ds.is_finite() || !de.is_finite() {
            return f64::INFINITY;
        }
        let [w1, w2, w3] = self.sig.weights;
        (w1 * dh * dh + w2 * ds * ds + w3 * de * de).sqrt()
    }
}

// ---------------------------------------------------------------------------
// SPEC-otimizacao itens 1--3: consulta preparada, normas pre-calculadas, e
// ranking por distancia AO QUADRADO.
// ---------------------------------------------------------------------------

/// Parte de um [`ProductPoint`] que pode ser calculada uma vez quando o ponto
/// entra num indice e reutilizada em todas as consultas seguintes.
///
/// As normas sao mantidas em `f64`, apesar de os vetores serem `f32`, porque a
/// metrica canonica promove cada elemento antes de acumular. Guardar os valores
/// em `f32` pouparia 12 bytes por no, mas alteraria arredondamentos e poderia
/// trocar candidatos quase empatados no HNSW.
///
/// `hyp_scale` depende da curvatura da metrica usada na preparacao. Portanto um
/// `PreparedPoint` deve ser consumido por uma [`PreparedQuery`] criada a partir
/// da mesma [`ProductMetric`]. O `VectorIndex` garante essa invariavel e
/// reconstroi o cache quando restaura um checkpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PreparedPoint {
    hyp_norm: f64,
    hyp_scale: f64,
    sph_norm: f64,
}

impl PreparedPoint {
    /// Prepara as normas de um ponto residente sob `metric`.
    #[must_use]
    pub fn new(metric: &ProductMetric, point: &ProductPoint) -> Self {
        let c = -metric.sig.k1;
        let max_norm_h = (1.0 - BALL_EPS) / c.sqrt();
        Self::with_max_norm(point, max_norm_h)
    }

    fn with_max_norm(point: &ProductPoint, max_norm_h: f64) -> Self {
        let hyp_norm = norm_f32(&point.hyp);
        let hyp_scale = if hyp_norm > max_norm_h {
            max_norm_h / hyp_norm
        } else {
            1.0
        };
        Self {
            hyp_norm,
            hyp_scale,
            sph_norm: norm_f32(&point.sph),
        }
    }
}

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
        let prepared = PreparedPoint::with_max_norm(b, self.max_norm_h);
        self.dist2_prepared(b, &prepared)
    }

    /// Distancia do produto **ao quadrado** para um ponto residente preparado.
    ///
    /// Ao contrario de [`Self::dist2`], este metodo nao percorre `b.hyp` nem
    /// `b.sph` para recalcular normas. Os produtos internos e diferencas ainda
    /// precisam ler os vetores — sao a parte que realmente depende do par
    /// consulta/candidato.
    #[must_use]
    pub fn dist2_prepared(&self, b: &ProductPoint, prepared: &PreparedPoint) -> f64 {
        let dh = self.dist_hyp_prepared(&b.hyp, prepared);
        if !dh.is_finite() {
            return f64::INFINITY;
        }
        let ds = self.dist_sph_prepared(&b.sph, prepared);
        let de2 = dist_euc2(&self.euc, &b.euc);
        // Auditoria 2026-09-05 (A03): as outras duas componentes tambem podem
        // recusar por dimensao incompativel; sem esta guarda um peso a 0.0
        // transformaria o infinito em NaN antes de chegar ao chamador.
        if !ds.is_finite() || !de2.is_finite() {
            return f64::INFINITY;
        }
        let [w1, w2, w3] = self.pesos;
        w1 * dh * dh + w2 * ds * ds + w3 * de2
    }

    fn dist_hyp_prepared(&self, v: &[f32], prepared: &PreparedPoint) -> f64 {
        if self.hyp.is_empty() {
            return 0.0;
        }
        // Auditoria 2026-09-05 (A03): a mesma recusa de `dist_hyp`, aqui no
        // caminho preparado que o HNSW percorre por candidato visitado.
        if self.hyp.len() != v.len() {
            return f64::INFINITY;
        }
        let nv_raw = prepared.hyp_norm;
        let sv = prepared.hyp_scale;
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

    fn dist_sph_prepared(&self, v: &[f32], prepared: &PreparedPoint) -> f64 {
        if self.sph.is_empty() {
            return 0.0;
        }
        // Auditoria 2026-09-05 (A03): idem — ver `dist_sph`.
        if self.sph.len() != v.len() {
            return f64::INFINITY;
        }
        let nv = prepared.sph_norm;
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
    // Auditoria 2026-09-05 (A03): ver `dist_hyp` — o `zip` truncava pelo mais
    // curto e um candidato mais curto ficava a distancia zero de tudo.
    if u.len() != v.len() {
        return f64::INFINITY;
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

/// Incremental Einstein-style centroid on the Poincare ball.
///
/// For points `x_i`, the centroid used by [`hyp_centroid`] is
///
/// `sum(gamma_i * x_i) / sum(gamma_i)`, where
/// `gamma_i = 1 / sqrt(1 - min(||x_i||^2, 1 - BALL_EPS))`.
///
/// Both sufficient statistics are additive, so retaining them avoids rebuilding
/// and cloning every point whenever a streaming cluster receives one more
/// member. `add` is `O(dim)`, memory remains `O(dim)`, and points are accumulated
/// in insertion order to preserve deterministic floating-point results.
#[derive(Debug)]
pub struct HypCentroidAccumulator {
    weighted_sum: Vec<f64>,
    weight_sum: f64,
    centroid: Vec<f32>,
}

impl HypCentroidAccumulator {
    /// Creates an empty accumulator for points with `dim` coordinates.
    pub fn new(dim: usize) -> Self {
        Self {
            weighted_sum: vec![0.0; dim],
            weight_sum: 0.0,
            // Keep the materialized centroid in fixed-size storage too. This
            // makes repeated `add` calls allocation-free after construction.
            centroid: vec![0.0; dim],
        }
    }

    /// Adds one point and updates the materialized centroid.
    pub fn add(&mut self, point: &[f32]) {
        // Keep the operation order identical to the former batch
        // implementation: norm first, then one ordered accumulation per
        // coordinate. Dimension mismatches retain its zip/truncation semantics.
        let norm2: f64 = point
            .iter()
            .map(|x| {
                let x = *x as f64;
                x * x
            })
            .sum();
        let norm2 = norm2.min(1.0 - BALL_EPS);
        let gamma = 1.0 / (1.0 - norm2).sqrt();
        for (sum, x) in self.weighted_sum.iter_mut().zip(point) {
            *sum += gamma * (*x as f64);
        }
        self.weight_sum += gamma;

        for (out, sum) in self.centroid.iter_mut().zip(&self.weighted_sum) {
            *out = (*sum / self.weight_sum) as f32;
        }
        project_to_ball(&mut self.centroid);
    }

    /// Current centroid. Empty accumulators return a zero vector of `dim`.
    pub fn centroid(&self) -> &[f32] {
        &self.centroid
    }

    /// Consumes the accumulator and returns its current centroid.
    pub fn into_centroid(self) -> Vec<f32> {
        self.centroid
    }
}

/// Einstein-style weighted midpoint on the ball (used by distill).
pub fn hyp_centroid(points: &[Vec<f32>]) -> Vec<f32> {
    let Some(first) = points.first() else {
        return Vec::new();
    };
    let mut accumulator = HypCentroidAccumulator::new(first.len());
    for point in points {
        accumulator.add(point);
    }
    accumulator.into_centroid()
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

    fn batch_centroid_reference(points: &[Vec<f32>]) -> Vec<f32> {
        if points.is_empty() {
            return Vec::new();
        }
        let mut weighted_sum = vec![0.0f64; points[0].len()];
        let mut weight_sum = 0.0f64;
        for point in points {
            let point64 = to64(point);
            let norm2 = dot(&point64, &point64).min(1.0 - BALL_EPS);
            let gamma = 1.0 / (1.0 - norm2).sqrt();
            for (sum, x) in weighted_sum.iter_mut().zip(&point64) {
                *sum += gamma * x;
            }
            weight_sum += gamma;
        }
        let mut centroid: Vec<f32> = weighted_sum
            .iter()
            .map(|sum| (sum / weight_sum) as f32)
            .collect();
        project_to_ball(&mut centroid);
        centroid
    }

    #[test]
    fn incremental_centroid_is_bit_identical_to_batch_reference() {
        let points = [
            vec![0.10, -0.20, 0.05],
            vec![0.55, 0.12, -0.08],
            vec![-0.32, 0.21, 0.17],
            vec![0.91, 0.04, -0.02],
            vec![0.03, -0.11, 0.44],
        ];
        let mut incremental = HypCentroidAccumulator::new(points[0].len());
        for end in 1..=points.len() {
            incremental.add(&points[end - 1]);
            let reference = batch_centroid_reference(&points[..end]);
            let got_bits: Vec<u32> = incremental.centroid().iter().map(|x| x.to_bits()).collect();
            let reference_bits: Vec<u32> = reference.iter().map(|x| x.to_bits()).collect();
            assert_eq!(
                got_bits, reference_bits,
                "prefix of {end} points must preserve the former operation order"
            );
        }
    }

    #[test]
    fn incremental_centroid_storage_is_constant_after_construction() {
        let mut incremental = HypCentroidAccumulator::new(32);
        let sum_ptr = incremental.weighted_sum.as_ptr();
        let centroid_ptr = incremental.centroid.as_ptr();
        let point = vec![0.01; 32];
        for _ in 0..10_000 {
            incremental.add(&point);
        }
        assert_eq!(incremental.weighted_sum.as_ptr(), sum_ptr);
        assert_eq!(incremental.centroid.as_ptr(), centroid_ptr);
        assert_eq!(incremental.weighted_sum.len(), 32);
        assert_eq!(incremental.centroid.len(), 32);
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
        a.sort_by(|&x, &y| {
            metric
                .dist(&q, &cands[x])
                .total_cmp(&metric.dist(&q, &cands[y]))
        });
        let pq = PreparedQuery::new(&metric, &q);
        let mut b: Vec<usize> = (0..cands.len()).collect();
        b.sort_by(|&x, &y| pq.dist2(&cands[x]).total_cmp(&pq.dist2(&cands[y])));
        assert_eq!(a, b);
    }

    /// O cache residente tem de ser uma optimizacao pura: para os mesmos
    /// valores ja usados por `PreparedQuery::dist2`, o resultado e bit a bit
    /// identico. Assim nao introduzimos uma nova fonte de desempate no HNSW.
    #[test]
    fn o_ponto_preparado_e_bit_a_bit_igual_ao_caminho_existente() {
        let mut rng = Rng(0xd1ce_cafe_1234_5678);
        for caso in 0..2_000 {
            let mut metric = ProductMetric::default();
            metric.sig.k1 = -[0.25, 1.0, 2.0][caso % 3];
            metric.sig.k2 = [0.5, 1.0, 3.0][caso % 3];
            let amp = [0.1, 0.6, 0.99, 3.0][caso % 4];
            let q = ponto(&mut rng, 8, amp);
            let b = ponto(&mut rng, 8, amp);
            let query = PreparedQuery::new(&metric, &q);
            let point = PreparedPoint::new(&metric, &b);
            let anterior = query.dist2(&b);
            let residente = query.dist2_prepared(&b, &point);
            assert_eq!(
                anterior.to_bits(),
                residente.to_bits(),
                "caso {caso}: {anterior} vs {residente}"
            );
        }
    }

    /// Prova mecanica do ganho pretendido pelo item 2: depois da preparacao,
    /// cem comparacoes nao executam uma unica chamada a `norm_f32`. O caminho
    /// de compatibilidade (`dist2`) continua a calcular as duas normas.
    #[test]
    fn dist2_prepared_nao_recalcula_normas_do_candidato() {
        let mut rng = Rng(0xdec0_de01);
        let metric = ProductMetric::default();
        let q = ponto(&mut rng, 32, 0.5);
        let b = ponto(&mut rng, 32, 0.5);
        let query = PreparedQuery::new(&metric, &q);
        let point = PreparedPoint::new(&metric, &b);

        NORM_F32_CALLS.with(|calls| calls.set(0));
        for _ in 0..100 {
            std::hint::black_box(query.dist2_prepared(&b, &point));
        }
        let prepared_calls = NORM_F32_CALLS.with(std::cell::Cell::get);
        assert_eq!(prepared_calls, 0, "o cache residente nao foi usado");

        std::hint::black_box(query.dist2(&b));
        let compatibility_calls = NORM_F32_CALLS.with(std::cell::Cell::get);
        assert_eq!(
            compatibility_calls, 2,
            "hyp e sph devem ser as duas normas calculadas no caminho sem cache"
        );
    }

    /// Componentes vazias sao uma configuracao legitima.
    #[test]
    fn componentes_vazias_comportam_se_como_na_canonica() {
        let metric = ProductMetric::default();
        let so_euc = |v: Vec<f32>| ProductPoint {
            hyp: vec![],
            sph: vec![],
            euc: v,
        };
        let q = so_euc(vec![1.0, 2.0]);
        let b = so_euc(vec![4.0, 6.0]);
        let c = metric.dist(&q, &b);
        let p = PreparedQuery::new(&metric, &q).dist2(&b);
        assert!((p - c * c).abs() < 1e-9);
        let vazio = ProductPoint {
            hyp: vec![],
            sph: vec![],
            euc: vec![],
        };
        assert_eq!(PreparedQuery::new(&metric, &vazio).dist2(&vazio), 0.0);
    }

    /// Um NaN continua infinitamente distante, e nao vizinho universal.
    #[test]
    fn um_nan_continua_infinitamente_distante() {
        let metric = ProductMetric::default();
        let q = ProductPoint {
            hyp: vec![0.1, 0.2],
            sph: vec![],
            euc: vec![],
        };
        let mau = ProductPoint {
            hyp: vec![f32::NAN, 0.2],
            sph: vec![],
            euc: vec![],
        };
        assert!(!PreparedQuery::new(&metric, &q).dist2(&mau).is_finite());
    }

    /// Auditoria 2026-09-05 (A03): um candidato com uma componente mais CURTA
    /// do que a da consulta era truncado em silencio pelo `zip` e ficava a
    /// distancia ZERO de toda a gente — vizinho universal com um unico append.
    ///
    /// O caso `mau` e exactamente o que a barreira de ingestao deixa passar
    /// hoje (`grpc.rs` so exige que os tres componentes nao estejam TODOS
    /// vazios). Cada componente e testada por si: corrigir uma so das guardas
    /// nao chega.
    #[test]
    fn um_candidato_de_dimensao_diferente_e_infinitamente_distante() {
        let metric = ProductMetric::default();

        // Componente hiperbolica: consulta de 3 dims contra candidatos mais curtos.
        let q = ProductPoint {
            hyp: vec![0.3, 0.4, 0.1],
            sph: vec![],
            euc: vec![],
        };
        let mau = ProductPoint {
            hyp: vec![],
            sph: vec![1.0],
            euc: vec![],
        };
        let curto = ProductPoint {
            hyp: vec![0.3],
            sph: vec![],
            euc: vec![],
        };
        for (nome, candidato) in [("hyp vazio", &mau), ("hyp curto", &curto)] {
            let canonica = metric.dist(&q, candidato);
            let preparada = PreparedQuery::new(&metric, &q).dist2(candidato);
            assert!(
                canonica.is_infinite(),
                "{nome}: dist canonica devia ser infinita, foi {canonica}"
            );
            assert!(
                preparada.is_infinite(),
                "{nome}: dist2 preparada devia ser infinita, foi {preparada}"
            );
        }

        // Componente esferica.
        let q_sph = ProductPoint {
            hyp: vec![],
            sph: vec![1.0, 0.0],
            euc: vec![],
        };
        let mau_sph = ProductPoint {
            hyp: vec![],
            sph: vec![1.0],
            euc: vec![],
        };
        assert!(metric.dist(&q_sph, &mau_sph).is_infinite());
        assert!(PreparedQuery::new(&metric, &q_sph)
            .dist2(&mau_sph)
            .is_infinite());

        // Componente euclidiana.
        let q_euc = ProductPoint {
            hyp: vec![],
            sph: vec![],
            euc: vec![1.0, 2.0],
        };
        let mau_euc = ProductPoint {
            hyp: vec![],
            sph: vec![],
            euc: vec![1.0],
        };
        assert!(metric.dist(&q_euc, &mau_euc).is_infinite());
        assert!(PreparedQuery::new(&metric, &q_euc)
            .dist2(&mau_euc)
            .is_infinite());
    }

    /// Guarda de nao-regressao do fix acima: uma consulta PARCIAL — so `hyp`
    /// preenchido, que e o formato que `engine::nearest` constroi — continua a
    /// ignorar as componentes que a consulta nao tem, em vez de as declarar
    /// infinitamente distantes. Este teste morre se a comparacao de
    /// comprimentos passar a correr ANTES da guarda `is_empty`.
    #[test]
    fn consulta_parcial_continua_a_ignorar_as_componentes_vazias() {
        let metric = ProductMetric::default();
        let mut rng = Rng(0x0bad_c0de_0bad_c0de);
        let q = ProductPoint {
            hyp: (0..32).map(|_| rng.f32(0.1)).collect(),
            sph: vec![],
            euc: vec![],
        };
        let b = ProductPoint {
            hyp: (0..32).map(|_| rng.f32(0.1)).collect(),
            sph: (0..8).map(|_| rng.f32(1.0)).collect(),
            euc: (0..8).map(|_| rng.f32(5.0)).collect(),
        };
        let dh = dist_hyp(&q.hyp, &b.hyp, -metric.sig.k1);
        assert!(dh.is_finite() && dh > 0.0, "dh = {dh}");

        let canonica = metric.dist(&q, &b);
        assert!(canonica.is_finite(), "dist canonica = {canonica}");
        assert!((canonica - dh).abs() < 1e-9, "{canonica} != {dh}");

        let preparada = PreparedQuery::new(&metric, &q).dist2(&b);
        assert!(preparada.is_finite(), "dist2 preparada = {preparada}");
        assert!((preparada - dh * dh).abs() < 1e-9);

        // E o simetrico: uma consulta que so tem `euc` contra o mesmo
        // candidato completo. Cobre a ordem das guardas em `dist_hyp` e
        // `dist_sph` (consulta vazia, candidato de 32 e 8 dims).
        let so_euc = ProductPoint {
            hyp: vec![],
            sph: vec![],
            euc: b.euc.iter().map(|x| x + 0.5).collect(),
        };
        let de = dist_euc(&so_euc.euc, &b.euc);
        assert!(de.is_finite() && de > 0.0, "de = {de}");

        let canonica_euc = metric.dist(&so_euc, &b);
        assert!(
            canonica_euc.is_finite(),
            "consulta so com euc = {canonica_euc}"
        );
        assert!((canonica_euc - de).abs() < 1e-9, "{canonica_euc} != {de}");

        let preparada_euc = PreparedQuery::new(&metric, &so_euc).dist2(&b);
        assert!(
            preparada_euc.is_finite(),
            "consulta so com euc, preparada = {preparada_euc}"
        );
        assert!((preparada_euc - de * de).abs() < 1e-9);
    }
}
#[cfg(test)]
mod perfil_componentes {
    use super::*;
    use std::time::Instant;

    /// Onde e que o tempo por candidato vai mesmo.
    ///
    /// # Porque este diagnostico ficou no ficheiro
    ///
    /// O item 4 da SPEC-otimizacao pede SIMD (AVX2/FMA) nas metricas e da-lhe
    /// tres asteriscos de CPU. Implementei-o de duas formas e MEDI as duas,
    /// com a geometria real (H32 x S8 x E8):
    ///
    /// - intrinsecas AVX2 por componente, com despacho por chamada:
    ///   **1,6x MAIS LENTO** (2,3 ms/consulta contra 1,4 ms). Uma funcao
    ///   `#[target_feature]` nao pode ser inlinada num chamador sem a feature,
    ///   portanto cada componente virava uma chamada real por candidato — e
    ///   para vectores de 32 e 8 elementos isso custa mais do que vectorizar
    ///   poupa;
    /// - a funcao INTEIRA marcada com AVX2, com os lacos a entrar por
    ///   `inline(always)` e auto-vectorizacao: 1,2--1,5 ms contra 1,4--1,5 ms
    ///   escalar. Empate dentro do ruido.
    ///
    /// Este teste diz porque: cerca de **dois tercos** do tempo por candidato
    /// esta nas transcendentais (`acosh`, `acos`) e na aritmetica escalar a
    /// volta, nao nos produtos internos. Mesmo um SIMD perfeito no terco
    /// restante daria menos de 1,4x global.
    ///
    /// Conclusao, e a razao de nao haver `unsafe` neste crate: para ESTA
    /// geometria o item 4 nao e o alvo. Os alvos sao os que evitam trabalho em
    /// vez de o acelerar — SQ8 para gerar candidatos (item 13) e `ef`
    /// adaptativo (item 12), que reduzem QUANTOS candidatos se avaliam.
    ///
    /// Correr com:
    ///   cargo test -p heraclitus-manifold --lib perfil -- --ignored --nocapture
    #[test]
    #[ignore]
    fn onde_vai_o_tempo_por_candidato() {
        let metric = ProductMetric::default();
        let mk = |s: u64| {
            let mut x = s.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut p = move || {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                ((x % 2001) as f32 / 2000.0 - 0.5) * 0.8
            };
            ProductPoint {
                hyp: (0..32).map(|_| p()).collect(),
                sph: (0..8).map(|_| p()).collect(),
                euc: (0..8).map(|_| p()).collect(),
            }
        };
        let q = mk(1);
        let pts: Vec<ProductPoint> = (0..20_000).map(|i| mk(100 + i)).collect();
        let pq = PreparedQuery::new(&metric, &q);

        let t = Instant::now();
        let mut acc = 0.0f64;
        for p in &pts {
            acc += pq.dist2(p);
        }
        let total = t.elapsed();

        // So os produtos internos, sem transcendentais.
        let t2 = Instant::now();
        let mut acc2 = 0.0f64;
        for p in &pts {
            acc2 += dist_euc2(&q.hyp, &p.hyp) + dot_f32(&q.sph, &p.sph) + dist_euc2(&q.euc, &p.euc);
        }
        let so_produtos = t2.elapsed();

        println!("dist2 completa   : {:>10.3?}  ({acc:.3})", total);
        println!("so os produtos   : {:>10.3?}  ({acc2:.3})", so_produtos);
        println!(
            "fraccao em transcendentais e resto: {:.0}%",
            100.0 * (1.0 - so_produtos.as_secs_f64() / total.as_secs_f64())
        );
    }
}
