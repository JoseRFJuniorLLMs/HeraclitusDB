//! heraclitus-activation — ACT-R, made O(1) (§3.7).
//!
//! Base-level activation `B_i = ln Σ_j t_j^(−d)` with the Petrov-style hybrid
//! approximation: exact sum over the last K accesses plus a closed-form tail.
//! Updates are O(1) on access; scoring is O(1) at read time; decay falls out
//! of the formula — no background job. Spec + error bound: docs/ACTIVATION.md.

use arrayvec::ArrayVec;
use dashmap::DashMap;
use heraclitus_core::{Episode, EventId, Lsn};
use heraclitus_views::View;

pub const RECENT_K: usize = 8;

#[derive(Debug, Clone, Default)]
pub struct ActivationRecord {
    /// Last K access timestamps (seconds) — exact head.
    pub recent: ArrayVec<u64, RECENT_K>,
    /// Total access count.
    pub n: u64,
    /// Lifetime anchor: first access timestamp.
    pub first_access: u64,
}

impl ActivationRecord {
    pub fn access(&mut self, now_secs: u64) {
        if self.n == 0 {
            self.first_access = now_secs;
        }
        if self.recent.is_full() {
            self.recent.remove(0);
        }
        self.recent.push(now_secs);
        self.n += 1;
    }

    /// Petrov-style hybrid base-level activation at `now_secs`.
    ///
    /// `B = ln( Σ_{recent} (now − t_j)^(−d)  +  tail )` where the tail
    /// approximates the (n − k) older accesses as uniformly spread over their
    /// age range `[h, L]` (h = age of the oldest retained access, L =
    /// lifetime):
    ///
    /// `tail = (n − k) · (L^(1−d) − h^(1−d)) / ((1 − d) · (L − h))`
    ///
    /// Error bound and derivation: docs/ACTIVATION.md.
    pub fn score(&self, now_secs: u64, d: f64) -> f64 {
        self.raw_sum(now_secs, d).ln()
    }

    /// The pre-logarithm activation mass (exposed for error-bound tests).
    pub fn raw_sum(&self, now_secs: u64, d: f64) -> f64 {
        if self.n == 0 {
            return 0.0;
        }
        let mut sum = 0.0f64;
        for &t in &self.recent {
            let age = (now_secs.saturating_sub(t)).max(1) as f64;
            sum += age.powf(-d);
        }
        let k = self.recent.len() as u64;
        if self.n > k {
            let life = (now_secs.saturating_sub(self.first_access)).max(1) as f64;
            let oldest_recent_age = (now_secs
                .saturating_sub(self.recent.first().copied().unwrap_or(now_secs)))
            .max(1) as f64;
            let (h, l) = (
                oldest_recent_age.min(life),
                life.max(oldest_recent_age + 1.0),
            );
            // Caso d == 1.0: (l^(1-d) - h^(1-d))/(1-d) é 0/0; o limite correto é
            // ln(l) - ln(h). Sem isto o NaN era mascarado por max(0.0) e a cauda
            // contribuía 0 em silêncio — score errado para todo item longevo.
            let tail_num = if (1.0 - d).abs() < 1e-12 {
                l.ln() - h.ln()
            } else {
                (l.powf(1.0 - d) - h.powf(1.0 - d)) / (1.0 - d)
            };
            let tail = ((self.n - k) as f64) * tail_num / (l - h);
            sum += tail.max(0.0);
        }
        sum
    }

    /// Exact ACT-R activation given the full access trace (test oracle).
    pub fn exact(trace: &[u64], now_secs: u64, d: f64) -> f64 {
        let sum: f64 = trace
            .iter()
            .map(|&t| ((now_secs.saturating_sub(t)).max(1) as f64).powf(-d))
            .sum();
        sum.ln()
    }
}

/// Store: event id -> activation record. Hot-set in a concurrent map.
#[derive(Default)]
pub struct ActivationStore {
    records: DashMap<EventId, ActivationRecord>,
    decay: f64,
    watermark: Lsn,
}

#[derive(Debug, Clone)]
pub struct ActivationHit {
    pub id: EventId,
    pub score: f32,
}

impl ActivationStore {
    pub fn new(decay: f64) -> Self {
        Self {
            records: DashMap::new(),
            decay,
            watermark: 0,
        }
    }

    /// Record an access (retrieval touch or new episode).
    pub fn touch(&self, id: EventId, now_secs: u64) {
        self.records.entry(id).or_default().access(now_secs);
    }

    pub fn score(&self, id: &EventId, now_secs: u64) -> Option<f64> {
        self.records.get(id).map(|r| r.score(now_secs, self.decay))
    }

    /// Top-k most active items at `now_secs`.
    pub fn top_k(&self, now_secs: u64, k: usize) -> Vec<ActivationHit> {
        let mut hits: Vec<ActivationHit> = self
            .records
            .iter()
            .map(|e| ActivationHit {
                id: *e.key(),
                score: e.value().score(now_secs, self.decay) as f32,
            })
            .collect();
        // Desempate por id: o DashMap itera em ordem aleatória — o conjunto
        // top-k com scores empatados variava entre execuções.
        hits.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
        hits.truncate(k);
        hits
    }

    /// Spreading activation: one-hop weighted sum from the context set,
    /// fan-out capped at 64 (§3.7).
    pub fn spread(
        &self,
        context: &[EventId],
        neighbors: impl Fn(&EventId) -> Vec<EventId>,
        now_secs: u64,
        weight: f64,
    ) -> Vec<ActivationHit> {
        let mut out = Vec::new();
        for c in context {
            for (i, n) in neighbors(c).into_iter().enumerate() {
                if i >= 64 {
                    break;
                }
                let base = self.score(&n, now_secs).unwrap_or(f64::NEG_INFINITY);
                if base.is_finite() {
                    out.push(ActivationHit {
                        id: n,
                        score: (base + weight) as f32,
                    });
                }
            }
        }
        out.sort_by(|a, b| b.score.total_cmp(&a.score));
        out
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Snapshot serializável (fast boot): o `ArrayVec` do registo vira `Vec`
/// no disco e é reconstruído no restore (evita depender da feature serde do
/// arrayvec).
#[derive(serde::Serialize, serde::Deserialize)]
struct ActivationSnapshot {
    decay: f64,
    watermark: Lsn,
    records: Vec<(EventId, Vec<u64>, u64, u64)>, // (id, recent, n, first_access)
}

impl View for ActivationStore {
    fn name(&self) -> &str {
        "activation"
    }

    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), heraclitus_core::HeraclitusError> {
        let records = self
            .records
            .iter()
            .map(|e| {
                let r = e.value();
                (*e.key(), r.recent.to_vec(), r.n, r.first_access)
            })
            .collect();
        heraclitus_views::ckpt::save(
            dir,
            "activation",
            &ActivationSnapshot {
                decay: self.decay,
                watermark: self.watermark,
                records,
            },
        )
    }

    fn restore(&mut self, dir: &std::path::Path) -> Result<bool, heraclitus_core::HeraclitusError> {
        let Some(snap) = heraclitus_views::ckpt::load::<ActivationSnapshot>(dir, "activation")?
        else {
            return Ok(false);
        };
        self.records = snap
            .records
            .into_iter()
            .map(|(id, recent, n, first_access)| {
                let mut rec = ActivationRecord {
                    n,
                    first_access,
                    ..Default::default()
                };
                for t in recent.into_iter().take(RECENT_K) {
                    rec.recent.push(t);
                }
                (id, rec)
            })
            .collect();
        // O decay é configuração de runtime (config.activation_decay), não
        // estado derivado: mantém o do processo atual.
        self.watermark = snap.watermark;
        Ok(true)
    }

    /// Determinism note (§3.5): the "access time" used during replay is the
    /// episode's own HLC timestamp, never the wall clock.
    fn apply(&mut self, lsn: Lsn, event: &Episode) {
        self.touch(event.id, event.ts_hlc >> 16); // physical millis -> stable seconds-ish unit
                                                  // Avanço-só: dois appends concorrentes aplicam-se fora de ordem (o
                                                  // `index_applied` não tranca as views atomicamente), e um insert cru
                                                  // regredia este watermark. Persistido no snapshot, ficava a mentir
                                                  // sobre o que a view cobre — e esta view NÃO é idempotente (`touch`
                                                  // conta cada acesso), pelo que um re-replay contaria duas vezes.
        self.watermark = self.watermark.max(lsn);
    }

    fn watermark(&self) -> Lsn {
        self.watermark
    }

    fn reset(&mut self) {
        self.records.clear();
        self.watermark = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn recency_beats_staleness() {
        let mut fresh = ActivationRecord::default();
        let mut stale = ActivationRecord::default();
        stale.access(100);
        fresh.access(9_000);
        let now = 10_000;
        assert!(fresh.score(now, 0.5) > stale.score(now, 0.5));
    }

    #[test]
    fn frequency_matters() {
        let mut once = ActivationRecord::default();
        let mut many = ActivationRecord::default();
        once.access(5_000);
        for t in (1_000..6_000).step_by(500) {
            many.access(t);
        }
        assert!(many.score(10_000, 0.5) > once.score(10_000, 0.5));
    }

    proptest! {
        /// Spec gate (§3.7): relative error of the hybrid approximation vs the
        /// exact sum < 5% on synthetic traces up to 10k accesses.
        #[test]
        fn approximation_error_bound(n in 9usize..2_000, span in 10_000u64..1_000_000) {
            let now = 2_000_000u64;
            let start = now - span;
            let step = (span / n as u64).max(1);
            let trace: Vec<u64> = (0..n as u64).map(|i| start + i * step).collect();

            let mut rec = ActivationRecord::default();
            for &t in &trace {
                rec.access(t);
            }
            // Compare the pre-log activation mass (the quantity the
            // approximation actually bounds; ln crosses zero).
            let approx = rec.raw_sum(now, 0.5);
            let exact: f64 = trace
                .iter()
                .map(|&t| ((now.saturating_sub(t)).max(1) as f64).powf(-0.5))
                .sum();
            let rel = ((approx - exact) / exact).abs();
            prop_assert!(rel < 0.05, "relative error {rel} (approx {approx}, exact {exact})");
        }
    }
}

#[cfg(test)]
mod watermark_order_tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind};
    use heraclitus_views::View;

    /// Entrega FORA DE ORDEM (dois appends concorrentes indexam 6 antes de 5)
    /// não pode regredir o watermark: ele é persistido no checkpoint e esta
    /// view não é idempotente — um re-replay contaria o acesso duas vezes.
    #[test]
    fn out_of_order_apply_does_not_regress_watermark() {
        let mut s = ActivationStore::default();
        let e6 = Episode::new("a", EventKind::Observation, b"six".to_vec());
        let e5 = Episode::new("a", EventKind::Observation, b"five".to_vec());
        s.apply(6, &e6);
        assert_eq!(s.watermark(), 6);
        s.apply(5, &e5); // chega atrasado
        assert_eq!(
            s.watermark(),
            6,
            "watermark regrediu com entrega fora de ordem"
        );
    }
}
