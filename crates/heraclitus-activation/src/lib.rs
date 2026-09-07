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

#[inline]
fn decay_mass(age: f64, d: f64) -> f64 {
    // O perfil padrão ACT-R usa d=0.5. A potência genérica entra em libm;
    // 1/sqrt(age) é a mesma função matemática e usa a instrução especializada.
    if d.to_bits() == 0.5f64.to_bits() {
        1.0 / age.sqrt()
    } else {
        age.powf(-d)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ActivationRecord {
    /// Last K access timestamps (seconds) — exact head.
    pub recent: ArrayVec<u64, RECENT_K>,
    /// Posição a sobrescrever quando `recent` está cheio — o que torna o
    /// buffer circular em vez de deslocado.
    pub proximo_slot: usize,
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
        // `remove(0)` desloca todo o buffer a cada acesso depois de ele
        // encher — O(RECENT_K) por acesso, e o acesso é a operação mais
        // frequente desta estrutura. Com o buffer cheio, sobrescreve-se a
        // posição mais antiga em vez de deslocar: O(1).
        //
        // A ordem deixa de ser cronológica dentro do `ArrayVec`. O somatório
        // em `raw_sum` não se importa — trata os instantes como um conjunto —
        // mas a CAUDA importa-se: precisa da idade do acesso mais antigo ainda
        // retido, que a versão deslocada lia em `recent.first()`.
        //
        // Num buffer circular esse elemento é exactamente o próximo a ser
        // sobrescrito, portanto continua a ser O(1) — ver `mais_antigo`. Foi um
        // teste existente (`approximation_error_bound`) que apanhou esta
        // dependência depois de eu ter afirmado, no primeiro comentário, que a
        // ordem não importava.
        if self.recent.is_full() {
            self.recent[self.proximo_slot] = now_secs;
            self.proximo_slot = (self.proximo_slot + 1) % RECENT_K;
        } else {
            self.recent.push(now_secs);
        }
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

    /// O instante do acesso mais antigo ainda retido em `recent`.
    ///
    /// Com o buffer cheio, é a posição que vai ser sobrescrita a seguir — o
    /// buffer é circular, portanto o próximo a sair é o mais velho. Antes de
    /// encher, os elementos ainda estão por ordem de chegada e o mais antigo é
    /// o primeiro.
    fn mais_antigo(&self) -> Option<u64> {
        if self.recent.is_full() {
            self.recent.get(self.proximo_slot).copied()
        } else {
            self.recent.first().copied()
        }
    }

    /// The pre-logarithm activation mass (exposed for error-bound tests).
    pub fn raw_sum(&self, now_secs: u64, d: f64) -> f64 {
        if self.n == 0 {
            return 0.0;
        }
        let mut sum = 0.0f64;
        for &t in &self.recent {
            let age = (now_secs.saturating_sub(t)).max(1) as f64;
            sum += decay_mass(age, d);
        }
        let k = self.recent.len() as u64;
        if self.n > k {
            let life = (now_secs.saturating_sub(self.first_access)).max(1) as f64;
            let oldest_recent_age =
                (now_secs.saturating_sub(self.mais_antigo().unwrap_or(now_secs))).max(1) as f64;
            let (h, l) = (
                oldest_recent_age.min(life),
                life.max(oldest_recent_age + 1.0),
            );
            // Caso d == 1.0: (l^(1-d) - h^(1-d))/(1-d) é 0/0; o limite correto é
            // ln(l) - ln(h). Sem isto o NaN era mascarado por max(0.0) e a cauda
            // contribuía 0 em silêncio — score errado para todo item longevo.
            let tail_num = if d.to_bits() == 0.5f64.to_bits() {
                2.0 * (l.sqrt() - h.sqrt())
            } else if (1.0 - d).abs() < 1e-12 {
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
        let ordem = |a: &ActivationHit, b: &ActivationHit| {
            b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id))
        };
        // Seleção parcial em vez de ordenação total: para devolver `k` de `n`
        // não é preciso ordenar os `n`. `select_nth_unstable_by` é O(n) e
        // deixa os `k` melhores no prefixo (por ordem arbitrária entre si);
        // ordenar só esse prefixo custa O(k log k).
        //
        // O resultado é IDÊNTICO ao da ordenação total porque o comparador é
        // uma ordem total — `total_cmp` sobre os scores, `id` a desempatar —
        // pelo que o conjunto dos `k` primeiros e a sua ordem ficam
        // determinados sem ambiguidade.
        if k < hits.len() {
            hits.select_nth_unstable_by(k, ordem);
            hits.truncate(k);
        }
        hits.sort_by(ordem);
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
                // `proximo_slot` NAO esta no snapshot, e nao precisa de estar:
                // e derivavel de `n`.
                //
                // Enquanto o buffer nao enche, `access` usa `push` e nunca toca
                // em `proximo_slot` — o valor e irrelevante. Depois de cheio,
                // `proximo_slot` e `n` avancam sempre juntos, e o buffer enche
                // exactamente em `n == RECENT_K` com `proximo_slot == 0`; logo
                // `proximo_slot == n % RECENT_K`.
                //
                // Sem isto, um restore punha `proximo_slot` a 0 sobre um buffer
                // cheio: `mais_antigo()` devolvia um instante recente em vez do
                // mais velho (inflacionando a cauda do `score`) e o `access`
                // seguinte sobrescrevia o slot errado. Derivar em vez de
                // persistir mantem os checkpoints antigos legiveis.
                if rec.recent.is_full() {
                    rec.proximo_slot = (n % RECENT_K as u64) as usize;
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

#[cfg(test)]
mod testes_otimizacao {
    use super::*;

    /// O fast path de `d = 0.5` troca apenas a forma de calcular a mesma
    /// função. A comparação cobre idades pequenas, grandes e não inteiras;
    /// a tolerância admite somente a diferença de arredondamento entre as
    /// implementações de `sqrt` e `powf` da plataforma.
    #[test]
    fn decay_meio_concorda_com_powf() {
        for age in [
            1.0,
            2.0,
            3.5,
            17.0,
            1_000.0,
            1_000_000_000.0,
            u32::MAX as f64,
        ] {
            let rapido = decay_mass(age, 0.5);
            let referencia = age.powf(-0.5);
            let erro_relativo = ((rapido - referencia) / referencia).abs();
            assert!(
                erro_relativo <= 4.0 * f64::EPSILON,
                "age={age}: rápido={rapido} referência={referencia} erro={erro_relativo}"
            );
        }
    }

    /// Decays diferentes do valor especializado continuam exactamente no
    /// caminho genérico; isto também protege configurações existentes.
    #[test]
    fn decay_nao_padrao_continua_bit_a_bit_igual_ao_powf() {
        for d in [0.0, 0.1, 0.49, 0.500_000_000_000_000_1, 0.9, 1.0] {
            let age = 12_345.0;
            assert_eq!(decay_mass(age, d).to_bits(), age.powf(-d).to_bits());
        }
    }

    /// Mede isoladamente o custo que aparece oito vezes por item pontuado.
    /// Ignorado por padrão para não transformar temporização em gate de CI.
    #[test]
    #[ignore = "microbenchmark manual do fast path d=0.5"]
    fn benchmark_decay_meio_sqrt_contra_powf() {
        use std::hint::black_box;
        use std::time::Instant;

        const N: u64 = 5_000_000;
        let inicio = Instant::now();
        let mut soma_powf = 0.0;
        for age in 1..=N {
            soma_powf += black_box(age as f64).powf(black_box(-0.5));
        }
        let tempo_powf = inicio.elapsed();

        let inicio = Instant::now();
        let mut soma_sqrt = 0.0;
        for age in 1..=N {
            soma_sqrt += 1.0 / black_box(age as f64).sqrt();
        }
        let tempo_sqrt = inicio.elapsed();

        let erro_relativo = ((soma_sqrt - soma_powf) / soma_powf).abs();
        assert!(erro_relativo < 1e-12);
        eprintln!(
            "N={N} powf={tempo_powf:?} sqrt={tempo_sqrt:?} ganho={:.2}x",
            tempo_powf.as_secs_f64() / tempo_sqrt.as_secs_f64()
        );
    }

    /// O buffer circular tem de continuar a saber qual e o acesso mais antigo.
    /// Foi isto que o `approximation_error_bound` apanhou quando eu troquei o
    /// `remove(0)` sem olhar para quem lia `recent.first()`.
    #[test]
    fn o_mais_antigo_esta_certo_depois_de_dar_a_volta() {
        let mut r = ActivationRecord::default();
        // Enche exactamente.
        for t in 0..RECENT_K as u64 {
            r.access(t + 1);
        }
        assert!(r.recent.is_full());
        assert_eq!(r.mais_antigo(), Some(1), "antes de dar a volta, o primeiro");

        // Uma volta completa: cada acesso substitui o mais velho.
        for i in 0..RECENT_K as u64 {
            let novo = 1000 + i;
            r.access(novo);
            let esperado = if i + 1 < RECENT_K as u64 {
                // ainda sobram instantes antigos; o mais velho e o seguinte
                i + 2
            } else {
                1000
            };
            assert_eq!(
                r.mais_antigo(),
                Some(esperado),
                "depois de {} sobrescritas o mais antigo devia ser {esperado}",
                i + 1
            );
        }
    }

    /// Antes de encher, o comportamento e o de sempre.
    #[test]
    fn antes_de_encher_o_mais_antigo_e_o_primeiro() {
        let mut r = ActivationRecord::default();
        r.access(10);
        r.access(20);
        assert_eq!(r.mais_antigo(), Some(10));
        assert_eq!(r.recent.len(), 2);
    }

    /// O somatorio nao depende da ordem — e o que permite o buffer circular.
    #[test]
    fn o_somatorio_e_o_mesmo_seja_qual_for_a_ordem() {
        let mut a = ActivationRecord::default();
        let mut b = ActivationRecord::default();
        for t in [100u64, 200, 300] {
            a.access(t);
        }
        for t in [300u64, 100, 200] {
            b.access(t);
        }
        a.n = 3;
        b.n = 3;
        let (sa, sb) = (a.raw_sum(1000, 0.5), b.raw_sum(1000, 0.5));
        assert!((sa - sb).abs() < 1e-12, "{sa} vs {sb}");
    }

    /// A seleccao parcial devolve exactamente o mesmo que a ordenacao total —
    /// mesmos elementos, mesma ordem, incluindo o desempate por id.
    #[test]
    fn o_top_k_parcial_concorda_com_a_ordenacao_total() {
        let idx = ActivationStore::new(0.5);
        let mut ids: Vec<EventId> = (0..500).map(|_| EventId::new()).collect();
        ids.sort();
        for (i, id) in ids.iter().enumerate() {
            // Muitos empates de proposito: e onde o desempate por id se ve.
            for _ in 0..=(i % 5) {
                idx.touch(*id, 1_000);
            }
        }
        for k in [1usize, 7, 50, 499, 500, 900] {
            let parcial = idx.top_k(2_000, k);
            // Referencia: ordenacao total, como era antes.
            let mut total: Vec<ActivationHit> = idx
                .records
                .iter()
                .map(|e| ActivationHit {
                    id: *e.key(),
                    score: e.value().score(2_000, idx.decay) as f32,
                })
                .collect();
            total.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
            total.truncate(k);
            assert_eq!(parcial.len(), total.len(), "k={k}");
            for (i, (p, t)) in parcial.iter().zip(total.iter()).enumerate() {
                assert_eq!(p.id, t.id, "k={k} posicao {i}");
            }
        }
    }

    /// O checkpoint nao persiste `proximo_slot`; o restore deriva-o de `n`. Se
    /// nao o fizesse, um buffer cheio e rodado voltava com `proximo_slot = 0`,
    /// `mais_antigo()` devolvia um instante recente em vez do mais velho, e o
    /// `score` mudava a seguir a um restore — estado que diverge de si mesmo ao
    /// atravessar o disco.
    #[test]
    fn restore_reconstroi_proximo_slot() {
        let dir = tempfile::tempdir().unwrap();
        let id = EventId::new();

        let store = ActivationStore::new(0.5);
        // 9 acessos com RECENT_K = 8: o buffer enche e roda uma vez, portanto
        // `proximo_slot` fica em 1 (nao em 0).
        for t in (1_000u64..=9_000).step_by(1_000) {
            store.touch(id, t);
        }
        let antes = store.score(&id, 100_000).unwrap();
        store.checkpoint(dir.path()).unwrap();

        let mut recuperado = ActivationStore::new(0.5);
        assert!(recuperado.restore(dir.path()).unwrap());
        let depois = recuperado.score(&id, 100_000).unwrap();

        assert!(
            (antes - depois).abs() < 1e-9,
            "o score nao pode mudar ao atravessar o checkpoint: {antes} vs {depois}"
        );
    }
}
