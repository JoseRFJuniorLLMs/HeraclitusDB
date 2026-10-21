//! heraclitus-activation — ACT-R, made O(1) (§3.7).
//!
//! Base-level activation `B_i = ln Σ_j t_j^(−d)` with the Petrov-style hybrid
//! approximation: exact sum over the last K accesses plus a closed-form tail.
//! Updates are O(1) on access; scoring is O(1) at read time; decay falls out
//! of the formula — no background job. Spec + error bound: docs/ACTIVATION.md.

use arrayvec::ArrayVec;
use heraclitus_core::{Episode, EventId, Lsn};
use heraclitus_views::View;
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap};
use std::sync::RwLock;

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

/// Store: event id -> activation record, mais o índice que deixa o `top_k`
/// parar cedo.
#[derive(Default)]
pub struct ActivationStore {
    /// Um só lock para o mapa e para o índice: o `touch` tem de mover o
    /// registo no índice na mesma secção crítica em que o altera, e o `top_k`
    /// lê os dois. Com o `DashMap` de antes mais um mutex para o índice, as
    /// duas operações tomavam os locks por ordens opostas (deadlock). As
    /// escritas já chegam serializadas pelo mutex das views do `Engine`.
    registos: RwLock<Registos>,
    decay: f64,
    watermark: Lsn,
}

#[derive(Default)]
struct Registos {
    mapa: HashMap<EventId, ActivationRecord>,
    /// `faixas[b]`: os registos com `n` em `[2^b, 2^(b+1))`, do acesso mais
    /// recente para o mais antigo (ver [`ActivationRecord::limite`]).
    faixas: Vec<BTreeSet<(Reverse<u64>, EventId)>>,
}

impl Registos {
    fn indexar(&mut self, id: EventId, chave: (usize, u64)) {
        let (faixa, t_ref) = chave;
        if self.faixas.len() <= faixa {
            self.faixas.resize_with(faixa + 1, BTreeSet::new);
        }
        self.faixas[faixa].insert((Reverse(t_ref), id));
    }

    fn desindexar(&mut self, id: EventId, chave: (usize, u64)) {
        let (faixa, t_ref) = chave;
        if let Some(conjunto) = self.faixas.get_mut(faixa) {
            conjunto.remove(&(Reverse(t_ref), id));
        }
    }
}

impl ActivationRecord {
    /// O instante mais recente que conta para o score: o último acesso
    /// retido ou o primeiro de todos, o que for maior (os instantes podem
    /// chegar fora de ordem).
    fn t_ref(&self) -> u64 {
        self.recent
            .iter()
            .copied()
            .max()
            .unwrap_or(self.first_access)
            .max(self.first_access)
    }

    /// Onde o registo vive no índice do `top_k`: a faixa de `n` e o `t_ref`.
    fn chave_de_indice(&self) -> (usize, u64) {
        let faixa = if self.n == 0 {
            0
        } else {
            63 - self.n.leading_zeros() as usize
        };
        (faixa, self.t_ref())
    }

    /// Limite superior do `score` em `now_secs` para QUALQUER registo da
    /// faixa `faixa` cujo `t_ref` seja `t_ref`, com `d > 0`.
    ///
    /// Com `a = max(now − t_ref, 1)`: cada termo exacto da soma tem idade
    /// `≥ a`, logo massa `≤ a^(−d)`; a cauda é `(n − k)` vezes a média de
    /// `x^(−d)` em `[h, l]` com `h ≥ a` (o acesso retido mais antigo e o
    /// primeiro acesso são ambos `≤ t_ref`), logo também `≤ (n − k)·a^(−d)`.
    /// Somado, `raw_sum ≤ n·a^(−d)` e `score ≤ ln(n) − d·ln(a)`, com `n` no
    /// máximo `2^(faixa+1) − 1`.
    fn limite(faixa: usize, t_ref: u64, now_secs: u64, d: f64) -> f64 {
        let n_max = if faixa >= 63 {
            u64::MAX as f64
        } else {
            ((1u64 << (faixa + 1)) - 1) as f64
        };
        let a = (now_secs.saturating_sub(t_ref)).max(1) as f64;
        n_max.ln() - d * a.ln()
    }
}

/// Uma entrada do top-k. A ordem é a do resultado (score desc, id asc); no
/// `BinaryHeap` o "maior" é o pior, para o topo do heap ser o k-ésimo.
struct Candidato(ActivationHit);

impl PartialEq for Candidato {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for Candidato {}

impl Ord for Candidato {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .0
            .score
            .total_cmp(&self.0.score)
            .then_with(|| self.0.id.cmp(&other.0.id))
    }
}

impl PartialOrd for Candidato {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Folga sobre o limite: absorve o arredondamento de `raw_sum` e do `ln`
/// (erro relativo ~1e-15 numa soma de no máximo `RECENT_K + 1` termos).
const FOLGA_DO_LIMITE: f64 = 1e-9;

#[cfg(test)]
thread_local! {
    /// Registos pontuados pelo último `top_k` desta thread.
    static PONTUADOS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, Clone)]
pub struct ActivationHit {
    pub id: EventId,
    pub score: f32,
}

impl ActivationStore {
    pub fn new(decay: f64) -> Self {
        Self {
            registos: RwLock::default(),
            decay,
            watermark: 0,
        }
    }

    fn ler(&self) -> std::sync::RwLockReadGuard<'_, Registos> {
        self.registos.read().unwrap_or_else(|e| e.into_inner())
    }

    fn escrever(&self) -> std::sync::RwLockWriteGuard<'_, Registos> {
        self.registos.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Record an access (retrieval touch or new episode).
    pub fn touch(&self, id: EventId, now_secs: u64) {
        let mut registos = self.escrever();
        let antes = registos
            .mapa
            .get(&id)
            .map(ActivationRecord::chave_de_indice);
        let registo = registos.mapa.entry(id).or_default();
        registo.access(now_secs);
        let depois = registo.chave_de_indice();
        if antes != Some(depois) {
            if let Some(antes) = antes {
                registos.desindexar(id, antes);
            }
            registos.indexar(id, depois);
        }
    }

    pub fn score(&self, id: &EventId, now_secs: u64) -> Option<f64> {
        self.ler()
            .mapa
            .get(id)
            .map(|r| r.score(now_secs, self.decay))
    }

    /// Top-k most active items at `now_secs`: os `k` maiores scores, desempate
    /// pelo id, exactamente como a ordenação total de todos os registos.
    ///
    /// Soak nightly de 20/10/2026: o recall pontuava TODOS os eventos a cada
    /// pesquisa (a view cria um registo por episódio). Agora percorre-se o
    /// índice por limite superior decrescente ([`ActivationRecord::limite`]) e
    /// pára-se quando o limite do próximo, já em `f32`, fica estritamente
    /// abaixo do k-ésimo score: nenhum dos que faltam pode entrar nem empatar.
    /// Com um acesso por registo o limite É o score e visitam-se `k`.
    ///
    /// `d ≤ 0` (sem decaimento, ou configuração inválida) não tem limite útil
    /// e cai na ordenação total.
    pub fn top_k(&self, now_secs: u64, k: usize) -> Vec<ActivationHit> {
        let registos = self.ler();
        if k == 0 {
            return Vec::new();
        }
        let d = self.decay;
        if !(d > 0.0 && d.is_finite()) || k >= registos.mapa.len() {
            return Self::top_k_total(&registos.mapa, now_secs, k, d);
        }
        // Um cursor por faixa; com no máximo 64 faixas, escolher o melhor
        // limite por varrimento linear é mais barato do que um heap.
        let mut cursores: Vec<_> = registos
            .faixas
            .iter()
            .enumerate()
            .map(|(faixa, conjunto)| (faixa, conjunto.iter().peekable()))
            .collect();
        let mut melhores: BinaryHeap<Candidato> = BinaryHeap::with_capacity(k + 1);
        #[cfg(test)]
        PONTUADOS.with(|c| c.set(0));
        loop {
            let mut escolhido: Option<(usize, f64)> = None;
            for (i, (faixa, cursor)) in cursores.iter_mut().enumerate() {
                if let Some((Reverse(t_ref), _)) = cursor.peek() {
                    let limite = ActivationRecord::limite(*faixa, *t_ref, now_secs, d);
                    if escolhido.is_none_or(|(_, melhor)| limite > melhor) {
                        escolhido = Some((i, limite));
                    }
                }
            }
            let Some((i, limite)) = escolhido else {
                break;
            };
            if melhores.len() == k {
                let k_esimo = melhores.peek().map_or(f32::NEG_INFINITY, |c| c.0.score);
                if ((limite + FOLGA_DO_LIMITE) as f32) < k_esimo {
                    break;
                }
            }
            let Some((_, id)) = cursores[i].1.next() else {
                continue;
            };
            let Some(registo) = registos.mapa.get(id) else {
                continue;
            };
            #[cfg(test)]
            PONTUADOS.with(|c| c.set(c.get() + 1));
            melhores.push(Candidato(ActivationHit {
                id: *id,
                score: registo.score(now_secs, d) as f32,
            }));
            if melhores.len() > k {
                melhores.pop();
            }
        }
        melhores
            .into_sorted_vec()
            .into_iter()
            .map(|c| c.0)
            .collect()
    }

    /// A ordenação de todos os registos: referência do `top_k` e o caminho
    /// quando não há limite útil.
    fn top_k_total(
        mapa: &HashMap<EventId, ActivationRecord>,
        now_secs: u64,
        k: usize,
        decay: f64,
    ) -> Vec<ActivationHit> {
        let mut hits: Vec<ActivationHit> = mapa
            .iter()
            .map(|(id, registo)| ActivationHit {
                id: *id,
                score: registo.score(now_secs, decay) as f32,
            })
            .collect();
        // Desempate por id: o mapa itera em ordem aleatória — o conjunto
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
        let mut map: std::collections::BTreeMap<EventId, (f64, f64)> =
            std::collections::BTreeMap::new();
        for c in context {
            for (i, n) in neighbors(c).into_iter().enumerate() {
                if i >= 64 {
                    break;
                }
                let base = self.score(&n, now_secs).unwrap_or(f64::NEG_INFINITY);
                if base.is_finite() {
                    let entry = map.entry(n).or_insert((base, 0.0));
                    entry.1 += weight;
                }
            }
        }
        let mut out: Vec<ActivationHit> = map
            .into_iter()
            .map(|(id, (base, spread_w))| ActivationHit {
                id,
                score: (base + spread_w) as f32,
            })
            .collect();
        out.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
        out
    }

    pub fn len(&self) -> usize {
        self.ler().mapa.len()
    }

    /// Bytes residentes, estimados pelas capacidades (ver
    /// `heraclitus_core::memoria`): o mapa e o índice ordenado do `top_k`.
    pub fn resident_bytes(&self) -> u64 {
        use heraclitus_core::memoria::{de_btree, de_hashmap, de_vec};
        let registos = self.ler();
        de_hashmap::<EventId, ActivationRecord>(registos.mapa.capacity())
            + de_vec::<BTreeSet<(Reverse<u64>, EventId)>>(registos.faixas.capacity())
            + registos
                .faixas
                .iter()
                .map(|faixa| de_btree::<(Reverse<u64>, EventId), ()>(faixa.len()))
                .sum::<u64>()
    }

    pub fn is_empty(&self) -> bool {
        self.ler().mapa.is_empty()
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
            .ler()
            .mapa
            .iter()
            .map(|(id, r)| (*id, r.recent.to_vec(), r.n, r.first_access))
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
        let mapa: HashMap<EventId, ActivationRecord> = snap
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
        // O índice do `top_k` é derivado: reconstrói-se do mapa, e o formato
        // do checkpoint não muda.
        let mut registos = Registos {
            mapa,
            faixas: Vec::new(),
        };
        let chaves: Vec<_> = registos
            .mapa
            .iter()
            .map(|(id, r)| (*id, r.chave_de_indice()))
            .collect();
        for (id, chave) in chaves {
            registos.indexar(id, chave);
        }
        *self.registos.get_mut().unwrap_or_else(|e| e.into_inner()) = registos;
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
        *self.registos.get_mut().unwrap_or_else(|e| e.into_inner()) = Registos::default();
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
                .ler()
                .mapa
                .iter()
                .map(|(id, r)| ActivationHit {
                    id: *id,
                    score: r.score(2_000, idx.decay) as f32,
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

    #[test]
    fn spread_deduplicates_and_sums_weights_from_multiple_context_sources() {
        let store = ActivationStore::new(0.5);
        let c1 = EventId::new();
        let c2 = EventId::new();
        let shared_neighbor = EventId::new();
        let unique_neighbor = EventId::new();

        store.touch(shared_neighbor, 1_000);
        store.touch(unique_neighbor, 1_000);

        let now = 2_000;
        let base_shared = store.score(&shared_neighbor, now).unwrap();
        let base_unique = store.score(&unique_neighbor, now).unwrap();
        let weight = 1.5f64;

        let neighbors_fn = |node: &EventId| {
            if *node == c1 {
                vec![shared_neighbor, unique_neighbor]
            } else if *node == c2 {
                vec![shared_neighbor]
            } else {
                vec![]
            }
        };

        let hits = store.spread(&[c1, c2], neighbors_fn, now, weight);

        // shared_neighbor deve aparecer apenas uma vez
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].id, shared_neighbor);
        assert_eq!(hits[1].id, unique_neighbor);

        // shared_neighbor recebe 2 * weight
        let expected_shared = (base_shared + 2.0 * weight) as f32;
        let expected_unique = (base_unique + 1.0 * weight) as f32;

        assert!((hits[0].score - expected_shared).abs() < 1e-5);
        assert!((hits[1].score - expected_unique).abs() < 1e-5);
    }
}

#[cfg(test)]
mod testes_top_k_por_limite {
    //! Soak nightly de 20/10/2026: o `top_k` deixa de pontuar todos os
    //! registos. O contrato é dar EXACTAMENTE o que a ordenação total dá —
    //! mesmos elementos, mesma ordem, mesmo desempate por id.
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir;

    fn referencia(store: &ActivationStore, now: u64, k: usize) -> Vec<(EventId, u32)> {
        ActivationStore::top_k_total(&store.ler().mapa, now, k, store.decay)
            .into_iter()
            .map(|h| (h.id, h.score.to_bits()))
            .collect()
    }

    fn obtido(store: &ActivationStore, now: u64, k: usize) -> Vec<(EventId, u32)> {
        store
            .top_k(now, k)
            .into_iter()
            .map(|h| (h.id, h.score.to_bits()))
            .collect()
    }

    proptest! {
        /// Acessos aleatórios: vários por registo, instantes repetidos (empates
        /// em f32) e fora de ordem, `now` antes de alguns acessos, decay
        /// padrão e não padrão.
        #[test]
        fn top_k_por_limite_igual_a_ordenacao_total(
            acessos in proptest::collection::vec((0usize..60, 0u64..2_000), 1..400),
            now in 0u64..3_000,
            k in 1usize..70,
            decay_meio in any::<bool>(),
        ) {
            let store = ActivationStore::new(if decay_meio { 0.5 } else { 0.83 });
            let mut ids: Vec<EventId> = (0..60).map(|_| EventId::new()).collect();
            ids.sort();
            for (i, t) in acessos {
                store.touch(ids[i], t);
            }
            prop_assert_eq!(obtido(&store, now, k), referencia(&store, now, k));
        }
    }

    /// Um acesso por registo (o que a view faz por episódio): o limite é o
    /// próprio score, e só se pontuam os `k` primeiros.
    #[test]
    fn um_acesso_por_registo_pontua_so_k() {
        let store = ActivationStore::new(0.5);
        for i in 0..10_000u64 {
            store.touch(EventId::new(), 1_000 + i);
        }
        let now = 20_000;
        assert_eq!(obtido(&store, now, 10), referencia(&store, now, 10));
        let pontuados = PONTUADOS.with(|c| c.get());
        assert!(pontuados <= 11, "pontuou {pontuados} registos para k = 10");
    }

    /// Sem decaimento (`d = 0`, o `Default`) não há limite útil: ordenação
    /// total, com o mesmo resultado.
    #[test]
    fn sem_decaimento_cai_na_ordenacao_total() {
        let store = ActivationStore::default();
        for i in 0..50u64 {
            let id = EventId::new();
            for _ in 0..=(i % 4) {
                store.touch(id, i);
            }
        }
        assert_eq!(obtido(&store, 100, 5), referencia(&store, 100, 5));
    }

    /// O índice é derivado: depois de um checkpoint e restore, e depois de um
    /// reset, o `top_k` continua igual à ordenação total.
    #[test]
    fn restore_e_reset_reconstroem_o_indice() {
        let dir = tempdir().unwrap();
        let store = ActivationStore::new(0.5);
        let ids: Vec<EventId> = (0..200).map(|_| EventId::new()).collect();
        for (i, id) in ids.iter().enumerate() {
            for j in 0..=(i % 12) {
                store.touch(*id, 1_000 + (i as u64) * 7 + j as u64);
            }
        }
        store.checkpoint(dir.path()).unwrap();

        let mut recuperado = ActivationStore::new(0.5);
        assert!(recuperado.restore(dir.path()).unwrap());
        for k in [1, 9, 40] {
            assert_eq!(obtido(&recuperado, 5_000, k), referencia(&store, 5_000, k));
        }
        recuperado.touch(ids[3], 4_999);
        assert_eq!(
            obtido(&recuperado, 5_000, 3),
            referencia(&recuperado, 5_000, 3)
        );

        recuperado.reset();
        assert!(recuperado.top_k(5_000, 3).is_empty());
    }
}
