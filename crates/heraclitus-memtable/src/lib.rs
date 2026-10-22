//! heraclitus-memtable — solves read-your-own-writes (§3.4).
//!
//! Async views lag behind the log head; the memtable holds everything above
//! the view watermark in RAM and every query merges
//! `memtable_results ∪ view_results` with LSN-based dedup. An agent must
//! always see its own write in the next query — hard correctness requirement.

use dashmap::DashMap;
use heraclitus_core::{Episode, EventId, Lsn, ProductPoint};
use heraclitus_manifold::ProductMetric;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

pub struct Memtable {
    cap: usize,
    byte_cap: usize,
    bytes: std::sync::atomic::AtomicUsize,
    /// `Arc` para partilhar a alocação que o log publica no `tail_subscribe`:
    /// a cauda em RAM não precisa de uma cópia própria de cada episódio.
    entries: RwLock<VecDeque<(Lsn, Arc<Episode>)>>,
    adjacency: DashMap<EventId, Vec<EventId>>,
}

#[derive(Debug, Clone)]
pub struct ScoredHit {
    pub id: EventId,
    pub lsn: Lsn,
    pub score: f32,
}

impl Memtable {
    pub fn new(cap: usize) -> Self {
        Self::with_byte_budget(cap, 64 << 20)
    }

    pub fn with_byte_budget(cap: usize, byte_cap: usize) -> Self {
        Self {
            cap,
            byte_cap,
            bytes: std::sync::atomic::AtomicUsize::new(0),
            entries: RwLock::new(VecDeque::new()),
            adjacency: DashMap::new(),
        }
    }

    /// Apply a tail event. O(1) amortized.
    pub fn apply(&self, lsn: Lsn, episode: Episode) {
        self.apply_shared(lsn, Arc::new(episode));
    }

    /// Como [`Memtable::apply`], guardando o `Arc` recebido tal como está —
    /// sem cópia profunda. É o que o engine usa com o episódio devolvido por
    /// `append_shared`, que é o mesmo que o broadcast do log entrega.
    pub fn apply_shared(&self, lsn: Lsn, episode: Arc<Episode>) {
        // Audit #12: hold the write lock for the whole publication so the
        // adjacency overlay never exposes an edge to a half-published event.
        let mut entries = self.entries.write().unwrap();
        self.bytes.fetch_add(
            episode.resident_bytes(),
            std::sync::atomic::Ordering::Relaxed,
        );
        for parent in &episode.parents {
            self.adjacency.entry(*parent).or_default().push(episode.id);
        }
        entries.push_back((lsn, episode));
        // INVARIANTE (auditoria 2026-07): a evicção por contagem só é segura
        // porque o engine aplica as views SINCRONAMENTE no mesmo
        // `index_applied` — tudo o que sai daqui já está indexado. Se as views
        // voltarem a ser assíncronas (o desenho original do §3.4), esta
        // evicção TEM de passar a respeitar o watermark (só evictar ≤ wm),
        // senão perde-se read-your-own-writes.
        while entries.len() > self.cap || self.resident_bytes() > self.byte_cap {
            if let Some((_, evicted)) = entries.pop_front() {
                self.subtract_bytes(evicted.resident_bytes());
                self.forget_adjacency(&evicted);
            } else {
                self.bytes.store(0, std::sync::atomic::Ordering::Relaxed);
                break;
            }
        }
    }

    /// Drop everything at or below the view watermark (it is now indexed).
    pub fn prune_below(&self, watermark: Lsn) {
        let mut entries = self.entries.write().unwrap();
        // Concurrent publishers may arrive out of LSN order. A high-LSN
        // front must not keep already indexed entries and adjacency alive.
        entries.retain(|(lsn, episode)| {
            if *lsn > watermark {
                return true;
            }
            self.subtract_bytes(episode.resident_bytes());
            self.forget_adjacency(episode);
            false
        });
        if entries.is_empty() {
            self.bytes.store(0, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn subtract_bytes(&self, amount: usize) {
        let _ = self.bytes.fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |curr| Some(curr.saturating_sub(amount)),
        );
    }

    /// Audit #12: evicted episodes must take their adjacency rows with them,
    /// or the overlay grows without bound (resident-memory leak).
    fn forget_adjacency(&self, evicted: &Episode) {
        for parent in &evicted.parents {
            if let Some(mut children) = self.adjacency.get_mut(parent) {
                children.retain(|c| *c != evicted.id);
                if children.is_empty() {
                    drop(children);
                    self.adjacency.remove(parent);
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    pub fn resident_bytes(&self) -> usize {
        self.bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove toda a cauda materializada. Usado por operações de privacidade
    /// antes de reconstruir as views a partir do log já crypto-shredded.
    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.clear();
        self.adjacency.clear();
        self.bytes.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Exact brute-force KNN over the tail (≤ cap points — fine, §3.4).
    pub fn knn(&self, metric: &ProductMetric, query: &ProductPoint, k: usize) -> Vec<ScoredHit> {
        let entries = self.entries.read().unwrap();
        let mut hits: Vec<ScoredHit> = entries
            .iter()
            .filter_map(|(lsn, e)| {
                let emb = e.embedding.as_ref()?;
                Some(ScoredHit {
                    id: e.id,
                    lsn: *lsn,
                    score: metric.dist(query, emb) as f32,
                })
            })
            .collect();
        hits.sort_by(|a, b| a.score.total_cmp(&b.score));
        hits.truncate(k);
        hits
    }

    /// Naive term-frequency text scan over the tail (merged with the BM25
    /// view at query time).
    pub fn text_search(&self, query: &str, k: usize) -> Vec<ScoredHit> {
        let terms: Vec<String> = tokenize(query);
        let entries = self.entries.read().unwrap();
        let mut hits: Vec<ScoredHit> = entries
            .iter()
            .filter_map(|(lsn, e)| {
                let text = String::from_utf8_lossy(&e.content).to_lowercase();
                let tf: usize = terms.iter().map(|t| text.matches(t.as_str()).count()).sum();
                (tf > 0).then_some(ScoredHit {
                    id: e.id,
                    lsn: *lsn,
                    score: tf as f32,
                })
            })
            .collect();
        hits.sort_by(|a, b| b.score.total_cmp(&a.score));
        hits.truncate(k);
        hits
    }

    pub fn children_of(&self, id: &EventId) -> Vec<EventId> {
        self.adjacency
            .get(id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    pub fn get(&self, id: &EventId) -> Option<(Lsn, Episode)> {
        self.get_shared(id)
            .map(|(lsn, episode)| (lsn, Arc::unwrap_or_clone(episode)))
    }

    /// Como [`Memtable::get`], sem copiar o episódio: devolve o `Arc` que a
    /// memtable guarda.
    pub fn get_shared(&self, id: &EventId) -> Option<(Lsn, Arc<Episode>)> {
        self.entries
            .read()
            .unwrap()
            .iter()
            .rev()
            .find(|(_, e)| e.id == *id)
            .map(|(lsn, episode)| (*lsn, Arc::clone(episode)))
    }
}

pub fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() > 1)
        .map(|t| t.to_string())
        .collect()
}

/// Merge memtable and view results with LSN-based dedup: for the same id,
/// the entry with the highest LSN wins (freshest truth).
pub fn merge_hits(
    mem: Vec<ScoredHit>,
    view: Vec<ScoredHit>,
    k: usize,
    ascending: bool,
) -> Vec<ScoredHit> {
    let mut best: std::collections::HashMap<EventId, ScoredHit> = std::collections::HashMap::new();
    for hit in view.into_iter().chain(mem) {
        match best.get(&hit.id) {
            Some(prev) if prev.lsn >= hit.lsn => {}
            _ => {
                best.insert(hit.id, hit);
            }
        }
    }
    let mut out: Vec<ScoredHit> = best.into_values().collect();
    // Desempate por LSN (único por hit após o dedup): `best` é um HashMap e a
    // ordem de iteração é aleatória — empates de score cortados pelo truncate
    // variavam entre execuções.
    if ascending {
        out.sort_by(|a, b| a.score.total_cmp(&b.score).then_with(|| a.lsn.cmp(&b.lsn)));
    } else {
        out.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.lsn.cmp(&b.lsn)));
    }
    out.truncate(k);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::EventKind;

    pub(super) fn ep_with_emb(content: &str, hyp: Vec<f32>) -> Episode {
        let mut e = Episode::new("a", EventKind::Observation, content.into());
        e.embedding = Some(ProductPoint {
            hyp,
            sph: vec![],
            euc: vec![],
        });
        e
    }

    #[test]
    fn read_your_own_writes_within_1ms() {
        // M2 acceptance gate: write -> query immediately -> visible.
        let mt = Memtable::new(1000);
        let metric = ProductMetric::default();
        let e = ep_with_emb("the river flows", vec![0.3, 0.1]);
        let id = e.id;
        let t0 = std::time::Instant::now();
        mt.apply(0, e);
        let hits = mt.knn(
            &metric,
            &ProductPoint {
                hyp: vec![0.3, 0.1],
                sph: vec![],
                euc: vec![],
            },
            1,
        );
        assert_eq!(hits[0].id, id);
        let text_hits = mt.text_search("river", 1);
        assert_eq!(text_hits[0].id, id);
        assert!(t0.elapsed().as_millis() < 10, "took {:?}", t0.elapsed());
    }

    #[test]
    fn prune_below_watermark() {
        let mt = Memtable::new(1000);
        for i in 0..10 {
            mt.apply(i, ep_with_emb(&format!("e{i}"), vec![0.1]));
        }
        mt.prune_below(4);
        assert_eq!(mt.len(), 5);
    }

    #[test]
    fn prune_handles_out_of_order_lsn_and_releases_adjacency() {
        let mt = Memtable::new(100);
        let parent = EventId::new();
        for lsn in [9, 1, 7, 2] {
            let mut ep = ep_with_emb("out-of-order", vec![0.1]);
            ep.parents.push(parent);
            mt.apply(lsn, ep);
        }
        mt.prune_below(2);
        assert_eq!(mt.len(), 2);
        assert_eq!(mt.children_of(&parent).len(), 2);
        mt.prune_below(9);
        assert_eq!(mt.len(), 0);
        assert_eq!(mt.resident_bytes(), 0);
        assert!(mt.children_of(&parent).is_empty());
    }

    #[test]
    fn merge_dedups_by_highest_lsn() {
        let id = EventId::new();
        let mem = vec![ScoredHit {
            id,
            lsn: 9,
            score: 0.5,
        }];
        let view = vec![ScoredHit {
            id,
            lsn: 3,
            score: 0.7,
        }];
        let out = merge_hits(mem, view, 10, true);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].lsn, 9);
    }
}

#[cfg(test)]
mod byte_budget_regression {
    use super::*;
    #[test]
    fn bytes_and_adjacency_are_released_by_eviction_prune_and_clear() {
        let mem = Memtable::with_byte_budget(100, 2048);
        let parent = EventId::new();
        for lsn in 0..20 {
            let mut e = Episode::new(
                "agent",
                heraclitus_core::EventKind::Observation,
                vec![0; 512],
            );
            e.parents.push(parent);
            mem.apply(lsn, e);
            assert!(mem.resident_bytes() <= 2048);
            assert_eq!(mem.children_of(&parent).len(), mem.len());
        }
        mem.prune_below(20);
        assert_eq!(mem.resident_bytes(), 0);
        assert!(mem.children_of(&parent).is_empty());
        mem.apply(
            21,
            Episode::new(
                "agent",
                heraclitus_core::EventKind::Observation,
                vec![0; 16],
            ),
        );
        mem.clear();
        assert_eq!(mem.resident_bytes(), 0);
    }

    #[test]
    fn eviction_breaks_safely_when_entries_empty_and_bytes_saturate() {
        let mem = Memtable::with_byte_budget(10, 100);
        for lsn in 0..5 {
            mem.apply(
                lsn,
                Episode::new(
                    "agent",
                    heraclitus_core::EventKind::Observation,
                    vec![0; 200],
                ),
            );
        }
        assert!(mem.len() <= 1);
        mem.clear();
        assert_eq!(mem.resident_bytes(), 0);
        assert_eq!(mem.len(), 0);
    }

    #[test]
    fn apply_shared_guarda_o_mesmo_arc_e_larga_o_na_eviccao() {
        let mem = Memtable::new(1);
        let partilhado = Arc::new(super::tests::ep_with_emb("partilhado", vec![0.1, 0.2]));
        let bytes = partilhado.resident_bytes();
        mem.apply_shared(3, Arc::clone(&partilhado));

        // A memtable segura a MESMA alocação, não uma cópia.
        assert_eq!(Arc::strong_count(&partilhado), 2);
        let (lsn, guardado) = mem.get_shared(&partilhado.id).unwrap();
        assert_eq!(lsn, 3);
        assert!(Arc::ptr_eq(&guardado, &partilhado));
        drop(guardado);
        assert_eq!(mem.resident_bytes(), bytes);
        // `get` continua a devolver um episódio por valor, igual ao guardado.
        let (_, copia) = mem.get(&partilhado.id).unwrap();
        assert_eq!(copia.content, partilhado.content);
        assert_eq!(Arc::strong_count(&partilhado), 2);

        // A evicção por contagem larga a referência da memtable.
        mem.apply(4, super::tests::ep_with_emb("seguinte", vec![0.3, 0.4]));
        assert_eq!(mem.len(), 1);
        assert!(mem.get_shared(&partilhado.id).is_none());
        assert_eq!(Arc::strong_count(&partilhado), 1);
    }
}
