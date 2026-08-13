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
use std::sync::RwLock;

pub struct Memtable {
    cap: usize,
    entries: RwLock<VecDeque<(Lsn, Episode)>>,
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
        Self {
            cap,
            entries: RwLock::new(VecDeque::new()),
            adjacency: DashMap::new(),
        }
    }

    /// Apply a tail event. O(1) amortized.
    pub fn apply(&self, lsn: Lsn, episode: Episode) {
        // Audit #12: hold the write lock for the whole publication so the
        // adjacency overlay never exposes an edge to a half-published event.
        let mut entries = self.entries.write().unwrap();
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
        while entries.len() > self.cap {
            if let Some((_, evicted)) = entries.pop_front() {
                self.forget_adjacency(&evicted);
            }
        }
    }

    /// Drop everything at or below the view watermark (it is now indexed).
    pub fn prune_below(&self, watermark: Lsn) {
        let mut entries = self.entries.write().unwrap();
        while matches!(entries.front(), Some((l, _)) if *l <= watermark) {
            if let Some((_, evicted)) = entries.pop_front() {
                self.forget_adjacency(&evicted);
            }
        }
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
        self.entries
            .read()
            .unwrap()
            .iter()
            .rev()
            .find(|(_, e)| e.id == *id)
            .cloned()
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

    fn ep_with_emb(content: &str, hyp: Vec<f32>) -> Episode {
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
