//! heraclitus-index-vector — in-crate HNSW (§3.6).
//!
//! We deliberately do NOT depend on an external HNSW crate: the metric is a
//! custom product-manifold distance and we need RoaringBitmap filter
//! push-down. The index is derived state: losing it means replay, not data
//! loss.

pub mod gate;

use heraclitus_core::{Episode, EventId, HeraclitusError, Lsn, ProductPoint};
use heraclitus_manifold::{ProductMetric, Signature};
use heraclitus_views::View;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::path::Path;

const DEFAULT_M: usize = 16;
const DEFAULT_EF_CONSTRUCTION: usize = 200;

#[derive(Clone, Serialize, Deserialize)]
struct Node {
    point: ProductPoint,
    level: usize,
    /// neighbors[level] = ids
    neighbors: Vec<Vec<u32>>,
}

/// Min-ordering helper for the search heaps.
#[derive(PartialEq)]
struct Candidate {
    dist: f64,
    id: u32,
}
impl Eq for Candidate {}
impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.dist.total_cmp(&self.dist) // reversed: BinaryHeap becomes min-heap
    }
}
impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub struct VectorIndex {
    metric: ProductMetric,
    m: usize,
    ef_construction: usize,
    nodes: Vec<Node>,
    entry: Option<u32>,
    by_event: HashMap<EventId, u32>,
    ids: Vec<EventId>,
    lsns: Vec<Lsn>,
    watermark: Lsn,
    rng: StdRng,
    /// Tombstones semânticos (padrão Qdrant): ids internos "retirados" ficam
    /// FORA dos resultados sem reconstruir o grafo — o nó continua traversável
    /// para preservar a conectividade do HNSW. Nada é apagado do log: um
    /// tombstone é ele próprio um evento (`attrs.tombstone_of = <event_id>`).
    tombstones: RoaringBitmap,
}

#[derive(Debug, Clone)]
pub struct VectorHit {
    pub id: EventId,
    pub lsn: Lsn,
    pub dist: f32,
}

/// Estado serializável do índice (#12 — checkpoint/restore para boot rápido).
/// `by_event` reconstrói-se de `ids`; `rng` fica no seed determinístico (só
/// afeta os níveis de inserções FUTURAS, não o estado restaurado).
#[derive(Serialize, Deserialize)]
struct VectorSnapshot {
    m: usize,
    ef_construction: usize,
    nodes: Vec<Node>,
    entry: Option<u32>,
    ids: Vec<EventId>,
    lsns: Vec<Lsn>,
    watermark: Lsn,
    sig: Signature,
    tombstones: Vec<u32>,
}

const VECTOR_CKPT_FILE: &str = "vector.ckpt";

impl VectorIndex {
    pub fn new(metric: ProductMetric) -> Self {
        Self {
            metric,
            m: DEFAULT_M,
            ef_construction: DEFAULT_EF_CONSTRUCTION,
            nodes: Vec::new(),
            entry: None,
            by_event: HashMap::new(),
            ids: Vec::new(),
            lsns: Vec::new(),
            watermark: 0,
            // Determinism requirement (§3.5): RNG seeded from a constant; the
            // level sequence is then a pure function of insertion order.
            rng: StdRng::seed_from_u64(0x48524B4C),
            tombstones: RoaringBitmap::new(),
        }
    }

    /// Marca o vetor de `event` como retirado (tombstone semântico). Devolve
    /// `true` se o evento estava indexado. Idempotente.
    pub fn tombstone_event(&mut self, event: &EventId) -> bool {
        match self.by_event.get(event) {
            Some(&id) => {
                self.tombstones.insert(id);
                true
            }
            None => false,
        }
    }

    pub fn is_tombstoned(&self, internal: u32) -> bool {
        self.tombstones.contains(internal)
    }

    /// Nº de vetores retirados — alimenta o trigger de compaction (delta ratio).
    pub fn tombstone_count(&self) -> u64 {
        self.tombstones.len()
    }

    fn dist(&self, a: u32, b: &ProductPoint) -> f64 {
        self.metric.dist(&self.nodes[a as usize].point, b)
    }

    fn random_level(&mut self) -> usize {
        let ml = 1.0 / (self.m as f64).ln();
        let r: f64 = self.rng.gen_range(f64::MIN_POSITIVE..1.0);
        ((-r.ln()) * ml).floor() as usize
    }

    /// Greedy search at one level, returning up to `ef` nearest candidates.
    ///
    /// Filter push-down (audit02 #3): traversal explores the whole reachable
    /// graph for connectivity, but only `filter`-passing nodes are admitted to
    /// `results`. So a selective filter keeps expanding until it has `ef`
    /// filtered hits (or the reachable set is exhausted) instead of returning
    /// fewer than `k` after a post-hoc filter. `filter = None` is identical to
    /// the unfiltered behavior.
    fn search_layer(
        &self,
        query: &ProductPoint,
        entry: u32,
        level: usize,
        ef: usize,
        filter: Option<&RoaringBitmap>,
    ) -> Vec<Candidate> {
        // Tombstones nunca entram nos RESULTADOS mas continuam a ser
        // atravessados (visited/candidates) — remover nós do grafo partiria a
        // conectividade; excluí-los só da seleção preserva o recall.
        let passes = |id: u32| {
            !self.tombstones.contains(id) && filter.map(|f| f.contains(id)).unwrap_or(true)
        };
        let mut visited: HashSet<u32> = HashSet::from([entry]);
        let d0 = self.dist(entry, query);
        // `candidates` drives traversal over every reachable node; `results`
        // keeps only filter-passing nodes (the ones we may return).
        let mut candidates = BinaryHeap::from([Candidate {
            dist: d0,
            id: entry,
        }]);
        // `results` como MAX-heap (via Reverse): o pior (maior dist) é o topo, então
        // consultar/descartar o pior é O(1)/O(log ef) em vez do fold O(ef) por
        // vizinho visitado. Semântica de seleção idêntica à versão em Vec.
        let mut results: BinaryHeap<Reverse<Candidate>> = BinaryHeap::new();
        if passes(entry) {
            results.push(Reverse(Candidate {
                dist: d0,
                id: entry,
            }));
        }

        while let Some(c) = candidates.pop() {
            let worst = results.peek().map(|r| r.0.dist).unwrap_or(f64::MIN);
            // Stop only once we have ef filtered hits AND cannot improve them.
            if results.len() >= ef && c.dist > worst {
                break;
            }
            for &n in &self.nodes[c.id as usize].neighbors
                [level.min(self.nodes[c.id as usize].neighbors.len() - 1)]
            {
                if visited.insert(n) {
                    let d = self.dist(n, query);
                    let worst = results.peek().map(|r| r.0.dist).unwrap_or(f64::MIN);
                    // Keep exploring while we still need filtered hits, or while
                    // n could improve the current frontier.
                    if results.len() < ef || d < worst {
                        candidates.push(Candidate { dist: d, id: n });
                        if passes(n) {
                            results.push(Reverse(Candidate { dist: d, id: n }));
                            if results.len() > ef {
                                results.pop(); // drop the worst (largest dist) filtered result
                            }
                        }
                    }
                }
            }
        }
        let mut out: Vec<Candidate> = results.into_iter().map(|r| r.0).collect();
        out.sort_by(|a, b| a.dist.total_cmp(&b.dist));
        out
    }

    pub fn insert(&mut self, event_id: EventId, lsn: Lsn, point: ProductPoint) {
        if self.by_event.contains_key(&event_id) {
            return; // idempotent replay
        }
        let id = self.nodes.len() as u32;
        let level = self.random_level();
        // The node is inserted (with empty adjacency) BEFORE any back-links
        // are created: a search during connection may already traverse it.
        self.nodes.push(Node {
            point: point.clone(),
            level,
            neighbors: vec![Vec::new(); level + 1],
        });
        self.by_event.insert(event_id, id);
        self.ids.push(event_id);
        self.lsns.push(lsn);

        let old_entry = self.entry;
        if let Some(mut ep) = old_entry {
            let top = self.nodes[ep as usize].level;
            // descend greedily above the new node's level
            for l in ((level + 1)..=top).rev() {
                let best =
                    self.search_layer(&point, ep, l.min(self.nodes[ep as usize].level), 1, None);
                // Com tombstones, a camada pode não devolver candidatos
                // elegíveis: mantém o entry-point atual em vez de indexar [0].
                if let Some(b) = best.first() {
                    ep = b.id;
                }
            }
            // connect at each level from min(level, top) down to 0
            for l in (0..=level.min(top)).rev() {
                let neighbors = self.search_layer(&point, ep, l, self.ef_construction, None);
                let selected: Vec<u32> = neighbors
                    .iter()
                    .filter(|c| c.id != id)
                    .take(self.m)
                    .map(|c| c.id)
                    .collect::<Vec<u32>>();
                for &n in &selected {
                    let nl = self.nodes[n as usize].neighbors.len();
                    if l < nl {
                        self.nodes[n as usize].neighbors[l].push(id);
                        if self.nodes[n as usize].neighbors[l].len() > self.m * 2 {
                            // prune: keep the m*2 closest
                            let np = self.nodes[n as usize].point.clone();
                            let mut nb = std::mem::take(&mut self.nodes[n as usize].neighbors[l]);
                            nb.sort_by(|&a, &b| self.dist(a, &np).total_cmp(&self.dist(b, &np)));
                            nb.truncate(self.m * 2);
                            self.nodes[n as usize].neighbors[l] = nb;
                        }
                    }
                }
                self.nodes[id as usize].neighbors[l] = selected;
                if let Some(n0) = neighbors.first() {
                    ep = n0.id;
                }
            }
            if level > top {
                self.entry = Some(id);
            }
        } else {
            self.entry = Some(id);
        }
    }

    /// Search top-k. `filter`: only internal ids present in the bitmap are
    /// returned (push-down happens during result selection). Results carry
    /// the LSN they are valid at.
    pub fn search(
        &self,
        query: &ProductPoint,
        k: usize,
        ef: usize,
        filter: Option<&RoaringBitmap>,
    ) -> Vec<VectorHit> {
        let Some(mut ep) = self.entry else {
            return Vec::new();
        };
        let top = self.nodes[ep as usize].level;
        // Entry-point descent ignores the filter (we want the best entry into
        // level 0 regardless); the filter is pushed down only at level 0.
        for l in (1..=top).rev() {
            let best = self.search_layer(query, ep, l, 1, None);
            if let Some(b) = best.first() {
                ep = b.id;
            }
        }
        let ef = ef.max(k);
        let candidates =
            self.search_layer(query, ep, 0, ef.max(self.ef_construction.min(64)), filter);
        candidates
            .into_iter()
            .take(k)
            .map(|c| VectorHit {
                id: self.ids[c.id as usize],
                lsn: self.lsns[c.id as usize],
                dist: c.dist as f32,
            })
            .collect()
    }

    /// Exact Top-k by brute-force over ALL points, accelerated by the GPU when
    /// available (M20.3.1b2). The GPU computes the batch product-manifold
    /// distance (RECALL, ≥30× oversample) via `heraclitus_gpu::topm_product`; the
    /// CPU then rescores the candidates with the exact f64 [`ProductMetric`] and
    /// has the final say — so the result is the true nearest set regardless of
    /// GPU float precision. Without a GPU it falls back to a CPU brute-force.
    /// The approximate HNSW [`search`](Self::search) is never affected.
    pub fn search_exact_gpu(&self, query: &ProductPoint, k: usize) -> Vec<VectorHit> {
        if self.nodes.is_empty() || k == 0 {
            return Vec::new();
        }
        let (a, b, c) = (query.hyp.len(), query.sph.len(), query.euc.len());
        let dim = a + b + c;

        let mut qflat = Vec::with_capacity(dim);
        qflat.extend_from_slice(&query.hyp);
        qflat.extend_from_slice(&query.sph);
        qflat.extend_from_slice(&query.euc);

        let mut vflat = Vec::with_capacity(self.nodes.len() * dim);
        for node in &self.nodes {
            if node.point.hyp.len() != a || node.point.sph.len() != b || node.point.euc.len() != c {
                // Heterogeneous point layout — stay exact via the CPU metric.
                return self.rescore(query, 0..self.nodes.len(), k);
            }
            vflat.extend_from_slice(&node.point.hyp);
            vflat.extend_from_slice(&node.point.sph);
            vflat.extend_from_slice(&node.point.euc);
        }

        let sig = heraclitus_gpu::ProductSig {
            a,
            b,
            c,
            c1: (-self.metric.sig.k1) as f32,
            k2: self.metric.sig.k2 as f32,
            weights: [
                self.metric.sig.weights[0] as f32,
                self.metric.sig.weights[1] as f32,
                self.metric.sig.weights[2] as f32,
            ],
            ball_eps: heraclitus_manifold::BALL_EPS as f32,
        };

        // GPU RECALL with ≥30× oversample, then exact f64 CPU rescore (final say).
        let m = k.saturating_mul(30).min(self.nodes.len());
        let cands = heraclitus_gpu::topm_product(&qflat, &vflat, &sig, m, 1e6);
        self.rescore(query, cands.iter().map(|c| c.index as usize), k)
    }

    /// Rescore candidate internal ids with the exact f64 metric, take Top-k.
    /// Tombstones ficam fora do rescore (mesma semântica do search HNSW).
    fn rescore(
        &self,
        query: &ProductPoint,
        cand: impl Iterator<Item = usize>,
        k: usize,
    ) -> Vec<VectorHit> {
        let mut scored: Vec<(f64, usize)> = cand
            .filter(|i| !self.tombstones.contains(*i as u32))
            .map(|i| (self.metric.dist(query, &self.nodes[i].point), i))
            .collect();
        scored.sort_by(|x, y| x.0.total_cmp(&y.0));
        scored.truncate(k);
        scored
            .into_iter()
            .map(|(d, i)| VectorHit {
                id: self.ids[i],
                lsn: self.lsns[i],
                dist: d as f32,
            })
            .collect()
    }

    /// Internal id for an event (to build filter bitmaps).
    pub fn internal_id(&self, event: &EventId) -> Option<u32> {
        self.by_event.get(event).copied()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// #12 — Persiste o estado completo do HNSW (`<dir>/vector.ckpt`) com escrita
    /// atómica (tmp + rename). Correção nunca depende disto: sem checkpoint, a
    /// view reconstrói-se do LSN 0 (ver `heraclitus_views`).
    pub fn save_checkpoint(&self, dir: &Path) -> Result<(), HeraclitusError> {
        let snap = VectorSnapshot {
            m: self.m,
            ef_construction: self.ef_construction,
            nodes: self.nodes.clone(),
            entry: self.entry,
            ids: self.ids.clone(),
            lsns: self.lsns.clone(),
            watermark: self.watermark,
            sig: self.metric.sig.clone(),
            tombstones: self.tombstones.iter().collect(),
        };
        let bytes = bincode::serde::encode_to_vec(&snap, bincode::config::standard())
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        let tmp = dir.join("vector.ckpt.tmp");
        // fsync ANTES do rename (alinhado com views::ckpt::save): sem ele, um
        // crash pós-rename podia deixar um ficheiro vazio/parcial — degradava
        // com segurança para rebuild, mas custava o boot inteiro.
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, dir.join(VECTOR_CKPT_FILE))?;
        Ok(())
    }

    /// #12 — Restaura o HNSW do checkpoint. Devolve `false` se não houver
    /// ficheiro OU se ele não descodificar (formato antigo/corrompido) — a
    /// view fica vazia e o registry força replay desde 0. Um checkpoint
    /// ilegível NUNCA pode impedir o boot: o estado é derivado, o log é a verdade.
    pub fn load_checkpoint(&mut self, dir: &Path) -> Result<bool, HeraclitusError> {
        let bytes = match std::fs::read(dir.join(VECTOR_CKPT_FILE)) {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };
        let Ok((snap, _)) = bincode::serde::decode_from_slice::<VectorSnapshot, _>(
            &bytes,
            bincode::config::standard(),
        ) else {
            return Ok(false);
        };
        // Invariante estrutural do HNSW: todo nó tem `level + 1` camadas de
        // vizinhos (nunca vazio — `search_layer` indexa `neighbors[..len()-1]`
        // e um vec vazio dava underflow/panic em TODA pesquisa futura). Um
        // checkpoint decodável mas violado degrada para rebuild do log (I6),
        // nunca para um índice que panica.
        let coherent = snap.nodes.len() == snap.ids.len()
            && snap.nodes.len() == snap.lsns.len()
            && snap
                .nodes
                .iter()
                .all(|n| n.neighbors.len() == n.level + 1 && !n.neighbors.is_empty())
            && snap
                .entry
                .map(|e| (e as usize) < snap.nodes.len())
                .unwrap_or(true);
        if !coherent {
            return Ok(false);
        }
        self.by_event = snap
            .ids
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i as u32))
            .collect();
        self.m = snap.m;
        self.ef_construction = snap.ef_construction;
        self.nodes = snap.nodes;
        self.entry = snap.entry;
        self.ids = snap.ids;
        self.lsns = snap.lsns;
        self.watermark = snap.watermark;
        self.metric = ProductMetric { sig: snap.sig };
        self.tombstones = snap.tombstones.into_iter().collect();
        Ok(true)
    }
}

impl View for VectorIndex {
    fn name(&self) -> &str {
        "vector"
    }

    fn apply(&mut self, lsn: Lsn, event: &Episode) {
        if let Some(emb) = &event.embedding {
            self.insert(event.id, lsn, emb.clone());
        }
        // Tombstone semântico como EVENTO (nada se apaga do log): um episódio
        // com `attrs.tombstone_of = <event_id>` retira o vetor alvo dos
        // resultados. Replay-determinístico como qualquer outra derivação.
        if let Some(target) = event.attrs.get("tombstone_of") {
            if let Ok(id) = target.parse::<EventId>() {
                self.tombstone_event(&id);
            }
        }
        // Avanço-só (ver activation/text/attr): entrega fora de ordem não pode
        // regredir o watermark persistido no checkpoint.
        self.watermark = self.watermark.max(lsn);
    }

    fn watermark(&self) -> Lsn {
        self.watermark
    }

    fn checkpoint(&self, dir: &Path) -> Result<(), HeraclitusError> {
        self.save_checkpoint(dir)
    }

    fn restore(&mut self, dir: &Path) -> Result<bool, HeraclitusError> {
        self.load_checkpoint(dir)
    }

    fn reset(&mut self) {
        *self = VectorIndex::new(self.metric.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(hyp: Vec<f32>) -> ProductPoint {
        ProductPoint {
            hyp,
            sph: vec![],
            euc: vec![],
        }
    }

    #[test]
    fn finds_nearest_in_small_set() {
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut ids = Vec::new();
        for i in 0..200 {
            let x = (i as f32) / 250.0;
            let id = EventId::new();
            ids.push(id);
            idx.insert(id, i as u64, pt(vec![x, 0.1]));
        }
        let hits = idx.search(&pt(vec![0.4, 0.1]), 5, 64, None);
        assert_eq!(hits.len(), 5);
        // exact nearest is i=100 (x=0.4)
        assert_eq!(hits[0].id, ids[100]);
    }

    #[test]
    fn filter_push_down() {
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut keep = RoaringBitmap::new();
        let mut kept_ids = Vec::new();
        for i in 0..100 {
            let id = EventId::new();
            idx.insert(id, i as u64, pt(vec![(i as f32) / 200.0, 0.0]));
            if i % 2 == 0 {
                keep.insert(idx.internal_id(&id).unwrap());
                kept_ids.push(id);
            }
        }
        let hits = idx.search(&pt(vec![0.25, 0.0]), 10, 128, Some(&keep));
        assert!(!hits.is_empty());
        for h in &hits {
            assert!(kept_ids.contains(&h.id), "filtered-out id leaked");
        }
    }

    #[test]
    fn filter_push_down_recall_under_high_selectivity() {
        // Regression (auditoria02 #3): with a highly selective filter (5% kept),
        // post-filtering an ef≈64 pool around the query returns fewer than k.
        // Push-down must keep expanding until it has k filtered hits.
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut keep = RoaringBitmap::new();
        let mut kept = Vec::new();
        for i in 0..500u64 {
            let id = EventId(ulid::Ulid::from_parts(i, i as u128));
            idx.insert(id, i, pt(vec![(i as f32) / 600.0, 0.02]));
            if i % 20 == 0 {
                keep.insert(idx.internal_id(&id).unwrap());
                kept.push(id);
            }
        }
        let hits = idx.search(&pt(vec![300.0 / 600.0, 0.02]), 5, 64, Some(&keep));
        assert_eq!(
            hits.len(),
            5,
            "push-down must return k even under a 5% filter"
        );
        for h in &hits {
            assert!(kept.contains(&h.id), "filtered-out id leaked");
        }
    }

    #[test]
    fn deterministic_replay() {
        let build = || {
            let mut idx = VectorIndex::new(ProductMetric::default());
            for i in 0..100u64 {
                let id = EventId(ulid::Ulid::from_parts(i, i as u128));
                idx.insert(id, i, pt(vec![(i as f32) / 150.0, 0.05]));
            }
            let hits = idx.search(&pt(vec![0.3, 0.05]), 10, 64, None);
            hits.iter().map(|h| h.id).collect::<Vec<_>>()
        };
        assert_eq!(build(), build(), "same input order must give same index");
    }

    /// M20.3.1b2 GATE: GPU-accelerated exact search must equal the f64
    /// brute-force ground truth over the *full* product metric (hyp+sph+euc).
    /// With `--features gpu` on real hardware this validates the wired GPU RECALL
    /// followed by CPU rescore; without it, the CPU fallback. Either way the HNSW
    /// `search()` is untouched.
    #[test]
    fn search_exact_gpu_matches_bruteforce() {
        let metric = ProductMetric::default();
        let mut idx = VectorIndex::new(metric.clone());
        // Well-separated product points: hyp, sph and euc all move with i.
        let mk = |i: usize| -> ProductPoint {
            let fi = i as f32;
            ProductPoint {
                hyp: vec![fi * 0.004, fi * 0.003],
                sph: vec![(fi * 0.02).cos(), (fi * 0.02).sin()],
                euc: vec![fi * 0.2, fi * 0.1],
            }
        };
        let mut ids = Vec::new();
        for i in 0..120usize {
            let id = EventId(ulid::Ulid::from_parts(i as u64, i as u128));
            ids.push(id);
            idx.insert(id, i as u64, mk(i));
        }
        let query = mk(0);
        let k = 8;

        // Ground truth: exact f64 brute-force with the REAL ProductMetric.
        let mut gt: Vec<(f64, usize)> =
            (0..120).map(|i| (metric.dist(&query, &mk(i)), i)).collect();
        gt.sort_by(|a, b| a.0.total_cmp(&b.0));
        let gt_ids: Vec<EventId> = gt.iter().take(k).map(|(_, i)| ids[*i]).collect();

        let got: Vec<EventId> = idx
            .search_exact_gpu(&query, k)
            .iter()
            .map(|h| h.id)
            .collect();
        assert_eq!(
            got, gt_ids,
            "GPU-accelerated exact search must equal f64 brute-force"
        );
    }

    #[test]
    fn tombstones_hide_from_results_but_preserve_graph() {
        // C2.1 (padrão Qdrant): o vetor retirado sai dos RESULTADOS sem
        // remontar o índice; a travessia continua a passar por ele.
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut ids = Vec::new();
        for i in 0..50 {
            let e = EventId::new();
            ids.push(e);
            idx.insert(e, i as u64, pt(vec![i as f32 / 50.0]));
        }
        let q = pt(vec![0.5]);

        // Antes: o mais próximo de 0.5 é o vetor 25.
        let hits = idx.search(&q, 3, 32, None);
        assert_eq!(hits[0].id, ids[25]);

        // Tombstone no 25: sai dos resultados; o 24/26 assumem o topo.
        assert!(idx.tombstone_event(&ids[25]));
        assert_eq!(idx.tombstone_count(), 1);
        let hits = idx.search(&q, 3, 32, None);
        assert!(hits.iter().all(|h| h.id != ids[25]), "retirado não aparece");
        assert!(hits[0].id == ids[24] || hits[0].id == ids[26]);

        // O rescore exato (GPU/brute-force) respeita o tombstone.
        let exact = idx.search_exact_gpu(&q, 3);
        assert!(exact.iter().all(|h| h.id != ids[25]));

        // Inserções novas continuam a funcionar com tombstones presentes.
        let novo = EventId::new();
        idx.insert(novo, 50, pt(vec![0.501]));
        let hits = idx.search(&q, 1, 32, None);
        assert_eq!(hits[0].id, novo);

        // Round-trip de checkpoint preserva os tombstones.
        let dir = tempfile::tempdir().unwrap();
        idx.save_checkpoint(dir.path()).unwrap();
        let mut re = VectorIndex::new(ProductMetric::default());
        assert!(re.load_checkpoint(dir.path()).unwrap());
        assert_eq!(re.tombstone_count(), 1);
        let hits = re.search(&q, 3, 32, None);
        assert!(hits.iter().all(|h| h.id != ids[25]));
    }

    #[test]
    fn unreadable_checkpoint_degrades_to_rebuild() {
        // Um snapshot de formato antigo/corrompido NUNCA impede o boot: o
        // restore devolve false e o registry replaya desde 0.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("vector.ckpt"), b"formato antigo qualquer").unwrap();
        let mut idx = VectorIndex::new(ProductMetric::default());
        assert!(!idx.load_checkpoint(dir.path()).unwrap());
        assert!(idx.is_empty());
    }

    #[test]
    fn checkpoint_restore_preserves_search() {
        // #12 — o HNSW restaurado do checkpoint deve dar buscas idênticas ao
        // original (boot rápido sem reconstruir do LSN 0).
        let dir = tempfile::tempdir().unwrap();
        let mut idx = VectorIndex::new(ProductMetric::default());
        let mut ids = Vec::new();
        for i in 0..200u64 {
            let id = EventId(ulid::Ulid::from_parts(i, i as u128));
            ids.push(id);
            idx.insert(id, i, pt(vec![(i as f32) / 250.0, 0.1]));
        }
        let query = pt(vec![0.4, 0.1]);
        let before: Vec<EventId> = idx
            .search(&query, 5, 64, None)
            .iter()
            .map(|h| h.id)
            .collect();

        idx.save_checkpoint(dir.path()).unwrap();

        // Nova instância vazia restaura do disco (simula restart).
        let mut restored = VectorIndex::new(ProductMetric::default());
        assert!(
            restored.load_checkpoint(dir.path()).unwrap(),
            "checkpoint deve existir"
        );
        assert_eq!(restored.len(), 200);
        assert_eq!(restored.internal_id(&ids[100]), idx.internal_id(&ids[100]));
        let after: Vec<EventId> = restored
            .search(&query, 5, 64, None)
            .iter()
            .map(|h| h.id)
            .collect();

        assert_eq!(
            before, after,
            "busca no índice restaurado deve ser idêntica"
        );

        // Sem ficheiro → restore devolve false (view fica vazia → replay desde 0).
        let empty_dir = tempfile::tempdir().unwrap();
        let mut fresh = VectorIndex::new(ProductMetric::default());
        assert!(!fresh.load_checkpoint(empty_dir.path()).unwrap());
    }
}
