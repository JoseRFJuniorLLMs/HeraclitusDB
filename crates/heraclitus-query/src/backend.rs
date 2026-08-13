//! The execution boundary. The query crate never owns indexes — it asks a
//! [`QueryBackend`]. The server composes the real backend (HNSW + BM25 +
//! activation + retrieval); [`LogBackend`] is the reference implementation
//! over the raw log: exact, lock-free on reads, and completely idempotent.

use crate::ast::{SimulateOp, Value};
use crate::fusion::{FusedHit, FusionInput, FusionWeights};
use arc_swap::ArcSwap;
use heraclitus_core::{Episode, EventKind, HeraclitusError, Lsn};
use heraclitus_index_graph::adaptive::{self, LabeledFlag, PolicyEval};
use heraclitus_index_graph::decision::{self, DecisionPolicy};
use heraclitus_index_graph::entity::EntityResolver;
use heraclitus_index_graph::temporal::{Edge, EdgeType, EdgeVersion, TemporalGraph};
use heraclitus_log::skip_scan::SkipScanner;
use heraclitus_log::Log;
use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};

// --- Estruturas Públicas de Linha e Resultados de Query (API M8-M17) ---

#[derive(Debug, Clone)]
pub struct NeighborRow {
    pub edge_id: String,
    pub to: String,
    pub etype: String,
    pub belief: f32,
    pub weight: f32,
    pub lsn: Lsn,
}

#[derive(Debug, Clone)]
pub struct EdgeRow {
    pub edge_id: String,
    pub from: String,
    pub to: String,
    pub etype: String,
    pub belief: f32,
    /// Bi-temporal (V2.4): validade do facto no mundo real, herdada do
    /// episódio que assertou a aresta (`None` = aberto/atemporal).
    pub world_valid_from: Option<u64>,
    pub world_valid_to: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct HypothesisRow {
    pub hypothesis_id: String,
    pub confidence: f32,
    pub polarity: f32,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct EdgeHypotheses {
    pub edge_id: String,
    pub alive: bool,
    pub belief: f32,
    pub versions: Vec<HypothesisRow>,
}

#[derive(Debug, Clone)]
pub struct AdaptReport {
    pub rule: String,
    pub samples: usize,
    pub learned_threshold: f32,
    pub default: PolicyEval,
    pub adapted: PolicyEval,
}

#[derive(Debug, Clone)]
pub struct ActionRecord {
    pub action_id: String,
    pub rule: String,
    pub subject: String,
    pub reason: String,
    pub lsn: Lsn,
}

#[derive(Debug, Clone, Default)]
pub struct DecisionReport {
    pub fired: Vec<ActionRecord>,
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CommunityResult {
    pub node: String,
    pub community: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MetricsResult {
    pub node: String,
    pub community: String,
    pub degree: u32,
    pub centrality: f32,
    pub anomaly_score: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CausalStep {
    pub id: String,
    pub depth: usize,
    pub causes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Trace {
    pub target: String,
    pub steps: Vec<CausalStep>,
    pub roots: Vec<String>,
}

pub const QUERY_SCAN_CAP: usize = 250_000;

// =========================================================================
// M29: ENTRADAS UNIFICADAS DE HEAP COM ORDENAÇÃO MÁXIMA/MÍNIMA EXPLICITA
// =========================================================================

#[derive(PartialEq)]
struct MinScoreEntry {
    score: f32,
    lsn: Lsn,
}
impl Eq for MinScoreEntry {}
impl Ord for MinScoreEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .total_cmp(&self.score)
            .then_with(|| other.lsn.cmp(&self.lsn))
    }
}
impl PartialOrd for MinScoreEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// NOTA (fix pós-M30): o "EntityResolver histórico" local que vivia aqui foi
// removido — ele só entendia attrs pré-processados (`resolved_key`/`entity_id`)
// que nenhum produtor emite, por isso RESOLVE/CLUSTER devolviam sempre vazio.
// O bundle usa agora o resolver canónico do index-graph (M11), que processa os
// eventos reais (`entity_key`, `er_op=merge/split`) e é o mesmo que o server
// materializa — uma única semântica de resolução em todo o sistema.

// =========================================================================
// M29: VECTOR SEARCH ENGINE (HNSW SEGURO, HEURÍSTICA DE DIVERSIDADE E GRAU)
// =========================================================================

#[derive(Clone, Default)]
struct HnswIndex {
    pub nodes: HashMap<Lsn, Vec<f32>>,
    // Camadas usam Arc<Vec<Lsn>> para permitir Copy-On-Write ultra-veloz de ponteiros no sync
    pub layers: Vec<HashMap<Lsn, Arc<Vec<Lsn>>>>,
    pub entry_points: Vec<Lsn>,
}

impl HnswIndex {
    fn compute_distance(&self, v1: &[f32], v2: &[f32]) -> f32 {
        let mut d_sq = 0.0f32;
        for i in 0..v1.len().min(v2.len()) {
            d_sq += (v1[i] - v2[i]).powi(2);
        }
        d_sq.sqrt()
    }

    fn pick_random_layer(&self, lsn: Lsn) -> usize {
        let mut seed = lsn.wrapping_mul(0xbf58476d1ce4e5b9);
        seed = (seed ^ (seed >> 30)).wrapping_mul(0x94d049bb133111eb);
        let u = (((seed & 0xFFFFFFFF) as f64) / (u32::MAX as f64)).max(1e-10);
        let m_l = 1.0 / (12.0f64.ln());
        let level = (-u.ln() * m_l).floor() as usize;
        level.min(4)
    }

    /// Implementação de seleção heurística com base em caminhos alternativos do HNSW original
    /// Impede o colapso do grafo ANN em cliques isolados e limita a densidade local controlando $O(M \log M)$
    fn select_neighbors_heuristic(
        &self,
        base_vec: &[f32],
        mut candidates: Vec<Lsn>,
        m: usize,
    ) -> Vec<Lsn> {
        if candidates.len() <= m {
            return candidates;
        }

        let mut result = Vec::with_capacity(m);
        // Ordena candidatos por proximidade absoluta ao nó inserido
        candidates.sort_by(|a, b| {
            let d1 = self
                .nodes
                .get(a)
                .map(|v| self.compute_distance(base_vec, v))
                .unwrap_or(f32::MAX);
            let d2 = self
                .nodes
                .get(b)
                .map(|v| self.compute_distance(base_vec, v))
                .unwrap_or(f32::MAX);
            d1.total_cmp(&d2)
        });

        for c in candidates {
            if result.len() >= m {
                break;
            }
            let c_vec = match self.nodes.get(&c) {
                Some(v) => v,
                None => continue,
            };
            let d_to_base = self.compute_distance(base_vec, c_vec);

            let mut keep = true;
            for r in &result {
                if let Some(r_vec) = self.nodes.get(r) {
                    let d_to_r = self.compute_distance(c_vec, r_vec);
                    // Se o candidato está mais perto de um vizinho já selecionado do que do nó base, descarta para manter diversidade espacial
                    if d_to_r < d_to_base {
                        keep = false;
                        break;
                    }
                }
            }
            if keep {
                result.push(c);
            }
        }
        result
    }

    pub fn search_layer_greedy(&self, query: &[f32], bound: Lsn) -> Option<Lsn> {
        if self.entry_points.is_empty() {
            return None;
        }

        let mut current_node = None;
        for &ep in self.entry_points.iter().rev() {
            if ep < bound {
                // Invariante de Camada M29: Verifica se o nó realmente existe no mapa da camada correspondente
                let layer_idx = self.entry_points.iter().position(|&x| x == ep).unwrap_or(0);
                if self
                    .layers
                    .get(layer_idx)
                    .is_some_and(|l| l.contains_key(&ep))
                {
                    current_node = Some(ep);
                    break;
                }
            }
        }

        let mut current_node = match current_node {
            Some(node) => node,
            None => {
                let mut fallback = None;
                let mut min_dist = f32::MAX;
                for (&lsn, vec) in &self.nodes {
                    if lsn < bound {
                        let d = self.compute_distance(query, vec);
                        if d < min_dist {
                            min_dist = d;
                            fallback = Some(lsn);
                        }
                    }
                }
                return fallback;
            }
        };

        let start_layer = self.layers.len().saturating_sub(1);
        for layer_idx in (0..=start_layer).rev() {
            let mut changed = true;
            while changed {
                changed = false;
                if let Some(neighbors) = self
                    .layers
                    .get(layer_idx)
                    .and_then(|l| l.get(&current_node))
                {
                    if let Some(current_vec) = self.nodes.get(&current_node) {
                        let mut current_dist = self.compute_distance(query, current_vec);
                        for &neighbor in neighbors.iter() {
                            if neighbor >= bound {
                                continue;
                            }
                            if let Some(neighbor_vec) = self.nodes.get(&neighbor) {
                                let dist = self.compute_distance(query, neighbor_vec);
                                if dist < current_dist {
                                    current_dist = dist;
                                    current_node = neighbor;
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        Some(current_node)
    }

    pub fn insert(&mut self, lsn: Lsn, vector: Vec<f32>) {
        self.nodes.insert(lsn, vector.clone());
        let target_layer = self.pick_random_layer(lsn);

        while self.layers.len() <= target_layer {
            self.layers.push(HashMap::new());
        }
        while self.entry_points.len() <= target_layer {
            self.entry_points.push(lsn);
        }

        if self.nodes.len() == 1 {
            for layer_idx in 0..=target_layer {
                self.layers[layer_idx].insert(lsn, Arc::new(Vec::new()));
                self.entry_points[layer_idx] = lsn;
            }
            return;
        }

        const M: usize = 12;
        let mut current_entry = self.entry_points[self.layers.len() - 1];
        let start_layer = self.layers.len() - 1;

        for layer_idx in (target_layer + 1..=start_layer).rev() {
            let mut changed = true;
            while changed {
                changed = false;
                if let Some(neighbors) = self
                    .layers
                    .get(layer_idx)
                    .and_then(|l| l.get(&current_entry))
                {
                    if let Some(entry_vec) = self.nodes.get(&current_entry) {
                        let mut current_dist = self.compute_distance(&vector, entry_vec);
                        for &neighbor in neighbors.iter() {
                            if neighbor < lsn {
                                if let Some(n_vec) = self.nodes.get(&neighbor) {
                                    let dist = self.compute_distance(&vector, n_vec);
                                    if dist < current_dist {
                                        current_dist = dist;
                                        current_entry = neighbor;
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut current_node = current_entry;
        for layer_idx in (0..=target_layer).rev() {
            self.layers[layer_idx].insert(lsn, Arc::new(Vec::new()));

            let mut changed = true;
            while changed {
                changed = false;
                if let Some(neighbors) = self
                    .layers
                    .get(layer_idx)
                    .and_then(|l| l.get(&current_node))
                {
                    if let Some(node_vec) = self.nodes.get(&current_node) {
                        let current_dist = self.compute_distance(&vector, node_vec);
                        for &neighbor in neighbors.iter() {
                            if neighbor < lsn {
                                if let Some(n_vec) = self.nodes.get(&neighbor) {
                                    let dist = self.compute_distance(&vector, n_vec);
                                    if dist < current_dist {
                                        current_node = neighbor;
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let mut candidates = vec![current_node];
            if let Some(neighbors) = self
                .layers
                .get(layer_idx)
                .and_then(|l| l.get(&current_node))
            {
                candidates.extend(neighbors.iter().cloned().filter(|&n| n < lsn));
            }

            // Substituição do truncate burro pela poda de diversidade espacial estruturada M29
            let selected = self.select_neighbors_heuristic(&vector, candidates, M);

            for neighbor in selected {
                // Fase 1: muta self.layers e decide se é preciso podar (liberta o
                // &mut self.layers no fim do bloco). Fase 2 usa &self (nodes +
                // select_neighbors_heuristic) sem conflito de borrow.
                let pool_for_prune = if let Some(layer_map) = self.layers.get_mut(layer_idx) {
                    let node_links = layer_map.get_mut(&lsn).unwrap();
                    Arc::make_mut(node_links).push(neighbor);

                    let links = layer_map.entry(neighbor).or_default();
                    if !links.contains(&lsn) {
                        Arc::make_mut(links).push(lsn);
                    }
                    if links.len() > M {
                        let mut pool = links.to_vec();
                        pool.push(lsn);
                        Some(pool)
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(pool) = pool_for_prune {
                    if let Some(n_vec) = self.nodes.get(&neighbor) {
                        let pruned = self.select_neighbors_heuristic(n_vec, pool, M);
                        if let Some(layer_map) = self.layers.get_mut(layer_idx) {
                            layer_map.insert(neighbor, Arc::new(pruned));
                        }
                    }
                }
            }
        }

        // Enforcement formal de pontos de entrada estáveis e obrigatoriamente existentes na camada
        for layer_idx in 0..=target_layer {
            if let Some(layer_map) = self.layers.get(layer_idx) {
                if !layer_map.contains_key(&self.entry_points[layer_idx]) {
                    self.entry_points[layer_idx] = lsn;
                }
            }
        }
    }
}

// =========================================================================
// M29: SUBSISTEMA TEXTUAL (LSM-LIKE STRUCTURAL ARCS PARA EVITAR AMPLIFICAÇÃO)
// =========================================================================

struct PostingCursor<'a> {
    slice: &'a [(Lsn, f32)],
    cursor: usize,
    idf: f32,
    max_term_score: f32,
}

impl<'a> PostingCursor<'a> {
    fn new(slice: &'a [(Lsn, f32)], idf: f32) -> Self {
        let max_tf = slice
            .iter()
            .map(|&(_, tf)| tf)
            .fold(0.0f32, |m, v| m.max(v));
        Self {
            slice,
            cursor: 0,
            idf,
            max_term_score: max_tf * idf,
        }
    }

    #[inline(always)]
    fn current_lsn(&self) -> Option<Lsn> {
        self.slice.get(self.cursor).map(|&(lsn, _)| lsn)
    }

    #[inline(always)]
    fn current_tf(&self) -> f32 {
        self.slice
            .get(self.cursor)
            .map(|&(_, tf)| tf)
            .unwrap_or(0.0f32)
    }

    #[inline(always)]
    fn advance_to(&mut self, target: Lsn) {
        while self.cursor < self.slice.len() && self.slice[self.cursor].0 < target {
            self.cursor += 1;
        }
    }
}

// Planos de índices totalmente desacoplados de forma isolada na raiz
#[derive(Clone, Default)]
struct TextInvertedIndex {
    pub inverted_text: HashMap<String, Arc<Vec<(Lsn, f32)>>>,
    pub total_docs: usize,
}

#[derive(Clone, Default)]
struct AttributeIndex {
    pub attributes: HashMap<String, HashMap<String, Arc<Vec<Lsn>>>>,
}

// =========================================================================
// M29: TRAIT DE CONSULTA UNIFICADO COM RESOLUÇÃO DINÂMICA DE SENTINELAS
// =========================================================================

pub trait QueryBackend {
    fn scan(&self, as_of: Option<Lsn>) -> Result<Vec<(Lsn, Episode)>, HeraclitusError>;
    fn scan_range(&self, from: Lsn, to: Lsn) -> Result<Vec<(Lsn, Episode)>, HeraclitusError>;
    fn head(&self) -> Result<Lsn, HeraclitusError>;
    fn graph(&self) -> Result<TemporalGraph, HeraclitusError>;
    fn append(
        &self,
        label: Option<&str>,
        props: &[(String, Value)],
    ) -> Result<Lsn, HeraclitusError>;

    fn attr_lookup(
        &self,
        field: &str,
        value: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<Vec<(Lsn, Episode)>>, HeraclitusError>;
    /// Range NUMÉRICO sobre um atributo (`WHERE n.campo > x AND n.campo < y`)
    /// resolvido pelo índice ordenado em vez do scan. Bounds `(valor,
    /// inclusivo?)`. Default `Ok(None)` = backend sem a capacidade → o planner
    /// cai no scan por janela (o pós-filtro revalida tudo; correção nunca
    /// depende do hint).
    fn attr_range_lookup(
        &self,
        _field: &str,
        _min: Option<(f64, bool)>,
        _max: Option<(f64, bool)>,
        _as_of: Option<Lsn>,
    ) -> Result<Option<Vec<(Lsn, Episode)>>, HeraclitusError> {
        Ok(None)
    }
    /// SPEC-010 pushdown: optimized scan for `WHERE <builtin> = "v"` on a
    /// zone-mapped builtin field (`agent_id`, `session_id`). Prunes sealed
    /// segments whose zone map cannot contain the value (skip-I/O), so those
    /// segments are never read. Returns a SUPERSET (the post-scan `matches`
    /// revalidates the exact field), capped at `as_of`. Default `Ok(None)` =
    /// backend has no zone maps, or the field is not zone-mapped → planner scans.
    fn scan_builtin_eq(
        &self,
        _field: &str,
        _value: &str,
        _as_of: Option<Lsn>,
    ) -> Result<Option<Vec<(Lsn, Episode)>>, HeraclitusError> {
        Ok(None)
    }
    fn recall(
        &self,
        text: &str,
        k: usize,
        as_of: Option<Lsn>,
    ) -> Result<Vec<(Lsn, Episode, f32)>, HeraclitusError>;
    fn nearest(
        &self,
        vector: &[f32],
        k: usize,
        as_of: Option<Lsn>,
    ) -> Result<Vec<(Lsn, Episode, f32)>, HeraclitusError>;

    fn provenance(&self, id: &str) -> Result<Vec<String>, HeraclitusError>;
    fn neighbors(
        &self,
        node: &str,
        etype: Option<&str>,
        as_of: Option<Lsn>,
        min_confidence: f32,
    ) -> Result<Vec<NeighborRow>, HeraclitusError>;
    fn traverse(
        &self,
        start: &str,
        max_depth: usize,
        as_of: Option<Lsn>,
        min_confidence: f32,
    ) -> Result<Vec<(String, usize)>, HeraclitusError>;
    fn match_edges(
        &self,
        src: Option<&str>,
        etype: Option<&str>,
        dst: Option<&str>,
        as_of: Option<Lsn>,
    ) -> Result<Vec<EdgeRow>, HeraclitusError>;
    fn community(
        &self,
        node: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<CommunityResult>, HeraclitusError>;
    /// Comunidades por LEIDEN (modularidade) — `COMMUNITY ("n", LEIDEN)`.
    /// Default: cai nas componentes conexas do `community` (backends sem a
    /// capacidade continuam corretos, só menos finos).
    fn community_leiden(
        &self,
        node: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<CommunityResult>, HeraclitusError> {
        self.community(node, as_of)
    }
    fn node_metrics(
        &self,
        node: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<MetricsResult>, HeraclitusError>;
    fn edge_hypotheses(
        &self,
        from: &str,
        to: &str,
        etype: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<EdgeHypotheses>, HeraclitusError>;
    fn lsn_for_timestamp(&self, ts_ms: u64) -> Result<Lsn, HeraclitusError>;
    fn resolve_entity(
        &self,
        key: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<String>, HeraclitusError>;
    fn entity_cluster(
        &self,
        entity_id: &str,
        as_of: Option<Lsn>,
    ) -> Result<Vec<String>, HeraclitusError>;

    fn why(
        &self,
        target: &str,
        max_depth: usize,
        as_of: Option<Lsn>,
    ) -> Result<Trace, HeraclitusError> {
        let bound = self.resolve_as_of_bound(as_of)?;
        let events = self.scan_range(0, bound)?;
        let present: BTreeSet<String> = events.iter().map(|(_, e)| e.id.to_string()).collect();
        let mut parents: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (_, e) in &events {
            let ps: Vec<String> = e
                .parents
                .iter()
                .map(|p| p.to_string())
                .filter(|p| present.contains(p))
                .collect();
            parents.insert(e.id.to_string(), ps);
        }
        Ok(trace_causes(&parents, target, max_depth))
    }

    /// SPEC-014: minimal causal chain from `target` down to `cause` (shortest
    /// path in the parent DAG). Reuses the same parent map as [`why`](Self::why),
    /// so it needs no extra graph representation. Empty ⇒ `cause` is not a cause.
    fn why_chain(
        &self,
        target: &str,
        cause: &str,
        as_of: Option<Lsn>,
    ) -> Result<Vec<String>, HeraclitusError> {
        let bound = self.resolve_as_of_bound(as_of)?;
        let events = self.scan_range(0, bound)?;
        let present: BTreeSet<String> = events.iter().map(|(_, e)| e.id.to_string()).collect();
        let mut parents: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (_, e) in &events {
            let ps: Vec<String> = e
                .parents
                .iter()
                .map(|p| p.to_string())
                .filter(|p| present.contains(p))
                .collect();
            parents.insert(e.id.to_string(), ps);
        }
        Ok(trace_minimal_chain(&parents, target, cause))
    }

    fn decide(
        &self,
        policy: DecisionPolicy,
        as_of: Option<Lsn>,
    ) -> Result<DecisionReport, HeraclitusError> {
        let bound = self.resolve_as_of_bound(as_of)?;
        let mut g = TemporalGraph::new();
        let mut existing = BTreeSet::new();

        let snapshot_events = self.scan_range(0, bound)?;
        for (lsn, e) in snapshot_events {
            g.apply_episode(lsn, &e);
            if e.kind == EventKind::Action {
                if let Some(act_id) = e.attrs.get("action_id") {
                    existing.insert(act_id.clone());
                }
            }
        }
        let decisions = decision::evaluate(&g, u64::MAX, &policy);

        let mut report = DecisionReport::default();
        for d in decisions {
            if existing.contains(&d.action_id) {
                report.skipped.push(d.action_id);
                continue;
            }
            let props = [
                ("action_id".to_string(), Value::Str(d.action_id.clone())),
                ("rule".to_string(), Value::Str(d.rule.clone())),
                ("subject".to_string(), Value::Str(d.subject.clone())),
                ("reason".to_string(), Value::Str(d.reason.clone())),
            ];
            let lsn = self.append(Some("action"), &props)?;
            report.fired.push(ActionRecord {
                action_id: d.action_id,
                rule: d.rule,
                subject: d.subject,
                reason: d.reason,
                lsn,
            });
        }
        Ok(report)
    }

    fn adapt(&self, as_of: Option<Lsn>) -> Result<AdaptReport, HeraclitusError> {
        let bound = self.resolve_as_of_bound(as_of)?;
        let rule = "flag_anomaly";
        let samples: Vec<LabeledFlag> = self
            .scan_range(0, bound)?
            .into_iter()
            .filter(|(_, e)| e.attrs.get("feedback_rule").map(|r| r.as_str()) == Some(rule))
            .filter_map(|(_, e)| {
                let score = e.attrs.get("score")?.parse::<f32>().ok()?;
                let confirmed = e
                    .attrs
                    .get("verdict")
                    .map(|v| v == "confirm")
                    .unwrap_or(false);
                Some(LabeledFlag { score, confirmed })
            })
            .collect();

        let default_threshold = DecisionPolicy::default().anomaly_threshold;
        let learned_threshold = adaptive::learn_threshold(&samples, default_threshold);
        Ok(AdaptReport {
            rule: rule.to_string(),
            samples: samples.len(),
            learned_threshold,
            default: adaptive::evaluate_threshold(&samples, default_threshold),
            adapted: adaptive::evaluate_threshold(&samples, learned_threshold),
        })
    }

    fn find_fused(
        &self,
        text: &str,
        vector: &[f32],
        connected_to: &str,
        weights: FusionWeights,
        k: usize,
        as_of: Option<Lsn>,
    ) -> Result<Vec<FusedHit>, HeraclitusError> {
        let fetch = (k * 4).max(8);
        let head_lsn = self.head()?;

        let mut graph_ch: Vec<(String, u64, f32)> = self
            .neighbors(connected_to, None, as_of, 0.0)?
            .into_iter()
            .map(|n| (n.to, n.lsn, n.belief))
            .collect();
        let mut vec_ch: Vec<(String, u64, f32)> = self
            .nearest(vector, fetch, as_of)?
            .into_iter()
            .map(|(l, e, d)| (e.id.to_string(), l, 1.0 / (1.0 + d)))
            .collect();
        let mut txt_ch: Vec<(String, u64, f32)> = self
            .recall(text, fetch, as_of)?
            .into_iter()
            .map(|(l, e, s)| (e.id.to_string(), l, s))
            .collect();

        fold_normalization(&mut graph_ch);
        fold_normalization(&mut vec_ch);
        fold_normalization(&mut txt_ch);

        let mut rows: HashMap<String, (u64, FusionInput)> = HashMap::with_capacity(fetch * 3);
        for (id, lsn, sc) in graph_ch {
            let entry = rows.entry(id).or_insert((0, FusionInput::default()));
            if lsn > entry.0 {
                entry.0 = lsn;
            }
            entry.1.graph_score = sc;
        }
        for (id, lsn, sc) in vec_ch {
            let entry = rows.entry(id).or_insert((0, FusionInput::default()));
            if lsn > entry.0 {
                entry.0 = lsn;
            }
            entry.1.vector_score = sc;
        }
        for (id, lsn, sc) in txt_ch {
            let entry = rows.entry(id).or_insert((0, FusionInput::default()));
            if lsn > entry.0 {
                entry.0 = lsn;
            }
            entry.1.text_score = sc;
        }

        let lambda = 0.0005f32;
        let mut hits: Vec<FusedHit> = rows
            .into_iter()
            .map(|(id, (lsn, input))| {
                let base_score = weights.fuse(&input);
                let delta = head_lsn.saturating_sub(lsn) as f32;
                let temporal_bias = (-lambda * delta).exp();
                FusedHit {
                    id,
                    lsn,
                    input,
                    score: base_score * temporal_bias,
                }
            })
            .collect();

        hits.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.id.cmp(&b.id)));
        hits.truncate(k);
        Ok(hits)
    }

    fn resolve_as_of_bound(&self, as_of: Option<Lsn>) -> Result<Lsn, HeraclitusError> {
        match as_of {
            Some(explicit_lsn) => Ok(explicit_lsn),
            None => self.head(),
        }
    }
}

// =========================================================================
// M29: SNAPSHOT BUNDLE UTILIZANDO COw PARCIAL (ELIMINA CLONE $O(N+E)$ SPICES)
// =========================================================================

struct SnapshotBundle {
    lsn: Lsn,
    graph: Arc<TemporalGraph>,
    resolver: Arc<EntityResolver>,
    text_index: Arc<TextInvertedIndex>,
    attr_index: Arc<AttributeIndex>,
    vector_index: Arc<HnswIndex>,
}

pub struct LogBackend {
    log: Arc<Log>,
    bundle: ArcSwap<SnapshotBundle>,
    sync_mutex: Mutex<()>,
    /// SPEC-028 wired: um SkipScanner vivo entre queries — o cache de zone maps
    /// em RAM paga-se a cada hit, e o ArtifactRegistry cataloga cada zone map
    /// (fingerprint por segmento) para reuso/evicção LRU sob pressão.
    scanner: SkipScanner,
    artifacts: Mutex<heraclitus_core::artifact_registry::ArtifactRegistry>,
    /// artifact_id → segment (para a evicção em cascata executar no scanner).
    artifact_segments: Mutex<std::collections::HashMap<u64, heraclitus_core::SegmentId>>,
    /// SPEC-032 wired: calibrador EMA por fingerprint de caminho de acesso; se
    /// o skip-scan se provar mais lento que o window-scan, o planner cai de
    /// volta (adaptativo, sem redes neuronais — pura estatística).
    calibrator: Mutex<heraclitus_core::cost::EmaCalibrator>,
}

impl LogBackend {
    pub fn new(log: Arc<Log>) -> Self {
        let initial_bundle = SnapshotBundle {
            lsn: 0,
            graph: Arc::new(TemporalGraph::new()),
            resolver: Arc::new(EntityResolver::new()),
            text_index: Arc::new(TextInvertedIndex::default()),
            attr_index: Arc::new(AttributeIndex::default()),
            vector_index: Arc::new(HnswIndex::default()),
        };
        Self {
            scanner: SkipScanner::new(log.clone()),
            log,
            bundle: ArcSwap::from_pointee(initial_bundle),
            sync_mutex: Mutex::new(()),
            artifacts: Mutex::new(Default::default()),
            artifact_segments: Mutex::new(std::collections::HashMap::new()),
            calibrator: Mutex::new(heraclitus_core::cost::EmaCalibrator::new(0.3)),
        }
    }

    /// Fingerprint de intenção para um caminho de acesso (SPEC-011/028).
    fn access_fingerprint(kind: &str, seed: u64) -> heraclitus_core::QueryFingerprint {
        let mut h = blake3::Hasher::new();
        h.update(kind.as_bytes());
        h.update(&seed.to_be_bytes());
        heraclitus_core::QueryFingerprint {
            logical_intent_hash: *h.finalize().as_bytes(),
            applicable_snapshot: seed,
        }
    }

    /// SPEC-032: regista uma medição de latência de um caminho de acesso
    /// (`"skip"` ou `"window"`). Público para o executor — e para testes.
    pub fn observe_access_path(&self, path: &str, nanos: f64) {
        let fp = Self::access_fingerprint(path, 0);
        self.calibrator.lock().unwrap().observe(fp.logical_intent_hash, nanos);
    }

    fn predicted_access_path(&self, path: &str) -> Option<f64> {
        let fp = Self::access_fingerprint(path, 0);
        self.calibrator.lock().unwrap().predicted(&fp.logical_intent_hash)
    }

    /// SPEC-028/031: cataloga os zone maps tocados; sob pressão (mais entradas
    /// em RAM que `cap`), evicta o LRU do registry E do cache do scanner.
    fn register_zone_maps(&self, cap: usize) {
        let sealed = self.log.sealed_segments();
        let mut reg = self.artifacts.lock().unwrap();
        let mut seg_of = self.artifact_segments.lock().unwrap();
        for meta in &sealed {
            let fp = Self::access_fingerprint("zonemap", meta.id);
            if reg.lookup(&fp).is_none() {
                let id = reg.register(
                    fp,
                    heraclitus_core::ArtifactType::ZoneMap,
                    1024, // estimativa fixa por zone map
                    vec![],
                );
                seg_of.insert(id, meta.id);
            }
        }
        while self.scanner.cached() > cap {
            let Some(evicted) = reg.evict_lru() else { break };
            let mut dropped = false;
            for id in evicted {
                if let Some(seg) = seg_of.remove(&id) {
                    dropped |= self.scanner.evict(seg);
                }
            }
            if !dropped {
                break; // registry esvaziou sem reduzir o cache — evita loop
            }
        }
    }

    /// Estatísticas do registry (testes/introspecção): `(artefactos, zone maps em RAM)`.
    pub fn artifact_stats(&self) -> (usize, usize) {
        (self.artifacts.lock().unwrap().len(), self.scanner.cached())
    }

    fn sync_bundle(&self) -> Result<Arc<SnapshotBundle>, HeraclitusError> {
        // Captura monotônica blindada do HEAD físico real antes da janela de processamento
        let pinned_head = self.log.head();
        let current_bundle = self.bundle.load();

        if current_bundle.lsn >= pinned_head {
            return Ok(self.bundle.load_full());
        }

        let _guard = self.sync_mutex.lock().unwrap();

        let current_bundle = self.bundle.load();
        if current_bundle.lsn >= pinned_head {
            return Ok(self.bundle.load_full());
        }

        let start_lsn = current_bundle.lsn;

        // CORRIGIDO: Eliminação da re-materialização profunda $O(N+E)$.
        // Copiamos os top-level maps por ponteiro imutável compartilhando as sub-listas internas via Arc.
        let mut updated_graph = (*current_bundle.graph).clone();
        let mut updated_resolver = (*current_bundle.resolver).clone();
        let mut updated_text = (*current_bundle.text_index).clone();
        let mut updated_attr = (*current_bundle.attr_index).clone();
        let mut updated_vector = (*current_bundle.vector_index).clone();

        // Correção R4: o scan cobre EXATAMENTE [start_lsn, pinned_head) e o
        // bundle novo declara `lsn = pinned_head` (o PRÓXIMO LSN a indexar).
        // A versão anterior punha `pinned_head + 1`, reclamando cobertura de um
        // LSN que ainda não existia — quando ele era escrito, o guard
        // `bundle.lsn >= head` dava o bundle como fresco e o episódio ficava
        // invisível para sempre nos índices (confirmado por sonda).
        let delta = self.log.scan_capped(start_lsn, pinned_head, usize::MAX)?;
        for (lsn, ep) in delta {
            if lsn >= start_lsn && lsn < pinned_head {
                updated_graph.apply_episode(lsn, &ep);
                updated_resolver.apply_episode(lsn, &ep);

                // Ingestão incremental com CoW granular. O tf persistido é a
                // contagem BRUTA do termo (não normalizada pelo comprimento do
                // doc): a semântica de referência do RECALL — e o gate M10 de
                // fusão — pontua repetição ("fraude fraude" > "fraude").
                updated_text.total_docs += 1;
                let content_str = String::from_utf8_lossy(&ep.content).to_lowercase();
                let mut local_frequencies: HashMap<String, f32> = HashMap::new();

                for token in content_str
                    .split(|c: char| !c.is_alphanumeric())
                    .filter(|s| !s.is_empty())
                {
                    *local_frequencies.entry(token.to_string()).or_insert(0.0f32) += 1.0f32;
                }

                for (token, raw_count) in local_frequencies {
                    let postings = updated_text.inverted_text.entry(token).or_default();
                    Arc::make_mut(postings).push((lsn, raw_count));
                }

                for (field, value) in &ep.attrs {
                    let postings = updated_attr
                        .attributes
                        .entry(field.clone())
                        .or_default()
                        .entry(value.clone())
                        .or_default();
                    Arc::make_mut(postings).push(lsn);
                }

                if let Some(emb) = &ep.embedding {
                    let mut flat_vector =
                        Vec::with_capacity(emb.hyp.len() + emb.sph.len() + emb.euc.len());
                    flat_vector.extend(&emb.hyp);
                    flat_vector.extend(&emb.sph);
                    flat_vector.extend(&emb.euc);
                    updated_vector.insert(lsn, flat_vector);
                }
            }
        }

        updated_resolver.watermark = pinned_head;

        let new_bundle = SnapshotBundle {
            lsn: pinned_head,
            graph: Arc::new(updated_graph),
            resolver: Arc::new(updated_resolver),
            text_index: Arc::new(updated_text),
            attr_index: Arc::new(updated_attr),
            vector_index: Arc::new(updated_vector),
        };

        self.bundle.store(Arc::new(new_bundle));
        Ok(self.bundle.load_full())
    }
}

impl QueryBackend for LogBackend {
    fn scan(&self, as_of: Option<Lsn>) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        let bound = self.resolve_as_of_bound(as_of)?;
        self.log.scan_capped(0, bound, QUERY_SCAN_CAP)
    }

    fn scan_range(&self, from: Lsn, to: Lsn) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        self.log.scan_capped(from, to, QUERY_SCAN_CAP)
    }

    fn head(&self) -> Result<Lsn, HeraclitusError> {
        Ok(self.log.head())
    }

    fn graph(&self) -> Result<TemporalGraph, HeraclitusError> {
        Ok((*self.sync_bundle()?.graph).clone())
    }

    fn attr_lookup(
        &self,
        field: &str,
        value: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<Vec<(Lsn, Episode)>>, HeraclitusError> {
        let b = self.sync_bundle()?;
        let bound = self.resolve_as_of_bound(as_of)?;

        let Some(values_map) = b.attr_index.attributes.get(field) else {
            return Ok(None);
        };
        let Some(postings) = values_map.get(value) else {
            return Ok(None);
        };

        let idx = match postings.binary_search(&bound) {
            Ok(found_idx) => found_idx,
            Err(insert_idx) => insert_idx,
        };

        let target_lsns = &postings[..idx];
        if target_lsns.is_empty() {
            return Ok(None);
        }

        let mut results = Vec::with_capacity(target_lsns.len());
        for &lsn in target_lsns {
            if let Some((_, ep)) = self.log.read(lsn)? {
                results.push((lsn, ep));
            }
        }
        Ok(Some(results))
    }

    /// Range numérico de referência: varre os VALORES distintos do campo no
    /// índice em RAM (O(#valores), exato) — o backend real usa o BTreeMap
    /// ordenado do heraclitus-index-attr.
    fn attr_range_lookup(
        &self,
        field: &str,
        min: Option<(f64, bool)>,
        max: Option<(f64, bool)>,
        as_of: Option<Lsn>,
    ) -> Result<Option<Vec<(Lsn, Episode)>>, HeraclitusError> {
        let b = self.sync_bundle()?;
        let bound = self.resolve_as_of_bound(as_of)?;

        let Some(values_map) = b.attr_index.attributes.get(field) else {
            return Ok(None);
        };

        let in_range = |n: f64| {
            min.is_none_or(|(m, inc)| if inc { n >= m } else { n > m })
                && max.is_none_or(|(m, inc)| if inc { n <= m } else { n < m })
        };

        let mut lsns: Vec<Lsn> = Vec::new();
        for (value, postings) in values_map.iter() {
            let Ok(n) = value.trim().parse::<f64>() else {
                continue;
            };
            if !n.is_finite() || !in_range(n) {
                continue;
            }
            let idx = match postings.binary_search(&bound) {
                Ok(found) => found,
                Err(ins) => ins,
            };
            lsns.extend_from_slice(&postings[..idx]);
        }
        if lsns.is_empty() {
            return Ok(Some(Vec::new()));
        }
        lsns.sort_unstable();
        lsns.dedup();

        let mut results = Vec::with_capacity(lsns.len());
        for lsn in lsns {
            if let Some((_, ep)) = self.log.read(lsn)? {
                results.push((lsn, ep));
            }
        }
        Ok(Some(results))
    }

    fn scan_builtin_eq(
        &self,
        field: &str,
        value: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<Vec<(Lsn, Episode)>>, HeraclitusError> {
        let bound = self.resolve_as_of_bound(as_of)?;
        // SPEC-032 (adaptativo): se o histórico EMA diz que o skip-scan tem sido
        // >20% mais lento que o window-scan, devolve None — o planner cai no
        // window scan e o pós-filtro mantém a correção. Sem histórico, skip.
        if let (Some(skip_ns), Some(win_ns)) = (
            self.predicted_access_path("skip"),
            self.predicted_access_path("window"),
        ) {
            if skip_ns > win_ns * 1.2 {
                return Ok(None);
            }
        }
        // Skip-I/O over sealed segments (SPEC-010) com o scanner PERSISTENTE
        // (SPEC-028: o cache de zone maps sobrevive entre queries; sidecars
        // .zmap cobrem o cold boot).
        let t0 = std::time::Instant::now();
        let (mut hits, _stats) = match field {
            "agent_id" => self.scanner.scan_pruned(|z| z.may_contain_agent(value))?,
            "session_id" => self.scanner.scan_pruned(|z| z.may_contain_session(value))?,
            _ => return Ok(None), // field not summarized by the zone map
        };
        self.observe_access_path("skip", t0.elapsed().as_nanos() as f64);
        // SPEC-028/031: cataloga os zone maps tocados e aplica a política de
        // evicção (cap de zone maps em RAM; o registry escolhe o LRU).
        self.register_zone_maps(1024);
        // Respect the AS OF ceiling and the query scan cap. We return a superset
        // of the surviving segments; the planner's `matches` post-filter checks
        // the exact field, so correctness never depends on this hint.
        hits.retain(|(l, _)| *l < bound);
        if hits.len() > QUERY_SCAN_CAP {
            hits.truncate(QUERY_SCAN_CAP);
        }
        Ok(Some(hits))
    }

    /// CORRIGIDO: WAND determinístico sem reorder global $O(k \log k)$ e com garantia de avanço monotônico livre de skips.
    fn recall(
        &self,
        text: &str,
        k: usize,
        as_of: Option<Lsn>,
    ) -> Result<Vec<(Lsn, Episode, f32)>, HeraclitusError> {
        let b = self.sync_bundle()?;
        let bound = self.resolve_as_of_bound(as_of)?;
        let tokens: Vec<String> = text
            .to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        if tokens.is_empty() {
            return Ok(Vec::new());
        }

        let total_docs = b.text_index.total_docs.max(1);
        let mut cursors = Vec::with_capacity(tokens.len());

        for token in &tokens {
            if let Some(postings) = b.text_index.inverted_text.get(token) {
                let idx = match postings.binary_search_by_key(&bound, |&(l, _)| l) {
                    Ok(found) => found,
                    Err(ins) => ins,
                };
                let active_slice = &postings[..idx];
                if !active_slice.is_empty() {
                    let df = active_slice.len() as f32;
                    let idf = (1.0 + ((total_docs as f32 - df + 0.5) / (df + 0.5)))
                        .ln()
                        .max(0.0001f32);
                    cursors.push(PostingCursor::new(active_slice, idf));
                }
            }
        }

        if cursors.is_empty() {
            return Ok(Vec::new());
        }

        let mut top_k_heap: BinaryHeap<MinScoreEntry> = BinaryHeap::with_capacity(k);
        let mut score_accumulator: HashMap<Lsn, f32> = HashMap::new();
        let mut current_threshold = 0.0f32;

        loop {
            // Varredura incremental linear indexada para achar o menor LSN corrente sem quebrar a cache com sort total
            let mut min_lsn = None;
            for c in &cursors {
                if let Some(l) = c.current_lsn() {
                    min_lsn = Some(min_lsn.map_or(l, |m| std::cmp::min(m, l)));
                }
            }

            let Some(pivot_lsn) = min_lsn else {
                break;
            };

            let mut accumulated_upper_bound = 0.0f32;
            let mut met_threshold = false;

            for cursor in &cursors {
                if cursor.current_lsn().is_some() {
                    accumulated_upper_bound += cursor.max_term_score;
                    if accumulated_upper_bound >= current_threshold {
                        met_threshold = true;
                        break;
                    }
                }
            }

            if !met_threshold {
                break;
            }

            // Avaliação e avanço determinístico sincronizado: Garante progresso real descartando loops infinitos
            let mut total_score = 0.0f32;
            let mut matched = false;

            for cursor in cursors.iter_mut() {
                if cursor.current_lsn() == Some(pivot_lsn) {
                    total_score += cursor.current_tf() * cursor.idf;
                    cursor.cursor += 1;
                    matched = true;
                }
            }

            if matched {
                score_accumulator.insert(pivot_lsn, total_score);
                let entry = MinScoreEntry {
                    score: total_score,
                    lsn: pivot_lsn,
                };

                if top_k_heap.len() < k {
                    top_k_heap.push(entry);
                } else if total_score > top_k_heap.peek().unwrap().score {
                    top_k_heap.pop();
                    top_k_heap.push(entry);
                }
                current_threshold = if top_k_heap.len() >= k {
                    top_k_heap.peek().unwrap().score
                } else {
                    0.0f32
                };
            } else {
                // Força o alinhamento monotônico de cursors atrasados para o próximo bloco válido
                for cursor in cursors.iter_mut() {
                    cursor.advance_to(pivot_lsn + 1);
                }
            }
        }

        let mut candidates: Vec<(Lsn, f32)> = score_accumulator.into_iter().collect();
        candidates.sort_by(|a, b| b.1.total_cmp(&a.1).then(b.0.cmp(&a.0)));
        candidates.truncate(k);

        let mut final_hits = Vec::with_capacity(candidates.len());
        for (lsn, score) in candidates {
            if let Some((_, e)) = self.log.read(lsn)? {
                final_hits.push((lsn, e, score));
            }
        }
        Ok(final_hits)
    }

    /// K-NN CORRIGIDO (fix pós-M30): (1) o nó de routing entra nos resultados —
    /// antes o melhor hit era descartado e a fusão perdia o vencedor do canal
    /// vetorial; (2) o heap de top-k é um MAX-heap por distância (via `Reverse`),
    /// para que `peek` devolva o PIOR hit retido — era um min-heap, o que fazia
    /// o corte usar o MELHOR hit como limite e a eviction expulsar o mais próximo.
    fn nearest(
        &self,
        vector: &[f32],
        k: usize,
        as_of: Option<Lsn>,
    ) -> Result<Vec<(Lsn, Episode, f32)>, HeraclitusError> {
        if k == 0 {
            return Ok(Vec::new());
        }
        let b = self.sync_bundle()?;
        let bound = self.resolve_as_of_bound(as_of)?;

        let Some(best_routing_node) = b.vector_index.search_layer_greedy(vector, bound) else {
            return Ok(Vec::new());
        };

        let mut visited = BTreeSet::new();
        let mut candidate_heap: BinaryHeap<MinScoreEntry> = BinaryHeap::new();
        let mut top_hits_heap: BinaryHeap<Reverse<MinScoreEntry>> = BinaryHeap::new();

        if let Some(first_vec) = b.vector_index.nodes.get(&best_routing_node) {
            let initial_dist = b.vector_index.compute_distance(vector, first_vec);
            candidate_heap.push(MinScoreEntry {
                score: initial_dist,
                lsn: best_routing_node,
            });
            top_hits_heap.push(Reverse(MinScoreEntry {
                score: initial_dist,
                lsn: best_routing_node,
            }));
            visited.insert(best_routing_node);
        }

        while let Some(MinScoreEntry {
            score: curr_dist,
            lsn: current_node,
        }) = candidate_heap.pop()
        {
            let limit_dist = if top_hits_heap.len() >= k {
                top_hits_heap.peek().unwrap().0.score
            } else {
                f32::MAX
            };
            if curr_dist > limit_dist {
                break;
            }

            if let Some(neighbors) = b
                .vector_index
                .layers
                .first()
                .and_then(|l| l.get(&current_node))
            {
                for &neighbor in neighbors.iter() {
                    if neighbor >= bound {
                        continue;
                    }
                    if visited.insert(neighbor) {
                        if let Some(n_vec) = b.vector_index.nodes.get(&neighbor) {
                            let dist = b.vector_index.compute_distance(vector, n_vec);

                            if top_hits_heap.len() < k {
                                top_hits_heap.push(Reverse(MinScoreEntry {
                                    score: dist,
                                    lsn: neighbor,
                                }));
                                candidate_heap.push(MinScoreEntry {
                                    score: dist,
                                    lsn: neighbor,
                                });
                            } else if dist < top_hits_heap.peek().unwrap().0.score {
                                top_hits_heap.pop();
                                top_hits_heap.push(Reverse(MinScoreEntry {
                                    score: dist,
                                    lsn: neighbor,
                                }));
                                candidate_heap.push(MinScoreEntry {
                                    score: dist,
                                    lsn: neighbor,
                                });
                            }
                        }
                    }
                }
            }
        }

        let mut raw_hits: Vec<(Lsn, f32)> = top_hits_heap
            .into_iter()
            .map(|Reverse(MinScoreEntry { score, lsn })| (lsn, score))
            .collect();
        raw_hits.sort_by(|a, b| a.1.total_cmp(&b.1));

        let mut final_hydrated_hits = Vec::with_capacity(raw_hits.len());
        for (lsn, dist) in raw_hits {
            if let Some((_, e)) = self.log.read(lsn)? {
                final_hydrated_hits.push((lsn, e, dist));
            }
        }
        Ok(final_hydrated_hits)
    }

    fn provenance(&self, id: &str) -> Result<Vec<String>, HeraclitusError> {
        let head = self.log.head();
        let mut chunk_iter = LogChunkIterator::new(self.log.clone(), 0, head);
        while let Some((_, e)) = chunk_iter.next_item()? {
            if e.id.to_string() == id {
                return Ok(e.parents.iter().map(|p| p.to_string()).collect());
            }
        }
        Ok(Vec::new())
    }

    // Leituras de grafo/entidade (fix pós-M30): delegam nas funções livres
    // `*_of`, que aplicam o contrato MVCC "AS OF LSN b = visível se lsn < b"
    // via `as_of_point` (b-1 inclusivo; b=0 ⇒ snapshot vazio). A impl anterior
    // passava o bound EXCLUSIVO como ponto INCLUSIVO ao TemporalGraph — um
    // off-by-one que fazia `AS OF LSN n` ver eventos do próprio lsn n (e
    // `AS OF LSN 0` devolver dados). Uma única semântica: LogBackend, server
    // e VirtualBackend usam o mesmo caminho.
    fn neighbors(
        &self,
        node: &str,
        etype: Option<&str>,
        as_of: Option<Lsn>,
        min_confidence: f32,
    ) -> Result<Vec<NeighborRow>, HeraclitusError> {
        let b = self.sync_bundle()?;
        Ok(neighbors_of(&b.graph, node, etype, as_of, min_confidence))
    }

    fn traverse(
        &self,
        start: &str,
        max_depth: usize,
        as_of: Option<Lsn>,
        min_confidence: f32,
    ) -> Result<Vec<(String, usize)>, HeraclitusError> {
        let b = self.sync_bundle()?;
        Ok(traverse_of(
            &b.graph,
            start,
            max_depth,
            as_of,
            min_confidence,
        ))
    }

    fn match_edges(
        &self,
        src: Option<&str>,
        etype: Option<&str>,
        dst: Option<&str>,
        as_of: Option<Lsn>,
    ) -> Result<Vec<EdgeRow>, HeraclitusError> {
        let b = self.sync_bundle()?;
        Ok(match_edges_of(&b.graph, src, etype, dst, as_of))
    }

    fn edge_hypotheses(
        &self,
        from: &str,
        to: &str,
        etype: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<EdgeHypotheses>, HeraclitusError> {
        let b = self.sync_bundle()?;
        Ok(hypotheses_of(&b.graph, from, to, etype, as_of))
    }

    fn community(
        &self,
        node: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<CommunityResult>, HeraclitusError> {
        let b = self.sync_bundle()?;
        Ok(community_of(&b.graph, node, as_of))
    }

    fn community_leiden(
        &self,
        node: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<CommunityResult>, HeraclitusError> {
        let b = self.sync_bundle()?;
        Ok(community_leiden_of(&b.graph, node, as_of))
    }

    fn node_metrics(
        &self,
        node: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<MetricsResult>, HeraclitusError> {
        let b = self.sync_bundle()?;
        Ok(node_metrics_of(&b.graph, node, as_of))
    }

    fn resolve_entity(
        &self,
        key: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<String>, HeraclitusError> {
        let b = self.sync_bundle()?;
        Ok(resolve_of(&b.resolver, key, as_of))
    }

    fn entity_cluster(
        &self,
        entity_id: &str,
        as_of: Option<Lsn>,
    ) -> Result<Vec<String>, HeraclitusError> {
        let b = self.sync_bundle()?;
        Ok(cluster_of(&b.resolver, entity_id, as_of))
    }

    fn lsn_for_timestamp(&self, ts_ms: u64) -> Result<Lsn, HeraclitusError> {
        let head = self.log.head();
        let mut low = 0;
        let mut high = head;
        let mut ans = head;
        while low <= high {
            let mid = low + (high - low) / 2;
            match self.log.read(mid)? {
                Some((_, e)) => {
                    let e_ts = e.ts_hlc >> 16;
                    if e_ts > ts_ms {
                        ans = mid;
                        if mid == 0 {
                            break;
                        }
                        high = mid - 1;
                    } else {
                        low = mid + 1;
                    }
                }
                None => {
                    if mid == 0 {
                        break;
                    }
                    high = mid - 1;
                }
            }
        }
        Ok(ans)
    }

    fn append(
        &self,
        label: Option<&str>,
        props: &[(String, Value)],
    ) -> Result<Lsn, HeraclitusError> {
        let kind = match label {
            Some(l) if l.eq_ignore_ascii_case("action") => EventKind::Action,
            Some(l) if l.eq_ignore_ascii_case("message") => EventKind::Message,
            Some(l) if l.eq_ignore_ascii_case("observation") || l.is_empty() => {
                EventKind::Observation
            }
            Some(l) => EventKind::Custom(l.to_string()),
            None => EventKind::Observation,
        };
        let mut e = Episode::new("query", kind, Vec::new());
        for (k, v) in props {
            let s = match v {
                Value::Str(s) => s.clone(),
                Value::Num(n) => n.to_string(),
            };
            e.attrs.insert(k.clone(), s);
        }
        self.log.append(e)
    }
}

// =========================================================================
// M29: LOG CHUNK ITERATOR RESILIENTE CONTRA COMPACTAÇÃO DE WAL
// =========================================================================

struct LogChunkIterator {
    log: Arc<Log>,
    current_lsn: Lsn,
    to_lsn: Lsn,
    current_batch: std::vec::IntoIter<(Lsn, Episode)>,
}

impl LogChunkIterator {
    fn new(log: Arc<Log>, from_lsn: Lsn, to_lsn: Lsn) -> Self {
        Self {
            log,
            current_lsn: from_lsn,
            to_lsn,
            current_batch: Vec::new().into_iter(),
        }
    }

    fn next_item(&mut self) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        if let Some(item) = self.current_batch.next() {
            return Ok(Some(item));
        }
        if self.current_lsn >= self.to_lsn {
            return Ok(None);
        }

        let batch = self.log.scan_capped(self.current_lsn, self.to_lsn, 2048)?;
        if batch.is_empty() {
            self.current_lsn += 1;
            return Ok(None);
        }

        if let Some(&(last_lsn, _)) = batch.last() {
            self.current_lsn = last_lsn + 1;
        }
        self.current_batch = batch.into_iter();
        Ok(self.current_batch.next())
    }
}

fn fold_normalization(items: &mut [(String, u64, f32)]) {
    let max = items.iter().map(|x| x.2).fold(0.0f32, f32::max);
    if max > 0.0 {
        for item in items.iter_mut() {
            item.2 /= max;
        }
    }
}

pub fn trace_causes(
    parents: &BTreeMap<String, Vec<String>>,
    target: &str,
    max_depth: usize,
) -> Trace {
    use std::collections::VecDeque;
    if !parents.contains_key(target) {
        return Trace {
            target: target.to_string(),
            steps: Vec::new(),
            roots: Vec::new(),
        };
    }
    let mut depth_of: BTreeMap<String, usize> = BTreeMap::new();
    let mut q: VecDeque<(String, usize)> = VecDeque::new();
    depth_of.insert(target.to_string(), 0);
    q.push_back((target.to_string(), 0));

    let mut steps: Vec<CausalStep> = Vec::new();
    let mut roots: Vec<String> = Vec::new();
    while let Some((id, d)) = q.pop_front() {
        let causes = parents.get(&id).cloned().unwrap_or_default();
        if causes.is_empty() {
            roots.push(id.clone());
        }
        if d < max_depth {
            for p in &causes {
                if !depth_of.contains_key(p) {
                    depth_of.insert(p.clone(), d + 1);
                    q.push_back((p.clone(), d + 1));
                }
            }
        }
        steps.push(CausalStep {
            id,
            depth: d,
            causes,
        });
    }
    steps.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.id.cmp(&b.id)));
    roots.sort();
    roots.dedup();
    Trace {
        target: target.to_string(),
        steps,
        roots,
    }
}

/// SPEC-014: minimal causal chain `[effect, …, cause]` — the shortest path from
/// `effect` up to `cause` in the parent DAG (BFS over `parents`). Returns empty
/// if `cause` is not an ancestor of `effect`. Same parent map as `trace_causes`.
pub fn trace_minimal_chain(
    parents: &BTreeMap<String, Vec<String>>,
    effect: &str,
    cause: &str,
) -> Vec<String> {
    if effect == cause {
        return vec![effect.to_string()];
    }
    let mut came_from: HashMap<String, String> = HashMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    seen.insert(effect.to_string());
    let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    queue.push_back(effect.to_string());
    while let Some(node) = queue.pop_front() {
        if let Some(ps) = parents.get(&node) {
            for p in ps {
                if !seen.insert(p.clone()) {
                    continue;
                }
                came_from.insert(p.clone(), node.clone());
                if p == cause {
                    // Reconstruct effect → … → cause.
                    let mut chain = vec![p.clone()];
                    let mut cur = p.clone();
                    while let Some(child) = came_from.get(&cur) {
                        chain.push(child.clone());
                        cur = child.clone();
                    }
                    chain.reverse();
                    return chain;
                }
                queue.push_back(p.clone());
            }
        }
    }
    Vec::new()
}

// ─────────────────────────────────────────────────────────────────────────
// Funções de grafo/entidade recuperadas (M30): o refactor moveu a query para
// métodos de trait mas o `heraclitus-server` ainda consome estas funções livres
// sobre `TemporalGraph`/`EntityResolver`. Restauradas do git (ae08c8b~1) para
// destravar o `server`. Semântica MVCC "AS OF" preservada por `as_of_point`.
// ─────────────────────────────────────────────────────────────────────────

/// Strict MVCC Snapshot Contract: visible if lsn < bound.
fn as_of_point(as_of: Option<Lsn>) -> Option<Lsn> {
    match as_of {
        None => Some(u64::MAX),
        Some(0) => None,        // estado vazio (lsn < 0 não existe)
        Some(b) => Some(b - 1), // fronteira exclusiva
    }
}

// `EntityResolver` do index-graph (M11) — o mesmo que o server materializa e
// que o LogBackend agrega no bundle: uma única semântica de resolução.
pub fn resolve_of(r: &EntityResolver, key: &str, as_of: Option<Lsn>) -> Option<String> {
    r.resolve(key, as_of_point(as_of)?)
}

pub fn cluster_of(r: &EntityResolver, entity_id: &str, as_of: Option<Lsn>) -> Vec<String> {
    let Some(point) = as_of_point(as_of) else {
        return Vec::new();
    };
    r.cluster(entity_id, point)
}

pub fn neighbors_of(
    g: &TemporalGraph,
    node: &str,
    etype: Option<&str>,
    as_of: Option<Lsn>,
    min_confidence: f32,
) -> Vec<NeighborRow> {
    let Some(point) = as_of_point(as_of) else {
        return Vec::new();
    };
    let et = etype.map(EdgeType::from_attr);
    g.neighbors(&node.to_string(), et.as_ref(), point, min_confidence, 0.0)
        .into_iter()
        .map(|n| NeighborRow {
            edge_id: n.edge_id,
            to: n.to,
            etype: n.etype.key(),
            belief: n.belief,
            weight: n.weight,
            lsn: n.lsn,
        })
        .collect()
}

pub fn traverse_of(
    g: &TemporalGraph,
    start: &str,
    max_depth: usize,
    as_of: Option<Lsn>,
    min_confidence: f32,
) -> Vec<(String, usize)> {
    let Some(point) = as_of_point(as_of) else {
        return Vec::new();
    };
    g.traverse(&start.to_string(), max_depth, point, min_confidence, 0.0)
}

pub fn community_of(g: &TemporalGraph, node: &str, as_of: Option<Lsn>) -> Option<CommunityResult> {
    let point = as_of_point(as_of)?;
    let a = g.analyze(point, 0.0);
    let community = a.community.get(node)?.clone();
    let members = a.members(&community);
    Some(CommunityResult {
        node: node.to_string(),
        community,
        members,
    })
}

pub fn node_metrics_of(g: &TemporalGraph, node: &str, as_of: Option<Lsn>) -> Option<MetricsResult> {
    let point = as_of_point(as_of)?;
    let a = g.analyze(point, 0.0);
    let m = a.metrics.get(node)?;
    let community = a.community.get(node).cloned().unwrap_or_default();
    Some(MetricsResult {
        node: node.to_string(),
        community,
        degree: m.degree,
        centrality: m.centrality,
        anomaly_score: m.anomaly_score,
    })
}

pub fn hypotheses_of(
    g: &TemporalGraph,
    from: &str,
    to: &str,
    etype: &str,
    as_of: Option<Lsn>,
) -> Option<EdgeHypotheses> {
    let point = as_of_point(as_of)?;
    let et = EdgeType::from_attr(etype);
    let edge_id = TemporalGraph::edge_id(from, to, &et);
    let edge = g.edges.get(&edge_id)?;
    let alive = edge.alive_at(point);
    let belief = g.belief_at(&edge_id, point);
    let versions = g
        .hypotheses_at(&edge_id, point)
        .into_iter()
        .map(|v| HypothesisRow {
            hypothesis_id: v.hypothesis_id,
            confidence: v.confidence,
            polarity: v.polarity,
            source: v.source,
        })
        .collect();
    Some(EdgeHypotheses {
        edge_id,
        alive,
        belief,
        versions,
    })
}

pub fn match_edges_of(
    g: &TemporalGraph,
    src: Option<&str>,
    etype: Option<&str>,
    dst: Option<&str>,
    as_of: Option<Lsn>,
) -> Vec<EdgeRow> {
    let Some(point) = as_of_point(as_of) else {
        return Vec::new();
    };
    let et = etype.map(EdgeType::from_attr);
    g.match_edges(src, et.as_ref(), dst, point, 0.0)
        .into_iter()
        .map(|m| EdgeRow {
            edge_id: m.edge_id,
            from: m.from,
            to: m.to,
            etype: m.etype.key(),
            belief: m.belief,
            world_valid_from: m.world_valid_from,
            world_valid_to: m.world_valid_to,
        })
        .collect()
}

/// Comunidades por LEIDEN (V2.4) — a mesma convenção do `community_of` (id =
/// menor nó), mas com a partição de modularidade do `communities_leiden`.
pub fn community_leiden_of(
    g: &TemporalGraph,
    node: &str,
    as_of: Option<Lsn>,
) -> Option<CommunityResult> {
    let point = as_of_point(as_of)?;
    let communities = g.communities_leiden(point, 0.0);
    let community = communities.get(node)?.clone();
    let members: Vec<String> = communities
        .iter()
        .filter(|(_, c)| **c == community)
        .map(|(n, _)| n.clone())
        .collect();
    Some(CommunityResult {
        node: node.to_string(),
        community,
        members,
    })
}

/// Replay de referência (recuperado pós-M30): reconstrói o grafo temporal a
/// partir do log inteiro, em janelas para limitar RAM. O backend de referência
/// e as verificações de consistência das views (server) partilham isto — a
/// regra de derivação tem uma única fonte de verdade.
pub fn replay_graph(log: &Log) -> Result<TemporalGraph, HeraclitusError> {
    let mut g = TemporalGraph::new();
    let head = log.head();
    let mut cur: Lsn = 0;
    while cur < head {
        let batch = log.scan_capped(cur, head, 2048)?;
        let Some(&(last_lsn, _)) = batch.last() else {
            break;
        };
        for (lsn, e) in &batch {
            g.apply_episode(*lsn, e);
        }
        cur = last_lsn + 1;
    }
    Ok(g)
}

/// Reconstrói o resolver de entidades a partir do log inteiro (referência M11).
pub fn replay_resolver(log: &Log) -> Result<EntityResolver, HeraclitusError> {
    let mut r = EntityResolver::new();
    let head = log.head();
    let mut cur: Lsn = 0;
    while cur < head {
        let batch = log.scan_capped(cur, head, 2048)?;
        let Some(&(last_lsn, _)) = batch.last() else {
            break;
        };
        for (lsn, e) in &batch {
            r.apply_episode(*lsn, e);
        }
        cur = last_lsn + 1;
    }
    Ok(r)
}

// ─────────────────────────────────────────────────────────────────────────
// M16: motor contrafactual (SIMULATE) — reintroduzido pós-M30 (do git 41480b6).
// SIMULATE ADD/REMOVE EDGE (...) THEN <query> sobrepõe uma mutação de aresta
// numa CÓPIA do grafo e executa a query interna contra ela. O grafo base e o
// log nunca são tocados — a divergência fica isolada na cópia.
// ─────────────────────────────────────────────────────────────────────────

/// Materializa um grafo **virtual** = `base` com uma aresta adicionada ou
/// removida. Devolve um grafo novo; `base` (e portanto o log) fica intacto.
pub fn materialize_virtual(
    base: &TemporalGraph,
    op: SimulateOp,
    from: &str,
    to: &str,
    etype: &str,
) -> TemporalGraph {
    let et = EdgeType::from_attr(etype);
    let edge_id = TemporalGraph::edge_id(from, to, &et);
    let remove = op == SimulateOp::RemoveEdge;

    let mut g = TemporalGraph::new();
    for (id, edge) in &base.edges {
        if remove && *id == edge_id {
            continue; // a remoção contrafactual
        }
        g.upsert_edge(
            edge.clone(),
            base.versions.get(id).cloned().unwrap_or_default(),
        );
    }
    if op == SimulateOp::AddEdge {
        let version = EdgeVersion {
            hypothesis_id: edge_id.clone(),
            confidence: 1.0,
            source: "simulate".into(),
            provenance: vec![],
            polarity: et.polarity(),
            valid_from_lsn: 0,
        };
        g.upsert_edge(
            Edge {
                id: edge_id,
                from: from.to_string(),
                to: to.to_string(),
                etype: et,
                valid_from_lsn: 0,
                valid_to_lsn: None,
                world_valid_from: None,
                world_valid_to: None,
                closed_intervals: Vec::new(),
            },
            vec![version],
        );
    }
    g.watermark = base.watermark;
    g
}

/// Vista contrafactual: leituras de grafo servidas pelo overlay virtual; tudo
/// o resto (texto, vetor, entidades, o próprio log) delega no backend real.
/// `append` é no-op para que `SIMULATE ... THEN` nunca escreva no log — o
/// ponto inteiro do M16. `graph()` devolve o overlay, por isso um SIMULATE
/// aninhado compõe sobre a mutação do exterior (audit bug B) em vez de
/// reconstruir a partir do log real.
pub struct VirtualBackend<'a> {
    base: &'a dyn QueryBackend,
    graph: TemporalGraph,
}

impl<'a> VirtualBackend<'a> {
    pub fn new(base: &'a dyn QueryBackend, graph: TemporalGraph) -> Self {
        Self { base, graph }
    }
}

impl QueryBackend for VirtualBackend<'_> {
    // --- delegadas: um contrafactual de aresta não as afeta ---
    fn scan(&self, as_of: Option<Lsn>) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        self.base.scan(as_of)
    }
    fn scan_range(&self, from: Lsn, to: Lsn) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        self.base.scan_range(from, to)
    }
    fn head(&self) -> Result<Lsn, HeraclitusError> {
        self.base.head()
    }
    fn attr_lookup(
        &self,
        field: &str,
        value: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<Vec<(Lsn, Episode)>>, HeraclitusError> {
        self.base.attr_lookup(field, value, as_of)
    }
    fn recall(
        &self,
        t: &str,
        k: usize,
        a: Option<Lsn>,
    ) -> Result<Vec<(Lsn, Episode, f32)>, HeraclitusError> {
        self.base.recall(t, k, a)
    }
    fn nearest(
        &self,
        v: &[f32],
        k: usize,
        a: Option<Lsn>,
    ) -> Result<Vec<(Lsn, Episode, f32)>, HeraclitusError> {
        self.base.nearest(v, k, a)
    }
    fn provenance(&self, id: &str) -> Result<Vec<String>, HeraclitusError> {
        self.base.provenance(id)
    }
    fn lsn_for_timestamp(&self, ts: u64) -> Result<Lsn, HeraclitusError> {
        self.base.lsn_for_timestamp(ts)
    }
    fn resolve_entity(&self, key: &str, a: Option<Lsn>) -> Result<Option<String>, HeraclitusError> {
        self.base.resolve_entity(key, a)
    }
    fn entity_cluster(&self, id: &str, a: Option<Lsn>) -> Result<Vec<String>, HeraclitusError> {
        self.base.entity_cluster(id, a)
    }
    /// No-op: um contrafactual nunca escreve no log real.
    fn append(
        &self,
        _label: Option<&str>,
        _props: &[(String, Value)],
    ) -> Result<Lsn, HeraclitusError> {
        Ok(Lsn::MAX)
    }

    // --- leituras de grafo servidas pelo overlay virtual ---
    fn graph(&self) -> Result<TemporalGraph, HeraclitusError> {
        Ok(self.graph.clone())
    }
    fn neighbors(
        &self,
        node: &str,
        etype: Option<&str>,
        a: Option<Lsn>,
        mc: f32,
    ) -> Result<Vec<NeighborRow>, HeraclitusError> {
        Ok(neighbors_of(&self.graph, node, etype, a, mc))
    }
    fn traverse(
        &self,
        start: &str,
        d: usize,
        a: Option<Lsn>,
        mc: f32,
    ) -> Result<Vec<(String, usize)>, HeraclitusError> {
        Ok(traverse_of(&self.graph, start, d, a, mc))
    }
    fn match_edges(
        &self,
        src: Option<&str>,
        et: Option<&str>,
        dst: Option<&str>,
        a: Option<Lsn>,
    ) -> Result<Vec<EdgeRow>, HeraclitusError> {
        Ok(match_edges_of(&self.graph, src, et, dst, a))
    }
    fn edge_hypotheses(
        &self,
        f: &str,
        t: &str,
        et: &str,
        a: Option<Lsn>,
    ) -> Result<Option<EdgeHypotheses>, HeraclitusError> {
        Ok(hypotheses_of(&self.graph, f, t, et, a))
    }
    fn community(
        &self,
        node: &str,
        a: Option<Lsn>,
    ) -> Result<Option<CommunityResult>, HeraclitusError> {
        Ok(community_of(&self.graph, node, a))
    }
    fn community_leiden(
        &self,
        node: &str,
        a: Option<Lsn>,
    ) -> Result<Option<CommunityResult>, HeraclitusError> {
        Ok(community_leiden_of(&self.graph, node, a))
    }
    fn node_metrics(
        &self,
        node: &str,
        a: Option<Lsn>,
    ) -> Result<Option<MetricsResult>, HeraclitusError> {
        Ok(node_metrics_of(&self.graph, node, a))
    }
}
