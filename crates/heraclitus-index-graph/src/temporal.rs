// Desenvolvedor: Jose R F Junior
// web2ajax@gmail.com
// joseribamar.junior@inss.gov.br

//! temporal.rs — M8 (MVP): grafo derivado **temporal + probabilístico**.
//!
//! Módulo autocontido que embute as decisões de arquitetura:
//!   - RFC-004: agregação de crença (log-odds) entre `EdgeVersion` concorrentes;
//!   - RFC-005: `EntityMapping` probabilística e temporal;
//!   - RFC-006: `decay` temporal (peso de relevância, nunca armazenado);
//!   - RFC-007: `NodeMetrics { computed_at_lsn }` (degree exato; centrality "as of").
//!
//! Adjacency em `BTreeMap` = ordenação determinística (alimenta o `state_hash`) e O(log N).
//! Não toca nos tipos existentes do crate (não quebra dependentes).

use std::collections::{BTreeMap, BTreeSet};

pub type Lsn = u64;
pub type EntityId = String;
pub type EdgeId = String;
pub type EventId = String;
pub type HypothesisId = String;
pub type RuleId = String;

/// Tipo de relação. `NotRelated` é a hipótese **negativa** (RFC-004, sinal −1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum EdgeType {
    FraudPartner,
    SocioDe,
    Pagou,
    SimilarA,
    NotRelated,
    Custom(String),
}

impl EdgeType {
    /// Polaridade da evidência na agregação de crença (RFC-004).
    pub fn polarity(&self) -> f32 {
        match self {
            EdgeType::NotRelated => -1.0,
            _ => 1.0,
        }
    }

    /// Chave estável (entra no `edge_id` e no `state_hash` — nunca usar `Debug`,
    /// cujo formato não é contrato e pode mudar entre versões do compilador).
    pub fn key(&self) -> String {
        match self {
            EdgeType::FraudPartner => "fraud_partner".into(),
            EdgeType::SocioDe => "socio_de".into(),
            EdgeType::Pagou => "pagou".into(),
            EdgeType::SimilarA => "similar_a".into(),
            EdgeType::NotRelated => "not_related".into(),
            EdgeType::Custom(s) => format!("custom:{s}"),
        }
    }

    /// Deriva o tipo a partir do atributo `edge_type` de um episódio.
    /// Desconhecido → `Custom` (o log permanece a verdade; nada se rejeita).
    pub fn from_attr(s: &str) -> EdgeType {
        match s.to_ascii_lowercase().as_str() {
            "fraud_partner" | "fraudpartner" => EdgeType::FraudPartner,
            "socio_de" | "sociode" => EdgeType::SocioDe,
            "pagou" => EdgeType::Pagou,
            "similar_a" | "similara" => EdgeType::SimilarA,
            "not_related" | "notrelated" => EdgeType::NotRelated,
            other => EdgeType::Custom(other.to_string()),
        }
    }
}

/// Hipótese concorrente sobre uma aresta (RFC-004). É **evidência**, não veredito.
/// Múltiplas versões da mesma aresta coexistem (M12): cada uma é uma afirmação
/// independente, com a sua própria origem, confiança, polaridade e `valid_from`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EdgeVersion {
    pub hypothesis_id: HypothesisId,
    pub confidence: f32, // 0.0..=1.0
    pub source: RuleId,
    pub provenance: Vec<EventId>,
    pub polarity: f32, // +1 suporta, -1 refuta
    /// M12: LSN em que esta hipótese foi afirmada — a versão só conta em
    /// `AS OF >= valid_from_lsn` (a hipótese também viaja no tempo).
    pub valid_from_lsn: Lsn,
}

/// Aresta puramente **topológica + temporal** (M8/M9). A confiança vive nas versions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Edge {
    pub id: EdgeId,
    pub from: EntityId,
    pub to: EntityId,
    pub etype: EdgeType,
    pub valid_from_lsn: Lsn,
    pub valid_to_lsn: Option<Lsn>,
    /// Bi-temporal (V2.4): validade do FACTO no mundo real (`[from, to)`,
    /// ausente = aberto) — vem do valid time do episódio que ASSERTOU a
    /// aresta. Distinto de `valid_*_lsn` (transaction time do log).
    pub world_valid_from: Option<u64>,
    pub world_valid_to: Option<u64>,
    /// R12: intervalos de vida ANTERIORES `[from, to)`. Um re-assert de uma
    /// aresta retratada fecha um capítulo e abre outro — a história dos
    /// períodos fechados fica preservada (o `AS OF` continua a vê-los), em vez
    /// de a aresta ficar morta para sempre (comportamento antigo) ou de a
    /// história ser reescrita. Nota: mudar o layout invalida checkpoints
    /// bincode antigos do tgraph — o restore degrada para replay (correto por
    /// construção, estado derivado).
    #[serde(default)]
    pub closed_intervals: Vec<(Lsn, Lsn)>,
}

impl Edge {
    pub fn alive_at(&self, at: Lsn) -> bool {
        (self.valid_from_lsn <= at && self.valid_to_lsn.is_none_or(|to| at < to))
            || self
                .closed_intervals
                .iter()
                .any(|(from, to)| *from <= at && at < *to)
    }

    /// O facto que a aresta representa é válido NO MUNDO em `t`?
    /// (`VALID AT t` sobre arestas; sem valid time = atemporal, passa sempre.)
    pub fn world_valid_at(&self, t: u64) -> bool {
        self.world_valid_from.is_none_or(|from| from <= t)
            && self.world_valid_to.is_none_or(|to| t < to)
    }
}

/// Mapeamento evento→entidade **probabilístico e temporal** (RFC-005).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntityMapping {
    pub entity_id: EntityId,
    pub confidence: f32,
    pub source: RuleId,
    pub provenance: Vec<EventId>,
    pub valid_from_lsn: Lsn,
    pub valid_to_lsn: Option<Lsn>,
}

/// Métricas (RFC-007). `degree` é exato em qualquer `as_of`; `centrality`/`anomaly`
/// refletem o checkpoint `computed_at_lsn` (staleness explícita).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NodeMetrics {
    pub degree: u32,
    pub centrality: f32,
    pub anomaly_score: f32,
    pub computed_at_lsn: Lsn,
}

/// Política de crença (RFC-004): log-odds. Versionada para reprodutibilidade.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeliefPolicy {
    pub version: u32,
    pub eps: f32, // clamp de confidence antes do logit
}

impl Default for BeliefPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            eps: 1e-4,
        }
    }
}

impl BeliefPolicy {
    fn logit(&self, p: f32) -> f32 {
        let p = p.clamp(self.eps, 1.0 - self.eps);
        (p / (1.0 - p)).ln()
    }

    /// Agrega as versions **vivas em `as_of`** → crença efetiva em [0,1] (RFC-004).
    /// Determinístico e independente da ordem de chegada: soma comutativa,
    /// ordenada por `hypothesis_id`. Evidência negativa (`polarity = -1`) subtrai,
    /// portanto duas regras conflitantes coexistem sem quebrar a consistência —
    /// a crença simplesmente reflete o saldo das evidências.
    pub fn aggregate_as_of(&self, versions: &[EdgeVersion], as_of: Lsn) -> f32 {
        let mut vs: Vec<&EdgeVersion> = versions
            .iter()
            .filter(|v| v.valid_from_lsn <= as_of)
            .collect();
        if vs.is_empty() {
            return 0.0;
        }
        vs.sort_by(|a, b| a.hypothesis_id.cmp(&b.hypothesis_id));
        let sum: f32 = vs
            .iter()
            .map(|v| v.polarity * self.logit(v.confidence))
            .sum();
        1.0 / (1.0 + (-sum).exp()) // sigmoid
    }

    /// Agrega todas as versions (head state) — atalho para `aggregate_as_of(.., MAX)`.
    pub fn aggregate(&self, versions: &[EdgeVersion]) -> f32 {
        self.aggregate_as_of(versions, u64::MAX)
    }
}

/// Decay temporal (RFC-006): peso de relevância calculado na query, **nunca armazenado**.
pub fn decay(lambda: f32, valid_from_lsn: Lsn, at_lsn: Lsn) -> f32 {
    let dt = at_lsn.saturating_sub(valid_from_lsn) as f32;
    (-lambda * dt).exp()
}

/// Vizinho devolvido pela travessia, com crença e peso efetivo (crença × decay).
#[derive(Debug, Clone)]
pub struct Neighbor {
    pub edge_id: EdgeId,
    pub to: EntityId,
    pub etype: EdgeType,
    pub belief: f32,
    pub weight: f32,
    /// LSN em que a aresta para este vizinho passou a existir. Para arestas de
    /// proveniência é o LSN do próprio evento candidato; para arestas explícitas
    /// é quando a relação foi afirmada.
    pub lsn: Lsn,
}

/// Aresta `(a)-[r]->(b)` devolvida pelo MATCH de relação (M9), com a crença
/// agregada. Já filtrada por `alive_at(as_of)` — viaja no tempo.
#[derive(Debug, Clone)]
pub struct EdgeMatch {
    pub edge_id: EdgeId,
    pub from: EntityId,
    pub to: EntityId,
    pub etype: EdgeType,
    pub belief: f32,
    /// Valid time do mundo herdado da aresta (V2.4; `None` = aberto).
    pub world_valid_from: Option<u64>,
    pub world_valid_to: Option<u64>,
}

/// Resultado das métricas de grafo (M14). Tudo é função pura do estado do grafo
/// (determinístico) ⇒ **estável entre replays**. `community` mapeia nó → id da
/// comunidade (o menor nó da componente conexa); `metrics` traz grau,
/// centralidade e anomaly por nó.
#[derive(Debug, Clone, Default)]
pub struct GraphAnalytics {
    pub community: BTreeMap<EntityId, EntityId>,
    pub metrics: BTreeMap<EntityId, NodeMetrics>,
}

impl GraphAnalytics {
    /// Membros (ordenados) da comunidade de `node`.
    pub fn members(&self, community: &str) -> Vec<EntityId> {
        self.community
            .iter()
            .filter(|(_, c)| c.as_str() == community)
            .map(|(n, _)| n.clone())
            .collect()
    }
}

/// Índice de grafo temporal (M8). View materializada, determinística, reconstruível.
#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct TemporalGraph {
    pub out: BTreeMap<EntityId, BTreeMap<EdgeType, Vec<EdgeId>>>,
    pub inn: BTreeMap<EntityId, BTreeMap<EdgeType, Vec<EdgeId>>>,
    pub edges: BTreeMap<EdgeId, Edge>,
    pub versions: BTreeMap<EdgeId, Vec<EdgeVersion>>,
    pub entity_map: BTreeMap<EventId, Vec<EntityMapping>>,
    pub metrics: BTreeMap<EntityId, NodeMetrics>,
    pub policy: BeliefPolicy,
    pub built_until_lsn: Lsn,
    /// Maior LSN já aplicado (watermark da View — distinto de `built_until_lsn`,
    /// que só avança quando o evento gera aresta; um evento sem `parents` move
    /// o watermark mas não cria aresta).
    pub watermark: Lsn,
}

impl TemporalGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert_edge(&mut self, edge: Edge, versions: Vec<EdgeVersion>) {
        // M12: várias hipóteses sobre a MESMA aresta coexistem. As versions
        // acumulam-se (não são substituídas), com dedup por `hypothesis_id` —
        // re-aplicar o mesmo evento no replay é no-op (idempotente) e a ordem de
        // armazenamento é determinística (ordenada por `hypothesis_id`), logo o
        // `state_hash` não depende da ordem de chegada.
        let entry = self.versions.entry(edge.id.clone()).or_default();
        for v in versions {
            if !entry.iter().any(|e| e.hypothesis_id == v.hypothesis_id) {
                entry.push(v);
            }
        }
        entry.sort_by(|a, b| a.hypothesis_id.cmp(&b.hypothesis_id));

        // A topologia (adjacência + Edge) regista-se uma única vez; o `edge_id`
        // é determinístico (from→to#etype), logo estável entre replays.
        // R12: um assert sobre uma aresta FECHADA reabre-a num novo intervalo,
        // arquivando o anterior em `closed_intervals` — antes era no-op
        // silencioso e a relação ficava morta para sempre. Idempotente: um
        // assert sobre aresta ABERTA continua a ser no-op topológico.
        if let Some(existing) = self.edges.get_mut(&edge.id) {
            if let Some(closed_at) = existing.valid_to_lsn {
                existing
                    .closed_intervals
                    .push((existing.valid_from_lsn, closed_at));
                existing.valid_from_lsn = edge.valid_from_lsn;
                existing.valid_to_lsn = None;
                existing.world_valid_from = edge.world_valid_from;
                existing.world_valid_to = edge.world_valid_to;
                self.built_until_lsn = self.built_until_lsn.max(edge.valid_from_lsn);
            }
            return;
        }
        self.out
            .entry(edge.from.clone())
            .or_default()
            .entry(edge.etype.clone())
            .or_default()
            .push(edge.id.clone());
        self.inn
            .entry(edge.to.clone())
            .or_default()
            .entry(edge.etype.clone())
            .or_default()
            .push(edge.id.clone());
        self.built_until_lsn = self.built_until_lsn.max(edge.valid_from_lsn);
        self.edges.insert(edge.id.clone(), edge);
    }

    /// Crença efetiva da aresta (RFC-004) considerando as hipóteses vivas em
    /// `as_of` (M12: a hipótese também viaja no tempo).
    pub fn belief_at(&self, edge_id: &EdgeId, as_of: Lsn) -> f32 {
        self.versions
            .get(edge_id)
            .map_or(0.0, |vs| self.policy.aggregate_as_of(vs, as_of))
    }

    /// Crença efetiva (head state) — atalho para `belief_at(.., MAX)`.
    pub fn belief(&self, edge_id: &EdgeId) -> f32 {
        self.belief_at(edge_id, u64::MAX)
    }

    /// Hipóteses vivas em `as_of` de uma aresta (M12), ordenadas por
    /// `hypothesis_id`. Vazio se a aresta não existe.
    pub fn hypotheses_at(&self, edge_id: &EdgeId, as_of: Lsn) -> Vec<EdgeVersion> {
        self.versions
            .get(edge_id)
            .map(|vs| {
                vs.iter()
                    .filter(|v| v.valid_from_lsn <= as_of)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// NEIGHBORS(node, type?, as_of, min_confidence) com decay (RFC-006).
    pub fn neighbors(
        &self,
        node: &EntityId,
        etype: Option<&EdgeType>,
        as_of: Lsn,
        min_confidence: f32,
        lambda: f32,
    ) -> Vec<Neighbor> {
        let mut out = Vec::new();
        if let Some(types) = self.out.get(node) {
            for (t, eids) in types {
                if let Some(want) = etype {
                    if want != t {
                        continue;
                    }
                }
                for eid in eids {
                    let edge = match self.edges.get(eid) {
                        Some(e) => e,
                        None => continue,
                    };
                    if !edge.alive_at(as_of) {
                        continue;
                    }
                    let belief = self.belief_at(eid, as_of);
                    if belief < min_confidence {
                        continue;
                    }
                    out.push(Neighbor {
                        edge_id: eid.clone(),
                        to: edge.to.clone(),
                        etype: t.clone(),
                        belief,
                        weight: belief * decay(lambda, edge.valid_from_lsn, as_of),
                        lsn: edge.valid_from_lsn,
                    });
                }
            }
        }
        out
    }

    /// TRAVERSE(start, max_depth, as_of, min_confidence) — BFS determinístico.
    /// Devolve (entidade, profundidade) na ordem de descoberta.
    pub fn traverse(
        &self,
        start: &EntityId,
        max_depth: usize,
        as_of: Lsn,
        min_confidence: f32,
        lambda: f32,
    ) -> Vec<(EntityId, usize)> {
        let mut seen: BTreeSet<EntityId> = BTreeSet::new();
        let mut result = Vec::new();
        let mut frontier = vec![start.clone()];
        seen.insert(start.clone());
        for depth in 1..=max_depth {
            let mut next = Vec::new();
            for node in &frontier {
                for nb in self.neighbors(node, None, as_of, min_confidence, lambda) {
                    if seen.insert(nb.to.clone()) {
                        result.push((nb.to.clone(), depth));
                        next.push(nb.to);
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            next.sort();
            frontier = next;
        }
        result
    }

    /// MATCH `(a)-[r:etype?]->(b) AS OF X` (M9): enumera arestas vivas em `as_of`
    /// que casam com os filtros opcionais de origem/tipo/destino. Ordem
    /// determinística: por `from` então por `etype` (iteração de `BTreeMap`), ou
    /// por `edge_id` quando varre o grafo inteiro. Corre por `min_confidence`.
    pub fn match_edges(
        &self,
        src: Option<&str>,
        etype: Option<&EdgeType>,
        dst: Option<&str>,
        as_of: Lsn,
        min_confidence: f32,
    ) -> Vec<EdgeMatch> {
        let mut out = Vec::new();
        let mut consider = |edge: &Edge| {
            if !edge.alive_at(as_of) {
                return;
            }
            if let Some(want) = etype {
                if *want != edge.etype {
                    return;
                }
            }
            if let Some(d) = dst {
                if edge.to != d {
                    return;
                }
            }
            let belief = self.belief_at(&edge.id, as_of);
            if belief < min_confidence {
                return;
            }
            out.push(EdgeMatch {
                edge_id: edge.id.clone(),
                from: edge.from.clone(),
                to: edge.to.clone(),
                etype: edge.etype.clone(),
                belief,
                world_valid_from: edge.world_valid_from,
                world_valid_to: edge.world_valid_to,
            });
        };
        match src {
            // Origem fixa: percorre só a adjacência de saída desse nó (rápido).
            Some(s) => {
                if let Some(types) = self.out.get(s) {
                    for eids in types.values() {
                        for eid in eids {
                            if let Some(edge) = self.edges.get(eid) {
                                consider(edge);
                            }
                        }
                    }
                }
            }
            // Sem origem: varre todas as arestas (ordenadas por edge_id).
            None => {
                for edge in self.edges.values() {
                    consider(edge);
                }
            }
        }
        out
    }

    /// degree exato em qualquer `as_of` (RFC-007) — conta arestas vivas (out+in).
    pub fn degree_at(&self, node: &EntityId, as_of: Lsn) -> u32 {
        let count = |m: &BTreeMap<EntityId, BTreeMap<EdgeType, Vec<EdgeId>>>| -> u32 {
            m.get(node).map_or(0, |types| {
                types
                    .values()
                    .flatten()
                    .filter(|eid| self.edges.get(*eid).is_some_and(|e| e.alive_at(as_of)))
                    .count() as u32
            })
        };
        count(&self.out) + count(&self.inn)
    }

    /// Métricas de grafo (M14): comunidades, centralidade e anomaly score sobre
    /// as arestas **vivas em `as_of`** com crença `>= min_confidence`.
    ///
    /// Determinístico em tudo (⇒ estável entre replays):
    ///   - **comunidades**: componentes conexas (não-direcionadas). O id da
    ///     comunidade é o **menor nó** da componente — iteramos os nós ordenados,
    ///     logo a primeira semente não rotulada de uma componente é o seu mínimo.
    ///   - **centralidade**: grau normalizado `degree / (n-1)`.
    ///   - **anomaly_score**: z-score do grau `(deg - média) / desvio` — um "hub"
    ///     com grau muito acima da média (laranja que liga muita gente) destaca-se.
    pub fn analyze(&self, as_of: Lsn, min_confidence: f32) -> GraphAnalytics {
        // Arestas vivas + confiáveis, em ordem determinística (por edge_id).
        let alive: Vec<&Edge> = self
            .edges
            .values()
            .filter(|e| e.alive_at(as_of) && self.belief_at(&e.id, as_of) >= min_confidence)
            .collect();

        // Conjunto de nós (ordenado) e adjacência não-direcionada.
        let mut nodes: BTreeSet<EntityId> = BTreeSet::new();
        let mut adj: BTreeMap<EntityId, BTreeSet<EntityId>> = BTreeMap::new();
        let mut degree: BTreeMap<EntityId, u32> = BTreeMap::new();
        for e in &alive {
            nodes.insert(e.from.clone());
            nodes.insert(e.to.clone());
            adj.entry(e.from.clone()).or_default().insert(e.to.clone());
            adj.entry(e.to.clone()).or_default().insert(e.from.clone());
            *degree.entry(e.from.clone()).or_default() += 1;
            *degree.entry(e.to.clone()).or_default() += 1;
        }

        // Componentes conexas → comunidades (id = menor nó da componente).
        let mut community: BTreeMap<EntityId, EntityId> = BTreeMap::new();
        for seed in &nodes {
            if community.contains_key(seed) {
                continue;
            }
            let mut stack = vec![seed.clone()];
            community.insert(seed.clone(), seed.clone());
            while let Some(n) = stack.pop() {
                if let Some(neigh) = adj.get(&n) {
                    for m in neigh {
                        if !community.contains_key(m) {
                            community.insert(m.clone(), seed.clone());
                            stack.push(m.clone());
                        }
                    }
                }
            }
        }

        // Centralidade e anomaly (z-score do grau) sobre o conjunto de nós.
        let n = nodes.len();
        let degs: Vec<f32> = nodes
            .iter()
            .map(|node| *degree.get(node).unwrap_or(&0) as f32)
            .collect();
        let mean = if n > 0 {
            degs.iter().sum::<f32>() / n as f32
        } else {
            0.0
        };
        let var = if n > 0 {
            degs.iter().map(|d| (d - mean) * (d - mean)).sum::<f32>() / n as f32
        } else {
            0.0
        };
        let std = var.sqrt();

        let mut metrics: BTreeMap<EntityId, NodeMetrics> = BTreeMap::new();
        for node in &nodes {
            let deg = *degree.get(node).unwrap_or(&0);
            let centrality = if n > 1 {
                deg as f32 / (n as f32 - 1.0)
            } else {
                0.0
            };
            let anomaly_score = if std > 0.0 {
                (deg as f32 - mean) / std
            } else {
                0.0
            };
            metrics.insert(
                node.clone(),
                NodeMetrics {
                    degree: deg,
                    centrality,
                    anomaly_score,
                    computed_at_lsn: as_of,
                },
            );
        }

        GraphAnalytics { community, metrics }
    }

    /// Comunidades por LEIDEN (C2.3, qualidade de modularidade) sobre as
    /// arestas vivas em `as_of` — upgrade opcional às componentes conexas do
    /// [`analyze`](Self::analyze): separa sub-comunidades densas dentro de uma
    /// mesma componente (anéis de fraude ligados por uma ponte fraca).
    ///
    /// Determinístico (§3.5): seed fixa no leiden-rs (que tem testes próprios
    /// de reprodutibilidade por seed), nós ordenados (BTreeSet) e pesos =
    /// crença agregada. Convenção de saída IGUAL ao `analyze`: nó → id da
    /// comunidade, com id = menor nó da comunidade. Em erro interno do Leiden,
    /// degrada para as componentes conexas — nunca pior que o baseline.
    pub fn communities_leiden(
        &self,
        as_of: Lsn,
        min_confidence: f32,
    ) -> BTreeMap<EntityId, EntityId> {
        // Arestas vivas com peso = crença; pares duplicados agregam pesos.
        let mut nodes: BTreeSet<EntityId> = BTreeSet::new();
        let mut weights: BTreeMap<(EntityId, EntityId), f64> = BTreeMap::new();
        for e in self.edges.values() {
            if !e.alive_at(as_of) {
                continue;
            }
            let belief = self.belief_at(&e.id, as_of);
            if belief < min_confidence || e.from == e.to {
                continue;
            }
            nodes.insert(e.from.clone());
            nodes.insert(e.to.clone());
            let key = if e.from <= e.to {
                (e.from.clone(), e.to.clone())
            } else {
                (e.to.clone(), e.from.clone())
            };
            *weights.entry(key).or_insert(0.0) += f64::from(belief.max(1e-6));
        }
        if nodes.is_empty() {
            return BTreeMap::new();
        }

        let by_index: Vec<&EntityId> = nodes.iter().collect();
        let index: BTreeMap<&EntityId, usize> =
            by_index.iter().enumerate().map(|(i, n)| (*n, i)).collect();

        let run = || -> Option<Vec<(usize, Vec<usize>)>> {
            let mut b = leiden_rs::GraphDataBuilder::new(by_index.len());
            for ((f, t), w) in &weights {
                b.add_edge(index[f], index[t], *w).ok()?;
            }
            let graph = b.build().ok()?;
            let config = leiden_rs::LeidenConfig::builder().seed(0x4852_4B4C).build();
            let out = leiden_rs::Leiden::new(config).run(&graph).ok()?;
            Some(out.partition.communities())
        };

        match run() {
            Some(communities) => {
                let mut result = BTreeMap::new();
                for (_cid, members) in communities {
                    let mut names: Vec<&EntityId> = members.iter().map(|&i| by_index[i]).collect();
                    names.sort();
                    let Some(&community_id) = names.first() else {
                        continue;
                    };
                    for n in names {
                        result.insert(n.clone(), community_id.clone());
                    }
                }
                result
            }
            // Fallback honesto: componentes conexas (o baseline do analyze).
            None => self.analyze(as_of, min_confidence).community,
        }
    }

    /// `edge_id` determinístico de uma aresta `from -[etype]-> to`. Estável entre
    /// replays e plataformas (alimenta o `state_hash`).
    pub fn edge_id(from: &str, to: &str, etype: &EdgeType) -> EdgeId {
        format!("{from}->{to}#{}", etype.key())
    }

    /// Fecha a aresta (M9: mutação temporal). Define `valid_to_lsn` se ainda
    /// estiver aberta — a aresta deixa de estar viva a partir de `at` (intervalo
    /// semi-aberto `[valid_from, valid_to)`). **Nada é destruído**: a aresta
    /// continua no log e visível em qualquer `AS OF` anterior ao fecho.
    /// Idempotente: re-fechar uma aresta já fechada é no-op (replay determinístico).
    pub fn close_edge(&mut self, edge_id: &str, at: Lsn) {
        if let Some(e) = self.edges.get_mut(edge_id) {
            if e.valid_to_lsn.is_none() {
                e.valid_to_lsn = Some(at);
            }
        }
    }

    /// Deriva arestas de **um** evento do log. O grafo é 100% derivado do log.
    ///
    /// Dois caminhos de derivação, ambos determinísticos em `(lsn, evento)`:
    ///
    /// 1. **Proveniência (M8):** cada `parent -> evento` em `Episode.parents` vira
    ///    uma aresta (sempre aberta). É como o `distill` materializa conhecimento:
    ///    `FactDerived` com `parents = provenance`.
    /// 2. **Aresta explícita (M9):** se `attrs["edge_from"]` e `attrs["edge_to"]`
    ///    existem, o evento declara/mutaciona uma aresta entre **entidades nomeadas**
    ///    (não eventos). `attrs["edge_op"]`: `assert` (default) cria a aresta a
    ///    partir de `lsn`; `retract`/`close` fecha-a em `lsn` (`valid_to_lsn`).
    ///    É isto que dá ao grafo "viagem no tempo" real (valid_from/valid_to).
    ///
    /// Comum: `edge_type` (default `Custom("provenance")`), `confidence` (default
    /// 1.0), `rule` (origem da evidência).
    ///
    /// M12: uma aresta explícita pode carregar uma **hipótese** concorrente —
    /// `attrs["hypothesis"]` (id, default = `rule`), `attrs["stance"]`
    /// (`support` default, ou `refute`/`against` → polaridade −1). Várias regras
    /// sobre o mesmo `(from,to,type)` acumulam versions e a crença agrega-as.
    pub fn apply_episode(&mut self, lsn: Lsn, e: &heraclitus_core::Episode) {
        let etype = e
            .attrs
            .get("edge_type")
            .map(|s| EdgeType::from_attr(s))
            .unwrap_or_else(|| EdgeType::Custom("provenance".into()));
        let confidence = e
            .attrs
            .get("confidence")
            .and_then(|s| s.parse::<f32>().ok())
            .unwrap_or(1.0);
        let source: RuleId = e
            .attrs
            .get("rule")
            .cloned()
            .unwrap_or_else(|| "provenance".into());

        match (e.attrs.get("edge_from"), e.attrs.get("edge_to")) {
            // M9/M12: aresta explícita entre entidades nomeadas (assert/retract +
            // hipóteses concorrentes).
            (Some(from), Some(to)) => {
                let edge_id = Self::edge_id(from, to, &etype);
                let op = e
                    .attrs
                    .get("edge_op")
                    .map(|s| s.as_str())
                    .unwrap_or("assert");
                if op.eq_ignore_ascii_case("retract") || op.eq_ignore_ascii_case("close") {
                    self.close_edge(&edge_id, lsn);
                } else {
                    // M12: id da hipótese e polaridade (stance). Sem hypothesis/rule
                    // explícitos, cada origem distinta é uma hipótese distinta.
                    let hypothesis_id = e
                        .attrs
                        .get("hypothesis")
                        .or_else(|| e.attrs.get("rule"))
                        .cloned()
                        .unwrap_or_else(|| edge_id.clone());
                    let stance = e
                        .attrs
                        .get("stance")
                        .map(|s| s.as_str())
                        .unwrap_or("support");
                    let polarity = if stance.eq_ignore_ascii_case("refute")
                        || stance.eq_ignore_ascii_case("against")
                    {
                        -1.0
                    } else {
                        1.0
                    };
                    let version = EdgeVersion {
                        hypothesis_id,
                        confidence,
                        source,
                        provenance: vec![e.id.to_string()],
                        polarity,
                        valid_from_lsn: lsn,
                    };
                    // Valid time do mundo: campos nativos (FORMAT v4) primeiro,
                    // attrs como fallback de compatibilidade.
                    let wnum = |k: &str| e.attrs.get(k).and_then(|v| v.trim().parse::<u64>().ok());
                    self.upsert_edge(
                        Edge {
                            id: edge_id,
                            from: from.clone(),
                            to: to.clone(),
                            etype,
                            valid_from_lsn: lsn,
                            valid_to_lsn: None,
                            world_valid_from: e.valid_from.or_else(|| wnum("valid_from")),
                            world_valid_to: e.valid_to.or_else(|| wnum("valid_to")),
                            closed_intervals: Vec::new(),
                        },
                        vec![version],
                    );
                }
            }
            // M8: proveniência — cada parent vira uma aresta aberta.
            _ => {
                let child: EntityId = e.id.to_string();
                for p in &e.parents {
                    let from: EntityId = p.to_string();
                    let edge_id = Self::edge_id(&from, &child, &etype);
                    let version = EdgeVersion {
                        hypothesis_id: edge_id.clone(),
                        confidence,
                        source: source.clone(),
                        provenance: vec![child.clone()],
                        polarity: etype.polarity(),
                        valid_from_lsn: lsn,
                    };
                    self.upsert_edge(
                        Edge {
                            id: edge_id,
                            from,
                            to: child.clone(),
                            etype: etype.clone(),
                            valid_from_lsn: lsn,
                            valid_to_lsn: None,
                            world_valid_from: e.valid_from,
                            world_valid_to: e.valid_to,
                            closed_intervals: Vec::new(),
                        },
                        vec![version],
                    );
                }
            }
        }
        self.watermark = self.watermark.max(lsn);
    }

    /// Hash criptográfico determinístico do estado do grafo (blake3).
    ///
    /// É o **contrato de determinismo** do M8: dois replays do mesmo log têm de
    /// produzir bytes idênticos. Itera `BTreeMap`s (já ordenados) e serializa
    /// campos em little-endian — independente de plataforma e de ordem de
    /// inserção. Não usa `Debug` (formato não-contratual) — usa `etype.key()`.
    pub fn state_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for (id, e) in &self.edges {
            h.update(id.as_bytes());
            h.update(e.from.as_bytes());
            h.update(e.to.as_bytes());
            h.update(e.etype.key().as_bytes());
            h.update(&e.valid_from_lsn.to_le_bytes());
            h.update(&e.valid_to_lsn.unwrap_or(u64::MAX).to_le_bytes());
            // R12: os intervalos fechados fazem parte do estado determinístico.
            for (from, to) in &e.closed_intervals {
                h.update(&from.to_le_bytes());
                h.update(&to.to_le_bytes());
            }
        }
        for (id, vs) in &self.versions {
            h.update(id.as_bytes());
            for v in vs {
                h.update(v.hypothesis_id.as_bytes());
                h.update(&v.confidence.to_le_bytes());
                h.update(v.source.as_bytes());
                h.update(&v.polarity.to_le_bytes());
                h.update(&v.valid_from_lsn.to_le_bytes());
                for prov in &v.provenance {
                    h.update(prov.as_bytes());
                }
            }
        }
        *h.finalize().as_bytes()
    }
}

/// A View materializada: o grafo temporal é derivado do log por replay
/// determinístico, exatamente como qualquer outro índice (§3.5).
impl heraclitus_views::View for TemporalGraph {
    fn name(&self) -> &str {
        "tgraph"
    }

    fn apply(&mut self, lsn: heraclitus_core::Lsn, event: &heraclitus_core::Episode) {
        self.apply_episode(lsn, event);
    }

    fn watermark(&self) -> heraclitus_core::Lsn {
        self.watermark
    }

    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), heraclitus_core::HeraclitusError> {
        heraclitus_views::ckpt::save(dir, "tgraph", self)
    }

    fn restore(&mut self, dir: &std::path::Path) -> Result<bool, heraclitus_core::HeraclitusError> {
        match heraclitus_views::ckpt::load::<TemporalGraph>(dir, "tgraph")? {
            Some(g) => {
                *self = g;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn reset(&mut self) {
        *self = TemporalGraph::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ver(hyp: &str, conf: f32, etype: &EdgeType) -> EdgeVersion {
        EdgeVersion {
            hypothesis_id: hyp.into(),
            confidence: conf,
            source: "rule".into(),
            provenance: vec![],
            polarity: etype.polarity(),
            valid_from_lsn: 0,
        }
    }

    fn edge(id: &str, from: &str, to: &str, etype: EdgeType, vf: Lsn) -> Edge {
        Edge {
            id: id.into(),
            from: from.into(),
            to: to.into(),
            etype,
            valid_from_lsn: vf,
            valid_to_lsn: None,
            world_valid_from: None,
            world_valid_to: None,
            closed_intervals: Vec::new(),
        }
    }

    #[test]
    fn belief_subtrai_evidencia_negativa() {
        // RFC-004: FRAUD_PARTNER 0.8 + NOT_RELATED 0.6 -> crença abaixo de 0.8.
        let p = BeliefPolicy::default();
        let only_pos = p.aggregate(&[ver("h1", 0.8, &EdgeType::FraudPartner)]);
        let with_neg = p.aggregate(&[
            ver("h1", 0.8, &EdgeType::FraudPartner),
            ver("h2", 0.6, &EdgeType::NotRelated),
        ]);
        assert!(
            with_neg < only_pos,
            "evidência negativa deve reduzir a crença"
        );
        assert!((0.0..=1.0).contains(&with_neg));
    }

    #[test]
    fn belief_independente_de_ordem() {
        let p = BeliefPolicy::default();
        let a = p.aggregate(&[
            ver("a", 0.7, &EdgeType::FraudPartner),
            ver("b", 0.6, &EdgeType::SimilarA),
        ]);
        let b = p.aggregate(&[
            ver("b", 0.6, &EdgeType::SimilarA),
            ver("a", 0.7, &EdgeType::FraudPartner),
        ]);
        assert!(
            (a - b).abs() < 1e-6,
            "agregação deve ser determinística/independente de ordem"
        );
    }

    #[test]
    fn leiden_separa_sub_comunidades_que_componentes_conexas_fundem() {
        // C2.3: duas cliques densas ligadas por UMA ponte fraca. Componentes
        // conexas veem 1 comunidade; Leiden (modularidade) separa as duas.
        let mut g = TemporalGraph::new();
        let mut add = |id: &str, from: &str, to: &str, conf: f32| {
            g.upsert_edge(
                edge(id, from, to, EdgeType::SocioDe, 0),
                vec![ver(id, conf, &EdgeType::SocioDe)],
            );
        };
        // Clique A (A1..A4, todas as arestas, crença alta)
        let a = ["A1", "A2", "A3", "A4"];
        for i in 0..a.len() {
            for j in (i + 1)..a.len() {
                add(&format!("a{i}{j}"), a[i], a[j], 0.95);
            }
        }
        // Clique B (B1..B4)
        let b = ["B1", "B2", "B3", "B4"];
        for i in 0..b.len() {
            for j in (i + 1)..b.len() {
                add(&format!("b{i}{j}"), b[i], b[j], 0.95);
            }
        }
        // Ponte fraca única A1—B1
        add("ponte", "A1", "B1", 0.2);

        // Baseline: componentes conexas fundem tudo numa comunidade só.
        let cc = g.analyze(100, 0.0).community;
        assert_eq!(
            cc.get("A2"),
            cc.get("B2"),
            "componentes conexas: 1 comunidade"
        );

        // Leiden separa as cliques apesar da ponte.
        let leiden = g.communities_leiden(100, 0.0);
        assert_eq!(leiden.len(), 8, "todos os nós classificados");
        assert_eq!(leiden.get("A1"), leiden.get("A4"), "clique A junta");
        assert_eq!(leiden.get("B1"), leiden.get("B4"), "clique B junta");
        assert_ne!(
            leiden.get("A2"),
            leiden.get("B2"),
            "cliques separadas pela modularidade"
        );

        // Determinismo (§3.5): mesma entrada, mesma partição — sempre.
        let again = g.communities_leiden(100, 0.0);
        assert_eq!(leiden, again, "seed fixa ⇒ partição reproduzível");

        // AS OF respeitado: em LSN anterior às arestas, não há comunidades.
        // (arestas com valid_from 0 ⇒ usa um grafo novo com arestas futuras)
        let mut g2 = TemporalGraph::new();
        g2.upsert_edge(
            edge("late", "X", "Y", EdgeType::SocioDe, 50),
            vec![EdgeVersion {
                valid_from_lsn: 50,
                ..ver("late", 0.9, &EdgeType::SocioDe)
            }],
        );
        assert!(g2.communities_leiden(10, 0.0).is_empty());
        assert_eq!(g2.communities_leiden(50, 0.0).len(), 2);
    }

    #[test]
    fn as_of_esconde_arestas_futuras() {
        let mut g = TemporalGraph::new();
        g.upsert_edge(
            edge("e1", "Alfa", "Maria", EdgeType::SocioDe, 10),
            vec![ver("h", 0.9, &EdgeType::SocioDe)],
        );
        // no LSN 5 a aresta (criada no 10) não existe; no 10 existe.
        assert_eq!(g.neighbors(&"Alfa".into(), None, 5, 0.0, 0.0).len(), 0);
        assert_eq!(g.neighbors(&"Alfa".into(), None, 10, 0.0, 0.0).len(), 1);
    }

    #[test]
    fn decay_reduz_peso_sem_apagar() {
        // RFC-006: aresta antiga pesa menos, mas continua viva (belief intacto).
        let mut g = TemporalGraph::new();
        g.upsert_edge(
            edge("e1", "A", "B", EdgeType::Pagou, 0),
            vec![ver("h", 0.9, &EdgeType::Pagou)],
        );
        let nb = g.neighbors(&"A".into(), None, 1000, 0.0, 0.001);
        assert_eq!(nb.len(), 1);
        assert!(nb[0].weight < nb[0].belief, "decay deve reduzir o peso");
        assert!(nb[0].belief > 0.8, "a crença não é apagada pelo decay");
    }

    #[test]
    fn traverse_e_degree_temporais() {
        // Cadeia de fraude: INSIGHT -> troca -> Alfa ; laranja partilhado liga casos.
        let mut g = TemporalGraph::new();
        let v = |c: f32| vec![ver("h", c, &EdgeType::FraudPartner)];
        g.upsert_edge(
            edge("e1", "INSIGHT", "troca", EdgeType::FraudPartner, 1),
            v(0.9),
        );
        g.upsert_edge(
            edge("e2", "troca", "Alfa", EdgeType::FraudPartner, 2),
            v(0.9),
        );
        g.upsert_edge(
            edge("e3", "troca", "Maria", EdgeType::FraudPartner, 3),
            v(0.9),
        );
        let reach = g.traverse(&"INSIGHT".into(), 3, 100, 0.5, 0.0);
        let names: BTreeSet<&str> = reach.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains("troca") && names.contains("Alfa") && names.contains("Maria"));
        assert_eq!(g.degree_at(&"troca".into(), 100), 3); // 1 in + 2 out
        assert_eq!(g.degree_at(&"troca".into(), 2), 2); // no LSN 2: e1(in)+e2(out); e3 ainda não
    }

    use heraclitus_core::{Episode, EventKind};
    use heraclitus_views::View;

    /// Constrói uma pequena cadeia de proveniência no log (em memória): a←b←c,
    /// e um FactDerived distilado de {a,b}.
    fn chain() -> Vec<(Lsn, Episode)> {
        let mut a = Episode::new("ag", EventKind::Observation, b"a".to_vec());
        a.attrs.insert("edge_type".into(), "socio_de".into());
        let mut b = Episode::new("ag", EventKind::Observation, b"b".to_vec());
        b.attrs.insert("edge_type".into(), "pagou".into());
        b.parents.push(a.id);
        let mut c = Episode::new("ag", EventKind::Observation, b"c".to_vec());
        c.parents.push(b.id);
        let mut f = Episode::new("distill", EventKind::FactDerived, b"f".to_vec());
        f.attrs.insert("edge_type".into(), "similar_a".into());
        f.parents.push(a.id);
        f.parents.push(b.id);
        vec![(0, a), (1, b), (2, c), (3, f)]
    }

    #[test]
    fn arestas_derivadas_do_log() {
        // M8: o grafo é 100% derivado de Episode.parents (proveniência/distill).
        let events = chain();
        let mut g = TemporalGraph::new();
        for (lsn, e) in &events {
            g.apply_episode(*lsn, e);
        }
        // 1 (b←a) + 1 (c←b) + 2 (f←a, f←b) = 4 arestas.
        assert_eq!(g.edges.len(), 4);
        // 'a' tem como vizinhos de saída 'b' e 'f' (quem o referenciou).
        let a = events[0].1.id.to_string();
        let outs: BTreeSet<EntityId> = g
            .neighbors(&a, None, u64::MAX, 0.0, 0.0)
            .into_iter()
            .map(|n| n.to)
            .collect();
        assert_eq!(outs.len(), 2);
    }

    #[test]
    fn replay_reconstroi_grafo_identico_bit_a_bit() {
        // GATE M8: dois replays do mesmo log ⇒ state_hash idêntico.
        let events = chain();

        let mut g1 = TemporalGraph::new();
        for (lsn, e) in &events {
            g1.apply(*lsn, e);
        }
        let h1 = g1.state_hash();

        // Replay do zero (reset + reaplicar) tem de bater bit-a-bit.
        g1.reset();
        for (lsn, e) in &events {
            g1.apply(*lsn, e);
        }
        assert_eq!(h1, g1.state_hash(), "replay deve ser determinístico");

        // E uma segunda instância construída independentemente também.
        let mut g2 = TemporalGraph::new();
        for (lsn, e) in &events {
            g2.apply(*lsn, e);
        }
        assert_eq!(
            h1,
            g2.state_hash(),
            "grafo idêntico em instâncias separadas"
        );
    }

    #[test]
    fn replay_idempotente_nao_duplica() {
        // Reaplicar o mesmo evento (tail + catch_up sobrepostos) é no-op.
        let events = chain();
        let mut g = TemporalGraph::new();
        for (lsn, e) in &events {
            g.apply(*lsn, e);
        }
        let h = g.state_hash();
        let n = g.edges.len();
        for (lsn, e) in &events {
            g.apply(*lsn, e); // segunda passagem
        }
        assert_eq!(g.edges.len(), n, "não pode duplicar arestas");
        assert_eq!(h, g.state_hash(), "estado inalterado após re-aplicar");
    }

    // ---- M9: arestas temporais (AS OF nas arestas + mutação valid_from/to) ----

    /// Episódio que **declara** uma aresta explícita entre entidades nomeadas.
    fn edge_ep(from: &str, to: &str, etype: &str, op: &str) -> Episode {
        let mut e = Episode::new("ag", EventKind::Observation, vec![]);
        e.attrs.insert("edge_from".into(), from.into());
        e.attrs.insert("edge_to".into(), to.into());
        e.attrs.insert("edge_type".into(), etype.into());
        e.attrs.insert("edge_op".into(), op.into());
        e
    }

    /// Log de mutação: Alfa—sócio—Maria nasce no LSN 1 e é retratada no LSN 5;
    /// Alfa—paga—Beto nasce no LSN 3 e fica aberta.
    fn mutation_log() -> Vec<(Lsn, Episode)> {
        vec![
            (1, edge_ep("Alfa", "Maria", "socio_de", "assert")),
            (3, edge_ep("Alfa", "Beto", "pagou", "assert")),
            (5, edge_ep("Alfa", "Maria", "socio_de", "retract")),
        ]
    }

    fn alive_ids(g: &TemporalGraph, as_of: Lsn) -> BTreeSet<EdgeId> {
        g.match_edges(None, None, None, as_of, 0.0)
            .into_iter()
            .map(|m| m.edge_id)
            .collect()
    }

    #[test]
    fn retract_fecha_aresta_sem_destruir() {
        // M9: a aresta vive em [valid_from, valid_to). Antes do retract está viva,
        // depois não — mas continua visível em qualquer AS OF anterior ao fecho.
        let mut g = TemporalGraph::new();
        for (lsn, e) in mutation_log() {
            g.apply_episode(lsn, &e);
        }
        let socio = TemporalGraph::edge_id("Alfa", "Maria", &EdgeType::SocioDe);

        // No LSN 1..4 a aresta sócio existe; em 5 (retract) já não.
        assert!(
            alive_ids(&g, 1).contains(&socio),
            "viva no nascimento (LSN 1)"
        );
        assert!(alive_ids(&g, 4).contains(&socio), "viva antes do retract");
        assert!(
            !alive_ids(&g, 5).contains(&socio),
            "morta a partir do retract"
        );
        // Nada destruído: a aresta permanece no grafo (com valid_to definido).
        assert!(g.edges.contains_key(&socio));
        assert_eq!(g.edges[&socio].valid_to_lsn, Some(5));
    }

    #[test]
    fn as_of_nas_arestas_igual_replay_parcial() {
        // GATE M9: para todo t, MATCH (a)-[r]->(b) AS OF t sobre o grafo COMPLETO
        // tem de bater com o grafo reconstruído só dos eventos com lsn <= t
        // (replay parcial). É a prova de que o grafo "viaja no tempo" de forma
        // consistente com o log.
        let log = mutation_log();

        let mut full = TemporalGraph::new();
        for (lsn, e) in &log {
            full.apply_episode(*lsn, e);
        }

        for t in 0..=6u64 {
            // Replay parcial: só os eventos até t (inclusive).
            let mut partial = TemporalGraph::new();
            for (lsn, e) in &log {
                if *lsn <= t {
                    partial.apply_episode(*lsn, e);
                }
            }
            // Grafo completo "as of t" == grafo parcial visto sem limite.
            assert_eq!(
                alive_ids(&full, t),
                alive_ids(&partial, u64::MAX),
                "AS OF {t} deve igualar o replay parcial até {t}"
            );
        }
    }

    #[test]
    fn match_edges_filtra_tipo_origem_destino() {
        let mut g = TemporalGraph::new();
        for (lsn, e) in mutation_log() {
            g.apply_episode(lsn, &e);
        }
        // Antes do retract (AS OF 4): Alfa tem 2 arestas de saída.
        assert_eq!(g.match_edges(Some("Alfa"), None, None, 4, 0.0).len(), 2);
        // Filtro por tipo: só 'pagou'.
        let pagou = g.match_edges(Some("Alfa"), Some(&EdgeType::Pagou), None, 4, 0.0);
        assert_eq!(pagou.len(), 1);
        assert_eq!(pagou[0].to, "Beto");
        // Filtro por destino inexistente.
        assert_eq!(g.match_edges(None, None, Some("Ninguem"), 4, 0.0).len(), 0);
    }

    // ---- M12: hypothesis graph (multi-versão de arestas) ----

    /// Evento que afirma uma hipótese sobre uma aresta explícita.
    fn hyp_ep(from: &str, to: &str, etype: &str, hyp: &str, conf: f32, stance: &str) -> Episode {
        let mut e = Episode::new("ag", EventKind::Observation, vec![]);
        e.attrs.insert("edge_from".into(), from.into());
        e.attrs.insert("edge_to".into(), to.into());
        e.attrs.insert("edge_type".into(), etype.into());
        e.attrs.insert("hypothesis".into(), hyp.into());
        e.attrs.insert("confidence".into(), conf.to_string());
        e.attrs.insert("stance".into(), stance.into());
        e
    }

    #[test]
    fn hipoteses_conflitantes_coexistem() {
        // GATE M12: duas regras conflitantes sobre a MESMA aresta coexistem; a
        // crença agrega ambas (a refutação puxa para baixo) sem quebrar nada.
        let mut g = TemporalGraph::new();
        g.apply_episode(1, &hyp_ep("X", "Y", "fraud_partner", "R1", 0.8, "support"));
        g.apply_episode(2, &hyp_ep("X", "Y", "fraud_partner", "R2", 0.6, "refute"));

        let eid = TemporalGraph::edge_id("X", "Y", &EdgeType::FraudPartner);
        // Ambas as hipóteses estão presentes (uma única aresta, duas versions).
        assert_eq!(g.edges.len(), 1, "uma só aresta topológica");
        assert_eq!(
            g.hypotheses_at(&eid, u64::MAX).len(),
            2,
            "duas hipóteses coexistem"
        );

        // A crença agregada fica abaixo da hipótese de suporte sozinha.
        let only_support = g
            .policy
            .aggregate(&[ver("R1", 0.8, &EdgeType::FraudPartner)]);
        assert!(g.belief(&eid) < only_support, "a refutação reduz a crença");
        assert!((0.0..=1.0).contains(&g.belief(&eid)));
    }

    #[test]
    fn hipotese_viaja_no_tempo() {
        // M12: uma hipótese só conta a partir do seu LSN (AS OF).
        let mut g = TemporalGraph::new();
        g.apply_episode(1, &hyp_ep("X", "Y", "fraud_partner", "R1", 0.8, "support"));
        g.apply_episode(5, &hyp_ep("X", "Y", "fraud_partner", "R2", 0.6, "refute"));
        let eid = TemporalGraph::edge_id("X", "Y", &EdgeType::FraudPartner);

        // No LSN 4 só existe R1 (suporte); a partir de 5 entra a refutação.
        assert_eq!(g.hypotheses_at(&eid, 4).len(), 1);
        assert_eq!(g.hypotheses_at(&eid, 5).len(), 2);
        assert!(
            g.belief_at(&eid, 4) > g.belief_at(&eid, 5),
            "AS OF antes da refutação crê mais"
        );
    }

    #[test]
    fn agregacao_independente_da_ordem_de_chegada() {
        // Conflito não quebra consistência: a ordem em que as hipóteses chegam
        // não muda a crença final nem o state_hash.
        let mut a = TemporalGraph::new();
        a.apply_episode(1, &hyp_ep("X", "Y", "fraud_partner", "R1", 0.8, "support"));
        a.apply_episode(2, &hyp_ep("X", "Y", "fraud_partner", "R2", 0.6, "refute"));

        let mut b = TemporalGraph::new();
        b.apply_episode(1, &hyp_ep("X", "Y", "fraud_partner", "R2", 0.6, "refute"));
        b.apply_episode(2, &hyp_ep("X", "Y", "fraud_partner", "R1", 0.8, "support"));

        let eid = TemporalGraph::edge_id("X", "Y", &EdgeType::FraudPartner);
        // valid_from difere (a ordem de chegada muda os LSNs), mas a crença em
        // "ambas presentes" é a mesma.
        assert!((a.belief_at(&eid, 100) - b.belief_at(&eid, 100)).abs() < 1e-6);
        // Re-aplicar a mesma hipótese é idempotente (não duplica versions).
        a.apply_episode(2, &hyp_ep("X", "Y", "fraud_partner", "R2", 0.6, "refute"));
        assert_eq!(a.hypotheses_at(&eid, 100).len(), 2);
    }

    // ---- M14: graph analytics (COMMUNITY / centralidade / anomaly) ----

    fn assert_ep(from: &str, to: &str) -> Episode {
        edge_ep(from, to, "socio_de", "assert")
    }

    /// Duas quadrilhas separadas: {A1,A2,A3} em triângulo, {B1,B2} em par.
    fn rings() -> Vec<(Lsn, Episode)> {
        vec![
            (1, assert_ep("A1", "A2")),
            (2, assert_ep("A2", "A3")),
            (3, assert_ep("A3", "A1")),
            (4, assert_ep("B1", "B2")),
        ]
    }

    #[test]
    fn community_detecta_quadrilhas() {
        let mut g = TemporalGraph::new();
        for (lsn, e) in rings() {
            g.apply_episode(lsn, &e);
        }
        let a = g.analyze(u64::MAX, 0.0);
        // Os três A* na mesma comunidade; os B* noutra; comunidades distintas.
        let ca = a.community["A1"].clone();
        assert_eq!(a.community["A2"], ca);
        assert_eq!(a.community["A3"], ca);
        assert_ne!(a.community["B1"], ca, "quadrilhas separadas não se fundem");
        assert_eq!(a.community["B1"], a.community["B2"]);
        // id da comunidade = menor nó da componente.
        assert_eq!(ca, "A1");
        assert_eq!(a.members("A1").len(), 3);
        // Grau: no triângulo cada nó tem grau 2.
        assert_eq!(a.metrics["A1"].degree, 2);
        assert_eq!(a.metrics["B1"].degree, 1);
    }

    #[test]
    fn anomaly_destaca_hub() {
        // Estrela: H ligado a 4 folhas → H é o hub (anomaly alto e positivo).
        let mut g = TemporalGraph::new();
        for (i, leaf) in ["L1", "L2", "L3", "L4"].iter().enumerate() {
            g.apply_episode(i as u64 + 1, &assert_ep("H", leaf));
        }
        let a = g.analyze(u64::MAX, 0.0);
        assert_eq!(a.metrics["H"].degree, 4);
        // O hub tem o maior anomaly score, e é positivo (acima da média).
        assert!(a.metrics["H"].anomaly_score > 0.0);
        for leaf in ["L1", "L2", "L3", "L4"] {
            assert!(a.metrics["H"].anomaly_score > a.metrics[leaf].anomaly_score);
        }
    }

    #[test]
    fn metricas_estaveis_entre_replays() {
        // GATE M14: as métricas não oscilam com o replay — função pura do grafo.
        let log = rings();
        let analyze = || {
            let mut g = TemporalGraph::new();
            for (lsn, e) in &log {
                g.apply(*lsn, e);
            }
            g.analyze(u64::MAX, 0.0)
        };
        let a = analyze();
        let b = analyze();
        assert_eq!(a.community, b.community, "comunidades estáveis");
        // Métricas idênticas nó a nó.
        for (node, m) in &a.metrics {
            let n = &b.metrics[node];
            assert_eq!(m.degree, n.degree);
            assert_eq!(m.centrality.to_bits(), n.centrality.to_bits());
            assert_eq!(m.anomaly_score.to_bits(), n.anomaly_score.to_bits());
        }
    }

    #[test]
    fn community_viaja_no_tempo() {
        // AS OF: antes da aresta que liga dois grupos, eles são comunidades
        // distintas; depois, uma só.
        let mut g = TemporalGraph::new();
        g.apply_episode(1, &assert_ep("P", "Q"));
        g.apply_episode(2, &assert_ep("R", "S"));
        g.apply_episode(5, &assert_ep("Q", "R")); // ponte P-Q-R-S
                                                  // No LSN 4: {P,Q} e {R,S} separados.
        let before = g.analyze(4, 0.0);
        assert_ne!(before.community["P"], before.community["R"]);
        // No LSN 5: tudo numa comunidade.
        let after = g.analyze(5, 0.0);
        assert_eq!(after.community["P"], after.community["S"]);
    }
}
