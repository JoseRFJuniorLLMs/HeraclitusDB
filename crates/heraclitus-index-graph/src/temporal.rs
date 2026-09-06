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

use std::collections::{BTreeMap, BTreeSet, HashMap};

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
        // Uma passagem, sem alocar e sem ordenar.
        //
        // A versão anterior construía um `Vec<&EdgeVersion>` e ordenava-o por
        // `hypothesis_id` — comparações de CADEIA — em cada chamada. Isso era
        // redundante: `upsert_edge` já guarda as versions ordenadas por
        // `hypothesis_id` (ver o `entry.sort_by` lá), e filtrar preserva a
        // ordem relativa. A soma vista aqui é exactamente a mesma sequência de
        // parcelas, pela mesma ordem, logo o resultado é idêntico até ao último
        // bit — não é uma aproximação.
        //
        // Importa que seja bit-a-bit: a soma é de `f32` e a ordem das parcelas
        // muda o arredondamento, e esta crença entra em decisões que têm de ser
        // reprodutíveis entre replays.
        //
        // `belief_at` é chamada uma vez POR ARESTA no filtro de `analyze`, pelo
        // que uma alocação e uma ordenação por chamada eram o grosso do custo
        // dessa análise.
        let mut sum = 0.0f32;
        let mut alguma = false;
        for v in versions.iter().filter(|v| v.valid_from_lsn <= as_of) {
            sum += v.polarity * self.logit(v.confidence);
            alguma = true;
        }
        if !alguma {
            return 0.0;
        }
        1.0 / (1.0 + (-sum).exp()) // sigmoid
    }

    /// A implementação anterior, guardada SÓ como referência de teste.
    #[cfg(test)]
    pub(crate) fn aggregate_as_of_referencia(&self, versions: &[EdgeVersion], as_of: Lsn) -> f32 {
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
        1.0 / (1.0 + (-sum).exp())
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

// Auditoria 2026-09-05 (A14/A17): arestas TOCADAS pelo último `match_edges`.
//
// Só existe em builds de teste. É a única forma determinista (sem relógio, logo
// sem flakiness em CI) de provar que a procura por destino consulta o índice de
// entrada `inn` em vez de varrer as E arestas do grafo — a diferença entre
// O(deg_in(dst)) e O(E) não é observável no resultado, que é idêntico.
#[cfg(test)]
thread_local! {
    pub(crate) static ARESTAS_TOCADAS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Média e desvio-padrão do grau — o que alimenta o z-score de `anomaly_score`.
///
/// Único sítio onde esta estatística se calcula: `analyze` (CSR) e
/// `analyze_referencia` têm de concordar, e uma cópia da fórmula em cada lado
/// significa que a referência confirmaria alegremente o valor errado do outro.
///
/// # Porquê `u64` e `f64` para somar inteiros pequenos
///
/// Auditoria 2026-09-05 (A30): os graus são INTEIROS, mas a soma era acumulada
/// em `f32`, que satura em 2^24. Acima de ~8,4 milhões de arestas vivas
/// (2E > 2^24) cada `+1.0` arredonda para nada, a soma congela em 16.777.216 e
/// a média sai grosseiramente abaixo da verdadeira. O erro é ZERO enquanto
/// 2E < 2^24 e depois cresce (medido: 1,2% em 2E≈24M, 4,8% em 2E≈60M), sempre
/// no mesmo sentido — média subestimada infla o z-score de todos os nós acima
/// da média, contra o limiar de 1.5 com que `decision::evaluate` emite
/// `flag_anomaly`. Há configurações de grau em que isso faz milhões de nós
/// cruzarem o limiar que a matemática exacta deixa abaixo.
///
/// Somar em `u64` é exacto, e acumular a variância em `f64` tira ao resultado
/// a dependência do NÚMERO de termos: reforça o contrato de determinismo do
/// replay em vez de o enfraquecer. A soma em `u64` não pode transbordar —
/// `offsets` no CSR do [`TemporalGraph::analyze`] é `u32` e `overflow-checks`
/// já impõe 2E < 2^32 antes de se chegar aqui.
fn estatistica_do_grau(grau: &[u32]) -> (f32, f32) {
    let n = grau.len();
    if n == 0 {
        return (0.0, 0.0);
    }
    let soma: u64 = grau.iter().map(|g| u64::from(*g)).sum();
    let media = soma as f64 / n as f64;
    let var = grau
        .iter()
        .map(|g| {
            let x = f64::from(*g) - media;
            x * x
        })
        .sum::<f64>()
        / n as f64;
    (media as f32, var.sqrt() as f32)
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
    /// determinística: por `from` então por `etype` (iteração de `BTreeMap`)
    /// quando a origem é fixa, e por `edge_id` nos restantes casos. Corta por
    /// `min_confidence`.
    ///
    /// # Qual das três adjacências se percorre
    ///
    /// Auditoria 2026-09-05 (A14/A17): só a ORIGEM tinha índice. Com destino
    /// fixo e origem livre — `MATCH (a)-[r]->(b) WHERE b.id = "X"`, um padrão
    /// GQL banal — varriam-se as E arestas do grafo para devolver `deg_in(X)`
    /// linhas, com o `RwLock` do grafo temporal tomado em leitura, e sem que o
    /// `LIMIT` travasse nada (o planeador só trunca depois de receber tudo). O
    /// índice de entrada `inn` já existia, é mantido em `upsert_edge` na mesma
    /// passagem de `out` (o único ponto de inserção de arestas) e sobrevive ao
    /// checkpoint — só nunca era consultado.
    ///
    /// O varrimento completo fica reservado ao caso em que não há nem origem
    /// nem destino, onde nenhum índice ajuda.
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
            #[cfg(test)]
            ARESTAS_TOCADAS.with(|c| c.set(c.get() + 1));
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
        // Origem fixa → adjacência de saída; senão destino fixo → adjacência de
        // entrada; sem nenhum dos dois, não há índice que ajude.
        let adjacencia = match (src, dst) {
            (Some(s), _) => self.out.get(s),
            (None, Some(d)) => self.inn.get(d),
            (None, None) => None,
        };
        if src.is_some() || dst.is_some() {
            if let Some(types) = adjacencia {
                for (t, eids) in types {
                    // Com o tipo conhecido nem se abrem os baldes dos outros
                    // tipos do nó — o `consider` filtrava-os, mas só depois de
                    // uma procura em `self.edges` por aresta descartada.
                    if let Some(want) = etype {
                        if want != t {
                            continue;
                        }
                    }
                    for eid in eids {
                        if let Some(edge) = self.edges.get(eid) {
                            consider(edge);
                        }
                    }
                }
            }
        } else {
            // Sem origem nem destino: varre todas as arestas (por edge_id).
            for edge in self.edges.values() {
                consider(edge);
            }
        }

        // A ordem é OBSERVÁVEL: o planeador aplica `LIMIT` sem exigir ORDER BY,
        // logo mudá-la mudaria em silêncio que linhas o utilizador vê. O
        // varrimento entregava por `edge_id` (chave do `BTreeMap` `edges`), mas
        // `inn` guarda `Vec<EdgeId>` por tipo e por ordem de chegada — repõe-se
        // aqui, sobre `deg_in(dst)` elementos (custo desprezável).
        if src.is_none() && dst.is_some() {
            out.sort_by(|a, b| a.edge_id.cmp(&b.edge_id));
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
    ///     comunidade é o **menor nó** da componente — os nós são indexados por
    ///     ordem alfabética, logo o índice 0 de cada componente é o seu mínimo.
    ///   - **centralidade**: grau normalizado `degree / (n-1)`.
    ///   - **anomaly_score**: z-score do grau `(deg - média) / desvio`.
    ///
    /// # Representação: CSR sobre `u32`, não `BTreeMap<String, BTreeSet<String>>`
    ///
    /// A versão anterior construía a adjacência em mapas indexados por
    /// `EntityId` — que é uma `String`. Por cada aresta viva fazia **seis
    /// `clone()` de String** (dois para o conjunto de nós, dois para a
    /// adjacência, dois para o grau) e cada `entry`/`get` custava uma
    /// comparação de cadeias, não de inteiros. Numa análise sobre dezenas de
    /// milhares de arestas isso é o grosso do trabalho, e nada disso é o
    /// algoritmo.
    ///
    /// Agora os nomes são traduzidos UMA vez para índices densos, e a
    /// adjacência vive em dois vectores contíguos — `offsets` e `vizinhos` —
    /// que é a forma canónica (CSR) e a que o cache gosta. Os nomes só voltam
    /// no fim, `n` vezes em vez de seis por aresta.
    ///
    /// Os duplicados na adjacência são deixados de propósito: a versão anterior
    /// usava `BTreeSet` e portanto deduplicava, mas para alcançabilidade visitar
    /// um vizinho duas vezes é inofensivo (o teste `visitado` trata disso), e o
    /// `degree` conta ARESTAS e não vizinhos distintos — que é o que a versão
    /// anterior também fazia. Deduplicar mudaria o grau.
    pub fn analyze(&self, as_of: Lsn, min_confidence: f32) -> GraphAnalytics {
        // Arestas vivas + confiáveis, em ordem determinística (por edge_id).
        //
        // MERGE JOIN, não `belief_at` por aresta. `self.edges` e
        // `self.versions` são ambos `BTreeMap` indexados por `EdgeId` — que é
        // uma `String` — e portanto já vêm ordenados pela MESMA chave. A versão
        // anterior fazia uma procura na árvore por cada aresta: 100 mil
        // descidas com comparação de cadeia, que medi serem **78% do custo de
        // `belief_at`** — mais do que a agregação que o item 39 da SPEC ataca.
        //
        // Percorrer os dois em paralelo dá os mesmos pares sem uma única
        // procura, e é exacto: mesma ordem, mesmos valores.
        let mut it_versions = self.versions.iter().peekable();
        let alive: Vec<&Edge> = self
            .edges
            .iter()
            .filter_map(|(id, e)| {
                // Avança SEMPRE, esteja a aresta viva ou não: é o que mantém os
                // dois cursores alinhados.
                while it_versions.peek().is_some_and(|(k, _)| *k < id) {
                    it_versions.next();
                }
                let vs = match it_versions.peek() {
                    Some((k, v)) if *k == id => Some(*v),
                    _ => None,
                };
                if !e.alive_at(as_of) {
                    return None;
                }
                let crenca = vs.map_or(0.0, |v| self.policy.aggregate_as_of(v, as_of));
                (crenca >= min_confidence).then_some(e)
            })
            .collect();

        // --- índice denso, por ordem alfabética -----------------------------
        //
        // Duas passagens, e a razão é medida: a primeira versão disto construía
        // um `BTreeSet<&String>` com as duas pontas de cada aresta, ou seja
        // 2·m inserções numa árvore ordenada — 200 mil comparações de CADEIA
        // vezes log(n) para 100 mil arestas. Isso era 80% do tempo de
        // `analyze`, e não é o algoritmo: é só chegar aos identificadores.
        //
        // Agora: um mapa de dispersão atribui ids por ordem de aparição (2·m
        // dispersões, sem comparações), e só os `n` nomes ÚNICOS são ordenados
        // no fim. Para 100 mil arestas e 10 mil nós, são 20 mil dispersões mais
        // 10 mil·log(10 mil) comparações, em vez de 2,7 milhões.
        //
        // A ordem alfabética continua a importar: o id da comunidade é o menor
        // nó, e é o `rank` que garante que o índice 0 de cada componente é esse
        // mínimo.
        // Os pares resolvidos ficam guardados: sem isto, cada nome era
        // procurado TRÊS vezes — ao indexar, ao contar o grau, e ao preencher o
        // CSR — e cada procura é uma dispersão de cadeia.
        let mut idx: HashMap<&str, u32> = HashMap::with_capacity(alive.len());
        let mut aparicao: Vec<&EntityId> = Vec::new();
        let mut pares: Vec<(u32, u32)> = Vec::with_capacity(alive.len());
        for e in &alive {
            let mut ids = [0u32; 2];
            for (slot, nome) in ids.iter_mut().zip([&e.from, &e.to]) {
                *slot = match idx.get(nome.as_str()) {
                    Some(i) => *i,
                    None => {
                        let novo = aparicao.len() as u32;
                        idx.insert(nome.as_str(), novo);
                        aparicao.push(nome);
                        novo
                    }
                };
            }
            pares.push((ids[0], ids[1]));
        }
        let n = aparicao.len();
        // Permutação para ordem alfabética: `rank[id_de_aparicao] = id_ordenado`.
        let mut ordem: Vec<u32> = (0..n as u32).collect();
        ordem.sort_unstable_by(|a, b| aparicao[*a as usize].cmp(aparicao[*b as usize]));
        let mut rank = vec![0u32; n];
        for (ordenado, &aparecido) in ordem.iter().enumerate() {
            rank[aparecido as usize] = ordenado as u32;
        }
        let nomes: Vec<&EntityId> = ordem.iter().map(|&i| aparicao[i as usize]).collect();

        if n == 0 {
            return GraphAnalytics {
                community: BTreeMap::new(),
                metrics: BTreeMap::new(),
            };
        }

        // --- grau (conta ARESTAS) e offsets do CSR --------------------------
        // Os pares passam de ids de APARIÇÃO para ids ORDENADOS, uma vez.
        for p in pares.iter_mut() {
            *p = (rank[p.0 as usize], rank[p.1 as usize]);
        }
        let mut grau = vec![0u32; n];
        for &(a, b) in &pares {
            grau[a as usize] += 1;
            grau[b as usize] += 1;
        }
        let mut offsets = vec![0u32; n + 1];
        for i in 0..n {
            offsets[i + 1] = offsets[i] + grau[i];
        }
        let mut vizinhos = vec![0u32; offsets[n] as usize];
        let mut cursor: Vec<u32> = offsets[..n].to_vec();
        for &(a, b) in &pares {
            let (a, b) = (a as usize, b as usize);
            vizinhos[cursor[a] as usize] = b as u32;
            cursor[a] += 1;
            vizinhos[cursor[b] as usize] = a as u32;
            cursor[b] += 1;
        }

        // --- componentes conexas sobre os índices ---------------------------
        const SEM_COMUNIDADE: u32 = u32::MAX;
        let mut comunidade = vec![SEM_COMUNIDADE; n];
        let mut pilha: Vec<u32> = Vec::new();
        for semente in 0..n as u32 {
            if comunidade[semente as usize] != SEM_COMUNIDADE {
                continue;
            }
            comunidade[semente as usize] = semente;
            pilha.push(semente);
            while let Some(no) = pilha.pop() {
                let (i, j) = (offsets[no as usize], offsets[no as usize + 1]);
                for &m in &vizinhos[i as usize..j as usize] {
                    if comunidade[m as usize] == SEM_COMUNIDADE {
                        comunidade[m as usize] = semente;
                        pilha.push(m);
                    }
                }
            }
        }

        // --- centralidade e anomaly (z-score do grau) -----------------------
        let (media, std) = estatistica_do_grau(&grau);

        // --- de volta aos nomes, `n` vezes ----------------------------------
        let mut community: BTreeMap<EntityId, EntityId> = BTreeMap::new();
        let mut metrics: BTreeMap<EntityId, NodeMetrics> = BTreeMap::new();
        for i in 0..n {
            community.insert(nomes[i].clone(), nomes[comunidade[i] as usize].clone());
            let deg = grau[i];
            metrics.insert(
                nomes[i].clone(),
                NodeMetrics {
                    degree: deg,
                    centrality: if n > 1 {
                        deg as f32 / (n as f32 - 1.0)
                    } else {
                        0.0
                    },
                    anomaly_score: if std > 0.0 {
                        (deg as f32 - media) / std
                    } else {
                        0.0
                    },
                    computed_at_lsn: as_of,
                },
            );
        }

        GraphAnalytics { community, metrics }
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
    #[cfg(test)]
    pub(crate) fn analyze_referencia(&self, as_of: Lsn, min_confidence: f32) -> GraphAnalytics {
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
        let degs: Vec<u32> = nodes
            .iter()
            .map(|node| *degree.get(node).unwrap_or(&0))
            .collect();
        let (mean, std) = estatistica_do_grau(&degs);

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

    pub(super) fn ver(hyp: &str, conf: f32, etype: &EdgeType) -> EdgeVersion {
        EdgeVersion {
            hypothesis_id: hyp.into(),
            confidence: conf,
            source: "rule".into(),
            provenance: vec![],
            polarity: etype.polarity(),
            valid_from_lsn: 0,
        }
    }

    pub(super) fn edge(id: &str, from: &str, to: &str, etype: EdgeType, vf: Lsn) -> Edge {
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

#[cfg(test)]
mod testes_csr {
    use super::tests::{edge, ver};
    use super::*;
    use std::time::Instant;

    struct R(u64);
    impl R {
        fn p(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Grafo com comunidades reais: blocos densos ligados por poucas pontes,
    /// alguns nos isolados, e arestas PARALELAS (que e onde `degree` e
    /// `adjacencia` divergem — o primeiro conta arestas, o segundo nao).
    pub(super) fn grafo(n_nos: usize, n_arestas: usize, semente: u64) -> TemporalGraph {
        let mut g = TemporalGraph::new();
        let mut r = R(semente);
        for i in 0..n_arestas {
            let bloco = (r.p() % 8) as usize;
            let base = bloco * (n_nos / 8).max(1);
            let a = base + (r.p() as usize % (n_nos / 8).max(1));
            let b = base + (r.p() as usize % (n_nos / 8).max(1));
            // Uma em cada 40 e uma ponte entre blocos.
            let b = if i % 40 == 0 {
                r.p() as usize % n_nos
            } else {
                b
            };
            let e = edge(
                &format!("e{i}"),
                &format!("no-{a:05}"),
                &format!("no-{b:05}"),
                EdgeType::SocioDe,
                0,
            );
            let v = ver(&format!("h{i}"), 0.9, &EdgeType::SocioDe);
            g.upsert_edge(e, vec![v]);
        }
        g
    }

    /// A prova de que o CSR nao mudou a resposta: comunidades, graus,
    /// centralidade e anomaly identicos aos da versao com `BTreeMap<String, ...>`.
    #[test]
    fn o_csr_concorda_com_a_versao_em_btreemap_de_string() {
        for (n_nos, n_arestas, semente) in [
            (50, 200, 1u64),
            (200, 1500, 7),
            (400, 5000, 99),
            (300, 3333, 5),
            (777, 9999, 13),
            (123, 4567, 21),
            (1000, 30000, 31),
            (64, 999, 77),
        ] {
            let g = grafo(n_nos, n_arestas, semente);
            let novo = g.analyze(u64::MAX, 0.0);
            let refer = g.analyze_referencia(u64::MAX, 0.0);

            assert_eq!(
                novo.community, refer.community,
                "comunidades divergiram (n={n_nos}, m={n_arestas})"
            );
            assert_eq!(
                novo.metrics.len(),
                refer.metrics.len(),
                "numero de nos divergiu"
            );
            for (no, m) in &refer.metrics {
                let a = novo
                    .metrics
                    .get(no)
                    .unwrap_or_else(|| panic!("no {no} em falta"));
                assert_eq!(a.degree, m.degree, "grau de {no}");
                assert!(
                    (a.centrality - m.centrality).abs() < 1e-6,
                    "centralidade de {no}"
                );
                // As duas vias partilham `estatistica_do_grau` sobre o MESMO
                // vector de graus (ambos por ordem alfabetica de no), logo tem
                // de coincidir BIT A BIT — nao apenas dentro de uma tolerancia.
                // Auditoria 2026-09-05 (A30): e isto que impede que uma das
                // vias volte a ter formula propria (a antiga, em f32).
                assert_eq!(
                    a.anomaly_score.to_bits(),
                    m.anomaly_score.to_bits(),
                    "anomaly de {no}: {} vs {}",
                    a.anomaly_score,
                    m.anomaly_score
                );
            }
        }
    }

    /// O desempate que o CSR tem de preservar: o id da comunidade e o MENOR
    /// no da componente. Indexar por ordem alfabetica e o que o garante.
    #[test]
    fn o_id_da_comunidade_continua_a_ser_o_menor_no() {
        let mut g = TemporalGraph::new();
        for (i, (a, b)) in [("zebra", "melancia"), ("melancia", "abacate")]
            .iter()
            .enumerate()
        {
            g.upsert_edge(
                edge(&format!("e{i}"), a, b, EdgeType::SocioDe, 0),
                vec![ver(&format!("h{i}"), 0.9, &EdgeType::SocioDe)],
            );
        }
        let a = g.analyze(u64::MAX, 0.0);
        for no in ["abacate", "melancia", "zebra"] {
            assert_eq!(a.community[no], "abacate", "comunidade de {no}");
        }
    }

    /// Auditoria 2026-09-05 (A30): a soma dos graus satura o acumulador `f32`
    /// em 2^24. Com graus todos IGUAIS o desvio verdadeiro e zero; um
    /// acumulador `f32` inventa media e desvio, e o z-score de nos identicos
    /// deixa de ser 0 — enviesado para cima, contra o limiar de 1.5 que
    /// `decision::evaluate` usa para emitir `flag_anomaly`.
    ///
    /// O teste ataca a formula isolada porque um grafo real com 2E > 2^24
    /// exigiria dezenas de GB de `BTreeMap<EdgeId, Edge>` vivos.
    #[test]
    fn a_estatistica_do_grau_nao_satura_o_acumulador() {
        // (1) A SOMA. 2E = 2e10, muito acima de 2^24 = 16.777.216. Com graus
        // todos IGUAIS o desvio verdadeiro e exactamente zero.
        let grau = vec![4_000_000u32; 5_000];
        let (media, std) = estatistica_do_grau(&grau);
        assert_eq!(
            media, 4_000_000.0,
            "media exacta; a somar em f32 da 3999799.3"
        );
        assert_eq!(
            std, 0.0,
            "graus identicos => desvio zero; a somar em f32 da 200.7554"
        );

        // (2) O ACUMULADOR DA VARIANCIA. Um outlier grande faz o acumulador
        // subir tanto que os termos seguintes ficam abaixo de meio-ulp e sao
        // engolidos. Aqui a media ja sai exacta nas duas versoes: o que a
        // tolerancia apertada mata e so o acumulador em f32.
        let mut grau = vec![1_000_000u32; 20_000];
        grau[0] = 3_000_000;
        let (media, std) = estatistica_do_grau(&grau);
        assert_eq!(media, 1_000_100.0, "media exacta com um outlier");
        assert!(
            (std - 14_141.782).abs() < 0.05,
            "desvio {std}; exacto 14141.782, com acumulador f32 da 14141.429"
        );

        // (3) O mesmo, com a cauda INTEIRA a ser engolida pelo outlier.
        let mut grau = vec![1u32; 20_000];
        grau[0] = 4_000_000;
        let (_, std) = estatistica_do_grau(&grau);
        assert!(
            (std - 28_283.557).abs() < 0.05,
            "desvio {std}; exacto 28283.557, com acumulador f32 da 28282.85"
        );
    }

    /// Um grafo sem arestas vivas nao pode partir a indexacao densa.
    #[test]
    fn um_grafo_vazio_devolve_analise_vazia() {
        let g = TemporalGraph::new();
        let a = g.analyze(u64::MAX, 0.0);
        assert!(a.community.is_empty() && a.metrics.is_empty());
        assert_eq!(a.community, g.analyze_referencia(u64::MAX, 0.0).community);
    }

    /// `cargo test -p heraclitus-index-graph --lib medicao_csr -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn custo_da_analise() {
        for (n_nos, n_arestas) in [(2_000usize, 20_000usize), (10_000, 100_000)] {
            let g = grafo(n_nos, n_arestas, 42);
            let t0 = Instant::now();
            let a = g.analyze(u64::MAX, 0.0);
            let csr = t0.elapsed();
            let t1 = Instant::now();
            let b = g.analyze_referencia(u64::MAX, 0.0);
            let btree = t1.elapsed();
            assert_eq!(a.community, b.community);
            println!(
                "nos={n_nos:>6} arestas={n_arestas:>7}  CSR {:>10.3?}  BTreeMap<String> {:>10.3?}  ganho {:.1}x",
                csr,
                btree,
                btree.as_secs_f64() / csr.as_secs_f64().max(1e-9)
            );
        }
    }

    /// Onde e que o tempo do CSR vai: no algoritmo, ou a construir o
    /// `BTreeMap<String, ...>` de saida?
    #[test]
    #[ignore]
    fn onde_vai_o_tempo_do_csr() {
        let g = grafo(10_000, 100_000, 42);
        let t0 = Instant::now();
        let a = g.analyze(u64::MAX, 0.0);
        let completo = t0.elapsed();
        // So a parte que constroi a saida: reinserir o mesmo conteudo em dois
        // BTreeMap de String custa o mesmo que construi-los na analise.
        let t1 = Instant::now();
        let mut c2: BTreeMap<EntityId, EntityId> = BTreeMap::new();
        let mut m2: BTreeMap<EntityId, NodeMetrics> = BTreeMap::new();
        for (k, v) in &a.community {
            c2.insert(k.clone(), v.clone());
        }
        for (k, v) in &a.metrics {
            m2.insert(k.clone(), v.clone());
        }
        let saida = t1.elapsed();
        // E o filtro `alive`, que chama `belief_at` por aresta?
        let t2 = Instant::now();
        let vivas = g
            .edges
            .values()
            .filter(|e| e.alive_at(u64::MAX) && g.belief_at(&e.id, u64::MAX) >= 0.0)
            .count();
        let filtro = t2.elapsed();
        // E so o `alive_at`, sem o belief?
        let t3 = Instant::now();
        let vivas2 = g.edges.values().filter(|e| e.alive_at(u64::MAX)).count();
        let so_alive = t3.elapsed();
        println!("analyze completa : {completo:>10.3?}");
        println!("filtro alive+belief: {filtro:>10.3?}  ({vivas} arestas)");
        println!("so alive_at        : {so_alive:>10.3?}  ({vivas2} arestas)");
        println!(
            "fraccao no belief  : {:.0}%",
            100.0 * (filtro.as_secs_f64() - so_alive.as_secs_f64()) / completo.as_secs_f64()
        );
        println!("so a saida       : {saida:>10.3?}");
        println!(
            "fraccao na saida : {:.0}%  (nos={}, arestas=100000)",
            100.0 * saida.as_secs_f64() / completo.as_secs_f64(),
            a.metrics.len()
        );
    }
}

/// Auditoria 2026-09-05 (A14/A17): `match_edges` com DESTINO fixo e origem
/// livre — o padrão GQL banal `MATCH (a)-[r]->(b) WHERE b.id = "X"` — varria as
/// E arestas do grafo, apesar de o índice de entrada `inn` existir, ser mantido
/// simetricamente com `out` em `upsert_edge` e sobreviver ao checkpoint.
#[cfg(test)]
mod testes_match_por_destino {
    use super::tests::{edge, ver};
    use super::*;

    struct R(u64);
    impl R {
        fn p(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn tipo(i: usize) -> EdgeType {
        match i % 6 {
            0 => EdgeType::FraudPartner,
            1 => EdgeType::SocioDe,
            2 => EdgeType::Pagou,
            3 => EdgeType::SimilarA,
            4 => EdgeType::NotRelated,
            _ => EdgeType::Custom("ligado_a".into()),
        }
    }

    /// Liga `from -[etype]-> to` com o `edge_id` determinístico REAL
    /// (`TemporalGraph::edge_id`). Importa que seja o real: a ordem de inserção
    /// em `inn` (por tipo, depois por chegada) não coincide com a ordem
    /// lexicográfica de `edge_id`, e é essa divergência que torna a ordem de
    /// saída observável.
    fn liga(
        g: &mut TemporalGraph,
        from: &str,
        to: &str,
        et: EdgeType,
        vf: Lsn,
        conf: f32,
    ) -> EdgeId {
        let id = TemporalGraph::edge_id(from, to, &et);
        let v = ver(&format!("h-{id}"), conf, &et);
        g.upsert_edge(edge(&id, from, to, et, vf), vec![v]);
        id
    }

    /// Muito ruído e um destino raro: só 3 arestas chegam a "ALVO".
    fn grafo_com_alvo(n_arestas: usize) -> TemporalGraph {
        let mut g = TemporalGraph::new();
        let mut r = R(2026);
        for i in 0..n_arestas {
            let a = r.p() % 4_000;
            let b = r.p() % 4_000;
            liga(
                &mut g,
                &format!("no-{a:05}"),
                &format!("no-{b:05}"),
                tipo(i),
                0,
                0.9,
            );
        }
        // As únicas arestas de entrada de ALVO, de três tipos distintos.
        for (i, de) in ["no-00007", "no-01234", "zz-ultimo"].iter().enumerate() {
            liga(&mut g, de, "ALVO", tipo(i), 0, 0.9);
        }
        g
    }

    /// O defeito: procurar por destino custava O(E). Aqui conta-se o trabalho
    /// REAL (arestas tocadas), não o relógio — determinista, sem flakiness.
    #[test]
    fn match_por_destino_nao_varre_o_grafo() {
        let g = grafo_com_alvo(20_000);
        let e = g.edges.len();
        assert!(e > 15_000, "grafo de teste degenerou: {e} arestas");

        ARESTAS_TOCADAS.with(|c| c.set(0));
        let r = g.match_edges(None, None, Some("ALVO"), u64::MAX, 0.0);
        let tocadas = ARESTAS_TOCADAS.with(|c| c.get());
        assert_eq!(r.len(), 3, "ALVO tem exactamente 3 arestas de entrada");
        assert!(
            tocadas <= 8,
            "procura por destino tocou {tocadas} arestas num grafo de {e}: \
             o índice de entrada `inn` não foi usado (varrimento O(E))"
        );

        // Com o tipo conhecido, nem os baldes dos outros tipos do nó se abrem.
        ARESTAS_TOCADAS.with(|c| c.set(0));
        let r = g.match_edges(
            None,
            Some(&EdgeType::FraudPartner),
            Some("ALVO"),
            u64::MAX,
            0.0,
        );
        let tocadas = ARESTAS_TOCADAS.with(|c| c.get());
        assert_eq!(r.len(), 1, "só uma aresta FraudPartner chega a ALVO");
        assert!(
            tocadas <= 2,
            "procura por destino+tipo tocou {tocadas} arestas num grafo de {e}"
        );
    }

    /// O irmão menor do mesmo defeito: com ORIGEM fixa e tipo conhecido,
    /// percorriam-se todos os tipos de aresta do nó em vez de só o pedido.
    #[test]
    fn match_por_origem_e_tipo_nao_abre_os_outros_tipos() {
        let mut g = TemporalGraph::new();
        for i in 0..6 {
            liga(&mut g, "HUB", &format!("destino-{i}"), tipo(i), 0, 0.9);
        }
        ARESTAS_TOCADAS.with(|c| c.set(0));
        let r = g.match_edges(Some("HUB"), Some(&EdgeType::SimilarA), None, u64::MAX, 0.0);
        let tocadas = ARESTAS_TOCADAS.with(|c| c.get());
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].to, "destino-3");
        assert!(
            tocadas <= 1,
            "com o tipo conhecido tocaram-se {tocadas} arestas das 6 do HUB"
        );
    }

    /// Projecção comparável de um `EdgeMatch` (a crença por bits — nunca
    /// igualdade de `f32` — e sem tocar no tipo público para lhe dar `PartialEq`).
    type Linha = (
        EdgeId,
        EntityId,
        EntityId,
        EdgeType,
        u32,
        Option<u64>,
        Option<u64>,
    );

    fn projecta(v: &[EdgeMatch]) -> Vec<Linha> {
        v.iter()
            .map(|m| {
                (
                    m.edge_id.clone(),
                    m.from.clone(),
                    m.to.clone(),
                    m.etype.clone(),
                    m.belief.to_bits(),
                    m.world_valid_from,
                    m.world_valid_to,
                )
            })
            .collect()
    }

    /// Oráculo: o varrimento `self.edges.values()` que `match_edges` fazia
    /// antes da correcção, com os MESMOS filtros. É contra isto que a versão
    /// indexada tem de ser idêntica — elementos E ordem.
    fn varrimento_referencia(
        g: &TemporalGraph,
        etype: Option<&EdgeType>,
        dst: Option<&str>,
        as_of: Lsn,
        min_confidence: f32,
    ) -> Vec<Linha> {
        let mut out = Vec::new();
        for e in g.edges.values() {
            if !e.alive_at(as_of) {
                continue;
            }
            if let Some(want) = etype {
                if *want != e.etype {
                    continue;
                }
            }
            if let Some(d) = dst {
                if e.to != d {
                    continue;
                }
            }
            let belief = g.belief_at(&e.id, as_of);
            if belief < min_confidence {
                continue;
            }
            out.push((
                e.id.clone(),
                e.from.clone(),
                e.to.clone(),
                e.etype.clone(),
                belief.to_bits(),
                e.world_valid_from,
                e.world_valid_to,
            ));
        }
        out
    }

    /// Grafo com tudo o que pode distinguir os dois caminhos: vários tipos,
    /// arestas fechadas, arestas reabertas (`closed_intervals`), auto-aresta,
    /// crenças variadas e valid time do mundo.
    fn grafo_rico() -> TemporalGraph {
        let mut g = TemporalGraph::new();
        let mut r = R(99);
        let destinos = ["alfa", "beto", "ALVO", "zeta"];
        let mut ids: Vec<EdgeId> = Vec::new();
        for i in 0..240 {
            let de = format!("origem-{:03}", r.p() % 40);
            let para = destinos[(r.p() % destinos.len() as u64) as usize];
            let conf = (r.p() % 100) as f32 / 100.0;
            ids.push(liga(&mut g, &de, para, tipo(i), 10, conf));
        }
        ids.push(liga(&mut g, "ALVO", "ALVO", EdgeType::SocioDe, 10, 0.8));

        // Fecha um terço em LSN 50; reabre metade dessas em LSN 70 (R12).
        let fechadas: Vec<EdgeId> = ids.iter().step_by(3).cloned().collect();
        for id in &fechadas {
            g.close_edge(id, 50);
        }
        for id in fechadas.iter().step_by(2) {
            let e = g.edges.get(id).cloned().expect("aresta fechada existe");
            g.upsert_edge(
                Edge {
                    valid_from_lsn: 70,
                    ..e
                },
                vec![],
            );
        }
        // Valid time do mundo em algumas — viaja no `EdgeMatch`.
        for id in ids.iter().step_by(7) {
            if let Some(e) = g.edges.get_mut(id) {
                e.world_valid_from = Some(100);
                e.world_valid_to = Some(200);
            }
        }
        g
    }

    /// A melhoria não pode mudar a resposta: mesmos elementos e MESMA ORDEM
    /// (o LIMIT do planeador corta pelo prefixo, logo a ordem é observável).
    #[test]
    fn match_por_destino_equivale_ao_varrimento() {
        let g = grafo_rico();
        let tipos: Vec<Option<EdgeType>> = std::iter::once(None)
            .chain((0..6).map(|i| Some(tipo(i))))
            .collect();
        let mut nao_vazios = 0usize;
        for d in ["alfa", "beto", "ALVO", "zeta", "inexistente"] {
            for t in &tipos {
                for as_of in [0u64, 40, 60, 80, u64::MAX] {
                    for mc in [0.0f32, 0.5, 0.95] {
                        let obtido = projecta(&g.match_edges(None, t.as_ref(), Some(d), as_of, mc));
                        let esperado = varrimento_referencia(&g, t.as_ref(), Some(d), as_of, mc);
                        assert_eq!(
                            obtido, esperado,
                            "divergiu em dst={d} etype={t:?} as_of={as_of} mc={mc}"
                        );
                        nao_vazios += usize::from(!esperado.is_empty());
                    }
                }
            }
        }
        assert!(
            nao_vazios >= 40,
            "grafo de teste demasiado esparso: só {nao_vazios} casos com resultados"
        );

        // A ordem só é observável se um destino receber arestas de VÁRIOS
        // tipos: sem o `sort_by(edge_id)` final, `inn` devolvê-las-ia agrupadas
        // por tipo. Garantir que o grafo de teste exercita esse caso.
        let alvo = g.match_edges(None, None, Some("ALVO"), u64::MAX, 0.0);
        assert!(
            alvo.len() > 10,
            "ALVO recebeu poucas arestas: {}",
            alvo.len()
        );
        let tipos_no_alvo: BTreeSet<EdgeType> = alvo.iter().map(|m| m.etype.clone()).collect();
        assert!(
            tipos_no_alvo.len() >= 3,
            "ALVO só recebeu {} tipos distintos",
            tipos_no_alvo.len()
        );
        assert!(
            alvo.windows(2).all(|w| w[0].edge_id < w[1].edge_id),
            "a saída por destino tem de vir ordenada por edge_id"
        );
    }
}

#[cfg(test)]
mod testes_belief {
    use super::tests::ver;
    use super::*;
    use std::time::Instant;

    struct R(u64);
    impl R {
        fn p(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn conf(&mut self) -> f32 {
            (self.p() % 9_999) as f32 / 10_000.0 + 0.00005
        }
    }

    /// Versoes com hypothesis_id fora de ordem alfabetica de CHEGADA, para o
    /// caso em que a ordenacao importaria se `upsert_edge` nao a fizesse.
    fn versoes(n: usize, semente: u64) -> Vec<EdgeVersion> {
        let mut r = R(semente);
        let mut v: Vec<EdgeVersion> = (0..n)
            .map(|i| {
                let mut e = ver(
                    &format!("h{:04}", (i * 7919) % 10_000),
                    r.conf(),
                    &EdgeType::SocioDe,
                );
                e.valid_from_lsn = (r.p() % 1_000) as Lsn;
                e.polarity = if r.p().is_multiple_of(3) { -1.0 } else { 1.0 };
                e
            })
            .collect();
        // Como `upsert_edge` faria.
        v.sort_by(|a, b| a.hypothesis_id.cmp(&b.hypothesis_id));
        v
    }

    /// A prova de que remover a ordenacao nao mudou NADA: bit a bit.
    ///
    /// Nao e uma tolerancia — e igualdade exacta. A soma e de `f32` e a ordem
    /// das parcelas muda o arredondamento; se a nova versao somasse por outra
    /// ordem, este teste apanhava.
    #[test]
    fn a_agregacao_sem_ordenacao_e_bit_a_bit_identica() {
        let politica = BeliefPolicy::default();
        for (n, semente) in [(1usize, 1u64), (2, 5), (7, 11), (50, 23), (200, 97)] {
            let vs = versoes(n, semente);
            for as_of in [0u64, 250, 500, 999, u64::MAX] {
                let novo = politica.aggregate_as_of(&vs, as_of);
                let refer = politica.aggregate_as_of_referencia(&vs, as_of);
                assert_eq!(
                    novo.to_bits(),
                    refer.to_bits(),
                    "n={n} semente={semente} as_of={as_of}: {novo} vs {refer}"
                );
            }
        }
    }

    /// Sem versoes vivas, zero — como antes.
    #[test]
    fn sem_versoes_vivas_a_crenca_e_zero() {
        let politica = BeliefPolicy::default();
        let vs = versoes(10, 3);
        // `valid_from_lsn` gerado em [0, 1000); as_of abaixo do minimo.
        let min = vs.iter().map(|v| v.valid_from_lsn).min().unwrap();
        if min > 0 {
            assert_eq!(politica.aggregate_as_of(&vs, min - 1), 0.0);
        }
        assert_eq!(politica.aggregate_as_of(&[], u64::MAX), 0.0);
    }

    /// Com UMA version por aresta, onde vai o custo de `belief_at`: na procura
    /// no `BTreeMap<EdgeId, _>` (EdgeId e `String`), ou na agregacao?
    #[test]
    #[ignore]
    fn procura_ou_agregacao() {
        let g = super::testes_csr::grafo(10_000, 100_000, 42);
        let ids: Vec<EdgeId> = g.edges.keys().cloned().collect();

        let t0 = Instant::now();
        let mut a = 0.0f32;
        for id in &ids {
            a += g.belief_at(id, u64::MAX);
        }
        let completo = t0.elapsed();

        // So a procura no mapa.
        let t1 = Instant::now();
        let mut n = 0usize;
        for id in &ids {
            n += g.versions.get(id).map_or(0, |v| v.len());
        }
        let so_procura = t1.elapsed();

        // So a agregacao, sobre as versions ja em mao.
        let todas: Vec<&Vec<EdgeVersion>> = ids.iter().filter_map(|i| g.versions.get(i)).collect();
        let t2 = Instant::now();
        let mut b = 0.0f32;
        for vs in &todas {
            b += g.policy.aggregate_as_of(vs, u64::MAX);
        }
        let so_agregacao = t2.elapsed();

        println!(
            "belief_at completo : {completo:>10.3?}  ({} arestas)",
            ids.len()
        );
        println!("so a procura       : {so_procura:>10.3?}  ({n} versions)");
        println!("so a agregacao     : {so_agregacao:>10.3?}");
        println!(
            "fraccao na PROCURA : {:.0}%",
            100.0 * so_procura.as_secs_f64() / completo.as_secs_f64()
        );
        let _ = (a, b);
    }

    /// Quanto do custo restante e o `logit()` (clamp + divisao + `ln`)?
    ///
    /// A resposta decide se vale a pena mudar a ordem canonica da soma para
    /// permitir prefix sums (item 40) ou se basta cachear o log-odds.
    #[test]
    #[ignore]
    fn quanto_custa_o_logit() {
        let politica = BeliefPolicy::default();
        for n in [3usize, 12, 60] {
            let vs = versoes(n, 42);
            // Log-odds ja calculados: e o tecto do que um cache daria.
            let cache: Vec<f32> = vs
                .iter()
                .map(|v| v.polarity * politica.logit(v.confidence))
                .collect();
            let repeticoes = 200_000usize;

            let t0 = Instant::now();
            let mut a = 0.0f32;
            for i in 0..repeticoes {
                a += politica.aggregate_as_of(&vs, (i % 1000) as Lsn);
            }
            let com_logit = t0.elapsed();

            let t1 = Instant::now();
            let mut b = 0.0f32;
            for i in 0..repeticoes {
                let as_of = (i % 1000) as Lsn;
                let mut sum = 0.0f32;
                let mut alguma = false;
                for (k, v) in vs.iter().enumerate() {
                    if v.valid_from_lsn <= as_of {
                        sum += cache[k];
                        alguma = true;
                    }
                }
                b += if alguma {
                    1.0 / (1.0 + (-sum).exp())
                } else {
                    0.0
                };
            }
            let com_cache = t1.elapsed();

            assert_eq!(a.to_bits(), b.to_bits(), "o cache tem de dar o MESMO valor");
            println!(
                "versoes={n:>3}  com logit {:>10.3?}  com cache {:>10.3?}  ganho {:.1}x",
                com_logit,
                com_cache,
                com_logit.as_secs_f64() / com_cache.as_secs_f64().max(1e-9)
            );
        }
    }

    /// `cargo test -p heraclitus-index-graph --lib custo_do_belief -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn custo_do_belief() {
        let politica = BeliefPolicy::default();
        for n in [3usize, 12, 60] {
            let vs = versoes(n, 42);
            let repeticoes = 200_000usize;

            let t0 = Instant::now();
            let mut a = 0.0f32;
            for i in 0..repeticoes {
                a += politica.aggregate_as_of(&vs, (i % 1000) as Lsn);
            }
            let novo = t0.elapsed();

            let t1 = Instant::now();
            let mut b = 0.0f32;
            for i in 0..repeticoes {
                b += politica.aggregate_as_of_referencia(&vs, (i % 1000) as Lsn);
            }
            let refer = t1.elapsed();

            assert_eq!(a.to_bits(), b.to_bits());
            println!(
                "versoes={n:>3}  novo {:>10.3?}  com ordenacao {:>10.3?}  ganho {:.1}x",
                novo,
                refer,
                refer.as_secs_f64() / novo.as_secs_f64().max(1e-9)
            );
        }
    }
}
