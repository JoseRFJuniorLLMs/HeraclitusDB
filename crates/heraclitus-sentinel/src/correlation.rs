//! Deterministic L3 temporal correlation primitives.
//!
//! The types in this module are deliberately standalone.  They can be fed by
//! the L0/L1/L2 adapters without changing the append path; a host that wants
//! durable incidents must persist the snapshots and transition records in the
//! Heraclitus log.  All collections are ordered so replaying the same inputs
//! produces byte-for-byte stable JSON and the same logical incident IDs.

use crate::event::{EntityRef, EvidenceRef, SecurityCategory, SecurityEvent, SecuritySignal};
use heraclitus_core::{Episode, EventId, EventKind, Lsn};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

const MAX_GRAPH_EDGES: usize = 100_000;
const MAX_INCIDENTS: usize = 50_000;
const MAX_INCIDENT_SIGNALS: usize = 4_096;
const MAX_INCIDENT_EVIDENCE: usize = 16_384;
const MAX_PATH_DEPTH: usize = 32;

/// Entity kinds named by SPEC-0045 §23.  Unknown integrations remain
/// lossless through [`SecurityEntityKind::Custom`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityEntityKind {
    User,
    Principal,
    ServiceAccount,
    Session,
    Credential,
    Token,
    Host,
    Process,
    Container,
    Pod,
    Ip,
    Domain,
    Service,
    Application,
    Database,
    File,
    CloudResource,
    Repository,
    Pipeline,
    Custom(String),
}

impl SecurityEntityKind {
    pub fn label(&self) -> &str {
        match self {
            Self::User => "User",
            Self::Principal => "Principal",
            Self::ServiceAccount => "ServiceAccount",
            Self::Session => "Session",
            Self::Credential => "Credential",
            Self::Token => "Token",
            Self::Host => "Host",
            Self::Process => "Process",
            Self::Container => "Container",
            Self::Pod => "Pod",
            Self::Ip => "IP",
            Self::Domain => "Domain",
            Self::Service => "Service",
            Self::Application => "Application",
            Self::Database => "Database",
            Self::File => "File",
            Self::CloudResource => "CloudResource",
            Self::Repository => "Repository",
            Self::Pipeline => "Pipeline",
            Self::Custom(value) => value.as_str(),
        }
    }

    pub fn from_label(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "user" => Self::User,
            "principal" => Self::Principal,
            "serviceaccount" | "service_account" | "service-account" => Self::ServiceAccount,
            "session" => Self::Session,
            "credential" => Self::Credential,
            "token" => Self::Token,
            "host" => Self::Host,
            "process" => Self::Process,
            "container" => Self::Container,
            "pod" => Self::Pod,
            "ip" | "address" => Self::Ip,
            "domain" => Self::Domain,
            "service" => Self::Service,
            "application" | "app" => Self::Application,
            "database" | "db" => Self::Database,
            "file" => Self::File,
            "cloudresource" | "cloud_resource" | "cloud-resource" => Self::CloudResource,
            "repository" | "repo" => Self::Repository,
            "pipeline" => Self::Pipeline,
            _ => Self::Custom(value.trim().to_owned()),
        }
    }
}

impl From<&EntityRef> for SecurityEntityKind {
    fn from(entity: &EntityRef) -> Self {
        Self::from_label(&entity.kind)
    }
}

/// Temporal edge kinds named by SPEC-0045 §24.  `ActiveOn` is included for
/// the example chain in §25 even though it is not in the non-exhaustive list.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityEdgeKind {
    AuthenticatedTo,
    CreatedSession,
    AssumedRole,
    Spawned,
    Executed,
    ConnectedTo,
    ResolvedTo,
    Read,
    Wrote,
    Downloaded,
    Uploaded,
    CreatedToken,
    UsedToken,
    EscalatedTo,
    Accessed,
    Queried,
    ExfiltratedTo,
    Modified,
    Deleted,
    ActiveOn,
    Custom(String),
}

impl SecurityEdgeKind {
    pub fn label(&self) -> &str {
        match self {
            Self::AuthenticatedTo => "AUTHENTICATED_TO",
            Self::CreatedSession => "CREATED_SESSION",
            Self::AssumedRole => "ASSUMED_ROLE",
            Self::Spawned => "SPAWNED",
            Self::Executed => "EXECUTED",
            Self::ConnectedTo => "CONNECTED_TO",
            Self::ResolvedTo => "RESOLVED_TO",
            Self::Read => "READ",
            Self::Wrote => "WROTE",
            Self::Downloaded => "DOWNLOADED",
            Self::Uploaded => "UPLOADED",
            Self::CreatedToken => "CREATED_TOKEN",
            Self::UsedToken => "USED_TOKEN",
            Self::EscalatedTo => "ESCALATED_TO",
            Self::Accessed => "ACCESSED",
            Self::Queried => "QUERIED",
            Self::ExfiltratedTo => "EXFILTRATED_TO",
            Self::Modified => "MODIFIED",
            Self::Deleted => "DELETED",
            Self::ActiveOn => "ACTIVE_ON",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Error)]
pub enum CorrelationError {
    #[error("referência de entidade inválida: {0}")]
    InvalidEntity(String),
    #[error("LSN temporal inválido: {0}")]
    InvalidLsn(String),
    #[error("grafo temporal excedeu o limite de {0} arestas")]
    GraphCapacity(usize),
    #[error("incidente excedeu o limite de {0} sinais/evidências")]
    IncidentCapacity(usize),
    #[error("aresta temporal não encontrada: {0}")]
    EdgeNotFound(String),
    #[error("snapshot contém identidade de aresta inválida: {0}")]
    InvalidEdge(String),
    #[error("confiança/score deve ser finito e estar entre 0 e 1")]
    InvalidScore,
    #[error("incidente não encontrado: {0}")]
    IncidentNotFound(String),
    #[error("transição de incidente inválida: {0:?} -> {1:?}")]
    InvalidTransition(IncidentState, IncidentState),
    #[error("fusão sem pesos positivos")]
    InvalidWeights,
}

/// One assertion in the temporal graph.  Evidence is sorted and deduplicated
/// on insertion; the interval is `[valid_from_lsn, valid_to_lsn)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporalSecurityEdge {
    pub edge_id: String,
    pub from: EntityRef,
    pub to: EntityRef,
    pub kind: SecurityEdgeKind,
    pub valid_from_lsn: Lsn,
    pub valid_to_lsn: Option<Lsn>,
    pub evidence: Vec<EvidenceRef>,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GraphEdgeObservation {
    pub from: EntityRef,
    pub to: EntityRef,
    pub kind: SecurityEdgeKind,
    pub evidence: EvidenceRef,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporalSecurityGraphSnapshot {
    pub edges: Vec<TemporalSecurityEdge>,
    pub watermark_lsn: Lsn,
}

/// Bounded temporal graph with deterministic adjacency and AS-OF traversal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporalSecurityGraph {
    edges: BTreeMap<String, TemporalSecurityEdge>,
    watermark_lsn: Lsn,
}

impl Default for TemporalSecurityGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl TemporalSecurityGraph {
    pub fn new() -> Self {
        Self {
            edges: BTreeMap::new(),
            watermark_lsn: 0,
        }
    }

    pub fn watermark_lsn(&self) -> Lsn {
        self.watermark_lsn
    }

    pub fn edges(&self) -> impl Iterator<Item = &TemporalSecurityEdge> {
        self.edges.values()
    }

    /// Assert one edge.  Replaying the same assertion is idempotent and only
    /// merges its evidence; a later assertion creates a new temporal version.
    pub fn assert_edge(
        &mut self,
        lsn: Lsn,
        from: EntityRef,
        to: EntityRef,
        kind: SecurityEdgeKind,
        evidence: EvidenceRef,
    ) -> Result<String, CorrelationError> {
        self.assert_edge_with_confidence(lsn, from, to, kind, evidence, 1.0)
    }

    pub fn assert_edge_with_confidence(
        &mut self,
        lsn: Lsn,
        from: EntityRef,
        to: EntityRef,
        kind: SecurityEdgeKind,
        evidence: EvidenceRef,
        confidence: f32,
    ) -> Result<String, CorrelationError> {
        validate_entity(&from)?;
        validate_entity(&to)?;
        validate_score(confidence)?;
        if evidence.lsn > lsn {
            return Err(CorrelationError::InvalidLsn(format!(
                "evidência está no LSN futuro {} mas a aresta foi observada em {lsn}",
                evidence.lsn
            )));
        }
        let edge_id = edge_id(&from, &to, &kind, lsn);
        if let Some(existing) = self.edges.get_mut(&edge_id) {
            merge_evidence(&mut existing.evidence, evidence);
            existing.confidence = existing.confidence.max(confidence);
        } else {
            if self.edges.len() >= MAX_GRAPH_EDGES {
                return Err(CorrelationError::GraphCapacity(MAX_GRAPH_EDGES));
            }
            self.edges.insert(
                edge_id.clone(),
                TemporalSecurityEdge {
                    edge_id: edge_id.clone(),
                    from,
                    to,
                    kind,
                    valid_from_lsn: lsn,
                    valid_to_lsn: None,
                    evidence: vec![evidence],
                    confidence,
                },
            );
        }
        self.watermark_lsn = self.watermark_lsn.max(lsn);
        Ok(edge_id)
    }

    /// Project and assert all conservative edges emitted by one canonical
    /// event.  The returned IDs are stable and sorted by the graph's identity
    /// hash, making this helper suitable for deterministic replay.
    pub fn apply_security_event(
        &mut self,
        lsn: Lsn,
        event: &SecurityEvent,
    ) -> Result<Vec<String>, CorrelationError> {
        let mut ids = Vec::new();
        for observation in security_event_edges(lsn, event) {
            ids.push(self.assert_edge_with_confidence(
                lsn,
                observation.from,
                observation.to,
                observation.kind,
                observation.evidence,
                observation.confidence,
            )?);
        }
        ids.sort();
        Ok(ids)
    }

    /// Retract an open edge at `lsn`; repeating the same retract is harmless.
    pub fn retract_edge(&mut self, edge_id: &str, lsn: Lsn) -> Result<(), CorrelationError> {
        let edge = self
            .edges
            .get_mut(edge_id)
            .ok_or_else(|| CorrelationError::EdgeNotFound(edge_id.to_owned()))?;
        if lsn < edge.valid_from_lsn {
            return Err(CorrelationError::InvalidLsn(format!(
                "retract {lsn} anterior ao início {}",
                edge.valid_from_lsn
            )));
        }
        match edge.valid_to_lsn {
            Some(existing) if existing != lsn => {
                return Err(CorrelationError::InvalidLsn(format!(
                    "aresta já encerrada no LSN {existing}"
                )))
            }
            Some(_) => {}
            None => edge.valid_to_lsn = Some(lsn),
        }
        self.watermark_lsn = self.watermark_lsn.max(lsn);
        Ok(())
    }

    pub fn edges_as_of(&self, as_of_lsn: Lsn) -> Vec<&TemporalSecurityEdge> {
        self.edges
            .values()
            .filter(|edge| edge.valid_from_lsn <= as_of_lsn)
            .filter(|edge| edge.valid_to_lsn.is_none_or(|end| as_of_lsn < end))
            .collect()
    }

    pub fn neighbors_as_of(&self, from: &EntityRef, as_of_lsn: Lsn) -> Vec<(EntityRef, String)> {
        let from_key = entity_key(from);
        let mut values: Vec<_> = self
            .edges_as_of(as_of_lsn)
            .into_iter()
            .filter(|edge| entity_key(&edge.from) == from_key)
            .map(|edge| (edge.to.clone(), edge.edge_id.clone()))
            .collect();
        values.sort_by(|left, right| {
            entity_key(&left.0)
                .cmp(&entity_key(&right.0))
                .then_with(|| left.1.cmp(&right.1))
        });
        values
    }

    /// Find the lexicographically first shortest path at an AS-OF LSN.
    pub fn find_path(
        &self,
        start: &EntityRef,
        goal: &EntityRef,
        as_of_lsn: Lsn,
        max_depth: usize,
    ) -> Option<GraphPath> {
        let max_depth = max_depth.min(MAX_PATH_DEPTH);
        let start_key = entity_key(start);
        let goal_key = entity_key(goal);
        if start_key == goal_key {
            return Some(GraphPath {
                entities: vec![start.clone()],
                edges: Vec::new(),
            });
        }
        let mut queue = VecDeque::from([(start.clone(), vec![start.clone()], Vec::new())]);
        let mut visited = BTreeSet::from([start_key]);
        while let Some((current, entities, path_edges)) = queue.pop_front() {
            if path_edges.len() >= max_depth {
                continue;
            }
            let mut next = self.neighbors_as_of(&current, as_of_lsn);
            next.sort_by(|left, right| {
                entity_key(&left.0)
                    .cmp(&entity_key(&right.0))
                    .then_with(|| left.1.cmp(&right.1))
            });
            for (entity, edge_id) in next {
                let key = entity_key(&entity);
                if !visited.insert(key.clone()) {
                    continue;
                }
                let mut next_entities = entities.clone();
                next_entities.push(entity.clone());
                let mut next_edges = path_edges.clone();
                next_edges.push(edge_id);
                if key == goal_key {
                    return Some(GraphPath {
                        entities: next_entities,
                        edges: next_edges,
                    });
                }
                queue.push_back((entity, next_entities, next_edges));
            }
        }
        None
    }

    pub fn entities_in_window(&self, start_lsn: Lsn, end_lsn: Lsn) -> Vec<EntityRef> {
        if start_lsn > end_lsn {
            return Vec::new();
        }
        let mut entities = BTreeMap::new();
        for edge in self.edges.values() {
            let overlaps = edge.valid_from_lsn <= end_lsn
                && edge.valid_to_lsn.is_none_or(|end| end > start_lsn);
            if overlaps {
                entities.insert(entity_key(&edge.from), edge.from.clone());
                entities.insert(entity_key(&edge.to), edge.to.clone());
            }
        }
        entities.into_values().collect()
    }

    pub fn snapshot(&self) -> TemporalSecurityGraphSnapshot {
        TemporalSecurityGraphSnapshot {
            edges: self.edges.values().cloned().collect(),
            watermark_lsn: self.watermark_lsn,
        }
    }

    pub fn from_snapshot(
        snapshot: TemporalSecurityGraphSnapshot,
    ) -> Result<Self, CorrelationError> {
        if snapshot.edges.len() > MAX_GRAPH_EDGES {
            return Err(CorrelationError::GraphCapacity(MAX_GRAPH_EDGES));
        }
        let mut graph = Self::new();
        for edge in snapshot.edges {
            validate_entity(&edge.from)?;
            validate_entity(&edge.to)?;
            validate_score(edge.confidence)?;
            if edge.edge_id != edge_id(&edge.from, &edge.to, &edge.kind, edge.valid_from_lsn) {
                return Err(CorrelationError::InvalidEdge(edge.edge_id));
            }
            if edge
                .valid_to_lsn
                .is_some_and(|end| end < edge.valid_from_lsn)
            {
                return Err(CorrelationError::InvalidLsn(edge.edge_id));
            }
            graph.edges.insert(edge.edge_id.clone(), edge);
        }
        graph.watermark_lsn = snapshot.watermark_lsn;
        Ok(graph)
    }
}

/// A path returned by [`TemporalSecurityGraph::find_path`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphPath {
    pub entities: Vec<EntityRef>,
    pub edges: Vec<String>,
}

/// Conservative projection from one canonical event to graph observations.
/// No edge is emitted unless both endpoints are explicitly present.
pub fn security_event_edges(lsn: Lsn, event: &SecurityEvent) -> Vec<GraphEdgeObservation> {
    let evidence_lsn = event
        .attributes
        .get("sec.source_lsn")
        .and_then(|value| value.parse().ok())
        .unwrap_or(lsn);
    let evidence = EvidenceRef {
        lsn: evidence_lsn,
        event_id: event.raw_event_id,
    };
    let mut result = Vec::new();
    let principal = event.principal.clone().or_else(|| event.user.clone());
    let activity = event.activity.to_ascii_lowercase();
    let successful = matches!(event.outcome.label().as_str(), "success" | "allowed");

    if let (Some(user), Some(session)) = (event.user.clone(), attribute_entity(event, "session")) {
        push_observation(
            &mut result,
            user,
            session,
            SecurityEdgeKind::CreatedSession,
            evidence.clone(),
        );
    }
    if let (Some(user), Some(host)) = (
        event.user.clone().or_else(|| event.principal.clone()),
        event.host.clone(),
    ) {
        if matches!(
            &event.category,
            SecurityCategory::Authentication | SecurityCategory::Identity
        ) && successful
        {
            push_observation(
                &mut result,
                user,
                host,
                SecurityEdgeKind::AuthenticatedTo,
                evidence.clone(),
            );
        }
    }
    if let (Some(session), Some(host)) = (attribute_entity(event, "session"), event.host.clone()) {
        push_observation(
            &mut result,
            session,
            host,
            SecurityEdgeKind::ActiveOn,
            evidence.clone(),
        );
    }
    if let (Some(host), Some(process)) = (event.host.clone(), event.process.clone()) {
        if matches!(&event.category, SecurityCategory::Process) || activity.contains("spawn") {
            push_observation(
                &mut result,
                host,
                process,
                SecurityEdgeKind::Spawned,
                evidence.clone(),
            );
        }
    }
    if let (Some(process), Some(dst)) = (event.process.clone(), endpoint_entity(event.dst.as_ref()))
    {
        if matches!(&event.category, SecurityCategory::Network) || event.dst.is_some() {
            push_observation(
                &mut result,
                process,
                dst,
                SecurityEdgeKind::ConnectedTo,
                evidence.clone(),
            );
        }
    }
    if let (Some(principal), Some(resource)) = (principal, attribute_entity(event, "resource")) {
        let kind = activity_edge_kind(&activity);
        push_observation(&mut result, principal, resource, kind, evidence);
    }
    result.sort_by(|left, right| {
        entity_key(&left.from)
            .cmp(&entity_key(&right.from))
            .then_with(|| entity_key(&left.to).cmp(&entity_key(&right.to)))
            .then_with(|| left.kind.label().cmp(right.kind.label()))
    });
    result.dedup_by(|left, right| {
        entity_key(&left.from) == entity_key(&right.from)
            && entity_key(&left.to) == entity_key(&right.to)
            && left.kind == right.kind
    });
    result
}

fn activity_edge_kind(activity: &str) -> SecurityEdgeKind {
    if activity.contains("query") {
        SecurityEdgeKind::Queried
    } else if activity.contains("read") {
        SecurityEdgeKind::Read
    } else if activity.contains("write") {
        SecurityEdgeKind::Wrote
    } else if activity.contains("download") {
        SecurityEdgeKind::Downloaded
    } else if activity.contains("upload") {
        SecurityEdgeKind::Uploaded
    } else if activity.contains("delete") {
        SecurityEdgeKind::Deleted
    } else if activity.contains("modify") || activity.contains("update") {
        SecurityEdgeKind::Modified
    } else if activity.contains("escalat") {
        SecurityEdgeKind::EscalatedTo
    } else {
        SecurityEdgeKind::Accessed
    }
}

fn attribute_entity(event: &SecurityEvent, prefix: &str) -> Option<EntityRef> {
    let id = event
        .attributes
        .get(&format!("{prefix}.id"))
        .or_else(|| event.attributes.get(&format!("{prefix}_id")))?;
    if id.trim().is_empty() {
        return None;
    }
    let kind = event
        .attributes
        .get(&format!("{prefix}.kind"))
        .map(|value| value.as_str())
        .unwrap_or(prefix);
    Some(EntityRef::new(kind, id.trim()))
}

fn endpoint_entity(endpoint: Option<&crate::NetworkEndpoint>) -> Option<EntityRef> {
    let endpoint = endpoint?;
    endpoint
        .ip
        .as_ref()
        .map(|ip| EntityRef::new("IP", ip))
        .or_else(|| {
            endpoint
                .hostname
                .as_ref()
                .map(|host| EntityRef::new("Domain", host))
        })
}

fn push_observation(
    output: &mut Vec<GraphEdgeObservation>,
    from: EntityRef,
    to: EntityRef,
    kind: SecurityEdgeKind,
    evidence: EvidenceRef,
) {
    if from.id.trim().is_empty() || to.id.trim().is_empty() {
        return;
    }
    output.push(GraphEdgeObservation {
        from,
        to,
        kind,
        evidence,
        confidence: 1.0,
    });
}

/// An incident state is monotonic except for the explicit containment branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentState {
    New,
    Enriching,
    Investigating,
    ActionProposed,
    AwaitingApproval,
    Contained,
    Monitoring,
    Resolved,
    FalsePositive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MitreMapping {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: Option<String>,
    pub confidence: f32,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityIncident {
    pub incident_id: String,
    pub state: IncidentState,
    pub severity: u8,
    pub risk_score: f32,
    pub subjects: Vec<EntityRef>,
    pub signals: Vec<String>,
    pub evidence: Vec<EvidenceRef>,
    pub first_seen_lsn: Lsn,
    pub last_seen_lsn: Lsn,
    pub mitre: Vec<MitreMapping>,
}

impl SecurityIncident {
    /// Stable identity for one complete append-only incident revision.  The
    /// incident engine keeps all collections ordered, so the serialized DTO is
    /// canonical for a given deterministic replay.
    pub fn revision_id(&self) -> Result<String, serde_json::Error> {
        let content = serde_json::to_vec(self)?;
        Ok(incident_revision_id(&content))
    }

    /// Persist the current incident state as a derived log episode.  A later
    /// enrichment produces another revision; the previous row is never
    /// mutated.  Raw evidence remains explicit causal provenance.
    pub fn into_episode(&self) -> Result<Episode, serde_json::Error> {
        let content = serde_json::to_vec(self)?;
        let revision_id = incident_revision_id(&content);
        let mut episode = Episode::new(
            "sentinel",
            EventKind::Custom("SecurityIncident".into()),
            content,
        );
        let mut parents: Vec<EventId> = self.evidence.iter().map(|item| item.event_id).collect();
        parents.sort_unstable();
        parents.dedup();
        episode.parents = parents;
        episode
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        episode
            .attrs
            .insert("sentinel.incident_id".into(), self.incident_id.clone());
        episode
            .attrs
            .insert("sentinel.incident_revision_id".into(), revision_id);
        episode.attrs.insert(
            "sentinel.first_seen_lsn".into(),
            self.first_seen_lsn.to_string(),
        );
        episode.attrs.insert(
            "sentinel.last_seen_lsn".into(),
            self.last_seen_lsn.to_string(),
        );
        Ok(episode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentPolicy {
    pub correlation_window_lsns: Lsn,
    pub cooldown_lsns: Lsn,
    pub max_incidents: usize,
    pub max_signals_per_incident: usize,
    pub max_evidence_per_incident: usize,
    pub graph_path_depth: usize,
}

impl Default for IncidentPolicy {
    fn default() -> Self {
        Self {
            correlation_window_lsns: 100,
            cooldown_lsns: 1_000,
            max_incidents: MAX_INCIDENTS,
            max_signals_per_incident: MAX_INCIDENT_SIGNALS,
            max_evidence_per_incident: MAX_INCIDENT_EVIDENCE,
            graph_path_depth: 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentTransition {
    pub incident_id: String,
    pub from: IncidentState,
    pub to: IncidentState,
    pub at_lsn: Lsn,
}

impl IncidentTransition {
    pub fn transition_id(&self) -> Result<String, serde_json::Error> {
        let content = serde_json::to_vec(self)?;
        Ok(incident_transition_id(&content))
    }

    /// State changes are independent append-only records.  Runtime policy
    /// adapters can use this without gaining a mutable incident-store escape
    /// hatch.
    pub fn into_episode(&self) -> Result<Episode, serde_json::Error> {
        let content = serde_json::to_vec(self)?;
        let transition_id = incident_transition_id(&content);
        let mut episode = Episode::new(
            "sentinel",
            EventKind::Custom("SecurityIncidentTransition".into()),
            content,
        );
        episode
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        episode
            .attrs
            .insert("sentinel.incident_id".into(), self.incident_id.clone());
        episode
            .attrs
            .insert("sentinel.incident_transition_id".into(), transition_id);
        episode
            .attrs
            .insert("sentinel.transition_lsn".into(), self.at_lsn.to_string());
        Ok(episode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentIngestResult {
    pub incident_id: String,
    pub created: bool,
    pub enriched: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentEngineSnapshot {
    pub policy: IncidentPolicy,
    pub incidents: Vec<SecurityIncident>,
    pub signal_index: BTreeMap<String, String>,
    pub transitions: Vec<IncidentTransition>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentEngine {
    policy: IncidentPolicy,
    incidents: BTreeMap<String, SecurityIncident>,
    signal_index: BTreeMap<String, String>,
    transitions: Vec<IncidentTransition>,
}

impl IncidentEngine {
    pub fn new(policy: IncidentPolicy) -> Self {
        Self {
            policy,
            incidents: BTreeMap::new(),
            signal_index: BTreeMap::new(),
            transitions: Vec::new(),
        }
    }

    pub fn policy(&self) -> &IncidentPolicy {
        &self.policy
    }

    pub fn incidents(&self) -> impl Iterator<Item = &SecurityIncident> {
        self.incidents.values()
    }

    pub fn incident(&self, incident_id: &str) -> Option<&SecurityIncident> {
        self.incidents.get(incident_id)
    }

    pub fn transitions(&self) -> &[IncidentTransition] {
        &self.transitions
    }

    pub fn ingest_signal(
        &mut self,
        signal: &SecuritySignal,
    ) -> Result<IncidentIngestResult, CorrelationError> {
        self.ingest_signal_with_graph(signal, None)
    }

    pub fn ingest_signal_with_graph(
        &mut self,
        signal: &SecuritySignal,
        graph: Option<&TemporalSecurityGraph>,
    ) -> Result<IncidentIngestResult, CorrelationError> {
        self.ingest_signal_with_graph_as_of(signal, graph, signal.created_at_lsn)
    }

    /// Correlate using the graph state known at the signal episode's
    /// transaction LSN while preserving `signal.created_at_lsn` as evidence
    /// time.  Runtime replay needs both clocks to avoid seeing future graph
    /// knowledge or hiding a graph edge persisted just after its raw evidence.
    pub fn ingest_signal_with_graph_as_of(
        &mut self,
        signal: &SecuritySignal,
        graph: Option<&TemporalSecurityGraph>,
        graph_as_of_lsn: Lsn,
    ) -> Result<IncidentIngestResult, CorrelationError> {
        validate_score(signal.score)?;
        if let Some(existing) = self.signal_index.get(&signal.signal_id) {
            return Ok(IncidentIngestResult {
                incident_id: existing.clone(),
                created: false,
                enriched: false,
            });
        }
        let subject_key = signal.subject.as_ref().map(entity_key);
        let mut candidates = Vec::new();
        for (id, incident) in &self.incidents {
            let within_window = lsn_distance(incident.last_seen_lsn, signal.created_at_lsn)
                <= self.policy.correlation_window_lsns;
            let shared_subject = subject_key.as_ref().is_some_and(|key| {
                incident
                    .subjects
                    .iter()
                    .any(|subject| entity_key(subject) == *key)
            });
            let shared_evidence = signal
                .evidence
                .iter()
                .any(|evidence| incident.evidence.contains(evidence));
            let graph_related = match (graph, signal.subject.as_ref()) {
                (Some(graph), Some(subject)) => incident.subjects.iter().any(|other| {
                    graph
                        .find_path(
                            subject,
                            other,
                            graph_as_of_lsn,
                            self.policy.graph_path_depth,
                        )
                        .is_some()
                        || graph
                            .find_path(
                                other,
                                subject,
                                graph_as_of_lsn,
                                self.policy.graph_path_depth,
                            )
                            .is_some()
                }),
                _ => false,
            };
            let cooldown_ok = signal.created_at_lsn
                <= incident
                    .last_seen_lsn
                    .saturating_add(self.policy.cooldown_lsns)
                || incident.last_seen_lsn
                    <= signal
                        .created_at_lsn
                        .saturating_add(self.policy.cooldown_lsns);
            if cooldown_ok
                && (shared_subject || shared_evidence || (within_window && graph_related))
            {
                candidates.push(id.clone());
            }
        }
        let selected_id = candidates
            .into_iter()
            .min()
            .unwrap_or_else(|| incident_id_for(signal, self.policy.correlation_window_lsns));
        let mut incident_id = selected_id.clone();
        // Replay normally arrives in LSN order, but Gate C2 also exercises
        // permutations.  Canonicalise to the earliest signal for a candidate
        // before any append-only transition exists; this makes the final
        // logical incident independent of arrival order without rewriting a
        // transitioned incident.
        if let Some(existing) = self.incidents.get(&selected_id) {
            if existing.first_seen_lsn > signal.created_at_lsn
                && !self
                    .transitions
                    .iter()
                    .any(|transition| transition.incident_id == selected_id)
            {
                let canonical_id = incident_id_for(signal, self.policy.correlation_window_lsns);
                if canonical_id != selected_id && !self.incidents.contains_key(&canonical_id) {
                    let mut incident = self
                        .incidents
                        .remove(&selected_id)
                        .expect("selected incident exists");
                    incident.incident_id = canonical_id.clone();
                    for value in self.signal_index.values_mut() {
                        if value == &selected_id {
                            *value = canonical_id.clone();
                        }
                    }
                    incident_id = canonical_id;
                    self.incidents.insert(incident_id.clone(), incident);
                }
            }
        }
        let created = !self.incidents.contains_key(&incident_id);
        if created {
            if self.incidents.len() >= self.policy.max_incidents {
                return Err(CorrelationError::IncidentCapacity(
                    self.policy.max_incidents,
                ));
            }
            self.incidents.insert(
                incident_id.clone(),
                SecurityIncident {
                    incident_id: incident_id.clone(),
                    state: IncidentState::New,
                    severity: signal.severity,
                    risk_score: signal.score,
                    subjects: signal.subject.clone().into_iter().collect(),
                    signals: vec![signal.signal_id.clone()],
                    evidence: sorted_evidence(signal.evidence.clone())
                        .into_iter()
                        .take(self.policy.max_evidence_per_incident)
                        .collect(),
                    first_seen_lsn: signal.created_at_lsn,
                    last_seen_lsn: signal.created_at_lsn,
                    mitre: mitre_from_signal(signal),
                },
            );
        } else {
            let incident = self
                .incidents
                .get_mut(&incident_id)
                .expect("candidate incident exists");
            incident.severity = incident.severity.max(signal.severity);
            incident.risk_score = incident.risk_score.max(signal.score);
            if let Some(subject) = signal.subject.clone() {
                incident.subjects.push(subject);
                incident.subjects.sort_by_key(entity_key);
                incident
                    .subjects
                    .dedup_by(|left, right| entity_key(left) == entity_key(right));
            }
            if incident.signals.len() >= self.policy.max_signals_per_incident {
                return Err(CorrelationError::IncidentCapacity(
                    self.policy.max_signals_per_incident,
                ));
            }
            incident.signals.push(signal.signal_id.clone());
            incident.signals.sort();
            incident.signals.dedup();
            for evidence in &signal.evidence {
                if incident.evidence.len() < self.policy.max_evidence_per_incident {
                    merge_evidence(&mut incident.evidence, evidence.clone());
                }
            }
            incident.first_seen_lsn = incident.first_seen_lsn.min(signal.created_at_lsn);
            incident.last_seen_lsn = incident.last_seen_lsn.max(signal.created_at_lsn);
            incident.mitre.extend(mitre_from_signal(signal));
            incident
                .mitre
                .sort_by(|left, right| left.technique_id.cmp(&right.technique_id));
            incident
                .mitre
                .dedup_by(|left, right| left.technique_id == right.technique_id);
        }
        self.signal_index
            .insert(signal.signal_id.clone(), incident_id.clone());
        Ok(IncidentIngestResult {
            incident_id,
            created,
            enriched: !created,
        })
    }

    pub fn transition(
        &mut self,
        incident_id: &str,
        to: IncidentState,
        at_lsn: Lsn,
    ) -> Result<IncidentTransition, CorrelationError> {
        if self
            .transitions
            .iter()
            .rev()
            .find(|transition| transition.incident_id == incident_id)
            .is_some_and(|transition| at_lsn < transition.at_lsn)
        {
            return Err(CorrelationError::InvalidLsn(format!(
                "transição no LSN {at_lsn} é anterior à última transição"
            )));
        }
        let incident = self
            .incidents
            .get_mut(incident_id)
            .ok_or_else(|| CorrelationError::IncidentNotFound(incident_id.to_owned()))?;
        let from = incident.state;
        if from == to {
            return Ok(IncidentTransition {
                incident_id: incident_id.to_owned(),
                from,
                to,
                at_lsn,
            });
        }
        if !valid_transition(from, to) {
            return Err(CorrelationError::InvalidTransition(from, to));
        }
        incident.state = to;
        let transition = IncidentTransition {
            incident_id: incident_id.to_owned(),
            from,
            to,
            at_lsn,
        };
        self.transitions.push(transition.clone());
        Ok(transition)
    }

    pub fn snapshot(&self) -> IncidentEngineSnapshot {
        IncidentEngineSnapshot {
            policy: self.policy.clone(),
            incidents: self.incidents.values().cloned().collect(),
            signal_index: self.signal_index.clone(),
            transitions: self.transitions.clone(),
        }
    }

    pub fn from_snapshot(snapshot: IncidentEngineSnapshot) -> Result<Self, CorrelationError> {
        if snapshot.incidents.len() > snapshot.policy.max_incidents {
            return Err(CorrelationError::IncidentCapacity(
                snapshot.policy.max_incidents,
            ));
        }
        let mut engine = Self::new(snapshot.policy);
        for incident in snapshot.incidents {
            validate_score(incident.risk_score)?;
            engine
                .incidents
                .insert(incident.incident_id.clone(), incident);
        }
        engine.signal_index = snapshot.signal_index;
        engine.transitions = snapshot.transitions;
        Ok(engine)
    }
}

fn valid_transition(from: IncidentState, to: IncidentState) -> bool {
    matches!(
        (from, to),
        (
            IncidentState::New,
            IncidentState::Enriching | IncidentState::FalsePositive
        ) | (
            IncidentState::Enriching,
            IncidentState::Investigating | IncidentState::FalsePositive
        ) | (
            IncidentState::Investigating,
            IncidentState::ActionProposed | IncidentState::FalsePositive
        ) | (
            IncidentState::ActionProposed,
            IncidentState::AwaitingApproval | IncidentState::FalsePositive
        ) | (
            IncidentState::AwaitingApproval,
            IncidentState::Contained | IncidentState::Monitoring | IncidentState::FalsePositive
        ) | (
            IncidentState::Contained,
            IncidentState::Monitoring | IncidentState::Resolved
        ) | (IncidentState::Monitoring, IncidentState::Resolved)
    )
}

fn incident_id_for(signal: &SecuritySignal, window: Lsn) -> String {
    let mut bytes = Vec::new();
    append_part(&mut bytes, b"incident-v1");
    if let Some(subject) = signal.subject.as_ref() {
        append_part(&mut bytes, entity_key(subject).as_bytes());
    } else if let Some(evidence) = signal.evidence.iter().min_by(|left, right| {
        left.lsn
            .cmp(&right.lsn)
            .then_with(|| left.event_id.cmp(&right.event_id))
    }) {
        append_part(&mut bytes, evidence.event_id.to_string().as_bytes());
    } else {
        append_part(&mut bytes, b"<none>");
    }
    // `window` is kept in the signature so callers can use one canonical
    // policy API; the exact earliest LSN is what permits order-independent
    // grouping when a set straddles a coarse window boundary.
    let _ = window;
    append_part(&mut bytes, &signal.created_at_lsn.to_le_bytes());
    format!("inc-{}", blake3::hash(&bytes).to_hex())
}

fn mitre_from_signal(signal: &SecuritySignal) -> Vec<MitreMapping> {
    let Some(technique_id) = signal.labels.get("mitre.technique_id") else {
        return Vec::new();
    };
    vec![MitreMapping {
        tactic: signal
            .labels
            .get("mitre.tactic")
            .cloned()
            .unwrap_or_default(),
        technique_id: technique_id.clone(),
        technique_name: signal.labels.get("mitre.technique_name").cloned(),
        confidence: signal.score,
        evidence: sorted_evidence(signal.evidence.clone()),
    }]
}

/// Versioned, monotonic weighted score fusion from SPEC-0045 §26–28.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FusionWeights {
    pub rule: f32,
    pub behavioral: f32,
    pub graph: f32,
    pub threat_intel: f32,
}

impl Default for FusionWeights {
    fn default() -> Self {
        Self {
            rule: 0.35,
            behavioral: 0.25,
            graph: 0.25,
            threat_intel: 0.15,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub subject: EntityRef,
    pub rule_score: f32,
    pub behavioral_score: f32,
    pub graph_score: f32,
    pub threat_intel_score: f32,
    pub fused_score: f32,
    pub evidence: Vec<EvidenceRef>,
    pub model_version: String,
}

impl RiskAssessment {
    /// Stable identity for an append-only risk assessment revision.
    pub fn revision_id(&self) -> Result<String, serde_json::Error> {
        Ok(risk_revision_id(&serde_json::to_vec(self)?))
    }

    /// Persist a versioned assessment with only its evidence IDs as causal
    /// parents. The assessment is derived data and never replaces the signal.
    pub fn into_episode(&self) -> Result<Episode, serde_json::Error> {
        let content = serde_json::to_vec(self)?;
        let revision_id = risk_revision_id(&content);
        let mut episode = Episode::new(
            "sentinel",
            EventKind::Custom("SecurityRiskAssessment".into()),
            content,
        );
        let mut parents: Vec<EventId> = self.evidence.iter().map(|item| item.event_id).collect();
        parents.sort_unstable();
        parents.dedup();
        episode.parents = parents;
        episode
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        episode
            .attrs
            .insert("sentinel.risk_revision_id".into(), revision_id);
        episode.attrs.insert(
            "sentinel.risk_model_version".into(),
            self.model_version.clone(),
        );
        episode.attrs.insert(
            "sentinel.risk_score_bps".into(),
            (self.fused_score.clamp(0.0, 1.0) * 10_000.0)
                .round()
                .to_string(),
        );
        Ok(episode)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceFusion {
    pub weights: FusionWeights,
    pub model_version: String,
}

impl EvidenceFusion {
    pub fn new(
        weights: FusionWeights,
        model_version: impl Into<String>,
    ) -> Result<Self, CorrelationError> {
        let sum = weights.rule + weights.behavioral + weights.graph + weights.threat_intel;
        if !sum.is_finite()
            || sum <= 0.0
            || [
                weights.rule,
                weights.behavioral,
                weights.graph,
                weights.threat_intel,
            ]
            .iter()
            .any(|weight| !weight.is_finite() || *weight < 0.0)
        {
            return Err(CorrelationError::InvalidWeights);
        }
        Ok(Self {
            weights,
            model_version: model_version.into(),
        })
    }

    pub fn fuse(
        &self,
        subject: EntityRef,
        rule_score: f32,
        behavioral_score: f32,
        graph_score: f32,
        threat_intel_score: f32,
        evidence: Vec<EvidenceRef>,
    ) -> Result<RiskAssessment, CorrelationError> {
        for score in [
            rule_score,
            behavioral_score,
            graph_score,
            threat_intel_score,
        ] {
            validate_score(score)?;
        }
        validate_entity(&subject)?;
        let fused_score = (self.weights.rule * rule_score
            + self.weights.behavioral * behavioral_score
            + self.weights.graph * graph_score
            + self.weights.threat_intel * threat_intel_score)
            .clamp(0.0, 1.0);
        Ok(RiskAssessment {
            subject,
            rule_score,
            behavioral_score,
            graph_score,
            threat_intel_score,
            fused_score: fused_score.clamp(0.0, 1.0),
            evidence: sorted_evidence(evidence),
            model_version: self.model_version.clone(),
        })
    }

    pub fn high_impact_allowed(
        assessment: &RiskAssessment,
        detectors: &[DetectorAgreement],
    ) -> bool {
        if assessment.fused_score < 0.90 {
            return false;
        }
        independent_detector_count(detectors) >= 2
            && detectors.iter().any(|detector| {
                matches!(
                    detector.channel,
                    DetectorChannel::Rule | DetectorChannel::Graph
                )
            })
    }
}

/// Number of distinct detector identities contributing to an assessment.
pub fn independent_detector_count(detectors: &[DetectorAgreement]) -> usize {
    detectors
        .iter()
        .map(|detector| detector.detector_id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

/// Free-function form of [`EvidenceFusion::high_impact_allowed`].
pub fn high_impact_allowed(assessment: &RiskAssessment, detectors: &[DetectorAgreement]) -> bool {
    EvidenceFusion::high_impact_allowed(assessment, detectors)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectorChannel {
    Rule,
    Behavioral,
    Graph,
    ThreatIntel,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorAgreement {
    pub detector_id: String,
    pub channel: DetectorChannel,
}

fn validate_entity(entity: &EntityRef) -> Result<(), CorrelationError> {
    if entity.kind.trim().is_empty() || entity.id.trim().is_empty() {
        return Err(CorrelationError::InvalidEntity(format!(
            "{}:{:?}",
            entity.kind, entity.id
        )));
    }
    Ok(())
}

fn validate_score(score: f32) -> Result<(), CorrelationError> {
    if score.is_finite() && (0.0..=1.0).contains(&score) {
        Ok(())
    } else {
        Err(CorrelationError::InvalidScore)
    }
}

fn entity_key(entity: &EntityRef) -> String {
    // Include both lengths so an ID containing `:` cannot collide with a
    // different kind/ID pair when used as a BTree key or hash input.
    format!(
        "{}:{}:{}:{}",
        entity.kind.len(),
        entity.kind,
        entity.id.len(),
        entity.id
    )
}

fn edge_id(from: &EntityRef, to: &EntityRef, kind: &SecurityEdgeKind, lsn: Lsn) -> String {
    let mut bytes = Vec::new();
    append_part(&mut bytes, entity_key(from).as_bytes());
    append_part(&mut bytes, entity_key(to).as_bytes());
    append_part(&mut bytes, kind.label().as_bytes());
    append_part(&mut bytes, &lsn.to_le_bytes());
    format!("edge-{}", blake3::hash(&bytes).to_hex())
}

fn incident_revision_id(content: &[u8]) -> String {
    let mut bytes = Vec::new();
    append_part(&mut bytes, b"security-incident-revision-v1");
    append_part(&mut bytes, content);
    format!("inc-rev-{}", blake3::hash(&bytes).to_hex())
}

fn incident_transition_id(content: &[u8]) -> String {
    let mut bytes = Vec::new();
    append_part(&mut bytes, b"security-incident-transition-v1");
    append_part(&mut bytes, content);
    format!("inc-tx-{}", blake3::hash(&bytes).to_hex())
}

fn risk_revision_id(content: &[u8]) -> String {
    let mut bytes = Vec::new();
    append_part(&mut bytes, b"security-risk-assessment-v1");
    append_part(&mut bytes, content);
    format!("risk-rev-{}", blake3::hash(&bytes).to_hex())
}

fn append_part(output: &mut Vec<u8>, part: &[u8]) {
    output.extend_from_slice(&(part.len() as u64).to_le_bytes());
    output.extend_from_slice(part);
}

fn merge_evidence(evidence: &mut Vec<EvidenceRef>, item: EvidenceRef) {
    if !evidence.contains(&item) {
        evidence.push(item);
        evidence.sort_by(|left, right| {
            left.lsn
                .cmp(&right.lsn)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
    }
}

fn sorted_evidence(mut evidence: Vec<EvidenceRef>) -> Vec<EvidenceRef> {
    evidence.sort_by(|left, right| {
        left.lsn
            .cmp(&right.lsn)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    evidence.dedup();
    evidence
}

fn lsn_distance(left: Lsn, right: Lsn) -> Lsn {
    left.abs_diff(right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{DetectorIdentity, Outcome, SecuritySource};
    use heraclitus_core::EventId;

    fn entity(kind: &str, id: &str) -> EntityRef {
        EntityRef::new(kind, id)
    }

    fn evidence(lsn: Lsn) -> EvidenceRef {
        EvidenceRef {
            lsn,
            event_id: EventId::new(),
        }
    }

    fn signal(id: &str, lsn: Lsn, subject: Option<EntityRef>, score: f32) -> SecuritySignal {
        SecuritySignal {
            signal_id: id.into(),
            detector: DetectorIdentity {
                id: "rule.test".into(),
                version: "1".into(),
            },
            severity: 5,
            score,
            subject,
            evidence: vec![evidence(lsn)],
            created_at_lsn: lsn,
            labels: BTreeMap::new(),
        }
    }

    #[test]
    fn incident_episode_has_stable_revision_and_causal_parents() {
        let mut engine = IncidentEngine::new(IncidentPolicy::default());
        let input = signal("sig-a", 7, Some(entity("User", "alice")), 0.8);
        let incident_id = engine.ingest_signal(&input).unwrap().incident_id;
        let incident = engine.incident(&incident_id).unwrap().clone();

        let first = incident.into_episode().unwrap();
        let second = incident.into_episode().unwrap();
        assert_eq!(
            first.attrs["sentinel.incident_revision_id"],
            second.attrs["sentinel.incident_revision_id"]
        );
        assert_eq!(
            first.attrs["sentinel.incident_revision_id"],
            incident.revision_id().unwrap()
        );
        assert_eq!(first.attrs["sentinel.incident_id"], incident_id);
        assert_eq!(first.parents, second.parents);
        assert_eq!(
            serde_json::from_slice::<SecurityIncident>(&first.content).unwrap(),
            incident
        );
    }

    #[test]
    fn incident_transition_episode_identity_changes_with_state() {
        let base = IncidentTransition {
            incident_id: "inc-a".into(),
            from: IncidentState::New,
            to: IncidentState::Enriching,
            at_lsn: 9,
        };
        let same = base.clone();
        let later = IncidentTransition {
            to: IncidentState::Investigating,
            from: IncidentState::Enriching,
            ..base.clone()
        };
        assert_eq!(base.transition_id().unwrap(), same.transition_id().unwrap());
        assert_ne!(
            base.transition_id().unwrap(),
            later.transition_id().unwrap()
        );
        let episode = base.into_episode().unwrap();
        assert_eq!(
            episode.kind,
            EventKind::Custom("SecurityIncidentTransition".into())
        );
    }

    #[test]
    fn risk_assessment_episode_is_versioned_and_causally_bounded() {
        let ev = evidence(3);
        let assessment = RiskAssessment {
            subject: entity("User", "alice"),
            rule_score: 0.9,
            behavioral_score: 0.7,
            graph_score: 0.2,
            threat_intel_score: 0.0,
            fused_score: 0.64,
            evidence: vec![ev.clone(), ev],
            model_version: "fusion-v1".into(),
        };
        let first = assessment.into_episode().unwrap();
        let second = assessment.into_episode().unwrap();
        assert_eq!(first.kind, second.kind);
        assert_eq!(first.content, second.content);
        assert_eq!(first.parents, second.parents);
        assert_eq!(first.attrs, second.attrs);
        assert_eq!(first.parents.len(), 1);
        assert_eq!(
            first.attrs["sentinel.risk_revision_id"],
            assessment.revision_id().unwrap()
        );
        assert_eq!(
            first.kind,
            EventKind::Custom("SecurityRiskAssessment".into())
        );
    }

    #[test]
    fn incident_graph_correlation_uses_transaction_lsn_not_evidence_time() {
        let user = entity("User", "alice");
        let host = entity("Host", "db01");
        let mut graph = TemporalSecurityGraph::new();
        graph
            .assert_edge(
                20,
                user.clone(),
                host.clone(),
                SecurityEdgeKind::AuthenticatedTo,
                evidence(10),
            )
            .unwrap();
        let user_signal = signal("sig-user", 10, Some(user), 0.7);
        let host_signal = signal("sig-host", 11, Some(host), 0.8);

        let mut before_knowledge = IncidentEngine::new(IncidentPolicy::default());
        let first = before_knowledge
            .ingest_signal_with_graph_as_of(&user_signal, Some(&graph), 19)
            .unwrap();
        let second = before_knowledge
            .ingest_signal_with_graph_as_of(&host_signal, Some(&graph), 19)
            .unwrap();
        assert_ne!(first.incident_id, second.incident_id);

        let mut after_knowledge = IncidentEngine::new(IncidentPolicy::default());
        let first = after_knowledge
            .ingest_signal_with_graph_as_of(&user_signal, Some(&graph), 19)
            .unwrap();
        let second = after_knowledge
            .ingest_signal_with_graph_as_of(&host_signal, Some(&graph), 20)
            .unwrap();
        assert_eq!(first.incident_id, second.incident_id);
    }

    #[test]
    fn graph_is_idempotent_temporal_and_as_of() {
        let mut graph = TemporalSecurityGraph::new();
        let a = entity("User", "alice");
        let b = entity("Host", "ws17");
        let ev = evidence(10);
        let id = graph
            .assert_edge(
                10,
                a.clone(),
                b.clone(),
                SecurityEdgeKind::AuthenticatedTo,
                ev.clone(),
            )
            .unwrap();
        graph
            .assert_edge(
                10,
                a.clone(),
                b.clone(),
                SecurityEdgeKind::AuthenticatedTo,
                ev,
            )
            .unwrap();
        assert_eq!(graph.edges().count(), 1);
        assert!(graph.find_path(&a, &b, 10, 2).is_some());
        graph.retract_edge(&id, 20).unwrap();
        assert!(graph.find_path(&a, &b, 19, 2).is_some());
        assert!(graph.find_path(&a, &b, 20, 2).is_none());
    }

    #[test]
    fn edge_identity_is_not_ambiguous_for_delimited_entity_ids() {
        let mut graph = TemporalSecurityGraph::new();
        let to = entity("Host", "ws17");
        let left = graph
            .assert_edge(
                1,
                entity("A", "B:C"),
                to.clone(),
                SecurityEdgeKind::Accessed,
                evidence(1),
            )
            .unwrap();
        let right = graph
            .assert_edge(
                1,
                entity("A:B", "C"),
                to,
                SecurityEdgeKind::Accessed,
                evidence(1),
            )
            .unwrap();
        assert_ne!(left, right);
    }

    #[test]
    fn event_projection_does_not_invent_missing_endpoints() {
        let raw = EventId::new();
        let event = SecurityEvent {
            schema_version: 1,
            type_uid: 0,
            source: SecuritySource::Application,
            category: SecurityCategory::Authentication,
            activity: "login".into(),
            principal: None,
            user: Some(entity("User", "alice")),
            host: None,
            process: None,
            src: None,
            dst: None,
            outcome: Outcome::Success,
            severity: 1,
            observed_at: 0,
            raw_event_id: raw,
            attributes: BTreeMap::new(),
        };
        assert!(security_event_edges(7, &event).is_empty());
    }

    #[test]
    fn incident_grouping_is_idempotent_and_order_stable() {
        let subject = entity("User", "alice");
        let first = signal("s1", 100, Some(subject.clone()), 0.7);
        let second = signal("s2", 110, Some(subject), 0.9);
        let mut left = IncidentEngine::new(IncidentPolicy::default());
        let left_id = left.ingest_signal(&first).unwrap().incident_id;
        left.ingest_signal(&second).unwrap();
        let mut right = IncidentEngine::new(IncidentPolicy::default());
        right.ingest_signal(&second).unwrap();
        let right_id = right.ingest_signal(&first).unwrap().incident_id;
        assert_eq!(left_id, right_id);
        assert!(!left.ingest_signal(&first).unwrap().enriched);
        assert_eq!(left.incidents().next().unwrap().signals, vec!["s1", "s2"]);
        assert_eq!(left.incidents().next().unwrap().risk_score, 0.9);
    }

    #[test]
    fn incident_id_canonicalises_an_earlier_signal_and_separates_unrelated_events() {
        let subject = entity("User", "alice");
        let earlier = signal("early", 100, Some(subject.clone()), 0.4);
        let later = signal("late", 199, Some(subject), 0.8);
        let mut engine = IncidentEngine::new(IncidentPolicy {
            correlation_window_lsns: 100,
            ..IncidentPolicy::default()
        });
        let later_id = engine.ingest_signal(&later).unwrap().incident_id;
        let early_id = engine.ingest_signal(&earlier).unwrap().incident_id;
        assert_ne!(later_id, early_id);
        assert_eq!(engine.incidents().count(), 1);
        let unrelated = signal("other", 100, None, 0.2);
        let other_id = engine.ingest_signal(&unrelated).unwrap().incident_id;
        assert_ne!(early_id, other_id);
        assert_eq!(engine.incidents().count(), 2);
    }

    #[test]
    fn incident_transitions_are_restricted_and_recorded() {
        let mut engine = IncidentEngine::new(IncidentPolicy::default());
        let id = engine
            .ingest_signal(&signal("s", 1, None, 0.5))
            .unwrap()
            .incident_id;
        assert!(engine.transition(&id, IncidentState::Resolved, 2).is_err());
        engine.transition(&id, IncidentState::Enriching, 2).unwrap();
        assert_eq!(engine.transitions().len(), 1);
    }

    #[test]
    fn fusion_is_versioned_monotonic_and_requires_independence() {
        let fusion = EvidenceFusion::new(FusionWeights::default(), "fusion-v1").unwrap();
        let assessment = fusion
            .fuse(entity("User", "alice"), 1.0, 0.0, 1.0, 0.0, vec![])
            .unwrap();
        assert_eq!(assessment.model_version, "fusion-v1");
        assert!((assessment.fused_score - 0.60).abs() < 0.0001);
        assert!(!EvidenceFusion::high_impact_allowed(
            &assessment,
            &[DetectorAgreement {
                detector_id: "r".into(),
                channel: DetectorChannel::Rule
            }]
        ));
        let high_assessment = fusion
            .fuse(entity("User", "alice"), 1.0, 1.0, 1.0, 1.0, vec![])
            .unwrap();
        assert!(EvidenceFusion::high_impact_allowed(
            &high_assessment,
            &[
                DetectorAgreement {
                    detector_id: "r".into(),
                    channel: DetectorChannel::Rule
                },
                DetectorAgreement {
                    detector_id: "g".into(),
                    channel: DetectorChannel::Graph
                },
            ]
        ));
    }

    #[test]
    fn snapshots_round_trip() {
        let mut graph = TemporalSecurityGraph::new();
        graph
            .assert_edge(
                1,
                entity("A", "a"),
                entity("B", "b"),
                SecurityEdgeKind::Custom("x".into()),
                evidence(1),
            )
            .unwrap();
        let restored = TemporalSecurityGraph::from_snapshot(graph.snapshot()).unwrap();
        assert_eq!(graph, restored);
        let mut engine = IncidentEngine::new(IncidentPolicy::default());
        engine.ingest_signal(&signal("s", 1, None, 0.5)).unwrap();
        let restored_engine = IncidentEngine::from_snapshot(engine.snapshot()).unwrap();
        assert_eq!(engine, restored_engine);
    }
}
