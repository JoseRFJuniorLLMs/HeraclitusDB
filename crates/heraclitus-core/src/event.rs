use crate::id::{EventId, FactId, Lsn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A point on the learned product manifold `P = H^a(k1) x S^b(k2) x E^c`.
///
/// The struct lives in `core` (not `manifold`) so that every crate can carry
/// embeddings without depending on the geometry engine. All *operations* on
/// points live in `heraclitus-manifold`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProductPoint {
    /// Poincaré-ball component, `norm < 1`, curvature k1 < 0.
    pub hyp: Vec<f32>,
    /// Unit-sphere component, `norm = 1`, curvature k2 > 0.
    pub sph: Vec<f32>,
    /// Euclidean component.
    pub euc: Vec<f32>,
}

impl ProductPoint {
    pub fn dims(&self) -> (usize, usize, usize) {
        (self.hyp.len(), self.sph.len(), self.euc.len())
    }

    pub fn is_empty(&self) -> bool {
        self.hyp.is_empty() && self.sph.is_empty() && self.euc.is_empty()
    }
}

/// What kind of episode this is. The engine is agnostic; kinds exist so that
/// views and compaction can route without parsing `content`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    Observation,
    Action,
    Message,
    /// Reranker training signal, persisted as an ordinary event (§3.8).
    RetrievalFeedback,
    /// A semantic fact distilled by compaction (§3.9). Payload = `Fact`.
    FactDerived,
    /// Cryptographic receipt of cold-tier demotion (§3.10).
    DemotionReceipt,
    Custom(String),
    /// SPEC-027 — endogenous telemetry sample, persisted as an ordinary event
    /// so the database can query its own vitals through the normal engine.
    ///
    /// MUST stay LAST: enum variants serialize by positional discriminant, so a
    /// mid-enum insertion shifts `Custom` (6→7) and breaks deserialization of
    /// already-written data. Appending keeps every pre-existing discriminant.
    SystemMetric,
}

/// The unit of truth. Episodes are appended to the log and never mutated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Episode {
    pub id: EventId,
    pub ts_hlc: u64,
    pub agent_id: String,
    pub session_id: String,
    pub kind: EventKind,
    #[serde(with = "serde_bytes_vec")]
    pub content: Vec<u8>,
    pub embedding: Option<ProductPoint>,
    pub attrs: BTreeMap<String, String>,
    /// Causal parents (explicit provenance edges between episodes).
    pub parents: Vec<EventId>,
    /// Bi-temporalidade NATIVA (FORMAT v4, SQL:2011/XTDB): desde quando o
    /// facto é válido NO MUNDO (valid time), distinto do `ts_hlc`/LSN
    /// (transaction time — quando foi gravado). `None` = desde sempre.
    /// Intervalo meio-aberto `[valid_from, valid_to)`.
    pub valid_from: Option<u64>,
    /// Fim da validade no mundo. `None` = ainda válido.
    pub valid_to: Option<u64>,
}

impl Episode {
    pub fn new(agent_id: impl Into<String>, kind: EventKind, content: Vec<u8>) -> Self {
        Self {
            id: EventId::new(),
            ts_hlc: 0,
            agent_id: agent_id.into(),
            session_id: String::new(),
            kind,
            content,
            embedding: None,
            attrs: BTreeMap::new(),
            parents: Vec::new(),
            valid_from: None,
            valid_to: None,
        }
    }
}

/// A semantic fact derived from episodes by `heraclitus-distill`.
/// Facts are *also* log events (kind = `FactDerived`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    pub id: FactId,
    pub statement: String,
    pub embedding: Option<ProductPoint>,
    pub confidence: f32,
    /// The episodes this fact was distilled from. Never empty.
    pub provenance: Vec<EventId>,
    pub derived_at_lsn: Lsn,
}

// Plain Vec<u8> serde (kept as a module for future zero-copy swap).
mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        v.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}
