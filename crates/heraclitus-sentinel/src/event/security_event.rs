//! Canonical L0 security event.
//!
//! The type intentionally lives in the Sentinel crate for now, while all
//! persistence still uses the stable `EventKind::Custom` escape hatch.  That
//! keeps the core event enum wire-compatible with existing databases.

use heraclitus_core::{Episode, EventId, EventKind, Lsn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Origin of a raw security observation.  Unknown integrations are carried as
/// `Custom` rather than being silently mapped to a guessed product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecuritySource {
    Auditd,
    WindowsEventLog,
    CloudTrail,
    AzureActivity,
    GcpAudit,
    KubernetesAudit,
    Nginx,
    Envoy,
    PostgreSql,
    MySql,
    Iam,
    Oauth,
    OpenTelemetry,
    Application,
    Custom(String),
}

impl SecuritySource {
    pub fn label(&self) -> String {
        match self {
            Self::Auditd => "auditd",
            Self::WindowsEventLog => "windows_event_log",
            Self::CloudTrail => "cloudtrail",
            Self::AzureActivity => "azure_activity",
            Self::GcpAudit => "gcp_audit",
            Self::KubernetesAudit => "kubernetes_audit",
            Self::Nginx => "nginx",
            Self::Envoy => "envoy",
            Self::PostgreSql => "postgresql",
            Self::MySql => "mysql",
            Self::Iam => "iam",
            Self::Oauth => "oauth",
            Self::OpenTelemetry => "otel",
            Self::Application => "application",
            Self::Custom(value) => value.as_str(),
        }
        .to_owned()
    }
}

/// Stable high-level security category.  The detailed OCSF class identity is
/// represented arithmetically by [`SecurityEvent::type_uid`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityCategory {
    Authentication,
    Authorization,
    Network,
    Process,
    File,
    Cloud,
    Identity,
    Discovery,
    Findings,
    Other(String),
}

impl SecurityCategory {
    pub fn label(&self) -> String {
        match self {
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::Network => "network",
            Self::Process => "process",
            Self::File => "file",
            Self::Cloud => "cloud",
            Self::Identity => "identity",
            Self::Discovery => "discovery",
            Self::Findings => "findings",
            Self::Other(value) => value.as_str(),
        }
        .to_owned()
    }
}

/// Outcome values use discriminants instead of booleans so the attribute index
/// does not drop them as `true`/`false` skip values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Outcome {
    Success,
    Failure,
    Blocked,
    Allowed,
    Error,
    #[default]
    Unknown,
    Custom(String),
}

impl Outcome {
    pub fn label(&self) -> String {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Blocked => "blocked",
            Self::Allowed => "allowed",
            Self::Error => "error",
            Self::Unknown => "unknown",
            Self::Custom(value) => value.as_str(),
        }
        .to_owned()
    }
}

/// A stable reference to an entity involved in the observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRef {
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl EntityRef {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
            name: None,
        }
    }
}

/// Network endpoint with only bounded, index-friendly fields.  Free-form
/// headers and command lines belong in the raw episode, not in attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Canonical normalized security event (SPEC-0045 §9.3, extended by
/// SPEC-0051 with the validated OCSF `type_uid`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub schema_version: u16,
    /// OCSF `type_uid = class_uid * 100 + activity_id`; zero means unmapped.
    pub type_uid: u64,
    pub source: SecuritySource,
    pub category: SecurityCategory,
    pub activity: String,
    pub principal: Option<EntityRef>,
    pub user: Option<EntityRef>,
    pub host: Option<EntityRef>,
    pub process: Option<EntityRef>,
    pub src: Option<NetworkEndpoint>,
    pub dst: Option<NetworkEndpoint>,
    pub outcome: Outcome,
    pub severity: u8,
    /// Source/world time in milliseconds when known.  This is copied to the
    /// episode's `valid_from`; ingestion time remains the log HLC/LSN.
    pub observed_at: u64,
    pub raw_event_id: EventId,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

impl SecurityEvent {
    pub fn unmapped(raw_event_id: EventId, source: SecuritySource) -> Self {
        Self {
            schema_version: 1,
            type_uid: 0,
            source,
            category: SecurityCategory::Other("unmapped".into()),
            activity: "unmapped".into(),
            principal: None,
            user: None,
            host: None,
            process: None,
            src: None,
            dst: None,
            outcome: Outcome::Unknown,
            severity: 0,
            observed_at: 0,
            raw_event_id,
            attributes: BTreeMap::new(),
        }
    }

    pub fn class_uid(&self) -> u64 {
        self.type_uid / 100
    }

    pub fn activity_id(&self) -> u64 {
        self.type_uid % 100
    }

    /// Convert the canonical value into the append-only representation.  The
    /// source LSN and generated marker are always written in the stable
    /// `sec.*`/`sentinel.*` namespaces, and the raw event remains the first
    /// causal parent.
    pub fn into_episode(
        &self,
        source_lsn: Option<Lsn>,
        normalized_at_ms: u64,
        raw_payload: Option<&[u8]>,
    ) -> Result<Episode, serde_json::Error> {
        let mut attrs = self.attributes.clone();
        attrs.insert("sentinel.generated".into(), "true".into());
        attrs.insert("security.source".into(), self.source.label());
        attrs.insert("security.category".into(), self.category.label());
        attrs.insert("security.activity".into(), self.activity.clone());
        attrs.insert("security.outcome".into(), self.outcome.label());
        attrs.insert("sec.schema_version".into(), self.schema_version.to_string());
        attrs.insert("sec.normalized_at".into(), normalized_at_ms.to_string());
        attrs.insert(
            "sec.mapping_fidelity".into(),
            attrs
                .get("sec.mapping_fidelity")
                .cloned()
                .unwrap_or_else(|| "unmapped".into()),
        );
        attrs.insert("sec.type_uid".into(), self.type_uid.to_string());
        if let Some(lsn) = source_lsn {
            attrs.insert("sec.source_lsn".into(), lsn.to_string());
            attrs.insert("sentinel.source_lsn".into(), lsn.to_string());
        }
        if let Some(payload) = raw_payload {
            attrs.insert(
                "sentinel.raw_digest".into(),
                blake3::hash(payload).to_hex().to_string(),
            );
        }

        let mut episode = Episode::new(
            "sentinel",
            EventKind::Custom("SecurityEvent".into()),
            serde_json::to_vec(self)?,
        );
        episode.parents.push(self.raw_event_id);
        episode.attrs = attrs;
        episode.valid_from = (self.observed_at != 0).then_some(self.observed_at);
        Ok(episode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn into_episode_preserves_provenance_and_uses_discriminants() {
        let raw = EventId::new();
        let mut event = SecurityEvent::unmapped(raw, SecuritySource::Application);
        event.outcome = Outcome::Failure;
        event
            .attributes
            .insert("sec.mapping_fidelity".into(), "partial".into());
        let episode = event.into_episode(Some(7), 42, Some(b"raw")).unwrap();
        assert_eq!(episode.kind, EventKind::Custom("SecurityEvent".into()));
        assert_eq!(episode.parents, vec![raw]);
        assert_eq!(episode.attrs["sec.source_lsn"], "7");
        assert_eq!(episode.attrs["sentinel.generated"], "true");
        assert_eq!(episode.attrs["security.outcome"], "failure");
        assert_eq!(episode.attrs["sec.mapping_fidelity"], "partial");
    }
}
