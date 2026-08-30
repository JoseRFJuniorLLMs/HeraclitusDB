//! Deterministic, dependency-free generic normalizer used by Fase 0.

use crate::event::{
    EntityRef, NetworkEndpoint, Outcome, SecurityCategory, SecurityEvent, SecuritySource,
};
use heraclitus_core::{Episode, Lsn};
use serde_json::Value;

/// Result of normalizing one raw episode.  The raw bytes are kept by the
/// caller so the canonical event can carry a digest without copying them into
/// the derived payload.
#[derive(Debug, Clone)]
pub struct NormalizedSecurityEvent {
    pub event: SecurityEvent,
    pub source_lsn: Lsn,
}

/// Parser identity is recorded on every event.  It is intentionally a plain
/// value (rather than a registry) so replays cannot depend on process-global
/// mutable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericNormalizer {
    pub parser_id: String,
    pub parser_version: String,
    pub schema_version: String,
}

impl Default for GenericNormalizer {
    fn default() -> Self {
        Self {
            parser_id: "heraclitus.generic".into(),
            parser_version: "1.0.0".into(),
            schema_version: "1.0.0".into(),
        }
    }
}

impl GenericNormalizer {
    /// Normalize an episode without network, clock or global-state access.
    /// `normalized_at_ms` is supplied by the worker and is the sole
    /// intentionally volatile field.
    pub fn normalize(
        &self,
        lsn: Lsn,
        episode: &Episode,
        normalized_at_ms: u64,
    ) -> Option<NormalizedSecurityEvent> {
        // Derived events are evidence, not new raw telemetry.  Accept the
        // historical `derived` spelling as well so an upgrade cannot create a
        // feedback loop from events emitted by an older worker.
        if episode.agent_id == "sentinel"
            && matches!(
                episode.attrs.get("sentinel.generated").map(String::as_str),
                Some("true" | "derived" | "1")
            )
        {
            return None;
        }

        let json = serde_json::from_slice::<Value>(&episode.content).ok();
        let object = json.as_ref().and_then(Value::as_object);
        let source = source(object.and_then(|o| value_string(o, &["source", "source_type"])))
            .unwrap_or_else(|| SecuritySource::Custom(episode.agent_id.clone()));
        let category =
            category(object.and_then(|o| value_string(o, &["category", "security.category"])))
                .unwrap_or_else(|| SecurityCategory::Other("unmapped".into()));
        let activity = object
            .and_then(|o| value_string(o, &["activity", "event", "action", "security.activity"]))
            .unwrap_or_else(|| "unmapped".into());
        let outcome =
            outcome(object.and_then(|o| value_string(o, &["outcome", "status", "result"])))
                .unwrap_or_default();
        let severity = object
            .and_then(|o| value_u64(o, &["severity", "severity_id", "risk"]))
            .unwrap_or(0)
            .min(u8::MAX as u64) as u8;
        let observed_at = object
            .and_then(|o| value_u64(o, &["observed_at", "timestamp", "time", "event_time"]))
            .unwrap_or(0);
        let type_uid = object
            .and_then(|o| value_u64(o, &["type_uid", "ocsf.type_uid"]))
            .unwrap_or(0);

        let principal = entity(object, &["principal", "principal_id"], "principal");
        let user = entity(object, &["user", "user_id", "username"], "user");
        let host = entity(object, &["host", "host_id", "hostname"], "host");
        let process = entity(object, &["process", "process_name"], "process");
        let session = entity(object, &["session", "session_id"], "session");
        let resource = entity(object, &["resource", "resource_id"], "resource")
            .or_else(|| entity(object, &["database", "database_id"], "database"))
            .or_else(|| entity(object, &["file", "file_id"], "file"))
            .or_else(|| entity(object, &["repository", "repository_id"], "repository"));
        let src = endpoint(object.and_then(|o| o.get("src").or_else(|| o.get("source_endpoint"))));
        let dst =
            endpoint(object.and_then(|o| o.get("dst").or_else(|| o.get("destination_endpoint"))));

        let mut attributes = std::collections::BTreeMap::new();
        insert(&mut attributes, "security.source", source.label());
        insert(&mut attributes, "security.category", category.label());
        insert(&mut attributes, "security.activity", activity.clone());
        insert(&mut attributes, "security.outcome", outcome.label());
        insert(&mut attributes, "security.severity", severity.to_string());
        if let Some(value) = &principal {
            insert(&mut attributes, "principal.id", value.id.clone());
        }
        if let Some(value) = &user {
            insert(&mut attributes, "user.id", value.id.clone());
        }
        if let Some(value) = &host {
            insert(&mut attributes, "host.id", value.id.clone());
        }
        if let Some(value) = &process {
            insert(&mut attributes, "process.id", value.id.clone());
            if let Some(name) = &value.name {
                insert(&mut attributes, "process.name", name.clone());
            }
        }
        if let Some(value) = &session {
            insert(&mut attributes, "session.id", value.id.clone());
            insert(&mut attributes, "session.kind", value.kind.clone());
        }
        if let Some(value) = &resource {
            insert(&mut attributes, "resource.id", value.id.clone());
            insert(&mut attributes, "resource.kind", value.kind.clone());
        }
        endpoint_attrs(&mut attributes, "src", src.as_ref());
        endpoint_attrs(&mut attributes, "dst", dst.as_ref());

        let fidelity = if type_uid != 0 && object.is_some() {
            "exact"
        } else if object.is_some()
            && (activity != "unmapped"
                || !matches!(category, SecurityCategory::Other(ref s) if s == "unmapped"))
        {
            "partial"
        } else {
            "unmapped"
        };
        insert(&mut attributes, "sec.mapping_fidelity", fidelity);
        insert(&mut attributes, "sec.parser_id", self.parser_id.clone());
        insert(
            &mut attributes,
            "sec.parser_version",
            self.parser_version.clone(),
        );
        insert(
            &mut attributes,
            "sec.schema_version",
            self.schema_version.clone(),
        );
        insert(
            &mut attributes,
            "sec.normalized_at",
            normalized_at_ms.to_string(),
        );
        insert(&mut attributes, "sec.source_lsn", lsn.to_string());
        insert(&mut attributes, "sec.type_uid", type_uid.to_string());
        if let Some(object) = object {
            insert_raw_scalar_attributes(object, &mut attributes);
        }

        Some(NormalizedSecurityEvent {
            event: SecurityEvent {
                schema_version: 1,
                type_uid,
                source,
                category,
                activity,
                principal,
                user,
                host,
                process,
                src,
                dst,
                outcome,
                severity,
                observed_at,
                raw_event_id: episode.id,
                attributes,
            },
            source_lsn: lsn,
        })
    }
}

fn value_string(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(|value| match value {
            Value::String(text) if !text.trim().is_empty() => Some(text.trim().to_owned()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
}

fn value_u64(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.parse().ok(),
            _ => None,
        })
}

fn source(value: Option<String>) -> Option<SecuritySource> {
    value.map(|value| match value.to_ascii_lowercase().as_str() {
        "auditd" | "linux_audit" => SecuritySource::Auditd,
        "windows" | "windows_event_log" | "wineventlog" => SecuritySource::WindowsEventLog,
        "cloudtrail" | "aws" => SecuritySource::CloudTrail,
        "azure" | "azure_activity" => SecuritySource::AzureActivity,
        "gcp" | "gcp_audit" => SecuritySource::GcpAudit,
        "kubernetes" | "k8s" => SecuritySource::KubernetesAudit,
        "nginx" => SecuritySource::Nginx,
        "envoy" => SecuritySource::Envoy,
        "postgres" | "postgresql" => SecuritySource::PostgreSql,
        "mysql" => SecuritySource::MySql,
        "iam" => SecuritySource::Iam,
        "oauth" => SecuritySource::Oauth,
        "otel" | "opentelemetry" => SecuritySource::OpenTelemetry,
        "application" | "app" => SecuritySource::Application,
        _ => SecuritySource::Custom(value),
    })
}

fn category(value: Option<String>) -> Option<SecurityCategory> {
    value.map(|value| match value.to_ascii_lowercase().as_str() {
        "authentication" | "auth" | "iam" => SecurityCategory::Authentication,
        "authorization" | "access" => SecurityCategory::Authorization,
        "network" | "dns" | "http" => SecurityCategory::Network,
        "process" | "execution" => SecurityCategory::Process,
        "file" | "filesystem" => SecurityCategory::File,
        "cloud" => SecurityCategory::Cloud,
        "identity" => SecurityCategory::Identity,
        "discovery" => SecurityCategory::Discovery,
        "findings" | "finding" => SecurityCategory::Findings,
        _ => SecurityCategory::Other(value),
    })
}

fn outcome(value: Option<String>) -> Option<Outcome> {
    value.map(|value| match value.to_ascii_lowercase().as_str() {
        "success" | "succeeded" | "ok" | "pass" => Outcome::Success,
        "failure" | "failed" | "fail" | "denied" => Outcome::Failure,
        "blocked" => Outcome::Blocked,
        "allowed" | "allow" => Outcome::Allowed,
        "error" | "exception" => Outcome::Error,
        _ => Outcome::Custom(value),
    })
}

fn entity(
    object: Option<&serde_json::Map<String, Value>>,
    keys: &[&str],
    kind: &str,
) -> Option<EntityRef> {
    let value = object.and_then(|o| keys.iter().find_map(|key| o.get(*key)))?;
    match value {
        Value::String(id) if !id.trim().is_empty() => Some(EntityRef::new(kind, id.trim())),
        Value::Object(map) => {
            let id = value_string(map, &["id", "uid", "name"])?;
            let actual_kind = value_string(map, &["kind", "type"]).unwrap_or_else(|| kind.into());
            let mut entity = EntityRef::new(actual_kind, id);
            entity.name = value_string(map, &["name", "display_name"]);
            Some(entity)
        }
        _ => None,
    }
}

fn endpoint(value: Option<&Value>) -> Option<NetworkEndpoint> {
    let map = value?.as_object()?;
    let ip = value_string(map, &["ip", "address"]);
    let hostname = value_string(map, &["hostname", "host"]);
    let protocol = value_string(map, &["protocol", "transport"]);
    let port = value_u64(map, &["port"]).and_then(|value| u16::try_from(value).ok());
    if ip.is_none() && hostname.is_none() && port.is_none() && protocol.is_none() {
        None
    } else {
        Some(NetworkEndpoint {
            ip,
            port,
            hostname,
            protocol,
        })
    }
}

fn endpoint_attrs(
    attrs: &mut std::collections::BTreeMap<String, String>,
    prefix: &str,
    endpoint: Option<&NetworkEndpoint>,
) {
    if let Some(endpoint) = endpoint {
        if let Some(ip) = &endpoint.ip {
            insert(attrs, &format!("{prefix}.ip"), ip.clone());
        }
        if let Some(port) = endpoint.port {
            insert(attrs, &format!("{prefix}.port"), port.to_string());
        }
        if let Some(hostname) = &endpoint.hostname {
            insert(attrs, &format!("{prefix}.hostname"), hostname.clone());
        }
        if let Some(protocol) = &endpoint.protocol {
            insert(attrs, &format!("{prefix}.protocol"), protocol.clone());
        }
    }
}

fn insert(
    attrs: &mut std::collections::BTreeMap<String, String>,
    key: &str,
    value: impl Into<String>,
) {
    let value = value.into();
    // The exact attribute index has an 80-byte value ceiling.  Keep long raw
    // values out of attrs; the original episode remains the evidence source.
    if !value.is_empty() && value.len() <= 80 && attrs.len() < 24 {
        attrs.insert(key.to_owned(), value);
    }
}

fn insert_raw_scalar_attributes(
    object: &serde_json::Map<String, Value>,
    attrs: &mut std::collections::BTreeMap<String, String>,
) {
    // Keep the canonical fields above authoritative.  Remaining scalar fields
    // are exposed under `event.*` so a Sigma rule can match a vendor field
    // without placing arbitrary JSON or unbounded values in the index.
    const RESERVED: &[&str] = &[
        "source",
        "source_type",
        "category",
        "security.category",
        "activity",
        "event",
        "action",
        "security.activity",
        "outcome",
        "status",
        "result",
        "severity",
        "severity_id",
        "risk",
        "observed_at",
        "timestamp",
        "time",
        "event_time",
        "type_uid",
        "ocsf.type_uid",
        "principal",
        "principal_id",
        "user",
        "user_id",
        "username",
        "host",
        "host_id",
        "hostname",
        "process",
        "process_name",
        "session",
        "session_id",
        "resource",
        "resource_id",
        "database",
        "database_id",
        "file",
        "file_id",
        "repository",
        "repository_id",
        "src",
        "source_endpoint",
        "dst",
        "destination_endpoint",
    ];
    let mut keys: Vec<&String> = object.keys().collect();
    keys.sort_unstable();
    for key in keys {
        if RESERVED
            .iter()
            .any(|reserved| reserved.eq_ignore_ascii_case(key))
            || key.contains('|')
            || key.trim().is_empty()
        {
            continue;
        }
        let Some(value) = scalar_text(object.get(key).expect("key came from object")) else {
            continue;
        };
        insert(attrs, &format!("event.{key}"), value);
    }
}

fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{EventId, EventKind};

    #[test]
    fn generic_parser_is_deterministic_and_bounded() {
        let mut episode = Episode::new(
            "collector-a",
            EventKind::Observation,
            br#"{"source":"cloudtrail","category":"authentication","activity":"login","outcome":"failure","user":{"id":"alice"},"src":{"ip":"203.0.113.4","port":443},"severity":7}"#.to_vec(),
        );
        episode.id = EventId::new();
        let parser = GenericNormalizer::default();
        let a = parser.normalize(4, &episode, 100).unwrap();
        let b = parser.normalize(4, &episode, 100).unwrap();
        assert_eq!(a.event, b.event);
        assert_eq!(a.event.attributes["security.outcome"], "failure");
        assert_eq!(a.event.attributes["user.id"], "alice");
        assert!(a.event.attributes.len() <= 24);
    }

    #[test]
    fn generated_events_are_not_reingested() {
        let mut episode = Episode::new(
            "sentinel",
            EventKind::Custom("SecurityEvent".into()),
            b"{}".to_vec(),
        );
        episode
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        assert!(GenericNormalizer::default()
            .normalize(1, &episode, 2)
            .is_none());
    }
}
