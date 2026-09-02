//! Consumer-side contract test for the byte-level golden emitted by
//! `Heraclitus-Forge/rust/src/telemetry.rs`.
//!
//! The producer repository deliberately has no Rust dependency on this crate.
//! Keeping its canonical serialized envelope here makes a wire change fail in
//! the consumer CI instead of being silently rejected only in production.

use heraclitus_telemetry_health::{
    FreshnessStatus, SensorIdentity, TelemetryHealthEnvelope, TelemetryHealthGraph,
    TELEMETRY_HEALTH_KIND, TELEMETRY_HEALTH_SCHEMA,
};
use heraclitus_views::View;

const FORGE_HEARTBEAT: &str = include_str!("golden/forge_sensor_heartbeat_v1.json");

#[test]
fn forge_golden_deserializes_validates_and_reaches_the_view() {
    let wire = FORGE_HEARTBEAT.trim();
    let envelope: TelemetryHealthEnvelope = serde_json::from_str(wire).unwrap();

    envelope.validate().unwrap();
    assert_eq!(envelope.schema, TELEMETRY_HEALTH_SCHEMA);
    assert_eq!(
        envelope.identity,
        SensorIdentity::new("gov.br/orgao-a", "teste://fonte", "forge-teste")
    );

    let episode = envelope.to_episode().unwrap();
    assert_eq!(episode.kind.label(), TELEMETRY_HEALTH_KIND);
    assert_eq!(episode.agent_id, "heraclitus-forge");
    assert_eq!(episode.content, wire.as_bytes());
    assert_eq!(
        episode
            .attrs
            .get("telemetry.event_type")
            .map(String::as_str),
        Some("SensorHeartbeat")
    );

    let identity = envelope.identity.clone();
    let mut graph = TelemetryHealthGraph::new();
    graph.apply(41, &episode);
    let snapshot = graph.snapshot_as_of(&identity, 42).unwrap();
    assert_eq!(snapshot.last_heartbeat_micros, Some(1_782_782_405_000_000));
    // A heartbeat proves life, but without a recorded expectation the honest
    // answer remains Unknown rather than inventing a healthy cadence.
    assert_eq!(snapshot.freshness.status, FreshnessStatus::Unknown);
    assert!(graph.rejected_payload_lsns().is_empty());
}

#[test]
fn forge_golden_round_trips_byte_for_byte() {
    let wire = FORGE_HEARTBEAT.trim();
    let envelope: TelemetryHealthEnvelope = serde_json::from_str(wire).unwrap();
    assert_eq!(serde_json::to_string(&envelope).unwrap(), wire);
}
