//! Runtime wiring for the SPEC-0071 TelemetryHealthGraph.

use heraclitus_core::{FsyncPolicy, HeraclitusConfig};
use heraclitus_server::engine::Engine;
use heraclitus_telemetry_health::{
    ExpectationConfigured, FreshnessStatus, HealthEvaluationTick, SensorIdentity,
    TelemetryHealthEnvelope, TelemetryHealthEvent,
};

fn config(dir: &std::path::Path) -> HeraclitusConfig {
    HeraclitusConfig {
        data_dir: dir.to_path_buf(),
        fsync: FsyncPolicy::Always,
        ..HeraclitusConfig::default()
    }
}

#[test]
fn append_replay_and_as_of_feed_the_live_health_view() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let identity = SensorIdentity::new("tenant-a", "windows-security", "sensor-01");

    {
        let engine = Engine::open(&cfg).unwrap();
        let configured = TelemetryHealthEnvelope::new(
            identity.clone(),
            1_000,
            TelemetryHealthEvent::ExpectationConfigured(ExpectationConfigured {
                heartbeat_cadence_micros: Some(100),
                max_lateness_micros: 50,
                minimum_events_per_window: Some(0),
                duplicate_storm_basis_points: 2_000,
            }),
        );
        let tick = TelemetryHealthEnvelope::new(
            identity.clone(),
            1_151,
            TelemetryHealthEvent::HealthEvaluationTick(HealthEvaluationTick {
                evaluated_at_micros: 1_151,
            }),
        );
        assert_eq!(engine.append(configured.to_episode().unwrap()).unwrap(), 0);
        assert_eq!(engine.append(tick.to_episode().unwrap()).unwrap(), 1);

        let before_tick = engine.telemetry_health(&identity, Some(1)).unwrap();
        assert_eq!(before_tick.freshness.status, FreshnessStatus::Starting);
        let current = engine.telemetry_health(&identity, None).unwrap();
        assert_eq!(current.freshness.status, FreshnessStatus::Silent);
    }

    // No checkpoint is required for correctness: a new Engine rebuilds the
    // derived view from the immutable HRKL log and returns the same answer.
    let reopened = Engine::open(&cfg).unwrap();
    assert_eq!(
        reopened
            .telemetry_health(&identity, None)
            .unwrap()
            .freshness
            .status,
        FreshnessStatus::Silent
    );
}
