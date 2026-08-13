//! SPEC-027 — endogenous telemetry.
//!
//! Vital metrics (replay throughput, freeze durations, memory pressure) are
//! appended to the *same* immutable log as ordinary events, tagged
//! [`EventKind::SystemMetric`]. Because they live in the log, the database can
//! investigate its own behaviour with the ordinary query/analytics engine and
//! feed the cost model's calibration loop (SPEC-032) from real history.

use crate::event::{Episode, EventKind};

/// A single telemetry sample.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemMetric {
    pub name: String,
    pub value: f64,
}

impl SystemMetric {
    pub fn new(name: impl Into<String>, value: f64) -> Self {
        Self { name: name.into(), value }
    }

    /// Materialize this metric as a log episode. The metric name/value ride in
    /// `attrs` so the analytics table can `WHERE kind='SystemMetric'` and read
    /// `metric`/`value` columns.
    pub fn to_episode(&self, agent_id: &str) -> Episode {
        let mut ep = Episode::new(agent_id, EventKind::SystemMetric, Vec::new());
        ep.attrs.insert("metric".into(), self.name.clone());
        ep.attrs.insert("value".into(), self.value.to_string());
        ep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_episode_is_tagged_and_carries_fields() {
        let m = SystemMetric::new("freeze_duration_ms", 12.5);
        let ep = m.to_episode("engine");
        assert_eq!(ep.kind, EventKind::SystemMetric);
        assert_eq!(ep.attrs.get("metric").map(String::as_str), Some("freeze_duration_ms"));
        assert_eq!(ep.attrs.get("value").map(String::as_str), Some("12.5"));
    }
}
