//! Lock-free counters and an operator-facing status snapshot.

use crate::config::SentinelMode;
use crate::execution::CircuitState;
use crate::queue::QueueSnapshot;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct SentinelMetrics {
    pub(crate) events_seen_total: AtomicU64,
    pub(crate) events_processed_total: AtomicU64,
    pub(crate) events_normalized_total: AtomicU64,
    pub(crate) signals_emitted_total: AtomicU64,
    /// SPEC-0047 — matches confirmados contra o índice de IOC.
    pub(crate) threat_matches_total: AtomicU64,
    /// SPEC-0047 §36 — observações locais de um IOC externo.
    pub(crate) threat_sightings_emitted_total: AtomicU64,
    pub(crate) risk_assessments_emitted_total: AtomicU64,
    pub(crate) incidents_created_total: AtomicU64,
    pub(crate) incident_revisions_emitted_total: AtomicU64,
    pub(crate) normalization_skipped_total: AtomicU64,
    pub(crate) normalization_errors_total: AtomicU64,
    pub(crate) queue_overflow_total: AtomicU64,
    pub(crate) catchup_passes_total: AtomicU64,
    pub(crate) l0_latency_us: AtomicU64,
    pub(crate) l1_latency_ms: AtomicU64,
    pub(crate) l2_latency_ms: AtomicU64,
    pub(crate) l3_latency_ms: AtomicU64,
    pub(crate) ai_requests_total: AtomicU64,
    pub(crate) ai_failures_total: AtomicU64,
    pub(crate) ai_latency_ms: AtomicU64,
    pub(crate) ai_tokens_total: AtomicU64,
    pub(crate) ai_investigations_persisted_total: AtomicU64,
    pub(crate) actions_proposed_total: AtomicU64,
    pub(crate) actions_approved_total: AtomicU64,
    pub(crate) actions_denied_total: AtomicU64,
    pub(crate) actions_executed_total: AtomicU64,
    pub(crate) action_failures_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SecurityLagState {
    Healthy,
    Degraded,
    CatchingUp,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct SentinelStatus {
    pub enabled: bool,
    pub mode: SentinelMode,
    pub pipeline_version: u32,
    pub head_lsn: u64,
    pub next_lsn: u64,
    pub processed_lsn: Option<u64>,
    pub detection_lag_lsn: u64,
    pub lag_state: SecurityLagState,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub queue_overflow_total: u64,
    pub catch_up_from_lsn: Option<u64>,
    pub events_seen_total: u64,
    pub events_processed_total: u64,
    pub events_normalized_total: u64,
    pub signals_emitted_total: u64,
    pub threat_matches_total: u64,
    pub threat_sightings_emitted_total: u64,
    pub risk_assessments_emitted_total: u64,
    pub incidents_created_total: u64,
    pub incident_revisions_emitted_total: u64,
    pub normalization_skipped_total: u64,
    pub normalization_errors_total: u64,
    pub catchup_passes_total: u64,
    pub l0_latency_us: u64,
    pub l1_latency_ms: u64,
    pub l2_latency_ms: u64,
    pub l3_latency_ms: u64,
    pub ai_requests_total: u64,
    pub ai_failures_total: u64,
    pub ai_latency_ms: u64,
    pub ai_tokens_total: u64,
    pub ai_investigations_persisted_total: u64,
    pub ai_circuit_state: CircuitState,
    pub ai_consecutive_failures: u32,
    pub ai_in_flight: u32,
    pub actions_proposed_total: u64,
    pub actions_approved_total: u64,
    pub actions_denied_total: u64,
    pub actions_executed_total: u64,
    pub action_failures_total: u64,
}

impl SentinelMetrics {
    pub fn snapshot(
        &self,
        enabled: bool,
        mode: SentinelMode,
        pipeline_version: u32,
        head_lsn: u64,
        next_lsn: u64,
        queue: QueueSnapshot,
    ) -> SentinelStatus {
        let lag = head_lsn.saturating_sub(next_lsn);
        let lag_state = if queue.catch_up_from_lsn.is_some() {
            SecurityLagState::CatchingUp
        } else if lag >= 100_000 {
            SecurityLagState::Critical
        } else if lag >= 10_000 {
            SecurityLagState::Degraded
        } else {
            SecurityLagState::Healthy
        };
        SentinelStatus {
            enabled,
            mode,
            pipeline_version,
            head_lsn,
            next_lsn,
            processed_lsn: next_lsn.checked_sub(1),
            detection_lag_lsn: lag,
            lag_state,
            queue_depth: queue.depth,
            queue_capacity: queue.capacity,
            queue_overflow_total: queue.overflow_total,
            catch_up_from_lsn: queue.catch_up_from_lsn,
            events_seen_total: self.events_seen_total.load(Ordering::Acquire),
            events_processed_total: self.events_processed_total.load(Ordering::Acquire),
            events_normalized_total: self.events_normalized_total.load(Ordering::Acquire),
            signals_emitted_total: self.signals_emitted_total.load(Ordering::Acquire),
            threat_matches_total: self.threat_matches_total.load(Ordering::Acquire),
            threat_sightings_emitted_total: self
                .threat_sightings_emitted_total
                .load(Ordering::Acquire),
            risk_assessments_emitted_total: self
                .risk_assessments_emitted_total
                .load(Ordering::Acquire),
            incidents_created_total: self.incidents_created_total.load(Ordering::Acquire),
            incident_revisions_emitted_total: self
                .incident_revisions_emitted_total
                .load(Ordering::Acquire),
            normalization_skipped_total: self.normalization_skipped_total.load(Ordering::Acquire),
            normalization_errors_total: self.normalization_errors_total.load(Ordering::Acquire),
            catchup_passes_total: self.catchup_passes_total.load(Ordering::Acquire),
            l0_latency_us: self.l0_latency_us.load(Ordering::Acquire),
            l1_latency_ms: self.l1_latency_ms.load(Ordering::Acquire),
            l2_latency_ms: self.l2_latency_ms.load(Ordering::Acquire),
            l3_latency_ms: self.l3_latency_ms.load(Ordering::Acquire),
            ai_requests_total: self.ai_requests_total.load(Ordering::Acquire),
            ai_failures_total: self.ai_failures_total.load(Ordering::Acquire),
            ai_latency_ms: self.ai_latency_ms.load(Ordering::Acquire),
            ai_tokens_total: self.ai_tokens_total.load(Ordering::Acquire),
            ai_investigations_persisted_total: self
                .ai_investigations_persisted_total
                .load(Ordering::Acquire),
            ai_circuit_state: CircuitState::Closed,
            ai_consecutive_failures: 0,
            ai_in_flight: 0,
            actions_proposed_total: self.actions_proposed_total.load(Ordering::Acquire),
            actions_approved_total: self.actions_approved_total.load(Ordering::Acquire),
            actions_denied_total: self.actions_denied_total.load(Ordering::Acquire),
            actions_executed_total: self.actions_executed_total.load(Ordering::Acquire),
            action_failures_total: self.action_failures_total.load(Ordering::Acquire),
        }
    }
}
