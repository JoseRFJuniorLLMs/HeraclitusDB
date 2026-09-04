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
    /// SPEC-0072 §24 — instrumentação do arranque.
    ///
    /// O arranque era uma caixa preta: a linha era `starting sentinel...` e a
    /// seguir, minutos depois, o serviço respondia. Sem estes números não há
    /// como distinguir "está a ler o cursor" de "está a reconstruir 20M de
    /// eventos", que é precisamente a diferença que o operador precisa de ver.
    pub(crate) boot: BootMetrics,
}

/// SPEC-0072 §24 — fases do arranque, medidas separadamente.
///
/// Escrito uma vez, no arranque, e depois só lido. Fica atómico na mesma
/// porque o `SentinelStatus` é servido por outra thread.
#[derive(Debug, Default)]
pub struct BootMetrics {
    pub(crate) cursor_load_ms: AtomicU64,
    pub(crate) snapshot_load_ms: AtomicU64,
    pub(crate) snapshot_verify_ms: AtomicU64,
    pub(crate) state_restore_ms: AtomicU64,
    pub(crate) tail_replay_ms: AtomicU64,
    pub(crate) total_boot_ms: AtomicU64,
    pub(crate) full_rebuild_total: AtomicU64,
    pub(crate) cursor_ahead_total: AtomicU64,
    pub(crate) snapshot_corrupt_total: AtomicU64,
    pub(crate) snapshot_version_mismatch_total: AtomicU64,
    pub(crate) snapshot_rejected_total: AtomicU64,
    pub(crate) divergence_total: AtomicU64,
    /// Watermark do snapshot restaurado, ou 0 quando houve rebuild.
    pub(crate) watermark_lsn: AtomicU64,
    /// Head do log no momento do arranque.
    pub(crate) head_at_boot_lsn: AtomicU64,
    /// Quantos eventos a cauda teve de reproduzir.
    pub(crate) tail_events: AtomicU64,
    /// `(outcome, motivo_do_rebuild)`. `OnceLock` diz exactamente o que isto
    /// é: escrito uma vez, no arranque, e a partir daí só lido.
    pub(crate) decisao: std::sync::OnceLock<(String, Option<String>)>,
}

impl BootMetrics {
    /// Regista a decisão do arranque. A segunda chamada é ignorada — não há
    /// dois arranques no mesmo runtime, e uma sobreposição silenciosa seria
    /// pior do que a perda.
    pub(crate) fn registar_decisao(&self, outcome: &str, motivo: Option<&str>) {
        let _ = self
            .decisao
            .set((outcome.to_owned(), motivo.map(str::to_owned)));
    }

    pub(crate) fn relatorio(&self) -> BootReport {
        let (outcome, rebuild_reason) = self
            .decisao
            .get()
            .cloned()
            .unwrap_or_else(|| ("nao_arrancado".to_owned(), None));
        BootReport {
            outcome,
            rebuild_reason,
            watermark_lsn: self.watermark_lsn.load(Ordering::Acquire),
            head_at_boot_lsn: self.head_at_boot_lsn.load(Ordering::Acquire),
            tail_events: self.tail_events.load(Ordering::Acquire),
            cursor_load_ms: self.cursor_load_ms.load(Ordering::Acquire),
            snapshot_load_ms: self.snapshot_load_ms.load(Ordering::Acquire),
            snapshot_verify_ms: self.snapshot_verify_ms.load(Ordering::Acquire),
            state_restore_ms: self.state_restore_ms.load(Ordering::Acquire),
            tail_replay_ms: self.tail_replay_ms.load(Ordering::Acquire),
            total_boot_ms: self.total_boot_ms.load(Ordering::Acquire),
            full_rebuild_total: self.full_rebuild_total.load(Ordering::Acquire),
            cursor_ahead_total: self.cursor_ahead_total.load(Ordering::Acquire),
            snapshot_corrupt_total: self.snapshot_corrupt_total.load(Ordering::Acquire),
            snapshot_version_mismatch_total: self
                .snapshot_version_mismatch_total
                .load(Ordering::Acquire),
            snapshot_rejected_total: self.snapshot_rejected_total.load(Ordering::Acquire),
            divergence_total: self.divergence_total.load(Ordering::Acquire),
        }
    }
}

/// A decisão que o arranque tomou, exposta para `/sentinel/status`.
#[derive(Debug, Clone, Serialize)]
pub struct BootReport {
    /// `synchronized` | `catch_up_tail` | `rebuild_canonical` | `divergence_detected`.
    pub outcome: String,
    /// Porque é que houve rebuild, quando houve. `None` nos outros casos.
    pub rebuild_reason: Option<String>,
    pub watermark_lsn: u64,
    pub head_at_boot_lsn: u64,
    pub tail_events: u64,
    pub cursor_load_ms: u64,
    pub snapshot_load_ms: u64,
    pub snapshot_verify_ms: u64,
    pub state_restore_ms: u64,
    pub tail_replay_ms: u64,
    pub total_boot_ms: u64,
    pub full_rebuild_total: u64,
    pub cursor_ahead_total: u64,
    pub snapshot_corrupt_total: u64,
    pub snapshot_version_mismatch_total: u64,
    pub snapshot_rejected_total: u64,
    pub divergence_total: u64,
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
    /// SPEC-0072 §24/§25 — o que o arranque fez, e quanto tempo levou cada fase.
    pub boot: BootReport,
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
            boot: self.boot.relatorio(),
        }
    }
}
