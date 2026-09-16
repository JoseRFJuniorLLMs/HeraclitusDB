use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const MAX_ALARM_HISTORY: usize = 200;
pub(super) const RECENT_REDTEAM_NANOS: u64 = 60_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum AlarmSeverity {
    Info,
    Warning,
    Critical,
}

impl AlarmSeverity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Critical => "CRIT",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct Alarm {
    pub id: String,
    pub severity: AlarmSeverity,
    pub source: String,
    pub title: String,
    pub detail: String,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub occurrences: u64,
    pub active: bool,
}

#[derive(Debug, Default, Clone)]
pub(super) struct StorageSnapshot {
    pub available: bool,
    pub append_bytes_total: u64,
    pub raw_bytes: u64,
    pub packed_bytes: u64,
    pub compression_ratio: f64,
    pub pack_queue_depth: u64,
    pub pack_seconds: f64,
    pub pack_throughput_bytes_sec: f64,
    pub blocks_total: u64,
    pub blocks_read: u64,
    pub blocks_pruned: u64,
    pub bytes_pruned: u64,
    pub decompressed_bytes: u64,
    pub hrki_hits: u64,
    pub hrki_misses: u64,
    pub hrki_rebuilds: u64,
    pub cold_range_reads: u64,
    pub cold_bytes_downloaded: u64,
    pub parquet_export_lag_lsn: u64,
    pub canonical_verify_failures: u64,
    pub physical_crc_failures: u64,
}

#[derive(Debug, Default, Clone)]
pub(super) struct IndexSnapshot {
    pub vector_indexed: u64,
    pub text_indexed: u64,
    pub graph_nodes: u64,
    pub tgraph_edges: u64,
    pub entity_keys: u64,
    pub activation_tracked: u64,
}

#[derive(Debug, Default, Clone)]
pub(super) struct SentinelSnapshot {
    pub available: bool,
    pub enabled: bool,
    pub mode: String,
    pub pipeline_version: u64,
    pub head_lsn: u64,
    pub processed_lsn: Option<u64>,
    pub detection_lag_lsn: u64,
    pub lag_state: String,
    pub queue_depth: u64,
    pub queue_capacity: u64,
    pub queue_overflow_total: u64,
    pub events_seen_total: u64,
    pub events_processed_total: u64,
    pub signals_emitted_total: u64,
    pub threat_matches_total: u64,
    pub incidents_created_total: u64,
    pub incident_capacity_drops_total: u64,
    pub normalization_errors_total: u64,
    pub l0_latency_us: u64,
    pub l1_latency_ms: u64,
    pub l2_latency_ms: u64,
    pub l3_latency_ms: u64,
    pub ai_requests_total: u64,
    pub ai_failures_total: u64,
    pub ai_latency_ms: u64,
    pub ai_tokens_total: u64,
    pub ai_investigations_persisted_total: u64,
    pub ai_circuit_state: String,
    pub actions_proposed_total: u64,
    pub actions_approved_total: u64,
    pub actions_denied_total: u64,
    pub actions_executed_total: u64,
    pub action_failures_total: u64,
    pub boot_outcome: String,
    pub boot_total_ms: u64,
}

#[derive(Debug, Default, Clone)]
pub(super) struct ComplianceSnapshot {
    pub available: bool,
    pub as_of_lsn: u64,
    pub status: String,
    pub trust_notice: String,
    pub receipts_total: u64,
    pub current_sealed_watermark: u64,
    pub last_anchor_lsn: Option<u64>,
    pub deferred_anchors: u64,
    pub deferred_anchor_forks: u64,
    pub deadline_total: u64,
    pub deadline_overdue: u64,
    pub deadline_24h: u64,
    pub deadline_48h: u64,
    pub deadline_72h: u64,
    pub pending_anpd: u64,
    pub legal_holds: u64,
    pub retention_exceptions: u64,
    pub active_policy_versions: u64,
    pub egress_allowed: u64,
    pub egress_denied: u64,
    pub model_allowed: u64,
    pub model_denied: u64,
}

#[derive(Debug, Default, Clone)]
pub(super) struct RaftSnapshot {
    pub available: bool,
    pub role: String,
    pub leader: String,
    pub term: Option<u64>,
    pub commit_index: Option<u64>,
    pub applied_index: Option<u64>,
    pub node_id: String,
    pub peers: Option<u64>,
}

#[derive(Debug, Default, Clone)]
pub(super) struct AgentSnapshot {
    pub available: bool,
    pub product: String,
    pub auth: String,
    pub auth_identifies_people: bool,
    pub evidence_log: String,
    pub otlp_ingest: String,
    pub mcp_gateway: String,
    pub bypass_protection: String,
    pub rfc3161: String,
    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub policy_lifecycle: String,
    pub capture_mode: String,
    pub runs: u64,
    pub tool_calls: u64,
    pub denied: u64,
    pub pending_approvals: u64,
    pub integrity: String,
    pub ingest_events: u64,
    pub ingest_duplicates: u64,
    pub ingest_conflicts: u64,
    pub ingest_rejected: u64,
    pub ingest_ignored_spans: u64,
    pub gateway_requests: u64,
    pub gateway_allow: u64,
    pub gateway_deny: u64,
    pub gateway_require_approval: u64,
    pub gateway_shadow_deny: u64,
    pub approval_expired: u64,
    pub approval_replay_rejected: u64,
    pub approval_capacity_rejected: u64,
    pub policy_errors: u64,
    pub evidence_errors: u64,
    pub upstream_errors: u64,
}

#[derive(Debug, Default, Clone)]
pub(super) struct RedTeamSnapshot {
    pub available: bool,
    pub returned: u64,
    pub blocked: u64,
    pub reached_upstream: u64,
    pub events: Vec<RedTeamEvent>,
}

#[derive(Debug, Default, Clone)]
pub(super) struct RedTeamEvent {
    pub evidence_id: String,
    pub observed_at_unix_nanos: u64,
    pub attack_id: String,
    pub campaign_id: String,
    pub vector: String,
    pub target: String,
    pub phase: String,
    pub result: String,
    pub expected: String,
    pub reason_code: String,
    pub blocked: bool,
    pub upstream_delta: i64,
    pub transport_status: Option<u64>,
}

#[derive(Debug, Default, Clone)]
pub(super) struct AlarmBaseline {
    pub sentinel_threat_matches: u64,
    pub sentinel_incidents: u64,
    pub sentinel_queue_overflows: u64,
    pub sentinel_incident_drops: u64,
    pub sentinel_normalization_errors: u64,
    pub sentinel_ai_failures: u64,
    pub sentinel_action_failures: u64,
    pub storage_crc_failures: u64,
    pub storage_canonical_failures: u64,
    pub ingest_conflicts: u64,
    pub ingest_rejected: u64,
    pub approval_replay_rejected: u64,
    pub approval_capacity_rejected: u64,
    pub gateway_policy_errors: u64,
    pub gateway_evidence_errors: u64,
    pub gateway_upstream_errors: u64,
    pub gateway_denies: u64,
}

#[derive(Debug, Default)]
pub(super) struct AlarmBook {
    active: BTreeMap<String, Alarm>,
    history: VecDeque<Alarm>,
}

impl AlarmBook {
    pub fn active(&self) -> Vec<Alarm> {
        let mut values = self.active.values().cloned().collect::<Vec<_>>();
        values.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| b.last_seen_unix.cmp(&a.last_seen_unix))
        });
        values
    }

    pub fn history(&self) -> Vec<Alarm> {
        self.history.iter().cloned().collect()
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut info = 0;
        let mut warning = 0;
        let mut critical = 0;
        for alarm in self.active.values() {
            match alarm.severity {
                AlarmSeverity::Info => info += 1,
                AlarmSeverity::Warning => warning += 1,
                AlarmSeverity::Critical => critical += 1,
            }
        }
        (info, warning, critical)
    }

    pub fn reconcile(&mut self, desired: Vec<AlarmCandidate>) {
        let now = unix_seconds();
        let desired_ids = desired.iter().map(|a| a.id.clone()).collect::<BTreeSet<_>>();
        let stale = self
            .active
            .keys()
            .filter(|id| !desired_ids.contains(*id))
            .cloned()
            .collect::<Vec<_>>();
        for id in stale {
            if let Some(mut resolved) = self.active.remove(&id) {
                resolved.active = false;
                resolved.last_seen_unix = now;
                self.push_history(resolved);
            }
        }

        for candidate in desired {
            match self.active.get_mut(&candidate.id) {
                Some(existing) => {
                    existing.severity = candidate.severity;
                    existing.source = candidate.source;
                    existing.title = candidate.title;
                    existing.detail = candidate.detail;
                    existing.last_seen_unix = now;
                    existing.occurrences = existing.occurrences.saturating_add(1);
                }
                None => {
                    let alarm = Alarm {
                        id: candidate.id,
                        severity: candidate.severity,
                        source: candidate.source,
                        title: candidate.title,
                        detail: candidate.detail,
                        first_seen_unix: now,
                        last_seen_unix: now,
                        occurrences: 1,
                        active: true,
                    };
                    self.push_history(alarm.clone());
                    self.active.insert(alarm.id.clone(), alarm);
                }
            }
        }
    }

    fn push_history(&mut self, alarm: Alarm) {
        self.history.push_front(alarm);
        while self.history.len() > MAX_ALARM_HISTORY {
            self.history.pop_back();
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct AlarmCandidate {
    pub id: String,
    pub severity: AlarmSeverity,
    pub source: String,
    pub title: String,
    pub detail: String,
}

impl AlarmCandidate {
    fn new(
        id: impl Into<String>,
        severity: AlarmSeverity,
        source: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            source: source.into(),
            title: title.into(),
            detail: detail.into(),
        }
    }
}

pub(super) struct AlarmInputs<'a> {
    pub online: bool,
    pub consecutive_failures: u64,
    pub grpc_reachable: Option<bool>,
    pub storage: &'a StorageSnapshot,
    pub sentinel: &'a SentinelSnapshot,
    pub compliance: &'a ComplianceSnapshot,
    pub agent: &'a AgentSnapshot,
    pub redteam: &'a RedTeamSnapshot,
    pub baseline: &'a AlarmBaseline,
}

pub(super) fn evaluate_alarms(input: AlarmInputs<'_>) -> Vec<AlarmCandidate> {
    let mut alarms = Vec::new();
    if !input.online {
        alarms.push(AlarmCandidate::new(
            "core.offline",
            AlarmSeverity::Critical,
            "CORE",
            "REST core indisponível",
            format!("/stats falhou {} vezes consecutivas", input.consecutive_failures),
        ));
    }
    if input.grpc_reachable == Some(false) {
        alarms.push(AlarmCandidate::new(
            "grpc.unreachable",
            AlarmSeverity::Warning,
            "TRANSPORT",
            "gRPC :7474 não alcançável",
            "probe TCP falhou; isso mede reachability, não gRPC HealthCheck",
        ));
    }

    if input.storage.available {
        if input.storage.physical_crc_failures > 0 {
            alarms.push(AlarmCandidate::new(
                "storage.crc",
                AlarmSeverity::Critical,
                "HRKL",
                "Falha física de CRC",
                format!("{} falhas acumuladas", input.storage.physical_crc_failures),
            ));
        }
        if input.storage.canonical_verify_failures > 0 {
            alarms.push(AlarmCandidate::new(
                "storage.canonical",
                AlarmSeverity::Critical,
                "HRKL",
                "Falha de verificação canônica",
                format!(
                    "{} falhas acumuladas",
                    input.storage.canonical_verify_failures
                ),
            ));
        }
    }

    if input.sentinel.available {
        let lag = input.sentinel.lag_state.to_ascii_uppercase();
        if matches!(lag.as_str(), "CRITICAL" | "FAILED") {
            alarms.push(AlarmCandidate::new(
                "sentinel.lag.critical",
                AlarmSeverity::Critical,
                "SENTINEL",
                "Pipeline de detecção em estado crítico",
                format!("lag={} LSN", input.sentinel.detection_lag_lsn),
            ));
        } else if matches!(lag.as_str(), "DEGRADED" | "CATCHINGUP" | "CATCHING_UP") {
            alarms.push(AlarmCandidate::new(
                "sentinel.lag.warning",
                AlarmSeverity::Warning,
                "SENTINEL",
                "Pipeline de detecção atrasado",
                format!("lag={} LSN", input.sentinel.detection_lag_lsn),
            ));
        }
        delta_alarm(
            &mut alarms,
            "sentinel.threats",
            AlarmSeverity::Critical,
            "SENTINEL",
            "Novos threat matches",
            input.sentinel.threat_matches_total,
            input.baseline.sentinel_threat_matches,
        );
        delta_alarm(
            &mut alarms,
            "sentinel.incidents",
            AlarmSeverity::Critical,
            "SENTINEL",
            "Novos incidentes",
            input.sentinel.incidents_created_total,
            input.baseline.sentinel_incidents,
        );
        delta_alarm(
            &mut alarms,
            "sentinel.queue_overflow",
            AlarmSeverity::Critical,
            "SENTINEL",
            "Overflow na fila de segurança",
            input.sentinel.queue_overflow_total,
            input.baseline.sentinel_queue_overflows,
        );
        delta_alarm(
            &mut alarms,
            "sentinel.incident_drop",
            AlarmSeverity::Critical,
            "SENTINEL",
            "Incidentes descartados por capacidade",
            input.sentinel.incident_capacity_drops_total,
            input.baseline.sentinel_incident_drops,
        );
        delta_alarm(
            &mut alarms,
            "sentinel.normalize",
            AlarmSeverity::Warning,
            "SENTINEL",
            "Erros de normalização",
            input.sentinel.normalization_errors_total,
            input.baseline.sentinel_normalization_errors,
        );
        delta_alarm(
            &mut alarms,
            "sentinel.ai_failures",
            AlarmSeverity::Warning,
            "SENTINEL-AI",
            "Falhas no investigador de IA",
            input.sentinel.ai_failures_total,
            input.baseline.sentinel_ai_failures,
        );
        delta_alarm(
            &mut alarms,
            "sentinel.action_failures",
            AlarmSeverity::Critical,
            "SENTINEL-ACTION",
            "Falhas em ações defensivas",
            input.sentinel.action_failures_total,
            input.baseline.sentinel_action_failures,
        );
        let circuit = input.sentinel.ai_circuit_state.to_ascii_uppercase();
        if !circuit.is_empty() && !matches!(circuit.as_str(), "CLOSED" | "HEALTHY") {
            alarms.push(AlarmCandidate::new(
                "sentinel.ai_circuit",
                AlarmSeverity::Warning,
                "SENTINEL-AI",
                "Circuit breaker de IA fora do normal",
                format!("state={}", input.sentinel.ai_circuit_state),
            ));
        }
    }

    if input.agent.available {
        if !eq_healthy(&input.agent.evidence_log) || !eq_healthy(&input.agent.integrity) {
            alarms.push(AlarmCandidate::new(
                "agent.evidence_integrity",
                AlarmSeverity::Critical,
                "AGENT",
                "Evidence log degradado",
                format!(
                    "evidence_log={} integrity={}",
                    input.agent.evidence_log, input.agent.integrity
                ),
            ));
        }
        delta_alarm(
            &mut alarms,
            "agent.ingest_conflicts",
            AlarmSeverity::Critical,
            "AGENT",
            "Conflitos de deduplicação/evidência",
            input.agent.ingest_conflicts,
            input.baseline.ingest_conflicts,
        );
        delta_alarm(
            &mut alarms,
            "agent.ingest_rejected",
            AlarmSeverity::Warning,
            "AGENT",
            "Eventos de agente rejeitados",
            input.agent.ingest_rejected,
            input.baseline.ingest_rejected,
        );
        delta_alarm(
            &mut alarms,
            "agent.approval_replay",
            AlarmSeverity::Critical,
            "AGENT",
            "Replay de approval bloqueado",
            input.agent.approval_replay_rejected,
            input.baseline.approval_replay_rejected,
        );
        delta_alarm(
            &mut alarms,
            "agent.approval_capacity",
            AlarmSeverity::Warning,
            "AGENT",
            "Approval rejeitado por capacidade",
            input.agent.approval_capacity_rejected,
            input.baseline.approval_capacity_rejected,
        );
        delta_alarm(
            &mut alarms,
            "agent.policy_errors",
            AlarmSeverity::Critical,
            "AGENT",
            "Erro na policy do gateway",
            input.agent.policy_errors,
            input.baseline.gateway_policy_errors,
        );
        delta_alarm(
            &mut alarms,
            "agent.evidence_errors",
            AlarmSeverity::Critical,
            "AGENT",
            "Falha ao persistir evidência",
            input.agent.evidence_errors,
            input.baseline.gateway_evidence_errors,
        );
        delta_alarm(
            &mut alarms,
            "agent.upstream_errors",
            AlarmSeverity::Warning,
            "AGENT",
            "Falhas no upstream MCP",
            input.agent.upstream_errors,
            input.baseline.gateway_upstream_errors,
        );
        let deny_delta = input
            .agent
            .gateway_deny
            .saturating_sub(input.baseline.gateway_denies);
        if deny_delta >= 10 {
            alarms.push(AlarmCandidate::new(
                "agent.deny_burst",
                AlarmSeverity::Warning,
                "AGENT",
                "Rajada de requests negados",
                format!("+{deny_delta} denies desde a última amostra"),
            ));
        }
        if input.agent.bypass_protection.eq_ignore_ascii_case("UNKNOWN") {
            alarms.push(AlarmCandidate::new(
                "agent.bypass_unknown",
                AlarmSeverity::Warning,
                "AGENT",
                "Proteção contra bypass não confirmada",
                "status do gateway reporta bypass_protection=UNKNOWN",
            ));
        }
    }

    if input.redteam.available {
        let now_ns = unix_nanos();
        let recent = input
            .redteam
            .events
            .iter()
            .filter(|event| now_ns.saturating_sub(event.observed_at_unix_nanos) <= RECENT_REDTEAM_NANOS)
            .collect::<Vec<_>>();
        let escaped = recent.iter().filter(|event| event.upstream_delta > 0).count();
        if escaped > 0 {
            alarms.push(AlarmCandidate::new(
                "redteam.upstream_escape",
                AlarmSeverity::Critical,
                "REDTEAM",
                "Teste adversarial alcançou upstream",
                format!("{escaped} evento(s) recentes com upstream_delta > 0"),
            ));
        } else if !recent.is_empty() {
            alarms.push(AlarmCandidate::new(
                "redteam.active",
                AlarmSeverity::Info,
                "REDTEAM",
                "Campanha adversarial ativa",
                format!("{} evento(s) nos últimos 60s", recent.len()),
            ));
        }
    }

    if input.compliance.available {
        if input.compliance.deferred_anchor_forks > 0 {
            alarms.push(AlarmCandidate::new(
                "compliance.anchor_fork",
                AlarmSeverity::Critical,
                "COMPLIANCE",
                "Fork de âncora de integridade",
                format!("{} fork(s)", input.compliance.deferred_anchor_forks),
            ));
        }
        if input.compliance.deadline_overdue > 0 {
            alarms.push(AlarmCandidate::new(
                "compliance.deadline",
                AlarmSeverity::Warning,
                "COMPLIANCE",
                "Prazo regulatório vencido",
                format!(
                    "{} de {} deadlines vencidos",
                    input.compliance.deadline_overdue, input.compliance.deadline_total
                ),
            ));
        }
    }

    alarms
}

fn delta_alarm(
    out: &mut Vec<AlarmCandidate>,
    id: &str,
    severity: AlarmSeverity,
    source: &str,
    title: &str,
    current: u64,
    previous: u64,
) {
    let delta = current.saturating_sub(previous);
    if delta > 0 {
        out.push(AlarmCandidate::new(
            id,
            severity,
            source,
            title,
            format!("+{delta} desde a última amostra; total={current}"),
        ));
    }
}

fn eq_healthy(value: &str) -> bool {
    matches!(value.to_ascii_uppercase().as_str(), "HEALTHY" | "OK" | "VERIFIED")
}

pub(super) fn baseline_from(
    storage: &StorageSnapshot,
    sentinel: &SentinelSnapshot,
    agent: &AgentSnapshot,
) -> AlarmBaseline {
    AlarmBaseline {
        sentinel_threat_matches: sentinel.threat_matches_total,
        sentinel_incidents: sentinel.incidents_created_total,
        sentinel_queue_overflows: sentinel.queue_overflow_total,
        sentinel_incident_drops: sentinel.incident_capacity_drops_total,
        sentinel_normalization_errors: sentinel.normalization_errors_total,
        sentinel_ai_failures: sentinel.ai_failures_total,
        sentinel_action_failures: sentinel.action_failures_total,
        storage_crc_failures: storage.physical_crc_failures,
        storage_canonical_failures: storage.canonical_verify_failures,
        ingest_conflicts: agent.ingest_conflicts,
        ingest_rejected: agent.ingest_rejected,
        approval_replay_rejected: agent.approval_replay_rejected,
        approval_capacity_rejected: agent.approval_capacity_rejected,
        gateway_policy_errors: agent.policy_errors,
        gateway_evidence_errors: agent.evidence_errors,
        gateway_upstream_errors: agent.upstream_errors,
        gateway_denies: agent.gateway_deny,
    }
}

pub(super) fn parse_storage(value: &Value) -> StorageSnapshot {
    StorageSnapshot {
        available: value.get("available").and_then(Value::as_bool).unwrap_or(true),
        append_bytes_total: u64_at(value, "hrkl_append_bytes_total").unwrap_or(0),
        raw_bytes: u64_at(value, "hrkl_raw_bytes").unwrap_or(0),
        packed_bytes: u64_at(value, "hrkl_packed_bytes").unwrap_or(0),
        compression_ratio: f64_at(value, "hrkl_compression_ratio").unwrap_or_else(|| {
            if u64_at(value, "hrkl_raw_bytes").unwrap_or(0) > 0 {
                u64_at(value, "hrkl_packed_bytes").unwrap_or(0) as f64
                    / u64_at(value, "hrkl_raw_bytes").unwrap_or(1) as f64
            } else {
                1.0
            }
        }),
        pack_queue_depth: u64_at(value, "hrkl_pack_queue_depth").unwrap_or(0),
        pack_seconds: f64_at(value, "hrkl_pack_seconds").unwrap_or(0.0),
        pack_throughput_bytes_sec: f64_at(value, "hrkl_pack_throughput_bytes_sec").unwrap_or(0.0),
        blocks_total: u64_at(value, "hrkl_blocks_total").unwrap_or(0),
        blocks_read: u64_at(value, "hrkl_blocks_read").unwrap_or(0),
        blocks_pruned: u64_at(value, "hrkl_blocks_pruned").unwrap_or(0),
        bytes_pruned: u64_at(value, "hrkl_bytes_pruned").unwrap_or(0),
        decompressed_bytes: u64_at(value, "hrkl_decompressed_bytes").unwrap_or(0),
        hrki_hits: u64_at(value, "hrki_hits").unwrap_or(0),
        hrki_misses: u64_at(value, "hrki_misses").unwrap_or(0),
        hrki_rebuilds: u64_at(value, "hrki_rebuilds").unwrap_or(0),
        cold_range_reads: u64_at(value, "cold_range_reads").unwrap_or(0),
        cold_bytes_downloaded: u64_at(value, "cold_bytes_downloaded").unwrap_or(0),
        parquet_export_lag_lsn: u64_at(value, "parquet_export_lag_lsn").unwrap_or(0),
        canonical_verify_failures: u64_at(value, "canonical_verify_failures").unwrap_or(0),
        physical_crc_failures: u64_at(value, "physical_crc_failures").unwrap_or(0),
    }
}

pub(super) fn parse_sentinel(value: &Value) -> SentinelSnapshot {
    let boot = value.get("boot").unwrap_or(&Value::Null);
    SentinelSnapshot {
        available: true,
        enabled: value.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        mode: value_string(value.get("mode")),
        pipeline_version: u64_at(value, "pipeline_version").unwrap_or(0),
        head_lsn: u64_at(value, "head_lsn").unwrap_or(0),
        processed_lsn: u64_at(value, "processed_lsn"),
        detection_lag_lsn: u64_at(value, "detection_lag_lsn").unwrap_or(0),
        lag_state: value_string(value.get("lag_state")),
        queue_depth: u64_at(value, "queue_depth").unwrap_or(0),
        queue_capacity: u64_at(value, "queue_capacity").unwrap_or(0),
        queue_overflow_total: u64_at(value, "queue_overflow_total").unwrap_or(0),
        events_seen_total: u64_at(value, "events_seen_total").unwrap_or(0),
        events_processed_total: u64_at(value, "events_processed_total").unwrap_or(0),
        signals_emitted_total: u64_at(value, "signals_emitted_total").unwrap_or(0),
        threat_matches_total: u64_at(value, "threat_matches_total").unwrap_or(0),
        incidents_created_total: u64_at(value, "incidents_created_total").unwrap_or(0),
        incident_capacity_drops_total: u64_at(value, "incident_capacity_drops_total").unwrap_or(0),
        normalization_errors_total: u64_at(value, "normalization_errors_total").unwrap_or(0),
        l0_latency_us: u64_at(value, "l0_latency_us").unwrap_or(0),
        l1_latency_ms: u64_at(value, "l1_latency_ms").unwrap_or(0),
        l2_latency_ms: u64_at(value, "l2_latency_ms").unwrap_or(0),
        l3_latency_ms: u64_at(value, "l3_latency_ms").unwrap_or(0),
        ai_requests_total: u64_at(value, "ai_requests_total").unwrap_or(0),
        ai_failures_total: u64_at(value, "ai_failures_total").unwrap_or(0),
        ai_latency_ms: u64_at(value, "ai_latency_ms").unwrap_or(0),
        ai_tokens_total: u64_at(value, "ai_tokens_total").unwrap_or(0),
        ai_investigations_persisted_total: u64_at(value, "ai_investigations_persisted_total").unwrap_or(0),
        ai_circuit_state: value_string(value.get("ai_circuit_state")),
        actions_proposed_total: u64_at(value, "actions_proposed_total").unwrap_or(0),
        actions_approved_total: u64_at(value, "actions_approved_total").unwrap_or(0),
        actions_denied_total: u64_at(value, "actions_denied_total").unwrap_or(0),
        actions_executed_total: u64_at(value, "actions_executed_total").unwrap_or(0),
        action_failures_total: u64_at(value, "action_failures_total").unwrap_or(0),
        boot_outcome: value_string(boot.get("outcome")),
        boot_total_ms: u64_at(boot, "total_boot_ms").unwrap_or(0),
    }
}

pub(super) fn parse_compliance(value: &Value) -> ComplianceSnapshot {
    let anchor = value.get("anchor_health").unwrap_or(&Value::Null);
    let deadlines = value.get("regulatory_deadlines").unwrap_or(&Value::Null);
    let sovereignty = value.get("sovereignty").unwrap_or(&Value::Null);
    ComplianceSnapshot {
        available: true,
        as_of_lsn: u64_at(value, "as_of_lsn").unwrap_or(0),
        status: value_string(value.get("status")),
        trust_notice: value_string(value.get("trust_notice")),
        receipts_total: u64_at(anchor, "receipts_total").unwrap_or(0),
        current_sealed_watermark: u64_at(anchor, "current_sealed_watermark").unwrap_or(0),
        last_anchor_lsn: u64_at(anchor, "last_anchor_lsn"),
        deferred_anchors: u64_at(anchor, "deferred_anchors").unwrap_or(0),
        deferred_anchor_forks: u64_at(anchor, "deferred_anchor_forks").unwrap_or(0),
        deadline_total: u64_at(deadlines, "total").unwrap_or(0),
        deadline_overdue: u64_at(deadlines, "overdue").unwrap_or(0),
        deadline_24h: u64_at(deadlines, "due_within_24h").unwrap_or(0),
        deadline_48h: u64_at(deadlines, "due_within_48h").unwrap_or(0),
        deadline_72h: u64_at(deadlines, "due_within_72h").unwrap_or(0),
        pending_anpd: array_len(value.get("anpd_pending_decisions")),
        legal_holds: array_len(value.get("legal_holds")),
        retention_exceptions: u64_at(value, "retention_exceptions").unwrap_or(0),
        active_policy_versions: u64_at(value, "active_policy_versions").unwrap_or(0),
        egress_allowed: u64_at(sovereignty, "egress_allowed").unwrap_or(0),
        egress_denied: u64_at(sovereignty, "egress_denied").unwrap_or(0),
        model_allowed: u64_at(sovereignty, "model_allowed").unwrap_or(0),
        model_denied: u64_at(sovereignty, "model_denied").unwrap_or(0),
    }
}

pub(super) fn parse_raft(value: &Value) -> RaftSnapshot {
    RaftSnapshot {
        available: value.is_object(),
        role: value_string(value.get("role").or_else(|| value.get("state"))),
        leader: value_string(value.get("leader").or_else(|| value.get("leader_id"))),
        term: u64_at(value, "term").or_else(|| u64_at(value, "current_term")),
        commit_index: u64_at(value, "commit_index"),
        applied_index: u64_at(value, "applied_index").or_else(|| u64_at(value, "last_applied")),
        node_id: value_string(value.get("node_id").or_else(|| value.get("id"))),
        peers: u64_at(value, "peers").or_else(|| {
            value.get("peers")
                .and_then(Value::as_array)
                .map(|v| v.len() as u64)
        }),
    }
}

pub(super) fn parse_agent(value: &Value) -> AgentSnapshot {
    let summary = value.get("summary").unwrap_or(&Value::Null);
    let ingest = value.get("ingest").unwrap_or(&Value::Null);
    let gateway = value.get("gateway").unwrap_or(&Value::Null);
    let policy = value.get("policy").unwrap_or(&Value::Null);
    let capture = value.get("capture").unwrap_or(&Value::Null);
    AgentSnapshot {
        available: true,
        product: value_string(value.get("product")),
        auth: value_string(value.get("auth")),
        auth_identifies_people: value
            .get("auth_identifies_people")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        evidence_log: value_string(value.get("evidence_log")),
        otlp_ingest: value_string(value.get("otlp_ingest")),
        mcp_gateway: value_string(value.get("mcp_gateway")),
        bypass_protection: value_string(value.get("bypass_protection")),
        rfc3161: value_string(value.get("rfc3161")),
        policy_id: value_string(policy.get("id")),
        policy_version: value_string(policy.get("version")),
        policy_hash: value_string(policy.get("hash")),
        policy_lifecycle: value_string(policy.get("lifecycle")),
        capture_mode: value_string(capture.get("mode")),
        runs: u64_at(summary, "runs").unwrap_or(0),
        tool_calls: u64_at(summary, "tool_calls").unwrap_or(0),
        denied: u64_at(summary, "denied").unwrap_or(0),
        pending_approvals: u64_at(summary, "pending_approvals").unwrap_or(0),
        integrity: value_string(summary.get("integrity")),
        ingest_events: u64_at(ingest, "events").unwrap_or(0),
        ingest_duplicates: u64_at(ingest, "duplicates").unwrap_or(0),
        ingest_conflicts: u64_at(ingest, "conflicts").unwrap_or(0),
        ingest_rejected: u64_at(ingest, "rejected").unwrap_or(0),
        ingest_ignored_spans: u64_at(ingest, "ignored_spans").unwrap_or(0),
        gateway_requests: u64_at(gateway, "requests").unwrap_or(0),
        gateway_allow: u64_at(gateway, "allow").unwrap_or(0),
        gateway_deny: u64_at(gateway, "deny").unwrap_or(0),
        gateway_require_approval: u64_at(gateway, "require_approval").unwrap_or(0),
        gateway_shadow_deny: u64_at(gateway, "shadow_deny").unwrap_or(0),
        approval_expired: u64_at(gateway, "approval_expired").unwrap_or(0),
        approval_replay_rejected: u64_at(gateway, "approval_replay_rejected").unwrap_or(0),
        approval_capacity_rejected: u64_at(gateway, "approval_capacity_rejected").unwrap_or(0),
        policy_errors: u64_at(gateway, "policy_errors").unwrap_or(0),
        evidence_errors: u64_at(gateway, "evidence_errors").unwrap_or(0),
        upstream_errors: u64_at(gateway, "upstream_errors").unwrap_or(0),
    }
}

pub(super) fn parse_redteam(value: &Value) -> RedTeamSnapshot {
    let summary = value.get("summary").unwrap_or(&Value::Null);
    let events = value
        .get("events")
        .and_then(Value::as_array)
        .map(|events| {
            events
                .iter()
                .map(|event| RedTeamEvent {
                    evidence_id: value_string(event.get("evidence_id")),
                    observed_at_unix_nanos: u64_at(event, "observed_at_unix_nanos").unwrap_or(0),
                    attack_id: value_string(event.get("attack_id")),
                    campaign_id: value_string(event.get("campaign_id")),
                    vector: value_string(event.get("vector")),
                    target: value_string(event.get("target")),
                    phase: value_string(event.get("phase")),
                    result: value_string(event.get("result")),
                    expected: value_string(event.get("expected")),
                    reason_code: value_string(event.get("reason_code")),
                    blocked: event.get("blocked").and_then(Value::as_bool).unwrap_or(false),
                    upstream_delta: event.get("upstream_delta").and_then(Value::as_i64).unwrap_or(0),
                    transport_status: u64_at(event, "transport_status"),
                })
                .collect()
        })
        .unwrap_or_default();
    RedTeamSnapshot {
        available: true,
        returned: u64_at(summary, "returned").unwrap_or(events.len() as u64),
        blocked: u64_at(summary, "blocked").unwrap_or(0),
        reached_upstream: u64_at(summary, "reached_upstream").unwrap_or(0),
        events,
    }
}

pub(super) fn extract_watermarks(value: &Value) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    if let Some(obj) = value.get("view_watermarks").and_then(Value::as_object) {
        for (name, value) in obj {
            if let Some(lsn) = value.as_u64() {
                out.push((name.clone(), lsn));
            }
        }
    }
    if out.is_empty() {
        if let Some(obj) = value.get("watermarks").and_then(Value::as_object) {
            for (name, value) in obj {
                if let Some(lsn) = value.as_u64() {
                    out.push((name.clone(), lsn));
                }
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn array_len(value: Option<&Value>) -> u64 {
    value
        .and_then(Value::as_array)
        .map(|array| array.len() as u64)
        .unwrap_or(0)
}

pub(super) fn u64_at(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
    })
}

pub(super) fn f64_at(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64)
}

pub(super) fn value_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

pub(super) fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redteam_escape_is_critical() {
        let storage = StorageSnapshot::default();
        let sentinel = SentinelSnapshot::default();
        let compliance = ComplianceSnapshot::default();
        let agent = AgentSnapshot::default();
        let baseline = AlarmBaseline::default();
        let redteam = RedTeamSnapshot {
            available: true,
            events: vec![RedTeamEvent {
                observed_at_unix_nanos: unix_nanos(),
                upstream_delta: 1,
                ..Default::default()
            }],
            ..Default::default()
        };
        let alarms = evaluate_alarms(AlarmInputs {
            online: true,
            consecutive_failures: 0,
            grpc_reachable: Some(true),
            storage: &storage,
            sentinel: &sentinel,
            compliance: &compliance,
            agent: &agent,
            redteam: &redteam,
            baseline: &baseline,
        });
        assert!(alarms.iter().any(|a| {
            a.id == "redteam.upstream_escape" && a.severity == AlarmSeverity::Critical
        }));
    }

    #[test]
    fn replay_rejection_generates_attack_alarm() {
        let storage = StorageSnapshot::default();
        let sentinel = SentinelSnapshot::default();
        let compliance = ComplianceSnapshot::default();
        let redteam = RedTeamSnapshot::default();
        let agent = AgentSnapshot {
            available: true,
            evidence_log: "HEALTHY".into(),
            integrity: "HEALTHY".into(),
            bypass_protection: "CONFIGURED".into(),
            approval_replay_rejected: 9,
            ..Default::default()
        };
        let baseline = AlarmBaseline {
            approval_replay_rejected: 8,
            ..Default::default()
        };
        let alarms = evaluate_alarms(AlarmInputs {
            online: true,
            consecutive_failures: 0,
            grpc_reachable: Some(true),
            storage: &storage,
            sentinel: &sentinel,
            compliance: &compliance,
            agent: &agent,
            redteam: &redteam,
            baseline: &baseline,
        });
        assert!(alarms.iter().any(|a| a.id == "agent.approval_replay"));
    }
}
