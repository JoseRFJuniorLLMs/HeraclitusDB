use super::http;
use super::security::{
    apply_redteam, derive_alarms, parse_agent_status, parse_dashboard, AgentSecuritySnapshot,
    AlarmInputs, SecurityAlarm, SecurityDashboardSnapshot,
};
use serde_json::Value;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub(super) const HISTORY_SAMPLES: usize = 120;
pub(super) const MIN_INTERVAL_SECS: f64 = 0.10;
pub(super) const MAX_INTERVAL_SECS: f64 = 10.0;
const SENTINEL_REFRESH: Duration = Duration::from_secs(2);
const AGENT_REFRESH: Duration = Duration::from_secs(1);
const GRPC_REFRESH: Duration = Duration::from_secs(5);
const COMPLIANCE_REFRESH: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ActiveTab {
    Overview = 0,
    Tasks = 1,
    Storage = 2,
    Queries = 3,
    Raft = 4,
    Security = 5,
    Agents = 6,
    Indexes = 7,
}

impl ActiveTab {
    pub(super) const COUNT: usize = 8;

    pub(super) fn from_index(index: usize) -> Self {
        match index % Self::COUNT {
            0 => Self::Overview,
            1 => Self::Tasks,
            2 => Self::Storage,
            3 => Self::Queries,
            4 => Self::Raft,
            5 => Self::Security,
            6 => Self::Agents,
            _ => Self::Indexes,
        }
    }

    pub(super) fn next(self) -> Self {
        Self::from_index(self as usize + 1)
    }

    pub(super) fn previous(self) -> Self {
        Self::from_index(self as usize + Self::COUNT - 1)
    }
}

#[derive(Debug, Default, Clone)]
pub(super) struct StorageSnapshot {
    pub(super) raw_bytes: u64,
    pub(super) packed_bytes: u64,
    pub(super) pack_queue_depth: u64,
    pub(super) parquet_export_lag_lsn: u64,
    pub(super) canonical_verify_failures: u64,
    pub(super) physical_crc_failures: u64,
    pub(super) hrki_hits: u64,
    pub(super) hrki_misses: u64,
    pub(super) hrki_rebuilds: u64,
}

#[derive(Debug, Default, Clone)]
pub(super) struct IndexSnapshot {
    pub(super) vector_indexed: u64,
    pub(super) text_indexed: u64,
    pub(super) graph_nodes: u64,
    pub(super) tgraph_edges: u64,
    pub(super) entity_keys: u64,
    pub(super) activation_tracked: u64,
}

#[derive(Debug, Default, Clone)]
pub(super) struct SentinelSnapshot {
    pub(super) available: bool,
    pub(super) enabled: bool,
    pub(super) mode: String,
    pub(super) lag_state: String,
    pub(super) detection_lag_lsn: u64,
    pub(super) queue_depth: u64,
    pub(super) queue_capacity: u64,
    pub(super) queue_overflow_total: u64,
    pub(super) events_processed_total: u64,
    pub(super) signals_emitted_total: u64,
    pub(super) threat_matches_total: u64,
    pub(super) incidents_created_total: u64,
    pub(super) incident_capacity_drops_total: u64,
    pub(super) normalization_errors_total: u64,
    pub(super) ai_requests_total: u64,
    pub(super) ai_failures_total: u64,
    pub(super) ai_latency_ms: u64,
    pub(super) ai_circuit_state: String,
    pub(super) actions_proposed_total: u64,
    pub(super) actions_approved_total: u64,
    pub(super) actions_denied_total: u64,
    pub(super) actions_executed_total: u64,
    pub(super) action_failures_total: u64,
}

#[derive(Debug, Default, Clone)]
pub(super) struct ComplianceSnapshot {
    pub(super) available: bool,
    pub(super) status: String,
    pub(super) current_sealed_watermark: u64,
    pub(super) deferred_anchors: u64,
    pub(super) deferred_anchor_forks: u64,
    pub(super) deadline_total: u64,
    pub(super) deadline_overdue: u64,
    pub(super) pending_anpd: u64,
    pub(super) legal_holds: u64,
    pub(super) egress_allowed: u64,
    pub(super) egress_denied: u64,
}

#[derive(Debug, Default, Clone)]
pub(super) struct RaftSnapshot {
    pub(super) available: bool,
    pub(super) role: String,
    pub(super) leader: String,
    pub(super) term: Option<u64>,
    pub(super) commit_index: Option<u64>,
    pub(super) applied_index: Option<u64>,
    pub(super) node_id: String,
    pub(super) peers: Option<u64>,
}

pub(super) struct AppState {
    pub(super) active_tab: ActiveTab,
    pub(super) paused: bool,
    pub(super) help: bool,
    pub(super) interval_sec: f64,
    pub(super) target_url: String,
    pub(super) core_authorization: String,
    pub(super) agent_url: String,
    pub(super) agent_authorization: String,
    pub(super) agent_expected: bool,
    pub(super) online: bool,
    pub(super) health: String,
    pub(super) last_error: Option<String>,
    pub(super) rest_latency_ms: f64,
    pub(super) grpc_reachable: Option<bool>,
    pub(super) grpc_latency_ms: Option<f64>,
    pub(super) head_lsn: u64,
    prev_head: Option<(u64, Instant)>,
    pub(super) insert_rate: f64,
    pub(super) peak_rate: f64,
    pub(super) rate_history: VecDeque<f64>,
    pub(super) storage_format: String,
    pub(super) memtable_entries: u64,
    pub(super) active_views: Vec<String>,
    pub(super) indexes: IndexSnapshot,
    pub(super) storage: StorageSnapshot,
    pub(super) sentinel: SentinelSnapshot,
    pub(super) security: SecurityDashboardSnapshot,
    pub(super) compliance: ComplianceSnapshot,
    pub(super) raft: RaftSnapshot,
    pub(super) agent: AgentSecuritySnapshot,
    last_sentinel: Option<Instant>,
    last_agent: Option<Instant>,
    last_compliance: Option<Instant>,
    last_grpc: Option<Instant>,
}

impl AppState {
    pub(super) fn new(
        target_url: String,
        core_authorization: String,
        interval_sec: f64,
    ) -> Self {
        let agent_url = http::agent_url(&target_url);
        Self {
            active_tab: ActiveTab::Overview,
            paused: false,
            help: false,
            interval_sec: interval_sec.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS),
            target_url,
            core_authorization,
            agent_url,
            agent_authorization: http::agent_authorization(),
            agent_expected: http::agent_explicitly_configured(),
            online: false,
            health: "UNKNOWN".into(),
            last_error: None,
            rest_latency_ms: 0.0,
            grpc_reachable: None,
            grpc_latency_ms: None,
            head_lsn: 0,
            prev_head: None,
            insert_rate: 0.0,
            peak_rate: 0.0,
            rate_history: VecDeque::with_capacity(HISTORY_SAMPLES),
            storage_format: "unknown".into(),
            memtable_entries: 0,
            active_views: Vec::new(),
            indexes: IndexSnapshot::default(),
            storage: StorageSnapshot::default(),
            sentinel: SentinelSnapshot::default(),
            security: SecurityDashboardSnapshot::default(),
            compliance: ComplianceSnapshot::default(),
            raft: RaftSnapshot::default(),
            agent: AgentSecuritySnapshot::default(),
            last_sentinel: None,
            last_agent: None,
            last_compliance: None,
            last_grpc: None,
        }
    }

    pub(super) fn refresh(&mut self, force: bool) {
        let now = Instant::now();
        match http::fetch_json(
            &self.target_url,
            &self.core_authorization,
            "/stats",
            7475,
        ) {
            Ok((stats, latency)) => {
                self.online = true;
                self.rest_latency_ms = latency;
                self.last_error = None;
                self.apply_stats(&stats, now);
            }
            Err(error) => {
                self.online = false;
                self.last_error = Some(error);
            }
        }

        if let Ok(response) = http::fetch_http(
            &self.target_url,
            &self.core_authorization,
            "/healthz",
            7475,
        ) {
            if response.is_success() {
                self.health = String::from_utf8_lossy(&response.body).trim().to_string();
            }
        }

        if force || due(self.last_sentinel, SENTINEL_REFRESH, now) {
            self.last_sentinel = Some(now);
            self.poll_sentinel();
        }
        if force || due(self.last_agent, AGENT_REFRESH, now) {
            self.last_agent = Some(now);
            self.poll_agent();
        }
        if force || due(self.last_compliance, COMPLIANCE_REFRESH, now) {
            self.last_compliance = Some(now);
            self.poll_compliance();
        }
        if force || due(self.last_grpc, GRPC_REFRESH, now) {
            self.last_grpc = Some(now);
            match http::probe_tcp(&self.target_url, 7474) {
                Ok(ms) => {
                    self.grpc_reachable = Some(true);
                    self.grpc_latency_ms = Some(ms);
                }
                Err(_) => {
                    self.grpc_reachable = Some(false);
                    self.grpc_latency_ms = None;
                }
            }
        }
    }

    pub(super) fn alarms(&self) -> Vec<SecurityAlarm> {
        derive_alarms(&AlarmInputs {
            online: self.online,
            grpc_reachable: self.grpc_reachable,
            threat_level: &self.security.threat_level,
            incidents: &self.security.incidents,
            sentinel_lag_state: &self.sentinel.lag_state,
            detection_lag_lsn: self.sentinel.detection_lag_lsn,
            queue_overflow_total: self.sentinel.queue_overflow_total,
            incident_capacity_drops_total: self.sentinel.incident_capacity_drops_total,
            normalization_errors_total: self.sentinel.normalization_errors_total,
            action_failures_total: self.sentinel.action_failures_total,
            ai_circuit_state: &self.sentinel.ai_circuit_state,
            canonical_verify_failures: self.storage.canonical_verify_failures,
            physical_crc_failures: self.storage.physical_crc_failures,
            parquet_export_lag_lsn: self.storage.parquet_export_lag_lsn,
            deferred_anchor_forks: self.compliance.deferred_anchor_forks,
            deadline_overdue: self.compliance.deadline_overdue,
            pending_anpd: self.compliance.pending_anpd,
            agent_expected: self.agent_expected || self.agent.available,
            agent: &self.agent,
        })
    }

    fn apply_stats(&mut self, value: &Value, now: Instant) {
        let head = u64_at(value, "head").unwrap_or(0);
        if let Some((previous, at)) = self.prev_head {
            let elapsed = now.saturating_duration_since(at).as_secs_f64();
            if elapsed > 0.0 {
                self.insert_rate = head.saturating_sub(previous) as f64 / elapsed;
            }
        }
        self.prev_head = Some((head, now));
        self.head_lsn = head;
        self.peak_rate = self.peak_rate.max(self.insert_rate);
        push_history(&mut self.rate_history, self.insert_rate);
        self.storage_format = string_at(value, "storage_format").unwrap_or_else(|| "unknown".into());
        self.memtable_entries = u64_at(value, "memtable").unwrap_or(0);
        self.active_views = value
            .get("views")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        self.indexes = IndexSnapshot {
            vector_indexed: u64_at(value, "vector_indexed").unwrap_or(0),
            text_indexed: u64_at(value, "text_indexed").unwrap_or(0),
            graph_nodes: u64_at(value, "graph_nodes").unwrap_or(0),
            tgraph_edges: u64_at(value, "tgraph_edges").unwrap_or(0),
            entity_keys: u64_at(value, "entity_keys").unwrap_or(0),
            activation_tracked: u64_at(value, "activation_tracked").unwrap_or(0),
        };
        if let Some(storage) = value.get("storage_metrics") {
            self.storage = parse_storage(storage);
        }
        if let Some(raft) = value.get("raft") {
            self.raft = parse_raft(raft);
        } else {
            self.raft.available = false;
        }
    }

    fn poll_sentinel(&mut self) {
        match http::fetch_json(
            &self.target_url,
            &self.core_authorization,
            "/sentinel/dashboard",
            7475,
        ) {
            Ok((value, _)) => {
                self.security = parse_dashboard(&value);
                if let Some(status) = value.get("status") {
                    self.sentinel = parse_sentinel(status);
                }
            }
            Err(_) => match http::fetch_json(
                &self.target_url,
                &self.core_authorization,
                "/sentinel/status",
                7475,
            ) {
                Ok((value, _)) => self.sentinel = parse_sentinel(&value),
                Err(_) => {
                    self.sentinel.available = false;
                    self.security.available = false;
                }
            },
        }
    }

    fn poll_agent(&mut self) {
        match http::fetch_json(
            &self.agent_url,
            &self.agent_authorization,
            "/api/v1/agent/status",
            8080,
        ) {
            Ok((value, latency_ms)) => {
                let previous = self.agent.clone();
                self.agent = parse_agent_status(&value, latency_ms, &previous);
                self.agent_expected = true;
                match http::fetch_json(
                    &self.agent_url,
                    &self.agent_authorization,
                    "/api/v1/agent/red-team/events?limit=40",
                    8080,
                ) {
                    Ok((redteam, _)) => apply_redteam(&mut self.agent, &redteam),
                    Err(_) => self.agent.redteam_available = false,
                }
            }
            Err(error) => {
                self.agent.available = false;
                self.agent.last_error = error;
            }
        }
    }

    fn poll_compliance(&mut self) {
        match http::fetch_json(
            &self.target_url,
            &self.core_authorization,
            "/compliance/status",
            7475,
        ) {
            Ok((value, _)) => self.compliance = parse_compliance(&value),
            Err(_) => self.compliance.available = false,
        }
    }
}

fn due(last: Option<Instant>, duration: Duration, now: Instant) -> bool {
    match last {
        Some(value) => now.saturating_duration_since(value) >= duration,
        None => true,
    }
}

fn push_history(history: &mut VecDeque<f64>, value: f64) {
    if history.len() >= HISTORY_SAMPLES {
        history.pop_front();
    }
    history.push_back(value);
}

fn parse_storage(value: &Value) -> StorageSnapshot {
    StorageSnapshot {
        raw_bytes: u64_at(value, "hrkl_raw_bytes").unwrap_or(0),
        packed_bytes: u64_at(value, "hrkl_packed_bytes").unwrap_or(0),
        pack_queue_depth: u64_at(value, "hrkl_pack_queue_depth").unwrap_or(0),
        parquet_export_lag_lsn: u64_at(value, "parquet_export_lag_lsn").unwrap_or(0),
        canonical_verify_failures: u64_at(value, "canonical_verify_failures").unwrap_or(0),
        physical_crc_failures: u64_at(value, "physical_crc_failures").unwrap_or(0),
        hrki_hits: u64_at(value, "hrki_hits").unwrap_or(0),
        hrki_misses: u64_at(value, "hrki_misses").unwrap_or(0),
        hrki_rebuilds: u64_at(value, "hrki_rebuilds").unwrap_or(0),
    }
}

fn parse_sentinel(value: &Value) -> SentinelSnapshot {
    SentinelSnapshot {
        available: true,
        enabled: value.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        mode: string_at(value, "mode").unwrap_or_default(),
        lag_state: string_at(value, "lag_state").unwrap_or_else(|| "unknown".into()),
        detection_lag_lsn: u64_at(value, "detection_lag_lsn").unwrap_or(0),
        queue_depth: u64_at(value, "queue_depth").unwrap_or(0),
        queue_capacity: u64_at(value, "queue_capacity").unwrap_or(0),
        queue_overflow_total: u64_at(value, "queue_overflow_total").unwrap_or(0),
        events_processed_total: u64_at(value, "events_processed_total").unwrap_or(0),
        signals_emitted_total: u64_at(value, "signals_emitted_total").unwrap_or(0),
        threat_matches_total: u64_at(value, "threat_matches_total").unwrap_or(0),
        incidents_created_total: u64_at(value, "incidents_created_total").unwrap_or(0),
        incident_capacity_drops_total: u64_at(value, "incident_capacity_drops_total").unwrap_or(0),
        normalization_errors_total: u64_at(value, "normalization_errors_total").unwrap_or(0),
        ai_requests_total: u64_at(value, "ai_requests_total").unwrap_or(0),
        ai_failures_total: u64_at(value, "ai_failures_total").unwrap_or(0),
        ai_latency_ms: u64_at(value, "ai_latency_ms").unwrap_or(0),
        ai_circuit_state: string_at(value, "ai_circuit_state").unwrap_or_default(),
        actions_proposed_total: u64_at(value, "actions_proposed_total").unwrap_or(0),
        actions_approved_total: u64_at(value, "actions_approved_total").unwrap_or(0),
        actions_denied_total: u64_at(value, "actions_denied_total").unwrap_or(0),
        actions_executed_total: u64_at(value, "actions_executed_total").unwrap_or(0),
        action_failures_total: u64_at(value, "action_failures_total").unwrap_or(0),
    }
}

fn parse_compliance(value: &Value) -> ComplianceSnapshot {
    ComplianceSnapshot {
        available: true,
        status: string_at(value, "status").unwrap_or_else(|| "unknown".into()),
        current_sealed_watermark: u64_at(value, "current_sealed_watermark").unwrap_or(0),
        deferred_anchors: u64_at(value, "deferred_anchors").unwrap_or(0),
        deferred_anchor_forks: u64_at(value, "deferred_anchor_forks").unwrap_or(0),
        deadline_total: u64_at(value, "deadline_total").unwrap_or(0),
        deadline_overdue: u64_at(value, "deadline_overdue").unwrap_or(0),
        pending_anpd: u64_at(value, "pending_anpd").unwrap_or(0),
        legal_holds: u64_at(value, "legal_holds").unwrap_or(0),
        egress_allowed: u64_at(value, "egress_allowed").unwrap_or(0),
        egress_denied: u64_at(value, "egress_denied").unwrap_or(0),
    }
}

fn parse_raft(value: &Value) -> RaftSnapshot {
    RaftSnapshot {
        available: true,
        role: string_at(value, "role").unwrap_or_default(),
        leader: string_at(value, "leader").unwrap_or_default(),
        term: u64_at(value, "term"),
        commit_index: u64_at(value, "commit_index"),
        applied_index: u64_at(value, "applied_index"),
        node_id: string_at(value, "node_id").unwrap_or_default(),
        peers: u64_at(value, "peers"),
    }
}

fn string_at(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn u64_at(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(|item| {
        item.as_u64()
            .or_else(|| item.as_i64().and_then(|number| (number >= 0).then_some(number as u64)))
    })
}
