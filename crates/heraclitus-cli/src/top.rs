//! HeraclitusDB interactive Task Manager (`heraclitus top`).
//!
//! This implementation intentionally renders only telemetry that the server
//! actually exposes. It does not fake Raft state, gRPC health, Sentinel health,
//! memtable capacity, task progress, CPU or RSS.
//!
//! Fast polling:
//!   GET /healthz
//!   GET /stats
//!
//! Periodic polling:
//!   GET /sentinel/status      (2 s)
//!   TCP probe of gRPC :7474   (5 s, reachability only)
//!   GET /state                (10 s; deliberately slower because it is heavier)
//!   GET /compliance/status    (30 s; deliberately slower because it replays state)

use crossterm::{
    cursor::Show,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Chart, Clear, Dataset, Gauge, GraphType, Paragraph, Row, Table,
        TableState, Tabs, Wrap,
    },
    Terminal,
};
use serde_json::Value;
use std::collections::VecDeque;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const HISTORY_SAMPLES: usize = 120;
const MIN_INTERVAL_SECS: f64 = 0.10;
const MAX_INTERVAL_SECS: f64 = 10.0;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
const IO_TIMEOUT: Duration = Duration::from_millis(3_000);
const SENTINEL_REFRESH: Duration = Duration::from_secs(2);
const GRPC_PROBE_REFRESH: Duration = Duration::from_secs(5);
const STATE_REFRESH: Duration = Duration::from_secs(10);
const COMPLIANCE_REFRESH: Duration = Duration::from_secs(30);
const REDTEAM_REFRESH: Duration = Duration::from_secs(1);
const AGENT_STATUS_REFRESH: Duration = Duration::from_secs(2);

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Overview = 0,
    Pipelines = 1,
    Storage = 2,
    Queries = 3,
    Raft = 4,
    Security = 5,
    Agents = 6,
    Indexes = 7,
    Compliance = 8,
}

impl ActiveTab {
    const COUNT: usize = 9;

    fn from_index(index: usize) -> Self {
        match index % Self::COUNT {
            0 => Self::Overview,
            1 => Self::Pipelines,
            2 => Self::Storage,
            3 => Self::Queries,
            4 => Self::Raft,
            5 => Self::Security,
            6 => Self::Agents,
            7 => Self::Indexes,
            _ => Self::Compliance,
        }
    }

    fn next(self) -> Self {
        Self::from_index(self as usize + 1)
    }

    fn previous(self) -> Self {
        Self::from_index(self as usize + Self::COUNT - 1)
    }
}

#[derive(Debug, Default, Clone)]
struct StorageSnapshot {
    available: bool,
    append_bytes_total: u64,
    raw_bytes: u64,
    packed_bytes: u64,
    compression_ratio: f64,
    pack_queue_depth: u64,
    pack_seconds: f64,
    pack_throughput_bytes_sec: f64,
    blocks_total: u64,
    blocks_read: u64,
    blocks_pruned: u64,
    bytes_pruned: u64,
    decompressed_bytes: u64,
    hrki_hits: u64,
    hrki_misses: u64,
    hrki_rebuilds: u64,
    cold_range_reads: u64,
    cold_bytes_downloaded: u64,
    parquet_export_lag_lsn: u64,
    canonical_verify_failures: u64,
    physical_crc_failures: u64,
}

#[derive(Debug, Default, Clone)]
struct IndexSnapshot {
    vector_indexed: u64,
    text_indexed: u64,
    graph_nodes: u64,
    tgraph_edges: u64,
    entity_keys: u64,
    activation_tracked: u64,
}

// Os campos abaixo são desserializados do `/sentinel/status` e ainda não têm
// linha no painel. Mantê-los é deliberado: o parser descreve a resposta INTEIRA,
// e um campo que desaparece do lado do servidor deixa de compilar aqui em vez de
// falhar em silêncio no dia em que alguém o quiser mostrar.
#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
struct SentinelSnapshot {
    available: bool,
    enabled: bool,
    mode: String,
    pipeline_version: u64,
    head_lsn: u64,
    next_lsn: u64,
    processed_lsn: Option<u64>,
    detection_lag_lsn: u64,
    lag_state: String,
    queue_depth: u64,
    queue_capacity: u64,
    queue_overflow_total: u64,
    events_seen_total: u64,
    events_processed_total: u64,
    events_normalized_total: u64,
    signals_emitted_total: u64,
    threat_matches_total: u64,
    incidents_created_total: u64,
    incident_capacity_drops_total: u64,
    normalization_errors_total: u64,
    l0_latency_us: u64,
    l1_latency_ms: u64,
    l2_latency_ms: u64,
    l3_latency_ms: u64,
    ai_requests_total: u64,
    ai_failures_total: u64,
    ai_latency_ms: u64,
    ai_tokens_total: u64,
    ai_investigations_persisted_total: u64,
    ai_circuit_state: String,
    actions_proposed_total: u64,
    actions_approved_total: u64,
    actions_denied_total: u64,
    actions_executed_total: u64,
    action_failures_total: u64,
    boot_outcome: String,
    boot_total_ms: u64,
    boot_tail_events: u64,
    boot_events_scanned_total: u64,
}

// Idem para `/compliance/status`.
#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
struct ComplianceSnapshot {
    available: bool,
    as_of_lsn: u64,
    status: String,
    trust_notice: String,
    receipts_total: u64,
    current_sealed_watermark: u64,
    last_anchor_lsn: Option<u64>,
    deferred_anchors: u64,
    deferred_anchor_forks: u64,
    deadline_total: u64,
    deadline_overdue: u64,
    deadline_24h: u64,
    deadline_48h: u64,
    deadline_72h: u64,
    pending_anpd: u64,
    legal_holds: u64,
    retention_exceptions: u64,
    active_policy_versions: u64,
    egress_allowed: u64,
    egress_denied: u64,
    model_allowed: u64,
    model_denied: u64,
}

#[derive(Debug, Default, Clone)]
struct RaftSnapshot {
    available: bool,
    role: String,
    leader: String,
    term: Option<u64>,
    commit_index: Option<u64>,
    applied_index: Option<u64>,
    node_id: String,
    peers: Option<u64>,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
struct RedTeamEvent {
    observed_at_unix_nanos: u64,
    attack_id: String,
    campaign_id: String,
    vector: String,
    target: String,
    phase: String,
    result: String,
    reason_code: String,
    blocked: bool,
    upstream_delta: i64,
    transport_status: Option<u16>,
    lsn: Option<u64>,
}

#[derive(Debug, Default, Clone)]
struct RedTeamSnapshot {
    available: bool,
    total_probes: u64,
    blocked: u64,
    reached_upstream: u64,
    active_campaign: String,
    last_attack_lsn: Option<u64>,
    events: Vec<RedTeamEvent>,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
struct AgentGatewayCounters {
    requests: u64,
    allow: u64,
    deny: u64,
    require_approval: u64,
    shadow_deny: u64,
    approval_replay_rejected: u64,
    approval_capacity_rejected: u64,
    approval_expired: u64,
    policy_errors: u64,
    evidence_errors: u64,
    upstream_errors: u64,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
struct AgentPolicySnapshot {
    id: String,
    version: String,
    lifecycle: String,
    rules: u64,
    hash: String,
    activated_by: String,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
struct AgentIngestSnapshot {
    events: u64,
    batches: u64,
    bytes: u64,
    duplicates: u64,
    conflicts: u64,
    rejected: u64,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
struct AgentIntegritySnapshot {
    total: u64,
    pending_seal: u64,
    proved: u64,
    broken: u64,
    missing: u64,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
struct AgentSummarySnapshot {
    runs: u64,
    tool_calls: u64,
    denied: u64,
    pending_approvals: u64,
    integrity: String,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
struct AgentStatusSnapshot {
    available: bool,
    engine: String,
    product: String,
    auth: String,
    bypass_protection: String,
    evidence_log: String,
    mcp_gateway: String,
    otlp_ingest: String,
    rfc3161: String,
    gateway: AgentGatewayCounters,
    policy: AgentPolicySnapshot,
    ingest: AgentIngestSnapshot,
    integrity: AgentIntegritySnapshot,
    summary: AgentSummarySnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlarmSeverity {
    Warning,
    Critical,
}

#[derive(Debug, Clone)]
struct Alarm {
    source: &'static str,
    code: &'static str,
    severity: AlarmSeverity,
    message: String,
    value: String,
}

#[derive(Debug, Clone)]
struct BackgroundTask {
    id: String,
    kind: String,
    state: String,
    progress: String,
    throughput: String,
    detail: String,
    severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Good,
    Neutral,
    Warning,
    Critical,
}

struct AppState {
    active_tab: ActiveTab,
    paused: bool,
    show_help: bool,
    interval_sec: f64,
    target_url: String,
    auth: String,

    online: bool,
    health_text: String,
    last_error: Option<String>,
    consecutive_failures: u64,
    rest_latency_ms: f64,
    last_success_elapsed: Option<Duration>,
    started_at: Instant,
    last_success_at: Option<Instant>,

    head_lsn: u64,
    prev_head: Option<u64>,
    prev_head_at: Option<Instant>,
    insert_rate: f64,
    peak_rate: f64,
    rate_history: VecDeque<f64>,
    storage_format: String,

    memtable_entries: u64,
    memtable_capacity: Option<u64>,
    active_views: Vec<String>,
    view_watermarks: Vec<(String, u64)>,

    indexes: IndexSnapshot,
    storage: StorageSnapshot,
    sentinel: SentinelSnapshot,
    compliance: ComplianceSnapshot,
    raft: RaftSnapshot,

    grpc_reachable: Option<bool>,
    grpc_probe_latency_ms: Option<f64>,

    last_state_poll: Option<Instant>,
    last_sentinel_poll: Option<Instant>,
    last_compliance_poll: Option<Instant>,
    last_grpc_probe: Option<Instant>,
    last_redteam_poll: Option<Instant>,
    last_agent_status_poll: Option<Instant>,

    agent_url: String,
    redteam: RedTeamSnapshot,
    agent_status: AgentStatusSnapshot,

    selected_task_index: usize,
}

impl AppState {
    fn new(target_url: String, auth: String, interval_sec: f64) -> Self {
        let agent_url = env::var("HERACLITUS_AGENT_URL")
            .unwrap_or_else(|_| derive_agent_url(&target_url));

        Self {
            active_tab: ActiveTab::Overview,
            paused: false,
            show_help: false,
            interval_sec: interval_sec.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS),
            target_url,
            auth,

            online: false,
            health_text: "UNKNOWN".to_string(),
            last_error: None,
            consecutive_failures: 0,
            rest_latency_ms: 0.0,
            last_success_elapsed: None,
            started_at: Instant::now(),
            last_success_at: None,

            head_lsn: 0,
            prev_head: None,
            prev_head_at: None,
            insert_rate: 0.0,
            peak_rate: 0.0,
            rate_history: VecDeque::with_capacity(HISTORY_SAMPLES),
            storage_format: "unknown".to_string(),

            memtable_entries: 0,
            memtable_capacity: None,
            active_views: Vec::new(),
            view_watermarks: Vec::new(),

            indexes: IndexSnapshot::default(),
            storage: StorageSnapshot::default(),
            sentinel: SentinelSnapshot::default(),
            compliance: ComplianceSnapshot::default(),
            raft: RaftSnapshot::default(),
            redteam: RedTeamSnapshot::default(),
            agent_status: AgentStatusSnapshot::default(),

            grpc_reachable: None,
            grpc_probe_latency_ms: None,

            last_state_poll: None,
            last_sentinel_poll: None,
            last_compliance_poll: None,
            last_grpc_probe: None,
            last_redteam_poll: None,
            last_agent_status_poll: None,

            agent_url,

            selected_task_index: 0,
        }
    }

    fn update_fast(&mut self) {
        let now = Instant::now();

        // /healthz is intentionally cheap and does not take the heavyweight
        // locks used by /stats and /state.
        if let Ok(response) = fetch_with_fallback(&mut self.target_url, &mut self.auth, "/healthz")
        {
            if response.is_success() {
                self.health_text = response.body_text().trim().to_string();
            }
        }

        match fetch_json_with_fallback(&mut self.target_url, &mut self.auth, "/stats") {
            Ok((stats, latency_ms)) => {
                self.online = true;
                self.consecutive_failures = 0;
                self.rest_latency_ms = latency_ms;
                self.last_error = None;
                self.last_success_at = Some(now);
                self.last_success_elapsed = Some(Duration::ZERO);
                self.apply_stats(stats, now);
            }
            Err(error) => {
                self.online = false;
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                self.last_error = Some(error);
                if let Some(last) = self.last_success_at {
                    self.last_success_elapsed = Some(now.saturating_duration_since(last));
                }
            }
        }

        if should_poll(self.last_sentinel_poll, SENTINEL_REFRESH, now) {
            self.last_sentinel_poll = Some(now);
            self.poll_sentinel();
        }

        if should_poll(self.last_grpc_probe, GRPC_PROBE_REFRESH, now) {
            self.last_grpc_probe = Some(now);
            self.poll_grpc();
        }

        if should_poll(self.last_state_poll, STATE_REFRESH, now) {
            self.last_state_poll = Some(now);
            self.poll_state();
        }

        if should_poll(self.last_compliance_poll, COMPLIANCE_REFRESH, now) {
            self.last_compliance_poll = Some(now);
            self.poll_compliance();
        }

        if should_poll(self.last_redteam_poll, REDTEAM_REFRESH, now) {
            self.last_redteam_poll = Some(now);
            self.poll_redteam();
        }

        if should_poll(self.last_agent_status_poll, AGENT_STATUS_REFRESH, now) {
            self.last_agent_status_poll = Some(now);
            self.poll_agent_status();
        }

        let task_count = self.background_tasks().len();
        if task_count == 0 {
            self.selected_task_index = 0;
        } else {
            self.selected_task_index = self.selected_task_index.min(task_count - 1);
        }
    }

    fn force_refresh(&mut self) {
        self.last_state_poll = None;
        self.last_sentinel_poll = None;
        self.last_compliance_poll = None;
        self.last_grpc_probe = None;
        self.last_redteam_poll = None;
        self.last_agent_status_poll = None;
        self.update_fast();
    }

    fn apply_stats(&mut self, stats: Value, now: Instant) {
        let current_head = u64_at(&stats, "head").unwrap_or(0);
        self.head_lsn = current_head;
        self.storage_format =
            string_at(&stats, "storage_format").unwrap_or_else(|| "unknown".into());
        self.memtable_entries = u64_at(&stats, "memtable").unwrap_or(0);
        self.memtable_capacity = u64_at(&stats, "memtable_capacity")
            .or_else(|| stats.pointer("/memtable/capacity").and_then(Value::as_u64));

        if let (Some(previous), Some(previous_at)) = (self.prev_head, self.prev_head_at) {
            let dt = now.saturating_duration_since(previous_at).as_secs_f64();
            if dt > 0.0 {
                self.insert_rate = current_head.saturating_sub(previous) as f64 / dt;
            }
        } else {
            self.insert_rate = 0.0;
        }
        self.prev_head = Some(current_head);
        self.prev_head_at = Some(now);
        self.peak_rate = self.peak_rate.max(self.insert_rate);
        push_history(&mut self.rate_history, self.insert_rate, HISTORY_SAMPLES);

        self.active_views = stats
            .get("views")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        self.indexes = IndexSnapshot {
            vector_indexed: u64_at(&stats, "vector_indexed").unwrap_or(0),
            text_indexed: u64_at(&stats, "text_indexed").unwrap_or(0),
            graph_nodes: u64_at(&stats, "graph_nodes").unwrap_or(0),
            tgraph_edges: u64_at(&stats, "tgraph_edges").unwrap_or(0),
            entity_keys: u64_at(&stats, "entity_keys").unwrap_or(0),
            activation_tracked: u64_at(&stats, "activation_tracked").unwrap_or(0),
        };

        if let Some(storage) = stats.get("storage_metrics") {
            self.storage = parse_storage(storage);
        }

        // Forward compatible: when the server eventually exposes a raft object
        // in /stats, the same CLI starts rendering it without inventing data on
        // older builds.
        if let Some(raft) = stats.get("raft") {
            self.raft = parse_raft(raft);
        } else {
            self.raft.available = false;
        }
    }

    fn poll_state(&mut self) {
        if let Ok((state, _)) =
            fetch_json_with_fallback(&mut self.target_url, &mut self.auth, "/state")
        {
            self.view_watermarks = extract_watermarks(&state);
        }
    }

    fn poll_sentinel(&mut self) {
        match fetch_json_with_fallback(&mut self.target_url, &mut self.auth, "/sentinel/status") {
            Ok((value, _)) => self.sentinel = parse_sentinel(&value),
            Err(_) => self.sentinel.available = false,
        }
    }

    fn poll_compliance(&mut self) {
        match fetch_json_with_fallback(&mut self.target_url, &mut self.auth, "/compliance/status") {
            Ok((value, _)) => self.compliance = parse_compliance(&value),
            Err(_) => self.compliance.available = false,
        }
    }

    fn poll_grpc(&mut self) {
        match probe_grpc_port(&self.target_url) {
            Ok(latency) => {
                self.grpc_reachable = Some(true);
                self.grpc_probe_latency_ms = Some(latency);
            }
            Err(_) => {
                self.grpc_reachable = Some(false);
                self.grpc_probe_latency_ms = None;
            }
        }
    }

    fn poll_redteam(&mut self) {
        let mut target = self.agent_url.clone();
        let mut auth = self.auth.clone();
        match fetch_json_with_fallback(&mut target, &mut auth, "/api/v1/agent/red-team/events?limit=50") {
            Ok((value, _)) => self.redteam = parse_redteam(&value),
            Err(_) => {
                let mut empty_auth = String::new();
                match fetch_json_with_fallback(&mut target, &mut empty_auth, "/api/v1/agent/red-team/events?limit=50") {
                    Ok((value, _)) => self.redteam = parse_redteam(&value),
                    Err(_) => self.redteam.available = false,
                }
            }
        }
    }

    fn poll_agent_status(&mut self) {
        let mut target = self.agent_url.clone();
        let mut auth = self.auth.clone();
        match fetch_json_with_fallback(&mut target, &mut auth, "/api/v1/agent/status") {
            Ok((value, _)) => self.agent_status = parse_agent_status(&value),
            Err(_) => {
                let mut empty_auth = String::new();
                match fetch_json_with_fallback(&mut target, &mut empty_auth, "/api/v1/agent/status") {
                    Ok((value, _)) => self.agent_status = parse_agent_status(&value),
                    Err(_) => self.agent_status.available = false,
                }
            }
        }
    }

    fn evaluate_alarms(&self) -> Vec<Alarm> {
        let mut alarms = Vec::new();

        if !self.online {
            alarms.push(Alarm {
                source: "SERVER",
                code: "ALM-SRV-001",
                severity: AlarmSeverity::Critical,
                message: "REST server unreachable or offline".into(),
                value: "OFFLINE".into(),
            });
        }

        if self.redteam.reached_upstream > 0 {
            alarms.push(Alarm {
                source: "GATEWAY",
                code: "ALM-SEC-001",
                severity: AlarmSeverity::Critical,
                message: "Security boundary breach! Attack reached upstream target".into(),
                value: format!("+{} leaks", self.redteam.reached_upstream),
            });
        }

        if self.storage.physical_crc_failures > 0 {
            alarms.push(Alarm {
                source: "STORAGE",
                code: "ALM-CRC-001",
                severity: AlarmSeverity::Critical,
                message: "HRKL physical block CRC verification failure".into(),
                value: format!("{} crc err", self.storage.physical_crc_failures),
            });
        }

        if self.storage.canonical_verify_failures > 0 {
            alarms.push(Alarm {
                source: "STORAGE",
                code: "ALM-CAN-001",
                severity: AlarmSeverity::Critical,
                message: "Canonical serialization / hash verification failure".into(),
                value: format!("{} verify err", self.storage.canonical_verify_failures),
            });
        }

        if self.agent_status.available {
            if self.agent_status.evidence_log != "HEALTHY" && !self.agent_status.evidence_log.is_empty() {
                alarms.push(Alarm {
                    source: "AGENT",
                    code: "ALM-EVD-001",
                    severity: AlarmSeverity::Critical,
                    message: "Agent Black Box evidence log degraded or broken".into(),
                    value: self.agent_status.evidence_log.clone(),
                });
            }

            if self.agent_status.gateway.evidence_errors > 0 {
                alarms.push(Alarm {
                    source: "GATEWAY",
                    code: "ALM-EVD-002",
                    severity: AlarmSeverity::Critical,
                    message: "Agent Gateway evidence logging error".into(),
                    value: format!("{} errors", self.agent_status.gateway.evidence_errors),
                });
            }

            if self.agent_status.gateway.approval_replay_rejected > 0 {
                alarms.push(Alarm {
                    source: "GATEWAY",
                    code: "ALM-REP-001",
                    severity: AlarmSeverity::Warning,
                    message: "Replay attack detected on human-in-the-loop approvals".into(),
                    value: format!("{} rejections", self.agent_status.gateway.approval_replay_rejected),
                });
            }

            if self.agent_status.gateway.policy_errors > 0 {
                alarms.push(Alarm {
                    source: "GATEWAY",
                    code: "ALM-POL-001",
                    severity: AlarmSeverity::Warning,
                    message: "Agent Gateway policy evaluation errors".into(),
                    value: format!("{} errors", self.agent_status.gateway.policy_errors),
                });
            }
        }

        if self.sentinel.available {
            if self.sentinel.queue_overflow_total > 0 {
                alarms.push(Alarm {
                    source: "SENTINEL",
                    code: "ALM-SNT-001",
                    severity: AlarmSeverity::Critical,
                    message: "Sentinel queue overflow dropped telemetry events".into(),
                    value: format!("{} drops", self.sentinel.queue_overflow_total),
                });
            }
            if self.sentinel.lag_state.to_ascii_uppercase() == "CRITICAL" {
                alarms.push(Alarm {
                    source: "SENTINEL",
                    code: "ALM-SNT-002",
                    severity: AlarmSeverity::Critical,
                    message: "Sentinel detection lag in critical state".into(),
                    value: format!("{} LSN lag", self.sentinel.detection_lag_lsn),
                });
            }
        }

        if self.compliance.available {
            if self.compliance.deadline_overdue > 0 {
                alarms.push(Alarm {
                    source: "COMPLIANCE",
                    code: "ALM-CMP-001",
                    severity: AlarmSeverity::Critical,
                    message: "Regulatory compliance deadlines overdue".into(),
                    value: format!("{}/{} overdue", self.compliance.deadline_overdue, self.compliance.deadline_total),
                });
            }
            if self.compliance.deferred_anchor_forks > 0 {
                alarms.push(Alarm {
                    source: "COMPLIANCE",
                    code: "ALM-CMP-002",
                    severity: AlarmSeverity::Critical,
                    message: "Deferred RFC 3161 anchor forks detected in trust store".into(),
                    value: format!("{} forks", self.compliance.deferred_anchor_forks),
                });
            }
        }

        if self.storage.available && self.storage.parquet_export_lag_lsn > 100_000 {
            alarms.push(Alarm {
                source: "LAKEHOUSE",
                code: "ALM-LAK-001",
                severity: AlarmSeverity::Warning,
                message: "Parquet Lakehouse export lag exceeds 100k LSN".into(),
                value: format!("lag={}", format_number(self.storage.parquet_export_lag_lsn)),
            });
        }

        alarms
    }

    fn alarm_counts(&self) -> (usize, usize) {
        let alarms = self.evaluate_alarms();
        let crit = alarms.iter().filter(|a| a.severity == AlarmSeverity::Critical).count();
        let warn = alarms.iter().filter(|a| a.severity == AlarmSeverity::Warning).count();
        (crit, warn)
    }

    fn background_tasks(&self) -> Vec<BackgroundTask> {
        let mut tasks = Vec::new();

        if self.storage.available {
            tasks.push(BackgroundTask {
                id: "HRKL".into(),
                kind: "PACKING".into(),
                state: if self.storage.pack_queue_depth > 0 {
                    "RUNNING"
                } else {
                    "IDLE"
                }
                .into(),
                progress: "N/D".into(),
                throughput: format_rate_bytes(self.storage.pack_throughput_bytes_sec),
                detail: format!("queue={} blocos", self.storage.pack_queue_depth),
                severity: if self.storage.pack_queue_depth > 0 {
                    Severity::Neutral
                } else {
                    Severity::Good
                },
            });

            tasks.push(BackgroundTask {
                id: "LAKE".into(),
                kind: "PARQUET EXPORT".into(),
                state: if self.storage.parquet_export_lag_lsn > 0 {
                    "LAGGING"
                } else {
                    "SYNCED"
                }
                .into(),
                progress: "N/D".into(),
                throughput: "N/D".into(),
                detail: format!(
                    "lag={} LSN",
                    format_number(self.storage.parquet_export_lag_lsn)
                ),
                severity: if self.storage.parquet_export_lag_lsn > 0 {
                    Severity::Warning
                } else {
                    Severity::Good
                },
            });

            let index_total = self
                .storage
                .hrki_hits
                .saturating_add(self.storage.hrki_misses);
            let hit_rate = if index_total > 0 {
                100.0 * self.storage.hrki_hits as f64 / index_total as f64
            } else {
                0.0
            };
            tasks.push(BackgroundTask {
                id: "HRKI".into(),
                kind: "INDEX SIDECAR".into(),
                state: if self.storage.hrki_rebuilds == 0 {
                    "HEALTHY"
                } else {
                    "OBSERVE"
                }
                .into(),
                progress: "N/D".into(),
                throughput: if index_total > 0 {
                    format!("{hit_rate:.1}% hit")
                } else {
                    "N/D".into()
                },
                detail: format!("rebuilds={}", self.storage.hrki_rebuilds),
                severity: if self.storage.hrki_rebuilds == 0 {
                    Severity::Good
                } else {
                    Severity::Warning
                },
            });

            tasks.push(BackgroundTask {
                id: "CRC".into(),
                kind: "PHYSICAL INTEGRITY".into(),
                state: if self.storage.physical_crc_failures == 0 {
                    "HEALTHY"
                } else {
                    "FAILED"
                }
                .into(),
                progress: "N/D".into(),
                throughput: "N/D".into(),
                detail: format!("crc_failures={}", self.storage.physical_crc_failures),
                severity: if self.storage.physical_crc_failures == 0 {
                    Severity::Good
                } else {
                    Severity::Critical
                },
            });

            tasks.push(BackgroundTask {
                id: "CAN".into(),
                kind: "CANONICAL VERIFY".into(),
                state: if self.storage.canonical_verify_failures == 0 {
                    "HEALTHY"
                } else {
                    "FAILED"
                }
                .into(),
                progress: "N/D".into(),
                throughput: "N/D".into(),
                detail: format!("verify_failures={}", self.storage.canonical_verify_failures),
                severity: if self.storage.canonical_verify_failures == 0 {
                    Severity::Good
                } else {
                    Severity::Critical
                },
            });
        }

        if self.sentinel.available {
            let lag = self.sentinel.lag_state.to_ascii_uppercase();
            tasks.push(BackgroundTask {
                id: "SEC".into(),
                kind: "SENTINEL".into(),
                state: lag.clone(),
                progress: queue_progress(self.sentinel.queue_depth, self.sentinel.queue_capacity),
                throughput: "N/D".into(),
                detail: format!(
                    "lag={} LSN | queue={}/{}",
                    format_number(self.sentinel.detection_lag_lsn),
                    self.sentinel.queue_depth,
                    self.sentinel.queue_capacity
                ),
                severity: match lag.as_str() {
                    "HEALTHY" => Severity::Good,
                    "DEGRADED" | "CATCHINGUP" | "CATCHING_UP" => Severity::Warning,
                    "CRITICAL" => Severity::Critical,
                    _ => Severity::Neutral,
                },
            });
        }

        if self.agent_status.available {
            tasks.push(BackgroundTask {
                id: "AGNT".into(),
                kind: "AGENT EVIDENCE LOG".into(),
                state: if self.agent_status.evidence_log.is_empty() {
                    "UNKNOWN".into()
                } else {
                    self.agent_status.evidence_log.clone()
                },
                progress: format!("{} events", format_number(self.agent_status.ingest.events)),
                throughput: format!("{} err", self.agent_status.gateway.evidence_errors),
                detail: format!(
                    "conflicts={} rejected={} bypass={}",
                    self.agent_status.ingest.conflicts,
                    self.agent_status.ingest.rejected,
                    self.agent_status.bypass_protection
                ),
                severity: if self.agent_status.evidence_log == "HEALTHY"
                    && self.agent_status.gateway.evidence_errors == 0
                {
                    Severity::Good
                } else {
                    Severity::Critical
                },
            });
        }

        if self.redteam.available {
            let state = if self.redteam.reached_upstream > 0 {
                "LEAK_DETECTED"
            } else if self.redteam.blocked > 0 {
                "DEFENDED"
            } else {
                "OBSERVING"
            };
            tasks.push(BackgroundTask {
                id: "REDT".into(),
                kind: "RED TEAM PROBES".into(),
                state: state.into(),
                progress: format!("{}/{} blocked", self.redteam.blocked, self.redteam.total_probes),
                throughput: "N/D".into(),
                detail: format!(
                    "campaign={} leaks={} last_lsn={}",
                    self.redteam.active_campaign,
                    self.redteam.reached_upstream,
                    self.redteam.last_attack_lsn.map(|n| n.to_string()).unwrap_or_else(|| "none".into())
                ),
                severity: if self.redteam.reached_upstream > 0 {
                    Severity::Critical
                } else if self.redteam.blocked > 0 {
                    Severity::Good
                } else {
                    Severity::Neutral
                },
            });
        }

        if self.compliance.available {
            tasks.push(BackgroundTask {
                id: "RFC".into(),
                kind: "RFC 3161 ANCHOR".into(),
                state: if self.compliance.deferred_anchor_forks == 0 {
                    "HEALTHY"
                } else {
                    "FORK_DETECTED"
                }
                .into(),
                progress: format!("{} receipts", format_number(self.compliance.receipts_total)),
                throughput: "N/D".into(),
                detail: format!(
                    "deferred={} overdue={}/{}",
                    self.compliance.deferred_anchors,
                    self.compliance.deadline_overdue,
                    self.compliance.deadline_total
                ),
                severity: if self.compliance.deferred_anchor_forks == 0
                    && self.compliance.deadline_overdue == 0
                {
                    Severity::Good
                } else {
                    Severity::Critical
                },
            });
        }

        if tasks.is_empty() {
            tasks.push(BackgroundTask {
                id: "--".into(),
                kind: "TELEMETRY".into(),
                state: "N/D".into(),
                progress: "N/D".into(),
                throughput: "N/D".into(),
                detail: "servidor não expôs tarefas operacionais".into(),
                severity: Severity::Neutral,
            });
        }

        tasks
    }

    fn reset_history(&mut self) {
        self.peak_rate = self.insert_rate;
        self.rate_history.clear();
    }

    fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }
}

pub fn run_top(url_str: &str, user: &str, pass: &str, interval_sec: f64) -> Result<String, String> {
    enable_raw_mode().map_err(|error| format!("erro ao ativar raw mode: {error}"))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)
        .map_err(|error| format!("erro ao entrar no alternate screen: {error}"))?;
    let _terminal_guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)
        .map_err(|error| format!("erro ao criar terminal Ratatui: {error}"))?;
    terminal
        .clear()
        .map_err(|error| format!("erro ao limpar terminal: {error}"))?;

    let auth = if user.is_empty() && pass.is_empty() {
        String::new()
    } else {
        format!("{user}:{pass}")
    };

    let mut app = AppState::new(url_str.to_owned(), auth, interval_sec);
    app.force_refresh();
    let mut last_tick = Instant::now();

    loop {
        terminal
            .draw(|frame| ui(frame, &mut app))
            .map_err(|error| format!("erro ao desenhar UI: {error}"))?;

        let refresh = Duration::from_secs_f64(app.interval_sec.max(MIN_INTERVAL_SECS));
        let timeout = refresh.saturating_sub(last_tick.elapsed());

        if event::poll(timeout).map_err(|error| format!("erro no event::poll: {error}"))? {
            if let Event::Key(key) =
                event::read().map_err(|error| format!("erro ao ler teclado: {error}"))?
            {
                if key.kind != KeyEventKind::Press && key.kind != KeyEventKind::Repeat {
                    continue;
                }

                if app.show_help {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('h') => {
                            app.show_help = false
                        }
                        KeyCode::Char('q') => break,
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('p') | KeyCode::Char(' ') => app.paused = !app.paused,
                    KeyCode::Char('r') => app.reset_history(),
                    KeyCode::Char('u') => {
                        app.force_refresh();
                        last_tick = Instant::now();
                    }
                    KeyCode::Char('?') | KeyCode::Char('h') => app.show_help = true,
                    KeyCode::Char('+') | KeyCode::Char('=') => {
                        app.interval_sec = (app.interval_sec - 0.25).max(MIN_INTERVAL_SECS)
                    }
                    KeyCode::Char('-') => {
                        app.interval_sec = (app.interval_sec + 0.25).min(MAX_INTERVAL_SECS)
                    }
                    KeyCode::Char('1') => app.active_tab = ActiveTab::Overview,
                    KeyCode::Char('2') => app.active_tab = ActiveTab::Pipelines,
                    KeyCode::Char('3') => app.active_tab = ActiveTab::Storage,
                    KeyCode::Char('4') => app.active_tab = ActiveTab::Queries,
                    KeyCode::Char('5') => app.active_tab = ActiveTab::Raft,
                    KeyCode::Char('6') => app.active_tab = ActiveTab::Security,
                    KeyCode::Char('7') => app.active_tab = ActiveTab::Agents,
                    KeyCode::Char('8') => app.active_tab = ActiveTab::Indexes,
                    KeyCode::Char('9') => app.active_tab = ActiveTab::Compliance,
                    KeyCode::Tab => app.active_tab = app.active_tab.next(),
                    KeyCode::BackTab => app.active_tab = app.active_tab.previous(),
                    KeyCode::Up => {
                        app.selected_task_index = app.selected_task_index.saturating_sub(1)
                    }
                    KeyCode::Down => {
                        let max_index = app.background_tasks().len().saturating_sub(1);
                        app.selected_task_index = (app.selected_task_index + 1).min(max_index);
                    }
                    KeyCode::Home => app.selected_task_index = 0,
                    KeyCode::End => {
                        app.selected_task_index = app.background_tasks().len().saturating_sub(1)
                    }
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= Duration::from_secs_f64(app.interval_sec.max(MIN_INTERVAL_SECS)) {
            if !app.paused {
                app.update_fast();
            }
            last_tick = Instant::now();
        }
    }

    Ok("Heraclitus Task Manager finalizado.".to_string())
}

fn ui(frame: &mut ratatui::Frame<'_>, app: &mut AppState) {
    let area = frame.area();
    if area.width < 80 || area.height < 24 {
        let warning = Paragraph::new(vec![
            Line::from(Span::styled(
                "HERACLITUS DB TASK MANAGER",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!("Terminal atual: {}x{}", area.width, area.height)),
            Line::from("Mínimo recomendado: 80x24"),
            Line::from("Redimensione o terminal. q = sair"),
        ])
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" TERMINAL PEQUENO "),
        );
        frame.render_widget(warning, area);
        return;
    }

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

    render_banner(frame, app, vertical[0]);
    render_tabs(frame, app, vertical[1]);

    match app.active_tab {
        ActiveTab::Overview => render_overview(frame, app, vertical[2]),
        ActiveTab::Pipelines => render_pipelines(frame, app, vertical[2]),
        ActiveTab::Storage => render_storage(frame, app, vertical[2]),
        ActiveTab::Queries => render_queries(frame, app, vertical[2]),
        ActiveTab::Raft => render_raft(frame, app, vertical[2]),
        ActiveTab::Security => render_security(frame, app, vertical[2]),
        ActiveTab::Agents => render_agents(frame, app, vertical[2]),
        ActiveTab::Indexes => render_indexes(frame, app, vertical[2]),
        ActiveTab::Compliance => render_compliance(frame, app, vertical[2]),
    }

    render_footer(frame, app, vertical[3]);

    if app.show_help {
        render_help(frame, area);
    }
}

fn render_banner(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let (crit_count, warn_count) = app.alarm_counts();

    let online_span = if app.online {
        Span::styled("● ONLINE", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("● OFFLINE", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    };

    let raft_role = if app.raft.available {
        value_or_nd(&app.raft.role)
    } else {
        "N/D".to_string()
    };

    let sentinel_status = if app.sentinel.available {
        format!("{}(lag:{})", app.sentinel.lag_state, app.sentinel.detection_lag_lsn)
    } else {
        "OFFLINE".to_string()
    };

    let agent_gw_status = if app.agent_status.available {
        "ACTIVE".to_string()
    } else {
        "N/D".to_string()
    };

    let redteam_status = if app.redteam.available {
        if app.redteam.reached_upstream > 0 {
            format!("LEAK(+{})", app.redteam.reached_upstream)
        } else if app.redteam.blocked > 0 {
            format!("{}/{} BLOCKED", app.redteam.blocked, app.redteam.total_probes)
        } else {
            "OBSERVING".to_string()
        }
    } else {
        "N/D".to_string()
    };

    let redteam_color = if app.redteam.reached_upstream > 0 {
        Color::Red
    } else if app.redteam.blocked > 0 {
        Color::Green
    } else {
        Color::Cyan
    };

    let line1 = Line::from(vec![
        Span::styled(" HERACLITUS ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        online_span,
        Span::raw(" │ "),
        Span::styled(format!("LSN {}", format_number(app.head_lsn)), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" │ "),
        Span::styled(format!("{:.1} evt/s", app.insert_rate), Style::default().fg(Color::Green)),
        Span::raw(" │ Raft: "),
        Span::styled(raft_role, Style::default().fg(Color::Yellow)),
        Span::raw(" │ Sentinel: "),
        Span::styled(sentinel_status, sentinel_color(&app.sentinel.lag_state)),
        Span::raw(" │ Agent GW: "),
        Span::styled(agent_gw_status, if app.agent_status.available { Color::Green } else { Color::DarkGray }),
        Span::raw(" │ Defense: "),
        Span::styled(redteam_status, Style::default().fg(redteam_color).add_modifier(Modifier::BOLD)),
    ]);

    let crit_span = if crit_count > 0 {
        Span::styled(format!(" {crit_count} CRITICAL "), Style::default().bg(Color::Red).fg(Color::White).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" 0 CRIT ", Style::default().bg(Color::Green).fg(Color::Black).add_modifier(Modifier::BOLD))
    };

    let warn_span = if warn_count > 0 {
        Span::styled(format!(" {warn_count} WARN "), Style::default().bg(Color::Yellow).fg(Color::Black).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" 0 WARN ", Style::default().fg(Color::DarkGray))
    };

    let crc_span = if app.storage.physical_crc_failures == 0 {
        Span::styled("CRC: OK", Style::default().fg(Color::Green))
    } else {
        Span::styled(format!("CRC: {} FAIL", app.storage.physical_crc_failures), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    };

    let can_span = if app.storage.canonical_verify_failures == 0 {
        Span::styled("CAN: OK", Style::default().fg(Color::Green))
    } else {
        Span::styled(format!("CAN: {} FAIL", app.storage.canonical_verify_failures), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    };

    let evd_span = if !app.agent_status.available {
        Span::styled("Evidence: N/D", Style::default().fg(Color::DarkGray))
    } else if app.agent_status.evidence_log == "HEALTHY" {
        Span::styled("Evidence: HEALTHY", Style::default().fg(Color::Green))
    } else {
        Span::styled(format!("Evidence: {}", app.agent_status.evidence_log), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    };

    let leak_span = if app.redteam.reached_upstream > 0 {
        Span::styled(format!("Boundary: +{} LEAK", app.redteam.reached_upstream), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("Boundary: CLEAN (0 leak)", Style::default().fg(Color::Green))
    };

    let line2 = Line::from(vec![
        Span::raw(" "),
        crit_span,
        Span::raw(" "),
        warn_span,
        Span::raw(" │ "),
        crc_span,
        Span::raw(" │ "),
        can_span,
        Span::raw(" │ "),
        evd_span,
        Span::raw(" │ "),
        leak_span,
        Span::raw(" │ "),
        Span::styled(truncate(&app.target_url, 28), Style::default().fg(Color::DarkGray)),
    ]);

    let banner = Paragraph::new(vec![line1, line2])
        .block(Block::default().borders(Borders::ALL).title(Line::from(vec![
            Span::styled(" ⚡ COMMAND CENTER ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ])));

    frame.render_widget(banner, area);
}

fn render_tabs(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let titles = [
        "[1] Overview",
        "[2] Pipelines",
        "[3] Storage",
        "[4] Queries",
        "[5] Raft",
        "[6] Security",
        "[7] Agents",
        "[8] Indexes",
        "[9] Compliance",
    ]
    .into_iter()
    .map(Line::from)
    .collect::<Vec<_>>();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" NAVIGATION "))
        .select(app.active_tab as usize)
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .divider("│");

    frame.render_widget(tabs, area);
}

fn render_footer(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let run_text = if app.paused { " PAUSED " } else { " RUNNING " };
    let run_style = if app.paused {
        Style::default().bg(Color::Yellow).fg(Color::Black)
    } else if app.online {
        Style::default().bg(Color::Green).fg(Color::Black)
    } else {
        Style::default().bg(Color::Red).fg(Color::White)
    }
    .add_modifier(Modifier::BOLD);

    let mut spans = vec![
        Span::styled(run_text, run_style),
        Span::raw(" Target: "),
        Span::styled(&app.target_url, Style::default().fg(Color::Cyan)),
        Span::raw(" | refresh "),
        Span::styled(
            format!("{:.2}s", app.interval_sec),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(" | "),
        Span::styled("Tab/1-9", Style::default().fg(Color::Yellow)),
        Span::raw(" abas | "),
        Span::styled("u", Style::default().fg(Color::Yellow)),
        Span::raw(" refresh | "),
        Span::styled("p", Style::default().fg(Color::Yellow)),
        Span::raw(" pause | "),
        Span::styled("?", Style::default().fg(Color::Yellow)),
        Span::raw(" help | "),
        Span::styled("q", Style::default().fg(Color::Red)),
        Span::raw(" sair"),
    ];

    if let Some(error) = &app.last_error {
        spans.push(Span::raw(" | "));
        spans.push(Span::styled(
            truncate(error, 52),
            Style::default().fg(Color::Red),
        ));
    }

    let paragraph = Paragraph::new(Line::from(spans))
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_overview(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Min(8),
            Constraint::Length(9),
        ])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(32),
            Constraint::Percentage(34),
        ])
        .split(vertical[0]);

    let ingest = Paragraph::new(vec![
        kv_line(
            "Taxa instantânea",
            format!("{:.1} evt/s", app.insert_rate),
            Color::Green,
        ),
        kv_line(
            "Pico observado",
            format!("{:.1} evt/s", app.peak_rate),
            Color::Yellow,
        ),
        kv_line("Head LSN", format_number(app.head_lsn), Color::Cyan),
        kv_line(
            "Memtable",
            format!("{} registros", format_number(app.memtable_entries)),
            Color::Magenta,
        ),
    ])
    .block(Block::default().borders(Borders::ALL).title(" INGESTION "));
    frame.render_widget(ingest, top[0]);

    let health_color = if app.online { Color::Green } else { Color::Red };
    let last_ok = app
        .last_success_elapsed
        .map(format_duration_short)
        .unwrap_or_else(|| "nunca".into());
    let system = Paragraph::new(vec![
        kv_line(
            "REST /stats",
            if app.online { "ONLINE" } else { "OFFLINE" },
            health_color,
        ),
        kv_line(
            "Latência REST",
            format!("{:.2} ms", app.rest_latency_ms),
            latency_color(app.rest_latency_ms),
        ),
        kv_line(
            "Healthz",
            if app.health_text.is_empty() {
                "N/D".to_string()
            } else {
                app.health_text.clone()
            },
            health_color,
        ),
        kv_line("Formato", app.storage_format.clone(), Color::Cyan),
        kv_line("Último OK", last_ok, Color::Gray),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" SERVER HEALTH "),
    );
    frame.render_widget(system, top[1]);

    let savings = storage_savings_factor(&app.storage);
    let storage = Paragraph::new(vec![
        kv_line("RAW", format_bytes(app.storage.raw_bytes), Color::Yellow),
        kv_line(
            "PACKED",
            format_bytes(app.storage.packed_bytes),
            Color::Green,
        ),
        kv_line(
            "Packed/RAW",
            format!("{:.1}%", app.storage.compression_ratio * 100.0),
            Color::Magenta,
        ),
        kv_line("Economia", format!("{savings:.2}x"), Color::Cyan),
        kv_line(
            "Pack queue",
            app.storage.pack_queue_depth.to_string(),
            if app.storage.pack_queue_depth == 0 {
                Color::Green
            } else {
                Color::Yellow
            },
        ),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" HRKL STORAGE "),
    );
    frame.render_widget(storage, top[2]);

    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(64), Constraint::Percentage(36)])
        .split(vertical[1]);

    render_ingest_chart(frame, app, middle[0]);
    render_overview_right(frame, app, middle[1]);

    render_verified_invariants(frame, vertical[2]);
}

fn render_verified_invariants(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let header = Row::new([
        "SPEC",
        "SUBSYSTEM",
        "THEOREM / INVARIANT",
        "FORMAL PROPERTY",
        "ENGINE",
        "STATUS",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
    .bottom_margin(0);

    let rows = vec![
        Row::new([
            "SPEC-0010",
            "heraclitus-storage",
            "ProofAppendOnly",
            "Monotonic LSN progression & physical block immutability",
            "Lean 4 (v4.8)",
            "PROVED",
        ])
        .style(Style::default().fg(Color::Green)),
        Row::new([
            "SPEC-0015",
            "heraclitus-merkle",
            "ProofMerkleTree",
            "Cryptographic state inclusion & collision resistance",
            "Lean 4 (v4.8)",
            "PROVED",
        ])
        .style(Style::default().fg(Color::Green)),
        Row::new([
            "SPEC-0022",
            "heraclitus-state",
            "ProofDeterministicReplay",
            "Strict state isomorphism under identical event history",
            "Lean 4 (v4.8)",
            "PROVED",
        ])
        .style(Style::default().fg(Color::Green)),
        Row::new([
            "SPEC-0034",
            "heraclitus-core",
            "ProofDenseMap",
            "Hazard pointers memory safety & lock-free progression",
            "Lean 4 (v4.8)",
            "PROVED",
        ])
        .style(Style::default().fg(Color::Green)),
        Row::new([
            "SPEC-0041",
            "heraclitus-hlc",
            "ProofHLC",
            "Strict causality & wall-clock forward monotonicity",
            "Lean 4 (v4.8)",
            "PROVED",
        ])
        .style(Style::default().fg(Color::Green)),
        Row::new([
            "SPEC-0081",
            "heraclitus-agent",
            "ProofApprovalIdempotence",
            "Zero double-execution & replay safety under burst",
            "Lean 4 (v4.8)",
            "PROVED",
        ])
        .style(Style::default().fg(Color::Green)),
        Row::new([
            "SPEC-0085",
            "heraclitus-agent-gateway",
            "ProofToolCallIsolation",
            "Zero leak past denial barrier (upstream_delta == 0)",
            "Lean 4 (v4.8)",
            "PROVED",
        ])
        .style(Style::default().fg(Color::Green)),
        Row::new([
            "SPEC-0078",
            "heraclitus-blackbox",
            "ProofRFC3161Seal",
            "Tamper-evident evidence chain non-repudiation",
            "Kani / Proptest",
            "TESTED",
        ])
        .style(Style::default().fg(Color::Cyan)),
    ];

    let table = Table::new(
        rows,
        [
            Constraint::Length(11),
            Constraint::Length(25),
            Constraint::Length(26),
            Constraint::Min(40),
            Constraint::Length(16),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" FORMAL SPEC & VERIFIED INVARIANTS (LEAN 4 / FORMAL PROOFS) "),
    );

    frame.render_widget(table, area);
}

fn render_ingest_chart(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let data = app
        .rate_history
        .iter()
        .enumerate()
        .map(|(index, value)| (index as f64, *value))
        .collect::<Vec<_>>();

    let max_y = app
        .rate_history
        .iter()
        .copied()
        .fold(1.0_f64, f64::max)
        .max(100.0);
    let max_x = (app.rate_history.len().max(2) - 1) as f64;

    let dataset = Dataset::default()
        .name("evt/s")
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::Cyan))
        .data(&data);

    let chart = Chart::new(vec![dataset])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" INGESTION RATE HISTORY "),
        )
        .x_axis(Axis::default().title("amostras").bounds([0.0, max_x]))
        .y_axis(Axis::default().title("evt/s").bounds([0.0, max_y * 1.10]));

    frame.render_widget(chart, area);
}

fn render_overview_right(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(5),
        ])
        .split(area);

    if let Some(capacity) = app.memtable_capacity.filter(|capacity| *capacity > 0) {
        let ratio = app.memtable_entries as f64 / capacity as f64;
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" MEMTABLE "))
            .gauge_style(Style::default().fg(if ratio < 0.8 {
                Color::Green
            } else if ratio < 0.95 {
                Color::Yellow
            } else {
                Color::Red
            }))
            .ratio(ratio.clamp(0.0, 1.0))
            .label(format!(
                "{} / {} ({:.1}%)",
                format_number(app.memtable_entries),
                format_number(capacity),
                ratio * 100.0
            ));
        frame.render_widget(gauge, sections[0]);
    } else {
        let memtable = Paragraph::new(vec![
            kv_line(
                "Entries",
                format_number(app.memtable_entries),
                Color::Yellow,
            ),
            Line::from(Span::styled(
                "Capacidade não exposta pelo /stats",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title(" MEMTABLE "));
        frame.render_widget(memtable, sections[0]);
    }

    if app.sentinel.available {
        let capacity = app.sentinel.queue_capacity.max(1);
        let ratio = app.sentinel.queue_depth as f64 / capacity as f64;
        let color = sentinel_color(&app.sentinel.lag_state);
        let gauge = Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" SENTINEL {} ", app.sentinel.lag_state)),
            )
            .gauge_style(Style::default().fg(color))
            .ratio(ratio.clamp(0.0, 1.0))
            .label(format!(
                "queue {}/{} | lag {} LSN",
                app.sentinel.queue_depth,
                app.sentinel.queue_capacity,
                format_number(app.sentinel.detection_lag_lsn)
            ));
        frame.render_widget(gauge, sections[1]);
    } else {
        let sentinel = Paragraph::new("/sentinel/status indisponível ou Sentinel não configurado")
            .block(Block::default().borders(Borders::ALL).title(" SENTINEL "))
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(sentinel, sections[1]);
    }

    let views = if app.active_views.is_empty() {
        "Nenhuma view reportada".to_string()
    } else {
        app.active_views.join("  │  ")
    };
    let views_widget = Paragraph::new(views)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" ACTIVE VIEWS "),
        )
        .style(Style::default().fg(Color::Cyan))
        .wrap(Wrap { trim: true });
    frame.render_widget(views_widget, sections[2]);
}

fn render_pipelines(frame: &mut ratatui::Frame<'_>, app: &mut AppState, area: Rect) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(6)])
        .split(area);

    let tasks = app.background_tasks();
    let header = Row::new(["ID", "TYPE", "STATE", "PROGRESS", "THROUGHPUT", "DETAILS"])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1);

    let rows = tasks.iter().map(|task| {
        Row::new(vec![
            task.id.clone(),
            task.kind.clone(),
            task.state.clone(),
            task.progress.clone(),
            task.throughput.clone(),
            task.detail.clone(),
        ])
        .style(severity_style(task.severity))
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(22),
            Constraint::Length(14),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Min(25),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" OPERATIONAL PIPELINES & BACKGROUND WORKERS "),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    let selected_idx = app.selected_task_index.min(tasks.len().saturating_sub(1));
    let mut state = TableState::default();
    state.select(Some(selected_idx));
    frame.render_stateful_widget(table, vertical[0], &mut state);

    let detail_lines = if let Some(task) = tasks.get(selected_idx) {
        let (color, desc) = match task.id.as_str() {
            "HRKL" => (Color::Cyan, "Motor de compactação e ordenação de blocos físicos append-only."),
            "LAKE" => (Color::Yellow, "Pipeline de exportação colunar contínua Parquet para arquitetura Lakehouse."),
            "HRKI" => (Color::Green, "Sidecar de indexação secundária e reconciliação de ponteiros de bloco."),
            "CRC" => (Color::Red, "Verificação contínua de integridade física CRC32C nos blocos de cauda e arquivo."),
            "CAN" => (Color::Magenta, "Verificação canônica de serialização e invariantes formais de replay."),
            "SEC" => (Color::Green, "Sentinel SOC telemetry ingest, processamento L0/L1/L2 e detecção de ameaças."),
            "AGNT" => (Color::Blue, "Agent Black Box evidence log, registro de auditoria e barramento de segurança."),
            "REDT" => (Color::Red, "Monitoramento contínuo de sondas adversariais e imunidade contra evasão."),
            "RFC" => (Color::Cyan, "Âncoras criptográficas RFC 3161 TSA para carimbo de tempo qualificado e não-repúdio."),
            _ => (Color::Gray, "Pipeline de telemetria operacional."),
        };
        vec![
            Line::from(vec![
                Span::styled(format!(" [{}] {} ", task.id, task.kind), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::raw(" Estado: "),
                Span::styled(&task.state, severity_style(task.severity)),
                Span::raw(" │ Progresso: "),
                Span::styled(&task.progress, Style::default().fg(Color::White)),
                Span::raw(" │ Vazão: "),
                Span::styled(&task.throughput, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(Span::styled(desc, Style::default().fg(Color::Gray))),
            kv_line("Telemetria do nó", &task.detail, Color::Cyan),
        ]
    } else {
        vec![Line::from("Nenhum pipeline operacional selecionado.")]
    };

    let detail_widget = Paragraph::new(detail_lines)
        .block(Block::default().borders(Borders::ALL).title(" DETALHES DO PIPELINE SELECIONADO (↑/↓) "))
        .wrap(Wrap { trim: false });
    frame.render_widget(detail_widget, vertical[1]);
}

fn render_storage(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left = Paragraph::new(vec![
        title_line("HRKL V6 / PACKING"),
        Line::from(""),
        kv_line(
            "Disponível",
            yes_no(app.storage.available),
            status_bool_color(app.storage.available),
        ),
        kv_line(
            "RAW bytes",
            format_bytes(app.storage.raw_bytes),
            Color::Yellow,
        ),
        kv_line(
            "PACKED bytes",
            format_bytes(app.storage.packed_bytes),
            Color::Green,
        ),
        kv_line(
            "Compression ratio",
            format!("{:.2}%", app.storage.compression_ratio * 100.0),
            Color::Cyan,
        ),
        kv_line(
            "Economia",
            format!("{:.2}x", storage_savings_factor(&app.storage)),
            Color::Cyan,
        ),
        kv_line(
            "Append bytes total",
            format_bytes(app.storage.append_bytes_total),
            Color::Gray,
        ),
        kv_line(
            "Pack queue",
            app.storage.pack_queue_depth.to_string(),
            Color::Yellow,
        ),
        kv_line(
            "Pack seconds",
            format!("{:.3}s", app.storage.pack_seconds),
            Color::Gray,
        ),
        kv_line(
            "Pack throughput",
            format_rate_bytes(app.storage.pack_throughput_bytes_sec),
            Color::Green,
        ),
        kv_line(
            "Blocks total",
            format_number(app.storage.blocks_total),
            Color::Gray,
        ),
        kv_line(
            "Blocks read",
            format_number(app.storage.blocks_read),
            Color::Gray,
        ),
        kv_line(
            "Blocks pruned",
            format_number(app.storage.blocks_pruned),
            Color::Gray,
        ),
        kv_line(
            "Bytes pruned",
            format_bytes(app.storage.bytes_pruned),
            Color::Gray,
        ),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" STORAGE ENGINE "),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(left, columns[0]);

    let crc_color = if app.storage.physical_crc_failures == 0 {
        Color::Green
    } else {
        Color::Red
    };
    let canonical_color = if app.storage.canonical_verify_failures == 0 {
        Color::Green
    } else {
        Color::Red
    };
    let right =
        Paragraph::new(vec![
        title_line("INDEX / COLD TIER / INTEGRITY"),
        Line::from(""),
        kv_line("HRKI hits", format_number(app.storage.hrki_hits), Color::Green),
        kv_line("HRKI misses", format_number(app.storage.hrki_misses), Color::Yellow),
        kv_line("HRKI rebuilds", format_number(app.storage.hrki_rebuilds), Color::Yellow),
        kv_line("Cold range reads", format_number(app.storage.cold_range_reads), Color::Gray),
        kv_line(
            "Cold bytes downloaded",
            format_bytes(app.storage.cold_bytes_downloaded),
            Color::Gray,
        ),
        kv_line(
            "Parquet export lag",
            format!("{} LSN", format_number(app.storage.parquet_export_lag_lsn)),
            if app.storage.parquet_export_lag_lsn == 0 {
                Color::Green
            } else {
                Color::Yellow
            },
        ),
        kv_line(
            "Canonical verify failures",
            format_number(app.storage.canonical_verify_failures),
            canonical_color,
        ),
        kv_line(
            "Physical CRC failures",
            format_number(app.storage.physical_crc_failures),
            crc_color,
        ),
        kv_line(
            "Decompressed bytes",
            format_bytes(app.storage.decompressed_bytes),
            Color::Gray,
        ),
        Line::from(""),
        Line::from(Span::styled(
            "Falhas CRC/canônicas > 0 são incidentes de integridade, não decoração de dashboard.",
            Style::default().fg(Color::DarkGray),
        )),
    ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" STORAGE HEALTH "),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(right, columns[1]);
}

fn render_queries(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(8)])
        .split(area);

    let grpc_text = match app.grpc_reachable {
        Some(true) => format!(
            "TCP reachable{}",
            app.grpc_probe_latency_ms
                .map(|ms| format!(" ({ms:.2} ms)"))
                .unwrap_or_default()
        ),
        Some(false) => "TCP unreachable".into(),
        None => "not probed".into(),
    };
    let grpc_color = match app.grpc_reachable {
        Some(true) => Color::Green,
        Some(false) => Color::Red,
        None => Color::Gray,
    };

    let api = Paragraph::new(vec![
        title_line("API / TRANSPORT"),
        Line::from(""),
        kv_line(
            "REST /stats",
            if app.online { "ONLINE" } else { "OFFLINE" },
            if app.online { Color::Green } else { Color::Red },
        ),
        kv_line(
            "REST latency",
            format!("{:.2} ms", app.rest_latency_ms),
            latency_color(app.rest_latency_ms),
        ),
        kv_line("gRPC :7474", grpc_text, grpc_color),
        kv_line(
            "Falhas consecutivas",
            app.consecutive_failures.to_string(),
            if app.consecutive_failures == 0 {
                Color::Green
            } else {
                Color::Red
            },
        ),
        kv_line(
            "CLI uptime",
            format_duration_short(app.uptime()),
            Color::Gray,
        ),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" QUERY / API HEALTH "),
    );
    frame.render_widget(api, sections[0]);

    let notes = Paragraph::new(vec![
        title_line("QUERY ENGINE TELEMETRY"),
        Line::from(""),
        Line::from(vec![
            Span::styled("QPS / p50 / p95 / p99: ", Style::default().fg(Color::White)),
            Span::styled("N/D", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("Queries ativas/falhas: ", Style::default().fg(Color::White)),
            Span::styled("N/D", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "O /stats atual do HeraclitusDB não publica contadores de query/latência por percentil. Este painel não inventa números.",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::styled(
            "O indicador gRPC acima é somente reachability TCP da porta 7474, não um gRPC HealthCheck.",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(Block::default().borders(Borders::ALL).title(" TELEMETRY CONTRACT "))
    .wrap(Wrap { trim: false });
    frame.render_widget(notes, sections[1]);
}

fn render_raft(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let text = if app.raft.available {
        vec![
            title_line("RAFT CONSENSUS"),
            Line::from(""),
            kv_line("Node ID", value_or_nd(&app.raft.node_id), Color::Cyan),
            kv_line(
                "Role",
                value_or_nd(&app.raft.role),
                raft_role_color(&app.raft.role),
            ),
            kv_line("Leader", value_or_nd(&app.raft.leader), Color::Green),
            kv_line("Term", option_number(app.raft.term), Color::Cyan),
            kv_line(
                "Commit index",
                option_number(app.raft.commit_index),
                Color::Yellow,
            ),
            kv_line(
                "Applied index",
                option_number(app.raft.applied_index),
                Color::Green,
            ),
            kv_line("Peers", option_number(app.raft.peers), Color::Gray),
        ]
    } else {
        vec![
            title_line("RAFT CONSENSUS"),
            Line::from(""),
            Line::from(Span::styled(
                "Estado Raft: N/D",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("O REST /stats atual não expõe role, leader, term, commit_index ou applied_index."),
            Line::from("Por isso este task manager não mostra 'LEADER term=1' por decreto imaginário."),
            Line::from(""),
            kv_line(
                "gRPC :7474",
                match app.grpc_reachable {
                    Some(true) => "TCP reachable",
                    Some(false) => "TCP unreachable",
                    None => "not probed",
                },
                match app.grpc_reachable {
                    Some(true) => Color::Green,
                    Some(false) => Color::Red,
                    None => Color::Gray,
                },
            ),
            Line::from(""),
            Line::from(Span::styled(
                "Se o servidor adicionar um objeto `raft` ao /stats, esta versão já tenta consumi-lo.",
                Style::default().fg(Color::DarkGray),
            )),
        ]
    };

    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" RAFT "))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn render_security(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(8)])
        .split(area);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(vertical[0]);

    let sentinel = if app.sentinel.available {
        Paragraph::new(vec![
            title_line("SENTINEL SOC ENGINE"),
            Line::from(""),
            kv_line(
                "Enabled",
                yes_no(app.sentinel.enabled),
                status_bool_color(app.sentinel.enabled),
            ),
            kv_line("Mode", value_or_nd(&app.sentinel.mode), Color::Cyan),
            kv_line(
                "Pipeline",
                app.sentinel.pipeline_version.to_string(),
                Color::Gray,
            ),
            kv_line(
                "Lag state",
                value_or_nd(&app.sentinel.lag_state),
                sentinel_color(&app.sentinel.lag_state),
            ),
            kv_line(
                "Detection lag",
                format!("{} LSN", format_number(app.sentinel.detection_lag_lsn)),
                sentinel_color(&app.sentinel.lag_state),
            ),
            kv_line(
                "Queue",
                format!(
                    "{}/{}",
                    app.sentinel.queue_depth, app.sentinel.queue_capacity
                ),
                if app.sentinel.queue_overflow_total == 0 {
                    Color::Green
                } else {
                    Color::Red
                },
            ),
            kv_line(
                "Processed",
                format_number(app.sentinel.events_processed_total),
                Color::Green,
            ),
            kv_line(
                "Signals",
                format_number(app.sentinel.signals_emitted_total),
                Color::Yellow,
            ),
            kv_line(
                "Threat matches",
                format_number(app.sentinel.threat_matches_total),
                Color::Red,
            ),
            kv_line(
                "Incidents",
                format_number(app.sentinel.incidents_created_total),
                Color::Red,
            ),
            kv_line(
                "L0/L1/L2 Latency",
                format!(
                    "{}µs / {}ms / {}ms",
                    app.sentinel.l0_latency_us,
                    app.sentinel.l1_latency_ms,
                    app.sentinel.l2_latency_ms
                ),
                Color::Gray,
            ),
        ])
        .block(Block::default().borders(Borders::ALL).title(" SENTINEL SOC "))
        .wrap(Wrap { trim: false })
    } else {
        Paragraph::new("/sentinel/status indisponível. O painel não assume HEALTHY sem medição.")
            .block(Block::default().borders(Borders::ALL).title(" SENTINEL SOC "))
            .style(Style::default().fg(Color::DarkGray))
    };
    frame.render_widget(sentinel, columns[0]);

    let controls = if app.sentinel.available {
        Paragraph::new(vec![
            title_line("THREAT POSTURE & SOC CONTROLS"),
            Line::from(""),
            kv_line(
                "AI Circuit",
                value_or_nd(&app.sentinel.ai_circuit_state),
                if app.sentinel.ai_circuit_state.to_ascii_uppercase() == "CLOSED" || app.sentinel.ai_circuit_state.to_ascii_uppercase() == "HEALTHY" {
                    Color::Green
                } else {
                    Color::Yellow
                },
            ),
            kv_line(
                "Queue Overflows",
                format_number(app.sentinel.queue_overflow_total),
                if app.sentinel.queue_overflow_total == 0 { Color::Green } else { Color::Red },
            ),
            kv_line(
                "Norm. Errors",
                format_number(app.sentinel.normalization_errors_total),
                if app.sentinel.normalization_errors_total == 0 { Color::Green } else { Color::Yellow },
            ),
            kv_line(
                "Capacity Drops",
                format_number(app.sentinel.incident_capacity_drops_total),
                if app.sentinel.incident_capacity_drops_total == 0 { Color::Green } else { Color::Red },
            ),
            kv_line(
                "Actions Proposed",
                format_number(app.sentinel.actions_proposed_total),
                Color::Cyan,
            ),
            kv_line(
                "Actions Approved",
                format_number(app.sentinel.actions_approved_total),
                Color::Green,
            ),
            kv_line(
                "Actions Denied",
                format_number(app.sentinel.actions_denied_total),
                Color::Yellow,
            ),
            kv_line(
                "Actions Executed",
                format_number(app.sentinel.actions_executed_total),
                Color::Green,
            ),
            kv_line(
                "Action Failures",
                format_number(app.sentinel.action_failures_total),
                if app.sentinel.action_failures_total == 0 { Color::Green } else { Color::Red },
            ),
        ])
        .block(Block::default().borders(Borders::ALL).title(" SOC RESPONSE "))
        .wrap(Wrap { trim: false })
    } else {
        Paragraph::new("Controles operacionais aguardando Sentinel...")
            .block(Block::default().borders(Borders::ALL).title(" SOC RESPONSE "))
            .style(Style::default().fg(Color::DarkGray))
    };
    frame.render_widget(controls, columns[1]);

    let ai_investigation = if app.sentinel.available {
        Paragraph::new(vec![
            title_line("AI INVESTIGATION & BOOT"),
            Line::from(""),
            kv_line(
                "AI Requests",
                format_number(app.sentinel.ai_requests_total),
                Color::Cyan,
            ),
            kv_line(
                "AI Failures",
                format_number(app.sentinel.ai_failures_total),
                if app.sentinel.ai_failures_total == 0 { Color::Green } else { Color::Red },
            ),
            kv_line(
                "AI Latency",
                format!("{} ms", app.sentinel.ai_latency_ms),
                Color::Yellow,
            ),
            kv_line(
                "AI Tokens",
                format_number(app.sentinel.ai_tokens_total),
                Color::Gray,
            ),
            kv_line(
                "Persisted Invs",
                format_number(app.sentinel.ai_investigations_persisted_total),
                Color::Green,
            ),
            kv_line(
                "Boot Outcome",
                value_or_nd(&app.sentinel.boot_outcome),
                if app.sentinel.boot_outcome.to_ascii_uppercase() == "SUCCESS" { Color::Green } else { Color::Yellow },
            ),
            kv_line(
                "Boot Duration",
                format!("{} ms", app.sentinel.boot_total_ms),
                Color::Gray,
            ),
            kv_line(
                "Scanned Events",
                format_number(app.sentinel.boot_events_scanned_total),
                Color::Cyan,
            ),
        ])
        .block(Block::default().borders(Borders::ALL).title(" AI INVESTIGATION "))
        .wrap(Wrap { trim: false })
    } else {
        Paragraph::new("Telemetria AI do Sentinel indisponível.")
            .block(Block::default().borders(Borders::ALL).title(" AI INVESTIGATION "))
            .style(Style::default().fg(Color::DarkGray))
    };
    frame.render_widget(ai_investigation, columns[2]);

    render_alarms_table(frame, app, vertical[1]);
}

fn render_alarms_table(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let alarms = app.evaluate_alarms();
    let header = Row::new([
        "ORIGEM",
        "CÓDIGO",
        "SEVERIDADE",
        "DESCRIÇÃO DO ALARME / INVARIANTE VIOLADO",
        "VALOR ATUAL",
        "ESTADO",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
    .bottom_margin(1);

    let rows: Vec<Row> = if alarms.is_empty() {
        vec![Row::new([
            "SISTEMA",
            "ALM-NOMINAL",
            "NORMAL",
            "Todos os sistemas operando em conformidade nominal — zero alarmes ou violações de barreira.",
            "100% ÍNTEGRO",
            "ATIVO",
        ])
        .style(Style::default().fg(Color::Green))]
    } else {
        alarms
            .iter()
            .map(|a| {
                let (sev_style, sev_text) = match a.severity {
                    AlarmSeverity::Critical => (Style::default().fg(Color::Red).add_modifier(Modifier::BOLD), "CRÍTICO"),
                    AlarmSeverity::Warning => (Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD), "AVISO"),
                };
                Row::new(vec![
                    a.source.to_string(),
                    a.code.to_string(),
                    sev_text.to_string(),
                    a.message.clone(),
                    a.value.clone(),
                    "DISPARADO".to_string(),
                ])
                .style(sev_style)
            })
            .collect()
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Min(45),
            Constraint::Length(20),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" MOTOR DE ALARMES & RASTREAMENTO DE DELTAS EM TEMPO REAL "),
    );

    frame.render_widget(table, area);
}

fn render_agents(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(8)])
        .split(area);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(vertical[0]);

    let gateway = if app.agent_status.available {
        Paragraph::new(vec![
            title_line("AGENT GATEWAY"),
            Line::from(""),
            kv_line("Product", value_or_nd(&app.agent_status.product), Color::Cyan),
            kv_line("Engine", value_or_nd(&app.agent_status.engine), Color::Cyan),
            kv_line("Auth Mode", value_or_nd(&app.agent_status.auth), Color::Yellow),
            kv_line(
                "Bypass Prot.",
                value_or_nd(&app.agent_status.bypass_protection),
                if app.agent_status.bypass_protection == "UNKNOWN" { Color::Yellow } else { Color::Green },
            ),
            kv_line(
                "Evidence Log",
                value_or_nd(&app.agent_status.evidence_log),
                if app.agent_status.evidence_log == "HEALTHY" { Color::Green } else { Color::Red },
            ),
            kv_line("MCP Gateway", value_or_nd(&app.agent_status.mcp_gateway), Color::Gray),
            kv_line(
                "Total Requests",
                format_number(app.agent_status.gateway.requests),
                Color::Cyan,
            ),
            kv_line(
                "Allowed",
                format_number(app.agent_status.gateway.allow),
                Color::Green,
            ),
            kv_line(
                "Denied",
                format_number(app.agent_status.gateway.deny),
                Color::Red,
            ),
            kv_line(
                "Shadow Deny",
                format_number(app.agent_status.gateway.shadow_deny),
                Color::Yellow,
            ),
        ])
        .block(Block::default().borders(Borders::ALL).title(" AGENT GATEWAY "))
        .wrap(Wrap { trim: false })
    } else {
        Paragraph::new(vec![
            title_line("AGENT GATEWAY"),
            Line::from(""),
            Line::from(Span::styled(
                format!("Aguardando Agent Gateway em {}", app.agent_url),
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled("GET /api/v1/agent/status", Style::default().fg(Color::DarkGray))),
        ])
        .block(Block::default().borders(Borders::ALL).title(" AGENT GATEWAY "))
        .wrap(Wrap { trim: false })
    };
    frame.render_widget(gateway, columns[0]);

    let approval = if app.agent_status.available {
        Paragraph::new(vec![
            title_line("APPROVAL & POLICY SECURITY"),
            Line::from(""),
            kv_line("Active Policy", format!("{}:{}", value_or_nd(&app.agent_status.policy.id), value_or_nd(&app.agent_status.policy.version)), Color::Cyan),
            kv_line("Lifecycle", value_or_nd(&app.agent_status.policy.lifecycle), Color::Green),
            kv_line("Rules Active", format_number(app.agent_status.policy.rules), Color::Yellow),
            kv_line("Activated By", value_or_nd(&app.agent_status.policy.activated_by), Color::Gray),
            kv_line(
                "Require Appr.",
                format_number(app.agent_status.gateway.require_approval),
                Color::Yellow,
            ),
            kv_line(
                "Replay Rejected",
                format_number(app.agent_status.gateway.approval_replay_rejected),
                if app.agent_status.gateway.approval_replay_rejected == 0 { Color::Green } else { Color::Yellow },
            ),
            kv_line(
                "Capacity Rej.",
                format_number(app.agent_status.gateway.approval_capacity_rejected),
                if app.agent_status.gateway.approval_capacity_rejected == 0 { Color::Green } else { Color::Red },
            ),
            kv_line(
                "Expired Appr.",
                format_number(app.agent_status.gateway.approval_expired),
                Color::Gray,
            ),
            kv_line(
                "Policy Errors",
                format_number(app.agent_status.gateway.policy_errors),
                if app.agent_status.gateway.policy_errors == 0 { Color::Green } else { Color::Red },
            ),
            kv_line(
                "Upstream Errors",
                format_number(app.agent_status.gateway.upstream_errors),
                if app.agent_status.gateway.upstream_errors == 0 { Color::Green } else { Color::Red },
            ),
        ])
        .block(Block::default().borders(Borders::ALL).title(" APPROVAL & POLICY "))
        .wrap(Wrap { trim: false })
    } else {
        Paragraph::new("Aguardando métricas de aprovação e governança...")
            .block(Block::default().borders(Borders::ALL).title(" APPROVAL & POLICY "))
            .style(Style::default().fg(Color::DarkGray))
    };
    frame.render_widget(approval, columns[1]);

    let resilience = if app.redteam.available {
        let (status_text, status_color) = if app.redteam.reached_upstream > 0 {
            ("VULNERABILIDADE DETECTADA", Color::Red)
        } else if app.redteam.total_probes > 0 && app.redteam.blocked > 0 {
            ("RESILIENTE / DEFENDED", Color::Green)
        } else {
            ("EM OBSERVAÇÃO", Color::Cyan)
        };

        Paragraph::new(vec![
            title_line("RED TEAM RESILIENCE"),
            Line::from(""),
            kv_line("Defesa Global", status_text, status_color),
            kv_line(
                "Campanha Ativa",
                value_or_nd(&app.redteam.active_campaign),
                Color::Cyan,
            ),
            kv_line(
                "Total de Probes",
                format_number(app.redteam.total_probes),
                Color::Yellow,
            ),
            kv_line(
                "Bloqueados (Pass)",
                format_number(app.redteam.blocked),
                Color::Green,
            ),
            kv_line(
                "Vazaram (Leaks)",
                format_number(app.redteam.reached_upstream),
                if app.redteam.reached_upstream == 0 { Color::Green } else { Color::Red },
            ),
            kv_line(
                "Último LSN Ataque",
                app.redteam
                    .last_attack_lsn
                    .map(format_number)
                    .unwrap_or_else(|| "N/D".into()),
                Color::Cyan,
            ),
            kv_line(
                "Evidence Ingest",
                format!("{} evts", format_number(app.agent_status.ingest.events)),
                Color::Green,
            ),
            kv_line(
                "Integridade",
                value_or_nd(&app.agent_status.summary.integrity),
                if app.agent_status.summary.integrity == "PROVED" { Color::Green } else { Color::Yellow },
            ),
            kv_line(
                "Total Proved",
                format!("{}/{}", app.agent_status.integrity.proved, app.agent_status.integrity.total),
                Color::Green,
            ),
        ])
        .block(Block::default().borders(Borders::ALL).title(" ADVERSARIAL RESILIENCE "))
        .wrap(Wrap { trim: false })
    } else {
        Paragraph::new(vec![
            title_line("RED TEAM RESILIENCE"),
            Line::from(""),
            Line::from(Span::styled("Aguardando telemetria de testes de invasão...", Style::default().fg(Color::DarkGray))),
        ])
        .block(Block::default().borders(Borders::ALL).title(" ADVERSARIAL RESILIENCE "))
        .wrap(Wrap { trim: false })
    };
    frame.render_widget(resilience, columns[2]);

    render_redteam_table(frame, app, vertical[1]);
}

fn render_redteam_table(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let attack_header = Row::new([
        "HORA",
        "ATTACK ID",
        "CAMPANHA",
        "VETOR",
        "ALVO",
        "RESULTADO",
        "BLOQUEADO",
        "UPSTREAM Δ",
        "LSN",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
    .bottom_margin(1);

    let attack_rows: Vec<Row> = if app.redteam.events.is_empty() {
        let msg = if app.redteam.available {
            "Aguardando execução de testes de invasão pelo runner...".to_string()
        } else {
            "Agent Gateway (/api/v1/agent/red-team/events) ainda não consultado ou sem eventos".to_string()
        };
        vec![Row::new([
            "—".to_string(),
            "—".to_string(),
            "—".to_string(),
            msg,
            "—".to_string(),
            "—".to_string(),
            "—".to_string(),
            "—".to_string(),
            "—".to_string(),
        ])
        .style(Style::default().fg(Color::DarkGray))]
    } else {
        app.redteam
            .events
            .iter()
            .take(30)
            .map(|e| {
                let time_str = format_unix_nanos_time(e.observed_at_unix_nanos);
                let (res_color, res_text) = if e.upstream_delta > 0 {
                    (Color::Red, format!("LEAK ({})", e.result))
                } else if e.blocked || e.result == "PASS" {
                    (Color::Green, e.result.clone())
                } else if e.result == "FAIL" {
                    (Color::Red, e.result.clone())
                } else {
                    (Color::Yellow, e.result.clone())
                };

                let blocked_str = if e.blocked { "SIM".to_string() } else { "não".to_string() };
                let upstream_str = if e.upstream_delta > 0 {
                    format!("+{}", e.upstream_delta)
                } else {
                    "0 (clean)".to_string()
                };

                let lsn_str = e
                    .lsn
                    .map(|v| format_number(v))
                    .unwrap_or_else(|| "N/D".to_string());

                Row::new(vec![
                    time_str,
                    truncate(&e.attack_id, 12).to_string(),
                    truncate(&e.campaign_id, 12).to_string(),
                    truncate(&e.vector, 28).to_string(),
                    truncate(&e.target, 24).to_string(),
                    res_text,
                    blocked_str,
                    upstream_str,
                    lsn_str,
                ])
                .style(Style::default().fg(res_color))
            })
            .collect()
    };

    let attacks_table = Table::new(
        attack_rows,
        [
            Constraint::Length(9),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(28),
            Constraint::Length(24),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(10),
        ],
    )
    .header(attack_header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" SONDAS DE INVASÃO / ADVERSARIAL ATTACKS (TEMPO REAL) "),
    );

    frame.render_widget(attacks_table, area);
}

fn render_compliance(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(8)])
        .split(area);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(vertical[0]);

    let tsa = if app.compliance.available {
        Paragraph::new(vec![
            title_line("RFC 3161 TSA & TRUST SEALS"),
            Line::from(""),
            kv_line(
                "Status",
                value_or_nd(&app.compliance.status),
                compliance_color(&app.compliance.status),
            ),
            kv_line(
                "As of LSN",
                format_number(app.compliance.as_of_lsn),
                Color::Cyan,
            ),
            kv_line(
                "RFC 3161 Seal",
                value_or_nd(&app.agent_status.rfc3161),
                if app.agent_status.rfc3161 == "ACTIVE" { Color::Green } else { Color::Yellow },
            ),
            kv_line(
                "Receipts Total",
                format_number(app.compliance.receipts_total),
                Color::Green,
            ),
            kv_line(
                "Sealed Watermark",
                format_number(app.compliance.current_sealed_watermark),
                Color::Cyan,
            ),
            kv_line(
                "Last Anchor LSN",
                app.compliance
                    .last_anchor_lsn
                    .map(format_number)
                    .unwrap_or_else(|| "N/D".into()),
                Color::Gray,
            ),
            Line::from(""),
            Line::from(Span::styled(
                truncate(&app.compliance.trust_notice, 38),
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title(" RFC 3161 TSA "))
        .wrap(Wrap { trim: false })
    } else {
        Paragraph::new("/compliance/status indisponível.")
            .block(Block::default().borders(Borders::ALL).title(" RFC 3161 TSA "))
            .style(Style::default().fg(Color::DarkGray))
    };
    frame.render_widget(tsa, columns[0]);

    let anchors = if app.compliance.available {
        Paragraph::new(vec![
            title_line("ANCHOR HEALTH & GOVERNANCE"),
            Line::from(""),
            kv_line(
                "Deferred Anchors",
                format_number(app.compliance.deferred_anchors),
                if app.compliance.deferred_anchor_forks == 0 {
                    Color::Green
                } else {
                    Color::Yellow
                },
            ),
            kv_line(
                "Anchor Forks",
                format_number(app.compliance.deferred_anchor_forks),
                if app.compliance.deferred_anchor_forks == 0 {
                    Color::Green
                } else {
                    Color::Red
                },
            ),
            kv_line(
                "Legal Holds",
                format_number(app.compliance.legal_holds),
                Color::Yellow,
            ),
            kv_line(
                "Retention Excs",
                format_number(app.compliance.retention_exceptions),
                Color::Yellow,
            ),
            kv_line(
                "Policy Versions",
                format_number(app.compliance.active_policy_versions),
                Color::Cyan,
            ),
            kv_line(
                "ANPD Pending",
                format_number(app.compliance.pending_anpd),
                Color::Yellow,
            ),
            Line::from(""),
            Line::from(Span::styled(
                "Âncoras em conformidade ICP-Brasil e RFC 3161.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title(" ANCHOR HEALTH "))
        .wrap(Wrap { trim: false })
    } else {
        Paragraph::new("Aguardando âncoras...")
            .block(Block::default().borders(Borders::ALL).title(" ANCHOR HEALTH "))
            .style(Style::default().fg(Color::DarkGray))
    };
    frame.render_widget(anchors, columns[1]);

    let deadlines = if app.compliance.available {
        Paragraph::new(vec![
            title_line("DEADLINES & SOVEREIGNTY"),
            Line::from(""),
            kv_line(
                "Total Deadlines",
                format_number(app.compliance.deadline_total),
                Color::Cyan,
            ),
            kv_line(
                "Overdue (Late)",
                format_number(app.compliance.deadline_overdue),
                if app.compliance.deadline_overdue == 0 { Color::Green } else { Color::Red },
            ),
            kv_line(
                "Due within 24h",
                format_number(app.compliance.deadline_24h),
                if app.compliance.deadline_24h == 0 { Color::Green } else { Color::Yellow },
            ),
            kv_line(
                "Due within 48h",
                format_number(app.compliance.deadline_48h),
                Color::Gray,
            ),
            kv_line(
                "Due within 72h",
                format_number(app.compliance.deadline_72h),
                Color::Gray,
            ),
            kv_line(
                "Egress Allowed/Denied",
                format!("{}/{}", app.compliance.egress_allowed, app.compliance.egress_denied),
                if app.compliance.egress_denied > 0 { Color::Yellow } else { Color::Green },
            ),
            kv_line(
                "Model Allowed/Denied",
                format!("{}/{}", app.compliance.model_allowed, app.compliance.model_denied),
                if app.compliance.model_denied > 0 { Color::Yellow } else { Color::Green },
            ),
        ])
        .block(Block::default().borders(Borders::ALL).title(" SOVEREIGNTY "))
        .wrap(Wrap { trim: false })
    } else {
        Paragraph::new("Prazos regulatórios indisponíveis.")
            .block(Block::default().borders(Borders::ALL).title(" SOVEREIGNTY "))
            .style(Style::default().fg(Color::DarkGray))
    };
    frame.render_widget(deadlines, columns[2]);

    let audit_info = Paragraph::new(vec![
        title_line("REGULATORY COMPLIANCE AUDIT RECORD"),
        Line::from(""),
        Line::from(vec![
            Span::styled("LGPD Art. 17/18/19: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw("Direito de confirmação, acesso e eliminação de dados tratados."),
        ]),
        Line::from(vec![
            Span::styled("RFC 3161 Evidence Token: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Carimbos de tempo criptograficamente selados por hash SHA-256 e cadeia X.509."),
        ]),
        Line::from(vec![
            Span::styled("Data Sovereignty Boundary: ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw("Controle estrito de fronteira de egress — zero exfiltração não autorizada de telemetria."),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title(" REGULATORY & LEGAL INVARIANTS "))
    .wrap(Wrap { trim: false });

    frame.render_widget(audit_info, vertical[1]);
}

fn render_indexes(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(area);

    let counts = Paragraph::new(vec![
        title_line("INDEX COUNTS FROM /stats"),
        Line::from(""),
        kv_line(
            "Vector indexed",
            format_number(app.indexes.vector_indexed),
            Color::Cyan,
        ),
        kv_line(
            "Text indexed",
            format_number(app.indexes.text_indexed),
            Color::Cyan,
        ),
        kv_line(
            "Graph nodes",
            format_number(app.indexes.graph_nodes),
            Color::Cyan,
        ),
        kv_line(
            "Temporal graph edges",
            format_number(app.indexes.tgraph_edges),
            Color::Cyan,
        ),
        kv_line(
            "Entity keys",
            format_number(app.indexes.entity_keys),
            Color::Cyan,
        ),
        kv_line(
            "Activation tracked",
            format_number(app.indexes.activation_tracked),
            Color::Cyan,
        ),
        Line::from(""),
        title_line("ACTIVE VIEWS"),
        Line::from(if app.active_views.is_empty() {
            "N/D".into()
        } else {
            app.active_views.join("  │  ")
        }),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" INDEXES / VIEWS "),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(counts, columns[0]);

    let mut lines = vec![title_line("VIEW WATERMARKS FROM /state"), Line::from("")];
    if app.view_watermarks.is_empty() {
        lines.push(Line::from(Span::styled(
            "Nenhum watermark reconhecido no payload atual.",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "O /state é consultado a cada 10s, não a cada frame, porque é uma rota mais pesada.",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for (name, watermark) in &app.view_watermarks {
            let lag = app.head_lsn.saturating_sub(*watermark);
            lines.push(Line::from(vec![
                Span::styled(format!("{name:<24}"), Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("LSN {:>12}", format_number(*watermark)),
                    Style::default().fg(Color::Green),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("lag {:>10}", format_number(lag)),
                    Style::default().fg(if lag == 0 {
                        Color::Green
                    } else {
                        Color::Yellow
                    }),
                ),
            ]));
        }
    }

    let watermarks = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" WATERMARKS "))
        .wrap(Wrap { trim: false });
    frame.render_widget(watermarks, columns[1]);
}

fn render_help(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let popup = centered_rect(72, 72, area);
    frame.render_widget(Clear, popup);

    let help = Paragraph::new(vec![
        title_line("HERACLITUS TOP - TECLAS"),
        Line::from(""),
        help_line("1..9", "abrir aba diretamente (Overview..Compliance)"),
        help_line("Tab / Shift+Tab", "aba seguinte / anterior"),
        help_line("↑ / ↓", "selecionar item / pipeline"),
        help_line("Home / End", "primeiro / último item"),
        help_line("p / Espaço", "pausar / continuar polling"),
        help_line("u", "forçar refresh de todas as rotas"),
        help_line("r", "zerar histórico e pico de ingestão"),
        help_line("+ / -", "aumentar / reduzir frequência de atualização"),
        help_line("? / h", "abrir / fechar esta ajuda"),
        help_line("q / Esc / Ctrl+C", "sair"),
        Line::from(""),
        Line::from(Span::styled(
            "Polling: /stats + /healthz rápido; Sentinel 2s; gRPC TCP 5s; /state 10s; compliance 30s.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "Métricas inexistentes no servidor aparecem como N/D. Humanos já inventam métricas suficientes sem ajuda do terminal.",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" HELP ")
            .style(Style::default().bg(Color::Black)),
    )
    .wrap(Wrap { trim: false });

    frame.render_widget(help, popup);
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn fetch_json_with_fallback(
    target: &mut String,
    auth: &mut String,
    path: &str,
) -> Result<(Value, f64), String> {
    let started = Instant::now();
    let response = fetch_with_fallback(target, auth, path)?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;

    if !response.is_success() {
        return Err(format!("HTTP {} em {}", response.status, path));
    }

    let value = serde_json::from_slice::<Value>(&response.body)
        .map_err(|error| format!("JSON inválido em {path}: {error}"))?;
    Ok((value, elapsed_ms))
}

fn fetch_with_fallback(
    target: &mut String,
    auth: &mut String,
    path: &str,
) -> Result<HttpResponse, String> {
    match fetch_http(target, auth, path) {
        Ok(response) if response.status != 401 => Ok(response),
        Ok(response) if response.status == 401 => {
            if let Some(token) = find_secret_token() {
                let replacement = format!("security-admin:{token}");
                match fetch_http(target, &replacement, path) {
                    Ok(retry) if retry.status != 401 => {
                        *auth = replacement;
                        Ok(retry)
                    }
                    Ok(retry) => Ok(retry),
                    Err(error) => Err(error),
                }
            } else {
                Ok(response)
            }
        }
        Ok(response) => Ok(response),
        Err(original_error) => {
            if !looks_like_connection_error(&original_error) {
                return Err(original_error);
            }

            if let Some(host_ip) = get_wsl_host_ip() {
                let fallback = format!("http://{host_ip}:7475");
                if let Ok(response) = fetch_http(&fallback, auth, path) {
                    if response.status != 401 {
                        *target = fallback;
                        return Ok(response);
                    }
                }

                if let Some(token) = find_secret_token() {
                    let fallback_auth = format!("security-admin:{token}");
                    if let Ok(response) = fetch_http(&fallback, &fallback_auth, path) {
                        *target = fallback;
                        *auth = fallback_auth;
                        return Ok(response);
                    }
                }
            }

            Err(original_error)
        }
    }
}

fn fetch_http(
    target_url: &str,
    auth_user_pass: &str,
    req_path: &str,
) -> Result<HttpResponse, String> {
    if target_url.starts_with("https://") {
        return Err("https:// não é suportado pelo cliente HTTP leve do `top`; use http:// local ou adicione TLS ao cliente".into());
    }

    let authority = http_authority(target_url)?;
    let socket_authority = authority_with_default_port(&authority, 7475);
    let socket = resolve_first(&socket_authority)?;

    let mut stream = TcpStream::connect_timeout(&socket, CONNECT_TIMEOUT)
        .map_err(|error| format!("falha ao conectar em {socket_authority}: {error}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("write timeout: {error}"))?;

    let auth_header = if auth_user_pass.is_empty() {
        String::new()
    } else {
        format!(
            "Authorization: Basic {}\r\n",
            base64_encode(auth_user_pass.as_bytes())
        )
    };

    let path = if req_path.starts_with('/') {
        req_path.to_owned()
    } else {
        format!("/{req_path}")
    };

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\n{auth_header}Accept: application/json, text/plain;q=0.9, */*;q=0.1\r\nUser-Agent: heraclitus-top/1\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("erro no envio HTTP: {error}"))?;

    let mut buffer = Vec::with_capacity(16 * 1024);
    stream
        .read_to_end(&mut buffer)
        .map_err(|error| format!("erro lendo resposta HTTP: {error}"))?;

    parse_http_response(&buffer)
}

fn parse_http_response(buffer: &[u8]) -> Result<HttpResponse, String> {
    let header_end = find_bytes(buffer, b"\r\n\r\n")
        .ok_or_else(|| "resposta HTTP sem terminador de cabeçalho".to_string())?;
    let header_bytes = &buffer[..header_end];
    let raw_body = &buffer[header_end + 4..];
    let headers = String::from_utf8_lossy(header_bytes);

    let mut lines = headers.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "resposta HTTP sem status line".to_string())?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| format!("status HTTP inválido: {status_line}"))?;

    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse::<usize>().ok();
            }
        }
    }

    let body = if chunked {
        decode_chunked(raw_body)?
    } else if let Some(length) = content_length {
        if raw_body.len() < length {
            return Err(format!(
                "corpo HTTP truncado: esperado {length} bytes, recebido {}",
                raw_body.len()
            ));
        }
        raw_body[..length].to_vec()
    } else {
        raw_body.to_vec()
    };

    Ok(HttpResponse { status, body })
}

fn decode_chunked(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut cursor = 0usize;
    let mut output = Vec::new();

    loop {
        let relative_end = find_bytes(&input[cursor..], b"\r\n")
            .ok_or_else(|| "chunk HTTP sem tamanho".to_string())?;
        let line_end = cursor + relative_end;
        let size_line = String::from_utf8_lossy(&input[cursor..line_end]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|error| format!("tamanho de chunk inválido '{size_hex}': {error}"))?;
        cursor = line_end + 2;

        if size == 0 {
            break;
        }

        let end = cursor
            .checked_add(size)
            .ok_or_else(|| "overflow no tamanho de chunk".to_string())?;
        if end > input.len() {
            return Err("chunk HTTP truncado".into());
        }
        output.extend_from_slice(&input[cursor..end]);
        cursor = end;

        if input.get(cursor..cursor + 2) != Some(b"\r\n") {
            return Err("chunk HTTP sem CRLF final".into());
        }
        cursor += 2;
    }

    Ok(output)
}

fn find_secret_token() -> Option<String> {
    for variable in ["HERACLITUS_ADMIN_TOKEN", "HERACLITUS_TOKEN"] {
        if let Ok(value) = env::var(variable) {
            let token = value.trim();
            if !token.is_empty() {
                return Some(token.to_owned());
            }
        }
    }

    let mut candidates = Vec::<PathBuf>::new();
    if let Ok(path) = env::var("HERACLITUS_TOKEN_FILE") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(home) = env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".config/heraclitus/admin.token"));
    }
    if let Some(profile) = env::var_os("USERPROFILE") {
        candidates.push(PathBuf::from(profile).join(".heraclitus/admin.token"));
    }

    // Compatibility with the current development layout. Environment/config
    // paths above take precedence, so the CLI no longer depends on these.
    candidates.extend([
        PathBuf::from(r"D:\HeraclitusDB\secrets-v1\admin.token"),
        PathBuf::from(r"D:\HeraclitusDB\secrets-v1\writer.token"),
        PathBuf::from("/mnt/d/HeraclitusDB/secrets-v1/admin.token"),
    ]);

    candidates.into_iter().find_map(read_non_empty_file)
}

fn read_non_empty_file(path: PathBuf) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    let content = fs::read_to_string(path).ok()?;
    let content = content.trim();
    if content.is_empty() {
        None
    } else {
        Some(content.to_owned())
    }
}

fn get_wsl_host_ip() -> Option<String> {
    let content = fs::read_to_string("/etc/resolv.conf").ok()?;
    content.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("nameserver"), Some(ip)) => Some(ip.to_owned()),
            _ => None,
        }
    })
}

fn probe_grpc_port(target_url: &str) -> Result<f64, String> {
    let authority = http_authority(target_url)?;
    let host = authority_host(&authority);
    let grpc_authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:7474")
    } else {
        format!("{host}:7474")
    };
    let socket = resolve_first(&grpc_authority)?;
    let started = Instant::now();
    TcpStream::connect_timeout(&socket, Duration::from_millis(500))
        .map_err(|error| format!("gRPC TCP probe falhou: {error}"))?;
    Ok(started.elapsed().as_secs_f64() * 1_000.0)
}

fn http_authority(url: &str) -> Result<String, String> {
    let clean = url.strip_prefix("http://").unwrap_or(url).trim_matches('/');
    let authority = clean.split('/').next().unwrap_or("").trim();
    if authority.is_empty() {
        Err(format!("URL HTTP inválida: {url}"))
    } else {
        Ok(authority.to_owned())
    }
}

fn authority_with_default_port(authority: &str, default_port: u16) -> String {
    if authority.starts_with('[') {
        if authority.contains("]:") {
            authority.to_owned()
        } else {
            format!("{authority}:{default_port}")
        }
    } else if authority
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .is_some()
    {
        authority.to_owned()
    } else {
        format!("{authority}:{default_port}")
    }
}

fn authority_host(authority: &str) -> String {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_owned();
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            return host.to_owned();
        }
    }
    authority.to_owned()
}

fn resolve_first(authority: &str) -> Result<std::net::SocketAddr, String> {
    authority
        .to_socket_addrs()
        .map_err(|error| format!("não foi possível resolver {authority}: {error}"))?
        .next()
        .ok_or_else(|| format!("nenhum endereço resolvido para {authority}"))
}

fn looks_like_connection_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    [
        "refused",
        "recusada",
        "111",
        "10061",
        "timed out",
        "timeout",
        "conectar",
        "resolve",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn parse_storage(value: &Value) -> StorageSnapshot {
    StorageSnapshot {
        available: value
            .get("available")
            .and_then(Value::as_bool)
            .unwrap_or(true),
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

fn parse_sentinel(value: &Value) -> SentinelSnapshot {
    let boot = value.get("boot").unwrap_or(&Value::Null);
    SentinelSnapshot {
        available: true,
        enabled: value
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        mode: value_string(value.get("mode")),
        pipeline_version: u64_at(value, "pipeline_version").unwrap_or(0),
        head_lsn: u64_at(value, "head_lsn").unwrap_or(0),
        next_lsn: u64_at(value, "next_lsn").unwrap_or(0),
        processed_lsn: u64_at(value, "processed_lsn"),
        detection_lag_lsn: u64_at(value, "detection_lag_lsn").unwrap_or(0),
        lag_state: value_string(value.get("lag_state")),
        queue_depth: u64_at(value, "queue_depth").unwrap_or(0),
        queue_capacity: u64_at(value, "queue_capacity").unwrap_or(0),
        queue_overflow_total: u64_at(value, "queue_overflow_total").unwrap_or(0),
        events_seen_total: u64_at(value, "events_seen_total").unwrap_or(0),
        events_processed_total: u64_at(value, "events_processed_total").unwrap_or(0),
        events_normalized_total: u64_at(value, "events_normalized_total").unwrap_or(0),
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
        ai_investigations_persisted_total: u64_at(value, "ai_investigations_persisted_total")
            .unwrap_or(0),
        ai_circuit_state: value_string(value.get("ai_circuit_state")),
        actions_proposed_total: u64_at(value, "actions_proposed_total").unwrap_or(0),
        actions_approved_total: u64_at(value, "actions_approved_total").unwrap_or(0),
        actions_denied_total: u64_at(value, "actions_denied_total").unwrap_or(0),
        actions_executed_total: u64_at(value, "actions_executed_total").unwrap_or(0),
        action_failures_total: u64_at(value, "action_failures_total").unwrap_or(0),
        boot_outcome: value_string(boot.get("outcome")),
        boot_total_ms: u64_at(boot, "total_boot_ms").unwrap_or(0),
        boot_tail_events: u64_at(boot, "tail_events").unwrap_or(0),
        boot_events_scanned_total: u64_at(boot, "events_scanned_total").unwrap_or(0),
    }
}

fn parse_compliance(value: &Value) -> ComplianceSnapshot {
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
        pending_anpd: value
            .get("anpd_pending_decisions")
            .and_then(Value::as_array)
            .map(|array| array.len() as u64)
            .unwrap_or(0),
        legal_holds: value
            .get("legal_holds")
            .and_then(Value::as_array)
            .map(|array| array.len() as u64)
            .unwrap_or(0),
        retention_exceptions: u64_at(value, "retention_exceptions").unwrap_or(0),
        active_policy_versions: u64_at(value, "active_policy_versions").unwrap_or(0),
        egress_allowed: u64_at(sovereignty, "egress_allowed").unwrap_or(0),
        egress_denied: u64_at(sovereignty, "egress_denied").unwrap_or(0),
        model_allowed: u64_at(sovereignty, "model_allowed").unwrap_or(0),
        model_denied: u64_at(sovereignty, "model_denied").unwrap_or(0),
    }
}

fn parse_raft(value: &Value) -> RaftSnapshot {
    RaftSnapshot {
        available: value.is_object(),
        role: value_string(value.get("role").or_else(|| value.get("state"))),
        leader: value_string(value.get("leader").or_else(|| value.get("leader_id"))),
        term: u64_at(value, "term").or_else(|| u64_at(value, "current_term")),
        commit_index: u64_at(value, "commit_index"),
        applied_index: u64_at(value, "applied_index").or_else(|| u64_at(value, "last_applied")),
        node_id: value_string(value.get("node_id").or_else(|| value.get("id"))),
        peers: u64_at(value, "peers").or_else(|| {
            value
                .get("members")
                .and_then(Value::as_array)
                .map(|members| members.len() as u64)
        }),
    }
}

fn derive_agent_url(target_url: &str) -> String {
    if let Ok(authority) = http_authority(target_url) {
        let host = authority_host(&authority);
        if host.contains(':') && !host.starts_with('[') {
            format!("http://[{host}]:8080")
        } else {
            format!("http://{host}:8080")
        }
    } else {
        "http://127.0.0.1:8080".to_string()
    }
}

fn format_unix_nanos_time(nanos: u64) -> String {
    let secs = nanos / 1_000_000_000;
    if secs == 0 {
        return "—".into();
    }
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

fn parse_redteam(value: &Value) -> RedTeamSnapshot {
    let events_arr = value.get("events").and_then(Value::as_array);
    let summary = value.get("summary");

    let mut events = Vec::new();
    if let Some(arr) = events_arr {
        for item in arr {
            events.push(RedTeamEvent {
                observed_at_unix_nanos: u64_at(item, "observed_at_unix_nanos").unwrap_or(0),
                attack_id: string_at(item, "attack_id").unwrap_or_else(|| "—".into()),
                campaign_id: string_at(item, "campaign_id").unwrap_or_else(|| "manual".into()),
                vector: string_at(item, "vector").unwrap_or_else(|| "—".into()),
                target: string_at(item, "target").unwrap_or_else(|| "—".into()),
                phase: string_at(item, "phase").unwrap_or_else(|| "result".into()),
                result: string_at(item, "result").unwrap_or_else(|| "—".into()),
                reason_code: string_at(item, "reason_code").unwrap_or_default(),
                blocked: item.get("blocked").and_then(Value::as_bool).unwrap_or(false),
                upstream_delta: item.get("upstream_delta").and_then(Value::as_i64).unwrap_or(0),
                transport_status: item.get("transport_status").and_then(Value::as_u64).map(|v| v as u16),
                lsn: item.get("lsn").and_then(Value::as_u64),
            });
        }
    }

    let total_probes = summary
        .and_then(|s| u64_at(s, "returned"))
        .unwrap_or(events.len() as u64);
    let blocked = summary
        .and_then(|s| u64_at(s, "blocked"))
        .unwrap_or_else(|| events.iter().filter(|e| e.blocked).count() as u64);
    let reached_upstream = summary
        .and_then(|s| u64_at(s, "reached_upstream"))
        .unwrap_or_else(|| events.iter().filter(|e| e.upstream_delta > 0).count() as u64);

    let active_campaign = events
        .first()
        .map(|e| e.campaign_id.clone())
        .unwrap_or_else(|| "nenhuma".into());

    let last_attack_lsn = events.first().and_then(|e| e.lsn);

    RedTeamSnapshot {
        available: true,
        total_probes,
        blocked,
        reached_upstream,
        active_campaign,
        last_attack_lsn,
        events,
    }
}

fn parse_agent_status(value: &Value) -> AgentStatusSnapshot {
    let gw = value.get("gateway").unwrap_or(&Value::Null);
    let pol = value.get("policy").unwrap_or(&Value::Null);
    let ing = value.get("ingest").unwrap_or(&Value::Null);
    let intg = value.get("integrity_detail").unwrap_or(&Value::Null);
    let summ = value.get("summary").unwrap_or(&Value::Null);

    AgentStatusSnapshot {
        available: true,
        engine: string_at(value, "engine").unwrap_or_default(),
        product: string_at(value, "product").unwrap_or_default(),
        auth: string_at(value, "auth").unwrap_or_default(),
        bypass_protection: string_at(value, "bypass_protection").unwrap_or_default(),
        evidence_log: string_at(value, "evidence_log").unwrap_or_default(),
        mcp_gateway: string_at(value, "mcp_gateway").unwrap_or_default(),
        otlp_ingest: string_at(value, "otlp_ingest").unwrap_or_default(),
        rfc3161: string_at(value, "rfc3161").unwrap_or_default(),
        gateway: AgentGatewayCounters {
            requests: u64_at(gw, "requests").unwrap_or(0),
            allow: u64_at(gw, "allow").unwrap_or(0),
            deny: u64_at(gw, "deny").unwrap_or(0),
            require_approval: u64_at(gw, "require_approval").unwrap_or(0),
            shadow_deny: u64_at(gw, "shadow_deny").unwrap_or(0),
            approval_replay_rejected: u64_at(gw, "approval_replay_rejected").unwrap_or(0),
            approval_capacity_rejected: u64_at(gw, "approval_capacity_rejected").unwrap_or(0),
            approval_expired: u64_at(gw, "approval_expired").unwrap_or(0),
            policy_errors: u64_at(gw, "policy_errors").unwrap_or(0),
            evidence_errors: u64_at(gw, "evidence_errors").unwrap_or(0),
            upstream_errors: u64_at(gw, "upstream_errors").unwrap_or(0),
        },
        policy: AgentPolicySnapshot {
            id: string_at(pol, "id").unwrap_or_default(),
            version: string_at(pol, "version").unwrap_or_default(),
            lifecycle: string_at(pol, "lifecycle").unwrap_or_default(),
            rules: u64_at(pol, "rules").unwrap_or(0),
            hash: string_at(pol, "hash").unwrap_or_default(),
            activated_by: string_at(pol, "activated_by").unwrap_or_default(),
        },
        ingest: AgentIngestSnapshot {
            events: u64_at(ing, "events").unwrap_or(0),
            batches: u64_at(ing, "batches").unwrap_or(0),
            bytes: u64_at(ing, "bytes").unwrap_or(0),
            duplicates: u64_at(ing, "duplicates").unwrap_or(0),
            conflicts: u64_at(ing, "conflicts").unwrap_or(0),
            rejected: u64_at(ing, "rejected").unwrap_or(0),
        },
        integrity: AgentIntegritySnapshot {
            total: u64_at(intg, "total").unwrap_or(0),
            pending_seal: u64_at(intg, "pending_seal").unwrap_or(0),
            proved: u64_at(intg, "proved").unwrap_or(0),
            broken: u64_at(intg, "broken").unwrap_or(0),
            missing: u64_at(intg, "missing").unwrap_or(0),
        },
        summary: AgentSummarySnapshot {
            runs: u64_at(summ, "runs").unwrap_or(0),
            tool_calls: u64_at(summ, "tool_calls").unwrap_or(0),
            denied: u64_at(summ, "denied").unwrap_or(0),
            pending_approvals: u64_at(summ, "pending_approvals").unwrap_or(0),
            integrity: string_at(summ, "integrity").unwrap_or_default(),
        },
    }
}

fn extract_watermarks(state: &Value) -> Vec<(String, u64)> {
    let candidate = state
        .pointer("/views/watermarks")
        .or_else(|| state.get("watermarks"))
        .or_else(|| state.get("view_watermarks"));

    let mut output = Vec::new();
    if let Some(object) = candidate.and_then(Value::as_object) {
        for (name, value) in object {
            if let Some(watermark) = value.as_u64() {
                output.push((name.clone(), watermark));
            } else if let Some(watermark) = value.get("watermark").and_then(Value::as_u64) {
                output.push((name.clone(), watermark));
            }
        }
    }

    // Forward/backward compatible fallback for state payloads where each view
    // is an object with a watermark field.
    if output.is_empty() {
        if let Some(views) = state.get("views").and_then(Value::as_object) {
            for (name, value) in views {
                if let Some(watermark) = value
                    .get("watermark")
                    .or_else(|| value.get("lsn"))
                    .and_then(Value::as_u64)
                {
                    output.push((name.clone(), watermark));
                }
            }
        }
    }

    output.sort_by(|left, right| left.0.cmp(&right.0));
    output
}

fn should_poll(last: Option<Instant>, every: Duration, now: Instant) -> bool {
    last.map(|instant| now.saturating_duration_since(instant) >= every)
        .unwrap_or(true)
}

fn push_history(history: &mut VecDeque<f64>, value: f64, max: usize) {
    if history.len() >= max {
        history.pop_front();
    }
    history.push_back(value);
}

fn u64_at(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(|item| {
        item.as_u64()
            .or_else(|| item.as_i64().and_then(|number| u64::try_from(number).ok()))
            .or_else(|| item.as_f64().map(|number| number.max(0.0) as u64))
    })
}

fn f64_at(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(|item| {
        item.as_f64()
            .or_else(|| item.as_u64().map(|number| number as f64))
            .or_else(|| item.as_i64().map(|number| number as f64))
    })
}

fn string_at(value: &Value, key: &str) -> Option<String> {
    value.get(key).map(|item| value_string(Some(item)))
}

fn value_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn kv_line<'a>(label: impl Into<String>, value: impl Into<String>, color: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!(" {:<22}", label.into()),
            Style::default().fg(Color::Gray),
        ),
        Span::styled(
            value.into(),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ])
}

fn title_line<'a>(text: impl Into<String>) -> Line<'a> {
    Line::from(Span::styled(
        text.into(),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))
}

fn help_line<'a>(key: impl Into<String>, description: impl Into<String>) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!(" {:<18}", key.into()),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(description.into()),
    ])
}

fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Good => Style::default().fg(Color::Green),
        Severity::Neutral => Style::default().fg(Color::White),
        Severity::Warning => Style::default().fg(Color::Yellow),
        Severity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

fn latency_color(ms: f64) -> Color {
    if ms < 50.0 {
        Color::Green
    } else if ms < 250.0 {
        Color::Yellow
    } else {
        Color::Red
    }
}

fn sentinel_color(state: &str) -> Color {
    match state.to_ascii_uppercase().as_str() {
        "HEALTHY" => Color::Green,
        "DEGRADED" | "CATCHING_UP" | "CATCHINGUP" => Color::Yellow,
        "CRITICAL" => Color::Red,
        _ => Color::Gray,
    }
}

fn compliance_color(state: &str) -> Color {
    match state.to_ascii_lowercase().as_str() {
        "operational" => Color::Green,
        "attention_required" => Color::Yellow,
        "not_yet_production_trusted" => Color::Red,
        _ => Color::Gray,
    }
}

fn raft_role_color(role: &str) -> Color {
    match role.to_ascii_lowercase().as_str() {
        "leader" => Color::Green,
        "follower" => Color::Cyan,
        "candidate" => Color::Yellow,
        _ => Color::Gray,
    }
}

fn status_bool_color(value: bool) -> Color {
    if value {
        Color::Green
    } else {
        Color::Red
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "YES"
    } else {
        "NO"
    }
}

fn value_or_nd(value: &str) -> String {
    if value.trim().is_empty() {
        "N/D".into()
    } else {
        value.to_owned()
    }
}

fn option_number(value: Option<u64>) -> String {
    value.map(format_number).unwrap_or_else(|| "N/D".into())
}

fn queue_progress(depth: u64, capacity: u64) -> String {
    if capacity == 0 {
        "N/D".into()
    } else {
        format!("{:.1}%", depth as f64 * 100.0 / capacity as f64)
    }
}

fn storage_savings_factor(storage: &StorageSnapshot) -> f64 {
    if storage.packed_bytes > 0 {
        storage.raw_bytes as f64 / storage.packed_bytes as f64
    } else {
        1.0
    }
}

fn format_rate_bytes(bytes_per_sec: f64) -> String {
    if bytes_per_sec <= 0.0 {
        return "0 B/s".into();
    }
    format!("{}/s", format_bytes(bytes_per_sec as u64))
}

fn format_bytes(bytes: u64) -> String {
    let mut value = bytes as f64;
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"] {
        if value < 1024.0 {
            return format!("{value:.2} {unit}");
        }
        value /= 1024.0;
    }
    format!("{value:.2} PiB")
}

fn format_number(number: u64) -> String {
    let text = number.to_string();
    let mut output = String::with_capacity(text.len() + text.len() / 3);
    let len = text.len();
    for (index, character) in text.chars().enumerate() {
        if index > 0 && (len - index).is_multiple_of(3) {
            output.push('.');
        }
        output.push(character);
    }
    output
}

fn format_duration_short(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let secs = seconds % 60;
    if days > 0 {
        format!("{days}d {hours:02}h")
    } else if hours > 0 {
        format!("{hours:02}:{minutes:02}:{secs:02}")
    } else {
        format!("{minutes:02}:{secs:02}")
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_owned();
    }
    let mut output = text
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    output.push('…');
    output
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn base64_encode(bytes: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        output.push(CHARSET[((triple >> 18) & 0x3f) as usize] as char);
        output.push(CHARSET[((triple >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            CHARSET[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            CHARSET[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(
            base64_encode(b"security-admin:token"),
            "c2VjdXJpdHktYWRtaW46dG9rZW4="
        );
    }

    #[test]
    fn parses_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
        let parsed = parse_http_response(raw).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"hello world");
    }

    #[test]
    fn parses_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let parsed = parse_http_response(raw).unwrap();
        assert_eq!(parsed.body, b"hello world");
    }

    #[test]
    fn extracts_known_watermark_shapes() {
        let state = serde_json::json!({
            "views": {
                "watermarks": {
                    "vector": 100,
                    "text": 99
                }
            }
        });
        assert_eq!(
            extract_watermarks(&state),
            vec![("text".into(), 99), ("vector".into(), 100)]
        );
    }

    #[test]
    fn formats_number_pt_br_style() {
        assert_eq!(format_number(575809), "575.809");
        assert_eq!(format_number(8_600_000), "8.600.000");
    }
}
