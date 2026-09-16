use super::http::{derive_url_with_port, fetch_json, fetch_text, probe_port};
use super::model::{
    baseline_from, evaluate_alarms, extract_watermarks, parse_agent, parse_compliance, parse_raft,
    parse_redteam, parse_sentinel, parse_storage, u64_at, ActiveTabCompat, AgentSnapshot,
    AlarmBaseline, AlarmBook, AlarmInputs, ComplianceSnapshot, IndexSnapshot, RaftSnapshot,
    RedTeamSnapshot, SentinelSnapshot, StorageSnapshot,
};
use super::render;
use crossterm::{
    cursor::Show,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use serde_json::Value;
use std::collections::VecDeque;
use std::env;
use std::io;
use std::time::{Duration, Instant};

pub(super) const HISTORY_SAMPLES: usize = 120;
const MIN_INTERVAL_SECS: f64 = 0.10;
const MAX_INTERVAL_SECS: f64 = 10.0;
const SENTINEL_REFRESH: Duration = Duration::from_secs(2);
const AGENT_REFRESH: Duration = Duration::from_secs(2);
const REDTEAM_REFRESH: Duration = Duration::from_secs(2);
const GRPC_PROBE_REFRESH: Duration = Duration::from_secs(5);
const STATE_REFRESH: Duration = Duration::from_secs(10);
const COMPLIANCE_REFRESH: Duration = Duration::from_secs(30);

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ActiveTab {
    Overview = 0,
    Alarms = 1,
    Sentinel = 2,
    Agents = 3,
    Storage = 4,
    Raft = 5,
    Indexes = 6,
    Compliance = 7,
    System = 8,
}

impl ActiveTab {
    pub(super) const COUNT: usize = 9;

    fn from_index(index: usize) -> Self {
        match index % Self::COUNT {
            0 => Self::Overview,
            1 => Self::Alarms,
            2 => Self::Sentinel,
            3 => Self::Agents,
            4 => Self::Storage,
            5 => Self::Raft,
            6 => Self::Indexes,
            7 => Self::Compliance,
            _ => Self::System,
        }
    }

    fn next(self) -> Self {
        Self::from_index(self as usize + 1)
    }

    fn previous(self) -> Self {
        Self::from_index(self as usize + Self::COUNT - 1)
    }
}

pub(super) struct AppState {
    pub active_tab: ActiveTab,
    pub paused: bool,
    pub show_help: bool,
    pub interval_sec: f64,
    pub target_url: String,
    pub agent_url: String,
    pub auth: String,
    pub agent_auth: String,

    pub online: bool,
    pub health_text: String,
    pub last_error: Option<String>,
    pub agent_last_error: Option<String>,
    pub consecutive_failures: u64,
    pub rest_latency_ms: f64,
    pub agent_latency_ms: Option<f64>,
    pub started_at: Instant,
    pub last_success_at: Option<Instant>,

    pub head_lsn: u64,
    prev_head: Option<u64>,
    prev_head_at: Option<Instant>,
    pub insert_rate: f64,
    pub peak_rate: f64,
    pub rate_history: VecDeque<f64>,
    pub storage_format: String,

    pub memtable_entries: u64,
    pub memtable_capacity: Option<u64>,
    pub active_views: Vec<String>,
    pub view_watermarks: Vec<(String, u64)>,

    pub indexes: IndexSnapshot,
    pub storage: StorageSnapshot,
    pub sentinel: SentinelSnapshot,
    pub compliance: ComplianceSnapshot,
    pub raft: RaftSnapshot,
    pub agent: AgentSnapshot,
    pub redteam: RedTeamSnapshot,

    pub grpc_reachable: Option<bool>,
    pub grpc_probe_latency_ms: Option<f64>,

    pub alarms: AlarmBook,
    alarm_baseline: AlarmBaseline,
    baseline_initialized: bool,

    last_state_poll: Option<Instant>,
    last_sentinel_poll: Option<Instant>,
    last_compliance_poll: Option<Instant>,
    last_agent_poll: Option<Instant>,
    last_redteam_poll: Option<Instant>,
    last_grpc_probe: Option<Instant>,
}

impl AppState {
    fn new(target_url: String, auth: String, interval_sec: f64) -> Self {
        let agent_url = env::var("HERACLITUS_AGENT_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| derive_url_with_port(&target_url, 8080));
        Self {
            active_tab: ActiveTab::Overview,
            paused: false,
            show_help: false,
            interval_sec: interval_sec.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS),
            target_url,
            agent_url,
            auth: auth.clone(),
            agent_auth: auth,
            online: false,
            health_text: "UNKNOWN".into(),
            last_error: None,
            agent_last_error: None,
            consecutive_failures: 0,
            rest_latency_ms: 0.0,
            agent_latency_ms: None,
            started_at: Instant::now(),
            last_success_at: None,
            head_lsn: 0,
            prev_head: None,
            prev_head_at: None,
            insert_rate: 0.0,
            peak_rate: 0.0,
            rate_history: VecDeque::with_capacity(HISTORY_SAMPLES),
            storage_format: "unknown".into(),
            memtable_entries: 0,
            memtable_capacity: None,
            active_views: Vec::new(),
            view_watermarks: Vec::new(),
            indexes: IndexSnapshot::default(),
            storage: StorageSnapshot::default(),
            sentinel: SentinelSnapshot::default(),
            compliance: ComplianceSnapshot::default(),
            raft: RaftSnapshot::default(),
            agent: AgentSnapshot::default(),
            redteam: RedTeamSnapshot::default(),
            grpc_reachable: None,
            grpc_probe_latency_ms: None,
            alarms: AlarmBook::default(),
            alarm_baseline: AlarmBaseline::default(),
            baseline_initialized: false,
            last_state_poll: None,
            last_sentinel_poll: None,
            last_compliance_poll: None,
            last_agent_poll: None,
            last_redteam_poll: None,
            last_grpc_probe: None,
        }
    }

    pub(super) fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    pub(super) fn last_success_age(&self) -> Option<Duration> {
        self.last_success_at.map(|instant| instant.elapsed())
    }

    fn update_fast(&mut self) {
        let now = Instant::now();

        if let Ok((text, _)) = fetch_text(&mut self.target_url, &mut self.auth, "/healthz", 7475) {
            self.health_text = text.trim().to_string();
        }

        match fetch_json(&mut self.target_url, &mut self.auth, "/stats", 7475) {
            Ok((stats, latency_ms)) => {
                self.online = true;
                self.consecutive_failures = 0;
                self.rest_latency_ms = latency_ms;
                self.last_error = None;
                self.last_success_at = Some(now);
                self.apply_stats(stats, now);
            }
            Err(error) => {
                self.online = false;
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                self.last_error = Some(error);
            }
        }

        if should_poll(self.last_sentinel_poll, SENTINEL_REFRESH, now) {
            self.last_sentinel_poll = Some(now);
            self.poll_sentinel();
        }
        if should_poll(self.last_agent_poll, AGENT_REFRESH, now) {
            self.last_agent_poll = Some(now);
            self.poll_agent();
        }
        if should_poll(self.last_redteam_poll, REDTEAM_REFRESH, now) {
            self.last_redteam_poll = Some(now);
            self.poll_redteam();
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

        self.recompute_alarms();
    }

    fn force_refresh(&mut self) {
        self.last_state_poll = None;
        self.last_sentinel_poll = None;
        self.last_compliance_poll = None;
        self.last_agent_poll = None;
        self.last_redteam_poll = None;
        self.last_grpc_probe = None;
        self.update_fast();
    }

    fn apply_stats(&mut self, stats: Value, now: Instant) {
        let current_head = u64_at(&stats, "head").unwrap_or(0);
        self.head_lsn = current_head;
        self.storage_format = stats
            .get("storage_format")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
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
        push_history(&mut self.rate_history, self.insert_rate);

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
        if let Some(raft) = stats.get("raft") {
            self.raft = parse_raft(raft);
        } else {
            self.raft.available = false;
        }
    }

    fn poll_state(&mut self) {
        if let Ok((state, _)) = fetch_json(&mut self.target_url, &mut self.auth, "/state", 7475) {
            self.view_watermarks = extract_watermarks(&state);
        }
    }

    fn poll_sentinel(&mut self) {
        match fetch_json(
            &mut self.target_url,
            &mut self.auth,
            "/sentinel/status",
            7475,
        ) {
            Ok((value, _)) => self.sentinel = parse_sentinel(&value),
            Err(_) => self.sentinel.available = false,
        }
    }

    fn poll_compliance(&mut self) {
        match fetch_json(
            &mut self.target_url,
            &mut self.auth,
            "/compliance/status",
            7475,
        ) {
            Ok((value, _)) => self.compliance = parse_compliance(&value),
            Err(_) => self.compliance.available = false,
        }
    }

    fn poll_agent(&mut self) {
        match fetch_json(
            &mut self.agent_url,
            &mut self.agent_auth,
            "/api/v1/agent/status",
            8080,
        ) {
            Ok((value, latency)) => {
                self.agent = parse_agent(&value);
                self.agent_latency_ms = Some(latency);
                self.agent_last_error = None;
            }
            Err(error) => {
                self.agent.available = false;
                self.agent_latency_ms = None;
                self.agent_last_error = Some(error);
            }
        }
    }

    fn poll_redteam(&mut self) {
        if !self.agent.available {
            self.redteam.available = false;
            return;
        }
        match fetch_json(
            &mut self.agent_url,
            &mut self.agent_auth,
            "/api/v1/agent/red-team/events?limit=200",
            8080,
        ) {
            Ok((value, _)) => self.redteam = parse_redteam(&value),
            Err(_) => self.redteam.available = false,
        }
    }

    fn poll_grpc(&mut self) {
        match probe_port(&self.target_url, 7474) {
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

    fn recompute_alarms(&mut self) {
        if !self.baseline_initialized {
            self.alarm_baseline = baseline_from(&self.storage, &self.sentinel, &self.agent);
            self.baseline_initialized = true;
        }
        let candidates = evaluate_alarms(AlarmInputs {
            online: self.online,
            consecutive_failures: self.consecutive_failures,
            grpc_reachable: self.grpc_reachable,
            storage: &self.storage,
            sentinel: &self.sentinel,
            compliance: &self.compliance,
            agent: &self.agent,
            redteam: &self.redteam,
            baseline: &self.alarm_baseline,
        });
        self.alarms.reconcile(candidates);
        self.alarm_baseline = baseline_from(&self.storage, &self.sentinel, &self.agent);
    }

    fn reset_history(&mut self) {
        self.peak_rate = self.insert_rate;
        self.rate_history.clear();
    }
}

pub fn run_top(url_str: &str, user: &str, pass: &str, interval_sec: f64) -> Result<String, String> {
    enable_raw_mode().map_err(|error| format!("erro ao ativar raw mode: {error}"))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)
        .map_err(|error| format!("erro ao entrar no alternate screen: {error}"))?;
    let _terminal_guard = TerminalGuard;

    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)
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
            .draw(|frame| render::ui(frame, &mut app))
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
                    KeyCode::Char('q') | KeyCode::Esc => break,
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
                    KeyCode::Char('2') => app.active_tab = ActiveTab::Alarms,
                    KeyCode::Char('3') => app.active_tab = ActiveTab::Sentinel,
                    KeyCode::Char('4') => app.active_tab = ActiveTab::Agents,
                    KeyCode::Char('5') => app.active_tab = ActiveTab::Storage,
                    KeyCode::Char('6') => app.active_tab = ActiveTab::Raft,
                    KeyCode::Char('7') => app.active_tab = ActiveTab::Indexes,
                    KeyCode::Char('8') => app.active_tab = ActiveTab::Compliance,
                    KeyCode::Char('9') => app.active_tab = ActiveTab::System,
                    KeyCode::Tab => app.active_tab = app.active_tab.next(),
                    KeyCode::BackTab => app.active_tab = app.active_tab.previous(),
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

    Ok("Heraclitus Operations & Security Cockpit finalizado.".to_string())
}

fn should_poll(last: Option<Instant>, every: Duration, now: Instant) -> bool {
    last.map(|instant| now.saturating_duration_since(instant) >= every)
        .unwrap_or(true)
}

fn push_history(history: &mut VecDeque<f64>, value: f64) {
    if history.len() >= HISTORY_SAMPLES {
        history.pop_front();
    }
    history.push_back(value);
}
