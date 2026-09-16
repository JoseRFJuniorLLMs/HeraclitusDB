//! HeraclitusDB operational console (`heraclitus top`).
//!
//! The console renders only telemetry actually exposed by HeraclitusDB.  The
//! security posture is derived from `/sentinel/dashboard`, storage-integrity,
//! compliance and transport facts.  Missing telemetry is UNKNOWN, never green.

#[path = "top_security.rs"]
mod security;

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
    widgets::{Axis, Block, Borders, Chart, Clear, Dataset, GraphType, Paragraph, Row, Table, Tabs, Wrap},
    Terminal,
};
use security::{alarm_line, derive_alarms, parse_dashboard, posture, AlarmSeverity, SecurityAlarm, SecurityDashboardSnapshot};
use serde_json::Value;
use std::collections::VecDeque;
use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const HISTORY_SAMPLES: usize = 120;
const MIN_INTERVAL_SECS: f64 = 0.10;
const MAX_INTERVAL_SECS: f64 = 10.0;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
const IO_TIMEOUT: Duration = Duration::from_millis(3_000);
const SENTINEL_REFRESH: Duration = Duration::from_secs(2);
const GRPC_REFRESH: Duration = Duration::from_secs(5);
const COMPLIANCE_REFRESH: Duration = Duration::from_secs(30);

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
    Tasks = 1,
    Storage = 2,
    Queries = 3,
    Raft = 4,
    Security = 5,
    Indexes = 6,
}
impl ActiveTab {
    const COUNT: usize = 7;
    fn from_index(i: usize) -> Self {
        match i % Self::COUNT {
            0 => Self::Overview,
            1 => Self::Tasks,
            2 => Self::Storage,
            3 => Self::Queries,
            4 => Self::Raft,
            5 => Self::Security,
            _ => Self::Indexes,
        }
    }
    fn next(self) -> Self { Self::from_index(self as usize + 1) }
    fn previous(self) -> Self { Self::from_index(self as usize + Self::COUNT - 1) }
}

#[derive(Debug, Default, Clone)]
struct StorageSnapshot {
    raw_bytes: u64,
    packed_bytes: u64,
    pack_queue_depth: u64,
    parquet_export_lag_lsn: u64,
    canonical_verify_failures: u64,
    physical_crc_failures: u64,
    hrki_hits: u64,
    hrki_misses: u64,
    hrki_rebuilds: u64,
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
#[derive(Debug, Default, Clone)]
struct SentinelSnapshot {
    available: bool,
    enabled: bool,
    mode: String,
    lag_state: String,
    detection_lag_lsn: u64,
    queue_depth: u64,
    queue_capacity: u64,
    queue_overflow_total: u64,
    events_processed_total: u64,
    signals_emitted_total: u64,
    threat_matches_total: u64,
    incidents_created_total: u64,
    incident_capacity_drops_total: u64,
    normalization_errors_total: u64,
    ai_requests_total: u64,
    ai_failures_total: u64,
    ai_latency_ms: u64,
    ai_circuit_state: String,
    actions_proposed_total: u64,
    actions_approved_total: u64,
    actions_denied_total: u64,
    actions_executed_total: u64,
    action_failures_total: u64,
}
#[derive(Debug, Default, Clone)]
struct ComplianceSnapshot {
    available: bool,
    status: String,
    current_sealed_watermark: u64,
    deferred_anchors: u64,
    deferred_anchor_forks: u64,
    deadline_total: u64,
    deadline_overdue: u64,
    pending_anpd: u64,
    legal_holds: u64,
    egress_allowed: u64,
    egress_denied: u64,
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

struct AppState {
    active_tab: ActiveTab,
    paused: bool,
    help: bool,
    interval_sec: f64,
    target_url: String,
    auth: String,
    online: bool,
    health: String,
    last_error: Option<String>,
    rest_latency_ms: f64,
    grpc_reachable: Option<bool>,
    grpc_latency_ms: Option<f64>,
    head_lsn: u64,
    prev_head: Option<(u64, Instant)>,
    insert_rate: f64,
    peak_rate: f64,
    rate_history: VecDeque<f64>,
    storage_format: String,
    memtable_entries: u64,
    active_views: Vec<String>,
    indexes: IndexSnapshot,
    storage: StorageSnapshot,
    sentinel: SentinelSnapshot,
    security: SecurityDashboardSnapshot,
    compliance: ComplianceSnapshot,
    raft: RaftSnapshot,
    last_sentinel: Option<Instant>,
    last_compliance: Option<Instant>,
    last_grpc: Option<Instant>,
    started_at: Instant,
}

impl AppState {
    fn new(target_url: String, auth: String, interval_sec: f64) -> Self {
        Self {
            active_tab: ActiveTab::Overview,
            paused: false,
            help: false,
            interval_sec: interval_sec.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS),
            target_url,
            auth,
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
            last_sentinel: None,
            last_compliance: None,
            last_grpc: None,
            started_at: Instant::now(),
        }
    }

    fn refresh(&mut self, force: bool) {
        let now = Instant::now();
        match fetch_json(&self.target_url, &self.auth, "/stats") {
            Ok((stats, latency)) => {
                self.online = true;
                self.rest_latency_ms = latency;
                self.last_error = None;
                self.apply_stats(&stats, now);
            }
            Err(e) => {
                self.online = false;
                self.last_error = Some(e);
            }
        }
        if let Ok(resp) = fetch_http(&self.target_url, &self.auth, "/healthz") {
            if resp.is_success() {
                self.health = String::from_utf8_lossy(&resp.body).trim().to_string();
            }
        }
        if force || due(self.last_sentinel, SENTINEL_REFRESH, now) {
            self.last_sentinel = Some(now);
            self.poll_sentinel();
        }
        if force || due(self.last_compliance, COMPLIANCE_REFRESH, now) {
            self.last_compliance = Some(now);
            self.poll_compliance();
        }
        if force || due(self.last_grpc, GRPC_REFRESH, now) {
            self.last_grpc = Some(now);
            match probe_grpc(&self.target_url) {
                Ok(ms) => { self.grpc_reachable = Some(true); self.grpc_latency_ms = Some(ms); }
                Err(_) => { self.grpc_reachable = Some(false); self.grpc_latency_ms = None; }
            }
        }
    }

    fn apply_stats(&mut self, v: &Value, now: Instant) {
        let head = u64_at(v, "head").unwrap_or(0);
        if let Some((prev, at)) = self.prev_head {
            let dt = now.saturating_duration_since(at).as_secs_f64();
            if dt > 0.0 { self.insert_rate = head.saturating_sub(prev) as f64 / dt; }
        }
        self.prev_head = Some((head, now));
        self.head_lsn = head;
        self.peak_rate = self.peak_rate.max(self.insert_rate);
        push_history(&mut self.rate_history, self.insert_rate);
        self.storage_format = string_at(v, "storage_format").unwrap_or_else(|| "unknown".into());
        self.memtable_entries = u64_at(v, "memtable").unwrap_or(0);
        self.active_views = v.get("views").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
        self.indexes = IndexSnapshot {
            vector_indexed: u64_at(v, "vector_indexed").unwrap_or(0),
            text_indexed: u64_at(v, "text_indexed").unwrap_or(0),
            graph_nodes: u64_at(v, "graph_nodes").unwrap_or(0),
            tgraph_edges: u64_at(v, "tgraph_edges").unwrap_or(0),
            entity_keys: u64_at(v, "entity_keys").unwrap_or(0),
            activation_tracked: u64_at(v, "activation_tracked").unwrap_or(0),
        };
        if let Some(s) = v.get("storage_metrics") { self.storage = parse_storage(s); }
        if let Some(r) = v.get("raft") { self.raft = parse_raft(r); } else { self.raft.available = false; }
    }

    fn poll_sentinel(&mut self) {
        match fetch_json(&self.target_url, &self.auth, "/sentinel/dashboard") {
            Ok((v, _)) => {
                self.security = parse_dashboard(&v);
                if let Some(status) = v.get("status") { self.sentinel = parse_sentinel(status); }
            }
            Err(_) => match fetch_json(&self.target_url, &self.auth, "/sentinel/status") {
                Ok((v, _)) => self.sentinel = parse_sentinel(&v),
                Err(_) => { self.sentinel.available = false; self.security.available = false; }
            },
        }
    }

    fn poll_compliance(&mut self) {
        match fetch_json(&self.target_url, &self.auth, "/compliance/status") {
            Ok((v, _)) => self.compliance = parse_compliance(&v),
            Err(_) => self.compliance.available = false,
        }
    }

    fn alarms(&self) -> Vec<SecurityAlarm> {
        derive_alarms(
            self.online,
            self.grpc_reachable,
            &self.security.threat_level,
            &self.security.incidents,
            &self.sentinel.lag_state,
            self.sentinel.detection_lag_lsn,
            self.sentinel.queue_overflow_total,
            self.sentinel.incident_capacity_drops_total,
            self.sentinel.normalization_errors_total,
            self.sentinel.action_failures_total,
            &self.sentinel.ai_circuit_state,
            self.storage.canonical_verify_failures,
            self.storage.physical_crc_failures,
            self.storage.parquet_export_lag_lsn,
            self.compliance.deferred_anchor_forks,
            self.compliance.deadline_overdue,
            self.compliance.pending_anpd,
        )
    }
}

pub fn run_top(url_str: &str, user: &str, pass: &str, interval_sec: f64) -> Result<String, String> {
    enable_raw_mode().map_err(|e| format!("erro ao ativar raw mode: {e}"))?;
    execute!(io::stdout(), EnterAlternateScreen).map_err(|e| format!("alternate screen: {e}"))?;
    let _guard = TerminalGuard;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|e| format!("terminal Ratatui: {e}"))?;
    let auth = if user.is_empty() && pass.is_empty() { env_auth() } else { format!("{user}:{pass}") };
    let mut app = AppState::new(url_str.to_string(), auth, interval_sec);
    app.refresh(true);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|frame| ui(frame, &app)).map_err(|e| format!("draw: {e}"))?;
        let refresh = Duration::from_secs_f64(app.interval_sec);
        let timeout = refresh.saturating_sub(last_tick.elapsed());
        if event::poll(timeout).map_err(|e| e.to_string())? {
            if let Event::Key(key) = event::read().map_err(|e| e.to_string())? {
                if key.kind != KeyEventKind::Press && key.kind != KeyEventKind::Repeat { continue; }
                if app.help {
                    match key.code { KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('h') => app.help = false, KeyCode::Char('q') => break, _ => {} }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('p') | KeyCode::Char(' ') => app.paused = !app.paused,
                    KeyCode::Char('u') => { app.refresh(true); last_tick = Instant::now(); },
                    KeyCode::Char('?') | KeyCode::Char('h') => app.help = true,
                    KeyCode::Char('+') | KeyCode::Char('=') => app.interval_sec = (app.interval_sec - 0.25).max(MIN_INTERVAL_SECS),
                    KeyCode::Char('-') => app.interval_sec = (app.interval_sec + 0.25).min(MAX_INTERVAL_SECS),
                    KeyCode::Char('1') => app.active_tab = ActiveTab::Overview,
                    KeyCode::Char('2') => app.active_tab = ActiveTab::Tasks,
                    KeyCode::Char('3') => app.active_tab = ActiveTab::Storage,
                    KeyCode::Char('4') => app.active_tab = ActiveTab::Queries,
                    KeyCode::Char('5') => app.active_tab = ActiveTab::Raft,
                    KeyCode::Char('6') => app.active_tab = ActiveTab::Security,
                    KeyCode::Char('7') => app.active_tab = ActiveTab::Indexes,
                    KeyCode::Tab => app.active_tab = app.active_tab.next(),
                    KeyCode::BackTab => app.active_tab = app.active_tab.previous(),
                    _ => {}
                }
            }
        }
        if last_tick.elapsed() >= Duration::from_secs_f64(app.interval_sec) {
            if !app.paused { app.refresh(false); }
            last_tick = Instant::now();
        }
    }
    Ok("Heraclitus Operations Console finalizado.".into())
}

fn ui(frame: &mut ratatui::Frame<'_>, app: &AppState) {
    let area = frame.area();
    if area.width < 90 || area.height < 26 {
        frame.render_widget(Paragraph::new("HERACLITUS OPERATIONS CONSOLE\nTerminal mínimo recomendado: 90x26\nq = sair").alignment(Alignment::Center).block(Block::default().borders(Borders::ALL).title(" TERMINAL PEQUENO ")), area);
        return;
    }
    let vertical = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(3)]).split(area);
    render_tabs(frame, app, vertical[0]);
    match app.active_tab {
        ActiveTab::Overview => render_overview(frame, app, vertical[1]),
        ActiveTab::Tasks => render_tasks(frame, app, vertical[1]),
        ActiveTab::Storage => render_storage(frame, app, vertical[1]),
        ActiveTab::Queries => render_queries(frame, app, vertical[1]),
        ActiveTab::Raft => render_raft(frame, app, vertical[1]),
        ActiveTab::Security => render_security(frame, app, vertical[1]),
        ActiveTab::Indexes => render_indexes(frame, app, vertical[1]),
    }
    render_footer(frame, app, vertical[2]);
    if app.help { render_help(frame, area); }
}

fn render_tabs(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let alarms = app.alarms();
    let (posture_label, posture_color) = posture(&alarms);
    let crit = alarms.iter().filter(|a| a.severity == AlarmSeverity::Critical).count();
    let warn = alarms.iter().filter(|a| a.severity == AlarmSeverity::Warning).count();
    let titles = ["[1] Overview","[2] Tasks","[3] Storage","[4] Queries","[5] Raft","[6] Security","[7] Indexes"].into_iter().map(Line::from).collect::<Vec<_>>();
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(Line::from(vec![
            Span::styled(" ⚡ HERACLITUS OPERATIONS ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(format!(" SECURITY {posture_label} "), Style::default().fg(Color::Black).bg(posture_color).add_modifier(Modifier::BOLD)),
            Span::styled(format!(" C:{crit} W:{warn} "), Style::default().fg(posture_color)),
        ])))
        .select(app.active_tab as usize)
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .divider("│");
    frame.render_widget(tabs, area);
}

fn render_overview(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let v = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(8), Constraint::Length(7), Constraint::Min(8)]).split(area);
    let top = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(33),Constraint::Percentage(34),Constraint::Percentage(33)]).split(v[0]);
    frame.render_widget(Paragraph::new(vec![kv("Head LSN", fmt_num(app.head_lsn), Color::Cyan),kv("Ingest", format!("{:.1} evt/s", app.insert_rate), Color::Green),kv("Peak", format!("{:.1} evt/s", app.peak_rate), Color::Yellow),kv("Memtable", fmt_num(app.memtable_entries), Color::Magenta)]).block(Block::default().borders(Borders::ALL).title(" DATABASE ")), top[0]);
    frame.render_widget(Paragraph::new(vec![kv("REST", if app.online{"ONLINE"}else{"OFFLINE"}, if app.online{Color::Green}else{Color::Red}),kv("Latency", format!("{:.2} ms",app.rest_latency_ms), Color::Cyan),kv("gRPC", match app.grpc_reachable{Some(true)=>"REACHABLE",Some(false)=>"UNREACHABLE",None=>"UNKNOWN"}, match app.grpc_reachable{Some(true)=>Color::Green,Some(false)=>Color::Red,None=>Color::Gray}),kv("Health", app.health.clone(), Color::Cyan)]).block(Block::default().borders(Borders::ALL).title(" TRANSPORT ")), top[1]);
    frame.render_widget(Paragraph::new(vec![kv("Threat", app.security.threat_level.clone(), threat_color(&app.security.threat_level)),kv("Active incidents",app.security.active_incidents.to_string(), if app.security.active_incidents>0{Color::Yellow}else{Color::Green}),kv("Critical",app.security.critical_incidents.to_string(), if app.security.critical_incidents>0{Color::Red}else{Color::Green}),kv("Approvals",app.security.pending_approvals.to_string(), Color::Yellow)]).block(Block::default().borders(Borders::ALL).title(" SECURITY POSTURE ")), top[2]);

    let alarms = app.alarms();
    let lines = if alarms.is_empty(){vec![Line::from(Span::styled("Nenhum alarme ativo medido.",Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)))]}else{alarms.iter().take(4).map(alarm_line).collect()};
    frame.render_widget(Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" ACTIVE ALARMS ")).wrap(Wrap{trim:true}), v[1]);
    render_chart(frame, app, v[2]);
}

fn render_tasks(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let rows = vec![
        Row::new(["SENTINEL", &app.sentinel.lag_state, &format!("lag {} LSN", app.sentinel.detection_lag_lsn), &format!("queue {}/{}",app.sentinel.queue_depth,app.sentinel.queue_capacity)]),
        Row::new(["PACKER", if app.storage.pack_queue_depth>0{"RUNNING"}else{"IDLE"}, &format!("queue {}",app.storage.pack_queue_depth), "HRKL"]),
        Row::new(["LAKEHOUSE", if app.storage.parquet_export_lag_lsn>0{"LAGGING"}else{"SYNCED"}, &format!("lag {} LSN",app.storage.parquet_export_lag_lsn), "Parquet"]),
        Row::new(["INTEGRITY", if app.storage.canonical_verify_failures+app.storage.physical_crc_failures>0{"FAILED"}else{"HEALTHY"}, &format!("canonical={} crc={}",app.storage.canonical_verify_failures,app.storage.physical_crc_failures), "HRKL"]),
    ];
    let table = Table::new(rows,[Constraint::Length(15),Constraint::Length(15),Constraint::Length(32),Constraint::Min(20)]).header(Row::new(["PIPELINE","STATE","DETAIL","DOMAIN"]).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))).block(Block::default().borders(Borders::ALL).title(" OPERATIONAL PIPELINES "));
    frame.render_widget(table,area);
}

fn render_storage(frame:&mut ratatui::Frame<'_>,app:&AppState,area:Rect){
    let c=Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(50),Constraint::Percentage(50)]).split(area);
    frame.render_widget(Paragraph::new(vec![kv("RAW",fmt_bytes(app.storage.raw_bytes),Color::Yellow),kv("PACKED",fmt_bytes(app.storage.packed_bytes),Color::Green),kv("Pack queue",app.storage.pack_queue_depth.to_string(),Color::Yellow),kv("Parquet lag",format!("{} LSN",app.storage.parquet_export_lag_lsn),if app.storage.parquet_export_lag_lsn>0{Color::Yellow}else{Color::Green}),kv("HRKI hits",fmt_num(app.storage.hrki_hits),Color::Green),kv("HRKI misses",fmt_num(app.storage.hrki_misses),Color::Yellow),kv("HRKI rebuilds",fmt_num(app.storage.hrki_rebuilds),Color::Yellow)]).block(Block::default().borders(Borders::ALL).title(" HRKL / TIER ")),c[0]);
    frame.render_widget(Paragraph::new(vec![kv("Canonical failures",fmt_num(app.storage.canonical_verify_failures),if app.storage.canonical_verify_failures>0{Color::Red}else{Color::Green}),kv("Physical CRC failures",fmt_num(app.storage.physical_crc_failures),if app.storage.physical_crc_failures>0{Color::Red}else{Color::Green}),Line::from(""),Line::from(Span::styled("Qualquer falha canônica ou CRC é tratada como alarme CRITICAL.",Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)))]).block(Block::default().borders(Borders::ALL).title(" INTEGRITY ")),c[1]);
}

fn render_queries(frame:&mut ratatui::Frame<'_>,app:&AppState,area:Rect){
    let grpc=match app.grpc_reachable{Some(true)=>format!("TCP reachable {:.2} ms",app.grpc_latency_ms.unwrap_or(0.0)),Some(false)=>"TCP unreachable".into(),None=>"not probed".into()};
    frame.render_widget(Paragraph::new(vec![kv("REST /stats",if app.online{"ONLINE"}else{"OFFLINE"},if app.online{Color::Green}else{Color::Red}),kv("REST latency",format!("{:.2} ms",app.rest_latency_ms),Color::Cyan),kv("gRPC :7474",grpc,match app.grpc_reachable{Some(true)=>Color::Green,Some(false)=>Color::Red,None=>Color::Gray}),kv("Format",app.storage_format.clone(),Color::Cyan),Line::from(""),Line::from(Span::styled("QPS e percentis só devem aparecer quando o servidor os publicar. O painel não fabrica telemetria.",Style::default().fg(Color::DarkGray)))]).block(Block::default().borders(Borders::ALL).title(" QUERY / API HEALTH ")),area);
}

fn render_raft(frame:&mut ratatui::Frame<'_>,app:&AppState,area:Rect){
    let lines=if app.raft.available{vec![kv("Node",app.raft.node_id.clone(),Color::Cyan),kv("Role",app.raft.role.clone(),Color::Yellow),kv("Leader",app.raft.leader.clone(),Color::Green),kv("Term",opt_num(app.raft.term),Color::Cyan),kv("Commit",opt_num(app.raft.commit_index),Color::Yellow),kv("Applied",opt_num(app.raft.applied_index),Color::Green),kv("Peers",opt_num(app.raft.peers),Color::Gray)]}else{vec![Line::from(Span::styled("Raft telemetry não exposta em /stats.",Style::default().fg(Color::Yellow))),Line::from("O painel mantém UNKNOWN em vez de inventar leader/term.")]};
    frame.render_widget(Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" RAFT CONSENSUS ")),area);
}

fn render_security(frame:&mut ratatui::Frame<'_>,app:&AppState,area:Rect){
    let v=Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(8),Constraint::Percentage(42),Constraint::Percentage(58)]).split(area);
    let top=Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(25),Constraint::Percentage(25),Constraint::Percentage(25),Constraint::Percentage(25)]).split(v[0]);
    metric_box(frame,top[0],"THREAT",&app.security.threat_level,threat_color(&app.security.threat_level));
    metric_box(frame,top[1],"ACTIVE INCIDENTS",&app.security.active_incidents.to_string(),if app.security.active_incidents>0{Color::Yellow}else{Color::Green});
    metric_box(frame,top[2],"CRITICAL",&app.security.critical_incidents.to_string(),if app.security.critical_incidents>0{Color::Red}else{Color::Green});
    metric_box(frame,top[3],"PENDING APPROVALS",&app.security.pending_approvals.to_string(),Color::Yellow);

    let alarms=app.alarms();
    let alarm_lines=if alarms.is_empty(){vec![Line::from(Span::styled("NORMAL — nenhum alarme ativo medido",Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)))]}else{alarms.iter().take(10).map(alarm_line).collect()};
    frame.render_widget(Paragraph::new(alarm_lines).block(Block::default().borders(Borders::ALL).title(" SECURITY ALARMS ")).wrap(Wrap{trim:true}),v[1]);

    let lower=Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(67),Constraint::Percentage(33)]).split(v[2]);
    let rows=app.security.incidents.iter().filter(|i|!matches!(i.state.as_str(),"Resolved"|"FalsePositive")).take(20).map(|i|Row::new(vec![security::short_id(&i.id),format!("S{}",i.severity),format!("{:.2}",i.risk),i.state.clone(),i.subject.clone(),i.mitre.clone(),format!("{}..{}",i.first_lsn,i.last_lsn)]).style(Style::default().fg(if i.severity>=8{Color::Red}else if i.severity>=5{Color::Yellow}else{Color::Cyan})));
    let table=Table::new(rows,[Constraint::Length(13),Constraint::Length(4),Constraint::Length(6),Constraint::Length(17),Constraint::Length(24),Constraint::Length(15),Constraint::Min(16)]).header(Row::new(["INCIDENT","SEV","RISK","STATE","SUBJECT","MITRE","LSN"]).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))).block(Block::default().borders(Borders::ALL).title(" ACTIVE INCIDENTS "));
    frame.render_widget(table,lower[0]);
    frame.render_widget(Paragraph::new(vec![kv("Sentinel",if app.sentinel.enabled{"ENABLED"}else{"DISABLED"},if app.sentinel.enabled{Color::Green}else{Color::Yellow}),kv("Mode",app.sentinel.mode.clone(),Color::Cyan),kv("Lag",format!("{} / {} LSN",app.sentinel.lag_state,app.sentinel.detection_lag_lsn),if app.sentinel.detection_lag_lsn>0{Color::Yellow}else{Color::Green}),kv("Queue",format!("{}/{}",app.sentinel.queue_depth,app.sentinel.queue_capacity),if app.sentinel.queue_overflow_total>0{Color::Red}else{Color::Green}),kv("Threat matches",fmt_num(app.sentinel.threat_matches_total),Color::Red),kv("Signals",fmt_num(app.sentinel.signals_emitted_total),Color::Yellow),kv("AI circuit",app.sentinel.ai_circuit_state.clone(),Color::Cyan),kv("AI failures",fmt_num(app.sentinel.ai_failures_total),if app.sentinel.ai_failures_total>0{Color::Yellow}else{Color::Green}),kv("Actions P/A/D/E",format!("{}/{}/{}/{}",app.sentinel.actions_proposed_total,app.sentinel.actions_approved_total,app.sentinel.actions_denied_total,app.sentinel.actions_executed_total),Color::Cyan),kv("Action failures",fmt_num(app.sentinel.action_failures_total),if app.sentinel.action_failures_total>0{Color::Red}else{Color::Green}),kv("Compliance",app.compliance.status.clone(),Color::Cyan),kv("Anchor forks",fmt_num(app.compliance.deferred_anchor_forks),if app.compliance.deferred_anchor_forks>0{Color::Red}else{Color::Green})]).block(Block::default().borders(Borders::ALL).title(" SECURITY PIPELINE ")).wrap(Wrap{trim:true}),lower[1]);
}

fn render_indexes(frame:&mut ratatui::Frame<'_>,app:&AppState,area:Rect){
    frame.render_widget(Paragraph::new(vec![kv("Vector",fmt_num(app.indexes.vector_indexed),Color::Cyan),kv("Text",fmt_num(app.indexes.text_indexed),Color::Cyan),kv("Graph nodes",fmt_num(app.indexes.graph_nodes),Color::Cyan),kv("Temporal edges",fmt_num(app.indexes.tgraph_edges),Color::Cyan),kv("Entity keys",fmt_num(app.indexes.entity_keys),Color::Cyan),kv("Activation tracked",fmt_num(app.indexes.activation_tracked),Color::Cyan),Line::from(""),Line::from(Span::styled(if app.active_views.is_empty(){"No views reported".into()}else{app.active_views.join(" │ ")},Style::default().fg(Color::Green)))]).block(Block::default().borders(Borders::ALL).title(" INDEXES / VIEWS ")),area);
}

fn render_chart(frame:&mut ratatui::Frame<'_>,app:&AppState,area:Rect){
    let data=app.rate_history.iter().enumerate().map(|(i,v)|(i as f64,*v)).collect::<Vec<_>>();
    let max_y=app.rate_history.iter().copied().fold(1.0_f64,f64::max).max(10.0);
    let max_x=(app.rate_history.len().max(2)-1) as f64;
    let ds=Dataset::default().name("evt/s").marker(symbols::Marker::Braille).graph_type(GraphType::Line).style(Style::default().fg(Color::Cyan)).data(&data);
    frame.render_widget(Chart::new(vec![ds]).block(Block::default().borders(Borders::ALL).title(" INGESTION RATE ")).x_axis(Axis::default().bounds([0.0,max_x])).y_axis(Axis::default().bounds([0.0,max_y*1.1])),area);
}

fn render_footer(frame:&mut ratatui::Frame<'_>,app:&AppState,area:Rect){
    let alarms=app.alarms(); let (p,c)=posture(&alarms);
    let line=Line::from(vec![Span::styled(if app.paused{" PAUSED "}else{" RUNNING "},Style::default().fg(Color::Black).bg(if app.paused{Color::Yellow}else if app.online{Color::Green}else{Color::Red}).add_modifier(Modifier::BOLD)),Span::raw(" Target: "),Span::styled(app.target_url.clone(),Style::default().fg(Color::Cyan)),Span::raw(" | Security: "),Span::styled(p,Style::default().fg(c).add_modifier(Modifier::BOLD)),Span::raw(format!(" | refresh {:.2}s | Tab/1-7 abas | u refresh | p pause | ? help | q sair",app.interval_sec))]);
    frame.render_widget(Paragraph::new(line).block(Block::default().borders(Borders::ALL)),area);
}

fn render_help(frame:&mut ratatui::Frame<'_>,area:Rect){
    let popup=centered_rect(76,72,area); frame.render_widget(Clear,popup);
    frame.render_widget(Paragraph::new(vec![Line::from("1..7  abas"),Line::from("Tab / Shift+Tab  próxima/anterior"),Line::from("p / espaço  pausa"),Line::from("u  força refresh"),Line::from("+ / -  frequência"),Line::from("q / Esc / Ctrl+C  sair"),Line::from(""),Line::from(Span::styled("Alarmes usam /sentinel/dashboard, integridade HRKL, compliance e transporte. UNKNOWN nunca é HEALTHY.",Style::default().fg(Color::Yellow)))]).block(Block::default().borders(Borders::ALL).title(" HELP ")),popup);
}

fn metric_box(frame:&mut ratatui::Frame<'_>,area:Rect,title:&str,value:&str,color:Color){frame.render_widget(Paragraph::new(Line::from(Span::styled(value.to_string(),Style::default().fg(color).add_modifier(Modifier::BOLD)))).alignment(Alignment::Center).block(Block::default().borders(Borders::ALL).title(format!(" {title} "))),area);}
fn kv(label:&str,value:impl Into<String>,color:Color)->Line<'static>{Line::from(vec![Span::styled(format!("{label:<22}"),Style::default().fg(Color::Gray)),Span::styled(value.into(),Style::default().fg(color).add_modifier(Modifier::BOLD))])}
fn threat_color(s:&str)->Color{match s.to_ascii_lowercase().as_str(){"critical"=>Color::Red,"elevated"=>Color::Yellow,"normal"=>Color::Green,_=>Color::Gray}}
fn due(last:Option<Instant>,d:Duration,now:Instant)->bool{last.is_none_or(|x|now.saturating_duration_since(x)>=d)}
fn push_history(h:&mut VecDeque<f64>,v:f64){if h.len()>=HISTORY_SAMPLES{h.pop_front();}h.push_back(v);}
fn centered_rect(px:u16,py:u16,r:Rect)->Rect{let v=Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage((100-py)/2),Constraint::Percentage(py),Constraint::Percentage((100-py)/2)]).split(r);Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage((100-px)/2),Constraint::Percentage(px),Constraint::Percentage((100-px)/2)]).split(v[1])[1]}
fn opt_num(v:Option<u64>)->String{v.map(fmt_num).unwrap_or_else(||"N/D".into())}
fn fmt_num(n:u64)->String{let s=n.to_string();let mut out=String::new();for(i,c)in s.chars().rev().enumerate(){if i>0&&i%3==0{out.push('.');}out.push(c);}out.chars().rev().collect()}
fn fmt_bytes(n:u64)->String{const U:[&str;5]=["B","KiB","MiB","GiB","TiB"];let mut v=n as f64;let mut i=0;while v>=1024.0&&i<U.len()-1{v/=1024.0;i+=1;}format!("{v:.2} {}",U[i])}
fn string_at(v:&Value,k:&str)->Option<String>{v.get(k).and_then(Value::as_str).map(str::to_string)}
fn u64_at(v:&Value,k:&str)->Option<u64>{v.get(k).and_then(|x|x.as_u64().or_else(||x.as_i64().and_then(|n|(n>=0).then_some(n as u64))))}

fn parse_storage(v:&Value)->StorageSnapshot{StorageSnapshot{raw_bytes:u64_at(v,"hrkl_raw_bytes").unwrap_or(0),packed_bytes:u64_at(v,"hrkl_packed_bytes").unwrap_or(0),pack_queue_depth:u64_at(v,"hrkl_pack_queue_depth").unwrap_or(0),parquet_export_lag_lsn:u64_at(v,"parquet_export_lag_lsn").unwrap_or(0),canonical_verify_failures:u64_at(v,"canonical_verify_failures").unwrap_or(0),physical_crc_failures:u64_at(v,"physical_crc_failures").unwrap_or(0),hrki_hits:u64_at(v,"hrki_hits").unwrap_or(0),hrki_misses:u64_at(v,"hrki_misses").unwrap_or(0),hrki_rebuilds:u64_at(v,"hrki_rebuilds").unwrap_or(0)}}
fn parse_sentinel(v:&Value)->SentinelSnapshot{SentinelSnapshot{available:true,enabled:v.get("enabled").and_then(Value::as_bool).unwrap_or(false),mode:string_at(v,"mode").unwrap_or_default(),lag_state:string_at(v,"lag_state").unwrap_or_else(||"unknown".into()),detection_lag_lsn:u64_at(v,"detection_lag_lsn").unwrap_or(0),queue_depth:u64_at(v,"queue_depth").unwrap_or(0),queue_capacity:u64_at(v,"queue_capacity").unwrap_or(0),queue_overflow_total:u64_at(v,"queue_overflow_total").unwrap_or(0),events_processed_total:u64_at(v,"events_processed_total").unwrap_or(0),signals_emitted_total:u64_at(v,"signals_emitted_total").unwrap_or(0),threat_matches_total:u64_at(v,"threat_matches_total").unwrap_or(0),incidents_created_total:u64_at(v,"incidents_created_total").unwrap_or(0),incident_capacity_drops_total:u64_at(v,"incident_capacity_drops_total").unwrap_or(0),normalization_errors_total:u64_at(v,"normalization_errors_total").unwrap_or(0),ai_requests_total:u64_at(v,"ai_requests_total").unwrap_or(0),ai_failures_total:u64_at(v,"ai_failures_total").unwrap_or(0),ai_latency_ms:u64_at(v,"ai_latency_ms").unwrap_or(0),ai_circuit_state:string_at(v,"ai_circuit_state").unwrap_or_default(),actions_proposed_total:u64_at(v,"actions_proposed_total").unwrap_or(0),actions_approved_total:u64_at(v,"actions_approved_total").unwrap_or(0),actions_denied_total:u64_at(v,"actions_denied_total").unwrap_or(0),actions_executed_total:u64_at(v,"actions_executed_total").unwrap_or(0),action_failures_total:u64_at(v,"action_failures_total").unwrap_or(0)}}
fn parse_compliance(v:&Value)->ComplianceSnapshot{ComplianceSnapshot{available:true,status:string_at(v,"status").unwrap_or_else(||"unknown".into()),current_sealed_watermark:u64_at(v,"current_sealed_watermark").unwrap_or(0),deferred_anchors:u64_at(v,"deferred_anchors").unwrap_or(0),deferred_anchor_forks:u64_at(v,"deferred_anchor_forks").unwrap_or(0),deadline_total:u64_at(v,"deadline_total").unwrap_or(0),deadline_overdue:u64_at(v,"deadline_overdue").unwrap_or(0),pending_anpd:u64_at(v,"pending_anpd").unwrap_or(0),legal_holds:u64_at(v,"legal_holds").unwrap_or(0),egress_allowed:u64_at(v,"egress_allowed").unwrap_or(0),egress_denied:u64_at(v,"egress_denied").unwrap_or(0)}}
fn parse_raft(v:&Value)->RaftSnapshot{RaftSnapshot{available:true,role:string_at(v,"role").unwrap_or_default(),leader:string_at(v,"leader").unwrap_or_default(),term:u64_at(v,"term"),commit_index:u64_at(v,"commit_index"),applied_index:u64_at(v,"applied_index"),node_id:string_at(v,"node_id").unwrap_or_default(),peers:u64_at(v,"peers")}}

#[derive(Debug)] struct HttpResponse{status:u16,body:Vec<u8>} impl HttpResponse{fn is_success(&self)->bool{(200..300).contains(&self.status)}}
fn fetch_json(target:&str,auth:&str,path:&str)->Result<(Value,f64),String>{let t=Instant::now();let r=fetch_http(target,auth,path)?;let ms=t.elapsed().as_secs_f64()*1000.0;if !r.is_success(){return Err(format!("HTTP {} em {path}",r.status));}let v=serde_json::from_slice(&r.body).map_err(|e|format!("JSON inválido em {path}: {e}"))?;Ok((v,ms))}
fn fetch_http(target:&str,auth:&str,path:&str)->Result<HttpResponse,String>{if target.starts_with("https://"){return Err("https:// não suportado pelo cliente leve do top".into());}let authority=http_authority(target)?;let socket_authority=authority_port(&authority,7475);let socket=socket_authority.to_socket_addrs().map_err(|e|e.to_string())?.next().ok_or("sem endereço")?;let mut s=TcpStream::connect_timeout(&socket,CONNECT_TIMEOUT).map_err(|e|format!("connect {socket_authority}: {e}"))?;s.set_read_timeout(Some(IO_TIMEOUT)).map_err(|e|e.to_string())?;s.set_write_timeout(Some(IO_TIMEOUT)).map_err(|e|e.to_string())?;let auth_header=if auth.is_empty(){String::new()}else{format!("Authorization: Basic {}\r\n",base64_encode(auth.as_bytes()))};let req=format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\n{auth_header}Accept: application/json, text/plain\r\nUser-Agent: heraclitus-top/2\r\nConnection: close\r\n\r\n");s.write_all(req.as_bytes()).map_err(|e|e.to_string())?;let mut b=Vec::new();s.read_to_end(&mut b).map_err(|e|e.to_string())?;parse_http(&b)}
fn parse_http(b:&[u8])->Result<HttpResponse,String>{let pos=find_bytes(b,b"\r\n\r\n").ok_or("HTTP sem header end")?;let h=String::from_utf8_lossy(&b[..pos]);let status=h.lines().next().and_then(|l|l.split_whitespace().nth(1)).and_then(|s|s.parse().ok()).ok_or("status inválido")?;let chunked=h.lines().any(|l|l.to_ascii_lowercase().starts_with("transfer-encoding:")&&l.to_ascii_lowercase().contains("chunked"));let raw=&b[pos+4..];let body=if chunked{decode_chunked(raw)?}else{raw.to_vec()};Ok(HttpResponse{status,body})}
fn decode_chunked(input:&[u8])->Result<Vec<u8>,String>{let mut c=0;let mut out=Vec::new();loop{let re=find_bytes(&input[c..],b"\r\n").ok_or("chunk size")?;let end=c+re;let size=usize::from_str_radix(String::from_utf8_lossy(&input[c..end]).split(';').next().unwrap_or("").trim(),16).map_err(|e|e.to_string())?;c=end+2;if size==0{break;}let e=c.checked_add(size).ok_or("chunk overflow")?;if e>input.len(){return Err("chunk truncado".into());}out.extend_from_slice(&input[c..e]);c=e+2;}Ok(out)}
fn find_bytes(h:&[u8],n:&[u8])->Option<usize>{h.windows(n.len()).position(|w|w==n)}
fn http_authority(url:&str)->Result<String,String>{let clean=url.strip_prefix("http://").unwrap_or(url).trim_matches('/');let a=clean.split('/').next().unwrap_or("");if a.is_empty(){Err("URL inválida".into())}else{Ok(a.into())}}
fn authority_port(a:&str,p:u16)->String{if a.rsplit_once(':').and_then(|(_,p)|p.parse::<u16>().ok()).is_some(){a.into()}else{format!("{a}:{p}")}}
fn probe_grpc(target:&str)->Result<f64,String>{let a=http_authority(target)?;let host=a.rsplit_once(':').filter(|(_,p)|p.parse::<u16>().is_ok()).map(|(h,_)|h).unwrap_or(&a);let addr=format!("{host}:7474");let socket=addr.to_socket_addrs().map_err(|e|e.to_string())?.next().ok_or("sem endereço")?;let t=Instant::now();TcpStream::connect_timeout(&socket,Duration::from_millis(500)).map_err(|e|e.to_string())?;Ok(t.elapsed().as_secs_f64()*1000.0)}
fn env_auth()->String{let token=env::var("HERACLITUS_ADMIN_TOKEN").or_else(|_|env::var("HERACLITUS_TOKEN")).unwrap_or_default();if token.trim().is_empty(){String::new()}else{format!("security-admin:{}",token.trim())}}
fn base64_encode(input:&[u8])->String{const T:&[u8;64]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";let mut out=String::new();let mut i=0;while i<input.len(){let a=input[i];let b=if i+1<input.len(){input[i+1]}else{0};let c=if i+2<input.len(){input[i+2]}else{0};out.push(T[(a>>2)as usize]as char);out.push(T[(((a&3)<<4)|(b>>4))as usize]as char);if i+1<input.len(){out.push(T[(((b&15)<<2)|(c>>6))as usize]as char)}else{out.push('=')}if i+2<input.len(){out.push(T[(c&63)as usize]as char)}else{out.push('=')}i+=3;}out}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn base64_basic(){assert_eq!(base64_encode(b"admin:secret"),"YWRtaW46c2VjcmV0");}
    #[test]fn http_authority_default(){assert_eq!(authority_port("127.0.0.1",7475),"127.0.0.1:7475");}
}
