use super::cockpit::{ActiveTab, AppState};
use super::model::{Alarm, AlarmSeverity};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Chart, Clear, Dataset, GraphType, Paragraph, Row, Table, Tabs, Wrap},
};

pub(super) fn ui(frame: &mut ratatui::Frame<'_>, app: &mut AppState) {
    let area = frame.area();
    if area.width < 92 || area.height < 28 {
        let warning = Paragraph::new(vec![
            Line::from(Span::styled(
                "HERACLITUS OPS & SECURITY COCKPIT",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!("Terminal atual: {}x{}", area.width, area.height)),
            Line::from("Mínimo recomendado: 92x28"),
            Line::from("Redimensione o terminal. q = sair"),
        ])
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(" TERMINAL PEQUENO "));
        frame.render_widget(warning, area);
        return;
    }

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(3),
        ])
        .split(area);

    render_tabs(frame, app, vertical[0]);
    render_alarm_banner(frame, app, vertical[1]);
    match app.active_tab {
        ActiveTab::Overview => render_overview(frame, app, vertical[2]),
        ActiveTab::Alarms => render_alarms(frame, app, vertical[2]),
        ActiveTab::Sentinel => render_sentinel(frame, app, vertical[2]),
        ActiveTab::Agents => render_agents(frame, app, vertical[2]),
        ActiveTab::Storage => render_storage(frame, app, vertical[2]),
        ActiveTab::Raft => render_raft(frame, app, vertical[2]),
        ActiveTab::Indexes => render_indexes(frame, app, vertical[2]),
        ActiveTab::Compliance => render_compliance(frame, app, vertical[2]),
        ActiveTab::System => render_system(frame, app, vertical[2]),
    }
    render_footer(frame, app, vertical[3]);

    if app.show_help {
        render_help(frame, area);
    }
}

fn render_tabs(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let titles = [
        "[1] Overview",
        "[2] Alarms",
        "[3] Sentinel",
        "[4] Agents",
        "[5] Storage",
        "[6] Raft",
        "[7] Indexes",
        "[8] Compliance",
        "[9] System",
    ]
    .into_iter()
    .map(Line::from)
    .collect::<Vec<_>>();
    let (_, warning, critical) = app.alarms.counts();
    let state = if app.online { "● ONLINE" } else { "● OFFLINE" };
    let state_style = if app.online {
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    };
    let alarm_style = if critical > 0 {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else if warning > 0 {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(vec![
                    Span::styled(
                        " ⚡ HERACLITUS OPS & SECURITY COCKPIT ",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(state, state_style),
                    Span::raw("  "),
                    Span::styled(format!("ALARMS C:{critical} W:{warning}"), alarm_style),
                    Span::raw(" "),
                ])),
        )
        .select(app.active_tab as usize)
        .style(Style::default().fg(Color::Gray))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .divider("│");
    frame.render_widget(tabs, area);
}

fn render_alarm_banner(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let active = app.alarms.active();
    let (_, warning, critical) = app.alarms.counts();
    let (text, style) = if let Some(alarm) = active.first() {
        let prefix = if alarm.severity == AlarmSeverity::Critical {
            "🚨 CRITICAL"
        } else if alarm.severity == AlarmSeverity::Warning {
            "⚠ WARNING"
        } else {
            "ℹ INFO"
        };
        (
            format!(
                " {prefix} [{}] {} :: {}  | active C:{critical} W:{warning} ",
                alarm.source,
                alarm.title,
                truncate(&alarm.detail, 110)
            ),
            alarm_style(alarm.severity).add_modifier(Modifier::BOLD),
        )
    } else {
        (
            " ✓ NO ACTIVE SECURITY / INTEGRITY ALARMS ".to_string(),
            Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD),
        )
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(text, style)))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn render_overview(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(12)])
        .split(area);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(vertical[0]);

    let core = Paragraph::new(vec![
        title_line("CORE / INGEST"),
        kv("REST", if app.online { "ONLINE" } else { "OFFLINE" }, bool_color(app.online)),
        kv("Head LSN", format_number(app.head_lsn), Color::Cyan),
        kv("Ingest", format!("{:.1} evt/s", app.insert_rate), Color::Green),
        kv("Peak", format!("{:.1} evt/s", app.peak_rate), Color::Yellow),
        kv("REST latency", format!("{:.2} ms", app.rest_latency_ms), latency_color(app.rest_latency_ms)),
    ])
    .block(Block::default().borders(Borders::ALL).title(" CORE "));
    frame.render_widget(core, top[0]);

    let sentinel = Paragraph::new(vec![
        title_line("SENTINEL"),
        kv("Available", yes_no(app.sentinel.available), bool_color(app.sentinel.available)),
        kv("State", nd(&app.sentinel.lag_state), sentinel_color(&app.sentinel.lag_state)),
        kv("Threats", format_number(app.sentinel.threat_matches_total), count_alarm_color(app.sentinel.threat_matches_total)),
        kv("Incidents", format_number(app.sentinel.incidents_created_total), count_alarm_color(app.sentinel.incidents_created_total)),
        kv("Detection lag", format!("{} LSN", format_number(app.sentinel.detection_lag_lsn)), sentinel_color(&app.sentinel.lag_state)),
    ])
    .block(Block::default().borders(Borders::ALL).title(" SECURITY "));
    frame.render_widget(sentinel, top[1]);

    let agent = Paragraph::new(vec![
        title_line("AGENT BLACK BOX"),
        kv("Available", yes_no(app.agent.available), bool_color(app.agent.available)),
        kv("Evidence", nd(&app.agent.evidence_log), health_color(&app.agent.evidence_log)),
        kv("Deny", format_number(app.agent.gateway_deny), Color::Yellow),
        kv("Replay blocked", format_number(app.agent.approval_replay_rejected), count_alarm_color(app.agent.approval_replay_rejected)),
        kv("Evidence errors", format_number(app.agent.evidence_errors), count_alarm_color(app.agent.evidence_errors)),
    ])
    .block(Block::default().borders(Borders::ALL).title(" AGENTS "));
    frame.render_widget(agent, top[2]);

    let storage = Paragraph::new(vec![
        title_line("HRKL"),
        kv("Format", app.storage_format.clone(), Color::Cyan),
        kv("RAW", format_bytes(app.storage.raw_bytes), Color::Yellow),
        kv("PACKED", format_bytes(app.storage.packed_bytes), Color::Green),
        kv("CRC failures", format_number(app.storage.physical_crc_failures), count_alarm_color(app.storage.physical_crc_failures)),
        kv("Canonical fail", format_number(app.storage.canonical_verify_failures), count_alarm_color(app.storage.canonical_verify_failures)),
    ])
    .block(Block::default().borders(Borders::ALL).title(" STORAGE "));
    frame.render_widget(storage, top[3]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(vertical[1]);
    render_ingest_chart(frame, app, bottom[0]);
    render_recent_alarms(frame, app, bottom[1]);
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
        .block(Block::default().borders(Borders::ALL).title(" INGESTION RATE HISTORY "))
        .x_axis(Axis::default().title("samples").bounds([0.0, max_x]))
        .y_axis(Axis::default().title("evt/s").bounds([0.0, max_y * 1.10]));
    frame.render_widget(chart, area);
}

fn render_recent_alarms(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let active = app.alarms.active();
    let mut lines = vec![title_line("ACTIVE ALARMS"), Line::from("")];
    if active.is_empty() {
        lines.push(Line::from(Span::styled("✓ Nenhum alarme ativo", Style::default().fg(Color::Green))));
    } else {
        for alarm in active.iter().take(10) {
            lines.push(Line::from(vec![
                Span::styled(format!("{:>4} ", alarm.severity.label()), alarm_style(alarm.severity)),
                Span::styled(format!("{:<12}", alarm.source), Style::default().fg(Color::Cyan)),
                Span::raw(truncate(&alarm.title, 34)),
            ]));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" SECURITY SIGNALS "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_alarms(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);
    render_alarm_table(frame, " ACTIVE ALARMS ", app.alarms.active(), sections[0]);
    render_alarm_table(frame, " ALARM HISTORY ", app.alarms.history(), sections[1]);
}

fn render_alarm_table(frame: &mut ratatui::Frame<'_>, title: &str, alarms: Vec<Alarm>, area: Rect) {
    let rows = alarms.iter().take(100).map(|alarm| {
        Row::new(vec![
            alarm.severity.label().to_string(),
            alarm.source.clone(),
            alarm.title.clone(),
            alarm.detail.clone(),
            alarm.occurrences.to_string(),
            if alarm.active { "ACTIVE".into() } else { "RESOLVED".into() },
        ])
        .style(alarm_style(alarm.severity))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(14),
            Constraint::Length(30),
            Constraint::Min(28),
            Constraint::Length(6),
            Constraint::Length(9),
        ],
    )
    .header(
        Row::new(["SEV", "SOURCE", "TITLE", "DETAIL", "COUNT", "STATE"])
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(table, area);
}

fn render_sentinel(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    if !app.sentinel.available {
        frame.render_widget(
            Paragraph::new("/sentinel/status indisponível. Estado não inferido.")
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title(" SENTINEL ")),
            area,
        );
        return;
    }
    let left = Paragraph::new(vec![
        title_line("PIPELINE / DETECTION"),
        kv("Enabled", yes_no(app.sentinel.enabled), bool_color(app.sentinel.enabled)),
        kv("Mode", nd(&app.sentinel.mode), Color::Cyan),
        kv("Pipeline version", app.sentinel.pipeline_version.to_string(), Color::Gray),
        kv("Head LSN", format_number(app.sentinel.head_lsn), Color::Cyan),
        kv("Processed LSN", option_number(app.sentinel.processed_lsn), Color::Green),
        kv("Lag", format!("{} LSN", format_number(app.sentinel.detection_lag_lsn)), sentinel_color(&app.sentinel.lag_state)),
        kv("Lag state", nd(&app.sentinel.lag_state), sentinel_color(&app.sentinel.lag_state)),
        kv("Queue", format!("{}/{}", app.sentinel.queue_depth, app.sentinel.queue_capacity), if app.sentinel.queue_overflow_total == 0 { Color::Green } else { Color::Red }),
        kv("Queue overflow", format_number(app.sentinel.queue_overflow_total), count_alarm_color(app.sentinel.queue_overflow_total)),
        kv("Seen / processed", format!("{} / {}", format_number(app.sentinel.events_seen_total), format_number(app.sentinel.events_processed_total)), Color::Gray),
        kv("Signals", format_number(app.sentinel.signals_emitted_total), Color::Yellow),
        kv("Threat matches", format_number(app.sentinel.threat_matches_total), count_alarm_color(app.sentinel.threat_matches_total)),
        kv("Incidents", format_number(app.sentinel.incidents_created_total), count_alarm_color(app.sentinel.incidents_created_total)),
        kv("Incident drops", format_number(app.sentinel.incident_capacity_drops_total), count_alarm_color(app.sentinel.incident_capacity_drops_total)),
        kv("Normalize errors", format_number(app.sentinel.normalization_errors_total), count_alarm_color(app.sentinel.normalization_errors_total)),
    ])
    .block(Block::default().borders(Borders::ALL).title(" SENTINEL SECURITY PIPELINE "))
    .wrap(Wrap { trim: false });
    frame.render_widget(left, columns[0]);

    let right = Paragraph::new(vec![
        title_line("AI / RESPONSE"),
        kv("AI circuit", nd(&app.sentinel.ai_circuit_state), health_color(&app.sentinel.ai_circuit_state)),
        kv("AI requests", format_number(app.sentinel.ai_requests_total), Color::Cyan),
        kv("AI failures", format_number(app.sentinel.ai_failures_total), count_alarm_color(app.sentinel.ai_failures_total)),
        kv("AI latency", format!("{} ms", app.sentinel.ai_latency_ms), Color::Gray),
        kv("AI tokens", format_number(app.sentinel.ai_tokens_total), Color::Gray),
        kv("Investigations", format_number(app.sentinel.ai_investigations_persisted_total), Color::Cyan),
        Line::from(""),
        kv("Actions proposed", format_number(app.sentinel.actions_proposed_total), Color::Yellow),
        kv("Approved", format_number(app.sentinel.actions_approved_total), Color::Green),
        kv("Denied", format_number(app.sentinel.actions_denied_total), Color::Yellow),
        kv("Executed", format_number(app.sentinel.actions_executed_total), Color::Cyan),
        kv("Action failures", format_number(app.sentinel.action_failures_total), count_alarm_color(app.sentinel.action_failures_total)),
        Line::from(""),
        kv("L0 latency", format!("{} µs", app.sentinel.l0_latency_us), Color::Gray),
        kv("L1/L2/L3", format!("{}/{}/{} ms", app.sentinel.l1_latency_ms, app.sentinel.l2_latency_ms, app.sentinel.l3_latency_ms), Color::Gray),
        kv("Boot", format!("{} ({} ms)", nd(&app.sentinel.boot_outcome), app.sentinel.boot_total_ms), Color::Gray),
    ])
    .block(Block::default().borders(Borders::ALL).title(" SENTINEL AI / RESPONSE "))
    .wrap(Wrap { trim: false });
    frame.render_widget(right, columns[1]);
}

fn render_agents(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(15), Constraint::Min(10)])
        .split(area);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(vertical[0]);

    let status = if app.agent.available {
        Paragraph::new(vec![
            title_line("AGENT BLACK BOX / GATEWAY"),
            kv("Endpoint", app.agent_url.clone(), Color::Cyan),
            kv("Product", nd(&app.agent.product), Color::Gray),
            kv("Auth", nd(&app.agent.auth), Color::Cyan),
            kv("Identifies people", yes_no(app.agent.auth_identifies_people), bool_color(app.agent.auth_identifies_people)),
            kv("Evidence log", nd(&app.agent.evidence_log), health_color(&app.agent.evidence_log)),
            kv("Integrity", nd(&app.agent.integrity), health_color(&app.agent.integrity)),
            kv("OTLP", nd(&app.agent.otlp_ingest), health_color(&app.agent.otlp_ingest)),
            kv("MCP gateway", nd(&app.agent.mcp_gateway), Color::Cyan),
            kv("Bypass protection", nd(&app.agent.bypass_protection), if app.agent.bypass_protection.eq_ignore_ascii_case("CONFIGURED") { Color::Green } else { Color::Yellow }),
            kv("RFC3161", nd(&app.agent.rfc3161), Color::Cyan),
            kv("Capture", nd(&app.agent.capture_mode), Color::Gray),
        ])
    } else {
        Paragraph::new(vec![
            title_line("AGENT BLACK BOX / GATEWAY"),
            Line::from(""),
            Line::from(Span::styled("Agent API indisponível", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from(format!("Endpoint: {}", app.agent_url)),
            Line::from(truncate(app.agent_last_error.as_deref().unwrap_or("sem detalhe"), 100)),
            Line::from("Override: HERACLITUS_AGENT_URL=http://host:8080"),
        ])
    }
    .block(Block::default().borders(Borders::ALL).title(" AGENT STATUS "))
    .wrap(Wrap { trim: false });
    frame.render_widget(status, top[0]);

    let counters = Paragraph::new(vec![
        title_line("SECURITY COUNTERS"),
        kv("Runs / tool calls", format!("{} / {}", format_number(app.agent.runs), format_number(app.agent.tool_calls)), Color::Cyan),
        kv("Denied", format_number(app.agent.denied), Color::Yellow),
        kv("Pending approvals", format_number(app.agent.pending_approvals), Color::Yellow),
        kv("Gateway requests", format_number(app.agent.gateway_requests), Color::Gray),
        kv("Allow / deny", format!("{} / {}", format_number(app.agent.gateway_allow), format_number(app.agent.gateway_deny)), Color::Yellow),
        kv("Require approval", format_number(app.agent.gateway_require_approval), Color::Yellow),
        kv("Shadow deny", format_number(app.agent.gateway_shadow_deny), Color::Yellow),
        kv("Replay rejected", format_number(app.agent.approval_replay_rejected), count_alarm_color(app.agent.approval_replay_rejected)),
        kv("Approval capacity", format_number(app.agent.approval_capacity_rejected), count_alarm_color(app.agent.approval_capacity_rejected)),
        kv("Policy errors", format_number(app.agent.policy_errors), count_alarm_color(app.agent.policy_errors)),
        kv("Evidence errors", format_number(app.agent.evidence_errors), count_alarm_color(app.agent.evidence_errors)),
        kv("Upstream errors", format_number(app.agent.upstream_errors), count_alarm_color(app.agent.upstream_errors)),
    ])
    .block(Block::default().borders(Borders::ALL).title(" AGENT SECURITY "))
    .wrap(Wrap { trim: false });
    frame.render_widget(counters, top[1]);

    render_redteam(frame, app, vertical[1]);
}

fn render_redteam(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let rows = app.redteam.events.iter().take(100).map(|event| {
        let style = if event.upstream_delta > 0 {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else if event.blocked {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Yellow)
        };
        Row::new(vec![
            truncate(&event.attack_id, 18),
            truncate(&event.vector, 24),
            truncate(&event.target, 20),
            if event.blocked { "BLOCKED".into() } else { "OBSERVED".into() },
            event.upstream_delta.to_string(),
            event.transport_status.map(|v| v.to_string()).unwrap_or_else(|| "N/D".into()),
            truncate(&event.reason_code, 28),
        ])
        .style(style)
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(19),
            Constraint::Length(25),
            Constraint::Length(21),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Min(18),
        ],
    )
    .header(Row::new(["ATTACK", "VECTOR", "TARGET", "RESULT", "UPSTREAM", "HTTP", "REASON"]).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
    .block(Block::default().borders(Borders::ALL).title(format!(
        " RED-TEAM EVIDENCE  returned={} blocked={} reached_upstream={} ",
        app.redteam.returned, app.redteam.blocked, app.redteam.reached_upstream
    )));
    frame.render_widget(table, area);
}

fn render_storage(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let left = Paragraph::new(vec![
        title_line("HRKL V6 / PACKING"),
        kv("Available", yes_no(app.storage.available), bool_color(app.storage.available)),
        kv("Append total", format_bytes(app.storage.append_bytes_total), Color::Gray),
        kv("RAW", format_bytes(app.storage.raw_bytes), Color::Yellow),
        kv("PACKED", format_bytes(app.storage.packed_bytes), Color::Green),
        kv("Packed/RAW", format!("{:.2}%", app.storage.compression_ratio * 100.0), Color::Cyan),
        kv("Pack queue", format_number(app.storage.pack_queue_depth), if app.storage.pack_queue_depth == 0 { Color::Green } else { Color::Yellow }),
        kv("Pack time", format!("{:.3}s", app.storage.pack_seconds), Color::Gray),
        kv("Pack throughput", format_rate_bytes(app.storage.pack_throughput_bytes_sec), Color::Green),
        kv("Blocks total", format_number(app.storage.blocks_total), Color::Gray),
        kv("Blocks read", format_number(app.storage.blocks_read), Color::Gray),
        kv("Blocks pruned", format_number(app.storage.blocks_pruned), Color::Gray),
        kv("Bytes pruned", format_bytes(app.storage.bytes_pruned), Color::Gray),
    ])
    .block(Block::default().borders(Borders::ALL).title(" STORAGE ENGINE "));
    frame.render_widget(left, columns[0]);

    let right = Paragraph::new(vec![
        title_line("INTEGRITY / COLD TIER"),
        kv("Physical CRC failures", format_number(app.storage.physical_crc_failures), count_alarm_color(app.storage.physical_crc_failures)),
        kv("Canonical failures", format_number(app.storage.canonical_verify_failures), count_alarm_color(app.storage.canonical_verify_failures)),
        kv("HRKI hits", format_number(app.storage.hrki_hits), Color::Green),
        kv("HRKI misses", format_number(app.storage.hrki_misses), Color::Yellow),
        kv("HRKI rebuilds", format_number(app.storage.hrki_rebuilds), Color::Yellow),
        kv("Cold reads", format_number(app.storage.cold_range_reads), Color::Gray),
        kv("Cold bytes", format_bytes(app.storage.cold_bytes_downloaded), Color::Gray),
        kv("Parquet lag", format!("{} LSN", format_number(app.storage.parquet_export_lag_lsn)), if app.storage.parquet_export_lag_lsn == 0 { Color::Green } else { Color::Yellow }),
        kv("Decompressed", format_bytes(app.storage.decompressed_bytes), Color::Gray),
        Line::from(""),
        Line::from(Span::styled("CRC ou canonical verify > 0 é alarme CRITICAL.", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))),
    ])
    .block(Block::default().borders(Borders::ALL).title(" STORAGE HEALTH "));
    frame.render_widget(right, columns[1]);
}

fn render_raft(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let text = if app.raft.available {
        vec![
            title_line("RAFT CONSENSUS"),
            Line::from(""),
            kv("Node", nd(&app.raft.node_id), Color::Cyan),
            kv("Role", nd(&app.raft.role), raft_color(&app.raft.role)),
            kv("Leader", nd(&app.raft.leader), Color::Green),
            kv("Term", option_number(app.raft.term), Color::Cyan),
            kv("Commit index", option_number(app.raft.commit_index), Color::Yellow),
            kv("Applied index", option_number(app.raft.applied_index), Color::Green),
            kv("Peers", option_number(app.raft.peers), Color::Gray),
            Line::from(""),
            Line::from(Span::styled("Este painel só mostra Raft se /stats realmente publicar o objeto `raft`.", Style::default().fg(Color::DarkGray))),
        ]
    } else {
        vec![
            title_line("RAFT CONSENSUS"),
            Line::from(""),
            Line::from(Span::styled("Raft telemetry: N/D", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from("O /stats não publicou role/leader/term/commit/applied."),
            Line::from("gRPC reachability aparece em System, mas não é prova de consenso."),
        ]
    };
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title(" RAFT "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_indexes(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);
    let left = Paragraph::new(vec![
        title_line("DERIVED INDEX COUNTS"),
        kv("Vector", format_number(app.indexes.vector_indexed), Color::Cyan),
        kv("Text/BM25", format_number(app.indexes.text_indexed), Color::Cyan),
        kv("Graph nodes", format_number(app.indexes.graph_nodes), Color::Cyan),
        kv("Temporal edges", format_number(app.indexes.tgraph_edges), Color::Cyan),
        kv("Entity keys", format_number(app.indexes.entity_keys), Color::Cyan),
        kv("Activation tracked", format_number(app.indexes.activation_tracked), Color::Cyan),
        Line::from(""),
        title_line("ACTIVE VIEWS"),
        Line::from(if app.active_views.is_empty() { "N/D".into() } else { app.active_views.join(" │ ") }),
    ])
    .block(Block::default().borders(Borders::ALL).title(" INDEXES / VIEWS "));
    frame.render_widget(left, columns[0]);

    let mut lines = vec![title_line("VIEW WATERMARKS"), Line::from("")];
    if app.view_watermarks.is_empty() {
        lines.push(Line::from(Span::styled("Nenhum watermark publicado/reconhecido.", Style::default().fg(Color::DarkGray))));
    } else {
        for (name, watermark) in &app.view_watermarks {
            let lag = app.head_lsn.saturating_sub(*watermark);
            lines.push(Line::from(vec![
                Span::styled(format!("{name:<25}"), Style::default().fg(Color::Cyan)),
                Span::styled(format!("LSN {:>14}", format_number(*watermark)), Style::default().fg(Color::Green)),
                Span::raw("   "),
                Span::styled(format!("lag {:>12}", format_number(lag)), Style::default().fg(if lag == 0 { Color::Green } else { Color::Yellow })),
            ]));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" REPLAY / VIEW LAG "))
            .wrap(Wrap { trim: false }),
        columns[1],
    );
}

fn render_compliance(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    if !app.compliance.available {
        frame.render_widget(
            Paragraph::new("/compliance/status indisponível ou ainda não consultado.")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::default().borders(Borders::ALL).title(" COMPLIANCE ")),
            area,
        );
        return;
    }
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let left = Paragraph::new(vec![
        title_line("TRUST / ANCHOR"),
        kv("Status", nd(&app.compliance.status), health_color(&app.compliance.status)),
        kv("As of LSN", format_number(app.compliance.as_of_lsn), Color::Cyan),
        kv("Receipts", format_number(app.compliance.receipts_total), Color::Gray),
        kv("Sealed watermark", format_number(app.compliance.current_sealed_watermark), Color::Green),
        kv("Last anchor", option_number(app.compliance.last_anchor_lsn), Color::Gray),
        kv("Deferred anchors", format_number(app.compliance.deferred_anchors), Color::Yellow),
        kv("Anchor forks", format_number(app.compliance.deferred_anchor_forks), count_alarm_color(app.compliance.deferred_anchor_forks)),
        kv("Policy versions", format_number(app.compliance.active_policy_versions), Color::Gray),
        kv("Legal holds", format_number(app.compliance.legal_holds), Color::Yellow),
        kv("Retention exceptions", format_number(app.compliance.retention_exceptions), Color::Yellow),
    ])
    .block(Block::default().borders(Borders::ALL).title(" COMPLIANCE TRUST "));
    frame.render_widget(left, columns[0]);

    let right = Paragraph::new(vec![
        title_line("REGULATORY / SOVEREIGNTY"),
        kv("Deadline overdue", format!("{} / {}", app.compliance.deadline_overdue, app.compliance.deadline_total), if app.compliance.deadline_overdue == 0 { Color::Green } else { Color::Red }),
        kv("Due 24/48/72h", format!("{}/{}/{}", app.compliance.deadline_24h, app.compliance.deadline_48h, app.compliance.deadline_72h), Color::Yellow),
        kv("ANPD pending", format_number(app.compliance.pending_anpd), Color::Yellow),
        kv("Egress allow/deny", format!("{}/{}", app.compliance.egress_allowed, app.compliance.egress_denied), Color::Cyan),
        kv("Model allow/deny", format!("{}/{}", app.compliance.model_allowed, app.compliance.model_denied), Color::Cyan),
        Line::from(""),
        Line::from(Span::styled(truncate(&app.compliance.trust_notice, 180), Style::default().fg(Color::DarkGray))),
    ])
    .block(Block::default().borders(Borders::ALL).title(" REGULATORY "))
    .wrap(Wrap { trim: false });
    frame.render_widget(right, columns[1]);
}

fn render_system(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let grpc = match app.grpc_reachable {
        Some(true) => format!("TCP reachable ({:.2} ms)", app.grpc_probe_latency_ms.unwrap_or(0.0)),
        Some(false) => "TCP unreachable".into(),
        None => "not probed".into(),
    };
    let left = Paragraph::new(vec![
        title_line("ENDPOINTS / TRANSPORT"),
        kv("Core URL", app.target_url.clone(), Color::Cyan),
        kv("Agent URL", app.agent_url.clone(), Color::Cyan),
        kv("REST /stats", if app.online { "ONLINE" } else { "OFFLINE" }, bool_color(app.online)),
        kv("Healthz", nd(&app.health_text), health_color(&app.health_text)),
        kv("REST latency", format!("{:.2} ms", app.rest_latency_ms), latency_color(app.rest_latency_ms)),
        kv("Agent latency", app.agent_latency_ms.map(|v| format!("{v:.2} ms")).unwrap_or_else(|| "N/D".into()), Color::Gray),
        kv("gRPC :7474", grpc, match app.grpc_reachable { Some(true) => Color::Green, Some(false) => Color::Red, None => Color::Gray }),
        kv("Failures", app.consecutive_failures.to_string(), if app.consecutive_failures == 0 { Color::Green } else { Color::Red }),
        kv("CLI uptime", format_duration(app.uptime()), Color::Gray),
        kv("Last core OK", app.last_success_age().map(format_duration).unwrap_or_else(|| "never".into()), Color::Gray),
    ])
    .block(Block::default().borders(Borders::ALL).title(" SYSTEM "));
    frame.render_widget(left, columns[0]);

    let right = Paragraph::new(vec![
        title_line("MEMTABLE / TELEMETRY CONTRACT"),
        kv("Memtable entries", format_number(app.memtable_entries), Color::Magenta),
        kv("Memtable capacity", app.memtable_capacity.map(format_number).unwrap_or_else(|| "N/D".into()), Color::Gray),
        Line::from(""),
        Line::from("Polling:"),
        Line::from("  /stats + /healthz       fast"),
        Line::from("  /sentinel/status        2s"),
        Line::from("  Agent status/red-team   2s"),
        Line::from("  gRPC TCP probe          5s"),
        Line::from("  /state                  10s"),
        Line::from("  /compliance/status      30s"),
        Line::from(""),
        Line::from(Span::styled("N/D significa dado não publicado. Não significa zero.", Style::default().fg(Color::Yellow))),
        Line::from(Span::styled("gRPC TCP reachable não significa gRPC healthy.", Style::default().fg(Color::DarkGray))),
    ])
    .block(Block::default().borders(Borders::ALL).title(" OBSERVABILITY CONTRACT "));
    frame.render_widget(right, columns[1]);
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
        Span::raw(" Core: "),
        Span::styled(&app.target_url, Style::default().fg(Color::Cyan)),
        Span::raw(" | refresh "),
        Span::styled(format!("{:.2}s", app.interval_sec), Style::default().fg(Color::Yellow)),
        Span::raw(" | "),
        Span::styled("1-9/Tab", Style::default().fg(Color::Yellow)),
        Span::raw(" tabs | "),
        Span::styled("u", Style::default().fg(Color::Yellow)),
        Span::raw(" refresh | "),
        Span::styled("p", Style::default().fg(Color::Yellow)),
        Span::raw(" pause | "),
        Span::styled("?", Style::default().fg(Color::Yellow)),
        Span::raw(" help | "),
        Span::styled("q", Style::default().fg(Color::Red)),
        Span::raw(" exit"),
    ];
    if let Some(error) = &app.last_error {
        spans.push(Span::raw(" | core: "));
        spans.push(Span::styled(truncate(error, 40), Style::default().fg(Color::Red)));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans))
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_help(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let popup = centered_rect(76, 76, area);
    frame.render_widget(Clear, popup);
    let help = Paragraph::new(vec![
        title_line("HERACLITUS TOP - OPERATIONS & SECURITY"),
        Line::from(""),
        help_line("1..9", "open tab directly"),
        help_line("Tab / Shift+Tab", "next / previous tab"),
        help_line("p / Space", "pause / continue polling"),
        help_line("u", "force refresh of every source"),
        help_line("r", "reset ingest graph/peak"),
        help_line("+ / -", "faster / slower refresh"),
        help_line("? / h", "open / close help"),
        help_line("q / Esc / Ctrl+C", "exit"),
        Line::from(""),
        Line::from("Agent API default: same host, port 8080."),
        Line::from("Override with HERACLITUS_AGENT_URL."),
        Line::from(""),
        Line::from(Span::styled("Alarm rules use measured counters and deltas. Historical counters do not become new attack alarms on startup.", Style::default().fg(Color::Cyan))),
        Line::from(Span::styled("Persistent integrity failures stay critical until the source reports recovery.", Style::default().fg(Color::Yellow))),
    ])
    .block(Block::default().borders(Borders::ALL).title(" HELP ").style(Style::default().bg(Color::Black)))
    .wrap(Wrap { trim: false });
    frame.render_widget(help, popup);
}

fn alarm_style(severity: AlarmSeverity) -> Style {
    match severity {
        AlarmSeverity::Info => Style::default().fg(Color::Cyan),
        AlarmSeverity::Warning => Style::default().fg(Color::Yellow),
        AlarmSeverity::Critical => Style::default().fg(Color::Red),
    }
}

fn title_line(text: &str) -> Line<'static> {
    Line::from(Span::styled(text.to_string(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
}

fn kv(label: &str, value: impl Into<String>, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<20}"), Style::default().fg(Color::Gray)),
        Span::styled(value.into(), Style::default().fg(color).add_modifier(Modifier::BOLD)),
    ])
}

fn help_line(key: &str, description: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key:<20}"), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(description.to_string()),
    ])
}

fn yes_no(value: bool) -> &'static str {
    if value { "YES" } else { "NO" }
}

fn bool_color(value: bool) -> Color {
    if value { Color::Green } else { Color::Red }
}

fn count_alarm_color(value: u64) -> Color {
    if value == 0 { Color::Green } else { Color::Red }
}

fn health_color(value: &str) -> Color {
    match value.to_ascii_uppercase().as_str() {
        "HEALTHY" | "OK" | "VERIFIED" | "CLOSED" | "ENABLED" => Color::Green,
        "DEGRADED" | "WARNING" | "UNKNOWN" | "DISABLED" => Color::Yellow,
        "FAILED" | "CRITICAL" | "BROKEN" | "ERROR" => Color::Red,
        _ => Color::Gray,
    }
}

fn sentinel_color(value: &str) -> Color {
    match value.to_ascii_uppercase().as_str() {
        "HEALTHY" => Color::Green,
        "DEGRADED" | "CATCHINGUP" | "CATCHING_UP" => Color::Yellow,
        "CRITICAL" | "FAILED" => Color::Red,
        _ => Color::Gray,
    }
}

fn raft_color(value: &str) -> Color {
    match value.to_ascii_uppercase().as_str() {
        "LEADER" => Color::Green,
        "FOLLOWER" => Color::Cyan,
        "CANDIDATE" => Color::Yellow,
        _ => Color::Gray,
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

fn nd(value: &str) -> String {
    if value.trim().is_empty() { "N/D".into() } else { value.to_string() }
}

fn option_number(value: Option<u64>) -> String {
    value.map(format_number).unwrap_or_else(|| "N/D".into())
}

fn format_number(value: u64) -> String {
    let text = value.to_string();
    let mut out = String::with_capacity(text.len() + text.len() / 3);
    for (index, ch) in text.chars().enumerate() {
        if index > 0 && (text.len() - index) % 3 == 0 {
            out.push('_');
        }
        out.push(ch);
    }
    out
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn format_rate_bytes(value: f64) -> String {
    if value <= 0.0 {
        "N/D".into()
    } else {
        format!("{}/s", format_bytes(value as u64))
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out = value.chars().take(max.saturating_sub(1)).collect::<String>();
    out.push('…');
    out
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
