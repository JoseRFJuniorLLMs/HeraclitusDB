use super::model::{ActiveTab, AppState};
use super::security::{alarm_line, posture, short_id, AlarmSeverity};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Chart, Clear, Dataset, GraphType, Paragraph, Row, Table, Tabs, Wrap,
    },
};

pub(super) fn render(frame: &mut ratatui::Frame<'_>, app: &AppState) {
    let area = frame.area();
    if area.width < 100 || area.height < 28 {
        frame.render_widget(
            Paragraph::new(
                "HERACLITUS SECURITY OPERATIONS CONSOLE\nTerminal mínimo recomendado: 100x28\nq = sair",
            )
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title(" TERMINAL PEQUENO ")),
            area,
        );
        return;
    }

    let alarms = app.alarms();
    let urgent = alarms.iter().any(|alarm| {
        matches!(
            alarm.severity,
            AlarmSeverity::Warning | AlarmSeverity::Critical
        )
    });

    if urgent {
        let vertical = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(5),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(area);
        render_tabs(frame, app, &alarms, vertical[0]);
        render_alarm_strip(frame, &alarms, vertical[1]);
        render_active_tab(frame, app, vertical[2]);
        render_footer(frame, app, vertical[3]);
    } else {
        let vertical = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(area);
        render_tabs(frame, app, &alarms, vertical[0]);
        render_active_tab(frame, app, vertical[1]);
        render_footer(frame, app, vertical[2]);
    }

    if app.help {
        render_help(frame, area);
    }
}

fn render_active_tab(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    match app.active_tab {
        ActiveTab::Overview => render_overview(frame, app, area),
        ActiveTab::Tasks => render_tasks(frame, app, area),
        ActiveTab::Storage => render_storage(frame, app, area),
        ActiveTab::Queries => render_queries(frame, app, area),
        ActiveTab::Raft => render_raft(frame, app, area),
        ActiveTab::Security => render_security(frame, app, area),
        ActiveTab::Agents => render_agents(frame, app, area),
        ActiveTab::Indexes => render_indexes(frame, app, area),
    }
}

fn render_tabs(
    frame: &mut ratatui::Frame<'_>,
    app: &AppState,
    alarms: &[super::security::SecurityAlarm],
    area: Rect,
) {
    let (posture_label, posture_color) = posture(alarms);
    let critical = alarms
        .iter()
        .filter(|alarm| alarm.severity == AlarmSeverity::Critical)
        .count();
    let warning = alarms
        .iter()
        .filter(|alarm| alarm.severity == AlarmSeverity::Warning)
        .count();
    let titles = [
        "[1] Overview",
        "[2] Tasks",
        "[3] Storage",
        "[4] Queries",
        "[5] Raft",
        "[6] Security",
        "[7] Agents",
        "[8] Indexes",
    ]
    .into_iter()
    .map(Line::from)
    .collect::<Vec<_>>();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(Line::from(vec![
            Span::styled(
                " ⚡ HERACLITUS COMMAND CENTER ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" SECURITY {posture_label} "),
                Style::default()
                    .fg(Color::Black)
                    .bg(posture_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" C:{critical} W:{warning} "),
                Style::default().fg(posture_color),
            ),
        ])))
        .select(app.active_tab as usize)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .divider("│");
    frame.render_widget(tabs, area);
}

fn render_alarm_strip(
    frame: &mut ratatui::Frame<'_>,
    alarms: &[super::security::SecurityAlarm],
    area: Rect,
) {
    let urgent = alarms
        .iter()
        .filter(|alarm| alarm.severity != AlarmSeverity::Info)
        .take(3)
        .map(alarm_line)
        .collect::<Vec<_>>();
    let color = if alarms
        .iter()
        .any(|alarm| alarm.severity == AlarmSeverity::Critical)
    {
        Color::Red
    } else {
        Color::Yellow
    };
    frame.render_widget(
        Paragraph::new(urgent)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(color))
                    .title(Span::styled(
                        " ⚠ ATTACK / INTEGRITY ALARM ",
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    )),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_overview(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(8),
        ])
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

    frame.render_widget(
        Paragraph::new(vec![
            kv("Head LSN", fmt_num(app.head_lsn), Color::Cyan),
            kv("Ingest", format!("{:.1} evt/s", app.insert_rate), Color::Green),
            kv("Peak", format!("{:.1} evt/s", app.peak_rate), Color::Yellow),
            kv("Memtable", fmt_num(app.memtable_entries), Color::Magenta),
        ])
        .block(Block::default().borders(Borders::ALL).title(" DATABASE ")),
        top[0],
    );

    frame.render_widget(
        Paragraph::new(vec![
            kv(
                "REST",
                if app.online { "ONLINE" } else { "OFFLINE" },
                if app.online { Color::Green } else { Color::Red },
            ),
            kv("Latency", format!("{:.2} ms", app.rest_latency_ms), Color::Cyan),
            kv(
                "gRPC",
                match app.grpc_reachable {
                    Some(true) => "REACHABLE",
                    Some(false) => "UNREACHABLE",
                    None => "UNKNOWN",
                },
                match app.grpc_reachable {
                    Some(true) => Color::Green,
                    Some(false) => Color::Red,
                    None => Color::Gray,
                },
            ),
            kv("Health", app.health.clone(), Color::Cyan),
        ])
        .block(Block::default().borders(Borders::ALL).title(" TRANSPORT ")),
        top[1],
    );

    frame.render_widget(
        Paragraph::new(vec![
            kv(
                "Threat",
                app.security.threat_level.clone(),
                threat_color(&app.security.threat_level),
            ),
            kv(
                "Active incidents",
                app.security.active_incidents.to_string(),
                if app.security.active_incidents > 0 {
                    Color::Yellow
                } else {
                    Color::Green
                },
            ),
            kv(
                "Critical",
                app.security.critical_incidents.to_string(),
                if app.security.critical_incidents > 0 {
                    Color::Red
                } else {
                    Color::Green
                },
            ),
            kv("Sentinel matches", fmt_num(app.sentinel.threat_matches_total), Color::Red),
        ])
        .block(Block::default().borders(Borders::ALL).title(" SENTINEL ")),
        top[2],
    );

    frame.render_widget(
        Paragraph::new(vec![
            kv(
                "Agent API",
                if app.agent.available { "ONLINE" } else { "UNKNOWN" },
                if app.agent.available { Color::Green } else { Color::Gray },
            ),
            kv("MCP gateway", app.agent.mcp_gateway.clone(), gateway_color(&app.agent.mcp_gateway)),
            kv("Deny Δ", fmt_num(app.agent.delta_deny), if app.agent.delta_deny > 0 { Color::Yellow } else { Color::Green }),
            kv("Replay Δ", fmt_num(app.agent.delta_replay), if app.agent.delta_replay > 0 { Color::Red } else { Color::Green }),
        ])
        .block(Block::default().borders(Borders::ALL).title(" AGENT SECURITY ")),
        top[3],
    );

    let alarms = app.alarms();
    let lines = if alarms.is_empty() {
        vec![Line::from(Span::styled(
            "Nenhum alarme ativo medido.",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))]
    } else {
        alarms.iter().take(6).map(alarm_line).collect()
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" ACTIVE ALARMS "))
            .wrap(Wrap { trim: true }),
        vertical[1],
    );
    render_chart(frame, app, vertical[2]);
}

fn render_tasks(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let gateway_state = if !app.agent.available {
        "UNKNOWN".to_string()
    } else {
        app.agent.mcp_gateway.clone()
    };
    let rows = vec![
        Row::new(vec![
            "SENTINEL".to_string(),
            app.sentinel.lag_state.clone(),
            format!("lag {} LSN", app.sentinel.detection_lag_lsn),
            format!("queue {}/{}", app.sentinel.queue_depth, app.sentinel.queue_capacity),
        ]),
        Row::new(vec![
            "AGENT GATEWAY".to_string(),
            gateway_state,
            format!("deny={} replay={}", app.agent.gateway_deny, app.agent.approval_replay_rejected),
            format!("evidence_errors={}", app.agent.evidence_errors),
        ]),
        Row::new(vec![
            "OTLP AGENT".to_string(),
            app.agent.otlp_ingest.clone(),
            format!("events={} rejected={}", app.agent.ingest_events, app.agent.ingest_rejected),
            format!("conflicts={}", app.agent.ingest_conflicts),
        ]),
        Row::new(vec![
            "PACKER".to_string(),
            if app.storage.pack_queue_depth > 0 { "RUNNING" } else { "IDLE" }.to_string(),
            format!("queue {}", app.storage.pack_queue_depth),
            "HRKL".to_string(),
        ]),
        Row::new(vec![
            "LAKEHOUSE".to_string(),
            if app.storage.parquet_export_lag_lsn > 0 { "LAGGING" } else { "SYNCED" }.to_string(),
            format!("lag {} LSN", app.storage.parquet_export_lag_lsn),
            "Parquet".to_string(),
        ]),
        Row::new(vec![
            "INTEGRITY".to_string(),
            if app.storage.canonical_verify_failures + app.storage.physical_crc_failures > 0 {
                "FAILED"
            } else {
                "HEALTHY"
            }
            .to_string(),
            format!(
                "canonical={} crc={}",
                app.storage.canonical_verify_failures, app.storage.physical_crc_failures
            ),
            "HRKL".to_string(),
        ]),
    ];
    let table = Table::new(
        rows,
        [
            Constraint::Length(17),
            Constraint::Length(16),
            Constraint::Length(36),
            Constraint::Min(24),
        ],
    )
    .header(
        Row::new(["PIPELINE", "STATE", "DETAIL", "DOMAIN"])
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(" OPERATIONAL PIPELINES "));
    frame.render_widget(table, area);
}

fn render_storage(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    frame.render_widget(
        Paragraph::new(vec![
            kv("RAW", fmt_bytes(app.storage.raw_bytes), Color::Yellow),
            kv("PACKED", fmt_bytes(app.storage.packed_bytes), Color::Green),
            kv("Pack queue", app.storage.pack_queue_depth.to_string(), Color::Yellow),
            kv(
                "Parquet lag",
                format!("{} LSN", app.storage.parquet_export_lag_lsn),
                if app.storage.parquet_export_lag_lsn > 0 {
                    Color::Yellow
                } else {
                    Color::Green
                },
            ),
            kv("HRKI hits", fmt_num(app.storage.hrki_hits), Color::Green),
            kv("HRKI misses", fmt_num(app.storage.hrki_misses), Color::Yellow),
            kv("HRKI rebuilds", fmt_num(app.storage.hrki_rebuilds), Color::Yellow),
        ])
        .block(Block::default().borders(Borders::ALL).title(" HRKL / TIER ")),
        columns[0],
    );
    frame.render_widget(
        Paragraph::new(vec![
            kv(
                "Canonical failures",
                fmt_num(app.storage.canonical_verify_failures),
                if app.storage.canonical_verify_failures > 0 {
                    Color::Red
                } else {
                    Color::Green
                },
            ),
            kv(
                "Physical CRC failures",
                fmt_num(app.storage.physical_crc_failures),
                if app.storage.physical_crc_failures > 0 {
                    Color::Red
                } else {
                    Color::Green
                },
            ),
            kv("Compliance", app.compliance.status.clone(), Color::Cyan),
            kv(
                "Anchor forks",
                fmt_num(app.compliance.deferred_anchor_forks),
                if app.compliance.deferred_anchor_forks > 0 {
                    Color::Red
                } else {
                    Color::Green
                },
            ),
            Line::from(""),
            Line::from(Span::styled(
                "Falha canônica, CRC ou fork de âncora sobe para CRITICAL.",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title(" INTEGRITY / COMPLIANCE ")),
        columns[1],
    );
}

fn render_queries(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let grpc = match app.grpc_reachable {
        Some(true) => format!("TCP reachable {:.2} ms", app.grpc_latency_ms.unwrap_or(0.0)),
        Some(false) => "TCP unreachable".into(),
        None => "not probed".into(),
    };
    frame.render_widget(
        Paragraph::new(vec![
            kv(
                "REST /stats",
                if app.online { "ONLINE" } else { "OFFLINE" },
                if app.online { Color::Green } else { Color::Red },
            ),
            kv("REST latency", format!("{:.2} ms", app.rest_latency_ms), Color::Cyan),
            kv(
                "gRPC :7474",
                grpc,
                match app.grpc_reachable {
                    Some(true) => Color::Green,
                    Some(false) => Color::Red,
                    None => Color::Gray,
                },
            ),
            kv("Format", app.storage_format.clone(), Color::Cyan),
            Line::from(""),
            Line::from(Span::styled(
                "QPS e percentis só aparecem quando o servidor os publica. UNKNOWN continua UNKNOWN.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title(" QUERY / API HEALTH ")),
        area,
    );
}

fn render_raft(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let lines = if app.raft.available {
        vec![
            kv("Node", app.raft.node_id.clone(), Color::Cyan),
            kv("Role", app.raft.role.clone(), Color::Yellow),
            kv("Leader", app.raft.leader.clone(), Color::Green),
            kv("Term", opt_num(app.raft.term), Color::Cyan),
            kv("Commit", opt_num(app.raft.commit_index), Color::Yellow),
            kv("Applied", opt_num(app.raft.applied_index), Color::Green),
            kv("Peers", opt_num(app.raft.peers), Color::Gray),
        ]
    } else {
        vec![
            Line::from(Span::styled(
                "Raft telemetry não exposta em /stats.",
                Style::default().fg(Color::Yellow),
            )),
            Line::from("O painel mantém UNKNOWN em vez de inventar leader/term."),
        ]
    };
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" RAFT CONSENSUS ")),
        area,
    );
}

fn render_security(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Percentage(42),
            Constraint::Percentage(58),
        ])
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
    metric_box(
        frame,
        top[0],
        "THREAT",
        &app.security.threat_level,
        threat_color(&app.security.threat_level),
    );
    metric_box(
        frame,
        top[1],
        "ACTIVE INCIDENTS",
        &app.security.active_incidents.to_string(),
        if app.security.active_incidents > 0 {
            Color::Yellow
        } else {
            Color::Green
        },
    );
    metric_box(
        frame,
        top[2],
        "CRITICAL",
        &app.security.critical_incidents.to_string(),
        if app.security.critical_incidents > 0 {
            Color::Red
        } else {
            Color::Green
        },
    );
    metric_box(
        frame,
        top[3],
        "GATEWAY DENY Δ",
        &app.agent.delta_deny.to_string(),
        if app.agent.delta_deny > 0 {
            Color::Yellow
        } else {
            Color::Green
        },
    );

    let alarms = app.alarms();
    let alarm_lines = if alarms.is_empty() {
        vec![Line::from(Span::styled(
            "NORMAL — nenhum alarme ativo medido",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ))]
    } else {
        alarms.iter().take(12).map(alarm_line).collect()
    };
    frame.render_widget(
        Paragraph::new(alarm_lines)
            .block(Block::default().borders(Borders::ALL).title(" SECURITY ALARMS "))
            .wrap(Wrap { trim: true }),
        vertical[1],
    );

    let lower = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(67), Constraint::Percentage(33)])
        .split(vertical[2]);
    let rows = app
        .security
        .incidents
        .iter()
        .filter(|incident| !matches!(incident.state.as_str(), "Resolved" | "FalsePositive"))
        .take(20)
        .map(|incident| {
            Row::new(vec![
                short_id(&incident.id),
                format!("S{}", incident.severity),
                format!("{:.2}", incident.risk),
                incident.state.clone(),
                incident.subject.clone(),
                incident.mitre.clone(),
                format!("{}..{}", incident.first_lsn, incident.last_lsn),
            ])
            .style(Style::default().fg(if incident.severity >= 8 {
                Color::Red
            } else if incident.severity >= 5 {
                Color::Yellow
            } else {
                Color::Cyan
            }))
        });
    let table = Table::new(
        rows,
        [
            Constraint::Length(13),
            Constraint::Length(4),
            Constraint::Length(6),
            Constraint::Length(17),
            Constraint::Length(24),
            Constraint::Length(15),
            Constraint::Min(16),
        ],
    )
    .header(
        Row::new(["INCIDENT", "SEV", "RISK", "STATE", "SUBJECT", "MITRE", "LSN"])
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(" ACTIVE INCIDENTS "));
    frame.render_widget(table, lower[0]);

    frame.render_widget(
        Paragraph::new(vec![
            kv(
                "Sentinel",
                if app.sentinel.enabled { "ENABLED" } else { "DISABLED" },
                if app.sentinel.enabled { Color::Green } else { Color::Yellow },
            ),
            kv("Mode", app.sentinel.mode.clone(), Color::Cyan),
            kv(
                "Lag",
                format!("{} / {} LSN", app.sentinel.lag_state, app.sentinel.detection_lag_lsn),
                if app.sentinel.detection_lag_lsn > 0 {
                    Color::Yellow
                } else {
                    Color::Green
                },
            ),
            kv(
                "Queue",
                format!("{}/{}", app.sentinel.queue_depth, app.sentinel.queue_capacity),
                if app.sentinel.queue_overflow_total > 0 {
                    Color::Red
                } else {
                    Color::Green
                },
            ),
            kv("Threat matches", fmt_num(app.sentinel.threat_matches_total), Color::Red),
            kv("Signals", fmt_num(app.sentinel.signals_emitted_total), Color::Yellow),
            kv("AI circuit", app.sentinel.ai_circuit_state.clone(), Color::Cyan),
            kv(
                "AI failures",
                fmt_num(app.sentinel.ai_failures_total),
                if app.sentinel.ai_failures_total > 0 {
                    Color::Yellow
                } else {
                    Color::Green
                },
            ),
            kv(
                "Actions P/A/D/E",
                format!(
                    "{}/{}/{}/{}",
                    app.sentinel.actions_proposed_total,
                    app.sentinel.actions_approved_total,
                    app.sentinel.actions_denied_total,
                    app.sentinel.actions_executed_total
                ),
                Color::Cyan,
            ),
            kv(
                "Action failures",
                fmt_num(app.sentinel.action_failures_total),
                if app.sentinel.action_failures_total > 0 {
                    Color::Red
                } else {
                    Color::Green
                },
            ),
            kv("Compliance", app.compliance.status.clone(), Color::Cyan),
            kv(
                "Anchor forks",
                fmt_num(app.compliance.deferred_anchor_forks),
                if app.compliance.deferred_anchor_forks > 0 {
                    Color::Red
                } else {
                    Color::Green
                },
            ),
        ])
        .block(Block::default().borders(Borders::ALL).title(" SECURITY PIPELINE "))
        .wrap(Wrap { trim: true }),
        lower[1],
    );
}

fn render_agents(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Min(10),
        ])
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

    metric_box(
        frame,
        top[0],
        "MCP GATEWAY",
        if app.agent.available {
            &app.agent.mcp_gateway
        } else {
            "UNKNOWN"
        },
        gateway_color(&app.agent.mcp_gateway),
    );
    metric_box(
        frame,
        top[1],
        "DENY Δ",
        &app.agent.delta_deny.to_string(),
        if app.agent.delta_deny > 0 {
            Color::Yellow
        } else {
            Color::Green
        },
    );
    metric_box(
        frame,
        top[2],
        "REPLAY Δ",
        &app.agent.delta_replay.to_string(),
        if app.agent.delta_replay > 0 {
            Color::Red
        } else {
            Color::Green
        },
    );
    metric_box(
        frame,
        top[3],
        "LAB UPSTREAM",
        &app.agent.redteam_reached_upstream.to_string(),
        if app.agent.redteam_reached_upstream > 0 {
            Color::Red
        } else {
            Color::Green
        },
    );

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(vertical[1]);

    let availability_color = if app.agent.available {
        Color::Green
    } else {
        Color::Gray
    };
    frame.render_widget(
        Paragraph::new(vec![
            kv("Agent API", if app.agent.available { "ONLINE" } else { "UNKNOWN" }, availability_color),
            kv("Target", app.agent_url.clone(), Color::Cyan),
            kv("Latency", format!("{:.2} ms", app.agent.latency_ms), Color::Cyan),
            kv("Auth", app.agent.auth.clone(), Color::Yellow),
            kv(
                "Identifies people",
                match app.agent.auth_identifies_people {
                    Some(true) => "YES",
                    Some(false) => "NO",
                    None => "UNKNOWN",
                },
                match app.agent.auth_identifies_people {
                    Some(true) => Color::Green,
                    Some(false) => Color::Yellow,
                    None => Color::Gray,
                },
            ),
            kv("Evidence log", app.agent.evidence_log.clone(), state_color(&app.agent.evidence_log)),
            kv("OTLP ingest", app.agent.otlp_ingest.clone(), state_color(&app.agent.otlp_ingest)),
            kv("Bypass", app.agent.bypass_protection.clone(), state_color(&app.agent.bypass_protection)),
            kv("RFC3161", app.agent.rfc3161.clone(), Color::Cyan),
        ])
        .block(Block::default().borders(Borders::ALL).title(" AGENT CONTROL PLANE "))
        .wrap(Wrap { trim: true }),
        columns[0],
    );

    frame.render_widget(
        Paragraph::new(vec![
            kv("Gateway requests", fmt_num(app.agent.gateway_requests), Color::Cyan),
            kv("Allow", fmt_num(app.agent.gateway_allow), Color::Green),
            kv("Deny", fmt_num(app.agent.gateway_deny), Color::Yellow),
            kv("Require approval", fmt_num(app.agent.gateway_require_approval), Color::Yellow),
            kv("Shadow deny", fmt_num(app.agent.gateway_shadow_deny), Color::Cyan),
            kv("Replay rejected", fmt_num(app.agent.approval_replay_rejected), if app.agent.approval_replay_rejected > 0 { Color::Red } else { Color::Green }),
            kv("Approval flood", fmt_num(app.agent.approval_capacity_rejected), if app.agent.approval_capacity_rejected > 0 { Color::Red } else { Color::Green }),
            kv("Policy errors", fmt_num(app.agent.policy_errors), if app.agent.policy_errors > 0 { Color::Red } else { Color::Green }),
            kv("Evidence errors", fmt_num(app.agent.evidence_errors), if app.agent.evidence_errors > 0 { Color::Red } else { Color::Green }),
            kv("Upstream errors", fmt_num(app.agent.upstream_errors), if app.agent.upstream_errors > 0 { Color::Yellow } else { Color::Green }),
        ])
        .block(Block::default().borders(Borders::ALL).title(" ATTACK / ENFORCEMENT COUNTERS "))
        .wrap(Wrap { trim: true }),
        columns[1],
    );

    let rows = app.agent.redteam_events.iter().take(30).map(|event| {
        Row::new(vec![
            event.lsn.to_string(),
            short_id(&event.attack_id),
            event.vector.clone(),
            event.target.clone(),
            event.phase.clone(),
            event.result.clone(),
            if event.blocked { "BLOCKED" } else { "OPEN" }.to_string(),
            event.upstream_delta.to_string(),
            event.reason_code.clone(),
        ])
        .style(Style::default().fg(if event.upstream_delta > 0 {
            Color::Red
        } else if event.blocked {
            Color::Green
        } else {
            Color::Yellow
        }))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Length(13),
            Constraint::Length(20),
            Constraint::Length(18),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Min(15),
        ],
    )
    .header(
        Row::new([
            "LSN", "ATTACK", "VECTOR", "TARGET", "PHASE", "RESULT", "BLOCK", "UPSTREAM", "REASON",
        ])
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(
        " RED-TEAM LAB EVIDENCE — LAB TELEMETRY, NOT PRODUCTION ATTACK ATTRIBUTION ",
    ));
    frame.render_widget(table, vertical[2]);
}

fn render_indexes(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    frame.render_widget(
        Paragraph::new(vec![
            kv("Vector", fmt_num(app.indexes.vector_indexed), Color::Cyan),
            kv("Text", fmt_num(app.indexes.text_indexed), Color::Cyan),
            kv("Graph nodes", fmt_num(app.indexes.graph_nodes), Color::Cyan),
            kv("Temporal edges", fmt_num(app.indexes.tgraph_edges), Color::Cyan),
            kv("Entity keys", fmt_num(app.indexes.entity_keys), Color::Cyan),
            kv("Activation tracked", fmt_num(app.indexes.activation_tracked), Color::Cyan),
            Line::from(""),
            Line::from(Span::styled(
                if app.active_views.is_empty() {
                    "No views reported".into()
                } else {
                    app.active_views.join(" │ ")
                },
                Style::default().fg(Color::Green),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title(" INDEXES / VIEWS ")),
        area,
    );
}

fn render_chart(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
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
        .max(10.0);
    let max_x = (app.rate_history.len().max(2) - 1) as f64;
    let dataset = Dataset::default()
        .name("evt/s")
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::Cyan))
        .data(&data);
    frame.render_widget(
        Chart::new(vec![dataset])
            .block(Block::default().borders(Borders::ALL).title(" INGESTION RATE "))
            .x_axis(Axis::default().bounds([0.0, max_x]))
            .y_axis(Axis::default().bounds([0.0, max_y * 1.1])),
        area,
    );
}

fn render_footer(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let alarms = app.alarms();
    let (posture_label, posture_color) = posture(&alarms);
    let line = Line::from(vec![
        Span::styled(
            if app.paused { " PAUSED " } else { " RUNNING " },
            Style::default()
                .fg(Color::Black)
                .bg(if app.paused {
                    Color::Yellow
                } else if app.online {
                    Color::Green
                } else {
                    Color::Red
                })
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Core: "),
        Span::styled(app.target_url.clone(), Style::default().fg(Color::Cyan)),
        Span::raw(" | Agent: "),
        Span::styled(app.agent_url.clone(), Style::default().fg(Color::Magenta)),
        Span::raw(" | Security: "),
        Span::styled(
            posture_label,
            Style::default()
                .fg(posture_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            " | refresh {:.2}s | Tab/1-8 | u refresh | p pause | ? help | q sair",
            app.interval_sec
        )),
    ]);
    frame.render_widget(
        Paragraph::new(line).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn render_help(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let popup = centered_rect(82, 78, area);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from("1..8  abas"),
            Line::from("Tab / Shift+Tab  próxima/anterior"),
            Line::from("p / espaço  pausa"),
            Line::from("u  força refresh"),
            Line::from("+ / -  frequência"),
            Line::from("q / Esc / Ctrl+C  sair"),
            Line::from(""),
            Line::from(Span::styled(
                "Alarm strip usa Sentinel + HRKL + compliance + Agent Gateway + red-team lab.",
                Style::default().fg(Color::Yellow),
            )),
            Line::from("HERACLITUS_AGENT_URL=http://host:8080 força o endpoint Agent."),
            Line::from("HERACLITUS_AGENT_BASIC_AUTH=user:pass configura Basic separado do Core."),
            Line::from("HERACLITUS_AGENT_AUTHORIZATION='Bearer ...' permite OIDC sem reutilizar credencial Core."),
            Line::from(Span::styled(
                "Red-team lab é identificado como LAB; o painel não atribui automaticamente isso a ataque real.",
                Style::default().fg(Color::Cyan),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title(" HELP ")),
        popup,
    );
}

fn metric_box(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    title: &str,
    value: &str,
    color: Color,
) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            value.to_string(),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(format!(" {title} "))),
        area,
    );
}

fn kv(label: &str, value: impl Into<String>, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:<22}"),
            Style::default().fg(Color::Gray),
        ),
        Span::styled(
            value.into(),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ])
}

fn threat_color(value: &str) -> Color {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Color::Red,
        "elevated" => Color::Yellow,
        "normal" => Color::Green,
        _ => Color::Gray,
    }
}

fn gateway_color(value: &str) -> Color {
    match value.to_ascii_uppercase().as_str() {
        "ENFORCE" => Color::Green,
        "SHADOW" => Color::Yellow,
        "OBSERVE" => Color::Cyan,
        "DISABLED" => Color::Gray,
        _ => Color::Gray,
    }
}

fn state_color(value: &str) -> Color {
    match value.to_ascii_uppercase().as_str() {
        "HEALTHY" | "CONFIGURED" | "ENABLED" | "ACTIVE" => Color::Green,
        "DEGRADED" | "UNKNOWN" => Color::Yellow,
        "FAILED" | "BROKEN" => Color::Red,
        "DISABLED" => Color::Gray,
        _ => Color::Cyan,
    }
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

fn opt_num(value: Option<u64>) -> String {
    value.map(fmt_num).unwrap_or_else(|| "N/D".into())
}

fn fmt_num(number: u64) -> String {
    let text = number.to_string();
    let mut out = String::new();
    for (index, character) in text.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            out.push('.');
        }
        out.push(character);
    }
    out.chars().rev().collect()
}

fn fmt_bytes(number: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = number as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}
