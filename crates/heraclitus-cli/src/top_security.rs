use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum AlarmSeverity {
    Info,
    Warning,
    Critical,
}

impl AlarmSeverity {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Critical => "CRITICAL",
        }
    }

    pub(super) fn color(self) -> Color {
        match self {
            Self::Info => Color::Cyan,
            Self::Warning => Color::Yellow,
            Self::Critical => Color::Red,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct SecurityAlarm {
    pub(super) severity: AlarmSeverity,
    pub(super) source: String,
    pub(super) code: String,
    pub(super) title: String,
    pub(super) detail: String,
}

#[derive(Debug, Clone, Default)]
pub(super) struct IncidentRow {
    pub(super) id: String,
    pub(super) state: String,
    pub(super) severity: u8,
    pub(super) risk: f64,
    pub(super) subject: String,
    pub(super) mitre: String,
    pub(super) first_lsn: u64,
    pub(super) last_lsn: u64,
}

#[derive(Debug, Clone, Default)]
pub(super) struct SecurityDashboardSnapshot {
    pub(super) available: bool,
    pub(super) threat_level: String,
    pub(super) active_incidents: u64,
    pub(super) critical_incidents: u64,
    pub(super) pending_approvals: u64,
    pub(super) incidents: Vec<IncidentRow>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct RedTeamEvent {
    pub(super) lsn: u64,
    pub(super) observed_at_unix_nanos: u64,
    pub(super) attack_id: String,
    pub(super) campaign_id: String,
    pub(super) vector: String,
    pub(super) target: String,
    pub(super) phase: String,
    pub(super) result: String,
    pub(super) reason_code: String,
    pub(super) blocked: bool,
    pub(super) upstream_delta: i64,
    pub(super) transport_status: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct AgentSecuritySnapshot {
    pub(super) available: bool,
    pub(super) last_error: String,
    pub(super) latency_ms: f64,
    pub(super) auth: String,
    pub(super) auth_identifies_people: Option<bool>,
    pub(super) evidence_log: String,
    pub(super) otlp_ingest: String,
    pub(super) mcp_gateway: String,
    pub(super) bypass_protection: String,
    pub(super) rfc3161: String,
    pub(super) policy_id: String,
    pub(super) policy_version: String,
    pub(super) policy_lifecycle: String,
    pub(super) policy_rules: u64,
    pub(super) capture_mode: String,
    pub(super) runs: u64,
    pub(super) tool_calls: u64,
    pub(super) denied: u64,
    pub(super) pending_approvals: u64,
    pub(super) integrity: String,
    pub(super) ingest_events: u64,
    pub(super) ingest_duplicates: u64,
    pub(super) ingest_conflicts: u64,
    pub(super) ingest_rejected: u64,
    pub(super) ignored_spans: u64,
    pub(super) batches: u64,
    pub(super) bytes: u64,
    pub(super) gateway_requests: u64,
    pub(super) gateway_allow: u64,
    pub(super) gateway_deny: u64,
    pub(super) gateway_require_approval: u64,
    pub(super) gateway_shadow_deny: u64,
    pub(super) approval_expired: u64,
    pub(super) approval_replay_rejected: u64,
    pub(super) approval_capacity_rejected: u64,
    pub(super) policy_errors: u64,
    pub(super) evidence_errors: u64,
    pub(super) upstream_errors: u64,
    pub(super) delta_deny: u64,
    pub(super) delta_shadow_deny: u64,
    pub(super) delta_replay: u64,
    pub(super) delta_capacity_rejected: u64,
    pub(super) delta_policy_errors: u64,
    pub(super) delta_evidence_errors: u64,
    pub(super) delta_upstream_errors: u64,
    pub(super) redteam_available: bool,
    pub(super) redteam_returned: u64,
    pub(super) redteam_blocked: u64,
    pub(super) redteam_reached_upstream: u64,
    pub(super) redteam_new_events: u64,
    pub(super) redteam_new_upstream: u64,
    pub(super) redteam_max_lsn: u64,
    pub(super) redteam_events: Vec<RedTeamEvent>,
}

pub(super) struct AlarmInputs<'a> {
    pub(super) online: bool,
    pub(super) grpc_reachable: Option<bool>,
    pub(super) threat_level: &'a str,
    pub(super) incidents: &'a [IncidentRow],
    pub(super) sentinel_lag_state: &'a str,
    pub(super) detection_lag_lsn: u64,
    pub(super) queue_overflow_total: u64,
    pub(super) incident_capacity_drops_total: u64,
    pub(super) normalization_errors_total: u64,
    pub(super) action_failures_total: u64,
    pub(super) ai_circuit_state: &'a str,
    pub(super) canonical_verify_failures: u64,
    pub(super) physical_crc_failures: u64,
    pub(super) parquet_export_lag_lsn: u64,
    pub(super) deferred_anchor_forks: u64,
    pub(super) deadline_overdue: u64,
    pub(super) pending_anpd: u64,
    pub(super) agent_expected: bool,
    pub(super) agent: &'a AgentSecuritySnapshot,
}

pub(super) fn parse_dashboard(value: &Value) -> SecurityDashboardSnapshot {
    let incidents = value
        .get("incidents")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().map(parse_incident).collect())
        .unwrap_or_default();

    SecurityDashboardSnapshot {
        available: true,
        threat_level: string_at(value, "threat_level").unwrap_or_else(|| "unknown".into()),
        active_incidents: u64_at(value, "active_incidents"),
        critical_incidents: u64_at(value, "critical_incidents"),
        pending_approvals: u64_at(value, "pending_approvals"),
        incidents,
    }
}

pub(super) fn parse_agent_status(
    value: &Value,
    latency_ms: f64,
    previous: &AgentSecuritySnapshot,
) -> AgentSecuritySnapshot {
    let gateway = value.get("gateway").unwrap_or(&Value::Null);
    let ingest = value.get("ingest").unwrap_or(&Value::Null);
    let summary = value.get("summary").unwrap_or(&Value::Null);
    let policy = value.get("policy").unwrap_or(&Value::Null);
    let capture = value.get("capture").unwrap_or(&Value::Null);

    let gateway_deny = u64_at(gateway, "deny");
    let gateway_shadow_deny = u64_at(gateway, "shadow_deny");
    let approval_replay_rejected = u64_at(gateway, "approval_replay_rejected");
    let approval_capacity_rejected = u64_at(gateway, "approval_capacity_rejected");
    let policy_errors = u64_at(gateway, "policy_errors");
    let evidence_errors = u64_at(gateway, "evidence_errors");
    let upstream_errors = u64_at(gateway, "upstream_errors");
    let had_previous = previous.available;

    AgentSecuritySnapshot {
        available: true,
        last_error: String::new(),
        latency_ms,
        auth: string_at(value, "auth").unwrap_or_else(|| "unknown".into()),
        auth_identifies_people: value.get("auth_identifies_people").and_then(Value::as_bool),
        evidence_log: string_at(value, "evidence_log").unwrap_or_else(|| "UNKNOWN".into()),
        otlp_ingest: string_at(value, "otlp_ingest").unwrap_or_else(|| "UNKNOWN".into()),
        mcp_gateway: string_at(value, "mcp_gateway").unwrap_or_else(|| "UNKNOWN".into()),
        bypass_protection: string_at(value, "bypass_protection").unwrap_or_else(|| "UNKNOWN".into()),
        rfc3161: string_at(value, "rfc3161").unwrap_or_else(|| "UNKNOWN".into()),
        policy_id: string_at(policy, "id").unwrap_or_default(),
        policy_version: string_at(policy, "version").unwrap_or_default(),
        policy_lifecycle: string_at(policy, "lifecycle").unwrap_or_default(),
        policy_rules: u64_at(policy, "rules"),
        capture_mode: string_at(capture, "mode").unwrap_or_else(|| "UNKNOWN".into()),
        runs: u64_at(summary, "runs"),
        tool_calls: u64_at(summary, "tool_calls"),
        denied: u64_at(summary, "denied"),
        pending_approvals: u64_at(summary, "pending_approvals"),
        integrity: string_at(summary, "integrity").unwrap_or_else(|| "UNKNOWN".into()),
        ingest_events: u64_at(ingest, "events"),
        ingest_duplicates: u64_at(ingest, "duplicates"),
        ingest_conflicts: u64_at(ingest, "conflicts"),
        ingest_rejected: u64_at(ingest, "rejected"),
        ignored_spans: u64_at(ingest, "ignored_spans"),
        batches: u64_at(ingest, "batches"),
        bytes: u64_at(ingest, "bytes"),
        gateway_requests: u64_at(gateway, "requests"),
        gateway_allow: u64_at(gateway, "allow"),
        gateway_deny,
        gateway_require_approval: u64_at(gateway, "require_approval"),
        gateway_shadow_deny,
        approval_expired: u64_at(gateway, "approval_expired"),
        approval_replay_rejected,
        approval_capacity_rejected,
        policy_errors,
        evidence_errors,
        upstream_errors,
        delta_deny: delta(had_previous, gateway_deny, previous.gateway_deny),
        delta_shadow_deny: delta(had_previous, gateway_shadow_deny, previous.gateway_shadow_deny),
        delta_replay: delta(
            had_previous,
            approval_replay_rejected,
            previous.approval_replay_rejected,
        ),
        delta_capacity_rejected: delta(
            had_previous,
            approval_capacity_rejected,
            previous.approval_capacity_rejected,
        ),
        delta_policy_errors: delta(had_previous, policy_errors, previous.policy_errors),
        delta_evidence_errors: delta(had_previous, evidence_errors, previous.evidence_errors),
        delta_upstream_errors: delta(had_previous, upstream_errors, previous.upstream_errors),
        redteam_available: previous.redteam_available,
        redteam_returned: previous.redteam_returned,
        redteam_blocked: previous.redteam_blocked,
        redteam_reached_upstream: previous.redteam_reached_upstream,
        redteam_new_events: 0,
        redteam_new_upstream: 0,
        redteam_max_lsn: previous.redteam_max_lsn,
        redteam_events: previous.redteam_events.clone(),
    }
}

pub(super) fn apply_redteam(snapshot: &mut AgentSecuritySnapshot, value: &Value) {
    let summary = value.get("summary").unwrap_or(&Value::Null);
    let old_max_lsn = snapshot.redteam_max_lsn;
    let had_previous = snapshot.redteam_available;
    let mut events = Vec::new();
    let mut new_events = 0u64;
    let mut new_upstream = 0u64;
    let mut max_lsn = old_max_lsn;

    if let Some(rows) = value.get("events").and_then(Value::as_array) {
        for row in rows {
            let event = parse_redteam_event(row);
            if had_previous && event.lsn > old_max_lsn {
                new_events += 1;
                if event.upstream_delta > 0 {
                    new_upstream += 1;
                }
            }
            max_lsn = max_lsn.max(event.lsn);
            events.push(event);
        }
    }

    snapshot.redteam_available = true;
    snapshot.redteam_returned = u64_at(summary, "returned");
    snapshot.redteam_blocked = u64_at(summary, "blocked");
    snapshot.redteam_reached_upstream = u64_at(summary, "reached_upstream");
    snapshot.redteam_new_events = new_events;
    snapshot.redteam_new_upstream = new_upstream;
    snapshot.redteam_max_lsn = max_lsn;
    snapshot.redteam_events = events;
}

pub(super) fn derive_alarms(input: &AlarmInputs<'_>) -> Vec<SecurityAlarm> {
    let mut alarms = Vec::new();

    if !input.online {
        alarms.push(alarm(
            AlarmSeverity::Critical,
            "transport",
            "REST_OFFLINE",
            "REST indisponível",
            "Não foi possível consultar /stats; o estado do banco não pode ser confirmado.",
        ));
    }
    if matches!(input.grpc_reachable, Some(false)) {
        alarms.push(alarm(
            AlarmSeverity::Warning,
            "transport",
            "GRPC_UNREACHABLE",
            "gRPC :7474 indisponível",
            "A porta gRPC não respondeu ao probe TCP.",
        ));
    }

    match input.threat_level.to_ascii_lowercase().as_str() {
        "critical" => alarms.push(alarm(
            AlarmSeverity::Critical,
            "sentinel",
            "THREAT_LEVEL_CRITICAL",
            "Nível de ameaça CRÍTICO",
            "O /sentinel/dashboard reportou threat_level=critical.",
        )),
        "elevated" => alarms.push(alarm(
            AlarmSeverity::Warning,
            "sentinel",
            "THREAT_LEVEL_ELEVATED",
            "Nível de ameaça elevado",
            "Há incidentes ativos no Sentinel.",
        )),
        _ => {}
    }

    for incident in input.incidents {
        if matches!(incident.state.as_str(), "Resolved" | "FalsePositive") {
            continue;
        }
        let severity = if incident.severity >= 8 {
            AlarmSeverity::Critical
        } else if incident.severity >= 5 {
            AlarmSeverity::Warning
        } else {
            AlarmSeverity::Info
        };
        alarms.push(alarm(
            severity,
            "sentinel",
            "SECURITY_INCIDENT",
            &format!("Incidente S{} {}", incident.severity, short_id(&incident.id)),
            &format!(
                "state={} risk={:.2} subject={} MITRE={} LSN {}..{}",
                incident.state,
                incident.risk,
                incident.subject,
                incident.mitre,
                incident.first_lsn,
                incident.last_lsn
            ),
        ));
    }

    let lag = input.sentinel_lag_state.to_ascii_lowercase();
    if lag == "critical" {
        alarms.push(alarm(
            AlarmSeverity::Critical,
            "sentinel",
            "DETECTION_LAG_CRITICAL",
            "Sentinel com lag crítico",
            &format!("detection_lag_lsn={}", input.detection_lag_lsn),
        ));
    } else if input.detection_lag_lsn > 0
        || matches!(lag.as_str(), "degraded" | "catchingup" | "catching_up")
    {
        alarms.push(alarm(
            AlarmSeverity::Warning,
            "sentinel",
            "DETECTION_LAG",
            "Sentinel atrasado",
            &format!(
                "state={} detection_lag_lsn={}",
                input.sentinel_lag_state, input.detection_lag_lsn
            ),
        ));
    }

    critical_counter(
        &mut alarms,
        "sentinel",
        "QUEUE_OVERFLOW",
        "Overflow da fila Sentinel",
        input.queue_overflow_total,
    );
    critical_counter(
        &mut alarms,
        "sentinel",
        "INCIDENT_CAPACITY_DROP",
        "Incidentes descartados por capacidade",
        input.incident_capacity_drops_total,
    );
    critical_counter(
        &mut alarms,
        "sentinel",
        "ACTION_FAILURE",
        "Falhas na execução de ações",
        input.action_failures_total,
    );
    warning_counter(
        &mut alarms,
        "sentinel",
        "NORMALIZATION_ERROR",
        "Erros de normalização",
        input.normalization_errors_total,
    );

    if !input.ai_circuit_state.is_empty()
        && !matches!(
            input.ai_circuit_state.to_ascii_lowercase().as_str(),
            "closed" | "healthy" | "disabled"
        )
    {
        alarms.push(alarm(
            AlarmSeverity::Warning,
            "sentinel-ai",
            "AI_CIRCUIT",
            "Circuit breaker da IA não está fechado",
            &format!("state={}", input.ai_circuit_state),
        ));
    }

    critical_counter(
        &mut alarms,
        "storage",
        "CANONICAL_VERIFY_FAILURE",
        "Falha de integridade canônica",
        input.canonical_verify_failures,
    );
    critical_counter(
        &mut alarms,
        "storage",
        "CRC_FAILURE",
        "Falha física CRC",
        input.physical_crc_failures,
    );
    warning_counter(
        &mut alarms,
        "storage",
        "PARQUET_EXPORT_LAG",
        "Lakehouse export atrasado",
        input.parquet_export_lag_lsn,
    );
    critical_counter(
        &mut alarms,
        "compliance",
        "ANCHOR_FORK",
        "Fork em âncora de compliance",
        input.deferred_anchor_forks,
    );
    warning_counter(
        &mut alarms,
        "compliance",
        "DEADLINE_OVERDUE",
        "Prazos regulatórios vencidos",
        input.deadline_overdue,
    );
    warning_counter(
        &mut alarms,
        "compliance",
        "ANPD_PENDING",
        "Pendências ANPD",
        input.pending_anpd,
    );

    derive_agent_alarms(&mut alarms, input.agent_expected, input.agent);

    alarms.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.code.cmp(&b.code))
    });
    alarms
}

fn derive_agent_alarms(
    alarms: &mut Vec<SecurityAlarm>,
    agent_expected: bool,
    agent: &AgentSecuritySnapshot,
) {
    if !agent.available {
        if agent_expected {
            alarms.push(alarm(
                AlarmSeverity::Warning,
                "agent",
                "AGENT_TELEMETRY_BLIND",
                "Agent control plane sem telemetria",
                if agent.last_error.is_empty() {
                    "A API Agent foi configurada, mas não respondeu."
                } else {
                    &agent.last_error
                },
            ));
        }
        return;
    }

    if !agent.evidence_log.eq_ignore_ascii_case("HEALTHY") {
        alarms.push(alarm(
            AlarmSeverity::Critical,
            "agent",
            "EVIDENCE_LOG_DEGRADED",
            "Evidence log do Agent degradado",
            &format!("state={}", agent.evidence_log),
        ));
    }

    if agent.mcp_gateway.eq_ignore_ascii_case("ENFORCE")
        && !agent.bypass_protection.eq_ignore_ascii_case("CONFIGURED")
    {
        alarms.push(alarm(
            AlarmSeverity::Warning,
            "gateway",
            "BYPASS_PROTECTION_UNKNOWN",
            "Gateway ENFORCE sem proteção de bypass confirmada",
            &format!("bypass_protection={}", agent.bypass_protection),
        ));
    }

    if agent.delta_evidence_errors > 0 || agent.evidence_errors > 0 {
        alarms.push(alarm(
            AlarmSeverity::Critical,
            "gateway",
            "EVIDENCE_WRITE_FAILURE",
            "Falha ao registrar evidência do gateway",
            &format!(
                "new={} total={}",
                agent.delta_evidence_errors, agent.evidence_errors
            ),
        ));
    }

    if agent.delta_replay > 0 {
        alarms.push(alarm(
            AlarmSeverity::Critical,
            "gateway",
            "APPROVAL_REPLAY_ATTEMPT",
            "Tentativa de replay de aprovação bloqueada",
            &format!(
                "new={} total={}",
                agent.delta_replay, agent.approval_replay_rejected
            ),
        ));
    } else if agent.approval_replay_rejected > 0 {
        alarms.push(alarm(
            AlarmSeverity::Info,
            "gateway",
            "APPROVAL_REPLAY_HISTORY",
            "Há replays de aprovação no histórico",
            &format!("total={}", agent.approval_replay_rejected),
        ));
    }

    if agent.delta_capacity_rejected >= 10 {
        alarms.push(alarm(
            AlarmSeverity::Critical,
            "gateway",
            "APPROVAL_FLOOD",
            "Flood de aprovações contido",
            &format!(
                "new_rejected={} total={}",
                agent.delta_capacity_rejected, agent.approval_capacity_rejected
            ),
        ));
    } else if agent.delta_capacity_rejected > 0 {
        alarms.push(alarm(
            AlarmSeverity::Warning,
            "gateway",
            "APPROVAL_CAPACITY_REJECTED",
            "Fila de aprovação recusou novas entradas",
            &format!(
                "new={} total={}",
                agent.delta_capacity_rejected, agent.approval_capacity_rejected
            ),
        ));
    }

    if agent.delta_deny >= 100 {
        alarms.push(alarm(
            AlarmSeverity::Critical,
            "gateway",
            "DENY_STORM",
            "Tempestade de ações bloqueadas",
            &format!("new_denies={} total={}", agent.delta_deny, agent.gateway_deny),
        ));
    } else if agent.delta_deny > 0 {
        alarms.push(alarm(
            AlarmSeverity::Warning,
            "gateway",
            "ACTION_BLOCKED",
            "Ação de agente bloqueada pela policy",
            &format!("new={} total={}", agent.delta_deny, agent.gateway_deny),
        ));
    }

    if agent.delta_shadow_deny > 0 {
        alarms.push(alarm(
            AlarmSeverity::Info,
            "gateway",
            "SHADOW_DENY",
            "Policy teria bloqueado ação em shadow",
            &format!(
                "new={} total={}",
                agent.delta_shadow_deny, agent.gateway_shadow_deny
            ),
        ));
    }

    if agent.delta_policy_errors > 0 || agent.policy_errors > 0 {
        alarms.push(alarm(
            AlarmSeverity::Critical,
            "gateway",
            "POLICY_ERROR",
            "Erro no plano de policy",
            &format!("new={} total={}", agent.delta_policy_errors, agent.policy_errors),
        ));
    }

    if agent.delta_upstream_errors > 0 {
        alarms.push(alarm(
            AlarmSeverity::Warning,
            "gateway",
            "UPSTREAM_ERROR",
            "Falha ao comunicar com upstream MCP",
            &format!(
                "new={} total={}",
                agent.delta_upstream_errors, agent.upstream_errors
            ),
        ));
    }

    if agent.ingest_conflicts > 0 {
        alarms.push(alarm(
            AlarmSeverity::Warning,
            "agent",
            "INGEST_CONFLICT",
            "Conflitos de deduplicação na ingestão Agent",
            &format!("total={}", agent.ingest_conflicts),
        ));
    }

    if agent.redteam_new_upstream > 0 {
        alarms.push(alarm(
            AlarmSeverity::Critical,
            "redteam-lab",
            "LAB_PROBE_REACHED_UPSTREAM",
            "Probe adversarial alcançou o upstream",
            &format!(
                "new={} returned={} reached_upstream={}",
                agent.redteam_new_upstream,
                agent.redteam_returned,
                agent.redteam_reached_upstream
            ),
        ));
    } else if agent.redteam_new_events > 0 {
        alarms.push(alarm(
            AlarmSeverity::Info,
            "redteam-lab",
            "LAB_PROBE_ACTIVITY",
            "Nova atividade do Agent-Atack-Heraclitus",
            &format!(
                "new={} blocked={} returned={}",
                agent.redteam_new_events, agent.redteam_blocked, agent.redteam_returned
            ),
        ));
    }
}

pub(super) fn posture(alarms: &[SecurityAlarm]) -> (&'static str, Color) {
    if alarms
        .iter()
        .any(|alarm| alarm.severity == AlarmSeverity::Critical)
    {
        ("CRITICAL", Color::Red)
    } else if alarms
        .iter()
        .any(|alarm| alarm.severity == AlarmSeverity::Warning)
    {
        ("ELEVATED", Color::Yellow)
    } else {
        ("NORMAL", Color::Green)
    }
}

pub(super) fn alarm_line(alarm: &SecurityAlarm) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {:<8} ", alarm.severity.label()),
            Style::default()
                .fg(Color::Black)
                .bg(alarm.severity.color())
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{:<12}", alarm.source),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(" "),
        Span::styled(
            alarm.title.clone(),
            Style::default()
                .fg(alarm.severity.color())
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(alarm.detail.clone(), Style::default().fg(Color::Gray)),
    ])
}

pub(super) fn short_id(id: &str) -> String {
    if id.chars().count() <= 12 {
        id.to_string()
    } else {
        id.chars().take(12).collect()
    }
}

fn parse_incident(value: &Value) -> IncidentRow {
    let subject = value
        .get("subjects")
        .and_then(Value::as_array)
        .and_then(|subjects| subjects.first())
        .map(render_subject)
        .unwrap_or_else(|| "N/D".into());
    let mitre = value
        .get("mitre")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("technique_id").and_then(Value::as_str))
                .take(3)
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "-".into());

    IncidentRow {
        id: string_at(value, "incident_id").unwrap_or_else(|| "unknown".into()),
        state: string_at(value, "state").unwrap_or_else(|| "Unknown".into()),
        severity: u64_at(value, "severity") as u8,
        risk: value.get("risk_score").and_then(Value::as_f64).unwrap_or(0.0),
        subject,
        mitre,
        first_lsn: u64_at(value, "first_seen_lsn"),
        last_lsn: u64_at(value, "last_seen_lsn"),
    }
}

fn parse_redteam_event(value: &Value) -> RedTeamEvent {
    RedTeamEvent {
        lsn: u64_at(value, "lsn"),
        observed_at_unix_nanos: u64_at(value, "observed_at_unix_nanos"),
        attack_id: string_at(value, "attack_id").unwrap_or_default(),
        campaign_id: string_at(value, "campaign_id").unwrap_or_default(),
        vector: string_at(value, "vector").unwrap_or_default(),
        target: string_at(value, "target").unwrap_or_default(),
        phase: string_at(value, "phase").unwrap_or_default(),
        result: string_at(value, "result").unwrap_or_default(),
        reason_code: string_at(value, "reason_code").unwrap_or_default(),
        blocked: value.get("blocked").and_then(Value::as_bool).unwrap_or(false),
        upstream_delta: value
            .get("upstream_delta")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        transport_status: value.get("transport_status").and_then(Value::as_i64),
    }
}

fn render_subject(value: &Value) -> String {
    let kind = value.get("kind").and_then(Value::as_str).unwrap_or("entity");
    let id = value.get("id").and_then(Value::as_str).unwrap_or("?");
    format!("{kind}:{id}")
}

fn delta(had_previous: bool, current: u64, previous: u64) -> u64 {
    if had_previous {
        current.saturating_sub(previous)
    } else {
        0
    }
}

fn critical_counter(
    alarms: &mut Vec<SecurityAlarm>,
    source: &str,
    code: &str,
    title: &str,
    value: u64,
) {
    if value > 0 {
        alarms.push(alarm(
            AlarmSeverity::Critical,
            source,
            code,
            title,
            &format!("contador={value}"),
        ));
    }
}

fn warning_counter(
    alarms: &mut Vec<SecurityAlarm>,
    source: &str,
    code: &str,
    title: &str,
    value: u64,
) {
    if value > 0 {
        alarms.push(alarm(
            AlarmSeverity::Warning,
            source,
            code,
            title,
            &format!("contador={value}"),
        ));
    }
}

fn alarm(
    severity: AlarmSeverity,
    source: &str,
    code: &str,
    title: &str,
    detail: &str,
) -> SecurityAlarm {
    SecurityAlarm {
        severity,
        source: source.into(),
        code: code.into(),
        title: title.into(),
        detail: detail.into(),
    }
}

fn string_at(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn u64_at(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(|item| {
            item.as_u64()
                .or_else(|| item.as_i64().and_then(|number| (number >= 0).then_some(number as u64)))
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_agent() -> AgentSecuritySnapshot {
        AgentSecuritySnapshot::default()
    }

    #[test]
    fn critical_integrity_never_becomes_green() {
        let agent = empty_agent();
        let alarms = derive_alarms(&AlarmInputs {
            online: true,
            grpc_reachable: Some(true),
            threat_level: "normal",
            incidents: &[],
            sentinel_lag_state: "healthy",
            detection_lag_lsn: 0,
            queue_overflow_total: 0,
            incident_capacity_drops_total: 0,
            normalization_errors_total: 0,
            action_failures_total: 0,
            ai_circuit_state: "closed",
            canonical_verify_failures: 1,
            physical_crc_failures: 0,
            parquet_export_lag_lsn: 0,
            deferred_anchor_forks: 0,
            deadline_overdue: 0,
            pending_anpd: 0,
            agent_expected: false,
            agent: &agent,
        });
        assert_eq!(posture(&alarms).0, "CRITICAL");
        assert!(alarms
            .iter()
            .any(|alarm| alarm.code == "CANONICAL_VERIFY_FAILURE"));
    }

    #[test]
    fn new_approval_replay_is_critical() {
        let agent = AgentSecuritySnapshot {
            available: true,
            evidence_log: "HEALTHY".into(),
            mcp_gateway: "ENFORCE".into(),
            bypass_protection: "CONFIGURED".into(),
            delta_replay: 1,
            approval_replay_rejected: 1,
            ..Default::default()
        };
        let alarms = derive_alarms(&AlarmInputs {
            online: true,
            grpc_reachable: Some(true),
            threat_level: "normal",
            incidents: &[],
            sentinel_lag_state: "healthy",
            detection_lag_lsn: 0,
            queue_overflow_total: 0,
            incident_capacity_drops_total: 0,
            normalization_errors_total: 0,
            action_failures_total: 0,
            ai_circuit_state: "closed",
            canonical_verify_failures: 0,
            physical_crc_failures: 0,
            parquet_export_lag_lsn: 0,
            deferred_anchor_forks: 0,
            deadline_overdue: 0,
            pending_anpd: 0,
            agent_expected: true,
            agent: &agent,
        });
        assert!(alarms.iter().any(|alarm| {
            alarm.code == "APPROVAL_REPLAY_ATTEMPT"
                && alarm.severity == AlarmSeverity::Critical
        }));
    }

    #[test]
    fn redteam_upstream_escape_is_critical() {
        let agent = AgentSecuritySnapshot {
            available: true,
            evidence_log: "HEALTHY".into(),
            redteam_new_upstream: 1,
            redteam_reached_upstream: 1,
            redteam_returned: 1,
            ..Default::default()
        };
        let alarms = derive_alarms(&AlarmInputs {
            online: true,
            grpc_reachable: Some(true),
            threat_level: "normal",
            incidents: &[],
            sentinel_lag_state: "healthy",
            detection_lag_lsn: 0,
            queue_overflow_total: 0,
            incident_capacity_drops_total: 0,
            normalization_errors_total: 0,
            action_failures_total: 0,
            ai_circuit_state: "closed",
            canonical_verify_failures: 0,
            physical_crc_failures: 0,
            parquet_export_lag_lsn: 0,
            deferred_anchor_forks: 0,
            deadline_overdue: 0,
            pending_anpd: 0,
            agent_expected: true,
            agent: &agent,
        });
        assert!(alarms.iter().any(|alarm| {
            alarm.code == "LAB_PROBE_REACHED_UPSTREAM"
                && alarm.severity == AlarmSeverity::Critical
        }));
    }
}
