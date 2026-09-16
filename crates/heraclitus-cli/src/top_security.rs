use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlarmSeverity {
    Info,
    Warning,
    Critical,
}

impl AlarmSeverity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn color(self) -> Color {
        match self {
            Self::Info => Color::Cyan,
            Self::Warning => Color::Yellow,
            Self::Critical => Color::Red,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityAlarm {
    pub severity: AlarmSeverity,
    pub source: String,
    pub code: String,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct IncidentRow {
    pub id: String,
    pub state: String,
    pub severity: u8,
    pub risk: f64,
    pub subject: String,
    pub mitre: String,
    pub first_lsn: u64,
    pub last_lsn: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityDashboardSnapshot {
    pub available: bool,
    pub threat_level: String,
    pub active_incidents: u64,
    pub critical_incidents: u64,
    pub pending_approvals: u64,
    pub incidents: Vec<IncidentRow>,
}

pub fn parse_dashboard(value: &Value) -> SecurityDashboardSnapshot {
    let incidents = value
        .get("incidents")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().map(parse_incident).collect())
        .unwrap_or_default();

    SecurityDashboardSnapshot {
        available: true,
        threat_level: value
            .get("threat_level")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        active_incidents: value
            .get("active_incidents")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        critical_incidents: value
            .get("critical_incidents")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        pending_approvals: value
            .get("pending_approvals")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        incidents,
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
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "-".into());

    IncidentRow {
        id: value
            .get("incident_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        state: value
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("Unknown")
            .to_string(),
        severity: value.get("severity").and_then(Value::as_u64).unwrap_or(0) as u8,
        risk: value.get("risk_score").and_then(Value::as_f64).unwrap_or(0.0),
        subject,
        mitre,
        first_lsn: value.get("first_seen_lsn").and_then(Value::as_u64).unwrap_or(0),
        last_lsn: value.get("last_seen_lsn").and_then(Value::as_u64).unwrap_or(0),
    }
}

fn render_subject(value: &Value) -> String {
    let kind = value.get("kind").and_then(Value::as_str).unwrap_or("entity");
    let id = value.get("id").and_then(Value::as_str).unwrap_or("?");
    format!("{kind}:{id}")
}

#[allow(clippy::too_many_arguments)]
pub fn derive_alarms(
    online: bool,
    grpc_reachable: Option<bool>,
    threat_level: &str,
    incidents: &[IncidentRow],
    sentinel_lag_state: &str,
    detection_lag_lsn: u64,
    queue_overflow_total: u64,
    incident_capacity_drops_total: u64,
    normalization_errors_total: u64,
    action_failures_total: u64,
    ai_circuit_state: &str,
    canonical_verify_failures: u64,
    physical_crc_failures: u64,
    parquet_export_lag_lsn: u64,
    deferred_anchor_forks: u64,
    deadline_overdue: u64,
    pending_anpd: u64,
) -> Vec<SecurityAlarm> {
    let mut alarms = Vec::new();

    if !online {
        alarms.push(alarm(AlarmSeverity::Critical, "transport", "REST_OFFLINE", "REST indisponível", "Não foi possível consultar /stats; o estado do banco não pode ser confirmado."));
    }
    if matches!(grpc_reachable, Some(false)) {
        alarms.push(alarm(AlarmSeverity::Warning, "transport", "GRPC_UNREACHABLE", "gRPC :7474 indisponível", "A porta gRPC não respondeu ao probe TCP."));
    }

    match threat_level.to_ascii_lowercase().as_str() {
        "critical" => alarms.push(alarm(AlarmSeverity::Critical, "sentinel", "THREAT_LEVEL_CRITICAL", "Nível de ameaça CRÍTICO", "O /sentinel/dashboard reportou threat_level=critical.")),
        "elevated" => alarms.push(alarm(AlarmSeverity::Warning, "sentinel", "THREAT_LEVEL_ELEVATED", "Nível de ameaça elevado", "Há incidentes ativos no Sentinel.")),
        _ => {}
    }

    for incident in incidents {
        let terminal = matches!(incident.state.as_str(), "Resolved" | "FalsePositive");
        if terminal {
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
            &format!("state={} risk={:.2} subject={} MITRE={} LSN {}..{}", incident.state, incident.risk, incident.subject, incident.mitre, incident.first_lsn, incident.last_lsn),
        ));
    }

    let lag = sentinel_lag_state.to_ascii_lowercase();
    if lag == "critical" {
        alarms.push(alarm(AlarmSeverity::Critical, "sentinel", "DETECTION_LAG_CRITICAL", "Sentinel com lag crítico", &format!("detection_lag_lsn={detection_lag_lsn}")));
    } else if detection_lag_lsn > 0 || matches!(lag.as_str(), "degraded" | "catchingup" | "catching_up") {
        alarms.push(alarm(AlarmSeverity::Warning, "sentinel", "DETECTION_LAG", "Sentinel atrasado", &format!("state={sentinel_lag_state} detection_lag_lsn={detection_lag_lsn}")));
    }

    critical_counter(&mut alarms, "sentinel", "QUEUE_OVERFLOW", "Overflow da fila Sentinel", queue_overflow_total);
    critical_counter(&mut alarms, "sentinel", "INCIDENT_CAPACITY_DROP", "Incidentes descartados por capacidade", incident_capacity_drops_total);
    critical_counter(&mut alarms, "sentinel", "ACTION_FAILURE", "Falhas na execução de ações", action_failures_total);
    warning_counter(&mut alarms, "sentinel", "NORMALIZATION_ERROR", "Erros de normalização", normalization_errors_total);

    if !ai_circuit_state.is_empty()
        && !matches!(ai_circuit_state.to_ascii_lowercase().as_str(), "closed" | "healthy" | "disabled")
    {
        alarms.push(alarm(AlarmSeverity::Warning, "sentinel-ai", "AI_CIRCUIT", "Circuit breaker da IA não está fechado", &format!("state={ai_circuit_state}")));
    }

    critical_counter(&mut alarms, "storage", "CANONICAL_VERIFY_FAILURE", "Falha de integridade canônica", canonical_verify_failures);
    critical_counter(&mut alarms, "storage", "CRC_FAILURE", "Falha física CRC", physical_crc_failures);
    warning_counter(&mut alarms, "storage", "PARQUET_EXPORT_LAG", "Lakehouse export atrasado", parquet_export_lag_lsn);
    critical_counter(&mut alarms, "compliance", "ANCHOR_FORK", "Fork em âncora de compliance", deferred_anchor_forks);
    warning_counter(&mut alarms, "compliance", "DEADLINE_OVERDUE", "Prazos regulatórios vencidos", deadline_overdue);
    warning_counter(&mut alarms, "compliance", "ANPD_PENDING", "Pendências ANPD", pending_anpd);

    alarms.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.code.cmp(&b.code)));
    alarms
}

fn critical_counter(alarms: &mut Vec<SecurityAlarm>, source: &str, code: &str, title: &str, value: u64) {
    if value > 0 {
        alarms.push(alarm(AlarmSeverity::Critical, source, code, title, &format!("contador={value}")));
    }
}

fn warning_counter(alarms: &mut Vec<SecurityAlarm>, source: &str, code: &str, title: &str, value: u64) {
    if value > 0 {
        alarms.push(alarm(AlarmSeverity::Warning, source, code, title, &format!("contador={value}")));
    }
}

fn alarm(severity: AlarmSeverity, source: &str, code: &str, title: &str, detail: &str) -> SecurityAlarm {
    SecurityAlarm {
        severity,
        source: source.into(),
        code: code.into(),
        title: title.into(),
        detail: detail.into(),
    }
}

pub fn posture(alarms: &[SecurityAlarm]) -> (&'static str, Color) {
    if alarms.iter().any(|a| a.severity == AlarmSeverity::Critical) {
        ("CRITICAL", Color::Red)
    } else if alarms.iter().any(|a| a.severity == AlarmSeverity::Warning) {
        ("ELEVATED", Color::Yellow)
    } else {
        ("NORMAL", Color::Green)
    }
}

pub fn alarm_line(alarm: &SecurityAlarm) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {:<8} ", alarm.severity.label()),
            Style::default()
                .fg(Color::Black)
                .bg(alarm.severity.color())
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(format!("{:<11}", alarm.source), Style::default().fg(Color::Cyan)),
        Span::raw(" "),
        Span::styled(alarm.title.clone(), Style::default().fg(alarm.severity.color()).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(alarm.detail.clone(), Style::default().fg(Color::Gray)),
    ])
}

pub fn short_id(id: &str) -> String {
    if id.chars().count() <= 12 {
        return id.to_string();
    }
    id.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_integrity_never_becomes_green() {
        let alarms = derive_alarms(true, Some(true), "normal", &[], "healthy", 0, 0, 0, 0, 0, "closed", 1, 0, 0, 0, 0, 0);
        assert_eq!(posture(&alarms).0, "CRITICAL");
        assert!(alarms.iter().any(|a| a.code == "CANONICAL_VERIFY_FAILURE"));
    }

    #[test]
    fn active_severity_9_incident_is_critical() {
        let incidents = vec![IncidentRow { id: "incident-1234567890".into(), state: "Investigating".into(), severity: 9, risk: 0.95, subject: "Host:srv1".into(), mitre: "T1059".into(), first_lsn: 10, last_lsn: 20 }];
        let alarms = derive_alarms(true, Some(true), "critical", &incidents, "healthy", 0, 0, 0, 0, 0, "closed", 0, 0, 0, 0, 0, 0);
        assert_eq!(posture(&alarms).0, "CRITICAL");
        assert!(alarms.iter().any(|a| a.code == "SECURITY_INCIDENT"));
    }

    #[test]
    fn resolved_incident_does_not_raise_incident_alarm() {
        let incidents = vec![IncidentRow { state: "Resolved".into(), severity: 10, ..Default::default() }];
        let alarms = derive_alarms(true, Some(true), "normal", &incidents, "healthy", 0, 0, 0, 0, 0, "closed", 0, 0, 0, 0, 0, 0);
        assert!(!alarms.iter().any(|a| a.code == "SECURITY_INCIDENT"));
    }
}
