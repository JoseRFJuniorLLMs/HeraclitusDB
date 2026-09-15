//! SPEC-0074 §19, SPEC-0075 §21 e SPEC-0076 §4–§12 — a API da Consola.
//!
//! # A regra que governa a forma das respostas
//!
//! > A API pode retornar LSN na secção `integrity`, mas o utilizador não deve
//! > precisar de entender LSN para operar o produto (§19).
//!
//! Por isso cada resposta tem duas camadas: o que o produto mostra (runs,
//! ferramentas, aprovações) e uma secção `integrity` onde vivem LSN, raiz
//! lógica e prova. Quem precisa, encontra; quem não precisa, não tropeça.
//!
//! # Erros são estados de produto (0076 §32)
//!
//! Cada erro traz um código estável (`EVIDENCE_VERIFY_FAILED`,
//! `APPROVAL_EXPIRED`, `POLICY_INVALID`...), o que falhou, o que foi afectado e
//! o que o operador deve fazer. Um `500` nu é uma resposta que obriga alguém a
//! ir ler os logs do servidor para saber se um pagamento aconteceu.

use crate::auth::{principal_from, Operation, Principal};
use crate::console;
use crate::platform;
use crate::runtime::{now_unix_nanos, now_unix_seconds, AgentRuntime};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use heraclitus_agent::action::{ApprovalDecisionV1, ApprovalVerdict};
use heraclitus_agent::bundle::{self, BundleSelectionV1, ExportOptions};
use heraclitus_agent::policy::{DeterministicAgentPolicyEngine, PolicyInput, PolicyValueV1};
use heraclitus_agent::projection::{self, EvidenceIntegritySummary};
use heraclitus_agent::store::{ProofAvailability, StoredEvidence};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;

pub fn router(runtime: Arc<AgentRuntime>) -> Router {
    Router::new()
        // ── Platform Console (SPEC-0077 §30) ────────────────────────────────
        //
        // `/` é do HeraclitusDB. Estava a ser da Agent Console, e era esse o
        // erro que a 0077 corrige: quem abria o porto da consola via um monitor
        // de agentes de IA onde devia ver um banco de dados temporal
        // verificável com um módulo de agentes.
        .route("/", get(platform::index))
        .route("/platform.css", get(platform::css))
        .route("/platform.js", get(platform::js))
        .route("/api/v1/platform/summary", get(platform::summary))
        // ── Agent Console (0076 §15: assets embutidos, sem Node em produção) ─
        //
        // Sob `/agent`, não na raiz. O roteamento interno é por hash
        // (`#/runs`), portanto uma só rota serve a aplicação inteira; o
        // wildcard existe para que um link antigo `/agent/qualquer-coisa`
        // continue a abrir a consola em vez de dar 404.
        .route("/agent", get(console::index))
        .route("/agent/", get(console::index))
        .route("/agent/*resto", get(console::index))
        .route("/console.css", get(console::css))
        .route("/console.js", get(console::js))
        // SPEC-0074 §21 / SPEC-0075 §30 — as métricas do plano de agentes.
        // Fica fora de `/api/v1` porque é o caminho que um Prometheus espera, e
        // porque a operação técnica vive separada do produto (0076 §13).
        .route("/metrics", get(metrics))
        // ── Evidência ───────────────────────────────────────────────────────
        .route("/api/v1/agent/status", get(status))
        .route("/api/v1/agent/runs", get(runs))
        .route("/api/v1/agent/runs/:id", get(run_detail))
        .route("/api/v1/agent/runs/:id/timeline", get(run_timeline))
        .route("/api/v1/agent/tool-calls", get(tool_calls))
        .route("/api/v1/agent/evidence/:id", get(evidence_detail))
        .route("/api/v1/agent/evidence/:id/proof", get(evidence_proof))
        .route("/api/v1/agent/evidence/export", post(export))
        // SPEC-0079 — laboratório defensivo: telemetria estruturada de probes.
        // POST é SystemAdmin; GET segue a permissão de leitura dos runs.
        .route(
            "/api/v1/agent/red-team/events",
            get(red_team_events).post(red_team_record),
        )
        .route("/api/v1/agent/bundles/:name", get(download_bundle))
        // ── Policy (0075 §21) ───────────────────────────────────────────────
        .route("/api/v1/agent/policies", get(policies))
        .route("/api/v1/agent/policies/validate", post(policy_validate))
        .route("/api/v1/agent/policies/simulate", post(policy_simulate))
        .route("/api/v1/agent/policies/activate", post(policy_activate))
        .route("/api/v1/agent/policies/:version", get(policy_get))
        // ── Aprovações (0075 §21) ───────────────────────────────────────────
        .route("/api/v1/agent/approvals", get(approvals))
        .route("/api/v1/agent/approvals/:id", get(approval_get))
        .route("/api/v1/agent/approvals/:id/approve", post(approve))
        .route("/api/v1/agent/approvals/:id/deny", post(deny))
        .with_state(runtime)
}

/// Erro com a forma de §32: código, o que falhou, o que fazer.
fn problem(status: StatusCode, code: &str, detail: impl Into<String>, action: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "detail": detail.into(),
            "operator_action": action,
        })),
    )
        .into_response()
}

/// Converte uma recusa de autenticação numa resposta HTTP.
///
/// O `WWW-Authenticate` não é decorativo: é ele que faz o browser abrir a caixa
/// de utilizador/senha. Sem ele, quem abre a Consola numa consola protegida vê
/// um JSON de erro e não tem por onde autenticar-se.
fn forbidden(rejeicao: crate::auth::AuthRejection) -> Response {
    let corpo = Json(serde_json::json!({
        "error": rejeicao.code,
        "detail": rejeicao.detail,
        "operator_action": if rejeicao.challenge {
            "introduza o utilizador e a senha da consola"
        } else if rejeicao.status == StatusCode::UNAUTHORIZED {
            "apresente uma credencial válida"
        } else {
            "peça a um administrador o papel necessário, ou use uma credencial com esse papel"
        },
    }));
    if rejeicao.challenge {
        return (
            rejeicao.status,
            [(header::WWW_AUTHENTICATE, crate::auth::BASIC_REALM)],
            corpo,
        )
            .into_response();
    }
    (rejeicao.status, corpo).into_response()
}

// O `Err` destes dois helpers é uma `Response` já pronta (128 bytes), e o
// `clippy::result_large_err` sugere caixá-la. Aqui isso seria pior: a resposta
// vai ser devolvida imediatamente pelo handler, portanto a caixa seria alocada e
// desfeita na linha seguinte. É o mesmo motivo pelo qual `heraclitus-server`
// permite este lint no interceptor do tonic.
#[allow(clippy::result_large_err)]
fn who(runtime: &Arc<AgentRuntime>, headers: &HeaderMap) -> Result<Principal, Response> {
    principal_from(runtime, headers, now_unix_seconds()).map_err(forbidden)
}

#[allow(clippy::result_large_err)]
fn rows_or_error(runtime: &Arc<AgentRuntime>) -> Result<Vec<StoredEvidence>, Response> {
    runtime.scan().map_err(|e| {
        problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EVIDENCE_READ_FAILED",
            e.to_string(),
            "verifique o estado do armazenamento com `heraclitus agent doctor`",
        )
    })
}

#[derive(Debug, Deserialize)]
struct RedTeamInput {
    attack_id: String,
    #[serde(default)]
    campaign_id: Option<String>,
    vector: String,
    target: String,
    phase: String,
    result: String,
    #[serde(default)]
    expected: Option<String>,
    #[serde(default)]
    reason_code: Option<String>,
    #[serde(default)]
    blocked: Option<bool>,
    #[serde(default)]
    upstream_delta: Option<i64>,
    #[serde(default)]
    transport_status: Option<i64>,
    #[serde(default)]
    sequence: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct RedTeamQuery {
    campaign: Option<String>,
    limit: Option<usize>,
}

fn invalid_probe_atom(label: &str, value: &str, max: usize) -> Option<Response> {
    if value.is_empty() || value.len() > max || value.chars().any(|c| c.is_control()) {
        return Some(problem(
            StatusCode::BAD_REQUEST,
            "REDTEAM_EVENT_INVALID",
            format!("{label} vazio, grande demais ou com caracteres de controlo"),
            "envie apenas metadados curtos; payloads ofensivos e segredos não pertencem ao evidence log",
        ));
    }
    None
}

async fn red_team_record(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Json(input): Json<RedTeamInput>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    // A telemetria do laboratório é uma escrita administrativa. O Dashboard é
    // somente leitura; o runner autorizado escreve directamente na Agent API.
    if let Err(e) = principal.require(Operation::ChangeCapture) {
        return forbidden(e);
    }
    for (label, value, max) in [
        ("attack_id", input.attack_id.as_str(), 128usize),
        ("vector", input.vector.as_str(), 128usize),
        ("target", input.target.as_str(), 256usize),
        ("phase", input.phase.as_str(), 48usize),
        ("result", input.result.as_str(), 64usize),
    ] {
        if let Some(r) = invalid_probe_atom(label, value, max) {
            return r;
        }
    }
    let campaign = input.campaign_id.as_deref().unwrap_or("manual");
    if let Some(r) = invalid_probe_atom("campaign_id", campaign, 128) {
        return r;
    }

    let now = now_unix_nanos();
    let mut ev = heraclitus_agent::evidence::AgentEvidenceV1::new(
        runtime.config.tenant_id.clone(),
        heraclitus_agent::evidence::AgentEvidenceKindV1::ErrorObserved,
        now,
    );
    ev.run_id = Some(format!("redteam:{campaign}"));
    ev.agent = heraclitus_agent::evidence::AgentIdentityV1 {
        agent_id: "agent-atack-heraclitus".into(),
        agent_name: Some("Agent-Atack-Heraclitus".into()),
        framework: Some("heraclitus-redteam-lab".into()),
        ..Default::default()
    };
    ev.subject.protocol = Some("redteam_lab".into());
    ev.subject.server_id = Some(input.target.clone());
    ev.subject.tool_name = Some(input.vector.clone());
    ev.subject.tool_call_id = Some(input.attack_id.clone());
    ev.source = heraclitus_agent::evidence::EvidenceSourceV1 {
        source_kind: "redteam_lab".into(),
        source_instance: Some(principal.subject.clone()),
        source_sequence: input.sequence,
        received_at_unix_nanos: Some(now),
    };
    ev.privacy.capture_mode = heraclitus_agent::evidence::CaptureModeV1::MetadataOnly;
    ev.privacy.redaction_applied = true;
    ev.content
        .fields
        .insert("attack_id".into(), input.attack_id.clone());
    ev.content
        .fields
        .insert("campaign_id".into(), campaign.to_string());
    ev.content
        .fields
        .insert("vector".into(), input.vector.clone());
    ev.content
        .fields
        .insert("target".into(), input.target.clone());
    ev.content
        .fields
        .insert("phase".into(), input.phase.clone());
    ev.content
        .fields
        .insert("result".into(), input.result.clone());
    if let Some(v) = &input.expected {
        if v.len() <= 128 {
            ev.content.fields.insert("expected".into(), v.clone());
        }
    }
    if let Some(v) = &input.reason_code {
        if v.len() <= 128 {
            ev.content.fields.insert("reason_code".into(), v.clone());
        }
    }
    if let Some(v) = input.blocked {
        ev.content.fields.insert("blocked".into(), v.to_string());
    }
    if let Some(v) = input.upstream_delta {
        ev.content
            .fields
            .insert("upstream_delta".into(), v.to_string());
    }
    ev.outcome = Some(heraclitus_agent::evidence::EvidenceOutcomeV1 {
        transport_status: input.transport_status,
        protocol_status: Some(input.result.clone()),
        error_code: input.reason_code.clone(),
        ..Default::default()
    });
    ev.dedupe_key = format!(
        "redteam:{}:{}:{}:{}",
        campaign,
        input.attack_id,
        input.phase,
        input.sequence.unwrap_or(0)
    );

    match runtime.append(&ev) {
        Ok(lsn) => Json(serde_json::json!({
            "accepted": true,
            "duplicate": lsn.is_none(),
            "evidence_id": ev.evidence_id,
            "lsn": lsn,
            "capture": "METADATA_ONLY",
        }))
        .into_response(),
        Err(e) => problem(
            StatusCode::CONFLICT,
            "REDTEAM_EVIDENCE_REJECTED",
            e.to_string(),
            "use outro attack_id/phase/sequence; evidência existente nunca é reescrita",
        ),
    }
}

async fn red_team_events(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Query(q): Query<RedTeamQuery>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ViewRuns) {
        return forbidden(e);
    }
    let rows = match rows_or_error(&runtime) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let mut events = Vec::new();
    let mut blocked = 0u64;
    let mut reached_upstream = 0u64;
    for row in rows.iter().rev() {
        let e = &row.evidence;
        if e.source.source_kind != "redteam_lab" {
            continue;
        }
        let campaign = e
            .content
            .fields
            .get("campaign_id")
            .map(String::as_str)
            .unwrap_or("");
        if q.campaign
            .as_deref()
            .is_some_and(|wanted| wanted != campaign)
        {
            continue;
        }
        let is_blocked = e.content.fields.get("blocked").is_some_and(|v| v == "true");
        if is_blocked {
            blocked += 1;
        }
        let delta = e
            .content
            .fields
            .get("upstream_delta")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        if delta > 0 {
            reached_upstream += 1;
        }
        events.push(serde_json::json!({
            "lsn": row.lsn,
            "record_hash": row.record_hash(),
            "evidence_id": e.evidence_id,
            "observed_at_unix_nanos": e.observed_at_unix_nanos,
            "run_id": e.run_id,
            "attack_id": e.content.fields.get("attack_id"),
            "campaign_id": e.content.fields.get("campaign_id"),
            "vector": e.content.fields.get("vector"),
            "target": e.content.fields.get("target"),
            "phase": e.content.fields.get("phase"),
            "result": e.content.fields.get("result"),
            "expected": e.content.fields.get("expected"),
            "reason_code": e.content.fields.get("reason_code"),
            "blocked": is_blocked,
            "upstream_delta": delta,
            "transport_status": e.outcome.as_ref().and_then(|o| o.transport_status),
            "capture_mode": e.privacy.capture_mode.label(),
        }));
        if events.len() >= limit {
            break;
        }
    }
    let returned = events.len();
    Json(serde_json::json!({
        "events": events,
        "summary": {
            "returned": returned,
            "blocked": blocked,
            "reached_upstream": reached_upstream,
        },
        "truth": "red-team metadata is lab-reporter evidence; native gateway decisions remain independent evidence",
    })).into_response()
}

#[derive(Debug, Deserialize, Default)]
pub struct RunsQuery {
    pub agent: Option<String>,
    pub status: Option<String>,
    pub tool: Option<String>,
    pub decision: Option<String>,
    pub approver: Option<String>,
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub limit: Option<usize>,
    pub cursor: Option<usize>,
}

async fn status(State(runtime): State<Arc<AgentRuntime>>, headers: HeaderMap) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let rows = match rows_or_error(&runtime) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let runs = projection::project_runs(&rows);
    let policy = runtime.policy();
    let counters = *runtime.counters.lock().unwrap();
    let pending = runtime.approvals.pending(now_unix_seconds()).len();
    let integrity = integrity_of(&runtime, &rows, 64);

    let denied: u32 = runs.iter().map(|r| r.denied).sum();
    let tool_calls: u32 = runs.iter().map(|r| r.tool_calls).sum();

    Json(serde_json::json!({
        "product": "Heraclitus Agent Black Box",
        "engine": format!("HeraclitusDB {}", env!("CARGO_PKG_VERSION")),
        "auth": runtime.auth_mode().label(),
        // §28: com uma credencial partilhada os papéis não distinguem pessoas.
        // A Consola tem de o mostrar; esconder seria deixar alguém supor que
        // tem RBAC a sério.
        "auth_identifies_people": runtime.auth_mode().identifies_people(),
        "principal": principal,
        "evidence_log": if integrity.broken > 0 { "DEGRADED" } else { "HEALTHY" },
        "otlp_ingest": if runtime.config.enabled { "HEALTHY" } else { "DISABLED" },
        "mcp_gateway": if runtime.gateway.enabled {
            runtime.mode().label().to_uppercase()
        } else {
            "DISABLED".to_string()
        },
        // §20 da 0075: nunca afirmar enforcement quando a topologia não o garante.
        "bypass_protection": if runtime.gateway.bypass_protection_configured { "CONFIGURED" } else { "UNKNOWN" },
        "policy": {
            "id": policy.engine.document().id,
            "version": policy.engine.revision(),
            "hash": policy.engine.hash(),
            "rules": policy.engine.document().rules.len(),
            "activated_by": policy.activated_by,
            "lifecycle": policy.lifecycle,
        },
        "capture": {
            "mode": runtime.config.capture_mode().label(),
            "prompt_bodies": "OFF",
            "completion_bodies": "OFF",
            "tool_args": if runtime.config.capture_mode().persists_body() { "REDACTED" } else { "METADATA_ONLY" },
            "tool_results": if runtime.config.capture_mode().persists_body() { "REDACTED" } else { "METADATA_ONLY" },
            "known_secret_filters": "ON",
        },
        "rfc3161": if runtime.config.evidence.rfc3161 { "ENABLED" } else { "DISABLED" },
        "summary": {
            "runs": runs.len(),
            "tool_calls": tool_calls,
            "denied": denied,
            "pending_approvals": pending,
            "integrity": integrity.state(),
        },
        "ingest": {
            "events": counters.events,
            "duplicates": counters.duplicates,
            "conflicts": counters.conflicts,
            "rejected": counters.rejected,
            "ignored_spans": counters.ignored,
            "batches": counters.batches,
            "bytes": counters.bytes,
        },
        "gateway": runtime.gateway_counters.snapshot(),
        "integrity_detail": integrity,
        "started_at_unix_seconds": runtime.started_at(),
    }))
    .into_response()
}

/// `GET /metrics` — formato de exposição do Prometheus.
///
/// Os nomes vêm todos de [`heraclitus_agent::metrics`] e de mais lado nenhum: a
/// partir do momento em que um painel consulta `agent_ingest_events_total` e o
/// código emite `agent_ingest_event_total`, o painel mostra zero sobre um
/// sistema que está a trabalhar — e ninguém vê o erro, porque zero é um valor
/// plausível.
///
/// Nenhuma etiqueta leva segredo, argumento, prompt ou identificador de pessoa.
async fn metrics(State(runtime): State<Arc<AgentRuntime>>, headers: HeaderMap) -> Response {
    use heraclitus_agent::metrics as m;
    if let Err(r) = who(&runtime, &headers) {
        return r;
    }
    let c = *runtime.counters.lock().unwrap();
    let g = runtime.gateway_counters.snapshot();
    let tenant = &runtime.config.tenant_id;
    let pending = runtime.approvals.pending(now_unix_seconds()).len();

    let mut out = String::with_capacity(2048);
    let mut counter = |name: &str, help: &str, value: u64| {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
        out.push_str(&format!("{name}{{tenant=\"{tenant}\"}} {value}\n"));
    };
    counter(m::INGEST_EVENTS_TOTAL, "evidências aceites", c.events);
    counter(
        m::INGEST_REJECTED_TOTAL,
        "lotes ou spans recusados",
        c.rejected,
    );
    counter(
        m::INGEST_DUPLICATES_TOTAL,
        "retransmissões descartadas em silêncio",
        c.duplicates,
    );
    counter(
        m::INGEST_CONFLICTS_TOTAL,
        "chaves de deduplicação com conteúdo diferente",
        c.conflicts,
    );
    counter(
        m::INGEST_IGNORED_TOTAL,
        "spans sem marca de agente, ignorados por desenho",
        c.ignored,
    );
    counter(
        m::REDACTIONS_TOTAL,
        "evidências com redacção aplicada",
        c.redactions,
    );
    counter(
        m::GATEWAY_REQUESTS_TOTAL,
        "pedidos que atravessaram o proxy MCP",
        g["requests"].as_u64().unwrap_or(0),
    );
    counter(
        m::GATEWAY_ALLOW_TOTAL,
        "decisões ALLOW",
        g["allow"].as_u64().unwrap_or(0),
    );
    counter(
        m::GATEWAY_DENY_TOTAL,
        "decisões DENY",
        g["deny"].as_u64().unwrap_or(0),
    );
    counter(
        m::GATEWAY_REQUIRE_APPROVAL_TOTAL,
        "decisões REQUIRE_APPROVAL",
        g["require_approval"].as_u64().unwrap_or(0),
    );
    counter(
        m::GATEWAY_SHADOW_DENY_TOTAL,
        "DENY que não bloqueou porque o modo é shadow",
        g["shadow_deny"].as_u64().unwrap_or(0),
    );
    counter(
        m::GATEWAY_APPROVAL_EXPIRED_TOTAL,
        "aprovações que expiraram",
        g["approval_expired"].as_u64().unwrap_or(0),
    );
    counter(
        m::GATEWAY_APPROVAL_REPLAY_REJECTED_TOTAL,
        "reutilizações de aprovação recusadas",
        g["approval_replay_rejected"].as_u64().unwrap_or(0),
    );
    counter(
        m::GATEWAY_POLICY_ERRORS_TOTAL,
        "erros do caminho de policy e de gravação de evidência",
        g["policy_errors"].as_u64().unwrap_or(0),
    );
    counter(
        m::GATEWAY_UPSTREAM_ERRORS_TOTAL,
        "falhas a falar com o servidor MCP",
        g["upstream_errors"].as_u64().unwrap_or(0),
    );

    out.push_str(&format!(
        "# HELP {n} aprovações à espera de decisão humana\n# TYPE {n} gauge\n{n}{{tenant=\"{tenant}\"}} {pending}\n",
        n = m::GATEWAY_APPROVAL_PENDING
    ));
    out.push_str(&format!(
        "# HELP {n} profundidade do índice de deduplicação\n# TYPE {n} gauge\n{n}{{tenant=\"{tenant}\"}} {v}\n",
        n = m::INGEST_QUEUE_DEPTH,
        v = c.batches
    ));

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response()
}

/// Amostra a integridade de até `sample` registos.
///
/// Amostrar e não varrer tudo é deliberado: pedir prova de cada LSN de um log
/// grande abriria e percorreria cada segmento a cada carregamento da página
/// inicial. O que a amostra sustenta é `HEALTHY`/`DEGRADED` — a afirmação
/// `VERIFIED` sobre uma selecção concreta vem sempre do bundle, que verifica
/// tudo o que inclui.
fn integrity_of(
    runtime: &Arc<AgentRuntime>,
    rows: &[StoredEvidence],
    sample: usize,
) -> EvidenceIntegritySummary {
    let mut out = EvidenceIntegritySummary::default();
    for row in rows.iter().rev().take(sample) {
        match runtime.log().prove(row.lsn) {
            Ok(a) => out.observe(&a),
            Err(_) => out.observe(&ProofAvailability::NotFound),
        }
    }
    out
}

async fn runs(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Query(q): Query<RunsQuery>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ViewRuns) {
        return forbidden(e);
    }
    let rows = match rows_or_error(&runtime) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let tool_calls = projection::project_tool_calls(&rows);
    let mut runs = projection::project_runs(&rows);

    if let Some(agent) = &q.agent {
        runs.retain(|r| r.agent_id.contains(agent.as_str()));
    }
    if let Some(status) = &q.status {
        runs.retain(|r| format!("{:?}", r.status).eq_ignore_ascii_case(status));
    }
    if let Some(approver) = &q.approver {
        let com_aprovador: std::collections::HashSet<String> = projection::project_approvals(&rows)
            .into_iter()
            .filter(|a| a.approver_subject.as_deref() == Some(approver.as_str()))
            .filter_map(|a| a.run_id)
            .collect();
        runs.retain(|r| com_aprovador.contains(&r.run_id));
    }
    if let Some(tool) = &q.tool {
        let com_tool: std::collections::HashSet<String> = tool_calls
            .iter()
            .filter(|c| c.tool_name.as_deref() == Some(tool.as_str()))
            .filter_map(|c| c.run_id.clone())
            .collect();
        runs.retain(|r| com_tool.contains(&r.run_id));
    }
    if let Some(decision) = &q.decision {
        let com_decisao: std::collections::HashSet<String> =
            projection::project_policy_decisions(&rows)
                .into_iter()
                .filter(|d| d.decision.eq_ignore_ascii_case(decision))
                .filter_map(|d| d.run_id)
                .collect();
        runs.retain(|r| com_decisao.contains(&r.run_id));
    }
    if let Some(from) = q.from {
        runs.retain(|r| r.started_at_unix_nanos >= from);
    }
    if let Some(to) = q.to {
        runs.retain(|r| r.started_at_unix_nanos <= to);
    }

    // §31 da 0076: paginação por cursor. Nunca carregar tudo no browser.
    let total = runs.len();
    let cursor = q.cursor.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let mut page: Vec<_> = runs.into_iter().skip(cursor).take(limit).collect();
    let next = (cursor + page.len() < total).then_some(cursor + page.len());

    // A integridade por run é calculada só para a PÁGINA que vai ser mostrada.
    //
    // `project_runs` é uma projecção pura — não abre o log, e por isso deixa o
    // estado em `UNVERIFIED`. Se a lista mostrasse esse valor cru enquanto o
    // cabeçalho mostra `VERIFIED` (que vem de uma amostra real), a mesma página
    // daria duas respostas à mesma pergunta. Um indicador de integridade que se
    // contradiz é pior do que nenhum: ensina o operador a ignorá-lo.
    //
    // O custo fica limitado por duas coisas: só a página, e só uma amostra de
    // cada run.
    const AMOSTRA_POR_RUN: usize = 32;
    for run in &mut page {
        let mut resumo = EvidenceIntegritySummary::default();
        for row in rows
            .iter()
            .filter(|r| r.evidence.effective_run_id() == Some(run.run_id.as_str()))
            .take(AMOSTRA_POR_RUN)
        {
            match runtime.log().prove(row.lsn) {
                Ok(a) => resumo.observe(&a),
                Err(_) => resumo.observe(&ProofAvailability::NotFound),
            }
        }
        run.integrity = resumo.state();
    }

    Json(serde_json::json!({
        "runs": page,
        "total": total,
        "next_cursor": next,
    }))
    .into_response()
}

async fn run_detail(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ViewRuns) {
        return forbidden(e);
    }
    let rows = match rows_or_error(&runtime) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let do_run: Vec<StoredEvidence> = rows
        .iter()
        .filter(|r| r.evidence.effective_run_id() == Some(id.as_str()))
        .cloned()
        .collect();
    if do_run.is_empty() {
        return problem(
            StatusCode::NOT_FOUND,
            "RUN_NOT_FOUND",
            format!("não há evidência para o run {id}"),
            "confirme o identificador na lista de runs",
        );
    }
    let mut summary = projection::project_runs(&do_run).remove(0);
    let integrity = integrity_of(&runtime, &do_run, do_run.len());
    summary.integrity = integrity.state();

    Json(serde_json::json!({
        "run": summary,
        "tool_calls": projection::project_tool_calls(&do_run),
        "approvals": projection::project_approvals(&do_run),
        "policy_decisions": projection::project_policy_decisions(&do_run),
        "identities": projection::project_identities(&do_run),
        "integrity": {
            "state": integrity.state(),
            "detail": integrity,
            "first_lsn": summary.first_lsn,
            "last_lsn": summary.last_lsn,
            "broken_parents": projection::broken_parents(&do_run).len(),
        }
    }))
    .into_response()
}

async fn run_timeline(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<RunsQuery>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ViewRuns) {
        return forbidden(e);
    }
    let rows = match rows_or_error(&runtime) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let all = projection::project_timeline(&rows, &id);
    let total = all.len();
    let cursor = q.cursor.unwrap_or(0);
    let limit = q.limit.unwrap_or(200).clamp(1, 2000);
    let page: Vec<_> = all.into_iter().skip(cursor).take(limit).collect();
    let next = (cursor + page.len() < total).then_some(cursor + page.len());
    Json(serde_json::json!({
        "run_id": id,
        "entries": page,
        "total": total,
        "next_cursor": next,
    }))
    .into_response()
}

async fn tool_calls(State(runtime): State<Arc<AgentRuntime>>, headers: HeaderMap) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ViewRuns) {
        return forbidden(e);
    }
    let rows = match rows_or_error(&runtime) {
        Ok(r) => r,
        Err(r) => return r,
    };
    Json(serde_json::json!({ "tool_calls": projection::project_tool_calls(&rows) })).into_response()
}

async fn evidence_detail(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ViewProofs) {
        return forbidden(e);
    }
    let rows = match rows_or_error(&runtime) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Some(row) = rows.iter().find(|r| r.evidence.evidence_id == id) else {
        return problem(
            StatusCode::NOT_FOUND,
            "EVIDENCE_NOT_FOUND",
            format!("não há evidência com o id {id}"),
            "confirme o identificador na timeline do run",
        );
    };
    let proof = runtime.log().prove(row.lsn).ok();
    Json(serde_json::json!({
        "evidence": row.evidence,
        "timeline_entry": projection::timeline_entry(row),
        "integrity": {
            "lsn": row.lsn,
            "record_hash": row.record_hash(),
            "proof": proof,
        }
    }))
    .into_response()
}

async fn evidence_proof(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ViewProofs) {
        return forbidden(e);
    }
    let rows = match rows_or_error(&runtime) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Some(row) = rows.iter().find(|r| r.evidence.evidence_id == id) else {
        return problem(
            StatusCode::NOT_FOUND,
            "EVIDENCE_NOT_FOUND",
            format!("não há evidência com o id {id}"),
            "confirme o identificador na timeline do run",
        );
    };
    match runtime.log().prove(row.lsn) {
        Ok(ProofAvailability::Available(p)) => {
            let fecha = heraclitus_agent::store::proof_closes(&p);
            if !fecha {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "EVIDENCE_VERIFY_FAILED",
                    format!(
                        "a prova do LSN {} não fecha contra a raiz declarada",
                        row.lsn
                    ),
                    "não represente esta evidência como verificada; corra `heraclitus storage doctor`",
                );
            }
            Json(serde_json::json!({ "state": "AVAILABLE", "proof": p, "closes": fecha }))
                .into_response()
        }
        Ok(other) => Json(serde_json::json!({ "state": other })).into_response(),
        Err(e) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EVIDENCE_VERIFY_FAILED",
            e.to_string(),
            "corra `heraclitus storage doctor` no directório de dados",
        ),
    }
}

#[derive(Debug, Deserialize)]
pub struct ExportBody {
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub from_unix_nanos: Option<u64>,
    #[serde(default)]
    pub to_unix_nanos: Option<u64>,
    #[serde(default)]
    pub evidence_ids: Option<Vec<String>>,
}

async fn export(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Json(body): Json<ExportBody>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ExportBundle) {
        return forbidden(e);
    }
    let selection = if let Some(run_id) = body.run_id {
        BundleSelectionV1::Run { run_id }
    } else if let (Some(from), Some(to)) = (body.from_unix_nanos, body.to_unix_nanos) {
        BundleSelectionV1::TimeWindow {
            from_unix_nanos: from,
            to_unix_nanos: to,
        }
    } else if let Some(ids) = body.evidence_ids {
        BundleSelectionV1::EvidenceIds { evidence_ids: ids }
    } else {
        BundleSelectionV1::Everything
    };

    let name = format!("evidence-{}.zip", ulid::Ulid::new());
    let destination = runtime.bundles_dir().join(&name);
    let opts = ExportOptions {
        tenant_id: runtime.config.tenant_id.clone(),
        selection,
        privacy_profile: runtime.config.redaction.profile.clone(),
        capture_mode: runtime.config.capture_mode(),
        max_records: if runtime.config.evidence.max_bundle_records == 0 {
            200_000
        } else {
            runtime.config.evidence.max_bundle_records
        },
        created_at_unix_nanos: now_unix_nanos(),
    };
    match bundle::build_bundle(runtime.log().as_ref(), &destination, &opts) {
        Ok(outcome) => Json(serde_json::json!({
            "bundle_id": outcome.bundle_id,
            "file": name,
            "download": format!("/api/v1/agent/bundles/{name}"),
            "path": outcome.path.display().to_string(),
            "records": outcome.record_count,
            "proofs_present": outcome.proofs_present,
            "pending_seal": outcome.pending_seal,
            "bytes": outcome.bytes,
            "verify_command": format!("heraclitus agent verify {name}"),
        }))
        .into_response(),
        Err(bundle::BundleError::EmptySelection) => problem(
            StatusCode::BAD_REQUEST,
            "EMPTY_SELECTION",
            "nenhuma evidência corresponde à selecção",
            "alargue a janela de tempo ou confirme o run id",
        ),
        Err(e) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EXPORT_FAILED",
            e.to_string(),
            "confirme que o directório de bundles é gravável",
        ),
    }
}

async fn download_bundle(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ExportBundle) {
        return forbidden(e);
    }
    // O nome vem do cliente. Só um segmento, só caracteres que nós próprios
    // geramos: qualquer outra coisa é uma tentativa de ler fora da pasta.
    let seguro = !name.is_empty()
        && name.len() <= 128
        && name.ends_with(".zip")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !name.contains("..");
    if !seguro {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_BUNDLE_NAME",
            "nome de bundle inválido",
            "use o nome devolvido pela exportação",
        );
    }
    match std::fs::read(runtime.bundles_dir().join(&name)) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/zip".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{name}\""),
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(e) => problem(
            StatusCode::NOT_FOUND,
            "BUNDLE_NOT_FOUND",
            e.to_string(),
            "exporte o bundle outra vez",
        ),
    }
}

// ── Policy ──────────────────────────────────────────────────────────────────

async fn policies(State(runtime): State<Arc<AgentRuntime>>, headers: HeaderMap) -> Response {
    if let Err(r) = who(&runtime, &headers) {
        return r;
    }
    let p = runtime.policy();
    Json(serde_json::json!({
        "active": {
            "id": p.engine.document().id,
            "version": p.engine.revision(),
            "hash": p.engine.hash(),
            "lifecycle": p.lifecycle,
            "activated_by": p.activated_by,
            "activated_at_unix_seconds": p.activated_at_unix_seconds,
            "source": p.source_path,
            "default_decision": p.engine.document().default_decision.label(),
            "rules": p.engine.document().rules,
        }
    }))
    .into_response()
}

async fn policy_get(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Path(version): Path<String>,
) -> Response {
    if let Err(r) = who(&runtime, &headers) {
        return r;
    }
    let p = runtime.policy();
    if p.engine.revision() != version {
        return problem(
            StatusCode::NOT_FOUND,
            "POLICY_VERSION_NOT_FOUND",
            format!(
                "a versão activa é `{}`; o histórico de versões vive na evidência de cada decisão",
                p.engine.revision()
            ),
            "procure o `policy_hash` nas decisões registadas do run que quer auditar",
        );
    }
    Json(serde_json::json!({ "document": p.engine.document(), "hash": p.engine.hash() }))
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct PolicyBody {
    pub document: String,
}

async fn policy_validate(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Json(body): Json<PolicyBody>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::SimulatePolicy) {
        return forbidden(e);
    }
    match DeterministicAgentPolicyEngine::parse(&body.document) {
        Ok(engine) => Json(serde_json::json!({
            "lifecycle": "VALIDATED",
            "id": engine.document().id,
            "version": engine.revision(),
            "hash": engine.hash(),
            "rules": engine.document().rules.len(),
        }))
        .into_response(),
        Err(e) => problem(
            StatusCode::BAD_REQUEST,
            "POLICY_INVALID",
            e.to_string(),
            "corrija o documento; nada foi activado",
        ),
    }
}

#[derive(Debug, Deserialize)]
pub struct SimulateBody {
    pub document: String,
    #[serde(default)]
    pub from_unix_nanos: Option<u64>,
    #[serde(default)]
    pub to_unix_nanos: Option<u64>,
}

/// SPEC-0075 §23 — simulação histórica sobre o que a SPEC-0074 já registou.
async fn policy_simulate(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Json(body): Json<SimulateBody>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::SimulatePolicy) {
        return forbidden(e);
    }
    let candidate = match DeterministicAgentPolicyEngine::parse(&body.document) {
        Ok(e) => e,
        Err(e) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "POLICY_INVALID",
                e.to_string(),
                "corrija o documento; nada foi activado",
            )
        }
    };
    let rows = match rows_or_error(&runtime) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let active = runtime.policy();
    let report = simulate(
        &rows,
        &candidate,
        &active.engine,
        body.from_unix_nanos,
        body.to_unix_nanos,
    );
    Json(report).into_response()
}

/// Reavalia o histórico de tool calls com a policy candidata.
pub fn simulate(
    rows: &[StoredEvidence],
    candidate: &DeterministicAgentPolicyEngine,
    active: &DeterministicAgentPolicyEngine,
    from: Option<u64>,
    to: Option<u64>,
) -> serde_json::Value {
    let mut historical = 0u64;
    let mut allow = 0u64;
    let mut deny = 0u64;
    let mut require_approval = 0u64;
    let mut outras = 0u64;
    let mut changed = 0u64;
    let mut amostras: Vec<serde_json::Value> = Vec::new();

    for row in rows {
        let e = &row.evidence;
        if e.kind != heraclitus_agent::evidence::AgentEvidenceKindV1::ToolRequested {
            continue;
        }
        if let Some(f) = from {
            if e.observed_at_unix_nanos < f {
                continue;
            }
        }
        if let Some(t) = to {
            if e.observed_at_unix_nanos > t {
                continue;
            }
        }
        historical += 1;
        let input = input_from_evidence(e);
        let novo = candidate.evaluate(&input);
        let velho = active.evaluate(&input);
        match novo.decision.label() {
            "allow" => allow += 1,
            "deny" => deny += 1,
            "require_approval" => require_approval += 1,
            _ => outras += 1,
        }
        if novo.decision.label() != velho.decision.label() {
            changed += 1;
            if amostras.len() < 25 {
                amostras.push(serde_json::json!({
                    "evidence_id": e.evidence_id,
                    "run_id": e.effective_run_id(),
                    "tool": e.subject.tool_name,
                    "server": e.subject.server_id,
                    "active": velho.decision.label(),
                    "candidate": novo.decision.label(),
                    "candidate_rule": novo.rule_id,
                }));
            }
        }
    }

    serde_json::json!({
        "candidate": { "id": candidate.document().id, "version": candidate.revision(), "hash": candidate.hash() },
        "active": { "id": active.document().id, "version": active.revision(), "hash": active.hash() },
        "historical_tool_calls": historical,
        "allow": allow,
        "deny": deny,
        "require_approval": require_approval,
        "other": outras,
        "changed_vs_active": changed,
        "samples": amostras,
    })
}

/// Projecta os campos tipados de uma evidência para input de policy.
pub fn input_from_evidence(e: &heraclitus_agent::evidence::AgentEvidenceV1) -> PolicyInput {
    let mut fields: BTreeMap<String, PolicyValueV1> = BTreeMap::new();
    for (k, v) in &e.content.fields {
        // Um campo redigido não pode alimentar uma decisão: usá-lo seria
        // decidir sobre o marcador `[REDACTED]` em vez do valor.
        if v == heraclitus_agent::privacy::REDACTED_MARKER {
            continue;
        }
        fields.insert(
            k.clone(),
            match v.parse::<i64>() {
                Ok(i) => PolicyValueV1::Int(i),
                Err(_) => PolicyValueV1::Str(v.clone()),
            },
        );
    }
    PolicyInput {
        server_id: e.subject.server_id.clone().unwrap_or_default(),
        tool_name: e.subject.tool_name.clone().unwrap_or_default(),
        agent_subject: e.agent.agent_id.clone(),
        environment: None,
        protocol: e.subject.protocol.clone(),
        fields,
        now_unix_seconds: e.observed_at_unix_nanos / 1_000_000_000,
    }
}

async fn policy_activate(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Json(body): Json<PolicyBody>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ActivatePolicy) {
        return forbidden(e);
    }
    match DeterministicAgentPolicyEngine::parse(&body.document) {
        Ok(engine) => {
            let hash = engine.hash().to_string();
            let version = engine.revision().to_string();
            runtime.activate_policy(engine, &principal.subject, None);
            Json(serde_json::json!({
                "lifecycle": "ACTIVE",
                "version": version,
                "hash": hash,
                "activated_by": principal.subject,
            }))
            .into_response()
        }
        Err(e) => problem(
            StatusCode::BAD_REQUEST,
            "POLICY_INVALID",
            e.to_string(),
            "corrija o documento; a policy anterior continua activa",
        ),
    }
}

// ── Aprovações ──────────────────────────────────────────────────────────────

async fn approvals(State(runtime): State<Arc<AgentRuntime>>, headers: HeaderMap) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ViewRuns) {
        return forbidden(e);
    }
    let now = now_unix_seconds();
    Json(serde_json::json!({
        "pending": runtime.approvals.pending(now),
        "all": runtime.approvals.all(),
        "can_approve": principal.can(Operation::ApproveAction),
    }))
    .into_response()
}

async fn approval_get(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = who(&runtime, &headers) {
        return r;
    }
    match runtime.approvals.get(&id) {
        Some(record) => Json(record).into_response(),
        None => problem(
            StatusCode::NOT_FOUND,
            "APPROVAL_NOT_FOUND",
            format!("não há aprovação {id}"),
            "a aprovação pode ter expirado; a caixa de entrada mostra as pendentes",
        ),
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct DecisionBody {
    #[serde(default)]
    pub comment: Option<String>,
}

async fn approve(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Response {
    decide(
        runtime,
        headers,
        id,
        true,
        body.map(|b| b.0).unwrap_or_default(),
    )
    .await
}

async fn deny(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Response {
    decide(
        runtime,
        headers,
        id,
        false,
        body.map(|b| b.0).unwrap_or_default(),
    )
    .await
}

async fn decide(
    runtime: Arc<AgentRuntime>,
    headers: HeaderMap,
    id: String,
    approved: bool,
    body: DecisionBody,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ApproveAction) {
        return forbidden(e);
    }
    let now = now_unix_seconds();
    let Some(record) = runtime.approvals.get(&id) else {
        return problem(
            StatusCode::NOT_FOUND,
            "APPROVAL_NOT_FOUND",
            format!("não há aprovação {id}"),
            "a aprovação pode ter expirado; recarregue a caixa de entrada",
        );
    };
    // O papel exigido pela REGRA, e não só o papel genérico de aprovador.
    // Sem isto, um `approver` de suporte aprovaria um pagamento que a policy
    // reservou ao CFO.
    if !record.request.requested_roles.is_empty()
        && !principal.roles.iter().any(|r| {
            record
                .request
                .requested_roles
                .iter()
                .any(|want| want.eq_ignore_ascii_case(r.label()))
        })
        && !principal.roles.contains(&crate::auth::Role::SystemAdmin)
    {
        return problem(
            StatusCode::FORBIDDEN,
            "APPROVAL_ROLE_MISMATCH",
            format!(
                "esta acção exige um de [{}]",
                record.request.requested_roles.join(", ")
            ),
            "encaminhe para alguém com o papel exigido pela policy",
        );
    }

    let decision = ApprovalDecisionV1 {
        approval_id: id.clone(),
        approver_subject: principal.subject.clone(),
        approver_issuer: principal.issuer.clone(),
        approved,
        authorization_subject_hash: record.request.authorization_subject_hash.clone(),
        decided_at: now,
        comment: body.comment,
    };
    match runtime.approvals.decide(decision.clone(), now) {
        Ok(record) => {
            // A decisão humana é evidência (§16 da 0075): sem isto, a timeline
            // mostraria a execução e não mostraria quem a autorizou.
            let kind = if approved {
                heraclitus_agent::evidence::AgentEvidenceKindV1::HumanApprovalGranted
            } else {
                heraclitus_agent::evidence::AgentEvidenceKindV1::HumanApprovalDenied
            };
            let mut e = heraclitus_agent::evidence::AgentEvidenceV1::new(
                runtime.config.tenant_id.clone(),
                kind,
                now_unix_nanos(),
            );
            e.subject.tool_name = Some(record.request.preview.tool.clone());
            e.subject.server_id = Some(record.request.preview.server.clone());
            e.run_id = record.request.preview.run_id.clone();
            e.human = Some(heraclitus_agent::evidence::HumanIdentityRefV1 {
                subject_id: principal.subject.clone(),
                issuer: Some(principal.issuer.clone()),
                display_hint: None,
            });
            e.content.approval = Some(heraclitus_agent::evidence::ApprovalProvenanceV1 {
                approval_id: id.clone(),
                authorization_subject_hash: record.request.authorization_subject_hash.clone(),
                approver_subject: Some(principal.subject.clone()),
                approver_issuer: Some(principal.issuer.clone()),
                decided_at_unix_nanos: Some(now_unix_nanos()),
            });
            e.source.source_kind = "gateway".to_string();
            e.dedupe_key = heraclitus_agent::dedupe::dedupe_key(&e);
            let lsn = runtime.append(&e).ok().flatten();
            let _ = runtime.flush();
            Json(serde_json::json!({
                "approval": record,
                "evidence_id": e.evidence_id,
                "integrity": { "lsn": lsn },
            }))
            .into_response()
        }
        Err(verdict) => {
            let status = match &verdict {
                ApprovalVerdict::NotFound => StatusCode::NOT_FOUND,
                ApprovalVerdict::Expired { .. } => StatusCode::GONE,
                _ => StatusCode::CONFLICT,
            };
            problem(
                status,
                verdict.reason_code(),
                format!("{verdict:?}"),
                "peça ao agente que repita a acção; a aprovação anterior não pode ser reutilizada",
            )
        }
    }
}
