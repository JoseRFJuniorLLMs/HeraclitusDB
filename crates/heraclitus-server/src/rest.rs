//! Minimal admin REST (axum) — a thin layer over the same engine.

use crate::engine::Engine;
use axum::{
    extract::{Extension, Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use heraclitus_sentinel::{IncidentFilter, IncidentState, SentinelRuntime};
use serde::Deserialize;
use std::sync::Arc;

/// Se `POST /titular/:id/eliminar` esta autorizado. Vem da config
/// (`rest_allow_erasure`), `false` por omissao.
///
/// Viaja como `Extension` do router e nao como `static` de processo: era um
/// `AtomicBool` global, portanto dois routers no mesmo processo (testes, ou uma
/// segunda instancia embebida) partilhavam o flag e o ultimo a ser construido
/// decidia pelos dois. Configuracao de um router pertence ao router.
#[derive(Debug, Clone, Copy)]
struct ErasureAllowed(bool);

/// Comparação em tempo constante (R17): o tempo não depende do prefixo
/// coincidente, fechando o side-channel de timing do `==` de strings. O
/// comprimento continua observável — inevitável e inócuo (o segredo não é o
/// comprimento). Partilhada pelo Basic (REST) e pelo Bearer (gRPC, `lib.rs`).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Base64 padrão (RFC 4648, com padding) — só para montar o valor esperado do
/// header `Authorization: Basic ...`; evita puxar uma dependência para 15 linhas.
fn b64(input: &[u8]) -> String {
    const AB: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(AB[(n >> 18) as usize & 63] as char);
        out.push(AB[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            AB[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            AB[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Constrói o router; com `basic_auth = Some("user:pass")` TODAS as rotas
/// exigem `Authorization: Basic ...` (comparação de string constante contra o
/// valor esperado — nunca se descodifica input do cliente).
pub fn router(
    engine: Arc<Engine>,
    basic_auth: Option<String>,
    cors_origins: Vec<String>,
    allow_erasure: bool,
) -> Router {
    router_with_sentinel(engine, None, basic_auth, cors_origins, allow_erasure)
}

/// Build the REST surface with an optional live Sentinel handle.  The legacy
/// [`router`] entry point remains unchanged for embedded hosts that do not
/// start Sentinel; the server passes the handle here so the read-only
/// `/sentinel/*` endpoints cannot outlive the worker set accidentally.
pub fn router_with_sentinel(
    engine: Arc<Engine>,
    sentinel: Option<Arc<SentinelRuntime>>,
    basic_auth: Option<String>,
    cors_origins: Vec<String>,
    allow_erasure: bool,
) -> Router {
    let routes = Router::new()
        .route("/healthz", get(healthz))
        .route("/stats", get(stats))
        .route("/metrics", get(metrics))
        .route("/state", get(state))
        .route("/compliance/status", get(compliance_status))
        .route("/telemetry/health", get(telemetry_health))
        // SPEC-0071 §3 — o evento canonico de seguranca, do lado do banco.
        .route("/security/events", get(security_events))
        .route("/security/events/counts", get(security_event_counts))
        // SPEC-0071 §8 — Case Management. Nao ha rota que MUTE um caso: o
        // POST acrescenta um comando ao log e o GET reconstroi.
        .route("/cases", get(case_list).post(case_command))
        .route("/cases/:id", get(case_state))
        // SPEC-0071 §7 — Content Hub.
        .route("/content", get(content_state).post(content_command))
        .route("/verify", get(verify))
        .route("/verify/:segment", get(verify_segment))
        // Fluxo ao vivo de appends (SSE). O log já emitia cada append
        // confirmado num broadcast interno; faltava só quem o expusesse.
        .route("/live/events", get(live_events))
        // LGPD art. 18: pegada do titular, acessos aos dados dele, e eliminacao.
        .route("/replay", get(replay).post(replay_post))
        .route("/fontes", get(fontes))
        .route("/fontes/:id", get(fonte_detalhe))
        .route("/atributos", get(atributos))
        .route("/diff", get(diff))
        .route("/titular/:id", get(titular))
        .route("/titular/:id/acessos", get(titular_acessos))
        .route(
            "/titular/:id/eliminar",
            axum::routing::post(titular_eliminar),
        )
        // M20 — H-VM sovereignty ledger (SPEC-025-adjacente). KV durável no log.
        .route("/hvm/state", get(hvm_state))
        .route("/hvm/upsert", axum::routing::post(hvm_upsert))
        .route("/hvm/delete", axum::routing::post(hvm_delete))
        .route("/hvm/checkpoint", axum::routing::post(hvm_checkpoint))
        // SPEC-0045 §88 — Sentinel status/incident views.  The checkpoint is
        // an auditable derived write; response actions remain unavailable
        // until durable approval/executor wiring.
        .route("/sentinel/status", get(sentinel_status))
        .route(
            "/sentinel/checkpoint",
            axum::routing::post(sentinel_checkpoint),
        )
        .route("/sentinel/incidents", get(sentinel_incidents))
        .route("/sentinel/incidents/:id", get(sentinel_incident))
        .route(
            "/sentinel/incidents/:id/evidence",
            get(sentinel_incident_evidence),
        )
        .route("/sentinel/incidents/:id/why", get(sentinel_incident_why))
        .route(
            "/sentinel/incidents/:id/approve",
            axum::routing::post(sentinel_approve),
        )
        .route(
            "/sentinel/incidents/:id/deny",
            axum::routing::post(sentinel_deny),
        )
        .route("/sentinel/actions", get(sentinel_actions))
        .route("/sentinel/actions/:id", get(sentinel_action))
        .route("/sentinel/dashboard", get(sentinel_dashboard));
    // SPEC-016 (feature `analytics`): data plane Flight — o log inteiro como um
    // stream Arrow IPC, legível por pyarrow/Polars/DuckDB sem parsing por linha.
    #[cfg(feature = "analytics")]
    let routes = routes
        .route("/flight/events", get(flight_events))
        .route("/sql", axum::routing::post(sql));
    // Cold tier (feature `tier`): lista de segmentos selados + demote.
    #[cfg(feature = "tier")]
    let routes = routes
        .route("/tier/sealed", get(tier_sealed))
        .route("/tier/demote", axum::routing::post(tier_demote))
        .route("/tier/receipts", get(tier_receipts))
        .route("/tier/fetch/:segment", get(tier_fetch));
    // O aprovador de uma accao humana passa a ser a identidade AUTENTICADA (ver
    // `IdentidadeRest`). Com Basic auth ha uma unica credencial partilhada, logo
    // a identidade e o utilizador configurado; sem auth nao ha identidade
    // nenhuma, e e ISSO que fica escrito no registo em vez de um nome bonito
    // escolhido pelo chamador.
    let identidade = IdentidadeRest(match basic_auth.as_deref() {
        Some(creds) => creds.split(':').next().unwrap_or("rest").to_owned(),
        None => "rest-sem-auth".to_owned(),
    });
    let routes = routes
        .with_state(engine)
        .layer(Extension(sentinel))
        .layer(Extension(identidade))
        .layer(Extension(ErasureAllowed(allow_erasure)));

    let protegido = aplicar_auth(routes, basic_auth);
    // O CORS fica por FORA da autenticação: o browser envia o preflight
    // `OPTIONS` sem credenciais nenhumas, portanto se a auth o apanhasse
    // primeiro devolveria 401 e o pedido real nem chegava a ser feito.
    aplicar_cors(protegido, cors_origins)
}

/// Quem esta a chamar o REST, segundo a AUTENTICACAO — nao segundo o corpo do
/// pedido.
///
/// O Basic auth desta superficie tem uma unica credencial partilhada, portanto
/// isto nao distingue pessoas; distingue "alguem que provou conhecer a
/// credencial" de "ninguem provou nada". Para um registo de aprovacao humana
/// essa distincao ja e o essencial, e e honesta sobre o que sabe.
#[derive(Clone, Debug)]
pub struct IdentidadeRest(pub String);

fn aplicar_auth(routes: Router, basic_auth: Option<String>) -> Router {
    match basic_auth {
        None => routes,
        Some(creds) => {
            let expected: Arc<String> = Arc::new(format!("Basic {}", b64(creds.as_bytes())));
            routes.layer(middleware::from_fn(move |req: Request, next: Next| {
                let expected = expected.clone();
                async move {
                    let ok = req
                        .headers()
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .map(|v| ct_eq(v.as_bytes(), expected.as_bytes()))
                        .unwrap_or(false);
                    if ok {
                        next.run(req).await
                    } else {
                        Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(header::WWW_AUTHENTICATE, "Basic realm=\"heraclitus\"")
                            .body("unauthorized".into())
                            .unwrap()
                    }
                }
            }))
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct SentinelIncidentQuery {
    state: Option<String>,
    min_severity: Option<u8>,
    subject_kind: Option<String>,
    subject_id: Option<String>,
    incident_id: Option<String>,
    as_of_lsn: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
struct TelemetryHealthQuery {
    tenant_id: Option<String>,
    datasource_id: Option<String>,
    sensor_id: Option<String>,
    as_of_lsn: Option<u64>,
}

/// SPEC-0071 §3 — filtro dos eventos canonicos de seguranca.
#[derive(Debug, Deserialize)]
struct SecurityEventQuery {
    tenant_id: Option<String>,
    datasource_id: Option<String>,
    category: Option<String>,
    outcome: Option<String>,
    min_severity: Option<u8>,
    as_of_lsn: Option<u64>,
    limit: Option<usize>,
}

fn parse_incident_state(value: &str) -> Option<IncidentState> {
    match value.to_ascii_lowercase().as_str() {
        "new" => Some(IncidentState::New),
        "enriching" => Some(IncidentState::Enriching),
        "investigating" => Some(IncidentState::Investigating),
        "actionproposed" | "action_proposed" => Some(IncidentState::ActionProposed),
        "awaitingapproval" | "awaiting_approval" => Some(IncidentState::AwaitingApproval),
        "contained" => Some(IncidentState::Contained),
        "monitoring" => Some(IncidentState::Monitoring),
        "resolved" => Some(IncidentState::Resolved),
        "falsepositive" | "false_positive" => Some(IncidentState::FalsePositive),
        _ => None,
    }
}

fn incident_filter(query: SentinelIncidentQuery) -> Result<IncidentFilter, String> {
    let state = match query.state.as_deref() {
        None => None,
        Some(value) => Some(
            parse_incident_state(value).ok_or_else(|| "state de incidente inválido".to_string())?,
        ),
    };
    let subject = match (query.subject_kind, query.subject_id) {
        (None, None) => None,
        (Some(kind), Some(id)) if !kind.trim().is_empty() && !id.trim().is_empty() => {
            Some(heraclitus_sentinel::EntityRef {
                kind,
                id,
                name: None,
            })
        }
        _ => return Err("subject_kind e subject_id devem ser fornecidos juntos".into()),
    };
    Ok(IncidentFilter {
        state,
        min_severity: query.min_severity,
        subject,
        as_of_lsn: query.as_of_lsn,
        limit: query.limit,
    })
}

fn sentinel_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "sentinel_unavailable",
            "message": "Sentinel está desabilitado ou não iniciou"
        })),
    )
        .into_response()
}

async fn sentinel_status(Extension(runtime): Extension<Option<Arc<SentinelRuntime>>>) -> Response {
    let Some(runtime) = runtime else {
        return sentinel_unavailable();
    };
    Json(serde_json::json!({
        "available": true,
        "status": runtime.status()
    }))
    .into_response()
}

async fn sentinel_checkpoint(
    Extension(runtime): Extension<Option<Arc<SentinelRuntime>>>,
) -> Response {
    let Some(runtime) = runtime else {
        return sentinel_unavailable();
    };
    // `spawn_blocking`: o `checkpoint()` varre o log e escreve em disco. Corrido
    // directamente no handler, bloqueava uma thread do reactor do tokio — e o
    // reactor tem um número fixo delas, portanto bastam alguns pedidos destes em
    // paralelo para o servidor deixar de aceitar QUALQUER pedido, incluindo os
    // que não tocam no disco. O vizinho `sentinel_incident_why` já fazia isto.
    match tokio::task::spawn_blocking(move || runtime.checkpoint()).await {
        Ok(Ok(lsn)) => Json(serde_json::json!({ "checkpoint_lsn": lsn })).into_response(),
        Ok(Err(error)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn sentinel_incidents(
    Extension(runtime): Extension<Option<Arc<SentinelRuntime>>>,
    Query(query): Query<SentinelIncidentQuery>,
) -> Response {
    let Some(runtime) = runtime else {
        return sentinel_unavailable();
    };
    let filter = match incident_filter(query) {
        Ok(filter) => filter,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": message })),
            )
                .into_response()
        }
    };
    // `spawn_blocking` pela mesma razão do `/sentinel/checkpoint`: esta consulta
    // percorre o log e não pode correr no reactor.
    match tokio::task::spawn_blocking(move || runtime.query_incidents(filter))
        .await
        .unwrap_or_else(|erro| Err(heraclitus_sentinel::SentinelError::Config(erro.to_string())))
    {
        Ok(incidents) => Json(serde_json::json!({
            "incidents": incidents,
            "count": incidents.len()
        }))
        .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn sentinel_incident(
    Extension(runtime): Extension<Option<Arc<SentinelRuntime>>>,
    Path(id): Path<String>,
    Query(query): Query<SentinelIncidentQuery>,
) -> Response {
    let Some(runtime) = runtime else {
        return sentinel_unavailable();
    };
    // `spawn_blocking`: o ramo `as_of` replaya o log. Ver o comentário do
    // `/sentinel/checkpoint`.
    let result = tokio::task::spawn_blocking(move || {
        if let Some(as_of_lsn) = query.as_of_lsn {
            runtime.incident_as_of(&id, as_of_lsn)
        } else {
            Ok(runtime.get_incident(&id))
        }
    })
    .await
    .unwrap_or_else(|erro| Err(heraclitus_sentinel::SentinelError::Config(erro.to_string())));
    match result {
        Ok(Some(incident)) => Json(incident).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "incident_not_found" })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn sentinel_incident_evidence(
    Extension(runtime): Extension<Option<Arc<SentinelRuntime>>>,
    Path(id): Path<String>,
    Query(query): Query<SentinelIncidentQuery>,
) -> Response {
    let Some(runtime) = runtime else {
        return sentinel_unavailable();
    };
    // `spawn_blocking` pela mesma razão do handler acima.
    let result = tokio::task::spawn_blocking(move || {
        if let Some(as_of_lsn) = query.as_of_lsn {
            runtime.incident_as_of(&id, as_of_lsn)
        } else {
            Ok(runtime.get_incident(&id))
        }
    })
    .await
    .unwrap_or_else(|erro| Err(heraclitus_sentinel::SentinelError::Config(erro.to_string())));
    match result {
        Ok(Some(incident)) => Json(serde_json::json!({
            "incident_id": incident.incident_id,
            "evidence": incident.evidence
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "incident_not_found" })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct SentinelApprovalBody {
    approval_id: String,
    proposal_id: String,
    /// Opcional, e NAO e o que fica registado. Se vier, tem de coincidir com a
    /// identidade autenticada — um cliente que peca para registar outra pessoa
    /// leva 403 em vez de ser silenciosamente corrigido, para que a tentativa
    /// seja visivel.
    #[serde(default)]
    approver: Option<String>,
    #[serde(default)]
    reason: String,
}

async fn sentinel_approve(
    Extension(runtime): Extension<Option<Arc<SentinelRuntime>>>,
    Extension(identidade): Extension<IdentidadeRest>,
    Path(incident_id): Path<String>,
    Json(body): Json<SentinelApprovalBody>,
) -> Response {
    sentinel_approval(runtime, identidade, incident_id, body, true).await
}

async fn sentinel_deny(
    Extension(runtime): Extension<Option<Arc<SentinelRuntime>>>,
    Extension(identidade): Extension<IdentidadeRest>,
    Path(incident_id): Path<String>,
    Json(body): Json<SentinelApprovalBody>,
) -> Response {
    sentinel_approval(runtime, identidade, incident_id, body, false).await
}

async fn sentinel_approval(
    runtime: Option<Arc<SentinelRuntime>>,
    identidade: IdentidadeRest,
    incident_id: String,
    body: SentinelApprovalBody,
    approved: bool,
) -> Response {
    // O `approver` vinha do CORPO: qualquer chamador registava uma aprovacao
    // humana em nome de quem quisesse, e um registo de aprovacao existe
    // precisamente para atribuir responsabilidade. Agora o registado e sempre a
    // identidade autenticada.
    //
    // Esta verificacao vem ANTES da guarda do runtime de proposito: tentar
    // registar uma aprovacao em nome de outra pessoa e um erro do PEDIDO, e a
    // resposta a isso nao pode depender de o sentinel estar ou nao ligado.
    let approver = match crate::auth::vincular_aprovador(body.approver.as_deref(), &identidade.0) {
        Ok(a) => a.to_owned(),
        Err(erro) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": erro })),
            )
                .into_response();
        }
    };
    let Some(runtime) = runtime else {
        return sentinel_unavailable();
    };
    let result = tokio::task::spawn_blocking(move || {
        runtime.persist_human_approval_for(
            &incident_id,
            &body.proposal_id,
            &body.approval_id,
            &approver,
            approved,
            &body.reason,
        )
    })
    .await;
    match result {
        Ok(Ok(lsn)) => Json(serde_json::json!({
            "approved": approved,
            "approval_lsn": lsn
        }))
        .into_response(),
        Ok(Err(error)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

fn l4_json(lsn: u64, episode: &heraclitus_core::Episode) -> serde_json::Value {
    serde_json::json!({
        "lsn": lsn,
        "id": episode.id.to_string(),
        "kind": episode.kind.label(),
        "content": bytes_str(&episode.content),
        "attrs": episode.attrs,
        "parents": episode.parents.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

async fn sentinel_actions(
    Extension(runtime): Extension<Option<Arc<SentinelRuntime>>>,
    Query(query): Query<SentinelIncidentQuery>,
) -> Response {
    let Some(runtime) = runtime else {
        return sentinel_unavailable();
    };
    let limit = query.limit.unwrap_or(100).min(10_000);
    let result = tokio::task::spawn_blocking(move || {
        runtime.l4_events(None, query.incident_id.as_deref(), query.as_of_lsn, limit)
    })
    .await;
    match result {
        Ok(Ok(rows)) => {
            let actions: Vec<_> = rows
                .into_iter()
                .filter(|(_, episode)| {
                    matches!(
                        &episode.kind,
                        heraclitus_core::EventKind::Custom(kind)
                            if kind == "SecurityActionProposal" || kind == "SecurityActionResult"
                    )
                })
                .map(|(lsn, episode)| l4_json(lsn, &episode))
                .collect();
            Json(serde_json::json!({ "actions": actions, "count": actions.len() })).into_response()
        }
        Ok(Err(error)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn sentinel_action(
    Extension(runtime): Extension<Option<Arc<SentinelRuntime>>>,
    Path(id): Path<String>,
) -> Response {
    let Some(runtime) = runtime else {
        return sentinel_unavailable();
    };
    let result = tokio::task::spawn_blocking(move || {
        let rows = runtime.l4_events(None, None, None, 10_000)?;
        Ok::<_, heraclitus_sentinel::SentinelError>(rows.into_iter().find(|(_, episode)| {
            episode
                .attrs
                .get("sentinel.action_proposal_id")
                .map(String::as_str)
                == Some(id.as_str())
                || episode.attrs.get("sentinel.action_id").map(String::as_str) == Some(id.as_str())
        }))
    })
    .await;
    match result {
        Ok(Ok(Some((lsn, episode)))) => Json(l4_json(lsn, &episode)).into_response(),
        Ok(Ok(None)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "action_not_found" })),
        )
            .into_response(),
        Ok(Err(error)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn sentinel_incident_why(
    Extension(runtime): Extension<Option<Arc<SentinelRuntime>>>,
    Path(id): Path<String>,
    Query(query): Query<SentinelIncidentQuery>,
) -> Response {
    let Some(runtime) = runtime else {
        return sentinel_unavailable();
    };
    let as_of = query.as_of_lsn;
    let result = tokio::task::spawn_blocking(move || {
        let incident = match as_of {
            Some(lsn) => runtime.incident_as_of(&id, lsn)?,
            None => runtime.get_incident(&id),
        };
        let records = runtime.l4_events(None, Some(&id), as_of, 10_000)?;
        Ok::<_, heraclitus_sentinel::SentinelError>((incident, records))
    })
    .await;
    match result {
        Ok(Ok((Some(incident), records))) => {
            let records: Vec<_> = records
                .iter()
                .map(|(lsn, episode)| l4_json(*lsn, episode))
                .collect();
            Json(serde_json::json!({
                "incident": incident,
                "why": {
                    "evidence": incident.evidence,
                    "risk_score": incident.risk_score,
                    "records": records
                }
            }))
            .into_response()
        }
        Ok(Ok((None, _))) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "incident_not_found" })),
        )
            .into_response(),
        Ok(Err(error)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn sentinel_dashboard(
    Extension(runtime): Extension<Option<Arc<SentinelRuntime>>>,
) -> Response {
    let Some(runtime) = runtime else {
        return sentinel_unavailable();
    };
    let result = tokio::task::spawn_blocking(move || {
        let status = runtime.status();
        let incidents = runtime.current_incidents();
        let actions = runtime.l4_events(None, None, None, 10_000)?;
        Ok::<_, heraclitus_sentinel::SentinelError>((status, incidents, actions))
    })
    .await;
    match result {
        Ok(Ok((status, incidents, actions))) => {
            let active = incidents
                .iter()
                .filter(|incident| {
                    !matches!(
                        incident.state,
                        IncidentState::Resolved | IncidentState::FalsePositive
                    )
                })
                .count();
            let critical = incidents
                .iter()
                .filter(|incident| incident.severity >= 8)
                .count();
            let approvals = actions
                .iter()
                .filter(|(_, episode)| matches!(&episode.kind, heraclitus_core::EventKind::Custom(kind) if kind == "SecurityApproval"))
                .count();
            Json(serde_json::json!({
                "status": status,
                "threat_level": if critical > 0 { "critical" } else if active > 0 { "elevated" } else { "normal" },
                "active_incidents": active,
                "critical_incidents": critical,
                "pending_approvals": approvals,
                "incidents": incidents,
                "why_endpoint": "/sentinel/incidents/:id/why"
            }))
            .into_response()
        }
        Ok(Err(error)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

/// CORS por lista explícita de origens. Vazio ⇒ nenhum cabeçalho, que é o
/// comportamento histórico.
///
/// Escrito à mão em vez de puxar o `tower-http`: são 30 linhas, e a política
/// aqui é restritiva de um modo que a camada genérica tornaria fácil de
/// afrouxar por acidente. **Nunca emite `*`** — este REST tem rotas que
/// escrevem e liga-se a `127.0.0.1`; um wildcard deixaria qualquer página que
/// o operador visitasse falar com a base de dados dele através do browser.
fn aplicar_cors(routes: Router, origens: Vec<String>) -> Router {
    // Validar à entrada em vez de confiar. Uma origem malformada nunca vai
    // casar com o `Origin` que o browser envia, e o sintoma seria o painel a
    // dizer "bloqueado por CORS" com a configuração aparentemente correta —
    // horas a depurar o lado errado. Um `*` aqui seria pior: o operador
    // pensaria tê-lo autorizado e o código ignorá-lo-ia em silêncio.
    let (validas, rejeitadas): (Vec<String>, Vec<String>) = origens.into_iter().partition(|o| {
        // Forma de "serialized origin" (RFC 6454): esquema://host[:porta], sem
        // barra final, sem caminho, sem wildcard.
        (o.starts_with("http://") || o.starts_with("https://"))
            && !o.contains('*')
            && !o.ends_with('/')
            && o.matches('/').count() == 2
    });
    for r in &rejeitadas {
        tracing::warn!(
            origem = %r,
            "rest_cors_origins: entrada IGNORADA — tem de ser esquema://host[:porta], \
             sem barra final e sem `*` (o wildcard nunca é aceite nesta superfície)"
        );
    }
    if validas.is_empty() {
        if !rejeitadas.is_empty() {
            tracing::warn!("rest_cors_origins: nenhuma origem válida — CORS fica DESLIGADO");
        }
        return routes;
    }
    tracing::info!(origens = ?validas, "CORS ativo para estas origens");
    let permitidas = Arc::new(validas);
    routes.layer(middleware::from_fn(move |req: Request, next: Next| {
        let permitidas = permitidas.clone();
        async move {
            let autorizada = req
                .headers()
                .get(header::ORIGIN)
                .and_then(|v| v.to_str().ok())
                .filter(|o| permitidas.iter().any(|p| p == o))
                .map(|o| o.to_string());

            // Preflight: responder aqui, sem tocar no handler.
            if req.method() == axum::http::Method::OPTIONS {
                let mut b = Response::builder().status(StatusCode::NO_CONTENT);
                if let Some(o) = &autorizada {
                    b = b
                        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, o.as_str())
                        .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS")
                        .header(
                            header::ACCESS_CONTROL_ALLOW_HEADERS,
                            "authorization, content-type",
                        )
                        // SEM `Allow-Credentials`, deliberadamente. O painel
                        // envia `Authorization` explicitamente, portanto não
                        // precisa dele. COM ele, bastava o operador ter feito
                        // login uma vez neste servidor no browser: qualquer
                        // página servida na origem autorizada podia então fazer
                        // `fetch(..., {credentials:'include'})`, o browser
                        // anexava sozinho a credencial guardada, e o cabeçalho
                        // tornava a resposta LEGÍVEL — leitura do log inteiro e
                        // escrita por /hvm/*, sem nunca saber a password.
                        .header(header::ACCESS_CONTROL_MAX_AGE, "600")
                        // Sem `Vary: Origin` um intermediário podia servir a
                        // resposta de uma origem autorizada a outra qualquer.
                        .header(header::VARY, "Origin");
                }
                return b.body("".into()).unwrap();
            }

            let mut resp = next.run(req).await;
            if let Some(o) = autorizada {
                let h = resp.headers_mut();
                if let Ok(v) = o.parse() {
                    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
                }
                // `append` e nao `insert`: um handler pode ja ter posto o seu
                // proprio `Vary`, e substitui-lo estragaria a chave de cache dele.
                h.append(header::VARY, "Origin".parse().unwrap());
            }
            resp
        }
    }))
}

/// `GET /live/events` → SSE com **metadados** de cada append confirmado.
///
/// O log já emitia isto: `Log::tail_subscribe` devolve um broadcast alimentado
/// pelo worker a cada registo commitado. Não havia era quem o expusesse.
///
/// ## O que NÃO vai no fluxo, e porquê
///
/// Nem `content` nem os valores dos `attrs`. O broadcast do log transporta o
/// episódio **antes de ser cifrado** — a cifra é aplicada ao payload que vai
/// para o disco, não à cópia que segue para o canal. Ou seja, com
/// `encryption_at_rest` ligado, o que está guardado vai cifrado mas o que passa
/// aqui iria em claro. Reencaminhar isso para um browser desfazia exatamente o
/// que a cifra em repouso e o crypto-shred existem para proteger.
///
/// ## O que vai, e a ressalva que fica
///
/// `lsn`, `agent_id`, `kind`, `bytes` e o instante. É quanto basta para ver
/// ritmo, origem e mistura de tipos.
///
/// **Ressalva séria:** no modelo do Forge o `agent_id` é o **titular** dos
/// dados (`titular:<id>`), não o produtor — é a chave por que o
/// crypto-shred apaga. Está pseudonimizado por HMAC na ponte, portanto não é
/// diretamente identificante, mas é um pseudónimo estável por pessoa. Este
/// endpoint fica atrás da autenticação de administração, o que é proporcional
/// para quem já podia consultar tudo por `/sql` — **mas um painel destes num
/// ecrã de parede tem outra exposição**. Quem o puser à vista deve pensar nisso.
async fn live_events(
    State(engine): State<Arc<Engine>>,
) -> axum::response::Sse<
    impl tokio_stream::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use tokio_stream::StreamExt;

    let rx = engine.log.tail_subscribe();
    let fluxo = tokio_stream::wrappers::BroadcastStream::new(rx).map(|item| {
        let dado = match item {
            Ok((lsn, ep)) => serde_json::json!({
                "lsn": lsn,
                "agent_id": ep.agent_id,
                "kind": rotulo_kind(&ep.kind),
                "bytes": ep.content.len(),
                "attrs": ep.attrs.len(),
                // Como STRING, nao como numero. Um HLC ronda 1,17e17, e o
                // `Number` do JavaScript so e exato ate 2^53 (9,0e15): ao
                // desserializar, os 16 bits do contador logico eram
                // silenciosamente arredondados. Quem comparasse dois `ts_hlc`
                // vindos do painel podia ve-los iguais sendo diferentes — num
                // sistema cuja premissa e a ordem total dos eventos.
                "ts_hlc": ep.ts_hlc.to_string(),
                // O HLC é `(milissegundos << 16) | contador` (core/src/hlc.rs).
                // Enviar já em milissegundos evita que o cliente tenha de
                // deslocar 64 bits — em JavaScript o `>>` é de 32 e truncava.
                "t_ms": ep.ts_hlc >> 16,
            }),
            // O canal tem 4096 de folga. Um cliente mais lento que a ingestão
            // fica para trás e o broadcast descarta — que é o correto numa
            // vista AO VIVO (quer-se o agora, não a fila). Mas tem de ser dito:
            // um painel que silenciosamente salta 200 mil eventos mente sobre
            // o que mostra.
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                serde_json::json!({ "saltados": n })
            }
        };
        Ok(Event::default().data(dado.to_string()))
    });

    Sse::new(fluxo).keep_alive(KeepAlive::default())
}

/// Rótulo estável para o tipo de evento. `Custom` já traz o nome; os restantes
/// usam o `Debug` da variante.
fn rotulo_kind(k: &heraclitus_core::EventKind) -> String {
    match k {
        heraclitus_core::EventKind::Custom(s) => s.clone(),
        outro => format!("{outro:?}"),
    }
}

/// `GET /replay[?executar=1]` — prova de reconstrução determinista.
///
/// Sem `executar`, devolve só os hashes atuais: barato, não toca em nada, e
/// serve para comparar com outra instância ou outro momento.
///
/// Com `executar=1`, reconstrói as views a partir do LSN 0 e compara os hashes
/// antes/depois. É caro e mexe nas views vivas — nunca acontece por omissão.
async fn replay(
    State(engine): State<Arc<Engine>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Um GET NÃO muta estado. `GET /replay?executar=1` disparava um rebuild
    // completo desde o LSN 0 — trabalho pesado e destrutivo de estado derivado,
    // alcançável por uma simples navegação: uma tag `<img>` numa página
    // qualquer bastava, porque um GET não é protegido por CORS (o browser
    // envia-o e só esconde a resposta) e a auth REST é opcional em loopback.
    //
    // O GET fica com a prova em seco. Quem quer executar usa POST — e recusar
    // explicitamente é melhor do que ignorar o parâmetro em silêncio, porque
    // quem já dependia disto fica a saber, em vez de deixar de reconstruir sem
    // reparar.
    if matches!(
        q.get("executar").map(|s| s.as_str()),
        Some("1") | Some("true")
    ) {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(serde_json::json!({
                "error": "executar=1 muta estado e exige POST /replay",
                "hint": "GET /replay devolve a prova sem reconstruir"
            })),
        )
            .into_response();
    }
    replay_executar(State(engine), false).await
}

/// `POST /replay[?executar=1]` — o mesmo, com autorização para reconstruir.
async fn replay_post(
    State(engine): State<Arc<Engine>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let executar = matches!(
        q.get("executar").map(|s| s.as_str()),
        Some("1") | Some("true")
    );
    replay_executar(State(engine), executar).await
}

async fn replay_executar(State(engine): State<Arc<Engine>>, executar: bool) -> Response {
    let out = tokio::task::spawn_blocking(move || engine.replay_prova(executar))
        .await
        .unwrap_or_else(|e| serde_json::json!({ "erro": format!("join: {e}") }));
    Json(out).into_response()
}

/// `GET /fontes` — quem escreve neste log, quanto, e desde/ate quando.
async fn fontes(State(engine): State<Arc<Engine>>) -> Json<serde_json::Value> {
    // `spawn_blocking`: percorre o indice de atributos e o catalogo. Ver o
    // comentario do `/sentinel/checkpoint`.
    Json(
        tokio::task::spawn_blocking(move || engine.fontes())
            .await
            .unwrap_or_else(|e| serde_json::json!({ "error": format!("join: {e}") })),
    )
}

/// `GET /fontes/:id` — características de uma fonte: tipos, campos, principais.
async fn fonte_detalhe(
    State(engine): State<Arc<Engine>>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let out = tokio::task::spawn_blocking(move || engine.fonte_detalhe(&id, 2_000))
        .await
        .unwrap_or_else(|e| serde_json::json!({ "error": format!("join: {e}") }));
    Json(out)
}

/// `GET /atributos` — campos indexados e cardinalidade (matéria-prima do ROPA).
async fn atributos(State(engine): State<Arc<Engine>>) -> Json<serde_json::Value> {
    // `spawn_blocking` pela mesma razao do `/fontes`.
    Json(
        tokio::task::spawn_blocking(move || engine.atributos())
            .await
            .unwrap_or_else(|e| serde_json::json!({ "error": format!("join: {e}") })),
    )
}

/// `GET /diff?de=&ate=` — o que mudou entre dois instantes do log.
///
/// As pontas aceitam-se em LSN (`de`/`ate`) ou em milissegundos epoch
/// (`de_ms`/`ate_ms`), que sao convertidos por busca binaria sobre o log. A
/// forma por tempo e a que uma pessoa usa; a forma por LSN e a que um auditor
/// cita, porque nao depende de relogios.
///
/// Sem qualquer parametro, a janela e a ultima hora.
async fn diff(
    State(engine): State<Arc<Engine>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let num = |k: &str| q.get(k).and_then(|v| v.parse::<u64>().ok());
    let (de_ms, ate_ms, de_lsn, ate_lsn) = (num("de_ms"), num("ate_ms"), num("de"), num("ate"));
    let topo = num("topo").unwrap_or(12).clamp(1, 200) as usize;

    let out = tokio::task::spawn_blocking(move || {
        let head = engine.head();
        let ate = ate_lsn
            .or_else(|| ate_ms.map(|m| engine.lsn_em(m)))
            .unwrap_or(head);
        let de = de_lsn
            .or_else(|| de_ms.map(|m| engine.lsn_em(m)))
            .unwrap_or_else(|| {
                // Sem janela pedida: a ultima hora de INGESTAO. Cair para "desde o
                // inicio" seria pior — num log grande devolve tudo como "novo" e da
                // a impressao de que tudo apareceu agora.
                match engine.ts_ms(ate.saturating_sub(1)) {
                    Some(ms) => engine.lsn_em(ms.saturating_sub(3_600_000)),
                    None => 0,
                }
            });
        engine.diff(de, ate, topo)
    })
    .await
    .unwrap_or_else(|e| serde_json::json!({ "error": format!("join: {e}") }));
    Json(out)
}

/// `GET /titular/:id` — pegada de um titular (LGPD art. 18, I e II).
/// Devolve METADADOS: quantos eventos, de que tipos, desde quando, e se a
/// chave dele ainda existe. Nunca devolve conteudo.
async fn titular(
    State(engine): State<Arc<Engine>>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    Json(engine.titular(&id, 50))
}

/// `GET /titular/:id/acessos` — eventos de auditoria que mencionam este titular.
async fn titular_acessos(
    State(engine): State<Arc<Engine>>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let out = tokio::task::spawn_blocking(move || engine.titular_acessos(&id, 100))
        .await
        .unwrap_or_else(|e| serde_json::json!({ "error": format!("join: {e}") }));
    Json(out)
}

/// `POST /titular/:id/eliminar` — crypto-shred (LGPD art. 18, VI).
///
/// DESLIGADO por omissao. Ver `HeraclitusConfig::rest_allow_erasure`: a
/// operacao e irreversivel e o REST so tem Basic auth, que nao distingue
/// papeis. Com o interruptor a `false` responde 403 **e diz qual o comando
/// gRPC equivalente**, que passa pelo RBAC — recusar sem indicar o caminho
/// certo so leva a que alguem procure um atalho pior.
///
/// Exige `{"confirmar": "<id>"}` no corpo: um POST acidental nao apaga nada.
async fn titular_eliminar(
    State(engine): State<Arc<Engine>>,
    Extension(erasure): Extension<ErasureAllowed>,
    Path(id): Path<String>,
    Json(corpo): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !erasure.0 {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "eliminacao pelo REST desligada (rest_allow_erasure = false)",
                "alternativa": format!("Admin RPC com op = \"shred:{id}\", que passa pelo RBAC do gRPC"),
            })),
        );
    }
    if corpo.get("confirmar").and_then(|v| v.as_str()) != Some(id.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "confirmacao em falta: o corpo tem de trazer {\"confirmar\": \"<id>\"}",
            })),
        );
    }
    let alvo = id.clone();
    let r = tokio::task::spawn_blocking(move || engine.shred(&alvo)).await;
    match r {
        Ok(Ok(destruida)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "chave_destruida": destruida,
                "nota": if destruida {
                    "Chave destruida. O log NAO foi alterado: a cadeia Merkle continua a verificar."
                } else {
                    "Nao havia chave para este titular (ja eliminado, ou nunca escreveu)."
                },
            })),
        ),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("join: {e}") })),
        ),
    }
}

/// `GET /flight/events[?as_of=N]` → corpo `application/vnd.apache.arrow.stream`.
#[cfg(feature = "analytics")]
async fn flight_events(
    State(engine): State<Arc<Engine>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let as_of = q.get("as_of").and_then(|v| v.parse::<u64>().ok());
    let log = engine.log.clone();
    // Materialização em spawn_blocking: nunca no executor async.
    let body = tokio::task::spawn_blocking(move || {
        heraclitus_analytics::flight::events_as_single_ipc(&log, as_of)
    })
    .await;
    match body {
        Ok(Ok(bytes)) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/vnd.apache.arrow.stream")
            .body(bytes.into())
            .unwrap(),
        Ok(Err(e)) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("flight: {e}").into())
            .unwrap(),
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("join: {e}").into())
            .unwrap(),
    }
}

/// `POST /sql` — corpo JSON `{"sql":"SELECT ... FROM events ...","as_of":123}`
/// (`as_of` opcional). Devolve as linhas como array JSON. Feature `analytics`:
/// SQL OLAP **read-only** (DataFusion) sobre a tabela `events` materializada do
/// log — a via de agregação sancionada pela I4 (não duplicamos o DataFusion).
/// Admin-gated pela mesma Basic Auth do router.
///
/// Caveat: `LogAnalytics::from_log` materializa o log até ao head (ou `as_of`)
/// por chamada — usar `as_of` e `LIMIT`/`WHERE` para consultas grandes.
#[cfg(feature = "analytics")]
async fn sql(State(engine): State<Arc<Engine>>, Json(body): Json<serde_json::Value>) -> Response {
    use axum::response::IntoResponse;
    let Some(query) = body.get("sql").and_then(|v| v.as_str()).map(str::to_owned) else {
        return (StatusCode::BAD_REQUEST, "corpo requer o campo string `sql`").into_response();
    };
    let as_of = body.get("as_of").and_then(|v| v.as_u64());
    match run_sql(&engine, query, as_of).await {
        Ok(rows) => Json(serde_json::Value::Array(rows)).into_response(),
        Err((code, msg)) => (code, msg).into_response(),
    }
}

/// Orçamento de materialização de UM `POST /sql` (admission control).
///
/// Um `tokio::time::timeout` à volta de um `spawn_blocking` **não cancela** a
/// tarefa bloqueante: no timeout o handler devolvia 408 e a materialização
/// CONTINUAVA a alocar em segundo plano, pelo que pedidos sucessivos se
/// empilhavam até ao OOM — o timeout dava a ilusão de proteção sem proteger. O
/// que limita de facto é um teto DENTRO do trabalho bloqueante, que o faz
/// terminar sozinho; daí o orçamento explícito em vez do timeout na construção.
#[cfg(feature = "analytics")]
const SQL_MAX_ROWS: usize = 2_000_000;
#[cfg(feature = "analytics")]
const SQL_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Núcleo testável de `POST /sql`: materializa o log em `spawn_blocking` (nunca
/// no executor async) e corre o SQL no DataFusion. Erro de SQL do utilizador =
/// 400; falha interna (scan/join) = 500; orçamento excedido = 413.
#[cfg(feature = "analytics")]
async fn run_sql(
    engine: &Engine,
    query: String,
    as_of: Option<u64>,
) -> Result<Vec<serde_json::Value>, (StatusCode, String)> {
    let log = engine.log.clone();
    let analytics = tokio::task::spawn_blocking(move || {
        heraclitus_analytics::LogAnalytics::from_log_capped(
            &log,
            as_of,
            SQL_MAX_ROWS,
            SQL_MAX_BYTES,
        )
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")))?
    .map_err(|e| match e {
        // Orçamento excedido é erro do PEDIDO (demasiado largo), não do servidor.
        heraclitus_analytics::AnalyticsError::Budget { .. } => {
            (StatusCode::PAYLOAD_TOO_LARGE, e.to_string())
        }
        other => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("analytics: {other}"),
        ),
    })?;

    // Aqui o timeout é eficaz: `analytics.sql` é um futuro async, que ao ser
    // largado é mesmo cancelado (ao contrário do `spawn_blocking` acima).
    let rows = tokio::time::timeout(std::time::Duration::from_secs(30), analytics.sql(&query))
        .await
        .map_err(|_| {
            (
                StatusCode::REQUEST_TIMEOUT,
                "timeout executando SQL".to_string(),
            )
        })?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("sql: {e}")))?;

    if rows.len() > 10_000 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "Conjunto de resultados muito grande (> 10.000 linhas). Utilize LIMIT.".to_string(),
        ));
    }

    Ok(rows)
}

// ── M20 H-VM ledger (KV soberano durável no log) ─────────────────────────────

/// Representa bytes do ledger de forma **injetiva e sem perdas**: UTF-8 válido
/// que não comece por `hex:` vai literal (legível — o caso comum, já que
/// `/hvm/upsert` só aceita `key`/`val` string); qualquer outra coisa (bytes
/// não-UTF-8, ou um literal que colidiria com o prefixo) vira `hex:<hex>`.
///
/// Sem isto, `from_utf8_lossy` mapeava bytes distintos para o MESMO string (com
/// `U+FFFD`): duas chaves binárias diferentes colapsavam na mesma chave JSON e
/// uma sobrescrevia a outra ⇒ entradas desapareciam da resposta. O esquema é
/// injetivo (literais e `hex:…` vivem em namespaces disjuntos; o hex é 1-para-1).
pub(crate) fn bytes_str(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) if !s.starts_with("hex:") => s.to_string(),
        _ => {
            use std::fmt::Write;
            let mut out = String::with_capacity(4 + b.len() * 2);
            out.push_str("hex:");
            for byte in b {
                let _ = write!(out, "{byte:02x}");
            }
            out
        }
    }
}

/// Vista JSON do estado do ledger H-VM (usada pelo handler e testável sem HTTP).
/// Chaves e valores são bytes: renderizados via [`hvm_bytes_str`] (UTF-8 legível
/// quando possível, senão `hex:…`), mais os LSNs de consistência.
fn hvm_state_json(engine: &Engine) -> Result<serde_json::Value, String> {
    let state = engine.hvm_state().map_err(|e| format!("hvm: {e}"))?;
    let entries: serde_json::Map<String, serde_json::Value> = state
        .memory_layers
        .iter()
        .map(|(k, v)| (bytes_str(k), serde_json::Value::String(bytes_str(v))))
        .collect();
    Ok(serde_json::json!({
        "current_lsn": state.current_lsn,
        "max_lsn_applied": state.max_lsn_applied,
        "entries": entries,
    }))
}

/// `GET /hvm/state` → o espaço KV do ledger H-VM (M20) + os LSNs, como JSON.
async fn hvm_state(State(engine): State<Arc<Engine>>) -> Response {
    use axum::response::IntoResponse;
    // Replay do ledger é bloqueante → spawn_blocking (nunca no reactor).
    match tokio::task::spawn_blocking(move || hvm_state_json(&engine)).await {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")).into_response(),
    }
}

/// `POST /hvm/upsert` — corpo `{"key":"…","val":"…"}` (UTF-8) → `{"lsn":n}`.
/// Escrita no ledger via `Engine::append` — logo pelo **consenso** quando a
/// replicação está ativa (num não-líder devolve erro com o hint do líder).
async fn hvm_upsert(
    State(engine): State<Arc<Engine>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    use axum::response::IntoResponse;
    let (Some(key), Some(val)) = (
        body.get("key").and_then(|v| v.as_str()),
        body.get("val").and_then(|v| v.as_str()),
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            "corpo requer os campos string `key` e `val`",
        )
            .into_response();
    };
    let (key, val) = (key.as_bytes().to_vec(), val.as_bytes().to_vec());
    match tokio::task::spawn_blocking(move || engine.hvm_upsert(key, val)).await {
        Ok(Ok(lsn)) => Json(serde_json::json!({ "lsn": lsn })).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("hvm: {e}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")).into_response(),
    }
}

/// `POST /hvm/delete` — corpo `{"key":"…"}` → `{"lsn":n}`.
async fn hvm_delete(
    State(engine): State<Arc<Engine>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    use axum::response::IntoResponse;
    let Some(key) = body.get("key").and_then(|v| v.as_str()) else {
        return (StatusCode::BAD_REQUEST, "corpo requer o campo string `key`").into_response();
    };
    let key = key.as_bytes().to_vec();
    match tokio::task::spawn_blocking(move || engine.hvm_delete(key)).await {
        Ok(Ok(lsn)) => Json(serde_json::json!({ "lsn": lsn })).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("hvm: {e}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")).into_response(),
    }
}

/// `POST /hvm/checkpoint` (sem corpo) — materializa o ledger num Bᵋ-tree no
/// caminho do **servidor** (`<data_dir>/hvm.hbt`; NUNCA um caminho do cliente) →
/// `{"ok":true,"path":"…"}`. É o que traz o `heraclitus-btree` ao caminho vivo.
async fn hvm_checkpoint(State(engine): State<Arc<Engine>>) -> Response {
    use axum::response::IntoResponse;
    match tokio::task::spawn_blocking(move || engine.hvm_checkpoint_default()).await {
        Ok(Ok(path)) => {
            Json(serde_json::json!({ "ok": true, "path": path.to_string_lossy() })).into_response()
        }
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("hvm: {e}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")).into_response(),
    }
}

// ── Cold tier (feature `tier`) ───────────────────────────────────────────────

/// `GET /tier/sealed` → ids dos segmentos selados (candidatos a demote).
#[cfg(feature = "tier")]
async fn tier_sealed(State(engine): State<Arc<Engine>>) -> Response {
    use axum::response::IntoResponse;
    Json(serde_json::json!({ "sealed": engine.sealed_segment_ids() })).into_response()
}

/// `POST /tier/demote` — corpo `{"segment": <id>}` → o `DemotionReceipt` (JSON).
/// Materializa o segmento selado no cold tier (object store local): `.hrkl` +
/// espelho Parquet + recibo Merkle apenso ao log. Recusado com 409 sob
/// replicação (o recibo appenda fora do consenso). Op de manutenção: o replay/
/// upload corre inline (aceitável para admin; não é hot-path).
#[cfg(feature = "tier")]
async fn tier_demote(
    State(engine): State<Arc<Engine>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    use axum::response::IntoResponse;
    // §2.6: o RECIBO já passa pelo consenso (Engine::append), mas o OBJETO cold
    // só é materializado no object store LOCAL deste nó — num cluster, os
    // seguidores teriam o recibo sem o objeto. O guard cai quando o store for
    // partilhado (nuvem via config).
    if engine.is_replicated() {
        return (
            StatusCode::CONFLICT,
            "demote requer object store partilhado sob replicacao",
        )
            .into_response();
    }
    let Some(seg) = body.get("segment").and_then(|v| v.as_u64()) else {
        return (
            StatusCode::BAD_REQUEST,
            "corpo requer o campo inteiro `segment`",
        )
            .into_response();
    };
    // demote faz fs::read + blake3 + encode Parquet + fsync — fora do reactor.
    let res = tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(engine.demote_segment_any(seg))
    })
    .await;
    match res {
        Ok(Ok(r)) => Json(demotion_receipt_json(&r)).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("tier: {e}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")).into_response(),
    }
}

/// `GET /tier/receipts` → recibos de demote no log (o que já foi para o cold tier).
#[cfg(feature = "tier")]
async fn tier_receipts(State(engine): State<Arc<Engine>>) -> Response {
    use axum::response::IntoResponse;
    // Scan do log em spawn_blocking (nunca no reactor).
    match tokio::task::spawn_blocking(move || engine.demotion_receipts_any()).await {
        Ok(Ok(rs)) => {
            let arr: Vec<_> = rs.iter().map(demotion_receipt_json).collect();
            Json(serde_json::json!({ "receipts": arr })).into_response()
        }
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("tier: {e}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")).into_response(),
    }
}

#[cfg(feature = "tier")]
fn demotion_receipt_json(r: &heraclitus_tier::AnyDemotionReceipt) -> serde_json::Value {
    match r {
        heraclitus_tier::AnyDemotionReceipt::V1(v1) => serde_json::json!({
            "receipt_version": 1,
            "segment_id": v1.segment_id,
            "object_path": v1.object_path,
            "parquet_path": v1.parquet_path,
            "record_count": v1.record_count,
            "min_lsn": v1.min_lsn,
            "max_lsn": v1.max_lsn,
            "logical_root": v1.blake3_root,
        }),
        heraclitus_tier::AnyDemotionReceipt::V2(v2) => serde_json::json!({
            "receipt_version": v2.receipt_version,
            "segment_id": v2.segment_id,
            "generation": v2.generation,
            "object_path": v2.object_path,
            "hrki_path": v2.hrki_path,
            "parquet_path": v2.parquet_path,
            "record_count": v2.record_count,
            "min_lsn": v2.first_lsn,
            "max_lsn": v2.last_lsn,
            "logical_root": v2.logical_root,
            "physical_digest": v2.physical_digest,
            "physical_layout": v2.physical_layout,
            "compression_codec": v2.compression_codec,
        }),
    }
}

/// `GET /tier/fetch/:segment` — recall: busca o segmento demotado do cold tier e
/// devolve os episódios (lsn/agent/kind/content). NÃO reinsere nos índices
/// quentes (recall-on-demand puro; a re-hidratação é follow-up).
#[cfg(feature = "tier")]
async fn tier_fetch(State(engine): State<Arc<Engine>>, Path(segment): Path<u64>) -> Response {
    use axum::response::IntoResponse;
    // fetch_cold_segment faz scan do log + decode do objeto — fora do reactor.
    let res = tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(engine.fetch_cold_segment(segment))
    })
    .await;
    match res {
        Ok(Ok(eps)) => {
            let arr: Vec<_> = eps
                .iter()
                .map(|(lsn, e)| {
                    serde_json::json!({
                        "lsn": lsn,
                        "agent_id": e.agent_id,
                        "kind": format!("{:?}", e.kind),
                        "content": bytes_str(&e.content),
                    })
                })
                .collect();
            Json(serde_json::json!({ "segment": segment, "count": arr.len(), "episodes": arr }))
                .into_response()
        }
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("tier: {e}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")).into_response(),
    }
}

async fn healthz() -> &'static str {
    "panta rhei"
}

/// `Engine::stats` toma os sete mutexes de índice. O checkpoint segura-os
/// enquanto serializa as views para disco — medido a 2026-09-02 com 8,6 M
/// eventos: 70 s a escrever 1,97 GiB, e um `GET /stats` iniciado dentro dessa
/// janela só respondeu 69,4 s depois. Fora do `spawn_blocking` cada pedido
/// nesse estado prende um fio do reactor durante todo o checkpoint, e um punhado
/// de scrapes de monitorização esgota o pool — os probes de saúde deixam de ser
/// servidos. Mesma razão pela qual `verify` já saiu do reactor.
async fn stats(State(engine): State<Arc<Engine>>) -> Response {
    match tokio::task::spawn_blocking(move || engine.stats()).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "stats_join_failed",
                "message": error.to_string()
            })),
        )
            .into_response(),
    }
}

async fn compliance_status(State(engine): State<Arc<Engine>>) -> Response {
    match tokio::task::spawn_blocking(move || engine.compliance_status()).await {
        Ok(Ok(snapshot)) => Json(snapshot).into_response(),
        Ok(Err(error)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "compliance_status_failed",
                "message": error.to_string()
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "compliance_status_join_failed",
                "message": error.to_string()
            })),
        )
            .into_response(),
    }
}

async fn telemetry_health(
    State(engine): State<Arc<Engine>>,
    Query(query): Query<TelemetryHealthQuery>,
) -> Json<serde_json::Value> {
    let as_of_lsn = query.as_of_lsn.unwrap_or_else(|| engine.head());
    // `spawn_blocking`: `telemetry_health_all` toma os locks dos índices e, com
    // `as_of`, reconstrói o estado a partir do log. Ver o comentário do
    // `/sentinel/checkpoint`.
    let sensors: Vec<_> = tokio::task::spawn_blocking(move || {
        engine
            .telemetry_health_all(Some(as_of_lsn))
            .into_iter()
            .filter(|snapshot| {
                query
                    .tenant_id
                    .as_ref()
                    .is_none_or(|value| &snapshot.identity.tenant_id == value)
                    && query
                        .datasource_id
                        .as_ref()
                        .is_none_or(|value| &snapshot.identity.datasource_id == value)
                    && query
                        .sensor_id
                        .as_ref()
                        .is_none_or(|value| &snapshot.identity.sensor_id == value)
            })
            .collect()
    })
    .await
    .unwrap_or_default();
    Json(serde_json::json!({
        "schema": "heraclitus-telemetry-health-snapshot/1.0",
        "as_of_lsn": as_of_lsn,
        "count": sensors.len(),
        "sensors": sensors,
    }))
}

async fn metrics(
    State(engine): State<Arc<Engine>>,
    Extension(sentinel): Extension<Option<Arc<SentinelRuntime>>>,
) -> Response {
    // `spawn_blocking`: o `prometheus_metrics` percorre o manifesto e conta
    // blocos por segmento. Ver o comentário do `/sentinel/checkpoint` — e este
    // é o handler que um scraper chama de quinze em quinze segundos, para
    // sempre, portanto é o pior de todos para deixar no reactor.
    let metricas = tokio::task::spawn_blocking({
        let engine = engine.clone();
        move || engine.prometheus_metrics()
    })
    .await
    .unwrap_or_else(|erro| {
        Err(heraclitus_core::HeraclitusError::StorageEngine(
            erro.to_string(),
        ))
    });
    match metricas {
        Ok(mut body) => {
            if let Some(runtime) = sentinel {
                let status = runtime.status();
                body.push_str(&format!(
                    concat!(
                        "\nsentinel_events_seen_total {}\n",
                        "sentinel_queue_depth {}\n",
                        "sentinel_queue_overflow_total {}\n",
                        "sentinel_catchup_lag_lsn {}\n",
                        "sentinel_l0_latency_us {}\n",
                        "sentinel_l1_latency_ms {}\n",
                        "sentinel_l2_latency_ms {}\n",
                        "sentinel_l3_latency_ms {}\n",
                        "sentinel_signals_total {}\n",
                        "sentinel_incidents_total {}\n",
                        "sentinel_ai_requests_total {}\n",
                        "sentinel_ai_failures_total {}\n",
                        "sentinel_ai_latency_ms {}\n",
                        "sentinel_ai_tokens_total {}\n",
                        "sentinel_actions_proposed_total {}\n",
                        "sentinel_actions_approved_total {}\n",
                        "sentinel_actions_denied_total {}\n",
                        "sentinel_actions_executed_total {}\n",
                        "sentinel_action_failures_total {}\n"
                    ),
                    status.events_seen_total,
                    status.queue_depth,
                    status.queue_overflow_total,
                    status.detection_lag_lsn,
                    status.l0_latency_us,
                    status.l1_latency_ms,
                    status.l2_latency_ms,
                    status.l3_latency_ms,
                    status.signals_emitted_total,
                    status.incidents_created_total,
                    status.ai_requests_total,
                    status.ai_failures_total,
                    status.ai_latency_ms,
                    status.ai_tokens_total,
                    status.actions_proposed_total,
                    status.actions_approved_total,
                    status.actions_denied_total,
                    status.actions_executed_total,
                    status.action_failures_total,
                ));
            }
            (
                StatusCode::OK,
                [(
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )],
                body,
            )
                .into_response()
        }
        Err(error) => (StatusCode::NOT_IMPLEMENTED, error.to_string()).into_response(),
    }
}

/// `heraclitus_state()`: head, segmentos e watermarks — diagnóstico num GET.
///
/// Percorre o manifesto inteiro (1394 segmentos na carga de 2026-09-02) e lê as
/// watermarks das views, portanto compete com o checkpoint pelos mesmos locks.
/// Vale aqui o mesmo que em `stats`: nunca no reactor.
async fn state(State(engine): State<Arc<Engine>>) -> Response {
    match tokio::task::spawn_blocking(move || engine.state()).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "state_join_failed",
                "message": error.to_string()
            })),
        )
            .into_response(),
    }
}

/// Verificação Merkle do log inteiro. `Log::verify` re-lê+re-hasha todos os
/// segmentos → `spawn_blocking` (nunca bloquear o reactor / os probes de saúde).
async fn verify(State(engine): State<Arc<Engine>>) -> (StatusCode, Json<serde_json::Value>) {
    // Uma falha de integridade saía com HTTP **200** e um `{"error": ...}` no
    // corpo. Um cliente que só olhasse ao estado — ou que procurasse campos que
    // ali não vinham — lia isso como sucesso: um painel chegou a escrever
    // "íntegro" por cima de uma corrupção detectada. A deteção de adulteração é
    // a razão de existir deste produto; não pode viajar como 200.
    match tokio::task::spawn_blocking(move || engine.verify()).await {
        Ok(Ok(v)) => (StatusCode::OK, Json(v)),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("join: {e}") })),
        ),
    }
}

/// Verificação Merkle pontual de um segmento (idem: em `spawn_blocking`).
async fn verify_segment(
    State(engine): State<Arc<Engine>>,
    Path(segment): Path<u64>,
) -> Json<serde_json::Value> {
    let out = match tokio::task::spawn_blocking(move || engine.verify_segment(segment)).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => serde_json::json!({ "error": e.to_string() }),
        Err(e) => serde_json::json!({ "error": format!("join: {e}") }),
    };
    Json(out)
}

#[cfg(all(test, feature = "analytics"))]
mod sql_tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusConfig};

    fn engine_in(dir: &std::path::Path) -> Engine {
        let cfg = HeraclitusConfig {
            data_dir: dir.to_path_buf(),
            fsync: FsyncPolicy::Always,
            ..Default::default()
        };
        Engine::open(&cfg).unwrap()
    }

    /// Gate: a via ligada (`run_sql`) devolve o mesmo que chamar o `LogAnalytics`
    /// de referência diretamente — o wiring nunca altera o resultado. Cobre
    /// também `as_of` e o erro 400 sem pânico.
    #[tokio::test]
    async fn post_sql_group_by_matches_reference() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        for i in 0..12 {
            let e = Episode::new(
                if i % 3 == 0 { "alice" } else { "bob" },
                EventKind::Observation,
                format!("evento {i}").into_bytes(),
            );
            engine.append(e).unwrap();
        }
        let q = "SELECT agent_id, COUNT(*) AS n FROM events GROUP BY agent_id ORDER BY agent_id";

        // Via ligada (o que o handler POST /sql executa).
        let rows = run_sql(&engine, q.to_owned(), None).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["agent_id"], "alice");
        assert_eq!(rows[0]["n"], 4);
        assert_eq!(rows[1]["agent_id"], "bob");
        assert_eq!(rows[1]["n"], 8);

        // Referência: o mesmo SQL direto no LogAnalytics.
        let reference = {
            let log = engine.log.clone();
            let a = heraclitus_analytics::LogAnalytics::from_log(&log, None).unwrap();
            a.sql(q).await.unwrap()
        };
        assert_eq!(rows, reference, "a via ligada difere da referência");

        // Snapshot AS OF: só lsn < 6.
        let as_of = run_sql(
            &engine,
            "SELECT COUNT(*) AS n FROM events".to_owned(),
            Some(6),
        )
        .await
        .unwrap();
        assert_eq!(as_of[0]["n"], 6);

        // SQL inválido = 400, nunca pânico.
        let bad = run_sql(&engine, "SELECT x FROM tabela_inexistente".to_owned(), None).await;
        assert_eq!(bad.unwrap_err().0, StatusCode::BAD_REQUEST);
    }
}

#[cfg(test)]
mod hvm_tests {
    use super::*;
    use heraclitus_core::{FsyncPolicy, HeraclitusConfig};

    fn engine_in(dir: &std::path::Path) -> Engine {
        let cfg = HeraclitusConfig {
            data_dir: dir.to_path_buf(),
            fsync: FsyncPolicy::Always,
            ..Default::default()
        };
        Engine::open(&cfg).unwrap()
    }

    /// A vista JSON que o `GET /hvm/state` serve reflete o ledger após
    /// upsert/delete — prova o núcleo do wiring do endpoint sem precisar de HTTP.
    #[test]
    fn hvm_state_json_reflects_the_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        engine
            .hvm_upsert(b"user:1".to_vec(), b"alice".to_vec())
            .unwrap();
        engine
            .hvm_upsert(b"user:2".to_vec(), b"bob".to_vec())
            .unwrap();
        engine.hvm_delete(b"user:1".to_vec()).unwrap();

        let v = hvm_state_json(&engine).unwrap();
        assert_eq!(v["entries"]["user:2"], "bob");
        assert!(
            v["entries"].get("user:1").is_none(),
            "chave apagada não aparece"
        );
        // 3 instruções escritas (upsert/upsert/delete), LSNs 0-indexados ⇒ 2.
        assert!(v["max_lsn_applied"].as_u64().unwrap() >= 2);
    }

    /// Auditoria §6.2: chaves binárias distintas NÃO podem colapsar. Com
    /// `from_utf8_lossy` ambas viravam a mesma string (`U+FFFD`) e uma
    /// sobrescrevia a outra no mapa JSON — uma entrada desaparecia. O esquema
    /// `hex:` é injetivo, por isso as duas sobrevivem com valores próprios.
    #[test]
    fn non_utf8_keys_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        // Dois bytes inválidos em UTF-8, distintos entre si; from_utf8_lossy
        // mapearia ambos para "\u{FFFD}".
        engine.hvm_upsert(vec![0xff], b"um".to_vec()).unwrap();
        engine.hvm_upsert(vec![0xfe], b"dois".to_vec()).unwrap();
        // Valor binário também: deve sair como hex, não corrompido em silêncio.
        engine
            .hvm_upsert(b"bin".to_vec(), vec![0x00, 0xff])
            .unwrap();

        let v = hvm_state_json(&engine).unwrap();
        let entries = v["entries"].as_object().unwrap();
        // As duas chaves binárias sobrevivem, cada uma com o SEU valor.
        assert_eq!(entries["hex:ff"], "um");
        assert_eq!(entries["hex:fe"], "dois");
        assert_eq!(entries.len(), 3, "nenhuma entrada colapsou");
        // Chave UTF-8 continua legível; valor binário vai em hex.
        assert_eq!(entries["bin"], "hex:00ff");
    }

    /// O prefixo `hex:` reservado não pode ser ambíguo: uma chave UTF-8 que já
    /// comece por `hex:` é ela própria codificada, para nunca colidir com a
    /// forma codificada de uma chave binária.
    #[test]
    fn literal_hex_prefix_is_disambiguated() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        // Chave literal "hex:ff" (texto) vs. chave binária 0xff (→ "hex:ff").
        engine
            .hvm_upsert(b"hex:ff".to_vec(), b"literal".to_vec())
            .unwrap();
        engine.hvm_upsert(vec![0xff], b"binario".to_vec()).unwrap();

        let v = hvm_state_json(&engine).unwrap();
        let entries = v["entries"].as_object().unwrap();
        assert_eq!(entries.len(), 2, "as duas não colidem apesar do prefixo");
        // O literal "hex:ff" é re-codificado (hex de b"hex:ff"); o binário 0xff
        // fica "hex:ff". Chaves distintas ⇒ ambas presentes.
        assert_eq!(entries["hex:ff"], "binario");
        assert_eq!(entries["hex:6865783a6666"], "literal");
    }
}

#[cfg(all(test, feature = "tier"))]
mod tier_tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusConfig, StorageFormat};

    /// Demote de um segmento selado produz um recibo verificável e materializa
    /// o objeto cold (.hrkl + Parquet) — prova o wiring do `tier` ponta-a-ponta.
    #[tokio::test]
    async fn demote_sealed_segment_produces_verifiable_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            segment_max_bytes: 8192, // força sealing rápido
            cold_tier_path: dir.path().join("cold"),
            // Este teste cobre o demote v1, que é do LAYOUT LEGADO por
            // definição: os seus recibos são v1 e o espelho é Parquet do
            // caminho antigo. Com o v6 como default, fixar o formato aqui é o
            // que mantém o teste a testar o que diz testar — o equivalente v6
            // é `v6_demote_publica_geracao_receipt_v2_e_faz_recall`.
            storage_format: StorageFormat::Legacy,
            ..Default::default()
        };
        let engine = Engine::open(&cfg).unwrap();
        for i in 0..500 {
            engine
                .append(Episode::new(
                    "a",
                    EventKind::Observation,
                    format!("evento de enchimento numero {i} para selar o segmento").into_bytes(),
                ))
                .unwrap();
        }
        let sealed = engine.sealed_segment_ids();
        assert!(!sealed.is_empty(), "deve haver >=1 segmento selado");
        let seg = sealed[0];

        let receipt = engine.demote_segment(seg).await.unwrap();
        assert_eq!(receipt.segment_id, seg);
        assert!(receipt.record_count > 0, "recibo conta registos");
        assert!(receipt.parquet_path.is_some(), "espelho Parquet criado");

        // O recibo verifica: re-computa o Merkle do objeto cold e confere.
        assert!(
            engine.verify_demotion(&receipt).await.unwrap(),
            "recibo verifica"
        );

        // Recall round-trip: o recibo está listado e o segmento busca-se de volta
        // do cold tier (object store) com todos os episódios.
        let receipts = engine.demotion_receipts().unwrap();
        assert!(
            receipts.iter().any(|r| r.segment_id == seg),
            "recibo listado"
        );
        let back = engine.fetch_cold_segment(seg).await.unwrap();
        assert_eq!(
            back.len() as u64,
            receipt.record_count,
            "recall devolve todos os episódios"
        );

        // GUARDA R21 (padrão §2.6, o mesmo do H-VM): o episódio DemotionReceipt
        // — agora appendado pelo Engine::append (caminho unificado) — tem de
        // ficar indexado AO VIVO igual ao que o boot-replay produz, senão o
        // state_hash do grafo diverge entre um nó recém-escrito e um reaberto.
        let live_hash = engine.graph_state_hash();
        drop(engine);
        let engine2 = Engine::open(&cfg).unwrap();
        assert_eq!(
            live_hash,
            engine2.graph_state_hash(),
            "recibo de demote indexado ao vivo ≡ boot-replay (state_hash idêntico)"
        );
    }

    /// SPEC-0050 Fase 6 — a projecção lakehouse vista do servidor.
    ///
    /// O teste de integração do `heraclitus-tier` prova a exportação em si.
    /// Este prova a canalização que o servidor usa: `Engine` em v6 ->
    /// `log.v6_arc()` -> `LakehouseWorker` construído a partir dos campos de
    /// configuração -> métricas do endpoint `/metrics`.
    ///
    /// O que se verifica aqui e em mais lado nenhum é o **atraso de
    /// exportação**: `parquet_export_lag_lsn` é positivo enquanto a fila tem
    /// segmentos e cai a zero quando a tabela apanha o log. Antes desta fase
    /// essa métrica media um pipeline que nunca corria, portanto crescia para
    /// sempre — um número que parecia saúde e era ficção.
    #[tokio::test]
    async fn v6_lakehouse_exporta_e_zera_o_atraso_da_metrica() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().join("v6"),
            storage_format: StorageFormat::V6,
            fsync: FsyncPolicy::Always,
            segment_max_bytes: 4096,
            cold_tier_path: dir.path().join("cold-v6"),
            v6_packing_interval_secs: 0,
            v6_hrki_interval_secs: 0,
            v6_lakehouse_interval_secs: 0,
            v6_lakehouse_path: dir.path().join("lakehouse").to_string_lossy().into_owned(),
            v6_lakehouse_table: "episodios".into(),
            ..Default::default()
        };
        cfg.validate_security().unwrap();
        let engine = Engine::open(&cfg).unwrap();
        for i in 0..200 {
            engine
                .append(Episode::new(
                    "lakehouse",
                    EventKind::Observation,
                    format!("evento-fase6-{i}-{}", "p".repeat(64)).into_bytes(),
                ))
                .unwrap();
        }
        let log = engine.log.v6_arc().unwrap();
        log.seal_active().unwrap();
        log.pack_pending(heraclitus_log::v6::PackingProfile::Balanced)
            .unwrap();

        let atraso_antes = engine.storage_metrics()["parquet_export_lag_lsn"]
            .as_u64()
            .unwrap();
        assert!(
            atraso_antes > 0,
            "com segmentos por exportar o atraso tem de ser positivo"
        );

        std::fs::create_dir_all(&cfg.v6_lakehouse_path).unwrap();
        let worker = heraclitus_tier::LakehouseWorker::open_location(
            &cfg.v6_lakehouse_path,
            cfg.v6_lakehouse_table.clone(),
            log.manifest().storage_namespace_id,
        )
        .unwrap();
        let saidas = worker.export_pending(&log).await.unwrap();
        assert!(!saidas.is_empty(), "nada foi exportado");
        assert!(saidas.iter().all(|s| s.attached));

        let atraso_depois = engine.storage_metrics()["parquet_export_lag_lsn"]
            .as_u64()
            .unwrap();
        assert!(
            atraso_depois < atraso_antes,
            "o atraso não desceu: {atraso_antes} -> {atraso_depois}"
        );
        let manifesto = log.manifest();
        assert_eq!(
            manifesto.exported_through_lsn,
            saidas.iter().map(|s| s.last_lsn).max().unwrap()
        );

        // §209 — a projecção não participa da durabilidade: o log continua a
        // aceitar escritas e a responder a queries depois de exportar.
        let cabeca = engine.snapshot();
        engine
            .append(Episode::new(
                "lakehouse",
                EventKind::Observation,
                b"depois-do-export".to_vec(),
            ))
            .unwrap();
        assert!(engine.snapshot() > cabeca);
    }

    /// Ligar o worker sem destino é erro de arranque, não um default calado.
    #[test]
    fn lakehouse_ligado_sem_destino_e_erro_de_configuracao() {
        let cfg = HeraclitusConfig {
            v6_lakehouse_interval_secs: 60,
            v6_lakehouse_path: String::new(),
            ..Default::default()
        };
        let err = cfg.validate_security().unwrap_err().to_string();
        assert!(err.contains("v6_lakehouse_path"), "{err}");
    }

    #[tokio::test]
    async fn v6_demote_publica_geracao_receipt_v2_e_faz_recall() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().join("v6"),
            storage_format: StorageFormat::V6,
            fsync: FsyncPolicy::Always,
            segment_max_bytes: 420,
            cold_tier_path: dir.path().join("cold-v6"),
            v6_packing_interval_secs: 0,
            v6_hrki_interval_secs: 0,
            ..Default::default()
        };
        let engine = Engine::open(&cfg).unwrap();
        for i in 0..60 {
            engine
                .append(Episode::new(
                    if i < 30 { "alice" } else { "bob" },
                    EventKind::Observation,
                    format!("evento-v6-{i}").into_bytes(),
                ))
                .unwrap();
        }
        engine.log.v6_arc().unwrap().seal_active().unwrap();
        let segment = engine.sealed_segment_ids()[0];

        let any = engine.demote_segment_any(segment).await.unwrap();
        let receipt = match any {
            heraclitus_tier::AnyDemotionReceipt::V2(v2) => v2,
            heraclitus_tier::AnyDemotionReceipt::V1(_) => panic!("V6 gerou recibo legado"),
        };
        assert_eq!(receipt.receipt_version, 2);
        assert_eq!(receipt.segment_id, segment);
        assert_eq!(receipt.physical_layout, "PACKED");
        assert!(receipt.object_path.starts_with("canonical/"));
        assert!(engine.verify_demotion_v2(&receipt).await.unwrap());

        let recalled = engine.fetch_cold_segment(segment).await.unwrap();
        assert_eq!(recalled.len() as u64, receipt.record_count);
        assert_eq!(recalled.first().unwrap().0, receipt.first_lsn);
        assert_eq!(recalled.last().unwrap().0, receipt.last_lsn);
        let metrics = engine.storage_metrics();
        assert!(metrics["cold_range_reads"].as_u64().unwrap() >= 2);
        assert!(metrics["cold_bytes_downloaded"].as_u64().unwrap() > 0);

        // Retry não appenda um segundo recibo equivalente.
        let head_after_first = engine.snapshot();
        let retry = engine.demote_segment_any(segment).await.unwrap();
        assert!(matches!(retry, heraclitus_tier::AnyDemotionReceipt::V2(_)));
        assert_eq!(engine.snapshot(), head_after_first);
        assert_eq!(
            engine
                .demotion_receipts_any()
                .unwrap()
                .into_iter()
                .filter(|r| matches!(r, heraclitus_tier::AnyDemotionReceipt::V2(_)))
                .count(),
            1
        );
    }

    /// C2.6 — o tick de compaction reescreve um segmento cold quando a fração
    /// de tombstones semânticos cruza a política, appenda o recibo novo pelo
    /// caminho unificado (§2.6) e é idempotente (2º tick não re-compacta).
    #[tokio::test]
    async fn tier_compaction_tick_rewrites_when_policy_fires() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            segment_max_bytes: 8192,
            cold_tier_path: dir.path().join("cold"),
            // Compaction v1 sobre recibos v1: legado por definição (ver acima).
            storage_format: StorageFormat::Legacy,
            ..Default::default()
        };
        let engine = Engine::open(&cfg).unwrap();
        for i in 0..500 {
            engine
                .append(Episode::new(
                    "a",
                    EventKind::Observation,
                    format!("evento de enchimento numero {i} para selar o segmento").into_bytes(),
                ))
                .unwrap();
        }
        let seg = engine.sealed_segment_ids()[0];
        let receipt = engine.demote_segment(seg).await.unwrap();

        // Tombstona ~metade dos eventos do segmento demotado.
        let cold_events = engine.fetch_cold_segment(seg).await.unwrap();
        let mut tombstoned = 0u64;
        for (i, (_lsn, ep)) in cold_events.iter().enumerate() {
            if i % 2 == 0 {
                let mut t = Episode::new("gc", EventKind::Observation, vec![]);
                t.attrs.insert("tombstone_of".into(), ep.id.to_string());
                engine.append(t).unwrap();
                tombstoned += 1;
            }
        }
        assert!(tombstoned > 0);

        // Política de teste (min_records=1) — a default exige 1024 registos.
        let policy = heraclitus_tier::CompactionPolicy {
            delta_ratio_threshold: 0.3,
            min_records: 1,
        };
        let new = engine.tier_compaction_tick(&policy).await.unwrap();
        assert_eq!(new.len(), 1, "um segmento compactado");
        assert_eq!(
            new[0].dropped, tombstoned,
            "removeu exatamente os tombstonados"
        );
        assert_eq!(
            new[0].record_count + new[0].dropped,
            receipt.record_count,
            "kept + dropped == original"
        );
        assert!(
            engine.verify_demotion(&new[0]).await.unwrap(),
            "recibo novo verifica"
        );

        // O recall do segmento passa a devolver só os sobreviventes.
        let survivors = engine.fetch_cold_segment(seg).await.unwrap();
        assert_eq!(survivors.len() as u64, new[0].record_count);

        // Idempotência: os tombstonados já foram removidos ⇒ 2º tick é no-op.
        let again = engine.tier_compaction_tick(&policy).await.unwrap();
        assert!(
            again.is_empty(),
            "sem lixo novo, nada a compactar: {again:?}"
        );
    }
}

#[cfg(test)]
mod aprovacao_tests {
    use super::*;
    use heraclitus_core::{FsyncPolicy, HeraclitusConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serve o router NUMA porta real. Vai por HTTP de propósito: o defeito que
    /// estes testes protegem não está só na lógica do handler — está também no
    /// facto de o `IdentidadeRest` ter de chegar lá por uma camada
    /// `Extension`. Chamar a função directamente passaria mesmo que a camada
    /// não existisse no router, e nesse caso todas as aprovações respondiam 500
    /// em produção.
    async fn servir(basic_auth: Option<&str>) -> (std::net::SocketAddr, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            ..Default::default()
        };
        let engine = Arc::new(Engine::open(&cfg).unwrap());
        let app = router_with_sentinel(
            engine,
            None,
            basic_auth.map(str::to_owned),
            Vec::new(),
            false,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, dir)
    }

    /// POST cru, para não puxar um cliente HTTP só para três testes.
    async fn post(
        addr: std::net::SocketAddr,
        caminho: &str,
        corpo: &str,
        auth: Option<&str>,
    ) -> (u16, String) {
        let mut cabecalhos = format!(
            "POST {caminho} HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n",
            corpo.len()
        );
        if let Some(a) = auth {
            cabecalhos.push_str(&format!("Authorization: Basic {}\r\n", b64(a.as_bytes())));
        }
        cabecalhos.push_str("\r\n");
        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        sock.write_all(cabecalhos.as_bytes()).await.unwrap();
        sock.write_all(corpo.as_bytes()).await.unwrap();
        let mut resposta = Vec::new();
        sock.read_to_end(&mut resposta).await.unwrap();
        let texto = String::from_utf8_lossy(&resposta).into_owned();
        let estado = texto
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (estado, texto)
    }

    const ROTA: &str = "/sentinel/incidents/inc-1/approve";

    /// O defeito: o `approver` vinha do corpo do pedido, portanto qualquer
    /// chamador registava uma aprovação humana em nome de outra pessoa. Um
    /// registo de aprovação existe precisamente para atribuir responsabilidade.
    #[tokio::test]
    async fn aprovador_diferente_da_identidade_e_recusado() {
        let (addr, _dir) = servir(None).await;
        let (estado, corpo) = post(
            addr,
            ROTA,
            r#"{"approval_id":"a1","proposal_id":"p1","approver":"a-directora"}"#,
            None,
        )
        .await;
        assert_eq!(
            estado, 403,
            "forjar o aprovador tem de ser recusado: {corpo}"
        );
        assert!(
            corpo.contains("rest-sem-auth"),
            "a resposta tem de dizer QUAL é a identidade real: {corpo}"
        );
    }

    /// A recusa é uma propriedade do PEDIDO, não do estado do serviço: sem o
    /// sentinel ligado continua a ser 403, e não um 503 que esconderia a
    /// tentativa. (É por isso que a verificação está antes da guarda do
    /// runtime.)
    #[tokio::test]
    async fn a_recusa_nao_depende_do_sentinel_estar_ligado() {
        let (addr, _dir) = servir(None).await;
        let (sem_aprovador, _) = post(
            addr,
            ROTA,
            r#"{"approval_id":"a1","proposal_id":"p1"}"#,
            None,
        )
        .await;
        // Sem sentinel, um pedido HONESTO chega ao 503 — o que prova que o
        // campo deixou de ser obrigatório e que a `Extension` está mesmo
        // montada no router (faltando, isto seria 500).
        assert_eq!(sem_aprovador, 503, "sem `approver` o pedido é legítimo");
    }

    /// Com Basic auth há uma identidade, e é essa que vale. Coincidir passa;
    /// não coincidir continua a ser 403.
    #[tokio::test]
    async fn com_basic_auth_a_identidade_e_o_utilizador_configurado() {
        let (addr, _dir) = servir(Some("auditor:segredo")).await;
        let (coincide, _) = post(
            addr,
            ROTA,
            r#"{"approval_id":"a1","proposal_id":"p1","approver":"auditor"}"#,
            Some("auditor:segredo"),
        )
        .await;
        assert_eq!(coincide, 503, "coincidir com a identidade é legítimo");

        let (difere, corpo) = post(
            addr,
            ROTA,
            r#"{"approval_id":"a1","proposal_id":"p1","approver":"outra-pessoa"}"#,
            Some("auditor:segredo"),
        )
        .await;
        assert_eq!(difere, 403, "{corpo}");
        assert!(corpo.contains("auditor"), "{corpo}");
    }
}

/// SPEC-0071 §3/§4.1 — os eventos canónicos de segurança, tipados e
/// filtráveis, `AS OF LSN`.
///
/// A vista é DERIVADA dos atributos `security_*` que o `bridge.py` escreve; o
/// log continua a ser o único canónico. Reconstruir com `as_of_lsn` dá o que
/// estava lá nesse ponto.
async fn security_events(
    State(engine): State<Arc<Engine>>,
    Query(query): Query<SecurityEventQuery>,
) -> Response {
    let as_of_lsn = query.as_of_lsn.unwrap_or_else(|| engine.head());
    // Tecto: sem ele, um pedido sem `limit` varreria a base inteira para dentro
    // de uma resposta HTTP. 1000 é generoso para um painel e finito para o
    // servidor.
    let limite = query.limit.unwrap_or(200).min(1_000);
    let filtro = heraclitus_telemetry_health::SecurityEventFilter {
        tenant_id: query.tenant_id,
        datasource_id: query.datasource_id,
        category: query.category,
        outcome: query.outcome,
        severidade_minima: query.min_severity,
    };
    // `spawn_blocking`: a projecção varre o log em janelas. Ver o comentário do
    // `/sentinel/checkpoint` — uma varredura no reactor bloqueia uma thread que
    // o tokio tem em número fixo.
    match tokio::task::spawn_blocking(move || {
        engine.security_events(&filtro, Some(as_of_lsn), limite)
    })
    .await
    {
        Ok(Ok(eventos)) => Json(serde_json::json!({
            "schema": heraclitus_telemetry_health::SECURITY_EVENT_SCHEMA,
            "as_of_lsn": as_of_lsn,
            "count": eventos.len(),
            "limit": limite,
            "events": eventos,
        }))
        .into_response(),
        Ok(Err(erro)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
        Err(erro) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
    }
}

/// Contagens por categoria, datasource e outcome — o agregado do painel.
async fn security_event_counts(
    State(engine): State<Arc<Engine>>,
    Query(query): Query<TelemetryHealthQuery>,
) -> Response {
    let as_of_lsn = query.as_of_lsn.unwrap_or_else(|| engine.head());
    match tokio::task::spawn_blocking(move || engine.security_event_counts(Some(as_of_lsn))).await {
        Ok(Ok(contagens)) => Json(serde_json::json!({
            "as_of_lsn": as_of_lsn,
            "counts": contagens,
        }))
        .into_response(),
        Ok(Err(erro)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
        Err(erro) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
    }
}

/// SPEC-0071 §8 — comandos e leitura de casos.
///
/// O POST aplica um comando; o GET reconstrói o estado `AS OF LSN`. Não há
/// rota que MUTE um caso directamente, e é essa a ausência que interessa: a
/// §8.2 diz que "não existe `UPDATE case SET ...` como fonte de verdade", e a
/// forma de garantir isso é não haver por onde.
async fn case_command(
    State(engine): State<Arc<Engine>>,
    Json(envelope): Json<heraclitus_case::CaseEnvelope>,
) -> Response {
    match tokio::task::spawn_blocking(move || engine.case_command(&envelope)).await {
        Ok(Ok((lsn, aplicado))) => Json(serde_json::json!({
            "lsn": lsn,
            // `false` é a repetição idempotente da §8.3: o comando já tinha
            // entrado, nada foi escrito, e o LSN é o da entrada original.
            "applied": aplicado,
        }))
        .into_response(),
        Ok(Err(erro)) => {
            let texto = erro.to_string();
            // Um conflito de revisão é 409, não 500: é uma resposta legítima a
            // um pedido bem formado, e o cliente sabe o que fazer com ela —
            // reler o estado e tentar outra vez.
            let codigo = if texto.contains("conflito de revisão") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            (codigo, Json(serde_json::json!({ "error": texto }))).into_response()
        }
        Err(erro) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
    }
}

async fn case_state(
    State(engine): State<Arc<Engine>>,
    axum::extract::Path(case_id): axum::extract::Path<String>,
    Query(query): Query<TelemetryHealthQuery>,
) -> Response {
    let as_of_lsn = query.as_of_lsn.unwrap_or_else(|| engine.head());
    match tokio::task::spawn_blocking(move || engine.case_state(&case_id, Some(as_of_lsn))).await {
        Ok(Ok(Some(estado))) => Json(serde_json::json!({
            "as_of_lsn": as_of_lsn,
            "case": estado,
        }))
        .into_response(),
        Ok(Ok(None)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "caso não encontrado neste LSN" })),
        )
            .into_response(),
        Ok(Err(erro)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
        Err(erro) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
    }
}

async fn case_list(
    State(engine): State<Arc<Engine>>,
    Query(query): Query<TelemetryHealthQuery>,
) -> Response {
    let as_of_lsn = query.as_of_lsn.unwrap_or_else(|| engine.head());
    match tokio::task::spawn_blocking(move || engine.case_ids(Some(as_of_lsn))).await {
        Ok(Ok(ids)) => Json(serde_json::json!({
            "as_of_lsn": as_of_lsn,
            "count": ids.len(),
            "cases": ids,
        }))
        .into_response(),
        Ok(Err(erro)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
        Err(erro) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
    }
}

/// SPEC-0071 §7 — Content Hub. POST acrescenta um comando; GET reconstrói.
async fn content_command(
    State(engine): State<Arc<Engine>>,
    Json(envelope): Json<heraclitus_content::ContentEnvelope>,
) -> Response {
    match tokio::task::spawn_blocking(move || engine.content_command(&envelope)).await {
        Ok(Ok(lsn)) => Json(serde_json::json!({ "lsn": lsn })).into_response(),
        Ok(Err(erro)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
        Err(erro) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
    }
}

async fn content_state(
    State(engine): State<Arc<Engine>>,
    Query(query): Query<TelemetryHealthQuery>,
) -> Response {
    let as_of_lsn = query.as_of_lsn.unwrap_or_else(|| engine.head());
    match tokio::task::spawn_blocking(move || engine.content_state(Some(as_of_lsn))).await {
        Ok(Ok(estado)) => Json(serde_json::json!({
            "as_of_lsn": as_of_lsn,
            "content": estado,
        }))
        .into_response(),
        Ok(Err(erro)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
        Err(erro) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": erro.to_string() })),
        )
            .into_response(),
    }
}
