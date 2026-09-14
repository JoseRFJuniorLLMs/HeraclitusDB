//! SPEC-0075 §4–§5, §16, §24 — o proxy MCP com policy.
//!
//! ```text
//! Agent -> Heraclitus Agent Policy Gateway -> MCP Server
//! ```
//!
//! # O fluxo de §16, escrito em código
//!
//! ```text
//! Agent calls send_payment
//!   -> canonicaliza a acção
//!   -> policy => REQUIRE_APPROVAL
//!        ToolRequested / PolicyEvaluated / HumanApprovalRequested (evidência)
//!   -> humano aprova
//!   -> confere o digest EXACTO dos argumentos
//!   -> AuthorizedAction -> tool call -> resultado (evidência)
//! ```
//!
//! # Os três modos (§24)
//!
//! | modo | avalia | bloqueia | `enforced` na evidência |
//! |---|---|---|---|
//! | `observe` | não | não | ausente |
//! | `shadow` | sim | **não** | `false` |
//! | `enforce` | sim | sim | `true` |
//!
//! `shadow` é o modo que torna a adopção possível: a organização vê `would
//! deny` durante uma semana antes de alguma coisa partir.
//!
//! # O que este ficheiro NÃO promete
//!
//! Que o agente não consegue falar directamente com o upstream. Isso é
//! topologia, não código (§20) — e por isso o estado aparece como
//! `BYPASS PROTECTION: CONFIGURED / UNKNOWN` em vez de o produto afirmar
//! enforcement que não pode garantir.

use crate::runtime::{now_unix_nanos, now_unix_seconds, AgentRuntime, GatewayCounters};
use crate::upstream::{UpstreamClient, UpstreamError};
use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use heraclitus_agent::action::{
    argument_digest, ActionAuthorizationV1, ApprovalPreviewV1, ApprovalRequestV1, ApprovalVerdict,
};
use heraclitus_agent::config::GatewayMode;
use heraclitus_agent::evidence::{
    AgentEvidenceKindV1, AgentEvidenceV1, AgentIdentityV1, ApprovalProvenanceV1, EvidenceOutcomeV1,
    HumanIdentityRefV1, PolicyProvenanceV1,
};
use heraclitus_agent::mcp::{self, McpExchange};
use heraclitus_agent::policy::{AgentPolicyDecisionV1, PolicyInput, PolicyValueV1};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Estado do proxy.
pub struct GatewayState {
    pub runtime: Arc<AgentRuntime>,
    pub upstream: Option<Arc<UpstreamClient>>,
}

/// O router do proxy. Um único `fallback`: tudo o que chega é reencaminhado,
/// porque o MCP HTTP não tem um caminho fixo que possamos assumir.
pub fn router(state: Arc<GatewayState>) -> Router {
    Router::new().fallback(proxy).with_state(state)
}

async fn proxy(
    State(state): State<Arc<GatewayState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let runtime = &state.runtime;
    GatewayCounters::bump(&runtime.gateway_counters.requests);
    let started = now_unix_nanos();

    let header_map: BTreeMap<String, String> = headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();

    let server_id = header_map
        .get("x-heraclitus-server")
        .cloned()
        .unwrap_or_else(|| {
            state
                .upstream
                .as_ref()
                .and_then(|u| u.base().host().map(str::to_string))
                .unwrap_or_else(|| "upstream".to_string())
        });

    let mut exchange = McpExchange {
        tenant_id: runtime.config.tenant_id.clone(),
        capture_mode: "proxy".to_string(),
        server_id: server_id.clone(),
        request_headers: header_map.clone(),
        request_body: (!body.is_empty()).then(|| body.to_vec()),
        observed_at_unix_nanos: started,
        trace_id: header_map.get("x-heraclitus-trace").cloned(),
        run_id: header_map.get("x-heraclitus-run").cloned(),
        agent_id: header_map.get("x-heraclitus-agent").cloned(),
        human_subject: header_map.get("x-heraclitus-user").cloned(),
        ..Default::default()
    };
    let facts = mcp::extract_facts(&exchange);

    let e_tool_call = facts
        .method
        .as_deref()
        .map(|m| m == "tools/call")
        .unwrap_or(false);

    // Tráfego que não é uma chamada de ferramenta (`initialize`, `tools/list`,
    // `ping`) passa sem policy e sem evidência. Registá-lo encheria a timeline
    // de ruído de protocolo e escondia as acções que interessam.
    if !e_tool_call {
        return forward_or_error(&state, &method, &uri, &header_map, body).await;
    }

    let agent_id = exchange
        .agent_id
        .clone()
        .unwrap_or_else(|| "unknown-agent".to_string());
    let args = facts.arguments.clone();
    let digest = argument_digest(&args);

    // ── policy ──────────────────────────────────────────────────────────────
    let mode = runtime.mode();
    let policy = runtime.policy();
    let input = PolicyInput {
        server_id: server_id.clone(),
        tool_name: facts.tool_name.clone().unwrap_or_default(),
        agent_subject: agent_id.clone(),
        environment: header_map.get("x-heraclitus-environment").cloned(),
        protocol: Some("mcp".to_string()),
        fields: args
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    match v.parse::<i64>() {
                        Ok(i) => PolicyValueV1::Int(i),
                        Err(_) => PolicyValueV1::Str(v.clone()),
                    },
                )
            })
            .collect(),
        now_unix_seconds: now_unix_seconds(),
    };

    let avaliacao = (mode != GatewayMode::Observe).then(|| policy.engine.evaluate(&input));
    let enforced = mode.enforces();

    let provenance = avaliacao.as_ref().map(|a| PolicyProvenanceV1 {
        policy_id: a.policy_id.clone(),
        policy_version: a.policy_version.clone(),
        policy_hash: a.policy_hash.clone(),
        rule_id: a.rule_id.clone(),
        decision: a.decision.label().to_string(),
        reason_code: a.reason_code.clone(),
        input_projection_hash: a.input_projection_hash.clone(),
        authorization_id: None,
        enforced,
    });

    // ── evidência: pedido + decisão ─────────────────────────────────────────
    let mut requested = base_evidence(
        runtime,
        AgentEvidenceKindV1::ToolRequested,
        started,
        &exchange,
        &facts,
        &agent_id,
    );
    // O hash canónico é dos argumentos CRUS, e tem de o ser: é ele que liga
    // uma aprovação a UMA execução exacta (§34 da 0075) e é ele que a
    // deduplicação compara. Redigir o que se MOSTRA não pode mudar aquilo a
    // que a autorização se vincula.
    requested.content.canonical_content_hash = Some(digest.clone());
    let redigidos = argumentos_para_persistir(runtime, &args);
    requested.content.fields = redigidos.content.fields;
    requested.privacy = redigidos.privacy;
    requested.content.policy = provenance.clone();
    let requested_id = append(runtime, requested);

    if let Some(prov) = &provenance {
        let mut evaluated = base_evidence(
            runtime,
            AgentEvidenceKindV1::PolicyEvaluated,
            now_unix_nanos(),
            &exchange,
            &facts,
            &agent_id,
        );
        evaluated.content.policy = Some(prov.clone());
        evaluated.parents = requested_id.iter().cloned().collect();
        append(runtime, evaluated);
    }

    // ── decidir ─────────────────────────────────────────────────────────────
    if let Some(a) = &avaliacao {
        match &a.decision {
            AgentPolicyDecisionV1::Allow => {
                GatewayCounters::bump(&runtime.gateway_counters.allow);
            }
            AgentPolicyDecisionV1::Deny { reason_code, .. } => {
                GatewayCounters::bump(&runtime.gateway_counters.deny);
                if enforced {
                    let mut denied = base_evidence(
                        runtime,
                        AgentEvidenceKindV1::ToolDenied,
                        now_unix_nanos(),
                        &exchange,
                        &facts,
                        &agent_id,
                    );
                    denied.content.policy = provenance.clone();
                    denied.parents = requested_id.iter().cloned().collect();
                    append(runtime, denied);
                    let _ = runtime.flush();
                    return mcp_error(
                        StatusCode::FORBIDDEN,
                        &facts.tool_call_id,
                        reason_code,
                        "a policy activa nega esta acção",
                    );
                }
                GatewayCounters::bump(&runtime.gateway_counters.shadow_deny);
            }
            AgentPolicyDecisionV1::RequireApproval {
                roles,
                ttl_seconds,
                rule_id,
            } => {
                GatewayCounters::bump(&runtime.gateway_counters.require_approval);
                let now = now_unix_seconds();
                let authorization = ActionAuthorizationV1 {
                    authorization_id: ulid::Ulid::new().to_string(),
                    policy_id: a.policy_id.clone(),
                    policy_version: a.policy_version.clone(),
                    policy_hash: a.policy_hash.clone(),
                    rule_id: rule_id.clone(),
                    agent_subject: agent_id.clone(),
                    human_subject: exchange.human_subject.clone(),
                    resource_id: format!(
                        "mcp://{server_id}/{}",
                        facts.tool_name.clone().unwrap_or_default()
                    ),
                    action: facts.tool_name.clone().unwrap_or_default(),
                    argument_digest: digest.clone(),
                    issued_at: now,
                    expires_at: now + *ttl_seconds,
                    nonce: ulid::Ulid::new().to_string(),
                };
                let subject_hash = authorization.subject_hash();
                let veredicto = runtime.approvals.consume(&authorization, now);

                match veredicto {
                    ApprovalVerdict::Authorized { approval_id } => {
                        let mut autorizada = base_evidence(
                            runtime,
                            AgentEvidenceKindV1::ToolAuthorized,
                            now_unix_nanos(),
                            &exchange,
                            &facts,
                            &agent_id,
                        );
                        autorizada.content.policy = provenance.clone();
                        autorizada.content.approval = Some(ApprovalProvenanceV1 {
                            approval_id,
                            authorization_subject_hash: subject_hash,
                            approver_subject: None,
                            approver_issuer: None,
                            decided_at_unix_nanos: None,
                        });
                        append(runtime, autorizada);
                    }
                    ApprovalVerdict::NotFound if enforced || mode == GatewayMode::Shadow => {
                        // Primeiro encontro com esta acção: abrir o pedido de
                        // aprovação. Em shadow o pedido é registado mas a acção
                        // segue — é isso que "would require approval" significa.
                        let pedido = ApprovalRequestV1 {
                            approval_id: ulid::Ulid::new().to_string(),
                            authorization_subject_hash: subject_hash.clone(),
                            requested_roles: roles.clone(),
                            reason: format!(
                                "a regra `{rule_id}` exige aprovação para {}",
                                facts.tool_name.clone().unwrap_or_default()
                            ),
                            preview: ApprovalPreviewV1 {
                                agent: agent_id.clone(),
                                tool: facts.tool_name.clone().unwrap_or_default(),
                                server: server_id.clone(),
                                environment: header_map.get("x-heraclitus-environment").cloned(),
                                run_id: exchange.run_id.clone(),
                                fields: preview_fields(runtime, &args),
                                argument_digest: digest.clone(),
                                policy_rule: Some(rule_id.clone()),
                            },
                            requested_at: now,
                            expires_at: now + *ttl_seconds,
                        };
                        let pedido = runtime.approvals.request(pedido, now);

                        let mut pedida = base_evidence(
                            runtime,
                            AgentEvidenceKindV1::HumanApprovalRequested,
                            now_unix_nanos(),
                            &exchange,
                            &facts,
                            &agent_id,
                        );
                        pedida.content.policy = provenance.clone();
                        pedida.content.approval = Some(ApprovalProvenanceV1 {
                            approval_id: pedido.approval_id.clone(),
                            authorization_subject_hash: subject_hash.clone(),
                            approver_subject: None,
                            approver_issuer: None,
                            decided_at_unix_nanos: None,
                        });
                        pedida.parents = requested_id.iter().cloned().collect();
                        append(runtime, pedida);
                        let _ = runtime.flush();

                        if enforced {
                            return approval_pending(&facts.tool_call_id, &pedido);
                        }
                    }
                    outro => {
                        if matches!(outro, ApprovalVerdict::Expired { .. }) {
                            GatewayCounters::bump(&runtime.gateway_counters.approval_expired);
                        }
                        if matches!(outro, ApprovalVerdict::AlreadyUsed { .. }) {
                            GatewayCounters::bump(
                                &runtime.gateway_counters.approval_replay_rejected,
                            );
                        }
                        if enforced {
                            let mut denied = base_evidence(
                                runtime,
                                AgentEvidenceKindV1::ToolDenied,
                                now_unix_nanos(),
                                &exchange,
                                &facts,
                                &agent_id,
                            );
                            denied.content.policy = provenance.clone();
                            append(runtime, denied);
                            let _ = runtime.flush();
                            return mcp_error(
                                StatusCode::FORBIDDEN,
                                &facts.tool_call_id,
                                outro.reason_code(),
                                "a aprovação necessária não está válida para esta acção exacta",
                            );
                        }
                    }
                }
            }
            AgentPolicyDecisionV1::RateLimit {
                bucket_id,
                retry_after_ms,
            } => {
                if enforced {
                    let _ = runtime.flush();
                    return mcp_error(
                        StatusCode::TOO_MANY_REQUESTS,
                        &facts.tool_call_id,
                        "RATE_LIMITED",
                        &format!("balde `{bucket_id}`; tente daqui a {retry_after_ms} ms"),
                    );
                }
            }
            // `Redact` actua sobre o conteúdo registado, não sobre a passagem;
            // `SandboxHint` é uma dica para quem executa. Nenhum dos dois
            // bloqueia.
            AgentPolicyDecisionV1::Redact { .. } | AgentPolicyDecisionV1::SandboxHint { .. } => {}
        }
    }

    // ── execução ────────────────────────────────────────────────────────────
    let mut started_ev = base_evidence(
        runtime,
        AgentEvidenceKindV1::ToolInvocationStarted,
        now_unix_nanos(),
        &exchange,
        &facts,
        &agent_id,
    );
    started_ev.parents = requested_id.iter().cloned().collect();
    let started_id = append(runtime, started_ev);

    let t0 = now_unix_nanos();
    let resultado = forward(&state, &method, &uri, &header_map, body).await;
    let duracao = now_unix_nanos().saturating_sub(t0);

    match resultado {
        Ok(resp) => {
            exchange.response_body = Some(resp.body.to_vec());
            exchange.transport_status = Some(resp.status as i64);
            exchange.duration_nanos = Some(duracao);
            let factos_resposta = mcp::extract_facts(&exchange);

            let mut finished = base_evidence(
                runtime,
                AgentEvidenceKindV1::ToolInvocationFinished,
                now_unix_nanos(),
                &exchange,
                &factos_resposta,
                &agent_id,
            );
            let redigido = heraclitus_agent::privacy::apply(
                &runtime.config.redaction_profile(),
                &heraclitus_agent::privacy::RawContent {
                    content_type: Some("application/json".into()),
                    body: exchange.response_body.clone(),
                    ..Default::default()
                },
            );
            finished.content = redigido.content;
            finished.privacy = redigido.privacy;
            finished.content.policy = provenance.clone();
            finished.subject.external_effect_id = factos_resposta.external_effect_id.clone();
            finished.outcome = Some(EvidenceOutcomeV1 {
                transport_status: Some(resp.status as i64),
                protocol_status: Some(
                    if factos_resposta.is_error {
                        "error"
                    } else {
                        "ok"
                    }
                    .to_string(),
                ),
                error_message: factos_resposta.error_message.clone(),
                duration_nanos: Some(duracao),
                retry_count: None,
                error_code: None,
            });
            finished.parents = started_id.iter().cloned().collect();
            let finished_id = append(runtime, finished);

            if let Some(effect) = &factos_resposta.external_effect_id {
                let mut ev = base_evidence(
                    runtime,
                    AgentEvidenceKindV1::ExternalEffectObserved,
                    now_unix_nanos(),
                    &exchange,
                    &factos_resposta,
                    &agent_id,
                );
                ev.subject.external_effect_id = Some(effect.clone());
                ev.parents = finished_id.into_iter().collect();
                append(runtime, ev);
            }
            let _ = runtime.flush();

            let mut headers_out = HeaderMap::new();
            for (k, v) in &resp.headers {
                let (Ok(name), Ok(value)) = (
                    axum::http::HeaderName::from_bytes(k.as_bytes()),
                    axum::http::HeaderValue::from_str(v),
                ) else {
                    continue;
                };
                headers_out.insert(name, value);
            }
            (
                StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY),
                headers_out,
                resp.body,
            )
                .into_response()
        }
        Err(e) => {
            GatewayCounters::bump(&runtime.gateway_counters.upstream_errors);
            let mut erro = base_evidence(
                runtime,
                AgentEvidenceKindV1::ErrorObserved,
                now_unix_nanos(),
                &exchange,
                &facts,
                &agent_id,
            );
            erro.outcome = Some(EvidenceOutcomeV1 {
                protocol_status: Some("error".into()),
                error_code: Some("MCP_UPSTREAM_UNAVAILABLE".into()),
                error_message: Some(e.to_string()),
                duration_nanos: Some(duracao),
                ..Default::default()
            });
            erro.parents = started_id.into_iter().collect();
            append(runtime, erro);
            let _ = runtime.flush();
            mcp_error(
                StatusCode::BAD_GATEWAY,
                &facts.tool_call_id,
                "MCP_UPSTREAM_UNAVAILABLE",
                &e.to_string(),
            )
        }
    }
}

/// Os argumentos de uma tool call, prontos a PERSISTIR.
///
/// # Porque é que isto é uma função e não três linhas inline
///
/// Porque durante um tempo foram três linhas inline — e estavam erradas. Os
/// argumentos crus eram inseridos directamente em `content.fields`, enquanto o
/// preview da tela de aprovação (efémero, que um humano olha uma vez e fecha)
/// ia redigido. O permanente ficava em claro e o efémero protegido, ao
/// contrário. Num `tools/call` com `{"api_key": "sk-live-..."}` isso escrevia o
/// segredo num log append-only, de onde não sai.
///
/// A invariante da SPEC-0074 §11 é que uma credencial nunca é persistida em
/// modo NENHUM — nem em `full_explicit`. Um caminho de escrita que não passe
/// por [`heraclitus_agent::privacy::apply`] não a pode cumprir, porque é lá que
/// vivem tanto a lista de campos negados como os detectores de segredo por
/// forma. Ter isto com nome torna visível qual é esse caminho.
fn argumentos_para_persistir(
    runtime: &Arc<AgentRuntime>,
    args: &BTreeMap<String, String>,
) -> heraclitus_agent::privacy::RedactionOutcome {
    heraclitus_agent::privacy::apply(
        &runtime.config.redaction_profile(),
        &heraclitus_agent::privacy::RawContent {
            fields: args.clone(),
            ..Default::default()
        },
    )
}

/// Os campos que aparecem na tela de aprovação (§34 da 0075).
///
/// Passam pelo mesmo portão de privacidade que tudo o resto: um preview não é
/// uma excepção à redacção só porque um humano o vai ler.
fn preview_fields(
    runtime: &Arc<AgentRuntime>,
    args: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut perfil = runtime.config.redaction_profile();
    // O preview mostra campos; o corpo não entra.
    perfil.capture_mode = heraclitus_agent::evidence::CaptureModeV1::Redacted;
    let out = heraclitus_agent::privacy::apply(
        &perfil,
        &heraclitus_agent::privacy::RawContent {
            fields: args.clone(),
            ..Default::default()
        },
    );
    out.content.fields
}

fn base_evidence(
    runtime: &Arc<AgentRuntime>,
    kind: AgentEvidenceKindV1,
    at: u64,
    ex: &McpExchange,
    facts: &mcp::McpCallFacts,
    agent_id: &str,
) -> AgentEvidenceV1 {
    let mut e = AgentEvidenceV1::new(runtime.config.tenant_id.clone(), kind, at);
    e.trace_id = ex.trace_id.clone();
    e.run_id = ex.run_id.clone().or_else(|| ex.trace_id.clone());
    e.session_id = facts.session_id.clone();
    e.agent = AgentIdentityV1 {
        agent_id: agent_id.to_string(),
        framework: Some("mcp".into()),
        framework_version: facts
            .protocol_version
            .clone()
            .or_else(|| Some(mcp::MCP_PROTOCOL_VERSION.to_string())),
        ..Default::default()
    };
    if let Some(h) = &ex.human_subject {
        e.human = Some(HumanIdentityRefV1 {
            subject_id: h.clone(),
            ..Default::default()
        });
    }
    e.subject.protocol = Some("mcp".into());
    e.subject.server_id = Some(ex.server_id.clone());
    e.subject.tool_name = facts.tool_name.clone();
    e.subject.tool_call_id = facts.tool_call_id.clone();
    e.source.source_kind = "gateway".to_string();
    e.source.source_instance = Some(ex.server_id.clone());
    e.dedupe_key = heraclitus_agent::dedupe::dedupe_key(&e);
    e
}

fn append(runtime: &Arc<AgentRuntime>, e: AgentEvidenceV1) -> Option<String> {
    let id = e.evidence_id.clone();
    match runtime.append(&e) {
        Ok(_) => Some(id),
        Err(err) => {
            // Falhar a gravar evidência não pode derrubar o proxy em silêncio,
            // mas também não pode passar despercebido: o operador vê-o no log
            // e no contador de erros.
            tracing::error!(erro = %err, "evidência de agente não foi gravada");
            GatewayCounters::bump(&runtime.gateway_counters.policy_errors);
            None
        }
    }
}

async fn forward(
    state: &Arc<GatewayState>,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &BTreeMap<String, String>,
    body: Bytes,
) -> Result<crate::upstream::UpstreamResponse, UpstreamError> {
    let Some(client) = &state.upstream else {
        return Err(UpstreamError::BadUrl(
            "o gateway não tem `upstream_url` configurado".into(),
        ));
    };
    let pq = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    client
        .forward(
            method.as_str(),
            &pq,
            headers,
            hyper::body::Bytes::from(body.to_vec()),
        )
        .await
}

async fn forward_or_error(
    state: &Arc<GatewayState>,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &BTreeMap<String, String>,
    body: Bytes,
) -> Response {
    match forward(state, method, uri, headers, body).await {
        Ok(resp) => {
            let mut headers_out = HeaderMap::new();
            for (k, v) in &resp.headers {
                let (Ok(name), Ok(value)) = (
                    axum::http::HeaderName::from_bytes(k.as_bytes()),
                    axum::http::HeaderValue::from_str(v),
                ) else {
                    continue;
                };
                headers_out.insert(name, value);
            }
            (
                StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY),
                headers_out,
                resp.body,
            )
                .into_response()
        }
        Err(e) => mcp_error(
            StatusCode::BAD_GATEWAY,
            &None,
            "MCP_UPSTREAM_UNAVAILABLE",
            &e.to_string(),
        ),
    }
}

/// Erro na forma JSON-RPC que o cliente MCP sabe ler.
///
/// Devolver um corpo JSON-RPC bem formado, e não um `403` nu, é o que permite
/// ao agente perceber que a ferramenta foi recusada — em vez de tratar a
/// recusa como falha de rede e tentar outra vez.
fn mcp_error(status: StatusCode, id: &Option<String>, code: &str, message: &str) -> Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.clone().map(serde_json::Value::String).unwrap_or(serde_json::Value::Null),
        "error": {
            // -32003 fica na gama reservada a erros de servidor do JSON-RPC.
            "code": -32003,
            "message": format!("{code}: {message}"),
            "data": { "heraclitus": { "reason_code": code } }
        }
    });
    (status, axum::Json(body)).into_response()
}

fn approval_pending(id: &Option<String>, pedido: &ApprovalRequestV1) -> Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.clone().map(serde_json::Value::String).unwrap_or(serde_json::Value::Null),
        "error": {
            "code": -32003,
            "message": format!(
                "APPROVAL_PENDING: esta acção precisa de aprovação de [{}]",
                pedido.requested_roles.join(", ")
            ),
            "data": {
                "heraclitus": {
                    "reason_code": "APPROVAL_PENDING",
                    "approval_id": pedido.approval_id,
                    "expires_at": pedido.expires_at,
                    "argument_digest": pedido.preview.argument_digest,
                }
            }
        }
    });
    (StatusCode::ACCEPTED, axum::Json(body)).into_response()
}
