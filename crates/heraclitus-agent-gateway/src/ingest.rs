//! SPEC-0074 §12 e §19 — o receptor OTLP/HTTP.
//!
//! ```text
//! POST /v1/traces        application/x-protobuf | application/json
//! ```
//!
//! É este endereço que faz a promessa de §0.1 funcionar:
//!
//! ```bash
//! export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
//! ```
//!
//! # Backpressure explícito (§26, gate 2)
//!
//! Quando o lote excede o tecto, a resposta é `413` com corpo que diz porquê.
//! Quando a normalização recusa spans por tecto de lote, a resposta é `200` com
//! `partialSuccess` — que é o que o protocolo OTLP define para "aceitei uma
//! parte" e o que faz o exporter parar de retransmitir o lote inteiro.
//!
//! O que **não** fazemos é aceitar tudo e crescer em memória: §12 diz "sem
//! alocação sem limite", e um coletor que nunca recusa é um coletor que
//! transfere o problema para o `OOM killer`.

use crate::runtime::AgentRuntime;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use heraclitus_agent::otlp::OtlpError;
use std::sync::Arc;

/// O router do receptor OTLP. Vive à parte do resto do produto de propósito: é
/// a única superfície que aceita input não autenticado num quickstart local, e
/// tê-la isolada torna óbvio o que está exposto.
pub fn router(runtime: Arc<AgentRuntime>) -> Router {
    // O tecto do axum (2 MiB por omissão) é MENOR do que o nosso default de
    // 4 MiB, e aplica-se antes de o handler existir. Sem esta linha,
    // `max_body_bytes` seria uma configuração que mente: um lote de 3 MiB seria
    // recusado por um limite que o operador nunca viu, com uma mensagem que não
    // diz qual. Aqui o limite configurado é o limite efectivo.
    let limite = runtime.config.limits.max_body_bytes.max(1024);
    Router::new()
        .route("/v1/traces", post(traces))
        // Muitos coletores também aceitam estes dois. Respondemos de forma
        // honesta: não os ingerimos (não são evidência de agente), mas
        // devolvemos sucesso para que o exporter da aplicação não fique em
        // retry infinito por causa de um sinal que não pedimos.
        .route("/v1/metrics", post(not_ingested))
        .route("/v1/logs", post(not_ingested))
        .layer(axum::extract::DefaultBodyLimit::max(limite))
        .with_state(runtime)
}

async fn traces(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/x-protobuf")
        .to_string();

    {
        let mut c = runtime.counters.lock().unwrap();
        c.batches += 1;
        c.bytes += body.len() as u64;
    }

    let batch = match runtime.normalizer().ingest_http(&content_type, &body) {
        Ok(b) => b,
        Err(e) => {
            let status = match &e {
                OtlpError::BodyTooLarge(..) => StatusCode::PAYLOAD_TOO_LARGE,
                OtlpError::UnsupportedContentType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
                _ => StatusCode::BAD_REQUEST,
            };
            runtime.counters.lock().unwrap().rejected += 1;
            return (
                status,
                Json(serde_json::json!({
                    "error": "INGEST_REJECTED",
                    "detail": e.to_string(),
                })),
            )
                .into_response();
        }
    };

    let mut accepted = 0u64;
    let mut duplicated = 0u64;
    let mut rejected = batch.rejected_spans as u64;
    let mut first_error: Option<String> = None;

    for evidence in &batch.evidences {
        match runtime.append(evidence) {
            Ok(Some(_)) => accepted += 1,
            Ok(None) => duplicated += 1,
            Err(e) => {
                rejected += 1;
                if first_error.is_none() {
                    first_error = Some(e.to_string());
                }
            }
        }
    }
    {
        let mut c = runtime.counters.lock().unwrap();
        c.ignored += batch.ignored_spans as u64;
        c.rejected += batch.rejected_spans as u64;
    }

    // O corpo segue a forma de `ExportTraceServiceResponse` na codificação JSON,
    // que é o que os exporters sabem ler nos dois transportes.
    let mut payload = serde_json::json!({
        "partialSuccess": {
            "rejectedSpans": rejected,
            "errorMessage": first_error.clone().unwrap_or_default(),
        }
    });
    // A extensão `heraclitus` não faz parte do OTLP; existe para o quickstart
    // conseguir mostrar o que aconteceu sem abrir a Consola.
    payload["heraclitus"] = serde_json::json!({
        "accepted": accepted,
        "duplicated": duplicated,
        "ignoredSpans": batch.ignored_spans,
        "truncatedAttributes": batch.truncated_attributes,
    });

    if let Err(e) = runtime.flush() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "EVIDENCE_APPEND_FAILED", "detail": e.to_string() })),
        )
            .into_response();
    }
    (StatusCode::OK, Json(payload)).into_response()
}

async fn not_ingested() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "partialSuccess": {},
            "heraclitus": {
                "note": "este produto ingere traces (/v1/traces). Métricas e logs são aceites e descartados."
            }
        })),
    )
        .into_response()
}
