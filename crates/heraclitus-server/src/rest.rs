//! Minimal admin REST (axum) — a thin layer over the same engine.

use crate::engine::Engine;
use axum::{
    extract::{Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use std::sync::Arc;

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
pub fn router(engine: Arc<Engine>, basic_auth: Option<String>) -> Router {
    let routes = Router::new()
        .route("/healthz", get(healthz))
        .route("/stats", get(stats))
        .route("/state", get(state))
        .route("/verify", get(verify))
        .route("/verify/:segment", get(verify_segment))
        // M20 — H-VM sovereignty ledger (SPEC-025-adjacente). KV durável no log.
        .route("/hvm/state", get(hvm_state))
        .route("/hvm/upsert", axum::routing::post(hvm_upsert))
        .route("/hvm/delete", axum::routing::post(hvm_delete))
        .route("/hvm/checkpoint", axum::routing::post(hvm_checkpoint));
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
    let routes = routes.with_state(engine);

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
async fn sql(
    State(engine): State<Arc<Engine>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
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
        .map_err(|_| (StatusCode::REQUEST_TIMEOUT, "timeout executando SQL".to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("sql: {e}")))?;

    if rows.len() > 10_000 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "Conjunto de resultados muito grande (> 10.000 linhas). Utilize LIMIT.".to_string()));
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
        .map(|(k, v)| {
            (
                bytes_str(k),
                serde_json::Value::String(bytes_str(v)),
            )
        })
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
async fn hvm_upsert(State(engine): State<Arc<Engine>>, Json(body): Json<serde_json::Value>) -> Response {
    use axum::response::IntoResponse;
    let (Some(key), Some(val)) = (
        body.get("key").and_then(|v| v.as_str()),
        body.get("val").and_then(|v| v.as_str()),
    ) else {
        return (StatusCode::BAD_REQUEST, "corpo requer os campos string `key` e `val`").into_response();
    };
    let (key, val) = (key.as_bytes().to_vec(), val.as_bytes().to_vec());
    match tokio::task::spawn_blocking(move || engine.hvm_upsert(key, val)).await {
        Ok(Ok(lsn)) => Json(serde_json::json!({ "lsn": lsn })).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("hvm: {e}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")).into_response(),
    }
}

/// `POST /hvm/delete` — corpo `{"key":"…"}` → `{"lsn":n}`.
async fn hvm_delete(State(engine): State<Arc<Engine>>, Json(body): Json<serde_json::Value>) -> Response {
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
        return (StatusCode::CONFLICT, "demote requer object store partilhado sob replicacao").into_response();
    }
    let Some(seg) = body.get("segment").and_then(|v| v.as_u64()) else {
        return (StatusCode::BAD_REQUEST, "corpo requer o campo inteiro `segment`").into_response();
    };
    // demote faz fs::read + blake3 + encode Parquet + fsync — fora do reactor.
    let res = tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(engine.demote_segment(seg))
    })
    .await;
    match res {
        Ok(Ok(r)) => Json(serde_json::json!({
            "segment_id": r.segment_id,
            "object_path": r.object_path,
            "parquet_path": r.parquet_path,
            "record_count": r.record_count,
            "min_lsn": r.min_lsn,
            "max_lsn": r.max_lsn,
            "blake3_root": r.blake3_root,
        }))
        .into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("tier: {e}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")).into_response(),
    }
}

/// `GET /tier/receipts` → recibos de demote no log (o que já foi para o cold tier).
#[cfg(feature = "tier")]
async fn tier_receipts(State(engine): State<Arc<Engine>>) -> Response {
    use axum::response::IntoResponse;
    // Scan do log em spawn_blocking (nunca no reactor).
    match tokio::task::spawn_blocking(move || engine.demotion_receipts()).await {
        Ok(Ok(rs)) => {
            let arr: Vec<_> = rs
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "segment_id": r.segment_id,
                        "object_path": r.object_path,
                        "parquet_path": r.parquet_path,
                        "record_count": r.record_count,
                        "min_lsn": r.min_lsn,
                        "max_lsn": r.max_lsn,
                    })
                })
                .collect();
            Json(serde_json::json!({ "receipts": arr })).into_response()
        }
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("tier: {e}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")).into_response(),
    }
}

/// `GET /tier/fetch/:segment` — recall: busca o segmento demotado do cold tier e
/// devolve os episódios (lsn/agent/kind/content). NÃO reinsere nos índices
/// quentes (recall-on-demand puro; a re-hidratação é follow-up).
#[cfg(feature = "tier")]
async fn tier_fetch(
    State(engine): State<Arc<Engine>>,
    Path(segment): Path<u64>,
) -> Response {
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

async fn stats(State(engine): State<Arc<Engine>>) -> Json<serde_json::Value> {
    Json(engine.stats())
}

/// `heraclitus_state()`: head, segmentos e watermarks — diagnóstico num GET.
async fn state(State(engine): State<Arc<Engine>>) -> Json<serde_json::Value> {
    Json(engine.state())
}

/// Verificação Merkle do log inteiro. `Log::verify` re-lê+re-hasha todos os
/// segmentos → `spawn_blocking` (nunca bloquear o reactor / os probes de saúde).
async fn verify(State(engine): State<Arc<Engine>>) -> Json<serde_json::Value> {
    let out = match tokio::task::spawn_blocking(move || engine.verify()).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => serde_json::json!({ "error": e.to_string() }),
        Err(e) => serde_json::json!({ "error": format!("join: {e}") }),
    };
    Json(out)
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
        let as_of = run_sql(&engine, "SELECT COUNT(*) AS n FROM events".to_owned(), Some(6))
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
        engine.hvm_upsert(b"user:1".to_vec(), b"alice".to_vec()).unwrap();
        engine.hvm_upsert(b"user:2".to_vec(), b"bob".to_vec()).unwrap();
        engine.hvm_delete(b"user:1".to_vec()).unwrap();

        let v = hvm_state_json(&engine).unwrap();
        assert_eq!(v["entries"]["user:2"], "bob");
        assert!(v["entries"].get("user:1").is_none(), "chave apagada não aparece");
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
        engine.hvm_upsert(b"bin".to_vec(), vec![0x00, 0xff]).unwrap();

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
        engine.hvm_upsert(b"hex:ff".to_vec(), b"literal".to_vec()).unwrap();
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
    use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusConfig};

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
        assert!(engine.verify_demotion(&receipt).await.unwrap(), "recibo verifica");

        // Recall round-trip: o recibo está listado e o segmento busca-se de volta
        // do cold tier (object store) com todos os episódios.
        let receipts = engine.demotion_receipts().unwrap();
        assert!(receipts.iter().any(|r| r.segment_id == seg), "recibo listado");
        let back = engine.fetch_cold_segment(seg).await.unwrap();
        assert_eq!(back.len() as u64, receipt.record_count, "recall devolve todos os episódios");

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
        assert_eq!(new[0].dropped, tombstoned, "removeu exatamente os tombstonados");
        assert_eq!(
            new[0].record_count + new[0].dropped,
            receipt.record_count,
            "kept + dropped == original"
        );
        assert!(engine.verify_demotion(&new[0]).await.unwrap(), "recibo novo verifica");

        // O recall do segmento passa a devolver só os sobreviventes.
        let survivors = engine.fetch_cold_segment(seg).await.unwrap();
        assert_eq!(survivors.len() as u64, new[0].record_count);

        // Idempotência: os tombstonados já foram removidos ⇒ 2º tick é no-op.
        let again = engine.tier_compaction_tick(&policy).await.unwrap();
        assert!(again.is_empty(), "sem lixo novo, nada a compactar: {again:?}");
    }
}
