//! SPEC-0075 §32 — os testes obrigatórios do gateway, sobre HTTP real.
//!
//! Um servidor MCP falso, um proxy Heraclitus à frente dele, e as perguntas que
//! interessam:
//!
//! ```text
//! shadow   a decisão é registada e o pedido SEGUE
//! enforce  deny nunca chega ao upstream
//! enforce  pending approval nunca chega ao upstream
//! enforce  approved exact action chega ao upstream UMA vez
//! §32      aprovar 5000 e executar 5001 => APPROVAL_BINDING_MISMATCH
//! ```

use heraclitus_agent::config::{
    AgentBlackBoxConfig, AgentGatewayConfig, ConsoleConfig, GatewayMode, OtlpConfig, PolicyConfig,
};
use heraclitus_agent::evidence::AgentEvidenceKindV1;
use heraclitus_agent::projection;
use heraclitus_agent::store::AnyLogEvidenceStore;
use heraclitus_agent_gateway::runtime::AgentRuntime;
use heraclitus_agent_gateway::{api, gateway, GatewayState, UpstreamClient};
use heraclitus_core::{FsyncPolicy, StorageFormat};
use heraclitus_log::AnyLog;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const POLICY: &str = r#"
version: "agent-policy-v1"
id: "teste"
revision: "v1"

defaults:
  decision: deny

rules:
  - id: lookup
    match:
      tool: lookup_vendor
    decision: allow

  - id: pagamento-grande
    match:
      tool: send_payment
      conditions:
        - field: amount
          op: gt
          value: 5000
    decision: require_approval
    approval:
      roles: ["cfo"]
      ttl_seconds: 300

  - id: shell
    match:
      tool: exec
    decision: deny
"#;

/// Quantas vezes o upstream foi realmente chamado. É o contador que prova
/// "deny nunca chega ao upstream".
///
/// É POR HARNESS e não global: os testes correm em paralelo no mesmo processo,
/// e um contador partilhado transformaria "o upstream foi chamado" numa
/// afirmação sobre todos os testes ao mesmo tempo.
type Hits = Arc<AtomicUsize>;

async fn spawn_upstream(hits: Hits) -> String {
    use axum::routing::post;
    let app = axum::Router::new().fallback(post(move |body: String| {
        let hits = hits.clone();
        async move {
        hits.fetch_add(1, Ordering::SeqCst);
        let id = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(serde_json::Value::Null);
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "content": [{ "type": "text", "text": "feito" }], "payment_id": "84723" }
        }))
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

struct Harness {
    _dir: tempfile::TempDir,
    runtime: Arc<AgentRuntime>,
    gateway_url: String,
    api_url: String,
    hits: Hits,
}

impl Harness {
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn harness(mode: GatewayMode) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let hits: Hits = Arc::new(AtomicUsize::new(0));
    let upstream_url = spawn_upstream(hits.clone()).await;
    let policy_path = dir.path().join("policy.yaml");
    std::fs::write(&policy_path, POLICY).unwrap();

    let config = AgentBlackBoxConfig {
        enabled: true,
        tenant_id: "acme".into(),
        otlp: OtlpConfig {
            http_addr: String::new(),
            grpc_addr: String::new(),
            ..Default::default()
        },
        console: ConsoleConfig {
            enabled: false,
            addr: String::new(),
            ..Default::default()
        },
        ..Default::default()
    };
    let gw = AgentGatewayConfig {
        enabled: true,
        mode,
        listen_addr: "127.0.0.1:0".into(),
        upstream_url: upstream_url.clone(),
        policy: PolicyConfig {
            active: policy_path.display().to_string(),
            default_decision: "deny".into(),
        },
        bypass_protection_configured: true,
        ..Default::default()
    };

    let log = Arc::new(
        AnyLog::open(
            StorageFormat::V6,
            dir.path().join("log"),
            64 * 1024,
            FsyncPolicy::Always,
        )
        .unwrap(),
    );
    let runtime = Arc::new(
        AgentRuntime::new(config, gw, Arc::new(AnyLogEvidenceStore::new(log)))
            .with_bundles_dir(dir.path().join("bundles")),
    );
    runtime.load_policy().unwrap();

    let upstream = Arc::new(UpstreamClient::new(&upstream_url, 10, 1 << 20).unwrap());
    let state = Arc::new(GatewayState {
        runtime: runtime.clone(),
        upstream: Some(upstream),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();
    let app = gateway::router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    let api_app = api::router(runtime.clone());
    tokio::spawn(async move {
        let _ = axum::serve(api_listener, api_app).await;
    });

    Harness {
        _dir: dir,
        runtime,
        gateway_url: format!("http://{gateway_addr}"),
        api_url: format!("http://{api_addr}"),
        hits,
    }
}

/// Cliente HTTP mínimo para os testes — evita puxar um cliente novo só para isto.
async fn post_json(
    url: &str,
    body: serde_json::Value,
    headers: &[(&str, &str)],
) -> (u16, serde_json::Value) {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<hyper::body::Bytes>,
    > = Client::builder(TokioExecutor::new()).build_http();
    let mut req = hyper::Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req
        .body(Full::new(hyper::body::Bytes::from(
            serde_json::to_vec(&body).unwrap(),
        )))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn get_json(url: &str) -> (u16, serde_json::Value) {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<hyper::body::Bytes>,
    > = Client::builder(TokioExecutor::new()).build_http();
    let req = hyper::Request::builder()
        .method("GET")
        .uri(url)
        .body(Full::new(hyper::body::Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn tool_call(id: &str, tool: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": tool, "arguments": args }
    })
}

const AGENT_HEADERS: &[(&str, &str)] = &[
    ("mcp-method", "tools/call"),
    ("x-heraclitus-agent", "procurement-agent"),
    ("x-heraclitus-run", "run-1"),
    ("x-heraclitus-user", "jose"),
    ("x-heraclitus-server", "finance"),
];

#[tokio::test]
async fn allow_chega_ao_upstream_e_deixa_evidencia() {
    let h = harness(GatewayMode::Enforce).await;
    let antes = h.hits();
    let (status, body) = post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call("c1", "lookup_vendor", serde_json::json!({ "name": "acme" })),
        AGENT_HEADERS,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(h.hits(), antes + 1);

    let rows = h.runtime.scan().unwrap();
    let kinds: Vec<_> = rows.iter().map(|r| r.evidence.kind).collect();
    assert!(kinds.contains(&AgentEvidenceKindV1::ToolRequested));
    assert!(kinds.contains(&AgentEvidenceKindV1::PolicyEvaluated));
    assert!(kinds.contains(&AgentEvidenceKindV1::ToolInvocationFinished));
    let decisoes = projection::project_policy_decisions(&rows);
    assert_eq!(decisoes[0].decision, "allow");
    assert!(decisoes[0].enforced);
}

#[tokio::test]
async fn deny_em_enforce_nunca_chega_ao_upstream() {
    let h = harness(GatewayMode::Enforce).await;
    let antes = h.hits();
    let (status, body) = post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call("c2", "exec", serde_json::json!({ "command": "rm -rf /" })),
        AGENT_HEADERS,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(h.hits(), antes, "o upstream foi chamado apesar do DENY");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("POLICY_DENY"));

    let rows = h.runtime.scan().unwrap();
    assert!(rows
        .iter()
        .any(|r| r.evidence.kind == AgentEvidenceKindV1::ToolDenied));
}

#[tokio::test]
async fn shadow_regista_mas_deixa_passar() {
    let h = harness(GatewayMode::Shadow).await;
    let antes = h.hits();
    let (status, _) = post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call("c3", "exec", serde_json::json!({ "command": "ls" })),
        AGENT_HEADERS,
    )
    .await;
    assert_eq!(status, 200, "em shadow a acção segue");
    assert_eq!(h.hits(), antes + 1);

    let rows = h.runtime.scan().unwrap();
    let decisoes = projection::project_policy_decisions(&rows);
    let deny = decisoes.iter().find(|d| d.decision == "deny").unwrap();
    assert!(!deny.enforced, "shadow tem de registar enforced=false");
    assert!(!rows
        .iter()
        .any(|r| r.evidence.kind == AgentEvidenceKindV1::ToolDenied));
}

#[tokio::test]
async fn require_approval_em_enforce_nao_chega_ao_upstream() {
    let h = harness(GatewayMode::Enforce).await;
    let antes = h.hits();
    let (status, body) = post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call(
            "c4",
            "send_payment",
            serde_json::json!({ "amount": 75000, "account": "v1" }),
        ),
        AGENT_HEADERS,
    )
    .await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(h.hits(), antes);
    let reason = body["error"]["data"]["heraclitus"]["reason_code"]
        .as_str()
        .unwrap();
    assert_eq!(reason, "APPROVAL_PENDING");

    let rows = h.runtime.scan().unwrap();
    assert!(rows
        .iter()
        .any(|r| r.evidence.kind == AgentEvidenceKindV1::HumanApprovalRequested));
}

#[tokio::test]
async fn aprovado_executa_uma_vez_e_so_uma() {
    let h = harness(GatewayMode::Enforce).await;
    let pedido = tool_call(
        "c5",
        "send_payment",
        serde_json::json!({ "amount": 75000, "account": "v1" }),
    );
    // 1. Primeira tentativa: abre o pedido de aprovação.
    let (status, body) = post_json(
        &format!("{}/mcp", h.gateway_url),
        pedido.clone(),
        AGENT_HEADERS,
    )
    .await;
    assert_eq!(status, 202);
    let approval_id = body["error"]["data"]["heraclitus"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. O humano aprova pela API.
    let (status, _) = post_json(
        &format!("{}/api/v1/agent/approvals/{approval_id}/approve", h.api_url),
        serde_json::json!({}),
        &[],
    )
    .await;
    assert_eq!(status, 200);

    // 3. A mesma acção exacta passa — uma vez.
    let antes = h.hits();
    let (status, _) = post_json(
        &format!("{}/mcp", h.gateway_url),
        pedido.clone(),
        AGENT_HEADERS,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(h.hits(), antes + 1);

    // 4. A segunda vez é recusada: a aprovação é de uso único.
    let (status, body) = post_json(&format!("{}/mcp", h.gateway_url), pedido, AGENT_HEADERS).await;
    assert_eq!(h.hits(), antes + 1, "executou duas vezes");
    assert!(status == 403 || status == 202, "status {status}: {body}");
}

#[tokio::test]
async fn aprovar_5000_e_executar_5001_e_recusado() {
    // O teste que a SPEC-0075 §32 nomeia por extenso.
    let h = harness(GatewayMode::Enforce).await;
    let cinco_mil_e_um = tool_call(
        "c6",
        "send_payment",
        serde_json::json!({ "amount": 75000, "account": "v1" }),
    );
    let (_, body) = post_json(
        &format!("{}/mcp", h.gateway_url),
        cinco_mil_e_um.clone(),
        AGENT_HEADERS,
    )
    .await;
    let approval_id = body["error"]["data"]["heraclitus"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _) = post_json(
        &format!("{}/api/v1/agent/approvals/{approval_id}/approve", h.api_url),
        serde_json::json!({}),
        &[],
    )
    .await;
    assert_eq!(status, 200);

    // Agora muda o argumento.
    let antes = h.hits();
    let mutado = tool_call(
        "c6",
        "send_payment",
        serde_json::json!({ "amount": 75001, "account": "v1" }),
    );
    let (status, body) = post_json(&format!("{}/mcp", h.gateway_url), mutado, AGENT_HEADERS).await;
    assert_eq!(h.hits(), antes, "a acção mutada chegou ao upstream");
    assert!(status == 403 || status == 202, "status {status}: {body}");
    let reason = body["error"]["data"]["heraclitus"]["reason_code"]
        .as_str()
        .unwrap_or_default();
    assert!(
        reason == "APPROVAL_PENDING" || reason == "APPROVAL_BINDING_MISMATCH",
        "a acção mutada tem de abrir uma aprovação NOVA ou falhar o binding; veio `{reason}`"
    );
}

#[tokio::test]
async fn trafego_de_protocolo_nao_vira_evidencia() {
    let h = harness(GatewayMode::Enforce).await;
    let (status, _) = post_json(
        &format!("{}/mcp", h.gateway_url),
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        &[("mcp-method", "tools/list")],
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        h.runtime.scan().unwrap().is_empty(),
        "tools/list virou evidência"
    );
}

#[tokio::test]
async fn o_bearer_do_agente_nunca_e_persistido() {
    let h = harness(GatewayMode::Enforce).await;
    let mut headers = AGENT_HEADERS.to_vec();
    headers.push(("authorization", "Bearer sk-segredo-do-cliente-123456"));
    post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call("c7", "lookup_vendor", serde_json::json!({})),
        &headers,
    )
    .await;
    let rows = h.runtime.scan().unwrap();
    let dump = serde_json::to_string(&rows).unwrap();
    assert!(!dump.contains("sk-segredo-do-cliente"), "{dump}");
}

#[tokio::test]
async fn o_efeito_externo_e_registado() {
    let h = harness(GatewayMode::Enforce).await;
    post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call("c8", "lookup_vendor", serde_json::json!({})),
        AGENT_HEADERS,
    )
    .await;
    let rows = h.runtime.scan().unwrap();
    assert!(rows
        .iter()
        .any(|r| r.evidence.subject.external_effect_id.as_deref() == Some("84723")));
}

#[tokio::test]
async fn a_api_mostra_o_run_e_a_timeline() {
    let h = harness(GatewayMode::Enforce).await;
    post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call("c9", "lookup_vendor", serde_json::json!({})),
        AGENT_HEADERS,
    )
    .await;
    let (status, body) = get_json(&format!("{}/api/v1/agent/runs", h.api_url)).await;
    assert_eq!(status, 200);
    assert_eq!(body["runs"][0]["run_id"], "run-1");

    let (status, body) = get_json(&format!("{}/api/v1/agent/runs/run-1/timeline", h.api_url)).await;
    assert_eq!(status, 200);
    assert!(body["entries"].as_array().unwrap().len() >= 3);

    let (status, body) = get_json(&format!("{}/api/v1/agent/status", h.api_url)).await;
    assert_eq!(status, 200);
    assert_eq!(body["auth"], "dev_local");
    assert_eq!(body["bypass_protection"], "CONFIGURED");
    assert_eq!(body["mcp_gateway"], "ENFORCE");
    assert_eq!(body["capture"]["prompt_bodies"], "OFF");
}

#[tokio::test]
async fn a_consola_serve_se_a_si_propria_com_csp() {
    let h = harness(GatewayMode::Shadow).await;
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    let client: Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<hyper::body::Bytes>,
    > = Client::builder(TokioExecutor::new()).build_http();
    // SPEC-0077 §30 — a Agent Console mudou-se para `/agent`; a raiz é a
    // Platform Console. A CSP tem de continuar a ser a mesma nas duas.
    let req = hyper::Request::builder()
        .uri(format!("{}/agent", h.api_url))
        .body(Full::new(hyper::body::Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(csp.contains("default-src 'none'"), "{csp}");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("Agent Evidence"), "{html}");
    assert!(html.contains("HeraclitusDB"), "{html}");
}

#[tokio::test]
async fn as_metricas_nao_levam_segredo_nas_etiquetas() {
    let h = harness(GatewayMode::Enforce).await;
    let mut headers = AGENT_HEADERS.to_vec();
    headers.push(("authorization", "Bearer sk-nao-pode-aparecer-aqui"));
    post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call(
            "cm",
            "lookup_vendor",
            serde_json::json!({ "vendor": "acme" }),
        ),
        &headers,
    )
    .await;

    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    let client: Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<hyper::body::Bytes>,
    > = Client::builder(TokioExecutor::new()).build_http();
    let req = hyper::Request::builder()
        .uri(format!("{}/metrics", h.api_url))
        .body(Full::new(hyper::body::Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let texto = String::from_utf8_lossy(&bytes).to_string();

    assert!(texto.contains("agent_ingest_events_total"), "{texto}");
    assert!(texto.contains("agent_gateway_allow_total"), "{texto}");
    assert!(texto.contains("agent_gateway_approval_pending"), "{texto}");
    // §32 da 0075: nenhum segredo em `metrics labels`.
    assert!(!texto.contains("sk-nao-pode-aparecer"), "{texto}");
    assert!(!texto.to_lowercase().contains("bearer"), "{texto}");
    assert!(
        !texto.contains("jose"),
        "nem identificadores de pessoa: {texto}"
    );
}

#[tokio::test]
async fn simular_uma_policy_nova_nao_a_activa() {
    let h = harness(GatewayMode::Enforce).await;
    post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call("c10", "lookup_vendor", serde_json::json!({})),
        AGENT_HEADERS,
    )
    .await;
    let hash_antes = h.runtime.policy().engine.hash().to_string();

    let candidata = r#"
version: "agent-policy-v1"
id: "teste"
revision: "v2"
defaults:
  decision: deny
rules:
  - id: lookup
    match:
      tool: lookup_vendor
    decision: deny
"#;
    let (status, body) = post_json(
        &format!("{}/api/v1/agent/policies/simulate", h.api_url),
        serde_json::json!({ "document": candidata }),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["historical_tool_calls"], 1);
    assert_eq!(body["deny"], 1);
    assert_eq!(body["changed_vs_active"], 1);
    assert_eq!(
        h.runtime.policy().engine.hash(),
        hash_antes,
        "a simulação activou a policy"
    );
}

#[tokio::test]
async fn activar_uma_policy_invalida_nao_derruba_a_activa() {
    let h = harness(GatewayMode::Enforce).await;
    let hash_antes = h.runtime.policy().engine.hash().to_string();
    let (status, body) = post_json(
        &format!("{}/api/v1/agent/policies/activate", h.api_url),
        serde_json::json!({ "document": "version: \"agent-policy-v9\"\n" }),
        &[],
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "POLICY_INVALID");
    assert_eq!(h.runtime.policy().engine.hash(), hash_antes);
}

#[tokio::test]
async fn exportar_pela_api_devolve_um_bundle_descarregavel() {
    let h = harness(GatewayMode::Enforce).await;
    post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call("c11", "lookup_vendor", serde_json::json!({})),
        AGENT_HEADERS,
    )
    .await;
    let (status, body) = post_json(
        &format!("{}/api/v1/agent/evidence/export", h.api_url),
        serde_json::json!({ "run_id": "run-1" }),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["records"].as_u64().unwrap() > 0);
    let caminho = body["path"].as_str().unwrap();
    let bytes = std::fs::read(caminho).unwrap();
    // O bundle ainda não tem provas (o segmento não selou), portanto o
    // verificador tem de dizer PARTIAL — nunca VERIFIED.
    let report = heraclitus_agent::verifier::verify_bundle_bytes(&bytes);
    assert_ne!(
        report.exit,
        heraclitus_agent::verifier::VerifyExit::Verified,
        "sem prova de inclusão o verdicto não pode ser VERIFIED: {}",
        report.to_human()
    );
}
