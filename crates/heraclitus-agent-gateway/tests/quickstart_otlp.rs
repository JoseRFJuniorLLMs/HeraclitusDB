//! SPEC-0074 §27 e SPEC-0076 §20 — o quickstart, testado.
//!
//! O gate de produto é "menos de cinco minutos até ao primeiro run visível". O
//! que isso exige do código é uma coisa só: **um lote OTLP com a forma que o
//! agente de exemplo produz tem de aparecer como um run na API**, sem
//! configuração adicional.
//!
//! O payload abaixo é o mesmo que
//! `examples/agent-black-box/sample-python-agent/sample.py` monta. Se a forma
//! do exemplo mudar e este teste não, o quickstart parte em silêncio — e o
//! utilizador descobre-o com uma página vazia, que é a pior forma de o
//! descobrir.

use heraclitus_agent::config::{
    AgentBlackBoxConfig, AgentGatewayConfig, ConsoleConfig, OtlpConfig,
};
use heraclitus_agent::store::AnyLogEvidenceStore;
use heraclitus_agent_gateway::runtime::AgentRuntime;
use heraclitus_agent_gateway::{api, ingest};
use heraclitus_core::{FsyncPolicy, StorageFormat};
use heraclitus_log::AnyLog;
use std::sync::Arc;

/// A forma exacta que o agente de exemplo manda.
const LOTE: &str = r#"{
  "resourceSpans": [{
    "resource": { "attributes": [
      { "key": "service.name", "value": { "stringValue": "procurement-agent" } },
      { "key": "service.version", "value": { "stringValue": "1.0.0" } },
      { "key": "service.instance.id", "value": { "stringValue": "sample-1" } },
      { "key": "deployment.environment.name", "value": { "stringValue": "demo" } }
    ]},
    "scopeSpans": [{
      "scope": { "name": "heraclitus.sample-python-agent", "version": "1.0.0" },
      "spans": [
        {
          "traceId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "spanId": "1111111111111111",
          "name": "invoke_agent procurement-agent",
          "startTimeUnixNano": "1700000000000000000",
          "endTimeUnixNano": "1700000014000000000",
          "attributes": [
            { "key": "gen_ai.operation.name", "value": { "stringValue": "invoke_agent" } },
            { "key": "gen_ai.agent.id", "value": { "stringValue": "procurement-agent" } },
            { "key": "gen_ai.agent.name", "value": { "stringValue": "Procurement Agent" } },
            { "key": "gen_ai.system", "value": { "stringValue": "demo" } },
            { "key": "heraclitus.agent.run_id", "value": { "stringValue": "run-quickstart" } },
            { "key": "heraclitus.agent.tenant", "value": { "stringValue": "default" } },
            { "key": "heraclitus.agent.human.subject", "value": { "stringValue": "jose@example" } }
          ],
          "status": { "code": "STATUS_CODE_OK" }
        },
        {
          "traceId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "spanId": "2222222222222222",
          "parentSpanId": "1111111111111111",
          "name": "chat demo-model",
          "startTimeUnixNano": "1700000000500000000",
          "endTimeUnixNano": "1700000001800000000",
          "attributes": [
            { "key": "gen_ai.operation.name", "value": { "stringValue": "chat" } },
            { "key": "gen_ai.system", "value": { "stringValue": "demo" } },
            { "key": "gen_ai.request.model", "value": { "stringValue": "demo-model" } },
            { "key": "gen_ai.usage.input_tokens", "value": { "intValue": "412" } },
            { "key": "gen_ai.prompt", "value": { "stringValue": "pagar a fatura do fornecedor 8832" } },
            { "key": "heraclitus.agent.run_id", "value": { "stringValue": "run-quickstart" } }
          ],
          "status": { "code": "STATUS_CODE_OK" }
        },
        {
          "traceId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "spanId": "3333333333333333",
          "parentSpanId": "1111111111111111",
          "name": "execute_tool lookup_vendor",
          "startTimeUnixNano": "1700000002000000000",
          "endTimeUnixNano": "1700000002400000000",
          "attributes": [
            { "key": "gen_ai.operation.name", "value": { "stringValue": "execute_tool" } },
            { "key": "gen_ai.tool.name", "value": { "stringValue": "lookup_vendor" } },
            { "key": "gen_ai.tool.call.id", "value": { "stringValue": "run-quickstart-call-1" } },
            { "key": "heraclitus.agent.server", "value": { "stringValue": "finance" } },
            { "key": "heraclitus.agent.run_id", "value": { "stringValue": "run-quickstart" } }
          ],
          "status": { "code": "STATUS_CODE_OK" }
        },
        {
          "traceId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "spanId": "4444444444444444",
          "parentSpanId": "1111111111111111",
          "name": "execute_tool send_payment",
          "startTimeUnixNano": "1700000005000000000",
          "endTimeUnixNano": "1700000006400000000",
          "attributes": [
            { "key": "gen_ai.operation.name", "value": { "stringValue": "execute_tool" } },
            { "key": "gen_ai.tool.name", "value": { "stringValue": "send_payment" } },
            { "key": "gen_ai.tool.call.id", "value": { "stringValue": "run-quickstart-call-4" } },
            { "key": "heraclitus.agent.server", "value": { "stringValue": "finance" } },
            { "key": "heraclitus.agent.run_id", "value": { "stringValue": "run-quickstart" } },
            { "key": "amount", "value": { "intValue": "75000" } },
            { "key": "error.type", "value": { "stringValue": "ToolError" } }
          ],
          "status": { "code": "STATUS_CODE_ERROR", "message": "payment above approval threshold" }
        },
        {
          "traceId": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "spanId": "5555555555555555",
          "name": "GET /healthz",
          "startTimeUnixNano": "1700000007000000000",
          "endTimeUnixNano": "1700000007100000000",
          "attributes": [
            { "key": "http.request.method", "value": { "stringValue": "GET" } }
          ],
          "status": { "code": "STATUS_CODE_OK" }
        }
      ]
    }]
  }]
}"#;

struct Quickstart {
    _dir: tempfile::TempDir,
    otlp_url: String,
    api_url: String,
}

async fn arrancar() -> Quickstart {
    arrancar_com(4 * 1024 * 1024).await
}

async fn arrancar_com(max_body_bytes: usize) -> Quickstart {
    let dir = tempfile::tempdir().unwrap();
    let config = AgentBlackBoxConfig {
        enabled: true,
        tenant_id: "default".into(),
        max_body_bytes,
        limits: heraclitus_agent::otlp::IngestLimits {
            max_body_bytes,
            ..Default::default()
        },
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
        AgentRuntime::new(
            config,
            AgentGatewayConfig::default(),
            Arc::new(AnyLogEvidenceStore::new(log)),
        )
        .with_bundles_dir(dir.path().join("bundles")),
    );

    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let otlp_addr = l1.local_addr().unwrap();
    let app = ingest::router(runtime.clone());
    tokio::spawn(async move {
        let _ = axum::serve(l1, app).await;
    });

    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = l2.local_addr().unwrap();
    let app = api::router(runtime.clone());
    tokio::spawn(async move {
        let _ = axum::serve(l2, app).await;
    });

    Quickstart {
        _dir: dir,
        otlp_url: format!("http://{otlp_addr}"),
        api_url: format!("http://{api_addr}"),
    }
}

async fn post(url: &str, body: impl Into<Vec<u8>>, content_type: &str) -> (u16, serde_json::Value) {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    let client: Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<hyper::body::Bytes>,
    > = Client::builder(TokioExecutor::new()).build_http();
    let req = hyper::Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", content_type)
        .body(Full::new(hyper::body::Bytes::from(body.into())))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn get(url: &str) -> serde_json::Value {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    let client: Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<hyper::body::Bytes>,
    > = Client::builder(TokioExecutor::new()).build_http();
    let req = hyper::Request::builder()
        .uri(url)
        .body(Full::new(hyper::body::Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn o_lote_do_agente_de_exemplo_vira_um_run_visivel() {
    let q = arrancar().await;
    let (status, body) = post(
        &format!("{}/v1/traces", q.otlp_url),
        LOTE,
        "application/json",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["heraclitus"]["accepted"].as_u64().unwrap() > 0,
        "{body}"
    );
    // O span `GET /healthz` não tem marca GenAI: é ignorado por desenho (§34).
    assert_eq!(body["heraclitus"]["ignoredSpans"], 1, "{body}");

    let runs = get(&format!("{}/api/v1/agent/runs", q.api_url)).await;
    let lista = runs["runs"].as_array().unwrap();
    assert_eq!(lista.len(), 1, "{runs}");
    assert_eq!(lista[0]["run_id"], "run-quickstart");
    assert_eq!(lista[0]["agent_id"], "procurement-agent");
    assert_eq!(lista[0]["human_subject"], "jose@example");
    assert_eq!(lista[0]["tool_calls"], 2);
    assert_eq!(lista[0]["status"], "failed", "o pagamento grande falhou");
    // Sem segmento selado ainda não há prova; o produto di-lo em vez de pintar
    // de verde.
    assert_eq!(lista[0]["integrity"], "UNVERIFIED");

    let tl = get(&format!(
        "{}/api/v1/agent/runs/run-quickstart/timeline",
        q.api_url
    ))
    .await;
    let kinds: Vec<&str> = tl["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    for esperado in [
        "RunStarted",
        "RunFinished",
        "ModelInvocationFinished",
        "ToolInvocationStarted",
        "ToolInvocationFinished",
        "ErrorObserved",
    ] {
        assert!(kinds.contains(&esperado), "faltou {esperado}: {kinds:?}");
    }
}

#[tokio::test]
async fn o_prompt_do_exemplo_nao_fica_em_claro() {
    let q = arrancar().await;
    post(
        &format!("{}/v1/traces", q.otlp_url),
        LOTE,
        "application/json",
    )
    .await;
    let tl = get(&format!(
        "{}/api/v1/agent/runs/run-quickstart/timeline?limit=500",
        q.api_url
    ))
    .await;
    let texto = tl.to_string();
    assert!(
        !texto.contains("pagar a fatura do fornecedor"),
        "o prompt apareceu em claro: {texto}"
    );
}

#[tokio::test]
async fn retransmitir_o_lote_nao_duplica_o_run() {
    let q = arrancar().await;
    let (_, primeiro) = post(
        &format!("{}/v1/traces", q.otlp_url),
        LOTE,
        "application/json",
    )
    .await;
    let aceites = primeiro["heraclitus"]["accepted"].as_u64().unwrap();

    let (_, segundo) = post(
        &format!("{}/v1/traces", q.otlp_url),
        LOTE,
        "application/json",
    )
    .await;
    assert_eq!(segundo["heraclitus"]["accepted"], 0, "{segundo}");
    assert_eq!(segundo["heraclitus"]["duplicated"], aceites, "{segundo}");

    let runs = get(&format!("{}/api/v1/agent/runs", q.api_url)).await;
    assert_eq!(runs["runs"].as_array().unwrap().len(), 1);
    assert_eq!(runs["runs"][0]["tool_calls"], 2, "a tool call duplicou");
}

#[tokio::test]
async fn protobuf_e_json_dao_o_mesmo_resultado() {
    use prost::Message;
    let td = heraclitus_agent::otlp::json::decode_traces_json(LOTE.as_bytes()).unwrap();
    let bytes = td.encode_to_vec();

    let q = arrancar().await;
    let (status, body) = post(
        &format!("{}/v1/traces", q.otlp_url),
        bytes,
        "application/x-protobuf",
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let runs = get(&format!("{}/api/v1/agent/runs", q.api_url)).await;
    assert_eq!(runs["runs"][0]["run_id"], "run-quickstart");
    assert_eq!(runs["runs"][0]["tool_calls"], 2);
}

#[tokio::test]
async fn o_tecto_configurado_e_o_tecto_efectivo() {
    // O default do axum são 2 MiB e aplica-se ANTES do handler. Se ele ganhasse
    // ao valor configurado, `max_body_bytes` seria uma configuração que mente.
    let q = arrancar_com(64 * 1024).await;

    // Logo abaixo do tecto: chega ao handler e é recusado por nós, com o código
    // de erro do produto.
    let quase = format!(
        "{{\"resourceSpans\":[],\"lixo\":\"{}\"}}",
        "x".repeat(60 * 1024)
    );
    let (status, body) = post(
        &format!("{}/v1/traces", q.otlp_url),
        quase.as_str(),
        "application/json",
    )
    .await;
    assert_eq!(status, 200, "abaixo do tecto tem de passar: {body}");

    // Acima do tecto: recusado. O axum devolve 413 sem corpo nosso quando o
    // corte acontece na camada de transporte, e o handler devolve 413 com
    // `INGEST_REJECTED` quando o corpo chega inteiro. Os dois são 413 — que é a
    // afirmação que interessa.
    let grande = format!(
        "{{\"resourceSpans\":[],\"lixo\":\"{}\"}}",
        "x".repeat(200 * 1024)
    );
    let (status, _) = post(
        &format!("{}/v1/traces", q.otlp_url),
        grande.as_str(),
        "application/json",
    )
    .await;
    assert_eq!(status, 413);
}

#[tokio::test]
async fn o_handler_recusa_o_que_excede_o_seu_proprio_tecto() {
    // Caminho directo, sem HTTP: o normalizador tem o seu tecto e di-lo.
    let n = heraclitus_agent::otlp::OtlpNormalizer::new("t").with_limits(
        heraclitus_agent::otlp::IngestLimits {
            max_body_bytes: 16,
            ..Default::default()
        },
    );
    let err = n.ingest_http("application/json", &[b'x'; 64]).unwrap_err();
    assert!(matches!(
        err,
        heraclitus_agent::otlp::OtlpError::BodyTooLarge(64, 16)
    ));
}

#[tokio::test]
async fn metricas_e_logs_sao_aceites_e_descartados() {
    let q = arrancar().await;
    for caminho in ["/v1/metrics", "/v1/logs"] {
        let (status, _) = post(
            &format!("{}{caminho}", q.otlp_url),
            "{}",
            "application/json",
        )
        .await;
        assert_eq!(status, 200, "{caminho}");
    }
    let runs = get(&format!("{}/api/v1/agent/runs", q.api_url)).await;
    assert!(runs["runs"].as_array().unwrap().is_empty());
}
