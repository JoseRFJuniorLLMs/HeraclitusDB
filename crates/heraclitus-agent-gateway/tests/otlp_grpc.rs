//! SPEC-0074 §12 e §30 — o receptor OTLP/gRPC, sobre gRPC real.
//!
//! A afirmação que estes testes seguram é a que a §12 faz e que é fácil
//! quebrar sem ninguém notar:
//!
//! > Os dois transportes descem à MESMA normalização.
//!
//! Um lote enviado por gRPC e o mesmo lote enviado por HTTP têm de produzir
//! evidência idêntica byte a byte — e o segundo tem de ser deduplicado, porque
//! é o mesmo facto e não um facto novo.

use heraclitus_agent::config::{
    AgentBlackBoxConfig, AgentGatewayConfig, ConsoleConfig, OtlpConfig,
};
use heraclitus_agent::otlp::proto::{
    any_value, AnyValue, ExportTraceServiceRequest, KeyValue, Resource, ResourceSpans, ScopeSpans,
    Span, Status,
};
use heraclitus_agent::store::AnyLogEvidenceStore;
use heraclitus_agent_gateway::grpc::{
    client::TraceServiceClient, AgentTraceService, TraceServiceServer,
};
use heraclitus_agent_gateway::runtime::AgentRuntime;
use heraclitus_agent_gateway::{api, ingest};
use heraclitus_core::{FsyncPolicy, StorageFormat};
use heraclitus_log::AnyLog;
use std::sync::Arc;

fn kv(k: &str, v: &str) -> KeyValue {
    KeyValue {
        key: k.into(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(v.into())),
        }),
    }
}

/// O mesmo run do agente de exemplo, na forma protobuf.
fn lote() -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![
                    kv("service.name", "procurement-agent"),
                    kv("service.instance.id", "sample-1"),
                ],
                dropped_attributes_count: 0,
            }),
            scope_spans: vec![ScopeSpans {
                scope: None,
                spans: vec![
                    Span {
                        trace_id: vec![0xaa; 16],
                        span_id: vec![0x11; 8],
                        name: "invoke_agent procurement-agent".into(),
                        start_time_unix_nano: 1_700_000_000_000_000_000,
                        end_time_unix_nano: 1_700_000_014_000_000_000,
                        attributes: vec![
                            kv("gen_ai.operation.name", "invoke_agent"),
                            kv("gen_ai.agent.id", "procurement-agent"),
                            kv("heraclitus.agent.run_id", "run-grpc"),
                            kv("heraclitus.agent.human.subject", "jose@example"),
                        ],
                        status: Some(Status {
                            code: 1,
                            message: String::new(),
                        }),
                        ..Default::default()
                    },
                    Span {
                        trace_id: vec![0xaa; 16],
                        span_id: vec![0x22; 8],
                        parent_span_id: vec![0x11; 8],
                        name: "execute_tool send_payment".into(),
                        start_time_unix_nano: 1_700_000_002_000_000_000,
                        end_time_unix_nano: 1_700_000_003_000_000_000,
                        attributes: vec![
                            kv("gen_ai.operation.name", "execute_tool"),
                            kv("gen_ai.tool.name", "send_payment"),
                            kv("gen_ai.tool.call.id", "call-grpc-1"),
                            kv("heraclitus.agent.server", "finance"),
                            kv("heraclitus.agent.run_id", "run-grpc"),
                        ],
                        status: Some(Status {
                            code: 1,
                            message: String::new(),
                        }),
                        ..Default::default()
                    },
                    // Sem marca GenAI: tem de ser ignorado (§34 da 0076).
                    Span {
                        trace_id: vec![0xbb; 16],
                        span_id: vec![0x33; 8],
                        name: "GET /healthz".into(),
                        start_time_unix_nano: 1_700_000_004_000_000_000,
                        end_time_unix_nano: 1_700_000_004_100_000_000,
                        attributes: vec![kv("http.request.method", "GET")],
                        ..Default::default()
                    },
                ],
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    runtime: Arc<AgentRuntime>,
    grpc_url: String,
    http_url: String,
    api_url: String,
}

async fn arrancar() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let config = AgentBlackBoxConfig {
        enabled: true,
        tenant_id: "default".into(),
        otlp: OtlpConfig {
            http_addr: String::new(),
            grpc_addr: String::new(),
        },
        console: ConsoleConfig {
            enabled: false,
            addr: String::new(),
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

    // gRPC
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_addr = l.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(l);
    let service = TraceServiceServer::new(AgentTraceService::new(runtime.clone()));
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    // HTTP, para comparar
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = l.local_addr().unwrap();
    let app = ingest::router(runtime.clone());
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });

    // API, para ver o resultado
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = l.local_addr().unwrap();
    let app = api::router(runtime.clone());
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });

    Fixture {
        _dir: dir,
        runtime,
        grpc_url: format!("http://{grpc_addr}"),
        http_url: format!("http://{http_addr}"),
        api_url: format!("http://{api_addr}"),
    }
}

async fn grpc_client(url: &str) -> TraceServiceClient<tonic::transport::Channel> {
    let canal = tonic::transport::Endpoint::from_shared(url.to_string())
        .unwrap()
        .connect()
        .await
        .expect("ligar ao listener gRPC");
    TraceServiceClient::new(canal)
}

async fn post_protobuf(url: &str, req: &ExportTraceServiceRequest) -> u16 {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use prost::Message;
    let bytes = req.encode_to_vec();
    let client: Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<hyper::body::Bytes>,
    > = Client::builder(TokioExecutor::new()).build_http();
    let r = hyper::Request::builder()
        .method("POST")
        .uri(format!("{url}/v1/traces"))
        .header("content-type", "application/x-protobuf")
        .body(Full::new(hyper::body::Bytes::from(bytes)))
        .unwrap();
    let resp = client.request(r).await.unwrap();
    let status = resp.status().as_u16();
    let _ = resp.into_body().collect().await;
    status
}

async fn get_json(url: &str) -> serde_json::Value {
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
async fn um_lote_por_grpc_vira_um_run_visivel() {
    let f = arrancar().await;
    let mut c = grpc_client(&f.grpc_url).await;
    let resposta = c.export(lote()).await.expect("Export deve aceitar");
    // Sem spans recusados, o OTLP manda não enviar `partial_success`.
    assert!(resposta.into_inner().partial_success.is_none());

    let runs = get_json(&format!("{}/api/v1/agent/runs", f.api_url)).await;
    let lista = runs["runs"].as_array().unwrap();
    assert_eq!(lista.len(), 1, "{runs}");
    assert_eq!(lista[0]["run_id"], "run-grpc");
    assert_eq!(lista[0]["agent_id"], "procurement-agent");
    assert_eq!(lista[0]["human_subject"], "jose@example");
    assert_eq!(lista[0]["tool_calls"], 1);

    // O span sem marca GenAI foi ignorado, não gravado.
    let c = *f.runtime.counters.lock().unwrap();
    assert_eq!(c.ignored, 1);
}

#[tokio::test]
async fn grpc_e_http_produzem_evidencia_identica() {
    // A afirmação central: dois transportes, uma normalização.
    let a = arrancar().await;
    let mut c = grpc_client(&a.grpc_url).await;
    c.export(lote()).await.unwrap();
    let por_grpc: Vec<_> = a
        .runtime
        .scan()
        .unwrap()
        .into_iter()
        .map(|r| r.evidence)
        .collect();

    let b = arrancar().await;
    assert_eq!(post_protobuf(&b.http_url, &lote()).await, 200);
    let por_http: Vec<_> = b
        .runtime
        .scan()
        .unwrap()
        .into_iter()
        .map(|r| r.evidence)
        .collect();

    assert!(!por_grpc.is_empty());
    assert_eq!(por_grpc, por_http, "os dois transportes divergiram");
}

#[tokio::test]
async fn o_mesmo_lote_pelos_dois_transportes_nao_duplica() {
    // Um operador que aponte metade da frota ao gRPC e metade ao HTTP não pode
    // acabar com a história a dobrar.
    let f = arrancar().await;
    let mut c = grpc_client(&f.grpc_url).await;
    c.export(lote()).await.unwrap();
    let depois_do_grpc = f.runtime.scan().unwrap().len();
    assert!(depois_do_grpc > 0);

    assert_eq!(post_protobuf(&f.http_url, &lote()).await, 200);
    assert_eq!(
        f.runtime.scan().unwrap().len(),
        depois_do_grpc,
        "o mesmo lote pelo outro transporte duplicou a história"
    );

    let contadores = *f.runtime.counters.lock().unwrap();
    assert_eq!(contadores.duplicates as usize, depois_do_grpc);
}

#[tokio::test]
async fn retransmitir_por_grpc_nao_duplica() {
    let f = arrancar().await;
    let mut c = grpc_client(&f.grpc_url).await;
    c.export(lote()).await.unwrap();
    let n = f.runtime.scan().unwrap().len();
    c.export(lote()).await.unwrap();
    assert_eq!(f.runtime.scan().unwrap().len(), n);
}

#[tokio::test]
async fn um_metodo_desconhecido_responde_unimplemented() {
    let f = arrancar().await;
    let canal = tonic::transport::Endpoint::from_shared(f.grpc_url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut grpc = tonic::client::Grpc::new(canal);
    grpc.ready().await.unwrap();
    let codec =
        tonic_prost::ProstCodec::<ExportTraceServiceRequest, ExportTraceServiceRequest>::default();
    let caminho = http::uri::PathAndQuery::from_static(
        "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
    );
    let erro = grpc
        .unary(tonic::Request::new(lote()), caminho, codec)
        .await
        .expect_err("um método que não servimos tem de falhar");
    assert_eq!(erro.code(), tonic::Code::Unimplemented, "{erro:?}");
}

#[tokio::test]
async fn um_lote_vazio_e_aceite_sem_criar_run() {
    let f = arrancar().await;
    let mut c = grpc_client(&f.grpc_url).await;
    c.export(ExportTraceServiceRequest {
        resource_spans: vec![],
    })
    .await
    .unwrap();
    assert!(f.runtime.scan().unwrap().is_empty());
}

#[tokio::test]
async fn o_bearer_nunca_chega_a_evidencia_pelo_grpc() {
    let f = arrancar().await;
    let mut req = lote();
    req.resource_spans[0].scope_spans[0].spans[1]
        .attributes
        .push(kv(
            "gen_ai.request.headers",
            "Authorization: Bearer sk-segredo-por-grpc-123",
        ));
    let mut c = grpc_client(&f.grpc_url).await;
    c.export(req).await.unwrap();
    let dump = serde_json::to_string(&f.runtime.scan().unwrap()).unwrap();
    assert!(!dump.contains("sk-segredo-por-grpc"), "{dump}");
}
