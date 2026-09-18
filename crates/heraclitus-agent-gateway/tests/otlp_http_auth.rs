//! Regressão: `otlp.require_auth` vale para TODA a superfície OTLP/HTTP.
//!
//! Antes desta correção, `/v1/traces` passava pelo gate mas `/v1/metrics` e
//! `/v1/logs` devolviam 200 sem autenticação.

use heraclitus_agent::config::{
    AgentBlackBoxConfig, AgentGatewayConfig, ConsoleConfig, OtlpConfig,
};
use heraclitus_agent::store::AnyLogEvidenceStore;
use heraclitus_agent_gateway::ingest;
use heraclitus_agent_gateway::runtime::AgentRuntime;
use heraclitus_core::{FsyncPolicy, StorageFormat};
use heraclitus_log::AnyLog;
use std::sync::Arc;

struct Lab {
    _dir: tempfile::TempDir,
    base: String,
}

async fn start() -> Lab {
    let dir = tempfile::tempdir().unwrap();
    let config = AgentBlackBoxConfig {
        enabled: true,
        tenant_id: "default".into(),
        otlp: OtlpConfig {
            http_addr: String::new(),
            grpc_addr: String::new(),
            require_auth: true,
        },
        console: ConsoleConfig {
            enabled: false,
            addr: String::new(),
            basic_auth: "x:y".into(),
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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = ingest::router(runtime);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Lab {
        _dir: dir,
        base: format!("http://{addr}"),
    }
}

async fn post_unauthenticated(base: &str, path: &str) -> u16 {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<hyper::body::Bytes>,
    > = Client::builder(TokioExecutor::new()).build_http();
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("{base}{path}"))
        .header("content-type", "application/json")
        .body(Full::new(hyper::body::Bytes::from_static(b"{}")))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status().as_u16();
    let _ = resp.into_body().collect().await.unwrap();
    status
}

#[tokio::test]
async fn require_auth_rejeita_sem_credencial_em_todos_os_sinais_http() {
    let lab = start().await;
    for path in ["/v1/traces", "/v1/metrics", "/v1/logs"] {
        assert_eq!(
            post_unauthenticated(&lab.base, path).await,
            401,
            "{path} escapou ao gate OTLP"
        );
    }
}
