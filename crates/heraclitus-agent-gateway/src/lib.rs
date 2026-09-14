//! # Heraclitus Agent Black Box — as superfícies de rede
//!
//! O `heraclitus-agent` sabe o que é evidência, como a canonizar, redigir,
//! provar e verificar — e não abre sockets (SPEC-0074 §7.1). Este crate abre.
//!
//! | superfície | porta sugerida | SPEC |
//! |---|---|---|
//! | Consola + API | 8080 | 0076 §14 |
//! | OTLP/HTTP | 4318 | 0074 §12 |
//! | OTLP/gRPC | 4317 | 0074 §12 |
//! | Proxy MCP | 8787 | 0075 §5 |
//!
//! # O quickstart que isto tem de tornar verdadeiro
//!
//! ```bash
//! docker compose up -d
//! export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
//! python sample.py
//! # http://localhost:8080
//! ```
//!
//! Gate de produto (§27 da 0074): **menos de cinco minutos** até ao primeiro
//! run visível, para um programador que já tem Docker.

pub mod api;
pub mod auth;
pub mod console;
pub mod gateway;
pub mod grpc;
pub mod ingest;
pub mod platform;
pub mod runtime;
pub mod upstream;

pub use auth::{Operation, Principal, Role};
pub use gateway::GatewayState;
pub use runtime::{AgentRuntime, PolicyLifecycle};
pub use upstream::UpstreamClient;

use heraclitus_core::HeraclitusError;
use std::sync::Arc;

/// O conjunto de tarefas que o Agent Black Box põe a correr.
pub struct AgentServices {
    pub handles: Vec<tokio::task::JoinHandle<()>>,
}

impl AgentServices {
    pub fn abort_all(&self) {
        for h in &self.handles {
            h.abort();
        }
    }
}

/// Arranca as superfícies configuradas.
///
/// Cada listener é uma tarefa independente: se o proxy MCP não conseguir ligar
/// à sua porta, a ingestão e a Consola continuam — mas o erro é devolvido em
/// vez de engolido, porque um gateway que o operador julga estar a proteger e
/// não arrancou é pior do que um que não existe.
/// O sinal de paragem é um `watch` e não um future: cada listener precisa da
/// SUA cópia, e um future só se consome uma vez. Com o `watch`, mandar `true`
/// uma vez pára os três de uma assentada.
pub type ShutdownSignal = tokio::sync::watch::Receiver<bool>;

async fn wait_for(mut rx: ShutdownSignal) {
    // Já marcado antes de chegarmos aqui: sair já.
    if *rx.borrow() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow() {
            return;
        }
    }
    // O emissor desapareceu: tratar como paragem, não como "servir para sempre".
}

pub async fn spawn(
    runtime: Arc<AgentRuntime>,
    shutdown: ShutdownSignal,
) -> Result<AgentServices, HeraclitusError> {
    let mut handles = Vec::new();

    if runtime.config.enabled && !runtime.config.otlp.http_addr.is_empty() {
        let app = ingest::router(runtime.clone());
        let addr = runtime.config.otlp.http_addr.clone();
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| HeraclitusError::Config(format!("OTLP/HTTP em {addr}: {e}")))?;
        let sd = shutdown.clone();
        handles.push(tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(wait_for(sd))
                .await;
        }));
        tracing::info!(%addr, "OTLP/HTTP a receber traces");
    }

    if runtime.config.enabled && !runtime.config.otlp.grpc_addr.is_empty() {
        let addr: std::net::SocketAddr = runtime.config.otlp.grpc_addr.parse().map_err(|e| {
            HeraclitusError::Config(format!(
                "OTLP/gRPC em {}: {e}",
                runtime.config.otlp.grpc_addr
            ))
        })?;
        // Ligar ANTES de `spawn` para que um endereço ocupado seja um erro de
        // arranque e não um listener que nunca existiu enquanto o operador
        // julgava que sim.
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| HeraclitusError::Config(format!("OTLP/gRPC em {addr}: {e}")))?;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let service = grpc::TraceServiceServer::new(grpc::AgentTraceService::new(runtime.clone()))
            .max_decoding_message_size(runtime.config.limits.max_body_bytes.max(1024));
        let sd = shutdown.clone();
        handles.push(tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, wait_for(sd))
                .await;
        }));
        tracing::info!(%addr, "OTLP/gRPC a receber traces");
    }

    if runtime.config.console.enabled {
        let app = api::router(runtime.clone());
        let addr = runtime.config.console.addr.clone();
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| HeraclitusError::Config(format!("Consola em {addr}: {e}")))?;
        let sd = shutdown.clone();
        handles.push(tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(wait_for(sd))
                .await;
        }));
        tracing::info!(%addr, "Consola do HeraclitusDB (Platform Console em /, Agent Evidence em /agent)");
    }

    if runtime.gateway.enabled {
        let upstream = if runtime.gateway.upstream_url.is_empty() {
            None
        } else {
            Some(Arc::new(
                UpstreamClient::new(&runtime.gateway.upstream_url, 30, 8 * 1024 * 1024).map_err(
                    |e| HeraclitusError::Config(format!("upstream do gateway MCP: {e}")),
                )?,
            ))
        };
        let state = Arc::new(GatewayState {
            runtime: runtime.clone(),
            upstream,
        });
        let app = gateway::router(state);
        let addr = runtime.gateway.listen_addr.clone();
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| HeraclitusError::Config(format!("proxy MCP em {addr}: {e}")))?;
        let sd = shutdown.clone();
        handles.push(tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(wait_for(sd))
                .await;
        }));
        tracing::info!(%addr, mode = runtime.mode().label(), "proxy MCP");
    }

    Ok(AgentServices { handles })
}
