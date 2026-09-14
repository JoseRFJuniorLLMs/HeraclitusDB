//! SPEC-0074 §12 e §19 — o receptor OTLP/gRPC.
//!
//! ```text
//! opentelemetry.proto.collector.trace.v1.TraceService/Export
//! ```
//!
//! # Porque escrito à mão, e não gerado
//!
//! Gerar exigiria vendorizar os `.proto` do OpenTelemetry, correr `protox` num
//! `build.rs` e passar a ter **duas** definições das mesmas mensagens: as que o
//! `heraclitus-agent::otlp::proto` já declara (e que o caminho HTTP usa) e as
//! geradas. Duas definições da mesma coisa divergem — e neste caso divergiriam
//! em silêncio, porque a incompatibilidade só apareceria no wire de um cliente
//! real.
//!
//! O que a geração produz é boilerplate: um `Service<http::Request<B>>` que
//! despacha por caminho e delega ao `tonic::server::Grpc` com um
//! `ProstCodec`. Isso está aqui, escrito uma vez, para **um** método unário,
//! sobre as mensagens que já existem. A identidade do serviço é o caminho HTTP
//! e os números de campo — não quem escreveu o `.proto`.
//!
//! # O que este módulo NÃO faz de diferente do HTTP
//!
//! Nada. Os dois transportes descem ao mesmo [`OtlpNormalizer`], ao mesmo
//! portão de privacidade e à mesma deduplicação. Um lote que chegue pelos dois
//! caminhos produz os mesmos bytes canónicos e é deduplicado — o que é
//! testado, porque "descem ao mesmo sítio" é uma afirmação que envelhece mal
//! sem um teste a segurá-la.

use crate::runtime::AgentRuntime;
use heraclitus_agent::otlp::proto::{
    ExportTracePartialSuccess, ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use std::sync::Arc;
use tonic::codegen::*;

/// O nome do serviço, tal como o protocolo o define. Mudar isto é deixar de
/// falar OTLP.
pub const SERVICE_NAME: &str = "opentelemetry.proto.collector.trace.v1.TraceService";
/// O caminho HTTP/2 do método unário.
pub const EXPORT_PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";

/// O que um receptor de traces tem de saber fazer.
#[async_trait]
pub trait TraceService: Send + Sync + 'static {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status>;
}

/// A implementação que grava no plano de evidência.
pub struct AgentTraceService {
    runtime: Arc<AgentRuntime>,
}

impl AgentTraceService {
    pub fn new(runtime: Arc<AgentRuntime>) -> Self {
        Self { runtime }
    }
}

#[async_trait]
impl TraceService for AgentTraceService {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        // A mesma credencial que fecha a porta HTTP tem de fechar esta. Duas
        // portas para o MESMO log com regras diferentes seria uma delas a
        // anular a outra em silencio: bastava trocar 4318 por 4317.
        if let Some(credencial) = self.runtime.otlp_credential() {
            let cabecalho = request
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok());
            if !credencial.matches(cabecalho) {
                self.runtime.counters.lock().unwrap().rejected += 1;
                return Err(tonic::Status::unauthenticated(
                    "esta porta OTLP exige `authorization: Basic <utilizador:senha>`",
                ));
            }
        }
        let traces = request.into_inner();
        {
            let mut c = self.runtime.counters.lock().unwrap();
            c.batches += 1;
        }
        let batch = self.runtime.normalizer().normalize(&traces);

        let mut rejected = batch.rejected_spans as i64;
        let mut primeiro_erro = String::new();
        for evidence in &batch.evidences {
            match self.runtime.append(evidence) {
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(e) => {
                    rejected += 1;
                    if primeiro_erro.is_empty() {
                        primeiro_erro = e.to_string();
                    }
                }
            }
        }
        {
            let mut c = self.runtime.counters.lock().unwrap();
            c.ignored += batch.ignored_spans as u64;
            c.rejected += batch.rejected_spans as u64;
        }
        // Uma falha a gravar evidência é um erro do servidor, não um lote mau:
        // devolver `OK` faria o exporter deitar fora traces que nunca foram
        // persistidos.
        if let Err(e) = self.runtime.flush() {
            return Err(tonic::Status::internal(format!(
                "EVIDENCE_APPEND_FAILED: {e}"
            )));
        }

        Ok(tonic::Response::new(ExportTraceServiceResponse {
            partial_success: (rejected > 0 || !primeiro_erro.is_empty()).then_some(
                ExportTracePartialSuccess {
                    rejected_spans: rejected,
                    error_message: primeiro_erro,
                },
            ),
        }))
    }
}

/// O servidor tonic. Mesma forma que o código gerado, para um método.
#[derive(Debug)]
pub struct TraceServiceServer<T> {
    inner: Arc<T>,
    max_decoding_message_size: Option<usize>,
}

impl<T> TraceServiceServer<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner: Arc::new(inner),
            max_decoding_message_size: None,
        }
    }

    /// O mesmo tecto que o caminho HTTP aplica (§12). Sem ele, o gRPC teria o
    /// default do tonic (4 MiB) e `max_body_bytes` voltaria a ser uma
    /// configuração que só governa metade dos transportes.
    #[must_use]
    pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
        self.max_decoding_message_size = Some(limit);
        self
    }
}

impl<T> Clone for TraceServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            max_decoding_message_size: self.max_decoding_message_size,
        }
    }
}

impl<T, B> tonic::codegen::Service<http::Request<B>> for TraceServiceServer<T>
where
    T: TraceService,
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        if req.uri().path() != EXPORT_PATH {
            return Box::pin(async move {
                let mut response = http::Response::new(tonic::body::Body::default());
                let headers = response.headers_mut();
                headers.insert(
                    tonic::Status::GRPC_STATUS,
                    (tonic::Code::Unimplemented as i32).into(),
                );
                headers.insert(
                    http::header::CONTENT_TYPE,
                    tonic::metadata::GRPC_CONTENT_TYPE,
                );
                Ok(response)
            });
        }

        struct ExportSvc<T: TraceService>(Arc<T>);
        impl<T: TraceService> tonic::server::UnaryService<ExportTraceServiceRequest> for ExportSvc<T> {
            type Response = ExportTraceServiceResponse;
            type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
            fn call(&mut self, request: tonic::Request<ExportTraceServiceRequest>) -> Self::Future {
                let inner = Arc::clone(&self.0);
                Box::pin(async move { inner.export(request).await })
            }
        }

        let max_decoding = self.max_decoding_message_size;
        let inner = self.inner.clone();
        Box::pin(async move {
            let method = ExportSvc(inner);
            let codec = tonic_prost::ProstCodec::default();
            let mut grpc =
                tonic::server::Grpc::new(codec).apply_max_message_size_config(max_decoding, None);
            Ok(grpc.unary(method, req).await)
        })
    }
}

impl<T> tonic::server::NamedService for TraceServiceServer<T> {
    const NAME: &'static str = SERVICE_NAME;
}

/// Cliente mínimo, para testes e para o `doctor` poder provar que o listener
/// responde de verdade em vez de só estar ligado a uma porta.
pub mod client {
    use super::*;

    pub struct TraceServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl<T> TraceServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = tonic::codegen::Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        pub fn new(inner: T) -> Self {
            Self {
                inner: tonic::client::Grpc::new(inner),
            }
        }

        pub async fn export(
            &mut self,
            request: impl tonic::IntoRequest<ExportTraceServiceRequest>,
        ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("o serviço não ficou pronto: {}", e.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(EXPORT_PATH);
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn o_caminho_e_o_do_protocolo() {
        // Se isto mudar, deixamos de falar OTLP — e o exporter do utilizador
        // recebe `Unimplemented` sem explicação.
        assert_eq!(
            EXPORT_PATH,
            "/opentelemetry.proto.collector.trace.v1.TraceService/Export"
        );
        assert_eq!(
            SERVICE_NAME,
            "opentelemetry.proto.collector.trace.v1.TraceService"
        );
        assert!(EXPORT_PATH.starts_with(&format!("/{SERVICE_NAME}/")));
    }
}
