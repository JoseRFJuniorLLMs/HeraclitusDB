//! heraclitus-client — Rust SDK over the gRPC surface.

use heraclitus_proto::v1 as pb;
use heraclitus_proto::v1::heraclitus_client::HeraclitusClient as Grpc;
use std::time::Duration;
use tonic::metadata::errors::InvalidMetadataValue;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// Teto para ESTABELECER a ligação. Sem isto, um servidor em baixo ou com os
/// pacotes engolidos (blackhole) prendia o chamador indefinidamente — o
/// `connect` do SO só desiste ao fim de minutos, ou nunca.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Teto por CHAMADA unária. Generoso porque uma query analítica legítima pode
/// demorar; ajustável com [`Client::with_request_timeout`].
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Client {
    inner: Grpc<Channel>,
    /// Aplicado a cada RPC unário (via cabeçalho grpc-timeout). NÃO é aplicado
    /// ao canal: um timeout de canal abortaria o `subscribe`, que é um stream
    /// de vida longa e legitimamente silencioso entre eventos.
    request_timeout: Duration,
    authorization: Option<MetadataValue<Ascii>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendResult {
    pub lsn: u64,
    pub deduplicated: bool,
    pub event_id: String,
}

#[derive(Debug, Default)]
pub struct AppendOptions {
    pub session_id: String,
    pub kind: String,
    pub hyp: Vec<f32>,
    pub attrs: std::collections::HashMap<String, String>,
    pub parents: Vec<String>,
    /// Chave estável para retries exactly-once. Vazio mantém o comportamento legado.
    pub idempotency_key: String,
}

impl Client {
    pub async fn connect(addr: impl Into<String>) -> Result<Self, tonic::transport::Error> {
        Self::connect_with(addr, DEFAULT_CONNECT_TIMEOUT).await
    }

    /// Como [`Client::connect`], com o teto de ligação escolhido pelo chamador.
    pub async fn connect_with(
        addr: impl Into<String>,
        connect_timeout: Duration,
    ) -> Result<Self, tonic::transport::Error> {
        let endpoint = Endpoint::from_shared(addr.into())?.connect_timeout(connect_timeout);
        Self::connect_endpoint(endpoint).await
    }

    /// Liga com validação de CA e, opcionalmente, identidade mTLS do cliente.
    /// O endereço deve usar `https://`; `domain_name` tem de existir no SAN do
    /// certificado do servidor.
    pub async fn connect_tls(
        addr: impl Into<String>,
        ca_pem: impl Into<Vec<u8>>,
        domain_name: impl Into<String>,
        client_identity: Option<(Vec<u8>, Vec<u8>)>,
        connect_timeout: Duration,
    ) -> Result<Self, tonic::transport::Error> {
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca_pem.into()))
            .domain_name(domain_name.into());
        if let Some((certificate, private_key)) = client_identity {
            tls = tls.identity(Identity::from_pem(certificate, private_key));
        }
        let endpoint = Endpoint::from_shared(addr.into())?
            .connect_timeout(connect_timeout)
            .tls_config(tls)?;
        Self::connect_endpoint(endpoint).await
    }

    async fn connect_endpoint(endpoint: Endpoint) -> Result<Self, tonic::transport::Error> {
        // Janelas de varredura podem devolver dezenas de MB (200k nós densos ≈
        // 56MB). O default do tonic é 4MB → sobe-se para 256MB nos dois sentidos.
        const MAX_MSG: usize = 256 * 1024 * 1024;
        let channel = endpoint
            // Keepalive TCP: deteta um par morto num `subscribe` parado, sem o
            // matar quando está apenas silencioso (o log pode não ter eventos).
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .connect()
            .await?;
        let inner = Grpc::new(channel)
            .max_decoding_message_size(MAX_MSG)
            .max_encoding_message_size(MAX_MSG);
        Ok(Self {
            inner,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            authorization: None,
        })
    }

    /// Aplica `Authorization: Bearer ...` em todas as RPCs, inclusive streams.
    pub fn with_bearer_token(mut self, token: &str) -> Result<Self, InvalidMetadataValue> {
        self.authorization = Some(format!("Bearer {token}").parse()?);
        Ok(self)
    }

    /// Ajusta o teto por chamada unária (não afeta o `subscribe`).
    pub fn with_request_timeout(mut self, t: Duration) -> Self {
        self.request_timeout = t;
        self
    }

    /// Embrulha a mensagem num `Request` com o teto por chamada.
    fn req<T>(&self, msg: T) -> tonic::Request<T> {
        let mut r = tonic::Request::new(msg);
        r.set_timeout(self.request_timeout);
        self.authorize(&mut r);
        r
    }

    fn authorize<T>(&self, request: &mut tonic::Request<T>) {
        if let Some(value) = &self.authorization {
            request
                .metadata_mut()
                .insert("authorization", value.clone());
        }
    }

    pub async fn append(
        &mut self,
        agent_id: &str,
        content: &[u8],
        opts: AppendOptions,
    ) -> Result<u64, tonic::Status> {
        Ok(self.append_with_result(agent_id, content, opts).await?.lsn)
    }

    /// Append com recibo completo para retries exactly-once.
    pub async fn append_with_result(
        &mut self,
        agent_id: &str,
        content: &[u8],
        opts: AppendOptions,
    ) -> Result<AppendResult, tonic::Status> {
        let req = pb::AppendRequest {
            agent_id: agent_id.to_string(),
            session_id: opts.session_id,
            kind: opts.kind,
            content: content.to_vec(),
            hyp: opts.hyp,
            sph: vec![],
            euc: vec![],
            attrs: opts.attrs,
            parents: opts.parents,
            idempotency_key: opts.idempotency_key,
        };
        let request = self.req(req);
        let response = self.inner.append(request).await?.into_inner();
        Ok(AppendResult {
            lsn: response.lsn,
            deduplicated: response.deduplicated,
            event_id: response.event_id,
        })
    }

    /// Execute a GQL statement (supports EXPLAIN / AS OF / RECALL / NEAREST).
    pub async fn query(&mut self, gql: &str) -> Result<serde_json::Value, tonic::Status> {
        let request = self.req(pb::QueryRequest {
            gql: gql.to_string(),
        });
        let resp = self.inner.query(request).await?.into_inner();
        serde_json::from_str(&resp.json).map_err(|e| tonic::Status::internal(e.to_string()))
    }

    /// Full two-stage retrieval.
    pub async fn recall(&mut self, text: &str, k: u32) -> Result<serde_json::Value, tonic::Status> {
        let request = self.req(pb::RecallRequest {
            text: text.to_string(),
            k,
        });
        let resp = self.inner.recall(request).await?.into_inner();
        serde_json::from_str(&resp.json).map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn snapshot(&mut self) -> Result<u64, tonic::Status> {
        let request = self.req(pb::SnapshotRequest {});
        Ok(self.inner.snapshot(request).await?.into_inner().lsn)
    }

    pub async fn admin(&mut self, op: &str, arg: &str) -> Result<(bool, String), tonic::Status> {
        let request = self.req(pb::AdminRequest {
            op: op.into(),
            arg: arg.into(),
        });
        let r = self.inner.admin(request).await?.into_inner();
        Ok((r.ok, r.message))
    }

    /// Subscribe to the tail from `from_lsn`; returns the raw stream.
    ///
    /// SEM teto por chamada, de propósito: é um stream de vida longa e o log
    /// pode ficar legitimamente silencioso entre eventos. A deteção de par
    /// morto fica a cargo do keepalive TCP do canal.
    pub async fn subscribe(
        &mut self,
        from_lsn: u64,
    ) -> Result<tonic::Streaming<pb::EventMessage>, tonic::Status> {
        let mut request = tonic::Request::new(pb::SubscribeRequest { from_lsn });
        self.authorize(&mut request);
        Ok(self.inner.subscribe(request).await?.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bearer_token_is_attached_to_every_request() {
        let endpoint = Endpoint::from_static("http://127.0.0.1:7474");
        let channel = endpoint.connect_lazy();
        let client = Client {
            inner: Grpc::new(channel),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            authorization: None,
        }
        .with_bearer_token("secret-token")
        .unwrap();
        let request = client.req(pb::SnapshotRequest {});
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer secret-token"
        );
    }

    /// Regressão: ligar a um par que engole os pacotes TEM de desistir no teto,
    /// não ficar preso. `192.0.2.1` é TEST-NET-1 (RFC 5737) — não roteável, os
    /// pacotes morrem em silêncio, que é exatamente o caso do blackhole. Sem
    /// `connect_timeout`, isto só desistia ao fim de minutos (ou nunca).
    #[tokio::test]
    async fn connect_desiste_no_teto_em_vez_de_pendurar() {
        let start = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            Client::connect_with("http://192.0.2.1:50051", Duration::from_millis(300)),
        )
        .await;

        assert!(
            outcome.is_ok(),
            "connect ficou pendurado — o connect_timeout não foi respeitado"
        );
        assert!(
            outcome.unwrap().is_err(),
            "ligar a um endereço blackhole devia falhar, não ter sucesso"
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "desistiu, mas demasiado tarde: {:?}",
            start.elapsed()
        );
    }
}
