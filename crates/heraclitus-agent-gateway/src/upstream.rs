//! O cliente HTTP que fala com o servidor MCP a jusante.
//!
//! # Porque não uma biblioteca de alto nível
//!
//! O `hyper` e o `hyper-util` já estão na árvore (o axum e o tonic trazem-nos),
//! e o que o proxy precisa é de uma coisa só: reencaminhar um `POST` com corpo
//! limitado e devolver a resposta. Um cliente de alto nível traria
//! redireccionamentos automáticos, cookie jar e retries — três comportamentos
//! que um gateway de autorização **não** quer:
//!
//! - **redireccionamento**: o upstream poderia mandar a chamada autorizada para
//!   outro lado, e a autorização ficou ligada ao recurso, não ao caminho;
//! - **cookies**: seriam credenciais guardadas por nós, exactamente o que a
//!   §9 proíbe;
//! - **retries automáticos**: uma tool call não idempotente executada duas
//!   vezes é um pagamento a dobrar (§26).
//!
//! Nada disto está aqui, e está escrito para que ninguém o acrescente por
//! engano.

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION};
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

const PREFIXO_CORRELACAO: &str = "x-heraclitus-";

/// RFC 9110: `Connection` pode nomear outros campos que são hop-by-hop para
/// aquela mensagem específica. Uma lista estática não basta: sem esta etapa,
/// `Connection: X-Private-Hop` removia `Connection` mas deixava
/// `X-Private-Hop` atravessar a fronteira do proxy.
fn connection_tokens_from_values<'a>(
    values: impl Iterator<Item = &'a str>,
) -> BTreeSet<String> {
    values
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn connection_tokens_from_btree(headers: &BTreeMap<String, String>) -> BTreeSet<String> {
    connection_tokens_from_values(
        headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
            .map(|(_, value)| value.as_str()),
    )
}

fn connection_tokens_from_header_map(headers: &HeaderMap) -> BTreeSet<String> {
    connection_tokens_from_values(
        headers
            .get_all(CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    )
}

fn is_hop_by_hop(name: &str, connection_tokens: &BTreeSet<String>) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
        || connection_tokens.contains(&name.to_ascii_lowercase())
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("URL de upstream inválido: {0}")]
    BadUrl(String),
    #[error("o upstream não respondeu: {0}")]
    Transport(String),
    #[error("a resposta do upstream excede o tecto de {0} bytes")]
    TooLarge(usize),
    #[error("tempo esgotado à espera do upstream")]
    Timeout,
}

#[derive(Debug)]
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Bytes,
}

fn tls_config() -> Result<rustls::ClientConfig, UpstreamError> {
    let mut roots = rustls::RootCertStore::empty();
    let carregadas = rustls_native_certs::load_native_certs();
    for cert in carregadas.certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err(UpstreamError::Transport(format!(
            "o armazém de certificados do sistema não deu nenhuma âncora de confiança \
             ({} erro(s) ao ler). Instale `ca-certificates` ou use um upstream `http://` \
             dentro da fronteira de confiança.",
            carregadas.errors.len()
        )));
    }
    rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| UpstreamError::Transport(format!("configuração TLS: {e}")))
    .map(|b| b.with_root_certificates(roots).with_no_client_auth())
}

pub struct UpstreamClient {
    base: Uri,
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
    timeout: Duration,
    max_response_bytes: usize,
}

impl UpstreamClient {
    pub fn new(
        base_url: &str,
        timeout_secs: u64,
        max_response_bytes: usize,
    ) -> Result<Self, UpstreamError> {
        let base: Uri = base_url
            .parse()
            .map_err(|e| UpstreamError::BadUrl(format!("{base_url}: {e}")))?;
        if base.scheme_str() != Some("http") && base.scheme_str() != Some("https") {
            return Err(UpstreamError::BadUrl(format!(
                "{base_url}: só `http` e `https` são aceites"
            )));
        }
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config()?)
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            base,
            client,
            timeout: Duration::from_secs(timeout_secs.max(1)),
            max_response_bytes: max_response_bytes.max(1),
        })
    }

    pub fn base(&self) -> &Uri {
        &self.base
    }

    pub async fn forward(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &BTreeMap<String, String>,
        body: Bytes,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let mut parts = self.base.clone().into_parts();
        let base_path = self
            .base
            .path_and_query()
            .map(|p| p.path().trim_end_matches('/').to_string())
            .unwrap_or_default();
        let alvo = format!("{base_path}{path_and_query}");
        parts.path_and_query = Some(
            alvo.parse()
                .map_err(|e| UpstreamError::BadUrl(format!("{alvo}: {e}")))?,
        );
        let uri =
            Uri::from_parts(parts).map_err(|e| UpstreamError::BadUrl(format!("{alvo}: {e}")))?;

        let method = Method::from_bytes(method.as_bytes())
            .map_err(|e| UpstreamError::BadUrl(format!("método inválido: {e}")))?;
        let mut req = Request::builder().method(method).uri(uri);
        let connection_tokens = connection_tokens_from_btree(headers);
        for (k, v) in headers {
            if is_hop_by_hop(k, &connection_tokens) {
                continue;
            }
            if k.to_ascii_lowercase().starts_with(PREFIXO_CORRELACAO) {
                continue;
            }
            let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) else {
                continue;
            };
            req = req.header(name, value);
        }
        let req = req
            .body(Full::new(body))
            .map_err(|e| UpstreamError::Transport(e.to_string()))?;

        let resposta = tokio::time::timeout(self.timeout, self.client.request(req))
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|e| UpstreamError::Transport(e.to_string()))?;

        let status = resposta.status().as_u16();
        let response_connection_tokens = connection_tokens_from_header_map(resposta.headers());
        let mut out_headers = BTreeMap::new();
        for (k, v) in resposta.headers() {
            if is_hop_by_hop(k.as_str(), &response_connection_tokens) {
                continue;
            }
            if let Ok(s) = v.to_str() {
                out_headers.insert(k.as_str().to_string(), s.to_string());
            }
        }

        // Never collect an attacker-controlled response before applying the cap.
        // The former collect-then-check sequence allowed a compromised MCP
        // upstream to force an allocation far above max_response_bytes.
        let mut response_body = resposta.into_body();
        let mut collected = Vec::with_capacity(self.max_response_bytes.min(64 * 1024));
        while let Some(frame) = response_body.frame().await {
            let frame = frame.map_err(|e| UpstreamError::Transport(e.to_string()))?;
            if let Some(data) = frame.data_ref() {
                let next_len = collected
                    .len()
                    .checked_add(data.len())
                    .ok_or(UpstreamError::TooLarge(self.max_response_bytes))?;
                if next_len > self.max_response_bytes {
                    return Err(UpstreamError::TooLarge(self.max_response_bytes));
                }
                collected.extend_from_slice(data);
            }
        }

        Ok(UpstreamResponse {
            status,
            headers: out_headers,
            body: Bytes::from(collected),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn url_sem_esquema_e_recusado() {
        assert!(UpstreamClient::new("mcp.interno:9000", 5, 1024).is_err());
        assert!(UpstreamClient::new("ftp://x/", 5, 1024).is_err());
        assert!(UpstreamClient::new("file:///etc/passwd", 5, 1024).is_err());
    }

    #[test]
    fn os_cabecalhos_de_correlacao_nao_saem_para_o_upstream() {
        for h in [
            "X-Heraclitus-User",
            "x-heraclitus-agent",
            "X-HERACLITUS-RUN",
            "X-Heraclitus-Environment",
        ] {
            assert!(
                h.to_ascii_lowercase().starts_with(PREFIXO_CORRELACAO),
                "`{h}` escapava ao filtro de correlação"
            );
        }
        for h in ["X-Request-Id", "Authorization", "Accept", "x-heraclitus"] {
            assert!(
                !h.to_ascii_lowercase().starts_with(PREFIXO_CORRELACAO),
                "`{h}` estava a ser removido sem ser nosso"
            );
        }
    }

    #[test]
    fn a_lista_hop_by_hop_cobre_o_essencial() {
        for h in [
            "Connection",
            "Proxy-Authorization",
            "Transfer-Encoding",
            "Host",
        ] {
            assert!(
                HOP_BY_HOP.iter().any(|x| h.eq_ignore_ascii_case(x)),
                "{h} devia ser hop-by-hop"
            );
        }
    }

    #[test]
    fn connection_remove_headers_hop_by_hop_nomeados_dinamicamente() {
        let mut headers = BTreeMap::new();
        headers.insert(
            "Connection".into(),
            "X-Redteam-Hop, keep-alive, X-Another-Hop".into(),
        );
        headers.insert("X-Redteam-Hop".into(), "synthetic".into());
        headers.insert("X-Another-Hop".into(), "synthetic-2".into());
        headers.insert("X-End-To-End".into(), "preserve".into());

        let tokens = connection_tokens_from_btree(&headers);
        assert!(is_hop_by_hop("X-Redteam-Hop", &tokens));
        assert!(is_hop_by_hop("x-another-hop", &tokens));
        assert!(is_hop_by_hop("Keep-Alive", &tokens));
        assert!(!is_hop_by_hop("X-End-To-End", &tokens));
    }

    #[tokio::test]
    async fn resposta_upstream_e_limitada_durante_a_leitura() {
        use axum::routing::post;

        let payload = Arc::new(vec![b'X'; 256 * 1024]);
        let app = axum::Router::new().fallback(post({
            let payload = payload.clone();
            move || {
                let payload = payload.clone();
                async move { payload.as_ref().clone() }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = UpstreamClient::new(&format!("http://{addr}"), 5, 1024).unwrap();
        let err = client
            .forward("POST", "/mcp", &BTreeMap::new(), Bytes::from_static(b"{}"))
            .await
            .unwrap_err();
        assert!(matches!(err, UpstreamError::TooLarge(1024)));
    }
}
