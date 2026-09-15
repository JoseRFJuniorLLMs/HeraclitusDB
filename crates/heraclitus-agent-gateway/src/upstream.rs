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
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::collections::BTreeMap;
use std::time::Duration;

/// Cabeçalhos que NUNCA são reencaminhados ao upstream nem devolvidos ao
/// cliente. `hop-by-hop` do RFC 9110 mais os que pertencem ao transporte.
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

/// Prefixo dos cabeçalhos de correlação do Heraclitus.
///
/// São nossos e param aqui. Reencaminhá-los dizia a um terceiro na Internet o
/// nome do utilizador humano (`X-Heraclitus-User: jose`), o identificador do run
/// e o ambiente — topologia interna publicada a troco de nada, porque o upstream
/// não sabe o que fazer com eles. Não é um segredo; é informação que ninguém
/// pediu para divulgar.
const PREFIXO_CORRELACAO: &str = "x-heraclitus-";

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

pub struct UpstreamResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Bytes,
}

/// A configuração TLS do cliente, com o fornecedor criptográfico **explícito**.
///
/// # Porque não `with_native_roots()` e pronto
///
/// Porque o `rustls` escolhe o fornecedor por um default de processo, e quando
/// mais do que um está compilado na árvore (`ring` e `aws-lc-rs` chegam por
/// caminhos diferentes conforme as features unificadas do workspace) ele
/// recusa-se a adivinhar e entra em pânico:
///
/// ```text
/// Could not automatically determine the process-level CryptoProvider
/// from Rustls crate features.
/// ```
///
/// Isso apareceu num teste; podia ter aparecido no primeiro pedido TLS de uma
/// instalação. A alternativa óbvia — `install_default()` — resolve, mas é uma
/// biblioteca a impor uma escolha global ao processo inteiro, exactamente o que
/// a SPEC-0073 §20 proíbe para o allocator e pela mesma razão: quem embebe o
/// motor deve poder escolher.
///
/// Portanto o fornecedor é declarado aqui, no sítio que o usa: `ring`, que é o
/// mesmo que o `tonic` já traz (`tls-ring`). Uma só implementação de TLS na
/// imagem, escolhida por nós e não por acaso de features.
fn tls_config() -> Result<rustls::ClientConfig, UpstreamError> {
    let mut roots = rustls::RootCertStore::empty();
    let carregadas = rustls_native_certs::load_native_certs();
    for cert in carregadas.certs {
        // Uma âncora malformada no armazém do sistema não deve derrubar o
        // gateway; o que derruba é não sobrar nenhuma.
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

/// Cliente para um upstream fixo.
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
            max_response_bytes,
        })
    }

    pub fn base(&self) -> &Uri {
        &self.base
    }

    /// Reencaminha um pedido. Sem redireccionamentos, sem retries.
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
        for (k, v) in headers {
            if HOP_BY_HOP.iter().any(|h| k.eq_ignore_ascii_case(h)) {
                continue;
            }
            // Os nossos cabeçalhos de correlação param no gateway. Só saem daqui
            // no sentido do upstream, e o upstream não tem nada a ver com eles.
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
        let mut out_headers = BTreeMap::new();
        for (k, v) in resposta.headers() {
            if HOP_BY_HOP
                .iter()
                .any(|h| k.as_str().eq_ignore_ascii_case(h))
            {
                continue;
            }
            if let Ok(s) = v.to_str() {
                out_headers.insert(k.as_str().to_string(), s.to_string());
            }
        }
        let collected = resposta
            .into_body()
            .collect()
            .await
            .map_err(|e| UpstreamError::Transport(e.to_string()))?
            .to_bytes();
        if collected.len() > self.max_response_bytes {
            return Err(UpstreamError::TooLarge(self.max_response_bytes));
        }
        Ok(UpstreamResponse {
            status,
            headers: out_headers,
            body: collected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_sem_esquema_e_recusado() {
        assert!(UpstreamClient::new("mcp.interno:9000", 5, 1024).is_err());
        assert!(UpstreamClient::new("ftp://x/", 5, 1024).is_err());
        assert!(UpstreamClient::new("file:///etc/passwd", 5, 1024).is_err());
    }

    #[test]
    fn os_cabecalhos_de_correlacao_nao_saem_para_o_upstream() {
        // O que isto impede: um `tools/call` para um servidor MCP público na
        // Internet levar consigo `X-Heraclitus-User: jose`. O upstream não pede
        // essa informação, não a usa, e passa a tê-la.
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
        // E o filtro não pode ser tão largo que apanhe cabeçalhos de terceiros.
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
}
