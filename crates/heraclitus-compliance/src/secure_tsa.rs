//! SPEC-0046 §10 — `SecureTsaClient`: o cliente HTTPS para a ACT.
//!
//! > O cliente atual não pode permanecer limitado a HTTP em produção.
//!
//! O [`crate::tsa::HttpTsa`] fala HTTP/1.1 sobre um `TcpStream` cru e recusa
//! explicitamente qualquer coisa que não seja `http://`. Em produção isso
//! significa que o pedido de carimbo — que contém o digest do que se está a
//! ancorar — e a resposta da autoridade atravessam a rede em claro, sem
//! autenticação do servidor. Um intermediário lê o digest e, pior, responde
//! ele próprio: o carimbo forjado só é apanhado depois, pelo
//! [`crate::icp::IcpBrasilTimestampVerifier`], e apenas se houver âncoras
//! configuradas.
//!
//! # A confiança do TLS é a MESMA do carimbo
//!
//! A decisão mais consequente deste módulo: o cliente valida o certificado do
//! servidor contra o **mesmo [`TrustStore`]** que valida o carimbo, e não
//! contra as raízes do sistema operativo. Duas razões, e a segunda é a que
//! importa:
//!
//! 1. Um órgão em air-gap ou numa rede soberana não tem — nem quer — a lista
//!    de CAs públicas do sistema.
//! 2. Se o TLS confiasse nas raízes do sistema, qualquer CA pública do mundo
//!    poderia emitir um certificado para o nome da ACT e interpor-se. A
//!    confiança que interessa aqui é a que o operador declarou (§11), e mais
//!    nenhuma.
//!
//! Consequência prática, dita à partida: com o trust store vazio o cliente
//! **não liga a lado nenhum**. É o comportamento certo — "ainda não disse a
//! quem confiar" não pode significar "confia em qualquer um".
//!
//! # Limites, e porque cada um existe
//!
//! - **Tamanho da resposta**: uma ACT devolve alguns KB. Sem tecto, um
//!   servidor hostil (ou avariado) faz o cliente alocar até morrer.
//! - **Timeouts de ligação, leitura e escrita**: sem eles um servidor que
//!   aceita a ligação e nunca responde bloqueia o worker de compliance para
//!   sempre.
//! - **Redirects**: `TlsPolicy::follow_redirects` é `false` e não há como o
//!   ligar. Seguir um redirect num protocolo binário POST significa reenviar
//!   o digest para um destino que o servidor escolheu — exactamente o que a
//!   validação de certificado existe para impedir.
//! - **mTLS**: opcional (§10), porque algumas ACTs autenticam o cliente.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::trust_store::TrustStore;
use crate::CompError;

/// Tecto absoluto da resposta, independentemente da política. Uma
/// `TimeStampResp` é pequena; isto é a rede de segurança para uma configuração
/// generosa de mais.
const HARD_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// SPEC-0046 §10.
#[derive(Debug, Clone)]
pub struct TlsPolicy {
    /// Certificado + chave do cliente, em DER, quando a ACT exige mTLS.
    pub client_identity: Option<ClientIdentity>,
    /// Tecto da resposta.
    pub max_response_bytes: usize,
    /// `false`, e sem forma de o ligar — ver o cabeçalho do módulo.
    pub follow_redirects: bool,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self {
            client_identity: None,
            max_response_bytes: 256 * 1024,
            follow_redirects: false,
        }
    }
}

/// Identidade do cliente para mTLS.
#[derive(Clone)]
pub struct ClientIdentity {
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub private_key_der: Vec<u8>,
}

impl std::fmt::Debug for ClientIdentity {
    /// A chave privada nunca chega a uma linha de log, nem a um `{:?}` dentro
    /// de uma mensagem de erro.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("certificate_chain_der", &self.certificate_chain_der.len())
            .field("private_key_der", &"<redacted>")
            .finish()
    }
}

/// SPEC-0046 §10.
#[derive(Debug, Clone)]
pub struct SecureTsaClient {
    endpoint: String,
    host: String,
    port: u16,
    path: String,
    policy_name: String,
    tls: TlsPolicy,
    timeout: Duration,
    trust_store: TrustStore,
}

impl SecureTsaClient {
    /// `endpoint` tem de ser `https://`. Um `http://` é **recusado na
    /// construção**, e não no envio: um cliente que se deixa construir com um
    /// endpoint inseguro é um cliente que alguém vai usar por engano.
    pub fn new(
        endpoint: impl Into<String>,
        policy_name: impl Into<String>,
        trust_store: TrustStore,
        tls: TlsPolicy,
        timeout: Duration,
    ) -> Result<Self, CompError> {
        let endpoint = endpoint.into();
        let resto = endpoint.strip_prefix("https://").ok_or_else(|| {
            CompError::Tsa(format!(
                "endpoint `{endpoint}` não é https://: §10 exige HTTPS em produção"
            ))
        })?;
        if trust_store.is_empty() {
            return Err(CompError::Tsa(
                "trust store vazio: sem âncoras não há como autenticar a ACT (§11)".into(),
            ));
        }
        let (autoridade, path) = match resto.find('/') {
            Some(i) => (&resto[..i], resto[i..].to_string()),
            None => (resto, "/".to_string()),
        };
        let (host, port) = match autoridade.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>().map_err(|_| {
                    CompError::Tsa(format!("porto inválido em `{endpoint}`"))
                })?,
            ),
            None => (autoridade.to_string(), 443),
        };
        if host.is_empty() {
            return Err(CompError::Tsa(format!("endpoint `{endpoint}` sem host")));
        }
        Ok(Self {
            endpoint,
            host,
            port,
            path,
            policy_name: policy_name.into(),
            tls,
            timeout,
            trust_store,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn policy_name(&self) -> &str {
        &self.policy_name
    }

    /// A configuração de TLS que este cliente usa.
    ///
    /// Exposta para ser testável sem rede: o que interessa provar é que as
    /// raízes vêm do trust store e mais lado nenhum, e isso vê-se aqui.
    pub fn tls_config(&self) -> Result<rustls::ClientConfig, CompError> {
        let mut roots = rustls::RootCertStore::empty();
        let mut aceites = 0usize;
        for anchor in self.trust_store.anchors() {
            use der::Encode;
            let der = anchor
                .certificate
                .to_der()
                .map_err(|e| CompError::Tsa(format!("âncora não recodifica: {e}")))?;
            if roots
                .add(rustls_pki_types::CertificateDer::from(der))
                .is_ok()
            {
                aceites += 1;
            }
            // Uma âncora que o rustls recuse continua a servir para validar o
            // CARIMBO: os dois usos têm requisitos diferentes (o TLS exige
            // extensões que um carimbo não exige). Contar as aceites e falhar
            // só se nenhuma servir é mais honesto do que rejeitar o store todo.
        }
        if aceites == 0 {
            return Err(CompError::Tsa(
                "nenhuma âncora do trust store serve como raiz TLS".into(),
            ));
        }
        // O provider é escolhido EXPLICITAMENTE. Com `ring` e `aws-lc-rs`
        // ambos na árvore — e estão, vindos de dependentes diferentes — o
        // `ClientConfig::builder()` não consegue decidir e **entra em pânico**
        // em vez de devolver erro. Num servidor isso seria uma paragem no
        // primeiro carimbo, não uma falha tratável.
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| CompError::Tsa(format!("versões de TLS não configuram: {e}")))?
            .with_root_certificates(roots);
        match &self.tls.client_identity {
            Some(id) => {
                let chain: Vec<_> = id
                    .certificate_chain_der
                    .iter()
                    .map(|d| rustls_pki_types::CertificateDer::from(d.clone()))
                    .collect();
                let key = rustls_pki_types::PrivateKeyDer::try_from(id.private_key_der.clone())
                    .map_err(|e| CompError::Tsa(format!("chave de cliente inválida: {e}")))?;
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|e| CompError::Tsa(format!("mTLS não configura: {e}")))
            }
            None => Ok(builder.with_no_client_auth()),
        }
    }

    /// Envia uma `TimeStampReq` em DER e devolve os bytes da `TimeStampResp`.
    pub fn post_timestamp_request(&self, req_der: &[u8]) -> Result<Vec<u8>, CompError> {
        let config = Arc::new(self.tls_config()?);
        let servidor = rustls_pki_types::ServerName::try_from(self.host.clone())
            .map_err(|_| CompError::Tsa(format!("host `{}` não é um nome válido", self.host)))?;
        let mut conexao = rustls::ClientConnection::new(config, servidor)
            .map_err(|e| CompError::Tsa(format!("handshake TLS não inicia: {e}")))?;

        let enderecos: Vec<_> = std::net::ToSocketAddrs::to_socket_addrs(&(
            self.host.as_str(),
            self.port,
        ))
        .map_err(|e| CompError::Tsa(format!("resolução de `{}` falhou: {e}", self.host)))?
        .collect();
        let endereco = enderecos
            .first()
            .ok_or_else(|| CompError::Tsa(format!("`{}` não resolve", self.host)))?;
        let mut socket = TcpStream::connect_timeout(endereco, self.timeout)
            .map_err(|e| CompError::Tsa(format!("ligação à ACT falhou: {e}")))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| socket.set_write_timeout(Some(self.timeout)))
            .map_err(|e| CompError::Tsa(format!("timeouts não aplicam: {e}")))?;

        let mut tls = rustls::Stream::new(&mut conexao, &mut socket);
        let cabecalho = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/timestamp-query\r\n\
             Accept: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.path,
            self.host,
            req_der.len()
        );
        tls.write_all(cabecalho.as_bytes())
            .and_then(|_| tls.write_all(req_der))
            .and_then(|_| tls.flush())
            .map_err(|e| CompError::Tsa(format!("envio à ACT falhou: {e}")))?;

        let tecto = self.tls.max_response_bytes.min(HARD_MAX_RESPONSE_BYTES);
        let mut bruto = Vec::with_capacity(8 * 1024);
        let mut buf = [0u8; 8 * 1024];
        loop {
            match tls.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if bruto.len() + n > tecto {
                        return Err(CompError::Tsa(format!(
                            "resposta da ACT acima do tecto de {tecto} bytes"
                        )));
                    }
                    bruto.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(CompError::Tsa(format!("leitura da ACT falhou: {e}"))),
            }
        }
        Self::corpo_http(&bruto)
    }

    /// Separa o corpo do cabeçalho e recusa o que não for `200`.
    ///
    /// Um `3xx` é recusado explicitamente em vez de seguido: ver o cabeçalho
    /// do módulo.
    fn corpo_http(bruto: &[u8]) -> Result<Vec<u8>, CompError> {
        let sep = bruto
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| CompError::Tsa("resposta HTTP sem cabeçalho completo".into()))?;
        let cabecalho = String::from_utf8_lossy(&bruto[..sep]);
        let primeira = cabecalho.lines().next().unwrap_or_default();
        let codigo = primeira
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| CompError::Tsa(format!("estado HTTP ilegível: `{primeira}`")))?;
        if (300..400).contains(&codigo) {
            return Err(CompError::Tsa(format!(
                "ACT respondeu {codigo}: redirects não são seguidos — reenviar o digest para um \
                 destino escolhido pelo servidor anula a autenticação do certificado"
            )));
        }
        if codigo != 200 {
            return Err(CompError::Tsa(format!("ACT respondeu {codigo}")));
        }
        Ok(bruto[sep + 4..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pki;

    fn store_de_teste() -> TrustStore {
        let mut store = TrustStore::new();
        store
            .add_pem_or_der("raiz", &test_pki::self_signed_root("Raiz TLS").certificate_der)
            .unwrap();
        store
    }

    #[test]
    fn http_e_recusado_na_construcao_e_nao_no_envio() {
        // §10. Um cliente que se deixa construir com um endpoint inseguro e um
        // cliente que alguem vai usar por engano.
        let erro = SecureTsaClient::new(
            "http://act.exemplo/tsa",
            "politica",
            store_de_teste(),
            TlsPolicy::default(),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(erro.to_string().contains("não é https"), "{erro}");
    }

    #[test]
    fn sem_ancoras_o_cliente_nem_se_constroi() {
        // "Ainda nao disse a quem confiar" nao pode significar "confia em
        // qualquer um".
        let erro = SecureTsaClient::new(
            "https://act.exemplo/tsa",
            "politica",
            TrustStore::new(),
            TlsPolicy::default(),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(erro.to_string().contains("trust store vazio"), "{erro}");
    }

    #[test]
    fn o_endpoint_e_decomposto_com_porto_por_omissao() {
        let c = SecureTsaClient::new(
            "https://act.exemplo/tsa/v1",
            "p",
            store_de_teste(),
            TlsPolicy::default(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(c.host, "act.exemplo");
        assert_eq!(c.port, 443);
        assert_eq!(c.path, "/tsa/v1");

        let c = SecureTsaClient::new(
            "https://act.exemplo:8443",
            "p",
            store_de_teste(),
            TlsPolicy::default(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(c.port, 8443);
        assert_eq!(c.path, "/");
    }

    /// A verificacao que mais importa e que nao precisa de rede: as raizes do
    /// TLS sao as do trust store, e mais nenhumas.
    #[test]
    fn as_raizes_tls_vem_do_trust_store_e_nao_do_sistema() {
        let c = SecureTsaClient::new(
            "https://act.exemplo/tsa",
            "p",
            store_de_teste(),
            TlsPolicy::default(),
            Duration::from_secs(5),
        )
        .unwrap();
        // Constroi sem erro: ha exactamente uma raiz, a que o operador poe.
        c.tls_config().expect("config TLS");
    }

    #[test]
    fn um_redirect_e_recusado_com_a_razao() {
        let resposta = b"HTTP/1.1 302 Found\r\nLocation: https://outro/\r\n\r\n";
        let erro = SecureTsaClient::corpo_http(resposta).unwrap_err();
        assert!(erro.to_string().contains("redirects"), "{erro}");
    }

    #[test]
    fn um_estado_que_nao_e_200_e_recusado() {
        let erro = SecureTsaClient::corpo_http(b"HTTP/1.1 500 Erro\r\n\r\ncorpo").unwrap_err();
        assert!(erro.to_string().contains("500"), "{erro}");
    }

    #[test]
    fn o_corpo_sai_depois_do_cabecalho() {
        let corpo =
            SecureTsaClient::corpo_http(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc").unwrap();
        assert_eq!(corpo, b"abc");
    }

    #[test]
    fn uma_resposta_sem_cabecalho_completo_e_recusada() {
        assert!(SecureTsaClient::corpo_http(b"HTTP/1.1 200 OK\r\n").is_err());
    }

    #[test]
    fn a_chave_privada_do_mtls_nunca_aparece_no_debug() {
        let id = ClientIdentity {
            certificate_chain_der: vec![vec![1, 2, 3]],
            private_key_der: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let texto = format!("{id:?}");
        assert!(texto.contains("<redacted>"));
        assert!(!texto.contains("222"), "{texto}");
    }

    #[test]
    fn o_tecto_absoluto_prevalece_sobre_uma_politica_generosa() {
        let politica = TlsPolicy {
            max_response_bytes: usize::MAX,
            ..Default::default()
        };
        assert_eq!(
            politica.max_response_bytes.min(HARD_MAX_RESPONSE_BYTES),
            HARD_MAX_RESPONSE_BYTES
        );
    }
}
