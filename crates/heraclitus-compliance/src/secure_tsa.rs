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

use crate::icp::{IcpBrasilTimestampVerifier, TimestampValidationPolicy};
use crate::receipt::TimestampValidationState;
use crate::rfc3161::{TimeStampReq, TimeStampResp};
use crate::trust_store::TrustStore;
use crate::tsa::TsaClient;
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
    /// Quando presente, o token é verificado ANTES de sair deste cliente.
    verifier: Option<IcpBrasilTimestampVerifier>,
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
            verifier: None,
        })
    }

    /// Instala o verificador ICP-Brasil **a partir do trust store deste
    /// cliente**, e não de um que o chamador traga.
    ///
    /// É deliberado não aceitar um `IcpBrasilTimestampVerifier` já construído:
    /// se o chamador pudesse passar um, podia passar um com âncoras diferentes
    /// das do TLS, e o sistema ficava a autenticar o *canal* contra um conjunto
    /// e o *carimbo* contra outro — uma divergência que ninguém veria na
    /// configuração e que só apareceria no dia em que uma das duas falhasse.
    ///
    /// Com o verificador instalado, [`TsaClient::stamp`] passa a **verificar o
    /// token antes de o devolver**: um carimbo que não encadeie até uma âncora
    /// nunca chega a ser escrito como recibo.
    pub fn with_verifier(mut self, policy: TimestampValidationPolicy) -> Self {
        self.verifier = Some(IcpBrasilTimestampVerifier::new(
            self.trust_store.clone(),
            policy,
        ));
        self
    }

    /// Instala CRLs no verificador deste cliente (§9).
    ///
    /// Devolve `Err` se [`Self::with_verifier`] não foi chamado antes, em vez
    /// de aceitar em silêncio: sem cadeia validada não há certificado cuja
    /// revogação consultar, e um cliente que aceitasse CRLs sem verificador
    /// deixaria o operador convencido de que a revogação está ligada quando
    /// nada a consulta.
    pub fn with_crls(
        mut self,
        store: crate::crl::CrlStore,
        policy: crate::crl::CrlPolicy,
    ) -> Result<Self, CompError> {
        let v = self.verifier.take().ok_or_else(|| {
            CompError::Tsa(
                "with_crls exige with_verifier antes: sem cadeia validada não há certificado \
                 cuja revogação consultar"
                    .into(),
            )
        })?;
        self.verifier = Some(v.with_crls(store, policy));
        Ok(self)
    }

    /// Se este cliente verifica o que recebe.
    pub const fn verifies(&self) -> bool {
        self.verifier.is_some()
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

    /// Os octetos de valor do INTEGER do nonce, como o
    /// [`IcpBrasilTimestampVerifier`] os vai comparar.
    ///
    /// Passa pelo mesmo codificador e descodificador DER que produziu o pedido
    /// em vez de reproduzir a codificação à mão: a forma mínima com
    /// complemento para dois tem casos de fronteira (o `0x00` à cabeça quando o
    /// bit alto está aceso) e um nonce que não bate faz o carimbo ser recusado
    /// como repetição — uma falha que só apareceria contra uma ACT real.
    fn nonce_octetos(nonce: u64) -> Result<Vec<u8>, CompError> {
        use der::{Decode, Encode};
        let tlv = nonce
            .to_der()
            .map_err(|e| CompError::Tsa(format!("nonce não codifica: {e}")))?;
        let int = der::asn1::Int::from_der(&tlv)
            .map_err(|e| CompError::Tsa(format!("nonce não relê: {e}")))?;
        Ok(int.as_bytes().to_vec())
    }

    fn timestamp_request(
        &self,
        imprint: &[u8; 32],
        nonce: u64,
    ) -> Result<TimeStampReq, CompError> {
        let req_policy = self
            .verifier
            .as_ref()
            .and_then(|v| v.policy().required_policy_oid);
        TimeStampReq::new_with_policy(imprint, nonce, req_policy)
            .map_err(|e| CompError::Tsa(format!("pedido não codifica: {e}")))
    }
}

impl TsaClient for SecureTsaClient {
    fn policy_name(&self) -> &str {
        &self.policy_name
    }

    /// Sem verificador isto é exactamente o que o [`crate::tsa::HttpTsa`] era —
    /// um transporte melhor, e nada mais. O estado tem de o dizer.
    fn validation_state(&self) -> TimestampValidationState {
        if self.verifier.is_some() {
            TimestampValidationState::ExternalTokenVerified
        } else {
            TimestampValidationState::ExternalTokenUnvalidated
        }
    }

    fn stamp(&self, imprint: &[u8; 32]) -> Result<Vec<u8>, CompError> {
        let mut bruto = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bruto);
        // Bit alto limpo: um nonce negativo é legal em DER mas irrita
        // implementações de ACT que o tratam como sem sinal, e não ganha
        // entropia nenhuma que interesse.
        let nonce = u64::from_be_bytes(bruto) >> 1;

        let req = self.timestamp_request(imprint, nonce)?;
        let corpo = req
            .to_der_bytes()
            .map_err(|e| CompError::Tsa(format!("pedido não codifica: {e}")))?;
        let resposta = self.post_timestamp_request(&corpo)?;

        // §2.4.2 — o corpo é uma `TimeStampResp`, não um token. Guardar o corpo
        // inteiro como se fosse o carimbo faria uma RECUSA da ACT ficar
        // persistida como evidência legal.
        let resp = TimeStampResp::from_der_bytes(&resposta)
            .map_err(|e| CompError::Tsa(format!("resposta da ACT não é TimeStampResp: {e}")))?;
        let token = resp
            .granted_token()
            .map_err(|e| CompError::Tsa(e.to_string()))?;

        if let Some(v) = &self.verifier {
            let esperado = Self::nonce_octetos(nonce)?;
            // A verificação acontece AQUI, e não no worker: um token que não
            // encadeie até uma âncora nunca chega a ser escrito em disco como
            // recibo. Falhar cedo é a diferença entre "não temos carimbo desta
            // marca" e "temos um recibo que não vale nada e ninguém sabe".
            v.verify(&token, imprint, Some(&esperado), crate::now_unix_ms())?;
        }
        Ok(token)
    }

    fn verified_gen_unix_ms(&self, token: &[u8], imprint: &[u8; 32]) -> Option<u64> {
        // Sem nonce: o nonce do pedido já não existe aqui, e a frescura foi
        // confirmada em `stamp`. O que esta segunda passagem tem de garantir é
        // que o `genTime` devolvido veio de um token que ENCADEIA — não é uma
        // leitura optimista do campo.
        let v = self.verifier.as_ref()?;
        v.verify(token, imprint, None, crate::now_unix_ms())
            .ok()
            .map(|t| t.gen_unix_ms)
    }

    fn verified_policy_oid(&self, token: &[u8], imprint: &[u8; 32]) -> Option<String> {
        let v = self.verifier.as_ref()?;
        v.verify(token, imprint, None, crate::now_unix_ms())
            .ok()
            .map(|t| t.policy_oid.to_string())
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
    fn politica_exigida_vai_no_req_policy_e_nao_so_no_verificador() {
        let oid = const_oid::ObjectIdentifier::new_unwrap("2.16.76.1.7.1.1.2.3");
        let client = SecureTsaClient::new(
            "https://act.exemplo/tsa",
            "ACT teste",
            store_de_teste(),
            TlsPolicy::default(),
            Duration::from_secs(5),
        )
        .unwrap()
        .with_verifier(TimestampValidationPolicy {
            required_policy_oid: Some(oid),
            ..Default::default()
        });

        let req = client.timestamp_request(&[0xA5; 32], 77).unwrap();
        assert_eq!(req.req_policy, Some(oid));
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
