//! Time-stamping authorities (ACTs).
//!
//! Two backends behind one trait:
//!
//! * [`LocalTsa`] — an in-process dev/demo authority. It issues a self-contained
//!   [`DevToken`] (a P-256 signed `DevTstInfo`) so the whole anchor → stamp →
//!   verify loop is exercised end-to-end **without any government credential**.
//!   It is NOT RFC 3161 / ICP-Brasil valid; it exists to prove the architecture.
//! * [`HttpTsa`] — POSTs a RFC 3161 `TimeStampReq` to an external endpoint over
//!   plain HTTP, extracts the `TimeStampToken` from the `TimeStampResp`, and
//!   refuses a response the ACT did not grant. It does **not** validate the
//!   CMS/X.509 chain, so its receipts stay `ExternalTokenUnvalidated`.
//!
//! O terceiro cliente não vive aqui: [`crate::secure_tsa::SecureTsaClient`]
//! fala HTTPS e valida a cadeia contra as âncoras que o operador instalou
//! (SPEC-0046 §10/§11). É o de produção. Este módulo descrevia-se como se ele
//! não existisse — e uma descrição que envelhece manda corrigir a coisa errada.

use crate::rfc3161::{MessageImprint, TimeStampReq};
use crate::receipt::TimestampValidationState;
use crate::{now_unix_ms, CompError};
use der::asn1::OctetString;
use der::{Encode, Sequence};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// One authority that turns a 32-byte SHA-256 imprint into a timestamp token.
pub trait TsaClient {
    /// Human-readable policy/authority name recorded in the receipt.
    fn policy_name(&self) -> &str;
    /// Provenance that can be established by this client implementation.
    ///
    /// Implementations must never return a state stronger than they can prove.
    /// In particular, an external token remains unvalidated until a CMS/X.509
    /// verifier and an explicit trust store are available.
    fn validation_state(&self) -> TimestampValidationState;
    /// Stamp `imprint`, returning DER token bytes to persist verbatim.
    fn stamp(&self, imprint: &[u8; 32]) -> Result<Vec<u8>, CompError>;

    /// `genTime` da autoridade para um token que este cliente acabou de
    /// produzir — e **apenas** quando o próprio cliente o verificou contra um
    /// trust store.
    ///
    /// O default é `None` de propósito: um cliente que não sabe verificar não
    /// pode contribuir com uma hora de autoridade. O `genTime` lido de um token
    /// que ninguém validou é uma *alegação* da ACT, não um facto, e gravá-lo
    /// num recibo seria dar-lhe um estatuto que não tem.
    fn verified_gen_unix_ms(&self, _token: &[u8], _imprint: &[u8; 32]) -> Option<u64> {
        None
    }

    /// OID de política lido de um token que este cliente verificou.
    ///
    /// É separado de [`Self::policy_name`]: esse é um rótulo humano escolhido
    /// pelo operador; este vem do `TSTInfo` assinado pela ACT.
    fn verified_policy_oid(&self, _token: &[u8], _imprint: &[u8; 32]) -> Option<String> {
        None
    }
}

// ---------------------------------------------------------------------------
// Dev token format (self-contained, P-256). Clearly distinct from a real RFC
// 3161 token so the two can never be confused at verification time.
// ---------------------------------------------------------------------------

/// Content signed by the dev TSA: version, wall-clock time, and the imprint.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct DevTstInfo {
    pub version: u8,
    pub gen_unix_ms: u64,
    pub message_imprint: MessageImprint,
}

/// A dev timestamp token: the signed `DevTstInfo`, the ECDSA signature, and the
/// TSA's SEC1 public key (so a verifier needs nothing else).
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct DevToken {
    /// DER of [`DevTstInfo`].
    pub tst_info: OctetString,
    /// 64-byte P-256 ECDSA signature over `tst_info`.
    pub signature: OctetString,
    /// SEC1 (uncompressed) encoding of the TSA verifying key.
    pub tsa_key: OctetString,
}

/// In-process dev/demo timestamp authority.
pub struct LocalTsa {
    signing: SigningKey,
    name: String,
}

impl LocalTsa {
    /// Create a dev TSA with a fresh random key.
    pub fn generate(name: impl Into<String>) -> Self {
        Self {
            signing: SigningKey::random(&mut rand::thread_rng()),
            name: name.into(),
        }
    }

    /// SEC1 (uncompressed) bytes of this TSA's public key.
    pub fn verifying_key_sec1(&self) -> Vec<u8> {
        self.signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
}

impl TsaClient for LocalTsa {
    fn policy_name(&self) -> &str {
        &self.name
    }

    fn validation_state(&self) -> TimestampValidationState {
        TimestampValidationState::DevelopmentOnly
    }

    fn stamp(&self, imprint: &[u8; 32]) -> Result<Vec<u8>, CompError> {
        let info = DevTstInfo {
            version: 1,
            gen_unix_ms: now_unix_ms(),
            message_imprint: MessageImprint::sha256(imprint)?,
        };
        let info_der = info.to_der()?;
        let sig: Signature = self.signing.sign(&info_der);
        let token = DevToken {
            tst_info: OctetString::new(info_der)?,
            signature: OctetString::new(sig.to_bytes().to_vec())?,
            tsa_key: OctetString::new(self.verifying_key_sec1())?,
        };
        Ok(token.to_der()?)
    }
}

/// Endpoint RFC 3161 externo sobre HTTP em claro.
///
/// Deliberadamente indisponível numa configuração de produção: `http://` não é
/// uma fronteira de confiança aceitável. Para HTTPS **com** validação de cadeia
/// use [`crate::secure_tsa::SecureTsaClient`], que existe desde a SPEC-0046
/// §10 — este cliente não é o único que há, é o que não valida nada.
///
/// O que ele faz e não fazia: extrai o `TimeStampToken` da `TimeStampResp` e
/// recusa uma resposta não concedida. O que continua a não fazer: validar a
/// cadeia CMS/X.509, pelo que os seus recibos ficam
/// `ExternalTokenUnvalidated`.
pub struct HttpTsa {
    url: String,
    policy: String,
    timeout: Duration,
}

impl HttpTsa {
    pub fn new(url: impl Into<String>, policy: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            policy: policy.into(),
            timeout: Duration::from_secs(10),
        }
    }
}

impl TsaClient for HttpTsa {
    fn policy_name(&self) -> &str {
        &self.policy
    }

    fn validation_state(&self) -> TimestampValidationState {
        TimestampValidationState::ExternalTokenUnvalidated
    }

    fn stamp(&self, imprint: &[u8; 32]) -> Result<Vec<u8>, CompError> {
        let mut nonce = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let req = TimeStampReq::new(imprint, u64::from_be_bytes(nonce))?;
        let body = req.to_der_bytes()?;
        let resposta = http_post_der(
            &self.url,
            "application/timestamp-query",
            &body,
            self.timeout,
        )?;
        // O corpo é uma `TimeStampResp` (§2.4.2), não um token. Devolvê-lo
        // inteiro — como aqui se fazia — tinha duas consequências: uma RECUSA
        // da ACT (`status=2`, sem token nenhum) ficava persistida como recibo,
        // e o que ficava em disco nunca poderia ser verificado por um
        // verificador CMS, porque não era um `ContentInfo`.
        //
        // Este cliente continua a não validar a cadeia — é o que
        // `ExternalTokenUnvalidated` diz. Mas o que ele guarda passa a ser um
        // token, e um token guardado hoje pode ser verificado amanhã, quando o
        // órgão instalar as âncoras.
        let resp = crate::rfc3161::TimeStampResp::from_der_bytes(&resposta).map_err(|e| {
            CompError::Tsa(format!("resposta da ACT não é uma TimeStampResp: {e}"))
        })?;
        resp.granted_token()
            .map_err(|e| CompError::Tsa(e.to_string()))
    }
}

/// POST HTTP/1.1 mínimo de um corpo binário, devolvendo os bytes da resposta.
/// Âmbito honesto: `http://` + respostas com `Content-Length`. Sem TLS, sem
/// transfer-encoding chunked, sem validação de confiança — nunca usar este
/// transporte como fronteira de conformidade de produção.
fn http_post_der(
    url: &str,
    content_type: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, CompError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        CompError::Unsupported(format!(
            "HttpTsa só fala http:// e recebeu `{url}`. Para HTTPS use \
             SecureTsaClient (SPEC-0046 §10), que valida a cadeia contra as âncoras \
             configuradas — no servidor, ponha compliance_tsa_mode=https"
        ))
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host_port = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let host = authority.split(':').next().unwrap_or(authority);

    let mut stream = TcpStream::connect(&host_port)
        .map_err(|e| CompError::Tsa(format!("ligação à ACT falhou: {e}")))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {content_type}\r\n\
         Accept: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|e| CompError::Tsa(format!("envio à ACT falhou: {e}")))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| CompError::Tsa(format!("leitura da ACT falhou: {e}")))?;

    // Split headers/body on the blank line.
    let sep = b"\r\n\r\n";
    let pos = raw
        .windows(sep.len())
        .position(|w| w == sep)
        .ok_or_else(|| CompError::Tsa("resposta HTTP da ACT malformada".into()))?;
    let head = String::from_utf8_lossy(&raw[..pos]);
    let status_ok = head
        .lines()
        .next()
        .map(|l| l.contains(" 200"))
        .unwrap_or(false);
    if !status_ok {
        return Err(CompError::Tsa(format!(
            "ACT respondeu sem 200: {}",
            head.lines().next().unwrap_or("")
        )));
    }
    Ok(raw[pos + sep.len()..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_tsa_issues_decodable_token() {
        use der::Decode;
        let tsa = LocalTsa::generate("ACT-dev");
        let token = tsa.stamp(&[9u8; 32]).unwrap();
        let decoded = DevToken::from_der(&token).unwrap();
        assert_eq!(decoded.signature.as_bytes().len(), 64);
        assert!(!decoded.tsa_key.as_bytes().is_empty());
    }
}
