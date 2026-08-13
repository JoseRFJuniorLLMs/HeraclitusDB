//! Time-stamping authorities (ACTs).
//!
//! Two backends behind one trait:
//!
//! * [`LocalTsa`] — an in-process dev/demo authority. It issues a self-contained
//!   [`DevToken`] (a P-256 signed `DevTstInfo`) so the whole anchor → stamp →
//!   verify loop is exercised end-to-end **without any government credential**.
//!   It is NOT RFC 3161 / ICP-Brasil valid; it exists to prove the architecture.
//! * [`HttpTsa`] — POSTs a real RFC 3161 `TimeStampReq` to a homologated ACT
//!   (SERPRO etc.) and returns the raw `.tst` (a CMS `TimeStampToken`). Use this
//!   in production; the token carries legal weight, validated by the production
//!   verifier against ICP-Brasil roots.

use crate::rfc3161::{MessageImprint, TimeStampReq};
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
    /// Stamp `imprint`, returning DER token bytes to persist verbatim.
    fn stamp(&self, imprint: &[u8; 32]) -> Result<Vec<u8>, CompError>;
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

/// Production ACT over RFC 3161 HTTP. Plain `http://` only — for `https://`
/// terminate TLS at a reverse proxy in the órgão's network, or extend this with
/// a vetted TLS stack. Returns the raw CMS `TimeStampToken` bytes.
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

    fn stamp(&self, imprint: &[u8; 32]) -> Result<Vec<u8>, CompError> {
        let mut nonce = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let req = TimeStampReq::new(imprint, u64::from_be_bytes(nonce))?;
        let body = req.to_der_bytes()?;
        http_post_der(
            &self.url,
            "application/timestamp-query",
            &body,
            self.timeout,
        )
    }
}

/// Minimal HTTP/1.1 POST of a binary body, returning the response body bytes.
/// Honest scope: `http://` + `Content-Length` responses (what RFC 3161 ACTs
/// return). No TLS, no chunked transfer — production hardening is a follow-up.
fn http_post_der(
    url: &str,
    content_type: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, CompError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        CompError::Unsupported(
            "HttpTsa só suporta http:// nesta versão (use proxy TLS para https)".into(),
        )
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
