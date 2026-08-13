//! RFC 3161 Time-Stamp Protocol — the *outbound* request structures.
//!
//! These are DER-encoded exactly as a homologated ACT (e.g. SERPRO, synced to
//! the Observatório Nacional atomic clock) expects. The response is a CMS
//! `TimeStampToken`; parsing + chain-validating that real token against
//! ICP-Brasil trust anchors is the production verifier (see `verify`), which
//! needs the órgão's trust roots and is staged after this milestone.

use der::asn1::{Null, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Sequence};

/// SHA-256 (`id-sha256`, 2.16.840.1.101.3.4.2.1) — the digest algorithm we
/// send. blake3 is intentionally *not* used here: ACTs reject unregistered OIDs.
pub const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// `AlgorithmIdentifier` with NULL parameters (the encoding ACTs expect for
/// SHA-256).
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    #[asn1(optional = "true")]
    pub parameters: Option<Null>,
}

impl AlgorithmIdentifier {
    pub fn sha256() -> Self {
        Self {
            algorithm: OID_SHA256,
            parameters: Some(Null),
        }
    }
}

/// `MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage OCTET STRING }`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifier,
    pub hashed_message: OctetString,
}

impl MessageImprint {
    /// Build a SHA-256 imprint from a 32-byte digest.
    pub fn sha256(digest: &[u8; 32]) -> Result<Self, der::Error> {
        Ok(Self {
            hash_algorithm: AlgorithmIdentifier::sha256(),
            hashed_message: OctetString::new(digest.as_slice())?,
        })
    }

    /// The raw hashed message bytes.
    pub fn digest_bytes(&self) -> &[u8] {
        self.hashed_message.as_bytes()
    }
}

/// `TimeStampReq` (RFC 3161 §2.4.1). `certReq` is sent TRUE so the ACT returns
/// its signing certificate inside the token (needed for offline verification).
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct TimeStampReq {
    pub version: u8,
    pub message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    pub req_policy: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    pub nonce: Option<u64>,
    pub cert_req: bool,
}

impl TimeStampReq {
    /// Construct a v1 request for a SHA-256 imprint with the given anti-replay
    /// nonce.
    pub fn new(imprint: &[u8; 32], nonce: u64) -> Result<Self, der::Error> {
        Ok(Self {
            version: 1,
            message_imprint: MessageImprint::sha256(imprint)?,
            req_policy: None,
            nonce: Some(nonce),
            cert_req: true,
        })
    }

    /// DER bytes, ready to POST (`Content-Type: application/timestamp-query`).
    pub fn to_der_bytes(&self) -> Result<Vec<u8>, der::Error> {
        self.to_der()
    }

    /// Parse a DER request (used by an in-process TSA to read the imprint back).
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, der::Error> {
        Self::from_der(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_der_roundtrips_and_carries_imprint() {
        let imprint = [0xABu8; 32];
        let req = TimeStampReq::new(&imprint, 0xDEAD_BEEF).unwrap();
        let der = req.to_der_bytes().unwrap();
        let back = TimeStampReq::from_der_bytes(&der).unwrap();
        assert_eq!(back.version, 1);
        assert_eq!(back.nonce, Some(0xDEAD_BEEF));
        assert!(back.cert_req);
        assert_eq!(back.message_imprint.digest_bytes(), &imprint[..]);
        assert_eq!(back.message_imprint.hash_algorithm.algorithm, OID_SHA256);
    }
}
