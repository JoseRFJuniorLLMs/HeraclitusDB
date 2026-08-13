//! Institutional signature over consolidated snapshots.
//!
//! A timestamp proves *when* a commitment existed. An institutional signature
//! proves *who* vouches for it (the AGU, CGU, etc.). These are orthogonal and
//! both go into the legal package.
//!
//! Backends sit behind [`InstitutionalSigner`]:
//!
//! * [`SoftKeySigner`] — software P-256 key. **Dev only.** A software key file
//!   (A1 `.pfx`) sitting on the database host is exactly what an órgão security
//!   review tends to reject.
//! * [`Pkcs11Signer`] — the production path: the private key lives in an HSM /
//!   token and is used over PKCS#11. Stubbed here so the integration point is
//!   explicit; wiring a concrete PKCS#11 provider is deliberately deferred to
//!   the órgão's homologated module.

use crate::CompError;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};

/// A detached institutional signature plus the material to verify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstitutionalSignature {
    pub subject: String,
    pub signature: Vec<u8>,
    /// SEC1 (uncompressed) public key of the signer (dev). In production the
    /// signer identity is the X.509 certificate chain instead.
    pub public_key_sec1: Vec<u8>,
}

/// Anything that can vouch for a snapshot on behalf of an institution.
pub trait InstitutionalSigner {
    /// Certificate subject / institution name.
    fn subject(&self) -> &str;
    /// Sign arbitrary snapshot bytes (e.g. the commitment DER).
    fn sign_snapshot(&self, data: &[u8]) -> Result<InstitutionalSignature, CompError>;
}

/// Dev-only software signer.
pub struct SoftKeySigner {
    signing: SigningKey,
    subject: String,
}

impl SoftKeySigner {
    pub fn generate(subject: impl Into<String>) -> Self {
        Self {
            signing: SigningKey::random(&mut rand::thread_rng()),
            subject: subject.into(),
        }
    }
}

impl InstitutionalSigner for SoftKeySigner {
    fn subject(&self) -> &str {
        &self.subject
    }

    fn sign_snapshot(&self, data: &[u8]) -> Result<InstitutionalSignature, CompError> {
        let sig: Signature = self.signing.sign(data);
        Ok(InstitutionalSignature {
            subject: self.subject.clone(),
            signature: sig.to_bytes().to_vec(),
            public_key_sec1: self
                .signing
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        })
    }
}

/// C2.5 — assinador pós-quântico **ML-DSA-44 (FIPS 204)**, padronizado pelo
/// NIST. Crypto-agility para a prova forense de longa duração: um adversário
/// com computador quântico futuro quebraria ECDSA P-256 retroativamente; a
/// âncora RFC 3161 já mitiga (o carimbo prova que a assinatura existia antes),
/// mas o ML-DSA fecha a janela por completo. `public_key_sec1` transporta a
/// chave pública ML-DSA em bytes (o nome do campo é herdado do formato dev).
pub struct MlDsaSigner {
    sk: fips204::ml_dsa_44::PrivateKey,
    pk_bytes: Vec<u8>,
    subject: String,
}

impl MlDsaSigner {
    pub fn generate(subject: impl Into<String>) -> Result<Self, CompError> {
        use fips204::traits::SerDes as _;
        let (pk, sk) = fips204::ml_dsa_44::try_keygen()
            .map_err(|e| CompError::Unsupported(format!("ML-DSA keygen: {e}")))?;
        Ok(Self {
            sk,
            pk_bytes: pk.into_bytes().to_vec(),
            subject: subject.into(),
        })
    }

    /// Verificação de referência (o par do `sign_snapshot`): o perito pode
    /// re-verificar com QUALQUER implementação FIPS 204 independente.
    pub fn verify(pk_bytes: &[u8], data: &[u8], signature: &[u8]) -> bool {
        use fips204::traits::{SerDes as _, Verifier as _};
        let Ok(pk_arr) = <[u8; fips204::ml_dsa_44::PK_LEN]>::try_from(pk_bytes) else {
            return false;
        };
        let Ok(pk) = fips204::ml_dsa_44::PublicKey::try_from_bytes(pk_arr) else {
            return false;
        };
        let Ok(sig) = <[u8; fips204::ml_dsa_44::SIG_LEN]>::try_from(signature) else {
            return false;
        };
        pk.verify(data, &sig, &[])
    }
}

impl InstitutionalSigner for MlDsaSigner {
    fn subject(&self) -> &str {
        &self.subject
    }

    fn sign_snapshot(&self, data: &[u8]) -> Result<InstitutionalSignature, CompError> {
        use fips204::traits::Signer as _;
        let sig = self
            .sk
            .try_sign(data, &[])
            .map_err(|e| CompError::Unsupported(format!("ML-DSA sign: {e}")))?;
        Ok(InstitutionalSignature {
            subject: self.subject.clone(),
            signature: sig.to_vec(),
            public_key_sec1: self.pk_bytes.clone(),
        })
    }
}

/// C2.5 — assinador HÍBRIDO para a transição pós-quântica: assina com AMBOS
/// (ECDSA P-256 + ML-DSA-44) e a verificação exige os dois. Se qualquer um
/// dos esquemas cair, a prova continua de pé pelo outro — o padrão recomendado
/// enquanto os trust anchors institucionais ainda são clássicos.
///
/// Codificação (assinatura e chave pública): `[len u16 BE][parte ECDSA][parte
/// ML-DSA]` — autodescritiva e estável.
pub struct HybridSigner {
    classical: SoftKeySigner,
    pqc: MlDsaSigner,
    subject: String,
}

fn hybrid_encode(classical: &[u8], pqc: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + classical.len() + pqc.len());
    out.extend_from_slice(&(classical.len() as u16).to_be_bytes());
    out.extend_from_slice(classical);
    out.extend_from_slice(pqc);
    out
}

fn hybrid_split(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    if bytes.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() < 2 + n {
        return None;
    }
    Some((&bytes[2..2 + n], &bytes[2 + n..]))
}

impl HybridSigner {
    pub fn generate(subject: impl Into<String>) -> Result<Self, CompError> {
        let subject = subject.into();
        Ok(Self {
            classical: SoftKeySigner::generate(subject.clone()),
            pqc: MlDsaSigner::generate(subject.clone())?,
            subject,
        })
    }

    /// Verifica AMBAS as componentes — falhar uma falha o híbrido.
    pub fn verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier as _;
        let (Some((pk_ec, pk_ml)), Some((sig_ec, sig_ml))) =
            (hybrid_split(public_key), hybrid_split(signature))
        else {
            return false;
        };
        let classical_ok = (|| {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk_ec).ok()?;
            let sig = Signature::from_slice(sig_ec).ok()?;
            vk.verify(data, &sig).ok()
        })()
        .is_some();
        classical_ok && MlDsaSigner::verify(pk_ml, data, sig_ml)
    }
}

impl InstitutionalSigner for HybridSigner {
    fn subject(&self) -> &str {
        &self.subject
    }

    fn sign_snapshot(&self, data: &[u8]) -> Result<InstitutionalSignature, CompError> {
        let c = self.classical.sign_snapshot(data)?;
        let p = self.pqc.sign_snapshot(data)?;
        Ok(InstitutionalSignature {
            subject: self.subject.clone(),
            signature: hybrid_encode(&c.signature, &p.signature),
            public_key_sec1: hybrid_encode(&c.public_key_sec1, &p.public_key_sec1),
        })
    }
}

/// Production signer whose key lives in an HSM / PKCS#11 token. Intentionally
/// not implemented in the open crate: the concrete provider is supplied by the
/// órgão's homologated build.
pub struct Pkcs11Signer {
    pub module_path: String,
    pub token_label: String,
    pub key_label: String,
    pub subject: String,
}

impl InstitutionalSigner for Pkcs11Signer {
    fn subject(&self) -> &str {
        &self.subject
    }

    fn sign_snapshot(&self, _data: &[u8]) -> Result<InstitutionalSignature, CompError> {
        Err(CompError::Unsupported(format!(
            "assinatura via HSM/PKCS#11 (módulo '{}', token '{}', chave '{}') exige o \
             provider homologado do órgão — não embutido no core aberto",
            self.module_path, self.token_label, self.key_label
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    #[test]
    fn soft_signer_produces_verifiable_signature() {
        let s = SoftKeySigner::generate("AGU");
        let data = b"commitment-snapshot";
        let sig = s.sign_snapshot(data).unwrap();
        assert_eq!(sig.subject, "AGU");
        let vk = VerifyingKey::from_sec1_bytes(&sig.public_key_sec1).unwrap();
        let parsed = Signature::from_slice(&sig.signature).unwrap();
        assert!(vk.verify(data, &parsed).is_ok());
    }

    #[test]
    fn mldsa_signer_roundtrip_fips204() {
        // C2.5: assinatura pós-quântica verificável (ML-DSA-44, FIPS 204).
        let s = MlDsaSigner::generate("AGU").unwrap();
        let data = b"commitment-snapshot";
        let sig = s.sign_snapshot(data).unwrap();
        assert_eq!(sig.subject, "AGU");
        assert!(MlDsaSigner::verify(
            &sig.public_key_sec1,
            data,
            &sig.signature
        ));
        // Adulterar o dado OU a assinatura falha a verificação.
        assert!(!MlDsaSigner::verify(
            &sig.public_key_sec1,
            b"outro",
            &sig.signature
        ));
        let mut bad = sig.signature.clone();
        bad[0] ^= 0xFF;
        assert!(!MlDsaSigner::verify(&sig.public_key_sec1, data, &bad));
    }

    #[test]
    fn hybrid_signer_requires_both_schemes() {
        // Transição PQC: ECDSA + ML-DSA; quebrar UMA componente falha o híbrido.
        let s = HybridSigner::generate("AGU").unwrap();
        let data = b"commitment-snapshot";
        let sig = s.sign_snapshot(data).unwrap();
        assert!(HybridSigner::verify(
            &sig.public_key_sec1,
            data,
            &sig.signature
        ));
        assert!(!HybridSigner::verify(
            &sig.public_key_sec1,
            b"outro",
            &sig.signature
        ));
        // Corromper a componente ML-DSA (cauda) derruba o conjunto.
        let mut bad = sig.signature.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(!HybridSigner::verify(&sig.public_key_sec1, data, &bad));
        // Corromper a componente ECDSA (cabeça, após o prefixo de 2 bytes) idem.
        let mut bad2 = sig.signature.clone();
        bad2[2] ^= 0xFF;
        assert!(!HybridSigner::verify(&sig.public_key_sec1, data, &bad2));
    }

    #[test]
    fn pkcs11_signer_is_explicitly_unsupported() {
        let s = Pkcs11Signer {
            module_path: "/usr/lib/libcs.so".into(),
            token_label: "AGU-HSM".into(),
            key_label: "agu-sign".into(),
            subject: "AGU".into(),
        };
        assert!(matches!(
            s.sign_snapshot(b"x"),
            Err(CompError::Unsupported(_))
        ));
    }
}
