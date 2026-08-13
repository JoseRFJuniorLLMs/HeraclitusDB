//! Verification of timestamp tokens.
//!
//! For the dev authority ([`crate::tsa::LocalTsa`]) this is a complete, offline
//! check: signature → imprint → time. For a real ICP-Brasil `.tst` (CMS
//! `TimeStampToken`) the production verifier must additionally chain the signer
//! certificate to the ICP-Brasil roots and honour the genTime accuracy — that
//! needs the órgão's trust anchors and is the next milestone.

use crate::rfc3161::OID_SHA256;
use crate::tsa::{DevToken, DevTstInfo};
use crate::CompError;
use der::Decode;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

/// Outcome of a successful verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedTime {
    /// Time asserted by the authority (ms since Unix epoch).
    pub gen_unix_ms: u64,
}

/// `true` se os bytes são um token da autoridade de DESENVOLVIMENTO. Serve para
/// distinguir "não consigo validar este formato" (um `.tst` RFC 3161 real) de
/// "a assinatura não confere" (adulteração) — confundir os dois fazia a
/// verificação reportar fraude em todos os recibos legítimos de produção.
pub fn is_dev_token(token_der: &[u8]) -> bool {
    DevToken::from_der(token_der).is_ok()
}

/// Verify a dev token against the expected SHA-256 imprint: the signature must
/// be valid under the embedded TSA key, the hash algorithm must be SHA-256, and
/// the stamped imprint must equal `expected_imprint`.
///
/// ⚠️ **Sem âncora de confiança.** A chave que valida a assinatura vem DE DENTRO
/// do próprio token (`token.tsa_key`), por isso quem forjar um par de chaves
/// produz um recibo que passa aqui. Isto deteta corrupção e adulteração
/// acidental, NÃO um adversário. O `LocalTsa` gera uma chave nova a cada
/// arranque (nem sequer há âncora estável para fixar) — é uma autoridade de
/// desenvolvimento. Prova forense a sério exige encadear o certificado do
/// signatário às raízes ICP-Brasil, que é o milestone seguinte.
pub fn verify_dev_token(
    token_der: &[u8],
    expected_imprint: &[u8; 32],
) -> Result<VerifiedTime, CompError> {
    let token = DevToken::from_der(token_der)?;
    let vk = VerifyingKey::from_sec1_bytes(token.tsa_key.as_bytes())
        .map_err(|e| CompError::Verify(format!("chave da TSA inválida: {e}")))?;
    let sig = Signature::from_slice(token.signature.as_bytes())
        .map_err(|e| CompError::Verify(format!("assinatura malformada: {e}")))?;
    vk.verify(token.tst_info.as_bytes(), &sig)
        .map_err(|_| CompError::Verify("assinatura do carimbo não confere".into()))?;

    let info = DevTstInfo::from_der(token.tst_info.as_bytes())?;
    if info.message_imprint.hash_algorithm.algorithm != OID_SHA256 {
        return Err(CompError::Verify(
            "algoritmo de hash inesperado no carimbo (esperado SHA-256)".into(),
        ));
    }
    if info.message_imprint.digest_bytes() != expected_imprint {
        return Err(CompError::Verify(
            "imprint do carimbo não corresponde ao commitment recalculado".into(),
        ));
    }
    Ok(VerifiedTime {
        gen_unix_ms: info.gen_unix_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tsa::{LocalTsa, TsaClient};

    #[test]
    fn roundtrip_verifies_and_tamper_fails() {
        let tsa = LocalTsa::generate("ACT-dev");
        let imprint = [0x11u8; 32];
        let token = tsa.stamp(&imprint).unwrap();

        // correct imprint verifies
        assert!(verify_dev_token(&token, &imprint).is_ok());

        // a different imprint (i.e. a different commitment) is rejected
        let other = [0x22u8; 32];
        assert!(verify_dev_token(&token, &other).is_err());

        // a token from a different TSA over the same imprint still verifies
        // against ITS key (signature is self-contained), proving the check is
        // on the embedded key + imprint, not a global secret
        let tsa2 = LocalTsa::generate("ACT-dev-2");
        let token2 = tsa2.stamp(&imprint).unwrap();
        assert!(verify_dev_token(&token2, &imprint).is_ok());

        // flipping a byte in the token breaks verification
        let mut bad = token.clone();
        let n = bad.len();
        bad[n / 2] ^= 0xFF;
        assert!(verify_dev_token(&bad, &imprint).is_err());
    }
}
