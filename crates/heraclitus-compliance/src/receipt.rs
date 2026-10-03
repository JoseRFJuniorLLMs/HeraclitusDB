//! Legal receipts — what an auditor actually keeps.
//!
//! For each anchored watermark we persist the raw token (`<lsn>.tst`) plus a
//! human/machine-readable line in `manifest.jsonl`. The manifest records the
//! recomputable commitment (watermark LSN, aggregate root, SHA-256 imprint) so
//! verification needs only the receipt + the immutable log.

use crate::commit::Commitment;
use crate::CompError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// What this build has actually verified about a timestamp token.
///
/// [`ExternalTokenVerified`] existe desde que o verificador CMS/X.509 passou a
/// existir (SPEC-0046 §9), e **só** um cliente que verifique o token contra um
/// trust store povoado o pode produzir. Continua a não haver variante que
/// afirme conformidade legal plena: falta a consulta de revogação e a prova de
/// interoperabilidade com uma ACT credenciada.
///
/// Manifestos antigos desserializam para [`LegacyUnverified`], de forma a que
/// um campo em falta nunca promova evidência histórica em silêncio.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TimestampValidationState {
    /// A self-contained token issued and verified by the in-process dev TSA.
    /// It proves the development flow only; it is not an ICP-Brasil timestamp.
    DevelopmentOnly,
    /// A token received from an external endpoint, with no CMS/X.509 trust
    /// validation yet. Its commitment can still be recomputed locally.
    ExternalTokenUnvalidated,
    /// Um `TimeStampToken` RFC 3161 externo cuja cadeia CMS/X.509 foi validada
    /// contra uma âncora que o **operador** instalou (SPEC-0046 §9/§11), com
    /// `messageImprint` e nonce confirmados.
    ///
    /// Este estado só pode ser produzido por um cliente que tenha um
    /// [`crate::icp::IcpBrasilTimestampVerifier`] instalado e que tenha
    /// verificado o token ANTES de o devolver. Não diz que a revogação foi
    /// consultada — isso está em `revocation_checked`, no resultado da
    /// verificação, e um recibo neste estado pode ter sido emitido por um
    /// certificado revogado dentro da validade.
    ExternalTokenVerified,
    /// A receipt written before validation state was persisted.
    #[default]
    LegacyUnverified,
}

impl TimestampValidationState {
    /// Stable, human-readable state for CLI and audit output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::DevelopmentOnly => "somente desenvolvimento",
            Self::ExternalTokenUnvalidated => "token externo não validado",
            Self::ExternalTokenVerified => "token externo verificado (cadeia ICP)",
            Self::LegacyUnverified => "recibo legado não validado",
        }
    }
}

/// Timestamp metadata known when an evidence receipt is written.
///
/// This intentionally separates receipt creation time from a validated
/// authority time. The latter must remain `None` unless the token verifier
/// extracted and verified it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampEvidence {
    /// Local receipt-creation time, or the verified development token time.
    pub recorded_unix_ms: u64,
    /// Authority `genTime` only after successful verification.
    pub authority_gen_unix_ms: Option<u64>,
    /// Strength of the available verification.
    pub validation_state: TimestampValidationState,
    /// Política efectivamente lida do token depois da verificação externa.
    pub tsa_policy_oid: Option<String>,
}

/// One notarized anchor, serialized into the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegalReceipt {
    /// Watermark LSN this receipt covers (every event with `lsn <= this`).
    pub lsn: u64,
    /// Sealed segments folded into the commitment.
    pub segments: u64,
    /// Aggregate blake3 Merkle root (hex).
    pub root_hex: String,
    /// SHA-256 imprint that was timestamped (hex).
    pub imprint_hex: String,
    /// Time recorded in this receipt (ms since Unix epoch).
    ///
    /// For a verified dev token this equals its embedded time. For an external
    /// unvalidated token it is the local receipt-creation time, not a claimed
    /// authority `genTime`. Kept under the historic field name for manifest
    /// compatibility; consumers must inspect `validation_state`.
    pub gen_unix_ms: u64,
    /// Time asserted by the token authority, but only when this build could
    /// validate it. `None` never means "unknown but valid".
    #[serde(default)]
    pub authority_gen_unix_ms: Option<u64>,
    /// Verification state available when this receipt was written.
    #[serde(default)]
    pub validation_state: TimestampValidationState,
    /// Que família de raízes foi dobrada no compromisso (SPEC-0050 §7.2).
    ///
    /// O default **nomeado** faz um recibo antigo — escrito antes de o HRKL v6
    /// existir — reler-se como `legacy-physical`, que é exactamente o que era.
    /// Um `#[serde(default)]` simples daria a string vazia, e um verificador
    /// teria de adivinhar o que "" significa; sem qualquer default, um recibo
    /// válido de 2025 passaria a falhar a desserialização e a prova mais antiga
    /// do sistema seria a primeira a partir-se.
    #[serde(default = "dominio_legado")]
    pub commitment_domain: String,
    /// Authority/policy name.
    pub policy: String,
    /// Política RFC 3161 efectivamente assinada pela ACT. Recibos antigos e
    /// tokens não validados ficam `None`.
    #[serde(default)]
    pub tsa_policy_oid: Option<String>,
    /// Token file name relative to the receipts dir.
    pub token_file: String,
}

/// Lowercase hex of a byte slice (no external dep).
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join("manifest.jsonl")
}

fn token_name(lsn: u64) -> String {
    format!("{lsn:020}.tst")
}

/// Grava o token num ficheiro **novo**, nunca sobre um que já exista.
///
/// Auditoria recursiva 2026-10-03, iteração 2: o worker arranca sempre com
/// `last_lsn = 0`, por isso depois de um reinício sem segmento novo selado
/// volta a ancorar a mesma marca d'água — e o `heraclitus anchor` corrido
/// duas vezes sobre uma base quieta faz o mesmo. Com `std::fs::write` o
/// segundo carimbo truncava `<lsn>.tst` e destruía o primeiro, que é a prova
/// mais antiga do estado; a linha antiga do manifesto ficava a apontar para
/// um token que já não a descreve (outro `genTime`, ou até outro formato se o
/// modo da ACT mudou entre arranques — falso alarme de adulteração). E a
/// escrita não era atómica: um crash a meio truncava um recibo já válido.
///
/// O primeiro token de cada LSN mantém o nome histórico; os seguintes ganham
/// um sufixo `-N`. `create_new` garante que nenhum ficheiro existente é
/// tocado: um crash a meio deixa, quando muito, um ficheiro novo parcial que
/// nenhuma linha do manifesto referencia (a linha só é escrita depois).
fn write_token_new(dir: &Path, lsn: u64, token: &[u8]) -> Result<String, CompError> {
    use std::io::Write;
    for n in 0u32.. {
        let name = if n == 0 {
            token_name(lsn)
        } else {
            format!("{lsn:020}-{n}.tst")
        };
        let mut f = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(&name))
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        };
        f.write_all(token)?;
        f.sync_all()?;
        return Ok(name);
    }
    unreachable!("u32 esgotado a procurar um nome livre para o token")
}

/// Persist a token + manifest entry, returning the receipt.
/// O domínio que um recibo sem o campo necessariamente usou: antes do HRKL v6
/// só existiam raízes físicas.
fn dominio_legado() -> String {
    crate::commit::CommitmentDomain::LegacyPhysical
        .as_str()
        .to_string()
}

pub fn persist(
    dir: impl AsRef<Path>,
    commitment: &Commitment,
    imprint: &[u8; 32],
    policy: &str,
    timestamp: TimestampEvidence,
    token: &[u8],
) -> Result<LegalReceipt, CompError> {
    let dir = dir.as_ref();
    std::fs::create_dir_all(dir)?;

    let token_file = write_token_new(dir, commitment.lsn, token)?;

    let receipt = LegalReceipt {
        lsn: commitment.lsn,
        segments: commitment.segments,
        root_hex: to_hex(&commitment.root),
        imprint_hex: to_hex(imprint),
        commitment_domain: commitment.domain.as_str().to_string(),
        gen_unix_ms: timestamp.recorded_unix_ms,
        authority_gen_unix_ms: timestamp.authority_gen_unix_ms,
        validation_state: timestamp.validation_state,
        policy: policy.to_string(),
        tsa_policy_oid: timestamp.tsa_policy_oid,
        token_file,
    };

    let mut line = serde_json::to_string(&receipt)?;
    line.push('\n');
    // append-only manifest, mirroring the log's own ethos
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(manifest_path(dir))?;
    f.write_all(line.as_bytes())?;

    Ok(receipt)
}

/// Read all receipts from the manifest, oldest first.
pub fn load_manifest(dir: impl AsRef<Path>) -> Result<Vec<LegalReceipt>, CompError> {
    let path = manifest_path(dir.as_ref());
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str(line)?);
    }
    Ok(out)
}

/// Read the raw token bytes referenced by a receipt.
pub fn read_token(dir: impl AsRef<Path>, receipt: &LegalReceipt) -> Result<Vec<u8>, CompError> {
    Ok(std::fs::read(dir.as_ref().join(&receipt.token_file))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Um recibo escrito antes de o HRKL v6 existir não tem o campo do
    /// domínio. Tem de continuar a ler-se — e a ler-se como o que era.
    #[test]
    fn um_recibo_sem_dominio_le_se_como_legado() {
        let json = r#"{
            "lsn": 42,
            "segments": 2,
            "root_hex": "0303030303030303030303030303030303030303030303030303030303030303",
            "imprint_hex": "0404040404040404040404040404040404040404040404040404040404040404",
            "gen_unix_ms": 1700000000000,
            "policy": "ACT-antiga",
            "token_file": "0000000000000042.tsr"
        }"#;
        let r: LegalReceipt = serde_json::from_str(json).unwrap();
        assert_eq!(r.commitment_domain, "legacy-physical");
        assert_eq!(r.lsn, 42);
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn persist_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let c = Commitment {
            lsn: 42,
            root: [3u8; 32],
            segments: 2,
            domain: crate::commit::CommitmentDomain::LegacyPhysical,
        };
        let imprint = [4u8; 32];
        let r = persist(
            dir.path(),
            &c,
            &imprint,
            "ACT-dev",
            TimestampEvidence {
                recorded_unix_ms: 1700,
                authority_gen_unix_ms: Some(1700),
                validation_state: TimestampValidationState::DevelopmentOnly,
                tsa_policy_oid: None,
            },
            b"token-bytes",
        )
        .unwrap();
        assert_eq!(r.lsn, 42);
        let all = load_manifest(dir.path()).unwrap();
        assert_eq!(all, vec![r.clone()]);
        assert_eq!(read_token(dir.path(), &r).unwrap(), b"token-bytes");
    }

    /// Auditoria recursiva 2026-10-03, iteração 2: reancorar a mesma marca
    /// d'água (reinício sem segmento novo, ou `anchor` repetido) não pode
    /// destruir o token anterior. Cada linha do manifesto tem de continuar a
    /// ler exactamente o token que tinha quando foi escrita.
    #[test]
    fn reancorar_o_mesmo_lsn_nao_destroi_o_token_anterior() {
        let dir = tempfile::tempdir().unwrap();
        let c = Commitment {
            lsn: 42,
            root: [3u8; 32],
            segments: 2,
            domain: crate::commit::CommitmentDomain::LegacyPhysical,
        };
        let imprint = [4u8; 32];
        let ev = |t: u64| TimestampEvidence {
            recorded_unix_ms: t,
            authority_gen_unix_ms: Some(t),
            validation_state: TimestampValidationState::DevelopmentOnly,
            tsa_policy_oid: None,
        };
        let r1 = persist(dir.path(), &c, &imprint, "ACT-dev", ev(1), b"token-t1").unwrap();
        let r2 = persist(dir.path(), &c, &imprint, "ACT-dev", ev(2), b"token-t2").unwrap();
        let r3 = persist(dir.path(), &c, &imprint, "ACT-dev", ev(3), b"token-t3").unwrap();

        assert_ne!(r1.token_file, r2.token_file);
        assert_ne!(r2.token_file, r3.token_file);
        assert_eq!(
            r1.token_file,
            token_name(42),
            "o primeiro mantém o nome histórico"
        );

        let all = load_manifest(dir.path()).unwrap();
        assert_eq!(all, vec![r1, r2, r3]);
        assert_eq!(read_token(dir.path(), &all[0]).unwrap(), b"token-t1");
        assert_eq!(read_token(dir.path(), &all[1]).unwrap(), b"token-t2");
        assert_eq!(read_token(dir.path(), &all[2]).unwrap(), b"token-t3");
    }

    #[test]
    fn legacy_manifest_entry_is_never_promoted() {
        let legacy = r#"{
            "lsn": 42,
            "segments": 2,
            "root_hex": "aa",
            "imprint_hex": "bb",
            "gen_unix_ms": 123,
            "policy": "ACT-antiga",
            "token_file": "00000000000000000042.tst"
        }"#;
        let receipt: LegalReceipt = serde_json::from_str(legacy).unwrap();
        assert_eq!(
            receipt.validation_state,
            TimestampValidationState::LegacyUnverified
        );
        assert_eq!(receipt.authority_gen_unix_ms, None);
        assert_eq!(receipt.tsa_policy_oid, None);
    }
}
