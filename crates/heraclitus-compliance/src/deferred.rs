//! Deferred timestamp anchoring for disconnected environments.
//!
//! Only a cryptographic commitment crosses the air-gap. Raw episodes, event
//! contents and attributes are never part of the request schema. Both export
//! and response are institutionally signed and bound to exact trust-policy
//! key digests. External RFC 3161 tokens remain explicitly unvalidated until
//! the production CMS/X.509/ICP-Brasil verifier is available.

use crate::commit::{aggregate_root, CommitmentDomain};
use crate::model_bundle::BundleSignatureScheme;
use crate::receipt::TimestampValidationState;
use crate::signer::{HybridSigner, MlDsaSigner};
use crate::{verify_dev_token, CompError, InstitutionalSigner, TsaClient};
use heraclitus_core::runtime::SegmentState;
use heraclitus_core::{Episode, EventKind, Lsn};
use heraclitus_log::{AnyLog, EpisodeLog};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

const ANCHOR_EVENT: &str = "ComplianceEvidenceAnchor";
const EXPORT_FILE: &str = "deferred-anchor-request.json";
const RESPONSE_FILE: &str = "deferred-anchor-response.json";
const MAX_TRANSFER_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum DeferredAnchorError {
    #[error("ancoragem diferida inválida: {0}")]
    Invalid(String),
    #[error("assinatura de transferência inválida: {0}")]
    Signature(String),
    #[error("E/S da transferência: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialização da transferência: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("assinador/ACT: {0}")]
    Compliance(#[from] CompError),
    #[error("log de ancoragem: {0}")]
    Storage(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCommitment {
    pub schema_version: u16,
    pub lsn_start: Lsn,
    pub lsn_end: Lsn,
    pub merkle_root: [u8; 32],
    pub state_digest: [u8; 32],
    pub created_at_hlc: u64,
    pub commitment_domain: String,
    pub segments: u64,
}

impl EvidenceCommitment {
    pub fn from_log<L: EpisodeLog + ?Sized>(
        log: &L,
        lsn_start: Lsn,
        lsn_end: Lsn,
        created_at_hlc: u64,
    ) -> Result<Self, DeferredAnchorError> {
        if lsn_start > lsn_end {
            return Err(DeferredAnchorError::Invalid(
                "intervalo LSN invertido".into(),
            ));
        }
        let manifest = log.manifest();
        let (ranges, roots, domain): (Vec<(Lsn, Lsn)>, Vec<[u8; 32]>, CommitmentDomain) =
            if !manifest.segments_v2.is_empty() {
                let mut segments: Vec<_> = manifest
                    .segments_v2
                    .iter()
                    .filter(|segment| {
                        segment.first_lsn >= lsn_start
                            && segment.last_lsn <= lsn_end
                            && segment.logical_root != [0; 32]
                    })
                    .collect();
                segments.sort_by_key(|segment| segment.first_lsn);
                (
                    segments
                        .iter()
                        .map(|segment| (segment.first_lsn, segment.last_lsn))
                        .collect(),
                    segments
                        .iter()
                        .map(|segment| segment.logical_root)
                        .collect(),
                    CommitmentDomain::V6Logical,
                )
            } else {
                let mut segments: Vec<_> = manifest
                    .segments
                    .iter()
                    .filter(|segment| {
                        segment.state == SegmentState::Frozen
                            && segment.first_lsn >= lsn_start
                            && segment.last_lsn <= lsn_end
                            && segment.payload_hash != [0; 32]
                    })
                    .collect();
                segments.sort_by_key(|segment| segment.first_lsn);
                (
                    segments
                        .iter()
                        .map(|segment| (segment.first_lsn, segment.last_lsn))
                        .collect(),
                    segments
                        .iter()
                        .map(|segment| segment.payload_hash)
                        .collect(),
                    CommitmentDomain::LegacyPhysical,
                )
            };
        validate_exact_segment_range(&ranges, lsn_start, lsn_end)?;
        let merkle_root = aggregate_root(&roots);
        let state_digest = evidence_state_digest(
            lsn_start,
            lsn_end,
            &merkle_root,
            roots.len() as u64,
            domain.as_str(),
            created_at_hlc,
        );
        Ok(Self {
            schema_version: 1,
            lsn_start,
            lsn_end,
            merkle_root,
            state_digest,
            created_at_hlc,
            commitment_domain: domain.as_str().into(),
            segments: roots.len() as u64,
        })
    }

    pub fn validate(&self) -> Result<(), DeferredAnchorError> {
        if self.schema_version != 1 || self.lsn_start > self.lsn_end || self.segments == 0 {
            return Err(DeferredAnchorError::Invalid(
                "EvidenceCommitment possui versão, intervalo ou segmentos inválidos".into(),
            ));
        }
        if !matches!(
            self.commitment_domain.as_str(),
            "legacy-physical" | "hrkl-v6-logical"
        ) {
            return Err(DeferredAnchorError::Invalid(
                "domínio de commitment desconhecido".into(),
            ));
        }
        let expected = evidence_state_digest(
            self.lsn_start,
            self.lsn_end,
            &self.merkle_root,
            self.segments,
            &self.commitment_domain,
            self.created_at_hlc,
        );
        if expected != self.state_digest {
            return Err(DeferredAnchorError::Invalid(
                "state_digest não corresponde ao commitment".into(),
            ));
        }
        Ok(())
    }

    /// RFC 3161 imprint. It binds the exact range, root, state and domain.
    pub fn message_imprint_sha256(&self) -> Result<[u8; 32], DeferredAnchorError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"heraclitus/deferred-evidence-commitment/v1\0");
        hash.update(canonical_bytes(self)?);
        Ok(hash.finalize().into())
    }
}

fn validate_exact_segment_range(
    ranges: &[(Lsn, Lsn)],
    lsn_start: Lsn,
    lsn_end: Lsn,
) -> Result<(), DeferredAnchorError> {
    if ranges.is_empty()
        || ranges.first().map(|range| range.0) != Some(lsn_start)
        || ranges.last().map(|range| range.1) != Some(lsn_end)
    {
        return Err(DeferredAnchorError::Invalid(
            "intervalo deve coincidir exatamente com segmentos selados".into(),
        ));
    }
    for pair in ranges.windows(2) {
        if pair[0].1.checked_add(1) != Some(pair[1].0) {
            return Err(DeferredAnchorError::Invalid(
                "intervalo possui lacuna entre segmentos selados".into(),
            ));
        }
    }
    Ok(())
}

fn evidence_state_digest(
    lsn_start: Lsn,
    lsn_end: Lsn,
    root: &[u8; 32],
    segments: u64,
    domain: &str,
    created_at_hlc: u64,
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"heraclitus/evidence-state/v1\0");
    hash.update(&lsn_start.to_be_bytes());
    hash.update(&lsn_end.to_be_bytes());
    hash.update(root);
    hash.update(&segments.to_be_bytes());
    hash.update(&(domain.len() as u64).to_be_bytes());
    hash.update(domain.as_bytes());
    hash.update(&created_at_hlc.to_be_bytes());
    *hash.finalize().as_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredAnchorRequest {
    pub request_id: String,
    pub commitment: EvidenceCommitment,
    pub previous_anchor_digest: Option<[u8; 32]>,
    pub export_digest: [u8; 32],
}

impl DeferredAnchorRequest {
    pub fn new(
        commitment: EvidenceCommitment,
        previous_anchor_digest: Option<[u8; 32]>,
    ) -> Result<Self, DeferredAnchorError> {
        commitment.validate()?;
        let export_digest = request_payload_digest(&commitment, previous_anchor_digest)?;
        Ok(Self {
            request_id: format!("deferred-{}", hex_digest(&export_digest)),
            commitment,
            previous_anchor_digest,
            export_digest,
        })
    }

    pub fn validate(&self) -> Result<(), DeferredAnchorError> {
        self.commitment.validate()?;
        let expected = request_payload_digest(&self.commitment, self.previous_anchor_digest)?;
        if expected != self.export_digest
            || self.request_id != format!("deferred-{}", hex_digest(&expected))
        {
            return Err(DeferredAnchorError::Invalid(
                "request_id/export_digest não correspondem ao payload".into(),
            ));
        }
        Ok(())
    }
}

fn request_payload_digest(
    commitment: &EvidenceCommitment,
    previous_anchor_digest: Option<[u8; 32]>,
) -> Result<[u8; 32], DeferredAnchorError> {
    #[derive(Serialize)]
    struct Material<'a> {
        domain: &'static str,
        commitment: &'a EvidenceCommitment,
        previous_anchor_digest: Option<[u8; 32]>,
    }
    Ok(*blake3::hash(&canonical_bytes(&Material {
        domain: "heraclitus/deferred-request/v1",
        commitment,
        previous_anchor_digest,
    })?)
    .as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredSignature {
    pub scheme: BundleSignatureScheme,
    pub subject: String,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDeferredAnchorRequest {
    pub request: DeferredAnchorRequest,
    pub signature: DeferredSignature,
}

impl SignedDeferredAnchorRequest {
    pub fn sign(
        request: DeferredAnchorRequest,
        signer: &dyn InstitutionalSigner,
        scheme: BundleSignatureScheme,
    ) -> Result<Self, DeferredAnchorError> {
        request.validate()?;
        let signature = signer.sign_snapshot(&canonical_bytes(&request)?)?;
        Ok(Self {
            request,
            signature: DeferredSignature {
                scheme,
                subject: signature.subject,
                signature: signature.signature,
                public_key: signature.public_key_sec1,
            },
        })
    }

    pub fn write_export(
        &self,
        directory: impl AsRef<Path>,
    ) -> Result<PathBuf, DeferredAnchorError> {
        self.request.validate()?;
        write_transfer_file(directory.as_ref(), EXPORT_FILE, self)
    }

    pub fn read_export(path: impl AsRef<Path>) -> Result<Self, DeferredAnchorError> {
        read_transfer_file(path.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredTransferPolicy {
    pub policy_id: String,
    pub version: String,
    pub approved_export_key_digests: BTreeSet<[u8; 32]>,
    pub approved_response_key_digests: BTreeSet<[u8; 32]>,
    pub allowed_signature_schemes: BTreeSet<BundleSignatureScheme>,
    pub max_timestamp_token_bytes: usize,
}

impl DeferredTransferPolicy {
    pub fn validate(&self) -> Result<(), DeferredAnchorError> {
        if self.policy_id.trim().is_empty()
            || self.version.trim().is_empty()
            || self.approved_export_key_digests.is_empty()
            || self.approved_response_key_digests.is_empty()
            || self.allowed_signature_schemes.is_empty()
            || self.max_timestamp_token_bytes == 0
            || self.max_timestamp_token_bytes > MAX_TRANSFER_BYTES
        {
            return Err(DeferredAnchorError::Invalid(
                "política de transferência incompleta ou insegura".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredAnchorResponse {
    pub request_id: String,
    pub export_digest: [u8; 32],
    pub commitment_imprint: [u8; 32],
    pub timestamp_token: Vec<u8>,
    /// Rótulo humano do cliente/autoridade, para operação e logs.
    pub tsa_policy: String,
    /// OID efectivamente lido do `TSTInfo` depois de validar o token. Ausente
    /// em respostas antigas e em tokens que não foram validados.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa_policy_oid: Option<String>,
    pub validation_state: TimestampValidationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDeferredAnchorResponse {
    pub response: DeferredAnchorResponse,
    pub signature: DeferredSignature,
}

impl SignedDeferredAnchorResponse {
    pub fn write_response(
        &self,
        directory: impl AsRef<Path>,
    ) -> Result<PathBuf, DeferredAnchorError> {
        write_transfer_file(directory.as_ref(), RESPONSE_FILE, self)
    }

    pub fn read_response(path: impl AsRef<Path>) -> Result<Self, DeferredAnchorError> {
        read_transfer_file(path.as_ref())
    }
}

/// Connected-zone operation. The request signature is verified before the ACT
/// is called, and the returned token is signed for controlled import.
pub fn stamp_deferred_request(
    signed_request: &SignedDeferredAnchorRequest,
    policy: &DeferredTransferPolicy,
    tsa: &dyn TsaClient,
    response_signer: &dyn InstitutionalSigner,
    response_scheme: BundleSignatureScheme,
) -> Result<SignedDeferredAnchorResponse, DeferredAnchorError> {
    policy.validate()?;
    verify_transfer_signature(
        &signed_request.signature,
        &canonical_bytes(&signed_request.request)?,
        &policy.approved_export_key_digests,
        &policy.allowed_signature_schemes,
    )?;
    signed_request.request.validate()?;
    if !policy.allowed_signature_schemes.contains(&response_scheme) {
        return Err(DeferredAnchorError::Signature(
            "esquema do assinador de resposta não permitido".into(),
        ));
    }
    let imprint = signed_request.request.commitment.message_imprint_sha256()?;
    let token = tsa.stamp(&imprint)?;
    if token.is_empty() || token.len() > policy.max_timestamp_token_bytes {
        return Err(DeferredAnchorError::Invalid(
            "token de timestamp vazio ou acima do limite".into(),
        ));
    }
    let validation_state = tsa.validation_state();
    let tsa_policy_oid = if validation_state == TimestampValidationState::ExternalTokenVerified {
        tsa.verified_policy_oid(&token, &imprint)
    } else {
        None
    };
    let response = DeferredAnchorResponse {
        request_id: signed_request.request.request_id.clone(),
        export_digest: signed_request.request.export_digest,
        commitment_imprint: imprint,
        timestamp_token: token,
        tsa_policy: tsa.policy_name().into(),
        tsa_policy_oid,
        validation_state,
    };
    let signature = response_signer.sign_snapshot(&canonical_bytes(&response)?)?;
    let signed = SignedDeferredAnchorResponse {
        response,
        signature: DeferredSignature {
            scheme: response_scheme,
            subject: signature.subject,
            signature: signature.signature,
            public_key: signature.public_key_sec1,
        },
    };
    verify_transfer_signature(
        &signed.signature,
        &canonical_bytes(&signed.response)?,
        &policy.approved_response_key_digests,
        &policy.allowed_signature_schemes,
    )?;
    Ok(signed)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceAnchor {
    pub anchor_id: String,
    pub commitment: EvidenceCommitment,
    pub timestamp_token: Vec<u8>,
    pub tsa_policy_oid: Option<String>,
    pub validation_state: TimestampValidationState,
    pub previous_anchor_digest: Option<[u8; 32]>,
    pub anchor_digest: [u8; 32],
    pub request_id: String,
    pub transfer_policy_id: String,
    pub transfer_policy_version: String,
}

impl EvidenceAnchor {
    pub fn validate(&self) -> Result<(), DeferredAnchorError> {
        self.commitment.validate()?;
        let digest = evidence_anchor_digest(
            &self.commitment,
            &self.timestamp_token,
            self.tsa_policy_oid.as_deref(),
            self.validation_state,
            self.previous_anchor_digest,
            &self.request_id,
            &self.transfer_policy_id,
            &self.transfer_policy_version,
        )?;
        if digest != self.anchor_digest
            || self.anchor_id != format!("anchor-{}", hex_digest(&digest))
        {
            return Err(DeferredAnchorError::Invalid(
                "anchor_id/digest não correspondem ao anchor".into(),
            ));
        }
        Ok(())
    }

    fn to_episode(&self) -> Result<Episode, DeferredAnchorError> {
        self.validate()?;
        let mut episode = Episode::new(
            "gov-compliance",
            EventKind::Custom(ANCHOR_EVENT.into()),
            canonical_bytes(self)?,
        );
        episode
            .attrs
            .insert("compliance.generated".into(), "true".into());
        episode
            .attrs
            .insert("compliance.anchor_id".into(), self.anchor_id.clone());
        episode.attrs.insert(
            "compliance.anchor_digest".into(),
            hex_digest(&self.anchor_digest),
        );
        Ok(episode)
    }
}

/// Air-gap import operation. It verifies both transfer signatures and exact
/// request binding. A development token is cryptographically checked; an
/// external token is retained as `ExternalTokenUnvalidated`, never promoted.
/// Importa uma resposta que se declara verificada, confirmando-a contra as
/// âncoras **deste** órgão.
///
/// O verificador é o de quem IMPORTA, não o de quem carimbou: é a única forma
/// de a validação significar alguma coisa deste lado do air-gap. Um token que
/// não encadeie até uma âncora local é recusado mesmo que a resposta venha
/// assinada por uma chave aprovada — a assinatura de transferência prova quem
/// enviou, não que o carimbo valha.
pub fn import_deferred_response_with_verifier(
    signed_request: &SignedDeferredAnchorRequest,
    signed_response: &SignedDeferredAnchorResponse,
    policy: &DeferredTransferPolicy,
    verifier: &crate::icp::IcpBrasilTimestampVerifier,
) -> Result<EvidenceAnchor, DeferredAnchorError> {
    importar_resposta(signed_request, signed_response, policy, Some(verifier))
}

pub fn import_deferred_response(
    signed_request: &SignedDeferredAnchorRequest,
    signed_response: &SignedDeferredAnchorResponse,
    policy: &DeferredTransferPolicy,
) -> Result<EvidenceAnchor, DeferredAnchorError> {
    importar_resposta(signed_request, signed_response, policy, None)
}

fn importar_resposta(
    signed_request: &SignedDeferredAnchorRequest,
    signed_response: &SignedDeferredAnchorResponse,
    policy: &DeferredTransferPolicy,
    verifier: Option<&crate::icp::IcpBrasilTimestampVerifier>,
) -> Result<EvidenceAnchor, DeferredAnchorError> {
    policy.validate()?;
    signed_request.request.validate()?;
    verify_transfer_signature(
        &signed_request.signature,
        &canonical_bytes(&signed_request.request)?,
        &policy.approved_export_key_digests,
        &policy.allowed_signature_schemes,
    )?;
    verify_transfer_signature(
        &signed_response.signature,
        &canonical_bytes(&signed_response.response)?,
        &policy.approved_response_key_digests,
        &policy.allowed_signature_schemes,
    )?;
    let response = &signed_response.response;
    let imprint = signed_request.request.commitment.message_imprint_sha256()?;
    if response.request_id != signed_request.request.request_id
        || response.export_digest != signed_request.request.export_digest
        || response.commitment_imprint != imprint
        || response.timestamp_token.is_empty()
        || response.timestamp_token.len() > policy.max_timestamp_token_bytes
        || response.tsa_policy.trim().is_empty()
    {
        return Err(DeferredAnchorError::Invalid(
            "resposta não corresponde exatamente ao pedido exportado".into(),
        ));
    }
    let tsa_policy_oid = match response.validation_state {
        TimestampValidationState::DevelopmentOnly => {
            verify_dev_token(&response.timestamp_token, &imprint).map_err(|error| {
                DeferredAnchorError::Invalid(format!(
                    "token de desenvolvimento importado inválido: {error}"
                ))
            })?;
            if response.tsa_policy_oid.is_some() {
                return Err(DeferredAnchorError::Invalid(
                    "token de desenvolvimento não pode declarar política RFC 3161 verificada"
                        .into(),
                ));
            }
            None
        }
        TimestampValidationState::ExternalTokenUnvalidated
        | TimestampValidationState::LegacyUnverified => {
            if response.tsa_policy_oid.is_some() {
                return Err(DeferredAnchorError::Invalid(
                    "resposta sem validação externa não pode promover um rótulo a OID verificado"
                        .into(),
                ));
            }
            None
        }
        // A resposta vem de FORA da fronteira de confiança — é exactamente a
        // parte contra a qual o air-gap existe. Que ela se declare
        // "verificada" é uma alegação de quem carimbou, não um facto que este
        // lado possa registar sem o confirmar.
        TimestampValidationState::ExternalTokenVerified => {
            let Some(v) = verifier else {
                return Err(DeferredAnchorError::Invalid(
                    "resposta importada declara-se verificada mas este importador não tem trust store: use `import_deferred_response_with_verifier` com as âncoras do órgão (§11) — aceitar gravaria um anchor cujo estado afirma uma validação que ninguém deste lado fez"
                        .into(),
                ));
            };
            // Sem nonce: o nonce do pedido ficou do outro lado do air-gap e
            // nunca atravessa. A frescura de um carimbo diferido não vem do
            // nonce — vem do `request_id` e do `export_digest`, já confrontados
            // acima contra o pedido original.
            let verificado = v
                .verify(&response.timestamp_token, &imprint, None, crate::now_unix_ms())
                .map_err(|e| {
                    DeferredAnchorError::Invalid(format!(
                        "resposta declara-se verificada mas o carimbo não confirma contra as âncoras deste órgão: {e}"
                    ))
                })?;
            let observado = verificado.policy_oid.to_string();
            match response.tsa_policy_oid.as_deref() {
                Some(declarado) if declarado == observado => Some(observado),
                Some(declarado) => {
                    return Err(DeferredAnchorError::Invalid(format!(
                        "resposta declara política `{declarado}` e o token verificado contém `{observado}`"
                    )))
                }
                None => {
                    return Err(DeferredAnchorError::Invalid(
                        "resposta ExternalTokenVerified sem tsa_policy_oid: estado verificado sem a política assinada"
                            .into(),
                    ))
                }
            }
        }
    };
    let previous_anchor_digest = signed_request.request.previous_anchor_digest;
    let anchor_digest = evidence_anchor_digest(
        &signed_request.request.commitment,
        &response.timestamp_token,
        tsa_policy_oid.as_deref(),
        response.validation_state,
        previous_anchor_digest,
        &response.request_id,
        &policy.policy_id,
        &policy.version,
    )?;
    Ok(EvidenceAnchor {
        anchor_id: format!("anchor-{}", hex_digest(&anchor_digest)),
        commitment: signed_request.request.commitment.clone(),
        timestamp_token: response.timestamp_token.clone(),
        tsa_policy_oid,
        validation_state: response.validation_state,
        previous_anchor_digest,
        anchor_digest,
        request_id: response.request_id.clone(),
        transfer_policy_id: policy.policy_id.clone(),
        transfer_policy_version: policy.version.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn evidence_anchor_digest(
    commitment: &EvidenceCommitment,
    timestamp_token: &[u8],
    tsa_policy_oid: Option<&str>,
    validation_state: TimestampValidationState,
    previous_anchor_digest: Option<[u8; 32]>,
    request_id: &str,
    transfer_policy_id: &str,
    transfer_policy_version: &str,
) -> Result<[u8; 32], DeferredAnchorError> {
    #[derive(Serialize)]
    struct Material<'a> {
        domain: &'static str,
        commitment: &'a EvidenceCommitment,
        timestamp_token_digest: [u8; 32],
        tsa_policy_oid: Option<&'a str>,
        validation_state: TimestampValidationState,
        previous_anchor_digest: Option<[u8; 32]>,
        request_id: &'a str,
        transfer_policy_id: &'a str,
        transfer_policy_version: &'a str,
    }
    Ok(*blake3::hash(&canonical_bytes(&Material {
        domain: "heraclitus/evidence-anchor/v1",
        commitment,
        timestamp_token_digest: *blake3::hash(timestamp_token).as_bytes(),
        tsa_policy_oid,
        validation_state,
        previous_anchor_digest,
        request_id,
        transfer_policy_id,
        transfer_policy_version,
    })?)
    .as_bytes())
}

fn verify_transfer_signature(
    signature: &DeferredSignature,
    payload: &[u8],
    approved_keys: &BTreeSet<[u8; 32]>,
    allowed_schemes: &BTreeSet<BundleSignatureScheme>,
) -> Result<(), DeferredAnchorError> {
    if signature.subject.trim().is_empty()
        || !allowed_schemes.contains(&signature.scheme)
        || !approved_keys.contains(blake3::hash(&signature.public_key).as_bytes())
    {
        return Err(DeferredAnchorError::Signature(
            "chave, sujeito ou esquema não aprovado".into(),
        ));
    }
    let valid = match signature.scheme {
        BundleSignatureScheme::P256Development => {
            VerifyingKey::from_sec1_bytes(&signature.public_key)
                .ok()
                .zip(Signature::from_slice(&signature.signature).ok())
                .is_some_and(|(key, signature)| key.verify(payload, &signature).is_ok())
        }
        BundleSignatureScheme::MlDsa44 => {
            MlDsaSigner::verify(&signature.public_key, payload, &signature.signature)
        }
        BundleSignatureScheme::HybridP256MlDsa44 => {
            HybridSigner::verify(&signature.public_key, payload, &signature.signature)
        }
    };
    if !valid {
        return Err(DeferredAnchorError::Signature(
            "assinatura criptográfica não confere".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeferredAnchorState {
    pub anchors: Vec<(Lsn, EvidenceAnchor)>,
    /// Ancoras que aterraram no log sem encadear com a anterior. Auditoria
    /// 2026-09-05 (A06): num log append-only uma bifurcacao nunca desaparece,
    /// logo ela e REGISTADA aqui em vez de abortar o replay, e publicada em
    /// `AnchorHealthSnapshot::deferred_anchor_forks` para nao ficar silenciosa.
    pub forks: Vec<(Lsn, EvidenceAnchor)>,
}

impl DeferredAnchorState {
    pub fn replay<L: EpisodeLog + ?Sized>(
        log: &L,
        as_of_lsn: Lsn,
    ) -> Result<Self, DeferredAnchorError> {
        let mut state = Self::default();
        let mut previous = None;
        // Janelado — ver `crate::varrimento`.
        crate::varrimento::por_episodio(
            log,
            log.head().min(as_of_lsn.saturating_add(1)),
            |error| DeferredAnchorError::Storage(error.to_string()),
            |lsn, episode| {
                if episode.kind.label() != ANCHOR_EVENT
                    || episode
                        .attrs
                        .get("compliance.generated")
                        .map(String::as_str)
                        != Some("true")
                {
                    return Ok(());
                }
                let anchor: EvidenceAnchor = serde_json::from_slice(&episode.content)?;
                anchor.validate()?;
                if anchor.previous_anchor_digest != previous {
                    // Auditoria 2026-09-05 (A06): uma bifurcacao NAO pode
                    // abortar o replay. O log e append-only: o episodio ofensor
                    // nunca desaparece, logo um `Err` aqui tornava o estado — e
                    // com ele o dashboard de compliance
                    // (`ComplianceDashboardSnapshot::build`) e a preparacao de
                    // novas ancoras (`deferred-anchor-prepare`, que chama
                    // `state()`) — irrecuperavel para SEMPRE. Mesmo raciocinio,
                    // e mesma escolha conservadora, da gemea
                    // `RegulatoryState::apply_range` para `hold_id` repetido:
                    // fica o PRIMEIRO ramo, e o intruso vai para `forks`.
                    tracing::warn!(
                        lsn,
                        anchor_id = %anchor.anchor_id,
                        "âncora não encadeia com a anterior; mantido o primeiro ramo e ignorada esta"
                    );
                    state.forks.push((lsn, anchor));
                    return Ok(());
                }
                previous = Some(anchor.anchor_digest);
                state.anchors.push((lsn, anchor));
                Ok(())
            },
        )?;
        Ok(state)
    }

    pub fn latest_digest(&self) -> Option<[u8; 32]> {
        self.anchors.last().map(|(_, anchor)| anchor.anchor_digest)
    }
}

#[derive(Clone)]
pub struct DeferredAnchorRegistry {
    log: Arc<AnyLog>,
    sink: Arc<dyn crate::ComplianceSink>,
}

impl DeferredAnchorRegistry {
    pub fn new(log: Arc<AnyLog>) -> Self {
        Self {
            sink: log.clone(),
            log,
        }
    }

    /// Redirige as escritas para o servidor (que as indexa ao vivo) em vez do
    /// log cru. Ver [`crate::ComplianceSink`].
    pub fn with_sink(mut self, sink: Arc<dyn crate::ComplianceSink>) -> Self {
        self.sink = sink;
        self
    }

    pub fn state(&self) -> Result<DeferredAnchorState, DeferredAnchorError> {
        DeferredAnchorState::replay(self.log.as_ref(), self.log.head())
    }

    pub fn persist(&self, anchor: EvidenceAnchor) -> Result<Lsn, DeferredAnchorError> {
        anchor.validate()?;
        // Auditoria 2026-09-05 (A06): a verificacao de encadeamento abaixo lia
        // o estado (`state()`, que reproduz o log inteiro) e so DEPOIS fazia o
        // append — uma janela TOCTOU larguissima. Duas importacoes concorrentes
        // (dois operadores, ou um simples retry do cliente: cada RPC admin cai
        // no seu proprio `spawn_blocking`) liam ambas o mesmo `latest_digest()`,
        // passavam ambas a verificacao e gravavam ambas, partindo a cadeia num
        // log de onde nada volta a sair.
        //
        // O lock e um `static` de processo, e nao um campo da estrutura, porque
        // `deferred_anchor_op` constroi um `DeferredAnchorRegistry` NOVO a cada
        // RPC: um `Mutex` por instancia nao serializaria nada. Serializar o
        // processo inteiro nao custa nada — importar uma ancora e uma operacao
        // administrativa, manual e rara — e nao ha reentrancia possivel:
        // `append_compliance` nunca volta a chamar `persist`.
        static CADEIA_DE_ANCORAS: Mutex<()> = Mutex::new(());
        let _guarda = CADEIA_DE_ANCORAS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = self.state()?;
        if let Some((lsn, existing)) = state
            .anchors
            .iter()
            .find(|(_, existing)| existing.anchor_id == anchor.anchor_id)
        {
            if existing == &anchor {
                return Ok(*lsn);
            }
            return Err(DeferredAnchorError::Invalid(
                "anchor_id reutilizado com conteúdo diferente".into(),
            ));
        }
        if anchor.previous_anchor_digest != state.latest_digest() {
            return Err(DeferredAnchorError::Invalid(
                "prev_anchor_digest não aponta para o último anchor persistido".into(),
            ));
        }
        self.sink
            .append_compliance(anchor.to_episode()?)
            .map_err(|error| DeferredAnchorError::Storage(error.to_string()))
    }
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, DeferredAnchorError> {
    Ok(serde_json::to_vec(value)?)
}

fn write_transfer_file<T: Serialize>(
    directory: &Path,
    file_name: &str,
    value: &T,
) -> Result<PathBuf, DeferredAnchorError> {
    let bytes = canonical_bytes(value)?;
    if bytes.len() > MAX_TRANSFER_BYTES {
        return Err(DeferredAnchorError::Invalid(
            "pacote de transferência acima do limite".into(),
        ));
    }
    std::fs::create_dir_all(directory)?;
    let path = directory.join(file_name);
    if path.exists() {
        if std::fs::read(&path)? != bytes {
            return Err(DeferredAnchorError::Invalid(format!(
                "retry diverge do pacote existente: {}",
                path.display()
            )));
        }
    } else {
        std::fs::write(&path, bytes)?;
    }
    Ok(path)
}

fn read_transfer_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, DeferredAnchorError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DeferredAnchorError::Invalid(
            "arquivo de transferência não regular".into(),
        ));
    }
    if metadata.len() as usize > MAX_TRANSFER_BYTES {
        return Err(DeferredAnchorError::Invalid(
            "arquivo de transferência acima do limite".into(),
        ));
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalTsa, SoftKeySigner};
    use heraclitus_core::{FsyncPolicy, StorageFormat};

    fn sample_commitment(start: Lsn, end: Lsn, created_at_hlc: u64) -> EvidenceCommitment {
        let merkle_root = [7; 32];
        EvidenceCommitment {
            schema_version: 1,
            lsn_start: start,
            lsn_end: end,
            merkle_root,
            state_digest: evidence_state_digest(
                start,
                end,
                &merkle_root,
                2,
                "hrkl-v6-logical",
                created_at_hlc,
            ),
            created_at_hlc,
            commitment_domain: "hrkl-v6-logical".into(),
            segments: 2,
        }
    }

    fn key_digest(signer: &SoftKeySigner) -> [u8; 32] {
        let signature = signer.sign_snapshot(b"key-discovery").unwrap();
        *blake3::hash(&signature.public_key_sec1).as_bytes()
    }

    fn policy(exporter: &SoftKeySigner, responder: &SoftKeySigner) -> DeferredTransferPolicy {
        DeferredTransferPolicy {
            policy_id: "air-gap-transfer".into(),
            version: "2026.1".into(),
            approved_export_key_digests: [key_digest(exporter)].into_iter().collect(),
            approved_response_key_digests: [key_digest(responder)].into_iter().collect(),
            allowed_signature_schemes: [BundleSignatureScheme::P256Development]
                .into_iter()
                .collect(),
            max_timestamp_token_bytes: 1024 * 1024,
        }
    }

    fn roundtrip(
        commitment: EvidenceCommitment,
        previous: Option<[u8; 32]>,
        exporter: &SoftKeySigner,
        responder: &SoftKeySigner,
        policy: &DeferredTransferPolicy,
    ) -> (SignedDeferredAnchorRequest, EvidenceAnchor) {
        let request = SignedDeferredAnchorRequest::sign(
            DeferredAnchorRequest::new(commitment, previous).unwrap(),
            exporter,
            BundleSignatureScheme::P256Development,
        )
        .unwrap();
        let response = stamp_deferred_request(
            &request,
            policy,
            &LocalTsa::generate("ACT-dev"),
            responder,
            BundleSignatureScheme::P256Development,
        )
        .unwrap();
        let anchor = import_deferred_response(&request, &response, policy).unwrap();
        (request, anchor)
    }

    #[test]
    fn signed_export_contains_commitment_but_no_raw_events() {
        let exporter = SoftKeySigner::generate("air-gap-exporter");
        let request = SignedDeferredAnchorRequest::sign(
            DeferredAnchorRequest::new(sample_commitment(0, 99, 42), None).unwrap(),
            &exporter,
            BundleSignatureScheme::P256Development,
        )
        .unwrap();
        let json = serde_json::to_value(&request).unwrap();
        assert!(json["request"]["commitment"]["merkle_root"].is_array());
        let text = serde_json::to_string(&json).unwrap();
        assert!(!text.contains("content"));
        assert!(!text.contains("attrs"));
        assert!(!text.contains("episodes"));

        let temp = tempfile::tempdir().unwrap();
        let path = request.write_export(temp.path()).unwrap();
        let loaded = SignedDeferredAnchorRequest::read_export(path).unwrap();
        assert_eq!(loaded, request);
    }

    #[test]
    fn controlled_roundtrip_binds_request_token_and_signers() {
        let exporter = SoftKeySigner::generate("air-gap-exporter");
        let responder = SoftKeySigner::generate("connected-zone");
        let policy = policy(&exporter, &responder);
        let (request, anchor) = roundtrip(
            sample_commitment(0, 99, 42),
            None,
            &exporter,
            &responder,
            &policy,
        );
        assert_eq!(anchor.request_id, request.request.request_id);
        assert_eq!(
            anchor.validation_state,
            TimestampValidationState::DevelopmentOnly
        );

        let impostor = SoftKeySigner::generate("impostor");
        let bad_request = SignedDeferredAnchorRequest::sign(
            DeferredAnchorRequest::new(sample_commitment(100, 199, 43), None).unwrap(),
            &impostor,
            BundleSignatureScheme::P256Development,
        )
        .unwrap();
        assert!(stamp_deferred_request(
            &bad_request,
            &policy,
            &LocalTsa::generate("ACT-dev"),
            &responder,
            BundleSignatureScheme::P256Development,
        )
        .is_err());
    }

    #[test]
    fn anchors_form_replayable_chain_and_reject_forks() {
        let exporter = SoftKeySigner::generate("air-gap-exporter");
        let responder = SoftKeySigner::generate("connected-zone");
        let policy = policy(&exporter, &responder);
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                StorageFormat::V6,
                temp.path().join("log"),
                4096,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let registry = DeferredAnchorRegistry::new(log.clone());
        let (_, first) = roundtrip(
            sample_commitment(0, 99, 42),
            None,
            &exporter,
            &responder,
            &policy,
        );
        let first_lsn = registry.persist(first.clone()).unwrap();
        assert_eq!(registry.persist(first.clone()).unwrap(), first_lsn);

        let (_, second) = roundtrip(
            sample_commitment(100, 199, 43),
            Some(first.anchor_digest),
            &exporter,
            &responder,
            &policy,
        );
        registry.persist(second.clone()).unwrap();
        let state = DeferredAnchorState::replay(log.as_ref(), log.head()).unwrap();
        assert_eq!(state.anchors.len(), 2);
        assert_eq!(state.latest_digest(), Some(second.anchor_digest));

        let (_, fork) = roundtrip(
            sample_commitment(200, 299, 44),
            None,
            &exporter,
            &responder,
            &policy,
        );
        assert!(registry.persist(fork).is_err());
    }

    #[test]
    fn tampering_response_or_request_breaks_import() {
        let exporter = SoftKeySigner::generate("air-gap-exporter");
        let responder = SoftKeySigner::generate("connected-zone");
        let policy = policy(&exporter, &responder);
        let request = SignedDeferredAnchorRequest::sign(
            DeferredAnchorRequest::new(sample_commitment(0, 99, 42), None).unwrap(),
            &exporter,
            BundleSignatureScheme::P256Development,
        )
        .unwrap();
        let mut response = stamp_deferred_request(
            &request,
            &policy,
            &LocalTsa::generate("ACT-dev"),
            &responder,
            BundleSignatureScheme::P256Development,
        )
        .unwrap();
        response.response.timestamp_token[0] ^= 0xff;
        assert!(import_deferred_response(&request, &response, &policy).is_err());
    }

    /// Auditoria 2026-09-05 (A06): duas importacoes concorrentes gravavam duas
    /// ancoras com o mesmo `previous_anchor_digest`. Como o log e append-only,
    /// o episodio ofensor nunca desaparece — o replay TEM de conseguir ler um
    /// log ja bifurcado, senao o dashboard de compliance e a preparacao de
    /// novas ancoras ficam mortos para sempre. Aqui a bifurcacao e injetada
    /// directamente no log: e a fotografia exacta do estado que a corrida deixa.
    #[test]
    fn replay_tolera_bifurcacao_e_mantem_o_primeiro_ramo() {
        let exporter = SoftKeySigner::generate("air-gap-exporter");
        let responder = SoftKeySigner::generate("connected-zone");
        let policy = policy(&exporter, &responder);
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                StorageFormat::V6,
                temp.path().join("log"),
                4096,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let registry = DeferredAnchorRegistry::new(log.clone());
        let (_, primeira) = roundtrip(
            sample_commitment(0, 99, 42),
            None,
            &exporter,
            &responder,
            &policy,
        );
        registry.persist(primeira.clone()).unwrap();

        // A gemea que a corrida gravaria: tambem com `previous_anchor_digest` a
        // None, portanto a cadeia bifurca no segundo episodio de ancora.
        let (_, bifurcada) = roundtrip(
            sample_commitment(100, 199, 43),
            None,
            &exporter,
            &responder,
            &policy,
        );
        EpisodeLog::append(log.as_ref(), bifurcada.to_episode().unwrap()).unwrap();

        let state = DeferredAnchorState::replay(log.as_ref(), log.head()).unwrap();
        assert_eq!(state.anchors.len(), 1);
        assert_eq!(state.latest_digest(), Some(primeira.anchor_digest));
        assert_eq!(state.forks.len(), 1);
        assert_eq!(state.forks[0].1.anchor_id, bifurcada.anchor_id);

        // O dashboard inteiro dependia deste replay (dashboard.rs, `Anchors`).
        let snapshot = crate::ComplianceDashboardSnapshot::build(
            log.as_ref(),
            temp.path().join("receipts"),
            0,
        )
        .unwrap();
        assert_eq!(snapshot.anchor_health.deferred_anchors, 1);
        assert_eq!(snapshot.anchor_health.deferred_anchor_forks, 1);
    }

    /// Auditoria 2026-09-05 (A06): `persist` lia o estado inteiro e so depois
    /// fazia o append, sem exclusao mutua. `deferred_anchor_op` constroi um
    /// registry NOVO por RPC e cada RPC corre no seu proprio `spawn_blocking`,
    /// logo duas importacoes simultaneas — dois operadores, ou um retry do
    /// cliente — liam ambas o mesmo `latest_digest()` e gravavam ambas. As
    /// repeticoes existem para tirar a flakiness ao teste, nao para procurar a
    /// corrida: a janela e larga (o `state()` reproduz o log inteiro antes de um
    /// append com fsync).
    #[test]
    fn persist_concorrente_nao_bifurca_a_cadeia() {
        let exporter = SoftKeySigner::generate("air-gap-exporter");
        let responder = SoftKeySigner::generate("connected-zone");
        let policy = policy(&exporter, &responder);
        for iteracao in 0..32u32 {
            let temp = tempfile::tempdir().unwrap();
            let log = Arc::new(
                AnyLog::open(
                    StorageFormat::V6,
                    temp.path().join("log"),
                    4096,
                    FsyncPolicy::Always,
                )
                .unwrap(),
            );
            let (_, a) = roundtrip(
                sample_commitment(0, 99, 42),
                None,
                &exporter,
                &responder,
                &policy,
            );
            let (_, b) = roundtrip(
                sample_commitment(100, 199, 43),
                None,
                &exporter,
                &responder,
                &policy,
            );
            let barreira = std::sync::Barrier::new(2);
            let resultados: Vec<_> = std::thread::scope(|escopo| {
                let tarefas: Vec<_> = [a, b]
                    .into_iter()
                    .map(|anchor| {
                        let log = log.clone();
                        let barreira = &barreira;
                        escopo.spawn(move || {
                            // Registries SEPARADOS sobre o mesmo log: e
                            // exactamente o que `deferred_anchor_op` faz a cada
                            // RPC, logo um `Mutex` por instancia nao serializa
                            // nada.
                            let registry = DeferredAnchorRegistry::new(log);
                            barreira.wait();
                            registry.persist(anchor)
                        })
                    })
                    .collect();
                tarefas
                    .into_iter()
                    .map(|tarefa| tarefa.join().unwrap())
                    .collect()
            });
            let aceites = resultados.iter().filter(|r| r.is_ok()).count();
            assert_eq!(aceites, 1, "iteracao {iteracao}: {resultados:?}");
            let state = DeferredAnchorState::replay(log.as_ref(), log.head()).unwrap();
            assert_eq!(state.anchors.len(), 1, "iteracao {iteracao}");
            assert!(state.forks.is_empty(), "iteracao {iteracao}");
        }
    }
}
