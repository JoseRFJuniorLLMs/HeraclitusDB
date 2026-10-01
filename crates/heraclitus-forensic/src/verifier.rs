use crate::manifest::{CustodyEntry, EvidenceManifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CUSTODY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROOF_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OBJECTS: usize = 100_000;
const MAX_TOTAL_OBJECT_BYTES: u64 = 16 * 1024 * 1024 * 1024;


const HRKL_DOMAIN_LEAF: &[u8] = b"HRKL6:MERKLE:LEAF";
const HRKL_DOMAIN_NODE: &[u8] = b"HRKL6:MERKLE:NODE";
const HRKL_DOMAIN_ROOT: &[u8] = b"HRKL6:MERKLE:ROOT";

/// Estado individual de uma verificação forense (SPEC-0087 §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Pass,
    NotPresent,
    Unverified,
    Invalid,
}

/// Resultado técnico agregado. Ausência de confiança externa produz Partial,
/// nunca Verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallTechnical {
    Verified,
    Partial,
    Failed,
}

/// Relatório estruturado para não confundir "manifesto parseou" com prova
/// institucional completa.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub package_structure: VerificationState,
    pub object_digests: VerificationState,
    pub custody_chain: VerificationState,
    pub merkle_proof: VerificationState,
    pub timestamp: VerificationState,
    pub signature: VerificationState,
    pub certificate_chain: VerificationState,
    pub overall_technical: OverallTechnical,
    pub notes: Vec<String>,
}


/// Resultado de um verificador externo de confiança.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalTrustState {
    /// Assinatura/token e cadeia de confiança foram validados.
    Verified,
    /// O material é sintaticamente/criptograficamente utilizável, mas a cadeia
    /// depende de trust anchors que não estão disponíveis neste ambiente.
    ExternalTrustRequired,
}

/// Adaptador para HSM/ICP-Brasil/PKI institucional.
///
/// O crate forense não embute raízes nem inventa identidade. A aplicação que
/// possui o trust store injeta um verificador e responde pelo encadeamento.
pub trait EvidenceTrustVerifier: Send + Sync {
    fn verify_timestamp(
        &self,
        manifest_commitment: &[u8; 32],
        timestamp: &crate::manifest::TrustedTimestamp,
    ) -> Result<ExternalTrustState, String>;

    fn verify_signature(
        &self,
        manifest_commitment: &[u8; 32],
        signature: &crate::manifest::EvidenceSignature,
    ) -> Result<ExternalTrustState, String>;
}

/// Formato offline da prova de origem HRKL v6 carregada em proofs/merkle.json.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HrklProofDocument {
    pub schema_version: String,
    pub proofs: Vec<HrklObjectProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HrklObjectProof {
    pub object_id: String,
    pub source_lsn: u64,
    pub segment_id: u64,
    pub generation: u64,
    pub format_version: u16,
    pub canonical_record_hash_hex: String,
    pub logical_root_hex: String,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub path: Vec<HrklProofStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HrklProofStep {
    pub sibling_hex: String,
    pub sibling_is_left: bool,
}

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Manifest checksum mismatch: expected {expected}, got {actual}")]
    ManifestChecksumMismatch { expected: String, actual: String },
    #[error("Object checksum mismatch for {path}: expected {expected}, got {actual}")]
    ObjectChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("Object size mismatch for {path}: expected {expected}, got {actual}")]
    ObjectSizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    #[error("Broken custody chain at step {step}")]
    BrokenCustodyChain { step: u64 },
    #[error("Custody digest mismatch: expected {expected}, got {actual}")]
    CustodyDigestMismatch { expected: String, actual: String },
    #[error("Merkle root mismatch: expected {expected}, got {actual}")]
    MerkleRootMismatch { expected: String, actual: String },
    #[error("Invalid leaves_count: expected {expected}, got {actual}")]
    LeavesCountMismatch { expected: u64, actual: u64 },
    #[error("Invalid HRKL Merkle proof: {0}")]
    InvalidMerkleProof(String),
    #[error("Unsupported evidence schema version: {0}")]
    UnsupportedSchema(String),
    #[error("Missing file: {0}")]
    MissingFile(String),
    #[error("Path traversal detected: {0}")]
    PathTraversal(String),
    #[error("Package budget exceeded: {0}")]
    BudgetExceeded(String),
    #[error("External trust material is present but not cryptographically verified: {kind} ({count})")]
    ExternalTrustUnverified { kind: &'static str, count: usize },
    #[error("External trust validation failed for {kind}: {detail}")]
    ExternalTrustInvalid {
        kind: &'static str,
        detail: String,
    },
}

fn decode_hex32(label: &str, value: &str) -> Result<[u8; 32], VerifierError> {
    let bytes = hex::decode(value)
        .map_err(|error| VerifierError::InvalidMerkleProof(format!("{label}: hex inválido: {error}")))?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| {
        VerifierError::InvalidMerkleProof(format!(
            "{label}: esperado digest de 32 bytes, recebido {len}"
        ))
    })
}

fn hrkl_leaf(record_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HRKL_DOMAIN_LEAF);
    hasher.update(record_hash);
    *hasher.finalize().as_bytes()
}

fn hrkl_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HRKL_DOMAIN_NODE);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

fn hrkl_seal_root(leaf_count: u64, accumulator: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HRKL_DOMAIN_ROOT);
    hasher.update(&leaf_count.to_le_bytes());
    hasher.update(accumulator);
    *hasher.finalize().as_bytes()
}

fn verify_hrkl_object_proof(proof: &HrklObjectProof) -> Result<(), VerifierError> {
    if proof.format_version != 6 {
        return Err(VerifierError::InvalidMerkleProof(format!(
            "objeto {} declara HRKL v{}, esperado v6",
            proof.object_id, proof.format_version
        )));
    }
    if proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count {
        return Err(VerifierError::InvalidMerkleProof(format!(
            "objeto {} tem leaf_index/count inválidos: {}/{}",
            proof.object_id, proof.leaf_index, proof.leaf_count
        )));
    }

    // Valida a geometria do caminho, incluindo a promoção de folha ímpar. Isso
    // impede uma lista arbitrária de irmãos que por acaso fecha contra uma raiz.
    let mut index = proof.leaf_index;
    let mut width = proof.leaf_count;
    let mut expected_sides = Vec::new();
    while width > 1 {
        let sibling = if index.is_multiple_of(2) {
            index.checked_add(1).filter(|s| *s < width)
        } else {
            Some(index - 1)
        };
        if let Some(sibling_index) = sibling {
            expected_sides.push(sibling_index < index);
        }
        index /= 2;
        width = width.div_ceil(2);
    }
    if expected_sides.len() != proof.path.len() {
        return Err(VerifierError::InvalidMerkleProof(format!(
            "objeto {} tem {} passos, geometria exige {}",
            proof.object_id,
            proof.path.len(),
            expected_sides.len()
        )));
    }
    for (step, expected_left) in proof.path.iter().zip(expected_sides) {
        if step.sibling_is_left != expected_left {
            return Err(VerifierError::InvalidMerkleProof(format!(
                "objeto {} tem lado de sibling incompatível com leaf_index",
                proof.object_id
            )));
        }
    }

    let record_hash = decode_hex32("canonical_record_hash", &proof.canonical_record_hash_hex)?;
    let expected_root = decode_hex32("logical_root", &proof.logical_root_hex)?;
    let mut acc = hrkl_leaf(&record_hash);
    for step in &proof.path {
        let sibling = decode_hex32("sibling", &step.sibling_hex)?;
        acc = if step.sibling_is_left {
            hrkl_node(&sibling, &acc)
        } else {
            hrkl_node(&acc, &sibling)
        };
    }
    let actual_root = hrkl_seal_root(proof.leaf_count, &acc);
    if actual_root != expected_root {
        return Err(VerifierError::InvalidMerkleProof(format!(
            "objeto {} não fecha contra logical_root",
            proof.object_id
        )));
    }
    Ok(())
}

pub(crate) fn validate_safe_relative_path(path_str: &str) -> bool {
    let path = Path::new(path_str);
    if path.is_absolute() {
        return false;
    }
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => return false,
            _ => {}
        }
    }
    true
}

pub struct EvidenceVerifier {
    package_dir: PathBuf,
    trust_verifier: Option<std::sync::Arc<dyn EvidenceTrustVerifier>>,
}

impl EvidenceVerifier {
    pub fn new<P: AsRef<Path>>(package_dir: P) -> Self {
        Self {
            package_dir: package_dir.as_ref().to_path_buf(),
            trust_verifier: None,
        }
    }


    pub fn with_trust_verifier(
        mut self,
        verifier: std::sync::Arc<dyn EvidenceTrustVerifier>,
    ) -> Self {
        self.trust_verifier = Some(verifier);
        self
    }

    fn manifest_trust_commitment(manifest: &EvidenceManifest) -> Result<[u8; 32], VerifierError> {
        // Evita circularidade: assinatura e timestamp atestam o manifesto-base,
        // não bytes que já contêm a própria assinatura/token.
        let mut canonical = manifest.clone();
        canonical.trusted_timestamps.clear();
        canonical.signatures.clear();
        let bytes = serde_json::to_vec(&canonical)?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    fn checked_file(&self, relative: &str, max_bytes: u64) -> Result<PathBuf, VerifierError> {
        if !validate_safe_relative_path(relative) {
            return Err(VerifierError::PathTraversal(relative.to_string()));
        }
        let path = self.package_dir.join(relative);
        let meta = fs::symlink_metadata(&path)
            .map_err(|_| VerifierError::MissingFile(relative.to_string()))?;
        if meta.file_type().is_symlink() {
            return Err(VerifierError::PathTraversal(format!(
                "{relative}: symbolic link refused"
            )));
        }
        if meta.len() > max_bytes {
            return Err(VerifierError::BudgetExceeded(format!(
                "{relative} has {} bytes; limit is {max_bytes}",
                meta.len()
            )));
        }

        // Defesa adicional contra junction/symlink em componentes ancestrais.
        // canonicalize resolve o destino; ele precisa continuar sob a raiz.
        let root = fs::canonicalize(&self.package_dir)?;
        let canonical = fs::canonicalize(&path)?;
        if !canonical.starts_with(&root) {
            return Err(VerifierError::PathTraversal(relative.to_string()));
        }
        Ok(path)
    }

    /// Relatório estruturado, separado do contrato legado de `verify()`.
    ///
    /// O relatório não promove ausência de confiança externa a PASS. Um pacote
    /// estruturalmente íntegro mas sem timestamp/assinatura verificáveis é
    /// `Partial`, como exige a SPEC-0087.
    pub fn verify_report(&self) -> VerificationReport {
        let mut report = VerificationReport {
            package_structure: VerificationState::Pass,
            object_digests: VerificationState::Pass,
            custody_chain: VerificationState::Pass,
            merkle_proof: VerificationState::NotPresent,
            timestamp: VerificationState::NotPresent,
            signature: VerificationState::NotPresent,
            certificate_chain: VerificationState::NotPresent,
            overall_technical: OverallTechnical::Partial,
            notes: Vec::new(),
        };

        let manifest = match self.verify_integrity() {
            Ok(manifest) => manifest,
            Err(error) => {
                match &error {
                    VerifierError::ObjectChecksumMismatch { .. }
                    | VerifierError::ObjectSizeMismatch { .. } => {
                        report.object_digests = VerificationState::Invalid;
                    }
                    VerifierError::BrokenCustodyChain { .. }
                    | VerifierError::CustodyDigestMismatch { .. } => {
                        report.custody_chain = VerificationState::Invalid;
                    }
                    VerifierError::MerkleRootMismatch { .. }
                    | VerifierError::LeavesCountMismatch { .. }
                    | VerifierError::InvalidMerkleProof(_) => {
                        report.merkle_proof = VerificationState::Invalid;
                    }
                    _ => report.package_structure = VerificationState::Invalid,
                }
                report.overall_technical = OverallTechnical::Failed;
                report.notes.push(error.to_string());
                return report;
            }
        };

        if let Ok(value) = self
            .checked_file("proofs/merkle.json", MAX_PROOF_BYTES)
            .and_then(|path| fs::read(path).map_err(VerifierError::Io))
            .and_then(|bytes| {
                serde_json::from_slice::<serde_json::Value>(&bytes).map_err(VerifierError::Json)
            })
        {
            let absent = value.is_null()
                || value
                    .as_object()
                    .map(|object| object.is_empty())
                    .unwrap_or(false);
            report.merkle_proof = if absent {
                VerificationState::NotPresent
            } else {
                VerificationState::Pass
            };
        }

        match Self::manifest_trust_commitment(&manifest) {
            Ok(commitment) => {
                report.timestamp = match self.timestamp_state(&manifest, &commitment) {
                    Ok(state) => state,
                    Err(error) => {
                        report.notes.push(error.to_string());
                        VerificationState::Invalid
                    }
                };
                report.signature = match self.signature_state(&manifest, &commitment) {
                    Ok(state) => state,
                    Err(error) => {
                        report.notes.push(error.to_string());
                        VerificationState::Invalid
                    }
                };
            }
            Err(error) => {
                report.package_structure = VerificationState::Invalid;
                report.notes.push(error.to_string());
            }
        }

        report.certificate_chain = match (report.timestamp, report.signature) {
            (VerificationState::Invalid, _) | (_, VerificationState::Invalid) => {
                VerificationState::Invalid
            }
            (VerificationState::Pass, VerificationState::Pass) => VerificationState::Pass,
            (VerificationState::NotPresent, VerificationState::NotPresent) => {
                VerificationState::NotPresent
            }
            (VerificationState::Unverified, _)
            | (_, VerificationState::Unverified)
            | (VerificationState::Pass, VerificationState::NotPresent)
            | (VerificationState::NotPresent, VerificationState::Pass) => {
                VerificationState::Unverified
            }
        };

        let failed = [
            report.package_structure,
            report.object_digests,
            report.custody_chain,
            report.merkle_proof,
            report.timestamp,
            report.signature,
            report.certificate_chain,
        ]
        .contains(&VerificationState::Invalid);

        let complete = report.package_structure == VerificationState::Pass
            && report.object_digests == VerificationState::Pass
            && report.custody_chain == VerificationState::Pass
            && report.merkle_proof == VerificationState::Pass
            && report.timestamp == VerificationState::Pass
            && report.signature == VerificationState::Pass
            && report.certificate_chain == VerificationState::Pass;

        report.overall_technical = if failed {
            OverallTechnical::Failed
        } else if complete {
            OverallTechnical::Verified
        } else {
            OverallTechnical::Partial
        };
        report
    }

    fn verify_integrity(&self) -> Result<EvidenceManifest, VerifierError> {
        let manifest_path = self.checked_file("manifest.json", MAX_MANIFEST_BYTES)?;
        let checksum_path = self.checked_file("manifest.sha256", 4096)?;

        let manifest_bytes = fs::read(&manifest_path)?;
        let sha256_content = fs::read_to_string(&checksum_path)?;
        let expected_sha256 = sha256_content
            .split_whitespace()
            .next()
            .ok_or_else(|| VerifierError::ManifestChecksumMismatch {
                expected: "<missing>".into(),
                actual: "<not-computed>".into(),
            })?;

        let mut hasher = Sha256::new();
        hasher.update(&manifest_bytes);
        let actual_sha256 = hex::encode(hasher.finalize());
        if expected_sha256 != actual_sha256 {
            return Err(VerifierError::ManifestChecksumMismatch {
                expected: expected_sha256.to_string(),
                actual: actual_sha256,
            });
        }

        let manifest: EvidenceManifest = serde_json::from_slice(&manifest_bytes)?;
        if manifest.schema_version != "1.0" {
            return Err(VerifierError::UnsupportedSchema(
                manifest.schema_version.clone(),
            ));
        }
        if manifest.objects.len() > MAX_OBJECTS {
            return Err(VerifierError::BudgetExceeded(format!(
                "{} objects; limit is {MAX_OBJECTS}",
                manifest.objects.len()
            )));
        }

        let expected_leaves = manifest.objects.len() as u64;
        if manifest.merkle.leaves_count != expected_leaves {
            return Err(VerifierError::LeavesCountMismatch {
                expected: expected_leaves,
                actual: manifest.merkle.leaves_count,
            });
        }

        let mut total_object_bytes = 0u64;
        for obj in &manifest.objects {
            total_object_bytes = total_object_bytes
                .checked_add(obj.size_bytes)
                .ok_or_else(|| VerifierError::BudgetExceeded("object byte sum overflow".into()))?;
            if total_object_bytes > MAX_TOTAL_OBJECT_BYTES {
                return Err(VerifierError::BudgetExceeded(format!(
                    "declared object bytes exceed {MAX_TOTAL_OBJECT_BYTES}"
                )));
            }

            let obj_path = self.checked_file(&obj.relative_path, obj.size_bytes)?;
            let meta = fs::metadata(&obj_path)?;
            if meta.len() != obj.size_bytes {
                return Err(VerifierError::ObjectSizeMismatch {
                    path: obj.relative_path.clone(),
                    expected: obj.size_bytes,
                    actual: meta.len(),
                });
            }
            // Hash streaming: um objeto permitido pelo budget pode ser grande,
            // mas verificação nunca precisa alocá-lo inteiro em RAM.
            let mut file = fs::File::open(&obj_path)?;
            let mut sha256_hasher = Sha256::new();
            let mut blake3_hasher = blake3::Hasher::new();
            let mut buffer = [0u8; 1024 * 1024];
            loop {
                use std::io::Read as _;
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                sha256_hasher.update(&buffer[..read]);
                blake3_hasher.update(&buffer[..read]);
            }

            let actual_sha256 = hex::encode(sha256_hasher.finalize());
            if actual_sha256 != obj.sha256_hex {
                return Err(VerifierError::ObjectChecksumMismatch {
                    path: obj.relative_path.clone(),
                    expected: obj.sha256_hex.clone(),
                    actual: actual_sha256,
                });
            }

            let actual_blake3 = blake3_hasher.finalize().to_hex().to_string();
            if actual_blake3 != obj.blake3_hex {
                return Err(VerifierError::ObjectChecksumMismatch {
                    path: obj.relative_path.clone(),
                    expected: obj.blake3_hex.clone(),
                    actual: actual_blake3,
                });
            }
        }

        let custody_relative = "provenance/custody.jsonl";
        let custody_path = self.package_dir.join(custody_relative);
        if !manifest.custody_digest.is_empty() {
            let path = self.checked_file(custody_relative, MAX_CUSTODY_BYTES)?;
            let custody_bytes = fs::read(&path)?;
            let mut hasher = Sha256::new();
            hasher.update(&custody_bytes);
            let actual_custody_digest = hex::encode(hasher.finalize());
            if actual_custody_digest != manifest.custody_digest {
                return Err(VerifierError::CustodyDigestMismatch {
                    expected: manifest.custody_digest.clone(),
                    actual: actual_custody_digest,
                });
            }
        }

        if custody_path.exists() {
            let path = self.checked_file(custody_relative, MAX_CUSTODY_BYTES)?;
            let custody_content = fs::read_to_string(&path)?;
            let mut previous_hash = String::new();
            let mut previous_timestamp = 0u64;
            let mut expected_step = 0u64;
            let mut seen_hashes = std::collections::HashSet::new();

            for line in custody_content.lines().filter(|line| !line.trim().is_empty()) {
                let entry: CustodyEntry = serde_json::from_str(line)?;
                if entry.step_index != expected_step {
                    return Err(VerifierError::BrokenCustodyChain {
                        step: entry.step_index,
                    });
                }
                if expected_step == 0 {
                    if !entry.previous_entry_hash.is_empty() {
                        return Err(VerifierError::BrokenCustodyChain { step: 0 });
                    }
                } else {
                    if entry.previous_entry_hash != previous_hash
                        || entry.timestamp_secs < previous_timestamp
                    {
                        return Err(VerifierError::BrokenCustodyChain {
                            step: entry.step_index,
                        });
                    }
                }

                if entry.compute_hash() != entry.entry_hash
                    || !seen_hashes.insert(entry.entry_hash.clone())
                {
                    return Err(VerifierError::BrokenCustodyChain {
                        step: entry.step_index,
                    });
                }

                previous_timestamp = entry.timestamp_secs;
                previous_hash = entry.entry_hash;
                expected_step = expected_step
                    .checked_add(1)
                    .ok_or_else(|| VerifierError::BudgetExceeded("custody step overflow".into()))?;
            }
        }

        // Provas de origem HRKL: JSON válido não basta. Quando presentes, as
        // provas têm de fechar contra a raiz declarada, respeitar a geometria
        // HRKL v6 e referenciar exatamente o objeto/LSN do manifesto.
        let proofs_path = self.checked_file("proofs/merkle.json", MAX_PROOF_BYTES)?;
        let proofs_bytes = fs::read(&proofs_path)?;
        let proof_value: serde_json::Value = serde_json::from_slice(&proofs_bytes)?;
        let proof_is_absent = proof_value.is_null()
            || proof_value
                .as_object()
                .map(|object| object.is_empty())
                .unwrap_or(false);

        if !proof_is_absent {
            let document: HrklProofDocument = serde_json::from_value(proof_value)?;
            if document.schema_version != "hrkl6-inclusion-v1" {
                return Err(VerifierError::InvalidMerkleProof(format!(
                    "schema de prova não suportado: {}",
                    document.schema_version
                )));
            }
            if document.proofs.is_empty() {
                return Err(VerifierError::InvalidMerkleProof(
                    "documento de provas não pode estar vazio".into(),
                ));
            }

            let objects_by_id: std::collections::HashMap<_, _> = manifest
                .objects
                .iter()
                .map(|object| (object.object_id.as_str(), object))
                .collect();
            let mut proven_objects = std::collections::HashSet::new();
            for proof in &document.proofs {
                let object = objects_by_id.get(proof.object_id.as_str()).ok_or_else(|| {
                    VerifierError::InvalidMerkleProof(format!(
                        "prova referencia objeto inexistente: {}",
                        proof.object_id
                    ))
                })?;
                if object.source_lsn != Some(proof.source_lsn) {
                    return Err(VerifierError::InvalidMerkleProof(format!(
                        "objeto {}: LSN do manifesto {:?} diverge da prova {}",
                        proof.object_id, object.source_lsn, proof.source_lsn
                    )));
                }
                if !proven_objects.insert(proof.object_id.as_str()) {
                    return Err(VerifierError::InvalidMerkleProof(format!(
                        "objeto {} possui prova duplicada",
                        proof.object_id
                    )));
                }
                verify_hrkl_object_proof(proof)?;
            }

            let expected: std::collections::HashSet<_> = manifest
                .objects
                .iter()
                .filter(|object| object.source_lsn.is_some())
                .map(|object| object.object_id.as_str())
                .collect();
            if proven_objects != expected {
                return Err(VerifierError::InvalidMerkleProof(
                    "documento de provas não cobre exatamente os objetos com source_lsn".into(),
                ));
            }
        }

        if !manifest.objects.is_empty() {
            let mut blake3_hasher = blake3::Hasher::new();
            let mut sha256_hasher = Sha256::new();
            for obj in &manifest.objects {
                blake3_hasher.update(obj.blake3_hex.as_bytes());
                sha256_hasher.update(obj.sha256_hex.as_bytes());
            }
            let computed_blake3 = blake3_hasher.finalize().to_hex().to_string();
            if computed_blake3 != manifest.merkle.root_blake3 {
                return Err(VerifierError::MerkleRootMismatch {
                    expected: manifest.merkle.root_blake3.clone(),
                    actual: computed_blake3,
                });
            }
            let computed_sha256 = hex::encode(sha256_hasher.finalize());
            if computed_sha256 != manifest.merkle.root_sha256 {
                return Err(VerifierError::MerkleRootMismatch {
                    expected: manifest.merkle.root_sha256.clone(),
                    actual: computed_sha256,
                });
            }
        } else if !manifest.merkle.root_blake3.is_empty()
            || !manifest.merkle.root_sha256.is_empty()
        {
            return Err(VerifierError::MerkleRootMismatch {
                expected: "<empty roots for zero objects>".into(),
                actual: format!(
                    "blake3={}, sha256={}",
                    manifest.merkle.root_blake3, manifest.merkle.root_sha256
                ),
            });
        }

        Ok(manifest)
    }

    fn timestamp_state(
        &self,
        manifest: &EvidenceManifest,
        commitment: &[u8; 32],
    ) -> Result<VerificationState, VerifierError> {
        if manifest.trusted_timestamps.is_empty() {
            return Ok(VerificationState::NotPresent);
        }
        let Some(verifier) = self.trust_verifier.as_ref() else {
            return Ok(VerificationState::Unverified);
        };

        let mut state = VerificationState::Pass;
        for timestamp in &manifest.trusted_timestamps {
            match verifier
                .verify_timestamp(commitment, timestamp)
                .map_err(|detail| VerifierError::ExternalTrustInvalid {
                    kind: "trusted timestamp",
                    detail,
                })? {
                ExternalTrustState::Verified => {}
                ExternalTrustState::ExternalTrustRequired => {
                    state = VerificationState::Unverified;
                }
            }
        }
        Ok(state)
    }

    fn signature_state(
        &self,
        manifest: &EvidenceManifest,
        commitment: &[u8; 32],
    ) -> Result<VerificationState, VerifierError> {
        if manifest.signatures.is_empty() {
            return Ok(VerificationState::NotPresent);
        }
        let Some(verifier) = self.trust_verifier.as_ref() else {
            return Ok(VerificationState::Unverified);
        };

        let mut state = VerificationState::Pass;
        for signature in &manifest.signatures {
            match verifier
                .verify_signature(commitment, signature)
                .map_err(|detail| VerifierError::ExternalTrustInvalid {
                    kind: "signature",
                    detail,
                })? {
                ExternalTrustState::Verified => {}
                ExternalTrustState::ExternalTrustRequired => {
                    state = VerificationState::Unverified;
                }
            }
        }
        Ok(state)
    }

    fn verify_external_trust(&self, manifest: &EvidenceManifest) -> Result<(), VerifierError> {
        let commitment = Self::manifest_trust_commitment(manifest)?;
        let timestamp = self.timestamp_state(manifest, &commitment)?;
        if timestamp == VerificationState::Unverified {
            return Err(VerifierError::ExternalTrustUnverified {
                kind: "trusted timestamp",
                count: manifest.trusted_timestamps.len(),
            });
        }
        let signature = self.signature_state(manifest, &commitment)?;
        if signature == VerificationState::Unverified {
            return Err(VerifierError::ExternalTrustUnverified {
                kind: "signature",
                count: manifest.signatures.len(),
            });
        }
        Ok(())
    }

    /// Verificação estrita compatível com a API existente.
    ///
    /// Integridade parcial sem material externo continua válida; material de
    /// confiança PRESENTE, porém não verificável, falha fechado.
    pub fn verify(&self) -> Result<EvidenceManifest, VerifierError> {
        let manifest = self.verify_integrity()?;
        self.verify_external_trust(&manifest)?;
        Ok(manifest)
    }

}

#[cfg(test)]
mod verifier_regressions {
    use super::*;
    use crate::manifest::{
        CustodyAction, EvidenceManifest, HlcRange, LsnRange, MerkleEvidence, TrustedTimestamp,
    };
    use crate::package::EvidencePackageBuilder;
    use tempfile::tempdir;


    struct AcceptTrust;
    impl EvidenceTrustVerifier for AcceptTrust {
        fn verify_timestamp(
            &self,
            _manifest_commitment: &[u8; 32],
            _timestamp: &crate::manifest::TrustedTimestamp,
        ) -> Result<ExternalTrustState, String> {
            Ok(ExternalTrustState::Verified)
        }

        fn verify_signature(
            &self,
            _manifest_commitment: &[u8; 32],
            _signature: &crate::manifest::EvidenceSignature,
        ) -> Result<ExternalTrustState, String> {
            Ok(ExternalTrustState::Verified)
        }
    }

    fn manifest() -> EvidenceManifest {
        EvidenceManifest {
            schema_version: "1.0".into(),
            package_id: "pkg".into(),
            case_id: "case".into(),
            tenant_id: "tenant".into(),
            source_database_id: "db".into(),
            source_build: "build".into(),
            lsn_range: LsnRange { min_lsn: 1, max_lsn: 1 },
            hlc_range: HlcRange { min_hlc: 1, max_hlc: 1 },
            objects: vec![],
            merkle: MerkleEvidence {
                root_blake3: String::new(),
                root_sha256: String::new(),
                leaves_count: 0,
            },
            custody_digest: String::new(),
            export_identity: "tester".into(),
            export_reason: "test".into(),
            created_at_claimed: 1,
            trusted_timestamps: vec![],
            signatures: vec![],
        }
    }

    #[test]
    fn second_genesis_is_rejected() {
        let dir = tempdir().unwrap();
        let package = dir.path().join("pkg");
        let mut builder = EvidencePackageBuilder::new(manifest());

        let mut first = CustodyEntry {
            step_index: 0,
            timestamp_secs: 1,
            action: CustodyAction::Coleta,
            operator_principal: "a".into(),
            terminal_or_node: "node-a".into(),
            previous_entry_hash: String::new(),
            entry_hash: String::new(),
        };
        first.entry_hash = first.compute_hash();

        let mut second = CustodyEntry {
            step_index: 0,
            timestamp_secs: 2,
            action: CustodyAction::Guarda,
            operator_principal: "b".into(),
            terminal_or_node: "node-b".into(),
            previous_entry_hash: String::new(),
            entry_hash: String::new(),
        };
        second.entry_hash = second.compute_hash();

        builder.add_custody_entry(first);
        builder.add_custody_entry(second);
        builder.build(&package).unwrap();

        assert!(matches!(
            EvidenceVerifier::new(&package).verify(),
            Err(VerifierError::BrokenCustodyChain { .. })
        ));
    }

    #[test]
    fn terminal_is_bound_into_custody_hash() {
        let mut entry = CustodyEntry {
            step_index: 0,
            timestamp_secs: 1,
            action: CustodyAction::Coleta,
            operator_principal: "a".into(),
            terminal_or_node: "node-a".into(),
            previous_entry_hash: String::new(),
            entry_hash: String::new(),
        };
        let before = entry.compute_hash();
        entry.terminal_or_node = "node-b".into();
        assert_ne!(before, entry.compute_hash());
    }

    #[test]
    fn invalid_proof_bytes_are_rejected() {
        let dir = tempdir().unwrap();
        let package = dir.path().join("pkg");
        let mut builder = EvidencePackageBuilder::new(manifest());
        builder.build(&package).unwrap();
        fs::write(package.join("proofs/merkle.json"), b"not-json").unwrap();

        assert!(matches!(
            EvidenceVerifier::new(&package).verify(),
            Err(VerifierError::Json(_))
        ));
    }

    #[test]
    fn claimed_timestamp_is_never_silently_verified() {
        let dir = tempdir().unwrap();
        let package = dir.path().join("pkg");
        let mut m = manifest();
        m.trusted_timestamps.push(TrustedTimestamp {
            authority: "fake".into(),
            timestamp_secs: 1,
            token: "deadbeef".into(),
        });
        let mut builder = EvidencePackageBuilder::new(m);
        builder.build(&package).unwrap();

        assert!(matches!(
            EvidenceVerifier::new(&package).verify(),
            Err(VerifierError::ExternalTrustUnverified {
                kind: "trusted timestamp",
                ..
            })
        ));
    }

    #[test]
    fn custody_rejects_time_regression_and_duplicate_hashes() {
        let dir = tempdir().unwrap();
        let package = dir.path().join("pkg");
        let mut builder = EvidencePackageBuilder::new(manifest());

        let mut first = CustodyEntry {
            step_index: 0,
            timestamp_secs: 20,
            action: CustodyAction::Coleta,
            operator_principal: "a".into(),
            terminal_or_node: "node-a".into(),
            previous_entry_hash: String::new(),
            entry_hash: String::new(),
        };
        first.entry_hash = first.compute_hash();

        let mut second = CustodyEntry {
            step_index: 1,
            timestamp_secs: 19,
            action: CustodyAction::Guarda,
            operator_principal: "b".into(),
            terminal_or_node: "node-b".into(),
            previous_entry_hash: first.entry_hash.clone(),
            entry_hash: String::new(),
        };
        second.entry_hash = second.compute_hash();

        builder.add_custody_entry(first);
        builder.add_custody_entry(second);
        builder.build(&package).unwrap();

        assert!(matches!(
            EvidenceVerifier::new(&package).verify(),
            Err(VerifierError::BrokenCustodyChain { step: 1 })
        ));
    }


    #[test]
    fn valid_single_leaf_hrkl_proof_is_accepted_and_reported() {
        let dir = tempdir().unwrap();
        let package = dir.path().join("pkg");
        let mut m = manifest();

        let data = b"evidence";
        let mut sha = Sha256::new();
        sha.update(data);
        let object = crate::manifest::EvidenceObject {
            object_id: "obj-1".into(),
            relative_path: "evidence/obj-1.bin".into(),
            size_bytes: data.len() as u64,
            sha256_hex: hex::encode(sha.finalize()),
            blake3_hex: blake3::hash(data).to_hex().to_string(),
            content_type: "application/octet-stream".into(),
            source_lsn: Some(7),
        };
        m.objects.push(object.clone());

        // O compromisso de objetos do schema 1.0 continua independente da
        // prova HRKL de origem.
        let mut b3 = blake3::Hasher::new();
        b3.update(object.blake3_hex.as_bytes());
        m.merkle.root_blake3 = b3.finalize().to_hex().to_string();
        let mut s256 = Sha256::new();
        s256.update(object.sha256_hex.as_bytes());
        m.merkle.root_sha256 = hex::encode(s256.finalize());
        m.merkle.leaves_count = 1;

        let record_hash = [0x42u8; 32];
        let root = hrkl_seal_root(1, &hrkl_leaf(&record_hash));
        let proof = HrklProofDocument {
            schema_version: "hrkl6-inclusion-v1".into(),
            proofs: vec![HrklObjectProof {
                object_id: "obj-1".into(),
                source_lsn: 7,
                segment_id: 3,
                generation: 1,
                format_version: 6,
                canonical_record_hash_hex: hex::encode(record_hash),
                logical_root_hex: hex::encode(root),
                leaf_index: 0,
                leaf_count: 1,
                path: vec![],
            }],
        };

        let mut builder = EvidencePackageBuilder::new(m);
        builder.add_object_data(object, data.to_vec());
        builder.set_proofs(serde_json::to_value(proof).unwrap());
        builder.build(&package).unwrap();

        let verifier = EvidenceVerifier::new(&package);
        assert!(verifier.verify().is_ok());
        let report = verifier.verify_report();
        assert_eq!(report.merkle_proof, VerificationState::Pass);
        assert_eq!(report.overall_technical, OverallTechnical::Partial);
    }

    #[test]
    fn hrkl_proof_with_wrong_geometry_is_rejected() {
        let proof = HrklObjectProof {
            object_id: "obj".into(),
            source_lsn: 1,
            segment_id: 1,
            generation: 1,
            format_version: 6,
            canonical_record_hash_hex: hex::encode([1u8; 32]),
            logical_root_hex: hex::encode([2u8; 32]),
            leaf_index: 0,
            leaf_count: 2,
            path: vec![],
        };
        assert!(matches!(
            verify_hrkl_object_proof(&proof),
            Err(VerifierError::InvalidMerkleProof(_))
        ));
    }


    #[test]
    fn injected_trust_verifier_can_promote_validated_material() {
        let dir = tempdir().unwrap();
        let package = dir.path().join("pkg");
        let mut m = manifest();
        m.trusted_timestamps.push(crate::manifest::TrustedTimestamp {
            authority: "ACT-test".into(),
            timestamp_secs: 1,
            token: "opaque".into(),
        });
        m.signatures.push(crate::manifest::EvidenceSignature {
            signer_identity: "CN=test".into(),
            signature_hex: "opaque".into(),
            algorithm: "test".into(),
        });
        let mut builder = EvidencePackageBuilder::new(m);
        builder.build(&package).unwrap();

        let verifier = EvidenceVerifier::new(&package)
            .with_trust_verifier(std::sync::Arc::new(AcceptTrust));
        assert!(verifier.verify().is_ok());
        let report = verifier.verify_report();
        assert_eq!(report.timestamp, VerificationState::Pass);
        assert_eq!(report.signature, VerificationState::Pass);
    }

}
