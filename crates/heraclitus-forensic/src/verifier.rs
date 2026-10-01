use crate::manifest::{CustodyEntry, EvidenceManifest};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CUSTODY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROOF_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OBJECTS: usize = 100_000;
const MAX_TOTAL_OBJECT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

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
}

impl EvidenceVerifier {
    pub fn new<P: AsRef<Path>>(package_dir: P) -> Self {
        Self {
            package_dir: package_dir.as_ref().to_path_buf(),
        }
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

    pub fn verify(&self) -> Result<EvidenceManifest, VerifierError> {
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
            let data = fs::read(&obj_path)?;

            let mut sha256_hasher = Sha256::new();
            sha256_hasher.update(&data);
            let actual_sha256 = hex::encode(sha256_hasher.finalize());
            if actual_sha256 != obj.sha256_hex {
                return Err(VerifierError::ObjectChecksumMismatch {
                    path: obj.relative_path.clone(),
                    expected: obj.sha256_hex.clone(),
                    actual: actual_sha256,
                });
            }

            let actual_blake3 = blake3::hash(&data).to_hex().to_string();
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
            let mut expected_step = 0u64;

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
                } else if entry.previous_entry_hash != previous_hash {
                    return Err(VerifierError::BrokenCustodyChain {
                        step: entry.step_index,
                    });
                }

                if entry.compute_hash() != entry.entry_hash {
                    return Err(VerifierError::BrokenCustodyChain {
                        step: entry.step_index,
                    });
                }

                previous_hash = entry.entry_hash;
                expected_step = expected_step
                    .checked_add(1)
                    .ok_or_else(|| VerifierError::BudgetExceeded("custody step overflow".into()))?;
            }
        }

        // O ficheiro de provas é parte estrutural do pacote. Mesmo antes de um
        // verificador HRKL completo, bytes arbitrários não podem ser ignorados.
        let proofs_path = self.checked_file("proofs/merkle.json", MAX_PROOF_BYTES)?;
        let proofs_bytes = fs::read(&proofs_path)?;
        let _proofs: serde_json::Value = serde_json::from_slice(&proofs_bytes)?;

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

        // Até existir validação criptográfica offline de confiança, a presença
        // destes campos nunca pode ser convertida em PASS. Fail-closed evita que
        // Ok(manifest) seja confundido com assinatura/timestamp verificados.
        if !manifest.trusted_timestamps.is_empty() {
            return Err(VerifierError::ExternalTrustUnverified {
                kind: "trusted timestamp",
                count: manifest.trusted_timestamps.len(),
            });
        }
        if !manifest.signatures.is_empty() {
            return Err(VerifierError::ExternalTrustUnverified {
                kind: "signature",
                count: manifest.signatures.len(),
            });
        }

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
}
