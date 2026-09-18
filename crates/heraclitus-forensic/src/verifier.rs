use crate::manifest::{EvidenceManifest, CustodyEntry};
use std::path::Path;
use std::fs;
use sha2::{Sha256, Digest};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Manifest checksum mismatch: expected {expected}, got {actual}")]
    ManifestChecksumMismatch { expected: String, actual: String },
    #[error("Object checksum mismatch for {path}: expected {expected}, got {actual}")]
    ObjectChecksumMismatch { path: String, expected: String, actual: String },
    #[error("Broken custody chain at step {step}")]
    BrokenCustodyChain { step: u64 },
    #[error("Custody digest mismatch: expected {expected}, got {actual}")]
    CustodyDigestMismatch { expected: String, actual: String },
    #[error("Merkle root mismatch: expected {expected}, got {actual}")]
    MerkleRootMismatch { expected: String, actual: String },
    #[error("Missing file: {0}")]
    MissingFile(String),
    #[error("Path traversal detected: {0}")]
    PathTraversal(String),
}

pub(crate) fn validate_safe_relative_path(path_str: &str) -> bool {
    let path = Path::new(path_str);
    if path.is_absolute() {
        return false;
    }
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir | std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return false;
            }
            _ => {}
        }
    }
    true
}

pub struct EvidenceVerifier {
    package_dir: std::path::PathBuf,
}

impl EvidenceVerifier {
    pub fn new<P: AsRef<Path>>(package_dir: P) -> Self {
        Self {
            package_dir: package_dir.as_ref().to_path_buf(),
        }
    }

    pub fn verify(&self) -> Result<EvidenceManifest, VerifierError> {
        let manifest_path = self.package_dir.join("manifest.json");
        if !manifest_path.exists() {
            return Err(VerifierError::MissingFile("manifest.json".to_string()));
        }

        let manifest_bytes = fs::read(&manifest_path)?;
        
        let manifest_sha256_path = self.package_dir.join("manifest.sha256");
        if manifest_sha256_path.exists() {
            let sha256_content = fs::read_to_string(&manifest_sha256_path)?;
            let expected_sha256 = sha256_content.split_whitespace().next().unwrap_or("");
            
            let mut hasher = Sha256::new();
            hasher.update(&manifest_bytes);
            let actual_sha256 = hex::encode(hasher.finalize());
            
            if expected_sha256 != actual_sha256 {
                return Err(VerifierError::ManifestChecksumMismatch {
                    expected: expected_sha256.to_string(),
                    actual: actual_sha256,
                });
            }
        }

        let manifest: EvidenceManifest = serde_json::from_slice(&manifest_bytes)?;

        // Verify objects
        for obj in &manifest.objects {
            if !validate_safe_relative_path(&obj.relative_path) {
                return Err(VerifierError::PathTraversal(obj.relative_path.clone()));
            }

            let obj_path = self.package_dir.join(&obj.relative_path);
            if !obj_path.exists() {
                return Err(VerifierError::MissingFile(obj.relative_path.clone()));
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

        // Verify custody chain
        let custody_path = self.package_dir.join("provenance").join("custody.jsonl");
        if !manifest.custody_digest.is_empty() {
            if !custody_path.exists() {
                return Err(VerifierError::MissingFile("provenance/custody.jsonl".to_string()));
            }
            let custody_bytes = fs::read(&custody_path)?;
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
            let custody_content = fs::read_to_string(&custody_path)?;
            let mut previous_hash = String::new();
            
            for line in custody_content.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let entry: CustodyEntry = serde_json::from_str(line)?;
                
                if entry.step_index > 0 && entry.previous_entry_hash != previous_hash {
                    return Err(VerifierError::BrokenCustodyChain { step: entry.step_index });
                }
                
                let expected_hash = entry.compute_hash();
                
                if expected_hash != entry.entry_hash {
                    return Err(VerifierError::BrokenCustodyChain { step: entry.step_index });
                }
                
                previous_hash = entry.entry_hash;
            }
        }

        // Verify Merkle
        if !manifest.merkle.root_blake3.is_empty() && !manifest.objects.is_empty() {
            let mut hasher = blake3::Hasher::new();
            for obj in &manifest.objects {
                hasher.update(obj.blake3_hex.as_bytes());
            }
            let computed_root_blake3 = hasher.finalize().to_hex().to_string();
            if computed_root_blake3 != manifest.merkle.root_blake3 {
                return Err(VerifierError::MerkleRootMismatch {
                    expected: manifest.merkle.root_blake3.clone(),
                    actual: computed_root_blake3,
                });
            }
        }

        Ok(manifest)
    }
}
