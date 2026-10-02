use crate::manifest::{CustodyEntry, EvidenceManifest};
use sha2::{Digest, Sha256};
use std::path::Path;
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
    ObjectChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("Broken custody chain at step {step}")]
    BrokenCustodyChain { step: u64 },
    #[error("Custody digest mismatch: expected {expected}, got {actual}")]
    CustodyDigestMismatch { expected: String, actual: String },
    #[error("Merkle root mismatch: expected {expected}, got {actual}")]
    MerkleRootMismatch { expected: String, actual: String },
    #[error("Missing file: {0}")]
    MissingFile(String),
    #[error("Invalid evidence: {0}")]
    Invalid(String),
    #[error("Path traversal detected: {0}")]
    PathTraversal(String),
}

pub(crate) fn validate_safe_relative_path(path_str: &str) -> bool {
    crate::safe_fs::valid(path_str)
}

pub struct EvidenceVerifier {
    package_dir: std::path::PathBuf,
}

/// Trust material is supplied by the operator, never learned from a package.
/// A successful integrity-only verification makes no institutional claim.
#[derive(Default)]
pub struct EvidenceTrustPolicy {
    pub signer_keys: std::collections::BTreeMap<String, Vec<u8>>,
    pub timestamp_authorities:
        std::collections::BTreeMap<String, heraclitus_compliance::icp::IcpBrasilTimestampVerifier>,
    pub require_signature: bool,
    pub require_timestamp: bool,
    pub now_unix_ms: u64,
}

pub fn evidence_signing_bytes(manifest: &EvidenceManifest) -> Result<Vec<u8>, serde_json::Error> {
    let mut unsigned = manifest.clone();
    unsigned.signatures.clear();
    unsigned.trusted_timestamps.clear();
    serde_json::to_vec(&("heraclitus-forensic-manifest-v2", unsigned))
}

impl EvidenceVerifier {
    pub fn new<P: AsRef<Path>>(package_dir: P) -> Self {
        Self {
            package_dir: package_dir.as_ref().to_path_buf(),
        }
    }

    pub fn verify(&self) -> Result<EvidenceManifest, VerifierError> {
        self.verify_inner(None)
    }

    pub fn verify_with_trust(
        &self,
        policy: &EvidenceTrustPolicy,
    ) -> Result<EvidenceManifest, VerifierError> {
        self.verify_inner(Some(policy))
    }

    fn verify_inner(
        &self,
        trust: Option<&EvidenceTrustPolicy>,
    ) -> Result<EvidenceManifest, VerifierError> {
        let manifest_path = self.package_dir.join("manifest.json");
        if !manifest_path.exists() {
            return Err(VerifierError::MissingFile("manifest.json".to_string()));
        }

        let manifest_bytes = crate::safe_fs::read(&self.package_dir, "manifest.json", 16 << 20)?;

        let manifest_sha256_path = self.package_dir.join("manifest.sha256");
        if !manifest_sha256_path.exists() {
            return Err(VerifierError::MissingFile("manifest.sha256".into()));
        }
        {
            let sha256_content = String::from_utf8(crate::safe_fs::read(
                &self.package_dir,
                "manifest.sha256",
                1024,
            )?)
            .map_err(|e| VerifierError::Invalid(e.to_string()))?;
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

        if manifest.schema_version != "1.0"
            || manifest.lsn_range.min_lsn > manifest.lsn_range.max_lsn
            || manifest.hlc_range.min_hlc > manifest.hlc_range.max_hlc
            || manifest.objects.len() > 100_000
        {
            return Err(VerifierError::Invalid(
                "schema, range or object-count budget".into(),
            ));
        }
        // Compatibility integrity verification must NEVER accept unverified
        // trust claims. Signature/TSA verification needs externally trusted roots.
        if trust.is_none()
            && (!manifest.signatures.is_empty() || !manifest.trusted_timestamps.is_empty())
        {
            return Err(VerifierError::Invalid("signature/timestamp require an authenticated verifier; integrity-only profile rejects them".into()));
        }
        if let Some(policy) = trust {
            if (policy.require_signature && manifest.signatures.is_empty())
                || (policy.require_timestamp && manifest.trusted_timestamps.is_empty())
            {
                return Err(VerifierError::Invalid(
                    "required signature/timestamp absent".into(),
                ));
            }
            let bytes = evidence_signing_bytes(&manifest)?;
            for sig in &manifest.signatures {
                let key = policy
                    .signer_keys
                    .get(&sig.signer_identity)
                    .ok_or_else(|| VerifierError::Invalid("untrusted signer".into()))?;
                let signature = hex::decode(&sig.signature_hex)
                    .map_err(|e| VerifierError::Invalid(e.to_string()))?;
                let valid = match sig.algorithm.as_str() {
                    "ECDSA-P256-SHA256" => {
                        use p256::ecdsa::signature::Verifier;
                        match (
                            p256::ecdsa::VerifyingKey::from_sec1_bytes(key),
                            p256::ecdsa::Signature::from_slice(&signature),
                        ) {
                            (Ok(key), Ok(sig)) => key.verify(&bytes, &sig).is_ok(),
                            _ => false,
                        }
                    }
                    "ML-DSA-65" => {
                        heraclitus_compliance::signer::MlDsaSigner::verify(key, &bytes, &signature)
                    }
                    "ECDSA-P256+ML-DSA-65" => {
                        heraclitus_compliance::signer::HybridSigner::verify(key, &bytes, &signature)
                    }
                    _ => false,
                };
                if !valid {
                    return Err(VerifierError::Invalid(
                        "invalid institutional signature".into(),
                    ));
                }
            }
            let imprint = Sha256::digest(&bytes);
            for ts in &manifest.trusted_timestamps {
                let authority =
                    policy
                        .timestamp_authorities
                        .get(&ts.authority)
                        .ok_or_else(|| {
                            VerifierError::Invalid("untrusted timestamp authority".into())
                        })?;
                let token =
                    hex::decode(&ts.token).map_err(|e| VerifierError::Invalid(e.to_string()))?;
                let validated = authority
                    .verify(&token, &imprint, None, policy.now_unix_ms)
                    .map_err(|e| VerifierError::Invalid(e.to_string()))?;
                if validated.gen_unix_ms / 1000 != ts.timestamp_secs {
                    return Err(VerifierError::Invalid(
                        "claimed timestamp differs from signed genTime".into(),
                    ));
                }
            }
        }
        let mut object_ids = std::collections::HashSet::new();
        let mut object_paths = std::collections::HashSet::new();
        let mut total_bytes = 0u64;
        // Verify objects
        for obj in &manifest.objects {
            if !validate_safe_relative_path(&obj.relative_path) {
                return Err(VerifierError::PathTraversal(obj.relative_path.clone()));
            }

            let obj_path = self.package_dir.join(&obj.relative_path);
            if !obj_path.exists() {
                return Err(VerifierError::MissingFile(obj.relative_path.clone()));
            }
            if !object_ids.insert(&obj.object_id) || !object_paths.insert(&obj.relative_path) {
                return Err(VerifierError::Invalid("duplicate object ID/path".into()));
            }
            total_bytes = total_bytes
                .checked_add(obj.size_bytes)
                .ok_or_else(|| VerifierError::Invalid("byte overflow".into()))?;
            if total_bytes > (1 << 30) {
                return Err(VerifierError::Invalid("package byte budget".into()));
            }
            let mut file = crate::safe_fs::open(&self.package_dir, &obj.relative_path, false)?;
            if file.metadata()?.len() != obj.size_bytes {
                return Err(VerifierError::ObjectChecksumMismatch {
                    path: obj.relative_path.clone(),
                    expected: format!("{} bytes", obj.size_bytes),
                    actual: format!("{} bytes", file.metadata()?.len()),
                });
            }
            let mut sha256_hasher = Sha256::new();
            let mut blake3_hasher = blake3::Hasher::new();
            let mut buf = [0; 65536];
            let mut seen = 0u64;
            loop {
                use std::io::Read;
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                seen += n as u64;
                if seen > obj.size_bytes {
                    return Err(VerifierError::Invalid("object changed during read".into()));
                }
                sha256_hasher.update(&buf[..n]);
                blake3_hasher.update(&buf[..n]);
            }
            if seen != obj.size_bytes {
                return Err(VerifierError::Invalid(
                    "object truncated during read".into(),
                ));
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

        // Verify custody chain
        let custody_path = self.package_dir.join("provenance").join("custody.jsonl");
        if !manifest.custody_digest.is_empty() {
            if !custody_path.exists() {
                return Err(VerifierError::MissingFile(
                    "provenance/custody.jsonl".to_string(),
                ));
            }
            let custody_bytes =
                crate::safe_fs::read(&self.package_dir, "provenance/custody.jsonl", 16 << 20)?;
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
            let custody_content = String::from_utf8(crate::safe_fs::read(
                &self.package_dir,
                "provenance/custody.jsonl",
                16 << 20,
            )?)
            .map_err(|e| VerifierError::Invalid(e.to_string()))?;
            let mut next_step = 0u64;
            let mut previous_timestamp = 0u64;
            if manifest.custody_digest.is_empty() {
                return Err(VerifierError::Invalid("custody digest missing".into()));
            }
            let mut previous_hash = String::new();

            for line in custody_content.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let entry: CustodyEntry = serde_json::from_str(line)?;

                if entry.step_index != next_step
                    || entry.previous_entry_hash != previous_hash
                    || entry.timestamp_secs < previous_timestamp
                {
                    return Err(VerifierError::BrokenCustodyChain {
                        step: entry.step_index,
                    });
                }

                let expected_hash = entry.compute_hash();

                if expected_hash != entry.entry_hash {
                    return Err(VerifierError::BrokenCustodyChain {
                        step: entry.step_index,
                    });
                }

                previous_timestamp = entry.timestamp_secs;
                next_step += 1;
                previous_hash = entry.entry_hash;
            }
        }

        // Verify Merkle
        {
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

        if manifest.merkle.leaves_count != manifest.objects.len() as u64 {
            return Err(VerifierError::Invalid("leaf count mismatch".into()));
        }
        let mut sha = Sha256::new();
        for obj in &manifest.objects {
            sha.update(obj.sha256_hex.as_bytes());
        }
        if hex::encode(sha.finalize()) != manifest.merkle.root_sha256 {
            return Err(VerifierError::Invalid(
                "SHA256 object commitment mismatch".into(),
            ));
        }
        let proof: serde_json::Value = serde_json::from_slice(&crate::safe_fs::read(
            &self.package_dir,
            "proofs/merkle.json",
            16 << 20,
        )?)?;
        if proof
            != serde_json::json!({"scheme":"object-digests/1", "objects":manifest.objects,
            "root_blake3":manifest.merkle.root_blake3, "root_sha256":manifest.merkle.root_sha256})
        {
            return Err(VerifierError::Invalid(
                "invalid object commitment proof; this profile does not claim HRKL inclusion"
                    .into(),
            ));
        }
        Ok(manifest)
    }
}
