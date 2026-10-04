use crate::manifest::{CustodyEntry, EvidenceManifest, EvidenceObject};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Path traversal detected: {0}")]
    PathTraversal(String),
}

pub struct EvidencePackageBuilder {
    manifest: EvidenceManifest,
    custody_entries: Vec<CustodyEntry>,
    proofs: serde_json::Value,
    objects_data: Vec<(EvidenceObject, Vec<u8>)>,
}

impl EvidencePackageBuilder {
    pub fn new(manifest: EvidenceManifest) -> Self {
        Self {
            manifest,
            custody_entries: Vec::new(),
            proofs: serde_json::json!({}),
            objects_data: Vec::new(),
        }
    }

    pub fn add_custody_entry(&mut self, entry: CustodyEntry) {
        self.custody_entries.push(entry);
    }

    pub fn set_proofs(&mut self, proofs: serde_json::Value) {
        self.proofs = proofs;
    }

    pub fn add_object_data(&mut self, object: EvidenceObject, data: Vec<u8>) {
        self.objects_data.push((object, data));
    }

    pub fn build<P: AsRef<Path>>(&mut self, target_dir: P) -> Result<(), PackageError> {
        let root = target_dir.as_ref();
        fs::create_dir_all(root)?;

        for (obj, data) in &self.objects_data {
            if !crate::verifier::validate_safe_relative_path(&obj.relative_path) {
                return Err(PackageError::PathTraversal(obj.relative_path.clone()));
            }

            crate::safe_fs::write(root, &obj.relative_path, data)?;
        }

        if !self.custody_entries.is_empty() {
            let mut custody_bytes = Vec::new();
            for entry in &self.custody_entries {
                let json = serde_json::to_string(entry)?;
                custody_bytes.extend_from_slice(json.as_bytes());
                custody_bytes.push(b'\n');
            }
            crate::safe_fs::write(root, "provenance/custody.jsonl", &custody_bytes)?;

            let mut hasher = Sha256::new();
            hasher.update(&custody_bytes);
            self.manifest.custody_digest = hex::encode(hasher.finalize());
        } else {
            // Se não há entradas de custódia fornecidas mas manifest tem digest dummy, limpa para não falhar
            self.manifest.custody_digest = String::new();
        }

        // Se raiz Merkle não foi informada mas há objetos, calcula automaticamente
        if self.manifest.merkle.root_blake3.is_empty() {
            let mut hasher = blake3::Hasher::new();
            for obj in &self.manifest.objects {
                hasher.update(obj.blake3_hex.as_bytes());
            }
            self.manifest.merkle.root_blake3 = hasher.finalize().to_hex().to_string();
            self.manifest.merkle.leaves_count = self.manifest.objects.len() as u64;
        } else if self.manifest.merkle.leaves_count == 0 {
            self.manifest.merkle.leaves_count = self.manifest.objects.len() as u64;
        }

        let mut sha = Sha256::new();
        for obj in &self.manifest.objects {
            sha.update(obj.sha256_hex.as_bytes());
        }
        if self.manifest.merkle.root_sha256.is_empty() {
            self.manifest.merkle.root_sha256 = hex::encode(sha.finalize());
        }
        if self.proofs == serde_json::json!({}) {
            self.proofs = serde_json::json!({"scheme":"object-digests/1", "objects": self.manifest.objects,
                "root_blake3": self.manifest.merkle.root_blake3, "root_sha256": self.manifest.merkle.root_sha256});
        }
        crate::safe_fs::write(
            root,
            "proofs/merkle.json",
            serde_json::to_string_pretty(&self.proofs)?.as_bytes(),
        )?;

        let manifest_json = serde_json::to_string_pretty(&self.manifest)?;
        crate::safe_fs::write(root, "manifest.json", manifest_json.as_bytes())?;

        let mut hasher = Sha256::new();
        hasher.update(manifest_json.as_bytes());
        let sha256_hex = hex::encode(hasher.finalize());
        crate::safe_fs::write(
            root,
            "manifest.sha256",
            format!("{}  manifest.json\n", sha256_hex).as_bytes(),
        )?;

        Ok(())
    }
}
