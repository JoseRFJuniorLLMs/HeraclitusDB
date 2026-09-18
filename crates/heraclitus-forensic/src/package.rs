use crate::manifest::{EvidenceManifest, CustodyEntry, EvidenceObject};
use std::path::Path;
use std::fs;
use std::io::Write;
use sha2::{Sha256, Digest};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
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

    pub fn build<P: AsRef<Path>>(&self, target_dir: P) -> Result<(), PackageError> {
        let root = target_dir.as_ref();
        fs::create_dir_all(root)?;
        
        let evidence_dir = root.join("evidence");
        fs::create_dir_all(&evidence_dir)?;

        for (obj, data) in &self.objects_data {
            let obj_path = root.join(&obj.relative_path);
            if let Some(parent) = obj_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&obj_path, data)?;
        }

        let provenance_dir = root.join("provenance");
        fs::create_dir_all(&provenance_dir)?;
        
        let mut custody_file = fs::File::create(provenance_dir.join("custody.jsonl"))?;
        for entry in &self.custody_entries {
            let json = serde_json::to_string(entry)?;
            writeln!(custody_file, "{}", json)?;
        }

        let proofs_dir = root.join("proofs");
        fs::create_dir_all(&proofs_dir)?;
        fs::write(
            proofs_dir.join("merkle.json"),
            serde_json::to_string_pretty(&self.proofs)?
        )?;

        let manifest_json = serde_json::to_string_pretty(&self.manifest)?;
        let manifest_path = root.join("manifest.json");
        fs::write(&manifest_path, &manifest_json)?;

        let mut hasher = Sha256::new();
        hasher.update(manifest_json.as_bytes());
        let sha256_hex = hex::encode(hasher.finalize());
        fs::write(root.join("manifest.sha256"), format!("{}  manifest.json\n", sha256_hex))?;

        Ok(())
    }
}
