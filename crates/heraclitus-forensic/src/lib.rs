pub mod manifest;
pub mod package;
pub mod verifier;

pub use manifest::*;
pub use package::*;
pub use verifier::*;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    use sha2::{Sha256, Digest};

    fn create_test_manifest() -> EvidenceManifest {
        EvidenceManifest {
            schema_version: "1.0".to_string(),
            package_id: "pkg-123".to_string(),
            case_id: "case-456".to_string(),
            tenant_id: "tenant-789".to_string(),
            source_database_id: "db-1".to_string(),
            source_build: "build-1".to_string(),
            lsn_range: LsnRange { min_lsn: 1, max_lsn: 100 },
            hlc_range: HlcRange { min_hlc: 1, max_hlc: 100 },
            objects: vec![],
            merkle: MerkleEvidence {
                root_blake3: String::new(),
                root_sha256: String::new(),
                leaves_count: 0,
            },
            custody_digest: "digest".to_string(),
            export_identity: "exporter".to_string(),
            export_reason: "investigation".to_string(),
            created_at_claimed: 1600000000,
            trusted_timestamps: vec![],
            signatures: vec![],
        }
    }

    #[test]
    fn test_package_creation_and_verification() {
        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("evidence_pkg");
        
        let mut manifest = create_test_manifest();
        
        let data = b"test content";
        let mut sha256 = Sha256::new();
        sha256.update(data);
        let sha256_hex = hex::encode(sha256.finalize());
        let blake3_hex = blake3::hash(data).to_hex().to_string();
        
        let obj = EvidenceObject {
            object_id: "obj-1".to_string(),
            relative_path: "evidence/file1.txt".to_string(),
            size_bytes: data.len() as u64,
            sha256_hex,
            blake3_hex,
            content_type: "text/plain".to_string(),
            source_lsn: Some(10),
        };
        
        manifest.objects.push(obj.clone());
        
        let mut builder = EvidencePackageBuilder::new(manifest);
        
        let mut entry1 = CustodyEntry {
            step_index: 0,
            timestamp_secs: 1600000001,
            action: CustodyAction::Coleta,
            operator_principal: "op-1".to_string(),
            terminal_or_node: "node-1".to_string(),
            previous_entry_hash: "".to_string(),
            entry_hash: "".to_string(),
        };
        entry1.entry_hash = entry1.compute_hash();
        
        let mut entry2 = CustodyEntry {
            step_index: 1,
            timestamp_secs: 1600000002,
            action: CustodyAction::Guarda,
            operator_principal: "op-2".to_string(),
            terminal_or_node: "node-2".to_string(),
            previous_entry_hash: entry1.entry_hash.clone(),
            entry_hash: "".to_string(),
        };
        entry2.entry_hash = entry2.compute_hash();
        
        builder.add_custody_entry(entry1);
        builder.add_custody_entry(entry2);
        builder.add_object_data(obj, data.to_vec());
        
        builder.build(&target_dir).expect("Failed to build package");
        
        let verifier = EvidenceVerifier::new(&target_dir);
        let result = verifier.verify();
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    #[test]
    fn test_tampered_object_fails() {
        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("evidence_pkg");
        
        let mut manifest = create_test_manifest();
        
        let data = b"test content";
        let mut sha256 = Sha256::new();
        sha256.update(data);
        let sha256_hex = hex::encode(sha256.finalize());
        let blake3_hex = blake3::hash(data).to_hex().to_string();
        
        let obj = EvidenceObject {
            object_id: "obj-1".to_string(),
            relative_path: "evidence/file1.txt".to_string(),
            size_bytes: data.len() as u64,
            sha256_hex,
            blake3_hex,
            content_type: "text/plain".to_string(),
            source_lsn: Some(10),
        };
        
        manifest.objects.push(obj.clone());
        
        let mut builder = EvidencePackageBuilder::new(manifest);
        builder.add_object_data(obj, data.to_vec());
        builder.build(&target_dir).expect("Failed to build package");
        
        // Tamper with the object
        fs::write(target_dir.join("evidence/file1.txt"), b"tampered content").unwrap();
        
        let verifier = EvidenceVerifier::new(&target_dir);
        let result = verifier.verify();
        assert!(matches!(result, Err(VerifierError::ObjectChecksumMismatch { .. })));
    }

    #[test]
    fn test_broken_custody_chain_fails() {
        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("evidence_pkg");
        
        let manifest = create_test_manifest();
        let mut builder = EvidencePackageBuilder::new(manifest);
        
        let mut entry1 = CustodyEntry {
            step_index: 0,
            timestamp_secs: 1600000001,
            action: CustodyAction::Coleta,
            operator_principal: "op-1".to_string(),
            terminal_or_node: "node-1".to_string(),
            previous_entry_hash: "".to_string(),
            entry_hash: "".to_string(),
        };
        entry1.entry_hash = entry1.compute_hash();
        
        let mut entry2 = CustodyEntry {
            step_index: 1,
            timestamp_secs: 1600000002,
            action: CustodyAction::Guarda,
            operator_principal: "op-2".to_string(),
            terminal_or_node: "node-2".to_string(),
            previous_entry_hash: "invalid-previous-hash".to_string(), // broken chain
            entry_hash: "".to_string(),
        };
        entry2.entry_hash = entry2.compute_hash();
        
        builder.add_custody_entry(entry1);
        builder.add_custody_entry(entry2);
        
        builder.build(&target_dir).expect("Failed to build package");
        
        let verifier = EvidenceVerifier::new(&target_dir);
        let result = verifier.verify();
        assert!(matches!(result, Err(VerifierError::BrokenCustodyChain { .. })));
    }

    #[test]
    fn test_merkle_root_mismatch_fails() {
        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("evidence_pkg");
        
        let mut manifest = create_test_manifest();
        manifest.merkle.root_blake3 = "bad-merkle-root-blake3".to_string();
        
        let data = b"test content";
        let mut sha256 = Sha256::new();
        sha256.update(data);
        let sha256_hex = hex::encode(sha256.finalize());
        let blake3_hex = blake3::hash(data).to_hex().to_string();
        
        let obj = EvidenceObject {
            object_id: "obj-1".to_string(),
            relative_path: "evidence/file1.txt".to_string(),
            size_bytes: data.len() as u64,
            sha256_hex,
            blake3_hex,
            content_type: "text/plain".to_string(),
            source_lsn: Some(10),
        };
        manifest.objects.push(obj.clone());
        
        let mut builder = EvidencePackageBuilder::new(manifest);
        builder.add_object_data(obj, data.to_vec());
        builder.build(&target_dir).expect("Failed to build package");
        
        let verifier = EvidenceVerifier::new(&target_dir);
        let result = verifier.verify();
        assert!(matches!(result, Err(VerifierError::MerkleRootMismatch { .. })));
    }

    #[test]
    fn test_path_traversal_rejected() {
        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("evidence_pkg");
        
        let manifest = create_test_manifest();
        let obj = EvidenceObject {
            object_id: "evil-obj".to_string(),
            relative_path: "../../evil.txt".to_string(),
            size_bytes: 4,
            sha256_hex: "dummy".to_string(),
            blake3_hex: "dummy".to_string(),
            content_type: "text/plain".to_string(),
            source_lsn: None,
        };
        let mut builder = EvidencePackageBuilder::new(manifest);
        builder.add_object_data(obj, b"evil".to_vec());
        let result = builder.build(&target_dir);
        assert!(matches!(result, Err(PackageError::PathTraversal(_))));
    }

    #[test]
    fn test_tampered_custody_digest_fails() {
        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("evidence_pkg");
        
        let manifest = create_test_manifest();
        let mut builder = EvidencePackageBuilder::new(manifest);
        let mut entry = CustodyEntry {
            step_index: 0,
            timestamp_secs: 1600000001,
            action: CustodyAction::Reconhecimento,
            operator_principal: "perito-1".to_string(),
            terminal_or_node: "terminal-01".to_string(),
            previous_entry_hash: "".to_string(),
            entry_hash: "".to_string(),
        };
        entry.entry_hash = entry.compute_hash();
        builder.add_custody_entry(entry);
        builder.build(&target_dir).expect("Failed to build package");

        // Altera o arquivo custody.jsonl sem alterar manifest
        let custody_file = target_dir.join("provenance/custody.jsonl");
        fs::write(custody_file, b"{\"tampered\": true}\n").unwrap();

        let verifier = EvidenceVerifier::new(&target_dir);
        let result = verifier.verify();
        assert!(matches!(result, Err(VerifierError::CustodyDigestMismatch { .. })));
    }
}
