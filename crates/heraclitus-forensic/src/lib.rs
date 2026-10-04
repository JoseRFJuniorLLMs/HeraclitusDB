pub mod manifest;
pub mod package;
mod safe_fs;
pub mod verifier;

pub use manifest::*;
pub use package::*;
pub use verifier::*;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use tempfile::tempdir;

    fn create_test_manifest() -> EvidenceManifest {
        EvidenceManifest {
            schema_version: "1.0".to_string(),
            package_id: "pkg-123".to_string(),
            case_id: "case-456".to_string(),
            tenant_id: "tenant-789".to_string(),
            source_database_id: "db-1".to_string(),
            source_build: "build-1".to_string(),
            lsn_range: LsnRange {
                min_lsn: 1,
                max_lsn: 100,
            },
            hlc_range: HlcRange {
                min_hlc: 1,
                max_hlc: 100,
            },
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
        assert!(matches!(
            result,
            Err(VerifierError::ObjectChecksumMismatch { .. })
        ));
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
        assert!(matches!(
            result,
            Err(VerifierError::BrokenCustodyChain { .. })
        ));
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
        assert!(matches!(
            result,
            Err(VerifierError::MerkleRootMismatch { .. })
        ));
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
        assert!(matches!(
            result,
            Err(VerifierError::CustodyDigestMismatch { .. })
        ));
    }

    #[test]
    fn missing_merkle_proof_returns_missing_file_error() {
        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("evidence_pkg");
        let manifest = create_test_manifest();
        let mut builder = EvidencePackageBuilder::new(manifest);
        builder.build(&target_dir).expect("Failed to build package");

        // Remove o proofs/merkle.json
        fs::remove_file(target_dir.join("proofs/merkle.json")).unwrap();

        let verifier = EvidenceVerifier::new(&target_dir);
        let result = verifier.verify();
        assert!(
            matches!(result, Err(VerifierError::MissingFile(ref f)) if f == "proofs/merkle.json"),
            "deve retornar MissingFile para proofs/merkle.json: {:?}",
            result
        );
    }

    #[test]
    fn empty_whitespace_custody_file_fails_with_broken_custody_chain() {
        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("evidence_pkg");
        let manifest = create_test_manifest();
        let mut builder = EvidencePackageBuilder::new(manifest);
        let mut entry = CustodyEntry {
            step_index: 0,
            timestamp_secs: 1600000001,
            action: CustodyAction::Reconhecimento,
            operator_principal: "op-1".to_string(),
            terminal_or_node: "node-1".to_string(),
            previous_entry_hash: "".to_string(),
            entry_hash: "".to_string(),
        };
        entry.entry_hash = entry.compute_hash();
        builder.add_custody_entry(entry);
        builder.build(&target_dir).expect("Failed to build package");

        // Substitui custody.jsonl por espaços em branco e atualiza custody_digest no manifest
        let empty_content = b"\n   \n\t\n";
        fs::write(target_dir.join("provenance/custody.jsonl"), empty_content).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(empty_content);
        let empty_digest = hex::encode(hasher.finalize());

        let manifest_file = target_dir.join("manifest.json");
        let mut m: EvidenceManifest =
            serde_json::from_slice(&fs::read(&manifest_file).unwrap()).unwrap();
        m.custody_digest = empty_digest;
        let m_bytes = serde_json::to_vec_pretty(&m).unwrap();
        fs::write(&manifest_file, &m_bytes).unwrap();
        let mut m_hasher = Sha256::new();
        m_hasher.update(&m_bytes);
        fs::write(
            target_dir.join("manifest.sha256"),
            format!("{}  manifest.json\n", hex::encode(m_hasher.finalize())),
        )
        .unwrap();

        let verifier = EvidenceVerifier::new(&target_dir);
        let result = verifier.verify();
        assert!(
            matches!(result, Err(VerifierError::BrokenCustodyChain { step: 0 })),
            "cadeia vazia deve falhar como BrokenCustodyChain no step 0: {:?}",
            result
        );
    }

    #[test]
    fn builder_populates_leaves_count_when_root_blake3_is_manually_set() {
        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("evidence_pkg");
        let mut manifest = create_test_manifest();
        let data = b"test object content";
        let sha256_hex = hex::encode(Sha256::digest(data));
        let blake3_hex = blake3::hash(data).to_hex().to_string();
        let obj = EvidenceObject {
            object_id: "obj-manual".to_string(),
            relative_path: "evidence/manual.txt".to_string(),
            size_bytes: data.len() as u64,
            sha256_hex,
            blake3_hex: blake3_hex.clone(),
            content_type: "text/plain".to_string(),
            source_lsn: Some(1),
        };
        manifest.objects.push(obj.clone());
        // A raiz é o hash de blake3_hex
        let mut h = blake3::Hasher::new();
        h.update(blake3_hex.as_bytes());
        manifest.merkle.root_blake3 = h.finalize().to_hex().to_string();
        manifest.merkle.leaves_count = 0; // omitido pelo chamador

        let mut builder = EvidencePackageBuilder::new(manifest);
        builder.add_object_data(obj, data.to_vec());
        builder.build(&target_dir).expect("Failed to build package");

        let verifier = EvidenceVerifier::new(&target_dir);
        let verified = verifier.verify().expect("deve verificar com sucesso");
        assert_eq!(verified.merkle.leaves_count, 1);
    }
}

#[cfg(test)]
mod audit_regressions {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    fn manifest() -> EvidenceManifest {
        serde_json::from_value(serde_json::json!({
            "schema_version":"1.0", "package_id":"p", "case_id":"c", "tenant_id":"t",
            "source_database_id":"d", "source_build":"b", "lsn_range":{"min_lsn":0,"max_lsn":0},
            "hlc_range":{"min_hlc":0,"max_hlc":0}, "objects":[],
            "merkle":{"root_blake3":"","root_sha256":"","leaves_count":0}, "custody_digest":"",
            "export_identity":"operator", "export_reason":"test", "created_at_claimed":1,
            "trusted_timestamps":[], "signatures":[]
        }))
        .unwrap()
    }
    fn rewrite(root: &std::path::Path, m: &EvidenceManifest) {
        let bytes = serde_json::to_vec_pretty(m).unwrap();
        fs::write(
            root.join("manifest.sha256"),
            hex::encode(Sha256::digest(&bytes)),
        )
        .unwrap();
        fs::write(root.join("manifest.json"), bytes).unwrap();
    }
    #[test]
    fn signature_requires_pinned_identity_and_authenticates_full_manifest() {
        use heraclitus_compliance::signer::{InstitutionalSigner, SoftKeySigner};
        let dir = tempfile::tempdir().unwrap();
        EvidencePackageBuilder::new(manifest())
            .build(dir.path())
            .unwrap();
        let mut m: EvidenceManifest =
            serde_json::from_slice(&fs::read(dir.path().join("manifest.json")).unwrap()).unwrap();
        let signer = SoftKeySigner::generate("institution");
        let signature = signer
            .sign_snapshot(&evidence_signing_bytes(&m).unwrap())
            .unwrap();
        m.signatures.push(EvidenceSignature {
            signer_identity: signature.subject.clone(),
            signature_hex: hex::encode(signature.signature),
            algorithm: "ECDSA-P256-SHA256".into(),
        });
        rewrite(dir.path(), &m);
        let verifier = EvidenceVerifier::new(dir.path());
        assert!(verifier.verify().is_err());
        let mut trust = EvidenceTrustPolicy {
            require_signature: true,
            ..Default::default()
        };
        assert!(verifier.verify_with_trust(&trust).is_err());
        trust
            .signer_keys
            .insert(signature.subject, signature.public_key_sec1);
        assert!(verifier.verify_with_trust(&trust).is_ok());
        m.case_id.push('x');
        rewrite(dir.path(), &m);
        assert!(verifier.verify_with_trust(&trust).is_err());
    }
    #[test]
    fn invalid_schema_count_timestamp_and_proof_never_pass() {
        let dir = tempfile::tempdir().unwrap();
        EvidencePackageBuilder::new(manifest())
            .build(dir.path())
            .unwrap();
        let m: EvidenceManifest =
            serde_json::from_slice(&fs::read(dir.path().join("manifest.json")).unwrap()).unwrap();
        for bad in [
            {
                let mut v = m.clone();
                v.schema_version = "999".into();
                v
            },
            {
                let mut v = m.clone();
                v.merkle.leaves_count = 1;
                v
            },
            {
                let mut v = m.clone();
                v.trusted_timestamps.push(TrustedTimestamp {
                    authority: "fake".into(),
                    timestamp_secs: 1,
                    token: "00".into(),
                });
                v
            },
        ] {
            rewrite(dir.path(), &bad);
            assert!(EvidenceVerifier::new(dir.path()).verify().is_err());
        }
        rewrite(dir.path(), &m);
        fs::write(dir.path().join("proofs/merkle.json"), b"{}").unwrap();
        assert!(EvidenceVerifier::new(dir.path()).verify().is_err());
    }
    #[test]
    fn second_genesis_and_terminal_mutation_are_detected() {
        let entry = CustodyEntry {
            step_index: 0,
            timestamp_secs: 1,
            action: CustodyAction::Coleta,
            operator_principal: "operator".into(),
            terminal_or_node: "node".into(),
            previous_entry_hash: String::new(),
            entry_hash: String::new(),
        };
        let mut changed = entry.clone();
        changed.terminal_or_node.push('x');
        assert_ne!(entry.compute_hash(), changed.compute_hash());
        let dir = tempfile::tempdir().unwrap();
        let mut builder = EvidencePackageBuilder::new(manifest());
        let mut first = entry.clone();
        first.entry_hash = first.compute_hash();
        builder.add_custody_entry(first.clone());
        builder.add_custody_entry(first);
        builder.build(dir.path()).unwrap();
        assert!(matches!(
            EvidenceVerifier::new(dir.path()).verify(),
            Err(VerifierError::BrokenCustodyChain { .. })
        ));
    }
    #[test]
    fn builder_never_overwrites_existing_hardlink() {
        let dir = tempfile::tempdir().unwrap();
        let external = dir.path().join("outside");
        fs::write(&external, b"preserve").unwrap();
        let root = dir.path().join("package");
        fs::create_dir(&root).unwrap();
        fs::hard_link(&external, root.join("manifest.json")).unwrap();
        assert!(EvidencePackageBuilder::new(manifest())
            .build(&root)
            .is_err());
        assert_eq!(fs::read(external).unwrap(), b"preserve");
    }
    #[cfg(windows)]
    #[test]
    fn junction_is_refused_for_read_and_write() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        let root = dir.path().join("package");
        fs::create_dir(&outside).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(outside.join("secret"), b"preserve").unwrap();
        let junction = root.join("evidence");
        assert!(std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .unwrap()
            .status
            .success());
        assert!(crate::safe_fs::read(&root, "evidence/secret", 100).is_err());
        assert!(crate::safe_fs::write(&root, "evidence/new", b"bad").is_err());
        assert!(!outside.join("new").exists());
        fs::remove_dir(junction).unwrap();
    }
}
