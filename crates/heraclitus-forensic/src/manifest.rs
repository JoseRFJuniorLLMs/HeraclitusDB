use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceManifest {
    pub schema_version: String,
    pub package_id: String,
    pub case_id: String,
    pub tenant_id: String,
    pub source_database_id: String,
    pub source_build: String,
    pub lsn_range: LsnRange,
    pub hlc_range: HlcRange,
    pub objects: Vec<EvidenceObject>,
    pub merkle: MerkleEvidence,
    pub custody_digest: String,
    pub export_identity: String,
    pub export_reason: String,
    pub created_at_claimed: u64,
    pub trusted_timestamps: Vec<TrustedTimestamp>,
    pub signatures: Vec<EvidenceSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LsnRange {
    pub min_lsn: u64,
    pub max_lsn: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HlcRange {
    pub min_hlc: u64,
    pub max_hlc: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceObject {
    pub object_id: String,
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256_hex: String,
    pub blake3_hex: String,
    pub content_type: String,
    pub source_lsn: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleEvidence {
    pub root_blake3: String,
    pub root_sha256: String,
    pub leaves_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedTimestamp {
    pub authority: String,
    pub timestamp_secs: u64,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSignature {
    pub signer_identity: String,
    pub signature_hex: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodyEntry {
    pub step_index: u64,
    pub timestamp_secs: u64,
    pub action: CustodyAction,
    pub operator_principal: String,
    pub terminal_or_node: String,
    pub previous_entry_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CustodyAction {
    /// 1. Reconhecimento (CPP Art. 158-B, I)
    Reconhecimento,
    /// 2. Isolamento (CPP Art. 158-B, II)
    Isolamento,
    /// 3. Fixação (CPP Art. 158-B, III)
    Fixacao,
    /// 4. Coleta (CPP Art. 158-B, IV)
    Coleta,
    /// 5. Acondicionamento (CPP Art. 158-B, V)
    Acondicionamento,
    /// 6. Transporte (CPP Art. 158-B, VI)
    Transporte,
    /// 7. Recebimento (CPP Art. 158-B, VII)
    Recebimento,
    /// 8. Processamento (CPP Art. 158-B, VIII)
    Processamento,
    /// 9. Armazenamento / Guarda (CPP Art. 158-B, IX)
    Armazenamento,
    Guarda,
    /// 10. Descarte (CPP Art. 158-B, X)
    Descarte,
}

impl CustodyEntry {
    pub fn compute_hash(&self) -> String {
        use sha2::{Sha256, Digest};
        let action_str = serde_json::to_string(&self.action).unwrap_or_default();
        let entry_str = format!(
            "{}:{}:{}:{}:{}",
            self.step_index,
            self.timestamp_secs,
            action_str,
            self.operator_principal,
            self.previous_entry_hash
        );
        let mut hasher = Sha256::new();
        hasher.update(entry_str.as_bytes());
        hex::encode(hasher.finalize())
    }
}
