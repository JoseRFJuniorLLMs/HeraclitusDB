//! Legal receipts — what an auditor actually keeps.
//!
//! For each anchored watermark we persist the raw token (`<lsn>.tst`) plus a
//! human/machine-readable line in `manifest.jsonl`. The manifest records the
//! recomputable commitment (watermark LSN, aggregate root, SHA-256 imprint) so
//! verification needs only the receipt + the immutable log.

use crate::commit::Commitment;
use crate::CompError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One notarized anchor, serialized into the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegalReceipt {
    /// Watermark LSN this receipt covers (every event with `lsn <= this`).
    pub lsn: u64,
    /// Sealed segments folded into the commitment.
    pub segments: u64,
    /// Aggregate blake3 Merkle root (hex).
    pub root_hex: String,
    /// SHA-256 imprint that was timestamped (hex).
    pub imprint_hex: String,
    /// Authority time (ms since Unix epoch).
    pub gen_unix_ms: u64,
    /// Authority/policy name.
    pub policy: String,
    /// Token file name relative to the receipts dir.
    pub token_file: String,
}

/// Lowercase hex of a byte slice (no external dep).
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join("manifest.jsonl")
}

fn token_name(lsn: u64) -> String {
    format!("{lsn:020}.tst")
}

/// Persist a token + manifest entry, returning the receipt.
pub fn persist(
    dir: impl AsRef<Path>,
    commitment: &Commitment,
    imprint: &[u8; 32],
    policy: &str,
    gen_unix_ms: u64,
    token: &[u8],
) -> Result<LegalReceipt, CompError> {
    let dir = dir.as_ref();
    std::fs::create_dir_all(dir)?;

    let token_file = token_name(commitment.lsn);
    std::fs::write(dir.join(&token_file), token)?;

    let receipt = LegalReceipt {
        lsn: commitment.lsn,
        segments: commitment.segments,
        root_hex: to_hex(&commitment.root),
        imprint_hex: to_hex(imprint),
        gen_unix_ms,
        policy: policy.to_string(),
        token_file,
    };

    let mut line = serde_json::to_string(&receipt)?;
    line.push('\n');
    // append-only manifest, mirroring the log's own ethos
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(manifest_path(dir))?;
    f.write_all(line.as_bytes())?;

    Ok(receipt)
}

/// Read all receipts from the manifest, oldest first.
pub fn load_manifest(dir: impl AsRef<Path>) -> Result<Vec<LegalReceipt>, CompError> {
    let path = manifest_path(dir.as_ref());
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str(line)?);
    }
    Ok(out)
}

/// Read the raw token bytes referenced by a receipt.
pub fn read_token(dir: impl AsRef<Path>, receipt: &LegalReceipt) -> Result<Vec<u8>, CompError> {
    Ok(std::fs::read(dir.as_ref().join(&receipt.token_file))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn persist_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let c = Commitment {
            lsn: 42,
            root: [3u8; 32],
            segments: 2,
        };
        let imprint = [4u8; 32];
        let r = persist(dir.path(), &c, &imprint, "ACT-dev", 1700, b"token-bytes").unwrap();
        assert_eq!(r.lsn, 42);
        let all = load_manifest(dir.path()).unwrap();
        assert_eq!(all, vec![r.clone()]);
        assert_eq!(read_token(dir.path(), &r).unwrap(), b"token-bytes");
    }
}
