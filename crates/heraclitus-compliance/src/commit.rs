//! Compliance commitment — a single 32-byte fingerprint of the river up to a
//! watermark LSN.
//!
//! The log already seals each segment with a blake3 Merkle root over its record
//! hashes. To anchor the *whole state* with one external timestamp we compute an
//! aggregate root: a blake3 Merkle root **over the sealed segment roots** up to
//! (and including) a watermark LSN. Re-running it over the same sealed segments
//! yields the same bytes — so a notarized commitment is reproducible by any
//! auditor straight from the log files.
//!
//! Only fully-sealed segments are covered. The active (tail) segment is still
//! mutable, so it is deliberately excluded; the watermark advances only as
//! segments seal.

use heraclitus_core::Lsn;
use heraclitus_log::{merkle_root, Log};

/// Domain separator so a compliance imprint can never be confused with a raw
/// segment/record hash.
pub const COMMIT_DOMAIN: &[u8] = b"heraclitus-compliance/commit/v1";

/// A reproducible commitment to all sealed events with `lsn <= lsn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment {
    /// Watermark: this commitment covers every event up to and including `lsn`.
    pub lsn: Lsn,
    /// Aggregate blake3 Merkle root over the covered sealed-segment roots.
    pub root: [u8; 32],
    /// Number of sealed segments folded into `root`.
    pub segments: u64,
}

impl Commitment {
    /// SHA-256 message imprint to hand to an RFC 3161 TSA.
    ///
    /// ICP-Brasil / Observatório Nacional timestamp authorities accept a digest
    /// under a registered algorithm OID (SHA-256/512) — **not** blake3. So we
    /// fold the blake3 commitment into SHA-256 over a canonical, domain-tagged
    /// serialization of `(domain, lsn, root)`. The ACT timestamps this digest;
    /// the auditor recomputes blake3→SHA-256 from the raw log and compares.
    pub fn message_imprint_sha256(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(COMMIT_DOMAIN);
        h.update(self.lsn.to_be_bytes());
        h.update(self.root);
        let out = h.finalize();
        let mut d = [0u8; 32];
        d.copy_from_slice(&out);
        d
    }
}

/// Aggregate blake3 Merkle root over a list of segment roots (exposed so tests
/// and auditors can reproduce it without a `Log`).
pub fn aggregate_root(segment_roots: &[[u8; 32]]) -> [u8; 32] {
    merkle_root(segment_roots)
}

/// The highest watermark currently anchorable: the max `max_lsn` across sealed
/// segments (0 when nothing is sealed yet).
pub fn current_watermark(log: &Log) -> Lsn {
    log.sealed_segments()
        .iter()
        .map(|s| s.max_lsn)
        .max()
        .unwrap_or(0)
}

/// Build the commitment over every sealed segment fully contained in
/// `[0, watermark_lsn]`.
pub fn commit_at(log: &Log, watermark_lsn: Lsn) -> Commitment {
    let mut segs: Vec<_> = log
        .sealed_segments()
        .into_iter()
        .filter(|s| s.max_lsn <= watermark_lsn && s.blake3_root.is_some())
        .collect();
    segs.sort_by_key(|s| s.base_lsn);
    let roots: Vec<[u8; 32]> = segs.iter().map(|s| s.blake3_root.unwrap()).collect();
    Commitment {
        lsn: watermark_lsn,
        root: aggregate_root(&roots),
        segments: roots.len() as u64,
    }
}

/// Convenience: commit at the current watermark.
pub fn commit_now(log: &Log) -> Commitment {
    commit_at(log, current_watermark(log))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_is_deterministic_and_order_sensitive() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(aggregate_root(&[a, b]), aggregate_root(&[a, b]));
        assert_ne!(aggregate_root(&[a, b]), aggregate_root(&[b, a]));
    }

    #[test]
    fn imprint_is_32_bytes_and_binds_lsn() {
        let c1 = Commitment {
            lsn: 100,
            root: [7u8; 32],
            segments: 3,
        };
        let c2 = Commitment {
            lsn: 101,
            root: [7u8; 32],
            segments: 3,
        };
        let i1 = c1.message_imprint_sha256();
        assert_eq!(i1.len(), 32);
        // a different watermark over the same root yields a different imprint
        assert_ne!(i1, c2.message_imprint_sha256());
    }
}
