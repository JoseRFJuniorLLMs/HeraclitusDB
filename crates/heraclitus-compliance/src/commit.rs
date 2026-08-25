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

use heraclitus_core::runtime::{DatabaseManifest, SegmentState};
use heraclitus_core::Lsn;
use heraclitus_log::{merkle_root, EpisodeLog};

/// Domain separator so a compliance imprint can never be confused with a raw
/// segment/record hash.
pub const COMMIT_DOMAIN: &[u8] = b"heraclitus-compliance/commit/v1";

/// SPEC-0050 §7.2 — domínio das âncoras sobre raízes **lógicas** canónicas.
///
/// Separado de [`COMMIT_DOMAIN`] porque não é a mesma afirmação. No layout
/// legado a raiz de um segmento é a Merkle dos bytes **físicos** do ficheiro;
/// em HRKL v6 é a raiz lógica canónica, invariante entre RAW e PACKED. A raiz
/// lógica é a melhor das duas para ancorar — sobrevive a um repack, ao passo
/// que a física muda e invalidaria um recibo já notarizado sem que uma única
/// linha de história tivesse mudado.
///
/// Mas *melhor* não é *igual*: um verificador que aplicasse o domínio errado
/// obteria um imprint diferente e reportaria fraude onde não há. Domínios
/// distintos tornam essa confusão impossível de exprimir.
pub const COMMIT_DOMAIN_V6: &[u8] = b"heraclitus-compliance/commit/hrkl-v6/v1";

/// Que família de raízes foi dobrada num compromisso.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CommitmentDomain {
    /// Raízes Merkle físicas dos segmentos v1--v5.
    #[default]
    LegacyPhysical,
    /// Raízes lógicas canónicas do HRKL v6 (SPEC-0050 §7.2).
    V6Logical,
}

impl CommitmentDomain {
    pub fn separator(self) -> &'static [u8] {
        match self {
            Self::LegacyPhysical => COMMIT_DOMAIN,
            Self::V6Logical => COMMIT_DOMAIN_V6,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyPhysical => "legacy-physical",
            Self::V6Logical => "hrkl-v6-logical",
        }
    }
}

/// A reproducible commitment to all sealed events with `lsn <= lsn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment {
    /// Watermark: this commitment covers every event up to and including `lsn`.
    pub lsn: Lsn,
    /// Aggregate blake3 Merkle root over the covered sealed-segment roots.
    pub root: [u8; 32],
    /// Number of sealed segments folded into `root`.
    pub segments: u64,
    /// Que família de raízes foi dobrada — entra no imprint.
    pub domain: CommitmentDomain,
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
        h.update(self.domain.separator());
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

/// As raízes seladas de um manifesto, na ordem do LSN, e o seu domínio.
///
/// É aqui que os dois formatos de armazenamento convergem, e a convergência é
/// feita **pelo manifesto**, não por um `if` sobre o tipo do backend. O
/// `DatabaseManifest` já é o catálogo comum: o legado povoa `segments` (vista
/// v1, raiz física em `payload_hash`), o HRKL v6 povoa `segments_v2` (raiz
/// lógica canónica). Um adaptador que fabricasse `SegmentMeta` legado a partir
/// de v6 para reaproveitar o código antigo estaria a inventar raízes físicas
/// que não existem — exactamente o que §69 proíbe.
///
/// Só entram segmentos **selados**: o tail é mutável, e ancorá-lo produziria
/// um compromisso que deixa de reproduzir no instante seguinte.
fn sealed_roots(manifest: &DatabaseManifest, watermark_lsn: Lsn) -> (Vec<[u8; 32]>, CommitmentDomain) {
    if !manifest.segments_v2.is_empty() {
        let mut segs: Vec<_> = manifest
            .segments_v2
            .iter()
            .filter(|s| s.last_lsn <= watermark_lsn && s.logical_root != [0; 32])
            .collect();
        segs.sort_by_key(|s| s.first_lsn);
        return (
            segs.iter().map(|s| s.logical_root).collect(),
            CommitmentDomain::V6Logical,
        );
    }
    let mut segs: Vec<_> = manifest
        .segments
        .iter()
        .filter(|s| {
            s.state == SegmentState::Frozen
                && s.last_lsn <= watermark_lsn
                && s.payload_hash != [0; 32]
        })
        .collect();
    segs.sort_by_key(|s| s.first_lsn);
    (
        segs.iter().map(|s| s.payload_hash).collect(),
        CommitmentDomain::LegacyPhysical,
    )
}

/// O maior watermark ancorável de um manifesto: o maior `last_lsn` selado.
pub fn current_watermark_of(manifest: &DatabaseManifest) -> Lsn {
    if !manifest.segments_v2.is_empty() {
        return manifest
            .segments_v2
            .iter()
            .map(|s| s.last_lsn)
            .max()
            .unwrap_or(0);
    }
    manifest
        .segments
        .iter()
        .filter(|s| s.state == SegmentState::Frozen)
        .map(|s| s.last_lsn)
        .max()
        .unwrap_or(0)
}

/// Compromisso sobre todos os segmentos selados contidos em `[0, watermark]`.
pub fn commit_at_manifest(manifest: &DatabaseManifest, watermark_lsn: Lsn) -> Commitment {
    let (roots, domain) = sealed_roots(manifest, watermark_lsn);
    Commitment {
        lsn: watermark_lsn,
        root: aggregate_root(&roots),
        segments: roots.len() as u64,
        domain,
    }
}

/// The highest watermark currently anchorable: the max `max_lsn` across sealed
/// segments (0 when nothing is sealed yet).
pub fn current_watermark<L: EpisodeLog + ?Sized>(log: &L) -> Lsn {
    current_watermark_of(&log.manifest())
}

/// Build the commitment over every sealed segment fully contained in
/// `[0, watermark_lsn]`.
pub fn commit_at<L: EpisodeLog + ?Sized>(log: &L, watermark_lsn: Lsn) -> Commitment {
    commit_at_manifest(&log.manifest(), watermark_lsn)
}

/// Convenience: commit at the current watermark.
pub fn commit_now<L: EpisodeLog + ?Sized>(log: &L) -> Commitment {
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
            domain: CommitmentDomain::LegacyPhysical,
        };
        let c2 = Commitment {
            lsn: 101,
            root: [7u8; 32],
            segments: 3,
            domain: CommitmentDomain::LegacyPhysical,
        };
        let i1 = c1.message_imprint_sha256();
        assert_eq!(i1.len(), 32);
        // a different watermark over the same root yields a different imprint
        assert_ne!(i1, c2.message_imprint_sha256());
    }
}
