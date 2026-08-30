//! Qualification commitment (SPEC-0049 §121–§122).
//!
//! §121 requires the final report to be bound to the digests of the artifacts
//! it describes, so that "a later change to the binary invalidates the
//! corresponding qualification". §122 aggregates the evidence into a Merkle
//! tree and names the triple that identifies a qualified release.
//!
//! The binding is built in two layers, deliberately:
//!
//! 1. `qualification-commitment.json` is written **before** sealing and covers
//!    the release binary, build manifest, result and report. It is then itself
//!    an artifact, so the Merkle root covers the commitment.
//! 2. The evidence root cannot appear inside the file it hashes, so the §122
//!    triple is *derived* at verification time from the sealed index.
//!
//! Putting the root inside the committed file would be circular, and a
//! self-referential root that nobody can recompute is not a commitment.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::evidence::sha256_file;
use crate::manifest::{EvidenceIndex, QualificationManifest};

pub const COMMITMENT_FILE: &str = "qualification-commitment.json";
const DOMAIN: &[u8] = b"HERACLITUS_QUALIFICATION_COMMITMENT_V1\0";

/// Written into the evidence set before sealing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedCommitment {
    pub schema_version: u32,
    pub qualification_id: String,
    pub release_version: String,
    /// SHA-256 of the exact binary the trials ran against. `None` when the plan
    /// declared no binary, which the policy already treats as a limitation for
    /// anything above Development.
    pub release_digest: Option<String>,
    pub build_manifest_digest: String,
    pub result_digest: String,
    pub report_digest: String,
    pub sbom_digest: Option<String>,
    /// Domain-separated hash over every field above, in declaration order.
    pub commitment: String,
}

/// The §122 triple. Derived, never stored, because `evidence_root` covers the
/// file it would otherwise live in.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QualificationCommitment {
    pub release_digest: Option<String>,
    pub evidence_root: String,
    pub report_digest: String,
}

fn field(hasher: &mut Sha256, label: &str, value: Option<&str>) {
    hasher.update((label.len() as u64).to_le_bytes());
    hasher.update(label.as_bytes());
    match value {
        Some(value) => {
            hasher.update([1_u8]);
            hasher.update((value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }
        // A present-but-empty value and an absent value must not hash alike:
        // otherwise a missing binary digest could be forged into an empty one.
        None => hasher.update([0_u8]),
    }
}

pub fn commitment_hash(
    qualification_id: &str,
    release_version: &str,
    release_digest: Option<&str>,
    build_manifest_digest: &str,
    result_digest: &str,
    report_digest: &str,
    sbom_digest: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    field(&mut hasher, "qualification_id", Some(qualification_id));
    field(&mut hasher, "release_version", Some(release_version));
    field(&mut hasher, "release_digest", release_digest);
    field(
        &mut hasher,
        "build_manifest_digest",
        Some(build_manifest_digest),
    );
    field(&mut hasher, "result_digest", Some(result_digest));
    field(&mut hasher, "report_digest", Some(report_digest));
    field(&mut hasher, "sbom_digest", sbom_digest);
    format!("{:x}", hasher.finalize())
}

/// Look for a release SBOM anywhere under the evidence root. A plan may place
/// it in `sbom/bom.cdx.json` or inside a trial directory; both bind.
fn find_sbom(root: &Path) -> Option<String> {
    for candidate in [
        root.join("sbom").join("bom.cdx.json"),
        root.join("bom.cdx.json"),
    ] {
        if candidate.is_file() {
            return sha256_file(&candidate).ok();
        }
    }
    None
}

pub fn build(root: &Path, manifest: &QualificationManifest) -> Result<SealedCommitment> {
    let build_manifest_digest = sha256_file(&root.join("build-manifest.json"))
        .context("hash build manifest for the commitment")?;
    let result_digest = sha256_file(&root.join("qualification-result.json"))
        .context("hash qualification result for the commitment")?;
    let report_digest = sha256_file(&root.join("qualification-report.md"))
        .context("hash qualification report for the commitment")?;
    let sbom_digest = find_sbom(root);
    let commitment = commitment_hash(
        &manifest.qualification_id,
        &manifest.release_version,
        manifest.binary_digest.as_deref(),
        &build_manifest_digest,
        &result_digest,
        &report_digest,
        sbom_digest.as_deref(),
    );
    Ok(SealedCommitment {
        schema_version: 1,
        qualification_id: manifest.qualification_id.clone(),
        release_version: manifest.release_version.clone(),
        release_digest: manifest.binary_digest.clone(),
        build_manifest_digest,
        result_digest,
        report_digest,
        sbom_digest,
        commitment,
    })
}

/// Recompute the sealed commitment from the artifacts actually on disk and
/// compare. A mismatch means one of the bound artifacts changed after sealing.
pub fn verify_sealed(root: &Path, manifest: &QualificationManifest) -> Result<SealedCommitment> {
    let stored: SealedCommitment = {
        let bytes = std::fs::read(root.join(COMMITMENT_FILE))
            .with_context(|| format!("read {COMMITMENT_FILE}"))?;
        serde_json::from_slice(&bytes).with_context(|| format!("parse {COMMITMENT_FILE}"))?
    };
    let recomputed = build(root, manifest)?;
    if stored != recomputed {
        anyhow::bail!("qualification commitment does not match the sealed artifacts");
    }
    Ok(stored)
}

pub fn derive(index: &EvidenceIndex, sealed: &SealedCommitment) -> QualificationCommitment {
    QualificationCommitment {
        release_digest: sealed.release_digest.clone(),
        evidence_root: index.merkle_root.clone(),
        report_digest: sealed.report_digest.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bound_field_changes_the_commitment() {
        let base = commitment_hash("q1", "1.0.0", Some("aa"), "bb", "cc", "dd", Some("ee"));
        assert_ne!(
            base,
            commitment_hash("q2", "1.0.0", Some("aa"), "bb", "cc", "dd", Some("ee"))
        );
        assert_ne!(
            base,
            commitment_hash("q1", "1.0.1", Some("aa"), "bb", "cc", "dd", Some("ee"))
        );
        // §121: a later change of the binary invalidates the qualification.
        assert_ne!(
            base,
            commitment_hash("q1", "1.0.0", Some("ab"), "bb", "cc", "dd", Some("ee"))
        );
        assert_ne!(
            base,
            commitment_hash("q1", "1.0.0", Some("aa"), "bb", "cc", "de", Some("ee"))
        );
        assert_ne!(
            base,
            commitment_hash("q1", "1.0.0", Some("aa"), "bb", "cc", "dd", None)
        );
    }

    #[test]
    fn an_absent_digest_does_not_collide_with_an_empty_one() {
        assert_ne!(
            commitment_hash("q", "1", None, "b", "c", "d", None),
            commitment_hash("q", "1", Some(""), "b", "c", "d", None)
        );
    }

    #[test]
    fn field_lengths_stop_boundaries_from_sliding() {
        // Without length prefixes "ab"+"c" and "a"+"bc" would hash alike.
        assert_ne!(
            commitment_hash("q", "1", Some("ab"), "c", "d", "e", None),
            commitment_hash("q", "1", Some("a"), "bc", "d", "e", None)
        );
    }
}
