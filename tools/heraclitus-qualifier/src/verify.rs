use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::commitment::{self, QualificationCommitment};
use crate::evidence::{self, INDEX_DIGEST_FILE, INDEX_FILE};
use crate::manifest::{
    EvidenceIndex, QualificationLevel, QualificationManifest, QualificationResult,
    QualificationStatus, TrialStatus,
};
use crate::policy;

#[derive(Debug)]
pub struct VerificationSummary {
    pub files: usize,
    pub merkle_root: String,
    pub status: QualificationStatus,
    /// The §122 triple, derived from the sealed set.
    pub commitment: QualificationCommitment,
    /// `Some(true)` when a binary was supplied and its digest matched;
    /// `Some(false)` never returns — a mismatch is an error, per §121, because
    /// the qualification of a changed binary is void, not merely suspect.
    /// `None` when no binary was supplied to check against.
    pub binary_rechecked: Option<bool>,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn verify_sidecar(root: &Path, sidecar: &str, subject: &str) -> Result<()> {
    let content = fs::read_to_string(root.join(sidecar))
        .with_context(|| format!("read digest sidecar {sidecar}"))?;
    let expected = content
        .split_whitespace()
        .next()
        .context("digest sidecar is empty")?;
    let observed = evidence::sha256_file(&root.join(subject))?;
    if !expected.eq_ignore_ascii_case(&observed) {
        bail!("digest sidecar mismatch for {subject}");
    }
    Ok(())
}

pub fn verify_evidence(root: &Path) -> Result<VerificationSummary> {
    verify_evidence_against(root, None)
}

/// Verify a sealed dossier and, when `binary` is supplied, re-hash it and
/// require it to be the exact artifact the trials ran against.
pub fn verify_evidence_against(
    root: &Path,
    binary: Option<&Path>,
) -> Result<VerificationSummary> {
    if !root.is_dir() {
        bail!("evidence directory does not exist: {}", root.display());
    }
    verify_sidecar(root, INDEX_DIGEST_FILE, INDEX_FILE)?;
    verify_sidecar(
        root,
        "qualification-manifest.sha256",
        "qualification-manifest.json",
    )?;
    verify_sidecar(
        root,
        "qualification-result.sha256",
        "qualification-result.json",
    )?;
    let index: EvidenceIndex = read_json(&root.join(INDEX_FILE))?;
    evidence::verify_inventory(root, &index)?;
    let manifest: QualificationManifest = read_json(&root.join("qualification-manifest.json"))?;
    let result: QualificationResult = read_json(&root.join("qualification-result.json"))?;
    if index.qualification_id != manifest.qualification_id
        || manifest.qualification_id != result.qualification_id
    {
        bail!("qualification id differs across sealed artifacts");
    }
    if manifest.release_version != result.release_version
        || manifest.binary_digest != result.binary_digest
        || manifest.qualification_level != result.level
    {
        bail!("qualification subject differs between manifest and result");
    }
    if result.passed != (result.status == QualificationStatus::Passed) {
        bail!("result passed flag contradicts qualification status");
    }
    if result.production_qualified
        && (result.status != QualificationStatus::Passed
            || result.level < QualificationLevel::GovernmentProduction
            || result.binary_digest.is_none()
            || manifest.repository_dirty)
    {
        bail!("invalid production_qualified claim");
    }
    if result
        .trials
        .iter()
        .any(|trial| trial.status == TrialStatus::Failed)
        && result.status != QualificationStatus::Failed
    {
        bail!("failed trial was not propagated to overall status");
    }
    let (policy_status, _) = policy::aggregate(result.level, &result.trials);
    if result.status == QualificationStatus::Passed && policy_status != QualificationStatus::Passed
    {
        bail!("Passed result lacks the normative evidence for its level");
    }
    let expected_required = policy::requirements(result.level)
        .into_iter()
        .map(|gate| gate.id.to_owned())
        .collect::<Vec<_>>();
    if result.required_gates != expected_required {
        bail!("required gate list differs from suite policy");
    }
    // §121 — the report, result, build manifest and SBOM must still hash to
    // what the commitment recorded when the dossier was sealed.
    let sealed = commitment::verify_sealed(root, &manifest)?;
    if sealed.release_digest != manifest.binary_digest {
        bail!("commitment names a different release binary than the manifest");
    }
    let binary_rechecked = match binary {
        Some(path) => {
            let observed = evidence::sha256_file(path)?;
            match manifest.binary_digest.as_deref() {
                None => bail!(
                    "a binary was supplied for re-checking but the qualification recorded none"
                ),
                Some(recorded) if recorded.eq_ignore_ascii_case(&observed) => Some(true),
                Some(recorded) => bail!(
                    "binary {} hashes to {observed}, not the qualified {recorded}; \
                     this qualification does not apply to it",
                    path.display()
                ),
            }
        }
        None => None,
    };
    let commitment = commitment::derive(&index, &sealed);
    Ok(VerificationSummary {
        files: index.artifacts.len(),
        merkle_root: index.merkle_root,
        status: result.status,
        commitment,
        binary_rechecked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_mismatch_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("subject"), b"subject").unwrap();
        fs::write(temp.path().join("subject.sha256"), "00  subject\n").unwrap();
        assert!(verify_sidecar(temp.path(), "subject.sha256", "subject").is_err());
    }
}
