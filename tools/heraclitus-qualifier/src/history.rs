//! Qualification history (SPEC-0049 §109).
//!
//! > `1.1.0 FAIL Q4` — "Uma falha não deve ser apagada quando corrigida."
//!
//! The history is an append-only JSON Lines ledger. There is no command to
//! delete or rewrite an entry, and that absence is the feature: a release train
//! whose failures can be edited out of its own record cannot be audited. A
//! later `1.1.1 PASS` sits *after* the failure, it does not replace it.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::commitment::{self, COMMITMENT_FILE};
use crate::evidence::INDEX_FILE;
use crate::manifest::{
    EvidenceIndex, QualificationLevel, QualificationManifest, QualificationResult,
    QualificationStatus,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    pub schema_version: u32,
    pub recorded_at_unix: u64,
    pub qualification_id: String,
    pub release_version: String,
    pub level: QualificationLevel,
    pub status: QualificationStatus,
    pub production_qualified: bool,
    pub release_digest: Option<String>,
    pub evidence_root: String,
    pub report_digest: String,
    pub commitment: String,
    pub evidence_path: String,
    /// Copied verbatim so the history states why a run was not qualified
    /// without needing the evidence directory to still exist.
    pub known_limitations: Vec<String>,
    pub failed_gates: Vec<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

pub fn read(history: &Path) -> Result<Vec<HistoryEntry>> {
    if !history.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(history)
        .with_context(|| format!("open history {}", history.display()))?;
    let mut entries = Vec::new();
    for (number, line) in BufReader::new(file).lines().enumerate() {
        let line = line.with_context(|| format!("read history line {}", number + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        entries.push(
            serde_json::from_str(&line)
                .with_context(|| format!("parse history line {}", number + 1))?,
        );
    }
    Ok(entries)
}

/// Append one sealed evidence set to the ledger.
pub fn record(evidence_root: &Path, history: &Path) -> Result<HistoryEntry> {
    // Verifying first means a tampered or unsealed dossier can never enter the
    // record. The history is only as trustworthy as its weakest entry.
    crate::verify::verify_evidence(evidence_root)
        .context("evidence must verify before it enters the history")?;

    let manifest: QualificationManifest =
        read_json(&evidence_root.join("qualification-manifest.json"))?;
    let result: QualificationResult = read_json(&evidence_root.join("qualification-result.json"))?;
    let index: EvidenceIndex = read_json(&evidence_root.join(INDEX_FILE))?;
    let sealed: commitment::SealedCommitment = read_json(&evidence_root.join(COMMITMENT_FILE))?;

    let existing = read(history)?;
    if let Some(previous) = existing
        .iter()
        .find(|entry| entry.qualification_id == manifest.qualification_id)
    {
        bail!(
            "qualification {} is already recorded at {}; the history is append-only",
            previous.qualification_id,
            previous.recorded_at_unix
        );
    }

    let failed_gates = result
        .trials
        .iter()
        .filter(|trial| trial.status != crate::manifest::TrialStatus::Passed)
        .map(|trial| format!("{}={:?}", trial.trial, trial.status))
        .collect();
    let entry = HistoryEntry {
        schema_version: 1,
        recorded_at_unix: now_unix(),
        qualification_id: manifest.qualification_id.clone(),
        release_version: result.release_version.clone(),
        level: result.level,
        status: result.status,
        production_qualified: result.production_qualified,
        release_digest: result.binary_digest.clone(),
        evidence_root: index.merkle_root.clone(),
        report_digest: sealed.report_digest.clone(),
        commitment: sealed.commitment.clone(),
        evidence_path: evidence_root.to_string_lossy().replace('\\', "/"),
        known_limitations: result.known_limitations.clone(),
        failed_gates,
    };

    if let Some(parent) = history.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut line = serde_json::to_string(&entry).context("serialize history entry")?;
    line.push('\n');
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(history)
        .with_context(|| format!("append to history {}", history.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("write history entry to {}", history.display()))?;
    file.sync_all()?;
    Ok(entry)
}

/// Latest entry per release, plus whether that release ever failed. §109's
/// point is that the summary must still show the failure after the fix.
pub fn summarize(entries: &[HistoryEntry]) -> BTreeMap<String, (QualificationStatus, usize)> {
    let mut summary = BTreeMap::new();
    for entry in entries {
        let counter = summary
            .entry(entry.release_version.clone())
            .or_insert((entry.status, 0_usize));
        counter.0 = entry.status;
        if entry.status != QualificationStatus::Passed {
            counter.1 += 1;
        }
    }
    summary
}

pub fn render(entries: &[HistoryEntry]) -> String {
    let mut text = String::from("release\tlevel\tstatus\tqualification_id\trelease_digest\n");
    for entry in entries {
        text.push_str(&format!(
            "{}\t{:?}\t{:?}\t{}\t{}\n",
            entry.release_version,
            entry.level,
            entry.status,
            entry.qualification_id,
            entry.release_digest.as_deref().unwrap_or("-")
        ));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(release: &str, id: &str, status: QualificationStatus) -> HistoryEntry {
        HistoryEntry {
            schema_version: 1,
            recorded_at_unix: 0,
            qualification_id: id.to_owned(),
            release_version: release.to_owned(),
            level: QualificationLevel::GovernmentProduction,
            status,
            production_qualified: status == QualificationStatus::Passed,
            release_digest: Some("aa".to_owned()),
            evidence_root: "bb".to_owned(),
            report_digest: "cc".to_owned(),
            commitment: "dd".to_owned(),
            evidence_path: "qa-evidence/x".to_owned(),
            known_limitations: Vec::new(),
            failed_gates: Vec::new(),
        }
    }

    #[test]
    fn a_later_pass_never_erases_an_earlier_failure() {
        let entries = vec![
            entry("1.1.0", "a", QualificationStatus::Failed),
            entry("1.1.1", "b", QualificationStatus::Passed),
        ];
        let summary = summarize(&entries);
        assert_eq!(summary["1.1.0"].0, QualificationStatus::Failed);
        assert_eq!(summary["1.1.1"].0, QualificationStatus::Passed);
        // The failed run is still in the ledger and still rendered.
        assert!(render(&entries).contains("Failed"));
    }

    #[test]
    fn re_qualifying_the_same_release_keeps_both_rows() {
        let entries = vec![
            entry("1.2.0", "first", QualificationStatus::Failed),
            entry("1.2.0", "second", QualificationStatus::Passed),
        ];
        let summary = summarize(&entries);
        assert_eq!(summary["1.2.0"].0, QualificationStatus::Passed);
        // ...and the count of non-passing attempts survives the fix.
        assert_eq!(summary["1.2.0"].1, 1);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn round_trips_through_the_append_only_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("history.jsonl");
        let mut file = std::fs::File::create(&path).unwrap();
        for entry in [
            entry("1.0.0", "a", QualificationStatus::Passed),
            entry("1.0.1", "b", QualificationStatus::Unqualified),
        ] {
            writeln!(file, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        }
        drop(file);
        let entries = read(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].status, QualificationStatus::Unqualified);
        assert!(read(&temp.path().join("absent.jsonl")).unwrap().is_empty());
    }
}
