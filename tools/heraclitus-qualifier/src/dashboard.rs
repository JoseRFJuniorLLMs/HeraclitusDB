//! Qualification dashboard contract (SPEC-0049 §108).
//!
//! §108 lists what the engineering dashboard should show. This module emits
//! exactly that field set as JSON so the panel renders a fact rather than a
//! sentence someone typed. §135 is enforced structurally: every field that
//! could not be measured is `null`, so the panel can render
//! `DATA UNAVAILABLE` instead of a green tick built from a missing value.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::history::{self, HistoryEntry};
use crate::manifest::{
    QualificationLevel, QualificationManifest, QualificationResult, QualificationStatus, TrialStatus,
};

#[derive(Debug, Serialize)]
pub struct GateCell {
    pub gate: String,
    /// `null` when the gate produced no evidence at all — different from
    /// `Skipped`, which is a deliberate decision someone recorded.
    pub status: Option<TrialStatus>,
    pub assurance: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DashboardStatus {
    pub schema_version: u32,
    pub generator: String,
    pub current_release: String,
    pub qualification_id: String,
    pub qualification_level: QualificationLevel,
    pub status: QualificationStatus,
    pub production_qualified: bool,
    pub binary_digest: Option<String>,
    pub evidence_root: Option<String>,
    /// The six trials, in §108's order, whether or not the plan configured them.
    pub trials: Vec<GateCell>,
    pub soak_seconds: Option<f64>,
    pub crash_cycles: Option<f64>,
    pub fuzz_hours: Option<f64>,
    pub open_security_findings: Option<f64>,
    pub sbom_status: Option<TrialStatus>,
    pub airgap_status: Option<TrialStatus>,
    pub artifact_signature_status: Option<TrialStatus>,
    pub known_limitations: Vec<String>,
    pub history: Vec<HistoryEntry>,
}

const SIX_TRIALS: &[&str] = &[
    "q1_load",
    "q2_failure",
    "q3_attack",
    "q4_upgrade",
    "q5_node_loss",
    "q6_restore",
];

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

/// Pull one metric out of whichever trial published it. Returns `None` rather
/// than a default: §135 requires "no data" to be distinguishable from "zero".
fn metric(result: &QualificationResult, gate: &str, name: &str) -> Option<f64> {
    result
        .trials
        .iter()
        .find(|trial| trial.trial == gate)?
        .metrics
        .get(name)
        .copied()
}

fn status_of(result: &QualificationResult, gate: &str) -> Option<TrialStatus> {
    result
        .trials
        .iter()
        .find(|trial| trial.trial == gate)
        .map(|trial| trial.status)
}

pub fn build(evidence: &Path, history_path: Option<&Path>) -> Result<DashboardStatus> {
    let manifest: QualificationManifest = read_json(&evidence.join("qualification-manifest.json"))?;
    let result: QualificationResult = read_json(&evidence.join("qualification-result.json"))?;
    let index: Result<crate::manifest::EvidenceIndex> =
        read_json(&evidence.join(crate::evidence::INDEX_FILE));

    let by_gate = result
        .trials
        .iter()
        .map(|trial| (trial.trial.as_str(), trial))
        .collect::<BTreeMap<_, _>>();
    let trials = SIX_TRIALS
        .iter()
        .map(|gate| GateCell {
            gate: (*gate).to_owned(),
            status: by_gate.get(gate).map(|trial| trial.status),
            assurance: by_gate
                .get(gate)
                .map(|trial| format!("{:?}", trial.assurance)),
        })
        .collect();

    let history = match history_path {
        Some(path) => history::read(path)?,
        None => Vec::new(),
    };

    Ok(DashboardStatus {
        schema_version: 1,
        generator: format!("heraclitus-qualifier/{}", env!("CARGO_PKG_VERSION")),
        current_release: result.release_version.clone(),
        qualification_id: manifest.qualification_id.clone(),
        qualification_level: result.level,
        status: result.status,
        production_qualified: result.production_qualified,
        binary_digest: result.binary_digest.clone(),
        evidence_root: index.ok().map(|index| index.merkle_root),
        trials,
        soak_seconds: metric(&result, "long_soak", "duration_seconds")
            .or_else(|| metric(&result, "extended_soak", "duration_seconds")),
        crash_cycles: metric(&result, "crash_loop", "cycles")
            .or_else(|| metric(&result, "q2_failure", "cycles")),
        fuzz_hours: metric(&result, "basic_fuzz", "execution_hours"),
        open_security_findings: metric(&result, "red_team", "open_findings"),
        sbom_status: status_of(&result, "sbom"),
        airgap_status: status_of(&result, "airgap_install"),
        artifact_signature_status: status_of(&result, "artifact_signature"),
        known_limitations: result.known_limitations.clone(),
        history,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{AssuranceLevel, TrialResult};

    fn result(trials: Vec<TrialResult>) -> QualificationResult {
        QualificationResult {
            schema_version: 1,
            qualification_id: "q".to_owned(),
            release_version: "1.0.0".to_owned(),
            binary_digest: None,
            level: QualificationLevel::GovernmentProduction,
            status: QualificationStatus::Unqualified,
            trials,
            passed: false,
            production_qualified: false,
            known_limitations: Vec::new(),
            required_gates: Vec::new(),
            finished_at_unix: 0,
        }
    }

    fn trial(id: &str, metrics: &[(&str, f64)]) -> TrialResult {
        TrialResult {
            trial: id.to_owned(),
            description: String::new(),
            status: TrialStatus::Passed,
            assurance: AssuranceLevel::QualificationLab,
            started_at_unix: 0,
            finished_at_unix: 0,
            duration_ms: 0,
            command: None,
            exit_code: None,
            metrics: metrics
                .iter()
                .map(|(name, value)| ((*name).to_owned(), *value))
                .collect(),
            evidence: Vec::new(),
            failures: Vec::new(),
        }
    }

    #[test]
    fn a_missing_metric_is_null_not_zero() {
        // §135: the panel must be able to say DATA UNAVAILABLE.
        let result = result(vec![trial("red_team", &[])]);
        assert_eq!(metric(&result, "red_team", "open_findings"), None);
        assert_eq!(metric(&result, "long_soak", "duration_seconds"), None);
    }

    #[test]
    fn zero_open_findings_is_reported_as_zero_not_as_absent() {
        let result = result(vec![trial("red_team", &[("open_findings", 0.0)])]);
        assert_eq!(metric(&result, "red_team", "open_findings"), Some(0.0));
    }

    #[test]
    fn every_one_of_the_six_trials_has_a_cell_even_when_unconfigured() {
        let result = result(vec![trial("q1_load", &[])]);
        let by_gate = result
            .trials
            .iter()
            .map(|trial| (trial.trial.as_str(), trial))
            .collect::<BTreeMap<_, _>>();
        let cells = SIX_TRIALS
            .iter()
            .map(|gate| by_gate.get(gate).map(|trial| trial.status))
            .collect::<Vec<_>>();
        assert_eq!(cells.len(), 6);
        assert_eq!(cells[0], Some(TrialStatus::Passed));
        assert_eq!(cells[5], None);
    }
}
