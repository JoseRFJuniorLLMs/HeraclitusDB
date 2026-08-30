use std::collections::{BTreeMap, BTreeSet};

use crate::manifest::{
    AssuranceLevel, QualificationLevel, QualificationStatus, TrialResult, TrialStatus,
};

#[derive(Debug, Clone, Copy)]
pub struct GateRequirement {
    pub id: &'static str,
    pub minimum_assurance: AssuranceLevel,
    pub description: &'static str,
}

const DEVELOPMENT: &[GateRequirement] = &[
    gate("unit_tests", AssuranceLevel::Development, "unit test suite"),
    gate(
        "integration_tests",
        AssuranceLevel::Development,
        "integration test suite",
    ),
    gate("lint", AssuranceLevel::Development, "format and lint gates"),
    gate(
        "basic_fuzz",
        AssuranceLevel::Development,
        "bounded malformed-input fuzzing",
    ),
];

const RELEASE_CANDIDATE: &[GateRequirement] = &[
    gate(
        "benchmark",
        AssuranceLevel::QualificationLab,
        "documented benchmark",
    ),
    gate(
        "crash_loop",
        AssuranceLevel::QualificationLab,
        "repeated abrupt process termination",
    ),
    gate(
        "upgrade",
        AssuranceLevel::QualificationLab,
        "N-1 to N upgrade and declared rollback",
    ),
    gate("sbom", AssuranceLevel::QualificationLab, "release SBOM"),
    gate(
        "artifact_signature",
        AssuranceLevel::QualificationLab,
        "verified artifact signature",
    ),
];

const GOVERNMENT: &[GateRequirement] = &[
    gate(
        "q1_load",
        AssuranceLevel::QualificationLab,
        "Q1 realistic load",
    ),
    gate(
        "q2_failure",
        AssuranceLevel::QualificationLab,
        "Q2 real failure",
    ),
    gate(
        "q3_attack",
        AssuranceLevel::QualificationLab,
        "Q3 attack campaign",
    ),
    gate(
        "q4_upgrade",
        AssuranceLevel::QualificationLab,
        "Q4 real upgrade",
    ),
    gate(
        "q5_node_loss",
        AssuranceLevel::QualificationLab,
        "Q5 real node loss",
    ),
    gate(
        "q6_restore",
        AssuranceLevel::QualificationLab,
        "Q6 empty-environment restore",
    ),
    gate(
        "long_soak",
        AssuranceLevel::QualificationLab,
        "long-running soak",
    ),
    gate(
        "power_loss",
        AssuranceLevel::QualificationLab,
        "physical or hypervisor power loss",
    ),
    gate(
        "corruption",
        AssuranceLevel::QualificationLab,
        "corruption injection and fail-closed recovery",
    ),
    gate(
        "raft_failover",
        AssuranceLevel::QualificationLab,
        "Raft failure matrix",
    ),
    gate(
        "dr",
        AssuranceLevel::QualificationLab,
        "disaster-recovery drill",
    ),
    gate(
        "red_team",
        AssuranceLevel::QualificationLab,
        "red-team campaign",
    ),
    gate(
        "airgap_install",
        AssuranceLevel::QualificationLab,
        "air-gapped installation",
    ),
    gate(
        "airgap_update",
        AssuranceLevel::QualificationLab,
        "air-gapped update",
    ),
    gate(
        "zero_egress",
        AssuranceLevel::QualificationLab,
        "monitored zero-egress gate",
    ),
    gate(
        "dependency_audit",
        AssuranceLevel::QualificationLab,
        "dependency vulnerability analysis",
    ),
    gate(
        "supply_chain",
        AssuranceLevel::QualificationLab,
        "build manifest, provenance and digests",
    ),
    gate(
        "vulnerability_policy",
        AssuranceLevel::QualificationLab,
        "published vulnerability response process",
    ),
    gate(
        "runbooks",
        AssuranceLevel::QualificationLab,
        "validated operational runbooks",
    ),
];

const MISSION_CRITICAL: &[GateRequirement] = &[
    gate(
        "extended_soak",
        AssuranceLevel::Independent,
        "extended soak",
    ),
    gate(
        "multi_site_dr",
        AssuranceLevel::Independent,
        "multi-site recovery",
    ),
    gate(
        "cluster_destruction",
        AssuranceLevel::Independent,
        "complete cluster destruction",
    ),
    gate(
        "bare_metal_restore",
        AssuranceLevel::Independent,
        "bare-metal restore",
    ),
    gate(
        "five_node_matrix",
        AssuranceLevel::Independent,
        "five-node fault matrix",
    ),
    gate(
        "external_red_team",
        AssuranceLevel::Independent,
        "independent external red team",
    ),
    gate(
        "operator_handover",
        AssuranceLevel::Independent,
        "operator handover drill",
    ),
    gate(
        "offline_recovery",
        AssuranceLevel::Independent,
        "offline recovery without original infrastructure",
    ),
    gate(
        "independent_verification",
        AssuranceLevel::Independent,
        "independent evidence verification",
    ),
];

/// §117 — the runbooks a government release must ship with. Listed here rather
/// than only in prose so a missing one breaks the build instead of being
/// discovered by an operator who needed it.
pub const REQUIRED_RUNBOOKS: &[&str] = &[
    "installation.md",
    "upgrade.md",
    "rollback.md",
    "backup.md",
    "restore.md",
    "disaster-recovery.md",
    "node-replacement.md",
    "certificate-rotation.md",
    "incident-response.md",
    "vulnerability-response.md",
    "air-gap-update.md",
];

/// One runbook's presence and whether it is substantial enough to follow.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunbookCheck {
    pub runbook: &'static str,
    pub present: bool,
    pub bytes: u64,
    /// A file that exists but says almost nothing satisfies "ships a runbook"
    /// and helps nobody at 03:17, so length is reported and judged.
    pub substantial: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RunbookReport {
    pub schema_version: u32,
    pub root: String,
    pub checks: Vec<RunbookCheck>,
    pub missing: usize,
    pub insubstantial: usize,
    /// §117 is satisfied only when all eleven are present and readable. It is
    /// still not *validated* until §118 is met: someone who did not write them
    /// has executed the critical ones.
    pub complete: bool,
}

/// Shortest a procedure can plausibly be. Chosen to reject a stub, not to
/// reward length.
const RUNBOOK_MINIMUM_BYTES: u64 = 800;

pub fn check_runbooks(root: &std::path::Path) -> RunbookReport {
    let checks = REQUIRED_RUNBOOKS
        .iter()
        .map(|runbook| {
            let bytes = std::fs::metadata(root.join(runbook))
                .ok()
                .filter(|metadata| metadata.is_file())
                .map(|metadata| metadata.len());
            RunbookCheck {
                runbook,
                present: bytes.is_some(),
                bytes: bytes.unwrap_or(0),
                substantial: bytes.is_some_and(|bytes| bytes >= RUNBOOK_MINIMUM_BYTES),
            }
        })
        .collect::<Vec<_>>();
    let missing = checks.iter().filter(|check| !check.present).count();
    let insubstantial = checks
        .iter()
        .filter(|check| check.present && !check.substantial)
        .count();
    RunbookReport {
        schema_version: 1,
        root: root.to_string_lossy().into_owned(),
        checks,
        missing,
        insubstantial,
        complete: missing == 0 && insubstantial == 0,
    }
}

const fn gate(
    id: &'static str,
    minimum_assurance: AssuranceLevel,
    description: &'static str,
) -> GateRequirement {
    GateRequirement {
        id,
        minimum_assurance,
        description,
    }
}

pub fn requirements(level: QualificationLevel) -> Vec<GateRequirement> {
    let mut requirements = DEVELOPMENT.to_vec();
    if level >= QualificationLevel::ReleaseCandidate {
        requirements.extend_from_slice(RELEASE_CANDIDATE);
    }
    if level >= QualificationLevel::GovernmentProduction {
        requirements.extend_from_slice(GOVERNMENT);
    }
    if level >= QualificationLevel::MissionCritical {
        requirements.extend_from_slice(MISSION_CRITICAL);
    }
    requirements
}

pub fn aggregate(
    level: QualificationLevel,
    trials: &[TrialResult],
) -> (QualificationStatus, Vec<String>) {
    let by_id: BTreeMap<&str, &TrialResult> = trials
        .iter()
        .map(|trial| (trial.trial.as_str(), trial))
        .collect();
    let required = requirements(level);
    let required_ids: BTreeSet<&str> = required.iter().map(|gate| gate.id).collect();
    let mut limitations = Vec::new();

    // A failed experiment is never hidden merely because it was an extra gate.
    if trials
        .iter()
        .any(|trial| trial.status == TrialStatus::Failed)
    {
        return (QualificationStatus::Failed, limitations);
    }

    for gate in &required {
        match by_id.get(gate.id) {
            None => limitations.push(format!("required gate {} has no evidence", gate.id)),
            Some(trial) if trial.status != TrialStatus::Passed => {
                limitations.push(format!("required gate {} is {:?}", gate.id, trial.status))
            }
            Some(trial) if trial.assurance < gate.minimum_assurance => limitations.push(format!(
                "required gate {} has {:?} assurance; {:?} required",
                gate.id, trial.assurance, gate.minimum_assurance
            )),
            Some(_) => {}
        }
    }

    // Duplicate ids make evidence ambiguous and therefore unqualified.
    if by_id.len() != trials.len() {
        limitations.push("duplicate trial ids make the evidence ambiguous".to_owned());
    }

    // A required gate is the normative set. Extra passed evidence is retained
    // but can never compensate for a missing named gate.
    let _extra_trials = trials
        .iter()
        .filter(|trial| !required_ids.contains(trial.trial.as_str()))
        .count();

    if limitations.is_empty() {
        (QualificationStatus::Passed, limitations)
    } else {
        (QualificationStatus::Unqualified, limitations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::TrialResult;

    fn result(id: &str, status: TrialStatus, assurance: AssuranceLevel) -> TrialResult {
        TrialResult {
            trial: id.to_owned(),
            description: String::new(),
            status,
            assurance,
            started_at_unix: 0,
            finished_at_unix: 0,
            duration_ms: 0,
            command: None,
            exit_code: None,
            metrics: BTreeMap::new(),
            evidence: Vec::new(),
            failures: Vec::new(),
        }
    }

    #[test]
    fn missing_gate_is_never_pass() {
        let trials = DEVELOPMENT[..3]
            .iter()
            .map(|gate| result(gate.id, TrialStatus::Passed, AssuranceLevel::Development))
            .collect::<Vec<_>>();
        assert_eq!(
            aggregate(QualificationLevel::Development, &trials).0,
            QualificationStatus::Unqualified
        );
    }

    #[test]
    fn inconclusive_is_never_pass() {
        let trials = DEVELOPMENT
            .iter()
            .map(|gate| {
                let status = if gate.id == "basic_fuzz" {
                    TrialStatus::Inconclusive
                } else {
                    TrialStatus::Passed
                };
                result(gate.id, status, AssuranceLevel::Development)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            aggregate(QualificationLevel::Development, &trials).0,
            QualificationStatus::Unqualified
        );
    }

    #[test]
    fn any_failure_blocks_even_when_not_required() {
        let mut trials = DEVELOPMENT
            .iter()
            .map(|gate| result(gate.id, TrialStatus::Passed, AssuranceLevel::Development))
            .collect::<Vec<_>>();
        trials.push(result(
            "optional_experiment",
            TrialStatus::Failed,
            AssuranceLevel::Development,
        ));
        assert_eq!(
            aggregate(QualificationLevel::Development, &trials).0,
            QualificationStatus::Failed
        );
    }

    #[test]
    fn sufficient_development_evidence_passes_without_production_claim() {
        let trials = DEVELOPMENT
            .iter()
            .map(|gate| result(gate.id, TrialStatus::Passed, AssuranceLevel::Development))
            .collect::<Vec<_>>();
        assert_eq!(
            aggregate(QualificationLevel::Development, &trials).0,
            QualificationStatus::Passed
        );
    }

    #[test]
    fn every_runbook_section_117_names_is_present_and_not_a_stub() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks");
        let report = check_runbooks(&root);
        assert_eq!(report.checks.len(), 11);
        assert!(
            report.complete,
            "missing={} insubstantial={} {:#?}",
            report.missing, report.insubstantial, report.checks
        );
    }

    #[test]
    fn a_missing_or_stub_runbook_is_reported_not_rounded_up() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("installation.md"), b"TODO").unwrap();
        let report = check_runbooks(temp.path());
        assert!(!report.complete);
        assert_eq!(report.missing, 10);
        assert_eq!(report.insubstantial, 1);
        let installation = report
            .checks
            .iter()
            .find(|check| check.runbook == "installation.md")
            .unwrap();
        assert!(installation.present && !installation.substantial);
    }

    #[test]
    fn development_assurance_cannot_satisfy_release_candidate() {
        let trials = requirements(QualificationLevel::ReleaseCandidate)
            .iter()
            .map(|gate| result(gate.id, TrialStatus::Passed, AssuranceLevel::Development))
            .collect::<Vec<_>>();
        assert_eq!(
            aggregate(QualificationLevel::ReleaseCandidate, &trials).0,
            QualificationStatus::Unqualified
        );
    }
}
