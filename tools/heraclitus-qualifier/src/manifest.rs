use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

fn default_schema_version() -> u32 {
    1
}

fn default_suite_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

fn default_timeout_seconds() -> u64 {
    3_600
}

fn default_assurance() -> AssuranceLevel {
    AssuranceLevel::Development
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum QualificationLevel {
    Development,
    ReleaseCandidate,
    GovernmentProduction,
    MissionCritical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    Development,
    QualificationLab,
    Independent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationStatus {
    Passed,
    Failed,
    Unqualified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialStatus {
    Passed,
    Failed,
    Inconclusive,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialMode {
    Command,
    ExternalAttestation,
    Unconfigured,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationPlan {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default = "default_suite_version")]
    pub suite_version: String,
    pub release_version: String,
    pub level: QualificationLevel,
    #[serde(default = "default_target")]
    pub target: String,
    #[serde(default = "default_build_profile")]
    pub build_profile: String,
    pub binary: Option<PathBuf>,
    #[serde(default)]
    pub known_limitations: Vec<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    pub external_verifier: Option<CommandSpec>,
    #[serde(default)]
    pub trials: Vec<TrialPlan>,
}

fn default_target() -> String {
    "local".to_owned()
}

fn default_build_profile() -> String {
    "release".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialPlan {
    pub id: String,
    pub description: String,
    pub mode: TrialMode,
    #[serde(default = "default_assurance")]
    pub assurance: AssuranceLevel,
    pub program: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    pub attestation: Option<PathBuf>,
    pub verifier: Option<CommandSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttestation {
    pub schema_version: u32,
    pub gate_id: String,
    pub release_version: String,
    pub subject_binary_sha256: String,
    pub issuer: String,
    pub executed_at_unix: u64,
    pub status: TrialStatus,
    #[serde(default)]
    pub findings: Vec<String>,
    #[serde(default)]
    pub metrics: BTreeMap<String, f64>,
    #[serde(default)]
    pub artifacts: Vec<AttestedArtifact>,
    pub signature: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedArtifact {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualificationManifest {
    pub schema_version: u32,
    pub qualification_id: String,
    pub release_version: String,
    pub git_commit: String,
    pub source_digest: String,
    pub binary_digest: Option<String>,
    pub rust_version: String,
    pub build_profile: String,
    pub target: String,
    pub environment: EnvironmentManifest,
    pub qualification_level: QualificationLevel,
    pub suite_version: String,
    pub started_at_unix: u64,
    pub repository_dirty: bool,
    /// Untracked, non-ignored files present during the run. `source_digest`
    /// deliberately does not cover them, so their number is stated instead of
    /// being silently absent.
    #[serde(default)]
    pub untracked_files: u64,
    pub plan_sha256: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentManifest {
    pub cpu_model: String,
    pub cpu_count: u32,
    pub memory_bytes: u64,
    pub storage_model: String,
    pub filesystem: String,
    pub os: String,
    pub kernel: String,
    pub network: String,
    pub virtualization: Option<String>,
    pub architecture: String,
    pub relevant_settings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildManifest {
    pub schema_version: u32,
    pub release_version: String,
    pub git_commit: String,
    pub source_sha256: String,
    pub cargo_lock_sha256: String,
    pub binary_path: Option<String>,
    pub binary_sha256: Option<String>,
    pub binary_size: Option<u64>,
    pub rustc: String,
    pub cargo: String,
    pub build_profile: String,
    pub repository_dirty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialResult {
    pub trial: String,
    pub description: String,
    pub status: TrialStatus,
    pub assurance: AssuranceLevel,
    pub started_at_unix: u64,
    pub finished_at_unix: u64,
    pub duration_ms: u128,
    pub command: Option<Vec<String>>,
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub metrics: BTreeMap<String, f64>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualificationResult {
    pub schema_version: u32,
    pub qualification_id: String,
    pub release_version: String,
    pub binary_digest: Option<String>,
    pub level: QualificationLevel,
    pub status: QualificationStatus,
    pub trials: Vec<TrialResult>,
    pub passed: bool,
    pub production_qualified: bool,
    pub known_limitations: Vec<String>,
    pub required_gates: Vec<String>,
    pub finished_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualificationArtifact {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceIndex {
    pub schema_version: u32,
    pub qualification_id: String,
    pub algorithm: String,
    pub artifacts: Vec<QualificationArtifact>,
    pub merkle_root: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadProfile {
    WriteHeavy,
    ReadHeavy,
    Mixed,
    SocIngestion,
    SocInvestigation,
    Burst,
    AdversarialCardinality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetManifest {
    pub schema_version: u32,
    pub provenance: String,
    pub generator: String,
    pub profile: WorkloadProfile,
    pub seed: u64,
    pub events: u64,
    pub sha256: String,
    pub event_classes: BTreeMap<String, u64>,
    pub operation_mix: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum CorruptionMode {
    FlipBit,
    Truncate,
    ZeroRange,
    DuplicateRange,
    RemoveRange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorruptionRecord {
    pub schema_version: u32,
    pub mode: CorruptionMode,
    pub seed: u64,
    pub input_sha256: String,
    pub output_sha256: String,
    pub input_size: u64,
    pub output_size: u64,
    pub offset: Option<u64>,
    pub length: Option<u64>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn shipped_plans_parse_and_cover_their_normative_gate_set() {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        for filename in [
            "development.toml",
            "lab-preflight.toml",
            "release-candidate.toml",
            "government-production.toml",
        ] {
            let path = repository.join("qa/qualification/plans").join(filename);
            let text = fs::read_to_string(&path).unwrap();
            let plan: QualificationPlan = toml::from_str(&text).unwrap();
            assert_eq!(plan.schema_version, 1, "{}", path.display());
            let ids = plan
                .trials
                .iter()
                .map(|trial| trial.id.as_str())
                .collect::<BTreeSet<_>>();
            assert_eq!(ids.len(), plan.trials.len(), "{}", path.display());
            for requirement in crate::policy::requirements(plan.level) {
                assert!(
                    ids.contains(requirement.id),
                    "{} lacks {}",
                    path.display(),
                    requirement.id
                );
            }
        }
    }
}
