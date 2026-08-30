use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::commitment;
use crate::environment;
use crate::evidence;
use crate::manifest::{
    AssuranceLevel, BuildManifest, CommandSpec, ExternalAttestation, QualificationLevel,
    QualificationManifest, QualificationPlan, QualificationResult, QualificationStatus, TrialMode,
    TrialPlan, TrialResult, TrialStatus,
};
use crate::{policy, report};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_gate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        bail!("invalid gate id {id:?}; use lowercase ASCII, digits and underscore");
    }
    Ok(())
}

fn resolve(repo: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        repo.join(path)
    }
}

fn replace_tokens(value: &str, tokens: &BTreeMap<&str, String>) -> String {
    tokens
        .iter()
        .fold(value.to_owned(), |current, (token, replacement)| {
            current.replace(token, replacement)
        })
}

#[derive(Debug)]
struct ProcessResult {
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u128,
    command: Vec<String>,
}

fn execute(
    spec: &CommandSpec,
    repo: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
    tokens: &BTreeMap<&str, String>,
) -> Result<ProcessResult> {
    let program = replace_tokens(&spec.program, tokens);
    let args = spec
        .args
        .iter()
        .map(|arg| replace_tokens(arg, tokens))
        .collect::<Vec<_>>();
    let cwd = spec
        .cwd
        .as_deref()
        .map(|path| resolve(repo, path))
        .unwrap_or_else(|| repo.to_owned());
    if !cwd.is_dir() {
        bail!(
            "command working directory does not exist: {}",
            cwd.display()
        );
    }
    if let Some(parent) = stdout_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(stdout_path)
        .with_context(|| format!("create command stdout {}", stdout_path.display()))?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(stderr_path)
        .with_context(|| format!("create command stderr {}", stderr_path.display()))?;

    let mut command = Command::new(&program);
    command
        .args(&args)
        .current_dir(cwd)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    for (key, value) in &spec.env {
        command.env(key, replace_tokens(value, tokens));
    }
    let started = Instant::now();
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn qualification command {program}"))?;
    let timeout = Duration::from_secs(spec.timeout_seconds.max(1));
    let (exit_code, timed_out) = loop {
        if let Some(status) = child.try_wait().context("poll qualification command")? {
            break (status.code(), false);
        }
        if started.elapsed() >= timeout {
            child
                .kill()
                .context("kill timed-out qualification command")?;
            let status = child
                .wait()
                .context("reap timed-out qualification command")?;
            break (status.code(), true);
        }
        thread::sleep(Duration::from_millis(100));
    };
    let mut rendered = vec![program];
    rendered.extend(args);
    Ok(ProcessResult {
        exit_code,
        timed_out,
        duration_ms: started.elapsed().as_millis(),
        command: rendered,
    })
}

fn command_trial(
    plan: &TrialPlan,
    repo: &Path,
    trial_root: &Path,
    tokens: &BTreeMap<&str, String>,
) -> TrialResult {
    let started_at_unix = now_unix();
    let Some(program) = plan.program.as_ref() else {
        return inconclusive(plan, "command mode requires program");
    };
    let spec = CommandSpec {
        program: program.clone(),
        args: plan.args.clone(),
        cwd: plan.cwd.clone(),
        env: plan.env.clone(),
        timeout_seconds: plan.timeout_seconds,
    };
    let stdout = trial_root.join("stdout.log");
    let stderr = trial_root.join("stderr.log");
    match execute(&spec, repo, &stdout, &stderr, tokens) {
        Ok(process) => {
            let mut failures = Vec::new();
            let mut status = if process.exit_code == Some(0) && !process.timed_out {
                TrialStatus::Passed
            } else {
                TrialStatus::Failed
            };
            let mut assurance = plan.assurance;
            if assurance == AssuranceLevel::Independent {
                // Independent claims require a signed external attestation;
                // a locally launched process cannot self-certify independence.
                assurance = AssuranceLevel::QualificationLab;
                if status == TrialStatus::Passed {
                    status = TrialStatus::Inconclusive;
                }
                failures
                    .push("independent assurance requires external_attestation mode".to_owned());
            }
            if process.timed_out {
                failures.push(format!(
                    "command exceeded timeout of {} seconds",
                    plan.timeout_seconds
                ));
            }
            if process.exit_code != Some(0) {
                failures.push(format!("command exit code was {:?}", process.exit_code));
            }
            TrialResult {
                trial: plan.id.clone(),
                description: plan.description.clone(),
                status,
                assurance,
                started_at_unix,
                finished_at_unix: now_unix(),
                duration_ms: process.duration_ms,
                command: Some(process.command),
                exit_code: process.exit_code,
                metrics: BTreeMap::new(),
                evidence: vec![
                    format!("trials/{}/stdout.log", plan.id),
                    format!("trials/{}/stderr.log", plan.id),
                ],
                failures,
            }
        }
        Err(error) => TrialResult {
            trial: plan.id.clone(),
            description: plan.description.clone(),
            status: TrialStatus::Failed,
            assurance: plan.assurance,
            started_at_unix,
            finished_at_unix: now_unix(),
            duration_ms: 0,
            command: Some(
                std::iter::once(program.clone())
                    .chain(plan.args.clone())
                    .collect(),
            ),
            exit_code: None,
            metrics: BTreeMap::new(),
            evidence: Vec::new(),
            failures: vec![format!("could not execute command: {error:#}")],
        },
    }
}

fn external_trial(
    plan: &TrialPlan,
    repo: &Path,
    trial_root: &Path,
    release_version: &str,
    binary_digest: Option<&str>,
    base_tokens: &BTreeMap<&str, String>,
    default_verifier: Option<&CommandSpec>,
) -> TrialResult {
    let started_at_unix = now_unix();
    let fail = |status: TrialStatus, message: String| TrialResult {
        trial: plan.id.clone(),
        description: plan.description.clone(),
        status,
        assurance: plan.assurance,
        started_at_unix,
        finished_at_unix: now_unix(),
        duration_ms: 0,
        command: None,
        exit_code: None,
        metrics: BTreeMap::new(),
        evidence: Vec::new(),
        failures: vec![message],
    };

    let Some(attestation_path) = plan.attestation.as_deref() else {
        return fail(
            TrialStatus::Inconclusive,
            "external attestation path is not configured".to_owned(),
        );
    };
    let source_attestation = resolve(repo, attestation_path);
    let bytes = match fs::read(&source_attestation) {
        Ok(bytes) => bytes,
        Err(error) => {
            return fail(
                TrialStatus::Inconclusive,
                format!("external attestation unavailable: {error}"),
            )
        }
    };
    let attestation: ExternalAttestation = match serde_json::from_slice(&bytes) {
        Ok(attestation) => attestation,
        Err(error) => {
            return fail(
                TrialStatus::Failed,
                format!("invalid external attestation JSON: {error}"),
            )
        }
    };
    if attestation.gate_id != plan.id {
        return fail(
            TrialStatus::Failed,
            format!(
                "attestation gate {} does not match {}",
                attestation.gate_id, plan.id
            ),
        );
    }
    if attestation.release_version != release_version {
        return fail(
            TrialStatus::Failed,
            "attestation release version does not match plan".to_owned(),
        );
    }
    let Some(binary_digest) = binary_digest else {
        return fail(
            TrialStatus::Inconclusive,
            "cannot bind attestation without a release binary digest".to_owned(),
        );
    };
    if !attestation
        .subject_binary_sha256
        .eq_ignore_ascii_case(binary_digest)
    {
        return fail(
            TrialStatus::Failed,
            "attestation subject does not match release binary digest".to_owned(),
        );
    }
    let attestation_parent = source_attestation.parent().unwrap_or(repo);
    let signature_source = resolve(attestation_parent, &attestation.signature);
    if !signature_source.is_file() {
        return fail(
            TrialStatus::Inconclusive,
            format!(
                "detached signature unavailable: {}",
                signature_source.display()
            ),
        );
    }
    if let Err(error) = fs::create_dir_all(trial_root) {
        return fail(TrialStatus::Failed, error.to_string());
    }
    let copied_attestation = trial_root.join("attestation.json");
    let copied_signature = trial_root.join("attestation.signature");
    if let Err(error) = evidence::write_bytes_new(&copied_attestation, &bytes)
        .and_then(|_| evidence::copy_new(&signature_source, &copied_signature))
    {
        return fail(TrialStatus::Failed, format!("copy attestation: {error:#}"));
    }

    let mut copied_evidence = vec![
        format!("trials/{}/attestation.json", plan.id),
        format!("trials/{}/attestation.signature", plan.id),
    ];
    for (index, artifact) in attestation.artifacts.iter().enumerate() {
        let source = resolve(attestation_parent, Path::new(&artifact.path));
        let observed_size = fs::metadata(&source).map(|meta| meta.len());
        let observed_digest = evidence::sha256_file(&source);
        let size_matches = matches!(observed_size, Ok(size) if size == artifact.size);
        let digest_matches = matches!(
            observed_digest,
            Ok(ref digest) if digest.eq_ignore_ascii_case(&artifact.sha256)
        );
        if !size_matches || !digest_matches {
            return fail(
                TrialStatus::Failed,
                format!("attested artifact digest mismatch: {}", artifact.path),
            );
        }
        let basename = source
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("artifact.bin");
        let destination = trial_root
            .join("attested")
            .join(format!("{index:04}-{basename}"));
        if let Err(error) = evidence::copy_new(&source, &destination) {
            return fail(
                TrialStatus::Failed,
                format!("copy attested artifact: {error:#}"),
            );
        }
        copied_evidence.push(format!("trials/{}/attested/{index:04}-{basename}", plan.id));
    }

    if attestation.status == TrialStatus::Failed {
        return TrialResult {
            trial: plan.id.clone(),
            description: plan.description.clone(),
            status: TrialStatus::Failed,
            assurance: plan.assurance,
            started_at_unix,
            finished_at_unix: now_unix(),
            duration_ms: 0,
            command: None,
            exit_code: None,
            metrics: attestation.metrics,
            evidence: copied_evidence,
            failures: if attestation.findings.is_empty() {
                vec!["external laboratory reported failure".to_owned()]
            } else {
                attestation.findings
            },
        };
    }
    if attestation.status != TrialStatus::Passed {
        return TrialResult {
            trial: plan.id.clone(),
            description: plan.description.clone(),
            status: attestation.status,
            assurance: plan.assurance,
            started_at_unix,
            finished_at_unix: now_unix(),
            duration_ms: 0,
            command: None,
            exit_code: None,
            metrics: attestation.metrics,
            evidence: copied_evidence,
            failures: attestation.findings,
        };
    }
    let Some(verifier) = plan.verifier.as_ref().or(default_verifier) else {
        return TrialResult {
            trial: plan.id.clone(),
            description: plan.description.clone(),
            status: TrialStatus::Inconclusive,
            assurance: plan.assurance,
            started_at_unix,
            finished_at_unix: now_unix(),
            duration_ms: 0,
            command: None,
            exit_code: None,
            metrics: attestation.metrics,
            evidence: copied_evidence,
            failures: vec!["attestation has no cryptographic verifier command".to_owned()],
        };
    };

    let mut tokens = base_tokens.clone();
    tokens.insert(
        "{attestation}",
        copied_attestation.to_string_lossy().into_owned(),
    );
    tokens.insert(
        "{signature}",
        copied_signature.to_string_lossy().into_owned(),
    );
    let stdout = trial_root.join("verifier.stdout.log");
    let stderr = trial_root.join("verifier.stderr.log");
    match execute(verifier, repo, &stdout, &stderr, &tokens) {
        Ok(process) => {
            copied_evidence.push(format!("trials/{}/verifier.stdout.log", plan.id));
            copied_evidence.push(format!("trials/{}/verifier.stderr.log", plan.id));
            let passed = process.exit_code == Some(0) && !process.timed_out;
            TrialResult {
                trial: plan.id.clone(),
                description: plan.description.clone(),
                status: if passed {
                    TrialStatus::Passed
                } else {
                    TrialStatus::Failed
                },
                assurance: plan.assurance,
                started_at_unix,
                finished_at_unix: now_unix(),
                duration_ms: process.duration_ms,
                command: Some(process.command),
                exit_code: process.exit_code,
                metrics: attestation.metrics,
                evidence: copied_evidence,
                failures: if passed {
                    attestation.findings
                } else {
                    vec!["cryptographic attestation verification failed".to_owned()]
                },
            }
        }
        Err(error) => fail(
            TrialStatus::Failed,
            format!("could not execute attestation verifier: {error:#}"),
        ),
    }
}

fn inconclusive(plan: &TrialPlan, reason: &str) -> TrialResult {
    let now = now_unix();
    TrialResult {
        trial: plan.id.clone(),
        description: plan.description.clone(),
        status: TrialStatus::Inconclusive,
        assurance: plan.assurance,
        started_at_unix: now,
        finished_at_unix: now,
        duration_ms: 0,
        command: None,
        exit_code: None,
        metrics: BTreeMap::new(),
        evidence: Vec::new(),
        failures: vec![reason.to_owned()],
    }
}

fn missing_trial(id: &str, description: &str, reason: &str) -> TrialResult {
    let now = now_unix();
    TrialResult {
        trial: id.to_owned(),
        description: description.to_owned(),
        status: TrialStatus::Inconclusive,
        assurance: AssuranceLevel::Development,
        started_at_unix: now,
        finished_at_unix: now,
        duration_ms: 0,
        command: None,
        exit_code: None,
        metrics: BTreeMap::new(),
        evidence: Vec::new(),
        failures: vec![reason.to_owned()],
    }
}

fn qualification_id(release: &str) -> String {
    let safe_release = release
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("{}-{}", safe_release, ulid::Ulid::new())
}

pub fn run(plan_path: &Path, output: &Path, only: &[String]) -> Result<QualificationResult> {
    if output.exists() {
        bail!(
            "evidence directory already exists; refusing to overwrite {}",
            output.display()
        );
    }
    let plan_bytes = fs::read(plan_path)
        .with_context(|| format!("read qualification plan {}", plan_path.display()))?;
    let plan_text = std::str::from_utf8(&plan_bytes).context("qualification plan is not UTF-8")?;
    let plan: QualificationPlan = toml::from_str(plan_text).context("parse qualification plan")?;
    if plan.schema_version != 1 {
        bail!(
            "unsupported qualification plan schema {}",
            plan.schema_version
        );
    }
    if plan.release_version.trim().is_empty() {
        bail!("qualification plan release_version is empty");
    }
    let mut ids = BTreeSet::new();
    for trial in &plan.trials {
        validate_gate_id(&trial.id)?;
        if !ids.insert(trial.id.as_str()) {
            bail!("duplicate trial id in plan: {}", trial.id);
        }
    }
    let only = only.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for selected in &only {
        validate_gate_id(selected)?;
        if !ids.contains(selected) {
            bail!("--only references unknown trial {selected}");
        }
    }

    let current = std::env::current_dir()?;
    let repo = evidence::repository_root(&current)?;
    let started_at_unix = now_unix();
    let qualification_id = qualification_id(&plan.release_version);
    let source_digest = evidence::source_digest(&repo)?;
    let dirty = evidence::repository_dirty(&repo);
    let untracked = evidence::untracked_file_count(&repo);
    let binary_path = plan.binary.as_deref().map(|path| resolve(&repo, path));
    let binary_digest = binary_path
        .as_deref()
        .filter(|path| path.is_file())
        .map(evidence::sha256_file)
        .transpose()?;
    let environment = environment::capture(&repo);
    let rustc = environment::tool_version("rustc", &["-Vv"], &repo);
    let cargo = environment::tool_version("cargo", &["-V"], &repo);
    let git_commit = evidence::git_commit(&repo);
    // Snapshot the source before creating an output that may itself live under
    // the checkout. This keeps the digest complete without recursively hashing
    // the evidence being produced.
    fs::create_dir(output)
        .with_context(|| format!("create immutable evidence root {}", output.display()))?;
    evidence::write_bytes_new(&output.join("qualification-plan.toml"), &plan_bytes)?;
    let manifest = QualificationManifest {
        schema_version: 1,
        qualification_id: qualification_id.clone(),
        release_version: plan.release_version.clone(),
        git_commit: git_commit.clone(),
        source_digest: source_digest.clone(),
        binary_digest: binary_digest.clone(),
        rust_version: rustc.clone(),
        build_profile: plan.build_profile.clone(),
        target: plan.target.clone(),
        environment: environment.clone(),
        qualification_level: plan.level,
        suite_version: plan.suite_version.clone(),
        started_at_unix,
        repository_dirty: dirty,
        untracked_files: untracked,
        plan_sha256: evidence::sha256_bytes(&plan_bytes),
        metadata: plan.metadata.clone(),
    };
    evidence::write_json_new(&output.join("qualification-manifest.json"), &manifest)?;
    let manifest_digest = evidence::sha256_file(&output.join("qualification-manifest.json"))?;
    evidence::write_bytes_new(
        &output.join("qualification-manifest.sha256"),
        format!("{manifest_digest}  qualification-manifest.json\n").as_bytes(),
    )?;

    let lock_path = repo.join("Cargo.lock");
    let build_manifest = BuildManifest {
        schema_version: 1,
        release_version: plan.release_version.clone(),
        git_commit,
        source_sha256: source_digest,
        cargo_lock_sha256: if lock_path.is_file() {
            evidence::sha256_file(&lock_path)?
        } else {
            "unavailable".to_owned()
        },
        binary_path: binary_path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        binary_sha256: binary_digest.clone(),
        binary_size: binary_path
            .as_deref()
            .and_then(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len()),
        rustc,
        cargo,
        build_profile: plan.build_profile.clone(),
        repository_dirty: dirty,
    };
    evidence::write_json_new(&output.join("build-manifest.json"), &build_manifest)?;
    evidence::write_json_new(&output.join("environment-manifest.json"), &environment)?;

    let mut tokens = BTreeMap::new();
    tokens.insert("{repo}", repo.to_string_lossy().into_owned());
    tokens.insert("{evidence}", output.to_string_lossy().into_owned());
    tokens.insert(
        "{binary}",
        binary_path
            .as_deref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
    );
    tokens.insert("{binary_sha256}", binary_digest.clone().unwrap_or_default());
    tokens.insert("{qualification_id}", qualification_id.clone());

    let mut trials = Vec::new();
    for trial in &plan.trials {
        if !only.is_empty() && !only.contains(trial.id.as_str()) {
            continue;
        }
        let trial_root = output.join("trials").join(&trial.id);
        let result = match trial.mode {
            TrialMode::Command => command_trial(trial, &repo, &trial_root, &tokens),
            TrialMode::ExternalAttestation => external_trial(
                trial,
                &repo,
                &trial_root,
                &plan.release_version,
                binary_digest.as_deref(),
                &tokens,
                plan.external_verifier.as_ref(),
            ),
            TrialMode::Unconfigured => inconclusive(
                trial,
                "gate is deliberately unconfigured; Skipped/Inconclusive is never Pass",
            ),
        };
        trials.push(result);
    }

    for requirement in policy::requirements(plan.level) {
        if !trials.iter().any(|trial| trial.trial == requirement.id) {
            let reason = if !only.is_empty() && ids.contains(requirement.id) {
                "required gate was not selected in this partial run"
            } else {
                "required gate has no configured trial"
            };
            trials.push(missing_trial(
                requirement.id,
                requirement.description,
                reason,
            ));
        }
    }
    trials.sort_by(|left, right| left.trial.cmp(&right.trial));

    let (mut status, policy_limitations) = policy::aggregate(plan.level, &trials);
    let mut limitations = plan.known_limitations.clone();
    limitations.extend(policy_limitations);
    if plan.level >= QualificationLevel::ReleaseCandidate {
        if dirty {
            limitations.push(
                "release qualification is bound to a dirty source tree; rebuild from a clean commit"
                    .to_owned(),
            );
        }
        if binary_digest.is_none() {
            limitations.push(
                "release qualification requires an existing binary with a captured SHA-256 digest"
                    .to_owned(),
            );
        }
        if untracked > 0 {
            // The source digest covers tracked files only, so untracked files
            // are outside the reproducible subject and must be declared.
            limitations.push(format!(
                "{untracked} untracked files are present; they are outside the source digest and \
                 no third party can reproduce this checkout"
            ));
        }
        if environment.cpu_model == "unavailable"
            || environment.memory_bytes == 0
            || environment.storage_model == "unavailable"
            || environment.filesystem == "unavailable"
        {
            limitations.push(
                "release benchmark environment is incomplete (CPU, memory, storage or filesystem)"
                    .to_owned(),
            );
        }
    }
    limitations.sort();
    limitations.dedup();
    if status == QualificationStatus::Passed && !limitations.is_empty() {
        status = QualificationStatus::Unqualified;
    }
    let passed = status == QualificationStatus::Passed;
    let production_qualified = passed && plan.level >= QualificationLevel::GovernmentProduction;
    let required_gates = policy::requirements(plan.level)
        .into_iter()
        .map(|gate| gate.id.to_owned())
        .collect();
    let result = QualificationResult {
        schema_version: 1,
        qualification_id,
        release_version: plan.release_version,
        binary_digest,
        level: plan.level,
        status,
        trials,
        passed,
        production_qualified,
        known_limitations: limitations,
        required_gates,
        finished_at_unix: now_unix(),
    };
    evidence::write_json_new(&output.join("qualification-result.json"), &result)?;
    let result_digest = evidence::sha256_file(&output.join("qualification-result.json"))?;
    evidence::write_bytes_new(
        &output.join("qualification-result.sha256"),
        format!("{result_digest}  qualification-result.json\n").as_bytes(),
    )?;
    evidence::write_bytes_new(
        &output.join("qualification-report.md"),
        report::render(&manifest, &result).as_bytes(),
    )?;
    // §121 — bind the report to the digests of everything it describes before
    // sealing, so the Merkle root then covers the binding itself.
    evidence::write_json_new(
        &output.join(commitment::COMMITMENT_FILE),
        &commitment::build(output, &manifest)?,
    )?;
    evidence::seal(output, &result.qualification_id)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_ids_cannot_escape_the_evidence_tree() {
        assert!(validate_gate_id("q1_load").is_ok());
        assert!(validate_gate_id("../escape").is_err());
        assert!(validate_gate_id("Q1").is_err());
    }

    #[test]
    fn tokens_are_replaced_without_a_shell() {
        let mut tokens = BTreeMap::new();
        tokens.insert("{binary_sha256}", "abc".to_owned());
        assert_eq!(
            replace_tokens("subject={binary_sha256}", &tokens),
            "subject=abc"
        );
    }

    #[test]
    fn end_to_end_development_evidence_is_sealed_and_verified() {
        let temp = tempfile::tempdir().unwrap();
        let plan_path = temp.path().join("plan.toml");
        let output = temp.path().join("evidence");
        let mut plan = String::from(
            "schema_version = 1\nrelease_version = \"runner-self-test\"\nlevel = \"development\"\n",
        );
        for gate in ["unit_tests", "integration_tests", "lint", "basic_fuzz"] {
            plan.push_str(&format!(
                "\n[[trials]]\nid = \"{gate}\"\ndescription = \"self-test\"\nmode = \"command\"\nprogram = \"rustc\"\nargs = [\"-V\"]\n"
            ));
        }
        fs::write(&plan_path, plan).unwrap();
        let result = run(&plan_path, &output, &[]).unwrap();
        assert_eq!(result.status, QualificationStatus::Passed);
        assert!(!result.production_qualified);
        crate::verify::verify_evidence(&output).unwrap();
    }
}
