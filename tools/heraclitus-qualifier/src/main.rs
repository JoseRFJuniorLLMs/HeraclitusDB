mod commitment;
mod corruption;
mod crash;
mod dashboard;
mod doctor;
mod egress;
mod environment;
mod evidence;
mod history;
mod load;
mod manifest;
mod policy;
mod procstat;
mod regression;
mod report;
mod runner;
mod sbom;
mod server;
mod soak;
mod verify;
mod workload;

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use manifest::{CorruptionMode, QualificationLevel, WorkloadProfile};
use server::DurabilityMode;

/// §110 — a third party MUST be able to run the suite without editing code, so
/// the shipped plans are addressable by name and not only by path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PlanProfile {
    Development,
    ReleaseCandidate,
    GovProduction,
}

impl PlanProfile {
    fn filename(self) -> &'static str {
        match self {
            Self::Development => "development.toml",
            Self::ReleaseCandidate => "release-candidate.toml",
            Self::GovProduction => "government-production.toml",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Durability {
    Always,
    GroupCommit,
}

impl From<Durability> for DurabilityMode {
    fn from(value: Durability) -> Self {
        match value {
            Durability::Always => Self::Always,
            Durability::GroupCommit => Self::GroupCommit,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "heraclitus-qualifier",
    version,
    about = "SPEC-0049 qualification and immutable evidence harness"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Execute a qualification plan into a new immutable evidence directory.
    Run {
        /// Path to a plan. Mutually exclusive with --profile.
        #[arg(long, conflicts_with = "profile")]
        plan: Option<PathBuf>,
        /// Shipped plan to run by name, resolved inside the checkout.
        #[arg(long, value_enum)]
        profile: Option<PlanProfile>,
        #[arg(long)]
        out: PathBuf,
        /// Run only these gate ids. Missing required gates remain Inconclusive.
        #[arg(long = "only")]
        only: Vec<String>,
        /// Append the sealed run to this append-only history ledger (§109).
        #[arg(long)]
        history: Option<PathBuf>,
    },
    /// Verify every digest, the commitment and the qualification invariant.
    Verify {
        #[arg(long)]
        evidence: PathBuf,
        /// Re-hash this binary and require it to be the qualified one (§121).
        #[arg(long)]
        binary: Option<PathBuf>,
    },
    /// Emit a deterministic synthetic SOC dataset and its provenance manifest.
    Workload {
        #[arg(long, value_enum, default_value = "mixed")]
        profile: WorkloadProfile,
        #[arg(long, default_value_t = 428_931)]
        seed: u64,
        #[arg(long, default_value_t = 100_000)]
        events: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Drive a real gRPC target with deterministic SOC ingest/query stages.
    Load {
        #[arg(long)]
        target: String,
        #[arg(long, value_enum, default_value = "mixed")]
        profile: WorkloadProfile,
        #[arg(long, default_value_t = 428_931)]
        seed: u64,
        #[arg(long, default_value_t = 10_000)]
        operations_per_stage: u64,
        #[arg(long, default_value_t = 32)]
        concurrency: usize,
        #[arg(long, value_delimiter = ',', default_value = "10,25,50,75,100,125,150")]
        ramp_percent: Vec<u16>,
        #[arg(long, default_value_t = 60)]
        request_timeout_seconds: u64,
        /// Name of the environment variable containing a bearer token.
        #[arg(long)]
        bearer_token_env: Option<String>,
        #[arg(long)]
        report: PathBuf,
    },
    /// Q2 — start, load, abrupt kill, restart, verify, repeat (§21-§27).
    CrashLoop {
        /// The release binary under qualification, not a test harness.
        #[arg(long)]
        server_binary: PathBuf,
        /// New working directory for data, config and generation logs.
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value_t = 50)]
        cycles: u32,
        #[arg(long, default_value_t = 8)]
        concurrency: usize,
        #[arg(long, value_enum, default_value = "always")]
        durability: Durability,
        #[arg(long, default_value_t = 428_931)]
        seed: u64,
        #[arg(long, default_value_t = 400)]
        min_kill_delay_ms: u64,
        #[arg(long, default_value_t = 2_500)]
        max_kill_delay_ms: u64,
        #[arg(long, default_value_t = 120)]
        ready_timeout_seconds: u64,
        #[arg(long)]
        report: PathBuf,
    },
    /// Long-running stability with the §20 memory-leak gate.
    Soak {
        #[arg(long)]
        target: String,
        /// Process id of the server, required for the resource growth gates.
        #[arg(long)]
        pid: Option<u32>,
        /// Soak profile JSON, e.g. qa/qualification/soak/24h.json.
        #[arg(long)]
        profile: PathBuf,
        #[arg(long, default_value_t = 428_931)]
        seed: u64,
        #[arg(long, default_value_t = 60)]
        request_timeout_seconds: u64,
        #[arg(long)]
        bearer_token_env: Option<String>,
        #[arg(long)]
        report: PathBuf,
    },
    /// Watch a process for network egress during an air-gapped run (§97-§98).
    EgressMonitor {
        /// Command to run under observation.
        #[arg(long)]
        program: Option<String>,
        #[arg(long, num_args = 0.., allow_hyphen_values = true)]
        args: Vec<String>,
        /// Observe an already running process instead.
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long, default_value_t = 300)]
        duration_seconds: u64,
        #[arg(long, default_value_t = 200)]
        sample_interval_ms: u64,
        /// Literal peer IPs that are legitimate. Loopback is always allowed.
        #[arg(long)]
        allow: Vec<String>,
        #[arg(long)]
        report: PathBuf,
    },
    /// Copy a file and inject one deterministic corruption; never mutates input.
    Corrupt {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum)]
        mode: CorruptionMode,
        #[arg(long, default_value_t = 428_931)]
        seed: u64,
    },
    /// Generate a deterministic CycloneDX SBOM from the locked Cargo graph.
    Sbom {
        #[arg(long)]
        out: PathBuf,
    },
    /// Qualify a configuration file, not just the release (§138-§140).
    Doctor {
        #[arg(long)]
        config: PathBuf,
        /// Write the machine-readable report here as well as to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Append-only qualification history (§109).
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    /// Compare a candidate against a baseline under declared budgets (§126).
    Regression {
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        budgets: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Emit the §108 dashboard status for an evidence set.
    Dashboard {
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        history: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Check that a release package carries the §117 operational runbooks.
    Runbooks {
        #[arg(long, default_value = "docs/runbooks")]
        root: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the normative gates for a qualification level.
    Gates {
        #[arg(long, value_enum)]
        level: QualificationLevel,
    },
}

#[derive(Debug, Subcommand)]
enum HistoryCommand {
    /// Verify a sealed evidence set and append it to the ledger.
    Record {
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        history: PathBuf,
    },
    /// Print the ledger. Failures stay visible after they are fixed.
    List {
        #[arg(long)]
        history: PathBuf,
    },
}

fn resolve_plan(plan: Option<PathBuf>, profile: Option<PlanProfile>) -> Result<PathBuf> {
    match (plan, profile) {
        (Some(plan), _) => Ok(plan),
        (None, Some(profile)) => {
            let current = std::env::current_dir()?;
            let repo = evidence::repository_root(&current)
                .context("--profile resolves plans inside the checkout")?;
            let path = repo.join("qa/qualification/plans").join(profile.filename());
            if !path.is_file() {
                bail!("shipped plan is missing: {}", path.display());
            }
            Ok(path)
        }
        (None, None) => bail!("pass either --plan <file> or --profile <name>"),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            plan,
            profile,
            out,
            only,
            history,
        } => {
            let plan = resolve_plan(plan, profile)?;
            let result = runner::run(&plan, &out, &only)?;
            println!(
                "qualification_id={} status={:?} production_qualified={} evidence={}",
                result.qualification_id,
                result.status,
                result.production_qualified,
                out.display()
            );
            if let Some(history) = history {
                // Recorded whatever the outcome: §109 keeps failures.
                let entry = history::record(&out, &history)?;
                println!(
                    "HISTORY_RECORDED release={} status={:?} commitment={}",
                    entry.release_version, entry.status, entry.commitment
                );
            }
            if !result.passed {
                std::process::exit(match result.status {
                    manifest::QualificationStatus::Failed => 1,
                    manifest::QualificationStatus::Unqualified => 2,
                    manifest::QualificationStatus::Passed => 0,
                });
            }
        }
        Command::Verify { evidence, binary } => {
            let summary = verify::verify_evidence_against(&evidence, binary.as_deref())?;
            println!(
                "EVIDENCE_OK files={} merkle_root={} status={:?} binary_rechecked={:?}",
                summary.files, summary.merkle_root, summary.status, summary.binary_rechecked
            );
            println!(
                "COMMITMENT release_digest={} evidence_root={} report_digest={}",
                summary.commitment.release_digest.as_deref().unwrap_or("-"),
                summary.commitment.evidence_root,
                summary.commitment.report_digest
            );
        }
        Command::Workload {
            profile,
            seed,
            events,
            out,
        } => {
            let manifest = workload::generate(profile, seed, events, &out)?;
            println!(
                "WORKLOAD_OK events={} sha256={} path={}",
                manifest.events,
                manifest.sha256,
                out.display()
            );
        }
        Command::Load {
            target,
            profile,
            seed,
            operations_per_stage,
            concurrency,
            ramp_percent,
            request_timeout_seconds,
            bearer_token_env,
            report,
        } => {
            let config = load::LoadConfig {
                target,
                profile,
                seed,
                operations_per_stage,
                concurrency,
                ramp_percent,
                request_timeout_seconds,
                bearer_token_env,
                report,
            };
            let summary = load::run(config)?;
            println!(
                "LOAD_{:?} operations={} errors={} p99_ms={:.3} report={}",
                summary.status,
                summary.total_operations,
                summary.errors,
                summary.latency_p99_ms,
                summary.report.display()
            );
            if summary.errors > 0 || summary.status != load::LoadStatus::Passed {
                std::process::exit(1);
            }
        }
        Command::CrashLoop {
            server_binary,
            root,
            cycles,
            concurrency,
            durability,
            seed,
            min_kill_delay_ms,
            max_kill_delay_ms,
            ready_timeout_seconds,
            report,
        } => {
            let summary = crash::run(crash::CrashConfig {
                server_binary,
                root,
                cycles,
                concurrency,
                durability: durability.into(),
                seed,
                min_kill_delay_ms,
                max_kill_delay_ms,
                ready_timeout_seconds,
                report,
            })?;
            println!(
                "CRASH_{:?} cycles={} acknowledged={} missing_after_restart={} report={}",
                summary.status,
                summary.cycles_completed,
                summary.total_acknowledged,
                summary.total_missing_after_restart,
                summary.report.display()
            );
            if summary.status != crash::CrashStatus::Passed {
                std::process::exit(1);
            }
        }
        Command::Soak {
            target,
            pid,
            profile,
            seed,
            request_timeout_seconds,
            bearer_token_env,
            report,
        } => {
            let profile = soak::load_profile(&profile)?;
            let summary = soak::run(soak::SoakConfig {
                target,
                pid,
                profile,
                seed,
                request_timeout_seconds,
                bearer_token_env,
                report,
            })?;
            println!(
                "SOAK_{:?} operations={} errors={} report={}",
                summary.status,
                summary.total_operations,
                summary.errors,
                summary.report.display()
            );
            if summary.status != soak::SoakStatus::Passed {
                std::process::exit(1);
            }
        }
        Command::EgressMonitor {
            program,
            args,
            pid,
            duration_seconds,
            sample_interval_ms,
            allow,
            report,
        } => {
            let summary = egress::run(egress::EgressConfig {
                program,
                args,
                pid,
                duration_seconds,
                sample_interval_ms,
                allow,
                report,
            })?;
            println!(
                "EGRESS attempted_egress={} samples={} passed={} report={}",
                summary.attempted_egress,
                summary.samples_taken,
                summary.passed,
                summary.report.display()
            );
            if !summary.passed {
                std::process::exit(1);
            }
        }
        Command::Corrupt {
            input,
            output,
            mode,
            seed,
        } => {
            let record = corruption::inject(&input, &output, mode, seed)?;
            println!(
                "CORRUPTION_OK mode={:?} offset={:?} output_sha256={}",
                record.mode, record.offset, record.output_sha256
            );
        }
        Command::Sbom { out } => {
            let summary = sbom::generate(&out)?;
            println!(
                "SBOM_OK components={} sha256={} path={}",
                summary.components,
                summary.sha256,
                out.display()
            );
        }
        Command::Doctor { config, out } => {
            let report = doctor::run(&config)?;
            for finding in &report.findings {
                println!(
                    "{:?}\t{}\t{}\n\t-> {}",
                    finding.severity, finding.area, finding.message, finding.remedy
                );
            }
            println!(
                "DOCTOR blocking={} warnings={} safe_to_start={}",
                report.blocking, report.warnings, report.safe_to_start
            );
            if let Some(out) = out {
                evidence::write_json_new(&out, &report)?;
            }
            if !report.safe_to_start {
                std::process::exit(1);
            }
        }
        Command::History { command } => match command {
            HistoryCommand::Record { evidence, history } => {
                let entry = history::record(&evidence, &history)?;
                println!(
                    "HISTORY_RECORDED release={} level={:?} status={:?} commitment={}",
                    entry.release_version, entry.level, entry.status, entry.commitment
                );
            }
            HistoryCommand::List { history } => {
                let entries = history::read(&history)?;
                print!("{}", history::render(&entries));
                for (release, (status, failures)) in history::summarize(&entries) {
                    println!("SUMMARY {release} latest={status:?} non_passing_attempts={failures}");
                }
            }
        },
        Command::Regression {
            baseline,
            candidate,
            budgets,
            out,
        } => {
            let report = regression::run(&baseline, &candidate, &budgets, &out)?;
            println!(
                "REGRESSION baseline={} candidate={} review_required={} undetermined={} eligible_as_golden={}",
                report.baseline_release,
                report.candidate_release,
                report.review_required,
                report.undetermined,
                report.eligible_as_golden
            );
            if report.review_required > 0 {
                std::process::exit(1);
            }
        }
        Command::Dashboard {
            evidence,
            history,
            out,
        } => {
            let status = dashboard::build(&evidence, history.as_deref())?;
            evidence::write_json_new(&out, &status)?;
            println!(
                "DASHBOARD release={} level={:?} status={:?} production_qualified={} out={}",
                status.current_release,
                status.qualification_level,
                status.status,
                status.production_qualified,
                out.display()
            );
        }
        Command::Runbooks { root, out } => {
            let report = policy::check_runbooks(&root);
            for check in &report.checks {
                println!(
                    "{}\t{}\t{} bytes",
                    check.runbook,
                    if !check.present {
                        "MISSING"
                    } else if !check.substantial {
                        "STUB"
                    } else {
                        "ok"
                    },
                    check.bytes
                );
            }
            println!(
                "RUNBOOKS complete={} missing={} insubstantial={}",
                report.complete, report.missing, report.insubstantial
            );
            if let Some(out) = out {
                evidence::write_json_new(&out, &report)?;
            }
            if !report.complete {
                std::process::exit(1);
            }
        }
        Command::Gates { level } => {
            for requirement in policy::requirements(level) {
                println!(
                    "{}\t{:?}\t{}",
                    requirement.id, requirement.minimum_assurance, requirement.description
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shipped_profile_names_a_plan_that_exists() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        for profile in [
            PlanProfile::Development,
            PlanProfile::ReleaseCandidate,
            PlanProfile::GovProduction,
        ] {
            let path = repo.join("qa/qualification/plans").join(profile.filename());
            assert!(path.is_file(), "{}", path.display());
        }
    }

    #[test]
    fn a_run_without_plan_or_profile_is_refused() {
        assert!(resolve_plan(None, None).is_err());
        assert_eq!(
            resolve_plan(Some(PathBuf::from("x.toml")), None).unwrap(),
            PathBuf::from("x.toml")
        );
    }

    #[test]
    fn the_cli_surface_parses() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
