//! Q2 — real failure (SPEC-0049 §21–§27).
//!
//! The loop is the one §23 describes: start, load, random sleep, abrupt kill,
//! restart, verify, repeat. What makes it evidence rather than a smoke test is
//! §24: every append the server **acknowledged** before the kill must still be
//! readable afterwards. An acknowledgement that silently disappears is the one
//! outcome that fails the whole qualification, so the harness records each
//! acknowledgement as it arrives and re-reads them one by one after restart.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use heraclitus_client::{AppendOptions, Client};
use serde::Serialize;
use tokio::task::JoinSet;

use crate::evidence::{sha256_file, write_bytes_new, write_json_new};
use crate::server::{wait_ready, DurabilityMode, ServerSpec, Supervised};

/// Above this many acknowledgements per cycle the harness re-reads an evenly
/// spread sample instead of every event. The report always says which happened,
/// because "checked 256 of 40000" and "checked all" are different claims.
const FULL_VERIFICATION_CEILING: usize = 4_096;

#[derive(Debug, Clone)]
pub struct CrashConfig {
    pub server_binary: PathBuf,
    pub root: PathBuf,
    pub cycles: u32,
    pub concurrency: usize,
    pub durability: DurabilityMode,
    pub seed: u64,
    pub min_kill_delay_ms: u64,
    pub max_kill_delay_ms: u64,
    pub ready_timeout_seconds: u64,
    pub report: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashStatus {
    Passed,
    Failed,
    /// The harness could not complete the campaign, so it proves nothing.
    /// PQ17: this is never a pass.
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum VerificationScope {
    Full,
    Sampled,
}

#[derive(Debug, Serialize)]
struct CycleReport {
    cycle: u32,
    generation_killed: u32,
    /// The process actually terminated. §27 asks the campaign to be traceable
    /// back to a specific process, not just to "the server".
    killed_pid: Option<u32>,
    kill_after_ms: u64,
    /// Wall-clock the process actually survived. Shorter than `kill_after_ms`
    /// means it died on its own, which is a failure, not an injection.
    survived_ms: u128,
    self_terminated_before_kill: bool,
    head_before: u64,
    acknowledged: u64,
    max_acknowledged_lsn: u64,
    unacknowledged_attempts: u64,
    restart_ok: bool,
    restart_ms: u128,
    head_after_restart: u64,
    /// §27 — the recovered span the restarted server exposes.
    recovered_records: u64,
    head_regressed: bool,
    verification_scope: VerificationScope,
    verified_acknowledgements: usize,
    missing_acknowledgements: usize,
    integrity_ok: bool,
    integrity_message: String,
    failures: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CrashReport {
    schema_version: u32,
    generator: String,
    started_at_unix: u64,
    finished_at_unix: u64,
    server_binary: String,
    server_binary_sha256: String,
    /// Where the campaign ran. Reproducing a durability result needs the data
    /// directory and the endpoints as much as it needs the seed.
    data_dir: String,
    grpc_endpoint: String,
    rest_endpoint: String,
    durability_mode: DurabilityMode,
    /// `HERACLITUS_*` variables removed from the child's environment, so the
    /// config file is the whole truth about what ran.
    neutralised_environment: Vec<String>,
    seed: u64,
    cycles_requested: u32,
    cycles_completed: u32,
    concurrency: usize,
    total_acknowledged: u64,
    total_missing_after_restart: u64,
    total_head_regressions: u64,
    integrity_failures: u64,
    /// §25 in plain words, carried inside the artifact so a reader of the
    /// evidence alone cannot mistake this trial for the power-loss gate.
    power_loss_equivalent: bool,
    power_loss_note: &'static str,
    status: CrashStatus,
    cycles: Vec<CycleReport>,
    failures: Vec<String>,
}

#[derive(Debug)]
pub struct CrashSummary {
    pub status: CrashStatus,
    pub cycles_completed: u32,
    pub total_acknowledged: u64,
    pub total_missing_after_restart: u64,
    pub report: PathBuf,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn mix(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Deterministic kill instant for a cycle: the same seed reproduces the same
/// campaign, which §111 requires so another laboratory can repeat the run.
fn kill_delay_ms(seed: u64, cycle: u32, min: u64, max: u64) -> u64 {
    let span = max.saturating_sub(min).max(1);
    min + (mix(seed ^ u64::from(cycle)) % span)
}

#[derive(Debug, Clone)]
struct Acknowledgement {
    lsn: u64,
    event_id: String,
}

async fn appender(
    mut client: Client,
    seed: u64,
    cycle: u32,
    worker: usize,
    stop: Arc<AtomicBool>,
    acknowledged: Arc<Mutex<Vec<Acknowledgement>>>,
    attempts: Arc<Mutex<u64>>,
) {
    let mut sequence = 0_u64;
    while !stop.load(Ordering::Relaxed) {
        let key = mix(seed ^ (u64::from(cycle) << 40) ^ ((worker as u64) << 24) ^ sequence);
        let mut attrs = HashMap::new();
        attrs.insert("cycle".to_owned(), cycle.to_string());
        attrs.insert("worker".to_owned(), worker.to_string());
        attrs.insert("sequence".to_owned(), sequence.to_string());
        let content = format!(
            "crash-loop cycle={cycle} worker={worker} sequence={sequence} marker={key:016x}"
        );
        {
            let mut attempts = attempts.lock().expect("attempt counter poisoned");
            *attempts += 1;
        }
        match client
            .append_with_result(
                &format!("crash-agent-{worker}"),
                content.as_bytes(),
                AppendOptions {
                    session_id: format!("crash-{seed}-{cycle}"),
                    kind: "authentication".to_owned(),
                    hyp: vec![0.1, 0.1],
                    attrs,
                    parents: Vec::new(),
                    idempotency_key: format!("crash-{seed}-{cycle}-{worker}-{sequence}"),
                },
            )
            .await
        {
            Ok(result) => {
                // Recorded the instant the server said "durable". Anything the
                // caller learns after this point cannot un-acknowledge it.
                acknowledged
                    .lock()
                    .expect("acknowledgement ledger poisoned")
                    .push(Acknowledgement {
                        lsn: result.lsn,
                        event_id: result.event_id,
                    });
            }
            Err(_) => {
                // The connection dying is the expected end of a cycle.
                stop.store(true, Ordering::Relaxed);
                break;
            }
        }
        sequence += 1;
    }
}

async fn verify_acknowledgements(
    client: &mut Client,
    acknowledged: &[Acknowledgement],
) -> (VerificationScope, usize, usize) {
    let (scope, sample): (VerificationScope, Vec<&Acknowledgement>) =
        if acknowledged.len() <= FULL_VERIFICATION_CEILING {
            (VerificationScope::Full, acknowledged.iter().collect())
        } else {
            let stride = acknowledged.len() / FULL_VERIFICATION_CEILING;
            (
                VerificationScope::Sampled,
                acknowledged
                    .iter()
                    .step_by(stride.max(1))
                    .take(FULL_VERIFICATION_CEILING)
                    .collect(),
            )
        };
    let mut missing = 0_usize;
    for entry in &sample {
        let readable = match client
            .query(&format!(
                "MATCH (n) WHERE n.id = \"{}\" RETURN n LIMIT 1",
                entry.event_id
            ))
            .await
        {
            Ok(value) => value.to_string().contains(&entry.event_id),
            Err(_) => false,
        };
        if !readable {
            missing += 1;
        }
    }
    (scope, sample.len(), missing)
}

async fn run_cycle(
    supervised: &mut Supervised,
    config: &CrashConfig,
    cycle: u32,
) -> Result<CycleReport> {
    let endpoint = supervised.grpc_endpoint();
    let head_before = wait_ready(&endpoint, Duration::from_secs(config.ready_timeout_seconds))
        .await
        .with_context(|| format!("cycle {cycle}: server never became ready"))?;
    let generation_killed = supervised.generation();

    let template = Client::connect_with(&endpoint, Duration::from_secs(10))
        .await
        .context("connect crash-loop client")?
        .with_request_timeout(Duration::from_secs(10));

    let stop = Arc::new(AtomicBool::new(false));
    let acknowledged = Arc::new(Mutex::new(Vec::new()));
    let attempts = Arc::new(Mutex::new(0_u64));
    let mut tasks = JoinSet::new();
    for worker in 0..config.concurrency.max(1) {
        tasks.spawn(appender(
            template.clone(),
            config.seed,
            cycle,
            worker,
            Arc::clone(&stop),
            Arc::clone(&acknowledged),
            Arc::clone(&attempts),
        ));
    }

    let delay = kill_delay_ms(
        config.seed,
        cycle,
        config.min_kill_delay_ms,
        config.max_kill_delay_ms,
    );
    let started = Instant::now();
    tokio::time::sleep(Duration::from_millis(delay)).await;
    let killed_pid = supervised.pid();
    let self_terminated = supervised.exited()?.is_some();
    let survived_ms = started.elapsed().as_millis();
    supervised.kill_abruptly()?;
    stop.store(true, Ordering::Relaxed);
    while tasks.join_next().await.is_some() {}

    // Take the contents rather than unwrapping the Arc: a worker that panicked
    // may still hold a clone, and losing the whole cycle's ledger over that
    // would discard the very evidence the cycle exists to produce.
    let acknowledged = std::mem::take(
        &mut *acknowledged
            .lock()
            .expect("acknowledgement ledger poisoned"),
    );
    let attempts = *attempts.lock().expect("attempt counter poisoned");
    let max_acknowledged_lsn = acknowledged.iter().map(|entry| entry.lsn).max().unwrap_or(0);

    let restart_started = Instant::now();
    supervised.restart()?;
    let restart = wait_ready(&endpoint, Duration::from_secs(config.ready_timeout_seconds)).await;
    let restart_ms = restart_started.elapsed().as_millis();

    let mut failures = Vec::new();
    if self_terminated {
        failures.push(
            "server exited on its own before the injected kill; this cycle injected nothing"
                .to_owned(),
        );
    }
    let (restart_ok, head_after_restart) = match restart {
        Ok(head) => (true, head),
        Err(error) => {
            failures.push(format!("server did not reopen after the kill: {error:#}"));
            (false, 0)
        }
    };

    let mut verification_scope = VerificationScope::Full;
    let mut verified = 0_usize;
    let mut missing = acknowledged.len();
    let mut integrity_ok = false;
    let mut integrity_message = "server unavailable after restart".to_owned();
    if restart_ok {
        let mut client = Client::connect_with(&endpoint, Duration::from_secs(10))
            .await
            .context("reconnect after restart")?
            .with_request_timeout(Duration::from_secs(60));
        let observed = verify_acknowledgements(&mut client, &acknowledged).await;
        verification_scope = observed.0;
        verified = observed.1;
        missing = observed.2;
        match client.admin("verify", "").await {
            Ok((ok, message)) => {
                integrity_ok = ok;
                integrity_message = message.chars().take(4_096).collect();
            }
            Err(error) => {
                integrity_message = error.to_string();
            }
        }
    }

    // Head must never move backwards past an acknowledgement.
    //
    // The comparison is `<` and not `<=` on purpose. `head` is the next LSN to
    // assign, so on this engine an acknowledged LSN implies a strictly greater
    // head — but that depends on whether LSNs are numbered from zero, which is
    // an engine detail this harness should not encode. A false alarm here would
    // discredit the gate; the authoritative §24 check is the per-event re-read
    // below, which needs no such assumption.
    let head_regressed = restart_ok && head_after_restart < max_acknowledged_lsn;
    if head_regressed {
        failures.push(format!(
            "head {head_after_restart} does not cover acknowledged LSN {max_acknowledged_lsn}"
        ));
    }
    if missing > 0 {
        failures.push(format!(
            "{missing} of {verified} acknowledged events were absent after restart"
        ));
    }
    if restart_ok && !integrity_ok {
        failures.push(format!("integrity verification failed: {integrity_message}"));
    }

    Ok(CycleReport {
        cycle,
        generation_killed,
        killed_pid,
        kill_after_ms: delay,
        survived_ms,
        self_terminated_before_kill: self_terminated,
        head_before,
        acknowledged: acknowledged.len() as u64,
        max_acknowledged_lsn,
        unacknowledged_attempts: attempts.saturating_sub(acknowledged.len() as u64),
        restart_ok,
        restart_ms,
        head_after_restart,
        recovered_records: head_after_restart.saturating_sub(head_before),
        head_regressed,
        verification_scope,
        verified_acknowledgements: verified,
        missing_acknowledgements: missing,
        integrity_ok,
        integrity_message,
        failures,
    })
}

async fn run_async(config: &CrashConfig) -> Result<CrashSummary> {
    let started_at_unix = now_unix();
    let binary_sha256 = sha256_file(&config.server_binary)?;
    let mut supervised = Supervised::start(ServerSpec {
        binary: config.server_binary.clone(),
        root: config.root.clone(),
        durability: config.durability,
        segment_max_bytes: 8 * 1024 * 1024,
        storage_format: "v6".to_owned(),
        extra_config: Default::default(),
    })?;

    let mut cycles = Vec::new();
    let mut aborted = None;
    for cycle in 1..=config.cycles {
        match run_cycle(&mut supervised, config, cycle).await {
            Ok(report) => {
                let fatal = !report.failures.is_empty();
                cycles.push(report);
                if fatal {
                    // Stop at the first violation. Continuing would bury the
                    // evidence of the failure under thousands of later cycles.
                    break;
                }
            }
            Err(error) => {
                aborted = Some(format!("cycle {cycle} could not run: {error:#}"));
                break;
            }
        }
    }

    let total_acknowledged = cycles.iter().map(|cycle| cycle.acknowledged).sum();
    let total_missing_after_restart = cycles
        .iter()
        .map(|cycle| cycle.missing_acknowledgements as u64)
        .sum();
    let total_head_regressions = cycles.iter().filter(|cycle| cycle.head_regressed).count() as u64;
    let integrity_failures = cycles
        .iter()
        .filter(|cycle| cycle.restart_ok && !cycle.integrity_ok)
        .count() as u64;
    let mut failures = cycles
        .iter()
        .flat_map(|cycle| {
            cycle
                .failures
                .iter()
                .map(move |failure| format!("cycle {}: {failure}", cycle.cycle))
        })
        .collect::<Vec<_>>();
    if let Some(reason) = aborted {
        failures.push(reason);
    }
    if cycles.is_empty() {
        failures.push("no crash cycle completed".to_owned());
    }

    let cycles_completed = cycles.len() as u32;
    let status = if !failures.is_empty() {
        if total_missing_after_restart > 0 || total_head_regressions > 0 || integrity_failures > 0 {
            CrashStatus::Failed
        } else if cycles_completed < config.cycles {
            CrashStatus::Inconclusive
        } else {
            CrashStatus::Failed
        }
    } else {
        CrashStatus::Passed
    };

    let report = CrashReport {
        schema_version: 1,
        generator: format!("heraclitus-qualifier/{}", env!("CARGO_PKG_VERSION")),
        started_at_unix,
        finished_at_unix: now_unix(),
        server_binary: config.server_binary.to_string_lossy().into_owned(),
        server_binary_sha256: binary_sha256,
        data_dir: supervised.data_dir().to_string_lossy().into_owned(),
        grpc_endpoint: supervised.grpc_endpoint(),
        rest_endpoint: supervised.rest_endpoint(),
        durability_mode: supervised.durability(),
        neutralised_environment: Supervised::neutralised_environment(),
        seed: config.seed,
        cycles_requested: config.cycles,
        cycles_completed,
        concurrency: config.concurrency,
        total_acknowledged,
        total_missing_after_restart,
        total_head_regressions,
        integrity_failures,
        power_loss_equivalent: false,
        power_loss_note:
            "SPEC-0049 §25: abrupt process termination leaves the OS page cache intact and is not \
             equivalent to power loss. The power_loss gate is a separate, externally attested trial.",
        status,
        cycles,
        failures: failures.clone(),
    };
    write_json_new(&config.report, &report)?;
    let digest = sha256_file(&config.report)?;
    write_bytes_new(
        &sidecar_path(&config.report),
        format!(
            "{digest}  {}\n",
            config
                .report
                .file_name()
                .map(|name| name.to_string_lossy())
                .unwrap_or_default()
        )
        .as_bytes(),
    )?;
    Ok(CrashSummary {
        status,
        cycles_completed,
        total_acknowledged,
        total_missing_after_restart,
        report: config.report.clone(),
    })
}

pub fn sidecar_path(report: &std::path::Path) -> PathBuf {
    report.with_extension(format!(
        "{}sha256",
        report
            .extension()
            .map(|extension| format!("{}.", extension.to_string_lossy()))
            .unwrap_or_default()
    ))
}

pub fn run(config: CrashConfig) -> Result<CrashSummary> {
    if config.report.exists() {
        bail!(
            "refusing to overwrite crash report {}",
            config.report.display()
        );
    }
    if config.root.exists() {
        bail!(
            "crash working root must be new; refusing to reuse {}",
            config.root.display()
        );
    }
    if config.cycles == 0 {
        bail!("--cycles must be greater than zero");
    }
    if config.concurrency == 0 || config.concurrency > 1_024 {
        bail!("--concurrency must be between 1 and 1024");
    }
    if config.min_kill_delay_ms == 0 || config.max_kill_delay_ms <= config.min_kill_delay_ms {
        bail!("--max-kill-delay-ms must be greater than --min-kill-delay-ms, which must be > 0");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create crash-loop runtime")?;
    runtime.block_on(run_async(&config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_instants_are_reproducible_and_inside_the_window() {
        for cycle in 0..500 {
            let delay = kill_delay_ms(428_931, cycle, 200, 1_200);
            assert!((200..1_200).contains(&delay), "{delay}");
            assert_eq!(delay, kill_delay_ms(428_931, cycle, 200, 1_200));
        }
        // Different seeds must not collapse onto the same campaign.
        let a = (0..64).map(|c| kill_delay_ms(1, c, 200, 1_200)).collect::<Vec<_>>();
        let b = (0..64).map(|c| kill_delay_ms(2, c, 200, 1_200)).collect::<Vec<_>>();
        assert_ne!(a, b);
    }

    #[test]
    fn a_zero_cycle_campaign_is_rejected_before_touching_the_disk() {
        let temp = tempfile::tempdir().unwrap();
        let error = run(CrashConfig {
            server_binary: temp.path().join("server"),
            root: temp.path().join("run"),
            cycles: 0,
            concurrency: 4,
            durability: DurabilityMode::Always,
            seed: 1,
            min_kill_delay_ms: 200,
            max_kill_delay_ms: 800,
            ready_timeout_seconds: 30,
            report: temp.path().join("crash.json"),
        })
        .unwrap_err();
        assert!(error.to_string().contains("--cycles"));
    }

    #[test]
    fn the_sidecar_sits_beside_the_report() {
        assert_eq!(
            sidecar_path(std::path::Path::new("q2.json")),
            PathBuf::from("q2.json.sha256")
        );
    }
}
