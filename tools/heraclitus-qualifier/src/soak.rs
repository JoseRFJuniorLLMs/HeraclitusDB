//! Soak testing (SPEC-0049 §18–§20).
//!
//! §18 is blunt about why this exists: a short benchmark does not prove
//! stability. The soak runs a steady workload for hours and watches the series
//! §19 names — memory, descriptors, threads, LSN lag, latency drift — then
//! applies the §20 gate, which is the subtle one. Caches are *supposed* to
//! grow; the failure is growth that never stops. The harness separates the two
//! by ignoring the warm-up window entirely and fitting a slope only over the
//! stabilized remainder, then comparing that slope against a budget the
//! operator declared in advance.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use heraclitus_client::Client;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use crate::evidence::{sha256_file, write_bytes_new, write_json_new};
use crate::load::{execute_operation, latency_summary, mix, operation, LatencySummary};
use crate::manifest::WorkloadProfile;
use crate::procstat::{self, ProcessSample};

/// A soak profile as shipped in `qa/qualification/soak/`. Budgets are declared
/// before the run, never derived from its own result: a threshold fitted to the
/// measurement it is meant to judge cannot fail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoakProfile {
    pub schema_version: u32,
    pub id: String,
    pub description: String,
    pub duration_seconds: u64,
    pub sample_interval_seconds: u64,
    /// Warm-up excluded from the leak gate. Cache fill and index warm-up
    /// legitimately grow memory here.
    pub stabilization_seconds: u64,
    pub concurrency: usize,
    pub workload_profile: WorkloadProfile,
    /// §20 budget. Growth beyond this over the stabilized window is
    /// "unbounded", not "expected cache growth".
    pub memory_growth_budget_bytes_per_hour: f64,
    pub handle_growth_budget_per_hour: f64,
    pub thread_growth_budget_per_hour: f64,
    /// Ratio of final-window p99 to first-window p99 above which latency has
    /// drifted rather than merely fluctuated.
    pub latency_drift_budget_ratio: f64,
    /// Minimum qualification level this profile can satisfy. Documented so a
    /// six-hour profile is never mistaken for the MissionCritical soak.
    pub satisfies_level: String,
}

#[derive(Debug, Clone)]
pub struct SoakConfig {
    pub target: String,
    pub pid: Option<u32>,
    pub profile: SoakProfile,
    pub seed: u64,
    pub request_timeout_seconds: u64,
    pub bearer_token_env: Option<String>,
    pub report: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SoakStatus {
    Passed,
    Failed,
    /// The host could not produce a series the gate depends on. PQ17: never a
    /// pass, and deliberately distinct from Failed — nothing was disproven.
    Inconclusive,
}

#[derive(Debug, Serialize)]
struct Sample {
    elapsed_seconds: f64,
    head: u64,
    operations_completed: u64,
    errors: u64,
    process: ProcessSample,
}

#[derive(Debug, Serialize)]
struct GrowthGate {
    metric: &'static str,
    /// Slope over the whole stabilized window, expressed per hour.
    observed_per_hour: Option<f64>,
    /// Slope over the second half of that window.
    ///
    /// §20 forbids *continuous* growth, and a single step is not continuous. A
    /// server whose thread pool settles from 13 to 17 workers and then stays
    /// there produces a positive slope across a window that contains the step,
    /// even though the series is flat afterwards — measured, not hypothesised.
    /// Requiring the tail to be growing too separates "grew once" from
    /// "growing", without hiding either number.
    observed_second_half_per_hour: Option<f64>,
    budget_per_hour: f64,
    samples_in_window: usize,
    samples_in_second_half: usize,
    within_budget: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SoakReport {
    schema_version: u32,
    generator: String,
    started_at_unix: u64,
    finished_at_unix: u64,
    target: String,
    monitored_pid: Option<u32>,
    profile: SoakProfile,
    seed: u64,
    planned_duration_seconds: u64,
    observed_duration_seconds: f64,
    total_operations: u64,
    total_errors: u64,
    initial_head: u64,
    final_head: u64,
    /// Percentiles over a bounded, decimated sample. Stated as sampled when it
    /// is, so nobody reads it as an exact figure over every operation.
    latency_overall: LatencySummary,
    latency_overall_is_sampled: bool,
    latency_overall_sample_stride: u64,
    /// One exact summary per sample window — this is where drift is visible.
    latency_windows: Vec<LatencySummary>,
    latency_first_window: LatencySummary,
    latency_final_window: LatencySummary,
    latency_drift_ratio: Option<f64>,
    latency_within_budget: Option<bool>,
    gates: Vec<GrowthGate>,
    integrity_ok: bool,
    integrity_message: String,
    samples: Vec<Sample>,
    status: SoakStatus,
    failures: Vec<String>,
    limitations: Vec<String>,
}

#[derive(Debug)]
pub struct SoakSummary {
    pub status: SoakStatus,
    pub total_operations: u64,
    pub errors: u64,
    pub report: PathBuf,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Bound on the retained latency sample used for the overall percentiles.
///
/// A 168-hour soak at a few thousand operations per second produces billions of
/// samples. Keeping them all would make the harness itself grow without limit —
/// a memory leak inside the tool whose job is to detect memory leaks, which
/// would then fail the run it was measuring.
const LATENCY_RESERVOIR_CAP: usize = 262_144;

/// Longest a worker may hold measured latencies before publishing them.
/// Shorter than any sensible sample interval, so no window can end up empty
/// simply because throughput was low.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);

/// Deterministic decimating reservoir: keeps every sample until the cap, then
/// halves by dropping every second entry and doubles the stride. No RNG, so
/// §111 reproducibility holds; the retained sample stays spread across the whole
/// run rather than favouring its beginning or its end.
#[derive(Debug, Default)]
struct LatencyReservoir {
    kept: Vec<u64>,
    stride: u64,
    seen_since_keep: u64,
}

impl LatencyReservoir {
    fn new() -> Self {
        Self {
            kept: Vec::new(),
            stride: 1,
            seen_since_keep: 0,
        }
    }

    fn extend(&mut self, samples: &[u64]) {
        for sample in samples {
            self.seen_since_keep += 1;
            if self.seen_since_keep < self.stride {
                continue;
            }
            self.seen_since_keep = 0;
            self.kept.push(*sample);
            if self.kept.len() >= LATENCY_RESERVOIR_CAP {
                let mut index = 0;
                self.kept.retain(|_| {
                    index += 1;
                    index % 2 == 1
                });
                self.stride = self.stride.saturating_mul(2);
            }
        }
    }
}

/// Fit growth over the samples taken after stabilization, converted to units
/// per hour so the budget reads the way an operator writes it.
fn growth_per_hour(
    samples: &[Sample],
    stabilization_seconds: f64,
    extract: impl Fn(&ProcessSample) -> Option<u64>,
) -> (Option<f64>, usize) {
    let mut seconds = Vec::new();
    let mut values = Vec::new();
    for sample in samples
        .iter()
        .filter(|sample| sample.elapsed_seconds >= stabilization_seconds)
    {
        if let Some(value) = extract(&sample.process) {
            seconds.push(sample.elapsed_seconds);
            values.push(value as f64);
        }
    }
    let count = seconds.len();
    (
        procstat::slope_per_second(&seconds, &values).map(|slope| slope * 3_600.0),
        count,
    )
}

fn gate(
    metric: &'static str,
    samples: &[Sample],
    stabilization_seconds: f64,
    budget_per_hour: f64,
    extract: impl Fn(&ProcessSample) -> Option<u64> + Copy,
) -> GrowthGate {
    let (observed_per_hour, samples_in_window) =
        growth_per_hour(samples, stabilization_seconds, extract);

    // The tail of the stabilized window, used to tell a step apart from a
    // trend. Its start is the midpoint between stabilization and the end of
    // the run, so it always covers the most recent half of what was measured.
    let last_elapsed = samples
        .last()
        .map(|sample| sample.elapsed_seconds)
        .unwrap_or(stabilization_seconds);
    let midpoint = stabilization_seconds + (last_elapsed - stabilization_seconds) / 2.0;
    let (observed_second_half_per_hour, samples_in_second_half) =
        growth_per_hour(samples, midpoint, extract);

    let within_budget = observed_per_hour.map(|whole| {
        if whole <= budget_per_hour {
            return true;
        }
        // Over budget across the window. It only counts as the unbounded growth
        // §20 forbids if the tail is still climbing. Too few tail samples to
        // fit means the tail cannot exonerate it, so the whole-window verdict
        // stands rather than being waved through.
        match observed_second_half_per_hour {
            Some(tail) => tail <= budget_per_hour,
            None => false,
        }
    });

    GrowthGate {
        metric,
        observed_per_hour,
        observed_second_half_per_hour,
        budget_per_hour,
        samples_in_window,
        samples_in_second_half,
        within_budget,
    }
}

/// Counters every soak worker shares. Grouped so the worker signature stays
/// readable as the set grows.
#[derive(Clone)]
struct SoakLedger {
    stop: Arc<AtomicBool>,
    completed: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    latencies: Arc<Mutex<Vec<u64>>>,
}

#[derive(Clone, Copy)]
struct SoakWorkerSpec {
    profile: WorkloadProfile,
    seed: u64,
    worker_index: usize,
    initial_head: u64,
}

async fn worker(mut client: Client, spec: SoakWorkerSpec, ledger: SoakLedger) {
    let mut sequence = spec.worker_index as u64;
    let mut local = Vec::new();
    let mut last_flush = Instant::now();
    while !ledger.stop.load(Ordering::Relaxed) {
        let kind = operation(spec.profile, spec.seed ^ mix(sequence));
        let started = Instant::now();
        let outcome = execute_operation(
            &mut client,
            kind,
            spec.seed,
            sequence,
            spec.initial_head,
            spec.profile,
        )
        .await
        .is_ok();
        local.push(started.elapsed().as_micros().min(u64::MAX as u128) as u64);
        if outcome {
            ledger.completed.fetch_add(1, Ordering::Relaxed);
        } else {
            ledger.errors.fetch_add(1, Ordering::Relaxed);
        }
        // Flush on a bounded delay OR a full batch. Batching alone was a real
        // defect: at a few operations per second the 256-sample threshold left
        // whole sample windows empty, so §19 latency drift — the reason the
        // windows exist — could not be computed at all. Time-bounding keeps
        // every window populated without making the shared lock the thing
        // being measured under load.
        if local.len() >= 256 || (!local.is_empty() && last_flush.elapsed() >= FLUSH_INTERVAL) {
            ledger
                .latencies
                .lock()
                .expect("latency ledger poisoned")
                .append(&mut local);
            last_flush = Instant::now();
        }
        sequence = sequence.wrapping_add(1_024);
    }
    if !local.is_empty() {
        ledger
            .latencies
            .lock()
            .expect("latency ledger poisoned")
            .append(&mut local);
    }
}

async fn run_async(config: &SoakConfig) -> Result<SoakSummary> {
    let started_at_unix = now_unix();
    let mut control = Client::connect_with(&config.target, Duration::from_secs(15))
        .await
        .with_context(|| format!("connect soak target {}", config.target))?
        .with_request_timeout(Duration::from_secs(config.request_timeout_seconds.max(1)));
    if let Some(name) = &config.bearer_token_env {
        let token = std::env::var(name)
            .with_context(|| format!("bearer token environment variable {name}"))?;
        control = control
            .with_bearer_token(&token)
            .context("invalid bearer token metadata")?;
    }
    let initial_head = control.snapshot().await.context("capture initial head")?;

    let ledger = SoakLedger {
        stop: Arc::new(AtomicBool::new(false)),
        completed: Arc::new(AtomicU64::new(0)),
        errors: Arc::new(AtomicU64::new(0)),
        latencies: Arc::new(Mutex::new(Vec::new())),
    };
    let mut tasks = JoinSet::new();
    for worker_index in 0..config.profile.concurrency.max(1) {
        tasks.spawn(worker(
            control.clone(),
            SoakWorkerSpec {
                profile: config.profile.workload_profile,
                seed: config.seed,
                worker_index,
                initial_head,
            },
            ledger.clone(),
        ));
    }
    let SoakLedger {
        stop,
        completed,
        errors,
        latencies,
    } = ledger;

    let interval = Duration::from_secs(config.profile.sample_interval_seconds.max(1));
    let deadline = Instant::now() + Duration::from_secs(config.profile.duration_seconds);
    let started = Instant::now();
    let mut samples = Vec::new();
    // Latency is summarised per sample window so drift is measurable; an
    // overall p99 hides a system that got three times slower halfway through.
    let mut window_summaries: Vec<LatencySummary> = Vec::new();
    let mut reservoir = LatencyReservoir::new();
    while Instant::now() < deadline {
        tokio::time::sleep(interval).await;
        let head = control.snapshot().await.unwrap_or(0);
        {
            // Drain, do not accumulate: the ledger must not grow with the soak.
            let window = std::mem::take(&mut *latencies.lock().expect("latency ledger poisoned"));
            reservoir.extend(&window);
            window_summaries.push(latency_summary(&window));
        }
        samples.push(Sample {
            elapsed_seconds: started.elapsed().as_secs_f64(),
            head,
            operations_completed: completed.load(Ordering::Relaxed),
            errors: errors.load(Ordering::Relaxed),
            process: match config.pid {
                Some(pid) => procstat::sample(pid),
                None => ProcessSample::default(),
            },
        });
    }
    stop.store(true, Ordering::Relaxed);
    while tasks.join_next().await.is_some() {}

    let observed_duration_seconds = started.elapsed().as_secs_f64();
    // Whatever the workers produced after the last window boundary.
    {
        let tail = std::mem::take(&mut *latencies.lock().expect("latency ledger poisoned"));
        if !tail.is_empty() {
            reservoir.extend(&tail);
            window_summaries.push(latency_summary(&tail));
        }
    }
    let final_head = control.snapshot().await.unwrap_or(0);
    let (integrity_ok, integrity_message) = match control.admin("verify", "").await {
        Ok((ok, message)) => (ok, message.chars().take(4_096).collect::<String>()),
        Err(error) => (false, error.to_string()),
    };

    let stabilization = config.profile.stabilization_seconds as f64;
    let gates = vec![
        gate(
            "resident_set_bytes",
            &samples,
            stabilization,
            config.profile.memory_growth_budget_bytes_per_hour,
            |process| process.rss_bytes,
        ),
        gate(
            "open_handles",
            &samples,
            stabilization,
            config.profile.handle_growth_budget_per_hour,
            |process| process.handles,
        ),
        gate(
            "threads",
            &samples,
            stabilization,
            config.profile.thread_growth_budget_per_hour,
            |process| process.threads,
        ),
    ];

    let latency_first_window = window_summaries
        .first()
        .cloned()
        .unwrap_or_else(|| latency_summary(&[]));
    let latency_final_window = window_summaries
        .last()
        .cloned()
        .unwrap_or_else(|| latency_summary(&[]));
    let latency_drift_ratio = if latency_first_window.p99_ms > 0.0 {
        Some(latency_final_window.p99_ms / latency_first_window.p99_ms)
    } else {
        None
    };
    let latency_within_budget =
        latency_drift_ratio.map(|ratio| ratio <= config.profile.latency_drift_budget_ratio);

    let mut failures = Vec::new();
    let mut limitations = Vec::new();
    let total_errors = errors.load(Ordering::Relaxed);
    let total_operations = completed.load(Ordering::Relaxed);
    if total_errors > 0 {
        failures.push(format!("{total_errors} operations failed during the soak"));
    }
    if !integrity_ok {
        failures.push(format!(
            "post-soak integrity check failed: {integrity_message}"
        ));
    }
    if final_head < initial_head {
        failures.push(format!(
            "head regressed from {initial_head} to {final_head} during the soak"
        ));
    }
    for gate in &gates {
        match gate.within_budget {
            Some(false) => failures.push(format!(
                "{} grew {:.2}/hour after stabilization and {:.2}/hour over the final half; \
                 budget is {:.2}/hour, and the tail is still climbing",
                gate.metric,
                gate.observed_per_hour.unwrap_or_default(),
                gate.observed_second_half_per_hour.unwrap_or_default(),
                gate.budget_per_hour
            )),
            None => limitations.push(format!(
                "{} was not observable on this host; the §20 leak gate is unproven",
                gate.metric
            )),
            Some(true) => {}
        }
    }
    match latency_within_budget {
        Some(false) => failures.push(format!(
            "p99 latency drifted by {:.2}x; budget is {:.2}x",
            latency_drift_ratio.unwrap_or_default(),
            config.profile.latency_drift_budget_ratio
        )),
        None => limitations.push("latency drift could not be computed from the windows".to_owned()),
        Some(true) => {}
    }
    if observed_duration_seconds + 1.0 < config.profile.duration_seconds as f64 {
        limitations.push(format!(
            "soak ran {observed_duration_seconds:.0}s of the planned {}s",
            config.profile.duration_seconds
        ));
    }
    if config.pid.is_none() {
        limitations
            .push("no --pid was supplied, so no process resource series was sampled".to_owned());
    } else {
        let incomplete = samples
            .iter()
            .filter(|sample| !sample.process.is_complete())
            .count();
        if incomplete > 0 {
            limitations.push(format!(
                "{incomplete} of {} samples could not read every resource series; the process may \
                 have been unreachable during them",
                samples.len()
            ));
        }
    }

    let status = if !failures.is_empty() {
        SoakStatus::Failed
    } else if !limitations.is_empty() {
        SoakStatus::Inconclusive
    } else {
        SoakStatus::Passed
    };

    let report = SoakReport {
        schema_version: 1,
        generator: format!("heraclitus-qualifier/{}", env!("CARGO_PKG_VERSION")),
        started_at_unix,
        finished_at_unix: now_unix(),
        target: config.target.clone(),
        monitored_pid: config.pid,
        profile: config.profile.clone(),
        seed: config.seed,
        planned_duration_seconds: config.profile.duration_seconds,
        observed_duration_seconds,
        total_operations,
        total_errors,
        initial_head,
        final_head,
        latency_overall: latency_summary(&reservoir.kept),
        latency_overall_is_sampled: reservoir.stride > 1,
        latency_overall_sample_stride: reservoir.stride,
        latency_windows: window_summaries,
        latency_first_window,
        latency_final_window,
        latency_drift_ratio,
        latency_within_budget,
        gates,
        integrity_ok,
        integrity_message,
        samples,
        status,
        failures,
        limitations,
    };
    write_json_new(&config.report, &report)?;
    let digest = sha256_file(&config.report)?;
    write_bytes_new(
        &crate::crash::sidecar_path(&config.report),
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
    Ok(SoakSummary {
        status,
        total_operations,
        errors: total_errors,
        report: config.report.clone(),
    })
}

pub fn load_profile(path: &std::path::Path) -> Result<SoakProfile> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read soak profile {}", path.display()))?;
    let profile: SoakProfile =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    if profile.schema_version != 1 {
        bail!("unsupported soak profile schema {}", profile.schema_version);
    }
    if profile.stabilization_seconds >= profile.duration_seconds {
        bail!("soak stabilization window must be shorter than the soak itself");
    }
    if profile.sample_interval_seconds == 0 {
        bail!("soak sample interval must be greater than zero");
    }
    Ok(profile)
}

pub fn run(config: SoakConfig) -> Result<SoakSummary> {
    if config.report.exists() {
        bail!(
            "refusing to overwrite soak report {}",
            config.report.display()
        );
    }
    if config.profile.concurrency == 0 || config.profile.concurrency > 4_096 {
        bail!("soak concurrency must be between 1 and 4096");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create soak runtime")?;
    runtime.block_on(run_async(&config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(elapsed: f64, rss: Option<u64>) -> Sample {
        Sample {
            elapsed_seconds: elapsed,
            head: 0,
            operations_completed: 0,
            errors: 0,
            process: ProcessSample {
                pid: 1,
                rss_bytes: rss,
                threads: Some(8),
                handles: Some(32),
            },
        }
    }

    #[test]
    fn warm_up_growth_does_not_count_against_the_leak_gate() {
        // Memory triples during warm-up and is flat afterwards: a cache filling,
        // not a leak. Fitting the whole series would call this a leak.
        let samples = vec![
            sample(0.0, Some(100_000_000)),
            sample(60.0, Some(300_000_000)),
            sample(120.0, Some(300_000_000)),
            sample(180.0, Some(300_000_000)),
            sample(240.0, Some(300_000_000)),
        ];
        let gate = gate("resident_set_bytes", &samples, 120.0, 1_000_000.0, |p| {
            p.rss_bytes
        });
        assert_eq!(gate.within_budget, Some(true));
        assert_eq!(gate.samples_in_window, 3);
    }

    #[test]
    fn a_single_step_that_then_goes_flat_is_not_a_leak() {
        // Measured, not invented: a real server settled its thread pool from 13
        // to 17 workers over the first minute and then stayed there. Fitting one
        // line across a window containing that step reports growth, and failing
        // on it would reject a perfectly stable server.
        let series = [
            (0.0, 13),
            (20.0, 14),
            (40.0, 14),
            (60.0, 17),
            (80.0, 17),
            (100.0, 17),
            (120.0, 17),
            (140.0, 17),
        ];
        let samples = series
            .iter()
            .map(|(elapsed, threads)| Sample {
                elapsed_seconds: *elapsed,
                head: 0,
                operations_completed: 0,
                errors: 0,
                process: ProcessSample {
                    pid: 1,
                    rss_bytes: Some(1),
                    threads: Some(*threads),
                    handles: Some(32),
                },
            })
            .collect::<Vec<_>>();
        let gate = gate("threads", &samples, 0.0, 60.0, |p| p.threads);
        // The whole-window slope is over budget...
        assert!(gate.observed_per_hour.unwrap() > 60.0);
        // ...but the tail is flat, so this is a step, not continuous growth.
        assert_eq!(gate.observed_second_half_per_hour, Some(0.0));
        assert_eq!(gate.within_budget, Some(true));
    }

    #[test]
    fn growth_that_keeps_going_still_fails_after_the_step_rule() {
        // The rule must not become an escape hatch: a series that grows in the
        // window AND in its tail is exactly what §20 forbids.
        let samples = (0..9)
            .map(|index| Sample {
                elapsed_seconds: index as f64 * 600.0,
                head: 0,
                operations_completed: 0,
                errors: 0,
                process: ProcessSample {
                    pid: 1,
                    rss_bytes: Some(100_000_000 + index as u64 * 50_000_000),
                    threads: Some(8),
                    handles: Some(32),
                },
            })
            .collect::<Vec<_>>();
        let gate = gate("resident_set_bytes", &samples, 0.0, 1_000_000.0, |p| {
            p.rss_bytes
        });
        assert!(gate.observed_second_half_per_hour.unwrap() > 1_000_000.0);
        assert_eq!(gate.within_budget, Some(false));
    }

    #[test]
    fn steady_growth_after_stabilization_fails_the_gate() {
        let samples = (0..7)
            .map(|index| {
                sample(
                    index as f64 * 600.0,
                    Some(100_000_000 + index as u64 * 50_000_000),
                )
            })
            .collect::<Vec<_>>();
        let gate = gate("resident_set_bytes", &samples, 600.0, 1_000_000.0, |p| {
            p.rss_bytes
        });
        assert_eq!(gate.within_budget, Some(false));
        // 50 MB per 600 s is 300 MB/hour.
        assert!((gate.observed_per_hour.unwrap() - 300_000_000.0).abs() < 1.0);
    }

    #[test]
    fn the_latency_reservoir_stays_bounded_over_a_long_soak() {
        // The tool that looks for unbounded growth must not grow without bound.
        let mut reservoir = LatencyReservoir::new();
        for chunk in 0..64 {
            let batch = (0..100_000_u64)
                .map(|i| chunk * 100_000 + i)
                .collect::<Vec<_>>();
            reservoir.extend(&batch);
            assert!(
                reservoir.kept.len() <= LATENCY_RESERVOIR_CAP,
                "reservoir grew to {}",
                reservoir.kept.len()
            );
        }
        assert!(reservoir.stride > 1, "6.4M samples should have decimated");
        // Decimation must keep the sample spread over the whole run, not just
        // its beginning — otherwise late latency never reaches the percentiles.
        let last = *reservoir.kept.last().unwrap();
        assert!(last > 6_000_000, "retained sample stops at {last}");
    }

    #[test]
    fn the_reservoir_is_exact_until_it_has_to_decimate() {
        let mut reservoir = LatencyReservoir::new();
        let batch = (0..1_000_u64).collect::<Vec<_>>();
        reservoir.extend(&batch);
        assert_eq!(reservoir.stride, 1);
        assert_eq!(reservoir.kept, batch);
    }

    #[test]
    fn an_unobservable_series_is_never_silently_within_budget() {
        let samples = vec![sample(0.0, None), sample(60.0, None), sample(120.0, None)];
        let gate = gate("resident_set_bytes", &samples, 0.0, 1.0, |p| p.rss_bytes);
        assert_eq!(gate.within_budget, None);
        assert_eq!(gate.samples_in_window, 0);
    }

    #[test]
    fn shipped_soak_profiles_parse_and_declare_their_level() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../qa/qualification/soak");
        for name in ["6h.json", "24h.json", "72h.json", "168h.json"] {
            let profile = load_profile(&root.join(name)).unwrap();
            assert!(profile.duration_seconds > profile.stabilization_seconds);
            assert!(!profile.satisfies_level.is_empty(), "{name}");
            assert!(profile.memory_growth_budget_bytes_per_hour > 0.0, "{name}");
        }
    }

    #[test]
    fn the_profiles_agree_with_the_soak_matrix_on_hours_per_level() {
        // Two files describing the same policy drift, and the one that drifts
        // is the one nobody reads until a laboratory runs the wrong duration.
        let qa =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../qa/qualification");
        let matrix: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(qa.join("matrices/soak-profiles.json")).unwrap(),
        )
        .unwrap();
        for (level, spec) in matrix["profiles"].as_object().unwrap() {
            let hours = spec["hours"].as_u64().unwrap();
            let profile = load_profile(&qa.join(format!("soak/{hours}h.json"))).unwrap();
            assert_eq!(
                &profile.satisfies_level, level,
                "{hours}h.json claims {} but the matrix assigns it to {level}",
                profile.satisfies_level
            );
            assert_eq!(profile.duration_seconds, hours * 3_600, "{hours}h.json");
        }
    }
}
