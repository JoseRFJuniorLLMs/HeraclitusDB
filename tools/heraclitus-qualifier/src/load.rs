use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use heraclitus_client::{AppendOptions, Client};
use serde::Serialize;
use tokio::task::JoinSet;

use crate::evidence::{sha256_file, write_bytes_new, write_json_new};
use crate::manifest::WorkloadProfile;

#[derive(Debug, Clone)]
pub struct LoadConfig {
    pub target: String,
    pub profile: WorkloadProfile,
    pub seed: u64,
    pub operations_per_stage: u64,
    pub concurrency: usize,
    pub ramp_percent: Vec<u16>,
    pub request_timeout_seconds: u64,
    pub bearer_token_env: Option<String>,
    pub report: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadStatus {
    Passed,
    Failed,
}

#[derive(Debug)]
pub struct LoadSummary {
    pub status: LoadStatus,
    pub total_operations: u64,
    pub errors: u64,
    pub latency_p99_ms: f64,
    pub report: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationKind {
    Ingest,
    AttributeQuery,
    TextRetrieval,
    VectorRetrieval,
    GraphTraversal,
    AsOfAnalytics,
}

impl OperationKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::AttributeQuery => "attribute_query",
            Self::TextRetrieval => "text_retrieval",
            Self::VectorRetrieval => "vector_retrieval",
            Self::GraphTraversal => "graph_traversal",
            Self::AsOfAnalytics => "as_of_analytics",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LatencySummary {
    pub(crate) count: u64,
    pub(crate) p50_ms: f64,
    pub(crate) p95_ms: f64,
    pub(crate) p99_ms: f64,
    pub(crate) max_ms: f64,
}

#[derive(Debug, Serialize)]
struct StageReport {
    ramp_percent: u16,
    concurrency: usize,
    operations: u64,
    successes: u64,
    errors: u64,
    duration_ms: u128,
    throughput_ops_s: f64,
    operation_counts: BTreeMap<String, u64>,
    latency: LatencySummary,
}

#[derive(Debug, Serialize)]
struct IntegrityReport {
    initial_head: u64,
    final_head: u64,
    acknowledged_appends: u64,
    minimum_expected_final_head: u64,
    head_progression_valid: bool,
    sampled_acknowledgements: usize,
    missing_acknowledgement_samples: usize,
    full_verify_ok: bool,
    full_verify_message: String,
}

#[derive(Debug, Serialize)]
struct LoadReport {
    schema_version: u32,
    generator: String,
    started_at_unix: u64,
    finished_at_unix: u64,
    target: String,
    profile: WorkloadProfile,
    seed: u64,
    operations_per_stage: u64,
    base_concurrency: usize,
    ramp_percent: Vec<u16>,
    bearer_token_env: Option<String>,
    stages: Vec<StageReport>,
    total_operations: u64,
    total_errors: u64,
    latency: LatencySummary,
    integrity: IntegrityReport,
    status: LoadStatus,
    error_samples: Vec<String>,
}

#[derive(Debug, Default)]
struct WorkerResult {
    successes: u64,
    errors: u64,
    latencies_us: Vec<u64>,
    operation_counts: BTreeMap<OperationKind, u64>,
    acknowledged_ids: Vec<String>,
    errors_sample: Vec<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn mix(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

pub(crate) fn operation(profile: WorkloadProfile, key: u64) -> OperationKind {
    let bucket = (mix(key) % 100) as u8;
    let weighted: &[(OperationKind, u8)] = match profile {
        WorkloadProfile::WriteHeavy => &[
            (OperationKind::Ingest, 90),
            (OperationKind::AttributeQuery, 10),
        ],
        WorkloadProfile::ReadHeavy => &[
            (OperationKind::Ingest, 20),
            (OperationKind::AttributeQuery, 40),
            (OperationKind::TextRetrieval, 20),
            (OperationKind::GraphTraversal, 20),
        ],
        WorkloadProfile::Mixed => &[
            (OperationKind::Ingest, 70),
            (OperationKind::AttributeQuery, 10),
            (OperationKind::TextRetrieval, 5),
            (OperationKind::VectorRetrieval, 5),
            (OperationKind::GraphTraversal, 5),
            (OperationKind::AsOfAnalytics, 5),
        ],
        WorkloadProfile::SocIngestion => &[
            (OperationKind::Ingest, 95),
            (OperationKind::AttributeQuery, 5),
        ],
        WorkloadProfile::SocInvestigation => &[
            (OperationKind::Ingest, 20),
            (OperationKind::AttributeQuery, 25),
            (OperationKind::TextRetrieval, 20),
            (OperationKind::VectorRetrieval, 10),
            (OperationKind::GraphTraversal, 15),
            (OperationKind::AsOfAnalytics, 10),
        ],
        WorkloadProfile::Burst => &[
            (OperationKind::Ingest, 85),
            (OperationKind::AttributeQuery, 15),
        ],
        WorkloadProfile::AdversarialCardinality => &[
            (OperationKind::Ingest, 70),
            (OperationKind::AttributeQuery, 30),
        ],
    };
    let mut upper = 0_u8;
    for (kind, weight) in weighted {
        upper = upper.saturating_add(*weight);
        if bucket < upper {
            return *kind;
        }
    }
    weighted
        .last()
        .map(|(kind, _)| *kind)
        .unwrap_or(OperationKind::Ingest)
}

pub(crate) fn percentile(sorted_us: &[u64], percentile: f64) -> f64 {
    if sorted_us.is_empty() {
        return 0.0;
    }
    let rank = ((sorted_us.len() as f64 * percentile).ceil() as usize)
        .saturating_sub(1)
        .min(sorted_us.len() - 1);
    sorted_us[rank] as f64 / 1_000.0
}

pub(crate) fn latency_summary(latencies: &[u64]) -> LatencySummary {
    let mut sorted = latencies.to_vec();
    sorted.sort_unstable();
    LatencySummary {
        count: sorted.len() as u64,
        p50_ms: percentile(&sorted, 0.50),
        p95_ms: percentile(&sorted, 0.95),
        p99_ms: percentile(&sorted, 0.99),
        max_ms: sorted.last().copied().unwrap_or(0) as f64 / 1_000.0,
    }
}

pub(crate) async fn execute_operation(
    client: &mut Client,
    kind: OperationKind,
    seed: u64,
    sequence: u64,
    initial_head: u64,
    profile: WorkloadProfile,
) -> std::result::Result<Option<String>, String> {
    let key = mix(seed ^ sequence);
    let agent_cardinality = if profile == WorkloadProfile::AdversarialCardinality {
        u64::MAX
    } else {
        4_096
    };
    let agent = format!("soc-agent-{}", key % agent_cardinality);
    match kind {
        OperationKind::Ingest => {
            let classes = [
                "authentication",
                "network",
                "dns",
                "http",
                "process",
                "endpoint",
                "iam",
                "kubernetes",
                "cloud_audit",
                "database_audit",
                "application_log",
            ];
            let event_class = classes[(key as usize) % classes.len()];
            let mut attrs = HashMap::new();
            attrs.insert("tenant".to_owned(), format!("tenant-{}", key % 32));
            attrs.insert("sensor".to_owned(), format!("sensor-{}", key % 512));
            attrs.insert("severity".to_owned(), format!("{}", key % 10 + 1));
            if profile == WorkloadProfile::AdversarialCardinality {
                attrs.insert("unique_key".to_owned(), format!("u{sequence:016x}"));
            }
            let content = format!(
                "synthetic qualification {event_class} sequence={sequence} marker={key:016x} {}",
                "x".repeat(96 + (key as usize % 512))
            );
            let result = client
                .append_with_result(
                    &agent,
                    content.as_bytes(),
                    AppendOptions {
                        session_id: format!("qualification-{seed}"),
                        kind: event_class.to_owned(),
                        hyp: vec![
                            ((key % 20) as f32) / 100.0,
                            (((key >> 8) % 20) as f32) / 100.0,
                        ],
                        attrs,
                        parents: Vec::new(),
                        idempotency_key: format!("qualifier-{seed}-{sequence}"),
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            Ok(Some(result.event_id))
        }
        OperationKind::AttributeQuery => client
            .query(&format!(
                "MATCH (n) WHERE n.agent_id = \"{agent}\" RETURN n LIMIT 10"
            ))
            .await
            .map(|_| None)
            .map_err(|error| error.to_string()),
        OperationKind::TextRetrieval => client
            .recall("synthetic authentication network process", 10)
            .await
            .map(|_| None)
            .map_err(|error| error.to_string()),
        OperationKind::VectorRetrieval => client
            .query("MATCH (n) RETURN n ORDER BY DIST_HYP([0.10, 0.10]) ASC LIMIT 10")
            .await
            .map(|_| None)
            .map_err(|error| error.to_string()),
        OperationKind::GraphTraversal => client
            .query("MATCH (a)-[r]->(b) RETURN * LIMIT 10")
            .await
            .map(|_| None)
            .map_err(|error| error.to_string()),
        OperationKind::AsOfAnalytics => {
            let ceiling = initial_head.saturating_add(sequence).max(1);
            client
                .query(&format!("MATCH (n) AS OF LSN {ceiling} RETURN n LIMIT 10"))
                .await
                .map(|_| None)
                .map_err(|error| error.to_string())
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct WorkerSpec {
    profile: WorkloadProfile,
    seed: u64,
    stage_offset: u64,
    operations: u64,
    worker_index: usize,
    worker_count: usize,
    initial_head: u64,
}

async fn worker(mut client: Client, spec: WorkerSpec) -> WorkerResult {
    let mut result = WorkerResult::default();
    let mut local = spec.worker_index as u64;
    while local < spec.operations {
        let sequence = spec.stage_offset.saturating_add(local);
        let kind = operation(spec.profile, spec.seed ^ sequence);
        *result.operation_counts.entry(kind).or_default() += 1;
        let started = Instant::now();
        match execute_operation(
            &mut client,
            kind,
            spec.seed,
            sequence,
            spec.initial_head,
            spec.profile,
        )
        .await
        {
            Ok(event_id) => {
                result.successes += 1;
                if let Some(event_id) = event_id {
                    result.acknowledged_ids.push(event_id);
                }
            }
            Err(error) => {
                result.errors += 1;
                if result.errors_sample.len() < 20 {
                    result
                        .errors_sample
                        .push(format!("{}: {}", kind.as_str(), error));
                }
            }
        }
        result
            .latencies_us
            .push(started.elapsed().as_micros().min(u64::MAX as u128) as u64);
        local = local.saturating_add(spec.worker_count as u64);
    }
    result
}

fn merge_worker(target: &mut WorkerResult, worker: WorkerResult) {
    target.successes += worker.successes;
    target.errors += worker.errors;
    target.latencies_us.extend(worker.latencies_us);
    target.acknowledged_ids.extend(worker.acknowledged_ids);
    for (kind, count) in worker.operation_counts {
        *target.operation_counts.entry(kind).or_default() += count;
    }
    let remaining = 100_usize.saturating_sub(target.errors_sample.len());
    target
        .errors_sample
        .extend(worker.errors_sample.into_iter().take(remaining));
}

async fn run_async(config: &LoadConfig) -> Result<(LoadReport, LoadSummary)> {
    let mut client = Client::connect_with(&config.target, Duration::from_secs(15))
        .await
        .with_context(|| format!("connect to qualification target {}", config.target))?
        .with_request_timeout(Duration::from_secs(config.request_timeout_seconds.max(1)));
    if let Some(environment_name) = &config.bearer_token_env {
        let token = std::env::var(environment_name)
            .with_context(|| format!("bearer token environment variable {environment_name}"))?;
        client = client
            .with_bearer_token(&token)
            .context("invalid bearer token metadata")?;
    }
    let started_at_unix = now_unix();
    let initial_head = client.snapshot().await.context("capture initial head")?;
    let mut ramp = config.ramp_percent.clone();
    if config.profile == WorkloadProfile::Burst && !ramp.contains(&200) {
        ramp.push(200);
    }
    let mut stage_reports = Vec::new();
    let mut combined = WorkerResult::default();
    let mut stage_offset = 0_u64;

    for percentage in &ramp {
        let worker_count =
            ((config.concurrency as u64 * u64::from(*percentage)) / 100).clamp(1, 4_096) as usize;
        let stage_started = Instant::now();
        let mut tasks = JoinSet::new();
        for worker_index in 0..worker_count {
            tasks.spawn(worker(
                client.clone(),
                WorkerSpec {
                    profile: config.profile,
                    seed: config.seed,
                    stage_offset,
                    operations: config.operations_per_stage,
                    worker_index,
                    worker_count,
                    initial_head,
                },
            ));
        }
        let mut stage = WorkerResult::default();
        while let Some(joined) = tasks.join_next().await {
            merge_worker(
                &mut stage,
                joined.context("qualification load worker panicked")?,
            );
        }
        let elapsed = stage_started.elapsed();
        let operation_counts = stage
            .operation_counts
            .iter()
            .map(|(kind, count)| (kind.as_str().to_owned(), *count))
            .collect();
        stage_reports.push(StageReport {
            ramp_percent: *percentage,
            concurrency: worker_count,
            operations: stage.successes + stage.errors,
            successes: stage.successes,
            errors: stage.errors,
            duration_ms: elapsed.as_millis(),
            throughput_ops_s: stage.successes as f64 / elapsed.as_secs_f64().max(0.000_001),
            operation_counts,
            latency: latency_summary(&stage.latencies_us),
        });
        merge_worker(&mut combined, stage);
        stage_offset = stage_offset.saturating_add(config.operations_per_stage);
    }

    let final_head = client.snapshot().await.context("capture final head")?;
    let (full_verify_ok, full_verify_message) = match client.admin("verify", "").await {
        Ok((ok, message)) => (ok, message.chars().take(16_384).collect()),
        Err(error) => (false, error.to_string()),
    };
    let acknowledged_appends = combined.acknowledged_ids.len() as u64;
    let minimum_expected_final_head = initial_head.saturating_add(acknowledged_appends);
    let head_progression_valid = final_head >= minimum_expected_final_head;

    let sample_count = combined.acknowledged_ids.len().min(128);
    let stride = combined
        .acknowledged_ids
        .len()
        .checked_div(sample_count.max(1))
        .unwrap_or(1)
        .max(1);
    let sampled_ids = combined
        .acknowledged_ids
        .iter()
        .step_by(stride)
        .take(sample_count)
        .cloned()
        .collect::<Vec<_>>();
    let mut missing_samples = 0_usize;
    for id in &sampled_ids {
        match client
            .query(&format!("MATCH (n) WHERE n.id = \"{id}\" RETURN n LIMIT 1"))
            .await
        {
            Ok(value) if value.to_string().contains(id) => {}
            _ => missing_samples += 1,
        }
    }

    if !head_progression_valid {
        combined.errors += 1;
        combined.errors_sample.push(format!(
            "final head {final_head} is below acknowledged minimum {minimum_expected_final_head}"
        ));
    }
    if !full_verify_ok {
        combined.errors += 1;
        combined
            .errors_sample
            .push(format!("full verify failed: {full_verify_message}"));
    }
    if missing_samples > 0 {
        combined.errors += missing_samples as u64;
        combined.errors_sample.push(format!(
            "{missing_samples} of {} acknowledged samples were not readable",
            sampled_ids.len()
        ));
    }
    let total_operations = stage_reports.iter().map(|stage| stage.operations).sum();
    let total_latency = latency_summary(&combined.latencies_us);
    let status = if combined.errors == 0 {
        LoadStatus::Passed
    } else {
        LoadStatus::Failed
    };
    let report = LoadReport {
        schema_version: 1,
        generator: format!("heraclitus-qualifier/{}", env!("CARGO_PKG_VERSION")),
        started_at_unix,
        finished_at_unix: now_unix(),
        target: config.target.clone(),
        profile: config.profile,
        seed: config.seed,
        operations_per_stage: config.operations_per_stage,
        base_concurrency: config.concurrency,
        ramp_percent: ramp,
        bearer_token_env: config.bearer_token_env.clone(),
        stages: stage_reports,
        total_operations,
        total_errors: combined.errors,
        latency: total_latency,
        integrity: IntegrityReport {
            initial_head,
            final_head,
            acknowledged_appends,
            minimum_expected_final_head,
            head_progression_valid,
            sampled_acknowledgements: sampled_ids.len(),
            missing_acknowledgement_samples: missing_samples,
            full_verify_ok,
            full_verify_message,
        },
        status,
        error_samples: combined.errors_sample,
    };
    write_json_new(&config.report, &report)?;
    let digest = sha256_file(&config.report)?;
    let sidecar = config.report.with_extension(format!(
        "{}sha256",
        config
            .report
            .extension()
            .map(|extension| format!("{}.", extension.to_string_lossy()))
            .unwrap_or_default()
    ));
    let filename = config
        .report
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    write_bytes_new(&sidecar, format!("{digest}  {filename}\n").as_bytes())?;
    let summary = LoadSummary {
        status,
        total_operations,
        errors: combined.errors,
        latency_p99_ms: report.latency.p99_ms,
        report: config.report.clone(),
    };
    Ok((report, summary))
}

pub fn run(config: LoadConfig) -> Result<LoadSummary> {
    if config.report.exists() {
        bail!(
            "refusing to overwrite load report {}",
            config.report.display()
        );
    }
    if config.operations_per_stage == 0 {
        bail!("--operations-per-stage must be greater than zero");
    }
    if config.concurrency == 0 || config.concurrency > 4_096 {
        bail!("--concurrency must be between 1 and 4096");
    }
    if config.ramp_percent.is_empty()
        || config
            .ramp_percent
            .iter()
            .any(|percentage| *percentage == 0 || *percentage > 1_000)
    {
        bail!("--ramp-percent values must be between 1 and 1000");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create load runtime")?;
    runtime
        .block_on(run_async(&config))
        .map(|(_, summary)| summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_profile_contains_all_six_lanes_deterministically() {
        let observed = (0..10_000)
            .map(|sequence| operation(WorkloadProfile::Mixed, 42 ^ sequence))
            .collect::<BTreeSet<_>>();
        assert_eq!(observed.len(), 6);
        assert_eq!(
            operation(WorkloadProfile::Mixed, 123),
            operation(WorkloadProfile::Mixed, 123)
        );
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        assert_eq!(percentile(&[1_000, 2_000, 3_000, 4_000], 0.50), 2.0);
        assert_eq!(percentile(&[1_000, 2_000, 3_000, 4_000], 0.99), 4.0);
        assert_eq!(percentile(&[], 0.99), 0.0);
    }

    use std::collections::BTreeSet;
}
