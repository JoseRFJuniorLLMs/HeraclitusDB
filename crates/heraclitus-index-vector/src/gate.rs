//! SPEC-0044 Gate C baseline for the direct product-manifold HNSW index.
//!
//! This module deliberately measures only `VectorIndex` with the H32×S8×E8
//! [`ProductMetric`]. It is **not** a benchmark of the live `Engine::nearest`
//! path, which currently accepts hyperbolic-only vectors and needs a separate
//! server-level harness. Keeping the workloads apart prevents incomparable
//! numbers from being used to justify a physical optimization.

use crate::VectorIndex;
use heraclitus_core::{CapabilityCatalog, EventId, Lsn, ProductPoint};
use heraclitus_manifold::{ProductMetric, Signature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

/// Schema version for a [`HnswGateRun`] JSON artifact.
pub const HNSW_GATE_ARTIFACT_VERSION: u32 = 1;
/// Schema version for a [`HnswGateCorpus`] JSON input.
pub const HNSW_GATE_CORPUS_VERSION: u32 = 1;

/// Workload measured by this gate.
///
/// Add a new enum variant only when its execution path is independently
/// instrumented. In particular, do not reuse this result for `Engine::nearest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HnswGateWorkload {
    /// Direct `VectorIndex` search over H32×S8×E8 points.
    Product32x8x8V0,
}

impl HnswGateWorkload {
    /// Stable workload name stored in artifacts and baseline comparisons.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Product32x8x8V0 => "product-32-8-8-v0",
        }
    }
}

/// One point in a frozen Gate C corpus.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HnswGatePoint {
    /// Stable source identifier; corpus insertion order is significant to HNSW.
    pub id: EventId,
    /// LSN recorded in returned hits.
    pub lsn: Lsn,
    /// Product-manifold embedding.
    pub point: ProductPoint,
}

/// A frozen, sanitized corpus and query set supplied by the benchmark operator.
///
/// The gate never fabricates a corpus and calls it representative. Persist this
/// structure as JSON, hash the source outside the process, and pass that source
/// fingerprint in [`HnswGateConfig`]. The gate additionally computes its own
/// content digest, making accidental corpus drift visible in the output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HnswGateCorpus {
    /// Must equal [`HNSW_GATE_CORPUS_VERSION`].
    pub format_version: u32,
    /// Original points in their intentional insertion order.
    pub points: Vec<HnswGatePoint>,
    /// Frozen query set, evaluated in listed order.
    pub queries: Vec<ProductPoint>,
}

/// Parameters for one benchmark run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HnswGateConfig {
    /// Explicit path/workload class represented by this run.
    pub workload: HnswGateWorkload,
    /// Digest of the frozen source supplied by the operator (for example SHA-256
    /// of the sanitized corpus file before it is parsed).
    pub source_fingerprint: String,
    /// Number of results compared per query.
    pub k: usize,
    /// HNSW exploration factor. It must be at least `k`.
    pub ef: usize,
    /// Queries to execute before recording latency.
    pub warmup_queries: usize,
    /// Reject debug builds by default. A test may opt out, but a real Gate C
    /// artifact must be created from `--release`.
    pub require_release: bool,
}

impl HnswGateConfig {
    /// Default configuration for direct H32×S8×E8 `VectorIndex` benchmarking.
    pub fn product_32_8_8(source_fingerprint: impl Into<String>) -> Self {
        Self {
            workload: HnswGateWorkload::Product32x8x8V0,
            source_fingerprint: source_fingerprint.into(),
            k: 10,
            ef: 64,
            warmup_queries: 16,
            require_release: true,
        }
    }
}

/// Host/build facts that make a result comparable (or explain why it is not).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HnswGateEnvironment {
    pub operating_system: String,
    pub target_arch: String,
    pub logical_cpus: usize,
    pub supports_hardware_vector_simd: bool,
    pub build_profile: String,
}

/// Latency percentiles over the recorded query set, in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HnswGateLatency {
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

/// Gate C evidence for one query, including the exact reference ordering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HnswGateQueryResult {
    pub query_index: usize,
    pub latency_ns: u64,
    /// HNSW result IDs in the order returned by the candidate implementation.
    pub approximate_ids: Vec<EventId>,
    /// Scalar ProductMetric brute-force IDs, ordered canonically by distance/id.
    pub exact_ids: Vec<EventId>,
    pub recall_at_k: f64,
}

/// A versioned, JSON-serializable Gate C artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HnswGateRun {
    pub artifact_version: u32,
    pub workload: HnswGateWorkload,
    pub source_fingerprint: String,
    /// Digest calculated from the parsed point/query values and insertion order.
    pub corpus_digest_blake3: String,
    /// Stable digest of configuration plus result IDs; excludes timing noise.
    pub result_digest_blake3: String,
    pub metric_signature: Signature,
    pub point_count: usize,
    pub query_count: usize,
    pub k: usize,
    pub ef: usize,
    pub warmup_queries: usize,
    pub build_ns: u64,
    pub environment: HnswGateEnvironment,
    pub latency: HnswGateLatency,
    pub mean_recall_at_k: f64,
    pub queries: Vec<HnswGateQueryResult>,
}

/// Reasons a Gate C run cannot be trusted as a benchmark artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HnswGateError {
    UnsupportedCorpusVersion {
        found: u32,
    },
    EmptyPoints,
    EmptyQueries,
    EmptySourceFingerprint,
    InvalidK {
        k: usize,
        points: usize,
    },
    EfBelowK {
        ef: usize,
        k: usize,
    },
    DuplicateEventId(EventId),
    UnexpectedDimensions {
        collection: &'static str,
        index: usize,
        found: (usize, usize, usize),
    },
    NonFiniteCoordinate {
        collection: &'static str,
        index: usize,
        component: &'static str,
    },
    ReleaseBuildRequired,
    ReadCorpus(String),
    ParseCorpus(String),
    SerializeArtifact(String),
    WriteArtifact(String),
}

impl fmt::Display for HnswGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCorpusVersion { found } => write!(
                f,
                "versão de corpus {found} não suportada (esperada {HNSW_GATE_CORPUS_VERSION})"
            ),
            Self::EmptyPoints => write!(f, "corpus Gate C não contém pontos"),
            Self::EmptyQueries => write!(f, "corpus Gate C não contém queries"),
            Self::EmptySourceFingerprint => write!(f, "source_fingerprint do corpus é obrigatório"),
            Self::InvalidK { k, points } => {
                write!(f, "k={k} inválido para corpus com {points} pontos")
            }
            Self::EfBelowK { ef, k } => write!(f, "ef={ef} deve ser maior ou igual a k={k}"),
            Self::DuplicateEventId(id) => write!(f, "EventId duplicado no corpus: {id}"),
            Self::UnexpectedDimensions {
                collection,
                index,
                found,
            } => write!(
                f,
                "{collection}[{index}] tem dimensões {:?}; product-32-8-8-v0 exige (32, 8, 8)",
                found
            ),
            Self::NonFiniteCoordinate {
                collection,
                index,
                component,
            } => write!(
                f,
                "{collection}[{index}] contém coordenada não-finita em {component}"
            ),
            Self::ReleaseBuildRequired => write!(
                f,
                "Gate C exige build --release; use require_release=false somente em testes"
            ),
            Self::ReadCorpus(error) => write!(f, "não foi possível ler corpus Gate C: {error}"),
            Self::ParseCorpus(error) => write!(f, "corpus Gate C inválido: {error}"),
            Self::SerializeArtifact(error) => {
                write!(f, "não foi possível serializar artefato: {error}")
            }
            Self::WriteArtifact(error) => write!(f, "não foi possível gravar artefato: {error}"),
        }
    }
}

impl std::error::Error for HnswGateError {}

/// Load one frozen Gate C corpus. This does not fabricate data or normalize it.
pub fn load_hnsw_gate_corpus_json(path: impl AsRef<Path>) -> Result<HnswGateCorpus, HnswGateError> {
    let bytes =
        std::fs::read(path).map_err(|error| HnswGateError::ReadCorpus(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| HnswGateError::ParseCorpus(error.to_string()))
}

/// Run the direct H32×S8×E8 HNSW Gate C baseline.
///
/// The benchmark records approximate output IDs and scalar exact output IDs for
/// every frozen query, then reports Recall@K and p50/p95/p99. It does not set a
/// performance pass/fail threshold: that comparison needs a reviewed baseline
/// for the same workload, source fingerprint, build profile and host class.
pub fn run_hnsw_gate(
    corpus: &HnswGateCorpus,
    config: &HnswGateConfig,
) -> Result<HnswGateRun, HnswGateError> {
    validate_corpus(corpus, config)?;
    if config.require_release && cfg!(debug_assertions) {
        return Err(HnswGateError::ReleaseBuildRequired);
    }

    let metric = ProductMetric::default();
    let corpus_digest_blake3 = corpus_digest(corpus);
    let build_start = Instant::now();
    let mut index = VectorIndex::new(metric.clone());
    for item in &corpus.points {
        index.insert(item.id, item.lsn, item.point.clone());
    }
    let build_ns = duration_ns(build_start.elapsed());

    for warmup in 0..config.warmup_queries {
        let query = &corpus.queries[warmup % corpus.queries.len()];
        std::hint::black_box(index.search(query, config.k, config.ef, None));
    }

    let mut latencies = Vec::with_capacity(corpus.queries.len());
    let mut results = Vec::with_capacity(corpus.queries.len());
    let mut recall_sum = 0.0;
    for (query_index, query) in corpus.queries.iter().enumerate() {
        let exact_ids = exact_top_k(&metric, &corpus.points, query, config.k);
        let started = Instant::now();
        let approximate_ids = index
            .search(query, config.k, config.ef, None)
            .into_iter()
            .map(|hit| hit.id)
            .collect::<Vec<_>>();
        let latency_ns = duration_ns(started.elapsed());
        let recall_at_k = recall_at_k(&approximate_ids, &exact_ids, config.k);
        recall_sum += recall_at_k;
        latencies.push(latency_ns);
        results.push(HnswGateQueryResult {
            query_index,
            latency_ns,
            approximate_ids,
            exact_ids,
            recall_at_k,
        });
    }

    latencies.sort_unstable();
    let latency = HnswGateLatency {
        p50_ns: percentile(&latencies, 50),
        p95_ns: percentile(&latencies, 95),
        p99_ns: percentile(&latencies, 99),
    };
    let environment = environment();
    let result_digest_blake3 = result_digest(&corpus_digest_blake3, config, &results);

    Ok(HnswGateRun {
        artifact_version: HNSW_GATE_ARTIFACT_VERSION,
        workload: config.workload,
        source_fingerprint: config.source_fingerprint.clone(),
        corpus_digest_blake3,
        result_digest_blake3,
        metric_signature: metric.sig,
        point_count: corpus.points.len(),
        query_count: corpus.queries.len(),
        k: config.k,
        ef: config.ef,
        warmup_queries: config.warmup_queries,
        build_ns,
        environment,
        latency,
        mean_recall_at_k: recall_sum / corpus.queries.len() as f64,
        queries: results,
    })
}

/// Write an artifact without overwriting any previous evidence file.
pub fn write_hnsw_gate_json(
    path: impl AsRef<Path>,
    run: &HnswGateRun,
) -> Result<(), HnswGateError> {
    let bytes = serde_json::to_vec_pretty(run)
        .map_err(|error| HnswGateError::SerializeArtifact(error.to_string()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| HnswGateError::WriteArtifact(error.to_string()))?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| HnswGateError::WriteArtifact(error.to_string()))
}

fn validate_corpus(corpus: &HnswGateCorpus, config: &HnswGateConfig) -> Result<(), HnswGateError> {
    if corpus.format_version != HNSW_GATE_CORPUS_VERSION {
        return Err(HnswGateError::UnsupportedCorpusVersion {
            found: corpus.format_version,
        });
    }
    if corpus.points.is_empty() {
        return Err(HnswGateError::EmptyPoints);
    }
    if corpus.queries.is_empty() {
        return Err(HnswGateError::EmptyQueries);
    }
    if config.source_fingerprint.trim().is_empty() {
        return Err(HnswGateError::EmptySourceFingerprint);
    }
    if config.k == 0 || config.k > corpus.points.len() {
        return Err(HnswGateError::InvalidK {
            k: config.k,
            points: corpus.points.len(),
        });
    }
    if config.ef < config.k {
        return Err(HnswGateError::EfBelowK {
            ef: config.ef,
            k: config.k,
        });
    }

    let mut ids = BTreeSet::new();
    for (index, item) in corpus.points.iter().enumerate() {
        if !ids.insert(item.id) {
            return Err(HnswGateError::DuplicateEventId(item.id));
        }
        validate_point("points", index, &item.point)?;
    }
    for (index, query) in corpus.queries.iter().enumerate() {
        validate_point("queries", index, query)?;
    }
    Ok(())
}

fn validate_point(
    collection: &'static str,
    index: usize,
    point: &ProductPoint,
) -> Result<(), HnswGateError> {
    if point.dims() != (32, 8, 8) {
        return Err(HnswGateError::UnexpectedDimensions {
            collection,
            index,
            found: point.dims(),
        });
    }
    for (component, coordinates) in [
        ("hyp", point.hyp.as_slice()),
        ("sph", point.sph.as_slice()),
        ("euc", point.euc.as_slice()),
    ] {
        if coordinates.iter().any(|coordinate| !coordinate.is_finite()) {
            return Err(HnswGateError::NonFiniteCoordinate {
                collection,
                index,
                component,
            });
        }
    }
    Ok(())
}

fn exact_top_k(
    metric: &ProductMetric,
    points: &[HnswGatePoint],
    query: &ProductPoint,
    k: usize,
) -> Vec<EventId> {
    let mut distances = points
        .iter()
        .map(|item| (metric.dist(&item.point, query), item.id))
        .collect::<Vec<_>>();
    distances.sort_by(|(left_distance, left_id), (right_distance, right_id)| {
        left_distance
            .total_cmp(right_distance)
            .then_with(|| left_id.cmp(right_id))
    });
    distances.into_iter().take(k).map(|(_, id)| id).collect()
}

fn recall_at_k(approximate: &[EventId], exact: &[EventId], k: usize) -> f64 {
    let exact = exact.iter().take(k).copied().collect::<BTreeSet<_>>();
    let matched = approximate
        .iter()
        .take(k)
        .filter(|id| exact.contains(id))
        .count();
    matched as f64 / k as f64
}

fn percentile(sorted_ns: &[u64], percentile: usize) -> u64 {
    debug_assert!(!sorted_ns.is_empty());
    // Nearest-rank percentile: rank = ceil(p * N / 100), one-indexed.
    let rank = (sorted_ns.len() * percentile).div_ceil(100).max(1);
    sorted_ns[rank - 1]
}

fn environment() -> HnswGateEnvironment {
    let capabilities = CapabilityCatalog::detect();
    HnswGateEnvironment {
        operating_system: std::env::consts::OS.to_string(),
        target_arch: std::env::consts::ARCH.to_string(),
        logical_cpus: capabilities.logical_cpus,
        supports_hardware_vector_simd: capabilities.supports_hardware_vector_simd,
        build_profile: if cfg!(debug_assertions) {
            "debug".into()
        } else {
            "release".into()
        },
    }
}

fn duration_ns(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn corpus_digest(corpus: &HnswGateCorpus) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"HERACLITUS:HNSW:GATE:CORPUS:v1\0");
    hash_u64(&mut hasher, corpus.format_version as u64);
    hash_u64(&mut hasher, corpus.points.len() as u64);
    for item in &corpus.points {
        hash_event_id(&mut hasher, item.id);
        hash_u64(&mut hasher, item.lsn);
        hash_point(&mut hasher, &item.point);
    }
    hash_u64(&mut hasher, corpus.queries.len() as u64);
    for query in &corpus.queries {
        hash_point(&mut hasher, query);
    }
    hasher.finalize().to_hex().to_string()
}

fn result_digest(
    corpus_digest_blake3: &str,
    config: &HnswGateConfig,
    results: &[HnswGateQueryResult],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"HERACLITUS:HNSW:GATE:RESULT:v1\0");
    hash_text(&mut hasher, config.workload.label());
    hash_text(&mut hasher, corpus_digest_blake3);
    hash_text(&mut hasher, &config.source_fingerprint);
    hash_u64(&mut hasher, config.k as u64);
    hash_u64(&mut hasher, config.ef as u64);
    hash_u64(&mut hasher, config.warmup_queries as u64);
    hash_u64(&mut hasher, results.len() as u64);
    for result in results {
        hash_u64(&mut hasher, result.query_index as u64);
        hash_u64(&mut hasher, result.approximate_ids.len() as u64);
        for id in &result.approximate_ids {
            hash_event_id(&mut hasher, *id);
        }
        hash_u64(&mut hasher, result.exact_ids.len() as u64);
        for id in &result.exact_ids {
            hash_event_id(&mut hasher, *id);
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn hash_point(hasher: &mut blake3::Hasher, point: &ProductPoint) {
    for component in [&point.hyp, &point.sph, &point.euc] {
        hash_u64(hasher, component.len() as u64);
        for coordinate in component {
            hasher.update(&coordinate.to_bits().to_le_bytes());
        }
    }
}

fn hash_event_id(hasher: &mut blake3::Hasher, id: EventId) {
    hash_text(hasher, &id.to_string());
}

fn hash_text(hasher: &mut blake3::Hasher, text: &str) {
    hash_u64(hasher, text.len() as u64);
    hasher.update(text.as_bytes());
}

fn hash_u64(hasher: &mut blake3::Hasher, value: u64) {
    hasher.update(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_manifold::{project_to_ball, project_to_sphere};

    fn point(seed: u64) -> ProductPoint {
        let value = |i: usize, factor: u64| {
            ((seed.wrapping_mul(factor).wrapping_add(i as u64) % 10_000) as f32 / 10_000.0) - 0.5
        };
        let mut hyp = (0..32).map(|i| value(i, 31) * 0.8).collect::<Vec<_>>();
        let mut sph = (0..8).map(|i| value(i, 37)).collect::<Vec<_>>();
        let euc = (0..8).map(|i| value(i, 41)).collect::<Vec<_>>();
        project_to_ball(&mut hyp);
        project_to_sphere(&mut sph);
        ProductPoint { hyp, sph, euc }
    }

    fn fixture_corpus() -> HnswGateCorpus {
        let points = (0..64u64)
            .map(|index| HnswGatePoint {
                id: EventId(ulid::Ulid::from_parts(index, index as u128)),
                lsn: index,
                point: point(index + 1),
            })
            .collect();
        let queries = (0..12u64)
            .map(|index| {
                let mut query = point(index * 5 + 3);
                query.hyp[0] *= 0.99;
                project_to_ball(&mut query.hyp);
                query
            })
            .collect();
        HnswGateCorpus {
            format_version: HNSW_GATE_CORPUS_VERSION,
            points,
            queries,
        }
    }

    fn test_config() -> HnswGateConfig {
        let mut config = HnswGateConfig::product_32_8_8("sha256:test-corpus");
        config.k = 5;
        config.ef = 32;
        config.warmup_queries = 3;
        config.require_release = false;
        config
    }

    #[test]
    fn run_is_deterministic_and_records_gate_c_evidence() {
        let corpus = fixture_corpus();
        let config = test_config();
        let first = run_hnsw_gate(&corpus, &config).unwrap();
        let second = run_hnsw_gate(&corpus, &config).unwrap();

        assert_eq!(first.workload, HnswGateWorkload::Product32x8x8V0);
        assert_eq!(first.corpus_digest_blake3, second.corpus_digest_blake3);
        assert_eq!(first.result_digest_blake3, second.result_digest_blake3);
        assert_eq!(first.queries.len(), corpus.queries.len());
        assert!(first.mean_recall_at_k > 0.0);
        assert!(first.latency.p50_ns <= first.latency.p95_ns);
        assert!(first.latency.p95_ns <= first.latency.p99_ns);
        assert!(
            first
                .queries
                .iter()
                .all(|query| query.approximate_ids.len() == 5 && query.exact_ids.len() == 5)
        );
    }

    #[test]
    fn gate_rejects_hyperbolic_only_or_mixed_shapes() {
        let mut corpus = fixture_corpus();
        corpus.queries[0].sph.clear();
        corpus.queries[0].euc.clear();
        assert!(matches!(
            run_hnsw_gate(&corpus, &test_config()),
            Err(HnswGateError::UnexpectedDimensions {
                collection: "queries",
                index: 0,
                ..
            })
        ));
    }

    #[test]
    fn artifact_is_append_only_and_loadable() {
        let corpus = fixture_corpus();
        let config = test_config();
        let run = run_hnsw_gate(&corpus, &config).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let corpus_path = dir.path().join("corpus.json");
        let artifact_path = dir.path().join("gate.json");
        std::fs::write(&corpus_path, serde_json::to_vec(&corpus).unwrap()).unwrap();

        assert_eq!(load_hnsw_gate_corpus_json(&corpus_path).unwrap(), corpus);
        write_hnsw_gate_json(&artifact_path, &run).unwrap();
        assert!(write_hnsw_gate_json(&artifact_path, &run).is_err());
        let written: HnswGateRun =
            serde_json::from_slice(&std::fs::read(artifact_path).unwrap()).unwrap();
        assert_eq!(written.result_digest_blake3, run.result_digest_blake3);
    }

    #[test]
    fn release_requirement_is_explicit() {
        let corpus = fixture_corpus();
        let mut config = test_config();
        config.require_release = true;
        if cfg!(debug_assertions) {
            assert!(matches!(
                run_hnsw_gate(&corpus, &config),
                Err(HnswGateError::ReleaseBuildRequired)
            ));
        } else {
            assert!(run_hnsw_gate(&corpus, &config).is_ok());
        }
    }
}
