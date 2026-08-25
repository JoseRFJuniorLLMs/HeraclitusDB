//! Gate A/B honesto da SPEC-HRKL-0050, §153--§154.
//!
//! Compara o writer legado v5 com o writer HRKL v6 RAW usando:
//! - o mesmo gerador determinístico de episódios;
//! - o mesmo tamanho de segmento e a mesma política de fsync;
//! - pelo menos cinco diretórios/corridas independentes por formato;
//! - ordem A/B alternada para reduzir viés de aquecimento e deriva temporal.
//!
//! O throughput inclui a barreira `flush` final. O p99 mede apenas as chamadas
//! de `append`, como exige §153. Depois das medições, a última corrida v6 é
//! selada e empacotada; os tamanhos de §154 são somados diretamente dos
//! `PackReceipt`, logo RAW e PACKED cobrem exatamente os mesmos registos.
//!
//! Execução representativa (release, fsync de produção por omissão):
//!
//! ```text
//! cargo bench -p heraclitus-log --bench hrkl_v6_ab
//! ```
//!
//! Variáveis:
//! - `HERACLITUS_AB_EVENTS` (default 10000; aceita 20000000+ sem guardar o
//!   corpus inteiro em RAM);
//! - `HERACLITUS_AB_RUNS` (default/minimum 5);
//! - `HERACLITUS_AB_SEGMENT_BYTES` (default 8 MiB);
//! - `HERACLITUS_AB_FSYNC=always|group:<ms>` (default `always`);
//! - `HERACLITUS_AB_PACK_PROFILE=fast|balanced|archive` (default `balanced`);
//! - `HERACLITUS_AB_ENFORCE=1` termina com código 2 se algum gate falhar.

use std::error::Error;
use std::io;
use std::time::Instant;

use heraclitus_core::{Episode, EventId, EventKind, FsyncPolicy, ProductPoint, StorageFormat};
use heraclitus_log::v6::PackingProfile;
use heraclitus_log::AnyLog;

const DEFAULT_EVENTS: usize = 10_000;
const DEFAULT_RUNS: usize = 5;
const DEFAULT_SEGMENT_BYTES: u64 = 8 << 20;
const HOT_WRITE_MAX_REGRESSION_PCT: f64 = 3.0;
const PACKED_MAX_RAW_RATIO: f64 = 0.50;
const CORPUS_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

const SERVICES: [&str; 8] = [
    "api-gateway",
    "auth-svc",
    "billing",
    "nginx-edge",
    "worker-etl",
    "db-proxy",
    "cron",
    "search",
];
const LEVELS: [&str; 5] = ["INFO", "WARN", "ERROR", "DEBUG", "AUDIT"];
const ROUTES: [&str; 8] = [
    "/v1/consulta",
    "/v1/protocolo",
    "/health",
    "/v1/documento/upload",
    "/login",
    "/v1/relatorio",
    "/v1/jobs",
    "/v1/search",
];
const WORDS: [&str; 24] = [
    "request",
    "completed",
    "tenant",
    "document",
    "policy",
    "cache",
    "database",
    "worker",
    "queue",
    "retry",
    "session",
    "latency",
    "trace",
    "authorization",
    "upload",
    "search",
    "result",
    "checkpoint",
    "connection",
    "response",
    "protocol",
    "region",
    "audit",
    "service",
];

#[derive(Clone, Copy)]
struct Config {
    events: usize,
    runs: usize,
    segment_bytes: u64,
    fsync: FsyncSetting,
    pack_profile: PackingProfile,
    enforce: bool,
}

#[derive(Clone, Copy)]
enum FsyncSetting {
    Always,
    GroupCommit { interval_ms: u64 },
}

impl FsyncSetting {
    fn policy(self) -> FsyncPolicy {
        match self {
            Self::Always => FsyncPolicy::Always,
            Self::GroupCommit { interval_ms } => FsyncPolicy::GroupCommit { interval_ms },
        }
    }

    fn label(self) -> String {
        match self {
            Self::Always => "always".into(),
            Self::GroupCommit { interval_ms } => format!("group:{interval_ms}"),
        }
    }
}

struct RunSample {
    throughput: f64,
    append_p99_ns: u64,
    flush_ns: u64,
    corpus_digest: [u8; 32],
}

struct CompletedRun {
    sample: RunSample,
    log: AnyLog,
    _dir: tempfile::TempDir,
}

#[derive(Default)]
struct FormatSamples {
    throughputs: Vec<f64>,
    append_p99_ns: Vec<u64>,
    flush_ns: Vec<u64>,
}

struct Summary {
    throughput_median: f64,
    append_p99_median_ns: u64,
    flush_median_ns: u64,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, ceiling: u64) -> u64 {
        self.next() % ceiling.max(1)
    }

    fn signed_unit(&mut self) -> f32 {
        let fraction = (self.next() as u32) as f64 / u32::MAX as f64;
        (fraction * 2.0 - 1.0) as f32
    }
}

fn operational_episode(rng: &mut Rng, index: usize) -> Episode {
    let service = SERVICES[index % SERVICES.len()];
    let level = LEVELS[rng.below(LEVELS.len() as u64) as usize];
    let route = ROUTES[rng.below(ROUTES.len() as u64) as usize];
    let status = [200u16, 200, 200, 201, 204, 304, 400, 404, 409, 500][rng.below(10) as usize];
    let latency_ms = rng.below(2_000);
    let request_id = rng.next();
    let tenant = rng.below(4_096);

    let mut message = format!(
        "{level} service={service} route={route} status={status} \
         latency_ms={latency_ms} request_id={request_id:016x} "
    );
    let words = 18 + rng.below(34) as usize;
    for _ in 0..words {
        message.push_str(WORDS[rng.below(WORDS.len() as u64) as usize]);
        message.push(' ');
    }

    let mut episode = Episode::new(
        service,
        EventKind::Custom(level.to_owned()),
        message.into_bytes(),
    );
    // ULID determinístico: todas as corridas e ambos os formatos recebem os
    // mesmos bytes lógicos antes de o writer carimbar o HLC.
    let id_bits = ((0x018F_FFFF_FFFFu128) << 80) | index as u128;
    episode.id = EventId(ulid::Ulid::from_bytes(id_bits.to_be_bytes()));
    episode.session_id = format!("sess-{:08x}", index / 1_000);
    episode.attrs.insert("route".into(), route.into());
    episode.attrs.insert("status".into(), status.to_string());
    episode
        .attrs
        .insert("latency_ms".into(), latency_ms.to_string());
    episode
        .attrs
        .insert("request_id".into(), format!("{request_id:016x}"));
    episode.attrs.insert("tenant".into(), tenant.to_string());

    // Uma pequena fração de embeddings evita que o corpus "operacional" seja
    // texto artificialmente fácil de comprimir.
    if index.is_multiple_of(16) {
        episode.embedding = Some(ProductPoint {
            hyp: (0..8).map(|_| rng.signed_unit() * 0.1).collect(),
            sph: (0..8).map(|_| rng.signed_unit()).collect(),
            euc: (0..16).map(|_| rng.signed_unit() * 8.0).collect(),
        });
    }
    if index > 0 && index.is_multiple_of(5) {
        let parent_bits = ((0x018F_FFFF_FFFFu128) << 80) | (index - 1) as u128;
        episode
            .parents
            .push(EventId(ulid::Ulid::from_bytes(parent_bits.to_be_bytes())));
    }
    if index.is_multiple_of(11) {
        episode.valid_from = Some(1_700_000_000_000 + index as u64 * 10);
    }
    episode
}

fn run_format(format: StorageFormat, config: Config) -> Result<CompletedRun, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let log = AnyLog::open(
        format,
        dir.path(),
        config.segment_bytes,
        config.fsync.policy(),
    )?;
    let mut rng = Rng(CORPUS_SEED);
    let mut append_ns = Vec::with_capacity(config.events);
    let mut corpus_hash = blake3::Hasher::new();
    let mut append_total_ns = 0u64;

    for index in 0..config.events {
        let episode = operational_episode(&mut rng, index);
        let encoded = bincode::serde::encode_to_vec(&episode, bincode::config::standard())?;
        corpus_hash.update(&(encoded.len() as u64).to_le_bytes());
        corpus_hash.update(&encoded);

        let started = Instant::now();
        log.append(episode)?;
        let elapsed = nanos(started);
        append_total_ns = append_total_ns.saturating_add(elapsed);
        append_ns.push(elapsed);
    }

    let flush_started = Instant::now();
    log.flush()?;
    let flush_ns = nanos(flush_started);
    let durable_ns = append_total_ns.saturating_add(flush_ns).max(1);
    let throughput = config.events as f64 * 1_000_000_000.0 / durable_ns as f64;
    let append_p99_ns = percentile_nearest_rank(&mut append_ns, 0.99);

    Ok(CompletedRun {
        sample: RunSample {
            throughput,
            append_p99_ns,
            flush_ns,
            corpus_digest: *corpus_hash.finalize().as_bytes(),
        },
        log,
        _dir: dir,
    })
}

fn nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

fn percentile_nearest_rank(values: &mut [u64], percentile: f64) -> u64 {
    values.sort_unstable();
    let rank = (percentile * values.len() as f64).ceil() as usize;
    values[rank.saturating_sub(1).min(values.len() - 1)]
}

fn median_f64(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    }
}

fn median_u64(values: &[u64]) -> u64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        sorted[middle - 1] / 2 + sorted[middle] / 2
    } else {
        sorted[middle]
    }
}

impl FormatSamples {
    fn push(&mut self, sample: &RunSample) {
        self.throughputs.push(sample.throughput);
        self.append_p99_ns.push(sample.append_p99_ns);
        self.flush_ns.push(sample.flush_ns);
    }

    fn summarize(&self) -> Summary {
        Summary {
            throughput_median: median_f64(&self.throughputs),
            append_p99_median_ns: median_u64(&self.append_p99_ns),
            flush_median_ns: median_u64(&self.flush_ns),
        }
    }
}

fn env_parse<T>(name: &str, default: T) -> Result<T, Box<dyn Error>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name}={value:?} inválido: {err}"),
            )
            .into()
        }),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(err.into()),
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn load_config() -> Result<Config, Box<dyn Error>> {
    let events = env_parse("HERACLITUS_AB_EVENTS", DEFAULT_EVENTS)?;
    let runs = env_parse("HERACLITUS_AB_RUNS", DEFAULT_RUNS)?;
    let segment_bytes = env_parse("HERACLITUS_AB_SEGMENT_BYTES", DEFAULT_SEGMENT_BYTES)?;
    if events == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HERACLITUS_AB_EVENTS deve ser maior que zero",
        )
        .into());
    }
    if runs < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SPEC-0050 §153 exige HERACLITUS_AB_RUNS >= 5",
        )
        .into());
    }
    if segment_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HERACLITUS_AB_SEGMENT_BYTES deve ser maior que zero",
        )
        .into());
    }

    let fsync_text = std::env::var("HERACLITUS_AB_FSYNC").unwrap_or_else(|_| "always".into());
    let fsync = if fsync_text.eq_ignore_ascii_case("always") {
        FsyncSetting::Always
    } else if let Some(interval) = fsync_text.strip_prefix("group:") {
        FsyncSetting::GroupCommit {
            interval_ms: interval.parse().map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("HERACLITUS_AB_FSYNC={fsync_text:?} inválido: {err}"),
                )
            })?,
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HERACLITUS_AB_FSYNC aceita always ou group:<ms>",
        )
        .into());
    };

    let profile_text =
        std::env::var("HERACLITUS_AB_PACK_PROFILE").unwrap_or_else(|_| "balanced".into());
    let pack_profile = PackingProfile::parse(&profile_text).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "HERACLITUS_AB_PACK_PROFILE aceita fast, balanced ou archive",
        )
    })?;

    Ok(Config {
        events,
        runs,
        segment_bytes,
        fsync,
        pack_profile,
        enforce: env_flag("HERACLITUS_AB_ENFORCE"),
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = load_config()?;
    println!("\n=== SPEC-HRKL-0050 §153--§154: v5 vs v6 RAW ===");
    println!(
        "events/run={} runs={} segment_bytes={} fsync={} pack_profile={:?}",
        config.events,
        config.runs,
        config.segment_bytes,
        config.fsync.label(),
        config.pack_profile
    );
    println!(
        "corpus=operational-v1 (logs 8 serviços/8 rotas; 5 attrs; embeddings em 1/16; IDs determinísticos)"
    );

    let mut v5 = FormatSamples::default();
    let mut v6 = FormatSamples::default();
    let mut expected_digest = None;
    let mut packing_source = None;

    for run in 0..config.runs {
        let order = if run % 2 == 0 {
            [StorageFormat::Legacy, StorageFormat::V6]
        } else {
            [StorageFormat::V6, StorageFormat::Legacy]
        };
        for format in order {
            let completed = run_format(format, config)?;
            if let Some(expected) = expected_digest {
                if completed.sample.corpus_digest != expected {
                    return Err(io::Error::other(
                        "digest do corpus divergiu entre corridas/formatos",
                    )
                    .into());
                }
            } else {
                expected_digest = Some(completed.sample.corpus_digest);
            }

            println!(
                "run {:>2} {:>6}: {:>10.0} append/s; p99={:>9.3} ms; flush={:>9.3} ms",
                run + 1,
                format.as_str(),
                completed.sample.throughput,
                completed.sample.append_p99_ns as f64 / 1_000_000.0,
                completed.sample.flush_ns as f64 / 1_000_000.0,
            );
            match format {
                StorageFormat::Legacy => v5.push(&completed.sample),
                StorageFormat::V6 => {
                    v6.push(&completed.sample);
                    if run + 1 == config.runs {
                        packing_source = Some(completed);
                        continue;
                    }
                }
            }
        }
    }

    let v5_summary = v5.summarize();
    let v6_summary = v6.summarize();
    let signed_throughput_delta_pct =
        (v6_summary.throughput_median / v5_summary.throughput_median - 1.0) * 100.0;
    let throughput_regression_pct = (-signed_throughput_delta_pct).max(0.0);
    let hot_gate_pass = throughput_regression_pct <= HOT_WRITE_MAX_REGRESSION_PCT;

    let packing_source = packing_source.ok_or_else(|| {
        io::Error::other("última corrida v6 não ficou disponível para o gate de compressão")
    })?;
    let v6_log = packing_source
        .log
        .v6_arc()
        .ok_or_else(|| io::Error::other("packing source não é V6Log"))?;
    v6_log.seal_active()?;
    let packed = v6_log.pack_pending(config.pack_profile)?;
    let raw_bytes: u64 = packed
        .iter()
        .map(|outcome| outcome.receipt.source_physical_size)
        .sum();
    let packed_bytes: u64 = packed
        .iter()
        .map(|outcome| outcome.receipt.target_physical_size)
        .sum();
    let packed_records: u64 = packed
        .iter()
        .map(|outcome| outcome.receipt.record_count)
        .sum();
    if packed_records != config.events as u64 {
        return Err(io::Error::other(format!(
            "recibos cobrem {packed_records} registos; esperados {}",
            config.events
        ))
        .into());
    }
    let packed_raw_ratio = packed_bytes as f64 / raw_bytes.max(1) as f64;
    let compression_gate_pass = packed_raw_ratio <= PACKED_MAX_RAW_RATIO;
    let corpus_digest = expected_digest.expect("ao menos uma corrida");
    let overall_pass = hot_gate_pass && compression_gate_pass;

    println!("\n--- Resumo (mediana de {} corridas) ---", config.runs);
    println!(
        "v5: throughput={:.0} append/s; append_p99={:.3} ms; flush={:.3} ms",
        v5_summary.throughput_median,
        v5_summary.append_p99_median_ns as f64 / 1_000_000.0,
        v5_summary.flush_median_ns as f64 / 1_000_000.0,
    );
    println!(
        "v6: throughput={:.0} append/s; append_p99={:.3} ms; flush={:.3} ms",
        v6_summary.throughput_median,
        v6_summary.append_p99_median_ns as f64 / 1_000_000.0,
        v6_summary.flush_median_ns as f64 / 1_000_000.0,
    );
    println!(
        "§153: v6-v5={signed_throughput_delta_pct:+.2}%; regressão={throughput_regression_pct:.2}% (limite {HOT_WRITE_MAX_REGRESSION_PCT:.0}%) => {}",
        if hot_gate_pass { "PASS" } else { "FAIL" }
    );
    println!(
        "§154: raw={raw_bytes} B packed={packed_bytes} B ratio={:.2}% em {} segmentos (limite {:.0}%) => {}",
        packed_raw_ratio * 100.0,
        packed.len(),
        PACKED_MAX_RAW_RATIO * 100.0,
        if compression_gate_pass { "PASS" } else { "FAIL" }
    );
    println!(
        "corpus_digest={}",
        blake3::Hash::from(corpus_digest).to_hex()
    );

    let result = serde_json::json!({
        "schema": "hrkl-v6-ab-result/1",
        "events_per_run": config.events,
        "runs": config.runs,
        "segment_bytes": config.segment_bytes,
        "fsync": config.fsync.label(),
        "pack_profile": format!("{:?}", config.pack_profile).to_ascii_lowercase(),
        "corpus": "operational-v1",
        "corpus_digest_blake3": blake3::Hash::from(corpus_digest).to_hex().to_string(),
        "v5": {
            "median_throughput_append_s": v5_summary.throughput_median,
            "median_run_append_p99_ns": v5_summary.append_p99_median_ns,
            "median_flush_ns": v5_summary.flush_median_ns,
        },
        "v6_raw": {
            "median_throughput_append_s": v6_summary.throughput_median,
            "median_run_append_p99_ns": v6_summary.append_p99_median_ns,
            "median_flush_ns": v6_summary.flush_median_ns,
        },
        "hot_write": {
            "signed_throughput_delta_pct": signed_throughput_delta_pct,
            "regression_pct": throughput_regression_pct,
            "max_regression_pct": HOT_WRITE_MAX_REGRESSION_PCT,
            "pass": hot_gate_pass,
        },
        "compression": {
            "raw_bytes": raw_bytes,
            "packed_bytes": packed_bytes,
            "packed_raw_ratio": packed_raw_ratio,
            "max_packed_raw_ratio": PACKED_MAX_RAW_RATIO,
            "segments": packed.len(),
            "records": packed_records,
            "pass": compression_gate_pass,
        },
        "pass": overall_pass,
    });
    println!("HRKL_AB_RESULT_JSON={result}");

    if config.enforce && !overall_pass {
        std::process::exit(2);
    }
    Ok(())
}
