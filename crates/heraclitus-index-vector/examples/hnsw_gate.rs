//! Run the SPEC-0044 Gate C baseline for a frozen H32×S8×E8 corpus.
//!
//! Example:
//! ```text
//! cargo run --release -p heraclitus-index-vector --example hnsw_gate -- \
//!   --corpus .\corpus.json --source-fingerprint sha256:... --out .\gate.json
//! ```
//!
//! This intentionally measures direct `VectorIndex` search only. It must not
//! be used as evidence for the hyperbolic-only `Engine::nearest` path.

use heraclitus_index_vector::gate::{
    HnswGateConfig, load_hnsw_gate_corpus_json, run_hnsw_gate, write_hnsw_gate_json,
};
use std::path::PathBuf;

struct Args {
    corpus: PathBuf,
    source_fingerprint: String,
    out: PathBuf,
    k: usize,
    ef: usize,
    warmup: usize,
}

fn usage() -> &'static str {
    "Usage:\n  cargo run --release -p heraclitus-index-vector --example hnsw_gate -- \\\n    --corpus <frozen-corpus.json> --source-fingerprint <digest> --out <new-artifact.json> \\\n    [--k 10] [--ef 64] [--warmup 16]\n\n\
The corpus must be HNSW_GATE_CORPUS_VERSION JSON with H32×S8×E8 points and queries.\n\
The output path must not already exist. This is not an Engine::nearest benchmark."
}

fn required_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requer um valor\n\n{}", usage()))
}

fn parse_usize(value: String, flag: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("{flag} precisa ser inteiro positivo: {value}"))
}

fn parse_args() -> Result<Args, String> {
    let mut values = std::env::args().skip(1);
    let mut corpus = None;
    let mut source_fingerprint = None;
    let mut out = None;
    let mut k = 10;
    let mut ef = 64;
    let mut warmup = 16;

    while let Some(flag) = values.next() {
        match flag.as_str() {
            "--corpus" => corpus = Some(PathBuf::from(required_value(&mut values, "--corpus")?)),
            "--source-fingerprint" => {
                source_fingerprint = Some(required_value(&mut values, "--source-fingerprint")?)
            }
            "--out" => out = Some(PathBuf::from(required_value(&mut values, "--out")?)),
            "--k" => k = parse_usize(required_value(&mut values, "--k")?, "--k")?,
            "--ef" => ef = parse_usize(required_value(&mut values, "--ef")?, "--ef")?,
            "--warmup" => {
                warmup = parse_usize(required_value(&mut values, "--warmup")?, "--warmup")?
            }
            "--help" | "-h" => return Err(usage().to_string()),
            _ => return Err(format!("opção desconhecida: {flag}\n\n{}", usage())),
        }
    }

    Ok(Args {
        corpus: corpus.ok_or_else(|| format!("--corpus é obrigatório\n\n{}", usage()))?,
        source_fingerprint: source_fingerprint
            .ok_or_else(|| format!("--source-fingerprint é obrigatório\n\n{}", usage()))?,
        out: out.ok_or_else(|| format!("--out é obrigatório\n\n{}", usage()))?,
        k,
        ef,
        warmup,
    })
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let corpus = load_hnsw_gate_corpus_json(&args.corpus).map_err(|error| error.to_string())?;
    let mut config = HnswGateConfig::product_32_8_8(args.source_fingerprint);
    config.k = args.k;
    config.ef = args.ef;
    config.warmup_queries = args.warmup;
    let result = run_hnsw_gate(&corpus, &config).map_err(|error| error.to_string())?;
    write_hnsw_gate_json(&args.out, &result).map_err(|error| error.to_string())?;

    println!(
        "Gate C {}: recall@{} {:.4}; p50/p95/p99 {} / {} / {} ns\nartifact: {}\nresult digest: {}",
        result.workload.label(),
        result.k,
        result.mean_recall_at_k,
        result.latency.p50_ns,
        result.latency.p95_ns,
        result.latency.p99_ns,
        args.out.display(),
        result.result_digest_blake3,
    );
    Ok(())
}

fn main() {
    if std::env::args().any(|argument| argument == "--help" || argument == "-h") {
        println!("{}", usage());
        return;
    }
    if let Err(error) = run() {
        eprintln!("hnsw_gate: {error}");
        std::process::exit(2);
    }
}
