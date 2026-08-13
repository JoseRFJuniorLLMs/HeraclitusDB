//! Seed a throwaway log with enough events to seal several segments — so the
//! CLI `anchor` / `verify-receipts` commands have something to anchor.
//!
//! Usage: `cargo run -p heraclitus-compliance --example seed_log -- <log_dir> [n]`

use heraclitus_compliance::current_watermark;
use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("uso: seed_log <log_dir> [n]");
    let n: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(300);

    // tiny segments so many seal and the watermark advances
    let log = Log::open(&dir, 512, FsyncPolicy::Always).expect("abrir log");
    for i in 0..n {
        log.append(Episode::new(
            "auditor",
            EventKind::Observation,
            format!("licitacao SIASG #{i} — empenho e contrato").into_bytes(),
        ))
        .expect("append");
    }
    println!(
        "log semeado em {dir}: head LSN {}, watermark selado {}",
        log.head(),
        current_watermark(&log)
    );
}
