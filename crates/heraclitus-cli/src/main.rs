use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "heraclitus", about = "HeraclitusDB admin & inspection CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Inspect a log directory: head, segments, merkle roots.
    LogInspect { dir: PathBuf },
    /// Full integrity scan: every crc + sealed-segment merkle roots.
    Verify { dir: PathBuf },
    /// QPS x recall@10 harness on a synthetic hierarchical dataset (M7).
    Bench {
        #[arg(long, default_value_t = 20_000)]
        n: usize,
        #[arg(long, default_value_t = 16)]
        dim: usize,
        #[arg(long, default_value_t = 100)]
        queries: usize,
    },
    /// Anchor the sealed state with a legal timestamp (RFC 3161 / ICP-Brasil).
    Anchor {
        /// Log directory.
        dir: PathBuf,
        /// Where to write the receipt (default: <dir>/../receipts).
        #[arg(long)]
        receipts: Option<PathBuf>,
        /// Real ACT endpoint; omit to use the in-process dev ACT.
        #[arg(long)]
        tsa_url: Option<String>,
        /// Authority/policy name recorded in the receipt.
        #[arg(long, default_value = "ACT-dev")]
        policy: String,
    },
    /// Re-verify all receipts against the log (forensic anti-fraud check).
    VerifyReceipts {
        /// Log directory.
        dir: PathBuf,
        /// Receipts directory (default: <dir>/../receipts).
        #[arg(long)]
        receipts: Option<PathBuf>,
    },
}

fn receipts_dir_for(dir: &std::path::Path, receipts: Option<PathBuf>) -> PathBuf {
    receipts.unwrap_or_else(|| {
        dir.parent()
            .map(|p| p.join("receipts"))
            .unwrap_or_else(|| PathBuf::from("receipts"))
    })
}

fn main() {
    let cli = Cli::parse();
    // Uma falha de integridade (verify/verify-receipts) ou qualquer erro TEM de
    // devolver código de saída 1 — scripts forenses gateiam com `&&`/`||`.
    let result: Result<String, String> = match cli.cmd {
        Cmd::LogInspect { dir } => heraclitus_cli::log_inspect(&dir).map_err(|e| e.to_string()),
        Cmd::Verify { dir } => heraclitus_cli::verify(&dir).map_err(|e| e.to_string()),
        Cmd::Bench { n, dim, queries } => {
            Ok(heraclitus_cli::bench_recall(n, dim, queries).to_markdown())
        }
        Cmd::Anchor {
            dir,
            receipts,
            tsa_url,
            policy,
        } => {
            let rdir = receipts_dir_for(&dir, receipts);
            heraclitus_cli::anchor(&dir, &rdir, tsa_url, policy)
        }
        Cmd::VerifyReceipts { dir, receipts } => {
            let rdir = receipts_dir_for(&dir, receipts);
            heraclitus_cli::verify_receipts(&dir, &rdir)
        }
    };
    match result {
        Ok(out) => println!("{out}"),
        Err(out) => {
            eprintln!("{out}");
            std::process::exit(1);
        }
    }
}
