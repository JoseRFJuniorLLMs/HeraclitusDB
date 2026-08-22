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
    /// Inspect one HRKL v6 segment without opening a database directory.
    Inspect { segment: PathBuf },
    /// Verify a legacy log directory or an HRKL v6 segment.
    Verify {
        target: PathBuf,
        /// Recompute the canonical root for one HRKL v6 segment.
        #[arg(long)]
        logical: bool,
    },
    /// Produce a canonical inclusion proof for one LSN in a sealed HRKL v6 segment.
    Prove {
        segment: PathBuf,
        #[arg(long)]
        lsn: u64,
    },
    /// Reescreve um data-dir inteiro num destino NOVO com cifra por agent_id.
    /// Preserva LSN, EventId e HLC; nunca altera nem apaga a origem.
    MigrateEncrypt {
        /// Data-dir de origem (contém `log/` e, opcionalmente, `keys/`).
        source: PathBuf,
        /// Data-dir novo; deve não existir.
        destination: PathBuf,
    },
    /// Gera credenciais RBAC bootstrap sem imprimir tokens no terminal.
    InitCredentials {
        /// Diretório novo que receberá credentials.json e tokens separados.
        output: PathBuf,
    },
    /// QPS x recall@10 harness on a synthetic hierarchical dataset (M7).
    Bench {
        #[arg(long, default_value_t = 20_000)]
        n: usize,
        #[arg(long, default_value_t = 16)]
        dim: usize,
        #[arg(long, default_value_t = 100)]
        queries: usize,
    },
    /// Anchor the sealed state as development evidence (not ICP-Brasil validated).
    Anchor {
        /// Log directory.
        dir: PathBuf,
        /// Where to write the receipt (default: <dir>/../receipts).
        #[arg(long)]
        receipts: Option<PathBuf>,
        /// External RFC 3161 endpoint; HTTP only and unvalidated in this build.
        #[arg(long)]
        tsa_url: Option<String>,
        /// Authority/policy name recorded in the receipt.
        #[arg(long, default_value = "ACT-dev")]
        policy: String,
    },
    /// Re-verify receipts: commitment integrity plus available token validation.
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
        Cmd::Inspect { segment } => heraclitus_cli::inspect_v6(&segment).map_err(|e| e.to_string()),
        Cmd::Verify { target, logical } => {
            heraclitus_cli::verify_target_with_level(&target, logical).map_err(|e| e.to_string())
        }
        Cmd::Prove { segment, lsn } => {
            heraclitus_cli::prove_v6_lsn(&segment, lsn).map_err(|e| e.to_string())
        }
        Cmd::MigrateEncrypt {
            source,
            destination,
        } => heraclitus_cli::migrate_encrypt(&source, &destination).map_err(|e| e.to_string()),
        Cmd::InitCredentials { output } => {
            heraclitus_cli::init_credentials(&output).map_err(|e| e.to_string())
        }
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
