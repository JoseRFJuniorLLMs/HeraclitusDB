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
    /// Rebuild HRKI sidecars and publish their references in the v6 HRKM.
    RebuildIndex {
        /// HRKL v6 storage root (the directory containing manifests/segments).
        target: PathBuf,
        #[arg(long, default_value_t = 0.01)]
        fpr: f64,
        /// Do not persist an equality filter for agent_id.
        #[arg(long)]
        no_agent_id: bool,
        /// Do not persist an equality filter for session_id.
        #[arg(long)]
        no_session_id: bool,
    },
    /// SPEC-0050 §90-§97 — plan or run the physical generation GC.
    ///
    /// Reclaims superseded generations (typically the RAW left behind by
    /// packing). Never removes the last canonical authority (§91), always
    /// respects the grace period (§93), legal hold (§94) and the verified-copy
    /// policy (§184). Quarantined generations (§127) need `--collect-quarantined`.
    Gc {
        /// HRKL v6 storage root.
        target: PathBuf,
        /// Show the plan and exit without removing anything.
        #[arg(long)]
        dry_run: bool,
        /// How many HRKM generations to keep (§90).
        #[arg(long, default_value_t = 3)]
        keep_manifests: usize,
        /// §127 — also collect quarantined generations. This destroys evidence
        /// of a problem: only pass it deliberately.
        #[arg(long)]
        collect_quarantined: bool,
    },
    /// Storage diagnostics that never repair or mutate the inspected database.
    Storage {
        #[command(subcommand)]
        command: StorageCmd,
    },
    /// Inspect the HRKL v6 internal manifest (HRKM): segments, generations,
    /// background queues and export watermark. Read-only.
    Manifest {
        #[command(subcommand)]
        command: ManifestCmd,
    },
    /// SPEC-0050 §129-§133 — migrate a v1-v5 log directory to a NEW HRKL v6
    /// storage root.
    ///
    /// Never destructive: the source is left byte-for-byte intact, the
    /// destination must not already exist, and every segment leaves a
    /// verifiable receipt pairing the legacy root with the v6 logical root.
    /// Delete the legacy data yourself, after checking the receipts.
    MigrateV6 {
        /// Legacy log directory (the one holding the `.hrkl` files).
        source: PathBuf,
        /// New HRKL v6 storage root; must not exist or must be empty.
        destination: PathBuf,
        /// Skip the per-segment record-by-record equivalence check.
        ///
        /// Faster, and a worse trade than it looks: migration recomputes the
        /// canonical identity from scratch, so a codec bug would produce a
        /// plausible-but-wrong v6 segment that only surfaces when someone
        /// tries to prove an LSN months later.
        #[arg(long)]
        no_verify: bool,
    },
    /// SPEC-0050 Fase 6 — publish the lakehouse projection (Parquet + Iceberg
    /// + Delta) for every sealed segment the HRKM has not exported yet.
    ///
    /// Writes: it materialises objects at the destination and commits a new
    /// HRKM generation. Running it twice is a no-op — the queue lives in the
    /// manifest, so idempotency does not depend on this process remembering
    /// anything.
    Export {
        /// HRKL v6 storage root (the directory containing manifests/segments).
        target: PathBuf,
        /// Destination: a local directory or an object store URL.
        #[arg(long)]
        to: String,
        /// Table name published in the Iceberg/Delta catalogues.
        #[arg(long, default_value = "episodios")]
        table: String,
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
        /// Endpoint RFC 3161 externo. Um URL `https://` usa o cliente que
        /// valida a cadeia e exige `--trust-store`; `http://` continua a ser
        /// transporte em claro sem validacao nenhuma.
        #[arg(long)]
        tsa_url: Option<String>,
        /// Pasta com as ancoras de confianca do orgao (SPEC-0046 §11).
        /// Obrigatoria quando `--tsa-url` e https://.
        #[arg(long)]
        trust_store: Option<PathBuf>,
        /// Authority/policy name recorded in the receipt.
        #[arg(long, default_value = "ACT-dev")]
        policy: String,
    },
    /// Re-verify receipts: commitment integrity plus available token validation.
    VerifyReceipts {
        /// Pasta com as âncoras de confiança (PEM/DER) do órgão. Sem ela a
        /// cadeia dos tokens externos NÃO é validada e o resultado é
        /// inconclusivo por construção (SPEC-0046 §11).
        #[arg(long)]
        trust_store: Option<PathBuf>,
        /// Pasta com as CRLs das ACs. Exige `--trust-store`. Sem ela a
        /// revogação NÃO é consultada e o relatório di-lo (SPEC-0046 §9).
        #[arg(long)]
        crl_dir: Option<PathBuf>,
        /// Log directory.
        dir: PathBuf,
        /// Receipts directory (default: <dir>/../receipts).
        #[arg(long)]
        receipts: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum StorageCmd {
    /// Compare HRKM, physical generations and HRKI sidecars read-only.
    Doctor { dir: PathBuf },
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Render the current HRKM: segments, generations, queues, watermarks.
    Show { dir: PathBuf },
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
        Cmd::Gc {
            target,
            dry_run,
            keep_manifests,
            collect_quarantined,
        } => heraclitus_cli::gc_v6(&target, dry_run, keep_manifests, collect_quarantined)
            .map_err(|e| e.to_string()),
        Cmd::Manifest { command } => match command {
            ManifestCmd::Show { dir } => {
                heraclitus_cli::manifest_show_v6(&dir).map_err(|e| e.to_string())
            }
        },
        Cmd::MigrateV6 {
            source,
            destination,
            no_verify,
        } => heraclitus_cli::migrate_v6(&source, &destination, !no_verify)
            .map_err(|e| e.to_string()),
        Cmd::Export { target, to, table } => {
            heraclitus_cli::export_lakehouse_v6(&target, &to, &table).map_err(|e| e.to_string())
        }
        Cmd::RebuildIndex {
            target,
            fpr,
            no_agent_id,
            no_session_id,
        } => heraclitus_cli::rebuild_index_v6(
            &target,
            fpr,
            !no_agent_id,
            !no_session_id,
        )
        .map_err(|e| e.to_string()),
        Cmd::Storage {
            command: StorageCmd::Doctor { dir },
        } => heraclitus_cli::storage_doctor_v6(&dir).map_err(|e| e.to_string()),
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
            trust_store,
        } => {
            let rdir = receipts_dir_for(&dir, receipts);
            heraclitus_cli::anchor(&dir, &rdir, tsa_url, policy, trust_store.as_deref())
        }
        Cmd::VerifyReceipts {
            dir,
            receipts,
            trust_store,
            crl_dir,
        } => {
            let rdir = receipts_dir_for(&dir, receipts);
            heraclitus_cli::verify_receipts(
                &dir,
                &rdir,
                trust_store.as_deref(),
                crl_dir.as_deref(),
            )
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
