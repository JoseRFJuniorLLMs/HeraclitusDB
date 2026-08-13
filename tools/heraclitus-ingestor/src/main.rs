//! heraclitus-ingestor — ETL de dados abertos do governo federal → HeraclitusDB
//!
//! Uso:
//!   ingestor --server http://127.0.0.1:7474 --dir D:/dados-governo --batch 500
//!
//! Datasets suportados (detectados automaticamente pelo nome do diretório):
//!   *_Despesas, *_Servidores_SIAPE, *_Compras, *_Transferencias, *_Licitacoes,
//!   *_Aposentados_SIAPE, *_Pensionistas_SIAPE, *_Servidores_BACEN

// Ferramenta ETL (fora do core): o módulo de datasets é scaffolding partilhado
// por dois binários (ingestor + edge-builder), logo cada binário usa só um
// subconjunto — o dead_code é intencional. Silencia-se aqui o ruído de estilo
// para o `clippy -D warnings` do CI passar sobre o workspace todo, sem afrouxar
// o gate nos crates do core (que ficam clippy-clean de verdade).
#![allow(
    dead_code,
    clippy::redundant_closure,
    clippy::manual_is_multiple_of,
    clippy::missing_transmute_annotations, // clap derive macro-generated
    clippy::doc_lazy_continuation
)]

mod datasets;
mod utils;

use clap::Parser;
use datasets::{
    compliance, compras, despesas, licitacoes, servidores_siape, socios, transferencias,
};
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(
    name = "ingestor",
    about = "Carrega dados abertos do governo federal no HeraclitusDB"
)]
struct Cli {
    /// Endereço gRPC do HeraclitusDB
    #[arg(long, default_value = "http://127.0.0.1:7474")]
    server: String,

    /// Diretório raiz dos dados (D:/dados-governo)
    #[arg(long, default_value = "D:/dados-governo")]
    dir: PathBuf,

    /// Tamanho do lote de eventos por chamada gRPC
    #[arg(long, default_value_t = 500)]
    batch: usize,

    /// Apenas simula — não envia eventos
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();
    let dir = cli.dir.canonicalize().unwrap_or_else(|_| cli.dir.clone());

    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  HeraclitusDB — Ingestor de Dados Governamentais        ║");
    info!("╚══════════════════════════════════════════════════════════╝");
    info!("  Servidor  : {}", cli.server);
    info!("  Dados     : {}", dir.display());
    info!("  Lote      : {} eventos/chamada", cli.batch);
    if cli.dry_run {
        warn!("  MODO DRY-RUN — nenhum dado será gravado");
    }

    // Conectar ao servidor
    let mut client = if !cli.dry_run {
        info!("Conectando ao HeraclitusDB...");
        Some(
            heraclitus_client::Client::connect(cli.server.clone())
                .await
                .map_err(|e| anyhow::anyhow!("Falha ao conectar em {}: {e}", cli.server))?,
        )
    } else {
        None
    };
    info!("Conexão estabelecida ✓");

    let mut total_eventos = 0u64;
    let mut total_erros = 0u64;

    // Percorrer subdiretórios do diretório raiz
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| anyhow::anyhow!("Não foi possível ler {}: {e}", dir.display()))?;

    let mut subdirs: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.path())
        .collect();
    subdirs.sort();

    for subdir in &subdirs {
        let nome = subdir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        info!("─────────────────────────────────────────");
        info!("📂 Processando: {}", nome);

        let resultado =
            processar_subdir(subdir, &nome, client.as_mut(), cli.batch, cli.dry_run).await;

        match resultado {
            Ok(n) => {
                info!("  ✓ {} eventos ingeridos em '{}'", n, nome);
                total_eventos += n;
            }
            Err(e) => {
                error!("  ✗ Erro em '{}': {}", nome, e);
                total_erros += 1;
            }
        }
    }

    info!("═════════════════════════════════════════════════════════");
    info!("✅ CARGA CONCLUÍDA");
    info!("   Total de eventos : {}", total_eventos);
    info!("   Subdiretórios com erro: {}", total_erros);

    // Seal final: forçar snapshot para selar o segmento ativo
    if let Some(ref mut c) = client {
        info!("Selando segmento final (snapshot)...");
        match c.snapshot().await {
            Ok(lsn) => info!("  Snapshot selado em LSN {lsn} ✓"),
            Err(e) => warn!("  Aviso no snapshot: {e}"),
        }
    }

    Ok(())
}

async fn processar_subdir(
    subdir: &Path,
    nome: &str,
    client: Option<&mut heraclitus_client::Client>,
    batch: usize,
    dry_run: bool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let nome_up = nome.to_uppercase();

    // Detectar tipo pelo nome do diretório
    let n = if nome_up.contains("_DESPESAS") && !nome_up.contains("(1)") {
        despesas::ingerir(subdir, nome, client, batch, dry_run).await?
    } else if nome_up.contains("_SERVIDORES_SIAPE") {
        servidores_siape::ingerir(subdir, nome, client, batch, dry_run).await?
    } else if nome_up.contains("_COMPRAS") {
        compras::ingerir(subdir, nome, client, batch, dry_run).await?
    } else if nome_up.contains("_TRANSFERENCIAS") && !nome_up.contains("(1)") {
        transferencias::ingerir(subdir, nome, client, batch, dry_run).await?
    } else if nome_up.contains("_LICITACOES") {
        licitacoes::ingerir(subdir, nome, client, batch, dry_run).await?
    } else if nome_up.contains("_APOSENTADOS_SIAPE")
        || nome_up.contains("_PENSIONISTAS_SIAPE")
        || nome_up.contains("_SERVIDORES_BACEN")
    {
        // Tratamento genérico: cada CSV vira Observation com attrs completos
        servidores_siape::ingerir_generico(subdir, nome, client, batch, dry_run).await?
    } else if nome_up.contains("_CEIS")
        || nome_up.contains("_CNEP")
        || nome_up.contains("_CEPIM")
        || nome_up.contains("_CEAF")
        || nome_up.contains("_CPGF")
        || nome_up.contains("_VIAGENS")
    {
        compliance::ingerir(subdir, nome, client, batch, dry_run).await?
    } else if nome_up.contains("SOCIO") || nome_up.contains("_QSA") {
        socios::ingerir(subdir, nome, client, batch, dry_run).await?
    } else {
        warn!("  ⚠ Tipo não reconhecido para '{}' — ignorado", nome);
        0
    };

    Ok(n)
}
