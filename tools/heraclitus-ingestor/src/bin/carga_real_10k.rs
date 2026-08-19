//! carga_real_10k — Insere 10.000 registros realistas no HeraclitusDB baseados em carga_real_1m.rs
//!
//! Uso:
//!   carga_real_10k --server http://127.0.0.1:7474 --n 10000

use clap::Parser;
use std::time::Instant;
use tracing::{info, warn};

#[derive(Parser)]
#[command(
    name = "carga_real_10k",
    about = "Insere registros realistas baseados em carga_real_1m.rs no HeraclitusDB"
)]
struct Cli {
    /// Endereço gRPC do HeraclitusDB
    #[arg(long, default_value = "http://127.0.0.1:7474")]
    server: String,

    /// Número de registros a inserir
    #[arg(long, default_value_t = 10000)]
    n: u64,

    /// Token de autenticação (Bearer Token)
    #[arg(long)]
    token: Option<String>,
}

struct Rng(u64);

impl Rng {
    fn proximo(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn ate(&mut self, n: u64) -> u64 {
        self.proximo() % n.max(1)
    }
}

const SERVICOS: [&str; 8] = [
    "api-gateway",
    "auth-svc",
    "billing",
    "nginx-edge",
    "worker-etl",
    "db-proxy",
    "cron",
    "search",
];
const NIVEIS: [&str; 5] = ["INFO", "WARN", "ERROR", "DEBUG", "AUDIT"];
const ROTAS: [&str; 6] = [
    "/v1/consulta",
    "/v1/protocolo",
    "/health",
    "/v1/documento/upload",
    "/login",
    "/v1/relatorio",
];

fn obter_token(cli_token: Option<String>) -> Option<String> {
    // 1. Opção via CLI
    if cli_token.is_some() {
        return cli_token;
    }

    // 2. Variável de ambiente HERACLITUS_TOKEN_FILE (caminho para arquivo com o token)
    if let Ok(caminho) = std::env::var("HERACLITUS_TOKEN_FILE") {
        if let Ok(conteudo) = std::fs::read_to_string(caminho) {
            let token = conteudo.trim().to_string();
            if !token.is_empty() {
                return Some(token);
            }
        }
    }

    // 3. Variável de ambiente HERACLITUS_AUTH_TOKEN (token direto)
    if let Ok(token) = std::env::var("HERACLITUS_AUTH_TOKEN") {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Some(token);
        }
    }

    // 4. config.local.toml
    if let Ok(conteudo) = std::fs::read_to_string("config.local.toml") {
        for linha in conteudo.lines() {
            let linha_limpa = linha.trim();
            if linha_limpa.starts_with("auth_token") {
                let partes: Vec<&str> = linha_limpa.split('=').collect();
                if partes.len() >= 2 {
                    let token = partes[1].trim().trim_matches('"').trim_matches('\'').to_string();
                    if !token.is_empty() {
                        return Some(token);
                    }
                }
            }
        }
    }

    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();

    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  HeraclitusDB — Carga Realista de {} Registros         ║", cli.n);
    info!("╚══════════════════════════════════════════════════════════╝");
    info!("  Servidor  : {}", cli.server);

    let token = obter_token(cli.token);

    info!("Conectando ao HeraclitusDB...");
    let mut client = heraclitus_client::Client::connect(cli.server.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Falha ao conectar em {}: {e}", cli.server))?;
    
    if let Some(ref t) = token {
        info!("Autenticação configurada com bearer token (origem detectada).");
        client = client.with_bearer_token(t)
            .map_err(|e| anyhow::anyhow!("Token inválido: {e}"))?;
    } else {
        warn!("Nenhum token de autenticação detectado. A chamada pode falhar se o servidor exigir autenticação.");
    }
    info!("Conexão estabelecida ✓");

    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let t_inicio = Instant::now();
    let mut inseridos = 0u64;

    for i in 0..cli.n {
        let svc = SERVICOS[(i % SERVICOS.len() as u64) as usize];
        let nivel = NIVEIS[(rng.ate(100) % NIVEIS.len() as u64) as usize];
        let rota = ROTAS[(rng.ate(100) % ROTAS.len() as u64) as usize];
        let status = [200u32, 200, 200, 201, 304, 400, 404, 500][rng.ate(8) as usize];
        let latencia = rng.ate(2000);
        let extra = (rng.ate(280) + 120) as usize;
        let msg = format!(
            "{nivel} {svc} {rota} status={status} lat={latencia}ms req={:016x} {}",
            rng.proximo(),
            "-".repeat(extra)
        );

        let mut attrs = std::collections::HashMap::new();
        attrs.insert("rota".to_string(), rota.to_string());
        attrs.insert("status".to_string(), status.to_string());
        attrs.insert("latencia_ms".to_string(), latencia.to_string());

        let opts = heraclitus_client::AppendOptions {
            session_id: format!("sess-{:08x}", i / 1000),
            kind: nivel.to_string(),
            attrs,
            ..Default::default()
        };

        match client.append(svc, msg.as_bytes(), opts).await {
            Ok(_) => {
                inseridos += 1;
            }
            Err(e) => {
                warn!("Erro ao inserir registro {}/{}: {}", i + 1, cli.n, e);
            }
        }

        if (i + 1) % 1000 == 0 {
            info!("  ... {} registros inseridos", i + 1);
        }
    }

    let duracao = t_inicio.elapsed();
    let vazao = inseridos as f64 / duracao.as_secs_f64();

    info!("═════════════════════════════════════════════════════════");
    info!("✅ CARGA CONCLUÍDA");
    info!("   Total inserido   : {}/{} registros", inseridos, cli.n);
    info!("   Tempo decorrido  : {:.2?}", duracao);
    info!("   Throughput       : {:.2} registros/segundo", vazao);

    info!("Selando segmento final (snapshot)...");
    match client.snapshot().await {
        Ok(lsn) => info!("  Snapshot selado em LSN {lsn} ✓"),
        Err(e) => warn!("  Aviso no snapshot: {e}"),
    }

    Ok(())
}
