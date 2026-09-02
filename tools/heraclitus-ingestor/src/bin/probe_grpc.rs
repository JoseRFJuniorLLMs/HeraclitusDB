//! probe_grpc — quanto custa o SERVIDOR, por cima do log?
//!
//! O bench `carga_real_20m` mede o motor de escrita puro (`Log::append`). Esta
//! sonda mede o mesmo evento a entrar pelo caminho que um cliente real usa:
//! `rpc Append (AppendRequest) returns (AppendResponse)` — **unário, um evento
//! por chamada** (`crates/heraclitus-proto/proto/heraclitus.proto:7`).
//!
//! A diferença entre os dois números é o "imposto do servidor": round-trip
//! gRPC, `spawn_blocking` por evento (`grpc.rs:90`), e — no caminho sem
//! `idempotency_key` — a RELEITURA do registo do disco só para devolver o
//! `event_id` (`engine.rs:1303`).
//!
//! Mede em três modos, contra um servidor DESCARTÁVEL (nunca o de produção):
//!   1. serial      — 1 conexão, espera o ACK de cada append;
//!   2. concorrente — C conexões em paralelo;
//!   3. o mesmo, com `--idempotency` (exercita o caminho com chave).
//!
//! ```bash
//! probe_grpc --server http://127.0.0.1:7480 --n 50000 --conc 8
//! ```

use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "probe_grpc", about = "Mede o custo do caminho gRPC por evento")]
struct Cli {
    /// Endereço gRPC do servidor DESCARTÁVEL (nunca o de produção)
    #[arg(long, default_value = "http://127.0.0.1:7480")]
    server: String,
    /// Eventos por modo
    #[arg(long, default_value_t = 50_000)]
    n: u64,
    /// Conexões concorrentes no modo 2
    #[arg(long, default_value_t = 8)]
    conc: u64,
    /// Token bearer, se o servidor exigir
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

/// Mesmo formato de evento do bench do log — é o que torna os dois números
/// comparáveis, e a comparação é o objetivo desta sonda.
fn evento(rng: &mut Rng, i: u64) -> (String, Vec<u8>, HashMap<String, String>, String) {
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
    let mut attrs = HashMap::new();
    attrs.insert("rota".to_string(), rota.to_string());
    attrs.insert("status".to_string(), status.to_string());
    attrs.insert("latencia_ms".to_string(), latencia.to_string());
    (
        svc.to_string(),
        msg.into_bytes(),
        attrs,
        format!("sess-{:08x}", i / 1000),
    )
}

fn opts(
    kind: &str,
    session: String,
    attrs: HashMap<String, String>,
    idem: String,
) -> heraclitus_client::AppendOptions {
    heraclitus_client::AppendOptions {
        session_id: session,
        kind: kind.to_string(),
        hyp: vec![],
        attrs,
        parents: vec![],
        idempotency_key: idem,
    }
}

async fn ligar(server: &str, token: &Option<String>) -> anyhow::Result<heraclitus_client::Client> {
    let c = heraclitus_client::Client::connect(server.to_string()).await?;
    Ok(match token {
        Some(t) => c.with_bearer_token(t)?,
        None => c,
    })
}

async fn serial(
    server: &str,
    token: &Option<String>,
    n: u64,
    semente: u64,
    idem: bool,
) -> anyhow::Result<f64> {
    let mut cli = ligar(server, token).await?;
    let mut rng = Rng(semente);
    let t = Instant::now();
    for i in 0..n {
        let (svc, msg, attrs, sess) = evento(&mut rng, i);
        let chave = if idem {
            format!("probe-{semente:x}-{i}")
        } else {
            String::new()
        };
        cli.append(&svc, &msg, opts("Observation", sess, attrs, chave))
            .await?;
    }
    Ok(n as f64 / t.elapsed().as_secs_f64())
}

async fn concorrente(
    server: &str,
    token: &Option<String>,
    n: u64,
    conc: u64,
    semente: u64,
    idem: bool,
) -> anyhow::Result<f64> {
    let server = Arc::new(server.to_string());
    let token = Arc::new(token.clone());
    let t = Instant::now();
    let mut hs = Vec::new();
    for w in 0..conc {
        let server = server.clone();
        let token = token.clone();
        let quota = n / conc + u64::from(w < n % conc);
        hs.push(tokio::spawn(async move {
            let mut cli = ligar(&server, &token).await?;
            let mut rng = Rng(semente ^ w.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            for i in 0..quota {
                let (svc, msg, attrs, sess) = evento(&mut rng, i);
                let chave = if idem {
                    format!("probe-{semente:x}-{w}-{i}")
                } else {
                    String::new()
                };
                cli.append(&svc, &msg, opts("Observation", sess, attrs, chave))
                    .await?;
            }
            Ok::<(), anyhow::Error>(())
        }));
    }
    for h in hs {
        h.await??;
    }
    Ok(n as f64 / t.elapsed().as_secs_f64())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    println!("\n=== Sonda: custo do caminho gRPC por evento ===\n");
    println!("servidor : {}", cli.server);
    println!("eventos  : {} por modo\n", cli.n);

    let s1 = serial(&cli.server, &cli.token, cli.n, 0x1111, false).await?;
    println!("  1. serial      · 1 conexao   · sem chave  : {s1:>9.0} eventos/s");

    let s2 = concorrente(&cli.server, &cli.token, cli.n, cli.conc, 0x2222, false).await?;
    println!(
        "  2. concorrente · {:>2} conexoes · sem chave  : {s2:>9.0} eventos/s  ({:.1}x)",
        cli.conc,
        s2 / s1
    );

    let s3 = concorrente(&cli.server, &cli.token, cli.n, cli.conc, 0x3333, true).await?;
    println!(
        "  3. concorrente · {:>2} conexoes · COM chave  : {s3:>9.0} eventos/s  ({:.2}x vs 2)",
        cli.conc,
        s3 / s2
    );

    println!();
    println!("  Compare com o motor de escrita puro (bench carga_real_20m).");
    println!("  A diferenca e o imposto do servidor: round-trip unario por");
    println!("  evento, spawn_blocking por evento, e a releitura do disco em");
    println!("  engine.rs:1303 no caminho sem chave de idempotencia.\n");
    Ok(())
}
