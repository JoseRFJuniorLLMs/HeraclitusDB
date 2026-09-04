use heraclitus_core::HeraclitusConfig;

// SPEC-0073 §20 — allocator global do EXECUTAVEL servidor.
//
// Fica AQUI e em mais lado nenhum. A §20 e explicita: "crates de biblioteca
// SHALL NOT definir allocator global". Quem embebe o motor noutro binario
// escolhe o seu, e um crate de biblioteca a impor jemalloc tirar-lhe-ia essa
// escolha sem o dizer.
//
// Experimental e OFF por default. A §21 exige um benchmark A/B (write-heavy,
// query-heavy, mixed, com Sentinel/HNSW/analytics ligados, 64+ clientes
// concorrentes) medindo throughput, p99, RSS, RSS de pico, fragmentacao,
// residente-apos-idle, CPU e alocacoes/s — e so permite promover a default "se
// houver ganho comprovado". Ligar por teoria e exactamente o que o invariante
// I-5 proibe, e ja aconteceu uma vez neste repositorio com o mmap: foi medido,
// perdeu, e ficou deliberadamente desligado.
//
// Para medir:  cargo build --release -p heraclitus-server --features linux-jemalloc
#[cfg(all(target_os = "linux", feature = "linux-jemalloc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable ANSI virtual-terminal + UTF-8 on the Windows console up front, so
    // both the boot sequence and the runtime tracing logs render with colour
    // instead of raw `←[2m…` escapes in the classic conhost.
    heraclitus_server::boot::enable_ansi();
    tracing_subscriber::fmt::init();
    let config_path = std::env::args().nth(1).map(std::path::PathBuf::from);
    let config = HeraclitusConfig::load(config_path.as_deref())?;
    heraclitus_server::serve(config, heraclitus_platform::wait_for_shutdown_signal()).await?;
    Ok(())
}
