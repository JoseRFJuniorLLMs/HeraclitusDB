use heraclitus_core::HeraclitusConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable ANSI virtual-terminal + UTF-8 on the Windows console up front, so
    // both the boot sequence and the runtime tracing logs render with colour
    // instead of raw `←[2m…` escapes in the classic conhost.
    heraclitus_server::boot::enable_ansi();
    tracing_subscriber::fmt::init();
    let config_path = std::env::args().nth(1).map(std::path::PathBuf::from);
    let config = HeraclitusConfig::load(config_path.as_deref())?;
    heraclitus_server::serve(config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
