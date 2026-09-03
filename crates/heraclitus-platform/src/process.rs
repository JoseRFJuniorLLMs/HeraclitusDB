//! Process lifecycle, signal orchestration, and service manager integration.
//!
//! Handles asynchronous shutdown triggers (SIGINT, SIGTERM) across operating
//! systems and provides lightweight systemd notification primitives.

use std::io;

/// Waits for a process termination signal.
///
/// Under Linux and Unix systems, this listens for:
/// - SIGINT (interactive Ctrl+C in terminal)
/// - SIGTERM (sent by systemd systemctl stop or container runtimes)
///
/// Under Windows and non-Unix targets, this listens for Ctrl+C.
pub async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("recebido sinal de interrupção (Ctrl+C)");
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
                tracing::info!("recebido sinal SIGTERM (systemd / container shutdown)");
            }
            Err(e) => {
                tracing::error!(error = %e, "falha ao registrar listener de SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

/// Notifies systemd watchdog using the NOTIFY_SOCKET environment protocol.
///
/// Implements the lightweight native protocol without linking against libsystemd.
pub fn notify_watchdog() -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
            use std::os::unix::net::UnixDatagram;
            let socket = UnixDatagram::unbound()?;
            let bytes_sent = socket.send_to(b"WATCHDOG=1", socket_path)?;
            return Ok(bytes_sent > 0);
        }
    }
    Ok(false)
}

/// Notifies systemd that the daemon is ready to serve requests (READY=1).
pub fn notify_ready() -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
            use std::os::unix::net::UnixDatagram;
            let socket = UnixDatagram::unbound()?;
            let bytes_sent = socket.send_to(b"READY=1", socket_path)?;
            return Ok(bytes_sent > 0);
        }
    }
    Ok(false)
}
