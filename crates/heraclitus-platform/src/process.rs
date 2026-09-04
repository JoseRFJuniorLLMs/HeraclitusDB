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
/// Envia uma mensagem do protocolo `sd_notify` pelo `NOTIFY_SOCKET`.
///
/// O systemd pode entregar o socket de duas formas, e o código só tratava uma:
/// um caminho no sistema de ficheiros (`/run/systemd/notify`) ou um socket do
/// **namespace abstracto**, que o protocolo escreve com `@` à cabeça. Passar
/// essa string a `send_to` como caminho falha com `ENOENT`, e como o chamador
/// descarta o resultado o `READY=1` desaparecia em silêncio.
///
/// No namespace abstracto o primeiro byte do endereço é NUL, e é isso que
/// `SocketAddr::from_abstract_name` constrói.
#[cfg(target_os = "linux")]
fn sd_notify(mensagem: &[u8]) -> io::Result<bool> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    let Ok(destino) = std::env::var("NOTIFY_SOCKET") else {
        return Ok(false);
    };
    if destino.is_empty() {
        return Ok(false);
    }
    let socket = UnixDatagram::unbound()?;
    let enviados = if let Some(nome) = destino.strip_prefix('@') {
        let addr = SocketAddr::from_abstract_name(nome.as_bytes())?;
        socket.send_to_addr(mensagem, &addr)?
    } else {
        socket.send_to(mensagem, &destino)?
    };
    Ok(enviados > 0)
}

/// Implements the lightweight native protocol without linking against libsystemd.
pub fn notify_watchdog() -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        sd_notify(b"WATCHDOG=1")
    }
    #[cfg(not(target_os = "linux"))]
    Ok(false)
}

/// Pede ao systemd mais tempo para acabar o arranque (`EXTEND_TIMEOUT_USEC=`).
///
/// É o idioma correcto para uma recuperação cujo custo cresce com o tamanho da
/// base: em vez de escolher um `TimeoutStartSec` que há-de ficar pequeno, o
/// daemon renova o prazo enquanto vai progredindo. Cada chamada estende a
/// contagem a partir de agora, portanto tem de ser repetida durante o replay.
pub fn notify_extend_timeout(micros: u64) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        sd_notify(format!("EXTEND_TIMEOUT_USEC={micros}").as_bytes())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = micros;
        Ok(false)
    }
}

/// Notifies systemd that the daemon is ready to serve requests (READY=1).
pub fn notify_ready() -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        sd_notify(b"READY=1")
    }
    #[cfg(not(target_os = "linux"))]
    Ok(false)
}
