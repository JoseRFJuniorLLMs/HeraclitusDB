//! heraclitus-service — runs the HeraclitusDB server as a Windows service.
//!
//! The same `heraclitus_server::serve` engine, but driven by the Windows
//! Service Control Manager (SCM) so it shows up under Task Manager → Services
//! and `services.msc`, survives logoff, and can auto-start at boot. Because a
//! service has no console, execution output is written to a rolling daily log
//! file instead of stdout.
//!
//! Subcommands (run from an elevated PowerShell):
//!   heraclitus-service install [config.toml]   register the service with SCM
//!   heraclitus-service uninstall               remove the service from SCM
//!   heraclitus-service console [config.toml]    run in the foreground (debug)
//!   heraclitus-service status                  print SCM state + log path
//! With no arguments it expects to be launched by SCM and starts the service
//! dispatcher.
//!
//! Paths default to %ProgramData%\HeraclitusDB (data, logs, cold tier) so the
//! service never writes into C:\Windows\System32 (the SCM working directory).

const SERVICE_NAME: &str = "HeraclitusDB";
const SERVICE_DISPLAY: &str = "HeraclitusDB Event-Sourced Memory";

#[cfg(windows)]
fn base_dir() -> std::path::PathBuf {
    let root = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"));
    root.join("HeraclitusDB")
}

#[cfg(windows)]
fn log_dir() -> std::path::PathBuf {
    std::env::var_os("HERACLITUS_LOG_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| base_dir().join("logs"))
}

/// Apply service-friendly defaults for any path env var the operator did not
/// set explicitly, so data lands under %ProgramData% rather than System32.
#[cfg(windows)]
fn apply_path_defaults() {
    let base = base_dir();
    if std::env::var_os("HERACLITUS_DATA_DIR").is_none() {
        std::env::set_var("HERACLITUS_DATA_DIR", base.join("data"));
    }
    // The service writes execution to a structured daily log file (and, in
    // console mode, to stdout too). Force the plain boot so the fancy console
    // sequence (spinner, ANSI, banner) never lands in the log; the standalone
    // `heraclitus-server` binary doesn't call this and keeps the pretty boot.
    if std::env::var_os("HERACLITUS_PLAIN_BOOT").is_none() {
        std::env::set_var("HERACLITUS_PLAIN_BOOT", "1");
    }
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arg = std::env::args().nth(1).unwrap_or_default();
    let config = std::env::args().nth(2).map(std::path::PathBuf::from);
    match arg.as_str() {
        "install" => service_ctl::install(config),
        "uninstall" | "remove" => service_ctl::uninstall(),
        "status" => service_ctl::status(),
        "console" | "run" => console::run(config),
        "" => {
            // No args: assume SCM launched us. Start the dispatcher; if that
            // fails because we were run from a console, explain how to use it.
            if let Err(e) = service_runner::start() {
                eprintln!("Não foi iniciado pelo SCM ({e}).\n");
                print_usage();
            }
            Ok(())
        }
        other => {
            eprintln!("Subcomando desconhecido: {other}\n");
            print_usage();
            Ok(())
        }
    }
}

#[cfg(windows)]
fn print_usage() {
    eprintln!(
        "heraclitus-service — HeraclitusDB como serviço do Windows\n\
         \n\
         Uso (PowerShell como Administrador):\n\
         \u{20}\u{20}heraclitus-service install [config.toml]   regista o serviço (auto-start)\n\
         \u{20}\u{20}heraclitus-service uninstall               remove o serviço\n\
         \u{20}\u{20}heraclitus-service console [config.toml]    corre em primeiro plano (debug)\n\
         \u{20}\u{20}heraclitus-service status                  mostra o estado e o log\n\
         \n\
         Depois de instalar:  Start-Service {SERVICE_NAME}\n\
         Log de execução em:  {}",
        log_dir().display()
    );
}

/// Foreground mode: identical engine, logs to both the file and stdout so the
/// operator can watch execution live before committing to the service.
#[cfg(windows)]
mod console {
    use heraclitus_core::HeraclitusConfig;

    pub fn run(config_path: Option<std::path::PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
        use tracing_subscriber::fmt::writer::MakeWriterExt;
        super::apply_path_defaults();
        let dir = super::log_dir();
        std::fs::create_dir_all(&dir)?;
        let appender = tracing_appender::rolling::daily(&dir, "heraclitus-service.log");
        let (file_writer, _guard) = tracing_appender::non_blocking(appender);
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(file_writer.and(std::io::stdout))
            .init();

        tracing::info!(service = super::SERVICE_NAME, mode = "console", "starting");
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async move {
            let config = HeraclitusConfig::load(config_path.as_deref())?;
            heraclitus_server::serve(config, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
        })?;
        tracing::info!("stopped");
        Ok(())
    }
}

/// SCM lifecycle: the dispatcher entry point and the service body that owns the
/// tokio runtime and bridges an SCM stop control into a graceful shutdown.
#[cfg(windows)]
mod service_runner {
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    use heraclitus_core::HeraclitusConfig;

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    define_windows_service!(ffi_service_main, service_main);

    pub fn start() -> windows_service::Result<()> {
        service_dispatcher::start(super::SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_args: Vec<OsString>) {
        // Logging must be live before anything can fail, so crashes are visible.
        super::apply_path_defaults();
        let dir = super::log_dir();
        let _ = std::fs::create_dir_all(&dir);
        let appender = tracing_appender::rolling::daily(&dir, "heraclitus-service.log");
        let (file_writer, _guard) = tracing_appender::non_blocking(appender);
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(file_writer)
            .init();

        if let Err(e) = run() {
            tracing::error!(error = %e, "service exited with error");
        }
    }

    fn run() -> Result<(), Box<dyn std::error::Error>> {
        // SCM delivers Stop/Preshutdown on its own thread; forward to the runtime.
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let event_handler = move |control| -> ServiceControlHandlerResult {
            match control {
                ServiceControl::Stop | ServiceControl::Preshutdown => {
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status_handle = service_control_handler::register(super::SERVICE_NAME, event_handler)?;

        let set_state = |state: ServiceState, accept: ServiceControlAccept, code: u32| {
            status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: state,
                controls_accepted: accept,
                exit_code: ServiceExitCode::Win32(code),
                checkpoint: 0,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            })
        };

        set_state(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
            0,
        )?;
        tracing::info!(service = super::SERVICE_NAME, "running");

        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(async move {
            let config = HeraclitusConfig::load(None)?;
            // Bridge the blocking stop channel into an async shutdown future.
            let (async_tx, async_rx) = tokio::sync::oneshot::channel::<()>();
            std::thread::spawn(move || {
                let _ = shutdown_rx.recv();
                let _ = async_tx.send(());
            });
            heraclitus_server::serve(config, async move {
                let _ = async_rx.await;
                tracing::info!("shutdown signal received");
            })
            .await
        });

        let exit_code = if let Err(e) = &result {
            tracing::error!(error = %e, "serve failed");
            1
        } else {
            0
        };
        set_state(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            exit_code,
        )?;
        tracing::info!("stopped");
        result.map_err(Into::into)
    }
}

/// install / uninstall / status against the SCM, so the operator never has to
/// hand-craft `sc.exe create` lines.
#[cfg(windows)]
mod service_ctl {
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    pub fn install(config: Option<std::path::PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let exe = std::env::current_exe()?;
        // If a config path is given, pass it so SCM launches `exe console <cfg>`?
        // No — SCM must launch the dispatcher (no args). A config file is honored
        // via the HERACLITUS_* env vars or the default; absolute config support
        // would need the service to read it, so we keep launch args empty and
        // document env-based config.
        let launch_arguments: Vec<OsString> = Vec::new();
        if let Some(c) = &config {
            eprintln!(
                "Nota: a config '{}' não é passada ao SCM. Configure via variáveis \
                 HERACLITUS_DATA_DIR / HERACLITUS_GRPC_ADDR / HERACLITUS_REST_ADDR \
                 (System environment) ou aceite os padrões em %ProgramData%\\HeraclitusDB.",
                c.display()
            );
        }
        let info = ServiceInfo {
            name: OsString::from(super::SERVICE_NAME),
            display_name: OsString::from(super::SERVICE_DISPLAY),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments,
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
        service.set_description(
            "HeraclitusDB — substrato de memória event-sourced (log imutável append-only). \
             gRPC :7474, REST :7475. Logs em %ProgramData%\\HeraclitusDB\\logs.",
        )?;
        println!(
            "Serviço '{}' instalado (auto-start).\n\
             Iniciar:  Start-Service {}\n\
             Estado :  Get-Service {}\n\
             Log    :  {}",
            super::SERVICE_NAME,
            super::SERVICE_NAME,
            super::SERVICE_NAME,
            super::log_dir().display()
        );
        Ok(())
    }

    pub fn uninstall() -> Result<(), Box<dyn std::error::Error>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(
            super::SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )?;
        let status = service.query_status()?;
        if status.current_state != ServiceState::Stopped {
            println!("A parar o serviço…");
            let _ = service.stop();
        }
        service.delete()?;
        println!("Serviço '{}' removido.", super::SERVICE_NAME);
        Ok(())
    }

    pub fn status() -> Result<(), Box<dyn std::error::Error>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        match manager.open_service(super::SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(service) => {
                let s = service.query_status()?;
                println!(
                    "Serviço '{}': {:?}\nLog: {}",
                    super::SERVICE_NAME,
                    s.current_state,
                    super::log_dir().display()
                );
            }
            Err(_) => println!(
                "Serviço '{}' não está instalado. Use: heraclitus-service install",
                super::SERVICE_NAME
            ),
        }
        Ok(())
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "heraclitus-service só faz sentido no Windows. \
         Noutros sistemas use heraclitus-server diretamente (ou systemd)."
    );
    std::process::exit(1);
}
