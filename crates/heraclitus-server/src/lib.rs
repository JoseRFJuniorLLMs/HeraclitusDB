//! heraclitus-server — gRPC (tonic) + minimal REST (axum), §3.14.
//! The server composes; the storage knows nothing about HTTP or LLMs.

pub mod boot;
#[cfg(feature = "replication")]
pub mod cluster; // SPEC-015/021: wiring do consenso Raft (nó de cluster sobre o log)
pub mod embedded;
pub mod engine;
pub mod grpc;
#[cfg(feature = "analytics")]
pub mod flight_grpc; // SPEC-016: protocolo Arrow Flight real (gRPC, tonic 0.14)
pub mod rest;

pub use embedded::Embedded;
pub use engine::Engine;

use crate::boot::{group, Boot};
use heraclitus_core::{FsyncPolicy, HeraclitusConfig, HeraclitusError};
use heraclitus_proto::v1::heraclitus_server::HeraclitusServer;
use std::sync::Arc;
use tonic::{Request, Status};

/// Serve gRPC on `config.grpc_addr` and REST on `config.rest_addr` until
/// the provided shutdown future resolves.
// tonic's interceptor must return `Result<_, Status>` by value; `Status` is a
// large enum, so the `result_large_err` lint fires on the auth closure. Boxing
// is not an option (the trait signature is fixed by tonic), so allow it here.
#[allow(clippy::result_large_err)]
pub async fn serve(
    config: HeraclitusConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), HeraclitusError> {
    serve_with(config, shutdown, Boot::auto()).await
}

/// Like [`serve`], but with an explicit boot narrator. `serve` uses
/// [`Boot::auto`] (a pretty console boot on a TTY, plain `tracing` otherwise);
/// pass [`Boot::silent`] to suppress the startup narration entirely.
#[allow(clippy::result_large_err)]
pub async fn serve_with(
    config: HeraclitusConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    boot: Boot,
) -> Result<(), HeraclitusError> {
    boot.banner(env!("CARGO_PKG_VERSION"));
    let fsync = match &config.fsync {
        FsyncPolicy::Always => "fsync sempre (durabilidade máxima)".to_string(),
        FsyncPolicy::GroupCommit { interval_ms } => format!("group-commit a cada {interval_ms}ms"),
    };
    boot.info_line("Dados", &config.data_dir.display().to_string());
    boot.info_line("Durabilidade", &fsync);
    boot.info_line(
        "Memtable",
        &format!("{} eventos", group(config.memtable_cap as u64)),
    );

    let engine = Arc::new(Engine::open_with_boot(&config, &boot)?);

    // SPEC-015/021 — replicação por consenso Raft (opt-in). Quando configurada,
    // o nó junta-se/forma o cluster e as escritas passam a ir pelo líder.
    #[cfg(feature = "replication")]
    let cluster_tasks = if let Some(rep) = config.replication.clone() {
        match cluster::spawn(&engine, &rep, &config.data_dir).await {
            Ok((handle, tasks)) => {
                engine.set_replication(handle);
                boot.warn_line(
                    "Replicação Raft",
                    &format!(
                        "nó {} · TCP {} · {} membros{}",
                        rep.node_id,
                        rep.raft_addr,
                        rep.peers.len(),
                        if rep.bootstrap { " · semente" } else { "" }
                    ),
                );
                Some(tasks)
            }
            Err(e) => {
                boot.warn_line("Replicação Raft", &format!("falhou a arrancar: {e}"));
                None
            }
        }
    } else {
        None
    };

    let grpc_addr: std::net::SocketAddr = config
        .grpc_addr
        .parse()
        .map_err(|e| HeraclitusError::Config(format!("grpc_addr: {e}")))?;
    let rest_addr: std::net::SocketAddr = config
        .rest_addr
        .parse()
        .map_err(|e| HeraclitusError::Config(format!("rest_addr: {e}")))?;

    // Authentication (§access control): when `auth_token` is set, every gRPC
    // call must carry `authorization: Bearer <token>`. When unset, the
    // interceptor is a no-op (default — backward compatible, localhost bind).
    let expected_auth = config.auth_token.clone().map(|t| format!("Bearer {t}"));
    if expected_auth.is_some() {
        boot.warn_line("Auth gRPC", "Bearer token EXIGIDO em cada chamada");
    } else if !grpc_addr.ip().is_loopback() {
        // Mesma política da superfície REST: o gRPC inclui ESCRITAS duráveis
        // (append) e admin destrutivo (shred, rebuild). Sem auth_token, o
        // interceptor é no-op — recusar expor isso fora do loopback.
        return Err(HeraclitusError::Config(format!(
            "grpc_addr {grpc_addr} não é loopback mas auth_token não está definido — \
             append/shred/rebuild ficariam abertos. Defina auth_token ou use 127.0.0.1."
        )));
    }
    let auth = move |req: Request<()>| -> Result<Request<()>, Status> {
        match &expected_auth {
            None => Ok(req),
            Some(exp) => {
                // R17: comparação constant-time (sem side-channel de timing).
                let ok = req
                    .metadata()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| rest::ct_eq(v.as_bytes(), exp.as_bytes()))
                    .unwrap_or(false);
                if ok {
                    Ok(req)
                } else {
                    Err(Status::unauthenticated("missing or invalid bearer token"))
                }
            }
        }
    };
    let svc = HeraclitusServer::with_interceptor(grpc::Service::new(engine.clone()), auth);
    if config.rest_basic_auth.is_some() {
        boot.warn_line("Auth REST", "HTTP Basic EXIGIDO em cada chamada");
    } else if !rest_addr.ip().is_loopback() {
        // A superfície REST inclui ESCRITAS duráveis (/hvm/*, /tier/demote, /sql).
        // Recusar expô-las sem autenticação num endereço não-loopback.
        return Err(HeraclitusError::Config(format!(
            "rest_addr {rest_addr} não é loopback mas rest_basic_auth não está definido — \
             as rotas de escrita ficariam abertas. Defina rest_basic_auth ou use 127.0.0.1."
        )));
    } else {
        boot.warn_line("Auth REST", "sem auth (loopback) — escritas locais /hvm//tier/sql abertas");
    }
    let rest = rest::router(engine.clone(), config.rest_basic_auth.clone());

    let rest_listener = tokio::net::TcpListener::bind(rest_addr).await?;
    boot.ok_line("Servidor REST (axum)", &format!("http://{rest_addr}"));
    let rest_task = tokio::spawn(async move {
        let _ = axum::serve(rest_listener, rest).await;
    });

    // Checkpoint PERIÓDICO das views (fast boot): limita a cauda que um boot
    // pós-crash tem de replayar — sem isto só havia checkpoint no arranque e
    // no shutdown gracioso. Nunca no caminho de escrita (spawn_blocking).
    let checkpoint_task = if config.checkpoint_interval_secs > 0 {
        let engine_ck = engine.clone();
        let every = std::time::Duration::from_secs(config.checkpoint_interval_secs);
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // o primeiro tick dispara já; salta-o (o boot acabou de checkpointar)
            loop {
                tick.tick().await;
                let e = engine_ck.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(err) = e.checkpoint_views() {
                        tracing::warn!(error = %err, "checkpoint periódico falhou (próximo boot replaya mais cauda)");
                    }
                })
                .await;
            }
        }))
    } else {
        None
    };

    // SPEC-027 — telemetria endógena: os vitais do motor entram no PRÓPRIO log
    // como episódios `SystemMetric` (opt-in via telemetry_interval_secs > 0),
    // consultáveis por GQL. Nunca no caminho de escrita do cliente.
    let telemetry_task = if config.telemetry_interval_secs > 0 {
        let engine_tl = engine.clone();
        let every = std::time::Duration::from_secs(config.telemetry_interval_secs);
        boot.warn_line(
            "Telemetria endógena",
            &format!("SystemMetric a cada {}s", config.telemetry_interval_secs),
        );
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // primeiro tick dispara já; salta-o
            loop {
                tick.tick().await;
                let e = engine_tl.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(err) = e.emit_telemetry() {
                        tracing::warn!(error = %err, "telemetria endógena falhou neste tick");
                    }
                })
                .await;
            }
        }))
    } else {
        None
    };

    // C2.6 — task de compaction do cold tier (feature `tier`, opt-in via
    // tier_compaction_interval_secs > 0). A cada tick, segmentos demotados com
    // fração de tombstones acima da CompactionPolicy são reescritos sem eles.
    // Nunca sob replicação (o object store é local ao nó) e nunca no caminho
    // de escrita do cliente.
    #[cfg(feature = "tier")]
    let tier_compaction_task = if config.tier_compaction_interval_secs > 0 {
        let engine_tc = engine.clone();
        let every = std::time::Duration::from_secs(config.tier_compaction_interval_secs);
        boot.warn_line(
            "Compaction do cold tier",
            &format!("tick a cada {}s", config.tier_compaction_interval_secs),
        );
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // primeiro tick dispara já; salta-o
            let policy = heraclitus_tier::CompactionPolicy::default();
            loop {
                tick.tick().await;
                if engine_tc.is_replicated() {
                    continue; // objetos cold são locais ao nó — não compactar em cluster
                }
                match engine_tc.tier_compaction_tick(&policy).await {
                    Ok(rs) if !rs.is_empty() => {
                        for r in rs {
                            tracing::info!(
                                segment = r.segment_id,
                                dropped = r.dropped,
                                kept = r.record_count,
                                "tier: segmento cold compactado (novo recibo Merkle)"
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "tier: tick de compaction falhou")
                    }
                }
            }
        }))
    } else {
        None
    };

    // §3.9 — task de consolidação (distill, feature `distill`, opt-in via
    // distill_interval_secs > 0). A cada tick agrupa os episódios novos e
    // emite Facts no log via Engine::append. Nunca sob replicação (cursor
    // local ao nó, v0) e nunca no caminho de escrita do cliente.
    #[cfg(feature = "distill")]
    let distill_task = if config.distill_interval_secs > 0 {
        let engine_ds = engine.clone();
        let every = std::time::Duration::from_secs(config.distill_interval_secs);
        boot.warn_line(
            "Consolidação (distill)",
            &format!("tick a cada {}s", config.distill_interval_secs),
        );
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // primeiro tick dispara já; salta-o
            let cfg = heraclitus_distill::DistillConfig::default();
            loop {
                tick.tick().await;
                if engine_ds.is_replicated() {
                    continue; // v0: cursor local ao nó — não consolidar em cluster
                }
                let e = engine_ds.clone();
                let cfg = cfg.clone();
                let _ = tokio::task::spawn_blocking(move || match e.distill_tick(&cfg) {
                    Ok(lsns) if !lsns.is_empty() => {
                        tracing::info!(facts = lsns.len(), "distill: novos Facts consolidados")
                    }
                    Ok(_) => {}
                    Err(err) => tracing::warn!(error = %err, "distill: tick falhou"),
                })
                .await;
            }
        }))
    } else {
        None
    };

    // SPEC-016 — servidor Arrow Flight (gRPC, tonic 0.14, listener próprio).
    // Opt-in via flight_addr; só existe com a feature `analytics`.
    #[cfg(feature = "analytics")]
    let flight_task = if let Some(addr) = config.flight_addr.clone() {
        // O Flight serve o LOG INTEIRO via DoGet e (ainda) não tem qualquer
        // autenticação — a única postura segura é loopback-only, como nas
        // outras superfícies sem auth.
        let flight_sock: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| HeraclitusError::Config(format!("flight_addr: {e}")))?;
        if !flight_sock.ip().is_loopback() {
            return Err(HeraclitusError::Config(format!(
                "flight_addr {flight_sock} não é loopback mas o Flight não tem autenticação — \
                 o log inteiro ficaria legível. Use 127.0.0.1."
            )));
        }
        match flight_grpc::serve_flight(engine.log.clone(), &addr).await {
            Ok((local, handle)) => {
                boot.ok_line("Arrow Flight (gRPC)", &format!("grpc://{local}"));
                Some(handle)
            }
            Err(e) => {
                boot.warn_line("Arrow Flight", &format!("falhou a arrancar: {e}"));
                None
            }
        }
    } else {
        None
    };

    // Compliance daemon (RFC 3161 watermark timestamping). Off by default; never
    // on the append path. Receipts under `<data_dir>/receipts`.
    let compliance_task = if config.compliance_enabled {
        use heraclitus_compliance::{run_worker, HttpTsa, LocalTsa, TsaClient, WorkerConfig};
        use std::time::Duration;
        let tsa: std::sync::Arc<dyn TsaClient + Send + Sync> =
            if config.compliance_tsa_mode.eq_ignore_ascii_case("http") {
                std::sync::Arc::new(HttpTsa::new(
                    config.compliance_tsa_url.clone(),
                    config.compliance_tsa_policy.clone(),
                ))
            } else {
                std::sync::Arc::new(LocalTsa::generate(config.compliance_tsa_policy.clone()))
            };
        let wcfg = WorkerConfig::new(
            Duration::from_secs(config.compliance_interval_secs.max(1)),
            config.compliance_min_lsn_step,
            config.data_dir.join("receipts"),
        );
        boot.warn_line(
            "Compliance RFC 3161",
            &format!(
                "carimbo de tempo ATIVO · modo {}",
                config.compliance_tsa_mode
            ),
        );
        let log = engine.log.clone();
        Some(tokio::spawn(run_worker(
            log,
            tsa,
            wcfg,
            std::future::pending::<()>(),
        )))
    } else {
        None
    };

    boot.ok_line("Servidor gRPC (tonic)", &grpc_addr.to_string());
    boot.ready(&grpc_addr.to_string(), &rest_addr.to_string());
    tonic::transport::Server::builder()
        .add_service(svc)
        .serve_with_shutdown(grpc_addr, shutdown)
        .await
        .map_err(|e| HeraclitusError::Config(format!("grpc serve: {e}")))?;
    rest_task.abort();
    if let Some(t) = compliance_task {
        t.abort();
    }
    if let Some(t) = checkpoint_task {
        t.abort();
    }
    if let Some(t) = telemetry_task {
        t.abort();
    }
    #[cfg(feature = "analytics")]
    if let Some(t) = flight_task {
        t.abort();
    }
    #[cfg(feature = "tier")]
    if let Some(t) = tier_compaction_task {
        t.abort();
    }
    #[cfg(feature = "distill")]
    if let Some(t) = distill_task {
        t.abort();
    }
    #[cfg(feature = "replication")]
    if let Some(t) = cluster_tasks {
        t.abort();
    }
    // Shutdown gracioso = checkpoint das views (fast boot): o próximo arranque
    // restaura os snapshots e replaya só a cauda. Falhar aqui não pode impedir
    // o encerramento — sem checkpoint, o boot cai no replay (mais lento, correto).
    if let Err(e) = engine.checkpoint_views() {
        tracing::warn!(error = %e, "checkpoint das views no shutdown falhou (boot seguinte replaya)");
    }
    Ok(())
}
