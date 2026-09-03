//! heraclitus-server — gRPC (tonic) + minimal REST (axum), §3.14.
//! The server composes; the storage knows nothing about HTTP or LLMs.

mod auth;
pub mod boot;
#[cfg(feature = "replication")]
pub mod cluster; // SPEC-015/021: wiring do consenso Raft (nó de cluster sobre o log)
pub mod embedded;
pub mod engine;
#[cfg(feature = "analytics")]
pub mod flight_grpc; // SPEC-016: protocolo Arrow Flight real (gRPC, tonic 0.14)
pub mod grpc;
pub mod rest;

pub use embedded::Embedded;
pub use engine::Engine;

use crate::boot::{group, Boot};
use heraclitus_core::{FsyncPolicy, HeraclitusConfig, HeraclitusError};
use heraclitus_proto::v1::heraclitus_server::HeraclitusServer;
use std::sync::Arc;

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
    // `HeraclitusConfig` também pode ser construído diretamente por embedding
    // (sem `load`); os gates de segurança precisam valer nos dois caminhos.
    config.validate_security()?;
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
    boot.info_line(
        "Plataforma",
        &heraclitus_platform::detect_capabilities().summary_line(),
    );

    let engine = Arc::new(Engine::open_with_boot(&config, &boot)?);

    // SPEC-015/021 — replicação por consenso Raft (opt-in). Quando configurada,
    // o nó junta-se/forma o cluster e as escritas passam a ir pelo líder.
    #[cfg(feature = "replication")]
    let mut sentinel_ownership: Option<Arc<dyn heraclitus_sentinel::LeaderOwnership>> = None;
    #[cfg(not(feature = "replication"))]
    let sentinel_ownership: Option<Arc<dyn heraclitus_sentinel::LeaderOwnership>> = None;
    #[cfg(feature = "replication")]
    let cluster_tasks = if let Some(rep) = config.replication.clone() {
        match cluster::spawn(&engine, &rep, &config.data_dir).await {
            Ok((handle, tasks)) => {
                sentinel_ownership = Some(handle.clone());
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

    // SPEC-0045 — derived writes go through Engine rather than AnyLog, keeping
    // live indexes coherent. In a Raft cluster every replica may maintain L0-L3
    // views, while the shared epoch gate permits only the current leader to
    // investigate, approve, or execute response actions.
    let sentinel_runtime = if config.replication.is_some()
        && config.sentinel.enabled
        && sentinel_ownership.is_none()
    {
        boot.warn_line(
            "Heraclitus Sentinel",
            "não iniciou em modo replicado; ownership Raft indisponível",
        );
        None
    } else {
        match heraclitus_sentinel::SentinelRuntime::start_with_sink_and_ownership(
            engine.log.clone(),
            engine.clone(),
            config.sentinel.clone(),
            sentinel_ownership,
        ) {
            Ok(Some(runtime)) => {
                boot.ok_line(
                    "Heraclitus Sentinel",
                    &format!(
                        "L0{}{}{} ativo(s) · modo {:?} · fila {} · {} worker(s)",
                        if config.sentinel.l1.enabled {
                            "/L1"
                        } else {
                            ""
                        },
                        if config.sentinel.l2.enabled {
                            "/L2"
                        } else {
                            ""
                        },
                        if config.sentinel.l3.enabled {
                            "/L3"
                        } else {
                            ""
                        },
                        config.sentinel.mode,
                        config.sentinel.queue_capacity,
                        config.sentinel.worker_threads
                    ),
                );
                Some(Arc::new(runtime))
            }
            Ok(None) => None,
            Err(error) => {
                boot.warn_line(
                    "Heraclitus Sentinel",
                    &format!("não iniciou; o banco continua disponível: {error}"),
                );
                None
            }
        }
    };

    let grpc_addr: std::net::SocketAddr = config
        .grpc_addr
        .parse()
        .map_err(|e| HeraclitusError::Config(format!("grpc_addr: {e}")))?;
    let rest_addr: std::net::SocketAddr = config
        .rest_addr
        .parse()
        .map_err(|e| HeraclitusError::Config(format!("rest_addr: {e}")))?;

    // Autenticação multi-principal: tokens nunca ficam armazenados em claro;
    // cada request é associado a um Principal que os handlers autorizam por papel.
    let authenticator = auth::Authenticator::from_config(&config)?;
    if authenticator.is_required() {
        boot.warn_line(
            "Auth gRPC",
            &format!(
                "Bearer + RBAC EXIGIDO · {} principal(is)",
                config.access_credentials.len() + usize::from(config.auth_token.is_some())
            ),
        );
    } else if !grpc_addr.ip().is_loopback() {
        // Mesma política da superfície REST: o gRPC inclui ESCRITAS duráveis
        // (append) e admin destrutivo (shred, rebuild). Sem auth_token, o
        // interceptor é no-op — recusar expor isso fora do loopback.
        return Err(HeraclitusError::Config(format!(
            "grpc_addr {grpc_addr} não é loopback mas auth_token não está definido — \
             append/shred/rebuild ficariam abertos. Defina auth_token ou use 127.0.0.1."
        )));
    } else {
        // O caso que faltava dizer em voz alta. Sem credenciais, o interceptor
        // NAO e um no-op benigno: `Authenticator::authenticate` injecta um
        // Principal com `AccessRole::Admin` em TODAS as chamadas (auth.rs). O
        // loopback e a unica coisa entre isso e a rede — e quem conseguir
        // qualquer execucao local, ou um proxy mal configurado, e Admin.
        //
        // As outras duas hipoteses imprimem uma linha; esta imprimia zero, que
        // e exactamente ao contrario do que a gravidade pede.
        boot.warn_line(
            "Auth gRPC",
            &format!(
                "SEM AUTENTICACAO · {grpc_addr} · TODAS as chamadas correm como \n                 Admin (append/shred/rebuild) — so o loopback protege"
            ),
        );
    }
    let auth = move |req| authenticator.authenticate(req);
    let svc = HeraclitusServer::with_interceptor(
        grpc::Service::new_with_sentinel(engine.clone(), sentinel_runtime.clone()),
        auth,
    );
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
        boot.warn_line(
            "Auth REST",
            "sem auth (loopback) — escritas locais /hvm//tier/sql abertas",
        );
    }
    let rest = rest::router_with_sentinel(
        engine.clone(),
        sentinel_runtime.clone(),
        config.rest_basic_auth.clone(),
        config.rest_cors_origins.clone(),
        config.rest_allow_erasure,
    );

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
        let sentinel_ck = sentinel_runtime.clone();
        let every = std::time::Duration::from_secs(config.checkpoint_interval_secs);
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // o primeiro tick dispara já; salta-o (o boot acabou de checkpointar)
            loop {
                tick.tick().await;
                let e = engine_ck.clone();
                let sentinel = sentinel_ck.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(err) = e.checkpoint_views() {
                        tracing::warn!(error = %err, "checkpoint periódico falhou (próximo boot replaya mais cauda)");
                    }
                    if let Some(runtime) = sentinel {
                        if let Err(err) = runtime.checkpoint() {
                            tracing::warn!(error = %err, "checkpoint do Sentinel falhou (próximo boot replaya a cauda)");
                        }
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

    // SPEC-0050 Fase 2 — packing RAW→PACKED em background. A implementação
    // desloca compressão/fsync para `spawn_blocking` e só toma o mutex do
    // writer durante o publish curto do HRKM; append nunca espera por Zstd.
    let v6_packing_task = if config.storage_format == heraclitus_core::StorageFormat::V6
        && config.v6_packing_interval_secs > 0
    {
        let log = engine.log.v6_arc().ok_or_else(|| {
            HeraclitusError::StorageEngine(
                "configuração v6 abriu um backend que não é V6Log".into(),
            )
        })?;
        let every = std::time::Duration::from_secs(config.v6_packing_interval_secs);
        boot.ok_line(
            "Packer HRKL v6",
            &format!("background a cada {}s", config.v6_packing_interval_secs),
        );
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                match log
                    .clone()
                    .pack_pending_async(heraclitus_log::v6::PackingProfile::Balanced)
                    .await
                {
                    Ok(outcomes) => {
                        for outcome in outcomes {
                            tracing::info!(
                                segment = outcome.receipt.segment_id,
                                records = outcome.stats.record_count,
                                blocks = outcome.stats.block_count,
                                physical_bytes = outcome.stats.physical_size,
                                compression_ratio = outcome.stats.compression_ratio(),
                                "packing HRKL v6 publicado"
                            );
                        }
                    }
                    Err(err) => tracing::warn!(error = %err, "packing HRKL v6 falhou"),
                }
            }
        }))
    } else {
        None
    };

    // SPEC-0050 §90–§97 — GC de gerações físicas.
    //
    // Até 2026-08-29 o `plan_gc`/`commit_gc` não tinham chamador nenhum: a
    // política estava escrita, testada e com injecção de crash, e nunca corria.
    // O efeito era invisível e caro — o `record_pack` marca a geração RAW como
    // `Superseded` e nada a removia, portanto cada banco guardava RAW **e**
    // PACKED de tudo, para sempre.
    let v6_gc_task = if config.storage_format == heraclitus_core::StorageFormat::V6
        && config.v6_gc_interval_secs > 0
    {
        let log = engine.log.v6_arc().ok_or_else(|| {
            HeraclitusError::StorageEngine(
                "configuração v6 abriu um backend que não é V6Log".into(),
            )
        })?;
        // O mesmo log visto como `AnyLog`, que e o que o motor regulatorio
        // aceita: a reconciliacao de §94 corre neste mesmo ciclo.
        let log_regulatorio = engine.log.clone();
        // SPEC-0046 §94 — reconciliar TAMBEM no arranque, e nao so antes de
        // cada GC. O bit `legal_hold` vive no HRKM; os holds vivem no log. Um
        // restauro de manifesto, uma migracao, ou um arranque sobre um HRKM
        // mais antigo que o log deixam os dois a discordar — e quem perde e o
        // hold, porque o default de `RetentionPolicy` e `legal_hold: false`.
        // O log e a autoridade; o HRKM e derivado. Reconciliar aqui repoe essa
        // ordem antes de a primeira passagem de GC sequer poder correr.
        match heraclitus_compliance::RegulatoryPolicyEngine::new(log_regulatorio.clone())
            .reconcile_legal_holds()
        {
            Ok(0) => {}
            Ok(marcados) => boot.ok_line(
                "Legal holds (§94)",
                &format!("{marcados} segmento(s) reconciliado(s) a partir do log"),
            ),
            Err(error) => boot.warn_line(
                "Legal holds (§94)",
                &format!("reconciliação falhou no arranque: {error}"),
            ),
        }
        let every = std::time::Duration::from_secs(config.v6_gc_interval_secs);
        let opts = heraclitus_log::v6::GcRunOptions {
            keep_manifests: config.v6_gc_keep_manifests,
            // §127: uma passagem automática NUNCA coleta quarentena. Isso é um
            // pedido explícito de um operador que sabe que está a destruir
            // evidência.
            collect_quarantined: false,
        };
        match log.gc_reclaimable_bytes() {
            Ok(bytes) if bytes > 0 => boot.ok_line(
                "GC HRKL v6",
                &format!(
                    "background a cada {}s; {} recuperáveis agora",
                    config.v6_gc_interval_secs,
                    human_bytes(bytes)
                ),
            ),
            _ => boot.ok_line(
                "GC HRKL v6",
                &format!("background a cada {}s", config.v6_gc_interval_secs),
            ),
        }
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                // SPEC-0046 §94 — reconciliar ANTES de coletar, e nao por
                // simetria: o `set_legal_hold_range` so marca os segmentos que
                // existiam no momento em que o hold foi colocado. Um segmento
                // selado DEPOIS disso, dentro do mesmo intervalo de LSN, fica
                // sem o bit no HRKM e o GC coletava-o — apagando prova sob
                // retencao judicial sem nada o assinalar.
                //
                // A janela era teorica enquanto nada em producao conseguia
                // colocar um hold. Deixou de ser quando o RPC `admin` passou a
                // conseguir. Reconciliar aqui e barato (le o estado por replay
                // e carimba os segmentos em falta) e fecha-a.
                //
                // Uma falha na reconciliacao SALTA a coleta desta passagem: e a
                // ordem fail-closed. Coletar com holds possivelmente por
                // aplicar seria trocar prova por espaco em disco.
                let reconciliado = {
                    let gc_log = log_regulatorio.clone();
                    tokio::task::spawn_blocking(move || {
                        heraclitus_compliance::RegulatoryPolicyEngine::new(gc_log)
                            .reconcile_legal_holds()
                    })
                    .await
                };
                match reconciliado {
                    Ok(Ok(marcados)) => {
                        if marcados > 0 {
                            tracing::info!(
                                segmentos = marcados,
                                "legal holds reconciliados antes do GC"
                            );
                        }
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(
                            error = %error,
                            "reconciliacao de legal holds falhou: GC adiado nesta passagem"
                        );
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "worker de reconciliacao de legal holds falhou: GC adiado"
                        );
                        continue;
                    }
                }
                match log.clone().collect_garbage_async(opts).await {
                    Ok(execution) => {
                        // A esmagadora maioria das passagens não encontra nada;
                        // registá-las encheria o log de ruído e escondia as que
                        // interessam.
                        if !execution.removed.is_empty()
                            || !execution.orphaned.is_empty()
                            || !execution.cold_detached.is_empty()
                        {
                            tracing::info!(
                                manifest_generation = execution.manifest_generation,
                                removed = execution.removed.len(),
                                orphaned = execution.orphaned.len(),
                                cold_detached = execution.cold_detached.len(),
                                lakehouse_detached = execution.lakehouse_detached.len(),
                                "GC HRKL v6"
                            );
                        }
                        // §176/§82 — o que este GC desligou do HRKM mas não pode
                        // apagar. Reportar a dívida é honesto; fingir a remoção
                        // não é, e um objecto vivo num bucket contado como
                        // removido é espaço que ninguém volta a procurar.
                        for location in &execution.cold_detached {
                            tracing::warn!(
                                location = %location,
                                "geração fria desligada do HRKM: os bytes ficam no object store até o tier os coletar"
                            );
                        }
                        for location in &execution.lakehouse_detached {
                            tracing::warn!(
                                location = %location,
                                "projecção lakehouse desligada do HRKM: a remoção é das regras do lakehouse (§176)"
                            );
                        }
                    }
                    Err(err) => tracing::warn!(error = %err, "GC HRKL v6 falhou"),
                }
            }
        }))
    } else {
        if config.storage_format == heraclitus_core::StorageFormat::V6 {
            // Desligado é uma escolha legítima — mas tem de ser uma escolha
            // informada, e o número é o que a torna informada.
            let detalhe = match engine.log.v6_arc().map(|l| l.gc_reclaimable_bytes()) {
                Some(Ok(bytes)) if bytes > 0 => format!(
                    "DESLIGADO (v6_gc_interval_secs = 0): {} de gerações superseded ficam em disco",
                    human_bytes(bytes)
                ),
                _ => "DESLIGADO (v6_gc_interval_secs = 0)".to_string(),
            };
            boot.warn_line("GC HRKL v6", &detalhe);
        }
        None
    };

    // SPEC-0050 Fase 4 — a fila nasce do HRKM e sobrevive a restart. Sidecar
    // ausente/corrompido só custa pruning; o worker reconstrói-o depois do
    // packing e nunca bloqueia append.
    let v6_hrki_task = if config.storage_format == heraclitus_core::StorageFormat::V6
        && config.v6_hrki_interval_secs > 0
    {
        let log = engine.log.v6_arc().ok_or_else(|| {
            HeraclitusError::StorageEngine(
                "configuração v6 abriu um backend que não é V6Log".into(),
            )
        })?;
        let mut policy = heraclitus_log::v6::hrki::IndexPolicySet::new();
        if config.v6_hrki_index_agent_id {
            policy = policy.com(
                "agent_id",
                heraclitus_log::v6::hrki::IndexPolicy::PublicTechnical,
            );
        }
        if config.v6_hrki_index_session_id {
            policy = policy.com(
                "session_id",
                heraclitus_log::v6::hrki::IndexPolicy::PublicTechnical,
            );
        }
        let fpr = config.v6_hrki_bloom_fpr;
        let every = std::time::Duration::from_secs(config.v6_hrki_interval_secs);
        boot.ok_line(
            "HRKI v6",
            &format!(
                "background a cada {}s; Bloom FPR {}",
                config.v6_hrki_interval_secs, fpr
            ),
        );
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                match log
                    .clone()
                    .build_pending_hrki_async(policy.clone(), None, fpr)
                    .await
                {
                    Ok(outcomes) => {
                        for outcome in outcomes {
                            tracing::info!(
                                segment = outcome.segment_id,
                                generation = outcome.generation,
                                bytes = outcome.size,
                                path = %outcome.path.display(),
                                "sidecar HRKI publicado"
                            );
                        }
                    }
                    Err(err) => tracing::warn!(error = %err, "reconstrução HRKI falhou"),
                }
            }
        }))
    } else {
        None
    };

    // SPEC-0050 Fase 6 — projecção lakehouse em background.
    //
    // É a prioridade mais baixa do trabalho de fundo (§147): a fila nasce do
    // HRKM, um segmento só entra nela depois de selado E empacotado, e falhar
    // aqui nunca toca no caminho de escrita — §209 exige exactamente isso.
    // Fica atrás da feature `tier` porque é lá que Parquet/Iceberg/Delta e o
    // `object_store` vivem; o log continua a não os conhecer.
    #[cfg(feature = "tier")]
    let v6_lakehouse_task = if config.storage_format == heraclitus_core::StorageFormat::V6
        && config.v6_lakehouse_interval_secs > 0
    {
        let log = engine.log.v6_arc().ok_or_else(|| {
            HeraclitusError::StorageEngine(
                "configuração v6 abriu um backend que não é V6Log".into(),
            )
        })?;
        // O destino tem de estar utilizável ANTES de o servidor declarar a
        // task viva. Descobrir no primeiro tick que o caminho não existe daria
        // um servidor que anuncia exportação e nunca exporta.
        let destino = config.v6_lakehouse_path.clone();
        if let Some(pai) = std::path::Path::new(&destino).parent() {
            if !destino.contains("://") && !pai.as_os_str().is_empty() {
                std::fs::create_dir_all(&destino)?;
            }
        }
        let worker = heraclitus_tier::LakehouseWorker::open_location(
            &destino,
            config.v6_lakehouse_table.clone(),
            log.manifest().storage_namespace_id,
        )?;
        let every = std::time::Duration::from_secs(config.v6_lakehouse_interval_secs);
        boot.ok_line(
            "Lakehouse v6",
            &format!(
                "background a cada {}s; tabela `{}` em {}",
                config.v6_lakehouse_interval_secs, config.v6_lakehouse_table, destino
            ),
        );
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                match worker.export_pending(&log).await {
                    Ok(saidas) => {
                        for saida in saidas {
                            tracing::info!(
                                segment = saida.segment_id,
                                generation = saida.generation,
                                rows = saida.rows,
                                bytes = saida.size,
                                delta_version = ?saida.delta_version,
                                attached = saida.attached,
                                path = %saida.path,
                                "projecção lakehouse publicada"
                            );
                        }
                    }
                    Err(err) => tracing::warn!(error = %err, "exportação lakehouse falhou"),
                }
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
    let tier_compaction_task = if config.tier_compaction_interval_secs > 0
        && config.storage_format != heraclitus_core::StorageFormat::V6
    {
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
    // (a guarda de soberania vive em `instalar_guarda_de_soberania`, abaixo)
    let compliance_task = if config.compliance_enabled {
        use heraclitus_compliance::icp::TimestampValidationPolicy;
        use heraclitus_compliance::secure_tsa::{SecureTsaClient, TlsPolicy};
        use heraclitus_compliance::trust_store::TrustStore;
        use heraclitus_compliance::{run_worker, HttpTsa, LocalTsa, TsaClient, WorkerConfig};
        use std::time::Duration;

        let modo = config.compliance_tsa_mode.to_ascii_lowercase();
        let (tsa, evidence_status): (std::sync::Arc<dyn TsaClient + Send + Sync>, String) =
            match modo.as_str() {
                // SPEC-0046 §10/§11 — o caminho de produção.
                "https" => {
                    let dir = config.compliance_trust_store_dir.as_ref().ok_or_else(|| {
                        HeraclitusError::Config(
                            "compliance_tsa_mode=https exige HERACLITUS_COMPLIANCE_TRUST_STORE com as âncoras do órgão (§11)"
                                .into(),
                        )
                    })?;
                    let (store, relatorio) = TrustStore::load_dir(dir)
                        .map_err(|e| HeraclitusError::Config(format!("trust store: {e}")))?;
                    // Arrancar com o trust store vazio daria um servidor que
                    // aceita carimbos que ninguém autenticou e os grava como
                    // recibos. Recusar arrancar é a resposta certa: a falha é de
                    // configuração e tem correcção óbvia.
                    if store.is_empty() {
                        return Err(HeraclitusError::Config(format!(
                            "trust store `{}` sem âncoras utilizáveis ({} ficheiro(s) vistos, {} recusado(s)): sem âncoras não há ACT a autenticar",
                            dir.display(),
                            relatorio.files_seen,
                            relatorio.files_seen.saturating_sub(store.len())
                        )));
                    }
                    boot.ok_line(
                        "Trust store",
                        &format!("{} âncora(s) de {}", store.len(), dir.display()),
                    );
                    // §9 — revogação, quando o operador instalou CRLs.
                    let crls = match config.compliance_crl_dir.as_ref() {
                        Some(d) => {
                            let (crls, rel) = heraclitus_compliance::crl::CrlStore::load_dir(d)
                                .map_err(|e| HeraclitusError::Config(format!("CRLs: {e}")))?;
                            // Pedir consulta de revogação e não a poder fazer
                            // pararia toda a ancoragem no primeiro carimbo,
                            // com um erro por marco em vez de um no arranque.
                            if crls.is_empty() {
                                return Err(HeraclitusError::Config(format!(
                                    "pasta de CRLs `{}` sem CRLs utilizáveis ({} ficheiro(s) vistos)",
                                    d.display(),
                                    rel.files_seen
                                )));
                            }
                            boot.ok_line(
                                "CRLs",
                                &format!("{} CRL(s) de {}", crls.len(), d.display()),
                            );
                            Some(crls)
                        }
                        None => None,
                    };
                    let revogacao_ligada = crls.is_some();

                    let mut timestamp_policy = TimestampValidationPolicy::default();
                    if let Some(oid) = config.compliance_tsa_policy_oid.as_deref() {
                        timestamp_policy.required_policy_oid = Some(oid.parse().map_err(|e| {
                            HeraclitusError::Config(format!(
                                "HERACLITUS_COMPLIANCE_TSA_POLICY_OID `{oid}`: {e}"
                            ))
                        })?);
                        boot.ok_line("Política RFC 3161", oid);
                    }

                    let mut cliente = SecureTsaClient::new(
                        config.compliance_tsa_url.clone(),
                        config.compliance_tsa_policy.clone(),
                        store,
                        TlsPolicy::default(),
                        Duration::from_secs(15),
                    )
                    .map_err(|e| HeraclitusError::Config(format!("cliente ACT: {e}")))?
                    .with_verifier(timestamp_policy);
                    if let Some(crls) = crls {
                        cliente = cliente
                            .with_crls(
                                crls,
                                heraclitus_compliance::crl::CrlPolicy {
                                    max_staleness: Duration::from_secs(
                                        config.compliance_crl_max_staleness_secs,
                                    ),
                                    exigir_next_update: config.compliance_crl_exigir_next_update,
                                },
                            )
                            .map_err(|e| HeraclitusError::Config(e.to_string()))?;
                    }

                    let estado = if revogacao_ligada {
                        "token externo VERIFICADO contra âncoras instaladas · revogação \
                         consultada por CRL"
                            .to_string()
                    } else {
                        "token externo VERIFICADO contra âncoras instaladas · revogação NÃO \
                         consultada (sem HERACLITUS_COMPLIANCE_CRL_DIR)"
                            .to_string()
                    };
                    (
                        instalar_guarda_de_soberania(cliente, &config, engine.log.clone())?,
                        estado,
                    )
                }
                "http" => (
                    std::sync::Arc::new(HttpTsa::new(
                        config.compliance_tsa_url.clone(),
                        config.compliance_tsa_policy.clone(),
                    )),
                    "token externo SEM validação CMS/X.509/ICP-Brasil e em claro na rede".into(),
                ),
                _ => (
                    std::sync::Arc::new(LocalTsa::generate(config.compliance_tsa_policy.clone())),
                    "token de desenvolvimento; não é ICP-Brasil".into(),
                ),
            };
        let wcfg = WorkerConfig::new(
            Duration::from_secs(config.compliance_interval_secs.max(1)),
            config.compliance_min_lsn_step,
            config.data_dir.join("receipts"),
        );
        let linha = format!(
            "ancoragem ATIVA · modo {} · {}",
            config.compliance_tsa_mode, evidence_status
        );
        if modo == "https" {
            boot.ok_line("Compliance evidence", &linha);
        } else {
            boot.warn_line("Compliance evidence", &linha);
        }
        // SPEC-0050 §7.2 — o worker corre sobre `AnyLog`, não sobre o `Log`
        // legado. O compromisso é calculado a partir do `DatabaseManifest`,
        // que ambos os backends publicam: o legado dá raízes Merkle físicas,
        // o HRKL v6 dá raízes lógicas canónicas, e os dois domínios são
        // separados no imprint para que um verificador não possa aplicar o
        // errado e reportar fraude onde não há.
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

    let mut grpc_server = tonic::transport::Server::builder();
    if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) {
        let cert = std::fs::read(cert_path).map_err(|e| {
            HeraclitusError::Config(format!("TLS cert {}: {e}", cert_path.display()))
        })?;
        let key = std::fs::read(key_path)
            .map_err(|e| HeraclitusError::Config(format!("TLS key {}: {e}", key_path.display())))?;
        let mut tls = tonic::transport::ServerTlsConfig::new()
            .identity(tonic::transport::Identity::from_pem(cert, key));
        if let Some(ca_path) = &config.tls_client_ca_path {
            let ca = std::fs::read(ca_path).map_err(|e| {
                HeraclitusError::Config(format!("TLS client CA {}: {e}", ca_path.display()))
            })?;
            tls = tls.client_ca_root(tonic::transport::Certificate::from_pem(ca));
            boot.warn_line("TLS gRPC", "mTLS obrigatório (CA de clientes configurada)");
        } else {
            boot.warn_line(
                "TLS gRPC",
                "TLS servidor ativo; certificado cliente não exigido",
            );
        }
        grpc_server = grpc_server
            .tls_config(tls)
            .map_err(|e| HeraclitusError::Config(format!("TLS gRPC: {e}")))?;
    }
    boot.ok_line(
        "Servidor gRPC (tonic)",
        &format!(
            "{}://{grpc_addr}",
            if config.tls_cert_path.is_some() {
                "https"
            } else {
                "http"
            }
        ),
    );
    boot.ready(&grpc_addr.to_string(), &rest_addr.to_string());
    let _ = heraclitus_platform::notify_ready();
    grpc_server
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
    if let Some(runtime) = sentinel_runtime {
        if let Err(error) = runtime.checkpoint() {
            tracing::warn!(error = %error, "checkpoint final do Sentinel falhou (próximo boot replaya a cauda)");
        }
        runtime.shutdown();
    }
    if let Some(t) = telemetry_task {
        t.abort();
    }
    if let Some(t) = v6_gc_task {
        t.abort();
    }
    if let Some(t) = v6_packing_task {
        t.abort();
    }
    if let Some(t) = v6_hrki_task {
        t.abort();
    }
    #[cfg(feature = "tier")]
    if let Some(t) = v6_lakehouse_task {
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
/// Bytes em unidades que um humano lê sem contar dígitos.
///
/// Existe porque a linha de arranque do GC precisa de dizer um número que o
/// operador entenda à primeira: "1 234 567 890" não comunica nada; "1.15 GiB"
/// comunica.
fn human_bytes(bytes: u64) -> String {
    const UNIDADES: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut valor = bytes as f64;
    let mut i = 0;
    while valor >= 1024.0 && i + 1 < UNIDADES.len() {
        valor /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{valor:.2} {}", UNIDADES[i])
    }
}

/// SPEC-0046 — envolve o cliente da ACT na guarda de egresso, quando o operador
/// a pediu.
///
/// `off` devolve o cliente **cru**, e é o default. Instalar a guarda com uma
/// política que autoriza tudo seria pior do que não a instalar: daria a
/// aparência de um controlo de egresso a quem lesse a configuração, sem que
/// ninguém estivesse a decidir o que sai. Aqui, quando não há decisão, não há
/// guarda — e vê-se na linha de arranque.
fn instalar_guarda_de_soberania(
    cliente: heraclitus_compliance::secure_tsa::SecureTsaClient,
    config: &heraclitus_core::HeraclitusConfig,
    log: std::sync::Arc<heraclitus_log::AnyLog>,
) -> Result<std::sync::Arc<dyn heraclitus_compliance::TsaClient + Send + Sync>, HeraclitusError> {
    use heraclitus_compliance::sovereignty::{
        EgressEndpoint, EgressPurpose, GuardedTsaClient, SovereigntyMode, SovereigntyPolicy,
        SovereigntyRuntime,
    };

    let modo = match config
        .compliance_sovereignty_mode
        .to_ascii_lowercase()
        .as_str()
    {
        "off" | "" => return Ok(std::sync::Arc::new(cliente)),
        "controlled" | "controlled_egress" => SovereigntyMode::ControlledEgress,
        "strict" | "strict_air_gap" | "strict-air-gap" => SovereigntyMode::StrictAirGap,
        outro => {
            return Err(HeraclitusError::Config(format!(
                "compliance_sovereignty_mode `{outro}` desconhecido: use off, controlled ou \
                 strict-air-gap"
            )))
        }
    };

    // O destino da guarda é derivado do MESMO URL que o cliente vai usar. Se
    // fosse configurado à parte, a allowlist podia autorizar um host e o
    // cliente ligar a outro, e a guarda passaria a autorizar uma ligação que
    // não é a que acontece.
    let resto = config
        .compliance_tsa_url
        .strip_prefix("https://")
        .ok_or_else(|| {
            HeraclitusError::Config("guarda de soberania exige compliance_tsa_url https://".into())
        })?;
    let autoridade = resto.split('/').next().unwrap_or(resto);
    let (host, porto) = match autoridade.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| {
                HeraclitusError::Config(format!("porto inválido em `{autoridade}`"))
            })?,
        ),
        None => (autoridade.to_string(), 443u16),
    };
    let endpoint = EgressEndpoint {
        scheme: "https".into(),
        host,
        port: porto,
        purpose: EgressPurpose::TimestampAuthority,
    };

    // Em air-gap estrito a política PROÍBE endpoints — e é isso que se quer:
    // o carimbo em linha passa a ser negado e auditado, e a ancoragem tem de
    // ir pelo caminho diferido. Não é um erro de configuração, é a
    // configuração a fazer o que diz.
    let allowed = if modo == SovereigntyMode::StrictAirGap {
        Default::default()
    } else {
        [endpoint.clone()].into_iter().collect()
    };
    let policy = SovereigntyPolicy {
        policy_id: "compliance-anchor".into(),
        version: "1".into(),
        mode: modo,
        allowed_endpoints: allowed,
        allow_local_network_models: false,
        allow_external_models: false,
    };
    let runtime = SovereigntyRuntime::new(policy, log)
        .map_err(|e| HeraclitusError::Config(format!("política de soberania: {e}")))?;
    let guarded = GuardedTsaClient::new(cliente, runtime, endpoint, "compliance-anchor-worker")
        .map_err(|e| HeraclitusError::Config(format!("guarda de egresso: {e}")))?;
    Ok(std::sync::Arc::new(guarded))
}
