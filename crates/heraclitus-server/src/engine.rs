//! The engine: composes log + memtable + views into one query surface.
//! All intelligence lives in the agent; this is just the riverbed.

use heraclitus_activation::ActivationStore;
use heraclitus_compliance::{ComplianceDashboardSnapshot, RegulatoryState, RequirementEffect};
use heraclitus_core::vm::{ConsistencyVirtualMachine, VmInstruction, VmState, VmVersion};
use heraclitus_core::{
    Episode, EventKind, HeraclitusConfig, HeraclitusError, Lsn, ProductPoint, SegmentId,
};
use heraclitus_crypto::KeyStore;
use heraclitus_index_attr::AttrIndex;
use heraclitus_index_graph::entity::EntityResolver;
use heraclitus_index_graph::temporal::TemporalGraph;
use heraclitus_index_graph::GraphIndex;
use heraclitus_index_text::TextIndex;
use heraclitus_index_vector::VectorIndex;
use heraclitus_log::vm_bridge;
use heraclitus_log::{AnyLog, EpisodeLog};
use heraclitus_manifold::ProductMetric;
use heraclitus_memtable::Memtable;
use heraclitus_query::ast::Value as GqlValue;
use heraclitus_query::backend::{
    cluster_of, community_of, hypotheses_of, match_edges_of, neighbors_of, node_metrics_of,
    resolve_of, traverse_of, CommunityResult, EdgeHypotheses, EdgeRow, MetricsResult, NeighborRow,
    PrunedScanResult, QueryBackend,
};
use heraclitus_retrieval::{retrieve, LinearReranker, RecallInputs};
use heraclitus_telemetry_health::{SensorIdentity, TelemetryHealthGraph, TelemetryHealthSnapshot};
use heraclitus_views::{View, ViewRegistry};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// Reserved technical attributes used to make external delivery exactly-once.
/// They remain outside the encrypted attribute envelope so retries can still be
/// identified after a subject has been crypto-shredded.
/// Shards do lock de idempotência. Chaves distintas nunca precisaram de
/// esperar umas pelas outras; o lock único fazia-o na mesma.
const IDEMPOTENCY_SHARDS: usize = 64;

pub const IDEMPOTENCY_KEY_ATTR: &str = "__heraclitus_idempotency_key";
pub const IDEMPOTENCY_HASH_ATTR: &str = "__heraclitus_idempotency_hash";

const SENTINEL_DERIVED_KINDS: &[&str] = &[
    "SecurityEvent",
    "SecuritySignal",
    "SecurityRiskAssessment",
    "SecurityInvestigation",
    "SecurityAiInvocation",
    "SecurityIncident",
    "SecurityIncidentTransition",
    "SecurityHypothesis",
    "SecurityActionProposal",
    "SecurityActionResult",
    "SecurityApproval",
    "SecurityPolicyDecision",
    "SecurityModelUpdate",
    "SecurityRulesetUpdate",
    "SecurityFeedback",
    "SentinelCheckpoint",
];

fn is_internal_sentinel_episode(episode: &Episode) -> bool {
    episode.agent_id == "sentinel"
        && episode
            .attrs
            .get("sentinel.generated")
            .is_some_and(|value| matches!(value.as_str(), "true" | "derived" | "1"))
        && matches!(
            &episode.kind,
            EventKind::Custom(kind) if SENTINEL_DERIVED_KINDS.contains(&kind.as_str())
        )
}

fn is_sentinel_reserved(episode: &Episode) -> bool {
    episode.agent_id == "sentinel"
        || episode
            .attrs
            .keys()
            .any(|key| key.starts_with("sentinel.") || key.starts_with("sec."))
        || matches!(
            &episode.kind,
            EventKind::Custom(kind) if SENTINEL_DERIVED_KINDS.contains(&kind.as_str())
        )
}

/// Kinds que o `heraclitus-compliance` escreve e cujo replay reconstrói o
/// estado regulatório. Como o do Sentinel, é território interno.
/// Retirados das constantes dos próprios módulos — `regulatory.rs:17-20`,
/// `privacy.rs:16-18`, `sovereignty.rs:17-18`, `deferred.rs:26` e
/// `model_bundle.rs:15` — e não de memória: é a lista que os `replay` casam.
const COMPLIANCE_DERIVED_KINDS: &[&str] = &[
    "CompliancePolicyActivation",
    "ComplianceAssessment",
    "LegalHold",
    "LegalHoldRelease",
    "PrivacyIncidentAssessment",
    "RegulatoryDeadline",
    "ComplianceExport",
    "ComplianceEgressDecision",
    "ComplianceModelDecision",
    "ComplianceEvidenceAnchor",
    "SecurityModelActivation",
];

/// O mesmo contrato de `is_sentinel_reserved`, para o domínio regulatório.
///
/// Sem isto, o append externo — que só exige `AccessRole::Writer` — deixava
/// forjar prova de compliance: o replay confia no atributo
/// `compliance.generated` e no `kind`, e ambos vinham do cliente. Um Writer
/// podia libertar um `LegalHold` que só o Admin devia libertar (abrindo o
/// crypto-shred sobre dados retidos), ou colocar um hold de âmbito total e
/// travar o GC para sempre.
///
/// O caso pior não era sequer a falsificação: repetir um `hold_id` faz
/// `RegulatoryState::replay` devolver `Err`, e como o log é append-only esse
/// episódio não se apaga. O estado regulatório ficava inválido de forma
/// **permanente** — e com ele o crypto-shred e o GC, que falham fechado. Era a
/// única falha do lote sem reparação possível depois de acontecer.
fn is_compliance_reserved(episode: &Episode) -> bool {
    episode.agent_id == "gov-compliance"
        || episode
            .attrs
            .keys()
            .any(|key| key.starts_with("compliance."))
        || matches!(
            &episode.kind,
            EventKind::Custom(kind) if COMPLIANCE_DERIVED_KINDS.contains(&kind.as_str())
        )
}

pub struct Engine {
    /// Backend append-only selecionado explicitamente na configuração.
    /// `legacy` continua sendo o default; `v6` nunca é inferido nem migrado.
    pub log: Arc<AnyLog>,
    pub memtable: Arc<Memtable>,
    views: Mutex<ViewRegistry>,
    vector: Arc<RwLock<VectorIndex>>,
    text: Arc<RwLock<TextIndex>>,
    graph: Arc<RwLock<GraphIndex>>,
    tgraph: Arc<RwLock<TemporalGraph>>,
    entity: Arc<RwLock<EntityResolver>>,
    activation: Arc<RwLock<ActivationStore>>,
    telemetry_health: Arc<RwLock<TelemetryHealthGraph>>,
    /// Índice secundário de atributos (qualquer campo -> [LSN]). Persistido em
    /// `<data_dir>/views`; gerido diretamente pelo Engine (fora do ViewRegistry)
    /// para controlar o checkpoint/replay e o arranque rápido.
    attr: Arc<RwLock<AttrIndex>>,
    attr_dir: std::path::PathBuf,
    /// Raiz do cold tier (object store local); `demote` materializa segmentos aqui.
    #[cfg(feature = "tier")]
    cold_tier_path: std::path::PathBuf,
    /// Contadores da leitura remota HRKL v6. Vivem no Engine porque cada
    /// operação abre um `ColdTierV6` efémero; mantê-los no cliente do object
    /// store faria os valores voltarem a zero entre requests.
    cold_range_reads: std::sync::atomic::AtomicU64,
    cold_bytes_downloaded: std::sync::atomic::AtomicU64,
    /// §3.9 (distill) — cursor do último LSN já consolidado (+1). Persistido em
    /// `<attr_dir>/distill.cursor`; garante que a task periódica não re-agrupa
    /// (e re-emite Facts d)os episódios já processados.
    #[cfg(feature = "distill")]
    distill_cursor: std::sync::atomic::AtomicU64,
    metric: ProductMetric,
    /// Per-agent key store when encryption at rest is enabled (§3.10).
    keystore: Option<Arc<KeyStore>>,
    /// Modo bulk-ingest: `append` grava SÓ no log (pula memtable/views/attr em
    /// RAM). Liga com HERACLITUS_LOG_ONLY=1 — permite cargas massivas (centenas
    /// de GB) com RAM limitada; as views se constroem depois via `view rebuild`.
    log_only: bool,
    /// Meta-auditoria de acessos (padrão immudb): cada query GQL executada
    /// gera um evento `AuditQuery` no próprio log — quem consultou o quê é,
    /// ele próprio, evidência imutável. Liga por config (audit_queries).
    audit_queries: bool,
    /// SPEC-015/021 — quando a replicação está ativa, as escritas passam por
    /// aqui (o líder do raft) em vez de irem direto ao log. Vazio = nó autónomo
    /// (o caminho normal). Preenchido uma vez por `set_replication`.
    replication: std::sync::OnceLock<Arc<dyn ReplRouter>>,
    /// R16: serializa o par (ler head → append) das escritas H-VM, para que
    /// dois upserts concorrentes nunca carimbem o mesmo lsn na VmInstruction.
    hvm_lock: Mutex<()>,
    /// Serializa check+append de uma chave externa. O índice de atributos é
    /// persistente/reconstruível pelo log, portanto isto fecha tanto corridas
    /// concorrentes quanto retries depois de crash/restart.
    /// Serialização da verificação-e-append idempotente, **por chave**.
    ///
    /// Era um único `Mutex<()>` global: cada append idempotente esperava por
    /// todos os outros, mesmo de chaves sem relação nenhuma — e a secção
    /// crítica inclui o append durável inteiro, com o round-trip de consenso
    /// quando há replicação. Um cliente a escrever com a chave `a` ficava atrás
    /// de outro a escrever com a chave `b`, sem qualquer razão.
    ///
    /// A correcção é sharding e não uma reserva em memória, de propósito. A
    /// reserva (bloquear → reservar → libertar → escrever → confirmar) tira
    /// mais latência, mas inventa um estado intermédio que pode sobreviver a um
    /// crash entre reservar e confirmar — um modo de falha novo num caminho que
    /// existe precisamente para garantir exactly-once. O sharding não muda
    /// semântica nenhuma: duas chaves distintas nunca interagem, portanto
    /// serializá-las juntas nunca foi um requisito, era um acidente.
    idempotency_locks: Vec<Mutex<()>>,
}

/// Contrato de encaminhamento de escritas pelo consenso. Implementado pelo
/// módulo `cluster` (feature `replication`); sem a feature nunca é preenchido, e
/// `Engine::append` segue o caminho direto ao log.
pub trait ReplRouter: Send + Sync {
    /// Submete um episódio ao líder do raft e devolve o LSN denso quando fica
    /// comitado e aplicado localmente. Num não-líder devolve um erro com o hint.
    fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError>;
    /// Estado do nó no cluster (papel, líder atual, membros) para `/state`.
    fn status(&self) -> serde_json::Value;
}

/// Wrapper so the same index object can be both registered as a View and
/// queried by the engine (the registry owns Box<dyn View>).
struct Shared<T>(Arc<RwLock<T>>);

// `RwLock` e não `Mutex` por uma razão medida: o checkpoint segura o índice
// enquanto serializa e escreve o snapshot — 70 s para 1,97 GiB com 8,6 M
// eventos, a 2026-09-02 — e sob exclusão mútua isso parava todos os leitores,
// `/stats` incluído, 23% do tempo. Mas `View::checkpoint` recebe `&self`: só
// lê. Estava a usar-se exclusão mútua para uma operação de leitura. Com um
// `RwLock`, o checkpoint e as leituras partilham o lock e correm ao mesmo
// tempo; só `apply`/`restore`/`reset`, que mutam, é que excluem.
impl<T: View> View for Shared<T> {
    fn name(&self) -> &str {
        // Names are static per index type.
        let g = self.0.read().unwrap();
        // SAFETY-free trick: names are 'static string literals in all our
        // views, so returning them outlives the guard.
        match g.name() {
            "vector" => "vector",
            "text" => "text",
            "graph" => "graph",
            "tgraph" => "tgraph",
            "entity" => "entity",
            "activation" => "activation",
            "telemetry-health" => "telemetry-health",
            _ => "view",
        }
    }
    fn apply(&mut self, lsn: Lsn, event: &Episode) {
        self.0.write().unwrap().apply(lsn, event);
    }
    fn watermark(&self) -> Lsn {
        self.0.read().unwrap().watermark()
    }
    // Sem estes forwards, o wrapper engolia os defaults do trait (no-op) e
    // NENHUMA view persistia/restaurava — todo o boot era replay desde 0.
    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), HeraclitusError> {
        self.0.read().unwrap().checkpoint(dir)
    }
    fn restore(&mut self, dir: &std::path::Path) -> Result<bool, HeraclitusError> {
        self.0.write().unwrap().restore(dir)
    }
    fn reset(&mut self) {
        self.0.write().unwrap().reset();
    }
    // Pelo mesmo motivo dos dois acima, e antes que alguém se queime: sem este
    // forward, `Shared` devolvia o default do trait (`None`) e TODAS as views
    // registadas apareciam a desistir do dígito de determinismo que o próprio
    // trait descreve como acceptance gate. Hoje ninguém lê `state_hash` pelo
    // registry — o engine pergunta ao índice concreto (`graph_state_hash`) —
    // por isso não havia sintoma. A armadilha era para o primeiro que
    // percorresse as views a recolher dígitos e concluísse, sem erro nenhum,
    // que nenhuma view os suporta.
    fn state_hash(&self) -> Option<[u8; 32]> {
        self.0.read().unwrap().state_hash()
    }
}

impl Engine {
    /// Open the engine silently (tests, the CLI, embedded callers). For the
    /// narrated server boot use [`Engine::open_with_boot`].
    pub fn open(config: &HeraclitusConfig) -> Result<Self, HeraclitusError> {
        Self::open_with_boot(config, &crate::boot::Boot::silent())
    }

    /// Open the engine while narrating each subsystem through `boot`. The server
    /// passes a console reporter (banner, `[  OK  ]` lines, spinner on the slow
    /// replay phases); `open` passes a silent one so nothing leaks into tests.
    pub fn open_with_boot(
        config: &HeraclitusConfig,
        boot: &crate::boot::Boot,
    ) -> Result<Self, HeraclitusError> {
        use crate::boot::{fmt_bytes, group, sup};

        // SPEC-0050 — a compaction do cold tier v1 percorre recibos de demote
        // **v1**. Num banco v6 todos os recibos são v2, portanto a task é
        // inerte: não corrompe nada, simplesmente nunca encontra o que
        // compactar.
        //
        // Antes isto recusava o arranque. Recusar o servidor inteiro por causa
        // de uma task de fundo opcional era desproporcionado — mas deixá-la a
        // girar em silêncio seria pior, porque o operador ligou-a à espera de
        // que algo acontecesse. O meio honesto é arrancar e dizer-lhe que esta
        // peça em concreto não vai actuar.
        #[cfg(feature = "tier")]
        if config.storage_format == heraclitus_core::StorageFormat::V6
            && config.tier_compaction_interval_secs > 0
        {
            boot.warn_line(
                "Compaction do cold tier",
                "INERTE em v6: percorre recibos v1 e o v6 emite v2; a task não é iniciada",
            );
        }

        // Modo recovery para stores grandes demais p/ a RAM: pula o replay das
        // views pesadas (que vivem 100% em RAM) e a (re)construção do índice de
        // atributos. O banco sobe servindo o log (a fonte da verdade); as views
        // ficam vazias até um `view rebuild`. Liga com HERACLITUS_SKIP_VIEW_REPLAY=1.
        let truthy = |k: &str| {
            std::env::var(k)
                .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"))
                .unwrap_or(false)
        };
        // Bulk-ingest: appends gravam só no log. Implica pular o replay no boot.
        let log_only = truthy("HERACLITUS_LOG_ONLY");
        let skip_replay = log_only || truthy("HERACLITUS_SKIP_VIEW_REPLAY");
        let privacy_rebuild_marker = config
            .data_dir
            .join("views")
            .join("privacy-rebuild-required");
        let privacy_rebuild = privacy_rebuild_marker.exists();

        // Encryption at rest (§3.10): when enabled, the log seals episode
        // content with a per-agent key kept under `<data_dir>/keys`.
        let keystore = if config.encryption_at_rest {
            let p = boot.phase("Cifra em repouso (keystore por agente)");
            let ks = KeyStore::open(config.data_dir.join("keys"))?;
            p.ok("ChaCha20-Poly1305 · crypto-shred pronto");
            Some(ks)
        } else {
            None
        };
        if privacy_rebuild && keystore.is_none() {
            return Err(HeraclitusError::Config(
                "privacy-rebuild-required existe, mas encryption_at_rest está desligado".into(),
            ));
        }

        let log = {
            let p = boot.phase("Log append-only (a fonte da verdade)");
            let log = Arc::new(AnyLog::open_with_keystore(
                config.storage_format,
                config.data_dir.join("log"),
                config.segment_max_bytes,
                config.fsync.clone(),
                keystore.clone(),
            )?);
            let head = log.head();
            p.ok(format!(
                "{} eventos · head LSN {} · formato {} · segmentos de {}",
                group(head),
                group(head),
                config.storage_format.as_str(),
                fmt_bytes(config.segment_max_bytes)
            ));
            log
        };

        // The geometry announces itself: the learned product manifold signature.
        let metric = {
            let p = boot.phase("Geometria de produto (variedade aprendida)");
            let m = ProductMetric::default();
            let s = &m.sig;
            p.ok(format!(
                "H{}⊗S{}⊗E{} · Poincaré κ={} · esfera κ=+{} · {} dims",
                sup(s.a),
                sup(s.b),
                sup(s.c),
                s.k1,
                s.k2,
                s.a + s.b + s.c
            ));
            m
        };

        let vector = {
            let p = boot.phase("Índice vetorial (HNSW hiperbólico)");
            let v = Arc::new(RwLock::new(VectorIndex::new(metric.clone())));
            p.ok("k-NN no espaço de produto");
            v
        };
        let text = {
            let p = boot.phase("Índice de texto (invertido)");
            let t = Arc::new(RwLock::new(TextIndex::new()));
            p.ok("recall em duas fases");
            t
        };
        let graph = {
            let p = boot.phase("Índice de grafo (proveniência DAG)");
            let g = Arc::new(RwLock::new(GraphIndex::new()));
            p.ok("WHY · arestas de origem");
            g
        };
        let tgraph = {
            let p = boot.phase("Grafo temporal (consultas AS OF)");
            let g = Arc::new(RwLock::new(TemporalGraph::new()));
            p.ok("arestas com intervalos de validade");
            g
        };
        let entity = {
            let p = boot.phase("Resolução de entidades");
            let e = Arc::new(RwLock::new(EntityResolver::new()));
            p.ok("merge/cluster por chave");
            e
        };
        let activation = {
            let p = boot.phase("Ativação ACT-R (memória cognitiva)");
            let a = Arc::new(RwLock::new(ActivationStore::new(config.activation_decay)));
            p.ok(format!("decaimento d={}", config.activation_decay));
            a
        };
        let telemetry_health = {
            let p = boot.phase("Telemetry Health / Sensor Trust");
            let health = Arc::new(RwLock::new(TelemetryHealthGraph::new()));
            p.ok("Coverage · Freshness · Completeness · Integrity · Trust");
            health
        };

        // The slow phase on a big log: replay the tail into every view. The
        // spinner moves here while millions of events stream through.
        let registry = {
            let p = boot.phase("Replay das views a partir do log");
            let mut registry = ViewRegistry::open(&config.data_dir)?;
            registry.register(Box::new(Shared(vector.clone())));
            registry.register(Box::new(Shared(text.clone())));
            registry.register(Box::new(Shared(graph.clone())));
            registry.register(Box::new(Shared(tgraph.clone())));
            registry.register(Box::new(Shared(entity.clone())));
            registry.register(Box::new(Shared(activation.clone())));
            registry.register(Box::new(Shared(telemetry_health.clone())));
            if privacy_rebuild {
                registry.rebuild(&log, None)?;
                registry.checkpoint()?;
                p.ok("rebuild integral obrigatório pós-shred concluído");
            } else if skip_replay {
                // As views ficam VAZIAS — os watermarks carregados do disco
                // deixam de as descrever. Mantê-los fazia um checkpoint
                // posterior (periódico ou de shutdown) gravar snapshots vazios
                // sob watermarks altos, e o arranque seguinte replayava só a
                // cauda: perda PERMANENTE e silenciosa de tudo ≤ watermark nas
                // views derivadas. A zero, qualquer checkpoint é seguro e o
                // próximo boot normal reconstrói do LSN 0.
                registry.reset_watermarks();
                p.ok("PULADO — HERACLITUS_SKIP_VIEW_REPLAY (views vazias; watermarks a zero)");
            } else {
                registry.catch_up(&log)?;
                let wm = registry.min_watermark();
                // Fast boot: persiste já o estado materializado — o próximo
                // arranque restaura os snapshots e replaya SÓ a cauda
                // `(watermark, head]` em vez do log inteiro (a lição da carga
                // massiva de 2026-07-02: replay total não escala).
                registry.checkpoint()?;
                p.ok(format!(
                    "{} views materializadas @ LSN {} · checkpoint gravado",
                    registry.view_names().len(),
                    group(wm),
                ));
            }
            registry
        };

        // Índice secundário de atributos: carrega o checkpoint e replaya só a
        // cauda (arranque rápido); num log virgem constrói tudo uma vez e grava.
        let attr_dir = config.data_dir.join("views");
        let attr = {
            let p = boot.phase("Índice de atributos (campo → LSN)");
            let attr = Arc::new(RwLock::new(if privacy_rebuild {
                AttrIndex::new()
            } else {
                AttrIndex::open(&attr_dir)
            }));
            let keys = {
                let mut idx = attr.write().unwrap();
                if !skip_replay {
                    // Build PAGINADO: o log é varrido em janelas (não materializa os
                    // milhões de episódios de uma vez — limita a RAM do arranque).
                    let head = log.head();
                    let mut cur = if idx.is_empty() { 0 } else { idx.watermark() };
                    let mut built = false;
                    while cur <= head {
                        let batch = log.scan_capped(cur, head + 1, 100_000)?;
                        if batch.is_empty() {
                            break;
                        }
                        let last = batch.last().unwrap().0;
                        for (lsn, ep) in &batch {
                            if vm_bridge::is_hvm(ep) {
                                continue; // H-VM frame — fora do índice attr.
                            }
                            idx.apply(*lsn, ep);
                        }
                        built = true;
                        cur = last + 1;
                    }
                    if built {
                        idx.save(&attr_dir)?;
                    }
                }
                idx.keys()
            };
            if skip_replay {
                p.ok(format!(
                    "PULADO — {} chaves do checkpoint",
                    group(keys as u64)
                ));
            } else {
                p.ok(format!("{} chaves indexadas", group(keys as u64)));
            }
            attr
        };

        // §3.9: recupera o cursor do distill persistido (0 se ausente/ilegível).
        // Antes do struct literal porque `attr_dir` é movido para o campo.
        #[cfg(feature = "distill")]
        // Formato novo: valor + complemento (16 B), que distingue um ficheiro a
        // zeros de um cursor 0 legítimo. Formato antigo: 8 B crus, ainda aceite
        // para uma actualização não forçar a re-derivação de toda a base.
        let distill_cursor = std::sync::atomic::AtomicU64::new(
            std::fs::read(attr_dir.join("distill.cursor"))
                .ok()
                .and_then(|b| match b.len() {
                    16 => {
                        let valor = u64::from_le_bytes(b[..8].try_into().ok()?);
                        let inverso = u64::from_le_bytes(b[8..].try_into().ok()?);
                        (inverso == !valor).then_some(valor)
                    }
                    8 => Some(u64::from_le_bytes(b.try_into().ok()?)),
                    _ => None,
                })
                .unwrap_or(0),
        );

        let engine = Self {
            log,
            memtable: Arc::new(Memtable::new(config.memtable_cap)),
            views: Mutex::new(registry),
            vector,
            text,
            graph,
            tgraph,
            entity,
            activation,
            telemetry_health,
            attr,
            attr_dir,
            metric,
            keystore,
            log_only,
            audit_queries: config.audit_queries,
            replication: std::sync::OnceLock::new(),
            hvm_lock: Mutex::new(()),
            idempotency_locks: (0..IDEMPOTENCY_SHARDS).map(|_| Mutex::new(())).collect(),
            cold_range_reads: std::sync::atomic::AtomicU64::new(0),
            cold_bytes_downloaded: std::sync::atomic::AtomicU64::new(0),
            #[cfg(feature = "tier")]
            cold_tier_path: config.cold_tier_path.clone(),
            #[cfg(feature = "distill")]
            distill_cursor,
        };
        if privacy_rebuild {
            engine.attr.read().unwrap().save(&engine.attr_dir)?;
            std::fs::remove_file(&privacy_rebuild_marker)?;
        }
        Ok(engine)
    }

    /// Ativa a replicação: a partir daqui `append` encaminha pelo consenso.
    /// Chamado uma vez no boot quando `config.replication` está presente.
    pub fn set_replication(&self, router: Arc<dyn ReplRouter>) {
        let _ = self.replication.set(router);
    }

    /// Indexação síncrona de um episódio já no log (memtable + views + attr).
    /// É o núcleo partilhado por `append` e pelo hook de apply do consenso — ao
    /// replicar, cada nó indexa localmente o que aplica (read-your-writes).
    pub fn index_applied(&self, lsn: Lsn, episode: &Episode) {
        if self.log_only {
            return;
        }
        // Frames H-VM (`hvm_isa`) não entram nas views/attr/memtable — vivem no
        // replay do VM. Excluí-los aqui e nos replays de boot mantém os índices
        // (e o `state_hash`) idênticos ao vivo vs. reconstruídos.
        if vm_bridge::is_hvm(episode) {
            return;
        }
        self.memtable.apply(lsn, episode.clone());
        self.views.lock().unwrap().apply(lsn, episode);
        self.attr.write().unwrap().apply(lsn, episode);
    }

    /// Meta-auditoria: regista a execução de uma query como EVENTO no log
    /// (best-effort — auditar nunca pode falhar a query auditada). O texto é
    /// truncado para não inchar o log com queries gigantes.
    pub fn audit_query(&self, gql: &str, ok: bool, principal: &str) {
        if !self.audit_queries {
            return;
        }
        let mut text: String = gql.chars().take(500).collect();
        if gql.len() > text.len() {
            text.push('…');
        }
        let mut e = Episode::new(
            "server",
            EventKind::Custom("AuditQuery".into()),
            text.into_bytes(),
        );
        e.attrs.insert("audit".into(), "query".into());
        e.attrs.insert("principal".into(), principal.into());
        e.attrs
            .insert("ok".into(), if ok { "true".into() } else { "false".into() });
        let _ = self.append(e);
    }

    /// Registra toda tentativa de operação administrativa, inclusive falhas.
    pub fn audit_admin(&self, operation: &str, ok: bool, principal: &str) {
        if !self.audit_queries {
            return;
        }
        let mut e = Episode::new(
            "heraclitus-audit",
            EventKind::Custom("AuditAdmin".into()),
            operation.as_bytes().to_vec(),
        );
        e.attrs.insert("audit".into(), "admin".into());
        e.attrs.insert("principal".into(), principal.into());
        e.attrs.insert("operation".into(), operation.into());
        e.attrs
            .insert("ok".into(), if ok { "true".into() } else { "false".into() });
        let _ = self.append(e);
    }

    /// Grava o checkpoint do índice de atributos (o servidor pode chamar
    /// periodicamente / no shutdown para o arranque seguinte só replayar a cauda).
    pub fn checkpoint_attr(&self) -> Result<(), HeraclitusError> {
        self.attr.read().unwrap().save(&self.attr_dir)
    }

    /// Fast boot: persiste o snapshot de TODAS as views (vector/text/graph/
    /// tgraph/entity/activation) + índice de atributos + watermarks. Chamado
    /// no shutdown gracioso e disponível para checkpoints periódicos — o
    /// arranque seguinte restaura e replaya só a cauda `(watermark, head]`.
    pub fn checkpoint_views(&self) -> Result<(), HeraclitusError> {
        self.views.lock().unwrap().checkpoint()?;
        self.checkpoint_attr()
    }

    /// SPEC-027 wired — endogenous telemetry: append the engine's vitals as
    /// ordinary `SystemMetric` episodes, so the DB can query its own history
    /// through the normal GQL engine (`WHERE n.kind = "SystemMetric"`).
    /// Returns how many metric episodes were appended.
    pub fn emit_telemetry(&self) -> Result<u64, HeraclitusError> {
        use heraclitus_core::telemetry::SystemMetric;
        let head = self.log.head();
        let sealed = self.log.sealed_segment_count();
        let metrics = [
            SystemMetric::new("log_head_lsn", head as f64),
            SystemMetric::new("sealed_segments", sealed as f64),
        ];
        // CRÍTICO com replicação: passa por `append` (não `log.append` direto).
        // Uma escrita direta ao log local contornaria o consenso e faria o
        // `append_replicated` do raft colidir (`lsn < head` ⇒ CasConflict),
        // divergindo/derrubando o nó. Via `append`, a telemetria vai pelo líder
        // e replica; num seguidor devolve "não sou líder" e o tick apenas salta.
        for m in &metrics {
            self.append(m.to_episode("heraclitus-engine"))?;
        }
        Ok(metrics.len() as u64)
    }

    // ── H-VM ledger (M20) ────────────────────────────────────────────────────
    // The Sovereignty-Layer key/value ledger, reachable from the engine. Writes
    // are H-VM ISA bytecode appended to the *same* durable log as episodes
    // (`vm_bridge`, additive — the format is untouched); reads replay the log
    // through the deterministic reducer (read-your-writes via the log being the
    // truth). State is replayed on demand today; an incremental cache backed by
    // the Bᵋ-tree checkpoint is the next refinement.

    /// Append an H-VM upsert to the durable log.
    pub fn hvm_upsert(&self, key: Vec<u8>, val: Vec<u8>) -> Result<Lsn, HeraclitusError> {
        // R16: head+append atómicos face a outras escritas H-VM — sem o lock,
        // dois upserts concorrentes carimbavam o MESMO lsn na instrução.
        let _g = self.hvm_lock.lock().unwrap();
        let lsn = self.log.head();
        let instr = VmInstruction::Upsert {
            key,
            val,
            lsn,
            ev_id: heraclitus_core::EventId::new(),
        };
        self.hvm_append(&instr)
    }

    /// Append an H-VM delete to the durable log.
    pub fn hvm_delete(&self, key: Vec<u8>) -> Result<Lsn, HeraclitusError> {
        let _g = self.hvm_lock.lock().unwrap();
        let lsn = self.log.head();
        let instr = VmInstruction::Delete {
            key,
            lsn,
            ev_id: heraclitus_core::EventId::new(),
        };
        self.hvm_append(&instr)
    }

    /// Encode an H-VM instruction as an ISA-frame `Episode` (`Custom("hvm_isa")`)
    /// and route it through [`Engine::append`] — assim as escritas H-VM passam
    /// pelo **consenso** quando a replicação está ativa (líder aplica, quórum
    /// acka, cada nó replica o frame e reconstrói o `VmState` por replay). O frame
    /// é excluído dos índices derivados (`index_applied`/views saltam `is_hvm`),
    /// por isso não polui o grafo nem diverge o `state_hash`.
    fn hvm_append(&self, instr: &VmInstruction) -> Result<Lsn, HeraclitusError> {
        let frame = heraclitus_core::vm::encode(VmVersion(1), instr);
        // : este é o ÚNICO produtor legítimo de frames hvm_isa.
        self.append_internal(Episode::new(
            "hvm",
            EventKind::Custom(vm_bridge::HVM_KIND.to_string()),
            frame,
        ))
    }

    /// Replay the H-VM ledger from the log into a deterministic [`VmState`].
    pub fn hvm_state(&self) -> Result<VmState, HeraclitusError> {
        let vm = ConsistencyVirtualMachine::new(VmVersion(1));
        vm_bridge::replay_vm(&self.log, &vm)
    }

    /// Materialize the H-VM ledger into a Bᵋ-tree (Fractal Tree) and persist it
    /// atomically as a checkpoint. Reload with `heraclitus_btree::BEpsilonTree::load`.
    pub fn hvm_checkpoint(&self, path: &std::path::Path) -> Result<(), HeraclitusError> {
        let vm = ConsistencyVirtualMachine::new(VmVersion(1));
        // replay_vm_to_btree agora é file-backed: constrói e persiste a árvore no
        // `path` (from_map opens+upsert+commit); o save separado ficou redundante.
        let _tree = vm_bridge::replay_vm_to_btree(&self.log, &vm, path)?;
        Ok(())
    }

    /// Checkpoint the H-VM ledger to the **server-owned** default path
    /// (`<data_dir>/hvm.hbt`), returning the path written. The REST endpoint uses
    /// this so a caller can never supply a filesystem path (no path traversal).
    pub fn hvm_checkpoint_default(&self) -> Result<std::path::PathBuf, HeraclitusError> {
        // `attr_dir` is `<data_dir>/views`; its parent is the data dir.
        let base = self.attr_dir.parent().unwrap_or(self.attr_dir.as_path());
        let path = base.join("hvm.hbt");
        self.hvm_checkpoint(&path)?;
        Ok(path)
    }

    /// SPEC-0046 §36 — snapshot operacional derivado exclusivamente do log
    /// append-only e dos recibos persistidos em `<data_dir>/receipts`.
    ///
    /// A construção é deliberadamente read-only e mantém tokens externos sem
    /// trust chain no estado `not_yet_production_trusted`; a superfície REST não
    /// pode promover evidência apenas por estar apresentando-a num dashboard.
    pub fn compliance_status(&self) -> Result<ComplianceDashboardSnapshot, HeraclitusError> {
        let data_dir = self.attr_dir.parent().unwrap_or(self.attr_dir.as_path());
        ComplianceDashboardSnapshot::build(
            self.log.as_ref(),
            data_dir.join("receipts"),
            heraclitus_compliance::now_unix_ms() / 1_000,
        )
        .map_err(|error| HeraclitusError::Config(format!("compliance dashboard: {error}")))
    }

    /// Resolve a server-owned compliance export directory. Remote callers can
    /// choose an identifier, never an arbitrary host path.
    pub(crate) fn compliance_export_dir(
        &self,
        category: &str,
        export_id: &str,
    ) -> Result<std::path::PathBuf, HeraclitusError> {
        let safe = |value: &str| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
                // O ponto está no allowlist, e sem esta linha `".."` passava:
                // é não-vazio, é curto, e todos os seus caracteres são
                // permitidos. Como o valor vira UM componente do caminho, isso
                // bastava para sair do directório de exportações do servidor —
                // o comentário acima promete "never an arbitrary host path" e
                // não era verdade. Recusar qualquer nome só de pontos fecha o
                // caso sem restringir nomes legítimos.
                && !value.chars().all(|ch| ch == '.')
        };
        if !safe(category) || !safe(export_id) {
            return Err(HeraclitusError::Config(
                "category/export_id deve conter apenas ASCII alfanumérico, '-', '_' ou '.', \
                 e não pode ser só pontos"
                    .into(),
            ));
        }
        let data_dir = self.attr_dir.parent().unwrap_or(self.attr_dir.as_path());
        Ok(data_dir
            .join("compliance")
            .join("exports")
            .join(category)
            .join(export_id))
    }

    /// True when the consensus replication router is installed (cluster mode).
    /// Usado por endpoints cuja escrita ainda **não** passa pelo consenso (o
    /// `tier` demote appenda o recibo direto ao log) para os recusar sob
    /// replicação em vez de deixar um nó divergir. O H-VM já passa por
    /// `Engine::append` (logo pelo consenso), por isso deixou de precisar disto.
    pub fn is_replicated(&self) -> bool {
        self.replication.get().is_some()
    }

    /// O `state_hash` do índice de grafo — usado em testes de equivalência de
    /// consenso (deve ser idêntico entre nós que replicaram o mesmo log).
    pub fn graph_state_hash(&self) -> [u8; 32] {
        self.graph.read().unwrap().state_hash()
    }

    /// Abre o backend do cold tier a partir de `cold_tier_path` — um URL de
    /// nuvem (`gs://…`/`s3://…`, features `gcp`/`aws` do tier) ou um caminho
    /// local (default). As credenciais de nuvem vêm do ambiente.
    #[cfg(feature = "tier")]
    fn open_cold_tier(&self) -> Result<heraclitus_tier::ColdTier, HeraclitusError> {
        heraclitus_tier::ColdTier::open_location(&self.cold_tier_path.to_string_lossy())
    }

    #[cfg(feature = "tier")]
    fn open_cold_tier_v6(&self) -> Result<heraclitus_tier::ColdTierV6, HeraclitusError> {
        heraclitus_tier::ColdTierV6::open_location(&self.cold_tier_path.to_string_lossy())
    }

    /// Ids dos segmentos selados — candidatos a demote para o cold tier.
    pub fn sealed_segment_ids(&self) -> Vec<SegmentId> {
        self.log.sealed_segment_ids()
    }

    /// Demote um segmento selado para o cold tier (object store local em
    /// `cold_tier_path`): upload do `.hrkl` + espelho Parquet + recibo Merkle
    /// (`DemotionReceipt`) apenso ao log. Feature `tier`.
    ///
    /// §2.6 (caminho unificado de evento derivado): o upload é preparado pelo
    /// crate tier SEM append; o recibo entra pelo `Engine::append` — logo é
    /// indexado ao vivo (≡ boot-replay, sem divergência de state_hash) E passa
    /// pelo consenso quando a replicação está ativa. NOTA: o OBJETO cold só
    /// existe no store local DESTE nó — por isso o endpoint continua a recusar
    /// demote sob replicação até o object store ser partilhado (nuvem).
    #[cfg(feature = "tier")]
    async fn demote_legacy_segment(
        &self,
        segment_id: SegmentId,
    ) -> Result<heraclitus_tier::DemotionReceipt, HeraclitusError> {
        let cold = self.open_cold_tier()?;
        let legacy = self.log.legacy_arc().ok_or_else(|| {
            HeraclitusError::Config(
                "demote do cold tier legado ainda não suporta storage_format=v6".into(),
            )
        })?;
        let receipt = cold.demote_prepared(legacy.as_ref(), segment_id).await?;
        self.append(heraclitus_tier::ColdTier::receipt_episode(&receipt)?)?;
        Ok(receipt)
    }

    /// Compatibilidade da API v1. O endpoint genérico usa
    /// [`Self::demote_segment_any`] para também devolver recibos v2.
    #[cfg(feature = "tier")]
    pub async fn demote_segment(
        &self,
        segment_id: SegmentId,
    ) -> Result<heraclitus_tier::DemotionReceipt, HeraclitusError> {
        self.demote_legacy_segment(segment_id).await
    }

    /// Publica o layout correspondente ao formato aberto. Legacy mantém o
    /// recibo v1; HRKL v6 publica a geração PACKED imutável e appenda recibo
    /// v2 pelo mesmo `Engine::append` usado pelas demais escritas derivadas.
    #[cfg(feature = "tier")]
    pub async fn demote_segment_any(
        &self,
        segment_id: SegmentId,
    ) -> Result<heraclitus_tier::AnyDemotionReceipt, HeraclitusError> {
        match self.log.as_ref() {
            AnyLog::Legacy(_) => self
                .demote_legacy_segment(segment_id)
                .await
                .map(heraclitus_tier::AnyDemotionReceipt::V1),
            AnyLog::V6(log) => {
                let source = match log.active_packed_generation(segment_id)? {
                    Some(source) => source,
                    None => {
                        // A API de demotion recebe um segmento lógico, não uma
                        // geração. Se ele ainda está RAW, conclui a fila de
                        // packing antes de escolher a geração publicada.
                        log.pack_pending(heraclitus_log::v6::PackingProfile::Balanced)?;
                        log.active_packed_generation(segment_id)?.ok_or_else(|| {
                            HeraclitusError::Query(format!(
                                "segmento v6 {segment_id} não existe ou não possui geração PACKED ativa"
                            ))
                        })?
                    }
                };
                let cold = self.open_cold_tier_v6()?;
                let receipt = cold
                    .publish_generation(
                        &source.path,
                        source.generation,
                        source.source_generation,
                        source.created_hlc,
                    )
                    .await?;

                // Retry depois de resposta perdida: o PUT é idempotente e o
                // log também não ganha um segundo recibo equivalente.
                if let Some(existing) =
                    self.demotion_receipts_any()?
                        .into_iter()
                        .find_map(|r| match r {
                            heraclitus_tier::AnyDemotionReceipt::V2(v2)
                                if v2.segment_id == receipt.segment_id
                                    && v2.generation == receipt.generation
                                    && v2.physical_digest == receipt.physical_digest =>
                            {
                                Some(v2)
                            }
                            _ => None,
                        })
                {
                    return Ok(heraclitus_tier::AnyDemotionReceipt::V2(existing));
                }
                self.append(receipt.episode()?)?;
                Ok(heraclitus_tier::AnyDemotionReceipt::V2(Box::new(receipt)))
            }
        }
    }

    /// C2.6 — um tick de compaction do cold tier, disparado pela
    /// [`heraclitus_tier::CompactionPolicy`]: para cada segmento demotado
    /// (recibo mais recente da cadeia), conta os eventos LOGICAMENTE apagados
    /// ainda presentes no objeto (tombstones semânticos `attrs.tombstone_of`
    /// cujo alvo cai no range LSN do segmento, menos os já removidos pela
    /// cadeia de compactions) e, se a política disparar, reescreve o objeto
    /// sem eles e appenda o novo recibo pelo caminho unificado §2.6.
    /// Devolve os recibos novos (vazio = nada a compactar).
    #[cfg(feature = "tier")]
    pub async fn tier_compaction_tick(
        &self,
        policy: &heraclitus_tier::CompactionPolicy,
    ) -> Result<Vec<heraclitus_tier::DemotionReceipt>, HeraclitusError> {
        use std::collections::{HashMap, HashSet};
        // 1. Tombstones semânticos: alvo → LSN do alvo (via o índice de grafo).
        //    Scan janelado do log à procura de `tombstone_of` (a mesma regra do
        //    VectorIndex); o LSN do alvo resolve o segmento a que pertence.
        let mut tombstoned: HashSet<heraclitus_core::EventId> = HashSet::new();
        let head = self.log.head();
        let mut cur = 0u64;
        while cur < head {
            let batch = self.log.scan_capped(cur, head, 100_000)?;
            let Some(&(last, _)) = batch.last() else {
                break;
            };
            for (_, ep) in &batch {
                if let Some(t) = ep.attrs.get("tombstone_of") {
                    if let Ok(id) = t.parse::<heraclitus_core::EventId>() {
                        tombstoned.insert(id);
                    }
                }
            }
            cur = last + 1;
        }
        if tombstoned.is_empty() {
            return Ok(Vec::new());
        }
        let tomb_lsns: Vec<Lsn> = {
            let g = self.graph.read().unwrap();
            tombstoned.iter().filter_map(|id| g.lsn_of(id)).collect()
        };

        // 2. Recibo MAIS RECENTE por segmento + total já removido pela cadeia.
        let mut latest: HashMap<SegmentId, heraclitus_tier::DemotionReceipt> = HashMap::new();
        let mut dropped_so_far: HashMap<SegmentId, u64> = HashMap::new();
        for r in self.demotion_receipts()? {
            *dropped_so_far.entry(r.segment_id).or_default() += r.dropped;
            latest.insert(r.segment_id, r); // ordem do log ⇒ o último é o mais novo
        }

        // 3. Trigger + rewrite por segmento.
        let cold = self.open_cold_tier()?;
        let mut out = Vec::new();
        for (seg, receipt) in latest {
            let in_range = tomb_lsns
                .iter()
                .filter(|l| **l >= receipt.min_lsn && **l <= receipt.max_lsn)
                .count() as u64;
            let still_present =
                in_range.saturating_sub(dropped_so_far.get(&seg).copied().unwrap_or(0));
            if !policy.should_compact(still_present, receipt.record_count) {
                continue;
            }
            let new_receipt = cold
                .compact_cold_prepared(&receipt, |_lsn, ep| tombstoned.contains(&ep.id))
                .await?;
            // §2.6: o recibo novo entra pelo caminho unificado (indexa + consenso).
            self.append(heraclitus_tier::ColdTier::receipt_episode(&new_receipt)?)?;
            out.push(new_receipt);
        }
        Ok(out)
    }

    /// Verifica um recibo de demote: re-computa o Merkle do objeto cold e confere.
    #[cfg(feature = "tier")]
    pub async fn verify_demotion(
        &self,
        receipt: &heraclitus_tier::DemotionReceipt,
    ) -> Result<bool, HeraclitusError> {
        let cold = self.open_cold_tier()?;
        cold.verify_receipt(receipt).await
    }

    #[cfg(feature = "tier")]
    pub async fn verify_demotion_v2(
        &self,
        receipt: &heraclitus_tier::DemotionReceiptV2,
    ) -> Result<bool, HeraclitusError> {
        let cold = self.open_cold_tier_v6()?;
        let report = cold
            .verify_generation(
                receipt,
                heraclitus_log::v6::IntegrityLevel::Logical,
                Some(&heraclitus_log::v6::persisted_record_hash),
            )
            .await?;
        self.cold_range_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.cold_bytes_downloaded.fetch_add(
            report.bytes_downloaded,
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(report.is_ok())
    }

    /// Os recibos de demote no log (o que já foi materializado no cold tier).
    /// Scan JANELADO do log (R20: o scan sem teto materializava o log inteiro
    /// num Vec — a mesma classe do R9/R10; op de manutenção não é desculpa
    /// para um alloc proporcional ao log).
    ///
    /// Devolve **só** os recibos v1, que são os que o caminho `cold/…` desta
    /// build sabe reler. Os v2 (SPEC-0050 §86) aparecem em
    /// [`Self::demotion_receipts_any`].
    #[cfg(feature = "tier")]
    pub fn demotion_receipts(
        &self,
    ) -> Result<Vec<heraclitus_tier::DemotionReceipt>, HeraclitusError> {
        Ok(self
            .demotion_receipts_any()?
            .into_iter()
            .filter_map(|r| match r {
                heraclitus_tier::AnyDemotionReceipt::V1(v1) => Some(v1),
                heraclitus_tier::AnyDemotionReceipt::V2(_) => None,
            })
            .collect())
    }

    /// Todos os recibos de demote, de qualquer versão.
    ///
    /// A discriminação é feita por `receipt_version`
    /// ([`heraclitus_tier::receipts_v2::decode_receipt_payload`]) e não por
    /// tentativa de desserialização: um recibo v2 lido com o `serde` do v1
    /// falha em silêncio e **desaparece** da listagem, o que faria um segmento
    /// demotado parecer nunca ter sido demotado.
    #[cfg(feature = "tier")]
    pub fn demotion_receipts_any(
        &self,
    ) -> Result<Vec<heraclitus_tier::AnyDemotionReceipt>, HeraclitusError> {
        let head = self.log.head();
        let mut out = Vec::new();
        let mut cur = 0u64;
        while cur < head {
            let batch = self.log.scan_capped(cur, head, 100_000)?;
            let Some(&(last, _)) = batch.last() else {
                break;
            };
            for (_lsn, ep) in &batch {
                if ep.kind == EventKind::DemotionReceipt {
                    if let Ok(r) = heraclitus_tier::receipts_v2::decode_receipt_payload(&ep.content)
                    {
                        out.push(r);
                    }
                }
            }
            cur = last + 1;
        }
        Ok(out)
    }

    /// Recall-on-demand: busca do cold tier os episódios de um segmento demotado
    /// (o recibo mais recente para esse segmento). Feature `tier`. NÃO reinsere
    /// nos índices quentes — devolve os episódios frios ao chamador.
    #[cfg(feature = "tier")]
    pub async fn fetch_cold_segment(
        &self,
        segment_id: SegmentId,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        let receipt = self
            .demotion_receipts_any()?
            .into_iter()
            .rev()
            .find(|r| match r {
                heraclitus_tier::AnyDemotionReceipt::V1(v1) => v1.segment_id == segment_id,
                heraclitus_tier::AnyDemotionReceipt::V2(v2) => v2.segment_id == segment_id,
            })
            .ok_or_else(|| {
                HeraclitusError::Query(format!("sem recibo de demote para o segmento {segment_id}"))
            })?;
        match receipt {
            heraclitus_tier::AnyDemotionReceipt::V1(v1) => {
                let cold = self.open_cold_tier()?;
                cold.fetch_cold(&v1).await
            }
            heraclitus_tier::AnyDemotionReceipt::V2(v2) => {
                let cold = self.open_cold_tier_v6()?;
                let (events, stats) = cold
                    .recall_lsn_range(&v2.key()?, v2.first_lsn, v2.last_lsn)
                    .await?;
                self.cold_range_reads
                    .fetch_add(stats.requests, std::sync::atomic::Ordering::Relaxed);
                self.cold_bytes_downloaded
                    .fetch_add(stats.bytes_fetched, std::sync::atomic::Ordering::Relaxed);
                Ok(events)
            }
        }
    }

    /// §3.9 — um tick de consolidação (distill): agrupa os episódios de
    /// Observação NOVOS (desde o cursor) na variedade e emite um `Fact`
    /// (`FactDerived`) por cluster estável, via `Engine::append` (caminho
    /// unificado §2.6 — indexado ao vivo ≡ boot-replay + consenso quando ativo).
    /// Avança e persiste o cursor. Devolve os LSNs dos Facts appendados.
    ///
    /// v0 honesto: o clustering vê a janela `[cursor, head)` capada por
    /// `QUERY_SCAN_CAP` de uma vez (agglomerativo precisa dos pontos juntos) —
    /// clusters que atravessam a fronteira de um tick/cap ficam partidos, e um
    /// erro de `append` a meio pode deixar Facts emitidos sem o cursor avançar
    /// (re-emissão no próximo tick). Ambos aceitáveis para consolidação
    /// aproximada; documentados. NÃO correr sob replicação (cursor local ao nó).
    #[cfg(feature = "distill")]
    pub fn distill_tick(
        &self,
        cfg: &heraclitus_distill::DistillConfig,
    ) -> Result<Vec<Lsn>, HeraclitusError> {
        use heraclitus_compliance::{
            classify_derived_episode, ClassificationPolicy, SourceClassification,
        };
        use std::collections::HashMap as StdHashMap;
        use std::sync::atomic::Ordering;
        let from = self.distill_cursor.load(Ordering::Acquire);
        let head = self.log.head();
        if from >= head {
            return Ok(Vec::new());
        }
        let episodes =
            self.log
                .scan_capped(from, head, heraclitus_query::backend::QUERY_SCAN_CAP)?;
        // Fronteira coberta: o próximo tick continua daqui (não do head, para o
        // caso de o cap ter truncado a janela).
        let next_cursor = episodes.last().map(|(l, _)| l + 1).unwrap_or(head);

        let distiller = heraclitus_distill::Distiller::new(self.metric.clone(), cfg.clone());
        let mut facts = distiller.distill_episodes(&episodes, head)?;

        // SPEC-0046: classificação acompanha a proveniência real do distill.
        // Preparar TODOS os Facts antes de appendar evita uma emissão parcial se
        // uma fonte estiver sem rótulo ou a política não puder ser validada.
        let sources_by_id: StdHashMap<_, _> = episodes
            .iter()
            .map(|(_, episode)| (episode.id, episode))
            .collect();
        let mut classification_policy: Option<ClassificationPolicy> = None;
        for fact in &mut facts {
            let classified_parent_count = fact
                .parents
                .iter()
                .filter_map(|id| sources_by_id.get(id))
                .filter(|source| source.attrs.contains_key("classification.label"))
                .count();
            if classified_parent_count == 0 {
                continue;
            }
            if classified_parent_count != fact.parents.len() {
                return Err(HeraclitusError::Config(
                    "distill recusado: cluster mistura fontes classificadas e sem classificação"
                        .into(),
                ));
            }

            if classification_policy.is_none() {
                let data_dir = self.attr_dir.parent().unwrap_or(self.attr_dir.as_path());
                let path = data_dir
                    .join("compliance")
                    .join("classification-policy.json");
                let raw = std::fs::read(&path).map_err(|error| {
                    HeraclitusError::Config(format!(
                        "fontes classificadas exigem política em {}: {error}",
                        path.display()
                    ))
                })?;
                let policy: ClassificationPolicy =
                    serde_json::from_slice(&raw).map_err(|error| {
                        HeraclitusError::Config(format!(
                            "política de classificação inválida em {}: {error}",
                            path.display()
                        ))
                    })?;
                policy.validate().map_err(|error| {
                    HeraclitusError::Config(format!(
                        "política de classificação inválida em {}: {error}",
                        path.display()
                    ))
                })?;
                if policy.identity.effective_from > head {
                    return Err(HeraclitusError::Config(format!(
                        "política de classificação {} só vigora a partir do LSN {} (head atual: {head})",
                        policy.identity.policy_id, policy.identity.effective_from
                    )));
                }
                classification_policy = Some(policy);
            }

            let sources: Vec<SourceClassification> = fact
                .parents
                .iter()
                .map(|id| {
                    let source = sources_by_id.get(id).ok_or_else(|| {
                        HeraclitusError::Config(format!(
                            "distill perdeu a fonte classificada {id} da janela corrente"
                        ))
                    })?;
                    let label = source
                        .attrs
                        .get("classification.label")
                        .cloned()
                        .ok_or_else(|| {
                            HeraclitusError::Config(format!(
                                "fonte {id} não possui classification.label"
                            ))
                        })?;
                    Ok(SourceClassification {
                        event_id: *id,
                        label,
                    })
                })
                .collect::<Result<_, HeraclitusError>>()?;
            classify_derived_episode(
                fact,
                &sources,
                None,
                None,
                classification_policy
                    .as_ref()
                    .expect("policy was loaded for classified sources"),
            )
            .map_err(|error| {
                HeraclitusError::Config(format!(
                    "não foi possível classificar FactDerived {}: {error}",
                    fact.id
                ))
            })?;
        }
        let mut out = Vec::with_capacity(facts.len());
        for ev in facts {
            out.push(self.append(ev)?); // §2.6
        }

        self.distill_cursor.store(next_cursor, Ordering::Release);
        // Persistência do cursor: tmp + fsync + rename + fsync do directório.
        //
        // O comentário anterior dizia "nunca perde dados", e isso é verdade
        // pela metade: um cursor perdido não apaga nada, mas volta a appendar
        // os `FactDerived` de uma janela já derivada — e num log append-only
        // esses duplicados ficam lá para sempre. Sem fsync, uma falha de
        // energia deixava 8 bytes a zeros, que o leitor aceitava como cursor 0
        // (é um valor legítimo) e re-derivava a base inteira.
        //
        // Guardam-se 16 bytes: o valor e o seu complemento. Um ficheiro a
        // zeros deixa de ser indistinguível de um cursor válido, sem precisar
        // de checksum para oito bytes. O formato antigo de 8 bytes continua a
        // ser lido, para uma actualização não forçar uma re-derivação.
        let path = self.attr_dir.join("distill.cursor");
        let tmp = self.attr_dir.join("distill.cursor.tmp");
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&next_cursor.to_le_bytes());
        bytes[8..].copy_from_slice(&(!next_cursor).to_le_bytes());
        let gravado = (|| -> std::io::Result<()> {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            Ok(())
        })();
        if gravado.is_ok() && std::fs::rename(&tmp, &path).is_ok() {
            #[cfg(unix)]
            if let Ok(d) = std::fs::File::open(&self.attr_dir) {
                let _ = d.sync_all();
            }
        } else {
            let _ = std::fs::remove_file(&tmp);
        }
        Ok(out)
    }

    /// Prova de reconstrucao determinista.
    ///
    /// A afirmacao mais forte deste sistema perante um auditor nao e "o painel
    /// mostrou isto naquele dia" — e **"consigo reconstruir o estado que levou
    /// a esta conclusao"**. O contrato ja existe e e testado (`state_hash`
    /// identico entre replays), mas nunca esteve visivel.
    ///
    /// Com `executar = false` devolve so os hashes atuais: barato, nao mexe em
    /// nada, e permite a um auditor comparar com os de outra instancia ou de
    /// outro momento.
    ///
    /// Com `executar = true` reconstroi as views a partir do LSN 0 e compara os
    /// hashes antes/depois. Se baterem, o replay e determinista **agora, sobre
    /// este log** — que e diferente de "os testes dizem que e". E caro e mexe
    /// nas views vivas, por isso e a pedido explicito.
    pub fn replay_prova(&self, executar: bool) -> serde_json::Value {
        let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let antes = hex(self.graph_state_hash());
        let head = self.log.head();

        if !executar {
            return serde_json::json!({
                "executado": false,
                "head": head,
                "graph_state_hash": antes,
                "nota": "Hashes do estado atual. Reconstruir e comparar exige `executar=true`.",
            });
        }

        let t0 = std::time::Instant::now();
        if let Err(e) = self.rebuild(None) {
            return serde_json::json!({
                "executado": true, "ok": false, "erro": e.to_string(),
            });
        }
        let depois = hex(self.graph_state_hash());
        serde_json::json!({
            "executado": true,
            "ok": antes == depois,
            "head": head,
            "hash_antes": antes,
            "hash_depois": depois,
            "segundos": t0.elapsed().as_secs_f64(),
            "nota": if antes == depois {
                "Estado reconstruido a partir do LSN 0 e IDENTICO ao anterior."
            } else {
                "DIVERGENCIA: a reconstrucao nao reproduziu o estado. Isto e um incidente."
            },
        })
    }

    /// Fontes que escrevem neste log: quem, quanto, e desde/ate quando.
    ///
    /// Numa plataforma forense, **uma fonte que se cala e um incidente** — pode
    /// ser o atacante a desligar o log. Este endpoint da a materia-prima para
    /// detetar isso: com o instante do ultimo evento de cada fonte, o painel
    /// compara com o ritmo historico dela e assinala silencio.
    ///
    /// Sai do indice `_agent`, nao de um varrimento: duas leituras por fonte
    /// (o primeiro e o ultimo LSN, que sao as pontas dos postings ordenados).
    pub fn fontes(&self) -> serde_json::Value {
        let vals = self.attr.read().unwrap().field_values("_agent");
        let mut fontes = Vec::with_capacity(vals.len());
        let (mut global_min, mut global_max) = (u64::MAX, 0u64);

        for (agente, eventos) in vals {
            let span = self.attr.read().unwrap().field_span("_agent", &agente);
            let (mut primeiro_ms, mut ultimo_ms) = (None, None);
            if let Some((a, b)) = span {
                if let Ok(Some((_, ep))) = self.log.read(a) {
                    let ms = ep.ts_hlc >> 16;
                    primeiro_ms = Some(ms);
                    global_min = global_min.min(ms);
                }
                if let Ok(Some((_, ep))) = self.log.read(b) {
                    let ms = ep.ts_hlc >> 16;
                    ultimo_ms = Some(ms);
                    global_max = global_max.max(ms);
                }
            }
            fontes.push(serde_json::json!({
                "agente": agente,
                "eventos": eventos,
                "primeiro_ms": primeiro_ms,
                "ultimo_ms": ultimo_ms,
                "primeiro_lsn": span.map(|s| s.0),
                "ultimo_lsn": span.map(|s| s.1),
            }));
        }

        serde_json::json!({
            "fontes": fontes,
            // Retencao: o evento mais antigo do log. O Marco Civil (12.965/2014)
            // obriga a guardar registos de conexao 1 ano e de aplicacao 6 meses;
            // a LGPD obriga a NAO guardar alem do necessario. Os dois lados
            // precisam deste numero.
            "mais_antigo_ms": if global_min == u64::MAX { None } else { Some(global_min) },
            "mais_recente_ms": if global_max == 0 { None } else { Some(global_max) },
            "head": self.log.head(),
        })
    }

    /// Caracteristicas de UMA fonte: que tipos de evento produz, que campos
    /// preenche, e sob que principal autenticado escreve.
    ///
    /// Num SOC a pergunta nao e so "quem escreve" — e "o que e que esta fonte
    /// mete no log". Um agente que sempre mandou `Observation` e comeca a
    /// mandar outra coisa, ou que passa a preencher um campo novo, mudou de
    /// comportamento; e isso e a materia-prima de uma deteccao.
    ///
    /// Le eventos, portanto tem tecto (`amostra_max`). Com o tecto atingido, o
    /// resultado diz `amostrado: true` — uma distribuicao calculada sobre parte
    /// dos dados nao pode ser apresentada como se fosse sobre todos.
    pub fn fonte_detalhe(&self, agente: &str, amostra_max: usize) -> serde_json::Value {
        let lsns: Vec<Lsn> = self.attr.read().unwrap().lookup("_agent", agente).to_vec();
        let total = lsns.len();
        // Amostra pelas pontas: os mais RECENTES importam mais para saber o que
        // a fonte faz agora, mas os primeiros mostram como comecou.
        let lidos: Vec<Lsn> = if total <= amostra_max {
            lsns.clone()
        } else {
            let metade = amostra_max / 2;
            lsns.iter()
                .take(metade)
                .chain(lsns.iter().rev().take(amostra_max - metade))
                .copied()
                .collect()
        };

        let mut tipos: std::collections::BTreeMap<String, u64> = Default::default();
        let mut campos: std::collections::BTreeMap<String, u64> = Default::default();
        let mut principais: std::collections::BTreeMap<String, u64> = Default::default();
        let mut sessoes: std::collections::BTreeSet<String> = Default::default();
        let (mut bytes, mut n) = (0u64, 0u64);

        for lsn in lidos {
            if let Ok(Some((_, ep))) = self.log.read(lsn) {
                n += 1;
                bytes += ep.content.len() as u64;
                let k = match &ep.kind {
                    heraclitus_core::EventKind::Custom(s) => s.clone(),
                    outro => format!("{outro:?}"),
                };
                *tipos.entry(k).or_insert(0) += 1;
                for campo in ep.attrs.keys() {
                    *campos.entry(campo.clone()).or_insert(0) += 1;
                }
                if let Some(p) = ep.attrs.get("__heraclitus_authenticated_principal") {
                    *principais.entry(p.clone()).or_insert(0) += 1;
                }
                if !ep.session_id.is_empty() {
                    sessoes.insert(ep.session_id.clone());
                }
            }
        }

        serde_json::json!({
            "agente": agente,
            "eventos": total,
            "amostrado": total > amostra_max,
            "amostra": n,
            "tipos": tipos,
            "campos": campos,
            // Quem escreveu, do ponto de vista da AUTENTICACAO — distinto do
            // `agent_id`, que e a quem os dados dizem respeito. Uma fonte que
            // muda de principal e uma mudanca de quem tem a credencial.
            "principais": principais,
            "sessoes": sessoes.len(),
            "bytes_medios": bytes.checked_div(n).unwrap_or(0),
        })
    }

    /// Campos indexados e a cardinalidade de cada um.
    ///
    /// Responde "que categorias de dados estao a ser tratadas?" a partir do que
    /// esta MESMO no log — o inverso de um registo de tratamento mantido a mao,
    /// que descreve o que alguem se lembrou de escrever.
    ///
    /// So nomes de campo e contagens: nunca valores. Listar os valores de um
    /// campo `cpf` seria despejar os CPFs todos.
    pub fn atributos(&self) -> serde_json::Value {
        let campos = self.attr.read().unwrap().fields();
        let lista: Vec<_> = campos
            .into_iter()
            .map(|(campo, distintos)| {
                serde_json::json!({
                    "campo": campo,
                    "valores_distintos": distintos,
                })
            })
            .collect();
        serde_json::json!({ "campos": lista })
    }

    /// O ultimo LSN escrito (exclusivo: o proximo append usa este valor).
    pub fn head(&self) -> Lsn {
        self.log.head()
    }

    /// Estado derivado de saúde de um sensor. `as_of_lsn` é exclusivo, como
    /// nas consultas `AS OF LSN n`; sem limite usa o head atual do log.
    pub fn telemetry_health(
        &self,
        identity: &SensorIdentity,
        as_of_lsn: Option<Lsn>,
    ) -> Option<TelemetryHealthSnapshot> {
        let bound = as_of_lsn.unwrap_or_else(|| self.log.head());
        self.telemetry_health
            .write()
            .unwrap()
            .snapshot_as_of(identity, bound)
    }

    /// Snapshot ordenado de todos os sensores conhecidos até o LSN exclusivo.
    pub fn telemetry_health_all(&self, as_of_lsn: Option<Lsn>) -> Vec<TelemetryHealthSnapshot> {
        let bound = as_of_lsn.unwrap_or_else(|| self.log.head());
        self.telemetry_health
            .write()
            .unwrap()
            .snapshots_as_of(bound)
    }

    /// O carimbo de ingestao (ms epoch) do evento em `lsn`, se legivel.
    pub fn ts_ms(&self, lsn: Lsn) -> Option<u64> {
        match self.log.read(lsn) {
            Ok(Some((_, ep))) => Some(ep.ts_hlc >> 16),
            _ => None,
        }
    }

    /// O LSN a partir do qual os eventos foram registados em/depois de `ms`.
    ///
    /// O `ts_hlc` e carimbado pelo `Log::append`, e o HLC e monotono — logo a
    /// ordem dos LSN E a ordem do tempo de INGESTAO, e uma busca binaria sobre
    /// o log resolve isto em O(log n) leituras em vez de um varrimento.
    ///
    /// Atencao ao que isto significa: o tempo aqui e quando o registo ENTROU,
    /// nao quando o facto aconteceu no mundo. Um lote importado ontem de logs
    /// da semana passada aparece com o carimbo de ontem.
    pub fn lsn_em(&self, ms: u64) -> Lsn {
        let (mut lo, mut hi) = (0u64, self.log.head());
        while lo < hi {
            let meio = lo + (hi - lo) / 2;
            match self.log.read(meio) {
                Ok(Some((_, ep))) if (ep.ts_hlc >> 16) < ms => lo = meio + 1,
                // Buraco no log (LSN sem registo legivel): trata-se como
                // "ainda nao chegou a `ms`" para a busca continuar em vez de
                // parar num ponto arbitrario.
                Ok(None) | Err(_) => lo = meio + 1,
                _ => hi = meio,
            }
        }
        lo
    }

    /// Diff entre dois instantes do log: o que existe em `ate` que nao existia
    /// em `de`, campo a campo.
    ///
    /// Num log append-only nada e apagado, por isso um diff **nao pode** mostrar
    /// remocoes. Mostra as duas coisas que um investigador de facto procura:
    ///
    ///  - **apareceu** — um valor cujo primeiro registo cai dentro da janela.
    ///    Um IP, um utilizador, um comando que o sistema nunca tinha visto.
    ///  - **calou-se** — um valor que existia antes e nao produziu nada na
    ///    janela. Numa plataforma forense isto pesa tanto como o resto: uma
    ///    fonte que emudece pode ser o atacante a desligar o registo.
    ///
    /// Sai todo do indice de atributos — nao le o log, tirando as duas leituras
    /// para carimbar as pontas da janela.
    pub fn diff(&self, de: Lsn, ate: Lsn, topo: usize) -> serde_json::Value {
        let head = self.log.head();
        let ate = ate.min(head);
        let de = de.min(ate);

        let campos = self.attr.read().unwrap().diff(de, ate, topo);
        let ms = |lsn: Lsn| self.ts_ms(lsn);

        serde_json::json!({
            "de": de,
            "ate": ate,
            "head": head,
            "eventos": ate.saturating_sub(de),
            "de_ms": ms(de),
            // `ate` e exclusivo: o ultimo evento DENTRO da janela e `ate - 1`.
            "ate_ms": if ate > de { ms(ate - 1) } else { None },
            // A janela ANTERIOR de igual duracao e o termo de comparacao de
            // "calou-se" e de "disparou". Vai no JSON para o painel poder
            // dizer contra o que compara, em vez de o subentender.
            "anterior_de": de.saturating_sub(ate.saturating_sub(de)),
            "anterior_ate": de,
            "campos": campos,
            "nota": "Janela [de, ate), comparada com a janela anterior de igual \
                     duracao. O tempo e o de INGESTAO (carimbo do append), nao o \
                     momento em que o facto ocorreu no mundo.",
        })
    }

    /// Pegada de um titular no log: quantos eventos, de que tipos, desde
    /// quando, e se a chave dele ainda existe.
    ///
    /// Responde ao que a LGPD art. 18 (I e II) obriga a conseguir responder —
    /// confirmação da existência do tratamento e acesso aos dados — e é a
    /// base do ecrã do titular no painel.
    ///
    /// Usa o índice `_agent` do `AttrIndex`. Um índice construído antes de
    /// esse campo existir não o tem: `indexado: false` diz isso em vez de
    /// devolver zero eventos e deixar alguém concluir que não há dados
    /// nenhuns sobre a pessoa. Nesse caso, `rebuild` resolve.
    pub fn titular(&self, agent_id: &str, limite: usize) -> serde_json::Value {
        let lsns: Vec<Lsn> = {
            let attr = self.attr.read().unwrap();
            attr.lookup("_agent", agent_id).to_vec()
        };
        // O índice conhece o campo `_agent`? Se não conhecer, foi construído
        // antes desta funcionalidade — e aí "0 eventos" NÃO é uma resposta, é
        // uma ausência de índice. Dizer a um titular "não temos nada sobre si"
        // por causa de um índice desatualizado é uma declaração falsa.
        //
        // Nota: os frames H-VM (`hvm_isa`) são excluídos dos índices por
        // desenho (`index_applied`) — vivem no replay da VM. Um log só com
        // esses frames dá `agentes_indexados: 0` legitimamente.
        let agentes_indexados = self.attr.read().unwrap().field_entries("_agent");

        let mut tipos: std::collections::BTreeMap<String, u64> = Default::default();
        let mut amostra = Vec::new();
        let (mut primeiro_ms, mut ultimo_ms) = (u64::MAX, 0u64);
        for &lsn in &lsns {
            if let Ok(Some((_, ep))) = self.log.read(lsn) {
                let kind = match &ep.kind {
                    heraclitus_core::EventKind::Custom(s) => s.clone(),
                    outro => format!("{outro:?}"),
                };
                *tipos.entry(kind.clone()).or_insert(0) += 1;
                let ms = ep.ts_hlc >> 16;
                primeiro_ms = primeiro_ms.min(ms);
                ultimo_ms = ultimo_ms.max(ms);
                if amostra.len() < limite {
                    // METADADOS apenas. O conteúdo não sai por aqui: este
                    // endpoint existe para provar tratamento, não para o expor.
                    amostra.push(serde_json::json!({
                        "lsn": lsn,
                        "kind": kind,
                        "bytes": ep.content.len(),
                        "t_ms": ms,
                        "atributos": ep.attrs.len(),
                    }));
                }
            }
        }

        serde_json::json!({
            "titular": agent_id,
            "eventos": lsns.len(),
            "tipos": tipos,
            "primeiro_ms": if primeiro_ms == u64::MAX { serde_json::Value::Null } else { primeiro_ms.into() },
            "ultimo_ms": if ultimo_ms == 0 { serde_json::Value::Null } else { ultimo_ms.into() },
            "cifrado": self.keystore.is_some(),
            // `false` com `cifrado: true` = a chave foi destruída: os dados
            // deste titular já foram eliminados por crypto-shred.
            "chave_presente": self
                .keystore
                .as_ref()
                // `get` devolve `None` quando a chave nao existe — que e
                // exatamente o estado pos-shred. Nao se usa a chave para nada:
                // so se pergunta se ainda la esta.
                .map(|ks| ks.get(agent_id).is_some())
                .unwrap_or(false),
            // `false` = este índice não conhece o campo do titular; a contagem
            // acima não é de confiança e um `rebuild` resolve.
            "indexado": agentes_indexados > 0,
            "agentes_indexados": agentes_indexados,
            "amostra": amostra,
        })
    }

    /// Eventos de auditoria que mencionam este titular.
    ///
    /// O `audit_queries` transforma cada consulta GQL num evento do log — quem
    /// consultou o quê é, ele próprio, prova. Aqui procuram-se os que citam
    /// este identificador, mais os `shred:<id>` do `AuditAdmin`.
    ///
    /// **Ressalva:** é uma procura por menção no texto registado, não um
    /// índice de "acessos a este titular". Uma consulta que devolva dados dele
    /// sem o nomear não aparece. É o que a informação atual permite afirmar.
    pub fn titular_acessos(&self, agent_id: &str, limite: usize) -> serde_json::Value {
        let head = self.log.head();
        let mut achados = Vec::new();
        let mut cur = 0u64;
        while cur < head && achados.len() < limite {
            let lote = match self.log.scan_capped(cur, head, 20_000) {
                Ok(l) => l,
                Err(_) => break,
            };
            let Some(&(ultimo, _)) = lote.last() else {
                break;
            };
            for (lsn, ep) in &lote {
                let e_auditoria = ep.attrs.contains_key("audit");
                if !e_auditoria {
                    continue;
                }
                let texto = String::from_utf8_lossy(&ep.content);
                let operacao = ep.attrs.get("operation").cloned().unwrap_or_default();
                if !texto.contains(agent_id) && !operacao.contains(agent_id) {
                    continue;
                }
                achados.push(serde_json::json!({
                    "lsn": lsn,
                    "t_ms": ep.ts_hlc >> 16,
                    "tipo": ep.attrs.get("audit").cloned().unwrap_or_default(),
                    "principal": ep.attrs.get("principal").cloned().unwrap_or_default(),
                    "operacao": operacao,
                    "ok": ep.attrs.get("ok").cloned().unwrap_or_default(),
                }));
                if achados.len() >= limite {
                    break;
                }
            }
            cur = ultimo + 1;
        }
        serde_json::json!({ "titular": agent_id, "acessos": achados })
    }

    /// Crypto-shred (§3.10): destroy an agent's encryption key so all of its
    /// sealed content becomes permanently unreadable. The log is never mutated.
    /// Errors if encryption at rest is disabled.
    pub fn shred(&self, agent_id: &str) -> Result<bool, HeraclitusError> {
        let ks = self.keystore.as_ref().ok_or_else(|| {
            HeraclitusError::Config("encryption at rest is disabled; nothing to shred".into())
        })?;
        self.ensure_crypto_shred_allowed(agent_id)?;
        std::fs::create_dir_all(&self.attr_dir)?;
        let marker = self.attr_dir.join("privacy-rebuild-required");
        let recovery_pending = marker.exists();
        if !recovery_pending {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&marker)?;
            f.write_all(b"rebuild all derived state before serving\n")?;
            f.sync_all()?;
            // O `sync_all` torna o CONTEÚDO durável, não a existência do
            // ficheiro. Sem o fsync do directório, uma falha de energia entre
            // criar o marcador e destruir a chave deixava o shred feito e o
            // marcador desaparecido — o arranque seguinte não sabia que tinha
            // de reconstruir, e o plaintext dessa agente ficava nas views e
            // nos índices depois de a chave ter sido destruída. É precisamente
            // a janela que este marcador existe para cobrir.
            #[cfg(unix)]
            if let Ok(d) = std::fs::File::open(&self.attr_dir) {
                d.sync_all()?;
            }
        }

        let destroyed = ks.shred(agent_id)?;
        if !destroyed && !recovery_pending {
            // Sem chave e sem operação interrompida: idempotência normal.
            let _ = std::fs::remove_file(&marker);
            return Ok(false);
        }

        self.memtable.clear();
        {
            let mut views = self.views.lock().unwrap();
            views.rebuild(&self.log, None)?;
            views.checkpoint()?;
        }

        let mut rebuilt = AttrIndex::new();
        let head = self.log.head();
        let mut cur = 0u64;
        while cur <= head {
            let batch = self.log.scan_capped(cur, head.saturating_add(1), 100_000)?;
            let Some(&(last, _)) = batch.last() else {
                break;
            };
            for (lsn, ep) in &batch {
                if !vm_bridge::is_hvm(ep) {
                    rebuilt.apply(*lsn, ep);
                }
            }
            cur = last.saturating_add(1);
        }
        rebuilt.save(&self.attr_dir)?;
        *self.attr.write().unwrap() = rebuilt;

        let subject_hash = blake3::hash(agent_id.as_bytes()).to_hex().to_string();
        let mut receipt = Episode::new(
            "heraclitus-privacy",
            EventKind::Custom("PrivacyErasureReceipt".into()),
            b"derived state rebuilt after crypto-shred".to_vec(),
        );
        receipt
            .attrs
            .insert("subject_key_hash".into(), subject_hash);
        receipt
            .attrs
            .insert("operation".into(), "crypto-shred".into());
        self.append(receipt)?;
        std::fs::remove_file(marker)?;
        Ok(destroyed || recovery_pending)
    }

    /// Fail-closed compliance gate for the irreversible key destruction.
    ///
    /// Legal holds are resolved from their append-only events, not only from
    /// sealed-segment HRKM flags, so a hold also protects an active tail that
    /// has not sealed yet. Regulatory `PreventDestruction`, protected retention
    /// classes and non-public classification independently veto the operation.
    fn ensure_crypto_shred_allowed(&self, agent_id: &str) -> Result<(), HeraclitusError> {
        let head = self.log.head();
        let state = RegulatoryState::replay(self.log.as_ref(), head).map_err(|error| {
            HeraclitusError::Config(format!(
                "crypto-shred bloqueado: estado regulatório inválido: {error}"
            ))
        })?;
        if let Some(record) =
            state.decisions.iter().find(|record| {
                record.decision.context.subject_id == agent_id
                    && record.decision.requirements.iter().any(|requirement| {
                        requirement.effect == RequirementEffect::PreventDestruction
                    })
            })
        {
            return Err(HeraclitusError::Config(format!(
                "crypto-shred bloqueado pela decisão regulatória {}",
                record.decision.decision_id
            )));
        }

        let active_holds: Vec<_> = state
            .active_holds()
            .map(|record| {
                (
                    record.hold.hold_id.as_str(),
                    record.hold.scope.lsn_start,
                    record.hold.scope.lsn_end,
                )
            })
            .collect();
        let mut cursor = 0;
        while cursor < head {
            let batch = self.log.scan_capped(cursor, head, 100_000)?;
            let Some((last_lsn, _)) = batch.last() else {
                break;
            };
            for (lsn, episode) in &batch {
                if episode.agent_id != agent_id {
                    continue;
                }
                if let Some((hold_id, _, _)) = active_holds
                    .iter()
                    .find(|(_, start, end)| *start <= *lsn && *lsn <= *end)
                {
                    return Err(HeraclitusError::Config(format!(
                        "crypto-shred bloqueado pelo LegalHold {hold_id}"
                    )));
                }
                if episode.attrs.get("retention.class").is_some_and(|class| {
                    matches!(
                        class.as_str(),
                        "incident_evidence"
                            | "permanent_archive"
                            | "classified_information"
                            | "legal_hold"
                    )
                }) {
                    return Err(HeraclitusError::Config(format!(
                        "crypto-shred bloqueado pela classe de retenção no LSN {lsn}"
                    )));
                }
                if episode
                    .attrs
                    .get("classification.rank")
                    .is_some_and(|rank| rank.parse::<u16>().map_or(true, |rank| rank > 0))
                {
                    return Err(HeraclitusError::Config(format!(
                        "crypto-shred bloqueado por informação classificada no LSN {lsn}"
                    )));
                }
            }
            cursor = last_lsn.saturating_add(1);
        }
        Ok(())
    }

    /// Append + synchronously index into memtable AND views.
    /// Read-your-own-writes holds for every index path.
    pub fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        // O kind `hvm_isa` é RESERVADO ao ledger soberano. Qualquer cliente podia
        // escolhê-lo num Append normal (gRPC/REST/GQL) e o efeito era duplo e
        // IRREVERSÍVEL (o log é imutável): (1) `is_hvm` fazia o episódio ser
        // saltado por views/attr/memtable, ficando invisível a todas as queries;
        // e (2) o frame entrava no replay do H-VM, onde bytes arbitrários não
        // decodificam como instrução ISA — envenenando o ledger de forma
        // permanente. As escritas H-VM legítimas usam `append_internal`.
        if vm_bridge::is_hvm(&episode) {
            return Err(HeraclitusError::Query(format!(
                "o kind '{}' é reservado ao ledger H-VM — use /hvm/upsert ou /hvm/delete",
                vm_bridge::HVM_KIND
            )));
        }
        if is_sentinel_reserved(&episode) {
            return Err(HeraclitusError::Query(
                "tipos, agente e atributos sentinel.* / sec.* são reservados ao pipeline interno"
                    .into(),
            ));
        }
        if is_compliance_reserved(&episode) {
            return Err(HeraclitusError::Query(
                "tipos, agente e atributos compliance.* são reservados ao motor regulatório".into(),
            ));
        }
        if episode.attrs.contains_key(IDEMPOTENCY_KEY_ATTR)
            || episode.attrs.contains_key(IDEMPOTENCY_HASH_ATTR)
        {
            return Err(HeraclitusError::Query(
                "atributos de idempotência são reservados; use AppendRequest.idempotency_key"
                    .into(),
            ));
        }
        self.append_internal(episode)
    }

    /// Exactly-once lógico para produtores externos.
    ///
    /// O primeiro request grava a chave e um hash canónico do payload no mesmo
    /// episódio. Um retry byte-equivalente recebe o LSN original; a mesma chave
    /// com dados diferentes é recusada explicitamente. O lock cobre a janela
    /// check→append no líder. Depois de restart o índice é reconstruído do log.
    pub fn append_idempotent(
        &self,
        episode: Episode,
        key: &str,
    ) -> Result<(Lsn, bool, String), HeraclitusError> {
        if is_sentinel_reserved(&episode) {
            return Err(HeraclitusError::Query(
                "tipos, agente e atributos sentinel.* / sec.* são reservados ao pipeline interno"
                    .into(),
            ));
        }
        if is_compliance_reserved(&episode) {
            return Err(HeraclitusError::Query(
                "tipos, agente e atributos compliance.* são reservados ao motor regulatório".into(),
            ));
        }
        if key.is_empty() {
            // O `EventId` é gerado por `Episode::new` ANTES de chegar aqui, e
            // `append_internal` nunca lhe toca (só o `ts_hlc` é carimbado pelo
            // log). Ler o `id` do episódio custa zero; relê-lo do disco, como
            // se fazia, custava uma leitura pontual COMPLETA por append —
            // abrir o ficheiro do segmento, seek, ler o registo e descodificar
            // o bincode — para devolver um valor que já estava em memória.
            // Medido a 2026-08-19: era o desperdício mais caro do caminho de
            // escrita por gRPC. Ver docs/md/auditorias/otimizacao-20m.md §3.5.
            let id = episode.id.to_string();
            let lsn = self.append(episode)?;
            return Ok((lsn, false, id));
        }
        self.append_idempotent_validated(episode, key)
    }

    /// O shard que serializa esta chave. Chaves diferentes que caiam no mesmo
    /// shard partilham lock — é contenção residual, não um erro: a correcção
    /// só precisa que a MESMA chave nunca corra em paralelo consigo própria.
    fn idempotency_shard(&self, key: &str) -> &Mutex<()> {
        let digest = blake3::hash(key.as_bytes());
        let indice = u64::from_le_bytes(digest.as_bytes()[..8].try_into().unwrap_or_default())
            as usize
            % self.idempotency_locks.len();
        &self.idempotency_locks[indice]
    }

    fn append_idempotent_validated(
        &self,
        mut episode: Episode,
        key: &str,
    ) -> Result<(Lsn, bool, String), HeraclitusError> {
        if self.log_only {
            return Err(HeraclitusError::Config(
                "Append idempotente não é permitido em HERACLITUS_LOG_ONLY".into(),
            ));
        }
        if key.len() > 80
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
        {
            return Err(HeraclitusError::Query(
                "idempotency_key deve ter 1..80 caracteres ASCII [A-Za-z0-9._:-]".into(),
            ));
        }
        if vm_bridge::is_hvm(&episode) {
            return Err(HeraclitusError::Query(format!(
                "o kind '{}' é reservado ao ledger H-VM",
                vm_bridge::HVM_KIND
            )));
        }
        if episode.attrs.contains_key(IDEMPOTENCY_KEY_ATTR)
            || episode.attrs.contains_key(IDEMPOTENCY_HASH_ATTR)
        {
            return Err(HeraclitusError::Query(
                "atributos de idempotência são reservados".into(),
            ));
        }

        // EventId/ts_hlc são gerados pelo destino e não participam do hash: um
        // retry legítimo cria um Episode novo antes de chegar aqui.
        let canonical = serde_json::to_vec(&(
            &episode.agent_id,
            &episode.session_id,
            &episode.kind,
            &episode.content,
            &episode.embedding,
            &episode.attrs,
            &episode.valid_from,
            &episode.valid_to,
        ))
        .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        let payload_hash = blake3::hash(&canonical).to_hex().to_string();

        let _guard = self.idempotency_shard(key).lock().unwrap();
        // `.read()` e não `.write()`: `lookup` é `&self`. Tomar o lock de
        // escrita aqui bloqueava o indexador durante toda a secção crítica —
        // que inclui o append durável — por causa de uma consulta.
        let previous = self
            .attr
            .read()
            .unwrap()
            .lookup(IDEMPOTENCY_KEY_ATTR, key)
            .last()
            .copied();
        if let Some(lsn) = previous {
            let (_, existing) = self
                .log
                .read(lsn)?
                .ok_or_else(|| HeraclitusError::Corruption {
                    context: "idempotency index".into(),
                    detail: format!("LSN {lsn} ausente para a chave {key}"),
                })?;
            if existing.attrs.get(IDEMPOTENCY_HASH_ATTR) == Some(&payload_hash) {
                return Ok((lsn, true, existing.id.to_string()));
            }
            return Err(HeraclitusError::IdempotencyConflict {
                key: key.to_string(),
            });
        }

        episode
            .attrs
            .insert(IDEMPOTENCY_KEY_ATTR.into(), key.to_string());
        episode
            .attrs
            .insert(IDEMPOTENCY_HASH_ATTR.into(), payload_hash);
        let lsn = self.append_internal(episode)?;
        let id = self
            .log
            .read(lsn)?
            .ok_or_else(|| HeraclitusError::Corruption {
                context: "append response".into(),
                detail: format!("LSN {lsn} não pôde ser relido"),
            })?
            .1
            .id
            .to_string();
        Ok((lsn, false, id))
    }

    /// Append sem a validação de kind reservado — só para o caminho INTERNO do
    /// H-VM, que precisa mesmo de emitir frames `hvm_isa`.
    fn append_internal(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        // SPEC-015/021: com replicação ativa, a escrita passa pelo consenso (o
        // líder aplica via a state machine, que grava no log de CADA nó e chama
        // de volta `index_applied` aqui). Num não-líder, devolve um erro com o
        // hint do líder — a fonte da verdade continua a ser o log replicado.
        if let Some(router) = self.replication.get() {
            return router.append(episode);
        }
        // Bulk-ingest: grava só no log (RAM limitada p/ cargas massivas). As
        // views/attr se reconstroem depois do log (a fonte da verdade).
        if self.log_only {
            return self.log.append(episode);
        }
        // Indexar o episódio COM o `ts_hlc` carimbado pelo log. Antes indexava-se
        // o original (pré-carimbo, `ts_hlc = 0`) enquanto o log guardava o valor
        // real: as views vivas divergiam das reconstruídas do LSN 0 — quebra do
        // invariante I6 (a `activation` usa `ts_hlc >> 16` como instante de acesso,
        // logo ao vivo registava tudo no instante 0).
        let (lsn, stamped) = self.log.append_stamped(episode)?;
        self.index_applied(lsn, &stamped);
        Ok(lsn)
    }

    /// Authoritative append boundary for the in-process Sentinel.  Keeping it
    /// separate from `append` lets external writers fail closed on reserved
    /// security namespaces while derived writes still follow Engine indexing
    /// (and, when leader ownership is implemented, the Raft router).
    pub(crate) fn append_sentinel_derived(
        &self,
        episode: Episode,
        idempotency_key: &str,
    ) -> Result<Lsn, HeraclitusError> {
        if !is_internal_sentinel_episode(&episode) {
            return Err(HeraclitusError::Query(
                "append_sentinel_derived exige episódio derivado válido do Sentinel".into(),
            ));
        }
        self.append_idempotent_validated(episode, idempotency_key)
            .map(|(lsn, _, _)| lsn)
    }

    pub fn snapshot(&self) -> Lsn {
        self.log.head()
    }

    pub fn rebuild(&self, view: Option<&str>) -> Result<(), HeraclitusError> {
        self.views.lock().unwrap().rebuild(&self.log, view)
    }

    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "head": self.log.head(),
            "storage_format": self.log.format().as_str(),
            "memtable": self.memtable.len(),
            // Contagens: leitura pura. Com `.write()` cada uma esperava pelo
            // checkpoint em curso, e era isso que punha o `/stats` a 44 s.
            "vector_indexed": self.vector.read().unwrap().len(),
            "text_indexed": self.text.read().unwrap().len(),
            "graph_nodes": self.graph.read().unwrap().len(),
            "tgraph_edges": self.tgraph.read().unwrap().edges.len(),
            "entity_keys": self.entity.read().unwrap().mappings.len(),
            "activation_tracked": self.activation.read().unwrap().len(),
            "views": self.views.lock().unwrap().view_names(),
            "storage_metrics": self.storage_metrics(),
        })
    }

    pub fn storage_metrics(&self) -> serde_json::Value {
        let AnyLog::V6(log) = self.log.as_ref() else {
            return serde_json::json!({
                "available": false,
                "reason": "HRKL v6 metrics require storage_format=v6"
            });
        };
        match log.metrics_snapshot() {
            Ok(m) => {
                let cold_range_reads = self
                    .cold_range_reads
                    .load(std::sync::atomic::Ordering::Relaxed);
                let cold_bytes_downloaded = self
                    .cold_bytes_downloaded
                    .load(std::sync::atomic::Ordering::Relaxed);
                serde_json::json!({
                "available": true,
                "hrkl_append_bytes_total": m.hrkl_append_bytes_total,
                "hrkl_raw_bytes": m.hrkl_raw_bytes,
                "hrkl_packed_bytes": m.hrkl_packed_bytes,
                "hrkl_compression_ratio": m.hrkl_compression_ratio,
                "hrkl_pack_queue_depth": m.hrkl_pack_queue_depth,
                "hrkl_pack_seconds": m.hrkl_pack_seconds,
                "hrkl_pack_throughput_bytes_sec": m.hrkl_pack_throughput_bytes_sec,
                "hrkl_blocks_total": m.hrkl_blocks_total,
                "hrkl_blocks_read": m.hrkl_blocks_read,
                "hrkl_blocks_pruned": m.hrkl_blocks_pruned,
                "hrkl_bytes_pruned": m.hrkl_bytes_pruned,
                "hrkl_decompressed_bytes": m.hrkl_decompressed_bytes,
                "hrki_hits": m.hrki_hits,
                "hrki_misses": m.hrki_misses,
                "hrki_rebuilds": m.hrki_rebuilds,
                "cold_range_reads": cold_range_reads,
                "cold_bytes_downloaded": cold_bytes_downloaded,
                "parquet_export_lag_lsn": m.parquet_export_lag_lsn,
                "canonical_verify_failures": m.canonical_verify_failures,
                "physical_crc_failures": m.physical_crc_failures,
                })
            }
            Err(error) => serde_json::json!({
                "available": false,
                "error": error.to_string(),
            }),
        }
    }

    /// Exposição Prometheus text format dos nomes normativos da §150.
    pub fn prometheus_metrics(&self) -> Result<String, HeraclitusError> {
        let AnyLog::V6(log) = self.log.as_ref() else {
            return Err(HeraclitusError::Config(
                "HRKL v6 metrics require storage_format=v6".into(),
            ));
        };
        let m = log.metrics_snapshot()?;
        let cold_range_reads = self
            .cold_range_reads
            .load(std::sync::atomic::Ordering::Relaxed);
        let cold_bytes_downloaded = self
            .cold_bytes_downloaded
            .load(std::sync::atomic::Ordering::Relaxed);
        Ok(format!(
            concat!(
                "hrkl_append_bytes_total {}\n",
                "hrkl_raw_bytes {}\n",
                "hrkl_packed_bytes {}\n",
                "hrkl_compression_ratio {}\n",
                "hrkl_pack_queue_depth {}\n",
                "hrkl_pack_seconds {}\n",
                "hrkl_pack_throughput_bytes_sec {}\n",
                "hrkl_blocks_total {}\n",
                "hrkl_blocks_read {}\n",
                "hrkl_blocks_pruned {}\n",
                "hrkl_bytes_pruned {}\n",
                "hrkl_decompressed_bytes {}\n",
                "hrki_hits {}\n",
                "hrki_misses {}\n",
                "hrki_rebuilds {}\n",
                "cold_range_reads {}\n",
                "cold_bytes_downloaded {}\n",
                "parquet_export_lag_lsn {}\n",
                "canonical_verify_failures {}\n",
                "physical_crc_failures {}\n"
            ),
            m.hrkl_append_bytes_total,
            m.hrkl_raw_bytes,
            m.hrkl_packed_bytes,
            m.hrkl_compression_ratio,
            m.hrkl_pack_queue_depth,
            m.hrkl_pack_seconds,
            m.hrkl_pack_throughput_bytes_sec,
            m.hrkl_blocks_total,
            m.hrkl_blocks_read,
            m.hrkl_blocks_pruned,
            m.hrkl_bytes_pruned,
            m.hrkl_decompressed_bytes,
            m.hrki_hits,
            m.hrki_misses,
            m.hrki_rebuilds,
            cold_range_reads,
            cold_bytes_downloaded,
            m.parquet_export_lag_lsn,
            m.canonical_verify_failures,
            m.physical_crc_failures,
        ))
    }

    pub fn verify(&self) -> Result<serde_json::Value, HeraclitusError> {
        match self.log.as_ref() {
            AnyLog::Legacy(log) => {
                let r = log.verify_durable()?;
                Ok(serde_json::json!({
                    "format": "legacy",
                    "segments": r.segments,
                    "sealed": r.sealed,
                    "records": r.records,
                    "merkle_ok": r.merkle_ok,
                    // `verify_durable` devolve Err assim que a raiz não bate.
                    "ok": true,
                    "sem_raiz": r.sealed.saturating_sub(r.merkle_ok)
                }))
            }
            AnyLog::V6(log) => {
                let manifest = log.manifest();
                let reports = log.verify_sealed(heraclitus_log::v6::IntegrityLevel::Logical)?;
                let active_records = log.verify_active_tail()?;
                let sealed = manifest.segments_v2.len();
                Ok(serde_json::json!({
                    "format": "v6",
                    "segments": sealed,
                    "sealed": sealed,
                    "records": log.head(),
                    "merkle_ok": sealed,
                    "physical_generations_verified": reports.len(),
                    "active_tail_records": active_records,
                    "active_tail_crc_ok": true,
                    "scope": "sealed logical+physical; active framing+crc+payload",
                    "ok": true,
                    "sem_raiz": 0
                }))
            }
        }
    }

    /// `heraclitus_state()` — introspecção operacional num só JSON: head,
    /// segmentos (id/versão/selado/raiz Merkle) e watermarks das views. O que
    /// um operador precisa para diagnosticar um boot/replay sem ir a logs.
    pub fn state(&self) -> serde_json::Value {
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let segments: Vec<serde_json::Value> = match self.log.as_ref() {
            AnyLog::Legacy(log) => log
                .sealed_segments()
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "id": m.id,
                        "version": m.version,
                        "sealed": m.sealed,
                        "base_lsn": m.base_lsn,
                        "max_lsn": m.max_lsn,
                        "blake3_root": m.blake3_root.as_ref().map(hex),
                    })
                })
                .collect(),
            AnyLog::V6(log) => log
                .manifest()
                .segments_v2
                .iter()
                .map(|m| {
                    let active = m.active();
                    serde_json::json!({
                        "id": m.segment_id,
                        "version": 6,
                        "sealed": true,
                        "base_lsn": m.first_lsn,
                        "max_lsn": m.last_lsn,
                        "blake3_root": hex(&m.logical_root),
                        "active_generation": m.active_generation,
                        "physical_layout": active.map(|g| format!("{:?}", g.layout).to_ascii_lowercase()),
                        "physical_generations": m.generations.len(),
                    })
                })
                .collect(),
        };
        let mut views = self.views.lock().unwrap();
        let mut out = serde_json::json!({
            "head_lsn": self.log.head(),
            "storage_format": self.log.format().as_str(),
            "sealed_segments": segments,
            "views": {
                "watermarks": views.watermarks(),
                "min_watermark": views.min_watermark(),
            },
            "log_only": self.log_only,
        });
        // SPEC-015/021: com replicação ativa, expõe papel/líder/membros do nó —
        // o que um operador precisa para diagnosticar o cluster.
        if let Some(rep) = self.replication.get() {
            out["replication"] = rep.status();
        }
        out
    }

    /// `heraclitus_verify_segment(id)` — prova de integridade pontual.
    pub fn verify_segment(
        &self,
        id: heraclitus_core::SegmentId,
    ) -> Result<serde_json::Value, HeraclitusError> {
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        match self.log.as_ref() {
            AnyLog::Legacy(log) => match log.verify_segment(id)? {
                None => Ok(serde_json::json!({ "found": false, "id": id })),
                Some(r) => Ok(serde_json::json!({
                    "found": true,
                    "id": r.id,
                    "version": r.version,
                    "sealed": r.sealed,
                    "records": r.records,
                    "base_lsn": r.base_lsn,
                    "max_lsn": r.max_lsn,
                    "computed_root": hex(&r.computed_root),
                    "stored_root": r.stored_root.as_ref().map(hex),
                    "valid": r.valid,
                })),
            },
            AnyLog::V6(log) => {
                let Some(reports) =
                    log.verify_segment(id, heraclitus_log::v6::IntegrityLevel::Logical)?
                else {
                    return Ok(serde_json::json!({ "found": false, "id": id }));
                };
                let manifest = log.manifest();
                let desc = manifest
                    .segment(id)
                    .ok_or_else(|| HeraclitusError::Corruption {
                        context: "hrkl v6 verify".into(),
                        detail: format!(
                            "segmento {id} desapareceu do manifesto durante verificação"
                        ),
                    })?;
                let generations: Vec<_> = reports
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "layout": format!("{:?}", r.layout).to_ascii_lowercase(),
                            "records": r.record_count,
                            "blocks": r.block_count,
                            "physical_ok": r.physical_ok,
                            "logical_ok": r.logical_ok,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({
                    "found": true,
                    "id": id,
                    "version": 6,
                    "sealed": true,
                    "records": desc.record_count,
                    "base_lsn": desc.first_lsn,
                    "max_lsn": desc.last_lsn,
                    "computed_root": hex(&desc.logical_root),
                    "stored_root": hex(&desc.logical_root),
                    "valid": reports.iter().all(|r| r.is_ok()),
                    "generations": generations,
                }))
            }
        }
    }

    /// Two-stage recall (§3.8) over the real indexes + memtable merge.
    pub fn recall(&self, text: &str, k: usize) -> Result<serde_json::Value, HeraclitusError> {
        // Recência ACT-R: `now` TEM de estar na mesma unidade que os tempos de
        // acesso gravados pelo `ActivationStore` (`ts_hlc >> 16`, ms físicos) —
        // NÃO o LSN, senão todas as idades colapsavam a 1 e o decay de recência
        // morria (activation degenerava em frequência pura). Usa-se o ts do
        // evento mais recente como relógio (mesma codificação, determinístico).
        let now = self
            .log
            .read(self.log.head().saturating_sub(1))
            .ok()
            .flatten()
            .map(|(_, e)| e.ts_hlc >> 16)
            .unwrap_or(0);
        let txt_hits: Vec<_> = {
            let idx = self.text.read().unwrap();
            idx.search(text, heraclitus_retrieval::RECALL_N)
                .into_iter()
                .map(|h| (h.id, h.lsn, h.score))
                .collect()
        };
        let act_hits: Vec<_> = {
            let act = self.activation.read().unwrap();
            act.top_k(now, heraclitus_retrieval::RECALL_N)
                .into_iter()
                .map(|h| (h.id, h.score))
                .collect()
        };
        let mem_hits: Vec<_> = self
            .memtable
            .text_search(text, heraclitus_retrieval::RECALL_N)
            .into_iter()
            .map(|h| (h.id, h.lsn, h.score))
            .collect();

        // Memtable hits join the text channel (freshest truth first).
        let mut text_channel = mem_hits;
        text_channel.extend(txt_hits);

        let reranker = LinearReranker {
            head_lsn: self.log.head(),
            ..Default::default()
        };
        let ranked = retrieve(
            text,
            RecallInputs {
                vector: Vec::new(), // no query embedding for raw text (no LLM in the engine)
                text: text_channel,
                activation: act_hits,
            },
            &reranker,
            k,
        );

        // Hydrate rows from the log.
        let mut rows = Vec::new();
        for (cand, score) in ranked {
            // Candidato vindo SÓ do canal de ativação chega com lsn=0 (o canal
            // não transporta LSN) — a leitura em 0 falhava o filtro de id e a
            // linha saía sem conteúdo. Resolve-se o LSN real pelo índice de
            // grafo (id → lsn) antes de hidratar.
            let lsn = if cand.lsn == 0 {
                self.graph
                    .write()
                    .unwrap()
                    .lsn_of(&cand.id)
                    .unwrap_or(cand.lsn)
            } else {
                cand.lsn
            };
            if let Some((lsn, ep)) = self.log.read(lsn)?.filter(|(_, e)| e.id == cand.id) {
                rows.push(serde_json::json!({
                    "lsn": lsn,
                    "id": ep.id.to_string(),
                    "content": crate::rest::bytes_str(&ep.content),
                    "score": score,
                }));
            } else {
                rows.push(serde_json::json!({
                    "id": cand.id.to_string(), "lsn": cand.lsn, "score": score
                }));
            }
        }
        Ok(serde_json::Value::Array(rows))
    }
}

/// The engine IS the real `QueryBackend` for the GQL layer: HNSW for
/// NEAREST, two-stage for RECALL, graph index for PROVENANCE.
impl QueryBackend for Engine {
    fn scan(&self, as_of: Option<Lsn>) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        // R9: capado como o LogBackend de referência — um scan sem teto
        // materializava o log inteiro num Vec (OOM em logs grandes).
        self.log.scan_capped(
            0,
            as_of.unwrap_or(u64::MAX),
            heraclitus_query::backend::QUERY_SCAN_CAP,
        )
    }

    /// Snapshot do grafo temporal materializado (a view incremental, sem replay).
    fn graph(&self) -> Result<TemporalGraph, HeraclitusError> {
        Ok(self.tgraph.read().unwrap().clone())
    }

    fn scan_range(&self, from: Lsn, to: Lsn) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        // Windowed + capped: segment pruning makes a time slice cheap, and the
        // QUERY_SCAN_CAP keeps a broad scan from exhausting memory (§query guard).
        self.log
            .scan_capped(from, to, heraclitus_query::backend::QUERY_SCAN_CAP)
    }

    fn scan_builtin_eq(
        &self,
        field: &str,
        value: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<PrunedScanResult>, HeraclitusError> {
        let bound = as_of.unwrap_or_else(|| self.log.head());
        self.log
            .scan_builtin_eq_capped(
                field,
                value,
                0,
                bound,
                heraclitus_query::backend::QUERY_SCAN_CAP,
            )
            .map(|result| {
                result.map(|(mut rows, stats)| {
                    rows.retain(|(lsn, _)| *lsn < bound);
                    PrunedScanResult {
                        rows,
                        stats: Some(stats),
                    }
                })
            })
    }

    fn attr_lookup(
        &self,
        field: &str,
        value: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<Vec<(Lsn, Episode)>>, HeraclitusError> {
        // O índice dá os LSNs exatos; cada `log.read` é O(1) via o índice de
        // offset por-LSN do log (seek directo). Hidratação = nº de matches × O(1).
        let mut lsns: Vec<Lsn> = {
            let idx = self.attr.read().unwrap();
            idx.lookup(field, value).to_vec()
        };
        if let Some(bound) = as_of {
            lsns.retain(|l| *l < bound);
        }
        lsns.sort_unstable();
        let mut out: Vec<(Lsn, Episode)> = Vec::with_capacity(lsns.len());
        for l in lsns {
            if let Some(hit) = self.log.read(l)? {
                out.push(hit);
            }
            if out.len() >= heraclitus_query::backend::QUERY_SCAN_CAP {
                break;
            }
        }
        Ok(Some(out))
    }

    /// Range numérico (C1.6): resolvido pelo BTreeMap ordenado do índice de
    /// atributos — `WHERE n.valor > x AND n.valor < y` vira `range()` +
    /// hidratação O(1)/LSN, sem scan do log.
    fn attr_range_lookup(
        &self,
        field: &str,
        min: Option<(f64, bool)>,
        max: Option<(f64, bool)>,
        as_of: Option<Lsn>,
    ) -> Result<Option<Vec<(Lsn, Episode)>>, HeraclitusError> {
        use std::ops::Bound;
        let to_bound = |b: Option<(f64, bool)>| match b {
            None => Bound::Unbounded,
            Some((v, true)) => Bound::Included(v),
            Some((v, false)) => Bound::Excluded(v),
        };
        let mut lsns: Vec<Lsn> = {
            let idx = self.attr.read().unwrap();
            idx.lookup_range(field, to_bound(min), to_bound(max))
        };
        if let Some(bound) = as_of {
            lsns.retain(|l| *l < bound);
        }
        let mut out: Vec<(Lsn, Episode)> = Vec::with_capacity(lsns.len());
        for l in lsns {
            if let Some(hit) = self.log.read(l)? {
                out.push(hit);
            }
            if out.len() >= heraclitus_query::backend::QUERY_SCAN_CAP {
                break;
            }
        }
        Ok(Some(out))
    }

    fn head(&self) -> Result<Lsn, HeraclitusError> {
        // Views apply synchronously on append, so the log head is the
        // consistency point the engine can serve.
        Ok(self.log.head())
    }

    fn recall(
        &self,
        text: &str,
        k: usize,
        as_of: Option<Lsn>,
    ) -> Result<Vec<(Lsn, Episode, f32)>, HeraclitusError> {
        // Audit #10: AS OF is honored by post-filtering on LSN (the indexes
        // are head-versioned in v0; a versioned-index time travel is the
        // planned upgrade). Over-fetch to compensate for filtered rows.
        let fetch = if as_of.is_some() { k * 4 } else { k };
        let v = Engine::recall(self, text, fetch)?;
        let empty = Vec::new();
        let mut out = Vec::new();
        for row in v.as_array().unwrap_or(&empty) {
            let lsn = row["lsn"].as_u64().unwrap_or(0);
            if let Some(bound) = as_of {
                if lsn >= bound {
                    continue;
                }
            }
            if let Some((l, e)) = self.log.read(lsn)? {
                out.push((l, e, row["score"].as_f64().unwrap_or(0.0) as f32));
            }
        }
        out.truncate(k);
        Ok(out)
    }

    fn nearest(
        &self,
        vector: &[f32],
        k: usize,
        as_of: Option<Lsn>,
    ) -> Result<Vec<(Lsn, Episode, f32)>, HeraclitusError> {
        let dims = {
            // Interpret the raw vector as the hyperbolic component (v0).
            let mut hyp = vector.to_vec();
            heraclitus_manifold::project_to_ball(&mut hyp);
            ProductPoint {
                hyp,
                sph: vec![],
                euc: vec![],
            }
        };
        // Audit #10: honor AS OF via LSN post-filter (over-fetch first).
        let fetch = if as_of.is_some() { k * 4 } else { k };
        let in_snapshot = |lsn: Lsn| as_of.map(|b| lsn < b).unwrap_or(true);
        let hits = self.vector.read().unwrap().search(&dims, fetch, 128, None);
        let mut out = Vec::new();
        for h in hits.into_iter().filter(|h| in_snapshot(h.lsn)) {
            if let Some((l, e)) = self.log.read(h.lsn)? {
                out.push((l, e, h.dist));
            }
        }
        // Merge the memtable tail (exact) for read-your-own-writes.
        let mem = self.memtable.knn(&self.metric, &dims, fetch);
        for m in mem.into_iter().filter(|m| in_snapshot(m.lsn)) {
            if !out.iter().any(|(_, e, _)| e.id == m.id) {
                if let Some((l, e)) = self.log.read(m.lsn)? {
                    out.push((l, e, m.score));
                }
            }
        }
        out.sort_by(|a, b| a.2.total_cmp(&b.2));
        out.truncate(k);
        Ok(out)
    }

    fn provenance(&self, id: &str) -> Result<Vec<String>, HeraclitusError> {
        let parsed: Result<heraclitus_core::EventId, _> = id.parse();
        match parsed {
            Ok(eid) => Ok(self
                .graph
                .write()
                .unwrap()
                .parents(&eid)
                .into_iter()
                .map(|p| p.to_string())
                .collect()),
            Err(_) => Ok(Vec::new()),
        }
    }

    fn lsn_for_timestamp(&self, ts_ms: u64) -> Result<Lsn, HeraclitusError> {
        // R9: busca binária sobre o ts monotónico por LSN (o mesmo algoritmo do
        // LogBackend de referência) — a versão anterior fazia scan(0, MAX) e
        // materializava o log INTEIRO em RAM a cada AS OF TIMESTAMP.
        let head = self.log.head();
        let mut low = 0;
        let mut high = head;
        let mut ans = head;
        while low <= high {
            let mid = low + (high - low) / 2;
            match self.log.read(mid)? {
                Some((_, e)) => {
                    if (e.ts_hlc >> 16) > ts_ms {
                        ans = mid;
                        if mid == 0 {
                            break;
                        }
                        high = mid - 1;
                    } else {
                        low = mid + 1;
                    }
                }
                None => {
                    if mid == 0 {
                        break;
                    }
                    high = mid - 1;
                }
            }
        }
        Ok(ans)
    }

    fn neighbors(
        &self,
        node: &str,
        etype: Option<&str>,
        as_of: Option<Lsn>,
        min_confidence: f32,
    ) -> Result<Vec<NeighborRow>, HeraclitusError> {
        // Real path: read the incrementally-maintained view (no replay). The
        // M8 gate is that this matches `LogBackend`'s from-scratch replay.
        let g = self.tgraph.read().unwrap();
        Ok(neighbors_of(&g, node, etype, as_of, min_confidence))
    }

    fn traverse(
        &self,
        start: &str,
        max_depth: usize,
        as_of: Option<Lsn>,
        min_confidence: f32,
    ) -> Result<Vec<(String, usize)>, HeraclitusError> {
        let g = self.tgraph.read().unwrap();
        Ok(traverse_of(&g, start, max_depth, as_of, min_confidence))
    }

    fn match_edges(
        &self,
        src: Option<&str>,
        etype: Option<&str>,
        dst: Option<&str>,
        as_of: Option<Lsn>,
    ) -> Result<Vec<EdgeRow>, HeraclitusError> {
        let g = self.tgraph.read().unwrap();
        Ok(match_edges_of(&g, src, etype, dst, as_of))
    }

    fn edge_hypotheses(
        &self,
        from: &str,
        to: &str,
        etype: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<EdgeHypotheses>, HeraclitusError> {
        Ok(hypotheses_of(
            &self.tgraph.read().unwrap(),
            from,
            to,
            etype,
            as_of,
        ))
    }

    fn community(
        &self,
        node: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<CommunityResult>, HeraclitusError> {
        Ok(community_of(&self.tgraph.read().unwrap(), node, as_of))
    }

    fn community_leiden(
        &self,
        node: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<CommunityResult>, HeraclitusError> {
        Ok(heraclitus_query::backend::community_leiden_of(
            &self.tgraph.read().unwrap(),
            node,
            as_of,
        ))
    }

    fn node_metrics(
        &self,
        node: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<MetricsResult>, HeraclitusError> {
        Ok(node_metrics_of(&self.tgraph.read().unwrap(), node, as_of))
    }

    fn resolve_entity(
        &self,
        key: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<String>, HeraclitusError> {
        let er = self.entity.write().unwrap();
        Ok(resolve_of(&er, key, as_of))
    }

    fn entity_cluster(
        &self,
        entity_id: &str,
        as_of: Option<Lsn>,
    ) -> Result<Vec<String>, HeraclitusError> {
        let er = self.entity.write().unwrap();
        Ok(cluster_of(&er, entity_id, as_of))
    }

    fn append(
        &self,
        label: Option<&str>,
        props: &[(String, GqlValue)],
    ) -> Result<Lsn, HeraclitusError> {
        let kind = match label {
            Some(l) if l.eq_ignore_ascii_case("action") => EventKind::Action,
            Some(l) if l.eq_ignore_ascii_case("message") => EventKind::Message,
            Some(l) if l.eq_ignore_ascii_case("observation") => EventKind::Observation,
            Some(l) => EventKind::Custom(l.to_string()),
            None => EventKind::Observation,
        };
        let mut attrs = HashMap::new();
        for (k, v) in props {
            let s = match v {
                GqlValue::Str(s) => s.clone(),
                GqlValue::Num(n) => n.to_string(),
            };
            attrs.insert(k.clone(), s);
        }
        let mut e = Episode::new("gql", kind, Vec::new());
        e.attrs = attrs.into_iter().collect();
        Engine::append(self, e)
    }
}

impl heraclitus_sentinel::DerivedEventSink for Engine {
    fn append(&self, episode: Episode, idempotency_key: &str) -> Result<Lsn, HeraclitusError> {
        self.append_sentinel_derived(episode, idempotency_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::FsyncPolicy;
    use heraclitus_query::backend::{replay_graph, LogBackend};

    /// Appends a provenance chain a←b←c plus a distilled fact f from {a,b}
    /// through the engine (which maintains the tgraph view incrementally).
    fn seed_chain(engine: &Engine) -> [String; 4] {
        let mut a = Episode::new("ag", EventKind::Observation, b"a".to_vec());
        a.attrs.insert("edge_type".into(), "socio_de".into());
        let mut b = Episode::new("ag", EventKind::Observation, b"b".to_vec());
        b.attrs.insert("edge_type".into(), "pagou".into());
        b.parents.push(a.id);
        let mut c = Episode::new("ag", EventKind::Observation, b"c".to_vec());
        c.parents.push(b.id);
        let mut f = Episode::new("distill", EventKind::FactDerived, b"f".to_vec());
        f.attrs.insert("edge_type".into(), "similar_a".into());
        f.parents.push(a.id);
        f.parents.push(b.id);
        let ids = [
            a.id.to_string(),
            b.id.to_string(),
            c.id.to_string(),
            f.id.to_string(),
        ];
        for e in [a, b, c, f] {
            engine.append(e).unwrap();
        }
        ids
    }

    fn engine_in(dir: &std::path::Path) -> Engine {
        let cfg = HeraclitusConfig {
            data_dir: dir.to_path_buf(),
            fsync: FsyncPolicy::Always,
            ..Default::default()
        };
        Engine::open(&cfg).unwrap()
    }

    #[test]
    fn sentinel_namespaces_are_external_reserved_but_internal_sink_can_append() {
        let temp = tempfile::tempdir().unwrap();
        let engine = engine_in(temp.path());

        let forged = Episode::new(
            "attacker",
            EventKind::Custom("SecuritySignal".into()),
            b"{}".to_vec(),
        );
        assert!(engine.append(forged).is_err());

        let mut forged_attr = Episode::new("attacker", EventKind::Observation, b"{}".to_vec());
        forged_attr
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        assert!(engine
            .append_idempotent(forged_attr, "forged-sentinel")
            .is_err());

        let mut derived = Episode::new(
            "sentinel",
            EventKind::Custom("SecuritySignal".into()),
            b"{}".to_vec(),
        );
        derived
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        let retry = derived.clone();
        assert_eq!(
            engine
                .append_sentinel_derived(derived, "sentinel:test:derived")
                .unwrap(),
            0
        );
        assert_eq!(
            engine
                .append_sentinel_derived(retry, "sentinel:test:derived")
                .unwrap(),
            0
        );
        assert_eq!(engine.log.head(), 1);
    }

    /// O append externo so exige `AccessRole::Writer`, e os replays de
    /// compliance confiam no `kind` e no atributo `compliance.generated` — dois
    /// sinais que vinham do cliente. Sem esta reserva, um Writer podia libertar
    /// um `LegalHold` que so o Admin devia libertar (abrindo o crypto-shred
    /// sobre dados retidos), pôr um hold de âmbito total e travar o GC, ou —
    /// pior — repetir um `hold_id` e deixar o estado regulatorio invalido para
    /// sempre, porque o log e append-only e o episodio nunca se apaga.
    #[test]
    fn compliance_namespaces_are_reserved_to_the_regulatory_engine() {
        let temp = tempfile::tempdir().unwrap();
        let engine = engine_in(temp.path());

        // Um release forjado levantaria uma retencao judicial.
        let forjado = Episode::new(
            "attacker",
            EventKind::Custom("LegalHoldRelease".into()),
            b"{}".to_vec(),
        );
        assert!(
            engine.append(forjado).is_err(),
            "um Writer nao pode forjar um LegalHoldRelease"
        );

        // O hold em si trava o GC e a eliminacao enquanto existir.
        let hold = Episode::new(
            "attacker",
            EventKind::Custom("LegalHold".into()),
            b"{}".to_vec(),
        );
        assert!(
            engine.append_idempotent(hold, "forjado-hold").is_err(),
            "um Writer nao pode forjar um LegalHold"
        );

        // O atributo de proveniencia e o que os replays leem para decidir se a
        // linha e prova regulatoria; tem de ser tao reservado como o kind.
        let mut atributo = Episode::new("attacker", EventKind::Observation, b"{}".to_vec());
        atributo
            .attrs
            .insert("compliance.generated".into(), "true".into());
        assert!(
            engine.append(atributo).is_err(),
            "compliance.* nao pode vir de fora"
        );

        // E o agente do motor regulatorio tambem nao se pode personificar.
        let agente = Episode::new("gov-compliance", EventKind::Observation, b"{}".to_vec());
        assert!(
            engine.append(agente).is_err(),
            "o agent_id do motor regulatorio e reservado"
        );

        // Telemetria normal continua a passar — a reserva nao pode ser um
        // bloqueio geral a palavra "compliance".
        let normal = Episode::new("app", EventKind::Observation, b"{\"ok\":1}".to_vec());
        assert!(engine.append(normal).is_ok());
    }

    #[test]
    fn v6_engine_append_query_and_restart_are_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            storage_format: heraclitus_core::StorageFormat::V6,
            fsync: FsyncPolicy::Always,
            ..Default::default()
        };

        {
            let engine = Engine::open(&cfg).unwrap();
            assert_eq!(engine.log.format(), heraclitus_core::StorageFormat::V6);
            for i in 0..6 {
                let mut event = Episode::new(
                    "v6-test",
                    EventKind::Observation,
                    format!("event-{i}").into_bytes(),
                );
                event.attrs.insert("ordinal".into(), i.to_string());
                assert_eq!(engine.append(event).unwrap(), i);
            }
            let rows = heraclitus_query::execute("MATCH (n) RETURN n", &engine).unwrap();
            assert_eq!(rows.as_array().unwrap().len(), 6);
            assert_eq!(engine.state()["storage_format"], "v6");
            assert_eq!(engine.verify().unwrap()["format"], "v6");
        }

        let reopened = Engine::open(&cfg).unwrap();
        assert_eq!(reopened.snapshot(), 6);
        assert_eq!(reopened.log.read(5).unwrap().unwrap().1.content, b"event-5");
        let rows = heraclitus_query::execute("MATCH (n) RETURN n", &reopened).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 6);
        assert_eq!(
            reopened
                .append(Episode::new(
                    "v6-test",
                    EventKind::Observation,
                    b"after-restart".to_vec(),
                ))
                .unwrap(),
            6
        );
    }

    #[test]
    fn v6_engine_real_query_backend_uses_hrki_and_explain_reports_pruning() {
        use heraclitus_log::v6::hrki::{IndexPolicy, IndexPolicySet};
        use heraclitus_log::v6::PackingProfile;

        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            storage_format: heraclitus_core::StorageFormat::V6,
            segment_max_bytes: 1_024,
            fsync: FsyncPolicy::Always,
            ..Default::default()
        };
        let engine = Engine::open(&cfg).unwrap();
        for i in 0..40 {
            let agent = if i < 20 { "alice" } else { "bob" };
            engine
                .append(Episode::new(agent, EventKind::Observation, vec![b'x'; 512]))
                .unwrap();
        }
        let v6 = engine.log.v6_arc().unwrap();
        v6.seal_active().unwrap();
        v6.pack_pending(PackingProfile::Balanced).unwrap();
        v6.build_pending_hrki(
            &IndexPolicySet::new().com("agent_id", IndexPolicy::PublicTechnical),
            None,
            0.01,
        )
        .unwrap();

        let probe = QueryBackend::scan_builtin_eq(&engine, "agent_id", "alice", None)
            .unwrap()
            .expect("Engine v6 deve expor a capability HRKI");
        assert_eq!(probe.rows.len(), 20);
        let stats = probe.stats.unwrap();
        assert!(stats.hrki_used > 0);
        assert!(stats.hrki_pruned > 0);
        assert!(stats.bytes_pruned > 0);

        let rows =
            heraclitus_query::execute("MATCH (n) WHERE n.agent_id = \"alice\" RETURN n", &engine)
                .unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 20);
        let explain = heraclitus_query::execute(
            "EXPLAIN MATCH (n) WHERE n.agent_id = \"alice\" RETURN n",
            &engine,
        )
        .unwrap();
        let explain = explain.as_str().unwrap();
        assert!(explain.contains("StoragePruning"), "{explain}");
        assert!(explain.contains("bytes pruned ="), "{explain}");

        let metrics = engine.storage_metrics();
        assert_eq!(metrics["available"], true);
        assert!(metrics["hrkl_append_bytes_total"].as_u64().unwrap() > 0);
        assert!(metrics["hrkl_packed_bytes"].as_u64().unwrap() > 0);
        assert!(metrics["hrkl_pack_seconds"].as_f64().unwrap() > 0.0);
        assert!(metrics["hrkl_blocks_pruned"].as_u64().unwrap() > 0);
        assert!(metrics["hrkl_bytes_pruned"].as_u64().unwrap() > 0);
        assert!(metrics["hrki_hits"].as_u64().unwrap() > 0);
        assert!(metrics["hrki_rebuilds"].as_u64().unwrap() > 0);
        let prometheus = engine.prometheus_metrics().unwrap();
        for name in [
            "hrkl_append_bytes_total",
            "hrkl_pack_queue_depth",
            "hrkl_blocks_pruned",
            "hrki_rebuilds",
            "parquet_export_lag_lsn",
            "canonical_verify_failures",
            "physical_crc_failures",
        ] {
            assert!(
                prometheus.lines().any(|line| line.starts_with(name)),
                "{name}"
            );
        }
    }

    #[test]
    fn idempotent_append_retries_return_original_lsn_and_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let key = "forge:0123456789abcdef";
        let make = || {
            let mut e = Episode::new(
                "subject:abc",
                EventKind::Custom("OperationalFact".into()),
                b"same".to_vec(),
            );
            e.attrs.insert("fact_id".into(), "fact-1".into());
            e
        };

        let original = {
            let engine = engine_in(dir.path());
            let (lsn, deduplicated, event_id) = engine.append_idempotent(make(), key).unwrap();
            assert!(!deduplicated);
            let head = engine.snapshot();
            let retry = engine.append_idempotent(make(), key).unwrap();
            assert_eq!(retry.0, lsn);
            assert!(retry.1);
            assert_eq!(retry.2, event_id);
            assert_eq!(engine.snapshot(), head, "retry não pode avançar o log");

            let mut conflicting = make();
            conflicting.content = b"different".to_vec();
            assert!(matches!(
                engine.append_idempotent(conflicting, key),
                Err(HeraclitusError::IdempotencyConflict { .. })
            ));
            lsn
        };

        let reopened = engine_in(dir.path());
        let retry = reopened.append_idempotent(make(), key).unwrap();
        assert_eq!(
            (retry.0, retry.1),
            (original, true),
            "o índice reconstruído do log tem de deduplicar depois de restart"
        );
    }

    #[test]
    fn shred_rebuilds_all_derived_state_and_queries_keep_working() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            encryption_at_rest: true,
            ..Default::default()
        };
        let engine = Engine::open(&cfg).unwrap();
        let mut event = Episode::new(
            "titular:hmac-sha256:subject-a",
            EventKind::Custom("OperationalFact".into()),
            b"Carlos entrou".to_vec(),
        );
        event
            .attrs
            .insert("actor_name".into(), "Carlos Silva".into());
        let lsn = engine.append(event).unwrap();
        let before = heraclitus_query::execute(
            "MATCH (n) WHERE n.actor_name = \"Carlos Silva\" RETURN n",
            &engine,
        )
        .unwrap();
        assert_eq!(before.as_array().unwrap().len(), 1);

        assert!(engine.shred("titular:hmac-sha256:subject-a").unwrap());
        let after = heraclitus_query::execute(
            "MATCH (n) WHERE n.actor_name = \"Carlos Silva\" RETURN n",
            &engine,
        )
        .unwrap();
        assert!(after.as_array().unwrap().is_empty());
        let (_, shredded) = engine.log.read(lsn).unwrap().unwrap();
        assert_eq!(shredded.content, heraclitus_crypto::SHREDDED);
        assert!(!engine.attr_dir.join("privacy-rebuild-required").exists());
        drop(engine);

        let reopened = Engine::open(&cfg).unwrap();
        let after_restart = heraclitus_query::execute(
            "MATCH (n) WHERE n.actor_name = \"Carlos Silva\" RETURN n",
            &reopened,
        )
        .unwrap();
        assert!(after_restart.as_array().unwrap().is_empty());
        assert!(reopened.log.read(lsn).unwrap().is_some());
    }

    #[test]
    fn legal_hold_blocks_crypto_shred_before_key_destruction() {
        use heraclitus_compliance::{
            EvidenceSelector, LegalHold, LegalHoldRelease, RegulatoryPolicyEngine,
        };

        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            storage_format: heraclitus_core::StorageFormat::V6,
            encryption_at_rest: true,
            ..Default::default()
        };
        let engine = Engine::open(&cfg).unwrap();
        let agent = "titular:hmac-sha256:held-subject";
        let lsn = engine
            .append(Episode::new(
                agent,
                EventKind::Custom("PersonalData".into()),
                b"protected".to_vec(),
            ))
            .unwrap();
        let regulatory = RegulatoryPolicyEngine::new(engine.log.clone());
        regulatory
            .place_legal_hold(LegalHold {
                hold_id: "hold-shred-test".into(),
                scope: EvidenceSelector {
                    lsn_start: lsn,
                    lsn_end: lsn,
                },
                authority: "court".into(),
                reason: "preserve evidence".into(),
                created_at_lsn: lsn,
            })
            .unwrap();

        assert!(engine.shred(agent).is_err());
        assert_eq!(
            engine.log.read(lsn).unwrap().unwrap().1.content,
            b"protected"
        );

        regulatory
            .release_legal_hold(LegalHoldRelease {
                hold_id: "hold-shred-test".into(),
                authority: "court".into(),
                reason: "case closed".into(),
                released_at_lsn: engine.log.head(),
            })
            .unwrap();
        assert!(engine.shred(agent).unwrap());
        assert_eq!(
            engine.log.read(lsn).unwrap().unwrap().1.content,
            heraclitus_crypto::SHREDDED
        );
    }

    /// §3.9/§2.6 — a task de distill consolida clusters em Facts pelo caminho
    /// unificado (Engine::append): os Facts ficam indexados AO VIVO (state_hash
    /// do grafo idêntico vivo vs reopen), o cursor evita re-emissão, e episódios
    /// novos num tick seguinte geram Facts novos.
    #[cfg(feature = "distill")]
    #[test]
    fn distill_tick_consolidates_via_unified_append_with_cursor() {
        use heraclitus_core::ProductPoint;
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            ..Default::default()
        };
        let obs = |text: &str, x: f32| {
            let mut e = Episode::new("agent", EventKind::Observation, text.as_bytes().to_vec());
            e.embedding = Some(ProductPoint {
                hyp: vec![x, 0.0],
                sph: vec![],
                euc: vec![],
            });
            e
        };

        let dcfg = heraclitus_distill::DistillConfig::default();
        let live_hash = {
            let engine = Engine::open(&cfg).unwrap();
            // Cluster apertado de "gato" + um outlier longe.
            for i in 0..4 {
                engine
                    .append(obs(&format!("gato {i}"), 0.60 + i as f32 * 0.01))
                    .unwrap();
            }
            engine.append(obs("galaxia distante", -0.7)).unwrap();

            let facts = engine.distill_tick(&dcfg).unwrap();
            assert_eq!(facts.len(), 1, "exatamente um cluster estável vira Fact");
            let (_, ev) = engine.log.read(facts[0]).unwrap().unwrap();
            assert_eq!(ev.kind, EventKind::FactDerived);
            assert_eq!(
                ev.parents.len(),
                4,
                "proveniência = os 4 episódios do cluster"
            );

            // Cursor: sem episódios novos, o 2º tick não re-emite nada.
            assert!(
                engine.distill_tick(&dcfg).unwrap().is_empty(),
                "cursor evita re-emissão"
            );

            // Episódios novos ⇒ o 3º tick consolida um Fact novo.
            for i in 0..3 {
                engine
                    .append(obs(&format!("chuva {i}"), -0.2 + i as f32 * 0.01))
                    .unwrap();
            }
            assert_eq!(
                engine.distill_tick(&dcfg).unwrap().len(),
                1,
                "cluster novo vira Fact"
            );

            engine.graph_state_hash()
        };

        // §2.6: os Facts foram indexados AO VIVO — o boot-replay produz o MESMO
        // state_hash do grafo (não divergem vivo vs reopen).
        let engine2 = Engine::open(&cfg).unwrap();
        assert_eq!(
            live_hash,
            engine2.graph_state_hash(),
            "Facts do distill indexados ao vivo ≡ boot-replay"
        );
        // E o cursor persistiu: reabrir e um tick sem episódios novos é no-op.
        assert!(
            engine2.distill_tick(&dcfg).unwrap().is_empty(),
            "cursor sobrevive ao restart"
        );
    }

    #[cfg(feature = "distill")]
    #[test]
    fn distill_tick_propagates_the_most_restrictive_classification() {
        use heraclitus_compliance::{ClassificationControls, ClassificationPolicy};
        use heraclitus_core::ProductPoint;
        use std::collections::{BTreeMap, BTreeSet};

        let dir = tempfile::tempdir().unwrap();
        let compliance_dir = dir.path().join("compliance");
        std::fs::create_dir_all(&compliance_dir).unwrap();
        let labels = BTreeMap::from([
            (
                "internal".into(),
                ClassificationControls {
                    label: "internal".into(),
                    rank: 1,
                    access_policy: "employees".into(),
                    export_policy: "company-only".into(),
                    ai_disclosure_policy: "approved-models".into(),
                    retention_policy: "ordinary".into(),
                },
            ),
            (
                "secret".into(),
                ClassificationControls {
                    label: "secret".into(),
                    rank: 5,
                    access_policy: "need-to-know".into(),
                    export_policy: "never".into(),
                    ai_disclosure_policy: "deny".into(),
                    retention_policy: "classified_information".into(),
                },
            ),
        ]);
        let policy = ClassificationPolicy::new(
            "classification-main",
            "2026-08-30",
            0,
            labels,
            BTreeSet::new(),
        )
        .unwrap();
        std::fs::write(
            compliance_dir.join("classification-policy.json"),
            serde_json::to_vec_pretty(&policy).unwrap(),
        )
        .unwrap();

        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            ..Default::default()
        };
        let engine = Engine::open(&cfg).unwrap();
        for i in 0..4 {
            let mut event = Episode::new(
                "classified-source",
                EventKind::Observation,
                format!("segredo {i}").into_bytes(),
            );
            event.embedding = Some(ProductPoint {
                hyp: vec![0.40 + i as f32 * 0.01, 0.0],
                sph: vec![],
                euc: vec![],
            });
            event
                .attrs
                .insert("classification.label".into(), "secret".into());
            engine.append(event).unwrap();
        }

        let facts = engine
            .distill_tick(&heraclitus_distill::DistillConfig::default())
            .unwrap();
        assert_eq!(facts.len(), 1);
        let (_, derived) = engine.log.read(facts[0]).unwrap().unwrap();
        assert_eq!(derived.attrs["classification.label"], "secret");
        assert_eq!(derived.attrs["classification.rank"], "5");
        assert_eq!(
            derived.attrs["classification.retention_policy"],
            "classified_information"
        );
        assert_eq!(
            derived.attrs["classification.policy_id"],
            "classification-main"
        );
        assert_eq!(derived.parents.len(), 4);
    }

    #[test]
    fn spec027_telemetry_lands_in_log_and_is_gql_queryable() {
        // SPEC-027 wired: emit_telemetry appends SystemMetric episodes to the
        // ordinary log, and the DB can investigate itself via the normal GQL
        // engine — the self-query the spec promises.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        let before = engine.log.head();
        let n = engine.emit_telemetry().unwrap();
        assert_eq!(n, 2, "log_head_lsn + sealed_segments");
        assert_eq!(engine.log.head(), before + n);

        // Self-query: the engine finds its own vitals through GQL.
        let rows = heraclitus_query::execute(
            "MATCH (n) WHERE n.agent_id = \"heraclitus-engine\" RETURN n",
            &engine,
        )
        .unwrap();
        let arr = rows.as_array().unwrap();
        assert_eq!(arr.len(), 2, "both metric episodes visible via GQL");
        let dump = rows.to_string();
        assert!(dump.contains("log_head_lsn"), "got: {dump}");
        assert!(dump.contains("sealed_segments"));
    }

    #[test]
    fn m20_hvm_ledger_through_engine_survives_reopen_and_checkpoints() {
        // M20 integration: the H-VM ledger is reachable from the Engine, durable
        // across a reopen (replay), and checkpointable to a Bᵋ-tree on disk.
        let dir = tempfile::tempdir().unwrap();
        let ckpt = dir.path().join("hvm.hbt");
        {
            let engine = engine_in(dir.path());
            engine
                .hvm_upsert(b"user:1".to_vec(), b"alice".to_vec())
                .unwrap();
            engine
                .hvm_upsert(b"user:2".to_vec(), b"bob".to_vec())
                .unwrap();
            engine.hvm_delete(b"user:1".to_vec()).unwrap();

            let state = engine.hvm_state().unwrap();
            assert_eq!(
                state.memory_layers.get(b"user:2".as_slice()),
                Some(&b"bob".to_vec())
            );
            assert!(!state.memory_layers.contains_key(b"user:1".as_slice()));

            // Checkpoint to a Bᵋ-tree on disk and verify its contents.
            engine.hvm_checkpoint(&ckpt).unwrap();
            let loaded = heraclitus_btree::BEpsilonTree::load(&ckpt).unwrap();
            assert_eq!(loaded.get(b"user:2"), Some(b"bob".to_vec()));
            assert_eq!(loaded.get(b"user:1"), None);
        }

        // Reopen over the same data dir: the ledger replays from the durable log.
        let engine2 = engine_in(dir.path());
        let state2 = engine2.hvm_state().unwrap();
        assert_eq!(
            state2.memory_layers.get(b"user:2".as_slice()),
            Some(&b"bob".to_vec())
        );
        assert!(!state2.memory_layers.contains_key(b"user:1".as_slice()));
    }

    #[test]
    fn hvm_checkpoint_default_writes_under_data_dir_and_is_not_replicated() {
        // P5: o endpoint usa estes dois — o checkpoint vai para um caminho do
        // servidor (nunca do cliente) e as escritas são recusadas sob replicação.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        assert!(!engine.is_replicated(), "nó autónomo por default");
        engine.hvm_upsert(b"k".to_vec(), b"v".to_vec()).unwrap();
        let path = engine.hvm_checkpoint_default().unwrap();
        assert!(path.ends_with("hvm.hbt"));
        assert!(
            path.starts_with(dir.path()),
            "checkpoint sob o data_dir: {path:?}"
        );
        let tree = heraclitus_btree::BEpsilonTree::load(&path).unwrap();
        assert_eq!(tree.get(b"k"), Some(b"v".to_vec()));
    }

    #[test]
    fn hvm_frames_keep_graph_state_hash_consistent_live_vs_reopen() {
        // Correção arquitetural: os frames H-VM (hvm_isa) NÃO entram no ÍNDICE de
        // grafo — nem ao vivo (bypass do index_applied) nem no boot-replay. Antes,
        // o replay de boot indexava-os (grafo passava de 3 para 5 nós) enquanto o
        // caminho vivo os saltava ⇒ o `state_hash` do grafo DIVERGIA entre um nó
        // recém-escrito e um nó reaberto — veneno para a equivalência do consenso.
        // (`MATCH (n)` lê o LOG, por isso não reflete o índice; o state_hash sim.)
        let dir = tempfile::tempdir().unwrap();
        let live_hash = {
            let engine = engine_in(dir.path());
            for i in 0..3 {
                engine
                    .append(Episode::new(
                        "alice",
                        EventKind::Observation,
                        format!("evento {i}").into_bytes(),
                    ))
                    .unwrap();
            }
            engine.hvm_upsert(b"k1".to_vec(), b"v1".to_vec()).unwrap();
            engine.hvm_upsert(b"k2".to_vec(), b"v2".to_vec()).unwrap();
            // `let` para o guard cair ANTES do `engine` no fim do bloco.
            let h = engine.graph.write().unwrap().state_hash();
            h
        };
        // Reopen: o boot-replay tem de produzir o MESMO state_hash do grafo.
        let engine2 = engine_in(dir.path());
        let reopened_hash = engine2.graph.write().unwrap().state_hash();
        assert_eq!(
            live_hash, reopened_hash,
            "escritas H-VM não devem divergir o state_hash do grafo (vivo vs replay)"
        );
        assert_eq!(
            engine2.hvm_state().unwrap().memory_layers.len(),
            2,
            "ledger intacto"
        );
    }

    #[test]
    fn m8_incremental_view_equals_replay_bit_for_bit() {
        // THE M8 GATE: the graph maintained incrementally on the append path
        // must equal the graph rebuilt from scratch by replaying the log.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        let _ids = seed_chain(&engine);

        let replayed = replay_graph(&engine.log).unwrap();
        let live = engine.tgraph.write().unwrap();
        assert_eq!(
            live.state_hash(),
            replayed.state_hash(),
            "incremental view must equal from-scratch replay, byte for byte"
        );
        assert_eq!(live.edges.len(), 4);
    }

    #[test]
    fn m8_reopen_rebuilds_identical_graph() {
        // Crash/restart story: a fresh engine over the same data_dir replays
        // the log and lands on the identical graph state.
        let dir = tempfile::tempdir().unwrap();
        let hash_a = {
            let engine = engine_in(dir.path());
            seed_chain(&engine);
            let h = engine.tgraph.write().unwrap().state_hash();
            h
        };
        let engine_b = engine_in(dir.path());
        let hash_b = engine_b.tgraph.write().unwrap().state_hash();
        assert_eq!(hash_a, hash_b, "reopened engine must reconstruct the graph");
    }

    #[test]
    fn m8_neighbors_via_gql_matches_reference() {
        // NEIGHBORS through GQL: the real (view-backed) engine and the
        // reference (replay-backed) LogBackend must return identical rows.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        let ids = seed_chain(&engine);

        let be = LogBackend::new(engine.log.clone());
        let q = format!("NEIGHBORS (\"{}\")", ids[0]);
        let via_engine = heraclitus_query::execute(&q, &engine).unwrap();
        let via_log = heraclitus_query::execute(&q, &be).unwrap();
        assert_eq!(via_engine, via_log, "real backend must match the reference");
        assert_eq!(via_engine.as_array().unwrap().len(), 2);

        let qt = format!("TRAVERSE (\"{}\", 3)", ids[0]);
        let t_engine = heraclitus_query::execute(&qt, &engine).unwrap();
        let t_log = heraclitus_query::execute(&qt, &be).unwrap();
        assert_eq!(t_engine, t_log);
    }

    /// Appends explicit, mutable edges through the engine (M9): the socio edge
    /// is asserted then retracted; the pagou edge stays open.
    fn seed_mutations(engine: &Engine) {
        let mk = |from: &str, to: &str, etype: &str, op: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), from.into());
            e.attrs.insert("edge_to".into(), to.into());
            e.attrs.insert("edge_type".into(), etype.into());
            e.attrs.insert("edge_op".into(), op.into());
            e
        };
        engine
            .append(mk("Alfa", "Maria", "socio_de", "assert"))
            .unwrap();
        engine
            .append(mk("Alfa", "Beto", "pagou", "assert"))
            .unwrap();
        engine
            .append(mk("Alfa", "Maria", "socio_de", "retract"))
            .unwrap();
    }

    #[test]
    fn m9_edge_match_via_gql_matches_reference() {
        // M9 GATE: relationship MATCH with AS OF + edge mutation. The real
        // (view-backed) engine and the reference (replay-backed) LogBackend
        // must agree at every snapshot.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        seed_mutations(&engine);
        let be = LogBackend::new(engine.log.clone());

        for q in [
            "MATCH (a)-[r]->(b) RETURN *",
            "MATCH (a)-[r]->(b) AS OF LSN 2 RETURN *",
            "MATCH (a)-[r]->(b) AS OF LSN 1 RETURN *",
            "MATCH (a)-[r:pagou]->(b) RETURN b.id, r.type",
            "MATCH (a)-[r]->(b) WHERE b = \"Maria\" AS OF LSN 2 RETURN *",
        ] {
            let via_engine = heraclitus_query::execute(q, &engine).unwrap();
            let via_log = heraclitus_query::execute(q, &be).unwrap();
            assert_eq!(via_engine, via_log, "engine vs reference disagree on `{q}`");
        }

        // Incremental view must still equal a from-scratch replay, even with the
        // valid_to mutation in play.
        let replayed = replay_graph(&engine.log).unwrap();
        let live = engine.tgraph.write().unwrap();
        assert_eq!(live.state_hash(), replayed.state_hash());
        // The retracted edge is closed, not deleted.
        assert_eq!(live.edges.len(), 2);
    }

    #[test]
    fn m10_fuse_runs_on_the_real_engine() {
        // FUSE is a default QueryBackend method, so the engine inherits it and
        // it flows through `execute` (and thus gRPC). Smoke-test the end-to-end
        // path on the real backend: it returns the per-channel breakdown and is
        // reproducible. (The "fusion wins" gate itself lives in the query crate
        // against the exact reference backend.)
        use heraclitus_core::ProductPoint;
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());

        let anchor = Episode::new("ag", EventKind::Observation, b"anchor".to_vec());
        let a_id = anchor.id;
        engine.append(anchor).unwrap();
        let child = |conf: &str, hyp: f32, text: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, text.as_bytes().to_vec());
            e.parents.push(a_id);
            e.attrs.insert("confidence".into(), conf.into());
            e.embedding = Some(ProductPoint {
                hyp: vec![hyp],
                sph: vec![],
                euc: vec![],
            });
            engine.append(e).unwrap();
        };
        child("0.7", 0.65, "fraude");
        child("1.0", 0.0, "pagamento rotineiro");
        child("0.2", 0.5, "transferencia comum");
        child("0.2", 0.95, "fraude fraude");

        let q = format!("FUSE (\"fraude\", [0.5], \"{a_id}\", 10)");
        let v = heraclitus_query::execute(&q, &engine).unwrap();
        let rows = v.as_array().unwrap();
        assert!(!rows.is_empty(), "fusion returns candidates");
        // Every row carries the audited per-channel breakdown.
        for r in rows {
            assert!(r["graph_score"].is_number());
            assert!(r["vector_score"].is_number());
            assert!(r["text_score"].is_number());
            assert!(r["score"].is_number());
        }
        let v2 = heraclitus_query::execute(&q, &engine).unwrap();
        assert_eq!(v, v2, "reproducible on the engine too");
    }

    #[test]
    fn m11_entity_resolution_view_equals_replay() {
        // M11 GATE: the incrementally maintained resolver equals a from-scratch
        // replay, and RESOLVE/CLUSTER via GQL match the reference backend.
        use heraclitus_query::backend::replay_resolver;
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());

        let mention = |key: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("entity_key".into(), key.into());
            e
        };
        let merge = |a: &str, b: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("er_op".into(), "merge".into());
            e.attrs.insert("er_a".into(), a.into());
            e.attrs.insert("er_b".into(), b.into());
            e
        };
        engine.append(mention("CPF:111")).unwrap();
        engine.append(mention("CPF:222")).unwrap();
        engine.append(mention("CPF:333")).unwrap();
        engine.append(merge("CPF:222", "CPF:111")).unwrap();
        engine.append(merge("CPF:333", "CPF:111")).unwrap();

        // View == replay (bit-identical).
        let replayed = replay_resolver(&engine.log).unwrap();
        let live = engine.entity.write().unwrap();
        assert_eq!(live.state_hash(), replayed.state_hash());
        drop(live);

        // GQL on the real engine matches the reference backend.
        let be = LogBackend::new(engine.log.clone());
        for q in [
            "RESOLVE (\"CPF:333\")",
            "RESOLVE (\"CPF:222\") AS OF LSN 3",
            "CLUSTER (\"CPF:111\")",
        ] {
            assert_eq!(
                heraclitus_query::execute(q, &engine).unwrap(),
                heraclitus_query::execute(q, &be).unwrap(),
                "engine vs reference disagree on `{q}`"
            );
        }
        // All three CPFs collapsed onto one entity.
        let cluster = heraclitus_query::execute("CLUSTER (\"CPF:111\")", &engine).unwrap();
        assert_eq!(cluster.as_array().unwrap().len(), 3);
    }

    #[test]
    fn m12_hypothesis_graph_via_gql_matches_reference() {
        // M12 GATE: conflicting hypotheses on one edge coexist; HYPOTHESES on the
        // real (view) engine matches the reference (replay), including AS OF.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        let hyp = |hid: &str, conf: &str, stance: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), "X".into());
            e.attrs.insert("edge_to".into(), "Y".into());
            e.attrs.insert("edge_type".into(), "fraud_partner".into());
            e.attrs.insert("hypothesis".into(), hid.into());
            e.attrs.insert("confidence".into(), conf.into());
            e.attrs.insert("stance".into(), stance.into());
            e
        };
        engine.append(hyp("R1", "0.8", "support")).unwrap();
        engine.append(hyp("R2", "0.6", "refute")).unwrap();

        // View == replay (the extra version must be in both).
        let replayed = replay_graph(&engine.log).unwrap();
        let live = engine.tgraph.write().unwrap();
        assert_eq!(live.state_hash(), replayed.state_hash());
        assert_eq!(live.edges.len(), 1, "one edge, two hypotheses");
        drop(live);

        let be = LogBackend::new(engine.log.clone());
        for q in [
            "HYPOTHESES (\"X\", \"Y\", \"fraud_partner\")",
            "HYPOTHESES (\"X\", \"Y\", \"fraud_partner\") AS OF LSN 1",
        ] {
            assert_eq!(
                heraclitus_query::execute(q, &engine).unwrap(),
                heraclitus_query::execute(q, &be).unwrap(),
                "engine vs reference disagree on `{q}`"
            );
        }
        let v = heraclitus_query::execute("HYPOTHESES (\"X\", \"Y\", \"fraud_partner\")", &engine)
            .unwrap();
        assert_eq!(v["hypotheses"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn m13_why_via_gql_matches_reference() {
        // M13 GATE: WHY over the provenance DAG. The real engine and the
        // reference backend agree, and the trace bottoms out at the roots.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        let a = Episode::new("ag", EventKind::Observation, b"a".to_vec());
        let b = Episode::new("ag", EventKind::Observation, b"b".to_vec());
        let mut f = Episode::new("distill", EventKind::FactDerived, b"f".to_vec());
        f.parents = vec![a.id, b.id];
        let mut d = Episode::new("ag", EventKind::Action, b"d".to_vec());
        d.parents = vec![f.id];
        let did = d.id.to_string();
        for e in [a, b, f, d] {
            engine.append(e).unwrap();
        }

        let be = LogBackend::new(engine.log.clone());
        let q = format!("WHY (\"{did}\")");
        assert_eq!(
            heraclitus_query::execute(&q, &engine).unwrap(),
            heraclitus_query::execute(&q, &be).unwrap(),
            "engine vs reference disagree on WHY"
        );
        let v = heraclitus_query::execute(&q, &engine).unwrap();
        assert_eq!(v["steps"].as_array().unwrap().len(), 4);
        assert_eq!(
            v["roots"].as_array().unwrap().len(),
            2,
            "two root observations"
        );
    }

    #[test]
    fn m14_analytics_via_gql_matches_reference() {
        // M14 GATE: COMMUNITY/METRICS on the real engine match the reference and
        // detect the fraud rings consistently.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        let edge = |from: &str, to: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), from.into());
            e.attrs.insert("edge_to".into(), to.into());
            e.attrs.insert("edge_type".into(), "socio_de".into());
            e
        };
        for (a, b) in [("A1", "A2"), ("A2", "A3"), ("A3", "A1"), ("B1", "B2")] {
            engine.append(edge(a, b)).unwrap();
        }
        let be = LogBackend::new(engine.log.clone());
        for q in [
            "COMMUNITY (\"A1\")",
            "METRICS (\"A1\")",
            "COMMUNITY (\"B1\")",
        ] {
            assert_eq!(
                heraclitus_query::execute(q, &engine).unwrap(),
                heraclitus_query::execute(q, &be).unwrap(),
                "engine vs reference disagree on `{q}`"
            );
        }
        let v = heraclitus_query::execute("COMMUNITY (\"A1\")", &engine).unwrap();
        assert_eq!(v["members"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn m15_decide_emits_actions_reproducible_via_replay() {
        // M15 GATE: a decision is an Action event in the log; a fresh engine
        // replaying the same data sees the decisions; re-deciding is idempotent.
        let dir = tempfile::tempdir().unwrap();
        let edge = |from: &str, to: &str, etype: &str, conf: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), from.into());
            e.attrs.insert("edge_to".into(), to.into());
            e.attrs.insert("edge_type".into(), etype.into());
            e.attrs.insert("confidence".into(), conf.into());
            e
        };
        let fired = {
            let engine = engine_in(dir.path());
            for leaf in ["L1", "L2", "L3", "L4"] {
                engine.append(edge("H", leaf, "socio_de", "1.0")).unwrap();
            }
            engine
                .append(edge("X", "Y", "fraud_partner", "0.9"))
                .unwrap();
            let v = heraclitus_query::execute("DECIDE ()", &engine).unwrap();
            v["fired"].as_array().unwrap().len()
        };
        assert!(fired >= 2, "hub and fraud edge flagged");

        // Reopen: replay reconstructs the decisions (they are log events).
        let engine2 = engine_in(dir.path());
        let actions = heraclitus_query::execute("MATCH (n:Action) RETURN n", &engine2).unwrap();
        assert_eq!(
            actions.as_array().unwrap().len(),
            fired,
            "replay reproduces decisions"
        );

        // Deciding again on the reopened engine is idempotent.
        let v2 = heraclitus_query::execute("DECIDE ()", &engine2).unwrap();
        assert!(
            v2["fired"].as_array().unwrap().is_empty(),
            "no duplicate actions after replay"
        );
        assert_eq!(v2["skipped"].as_array().unwrap().len(), fired);
    }

    #[test]
    fn m16_simulate_does_not_touch_the_real_engine() {
        // M16 GATE: a counterfactual on the real engine changes the observed
        // result but leaves the base graph and the log untouched.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        let edge = |from: &str, to: &str| {
            let mut e = Episode::new("ag", EventKind::Observation, vec![]);
            e.attrs.insert("edge_from".into(), from.into());
            e.attrs.insert("edge_to".into(), to.into());
            e.attrs.insert("edge_type".into(), "socio_de".into());
            e
        };
        for (a, b) in [
            ("A1", "A2"),
            ("A2", "A3"),
            ("A3", "A1"),
            ("B1", "B2"),
            ("A1", "B1"),
        ] {
            engine.append(edge(a, b)).unwrap();
        }
        let head_before = engine.snapshot();
        let real = heraclitus_query::execute("COMMUNITY (\"A1\")", &engine).unwrap();
        assert_eq!(
            real["members"].as_array().unwrap().len(),
            5,
            "A1..A3 + B1,B2 joined"
        );

        // Counterfactual removal splits the community.
        let cf = heraclitus_query::execute(
            "SIMULATE REMOVE EDGE (\"A1\", \"B1\", \"socio_de\") THEN COMMUNITY (\"A1\")",
            &engine,
        )
        .unwrap();
        assert_eq!(
            cf["members"].as_array().unwrap().len(),
            3,
            "bridge removed in the counterfactual"
        );

        // Base + log untouched.
        let real_again = heraclitus_query::execute("COMMUNITY (\"A1\")", &engine).unwrap();
        assert_eq!(real_again["members"].as_array().unwrap().len(), 5);
        assert_eq!(engine.snapshot(), head_before, "the log head did not move");
    }

    #[test]
    fn m17_adapt_learns_and_is_replay_stable() {
        // M17 GATE: ADAPT learns a better threshold from feedback on the engine,
        // and a reopened engine (replay) learns the exact same rule.
        let dir = tempfile::tempdir().unwrap();
        let feedback = |score: &str, verdict: &str| {
            let mut e = Episode::new("analyst", EventKind::Observation, vec![]);
            e.attrs
                .insert("feedback_rule".into(), "flag_anomaly".into());
            e.attrs.insert("score".into(), score.into());
            e.attrs.insert("verdict".into(), verdict.into());
            e
        };
        let learned = {
            let engine = engine_in(dir.path());
            for (s, v) in [
                ("3.0", "confirm"),
                ("2.0", "confirm"),
                ("1.6", "reject"),
                ("1.0", "reject"),
            ] {
                engine.append(feedback(s, v)).unwrap();
            }
            let r = heraclitus_query::execute("ADAPT ()", &engine).unwrap();
            assert!(r["adapted"]["f1"].as_f64().unwrap() > r["default"]["f1"].as_f64().unwrap());
            r["learned_threshold"].as_f64().unwrap()
        };

        // Reopen and re-learn: replay yields the identical rule.
        let engine2 = engine_in(dir.path());
        let r2 = heraclitus_query::execute("ADAPT ()", &engine2).unwrap();
        assert_eq!(
            r2["learned_threshold"].as_f64().unwrap(),
            learned,
            "replay learns the same rule"
        );
    }

    #[test]
    fn m18_require_lsn_contract_on_the_engine() {
        // M18 GATE: read-your-writes via the consistency contract. After N
        // appends, REQUIRE LSN >= N succeeds and REQUIRE LSN >= N+1 fails.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        for i in 0..3 {
            engine
                .append(Episode::new(
                    "ag",
                    EventKind::Observation,
                    format!("e{i}").into_bytes(),
                ))
                .unwrap();
        }
        let head = engine.snapshot();
        assert_eq!(head, 3);

        let ok = heraclitus_query::execute(
            &format!("REQUIRE LSN >= {head} MATCH (n) RETURN n"),
            &engine,
        )
        .unwrap();
        assert_eq!(ok.as_array().unwrap().len(), 3);

        let err = heraclitus_query::execute(
            &format!("REQUIRE LSN >= {} MATCH (n) RETURN n", head + 1),
            &engine,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("consistency requirement not met"));
    }

    #[test]
    fn attr_index_resolves_equality_and_matches_reference() {
        // O índice secundário: `MATCH (n) WHERE n.cnpj = "X"` resolve pelo índice
        // (não por scan) e devolve exatamente os mesmos nós que a referência.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path());
        for i in 0..500u64 {
            let mut e = Episode::new(
                "etl",
                EventKind::Observation,
                format!("emp {i}").into_bytes(),
            );
            let cnpj = if i % 50 == 7 {
                "11222333000144".to_string()
            } else {
                format!("{i:014}")
            };
            e.attrs.insert("cnpj".into(), cnpj);
            e.attrs.insert("uf".into(), "MG".into());
            engine.append(e).unwrap();
        }
        let q = r#"MATCH (n) WHERE n.cnpj = "11222333000144" RETURN n"#;
        let via_engine = heraclitus_query::execute(q, &engine).unwrap();
        // 10 ocorrências (i = 7,57,…,457)
        assert_eq!(via_engine.as_array().unwrap().len(), 10);

        // índice == scan de referência (mesmas linhas, mesma ordem)
        let be = LogBackend::new(engine.log.clone());
        let via_ref = heraclitus_query::execute(q, &be).unwrap();
        assert_eq!(
            via_engine, via_ref,
            "índice deve igualar o scan de referência"
        );

        // campo arbitrário também é indexado (uf), e valor inexistente => vazio
        assert_eq!(
            heraclitus_query::execute(r#"MATCH (n) WHERE n.uf = "MG" RETURN n"#, &engine)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            500
        );
        assert!(
            heraclitus_query::execute(r#"MATCH (n) WHERE n.cnpj = "0000" RETURN n"#, &engine)
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    /// SPEC-0046 §94 — a janela que o `reconcile_legal_holds` fecha, e que so
    /// passou a importar quando o hold se tornou colocavel.
    ///
    /// O `set_legal_hold_range` marca os segmentos que EXISTEM no momento em
    /// que o hold e colocado. Um segmento selado depois disso, dentro do mesmo
    /// intervalo de LSN, ficava sem o bit no HRKM — e o GC automatico
    /// coletava-o, apagando prova sob retencao judicial sem nada o assinalar.
    ///
    /// A task de GC do servidor passou a reconciliar antes de cada passagem.
    /// Este teste faz o mesmo pela via directa: coloca o hold, sela DEPOIS, e
    /// verifica que so apos a reconciliacao o segmento novo fica protegido.
    #[test]
    fn a_reconciliacao_protege_um_segmento_selado_depois_do_hold() {
        use heraclitus_compliance::RegulatoryPolicyEngine;

        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            storage_format: heraclitus_core::StorageFormat::V6,
            ..Default::default()
        };
        let engine = Arc::new(Engine::open(&cfg).unwrap());
        engine
            .append(Episode::new("a", EventKind::Observation, b"antes".to_vec()))
            .unwrap();

        // Hold com fim aberto ate um LSN muito a frente: cobre o que vier.
        let (ok, msg) = crate::grpc::legal_hold_op(
            &engine,
            "legal-hold-place",
            r#"{"hold_id":"h","lsn_start":0,"lsn_end":1000000,
                "authority":"tribunal","reason":"preservar"}"#,
        );
        assert!(ok, "{msg}");

        let v6 = engine.log.v6_arc().expect("v6");
        // Um segmento NOVO, selado depois de o hold ter sido colocado.
        engine
            .append(Episode::new(
                "a",
                EventKind::Observation,
                b"depois".to_vec(),
            ))
            .unwrap();
        v6.seal_active().unwrap();

        let sem_hold = v6
            .manifest()
            .segments_v2
            .iter()
            .filter(|s| !s.retention.legal_hold)
            .count();
        assert!(
            sem_hold > 0,
            "premissa do teste: tem de haver um segmento por proteger antes da reconciliacao"
        );

        let marcados = RegulatoryPolicyEngine::new(engine.log.clone())
            .reconcile_legal_holds()
            .unwrap();
        assert!(marcados > 0, "a reconciliacao nao marcou nada");
        assert_eq!(
            v6.manifest()
                .segments_v2
                .iter()
                .filter(|s| !s.retention.legal_hold)
                .count(),
            0,
            "sobrou um segmento no intervalo do hold sem proteccao no HRKM"
        );
    }
}

#[cfg(test)]
mod legal_hold_entrypoint_tests {
    use super::*;
    use heraclitus_core::config::HeraclitusConfig;
    use heraclitus_core::{Episode, EventKind, FsyncPolicy};
    use std::sync::Arc;

    /// SPEC-0046 §94 / C10 — a porta de entrada do legal hold.
    ///
    /// A verificacao adversarial de 2026-08-30 apurou que o circuito estava
    /// inteiro e era **inalcancavel**: `place_legal_hold` persiste o evento e
    /// carimba o HRKM, o `plan_gc` respeita-o, o `ensure_crypto_shred_allowed`
    /// bloqueia — e nada em producao podia criar um hold. Nem rota REST, nem
    /// RPC, nem comando. §94 era uma garantia que so os testes exerciam.
    ///
    /// Este teste percorre a operacao do RPC `admin`, com o corpo JSON que um
    /// operador enviaria, e verifica o EFEITO: bloqueia, lista, liberta.
    #[test]
    fn a_operacao_admin_coloca_lista_e_levanta_um_hold() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            storage_format: heraclitus_core::StorageFormat::V6,
            encryption_at_rest: true,
            ..Default::default()
        };
        let engine = Arc::new(Engine::open(&cfg).unwrap());
        let agent = "titular:hmac-sha256:sujeito-retido";
        let lsn = engine
            .append(Episode::new(
                agent,
                EventKind::Custom("PersonalData".into()),
                b"protegido".to_vec(),
            ))
            .unwrap();

        // Antes do hold, o shred passa — e este ramo do teste e o que da
        // significado ao resto: sem ele, "bloqueado" podia ser um shred que
        // nunca funcionou.
        let sonda = "titular:hmac-sha256:sem-hold";
        engine
            .append(Episode::new(
                sonda,
                EventKind::Custom("PersonalData".into()),
                b"efemero".to_vec(),
            ))
            .unwrap();
        assert!(engine.shred(sonda).unwrap());

        let (ok, msg) = crate::grpc::legal_hold_op(
            &engine,
            "legal-hold-place",
            &format!(
                r#"{{"hold_id":"hold-1","lsn_start":{lsn},"lsn_end":{lsn},
                     "authority":"tribunal","reason":"preservar prova"}}"#
            ),
        );
        assert!(ok, "{msg}");

        // A listagem diz a verdade sobre o que esta retido.
        let (ok, listagem) = crate::grpc::legal_hold_op(&engine, "legal-holds", "");
        assert!(ok, "{listagem}");
        let holds: serde_json::Value = serde_json::from_str(&listagem).unwrap();
        assert_eq!(holds.as_array().unwrap().len(), 1);
        assert_eq!(holds[0]["hold_id"], "hold-1");
        assert_eq!(holds[0]["authority"], "tribunal");

        // O efeito: §98 (crypto-shred) cede perante §94 (legal hold) — C10.
        assert!(engine.shred(agent).is_err());
        assert_eq!(
            engine.log.read(lsn).unwrap().unwrap().1.content,
            b"protegido"
        );

        // E o GC nao pode coletar o que esta retido.
        if let Some(v6) = engine.log.v6_arc() {
            let plano = v6
                .gc_plan(heraclitus_log::v6::GcRunOptions::default())
                .unwrap();
            assert!(
                plano.generations.is_empty(),
                "o GC nao pode ter candidatos com um hold activo: {:?}",
                plano.generations
            );
        }

        // Levantar exige autoridade e razao, e e auditado no log.
        let (ok, msg) = crate::grpc::legal_hold_op(
            &engine,
            "legal-hold-release",
            r#"{"hold_id":"hold-1","authority":"tribunal","reason":"caso encerrado"}"#,
        );
        assert!(ok, "{msg}");

        let (_, listagem) = crate::grpc::legal_hold_op(&engine, "legal-holds", "");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&listagem)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert!(engine.shred(agent).unwrap());
    }

    /// Um pedido sem autoridade ou sem razao e recusado: um hold anonimo nao
    /// e accionavel por quem o tiver de justificar depois.
    #[test]
    fn um_hold_sem_autoridade_ou_razao_e_recusado() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            storage_format: heraclitus_core::StorageFormat::V6,
            ..Default::default()
        };
        let engine = Arc::new(Engine::open(&cfg).unwrap());
        for corpo in [
            r#"{"hold_id":"h","lsn_start":0,"lsn_end":0,"reason":"r"}"#,
            r#"{"hold_id":"h","lsn_start":0,"lsn_end":0,"authority":"a"}"#,
            r#"{"lsn_start":0,"lsn_end":0,"authority":"a","reason":"r"}"#,
            "isto nao e json",
        ] {
            let (ok, _) = crate::grpc::legal_hold_op(&engine, "legal-hold-place", corpo);
            assert!(!ok, "aceitou um pedido incompleto: {corpo}");
        }
    }

    /// Sem `lsn_end`, o hold cobre o que existe AGORA — nao o futuro. Um hold
    /// de fim aberto reteria eventos que nenhuma autoridade avaliou.
    #[test]
    fn um_hold_sem_fim_nao_retem_o_futuro() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            storage_format: heraclitus_core::StorageFormat::V6,
            ..Default::default()
        };
        let engine = Arc::new(Engine::open(&cfg).unwrap());
        engine
            .append(Episode::new("a", EventKind::Observation, b"antes".to_vec()))
            .unwrap();
        let (ok, _) = crate::grpc::legal_hold_op(
            &engine,
            "legal-hold-place",
            r#"{"hold_id":"h","authority":"a","reason":"r"}"#,
        );
        assert!(ok);
        let depois = engine
            .append(Episode::new(
                "a",
                EventKind::Observation,
                b"depois".to_vec(),
            ))
            .unwrap();

        let (_, listagem) = crate::grpc::legal_hold_op(&engine, "legal-holds", "");
        let holds: serde_json::Value = serde_json::from_str(&listagem).unwrap();
        assert!(
            holds[0]["lsn_end"].as_u64().unwrap() < depois,
            "o hold cobriu um evento posterior a sua criacao"
        );
    }
}

#[cfg(test)]
mod regulatory_entrypoint_tests {
    use super::*;
    use heraclitus_compliance::{
        BusinessCalendar, ComplianceContext, ComplianceEvidenceRef, CompliancePredicate,
        ComplianceRequirement, ConfiguredRegulatoryPolicy, DeadlinePolicy, DeferredAnchorRequest,
        DeferredTransferPolicy, IncidentPackageData, InstitutionalSigner, LocalTsa,
        ModelBundlePolicy, ModelManifest, PolicyActivation, PolicyIdentity, PrivacyExportPolicy,
        PrivacyIncidentAssessment, RegulatoryRule, RequirementEffect, RetentionClass, RiskLevel,
        SignedDeferredAnchorRequest, SoftKeySigner,
    };
    use heraclitus_core::{FsyncPolicy, HeraclitusConfig};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    #[test]
    fn admin_activates_evaluates_lists_and_enforces_regulatory_policy() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            encryption_at_rest: true,
            ..Default::default()
        };
        let engine = Arc::new(Engine::open(&cfg).unwrap());
        let subject = "titular:hmac-sha256:policy-protected";
        engine
            .append(Episode::new(
                subject,
                EventKind::Custom("PersonalData".into()),
                b"protected by policy".to_vec(),
            ))
            .unwrap();

        let policy = ConfiguredRegulatoryPolicy::new(
            "lgpd-retention",
            "2026.1",
            0,
            vec![RegulatoryRule {
                rule_id: "prevent-personal-data-destruction".into(),
                predicate: CompliancePredicate {
                    event_kind: Some("PersonalData".into()),
                    retention_class: Some(RetentionClass::PersonalData),
                    attr_equals: BTreeMap::new(),
                },
                requirements: vec![ComplianceRequirement {
                    requirement_id: "legal-basis-required".into(),
                    legal_basis: "LGPD art. 16".into(),
                    effect: RequirementEffect::PreventDestruction,
                }],
            }],
        )
        .unwrap();
        let activation = PolicyActivation {
            policy,
            activated_by: "dpo@example.test".into(),
            approval_ref: "change-0046".into(),
        };
        let (ok, message) = crate::grpc::regulatory_policy_op(
            &engine,
            "regulatory-policy-activate",
            &serde_json::to_string(&activation).unwrap(),
        );
        assert!(ok, "{message}");

        let context = ComplianceContext {
            subject_id: subject.into(),
            event_kind: "PersonalData".into(),
            attrs: BTreeMap::new(),
            retention_class: RetentionClass::PersonalData,
            effective_at: 0,
            as_of_lsn: engine.log.head().saturating_sub(1),
        };
        let request = serde_json::json!({
            "policy_id": "lgpd-retention",
            "context": context,
        });
        let (ok, decision) =
            crate::grpc::regulatory_policy_op(&engine, "regulatory-evaluate", &request.to_string());
        assert!(ok, "{decision}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&decision).unwrap()["decision"]
                ["requirements"][0]["effect"]["effect"],
            "prevent_destruction"
        );

        let (ok, policies) = crate::grpc::regulatory_policy_op(&engine, "regulatory-policies", "");
        assert!(ok, "{policies}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&policies)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let (ok, decisions) =
            crate::grpc::regulatory_policy_op(&engine, "regulatory-decisions", "");
        assert!(ok, "{decisions}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&decisions)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );

        assert!(
            engine.shred(subject).is_err(),
            "a decisão persistida precisa bloquear a destruição real"
        );
    }

    #[test]
    fn admin_builds_auditable_anpd_draft_under_the_server_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            ..Default::default()
        };
        let engine = Arc::new(Engine::open(&cfg).unwrap());
        let evidence = Episode::new(
            "sentinel",
            EventKind::Custom("IncidentEvidence".into()),
            b"evidence".to_vec(),
        );
        let evidence_id = evidence.id;
        let evidence_lsn = engine.append_internal(evidence).unwrap();
        let evidence_ref = ComplianceEvidenceRef {
            lsn: evidence_lsn,
            event_id: evidence_id,
            relation: "source incident".into(),
        };
        let assessment = PrivacyIncidentAssessment {
            assessment_id: "assessment-anpd-1".into(),
            incident_id: "incident-anpd-1".into(),
            personal_data_involved: true,
            categories: vec!["credentials".into()],
            estimated_subjects: Some(12),
            vulnerable_subjects: false,
            sensitive_data: false,
            estimated_risk: RiskLevel::High,
            evidence: vec![evidence_ref.clone()],
            assessed_by: "privacy-officer".into(),
            assessed_at_lsn: engine.log.head(),
            policy: PolicyIdentity {
                policy_id: "incident-assessment".into(),
                version: "2026.1".into(),
                digest: [7; 32],
                effective_from: 0,
            },
        };
        let (ok, message) = crate::grpc::privacy_incident_op(
            &engine,
            "privacy-assessment",
            &serde_json::to_string(&assessment).unwrap(),
        );
        assert!(ok, "{message}");

        let deadline_policy = DeadlinePolicy::new(
            "anpd-deadline",
            "resolution-15-2024/v1",
            0,
            "ANPD",
            3,
            20,
            "Resolução CD/ANPD 15/2024",
            BusinessCalendar::default(),
        )
        .unwrap();
        let deadline_request = serde_json::json!({
            "incident_id": "incident-anpd-1",
            "triggered_at": 0,
            "policy": deadline_policy,
        });
        let (ok, deadline_response) = crate::grpc::privacy_incident_op(
            &engine,
            "privacy-deadline",
            &deadline_request.to_string(),
        );
        assert!(ok, "{deadline_response}");
        let deadline_id = serde_json::from_str::<serde_json::Value>(&deadline_response).unwrap()
            ["deadline"]["deadline_id"]
            .as_str()
            .unwrap()
            .to_owned();

        let export_policy = PrivacyExportPolicy::new(
            "anpd-export",
            "2026.1",
            0,
            [
                "assessment".into(),
                "incident".into(),
                "affected_data".into(),
                "mitigation".into(),
                "timeline".into(),
            ]
            .into_iter()
            .collect::<BTreeSet<String>>(),
            BTreeSet::new(),
        )
        .unwrap();
        let package_request = serde_json::json!({
            "assessment_id": "assessment-anpd-1",
            "deadline_id": deadline_id,
            "export_id": "incident-anpd-1",
            "data": IncidentPackageData {
                summary: "credential disclosure under investigation".into(),
                affected_assets: vec!["portal".into()],
                affected_data: BTreeMap::from([("category".into(), "credential".into())]),
                mitigation_actions: vec!["credential rotation".into()],
                timeline: vec![evidence_ref],
                evidence_anchor_ids: vec!["anchor-1".into()],
            },
            "export_policy": export_policy,
        });
        let (ok, package_response) = crate::grpc::privacy_incident_op(
            &engine,
            "privacy-package",
            &package_request.to_string(),
        );
        assert!(ok, "{package_response}");
        let expected = dir.path().join("compliance/exports/anpd/incident-anpd-1");
        assert!(expected.join("evidence-manifest.json").is_file());
        assert!(expected.join("privacy-sanitization.json").is_file());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&package_response).unwrap()["receipt"]
                ["submission_state"],
            "awaiting_human_authorization"
        );

        let (ok, state) = crate::grpc::privacy_incident_op(&engine, "privacy-state", "");
        assert!(ok, "{state}");
        let state: serde_json::Value = serde_json::from_str(&state).unwrap();
        assert_eq!(state["assessments"].as_array().unwrap().len(), 1);
        assert_eq!(state["deadlines"].as_array().unwrap().len(), 1);
        assert_eq!(state["exports"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn admin_prepares_and_imports_a_signed_air_gap_anchor_without_raw_events() {
        use heraclitus_compliance::{stamp_deferred_request, BundleSignatureScheme};

        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            storage_format: heraclitus_core::StorageFormat::V6,
            ..Default::default()
        };
        let engine = Arc::new(Engine::open(&cfg).unwrap());
        engine
            .append(Episode::new(
                "evidence-source",
                EventKind::Observation,
                b"raw evidence must stay here".to_vec(),
            ))
            .unwrap();
        let v6 = engine.log.v6_arc().unwrap();
        v6.seal_active().unwrap();
        let sealed = v6.manifest().segments_v2[0].clone();

        let prepare = serde_json::json!({
            "lsn_start": sealed.first_lsn,
            "lsn_end": sealed.last_lsn,
            "created_at_hlc": 42,
        });
        let (ok, request_json) = crate::grpc::deferred_anchor_op(
            &engine,
            "deferred-anchor-prepare",
            &prepare.to_string(),
        );
        assert!(ok, "{request_json}");
        assert!(
            !request_json.contains("raw evidence"),
            "a fronteira air-gap transportou conteúdo bruto"
        );
        let request: DeferredAnchorRequest = serde_json::from_str(&request_json).unwrap();

        let export_signer = SoftKeySigner::generate("offline-zone");
        let response_signer = SoftKeySigner::generate("connected-zone");
        let signed_request = SignedDeferredAnchorRequest::sign(
            request,
            &export_signer,
            BundleSignatureScheme::P256Development,
        )
        .unwrap();
        let response_key = response_signer
            .sign_snapshot(b"key-discovery")
            .unwrap()
            .public_key_sec1;
        let policy = DeferredTransferPolicy {
            policy_id: "air-gap-transfer".into(),
            version: "2026.1".into(),
            approved_export_key_digests: [
                *blake3::hash(&signed_request.signature.public_key).as_bytes()
            ]
            .into_iter()
            .collect(),
            approved_response_key_digests: [*blake3::hash(&response_key).as_bytes()]
                .into_iter()
                .collect(),
            allowed_signature_schemes: [BundleSignatureScheme::P256Development]
                .into_iter()
                .collect(),
            max_timestamp_token_bytes: 1024 * 1024,
        };
        let tsa = LocalTsa::generate("ACT-dev");
        let signed_response = stamp_deferred_request(
            &signed_request,
            &policy,
            &tsa,
            &response_signer,
            BundleSignatureScheme::P256Development,
        )
        .unwrap();
        let import = serde_json::json!({
            "signed_request": signed_request,
            "signed_response": signed_response,
            "policy": policy,
        });
        let (ok, imported) =
            crate::grpc::deferred_anchor_op(&engine, "deferred-anchor-import", &import.to_string());
        assert!(ok, "{imported}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&imported).unwrap()["anchor"]
                ["validation_state"],
            "development_only"
        );

        let (ok, anchors) = crate::grpc::deferred_anchor_op(&engine, "deferred-anchors", "");
        assert!(ok, "{anchors}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&anchors)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn admin_verifies_and_activates_a_server_owned_offline_model_bundle() {
        use heraclitus_compliance::{build_signed_model_bundle, BundleSignatureScheme};

        let dir = tempfile::tempdir().unwrap();
        let cfg = HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            fsync: FsyncPolicy::Always,
            ..Default::default()
        };
        let engine = Arc::new(Engine::open(&cfg).unwrap());
        let root = engine
            .compliance_export_dir("model-bundles", "sentinel-investigator-v1")
            .unwrap();
        for directory in ["model", "tokenizer", "sbom"] {
            std::fs::create_dir_all(root.join(directory)).unwrap();
        }
        std::fs::write(root.join("model/weights.bin"), b"weights-v1").unwrap();
        std::fs::write(root.join("tokenizer/vocab.json"), b"{\"a\":1}").unwrap();
        std::fs::write(root.join("sbom/sbom.json"), b"{\"spdx\":true}").unwrap();

        let signer = SoftKeySigner::generate("model-release-office");
        let signed = build_signed_model_bundle(
            &root,
            ModelManifest {
                model_id: "sentinel-investigator".into(),
                version: "v1".into(),
                artifact_digest: [0; 32],
                tokenizer_digest: [0; 32],
                runtime_id: "onnxruntime".into(),
                runtime_version: "1.22".into(),
                quantization: None,
                approved_by: "security-office".into(),
            },
            &signer,
            BundleSignatureScheme::P256Development,
        )
        .unwrap();
        signed.write_metadata(&root).unwrap();
        let policy = ModelBundlePolicy {
            policy_id: "offline-models".into(),
            version: "2026.1".into(),
            allowed_models: ["sentinel-investigator".into()].into_iter().collect(),
            approved_runtimes: [("onnxruntime".into(), ["1.22".into()].into_iter().collect())]
                .into_iter()
                .collect(),
            approved_signer_key_digests: [*blake3::hash(&signed.signature.public_key).as_bytes()]
                .into_iter()
                .collect(),
            allowed_signature_schemes: [BundleSignatureScheme::P256Development]
                .into_iter()
                .collect(),
        };
        let request = serde_json::json!({
            "bundle_id": "sentinel-investigator-v1",
            "policy": policy,
        });
        let (ok, activation) =
            crate::grpc::model_bundle_op(&engine, "model-bundle-activate", &request.to_string());
        assert!(ok, "{activation}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&activation).unwrap()["bundle"]["model"]
                ["model_id"],
            "sentinel-investigator"
        );

        let (ok, bundles) = crate::grpc::model_bundle_op(&engine, "model-bundles", "");
        assert!(ok, "{bundles}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&bundles)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}
