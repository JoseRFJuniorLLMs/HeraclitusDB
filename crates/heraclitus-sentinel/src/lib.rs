//! Heraclitus Sentinel — Fases 0–6 security derivation plane.
//!
//! The runtime is deliberately small and conservative: the log remains the
//! source of truth, the subscriber only enqueues LSNs, and workers normalize
//! events off the append path.  Later runtime adapters can consume the same
//! replay/cursor interfaces without changing this boundary.  Fase 2's
//! behavioural engine and canonical event-to-feature adapter are opt-in and
//! replay through the same transaction-LSN ordered worker.  Fase 3 adds
//! temporal graph, incident grouping and deterministic
//! evidence-fusion primitives; its graph/incident runtime adapter is opt-in and
//! persists incident revisions through a host-provided derived-event sink.
//! Fase 4 adds a bounded
//! and redacted L4 context/model boundary with typed, allowlisted actions.
//! Fase 5 adds deterministic policy decisions and a typed executor boundary.
//! Fase 6 adds leader epoch/lease, idempotent action identity and the AI
//! circuit breaker; all are coordination primitives with no external I/O.

pub mod ai;
pub mod autonomy;
pub mod behavior;
pub mod config;
pub mod correlation;
pub mod cursor;
pub mod detection;
pub mod error;
pub mod event;
pub mod execution;
pub mod governance;
pub mod metrics;
pub mod normalize;
pub mod policy;
pub mod queue;
pub mod sigma;
pub mod state;
pub mod subscriber;
pub mod threat;

pub use ai::{
    ActionCapability, ActionKind, ActionProposal, AiContextBuilder, AiError, AiInvocationAudit,
    ContextBudget, DetectorFinding, EntityContext, EnvironmentContext, Hypothesis, IncidentContext,
    InvestigationQuery, InvestigationResult, ModelBackend, RelatedIncident, SecurityAction,
    SecurityInvestigation, SensitiveDataFilter, TimelineItem,
};
pub use autonomy::{AutonomousMode, AutonomousRequirements, AutonomyError, GateEvidence};
pub use behavior::{
    security_event_inputs, BaselinePolicy, BehaviorError, BehavioralEngine, BehavioralInput,
    BehavioralObservation, BehavioralProfile, BehavioralScore, BehavioralSnapshot, EwmaState,
    FeatureId, FeatureValue, MomentState, ObservationDisposition, ProfileTrustState, QuantileState,
};
pub use config::{
    SentinelConfig, SentinelL1Config, SentinelL2Config, SentinelL3Config, SentinelMode,
};
pub use correlation::{
    high_impact_allowed, independent_detector_count, security_event_edges, CorrelationError,
    DetectorAgreement, DetectorChannel, EvidenceFusion, FusionWeights, GraphEdgeObservation,
    GraphPath, IncidentEngine, IncidentEngineSnapshot, IncidentIngestResult, IncidentPolicy,
    IncidentState, IncidentTransition, MitreMapping, RiskAssessment, SecurityEdgeKind,
    SecurityEntityKind, SecurityIncident, TemporalSecurityEdge, TemporalSecurityGraph,
    TemporalSecurityGraphSnapshot,
};
pub use cursor::SentinelCursor;
pub use detection::{DetectionExpr, DetectionRule, Field, RuleCompileError, RuleEngine, Value};
pub use error::SentinelError;
pub use event::{
    DetectorIdentity, EntityRef, EvidenceRef, NetworkEndpoint, Outcome, SecurityCategory,
    SecurityEvent, SecuritySignal, SecuritySource,
};
pub use execution::{
    deterministic_action_id, ActionDispatch, ActionLease, AiCircuitBreaker, CircuitBreakerConfig,
    CircuitState, DryRunExecutor, LeaseError, MemoryReversibleExecutor, SentinelEpoch,
};
pub use governance::{
    FeedbackLabel, GovernanceError, SecurityFeedback, SecurityModelUpdate, SecurityRulesetUpdate,
};
pub use metrics::{SecurityLagState, SentinelMetrics, SentinelStatus};
pub use normalize::{GenericNormalizer, NormalizedSecurityEvent};
pub use policy::{
    ActionResult, ActionRule, AuthorizedAction, DeterministicPolicyEngine, ExecutionConstraints,
    HumanApproval, PolicyConfig, PolicyDecision, PolicyEngine, PolicyError, SecurityActionExecutor,
};
pub use queue::{EnqueueOutcome, QueueSnapshot, SecurityQueue};
pub use sigma::{
    compile_sigma, compile_sigma_file, compile_sigma_path, compile_sigma_rules, parse_sigma,
};
pub use state::{replay, CursorStore, ReplayReport, SentinelCheckpoint};
pub use subscriber::SecuritySubscriber;
pub use threat::{
    Admission, CanonicalError, ConfirmedMatch, FeedVersionState, HashAlgorithm, Indicator,
    IndicatorState, IocIndex, IpCidr, MatchKind, PrefilterOutcome, Pseudonymizer,
    SanitizationError, SanitizedThreatObject, SharingPolicy, StixImporter, ThreatFeed,
    ThreatFeedUpdate, ThreatGateError, ThreatImportError, ThreatImporter, ThreatInputLimits,
    ThreatIntelDetector, ThreatObject, ThreatObjectType, ThreatProvenance, ThreatSanitizer,
    ThreatSighting, ThreatSourcePolicy, ThreatSourceRegistry, TlpLevel, TrustLevel,
};

use heraclitus_core::{Episode, EventId, EventKind, HeraclitusError, Lsn};
use heraclitus_log::subscribe::attach_subscriber_with_stop;
use heraclitus_log::AnyLog;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Bounded incident query used by the internal SPEC-0045 §87 API.  `as_of_lsn`
/// refers to transaction/log time: the latest durable incident revision at or
/// before that LSN wins.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IncidentFilter {
    pub state: Option<IncidentState>,
    pub min_severity: Option<u8>,
    pub subject: Option<EntityRef>,
    pub as_of_lsn: Option<Lsn>,
    pub limit: Option<usize>,
}

/// Host-facing contract from SPEC-0045 §87.
pub trait Sentinel {
    fn status(&self) -> SentinelStatus;
    fn incident(&self, id: &str) -> Result<Option<SecurityIncident>, SentinelError>;
    fn incidents(&self, filter: IncidentFilter) -> Result<Vec<SecurityIncident>, SentinelError>;
}

/// Host-owned append boundary for every event derived by Sentinel.  The server
/// implements this over `Engine`, so a derived event follows the same indexing
/// and replication path as any other authoritative write.  The callback is
/// invoked only by background workers, never by `StreamSubscriber::on_append`.
pub trait DerivedEventSink: Send + Sync {
    /// `idempotency_key` is stable for the logical derived revision.  Hosts
    /// with an exactly-once append facility should persistently deduplicate it.
    fn append(&self, episode: Episode, idempotency_key: &str) -> Result<Lsn, HeraclitusError>;
}

/// Host-provided leadership view for clustered Sentinel operation. `None`
/// means this process is not currently authoritative and must not perform L4
/// investigation, approval, or external execution. L0-L3 remain safe to run
/// on every replica because derived writes are idempotent and replicated.
pub trait LeaderOwnership: Send + Sync {
    fn current_epoch(&self) -> Option<SentinelEpoch>;
}

struct DirectLogSink {
    log: Arc<AnyLog>,
}

impl DerivedEventSink for DirectLogSink {
    fn append(&self, episode: Episode, _idempotency_key: &str) -> Result<Lsn, HeraclitusError> {
        self.log.append(episode)
    }
}

/// Conjunto de chaves recentes com tecto: deduplica sem crescer para sempre.
///
/// Um `HashSet` puro num processo de vida longa e um vazamento com outro nome.
/// Aqui a ordem de insercao vive num `VecDeque` e a mais antiga sai quando o
/// tecto e atingido.
#[derive(Debug)]
pub(crate) struct JanelaRecente<T> {
    vistas: HashSet<T>,
    ordem: VecDeque<T>,
    tecto: usize,
}

impl<T: std::hash::Hash + Eq + Clone> JanelaRecente<T> {
    pub(crate) fn nova(tecto: usize) -> Self {
        Self {
            vistas: HashSet::new(),
            ordem: VecDeque::new(),
            tecto: tecto.max(1),
        }
    }

    /// `true` se a chave e NOVA (e portanto o trabalho deve ser feito).
    pub(crate) fn inserir(&mut self, chave: &T) -> bool {
        if self.vistas.contains(chave) {
            return false;
        }
        if self.ordem.len() >= self.tecto {
            if let Some(velha) = self.ordem.pop_front() {
                self.vistas.remove(&velha);
            }
        }
        self.vistas.insert(chave.clone());
        self.ordem.push_back(chave.clone());
        true
    }

    pub(crate) fn contem(&self, chave: &T) -> bool {
        self.vistas.contains(chave)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn len(&self) -> usize {
        self.ordem.len()
    }
}

/// Nome antigo, mantido para o sitio que so lida com chaves de texto.
pub(crate) type JanelaDeChaves = JanelaRecente<String>;

/// Quantas chaves de sighting se guardam. O duplicado que a deduplicacao existe
/// para apanhar chega no mesmo ciclo de processamento, portanto isto e ordens de
/// grandeza mais do que o necessario — e continua a caber em poucos MB.
pub(crate) const TECTO_CHAVES_SIGHTING: usize = 65_536;

/// Quantos LSNs de origem se guardam. Cobre qualquer reordenacao realista entre
/// a derivacao e o derivado a voltar pelo subscriber.
pub(crate) const TECTO_LSN_DERIVADOS: usize = 262_144;

struct RuntimeInner {
    log: Arc<AnyLog>,
    derived_sink: Arc<dyn DerivedEventSink>,
    config: SentinelConfig,
    queue: Arc<SecurityQueue>,
    metrics: Arc<SentinelMetrics>,
    cursor_store: CursorStore,
    cursor: Mutex<SentinelCursor>,
    /// A posição do cursor, publicada para quem só quer LER o estado.
    ///
    /// `process_until` segura `cursor` durante o lote inteiro — appends e
    /// `fsync` incluídos — e `status()` pegava no MESMO mutex. Consequência: a
    /// rota `/sentinel/status` bloqueava atrás do worker, e o endpoint que
    /// reporta o atraso deixava de responder exactamente quando o atraso era a
    /// coisa que era preciso ver. Com replicação, um append à espera de quórum
    /// prendia-o sem limite de tempo.
    ///
    /// Publicado **depois** do commit durável (`Release`), para que um
    /// observador nunca veja uma posição que ainda não está em disco.
    next_lsn_publicado: std::sync::atomic::AtomicU64,
    normalizer: GenericNormalizer,
    rule_engine: Option<RuleEngine>,
    /// SPEC-0047 — índice de IOC e políticas de fonte. `None` quando o plano
    /// de threat intel está desligado, que é o default.
    threat: Option<crate::threat::ThreatPlane>,
    rule_history: Mutex<Vec<(Lsn, SecurityEvent)>>,
    behavior_engine: Option<Mutex<BehavioralEngine>>,
    fusion: Option<Mutex<EvidenceFusion>>,
    fusion_state: Mutex<BTreeMap<String, FusionAccumulator>>,
    signal_ids: Mutex<HashSet<String>>,
    /// SPEC-0047 §36 — sightings ja emitidos.
    ///
    /// O `DirectLogSink` IGNORA a chave de idempotencia (so um host com
    /// deduplicacao propria a honra), portanto a deduplicacao tem de viver
    /// aqui — como ja vivia para os sinais. Sem isto, o mesmo evento visto
    /// pelos dois caminhos (a derivacao e o derivado a voltar pelo
    /// subscriber) produzia dois sightings da mesma observacao.
    ///
    /// Tem TECTO. Escrevi isto primeiro como um `HashSet<String>` puro, e essa
    /// versao nunca largava nada: a chave inclui o `event_id`, que e um ULID
    /// unico por evento, portanto **cada sighting emitido acrescentava uma
    /// entrada permanente**. Num servico que corre semanas com um feed activo
    /// sao centenas de MB de chaves que nunca mais servem para nada.
    ///
    /// A janela e suficiente porque o duplicado que isto existe para apanhar
    /// chega PERTO: e o mesmo evento a voltar pelo subscriber logo a seguir a
    /// derivacao, nao um evento de ha uma semana.
    sighting_keys: Mutex<JanelaDeChaves>,
    /// LSNs de origem ja derivados, para nao derivar duas vezes o mesmo evento.
    ///
    /// Tem TECTO, e nao tinha. Era um `HashSet<Lsn>` que recebia um `u64` por
    /// CADA evento derivado e nunca largava nenhum: num servico desenhado para
    /// correr indefinidamente, isso e um vazamento que cresce com o trafego —
    /// alguns bytes por evento, mas sem fim.
    ///
    /// A janela e conservadora de proposito. Um marco de agua alta seria exacto
    /// se o processamento fosse estritamente monotonico, e nao confirmei que
    /// seja; uma janela funciona sob qualquer ordenacao. O que se troca e
    /// explicito: um evento repetido a mais de `TECTO_LSN_DERIVADOS` de
    /// distancia voltaria a ser derivado.
    derived_sources: Mutex<JanelaRecente<Lsn>>,
    security_graph: Option<Mutex<TemporalSecurityGraph>>,
    incident_engine: Option<Mutex<IncidentEngine>>,
    incident_revision_ids: Mutex<HashSet<String>>,
    risk_revision_ids: Mutex<HashSet<String>>,
    checkpoint_ids: Mutex<HashSet<String>>,
    last_checkpoint_lsn: Mutex<Option<Lsn>>,
    l4_ids: Mutex<BTreeMap<String, Lsn>>,
    ai_breaker: Mutex<AiCircuitBreaker>,
    ownership: Option<Arc<dyn LeaderOwnership>>,
    stop: Arc<AtomicBool>,
}

#[derive(Default)]
struct SecurityState {
    rule_history: Vec<(Lsn, SecurityEvent)>,
    behavior_history: Vec<(Lsn, SecurityEvent)>,
    graph_history: Vec<(Lsn, SecurityEvent)>,
    signal_ids: HashSet<String>,
    derived_sources: HashSet<Lsn>,
    signals: Vec<(Lsn, SecuritySignal)>,
    incident_revision_ids: HashSet<String>,
    risk_revision_ids: HashSet<String>,
    checkpoint_ids: HashSet<String>,
    last_checkpoint_lsn: Option<Lsn>,
    l4_ids: BTreeMap<String, Lsn>,
}

#[derive(Debug, Clone)]
struct FusionAccumulator {
    subject: EntityRef,
    rule_score: f32,
    behavioral_score: f32,
    graph_score: f32,
    threat_intel_score: f32,
    evidence: Vec<EvidenceRef>,
    detectors: BTreeMap<String, DetectorChannel>,
}

/// Running Fase 0/L1 worker set.  Dropping it requests shutdown and joins all
/// background threads; no thread owns the log, so the host remains in control
/// of its lifecycle.
pub struct SentinelRuntime {
    inner: Arc<RuntimeInner>,
    tail_handle: Mutex<Option<JoinHandle<()>>>,
    worker_handles: Mutex<Vec<JoinHandle<()>>>,
}

impl SentinelRuntime {
    /// Start the runtime when enabled.  `Ok(None)` is the explicit disabled
    /// state and performs no subscription or I/O.  This convenience path is
    /// intended for a non-replicated embedded host; the server uses
    /// [`Self::start_with_sink`] so derived writes pass through `Engine`.
    pub fn start(log: Arc<AnyLog>, config: SentinelConfig) -> Result<Option<Self>, SentinelError> {
        let sink = Arc::new(DirectLogSink { log: log.clone() });
        Self::start_with_sink(log, sink, config)
    }

    pub fn start_with_sink(
        log: Arc<AnyLog>,
        derived_sink: Arc<dyn DerivedEventSink>,
        config: SentinelConfig,
    ) -> Result<Option<Self>, SentinelError> {
        Self::start_with_sink_and_ownership(log, derived_sink, config, None)
    }

    pub fn start_with_sink_and_ownership(
        log: Arc<AnyLog>,
        derived_sink: Arc<dyn DerivedEventSink>,
        config: SentinelConfig,
        ownership: Option<Arc<dyn LeaderOwnership>>,
    ) -> Result<Option<Self>, SentinelError> {
        config::validate(&config)?;
        if !config.enabled || config.mode == SentinelMode::Disabled {
            return Ok(None);
        }

        let queue = Arc::new(
            SecurityQueue::new(config.queue_capacity)
                .map_err(|e| SentinelError::Config(e.to_owned()))?,
        );
        let metrics = Arc::new(SentinelMetrics::default());
        let cursor_store = CursorStore::new(log.dir().join("sentinel").join("cursor.json"));
        let cursor = cursor_store.load(config.pipeline_version)?;
        if cursor.next_lsn > log.head() {
            return Err(SentinelError::Cursor(format!(
                "cursor next_lsn={} está além do head={}",
                cursor.next_lsn,
                log.head()
            )));
        }
        let stop = Arc::new(AtomicBool::new(false));
        // SPEC-0047 — os feeds são lidos uma vez, no arranque. Recarregar a
        // quente é outra coisa (§40/§41 querem versionamento e rollback), e
        // fazê-lo mal daria dois índices diferentes a decidir ao mesmo tempo.
        // O que o carregamento apurou não vai para um log: vai para o
        // `SentinelStatus`, como o resto do estado deste crate. Um feed que
        // não importou tem de ser consultável depois do arranque, não só
        // visível na altura em que passou.
        let threat = if config.threat.enabled {
            let policy = crate::threat::ThreatSourcePolicy {
                source_id: config.threat.source_id.clone(),
                trust_level: crate::threat::trust_from_config(&config.threat.trust_level),
                minimum_confidence: config.threat.minimum_confidence,
                // §11 — mesmo `true` não seria permissão, e nada nesta versão
                // executa acções: o valor é conservador até haver executor.
                auto_block_allowed: false,
                default_ttl_secs: config.threat.default_ttl_secs,
            };
            Some(crate::threat::ThreatPlane::load(
                std::path::Path::new(&config.threat.feeds_dir),
                policy,
                now_ms(),
            ))
        } else {
            None
        };
        let rule_engine = if config.l1.enabled {
            let path = config.l1.rules_path.as_ref().ok_or_else(|| {
                SentinelError::Config(
                    "sentinel.l1.rules_path is required when L1 is enabled".into(),
                )
            })?;
            let rules = compile_sigma_path(path)
                .map_err(|error| SentinelError::Sigma(error.to_string()))?;
            Some(RuleEngine::new(rules).map_err(|error| SentinelError::Sigma(error.to_string()))?)
        } else {
            None
        };
        let SecurityState {
            rule_history,
            behavior_history,
            graph_history,
            signal_ids,
            derived_sources,
            signals,
            incident_revision_ids,
            risk_revision_ids,
            checkpoint_ids,
            last_checkpoint_lsn,
            l4_ids,
        } = load_security_state(
            &log,
            rule_engine.is_some(),
            config.l2.enabled,
            config.l3.enabled,
            rule_engine.is_some() || config.l2.enabled || config.l3.enabled,
        )?;
        let behavior_engine = if config.l2.enabled {
            let policy = BaselinePolicy {
                minimum_support: config.l2.minimum_support,
                learning_delay_events: config.l2.learning_delay_events,
                shadow_only: config.l2.shadow_only,
                ..BaselinePolicy::default()
            };
            Some(Mutex::new(BehavioralEngine::new(policy)?))
        } else {
            None
        };
        let security_graph = if config.l3.enabled {
            let mut graph = TemporalSecurityGraph::new();
            for (episode_lsn, event) in &graph_history {
                graph.apply_security_event(*episode_lsn, event)?;
            }
            Some(Mutex::new(graph))
        } else {
            None
        };
        let incident_engine = if config.l3.enabled {
            let policy = IncidentPolicy {
                graph_path_depth: config.l3.max_graph_hops,
                ..IncidentPolicy::default()
            };
            Some(Mutex::new(IncidentEngine::new(policy)))
        } else {
            None
        };
        let fusion = if rule_engine.is_some() || config.l2.enabled || config.l3.enabled {
            Some(Mutex::new(EvidenceFusion::new(
                FusionWeights::default(),
                "sentinel-fusion-v1",
            )?))
        } else {
            None
        };
        let runtime_rule_history = if rule_engine.is_some() {
            rule_history
        } else {
            Vec::new()
        };
        let inner = Arc::new(RuntimeInner {
            log: log.clone(),
            derived_sink,
            config: config.clone(),
            queue: queue.clone(),
            metrics: metrics.clone(),
            cursor_store,
            next_lsn_publicado: std::sync::atomic::AtomicU64::new(cursor.next_lsn),
            cursor: Mutex::new(cursor),
            normalizer: GenericNormalizer::default(),
            rule_engine,
            threat,
            rule_history: Mutex::new(runtime_rule_history),
            behavior_engine,
            fusion,
            fusion_state: Mutex::new(BTreeMap::new()),
            signal_ids: Mutex::new(signal_ids),
            sighting_keys: Mutex::new(JanelaDeChaves::nova(TECTO_CHAVES_SIGHTING)),
            derived_sources: Mutex::new({
                let mut j = JanelaRecente::nova(TECTO_LSN_DERIVADOS);
                for lsn in derived_sources {
                    j.inserir(&lsn);
                }
                j
            }),
            security_graph,
            incident_engine,
            incident_revision_ids: Mutex::new(incident_revision_ids),
            risk_revision_ids: Mutex::new(risk_revision_ids),
            checkpoint_ids: Mutex::new(checkpoint_ids),
            last_checkpoint_lsn: Mutex::new(last_checkpoint_lsn),
            l4_ids: Mutex::new(l4_ids),
            ai_breaker: Mutex::new(
                AiCircuitBreaker::new(CircuitBreakerConfig::default())
                    .map_err(|error| SentinelError::Config(error.to_string()))?,
            ),
            ownership,
            stop: stop.clone(),
        });

        // Re-evaluate L1 before L2 so events classified by a deterministic
        // rule are never incorporated into an active behavioral baseline.
        let l1_suspicious = evaluate_l1(&inner)?;

        // Rebuild L2 from canonical SecurityEvent episodes in transaction-LSN
        // order. Stable signal IDs make enabling L2 on an existing database
        // and replaying after a crash safe and idempotent.
        for (episode_lsn, event) in behavior_history {
            evaluate_l2(
                &inner,
                episode_lsn,
                &event,
                l1_suspicious.contains(&event.raw_event_id),
            )?;
        }

        // Replay persisted signals in transaction (episode-LSN) order.  This
        // reproduces live append-only revisions even when their event-time LSNs
        // arrive out of order and trigger canonical incident re-keying.
        for (signal_lsn, signal) in signals {
            evaluate_fusion(&inner, signal_lsn, &signal)?;
            evaluate_l3(&inner, signal_lsn, &signal)?;
        }

        let subscriber = Arc::new(SecuritySubscriber::new(queue.clone(), metrics));
        let tail_handle = attach_subscriber_with_stop(log.as_ref(), subscriber, stop.clone());

        // Force a boot catch-up.  This is also what makes a missing/old cursor
        // recover history even when no new append arrives after startup.
        queue.request_catch_up(cursor.next_lsn);
        let mut worker_handles = Vec::with_capacity(config.worker_threads);
        for index in 0..config.worker_threads {
            let worker_inner = inner.clone();
            let builder = std::thread::Builder::new().name(format!("heraclitus-sentinel-{index}"));
            let handle = builder
                .spawn(move || worker_loop(worker_inner))
                .map_err(|error| SentinelError::Worker(error.to_string()))?;
            worker_handles.push(handle);
        }

        Ok(Some(Self {
            inner,
            tail_handle: Mutex::new(Some(tail_handle)),
            worker_handles: Mutex::new(worker_handles),
        }))
    }

    pub fn status(&self) -> SentinelStatus {
        // Leitura sem lock, de propósito: ver o estado não pode depender de o
        // worker ter largado o cursor. Ver `next_lsn_publicado`.
        let next_lsn = self
            .inner
            .next_lsn_publicado
            .load(std::sync::atomic::Ordering::Acquire);
        let mut status = self.inner.metrics.snapshot(
            self.inner.config.enabled,
            self.inner.config.mode,
            self.inner.config.pipeline_version,
            self.inner.log.head(),
            next_lsn,
            self.inner.queue.snapshot(),
        );
        let breaker = self
            .inner
            .ai_breaker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        status.ai_circuit_state = breaker.state();
        status.ai_consecutive_failures = breaker.consecutive_failures();
        status.ai_in_flight = breaker.in_flight();
        status
    }

    /// SPEC-0047 — o que o carregamento dos feeds apurou no arranque.
    ///
    /// `None` quando o plano está desligado. Um índice vazio porque nenhum
    /// ficheiro importou tem de ser distinguível de um índice vazio porque não
    /// há feeds configurados, e é isso que este relatório permite.
    pub fn threat_load_report(&self) -> Option<crate::threat::ThreatLoadReport> {
        self.inner.threat.as_ref().map(|p| p.report().clone())
    }

    /// Quantos indicadores exactos estão no índice de IOC.
    pub fn threat_indicator_count(&self) -> usize {
        self.inner
            .threat
            .as_ref()
            .map_or(0, |p| p.indicator_count())
    }

    /// Append an auditable checkpoint of the current derived-state watermarks.
    /// The local cursor remains the fast restart hint; this event is the
    /// durable AS-OF record that can be verified and replayed by another host.
    pub fn checkpoint(&self) -> Result<Lsn, SentinelError> {
        let status = self.status();
        let mut detector_versions = BTreeMap::new();
        if self.inner.config.l1.enabled {
            detector_versions.insert(
                "l1.sigma".into(),
                format!("pipeline-{}", self.inner.config.pipeline_version),
            );
        }
        if self.inner.config.l2.enabled {
            detector_versions.insert(
                "l2.behavioral.baseline".into(),
                format!(
                    "pipeline-{}-support-{}-delay-{}",
                    self.inner.config.pipeline_version,
                    self.inner.config.l2.minimum_support,
                    self.inner.config.l2.learning_delay_events
                ),
            );
        }
        if self.inner.config.l3.enabled {
            detector_versions.insert(
                "l3.temporal-graph".into(),
                format!("pipeline-{}", self.inner.config.pipeline_version),
            );
        }
        if let Some(plane) = self.inner.threat.as_ref() {
            // O número de indicadores entra na versão do detector de
            // propósito: dois checkpoints com o mesmo `pipeline_version` mas
            // índices diferentes não descrevem o mesmo detector, e um replay
            // que não distinguisse os dois explicaria mal porque é que o mesmo
            // evento deu resultados diferentes.
            detector_versions.insert(
                "threat-intel".into(),
                format!(
                    "pipeline-{}-indicators-{}",
                    self.inner.config.pipeline_version,
                    plane.indicator_count()
                ),
            );
        }
        let checkpoint = SentinelCheckpoint {
            as_of_lsn: status.processed_lsn.unwrap_or(0),
            next_lsn: status.next_lsn,
            pipeline_version: status.pipeline_version,
            detector_versions,
            graph_watermark_lsn: self
                .temporal_graph_snapshot()
                .map(|snapshot| snapshot.watermark_lsn),
            incident_revisions: status.incident_revisions_emitted_total,
            risk_revisions: status.risk_assessments_emitted_total,
        };
        let checkpoint_id = checkpoint.checkpoint_id()?;
        if let Some(previous_lsn) = *self
            .inner
            .last_checkpoint_lsn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            let unchanged = self
                .inner
                .log
                .scan(previous_lsn.saturating_add(1), self.inner.log.head())?
                .into_iter()
                .all(|(_, episode)| {
                    matches!(&episode.kind, EventKind::Custom(kind) if kind == "SentinelCheckpoint")
                });
            if unchanged {
                return Ok(previous_lsn);
            }
        }
        let mut checkpoints = self
            .inner
            .checkpoint_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if checkpoints.contains(&checkpoint_id) {
            return Ok(self.inner.log.head().saturating_sub(1));
        }
        let episode = checkpoint.into_episode()?;
        let lsn = self
            .inner
            .derived_sink
            .append(episode, &format!("c:{checkpoint_id}"))
            .map_err(SentinelError::from)?;
        checkpoints.insert(checkpoint_id);
        *self
            .inner
            .last_checkpoint_lsn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(lsn);
        Ok(lsn)
    }

    /// Run a host-supplied provider against one already-built, bounded
    /// `IncidentContext`. The provider can return only the typed investigation
    /// schema; the result is validated and persisted as a derived event.
    pub async fn investigate(
        &self,
        backend: &dyn ModelBackend,
        context: IncidentContext,
    ) -> Result<(InvestigationResult, Lsn), SentinelError> {
        self.investigate_with_audit(
            backend,
            context,
            "host-supplied",
            "unknown",
            "host",
            "sentinel-l4-v1",
            now_ms(),
        )
        .await
    }

    /// Variant used by hosts that can identify the concrete model/provider.
    /// The supplied metadata is persisted together with the redacted context
    /// and response digests; it is never handed to an executor.
    #[allow(clippy::too_many_arguments)]
    pub async fn investigate_with_audit(
        &self,
        backend: &dyn ModelBackend,
        context: IncidentContext,
        model_id: &str,
        model_version: &str,
        provider: &str,
        prompt_template_version: &str,
        timestamp_ms: u64,
    ) -> Result<(InvestigationResult, Lsn), SentinelError> {
        self.require_authority()?;
        context.validate()?;
        let context_digest = context.digest()?;
        if let Some((lsn, episode)) = self
            .l4_events(
                Some("SecurityInvestigation"),
                Some(&context.incident_id),
                None,
                10_000,
            )?
            .into_iter()
            .find(|(_, episode)| {
                episode
                    .attrs
                    .get("sentinel.context_digest")
                    .map(String::as_str)
                    == Some(context_digest.as_str())
            })
        {
            if let Ok(investigation) =
                serde_json::from_slice::<SecurityInvestigation>(&episode.content)
            {
                return Ok((investigation.result, lsn));
            }
        }
        let request_started_at = now_ms();
        {
            let mut breaker = self
                .inner
                .ai_breaker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !breaker.begin_request(request_started_at) {
                return Err(AiError::Backend(
                    "circuit breaker L4 aberto ou limite de concorrência atingido".into(),
                )
                .into());
            }
        }
        self.inner
            .metrics
            .ai_requests_total
            .fetch_add(1, Ordering::Relaxed);
        let backend_result = backend.investigate(&context).await;
        let duration_ms = now_ms().saturating_sub(request_started_at);
        self.inner
            .metrics
            .ai_latency_ms
            .store(duration_ms, Ordering::Relaxed);
        let result = match backend_result {
            Ok(result) => result,
            Err(error) => {
                self.inner
                    .ai_breaker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .record_failure(now_ms());
                self.inner
                    .metrics
                    .ai_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error.into());
            }
        };
        if let Err(error) = result.validate_for(&context) {
            self.inner
                .ai_breaker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .record_failure(now_ms());
            self.inner
                .metrics
                .ai_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(error.into());
        }
        self.inner
            .ai_breaker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_success();
        let investigation = SecurityInvestigation::from_context(&context, result.clone())?;
        let estimated_tokens = serde_json::to_vec(&result)?.len().div_ceil(4) as u64;
        self.inner
            .metrics
            .ai_tokens_total
            .fetch_add(estimated_tokens, Ordering::Relaxed);
        let audit = AiInvocationAudit::from_result_with_usage(
            model_id,
            model_version,
            provider,
            &context,
            prompt_template_version,
            &result,
            timestamp_ms,
            duration_ms,
            Some(estimated_tokens),
            "success",
        )?;
        let invocation_id = format!("ai-{}", blake3::hash(&serde_json::to_vec(&audit)?).to_hex());
        let invocation = audit.into_episode(&context.incident_id, &context.risk.evidence)?;
        self.append_l4_once(format!("invocation:{invocation_id}"), invocation)?;
        let episode = investigation.into_episode(&context)?;
        let lsn = self.append_l4_once(format!("investigation:{context_digest}"), episode)?;
        self.inner
            .metrics
            .ai_investigations_persisted_total
            .fetch_add(1, Ordering::Relaxed);
        Ok((result, lsn))
    }

    /// Persist a validated, allowlisted action proposal. This is a durable
    /// proposal boundary only; it never invokes an executor.
    pub fn persist_action_proposal(
        &self,
        context: &IncidentContext,
        proposal: &ActionProposal,
    ) -> Result<Lsn, SentinelError> {
        self.require_authority()?;
        if proposal.proposal_id.trim().is_empty() {
            return Err(SentinelError::Config(
                "proposal_id não pode ser vazio".into(),
            ));
        }
        proposal.validate_for(context)?;
        let episode = proposal.into_episode()?;
        let (lsn, inserted) =
            self.append_l4_once_with_status(format!("proposal:{}", proposal.proposal_id), episode)?;
        if inserted {
            self.inner
                .metrics
                .actions_proposed_total
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(lsn)
    }

    /// Evaluate the deterministic policy and persist exactly the decision it
    /// produced. A caller cannot inject an arbitrary approval payload through
    /// this boundary; human approval/executor transitions remain separate.
    pub fn evaluate_and_persist_policy(
        &self,
        incident: &SecurityIncident,
        assessment: &RiskAssessment,
        proposal: &ActionProposal,
    ) -> Result<(PolicyDecision, Lsn), SentinelError> {
        self.require_authority()?;
        if incident.incident_id != proposal.incident_id {
            return Err(SentinelError::Config(
                "proposal aponta para incidente diferente".into(),
            ));
        }
        proposal.action.validate()?;
        let policy = DeterministicPolicyEngine::new(PolicyConfig::default())?;
        let decision = PolicyEngine::evaluate(&policy, incident, assessment, proposal);
        let decision_id =
            PolicyDecision::decision_id(policy.policy_version(), proposal, &decision)?;
        let episode = decision.into_episode(policy.policy_version(), proposal, assessment)?;
        let (lsn, inserted) =
            self.append_l4_once_with_status(format!("decision:{decision_id}"), episode)?;
        match (&decision, inserted) {
            (PolicyDecision::Approve { .. }, true) => {
                self.inner
                    .metrics
                    .actions_approved_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            (PolicyDecision::Deny { .. }, true) => {
                self.inner
                    .metrics
                    .actions_denied_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        Ok((decision, lsn))
    }

    /// Persist a human approval/rejection as an immutable event. Approval is
    /// keyed by its policy-issued ID, so a retry cannot create a second logical
    /// authorization record.
    pub fn persist_human_approval(&self, approval: HumanApproval) -> Result<Lsn, SentinelError> {
        self.require_authority()?;
        approval.validate()?;
        let id = format!("approval:{}", approval.approval_id);
        let approved = approval.approved;
        let episode = approval.into_episode()?;
        let (lsn, inserted) = self.append_l4_once_with_status(id, episode)?;
        if inserted {
            let metric = if approved {
                &self.inner.metrics.actions_approved_total
            } else {
                &self.inner.metrics.actions_denied_total
            };
            metric.fetch_add(1, Ordering::Relaxed);
        }
        Ok(lsn)
    }

    /// Approve/deny a policy decision only when the requested approval ID was
    /// actually emitted for this incident and proposal. This closes the
    /// confused-deputy gap in a plain `POST` endpoint.
    pub fn persist_human_approval_for(
        &self,
        incident_id: &str,
        proposal_id: &str,
        approval_id: &str,
        approver: &str,
        approved: bool,
        reason: &str,
    ) -> Result<Lsn, SentinelError> {
        self.require_authority()?;
        if incident_id.trim().is_empty()
            || proposal_id.trim().is_empty()
            || approval_id.trim().is_empty()
        {
            return Err(SentinelError::Config(
                "incident_id, proposal_id e approval_id são obrigatórios".into(),
            ));
        }
        let decisions = self.l4_events(
            Some("SecurityPolicyDecision"),
            Some(incident_id),
            None,
            10_000,
        )?;
        let matching = decisions.iter().any(|(_, episode)| {
            if episode
                .attrs
                .get("sentinel.action_proposal_id")
                .map(String::as_str)
                != Some(proposal_id)
            {
                return false;
            }
            let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&episode.content) else {
                return false;
            };
            payload
                .get("decision")
                .and_then(|decision| decision.get("RequireHumanApproval"))
                .and_then(|approval| approval.get("approval_id"))
                .and_then(serde_json::Value::as_str)
                == Some(approval_id)
        });
        if !matching {
            return Err(SentinelError::Policy(PolicyError::Invalid(
                "approval_id não corresponde a uma decisão persistida".into(),
            )));
        }
        let evidence = self
            .l4_events(
                Some("SecurityActionProposal"),
                Some(incident_id),
                None,
                10_000,
            )?
            .into_iter()
            .filter(|(_, episode)| {
                episode
                    .attrs
                    .get("sentinel.action_proposal_id")
                    .map(String::as_str)
                    == Some(proposal_id)
            })
            .find_map(|(_, episode)| {
                serde_json::from_slice::<ActionProposal>(&episode.content)
                    .ok()
                    .map(|proposal| proposal.evidence)
            })
            .unwrap_or_default();
        self.persist_human_approval(HumanApproval {
            approval_id: approval_id.into(),
            incident_id: incident_id.into(),
            proposal_id: proposal_id.into(),
            approver: approver.into(),
            approved,
            reason: reason.into(),
            evidence,
        })
    }

    /// Execute a typed, already-authorized action and persist its result. The
    /// runtime refuses to execute in Observe/Shadow and refuses envelopes that
    /// still require approval; a human-approved envelope must carry the
    /// persisted `approval:<id>` record created above.
    pub async fn execute_authorized_action(
        &self,
        executor: &dyn SecurityActionExecutor,
        authorized: AuthorizedAction,
    ) -> Result<(ActionResult, Lsn), SentinelError> {
        self.require_authority()?;
        if matches!(
            self.inner.config.mode,
            SentinelMode::Observe | SentinelMode::Shadow
        ) {
            return Err(SentinelError::Policy(PolicyError::Invalid(
                "execução externa desabilitada em modo observe/shadow".into(),
            )));
        }
        if authorized.constraints.requires_approval {
            return Err(SentinelError::Policy(PolicyError::Invalid(
                "ação ainda exige aprovação humana persistida".into(),
            )));
        }
        self.ensure_persisted_authorization(&authorized)?;
        let expected = crate::execution::deterministic_action_id(
            &authorized.incident_id,
            &authorized.action,
            &authorized.policy_version,
        )
        .map_err(|error| SentinelError::Policy(PolicyError::Invalid(error.to_string())))?;
        let result = match executor.execute(&authorized).await {
            Ok(result) => result,
            Err(error) => {
                self.inner
                    .metrics
                    .action_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error.into());
            }
        };
        if result.action_id != expected {
            return Err(SentinelError::Policy(PolicyError::Invalid(
                "executor devolveu action_id incompatível".into(),
            )));
        }
        let episode = result.into_episode(&authorized)?;
        let lsn = self.append_l4_once(format!("result:{expected}"), episode)?;
        self.inner
            .metrics
            .actions_executed_total
            .fetch_add(1, Ordering::Relaxed);
        Ok((result, lsn))
    }

    fn ensure_persisted_authorization(
        &self,
        authorized: &AuthorizedAction,
    ) -> Result<(), SentinelError> {
        let decisions = self.l4_events(
            Some("SecurityPolicyDecision"),
            Some(&authorized.incident_id),
            None,
            10_000,
        )?;
        for (_, decision_episode) in decisions {
            let Ok(payload) =
                serde_json::from_slice::<serde_json::Value>(&decision_episode.content)
            else {
                continue;
            };
            if payload
                .get("policy_version")
                .and_then(serde_json::Value::as_str)
                != Some(authorized.policy_version.as_str())
            {
                continue;
            }
            let Some(proposal_id) = payload
                .get("proposal_id")
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let proposal_matches = self
                .l4_events(
                    Some("SecurityActionProposal"),
                    Some(&authorized.incident_id),
                    None,
                    10_000,
                )?
                .into_iter()
                .filter(|(_, episode)| {
                    episode
                        .attrs
                        .get("sentinel.action_proposal_id")
                        .map(String::as_str)
                        == Some(proposal_id)
                })
                .any(|(_, episode)| {
                    serde_json::from_slice::<ActionProposal>(&episode.content)
                        .map(|proposal| proposal.action == authorized.action)
                        .unwrap_or(false)
                });
            if !proposal_matches {
                continue;
            }
            if payload
                .get("decision")
                .and_then(|decision| decision.get("Approve"))
                .and_then(|approve| approve.get("authorization_id"))
                .and_then(serde_json::Value::as_str)
                == Some(authorized.authorization_id.as_str())
            {
                return Ok(());
            }
            if let Some(approval_id) = payload
                .get("decision")
                .and_then(|decision| decision.get("RequireHumanApproval"))
                .and_then(|approval| approval.get("approval_id"))
                .and_then(serde_json::Value::as_str)
            {
                if authorized.authorization_id != format!("authz-{approval_id}") {
                    continue;
                }
                let approved = self
                    .l4_events(
                        Some("SecurityApproval"),
                        Some(&authorized.incident_id),
                        None,
                        10_000,
                    )?
                    .into_iter()
                    .any(|(_, episode)| {
                        episode
                            .attrs
                            .get("sentinel.approval_id")
                            .map(String::as_str)
                            == Some(approval_id)
                            && episode.attrs.get("sentinel.approved").map(String::as_str)
                                == Some("true")
                    });
                if approved {
                    return Ok(());
                }
            }
        }
        Err(SentinelError::Policy(PolicyError::Invalid(
            "ação não possui autorização de policy persistida".into(),
        )))
    }

    /// Persist an immutable model activation record.  This records artifact
    /// provenance only; it never downloads, loads or switches a model.
    pub fn persist_model_update(&self, update: SecurityModelUpdate) -> Result<Lsn, SentinelError> {
        self.require_authority()?;
        update.validate()?;
        let update_id = update.update_id()?;
        let episode = update.into_episode()?;
        self.append_l4_once(format!("model-update:{update_id}"), episode)
    }

    /// Persist a signed/approved ruleset activation record.  The running rule
    /// engine remains immutable; activation takes effect only when the host
    /// explicitly loads that version.
    pub fn persist_ruleset_update(
        &self,
        update: SecurityRulesetUpdate,
    ) -> Result<Lsn, SentinelError> {
        self.require_authority()?;
        update.validate()?;
        let update_id = update.update_id()?;
        let episode = update.into_episode()?;
        self.append_l4_once(format!("ruleset-update:{update_id}"), episode)
    }

    /// Persist analyst feedback for offline evaluation.  This method cannot
    /// mutate a baseline, model, ruleset or policy directly.
    pub fn persist_feedback(&self, feedback: SecurityFeedback) -> Result<Lsn, SentinelError> {
        self.require_authority()?;
        feedback.validate()?;
        let id = feedback.feedback_id().to_owned();
        let episode = feedback.into_episode()?;
        self.append_l4_once(format!("feedback:{id}"), episode)
    }

    fn require_authority(&self) -> Result<(), SentinelError> {
        if self
            .inner
            .ownership
            .as_ref()
            .is_some_and(|ownership| ownership.current_epoch().is_none())
        {
            return Err(SentinelError::Policy(PolicyError::Invalid(
                "nó Sentinel não é o líder/epoch vigente".into(),
            )));
        }
        Ok(())
    }

    fn append_l4_once(&self, id: String, episode: Episode) -> Result<Lsn, SentinelError> {
        Ok(self.append_l4_once_with_status(id, episode)?.0)
    }

    fn append_l4_once_with_status(
        &self,
        id: String,
        episode: Episode,
    ) -> Result<(Lsn, bool), SentinelError> {
        let mut ids = self
            .inner
            .l4_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(lsn) = ids.get(&id) {
            return Ok((*lsn, false));
        }
        let lsn = self
            .inner
            .derived_sink
            .append(episode, &format!("l4:{id}"))
            .map_err(SentinelError::from)?;
        ids.insert(id, lsn);
        Ok((lsn, true))
    }

    pub fn queue(&self) -> Arc<SecurityQueue> {
        self.inner.queue.clone()
    }

    pub fn metrics(&self) -> Arc<SentinelMetrics> {
        self.inner.metrics.clone()
    }

    pub fn cursor(&self) -> SentinelCursor {
        *self.inner.cursor.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get_incident(&self, incident_id: &str) -> Option<SecurityIncident> {
        self.inner.incident_engine.as_ref().and_then(|engine| {
            engine
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .incident(incident_id)
                .cloned()
        })
    }

    pub fn current_incidents(&self) -> Vec<SecurityIncident> {
        self.inner
            .incident_engine
            .as_ref()
            .map(|engine| {
                engine
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .incidents()
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return what the Sentinel knew about one incident at a transaction LSN.
    /// The query reads append-only revisions rather than mutating current state.
    pub fn incident_as_of(
        &self,
        incident_id: &str,
        as_of_lsn: Lsn,
    ) -> Result<Option<SecurityIncident>, SentinelError> {
        Ok(self
            .incident_revisions_as_of(as_of_lsn)?
            .into_iter()
            .find(|incident| incident.incident_id == incident_id))
    }

    pub fn query_incidents(
        &self,
        filter: IncidentFilter,
    ) -> Result<Vec<SecurityIncident>, SentinelError> {
        if filter.min_severity.is_some_and(|severity| severity > 10) {
            return Err(SentinelError::Config(
                "incident filter min_severity deve estar entre 0 e 10".into(),
            ));
        }
        if filter
            .limit
            .is_some_and(|limit| limit == 0 || limit > 10_000)
        {
            return Err(SentinelError::Config(
                "incident filter limit deve estar entre 1 e 10000".into(),
            ));
        }
        let mut incidents = if let Some(as_of_lsn) = filter.as_of_lsn {
            self.incident_revisions_as_of(as_of_lsn)?
        } else {
            self.current_incidents()
        };
        incidents.retain(|incident| {
            filter.state.is_none_or(|state| incident.state == state)
                && filter
                    .min_severity
                    .is_none_or(|severity| incident.severity >= severity)
                && filter.subject.as_ref().is_none_or(|subject| {
                    incident.subjects.iter().any(|candidate| {
                        candidate.kind == subject.kind && candidate.id == subject.id
                    })
                })
        });
        incidents.sort_by(|left, right| {
            right
                .last_seen_lsn
                .cmp(&left.last_seen_lsn)
                .then_with(|| left.incident_id.cmp(&right.incident_id))
        });
        if let Some(limit) = filter.limit {
            incidents.truncate(limit);
        }
        Ok(incidents)
    }

    /// Read bounded L4/action records from the canonical log. This is used by
    /// the REST dashboard and audit tooling; it never exposes mutable runtime
    /// state and supports transaction-time AS-OF queries.
    pub fn l4_events(
        &self,
        kind: Option<&str>,
        incident_id: Option<&str>,
        as_of_lsn: Option<Lsn>,
        limit: usize,
    ) -> Result<Vec<(Lsn, Episode)>, SentinelError> {
        if limit == 0 || limit > 10_000 {
            return Err(SentinelError::Config(
                "l4 event limit deve estar entre 1 e 10000".into(),
            ));
        }
        let upper = as_of_lsn
            .map(|lsn| self.inner.log.head().min(lsn.saturating_add(1)))
            .unwrap_or_else(|| self.inner.log.head());
        let mut rows = Vec::new();
        for (lsn, episode) in self.inner.log.scan(0, upper)? {
            let EventKind::Custom(event_kind) = &episode.kind else {
                continue;
            };
            if !matches!(
                event_kind.as_str(),
                "SecurityInvestigation"
                    | "SecurityAiInvocation"
                    | "SecurityActionProposal"
                    | "SecurityPolicyDecision"
                    | "SecurityApproval"
                    | "SecurityActionResult"
                    | "SecurityModelUpdate"
                    | "SecurityRulesetUpdate"
                    | "SecurityFeedback"
            ) || !episode_is_generated(&episode)
            {
                continue;
            }
            if kind.is_some_and(|wanted| wanted != event_kind) {
                continue;
            }
            if incident_id.is_some_and(|wanted| {
                episode
                    .attrs
                    .get("sentinel.incident_id")
                    .map(String::as_str)
                    != Some(wanted)
            }) {
                continue;
            }
            rows.push((lsn, episode));
            if rows.len() >= limit {
                break;
            }
        }
        Ok(rows)
    }

    fn incident_revisions_as_of(
        &self,
        as_of_lsn: Lsn,
    ) -> Result<Vec<SecurityIncident>, SentinelError> {
        let to_exclusive = self.inner.log.head().min(as_of_lsn.saturating_add(1));
        let mut revisions = BTreeMap::new();
        for (_, episode) in self.inner.log.scan(0, to_exclusive)? {
            if !episode_is_generated(&episode)
                || !matches!(&episode.kind, EventKind::Custom(kind) if kind == "SecurityIncident")
            {
                continue;
            }
            if let Ok(incident) = serde_json::from_slice::<SecurityIncident>(&episode.content) {
                revisions.insert(incident.incident_id.clone(), incident);
            }
        }
        Ok(revisions.into_values().collect())
    }

    pub fn temporal_graph_snapshot(&self) -> Option<TemporalSecurityGraphSnapshot> {
        self.inner.security_graph.as_ref().map(|graph| {
            graph
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .snapshot()
        })
    }

    pub fn temporal_graph_snapshot_as_of(
        &self,
        as_of_lsn: Lsn,
    ) -> Option<TemporalSecurityGraphSnapshot> {
        self.inner.security_graph.as_ref().map(|graph| {
            let graph = graph
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            TemporalSecurityGraphSnapshot {
                edges: graph.edges_as_of(as_of_lsn).into_iter().cloned().collect(),
                watermark_lsn: graph.watermark_lsn().min(as_of_lsn),
            }
        })
    }

    pub fn behavioral_snapshot(&self) -> Option<BehavioralSnapshot> {
        self.inner.behavior_engine.as_ref().map(|engine| {
            engine
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .snapshot()
        })
    }

    /// Reconstruct the behavioral model known at a transaction LSN.  This is
    /// intentionally a bounded log scan: a caller asking historical questions
    /// must not observe today's profile after a rollback point.
    pub fn behavioral_snapshot_as_of(
        &self,
        as_of_lsn: Lsn,
    ) -> Result<Option<BehavioralSnapshot>, SentinelError> {
        if !self.inner.config.l2.enabled {
            return Ok(None);
        }
        let policy = BaselinePolicy {
            minimum_support: self.inner.config.l2.minimum_support,
            learning_delay_events: self.inner.config.l2.learning_delay_events,
            shadow_only: self.inner.config.l2.shadow_only,
            ..BaselinePolicy::default()
        };
        let mut engine = BehavioralEngine::new(policy)?;
        let to_exclusive = self.inner.log.head().min(as_of_lsn.saturating_add(1));
        let rows = self.inner.log.scan(0, to_exclusive)?;
        let mut rule_evidence = HashSet::new();
        for (_, episode) in &rows {
            if !episode_is_generated(episode)
                || !matches!(&episode.kind, EventKind::Custom(kind) if kind == "SecuritySignal")
            {
                continue;
            }
            if let Ok(signal) = serde_json::from_slice::<SecuritySignal>(&episode.content) {
                if !signal.detector.id.starts_with("l2.") {
                    rule_evidence.extend(signal.evidence.iter().map(|evidence| evidence.event_id));
                }
            }
        }
        for (lsn, episode) in rows {
            if !episode_is_generated(&episode)
                || !matches!(&episode.kind, EventKind::Custom(kind) if kind == "SecurityEvent")
            {
                continue;
            }
            let Ok(event) = serde_json::from_slice::<SecurityEvent>(&episode.content) else {
                continue;
            };
            for input in security_event_inputs(&event, self.inner.config.l2.suspicious_severity)? {
                let suspicious = input.suspicious || rule_evidence.contains(&event.raw_event_id);
                let _ = engine.observe(lsn, input.entity, input.features, suspicious)?;
            }
        }
        Ok(Some(engine.snapshot()))
    }

    /// Request stop and wait for the tail adapter and workers to exit.
    pub fn shutdown(&self) {
        if self.inner.stop.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(handle) = self
            .tail_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = handle.join();
        }
        let mut workers = self
            .worker_handles
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for handle in workers.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Sentinel for SentinelRuntime {
    fn status(&self) -> SentinelStatus {
        self.status()
    }

    fn incident(&self, id: &str) -> Result<Option<SecurityIncident>, SentinelError> {
        Ok(self.get_incident(id))
    }

    fn incidents(&self, filter: IncidentFilter) -> Result<Vec<SecurityIncident>, SentinelError> {
        self.query_incidents(filter)
    }
}

impl Drop for SentinelRuntime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn load_security_state(
    log: &AnyLog,
    l1_enabled: bool,
    l2_enabled: bool,
    l3_enabled: bool,
    fusion_enabled: bool,
) -> Result<SecurityState, SentinelError> {
    let rows = log.scan(0, log.head())?;
    let mut state = SecurityState::default();
    for (lsn, episode) in rows {
        // Attribute names alone are not an authenticity boundary.  Only rows
        // emitted by the internal Sentinel sink are restored as derived state;
        // external lookalikes remain ordinary raw telemetry.
        if !episode_is_generated(&episode) {
            continue;
        }
        if let EventKind::Custom(kind) = &episode.kind {
            if kind == "SecurityEvent" {
                if let Ok(event) = serde_json::from_slice::<SecurityEvent>(&episode.content) {
                    let source_lsn = episode
                        .attrs
                        .get("sec.source_lsn")
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(lsn);
                    state.derived_sources.insert(source_lsn);
                    if l1_enabled {
                        state.rule_history.push((source_lsn, event.clone()));
                    }
                    if l2_enabled {
                        state.behavior_history.push((lsn, event.clone()));
                    }
                    if l3_enabled {
                        state.graph_history.push((lsn, event));
                    }
                }
            } else if kind == "SecuritySignal" {
                if let Some(signal_id) = episode.attrs.get("sentinel.signal_id") {
                    state.signal_ids.insert(signal_id.clone());
                }
                if let Ok(signal) = serde_json::from_slice::<SecuritySignal>(&episode.content) {
                    state.signal_ids.insert(signal.signal_id.clone());
                    if l3_enabled || fusion_enabled {
                        state.signals.push((lsn, signal));
                    }
                }
            } else if kind == "SecurityIncident" && l3_enabled {
                if let Some(revision_id) =
                    episode.attrs.get("sentinel.incident_revision_id").cloned()
                {
                    state.incident_revision_ids.insert(revision_id);
                } else if let Ok(incident) =
                    serde_json::from_slice::<SecurityIncident>(&episode.content)
                {
                    state.incident_revision_ids.insert(incident.revision_id()?);
                }
            } else if kind == "SecurityRiskAssessment" && fusion_enabled {
                if let Some(revision_id) = episode.attrs.get("sentinel.risk_revision_id") {
                    state.risk_revision_ids.insert(revision_id.clone());
                } else if let Ok(assessment) =
                    serde_json::from_slice::<RiskAssessment>(&episode.content)
                {
                    state.risk_revision_ids.insert(assessment.revision_id()?);
                }
            } else if kind == "SentinelCheckpoint" {
                if let Some(checkpoint_id) = episode.attrs.get("sentinel.checkpoint_id") {
                    state.checkpoint_ids.insert(checkpoint_id.clone());
                } else if let Ok(checkpoint) =
                    serde_json::from_slice::<SentinelCheckpoint>(&episode.content)
                {
                    state.checkpoint_ids.insert(checkpoint.checkpoint_id()?);
                }
                state.last_checkpoint_lsn = Some(lsn);
            } else if matches!(
                kind.as_str(),
                "SecurityInvestigation"
                    | "SecurityActionProposal"
                    | "SecurityPolicyDecision"
                    | "SecurityActionResult"
                    | "SecurityAiInvocation"
                    | "SecurityApproval"
                    | "SecurityModelUpdate"
                    | "SecurityRulesetUpdate"
                    | "SecurityFeedback"
            ) {
                let (prefix, attr) = match kind.as_str() {
                    "SecurityInvestigation" => ("investigation", "sentinel.investigation_id"),
                    "SecurityActionProposal" => ("proposal", "sentinel.action_proposal_id"),
                    "SecurityPolicyDecision" => ("decision", "sentinel.policy_decision_id"),
                    "SecurityActionResult" => ("result", "sentinel.action_id"),
                    "SecurityAiInvocation" => ("invocation", "sentinel.invocation_id"),
                    "SecurityApproval" => ("approval", "sentinel.approval_id"),
                    "SecurityModelUpdate" => ("model-update", "sentinel.model_update_id"),
                    "SecurityRulesetUpdate" => ("ruleset-update", "sentinel.ruleset_update_id"),
                    "SecurityFeedback" => ("feedback", "sentinel.feedback_id"),
                    _ => unreachable!(),
                };
                if let Some(id) = episode.attrs.get(attr) {
                    state.l4_ids.insert(format!("{prefix}:{id}"), lsn);
                }
                if kind == "SecurityInvestigation" {
                    if let Some(digest) = episode.attrs.get("sentinel.context_digest") {
                        state.l4_ids.insert(format!("investigation:{digest}"), lsn);
                    }
                }
            }
        }
    }
    state.rule_history.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.raw_event_id.cmp(&right.1.raw_event_id))
    });
    state
        .rule_history
        .dedup_by(|left, right| left.0 == right.0 && left.1.raw_event_id == right.1.raw_event_id);
    state.behavior_history.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.raw_event_id.cmp(&right.1.raw_event_id))
    });
    state
        .behavior_history
        .dedup_by(|left, right| left.0 == right.0 && left.1.raw_event_id == right.1.raw_event_id);
    state.graph_history.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.raw_event_id.cmp(&right.1.raw_event_id))
    });
    state
        .graph_history
        .dedup_by(|left, right| left.0 == right.0 && left.1.raw_event_id == right.1.raw_event_id);
    state.signals.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.signal_id.cmp(&right.1.signal_id))
    });
    let mut seen_signals = HashSet::new();
    state
        .signals
        .retain(|(_, signal)| seen_signals.insert(signal.signal_id.clone()));
    Ok(state)
}

fn worker_loop(inner: Arc<RuntimeInner>) {
    while !inner.stop.load(Ordering::Acquire) {
        if inner.queue.take_catch_up().is_some() {
            inner
                .metrics
                .catchup_passes_total
                .fetch_add(1, Ordering::Relaxed);
            if let Err(error) = process_until(&inner) {
                inner
                    .metrics
                    .normalization_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                // Retry after a short pause; a malformed single event must not
                // terminate the worker and silently stop catch-up forever.
                let _ = error;
                std::thread::sleep(Duration::from_millis(20));
            }
            continue;
        }

        match inner.queue.recv_timeout(Duration::from_millis(100)) {
            Ok(_notification_lsn) => {
                if let Err(error) = process_until(&inner) {
                    inner
                        .metrics
                        .normalization_errors_total
                        .fetch_add(1, Ordering::Relaxed);
                    let _ = error;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // A restart/cursor catch-up can be requested without a new
                // broadcast notification; check the head periodically.
                let needs_work = {
                    let cursor = inner.cursor.lock().unwrap_or_else(|e| e.into_inner());
                    cursor.next_lsn < inner.log.head()
                };
                if needs_work {
                    inner.queue.request_catch_up(0);
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn process_until(inner: &RuntimeInner) -> Result<(), SentinelError> {
    let target = inner.log.head();
    let mut cursor = inner.cursor.lock().unwrap_or_else(|e| e.into_inner());
    if cursor.next_lsn >= target {
        return Ok(());
    }
    let rows = inner
        .log
        .scan_capped(cursor.next_lsn, target, inner.config.catch_up_batch)?;
    if rows.is_empty() {
        return Ok(());
    }

    // If a crash occurred after appending a derived event but before committing
    // the cursor, the derived row is visible either in this replay window or in
    // the durable source set loaded at boot.  Skip it by source LSN to avoid
    // duplicate logical SecurityEvents.
    let existing_sources: HashSet<Lsn> = rows
        .iter()
        .filter(|(_, episode)| episode_is_generated(episode))
        .filter(|(_, episode)| matches!(&episode.kind, EventKind::Custom(kind) if kind == "SecurityEvent"))
        .filter_map(|(_, episode)| episode.attrs.get("sec.source_lsn").and_then(|value| value.parse().ok()))
        .collect();

    for (lsn, episode) in rows {
        if lsn < cursor.next_lsn {
            continue;
        }
        if episode_is_generated(&episode) {
            if let EventKind::Custom(kind) = &episode.kind {
                match kind.as_str() {
                    "SecurityEvent" => {
                        if let Ok(event) = serde_json::from_slice::<SecurityEvent>(&episode.content)
                        {
                            let source_lsn = episode
                                .attrs
                                .get("sec.source_lsn")
                                .and_then(|value| value.parse().ok())
                                .unwrap_or(lsn);
                            remember_rule_event(inner, source_lsn, &event);
                            apply_security_graph(inner, lsn, &event)?;
                            // `source_lsn` (o LSN do episodio BRUTO), nao `lsn`
                            // (o do SecurityEvent). O mesmo evento chega aqui
                            // por dois caminhos — a derivacao e, depois, o
                            // proprio derivado a passar pelo subscriber — e
                            // ancorar a evidencia no LSN de cada representacao
                            // dava dois sinais e dois sightings para uma so
                            // observacao.
                            evaluate_threat(inner, source_lsn, event.raw_event_id, &event)?;
                            let l1_suspicious = evaluate_l1(inner)?;
                            evaluate_l2(
                                inner,
                                lsn,
                                &event,
                                l1_suspicious.contains(&event.raw_event_id),
                            )?;
                        }
                    }
                    "SecuritySignal" => {
                        if let Ok(signal) =
                            serde_json::from_slice::<SecuritySignal>(&episode.content)
                        {
                            evaluate_fusion(inner, lsn, &signal)?;
                            evaluate_l3(inner, lsn, &signal)?;
                        }
                    }
                    _ => {}
                }
            }
            inner
                .metrics
                .normalization_skipped_total
                .fetch_add(1, Ordering::Relaxed);
        } else if let Some(normalized) = normalize_l0(inner, lsn, &episode) {
            let already_derived = existing_sources.contains(&lsn)
                || inner
                    .derived_sources
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contem(&lsn);
            let derived_lsn = if !already_derived {
                let derived = normalized.event.into_episode(
                    Some(normalized.source_lsn),
                    now_ms(),
                    Some(&episode.content),
                )?;
                let key = format!(
                    "e:v{}:{}",
                    inner.config.pipeline_version, normalized.source_lsn
                );
                let derived_lsn = inner.derived_sink.append(derived, &key)?;
                inner
                    .derived_sources
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .inserir(&lsn);
                Some(derived_lsn)
            } else {
                None
            };
            remember_rule_event(inner, lsn, &normalized.event);
            if let Some(derived_lsn) = derived_lsn {
                apply_security_graph(inner, derived_lsn, &normalized.event)?;
                // SPEC-0047 — depois do grafo e antes do L1/L2, pela mesma
                // razão que o grafo vem antes: o evento derivado já tem LSN,
                // portanto a evidência pode apontar para ele.
                evaluate_threat(
                    inner,
                    normalized.source_lsn,
                    normalized.event.raw_event_id,
                    &normalized.event,
                )?;
            }
            let l1_suspicious = evaluate_l1(inner)?;
            if let Some(derived_lsn) = derived_lsn {
                evaluate_l2(
                    inner,
                    derived_lsn,
                    &normalized.event,
                    l1_suspicious.contains(&normalized.event.raw_event_id),
                )?;
            }
            inner
                .metrics
                .events_normalized_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            inner
                .metrics
                .normalization_skipped_total
                .fetch_add(1, Ordering::Relaxed);
        }
        // This is the commit point: all recoverable work for `lsn` completed.
        cursor.next_lsn = lsn.saturating_add(1);
        inner.cursor_store.commit(*cursor)?;
        // Só DEPOIS de o commit ser durável: publicar antes daria a um
        // observador uma posição que um crash desfaria.
        inner
            .next_lsn_publicado
            .store(cursor.next_lsn, std::sync::atomic::Ordering::Release);
        inner
            .metrics
            .events_processed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    if cursor.next_lsn < inner.log.head() {
        inner.queue.request_catch_up(cursor.next_lsn);
    }
    Ok(())
}

fn episode_is_generated(episode: &heraclitus_core::Episode) -> bool {
    episode.agent_id == "sentinel"
        && episode
            .attrs
            .get("sentinel.generated")
            .is_some_and(|value| matches!(value.as_str(), "true" | "derived" | "1"))
}

fn normalize_l0(
    inner: &RuntimeInner,
    lsn: Lsn,
    episode: &Episode,
) -> Option<NormalizedSecurityEvent> {
    let _latency = LatencyRecorder::microseconds(&inner.metrics.l0_latency_us);
    inner.normalizer.normalize(lsn, episode, now_ms())
}

fn remember_rule_event(inner: &RuntimeInner, source_lsn: Lsn, event: &SecurityEvent) {
    if inner.rule_engine.is_some() {
        let mut history = inner
            .rule_history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !history.iter().any(|(lsn, existing)| {
            *lsn == source_lsn && existing.raw_event_id == event.raw_event_id
        }) {
            history.push((source_lsn, event.clone()));
            history.sort_by(|left, right| {
                left.0
                    .cmp(&right.0)
                    .then_with(|| left.1.raw_event_id.cmp(&right.1.raw_event_id))
            });
        }
    }
}

/// SPEC-0047 §11/§36 — correlaciona o evento contra o índice de IOC e persiste
/// o que daí sai: **evidência**, nunca uma acção.
///
/// A idempotência é a mesma dos outros derivados: o `signal_id` é
/// determinístico (BLAKE3 sobre detector + sujeito + evidência + janela), por
/// isso um replay do mesmo LSN não emite um segundo sinal. As sightings vão
/// pela mesma chave de deduplicação do sink.
fn evaluate_threat(
    inner: &RuntimeInner,
    source_lsn: Lsn,
    derived_event_id: EventId,
    event: &SecurityEvent,
) -> Result<(), SentinelError> {
    let Some(plane) = inner.threat.as_ref() else {
        return Ok(());
    };
    // O relógio do evento, não o da máquina: um replay a um LSN antigo tem de
    // reproduzir a decisão que era correcta então (§12).
    let now = if event.observed_at != 0 {
        event.observed_at
    } else {
        now_ms()
    };
    let hits = plane.correlate(event, now);
    if hits.is_empty() {
        return Ok(());
    }
    inner
        .metrics
        .threat_matches_total
        .fetch_add(hits.len() as u64, Ordering::Relaxed);

    for sighting in plane.sightings(&hits, derived_event_id, source_lsn, now) {
        // A identidade e "este indicador, casado desta forma, NESTE evento" —
        // e o `event_id` e o mesmo qualquer que seja o caminho por onde o
        // evento chegou. Com o LSN na chave, a mesma observacao vista duas
        // vezes produzia dois sightings.
        let key = format!(
            "t:{}:{}:{}",
            sighting.indicator_id, sighting.match_kind, sighting.event_id
        );
        let novo = inner
            .sighting_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .inserir(&key.to_string());
        if !novo {
            continue;
        }
        inner.derived_sink.append(sighting.into_episode()?, &key)?;
        inner
            .metrics
            .threat_sightings_emitted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    if let Some(signal) = plane.signal_for(event, &hits, source_lsn, derived_event_id) {
        let already_emitted = inner
            .signal_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&signal.signal_id);
        if !already_emitted {
            let signal_id = signal.signal_id.clone();
            let mut episode = signal.into_episode()?;
            episode.attrs.insert(
                "sentinel.pipeline_version".into(),
                inner.config.pipeline_version.to_string(),
            );
            inner
                .derived_sink
                .append(episode, &format!("s:{signal_id}"))?;
            inner
                .signal_ids
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(signal_id);
            inner
                .metrics
                .signals_emitted_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

fn apply_security_graph(
    inner: &RuntimeInner,
    episode_lsn: Lsn,
    event: &SecurityEvent,
) -> Result<(), SentinelError> {
    if let Some(graph) = inner.security_graph.as_ref() {
        let _latency = LatencyRecorder::milliseconds(&inner.metrics.l3_latency_ms);
        graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .apply_security_event(episode_lsn, event)?;
    }
    Ok(())
}

fn evaluate_l2(
    inner: &RuntimeInner,
    security_event_lsn: Lsn,
    event: &SecurityEvent,
    rule_suspicious: bool,
) -> Result<(), SentinelError> {
    let Some(engine) = inner.behavior_engine.as_ref() else {
        return Ok(());
    };
    let _latency = LatencyRecorder::milliseconds(&inner.metrics.l2_latency_ms);

    // Work on a candidate copy.  Durable derived signals are appended before
    // the candidate replaces live state, closing the crash window where an
    // in-memory baseline advanced but its anomaly signal did not reach the log.
    let mut candidate = engine
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let source_lsn = event
        .attributes
        .get("sec.source_lsn")
        .and_then(|value| value.parse().ok())
        .unwrap_or(security_event_lsn);
    let evidence = EvidenceRef {
        lsn: source_lsn,
        event_id: event.raw_event_id,
    };
    let detector = DetectorIdentity {
        id: "l2.behavioral.baseline".into(),
        version: format!(
            "p{}-ms{}-ld{}-shadow{}-sev{}",
            inner.config.pipeline_version,
            inner.config.l2.minimum_support,
            inner.config.l2.learning_delay_events,
            u8::from(inner.config.l2.shadow_only),
            inner.config.l2.suspicious_severity
        ),
    };
    let mut derived = Vec::new();
    for mut input in security_event_inputs(event, inner.config.l2.suspicious_severity)? {
        input.suspicious |= rule_suspicious;
        let observation = candidate.observe(
            security_event_lsn,
            input.entity.clone(),
            input.features,
            input.suspicious,
        )?;
        if !observation.score.anomalous {
            continue;
        }
        let threshold = candidate.policy().outlier_z;
        let score = if !observation.score.score.is_finite() {
            1.0
        } else if observation.score.score <= 0.0 {
            0.0
        } else {
            (observation.score.score / (observation.score.score + threshold)).clamp(0.0, 1.0)
        } as f32;
        let signal_id = SecuritySignal::deterministic_id(
            &detector,
            Some(&input.entity),
            std::slice::from_ref(&evidence),
            source_lsn,
        );
        let mut labels = BTreeMap::new();
        labels.insert("sentinel.level".into(), "l2".into());
        labels.insert(
            "behavior.disposition".into(),
            format!("{:?}", observation.disposition).to_ascii_lowercase(),
        );
        labels.insert(
            "behavior.support".into(),
            observation.score.support.to_string(),
        );
        labels.insert(
            "behavior.raw_score".into(),
            observation.score.score.to_string(),
        );
        derived.push(SecuritySignal {
            signal_id,
            detector: detector.clone(),
            severity: ((score * 10.0).ceil() as u8).clamp(1, 10),
            score,
            subject: Some(input.entity),
            evidence: vec![
                evidence.clone(),
                EvidenceRef {
                    lsn: 1,
                    event_id: EventId::new(),
                },
            ],
            created_at_lsn: source_lsn,
            labels,
        });
    }

    for signal in derived {
        let already_emitted = inner
            .signal_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&signal.signal_id);
        if already_emitted {
            continue;
        }
        let signal_id = signal.signal_id.clone();
        let mut episode = signal.into_episode()?;
        episode.attrs.insert(
            "sentinel.pipeline_version".into(),
            inner.config.pipeline_version.to_string(),
        );
        inner
            .derived_sink
            .append(episode, &format!("s:{signal_id}"))?;
        inner
            .signal_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(signal_id);
        inner
            .metrics
            .signals_emitted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    *engine
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = candidate;
    Ok(())
}

fn evaluate_l1(inner: &RuntimeInner) -> Result<HashSet<EventId>, SentinelError> {
    let Some(rule_engine) = inner.rule_engine.as_ref() else {
        return Ok(HashSet::new());
    };
    let _latency = LatencyRecorder::milliseconds(&inner.metrics.l1_latency_ms);
    // Evaluate while borrowing the canonical history.  RuleEngine only reads
    // it, and `process_until` serialises workers with the cursor mutex.  The
    // previous deep clone duplicated every SecurityEvent (including strings
    // and attribute maps) for every invocation and briefly doubled L1 memory.
    //
    // We intentionally do not discard rows based on observed_at: Sentinel
    // accepts late/out-of-order event time, so no finite time horizon is safe
    // until the configuration has an explicit lateness contract.
    let window = inner
        .rule_history
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let signals = rule_engine.evaluate(&window);
    drop(window);
    let suspicious_events = signals
        .iter()
        .flat_map(|signal| signal.evidence.iter().map(|evidence| evidence.event_id))
        .collect();
    for signal in signals {
        let already_emitted = inner
            .signal_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&signal.signal_id);
        if already_emitted {
            continue;
        }
        let signal_id = signal.signal_id.clone();
        let mut episode = signal.into_episode()?;
        episode.attrs.insert(
            "sentinel.pipeline_version".into(),
            inner.config.pipeline_version.to_string(),
        );
        let key = format!("s:{signal_id}");
        inner.derived_sink.append(episode, &key)?;
        inner
            .signal_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(signal_id);
        inner
            .metrics
            .signals_emitted_total
            .fetch_add(1, Ordering::Relaxed);
    }
    Ok(suspicious_events)
}

fn evaluate_fusion(
    inner: &RuntimeInner,
    signal_episode_lsn: Lsn,
    signal: &SecuritySignal,
) -> Result<(), SentinelError> {
    let (Some(fusion), Some(subject)) = (inner.fusion.as_ref(), signal.subject.clone()) else {
        return Ok(());
    };
    let _latency = LatencyRecorder::milliseconds(&inner.metrics.l3_latency_ms);
    let channel = if signal.detector.id.starts_with("l2.") {
        DetectorChannel::Behavioral
    } else if signal.detector.id.starts_with("l3.") {
        DetectorChannel::Graph
    } else if signal.detector.id.starts_with("threat.") {
        DetectorChannel::ThreatIntel
    } else {
        DetectorChannel::Rule
    };
    let subject_key = format!(
        "{}:{}:{}:{}",
        subject.kind.len(),
        subject.kind,
        subject.id.len(),
        subject.id
    );
    let (assessment, detector_ids) = {
        let mut states = inner
            .fusion_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = states
            .entry(subject_key)
            .or_insert_with(|| FusionAccumulator {
                subject: subject.clone(),
                rule_score: 0.0,
                behavioral_score: 0.0,
                graph_score: 0.0,
                threat_intel_score: 0.0,
                evidence: Vec::new(),
                detectors: BTreeMap::new(),
            });
        match channel {
            DetectorChannel::Rule => state.rule_score = state.rule_score.max(signal.score),
            DetectorChannel::Behavioral => {
                state.behavioral_score = state.behavioral_score.max(signal.score)
            }
            DetectorChannel::Graph => state.graph_score = state.graph_score.max(signal.score),
            DetectorChannel::ThreatIntel => {
                state.threat_intel_score = state.threat_intel_score.max(signal.score)
            }
            DetectorChannel::Custom(_) => {}
        }
        state.detectors.insert(signal.detector.id.clone(), channel);
        for evidence in &signal.evidence {
            if !state.evidence.contains(evidence) {
                state.evidence.push(evidence.clone());
            }
        }
        state.evidence.sort_by(|left, right| {
            left.lsn
                .cmp(&right.lsn)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        let fusion = fusion
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let assessment = fusion.fuse(
            state.subject.clone(),
            state.rule_score,
            state.behavioral_score,
            state.graph_score,
            state.threat_intel_score,
            state.evidence.clone(),
        )?;
        let detector_ids = state.detectors.keys().cloned().collect::<Vec<_>>();
        (assessment, detector_ids)
    };
    let revision_id = assessment.revision_id()?;
    let mut revisions = inner
        .risk_revision_ids
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if revisions.contains(&revision_id) {
        return Ok(());
    }
    let mut episode = assessment.into_episode()?;
    episode.attrs.insert(
        "sentinel.pipeline_version".into(),
        inner.config.pipeline_version.to_string(),
    );
    episode.attrs.insert(
        "sentinel.risk_transaction_lsn".into(),
        signal_episode_lsn.to_string(),
    );
    episode
        .attrs
        .insert("sentinel.detectors".into(), detector_ids.join(","));
    inner
        .derived_sink
        .append(episode, &format!("r:{revision_id}"))?;
    revisions.insert(revision_id);
    inner
        .metrics
        .risk_assessments_emitted_total
        .fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn evaluate_l3(
    inner: &RuntimeInner,
    signal_episode_lsn: Lsn,
    signal: &SecuritySignal,
) -> Result<(), SentinelError> {
    let Some(incident_engine) = inner.incident_engine.as_ref() else {
        return Ok(());
    };
    let _latency = LatencyRecorder::milliseconds(&inner.metrics.l3_latency_ms);

    // Lock order is graph -> incident.  Both guards are released before the
    // durable append, so neither a slow fsync nor host replication blocks L3
    // queries or creates a callback lock cycle.
    let graph = inner.security_graph.as_ref().map(|graph| {
        graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    });
    let (ingest, incident) = {
        let mut engine = incident_engine
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let ingest =
            engine.ingest_signal_with_graph_as_of(signal, graph.as_deref(), signal_episode_lsn)?;
        let incident = engine
            .incident(&ingest.incident_id)
            .cloned()
            .ok_or_else(|| SentinelError::Worker("incidente ingerido não encontrado".into()))?;
        (ingest, incident)
    };
    drop(graph);

    let revision_id = incident.revision_id()?;
    let mut revisions = inner
        .incident_revision_ids
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if revisions.contains(&revision_id) {
        return Ok(());
    }
    let mut episode = incident.into_episode()?;
    episode.attrs.insert(
        "sentinel.pipeline_version".into(),
        inner.config.pipeline_version.to_string(),
    );
    let key = format!("i:{revision_id}");
    inner.derived_sink.append(episode, &key)?;
    revisions.insert(revision_id);
    inner
        .metrics
        .incident_revisions_emitted_total
        .fetch_add(1, Ordering::Relaxed);
    if ingest.created {
        inner
            .metrics
            .incidents_created_total
            .fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

enum LatencyUnit {
    Microseconds,
    Milliseconds,
}

struct LatencyRecorder<'a> {
    metric: &'a std::sync::atomic::AtomicU64,
    started: Instant,
    unit: LatencyUnit,
}

impl<'a> LatencyRecorder<'a> {
    fn microseconds(metric: &'a std::sync::atomic::AtomicU64) -> Self {
        Self {
            metric,
            started: Instant::now(),
            unit: LatencyUnit::Microseconds,
        }
    }

    fn milliseconds(metric: &'a std::sync::atomic::AtomicU64) -> Self {
        Self {
            metric,
            started: Instant::now(),
            unit: LatencyUnit::Milliseconds,
        }
    }
}

impl Drop for LatencyRecorder<'_> {
    fn drop(&mut self) {
        let elapsed = match self.unit {
            LatencyUnit::Microseconds => self.started.elapsed().as_micros(),
            LatencyUnit::Milliseconds => self.started.elapsed().as_millis(),
        }
        .min(u64::MAX as u128) as u64;
        self.metric.store(elapsed, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventId, EventKind, FsyncPolicy};
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::pin::Pin;

    struct FailingBackend;

    impl ModelBackend for FailingBackend {
        fn investigate<'a>(
            &'a self,
            _context: &'a IncidentContext,
        ) -> Pin<Box<dyn Future<Output = Result<InvestigationResult, AiError>> + Send + 'a>>
        {
            Box::pin(async { Err(AiError::Backend("offline".into())) })
        }
    }

    fn l3_config() -> SentinelConfig {
        SentinelConfig {
            enabled: true,
            mode: SentinelMode::Observe,
            queue_capacity: 8,
            worker_threads: 1,
            pipeline_version: 1,
            catch_up_batch: 1,
            l1: SentinelL1Config::default(),
            l2: SentinelL2Config::default(),
            l3: SentinelL3Config {
                enabled: true,
                max_graph_hops: 6,
            },
            threat: Default::default(),
        }
    }

    fn signal(
        signal_id: &str,
        created_at_lsn: Lsn,
        evidence_id: EventId,
        score: f32,
    ) -> SecuritySignal {
        SecuritySignal {
            signal_id: signal_id.into(),
            detector: DetectorIdentity {
                id: "test.rule".into(),
                version: "1".into(),
            },
            severity: if score >= 0.8 { 9 } else { 4 },
            score,
            subject: Some(EntityRef::new("User", "alice")),
            evidence: vec![EvidenceRef {
                lsn: created_at_lsn,
                event_id: evidence_id,
            }],
            created_at_lsn,
            labels: BTreeMap::new(),
        }
    }

    fn wait_for_catch_up(runtime: &SentinelRuntime, log: &AnyLog) {
        // 30 s e nao 5, pela mesma razao documentada em
        // `l2_behavioral_adapter_emits_replayable_signal_after_shadow_promotion`:
        // o prazo mede carga da maquina, que o teste nao controla.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while runtime.cursor().next_lsn < log.head() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            runtime.cursor().next_lsn >= log.head(),
            "Sentinel did not catch up: cursor={} head={}",
            runtime.cursor().next_lsn,
            log.head()
        );
    }

    fn count_custom(log: &AnyLog, expected: &str) -> usize {
        log.scan(0, log.head())
            .unwrap()
            .into_iter()
            .filter(
                |(_, episode)| matches!(&episode.kind, EventKind::Custom(kind) if kind == expected),
            )
            .count()
    }

    #[test]
    fn disabled_runtime_does_not_attach_or_write() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let runtime = SentinelRuntime::start(log.clone(), SentinelConfig::default()).unwrap();
        assert!(runtime.is_none());
        log.append(Episode::new("raw", EventKind::Observation, b"{}".to_vec()))
            .unwrap();
        assert_eq!(log.head(), 1);
    }

    #[test]
    fn checkpoint_is_auditable_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let runtime = SentinelRuntime::start(
            log.clone(),
            SentinelConfig {
                enabled: true,
                mode: SentinelMode::Observe,
                queue_capacity: 8,
                worker_threads: 1,
                pipeline_version: 3,
                catch_up_batch: 32,
                l1: SentinelL1Config::default(),
                l2: SentinelL2Config::default(),
                l3: SentinelL3Config::default(),
                threat: Default::default(),
            },
        )
        .unwrap()
        .unwrap();
        log.append(Episode::new("raw", EventKind::Observation, b"{}".to_vec()))
            .unwrap();
        wait_for_catch_up(&runtime, &log);
        let processed_lsn = runtime.status().processed_lsn.unwrap_or(0);
        let first_lsn = runtime.checkpoint().unwrap();
        let head_after_first = log.head();
        let second_lsn = runtime.checkpoint().unwrap();
        assert_eq!(second_lsn, first_lsn);
        assert_eq!(log.head(), head_after_first);
        let checkpoints: Vec<_> = log
            .scan(0, log.head())
            .unwrap()
            .into_iter()
            .filter(|(_, episode)| {
                matches!(&episode.kind, EventKind::Custom(kind) if kind == "SentinelCheckpoint")
            })
            .collect();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].1.agent_id, "sentinel");
        let payload: SentinelCheckpoint =
            serde_json::from_slice(&checkpoints[0].1.content).unwrap();
        assert_eq!(payload.pipeline_version, 3);
        assert_eq!(payload.as_of_lsn, processed_lsn);
        assert_eq!(
            checkpoints[0].1.attrs["sentinel.as_of_lsn"],
            processed_lsn.to_string()
        );
        runtime.shutdown();
    }

    #[test]
    fn governance_updates_and_feedback_are_durable_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let runtime = SentinelRuntime::start(
            log.clone(),
            SentinelConfig {
                enabled: true,
                mode: SentinelMode::Assist,
                queue_capacity: 8,
                worker_threads: 1,
                pipeline_version: 1,
                catch_up_batch: 32,
                l1: SentinelL1Config::default(),
                l2: SentinelL2Config::default(),
                l3: SentinelL3Config::default(),
                threat: Default::default(),
            },
        )
        .unwrap()
        .unwrap();
        let model = SecurityModelUpdate {
            model_id: "investigator".into(),
            version: "v2".into(),
            previous_digest: Some("blake3:aa".into()),
            new_digest: "blake3:bb".into(),
            artifact_digest: "blake3:cc".into(),
            config_digest: "blake3:dd".into(),
            evaluator_version: "eval-v1".into(),
            validation_metrics: [("precision".into(), 0.98)].into_iter().collect(),
            activated_at_lsn: 0,
        };
        let model_lsn = runtime.persist_model_update(model.clone()).unwrap();
        assert_eq!(runtime.persist_model_update(model).unwrap(), model_lsn);

        let ruleset = SecurityRulesetUpdate {
            ruleset_id: "sigma-enterprise".into(),
            version: "2026.08.29".into(),
            digest: "blake3:ee".into(),
            activation_lsn: model_lsn,
            author: "security-team".into(),
            approval_metadata: "change-ticket=SEC-45".into(),
        };
        let ruleset_lsn = runtime.persist_ruleset_update(ruleset.clone()).unwrap();
        assert_eq!(
            runtime.persist_ruleset_update(ruleset).unwrap(),
            ruleset_lsn
        );

        let feedback = SecurityFeedback {
            feedback_id: "feedback-1".into(),
            incident_id: "incident-1".into(),
            label: FeedbackLabel::TruePositive,
            analyst: "analyst".into(),
            reason: "evidence confirmed".into(),
            evidence: Vec::new(),
        };
        let feedback_lsn = runtime.persist_feedback(feedback.clone()).unwrap();
        assert_eq!(runtime.persist_feedback(feedback).unwrap(), feedback_lsn);
        assert_eq!(count_custom(&log, "SecurityModelUpdate"), 1);
        assert_eq!(count_custom(&log, "SecurityRulesetUpdate"), 1);
        assert_eq!(count_custom(&log, "SecurityFeedback"), 1);
        runtime.shutdown();
    }

    #[test]
    fn runtime_l4_circuit_breaker_opens_after_backend_failures() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let runtime = SentinelRuntime::start(
            log,
            SentinelConfig {
                enabled: true,
                mode: SentinelMode::Shadow,
                queue_capacity: 8,
                worker_threads: 1,
                pipeline_version: 1,
                catch_up_batch: 32,
                l1: SentinelL1Config::default(),
                l2: SentinelL2Config::default(),
                l3: SentinelL3Config::default(),
                threat: Default::default(),
            },
        )
        .unwrap()
        .unwrap();
        let context = AiContextBuilder::new(ContextBudget::default())
            .unwrap()
            .build(
                "incident-offline",
                RiskAssessment {
                    subject: EntityRef::new("Host", "host-1"),
                    rule_score: 0.9,
                    behavioral_score: 0.0,
                    graph_score: 0.0,
                    threat_intel_score: 0.0,
                    fused_score: 0.9,
                    evidence: Vec::new(),
                    model_version: "risk-v1".into(),
                },
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                EnvironmentContext::default(),
                Vec::new(),
            )
            .unwrap();
        for _ in 0..5 {
            assert!(block_on(runtime.investigate(&FailingBackend, context.clone())).is_err());
        }
        let status = runtime.status();
        assert_eq!(status.ai_requests_total, 5);
        assert_eq!(status.ai_failures_total, 5);
        assert_eq!(status.ai_circuit_state, CircuitState::Open);
        assert!(block_on(runtime.investigate(&FailingBackend, context)).is_err());
        assert_eq!(runtime.status().ai_requests_total, 5);
        runtime.shutdown();
    }

    #[test]
    fn policy_approval_and_reversible_action_are_durable() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let runtime = SentinelRuntime::start(
            log.clone(),
            SentinelConfig {
                enabled: true,
                mode: SentinelMode::Assist,
                queue_capacity: 8,
                worker_threads: 1,
                pipeline_version: 1,
                catch_up_batch: 32,
                l1: SentinelL1Config::default(),
                l2: SentinelL2Config::default(),
                l3: SentinelL3Config::default(),
                threat: Default::default(),
            },
        )
        .unwrap()
        .unwrap();
        let evidence = EvidenceRef {
            lsn: 0,
            event_id: EventId::new(),
        };
        let assessment = EvidenceFusion::new(FusionWeights::default(), "v1")
            .unwrap()
            .fuse(
                EntityRef::new("User", "alice"),
                1.0,
                1.0,
                1.0,
                1.0,
                vec![evidence.clone()],
            )
            .unwrap();
        let incident = SecurityIncident {
            incident_id: "inc-1".into(),
            state: IncidentState::New,
            severity: 8,
            risk_score: 1.0,
            subjects: vec![EntityRef::new("User", "alice")],
            signals: vec!["s1".into(), "s2".into()],
            evidence: vec![evidence.clone()],
            first_seen_lsn: 0,
            last_seen_lsn: 0,
            mitre: Vec::new(),
        };
        let proposal = ActionProposal {
            proposal_id: "p-1".into(),
            incident_id: "inc-1".into(),
            action: SecurityAction::BlockIp {
                ip: "203.0.113.25".into(),
                ttl_secs: 60,
            },
            rationale: "detector quorum".into(),
            evidence: vec![evidence.clone()],
            expected_effect: "contenção temporária".into(),
            requested_ttl: Some(60),
        };
        let context = AiContextBuilder::new(ContextBudget::default())
            .unwrap()
            .build(
                "inc-1",
                assessment.clone(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                EnvironmentContext::default(),
                vec![ActionCapability {
                    kind: ActionKind::BlockIp,
                    enabled: true,
                    requires_approval: false,
                }],
            )
            .unwrap();
        assert!(runtime.persist_action_proposal(&context, &proposal).is_ok());
        let (decision, _) = runtime
            .evaluate_and_persist_policy(&incident, &assessment, &proposal)
            .unwrap();
        let authorized = decision.authorized_action(&proposal, None).unwrap();
        let executor = MemoryReversibleExecutor::default();
        let (result, _) =
            block_on(runtime.execute_authorized_action(&executor, authorized)).unwrap();
        assert!(result.success);
        assert_eq!(count_custom(&log, "SecurityActionResult"), 1);

        let high_proposal = ActionProposal {
            proposal_id: "p-high".into(),
            incident_id: "inc-1".into(),
            action: SecurityAction::QuarantineHost {
                host_id: "host-17".into(),
                ttl_secs: 60,
            },
            rationale: "host containment".into(),
            evidence: vec![
                evidence.clone(),
                EvidenceRef {
                    lsn: 1,
                    event_id: EventId::new(),
                },
            ],
            expected_effect: "quarentena temporária".into(),
            requested_ttl: Some(60),
        };
        let mut high_context = context;
        high_context.allowed_actions = vec![ActionCapability {
            kind: ActionKind::QuarantineHost,
            enabled: true,
            requires_approval: true,
        }];
        runtime
            .persist_action_proposal(&high_context, &high_proposal)
            .unwrap();
        let (high_decision, _) = runtime
            .evaluate_and_persist_policy(&incident, &assessment, &high_proposal)
            .unwrap();
        let approval_id = match &high_decision {
            PolicyDecision::RequireHumanApproval { approval_id, .. } => approval_id.clone(),
            other => panic!("esperava aprovação humana, recebeu {other:?}"),
        };
        runtime
            .persist_human_approval_for(
                "inc-1",
                "p-high",
                &approval_id,
                "analyst",
                true,
                "confirmado",
            )
            .unwrap();
        let approval = HumanApproval {
            approval_id: approval_id.clone(),
            incident_id: "inc-1".into(),
            proposal_id: "p-high".into(),
            approver: "analyst".into(),
            approved: true,
            reason: "confirmado".into(),
            evidence: high_proposal.evidence.clone(),
        };
        let authorized = high_decision
            .authorized_action_with_policy_version(
                "response-policy-v1",
                &high_proposal,
                Some(&approval),
            )
            .unwrap();
        let (high_result, _) =
            block_on(runtime.execute_authorized_action(&executor, authorized)).unwrap();
        assert!(high_result.success);
        assert_eq!(count_custom(&log, "SecurityApproval"), 1);
        runtime.shutdown();
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn live_runtime_normalizes_and_replays_without_looping() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let config = SentinelConfig {
            enabled: true,
            mode: SentinelMode::Observe,
            queue_capacity: 4,
            worker_threads: 1,
            pipeline_version: 1,
            catch_up_batch: 32,
            l1: SentinelL1Config::default(),
            l2: SentinelL2Config::default(),
            l3: SentinelL3Config::default(),
            threat: Default::default(),
        };
        let runtime = SentinelRuntime::start(log.clone(), config)
            .unwrap()
            .unwrap();
        log.append(Episode::new(
            "collector",
            EventKind::Observation,
            br#"{"source":"auditd","category":"authentication","activity":"login","outcome":"failure","user":"alice"}"#.to_vec(),
        )).unwrap();
        // 30 s e nao 5, pela mesma razao documentada em
        // `l2_behavioral_adapter_emits_replayable_signal_after_shadow_promotion`:
        // o prazo mede carga da maquina, que o teste nao controla.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while runtime.status().events_normalized_total < 1 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(runtime.status().events_normalized_total, 1);
        let rows = log.scan(0, log.head()).unwrap();
        assert!(rows
            .iter()
            .any(|(_, e)| matches!(&e.kind, EventKind::Custom(kind) if kind == "SecurityEvent")));
        let before = log.head();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(log.head(), before, "derived SecurityEvent must not loop");
        runtime.shutdown();
    }

    #[test]
    fn l1_sigma_rule_is_live_and_signal_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let rules = temp.path().join("failed-login.yml");
        std::fs::write(
            &rules,
            r#"title: Failed login
id: test-failed-login
level: high
detection:
  selection:
    EventID: 4625
  condition: selection
"#,
        )
        .unwrap();
        let config = SentinelConfig {
            enabled: true,
            mode: SentinelMode::Observe,
            queue_capacity: 8,
            worker_threads: 1,
            pipeline_version: 1,
            catch_up_batch: 32,
            l1: SentinelL1Config {
                enabled: true,
                rules_path: Some(rules),
            },
            l2: SentinelL2Config::default(),
            l3: SentinelL3Config::default(),
            threat: Default::default(),
        };
        let runtime = SentinelRuntime::start(log.clone(), config)
            .unwrap()
            .unwrap();
        log.append(Episode::new(
            "auditd",
            EventKind::Observation,
            br#"{"source":"auditd","EventID":4625}"#.to_vec(),
        ))
        .unwrap();
        // 30 s e nao 5, pela mesma razao documentada em
        // `l2_behavioral_adapter_emits_replayable_signal_after_shadow_promotion`:
        // o prazo mede carga da maquina, que o teste nao controla.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while runtime.status().signals_emitted_total < 1 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(runtime.status().signals_emitted_total, 1);
        let before = log.head();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            log.head(),
            before,
            "same evidence must not emit another signal"
        );
        assert!(log.scan(0, log.head()).unwrap().iter().any(|(_, episode)| {
            matches!(&episode.kind, EventKind::Custom(kind) if kind == "SecuritySignal")
        }));
        runtime.shutdown();
        drop(runtime);
        drop(log);

        let reopened = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let before_restart = reopened.head();
        let restarted = SentinelRuntime::start(
            reopened.clone(),
            SentinelConfig {
                enabled: true,
                mode: SentinelMode::Observe,
                queue_capacity: 8,
                worker_threads: 1,
                pipeline_version: 1,
                catch_up_batch: 32,
                l1: SentinelL1Config {
                    enabled: true,
                    rules_path: Some(temp.path().join("failed-login.yml")),
                },
                l2: SentinelL2Config::default(),
                l3: SentinelL3Config::default(),
                threat: Default::default(),
            },
        )
        .unwrap()
        .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(restarted.status().signals_emitted_total, 0);
        assert_eq!(reopened.head(), before_restart);
        restarted.shutdown();
    }

    #[test]
    fn l2_behavioral_adapter_emits_replayable_signal_after_shadow_promotion() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let runtime = SentinelRuntime::start(
            log.clone(),
            SentinelConfig {
                enabled: true,
                mode: SentinelMode::Observe,
                queue_capacity: 8,
                worker_threads: 1,
                pipeline_version: 2,
                catch_up_batch: 32,
                l1: SentinelL1Config::default(),
                l2: SentinelL2Config {
                    enabled: true,
                    minimum_support: 1,
                    learning_delay_events: 1,
                    shadow_only: false,
                    suspicious_severity: 9,
                },
                l3: SentinelL3Config::default(),
                threat: Default::default(),
            },
        )
        .unwrap()
        .unwrap();
        for severity in [1, 1, 10] {
            log.append(Episode::new(
                "auditd",
                EventKind::Observation,
                format!(
                    r#"{{"source":"auditd","category":"authentication","activity":"login","outcome":"success","user":"alice","severity":{severity}}}"#
                )
                .into_bytes(),
            ))
            .unwrap();
        }
        // ESTE TESTE E INSTAVEL E O PRAZO NAO O ARRANJA. Fica aqui o que ja se
        // mediu, para nao se repetir trabalho nem se voltar a aumentar o numero.
        //
        // 2026-08-31: o prazo subiu de 5 s para 30 s, atribuindo a falha a falta
        // de PROCESSADOR (um so worker a competir com dezenas de binarios de
        // teste). 2026-09-02: continua a falhar em `cargo test --workspace`, aos
        // 30 s.
        //
        // Tres medicoes de 2026-09-02, cada uma a correr o binario completo:
        //
        //   isolado, maquina livre ............. 6 corridas, 0 falhas, ~0,6 s
        //   8 geradores a saturar os 8 nucleos . 5 corridas, 0 falhas, ~0,6 s
        //   6 escritores com flush sincrono .... 5 corridas, 1 falha,  30,8 s
        //
        // A primeira e a segunda REFUTAM a explicacao pelo processador:
        // `worker_threads` sao threads do SO e o escalonador da-lhes tempo. A
        // terceira reproduz a falha de forma fiavel, portanto o gatilho tem a
        // ver com I/O.
        //
        // Mas a correccao obvia NAO funciona: passar o log deste teste de
        // `FsyncPolicy::Always` para `GroupCommit { interval_ms: 5 }` -- para o
        // append do sinal deixar de esperar pelo seu proprio fsync -- deu 4
        // falhas em 8 sob a mesma carga, ou seja pior. A causa esta mais fundo
        // do que o fsync do append, e nao esta identificada.
        //
        // 2026-09-03: o que faltava era diagnostico, e o diagnostico nao
        // precisa de stacks de threads — o `SentinelStatus` ja publica os
        // contadores de cada estagio. O timeout passa a imprimi-los, o que
        // transforma a proxima falha numa resposta em vez de mais uma medicao.
        // A arvore de decisao esta no `panic!` abaixo.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while runtime.status().signals_emitted_total < 1 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let s = runtime.status();
        if s.signals_emitted_total < 1 {
            // Onde e que o pipeline parou? Cada contador a zero acusa o
            // estagio anterior; o primeiro zero da cadeia e o culpado.
            let estagio = if s.events_seen_total == 0 {
                "a ponte log->subscritor nunca notificou (attach_subscriber_with_stop / tail_subscribe)"
            } else if s.events_processed_total == 0 {
                "o subscritor viu, mas o worker nunca processou (fila ou worker_loop)"
            } else if s.events_normalized_total == 0 {
                "o worker processou, mas nada foi normalizado (normalize_l0)"
            } else {
                "normalizou mas o L2 nao emitiu (evaluate_l2 / promocao do shadow)"
            };
            panic!(
                "o pipeline L2 nao emitiu sinal nenhum em 30 s.\n\
                 ESTAGIO SUSPEITO: {estagio}\n\
                 log:    head={} next={} lag={} ({:?})\n\
                 fila:   profundidade={}/{} overflows={} catch_up_from={:?} passagens={}\n\
                 cadeia: vistos={} processados={} normalizados={} saltados={} erros={}\n\
                 latencias: l0={}us l1={}ms l2={}ms",
                s.head_lsn,
                s.next_lsn,
                s.detection_lag_lsn,
                s.lag_state,
                s.queue_depth,
                s.queue_capacity,
                s.queue_overflow_total,
                s.catch_up_from_lsn,
                s.catchup_passes_total,
                s.events_seen_total,
                s.events_processed_total,
                s.events_normalized_total,
                s.normalization_skipped_total,
                s.normalization_errors_total,
                s.l0_latency_us,
                s.l1_latency_ms,
                s.l2_latency_ms,
            );
        }
        assert!(log.scan(0, log.head()).unwrap().iter().any(|(_, episode)| {
            matches!(&episode.kind, EventKind::Custom(kind) if kind == "SecuritySignal")
                && episode
                    .attrs
                    .get("sentinel.detector")
                    .is_some_and(|value| value == "l2.behavioral.baseline")
        }));
        assert!(runtime.behavioral_snapshot().is_some());
        assert!(runtime
            .behavioral_snapshot_as_of(0)
            .unwrap()
            .unwrap()
            .profiles
            .is_empty());
        runtime.shutdown();
    }

    #[test]
    fn l3_rebuilds_incidents_and_cursor_rewind_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let log_path = temp.path().join("log");
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                &log_path,
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );

        let raw_one = Episode::new("sensor", EventKind::Observation, b"{}".to_vec());
        let raw_one_id = raw_one.id;
        let raw_one_lsn = log.append(raw_one).unwrap();
        log.append(
            signal("sig-one", raw_one_lsn, raw_one_id, 0.4)
                .into_episode()
                .unwrap(),
        )
        .unwrap();
        let raw_two = Episode::new("sensor", EventKind::Observation, b"{}".to_vec());
        let raw_two_id = raw_two.id;
        let raw_two_lsn = log.append(raw_two).unwrap();
        log.append(
            signal("sig-two", raw_two_lsn, raw_two_id, 0.9)
                .into_episode()
                .unwrap(),
        )
        .unwrap();

        let config = l3_config();
        let runtime = SentinelRuntime::start(log.clone(), config.clone())
            .unwrap()
            .unwrap();
        wait_for_catch_up(&runtime, &log);
        let incidents = runtime.current_incidents();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].signals, vec!["sig-one", "sig-two"]);
        assert_eq!(incidents[0].severity, 9);
        assert_eq!(incidents[0].risk_score, 0.9);
        assert_eq!(count_custom(&log, "SecurityIncident"), 2);
        assert_eq!(runtime.status().incident_revisions_emitted_total, 2);
        let before_restart = log.head();
        runtime.shutdown();
        drop(runtime);
        drop(log);

        // Simulate the semantic crash window by rewinding the durable cursor
        // behind raw and derived rows.  Full replay must not duplicate either
        // normalized events or incident revisions, even with batch size one.
        CursorStore::new(log_path.join("sentinel").join("cursor.json"))
            .commit(SentinelCursor::new(1))
            .unwrap();
        let reopened = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                &log_path,
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let restarted = SentinelRuntime::start(reopened.clone(), config)
            .unwrap()
            .unwrap();
        wait_for_catch_up(&restarted, &reopened);
        assert_eq!(reopened.head(), before_restart);
        assert_eq!(count_custom(&reopened, "SecurityIncident"), 2);
        assert_eq!(restarted.status().incident_revisions_emitted_total, 0);
        assert_eq!(restarted.current_incidents(), incidents);
        restarted.shutdown();
    }

    #[test]
    fn l3_live_runtime_builds_temporal_graph_from_security_events() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let runtime = SentinelRuntime::start(log.clone(), l3_config())
            .unwrap()
            .unwrap();
        log.append(Episode::new(
            "auditd",
            EventKind::Observation,
            br#"{"source":"auditd","category":"authentication","activity":"login","outcome":"success","user":"alice","session":"sess-1","host":"db01","resource":{"id":"prod","kind":"Database"}}"#.to_vec(),
        ))
        .unwrap();
        wait_for_catch_up(&runtime, &log);

        let graph = runtime.temporal_graph_snapshot().unwrap();
        assert_eq!(graph.edges.len(), 4);
        assert!(graph.edges.iter().all(|edge| edge.valid_from_lsn == 1));
        assert!(graph
            .edges
            .iter()
            .all(|edge| edge.evidence.iter().all(|evidence| evidence.lsn == 0)));
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == SecurityEdgeKind::AuthenticatedTo
                && edge.from.id == "alice"
                && edge.to.id == "db01"
        }));
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.kind == SecurityEdgeKind::CreatedSession));
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.kind == SecurityEdgeKind::ActiveOn));
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == SecurityEdgeKind::Accessed
                && edge.to.kind == "Database"
                && edge.to.id == "prod"
        }));
        assert!(runtime
            .temporal_graph_snapshot_as_of(0)
            .unwrap()
            .edges
            .is_empty());
        runtime.shutdown();
    }

    #[test]
    fn l3_consumes_a_security_signal_appended_after_startup() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                heraclitus_core::StorageFormat::Legacy,
                temp.path().join("log"),
                1 << 20,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let runtime = SentinelRuntime::start(log.clone(), l3_config())
            .unwrap()
            .unwrap();
        let evidence_id = EventId::new();
        log.append(
            signal("sig-live", 0, evidence_id, 0.75)
                .into_episode()
                .unwrap(),
        )
        .unwrap();
        wait_for_catch_up(&runtime, &log);

        let current = runtime.current_incidents();
        assert_eq!(current.len(), 1);
        let incident_id = current[0].incident_id.clone();
        assert!(runtime.incident_as_of(&incident_id, 0).unwrap().is_none());
        let filtered = Sentinel::incidents(
            &runtime,
            IncidentFilter {
                min_severity: Some(4),
                ..IncidentFilter::default()
            },
        )
        .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(count_custom(&log, "SecurityIncident"), 1);
        assert_eq!(count_custom(&log, "SecurityRiskAssessment"), 1);
        assert_eq!(runtime.status().risk_assessments_emitted_total, 1);
        assert_eq!(runtime.status().incidents_created_total, 1);
        runtime.shutdown();
    }
}

#[cfg(test)]
mod testes_janela_de_chaves {
    use super::{JanelaDeChaves, TECTO_CHAVES_SIGHTING};

    /// A propriedade que a deduplicacao existe para ter: o mesmo evento visto
    /// duas vezes pelos dois caminhos so produz UM sighting.
    #[test]
    fn uma_chave_repetida_e_suprimida() {
        let mut j = JanelaDeChaves::nova(8);
        assert!(
            j.inserir(&"t:ioc-1:domain:E1".to_string()),
            "a primeira e nova"
        );
        assert!(
            !j.inserir(&"t:ioc-1:domain:E1".to_string()),
            "a segunda e o duplicado"
        );
        assert!(
            j.inserir(&"t:ioc-1:domain:E2".to_string()),
            "outro evento e outra chave"
        );
    }

    /// A propriedade que faltava: a estrutura NAO cresce para sempre.
    ///
    /// A versao anterior era um `HashSet<String>` sem poda, e a chave inclui um
    /// ULID unico por evento — cada sighting emitido deixava la uma entrada que
    /// nunca mais servia para nada.
    #[test]
    fn a_janela_nao_cresce_para_alem_do_tecto() {
        let mut j = JanelaDeChaves::nova(16);
        for i in 0..10_000 {
            j.inserir(&format!("t:ioc:kind:evento-{i}"));
        }
        assert_eq!(
            j.len(),
            16,
            "dez mil chaves distintas nao podem deixar dez mil entradas"
        );
    }

    /// A consequencia aceite de ter tecto: uma chave antiga sai, e se o mesmo
    /// evento voltasse muito depois seria emitido outra vez. E aceitavel porque
    /// o duplicado que isto apanha chega no mesmo ciclo, nao dias depois.
    #[test]
    fn a_chave_mais_antiga_sai_quando_o_tecto_e_atingido() {
        let mut j = JanelaDeChaves::nova(2);
        assert!(j.inserir(&"a".to_string()));
        assert!(j.inserir(&"b".to_string()));
        assert!(!j.inserir(&"a".to_string()), "ainda esta na janela");
        j.inserir(&"c".to_string()); // expulsa "a"
        assert!(
            j.inserir(&"a".to_string()),
            "saiu da janela, volta a ser nova"
        );
        assert_eq!(j.len(), 2);
    }

    /// Um tecto de zero seria um `insert` que nunca deduplica; a construcao
    /// eleva-o a um.
    #[test]
    fn um_tecto_de_zero_e_elevado_a_um() {
        let mut j = JanelaDeChaves::nova(0);
        assert!(j.inserir(&"x".to_string()));
        assert!(!j.inserir(&"x".to_string()));
        assert_eq!(j.len(), 1);
    }

    #[test]
    fn o_tecto_de_producao_e_o_declarado() {
        let j = JanelaDeChaves::nova(TECTO_CHAVES_SIGHTING);
        assert_eq!(j.len(), 0);
        assert_eq!(TECTO_CHAVES_SIGHTING, 65_536);
    }
}

#[cfg(test)]
mod testes_janela_de_lsn {
    use super::{JanelaRecente, TECTO_LSN_DERIVADOS};

    /// A propriedade que existe para ter: nao derivar duas vezes o mesmo LSN.
    #[test]
    fn um_lsn_ja_derivado_e_reconhecido() {
        let mut j: JanelaRecente<u64> = JanelaRecente::nova(8);
        assert!(j.inserir(&42));
        assert!(j.contem(&42));
        assert!(!j.inserir(&42), "o segundo pedido nao e novo");
        assert!(!j.contem(&43));
    }

    /// A que faltava: NAO cresce com o trafego. Era um `HashSet<Lsn>` que
    /// recebia um u64 por evento derivado e nunca largava nenhum — num servico
    /// desenhado para correr indefinidamente, um vazamento sem fim.
    #[test]
    fn a_janela_de_lsn_nao_cresce_com_o_trafego() {
        let mut j: JanelaRecente<u64> = JanelaRecente::nova(64);
        for lsn in 0..100_000u64 {
            j.inserir(&lsn);
        }
        assert_eq!(
            j.len(),
            64,
            "cem mil eventos nao podem deixar cem mil entradas"
        );
        assert!(j.contem(&99_999), "os recentes continuam la");
        assert!(
            !j.contem(&0),
            "os antigos sairam, que e o que o tecto significa"
        );
    }

    #[test]
    fn o_tecto_de_producao_e_o_declarado() {
        assert_eq!(TECTO_LSN_DERIVADOS, 262_144);
    }
}
