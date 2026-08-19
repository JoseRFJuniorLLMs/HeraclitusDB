//! The engine: composes log + memtable + views into one query surface.
//! All intelligence lives in the agent; this is just the riverbed.

use heraclitus_activation::ActivationStore;
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
use heraclitus_log::Log;
use heraclitus_manifold::ProductMetric;
use heraclitus_memtable::Memtable;
use heraclitus_query::ast::Value as GqlValue;
use heraclitus_query::backend::{
    cluster_of, community_of, hypotheses_of, match_edges_of, neighbors_of, node_metrics_of,
    resolve_of, traverse_of, CommunityResult, EdgeHypotheses, EdgeRow, MetricsResult, NeighborRow,
    QueryBackend,
};
use heraclitus_retrieval::{retrieve, LinearReranker, RecallInputs};
use heraclitus_views::{View, ViewRegistry};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Reserved technical attributes used to make external delivery exactly-once.
/// They remain outside the encrypted attribute envelope so retries can still be
/// identified after a subject has been crypto-shredded.
pub const IDEMPOTENCY_KEY_ATTR: &str = "__heraclitus_idempotency_key";
pub const IDEMPOTENCY_HASH_ATTR: &str = "__heraclitus_idempotency_hash";

pub struct Engine {
    pub log: Arc<Log>,
    pub memtable: Arc<Memtable>,
    views: Mutex<ViewRegistry>,
    vector: Arc<Mutex<VectorIndex>>,
    text: Arc<Mutex<TextIndex>>,
    graph: Arc<Mutex<GraphIndex>>,
    tgraph: Arc<Mutex<TemporalGraph>>,
    entity: Arc<Mutex<EntityResolver>>,
    activation: Arc<Mutex<ActivationStore>>,
    /// Índice secundário de atributos (qualquer campo -> [LSN]). Persistido em
    /// `<data_dir>/views`; gerido diretamente pelo Engine (fora do ViewRegistry)
    /// para controlar o checkpoint/replay e o arranque rápido.
    attr: Arc<Mutex<AttrIndex>>,
    attr_dir: std::path::PathBuf,
    /// Raiz do cold tier (object store local); `demote` materializa segmentos aqui.
    #[cfg(feature = "tier")]
    cold_tier_path: std::path::PathBuf,
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
    idempotency_lock: Mutex<()>,
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
struct Shared<T>(Arc<Mutex<T>>);

impl<T: View> View for Shared<T> {
    fn name(&self) -> &str {
        // Names are static per index type.
        let g = self.0.lock().unwrap();
        // SAFETY-free trick: names are 'static string literals in all our
        // views, so returning them outlives the guard.
        match g.name() {
            "vector" => "vector",
            "text" => "text",
            "graph" => "graph",
            "tgraph" => "tgraph",
            "entity" => "entity",
            "activation" => "activation",
            _ => "view",
        }
    }
    fn apply(&mut self, lsn: Lsn, event: &Episode) {
        self.0.lock().unwrap().apply(lsn, event);
    }
    fn watermark(&self) -> Lsn {
        self.0.lock().unwrap().watermark()
    }
    // Sem estes forwards, o wrapper engolia os defaults do trait (no-op) e
    // NENHUMA view persistia/restaurava — todo o boot era replay desde 0.
    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), HeraclitusError> {
        self.0.lock().unwrap().checkpoint(dir)
    }
    fn restore(&mut self, dir: &std::path::Path) -> Result<bool, HeraclitusError> {
        self.0.lock().unwrap().restore(dir)
    }
    fn reset(&mut self) {
        self.0.lock().unwrap().reset();
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
            let log = Arc::new(Log::open_with_keystore(
                config.data_dir.join("log"),
                config.segment_max_bytes,
                config.fsync.clone(),
                keystore.clone(),
            )?);
            let head = log.head();
            p.ok(format!(
                "{} eventos · head LSN {} · segmentos de {}",
                group(head),
                group(head),
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
            let v = Arc::new(Mutex::new(VectorIndex::new(metric.clone())));
            p.ok("k-NN no espaço de produto");
            v
        };
        let text = {
            let p = boot.phase("Índice de texto (invertido)");
            let t = Arc::new(Mutex::new(TextIndex::new()));
            p.ok("recall em duas fases");
            t
        };
        let graph = {
            let p = boot.phase("Índice de grafo (proveniência DAG)");
            let g = Arc::new(Mutex::new(GraphIndex::new()));
            p.ok("WHY · arestas de origem");
            g
        };
        let tgraph = {
            let p = boot.phase("Grafo temporal (consultas AS OF)");
            let g = Arc::new(Mutex::new(TemporalGraph::new()));
            p.ok("arestas com intervalos de validade");
            g
        };
        let entity = {
            let p = boot.phase("Resolução de entidades");
            let e = Arc::new(Mutex::new(EntityResolver::new()));
            p.ok("merge/cluster por chave");
            e
        };
        let activation = {
            let p = boot.phase("Ativação ACT-R (memória cognitiva)");
            let a = Arc::new(Mutex::new(ActivationStore::new(config.activation_decay)));
            p.ok(format!("decaimento d={}", config.activation_decay));
            a
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
                    "6 views materializadas @ LSN {} · checkpoint gravado",
                    group(wm)
                ));
            }
            registry
        };

        // Índice secundário de atributos: carrega o checkpoint e replaya só a
        // cauda (arranque rápido); num log virgem constrói tudo uma vez e grava.
        let attr_dir = config.data_dir.join("views");
        let attr = {
            let p = boot.phase("Índice de atributos (campo → LSN)");
            let attr = Arc::new(Mutex::new(if privacy_rebuild {
                AttrIndex::new()
            } else {
                AttrIndex::open(&attr_dir)
            }));
            let keys = {
                let mut idx = attr.lock().unwrap();
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
        let distill_cursor = std::sync::atomic::AtomicU64::new(
            std::fs::read(attr_dir.join("distill.cursor"))
                .ok()
                .filter(|b| b.len() == 8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
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
            attr,
            attr_dir,
            metric,
            keystore,
            log_only,
            audit_queries: config.audit_queries,
            replication: std::sync::OnceLock::new(),
            hvm_lock: Mutex::new(()),
            idempotency_lock: Mutex::new(()),
            #[cfg(feature = "tier")]
            cold_tier_path: config.cold_tier_path.clone(),
            #[cfg(feature = "distill")]
            distill_cursor,
        };
        if privacy_rebuild {
            engine.attr.lock().unwrap().save(&engine.attr_dir)?;
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
        self.attr.lock().unwrap().apply(lsn, episode);
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
        self.attr.lock().unwrap().save(&self.attr_dir)
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
        let sealed = self.log.sealed_segments().len();
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
        self.graph.lock().unwrap().state_hash()
    }

    /// Abre o backend do cold tier a partir de `cold_tier_path` — um URL de
    /// nuvem (`gs://…`/`s3://…`, features `gcp`/`aws` do tier) ou um caminho
    /// local (default). As credenciais de nuvem vêm do ambiente.
    #[cfg(feature = "tier")]
    fn open_cold_tier(&self) -> Result<heraclitus_tier::ColdTier, HeraclitusError> {
        heraclitus_tier::ColdTier::open_location(&self.cold_tier_path.to_string_lossy())
    }

    /// Ids dos segmentos selados — candidatos a demote para o cold tier.
    pub fn sealed_segment_ids(&self) -> Vec<SegmentId> {
        self.log
            .sealed_segments()
            .into_iter()
            .map(|s| s.id)
            .collect()
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
    pub async fn demote_segment(
        &self,
        segment_id: SegmentId,
    ) -> Result<heraclitus_tier::DemotionReceipt, HeraclitusError> {
        let cold = self.open_cold_tier()?;
        let receipt = cold.demote_prepared(&self.log, segment_id).await?;
        self.append(heraclitus_tier::ColdTier::receipt_episode(&receipt)?)?;
        Ok(receipt)
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
            let g = self.graph.lock().unwrap();
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

    /// Os recibos de demote no log (o que já foi materializado no cold tier).
    /// Scan JANELADO do log (R20: o scan sem teto materializava o log inteiro
    /// num Vec — a mesma classe do R9/R10; op de manutenção não é desculpa
    /// para um alloc proporcional ao log).
    #[cfg(feature = "tier")]
    pub fn demotion_receipts(
        &self,
    ) -> Result<Vec<heraclitus_tier::DemotionReceipt>, HeraclitusError> {
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
                    if let Ok(r) =
                        serde_json::from_slice::<heraclitus_tier::DemotionReceipt>(&ep.content)
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
            .demotion_receipts()?
            .into_iter()
            .rev()
            .find(|r| r.segment_id == segment_id)
            .ok_or_else(|| {
                HeraclitusError::Query(format!("sem recibo de demote para o segmento {segment_id}"))
            })?;
        let cold = self.open_cold_tier()?;
        cold.fetch_cold(&receipt).await
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
        let facts = distiller.distill_episodes(&episodes, head)?;
        let mut out = Vec::with_capacity(facts.len());
        for ev in facts {
            out.push(self.append(ev)?); // §2.6
        }

        self.distill_cursor.store(next_cursor, Ordering::Release);
        // Persistência best-effort do cursor (tmp + rename atómico). Falhar aqui
        // só arrisca re-agrupar uma janela num restart — nunca perde dados.
        let path = self.attr_dir.join("distill.cursor");
        let tmp = self.attr_dir.join("distill.cursor.tmp");
        if std::fs::write(&tmp, next_cursor.to_le_bytes()).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
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
        let vals = self.attr.lock().unwrap().field_values("_agent");
        let mut fontes = Vec::with_capacity(vals.len());
        let (mut global_min, mut global_max) = (u64::MAX, 0u64);

        for (agente, eventos) in vals {
            let span = self.attr.lock().unwrap().field_span("_agent", &agente);
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
        let lsns: Vec<Lsn> = self.attr.lock().unwrap().lookup("_agent", agente).to_vec();
        let total = lsns.len();
        // Amostra pelas pontas: os mais RECENTES importam mais para saber o que
        // a fonte faz agora, mas os primeiros mostram como comecou.
        let lidos: Vec<Lsn> = if total <= amostra_max {
            lsns.clone()
        } else {
            let metade = amostra_max / 2;
            lsns.iter().take(metade).chain(lsns.iter().rev().take(amostra_max - metade)).copied().collect()
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
        let campos = self.attr.lock().unwrap().fields();
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

        let campos = self.attr.lock().unwrap().diff(de, ate, topo);
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
            let attr = self.attr.lock().unwrap();
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
        let agentes_indexados = self.attr.lock().unwrap().field_entries("_agent");

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
            let Some(&(ultimo, _)) = lote.last() else { break };
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
        std::fs::create_dir_all(&self.attr_dir)?;
        let marker = self.attr_dir.join("privacy-rebuild-required");
        let recovery_pending = marker.exists();
        if !recovery_pending {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&marker)?;
            f.write_all(b"rebuild all derived state before serving\n")?;
            f.sync_all()?;
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
        *self.attr.lock().unwrap() = rebuilt;

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
        mut episode: Episode,
        key: &str,
    ) -> Result<(Lsn, bool, String), HeraclitusError> {
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

        let _guard = self.idempotency_lock.lock().unwrap();
        let previous = self
            .attr
            .lock()
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

    pub fn snapshot(&self) -> Lsn {
        self.log.head()
    }

    pub fn rebuild(&self, view: Option<&str>) -> Result<(), HeraclitusError> {
        self.views.lock().unwrap().rebuild(&self.log, view)
    }

    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "head": self.log.head(),
            "memtable": self.memtable.len(),
            "vector_indexed": self.vector.lock().unwrap().len(),
            "text_indexed": self.text.lock().unwrap().len(),
            "graph_nodes": self.graph.lock().unwrap().len(),
            "tgraph_edges": self.tgraph.lock().unwrap().edges.len(),
            "entity_keys": self.entity.lock().unwrap().mappings.len(),
            "activation_tracked": self.activation.lock().unwrap().len(),
            "views": self.views.lock().unwrap().view_names(),
        })
    }

    pub fn verify(&self) -> Result<serde_json::Value, HeraclitusError> {
        let r = self.log.verify_durable()?;
        Ok(serde_json::json!({
            "segments": r.segments,
            "sealed": r.sealed,
            "records": r.records,
            "merkle_ok": r.merkle_ok,
            // Verdadeiro sempre que existe relatório: `Log::verify` devolve
            // `Err` assim que uma raiz Merkle não bate. Explicitar isto poupa
            // ao cliente ter de o inferir da AUSÊNCIA de um campo de erro —
            // inferência que já levou um painel a escrever "íntegro" em cima
            // de uma corrupção detectada.
            "ok": true,
            // Selados sem raiz gravada no rodapé: não são falha, são
            // não-verificáveis. Sem este número, "3 de 5" não se explica.
            "sem_raiz": r.sealed.saturating_sub(r.merkle_ok)
        }))
    }

    /// `heraclitus_state()` — introspecção operacional num só JSON: head,
    /// segmentos (id/versão/selado/raiz Merkle) e watermarks das views. O que
    /// um operador precisa para diagnosticar um boot/replay sem ir a logs.
    pub fn state(&self) -> serde_json::Value {
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let sealed = self.log.sealed_segments();
        let segments: Vec<serde_json::Value> = sealed
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
            .collect();
        let views = self.views.lock().unwrap();
        let mut out = serde_json::json!({
            "head_lsn": self.log.head(),
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
        match self.log.verify_segment(id)? {
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
            let idx = self.text.lock().unwrap();
            idx.search(text, heraclitus_retrieval::RECALL_N)
                .into_iter()
                .map(|h| (h.id, h.lsn, h.score))
                .collect()
        };
        let act_hits: Vec<_> = {
            let act = self.activation.lock().unwrap();
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
                    .lock()
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
        Ok(self.tgraph.lock().unwrap().clone())
    }

    fn scan_range(&self, from: Lsn, to: Lsn) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        // Windowed + capped: segment pruning makes a time slice cheap, and the
        // QUERY_SCAN_CAP keeps a broad scan from exhausting memory (§query guard).
        self.log
            .scan_capped(from, to, heraclitus_query::backend::QUERY_SCAN_CAP)
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
            let idx = self.attr.lock().unwrap();
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
            let idx = self.attr.lock().unwrap();
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
        let hits = self.vector.lock().unwrap().search(&dims, fetch, 128, None);
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
                .lock()
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
        let g = self.tgraph.lock().unwrap();
        Ok(neighbors_of(&g, node, etype, as_of, min_confidence))
    }

    fn traverse(
        &self,
        start: &str,
        max_depth: usize,
        as_of: Option<Lsn>,
        min_confidence: f32,
    ) -> Result<Vec<(String, usize)>, HeraclitusError> {
        let g = self.tgraph.lock().unwrap();
        Ok(traverse_of(&g, start, max_depth, as_of, min_confidence))
    }

    fn match_edges(
        &self,
        src: Option<&str>,
        etype: Option<&str>,
        dst: Option<&str>,
        as_of: Option<Lsn>,
    ) -> Result<Vec<EdgeRow>, HeraclitusError> {
        let g = self.tgraph.lock().unwrap();
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
            &self.tgraph.lock().unwrap(),
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
        Ok(community_of(&self.tgraph.lock().unwrap(), node, as_of))
    }

    fn community_leiden(
        &self,
        node: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<CommunityResult>, HeraclitusError> {
        Ok(heraclitus_query::backend::community_leiden_of(
            &self.tgraph.lock().unwrap(),
            node,
            as_of,
        ))
    }

    fn node_metrics(
        &self,
        node: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<MetricsResult>, HeraclitusError> {
        Ok(node_metrics_of(&self.tgraph.lock().unwrap(), node, as_of))
    }

    fn resolve_entity(
        &self,
        key: &str,
        as_of: Option<Lsn>,
    ) -> Result<Option<String>, HeraclitusError> {
        let er = self.entity.lock().unwrap();
        Ok(resolve_of(&er, key, as_of))
    }

    fn entity_cluster(
        &self,
        entity_id: &str,
        as_of: Option<Lsn>,
    ) -> Result<Vec<String>, HeraclitusError> {
        let er = self.entity.lock().unwrap();
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
            let h = engine.graph.lock().unwrap().state_hash();
            h
        };
        // Reopen: o boot-replay tem de produzir o MESMO state_hash do grafo.
        let engine2 = engine_in(dir.path());
        let reopened_hash = engine2.graph.lock().unwrap().state_hash();
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
        let live = engine.tgraph.lock().unwrap();
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
            let h = engine.tgraph.lock().unwrap().state_hash();
            h
        };
        let engine_b = engine_in(dir.path());
        let hash_b = engine_b.tgraph.lock().unwrap().state_hash();
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
        let live = engine.tgraph.lock().unwrap();
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
        let live = engine.entity.lock().unwrap();
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
        let live = engine.tgraph.lock().unwrap();
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
}
