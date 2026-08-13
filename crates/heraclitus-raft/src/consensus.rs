//! SPEC-015/021 — consenso Raft real (openraft 0.9), atrás da feature
//! `replication`.
//!
//! (`result_large_err` é inerente ao `StorageError` do openraft — silenciado.)
#![allow(clippy::result_large_err)]
//!
//! O upgrade prometido pelo header deste crate: **eleição de líder, commit por
//! quórum e failover automático**, provados pelos testes de cluster in-process
//! no fundo deste ficheiro. A tese do SPEC-015 é preservada por construção:
//!
//! - **Só bytes de episódios viajam** (`AppData = Vec<u8>` — o bincode do
//!   `Episode`, exatamente o que o log grava em disco). Nenhuma view, matriz
//!   ou índice atravessa a rede.
//! - **Cada nó aplica ao seu próprio `heraclitus_log::Log`** via
//!   `append_replicated` (LSN denso local) e hidrata as suas views localmente
//!   — soberania local absoluta.
//! - **Ack só depois do quórum**: `client_write` devolve apenas quando a
//!   maioria persistiu; sem quórum não há ack (testado).
//!
//! Honestidade de escopo (o que isto ainda NÃO é):
//! - o *raft-log* pode ser em memória ([`MemRaftLog`], referência p/ testes) OU
//!   **durável em disco** ([`crate::durable::FileRaftLog`], com recuperação de
//!   restart provada — ver `durable_node_survives_restart_*`);
//! - o transporte pode ser o router in-process com links cortáveis
//!   ([`Router`], determinístico para testes de partição/failover) OU um
//!   **transporte de rede TCP real** ([`crate::net`], consenso sobre sockets —
//!   eleição, replicação e failover provados na rede);
//! - snapshots: a lógica (build/install de episódios crus, skip de prefixo
//!   idempotente) é testada por round-trip direto E pelo fluxo REAL do openraft
//!   (`lagging_follower_catches_up_via_install_snapshot`: o líder purga o log e
//!   um seguidor atrasado apanha via `install_snapshot`).

use heraclitus_core::Episode;
use heraclitus_log::Log;
use openraft::error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::storage::{LogFlushed, LogState, RaftLogStorage, RaftStateMachine, Snapshot};
use openraft::{
    StorageIOError,
    BasicNode, Entry, EntryPayload, LogId, RaftLogReader, RaftNetwork, RaftNetworkFactory,
    RaftSnapshotBuilder, SnapshotMeta, StorageError, StoredMembership, Vote,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::{Arc, Mutex};

const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();

openraft::declare_raft_types!(
    /// Config de tipos do cluster Heraclitus: a app data é o bincode cru do
    /// `Episode` (os mesmos bytes do log em disco) e a resposta é o LSN denso
    /// que o nó atribuiu ao aplicar.
    pub TypeConfig:
        D = Vec<u8>,
        R = u64,
);

pub type NodeId = <TypeConfig as openraft::RaftTypeConfig>::NodeId;
pub type HeraclitusRaft = openraft::Raft<TypeConfig>;

// ─────────────────────────────────────────────────────────────────────────
// Raft-log em memória (termos, votos, entradas ainda não aplicadas)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct MemLogInner {
    entries: BTreeMap<u64, Entry<TypeConfig>>,
    committed: Option<LogId<NodeId>>,
    vote: Option<Vote<NodeId>>,
    last_purged: Option<LogId<NodeId>>,
}

/// Armazenamento do raft-log. Deliberadamente em memória (v1): o estado
/// APLICADO é durável (vive no `heraclitus_log::Log` de cada nó); o raft-log
/// durável em disco é o próximo milestone.
#[derive(Debug, Clone, Default)]
pub struct MemRaftLog {
    inner: Arc<Mutex<MemLogInner>>,
}

impl RaftLogReader<TypeConfig> for MemRaftLog {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.entries.range(range).map(|(_, e)| e.clone()).collect())
    }
}

impl RaftLogStorage<TypeConfig> for MemRaftLog {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let inner = self.inner.lock().unwrap();
        let last = inner
            .entries
            .values()
            .next_back()
            .map(|e| e.log_id)
            .or(inner.last_purged);
        Ok(LogState {
            last_purged_log_id: inner.last_purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        self.inner.lock().unwrap().vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().unwrap().vote)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        self.inner.lock().unwrap().committed = committed;
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().unwrap().committed)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
    {
        {
            let mut inner = self.inner.lock().unwrap();
            for e in entries {
                inner.entries.insert(e.log_id.index, e);
            }
        }
        // Memória = "flushed" imediato. Quando o raft-log for para disco, o
        // callback só dispara depois do fsync — é ELE que gate o ack de quórum.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().unwrap();
        inner.entries.split_off(&log_id.index);
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().unwrap();
        inner.entries = inner.entries.split_off(&(log_id.index + 1));
        inner.last_purged = Some(log_id);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// State machine: aplicar = append_replicated no heraclitus-log local
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct SmState {
    applied: Option<LogId<NodeId>>,
    membership: StoredMembership<NodeId, BasicNode>,
    snapshot_idx: u64,
    /// Nº de entradas Normal já aplicadas (= episódios que DEVEM estar no log).
    /// Chave da recuperação de restart: se `log.head() > normals`, os episódios
    /// a mais foram aplicados num crash sem que o meta fosse gravado ⇒ o openraft
    /// vai re-aplicar essas entradas e nós saltamos o append (idempotência).
    normals: u64,
    /// Transiente: quantos re-appends de Normal saltar por já estarem em disco.
    skip_normals: u64,
    current_snapshot: Option<(SnapshotMeta<NodeId, BasicNode>, Vec<u8>)>,
}

/// Snapshot durável do estado da máquina (para recuperação de restart).
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct SmMeta {
    applied: Option<LogId<NodeId>>,
    membership: StoredMembership<NodeId, BasicNode>,
    snapshot_idx: u64,
    normals: u64,
}

/// A máquina de estados do consenso É o log de episódios local: aplicar uma
/// entrada Normal = decodificar o `Episode` e fazer `append_replicated` com o
/// próximo LSN denso. Entradas Blank/Membership não produzem episódios — por
/// isso os LSNs dos episódios ficam densos mesmo com ruído de eleição no meio.
///
/// Com `sm_dir = Some(_)` a máquina é DURÁVEL: grava `(applied, membership,
/// normals)` num sidecar a cada batch de apply e recupera-o no restart. O log de
/// episódios já é durável; este sidecar fecha a lacuna do `applied`/membership
/// para o nó reiniciar sem re-aplicar (duplicar) nem perder.
/// Callback chamado após CADA episódio ser aplicado ao log — e só em appends
/// genuínos, nunca nas re-aplicações idempotentes de restart (`skip_normals`).
/// Permite ao host (ex.: o `heraclitus-server`) indexar o episódio nas suas
/// views derivadas de forma SÍNCRONA com o apply, preservando read-your-writes.
pub type ApplyHook = Arc<dyn Fn(heraclitus_core::Lsn, &Episode) + Send + Sync>;

#[derive(Clone)]
pub struct EpisodeStateMachine {
    log: Arc<Log>,
    state: Arc<Mutex<SmState>>,
    sm_dir: Option<std::path::PathBuf>,
    on_apply: Option<ApplyHook>,
}

impl EpisodeStateMachine {
    /// Máquina em memória (sem durabilidade do `applied`/membership).
    pub fn new(log: Arc<Log>) -> Self {
        Self {
            log,
            state: Arc::new(Mutex::new(SmState::default())),
            sm_dir: None,
            on_apply: None,
        }
    }

    /// Regista um hook invocado após cada episódio aplicado (ver [`ApplyHook`]).
    pub fn with_apply_hook(mut self, hook: ApplyHook) -> Self {
        self.on_apply = Some(hook);
        self
    }

    /// Máquina DURÁVEL: recupera `(applied, membership, normals)` do sidecar em
    /// `sm_dir` e calcula `skip_normals = head_de_episódios − normals` (os
    /// episódios que ficaram em disco num crash antes de o meta ser gravado).
    pub fn open_durable(
        log: Arc<Log>,
        sm_dir: impl AsRef<std::path::Path>,
    ) -> Result<Self, StorageError<NodeId>> {
        let sm_dir = sm_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&sm_dir)
            .map_err(|e| StorageError::from(StorageIOError::read(Self::io_err(e))))?;
        let meta = Self::load_sm_meta(&sm_dir)?;
        // Os episódios já em disco além do que o meta registou = aplicados num
        // crash sem meta gravado; o openraft vai re-enviá-los e nós saltamos.
        let head = log.head();
        // INVARIANTE DE DURABILIDADE: o meta NUNCA pode estar à frente do log.
        // Sob `FsyncPolicy::GroupCommit` (o DEFAULT) um crash na janela pode
        // deixar `sm_meta` (fsynced) à frente de um episódio ainda não
        // group-committed. Antes isto era escondido por `saturating_sub` ⇒ os
        // episódios em falta nunca eram re-aplicados (divergência SILENCIOSA).
        // Falhar ALTO (como o caminho de meta-corrompido) é a postura segura.
        if head < meta.normals {
            return Err(StorageError::from(StorageIOError::read(Self::io_err(format!(
                "state-machine à frente do log (normals={} > head={}): crash na janela de fsync. \
                 Recupere de um snapshot, ou use FsyncPolicy::Always sob replicação.",
                meta.normals, head
            )))));
        }
        let skip_normals = head - meta.normals;
        Ok(Self {
            log,
            on_apply: None,
            state: Arc::new(Mutex::new(SmState {
                applied: meta.applied,
                membership: meta.membership,
                snapshot_idx: meta.snapshot_idx,
                normals: meta.normals,
                skip_normals,
                current_snapshot: None,
            })),
            sm_dir: Some(sm_dir),
        })
    }

    fn load_sm_meta(dir: &std::path::Path) -> Result<SmMeta, StorageError<NodeId>> {
        match std::fs::read(dir.join("sm_meta.bin")) {
            // Escrito atomicamente (tmp+rename) — nunca meio-escrito. Um decode
            // que falhe = corrupção real: FALHAR ALTO em vez de repor um
            // `applied`/membership vazio em silêncio (recuperação incorreta).
            Ok(bytes) => bincode::serde::decode_from_slice(&bytes, BINCODE_CFG)
                .map(|(m, _)| m)
                .map_err(|e| {
                    StorageError::from(StorageIOError::read(Self::io_err(format!(
                        "sm_meta.bin corrompido (recusa arrancar): {e}"
                    ))))
                }),
            Err(_) => Ok(SmMeta::default()), // primeiro arranque durável
        }
    }

    /// Persiste o meta da máquina de forma atómica (tmp+rename+fsync). Chamado
    /// no fim de cada batch de apply, DEPOIS de os episódios estarem em disco.
    fn persist_sm_meta(&self, st: &SmState) -> Result<(), StorageError<NodeId>> {
        let Some(dir) = &self.sm_dir else { return Ok(()) };
        let meta = SmMeta {
            applied: st.applied,
            membership: st.membership.clone(),
            snapshot_idx: st.snapshot_idx,
            normals: st.normals,
        };
        let bytes = bincode::serde::encode_to_vec(&meta, BINCODE_CFG)
            .map_err(|e| StorageError::from(StorageIOError::write(Self::io_err(e))))?;
        let tmp = dir.join("sm_meta.bin.tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| StorageError::from(StorageIOError::write(Self::io_err(e))))?;
            f.write_all(&bytes)
                .and_then(|_| f.sync_all())
                .map_err(|e| StorageError::from(StorageIOError::write(Self::io_err(e))))?;
        }
        std::fs::rename(&tmp, dir.join("sm_meta.bin"))
            .map_err(|e| StorageError::from(StorageIOError::write(Self::io_err(e))))?;
        // Torna o rename durável (a entrada de diretório) — mesma razão do
        // `FileRaftLog`: sem isto um crash pode reverter o `applied` recuperado.
        crate::durable::fsync_dir(dir);
        Ok(())
    }

    fn io_err(e: impl std::fmt::Display) -> openraft::AnyError {
        openraft::AnyError::error(e.to_string())
    }
}

impl RaftSnapshotBuilder<TypeConfig> for EpisodeStateMachine {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        // Um snapshot heraclitiano = os episódios crus [0, head) — a mesma
        // matéria que viaja na replicação normal; nada derivado.
        //
        // CORRETUDE (openraft corre build_snapshot SPAWNADO em paralelo com o
        // worker de `apply` — worker.rs: "the builder must hold a consistent
        // view or a lock that prevents writes"): seguramos `state` durante TODO
        // o build, e `apply` também o segura à volta do append+applied. Assim o
        // par (conjunto de episódios, last_log_id) é capturado ATÓMICO — sem
        // este lock, um apply intercalado geraria um snapshot rasgado (bytes com
        // N episódios mas meta a apontar N±1). Nenhum `.await` é retido sob o
        // guard, logo não há await-holding-lock nem deadlock.
        let mut st = self.state.lock().unwrap();
        // R22: scan JANELADO direto para o vec de payloads — o scan(0, MAX)
        // antigo materializava o log inteiro num Vec de Episodes ALÉM do vec de
        // payloads e dos bytes finais (~3× o log em RAM, sob o mutex). O
        // snapshot continua a ser todos os episódios por design; isto corta o
        // pico para ~2× sem mudar um byte do formato.
        let head = self.log.head();
        let mut payload: Vec<Vec<u8>> = Vec::new();
        let mut cur = 0u64;
        while cur < head {
            let batch = self
                .log
                .scan_capped(cur, head, 100_000)
                .map_err(|e| StorageError::from(StorageIOError::read(Self::io_err(e))))?;
            let Some(&(last, _)) = batch.last() else {
                break;
            };
            for (_, ep) in &batch {
                payload.push(
                    bincode::serde::encode_to_vec(ep, BINCODE_CFG).map_err(|e| {
                        StorageError::from(StorageIOError::read(Self::io_err(e)))
                    })?,
                );
            }
            cur = last + 1;
        }
        let bytes = bincode::serde::encode_to_vec(&payload, BINCODE_CFG)
            .map_err(|e| StorageError::from(StorageIOError::read(Self::io_err(e))))?;

        st.snapshot_idx += 1;
        let meta = SnapshotMeta {
            last_log_id: st.applied,
            last_membership: st.membership.clone(),
            snapshot_id: format!(
                "{}-{}",
                st.applied.map(|l| l.index).unwrap_or(0),
                st.snapshot_idx
            ),
        };
        st.current_snapshot = Some((meta.clone(), bytes.clone()));
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(bytes)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for EpisodeStateMachine {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StorageError<NodeId>>
    {
        let st = self.state.lock().unwrap();
        Ok((st.applied, st.membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<u64>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
    {
        let mut out = Vec::new();
        let mut st = self.state.lock().unwrap();
        // Segura `state` à volta de todo o batch (append_replicated + applied)
        // para que o build_snapshot concorrente (spawnado pelo openraft) nunca
        // veja um par (episódios, applied) rasgado. Corpo síncrono — nenhum
        // `.await` sob o guard.
        for entry in entries {
            let resp = match entry.payload {
                EntryPayload::Blank => u64::MAX,
                EntryPayload::Membership(ref m) => {
                    st.membership = StoredMembership::new(Some(entry.log_id), m.clone());
                    u64::MAX
                }
                EntryPayload::Normal(ref bytes) => {
                    st.normals += 1;
                    if st.skip_normals > 0 {
                        // Re-aplicação de um Normal cujo episódio JÁ está em disco
                        // (aplicado num crash antes de o meta ser gravado). Salta
                        // o append — idempotência que evita duplicar episódios.
                        st.skip_normals -= 1;
                        st.normals - 1 // o LSN denso que este episódio já tem
                    } else {
                        let (ep, _): (Episode, usize) =
                            bincode::serde::decode_from_slice(bytes, BINCODE_CFG).map_err(|e| {
                                StorageError::from(StorageIOError::apply(entry.log_id, Self::io_err(e)))
                            })?;
                        let lsn = self.log.head();
                        // Só clonamos quando há hook (o host quer indexar). O
                        // hook corre síncrono com o apply ⇒ read-your-writes.
                        if let Some(hook) = &self.on_apply {
                            self.log.append_replicated(lsn, ep.clone()).map_err(|e| {
                                StorageError::from(StorageIOError::apply(entry.log_id, Self::io_err(e)))
                            })?;
                            hook(lsn, &ep);
                        } else {
                            self.log.append_replicated(lsn, ep).map_err(|e| {
                                StorageError::from(StorageIOError::apply(entry.log_id, Self::io_err(e)))
                            })?;
                        }
                        lsn
                    }
                }
            };
            st.applied = Some(entry.log_id);
            out.push(resp);
        }
        // Os episódios já estão em disco (FsyncPolicy::Always); só AGORA gravamos
        // o meta ⇒ o meta nunca fica à frente dos episódios (o que perderia um
        // episódio no restart). Se um crash acontecer aqui, `skip_normals`
        // recupera no próximo open.
        self.persist_sm_meta(&st)?;
        Ok(out)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let bytes = snapshot.into_inner();
        let (payload, _): (Vec<Vec<u8>>, usize) =
            bincode::serde::decode_from_slice(&bytes, BINCODE_CFG)
                .map_err(|e| StorageError::from(StorageIOError::read(Self::io_err(e))))?;
        // O log local é append-only: instalar = acrescentar apenas os episódios
        // que ainda faltam (o prefixo já presente é, por determinismo, igual).
        for (i, ep_bytes) in payload.iter().enumerate() {
            let lsn = i as u64;
            if lsn < self.log.head() {
                continue;
            }
            let (ep, _): (Episode, usize) =
                bincode::serde::decode_from_slice(ep_bytes, BINCODE_CFG)
                    .map_err(|e| StorageError::from(StorageIOError::read(Self::io_err(e))))?;
            self.log
                .append_replicated(lsn, ep.clone())
                .map_err(|e| StorageError::from(StorageIOError::write(Self::io_err(e))))?;
            // CRÍTICO: um episódio entregue por snapshot também tem de disparar
            // o hook, senão o nó que apanha via install_snapshot fica com os
            // episódios no log mas SEM os indexar nas views (queries erradas até
            // ao próximo boot/rebuild). Só nos recém-acrescentados (lsn >= head),
            // nunca no prefixo já presente.
            if let Some(hook) = &self.on_apply {
                hook(lsn, &ep);
            }
        }
        let mut st = self.state.lock().unwrap();
        st.applied = meta.last_log_id;
        st.membership = meta.last_membership.clone();
        // Todos os episódios do log vêm de entradas Normal ⇒ `normals` = head; e
        // um snapshot recém-instalado não deixa nada por saltar.
        st.normals = self.log.head();
        st.skip_normals = 0;
        st.current_snapshot = Some((meta.clone(), bytes));
        self.persist_sm_meta(&st)?;
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        let st = self.state.lock().unwrap();
        Ok(st.current_snapshot.as_ref().map(|(meta, bytes)| Snapshot {
            meta: meta.clone(),
            snapshot: Box::new(Cursor::new(bytes.clone())),
        }))
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Router de rede in-process com links cortáveis (determinístico p/ testes)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct RouterInner {
    targets: BTreeMap<NodeId, HeraclitusRaft>,
    /// Links DIRECIONAIS cortados: (origem, destino).
    down: BTreeSet<(NodeId, NodeId)>,
}

/// Router in-process: cada RPC invoca diretamente o `Raft` do nó destino.
/// Cortar links simula partição/kill de líder de forma determinística — o
/// análogo do `sim.partition()` do turmoil, mas dentro do runtime do openraft.
#[derive(Clone, Default)]
pub struct Router {
    inner: Arc<Mutex<RouterInner>>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    /// Regista o handle do nó (depois do `Raft::new` — o router resolve o
    /// ovo-e-galinha entre factory e handles com mutabilidade interior).
    pub fn register(&self, id: NodeId, raft: HeraclitusRaft) {
        self.inner.lock().unwrap().targets.insert(id, raft);
    }

    /// Corta/repõe um link direcional.
    pub fn set_link(&self, from: NodeId, to: NodeId, up: bool) {
        let mut inner = self.inner.lock().unwrap();
        if up {
            inner.down.remove(&(from, to));
        } else {
            inner.down.insert((from, to));
        }
    }

    /// Isola um nó por completo (todos os links de/para ele) — "kill" lógico.
    pub fn isolate(&self, node: NodeId) {
        let mut inner = self.inner.lock().unwrap();
        let ids: Vec<NodeId> = inner.targets.keys().copied().collect();
        for other in ids {
            if other != node {
                inner.down.insert((node, other));
                inner.down.insert((other, node));
            }
        }
    }

    pub fn heal_all(&self) {
        self.inner.lock().unwrap().down.clear();
    }

    fn conn(&self, from: NodeId, to: NodeId) -> Result<HeraclitusRaft, Unreachable> {
        let inner = self.inner.lock().unwrap();
        if inner.down.contains(&(from, to)) {
            return Err(Unreachable::new(&std::io::Error::other(format!(
                "link {from}->{to} particionado"
            ))));
        }
        inner
            .targets
            .get(&to)
            .cloned()
            .ok_or_else(|| {
                Unreachable::new(&std::io::Error::other(format!("nó {to} não registado")))
            })
    }
}

/// Factory de rede de UM nó (sabe o seu próprio id de origem).
pub struct RouterNode {
    pub id: NodeId,
    pub router: Router,
}

impl RaftNetworkFactory<TypeConfig> for RouterNode {
    type Network = RouterConnection;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        RouterConnection {
            from: self.id,
            target,
            router: self.router.clone(),
        }
    }
}

pub struct RouterConnection {
    from: NodeId,
    target: NodeId,
    router: Router,
}

impl RaftNetwork<TypeConfig> for RouterConnection {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>>
    {
        let raft = self.router.conn(self.from, self.target).map_err(RPCError::Unreachable)?;
        raft.append_entries(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        let raft = self.router.conn(self.from, self.target).map_err(RPCError::Unreachable)?;
        raft.install_snapshot(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let raft = self.router.conn(self.from, self.target).map_err(RPCError::Unreachable)?;
        raft.vote(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Montagem de um nó de consenso
// ─────────────────────────────────────────────────────────────────────────

/// Um nó do cluster: o handle raft + o log de episódios local durável.
pub struct ConsensusNode {
    pub id: NodeId,
    pub raft: HeraclitusRaft,
    pub log: Arc<Log>,
}

/// Cria um nó de consenso a partir de um raft-log e uma máquina de estados já
/// construídos, e regista-o no router. É o construtor genérico que suporta
/// tanto o modo em-memória como o durável.
pub async fn spawn_node_with<LS>(
    id: NodeId,
    log: Arc<Log>,
    router: &Router,
    config: Arc<openraft::Config>,
    store: LS,
    sm: EpisodeStateMachine,
) -> Result<ConsensusNode, Box<dyn std::error::Error>>
where
    LS: RaftLogStorage<TypeConfig>,
{
    let raft = HeraclitusRaft::new(
        id,
        config,
        RouterNode {
            id,
            router: router.clone(),
        },
        store,
        sm,
    )
    .await?;
    router.register(id, raft.clone());
    Ok(ConsensusNode { id, raft, log })
}

/// Nó em-memória (raft-log volátil): o caminho de referência para testes de
/// consenso. Config de eleição curta para determinismo.
pub async fn spawn_node(
    id: NodeId,
    log: Arc<Log>,
    router: &Router,
    config: Arc<openraft::Config>,
) -> Result<ConsensusNode, Box<dyn std::error::Error>> {
    let sm = EpisodeStateMachine::new(log.clone());
    spawn_node_with(id, log, router, config, MemRaftLog::default(), sm).await
}

/// Nó **totalmente durável**: raft-log em [`crate::durable::FileRaftLog`]
/// (`raft_dir`) + `applied`/membership da máquina em `sm_dir`. Sobrevive a
/// restart sem re-aplicar (duplicar) nem perder — ver o teste `restart_*`.
pub async fn spawn_node_durable(
    id: NodeId,
    log: Arc<Log>,
    router: &Router,
    config: Arc<openraft::Config>,
    raft_dir: impl AsRef<std::path::Path>,
    sm_dir: impl AsRef<std::path::Path>,
) -> Result<ConsensusNode, Box<dyn std::error::Error>> {
    let store = crate::durable::FileRaftLog::open(raft_dir)?;
    let sm = EpisodeStateMachine::open_durable(log.clone(), sm_dir)?;
    spawn_node_with(id, log, router, config, store, sm).await
}

/// Serializa um episódio para o formato que viaja no consenso (o mesmo bincode
/// do disco — a rede transporta apenas bytes do log, SPEC-015).
pub fn episode_bytes(ep: &Episode) -> Vec<u8> {
    bincode::serde::encode_to_vec(ep, BINCODE_CFG).expect("Episode é sempre serializável")
}

// ── API de alto nível para hosts (ex.: heraclitus-server) ────────────────────
// Encapsula o openraft para que o host não precise de o importar.

/// Config de produção do cluster (heartbeat/eleição sensatos).
pub fn production_config() -> Arc<openraft::Config> {
    Arc::new(
        openraft::Config {
            heartbeat_interval: 250,
            election_timeout_min: 750,
            election_timeout_max: 1500,
            ..Default::default()
        }
        .validate()
        .expect("config de raft válida"),
    )
}

/// Resultado de submeter uma escrita ao cluster.
pub enum SubmitOutcome {
    /// Comitado por quórum e aplicado localmente; LSN denso deste nó.
    Applied(heraclitus_core::Lsn),
    /// Este nó não é o líder — escrever no líder indicado (se conhecido).
    NotLeader(Option<NodeId>),
}

/// Submete um episódio (já serializado) ao líder do raft. Traduz o
/// `ForwardToLeader` do openraft num `NotLeader` limpo; outros erros → `Err`.
pub async fn submit_episode(
    raft: &HeraclitusRaft,
    bytes: Vec<u8>,
) -> Result<SubmitOutcome, String> {
    use openraft::error::ClientWriteError;
    match raft.client_write(bytes).await {
        Ok(resp) => Ok(SubmitOutcome::Applied(resp.data)),
        Err(RaftError::APIError(ClientWriteError::ForwardToLeader(f))) => {
            Ok(SubmitOutcome::NotLeader(f.leader_id))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Inicializa o cluster (nó semente) a partir de um mapa `node_id -> endereço`.
pub async fn initialize_cluster(
    raft: &HeraclitusRaft,
    members: &BTreeMap<NodeId, String>,
) -> Result<(), String> {
    let m: BTreeMap<NodeId, BasicNode> = members
        .iter()
        .map(|(id, addr)| (*id, BasicNode::new(addr)))
        .collect();
    raft.initialize(m).await.map_err(|e| e.to_string())
}

/// Estado resumido do nó: `(líder atual, papel textual)`.
pub fn node_status(raft: &HeraclitusRaft) -> (Option<NodeId>, String) {
    let m = raft.metrics().borrow().clone();
    (m.current_leader, format!("{:?}", m.state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs_equivalent;
    use heraclitus_core::{EventKind, FsyncPolicy};
    use std::time::Duration;

    fn test_config() -> Arc<openraft::Config> {
        cfg_with(|_| {})
    }

    /// Config base (eleição curta p/ determinismo) com um ajuste opcional.
    fn cfg_with(tweak: impl FnOnce(&mut openraft::Config)) -> Arc<openraft::Config> {
        let mut c = openraft::Config {
            heartbeat_interval: 50,
            election_timeout_min: 150,
            election_timeout_max: 300,
            ..Default::default()
        };
        tweak(&mut c);
        Arc::new(c.validate().unwrap())
    }

    fn ep(i: u64) -> Episode {
        Episode::new("cluster", EventKind::Observation, format!("acked-{i}").into_bytes())
    }

    async fn three_nodes() -> (Vec<ConsensusNode>, Router, Vec<tempfile::TempDir>) {
        three_nodes_cfg(test_config()).await
    }

    async fn three_nodes_cfg(
        cfg: Arc<openraft::Config>,
    ) -> (Vec<ConsensusNode>, Router, Vec<tempfile::TempDir>) {
        let router = Router::new();
        let mut nodes = Vec::new();
        let mut dirs = Vec::new();
        for id in 0..3u64 {
            let dir = tempfile::tempdir().unwrap();
            let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
            nodes.push(spawn_node(id, log, &router, cfg.clone()).await.unwrap());
            dirs.push(dir);
        }
        let members: BTreeMap<NodeId, BasicNode> =
            (0..3).map(|i| (i, BasicNode::new(format!("node-{i}")))).collect();
        nodes[0].raft.initialize(members).await.unwrap();
        (nodes, router, dirs)
    }

    /// Espera até haver líder e devolve-o. `Wait::metrics` devolve o snapshot de
    /// métricas que satisfez o predicado, logo `current_leader` é sempre `Some`.
    async fn wait_leader(nodes: &[ConsensusNode]) -> NodeId {
        nodes[0]
            .raft
            .wait(Some(Duration::from_secs(10)))
            .metrics(|m| m.current_leader.is_some(), "há líder eleito")
            .await
            .expect("nenhum líder eleito em 10s")
            .current_leader
            .unwrap()
    }

    /// Espera por um líder DIFERENTE de `old`, observado por um nó que não é o
    /// `old` (o `old` pode estar isolado). Prova de failover.
    async fn wait_new_leader(nodes: &[ConsensusNode], old: NodeId) -> NodeId {
        let survivor = nodes.iter().find(|n| n.id != old).unwrap();
        survivor
            .raft
            .wait(Some(Duration::from_secs(10)))
            .metrics(
                |m| matches!(m.current_leader, Some(l) if l != old),
                "novo líder ≠ antigo",
            )
            .await
            .expect("nenhum novo líder em 10s")
            .current_leader
            .unwrap()
    }

    /// Escreve resolvendo o líder atual, com retry tolerante a `ForwardToLeader`
    /// (uma re-eleição espontânea entre resolver o líder e escrever não deve
    /// fazer o teste flakear). Devolve `(lsn_denso, raft_index)` do write acked.
    async fn write_to_leader(nodes: &[ConsensusNode], data: Vec<u8>) -> (u64, u64) {
        for _ in 0..40 {
            let leader = wait_leader(nodes).await;
            match nodes[leader as usize].raft.client_write(data.clone()).await {
                Ok(resp) => return (resp.data, resp.log_id.index),
                Err(_) => tokio::time::sleep(Duration::from_millis(30)).await,
            }
        }
        panic!("write não aceite após retries");
    }

    /// Espera que todos os nós apliquem pelo menos até `idx` (o índice raft do
    /// último write ACKED — vindo da resposta, nunca das metrics assíncronas).
    async fn wait_all_applied(nodes: &[ConsensusNode], idx: u64) {
        for n in nodes {
            n.raft
                .wait(Some(Duration::from_secs(10)))
                .applied_index_at_least(Some(idx), "todos aplicam")
                .await
                .unwrap();
        }
    }

    /// O gate básico do consenso — e a tese SPEC-015 completa: 3 nós elegem um
    /// líder, N writes acked por quórum aplicam-se a TODOS os logs de episódios
    /// com LSNs densos, os logs são byte-equivalentes, e as views derivadas
    /// (GraphIndex) hidratadas LOCALMENTE em cada nó têm `state_hash`
    /// bit-idêntico — só bytes do log viajaram, nunca uma view.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_elects_commits_and_applies_identically() {
        let (nodes, _router, _dirs) = three_nodes().await;
        wait_leader(&nodes).await;

        // Um DAG causal: cada episódio referencia os 1-2 anteriores.
        let mut prev: Vec<heraclitus_core::EventId> = Vec::new();
        let mut last_index = 0u64;
        for i in 0..30 {
            let mut e = ep(i);
            if let Some(&p) = prev.last() {
                e.parents.push(p);
            }
            if prev.len() >= 2 {
                e.parents.push(prev[prev.len() - 2]);
            }
            prev.push(e.id);
            // A resposta traz o LSN denso local — denso apesar das entradas
            // Blank/Membership do raft não gerarem episódios. O helper tolera
            // uma re-eleição espontânea (ForwardToLeader) sem flakear.
            let (dense, idx) = write_to_leader(&nodes, episode_bytes(&e)).await;
            assert_eq!(dense, i, "LSN denso atribuído pela state machine");
            last_index = idx;
        }

        // Sincroniza pelo índice raft do último write ACKED (da resposta, não
        // das metrics assíncronas — usar metrics aqui era um flake real).
        wait_all_applied(&nodes, last_index).await;

        for n in &nodes {
            assert_eq!(n.log.head(), 30, "nó {} tem os 30 episódios", n.id);
        }
        assert!(logs_equivalent(&nodes[0].log, &nodes[1].log).unwrap());
        assert!(logs_equivalent(&nodes[1].log, &nodes[2].log).unwrap());

        // SPEC-021 amarrado ao consenso: cada nó hidrata a SUA view de grafo do
        // SEU log local; os três `state_hash` têm de ser bit-idênticos.
        use heraclitus_index_graph::GraphIndex;
        use heraclitus_views::View;
        let hash_of = |log: &Log| {
            let mut g = GraphIndex::new();
            for (lsn, e) in log.scan(0, u64::MAX).unwrap() {
                g.apply(lsn, &e);
            }
            g.state_hash()
        };
        let (h0, h1, h2) = (hash_of(&nodes[0].log), hash_of(&nodes[1].log), hash_of(&nodes[2].log));
        assert_eq!(h0, h1, "view derivada do nó 1 ≡ nó 0, bit a bit");
        assert_eq!(h1, h2, "view derivada do nó 2 ≡ nó 1, bit a bit");
    }

    /// THE failover gate (a promessa do header): o líder morre (isolado), a
    /// maioria elege OUTRO líder, os writes continuam, e depois do heal o
    /// antigo líder converge — zero writes acked perdidos.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn leader_kill_triggers_failover_and_heals_without_acked_loss() {
        let (nodes, router, _dirs) = three_nodes().await;
        let old_leader = wait_leader(&nodes).await;

        // 10 writes acked antes da morte do líder.
        let mut last_index = 0u64;
        for i in 0..10 {
            let (_d, idx) = write_to_leader(&nodes, episode_bytes(&ep(i))).await;
            last_index = idx;
        }
        wait_all_applied(&nodes, last_index).await; // cluster em sincronia total

        // "Kill": isolar o líder de todos (não recebe nem envia nada).
        router.isolate(old_leader);

        // A maioria sobrevivente (2/3) elege um novo líder — failover real.
        let new_leader = wait_new_leader(&nodes, old_leader).await;
        assert_ne!(new_leader, old_leader, "failover real: líder diferente");

        // O cluster continua vivo: mais 10 writes acked no novo líder.
        for i in 10..20 {
            let (_d, idx) = nodes[new_leader as usize]
                .raft
                .client_write(episode_bytes(&ep(i)))
                .await
                .map(|r| (r.data, r.log_id.index))
                .unwrap();
            last_index = idx;
        }

        // Heal: o antigo líder regressa como seguidor e converge ao índice do
        // último write ACKED (da resposta, não das metrics assíncronas).
        router.heal_all();
        wait_all_applied(&nodes, last_index).await;

        for n in &nodes {
            assert_eq!(n.log.head(), 20, "nó {}: zero acked perdidos", n.id);
        }
        assert!(logs_equivalent(&nodes[0].log, &nodes[1].log).unwrap());
        assert!(logs_equivalent(&nodes[1].log, &nodes[2].log).unwrap());
    }

    /// A prova de que o ack é REAL: um líder que fica em MINORIA (isolado dos
    /// outros dois, que retêm o quórum) NUNCA pode confirmar um write. Depois do
    /// heal ele reintegra-se como seguidor, o seu write não-comitado é
    /// descartado (nenhum episódio fantasma entra no log), e um write fresco
    /// pelo líder atual comita nos três — o cluster está inteiro outra vez.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn isolated_minority_leader_cannot_ack_and_rejoins_cleanly() {
        let (nodes, router, _dirs) = three_nodes().await;
        let leader_id = wait_leader(&nodes).await;

        // 5 writes acked pelo cluster inteiro (todos em sincronia).
        let mut last = 0u64;
        for i in 0..5 {
            let (_d, idx) = write_to_leader(&nodes, episode_bytes(&ep(i))).await;
            last = idx;
        }
        wait_all_applied(&nodes, last).await;

        // Isola o líder. Os dois seguidores mantêm quórum (2/3) e elegem um novo
        // líder entre si; o líder antigo passa a ser uma minoria de um.
        router.isolate(leader_id);
        let isolated = &nodes[leader_id as usize];
        let head_before = isolated.log.head();
        assert_eq!(head_before, 5);

        // Um write submetido à minoria isolada NUNCA alcança quórum ⇒ nunca é
        // acked. 2s é folgado vs o heartbeat de 50ms.
        let pending = tokio::time::timeout(
            Duration::from_secs(2),
            isolated.raft.client_write(episode_bytes(&ep(99))),
        )
        .await;
        assert!(
            !matches!(pending, Ok(Ok(_))),
            "a minoria isolada NUNCA pode confirmar um write"
        );
        assert_eq!(
            isolated.log.head(),
            head_before,
            "nada aplicado sem quórum — sem falso ack, sem estado fantasma"
        );

        // Heal: o líder antigo reintegra-se como seguidor. Um write fresco pelo
        // líder ATUAL tem de comitar nos três; o `ep(99)` não-comitado é
        // descartado e NÃO aparece no log de ninguém (head = 5 originais + 1).
        router.heal_all();
        let (_d, idx) = write_to_leader(&nodes, episode_bytes(&ep(5))).await;
        wait_all_applied(&nodes, idx).await;
        for n in &nodes {
            assert_eq!(
                n.log.head(),
                6,
                "nó {}: 5 originais + 1 pós-heal; o ep(99) fantasma não entrou",
                n.id
            );
        }
        assert!(logs_equivalent(&nodes[0].log, &nodes[1].log).unwrap());
        assert!(logs_equivalent(&nodes[1].log, &nodes[2].log).unwrap());
    }

    /// Contrato de redirecionamento: um write num NÃO-líder devolve
    /// `ForwardToLeader` com o hint do líder correto. É a base de que qualquer
    /// transporte real (o milestone gRPC) vai depender.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn write_to_follower_is_redirected_to_leader() {
        use openraft::error::ClientWriteError;
        let (nodes, _router, _dirs) = three_nodes().await;
        let leader_id = wait_leader(&nodes).await;
        // Garante que os seguidores já conhecem o líder atual.
        wait_all_applied(&nodes, 0).await;

        let follower = nodes.iter().find(|n| n.id != leader_id).unwrap();
        let err = follower
            .raft
            .client_write(episode_bytes(&ep(0)))
            .await
            .unwrap_err();
        match err {
            RaftError::APIError(ClientWriteError::ForwardToLeader(f)) => {
                assert_eq!(
                    f.leader_id,
                    Some(leader_id),
                    "redireciona para o líder correto"
                );
            }
            other => panic!("esperava ForwardToLeader, veio {other:?}"),
        }
    }

    /// Dois failovers consecutivos: isolar o 1.º líder, eleger o 2.º, curar,
    /// depois isolar o líder ATUAL e eleger o 3.º — o cluster mantém-se
    /// disponível e os três logs convergem. Cobre estado residual no router,
    /// termos/votos que têm de progredir à segunda, e um nó reintegrado a
    /// voltar a participar/vencer eleições.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_consecutive_failovers_keep_the_cluster_available() {
        let (nodes, router, _dirs) = three_nodes().await;
        let l1 = wait_leader(&nodes).await;
        let (_d, i0) = write_to_leader(&nodes, episode_bytes(&ep(0))).await;
        wait_all_applied(&nodes, i0).await;

        // 1.º failover.
        router.isolate(l1);
        let l2 = wait_new_leader(&nodes, l1).await;
        assert_ne!(l2, l1);
        router.heal_all(); // l1 reintegra-se como seguidor
        let (_d, i1) = write_to_leader(&nodes, episode_bytes(&ep(1))).await;
        wait_all_applied(&nodes, i1).await;

        // 2.º failover: isola o líder ATUAL (l2, ou um l1 re-eleito).
        let cur = wait_leader(&nodes).await;
        router.isolate(cur);
        let l3 = wait_new_leader(&nodes, cur).await;
        assert_ne!(l3, cur);
        router.heal_all();
        let (_d, i2) = write_to_leader(&nodes, episode_bytes(&ep(2))).await;
        wait_all_applied(&nodes, i2).await;

        for n in &nodes {
            assert_eq!(n.log.head(), 3, "nó {}: 3 writes através de 2 failovers", n.id);
        }
        assert!(logs_equivalent(&nodes[0].log, &nodes[1].log).unwrap());
        assert!(logs_equivalent(&nodes[1].log, &nodes[2].log).unwrap());
    }

    /// Snapshot round-trip DIRETO (determinístico, sem depender das heurísticas
    /// de disparo do openraft): build_snapshot num nó com 10 episódios →
    /// install_snapshot num nó vazio reconstrói o log byte-a-byte; reinstalar é
    /// idempotente (o skip de prefixo `lsn < head` funciona). Cobre o caminho
    /// que o header afirma que "funciona" e exercita o lock de consistência.
    #[tokio::test]
    async fn snapshot_build_and_install_reconstructs_episode_log() {
        use openraft::{CommittedLeaderId, LogId};

        let mk_entries = |n: u64| -> Vec<Entry<TypeConfig>> {
            (0..n)
                .map(|i| Entry {
                    log_id: LogId::new(CommittedLeaderId::new(1, 0), i + 1),
                    payload: EntryPayload::Normal(episode_bytes(&ep(i))),
                })
                .collect()
        };

        // Nó fonte: aplica 10 episódios e constrói um snapshot.
        let src_dir = tempfile::tempdir().unwrap();
        let src_log = Arc::new(Log::open(src_dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let mut src = EpisodeStateMachine::new(src_log.clone());
        src.apply(mk_entries(10)).await.unwrap();
        assert_eq!(src_log.head(), 10);
        let snap = src.get_snapshot_builder().await.build_snapshot().await.unwrap();
        assert_eq!(snap.meta.last_log_id.unwrap().index, 10, "meta consistente com o applied");

        // Nó destino vazio COM hook: o install_snapshot tem de disparar o hook
        // para cada episódio entregue — senão o nó apanharia o log mas não
        // indexaria as views (queries erradas). Contamos os disparos.
        use std::sync::atomic::{AtomicU64, Ordering};
        let hook_fires = Arc::new(AtomicU64::new(0));
        let hc = hook_fires.clone();
        let dst_dir = tempfile::tempdir().unwrap();
        let dst_log = Arc::new(Log::open(dst_dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let mut dst = EpisodeStateMachine::new(dst_log.clone())
            .with_apply_hook(Arc::new(move |_lsn, _ep| {
                hc.fetch_add(1, Ordering::SeqCst);
            }));
        dst.install_snapshot(&snap.meta, snap.snapshot).await.unwrap();
        assert_eq!(dst_log.head(), 10, "install reconstrói os 10 episódios");
        assert_eq!(hook_fires.load(Ordering::SeqCst), 10, "o hook indexa os 10 do snapshot");
        assert!(logs_equivalent(&src_log, &dst_log).unwrap());

        // Reinstalar é idempotente — o skip de prefixo não duplica NEM re-dispara
        // o hook para o prefixo já presente.
        let snap2 = src.get_snapshot_builder().await.build_snapshot().await.unwrap();
        dst.install_snapshot(&snap2.meta, snap2.snapshot).await.unwrap();
        assert_eq!(dst_log.head(), 10, "reinstalar não duplica episódios");
        assert_eq!(hook_fires.load(Ordering::SeqCst), 10, "prefixo já presente não re-indexa");
        assert!(logs_equivalent(&src_log, &dst_log).unwrap());
    }

    /// **Durabilidade ponta-a-ponta**: um nó totalmente durável (raft-log em
    /// `FileRaftLog` + `applied`/membership em sidecar) que reinicia recupera do
    /// disco — re-lidera com o voto durável, NÃO re-aplica (não duplica) os
    /// episódios já em disco, não perde nenhum, e continua a servir writes. É a
    /// prova de que o consenso sobrevive a um restart de processo.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn durable_node_survives_restart_without_dup_or_loss() {
        let root = tempfile::tempdir().unwrap();
        let log_dir = root.path().join("episodes");
        let raft_dir = root.path().join("raft");
        let sm_dir = root.path().join("sm");
        let cfg = test_config();

        // ── Vida 1: arranca, inicializa (cluster de 1), escreve 5 episódios. ──
        let last_index = {
            let router = Router::new();
            let log = Arc::new(Log::open(&log_dir, 1 << 20, FsyncPolicy::Always).unwrap());
            let node =
                spawn_node_durable(0, log.clone(), &router, cfg.clone(), &raft_dir, &sm_dir)
                    .await
                    .unwrap();
            node.raft
                .initialize(BTreeMap::from([(0u64, BasicNode::new("n0"))]))
                .await
                .unwrap();
            node.raft
                .wait(Some(Duration::from_secs(10)))
                .metrics(|m| m.current_leader == Some(0), "auto-eleição")
                .await
                .unwrap();
            let mut last = 0;
            for i in 0..5 {
                let r = node.raft.client_write(episode_bytes(&ep(i))).await.unwrap();
                assert_eq!(r.data, i, "LSN denso i");
                last = r.log_id.index;
            }
            assert_eq!(log.head(), 5);
            // Encerramento limpo + libertação de TODAS as referências ao Log
            // (para o reabrir na vida 2 sem conflito de ficheiro).
            node.raft.shutdown().await.unwrap();
            drop(node);
            drop(log);
            drop(router);
            last
        };

        // ── Vida 2: reabre do disco. Nada em memória sobreviveu. ──
        let router = Router::new();
        let log = Arc::new(Log::open(&log_dir, 1 << 20, FsyncPolicy::Always).unwrap());
        assert_eq!(log.head(), 5, "os 5 episódios estavam duráveis no log");
        let node = spawn_node_durable(0, log.clone(), &router, cfg.clone(), &raft_dir, &sm_dir)
            .await
            .unwrap();

        // Re-lidera usando o VOTO/termo durável e recupera o applied — sem
        // re-aplicar os 5 episódios que já estão em disco.
        node.raft
            .wait(Some(Duration::from_secs(10)))
            .metrics(|m| m.current_leader == Some(0), "re-eleição pós-restart")
            .await
            .unwrap();
        assert_eq!(log.head(), 5, "restart NÃO duplicou episódios");

        // Continua a servir: um novo write comita e a sequência de LSN densos
        // continua exatamente onde estava (5) — sem buraco, sem repetição.
        let r = node.raft.client_write(episode_bytes(&ep(5))).await.unwrap();
        assert!(r.log_id.index > last_index, "o raft-log avançou do ponto durável");
        assert_eq!(r.data, 5, "LSN denso continua a sequência (0..5)");
        assert_eq!(log.head(), 6, "5 recuperados + 1 novo");
    }

    /// O `on_apply` dispara para cada episódio aplicado no cluster (a base do
    /// wiring no servidor: indexar as views ao replicar), e SÓ para appends
    /// genuínos — as re-aplicações de restart não o re-disparam.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn apply_hook_fires_for_each_replicated_episode() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let seen = Arc::new(AtomicU64::new(0));
        let last_lsn = Arc::new(AtomicU64::new(u64::MAX));

        let router = Router::new();
        let cfg = test_config();
        let mut nodes = Vec::new();
        let mut dirs = Vec::new();
        for id in 0..3u64 {
            let dir = tempfile::tempdir().unwrap();
            let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
            // Cada nó tem o seu hook; contamos os do nó 0.
            let (seen_c, last_c) = (seen.clone(), last_lsn.clone());
            let sm = if id == 0 {
                EpisodeStateMachine::new(log.clone()).with_apply_hook(Arc::new(move |lsn, _ep| {
                    seen_c.fetch_add(1, Ordering::SeqCst);
                    last_c.store(lsn, Ordering::SeqCst);
                }))
            } else {
                EpisodeStateMachine::new(log.clone())
            };
            nodes.push(
                spawn_node_with(id, log, &router, cfg.clone(), MemRaftLog::default(), sm)
                    .await
                    .unwrap(),
            );
            dirs.push(dir);
        }
        let members: BTreeMap<NodeId, BasicNode> =
            (0..3).map(|i| (i, BasicNode::new(format!("n{i}")))).collect();
        nodes[0].raft.initialize(members).await.unwrap();
        let leader = wait_leader(&nodes).await;

        let mut last = 0u64;
        for i in 0..12 {
            let (_d, idx) = nodes[leader as usize]
                .raft
                .client_write(episode_bytes(&ep(i)))
                .await
                .map(|r| (r.data, r.log_id.index))
                .unwrap();
            last = idx;
        }
        wait_all_applied(&nodes, last).await;

        // O nó 0 aplicou os 12 episódios ⇒ 12 disparos do hook, último LSN = 11.
        assert_eq!(seen.load(Ordering::SeqCst), 12, "um disparo por episódio");
        assert_eq!(last_lsn.load(Ordering::SeqCst), 11, "LSN denso do último");
    }

    /// **Transferência de snapshot pelo openraft real** (fecha a última lacuna do
    /// header): um seguidor fica tão atrasado que o líder já PURGOU do seu
    /// raft-log as entradas que ele precisa ⇒ o openraft envia-lhe um
    /// `install_snapshot` em vez de `append_entries`. O seguidor reconstrói o log
    /// de episódios do snapshot e converge — o `install_snapshot` da
    /// `EpisodeStateMachine` corre agora no fluxo real, não só em round-trip.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lagging_follower_catches_up_via_install_snapshot() {
        // `max_in_snapshot_log_to_keep = 0` ⇒ o purge pode remover tudo até ao
        // ponto do snapshot, forçando o caminho de snapshot para quem ficar atrás.
        let cfg = cfg_with(|c| c.max_in_snapshot_log_to_keep = 0);
        let (nodes, router, _dirs) = three_nodes_cfg(cfg).await;
        let leader_id = wait_leader(&nodes).await;
        let follower_id = (0..3).find(|&i| i != leader_id).unwrap();

        // Isola o seguidor-cobaia; o líder + o outro seguidor mantêm quórum.
        router.set_link(leader_id, follower_id, false);
        router.set_link(follower_id, leader_id, false);

        // 25 writes acked SEM o seguidor isolado (quórum 2/3).
        let mut last = 0u64;
        for i in 0..25 {
            let (_d, idx) = nodes[leader_id as usize]
                .raft
                .client_write(episode_bytes(&ep(i)))
                .await
                .map(|r| (r.data, r.log_id.index))
                .unwrap();
            last = idx;
        }

        // Força um snapshot no líder e purga o raft-log até esse ponto: as
        // entradas que o seguidor atrasado precisa DEIXAM de existir como log.
        nodes[leader_id as usize].raft.trigger().snapshot().await.unwrap();
        nodes[leader_id as usize]
            .raft
            .wait(Some(Duration::from_secs(10)))
            .metrics(
                |m| m.snapshot.map(|s| s.index >= last).unwrap_or(false),
                "líder construiu snapshot",
            )
            .await
            .unwrap();
        nodes[leader_id as usize].raft.trigger().purge_log(last).await.unwrap();

        // Cura o link: o seguidor está a ~0, mas o log do líder já não tem as
        // entradas antigas ⇒ o openraft manda-lhe um snapshot.
        router.set_link(leader_id, follower_id, true);
        router.set_link(follower_id, leader_id, true);

        // O seguidor recebe e instala o snapshot (metrics.snapshot passa a Some)
        // e converge ao head do líder.
        nodes[follower_id as usize]
            .raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(
                |m| m.snapshot.map(|s| s.index >= last).unwrap_or(false),
                "seguidor instalou o snapshot recebido",
            )
            .await
            .unwrap();

        assert_eq!(
            nodes[follower_id as usize].log.head(),
            25,
            "o seguidor reconstruiu os 25 episódios via install_snapshot"
        );
        assert!(logs_equivalent(
            &nodes[leader_id as usize].log,
            &nodes[follower_id as usize].log
        )
        .unwrap());
    }
}
