//! SPEC-015/021 — wiring do consenso Raft no servidor (feature `replication`).
//!
//! Liga um nó de cluster (**raft-log durável** + **transporte TCP**) sobre o log
//! do [`Engine`], com um hook que indexa cada episódio aplicado nas views locais
//! (read-your-writes preservado). Com replicação ativa, `Engine::append` deixa de
//! escrever direto no log e passa a submeter ao **líder** do raft; o líder aplica
//! via a state machine, que grava no log de CADA nó e chama de volta
//! `index_applied`.
//!
//! Nota de escopo: `ReplicationHandle::append` é síncrono (o contrato do
//! `Engine`) e BLOQUEIA a thread a aguardar o commit por quórum — tal como o
//! `append` já bloqueia no `fsync`. Por isso o handler gRPC de escrita já corre
//! `Engine::append` dentro de um `spawn_blocking`, que evita estagnar o reactor
//! do tokio sob escrita concorrente (ver `grpc::Service::append`).

use crate::engine::{Engine, ReplRouter};
use heraclitus_core::{Episode, HeraclitusError, Lsn, RaftTransport, ReplicationConfig};
use heraclitus_raft::consensus::{
    self, episode_bytes, ApplyHook, EpisodeStateMachine, HeraclitusRaft, NodeId, SubmitOutcome,
};
use heraclitus_raft::durable::FileRaftLog;
use heraclitus_raft::grpc::spawn_node_grpc_on;
use heraclitus_raft::net::spawn_node_tcp_on;
use std::sync::{Arc, Weak};
use std::time::Duration;

/// Escrita a submeter: episódio + canal (std) de resposta, para o `append`
/// síncrono do `Engine` bloquear até o consenso confirmar ou rejeitar.
type Submit = (Episode, std::sync::mpsc::Sender<Result<Lsn, HeraclitusError>>);

/// Handle de replicação instalado no `Engine` via `set_replication`.
pub struct ReplicationHandle {
    submit: tokio::sync::mpsc::UnboundedSender<Submit>,
    raft: HeraclitusRaft,
    node_id: NodeId,
}

impl ReplRouter for ReplicationHandle {
    fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.submit
            .send((episode, tx))
            .map_err(|_| HeraclitusError::StorageEngine("replicação encerrada".into()))?;
        // Bloqueia (como o fsync do append já bloqueia); o loop assíncrono
        // responde quando o raft comita por quórum ou rejeita.
        rx.recv()
            .map_err(|_| HeraclitusError::StorageEngine("replicação sem resposta".into()))?
    }

    fn status(&self) -> serde_json::Value {
        let (leader, role) = consensus::node_status(&self.raft);
        serde_json::json!({
            "replication": true,
            "node_id": self.node_id,
            "role": role,
            "leader": leader,
        })
    }
}

/// Tasks do cluster a abortar no shutdown (servidor TCP de raft + loop de submissão).
pub struct ClusterTasks {
    server: tokio::task::JoinHandle<()>,
    submit: tokio::task::JoinHandle<()>,
}

impl ClusterTasks {
    pub fn abort(&self) {
        self.server.abort();
        self.submit.abort();
    }
}

/// Arranca o nó de cluster sobre o `Engine` e devolve o handle (a instalar via
/// `Engine::set_replication`) mais as tasks a encerrar no fim.
pub async fn spawn(
    engine: &Arc<Engine>,
    cfg: &ReplicationConfig,
    data_dir: &std::path::Path,
) -> Result<(Arc<ReplicationHandle>, ClusterTasks), HeraclitusError> {
    let raft_dir = default_dir(&cfg.raft_dir, data_dir, "raft");
    let sm_dir = default_dir(&cfg.sm_dir, data_dir, "raft-sm");

    // Hook: cada episódio aplicado é indexado nas views DESTE nó. `Weak` para não
    // criar ciclo (Engine → handle → raft → sm → hook → Engine).
    let weak: Weak<Engine> = Arc::downgrade(engine);
    let hook: ApplyHook = Arc::new(move |lsn: Lsn, ep: &Episode| {
        if let Some(e) = weak.upgrade() {
            e.index_applied(lsn, ep);
        }
    });

    let store = FileRaftLog::open(&raft_dir)
        .map_err(|e| HeraclitusError::StorageEngine(format!("raft-log durável: {e}")))?;
    let sm = EpisodeStateMachine::open_durable(engine.log.clone(), &sm_dir)
        .map_err(|e| HeraclitusError::StorageEngine(format!("raft sm durável: {e}")))?
        .with_apply_hook(hook);

    // Transporte: TCP (referência) ou gRPC/tonic (superfície unificada do
    // servidor). Ambos correm os mesmos RPCs de raft sobre os mesmos tipos serde.
    let (node, server_handle) = match cfg.transport {
        RaftTransport::Tcp => {
            let t = spawn_node_tcp_on(
                cfg.node_id,
                engine.log.clone(),
                consensus::production_config(),
                &cfg.raft_addr,
                store,
                sm,
            )
            .await
            .map_err(|e| HeraclitusError::Config(format!("nó raft TCP em {}: {e}", cfg.raft_addr)))?;
            (t.node, t.server)
        }
        RaftTransport::Grpc => {
            let g = spawn_node_grpc_on(
                cfg.node_id,
                engine.log.clone(),
                consensus::production_config(),
                &cfg.raft_addr,
                store,
                sm,
            )
            .await
            .map_err(|e| HeraclitusError::Config(format!("nó raft gRPC em {}: {e}", cfg.raft_addr)))?;
            (g.node, g.server)
        }
    };

    // Bootstrap: a semente inicializa o cluster, com retry (os pares podem ainda
    // estar a subir). Exatamente UM nó deve ter `bootstrap = true`.
    if cfg.bootstrap {
        let raft = node.raft.clone();
        let peers = cfg.peers.clone();
        tokio::spawn(async move {
            for _ in 0..40 {
                if consensus::initialize_cluster(&raft, &peers).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            tracing::warn!("bootstrap do cluster raft não concluiu (pares inacessíveis?)");
        });
    }

    // Loop de submissão: recebe escritas do Engine (síncrono) e fá-las passar pelo
    // raft (assíncrono), respondendo pelo canal std. Uma task por escrita ⇒
    // submissões concorrentes não se serializam entre si.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Submit>();
    let raft_for_loop = node.raft.clone();
    let submit = tokio::spawn(async move {
        while let Some((ep, reply)) = rx.recv().await {
            let raft = raft_for_loop.clone();
            tokio::spawn(async move {
                let res = match consensus::submit_episode(&raft, episode_bytes(&ep)).await {
                    Ok(SubmitOutcome::Applied(lsn)) => Ok(lsn),
                    Ok(SubmitOutcome::NotLeader(leader)) => Err(HeraclitusError::StorageEngine(
                        format!("não sou o líder; encaminhar a escrita para o nó {leader:?}"),
                    )),
                    Err(e) => Err(HeraclitusError::StorageEngine(format!("consenso: {e}"))),
                };
                let _ = reply.send(res);
            });
        }
    });

    let handle = Arc::new(ReplicationHandle {
        submit: tx,
        raft: node.raft.clone(),
        node_id: cfg.node_id,
    });
    Ok((
        handle,
        ClusterTasks {
            server: server_handle,
            submit,
        },
    ))
}

fn default_dir(
    configured: &std::path::Path,
    data_dir: &std::path::Path,
    name: &str,
) -> std::path::PathBuf {
    if configured.as_os_str().is_empty() {
        data_dir.join(name)
    } else {
        configured.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{EventKind, FsyncPolicy, HeraclitusConfig};
    use std::collections::BTreeMap;

    /// Um endereço TCP livre em `127.0.0.1` (bind efémero + release). Damos os
    /// endereços à membership ANTES de os nós religarem — a janela é mínima em
    /// localhost.
    fn free_addr() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    }

    fn obs(agent: &str, body: &str) -> Episode {
        Episode::new(agent, EventKind::Observation, body.as_bytes().to_vec())
    }

    /// Escreve pelo cluster: tenta cada nó até o LÍDER aceitar (os não-líderes
    /// devolvem "não sou o líder"). `append` bloqueia ⇒ `spawn_blocking`.
    async fn write_via_cluster(engines: &[Arc<Engine>], ep: Episode) -> Lsn {
        for _ in 0..80 {
            for e in engines {
                let (e, ep) = (e.clone(), ep.clone());
                if let Ok(lsn) = tokio::task::spawn_blocking(move || e.append(ep)).await.unwrap() {
                    return lsn;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("nenhum líder aceitou a escrita");
    }

    /// Escreve H-VM pelo cluster: tenta cada nó até o líder aceitar (num
    /// não-líder, `hvm_upsert` → `Engine::append` → erro com hint do líder).
    async fn hvm_write_via_cluster(engines: &[Arc<Engine>], key: Vec<u8>, val: Vec<u8>) {
        for _ in 0..80 {
            for e in engines {
                let (e, k, v) = (e.clone(), key.clone(), val.clone());
                if tokio::task::spawn_blocking(move || e.hvm_upsert(k, v)).await.unwrap().is_ok() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("nenhum líder aceitou a escrita H-VM");
    }

    /// Follow-on do routing do H-VM pelo consenso: as escritas H-VM passam agora
    /// pelo `Engine::append` do líder e **replicam** — o `hvm_state` fica idêntico
    /// nos 3 nós (ledger soberano replicado). E os frames `hvm_isa`, excluídos dos
    /// índices, NÃO divergem o `state_hash` do grafo (idêntico em todos os nós).
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn three_server_cluster_replicates_hvm_writes() {
        let addrs: Vec<String> = (0..3).map(|_| free_addr()).collect();
        let peers: BTreeMap<u64, String> =
            (0..3).map(|i| (i as u64, addrs[i].clone())).collect();

        let mut engines: Vec<Arc<Engine>> = Vec::new();
        let mut tasks: Vec<ClusterTasks> = Vec::new();
        let mut dirs = Vec::new();
        for id in 0..3u64 {
            let dir = tempfile::tempdir().unwrap();
            let cfg = HeraclitusConfig {
                data_dir: dir.path().to_path_buf(),
                fsync: FsyncPolicy::Always,
                replication: Some(ReplicationConfig {
                    node_id: id,
                    raft_addr: addrs[id as usize].clone(),
                    peers: peers.clone(),
                    bootstrap: id == 0,
                    raft_dir: dir.path().join("raft"),
                    sm_dir: dir.path().join("raft-sm"),
                    transport: RaftTransport::Tcp,
                }),
                ..Default::default()
            };
            let engine = Arc::new(Engine::open(&cfg).unwrap());
            let (handle, t) = spawn(&engine, cfg.replication.as_ref().unwrap(), &cfg.data_dir)
                .await
                .unwrap();
            engine.set_replication(handle);
            engines.push(engine);
            tasks.push(t);
            dirs.push(dir);
        }

        // 1 escrita normal (vai para o grafo) + 5 upserts H-VM (ficam fora do grafo).
        write_via_cluster(&engines, obs("alice", "facto")).await;
        for i in 0..5 {
            hvm_write_via_cluster(&engines, format!("k{i}").into_bytes(), format!("v{i}").into_bytes())
                .await;
        }

        // Convergência: log head = 6 e ledger H-VM = 5 em TODOS os nós.
        for _ in 0..60 {
            if engines.iter().all(|e| {
                e.log.head() == 6 && e.hvm_state().map(|s| s.memory_layers.len()).unwrap_or(0) == 5
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for (i, e) in engines.iter().enumerate() {
            let st = e.hvm_state().unwrap();
            assert_eq!(st.memory_layers.len(), 5, "nó {i} replicou o ledger H-VM");
            assert_eq!(
                st.memory_layers.get(b"k4".as_slice()),
                Some(&b"v4".to_vec()),
                "nó {i} tem k4=v4"
            );
        }
        // Consenso: o `state_hash` do grafo é IDÊNTICO nos 3 nós — os frames
        // hvm_isa excluídos consistentemente ⇒ só o episódio normal conta.
        let h0 = engines[0].graph_state_hash();
        for (i, e) in engines.iter().enumerate() {
            assert_eq!(e.graph_state_hash(), h0, "nó {i}: state_hash do grafo diverge");
        }

        for t in tasks {
            t.abort();
        }
    }

    /// **O milestone**: 3 servidores in-process formam um cluster Raft real
    /// (transporte TCP), as escritas passam pelo `Engine::append` do líder, e os
    /// três nós **replicam o log E indexam** (uma query GQL devolve os dados em
    /// TODOS — read-your-writes preservado pelo hook de apply).
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn three_server_cluster_replicates_writes_and_indexes() {
        let addrs: Vec<String> = (0..3).map(|_| free_addr()).collect();
        let peers: BTreeMap<u64, String> =
            (0..3).map(|i| (i as u64, addrs[i].clone())).collect();

        let mut engines: Vec<Arc<Engine>> = Vec::new();
        let mut tasks: Vec<ClusterTasks> = Vec::new();
        let mut dirs = Vec::new();
        for id in 0..3u64 {
            let dir = tempfile::tempdir().unwrap();
            let cfg = HeraclitusConfig {
                data_dir: dir.path().to_path_buf(),
                fsync: FsyncPolicy::Always,
                replication: Some(ReplicationConfig {
                    node_id: id,
                    raft_addr: addrs[id as usize].clone(),
                    peers: peers.clone(),
                    bootstrap: id == 0,
                    raft_dir: dir.path().join("raft"),
                    sm_dir: dir.path().join("raft-sm"),
                    transport: RaftTransport::Tcp,
                }),
                ..Default::default()
            };
            let engine = Arc::new(Engine::open(&cfg).unwrap());
            let (handle, t) = spawn(&engine, cfg.replication.as_ref().unwrap(), &cfg.data_dir)
                .await
                .unwrap();
            engine.set_replication(handle);
            engines.push(engine);
            tasks.push(t);
            dirs.push(dir);
        }

        // 8 escritas pelo líder (via o caminho de escrita real do servidor).
        for i in 0..8 {
            write_via_cluster(&engines, obs("alice", &format!("evento {i}"))).await;
        }

        // Espera os 3 nós convergirem ao head = 8 (replicação do log).
        for _ in 0..50 {
            if engines.iter().all(|e| e.log.head() == 8) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for (i, e) in engines.iter().enumerate() {
            assert_eq!(e.log.head(), 8, "nó {i} replicou os 8 episódios");
            // Indexação (read-your-writes): a query GQL — que usa as views/memtable
            // derivadas — devolve os 8 em CADA nó, prova de que o hook indexou.
            let v = heraclitus_query::execute("MATCH (n) RETURN n", e.as_ref()).unwrap();
            assert_eq!(v.as_array().unwrap().len(), 8, "nó {i} indexou (query devolve 8)");
            // Observabilidade: state() expõe o estado do cluster (papel/líder).
            let st = e.state();
            let rep = &st["replication"];
            assert_eq!(rep["node_id"].as_u64(), Some(i as u64), "state() traz o node_id");
            assert!(rep["leader"].is_number(), "state() traz o líder atual do cluster");
        }

        // Um não-líder recusa a escrita com um erro claro (não corrompe nada).
        let leader_idx = {
            let mut idx = 0;
            for (i, e) in engines.iter().enumerate() {
                if tokio::task::spawn_blocking({
                    let e = e.clone();
                    move || e.append(obs("bob", "probe"))
                })
                .await
                .unwrap()
                .is_ok()
                {
                    idx = i;
                    break;
                }
            }
            idx
        };
        let follower = engines.iter().enumerate().find(|(i, _)| *i != leader_idx).unwrap().1.clone();
        let err = tokio::task::spawn_blocking(move || follower.append(obs("bob", "no")))
            .await
            .unwrap()
            .unwrap_err();
        assert!(
            format!("{err}").contains("líder"),
            "um seguidor recusa a escrita com hint do líder: {err}"
        );

        for t in tasks {
            t.abort();
        }
    }

    /// Como o milestone acima, mas com **transporte gRPC** (`RaftTransport::Grpc`):
    /// 3 servidores formam o cluster pela superfície gRPC, replicam o log e
    /// indexam (query GQL devolve os dados em TODOS) — prova o wiring do toggle
    /// de transporte ponta-a-ponta pelo servidor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn three_server_cluster_over_grpc_replicates_and_indexes() {
        let addrs: Vec<String> = (0..3).map(|_| free_addr()).collect();
        let peers: BTreeMap<u64, String> =
            (0..3).map(|i| (i as u64, addrs[i].clone())).collect();

        let mut engines: Vec<Arc<Engine>> = Vec::new();
        let mut tasks: Vec<ClusterTasks> = Vec::new();
        let mut dirs = Vec::new();
        for id in 0..3u64 {
            let dir = tempfile::tempdir().unwrap();
            let cfg = HeraclitusConfig {
                data_dir: dir.path().to_path_buf(),
                fsync: FsyncPolicy::Always,
                replication: Some(ReplicationConfig {
                    node_id: id,
                    raft_addr: addrs[id as usize].clone(),
                    peers: peers.clone(),
                    bootstrap: id == 0,
                    raft_dir: dir.path().join("raft"),
                    sm_dir: dir.path().join("raft-sm"),
                    transport: RaftTransport::Grpc,
                }),
                ..Default::default()
            };
            let engine = Arc::new(Engine::open(&cfg).unwrap());
            let (handle, t) = spawn(&engine, cfg.replication.as_ref().unwrap(), &cfg.data_dir)
                .await
                .unwrap();
            engine.set_replication(handle);
            engines.push(engine);
            tasks.push(t);
            dirs.push(dir);
        }

        for i in 0..6 {
            write_via_cluster(&engines, obs("alice", &format!("grpc {i}"))).await;
        }

        for _ in 0..50 {
            if engines.iter().all(|e| e.log.head() == 6) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for (i, e) in engines.iter().enumerate() {
            assert_eq!(e.log.head(), 6, "nó {i} replicou por gRPC");
            let v = heraclitus_query::execute("MATCH (n) RETURN n", e.as_ref()).unwrap();
            assert_eq!(v.as_array().unwrap().len(), 6, "nó {i} indexou (gRPC)");
        }

        for t in tasks {
            t.abort();
        }
    }
}
