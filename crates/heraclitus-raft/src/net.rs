//! SPEC-015/021 — transporte de rede **real** (TCP) para o consenso.
//!
//! O [`crate::consensus::Router`] é in-process (determinístico, para testes). Este
//! módulo é o transporte de rede a sério: cada nó corre um servidor TCP que
//! despacha RPCs de raft para o seu `Raft` local, e o [`TcpNetworkFactory`]
//! implementa o `RaftNetwork` do openraft ligando ao `addr` de cada nó (o campo
//! `BasicNode.addr` que viaja na membership). Prova que o consenso funciona sobre
//! **sockets reais**, com serialização real dos pedidos/respostas.
//!
//! Protocolo de fio: enquadramento por comprimento (`u32` LE, com teto
//! [`MAX_FRAME`]) + bincode de um enum `RaftRpc`/`RaftRpcResp`. O **cliente liga
//! por pedido** (`TcpConnection` não retém socket — openraft reutiliza o objeto,
//! não a ligação TCP); o **servidor** aceita vários pedidos enquadrados por
//! ligação. Um pool/keep-alive de ligações é uma otimização por fazer.
//!
//! Honestidade: este módulo é TCP puro, **não gRPC literal** — o valor do
//! milestone é o consenso sobre a rede, não o wire-format. O wrapper gRPC/tonic
//! (camada fina por cima destes mesmos tipos serde) **existe** em
//! [`crate::grpc`]; o servidor escolhe TCP ou gRPC via
//! `ReplicationConfig.transport`.
#![allow(clippy::result_large_err)]

use crate::consensus::{
    ConsensusNode, EpisodeStateMachine, HeraclitusRaft, MemRaftLog, NodeId, TypeConfig,
};
use heraclitus_log::Log;
use openraft::error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, RaftNetwork, RaftNetworkFactory};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();

/// Teto de tamanho de frame (256 MiB). O comprimento vem do fio e é controlado
/// pelo par; sem teto, um valor gigante (`0xFFFF_FFFF` ≈ 4 GiB) provocaria uma
/// alocação enorme por ligação (esgotamento de memória, ou `abort()` do processo
/// se a alocação falhar). Um snapshot real de episódios cabe folgadamente aqui.
const MAX_FRAME: usize = 256 * 1024 * 1024;

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Pedido de raft que viaja no fio.
#[derive(serde::Serialize, serde::Deserialize)]
enum RaftRpc {
    AppendEntries(AppendEntriesRequest<TypeConfig>),
    Vote(VoteRequest<NodeId>),
    InstallSnapshot(InstallSnapshotRequest<TypeConfig>),
}

/// Resposta correspondente (inclui o `RaftError` remoto, também serializável).
#[derive(serde::Serialize, serde::Deserialize)]
enum RaftRpcResp {
    AppendEntries(Result<AppendEntriesResponse<NodeId>, RaftError<NodeId>>),
    Vote(Result<VoteResponse<NodeId>, RaftError<NodeId>>),
    InstallSnapshot(Result<InstallSnapshotResponse<NodeId>, RaftError<NodeId, InstallSnapshotError>>),
}

// ── enquadramento ───────────────────────────────────────────────────────────

// Genéricos sobre o stream (testáveis com `tokio::io::duplex`, e o mesmo código
// serve `TcpStream`).
async fn write_frame<S: tokio::io::AsyncWrite + Unpin>(
    sock: &mut S,
    bytes: &[u8],
) -> std::io::Result<()> {
    sock.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    sock.write_all(bytes).await?;
    sock.flush().await
}

async fn read_frame<S: tokio::io::AsyncRead + Unpin>(sock: &mut S) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    sock.read_exact(&mut len).await?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        // Recusa o frame (fecha a ligação) em vez de alocar cegamente do fio.
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame de {len} bytes excede o teto {MAX_FRAME}"),
        ));
    }
    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf).await?;
    Ok(buf)
}

// ── servidor ────────────────────────────────────────────────────────────────

/// Serve RPCs de raft para o `raft` local sobre um listener já ligado. Uma task
/// por ligação; cada ligação processa um fluxo de pedidos enquadrados.
pub fn serve(listener: TcpListener, raft: HeraclitusRaft) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // Erros de accept transitórios (ECONNABORTED, EMFILE por esgotamento
            // de FDs sob carga) NÃO devem matar o servidor — se saíssemos, o nó
            // caía do cluster para sempre. Recua brevemente e continua.
            let (mut sock, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
            };
            let raft = raft.clone();
            tokio::spawn(async move {
                loop {
                    let req = match read_frame(&mut sock).await {
                        Ok(b) => b,
                        Err(_) => break, // par fechou a ligação
                    };
                    let rpc: RaftRpc = match bincode::serde::decode_from_slice(&req, BINCODE_CFG) {
                        Ok((r, _)) => r,
                        Err(_) => break,
                    };
                    let resp = match rpc {
                        RaftRpc::AppendEntries(r) => {
                            RaftRpcResp::AppendEntries(raft.append_entries(r).await)
                        }
                        RaftRpc::Vote(r) => RaftRpcResp::Vote(raft.vote(r).await),
                        RaftRpc::InstallSnapshot(r) => {
                            RaftRpcResp::InstallSnapshot(raft.install_snapshot(r).await)
                        }
                    };
                    let bytes = match bincode::serde::encode_to_vec(&resp, BINCODE_CFG) {
                        Ok(b) => b,
                        Err(_) => break,
                    };
                    if write_frame(&mut sock, &bytes).await.is_err() {
                        break;
                    }
                }
            });
        }
    })
}

// ── cliente (RaftNetwork) ────────────────────────────────────────────────────

/// Factory de rede TCP: descobre o destino pelo `addr` que vem na membership.
#[derive(Clone, Default)]
pub struct TcpNetworkFactory;

impl RaftNetworkFactory<TypeConfig> for TcpNetworkFactory {
    type Network = TcpConnection;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> TcpConnection {
        TcpConnection {
            target,
            addr: node.addr.clone(),
        }
    }
}

/// Uma ligação lógica a um nó. Liga por pedido (simples e correto para o modo de
/// referência); openraft chama estes métodos em série (`&mut self`).
pub struct TcpConnection {
    target: NodeId,
    addr: String,
}

impl TcpConnection {
    async fn call(&self, rpc: RaftRpc) -> Result<RaftRpcResp, Unreachable> {
        let mut sock = TcpStream::connect(&self.addr)
            .await
            .map_err(|e| Unreachable::new(&e))?;
        let req = bincode::serde::encode_to_vec(&rpc, BINCODE_CFG)
            .map_err(|e| Unreachable::new(&io_err(e)))?;
        write_frame(&mut sock, &req)
            .await
            .map_err(|e| Unreachable::new(&e))?;
        let resp = read_frame(&mut sock)
            .await
            .map_err(|e| Unreachable::new(&e))?;
        bincode::serde::decode_from_slice(&resp, BINCODE_CFG)
            .map(|(r, _)| r)
            .map_err(|e| Unreachable::new(&io_err(e)))
    }
}

impl RaftNetwork<TypeConfig> for TcpConnection {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        match self.call(RaftRpc::AppendEntries(rpc)).await.map_err(RPCError::Unreachable)? {
            RaftRpcResp::AppendEntries(Ok(r)) => Ok(r),
            RaftRpcResp::AppendEntries(Err(e)) => {
                Err(RPCError::RemoteError(RemoteError::new(self.target, e)))
            }
            _ => Err(RPCError::Unreachable(Unreachable::new(&io_err(
                "resposta de tipo trocado",
            )))),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        match self.call(RaftRpc::Vote(rpc)).await.map_err(RPCError::Unreachable)? {
            RaftRpcResp::Vote(Ok(r)) => Ok(r),
            RaftRpcResp::Vote(Err(e)) => Err(RPCError::RemoteError(RemoteError::new(self.target, e))),
            _ => Err(RPCError::Unreachable(Unreachable::new(&io_err(
                "resposta de tipo trocado",
            )))),
        }
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        match self.call(RaftRpc::InstallSnapshot(rpc)).await.map_err(RPCError::Unreachable)? {
            RaftRpcResp::InstallSnapshot(Ok(r)) => Ok(r),
            RaftRpcResp::InstallSnapshot(Err(e)) => {
                Err(RPCError::RemoteError(RemoteError::new(self.target, e)))
            }
            _ => Err(RPCError::Unreachable(Unreachable::new(&io_err(
                "resposta de tipo trocado",
            )))),
        }
    }
}

// ── montagem de um nó com transporte TCP ─────────────────────────────────────

/// Um nó de consenso ligado por TCP: o nó + o `addr` do seu servidor + o handle
/// da task servidora (aborta-se no fim do teste).
pub struct TcpNode {
    pub node: ConsensusNode,
    pub addr: String,
    pub server: tokio::task::JoinHandle<()>,
}

/// Cria um nó com transporte TCP real, ligando o listener em `bind_addr` (use
/// `127.0.0.1:0` para porta efémera) e usando o raft-log/máquina fornecidos —
/// é o construtor genérico que suporta o modo durável (`FileRaftLog` +
/// `EpisodeStateMachine::open_durable().with_apply_hook(..)`).
pub async fn spawn_node_tcp_on<LS>(
    id: NodeId,
    log: Arc<Log>,
    config: Arc<openraft::Config>,
    bind_addr: &str,
    store: LS,
    sm: EpisodeStateMachine,
) -> Result<TcpNode, Box<dyn std::error::Error>>
where
    LS: openraft::storage::RaftLogStorage<crate::consensus::TypeConfig>,
{
    let listener = TcpListener::bind(bind_addr).await?;
    let addr = listener.local_addr()?.to_string();
    let raft = HeraclitusRaft::new(id, config, TcpNetworkFactory, store, sm).await?;
    let server = serve(listener, raft.clone());
    Ok(TcpNode {
        node: ConsensusNode { id, raft, log },
        addr,
        server,
    })
}

/// Como [`spawn_node_tcp_on`] mas em `127.0.0.1:0` com raft-log em memória — o
/// caminho de referência para testes de transporte.
pub async fn spawn_node_tcp(
    id: NodeId,
    log: Arc<Log>,
    config: Arc<openraft::Config>,
) -> Result<TcpNode, Box<dyn std::error::Error>> {
    let sm = EpisodeStateMachine::new(log.clone());
    spawn_node_tcp_on(id, log, config, "127.0.0.1:0", MemRaftLog::default(), sm).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::episode_bytes;
    use crate::logs_equivalent;
    use heraclitus_core::{Episode, EventKind, FsyncPolicy};
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn cfg() -> Arc<openraft::Config> {
        Arc::new(
            openraft::Config {
                heartbeat_interval: 100,
                election_timeout_min: 300,
                election_timeout_max: 600,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        )
    }

    fn ep(i: u64) -> Episode {
        Episode::new("tcp", EventKind::Observation, format!("net-{i}").into_bytes())
    }

    /// O teto de frame protege contra um comprimento gigante vindo do fio: em vez
    /// de alocar ~4 GiB (esgotar memória / abortar o processo), `read_frame`
    /// recusa. Um frame dentro do teto passa normalmente.
    #[tokio::test]
    async fn read_frame_rejects_oversized_length() {
        // Prefixo de comprimento hostil: 0xFFFFFFFF (~4 GiB) + sem payload.
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        a.flush().await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "recusa, não aloca");

        // Um frame legítimo faz round-trip.
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, b"ola").await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), b"ola");
    }

    /// O consenso sobre **sockets TCP reais**: 3 nós em portas efémeras elegem um
    /// líder, replicam 20 writes e os três logs de episódios ficam
    /// byte-equivalentes — pedidos/respostas serializados e trocados na rede.
    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn tcp_cluster_elects_and_replicates_over_real_sockets() {
        let config = cfg();
        let mut tcp = Vec::new();
        let mut dirs = Vec::new();
        for id in 0..3u64 {
            let dir = tempfile::tempdir().unwrap();
            let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
            tcp.push(spawn_node_tcp(id, log, config.clone()).await.unwrap());
            dirs.push(dir);
        }

        // A membership carrega os ENDEREÇOS TCP reais; é por aqui que o
        // TcpNetworkFactory descobre para onde ligar.
        let members: BTreeMap<NodeId, BasicNode> = tcp
            .iter()
            .map(|t| (t.node.id, BasicNode::new(&t.addr)))
            .collect();
        tcp[0].node.raft.initialize(members).await.unwrap();

        // Espera eleição (agora via mensagens de voto pela rede).
        let leader = tcp[0]
            .node
            .raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(|m| m.current_leader.is_some(), "líder eleito pela rede")
            .await
            .unwrap()
            .current_leader
            .unwrap();

        // 20 writes no líder, replicados por append_entries sobre TCP.
        let mut last = 0u64;
        for i in 0..20 {
            let r = tcp[leader as usize]
                .node
                .raft
                .client_write(episode_bytes(&ep(i)))
                .await
                .unwrap();
            last = r.log_id.index;
        }

        // Todos aplicam o último write acked (índice da resposta, não das metrics).
        for t in &tcp {
            t.node
                .raft
                .wait(Some(Duration::from_secs(15)))
                .applied_index_at_least(Some(last), "replicado pela rede")
                .await
                .unwrap();
        }

        for t in &tcp {
            assert_eq!(t.node.log.head(), 20, "nó {} replicou os 20 episódios", t.node.id);
        }
        assert!(logs_equivalent(&tcp[0].node.log, &tcp[1].node.log).unwrap());
        assert!(logs_equivalent(&tcp[1].node.log, &tcp[2].node.log).unwrap());

        for t in tcp {
            t.server.abort();
        }
    }

    /// Failover sobre TCP: um nó "morre" de verdade (`raft.shutdown()`), os dois
    /// sobreviventes (quórum 2/3) elegem um novo líder pela rede e continuam a
    /// comitar; os seus logs convergem. Prova o failover com transporte real, não
    /// só com o router in-process.
    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn tcp_cluster_survives_leader_shutdown() {
        let config = cfg();
        let mut tcp = Vec::new();
        let mut dirs = Vec::new();
        for id in 0..3u64 {
            let dir = tempfile::tempdir().unwrap();
            let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
            tcp.push(spawn_node_tcp(id, log, config.clone()).await.unwrap());
            dirs.push(dir);
        }
        let members: BTreeMap<NodeId, BasicNode> = tcp
            .iter()
            .map(|t| (t.node.id, BasicNode::new(&t.addr)))
            .collect();
        tcp[0].node.raft.initialize(members).await.unwrap();
        let leader = tcp[0]
            .node
            .raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(|m| m.current_leader.is_some(), "líder")
            .await
            .unwrap()
            .current_leader
            .unwrap();

        for i in 0..5 {
            tcp[leader as usize].node.raft.client_write(episode_bytes(&ep(i))).await.unwrap();
        }

        // Morte real do líder: encerra o seu Raft.
        tcp[leader as usize].node.raft.shutdown().await.unwrap();

        // Os dois sobreviventes elegem um novo líder pela rede.
        let survivor = tcp.iter().find(|t| t.node.id != leader).unwrap();
        let new_leader = survivor
            .node
            .raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(
                |m| matches!(m.current_leader, Some(l) if l != leader),
                "novo líder após a morte",
            )
            .await
            .unwrap()
            .current_leader
            .unwrap();
        assert_ne!(new_leader, leader);

        // O cluster continua vivo: mais 5 writes no novo líder, replicados por TCP.
        let mut last = 0u64;
        for i in 5..10 {
            let r = tcp[new_leader as usize]
                .node
                .raft
                .client_write(episode_bytes(&ep(i)))
                .await
                .unwrap();
            last = r.log_id.index;
        }

        // Os dois sobreviventes convergem (o morto fica de fora).
        for t in tcp.iter().filter(|t| t.node.id != leader) {
            t.node
                .raft
                .wait(Some(Duration::from_secs(15)))
                .applied_index_at_least(Some(last), "sobrevivente converge")
                .await
                .unwrap();
            assert_eq!(t.node.log.head(), 10, "nó {} tem os 10 episódios", t.node.id);
        }
        let survivors: Vec<&TcpNode> = tcp.iter().filter(|t| t.node.id != leader).collect();
        assert!(logs_equivalent(&survivors[0].node.log, &survivors[1].node.log).unwrap());

        for t in tcp {
            t.server.abort();
        }
    }
}
