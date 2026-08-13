//! SPEC-015/021 — transporte **gRPC/tonic** para o consenso (feature `replication`).
//!
//! Espelha [`crate::net`] (TCP), mas sobre gRPC: cada nó corre um serviço tonic
//! `RaftTransport` (3 RPCs unários) e o [`GrpcNetworkFactory`] implementa o
//! `RaftNetwork` do openraft ligando por gRPC ao `addr` que vem na membership.
//! As mensagens carregam o **bincode dos mesmos tipos serde do openraft**
//! (idêntico ao transporte TCP) — é a camada fina de gRPC por cima, não uma
//! re-modelação protobuf dos tipos de raft. Unifica o consenso na mesma
//! superfície gRPC do resto do servidor.
//!
//! Como no TCP, o cliente liga **por pedido** (`GrpcConnection` não retém canal);
//! um pool/keep-alive de canais é uma otimização por fazer. O servidor liga o
//! listener ANTES de devolver (o `addr` já está a aceitar quando o nó existe).
#![allow(clippy::result_large_err)]

use crate::consensus::{
    ConsensusNode, EpisodeStateMachine, HeraclitusRaft, MemRaftLog, NodeId, TypeConfig,
};
use heraclitus_log::Log;
use heraclitus_proto::raft_v1::{
    raft_transport_client::RaftTransportClient,
    raft_transport_server::{RaftTransport, RaftTransportServer},
    RaftEnvelope,
};
use openraft::error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, RaftNetwork, RaftNetworkFactory};
use std::sync::Arc;
use tonic::{Request, Response, Status};

const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, std::io::Error> {
    bincode::serde::encode_to_vec(v, BINCODE_CFG).map_err(io_err)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, std::io::Error> {
    bincode::serde::decode_from_slice(bytes, BINCODE_CFG)
        .map(|(v, _)| v)
        .map_err(io_err)
}

// ── servidor (serviço tonic) ─────────────────────────────────────────────────

/// Serviço tonic que despacha os RPCs de raft para o `Raft` local.
pub struct RaftTransportSvc {
    raft: HeraclitusRaft,
}

#[tonic::async_trait]
impl RaftTransport for RaftTransportSvc {
    async fn append_entries(
        &self,
        request: Request<RaftEnvelope>,
    ) -> Result<Response<RaftEnvelope>, Status> {
        let req: AppendEntriesRequest<TypeConfig> = decode(&request.into_inner().payload)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let resp = self.raft.append_entries(req).await; // Result<_, RaftError>
        let payload = encode(&resp).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(RaftEnvelope { payload }))
    }

    async fn vote(
        &self,
        request: Request<RaftEnvelope>,
    ) -> Result<Response<RaftEnvelope>, Status> {
        let req: VoteRequest<NodeId> = decode(&request.into_inner().payload)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let resp = self.raft.vote(req).await;
        let payload = encode(&resp).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(RaftEnvelope { payload }))
    }

    async fn install_snapshot(
        &self,
        request: Request<RaftEnvelope>,
    ) -> Result<Response<RaftEnvelope>, Status> {
        let req: InstallSnapshotRequest<TypeConfig> = decode(&request.into_inner().payload)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let resp = self.raft.install_snapshot(req).await;
        let payload = encode(&resp).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(RaftEnvelope { payload }))
    }
}

// ── cliente (RaftNetwork) ────────────────────────────────────────────────────

/// Factory de rede gRPC: descobre o destino pelo `addr` da membership.
#[derive(Clone, Default)]
pub struct GrpcNetworkFactory;

impl RaftNetworkFactory<TypeConfig> for GrpcNetworkFactory {
    type Network = GrpcConnection;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> GrpcConnection {
        GrpcConnection {
            target,
            addr: node.addr.clone(),
        }
    }
}

/// Uma ligação lógica a um nó; liga por pedido (openraft chama em série).
pub struct GrpcConnection {
    target: NodeId,
    addr: String,
}

/// Snapshots/lotes de raft podem exceder o default de 4MB do tonic; o transporte
/// TCP permite 256MiB — igualar nos dois sentidos, senão um seguidor atrasado com
/// snapshot grande NUNCA recuperaria por gRPC (mensagem rejeitada para sempre).
const MAX_RAFT_MSG: usize = 256 * 1024 * 1024;

impl GrpcConnection {
    async fn client(&self) -> Result<RaftTransportClient<tonic::transport::Channel>, Unreachable> {
        let c = RaftTransportClient::connect(format!("http://{}", self.addr))
            .await
            .map_err(|e| Unreachable::new(&e))?;
        Ok(c.max_decoding_message_size(MAX_RAFT_MSG)
            .max_encoding_message_size(MAX_RAFT_MSG))
    }
}

impl RaftNetwork<TypeConfig> for GrpcConnection {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let payload = encode(&rpc).map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;
        let mut client = self.client().await.map_err(RPCError::Unreachable)?;
        let env = client
            .append_entries(Request::new(RaftEnvelope { payload }))
            .await
            .map_err(|s| RPCError::Unreachable(Unreachable::new(&s)))?
            .into_inner();
        let resp: Result<AppendEntriesResponse<NodeId>, RaftError<NodeId>> =
            decode(&env.payload).map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;
        resp.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let payload = encode(&rpc).map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;
        let mut client = self.client().await.map_err(RPCError::Unreachable)?;
        let env = client
            .vote(Request::new(RaftEnvelope { payload }))
            .await
            .map_err(|s| RPCError::Unreachable(Unreachable::new(&s)))?
            .into_inner();
        let resp: Result<VoteResponse<NodeId>, RaftError<NodeId>> =
            decode(&env.payload).map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;
        resp.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        let payload = encode(&rpc).map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;
        let mut client = self.client().await.map_err(RPCError::Unreachable)?;
        let env = client
            .install_snapshot(Request::new(RaftEnvelope { payload }))
            .await
            .map_err(|s| RPCError::Unreachable(Unreachable::new(&s)))?
            .into_inner();
        let resp: Result<InstallSnapshotResponse<NodeId>, RaftError<NodeId, InstallSnapshotError>> =
            decode(&env.payload).map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;
        resp.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}

// ── montagem de um nó com transporte gRPC ────────────────────────────────────

/// Um nó de consenso ligado por gRPC: o nó + o `addr` do seu servidor + o handle
/// da task servidora (aborta-se no shutdown).
pub struct GrpcNode {
    pub node: ConsensusNode,
    pub addr: String,
    pub server: tokio::task::JoinHandle<()>,
}

/// Cria um nó com transporte gRPC real. O listener é ligado ANTES de devolver
/// (via `serve_with_incoming` sobre um `TcpListener` já bound) — logo o `addr`
/// devolvido já está a aceitar. `bind_addr = "127.0.0.1:0"` dá porta efémera.
pub async fn spawn_node_grpc_on<LS>(
    id: NodeId,
    log: Arc<Log>,
    config: Arc<openraft::Config>,
    bind_addr: &str,
    store: LS,
    sm: EpisodeStateMachine,
) -> Result<GrpcNode, Box<dyn std::error::Error>>
where
    LS: openraft::storage::RaftLogStorage<TypeConfig>,
{
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let addr = listener.local_addr()?.to_string();
    let raft = HeraclitusRaft::new(id, config, GrpcNetworkFactory, store, sm).await?;
    let svc = RaftTransportSvc { raft: raft.clone() };
    // Um erro de `accept()` (ex.: EMFILE por exaustão de FDs sob carga) NÃO deve
    // terminar o serve — senão o nó cairia do cluster até restart, sem sinal. O
    // TCP puro (`net::serve`) já recua e continua; aqui saltamos o erro no stream.
    use tokio_stream::StreamExt as _;
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener)
        .filter_map(|r| r.ok().map(Ok::<_, std::io::Error>));
    let server = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(
                RaftTransportServer::new(svc)
                    .max_decoding_message_size(MAX_RAFT_MSG)
                    .max_encoding_message_size(MAX_RAFT_MSG),
            )
            .serve_with_incoming(incoming)
            .await;
    });
    Ok(GrpcNode {
        node: ConsensusNode { id, raft, log },
        addr,
        server,
    })
}

/// Como [`spawn_node_grpc_on`] mas com raft-log em memória — referência p/ testes.
pub async fn spawn_node_grpc(
    id: NodeId,
    log: Arc<Log>,
    config: Arc<openraft::Config>,
    bind_addr: &str,
) -> Result<GrpcNode, Box<dyn std::error::Error>> {
    let sm = EpisodeStateMachine::new(log.clone());
    spawn_node_grpc_on(id, log, config, bind_addr, MemRaftLog::default(), sm).await
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
        Episode::new("grpc", EventKind::Observation, format!("grpc-{i}").into_bytes())
    }

    /// O consenso sobre **gRPC/tonic real**: 3 nós em portas efémeras elegem um
    /// líder, replicam 20 writes e os três logs ficam byte-equivalentes —
    /// pedidos/respostas serializados e trocados por gRPC.
    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn grpc_cluster_elects_and_replicates_over_tonic() {
        let config = cfg();
        let mut nodes = Vec::new();
        let mut dirs = Vec::new();
        for id in 0..3u64 {
            let dir = tempfile::tempdir().unwrap();
            let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
            nodes.push(spawn_node_grpc(id, log, config.clone(), "127.0.0.1:0").await.unwrap());
            dirs.push(dir);
        }

        // A membership carrega os endereços gRPC reais.
        let members: BTreeMap<NodeId, BasicNode> = nodes
            .iter()
            .map(|n| (n.node.id, BasicNode::new(&n.addr)))
            .collect();
        nodes[0].node.raft.initialize(members).await.unwrap();

        let leader = nodes[0]
            .node
            .raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(|m| m.current_leader.is_some(), "líder eleito por gRPC")
            .await
            .unwrap()
            .current_leader
            .unwrap();

        let mut last = 0u64;
        for i in 0..20 {
            let r = nodes[leader as usize]
                .node
                .raft
                .client_write(episode_bytes(&ep(i)))
                .await
                .unwrap();
            last = r.log_id.index;
        }

        for n in &nodes {
            n.node
                .raft
                .wait(Some(Duration::from_secs(15)))
                .applied_index_at_least(Some(last), "replicado por gRPC")
                .await
                .unwrap();
        }

        for n in &nodes {
            assert_eq!(n.node.log.head(), 20, "nó {} replicou os 20 episódios", n.node.id);
        }
        assert!(logs_equivalent(&nodes[0].node.log, &nodes[1].node.log).unwrap());
        assert!(logs_equivalent(&nodes[1].node.log, &nodes[2].node.log).unwrap());

        for n in nodes {
            n.server.abort();
        }
    }
}
