//! heraclitus-proto — generated gRPC types (tonic + protox, no protoc).

pub mod v1 {
    tonic::include_proto!("heraclitus.v1");
}

/// SPEC-015/021 — transporte gRPC do consenso raft (usado por
/// `heraclitus-raft::grpc` sob a feature `replication`).
pub mod raft_v1 {
    tonic::include_proto!("heraclitus.raft.v1");
}
