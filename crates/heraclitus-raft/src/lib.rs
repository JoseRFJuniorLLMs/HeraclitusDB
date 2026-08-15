//! heraclitus-raft — replication (§3.13).
//!
//! Two replication modes, honestly delimited:
//!
//! **v0 (RFC-003, default): single-leader log shipping with anti-entropy
//! catch-up.** The log *is* the state machine input; followers pull batches
//! from the leader's head and replay them into their own log (preserving
//! LSN + HLC), and their views replay locally. No failover claim: we claim,
//! and test, that a partitioned follower converges to every leader-acked
//! event after healing, losing nothing.
//!
//! **`replication` feature (SPEC-015/021): real openraft 0.9 consensus** —
//! see [`consensus`]. Leader election, quorum-gated acks and automatic
//! failover, proven by in-process cluster tests (leader killed → majority
//! elects a new leader → writes continue → healed node converges; a leader
//! without quorum can NEVER ack). The raft-log can be **durable on disk**
//! ([`durable::FileRaftLog`]) and a fully-durable node **survives process
//! restart** without duplicating or losing episodes (tested). Consensus also
//! runs over a **real TCP network transport** ([`net`]) — election,
//! replication and failover proven over sockets; the in-process
//! [`consensus::Router`] remains for deterministic partition/failover tests.
//! A **gRPC/tonic wrapper** over the same serde types is also available
//! ([`grpc`], SPEC-015/021) — the server selects TCP or gRPC via
//! `ReplicationConfig.transport`. Default build stays on v0.

use heraclitus_core::HeraclitusError;
use heraclitus_log::Log;

/// SPEC-015/021 — o upgrade openraft: eleição + quórum + failover (opt-in).
#[cfg(feature = "replication")]
pub mod consensus;

/// SPEC-015/021 — raft-log durável em disco (WAL + recuperação), opt-in.
#[cfg(feature = "replication")]
pub mod durable;

/// SPEC-015/021 — transporte de rede real (TCP) para o consenso, opt-in.
#[cfg(feature = "replication")]
pub mod net;

/// SPEC-015/021 — transporte gRPC/tonic para o consenso, opt-in. Mesma
/// serialização serde que [`net`], sobre a superfície gRPC do servidor.
#[cfg(feature = "replication")]
pub mod grpc;

// ─────────────────────────────────────────────────────────────────────────
/// Compare two logs for byte-level payload equivalence over `[0, head)`.
/// Used by the sim suite to prove zero acked-event loss after healing.
pub fn logs_equivalent(a: &Log, b: &Log) -> Result<bool, HeraclitusError> {
    let (ea, eb) = (a.scan(0, u64::MAX)?, b.scan(0, u64::MAX)?);
    if ea.len() != eb.len() {
        return Ok(false);
    }
    Ok(ea.iter().zip(&eb).all(|((la, xa), (lb, xb))| {
        la == lb && xa.id == xb.id && xa.ts_hlc == xb.ts_hlc && xa.content == xb.content
    }))
}
