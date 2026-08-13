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

use heraclitus_core::{Episode, HeraclitusError, Lsn};
use heraclitus_log::Log;
use std::sync::Arc;

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
// LEGADO v0 (§2.3, marcado 2026-07-16): tudo abaixo desta linha é a camada de
// log-shipping RFC-003 SUBSTITUÍDA pelo consenso openraft (feature
// `replication`). Fica como referência/testes de convergência pull-based —
// NENHUM caminho vivo a usa. Não estender; promover exige reabrir a decisão.
// ─────────────────────────────────────────────────────────────────────────

/// LEGADO v0 — transport boundary: how a follower fetches batches from a
/// leader. Implementations: in-process (tests), TCP (sim/turmoil).
pub trait LogTransport {
    fn fetch(&mut self, from: Lsn, max: usize) -> Result<Vec<(Lsn, Episode)>, HeraclitusError>;
}

/// LEGADO v0 — in-process transport over a shared leader log (reference + tests).
pub struct LocalTransport {
    pub leader: Arc<Log>,
}

impl LogTransport for LocalTransport {
    fn fetch(&mut self, from: Lsn, max: usize) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        let mut batch = self.leader.scan(from, from.saturating_add(max as u64))?;
        batch.truncate(max);
        Ok(batch)
    }
}

/// LEGADO v0 — a pull-based follower. `sync_once` is idempotent and safe to
/// call in a loop; contiguity is enforced by `append_replicated`.
pub struct Follower {
    pub log: Arc<Log>,
    pub batch: usize,
}

impl Follower {
    pub fn new(log: Arc<Log>) -> Self {
        Self { log, batch: 256 }
    }

    /// Pull until the transport has nothing newer. Returns events applied.
    pub fn sync_once(&self, transport: &mut dyn LogTransport) -> Result<u64, HeraclitusError> {
        let mut applied = 0u64;
        loop {
            let from = self.log.head();
            let batch = transport.fetch(from, self.batch)?;
            if batch.is_empty() {
                return Ok(applied);
            }
            let mut progressed = 0u64;
            for (lsn, ep) in batch {
                if lsn < self.log.head() {
                    continue; // duplicate delivery — idempotent skip
                }
                self.log.append_replicated(lsn, ep)?;
                applied += 1;
                progressed += 1;
            }
            // Audit #3: a non-empty batch that applied nothing means the
            // transport is replaying stale data — exit instead of spinning.
            if progressed == 0 {
                return Ok(applied);
            }
        }
    }

    /// Partition-tolerant driver: pull until the follower's head reaches
    /// `target` (typically the leader's acked head), absorbing up to
    /// `max_transient_errors` no-progress rounds (an empty/failing transport =
    /// a network partition) before giving up. Never loses or reorders events —
    /// contiguity and idempotency are enforced by `append_replicated`, so a
    /// broken link only leaves the follower *behind*, never corrupt. The caller
    /// owns retry pacing (sleep/backoff); this loop does not sleep.
    pub fn sync_until_head(
        &self,
        transport: &mut dyn LogTransport,
        target: Lsn,
        max_transient_errors: u32,
    ) -> Result<u64, HeraclitusError> {
        let mut applied = 0u64;
        let mut stalls = 0u32;
        while self.log.head() < target {
            // A partition surfaces as a transport error; treat it as a
            // transient stall (progress 0), not a data fault. The contiguous
            // prefix that did apply (if any) is already durable.
            let progress = self.sync_once(transport).unwrap_or_default();
            applied += progress;
            if progress == 0 {
                stalls += 1;
                if stalls > max_transient_errors {
                    return Err(HeraclitusError::StorageEngine(format!(
                        "follower stalled at head {} below target {} (partition budget exhausted)",
                        self.log.head(),
                        target
                    )));
                }
            } else {
                stalls = 0;
            }
        }
        Ok(applied)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{EventKind, FsyncPolicy};

    fn ep(s: &str) -> Episode {
        Episode::new("leader", EventKind::Observation, s.into())
    }

    #[test]
    fn follower_replicates_and_converges() {
        let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let leader = Arc::new(Log::open(d1.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let follower_log = Arc::new(Log::open(d2.path(), 1 << 20, FsyncPolicy::Always).unwrap());

        for i in 0..50 {
            leader.append(ep(&format!("e{i}"))).unwrap();
        }
        let follower = Follower::new(follower_log.clone());
        let mut t = LocalTransport {
            leader: leader.clone(),
        };
        assert_eq!(follower.sync_once(&mut t).unwrap(), 50);

        // More writes land while the follower is "away"; it catches up.
        for i in 50..80 {
            leader.append(ep(&format!("e{i}"))).unwrap();
        }
        assert_eq!(follower.sync_once(&mut t).unwrap(), 30);
        assert!(logs_equivalent(&leader, &follower_log).unwrap());
        // HLC stamps preserved bit-for-bit (append_replicated does not re-stamp).
        let (la, lb) = (
            leader.scan(0, u64::MAX).unwrap(),
            follower_log.scan(0, u64::MAX).unwrap(),
        );
        assert_eq!(la[7].1.ts_hlc, lb[7].1.ts_hlc);
    }

    #[test]
    fn duplicate_delivery_is_idempotent() {
        let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let leader = Arc::new(Log::open(d1.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let flog = Arc::new(Log::open(d2.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        for i in 0..10 {
            leader.append(ep(&format!("e{i}"))).unwrap();
        }
        /// A transport that maliciously re-delivers from LSN 0 every time.
        struct Dup(Arc<Log>, bool);
        impl LogTransport for Dup {
            fn fetch(
                &mut self,
                from: Lsn,
                max: usize,
            ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
                if !self.1 {
                    self.1 = true;
                    return self.0.scan(0, max as u64); // duplicates!
                }
                self.0.scan(from, from + max as u64)
            }
        }
        let follower = Follower::new(flog.clone());
        follower.sync_once(&mut Dup(leader.clone(), false)).unwrap();
        follower.sync_once(&mut Dup(leader.clone(), false)).unwrap();
        assert!(logs_equivalent(&leader, &flog).unwrap());
    }

    // ── Fase 1.2 hardening — prove the header's convergence guarantee ────────

    use std::sync::atomic::{AtomicBool, Ordering};

    /// A leader link that can be cut (`up=false` → connection error) and healed.
    struct Link {
        leader: Arc<Log>,
        up: Arc<AtomicBool>,
    }
    impl LogTransport for Link {
        fn fetch(&mut self, from: Lsn, max: usize) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
            if !self.up.load(Ordering::Acquire) {
                return Err(HeraclitusError::StorageEngine("partitioned link".into()));
            }
            let mut b = self.leader.scan(from, from.saturating_add(max as u64))?;
            b.truncate(max);
            Ok(b)
        }
    }

    #[test]
    fn partitioned_follower_converges_after_heal_losing_nothing() {
        let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let leader = Arc::new(Log::open(d1.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let flog = Arc::new(Log::open(d2.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        for i in 0..100 {
            leader.append(ep(&format!("e{i}"))).unwrap();
        }
        let target = leader.head();

        let up = Arc::new(AtomicBool::new(false));
        let follower = Follower::new(flog.clone());
        let mut link = Link {
            leader: leader.clone(),
            up: up.clone(),
        };

        // Partitioned: the driver exhausts its retry budget and reports the
        // stall — but the follower is only *behind*, never corrupt.
        let err = follower.sync_until_head(&mut link, target, 3).unwrap_err();
        assert!(matches!(err, HeraclitusError::StorageEngine(_)));
        assert!(flog.head() < target, "partition leaves the follower behind");

        // Heal → converges to every leader-acked event, byte-for-byte.
        up.store(true, Ordering::Release);
        follower.sync_until_head(&mut link, target, 3).unwrap();
        assert_eq!(flog.head(), target);
        assert!(logs_equivalent(&leader, &flog).unwrap());
    }

    #[test]
    fn followers_with_different_batch_sizes_converge_identically() {
        let (d0, d1, d2) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        let leader = Arc::new(Log::open(d0.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let flog1 = Arc::new(Log::open(d1.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let flog2 = Arc::new(Log::open(d2.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        for i in 0..77 {
            leader.append(ep(&format!("e{i}"))).unwrap();
        }
        let mut f1 = Follower::new(flog1.clone());
        f1.batch = 1; // pathological: one event per round
        let mut f2 = Follower::new(flog2.clone());
        f2.batch = 4096; // whole log in one shot
        f1.sync_once(&mut LocalTransport { leader: leader.clone() }).unwrap();
        f2.sync_once(&mut LocalTransport { leader: leader.clone() }).unwrap();

        assert!(logs_equivalent(&leader, &flog1).unwrap());
        assert!(logs_equivalent(&flog1, &flog2).unwrap());
    }

    /// THE thesis test: replication ships *only the raw log*; each node rebuilds
    /// its derived graph view locally, and the `state_hash` is bit-identical
    /// across leader and followers. This is "log is the only truth + views are
    /// deterministic derivations + only bytes travel the network", proven end to
    /// end (ties Fase 1.2 ↔ Fase 1.3).
    #[test]
    fn replication_ships_log_only_and_derived_state_is_bit_identical() {
        use heraclitus_index_graph::GraphIndex;
        use heraclitus_views::View; // brings `apply` into scope

        let (d0, d1, d2) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        let leader = Arc::new(Log::open(d0.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let flog1 = Arc::new(Log::open(d1.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        let flog2 = Arc::new(Log::open(d2.path(), 1 << 20, FsyncPolicy::Always).unwrap());

        // A causal DAG: e1←e0, e2←{e0,e1}, e3←e2 … parents are set before append
        // (ids captured first, since append consumes the episode).
        let mut prev = Vec::new();
        for i in 0..40 {
            let mut e = ep(&format!("e{i}"));
            if let Some(&p) = prev.last() {
                e.parents.push(p);
            }
            if prev.len() >= 2 {
                e.parents.push(prev[prev.len() - 2]);
            }
            prev.push(e.id);
            leader.append(e).unwrap();
        }

        // Followers pull the raw log only — they never receive a GraphIndex.
        Follower::new(flog1.clone())
            .sync_once(&mut LocalTransport { leader: leader.clone() })
            .unwrap();
        Follower::new(flog2.clone())
            .sync_once(&mut LocalTransport { leader: leader.clone() })
            .unwrap();

        // Each node hydrates its own graph view from its own local log.
        let graph_of = |log: &Log| {
            let mut g = GraphIndex::new();
            for (lsn, e) in log.scan(0, u64::MAX).unwrap() {
                g.apply(lsn, &e);
            }
            g
        };
        let h_leader = graph_of(&leader).state_hash();
        let h_f1 = graph_of(&flog1).state_hash();
        let h_f2 = graph_of(&flog2).state_hash();

        assert_eq!(h_leader, h_f1, "follower 1 derived state must match leader");
        assert_eq!(h_leader, h_f2, "follower 2 derived state must match leader");
    }
}
