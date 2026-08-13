//! heraclitus-txn — MVCC snapshots over log offsets (§3.11).
//!
//! > **ESTADO: REFERÊNCIA DE I&D — NÃO LIGADO AO CAMINHO VIVO** (decisão P3,
//! > 2026-07-16 — `docs/md/DECISAO-P3-isolation-txn.md`). Nenhum crate depende
//! > deste. A capacidade que a SPEC-019 descreve (leitura `AS OF` / snapshot
//! > histórico) **já está ligada** — pelo `as_of: Option<Lsn>` que o
//! > `heraclitus-query::QueryBackend` recebe em todos os métodos de leitura,
//! > resolvido do GQL `AS OF LSN|SNAPSHOT`. Como o log é single-writer
//! > append-only (committed = fsync-acked = `head()`) e o GQL é single-shot por
//! > `execute`, os níveis Repeatable/ReadCommitted/Streaming são degenerados e
//! > não há transação de escrita multi-statement a que os prender. Este crate
//! > fica como implementação de referência; não o promover sem reabrir a P3.
//!
//! A snapshot *is* an LSN. All reads carry it; views answer "as of ≤ LSN"
//! via their watermark + memtable merge. Writes are single-writer appends;
//! `compare_and_append` provides optimistic CAS workflows. There are NO
//! interactive multi-statement write transactions in v0.x — documented
//! honestly in docs/CONSISTENCY.md.

use heraclitus_core::{Episode, HeraclitusError, Lsn};
use heraclitus_log::Log;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A consistent read point: every event with `lsn < self.lsn()` is inside
/// the snapshot; everything at or after the captured head is invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot(Lsn);

impl Snapshot {
    /// The head LSN captured at snapshot time (exclusive upper bound).
    pub fn lsn(&self) -> Lsn {
        self.0
    }

    pub fn contains(&self, lsn: Lsn) -> bool {
        lsn < self.0
    }
}

pub struct TxnManager {
    log: Arc<Log>,
}

impl TxnManager {
    pub fn new(log: Arc<Log>) -> Self {
        Self { log }
    }

    /// `begin_snapshot() -> Lsn` (§3.11): captures the current head. The
    /// snapshot sees exactly the events with `lsn < head`.
    pub fn begin_snapshot(&self) -> Snapshot {
        Snapshot(self.log.head())
    }

    /// SPEC-019 (reference — NOT on the live path; the live `AS OF` runs through
    /// GQL's `as_of: Option<Lsn>`, not this). Open a snapshot under an explicit
    /// isolation level. All levels resolve to a pinned LSN (reads never see past it):
    /// - `HistoricalSnapshot(l)` — anchored at `l` (`AS OF`), ignoring newer data;
    /// - `RepeatableSnapshot` / `ReadCommittedSnapshot` — pinned at the current
    ///   committed head (the log only exposes fsync-acked events, so "committed"
    ///   is exactly `head()`);
    /// - `StreamingSnapshot` — same pin; the live tail arrives via
    ///   `heraclitus_log::subscribe::attach_subscriber` (SPEC-022), never by
    ///   mutating this snapshot.
    pub fn begin_with(&self, level: heraclitus_core::IsolationLevel) -> Snapshot {
        use heraclitus_core::IsolationLevel::*;
        match level {
            HistoricalSnapshot(lsn) => Snapshot(lsn.min(self.log.head())),
            RepeatableSnapshot(_) | ReadCommittedSnapshot(_) | StreamingSnapshot(_) => {
                Snapshot(self.log.head())
            }
        }
    }

    /// Read everything visible in `snap` within `[from, to)`.
    pub fn read_at(
        &self,
        snap: Snapshot,
        from: Lsn,
        to: Lsn,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        self.log.scan(from, to.min(snap.lsn()))
    }

    /// Plain append (the log serializes writers).
    pub fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        self.log.append(episode)
    }

    /// Optimistic compare-and-append: succeeds only if the head still equals
    /// `expected` (typically `snapshot.lsn()`), i.e. nothing was written
    /// since the snapshot was taken.
    pub fn compare_and_append(
        &self,
        expected: Lsn,
        episode: Episode,
    ) -> Result<Lsn, HeraclitusError> {
        self.log.append_cas(expected, episode)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Fase 1.1 (M4) — TransactionSnapshot + SnapshotManager
//
// Reconciled with the v3.2.0 briefing but adapted to THIS codebase's real
// types: `Lsn`/`SegmentId` are `u64` aliases (heraclitus-core/src/id.rs), NOT
// newtypes. We deliberately do NOT introduce `Lsn(pub u64)` — that would be a
// breaking change rippling through all 26 crates, which is the premature
// over-engineering the plan (Fase 3, benchmark-gated) explicitly defers.
//
// The briefing gave two contradictory shapes for `TransactionSnapshot`
// (one with `visible_segments: Vec<u64>`, one with `catalog_epoch`, `Copy`,
// 24 bytes). We keep the second: a fixed-size, `Copy`, allocation-free logical
// snapshot. Segment visibility is derived from `target_lsn`, not carried.
// ─────────────────────────────────────────────────────────────────────────

/// A strictly logical, allocation-free temporal snapshot (24 bytes, `Copy`).
///
/// - `target_lsn`   — exclusive upper bound: events with `lsn < target_lsn`
///   are visible; everything at/after the captured head is invisible.
/// - `watermark_lsn`— lowest LSN still pinned by any *active* reader; the GC
///   floor below which derived views may compact/demote safely.
/// - `catalog_epoch`— bumps on view/catalog blue-green swaps, so a reader can
///   detect that the physical layout it was planned against was replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionSnapshot {
    pub target_lsn: Lsn,
    pub watermark_lsn: Lsn,
    pub catalog_epoch: u64,
}

impl TransactionSnapshot {
    /// True iff `lsn` is inside this snapshot's visible history.
    pub fn contains(&self, lsn: Lsn) -> bool {
        lsn < self.target_lsn
    }
}

/// Tracks active read points to compute a safe watermark (the oldest LSN still
/// pinned by a live snapshot). Views consult `watermark()` as the floor below
/// which frozen state can be compacted/demoted without breaking any live read.
///
/// Isolation invariant: once `begin()` returns, appends past `target_lsn` are
/// mathematically invisible to that snapshot (`contains` is a pure `<` test).
pub struct SnapshotManager {
    current_lsn: AtomicU64,
    watermark_lsn: AtomicU64,
    current_epoch: AtomicU64,
    /// `target_lsn -> refcount` of live snapshots pinned at that head.
    active: Mutex<BTreeMap<Lsn, usize>>,
}

impl SnapshotManager {
    pub fn new(initial_lsn: Lsn, initial_epoch: u64) -> Self {
        Self {
            current_lsn: AtomicU64::new(initial_lsn),
            watermark_lsn: AtomicU64::new(initial_lsn),
            current_epoch: AtomicU64::new(initial_epoch),
            active: Mutex::new(BTreeMap::new()),
        }
    }

    /// Advance the visible head as the log grows (monotonic; never regresses).
    pub fn advance_head(&self, head: Lsn) {
        self.current_lsn.fetch_max(head, Ordering::AcqRel);
    }

    /// Publish a new catalog epoch (e.g. after a blue-green view swap).
    pub fn bump_epoch(&self) -> u64 {
        self.current_epoch.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Open a snapshot pinned at the current head. Refcounts the head so the
    /// watermark cannot advance past a still-active reader.
    pub fn begin(&self) -> TransactionSnapshot {
        let mut active = self.active.lock().unwrap();
        let target = self.current_lsn.load(Ordering::Acquire);
        let epoch = self.current_epoch.load(Ordering::Acquire);
        *active.entry(target).or_insert(0) += 1;
        // Watermark = oldest pinned read point (first key of the BTreeMap).
        let wm = *active.keys().next().unwrap_or(&target);
        self.watermark_lsn.store(wm, Ordering::Release);
        TransactionSnapshot {
            target_lsn: target,
            watermark_lsn: wm,
            catalog_epoch: epoch,
        }
    }

    /// Release a snapshot. When the last reader at a head drops, the watermark
    /// advances to the next-oldest pinned read point, or to the head if none.
    pub fn release(&self, snap: &TransactionSnapshot) {
        let mut active = self.active.lock().unwrap();
        if let Some(count) = active.get_mut(&snap.target_lsn) {
            *count -= 1;
            if *count == 0 {
                active.remove(&snap.target_lsn);
            }
        }
        let wm = active
            .keys()
            .next()
            .copied()
            .unwrap_or_else(|| self.current_lsn.load(Ordering::Acquire));
        self.watermark_lsn.store(wm, Ordering::Release);
    }

    /// The current GC floor: no live snapshot depends on anything below this.
    pub fn watermark(&self) -> Lsn {
        self.watermark_lsn.load(Ordering::Acquire)
    }

    /// The current visible head.
    pub fn head(&self) -> Lsn {
        self.current_lsn.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{EventKind, FsyncPolicy};

    fn ep(s: &str) -> Episode {
        Episode::new("txn", EventKind::Observation, s.into())
    }

    fn open() -> (tempfile::TempDir, TxnManager) {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
        (dir, TxnManager::new(log))
    }

    #[test]
    fn snapshot_isolation() {
        let (_d, txn) = open();
        for i in 0..5 {
            txn.append(ep(&format!("e{i}"))).unwrap();
        }
        let snap = txn.begin_snapshot();
        // Writes after the snapshot are invisible to it.
        txn.append(ep("after")).unwrap();
        txn.append(ep("after2")).unwrap();

        let visible = txn.read_at(snap, 0, u64::MAX).unwrap();
        assert_eq!(visible.len(), 5);
        assert!(visible.iter().all(|(l, _)| snap.contains(*l)));

        // A fresh snapshot sees everything.
        let snap2 = txn.begin_snapshot();
        assert_eq!(txn.read_at(snap2, 0, u64::MAX).unwrap().len(), 7);
    }

    #[test]
    fn cas_workflow() {
        let (_d, txn) = open();
        let snap = txn.begin_snapshot();
        // First CAS at the snapshot head succeeds…
        txn.compare_and_append(snap.lsn(), ep("mine")).unwrap();
        // …a second writer using the same stale snapshot must conflict.
        let err = txn.compare_and_append(snap.lsn(), ep("stale")).unwrap_err();
        assert!(matches!(err, HeraclitusError::CasConflict { .. }));
    }

    #[test]
    fn isolation_levels_pin_the_right_lsn() {
        use heraclitus_core::IsolationLevel::*;
        let (_d, txn) = open();
        for i in 0..10 {
            txn.append(ep(&format!("e{i}"))).unwrap();
        }
        // Historical: anchored at 4 — sees exactly e0..e3.
        let hist = txn.begin_with(HistoricalSnapshot(4));
        assert_eq!(txn.read_at(hist, 0, u64::MAX).unwrap().len(), 4);
        // Historical beyond head clamps to head (cannot see the future).
        let fut = txn.begin_with(HistoricalSnapshot(999));
        assert_eq!(fut.lsn(), 10);
        // Repeatable: pinned at open; later appends are invisible to it.
        let rep = txn.begin_with(RepeatableSnapshot(0));
        txn.append(ep("later")).unwrap();
        assert_eq!(txn.read_at(rep, 0, u64::MAX).unwrap().len(), 10);
        // ReadCommitted/Streaming re-opened after the append see it.
        let rc = txn.begin_with(ReadCommittedSnapshot(0));
        assert_eq!(txn.read_at(rc, 0, u64::MAX).unwrap().len(), 11);
    }

    #[test]
    fn snapshot_manager_watermark_tracks_oldest_reader() {
        let sm = SnapshotManager::new(100, 0);
        // A reader pins head=100.
        let s1 = sm.begin();
        assert_eq!(s1.target_lsn, 100);
        assert_eq!(sm.watermark(), 100);

        // Head advances; a newer reader pins 150, but the watermark stays at
        // the oldest live read point (100) — the GC floor cannot pass s1.
        sm.advance_head(150);
        let s2 = sm.begin();
        assert_eq!(s2.target_lsn, 150);
        assert_eq!(sm.watermark(), 100);

        // Releasing the old reader lets the watermark jump to the next-oldest.
        sm.release(&s1);
        assert_eq!(sm.watermark(), 150);

        // Releasing the last reader floats the watermark up to the head.
        sm.release(&s2);
        assert_eq!(sm.watermark(), 150);
    }

    #[test]
    fn snapshot_isolation_and_epoch() {
        let sm = SnapshotManager::new(10, 7);
        let snap = sm.begin();
        assert_eq!(snap.catalog_epoch, 7);
        // Appends past the captured head are invisible to a `<` test.
        sm.advance_head(42);
        assert!(snap.contains(9));
        assert!(!snap.contains(10));
        assert!(!snap.contains(41));
        // A blue-green swap bumps the epoch for *new* snapshots only.
        assert_eq!(sm.bump_epoch(), 8);
        assert_eq!(sm.begin().catalog_epoch, 8);
        assert_eq!(snap.catalog_epoch, 7); // the old snapshot is immutable
    }
}
