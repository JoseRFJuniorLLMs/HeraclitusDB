//! SPEC-011 — runtime infrastructure contracts.
//!
//! Storage abstraction, the atomic database manifest, the derived-artifact
//! lifecycle, and the execution sandbox (budgets + cancellation). These are the
//! *contracts* (traits + plain data); concrete engines implement them in their
//! own crates (`heraclitus-log`, `heraclitus-analytics`, …).
//!
//! Adapted to the real codebase: `Lsn`/`SegmentId` are `u64` aliases, not the
//! draft's newtypes; nothing here pulls Arrow into `core`.

use crate::{Lsn, SegmentId};
use std::sync::atomic::{AtomicBool, Ordering};

// ── §1.1 Database manifest — atomic macro-state ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentState {
    Active,
    Frozen,
    Archived,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SegmentDescriptor {
    pub segment_id: SegmentId,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub event_count: u64,
    pub payload_hash: [u8; 32],
    pub state: SegmentState,
}

/// The root of storage metadata, swapped atomically on every macro-state change.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DatabaseManifest {
    pub manifest_version: u32,
    pub format_identifier: [u8; 4],
    pub segments: Vec<SegmentDescriptor>,
    /// Highest stabilized+audited LSN.
    pub cumulative_watermark: Lsn,
    pub statistics_root_hash: [u8; 32],
}

impl DatabaseManifest {
    /// Segments visible under a read snapshot pinned at `target_lsn`.
    pub fn visible_segments(&self, target_lsn: Lsn) -> impl Iterator<Item = &SegmentDescriptor> {
        self.segments.iter().filter(move |s| s.first_lsn <= target_lsn)
    }
}

// ── §1.2 Storage engine contract ────────────────────────────────────────────

/// Isolates physical persistence (files, mmap, S3) from planners and replay.
pub trait StorageEngine: Send + Sync {
    fn append_raw(&self, payload: &[u8]) -> Result<Lsn, String>;
    fn fetch_segment(&self, segment_id: SegmentId) -> Result<Vec<u8>, String>;
    fn write_manifest(&self, manifest: &DatabaseManifest) -> Result<(), String>;
    fn sync_active_segment(&self) -> Result<(), String>;
}

// ── §3 Derived-artifact lifecycle ───────────────────────────────────────────

/// A logical-intent hash identifying the structural need of a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryFingerprint {
    pub logical_intent_hash: [u8; 32],
    pub applicable_snapshot: Lsn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactType {
    CompressedSparseRow,
    RoaringBitmapFilter,
    VectorCacheHnsw,
    ArrowColumnarBatch,
    /// Per-segment min/max summary used for skip-I/O (SPEC-010).
    ZoneMap,
}

/// Homogeneous lifecycle contract for any accelerator structure (CSR, HNSW
/// cache, roaring filter, Arrow batch) so the manager can treat them uniformly.
pub trait DerivedExecutionArtifact: Send + Sync {
    fn artifact_type(&self) -> ArtifactType;
    fn estimated_memory_usage(&self) -> usize;
    fn query_fingerprint(&self) -> &QueryFingerprint;
}

// ── §4 Execution sandbox — budgets & cancellation ───────────────────────────

/// RAM budget with an explicit OOM guard: reservations that would exceed the
/// cap are rejected instead of aborting the process.
#[derive(Debug)]
pub struct MemoryBudget {
    pub allowed_bytes: usize,
    pub used_bytes: usize,
}

impl MemoryBudget {
    pub fn new(allowed_bytes: usize) -> Self {
        Self { allowed_bytes, used_bytes: 0 }
    }

    /// Reserve `bytes`, or `Err` if it would blow the cap (caller then falls
    /// back to the imperative/streaming path instead of OOM-ing).
    pub fn try_reserve(&mut self, bytes: usize) -> Result<(), String> {
        match self.used_bytes.checked_add(bytes) {
            Some(total) if total <= self.allowed_bytes => {
                self.used_bytes = total;
                Ok(())
            }
            _ => Err(format!(
                "MemoryBudget exceeded: used {} + {} > cap {}",
                self.used_bytes, bytes, self.allowed_bytes
            )),
        }
    }

    pub fn release(&mut self, bytes: usize) {
        self.used_bytes = self.used_bytes.saturating_sub(bytes);
    }
}

#[derive(Debug)]
pub struct CpuBudget {
    pub max_microseconds: u64,
}

/// Cooperative cancellation flag threaded through long operations.
#[derive(Debug, Default)]
pub struct CancellationToken {
    cancelled: AtomicBool,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Mandatory isolation object for a runtime task: read point + resource limits.
pub struct ExecutionContext {
    pub snapshot_lsn: Lsn,
    pub memory_budget: std::sync::Mutex<MemoryBudget>,
    pub cpu_budget: CpuBudget,
    pub cancellation: std::sync::Arc<CancellationToken>,
}

impl ExecutionContext {
    pub fn new(snapshot_lsn: Lsn, mem_cap: usize, cpu_micros: u64) -> Self {
        Self {
            snapshot_lsn,
            memory_budget: std::sync::Mutex::new(MemoryBudget::new(mem_cap)),
            cpu_budget: CpuBudget { max_microseconds: cpu_micros },
            cancellation: std::sync::Arc::new(CancellationToken::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_visibility_by_snapshot() {
        let seg = |id, f, l| SegmentDescriptor {
            segment_id: id,
            first_lsn: f,
            last_lsn: l,
            event_count: l - f + 1,
            payload_hash: [0; 32],
            state: SegmentState::Frozen,
        };
        let m = DatabaseManifest {
            segments: vec![seg(0, 0, 9), seg(1, 10, 19), seg(2, 20, 29)],
            cumulative_watermark: 29,
            ..Default::default()
        };
        // A snapshot at LSN 15 sees the first two segments only.
        let ids: Vec<_> = m.visible_segments(15).map(|s| s.segment_id).collect();
        assert_eq!(ids, vec![0, 1]);
    }

    #[test]
    fn memory_budget_guards_oom() {
        let mut b = MemoryBudget::new(1000);
        assert!(b.try_reserve(600).is_ok());
        assert!(b.try_reserve(600).is_err(), "must reject over-cap reservation");
        assert_eq!(b.used_bytes, 600);
        b.release(600);
        assert!(b.try_reserve(1000).is_ok());
    }

    #[test]
    fn cancellation_token_flips_once() {
        let ctx = ExecutionContext::new(42, 4096, 1_000_000);
        assert!(!ctx.cancellation.is_cancelled());
        ctx.cancellation.cancel();
        assert!(ctx.cancellation.is_cancelled());
        assert_eq!(ctx.snapshot_lsn, 42);
    }

    /// A trivial in-memory `StorageEngine` proves the contract is implementable.
    #[test]
    fn storage_engine_contract_is_implementable() {
        use std::sync::Mutex;
        #[derive(Default)]
        struct MemStore {
            log: Mutex<Vec<Vec<u8>>>,
        }
        impl StorageEngine for MemStore {
            fn append_raw(&self, payload: &[u8]) -> Result<Lsn, String> {
                let mut l = self.log.lock().unwrap();
                l.push(payload.to_vec());
                Ok((l.len() - 1) as Lsn)
            }
            fn fetch_segment(&self, segment_id: SegmentId) -> Result<Vec<u8>, String> {
                self.log
                    .lock()
                    .unwrap()
                    .get(segment_id as usize)
                    .cloned()
                    .ok_or_else(|| "no such segment".into())
            }
            fn write_manifest(&self, _m: &DatabaseManifest) -> Result<(), String> {
                Ok(())
            }
            fn sync_active_segment(&self) -> Result<(), String> {
                Ok(())
            }
        }
        let s = MemStore::default();
        let lsn = s.append_raw(b"hello").unwrap();
        assert_eq!(s.fetch_segment(lsn).unwrap(), b"hello");
    }
}
