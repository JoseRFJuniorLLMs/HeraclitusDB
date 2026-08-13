//! SPEC-010 wiring — segment-level skip-I/O scan over the real log.
//!
//! Builds a [`ZoneMap`](crate::zone_map::ZoneMap) per sealed segment (once,
//! cached) and then answers predicate scans by *skipping* any segment whose
//! zone map proves it cannot match — those segments incur zero read I/O. This
//! is the concrete skip-I/O of SPEC-010, wired on top of the log's public API
//! (`sealed_segments` + `scan`), so it touches neither the write nor the seal
//! hot path.
//!
//! Granularity: sealed segments. The active (unsealed) tail has no footer/zone
//! map yet and is always included. Persisting each zone map into the segment
//! footer (to drop the one-time warm read) is the next optimization.
//!
//! Safety invariant (tested): pruning may return extra events from a mixed
//! segment, but it must NEVER drop an event the predicate would accept.

use crate::zone_map::ZoneMap;
use crate::{Log, SegmentMeta};
use heraclitus_core::{Episode, HeraclitusError, Lsn, SegmentId};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PruneStats {
    pub segments_considered: usize,
    pub segments_skipped: usize,
    pub episodes_returned: usize,
}

pub struct SkipScanner {
    log: Arc<Log>,
    cache: Mutex<HashMap<SegmentId, Arc<ZoneMap>>>,
    /// Zone maps built from a full segment scan (cold).
    built: AtomicUsize,
    /// Zone maps loaded from the persisted `.zmap` sidecar (cheap).
    loaded: AtomicUsize,
}

impl SkipScanner {
    /// Owns an `Arc<Log>` so a backend can keep ONE scanner alive across
    /// queries — the in-RAM zone-map cache then pays off on every hit
    /// (SPEC-028 reuse), not just within a single scan.
    pub fn new(log: Arc<Log>) -> Self {
        Self {
            log,
            cache: Mutex::new(HashMap::new()),
            built: AtomicUsize::new(0),
            loaded: AtomicUsize::new(0),
        }
    }

    /// `(built, loaded)` — how many zone maps were rebuilt from a full segment
    /// scan vs. loaded from the persisted sidecar. On a warm data dir a fresh
    /// scanner should load everything and build nothing.
    pub fn build_stats(&self) -> (usize, usize) {
        (self.built.load(Ordering::Relaxed), self.loaded.load(Ordering::Relaxed))
    }

    /// Drop one segment's zone map from the in-RAM cache (SPEC-031 eviction
    /// hook — the ArtifactRegistry drives WHAT to evict; this executes it).
    /// The persisted sidecar survives, so a later query reloads it cheaply.
    pub fn evict(&self, seg: SegmentId) -> bool {
        self.cache.lock().unwrap().remove(&seg).is_some()
    }

    /// Number of zone maps currently held in RAM.
    pub fn cached(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Path of a segment's derived zone-map sidecar (`<id>.zmap`). Derived and
    /// disposable — deleting it just forces a rebuild; the log is untouched.
    fn sidecar_path(&self, id: SegmentId) -> PathBuf {
        self.log.dir().join(format!("{id:020}.zmap"))
    }

    /// Zone map for a sealed segment. Resolution order: in-RAM cache → persisted
    /// `.zmap` sidecar (small read, no segment scan) → build from the segment
    /// once and persist the sidecar for next time.
    fn zone_map_for(&self, meta: &SegmentMeta) -> Result<Arc<ZoneMap>, HeraclitusError> {
        if let Some(z) = self.cache.lock().unwrap().get(&meta.id) {
            return Ok(z.clone());
        }
        // Try the persisted sidecar first (avoids the full-segment warm read).
        let path = self.sidecar_path(meta.id);
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok((zm, _)) = bincode::serde::decode_from_slice::<ZoneMap, _>(&bytes, BINCODE_CFG) {
                let zm = Arc::new(zm);
                self.cache.lock().unwrap().insert(meta.id, zm.clone());
                self.loaded.fetch_add(1, Ordering::Relaxed);
                return Ok(zm);
            }
            // Corrupt/old sidecar: fall through and rebuild (never fatal).
        }
        let eps = self.log.scan(meta.base_lsn, meta.max_lsn + 1)?;
        let zm = Arc::new(ZoneMap::build(eps.iter().map(|(l, e)| (*l, e))));
        self.persist_sidecar(&path, &zm);
        self.cache.lock().unwrap().insert(meta.id, zm.clone());
        self.built.fetch_add(1, Ordering::Relaxed);
        Ok(zm)
    }

    /// Atomically write the sidecar (tmp + rename). Best-effort: a write failure
    /// is non-fatal (the zone map stays in RAM; next run just rebuilds it).
    fn persist_sidecar(&self, path: &std::path::Path, zm: &ZoneMap) {
        if let Ok(bytes) = bincode::serde::encode_to_vec(zm, BINCODE_CFG) {
            let tmp = path.with_extension("zmap.tmp");
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    /// Pre-build every sealed segment's zone map, so a subsequent `scan_pruned`
    /// pays zero I/O for the segments it skips. Returns how many were warmed.
    pub fn warm(&self) -> Result<usize, HeraclitusError> {
        let segs = self.log.sealed_segments();
        for m in &segs {
            self.zone_map_for(m)?;
        }
        Ok(segs.len())
    }

    /// Scan, skipping any sealed segment whose zone map proves it cannot match
    /// `may_match`. Build predicates from `ZoneMap::may_*`, e.g.
    /// `|z| z.may_contain_agent("alice")`.
    pub fn scan_pruned<F>(
        &self,
        may_match: F,
    ) -> Result<(Vec<(Lsn, Episode)>, PruneStats), HeraclitusError>
    where
        F: Fn(&ZoneMap) -> bool,
    {
        let mut out = Vec::new();
        let mut stats = PruneStats::default();

        let mut sealed = self.log.sealed_segments();
        sealed.sort_by_key(|m| m.base_lsn);
        let mut next = 0u64;
        for meta in &sealed {
            stats.segments_considered += 1;
            let zm = self.zone_map_for(meta)?;
            if may_match(&zm) {
                out.extend(self.log.scan(meta.base_lsn, meta.max_lsn + 1)?);
            } else {
                stats.segments_skipped += 1;
            }
            next = meta.max_lsn + 1;
        }

        // Active (unsealed) tail: no footer yet, always included.
        let head = self.log.head();
        if next < head {
            out.extend(self.log.scan(next, head)?);
        }

        stats.episodes_returned = out.len();
        Ok((out, stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{EventKind, FsyncPolicy};

    fn ep(agent: &str, i: usize) -> Episode {
        Episode::new(
            agent,
            EventKind::Observation,
            format!("payload-{agent}-{i:04}-xxxxxxxxxxxxxxxxxxxxxxxx").into_bytes(),
        )
    }

    #[test]
    fn skip_scan_prunes_segments_but_never_drops_a_match() {
        let dir = tempfile::tempdir().unwrap();
        // Small segments → many sealed segments, so whole segments are alice-only
        // or bob-only and become skippable.
        let log = std::sync::Arc::new(Log::open(dir.path(), 2048, FsyncPolicy::Always).unwrap());
        for i in 0..80 {
            log.append(ep("alice", i)).unwrap();
        }
        for i in 0..80 {
            log.append(ep("bob", i)).unwrap();
        }
        for i in 0..80 {
            log.append(ep("alice", i)).unwrap();
        }
        assert!(
            log.sealed_segments().len() >= 3,
            "need multiple sealed segments to demonstrate skipping"
        );

        let scanner = SkipScanner::new(log.clone());
        scanner.warm().unwrap();

        // Query agent = "bob": alice-only segments must be skipped (zero I/O).
        let (res, stats) = scanner.scan_pruned(|z| z.may_contain_agent("bob")).unwrap();
        assert!(
            stats.segments_skipped > 0,
            "expected to skip alice-only segments, stats={stats:?}"
        );
        assert!(stats.segments_skipped < stats.segments_considered);

        // Safety invariant: every "bob" event a full scan would return is still
        // present — pruning skips segments but never drops a match.
        let full = log.scan(0, log.head()).unwrap();
        let bobs_full: Vec<Lsn> = full
            .iter()
            .filter(|(_, e)| e.agent_id == "bob")
            .map(|(l, _)| *l)
            .collect();
        let bobs_res: Vec<Lsn> = res
            .iter()
            .filter(|(_, e)| e.agent_id == "bob")
            .map(|(l, _)| *l)
            .collect();
        assert_eq!(bobs_full, bobs_res, "pruning must never drop a matching event");
        assert_eq!(bobs_full.len(), 80);
    }

    #[test]
    fn persisted_sidecars_avoid_the_warm_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let log = std::sync::Arc::new(Log::open(dir.path(), 2048, FsyncPolicy::Always).unwrap());
        for i in 0..120 {
            log.append(ep(if i % 2 == 0 { "alice" } else { "bob" }, i)).unwrap();
        }
        let n_sealed = log.sealed_segments().len();
        assert!(n_sealed >= 2);

        // First scanner: cold — builds every zone map and persists a sidecar.
        let s1 = SkipScanner::new(log.clone());
        s1.warm().unwrap();
        let (built1, loaded1) = s1.build_stats();
        assert_eq!(built1, n_sealed, "cold run builds all");
        assert_eq!(loaded1, 0);

        // Second scanner (fresh cache, same data dir) — loads every zone map from
        // the persisted sidecar, scanning zero full segments to build them.
        let s2 = SkipScanner::new(log.clone());
        let (_res, stats) = s2.scan_pruned(|z| z.may_contain_agent("bob")).unwrap();
        let (built2, loaded2) = s2.build_stats();
        assert_eq!(built2, 0, "warm data dir must rebuild nothing");
        assert_eq!(loaded2, n_sealed, "all zone maps loaded from sidecars");
        // Still correct: bob lives in every segment here, so nothing is skipped,
        // but the mechanism resolved purely from sidecars.
        assert_eq!(stats.segments_considered, n_sealed);
    }
}
