//! SPEC-028 artifact registry (JIT structure catalog) + SPEC-031 dependency
//! DAG with cascading eviction.
//!
//! Ephemeral accelerator structures (CSR matrices, roaring filters, HNSW
//! caches) are catalogued by their `QueryFingerprint` so a compatible structure
//! already in RAM is reused (`lookup` hit = zero-I/O share) instead of rebuilt.
//! Each artifact records what it `depends_on`; evicting a node under memory
//! pressure cascades to every downstream artifact, so no dangling structure is
//! ever left pointing at freed memory (SPEC-031 safety invariant).

use crate::runtime::{ArtifactType, QueryFingerprint};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ArtifactDescriptor {
    pub artifact_id: u64,
    pub fingerprint: QueryFingerprint,
    pub artifact_type: ArtifactType,
    pub memory_footprint_bytes: usize,
    pub last_used_tick: u64,
    pub reuse_frequency: u32,
    pub depends_on: Vec<u64>,
    pub downstream: Vec<u64>,
}

#[derive(Default)]
pub struct ArtifactRegistry {
    next_id: u64,
    tick: u64,
    by_id: HashMap<u64, ArtifactDescriptor>,
    by_fingerprint: HashMap<QueryFingerprint, u64>,
}

impl ArtifactRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn bump(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Register a freshly compiled artifact, wiring the dependency DAG in both
    /// directions. Returns its id.
    pub fn register(
        &mut self,
        fingerprint: QueryFingerprint,
        artifact_type: ArtifactType,
        memory_footprint_bytes: usize,
        depends_on: Vec<u64>,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let tick = self.bump();
        for dep in &depends_on {
            if let Some(d) = self.by_id.get_mut(dep) {
                d.downstream.push(id);
            }
        }
        self.by_fingerprint.insert(fingerprint, id);
        self.by_id.insert(
            id,
            ArtifactDescriptor {
                artifact_id: id,
                fingerprint,
                artifact_type,
                memory_footprint_bytes,
                last_used_tick: tick,
                reuse_frequency: 0,
                depends_on,
                downstream: Vec::new(),
            },
        );
        id
    }

    /// Look up a compatible artifact by intent. A hit bumps its reuse counter
    /// and recency (so the LRU victim selection stays fair).
    pub fn lookup(&mut self, fingerprint: &QueryFingerprint) -> Option<u64> {
        let id = *self.by_fingerprint.get(fingerprint)?;
        let tick = self.bump();
        let d = self.by_id.get_mut(&id)?;
        d.reuse_frequency += 1;
        d.last_used_tick = tick;
        Some(id)
    }

    pub fn total_memory(&self) -> usize {
        self.by_id.values().map(|d| d.memory_footprint_bytes).sum()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn contains(&self, id: u64) -> bool {
        self.by_id.contains_key(&id)
    }

    /// SPEC-031 cascade: evict `id` and, recursively, every artifact that
    /// depends on it. Returns all evicted ids. No orphan may survive pointing
    /// at freed memory.
    pub fn evict(&mut self, id: u64) -> Vec<u64> {
        let mut removed = Vec::new();
        let mut stack = vec![id];
        while let Some(cur) = stack.pop() {
            if let Some(d) = self.by_id.remove(&cur) {
                self.by_fingerprint.remove(&d.fingerprint);
                stack.extend(d.downstream.iter().copied());
                removed.push(cur);
            }
        }
        // Drop dangling depends_on references in survivors.
        for d in self.by_id.values_mut() {
            d.downstream.retain(|c| !removed.contains(c));
            d.depends_on.retain(|p| !removed.contains(p));
        }
        removed
    }

    /// Evict the least-recently-used root (and its cascade) to relieve memory
    /// pressure. Returns the evicted ids, or `None` if empty.
    pub fn evict_lru(&mut self) -> Option<Vec<u64>> {
        let victim = self
            .by_id
            .values()
            .min_by_key(|d| d.last_used_tick)
            .map(|d| d.artifact_id)?;
        Some(self.evict(victim))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u8) -> QueryFingerprint {
        QueryFingerprint { logical_intent_hash: [n; 32], applicable_snapshot: n as u64 }
    }

    #[test]
    fn reuse_hit_bumps_frequency() {
        let mut r = ArtifactRegistry::new();
        let a = r.register(fp(1), ArtifactType::CompressedSparseRow, 100, vec![]);
        assert_eq!(r.lookup(&fp(1)), Some(a));
        assert_eq!(r.lookup(&fp(1)), Some(a));
        assert_eq!(r.by_id[&a].reuse_frequency, 2);
        assert_eq!(r.lookup(&fp(99)), None);
    }

    #[test]
    fn eviction_cascades_to_all_downstream() {
        let mut r = ArtifactRegistry::new();
        // A ← B ← C  and A ← D (D independent of B/C).
        let a = r.register(fp(1), ArtifactType::RoaringBitmapFilter, 10, vec![]);
        let b = r.register(fp(2), ArtifactType::CompressedSparseRow, 20, vec![a]);
        let c = r.register(fp(3), ArtifactType::CompressedSparseRow, 40, vec![b]);
        let d = r.register(fp(4), ArtifactType::VectorCacheHnsw, 80, vec![a]);
        assert_eq!(r.total_memory(), 150);

        // Evicting A must take B, C and D with it (all transitively depend on A).
        let mut removed = r.evict(a);
        removed.sort();
        assert_eq!(removed, vec![a, b, c, d]);
        assert!(r.is_empty());
        assert_eq!(r.total_memory(), 0);
    }

    #[test]
    fn evict_lru_picks_oldest_root() {
        let mut r = ArtifactRegistry::new();
        let a = r.register(fp(1), ArtifactType::RoaringBitmapFilter, 10, vec![]);
        let _b = r.register(fp(2), ArtifactType::RoaringBitmapFilter, 10, vec![]);
        // Touch A so B becomes the least-recently-used.
        r.lookup(&fp(1));
        let evicted = r.evict_lru().unwrap();
        assert_eq!(evicted.len(), 1);
        assert!(r.contains(a));
    }
}
