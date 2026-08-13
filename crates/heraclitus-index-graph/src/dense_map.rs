//! SPEC-009 — dense entity map.
//!
//! Projects sparse 128-bit `EventId`s (ULIDs) onto contiguous `u32` dense ids
//! assigned in insertion (LSN-replay) order. Dense ids pack ~16/cache-line vs
//! ~4 for the raw ULID, which is what makes CSR adjacency and SIMD-friendly
//! scans possible downstream (SPEC-009 §5-6).
//!
//! Adapted from the SPEC-009 draft to the *real* `heraclitus_core::EventId`
//! (a `ulid::Ulid` newtype), not the draft's `[u8; 16]`.
//!
//! Lifecycle: a mutable [`DenseEntityMap`] ingests during replay, then
//! [`DenseEntityMap::optimize_and_freeze`] publishes an immutable, lock-free,
//! `Arc`-shareable [`FrozenDenseEntityMap`] for the analytical read path.

use heraclitus_core::EventId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;

/// Phase 1 (Replay): mutable, single-writer, throughput-oriented.
#[derive(Default)]
pub struct DenseEntityMap {
    forward: HashMap<EventId, u32>,
    backward: Vec<EventId>,
}

impl DenseEntityMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            forward: HashMap::with_capacity(capacity),
            backward: Vec::with_capacity(capacity),
        }
    }

    /// Allocate (or return the existing) contiguous dense id for `event_id`.
    /// Ids are handed out `0, 1, 2, …` in first-seen order — deterministic
    /// under a fixed replay order. Single `Entry` lookup (no double hashing).
    pub fn get_or_alloc(&mut self, event_id: EventId) -> u32 {
        match self.forward.entry(event_id) {
            Entry::Occupied(e) => *e.get(),
            Entry::Vacant(e) => {
                let id = self.backward.len() as u32;
                self.backward.push(event_id);
                e.insert(id);
                id
            }
        }
    }

    pub fn lookup_id(&self, event_id: &EventId) -> Option<u32> {
        self.forward.get(event_id).copied()
    }

    pub fn lookup_event(&self, id: u32) -> Option<EventId> {
        self.backward.get(id as usize).copied()
    }

    pub fn len(&self) -> usize {
        self.backward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backward.is_empty()
    }

    /// All mapped events in dense-id order (`events()[i]` has dense id `i`).
    /// This is the LSN-replay order, so iterating it is deterministic.
    pub fn events(&self) -> &[EventId] {
        &self.backward
    }

    /// Rebuild from a dense-ordered event list (checkpoint restore): the ids
    /// are re-assigned `0..n` in slice order, matching the original mapping.
    pub fn from_events(events: Vec<EventId>) -> Self {
        let forward = events
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i as u32))
            .collect();
        Self { forward, backward: events }
    }

    /// Phase 2+3 (Optimize → Freeze): publish an immutable, shareable view.
    /// Phase 2 (physical renumbering for cache affinity) is intentionally a
    /// no-op here; any such permutation MUST keep `forward`/`backward` in sync
    /// before freezing.
    pub fn optimize_and_freeze(self) -> FrozenDenseEntityMap {
        FrozenDenseEntityMap {
            forward: Arc::new(self.forward),
            backward: Arc::from(self.backward),
        }
    }
}

/// Phase 3 (Freeze): immutable, lock-free, `Arc`-shareable across analytical
/// threads with zero atomics on the read path.
#[derive(Clone)]
pub struct FrozenDenseEntityMap {
    forward: Arc<HashMap<EventId, u32>>,
    backward: Arc<[EventId]>,
}

impl FrozenDenseEntityMap {
    #[inline]
    pub fn lookup_id(&self, event_id: &EventId) -> Option<u32> {
        self.forward.get(event_id).copied()
    }

    #[inline]
    pub fn lookup_event(&self, id: u32) -> Option<EventId> {
        self.backward.get(id as usize).copied()
    }

    pub fn len(&self) -> usize {
        self.backward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backward.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eid() -> EventId {
        EventId::new()
    }

    #[test]
    fn allocates_contiguous_ids_in_order() {
        let mut m = DenseEntityMap::new();
        let (a, b, c) = (eid(), eid(), eid());
        assert_eq!(m.get_or_alloc(a), 0);
        assert_eq!(m.get_or_alloc(b), 1);
        assert_eq!(m.get_or_alloc(c), 2);
        // Re-allocating a known id is idempotent.
        assert_eq!(m.get_or_alloc(a), 0);
        assert_eq!(m.get_or_alloc(b), 1);
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn bidirectional_lookup_survives_freeze() {
        let mut m = DenseEntityMap::with_capacity(4);
        let ids: Vec<EventId> = (0..4).map(|_| eid()).collect();
        for id in &ids {
            m.get_or_alloc(*id);
        }
        let frozen = m.optimize_and_freeze();
        assert_eq!(frozen.len(), 4);
        for (dense, id) in ids.iter().enumerate() {
            assert_eq!(frozen.lookup_id(id), Some(dense as u32));
            assert_eq!(frozen.lookup_event(dense as u32), Some(*id));
        }
        // Cheap to share across threads.
        let clone = frozen.clone();
        assert_eq!(clone.lookup_event(0), frozen.lookup_event(0));
    }

    #[test]
    fn deterministic_under_same_insertion_order() {
        let ids: Vec<EventId> = (0..16).map(|_| eid()).collect();
        let build = || {
            let mut m = DenseEntityMap::new();
            for id in &ids {
                m.get_or_alloc(*id);
            }
            m.optimize_and_freeze()
        };
        let (a, b) = (build(), build());
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(a.lookup_id(id), b.lookup_id(id));
            assert_eq!(a.lookup_event(i as u32), b.lookup_event(i as u32));
        }
    }
}
