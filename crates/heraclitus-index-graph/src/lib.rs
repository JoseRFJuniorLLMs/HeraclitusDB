//! heraclitus-index-graph — derived adjacency / property indexes (§3.6).
//!
//! Adjacency comes from `Episode.parents` (causal provenance edges).
//! Property index maps `(attr_key, attr_value) -> bitmap of internal ids`
//! for ANN filter push-down.

use dashmap::DashMap;
use heraclitus_core::{Episode, EventId, Lsn};
use heraclitus_views::View;
use roaring::RoaringBitmap;
use std::collections::HashMap;

pub mod adaptive; // M17: regras aprendidas de feedback (threshold tuning)
pub mod decision; // M15: regras que agem (Action events no log)
pub mod dense_map; // SPEC-009: EventId → u32 denso (ordem de LSN)
pub mod entity; // M11: entity resolution determinística e temporal
pub mod provenance; // SPEC-014: provenance engine (WHY / minimal causal chain)
pub mod temporal; // M8: grafo temporal + probabilístico (RFC-004/005/006/007)

#[derive(Default)]
pub struct GraphIndex {
    /// parent -> children
    out: DashMap<EventId, Vec<EventId>>,
    /// child -> parents
    inn: DashMap<EventId, Vec<EventId>>,
    /// (key=value) -> internal id bitmap
    attr_idx: DashMap<String, RoaringBitmap>,
    /// SPEC-009 wired: event ↔ dense internal id (assigned in LSN order,
    /// deterministic) via the DenseEntityMap instead of an ad-hoc map pair.
    dense: dense_map::DenseEntityMap,
    /// event -> lsn (snapshot reads)
    lsn_of: HashMap<EventId, Lsn>,
    watermark: Lsn,
}

impl GraphIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn children(&self, id: &EventId) -> Vec<EventId> {
        self.out.get(id).map(|v| v.clone()).unwrap_or_default()
    }

    pub fn parents(&self, id: &EventId) -> Vec<EventId> {
        self.inn.get(id).map(|v| v.clone()).unwrap_or_default()
    }

    /// Walk provenance ancestors up to `depth` hops (PROVENANCE(fact), §3.12).
    pub fn ancestors(&self, id: &EventId, depth: usize) -> Vec<EventId> {
        // Membership em HashSet (o Vec::contains antigo era O(n²) em DAGs
        // profundos); o Vec preserva a ordem de descoberta para o chamador.
        let mut frontier = vec![*id];
        let mut seen: Vec<EventId> = Vec::new();
        let mut member: std::collections::HashSet<EventId> = std::collections::HashSet::new();
        for _ in 0..depth {
            let mut next = Vec::new();
            for f in &frontier {
                for p in self.parents(f) {
                    if member.insert(p) {
                        seen.push(p);
                        next.push(p);
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        seen
    }

    /// Bitmap of internal ids where `attrs[key] == value` (Eq filter).
    pub fn filter_eq(&self, key: &str, value: &str) -> RoaringBitmap {
        self.attr_idx
            .get(&format!("{key}={value}"))
            .map(|b| b.clone())
            .unwrap_or_default()
    }

    pub fn internal_id(&self, id: &EventId) -> Option<u32> {
        self.dense.lookup_id(id)
    }

    pub fn event_of_internal(&self, internal: u32) -> Option<EventId> {
        self.dense.lookup_event(internal)
    }

    pub fn lsn_of(&self, id: &EventId) -> Option<Lsn> {
        self.lsn_of.get(id).copied()
    }

    pub fn len(&self) -> usize {
        self.dense.len()
    }

    pub fn is_empty(&self) -> bool {
        self.dense.is_empty()
    }

    /// Canonical, deterministic BLAKE3 signature of the derived graph state
    /// (Fase 1.3 / M8–M18 acceptance gate — see docs/md/SPEC-new/PLANO-SPECS.md).
    ///
    /// Determinism by construction:
    /// - nodes are hashed in `by_internal` order — assigned in strict LSN order
    ///   during replay, so the digest survives a wipe + `rebuild(0)` unchanged;
    /// - out-edges are mapped to dense internal ids and **sorted**, so DashMap
    ///   iteration order can never leak into the hash;
    /// - all integers are big-endian, so the digest is identical on `x86_64`
    ///   and `AArch64` (no host-endianness dependence).
    pub fn state_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"HGRAPH-STATE-v1");
        h.update(&(self.dense.len() as u64).to_be_bytes());
        for (i, ev) in self.dense.events().iter().enumerate() {
            h.update(&(i as u32).to_be_bytes());
            h.update(&ev.0.to_bytes()); // 16-byte ULID identity
            // Children (out-edges) resolved to dense internal ids, then sorted.
            let mut outs: Vec<u32> = self
                .out
                .get(ev)
                .map(|v| v.iter().filter_map(|t| self.dense.lookup_id(t)).collect())
                .unwrap_or_default();
            outs.sort_unstable();
            h.update(&(outs.len() as u32).to_be_bytes());
            for t in outs {
                h.update(&t.to_be_bytes());
            }
        }
        *h.finalize().as_bytes()
    }
}

/// Snapshot serializável (fast boot). DashMaps viram Vec de pares; bitmaps
/// roaring vão no formato nativo (portável); `internal` reconstrói-se de
/// `by_internal` no restore.
#[derive(serde::Serialize, serde::Deserialize)]
struct GraphSnapshot {
    out: Vec<(EventId, Vec<EventId>)>,
    inn: Vec<(EventId, Vec<EventId>)>,
    attr: Vec<(String, Vec<u8>)>,
    by_internal: Vec<EventId>,
    lsn_of: Vec<(EventId, Lsn)>,
    watermark: Lsn,
}

impl View for GraphIndex {
    fn name(&self) -> &str {
        "graph"
    }

    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), heraclitus_core::HeraclitusError> {
        let mut attr = Vec::with_capacity(self.attr_idx.len());
        for e in self.attr_idx.iter() {
            let mut bytes = Vec::with_capacity(e.value().serialized_size());
            e.value()
                .serialize_into(&mut bytes)
                .map_err(|err| heraclitus_core::HeraclitusError::Serialization(err.to_string()))?;
            attr.push((e.key().clone(), bytes));
        }
        heraclitus_views::ckpt::save(
            dir,
            "graph",
            &GraphSnapshot {
                out: self
                    .out
                    .iter()
                    .map(|e| (*e.key(), e.value().clone()))
                    .collect(),
                inn: self
                    .inn
                    .iter()
                    .map(|e| (*e.key(), e.value().clone()))
                    .collect(),
                attr,
                by_internal: self.dense.events().to_vec(),
                lsn_of: self.lsn_of.iter().map(|(k, v)| (*k, *v)).collect(),
                watermark: self.watermark,
            },
        )
    }

    fn restore(&mut self, dir: &std::path::Path) -> Result<bool, heraclitus_core::HeraclitusError> {
        let Some(snap) = heraclitus_views::ckpt::load::<GraphSnapshot>(dir, "graph")? else {
            return Ok(false);
        };
        self.out = snap.out.into_iter().collect();
        self.inn = snap.inn.into_iter().collect();
        self.attr_idx = snap
            .attr
            .into_iter()
            .map(|(k, bytes)| {
                RoaringBitmap::deserialize_from(&bytes[..])
                    .map(|b| (k, b))
                    .map_err(|e| heraclitus_core::HeraclitusError::Serialization(e.to_string()))
            })
            .collect::<Result<_, _>>()?;
        self.dense = dense_map::DenseEntityMap::from_events(snap.by_internal);
        self.lsn_of = snap.lsn_of.into_iter().collect();
        self.watermark = snap.watermark;
        Ok(true)
    }

    fn apply(&mut self, lsn: Lsn, event: &Episode) {
        // Audit #9: idempotent replay must bail out entirely — continuing
        // would duplicate adjacency rows and index a wrong internal id.
        if self.dense.lookup_id(&event.id).is_some() {
            self.watermark = self.watermark.max(lsn); // avanço-só (entrega fora de ordem)
            return;
        }
        let internal = self.dense.get_or_alloc(event.id);
        self.lsn_of.insert(event.id, lsn);
        for parent in &event.parents {
            self.out.entry(*parent).or_default().push(event.id);
            self.inn.entry(event.id).or_default().push(*parent);
        }
        for (k, v) in &event.attrs {
            self.attr_idx
                .entry(format!("{k}={v}"))
                .or_default()
                .insert(internal);
        }
        self.watermark = self.watermark.max(lsn); // avanço-só (entrega fora de ordem)
    }

    fn watermark(&self) -> Lsn {
        self.watermark
    }

    fn reset(&mut self) {
        *self = GraphIndex::default();
    }

    fn state_hash(&self) -> Option<[u8; 32]> {
        Some(GraphIndex::state_hash(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::EventKind;

    #[test]
    fn adjacency_and_attrs() {
        let mut g = GraphIndex::new();
        let mut a = Episode::new("x", EventKind::Observation, b"a".to_vec());
        a.attrs.insert("topic".into(), "rivers".into());
        let mut b = Episode::new("x", EventKind::Observation, b"b".to_vec());
        b.parents.push(a.id);
        g.apply(0, &a);
        g.apply(1, &b);

        assert_eq!(g.children(&a.id), vec![b.id]);
        assert_eq!(g.parents(&b.id), vec![a.id]);
        assert_eq!(g.ancestors(&b.id, 3), vec![a.id]);
        assert!(g
            .filter_eq("topic", "rivers")
            .contains(g.internal_id(&a.id).unwrap()));
    }

    /// Build a small causal DAG once (stable ids reused across replays).
    fn dag() -> Vec<Episode> {
        let e0 = Episode::new("x", EventKind::Observation, b"e0".to_vec());
        let mut e1 = Episode::new("x", EventKind::Observation, b"e1".to_vec());
        e1.parents.push(e0.id);
        let mut e2 = Episode::new("x", EventKind::Observation, b"e2".to_vec());
        e2.parents.push(e0.id);
        e2.parents.push(e1.id);
        let mut e3 = Episode::new("x", EventKind::Observation, b"e3".to_vec());
        e3.parents.push(e2.id);
        vec![e0, e1, e2, e3]
    }

    fn hydrate(eps: &[Episode]) -> GraphIndex {
        let mut g = GraphIndex::new();
        for (i, e) in eps.iter().enumerate() {
            g.apply(i as u64, e);
        }
        g
    }

    #[test]
    fn state_hash_is_deterministic_across_wipe_and_replay() {
        // M8–M18 acceptance gate: a wipe + rebuild-from-0 yields a bit-identical
        // state_hash (zero-bit tolerance). `reset()` + re-apply is exactly what
        // `ViewRegistry::rebuild` does internally.
        let eps = dag();

        let mut g = hydrate(&eps);
        let h1 = g.state_hash();

        g.reset();
        assert!(g.is_empty(), "reset must clear all derived state");
        for (i, e) in eps.iter().enumerate() {
            g.apply(i as u64, e);
        }
        let h2 = g.state_hash();
        assert_eq!(h1, h2, "rebuild-from-0 must be bit-identical");

        // A fresh, independent index gives the same digest (no hidden global state).
        let g3 = hydrate(&eps);
        assert_eq!(h1, g3.state_hash());

        // Exposed identically through the View trait.
        assert_eq!(<GraphIndex as View>::state_hash(&g3), Some(h1));

        // Sanity: different content ⇒ different digest.
        let mut g4 = GraphIndex::new();
        g4.apply(0, &eps[0]);
        assert_ne!(h1, g4.state_hash(), "distinct states must not collide");
    }

    #[test]
    fn state_hash_ignores_dashmap_iteration_order() {
        // Two logically identical graphs built via the same LSN-ordered replay
        // must hash equal regardless of internal DashMap bucket layout.
        let eps = dag();
        assert_eq!(hydrate(&eps).state_hash(), hydrate(&eps).state_hash());
    }
}
