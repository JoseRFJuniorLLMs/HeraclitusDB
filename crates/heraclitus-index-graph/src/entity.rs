//! entity.rs — M11: deterministic, temporal entity resolution.
//!
//! Identity is **not mutable state** — it is derived from the append-only log,
//! like every other view. Two signals, both replay-stable:
//!
//! 1. **Key collapse.** An event that mentions a resolution key (`attrs
//!    ["entity_key"]`, e.g. a CPF/CNPJ) maps to a canonical entity. Records
//!    sharing a key collapse onto the same entity for free — the canonical id
//!    of a fresh key is the key itself.
//! 2. **Merge / split.** An `er_op = "merge"` event unifies two keys' groups;
//!    `er_op = "split"` re-isolates a key. The survivor of a merge is the
//!    lexicographically smaller canonical id, so the outcome is independent of
//!    the order merges are *discovered* in (only the log order, which is fixed,
//!    drives the temporal intervals).
//!
//! Every assignment is an interval `[valid_from_lsn, valid_to_lsn)`, so identity
//! travels in time: `AS OF` before a merge sees the entities apart, after sees
//! them as one. A re-merge or re-split is idempotent — replay is deterministic.

use std::collections::{BTreeMap, BTreeSet};

pub type Lsn = u64;
pub type Key = String; // resolution key, e.g. "CPF:111"
pub type EntityId = String; // canonical entity id

/// One canonical assignment of a key, valid over the half-open LSN interval
/// `[valid_from_lsn, valid_to_lsn)`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EntityInterval {
    pub entity_id: EntityId,
    pub valid_from_lsn: Lsn,
    pub valid_to_lsn: Option<Lsn>,
}

impl EntityInterval {
    pub fn alive_at(&self, at: Lsn) -> bool {
        self.valid_from_lsn <= at && self.valid_to_lsn.is_none_or(|to| at < to)
    }
}

/// Deterministic temporal entity resolver (M11). Materialized view over the log.
#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntityResolver {
    /// Append-only temporal record: key → its assignment intervals.
    pub mappings: BTreeMap<Key, Vec<EntityInterval>>,
    /// Which events mentioned each key (audit / clustering). A set → idempotent.
    pub mentions: BTreeMap<Key, BTreeSet<String>>,
    /// Head-state canonical per key (drives merge/split processing).
    canonical: BTreeMap<Key, EntityId>,
    /// Head-state members per canonical.
    groups: BTreeMap<EntityId, BTreeSet<Key>>,
    pub watermark: Lsn,
}

impl EntityResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create the canonical assignment for a never-seen key (id = the key).
    fn ensure_canonical(&mut self, key: &str, lsn: Lsn) {
        if self.canonical.contains_key(key) {
            return;
        }
        self.canonical.insert(key.to_string(), key.to_string());
        self.groups
            .entry(key.to_string())
            .or_default()
            .insert(key.to_string());
        self.mappings
            .entry(key.to_string())
            .or_default()
            .push(EntityInterval {
                entity_id: key.to_string(),
                valid_from_lsn: lsn,
                valid_to_lsn: None,
            });
    }

    /// Record that `event` mentioned `key` (and ensure the key exists).
    fn record_mention(&mut self, key: &str, lsn: Lsn, event: &str) {
        self.ensure_canonical(key, lsn);
        self.mentions
            .entry(key.to_string())
            .or_default()
            .insert(event.to_string());
    }

    /// Close the currently-open interval of `key` at `at` (if any).
    fn close_open(&mut self, key: &str, at: Lsn) {
        if let Some(last) = self.mappings.get_mut(key).and_then(|v| v.last_mut()) {
            if last.valid_to_lsn.is_none() {
                last.valid_to_lsn = Some(at);
            }
        }
    }

    /// Merge the groups of `a` and `b` at `lsn`. Survivor = min canonical id.
    /// Idempotent: already-unified keys are a no-op.
    fn merge_keys(&mut self, a: &str, b: &str, lsn: Lsn) {
        self.ensure_canonical(a, lsn);
        self.ensure_canonical(b, lsn);
        let ca = self.canonical[a].clone();
        let cb = self.canonical[b].clone();
        if ca == cb {
            return;
        }
        let (surv, other) = if ca <= cb { (ca, cb) } else { (cb, ca) };
        let members: Vec<Key> = self
            .groups
            .get(&other)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        for key in members {
            self.close_open(&key, lsn);
            self.mappings
                .entry(key.clone())
                .or_default()
                .push(EntityInterval {
                    entity_id: surv.clone(),
                    valid_from_lsn: lsn,
                    valid_to_lsn: None,
                });
            self.canonical.insert(key.clone(), surv.clone());
            self.groups.entry(surv.clone()).or_default().insert(key);
        }
        self.groups.remove(&other);
    }

    /// Re-isolate `key` under a fresh deterministic id `key@lsn` from `lsn` on.
    /// Idempotent at a given lsn.
    fn split_key(&mut self, key: &str, lsn: Lsn) {
        if !self.canonical.contains_key(key) {
            return;
        }
        let new_id = format!("{key}@{lsn}");
        if self.canonical.get(key) == Some(&new_id) {
            return; // already split at this lsn
        }
        let old = self.canonical[key].clone();
        self.close_open(key, lsn);
        self.mappings
            .entry(key.to_string())
            .or_default()
            .push(EntityInterval {
                entity_id: new_id.clone(),
                valid_from_lsn: lsn,
                valid_to_lsn: None,
            });
        self.canonical.insert(key.to_string(), new_id.clone());
        if let Some(g) = self.groups.get_mut(&old) {
            g.remove(key);
        }
        self.groups
            .entry(new_id)
            .or_default()
            .insert(key.to_string());
    }

    /// Derive resolution from one event. `er_op`: `merge` (er_a, er_b) | `split`
    /// (er_key); otherwise a mention via `entity_key`.
    pub fn apply_episode(&mut self, lsn: Lsn, e: &heraclitus_core::Episode) {
        match e.attrs.get("er_op").map(|s| s.as_str()) {
            Some("merge") => {
                if let (Some(a), Some(b)) = (e.attrs.get("er_a"), e.attrs.get("er_b")) {
                    self.merge_keys(a, b, lsn);
                }
            }
            Some("split") => {
                if let Some(k) = e.attrs.get("er_key") {
                    self.split_key(k, lsn);
                }
            }
            _ => {
                if let Some(key) = e.attrs.get("entity_key") {
                    self.record_mention(key, lsn, &e.id.to_string());
                }
            }
        }
        self.watermark = self.watermark.max(lsn);
    }

    /// Canonical entity of `key` as of `as_of` (the interval that contains it).
    pub fn resolve(&self, key: &str, as_of: Lsn) -> Option<EntityId> {
        self.mappings
            .get(key)?
            .iter()
            .find(|iv| iv.alive_at(as_of))
            .map(|iv| iv.entity_id.clone())
    }

    /// All keys that resolve to `entity_id` as of `as_of` (sorted, deterministic).
    pub fn cluster(&self, entity_id: &str, as_of: Lsn) -> Vec<Key> {
        self.mappings
            .keys()
            .filter(|k| self.resolve(k, as_of).as_deref() == Some(entity_id))
            .cloned()
            .collect()
    }

    /// Deterministic state hash (blake3) — the replay contract (M11).
    pub fn state_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for (key, ivs) in &self.mappings {
            h.update(key.as_bytes());
            for iv in ivs {
                h.update(iv.entity_id.as_bytes());
                h.update(&iv.valid_from_lsn.to_le_bytes());
                h.update(&iv.valid_to_lsn.unwrap_or(u64::MAX).to_le_bytes());
            }
        }
        for (key, evs) in &self.mentions {
            h.update(key.as_bytes());
            for ev in evs {
                h.update(ev.as_bytes());
            }
        }
        *h.finalize().as_bytes()
    }
}

impl heraclitus_views::View for EntityResolver {
    fn name(&self) -> &str {
        "entity"
    }
    fn apply(&mut self, lsn: heraclitus_core::Lsn, event: &heraclitus_core::Episode) {
        self.apply_episode(lsn, event);
    }
    fn watermark(&self) -> heraclitus_core::Lsn {
        self.watermark
    }
    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), heraclitus_core::HeraclitusError> {
        heraclitus_views::ckpt::save(dir, "entity", self)
    }
    fn restore(&mut self, dir: &std::path::Path) -> Result<bool, heraclitus_core::HeraclitusError> {
        match heraclitus_views::ckpt::load::<EntityResolver>(dir, "entity")? {
            Some(r) => {
                *self = r;
                Ok(true)
            }
            None => Ok(false),
        }
    }
    fn reset(&mut self) {
        *self = EntityResolver::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind};
    use heraclitus_views::View;

    fn mention(key: &str) -> Episode {
        let mut e = Episode::new("ag", EventKind::Observation, vec![]);
        e.attrs.insert("entity_key".into(), key.into());
        e
    }
    fn merge(a: &str, b: &str) -> Episode {
        let mut e = Episode::new("ag", EventKind::Observation, vec![]);
        e.attrs.insert("er_op".into(), "merge".into());
        e.attrs.insert("er_a".into(), a.into());
        e.attrs.insert("er_b".into(), b.into());
        e
    }
    fn split(key: &str) -> Episode {
        let mut e = Episode::new("ag", EventKind::Observation, vec![]);
        e.attrs.insert("er_op".into(), "split".into());
        e.attrs.insert("er_key".into(), key.into());
        e
    }

    #[test]
    fn duplicate_keys_collapse() {
        // CPF/CNPJ duplicates collapse with no merge needed.
        let mut r = EntityResolver::new();
        r.apply_episode(0, &mention("CPF:111"));
        r.apply_episode(1, &mention("CPF:111")); // a second record, same CPF
        assert_eq!(r.resolve("CPF:111", u64::MAX).as_deref(), Some("CPF:111"));
        assert_eq!(r.mentions["CPF:111"].len(), 2, "both records recorded");
        assert_eq!(r.cluster("CPF:111", u64::MAX), vec!["CPF:111"]);
    }

    #[test]
    fn merge_is_temporal() {
        // Two entities, merged at lsn 5: apart before, one entity after.
        let log = vec![
            (0u64, mention("CPF:111")),
            (1, mention("CPF:222")),
            (5, merge("CPF:222", "CPF:111")),
        ];
        let mut r = EntityResolver::new();
        for (lsn, e) in &log {
            r.apply_episode(*lsn, e);
        }
        // Before the merge they are distinct.
        assert_eq!(r.resolve("CPF:111", 4).as_deref(), Some("CPF:111"));
        assert_eq!(r.resolve("CPF:222", 4).as_deref(), Some("CPF:222"));
        // From the merge on, both resolve to the survivor (min canonical).
        assert_eq!(r.resolve("CPF:111", 5).as_deref(), Some("CPF:111"));
        assert_eq!(r.resolve("CPF:222", 5).as_deref(), Some("CPF:111"));
        let mut cluster = r.cluster("CPF:111", 6);
        cluster.sort();
        assert_eq!(cluster, vec!["CPF:111", "CPF:222"]);
    }

    #[test]
    fn split_re_isolates() {
        let mut r = EntityResolver::new();
        r.apply_episode(0, &mention("CPF:111"));
        r.apply_episode(1, &mention("CPF:222"));
        r.apply_episode(2, &merge("CPF:111", "CPF:222"));
        assert_eq!(r.resolve("CPF:222", 3).as_deref(), Some("CPF:111"));
        r.apply_episode(4, &split("CPF:222"));
        // After the split, 222 has its own id again; 111 is unaffected.
        assert_eq!(r.resolve("CPF:222", 5).as_deref(), Some("CPF:222@4"));
        assert_eq!(r.resolve("CPF:111", 5).as_deref(), Some("CPF:111"));
        // And AS OF before the split still sees them merged.
        assert_eq!(r.resolve("CPF:222", 3).as_deref(), Some("CPF:111"));
    }

    #[test]
    fn merge_survivor_is_order_independent() {
        // Merging in either direction yields the same survivor (min id).
        let mut r1 = EntityResolver::new();
        r1.apply_episode(0, &mention("B"));
        r1.apply_episode(1, &mention("A"));
        r1.apply_episode(2, &merge("A", "B"));

        let mut r2 = EntityResolver::new();
        r2.apply_episode(0, &mention("B"));
        r2.apply_episode(1, &mention("A"));
        r2.apply_episode(2, &merge("B", "A"));

        assert_eq!(r1.resolve("B", 3), r2.resolve("B", 3));
        assert_eq!(r1.resolve("B", 3).as_deref(), Some("A"));
    }

    #[test]
    fn replay_is_deterministic_and_idempotent() {
        // GATE M11: merge/split reproducible via replay (bit-identical hash).
        let log = vec![
            (0u64, mention("CPF:111")),
            (1, mention("CPF:222")),
            (2, mention("CPF:333")),
            (5, merge("CPF:222", "CPF:111")),
            (7, merge("CPF:333", "CPF:111")),
            (9, split("CPF:222")),
        ];
        let build = || {
            let mut r = EntityResolver::new();
            for (lsn, e) in &log {
                r.apply(*lsn, e);
            }
            r
        };
        let h = build().state_hash();
        assert_eq!(h, build().state_hash(), "replay must be bit-identical");

        // Idempotency at the delivery boundary: a duplicated event (the same
        // event applied twice in a row, as a crashed catch_up might) is a no-op.
        let mut r = EntityResolver::new();
        for (lsn, e) in &log {
            r.apply(*lsn, e);
            r.apply(*lsn, e); // duplicate delivery of the current event
        }
        assert_eq!(h, r.state_hash(), "duplicate delivery must be idempotent");
    }

    #[test]
    fn labeled_precision_is_perfect() {
        // Ground truth: {a1,a2,a3} are entity A; {b1,b2} are entity B.
        let log = vec![
            (0u64, mention("a1")),
            (1, mention("a2")),
            (2, mention("a3")),
            (3, mention("b1")),
            (4, mention("b2")),
            (5, merge("a1", "a2")),
            (6, merge("a2", "a3")),
            (7, merge("b1", "b2")),
        ];
        let mut r = EntityResolver::new();
        for (lsn, e) in &log {
            r.apply_episode(*lsn, e);
        }
        let now = u64::MAX;
        // All a* share one entity; all b* share another; the two differ.
        let ea = r.resolve("a1", now).unwrap();
        assert_eq!(r.resolve("a2", now).as_deref(), Some(ea.as_str()));
        assert_eq!(r.resolve("a3", now).as_deref(), Some(ea.as_str()));
        let eb = r.resolve("b1", now).unwrap();
        assert_eq!(r.resolve("b2", now).as_deref(), Some(eb.as_str()));
        assert_ne!(ea, eb, "A and B must not be conflated");
        assert_eq!(r.cluster(&ea, now).len(), 3);
        assert_eq!(r.cluster(&eb, now).len(), 2);
    }
}
