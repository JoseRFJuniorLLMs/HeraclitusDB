//! SPEC-010 §3 — Zone maps for predicate skip-I/O.
//!
//! A [`ZoneMap`] is a tiny per-segment summary (min/max of the selective
//! columns) that lets the scan planner *skip an entire segment without opening
//! it* when a query predicate provably cannot match. This is the disk-frontier
//! pruning of SPEC-010: `may_*` returns `false` ⇒ the segment is guaranteed not
//! to contain a match, so no I/O is issued.
//!
//! Correctness rule: `may_*` is a *conservative* filter — it may return `true`
//! for a segment that turns out to have no match (a false positive is only a
//! wasted read), but it must NEVER return `false` for a segment that does
//! contain a match (that would lose data). All bounds are inclusive.
//!
//! Status: this is the standalone primitive + its skip logic, unit-tested here.
//! Wiring it into the segment footer and the query planner's scan path is the
//! SPEC-010 integration step (tracked in docs/md/SPEC-new/PLANO-SPECS.md).

use heraclitus_core::{Episode, Lsn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Per-segment min/max summary over the selective columns.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ZoneMap {
    pub count: u64,
    /// Inclusive `(min, max)` LSN of the events summarized.
    pub lsn: Option<(Lsn, Lsn)>,
    /// Inclusive `(min, max)` HLC timestamp.
    pub ts_hlc: Option<(u64, u64)>,
    /// Inclusive lexicographic `(min, max)` agent id.
    pub agent: Option<(String, String)>,
    /// Inclusive lexicographic `(min, max)` session id.
    pub session: Option<(String, String)>,
    /// Per-attribute-key inclusive lexicographic `(min, max)` value.
    pub attrs: BTreeMap<String, (String, String)>,
}

fn fold_min_max<T: Ord + Clone>(slot: &mut Option<(T, T)>, v: T) {
    match slot {
        None => *slot = Some((v.clone(), v)),
        Some((lo, hi)) => {
            if v < *lo {
                *lo = v.clone();
            }
            if v > *hi {
                *hi = v;
            }
        }
    }
}

impl ZoneMap {
    /// Build a zone map by folding min/max over a segment's events.
    pub fn build<'a, I>(events: I) -> Self
    where
        I: IntoIterator<Item = (Lsn, &'a Episode)>,
    {
        let mut z = ZoneMap::default();
        for (lsn, ep) in events {
            z.count += 1;
            fold_min_max(&mut z.lsn, lsn);
            fold_min_max(&mut z.ts_hlc, ep.ts_hlc);
            fold_min_max(&mut z.agent, ep.agent_id.clone());
            fold_min_max(&mut z.session, ep.session_id.clone());
            for (k, v) in &ep.attrs {
                match z.attrs.get_mut(k) {
                    Some(bounds) => {
                        if *v < bounds.0 {
                            bounds.0 = v.clone();
                        }
                        if *v > bounds.1 {
                            bounds.1 = v.clone();
                        }
                    }
                    None => {
                        z.attrs.insert(k.clone(), (v.clone(), v.clone()));
                    }
                }
            }
        }
        z
    }

    /// May this segment hold any LSN in the inclusive range `[from, to]`?
    pub fn may_overlap_lsn(&self, from: Lsn, to: Lsn) -> bool {
        match self.lsn {
            None => false, // empty segment holds nothing
            Some((lo, hi)) => lo <= to && from <= hi,
        }
    }

    /// May this segment hold any HLC timestamp in the inclusive range?
    pub fn may_overlap_ts(&self, from: u64, to: u64) -> bool {
        match self.ts_hlc {
            None => false,
            Some((lo, hi)) => lo <= to && from <= hi,
        }
    }

    /// May this segment contain an event from exactly `agent`?
    pub fn may_contain_agent(&self, agent: &str) -> bool {
        match &self.agent {
            None => false,
            Some((lo, hi)) => lo.as_str() <= agent && agent <= hi.as_str(),
        }
    }

    /// May this segment contain an event from exactly `session`?
    pub fn may_contain_session(&self, session: &str) -> bool {
        match &self.session {
            None => false,
            Some((lo, hi)) => lo.as_str() <= session && session <= hi.as_str(),
        }
    }

    /// May this segment contain an event whose `attrs[key] == value`?
    /// A key absent from the zone map means *no* event in the segment carried
    /// that key ⇒ guaranteed no match ⇒ skip.
    pub fn may_contain_attr_eq(&self, key: &str, value: &str) -> bool {
        match self.attrs.get(key) {
            None => false,
            Some((lo, hi)) => lo.as_str() <= value && value <= hi.as_str(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::EventKind;

    fn ep(agent: &str, ts: u64, topic: Option<&str>) -> Episode {
        let mut e = Episode::new(agent, EventKind::Observation, b"x".to_vec());
        e.ts_hlc = ts;
        if let Some(t) = topic {
            e.attrs.insert("topic".into(), t.into());
        }
        e
    }

    fn seg() -> Vec<(Lsn, Episode)> {
        vec![
            (10, ep("alice", 100, Some("rivers"))),
            (11, ep("bob", 150, Some("time"))),
            (12, ep("carol", 200, None)),
        ]
    }

    fn zmap(seg: &[(Lsn, Episode)]) -> ZoneMap {
        ZoneMap::build(seg.iter().map(|(l, e)| (*l, e)))
    }

    #[test]
    fn bounds_are_computed() {
        let z = zmap(&seg());
        assert_eq!(z.count, 3);
        assert_eq!(z.lsn, Some((10, 12)));
        assert_eq!(z.ts_hlc, Some((100, 200)));
        assert_eq!(z.agent, Some(("alice".into(), "carol".into())));
        assert_eq!(z.attrs["topic"], ("rivers".into(), "time".into()));
    }

    #[test]
    fn lsn_and_ts_skip() {
        let z = zmap(&seg());
        assert!(z.may_overlap_lsn(0, 10)); // touches min
        assert!(z.may_overlap_lsn(12, 99)); // touches max
        assert!(!z.may_overlap_lsn(0, 9)); // entirely below → SKIP
        assert!(!z.may_overlap_lsn(13, 99)); // entirely above → SKIP
        assert!(z.may_overlap_ts(120, 130));
        assert!(!z.may_overlap_ts(0, 99)); // → SKIP
    }

    #[test]
    fn agent_and_attr_skip() {
        let z = zmap(&seg());
        assert!(z.may_contain_agent("bob")); // within [alice, carol]
        assert!(!z.may_contain_agent("zoe")); // above max → SKIP
        assert!(!z.may_contain_agent("aaron")); // below min → SKIP
        assert!(z.may_contain_attr_eq("topic", "rivers"));
        assert!(z.may_contain_attr_eq("topic", "space")); // within [rivers, time]
        assert!(!z.may_contain_attr_eq("topic", "zzz")); // above max → SKIP
        assert!(!z.may_contain_attr_eq("author", "x")); // key absent → SKIP
    }

    #[test]
    fn empty_segment_matches_nothing() {
        let z = ZoneMap::build(std::iter::empty());
        assert!(!z.may_overlap_lsn(0, u64::MAX));
        assert!(!z.may_contain_agent("alice"));
    }
}
