//! SPEC-0047 §36–§37 — sightings.
//!
//! > Cada ocorrência local de IOC externo gera `ThreatSighting` e **NÃO**
//! > altera o objeto original.
//!
//! The rule is small and the reason it exists is not.  A threat object is
//! someone else's assertion, carried with their digest (§9) and re-exportable
//! unchanged (§17).  The moment a local match writes a `last_seen` or a
//! `hit_count` back into it, that digest stops matching, the object stops
//! being what the source said, and a re-export publishes our telemetry as
//! their intelligence.
//!
//! So a sighting is a separate, append-only fact that *points at* the
//! indicator.  [`ThreatSighting`] holds an id, never a `&mut ThreatObject`.

use heraclitus_core::{Episode, EventId, EventKind, Lsn};
use serde::{Deserialize, Serialize};

/// SPEC-0047 §37.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatSighting {
    /// The [`super::ir::ThreatObject::object_id`] that matched.
    pub indicator_id: String,
    /// The local event in which it was seen.
    pub event_id: EventId,
    pub lsn: Lsn,
    /// Confidence of *this observation*, not of the indicator.  They are
    /// different quantities: a high-confidence IOC seen through a lossy
    /// normaliser is a low-confidence sighting.
    pub confidence: f32,
    pub observed_at: u64,
    /// Which indicator inside the object matched, as
    /// [`super::ir::Indicator::kind_label`].  Kept because an object can carry
    /// several indicators and "object X matched" does not say which.
    pub indicator_kind: String,
    /// Whether the match was exact or broadened (suffix/prefix), as
    /// [`super::index::MatchKind`].  A reviewer reading a sighting a month
    /// later cannot recover this from the object.
    pub match_kind: String,
}

impl ThreatSighting {
    pub fn new(
        indicator_id: impl Into<String>,
        event_id: EventId,
        lsn: Lsn,
        confidence: f32,
        observed_at: u64,
        indicator_kind: impl Into<String>,
        match_kind: impl Into<String>,
    ) -> Self {
        Self {
            indicator_id: indicator_id.into(),
            event_id,
            lsn,
            confidence: confidence.clamp(0.0, 1.0),
            observed_at,
            indicator_kind: indicator_kind.into(),
            match_kind: match_kind.into(),
        }
    }

    /// Build a sighting from a confirmed match.  Takes `&ConfirmedMatch`, so
    /// there is no path here that could mutate the object it came from.
    pub fn from_match(
        hit: &super::index::ConfirmedMatch,
        event_id: EventId,
        lsn: Lsn,
        observed_at: u64,
    ) -> Self {
        Self::new(
            hit.object_id.clone(),
            event_id,
            lsn,
            hit.confidence as f32 / 100.0,
            observed_at,
            hit.indicator.kind_label(),
            match hit.kind {
                super::index::MatchKind::Exact => "exact",
                super::index::MatchKind::DomainSuffix => "domain-suffix",
                super::index::MatchKind::IpPrefix => "ip-prefix",
            },
        )
    }

    /// Persist as a derived event, following the same conventions as
    /// [`crate::event::SecuritySignal::into_episode`]: no new `EventKind`
    /// discriminant, the observed event as the causal parent.
    pub fn into_episode(&self) -> Result<Episode, serde_json::Error> {
        let mut episode = Episode::new(
            "sentinel",
            EventKind::Custom("ThreatSighting".into()),
            serde_json::to_vec(self)?,
        );
        episode.parents = vec![self.event_id];
        episode
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        episode
            .attrs
            .insert("threat.indicator_id".into(), self.indicator_id.clone());
        episode
            .attrs
            .insert("threat.indicator_kind".into(), self.indicator_kind.clone());
        episode
            .attrs
            .insert("threat.match_kind".into(), self.match_kind.clone());
        episode
            .attrs
            .insert("sentinel.source_lsn".into(), self.lsn.to_string());
        episode.valid_from = (self.observed_at != 0).then_some(self.observed_at);
        Ok(episode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::index::{ConfirmedMatch, MatchKind};
    use crate::threat::ir::Indicator;
    use crate::threat::tlp::TlpLevel;

    fn hit() -> ConfirmedMatch {
        ConfirmedMatch {
            object_id: "indicator--7".into(),
            source_id: "cert".into(),
            indicator: Indicator::Domain("evil.com".into()),
            confidence: 90,
            tlp: TlpLevel::Amber,
            kind: MatchKind::DomainSuffix,
        }
    }

    #[test]
    fn a_sighting_only_references_the_object() {
        let event = EventId::new();
        let s = ThreatSighting::from_match(&hit(), event, 42, 1_700);
        assert_eq!(s.indicator_id, "indicator--7");
        assert_eq!(s.event_id, event);
        assert_eq!(s.lsn, 42);
        assert!((s.confidence - 0.9).abs() < 1e-6);
        assert_eq!(s.indicator_kind, "domain");
        assert_eq!(s.match_kind, "domain-suffix");
    }

    #[test]
    fn the_original_object_is_untouched_by_construction() {
        // §36 is enforced by the signature: `from_match` takes `&`, so there is
        // no code path from observing a hit to mutating the intelligence.
        let original = hit();
        let before = original.clone();
        let _ = ThreatSighting::from_match(&original, EventId::new(), 1, 0);
        assert_eq!(original, before);
    }

    #[test]
    fn confidence_is_clamped_rather_than_trusted() {
        let s = ThreatSighting::new("i", EventId::new(), 1, 9.0, 0, "domain", "exact");
        assert_eq!(s.confidence, 1.0);
        let s = ThreatSighting::new("i", EventId::new(), 1, -3.0, 0, "domain", "exact");
        assert_eq!(s.confidence, 0.0);
    }

    #[test]
    fn the_episode_carries_provenance_and_no_new_event_kind() {
        let event = EventId::new();
        let episode = ThreatSighting::from_match(&hit(), event, 9, 1_700)
            .into_episode()
            .unwrap();
        assert_eq!(episode.kind, EventKind::Custom("ThreatSighting".into()));
        assert_eq!(episode.parents, vec![event]);
        assert_eq!(episode.attrs["sentinel.source_lsn"], "9");
        assert_eq!(episode.attrs["threat.match_kind"], "domain-suffix");
        assert_eq!(episode.valid_from, Some(1_700));
    }
}
