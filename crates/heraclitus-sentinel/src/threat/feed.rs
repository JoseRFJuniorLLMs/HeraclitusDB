//! SPEC-0047 §40–§41, and the part of §13 that is about time — feed
//! versioning, abrupt-change detection and rollback.
//!
//! # §41 is a state change, not a delete
//!
//! > Uma atualização contaminada deve poder ser desativada **sem apagar o
//! > histórico**.
//! >
//! > ```text
//! > FeedVersion n+1 = inactive
//! > FeedVersion n   = active
//! > ```
//!
//! Deleting the bad version would destroy the only record of what was ingested
//! during the window it was active — which is precisely the question an
//! incident review asks afterwards: *what did we believe, and between when and
//! when?*  So [`ThreatFeed::rollback_to`] flips states and appends a reason;
//! nothing is removed, and [`ThreatFeed::version`] can still answer for any
//! version that ever existed.
//!
//! # Abrupt-change detection (§13)
//!
//! A compromised feed rarely changes one indicator.  It replaces the file:
//! the new version drops most of what was there and adds a block of
//! attacker-chosen entries — often broad ones, so that a downstream
//! auto-block takes out infrastructure the attacker wants unreachable.
//!
//! [`ChurnPolicy`] therefore compares an update against the version it
//! replaces and quarantines it when the churn is implausible.  Quarantine, not
//! rejection: a legitimate feed *does* occasionally re-baseline, and throwing
//! the update away would mean the operator never sees why intelligence stopped
//! arriving.

use serde::{Deserialize, Serialize};

/// SPEC-0047 §40 — the record of one feed update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatFeedUpdate {
    pub feed_id: String,
    /// `None` for the first version of a feed.
    pub previous_digest: Option<[u8; 32]>,
    pub new_digest: [u8; 32],
    pub object_count: u64,
    pub added: u64,
    pub removed: u64,
    pub changed: u64,
    pub timestamp: u64,
}

impl ThreatFeedUpdate {
    /// Fraction of the *previous* version that this update removes.
    ///
    /// Denominated in the previous size, not the new one: an update that
    /// removes 900 of 1 000 and adds 10 000 has a churn of 0.9, and measuring
    /// against the new total would hide it as 0.08.
    pub fn removed_fraction(&self, previous_count: u64) -> f64 {
        if previous_count == 0 {
            return 0.0;
        }
        self.removed as f64 / previous_count as f64
    }

    pub fn changed_fraction(&self, previous_count: u64) -> f64 {
        if previous_count == 0 {
            return 0.0;
        }
        self.changed as f64 / previous_count as f64
    }
}

/// SPEC-0047 §13 — what counts as an implausible update.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChurnPolicy {
    pub max_removed_fraction: f64,
    pub max_changed_fraction: f64,
    /// Growth factor beyond which an update is suspicious.  A feed that
    /// suddenly ships twenty times its usual volume is either broken or
    /// hostile, and both warrant a human.
    pub max_growth_factor: f64,
}

impl Default for ChurnPolicy {
    fn default() -> Self {
        Self {
            max_removed_fraction: 0.5,
            max_changed_fraction: 0.5,
            max_growth_factor: 10.0,
        }
    }
}

impl ChurnPolicy {
    /// `None` when the update looks ordinary; otherwise the reason to
    /// quarantine it.
    pub fn assess(&self, update: &ThreatFeedUpdate, previous_count: u64) -> Option<String> {
        if previous_count == 0 {
            return None;
        }
        let removed = update.removed_fraction(previous_count);
        if removed > self.max_removed_fraction {
            return Some(format!(
                "removes {:.0}% of the previous version (limit {:.0}%)",
                removed * 100.0,
                self.max_removed_fraction * 100.0
            ));
        }
        let changed = update.changed_fraction(previous_count);
        if changed > self.max_changed_fraction {
            return Some(format!(
                "changes {:.0}% of the previous version (limit {:.0}%)",
                changed * 100.0,
                self.max_changed_fraction * 100.0
            ));
        }
        let growth = update.object_count as f64 / previous_count as f64;
        if growth > self.max_growth_factor {
            return Some(format!(
                "grows {growth:.1}x over the previous version (limit {:.1}x)",
                self.max_growth_factor
            ));
        }
        None
    }
}

/// SPEC-0047 §41.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeedVersionState {
    Active,
    /// Superseded by a later version, or rolled back past.  Still readable.
    Inactive,
    /// Held by §13 churn detection or by an operator.  Never active without
    /// an explicit human decision.
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedVersion {
    pub version: u32,
    pub update: ThreatFeedUpdate,
    pub state: FeedVersionState,
    /// Why the version is in its current state, when it is not simply the
    /// newest good one.  An operator reading this a month later should not
    /// have to reconstruct the reasoning.
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    #[error("update for feed `{feed_id}` declares previous digest {declared} but the active version is {actual}")]
    DigestChainBroken {
        feed_id: String,
        declared: String,
        actual: String,
    },
    #[error("feed `{feed_id}` has no version {version}")]
    UnknownVersion { feed_id: String, version: u32 },
    #[error("version {version} of feed `{feed_id}` is quarantined and cannot be made active without clearing the quarantine first")]
    QuarantinedVersion { feed_id: String, version: u32 },
}

/// The version history of one feed.
#[derive(Debug, Clone)]
pub struct ThreatFeed {
    feed_id: String,
    versions: Vec<FeedVersion>,
    churn: ChurnPolicy,
}

impl ThreatFeed {
    pub fn new(feed_id: impl Into<String>, churn: ChurnPolicy) -> Self {
        Self {
            feed_id: feed_id.into(),
            versions: Vec::new(),
            churn,
        }
    }

    pub fn feed_id(&self) -> &str {
        &self.feed_id
    }

    pub fn versions(&self) -> &[FeedVersion] {
        &self.versions
    }

    pub fn version(&self, version: u32) -> Option<&FeedVersion> {
        self.versions.iter().find(|v| v.version == version)
    }

    /// The version currently in force, if any.
    pub fn active(&self) -> Option<&FeedVersion> {
        self.versions
            .iter()
            .find(|v| v.state == FeedVersionState::Active)
    }

    /// Record an update (§40).
    ///
    /// The digest chain is verified against the active version: an update that
    /// claims to follow something else is either out of order or fabricated,
    /// and applying it would leave the history saying a sequence happened that
    /// did not.
    ///
    /// Returns the new version's state.  A quarantined update is still
    /// *recorded* — §41's principle applied forwards.
    pub fn apply(&mut self, update: ThreatFeedUpdate) -> Result<FeedVersionState, FeedError> {
        let active = self.active().cloned();
        if let Some(current) = &active {
            let expected = current.update.new_digest;
            match update.previous_digest {
                Some(declared) if declared == expected => {}
                declared => {
                    return Err(FeedError::DigestChainBroken {
                        feed_id: self.feed_id.clone(),
                        declared: declared.map(hex).unwrap_or_else(|| "<none>".into()),
                        actual: hex(expected),
                    })
                }
            }
        }

        let previous_count = active.as_ref().map(|v| v.update.object_count).unwrap_or(0);
        let quarantine_reason = self.churn.assess(&update, previous_count);
        let state = match &quarantine_reason {
            Some(_) => FeedVersionState::Quarantined,
            None => FeedVersionState::Active,
        };
        // Only a healthy update supersedes the previous one.  A quarantined
        // update must not leave the feed with nothing in force: the old
        // intelligence is stale, but stale is better than absent, and this is
        // the behaviour an attacker is trying to defeat by poisoning.
        if state == FeedVersionState::Active {
            for v in &mut self.versions {
                if v.state == FeedVersionState::Active {
                    v.state = FeedVersionState::Inactive;
                }
            }
        }
        let version = self.versions.last().map(|v| v.version + 1).unwrap_or(1);
        self.versions.push(FeedVersion {
            version,
            update,
            state,
            note: quarantine_reason,
        });
        Ok(state)
    }

    /// SPEC-0047 §41 — make an earlier version active again.
    ///
    /// Nothing is deleted: every version keeps its record, and the ones passed
    /// over become `Inactive` with a note saying which rollback did it.
    pub fn rollback_to(&mut self, version: u32, reason: impl Into<String>) -> Result<(), FeedError> {
        let target = self
            .versions
            .iter()
            .find(|v| v.version == version)
            .ok_or_else(|| FeedError::UnknownVersion {
                feed_id: self.feed_id.clone(),
                version,
            })?;
        if target.state == FeedVersionState::Quarantined {
            return Err(FeedError::QuarantinedVersion {
                feed_id: self.feed_id.clone(),
                version,
            });
        }
        let reason = reason.into();
        for v in &mut self.versions {
            if v.version == version {
                v.state = FeedVersionState::Active;
                v.note = Some(format!("activated: {reason}"));
            } else if v.state != FeedVersionState::Quarantined {
                // Every other non-quarantined version steps down, not just the
                // later ones.  Deactivating only `> version` was wrong in the
                // forward direction — releasing a quarantine and then
                // activating that version would leave the older one Active too,
                // and `active()` would answer with whichever came first in the
                // vector.  Two versions in force at once is not a state this
                // type should be able to represent.
                v.state = FeedVersionState::Inactive;
                v.note = Some(format!("superseded by version {version}: {reason}"));
            }
        }
        Ok(())
    }

    /// Clear a quarantine after a human has looked at it.  Deliberately
    /// separate from [`Self::rollback_to`]: releasing intelligence that
    /// automated analysis flagged is a decision, and it should read like one
    /// in the call site.
    pub fn release_quarantine(
        &mut self,
        version: u32,
        approver: impl Into<String>,
    ) -> Result<(), FeedError> {
        let feed_id = self.feed_id.clone();
        let target = self
            .versions
            .iter_mut()
            .find(|v| v.version == version)
            .ok_or(FeedError::UnknownVersion { feed_id, version })?;
        target.state = FeedVersionState::Inactive;
        target.note = Some(format!("quarantine released by {}", approver.into()));
        Ok(())
    }
}

fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(prev: Option<u8>, new: u8, count: u64, added: u64, removed: u64) -> ThreatFeedUpdate {
        ThreatFeedUpdate {
            feed_id: "feed".into(),
            previous_digest: prev.map(|b| [b; 32]),
            new_digest: [new; 32],
            object_count: count,
            added,
            removed,
            changed: 0,
            timestamp: 0,
        }
    }

    fn feed() -> ThreatFeed {
        ThreatFeed::new("feed", ChurnPolicy::default())
    }

    #[test]
    fn the_first_version_becomes_active() {
        let mut f = feed();
        assert_eq!(
            f.apply(update(None, 1, 100, 100, 0)).unwrap(),
            FeedVersionState::Active
        );
        assert_eq!(f.active().unwrap().version, 1);
    }

    #[test]
    fn an_update_that_does_not_follow_the_active_version_is_refused() {
        let mut f = feed();
        f.apply(update(None, 1, 100, 100, 0)).unwrap();
        assert!(matches!(
            f.apply(update(Some(9), 2, 101, 1, 0)),
            Err(FeedError::DigestChainBroken { .. })
        ));
    }

    #[test]
    fn a_mass_removal_is_quarantined_not_applied() {
        // §13 — the shape of a poisoned re-baseline.
        let mut f = feed();
        f.apply(update(None, 1, 1_000, 1_000, 0)).unwrap();
        let state = f.apply(update(Some(1), 2, 1_010, 1_000, 900)).unwrap();
        assert_eq!(state, FeedVersionState::Quarantined);
        assert!(f.version(2).unwrap().note.as_ref().unwrap().contains("90%"));
    }

    #[test]
    fn a_quarantined_update_leaves_the_previous_version_in_force() {
        // Losing all intelligence is exactly what the poisoning was for.
        let mut f = feed();
        f.apply(update(None, 1, 1_000, 1_000, 0)).unwrap();
        f.apply(update(Some(1), 2, 1_010, 1_000, 900)).unwrap();
        assert_eq!(
            f.active().unwrap().version,
            1,
            "version 1 must stay active while version 2 is held"
        );
    }

    #[test]
    fn a_sudden_twentyfold_growth_is_quarantined() {
        let mut f = feed();
        f.apply(update(None, 1, 100, 100, 0)).unwrap();
        assert_eq!(
            f.apply(update(Some(1), 2, 2_000, 1_900, 0)).unwrap(),
            FeedVersionState::Quarantined
        );
    }

    #[test]
    fn ordinary_growth_is_not_quarantined() {
        let mut f = feed();
        f.apply(update(None, 1, 1_000, 1_000, 0)).unwrap();
        assert_eq!(
            f.apply(update(Some(1), 2, 1_050, 60, 10)).unwrap(),
            FeedVersionState::Active
        );
        assert_eq!(f.active().unwrap().version, 2);
    }

    #[test]
    fn rollback_deactivates_without_deleting() {
        // §41 — the history of what we believed, and when, survives.
        let mut f = feed();
        f.apply(update(None, 1, 1_000, 1_000, 0)).unwrap();
        f.apply(update(Some(1), 2, 1_020, 30, 10)).unwrap();
        assert_eq!(f.active().unwrap().version, 2);

        f.rollback_to(1, "version 2 contained attacker-supplied CIDRs")
            .unwrap();
        assert_eq!(f.active().unwrap().version, 1);
        assert_eq!(f.versions().len(), 2, "nothing was deleted");
        let v2 = f.version(2).unwrap();
        assert_eq!(v2.state, FeedVersionState::Inactive);
        assert!(v2.note.as_ref().unwrap().contains("attacker-supplied"));
        assert_eq!(
            f.versions()
                .iter()
                .filter(|v| v.state == FeedVersionState::Active)
                .count(),
            1,
            "exactly one version may be in force"
        );
    }

    #[test]
    fn rollback_to_an_unknown_version_is_an_error() {
        let mut f = feed();
        f.apply(update(None, 1, 10, 10, 0)).unwrap();
        assert!(matches!(
            f.rollback_to(7, "x"),
            Err(FeedError::UnknownVersion { .. })
        ));
    }

    #[test]
    fn a_quarantined_version_cannot_be_activated_by_a_rollback() {
        let mut f = feed();
        f.apply(update(None, 1, 1_000, 1_000, 0)).unwrap();
        f.apply(update(Some(1), 2, 1_010, 1_000, 900)).unwrap();
        assert!(matches!(
            f.rollback_to(2, "let it through"),
            Err(FeedError::QuarantinedVersion { .. })
        ));
    }

    #[test]
    fn releasing_a_quarantine_is_recorded_with_who_did_it() {
        let mut f = feed();
        f.apply(update(None, 1, 1_000, 1_000, 0)).unwrap();
        f.apply(update(Some(1), 2, 1_010, 1_000, 900)).unwrap();
        f.release_quarantine(2, "analyst@org").unwrap();
        let v2 = f.version(2).unwrap();
        assert_eq!(v2.state, FeedVersionState::Inactive);
        assert!(v2.note.as_ref().unwrap().contains("analyst@org"));
        // And now it can be activated deliberately.
        f.rollback_to(2, "reviewed and accepted").unwrap();
        assert_eq!(f.active().unwrap().version, 2);
    }

    #[test]
    fn churn_is_measured_against_the_previous_size() {
        // Measuring against the new total would hide a mass removal behind a
        // mass addition.
        let u = update(Some(1), 2, 11_000, 10_900, 900);
        assert!((u.removed_fraction(1_000) - 0.9).abs() < 1e-9);
    }
}
