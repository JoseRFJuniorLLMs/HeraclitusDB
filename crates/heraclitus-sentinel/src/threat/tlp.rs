//! SPEC-0047 §22–§23 — TLP 2.0 and its propagation.
//!
//! TLP is an ordering, not a label set.  Encoding that ordering in the type
//! (`Clear < Green < Amber < AmberStrict < Red`) is what makes §23 —
//! *"derived_tlp = most_restrictive(parent_tlp)"* — a one-line function
//! instead of a table someone has to keep right.
//!
//! The failure this prevents is specific: an incident correlating a TLP:CLEAR
//! open feed with a TLP:RED government notification is itself TLP:RED.  A
//! system that derived the *first* parent's marking, or the most common one,
//! would export the government material to a public destination while
//! believing it was sharing an open-source IOC.

use serde::{Deserialize, Serialize};

/// SPEC-0047 §22.  Ordered from least to most restrictive; the derived `Ord`
/// **is** the sharing lattice, so any comparison here is the policy.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum TlpLevel {
    Clear,
    Green,
    Amber,
    AmberStrict,
    /// The default is the most restrictive on purpose.  A missing or
    /// unparseable marking must not silently become the most shareable one —
    /// that is the one default whose failure mode is a disclosure.
    #[default]
    Red,
}

impl TlpLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Clear => "TLP:CLEAR",
            Self::Green => "TLP:GREEN",
            Self::Amber => "TLP:AMBER",
            Self::AmberStrict => "TLP:AMBER+STRICT",
            Self::Red => "TLP:RED",
        }
    }

    /// Parse a TLP 2.0 marking.
    ///
    /// TLP 1.0's `TLP:WHITE` is accepted as `Clear` because feeds in the field
    /// still emit it and the two mean the same thing.  Anything else returns
    /// `None` — and callers must treat `None` as [`TlpLevel::Red`], never as
    /// "unmarked, therefore shareable".
    pub fn parse(value: &str) -> Option<Self> {
        let normalised = value.trim().to_ascii_uppercase().replace(' ', "");
        let normalised = normalised.strip_prefix("TLP:").unwrap_or(&normalised);
        match normalised {
            "CLEAR" | "WHITE" => Some(Self::Clear),
            "GREEN" => Some(Self::Green),
            "AMBER" => Some(Self::Amber),
            "AMBER+STRICT" | "AMBERSTRICT" => Some(Self::AmberStrict),
            "RED" => Some(Self::Red),
            _ => None,
        }
    }

    /// Parse, falling back to the most restrictive level.  This is the
    /// function ingestion should call: an unrecognised marking is a reason to
    /// be careful, not a reason to publish.
    pub fn parse_or_restricted(value: &str) -> Self {
        Self::parse(value).unwrap_or(Self::Red)
    }

    /// SPEC-0047 §23 — the marking a derived object inherits.
    ///
    /// An empty parent set yields [`TlpLevel::Red`]: an object with no known
    /// provenance is the *least* safe thing to share, not the most.
    pub fn most_restrictive<I: IntoIterator<Item = TlpLevel>>(parents: I) -> TlpLevel {
        parents.into_iter().max().unwrap_or(TlpLevel::Red)
    }

    /// Whether this marking may leave towards a destination whose ceiling is
    /// `maximum`.  Equality is allowed; anything above the ceiling is not.
    pub fn may_share_to(&self, maximum: TlpLevel) -> bool {
        *self <= maximum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ordering_is_the_lattice() {
        assert!(TlpLevel::Clear < TlpLevel::Green);
        assert!(TlpLevel::Green < TlpLevel::Amber);
        assert!(TlpLevel::Amber < TlpLevel::AmberStrict);
        assert!(TlpLevel::AmberStrict < TlpLevel::Red);
    }

    #[test]
    fn derived_marking_takes_the_most_restrictive_parent() {
        // §23, and the case that matters: one restricted parent is enough.
        assert_eq!(
            TlpLevel::most_restrictive([TlpLevel::Clear, TlpLevel::Red, TlpLevel::Green]),
            TlpLevel::Red
        );
        assert_eq!(
            TlpLevel::most_restrictive([TlpLevel::Clear, TlpLevel::Clear]),
            TlpLevel::Clear
        );
    }

    #[test]
    fn no_parents_means_restricted_not_open() {
        assert_eq!(TlpLevel::most_restrictive([]), TlpLevel::Red);
        assert_eq!(TlpLevel::default(), TlpLevel::Red);
    }

    #[test]
    fn an_unrecognised_marking_is_treated_as_red() {
        assert_eq!(TlpLevel::parse("TLP:PURPLE"), None);
        assert_eq!(TlpLevel::parse_or_restricted("TLP:PURPLE"), TlpLevel::Red);
        assert_eq!(TlpLevel::parse_or_restricted(""), TlpLevel::Red);
    }

    #[test]
    fn tlp_1_white_still_parses() {
        assert_eq!(TlpLevel::parse("TLP:WHITE"), Some(TlpLevel::Clear));
        assert_eq!(TlpLevel::parse("tlp:clear"), Some(TlpLevel::Clear));
        assert_eq!(
            TlpLevel::parse("TLP:AMBER+STRICT"),
            Some(TlpLevel::AmberStrict)
        );
    }

    #[test]
    fn sharing_respects_the_destination_ceiling() {
        // T5: TLP:RED never leaves towards an unauthorised destination.
        assert!(!TlpLevel::Red.may_share_to(TlpLevel::AmberStrict));
        assert!(!TlpLevel::Red.may_share_to(TlpLevel::Clear));
        assert!(TlpLevel::Red.may_share_to(TlpLevel::Red));
        assert!(TlpLevel::Green.may_share_to(TlpLevel::Amber));
    }
}
