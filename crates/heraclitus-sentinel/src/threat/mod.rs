//! SPEC-0047 — Heraclitus Threat-Sync: the sovereign threat-intelligence
//! plane.
//!
//! > *Threat intelligence is evidence with provenance, expiration and trust,
//! > not a magic list of evil strings.*
//!
//! # What is implemented here
//!
//! | § | area | module |
//! |---|---|---|
//! | §4–§6, §9, §12 | canonical threat IR, provenance, lifecycle | [`ir`] |
//! | §21 | canonicalisation before indexing | [`canonical`] |
//! | §22–§23 | TLP 2.0 and propagation | [`tlp`] |
//! | §7 | exact IOC indexes, Bloom as prefilter only | [`index`] |
//! | §10–§13 | source trust, admission gate, IOC → signal | [`trust`] |
//! | §36–§37 | sightings | [`sighting`] |
//! | §40–§41 | feed versioning and rollback | [`feed`] |
//! | §24–§27 | sharing policy, sanitiser, leak gate | [`sharing`] |
//! | §14–§17 | STIX 2.1 import with input limits | [`stix`] |
//!
//! # What is deliberately NOT implemented, and why
//!
//! These are not oversights; each needs something this crate does not and
//! should not have.
//!
//! - **TAXII client and server (§18, §19).** The sentinel crate has no HTTP
//!   client, no TLS and no async runtime, and acquiring them here would put a
//!   network stack on the derivation plane. The importer boundary
//!   ([`stix::ThreatImporter`]) is the seam a transport plugs into: a TAXII
//!   client is a fetch loop feeding bytes to it, and belongs with the server.
//! - **MISP adapter (§20).** Same reason, plus the MISP core format evolves
//!   independently of STIX (§1 explicitly forbids pinning it), so it wants
//!   fixtures from a live instance to be worth anything.
//! - **CTIR transport (§28–§32).** §30 says an `HttpApi` "NÃO será presumida"
//!   and the current official guidance is institutional notification. Writing
//!   a renderer against an API nobody has published would be inventing a
//!   protocol; the honest deliverable is a rendering step plus a human
//!   approval gate, and §31 already makes `send` approval-only.
//! - **Air-gap bundles (§33–§35).** Bundle signing overlaps the SPEC-0046
//!   evidence and air-gap work that is in flight, and two independent
//!   implementations of "verify a signed bundle" would diverge — the one that
//!   diverged would be the one nobody exercised.
//! - **Dashboard (§42).** Needs the server views, not this crate.
//!
//! # The invariants that are mechanical here
//!
//! | invariant | how it is enforced |
//! |---|---|
//! | T1 feed is not absolute authority | [`trust::TrustLevel::evidence_weight`]; untrusted weighs exactly zero |
//! | T2 exact IOC uses exact confirmation | fuzzy hashes never enter [`index::IocIndex`] |
//! | T3 Bloom never authorises | [`index::PrefilterHit`] is opaque and cannot become a [`index::ConfirmedMatch`] |
//! | T4 ANN never replaces exact | no vector search in this module at all |
//! | T5 all intelligence has provenance | [`ir::ThreatProvenance`] is a required field |
//! | T6 every indicator has a lifecycle | [`trust::ThreatSourceRegistry::admit`] rejects an object with no expiry policy |
//! | T7 TLP follows derivatives | [`tlp::TlpLevel::most_restrictive`] |
//! | T8 sanitisation precedes export | [`sharing::SanitizedThreatObject`] is unconstructible outside the sanitiser |
//! | T12 a feed update can be reverted | [`feed::ThreatFeed::rollback_to`] |

pub mod canonical;
pub mod feed;
pub mod index;
pub mod ir;
pub mod plane;
pub mod sharing;
pub mod sighting;
pub mod stix;
pub mod tlp;
pub mod trust;

pub use canonical::CanonicalError;
pub use feed::{FeedVersionState, ThreatFeed, ThreatFeedUpdate, FeedError};
pub use index::{ConfirmedMatch, IocIndex, MatchKind, PrefilterHit, PrefilterOutcome};
pub use ir::{
    HashAlgorithm, Indicator, IndicatorState, IpCidr, ThreatObject, ThreatObjectType,
    ThreatProvenance, ThreatRelation,
};
pub use sharing::{
    Pseudonymizer, SanitizationError, SanitizedThreatObject, SharingPolicy, ThreatSanitizer,
};
pub use plane::{trust_from_config, ThreatLoadReport, ThreatPlane};
pub use sighting::ThreatSighting;
pub use stix::{StixImporter, ThreatImportError, ThreatImporter, ThreatInputLimits};
pub use tlp::TlpLevel;
pub use trust::{
    Admission, ThreatGateError, ThreatIntelDetector, ThreatSourcePolicy, ThreatSourceRegistry,
    TrustLevel,
};
