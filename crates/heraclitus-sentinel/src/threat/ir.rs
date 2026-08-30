//! SPEC-0047 §4–§6, §9, §12 — the canonical threat IR.
//!
//! The principle the SPEC opens with is the whole design constraint:
//!
//! > *Threat intelligence is evidence with provenance, expiration and trust,
//! > not a magic list of evil strings.*
//!
//! Three consequences are encoded in the types rather than in documentation:
//!
//! 1. **Provenance is not optional.** [`ThreatObject`] has no constructor that
//!    omits [`ThreatProvenance`] (§9, invariant T5).  A list of IOCs with no
//!    source, no digest and no confidence is exactly the "magic list of evil
//!    strings" the SPEC refuses.
//! 2. **Every indicator has a lifecycle.** An object without an expiry and
//!    without a source default TTL is rejected at the gate, not stored
//!    forever (§12, invariant T6).
//! 3. **Unknown shapes survive.** §5 and §17 both require that unrecognised
//!    types and fields be preserved rather than dropped; `Unknown(String)` and
//!    `unknown_fields` exist so that an object from a newer STIX profile can
//!    still be re-exported unchanged.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

use super::tlp::TlpLevel;

/// SPEC-0047 §5.  `Unknown` carries the original type string: dropping it
/// would make §17 ("preserved / exported unchanged") impossible.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatObjectType {
    Indicator,
    Malware,
    Tool,
    Infrastructure,
    Campaign,
    ThreatActor,
    Vulnerability,
    AttackPattern,
    Incident,
    Report,
    Unknown(String),
}

impl ThreatObjectType {
    pub fn label(&self) -> &str {
        match self {
            Self::Indicator => "indicator",
            Self::Malware => "malware",
            Self::Tool => "tool",
            Self::Infrastructure => "infrastructure",
            Self::Campaign => "campaign",
            Self::ThreatActor => "threat-actor",
            Self::Vulnerability => "vulnerability",
            Self::AttackPattern => "attack-pattern",
            Self::Incident => "incident",
            Self::Report => "report",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

/// SPEC-0047 §6.  The algorithm is explicit and never inferred from the digest
/// length: SHA-256 and SHA3-256 are both 32 bytes, and guessing would make two
/// different indicators compare equal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Sha3_256,
    Ssdeep,
    Tlsh,
    Custom(String),
}

impl HashAlgorithm {
    pub fn label(&self) -> &str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Sha3_256 => "SHA3-256",
            Self::Ssdeep => "SSDEEP",
            Self::Tlsh => "TLSH",
            Self::Custom(value) => value.as_str(),
        }
    }

    /// Whether an equality comparison over this algorithm's digest is a sound
    /// identity test.  Fuzzy hashes (`SSDEEP`, `TLSH`) are *similarity*
    /// digests: two different files routinely share a prefix, and treating a
    /// match as identity would produce confident false positives — the exact
    /// failure mode invariant T2 exists to prevent.
    pub fn is_exact(&self) -> bool {
        !matches!(self, Self::Ssdeep | Self::Tlsh)
    }
}

/// An IP address or CIDR block.
///
/// Written here rather than pulled from a crate because the sentinel crate has
/// no network dependencies and the surface actually needed is small: parse,
/// canonicalise, contain.
///
/// Host bits are **masked on construction**.  §21 forbids normalisation that
/// changes an indicator's meaning; masking does not — `10.0.0.7/8` and
/// `10.0.0.0/8` denote the identical address set — while *not* masking would
/// let the same block be stored under two keys and matched by neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IpCidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    pub fn new(addr: IpAddr, prefix_len: u8) -> Option<Self> {
        let max = Self::max_prefix(&addr);
        if prefix_len > max {
            return None;
        }
        Some(Self {
            addr: mask(addr, prefix_len),
            prefix_len,
        })
    }

    /// A single address as a host route (`/32` or `/128`).
    pub fn host(addr: IpAddr) -> Self {
        let prefix_len = Self::max_prefix(&addr);
        Self { addr, prefix_len }
    }

    fn max_prefix(addr: &IpAddr) -> u8 {
        match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn is_host(&self) -> bool {
        self.prefix_len == Self::max_prefix(&self.addr)
    }

    /// Whether `probe` falls inside this block.  A v4 probe never matches a v6
    /// block and vice versa: v4-mapped v6 addresses are canonicalised before
    /// they reach here (see [`super::canonical`]), so no implicit conversion
    /// happens at match time where it would be invisible.
    pub fn contains(&self, probe: IpAddr) -> bool {
        match (self.addr, probe) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(probe, self.prefix_len) == self.addr
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

fn mask(addr: IpAddr, prefix_len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let keep = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            IpAddr::V4((bits & keep).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let keep = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            IpAddr::V6((bits & keep).into())
        }
    }
}

/// SPEC-0047 §6.  Values arrive here already canonical — construction goes
/// through [`super::canonical`], which is where §21 is enforced.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Indicator {
    Ip(IpCidr),
    Domain(String),
    Url(String),
    FileHash {
        algorithm: HashAlgorithm,
        value: Vec<u8>,
    },
    CertificateFingerprint(Vec<u8>),
    Email(String),
    UserAgent(String),
    Custom {
        kind: String,
        value: String,
    },
}

impl Indicator {
    pub fn kind_label(&self) -> &str {
        match self {
            Self::Ip(_) => "ip",
            Self::Domain(_) => "domain",
            Self::Url(_) => "url",
            Self::FileHash { .. } => "file-hash",
            Self::CertificateFingerprint(_) => "certificate-fingerprint",
            Self::Email(_) => "email",
            Self::UserAgent(_) => "user-agent",
            Self::Custom { kind, .. } => kind.as_str(),
        }
    }

    /// The bytes an exact index keys on.  Distinct kinds never collide because
    /// the kind label is length-prefixed into the key; without that, the domain
    /// `ip` and an IP literal could hash to the same slot.
    pub fn index_key(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        let kind = self.kind_label().as_bytes();
        out.extend_from_slice(&(kind.len() as u32).to_le_bytes());
        out.extend_from_slice(kind);
        match self {
            Self::Ip(cidr) => out.extend_from_slice(cidr.to_string().as_bytes()),
            Self::Domain(v) | Self::Url(v) | Self::Email(v) | Self::UserAgent(v) => {
                out.extend_from_slice(v.as_bytes())
            }
            Self::FileHash { algorithm, value } => {
                let algo = algorithm.label().as_bytes();
                out.extend_from_slice(&(algo.len() as u32).to_le_bytes());
                out.extend_from_slice(algo);
                out.extend_from_slice(value);
            }
            Self::CertificateFingerprint(value) => out.extend_from_slice(value),
            Self::Custom { value, .. } => out.extend_from_slice(value.as_bytes()),
        }
        out
    }

    /// Whether an equality match on this indicator is a sound identity claim.
    /// Fuzzy file hashes are not (see [`HashAlgorithm::is_exact`]); everything
    /// else here is.
    pub fn supports_exact_match(&self) -> bool {
        match self {
            Self::FileHash { algorithm, .. } => algorithm.is_exact(),
            _ => true,
        }
    }
}

/// SPEC-0047 §9 — the provenance every IOC must carry.
///
/// Every field is required.  An `Option` here would be an invitation to build
/// an object "just for now" without a source, and the whole trust model of
/// §10, §13 and §23 reads from these fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatProvenance {
    /// Matches [`super::trust::ThreatSourcePolicy::source_id`].
    pub source_id: String,
    /// TAXII collection, MISP event, bundle name — whatever subdivides the
    /// source.
    pub collection: String,
    /// Ingestion time in milliseconds.  Distinct from `valid_from`, which is
    /// what the *source* asserts.
    pub received_at: u64,
    /// The identifier the source itself used (`indicator--<uuid>` in STIX).
    pub source_object_id: String,
    /// Digest of the document this object was carried in.
    pub source_digest: [u8; 32],
    pub confidence: u8,
    pub tlp: TlpLevel,
}

/// SPEC-0047 §12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorState {
    Active,
    Expired,
    Revoked,
    Superseded,
    Quarantined,
}

impl IndicatorState {
    /// Only `Active` may feed correlation.  Note that this is *not* permission
    /// to act — see §11 and [`super::trust`].
    pub fn is_in_force(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// SPEC-0047 §4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatRelation {
    /// STIX `relationship_type` (`uses`, `indicates`, `attributed-to`, …).
    /// Kept as a string: §38 says attribution is a hypothesis, and an enum
    /// would quietly drop relationship types a newer feed invents.
    pub relationship_type: String,
    pub target_object_id: String,
}

/// SPEC-0047 §4 — the canonical object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatObject {
    pub object_id: String,
    pub object_type: ThreatObjectType,
    pub provenance: ThreatProvenance,
    /// Explicit lifecycle state.  Expiry by clock is derived, not stored —
    /// see [`Self::state_at`].
    pub state: IndicatorState,
    pub valid_from: Option<u64>,
    pub valid_until: Option<u64>,
    pub indicators: Vec<Indicator>,
    pub relationships: Vec<ThreatRelation>,
    /// BLAKE3 of the object's original serialised bytes, so §17
    /// ("exported unchanged when policy permits") stays checkable.
    pub original_digest: [u8; 32],
    pub source_version: String,
    /// §5/§17 — fields this build does not model, preserved verbatim.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown_fields: BTreeMap<String, serde_json::Value>,
}

impl ThreatObject {
    /// Convenience constructor that makes the required parts required.
    pub fn new(
        object_id: impl Into<String>,
        object_type: ThreatObjectType,
        provenance: ThreatProvenance,
        original_digest: [u8; 32],
    ) -> Self {
        Self {
            object_id: object_id.into(),
            object_type,
            provenance,
            state: IndicatorState::Active,
            valid_from: None,
            valid_until: None,
            indicators: Vec::new(),
            relationships: Vec::new(),
            original_digest,
            source_version: String::new(),
            unknown_fields: BTreeMap::new(),
        }
    }

    pub fn confidence(&self) -> u8 {
        self.provenance.confidence
    }

    pub fn tlp(&self) -> TlpLevel {
        self.provenance.tlp
    }

    /// SPEC-0047 §12 — the state at a point in time.
    ///
    /// An explicit terminal state always wins: a revoked object does not come
    /// back to life because its `valid_until` is still in the future.
    ///
    /// A `valid_from` in the future deliberately does **not** map to a state.
    /// The §12 enum has five variants and none of them means "not yet"; adding
    /// a sixth would change an enum that other components serialise.  "Not yet
    /// effective" is a window question, and [`Self::is_in_force_at`] answers
    /// it.
    pub fn state_at(&self, now_ms: u64) -> IndicatorState {
        if self.state != IndicatorState::Active {
            return self.state;
        }
        match self.valid_until {
            Some(until) if now_ms >= until => IndicatorState::Expired,
            _ => IndicatorState::Active,
        }
    }

    /// Whether the object is inside its validity window *and* in force.
    pub fn is_in_force_at(&self, now_ms: u64) -> bool {
        if !self.state_at(now_ms).is_in_force() {
            return false;
        }
        match self.valid_from {
            Some(from) => now_ms >= from,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prov() -> ThreatProvenance {
        ThreatProvenance {
            source_id: "feed".into(),
            collection: "col".into(),
            received_at: 1_000,
            source_object_id: "indicator--1".into(),
            source_digest: [7; 32],
            confidence: 80,
            tlp: TlpLevel::Amber,
        }
    }

    fn object() -> ThreatObject {
        ThreatObject::new("obj-1", ThreatObjectType::Indicator, prov(), [1; 32])
    }

    #[test]
    fn cidr_masks_host_bits_without_changing_the_address_set() {
        let a = IpCidr::new("10.0.0.7".parse().unwrap(), 8).unwrap();
        let b = IpCidr::new("10.255.1.1".parse().unwrap(), 8).unwrap();
        assert_eq!(a, b, "the same block must have one canonical key");
        assert_eq!(a.to_string(), "10.0.0.0/8");
        assert!(a.contains("10.9.9.9".parse().unwrap()));
        assert!(!a.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn prefix_longer_than_the_family_is_rejected() {
        assert!(IpCidr::new("10.0.0.0".parse().unwrap(), 33).is_none());
        assert!(IpCidr::new("::1".parse().unwrap(), 129).is_none());
        assert!(IpCidr::new("::1".parse().unwrap(), 128).is_some());
    }

    #[test]
    fn v4_and_v6_never_match_across_families() {
        let block = IpCidr::new("0.0.0.0".parse().unwrap(), 0).unwrap();
        assert!(block.contains("203.0.113.9".parse().unwrap()));
        assert!(
            !block.contains("::ffff:203.0.113.9".parse().unwrap()),
            "a v4-mapped v6 address must be canonicalised before matching, not coerced here"
        );
    }

    #[test]
    fn index_keys_do_not_collide_across_kinds() {
        let domain = Indicator::Domain("ip".into());
        let ua = Indicator::UserAgent("ip".into());
        assert_ne!(domain.index_key(), ua.index_key());

        // Same digest bytes, different algorithm: two different claims.
        let a = Indicator::FileHash {
            algorithm: HashAlgorithm::Sha256,
            value: vec![0xAB; 32],
        };
        let b = Indicator::FileHash {
            algorithm: HashAlgorithm::Sha3_256,
            value: vec![0xAB; 32],
        };
        assert_ne!(a.index_key(), b.index_key());
    }

    #[test]
    fn fuzzy_hashes_are_not_exact_matches() {
        // T2: an SSDEEP equality is a similarity claim, not identity.
        assert!(!Indicator::FileHash {
            algorithm: HashAlgorithm::Ssdeep,
            value: vec![1, 2, 3],
        }
        .supports_exact_match());
        assert!(Indicator::FileHash {
            algorithm: HashAlgorithm::Sha256,
            value: vec![1, 2, 3],
        }
        .supports_exact_match());
    }

    #[test]
    fn expiry_is_derived_and_terminal_states_win() {
        let mut o = object();
        o.valid_until = Some(5_000);
        assert_eq!(o.state_at(4_999), IndicatorState::Active);
        assert_eq!(o.state_at(5_000), IndicatorState::Expired);

        o.state = IndicatorState::Revoked;
        assert_eq!(
            o.state_at(4_999),
            IndicatorState::Revoked,
            "a revoked object must not be resurrected by its validity window"
        );
    }

    #[test]
    fn a_future_valid_from_is_not_in_force() {
        let mut o = object();
        o.valid_from = Some(10_000);
        assert_eq!(o.state_at(9_999), IndicatorState::Active);
        assert!(!o.is_in_force_at(9_999));
        assert!(o.is_in_force_at(10_000));
    }

    #[test]
    fn unknown_type_keeps_its_original_label() {
        let t = ThreatObjectType::Unknown("x-custom-thing".into());
        assert_eq!(t.label(), "x-custom-thing");
    }
}
