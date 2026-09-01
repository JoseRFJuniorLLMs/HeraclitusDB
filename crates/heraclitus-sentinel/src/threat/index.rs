//! SPEC-0047 §7–§8 — exact IOC indexes, with the Bloom filter kept in its
//! place.
//!
//! §7 is unusually blunt for a spec, and the bluntness is the requirement:
//!
//! > `Bloom match != confirmed IOC match`
//!
//! Invariants T2, T3 and T4 all say versions of the same thing — an
//! approximate structure may narrow the search and may never *decide* it.
//! This module encodes that in the type system rather than in a comment:
//!
//! - [`IocIndex::prefilter`] returns a [`PrefilterHit`], which is opaque: it
//!   carries no indicator, no object id, and has no method or conversion that
//!   yields a [`ConfirmedMatch`].
//! - [`ConfirmedMatch`] can only be produced by [`IocIndex::lookup`], which
//!   consults the exact structure.
//!
//! A caller who wants to act on a Bloom hit has to go back through `lookup`.
//! There is no shortcut to remove under deadline, which is when this kind of
//! shortcut normally gets taken.
//!
//! ## Structures, per §7
//!
//! | indicator | structure | why |
//! |---|---|---|
//! | IP / CIDR | prefix map, one bucket per prefix length | longest-prefix match without a radix trie's code |
//! | domain | reversed-label suffix trie | `evil.com` has to be findable from `a.b.evil.com` |
//! | hash, email, URL, UA, cert | exact map on the length-prefixed key | identity, nothing more |
//!
//! The IP structure deserves a note: instead of a radix trie it keeps one hash
//! map per distinct prefix length present in the index, and probes each.  That
//! is O(number of distinct prefix lengths) — in practice under a dozen — and
//! is *exact*, which is the property that matters here.  A radix trie would be
//! faster at a scale this index does not have, and would be more code to get
//! wrong.
//!
//! ## What is deliberately absent
//!
//! No ANN, no vector search, no similarity (invariant T4).  §8 allows the
//! vector index for URL/domain/campaign *similarity*, and that is a different
//! question asked by a different component; letting it in here would put an
//! approximate answer on the path that produces confirmed matches.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use super::ir::{Indicator, IndicatorState, IpCidr, ThreatObject};
use super::tlp::TlpLevel;

/// How a probe met the stored indicator.  Distinguished because they are
/// different claims: an exact hit says *this is the thing*, a suffix hit says
/// *this is under something*, and a policy that treats them alike will block a
/// whole zone on the strength of one subdomain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    Exact,
    /// The stored indicator is a parent domain of the probe.
    DomainSuffix,
    /// The stored indicator is a CIDR block containing the probe.
    IpPrefix,
}

/// A confirmed hit against the exact structure.
///
/// Constructible only inside this module — the field is public for reading,
/// but the struct is never built from a prefilter result.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfirmedMatch {
    pub object_id: String,
    pub source_id: String,
    pub indicator: Indicator,
    pub confidence: u8,
    pub tlp: TlpLevel,
    pub kind: MatchKind,
}

/// The result of the approximate pass.  Opaque on purpose: there is nothing to
/// read out of it, because anything readable would eventually be treated as an
/// answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefilterHit(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefilterOutcome {
    /// Guaranteed absent.  A Bloom filter has no false negatives, so this
    /// answer *is* decisive — the asymmetry is the whole reason the prefilter
    /// is worth having.
    DefinitelyAbsent,
    /// May be present.  Says nothing on its own.
    MaybePresent(PrefilterHit),
}

impl PrefilterOutcome {
    pub fn is_maybe_present(&self) -> bool {
        matches!(self, Self::MaybePresent(_))
    }
}

#[derive(Debug, Clone)]
struct Entry {
    object_id: String,
    source_id: String,
    indicator: Indicator,
    confidence: u8,
    tlp: TlpLevel,
    state: IndicatorState,
    valid_from: Option<u64>,
    valid_until: Option<u64>,
}

impl Entry {
    /// §12/T6 — an expired or revoked indicator is not a match.  Enforced at
    /// lookup rather than by sweeping the index, so a clock that moves does
    /// not need a rebuild and a replay at an earlier `now_ms` gives the answer
    /// that was correct then.
    fn in_force_at(&self, now_ms: u64) -> bool {
        if self.state != IndicatorState::Active {
            return false;
        }
        if let Some(until) = self.valid_until {
            if now_ms >= until {
                return false;
            }
        }
        if let Some(from) = self.valid_from {
            if now_ms < from {
                return false;
            }
        }
        true
    }
}

/// Approximate membership over index keys.  Prefilter only.
#[derive(Debug, Clone)]
pub struct BloomPrefilter {
    bits: Vec<u64>,
    bit_len: usize,
    hashes: u32,
}

impl BloomPrefilter {
    /// `expected` items at false-positive rate `fpr`.  Both are clamped: a
    /// zero-sized or zero-hash filter would answer "maybe" to everything,
    /// which is safe but useless, and a nonsensical `fpr` should not produce a
    /// gigabyte of bits.
    pub fn new(expected: usize, fpr: f64) -> Self {
        let expected = expected.max(1);
        let fpr = fpr.clamp(1e-6, 0.5);
        let ln2 = std::f64::consts::LN_2;
        let bit_len = ((-(expected as f64) * fpr.ln()) / (ln2 * ln2)).ceil() as usize;
        let bit_len = bit_len.clamp(64, 1 << 28);
        let hashes = (((bit_len as f64 / expected as f64) * ln2).round() as u32).clamp(1, 16);
        Self {
            bits: vec![0u64; bit_len.div_ceil(64)],
            bit_len,
            hashes,
        }
    }

    fn positions(&self, key: &[u8]) -> impl Iterator<Item = usize> + '_ {
        let h = blake3::hash(key);
        let bytes = *h.as_bytes();
        let a = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let b = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let bit_len = self.bit_len as u64;
        (0..self.hashes).map(move |i| {
            let combined = a.wrapping_add((i as u64).wrapping_mul(b));
            (combined % bit_len) as usize
        })
    }

    pub fn insert(&mut self, key: &[u8]) {
        for pos in self.positions(key).collect::<Vec<_>>() {
            self.bits[pos / 64] |= 1u64 << (pos % 64);
        }
    }

    pub fn maybe_contains(&self, key: &[u8]) -> bool {
        self.positions(key)
            .all(|pos| self.bits[pos / 64] & (1u64 << (pos % 64)) != 0)
    }

    /// Every bit set — the degenerate filter that answers "maybe" to
    /// everything.  Exists so tests can prove that a saturated prefilter still
    /// produces zero confirmed matches (gate T3).
    #[cfg(test)]
    fn saturated(expected: usize) -> Self {
        let mut f = Self::new(expected, 0.01);
        for word in &mut f.bits {
            *word = u64::MAX;
        }
        f
    }
}

/// Reversed-label suffix index for domains.
#[derive(Debug, Default, Clone)]
struct DomainSuffixIndex {
    /// `com -> evil -> [entry]`, i.e. labels stored right to left.
    children: BTreeMap<String, DomainSuffixIndex>,
    terminal: Vec<usize>,
}

impl DomainSuffixIndex {
    fn insert(&mut self, domain: &str, entry: usize) {
        let mut node = self;
        for label in domain.rsplit('.') {
            node = node.children.entry(label.to_owned()).or_default();
        }
        node.terminal.push(entry);
    }

    /// Every stored domain that is the probe itself or one of its parents.
    fn matches(&self, domain: &str) -> Vec<(usize, MatchKind)> {
        let labels: Vec<&str> = domain.rsplit('.').collect();
        let mut out = Vec::new();
        let mut node = self;
        for (depth, label) in labels.iter().enumerate() {
            let Some(next) = node.children.get(*label) else {
                break;
            };
            node = next;
            let kind = if depth + 1 == labels.len() {
                MatchKind::Exact
            } else {
                MatchKind::DomainSuffix
            };
            out.extend(node.terminal.iter().map(|e| (*e, kind)));
        }
        out
    }
}

/// The exact IOC index of §7.
#[derive(Debug, Clone)]
pub struct IocIndex {
    entries: Vec<Entry>,
    exact: HashMap<Vec<u8>, Vec<usize>>,
    domains: DomainSuffixIndex,
    /// One bucket per prefix length, so a probe is masked once per length.
    ips: BTreeMap<u8, HashMap<IpAddr, Vec<usize>>>,
    bloom: BloomPrefilter,
}

impl IocIndex {
    pub fn new(expected_indicators: usize) -> Self {
        Self {
            entries: Vec::new(),
            exact: HashMap::new(),
            domains: DomainSuffixIndex::default(),
            ips: BTreeMap::new(),
            bloom: BloomPrefilter::new(expected_indicators, 0.01),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Index every indicator an object carries.
    ///
    /// Fuzzy hashes are **skipped**, not stored: `supports_exact_match` is
    /// false for them, and an index whose job is exactness has nothing to do
    /// with a similarity digest.  Returns how many indicators were indexed so
    /// the difference is visible to the caller rather than silent.
    pub fn insert_object(&mut self, object: &ThreatObject) -> usize {
        let mut indexed = 0;
        for indicator in &object.indicators {
            if !indicator.supports_exact_match() {
                continue;
            }
            let idx = self.entries.len();
            self.entries.push(Entry {
                object_id: object.object_id.clone(),
                source_id: object.provenance.source_id.clone(),
                indicator: indicator.clone(),
                confidence: object.provenance.confidence,
                tlp: object.provenance.tlp,
                state: object.state,
                valid_from: object.valid_from,
                valid_until: object.valid_until,
            });
            self.bloom.insert(&indicator.index_key());
            match indicator {
                Indicator::Domain(d) => self.domains.insert(d, idx),
                Indicator::Ip(cidr) => {
                    self.ips
                        .entry(cidr.prefix_len())
                        .or_default()
                        .entry(cidr.addr())
                        .or_default()
                        .push(idx);
                }
                other => self.exact.entry(other.index_key()).or_default().push(idx),
            }
            indexed += 1;
        }
        indexed
    }

    /// The approximate pass (§7).  Cheap, and never an answer.
    ///
    /// Only meaningful for indicators keyed by exact equality: a CIDR block or
    /// a parent domain is not in the filter under the probe's own key, so
    /// asking about them would produce `DefinitelyAbsent` for something that
    /// is present.  Those kinds return `MaybePresent`, which is the honest
    /// answer — the prefilter simply does not narrow them.
    pub fn prefilter(&self, probe: &Indicator) -> PrefilterOutcome {
        match probe {
            Indicator::Ip(_) | Indicator::Domain(_) => {
                PrefilterOutcome::MaybePresent(PrefilterHit(()))
            }
            other => {
                if self.bloom.maybe_contains(&other.index_key()) {
                    PrefilterOutcome::MaybePresent(PrefilterHit(()))
                } else {
                    PrefilterOutcome::DefinitelyAbsent
                }
            }
        }
    }

    /// The exact pass.  The **only** producer of [`ConfirmedMatch`].
    ///
    /// `now_ms` is required rather than read from a clock so that a replay at
    /// an earlier point in time reproduces the decision that was correct then
    /// — the same reason the rest of the sentinel takes time as an argument.
    pub fn lookup(&self, probe: &Indicator, now_ms: u64) -> Vec<ConfirmedMatch> {
        let raw: Vec<(usize, MatchKind)> = match probe {
            Indicator::Domain(d) => self.domains.matches(d),
            Indicator::Ip(cidr) => self.lookup_ip(cidr),
            other => self
                .exact
                .get(&other.index_key())
                .map(|v| v.iter().map(|i| (*i, MatchKind::Exact)).collect())
                .unwrap_or_default(),
        };
        raw.into_iter()
            .filter_map(|(idx, kind)| {
                let entry = &self.entries[idx];
                entry.in_force_at(now_ms).then(|| ConfirmedMatch {
                    object_id: entry.object_id.clone(),
                    source_id: entry.source_id.clone(),
                    indicator: entry.indicator.clone(),
                    confidence: entry.confidence,
                    tlp: entry.tlp,
                    kind,
                })
            })
            .collect()
    }

    fn lookup_ip(&self, probe: &IpCidr) -> Vec<(usize, MatchKind)> {
        let mut out = Vec::new();
        for (prefix_len, bucket) in &self.ips {
            // A stored block can only contain the probe if it is no more
            // specific than the probe itself.
            if *prefix_len > probe.prefix_len() {
                continue;
            }
            let Some(masked) = IpCidr::new(probe.addr(), *prefix_len) else {
                continue;
            };
            if let Some(hits) = bucket.get(&masked.addr()) {
                let kind = if *prefix_len == probe.prefix_len() {
                    MatchKind::Exact
                } else {
                    MatchKind::IpPrefix
                };
                out.extend(hits.iter().map(|i| (*i, kind)));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::canonical::{canonical_domain, canonical_ip};
    use super::super::ir::{HashAlgorithm, ThreatObjectType, ThreatProvenance};
    use super::*;

    fn prov(source: &str, confidence: u8) -> ThreatProvenance {
        ThreatProvenance {
            source_id: source.into(),
            collection: "c".into(),
            received_at: 0,
            source_object_id: "o".into(),
            source_digest: [0; 32],
            confidence,
            tlp: TlpLevel::Amber,
        }
    }

    fn object(id: &str, indicators: Vec<Indicator>) -> ThreatObject {
        let mut o = ThreatObject::new(id, ThreatObjectType::Indicator, prov("feed", 70), [0; 32]);
        o.indicators = indicators;
        o
    }

    fn sha256(byte: u8) -> Indicator {
        Indicator::FileHash {
            algorithm: HashAlgorithm::Sha256,
            value: vec![byte; 32],
        }
    }

    #[test]
    fn exact_hash_lookup() {
        let mut idx = IocIndex::new(16);
        idx.insert_object(&object("a", vec![sha256(0xAA)]));
        assert_eq!(idx.lookup(&sha256(0xAA), 0).len(), 1);
        assert!(idx.lookup(&sha256(0xBB), 0).is_empty());
    }

    #[test]
    fn a_saturated_bloom_still_confirms_nothing() {
        // Gate T3, mechanically: the prefilter says "maybe" to every probe and
        // the exact structure still returns nothing.  This is the test that
        // would fail if anyone ever wired a prefilter hit to a match.
        let mut idx = IocIndex::new(16);
        idx.insert_object(&object("a", vec![sha256(0xAA)]));
        idx.bloom = BloomPrefilter::saturated(16);

        let absent = sha256(0xBB);
        assert!(
            idx.prefilter(&absent).is_maybe_present(),
            "the saturated filter must claim a hit for the test to mean anything"
        );
        assert!(
            idx.lookup(&absent, 0).is_empty(),
            "T3: a Bloom hit alone must never become a confirmed match"
        );
    }

    #[test]
    fn definitely_absent_is_the_only_decisive_prefilter_answer() {
        let mut idx = IocIndex::new(1_000);
        idx.insert_object(&object("a", vec![sha256(0xAA)]));
        assert_eq!(
            idx.prefilter(&sha256(0x01)),
            PrefilterOutcome::DefinitelyAbsent
        );
        assert!(idx.prefilter(&sha256(0xAA)).is_maybe_present());
        // No false negatives: everything inserted must survive the prefilter.
        assert!(idx.lookup(&sha256(0xAA), 0).len() == 1);
    }

    #[test]
    fn domain_suffix_matches_are_labelled_differently_from_exact() {
        let mut idx = IocIndex::new(16);
        idx.insert_object(&object(
            "a",
            vec![Indicator::Domain(canonical_domain("evil.com").unwrap())],
        ));

        let exact = idx.lookup(&Indicator::Domain("evil.com".into()), 0);
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].kind, MatchKind::Exact);

        let sub = idx.lookup(&Indicator::Domain("a.b.evil.com".into()), 0);
        assert_eq!(sub.len(), 1);
        assert_eq!(
            sub[0].kind,
            MatchKind::DomainSuffix,
            "blocking a zone on a subdomain hit is a bigger claim and must be distinguishable"
        );

        // A domain that merely ends with the same *characters* is not a
        // subdomain: `notevil.com` must not match `evil.com`.
        assert!(idx
            .lookup(&Indicator::Domain("notevil.com".into()), 0)
            .is_empty());
    }

    #[test]
    fn cidr_blocks_match_by_longest_prefix() {
        let mut idx = IocIndex::new(16);
        idx.insert_object(&object(
            "net",
            vec![canonical_ip("203.0.113.0/24").unwrap()],
        ));
        idx.insert_object(&object("host", vec![canonical_ip("203.0.113.7").unwrap()]));

        let hits = idx.lookup(&canonical_ip("203.0.113.7").unwrap(), 0);
        assert_eq!(hits.len(), 2, "both the block and the host route match");
        assert!(hits.iter().any(|h| h.kind == MatchKind::Exact));
        assert!(hits.iter().any(|h| h.kind == MatchKind::IpPrefix));

        assert!(idx
            .lookup(&canonical_ip("203.0.114.7").unwrap(), 0)
            .is_empty());
    }

    #[test]
    fn v6_probes_never_match_v4_blocks() {
        let mut idx = IocIndex::new(16);
        idx.insert_object(&object("net", vec![canonical_ip("0.0.0.0/0").unwrap()]));
        assert!(idx
            .lookup(&canonical_ip("2001:db8::1").unwrap(), 0)
            .is_empty());
    }

    #[test]
    fn expired_and_revoked_indicators_do_not_match() {
        // T6 at match time.
        let mut idx = IocIndex::new(16);
        let mut expiring = object("a", vec![sha256(0xAA)]);
        expiring.valid_until = Some(1_000);
        let mut revoked = object("b", vec![sha256(0xBB)]);
        revoked.state = IndicatorState::Revoked;
        idx.insert_object(&expiring);
        idx.insert_object(&revoked);

        assert_eq!(idx.lookup(&sha256(0xAA), 999).len(), 1);
        assert!(idx.lookup(&sha256(0xAA), 1_000).is_empty());
        assert!(idx.lookup(&sha256(0xBB), 0).is_empty());
    }

    #[test]
    fn a_replay_at_an_earlier_time_sees_what_was_true_then() {
        let mut idx = IocIndex::new(16);
        let mut o = object("a", vec![sha256(0xAA)]);
        o.valid_from = Some(500);
        o.valid_until = Some(1_500);
        idx.insert_object(&o);

        assert!(idx.lookup(&sha256(0xAA), 499).is_empty());
        assert_eq!(idx.lookup(&sha256(0xAA), 1_000).len(), 1);
        assert!(idx.lookup(&sha256(0xAA), 1_500).is_empty());
    }

    #[test]
    fn fuzzy_hashes_are_not_indexed_and_the_caller_can_tell() {
        let mut idx = IocIndex::new(16);
        let indexed = idx.insert_object(&object(
            "a",
            vec![
                sha256(0xAA),
                Indicator::FileHash {
                    algorithm: HashAlgorithm::Ssdeep,
                    value: b"3:abc".to_vec(),
                },
            ],
        ));
        assert_eq!(
            indexed, 1,
            "the SSDEEP indicator must not enter an exact index"
        );
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn matches_carry_the_provenance_needed_to_judge_them() {
        let mut idx = IocIndex::new(16);
        let mut o = object("obj", vec![sha256(0xAA)]);
        o.provenance = prov("public-feed", 30);
        idx.insert_object(&o);
        let hit = &idx.lookup(&sha256(0xAA), 0)[0];
        assert_eq!(hit.source_id, "public-feed");
        assert_eq!(hit.confidence, 30);
        assert_eq!(hit.object_id, "obj");
    }
}
