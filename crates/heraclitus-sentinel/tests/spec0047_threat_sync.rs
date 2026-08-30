//! SPEC-0047 gates T0–T5 and the invariants, end to end.
//!
//! The unit tests prove each piece.  This file proves the pipeline the SPEC
//! actually specifies — bytes in from an untrusted feed, evidence out, and
//! nothing in between that can shortcut a step:
//!
//! ```text
//! STIX bundle → import (§14–§17) → admit (§10, §12) → index (§7)
//!            → match → SecuritySignal (§11) → sighting (§36)
//!            → sanitize (§26) → export
//! ```
//!
//! Each test below is one of the SPEC's own gates, named after it.

use heraclitus_core::EventId;
use heraclitus_sentinel::threat::canonical::canonical_ip;
use heraclitus_sentinel::threat::sharing::PolicySanitizer;
use heraclitus_sentinel::{
    Admission, EntityRef, Indicator, IndicatorState, IocIndex, MatchKind, PrefilterOutcome,
    Pseudonymizer, SanitizationError, SharingPolicy, StixImporter, ThreatImporter,
    ThreatIntelDetector, ThreatSanitizer, ThreatSourcePolicy, ThreatSourceRegistry, ThreatSighting,
    TlpLevel, TrustLevel,
};

const NOW: u64 = 1_800_000_000_000;

/// A bundle shaped like the ones a CERT actually publishes: a TLP marking, a
/// couple of indicators, a malware object and a relationship between them.
fn bundle() -> Vec<u8> {
    br#"{
      "type": "bundle",
      "id": "bundle--sample",
      "objects": [
        {"type":"marking-definition","id":"marking-definition--amber","name":"TLP:AMBER"},
        {"type":"marking-definition","id":"marking-definition--red","name":"TLP:RED"},
        {"type":"indicator","id":"indicator--net","spec_version":"2.1","confidence":85,
         "pattern":"[ipv4-addr:value = '203.0.113.0/24']",
         "valid_from":"2027-01-01T00:00:00Z",
         "object_marking_refs":["marking-definition--amber"]},
        {"type":"indicator","id":"indicator--dom","spec_version":"2.1","confidence":95,
         "pattern":"[domain-name:value = 'EVIL.example.']",
         "valid_from":"2027-01-01T00:00:00Z",
         "object_marking_refs":["marking-definition--amber"]},
        {"type":"indicator","id":"indicator--secret","spec_version":"2.1","confidence":60,
         "pattern":"[url:value = 'https://leak.example/cb?api_key=AKIA1234567890ABCD']",
         "valid_from":"2027-01-01T00:00:00Z",
         "object_marking_refs":["marking-definition--red"]},
        {"type":"malware","id":"malware--x","name":"Sample","is_family":false,
         "object_marking_refs":["marking-definition--amber"]},
        {"type":"relationship","id":"relationship--1","relationship_type":"indicates",
         "source_ref":"indicator--dom","target_ref":"malware--x",
         "object_marking_refs":["marking-definition--amber"]}
      ]
    }"#
    .to_vec()
}

fn registry(trust: TrustLevel) -> ThreatSourceRegistry {
    let mut r = ThreatSourceRegistry::new();
    r.insert(ThreatSourcePolicy {
        source_id: "cert".into(),
        trust_level: trust,
        minimum_confidence: 50,
        auto_block_allowed: true,
        default_ttl_secs: 90 * 24 * 3_600,
    });
    r
}

/// Import, admit and index the sample bundle.
fn ingest(trust: TrustLevel) -> (IocIndex, ThreatSourceRegistry, Vec<Admission>) {
    let importer = StixImporter::new("cert", "collection-1", NOW);
    let objects = importer.import(&bundle()).unwrap();
    let registry = registry(trust);
    let mut index = IocIndex::new(64);
    let mut admissions = Vec::new();
    for object in objects {
        // §12: the gate rejects an object it cannot give a lifecycle to, and
        // the relationship-only object carries no indicators of its own.
        let Ok(admission) = registry.admit(object, NOW) else {
            continue;
        };
        if admission.is_accepted() {
            index.insert_object(admission.object());
        }
        admissions.push(admission);
    }
    (index, registry, admissions)
}

// ---------------------------------------------------------------------------
// T0 — STIX interoperability
// ---------------------------------------------------------------------------

#[test]
fn t0_a_stix_bundle_imports_without_losing_supported_fields() {
    let importer = StixImporter::new("cert", "collection-1", NOW);
    let (objects, report) = importer.import_with_report(&bundle()).unwrap();

    // Markings are metadata, not intelligence: 3 indicators + malware +
    // relationship.
    assert_eq!(objects.len(), 5);
    assert_eq!(report.indicators, 3);
    assert_eq!(report.unsupported_patterns, 0);

    let net = &objects[0];
    assert_eq!(net.provenance.source_id, "cert");
    assert_eq!(net.provenance.collection, "collection-1");
    assert_eq!(net.provenance.received_at, NOW);
    assert_eq!(net.provenance.source_object_id, "indicator--net");
    assert_eq!(net.confidence(), 85);
    assert_eq!(net.tlp(), TlpLevel::Amber);
    assert_eq!(net.indicators[0], canonical_ip("203.0.113.0/24").unwrap());

    // §21 happened on the way in: uppercase and the root dot are gone.
    assert_eq!(
        objects[1].indicators[0],
        Indicator::Domain("evil.example".into())
    );

    // §5/§17: the malware object's unmodelled fields survived.
    let malware = &objects[3];
    assert!(malware.unknown_fields.contains_key("name"));
    assert!(malware.unknown_fields.contains_key("is_family"));

    // The relationship became a relationship, not a lost object.
    assert_eq!(objects[4].relationships.len(), 1);
    assert_eq!(objects[4].relationships[0].relationship_type, "indicates");
    assert_eq!(objects[4].relationships[0].target_object_id, "malware--x");
}

// ---------------------------------------------------------------------------
// T3 — Bloom safety
// ---------------------------------------------------------------------------

#[test]
fn t3_a_prefilter_hit_carries_nothing_and_decides_nothing() {
    let (index, _, _) = ingest(TrustLevel::Institutional);

    // The absent probe: the prefilter may say "maybe", the exact structure
    // says no, and there is no third opinion available to a caller.
    let absent = Indicator::UserAgent("curl/8.0".into());
    let outcome = index.prefilter(&absent);
    assert!(index.lookup(&absent, NOW).is_empty());

    // A `PrefilterHit` exposes no field and converts to nothing: the only way
    // past it is `lookup`.  This match is the whole assertion — if the variant
    // ever gains a payload that names an object, this stops compiling.
    match outcome {
        PrefilterOutcome::DefinitelyAbsent => {}
        PrefilterOutcome::MaybePresent(_hit) => {}
    }
}

// ---------------------------------------------------------------------------
// The pipeline: match → signal → sighting
// ---------------------------------------------------------------------------

#[test]
fn an_ioc_match_produces_evidence_and_a_sighting_and_nothing_else() {
    let (index, registry, _) = ingest(TrustLevel::Institutional);
    let detector = ThreatIntelDetector::new("1.0.0");

    // Traffic to an address inside the published block.
    let probe = canonical_ip("203.0.113.42").unwrap();
    let hits = index.lookup(&probe, NOW);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].kind, MatchKind::IpPrefix);
    assert_eq!(hits[0].object_id, "indicator--net");

    // §11 — the output of a match is a signal.
    let event = EventId::new();
    let signal = detector
        .signal(
            EntityRef::new("host", "web-01"),
            &hits,
            vec![heraclitus_sentinel::EvidenceRef {
                lsn: 99,
                event_id: event,
            }],
            &registry,
            99,
        )
        .expect("an institutional match must produce evidence");
    assert_eq!(signal.detector.id, "threat-intel");
    assert!(signal.score > 0.0 && signal.score < 1.0);
    assert_eq!(signal.labels["threat.object_ids"], "indicator--net");

    // §36 — the sighting is a new fact that points at the indicator.
    let sighting = ThreatSighting::from_match(&hits[0], event, 99, NOW);
    assert_eq!(sighting.indicator_id, "indicator--net");
    assert_eq!(sighting.match_kind, "ip-prefix");

    // Both persist as derived events with the observed event as parent, using
    // the existing `Custom` escape hatch rather than a new discriminant.
    let signal_episode = signal.into_episode().unwrap();
    let sighting_episode = sighting.into_episode().unwrap();
    assert_eq!(signal_episode.parents, vec![event]);
    assert_eq!(sighting_episode.parents, vec![event]);
    assert_eq!(sighting_episode.attrs["sentinel.generated"], "true");
}

#[test]
fn a_domain_below_a_published_one_matches_as_a_suffix() {
    let (index, _, _) = ingest(TrustLevel::Institutional);
    let hits = index.lookup(&Indicator::Domain("c2.evil.example".into()), NOW);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].kind, MatchKind::DomainSuffix);

    // And a lookalike does not.
    assert!(index
        .lookup(&Indicator::Domain("notevil.example".into()), NOW)
        .is_empty());
}

// ---------------------------------------------------------------------------
// T4 — poisoning
// ---------------------------------------------------------------------------

#[test]
fn t4_an_untrusted_feed_reaches_the_index_but_never_the_evidence() {
    // The whole feed is the same bytes; only the trust configuration differs.
    let (index, registry, admissions) = ingest(TrustLevel::Untrusted);
    assert!(
        admissions.iter().all(|a| !a.is_accepted()),
        "an untrusted source must not be admitted outright"
    );
    assert!(
        admissions
            .iter()
            .all(|a| a.object().state == IndicatorState::Quarantined),
        "and must be kept, quarantined, rather than discarded"
    );
    // Quarantined objects were never indexed, so nothing matches...
    assert!(index.is_empty());

    // ...and even if one had been, an untrusted match weighs zero and
    // produces no signal at all.
    let detector = ThreatIntelDetector::new("1.0.0");
    let mut forced = IocIndex::new(8);
    let mut object = admissions[0].object().clone();
    object.state = IndicatorState::Active;
    forced.insert_object(&object);
    let hits = forced.lookup(&canonical_ip("203.0.113.42").unwrap(), NOW);
    assert_eq!(hits.len(), 1, "the forced index must actually match");
    assert!(
        detector
            .signal(EntityRef::new("host", "h"), &hits, vec![], &registry, 1)
            .is_none(),
        "a poisoned feed must not be able to manufacture evidence"
    );
}

// ---------------------------------------------------------------------------
// T5 — TLP
// ---------------------------------------------------------------------------

#[test]
fn t5_tlp_red_never_leaves_and_amber_leaves_only_where_allowed() {
    let (_, _, admissions) = ingest(TrustLevel::Institutional);
    let sanitizer = PolicySanitizer::new(Pseudonymizer::for_destination(b"deployment", "partner"));

    let red = admissions
        .iter()
        .map(|a| a.object())
        .find(|o| o.tlp() == TlpLevel::Red)
        .expect("the sample bundle carries a TLP:RED object");
    let amber = admissions
        .iter()
        .map(|a| a.object())
        .find(|o| o.object_id == "indicator--net")
        .unwrap();

    let to_partner = SharingPolicy {
        destination: "partner".into(),
        maximum_tlp: TlpLevel::Amber,
        allow_internal_ips: false,
        allow_user_identity: false,
        allow_asset_names: false,
        allow_raw_evidence: false,
    };

    assert!(
        matches!(
            sanitizer.sanitize(red, &to_partner),
            Err(SanitizationError::TlpCeiling { .. })
        ),
        "TLP:RED must not clear an TLP:AMBER destination"
    );

    let shared = sanitizer.sanitize(amber, &to_partner).unwrap();
    assert_eq!(shared.indicators, vec!["203.0.113.0/24"]);
    assert_eq!(shared.destination, "partner");
    assert_eq!(shared.tlp, TlpLevel::Amber);
}

#[test]
fn the_red_object_would_also_have_been_stopped_by_the_leak_gate() {
    // Defence in depth, and a real case: the TLP:RED indicator in the sample
    // is a callback URL carrying an API key.  Even to a destination cleared
    // for TLP:RED, §27 refuses it.
    let (_, _, admissions) = ingest(TrustLevel::Institutional);
    let sanitizer = PolicySanitizer::new(Pseudonymizer::for_destination(b"deployment", "gov"));
    let red = admissions
        .iter()
        .map(|a| a.object())
        .find(|o| o.tlp() == TlpLevel::Red)
        .unwrap();

    let cleared_for_red = SharingPolicy {
        destination: "gov".into(),
        maximum_tlp: TlpLevel::Red,
        allow_internal_ips: true,
        allow_user_identity: true,
        allow_asset_names: true,
        allow_raw_evidence: true,
    };
    match sanitizer.sanitize(red, &cleared_for_red) {
        Err(SanitizationError::InternalDataLeak { category, .. }) => {
            assert_eq!(category, "raw token")
        }
        other => panic!("§27 must refuse a credential regardless of the ceiling: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// §12 — lifecycle across the pipeline
// ---------------------------------------------------------------------------

#[test]
fn every_admitted_object_has_an_expiry_and_stops_matching_at_it() {
    let (index, _, admissions) = ingest(TrustLevel::Institutional);
    for admission in &admissions {
        assert!(
            admission.object().valid_until.is_some(),
            "§12: `{}` was admitted without an expiry",
            admission.object().object_id
        );
    }

    let probe = canonical_ip("203.0.113.42").unwrap();
    assert_eq!(index.lookup(&probe, NOW).len(), 1);

    let expiry = admissions
        .iter()
        .find(|a| a.object().object_id == "indicator--net")
        .unwrap()
        .object()
        .valid_until
        .unwrap();
    assert!(
        index.lookup(&probe, expiry).is_empty(),
        "an expired indicator must stop matching without anyone sweeping the index"
    );
}
