//! SPEC-0047 §10–§13 — source trust, the admission gate, and the boundary
//! between "an IOC matched" and "do something about it".
//!
//! # §11, which is the point of the whole module
//!
//! ```text
//! IOC MATCH → SecuritySignal → EvidenceFusion → PolicyEngine
//! ```
//!
//! and never
//!
//! ```text
//! IOC MATCH → BLOCK FOREVER
//! ```
//!
//! [`ThreatIntelDetector`] therefore produces a [`SecuritySignal`] and a
//! [`DetectorAgreement`] on the `ThreatIntel` channel — and nothing else.  It
//! cannot return an action, because it has no type that is one.
//!
//! The second half of the guarantee already existed and is reused rather than
//! rebuilt: [`crate::correlation::high_impact_allowed`] requires two
//! *independent* detectors and at least one `Rule` or `Graph` channel.  Threat
//! intel alone therefore cannot reach a high-impact response no matter how
//! confident the feed claims to be — which is invariant T4 and §13's answer to
//! feed poisoning.  There is a test for it here, because a guarantee that
//! lives in another module's logic is one refactor away from silently
//! disappearing.
//!
//! # §13 — `source != truth`
//!
//! A compromised feed is assumed, not hoped against.  What this module
//! contributes: trust levels that gate `auto_block_allowed`, a minimum
//! confidence per source, and quarantine as a first-class admission outcome.
//! Feed signing and transport pinning belong to the importer and the transport
//! respectively; abrupt-change detection and version rollback are in
//! [`super::feed`].

use std::collections::BTreeMap;

use heraclitus_core::Lsn;
use serde::{Deserialize, Serialize};

use crate::correlation::{DetectorAgreement, DetectorChannel};
use crate::event::{DetectorIdentity, EntityRef, EvidenceRef, SecuritySignal};

use super::index::{ConfirmedMatch, MatchKind};
use super::ir::{IndicatorState, ThreatObject};

/// SPEC-0047 §10.  Ordered least to most authoritative; the ordering is used,
/// so adding a variant in the middle changes policy.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, Hash,
)]
pub enum TrustLevel {
    /// Quarantined or unknown origin.  Indicators are stored and correlated
    /// but never weighted as evidence.
    #[default]
    Untrusted,
    /// Open/community feeds.  High volume, uneven curation.
    Community,
    /// Paid feeds with a contract behind them.
    Commercial,
    /// A CERT, a regulator, a sector ISAC — authenticated and attributable.
    Institutional,
    /// Produced by this deployment.
    Internal,
}

impl TrustLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Community => "community",
            Self::Commercial => "commercial",
            Self::Institutional => "institutional",
            Self::Internal => "internal",
        }
    }

    /// The weight this source's confidence carries as evidence.
    ///
    /// `Untrusted` is exactly zero, not "a small number".  §13 says
    /// `source != truth`; a quarantined feed that still nudged the score
    /// upwards would let an attacker who owns the feed move the needle by
    /// volume alone.
    pub fn evidence_weight(&self) -> f32 {
        match self {
            Self::Untrusted => 0.0,
            Self::Community => 0.4,
            Self::Commercial => 0.7,
            Self::Institutional => 0.9,
            Self::Internal => 1.0,
        }
    }
}

/// SPEC-0047 §10.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatSourcePolicy {
    pub source_id: String,
    pub trust_level: TrustLevel,
    pub minimum_confidence: u8,
    /// Whether this source *may* participate in an automatic block at all.
    /// Even `true` is not permission: it is a precondition that the policy
    /// engine still has to clear (§11).
    pub auto_block_allowed: bool,
    /// §12 — the expiry applied when the source does not state one.  Zero
    /// means "the source must state one", and objects without an expiry from
    /// such a source are rejected.
    pub default_ttl_secs: u64,
}

impl ThreatSourcePolicy {
    /// A safe default for a source someone forgot to configure: untrusted, no
    /// automatic anything, and a 30-day expiry so it cannot accumulate
    /// forever.
    pub fn unconfigured(source_id: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            trust_level: TrustLevel::Untrusted,
            minimum_confidence: 0,
            auto_block_allowed: false,
            default_ttl_secs: 30 * 24 * 3_600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ThreatGateError {
    #[error("source `{source_id}` is unknown: an object with no configured policy has no trust, no TTL and no minimum confidence")]
    UnknownSource { source_id: String },
    #[error("object `{object_id}` has confidence {confidence}, below the {minimum} required by source `{source_id}`")]
    BelowMinimumConfidence {
        object_id: String,
        source_id: String,
        confidence: u8,
        minimum: u8,
    },
    #[error("object `{object_id}` has no expiry and source `{source_id}` declares no default TTL (§12 requires every indicator to have an expiration policy)")]
    NoExpiryPolicy {
        object_id: String,
        source_id: String,
    },
    #[error("object `{object_id}` carries no indicators")]
    NoIndicators { object_id: String },
}

/// What the admission gate decided.
#[derive(Debug, Clone, PartialEq)]
pub enum Admission {
    /// Admitted, possibly with a derived expiry filled in.
    Accepted(Box<ThreatObject>),
    /// Stored with `state = Quarantined`: it will not match and will not
    /// weigh, but it is not thrown away — §41 wants a contaminated update to
    /// be *deactivated*, not erased, and the same logic applies per object.
    Quarantined {
        object: Box<ThreatObject>,
        reason: String,
    },
}

impl Admission {
    pub fn object(&self) -> &ThreatObject {
        match self {
            Self::Accepted(o) => o,
            Self::Quarantined { object, .. } => object,
        }
    }

    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }
}

/// The configured sources of a deployment.
#[derive(Debug, Clone, Default)]
pub struct ThreatSourceRegistry {
    policies: BTreeMap<String, ThreatSourcePolicy>,
}

impl ThreatSourceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, policy: ThreatSourcePolicy) {
        self.policies.insert(policy.source_id.clone(), policy);
    }

    pub fn get(&self, source_id: &str) -> Option<&ThreatSourcePolicy> {
        self.policies.get(source_id)
    }

    /// SPEC-0047 §10/§12 — the admission gate.
    ///
    /// An unknown source is an **error**, not an implicit
    /// [`ThreatSourcePolicy::unconfigured`].  Silently inventing a policy is
    /// how a feed that nobody approved ends up in the index: the object would
    /// be stored, would match, and the only trace would be a source id nobody
    /// recognises. Callers that genuinely want a permissive default can insert
    /// `unconfigured` explicitly, which leaves a record of the choice.
    pub fn admit(
        &self,
        mut object: ThreatObject,
        now_ms: u64,
    ) -> Result<Admission, ThreatGateError> {
        let source = object.provenance.source_id.clone();
        let Some(policy) = self.policies.get(&source) else {
            return Err(ThreatGateError::UnknownSource { source_id: source });
        };
        if object.indicators.is_empty() && object.relationships.is_empty() {
            return Err(ThreatGateError::NoIndicators {
                object_id: object.object_id.clone(),
            });
        }
        if object.confidence() < policy.minimum_confidence {
            return Err(ThreatGateError::BelowMinimumConfidence {
                object_id: object.object_id.clone(),
                source_id: source,
                confidence: object.confidence(),
                minimum: policy.minimum_confidence,
            });
        }
        // §12 — every indicator gets an expiry, from the source or from policy.
        if object.valid_until.is_none() {
            if policy.default_ttl_secs == 0 {
                return Err(ThreatGateError::NoExpiryPolicy {
                    object_id: object.object_id.clone(),
                    source_id: source,
                });
            }
            let base = object.valid_from.unwrap_or(now_ms);
            // Auditoria 2026-09-05: a soma já saturava, a multiplicação que a
            // alimenta não. Com `overflow-checks = true` também em release, um
            // `default_ttl_secs` acima de `u64::MAX / 1_000` matava o arranque
            // do Sentinel no primeiro objecto sem `valid_until` — que é o caso
            // normal, e a razão de existir o TTL por omissão. O extremo superior
            // é tão configuração como o `== 0` acima; saturar aqui garante que
            // nunca há pânico, e o tecto em `validate_security`
            // (`sentinel.threat.default_ttl_secs`) garante que o valor absurdo
            // é recusado com diagnóstico em vez de virar um indicador eterno.
            object.valid_until =
                Some(base.saturating_add(policy.default_ttl_secs.saturating_mul(1_000)));
        }
        if policy.trust_level == TrustLevel::Untrusted {
            object.state = IndicatorState::Quarantined;
            return Ok(Admission::Quarantined {
                object: Box::new(object),
                reason: format!("source `{source}` is untrusted"),
            });
        }
        Ok(Admission::Accepted(Box::new(object)))
    }
}

/// SPEC-0047 §11 — turns confirmed matches into evidence and nothing else.
#[derive(Debug, Clone)]
pub struct ThreatIntelDetector {
    identity: DetectorIdentity,
}

impl ThreatIntelDetector {
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            identity: DetectorIdentity {
                id: "threat-intel".into(),
                version: version.into(),
            },
        }
    }

    pub fn identity(&self) -> &DetectorIdentity {
        &self.identity
    }

    /// The score a set of matches contributes.
    ///
    /// Trust multiplies confidence, and a domain-suffix or CIDR-prefix hit is
    /// discounted: matching `a.b.evil.com` against a stored `evil.com` is a
    /// weaker claim than matching `evil.com` itself, and scoring them equally
    /// is how a single broad indicator ends up dominating an assessment.
    /// Matches are combined as a noisy-OR so that ten mediocre community hits
    /// cannot out-vote one institutional one.
    pub fn score(&self, matches: &[ConfirmedMatch], registry: &ThreatSourceRegistry) -> f32 {
        let mut miss = 1.0f32;
        for m in matches {
            let trust = registry
                .get(&m.source_id)
                .map(|p| p.trust_level.evidence_weight())
                .unwrap_or(0.0);
            let breadth = match m.kind {
                MatchKind::Exact => 1.0,
                MatchKind::DomainSuffix | MatchKind::IpPrefix => 0.5,
            };
            let contribution = (m.confidence as f32 / 100.0) * trust * breadth;
            miss *= 1.0 - contribution.clamp(0.0, 1.0);
        }
        (1.0 - miss).clamp(0.0, 1.0)
    }

    /// SPEC-0047 §11 — the only output of an IOC match.
    ///
    /// Returns `None` when nothing matched, or when everything that matched
    /// carries zero weight (an untrusted source).  A signal with score zero
    /// would still be a signal: it would appear in the incident, in the
    /// dashboard and in the fusion input, and someone would eventually treat
    /// its presence as meaning something.
    pub fn signal(
        &self,
        subject: EntityRef,
        matches: &[ConfirmedMatch],
        evidence: Vec<EvidenceRef>,
        registry: &ThreatSourceRegistry,
        created_at_lsn: Lsn,
    ) -> Option<SecuritySignal> {
        if matches.is_empty() {
            return None;
        }
        let score = self.score(matches, registry);
        if score <= 0.0 {
            return None;
        }
        let mut labels = BTreeMap::new();
        labels.insert("threat.match_count".into(), matches.len().to_string());
        labels.insert("threat.object_ids".into(), {
            let mut ids: Vec<&str> = matches.iter().map(|m| m.object_id.as_str()).collect();
            ids.sort_unstable();
            ids.dedup();
            ids.join(",")
        });
        labels.insert(
            "threat.max_tlp".into(),
            matches
                .iter()
                .map(|m| m.tlp)
                .max()
                .unwrap_or_default()
                .label()
                .to_owned(),
        );
        labels.insert(
            "threat.broadest_match".into(),
            if matches.iter().all(|m| m.kind == MatchKind::Exact) {
                "exact".into()
            } else {
                "suffix-or-prefix".to_string()
            },
        );
        let signal_id = SecuritySignal::deterministic_id(
            &self.identity,
            Some(&subject),
            &evidence,
            created_at_lsn,
        );
        Some(SecuritySignal {
            signal_id,
            detector: self.identity.clone(),
            // Auditoria 2026-09-05: aqui estava `(score * 100.0).round()`, uma
            // escala 0-100 que mais nenhum produtor de `SecuritySignal` usa. O
            // Sigma emite 1-10 (`critical` => 10) e o L2 emite
            // `((score*10.0).ceil() as u8).clamp(1, 10)`. A severidade de um
            // incidente é o MÁXIMO das dos seus sinais, e esse máximo é
            // irreversível: um único match de IOC punha o incidente em 81 e
            // deixava-o lá. Fora do domínio 0-10, nenhum filtro que o operador
            // consiga exprimir o exclui (o filtro recusa `min_severity > 10`) e
            // a triagem inverte-se — um IOC medíocre pesava mais do que um
            // alerta Sigma crítico. O `ceil` (e não `round`) é o mesmo do L2 e é
            // deliberado: um sinal só é emitido quando `score > 0`, logo o piso
            // da escala tem de ser 1 e nunca 0.
            severity: ((score * 10.0).ceil() as u8).clamp(1, 10),
            score,
            subject: Some(subject),
            evidence,
            created_at_lsn,
            labels,
        })
    }

    /// The fusion input this detector contributes.  Always on the
    /// `ThreatIntel` channel, which is what keeps
    /// [`crate::correlation::high_impact_allowed`] from counting it as one of
    /// the `Rule`/`Graph` detectors a high-impact action requires.
    pub fn agreement(&self) -> DetectorAgreement {
        DetectorAgreement {
            detector_id: self.identity.id.clone(),
            channel: DetectorChannel::ThreatIntel,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlation::{high_impact_allowed, EvidenceFusion, FusionWeights};
    use crate::threat::index::MatchKind;
    use crate::threat::ir::{HashAlgorithm, Indicator, ThreatObjectType, ThreatProvenance};
    use crate::threat::tlp::TlpLevel;

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

    fn object(source: &str, confidence: u8) -> ThreatObject {
        let mut o = ThreatObject::new(
            "obj",
            ThreatObjectType::Indicator,
            prov(source, confidence),
            [0; 32],
        );
        o.indicators = vec![Indicator::FileHash {
            algorithm: HashAlgorithm::Sha256,
            value: vec![0xAA; 32],
        }];
        o
    }

    fn registry(trust: TrustLevel, minimum: u8, ttl: u64) -> ThreatSourceRegistry {
        let mut r = ThreatSourceRegistry::new();
        r.insert(ThreatSourcePolicy {
            source_id: "feed".into(),
            trust_level: trust,
            minimum_confidence: minimum,
            auto_block_allowed: false,
            default_ttl_secs: ttl,
        });
        r
    }

    fn hit(source: &str, confidence: u8, kind: MatchKind) -> ConfirmedMatch {
        ConfirmedMatch {
            object_id: "obj".into(),
            source_id: source.into(),
            indicator: Indicator::Domain("evil.com".into()),
            confidence,
            tlp: TlpLevel::Amber,
            kind,
        }
    }

    #[test]
    fn an_unknown_source_is_refused_not_defaulted() {
        let r = ThreatSourceRegistry::new();
        assert!(matches!(
            r.admit(object("feed", 80), 0),
            Err(ThreatGateError::UnknownSource { .. })
        ));
    }

    #[test]
    fn default_ttl_is_applied_when_the_source_states_no_expiry() {
        // §12 — no indicator lives forever by omission.
        let r = registry(TrustLevel::Commercial, 0, 3_600);
        let admitted = r.admit(object("feed", 80), 1_000).unwrap();
        assert_eq!(admitted.object().valid_until, Some(1_000 + 3_600_000));
    }

    #[test]
    fn old_intelligence_does_not_become_fresh_on_ingestion() {
        // The TTL is measured from what the source asserts, not from when we
        // happened to download it.  Anchoring to `now` would give a six-year-old
        // indicator a full new lifetime every time a feed was re-fetched, so it
        // would never expire at all — which is §12 defeated by a re-sync loop.
        let r = registry(TrustLevel::Commercial, 0, 90 * 24 * 3_600);
        let mut old = object("feed", 80);
        old.valid_from = Some(1_000);
        let now = 1_000 + 200 * 24 * 3_600 * 1_000;
        let admitted = r.admit(old, now).unwrap();
        let object = admitted.object();
        assert_eq!(object.valid_until, Some(1_000 + 90 * 24 * 3_600 * 1_000));
        assert!(
            !object.is_in_force_at(now),
            "an indicator whose stated window closed long ago must arrive expired"
        );
    }

    #[test]
    fn no_expiry_and_no_default_ttl_is_rejected() {
        let r = registry(TrustLevel::Commercial, 0, 0);
        assert!(matches!(
            r.admit(object("feed", 80), 0),
            Err(ThreatGateError::NoExpiryPolicy { .. })
        ));
    }

    #[test]
    fn confidence_below_the_source_minimum_is_rejected() {
        let r = registry(TrustLevel::Commercial, 60, 3_600);
        assert!(matches!(
            r.admit(object("feed", 59), 0),
            Err(ThreatGateError::BelowMinimumConfidence { .. })
        ));
        assert!(r.admit(object("feed", 60), 0).unwrap().is_accepted());
    }

    #[test]
    fn an_untrusted_source_is_quarantined_and_kept() {
        // §41's logic at object granularity: deactivate, do not erase.
        let r = registry(TrustLevel::Untrusted, 0, 3_600);
        let admitted = r.admit(object("feed", 100), 0).unwrap();
        assert!(!admitted.is_accepted());
        assert_eq!(admitted.object().state, IndicatorState::Quarantined);
    }

    #[test]
    fn an_untrusted_match_produces_no_signal_at_all() {
        // Not "a signal with score 0": its mere presence would be read as
        // meaning something by an incident view or a dashboard.
        let detector = ThreatIntelDetector::new("1.0.0");
        let r = registry(TrustLevel::Untrusted, 0, 3_600);
        assert!(detector
            .signal(
                EntityRef::new("host", "h1"),
                &[hit("feed", 100, MatchKind::Exact)],
                vec![],
                &r,
                1,
            )
            .is_none());
    }

    #[test]
    fn a_broad_match_scores_below_an_exact_one() {
        let detector = ThreatIntelDetector::new("1.0.0");
        let r = registry(TrustLevel::Institutional, 0, 3_600);
        let exact = detector.score(&[hit("feed", 90, MatchKind::Exact)], &r);
        let suffix = detector.score(&[hit("feed", 90, MatchKind::DomainSuffix)], &r);
        assert!(
            suffix < exact,
            "a zone-wide hit must not weigh the same as the domain itself ({suffix} vs {exact})"
        );
    }

    #[test]
    fn volume_from_a_weak_source_cannot_outweigh_one_strong_hit() {
        let detector = ThreatIntelDetector::new("1.0.0");
        let mut r = ThreatSourceRegistry::new();
        r.insert(ThreatSourcePolicy {
            source_id: "public".into(),
            trust_level: TrustLevel::Community,
            minimum_confidence: 0,
            auto_block_allowed: false,
            default_ttl_secs: 3_600,
        });
        r.insert(ThreatSourcePolicy {
            source_id: "cert".into(),
            trust_level: TrustLevel::Institutional,
            minimum_confidence: 0,
            auto_block_allowed: true,
            default_ttl_secs: 3_600,
        });
        // Ten low-confidence community hits...
        let many: Vec<ConfirmedMatch> = (0..10)
            .map(|_| hit("public", 20, MatchKind::DomainSuffix))
            .collect();
        let one = vec![hit("cert", 95, MatchKind::Exact)];
        assert!(
            detector.score(&one, &r) > detector.score(&many, &r),
            "noisy-OR must not let a poisoned high-volume feed dominate"
        );
    }

    #[test]
    fn threat_intel_alone_never_authorises_a_high_impact_action() {
        // Invariant T4 / §13.  The rule lives in `correlation`; this test
        // exists so a refactor there cannot silently remove it from under the
        // threat plane.
        let detector = ThreatIntelDetector::new("1.0.0");
        let fusion = EvidenceFusion::new(FusionWeights::default(), "m1").unwrap();
        let assessment = fusion
            .fuse(EntityRef::new("host", "h1"), 0.0, 0.0, 0.0, 1.0, vec![])
            .unwrap();
        assert!(
            !high_impact_allowed(&assessment, &[detector.agreement()]),
            "a maximal threat-intel score with no other channel must not authorise a response"
        );
    }

    #[test]
    fn the_signal_records_what_a_reviewer_needs_to_judge_it() {
        let detector = ThreatIntelDetector::new("1.0.0");
        let r = registry(TrustLevel::Institutional, 0, 3_600);
        let signal = detector
            .signal(
                EntityRef::new("host", "h1"),
                &[hit("feed", 90, MatchKind::DomainSuffix)],
                vec![],
                &r,
                7,
            )
            .unwrap();
        assert_eq!(signal.detector.id, "threat-intel");
        assert_eq!(signal.labels["threat.match_count"], "1");
        assert_eq!(signal.labels["threat.broadest_match"], "suffix-or-prefix");
        assert_eq!(signal.labels["threat.max_tlp"], "TLP:AMBER");
        assert_eq!(signal.created_at_lsn, 7);
    }

    #[test]
    fn a_severidade_do_sinal_vive_na_escala_1_a_10_do_sigma_e_do_l2() {
        // Auditoria 2026-09-05 (A12): `severity` era `(score * 100.0).round()`,
        // enquanto os outros dois produtores de `SecuritySignal` usam 0-10 — o
        // Sigma (`critical` => 10) e o L2 (`((score*10.0).ceil()).clamp(1,10)`).
        // Como a severidade do incidente é o MÁXIMO das dos sinais
        // (`correlation.rs`), um único IOC punha o incidente em 81, fora do
        // domínio que o próprio filtro de consulta declara (`min_severity`
        // recusa > 10): nenhum filtro do operador o conseguia excluir.
        let detector = ThreatIntelDetector::new("1.0.0");

        // Institutional (0.9) x confidence 90 x exacto (1.0) => score 0.81.
        let institucional = registry(TrustLevel::Institutional, 0, 3_600);
        let forte = detector
            .signal(
                EntityRef::new("host", "h1"),
                &[hit("feed", 90, MatchKind::Exact)],
                vec![],
                &institucional,
                1,
            )
            .unwrap();
        assert!(
            (1..=10).contains(&forte.severity),
            "a severidade tem de caber na escala partilhada 1-10; veio {}",
            forte.severity
        );

        // O topo desta escala é o mesmo topo do Sigma `critical`: 10.
        let interno = registry(TrustLevel::Internal, 0, 3_600);
        let maximo = detector
            .signal(
                EntityRef::new("host", "h1"),
                &[hit("feed", 100, MatchKind::Exact)],
                vec![],
                &interno,
                1,
            )
            .unwrap();
        assert_eq!(
            maximo.severity, 10,
            "um match máximo vale exactamente o mesmo que um Sigma critical"
        );

        // Um sinal só existe quando `score > 0`, logo o piso da escala é 1 e
        // nunca 0: um sinal de severidade zero seria um sinal invisível.
        let comunidade = registry(TrustLevel::Community, 0, 3_600);
        let fraco = detector
            .signal(
                EntityRef::new("host", "h1"),
                &[hit("feed", 20, MatchKind::DomainSuffix)],
                vec![],
                &comunidade,
                1,
            )
            .unwrap();
        assert_eq!(
            fraco.severity, 1,
            "o match mais fraco que ainda produz sinal vale 1, não 0"
        );
        assert!(
            fraco.severity < forte.severity,
            "a ordem de triagem tem de sobreviver à escala ({} vs {})",
            fraco.severity,
            forte.severity
        );
    }

    #[test]
    fn um_ttl_de_configuracao_absurdo_satura_em_vez_de_matar_o_arranque() {
        // Auditoria 2026-09-05 (A52): a soma já era `saturating_add`, mas a
        // multiplicação que a alimenta (`default_ttl_secs * 1_000`) estava nua.
        // Com `overflow-checks = true` também em release, um TTL de configuração
        // acima de `u64::MAX/1000` matava o arranque do Sentinel no primeiro
        // objecto sem `valid_until` — que é o caso normal, e a razão de existir
        // o TTL por omissão.
        let r = registry(TrustLevel::Commercial, 0, u64::MAX);
        let admitido = r
            .admit(object("feed", 80), 0)
            .expect("a admissão não pode entrar em pânico por causa da configuração");
        assert_eq!(admitido.object().valid_until, Some(u64::MAX));
    }
}
