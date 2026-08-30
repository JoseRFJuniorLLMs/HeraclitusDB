//! Information-classification propagation for derived events.
//!
//! Classification is stored on the immutable derived episode itself.  The
//! default is the most restrictive source label.  A lower label requires an
//! explicit, policy-bound authorization whose scope matches the exact derived
//! event and exact source set.

use crate::regulatory::PolicyIdentity;
use heraclitus_core::{Episode, EventId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_VALUE_BYTES: usize = 4096;

#[derive(Debug, Error)]
pub enum ClassificationError {
    #[error("classificação inválida: {0}")]
    Invalid(String),
    #[error("rótulo de classificação desconhecido: {0}")]
    UnknownLabel(String),
    #[error("downgrade de classificação negado: {0}")]
    DowngradeDenied(String),
    #[error("serialização de classificação: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn required(name: &str, value: &str) -> Result<(), ClassificationError> {
    if value.trim().is_empty() || value.len() > MAX_VALUE_BYTES {
        return Err(ClassificationError::Invalid(format!(
            "{name} vazio ou maior que {MAX_VALUE_BYTES} bytes"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationControls {
    pub label: String,
    /// Higher rank means more restrictive.
    pub rank: u16,
    pub access_policy: String,
    pub export_policy: String,
    pub ai_disclosure_policy: String,
    pub retention_policy: String,
}

impl ClassificationControls {
    fn validate(&self) -> Result<(), ClassificationError> {
        for (name, value) in [
            ("label", self.label.as_str()),
            ("access_policy", self.access_policy.as_str()),
            ("export_policy", self.export_policy.as_str()),
            ("ai_disclosure_policy", self.ai_disclosure_policy.as_str()),
            ("retention_policy", self.retention_policy.as_str()),
        ] {
            required(name, value)?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ClassificationPolicyMaterial<'a> {
    policy_id: &'a str,
    version: &'a str,
    effective_from: u64,
    labels: &'a BTreeMap<String, ClassificationControls>,
    downgrade_authorities: &'a BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationPolicy {
    pub identity: PolicyIdentity,
    pub labels: BTreeMap<String, ClassificationControls>,
    pub downgrade_authorities: BTreeSet<String>,
}

impl ClassificationPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        version: impl Into<String>,
        effective_from: u64,
        labels: BTreeMap<String, ClassificationControls>,
        downgrade_authorities: BTreeSet<String>,
    ) -> Result<Self, ClassificationError> {
        let policy_id = policy_id.into();
        let version = version.into();
        let digest = policy_digest(
            &policy_id,
            &version,
            effective_from,
            &labels,
            &downgrade_authorities,
        )?;
        let policy = Self {
            identity: PolicyIdentity {
                policy_id,
                version,
                digest,
                effective_from,
            },
            labels,
            downgrade_authorities,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), ClassificationError> {
        required("policy_id", &self.identity.policy_id)?;
        required("policy version", &self.identity.version)?;
        if self.labels.is_empty() {
            return Err(ClassificationError::Invalid("política sem rótulos".into()));
        }
        let mut ranks = BTreeSet::new();
        for (key, controls) in &self.labels {
            controls.validate()?;
            if key != &controls.label {
                return Err(ClassificationError::Invalid(format!(
                    "chave {key} diverge do rótulo {}",
                    controls.label
                )));
            }
            if !ranks.insert(controls.rank) {
                return Err(ClassificationError::Invalid(format!(
                    "rank duplicado: {}",
                    controls.rank
                )));
            }
        }
        for authority in &self.downgrade_authorities {
            required("downgrade authority", authority)?;
        }
        let expected = policy_digest(
            &self.identity.policy_id,
            &self.identity.version,
            self.identity.effective_from,
            &self.labels,
            &self.downgrade_authorities,
        )?;
        if expected != self.identity.digest {
            return Err(ClassificationError::Invalid(
                "digest da política diverge da configuração".into(),
            ));
        }
        Ok(())
    }

    fn controls(&self, label: &str) -> Result<&ClassificationControls, ClassificationError> {
        self.labels
            .get(label)
            .ok_or_else(|| ClassificationError::UnknownLabel(label.into()))
    }
}

fn policy_digest(
    policy_id: &str,
    version: &str,
    effective_from: u64,
    labels: &BTreeMap<String, ClassificationControls>,
    downgrade_authorities: &BTreeSet<String>,
) -> Result<[u8; 32], ClassificationError> {
    let material = ClassificationPolicyMaterial {
        policy_id,
        version,
        effective_from,
        labels,
        downgrade_authorities,
    };
    Ok(*blake3::hash(&serde_json::to_vec(&material)?).as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceClassification {
    pub event_id: EventId,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationDowngradeAuthorization {
    pub authorization_id: String,
    pub derived_event_id: EventId,
    pub source_set_digest: [u8; 32],
    pub from_label: String,
    pub target_label: String,
    pub authorized_by: String,
    pub legal_basis: String,
    pub policy_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationDecision {
    pub derived_event_id: EventId,
    pub effective_label: String,
    pub maximum_source_label: String,
    pub source_set_digest: [u8; 32],
    pub downgrade_authorization_id: Option<String>,
    pub policy: PolicyIdentity,
}

fn source_digest(sources: &[SourceClassification]) -> Result<[u8; 32], ClassificationError> {
    let mut canonical = sources.to_vec();
    canonical.sort();
    canonical.dedup();
    Ok(*blake3::hash(&serde_json::to_vec(&canonical)?).as_bytes())
}

/// Classify a derived episode and attach the complete enforcement context.
///
/// The episode's causal parents are extended with all classified sources, so
/// a verifier can recompute the propagation decision during replay.
pub fn classify_derived_episode(
    derived: &mut Episode,
    sources: &[SourceClassification],
    requested_label: Option<&str>,
    authorization: Option<&ClassificationDowngradeAuthorization>,
    policy: &ClassificationPolicy,
) -> Result<ClassificationDecision, ClassificationError> {
    policy.validate()?;
    if sources.is_empty() {
        return Err(ClassificationError::Invalid(
            "evento derivado sem fontes classificadas".into(),
        ));
    }
    let mut maximum: Option<&ClassificationControls> = None;
    for source in sources {
        required("source label", &source.label)?;
        let controls = policy.controls(&source.label)?;
        if maximum.is_none_or(|current| controls.rank > current.rank) {
            maximum = Some(controls);
        }
    }
    let maximum = maximum.expect("sources was checked non-empty");
    let target = policy.controls(requested_label.unwrap_or(&maximum.label))?;
    let sources_digest = source_digest(sources)?;

    let downgrade_authorization_id = if target.rank < maximum.rank {
        let authorization = authorization.ok_or_else(|| {
            ClassificationError::DowngradeDenied("autorização explícita ausente".into())
        })?;
        validate_downgrade_authorization(
            authorization,
            derived.id,
            sources_digest,
            maximum,
            target,
            policy,
        )?;
        Some(authorization.authorization_id.clone())
    } else {
        if authorization.is_some() {
            return Err(ClassificationError::Invalid(
                "autorização de downgrade fornecida sem downgrade".into(),
            ));
        }
        None
    };

    for source in sources {
        derived.parents.push(source.event_id);
    }
    derived.parents.sort_unstable();
    derived.parents.dedup();
    let policy_digest_hex = hex_digest(&policy.identity.digest);
    for (key, value) in [
        ("classification.label", target.label.clone()),
        ("classification.rank", target.rank.to_string()),
        ("classification.access_policy", target.access_policy.clone()),
        ("classification.export_policy", target.export_policy.clone()),
        (
            "classification.ai_disclosure_policy",
            target.ai_disclosure_policy.clone(),
        ),
        (
            "classification.retention_policy",
            target.retention_policy.clone(),
        ),
        ("classification.maximum_source_label", maximum.label.clone()),
        (
            "classification.source_set_digest",
            hex_digest(&sources_digest),
        ),
        (
            "classification.policy_id",
            policy.identity.policy_id.clone(),
        ),
        (
            "classification.policy_version",
            policy.identity.version.clone(),
        ),
        ("classification.policy_digest", policy_digest_hex),
    ] {
        derived.attrs.insert(key.into(), value);
    }
    if let Some(authorization) = authorization.filter(|_| downgrade_authorization_id.is_some()) {
        derived.attrs.insert(
            "classification.downgrade_authorization_id".into(),
            authorization.authorization_id.clone(),
        );
        derived.attrs.insert(
            "classification.downgrade_authorized_by".into(),
            authorization.authorized_by.clone(),
        );
        derived.attrs.insert(
            "classification.downgrade_legal_basis".into(),
            authorization.legal_basis.clone(),
        );
    }

    Ok(ClassificationDecision {
        derived_event_id: derived.id,
        effective_label: target.label.clone(),
        maximum_source_label: maximum.label.clone(),
        source_set_digest: sources_digest,
        downgrade_authorization_id,
        policy: policy.identity.clone(),
    })
}

fn validate_downgrade_authorization(
    authorization: &ClassificationDowngradeAuthorization,
    derived_event_id: EventId,
    sources_digest: [u8; 32],
    maximum: &ClassificationControls,
    target: &ClassificationControls,
    policy: &ClassificationPolicy,
) -> Result<(), ClassificationError> {
    for (name, value) in [
        ("authorization_id", authorization.authorization_id.as_str()),
        ("authorized_by", authorization.authorized_by.as_str()),
        ("legal_basis", authorization.legal_basis.as_str()),
    ] {
        required(name, value)?;
    }
    if authorization.derived_event_id != derived_event_id
        || authorization.source_set_digest != sources_digest
        || authorization.from_label != maximum.label
        || authorization.target_label != target.label
        || authorization.policy_digest != policy.identity.digest
    {
        return Err(ClassificationError::DowngradeDenied(
            "escopo da autorização não corresponde ao derivado, fontes ou política".into(),
        ));
    }
    if !policy
        .downgrade_authorities
        .contains(&authorization.authorized_by)
    {
        return Err(ClassificationError::DowngradeDenied(format!(
            "autoridade não permitida: {}",
            authorization.authorized_by
        )));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::EventKind;

    fn controls(label: &str, rank: u16) -> ClassificationControls {
        ClassificationControls {
            label: label.into(),
            rank,
            access_policy: format!("access-{label}"),
            export_policy: format!("export-{label}"),
            ai_disclosure_policy: format!("ai-{label}"),
            retention_policy: format!("retention-{label}"),
        }
    }

    fn policy() -> ClassificationPolicy {
        ClassificationPolicy::new(
            "information-classification",
            "2026.1",
            0,
            [
                ("public".into(), controls("public", 0)),
                ("restricted".into(), controls("restricted", 10)),
                ("secret".into(), controls("secret", 20)),
            ]
            .into_iter()
            .collect(),
            ["security-office".into()].into_iter().collect(),
        )
        .unwrap()
    }

    fn sources() -> Vec<SourceClassification> {
        vec![
            SourceClassification {
                event_id: EventId::new(),
                label: "public".into(),
            },
            SourceClassification {
                event_id: EventId::new(),
                label: "secret".into(),
            },
        ]
    }

    #[test]
    fn derived_inherits_most_restrictive_source_and_all_controls() {
        let policy = policy();
        let sources = sources();
        let mut derived = Episode::new("distiller", EventKind::FactDerived, vec![]);
        let decision =
            classify_derived_episode(&mut derived, &sources, None, None, &policy).unwrap();
        assert_eq!(decision.effective_label, "secret");
        assert_eq!(derived.attrs["classification.label"], "secret");
        assert_eq!(
            derived.attrs["classification.access_policy"],
            "access-secret"
        );
        assert_eq!(derived.parents.len(), 2);
    }

    #[test]
    fn downgrade_without_exact_authorization_is_rejected() {
        let policy = policy();
        let sources = sources();
        let mut derived = Episode::new("distiller", EventKind::FactDerived, vec![]);
        assert!(matches!(
            classify_derived_episode(&mut derived, &sources, Some("restricted"), None, &policy),
            Err(ClassificationError::DowngradeDenied(_))
        ));
        assert!(!derived.attrs.contains_key("classification.label"));
    }

    #[test]
    fn exact_authorization_is_embedded_in_immutable_derived_event() {
        let policy = policy();
        let sources = sources();
        let mut derived = Episode::new("distiller", EventKind::FactDerived, vec![]);
        let authorization = ClassificationDowngradeAuthorization {
            authorization_id: "downgrade-42".into(),
            derived_event_id: derived.id,
            source_set_digest: source_digest(&sources).unwrap(),
            from_label: "secret".into(),
            target_label: "restricted".into(),
            authorized_by: "security-office".into(),
            legal_basis: "declassification-order-7".into(),
            policy_digest: policy.identity.digest,
        };
        let decision = classify_derived_episode(
            &mut derived,
            &sources,
            Some("restricted"),
            Some(&authorization),
            &policy,
        )
        .unwrap();
        assert_eq!(decision.effective_label, "restricted");
        assert_eq!(
            derived.attrs["classification.downgrade_authorization_id"],
            "downgrade-42"
        );

        let mut other = Episode::new("distiller", EventKind::FactDerived, vec![]);
        assert!(classify_derived_episode(
            &mut other,
            &sources,
            Some("restricted"),
            Some(&authorization),
            &policy,
        )
        .is_err());
    }

    #[test]
    fn policy_digest_detects_mutation() {
        let mut policy = policy();
        policy.labels.get_mut("public").unwrap().rank = 99;
        assert!(policy.validate().is_err());
    }
}
