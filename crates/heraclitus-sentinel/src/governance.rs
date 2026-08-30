//! Append-only governance records for models, rulesets and analyst feedback.
//!
//! These records deliberately live beside the Sentinel runtime rather than in
//! mutable process configuration.  A replay can therefore recover which
//! artifact, ruleset and human assessment were in force at any LSN.

use crate::event::EvidenceRef;
use heraclitus_core::{Episode, EventKind, Lsn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

const MAX_TEXT_BYTES: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum GovernanceError {
    #[error("registro de governança inválido: {0}")]
    Invalid(String),
    #[error("serialização de governança: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn required(name: &str, value: &str) -> Result<(), GovernanceError> {
    if value.trim().is_empty() {
        Err(GovernanceError::Invalid(format!("{name} vazio")))
    } else {
        Ok(())
    }
}

fn digest(name: &str, value: &str) -> Result<(), GovernanceError> {
    required(name, value)?;
    let raw = value.strip_prefix("blake3:").unwrap_or(value);
    if value.len() > 256 || raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GovernanceError::Invalid(format!(
            "{name} não é um digest estável"
        )));
    }
    Ok(())
}

fn generated_episode(kind: &str, payload: Vec<u8>) -> Episode {
    let mut episode = Episode::new("sentinel", EventKind::Custom(kind.into()), payload);
    episode
        .attrs
        .insert("sentinel.generated".into(), "true".into());
    episode
}

/// Immutable model/artifact activation record (§71–72).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityModelUpdate {
    pub model_id: String,
    pub version: String,
    pub previous_digest: Option<String>,
    pub new_digest: String,
    pub artifact_digest: String,
    pub config_digest: String,
    pub evaluator_version: String,
    pub validation_metrics: BTreeMap<String, f64>,
    pub activated_at_lsn: Lsn,
}

impl SecurityModelUpdate {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        required("model_id", &self.model_id)?;
        required("version", &self.version)?;
        required("evaluator_version", &self.evaluator_version)?;
        digest("new_digest", &self.new_digest)?;
        digest("artifact_digest", &self.artifact_digest)?;
        digest("config_digest", &self.config_digest)?;
        if let Some(previous) = &self.previous_digest {
            digest("previous_digest", previous)?;
        }
        for (metric, value) in &self.validation_metrics {
            required("validation metric", metric)?;
            if !value.is_finite() || *value < 0.0 {
                return Err(GovernanceError::Invalid(
                    "métrica de validação inválida".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn update_id(&self) -> Result<String, GovernanceError> {
        Ok(format!(
            "model-{}",
            blake3::hash(&serde_json::to_vec(self)?).to_hex()
        ))
    }

    pub fn into_episode(&self) -> Result<Episode, GovernanceError> {
        self.validate()?;
        let mut episode = generated_episode("SecurityModelUpdate", serde_json::to_vec(self)?);
        episode
            .attrs
            .insert("sentinel.model_update_id".into(), self.update_id()?);
        episode
            .attrs
            .insert("sentinel.model_id".into(), self.model_id.clone());
        episode
            .attrs
            .insert("sentinel.model_version".into(), self.version.clone());
        episode.attrs.insert(
            "sentinel.artifact_digest".into(),
            self.artifact_digest.clone(),
        );
        episode
            .attrs
            .insert("sentinel.config_digest".into(), self.config_digest.clone());
        Ok(episode)
    }
}

/// Versioned rules/policy activation record (§73).  `approval_metadata` is
/// opaque but mandatory so a live ruleset cannot change without an auditable
/// authorisation trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityRulesetUpdate {
    pub ruleset_id: String,
    pub version: String,
    pub digest: String,
    pub activation_lsn: Lsn,
    pub author: String,
    pub approval_metadata: String,
}

impl SecurityRulesetUpdate {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        required("ruleset_id", &self.ruleset_id)?;
        required("version", &self.version)?;
        digest("digest", &self.digest)?;
        required("author", &self.author)?;
        required("approval_metadata", &self.approval_metadata)?;
        if self.approval_metadata.len() > MAX_TEXT_BYTES {
            return Err(GovernanceError::Invalid(
                "approval_metadata excede o limite".into(),
            ));
        }
        Ok(())
    }

    pub fn update_id(&self) -> Result<String, GovernanceError> {
        Ok(format!(
            "ruleset-{}",
            blake3::hash(&serde_json::to_vec(self)?).to_hex()
        ))
    }

    pub fn into_episode(&self) -> Result<Episode, GovernanceError> {
        self.validate()?;
        let mut episode = generated_episode("SecurityRulesetUpdate", serde_json::to_vec(self)?);
        episode
            .attrs
            .insert("sentinel.ruleset_update_id".into(), self.update_id()?);
        episode
            .attrs
            .insert("sentinel.ruleset_id".into(), self.ruleset_id.clone());
        episode
            .attrs
            .insert("sentinel.ruleset_version".into(), self.version.clone());
        episode
            .attrs
            .insert("sentinel.ruleset_digest".into(), self.digest.clone());
        Ok(episode)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackLabel {
    TruePositive,
    FalsePositive,
    BenignExpected,
    PolicyException,
}

/// Analyst feedback is evidence for offline evaluation, never an immediate
/// model or policy mutation (§74–75).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFeedback {
    pub feedback_id: String,
    pub incident_id: String,
    pub label: FeedbackLabel,
    pub analyst: String,
    pub reason: String,
    pub evidence: Vec<EvidenceRef>,
}

impl SecurityFeedback {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        required("feedback_id", &self.feedback_id)?;
        required("incident_id", &self.incident_id)?;
        required("analyst", &self.analyst)?;
        if self.reason.len() > MAX_TEXT_BYTES {
            return Err(GovernanceError::Invalid("reason excede o limite".into()));
        }
        Ok(())
    }

    pub fn feedback_id(&self) -> &str {
        &self.feedback_id
    }

    pub fn into_episode(&self) -> Result<Episode, GovernanceError> {
        self.validate()?;
        let mut episode = generated_episode("SecurityFeedback", serde_json::to_vec(self)?);
        let mut parents: Vec<_> = self.evidence.iter().map(|item| item.event_id).collect();
        parents.sort_unstable();
        parents.dedup();
        episode.parents = parents;
        episode
            .attrs
            .insert("sentinel.feedback_id".into(), self.feedback_id.clone());
        episode
            .attrs
            .insert("sentinel.incident_id".into(), self.incident_id.clone());
        Ok(episode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_records_are_validated_and_generated() {
        let update = SecurityModelUpdate {
            model_id: "investigator".into(),
            version: "v2".into(),
            previous_digest: None,
            new_digest: "blake3:abc123".into(),
            artifact_digest: "blake3:def456".into(),
            config_digest: "blake3:c0ffee".into(),
            evaluator_version: "eval-v1".into(),
            validation_metrics: [("precision".into(), 0.99)].into_iter().collect(),
            activated_at_lsn: 10,
        };
        let episode = update.into_episode().unwrap();
        assert_eq!(episode.kind.label(), "SecurityModelUpdate");
        assert_eq!(episode.attrs.get("sentinel.generated").unwrap(), "true");

        let feedback = SecurityFeedback {
            feedback_id: "fb-1".into(),
            incident_id: "inc-1".into(),
            label: FeedbackLabel::FalsePositive,
            analyst: "alice".into(),
            reason: "maintenance window".into(),
            evidence: Vec::new(),
        };
        assert_eq!(
            feedback.into_episode().unwrap().kind.label(),
            "SecurityFeedback"
        );
    }

    #[test]
    fn invalid_model_digest_fails_closed() {
        let update = SecurityModelUpdate {
            model_id: "m".into(),
            version: "v1".into(),
            previous_digest: None,
            new_digest: "not a digest".into(),
            artifact_digest: "blake3:a".into(),
            config_digest: "blake3:b".into(),
            evaluator_version: "e".into(),
            validation_metrics: BTreeMap::new(),
            activated_at_lsn: 1,
        };
        assert!(update.validate().is_err());
    }
}
