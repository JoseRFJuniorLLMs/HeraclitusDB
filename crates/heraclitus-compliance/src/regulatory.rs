//! Versioned regulatory policy, retention classes and event-sourced legal holds.
//!
//! The policy engine deliberately stores policy definitions and decisions in
//! the episode log.  Process configuration is only an input: a replay can
//! recover exactly which policy version produced a decision at a given LSN.

use heraclitus_core::{Episode, EventKind, Lsn};
use heraclitus_log::{AnyLog, EpisodeLog};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;

const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_RULES: usize = 4096;

const POLICY_EVENT: &str = "CompliancePolicyActivation";
const ASSESSMENT_EVENT: &str = "ComplianceAssessment";
const LEGAL_HOLD_EVENT: &str = "LegalHold";
const LEGAL_HOLD_RELEASE_EVENT: &str = "LegalHoldRelease";

#[derive(Debug, Error)]
pub enum RegulatoryError {
    #[error("configuração regulatória inválida: {0}")]
    Invalid(String),
    #[error("serialização regulatória: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("log regulatório: {0}")]
    Storage(String),
    #[error("operação regulatória não suportada: {0}")]
    Unsupported(String),
}

fn required(name: &str, value: &str) -> Result<(), RegulatoryError> {
    if value.trim().is_empty() {
        return Err(RegulatoryError::Invalid(format!("{name} vazio")));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(RegulatoryError::Invalid(format!(
            "{name} excede {MAX_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn generated_episode(kind: &str, payload: Vec<u8>) -> Episode {
    let mut episode = Episode::new(
        "gov-compliance",
        EventKind::Custom(kind.to_owned()),
        payload,
    );
    episode
        .attrs
        .insert("compliance.generated".into(), "true".into());
    episode
}

/// Stable identity of one regulatory policy version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIdentity {
    pub policy_id: String,
    pub version: String,
    pub digest: [u8; 32],
    pub effective_from: u64,
}

/// Retention is selected by policy; the engine does not assign universal
/// durations to any class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    Operational,
    Security,
    IncidentEvidence,
    PersonalData,
    ClassifiedInformation,
    PermanentArchive,
    LegalHold,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "effect", rename_all = "snake_case")]
pub enum RequirementEffect {
    RetainForSeconds { seconds: u64 },
    PreventDestruction,
    RequireHumanAuthorization,
    PreserveClassification,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    pub requirement_id: String,
    pub legal_basis: String,
    pub effect: RequirementEffect,
}

impl ComplianceRequirement {
    fn validate(&self) -> Result<(), RegulatoryError> {
        required("requirement_id", &self.requirement_id)?;
        required("legal_basis", &self.legal_basis)?;
        if matches!(
            self.effect,
            RequirementEffect::RetainForSeconds { seconds: 0 }
        ) {
            return Err(RegulatoryError::Invalid(
                "retenção configurada com zero segundos".into(),
            ));
        }
        Ok(())
    }
}

/// Declarative selector for a policy rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompliancePredicate {
    pub event_kind: Option<String>,
    pub retention_class: Option<RetentionClass>,
    #[serde(default)]
    pub attr_equals: BTreeMap<String, String>,
}

impl CompliancePredicate {
    fn matches(&self, context: &ComplianceContext) -> bool {
        self.event_kind
            .as_ref()
            .is_none_or(|wanted| wanted == &context.event_kind)
            && self
                .retention_class
                .is_none_or(|wanted| wanted == context.retention_class)
            && self
                .attr_equals
                .iter()
                .all(|(key, value)| context.attrs.get(key) == Some(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegulatoryRule {
    pub rule_id: String,
    pub predicate: CompliancePredicate,
    pub requirements: Vec<ComplianceRequirement>,
}

impl RegulatoryRule {
    fn validate(&self) -> Result<(), RegulatoryError> {
        required("rule_id", &self.rule_id)?;
        if self.requirements.is_empty() {
            return Err(RegulatoryError::Invalid(format!(
                "regra {} não possui requisitos",
                self.rule_id
            )));
        }
        for requirement in &self.requirements {
            requirement.validate()?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct PolicyDigestMaterial<'a> {
    policy_id: &'a str,
    version: &'a str,
    effective_from: u64,
    rules: &'a [RegulatoryRule],
}

/// Serializable policy implementation suitable for configuration and replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfiguredRegulatoryPolicy {
    pub identity: PolicyIdentity,
    pub rules: Vec<RegulatoryRule>,
}

impl ConfiguredRegulatoryPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        version: impl Into<String>,
        effective_from: u64,
        rules: Vec<RegulatoryRule>,
    ) -> Result<Self, RegulatoryError> {
        let policy_id = policy_id.into();
        let version = version.into();
        let digest = policy_digest(&policy_id, &version, effective_from, &rules)?;
        let policy = Self {
            identity: PolicyIdentity {
                policy_id,
                version,
                digest,
                effective_from,
            },
            rules,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), RegulatoryError> {
        required("policy_id", &self.identity.policy_id)?;
        required("policy version", &self.identity.version)?;
        if self.rules.is_empty() || self.rules.len() > MAX_RULES {
            return Err(RegulatoryError::Invalid(format!(
                "política deve conter entre 1 e {MAX_RULES} regras"
            )));
        }
        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            rule.validate()?;
            if !ids.insert(&rule.rule_id) {
                return Err(RegulatoryError::Invalid(format!(
                    "rule_id duplicado: {}",
                    rule.rule_id
                )));
            }
        }
        let expected = policy_digest(
            &self.identity.policy_id,
            &self.identity.version,
            self.identity.effective_from,
            &self.rules,
        )?;
        if expected != self.identity.digest {
            return Err(RegulatoryError::Invalid(
                "digest da política não corresponde à definição".into(),
            ));
        }
        Ok(())
    }
}

fn policy_digest(
    policy_id: &str,
    version: &str,
    effective_from: u64,
    rules: &[RegulatoryRule],
) -> Result<[u8; 32], RegulatoryError> {
    let material = PolicyDigestMaterial {
        policy_id,
        version,
        effective_from,
        rules,
    };
    Ok(*blake3::hash(&serde_json::to_vec(&material)?).as_bytes())
}

pub trait RegulatoryPolicy {
    fn identity(&self) -> &PolicyIdentity;
    fn evaluate(&self, context: &ComplianceContext) -> Vec<ComplianceRequirement>;
}

impl RegulatoryPolicy for ConfiguredRegulatoryPolicy {
    fn identity(&self) -> &PolicyIdentity {
        &self.identity
    }

    fn evaluate(&self, context: &ComplianceContext) -> Vec<ComplianceRequirement> {
        let mut requirements: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| rule.predicate.matches(context))
            .flat_map(|rule| rule.requirements.iter().cloned())
            .collect();
        requirements.sort();
        requirements.dedup();
        requirements
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceContext {
    pub subject_id: String,
    pub event_kind: String,
    #[serde(default)]
    pub attrs: BTreeMap<String, String>,
    pub retention_class: RetentionClass,
    /// Regulatory/business time used for `effective_from` selection.
    pub effective_at: u64,
    /// Transaction-time view that the assessment is allowed to observe.
    pub as_of_lsn: Lsn,
}

impl ComplianceContext {
    fn validate(&self) -> Result<(), RegulatoryError> {
        required("subject_id", &self.subject_id)?;
        required("event_kind", &self.event_kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegulatoryDecision {
    pub decision_id: String,
    pub policy: PolicyIdentity,
    pub context: ComplianceContext,
    pub requirements: Vec<ComplianceRequirement>,
}

impl RegulatoryDecision {
    fn build(
        policy: &ConfiguredRegulatoryPolicy,
        context: ComplianceContext,
    ) -> Result<Self, RegulatoryError> {
        context.validate()?;
        let requirements = policy.evaluate(&context);
        let digest_material = serde_json::to_vec(&(&policy.identity, &context, &requirements))?;
        Ok(Self {
            decision_id: format!("assessment-{}", blake3::hash(&digest_material).to_hex()),
            policy: policy.identity.clone(),
            context,
            requirements,
        })
    }

    fn to_episode(&self) -> Result<Episode, RegulatoryError> {
        let mut episode = generated_episode(ASSESSMENT_EVENT, serde_json::to_vec(self)?);
        episode
            .attrs
            .insert("compliance.decision_id".into(), self.decision_id.clone());
        episode
            .attrs
            .insert("compliance.policy_id".into(), self.policy.policy_id.clone());
        episode.attrs.insert(
            "compliance.policy_version".into(),
            self.policy.version.clone(),
        );
        Ok(episode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyActivation {
    pub policy: ConfiguredRegulatoryPolicy,
    pub activated_by: String,
    pub approval_ref: String,
}

impl PolicyActivation {
    fn validate(&self) -> Result<(), RegulatoryError> {
        self.policy.validate()?;
        required("activated_by", &self.activated_by)?;
        required("approval_ref", &self.approval_ref)
    }

    fn to_episode(&self) -> Result<Episode, RegulatoryError> {
        self.validate()?;
        let mut episode = generated_episode(POLICY_EVENT, serde_json::to_vec(self)?);
        episode.attrs.insert(
            "compliance.policy_id".into(),
            self.policy.identity.policy_id.clone(),
        );
        episode.attrs.insert(
            "compliance.policy_version".into(),
            self.policy.identity.version.clone(),
        );
        episode.attrs.insert(
            "compliance.policy_digest".into(),
            hex_digest(&self.policy.identity.digest),
        );
        Ok(episode)
    }
}

/// Selector intentionally starts with LSN ranges: they map exactly to the
/// canonical segments protected by HRKL.  More expressive selectors can be
/// resolved to ranges before a hold is activated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSelector {
    pub lsn_start: Lsn,
    pub lsn_end: Lsn,
}

impl EvidenceSelector {
    pub fn validate(&self) -> Result<(), RegulatoryError> {
        if self.lsn_start > self.lsn_end {
            return Err(RegulatoryError::Invalid(
                "EvidenceSelector possui intervalo LSN invertido".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHold {
    pub hold_id: String,
    pub scope: EvidenceSelector,
    pub authority: String,
    pub reason: String,
    pub created_at_lsn: Lsn,
}

impl LegalHold {
    pub fn validate(&self) -> Result<(), RegulatoryError> {
        required("hold_id", &self.hold_id)?;
        required("authority", &self.authority)?;
        required("reason", &self.reason)?;
        self.scope.validate()
    }

    fn to_episode(&self) -> Result<Episode, RegulatoryError> {
        self.validate()?;
        let mut episode = generated_episode(LEGAL_HOLD_EVENT, serde_json::to_vec(self)?);
        episode
            .attrs
            .insert("compliance.hold_id".into(), self.hold_id.clone());
        episode.attrs.insert(
            "compliance.lsn_start".into(),
            self.scope.lsn_start.to_string(),
        );
        episode
            .attrs
            .insert("compliance.lsn_end".into(), self.scope.lsn_end.to_string());
        Ok(episode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHoldRelease {
    pub hold_id: String,
    pub authority: String,
    pub reason: String,
    pub released_at_lsn: Lsn,
}

impl LegalHoldRelease {
    fn validate(&self) -> Result<(), RegulatoryError> {
        required("hold_id", &self.hold_id)?;
        required("authority", &self.authority)?;
        required("reason", &self.reason)
    }

    fn to_episode(&self) -> Result<Episode, RegulatoryError> {
        self.validate()?;
        let mut episode = generated_episode(LEGAL_HOLD_RELEASE_EVENT, serde_json::to_vec(self)?);
        episode
            .attrs
            .insert("compliance.hold_id".into(), self.hold_id.clone());
        Ok(episode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyActivationRecord {
    pub lsn: Lsn,
    pub activation: PolicyActivation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegulatoryDecisionRecord {
    pub lsn: Lsn,
    pub decision: RegulatoryDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegalHoldRecord {
    pub lsn: Lsn,
    pub hold: LegalHold,
    pub released: Option<(Lsn, LegalHoldRelease)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegulatoryState {
    pub policy_activations: Vec<PolicyActivationRecord>,
    pub decisions: Vec<RegulatoryDecisionRecord>,
    pub legal_holds: BTreeMap<String, LegalHoldRecord>,
}

impl RegulatoryState {
    pub fn replay<L: EpisodeLog + ?Sized>(
        log: &L,
        as_of_lsn: Lsn,
    ) -> Result<Self, RegulatoryError> {
        let end = log.head().min(as_of_lsn.saturating_add(1));
        let mut state = Self::default();
        // Janelado: o `scan(0, end)` anterior materializava o log inteiro em
        // RAM antes de olhar para a primeira linha, e este replay corre no
        // arranque do servidor E em cada chamada dos RPCs de compliance.
        crate::varrimento::por_episodio(
            log,
            end,
            |error| RegulatoryError::Storage(error.to_string()),
            |lsn, episode| {
                if episode
                    .attrs
                    .get("compliance.generated")
                    .map(String::as_str)
                    != Some("true")
                {
                    return Ok(());
                }
                match episode.kind.label().as_str() {
                    POLICY_EVENT => {
                        let activation: PolicyActivation =
                            serde_json::from_slice(&episode.content)?;
                        activation.validate()?;
                        state
                            .policy_activations
                            .push(PolicyActivationRecord { lsn, activation });
                    }
                    ASSESSMENT_EVENT => {
                        let decision: RegulatoryDecision =
                            serde_json::from_slice(&episode.content)?;
                        decision.context.validate()?;
                        state
                            .decisions
                            .push(RegulatoryDecisionRecord { lsn, decision });
                    }
                    LEGAL_HOLD_EVENT => {
                        let hold: LegalHold = serde_json::from_slice(&episode.content)?;
                        hold.validate()?;
                        // Um duplicado NAO pode abortar o replay. O log e
                        // append-only: o episodio ofensor nunca desaparece, logo um
                        // `Err` aqui tornava o estado regulatorio irrecuperavel
                        // para sempre — e com ele o crypto-shred e o GC, que falham
                        // fechado. Fica o PRIMEIRO hold, que e a escolha
                        // conservadora: manter a retencao em vez de a levantar.
                        if state.legal_holds.contains_key(&hold.hold_id) {
                            tracing::warn!(
                                hold_id = %hold.hold_id,
                                lsn,
                                "hold_id repetido no log; mantido o primeiro e ignorado este"
                            );
                            return Ok(());
                        }
                        state.legal_holds.insert(
                            hold.hold_id.clone(),
                            LegalHoldRecord {
                                lsn,
                                hold,
                                released: None,
                            },
                        );
                    }
                    LEGAL_HOLD_RELEASE_EVENT => {
                        let release: LegalHoldRelease = serde_json::from_slice(&episode.content)?;
                        release.validate()?;
                        // Mesma razao do duplicado acima: um release orfao ou
                        // repetido e um episodio que ja esta no log para sempre.
                        // Ignora-se com aviso, e mantem-se o PRIMEIRO release —
                        // nunca se levanta uma retencao por causa de um segundo.
                        let Some(record) = state.legal_holds.get_mut(&release.hold_id) else {
                            tracing::warn!(
                                hold_id = %release.hold_id,
                                lsn,
                                "release sem LegalHold anterior; ignorado"
                            );
                            return Ok(());
                        };
                        if record.released.is_some() {
                            tracing::warn!(
                                hold_id = %release.hold_id,
                                lsn,
                                "LegalHold libertado duas vezes; mantido o primeiro release"
                            );
                            return Ok(());
                        }
                        record.released = Some((lsn, release));
                    }
                    _ => {}
                }
                Ok(())
            },
        )?;
        state.policy_activations.sort_by_key(|record| record.lsn);
        state.decisions.sort_by_key(|record| record.lsn);
        Ok(state)
    }

    pub fn active_policy(
        &self,
        policy_id: &str,
        effective_at: u64,
    ) -> Option<&PolicyActivationRecord> {
        self.policy_activations
            .iter()
            .filter(|record| {
                record.activation.policy.identity.policy_id == policy_id
                    && record.activation.policy.identity.effective_from <= effective_at
            })
            .max_by_key(|record| record.lsn)
    }

    pub fn active_holds(&self) -> impl Iterator<Item = &LegalHoldRecord> {
        self.legal_holds
            .values()
            .filter(|record| record.released.is_none())
    }
}

/// Runtime facade that persists every policy activation, assessment and hold.
#[derive(Clone)]
pub struct RegulatoryPolicyEngine {
    log: Arc<AnyLog>,
}

impl RegulatoryPolicyEngine {
    pub fn new(log: Arc<AnyLog>) -> Self {
        Self { log }
    }

    pub fn state_as_of(&self, as_of_lsn: Lsn) -> Result<RegulatoryState, RegulatoryError> {
        RegulatoryState::replay(self.log.as_ref(), as_of_lsn)
    }

    pub fn state(&self) -> Result<RegulatoryState, RegulatoryError> {
        self.state_as_of(self.log.head().saturating_sub(1))
    }

    pub fn activate_policy(&self, activation: PolicyActivation) -> Result<Lsn, RegulatoryError> {
        activation.validate()?;
        let state = self.state()?;
        if let Some(existing) = state.policy_activations.iter().find(|record| {
            record.activation.policy.identity.policy_id == activation.policy.identity.policy_id
                && record.activation.policy.identity.version == activation.policy.identity.version
        }) {
            if existing.activation == activation {
                return Ok(existing.lsn);
            }
            return Err(RegulatoryError::Invalid(format!(
                "policy/version já existe com outro conteúdo: {}/{}",
                activation.policy.identity.policy_id, activation.policy.identity.version
            )));
        }
        self.log
            .append(activation.to_episode()?)
            .map_err(|error| RegulatoryError::Storage(error.to_string()))
    }

    pub fn evaluate_and_persist(
        &self,
        policy_id: &str,
        context: ComplianceContext,
    ) -> Result<(Lsn, RegulatoryDecision), RegulatoryError> {
        context.validate()?;
        let state = self.state_as_of(context.as_of_lsn)?;
        let active = state
            .active_policy(policy_id, context.effective_at)
            .ok_or_else(|| {
                RegulatoryError::Invalid(format!(
                    "nenhuma versão efetiva da política {policy_id} no AS OF solicitado"
                ))
            })?;
        let decision = RegulatoryDecision::build(&active.activation.policy, context)?;
        if let Some(existing) = state
            .decisions
            .iter()
            .find(|record| record.decision.decision_id == decision.decision_id)
        {
            return Ok((existing.lsn, existing.decision.clone()));
        }
        let lsn = self
            .log
            .append(decision.to_episode()?)
            .map_err(|error| RegulatoryError::Storage(error.to_string()))?;
        Ok((lsn, decision))
    }

    /// Fail-closed ordering: protect matching sealed segments before appending
    /// the hold event.  If the append fails, data remains over-protected rather
    /// than becoming destructible without an audit record.
    pub fn place_legal_hold(&self, hold: LegalHold) -> Result<Lsn, RegulatoryError> {
        hold.validate()?;
        let state = self.state()?;
        if let Some(existing) = state.legal_holds.get(&hold.hold_id) {
            if existing.hold == hold && existing.released.is_none() {
                return Ok(existing.lsn);
            }
            return Err(RegulatoryError::Invalid(format!(
                "hold_id já utilizado: {}",
                hold.hold_id
            )));
        }
        let v6 = self.log.v6_arc().ok_or_else(|| {
            RegulatoryError::Unsupported(
                "LegalHold aplicado ao catálogo exige storage_format=v6".into(),
            )
        })?;
        v6.set_legal_hold_range(hold.scope.lsn_start, hold.scope.lsn_end, true)
            .map_err(|error| RegulatoryError::Storage(error.to_string()))?;
        let lsn = self
            .log
            .append(hold.to_episode()?)
            .map_err(|error| RegulatoryError::Storage(error.to_string()))?;
        self.reconcile_legal_holds()?;
        Ok(lsn)
    }

    /// The release is appended first.  A failure while updating HRKM therefore
    /// leaves the physical hold active, which is the safe side of the failure.
    pub fn release_legal_hold(&self, release: LegalHoldRelease) -> Result<Lsn, RegulatoryError> {
        release.validate()?;
        let state = self.state()?;
        let existing = state.legal_holds.get(&release.hold_id).ok_or_else(|| {
            RegulatoryError::Invalid(format!("LegalHold inexistente: {}", release.hold_id))
        })?;
        if let Some((lsn, previous)) = &existing.released {
            if previous == &release {
                return Ok(*lsn);
            }
            return Err(RegulatoryError::Invalid(format!(
                "LegalHold já liberado: {}",
                release.hold_id
            )));
        }
        if self.log.v6_arc().is_none() {
            return Err(RegulatoryError::Unsupported(
                "LegalHold aplicado ao catálogo exige storage_format=v6".into(),
            ));
        }
        let lsn = self
            .log
            .append(release.to_episode()?)
            .map_err(|error| RegulatoryError::Storage(error.to_string()))?;
        self.reconcile_legal_holds()?;
        Ok(lsn)
    }

    /// Rebuild the HRKM legal-hold flags from the append-only event history.
    /// Call at boot and immediately before any automated GC cycle.
    pub fn reconcile_legal_holds(&self) -> Result<usize, RegulatoryError> {
        let state = self.state()?;
        let ranges: Vec<_> = state
            .active_holds()
            .map(|record| (record.hold.scope.lsn_start, record.hold.scope.lsn_end))
            .collect();
        let v6 = self.log.v6_arc().ok_or_else(|| {
            RegulatoryError::Unsupported(
                "reconciliação de LegalHold exige storage_format=v6".into(),
            )
        })?;
        v6.reconcile_legal_hold_ranges(&ranges)
            .map_err(|error| RegulatoryError::Storage(error.to_string()))
    }
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind, FsyncPolicy, StorageFormat};
    use heraclitus_log::v6::{plan_gc, GcBlockReason, GcOptions, PackingProfile, PinRegistry};

    fn policy(retain_seconds: u64) -> ConfiguredRegulatoryPolicy {
        ConfiguredRegulatoryPolicy::new(
            "gov-br-retention",
            "2026.1",
            100,
            vec![RegulatoryRule {
                rule_id: "incident-evidence".into(),
                predicate: CompliancePredicate {
                    event_kind: Some("SecurityIncident".into()),
                    retention_class: Some(RetentionClass::IncidentEvidence),
                    attr_equals: [("jurisdiction".into(), "BR".into())].into_iter().collect(),
                },
                requirements: vec![
                    ComplianceRequirement {
                        requirement_id: "retain".into(),
                        legal_basis: "policy-table-42".into(),
                        effect: RequirementEffect::RetainForSeconds {
                            seconds: retain_seconds,
                        },
                    },
                    ComplianceRequirement {
                        requirement_id: "human-erasure".into(),
                        legal_basis: "legal-hold-policy".into(),
                        effect: RequirementEffect::RequireHumanAuthorization,
                    },
                ],
            }],
        )
        .unwrap()
    }

    fn open_v6() -> (tempfile::TempDir, Arc<AnyLog>) {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(StorageFormat::V6, temp.path(), 512, FsyncPolicy::Always).unwrap(),
        );
        (temp, log)
    }

    #[test]
    fn versioned_policy_is_deterministic_and_replayable() {
        let (_temp, log) = open_v6();
        let engine = RegulatoryPolicyEngine::new(log.clone());
        let activation = PolicyActivation {
            policy: policy(31_536_000),
            activated_by: "compliance-officer".into(),
            approval_ref: "approval-2026-001".into(),
        };
        let activation_lsn = engine.activate_policy(activation.clone()).unwrap();
        assert_eq!(engine.activate_policy(activation).unwrap(), activation_lsn);

        let context = ComplianceContext {
            subject_id: "incident-7".into(),
            event_kind: "SecurityIncident".into(),
            attrs: [("jurisdiction".into(), "BR".into())].into_iter().collect(),
            retention_class: RetentionClass::IncidentEvidence,
            effective_at: 101,
            as_of_lsn: log.head(),
        };
        let (decision_lsn, decision) = engine
            .evaluate_and_persist("gov-br-retention", context.clone())
            .unwrap();
        assert_eq!(decision.policy.version, "2026.1");
        assert_eq!(decision.requirements.len(), 2);
        assert_eq!(
            engine
                .evaluate_and_persist("gov-br-retention", context)
                .unwrap()
                .0,
            decision_lsn
        );

        let replay = RegulatoryState::replay(log.as_ref(), log.head()).unwrap();
        assert_eq!(replay.policy_activations.len(), 1);
        assert_eq!(replay.decisions.len(), 1);
        assert_eq!(
            replay.decisions[0].decision.policy.digest,
            decision.policy.digest
        );
    }

    #[test]
    fn policy_digest_rejects_silent_rule_mutation() {
        let mut configured = policy(86_400);
        configured.rules[0].requirements[0].effect =
            RequirementEffect::RetainForSeconds { seconds: 1 };
        assert!(configured.validate().is_err());
    }

    #[test]
    fn legal_hold_reaches_hrkm_and_blocks_gc_until_audited_release() {
        let (_temp, log) = open_v6();
        for i in 0..80 {
            log.append(Episode::new(
                "sensor",
                EventKind::Observation,
                format!("evidence-{i}").into_bytes(),
            ))
            .unwrap();
        }
        let v6 = log.v6_arc().unwrap();
        v6.seal_active().unwrap();
        v6.pack_pending(PackingProfile::Balanced).unwrap();
        let segment = v6.manifest().segments_v2[0].clone();

        let engine = RegulatoryPolicyEngine::new(log.clone());
        let hold = LegalHold {
            hold_id: "hold-001".into(),
            scope: EvidenceSelector {
                lsn_start: segment.first_lsn,
                lsn_end: segment.last_lsn,
            },
            authority: "controladoria".into(),
            reason: "investigação administrativa".into(),
            created_at_lsn: log.head(),
        };
        let hold_lsn = engine.place_legal_hold(hold.clone()).unwrap();
        assert_eq!(engine.place_legal_hold(hold).unwrap(), hold_lsn);
        assert!(
            v6.manifest()
                .segment(segment.segment_id)
                .unwrap()
                .retention
                .legal_hold
        );

        let blocked = plan_gc(
            &v6.manifest(),
            &PinRegistry::new(),
            &GcOptions {
                now_hlc: u64::MAX,
                ..GcOptions::default()
            },
        );
        assert!(blocked.blocked.iter().any(|item| {
            item.segment_id == segment.segment_id && item.reason == GcBlockReason::LegalHold
        }));

        engine
            .release_legal_hold(LegalHoldRelease {
                hold_id: "hold-001".into(),
                authority: "controladoria".into(),
                reason: "processo encerrado".into(),
                released_at_lsn: log.head(),
            })
            .unwrap();
        assert!(
            !v6.manifest()
                .segment(segment.segment_id)
                .unwrap()
                .retention
                .legal_hold
        );
        assert_eq!(engine.state().unwrap().active_holds().count(), 0);
    }

    #[test]
    fn legal_hold_refuses_legacy_backend_instead_of_claiming_protection() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(StorageFormat::Legacy, temp.path(), 512, FsyncPolicy::Always).unwrap(),
        );
        let engine = RegulatoryPolicyEngine::new(log);
        let error = engine
            .place_legal_hold(LegalHold {
                hold_id: "hold-legacy".into(),
                scope: EvidenceSelector {
                    lsn_start: 0,
                    lsn_end: 1,
                },
                authority: "court".into(),
                reason: "preserve".into(),
                created_at_lsn: 0,
            })
            .unwrap_err();
        assert!(matches!(error, RegulatoryError::Unsupported(_)));
    }
}
