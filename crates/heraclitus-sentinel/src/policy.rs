//! Deterministic response policy for SPEC-0045 Fase 5.
//!
//! The policy layer only returns a typed decision.  It never contacts a
//! firewall/IAM service and never receives model credentials; a host must
//! persist the decision and explicitly hand an `AuthorizedAction` to a
//! least-privilege executor.

use crate::ai::{ActionKind, ActionProposal, SecurityAction};
use crate::correlation::{IncidentState, RiskAssessment, SecurityIncident};
use crate::event::EvidenceRef;
use heraclitus_core::{Episode, EventId, EventKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("política de resposta inválida: {0}")]
    Invalid(String),
}

/// SPEC-0071 §9.1 — uma exigência de saúde da telemetria, declarada.
///
/// É o bloco `required_telemetry` da spec, campo a campo:
///
/// ```yaml
/// required_telemetry:
///   - datasource_class: identity
///     minimum_trust: 0.90
///     maximum_age_secs: 300
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequiredTelemetry {
    /// A classe de datasource que esta acção precisa de ver saudável.
    pub datasource_class: String,
    /// Confiança mínima, em [0, 1].
    pub minimum_trust: f32,
    /// Idade máxima da observação mais recente, em segundos.
    pub maximum_age_secs: u64,
}

impl RequiredTelemetry {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.datasource_class.trim().is_empty() {
            return Err(PolicyError::Invalid(
                "required_telemetry.datasource_class vazio".into(),
            ));
        }
        if !self.minimum_trust.is_finite() || !(0.0..=1.0).contains(&self.minimum_trust) {
            return Err(PolicyError::Invalid(
                "required_telemetry.minimum_trust inválido".into(),
            ));
        }
        if self.maximum_age_secs == 0 {
            return Err(PolicyError::Invalid(
                "required_telemetry.maximum_age_secs tem de ser > 0".into(),
            ));
        }
        Ok(())
    }
}

/// O que a view de Telemetry Health diz sobre uma classe de datasource.
///
/// Deliberadamente MÍNIMO e sem `Option`: cada campo tem de ser respondido.
/// `saudavel: false` e `confianca: 0.0` é a resposta certa para "não sei", e é
/// o default que [`TelemetryHealthProbe`] devolve quando não conhece a classe.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TelemetryHealthReading {
    /// A classe é conhecida E o seu estado agregado é saudável (nem `Silent`,
    /// nem `Unknown`, nem `Degraded`).
    pub saudavel: bool,
    /// Confiança agregada em [0, 1].
    pub confianca: f32,
    /// Segundos desde a observação mais recente desta classe.
    pub idade_secs: u64,
}

impl TelemetryHealthReading {
    /// O que se sabe quando não se sabe nada: `Unknown`.
    ///
    /// A §9.1 põe `Unknown` ao lado de `Silent` de propósito — não saber se um
    /// sensor está vivo não é melhor do que saber que está morto.
    pub fn desconhecida() -> Self {
        Self {
            saudavel: false,
            confianca: 0.0,
            idade_secs: u64::MAX,
        }
    }
}

/// A fonte da saúde da telemetria, vista pela política.
///
/// É um trait e não uma dependência directa do `heraclitus-telemetry-health`
/// por duas razões. A política fica testável com uma sonda falsa — e um gate
/// de segurança que não se consegue testar em todos os estados não é um gate.
/// E o `heraclitus-sentinel` não passa a depender do crate da view, o que
/// manteria a fronteira: a política PERGUNTA pela saúde, não a calcula.
pub trait TelemetryHealthProbe: Send + Sync {
    fn leitura(&self, datasource_class: &str) -> TelemetryHealthReading;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionRule {
    pub minimum_risk: f32,
    pub minimum_evidence: usize,
    /// A conservative quorum over distinct signal IDs.  A host that tracks
    /// detector identities separately can apply a stricter pre-check.
    pub minimum_signals: usize,
    pub human_approval: bool,
    pub max_ttl_secs: Option<u64>,
    pub scope: String,
    pub enabled: bool,
    /// SPEC-0071 §9.1 — a telemetria que esta acção exige ver saudável.
    ///
    /// Vazio por omissão, e isso é a decisão de calibração mais importante
    /// deste gate. A §9.1 fala da "telemetria REQUERIDA", e quem a requer é o
    /// playbook (§9.2) — que ainda não existe: não há Content Hub, não há
    /// Playbook IR activado por assinatura. Um gate que, sem playbook,
    /// inventasse um requisito recusaria toda a acção automática desde o
    /// primeiro dia, porque em produção o produtor emite
    /// `minimum_events_per_window: None` e a Completeness fica `Unknown`.
    ///
    /// Então o mecanismo fica completo e inerte até alguém declarar o
    /// requisito. É a diferença entre um gate desligado e um gate que não
    /// tem nada para verificar — e a segunda é honesta.
    #[serde(default)]
    pub required_telemetry: Vec<RequiredTelemetry>,
}

impl ActionRule {
    fn validate(&self) -> Result<(), PolicyError> {
        if !self.minimum_risk.is_finite() || !(0.0..=1.0).contains(&self.minimum_risk) {
            return Err(PolicyError::Invalid("minimum_risk inválido".into()));
        }
        if self.scope.trim().is_empty() {
            return Err(PolicyError::Invalid("scope vazio".into()));
        }
        for requisito in &self.required_telemetry {
            requisito.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policy_version: String,
    pub actions: BTreeMap<ActionKind, ActionRule>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        let mut actions = BTreeMap::new();
        let add = |actions: &mut BTreeMap<ActionKind, ActionRule>,
                   kind: ActionKind,
                   minimum_risk: f32,
                   minimum_evidence: usize,
                   minimum_signals: usize,
                   human_approval: bool,
                   max_ttl_secs: Option<u64>,
                   scope: &str| {
            actions.insert(
                kind,
                ActionRule {
                    minimum_risk,
                    minimum_evidence,
                    minimum_signals,
                    human_approval,
                    max_ttl_secs,
                    scope: scope.into(),
                    enabled: true,
                    // Vazio: ver a nota em `ActionRule::required_telemetry`.
                    required_telemetry: Vec::new(),
                },
            );
        };
        add(
            &mut actions,
            ActionKind::SnapshotEvidence,
            0.0,
            0,
            1,
            false,
            None,
            "evidence",
        );
        add(
            &mut actions,
            ActionKind::IncreaseTelemetry,
            0.50,
            0,
            1,
            false,
            Some(3_600),
            "telemetry",
        );
        add(
            &mut actions,
            ActionKind::RequireMfa,
            0.75,
            1,
            1,
            false,
            None,
            "identity",
        );
        add(
            &mut actions,
            ActionKind::RateLimitPrincipal,
            0.80,
            1,
            1,
            false,
            Some(900),
            "network",
        );
        add(
            &mut actions,
            ActionKind::BlockIp,
            0.80,
            1,
            1,
            false,
            Some(900),
            "network",
        );
        add(
            &mut actions,
            ActionKind::RevokeSession,
            0.92,
            2,
            2,
            true,
            Some(3_600),
            "session",
        );
        add(
            &mut actions,
            ActionKind::QuarantineHost,
            0.95,
            2,
            2,
            true,
            Some(3_600),
            "host",
        );
        add(
            &mut actions,
            ActionKind::DisableApiToken,
            0.95,
            2,
            2,
            true,
            Some(3_600),
            "identity",
        );
        Self {
            policy_version: "response-policy-v1".into(),
            actions,
        }
    }
}

impl PolicyConfig {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.policy_version.trim().is_empty() {
            return Err(PolicyError::Invalid("policy_version vazio".into()));
        }
        if self.actions.is_empty() {
            return Err(PolicyError::Invalid("nenhuma ação configurada".into()));
        }
        for (kind, rule) in &self.actions {
            rule.validate()?;
            if *kind == ActionKind::SnapshotEvidence && rule.human_approval {
                return Err(PolicyError::Invalid(
                    "snapshot não pode exigir aprovação humana".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionConstraints {
    pub scope: String,
    pub max_ttl_secs: Option<u64>,
    pub requires_approval: bool,
    pub allow_retries: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Deny {
        reason: String,
    },
    Approve {
        authorization_id: String,
        constraints: ExecutionConstraints,
    },
    RequireHumanApproval {
        approval_id: String,
        reason: String,
    },
}

/// Durable human decision for a policy branch that cannot execute
/// automatically. An in-memory boolean is never sufficient after restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanApproval {
    pub approval_id: String,
    pub incident_id: String,
    pub proposal_id: String,
    pub approver: String,
    pub approved: bool,
    pub reason: String,
    pub evidence: Vec<EvidenceRef>,
}

impl HumanApproval {
    pub fn validate(&self) -> Result<(), PolicyError> {
        for (name, value) in [
            ("approval_id", self.approval_id.as_str()),
            ("incident_id", self.incident_id.as_str()),
            ("proposal_id", self.proposal_id.as_str()),
            ("approver", self.approver.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(PolicyError::Invalid(format!("{name} vazio")));
            }
        }
        if self.reason.len() > 16 * 1024 {
            return Err(PolicyError::Invalid(
                "razão de aprovação excede o limite".into(),
            ));
        }
        Ok(())
    }

    pub fn into_episode(&self) -> Result<Episode, serde_json::Error> {
        let mut episode = Episode::new(
            "sentinel",
            EventKind::Custom("SecurityApproval".into()),
            serde_json::to_vec(self)?,
        );
        let mut parents: Vec<EventId> = self.evidence.iter().map(|item| item.event_id).collect();
        parents.sort_unstable();
        parents.dedup();
        episode.parents = parents;
        episode
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        episode
            .attrs
            .insert("sentinel.approval_id".into(), self.approval_id.clone());
        episode
            .attrs
            .insert("sentinel.incident_id".into(), self.incident_id.clone());
        episode.attrs.insert(
            "sentinel.action_proposal_id".into(),
            self.proposal_id.clone(),
        );
        episode
            .attrs
            .insert("sentinel.approved".into(), self.approved.to_string());
        Ok(episode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedAction {
    pub authorization_id: String,
    pub incident_id: String,
    pub action: SecurityAction,
    pub constraints: ExecutionConstraints,
    pub evidence: Vec<EvidenceRef>,
    pub policy_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionResult {
    pub action_id: String,
    pub success: bool,
    pub external_reference: Option<String>,
    pub rollback_token: Option<String>,
    pub message: String,
    pub executed_at: u64,
}

impl ActionResult {
    pub fn into_episode(
        &self,
        authorized: &AuthorizedAction,
    ) -> Result<Episode, serde_json::Error> {
        let payload = serde_json::json!({
            "action_id": self.action_id,
            "incident_id": authorized.incident_id,
            "authorization_id": authorized.authorization_id,
            "policy_version": authorized.policy_version,
            "action": authorized.action,
            "result": self,
        });
        let mut episode = Episode::new(
            "sentinel",
            EventKind::Custom("SecurityActionResult".into()),
            serde_json::to_vec(&payload)?,
        );
        let mut parents: Vec<EventId> = authorized
            .evidence
            .iter()
            .map(|item| item.event_id)
            .collect();
        parents.sort_unstable();
        parents.dedup();
        episode.parents = parents;
        episode
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        episode
            .attrs
            .insert("sentinel.action_id".into(), self.action_id.clone());
        episode.attrs.insert(
            "sentinel.incident_id".into(),
            authorized.incident_id.clone(),
        );
        episode.attrs.insert(
            "sentinel.policy_version".into(),
            authorized.policy_version.clone(),
        );
        Ok(episode)
    }
}

pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        incident: &SecurityIncident,
        assessment: &RiskAssessment,
        proposal: &ActionProposal,
    ) -> PolicyDecision;
}

/// O `Debug` e escrito a mao: o `Arc<dyn TelemetryHealthProbe>` nao o
/// implementa, e exigi-lo do trait obrigaria cada sonda a derivar `Debug` sem
/// ganho nenhum.
#[derive(Clone)]
pub struct DeterministicPolicyEngine {
    config: PolicyConfig,
    allowlisted_targets: BTreeSet<String>,
    maintenance_window: bool,
    privileged_exception: bool,
    /// SPEC-0071 §9.1 — a sonda de saude da telemetria. `None` ate alguem a
    /// ligar; ver `telemetria_em_falta` para o que isso significa.
    telemetry: Option<Arc<dyn TelemetryHealthProbe>>,
}

impl std::fmt::Debug for DeterministicPolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeterministicPolicyEngine")
            .field("config", &self.config)
            .field("allowlisted_targets", &self.allowlisted_targets)
            .field("maintenance_window", &self.maintenance_window)
            .field("privileged_exception", &self.privileged_exception)
            .field("telemetry", &self.telemetry.is_some())
            .finish()
    }
}

impl DeterministicPolicyEngine {
    pub fn new(config: PolicyConfig) -> Result<Self, PolicyError> {
        config.validate()?;
        Ok(Self {
            config,
            allowlisted_targets: BTreeSet::new(),
            maintenance_window: false,
            privileged_exception: false,
            telemetry: None,
        })
    }

    pub fn with_allowlist(mut self, targets: impl IntoIterator<Item = String>) -> Self {
        self.allowlisted_targets = targets.into_iter().collect();
        self
    }

    /// Liga a sonda de saúde da telemetria (SPEC-0071 §9.1).
    ///
    /// Sem sonda, uma regra que DECLARE `required_telemetry` não pode ser
    /// satisfeita — e é assim que tem de ser. Declarar que uma acção depende de
    /// telemetria e depois não ter como a verificar não é razão para aprovar;
    /// é razão para exigir um humano. Ver [`Self::telemetria_em_falta`].
    pub fn with_telemetry_probe(mut self, probe: Arc<dyn TelemetryHealthProbe>) -> Self {
        self.telemetry = Some(probe);
        self
    }

    /// SPEC-0071 §9.1 — o primeiro requisito de telemetria que não está
    /// satisfeito, se houver.
    ///
    /// `None` significa "nada a impedir": ou a regra não declara requisitos, ou
    /// declara e todos estão satisfeitos.
    fn telemetria_em_falta(&self, rule: &ActionRule) -> Option<String> {
        if rule.required_telemetry.is_empty() {
            return None;
        }
        let Some(probe) = self.telemetry.as_ref() else {
            return Some(format!(
                "a política exige telemetria saudável de {} classe(s) e não há \
                 sonda de saúde ligada para o verificar",
                rule.required_telemetry.len()
            ));
        };
        for requisito in &rule.required_telemetry {
            let leitura = probe.leitura(&requisito.datasource_class);
            if !leitura.saudavel {
                return Some(format!(
                    "telemetria '{}' não está saudável (Silent ou Unknown)",
                    requisito.datasource_class
                ));
            }
            if leitura.confianca < requisito.minimum_trust {
                return Some(format!(
                    "confiança da telemetria '{}' é {:.3}, abaixo do mínimo {:.3}",
                    requisito.datasource_class, leitura.confianca, requisito.minimum_trust
                ));
            }
            if leitura.idade_secs > requisito.maximum_age_secs {
                return Some(format!(
                    "telemetria '{}' tem {}s, acima do máximo {}s",
                    requisito.datasource_class, leitura.idade_secs, requisito.maximum_age_secs
                ));
            }
        }
        None
    }

    pub fn policy_version(&self) -> &str {
        &self.config.policy_version
    }

    pub fn with_maintenance_window(mut self, active: bool) -> Self {
        self.maintenance_window = active;
        self
    }

    pub fn with_privileged_exception(mut self, active: bool) -> Self {
        self.privileged_exception = active;
        self
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    pub fn authorize(
        &self,
        incident: &SecurityIncident,
        assessment: &RiskAssessment,
        proposal: &ActionProposal,
    ) -> PolicyDecision {
        self.evaluate(incident, assessment, proposal)
    }
}

impl PolicyDecision {
    /// Stable identity for one proposal/policy decision pair.
    pub fn decision_id(
        policy_version: &str,
        proposal: &ActionProposal,
        decision: &Self,
    ) -> Result<String, serde_json::Error> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(policy_version.len() as u64).to_le_bytes());
        bytes.extend_from_slice(policy_version.as_bytes());
        bytes.extend_from_slice(&(proposal.proposal_id.len() as u64).to_le_bytes());
        bytes.extend_from_slice(proposal.proposal_id.as_bytes());
        bytes.extend_from_slice(&serde_json::to_vec(decision)?);
        Ok(format!("dec-{}", blake3::hash(&bytes).to_hex()))
    }

    pub fn into_episode(
        &self,
        policy_version: &str,
        proposal: &ActionProposal,
        risk: &RiskAssessment,
    ) -> Result<Episode, serde_json::Error> {
        let decision_id = Self::decision_id(policy_version, proposal, self)?;
        let payload = serde_json::json!({
            "decision_id": decision_id,
            "policy_version": policy_version,
            "proposal_id": proposal.proposal_id,
            "incident_id": proposal.incident_id,
            "risk_revision_id": risk.revision_id()?,
            "decision": self,
        });
        let mut episode = Episode::new(
            "sentinel",
            EventKind::Custom("SecurityPolicyDecision".into()),
            serde_json::to_vec(&payload)?,
        );
        let mut parents: Vec<EventId> =
            proposal.evidence.iter().map(|item| item.event_id).collect();
        parents.sort_unstable();
        parents.dedup();
        episode.parents = parents;
        episode
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        episode
            .attrs
            .insert("sentinel.policy_decision_id".into(), decision_id);
        episode
            .attrs
            .insert("sentinel.policy_version".into(), policy_version.into());
        episode.attrs.insert(
            "sentinel.action_proposal_id".into(),
            proposal.proposal_id.clone(),
        );
        episode
            .attrs
            .insert("sentinel.incident_id".into(), proposal.incident_id.clone());
        Ok(episode)
    }

    /// Convert a policy result into an executor envelope. RequireHumanApproval
    /// is rejected unless a matching durable approval is supplied.
    pub fn authorized_action(
        &self,
        proposal: &ActionProposal,
        approval: Option<&HumanApproval>,
    ) -> Result<AuthorizedAction, PolicyError> {
        self.authorized_action_with_policy_version("response-policy-v1", proposal, approval)
    }

    pub fn authorized_action_with_policy_version(
        &self,
        policy_version: &str,
        proposal: &ActionProposal,
        approval: Option<&HumanApproval>,
    ) -> Result<AuthorizedAction, PolicyError> {
        if policy_version.trim().is_empty() {
            return Err(PolicyError::Invalid("policy_version vazio".into()));
        }
        let (authorization_id, constraints) = match self {
            Self::Approve {
                authorization_id,
                constraints,
            } => (authorization_id.clone(), constraints.clone()),
            Self::RequireHumanApproval { approval_id, .. } => {
                let Some(approval) = approval else {
                    return Err(PolicyError::Invalid(
                        "aprovação humana persistida é obrigatória".into(),
                    ));
                };
                approval.validate()?;
                if !approval.approved
                    || approval.approval_id != *approval_id
                    || approval.incident_id != proposal.incident_id
                    || approval.proposal_id != proposal.proposal_id
                {
                    return Err(PolicyError::Invalid(
                        "aprovação humana ausente, negada ou incompatível".into(),
                    ));
                }
                (
                    format!("authz-{}", approval.approval_id),
                    ExecutionConstraints {
                        scope: "approved-human".into(),
                        max_ttl_secs: None,
                        requires_approval: false,
                        allow_retries: false,
                    },
                )
            }
            Self::Deny { reason } => {
                return Err(PolicyError::Invalid(format!(
                    "ação negada pela policy: {reason}"
                )))
            }
        };
        proposal
            .action
            .validate()
            .map_err(|error| PolicyError::Invalid(error.to_string()))?;
        Ok(AuthorizedAction {
            authorization_id,
            incident_id: proposal.incident_id.clone(),
            action: proposal.action.clone(),
            constraints,
            evidence: proposal.evidence.clone(),
            policy_version: policy_version.into(),
        })
    }
}

impl PolicyEngine for DeterministicPolicyEngine {
    fn evaluate(
        &self,
        incident: &SecurityIncident,
        assessment: &RiskAssessment,
        proposal: &ActionProposal,
    ) -> PolicyDecision {
        if proposal.incident_id != incident.incident_id {
            return deny("proposal não pertence ao incidente");
        }
        if incident.state == IncidentState::FalsePositive
            || incident.state == IncidentState::Resolved
        {
            return deny("incidente encerrado ou marcado como falso positivo");
        }
        if let Err(error) = proposal.action.validate() {
            return deny(error.to_string());
        }
        let Some(rule) = self.config.actions.get(&proposal.action.kind()) else {
            return deny("ação não configurada");
        };
        if !rule.enabled {
            return deny("ação desabilitada");
        }
        if assessment.fused_score < rule.minimum_risk {
            return deny(format!(
                "risco {:.3} abaixo do mínimo {:.3}",
                assessment.fused_score, rule.minimum_risk
            ));
        }
        let evidence_count = proposal.evidence.len().max(assessment.evidence.len());
        if evidence_count < rule.minimum_evidence {
            return deny(format!(
                "evidência insuficiente: {evidence_count} < {}",
                rule.minimum_evidence
            ));
        }
        if incident.signals.len() < rule.minimum_signals {
            return deny(format!(
                "quorum insuficiente: {} < {}",
                incident.signals.len(),
                rule.minimum_signals
            ));
        }
        let target = action_target(&proposal.action);
        if self.allowlisted_targets.contains(&target) {
            return deny("alvo está na allowlist");
        }
        if (self.maintenance_window || self.privileged_exception)
            && !matches!(
                proposal.action.kind(),
                ActionKind::SnapshotEvidence | ActionKind::IncreaseTelemetry
            )
        {
            return deny("janela de manutenção/exceção privilegiada ativa");
        }
        let action_ttl = action_ttl(&proposal.action);
        if let Some(max_ttl) = rule.max_ttl_secs {
            if action_ttl.is_some_and(|ttl| ttl == 0 || ttl > max_ttl)
                || proposal
                    .requested_ttl
                    .is_some_and(|ttl| ttl == 0 || ttl > max_ttl)
            {
                return deny("TTL excede o limite da política");
            }
        }
        let constraints = ExecutionConstraints {
            scope: rule.scope.clone(),
            max_ttl_secs: rule.max_ttl_secs,
            requires_approval: rule.human_approval,
            allow_retries: false,
        };
        if rule.human_approval {
            return PolicyDecision::RequireHumanApproval {
                approval_id: decision_id("approval-v1", incident, proposal, assessment),
                reason: "ação de impacto elevado exige aprovação humana".into(),
            };
        }
        // SPEC-0071 §9.1 — o health gate da telemetria.
        //
        // É o ÚLTIMO teste antes da aprovação automática, e tem de ser: uma
        // acção que já ia ser recusada por risco, evidência ou quórum não
        // precisa de telemetria saudável para ser recusada. Chegar aqui
        // significa que tudo o resto passou e que a única coisa entre a
        // proposta e a execução automática é saber se o que a fundamenta ainda
        // está a ser observado.
        //
        // Recusar ou exigir aprovação? A §9.1 admite as duas. Escolhi exigir
        // aprovação, e o critério é este: uma falha de telemetria é
        // exactamente a altura em que pode ser mais preciso agir, e transformar
        // "não vejo" em "não faço" entrega ao atacante um modo de negar a
        // resposta a partir do momento em que consegue silenciar um sensor.
        // Com aprovação humana o caminho continua aberto, mas nunca por
        // omissão, e fica auditado.
        if let Some(motivo) = self.telemetria_em_falta(rule) {
            return PolicyDecision::RequireHumanApproval {
                approval_id: decision_id("approval-telemetry-v1", incident, proposal, assessment),
                reason: motivo,
            };
        }
        PolicyDecision::Approve {
            authorization_id: decision_id("authorization-v1", incident, proposal, assessment),
            constraints,
        }
    }
}

pub trait SecurityActionExecutor: Send + Sync {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, PolicyError>> + Send + 'a>>;
}

fn deny(reason: impl Into<String>) -> PolicyDecision {
    PolicyDecision::Deny {
        reason: reason.into(),
    }
}

fn action_target(action: &SecurityAction) -> String {
    match action {
        SecurityAction::RevokeSession { session_id, .. } => format!("session:{session_id}"),
        SecurityAction::BlockIp { ip, .. } => format!("ip:{ip}"),
        SecurityAction::QuarantineHost { host_id, .. } => format!("host:{host_id}"),
        SecurityAction::RateLimitPrincipal { principal_id, .. } => {
            format!("principal:{principal_id}")
        }
        SecurityAction::DisableApiToken { token_hash } => format!("token:{token_hash}"),
        SecurityAction::RequireMfa { user_id } => format!("user:{user_id}"),
        SecurityAction::IncreaseTelemetry { target, .. }
        | SecurityAction::SnapshotEvidence { target } => {
            format!("target:{target}")
        }
    }
}

fn action_ttl(action: &SecurityAction) -> Option<u64> {
    match action {
        SecurityAction::RevokeSession { .. }
        | SecurityAction::DisableApiToken { .. }
        | SecurityAction::RequireMfa { .. }
        | SecurityAction::SnapshotEvidence { .. } => None,
        SecurityAction::BlockIp { ttl_secs, .. }
        | SecurityAction::QuarantineHost { ttl_secs, .. }
        | SecurityAction::IncreaseTelemetry { ttl_secs, .. }
        | SecurityAction::RateLimitPrincipal { ttl_secs, .. } => Some(*ttl_secs),
    }
}

fn decision_id(
    prefix: &str,
    incident: &SecurityIncident,
    proposal: &ActionProposal,
    assessment: &RiskAssessment,
) -> String {
    let mut bytes = Vec::new();
    append_part(&mut bytes, prefix.as_bytes());
    append_part(&mut bytes, incident.incident_id.as_bytes());
    append_part(&mut bytes, proposal.proposal_id.as_bytes());
    append_part(&mut bytes, assessment.model_version.as_bytes());
    append_part(&mut bytes, &assessment.fused_score.to_bits().to_le_bytes());
    format!(
        "{}-{}",
        prefix.trim_end_matches("-"),
        blake3::hash(&bytes).to_hex()
    )
}

fn append_part(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::{ActionCapability, ContextBudget, EnvironmentContext, IncidentContext};
    use crate::correlation::FusionWeights;
    use crate::event::EntityRef;

    pub(super) fn assessment() -> RiskAssessment {
        crate::EvidenceFusion::new(FusionWeights::default(), "v1")
            .unwrap()
            .fuse(EntityRef::new("User", "alice"), 1.0, 1.0, 1.0, 1.0, vec![])
            .unwrap()
    }

    pub(super) fn incident() -> SecurityIncident {
        SecurityIncident {
            incident_id: "inc-1".into(),
            state: IncidentState::New,
            severity: 5,
            risk_score: 1.0,
            subjects: vec![EntityRef::new("User", "alice")],
            signals: vec!["s1".into(), "s2".into()],
            evidence: vec![],
            first_seen_lsn: 1,
            last_seen_lsn: 2,
            mitre: vec![],
        }
    }

    pub(super) fn proposal(action: SecurityAction) -> ActionProposal {
        ActionProposal {
            proposal_id: "p1".into(),
            incident_id: "inc-1".into(),
            action,
            rationale: "r".into(),
            evidence: vec![EvidenceRef {
                lsn: 1,
                event_id: heraclitus_core::EventId::new(),
            }],
            expected_effect: "e".into(),
            requested_ttl: Some(60),
        }
    }

    #[test]
    fn policy_is_deterministic_and_requires_human_for_high_impact() {
        let engine = DeterministicPolicyEngine::new(PolicyConfig::default()).unwrap();
        let mut high = proposal(SecurityAction::QuarantineHost {
            host_id: "ws17".into(),
            ttl_secs: 60,
        });
        high.evidence.push(EvidenceRef {
            lsn: 2,
            event_id: heraclitus_core::EventId::new(),
        });
        let first = engine.evaluate(&incident(), &assessment(), &high);
        let second = engine.evaluate(&incident(), &assessment(), &high);
        assert_eq!(first, second);
        assert!(matches!(first, PolicyDecision::RequireHumanApproval { .. }));
    }

    #[test]
    fn policy_denies_allowlist_and_approves_low_impact_with_ttl() {
        let engine = DeterministicPolicyEngine::new(PolicyConfig::default()).unwrap();
        let proposal = proposal(SecurityAction::BlockIp {
            ip: "203.0.113.25".into(),
            ttl_secs: 60,
        });
        let approved = engine.evaluate(&incident(), &assessment(), &proposal);
        assert!(matches!(approved, PolicyDecision::Approve { .. }));
        let allowlisted = engine
            .clone()
            .with_allowlist(vec!["ip:203.0.113.25".into()])
            .evaluate(&incident(), &assessment(), &proposal);
        assert!(matches!(allowlisted, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn policy_rejects_low_risk_and_invalid_token_action() {
        let engine = DeterministicPolicyEngine::new(PolicyConfig::default()).unwrap();
        let mut low = assessment();
        low.fused_score = 0.1;
        let telemetry = proposal(SecurityAction::IncreaseTelemetry {
            target: "host:ws17".into(),
            ttl_secs: 60,
        });
        assert!(matches!(
            engine.evaluate(&incident(), &low, &telemetry),
            PolicyDecision::Deny { .. }
        ));
        let token = proposal(SecurityAction::DisableApiToken {
            token_hash: "clear".into(),
        });
        assert!(matches!(
            engine.evaluate(&incident(), &assessment(), &token),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn authorized_proposal_can_be_checked_against_static_context() {
        let builder = crate::AiContextBuilder::new(ContextBudget::default()).unwrap();
        let context: IncidentContext = builder
            .build(
                "inc-1",
                assessment(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                EnvironmentContext::default(),
                vec![ActionCapability {
                    kind: ActionKind::SnapshotEvidence,
                    enabled: true,
                    requires_approval: false,
                }],
            )
            .unwrap();
        let p = proposal(SecurityAction::SnapshotEvidence {
            target: "inc-1".into(),
        });
        p.validate_for(&context).unwrap();
    }

    #[test]
    fn high_impact_requires_matching_approval_before_authorization() {
        let engine = DeterministicPolicyEngine::new(PolicyConfig::default()).unwrap();
        let mut p = proposal(SecurityAction::QuarantineHost {
            host_id: "ws17".into(),
            ttl_secs: 60,
        });
        p.evidence.push(EvidenceRef {
            lsn: 2,
            event_id: heraclitus_core::EventId::new(),
        });
        let decision = engine.evaluate(&incident(), &assessment(), &p);
        assert!(decision.authorized_action(&p, None).is_err());
        let PolicyDecision::RequireHumanApproval { approval_id, .. } = decision else {
            panic!("esperava aprovação humana")
        };
        let approval = HumanApproval {
            approval_id,
            incident_id: "inc-1".into(),
            proposal_id: "p1".into(),
            approver: "analyst".into(),
            approved: true,
            reason: "confirmado".into(),
            evidence: p.evidence.clone(),
        };
        let authorized = PolicyDecision::RequireHumanApproval {
            approval_id: approval.approval_id.clone(),
            reason: "confirmado".into(),
        }
        .authorized_action(&p, Some(&approval))
        .unwrap();
        assert_eq!(authorized.incident_id, "inc-1");
    }
}

#[cfg(test)]
mod testes_health_gate_spec0071 {
    use super::*;
    use std::collections::HashMap;

    /// Sonda controlada: devolve o que o teste mandar, e
    /// `TelemetryHealthReading::desconhecida()` para o que não conhecer — que é
    /// exactamente o que a sonda real faz com uma classe sem expectativa
    /// configurada.
    struct SondaFalsa(HashMap<String, TelemetryHealthReading>);

    impl SondaFalsa {
        fn com(pares: &[(&str, TelemetryHealthReading)]) -> Arc<Self> {
            Arc::new(Self(
                pares.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
            ))
        }
    }

    impl TelemetryHealthProbe for SondaFalsa {
        fn leitura(&self, datasource_class: &str) -> TelemetryHealthReading {
            self.0
                .get(datasource_class)
                .copied()
                .unwrap_or_else(TelemetryHealthReading::desconhecida)
        }
    }

    fn saudavel(confianca: f32, idade_secs: u64) -> TelemetryHealthReading {
        TelemetryHealthReading {
            saudavel: true,
            confianca,
            idade_secs,
        }
    }

    fn requisito() -> RequiredTelemetry {
        RequiredTelemetry {
            datasource_class: "identity".into(),
            minimum_trust: 0.90,
            maximum_age_secs: 300,
        }
    }

    /// Uma política em que `RequireMfa` exige telemetria de identidade —
    /// o exemplo literal da §9.1.
    fn politica_com_requisito() -> PolicyConfig {
        let mut config = PolicyConfig::default();
        config
            .actions
            .get_mut(&ActionKind::RequireMfa)
            .expect("RequireMfa está na política default")
            .required_telemetry = vec![requisito()];
        config
    }

    fn cenario() -> (SecurityIncident, RiskAssessment, ActionProposal) {
        (
            super::tests::incident(),
            super::tests::assessment(),
            super::tests::proposal(SecurityAction::RequireMfa {
                user_id: "alice".into(),
            }),
        )
    }

    fn decidir(
        engine: &DeterministicPolicyEngine,
        cenario: &(SecurityIncident, RiskAssessment, ActionProposal),
    ) -> PolicyDecision {
        engine.evaluate(&cenario.0, &cenario.1, &cenario.2)
    }

    #[test]
    fn sem_requisito_declarado_o_gate_nao_muda_nada() {
        // A decisão de calibração: um gate que, sem playbook, inventasse um
        // requisito recusaria toda a acção automática desde o primeiro dia.
        let c = cenario();
        let engine = DeterministicPolicyEngine::new(PolicyConfig::default()).unwrap();
        let sem_sonda = decidir(&engine, &c);
        let com_sonda_vazia = decidir(
            &engine.clone().with_telemetry_probe(SondaFalsa::com(&[])),
            &c,
        );
        assert!(
            matches!(sem_sonda, PolicyDecision::Approve { .. }),
            "sem requisito declarado a decisão tem de ser a de sempre: {sem_sonda:?}"
        );
        assert_eq!(
            std::mem::discriminant(&sem_sonda),
            std::mem::discriminant(&com_sonda_vazia),
            "ligar uma sonda não pode mudar a decisão quando nada é exigido"
        );
    }

    #[test]
    fn telemetria_saudavel_e_fresca_deixa_aprovar() {
        let c = cenario();
        let engine = DeterministicPolicyEngine::new(politica_com_requisito())
            .unwrap()
            .with_telemetry_probe(SondaFalsa::com(&[("identity", saudavel(0.95, 60))]));
        assert!(matches!(
            decidir(&engine, &c),
            PolicyDecision::Approve { .. }
        ));
    }

    #[test]
    fn telemetria_silent_ou_unknown_nunca_aprova() {
        // O gate SO0. `Silent` e `Unknown` estão lado a lado na §9.1 de
        // propósito: não saber se um sensor está vivo não é melhor do que
        // saber que está morto.
        let c = cenario();
        let silent = TelemetryHealthReading {
            saudavel: false,
            confianca: 0.99,
            idade_secs: 1,
        };
        for (nome, sonda) in [
            ("silent", SondaFalsa::com(&[("identity", silent)])),
            ("unknown", SondaFalsa::com(&[])),
        ] {
            let engine = DeterministicPolicyEngine::new(politica_com_requisito())
                .unwrap()
                .with_telemetry_probe(sonda);
            let decisao = decidir(&engine, &c);
            assert!(
                matches!(decisao, PolicyDecision::RequireHumanApproval { .. }),
                "{nome}: tinha de exigir humano, veio {decisao:?}"
            );
        }
    }

    #[test]
    fn confianca_abaixo_do_minimo_e_telemetria_velha_nao_aprovam() {
        let c = cenario();
        for (nome, leitura) in [
            ("confiança baixa", saudavel(0.89, 60)),
            ("velha", saudavel(0.99, 301)),
        ] {
            let engine = DeterministicPolicyEngine::new(politica_com_requisito())
                .unwrap()
                .with_telemetry_probe(SondaFalsa::com(&[("identity", leitura)]));
            let decisao = decidir(&engine, &c);
            assert!(
                matches!(decisao, PolicyDecision::RequireHumanApproval { .. }),
                "{nome}: tinha de exigir humano, veio {decisao:?}"
            );
        }
        // As fronteiras exactas aprovam: 0.90 é o mínimo, 300s é o máximo.
        for leitura in [saudavel(0.90, 60), saudavel(0.99, 300)] {
            let engine = DeterministicPolicyEngine::new(politica_com_requisito())
                .unwrap()
                .with_telemetry_probe(SondaFalsa::com(&[("identity", leitura)]));
            assert!(matches!(
                decidir(&engine, &c),
                PolicyDecision::Approve { .. }
            ));
        }
    }

    #[test]
    fn um_sensor_saudavel_de_outra_classe_nao_satisfaz_o_requisito() {
        // O teste adversarial: o gate tem de olhar para a classe PEDIDA e não
        // para "existe telemetria saudável algures".
        let c = cenario();
        let engine = DeterministicPolicyEngine::new(politica_com_requisito())
            .unwrap()
            .with_telemetry_probe(SondaFalsa::com(&[
                ("network", saudavel(1.0, 1)),
                ("endpoint", saudavel(1.0, 1)),
            ]));
        let decisao = decidir(&engine, &c);
        assert!(
            matches!(decisao, PolicyDecision::RequireHumanApproval { .. }),
            "um sensor de outra classe não pode satisfazer o requisito: {decisao:?}"
        );
    }

    #[test]
    fn declarar_um_requisito_sem_sonda_ligada_nao_aprova() {
        // Declarar que uma acção depende de telemetria e depois não ter como a
        // verificar não é razão para aprovar; é razão para exigir um humano.
        let c = cenario();
        let engine = DeterministicPolicyEngine::new(politica_com_requisito()).unwrap();
        let decisao = decidir(&engine, &c);
        assert!(
            matches!(decisao, PolicyDecision::RequireHumanApproval { .. }),
            "sem sonda, um requisito declarado não pode ser dado por satisfeito: {decisao:?}"
        );
    }

    #[test]
    fn o_gate_nao_transforma_um_deny_em_pedido_de_aprovacao() {
        // O gate é o ÚLTIMO teste: uma acção que já ia ser recusada por outra
        // razão continua recusada, e não passa a "pede-se um humano" — que
        // seria abrir um caminho que a política tinha fechado.
        let (incident, assessment, proposal) = cenario();
        let mut config = politica_com_requisito();
        // Desligada: uma recusa que nao depende de nenhum score.
        config
            .actions
            .get_mut(&ActionKind::RequireMfa)
            .unwrap()
            .enabled = false;
        let engine = DeterministicPolicyEngine::new(config)
            .unwrap()
            .with_telemetry_probe(SondaFalsa::com(&[]));
        let decisao = engine.evaluate(&incident, &assessment, &proposal);
        assert!(
            matches!(decisao, PolicyDecision::Deny { .. }),
            "o gate não pode reabrir o que a política fechou: {decisao:?}"
        );
    }

    #[test]
    fn um_requisito_malformado_e_recusado_na_configuracao() {
        for mau in [
            RequiredTelemetry {
                datasource_class: "  ".into(),
                minimum_trust: 0.9,
                maximum_age_secs: 300,
            },
            RequiredTelemetry {
                datasource_class: "identity".into(),
                minimum_trust: 1.5,
                maximum_age_secs: 300,
            },
            RequiredTelemetry {
                datasource_class: "identity".into(),
                minimum_trust: f32::NAN,
                maximum_age_secs: 300,
            },
            RequiredTelemetry {
                datasource_class: "identity".into(),
                minimum_trust: 0.9,
                maximum_age_secs: 0,
            },
        ] {
            let mut config = PolicyConfig::default();
            config
                .actions
                .get_mut(&ActionKind::RequireMfa)
                .unwrap()
                .required_telemetry = vec![mau.clone()];
            assert!(
                DeterministicPolicyEngine::new(config).is_err(),
                "{mau:?} tinha de ser recusado"
            );
        }
    }
}
