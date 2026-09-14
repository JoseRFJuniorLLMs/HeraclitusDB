//! SPEC-0074 §20 e SPEC-0076 §6–§9 — as projecções derivadas que a Consola lê.
//!
//! # Porque projecções e não queries directas
//!
//! > A UI não deve consultar directamente o grafo/vector engine genérico
//! > (§20).
//!
//! A razão não é de gosto: a Consola tem cinco tarefas (§4 da 0076) e cada uma
//! precisa de uma forma estável. Se a UI falasse GQL sobre o log, cada mudança
//! interna do motor partiria a UI, e a promessa de §31 da 0074 ("o utilizador
//! não precisa de entender HRKL") morria na primeira tela.
//!
//! # Honestidade sobre integridade (0076 §8)
//!
//! > Nunca transformar "não verificado" em "válido" só porque a UI gosta de
//! > verde.
//!
//! [`IntegrityState`] tem quatro estados e a projecção só emite `Verified`
//! quando **todas** as evidências seleccionadas têm prova que fecha. Um
//! segmento ainda por selar dá `Unverified` — não `Verified`.

use crate::evidence::{AgentEvidenceKindV1, AgentEvidenceV1};
use crate::store::{ProofAvailability, StoredEvidence};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Estado de integridade de uma selecção (SPEC-0076 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IntegrityState {
    /// Tudo o que o contrato de verificação exige passou.
    Verified,
    /// A verificação necessária ainda não correu (segmento por selar, prova
    /// ainda não pedida).
    Unverified,
    /// Digest/prova/raiz falhou. Isto é um incidente, não um aviso.
    Broken,
    /// Evidência válida, mas faltam artefactos opcionais ou a selecção é
    /// propositadamente parcial.
    Partial,
}

impl IntegrityState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Unverified => "UNVERIFIED",
            Self::Broken => "BROKEN",
            Self::Partial => "PARTIAL",
        }
    }
}

/// Estado final de um run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Running,
    Success,
    Failed,
}

/// Uma linha da lista de runs (SPEC-0076 §6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub agent_name: Option<String>,
    pub human_subject: Option<String>,
    pub started_at_unix_nanos: u64,
    pub finished_at_unix_nanos: Option<u64>,
    pub status: RunStatus,
    pub tool_calls: u32,
    pub approvals: u32,
    pub denied: u32,
    pub errors: u32,
    pub evidence_count: u32,
    pub first_lsn: u64,
    pub last_lsn: u64,
    pub integrity: IntegrityState,
}

/// Uma linha da timeline (SPEC-0076 §7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunTimelineEntry {
    pub evidence_id: String,
    pub lsn: u64,
    pub at_unix_nanos: u64,
    pub kind: String,
    /// Texto curto e humano. A Consola mostra isto; os ids ficam por baixo.
    pub summary: String,
    pub tool_name: Option<String>,
    pub tool_call_id: Option<String>,
    pub model_id: Option<String>,
    pub policy_decision: Option<String>,
    pub policy_rule_id: Option<String>,
    pub policy_enforced: Option<bool>,
    pub approval_id: Option<String>,
    pub approver_subject: Option<String>,
    pub external_effect_id: Option<String>,
    pub error_code: Option<String>,
    pub duration_nanos: Option<u64>,
    pub record_hash: String,
    pub capture_mode: String,
    pub parents: Vec<String>,
}

/// Uma tool call reconstruída a partir das suas evidências (§13 da 0074).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallSummary {
    pub tool_call_id: String,
    pub run_id: Option<String>,
    pub server_id: Option<String>,
    pub tool_name: Option<String>,
    pub requested_at: Option<u64>,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub decision: Option<String>,
    pub enforced: Option<bool>,
    pub approval_id: Option<String>,
    pub argument_hash: Option<String>,
    pub result_hash: Option<String>,
    pub external_effect_id: Option<String>,
    pub status: Option<String>,
    /// `true` quando o trio Requested -> Started -> Finished está completo.
    pub complete: bool,
    pub evidence_ids: Vec<String>,
}

/// Uma aprovação humana, na forma que o bundle exporta.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSummary {
    pub approval_id: String,
    pub run_id: Option<String>,
    pub tool_name: Option<String>,
    pub authorization_subject_hash: String,
    pub requested_at: Option<u64>,
    pub decided_at: Option<u64>,
    pub approver_subject: Option<String>,
    pub approver_issuer: Option<String>,
    pub granted: Option<bool>,
    pub evidence_ids: Vec<String>,
}

/// Uma decisão de policy, na forma que o bundle exporta.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecisionSummary {
    pub evidence_id: String,
    pub run_id: Option<String>,
    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub rule_id: Option<String>,
    pub decision: String,
    pub reason_code: Option<String>,
    pub input_projection_hash: String,
    pub authorization_id: Option<String>,
    pub enforced: bool,
    pub tool_name: Option<String>,
    pub at_unix_nanos: u64,
}

/// Contadores de integridade de uma selecção.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceIntegritySummary {
    pub total: u32,
    pub proved: u32,
    pub pending_seal: u32,
    pub missing: u32,
    pub broken: u32,
}

impl EvidenceIntegritySummary {
    pub fn state(&self) -> IntegrityState {
        if self.broken > 0 || self.missing > 0 {
            IntegrityState::Broken
        } else if self.total == 0 {
            IntegrityState::Unverified
        } else if self.proved == self.total {
            IntegrityState::Verified
        } else if self.proved == 0 {
            IntegrityState::Unverified
        } else {
            IntegrityState::Partial
        }
    }

    pub fn observe(&mut self, availability: &ProofAvailability) {
        self.total += 1;
        match availability {
            ProofAvailability::Available(p) if p.verified => self.proved += 1,
            ProofAvailability::Available(_) => self.broken += 1,
            ProofAvailability::PendingSeal => self.pending_seal += 1,
            ProofAvailability::NotFound => self.missing += 1,
        }
    }
}

/// Projecta um conjunto de evidências em runs.
///
/// Determinística e pura: a mesma lista produz a mesma projecção, sempre. É o
/// que permite ao bundle exportar `timeline.ndjson` e o verificador offline
/// recalcular tudo sem o servidor.
pub fn project_runs(rows: &[StoredEvidence]) -> Vec<RunSummary> {
    let mut by_run: BTreeMap<String, RunSummary> = BTreeMap::new();
    for row in rows {
        let e = &row.evidence;
        let Some(run_id) = e.effective_run_id() else {
            continue;
        };
        let entry = by_run
            .entry(run_id.to_string())
            .or_insert_with(|| RunSummary {
                run_id: run_id.to_string(),
                tenant_id: e.tenant_id.clone(),
                agent_id: e.agent.agent_id.clone(),
                agent_name: e.agent.agent_name.clone(),
                human_subject: e.human.as_ref().map(|h| h.subject_id.clone()),
                started_at_unix_nanos: e.observed_at_unix_nanos,
                finished_at_unix_nanos: None,
                status: RunStatus::Running,
                tool_calls: 0,
                approvals: 0,
                denied: 0,
                errors: 0,
                evidence_count: 0,
                first_lsn: row.lsn,
                last_lsn: row.lsn,
                // A projecção pura não abre o log; quem tiver acesso às provas
                // sobrepõe isto com `apply_integrity`.
                integrity: IntegrityState::Unverified,
            });
        entry.evidence_count += 1;
        entry.first_lsn = entry.first_lsn.min(row.lsn);
        entry.last_lsn = entry.last_lsn.max(row.lsn);
        entry.started_at_unix_nanos = entry.started_at_unix_nanos.min(e.observed_at_unix_nanos);
        if entry.human_subject.is_none() {
            entry.human_subject = e.human.as_ref().map(|h| h.subject_id.clone());
        }
        match e.kind {
            AgentEvidenceKindV1::ToolInvocationFinished => entry.tool_calls += 1,
            AgentEvidenceKindV1::HumanApprovalGranted => entry.approvals += 1,
            AgentEvidenceKindV1::ToolDenied | AgentEvidenceKindV1::HumanApprovalDenied => {
                entry.denied += 1
            }
            AgentEvidenceKindV1::ErrorObserved => entry.errors += 1,
            AgentEvidenceKindV1::RunFinished => {
                entry.finished_at_unix_nanos = Some(e.observed_at_unix_nanos);
            }
            _ => {}
        }
        if let Some(p) = &e.content.policy {
            if p.decision.eq_ignore_ascii_case("deny") && p.enforced {
                // `ToolDenied` pode não existir quando o gateway está em
                // shadow; contar a decisão evita uma lista de runs que diz
                // "0 negados" sobre um run cheio de negações.
                entry.denied = entry.denied.max(1);
            }
        }
    }
    let mut runs: Vec<RunSummary> = by_run.into_values().collect();
    for r in &mut runs {
        r.status = if r.errors > 0 {
            RunStatus::Failed
        } else if r.finished_at_unix_nanos.is_some() {
            RunStatus::Success
        } else {
            RunStatus::Running
        };
    }
    // Mais recente primeiro — é a ordem que a lista de runs mostra.
    runs.sort_by(|a, b| {
        b.started_at_unix_nanos
            .cmp(&a.started_at_unix_nanos)
            .then_with(|| a.run_id.cmp(&b.run_id))
    });
    runs
}

/// Projecta a timeline de um run (ordem cronológica, depois por LSN).
pub fn project_timeline(rows: &[StoredEvidence], run_id: &str) -> Vec<RunTimelineEntry> {
    let mut out: Vec<RunTimelineEntry> = rows
        .iter()
        .filter(|r| r.evidence.effective_run_id() == Some(run_id))
        .map(timeline_entry)
        .collect();
    out.sort_by(|a, b| {
        a.at_unix_nanos
            .cmp(&b.at_unix_nanos)
            .then_with(|| a.lsn.cmp(&b.lsn))
    });
    out
}

/// Converte uma evidência numa linha de timeline.
pub fn timeline_entry(row: &StoredEvidence) -> RunTimelineEntry {
    let e = &row.evidence;
    RunTimelineEntry {
        evidence_id: e.evidence_id.clone(),
        lsn: row.lsn,
        at_unix_nanos: e.observed_at_unix_nanos,
        kind: e.kind.label().to_string(),
        summary: summarize(e),
        tool_name: e.subject.tool_name.clone(),
        tool_call_id: e.subject.tool_call_id.clone(),
        model_id: e.subject.model_id.clone(),
        policy_decision: e.content.policy.as_ref().map(|p| p.decision.clone()),
        policy_rule_id: e.content.policy.as_ref().and_then(|p| p.rule_id.clone()),
        policy_enforced: e.content.policy.as_ref().map(|p| p.enforced),
        approval_id: e.content.approval.as_ref().map(|a| a.approval_id.clone()),
        approver_subject: e
            .content
            .approval
            .as_ref()
            .and_then(|a| a.approver_subject.clone()),
        external_effect_id: e.subject.external_effect_id.clone(),
        error_code: e.outcome.as_ref().and_then(|o| o.error_code.clone()),
        duration_nanos: e.outcome.as_ref().and_then(|o| o.duration_nanos),
        record_hash: row.record_hash(),
        capture_mode: e.privacy.capture_mode.label().to_string(),
        parents: e.parents.clone(),
    }
}

/// Uma frase por evidência. Curta de propósito: a Consola mostra a linha, e os
/// ids/hashes aparecem quando se expande (0076 §7).
fn summarize(e: &AgentEvidenceV1) -> String {
    let tool = e.subject.tool_name.as_deref().unwrap_or("");
    let model = e.subject.model_id.as_deref().unwrap_or("");
    match e.kind {
        AgentEvidenceKindV1::RunStarted => "Run started".into(),
        AgentEvidenceKindV1::RunFinished => "Run finished".into(),
        AgentEvidenceKindV1::ModelInvocationStarted => {
            if model.is_empty() {
                "Model invocation".into()
            } else {
                format!("Model invocation: {model}")
            }
        }
        AgentEvidenceKindV1::ModelInvocationFinished => {
            if model.is_empty() {
                "Model result".into()
            } else {
                format!("Model result: {model}")
            }
        }
        AgentEvidenceKindV1::ToolRequested => format!("Tool requested: {tool}"),
        AgentEvidenceKindV1::ToolAuthorized => format!("Tool authorized: {tool}"),
        AgentEvidenceKindV1::ToolDenied => format!("Tool denied: {tool}"),
        AgentEvidenceKindV1::ToolInvocationStarted => format!("Tool executing: {tool}"),
        AgentEvidenceKindV1::ToolInvocationFinished => format!("Tool result: {tool}"),
        AgentEvidenceKindV1::HumanApprovalRequested => format!("Approval requested: {tool}"),
        AgentEvidenceKindV1::HumanApprovalGranted => {
            let who = e
                .content
                .approval
                .as_ref()
                .and_then(|a| a.approver_subject.as_deref())
                .unwrap_or("approver");
            format!("Approved by {who}")
        }
        AgentEvidenceKindV1::HumanApprovalDenied => "Approval denied".into(),
        AgentEvidenceKindV1::PolicyEvaluated => {
            let d = e
                .content
                .policy
                .as_ref()
                .map(|p| p.decision.to_uppercase())
                .unwrap_or_else(|| "EVALUATED".into());
            format!("Policy: {d}")
        }
        AgentEvidenceKindV1::AgentOutputProduced => "Agent output".into(),
        AgentEvidenceKindV1::ExternalEffectObserved => {
            let id = e.subject.external_effect_id.as_deref().unwrap_or("");
            format!("External effect: {id}")
        }
        AgentEvidenceKindV1::ErrorObserved => {
            let code = e
                .outcome
                .as_ref()
                .and_then(|o| o.error_code.as_deref())
                .unwrap_or("error");
            format!("Error: {code}")
        }
        AgentEvidenceKindV1::ArtifactReferenced => "Artifact referenced".into(),
    }
}

/// Reconstrói as tool calls a partir do trio correlacionado por `tool_call_id`.
pub fn project_tool_calls(rows: &[StoredEvidence]) -> Vec<ToolCallSummary> {
    let mut by_call: BTreeMap<String, ToolCallSummary> = BTreeMap::new();
    for row in rows {
        let e = &row.evidence;
        let Some(id) = e.subject.tool_call_id.as_deref() else {
            continue;
        };
        let entry = by_call
            .entry(id.to_string())
            .or_insert_with(|| ToolCallSummary {
                tool_call_id: id.to_string(),
                run_id: e.effective_run_id().map(str::to_string),
                server_id: e.subject.server_id.clone(),
                tool_name: e.subject.tool_name.clone(),
                requested_at: None,
                started_at: None,
                finished_at: None,
                decision: None,
                enforced: None,
                approval_id: None,
                argument_hash: None,
                result_hash: None,
                external_effect_id: None,
                status: None,
                complete: false,
                evidence_ids: Vec::new(),
            });
        entry.evidence_ids.push(e.evidence_id.clone());
        if entry.tool_name.is_none() {
            entry.tool_name = e.subject.tool_name.clone();
        }
        if entry.server_id.is_none() {
            entry.server_id = e.subject.server_id.clone();
        }
        if let Some(p) = &e.content.policy {
            entry.decision = Some(p.decision.clone());
            entry.enforced = Some(p.enforced);
        }
        if let Some(a) = &e.content.approval {
            entry.approval_id = Some(a.approval_id.clone());
        }
        if entry.external_effect_id.is_none() {
            entry.external_effect_id = e.subject.external_effect_id.clone();
        }
        match e.kind {
            AgentEvidenceKindV1::ToolRequested => {
                entry.requested_at = Some(e.observed_at_unix_nanos);
                entry.argument_hash = e.content.canonical_content_hash.clone();
            }
            AgentEvidenceKindV1::ToolInvocationStarted => {
                entry.started_at = Some(e.observed_at_unix_nanos);
                if entry.argument_hash.is_none() {
                    entry.argument_hash = e.content.canonical_content_hash.clone();
                }
            }
            AgentEvidenceKindV1::ToolInvocationFinished => {
                entry.finished_at = Some(e.observed_at_unix_nanos);
                entry.result_hash = e.content.canonical_content_hash.clone();
                entry.status = e.outcome.as_ref().and_then(|o| o.protocol_status.clone());
            }
            _ => {}
        }
    }
    let mut out: Vec<ToolCallSummary> = by_call.into_values().collect();
    for c in &mut out {
        c.complete = c.requested_at.is_some() && c.started_at.is_some() && c.finished_at.is_some();
        c.evidence_ids.sort();
        c.evidence_ids.dedup();
    }
    out
}

/// Reconstrói as aprovações humanas.
pub fn project_approvals(rows: &[StoredEvidence]) -> Vec<ApprovalSummary> {
    let mut by_id: BTreeMap<String, ApprovalSummary> = BTreeMap::new();
    for row in rows {
        let e = &row.evidence;
        let Some(a) = &e.content.approval else {
            continue;
        };
        let entry = by_id
            .entry(a.approval_id.clone())
            .or_insert_with(|| ApprovalSummary {
                approval_id: a.approval_id.clone(),
                run_id: e.effective_run_id().map(str::to_string),
                tool_name: e.subject.tool_name.clone(),
                authorization_subject_hash: a.authorization_subject_hash.clone(),
                requested_at: None,
                decided_at: None,
                approver_subject: None,
                approver_issuer: None,
                granted: None,
                evidence_ids: Vec::new(),
            });
        entry.evidence_ids.push(e.evidence_id.clone());
        match e.kind {
            AgentEvidenceKindV1::HumanApprovalRequested => {
                entry.requested_at = Some(e.observed_at_unix_nanos)
            }
            AgentEvidenceKindV1::HumanApprovalGranted => {
                entry.granted = Some(true);
                entry.decided_at = a.decided_at_unix_nanos.or(Some(e.observed_at_unix_nanos));
                entry.approver_subject = a.approver_subject.clone();
                entry.approver_issuer = a.approver_issuer.clone();
            }
            AgentEvidenceKindV1::HumanApprovalDenied => {
                entry.granted = Some(false);
                entry.decided_at = a.decided_at_unix_nanos.or(Some(e.observed_at_unix_nanos));
                entry.approver_subject = a.approver_subject.clone();
                entry.approver_issuer = a.approver_issuer.clone();
            }
            _ => {}
        }
    }
    by_id.into_values().collect()
}

/// Extrai as decisões de policy.
pub fn project_policy_decisions(rows: &[StoredEvidence]) -> Vec<PolicyDecisionSummary> {
    rows.iter()
        .filter_map(|row| {
            let e = &row.evidence;
            let p = e.content.policy.as_ref()?;
            Some(PolicyDecisionSummary {
                evidence_id: e.evidence_id.clone(),
                run_id: e.effective_run_id().map(str::to_string),
                policy_id: p.policy_id.clone(),
                policy_version: p.policy_version.clone(),
                policy_hash: p.policy_hash.clone(),
                rule_id: p.rule_id.clone(),
                decision: p.decision.clone(),
                reason_code: p.reason_code.clone(),
                input_projection_hash: p.input_projection_hash.clone(),
                authorization_id: p.authorization_id.clone(),
                enforced: p.enforced,
                tool_name: e.subject.tool_name.clone(),
                at_unix_nanos: e.observed_at_unix_nanos,
            })
        })
        .collect()
}

/// As identidades distintas envolvidas — o `identities.json` do bundle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentitiesProjection {
    pub agents: Vec<crate::evidence::AgentIdentityV1>,
    pub humans: Vec<crate::evidence::HumanIdentityRefV1>,
    pub delegations: Vec<crate::evidence::DelegationRefV1>,
}

pub fn project_identities(rows: &[StoredEvidence]) -> IdentitiesProjection {
    let mut agents: BTreeMap<String, crate::evidence::AgentIdentityV1> = BTreeMap::new();
    let mut humans: BTreeMap<String, crate::evidence::HumanIdentityRefV1> = BTreeMap::new();
    let mut delegations: BTreeMap<String, crate::evidence::DelegationRefV1> = BTreeMap::new();
    for row in rows {
        let e = &row.evidence;
        agents
            .entry(e.agent.agent_id.clone())
            .or_insert_with(|| e.agent.clone());
        if let Some(h) = &e.human {
            humans
                .entry(h.subject_id.clone())
                .or_insert_with(|| h.clone());
        }
        if let Some(d) = &e.delegation {
            delegations
                .entry(d.delegation_id.clone())
                .or_insert_with(|| d.clone());
        }
    }
    IdentitiesProjection {
        agents: agents.into_values().collect(),
        humans: humans.into_values().collect(),
        delegations: delegations.into_values().collect(),
    }
}

/// Conta quantos `parents` apontam para evidências que não estão na selecção.
///
/// Um bundle com pais partidos não é necessariamente adulterado — pode ser uma
/// selecção parcial deliberada. É por isso que o verificador o reporta em vez
/// de falhar cegamente (§18).
pub fn broken_parents(rows: &[StoredEvidence]) -> Vec<(String, String)> {
    let present: std::collections::HashSet<&str> = rows
        .iter()
        .map(|r| r.evidence.evidence_id.as_str())
        .collect();
    let mut out = Vec::new();
    for r in rows {
        for p in &r.evidence.parents {
            if !present.contains(p.as_str()) {
                out.push((r.evidence.evidence_id.clone(), p.clone()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{ApprovalProvenanceV1, PolicyProvenanceV1};

    fn row(lsn: u64, kind: AgentEvidenceKindV1, at: u64, id: &str) -> StoredEvidence {
        let mut e = AgentEvidenceV1::new("t", kind, at);
        e.evidence_id = id.to_string();
        e.run_id = Some("run-1".into());
        e.agent.agent_id = "procurement-agent".into();
        e.subject.tool_name = Some("send_payment".into());
        e.subject.tool_call_id = Some("call-1".into());
        StoredEvidence { lsn, evidence: e }
    }

    #[test]
    fn a_timeline_fica_por_ordem_cronologica() {
        let rows = vec![
            row(3, AgentEvidenceKindV1::ToolInvocationFinished, 300, "c"),
            row(1, AgentEvidenceKindV1::RunStarted, 100, "a"),
            row(2, AgentEvidenceKindV1::ToolRequested, 200, "b"),
        ];
        let tl = project_timeline(&rows, "run-1");
        let ids: Vec<_> = tl.iter().map(|t| t.evidence_id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn o_trio_de_uma_tool_call_e_reconstruido() {
        let rows = vec![
            row(1, AgentEvidenceKindV1::ToolRequested, 100, "a"),
            row(2, AgentEvidenceKindV1::ToolInvocationStarted, 200, "b"),
            row(3, AgentEvidenceKindV1::ToolInvocationFinished, 300, "c"),
        ];
        let calls = project_tool_calls(&rows);
        assert_eq!(calls.len(), 1);
        assert!(calls[0].complete);
        assert_eq!(calls[0].requested_at, Some(100));
        assert_eq!(calls[0].finished_at, Some(300));
    }

    #[test]
    fn uma_tool_call_sem_resultado_nao_e_completa() {
        let rows = vec![row(1, AgentEvidenceKindV1::ToolRequested, 100, "a")];
        assert!(!project_tool_calls(&rows)[0].complete);
    }

    #[test]
    fn run_com_erro_e_failed() {
        let rows = vec![
            row(1, AgentEvidenceKindV1::RunStarted, 100, "a"),
            row(2, AgentEvidenceKindV1::ErrorObserved, 200, "b"),
            row(3, AgentEvidenceKindV1::RunFinished, 300, "c"),
        ];
        assert_eq!(project_runs(&rows)[0].status, RunStatus::Failed);
    }

    #[test]
    fn integridade_parcial_nao_vira_verde() {
        let mut s = EvidenceIntegritySummary::default();
        s.observe(&ProofAvailability::Available(crate::store::StorageProof {
            lsn: 1,
            canonical_record_hash: String::new(),
            canonical_evidence_hash: String::new(),
            logical_root: String::new(),
            segment_id: 0,
            generation: 0,
            inclusion_path: vec![],
            leaf_index: 0,
            leaf_count: 1,
            timestamp_receipt: None,
            verified: true,
        }));
        s.observe(&ProofAvailability::PendingSeal);
        assert_eq!(s.state(), IntegrityState::Partial);
    }

    #[test]
    fn prova_que_nao_fecha_e_broken() {
        let mut s = EvidenceIntegritySummary::default();
        s.observe(&ProofAvailability::NotFound);
        assert_eq!(s.state(), IntegrityState::Broken);
    }

    #[test]
    fn aprovacao_e_reconstruida() {
        let mut r1 = row(1, AgentEvidenceKindV1::HumanApprovalRequested, 100, "a");
        r1.evidence.content.approval = Some(ApprovalProvenanceV1 {
            approval_id: "A-1".into(),
            authorization_subject_hash: "deadbeef".into(),
            ..Default::default()
        });
        let mut r2 = row(2, AgentEvidenceKindV1::HumanApprovalGranted, 200, "b");
        r2.evidence.content.approval = Some(ApprovalProvenanceV1 {
            approval_id: "A-1".into(),
            authorization_subject_hash: "deadbeef".into(),
            approver_subject: Some("cfo".into()),
            decided_at_unix_nanos: Some(199),
            ..Default::default()
        });
        let out = project_approvals(&[r1, r2]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].granted, Some(true));
        assert_eq!(out[0].approver_subject.as_deref(), Some("cfo"));
        assert_eq!(out[0].decided_at, Some(199));
    }

    #[test]
    fn decisao_de_policy_e_extraida() {
        let mut r = row(1, AgentEvidenceKindV1::PolicyEvaluated, 100, "a");
        r.evidence.content.policy = Some(PolicyProvenanceV1 {
            policy_id: "agent-policy".into(),
            policy_version: "v17".into(),
            policy_hash: "abc".into(),
            rule_id: Some("finance-large".into()),
            decision: "require_approval".into(),
            input_projection_hash: "def".into(),
            enforced: true,
            ..Default::default()
        });
        let out = project_policy_decisions(&[r]);
        assert_eq!(out[0].rule_id.as_deref(), Some("finance-large"));
    }

    #[test]
    fn pai_em_falta_e_reportado() {
        let mut r = row(1, AgentEvidenceKindV1::ToolRequested, 100, "a");
        r.evidence.parents = vec!["nao-existe".into()];
        assert_eq!(broken_parents(&[r]).len(), 1);
    }
}
