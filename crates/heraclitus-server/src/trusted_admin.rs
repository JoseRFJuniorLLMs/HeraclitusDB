//! SPEC-0089 — Trusted Administration Protocol.
//!
//! Protocolo de execução administrativa privilegiada com evidência durável em duas fases:
//! - Invariante 1: `NO DURABLE INTENT => NO PRIVILEGED SIDE EFFECT`
//! - Invariante 2: `SIDE EFFECT => DURABLE RESULT OR RECOVERABLE UNKNOWN`
//!
//! Operações destrutivas ou de alto impacto (crypto-shred, alteração de Legal Hold,
//! rotação de chaves, exportação forense privilegiada) DEVEM passar por este protocolo.

use heraclitus_core::error::HeraclitusError;
use heraclitus_core::Lsn;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Classificação da auditoria (SPEC-0089 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditClass {
    /// Consulta operacional de rotina (pode ser best-effort se configurado).
    OperationalQuery,
    /// Operação administrativa privilegiada (obrigatoriamente fail-closed e em duas fases).
    PrivilegedAdmin,
    /// Evidência forense ou de conformidade regulatória.
    SecurityEvidence,
}

/// Tipo de operação administrativa abrangida pela SPEC-0089 §2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminOperationKind {
    /// Eliminação irreversível por destruição de chave (crypto-shred).
    CryptoShred { agent_id: String },
    /// Criação de Legal Hold (bloqueio de expiração/shred).
    LegalHoldCreate { hold_id: String, reason: String },
    /// Liberação / revogação de Legal Hold.
    LegalHoldRelease { hold_id: String, reason: String },
    /// Rotação de chaves criptográficas.
    KeyRotation { key_id: String },
    /// Destruição definitiva de material de chaves.
    KeyDestruction { key_id: String },
    /// Alteração da política de retenção / tiering.
    RetentionPolicyChange { policy_id: String, details: String },
    /// Alteração de Key Provider (ex.: HSM, KMS, software).
    KeyProviderChange { new_provider_id: String },
    /// Exportação forense de custódia privilegiada.
    PrivilegedForensicExport { scope: String },
    /// Alteração de configurações de segurança em tempo de execução.
    SecurityConfigChange {
        parameter: String,
        new_value: String,
    },
    /// Ação crítica de cluster / consenso.
    ClusterCriticalAction { action: String, target_node: u64 },
    /// Aprovação humana de ação irreversível (four-eyes).
    HumanApproval { action_digest: String },
    /// Purge ou Garbage Collection administrativo fora de ciclo.
    EmergencyGc { target_segment: u64 },
    /// Operação administrativa personalizada.
    Custom { name: String, details: String },
}

/// Contexto de execução e autenticação do operador (SPEC-0089 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminContext {
    pub principal: String,
    pub tenant: String,
    pub roles: Vec<String>,
    pub client_endpoint: Option<String>,
    pub request_id: String,
    pub requested_at_secs: u64,
}

impl AdminContext {
    pub fn new(
        principal: impl Into<String>,
        tenant: impl Into<String>,
        roles: Vec<String>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            principal: principal.into(),
            tenant: tenant.into(),
            roles,
            client_endpoint: None,
            request_id: heraclitus_core::EventId::new().to_string(),
            requested_at_secs: now,
        }
    }
}

/// Política de aprovação dupla / four-eyes (SPEC-0089 §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    pub min_distinct_approvers: usize,
    pub requester_may_approve: bool,
    pub required_roles: Vec<String>,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            min_distinct_approvers: 1,
            requester_may_approve: true,
            required_roles: vec!["admin".to_string()],
        }
    }
}

impl ApprovalPolicy {
    /// Política estrita four-eyes (duas pessoas distintas com papel de segurança).
    pub fn strict_four_eyes(required_role: impl Into<String>) -> Self {
        Self {
            min_distinct_approvers: 2,
            requester_may_approve: false,
            required_roles: vec![required_role.into()],
        }
    }
}

/// Aprovação registrada para uma operação.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approver_principal: String,
    pub approver_role: String,
    pub approved_intent_digest: String,
    pub approved_at_secs: u64,
    pub signature: Option<String>,
}

/// Parâmetros e identificação de uma operação administrativa.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminOperation {
    pub operation_id: String,
    pub idempotency_key: String,
    pub kind: AdminOperationKind,
    pub target_digest: String,
    pub parameters_digest: String,
    pub reason: String,
    pub approval_policy: Option<ApprovalPolicy>,
    pub approvals: Vec<ApprovalRecord>,
}

impl AdminOperation {
    pub fn new(
        operation_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        kind: AdminOperationKind,
        reason: impl Into<String>,
    ) -> Self {
        let kind_bytes = serde_json::to_vec(&kind).unwrap_or_default();
        let target_digest = blake3::hash(&kind_bytes).to_hex().to_string();
        Self {
            operation_id: operation_id.into(),
            idempotency_key: idempotency_key.into(),
            kind,
            target_digest,
            parameters_digest: String::new(),
            reason: reason.into(),
            approval_policy: None,
            approvals: Vec::new(),
        }
    }

    /// Calcula o digest determinístico dos parâmetros da operação.
    pub fn compute_intent_digest(&self, ctx: &AdminContext) -> String {
        let bytes = serde_json::to_vec(&(
            "heraclitus-admin-intent-v2",
            &self.operation_id,
            &self.idempotency_key,
            &ctx.principal,
            &ctx.tenant,
            &ctx.roles,
            &self.kind,
            &self.target_digest,
            &self.parameters_digest,
            &self.reason,
            &self.approval_policy,
        ))
        .expect("administrative intent serializes");
        blake3::hash(&bytes).to_hex().to_string()
    }
}

/// Estado do ciclo de vida da operação administrativa (SPEC-0089 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminState {
    Proposed,
    Authorized,
    IntentDurable,
    Executing,
    Succeeded,
    Failed,
    Unknown,
    Reconciled,
}

/// Registro durável da intenção autorizada (Fase 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminIntent {
    pub operation_id: String,
    pub idempotency_key: String,
    pub intent_digest: String,
    pub principal: String,
    pub tenant: String,
    pub kind: AdminOperationKind,
    pub reason: String,
    pub requested_at_secs: u64,
    pub approver_count: usize,
}

/// Resultado durável da execução (Fase 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminResult {
    pub operation_id: String,
    pub idempotency_key: String,
    pub status: AdminState,
    pub post_state_digest: String,
    pub provider_receipts: BTreeMap<String, String>,
    pub error_detail: Option<String>,
    pub completed_at_secs: u64,
}

/// Token interno intransferível fornecido à closure de execução para provar que a Fase 2 (Durable Intent) foi concluída.
/// Não pode ser construído fora deste módulo (SPEC-0089 §3).
pub struct AdminExecutionToken {
    operation_id: String,
    intent_lsn: Lsn,
    /// A operação para que a intenção foi autorizada e gravada.
    kind: AdminOperationKind,
    _private: (),
}

impl AdminExecutionToken {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// `true` se este token foi emitido para destruir a chave de `agent_id`.
    ///
    /// Conferência de 2026-10-02 (SPEC-0089 §14): o `shred_effect` recebia o
    /// token e ignorava-o (`_token`). Qualquer token — de um legal hold, de
    /// uma aprovação do Sentinel — servia para destruir a chave de qualquer
    /// titular, e a intenção gravada no diário descrevia outra operação.
    pub fn authorizes_crypto_shred(&self, agent_id: &str) -> bool {
        match &self.kind {
            AdminOperationKind::CryptoShred { agent_id: alvo } => alvo == agent_id,
            // O RPC `Admin op="shred:<id>"` grava a intenção como Custom com
            // o nome da operação — o mesmo texto que o despachante executa.
            AdminOperationKind::Custom { name, .. } => {
                name.strip_prefix("shred:") == Some(agent_id)
            }
            _ => false,
        }
    }

    pub fn intent_lsn(&self) -> Lsn {
        self.intent_lsn
    }
}

/// Resultado retornado por uma chamada bem-sucedida a `execute_admin`.
pub struct AdminOutcome<T> {
    pub value: T,
    pub operation_id: String,
    pub intent_lsn: Lsn,
    pub result_lsn: Lsn,
    pub state: AdminState,
}

/// Erros emitidos pelo protocolo de administração confiável.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("Operação administrativa negada por autorização: {0}")]
    AccessDenied(String),

    #[error(
        "Aprovação four-eyes insuficiente: {detail} (requerido: {required}, obtido: {obtained})"
    )]
    ApprovalMissing {
        required: usize,
        obtained: usize,
        detail: String,
    },

    #[error("Conflito de idempotência: a chave {idempotency_key} já foi usada para digest {existing_digest}, mas recebeu {new_digest}")]
    IdempotencyConflict {
        idempotency_key: String,
        existing_digest: String,
        new_digest: String,
    },

    #[error("Falha ao persistir Durable Intent (Fase 2): {0}")]
    IntentPersistenceFailed(String),

    #[error("Falha ao persistir Durable Result (Fase 4): {0}")]
    ResultPersistenceFailed(String),

    #[error("Erro durante a execução do side-effect administrativo: {0}")]
    ExecutionFailed(String),

    #[error("Pré-condição violada: {0}")]
    PreconditionFailed(String),

    #[error("Estado indeterminado após falha (UNKNOWN) — encaminhado para reconciliação: {0}")]
    UnknownState(String),

    #[error("Erro de armazenamento subjacente: {0}")]
    Storage(#[from] HeraclitusError),
}

/// Registro de idempotência armazenado em memória e reconciliado no arranque.
#[derive(Debug, Clone)]
struct IdempotencyEntry {
    intent_digest: String,
    state: AdminState,
    intent_lsn: Lsn,
    result_lsn: Option<Lsn>,
    completed_at_secs: Option<u64>,
}

type ApprovalWitnesses = HashMap<(String, String, String), String>;

/// Gerenciador do Protocolo de Administração Confiável (SPEC-0089).
pub struct TrustedAdminProtocol {
    idempotency_map: Mutex<HashMap<String, IdempotencyEntry>>,
    active_operations: RwLock<HashMap<String, AdminState>>,
    execution: Mutex<()>,
    journal: Mutex<HashMap<String, DurableRecord>>,
    authenticated_approvals: Mutex<ApprovalWitnesses>,
}

impl Default for TrustedAdminProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustedAdminProtocol {
    pub fn new() -> Self {
        Self {
            idempotency_map: Mutex::new(HashMap::new()),
            active_operations: RwLock::new(HashMap::new()),
            execution: Mutex::new(()),
            journal: Mutex::new(HashMap::new()),
            authenticated_approvals: Mutex::new(HashMap::new()),
        }
    }

    /// Valida pré-condições, autorizações e aprovações four-eyes (Fase 1).
    pub fn validate(&self, ctx: &AdminContext, op: &AdminOperation) -> Result<String, AdminError> {
        // Validação básica de principal e tenant
        if ctx.principal.trim().is_empty() {
            return Err(AdminError::AccessDenied("Principal vazio".into()));
        }
        if ctx.tenant.trim().is_empty() {
            return Err(AdminError::AccessDenied("Tenant vazio".into()));
        }

        if !ctx
            .roles
            .iter()
            .any(|role| role.eq_ignore_ascii_case("admin"))
        {
            return Err(AdminError::AccessDenied("Admin role required".into()));
        }
        if op.operation_id.is_empty()
            || op.idempotency_key.is_empty()
            || op.reason.trim().is_empty()
        {
            return Err(AdminError::PreconditionFailed(
                "operation ID, idempotency key and reason required".into(),
            ));
        }
        let intent_digest = op.compute_intent_digest(ctx);

        // Verificação de idempotência prévia
        {
            let map = self.idempotency_map.lock().unwrap();
            if let Some(entry) = map.get(&op.idempotency_key) {
                if entry.intent_digest != intent_digest {
                    return Err(AdminError::IdempotencyConflict {
                        idempotency_key: op.idempotency_key.clone(),
                        existing_digest: entry.intent_digest.clone(),
                        new_digest: intent_digest,
                    });
                }
            }
        }

        // Validação de Four-Eyes / Aprovações (SPEC-0089 §9)
        if let Some(policy) = &op.approval_policy {
            let mut distinct_approvers = std::collections::HashSet::new();
            let authenticated = self.authenticated_approvals.lock().unwrap();
            for app in &op.approvals {
                if authenticated.get(&(
                    ctx.tenant.clone(),
                    app.approver_principal.clone(),
                    intent_digest.clone(),
                )) != Some(&app.approver_role)
                {
                    continue; // Request-supplied identity/role is not authorization.
                }
                if app.approved_intent_digest != intent_digest {
                    return Err(AdminError::ApprovalMissing {
                        required: policy.min_distinct_approvers,
                        obtained: distinct_approvers.len(),
                        detail: format!(
                            "Aprovação do principal {} é para digest diferente ({})",
                            app.approver_principal, app.approved_intent_digest
                        ),
                    });
                }
                if !policy.requester_may_approve && app.approver_principal == ctx.principal {
                    continue; // O solicitante não pode aprovar a si mesmo se a política proibir
                }
                if policy.required_roles.is_empty()
                    || policy.required_roles.contains(&app.approver_role)
                {
                    distinct_approvers.insert(app.approver_principal.clone());
                }
            }

            if distinct_approvers.len() < policy.min_distinct_approvers {
                return Err(AdminError::ApprovalMissing {
                    required: policy.min_distinct_approvers,
                    obtained: distinct_approvers.len(),
                    detail: format!(
                        "Operação exige {} aprovadores distintos com papéis {:?}",
                        policy.min_distinct_approvers, policy.required_roles
                    ),
                });
            }
        }

        Ok(intent_digest)
    }

    pub fn authenticate_approval(
        &self,
        principal: &AdminContext,
        digest: &str,
        role: &str,
    ) -> Result<(), AdminError> {
        if !principal.roles.iter().any(|r| r == role) {
            return Err(AdminError::AccessDenied("approver role unavailable".into()));
        }
        self.authenticated_approvals.lock().unwrap().insert(
            (
                principal.tenant.clone(),
                principal.principal.clone(),
                digest.into(),
            ),
            role.into(),
        );
        Ok(())
    }
    /// Registra a conclusão da operação no mapa de idempotência.
    pub fn record_completion(
        &self,
        idempotency_key: &str,
        intent_digest: String,
        state: AdminState,
        intent_lsn: Lsn,
        result_lsn: Option<Lsn>,
    ) {
        let mut active = self.active_operations.write().unwrap();
        active.remove(idempotency_key);
        drop(active);

        let mut map = self.idempotency_map.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        map.insert(
            idempotency_key.to_string(),
            IdempotencyEntry {
                intent_digest,
                state,
                intent_lsn,
                result_lsn,
                completed_at_secs: Some(now),
            },
        );
    }

    /// Consulta se uma operação já foi processada anteriormente por idempotency_key.
    pub fn query_idempotency(
        &self,
        idempotency_key: &str,
    ) -> Option<(AdminState, Lsn, Option<Lsn>, Option<u64>)> {
        let map = self.idempotency_map.lock().unwrap();
        map.get(idempotency_key)
            .map(|e| (e.state, e.intent_lsn, e.result_lsn, e.completed_at_secs))
    }

    /// Retorna o estado de uma operação ativa ou registrada por idempotency_key.
    pub fn operation_state(&self, ctx: &AdminContext, idempotency_key: &str) -> Option<AdminState> {
        let key = serde_json::to_string(&(&ctx.tenant, &ctx.principal, idempotency_key)).ok()?;
        // Um `error` gravado é Failed (o efeito devolveu erro), não Unknown:
        // reportá-lo como Unknown mandava o operador reconciliar uma operação
        // que já tinha desfecho.
        self.journal
            .lock()
            .ok()?
            .get(&key)
            .map(DurableRecord::estado)
    }

    pub fn get_operation_state(&self, idempotency_key: &str) -> Option<AdminState> {
        let active = self.active_operations.read().unwrap();
        if let Some(state) = active.get(idempotency_key) {
            return Some(*state);
        }
        let map = self.idempotency_map.lock().unwrap();
        map.get(idempotency_key).map(|e| e.state)
    }

    /// Cria um token de execução após a persistência da intenção (Fase 2).
    fn create_execution_token(
        &self,
        operation_id: String,
        intent_lsn: Lsn,
        kind: AdminOperationKind,
    ) -> AdminExecutionToken {
        let mut active = self.active_operations.write().unwrap();
        active.insert(operation_id.clone(), AdminState::IntentDurable);
        drop(active);

        AdminExecutionToken {
            operation_id,
            intent_lsn,
            kind,
            _private: (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_approval_cannot_cross_tenants() {
        let protocol = TrustedAdminProtocol::new();
        let ctx = AdminContext::new("alice", "tenant-a", vec!["admin".into()]);
        let mut op = AdminOperation::new(
            "op",
            "key",
            AdminOperationKind::EmergencyGc { target_segment: 1 },
            "approved cleanup",
        );
        op.approval_policy = Some(ApprovalPolicy {
            min_distinct_approvers: 1,
            requester_may_approve: false,
            required_roles: vec!["officer".into()],
        });
        let digest = op.compute_intent_digest(&ctx);
        op.approvals.push(ApprovalRecord {
            approver_principal: "bob".into(),
            approver_role: "officer".into(),
            approved_intent_digest: digest.clone(),
            approved_at_secs: 1,
            signature: None,
        });
        protocol
            .authenticate_approval(
                &AdminContext::new("bob", "tenant-b", vec!["officer".into()]),
                &digest,
                "officer",
            )
            .unwrap();
        assert!(protocol.validate(&ctx, &op).is_err());
        protocol
            .authenticate_approval(
                &AdminContext::new("bob", "tenant-a", vec!["officer".into()]),
                &digest,
                "officer",
            )
            .unwrap();
        assert!(protocol.validate(&ctx, &op).is_ok());
        let mut changed = ctx.clone();
        changed.roles.push("reader".into());
        assert_ne!(digest, op.compute_intent_digest(&changed));
    }

    #[test]
    fn four_eyes_policy_enforcement() {
        let protocol = TrustedAdminProtocol::new();
        let ctx = AdminContext::new("alice", "tenant-gov", vec!["admin".into()]);
        let mut op = AdminOperation::new(
            "op-shred-01",
            "idem-shred-01",
            AdminOperationKind::CryptoShred {
                agent_id: "agent-x".into(),
            },
            "LGPD Right to erasure",
        );
        let policy = ApprovalPolicy::strict_four_eyes("security_officer");
        op.approval_policy = Some(policy);

        // Sem aprovações -> Erro
        assert!(protocol.validate(&ctx, &op).is_err());

        // Solicitante não pode ser o aprovador em strict_four_eyes
        let intent_digest = op.compute_intent_digest(&ctx);
        op.approvals.push(ApprovalRecord {
            approver_principal: "alice".into(),
            approver_role: "security_officer".into(),
            approved_intent_digest: intent_digest.clone(),
            approved_at_secs: 100,
            signature: None,
        });
        assert!(protocol.validate(&ctx, &op).is_err());

        // Aprovador legítimo 1
        op.approvals.push(ApprovalRecord {
            approver_principal: "bob".into(),
            approver_role: "security_officer".into(),
            approved_intent_digest: intent_digest.clone(),
            approved_at_secs: 101,
            signature: None,
        });
        assert!(protocol.validate(&ctx, &op).is_err()); // Precisa de 2

        // Aprovador legítimo 2
        op.approvals.push(ApprovalRecord {
            approver_principal: "carol".into(),
            approver_role: "security_officer".into(),
            approved_intent_digest: intent_digest.clone(),
            approved_at_secs: 102,
            signature: None,
        });
        for name in ["bob", "carol"] {
            protocol
                .authenticate_approval(
                    &AdminContext::new(name, "tenant-gov", vec!["security_officer".into()]),
                    &intent_digest,
                    "security_officer",
                )
                .unwrap();
        }
        assert!(protocol.validate(&ctx, &op).is_ok()); // 2 aprovadores distintos atendem a política
    }

    #[test]
    fn idempotency_conflict_detection() {
        let protocol = TrustedAdminProtocol::new();
        let ctx = AdminContext::new("alice", "tenant-gov", vec!["admin".into()]);
        let op1 = AdminOperation::new(
            "op-01",
            "idem-key-1",
            AdminOperationKind::LegalHoldCreate {
                hold_id: "h1".into(),
                reason: "investigation".into(),
            },
            "Processo 123",
        );
        let digest1 = protocol.validate(&ctx, &op1).unwrap();
        protocol.record_completion("idem-key-1", digest1, AdminState::Succeeded, 10, Some(11));

        // Reenvio com os mesmos parâmetros -> OK
        assert!(protocol.validate(&ctx, &op1).is_ok());

        // Reenvio com a mesma idempotency_key mas parâmetros diferentes -> Conflito
        let op2 = AdminOperation::new(
            "op-02",
            "idem-key-1",
            AdminOperationKind::LegalHoldCreate {
                hold_id: "h2_diferente".into(),
                reason: "outra".into(),
            },
            "Processo 999",
        );
        assert!(matches!(
            protocol.validate(&ctx, &op2),
            Err(AdminError::IdempotencyConflict { .. })
        ));
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct DurableRecord {
    key: String,
    digest: String,
    operation_id: String,
    intent: Option<(AdminContext, AdminOperation)>,
    result: Option<serde_json::Value>,
    error: Option<String>,
    /// Quem resolveu manualmente uma operação UNKNOWN (SPEC-0089 §9). Campo
    /// opcional com `default`: diários gravados antes dele continuam a ler-se.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconciled_by: Option<String>,
}

impl DurableRecord {
    fn estado(&self) -> AdminState {
        match (&self.result, &self.error, &self.reconciled_by) {
            (_, _, Some(_)) => AdminState::Reconciled,
            (Some(_), _, None) => AdminState::Succeeded,
            (None, Some(_), None) => AdminState::Failed,
            (None, None, None) => AdminState::Unknown,
        }
    }
}

/// O desfecho que quem reconcilia declara para uma operação UNKNOWN, depois
/// de verificar o efeito real fora do sistema (chave existe ou não no HSM,
/// hold aplicado ou não, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciledOutcome {
    Succeeded,
    Failed,
}

impl TrustedAdminProtocol {
    /// Resolve uma operação UNKNOWN (SPEC-0089 §9).
    ///
    /// Conferência de 2026-10-02: `AdminState::Reconciled` existia e nunca
    /// era usado. Uma operação interrompida entre o efeito e o resultado
    /// ficava UNKNOWN para sempre — o protocolo recusa repeti-la (correcto) e
    /// não oferecia saída nenhuma além de a contornar com OUTRA chave de
    /// idempotência, que é exactamente o duplicado que o protocolo existe
    /// para impedir.
    ///
    /// Grava um `AdminResult` para a intenção pendente, com o desfecho
    /// declarado, a evidência e quem reconciliou; o `recover` aceita-o como
    /// qualquer outro resultado. Só aceita operações sem resultado, e verifica
    /// e grava sob o lock do diário: duas reconciliações concorrentes não
    /// podem gravar dois resultados (o segundo faria o `recover` recusar o
    /// arranque).
    ///
    /// Chamado de DENTRO de um `execute` (a própria reconciliação é uma
    /// operação administrativa auditada), portanto não toma o lock de
    /// execução.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reconcile(
        &self,
        reconciler: &AdminContext,
        tenant: &str,
        principal: &str,
        idempotency_key: &str,
        outcome: ReconciledOutcome,
        evidence: &str,
        mut persist: impl FnMut(heraclitus_core::Episode) -> Result<Lsn, HeraclitusError>,
    ) -> Result<AdminState, HeraclitusError> {
        if evidence.trim().is_empty() {
            return Err(HeraclitusError::Config(
                "reconciliação exige evidência do efeito real".into(),
            ));
        }
        let key = serde_json::to_string(&(tenant, principal, idempotency_key)).unwrap();
        let mut journal = self.journal.lock().unwrap();
        let Some(record) = journal.get(&key) else {
            return Err(HeraclitusError::Config(format!(
                "operação administrativa desconhecida: {idempotency_key}"
            )));
        };
        if record.estado() != AdminState::Unknown {
            return Err(HeraclitusError::Config(format!(
                "operação {} já está {:?}; nada a reconciliar",
                record.operation_id,
                record.estado()
            )));
        }
        let mut resolvido = record.clone();
        resolvido.reconciled_by = Some(reconciler.principal.clone());
        match outcome {
            ReconciledOutcome::Succeeded => {
                resolvido.result = Some(serde_json::json!({
                    "reconciled": true,
                    "evidence": evidence,
                }))
            }
            ReconciledOutcome::Failed => {
                resolvido.error = Some(format!("reconciled as failed: {evidence}"))
            }
        }
        persist(heraclitus_core::Episode::new(
            "heraclitus-admin",
            heraclitus_core::EventKind::Custom("AdminResult".into()),
            serde_json::to_vec(&resolvido)
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?,
        ))?;
        journal.insert(key, resolvido);
        Ok(AdminState::Reconciled)
    }

    pub(crate) fn recover<L: heraclitus_log::EpisodeLog + ?Sized>(
        &self,
        log: &L,
    ) -> Result<(), HeraclitusError> {
        let mut records: HashMap<String, DurableRecord> = HashMap::new();
        let head = log.head();
        // Conferência de 2026-10-02: a reconstrução do diário corria em CADA
        // `Engine::open` varrendo o log INTEIRO em janelas de 16 e decifrando
        // cada episódio só para o descartar pelo `agent_id` — custo O(log) no
        // arranque, pago até nos arranques log-only. O scan podado por
        // built-in só salta um segmento quando o Bloom PROVA a ausência (e um
        // sidecar ausente/corrompido cai no `.hrkl`), por isso a correcção do
        // diário não passa a depender de nenhum índice derivado. Sem a
        // capacidade (log legado) mantém-se a varredura completa.
        if let Some((rows, _)) =
            log.scan_builtin_eq_capped("agent_id", "heraclitus-admin", 0, head, usize::MAX)?
        {
            for (_, ep) in &rows {
                Self::aplicar_registo(&mut records, ep)?;
            }
        } else {
            let mut cur = 0;
            while cur < head {
                let rows = log.scan_capped(cur, head, 16)?;
                let Some((last, _)) = rows.last() else {
                    break;
                };
                for (_, ep) in &rows {
                    Self::aplicar_registo(&mut records, ep)?;
                }
                cur = last.saturating_add(1);
            }
        }
        *self.journal.lock().unwrap() = records;
        Ok(())
    }

    /// Valida e incorpora um evento do diário administrativo; ignora tudo o
    /// que não for `AdminIntent`/`AdminResult` do agente `heraclitus-admin`.
    fn aplicar_registo(
        records: &mut HashMap<String, DurableRecord>,
        ep: &heraclitus_core::Episode,
    ) -> Result<(), HeraclitusError> {
        if ep.agent_id != "heraclitus-admin" {
            return Ok(());
        }
        if !matches!(&ep.kind, heraclitus_core::EventKind::Custom(k) if k == "AdminIntent" || k == "AdminResult")
        {
            return Ok(());
        }
        let record: DurableRecord = serde_json::from_slice(&ep.content)
            .map_err(|e| HeraclitusError::Config(format!("administrative journal corrupt: {e}")))?;
        let Some((ctx, op)) = &record.intent else {
            return Err(HeraclitusError::Config("journal missing intent".into()));
        };
        let key =
            serde_json::to_string(&(&ctx.tenant, &ctx.principal, &op.idempotency_key)).unwrap();
        if key != record.key
            || op.compute_intent_digest(ctx) != record.digest
            || op.operation_id != record.operation_id
        {
            return Err(HeraclitusError::Config(
                "journal invalid intent binding".into(),
            ));
        }
        let is_intent =
            matches!(&ep.kind, heraclitus_core::EventKind::Custom(k) if k == "AdminIntent");
        if is_intent
            && (record.result.is_some() || record.error.is_some() || records.contains_key(&key))
        {
            return Err(HeraclitusError::Config(
                "duplicate/invalid administrative intent".into(),
            ));
        }
        if !is_intent
            && (!records.contains_key(&key) || record.result.is_some() == record.error.is_some())
        {
            return Err(HeraclitusError::Config(
                "journal orphan/invalid outcome".into(),
            ));
        }
        if let Some(previous) = records.get(&record.key) {
            if previous.result.is_some()
                || previous.error.is_some()
                || previous.digest != record.digest
                || previous.operation_id != record.operation_id
            {
                return Err(HeraclitusError::Config(
                    "administrative journal identity conflict".into(),
                ));
            }
        }
        records.insert(record.key.clone(), record);
        Ok(())
    }

    /// Serialized intent -> fsync -> effect -> result -> fsync. An incomplete
    /// or ambiguous execution remains UNKNOWN and is NEVER automatically retried.
    pub(crate) fn execute<T: Serialize + serde::de::DeserializeOwned>(
        &self,
        ctx: &AdminContext,
        op: &AdminOperation,
        mut persist: impl FnMut(heraclitus_core::Episode) -> Result<Lsn, HeraclitusError>,
        effect: impl FnOnce(&AdminExecutionToken) -> Result<T, HeraclitusError>,
    ) -> Result<T, HeraclitusError> {
        let _execution = self.execution.lock().map_err(|_| {
            HeraclitusError::Config("admin execution interrupted; restart and reconcile".into())
        })?;
        let digest = self
            .validate(ctx, op)
            .map_err(|e| HeraclitusError::Config(e.to_string()))?;
        // Scope keys by principal and tenant to prevent cross-principal replay.
        let key =
            serde_json::to_string(&(&ctx.tenant, &ctx.principal, &op.idempotency_key)).unwrap();
        if let Some(previous) = self.journal.lock().unwrap().get(&key) {
            if previous.digest != digest {
                return Err(HeraclitusError::IdempotencyConflict {
                    key: op.idempotency_key.clone(),
                });
            }
            // Um retry com a mesma chave devolve o desfecho GRAVADO, nunca
            // re-executa. Antes, um `error` gravado (o efeito falhou de forma
            // definitiva) era respondido como "UNKNOWN; reconciliation
            // required" — mandava reconciliar uma operação que não tinha nada
            // por reconciliar.
            match previous.estado() {
                AdminState::Succeeded => {
                    if let Some(value) = &previous.result {
                        return serde_json::from_value(value.clone())
                            .map_err(|e| HeraclitusError::Serialization(e.to_string()));
                    }
                }
                AdminState::Failed => {
                    return Err(HeraclitusError::Config(format!(
                        "administrative operation previously FAILED (not re-executed): {}: {}",
                        previous.operation_id,
                        previous.error.as_deref().unwrap_or("")
                    )));
                }
                AdminState::Reconciled => {
                    return Err(HeraclitusError::Config(format!(
                        "administrative operation was RECONCILED by {} (not re-executed): {}",
                        previous.reconciled_by.as_deref().unwrap_or("?"),
                        previous.operation_id
                    )));
                }
                _ => {}
            }
            return Err(HeraclitusError::Config(format!(
                "administrative operation UNKNOWN; reconciliation required: {}",
                previous.operation_id
            )));
        }
        let mut record = DurableRecord {
            key: key.clone(),
            digest,
            operation_id: op.operation_id.clone(),
            intent: Some((ctx.clone(), op.clone())),
            result: None,
            error: None,
            reconciled_by: None,
        };
        let event = |kind: &str,
                     record: &DurableRecord|
         -> Result<heraclitus_core::Episode, HeraclitusError> {
            Ok(heraclitus_core::Episode::new(
                "heraclitus-admin",
                heraclitus_core::EventKind::Custom(kind.into()),
                serde_json::to_vec(record)
                    .map_err(|e| HeraclitusError::Serialization(e.to_string()))?,
            ))
        };
        // Reserve before attempting persistence: an ambiguous write also fails closed.
        self.journal
            .lock()
            .unwrap()
            .insert(key.clone(), record.clone());
        let intent_lsn = persist(event("AdminIntent", &record)?)?;
        let token =
            self.create_execution_token(op.idempotency_key.clone(), intent_lsn, op.kind.clone());
        let result = effect(&token);
        match &result {
            Ok(value) => {
                record.result = Some(
                    serde_json::to_value(value)
                        .map_err(|e| HeraclitusError::Serialization(e.to_string()))?,
                )
            }
            Err(error) => record.error = Some(error.to_string()),
        }
        persist(event("AdminResult", &record)?)?;
        self.active_operations
            .write()
            .unwrap()
            .remove(&op.idempotency_key);
        self.journal.lock().unwrap().insert(key, record);
        result
    }
}

#[cfg(test)]
mod durable_regressions {
    use super::*;
    use heraclitus_log::Log;
    fn context() -> AdminContext {
        AdminContext::new("admin", "tenant", vec!["admin".into()])
    }
    fn operation() -> AdminOperation {
        AdminOperation::new(
            "op",
            "key",
            AdminOperationKind::CryptoShred {
                agent_id: "subject".into(),
            },
            "reason",
        )
    }
    #[test]
    fn digest_has_boundaries_and_binds_operation_policy_and_identity() {
        let op = operation();
        let a = context();
        let mut b = a.clone();
        b.principal = "admi".into();
        b.tenant = "ntenant".into();
        assert_ne!(op.compute_intent_digest(&a), op.compute_intent_digest(&b));
        let mut other = op.clone();
        other.operation_id.push('x');
        assert_ne!(
            op.compute_intent_digest(&a),
            other.compute_intent_digest(&a)
        );
        b = a.clone();
        b.roles.clear();
        assert!(TrustedAdminProtocol::new().validate(&b, &op).is_err());
    }
    #[test]
    fn failed_intent_never_executes_and_same_process_retry_is_unknown() {
        let p = TrustedAdminProtocol::new();
        let hits = std::cell::Cell::new(0);
        let result: Result<bool, _> = p.execute(
            &context(),
            &operation(),
            |_| {
                Err(HeraclitusError::Config(
                    "injected persistence failure".into(),
                ))
            },
            |_| {
                hits.set(hits.get() + 1);
                Ok(true)
            },
        );
        assert!(result.is_err());
        assert_eq!(hits.get(), 0);
        assert!(p
            .execute(
                &context(),
                &operation(),
                |_| Ok(1),
                |_| {
                    hits.set(hits.get() + 1);
                    Ok(true)
                }
            )
            .is_err());
        assert_eq!(hits.get(), 0);
    }
    #[test]
    fn durable_success_replays_after_restart_without_repeating_effect() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, heraclitus_core::FsyncPolicy::Always).unwrap();
        let p = TrustedAdminProtocol::new();
        let hits = std::cell::Cell::new(0);
        let persist = |ep| {
            let lsn = log.append(ep)?;
            log.flush()?;
            Ok(lsn)
        };
        let effect = |_: &AdminExecutionToken| {
            hits.set(hits.get() + 1);
            Ok(serde_json::json!({"receipt":"real"}))
        };
        assert!(p.execute(&context(), &operation(), persist, effect).is_ok());
        assert_eq!(hits.get(), 1);
        let restarted = TrustedAdminProtocol::new();
        restarted.recover(&log).unwrap();
        assert_eq!(
            restarted
                .execute(&context(), &operation(), persist, effect)
                .unwrap()["receipt"],
            "real"
        );
        assert_eq!(hits.get(), 1);
    }
    /// Conferência de 2026-10-02: um efeito que devolve erro tem desfecho
    /// (Failed), não é UNKNOWN. O estado reportava Unknown e um retry pedia
    /// "reconciliation required" para uma operação sem nada por reconciliar.
    #[test]
    fn efeito_com_erro_fica_failed_e_o_retry_devolve_a_falha_sem_reexecutar() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, heraclitus_core::FsyncPolicy::Always).unwrap();
        let p = TrustedAdminProtocol::new();
        let hits = std::cell::Cell::new(0);
        let persist = |ep| {
            let lsn = log.append(ep)?;
            log.flush()?;
            Ok(lsn)
        };
        let falha = |_: &AdminExecutionToken| -> Result<bool, HeraclitusError> {
            hits.set(hits.get() + 1);
            Err(HeraclitusError::Config("chave não existe no HSM".into()))
        };
        assert!(p.execute(&context(), &operation(), persist, falha).is_err());
        assert_eq!(
            p.operation_state(&context(), "key"),
            Some(AdminState::Failed)
        );
        let erro = p
            .execute(&context(), &operation(), persist, falha)
            .unwrap_err()
            .to_string();
        assert!(erro.contains("previously FAILED"), "{erro}");
        assert_eq!(hits.get(), 1, "retry não re-executa o efeito");

        let reiniciado = TrustedAdminProtocol::new();
        reiniciado.recover(&log).unwrap();
        assert_eq!(
            reiniciado.operation_state(&context(), "key"),
            Some(AdminState::Failed)
        );
    }

    fn deixar_unknown<L: heraclitus_log::EpisodeLog>(log: &L) {
        let p = TrustedAdminProtocol::new();
        let writes = std::cell::Cell::new(0);
        let _: Result<bool, _> = p.execute(
            &context(),
            &operation(),
            |ep| {
                writes.set(writes.get() + 1);
                if writes.get() == 2 {
                    return Err(HeraclitusError::Config(
                        "injected result fsync failure".into(),
                    ));
                }
                let lsn = log.append(ep)?;
                log.flush()?;
                Ok(lsn)
            },
            |_| Ok(true),
        );
    }

    /// SPEC-0089 §9: `AdminState::Reconciled` nunca era usado — uma operação
    /// UNKNOWN ficava presa para sempre, e a única saída era repeti-la com
    /// outra chave (o duplicado que o protocolo existe para impedir).
    fn reconciliacao_resolve_unknown_e_sobrevive_ao_restart<L: heraclitus_log::EpisodeLog>(
        log: &L,
    ) {
        deixar_unknown(log);
        let p = TrustedAdminProtocol::new();
        p.recover(log).unwrap();
        assert_eq!(
            p.operation_state(&context(), "key"),
            Some(AdminState::Unknown)
        );

        let revisor = AdminContext::new("revisora", "tenant", vec!["admin".into()]);
        let persist = |ep| {
            let lsn = log.append(ep)?;
            log.flush()?;
            Ok(lsn)
        };
        // Sem evidência: recusado.
        assert!(p
            .reconcile(
                &revisor,
                "tenant",
                "admin",
                "key",
                ReconciledOutcome::Succeeded,
                " ",
                persist
            )
            .is_err());
        assert_eq!(
            p.reconcile(
                &revisor,
                "tenant",
                "admin",
                "key",
                ReconciledOutcome::Succeeded,
                "HSM confirma a chave destruída (ticket 42)",
                persist,
            )
            .unwrap(),
            AdminState::Reconciled
        );
        // Uma segunda reconciliação não pode gravar outro resultado.
        assert!(p
            .reconcile(
                &revisor,
                "tenant",
                "admin",
                "key",
                ReconciledOutcome::Failed,
                "x",
                persist
            )
            .is_err());

        // O restart lê o resultado reconciliado (o `recover` aceita-o) e o
        // retry continua a não re-executar.
        let reiniciado = TrustedAdminProtocol::new();
        reiniciado.recover(log).unwrap();
        assert_eq!(
            reiniciado.operation_state(&context(), "key"),
            Some(AdminState::Reconciled)
        );
        let hits = std::cell::Cell::new(0);
        let erro = reiniciado
            .execute(&context(), &operation(), persist, |_| {
                hits.set(hits.get() + 1);
                Ok(true)
            })
            .unwrap_err()
            .to_string();
        assert!(erro.contains("RECONCILED"), "{erro}");
        assert_eq!(hits.get(), 0);
    }

    #[test]
    fn reconciliacao_no_log_legado() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, heraclitus_core::FsyncPolicy::Always).unwrap();
        reconciliacao_resolve_unknown_e_sobrevive_ao_restart(&log);
    }

    /// No V6 o `recover` usa o scan podado por `agent_id` em vez de decifrar o
    /// log inteiro. Com ruído de outros agentes antes, entre e depois das
    /// entradas do diário, o resultado tem de ser o mesmo.
    #[test]
    fn reconciliacao_no_v6_com_recover_podado() {
        let dir = tempfile::tempdir().unwrap();
        let log = heraclitus_log::v6::V6Log::open(
            dir.path(),
            8 << 20,
            heraclitus_core::FsyncPolicy::Always,
        )
        .unwrap();
        for i in 0..50 {
            log.append(heraclitus_core::Episode::new(
                "outro-agente",
                heraclitus_core::EventKind::Observation,
                format!("ruido {i}").into_bytes(),
            ))
            .unwrap();
        }
        assert!(log
            .scan_builtin_eq_capped("agent_id", "heraclitus-admin", 0, log.head(), usize::MAX)
            .unwrap()
            .is_some());
        reconciliacao_resolve_unknown_e_sobrevive_ao_restart(&log);
    }

    #[test]
    fn failed_result_is_unknown_after_restart_and_is_not_reexecuted() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, heraclitus_core::FsyncPolicy::Always).unwrap();
        let p = TrustedAdminProtocol::new();
        let writes = std::cell::Cell::new(0);
        let hits = std::cell::Cell::new(0);
        let result: Result<bool, _> = p.execute(
            &context(),
            &operation(),
            |ep| {
                writes.set(writes.get() + 1);
                if writes.get() == 2 {
                    return Err(HeraclitusError::Config(
                        "injected result fsync failure".into(),
                    ));
                }
                let lsn = log.append(ep)?;
                log.flush()?;
                Ok(lsn)
            },
            |_| {
                hits.set(hits.get() + 1);
                Ok(true)
            },
        );
        assert!(result.is_err());
        assert_eq!(hits.get(), 1);
        let restarted = TrustedAdminProtocol::new();
        restarted.recover(&log).unwrap();
        assert!(restarted
            .execute(
                &context(),
                &operation(),
                |_| Ok(1),
                |_| {
                    hits.set(hits.get() + 1);
                    Ok(true)
                }
            )
            .is_err());
        assert_eq!(hits.get(), 1);
    }
}
