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
    SecurityConfigChange { parameter: String, new_value: String },
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
    pub fn new(principal: impl Into<String>, tenant: impl Into<String>, roles: Vec<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            principal: principal.into(),
            tenant: tenant.into(),
            roles,
            client_endpoint: None,
            request_id: format!("req-{}", blake3::hash(format!("{now}").as_bytes()).to_hex()),
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
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.operation_id.as_bytes());
        hasher.update(self.idempotency_key.as_bytes());
        hasher.update(ctx.principal.as_bytes());
        hasher.update(ctx.tenant.as_bytes());
        let kind_json = serde_json::to_string(&self.kind).unwrap_or_default();
        hasher.update(kind_json.as_bytes());
        hasher.update(self.target_digest.as_bytes());
        hasher.update(self.reason.as_bytes());
        hasher.finalize().to_hex().to_string()
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
    _private: (),
}

impl AdminExecutionToken {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
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

    #[error("Aprovação four-eyes insuficiente: {detail} (requerido: {required}, obtido: {obtained})")]
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

/// Gerenciador do Protocolo de Administração Confiável (SPEC-0089).
pub struct TrustedAdminProtocol {
    idempotency_map: Mutex<HashMap<String, IdempotencyEntry>>,
    active_operations: RwLock<HashMap<String, AdminState>>,
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
        }
    }

    /// Valida pré-condições, autorizações e aprovações four-eyes (Fase 1).
    pub fn validate(
        &self,
        ctx: &AdminContext,
        op: &AdminOperation,
    ) -> Result<String, AdminError> {
        // Validação básica de principal e tenant
        if ctx.principal.trim().is_empty() {
            return Err(AdminError::AccessDenied("Principal vazio".into()));
        }
        if ctx.tenant.trim().is_empty() {
            return Err(AdminError::AccessDenied("Tenant vazio".into()));
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
            for app in &op.approvals {
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
                if policy.required_roles.is_empty() || policy.required_roles.contains(&app.approver_role) {
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

    /// Registra a conclusão da operação no mapa de idempotência.
    pub fn record_completion(
        &self,
        idempotency_key: &str,
        intent_digest: String,
        state: AdminState,
        intent_lsn: Lsn,
        result_lsn: Option<Lsn>,
    ) {
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
    pub fn query_idempotency(&self, idempotency_key: &str) -> Option<(AdminState, Lsn, Option<Lsn>)> {
        let map = self.idempotency_map.lock().unwrap();
        map.get(idempotency_key).map(|e| (e.state, e.intent_lsn, e.result_lsn))
    }

    /// Cria um token de execução após a persistência da intenção (Fase 2).
    pub fn create_execution_token(&self, operation_id: String, intent_lsn: Lsn) -> AdminExecutionToken {
        AdminExecutionToken {
            operation_id,
            intent_lsn,
            _private: (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_eyes_policy_enforcement() {
        let protocol = TrustedAdminProtocol::new();
        let ctx = AdminContext::new("alice", "tenant-gov", vec!["admin".into()]);
        let mut op = AdminOperation::new(
            "op-shred-01",
            "idem-shred-01",
            AdminOperationKind::CryptoShred { agent_id: "agent-x".into() },
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
        assert!(protocol.validate(&ctx, &op).is_ok()); // 2 aprovadores distintos atendem a política
    }

    #[test]
    fn idempotency_conflict_detection() {
        let protocol = TrustedAdminProtocol::new();
        let ctx = AdminContext::new("alice", "tenant-gov", vec!["admin".into()]);
        let op1 = AdminOperation::new(
            "op-01",
            "idem-key-1",
            AdminOperationKind::LegalHoldCreate { hold_id: "h1".into(), reason: "investigation".into() },
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
            AdminOperationKind::LegalHoldCreate { hold_id: "h2_diferente".into(), reason: "outra".into() },
            "Processo 999",
        );
        assert!(matches!(
            protocol.validate(&ctx, &op2),
            Err(AdminError::IdempotencyConflict { .. })
        ));
    }
}
