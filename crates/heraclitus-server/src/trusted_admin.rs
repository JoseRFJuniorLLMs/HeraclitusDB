//! SPEC-0089 — Trusted Administration Protocol.
//!
//! Invariantes:
//! - NO DURABLE INTENT => NO PRIVILEGED SIDE EFFECT
//! - SIDE EFFECT => DURABLE RESULT OR RECOVERABLE UNKNOWN
//!
//! A persistência concreta é injetada pelo servidor, mas o token de execução só
//! nasce dentro de `execute_admin`, depois de a intenção ter sido persistida.

use heraclitus_core::error::HeraclitusError;
use heraclitus_core::Lsn;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditClass {
    OperationalQuery,
    PrivilegedAdmin,
    SecurityEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminOperationKind {
    CryptoShred { agent_id: String },
    LegalHoldCreate { hold_id: String, reason: String },
    LegalHoldRelease { hold_id: String, reason: String },
    KeyRotation { key_id: String },
    KeyDestruction { key_id: String },
    RetentionPolicyChange { policy_id: String, details: String },
    KeyProviderChange { new_provider_id: String },
    PrivilegedForensicExport { scope: String },
    SecurityConfigChange { parameter: String, new_value: String },
    ClusterCriticalAction { action: String, target_node: u64 },
    HumanApproval { action_digest: String },
    EmergencyGc { target_segment: u64 },
    Custom { name: String, details: String },
}

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
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let now = duration.as_secs();
        let n = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = format!(
            "{}:{}:{}:{}",
            std::process::id(),
            duration.as_nanos(),
            n,
            now
        );
        Self {
            principal: principal.into(),
            tenant: tenant.into(),
            roles,
            client_endpoint: None,
            request_id: format!("req-{}", blake3::hash(seed.as_bytes()).to_hex()),
            requested_at_secs: now,
        }
    }

    pub fn is_privileged(&self) -> bool {
        self.roles
            .iter()
            .any(|role| matches!(role.as_str(), "admin" | "security_officer" | "root"))
    }
}

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
    pub fn strict_four_eyes(required_role: impl Into<String>) -> Self {
        Self {
            min_distinct_approvers: 2,
            requester_may_approve: false,
            required_roles: vec![required_role.into()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approver_principal: String,
    pub approver_role: String,
    pub approved_intent_digest: String,
    pub approved_at_secs: u64,
    pub signature: Option<String>,
}

/// Verificador ligado à fonte autenticada de identidade/aprovação.
///
/// A implementação do protocolo nunca confia apenas em strings fornecidas pelo
/// pedido. Se uma política four-eyes existir e nenhum verificador estiver
/// instalado, a operação falha fechada.
pub trait ApprovalVerifier: Send + Sync {
    fn verify(
        &self,
        requester: &AdminContext,
        approval: &ApprovalRecord,
        intent_digest: &str,
    ) -> Result<(), String>;
}

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

    pub fn compute_intent_digest(&self, ctx: &AdminContext) -> String {
        fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
            hasher.update(&(bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"HeraclitusDB/AdminIntent/v1");
        field(&mut hasher, self.operation_id.as_bytes());
        field(&mut hasher, self.idempotency_key.as_bytes());
        field(&mut hasher, ctx.principal.as_bytes());
        field(&mut hasher, ctx.tenant.as_bytes());
        field(
            &mut hasher,
            &serde_json::to_vec(&self.kind).unwrap_or_default(),
        );
        field(&mut hasher, self.target_digest.as_bytes());
        field(&mut hasher, self.parameters_digest.as_bytes());
        field(&mut hasher, self.reason.as_bytes());
        field(
            &mut hasher,
            &serde_json::to_vec(&self.approval_policy).unwrap_or_default(),
        );
        hasher.finalize().to_hex().to_string()
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminIntent {
    pub operation_id: String,
    pub idempotency_key: String,
    pub intent_digest: String,
    pub principal: String,
    pub tenant: String,
    pub kind: AdminOperationKind,
    pub target_digest: String,
    pub parameters_digest: String,
    pub reason: String,
    pub approval_policy: Option<ApprovalPolicy>,
    pub requested_at_secs: u64,
    pub approver_count: usize,
}

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

pub struct AdminExecutionToken {
    operation_id: String,
    idempotency_key: String,
    intent_lsn: Lsn,
    _private: (),
}

impl AdminExecutionToken {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn intent_lsn(&self) -> Lsn {
        self.intent_lsn
    }
}

pub struct AdminOutcome<T> {
    pub value: T,
    pub operation_id: String,
    pub intent_lsn: Lsn,
    pub result_lsn: Lsn,
    pub state: AdminState,
}

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
    #[error("Operação idempotente já está em andamento ou concluída: {0}")]
    AlreadyProcessed(String),
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

#[derive(Debug, Clone)]
struct IdempotencyEntry {
    intent_digest: String,
    state: AdminState,
    intent_lsn: Lsn,
    result_lsn: Option<Lsn>,
    completed_at_secs: Option<u64>,
}

pub struct TrustedAdminProtocol {
    idempotency_map: Mutex<HashMap<String, IdempotencyEntry>>,
    active_operations: RwLock<HashMap<String, AdminState>>,
    approval_verifier: RwLock<Option<Arc<dyn ApprovalVerifier>>>,
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
            approval_verifier: RwLock::new(None),
        }
    }

    pub fn set_approval_verifier(&self, verifier: Arc<dyn ApprovalVerifier>) {
        *self.approval_verifier.write().unwrap() = Some(verifier);
    }

    pub fn validate(
        &self,
        ctx: &AdminContext,
        op: &AdminOperation,
    ) -> Result<String, AdminError> {
        if ctx.principal.trim().is_empty() {
            return Err(AdminError::AccessDenied("Principal vazio".into()));
        }
        if ctx.tenant.trim().is_empty() {
            return Err(AdminError::AccessDenied("Tenant vazio".into()));
        }
        if !ctx.is_privileged() {
            return Err(AdminError::AccessDenied(format!(
                "principal {} não possui papel administrativo autenticado",
                ctx.principal
            )));
        }
        if op.operation_id.trim().is_empty() || op.idempotency_key.trim().is_empty() {
            return Err(AdminError::PreconditionFailed(
                "operation_id e idempotency_key são obrigatórios".into(),
            ));
        }

        let intent_digest = op.compute_intent_digest(ctx);

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

        if let Some(policy) = &op.approval_policy {
            if policy.min_distinct_approvers == 0 {
                return Err(AdminError::PreconditionFailed(
                    "approval_policy com zero aprovadores é inválida".into(),
                ));
            }
            let verifier = self
                .approval_verifier
                .read()
                .unwrap()
                .clone()
                .ok_or_else(|| {
                    AdminError::AccessDenied(
                        "política de aprovação exige fonte autenticada de aprovadores".into(),
                    )
                })?;

            let mut distinct_approvers = std::collections::HashSet::new();
            for app in &op.approvals {
                if app.approved_intent_digest != intent_digest {
                    return Err(AdminError::ApprovalMissing {
                        required: policy.min_distinct_approvers,
                        obtained: distinct_approvers.len(),
                        detail: format!(
                            "aprovação de {} referencia outro digest",
                            app.approver_principal
                        ),
                    });
                }
                if !policy.requester_may_approve && app.approver_principal == ctx.principal {
                    continue;
                }
                if !policy.required_roles.is_empty()
                    && !policy.required_roles.contains(&app.approver_role)
                {
                    continue;
                }
                verifier
                    .verify(ctx, app, &intent_digest)
                    .map_err(AdminError::AccessDenied)?;
                distinct_approvers.insert(app.approver_principal.clone());
            }

            if distinct_approvers.len() < policy.min_distinct_approvers {
                return Err(AdminError::ApprovalMissing {
                    required: policy.min_distinct_approvers,
                    obtained: distinct_approvers.len(),
                    detail: format!(
                        "operação exige {} aprovadores autenticados com papéis {:?}",
                        policy.min_distinct_approvers, policy.required_roles
                    ),
                });
            }
        }

        Ok(intent_digest)
    }

    fn reserve(
        &self,
        op: &AdminOperation,
        intent_digest: &str,
    ) -> Result<(), AdminError> {
        let mut map = self.idempotency_map.lock().unwrap();
        if let Some(entry) = map.get(&op.idempotency_key) {
            if entry.intent_digest != intent_digest {
                return Err(AdminError::IdempotencyConflict {
                    idempotency_key: op.idempotency_key.clone(),
                    existing_digest: entry.intent_digest.clone(),
                    new_digest: intent_digest.to_string(),
                });
            }
            if !matches!(entry.state, AdminState::Failed) {
                return Err(AdminError::AlreadyProcessed(format!(
                    "{} ({:?})",
                    op.idempotency_key, entry.state
                )));
            }
        }

        map.insert(
            op.idempotency_key.clone(),
            IdempotencyEntry {
                intent_digest: intent_digest.to_string(),
                state: AdminState::Authorized,
                intent_lsn: 0,
                result_lsn: None,
                completed_at_secs: None,
            },
        );
        self.active_operations
            .write()
            .unwrap()
            .insert(op.idempotency_key.clone(), AdminState::Authorized);
        Ok(())
    }

    fn release_reservation(&self, key: &str, intent_digest: &str) {
        let mut map = self.idempotency_map.lock().unwrap();
        if map
            .get(key)
            .map(|entry| {
                entry.intent_digest == intent_digest && entry.state == AdminState::Authorized
            })
            .unwrap_or(false)
        {
            map.remove(key);
        }
        self.active_operations.write().unwrap().remove(key);
    }

    fn create_execution_token(
        &self,
        op: &AdminOperation,
        intent_digest: &str,
        intent_lsn: Lsn,
    ) -> Result<AdminExecutionToken, AdminError> {
        let mut map = self.idempotency_map.lock().unwrap();
        let entry = map
            .get_mut(&op.idempotency_key)
            .ok_or_else(|| AdminError::PreconditionFailed("reserva idempotente ausente".into()))?;
        if entry.intent_digest != intent_digest || entry.state != AdminState::Authorized {
            return Err(AdminError::PreconditionFailed(
                "estado não permite emissão do token de execução".into(),
            ));
        }
        entry.intent_lsn = intent_lsn;
        entry.state = AdminState::IntentDurable;
        drop(map);

        self.active_operations
            .write()
            .unwrap()
            .insert(op.idempotency_key.clone(), AdminState::IntentDurable);

        Ok(AdminExecutionToken {
            operation_id: op.operation_id.clone(),
            idempotency_key: op.idempotency_key.clone(),
            intent_lsn,
            _private: (),
        })
    }

    fn mark_executing(&self, key: &str) {
        if let Some(entry) = self.idempotency_map.lock().unwrap().get_mut(key) {
            entry.state = AdminState::Executing;
        }
        self.active_operations
            .write()
            .unwrap()
            .insert(key.to_string(), AdminState::Executing);
    }

    fn mark_unknown(&self, key: &str) {
        if let Some(entry) = self.idempotency_map.lock().unwrap().get_mut(key) {
            entry.state = AdminState::Unknown;
        }
        self.active_operations
            .write()
            .unwrap()
            .insert(key.to_string(), AdminState::Unknown);
    }

    pub fn execute_admin<T, PersistIntent, Execute, PersistResult>(
        &self,
        ctx: &AdminContext,
        op: &AdminOperation,
        persist_intent: PersistIntent,
        execute: Execute,
        persist_result: PersistResult,
    ) -> Result<AdminOutcome<T>, AdminError>
    where
        PersistIntent: FnOnce(&AdminIntent) -> Result<Lsn, AdminError>,
        Execute: FnOnce(
            &AdminExecutionToken,
        ) -> Result<(T, String, BTreeMap<String, String>), AdminError>,
        PersistResult: FnOnce(&AdminResult) -> Result<Lsn, AdminError>,
    {
        let digest = self.validate(ctx, op)?;
        self.reserve(op, &digest)?;

        let intent = AdminIntent {
            operation_id: op.operation_id.clone(),
            idempotency_key: op.idempotency_key.clone(),
            intent_digest: digest.clone(),
            principal: ctx.principal.clone(),
            tenant: ctx.tenant.clone(),
            kind: op.kind.clone(),
            target_digest: op.target_digest.clone(),
            parameters_digest: op.parameters_digest.clone(),
            reason: op.reason.clone(),
            approval_policy: op.approval_policy.clone(),
            requested_at_secs: ctx.requested_at_secs,
            approver_count: op.approvals.len(),
        };

        let intent_lsn = match persist_intent(&intent) {
            Ok(lsn) => lsn,
            Err(error) => {
                self.release_reservation(&op.idempotency_key, &digest);
                return Err(AdminError::IntentPersistenceFailed(error.to_string()));
            }
        };
        let token = self.create_execution_token(op, &digest, intent_lsn)?;
        self.mark_executing(&op.idempotency_key);

        let executed = execute(&token);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match executed {
            Ok((value, post_state_digest, provider_receipts)) => {
                let result = AdminResult {
                    operation_id: op.operation_id.clone(),
                    idempotency_key: op.idempotency_key.clone(),
                    status: AdminState::Succeeded,
                    post_state_digest,
                    provider_receipts,
                    error_detail: None,
                    completed_at_secs: now,
                };
                let result_lsn = match persist_result(&result) {
                    Ok(lsn) => lsn,
                    Err(error) => {
                        self.mark_unknown(&op.idempotency_key);
                        return Err(AdminError::UnknownState(format!(
                            "side-effect executado, mas Durable Result falhou: {error}"
                        )));
                    }
                };
                self.record_completion(
                    &op.idempotency_key,
                    digest,
                    AdminState::Succeeded,
                    intent_lsn,
                    Some(result_lsn),
                );
                Ok(AdminOutcome {
                    value,
                    operation_id: op.operation_id.clone(),
                    intent_lsn,
                    result_lsn,
                    state: AdminState::Succeeded,
                })
            }
            Err(error) => {
                // A closure pode ter falhado depois de tocar o provider/FS.
                // Sem prova de não-efeito, o estado seguro é UNKNOWN.
                let result = AdminResult {
                    operation_id: op.operation_id.clone(),
                    idempotency_key: op.idempotency_key.clone(),
                    status: AdminState::Unknown,
                    post_state_digest: String::new(),
                    provider_receipts: BTreeMap::new(),
                    error_detail: Some(error.to_string()),
                    completed_at_secs: now,
                };
                match persist_result(&result) {
                    Ok(lsn) => {
                        self.record_completion(
                            &op.idempotency_key,
                            digest,
                            AdminState::Unknown,
                            intent_lsn,
                            Some(lsn),
                        );
                    }
                    Err(_) => self.mark_unknown(&op.idempotency_key),
                }
                Err(AdminError::UnknownState(error.to_string()))
            }
        }
    }

    pub fn record_completion(
        &self,
        idempotency_key: &str,
        intent_digest: String,
        state: AdminState,
        intent_lsn: Lsn,
        result_lsn: Option<Lsn>,
    ) {
        self.active_operations.write().unwrap().remove(idempotency_key);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.idempotency_map.lock().unwrap().insert(
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

    pub fn recover_intent(&self, lsn: Lsn, intent: &AdminIntent) {
        self.idempotency_map.lock().unwrap().insert(
            intent.idempotency_key.clone(),
            IdempotencyEntry {
                intent_digest: intent.intent_digest.clone(),
                state: AdminState::Unknown,
                intent_lsn: lsn,
                result_lsn: None,
                completed_at_secs: None,
            },
        );
        self.active_operations
            .write()
            .unwrap()
            .insert(intent.idempotency_key.clone(), AdminState::Unknown);
    }

    pub fn recover_result(&self, lsn: Lsn, result: &AdminResult) {
        let mut map = self.idempotency_map.lock().unwrap();
        if let Some(entry) = map.get_mut(&result.idempotency_key) {
            entry.state = result.status;
            entry.result_lsn = Some(lsn);
            entry.completed_at_secs = Some(result.completed_at_secs);
        }
        drop(map);
        if matches!(
            result.status,
            AdminState::Succeeded | AdminState::Failed | AdminState::Reconciled
        ) {
            self.active_operations
                .write()
                .unwrap()
                .remove(&result.idempotency_key);
        } else {
            self.active_operations
                .write()
                .unwrap()
                .insert(result.idempotency_key.clone(), result.status);
        }
    }

    pub fn query_idempotency(
        &self,
        idempotency_key: &str,
    ) -> Option<(AdminState, Lsn, Option<Lsn>, Option<u64>)> {
        self.idempotency_map.lock().unwrap().get(idempotency_key).map(|e| {
            (
                e.state,
                e.intent_lsn,
                e.result_lsn,
                e.completed_at_secs,
            )
        })
    }

    pub fn get_operation_state(&self, idempotency_key: &str) -> Option<AdminState> {
        if let Some(state) = self.active_operations.read().unwrap().get(idempotency_key) {
            return Some(*state);
        }
        self.idempotency_map
            .lock()
            .unwrap()
            .get(idempotency_key)
            .map(|e| e.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestApprovalVerifier;
    impl ApprovalVerifier for TestApprovalVerifier {
        fn verify(
            &self,
            _requester: &AdminContext,
            approval: &ApprovalRecord,
            intent_digest: &str,
        ) -> Result<(), String> {
            if approval.signature.as_deref() == Some("verified")
                && approval.approved_intent_digest == intent_digest
            {
                Ok(())
            } else {
                Err("aprovação não autenticada".into())
            }
        }
    }

    #[test]
    fn digest_binds_parameters_and_has_length_framing() {
        let ctx = AdminContext::new("alice", "tenant", vec!["admin".into()]);
        let mut a = AdminOperation::new(
            "ab",
            "c",
            AdminOperationKind::Custom {
                name: "x".into(),
                details: "y".into(),
            },
            "reason",
        );
        let mut b = AdminOperation::new(
            "a",
            "bc",
            a.kind.clone(),
            "reason",
        );
        a.parameters_digest = "p1".into();
        b.parameters_digest = "p1".into();
        assert_ne!(a.compute_intent_digest(&ctx), b.compute_intent_digest(&ctx));

        let d1 = a.compute_intent_digest(&ctx);
        a.parameters_digest = "p2".into();
        assert_ne!(d1, a.compute_intent_digest(&ctx));
    }

    #[test]
    fn reader_cannot_validate_privileged_operation() {
        let protocol = TrustedAdminProtocol::new();
        let ctx = AdminContext::new("reader", "tenant", vec!["reader".into()]);
        let op = AdminOperation::new(
            "op",
            "idem",
            AdminOperationKind::CryptoShred {
                agent_id: "a".into(),
            },
            "test",
        );
        assert!(matches!(
            protocol.validate(&ctx, &op),
            Err(AdminError::AccessDenied(_))
        ));
    }

    #[test]
    fn four_eyes_requires_authenticated_approvals() {
        let protocol = TrustedAdminProtocol::new();
        protocol.set_approval_verifier(Arc::new(TestApprovalVerifier));
        let ctx = AdminContext::new("alice", "tenant-gov", vec!["admin".into()]);
        let mut op = AdminOperation::new(
            "op-shred-01",
            "idem-shred-01",
            AdminOperationKind::CryptoShred {
                agent_id: "agent-x".into(),
            },
            "LGPD Right to erasure",
        );
        op.approval_policy = Some(ApprovalPolicy::strict_four_eyes("security_officer"));
        let digest = op.compute_intent_digest(&ctx);
        for who in ["bob", "carol"] {
            op.approvals.push(ApprovalRecord {
                approver_principal: who.into(),
                approver_role: "security_officer".into(),
                approved_intent_digest: digest.clone(),
                approved_at_secs: 100,
                signature: Some("verified".into()),
            });
        }
        assert!(protocol.validate(&ctx, &op).is_ok());
    }

    #[test]
    fn execute_orders_intent_before_effect_and_result_after() {
        let protocol = TrustedAdminProtocol::new();
        let ctx = AdminContext::new("alice", "tenant", vec!["admin".into()]);
        let op = AdminOperation::new(
            "op-1",
            "idem-1",
            AdminOperationKind::Custom {
                name: "test".into(),
                details: "x".into(),
            },
            "test",
        );
        let order = Mutex::new(Vec::new());

        let out = protocol
            .execute_admin(
                &ctx,
                &op,
                |_| {
                    order.lock().unwrap().push("intent");
                    Ok(10)
                },
                |token| {
                    assert_eq!(token.intent_lsn(), 10);
                    order.lock().unwrap().push("effect");
                    Ok((42u64, "post".into(), BTreeMap::new()))
                },
                |_| {
                    order.lock().unwrap().push("result");
                    Ok(11)
                },
            )
            .unwrap();

        assert_eq!(out.value, 42);
        assert_eq!(*order.lock().unwrap(), vec!["intent", "effect", "result"]);
        assert_eq!(
            protocol.get_operation_state("idem-1"),
            Some(AdminState::Succeeded)
        );
    }

    #[test]
    fn recovery_marks_intent_without_result_unknown() {
        let protocol = TrustedAdminProtocol::new();
        let intent = AdminIntent {
            operation_id: "op".into(),
            idempotency_key: "idem".into(),
            intent_digest: "digest".into(),
            principal: "alice".into(),
            tenant: "tenant".into(),
            kind: AdminOperationKind::Custom {
                name: "x".into(),
                details: "y".into(),
            },
            target_digest: "target".into(),
            parameters_digest: "params".into(),
            reason: "reason".into(),
            approval_policy: None,
            requested_at_secs: 1,
            approver_count: 0,
        };
        protocol.recover_intent(7, &intent);
        assert_eq!(
            protocol.get_operation_state("idem"),
            Some(AdminState::Unknown)
        );
    }

    #[test]
    fn intent_persistence_failure_never_runs_side_effect_and_releases_reservation() {
        let protocol = TrustedAdminProtocol::new();
        let ctx = AdminContext::new("alice", "tenant", vec!["admin".into()]);
        let op = AdminOperation::new(
            "op-intent-fail",
            "idem-intent-fail",
            AdminOperationKind::Custom {
                name: "test".into(),
                details: "intent fail".into(),
            },
            "test",
        );
        let effect_ran = std::sync::atomic::AtomicBool::new(false);

        let result = protocol.execute_admin(
            &ctx,
            &op,
            |_| Err(AdminError::IntentPersistenceFailed("disk offline".into())),
            |_| {
                effect_ran.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(((), String::new(), BTreeMap::new()))
            },
            |_| Ok(2),
        );

        assert!(matches!(result, Err(AdminError::IntentPersistenceFailed(_))));
        assert!(!effect_ran.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(protocol.get_operation_state("idem-intent-fail"), None);
    }

    #[test]
    fn result_persistence_failure_marks_operation_unknown_and_blocks_replay() {
        let protocol = TrustedAdminProtocol::new();
        let ctx = AdminContext::new("alice", "tenant", vec!["admin".into()]);
        let op = AdminOperation::new(
            "op-result-fail",
            "idem-result-fail",
            AdminOperationKind::Custom {
                name: "test".into(),
                details: "result fail".into(),
            },
            "test",
        );

        let result = protocol.execute_admin(
            &ctx,
            &op,
            |_| Ok(41),
            |_| Ok((7u64, "post".into(), BTreeMap::new())),
            |_| Err(AdminError::ResultPersistenceFailed("disk offline".into())),
        );
        assert!(matches!(result, Err(AdminError::UnknownState(_))));
        assert_eq!(
            protocol.get_operation_state("idem-result-fail"),
            Some(AdminState::Unknown)
        );

        let replay = protocol.execute_admin(
            &ctx,
            &op,
            |_| Ok(42),
            |_| Ok((8u64, "post-2".into(), BTreeMap::new())),
            |_| Ok(43),
        );
        assert!(matches!(replay, Err(AdminError::AlreadyProcessed(_))));
    }

    #[test]
    fn idempotency_key_cannot_be_reused_for_different_intent() {
        let protocol = TrustedAdminProtocol::new();
        let ctx = AdminContext::new("alice", "tenant", vec!["admin".into()]);
        let mut first = AdminOperation::new(
            "op-a",
            "same-key",
            AdminOperationKind::Custom {
                name: "test".into(),
                details: "a".into(),
            },
            "test",
        );
        first.parameters_digest = "params-a".into();

        protocol
            .execute_admin(
                &ctx,
                &first,
                |_| Ok(1),
                |_| Ok(((), "post".into(), BTreeMap::new())),
                |_| Ok(2),
            )
            .unwrap();

        let mut second = AdminOperation::new(
            "op-b",
            "same-key",
            AdminOperationKind::Custom {
                name: "test".into(),
                details: "b".into(),
            },
            "test",
        );
        second.parameters_digest = "params-b".into();

        assert!(matches!(
            protocol.validate(&ctx, &second),
            Err(AdminError::IdempotencyConflict { .. })
        ));
    }

}
