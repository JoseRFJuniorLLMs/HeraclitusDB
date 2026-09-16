//! SPEC-0075 §6, §14–§16, §26 — acção, autorização ligada ao conteúdo e
//! aprovação humana.
//!
//! # A invariante central
//!
//! > Uma aprovação para `send_payment(amount=5000, account=A)` **não** autoriza
//! > `send_payment(amount=50000, account=B)` (§2.3).
//!
//! Isto não é uma verificação que se faz "com cuidado" no sítio certo: é um
//! **hash do assunto** calculado antes de pedir a aprovação e reconferido antes
//! de executar. Se qualquer coisa que importa mudar — ferramenta, servidor,
//! argumentos, agente, humano ou policy — o hash muda e a autorização
//! deixa de valer. A validade temporal é verificada separadamente pelo lifecycle
//! da aprovação e pela autorização apresentada; não faz parte da identidade do
//! assunto. Não há caminho no código que execute sem ambas as verificações.
//!
//! # Single-use e expiração
//!
//! Uma aprovação vale para **uma** execução (§15.3) e expira (§15.1). As duas
//! coisas existem pelo mesmo motivo: uma aprovação reutilizável é uma
//! credencial, e uma credencial sem prazo é uma credencial permanente que
//! ninguém emitiu de propósito.

use crate::canonical::{domain_hash, hex32, CanonicalWriter, DOMAIN_AUTHZ_SUBJECT};
use crate::policy::PolicyValueV1;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Força da autenticação com que o principal chegou.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStrengthV1 {
    /// Nenhuma: só aceitável no perfil de desenvolvimento em loopback.
    #[default]
    None,
    /// Segredo partilhado local (perfil DEV_LOCAL).
    LocalKey,
    /// Token OIDC/JWT validado.
    Oidc,
    /// Identidade de carga de trabalho (mTLS, SPIFFE).
    Workload,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPrincipalV1 {
    pub subject: String,
    pub issuer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    #[serde(default)]
    pub auth_strength: AuthStrengthV1,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanPrincipalV1 {
    pub subject: String,
    pub issuer: String,
    /// Só são de confiança **dentro do issuer configurado** (§7.2).
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationContextV1 {
    pub delegation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_subject: Option<String>,
    pub agent_subject: String,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Impressão digital da credencial de origem. **Nunca a credencial** (§7.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_credential_fingerprint: Option<String>,
}

impl DelegationContextV1 {
    pub fn is_valid_at(&self, now_unix_seconds: u64) -> bool {
        self.issued_at <= now_unix_seconds && now_unix_seconds < self.expires_at
    }
}

/// A ferramenta como recurso (§10).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResourceV1 {
    pub protocol: String,
    pub server_id: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
}

impl ToolResourceV1 {
    /// `mcp://finance/send_payment` — a identidade conceptual de §10.
    pub fn resource_id(&self) -> String {
        format!("{}://{}/{}", self.protocol, self.server_id, self.tool_name)
    }
}

/// O pedido de acção (§6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentActionRequestV1 {
    /// Idempotência: o mesmo `request_id` com os mesmos argumentos não cria
    /// nova aprovação nem executa duas vezes (§26).
    pub request_id: String,
    pub tenant_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    pub agent: AgentPrincipalV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human: Option<HumanPrincipalV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DelegationContextV1>,

    pub resource: ToolResourceV1,
    pub action: String,

    /// Hash canónico dos argumentos efectivos. A policy pode nunca ver os
    /// argumentos; este hash é o que os liga à aprovação.
    pub argument_digest: String,
    /// Os campos explicitamente permitidos para decisão (§6).
    #[serde(default)]
    pub arguments_for_policy: BTreeMap<String, PolicyValueV1>,

    pub requested_at_unix_nanos: u64,
}

/// A autorização emitida (§14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionAuthorizationV1 {
    pub authorization_id: String,
    /// Stable logical request identity. Same id means retry; a new id means a new operation.
    #[serde(default)]
    pub request_id: String,

    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub rule_id: String,

    pub agent_subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_subject: Option<String>,

    pub resource_id: String,
    pub action: String,
    pub argument_digest: String,

    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

impl ActionAuthorizationV1 {
    /// O hash do **assunto** da autorização.
    ///
    /// Binding estável da SPEC-0078 §3: ferramenta/servidor, argumentos,
    /// agente, humano e policy identificam o assunto aprovado. `issued_at`,
    /// `expires_at`, `authorization_id` e `nonce` NÃO entram: são lifecycle e
    /// envelope efémero. Expiração continua obrigatória em `ApprovalStore` e
    /// `is_valid_at`, mas um retry um segundo depois não muda o que o humano
    /// aprovou.
    pub fn subject_hash(&self) -> String {
        let mut w = CanonicalWriter::new();
        w.str(&self.policy_id);
        w.str(&self.policy_version);
        w.str(&self.policy_hash);
        w.str(&self.rule_id);
        w.str(&self.request_id);
        w.str(&self.agent_subject);
        w.opt_str(self.human_subject.as_deref());
        w.str(&self.resource_id);
        w.str(&self.action);
        w.str(&self.argument_digest);
        hex32(&domain_hash(DOMAIN_AUTHZ_SUBJECT, w.as_slice()))
    }

    pub fn is_valid_at(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds < self.expires_at
    }
}

/// Hash canónico de um conjunto de argumentos.
///
/// `BTreeMap` garante a ordem; o prefixo de comprimento garante que
/// `{"ab":"c"}` e `{"a":"bc"}` não colidem.
pub fn argument_digest(args: &BTreeMap<String, String>) -> String {
    let mut w = CanonicalWriter::new();
    w.map(args);
    hex32(&crate::canonical::content_hash(w.as_slice()))
}

/// Pedido de aprovação (§15.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequestV1 {
    pub approval_id: String,
    /// Logical request identity kept explicitly for mutation/replay discrimination.
    #[serde(default)]
    pub request_id: String,
    pub authorization_subject_hash: String,
    pub requested_roles: Vec<String>,
    pub reason: String,
    pub preview: ApprovalPreviewV1,
    pub requested_at: u64,
    pub expires_at: u64,
}

/// O que a pessoa vê antes de decidir (§34). Passa pelo portão de privacidade
/// como tudo o resto: um preview não é uma excepção à redacção.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPreviewV1 {
    pub agent: String,
    pub tool: String,
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    pub argument_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_rule: Option<String>,
}

/// A decisão humana (§15.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecisionV1 {
    pub approval_id: String,
    pub approver_subject: String,
    pub approver_issuer: String,
    pub approved: bool,
    /// Repetido de propósito: a decisão declara a que assunto se refere, para
    /// que uma decisão não possa ser colada noutro pedido.
    pub authorization_subject_hash: String,
    pub decided_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Estado de uma aprovação no registo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Granted,
    Denied,
    Expired,
    /// Já foi usada para executar. Uma segunda tentativa falha (§15.3).
    Consumed,
}

/// Entrada do registo de aprovações.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub request: ApprovalRequestV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<ApprovalDecisionV1>,
    pub state: ApprovalState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<ActionAuthorizationV1>,
}

/// Porque é que uma tentativa de executar foi recusada.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ApprovalVerdict {
    /// Pode executar. Consome a aprovação.
    Authorized {
        approval_id: String,
    },
    /// Ainda não há decisão humana.
    Pending {
        approval_id: String,
    },
    NotFound,
    Denied {
        approval_id: String,
    },
    Expired {
        approval_id: String,
    },
    /// Já foi usada (§15.3).
    AlreadyUsed {
        approval_id: String,
    },
    /// O assunto mudou depois da aprovação — o caso de §32.
    BindingMismatch {
        approval_id: String,
        approved_subject_hash: String,
        presented_subject_hash: String,
    },
}

impl ApprovalVerdict {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Authorized { .. } => "APPROVED",
            Self::Pending { .. } => "APPROVAL_PENDING",
            Self::NotFound => "APPROVAL_NOT_FOUND",
            Self::Denied { .. } => "APPROVAL_DENIED",
            Self::Expired { .. } => "APPROVAL_EXPIRED",
            Self::AlreadyUsed { .. } => "APPROVAL_REPLAYED",
            Self::BindingMismatch { .. } => "APPROVAL_BINDING_MISMATCH",
        }
    }
    pub fn allows_execution(&self) -> bool {
        matches!(self, Self::Authorized { .. })
    }
}

/// Registo de aprovações em memória, com expiração explícita.
///
/// # Porque em memória, e o que isso significa
///
/// A verdade durável é o HRKL: cada `HumanApprovalRequested`,
/// `HumanApprovalGranted` e `HumanApprovalDenied` é uma evidência append-only.
/// Este registo é o índice vivo que o gateway consulta no caminho quente e
/// reconstrói no arranque a partir do log ([`ApprovalStore::warm`]).
///
/// A consequência honesta: uma aprovação concedida e **não consumida** antes de
/// um crash volta a ficar pendente depois do reinício. É o lado seguro do
/// trade-off — a alternativa seria reconstruir "consumida" a partir de um facto
/// que pode não ter chegado ao log (§33, a matriz de caos).
#[derive(Debug, Default)]
pub struct ApprovalStore {
    inner: Mutex<BTreeMap<String, ApprovalRecord>>,
    /// Assuntos já consumidos reconstruídos do HRKL. Separado dos records
    /// vivos porque uma execução antiga não precisa de preview/TTL para ser
    /// reconhecida como replay, apenas do subject hash e approval id.
    consumed_subjects: Mutex<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalAdmissionError {
    GlobalLimit { limit: usize },
    PerAgentLimit { agent: String, limit: usize },
}

impl std::fmt::Display for ApprovalAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GlobalLimit { limit } => {
                write!(f, "global pending approval limit reached ({limit})")
            }
            Self::PerAgentLimit { agent, limit } => {
                write!(
                    f,
                    "pending approval limit reached for agent `{agent}` ({limit})"
                )
            }
        }
    }
}

impl ApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Regista um pedido novo. Se já existir um pedido pendente para o mesmo
    /// assunto, devolve-o em vez de criar outro (§26: um retry não cria uma
    /// segunda aprovação).
    pub fn request(&self, req: ApprovalRequestV1, now: u64) -> ApprovalRequestV1 {
        self.request_bounded(req, now, usize::MAX, usize::MAX)
            .expect("unbounded approval admission cannot hit a capacity limit")
    }

    /// SPEC-0085: duplicate detection and capacity admission are one critical
    /// section, so a concurrent swarm cannot race past either ceiling. Exact
    /// retries are checked first and therefore consume no extra capacity.
    pub fn request_bounded(
        &self,
        req: ApprovalRequestV1,
        now: u64,
        max_pending_global: usize,
        max_pending_per_agent: usize,
    ) -> Result<ApprovalRequestV1, ApprovalAdmissionError> {
        let mut map = self.inner.lock().unwrap();
        expire_locked(&mut map, now);
        if let Some(existing) = map.values().find(|r| {
            r.state == ApprovalState::Pending
                && r.request.authorization_subject_hash == req.authorization_subject_hash
        }) {
            return Ok(existing.request.clone());
        }

        let pending_global = map
            .values()
            .filter(|r| r.state == ApprovalState::Pending)
            .count();
        if pending_global >= max_pending_global {
            return Err(ApprovalAdmissionError::GlobalLimit {
                limit: max_pending_global,
            });
        }

        let agent = req.preview.agent.clone();
        let pending_agent = map
            .values()
            .filter(|r| r.state == ApprovalState::Pending && r.request.preview.agent == agent)
            .count();
        if pending_agent >= max_pending_per_agent {
            return Err(ApprovalAdmissionError::PerAgentLimit {
                agent,
                limit: max_pending_per_agent,
            });
        }

        let out = req.clone();
        map.insert(
            req.approval_id.clone(),
            ApprovalRecord {
                request: req,
                decision: None,
                state: ApprovalState::Pending,
                authorization: None,
            },
        );
        Ok(out)
    }

    /// Aplica uma decisão humana. Recusa decidir o que já foi decidido.
    pub fn decide(
        &self,
        decision: ApprovalDecisionV1,
        now: u64,
    ) -> Result<ApprovalRecord, ApprovalVerdict> {
        let mut map = self.inner.lock().unwrap();
        expire_locked(&mut map, now);
        let Some(record) = map.get_mut(&decision.approval_id) else {
            return Err(ApprovalVerdict::NotFound);
        };
        match record.state {
            ApprovalState::Pending => {}
            ApprovalState::Expired => {
                return Err(ApprovalVerdict::Expired {
                    approval_id: decision.approval_id.clone(),
                })
            }
            _ => {
                return Err(ApprovalVerdict::AlreadyUsed {
                    approval_id: decision.approval_id.clone(),
                })
            }
        }
        // Uma decisão tem de se referir ao assunto que foi apresentado. Sem
        // isto, um `approve` legítimo podia ser reencaminhado para outro pedido.
        if decision.authorization_subject_hash != record.request.authorization_subject_hash {
            return Err(ApprovalVerdict::BindingMismatch {
                approval_id: decision.approval_id.clone(),
                approved_subject_hash: record.request.authorization_subject_hash.clone(),
                presented_subject_hash: decision.authorization_subject_hash.clone(),
            });
        }
        record.state = if decision.approved {
            ApprovalState::Granted
        } else {
            ApprovalState::Denied
        };
        record.decision = Some(decision);
        Ok(record.clone())
    }

    /// Tenta consumir uma aprovação para executar `authorization`.
    ///
    /// É aqui que a invariante de §2.3 se torna mecânica: o hash apresentado é
    /// recalculado a partir da autorização que está prestes a ser executada, e
    /// comparado com o que foi aprovado.
    pub fn consume(&self, authorization: &ActionAuthorizationV1, now: u64) -> ApprovalVerdict {
        let presented = authorization.subject_hash();
        let mut map = self.inner.lock().unwrap();
        expire_locked(&mut map, now);
        let Some((id, record)) = map
            .iter_mut()
            .find(|(_, r)| r.request.authorization_subject_hash == presented)
            .map(|(k, v)| (k.clone(), v))
        else {
            if let Some(approval_id) = self
                .consumed_subjects
                .lock()
                .unwrap()
                .get(&presented)
                .cloned()
            {
                return ApprovalVerdict::AlreadyUsed { approval_id };
            }
            // Binding mismatch belongs to the same logical request only. A grant
            // for an unrelated request must never poison a new operation.
            let same_request = if authorization.request_id.is_empty() {
                None
            } else {
                map.values()
                    .find(|r| {
                        !r.request.request_id.is_empty()
                            && r.request.request_id == authorization.request_id
                    })
                    .map(|r| r.request.clone())
            };
            return match same_request {
                Some(r) => ApprovalVerdict::BindingMismatch {
                    approval_id: r.approval_id,
                    approved_subject_hash: r.authorization_subject_hash,
                    presented_subject_hash: presented,
                },
                None => ApprovalVerdict::NotFound,
            };
        };
        match record.state {
            ApprovalState::Pending => ApprovalVerdict::Pending { approval_id: id },
            ApprovalState::Denied => ApprovalVerdict::Denied { approval_id: id },
            ApprovalState::Expired => ApprovalVerdict::Expired { approval_id: id },
            ApprovalState::Consumed => ApprovalVerdict::AlreadyUsed { approval_id: id },
            ApprovalState::Granted => {
                if !authorization.is_valid_at(now) {
                    record.state = ApprovalState::Expired;
                    return ApprovalVerdict::Expired { approval_id: id };
                }
                record.state = ApprovalState::Consumed;
                record.authorization = Some(authorization.clone());
                self.consumed_subjects
                    .lock()
                    .unwrap()
                    .insert(presented, id.clone());
                ApprovalVerdict::Authorized { approval_id: id }
            }
        }
    }

    pub fn get(&self, approval_id: &str) -> Option<ApprovalRecord> {
        self.inner.lock().unwrap().get(approval_id).cloned()
    }

    /// Pendentes, por ordem de expiração — o que a caixa de entrada mostra.
    pub fn pending(&self, now: u64) -> Vec<ApprovalRecord> {
        let mut map = self.inner.lock().unwrap();
        expire_locked(&mut map, now);
        let mut out: Vec<ApprovalRecord> = map
            .values()
            .filter(|r| r.state == ApprovalState::Pending)
            .cloned()
            .collect();
        out.sort_by_key(|r| r.request.expires_at);
        out
    }

    pub fn all(&self) -> Vec<ApprovalRecord> {
        self.inner.lock().unwrap().values().cloned().collect()
    }

    /// Reconstrói o ledger mínimo de approvals já consumidos.
    /// Chamado no arranque a partir de evidências `ToolAuthorized` duráveis.
    pub fn warm_consumed(&self, records: impl IntoIterator<Item = (String, String)>) {
        let mut consumed = self.consumed_subjects.lock().unwrap();
        for (subject_hash, approval_id) in records {
            consumed.insert(subject_hash, approval_id);
        }
    }

    /// Reconstrói o índice a partir de registos já persistidos.
    pub fn warm(&self, records: impl IntoIterator<Item = ApprovalRecord>) {
        let mut map = self.inner.lock().unwrap();
        for r in records {
            map.insert(r.request.approval_id.clone(), r);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn expire_locked(map: &mut BTreeMap<String, ApprovalRecord>, now: u64) {
    for r in map.values_mut() {
        if matches!(r.state, ApprovalState::Pending | ApprovalState::Granted)
            && now >= r.request.expires_at
        {
            r.state = ApprovalState::Expired;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authz(amount: &str) -> ActionAuthorizationV1 {
        let mut args = BTreeMap::new();
        args.insert("amount".to_string(), amount.to_string());
        args.insert("account".to_string(), "A".to_string());
        ActionAuthorizationV1 {
            authorization_id: "AZ-1".into(),
            request_id: "request-1".into(),
            policy_id: "agent-policy".into(),
            policy_version: "v17".into(),
            policy_hash: "hash".into(),
            rule_id: "finance-large".into(),
            agent_subject: "procurement-agent".into(),
            human_subject: Some("jose".into()),
            resource_id: "mcp://finance/send_payment".into(),
            action: "send_payment".into(),
            argument_digest: argument_digest(&args),
            issued_at: 100,
            expires_at: 400,
            nonce: "n1".into(),
        }
    }

    #[test]
    fn o_binding_do_assunto_nao_depende_do_relogio_ou_envelope() {
        let a = authz("5000");
        let mut retry = a.clone();
        retry.authorization_id = "AZ-2".into();
        retry.nonce = "n2".into();
        retry.issued_at = 250;
        retry.expires_at = 900;
        assert_eq!(a.subject_hash(), retry.subject_hash());
    }

    #[test]
    fn request_id_novo_define_operacao_logica_nova() {
        let a = authz("5000");
        let mut nova = a.clone();
        nova.request_id = "request-2".into();
        nova.authorization_id = "AZ-2".into();
        nova.nonce = "n2".into();
        assert_ne!(a.subject_hash(), nova.subject_hash());
    }

    #[test]
    fn replay_consumido_reconstruido_do_log_continua_bloqueado() {
        let store = ApprovalStore::new();
        let a = authz("5000");
        store.warm_consumed([(a.subject_hash(), "A-durable".to_string())]);
        assert!(matches!(
            store.consume(&a, 200),
            ApprovalVerdict::AlreadyUsed { approval_id } if approval_id == "A-durable"
        ));
    }

    #[test]
    fn operacao_identica_nova_pode_pedir_nova_aprovacao_apos_consumo() {
        let store = ApprovalStore::new();
        let primeira = authz("5000");
        store.request(request_for(&primeira, 400), 100);
        grant(&store, &primeira, 150);
        assert!(store.consume(&primeira, 200).allows_execution());
        let mut nova = primeira.clone();
        nova.request_id = "request-2".into();
        nova.authorization_id = "AZ-2".into();
        nova.nonce = "n2".into();
        assert!(matches!(
            store.consume(&nova, 210),
            ApprovalVerdict::NotFound
        ));
        let mut pedido = request_for(&nova, 500);
        pedido.approval_id = "A-772".into();
        assert_eq!(store.request(pedido, 210).approval_id, "A-772");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn granted_de_outro_request_nao_envenena_operacao_nova() {
        let store = ApprovalStore::new();
        let primeira = authz("5000");
        store.request(request_for(&primeira, 400), 100);
        grant(&store, &primeira, 150);
        let mut outra = authz("5001");
        outra.request_id = "request-2".into();
        assert!(matches!(
            store.consume(&outra, 160),
            ApprovalVerdict::NotFound
        ));
    }

    #[test]
    fn mesmo_request_id_mutado_continua_binding_mismatch() {
        let store = ApprovalStore::new();
        let aprovado = authz("5000");
        store.request(request_for(&aprovado, 400), 100);
        grant(&store, &aprovado, 150);
        let mut mutado = authz("5001");
        mutado.request_id = aprovado.request_id.clone();
        assert!(matches!(
            store.consume(&mutado, 160),
            ApprovalVerdict::BindingMismatch { .. }
        ));
    }

    #[test]
    fn uma_aprovacao_exata_sobrevive_a_mudanca_de_segundo_sem_estender_o_ttl() {
        let store = ApprovalStore::new();
        let original = authz("5000");
        store.request(request_for(&original, 400), 100);
        grant(&store, &original, 150);

        let mut retry = original.clone();
        retry.authorization_id = "AZ-retry".into();
        retry.nonce = "retry-nonce".into();
        retry.issued_at = 250;
        retry.expires_at = 550;
        assert_eq!(original.subject_hash(), retry.subject_hash());
        assert!(store.consume(&retry, 250).allows_execution());
    }

    fn request_for(a: &ActionAuthorizationV1, expires: u64) -> ApprovalRequestV1 {
        ApprovalRequestV1 {
            approval_id: "A-771".into(),
            request_id: a.request_id.clone(),
            authorization_subject_hash: a.subject_hash(),
            requested_roles: vec!["cfo".into()],
            reason: "pagamento acima de 50.000".into(),
            preview: ApprovalPreviewV1::default(),
            requested_at: 100,
            expires_at: expires,
        }
    }

    fn grant(store: &ApprovalStore, a: &ActionAuthorizationV1, now: u64) {
        store
            .decide(
                ApprovalDecisionV1 {
                    approval_id: "A-771".into(),
                    approver_subject: "cfo".into(),
                    approver_issuer: "https://id.example".into(),
                    approved: true,
                    authorization_subject_hash: a.subject_hash(),
                    decided_at: now,
                    comment: None,
                },
                now,
            )
            .unwrap();
    }

    #[test]
    fn aprovar_5000_e_executar_5001_e_binding_mismatch() {
        // §32: o teste obrigatório.
        let store = ApprovalStore::new();
        let aprovado = authz("5000");
        store.request(request_for(&aprovado, 400), 100);
        grant(&store, &aprovado, 150);

        let mutado = authz("5001");
        let verdict = store.consume(&mutado, 200);
        assert!(
            matches!(verdict, ApprovalVerdict::BindingMismatch { .. }),
            "{verdict:?}"
        );
        assert_eq!(verdict.reason_code(), "APPROVAL_BINDING_MISMATCH");
        assert!(!verdict.allows_execution());
    }

    #[test]
    fn mudar_a_conta_tambem_invalida() {
        let store = ApprovalStore::new();
        let aprovado = authz("5000");
        store.request(request_for(&aprovado, 400), 100);
        grant(&store, &aprovado, 150);

        let mut outro = authz("5000");
        let mut args = BTreeMap::new();
        args.insert("amount".to_string(), "5000".to_string());
        args.insert("account".to_string(), "B".to_string());
        outro.argument_digest = argument_digest(&args);
        assert!(matches!(
            store.consume(&outro, 200),
            ApprovalVerdict::BindingMismatch { .. }
        ));
    }

    #[test]
    fn mudar_a_ferramenta_invalida() {
        let store = ApprovalStore::new();
        let a = authz("5000");
        store.request(request_for(&a, 400), 100);
        grant(&store, &a, 150);
        let mut outra = a.clone();
        outra.resource_id = "mcp://finance/refund".into();
        assert!(matches!(
            store.consume(&outra, 200),
            ApprovalVerdict::BindingMismatch { .. }
        ));
    }

    #[test]
    fn mudar_o_agente_invalida() {
        let store = ApprovalStore::new();
        let a = authz("5000");
        store.request(request_for(&a, 400), 100);
        grant(&store, &a, 150);
        let mut outro = a.clone();
        outro.agent_subject = "outro-agente".into();
        assert!(matches!(
            store.consume(&outro, 200),
            ApprovalVerdict::BindingMismatch { .. }
        ));
    }

    #[test]
    fn mudar_a_policy_invalida() {
        let store = ApprovalStore::new();
        let a = authz("5000");
        store.request(request_for(&a, 400), 100);
        grant(&store, &a, 150);
        let mut outra = a.clone();
        outra.policy_hash = "outro-hash".into();
        assert!(matches!(
            store.consume(&outra, 200),
            ApprovalVerdict::BindingMismatch { .. }
        ));
    }

    #[test]
    fn a_aprovacao_e_de_uso_unico() {
        let store = ApprovalStore::new();
        let a = authz("5000");
        store.request(request_for(&a, 400), 100);
        grant(&store, &a, 150);
        assert!(store.consume(&a, 200).allows_execution());
        let segunda = store.consume(&a, 210);
        assert!(matches!(segunda, ApprovalVerdict::AlreadyUsed { .. }));
        assert_eq!(segunda.reason_code(), "APPROVAL_REPLAYED");
    }

    #[test]
    fn a_aprovacao_expira() {
        let store = ApprovalStore::new();
        let a = authz("5000");
        store.request(request_for(&a, 300), 100);
        grant(&store, &a, 150);
        let v = store.consume(&a, 301);
        assert!(matches!(v, ApprovalVerdict::Expired { .. }), "{v:?}");
    }

    #[test]
    fn a_autorizacao_expirada_nao_executa_mesmo_com_aprovacao_viva() {
        let store = ApprovalStore::new();
        let mut a = authz("5000");
        a.expires_at = 180;
        store.request(request_for(&a, 999), 100);
        grant(&store, &a, 150);
        assert!(matches!(
            store.consume(&a, 200),
            ApprovalVerdict::Expired { .. }
        ));
    }

    #[test]
    fn negada_nunca_executa() {
        let store = ApprovalStore::new();
        let a = authz("5000");
        store.request(request_for(&a, 400), 100);
        store
            .decide(
                ApprovalDecisionV1 {
                    approval_id: "A-771".into(),
                    approver_subject: "cfo".into(),
                    approver_issuer: "i".into(),
                    approved: false,
                    authorization_subject_hash: a.subject_hash(),
                    decided_at: 150,
                    comment: None,
                },
                150,
            )
            .unwrap();
        assert!(matches!(
            store.consume(&a, 200),
            ApprovalVerdict::Denied { .. }
        ));
    }

    #[test]
    fn pendente_nao_executa() {
        let store = ApprovalStore::new();
        let a = authz("5000");
        store.request(request_for(&a, 400), 100);
        assert!(matches!(
            store.consume(&a, 120),
            ApprovalVerdict::Pending { .. }
        ));
    }

    #[test]
    fn retry_nao_cria_segunda_aprovacao() {
        let store = ApprovalStore::new();
        let a = authz("5000");
        let primeira = store.request(request_for(&a, 400), 100);
        let mut segunda_req = request_for(&a, 400);
        segunda_req.approval_id = "A-999".into();
        let segunda = store.request(segunda_req, 110);
        assert_eq!(primeira.approval_id, segunda.approval_id);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn decidir_com_o_assunto_errado_e_recusado() {
        let store = ApprovalStore::new();
        let a = authz("5000");
        store.request(request_for(&a, 400), 100);
        let err = store
            .decide(
                ApprovalDecisionV1 {
                    approval_id: "A-771".into(),
                    approver_subject: "cfo".into(),
                    approver_issuer: "i".into(),
                    approved: true,
                    authorization_subject_hash: "outro".into(),
                    decided_at: 150,
                    comment: None,
                },
                150,
            )
            .unwrap_err();
        assert!(matches!(err, ApprovalVerdict::BindingMismatch { .. }));
    }

    #[test]
    fn o_digest_dos_argumentos_nao_depende_da_ordem() {
        let mut a = BTreeMap::new();
        a.insert("amount".to_string(), "1".to_string());
        a.insert("account".to_string(), "A".to_string());
        let mut b = BTreeMap::new();
        b.insert("account".to_string(), "A".to_string());
        b.insert("amount".to_string(), "1".to_string());
        assert_eq!(argument_digest(&a), argument_digest(&b));
    }

    #[test]
    fn o_digest_distingue_concatenacoes() {
        let mut a = BTreeMap::new();
        a.insert("k".to_string(), "ab".to_string());
        let mut b = BTreeMap::new();
        b.insert("ka".to_string(), "b".to_string());
        assert_ne!(argument_digest(&a), argument_digest(&b));
    }

    #[test]
    fn a_delegacao_expira() {
        let d = DelegationContextV1 {
            delegation_id: "D1".into(),
            agent_subject: "a".into(),
            issued_at: 100,
            expires_at: 200,
            ..Default::default()
        };
        assert!(d.is_valid_at(150));
        assert!(!d.is_valid_at(200));
        assert!(!d.is_valid_at(99));
    }

    #[test]
    fn o_resource_id_segue_a_forma_da_spec() {
        let r = ToolResourceV1 {
            protocol: "mcp".into(),
            server_id: "finance".into(),
            tool_name: "send_payment".into(),
            ..Default::default()
        };
        assert_eq!(r.resource_id(), "mcp://finance/send_payment");
    }
}

#[cfg(test)]
mod spec_0085_capacity_tests {
    use super::*;

    fn request(agent: &str, id: &str, subject: &str) -> ApprovalRequestV1 {
        ApprovalRequestV1 {
            approval_id: id.into(),
            request_id: id.into(),
            authorization_subject_hash: subject.into(),
            requested_roles: vec!["approver".into()],
            reason: "test".into(),
            preview: ApprovalPreviewV1 {
                agent: agent.into(),
                ..Default::default()
            },
            requested_at: 1,
            expires_at: 999,
        }
    }

    #[test]
    fn per_agent_limit_is_atomic_and_retry_costs_nothing() {
        let store = ApprovalStore::new();
        let a = request("agent-a", "a1", "subject-a1");
        let b = request("agent-a", "a2", "subject-a2");
        assert!(store.request_bounded(a.clone(), 10, 4, 2).is_ok());
        assert!(store.request_bounded(b, 10, 4, 2).is_ok());
        assert!(matches!(
            store.request_bounded(request("agent-a", "a3", "subject-a3"), 10, 4, 2),
            Err(ApprovalAdmissionError::PerAgentLimit { limit: 2, .. })
        ));
        let retry = store.request_bounded(a, 10, 4, 2).unwrap();
        assert_eq!(retry.approval_id, "a1");
        assert_eq!(store.pending(10).len(), 2);
    }

    #[test]
    fn global_limit_contains_multi_agent_fanout() {
        let store = ApprovalStore::new();
        for i in 0..4 {
            assert!(store
                .request_bounded(
                    request(&format!("agent-{i}"), &format!("id-{i}"), &format!("s-{i}")),
                    10,
                    4,
                    4,
                )
                .is_ok());
        }
        assert!(matches!(
            store.request_bounded(request("agent-z", "id-z", "s-z"), 10, 4, 4),
            Err(ApprovalAdmissionError::GlobalLimit { limit: 4 })
        ));
        assert_eq!(store.pending(10).len(), 4);
    }
}
