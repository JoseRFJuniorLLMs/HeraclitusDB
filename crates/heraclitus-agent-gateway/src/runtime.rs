//! O estado partilhado do Agent Black Box.
//!
//! # A fronteira que este ficheiro defende
//!
//! O `heraclitus-agent` não abre sockets (SPEC-0074 §7.1) e não conhece HTTP.
//! Este crate conhece. O [`AgentRuntime`] é a única peça que os dois lados
//! partilham: guarda o log de evidência, o índice de deduplicação, o registo de
//! aprovações e a policy activa, e expõe-os às superfícies de rede.
//!
//! # Porque a policy vive atrás de um `RwLock` e não é copiada por pedido
//!
//! A activação de policy é uma operação administrativa auditada (§21 da 0075) e
//! rara; a avaliação é por tool call e frequente. Um `RwLock` dá leitura
//! concorrente sem alocação, e a troca atómica garante que nenhuma avaliação vê
//! meia policy — uma decisão tomada com metade das regras de uma versão e
//! metade da outra seria indefensável numa auditoria.

use heraclitus_agent::action::ApprovalStore;
use heraclitus_agent::config::{AgentBlackBoxConfig, AgentGatewayConfig, GatewayMode};
use heraclitus_agent::dedupe::{DedupeIndex, DedupeVerdict};
use heraclitus_agent::evidence::AgentEvidenceV1;
use heraclitus_agent::identity::{KeySet, OidcValidator};
use heraclitus_agent::metrics::IngestCounters;
use heraclitus_agent::otlp::OtlpNormalizer;
use heraclitus_agent::policy::DeterministicAgentPolicyEngine;
use heraclitus_agent::store::{EvidenceLog, StoredEvidence};
use heraclitus_core::{HeraclitusError, Lsn};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};

struct DedupeState {
    index: DedupeIndex,
    in_flight: HashMap<String, String>,
}

/// Estado de uma policy no seu ciclo de vida (§22 da 0075).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyLifecycle {
    Draft,
    Validated,
    Simulated,
    Active,
    Retired,
}

/// A policy activa e quem a activou.
#[derive(Clone)]
pub struct ActivePolicy {
    pub engine: Arc<DeterministicAgentPolicyEngine>,
    pub activated_by: String,
    pub activated_at_unix_seconds: u64,
    pub lifecycle: PolicyLifecycle,
    pub source_path: Option<String>,
}

impl ActivePolicy {
    fn deny_all() -> Self {
        Self {
            engine: Arc::new(DeterministicAgentPolicyEngine::deny_all()),
            activated_by: "default".to_string(),
            activated_at_unix_seconds: 0,
            lifecycle: PolicyLifecycle::Active,
            source_path: None,
        }
    }
}

/// Contadores do gateway.
#[derive(Debug, Default)]
pub struct GatewayCounters {
    pub requests: AtomicU64,
    pub allow: AtomicU64,
    pub deny: AtomicU64,
    pub require_approval: AtomicU64,
    pub shadow_deny: AtomicU64,
    pub approval_expired: AtomicU64,
    pub approval_replay_rejected: AtomicU64,
    pub approval_capacity_rejected: AtomicU64,
    pub policy_errors: AtomicU64,
    /// Evidência que NÃO foi gravada. Ver `gateway::append`.
    pub evidence_errors: AtomicU64,
    pub upstream_errors: AtomicU64,
}

impl GatewayCounters {
    pub fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "requests": self.requests.load(Ordering::Relaxed),
            "evidence_errors": self.evidence_errors.load(Ordering::Relaxed),
            "allow": self.allow.load(Ordering::Relaxed),
            "deny": self.deny.load(Ordering::Relaxed),
            "require_approval": self.require_approval.load(Ordering::Relaxed),
            "shadow_deny": self.shadow_deny.load(Ordering::Relaxed),
            "approval_expired": self.approval_expired.load(Ordering::Relaxed),
            "approval_replay_rejected": self.approval_replay_rejected.load(Ordering::Relaxed),
            "approval_capacity_rejected": self.approval_capacity_rejected.load(Ordering::Relaxed),
            "policy_errors": self.policy_errors.load(Ordering::Relaxed),
            "upstream_errors": self.upstream_errors.load(Ordering::Relaxed),
        })
    }
}

/// O estado partilhado.
pub struct AgentRuntime {
    pub config: AgentBlackBoxConfig,
    pub gateway: AgentGatewayConfig,
    log: Arc<dyn EvidenceLog>,
    dedupe: (Mutex<DedupeState>, Condvar),
    pub approvals: ApprovalStore,
    policy: RwLock<ActivePolicy>,
    pub counters: Mutex<IngestCounters>,
    pub gateway_counters: GatewayCounters,
    validator: Option<OidcValidator>,
    /// Credencial partilhada da Consola, quando configurada. Guarda o cabeçalho
    /// esperado, não a senha — ver `auth::SharedCredential`.
    console_credential: Option<crate::auth::SharedCredential>,
    /// Quem responde pelo estado da PLATAFORMA (SPEC-0077 §37).
    ///
    /// `None` num gateway autónomo: aí a Platform Console diz `N/A` em vez de
    /// inventar um número. Ver `platform::PlatformSource`.
    platform: Option<Arc<dyn crate::platform::PlatformSource>>,
    normalizer: OtlpNormalizer,
    started_at_unix_seconds: u64,
    /// Onde os Evidence Bundles exportados ficam. Fora do directório de dados
    /// do log de propósito: um bundle é um artefacto que se copia para fora, e
    /// misturá-lo com os segmentos do HRKL convida a que alguém apague o
    /// errado.
    bundles_dir: std::path::PathBuf,
}

/// O que aconteceu a uma tentativa de gravar evidência.
///
/// Existe para separar duas coisas que o `Result` juntava e que têm
/// consequências opostas:
///
/// - [`Conflito`](AppendOutcome::Conflito) — a chave já existe com conteúdo
///   diferente. Para OTLP isto continua a significar colisão/rewrite da mesma
///   identidade lógica. Para o gateway, cada tentativa HTTP recebe identidade
///   de evidência distinta, portanto um conflito também é falha de integridade
///   e o modo `enforce` recusa a acção.
/// - [`Falhou`](AppendOutcome::Falhou) — o log não aceitou a escrita. Aqui não
///   há leitura benigna: a acção não ficou registada.
#[derive(Debug)]
pub enum AppendOutcome {
    Gravada(Lsn),
    /// Já lá estava, com o mesmo conteúdo. Retransmissão normal.
    Duplicada,
    Conflito {
        existing_hash: String,
    },
    Falhou(HeraclitusError),
}

impl AgentRuntime {
    pub fn new(
        config: AgentBlackBoxConfig,
        gateway: AgentGatewayConfig,
        log: Arc<dyn EvidenceLog>,
    ) -> Self {
        let normalizer = OtlpNormalizer::new(config.tenant_id.clone())
            .with_limits(config.limits.clone())
            .with_redaction(config.redaction_profile());
        Self {
            dedupe: (
                Mutex::new(DedupeState {
                    index: DedupeIndex::new(config.limits.max_queue_depth.max(1024)),
                    in_flight: HashMap::new(),
                }),
                Condvar::new(),
            ),
            normalizer,
            config,
            gateway,
            log,
            approvals: ApprovalStore::new(),
            policy: RwLock::new(ActivePolicy::deny_all()),
            counters: Mutex::new(IngestCounters::default()),
            gateway_counters: GatewayCounters::default(),
            validator: None,
            console_credential: None,
            platform: None,
            started_at_unix_seconds: now_unix_seconds(),
            bundles_dir: std::path::PathBuf::from("bundles"),
        }
    }

    pub fn with_validator(mut self, validator: OidcValidator) -> Self {
        self.validator = Some(validator);
        self
    }

    pub fn with_bundles_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.bundles_dir = dir.into();
        self
    }

    pub fn bundles_dir(&self) -> &std::path::Path {
        &self.bundles_dir
    }

    /// Carrega o validador OIDC a partir da configuração. Sem ficheiro JWKS não
    /// há validador — e um gateway em produção sem validador é recusado pelo
    /// [`AgentGatewayConfig::validate`], não silenciosamente aceite.
    pub fn load_validator(&mut self) -> Result<(), HeraclitusError> {
        if self.gateway.identity.mode != "oidc" {
            return Ok(());
        }
        let path = self.gateway.identity.jwks_path.clone();
        if path.is_empty() {
            return Ok(());
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| {
            HeraclitusError::Config(format!("não foi possível ler o JWKS em {path}: {e}"))
        })?;
        let keys = KeySet::from_jwks(&raw)
            .map_err(|e| HeraclitusError::Config(format!("JWKS inválido em {path}: {e}")))?;
        if keys.is_empty() {
            return Err(HeraclitusError::Config(format!(
                "o JWKS em {path} não tem nenhuma chave que saibamos validar (RSA ou EC P-256)"
            )));
        }
        self.validator = Some(OidcValidator {
            issuers: vec![self.gateway.identity.issuer.clone()],
            audience: self.gateway.identity.audience.clone(),
            clock_skew_seconds: self.gateway.identity.clock_skew_seconds,
            roles_claim: self.gateway.identity.roles_claim.clone(),
            keys,
        });
        Ok(())
    }

    pub fn validator(&self) -> Option<&OidcValidator> {
        self.validator.as_ref()
    }

    /// Lê a credencial partilhada da configuração.
    ///
    /// Uma credencial mal formada (sem `:`, ou com utilizador ou senha vazios)
    /// é um ERRO de arranque, não um aviso. O modo de falha contrário — aceitar
    /// e não proteger — deixaria o operador a olhar para uma consola aberta
    /// convencido de que a tinha fechado.
    pub fn load_console_credential(&mut self) -> Result<(), HeraclitusError> {
        let raw = self.config.console.basic_auth.trim().to_string();
        if raw.is_empty() {
            self.console_credential = None;
            return Ok(());
        }
        let credencial = crate::auth::SharedCredential::parse(&raw).ok_or_else(|| {
            HeraclitusError::Config(
                "[agent_black_box.console] basic_auth tem de ser `utilizador:senha`,                  com os dois campos preenchidos"
                    .to_string(),
            )
        })?;
        self.console_credential = Some(credencial);
        Ok(())
    }

    /// Liga a fonte de estado da plataforma. Chamado pelo `heraclitus-server`,
    /// que é quem tem o motor.
    pub fn with_platform(mut self, fonte: Arc<dyn crate::platform::PlatformSource>) -> Self {
        self.platform = Some(fonte);
        self
    }

    pub fn platform(&self) -> Option<&Arc<dyn crate::platform::PlatformSource>> {
        self.platform.as_ref()
    }

    pub fn console_credential(&self) -> Option<&crate::auth::SharedCredential> {
        self.console_credential.as_ref()
    }

    /// Como a Consola se apresenta. `oidc` ganha sempre ao `basic`.
    pub fn auth_mode(&self) -> crate::auth::AuthMode {
        if self.validator.is_some() {
            crate::auth::AuthMode::Oidc
        } else if self.console_credential.is_some() {
            crate::auth::AuthMode::Basic
        } else {
            crate::auth::AuthMode::DevLocal
        }
    }

    /// Se a ingestão OTLP exige a mesma credencial.
    pub fn otlp_credential(&self) -> Option<&crate::auth::SharedCredential> {
        if self.config.otlp.require_auth {
            self.console_credential.as_ref()
        } else {
            None
        }
    }

    pub fn normalizer(&self) -> &OtlpNormalizer {
        &self.normalizer
    }

    pub fn mode(&self) -> GatewayMode {
        self.gateway.mode
    }

    pub fn started_at(&self) -> u64 {
        self.started_at_unix_seconds
    }

    /// Carrega a policy do ficheiro configurado, se houver.
    pub fn load_policy(&self) -> Result<(), HeraclitusError> {
        let path = self.gateway.policy.active.clone();
        if path.is_empty() {
            return Ok(());
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| HeraclitusError::Config(format!("policy {path}: {e}")))?;
        let engine = DeterministicAgentPolicyEngine::parse(&raw)
            .map_err(|e| HeraclitusError::Config(format!("policy {path}: {e}")))?;
        self.activate_policy(engine, "config", Some(path));
        Ok(())
    }

    pub fn activate_policy(
        &self,
        engine: DeterministicAgentPolicyEngine,
        by: &str,
        source_path: Option<String>,
    ) {
        let mut guard = self.policy.write().unwrap();
        *guard = ActivePolicy {
            engine: Arc::new(engine),
            activated_by: by.to_string(),
            activated_at_unix_seconds: now_unix_seconds(),
            lifecycle: PolicyLifecycle::Active,
            source_path,
        };
    }

    pub fn policy(&self) -> ActivePolicy {
        self.policy.read().unwrap().clone()
    }

    /// Como [`AgentRuntime::append`], mas dizendo QUAL das três coisas
    /// aconteceu em vez de colapsar duas delas num erro.
    pub fn append_outcome(&self, e: &AgentEvidenceV1) -> AppendOutcome {
        let key = if e.dedupe_key.is_empty() {
            heraclitus_agent::dedupe::dedupe_key(e)
        } else {
            e.dedupe_key.clone()
        };
        let hash = heraclitus_agent::canonical::hex32(
            &heraclitus_agent::canonical::canonical_evidence_hash(e),
        );

        let (state, cvar) = (&self.dedupe.0, &self.dedupe.1);
        let mut guard = state.lock().unwrap();
        loop {
            if let Some(verdict) = guard.index.check(&key, &hash) {
                match verdict {
                    DedupeVerdict::Duplicate => {
                        self.counters.lock().unwrap().duplicates += 1;
                        return AppendOutcome::Duplicada;
                    }
                    DedupeVerdict::Conflict { existing_hash } => {
                        self.counters.lock().unwrap().conflicts += 1;
                        return AppendOutcome::Conflito { existing_hash };
                    }
                    DedupeVerdict::Novel => unreachable!(),
                }
            }
            if let Some(in_flight_hash) = guard.in_flight.get(&key) {
                if in_flight_hash != &hash {
                    let existing_hash = in_flight_hash.clone();
                    self.counters.lock().unwrap().conflicts += 1;
                    return AppendOutcome::Conflito { existing_hash };
                }
                guard = cvar.wait(guard).unwrap();
                continue;
            }
            guard.in_flight.insert(key.clone(), hash.clone());
            break;
        }
        drop(guard);

        struct InFlightGuard<'a> {
            state: &'a Mutex<DedupeState>,
            cvar: &'a Condvar,
            key: &'a str,
            committed: bool,
        }
        impl<'a> Drop for InFlightGuard<'a> {
            fn drop(&mut self) {
                if !self.committed {
                    let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
                    g.in_flight.remove(self.key);
                    self.cvar.notify_all();
                }
            }
        }
        let mut inflight_guard = InFlightGuard {
            state,
            cvar,
            key: &key,
            committed: false,
        };

        match self.log.append_evidence(e) {
            Ok(lsn) => {
                {
                    let mut g = state.lock().unwrap();
                    g.in_flight.remove(&key);
                    g.index.insert_committed(key.clone(), hash);
                    cvar.notify_all();
                    inflight_guard.committed = true;
                }
                let mut c = self.counters.lock().unwrap();
                c.events += 1;
                if e.privacy.redaction_applied {
                    c.redactions += 1;
                }
                AppendOutcome::Gravada(lsn)
            }
            Err(err) => AppendOutcome::Falhou(err),
        }
    }

    /// Persiste uma evidência, passando pela deduplicação.
    ///
    /// Devolve o LSN quando gravou, `None` quando a evidência era duplicada, e
    /// erro quando a chave colidiu com conteúdo diferente — que é o caso que a
    /// SPEC-0074 §14 manda falhar explicitamente.
    pub fn append(&self, e: &AgentEvidenceV1) -> Result<Option<Lsn>, HeraclitusError> {
        let key = if e.dedupe_key.is_empty() {
            heraclitus_agent::dedupe::dedupe_key(e)
        } else {
            e.dedupe_key.clone()
        };
        let hash = heraclitus_agent::canonical::hex32(
            &heraclitus_agent::canonical::canonical_evidence_hash(e),
        );

        let (state, cvar) = (&self.dedupe.0, &self.dedupe.1);
        let mut guard = state.lock().unwrap();
        loop {
            if let Some(verdict) = guard.index.check(&key, &hash) {
                let mut counters = self.counters.lock().unwrap();
                return match verdict {
                    DedupeVerdict::Duplicate => {
                        counters.duplicates += 1;
                        Ok(None)
                    }
                    DedupeVerdict::Conflict { existing_hash } => {
                        counters.conflicts += 1;
                        Err(HeraclitusError::Config(format!(
                            "a chave de deduplicação {key} já existe com conteúdo diferente \
                             (gravado {existing_hash}). Recusado: aceitar seria deixar reescrever \
                             evidência já registada (SPEC-0074 §14)."
                        )))
                    }
                    DedupeVerdict::Novel => unreachable!(),
                };
            }
            if let Some(in_flight_hash) = guard.in_flight.get(&key) {
                if in_flight_hash != &hash {
                    let existing_hash = in_flight_hash.clone();
                    self.counters.lock().unwrap().conflicts += 1;
                    return Err(HeraclitusError::Config(format!(
                        "a chave de deduplicação {key} já está em gravação com conteúdo diferente \
                         (conflito {existing_hash}). Recusado: aceitar seria deixar reescrever \
                         evidência já registada (SPEC-0074 §14)."
                    )));
                }
                guard = cvar.wait(guard).unwrap();
                continue;
            }
            guard.in_flight.insert(key.clone(), hash.clone());
            break;
        }
        drop(guard);

        struct InFlightGuard<'a> {
            state: &'a Mutex<DedupeState>,
            cvar: &'a Condvar,
            key: &'a str,
            committed: bool,
        }
        impl<'a> Drop for InFlightGuard<'a> {
            fn drop(&mut self) {
                if !self.committed {
                    let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
                    g.in_flight.remove(self.key);
                    self.cvar.notify_all();
                }
            }
        }
        let mut inflight_guard = InFlightGuard {
            state,
            cvar,
            key: &key,
            committed: false,
        };

        let lsn = self.log.append_evidence(e)?;
        {
            let mut g = state.lock().unwrap();
            g.in_flight.remove(&key);
            g.index.insert_committed(key.clone(), hash);
            cvar.notify_all();
            inflight_guard.committed = true;
        }
        let mut counters = self.counters.lock().unwrap();
        counters.events += 1;
        if e.privacy.redaction_applied {
            counters.redactions += 1;
        }
        Ok(Some(lsn))
    }

    /// Reconstrói o índice de deduplicação a partir do log (arranque).
    pub fn warm(&self) -> Result<usize, HeraclitusError> {
        let rows = self.scan()?;
        let mut guard = self.dedupe.0.lock().unwrap();
        guard.index.warm_from(rows.iter().map(|r| &r.evidence));
        self.approvals.warm(Vec::new());
        self.approvals.warm_consumed(rows.iter().filter_map(|row| {
            let e = &row.evidence;
            if e.kind != heraclitus_agent::evidence::AgentEvidenceKindV1::ToolAuthorized {
                return None;
            }
            let approval = e.content.approval.as_ref()?;
            Some((
                approval.authorization_subject_hash.clone(),
                approval.approval_id.clone(),
            ))
        }));
        Ok(rows.len())
    }

    pub fn scan(&self) -> Result<Vec<StoredEvidence>, HeraclitusError> {
        self.log.scan_evidence(0, self.log.head())
    }

    pub fn log(&self) -> &Arc<dyn EvidenceLog> {
        &self.log
    }

    pub fn flush(&self) -> Result<(), HeraclitusError> {
        self.log.flush()
    }

    pub fn head(&self) -> Lsn {
        self.log.head()
    }
}

pub fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_agent::evidence::AgentEvidenceKindV1;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    struct MockLog {
        should_fail: AtomicBool,
        head_count: AtomicU64,
        entries: Mutex<Vec<AgentEvidenceV1>>,
    }

    impl MockLog {
        fn new() -> Self {
            Self {
                should_fail: AtomicBool::new(false),
                head_count: AtomicU64::new(0),
                entries: Mutex::new(Vec::new()),
            }
        }
    }

    impl EvidenceLog for MockLog {
        fn append_evidence(&self, e: &AgentEvidenceV1) -> Result<Lsn, HeraclitusError> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(HeraclitusError::Storage(std::io::Error::other(
                    "simulated write error",
                )));
            }
            let mut list = self.entries.lock().unwrap();
            let lsn = self.head_count.fetch_add(1, Ordering::SeqCst);
            list.push(e.clone());
            Ok(lsn)
        }

        fn head(&self) -> Lsn {
            self.head_count.load(Ordering::SeqCst)
        }

        fn scan_evidence(
            &self,
            from: Lsn,
            limit: u64,
        ) -> Result<Vec<StoredEvidence>, HeraclitusError> {
            let list = self.entries.lock().unwrap();
            let mut res = Vec::new();
            for (idx, e) in list.iter().enumerate() {
                let lsn = idx as u64;
                if lsn >= from && (res.len() as u64) < limit {
                    res.push(StoredEvidence {
                        lsn,
                        evidence: e.clone(),
                    });
                }
            }
            Ok(res)
        }

        fn read_evidence(&self, lsn: Lsn) -> Result<Option<StoredEvidence>, HeraclitusError> {
            let list = self.entries.lock().unwrap();
            Ok(list.get(lsn as usize).map(|e| StoredEvidence {
                lsn,
                evidence: e.clone(),
            }))
        }

        fn flush(&self) -> Result<(), HeraclitusError> {
            Ok(())
        }

        fn prove(
            &self,
            _lsn: Lsn,
        ) -> Result<heraclitus_agent::store::ProofAvailability, HeraclitusError> {
            Ok(heraclitus_agent::store::ProofAvailability::PendingSeal)
        }
    }

    fn sample_evidence() -> AgentEvidenceV1 {
        let mut e = AgentEvidenceV1::new("t", AgentEvidenceKindV1::ToolRequested, 1);
        e.evidence_id = "ev-1".into();
        e.dedupe_key = "key-test-1".into();
        e
    }

    #[test]
    fn failed_append_does_not_poison_dedupe_index() {
        let mock_log = Arc::new(MockLog::new());
        let runtime = AgentRuntime::new(
            AgentBlackBoxConfig::default(),
            AgentGatewayConfig::default(),
            mock_log.clone(),
        );
        let ev = sample_evidence();

        // 1. Falha na escrita: não pode marcar a chave como vista
        mock_log.should_fail.store(true, Ordering::SeqCst);
        assert!(runtime.append(&ev).is_err());
        assert_eq!(mock_log.head(), 0);

        // 2. Retry com log recuperado: deve conseguir gravar e não ser descartado como duplicado
        mock_log.should_fail.store(false, Ordering::SeqCst);
        let res = runtime.append(&ev);
        assert_eq!(res.unwrap(), Some(0));
        assert_eq!(mock_log.head(), 1);

        // 3. Próximo envio com a mesma chave: agora sim é duplicado
        let res_dup = runtime.append(&ev);
        assert_eq!(res_dup.unwrap(), None);
        assert_eq!(mock_log.head(), 1);
    }

    #[test]
    fn unstamped_dedupe_key_conflict_error_contains_computed_key() {
        let mock_log = Arc::new(MockLog::new());
        let runtime = AgentRuntime::new(
            AgentBlackBoxConfig::default(),
            AgentGatewayConfig::default(),
            mock_log.clone(),
        );

        let mut ev1 = AgentEvidenceV1::new("t", AgentEvidenceKindV1::ToolRequested, 1);
        ev1.evidence_id = "ev-1".into();
        ev1.dedupe_key = "".into(); // não estampada
        let computed_key = heraclitus_agent::dedupe::dedupe_key(&ev1);
        assert!(!computed_key.is_empty());

        assert_eq!(runtime.append(&ev1).unwrap(), Some(0));

        // Evidência diferente que resulta na mesma chave (ou mesma chave com conteúdo modificado)
        let mut ev2 = ev1.clone();
        ev2.subject.tool_name = Some("tool_diferente".into());
        // Força a mesma chave para simular colisão de idempotência
        ev2.dedupe_key = computed_key.clone();

        let err = runtime.append(&ev2).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&computed_key),
            "mensagem de erro deve conter a chave calculada: {msg}"
        );
    }
}
