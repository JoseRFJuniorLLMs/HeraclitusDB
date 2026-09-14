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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

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
    pub policy_errors: AtomicU64,
    pub upstream_errors: AtomicU64,
}

impl GatewayCounters {
    pub fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "requests": self.requests.load(Ordering::Relaxed),
            "allow": self.allow.load(Ordering::Relaxed),
            "deny": self.deny.load(Ordering::Relaxed),
            "require_approval": self.require_approval.load(Ordering::Relaxed),
            "shadow_deny": self.shadow_deny.load(Ordering::Relaxed),
            "approval_expired": self.approval_expired.load(Ordering::Relaxed),
            "approval_replay_rejected": self.approval_replay_rejected.load(Ordering::Relaxed),
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
    dedupe: Mutex<DedupeIndex>,
    pub approvals: ApprovalStore,
    policy: RwLock<ActivePolicy>,
    pub counters: Mutex<IngestCounters>,
    pub gateway_counters: GatewayCounters,
    validator: Option<OidcValidator>,
    normalizer: OtlpNormalizer,
    started_at_unix_seconds: u64,
    /// Onde os Evidence Bundles exportados ficam. Fora do directório de dados
    /// do log de propósito: um bundle é um artefacto que se copia para fora, e
    /// misturá-lo com os segmentos do HRKL convida a que alguém apague o
    /// errado.
    bundles_dir: std::path::PathBuf,
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
            dedupe: Mutex::new(DedupeIndex::new(config.limits.max_queue_depth.max(1024))),
            normalizer,
            config,
            gateway,
            log,
            approvals: ApprovalStore::new(),
            policy: RwLock::new(ActivePolicy::deny_all()),
            counters: Mutex::new(IngestCounters::default()),
            gateway_counters: GatewayCounters::default(),
            validator: None,
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

    /// Persiste uma evidência, passando pela deduplicação.
    ///
    /// Devolve o LSN quando gravou, `None` quando a evidência era duplicada, e
    /// erro quando a chave colidiu com conteúdo diferente — que é o caso que a
    /// SPEC-0074 §14 manda falhar explicitamente.
    pub fn append(&self, e: &AgentEvidenceV1) -> Result<Option<Lsn>, HeraclitusError> {
        let verdict = {
            let mut idx = self.dedupe.lock().unwrap();
            idx.admit(e)
        };
        let mut counters = self.counters.lock().unwrap();
        match verdict {
            DedupeVerdict::Duplicate => {
                counters.duplicates += 1;
                Ok(None)
            }
            DedupeVerdict::Conflict { existing_hash } => {
                counters.conflicts += 1;
                Err(HeraclitusError::Config(format!(
                    "a chave de deduplicação {} já existe com conteúdo diferente \
                     (gravado {existing_hash}). Recusado: aceitar seria deixar reescrever \
                     evidência já registada (SPEC-0074 §14).",
                    e.dedupe_key
                )))
            }
            DedupeVerdict::Novel => {
                drop(counters);
                let lsn = self.log.append_evidence(e)?;
                let mut counters = self.counters.lock().unwrap();
                counters.events += 1;
                if e.privacy.redaction_applied {
                    counters.redactions += 1;
                }
                Ok(Some(lsn))
            }
        }
    }

    /// Reconstrói o índice de deduplicação a partir do log (arranque).
    pub fn warm(&self) -> Result<usize, HeraclitusError> {
        let rows = self.scan()?;
        let mut idx = self.dedupe.lock().unwrap();
        idx.warm_from(rows.iter().map(|r| &r.evidence));
        self.approvals.warm(Vec::new());
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
