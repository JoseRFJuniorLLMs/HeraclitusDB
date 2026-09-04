//! Operational safety primitives for Sentinel response (SPEC-0045 §61–67).
//!
//! These types only make a dispatch envelope and gate retries.  They do not
//! perform network/IAM/firewall work.  A concrete executor must check the
//! epoch and lease immediately before invoking an external system.

use crate::ai::SecurityAction;
use crate::policy::{ActionResult, AuthorizedAction, PolicyError, SecurityActionExecutor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelEpoch {
    pub cluster_term: u64,
    pub leader_node_id: String,
    pub sentinel_epoch: u64,
}

impl SentinelEpoch {
    pub fn new(
        cluster_term: u64,
        leader_node_id: impl Into<String>,
        sentinel_epoch: u64,
    ) -> Result<Self, LeaseError> {
        let epoch = Self {
            cluster_term,
            leader_node_id: leader_node_id.into(),
            sentinel_epoch,
        };
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn validate(&self) -> Result<(), LeaseError> {
        if self.leader_node_id.trim().is_empty() {
            return Err(LeaseError::InvalidEpoch("leader_node_id vazio".into()));
        }
        if self.cluster_term == 0 || self.sentinel_epoch == 0 {
            return Err(LeaseError::InvalidEpoch(
                "cluster_term e sentinel_epoch devem ser positivos".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum LeaseError {
    #[error("epoch do Sentinel inválido: {0}")]
    InvalidEpoch(String),
    #[error("lease de ação inválida: {0}")]
    InvalidLease(String),
    #[error("lease de ação expirada")]
    Expired,
    #[error("lease pertence a outro epoch/líder")]
    StaleEpoch,
    #[error("duração de lease inválida")]
    InvalidDuration,
    #[error("serialização da ação: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionLease {
    pub action_id: String,
    pub leader_epoch: SentinelEpoch,
    pub expires_at_ms: u64,
}

impl ActionLease {
    pub fn acquire(
        action_id: impl Into<String>,
        leader_epoch: SentinelEpoch,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<Self, LeaseError> {
        leader_epoch.validate()?;
        let action_id = action_id.into();
        if action_id.trim().is_empty() {
            return Err(LeaseError::InvalidLease("action_id vazio".into()));
        }
        let expires_at_ms = now_ms
            .checked_add(ttl_ms)
            .ok_or(LeaseError::InvalidDuration)?;
        if expires_at_ms <= now_ms {
            return Err(LeaseError::InvalidDuration);
        }
        Ok(Self {
            action_id,
            leader_epoch,
            expires_at_ms,
        })
    }

    pub fn validate(&self, current_epoch: &SentinelEpoch, now_ms: u64) -> Result<(), LeaseError> {
        if self.leader_epoch != *current_epoch {
            return Err(LeaseError::StaleEpoch);
        }
        if now_ms >= self.expires_at_ms {
            return Err(LeaseError::Expired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionDispatch {
    pub action_id: String,
    pub authorized: AuthorizedAction,
    pub epoch: SentinelEpoch,
    pub lease: ActionLease,
}

impl ActionDispatch {
    pub fn prepare(
        authorized: AuthorizedAction,
        epoch: SentinelEpoch,
        now_ms: u64,
        lease_ttl_ms: u64,
    ) -> Result<Self, LeaseError> {
        epoch.validate()?;
        let action_id = deterministic_action_id(
            &authorized.incident_id,
            &authorized.action,
            &authorized.policy_version,
        )?;
        let lease = ActionLease::acquire(action_id.clone(), epoch.clone(), now_ms, lease_ttl_ms)?;
        Ok(Self {
            action_id,
            authorized,
            epoch,
            lease,
        })
    }

    pub fn validate(&self, now_ms: u64, current_epoch: &SentinelEpoch) -> Result<(), LeaseError> {
        let expected = deterministic_action_id(
            &self.authorized.incident_id,
            &self.authorized.action,
            &self.authorized.policy_version,
        )?;
        if expected != self.action_id || self.lease.action_id != self.action_id {
            return Err(LeaseError::InvalidLease(
                "action_id não corresponde ao envelope".into(),
            ));
        }
        self.lease.validate(current_epoch, now_ms)
    }
}

pub fn deterministic_action_id(
    incident_id: &str,
    action: &SecurityAction,
    policy_version: &str,
) -> Result<String, LeaseError> {
    let mut bytes = Vec::new();
    append_part(&mut bytes, incident_id.as_bytes());
    append_part(&mut bytes, &serde_json::to_vec(action)?);
    append_part(&mut bytes, policy_version.as_bytes());
    Ok(format!("act-{}", blake3::hash(&bytes).to_hex()))
}

/// Test/development executor which validates the typed action and records a
/// deterministic result without contacting any external system.
#[derive(Debug, Clone, Copy, Default)]
pub struct DryRunExecutor;

impl SecurityActionExecutor for DryRunExecutor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, PolicyError>> + Send + 'a>> {
        Box::pin(async move {
            action
                .action
                .validate()
                .map_err(|error| PolicyError::Invalid(error.to_string()))?;
            let action_id = deterministic_action_id(
                &action.incident_id,
                &action.action,
                &action.policy_version,
            )
            .map_err(|error| PolicyError::Invalid(error.to_string()))?;
            Ok(ActionResult {
                action_id,
                success: true,
                external_reference: Some("dry-run".into()),
                rollback_token: None,
                message: "dry-run: nenhum efeito externo aplicado".into(),
                executed_at: 0,
            })
        })
    }
}

/// A concrete, least-privilege reversible executor for development and
/// integration tests. It models the external control-plane state in memory,
/// returns a rollback token, and is idempotent by `action_id`; it never opens a
/// shell or performs network/IAM calls. Production adapters can use the same
/// typed envelope and provenance contract.
#[derive(Debug, Clone, Default)]
pub struct MemoryReversibleExecutor {
    applied: Arc<Mutex<BTreeMap<String, SecurityAction>>>,
}

impl MemoryReversibleExecutor {
    pub fn active_actions(&self) -> Vec<String> {
        self.applied
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    pub fn rollback(&self, action_id: &str, rollback_token: &str) -> Result<bool, PolicyError> {
        if action_id.trim().is_empty() || rollback_token.trim().is_empty() {
            return Err(PolicyError::Invalid("identidade de rollback vazia".into()));
        }
        let expected = format!("rollback-{}", blake3::hash(action_id.as_bytes()).to_hex());
        if rollback_token != expected {
            return Err(PolicyError::Invalid("rollback token inválido".into()));
        }
        Ok(self
            .applied
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(action_id)
            .is_some())
    }
}

impl SecurityActionExecutor for MemoryReversibleExecutor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, PolicyError>> + Send + 'a>> {
        Box::pin(async move {
            action
                .action
                .validate()
                .map_err(|error| PolicyError::Invalid(error.to_string()))?;
            let action_id = deterministic_action_id(
                &action.incident_id,
                &action.action,
                &action.policy_version,
            )
            .map_err(|error| PolicyError::Invalid(error.to_string()))?;
            let mut applied = self
                .applied
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let inserted = applied
                .entry(action_id.clone())
                .or_insert_with(|| action.action.clone());
            let rollback_token =
                format!("rollback-{}", blake3::hash(action_id.as_bytes()).to_hex());
            Ok(ActionResult {
                action_id,
                success: true,
                external_reference: Some(format!("memory:{}", action_target(inserted))),
                rollback_token: Some(rollback_token),
                message: "efeito reversível mantido no executor de memória".into(),
                executed_at: 0,
            })
        })
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
        | SecurityAction::SnapshotEvidence { target } => format!("target:{target}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    Closed,
    Open,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub cooldown_secs: u64,
    pub max_concurrent_requests: u32,
    pub timeout_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            cooldown_secs: 60,
            max_concurrent_requests: 8,
            timeout_secs: 30,
        }
    }
}

impl CircuitBreakerConfig {
    pub fn validate(&self) -> Result<(), LeaseError> {
        if self.failure_threshold == 0
            || self.max_concurrent_requests == 0
            || self.cooldown_secs == 0
            || self.timeout_secs == 0
        {
            return Err(LeaseError::InvalidDuration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiCircuitBreaker {
    config: CircuitBreakerConfig,
    state: CircuitState,
    consecutive_failures: u32,
    in_flight: u32,
    opened_at_ms: Option<u64>,
}

impl AiCircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Result<Self, LeaseError> {
        config.validate()?;
        Ok(Self {
            config,
            state: CircuitState::Closed,
            consecutive_failures: 0,
            in_flight: 0,
            opened_at_ms: None,
        })
    }

    pub fn state(&self) -> CircuitState {
        self.state
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight
    }

    /// Begin one L4 call.  `false` means the breaker is open/cooling down or
    /// the concurrency budget is full; lower Sentinel levels remain usable.
    pub fn begin_request(&mut self, now_ms: u64) -> bool {
        if self.state == CircuitState::Open {
            let cooldown_ms = self.config.cooldown_secs.saturating_mul(1_000);
            if self
                .opened_at_ms
                .is_some_and(|opened| now_ms.saturating_sub(opened) >= cooldown_ms)
            {
                self.state = CircuitState::Closed;
                self.consecutive_failures = 0;
                self.opened_at_ms = None;
            } else {
                return false;
            }
        }
        if self.in_flight >= self.config.max_concurrent_requests {
            return false;
        }
        self.in_flight += 1;
        true
    }

    pub fn record_success(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.consecutive_failures = 0;
        self.state = CircuitState::Closed;
        self.opened_at_ms = None;
    }

    /// Devolve a permissão sem a contar como sucesso nem como falha.
    ///
    /// Existe para o caso em que a future do pedido é **cancelada** antes de
    /// terminar: sem isto, nem `record_success` nem `record_failure` chegavam a
    /// correr e o `in_flight` nunca descia. Ao fim de
    /// `max_concurrent_requests` cancelamentos o `begin_request` passava a
    /// recusar sempre, e o plano L4 ficava fechado até ao próximo reinício.
    ///
    /// Um cancelamento não é um voto sobre a saúde do backend, por isso não
    /// toca no contador de falhas consecutivas.
    pub fn release_cancelled(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    pub fn record_failure(&mut self, now_ms: u64) {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= self.config.failure_threshold {
            self.state = CircuitState::Open;
            self.opened_at_ms = Some(now_ms);
        }
    }
}

fn append_part(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ExecutionConstraints;

    fn authorized() -> AuthorizedAction {
        AuthorizedAction {
            authorization_id: "auth".into(),
            incident_id: "inc-1".into(),
            action: SecurityAction::BlockIp {
                ip: "203.0.113.25".into(),
                ttl_secs: 60,
            },
            constraints: ExecutionConstraints {
                scope: "network".into(),
                max_ttl_secs: Some(900),
                requires_approval: false,
                allow_retries: false,
            },
            evidence: Vec::new(),
            policy_version: "response-policy-v1".into(),
        }
    }

    #[test]
    fn action_id_and_dispatch_are_retry_stable() {
        let epoch = SentinelEpoch::new(3, "node-a", 7).unwrap();
        let left = ActionDispatch::prepare(authorized(), epoch.clone(), 1_000, 500).unwrap();
        let right = ActionDispatch::prepare(authorized(), epoch.clone(), 1_000, 500).unwrap();
        assert_eq!(left.action_id, right.action_id);
        left.validate(1_100, &epoch).unwrap();
        assert!(left.validate(1_500, &epoch).is_err());
    }

    #[test]
    fn stale_leader_epoch_is_rejected() {
        let old = SentinelEpoch::new(3, "node-a", 7).unwrap();
        let new = SentinelEpoch::new(4, "node-b", 8).unwrap();
        let dispatch = ActionDispatch::prepare(authorized(), old, 1_000, 500).unwrap();
        assert!(matches!(
            dispatch.validate(1_100, &new),
            Err(LeaseError::StaleEpoch)
        ));
    }

    #[test]
    fn breaker_opens_and_recovers_without_affecting_other_levels() {
        let mut breaker = AiCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            cooldown_secs: 1,
            max_concurrent_requests: 1,
            timeout_secs: 1,
        })
        .unwrap();
        assert!(breaker.begin_request(0));
        breaker.record_failure(0);
        assert!(breaker.begin_request(0));
        breaker.record_failure(10);
        assert_eq!(breaker.state(), CircuitState::Open);
        assert!(!breaker.begin_request(500));
        assert!(breaker.begin_request(1_010));
        breaker.record_success();
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn breaker_enforces_concurrency_budget() {
        let mut breaker = AiCircuitBreaker::new(CircuitBreakerConfig {
            max_concurrent_requests: 1,
            ..CircuitBreakerConfig::default()
        })
        .unwrap();
        assert!(breaker.begin_request(0));
        assert!(!breaker.begin_request(0));
        breaker.record_success();
        assert!(breaker.begin_request(0));
    }

    #[test]
    fn dry_run_executor_has_no_external_effect_and_is_idempotent() {
        let executor = DryRunExecutor;
        let action = authorized();
        let first = block_on(executor.execute(&action)).unwrap();
        let second = block_on(executor.execute(&action)).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.external_reference.as_deref(), Some("dry-run"));
        assert_eq!(first.executed_at, 0);
    }

    #[test]
    fn memory_executor_is_reversible_and_retry_stable() {
        let executor = MemoryReversibleExecutor::default();
        let action = authorized();
        let first = block_on(executor.execute(&action)).unwrap();
        let second = block_on(executor.execute(&action)).unwrap();
        assert_eq!(first, second);
        assert_eq!(executor.active_actions(), vec![first.action_id.clone()]);
        assert!(executor
            .rollback(&first.action_id, first.rollback_token.as_deref().unwrap())
            .unwrap());
        assert!(executor.active_actions().is_empty());
        assert!(!executor
            .rollback(&first.action_id, first.rollback_token.as_deref().unwrap())
            .unwrap());
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
