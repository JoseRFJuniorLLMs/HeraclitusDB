//! Application-layer sovereignty guard for egress and model inference.
//!
//! This guard is intentionally fail-closed and audit-first.  It complements,
//! but does not claim to replace, an operating-system firewall or the external
//! zero-egress qualification required by SPEC-0049.

use crate::{CompError, TimestampValidationState, TsaClient};
use heraclitus_core::{Episode, EventKind, Lsn};
use heraclitus_log::{AnyLog, EpisodeLog};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;

const EGRESS_EVENT: &str = "ComplianceEgressDecision";
const MODEL_EVENT: &str = "ComplianceModelDecision";
const MAX_TEXT_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SovereigntyMode {
    Normal,
    ControlledEgress,
    StrictAirGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSovereignty {
    LocalProcess,
    LocalNetwork,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressPurpose {
    TimestampAuthority,
    RevocationStatus,
    ThreatIntelligence,
    InstitutionalGateway,
    ModelInference,
    Telemetry,
    SoftwareUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EgressEndpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub purpose: EgressPurpose,
}

impl EgressEndpoint {
    pub fn validate(&self) -> Result<(), SovereigntyError> {
        if self.scheme != "https" {
            return Err(SovereigntyError::Invalid(
                "egress externo exige scheme=https".into(),
            ));
        }
        if self.host.trim().is_empty()
            || self.host.len() > 253
            || self.host.contains('/')
            || self.host.contains('@')
            || self.host.chars().any(char::is_whitespace)
        {
            return Err(SovereigntyError::Invalid("host de egress inválido".into()));
        }
        if self.port == 0 {
            return Err(SovereigntyError::Invalid("porta de egress zero".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereigntyPolicy {
    pub policy_id: String,
    pub version: String,
    pub mode: SovereigntyMode,
    #[serde(default)]
    pub allowed_endpoints: BTreeSet<EgressEndpoint>,
    pub allow_local_network_models: bool,
    pub allow_external_models: bool,
}

impl SovereigntyPolicy {
    pub fn validate(&self) -> Result<(), SovereigntyError> {
        required("policy_id", &self.policy_id)?;
        required("version", &self.version)?;
        for endpoint in &self.allowed_endpoints {
            endpoint.validate()?;
        }
        if self.mode == SovereigntyMode::StrictAirGap
            && (!self.allowed_endpoints.is_empty()
                || self.allow_local_network_models
                || self.allow_external_models)
        {
            return Err(SovereigntyError::Invalid(
                "StrictAirGap não aceita allowlist nem backends de rede".into(),
            ));
        }
        if self.mode == SovereigntyMode::ControlledEgress && self.allow_external_models {
            let has_model_endpoint = self
                .allowed_endpoints
                .iter()
                .any(|endpoint| endpoint.purpose == EgressPurpose::ModelInference);
            if !has_model_endpoint {
                return Err(SovereigntyError::Invalid(
                    "modelo externo permitido sem endpoint de inferência allowlisted".into(),
                ));
            }
        }
        Ok(())
    }
}

fn required(name: &str, value: &str) -> Result<(), SovereigntyError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_BYTES {
        Err(SovereigntyError::Invalid(format!("{name} inválido")))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SovereigntyVerdict {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDecision {
    pub decision_id: String,
    pub policy_id: String,
    pub policy_version: String,
    pub mode: SovereigntyMode,
    pub endpoint: EgressEndpoint,
    pub component: String,
    pub reason: String,
    pub verdict: SovereigntyVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelDecision {
    pub decision_id: String,
    pub policy_id: String,
    pub policy_version: String,
    pub mode: SovereigntyMode,
    pub model_id: String,
    pub sovereignty: ModelSovereignty,
    pub reason: String,
    pub verdict: SovereigntyVerdict,
}

#[derive(Debug, Error)]
pub enum SovereigntyError {
    #[error("política de soberania inválida: {0}")]
    Invalid(String),
    #[error("egress negado: {0}")]
    Denied(String),
    #[error("auditoria de soberania: {0}")]
    Audit(String),
    #[error("serialização de soberania: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("backend soberano: {0}")]
    Backend(String),
}

/// Non-forgeable marker returned only after an allow decision was persisted.
#[derive(Debug)]
pub struct EgressPermit {
    decision_lsn: Lsn,
}

impl EgressPermit {
    pub fn decision_lsn(&self) -> Lsn {
        self.decision_lsn
    }
}

#[derive(Clone)]
pub struct SovereigntyRuntime {
    policy: SovereigntyPolicy,
    log: Arc<AnyLog>,
}

impl SovereigntyRuntime {
    pub fn new(policy: SovereigntyPolicy, log: Arc<AnyLog>) -> Result<Self, SovereigntyError> {
        policy.validate()?;
        Ok(Self { policy, log })
    }

    pub fn policy(&self) -> &SovereigntyPolicy {
        &self.policy
    }

    pub fn authorize_egress(
        &self,
        endpoint: &EgressEndpoint,
        component: &str,
    ) -> Result<EgressPermit, SovereigntyError> {
        endpoint.validate()?;
        required("component", component)?;
        let allowed = match self.policy.mode {
            SovereigntyMode::StrictAirGap => false,
            SovereigntyMode::ControlledEgress | SovereigntyMode::Normal => {
                self.policy.allowed_endpoints.contains(endpoint)
            }
        };
        let reason = match (self.policy.mode, allowed) {
            (SovereigntyMode::StrictAirGap, _) => "strict_air_gap_denies_all_egress",
            (_, true) => "endpoint_exactly_allowlisted",
            (_, false) => "endpoint_not_allowlisted",
        };
        let material = serde_json::to_vec(&(
            &self.policy.policy_id,
            &self.policy.version,
            endpoint,
            component,
            reason,
            allowed,
        ))?;
        let decision = EgressDecision {
            decision_id: format!("egress-{}", blake3::hash(&material).to_hex()),
            policy_id: self.policy.policy_id.clone(),
            policy_version: self.policy.version.clone(),
            mode: self.policy.mode,
            endpoint: endpoint.clone(),
            component: component.to_owned(),
            reason: reason.into(),
            verdict: if allowed {
                SovereigntyVerdict::Allow
            } else {
                SovereigntyVerdict::Deny
            },
        };
        let lsn = self.persist_egress_decision(&decision)?;
        if !allowed {
            return Err(SovereigntyError::Denied(format!(
                "{}:{} para {:?} ({reason})",
                endpoint.host, endpoint.port, endpoint.purpose
            )));
        }
        Ok(EgressPermit { decision_lsn: lsn })
    }

    pub fn authorize_model(
        &self,
        model_id: &str,
        sovereignty: ModelSovereignty,
    ) -> Result<Lsn, SovereigntyError> {
        required("model_id", model_id)?;
        let allowed = match (self.policy.mode, sovereignty) {
            (_, ModelSovereignty::LocalProcess) => true,
            (SovereigntyMode::StrictAirGap, _) => false,
            (_, ModelSovereignty::LocalNetwork) => self.policy.allow_local_network_models,
            (_, ModelSovereignty::External) => self.policy.allow_external_models,
        };
        let reason = match (sovereignty, allowed) {
            (ModelSovereignty::LocalProcess, true) => "local_process",
            (ModelSovereignty::LocalNetwork, true) => "local_network_allowed",
            (ModelSovereignty::External, true) => "external_model_allowed",
            (ModelSovereignty::LocalNetwork, false) => "local_network_model_denied",
            (ModelSovereignty::External, false) => "external_model_denied",
            (ModelSovereignty::LocalProcess, false) => unreachable!(),
        };
        let material = serde_json::to_vec(&(
            &self.policy.policy_id,
            &self.policy.version,
            model_id,
            sovereignty,
            reason,
            allowed,
        ))?;
        let decision = ModelDecision {
            decision_id: format!("model-{}", blake3::hash(&material).to_hex()),
            policy_id: self.policy.policy_id.clone(),
            policy_version: self.policy.version.clone(),
            mode: self.policy.mode,
            model_id: model_id.to_owned(),
            sovereignty,
            reason: reason.into(),
            verdict: if allowed {
                SovereigntyVerdict::Allow
            } else {
                SovereigntyVerdict::Deny
            },
        };
        let lsn = self.persist_model_decision(&decision)?;
        if allowed {
            Ok(lsn)
        } else {
            Err(SovereigntyError::Denied(format!(
                "modelo {model_id} com soberania {sovereignty:?}"
            )))
        }
    }

    fn persist_egress_decision(&self, decision: &EgressDecision) -> Result<Lsn, SovereigntyError> {
        let mut episode = generated_episode(EGRESS_EVENT, serde_json::to_vec(decision)?);
        episode.attrs.insert(
            "compliance.decision_id".into(),
            decision.decision_id.clone(),
        );
        episode.attrs.insert(
            "compliance.egress_verdict".into(),
            format!("{:?}", decision.verdict).to_ascii_lowercase(),
        );
        self.log
            .append(episode)
            .map_err(|error| SovereigntyError::Audit(error.to_string()))
    }

    fn persist_model_decision(&self, decision: &ModelDecision) -> Result<Lsn, SovereigntyError> {
        let mut episode = generated_episode(MODEL_EVENT, serde_json::to_vec(decision)?);
        episode.attrs.insert(
            "compliance.decision_id".into(),
            decision.decision_id.clone(),
        );
        episode
            .attrs
            .insert("compliance.model_id".into(), decision.model_id.clone());
        self.log
            .append(episode)
            .map_err(|error| SovereigntyError::Audit(error.to_string()))
    }
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

/// TSA adapter that makes bypassing the sovereignty decision impossible for
/// callers using the compliance client abstraction.
pub struct GuardedTsaClient<C> {
    inner: C,
    runtime: SovereigntyRuntime,
    endpoint: EgressEndpoint,
    component: String,
}

impl<C> GuardedTsaClient<C> {
    pub fn new(
        inner: C,
        runtime: SovereigntyRuntime,
        endpoint: EgressEndpoint,
        component: impl Into<String>,
    ) -> Result<Self, SovereigntyError> {
        endpoint.validate()?;
        let component = component.into();
        required("component", &component)?;
        if endpoint.purpose != EgressPurpose::TimestampAuthority {
            return Err(SovereigntyError::Invalid(
                "GuardedTsaClient exige purpose=timestamp_authority".into(),
            ));
        }
        Ok(Self {
            inner,
            runtime,
            endpoint,
            component,
        })
    }
}

impl<C: TsaClient> TsaClient for GuardedTsaClient<C> {
    fn policy_name(&self) -> &str {
        self.inner.policy_name()
    }

    fn validation_state(&self) -> TimestampValidationState {
        self.inner.validation_state()
    }

    fn stamp(&self, imprint: &[u8; 32]) -> Result<Vec<u8>, CompError> {
        self.runtime
            .authorize_egress(&self.endpoint, &self.component)
            .map_err(|error| CompError::Tsa(error.to_string()))?;
        self.inner.stamp(imprint)
    }
}

pub trait SovereignModelBackend: Send + Sync {
    type Request: Sync;
    type Response: Send;

    fn model_id(&self) -> &str;
    fn sovereignty(&self) -> ModelSovereignty;
    fn infer<'a>(
        &'a self,
        request: &'a Self::Request,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Response, String>> + Send + 'a>>;
}

pub struct GuardedModelBackend<B> {
    inner: B,
    runtime: SovereigntyRuntime,
}

impl<B> GuardedModelBackend<B> {
    pub fn new(inner: B, runtime: SovereigntyRuntime) -> Self {
        Self { inner, runtime }
    }
}

impl<B: SovereignModelBackend> GuardedModelBackend<B> {
    pub async fn infer(&self, request: &B::Request) -> Result<B::Response, SovereigntyError> {
        self.runtime
            .authorize_model(self.inner.model_id(), self.inner.sovereignty())?;
        self.inner
            .infer(request)
            .await
            .map_err(SovereigntyError::Backend)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SovereigntyAuditState {
    pub egress: Vec<(Lsn, EgressDecision)>,
    pub models: Vec<(Lsn, ModelDecision)>,
}

impl SovereigntyAuditState {
    pub fn replay<L: EpisodeLog + ?Sized>(log: &L) -> Result<Self, SovereigntyError> {
        let mut state = Self::default();
        let rows = log
            .scan(0, log.head())
            .map_err(|error| SovereigntyError::Audit(error.to_string()))?;
        for (lsn, episode) in rows {
            if episode
                .attrs
                .get("compliance.generated")
                .map(String::as_str)
                != Some("true")
            {
                continue;
            }
            match episode.kind.label().as_str() {
                EGRESS_EVENT => state
                    .egress
                    .push((lsn, serde_json::from_slice(&episode.content)?)),
                MODEL_EVENT => state
                    .models
                    .push((lsn, serde_json::from_slice(&episode.content)?)),
                _ => {}
            }
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{FsyncPolicy, StorageFormat};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn log() -> (tempfile::TempDir, Arc<AnyLog>) {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(StorageFormat::V6, temp.path(), 4096, FsyncPolicy::Always).unwrap(),
        );
        (temp, log)
    }

    fn endpoint() -> EgressEndpoint {
        EgressEndpoint {
            scheme: "https".into(),
            host: "tsa.example.gov.br".into(),
            port: 443,
            purpose: EgressPurpose::TimestampAuthority,
        }
    }

    fn strict_policy() -> SovereigntyPolicy {
        SovereigntyPolicy {
            policy_id: "airgap".into(),
            version: "v1".into(),
            mode: SovereigntyMode::StrictAirGap,
            allowed_endpoints: BTreeSet::new(),
            allow_local_network_models: false,
            allow_external_models: false,
        }
    }

    struct CountingTsa(Arc<AtomicUsize>);

    impl TsaClient for CountingTsa {
        fn policy_name(&self) -> &str {
            "counting-tsa"
        }

        fn validation_state(&self) -> TimestampValidationState {
            TimestampValidationState::ExternalTokenUnvalidated
        }

        fn stamp(&self, _imprint: &[u8; 32]) -> Result<Vec<u8>, CompError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(vec![0x30, 0])
        }
    }

    #[test]
    fn strict_air_gap_denies_before_network_backend_and_audits_the_denial() {
        let (_temp, log) = log();
        let runtime = SovereigntyRuntime::new(strict_policy(), log.clone()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let client = GuardedTsaClient::new(
            CountingTsa(calls.clone()),
            runtime,
            endpoint(),
            "anchor-worker",
        )
        .unwrap();
        assert!(client.stamp(&[7; 32]).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let audit = SovereigntyAuditState::replay(log.as_ref()).unwrap();
        assert_eq!(audit.egress.len(), 1);
        assert_eq!(audit.egress[0].1.verdict, SovereigntyVerdict::Deny);
    }

    #[test]
    fn controlled_egress_is_exact_allowlist_not_host_suffix_matching() {
        let (_temp, log) = log();
        let allowed = endpoint();
        let policy = SovereigntyPolicy {
            policy_id: "controlled".into(),
            version: "v3".into(),
            mode: SovereigntyMode::ControlledEgress,
            allowed_endpoints: [allowed.clone()].into_iter().collect(),
            allow_local_network_models: true,
            allow_external_models: false,
        };
        let runtime = SovereigntyRuntime::new(policy, log.clone()).unwrap();
        assert!(runtime.authorize_egress(&allowed, "anchor-worker").is_ok());
        let mut lookalike = allowed;
        lookalike.host = "tsa.example.gov.br.attacker.invalid".into();
        assert!(matches!(
            runtime.authorize_egress(&lookalike, "anchor-worker"),
            Err(SovereigntyError::Denied(_))
        ));
        assert_eq!(
            SovereigntyAuditState::replay(log.as_ref())
                .unwrap()
                .egress
                .len(),
            2
        );
    }

    struct TestModel {
        calls: Arc<AtomicUsize>,
        sovereignty: ModelSovereignty,
    }

    impl SovereignModelBackend for TestModel {
        type Request = String;
        type Response = String;

        fn model_id(&self) -> &str {
            "investigator"
        }

        fn sovereignty(&self) -> ModelSovereignty {
            self.sovereignty
        }

        fn infer<'a>(
            &'a self,
            request: &'a Self::Request,
        ) -> Pin<Box<dyn Future<Output = Result<Self::Response, String>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(format!("local:{request}")) })
        }
    }

    #[tokio::test]
    async fn strict_air_gap_blocks_external_model_but_allows_local_process() {
        let (_temp, log) = log();
        let runtime = SovereigntyRuntime::new(strict_policy(), log.clone()).unwrap();
        let external_calls = Arc::new(AtomicUsize::new(0));
        let external = GuardedModelBackend::new(
            TestModel {
                calls: external_calls.clone(),
                sovereignty: ModelSovereignty::External,
            },
            runtime.clone(),
        );
        assert!(matches!(
            external.infer(&"incident".into()).await,
            Err(SovereigntyError::Denied(_))
        ));
        assert_eq!(external_calls.load(Ordering::SeqCst), 0);

        let local_calls = Arc::new(AtomicUsize::new(0));
        let local = GuardedModelBackend::new(
            TestModel {
                calls: local_calls.clone(),
                sovereignty: ModelSovereignty::LocalProcess,
            },
            runtime,
        );
        assert_eq!(
            local.infer(&"incident".into()).await.unwrap(),
            "local:incident"
        );
        assert_eq!(local_calls.load(Ordering::SeqCst), 1);
        let audit = SovereigntyAuditState::replay(log.as_ref()).unwrap();
        assert_eq!(audit.models.len(), 2);
    }

    #[test]
    fn strict_policy_cannot_smuggle_an_allowlist() {
        let mut policy = strict_policy();
        policy.allowed_endpoints.insert(endpoint());
        assert!(policy.validate().is_err());
    }
}
