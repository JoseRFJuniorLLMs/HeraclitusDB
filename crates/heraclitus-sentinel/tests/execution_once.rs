use heraclitus_core::{Episode, EventKind, FsyncPolicy, StorageFormat};
use heraclitus_log::AnyLog;
use heraclitus_sentinel::ai::{ActionProposal, SecurityAction};
use heraclitus_sentinel::execution::deterministic_action_id;
use heraclitus_sentinel::policy::{
    ActionResult, AuthorizedAction, ExecutionConstraints, PolicyError, SecurityActionExecutor,
};
use heraclitus_sentinel::{SentinelConfig, SentinelMode, SentinelRuntime};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
};

struct Executor {
    calls: AtomicUsize,
    fail: bool,
}
impl SecurityActionExecutor for Executor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, PolicyError>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.fail {
                return Err(PolicyError::Invalid("external outcome unknown".into()));
            }
            Ok(ActionResult {
                action_id: deterministic_action_id(
                    &action.incident_id,
                    &action.action,
                    &action.policy_version,
                )
                .unwrap(),
                success: true,
                external_reference: None,
                rollback_token: None,
                message: "done".into(),
                executed_at: 1,
            })
        })
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(result) => return result,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn config() -> SentinelConfig {
    SentinelConfig {
        enabled: true,
        mode: SentinelMode::Assist,
        ..Default::default()
    }
}

fn setup() -> (
    tempfile::TempDir,
    Arc<AnyLog>,
    SentinelRuntime,
    AuthorizedAction,
) {
    let temp = tempfile::tempdir().unwrap();
    let log = Arc::new(
        AnyLog::open(
            StorageFormat::Legacy,
            temp.path().join("log"),
            1 << 20,
            FsyncPolicy::Always,
        )
        .unwrap(),
    );
    let authorized = AuthorizedAction {
        authorization_id: "auth-test".into(),
        incident_id: "inc-test".into(),
        action: SecurityAction::BlockIp {
            ip: "203.0.113.25".into(),
            ttl_secs: 60,
        },
        constraints: ExecutionConstraints {
            scope: "test".into(),
            max_ttl_secs: Some(60),
            requires_approval: false,
            allow_retries: false,
        },
        evidence: vec![],
        policy_version: "test-v1".into(),
    };
    let proposal = ActionProposal {
        proposal_id: "proposal-test".into(),
        incident_id: authorized.incident_id.clone(),
        action: authorized.action.clone(),
        rationale: "test".into(),
        evidence: vec![],
        expected_effect: "test".into(),
        requested_ttl: Some(60),
    };
    let decision = serde_json::json!({"policy_version": authorized.policy_version, "proposal_id": proposal.proposal_id,
        "decision": {"Approve": {"authorization_id": authorized.authorization_id, "constraints": authorized.constraints}}});
    for (kind, payload) in [
        (
            "SecurityActionProposal",
            serde_json::to_vec(&proposal).unwrap(),
        ),
        (
            "SecurityPolicyDecision",
            serde_json::to_vec(&decision).unwrap(),
        ),
    ] {
        let mut episode = Episode::new("sentinel", EventKind::Custom(kind.into()), payload);
        episode
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        episode.attrs.insert(
            "sentinel.incident_id".into(),
            authorized.incident_id.clone(),
        );
        episode.attrs.insert(
            "sentinel.action_proposal_id".into(),
            proposal.proposal_id.clone(),
        );
        log.append(episode).unwrap();
    }
    let runtime = SentinelRuntime::start(log.clone(), config())
        .unwrap()
        .unwrap();
    (temp, log, runtime, authorized)
}

#[test]
fn completed_result_is_reused_and_constraints_cannot_be_replaced() {
    let (_temp, log, runtime, authorized) = setup();
    let executor = Executor {
        calls: AtomicUsize::new(0),
        fail: false,
    };
    let mut forged = authorized.clone();
    forged.constraints.max_ttl_secs = None;
    assert!(block_on(runtime.execute_authorized_action(&executor, forged)).is_err());
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    let first = block_on(runtime.execute_authorized_action(&executor, authorized.clone())).unwrap();
    assert_eq!(
        block_on(runtime.execute_authorized_action(&executor, authorized.clone())).unwrap(),
        first
    );
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    runtime.shutdown();
    drop(runtime);
    let runtime = SentinelRuntime::start(log, config()).unwrap().unwrap();
    assert_eq!(
        block_on(runtime.execute_authorized_action(&executor, authorized)).unwrap(),
        first
    );
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    runtime.shutdown();
}

#[test]
fn ambiguous_failure_is_not_reexecuted_even_after_restart() {
    let (_temp, log, runtime, authorized) = setup();
    let executor = Executor {
        calls: AtomicUsize::new(0),
        fail: true,
    };
    assert!(block_on(runtime.execute_authorized_action(&executor, authorized.clone())).is_err());
    assert!(block_on(runtime.execute_authorized_action(&executor, authorized.clone())).is_err());
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    runtime.shutdown();
    drop(runtime);
    let runtime = SentinelRuntime::start(log, config()).unwrap().unwrap();
    assert!(block_on(runtime.execute_authorized_action(&executor, authorized)).is_err());
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    runtime.shutdown();
}

#[test]
fn sink_returning_another_executions_claim_cannot_dispatch() {
    struct CompetingSink(Arc<AnyLog>);
    impl heraclitus_sentinel::DerivedEventSink for CompetingSink {
        fn append(
            &self,
            mut episode: Episode,
            _key: &str,
        ) -> Result<heraclitus_core::Lsn, heraclitus_core::HeraclitusError> {
            // Model a host returning a competing execution's persisted claim
            // before the runtime's local deduplication map has observed it.
            if episode.kind == EventKind::Custom("SecurityActionAttempt".into()) {
                episode.id = Episode::new("competitor", episode.kind.clone(), vec![]).id;
            }
            self.0.append(episode)
        }
    }
    let (_temp, log, runtime, authorized) = setup();
    runtime.shutdown();
    drop(runtime);
    let runtime =
        SentinelRuntime::start_with_sink(log.clone(), Arc::new(CompetingSink(log)), config())
            .unwrap()
            .unwrap();
    let executor = Executor {
        calls: AtomicUsize::new(0),
        fail: false,
    };
    assert!(block_on(runtime.execute_authorized_action(&executor, authorized)).is_err());
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    runtime.shutdown();
}
