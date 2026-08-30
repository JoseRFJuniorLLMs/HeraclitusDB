# Heraclitus Sentinel — Fases 0–6

`heraclitus-sentinel` is the optional, append-isolated security derivation
plane described by SPEC-0045.  The Fases 0–1 runtime provides:

- a bounded notification queue containing only LSNs;
- overflow recovery by scanning the canonical log from a persisted cursor;
- deterministic generic JSON normalization into `SecurityEvent`;
- provenance (`parents[0]`, `sec.source_lsn`) and `sentinel.generated=true`;
- atomic cursor checkpoints and lock-free operational counters;
- a fail-closed L1 detection IR/rule executor, a documented Sigma subset and
  deterministic `SecuritySignal` identity (no rule set is enabled by default);
- opt-in server wiring that never makes `Engine::append` wait for Sentinel.

Fase 2 now provides an opt-in runtime adapter over the standalone
`BehavioralEngine`: canonical events become bounded scalar observations for
each explicit entity, then EWMA/Welford moments, bounded deterministic
quantiles, robust z-score/IQR scoring, shadow promotion, quarantine and
update-rate limiting produce deterministic L2 `SecuritySignal`s. Suspicious
events (including L1 evidence) are excluded unless an explicit trusted-feedback
call supplies the reduced policy weight. The behavioral snapshot can be
reconstructed at an AS-OF transaction LSN.

Fase 3 adds L3 correlation primitives and an opt-in runtime adapter: canonical
`SecurityEvent`s rebuild a bounded temporal graph, persisted `SecuritySignal`s
feed the deterministic `IncidentEngine`, and every created/enriched incident is
appended as a `SecurityIncident` revision with a stable BLAKE3 revision ID and
causal evidence parents. Replay follows transaction-LSN order, so restart and a
rewound cursor converge without duplicate revisions. Versioned monotonic
`EvidenceFusion` now consumes live/replayed L1/L2 and accepts supplied
L3/threat-intel signals per subject, persisting a `SecurityRiskAssessment` revision with
causal evidence parents. The two-detector high-impact guard remains an
explicit policy primitive; it is not implicitly treated as authorization.

Fase 4 adds an L4 foundation without a provider dependency: `AiContextBuilder`
enforces event/path/byte/token budgets, `SensitiveDataFilter` hashes secret
fields, `IncidentContext::prompt_envelope` marks evidence as untrusted, and
typed `SecurityAction`/`ActionProposal` values are checked against a static
capability registry. A host-supplied `ModelBackend` can now be invoked through
`SentinelRuntime::investigate`; the typed `SecurityInvestigation` response is
validated and persisted with a deterministic digest, together with a
`SecurityAiInvocation` audit record (model/provider/request/context/response
digests, latency, token estimate and result). The runtime circuit breaker is
on the actual provider path: failures and invalid structured output open it
without affecting L0–L3.

Fase 5 adds `DeterministicPolicyEngine`: versioned action rules return only
`Deny`, `Approve` or `RequireHumanApproval`, enforce risk/evidence/quorum,
allowlists, maintenance exceptions and TTL limits, and produce deterministic
authorization IDs. `AuthorizedAction`, `ActionResult` and
`SecurityActionExecutor` define a typed least-privilege boundary. Human
approval and action results are durable events; `MemoryReversibleExecutor` is
included for tests and integration, while production credentials/adapters stay
host-supplied.

The §61–67 operational guards add leader `SentinelEpoch`, expiring `ActionLease`/`ActionDispatch`,
retry-stable BLAKE3 action identities and an `AiCircuitBreaker` with failure,
cooldown and concurrency limits.  These are coordination guards only; L0–L3
remain independent when L4 is unavailable. The official Fase 6 reversible
response executors remain host-supplied for real infrastructure; the crate
includes both `DryRunExecutor` and a reversible in-memory executor.

Model/ruleset governance and analyst feedback are also canonical records:
`SecurityModelUpdate` captures artifact/config digests and validation metrics,
`SecurityRulesetUpdate` requires version/author/approval metadata, and
`SecurityFeedback` records true-positive, false-positive, benign or policy
exception labels. Feedback is append-only input to offline evaluation and
cannot mutate a live model, baseline or policy.

`AutonomousMode::try_enable` is a fail-closed gate: it requires all P0–P2,
C0–C2, S0–S4 and R0–R3 evidence plus a minimum-size false-positive
benchmark. It enables no executor by itself.

The default is disabled.  Enable it in TOML or with environment variables:

```toml
[sentinel]
enabled = true
mode = "observe"
queue_capacity = 65536
worker_threads = 4
pipeline_version = 1
catch_up_batch = 1024

[sentinel.l1]
enabled = true
rules_path = "./security/rules"

[sentinel.l2]
enabled = true
minimum_support = 20
learning_delay_events = 10
shadow_only = true
suspicious_severity = 7

[sentinel.l3]
enabled = true
max_graph_hops = 6
```

```text
HERACLITUS_SENTINEL_ENABLED=true
HERACLITUS_SENTINEL_MODE=observe
HERACLITUS_SENTINEL_L2_ENABLED=true
HERACLITUS_SENTINEL_L3_ENABLED=true
```

The Sigma frontend accepts scalar/list selections and deterministic boolean
conditions (`and`, `or`, `not`, `1 of`, `all of`) and rejects unsupported
modifiers or aggregations at compile time. L3 is disabled by default; when
enabled, its derived writes use a host `DerivedEventSink` (the server routes it
through `Engine`) and client appends cannot claim reserved Sentinel
kinds/namespaces. The server exposes `/sentinel/status`, bounded AS-OF incident,
evidence and WHY views, action/proposal views, approval endpoints, a compact
dashboard, and `POST /sentinel/checkpoint` for an auditable derived checkpoint.
`GET /metrics` exports the normative `sentinel_*` queue, lag, L0–L4, AI and
action counters/latencies.
The same status/incidents/actions/checkpoint operations are available through
RBAC-protected gRPC admin operations. In replicated server mode all replicas
maintain L0-L3 views, while the current Raft leader epoch alone may run L4,
approval, or response operations. L4 providers and real infrastructure
credentials remain host-supplied; `MemoryReversibleExecutor` is the included
safe executor. `mode=autonomous` is rejected until a verified permit and
qualified executor exist. No shell, arbitrary network request, or destructive
action is available.
