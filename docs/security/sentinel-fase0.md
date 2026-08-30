# SPEC-0045 — Sentinel Fases 0–5 + guards operacionais

The current implementation is the non-AI foundation, not the complete v1
security plane.

## Runtime contract

`HeraclitusConfig.sentinel` is disabled by default. When enabled, the server
attaches `SecuritySubscriber` to the selected legacy/v6 log through the real
tail. `on_append` performs only atomic accounting and a non-blocking enqueue of
the LSN. A bounded queue overflow records the earliest `catch_up_from_lsn`; a
worker then reads the canonical log with `scan_capped`.

The cursor is stored at `<data-dir>/log/sentinel/cursor.json`. It advances only
after normalization and (when applicable) the derived `SecurityEvent` append
complete. A generated event carries `sentinel.generated=true` and is ignored by
the normalizer only when it also came from the internal `sentinel` agent,
preventing alert-on-alert loops without trusting a client-supplied attribute.
The server reserves Sentinel event kinds and `sentinel.*`/`sec.*` attributes to
the internal sink. The raw event remains the first causal parent and
`sec.source_lsn` points back to its log position.

## Honest scope

Implemented: Fase 0 crate/config/subscriber/queue/cursor/normalizer/metrics,
deterministic replay tests, and the fail-closed L1 detection IR/rule executor
with deterministic `SecuritySignal` IDs. The Sigma subset can be enabled with
`[sentinel.l1]` and a file/directory of rules; compiled signals are persisted
on the same append-isolated path and deduplicated by their deterministic ID.
The default runtime still has no rules. Fase 2 adds the standalone
`BehavioralEngine`: bounded EWMA/Welford/quantile state, robust scoring,
shadow profiles, explicit promotion, quarantine and rate/poisoning controls.
It is checkpointable and tested for replay, but is not connected to the worker
until the canonical-event-to-feature contract is specified. Fase 3 now has an
opt-in worker adapter: normalized events rebuild the temporal graph, generated
signals are consumed live or by replay, and deterministic `SecurityIncident`
revisions are appended with causal parents and deduplicated across restart or a
rewound cursor. Session/resource fields are promoted for conservative attack
chains. `EvidenceFusion` remains versioned but standalone. Fase 4 adds a
bounded/redacted `IncidentContext`,
anti-prompt-injection envelope, typed allowlisted actions and provider-neutral
`ModelBackend`; no model is invoked by this crate. Not implemented yet: runtime
L2/L4 wiring, live fusion of independent L1/L2/L3 scores, provider integration.
Fase 5 adds a deterministic
`PolicyEngine` foundation with TTL/allowlist/quorum checks, typed decisions and
an executor trait without external credentials; concrete response executors,
dedicated RBAC endpoints, and the adversarial gates P0–P2/C0–C2/S0–S4/R0–R3.
The §61–67 guards add leader epoch, expiring action leases, retry-stable action
IDs and an AI circuit breaker; these guards have no external I/O. The official
Fase 6 reversible response executors remain host-supplied; only a `DryRunExecutor`
is included.

The server treats a Sentinel startup/worker failure as a degraded optional
subsystem and continues serving the append-only log. External qualification of
the remaining gates is still required before any production/autonomous claim.
When replication is configured, the server currently keeps Sentinel disabled
until worker ownership can follow Raft leadership/epoch changes; it never runs
one authoritative derivation worker per replica.
