# SPEC-0085 — Approval Flood Containment and Control-Plane Backpressure

**Status:** IMPLEMENTED  
**Date:** 2026-09-16  
**Scope:** Agent Policy Gateway / ApprovalStore / Agent Black Box

## 1. Finding

A live, loopback-only adversarial campaign against the sandbox build accepted **5,000 distinct approval-required operations in 1.811 s**, all as `202 APPROVAL_PENDING`. The live pending count reached **5,130** and server RSS rose by roughly **2.3 MiB** in that bounded sample. No protected tool executed and the evidence log remained healthy, but the hot approval index had no admission bound.

This is a control-plane denial-of-service primitive available to a compromised agent that is correctly prevented from executing the protected action but is still allowed to manufacture arbitrarily many distinct logical requests.

## 2. Security invariant

A compromised agent MUST NOT be able to make the live approval index grow without an operator-defined bound.

The invariant is independent of policy authorization. `require_approval` is a security control, therefore exhausting its queue is itself a security event.

## 3. Required controls

1. `ApprovalStore` admission MUST be atomic with respect to duplicate detection and capacity checks.
2. The gateway MUST enforce both:
   - a global bound on live pending approvals;
   - a per-agent bound so one compromised identity cannot consume the entire shared queue.
3. Exact retries of an already-pending logical request MUST continue returning the same approval and MUST NOT consume additional capacity.
4. Capacity rejection in `enforce` MUST fail closed with HTTP `429` and stable reason code `APPROVAL_QUEUE_FULL`.
5. The rejection MUST be visible in native evidence and in `/api/v1/agent/status` through a dedicated counter.
6. `shadow` MUST preserve its non-blocking policy semantics: when approval simulation capacity is exhausted it records/metrics the condition but does not pretend that an approval was created.
7. Limits MUST be explicit configuration under `[agent_gateway.approval]` with secure finite defaults.

## 4. Configuration

```toml
[agent_gateway.approval]
default_ttl_seconds = 300
max_pending_global = 4096
max_pending_per_agent = 64
```

Zero is invalid. `max_pending_per_agent` MUST NOT exceed `max_pending_global`.

## 5. Defaults

- `max_pending_global = 4096`
- `max_pending_per_agent = 64`

These are safety ceilings, not throughput targets. Operators with a legitimate larger approval workload may raise them deliberately after measuring memory and human review capacity.

## 6. Evidence

A capacity rejection records a native gateway evidence item with:

- agent identity;
- tool/resource identity;
- policy provenance;
- reason code `APPROVAL_QUEUE_FULL`;
- no raw secret/tool payload beyond the normal privacy profile.

The gateway counter `approval_capacity_rejected` increments exactly once per rejected admission.

## 7. Acceptance tests

The implementation is accepted only if all of the following hold:

1. 65 distinct pending requests from one agent with the default per-agent limit yield 64 pending and the 65th is rejected with `429 APPROVAL_QUEUE_FULL`.
2. An exact retry of one of the 64 pending requests still returns its original `202` approval id.
3. Concurrent admission cannot race beyond the configured limit.
4. Filling one agent's quota does not prevent another agent from using its own quota while global capacity remains.
5. The global bound is respected under multi-agent fan-out.
6. No capacity rejection reaches the MCP upstream.
7. `/api/v1/agent/status` remains `evidence_log=HEALTHY`, `evidence_errors=0`, and exposes `approval_capacity_rejected`.
8. Existing single-use, cross-agent theft, binding-mutation and approval-race tests remain green.

## 8. Non-goals

This SPEC does not claim to solve network volumetric DoS. It bounds the approval control-plane state created after a request reaches the local gateway. Network-level connection floods remain the responsibility of listener limits, service manager and host/network controls.
