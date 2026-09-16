# SPEC-0085 — Bounded Agent Evidence Under Hostile Flood

**Status:** IMPLEMENTATION / qualification pending  
**Origin:** authorized loopback-only sandbox red-team, 2026-09-16  
**Scope:** Agent Evidence persistence, generic projections and availability

## 1. Finding measured on the real release-mode binary

The authorization boundary held under a sustained local hostile-agent campaign, but the audit path amplified memory.

On exact branch build `f9dcffe327c98b67a1f3ad2f0ec839c4ec4ace75`, with the MCP Gateway in `enforce`, a synthetic upstream and all listeners bound to loopback:

- 20,000 denied `tools/call` requests: **20,000/20,000 HTTP 403**, upstream delta **0**, process alive, about **+229,148 KiB RSS**;
- 10,000 additional denied requests: **10,000/10,000 HTTP 403**, upstream delta **0**, process alive, about **+147,100 KiB RSS**;
- after ~30k denied requests the process was around **797 MiB RSS**;
- `evidence_errors=0`, `policy_errors=0`, `upstream_errors=0`.

This is not an authorization or integrity bypass. It is an **availability finding**: an attacker unable to execute a denied action can still force several durable evidence records per attempt, and those internal evidence records currently traverse the generic database projection path.

## 2. Root cause

Agent evidence is correctly persisted as ordinary append-only HRKL episodes so it receives an LSN and participates in durability and storage proofs. The problem is what happens *after* the append.

`EngineEvidenceStore::append_evidence` intentionally calls `Engine::append`, which then sends the resulting `EventKind::Custom("AgentEvidence")` episode through `Engine::index_applied`.

The generic path currently does all of the following for every evidence record:

1. clones it into the generic memtable;
2. applies it to every materialized generic view;
3. indexes `_agent`, `_kind` and all evidence attributes in the general-purpose `AttrIndex`.

The Agent Console/API does not require those generic projections to recover authoritative evidence. Its authority is the HRKL evidence store and Agent-specific projections. Keeping every denied attempt in unrelated text/vector/graph/general-attribute structures pays memory for representations that are not used to prove or inspect the denial.

## 3. Security invariant

**Never solve evidence-flood pressure by silently dropping canonical evidence.**

A request that the Gateway promises to record must still:

- append an `AgentEvidenceV1` to HRKL;
- receive an LSN;
- remain readable through the Agent evidence APIs;
- survive restart/replay;
- become eligible for Merkle/inclusion proof when its segment is sealed;
- preserve fail-closed behavior in `enforce` if the canonical append fails.

The optimization is projection isolation, not evidence suppression.

## 4. Projection isolation

`EventKind::Custom("AgentEvidence")` is an internal evidence-plane record.

For that kind, the generic engine projection path SHALL:

- **not** retain the full episode in the generic memtable;
- **not** feed the episode body/metadata into generic materialized views such as text/vector/graph/activation/telemetry views;
- **not** create general-purpose attribute postings for the Agent evidence envelope;
- **still advance projection watermarks** so boot replay and checkpoints do not repeatedly scan already-consumed internal evidence.

The live append path, boot catch-up path and explicit view rebuild path MUST make the same decision. Otherwise a restart would materialize records that the live path deliberately excluded and state hashes would depend on whether the node had restarted.

The general `AttrIndex` SHALL expose a watermark-only advance operation for intentionally non-indexed internal records. It MUST NOT fabricate postings.

## 5. Query semantics

This change deliberately means generic GQL/graph/text/vector queries are not the authoritative interface for `AgentEvidence`.

Agent evidence remains queryable through the Agent API and its dedicated projections. A user who asks the generic query layer for `EventKind::Custom("AgentEvidence")` MUST NOT receive a silently partial answer from an attribute-index shortcut. Planner fallback behavior must continue to scan the canonical log when a field/kind is not represented by the general index.

This is the same product boundary already implied by the dedicated Agent evidence APIs: security evidence is a first-class plane, not application graph content.

## 6. Required tests

Permanent tests SHALL prove:

1. a normal application episode still enters memtable/views/AttrIndex;
2. `AgentEvidence` advances the canonical log head and is recoverable from `EvidenceLog`;
3. `AgentEvidence` does not create generic AttrIndex postings;
4. generic view watermarks advance across skipped AgentEvidence without mutating the view state;
5. boot `catch_up` and explicit `rebuild` make the same skip decision as live append;
6. restart preserves Agent evidence and does not re-amplify generic projections;
7. Gateway deny/approval/replay tests remain green;
8. full workspace tests, release tests, Clippy and supply-chain gates remain green.

## 7. Live acceptance gate

Build the exact hardened head in release mode and run two fresh-process campaigns on equivalent empty data directories:

### Gate A — security

- at least 4,096 hostile requests from at least 256 synthetic agent identities;
- all denied actions remain denied;
- denied upstream delta remains zero;
- `evidence_errors=0`;
- service remains alive.

### Gate B — memory

Run at least 30,000 denied requests and record RSS before/after.

Acceptance is not “zero growth”, because the canonical log, allocator arenas, active segment buffers and bounded Agent projections legitimately consume memory. Acceptance requires:

- no growth proportional to retaining full generic copies of each evidence episode;
- post-flood RSS materially below the pre-fix baseline under the same workload;
- a second equal-sized flood must show a substantially flatter slope than the first, consistent with bounded caches rather than per-event generic retention.

The report MUST publish raw before/after KiB and requests/sec. No percentage-only victory claims.

## 8. Federal deployment posture

For production profiles, this fix is necessary but not sufficient. Continue to require:

- Core gRPC and REST authentication when Agent Gateway is `enforce` (SPEC-0084);
- OIDC/workload identity for agents rather than caller-supplied development headers;
- network topology that prevents direct upstream bypass;
- bounded ingress/rate controls at the deployment edge;
- resource limits and monitoring at the process/container/service layer.

HeraclitusDB should preserve every security-relevant fact it promises to preserve. It should not, however, turn each rejected action into half a dozen unrelated in-memory search structures and hand an attacker a RAM lever.