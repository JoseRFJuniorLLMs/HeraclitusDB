# SPEC-0080 — MCP Non-Tool Governance

**Status:** PROPOSED / implementation in the same qualification branch  
**Scope:** Heraclitus Agent Policy Gateway  
**Origin:** sandbox multi-agent red-team, 2026-09-15

## 1. Problem

The MCP gateway currently applies deterministic policy to `tools/call`, but forwards every other canonical MCP method to the upstream. The sandbox campaign demonstrated that `resources/read` and `prompts/get` cross the gateway exactly like harmless control methods such as `ping` and `tools/list`.

That is not a `tools/call` policy bypass. It is nevertheless a governance gap: a compromised agent may be unable to execute a denied tool while still reading sensitive resources or prompts from the same MCP server.

## 2. Security invariant

In `enforce`, an MCP data-bearing method MUST NOT reach the upstream merely because it is not `tools/call`.

The gateway SHALL distinguish protocol-control traffic from data-bearing non-tool traffic. Unknown non-tool methods fail closed in `enforce`.

## 3. Method classes

### 3.1 Control/read-only discovery methods allowed by default

The following methods may pass without tool policy:

- `initialize`
- `ping`
- `tools/list`
- `resources/list`
- `resources/templates/list`
- `prompts/list`
- `logging/setLevel`

Notifications (`notifications/*`) may pass if their method spelling is canonical.

These methods are protocol/discovery traffic. Allowing them does not imply that returned metadata is non-sensitive; deployments needing stricter discovery controls SHOULD place the upstream behind an additional network or application authorization boundary.

### 3.2 Data-bearing non-tool methods denied by default in enforce

At minimum:

- `resources/read`
- `resources/subscribe`
- `resources/unsubscribe`
- `prompts/get`
- `completion/complete`

Unknown request methods also fail closed in `enforce`.

`observe` continues forwarding while recording the security decision; `shadow` records a would-deny decision but does not block.

## 4. Evidence

A denied or shadow-denied non-tool method SHALL create durable native evidence before a response is returned. The evidence MUST include:

- canonical MCP method;
- trusted agent identity when available;
- run/trace correlation identifiers;
- upstream/server identity derived from configuration, not caller headers;
- reason code `MCP_NON_TOOL_DENIED` or `MCP_UNKNOWN_METHOD_DENIED`;
- enforced flag;
- transport outcome;
- LSN when persistence succeeds.

Raw resource contents, prompt contents, credentials and Authorization headers MUST NOT be copied into the evidence record.

In `enforce`, inability to persist the denial evidence is fail-closed.

## 5. Compatibility

This is intentionally a security tightening. Installations that relied on transparent `resources/read` or `prompts/get` through an ENFORCE gateway must explicitly redesign that access instead of receiving an accidental allow.

## 6. Red-team gates

The localhost-only `Agent-Atack-Heraclitus` suite MUST prove:

1. `resources/read` => blocked in ENFORCE, upstream delta 0;
2. `prompts/get` => blocked in ENFORCE, upstream delta 0;
3. `completion/complete` => blocked in ENFORCE, upstream delta 0;
4. unknown canonical method => blocked in ENFORCE, upstream delta 0;
5. `ping` and `tools/list` still reach the synthetic upstream;
6. `tools/call` behavior is unchanged;
7. denial evidence survives concurrent attempts without `evidence_errors`;
8. malformed or duplicate-key JSON is rejected before method classification.

## 7. Acceptance

SPEC-0080 is IMPLEMENTED only when focused gateway tests, Agent tests, Clippy and the localhost red-team regression are green. A full repository CI run remains required before merge to `main`.
