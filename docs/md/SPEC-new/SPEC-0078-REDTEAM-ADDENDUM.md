# SPEC-0078 Red-Team Addendum — Gateway fail-closed after hostile-agent sandbox qualification

Status: PROPOSED / SECURITY-BLOCKING

This addendum records vulnerabilities reproduced against an isolated localhost-only HeraclitusDB laboratory and extends SPEC-0078 with mandatory closure gates before production deployment of the Agent Policy Gateway.

## Threat model

Assume an AI agent is hostile or prompt-injected and can fully control its HTTP request body, MCP/Heraclitus metadata headers, JSON-RPC ids, run ids and retry timing. In OIDC mode it may also omit, corrupt or replay bearer credentials. The upstream MCP/API server is safety critical and must never receive a tool invocation unless the gateway authenticated the caller, interpreted the same semantic action the upstream will receive, evaluated policy for that action, recorded the decision, and, where required, consumed an exact single-use human approval.

## Findings reproduced in the sandbox

### P0-1 JSON-RPC batch bypass

A JSON-RPC array containing `tools/call` was not classified as a tool call when `mcp-method` was absent. The request reached the upstream without policy or tool evidence.

Closure: in ENFORCE, batches MUST be rejected locally with `MCP_BATCH_UNSUPPORTED` until per-item atomic policy enforcement exists. Zero upstream calls.

### P0-2 header/body semantic confusion

`mcp-method` and `mcp-name` were trusted before the JSON body. A caller could label the request `lookup_vendor` while the body sent `exec`; policy evaluated the benign header and the upstream received the dangerous body.

Closure: the JSON-RPC body is canonical semantic truth. Contradictory classification headers MUST fail closed with `MCP_SEMANTIC_MISMATCH`. Headers may assist observability only when equal to body semantics.

### P0-3 method confusion

`mcp-method: tools/list` with a body containing `tools/call` bypassed policy as protocol traffic.

Closure: same as P0-2. Classification used for authorization MUST equal the body forwarded upstream.

### P0-4 production OIDC gateway accepted unauthenticated tool traffic

OIDC protected the console/API, but the MCP gateway proxy did not authenticate before forwarding. A request without `Authorization` reached the upstream.

Closure: every gateway request MUST pass the configured identity validator before any forwarding in OIDC/basic modes. Missing or invalid credentials return 401 and produce zero upstream calls. In OIDC mode the authenticated token subject, not spoofable `x-heraclitus-agent`, is the canonical agent subject.

### P1-1 dedupe collision hides a second agent/run

Two different agents/runs reusing the same JSON-RPC id on the same MCP server collided because dedupe omitted agent/run scope. Both external requests reached upstream while one run could disappear from evidence.

Closure: MCP dedupe identity MUST include agent id and run id in addition to existing source/protocol ids. Exact retry inside the same agent/run remains deduplicated; a different agent or run MUST never collide.

### P1-2 arbitrary-path reverse proxy

The fallback router forwarded unrelated paths such as `/admin/delete` to the upstream without MCP policy/evidence.

Closure: default gateway surface is `POST /mcp` only. Other paths/methods are rejected locally. Additional MCP transports, if needed, require explicit configured allowlists and their own policy tests.

### P1-3 bypass-protection status overclaims topology

`bypass_protection_configured=true` is an operator assertion, not proof that firewall/ACL topology prevents direct agent-to-upstream traffic.

Closure: status/UI/documentation MUST report this as `DECLARED`, not `CONFIGURED`/verified. Production runbooks MUST require an external network control proving the upstream is unreachable directly from the agent.

### P1-4 custom approval roles lost by fixed RBAC enum

An OIDC token carrying roles such as `approver,cfo` lost the custom `cfo` claim because only console RBAC roles were retained. A policy requesting `cfo` could not be satisfied except through broad system-admin override.

Closure: preserve normalized raw OIDC role claims separately from fixed console RBAC roles. Approval-policy role matching uses the authenticated raw claims, while console/API authorization continues to use the fixed `Role` enum. Unknown claims grant no console privilege by themselves.

## Mandatory regression gates

1. OIDC gateway, no bearer -> 401, upstream delta 0.
2. OIDC gateway, invalid bearer -> 401, upstream delta 0.
3. Valid OIDC token plus spoofed `x-heraclitus-agent` -> policy/evidence subject equals authenticated token subject.
4. Header says allow-listed tool, body says denied tool -> `MCP_SEMANTIC_MISMATCH`, upstream delta 0.
5. Header says non-tool method, body says `tools/call` -> `MCP_SEMANTIC_MISMATCH`, upstream delta 0.
6. JSON-RPC batch containing a tool call -> `MCP_BATCH_UNSUPPORTED`, upstream delta 0.
7. POST to an unapproved path -> local 404/405, upstream delta 0.
8. Non-POST on `/mcp` -> 405, upstream delta 0.
9. Same agent/run/tool-call id exact retry -> existing dedupe behavior remains stable.
10. Different agent or run with same JSON-RPC id -> distinct evidence, no collision.
11. OIDC token with `approver,cfo` can approve a `cfo` rule; `approver` without `cfo` cannot.
12. Status must never imply network bypass protection was cryptographically or actively verified when only the configuration assertion exists.
13. Existing approval binding, single-use approval, expiry, privacy/redaction, malformed OTLP, oversized input and concurrent DENY tests remain green.
14. `cargo clippy --all-targets --all-features -- -D warnings` is green for touched crates/workspace as feasible.
15. `cargo audit` is green except explicitly documented, time-bounded risk acceptances already approved elsewhere in the repository.

## Production invariant

A hostile agent MUST NOT be able to make the upstream perform an action whose authenticated principal, semantic tool name, arguments, policy decision and evidence record disagree. Any ambiguity at these boundaries fails closed.

This addendum remains SECURITY-BLOCKING until every gate above is executable and green in CI and the corresponding sandbox exploit no longer reaches the harmless upstream stub.