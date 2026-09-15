# SPEC-0084 — Agent ENFORCE Core Auth Barrier

**Status:** PROPOSED → qualification in security branch  
**Origin:** authorized loopback-only red-team campaign, 2026-09-15

## 1. Finding

The live sandbox proved that loopback is not a sufficient trust boundary when the threat model is a compromised local agent.

With the Agent Gateway in `enforce`, no gRPC credentials configured, and the Core bound to `127.0.0.1`, the generated official gRPC client was able to call `Admin(stats)` and `Append` with no metadata. The append advanced the Core head. This was not a TCP reachability observation; it was an authenticated-identity bypass by design: `Authenticator::resolver` maps the no-credential profile to `local-loopback` with `Admin`.

That behavior is convenient for ordinary local development, but it contradicts the meaning of an Agent Gateway in `enforce`: an agent process executing on the same host can bypass the gateway and mutate the source of truth directly.

A second configuration-truth issue was found while tracing the boundary: `AgentPlane::validate` treated `rest_basic_auth`, Core gRPC auth and Agent-console auth as one generic boolean even though they protect different listeners.

## 2. Security invariants

### INV-1 — ENFORCE means no anonymous Core bypass

When `[agent_gateway] enabled = true` and `mode = "enforce"`, server startup SHALL fail unless both Core network surfaces have authentication configured:

- gRPC: `auth_token` or `access_credentials`;
- REST: `rest_basic_auth` or `access_credentials`.

Loopback does not waive this invariant. The attacker being modeled is a local agent.

This does not remove the historical unauthenticated loopback development profile when the Agent Gateway is disabled, `observe`, or `shadow`. It makes the stronger promise opt-in and truthful.

### INV-2 — one surface's password does not secure another surface

`rest_basic_auth` MUST NOT count as authentication for Agent Console / OTLP. Agent Black Box validation SHALL use the credentials actually consumed by the Agent plane.

### INV-3 — OTLP `require_auth` must be real

If `[agent_black_box.otlp] require_auth = true`, a valid `[agent_black_box.console] basic_auth = "user:password"` SHALL exist. A configuration where `require_auth=true` silently resolves to no credential is invalid.

In `production_mode`, a non-loopback OTLP HTTP or gRPC listener SHALL require OTLP authentication in addition to the existing transport/authentication gates.

## 3. Required behavior

### Enforce startup matrix

| Gateway | Core gRPC auth | Core REST auth | Expected |
|---|---:|---:|---|
| off / observe / shadow | no | no | existing loopback dev behavior retained |
| enforce | no | yes | startup rejected |
| enforce | yes | no | startup rejected |
| enforce | yes | yes | startup accepted |
| enforce | `access_credentials` | same RBAC credentials | startup accepted |

### Runtime proof

For an accepted `enforce` configuration, the sandbox SHALL prove:

1. gRPC `Admin` with no metadata returns `UNAUTHENTICATED`;
2. gRPC `Append` with no metadata returns `UNAUTHENTICATED` and does not advance head;
3. gRPC with the configured bearer credential still works;
4. REST with no credential remains rejected;
5. MCP denied calls still produce zero upstream effects;
6. the Agent evidence log remains healthy.

## 4. Agent-plane auth truth

The Agent Black Box console is protected only by its own Basic credential or the configured Agent OIDC validator. Host REST Basic is not a substitute.

OTLP Basic authentication is backed by the Agent Console shared credential today. Therefore `require_auth=true` without that credential is an invalid configuration rather than an apparently protected but actually open listener.

## 5. Tests

Permanent tests SHALL include:

- enforce rejects missing Core gRPC auth;
- enforce rejects missing Core REST auth;
- enforce accepts legacy bearer + REST Basic for development qualification;
- enforce accepts multi-principal RBAC credentials (which cover both Core surfaces);
- shadow retains the historical loopback no-auth development profile;
- OTLP require-auth without Agent Basic credential is rejected;
- production public OTLP without require-auth is rejected.

## 6. Deployment recommendation

For federal production deployments, use `access_credentials` with at least separate Admin and Writer principals, TLS/mTLS as already required by the production profile, and OIDC for Agent identity. The legacy single Admin bearer and REST Basic pair are accepted here only to keep controlled local demonstrations and migration paths usable.

## 7. Acceptance

Qualified only after focused unit tests, full Agent/Gateway tests, Clippy, release build, and a live loopback red-team rerun proving anonymous gRPC Admin/Append are closed while authenticated operation remains functional.
