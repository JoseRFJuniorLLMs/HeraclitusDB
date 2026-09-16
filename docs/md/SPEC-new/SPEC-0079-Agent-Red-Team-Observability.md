# SPEC-0079 — Agent Red-Team Observability

Status: **IMPLEMENTED / QUALIFIED (2026-09-15)**.

## Goal

Make authorized adversarial tests visible and durable without pretending that
self-reported lab telemetry is the same thing as a native gateway decision.

## Contract

`POST /api/v1/agent/red-team/events` records **metadata only** in the Agent
Evidence log/HRKL. It never persists an offensive payload, credential, prompt,
Authorization header, shell command or exploit body. The writer needs the same
administrative capability used for capture changes. `GET` is read-only and uses
the ordinary run-view permission.

Each event carries `attack_id`, `campaign_id`, vector, target, phase, result,
expected result, reason code, `blocked`, `upstream_delta` and transport status.
The resulting response returns the evidence id and LSN.

## Trust boundary

A `redteam_lab` record proves that this reporter record was appended to HRKL at
that LSN. It does **not**, by itself, prove that an external effect did or did
not happen. Native `PolicyEvaluated`, `ToolDenied`, approval and
`ExternalEffectObserved` evidence remains the authoritative independent side of
the correlation. The Dashboard must show this distinction.

## Demonstration requirement

The laboratory runner uses a campaign id and unique attack ids. It performs the
real request against localhost, measures the observed response and upstream hit
delta when available, then reports only the safe metadata. The Dashboard shows
both the lab event stream and the native Agent Black Box counters/timeline.

## Qualification evidence — 2026-09-15

The loopback-only laboratory was executed against the release-mode server
artifact built from commit `138c46d141aee0fe2cf84bed0c15f69f847cc670`.
The reference runner completed **17/17 probes successfully**. The persisted
`red-team/events` query returned the same 17 probes with HRKL LSNs, including
Core authentication failures, malformed and oversized OTLP, MCP deny/allow,
JSON-RPC batch bypass check, approval single-use/replay, approval argument
mutation, 64-way concurrent DENY, invalid policy reload, bundle path traversal
and oversized identity headers.

The native Agent status remained `evidence_log=HEALTHY` and
`mcp_gateway=ENFORCE` after the campaign. Native Gateway counters independently
recorded policy DENY and approval replay activity; the synthetic upstream hit
counter independently confirmed zero forwarding for the explicit DENY, mixed
batch bypass check, argument-mutation denial and 64-request DENY flood.

The live campaign also exposed a native observability flaw around approval
retries: multiple HTTP attempts could legitimately reuse the same MCP
`tool_call_id`, causing the gateway evidence dedupe key to collide. Commit
`441935b2db857c74c2ec0f2bc6afc466e8bb5862` hardened that path so every gateway
HTTP attempt receives distinct durable evidence identity while OTLP keeps its
trace/span retry semantics. In `ENFORCE`, an unexpected evidence conflict is now
fail-closed rather than merely logged.

The SPEC-0078 final qualification pass also completed successfully after
removing the vulnerable `lru 0.12.5` dependency path through the CLI, running
focused Agent/Gateway regressions, Clippy and the RustSec gate with only the
repository's explicitly documented risk acceptances.

## Safety

The reference runner is **loopback-only** and refuses non-loopback hosts. There
is no `--allow-remote` escape hatch. Its synthetic upstream never executes a
shell, filesystem operation, subprocess or external network action. This is a
qualification and demonstration tool, not a network scanner.
