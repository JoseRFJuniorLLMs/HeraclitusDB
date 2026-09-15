# SPEC-0079 — Agent Red-Team Observability

Status: IMPLEMENTED BY BRANCH / qualification pending.

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

## Safety

The reference runner is localhost-only by default and refuses non-loopback
hosts unless its source is deliberately changed. This is a qualification tool,
not a network scanner.
