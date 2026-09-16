# SPEC — Heraclitus Top Security Operations View

Status: implementation plan for `heraclitus top`.

## Goal
Turn the existing Rust/Ratatui `heraclitus top` into an operational console that presents database health and real security alarms from telemetry already exposed by HeraclitusDB.

## Sources
- `/healthz`
- `/stats`
- `/state`
- `/sentinel/status`
- `/sentinel/dashboard`
- `/compliance/status`
- gRPC TCP reachability on :7474

## Alarm invariants
The UI must never invent a healthy state when a source is unavailable. Alarms are derived from measured facts only.

Critical alarms include:
- Sentinel threat level `critical`
- incident severity >= 8
- physical CRC failures > 0
- canonical verification failures > 0
- Sentinel queue overflow > 0
- incident capacity drops > 0
- Sentinel lag state `critical`
- action execution failures > 0
- deferred anchor forks > 0

Warnings include:
- active incident severity 5..7
- threat level `elevated`
- Sentinel degraded/catching-up
- detection lag > 0
- normalization errors > 0
- AI circuit state not closed/healthy
- overdue compliance deadlines
- pending ANPD work
- Parquet export lag
- REST/gRPC availability degradation

## UX
The top border must expose the global security posture at all times. The Security tab must show:
1. global threat posture and alarm counts,
2. active incident table (severity, risk, state, subjects, MITRE, first/last LSN),
3. Sentinel pipeline/queue/AI/action health,
4. storage and compliance integrity alarms.

The Overview tab should show a compact alarm banner so operators do not need to be on the Security tab to notice an attack.

## Evidence
An alarm must identify its source (`sentinel`, `storage`, `compliance`, `transport`) and the measured value that caused it. No heuristic should claim an attack solely from generic HTTP errors.
