# Massive-v2 sandbox qualification

`massive_v2.py` is an authorized, loopback-only adversarial campaign for the HeraclitusDB Agent security plane. It refuses remote targets and uses only synthetic markers and a non-executing local MCP stub.

The campaign covers multi-agent deny swarms, cross-agent JSON-RPC id collisions, MCP method spelling ambiguity, header/body disagreement, non-tool data surfaces, approval consume races, cross-agent approval theft, typed-JSON approval binding, malformed JSON floods, HTTP method/content-type confusion, identity spelling variants, malformed and oversized OTLP pressure, Core/Agent credential separation, bounded red-team queries, and post-campaign evidence health.

The reporter persists only bounded metadata to `POST /api/v1/agent/red-team/events`; native gateway evidence remains the independent source for policy decisions, approvals, denial and external effects. A PASS therefore means the measured invariant held against the local synthetic topology, not that HeraclitusDB is universally invulnerable.
