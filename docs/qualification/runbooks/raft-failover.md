# Runbook — Raft failover and node loss

Execute every scenario in `qa/qualification/matrices/raft-failure-matrix.json`
against the same signed candidate binary on 3-node hardware. MissionCritical
also requires the 5-node matrix.

For each scenario:

1. record members, term, leader, committed index and client acknowledgement;
2. inject exactly one named fault through an independent controller;
3. continue a deterministic write/read workload;
4. measure detection, election, write-unavailable and catch-up time;
5. heal the fault and wait for convergence;
6. compare committed histories and event hashes on every node;
7. retry timed-out operations with stable idempotency keys;
8. archive controller logs and cluster metrics.

Without quorum, writes must fail closed. Any split brain, committed-entry loss,
divergent history or duplicated external action is an immediate failure.
Unit tests and in-process turmoil simulations are preflight evidence, not a
substitute for host and network fault injection.
