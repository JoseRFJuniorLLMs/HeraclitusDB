# Runbook — Q3 security campaign and red team

Use qa/qualification/matrices/attack-matrix.json to scope the campaign.
Provide the red team with the candidate binary digest, supported protocols,
threat model, tenant model and explicit rules of engagement. Do not provide
private customer data or production credentials.

Every finding needs a stable ID, attack ID, severity, reproduction evidence,
affected binary digest, configuration digest, owner and disposition. Fixed
vulnerabilities should gain a regression test whenever technically possible.
Risk acceptance must name an authority, expiry and compensating controls.

Q3 includes malformed protocols, authentication and authorization boundaries,
tenant isolation, configuration abuse, resource exhaustion and adversarial
state-machine behavior. Fuzzing alone is not a red team.

For MissionCritical, the assessment and evidence verification must be
independent.

Open critical findings block GovernmentProduction. High findings require the
formal policy disposition defined in the qualification plan; hiding or deleting
a historical failure is forbidden.

## Deep campaign harness

The repository contains two complementary laboratories:

~~~text
labs/Agent-Atack-Heraclitus/
    MCP / Agent Gateway / approvals / replay / hostile agents

labs/Deep-RedTeam-Heraclitus/
    tenant isolation
    privileged admin fault injection
    valid-but-expensive queries
    HRKL rollback/substitution
    hostile Raft peers
~~~

The deep runner is intentionally loopback-only. It refuses remote targets,
mutates only temporary storage copies and kills only child processes that it
started.

Validate the harness before a campaign:

~~~bash
python3 labs/Deep-RedTeam-Heraclitus/runner.py --self-test
~~~

## Required deep campaigns

### Tenant isolation

Use at least two synthetic tenants and distinct authenticated principals.

For every enabled data plane, try the same logical object through both the
authorized and cross-tenant identity.

At minimum cover:

- telemetry;
- security events;
- Agent Evidence;
- text;
- vector;
- graph;
- analytics;
- historical AS OF;
- cold recall;
- export/backup.

The authenticated identity is authoritative. Tenant identifiers supplied by the
caller are selectors only and must never elevate or cross the principal scope.

### Privileged administration under faults

For each irreversible operation, inject process death, disk failure or quorum
loss at the boundaries:

~~~text
validate
  |
durable intent
  |
side effect
  |
durable result
~~~

Required operations include crypto-shred, Legal Hold, Legal Hold removal, key
rotation/destruction and security-policy change.

Required invariant:

~~~text
NO DURABLE INTENT
    =>
NO IRREVERSIBLE SIDE EFFECT
~~~

A crash after a side effect but before a durable result must recover as a
defined SUCCEEDED, FAILED or UNKNOWN/RECONCILE state. It must not blindly retry
a non-idempotent action.

### Query resource isolation

Do not limit Q3 to malformed requests. A valid query can be a denial-of-service
primitive.

Exercise:

- external-table/file-read regression;
- DML rejection on read-only SQL;
- bounded concurrent valid queries;
- result limits;
- timeouts;
- cancellation;
- per-tenant noisy-neighbor behavior.

Record CPU, RSS, result bytes, disk reads/spill, latency and whether unrelated
tenants preserve their declared SLO.

### HRKL rollback and substitution

Corruption testing must include semantically valid but wrong artifacts, not only
random bit flips.

Exercise:

- bit flip;
- valid segment from a different database;
- valid segment from a different tenant;
- old manifest generation;
- new manifest with old segment and the inverse;
- wrong cold generation/logical root.

A locally valid old state does not prove freshness. Anti-rollback claims require
a monotonic root/head anchored outside the mutable host or another explicit
freshness authority.

### Raft hostile peer

The current TCP transport has a declared network trust boundary. Q3/Q5 must
therefore test that boundary instead of quietly assuming it.

Exercise:

- oversized frame;
- malformed bincode;
- rogue peer reachability;
- old/tampered snapshot;
- AppendEntries replay;
- old leader returning after heal;
- membership races;
- follower restored from stale backup.

If deployment policy requires authenticated peers or mTLS, raw unauthenticated
reachability becomes a critical failure. If private network isolation is the
declared control, independently prove that isolation and attach the evidence.

## Evidence requirements

Each deep attack result should preserve:

~~~text
attack_id
campaign_id
binary_sha256
configuration_digest
request_or_fixture_digest
expected_invariant
observed_effect
timestamps
resource deltas where applicable
PASS / FAIL / FINDING / SKIP
~~~

SKIP is never PASS.

A FINDING may be an accepted trust boundary, but acceptance must be explicit,
time-bounded and tied to compensating controls.

The campaign report should be attached to the Q3 attestation for the exact
candidate binary.
