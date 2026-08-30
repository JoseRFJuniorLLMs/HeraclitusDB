# Signed qualification attestations

This directory is intentionally empty in source control apart from examples.
Laboratory evidence belongs to a release-specific immutable evidence store and
is copied here only for a qualification run.

Each JSON attestation has this contract:

```json
{
  "schema_version": 1,
  "gate_id": "q1_load",
  "release_version": "1.0.5-gov-candidate",
  "subject_binary_sha256": "64 lowercase hex characters",
  "issuer": "named laboratory or qualification authority",
  "executed_at_unix": 1787800000,
  "status": "passed",
  "findings": [],
  "metrics": { "p99_ms": 12.4 },
  "artifacts": [
    { "path": "q1/report.json", "sha256": "...", "size": 1234 }
  ],
  "signature": "q1_load.json.sig"
}
```

Paths in `artifacts` and `signature` are resolved relative to the attestation.
The configured verifier must validate the detached signature against the
laboratory trust root. A JSON file without successful cryptographic
verification is `Inconclusive`, even if it says `passed`.

Never commit private signing keys. Public trust roots live under
`qa/qualification/trust/`; release-specific evidence should normally remain in
the protected qualification archive.

## Which gates the project can produce evidence for, and which it cannot

The distinction matters more than it looks. A laboratory that re-runs the
project's own harness and signs the result is doing something useful; a
laboratory that signs a result it did not independently produce is not.

**The harness produces the artifact; the laboratory runs it and signs.** Attach
the JSON report the tool wrote as an `artifacts` entry:

| gate | artifact to attach | produced by |
|---|---|---|
| `q1_load` | `q1-load.json` | `heraclitus-qualifier load` |
| `q2_failure`, `crash_loop` | `crash-report.json` | `heraclitus-qualifier crash-loop` |
| `long_soak` | `soak-report.json` | `heraclitus-qualifier soak` |
| `corruption` | `result.json` | `Invoke-CorruptionMatrix.ps1` |
| `q4_upgrade`, `upgrade` | `result.json` | `Invoke-UpgradeMatrix.ps1` |
| `q6_restore` | `result.json` | `Invoke-Q6Restore.ps1` |
| `q5_node_loss`, `raft_failover` | `result.json` | `Invoke-RaftFailureMatrix.ps1` **plus the lab's own fault injector** |
| `sbom`, `supply_chain` | `bom.cdx.json`, `build-manifest.json` | `sbom` + the release workflow |
| `runbooks` | runbook check report | `heraclitus-qualifier runbooks` **plus the §118 execution record** |

**The laboratory produces the evidence; no harness here can.** For these,
attaching a report this repository generated would be circular:

| gate | why |
|---|---|
| `power_loss` | removing power is the hypervisor's or the PDU's job (§25); `kill -9` is explicitly not equivalent, and the crash report says so |
| `zero_egress` | the local monitor can prove egress happened, never that it did not; absence needs an independent network tap (§98) |
| `red_team`, `external_red_team` | §35 requires a team other than the one that implemented the component |
| `dr`, `airgap_install`, `airgap_update` | infrastructure, with measured RPO and RTO |
| `artifact_signature` | signing authority outside the build |

## Metrics worth recording

`metrics` feeds two things beyond the report: the §108 dashboard and the §126
regression comparison. Use the names in
`qa/qualification/regression-budgets.json`, because a metric under a different
name compares against nothing and shows as `Undetermined` — which is honest,
but useless.
