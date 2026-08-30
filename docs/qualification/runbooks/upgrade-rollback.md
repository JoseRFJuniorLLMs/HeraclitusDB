# Runbook — Upgrade and rollback

1. Select N-1 (and N-2 when supported) official binaries and verify signatures.
2. Ingest the release dataset under the old binary; capture head, counts,
   sample hashes and backup manifest.
3. Run `Invoke-UpgradeMatrix.ps1` as format/migration preflight.
4. Upgrade while the configured workload continues. If rolling upgrade is
   supported, record the mixed-version interval and node order.
5. Verify head, counts, samples, canonical integrity, derived rebuild and serve.
6. Exercise rollback exactly as declared by `upgrade-matrix.json`.

If an on-disk migration is irreversible, set `rollback_supported=false` before
the run, list every irreversible transition and require operator
acknowledgement plus a tested backup restore. “Rollback” may never mean silently
starting an older binary on an unsupported format.

Any lost acknowledgement, schema ambiguity, undeclared irreversible change or
failed recovery blocks the gate.
