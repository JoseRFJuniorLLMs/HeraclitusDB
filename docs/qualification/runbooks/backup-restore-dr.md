# Runbook — Backup, restore and disaster recovery

## Q6 empty-environment restore

1. Capture source head, counts, sample hashes, release digest and keystore
   custody reference.
2. Run `windows/heraclitus-backup.ps1 backup` and then `verify`.
3. Provision a clean destination that contains neither HeraclitusDB nor source
   data. Start the RTO clock at the declared incident point.
4. Use `Invoke-Q6Restore.ps1` to restore into a new path, run canonical verify
   and execute a serve/read probe.
5. Rebuild derived views from the canonical log. Never restore stale derived
   checkpoints as proof of correctness.
6. Compare head, counts, selected event hashes and policy/security state.
7. Record measured RPO and RTO, not target values.

Encrypted data requires the separately controlled keystore. Crypto-shredded
subject keys must not be resurrected by restore.

## DR drill

Assume the original host and service configuration are unavailable. Restore
the offline bundle, configuration, keystore subset and latest verified backup
in the DR environment. Repoint a test client only after integrity and serve
probes pass. GovernmentProduction requires a complete drill; MissionCritical
also requires multi-site and bare-infrastructure scenarios.

A backup is not valid qualification evidence until this restore procedure has
passed for the exact release family.
