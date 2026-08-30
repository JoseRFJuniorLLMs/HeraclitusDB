# Runbook — Air-gapped install, update and recovery

## Bundle intake

1. Receive the offline bundle and public trust roots on controlled media.
2. On an intake station, verify bundle digest, every file digest, SBOM,
   provenance and detached signatures.
3. Malware-scan according to site policy, then record media custody.
4. Transfer into an isolated environment with independent egress monitoring.

## Install and zero-egress gate

Install only from bundled artifacts. Package managers must run in offline mode;
DNS and all external routes must be unavailable. Exercise startup, ingest,
query, backup and restore while a network sensor records attempted connections.
“No successful connection” is insufficient: the gate requires zero attempted
egress except endpoints explicitly declared inside the isolated enclave.

## Update and rollback

Verify the update bundle before stopping the current service. Take and verify a
backup, apply the signed update, run integrity/serve probes and exercise the
declared rollback path. Preserve both the current and previous qualified
release when policy permits.

## Offline recovery

MissionCritical recovery starts with no original package registry, CI service,
DNS, source checkout or running cluster. The stored bundle, trust roots,
configuration escrow, keystore custody and backup must be sufficient.
