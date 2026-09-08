# HeraclitusDB v1.0.6-rc.1

Release candidate for evaluation on Linux x86_64. **Not a stable release or production qualification.** Do not migrate the only copy of a database; use a verified backup and an isolated test instance.

## Included

- Confirmed partial-audit fixes from `536dd91`: exact-or-error bounded queries, paged filtering and ordering; case-insensitive kind lookup; native timestamp protection; conservative LSN bounds; zero-result recall; graph ORDER variable resolution.
- Btree historical generations now fail explicitly instead of returning current leaves. Current-head reads remain supported.
- Sentinel L1 emits each occurrence; nested temporal horizons accumulate safely. External actions persist an execution attempt before dispatch, validate authorization constraints, reuse completed results and refuse ambiguous retries. The server reserves and accepts internal attempt events.
- Sigma rejects unsupported nonempty `logsource` and numeric severity outside 0–10.
- Key durability barriers before cache publication; idle GroupCommit barriers in Legacy and V6.
- Remaining committed wave-2 fixes: attribute checkpoint CRC and rebuild diagnostics; crash-test build-path correction; stronger SIMULATE/REMOVE and crypto-shred snapshot tests.
- Crash harness now builds its helper in the tested profile and verifies every acknowledged LSN and exact event ID after restart. It no longer performs an unbounded whole-database ID search per acknowledgement or accepts arbitrary JSON substrings as evidence.

## Compatibility and limitations

- Queries exceeding supported intermediate-result limits return an explicit error, not a partial result. Arbitrary global top-k optimization is not implemented.
- `BTree::get_snapshot` does not implement historical MVCC; finite historical generations are unsupported.
- Existing Sigma rules with `logsource` must not be broadened by simply deleting the restriction. A source mapping implementation is still required.
- An external action with an ambiguous outcome requires reconciliation. Exactly-once effects on arbitrary external systems are not promised; distributed hosts and destinations require persistent idempotency.
- Attribute checkpoints are written in derived format v6 with CRC-32 IEEE, not a cryptographic signature. Older v5/v4/v1 checkpoints remain readable but do not retroactively acquire checksum protection. Older binaries may rebuild the derived index after rollback; preserve backups and test rollback on a copy.
- No new canonical log format is introduced by this RC. This is not a blanket upgrade/rollback certification.
- The source audit is partial, not a review of all Rust files. Unfinished worktree edits and unresolved adversarial verdicts are excluded; see the reconciliation record.
- This package targets Linux x86_64 CPU execution. No GPU-runtime, Windows-binary, long-soak or physical power-loss qualification is claimed. SIGKILL leaves the OS page cache intact.
- SDK packages are not independently released by this server RC.

## Evidence and verification

Publication requires green CI for the candidate commit, a reproducible pair of Linux release builds, and successful recovery qualification of the **extracted package**. The attached crash report identifies the binary SHA-256, 40 requested/completed cycles, acknowledged writes and verification results. Read the actual artifact; a checklist or test count is not a substitute for evidence.

Assets include the Linux archive, SHA-256 checksum, CycloneDX SBOM, build manifest, crash report and Sigstore provenance bundle. Verify the archive checksum and provenance before executing it; the archive's `SHA256SUMS` covers the packaged files.
