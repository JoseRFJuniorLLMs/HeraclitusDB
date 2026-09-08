# RC 1.0.6-rc.1 — content reconciliation

## Frozen scope

Base audit fixes: `536dd91` on top of `e669f77`. Worktree and branch inventory inspected on 2026-09-08; external workflow IDs `w1hug7jfg` and `wq2s4a1ln` are not accessible as running Codex tasks. This record does not claim that those workflows finished.

`git cherry main <branch>` was used to identify patch-equivalent commits, not just compare hashes.

Included remaining committed work:

| Source commit | Area | Integration |
| --- | --- | --- |
| `6fa5030` | Legacy crash-test helper path | `fda7a25`; additionally corrected helper profile selection |
| `27d1583` | Attribute checkpoint checksum | `8e05398` |
| `819b62e` | Attribute checkpoint rejection diagnostics | `1f53623` |
| `d63c2ef` | Sigma severity 0–10 | `8648876`; both severity and logsource regression tests retained |
| `17b9a67` | SIMULATE/REMOVE regression | `aea8232` |
| `e1ff3e0` | Crypto-shred snapshot regression | `c7f5f0a` |

Patch-equivalent work already present: btree, GPU metrics, Hume compression, zmap skip-scan, V6 scan branch, retrieval, Sentinel behavior/cursor/STIX and server gRPC groups. No duplicate cherry-picks were made.

## Explicit exclusions

The aud3/X2–X5 branches contain reproductions (including ignored failing tests), not completed fixes/verdicts. X1 has an untracked reproducer. Their source findings overlap the partial-audit fixes, but they are **not** evidence of independent approval of this RC. In particular X2's historical-MVCC expectation differs from the explicit unsupported-history contract chosen here.

Uncommitted edits were observed in wf3/server-cluster, wf3/server-engine, wf3/log-store and wf3/sentinel-correlation. These belong to ongoing work, were not overwritten, and are excluded from this RC. No claim of complete wave-2 closure or comprehensive security qualification is made. Pending changes need their own review and tests before a later candidate.

## Crash qualification defect

Nightly run `34202430123` failed before injection with `spawn crash_writer: NotFound`. `test_target_dir` removed only two path components, passing `<target>/debug` as Cargo's target root; Cargo then wrote `<target>/debug/debug/examples`, while spawn looked in `<target>/debug/examples`. Source commit `6fa5030` repairs the missing parent and adds a path assertion. RC preparation also selects the actual test profile in the nested build, so release tests do not run an obsolete debug helper.

After integration, the local Legacy campaign completed 1,000 injected kills (three tests passed). This reproduces the intended workload after fixing the harness; it does not retroactively turn the failed nightly run green or certify power-loss safety.

The earlier binary crash-loop was cancelled without a final report. Code inspection found whole-log ID searches repeated for every ACK, with a growing database and up to 60 seconds per query. The new verifier bounds each read to the acknowledged LSN, checks exact ID/LSN fields and verifies all ACKs; a no-ACK campaign fails. Whether this closes the runtime timeout must be confirmed by the Linux package campaign, not inferred from the optimization.

## Publication gate

The candidate CI and manual release-supply-chain run must both succeed before the pre-release is published. The latter qualifies the extracted archive, checks file hashes, and signs provenance bound to the artifact and crash report. No stable/latest designation, service deployment or production-data changes are authorized by this RC workflow.
