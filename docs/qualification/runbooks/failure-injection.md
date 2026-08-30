# Runbook — Crash, corruption and physical power loss

## Process crash

Run both legacy and HRKL v6 crash suites with the candidate commit and a fixed
iteration count. Capture stdout/stderr and `CRASH_ITERS`. Reopen and verify the
log after every abrupt termination. A graceful shutdown is not crash evidence.

## Corruption matrix

Use `Invoke-CorruptionMatrix.ps1` against a copied, representative canonical
segment. It invokes the qualifier's deterministic injector for:

- bit flip;
- truncation;
- zeroed range;
- duplicated range;
- removed range.

Every corrupt canonical input must fail closed. Derived indexes may be rebuilt
only after the canonical log is proven intact. Preserve the unmodified source,
all mutants, injector records and verifier output.

## Physical power loss

`Invoke-PowerLossQualification.ps1 Prepare` starts the workload and produces an
Armed record. A separate PDU or hypervisor controller must then remove power.
The system under test must not issue its own shutdown and `kill -9` must not be
reported as power-loss.

After boot, run the script with `Recover`, the external controller record and a
full integrity verifier. Capture acknowledged head before the cut whenever the
client can persist it independently.

Hard gates:

- no acknowledged record disappears;
- torn tails are repaired or rejected according to format policy;
- mid-file corruption is never silently truncated;
- server can reopen and serve verified state;
- controller evidence proves that power was removed externally.
