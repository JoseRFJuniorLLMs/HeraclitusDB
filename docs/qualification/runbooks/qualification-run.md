# Runbook — Qualification run and chain of custody

## Preconditions

1. Reserve a clean Git checkout at the exact candidate commit.
2. Record the release version and build profile; use `Cargo.lock` and `--locked`.
3. Build the candidate binary once. Never rebuild between trials.
4. Store private signing material outside the checkout, preferably in an HSM.
5. Copy the appropriate plan and replace its candidate version, target and
   binary path. Review every trial assurance level.
6. Synchronize clocks according to the laboratory policy and record any drift.

## Procedure

1. Generate the candidate SBOM with `heraclitus-qualifier sbom`.
2. Generate deterministic datasets with the exact profile, seed and event
   count recorded in the Q1 attestation.
3. Run each lab campaign and sign its JSON attestation. Preserve raw logs,
   metrics and controller evidence; never edit a failed result.
4. Execute `heraclitus-qualifier run --plan <plan> --out <new-directory>`.
5. Interpret exit codes: `0=Passed`, `1=Failed`, `2=Unqualified`. Exit 2 is an
   expected safe result while evidence is missing.
6. Run `heraclitus-qualifier verify --evidence <directory>` on a second host.
7. Sign `evidence-index.json`, `qualification-report.md` and the candidate
   binary digest. Store the public certificate and signature with the dossier.
8. Move the entire directory into write-once or retention-controlled storage.

## Abort conditions

- candidate binary digest changes;
- source tree is dirty for RC or higher;
- clock, hardware, filesystem or network environment is undocumented;
- any gate reports `Failed`;
- evidence verifier, signature verifier or digest comparison fails;
- an operator attempts to convert `Skipped`/`Inconclusive` into `Passed`.

Restart with a new qualification ID. Never overwrite or delete the failed run.
