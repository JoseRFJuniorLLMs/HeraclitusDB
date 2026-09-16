# SPEC-0085 — Sandbox validation record

This record intentionally separates implementation qualification from live adversarial validation.

Implementation commit: `b30000f645ce75c2d9c87bfe8ff204974129dcf7`.

The next sandbox campaign must validate the compiled code, not merely unit tests:

- one-agent approval flood is bounded at `max_pending_per_agent`;
- multi-agent fan-out is bounded at `max_pending_global`;
- excess requests fail closed as `429 APPROVAL_QUEUE_FULL`;
- exact retry of an existing pending subject still returns the existing approval;
- no rejected request reaches the MCP upstream;
- `approval_capacity_rejected` is observable;
- evidence remains healthy with zero evidence-write errors;
- classic, massive, parser-differential and multi-agent adversarial regressions remain green.

Results belong in the generated sandbox report, not as pre-declared claims in this file.
