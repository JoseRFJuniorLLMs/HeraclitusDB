# SPEC-0081 — Strict MCP JSON Boundary

Status: implemented / qualification-gated.

## Red-team finding

A multi-agent campaign found two parser-boundary bypasses. Duplicate security-sensitive JSON keys were accepted with last-key-wins semantics, and an excessively deep `tools/call` body could fail parsing and then be misclassified as non-tool passthrough.

## Contract

Every non-empty MCP request body is parsed strictly before passthrough or policy classification. Duplicate object keys at any depth are invalid. Invalid JSON, trailing data, and parser depth failures are HTTP 400 with `MCP_JSON_INVALID`, and **zero bytes reach the upstream**. Valid protocol messages continue through normal policy/passthrough handling.

The response/SSE parser also uses the strict parser so evidence cannot silently normalize ambiguous upstream JSON.
