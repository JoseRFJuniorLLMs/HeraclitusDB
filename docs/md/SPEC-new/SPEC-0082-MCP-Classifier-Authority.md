# SPEC-0082 — MCP Classifier Authority and Request Namespace

Status: implemented / qualification-gated.

## Red-team findings

A valid `tools/call` body could be paired with `mcp-method: resources/read` or `mcp-name: lookup_vendor`, causing policy and upstream to observe different classifications. Separately, JSON-RPC ids are only client-scoped, so using a bare id as approval identity caused unrelated agents reusing the same id to interfere with each other.

## Contract

The JSON-RPC body is authoritative for `method` and tool `name`. Capture helper headers never override body fields and `mcp-method`/`mcp-name` are stripped before forwarding. Approval logical request identity is namespaced by trusted agent identity + run correlation + JSON-RPC id. Same namespaced request mutation is still a binding mismatch; different agents or runs may safely reuse the same JSON-RPC id.
