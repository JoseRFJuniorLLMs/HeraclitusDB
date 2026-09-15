# SPEC-0080 — Per-Request Approval Binding

Status: implemented and qualification-gated.

An approval binds to policy, identity, resource, action, arguments and the stable logical request id. Same request id plus changed content is a binding mismatch. Same request id after consumption is replay. A new request id is a new operation and may request a fresh approval even when its arguments are identical to a prior operation. An unrelated granted approval cannot poison another request. Approval-required MCP calls without a stable JSON-RPC id fail closed.
