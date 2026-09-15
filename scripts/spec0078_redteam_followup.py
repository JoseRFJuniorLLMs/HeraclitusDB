from pathlib import Path

p = Path("crates/heraclitus-agent-gateway/src/gateway.rs")
text = p.read_text()
old = '''    // Server identity is derived from the configured upstream, never from an
    // attacker-controlled header. A contradictory header is rejected instead
    // of being allowed to select a weaker policy rule.
    let server_id = state
        .upstream
        .as_ref()
        .and_then(|u| u.base().host().map(str::to_string))
        .unwrap_or_else(|| "upstream".to_string());
    if let Some(claimed) = header_map.get("x-heraclitus-server") {
        if claimed != &server_id {
            return mcp_error(
                StatusCode::BAD_REQUEST,
                &None,
                "MCP_SERVER_MISMATCH",
                "x-heraclitus-server não corresponde ao upstream configurado",
            );
        }
    }
'''
new = '''    // A logical MCP server id is useful in dev_local tests and local PoCs, but
    // an authenticated hostile client must never be able to select policy
    // context with x-heraclitus-server. In authenticated modes we bind the
    // policy resource to the configured upstream host.
    let configured_server = state
        .upstream
        .as_ref()
        .and_then(|u| u.base().host().map(str::to_string))
        .unwrap_or_else(|| "upstream".to_string());
    let server_id = if principal.mode == AuthMode::DevLocal {
        header_map
            .get("x-heraclitus-server")
            .cloned()
            .unwrap_or(configured_server)
    } else {
        configured_server
    };
'''
if old not in text:
    raise SystemExit("post-codemod server identity block not found")
p.write_text(text.replace(old, new, 1))
print("SPEC-0078 follow-up applied: logical server header scoped to dev_local")
