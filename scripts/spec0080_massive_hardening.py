from pathlib import Path

p = Path('crates/heraclitus-agent-gateway/src/gateway.rs')
text = p.read_text()
old = '''    let e_tool_call = facts
        .method
        .as_deref()
        .map(|m| m == "tools/call")
        .unwrap_or(false);

    // Tráfego que não é uma chamada de ferramenta (`initialize`, `tools/list`,
    // `ping`) passa sem policy e sem evidência. Registá-lo encheria a timeline
    // de ruído de protocolo e escondia as acções que interessam.
    if !e_tool_call {
        return forward_or_error(&state, &method, &uri, &upstream_header_map, body).await;
    }
'''
new = '''    let method_name = facts.method.as_deref().unwrap_or_default();
    let e_tool_call = method_name == "tools/call";

    // Near-miss spellings of `tools/call` are never forwarded. A permissive
    // upstream could normalize case, slash variants or percent encoding after
    // this gateway and thereby turn what looked like protocol traffic here into
    // a tool execution there. Unknown ordinary MCP methods may still pass
    // through; confusable tool-call spellings fail closed.
    if !e_tool_call {
        let mut normalized = method_name
            .trim()
            .to_ascii_lowercase()
            .replace('\\\\', "/")
            .replace('∕', "/")
            .replace('⁄', "/")
            .replace("%2f", "/")
            .replace("%5c", "/");
        while normalized.contains("//") {
            normalized = normalized.replace("//", "/");
        }
        if normalized == "tools/call" || normalized.starts_with("tools/call/") {
            return mcp_error(
                StatusCode::BAD_REQUEST,
                &None,
                "MCP_METHOD_INVALID",
                "confusable tools/call method spelling refused before upstream",
            );
        }

        return forward_or_error(&state, &method, &uri, &upstream_header_map, body).await;
    }
'''
if old not in text:
    raise SystemExit('target gateway snippet not found')
p.write_text(text.replace(old, new, 1))
