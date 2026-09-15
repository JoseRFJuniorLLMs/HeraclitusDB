from pathlib import Path

p = Path('crates/heraclitus-agent-gateway/src/gateway.rs')
s = p.read_text()
needle = '''    let method_name = facts.method.as_deref().unwrap_or_default();\n    let e_tool_call = method_name == "tools/call";\n'''
replacement = '''    let method_name = facts.method.as_deref().unwrap_or_default();\n    if !mcp_method_is_canonical(method_name) {\n        return mcp_error(\n            StatusCode::BAD_REQUEST,\n            &facts.tool_call_id,\n            "MCP_METHOD_INVALID",\n            "MCP method must use the canonical ASCII alphabet [A-Za-z0-9._/-] and be <= 128 bytes",\n        );\n    }\n    let e_tool_call = method_name == "tools/call";\n'''
if needle not in s:
    raise SystemExit('classification insertion point not found')
s = s.replace(needle, replacement, 1)

marker = '''async fn proxy(\n'''
helper = '''fn mcp_method_is_canonical(method: &str) -> bool {\n    !method.is_empty()\n        && method.len() <= 128\n        && method.bytes().all(|b| {\n            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.')\n        })\n}\n\n'''
if helper not in s:
    if marker not in s:
        raise SystemExit('proxy marker not found')
    s = s.replace(marker, helper + marker, 1)

# Put regression tests at the end of the module file.
tests = r'''

#[cfg(test)]
mod method_canonical_tests {
    use super::mcp_method_is_canonical;

    #[test]
    fn standard_mcp_methods_use_canonical_alphabet() {
        for method in [
            "initialize",
            "ping",
            "tools/list",
            "tools/call",
            "resources/read",
            "prompts/get",
        ] {
            assert!(mcp_method_is_canonical(method), "{method}");
        }
    }

    #[test]
    fn ambiguous_or_encoded_methods_are_rejected() {
        for method in [
            "tools／call",
            "tools﹨call",
            "tools＼call",
            "tools%252Fcall",
            "tools%252fcall",
            "tools/call\u{200b}",
            "tools/\u{200b}call",
            "tools/call\0",
            "tools\\call",
            "tools call",
            "tools\tcall",
        ] {
            assert!(!mcp_method_is_canonical(method), "unexpectedly canonical: {method:?}");
        }
        assert!(!mcp_method_is_canonical(""));
        assert!(!mcp_method_is_canonical(&"a".repeat(129)));
    }
}
'''
if 'mod method_canonical_tests' not in s:
    s += tests

p.write_text(s)
