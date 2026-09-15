from pathlib import Path


def rep(path, old, new, n=1):
    p=Path(path); s=p.read_text()
    if s.count(old)<n: raise SystemExit(f'pattern missing {path}: {old[:120]!r}')
    p.write_text(s.replace(old,new,n))

mcp='crates/heraclitus-agent/src/mcp.rs'
rep(mcp,
'''            if facts.method.is_none() {
                facts.method = v.get("method").and_then(Value::as_str).map(str::to_string);
            }''',
'''            // The JSON-RPC body is authoritative. Caller-controlled helper
            // headers are capture hints only and may never override the message
            // that the upstream will actually parse.
            if let Some(method) = v.get("method").and_then(Value::as_str) {
                facts.method = Some(method.to_string());
            }''')
rep(mcp,
'''                if facts.tool_name.is_none() {
                    facts.tool_name = params
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                }''',
'''                if let Some(name) = params.get("name").and_then(Value::as_str) {
                    facts.tool_name = Some(name.to_string());
                }''')

# Add body-authority regression test in mcp tests.
needle='''    #[test]
    fn strict_json_aceita_tool_call_normal() {'''
test='''    #[test]
    fn corpo_json_rpc_prevalece_sobre_headers_de_classificacao() {
        let mut ex = McpExchange::default();
        ex.request_headers.insert(HEADER_METHOD.into(), "resources/read".into());
        ex.request_headers.insert(HEADER_NAME.into(), "lookup_vendor".into());
        ex.request_body = Some(br#"{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"exec","arguments":{}}}"#.to_vec());
        let facts = extract_facts(&ex);
        assert_eq!(facts.method.as_deref(), Some("tools/call"));
        assert_eq!(facts.tool_name.as_deref(), Some("exec"));
    }

'''+needle
rep(mcp,needle,test)

gw='crates/heraclitus-agent-gateway/src/gateway.rs'
rep(gw,
'''    upstream_header_map.remove("authorization");''',
'''    upstream_header_map.remove("authorization");
    // Classification hints are never forwarded. The body is the single
    // security/protocol authority, preventing header-vs-body parser differential.
    upstream_header_map.remove("mcp-method");
    upstream_header_map.remove("mcp-name");''')

old='''                let Some(logical_request_id) = facts
                    .tool_call_id
                    .as_deref()
                    .filter(|id| !id.trim().is_empty())
                    .map(str::to_string)
                else {'''
new='''                let Some(raw_request_id) = facts
                    .tool_call_id
                    .as_deref()
                    .filter(|id| !id.trim().is_empty())
                    .map(str::to_string)
                else {'''
rep(gw,old,new)
needle2='''                };
                let authorization = ActionAuthorizationV1 {'''
new2='''                };
                // JSON-RPC ids are scoped to a client/session, not globally.
                // Namespace them by trusted agent identity and run correlation so
                // 256 agents may all use id=1 without poisoning one another.
                let logical_request_id = format!(
                    "{}:{}:{}",
                    agent_id,
                    exchange.run_id.as_deref().unwrap_or(""),
                    raw_request_id
                );
                let authorization = ActionAuthorizationV1 {'''
rep(gw,needle2,new2)

Path('docs/md/SPEC-new/SPEC-0082-MCP-Classifier-Authority.md').write_text('''# SPEC-0082 — MCP Classifier Authority and Request Namespace

Status: implemented / qualification-gated.

## Red-team findings

A valid `tools/call` body could be paired with `mcp-method: resources/read` or `mcp-name: lookup_vendor`, causing policy and upstream to observe different classifications. Separately, JSON-RPC ids are only client-scoped, so using a bare id as approval identity caused unrelated agents reusing the same id to interfere with each other.

## Contract

The JSON-RPC body is authoritative for `method` and tool `name`. Capture helper headers never override body fields and `mcp-method`/`mcp-name` are stripped before forwarding. Approval logical request identity is namespaced by trusted agent identity + run correlation + JSON-RPC id. Same namespaced request mutation is still a binding mismatch; different agents or runs may safely reuse the same JSON-RPC id.
''')
