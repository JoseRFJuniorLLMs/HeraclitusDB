from pathlib import Path


def rep(path: str, old: str, new: str, n: int = 1) -> None:
    p = Path(path)
    s = p.read_text()
    if s.count(old) < n:
        raise SystemExit(f"pattern not found in {path}: {old[:140]!r}")
    p.write_text(s.replace(old, new, n))

mcp = "crates/heraclitus-agent/src/mcp.rs"
rep(
    mcp,
    "use serde::{Deserialize, Serialize};\nuse serde_json::Value;\nuse std::collections::BTreeMap;",
    "use serde::de::{self, MapAccess, SeqAccess, Visitor};\nuse serde::{Deserialize, Deserializer, Serialize};\nuse serde_json::{Map, Number, Value};\nuse std::collections::{BTreeMap, HashSet};",
)

anchor = '''/// O payload JSON-RPC de um corpo MCP, seja ele JSON puro ou enquadrado em SSE.'''
strict = r'''/// JSON de fronteira MCP: recusa chaves duplicadas em qualquer profundidade.
///
/// `serde_json::Value` por si só aceita a última ocorrência de uma chave. Em uma
/// fronteira de policy isso cria parser differential: policy pode interpretar um
/// campo e o upstream outro. Este wrapper torna a representação ambígua inválida.
struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Value;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON sem chaves duplicadas")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Value, E> { Ok(Value::Bool(v)) }
            fn visit_i64<E>(self, v: i64) -> Result<Value, E> { Ok(Value::Number(v.into())) }
            fn visit_u64<E>(self, v: u64) -> Result<Value, E> { Ok(Value::Number(v.into())) }
            fn visit_f64<E>(self, v: f64) -> Result<Value, E>
            where E: de::Error {
                Number::from_f64(v).map(Value::Number).ok_or_else(|| E::custom("número JSON inválido"))
            }
            fn visit_str<E>(self, v: &str) -> Result<Value, E>
            where E: de::Error { Ok(Value::String(v.to_owned())) }
            fn visit_string<E>(self, v: String) -> Result<Value, E> { Ok(Value::String(v)) }
            fn visit_none<E>(self) -> Result<Value, E> { Ok(Value::Null) }
            fn visit_unit<E>(self) -> Result<Value, E> { Ok(Value::Null) }
            fn visit_some<D>(self, d: D) -> Result<Value, D::Error>
            where D: Deserializer<'de> { StrictJson::deserialize(d).map(|v| v.0) }
            fn visit_seq<A>(self, mut seq: A) -> Result<Value, A::Error>
            where A: SeqAccess<'de> {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element::<StrictJson>()? { out.push(v.0); }
                Ok(Value::Array(out))
            }
            fn visit_map<A>(self, mut map: A) -> Result<Value, A::Error>
            where A: MapAccess<'de> {
                let mut out = Map::new();
                let mut seen = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!("chave JSON duplicada: {key}")));
                    }
                    let value = map.next_value::<StrictJson>()?.0;
                    out.insert(key, value);
                }
                Ok(Value::Object(out))
            }
        }
        deserializer.deserialize_any(StrictVisitor).map(StrictJson)
    }
}

fn strict_json(body: &[u8]) -> Result<Value, String> {
    let mut de = serde_json::Deserializer::from_slice(body);
    let value = StrictJson::deserialize(&mut de).map_err(|e| e.to_string())?.0;
    de.end().map_err(|e| e.to_string())?;
    Ok(value)
}

/// Valida um corpo JSON-RPC de PEDIDO antes de qualquer decisão de passthrough.
/// JSON inválido, profundo demais ou ambíguo nunca chega ao upstream.
pub fn validate_request_json(body: &[u8]) -> Result<(), String> {
    strict_json(body).map(|_| ())
}

'''
rep(mcp, anchor, strict + anchor)
rep(
    mcp,
    "    if let Ok(v) = serde_json::from_slice::<Value>(body) {\n        return Some(v);\n    }",
    "    if let Ok(v) = strict_json(body) {\n        return Some(v);\n    }",
)
rep(
    mcp,
    "        let v = serde_json::from_str::<Value>(acc.trim()).ok();",
    "        let v = strict_json(acc.trim().as_bytes()).ok();",
)

# Tests before the existing test module's final area.
marker = "#[cfg(test)]\nmod tests {"
rep(mcp, marker, marker)
# inject right after mod tests opening/imports by looking for first use super
rep(
    mcp,
    "mod tests {\n    use super::*;",
    '''mod tests {
    use super::*;

    #[test]
    fn strict_json_rejeita_method_duplicado() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"resources/read","params":{}}"#;
        assert!(validate_request_json(raw).unwrap_err().contains("duplicada"));
    }

    #[test]
    fn strict_json_rejeita_chave_duplicada_aninhada() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","name":"lookup_vendor","arguments":{}}}"#;
        assert!(validate_request_json(raw).unwrap_err().contains("duplicada"));
    }

    #[test]
    fn strict_json_aceita_tool_call_normal() {
        let raw = br#"{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"exec","arguments":{"command":"safe-marker"}}}"#;
        assert!(validate_request_json(raw).is_ok());
    }

    #[test]
    fn strict_json_rejeita_profundidade_excessiva() {
        let mut raw = String::from("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\",\"arguments\":{\"x\":");
        raw.push_str(&"[".repeat(256));
        raw.push('0');
        raw.push_str(&"]".repeat(256));
        raw.push_str("}}}");
        assert!(validate_request_json(raw.as_bytes()).is_err());
    }
''',
)

gateway = "crates/heraclitus-agent-gateway/src/gateway.rs"
anchor2 = '''    // Gateway credentials authenticate to the gateway, not to its upstream.
    let mut upstream_header_map = header_map.clone();'''
insert = '''    // A policy boundary may never turn a parser failure into passthrough. A
    // non-empty MCP request with invalid/ambiguous JSON is rejected before the
    // upstream sees a byte. This closes duplicate-key differential parsing and
    // excessive-depth bypasses found by the multi-agent red team.
    if !body.is_empty() {
        if let Err(detail) = mcp::validate_request_json(&body) {
            return mcp_error(
                StatusCode::BAD_REQUEST,
                &None,
                "MCP_JSON_INVALID",
                &detail,
            );
        }
    }

'''
rep(gateway, anchor2, insert + anchor2)

spec = Path("docs/md/SPEC-new/SPEC-0081-Strict-MCP-JSON-Boundary.md")
spec.write_text('''# SPEC-0081 — Strict MCP JSON Boundary

Status: implemented / qualification-gated.

## Red-team finding

A multi-agent campaign found two parser-boundary bypasses. Duplicate security-sensitive JSON keys were accepted with last-key-wins semantics, and an excessively deep `tools/call` body could fail parsing and then be misclassified as non-tool passthrough.

## Contract

Every non-empty MCP request body is parsed strictly before passthrough or policy classification. Duplicate object keys at any depth are invalid. Invalid JSON, trailing data, and parser depth failures are HTTP 400 with `MCP_JSON_INVALID`, and **zero bytes reach the upstream**. Valid protocol messages continue through normal policy/passthrough handling.

The response/SSE parser also uses the strict parser so evidence cannot silently normalize ambiguous upstream JSON.
''')
