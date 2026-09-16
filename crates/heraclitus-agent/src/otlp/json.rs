//! OTLP/HTTP com `Content-Type: application/json`.
//!
//! O OTLP/JSON é a *Protobuf JSON mapping* aplicada às mesmas mensagens: os
//! campos vêm em `lowerCamelCase`, os `bytes` em hexadecimal (`traceId`), e os
//! inteiros de 64 bits em **string** (porque o JSON de um browser perderia
//! precisão num `f64`). Alguns coletores aceitam também `snake_case`, por isso
//! lemos as duas formas.
//!
//! Isto desce ao mesmo [`super::proto::TracesData`] que o protobuf produz, e
//! não a um caminho paralelo: a normalização, a redacção e o hash canónico são
//! os mesmos bytes-a-bytes venha o lote de onde vier. Duas normalizações
//! independentes é exactamente o defeito que a SPEC-0050 §27 chama de "dois
//! sinks".

use super::proto::{
    any_value, AnyValue, ArrayValue, InstrumentationScope, KeyValue, KeyValueList, Resource,
    ResourceSpans, ScopeSpans, Span, SpanEvent, Status, TracesData,
};
use super::OtlpError;
use serde_json::Value;

/// Descodifica um lote OTLP/JSON.
pub fn decode_traces_json(bytes: &[u8]) -> Result<TracesData, OtlpError> {
    let root: Value = serde_json::from_slice(bytes).map_err(|e| OtlpError::Json(e.to_string()))?;
    if !root.is_object() {
        return Err(OtlpError::Json(
            "OTLP/JSON top-level must be an object".to_string(),
        ));
    }
    let arr = match pick(&root, "resourceSpans", "resource_spans") {
        None => Vec::new(),
        Some(v) => v
            .as_array()
            .cloned()
            .ok_or_else(|| OtlpError::Json("resourceSpans must be an array".to_string()))?,
    };
    Ok(TracesData {
        resource_spans: arr.iter().map(resource_spans).collect(),
    })
}

fn pick<'a>(v: &'a Value, camel: &str, snake: &str) -> Option<&'a Value> {
    v.get(camel).or_else(|| v.get(snake))
}

fn resource_spans(v: &Value) -> ResourceSpans {
    ResourceSpans {
        resource: v.get("resource").map(|r| Resource {
            attributes: attributes(r),
            dropped_attributes_count: 0,
        }),
        scope_spans: pick(v, "scopeSpans", "scope_spans")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(scope_spans).collect())
            .unwrap_or_default(),
        schema_url: str_at(v, "schemaUrl", "schema_url"),
    }
}

fn scope_spans(v: &Value) -> ScopeSpans {
    ScopeSpans {
        scope: v.get("scope").map(|s| InstrumentationScope {
            name: s
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            version: s
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            attributes: attributes(s),
            dropped_attributes_count: 0,
        }),
        spans: v
            .get("spans")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(span).collect())
            .unwrap_or_default(),
        schema_url: str_at(v, "schemaUrl", "schema_url"),
    }
}

fn span(v: &Value) -> Span {
    Span {
        trace_id: hex_bytes(&str_at(v, "traceId", "trace_id")),
        span_id: hex_bytes(&str_at(v, "spanId", "span_id")),
        trace_state: str_at(v, "traceState", "trace_state"),
        parent_span_id: hex_bytes(&str_at(v, "parentSpanId", "parent_span_id")),
        name: v
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        kind: num_at(v, "kind", "kind").unwrap_or(0) as i32,
        start_time_unix_nano: num_at(v, "startTimeUnixNano", "start_time_unix_nano").unwrap_or(0),
        end_time_unix_nano: num_at(v, "endTimeUnixNano", "end_time_unix_nano").unwrap_or(0),
        attributes: attributes(v),
        dropped_attributes_count: 0,
        events: v
            .get("events")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(span_event).collect())
            .unwrap_or_default(),
        dropped_events_count: 0,
        links: Vec::new(),
        dropped_links_count: 0,
        status: v.get("status").map(|s| Status {
            message: s
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            code: status_code(s.get("code")),
        }),
        flags: 0,
    }
}

fn span_event(v: &Value) -> SpanEvent {
    SpanEvent {
        time_unix_nano: num_at(v, "timeUnixNano", "time_unix_nano").unwrap_or(0),
        name: v
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        attributes: attributes(v),
        dropped_attributes_count: 0,
    }
}

/// O `code` do `Status` chega ou como número ou como o nome do enum
/// (`STATUS_CODE_ERROR`), conforme o SDK. Aceitar os dois evita que um lote
/// perfeitamente válido seja lido como "sem erro".
fn status_code(v: Option<&Value>) -> i32 {
    match v {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0) as i32,
        Some(Value::String(s)) => match s.as_str() {
            "STATUS_CODE_OK" | "Ok" | "OK" => 1,
            "STATUS_CODE_ERROR" | "Error" | "ERROR" => 2,
            _ => 0,
        },
        _ => 0,
    }
}

fn attributes(v: &Value) -> Vec<KeyValue> {
    v.get("attributes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|kv| KeyValue {
                    key: kv
                        .get("key")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    value: kv.get("value").map(any_value_from_json),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn any_value_from_json(v: &Value) -> AnyValue {
    use any_value::Value as V;
    let inner = if let Some(s) = pick(v, "stringValue", "string_value").and_then(Value::as_str) {
        Some(V::StringValue(s.to_string()))
    } else if let Some(b) = pick(v, "boolValue", "bool_value").and_then(Value::as_bool) {
        Some(V::BoolValue(b))
    } else if let Some(i) = pick(v, "intValue", "int_value").and_then(json_i64) {
        Some(V::IntValue(i))
    } else if let Some(d) = pick(v, "doubleValue", "double_value").and_then(Value::as_f64) {
        Some(V::DoubleValue(d))
    } else if let Some(a) = pick(v, "arrayValue", "array_value") {
        Some(V::ArrayValue(ArrayValue {
            values: a
                .get("values")
                .and_then(Value::as_array)
                .map(|x| x.iter().map(any_value_from_json).collect())
                .unwrap_or_default(),
        }))
    } else if let Some(k) = pick(v, "kvlistValue", "kvlist_value") {
        Some(V::KvlistValue(KeyValueList {
            values: attributes(&serde_json::json!({ "attributes": k.get("values") })),
        }))
    } else {
        pick(v, "bytesValue", "bytes_value")
            .and_then(Value::as_str)
            .map(|s| V::BytesValue(hex_bytes(s)))
    };
    AnyValue { value: inner }
}

fn json_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn str_at(v: &Value, camel: &str, snake: &str) -> String {
    pick(v, camel, snake)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Inteiros de 64 bits chegam como string no OTLP/JSON. Aceitar também o número
/// cobre os SDK que não seguem o mapeamento à letra.
fn num_at(v: &Value, camel: &str, snake: &str) -> Option<u64> {
    match pick(v, camel, snake)? {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

/// Hex -> bytes, tolerante: um `traceId` malformado devolve vazio em vez de
/// derrubar o lote (§12: "um atributo opcional desconhecido não derruba o
/// lote" — e um campo mal formatado também não deve).
fn hex_bytes(s: &str) -> Vec<u8> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return Vec::new();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks(2) {
        let (Some(hi), Some(lo)) = (hexval(pair[0]), hexval(pair[1])) else {
            return Vec::new();
        };
        out.push((hi << 4) | lo);
    }
    out
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otlp::OtlpNormalizer;

    const LOTE: &str = r#"{
      "resourceSpans": [{
        "resource": { "attributes": [
          { "key": "service.name", "value": { "stringValue": "procurement-agent" } }
        ]},
        "scopeSpans": [{
          "scope": { "name": "opentelemetry.instrumentation.anthropic", "version": "0.1.0" },
          "spans": [{
            "traceId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "spanId": "bbbbbbbbbbbbbbbb",
            "name": "execute_tool send_payment",
            "startTimeUnixNano": "1700000000000000000",
            "endTimeUnixNano": "1700000002000000000",
            "attributes": [
              { "key": "gen_ai.operation.name", "value": { "stringValue": "execute_tool" } },
              { "key": "gen_ai.tool.name", "value": { "stringValue": "send_payment" } },
              { "key": "gen_ai.usage.input_tokens", "value": { "intValue": "1234" } }
            ],
            "status": { "code": "STATUS_CODE_OK" }
          }]
        }]
      }]
    }"#;

    #[test]
    fn json_e_protobuf_produzem_a_mesma_evidencia() {
        let from_json = decode_traces_json(LOTE.as_bytes()).unwrap();
        let bytes = {
            use prost::Message;
            from_json.encode_to_vec()
        };
        let from_proto = crate::otlp::proto::decode_traces(&bytes).unwrap();
        let n = OtlpNormalizer::new("t");
        assert_eq!(
            n.normalize(&from_json).evidences,
            n.normalize(&from_proto).evidences
        );
    }

    #[test]
    fn inteiros_em_string_sao_lidos() {
        let td = decode_traces_json(LOTE.as_bytes()).unwrap();
        let span = &td.resource_spans[0].scope_spans[0].spans[0];
        assert_eq!(span.start_time_unix_nano, 1_700_000_000_000_000_000);
        assert_eq!(span.end_time_unix_nano, 1_700_000_002_000_000_000);
        assert_eq!(span.trace_id.len(), 16);
        assert_eq!(span.span_id.len(), 8);
    }

    #[test]
    fn status_por_nome_e_reconhecido() {
        let td = decode_traces_json(LOTE.as_bytes()).unwrap();
        assert_eq!(
            td.resource_spans[0].scope_spans[0].spans[0]
                .status
                .as_ref()
                .unwrap()
                .code,
            1
        );
    }

    #[test]
    fn json_invalido_e_erro_e_nao_panico() {
        assert!(decode_traces_json(b"{nao e json").is_err());
    }

    #[test]
    fn top_level_otlp_json_tem_de_ser_objeto() {
        assert!(decode_traces_json(b"[]").is_err());
        assert!(decode_traces_json(b"null").is_err());
        assert!(decode_traces_json(br#"{"resourceSpans":{}}"#).is_err());
        assert!(decode_traces_json(b"{}").is_ok());
    }

    #[test]
    fn trace_id_malformado_nao_derruba_o_lote() {
        let lote = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[
            {"traceId":"zz","spanId":"bbbbbbbbbbbbbbbb","name":"x",
             "attributes":[{"key":"gen_ai.system","value":{"stringValue":"openai"}}]}
        ]}]}]}"#;
        let td = decode_traces_json(lote.as_bytes()).unwrap();
        assert!(td.resource_spans[0].scope_spans[0].spans[0]
            .trace_id
            .is_empty());
    }
}
