//! O subconjunto do OTLP/trace que a ingestão precisa, escrito à mão.
//!
//! # Porque não gerar a partir dos `.proto` do OpenTelemetry
//!
//! Gerar exigiria vendorizar quatro ficheiros `.proto` de um repositório
//! externo, correr `protox`/`tonic-prost-build` no `build.rs` e passar a ter o
//! formato do wire a depender de uma cadeia de geração. O que a ingestão
//! precisa é de **cinco mensagens** cujos números de campo estão congelados
//! pela especificação OTLP há anos.
//!
//! Escrevê-las à mão dá três coisas: o build não ganha um passo, o `SBOM` não
//! ganha entradas, e os números de campo ficam visíveis e comentados ao lado do
//! código que os lê — que é onde alguém vai procurar quando um exporter mandar
//! algo inesperado.
//!
//! Campos que não usamos (links, flags, `dropped_*`) são declarados na mesma
//! quando ocupam um número de campo, porque o `prost` precisa de saber saltá-los
//! sem os tratar como desconhecidos — e porque um campo por declarar é um campo
//! que alguém vai reutilizar por engano.
//!
//! Referência: `opentelemetry/proto/trace/v1/trace.proto` e
//! `opentelemetry/proto/common/v1/common.proto`, OTLP 1.x.

use prost::Message;

// ── common.proto ──────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Message)]
pub struct AnyValue {
    #[prost(oneof = "any_value::Value", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub value: Option<any_value::Value>,
}

pub mod any_value {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Value {
        #[prost(string, tag = "1")]
        StringValue(String),
        #[prost(bool, tag = "2")]
        BoolValue(bool),
        #[prost(int64, tag = "3")]
        IntValue(i64),
        #[prost(double, tag = "4")]
        DoubleValue(f64),
        #[prost(message, tag = "5")]
        ArrayValue(super::ArrayValue),
        #[prost(message, tag = "6")]
        KvlistValue(super::KeyValueList),
        #[prost(bytes = "vec", tag = "7")]
        BytesValue(Vec<u8>),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct ArrayValue {
    #[prost(message, repeated, tag = "1")]
    pub values: Vec<AnyValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct KeyValueList {
    #[prost(message, repeated, tag = "1")]
    pub values: Vec<KeyValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct KeyValue {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(message, optional, tag = "2")]
    pub value: Option<AnyValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct InstrumentationScope {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub version: String,
    #[prost(message, repeated, tag = "3")]
    pub attributes: Vec<KeyValue>,
    #[prost(uint32, tag = "4")]
    pub dropped_attributes_count: u32,
}

// ── resource.proto ────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Message)]
pub struct Resource {
    #[prost(message, repeated, tag = "1")]
    pub attributes: Vec<KeyValue>,
    #[prost(uint32, tag = "2")]
    pub dropped_attributes_count: u32,
}

// ── trace.proto ───────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Message)]
pub struct TracesData {
    #[prost(message, repeated, tag = "1")]
    pub resource_spans: Vec<ResourceSpans>,
}

/// `ExportTraceServiceRequest` tem exactamente a mesma forma de wire que
/// `TracesData` (campo 1 repetido de `ResourceSpans`), portanto um só tipo
/// serve os dois — e não há como descodificar um com o esquema do outro.
pub type ExportTraceServiceRequest = TracesData;

#[derive(Clone, PartialEq, Message)]
pub struct ResourceSpans {
    #[prost(message, optional, tag = "1")]
    pub resource: Option<Resource>,
    #[prost(message, repeated, tag = "2")]
    pub scope_spans: Vec<ScopeSpans>,
    #[prost(string, tag = "3")]
    pub schema_url: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ScopeSpans {
    #[prost(message, optional, tag = "1")]
    pub scope: Option<InstrumentationScope>,
    #[prost(message, repeated, tag = "2")]
    pub spans: Vec<Span>,
    #[prost(string, tag = "3")]
    pub schema_url: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Span {
    #[prost(bytes = "vec", tag = "1")]
    pub trace_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub span_id: Vec<u8>,
    #[prost(string, tag = "3")]
    pub trace_state: String,
    #[prost(bytes = "vec", tag = "4")]
    pub parent_span_id: Vec<u8>,
    #[prost(string, tag = "5")]
    pub name: String,
    /// `SpanKind`: 0 unspecified, 1 internal, 2 server, 3 client, 4 producer,
    /// 5 consumer.
    #[prost(int32, tag = "6")]
    pub kind: i32,
    #[prost(fixed64, tag = "7")]
    pub start_time_unix_nano: u64,
    #[prost(fixed64, tag = "8")]
    pub end_time_unix_nano: u64,
    #[prost(message, repeated, tag = "9")]
    pub attributes: Vec<KeyValue>,
    #[prost(uint32, tag = "10")]
    pub dropped_attributes_count: u32,
    #[prost(message, repeated, tag = "11")]
    pub events: Vec<SpanEvent>,
    #[prost(uint32, tag = "12")]
    pub dropped_events_count: u32,
    #[prost(message, repeated, tag = "13")]
    pub links: Vec<SpanLink>,
    #[prost(uint32, tag = "14")]
    pub dropped_links_count: u32,
    #[prost(message, optional, tag = "15")]
    pub status: Option<Status>,
    #[prost(fixed32, tag = "16")]
    pub flags: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct SpanEvent {
    #[prost(fixed64, tag = "1")]
    pub time_unix_nano: u64,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(message, repeated, tag = "3")]
    pub attributes: Vec<KeyValue>,
    #[prost(uint32, tag = "4")]
    pub dropped_attributes_count: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct SpanLink {
    #[prost(bytes = "vec", tag = "1")]
    pub trace_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub span_id: Vec<u8>,
    #[prost(string, tag = "3")]
    pub trace_state: String,
    #[prost(message, repeated, tag = "4")]
    pub attributes: Vec<KeyValue>,
    #[prost(uint32, tag = "5")]
    pub dropped_attributes_count: u32,
    #[prost(fixed32, tag = "6")]
    pub flags: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct Status {
    #[prost(string, tag = "2")]
    pub message: String,
    /// 0 unset, 1 ok, 2 error.
    #[prost(int32, tag = "3")]
    pub code: i32,
}

// ── collector/trace/v1/trace_service.proto (resposta) ─────────────────────

#[derive(Clone, PartialEq, Message)]
pub struct ExportTraceServiceResponse {
    #[prost(message, optional, tag = "1")]
    pub partial_success: Option<ExportTracePartialSuccess>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ExportTracePartialSuccess {
    #[prost(int64, tag = "1")]
    pub rejected_spans: i64,
    #[prost(string, tag = "2")]
    pub error_message: String,
}

/// Representação textual plana de um [`AnyValue`], para alimentar o mapa de
/// atributos do modelo canónico.
///
/// Listas e mapas aninhados são achatados em JSON com um tecto de profundidade:
/// um atributo hostil com mil níveis de aninhamento não pode custar mil frames
/// de pilha (§12: "sem alocação sem limite" vale também para a pilha).
pub fn any_value_to_string(v: &AnyValue, depth: u8) -> String {
    use any_value::Value as V;
    const MAX_DEPTH: u8 = 4;
    match &v.value {
        None => String::new(),
        Some(V::StringValue(s)) => s.clone(),
        Some(V::BoolValue(b)) => b.to_string(),
        Some(V::IntValue(i)) => i.to_string(),
        // Os doubles do OTel entram como texto e nunca participam do hash
        // canónico como número: `{:?}` de f64 é a forma curta e estável do Rust.
        Some(V::DoubleValue(d)) => format!("{d:?}"),
        Some(V::BytesValue(b)) => format!("base16:{}", hex_lower(b)),
        Some(V::ArrayValue(a)) => {
            if depth >= MAX_DEPTH {
                return "[...]".to_string();
            }
            let items: Vec<String> = a
                .values
                .iter()
                .map(|x| any_value_to_string(x, depth + 1))
                .collect();
            serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string())
        }
        Some(V::KvlistValue(kv)) => {
            if depth >= MAX_DEPTH {
                return "{...}".to_string();
            }
            let map: std::collections::BTreeMap<String, String> = kv
                .values
                .iter()
                .map(|e| {
                    (
                        e.key.clone(),
                        e.value
                            .as_ref()
                            .map(|v| any_value_to_string(v, depth + 1))
                            .unwrap_or_default(),
                    )
                })
                .collect();
            serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
        }
    }
}

pub fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Descodifica um lote OTLP em protobuf.
pub fn decode_traces(bytes: &[u8]) -> Result<TracesData, prost::DecodeError> {
    TracesData::decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ida_e_volta_do_protobuf() {
        let td = TracesData {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".into(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("agent".into())),
                        }),
                    }],
                    dropped_attributes_count: 0,
                }),
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![Span {
                        trace_id: vec![1; 16],
                        span_id: vec![2; 8],
                        name: "chat".into(),
                        start_time_unix_nano: 7,
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        let bytes = td.encode_to_vec();
        let back = decode_traces(&bytes).unwrap();
        assert_eq!(back, td);
    }

    #[test]
    fn lixo_nao_entra_em_panico() {
        assert!(decode_traces(&[0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn aninhamento_hostil_tem_tecto() {
        let mut v = AnyValue {
            value: Some(any_value::Value::StringValue("fundo".into())),
        };
        for _ in 0..50 {
            v = AnyValue {
                value: Some(any_value::Value::ArrayValue(ArrayValue { values: vec![v] })),
            };
        }
        let s = any_value_to_string(&v, 0);
        assert!(s.contains("[..."), "{s}");
    }
}
