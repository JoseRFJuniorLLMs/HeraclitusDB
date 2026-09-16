//! SPEC-0074 §13 — captura MCP.
//!
//! # Dois modos, uma responsabilidade
//!
//! ```text
//! observe   o host emite metadados; nós normalizamos
//! proxy     Agent -> Heraclitus MCP Proxy -> MCP Server
//! ```
//!
//! Na SPEC-0074 o proxy existe **para evidência**. O bloqueio pertence à
//! SPEC-0075 e mora no gateway; aqui só se observa e se normaliza.
//!
//! # A correlação que torna a timeline legível
//!
//! ```text
//! ToolRequested -> ToolInvocationStarted -> ToolInvocationFinished
//! ```
//!
//! correlacionados por `tool_call_id`. Sem essa correlação a Consola mostraria
//! três linhas soltas e o utilizador teria de as juntar com os olhos.
//!
//! # Nunca persistir bearer token
//!
//! Os cabeçalhos de uma chamada MCP passam pelo [`crate::privacy`] como
//! qualquer outro conteúdo. O `Authorization` não sobrevive, em modo nenhum.

use crate::dedupe;
use crate::evidence::{
    AgentEvidenceKindV1, AgentEvidenceV1, AgentIdentityV1, EvidenceOutcomeV1, EvidenceSourceV1,
};
use crate::privacy::{self, RawContent, RedactionProfile};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use std::collections::{BTreeMap, HashSet};

/// Versão do core MCP com que a captura foi escrita.
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

/// Cabeçalhos que o MCP HTTP transporta e que classificam a chamada cedo,
/// antes de olhar para o corpo (§13).
pub const HEADER_METHOD: &str = "mcp-method";
pub const HEADER_NAME: &str = "mcp-name";
pub const HEADER_SESSION: &str = "mcp-session-id";
pub const HEADER_PROTOCOL: &str = "mcp-protocol-version";

/// Uma troca MCP observada.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpExchange {
    pub tenant_id: String,
    /// `observe` ou `proxy`.
    pub capture_mode: String,
    pub server_id: String,
    /// Cabeçalhos do pedido, tal como chegaram.
    #[serde(default)]
    pub request_headers: BTreeMap<String, String>,
    /// Corpo JSON-RPC do pedido.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<Vec<u8>>,
    /// Corpo JSON-RPC da resposta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_status: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_nanos: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_subject: Option<String>,
    pub observed_at_unix_nanos: u64,
}

/// O que a captura conseguiu perceber da troca.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpCallFacts {
    pub method: Option<String>,
    pub tool_name: Option<String>,
    pub tool_call_id: Option<String>,
    pub session_id: Option<String>,
    pub protocol_version: Option<String>,
    /// `true` quando a resposta MCP declara erro (`isError` ou `error`).
    pub is_error: bool,
    pub error_message: Option<String>,
    /// Argumentos para policy/preview, achatados para strings. Mantemos esta
    /// projecção por compatibilidade com as policies existentes.
    pub arguments: BTreeMap<String, String>,
    /// Representação canónica TIPADA dos mesmos argumentos, exclusivamente
    /// para authorization binding. JSON string `"75000"` e JSON number `75000`
    /// têm de produzir digests diferentes, mesmo que a policy os projecte para
    /// a mesma string.
    pub binding_arguments: BTreeMap<String, String>,
    /// Identificadores de efeito externo que a resposta devolveu, por
    /// allowlist (SPEC-0075 §25).
    pub external_effect_id: Option<String>,
}

/// Nomes de campo cujo valor, vindo do upstream, pode virar `external_effect_id`.
///
/// É uma **allowlist** e não um heurístico: mapear qualquer campo que pareça um
/// identificador transformaria dados do upstream em afirmações do produto.
pub const EXTERNAL_EFFECT_FIELDS: &[&str] = &[
    "payment_id",
    "paymentId",
    "transaction_id",
    "transactionId",
    "ticket_id",
    "ticketId",
    "commit_sha",
    "commitSha",
    "deployment_id",
    "deploymentId",
    "order_id",
    "orderId",
];

/// JSON de fronteira MCP: recusa chaves duplicadas em qualquer profundidade.
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
            fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
                Ok(Value::Number(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
                Ok(Value::Number(v.into()))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Value, E>
            where
                E: de::Error,
            {
                Number::from_f64(v)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("número JSON inválido"))
            }
            fn visit_str<E>(self, v: &str) -> Result<Value, E>
            where
                E: de::Error,
            {
                Ok(Value::String(v.to_owned()))
            }
            fn visit_string<E>(self, v: String) -> Result<Value, E> {
                Ok(Value::String(v))
            }
            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_some<D>(self, d: D) -> Result<Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                StrictJson::deserialize(d).map(|v| v.0)
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element::<StrictJson>()? {
                    out.push(v.0);
                }
                Ok(Value::Array(out))
            }
            fn visit_map<A>(self, mut map: A) -> Result<Value, A::Error>
            where
                A: MapAccess<'de>,
            {
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
    let value = StrictJson::deserialize(&mut de)
        .map_err(|e| e.to_string())?
        .0;
    de.end().map_err(|e| e.to_string())?;
    Ok(value)
}

/// Valida um corpo JSON-RPC de PEDIDO antes de qualquer decisão de passthrough.
/// JSON inválido, profundo demais ou ambíguo nunca chega ao upstream.
pub fn validate_request_json(body: &[u8]) -> Result<(), String> {
    strict_json(body).map(|_| ())
}

/// O payload JSON-RPC de um corpo MCP, seja ele JSON puro ou enquadrado em SSE.
///
/// # Porque é que isto é preciso
///
/// O MCP Streamable HTTP permite ao servidor responder em `text/event-stream`,
/// e na prática **todos** os servidores MCP HTTP públicos que testámos o fazem
/// (Context7, DeepWiki, Cloudflare docs, GitMCP). O corpo não é JSON: é
///
/// ```text
/// event: message
/// data: {"jsonrpc":"2.0","id":1,"result":{...}}
/// ```
///
/// Antes disto, o `serde_json::from_slice` falhava e o erro era engolido por um
/// `if let Ok`. A consequência não era cosmética: `is_error` ficava `false`, e
/// uma tool call que o upstream tinha RECUSADO era gravada no log append-only
/// com `protocol_status: "ok"`. Um black box que regista um fracasso como
/// sucesso é pior do que não ter black box — alguém lê o relatório e conclui o
/// contrário do que aconteceu.
///
/// # O que isto NÃO resolve
///
/// O gateway continua a bufferizar a resposta inteira antes de a devolver. Para
/// um upstream que fecha o stream depois de responder (o caso de todos os que
/// medimos) isso funciona; para um que mantenha o stream aberto, o pedido
/// espera pelo timeout. Streaming verdadeiro é outro trabalho, e está por fazer.
fn payload_jsonrpc(body: &[u8]) -> Option<Value> {
    // O caminho normal primeiro: a esmagadora maioria dos corpos de PEDIDO, e
    // as respostas de servidores que não usam SSE.
    if let Ok(v) = strict_json(body) {
        return Some(v);
    }
    let texto = std::str::from_utf8(body).ok()?;

    // SSE: várias linhas `data:` dentro do mesmo evento concatenam-se com "\n"
    // (RFC do EventSource). Um corpo pode trazer mais do que um evento; fica o
    // primeiro que seja uma resposta JSON-RPC, porque é esse que corresponde ao
    // pedido que fizemos.
    let mut acumulado = String::new();
    let evento_terminado = |acc: &mut String| -> Option<Value> {
        if acc.is_empty() {
            return None;
        }
        let v = strict_json(acc.trim().as_bytes()).ok();
        acc.clear();
        v.filter(|v| v.get("result").is_some() || v.get("error").is_some())
    };
    for linha in texto.lines() {
        let linha = linha.strip_suffix('\r').unwrap_or(linha);
        if linha.is_empty() {
            if let Some(v) = evento_terminado(&mut acumulado) {
                return Some(v);
            }
            continue;
        }
        if let Some(dados) = linha.strip_prefix("data:") {
            if !acumulado.is_empty() {
                acumulado.push('\n');
            }
            acumulado.push_str(dados.strip_prefix(' ').unwrap_or(dados));
        }
        // `event:`, `id:`, `retry:` e comentários (`:`) não interessam aqui.
    }
    evento_terminado(&mut acumulado)
}

/// Extrai o que se consegue de uma troca, sem falhar por campos em falta.
pub fn extract_facts(ex: &McpExchange) -> McpCallFacts {
    let mut facts = McpCallFacts {
        method: header(ex, HEADER_METHOD),
        tool_name: header(ex, HEADER_NAME),
        session_id: header(ex, HEADER_SESSION),
        protocol_version: header(ex, HEADER_PROTOCOL),
        ..Default::default()
    };

    if let Some(body) = &ex.request_body {
        if let Some(v) = payload_jsonrpc(body) {
            // The JSON-RPC body is authoritative. Caller-controlled helper
            // headers are capture hints only and may never override the message
            // that the upstream will actually parse.
            if let Some(method) = v.get("method").and_then(Value::as_str) {
                facts.method = Some(method.to_string());
            }
            facts.tool_call_id = v
                .get("id")
                .map(|id| match id {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .filter(|s| !s.is_empty() && s != "null");
            if let Some(params) = v.get("params") {
                if let Some(name) = params.get("name").and_then(Value::as_str) {
                    facts.tool_name = Some(name.to_string());
                }
                if let Some(args) = params.get("arguments").and_then(Value::as_object) {
                    for (k, val) in args {
                        facts.arguments.insert(k.clone(), flatten(val));
                        facts.binding_arguments.insert(
                            k.clone(),
                            serde_json::to_string(val).unwrap_or_else(|_| "null".to_string()),
                        );
                    }
                }
            }
        }
    }

    if let Some(body) = &ex.response_body {
        if let Some(v) = payload_jsonrpc(body) {
            if v.get("error").is_some() {
                facts.is_error = true;
                facts.error_message = v
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
            if let Some(result) = v.get("result") {
                if result.get("isError").and_then(Value::as_bool) == Some(true) {
                    facts.is_error = true;
                }
                facts.external_effect_id = find_effect_id(result, 0);
            }
        }
    }
    facts
}

fn header(ex: &McpExchange, name: &str) -> Option<String> {
    ex.request_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty())
}

fn flatten(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Procura um identificador de efeito externo, com tecto de profundidade.
fn find_effect_id(v: &Value, depth: u8) -> Option<String> {
    const MAX_DEPTH: u8 = 4;
    if depth > MAX_DEPTH {
        return None;
    }
    match v {
        Value::Object(map) => {
            for field in EXTERNAL_EFFECT_FIELDS {
                if let Some(x) = map.get(*field) {
                    let s = flatten(x);
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
            }
            map.values().find_map(|x| find_effect_id(x, depth + 1))
        }
        Value::Array(a) => a.iter().find_map(|x| find_effect_id(x, depth + 1)),
        _ => None,
    }
}

/// Converte uma troca MCP nas evidências correlacionadas de §13.
///
/// Produz o trio `ToolRequested -> ToolInvocationStarted ->
/// ToolInvocationFinished` quando há resposta, e só os dois primeiros quando a
/// troca ainda está aberta. Um método MCP que não seja `tools/call` produz
/// zero evidências: `initialize` e `tools/list` são tráfego de protocolo, não
/// acções do agente.
pub fn exchange_to_evidences(ex: &McpExchange, profile: &RedactionProfile) -> Vec<AgentEvidenceV1> {
    let facts = extract_facts(ex);
    let is_tool_call = facts
        .method
        .as_deref()
        .map(|m| m == "tools/call")
        .unwrap_or(false)
        || (facts.method.is_none() && facts.tool_name.is_some());
    if !is_tool_call {
        return Vec::new();
    }

    let request_raw = RawContent {
        content_type: Some("application/json".into()),
        body: ex.request_body.clone(),
        fields: facts.arguments.clone(),
        headers: ex.request_headers.clone(),
    };
    let request_redacted = privacy::apply(profile, &request_raw);

    let start = ex.observed_at_unix_nanos;
    let end = start.saturating_add(ex.duration_nanos.unwrap_or(0));

    let mut out = Vec::new();
    let push = |kind: AgentEvidenceKindV1, at: u64, content_from_response: bool| {
        let mut e = AgentEvidenceV1::new(ex.tenant_id.clone(), kind, at);
        e.trace_id = ex.trace_id.clone();
        e.run_id = ex.run_id.clone().or_else(|| ex.trace_id.clone());
        e.session_id = facts.session_id.clone();
        e.agent = AgentIdentityV1 {
            agent_id: ex
                .agent_id
                .clone()
                .unwrap_or_else(|| "unknown-agent".to_string()),
            framework: Some("mcp".into()),
            framework_version: facts
                .protocol_version
                .clone()
                .or_else(|| Some(MCP_PROTOCOL_VERSION.to_string())),
            ..Default::default()
        };
        if let Some(h) = &ex.human_subject {
            e.human = Some(crate::evidence::HumanIdentityRefV1 {
                subject_id: h.clone(),
                ..Default::default()
            });
        }
        e.subject.protocol = Some("mcp".into());
        e.subject.server_id = Some(ex.server_id.clone());
        e.subject.tool_name = facts.tool_name.clone();
        e.subject.tool_call_id = facts.tool_call_id.clone();
        if content_from_response {
            let raw = RawContent {
                content_type: Some("application/json".into()),
                body: ex.response_body.clone(),
                ..Default::default()
            };
            let red = privacy::apply(profile, &raw);
            e.content = red.content;
            e.privacy = red.privacy;
            e.subject.external_effect_id = facts.external_effect_id.clone();
            e.outcome = Some(EvidenceOutcomeV1 {
                transport_status: ex.transport_status,
                protocol_status: Some(if facts.is_error { "error" } else { "ok" }.to_string()),
                error_message: facts.error_message.clone(),
                duration_nanos: ex.duration_nanos,
                ..Default::default()
            });
        } else {
            e.content = request_redacted.content.clone();
            e.privacy = request_redacted.privacy.clone();
        }
        e.source = EvidenceSourceV1 {
            source_kind: format!("mcp_{}", ex.capture_mode),
            source_instance: Some(ex.server_id.clone()),
            source_sequence: None,
            received_at_unix_nanos: None,
        };
        e.dedupe_key = dedupe::dedupe_key(&e);
        e.evidence_id = crate::otlp::derive_evidence_id(&e.dedupe_key);
        e
    };

    let requested = push(AgentEvidenceKindV1::ToolRequested, start, false);
    let requested_id = requested.evidence_id.clone();
    out.push(requested);

    let mut started = push(AgentEvidenceKindV1::ToolInvocationStarted, start, false);
    started.parents = vec![requested_id.clone()];
    started.dedupe_key = dedupe::dedupe_key(&started);
    started.evidence_id = crate::otlp::derive_evidence_id(&started.dedupe_key);
    let started_id = started.evidence_id.clone();
    out.push(started);

    if ex.response_body.is_some() || ex.transport_status.is_some() {
        let mut finished = push(AgentEvidenceKindV1::ToolInvocationFinished, end, true);
        finished.parents = vec![started_id];
        finished.dedupe_key = dedupe::dedupe_key(&finished);
        finished.evidence_id = crate::otlp::derive_evidence_id(&finished.dedupe_key);
        out.push(finished);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_json_rejeita_method_duplicado() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"resources/read","params":{}}"#;
        assert!(validate_request_json(raw)
            .unwrap_err()
            .contains("duplicada"));
    }

    #[test]
    fn strict_json_rejeita_chave_duplicada_aninhada() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","name":"lookup_vendor","arguments":{}}}"#;
        assert!(validate_request_json(raw)
            .unwrap_err()
            .contains("duplicada"));
    }

    #[test]
    fn binding_preserva_tipo_json_mesmo_quando_policy_achata() {
        let a = McpExchange {
            request_body: Some(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_payment","arguments":{"amount":75000}}}"#.to_vec()),
            ..Default::default()
        };
        let b = McpExchange {
            request_body: Some(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_payment","arguments":{"amount":"75000"}}}"#.to_vec()),
            ..Default::default()
        };
        let fa = extract_facts(&a);
        let fb = extract_facts(&b);
        assert_eq!(fa.arguments.get("amount"), fb.arguments.get("amount"));
        assert_ne!(
            fa.binding_arguments.get("amount"),
            fb.binding_arguments.get("amount")
        );
    }

    #[test]
    fn corpo_json_rpc_prevalece_sobre_headers_de_classificacao() {
        let mut ex = McpExchange::default();
        ex.request_headers
            .insert(HEADER_METHOD.into(), "resources/read".into());
        ex.request_headers
            .insert(HEADER_NAME.into(), "lookup_vendor".into());
        ex.request_body = Some(br#"{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"exec","arguments":{}}}"#.to_vec());
        let facts = extract_facts(&ex);
        assert_eq!(facts.method.as_deref(), Some("tools/call"));
        assert_eq!(facts.tool_name.as_deref(), Some("exec"));
    }

    #[test]
    fn strict_json_aceita_tool_call_normal() {
        let raw = br#"{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"exec","arguments":{"command":"safe-marker"}}}"#;
        assert!(validate_request_json(raw).is_ok());
    }

    #[test]
    fn strict_json_rejeita_profundidade_excessiva() {
        let mut raw = String::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"x":"#,
        );
        raw.push_str(&"[".repeat(256));
        raw.push('0');
        raw.push_str(&"]".repeat(256));
        raw.push_str("}}}");
        assert!(validate_request_json(raw.as_bytes()).is_err());
    }

    use crate::evidence::CaptureModeV1;

    fn exchange() -> McpExchange {
        let mut headers = BTreeMap::new();
        headers.insert("Mcp-Method".into(), "tools/call".into());
        headers.insert("Mcp-Name".into(), "send_payment".into());
        headers.insert("Mcp-Session-Id".into(), "sess-1".into());
        headers.insert(
            "Authorization".into(),
            "Bearer sk-supersecretvalue123".into(),
        );
        McpExchange {
            tenant_id: "acme".into(),
            capture_mode: "proxy".into(),
            server_id: "finance".into(),
            request_headers: headers,
            request_body: Some(
                br#"{"jsonrpc":"2.0","id":"call-1","method":"tools/call",
                     "params":{"name":"send_payment","arguments":{"amount":75000,"account":"vendor-8832"}}}"#
                    .to_vec(),
            ),
            response_body: Some(
                br#"{"jsonrpc":"2.0","id":"call-1","result":{"content":[{"type":"text","text":"ok"}],"payment_id":"84723"}}"#
                    .to_vec(),
            ),
            transport_status: Some(200),
            duration_nanos: Some(1_000_000),
            run_id: Some("run-1".into()),
            trace_id: Some("trace-1".into()),
            agent_id: Some("procurement-agent".into()),
            human_subject: Some("jose".into()),
            observed_at_unix_nanos: 1_000,
        }
    }

    #[test]
    fn extrai_o_essencial_da_troca() {
        let f = extract_facts(&exchange());
        assert_eq!(f.method.as_deref(), Some("tools/call"));
        assert_eq!(f.tool_name.as_deref(), Some("send_payment"));
        assert_eq!(f.tool_call_id.as_deref(), Some("call-1"));
        assert_eq!(f.arguments.get("amount").map(String::as_str), Some("75000"));
        assert_eq!(f.external_effect_id.as_deref(), Some("84723"));
        assert!(!f.is_error);
    }

    #[test]
    fn o_trio_e_produzido_e_correlacionado() {
        let evs = exchange_to_evidences(&exchange(), &RedactionProfile::default());
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[0].kind, AgentEvidenceKindV1::ToolRequested);
        assert_eq!(evs[1].kind, AgentEvidenceKindV1::ToolInvocationStarted);
        assert_eq!(evs[2].kind, AgentEvidenceKindV1::ToolInvocationFinished);
        for e in &evs {
            assert_eq!(e.subject.tool_call_id.as_deref(), Some("call-1"));
        }
        assert_eq!(evs[1].parents, vec![evs[0].evidence_id.clone()]);
        assert_eq!(evs[2].parents, vec![evs[1].evidence_id.clone()]);
    }

    #[test]
    fn o_bearer_nunca_e_persistido() {
        for modo in [
            CaptureModeV1::MetadataOnly,
            CaptureModeV1::Redacted,
            CaptureModeV1::FullExplicit,
        ] {
            let profile = RedactionProfile::default().with_mode(modo);
            let evs = exchange_to_evidences(&exchange(), &profile);
            let dump = serde_json::to_string(&evs).unwrap();
            assert!(
                !dump.contains("sk-supersecretvalue123"),
                "modo {modo:?}: {dump}"
            );
        }
    }

    #[test]
    fn o_efeito_externo_e_registado() {
        let evs = exchange_to_evidences(&exchange(), &RedactionProfile::default());
        assert_eq!(evs[2].subject.external_effect_id.as_deref(), Some("84723"));
    }

    #[test]
    fn erro_do_protocolo_nao_e_sucesso_de_transporte() {
        let mut ex = exchange();
        ex.response_body = Some(
            br#"{"jsonrpc":"2.0","id":"call-1","result":{"isError":true,"content":[]}}"#.to_vec(),
        );
        let evs = exchange_to_evidences(&ex, &RedactionProfile::default());
        let o = evs[2].outcome.as_ref().unwrap();
        assert_eq!(o.transport_status, Some(200));
        assert_eq!(o.protocol_status.as_deref(), Some("error"));
    }

    #[test]
    fn troca_sem_resposta_produz_so_dois_eventos() {
        let mut ex = exchange();
        ex.response_body = None;
        ex.transport_status = None;
        let evs = exchange_to_evidences(&ex, &RedactionProfile::default());
        assert_eq!(evs.len(), 2);
    }

    #[test]
    fn metodos_de_protocolo_nao_viram_evidencia() {
        let mut ex = exchange();
        ex.request_headers
            .insert("Mcp-Method".into(), "tools/list".into());
        ex.request_headers.remove("Mcp-Name");
        ex.request_body = Some(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec());
        assert!(exchange_to_evidences(&ex, &RedactionProfile::default()).is_empty());
    }

    #[test]
    fn corpo_ilegivel_nao_entra_em_panico() {
        let mut ex = exchange();
        ex.request_body = Some(b"{ isto nao e json".to_vec());
        ex.response_body = Some(vec![0xff, 0x00, 0xfe]);
        let _ = exchange_to_evidences(&ex, &RedactionProfile::default());
    }

    #[test]
    fn retransmitir_a_mesma_troca_da_os_mesmos_ids() {
        let a = exchange_to_evidences(&exchange(), &RedactionProfile::default());
        let b = exchange_to_evidences(&exchange(), &RedactionProfile::default());
        assert_eq!(a, b);
    }

    #[test]
    fn aninhamento_hostil_na_resposta_tem_tecto() {
        let mut deep = serde_json::json!({ "payment_id": "fundo" });
        for _ in 0..30 {
            deep = serde_json::json!({ "x": deep });
        }
        let body = serde_json::to_vec(&serde_json::json!({ "result": deep })).unwrap();
        let mut ex = exchange();
        ex.response_body = Some(body);
        let f = extract_facts(&ex);
        assert_eq!(
            f.external_effect_id, None,
            "o tecto de profundidade parou a busca"
        );
    }

    // ── SSE ─────────────────────────────────────────────────────────────
    //
    // Os enquadramentos abaixo foram MEDIDOS contra servidores reais em
    // 2026-09-14 (Context7 v4.1.1, DeepWiki, Cloudflare docs, GitMCP). Todos
    // respondem em `text/event-stream`; nenhum responde JSON puro.

    #[test]
    fn um_erro_do_upstream_em_sse_nao_passa_por_sucesso() {
        // O defeito que isto trava: `serde_json::from_slice` falha num corpo
        // SSE, o `if let Ok` engole o erro, e uma tool call RECUSADA pelo
        // upstream fica gravada com `protocol_status: "ok"` num log que não se
        // apaga. Alguém lê o relatório e conclui o contrário do que aconteceu.
        let corpo = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":12,\"error\":{\"code\":-32602,\"message\":\"Tool nao-existe not found\"}}\n\n";
        let mut ex = exchange();
        ex.response_body = Some(corpo.to_vec());
        let f = extract_facts(&ex);
        assert!(f.is_error, "um erro em SSE passou por sucesso");
        assert_eq!(
            f.error_message.as_deref(),
            Some("Tool nao-existe not found")
        );
    }

    #[test]
    fn um_is_error_do_resultado_em_sse_tambem_conta() {
        // O MCP tem DOIS modos de falha: o erro JSON-RPC (protocolo) e o
        // `result.isError` (a ferramenta correu e falhou). O segundo vem com
        // HTTP 200 e com `result` presente — é o mais fácil de deixar passar.
        let corpo = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"falhou\"}],\"isError\":true}}\n\n";
        let mut ex = exchange();
        ex.response_body = Some(corpo.to_vec());
        assert!(extract_facts(&ex).is_error);
    }

    #[test]
    fn json_puro_continua_a_funcionar() {
        // A correcção não pode partir o caminho que já funcionava.
        let corpo = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"nao"}}"#;
        let mut ex = exchange();
        ex.response_body = Some(corpo.to_vec());
        let f = extract_facts(&ex);
        assert!(f.is_error);
        assert_eq!(f.error_message.as_deref(), Some("nao"));
    }

    #[test]
    fn sse_com_crlf_e_com_varios_eventos() {
        // Enquadramento com CRLF, precedido de um comentário de keep-alive e de
        // um evento que NÃO é uma resposta JSON-RPC. Fica o primeiro que o é.
        let corpo = b": keep-alive\r\n\r\nevent: ping\r\ndata: {\"nada\":1}\r\n\r\nevent: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"isError\":true}}\r\n\r\n";
        let mut ex = exchange();
        ex.response_body = Some(corpo.to_vec());
        assert!(extract_facts(&ex).is_error, "o evento certo foi ignorado");
    }

    #[test]
    fn um_corpo_que_nao_e_nem_json_nem_sse_nao_inventa_nada() {
        // Uma página de erro de um proxy, por exemplo. O importante é NÃO
        // afirmar sucesso: sem payload legível, não há facto nenhum a extrair.
        let mut ex = exchange();
        ex.response_body = Some(b"<html><body>502 Bad Gateway</body></html>".to_vec());
        let f = extract_facts(&ex);
        assert!(!f.is_error, "inventou um erro que nao leu");
        assert_eq!(f.external_effect_id, None);
    }

    #[test]
    fn o_efeito_externo_tambem_se_le_de_sse() {
        let corpo = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}],\"order_id\":\"ORD-42\"}}\n\n";
        let mut ex = exchange();
        ex.response_body = Some(corpo.to_vec());
        assert_eq!(
            extract_facts(&ex).external_effect_id.as_deref(),
            Some("ORD-42")
        );
    }
}
