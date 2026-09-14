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
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

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
    /// Argumentos tipados extraídos de `params.arguments`, achatados.
    pub arguments: BTreeMap<String, String>,
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
        if let Ok(v) = serde_json::from_slice::<Value>(body) {
            if facts.method.is_none() {
                facts.method = v.get("method").and_then(Value::as_str).map(str::to_string);
            }
            facts.tool_call_id = v
                .get("id")
                .map(|id| match id {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .filter(|s| !s.is_empty() && s != "null");
            if let Some(params) = v.get("params") {
                if facts.tool_name.is_none() {
                    facts.tool_name = params
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                }
                if let Some(args) = params.get("arguments").and_then(Value::as_object) {
                    for (k, val) in args {
                        facts.arguments.insert(k.clone(), flatten(val));
                    }
                }
            }
        }
    }

    if let Some(body) = &ex.response_body {
        if let Ok(v) = serde_json::from_slice::<Value>(body) {
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
}
