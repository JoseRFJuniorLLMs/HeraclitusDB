//! SPEC-0074 §12 — ingestão OpenTelemetry.
//!
//! # A promessa comercial que este módulo tem de cumprir
//!
//! > Se a aplicação já exporta OpenTelemetry, o primeiro run deve aparecer sem
//! > outra dependência obrigatória (§0.1).
//!
//! Portanto: aceitar o que o exporter OTel manda por omissão (`protobuf` sobre
//! `POST /v1/traces`), aceitar também `application/json`, e mapear as GenAI
//! Semantic Conventions para o modelo canónico sem exigir que a aplicação
//! saiba o que é o Heraclitus.
//!
//! # A regra que impede o produto de se comer a si próprio (§34)
//!
//! Um span sem marca GenAI **não** vira evidência de agente. Sem esta regra, um
//! serviço com tracing HTTP normal despejaria a aplicação inteira no log de
//! evidência — e o próprio Heraclitus, se exportasse a sua telemetria para si
//! mesmo, entraria no ciclo `OTEL -> ingest -> OTEL`. O filtro é explícito e
//! testado ([`tests::span_sem_marca_genai_e_ignorado`]).
//!
//! # Determinismo da retransmissão
//!
//! `evidence_id` é **derivado** da chave de deduplicação, e o tempo de
//! observação é o do próprio span — não o relógio de parede da ingestão. Sem
//! isso, um retry do exporter produziria bytes canónicos diferentes para o
//! mesmo facto e a deduplicação reportaria conflito em vez de silêncio (§24).

pub mod proto;

use crate::dedupe;
use crate::evidence::{
    AgentEvidenceKindV1, AgentEvidenceV1, AgentIdentityV1, EvidenceOutcomeV1, EvidenceSourceV1,
    HumanIdentityRefV1,
};
use crate::privacy::{self, RawContent, RedactionProfile};
use proto::{any_value_to_string, hex_lower, KeyValue, ResourceSpans, Span, TracesData};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Prefixo das GenAI Semantic Conventions.
const GENAI_PREFIX: &str = "gen_ai.";
/// Prefixo dos atributos próprios, para quem quiser enriquecer a evidência sem
/// sair do OpenTelemetry.
const HRK_PREFIX: &str = "heraclitus.agent.";

/// Limites obrigatórios da ingestão (SPEC-0074 §12). Sem alocação sem tecto.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IngestLimits {
    pub max_attributes: usize,
    pub max_attribute_key_bytes: usize,
    pub max_attribute_value_bytes: usize,
    pub max_events_per_batch: usize,
    pub max_body_bytes: usize,
    pub max_queue_depth: usize,
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self {
            max_attributes: 128,
            max_attribute_key_bytes: 256,
            max_attribute_value_bytes: 4096,
            max_events_per_batch: 10_000,
            max_body_bytes: 4 * 1024 * 1024,
            max_queue_depth: 65_536,
        }
    }
}

/// O que a normalização de um lote produziu.
#[derive(Debug, Default)]
pub struct NormalizedBatch {
    pub evidences: Vec<AgentEvidenceV1>,
    /// Spans que não têm marca de agente. Não é erro — é o filtro de §34 a
    /// funcionar.
    pub ignored_spans: usize,
    /// Spans recusados por exceder os limites do lote.
    pub rejected_spans: usize,
    /// Atributos cortados por tecto de cardinalidade/tamanho.
    pub truncated_attributes: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum OtlpError {
    #[error("lote OTLP maior do que o tecto configurado ({0} > {1} bytes)")]
    BodyTooLarge(usize, usize),
    #[error("protobuf OTLP inválido: {0}")]
    Protobuf(#[from] prost::DecodeError),
    #[error("JSON OTLP inválido: {0}")]
    Json(String),
    #[error("content-type não suportado: {0}")]
    UnsupportedContentType(String),
}

/// Normalizador determinístico: mesmos bytes de entrada, mesma evidência.
pub struct OtlpNormalizer {
    pub tenant_id: String,
    pub limits: IngestLimits,
    pub redaction: RedactionProfile,
    pub source_kind: String,
}

impl OtlpNormalizer {
    pub fn new(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            limits: IngestLimits::default(),
            redaction: RedactionProfile::default(),
            source_kind: "otlp_http".to_string(),
        }
    }

    pub fn with_limits(mut self, limits: IngestLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_redaction(mut self, profile: RedactionProfile) -> Self {
        self.redaction = profile;
        self
    }

    pub fn with_source_kind(mut self, kind: impl Into<String>) -> Self {
        self.source_kind = kind.into();
        self
    }

    /// Ponto de entrada do servidor HTTP: bytes + content-type.
    pub fn ingest_http(
        &self,
        content_type: &str,
        body: &[u8],
    ) -> Result<NormalizedBatch, OtlpError> {
        if body.len() > self.limits.max_body_bytes {
            return Err(OtlpError::BodyTooLarge(
                body.len(),
                self.limits.max_body_bytes,
            ));
        }
        let ct = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let traces = match ct.as_str() {
            "application/x-protobuf" | "application/protobuf" | "" => proto::decode_traces(body)?,
            "application/json" => json::decode_traces_json(body)?,
            other => return Err(OtlpError::UnsupportedContentType(other.to_string())),
        };
        Ok(self.normalize(&traces))
    }

    /// Mapeia um `TracesData` já descodificado.
    pub fn normalize(&self, traces: &TracesData) -> NormalizedBatch {
        let mut out = NormalizedBatch::default();
        for rs in &traces.resource_spans {
            let resource = self.flatten_attrs(
                rs.resource
                    .as_ref()
                    .map(|r| r.attributes.as_slice())
                    .unwrap_or(&[]),
                &mut out,
            );
            for ss in &rs.scope_spans {
                let scope_name = ss
                    .scope
                    .as_ref()
                    .map(|s| s.name.clone())
                    .unwrap_or_default();
                for span in &ss.spans {
                    if out.evidences.len() >= self.limits.max_events_per_batch {
                        out.rejected_spans += 1;
                        continue;
                    }
                    let produced =
                        self.span_to_evidences(rs, span, &resource, &scope_name, &mut out);
                    if produced == 0 {
                        out.ignored_spans += 1;
                    }
                }
            }
        }
        out
    }

    fn flatten_attrs(
        &self,
        attrs: &[KeyValue],
        out: &mut NormalizedBatch,
    ) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for kv in attrs {
            if map.len() >= self.limits.max_attributes {
                out.truncated_attributes += 1;
                continue;
            }
            if kv.key.len() > self.limits.max_attribute_key_bytes {
                out.truncated_attributes += 1;
                continue;
            }
            let mut value = kv
                .value
                .as_ref()
                .map(|v| any_value_to_string(v, 0))
                .unwrap_or_default();
            if value.len() > self.limits.max_attribute_value_bytes {
                let mut end = self.limits.max_attribute_value_bytes;
                while end > 0 && !value.is_char_boundary(end) {
                    end -= 1;
                }
                value.truncate(end);
                out.truncated_attributes += 1;
            }
            map.insert(kv.key.clone(), value);
        }
        map
    }

    /// Um span vira zero, uma ou duas evidências. Devolve quantas produziu.
    fn span_to_evidences(
        &self,
        rs: &ResourceSpans,
        span: &Span,
        resource: &BTreeMap<String, String>,
        scope_name: &str,
        out: &mut NormalizedBatch,
    ) -> usize {
        let attrs = self.flatten_attrs(&span.attributes, out);
        let Some(shape) = classify(&attrs, span) else {
            return 0;
        };
        let _ = rs;

        let completed = span.end_time_unix_nano > 0;
        let kinds: Vec<(AgentEvidenceKindV1, u64)> = if completed {
            vec![
                (shape.started, span.start_time_unix_nano),
                (shape.finished, span.end_time_unix_nano),
            ]
        } else {
            vec![(shape.started, span.start_time_unix_nano)]
        };

        let mut produced = 0usize;
        for (kind, at) in kinds {
            if out.evidences.len() >= self.limits.max_events_per_batch {
                out.rejected_spans += 1;
                break;
            }
            let e = self.build(span, resource, &attrs, scope_name, kind, at, completed);
            out.evidences.push(e);
            produced += 1;
        }

        // Um span com erro produz também a evidência de erro: uma timeline que
        // mostra "tool executada" e esconde "tool falhou" é pior do que não ter
        // timeline.
        let errored = span.status.as_ref().map(|s| s.code == 2).unwrap_or(false)
            || attrs.contains_key("error.type");
        if errored && out.evidences.len() < self.limits.max_events_per_batch {
            let mut e = self.build(
                span,
                resource,
                &attrs,
                scope_name,
                AgentEvidenceKindV1::ErrorObserved,
                if completed {
                    span.end_time_unix_nano
                } else {
                    span.start_time_unix_nano
                },
                completed,
            );
            e.outcome = Some(EvidenceOutcomeV1 {
                protocol_status: Some("error".into()),
                error_code: attrs.get("error.type").cloned(),
                error_message: span
                    .status
                    .as_ref()
                    .map(|s| s.message.clone())
                    .filter(|m| !m.is_empty()),
                duration_nanos: duration(span),
                ..Default::default()
            });
            e.dedupe_key = dedupe::dedupe_key(&e);
            e.evidence_id = derive_evidence_id(&e.dedupe_key);
            out.evidences.push(e);
            produced += 1;
        }
        produced
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        &self,
        span: &Span,
        resource: &BTreeMap<String, String>,
        attrs: &BTreeMap<String, String>,
        scope_name: &str,
        kind: AgentEvidenceKindV1,
        observed_at: u64,
        completed: bool,
    ) -> AgentEvidenceV1 {
        let tenant = attrs
            .get("heraclitus.agent.tenant")
            .or_else(|| resource.get("heraclitus.agent.tenant"))
            .cloned()
            .unwrap_or_else(|| self.tenant_id.clone());
        let mut e = AgentEvidenceV1::new(tenant, kind, observed_at);

        e.trace_id = non_empty(hex_lower(&span.trace_id));
        e.span_id = non_empty(hex_lower(&span.span_id));
        e.parent_span_id = non_empty(hex_lower(&span.parent_span_id));
        e.run_id = attrs
            .get("heraclitus.agent.run_id")
            .or_else(|| attrs.get("gen_ai.agent.id"))
            .cloned()
            .or_else(|| non_empty(hex_lower(&span.trace_id)));
        e.session_id = attrs
            .get("gen_ai.conversation.id")
            .or_else(|| attrs.get("session.id"))
            .cloned();

        e.agent = AgentIdentityV1 {
            agent_id: attrs
                .get("gen_ai.agent.id")
                .or_else(|| attrs.get("heraclitus.agent.id"))
                .or_else(|| resource.get("service.name"))
                .cloned()
                .unwrap_or_else(|| "unknown-agent".to_string()),
            agent_name: attrs
                .get("gen_ai.agent.name")
                .or_else(|| resource.get("service.name"))
                .cloned(),
            framework: non_empty(scope_name.to_string()),
            framework_version: resource.get("telemetry.sdk.version").cloned(),
            deployment_id: resource
                .get("service.instance.id")
                .or_else(|| resource.get("deployment.environment.name"))
                .cloned(),
            code_revision: resource.get("service.version").cloned(),
        };

        if let Some(subject) = attrs
            .get("heraclitus.agent.human.subject")
            .or_else(|| attrs.get("enduser.id"))
        {
            e.human = Some(HumanIdentityRefV1 {
                subject_id: subject.clone(),
                issuer: attrs.get("heraclitus.agent.human.issuer").cloned(),
                display_hint: attrs.get("heraclitus.agent.human.display").cloned(),
            });
        }

        e.subject.protocol = Some("genai".to_string());
        e.subject.tool_name = attrs.get("gen_ai.tool.name").cloned();
        e.subject.tool_call_id = attrs.get("gen_ai.tool.call.id").cloned();
        e.subject.server_id = attrs
            .get("heraclitus.agent.server")
            .or_else(|| attrs.get("gen_ai.tool.type"))
            .cloned();
        e.subject.model_id = attrs
            .get("gen_ai.response.model")
            .or_else(|| attrs.get("gen_ai.request.model"))
            .cloned();
        e.subject.model_provider = attrs.get("gen_ai.system").cloned();
        e.subject.external_effect_id = attrs.get("heraclitus.agent.external_effect_id").cloned();

        // Conteúdo: os atributos GenAI conhecidos viram campos tipados; o resto
        // vai para `extensions`, com tecto. Tudo passa pelo portão de
        // privacidade — inclusive `gen_ai.prompt`, que é exactamente o que
        // NUNCA deve ficar em claro por omissão (§11).
        let mut raw = RawContent::default();
        for (k, v) in attrs {
            if k.starts_with(GENAI_PREFIX) || k.starts_with(HRK_PREFIX) {
                raw.fields.insert(k.clone(), v.clone());
            }
        }
        let redacted = privacy::apply(&self.redaction, &raw);
        e.content = redacted.content;
        e.privacy = redacted.privacy;
        for (k, v) in attrs {
            if e.content.extensions.len() >= self.limits.max_attributes {
                break;
            }
            if !k.starts_with(GENAI_PREFIX) && !k.starts_with(HRK_PREFIX) {
                e.content.extensions.insert(k.clone(), v.clone());
            }
        }

        if completed && is_finished(kind) {
            e.outcome = Some(EvidenceOutcomeV1 {
                protocol_status: span
                    .status
                    .as_ref()
                    .map(|s| status_label(s.code).to_string()),
                duration_nanos: duration(span),
                error_code: attrs.get("error.type").cloned(),
                ..Default::default()
            });
        }

        e.source = EvidenceSourceV1 {
            source_kind: self.source_kind.clone(),
            source_instance: resource
                .get("service.instance.id")
                .or_else(|| resource.get("service.name"))
                .cloned(),
            source_sequence: None,
            // Deliberadamente `None`: o relógio de parede da ingestão não é um
            // facto sobre o agente e destruiria o determinismo da
            // retransmissão. Ver o cabeçalho do módulo.
            received_at_unix_nanos: None,
        };

        e.dedupe_key = dedupe::dedupe_key(&e);
        e.evidence_id = derive_evidence_id(&e.dedupe_key);
        e
    }
}

/// Como um span se projecta no modelo de evidência.
struct SpanShape {
    started: AgentEvidenceKindV1,
    finished: AgentEvidenceKindV1,
}

/// Decide se o span é de agente e, se for, que par de eventos produz.
///
/// Devolver `None` é o filtro de §34: um span de HTTP normal não é evidência de
/// agente e não entra no log.
fn classify(attrs: &BTreeMap<String, String>, span: &Span) -> Option<SpanShape> {
    let has_marker = attrs
        .keys()
        .any(|k| k.starts_with(GENAI_PREFIX) || k.starts_with(HRK_PREFIX));
    if !has_marker {
        return None;
    }
    let op = attrs
        .get("gen_ai.operation.name")
        .map(String::as_str)
        .unwrap_or("");
    let shape = match op {
        "execute_tool" | "tool" => SpanShape {
            started: AgentEvidenceKindV1::ToolInvocationStarted,
            finished: AgentEvidenceKindV1::ToolInvocationFinished,
        },
        "chat" | "text_completion" | "generate_content" | "embeddings" => SpanShape {
            started: AgentEvidenceKindV1::ModelInvocationStarted,
            finished: AgentEvidenceKindV1::ModelInvocationFinished,
        },
        "invoke_agent" | "create_agent" => SpanShape {
            started: AgentEvidenceKindV1::RunStarted,
            finished: AgentEvidenceKindV1::RunFinished,
        },
        _ => {
            // Sem `operation.name` explícito: um span com `gen_ai.tool.name` é
            // uma tool call; um span raiz é um run; o resto é invocação de
            // modelo, que é o caso mais comum da instrumentação automática.
            if attrs.contains_key("gen_ai.tool.name") {
                SpanShape {
                    started: AgentEvidenceKindV1::ToolInvocationStarted,
                    finished: AgentEvidenceKindV1::ToolInvocationFinished,
                }
            } else if span.parent_span_id.is_empty() {
                SpanShape {
                    started: AgentEvidenceKindV1::RunStarted,
                    finished: AgentEvidenceKindV1::RunFinished,
                }
            } else {
                SpanShape {
                    started: AgentEvidenceKindV1::ModelInvocationStarted,
                    finished: AgentEvidenceKindV1::ModelInvocationFinished,
                }
            }
        }
    };
    Some(shape)
}

fn is_finished(k: AgentEvidenceKindV1) -> bool {
    matches!(
        k,
        AgentEvidenceKindV1::RunFinished
            | AgentEvidenceKindV1::ModelInvocationFinished
            | AgentEvidenceKindV1::ToolInvocationFinished
    )
}

fn status_label(code: i32) -> &'static str {
    match code {
        1 => "ok",
        2 => "error",
        _ => "unset",
    }
}

fn duration(span: &Span) -> Option<u64> {
    span.end_time_unix_nano
        .checked_sub(span.start_time_unix_nano)
        .filter(|_| span.end_time_unix_nano > 0)
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// `evidence_id` determinístico a partir da chave de deduplicação.
///
/// Um ULID aleatório aqui quebraria a idempotência da retransmissão: o mesmo
/// facto chegaria com bytes canónicos diferentes e a deduplicação teria de
/// escolher entre reportar conflito (falso) ou ignorar o conteúdo (perigoso).
pub fn derive_evidence_id(dedupe_key: &str) -> String {
    let prefix: String = dedupe_key.chars().take(32).collect();
    format!("E{prefix}")
}

pub mod json;

#[cfg(test)]
mod tests {
    use super::proto::{any_value, AnyValue, KeyValue, Resource, ScopeSpans, Status};
    use super::*;

    fn kv(k: &str, v: &str) -> KeyValue {
        KeyValue {
            key: k.into(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue(v.into())),
            }),
        }
    }

    fn traces(span: Span) -> TracesData {
        TracesData {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![kv("service.name", "procurement-agent")],
                    dropped_attributes_count: 0,
                }),
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![span],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        }
    }

    fn tool_span() -> Span {
        Span {
            trace_id: vec![0xaa; 16],
            span_id: vec![0xbb; 8],
            name: "execute_tool send_payment".into(),
            start_time_unix_nano: 1_000,
            end_time_unix_nano: 3_000,
            attributes: vec![
                kv("gen_ai.operation.name", "execute_tool"),
                kv("gen_ai.tool.name", "send_payment"),
                kv("gen_ai.tool.call.id", "call-1"),
                kv("gen_ai.system", "anthropic"),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn span_sem_marca_genai_e_ignorado() {
        let span = Span {
            trace_id: vec![1; 16],
            span_id: vec![2; 8],
            name: "GET /healthz".into(),
            start_time_unix_nano: 1,
            end_time_unix_nano: 2,
            attributes: vec![kv("http.request.method", "GET")],
            ..Default::default()
        };
        let out = OtlpNormalizer::new("t").normalize(&traces(span));
        assert!(out.evidences.is_empty());
        assert_eq!(out.ignored_spans, 1);
    }

    #[test]
    fn tool_span_vira_started_e_finished() {
        let out = OtlpNormalizer::new("t").normalize(&traces(tool_span()));
        let kinds: Vec<_> = out.evidences.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                AgentEvidenceKindV1::ToolInvocationStarted,
                AgentEvidenceKindV1::ToolInvocationFinished
            ]
        );
        let fin = &out.evidences[1];
        assert_eq!(fin.subject.tool_name.as_deref(), Some("send_payment"));
        assert_eq!(fin.subject.tool_call_id.as_deref(), Some("call-1"));
        assert_eq!(fin.outcome.as_ref().unwrap().duration_nanos, Some(2_000));
    }

    #[test]
    fn retransmitir_o_mesmo_lote_da_bytes_identicos() {
        let n = OtlpNormalizer::new("t");
        let a = n.normalize(&traces(tool_span()));
        let b = n.normalize(&traces(tool_span()));
        assert_eq!(a.evidences, b.evidences);
    }

    #[test]
    fn retransmissao_e_deduplicada_em_silencio() {
        let n = OtlpNormalizer::new("t");
        let mut idx = dedupe::DedupeIndex::new(1024);
        let first = n.normalize(&traces(tool_span()));
        for e in &first.evidences {
            assert_eq!(idx.admit(e), dedupe::DedupeVerdict::Novel);
        }
        let again = n.normalize(&traces(tool_span()));
        for e in &again.evidences {
            assert_eq!(idx.admit(e), dedupe::DedupeVerdict::Duplicate);
        }
    }

    #[test]
    fn prompt_nao_e_persistido_por_omissao() {
        // §11: "prompts completos = OFF". A CHAVE fica (a auditoria precisa de
        // saber que houve prompt); o VALOR nunca.
        let mut span = tool_span();
        span.attributes
            .push(kv("gen_ai.prompt", "numero de cartao do cliente"));
        let out = OtlpNormalizer::new("t").normalize(&traces(span));
        let dump = serde_json::to_string(&out.evidences).unwrap();
        assert!(dump.contains("gen_ai.prompt"), "{dump}");
        assert!(!dump.contains("numero de cartao"), "{dump}");
    }

    #[test]
    fn bearer_em_atributo_nunca_e_persistido() {
        let mut span = tool_span();
        span.attributes.push(kv(
            "gen_ai.request.headers",
            "Authorization: Bearer sk-abcdefghijklmnop",
        ));
        let out = OtlpNormalizer::new("t").normalize(&traces(span));
        let dump = serde_json::to_string(&out.evidences).unwrap();
        assert!(!dump.contains("sk-abcdefghijklmnop"), "{dump}");
    }

    #[test]
    fn span_com_erro_produz_error_observed() {
        let mut span = tool_span();
        span.status = Some(Status {
            code: 2,
            message: "upstream 500".into(),
        });
        let out = OtlpNormalizer::new("t").normalize(&traces(span));
        assert!(out
            .evidences
            .iter()
            .any(|e| e.kind == AgentEvidenceKindV1::ErrorObserved));
    }

    #[test]
    fn atributo_desconhecido_nao_derruba_o_lote() {
        let mut span = tool_span();
        span.attributes.push(kv("alguma.coisa.nova", "42"));
        let out = OtlpNormalizer::new("t").normalize(&traces(span));
        assert_eq!(out.evidences.len(), 2);
        assert_eq!(
            out.evidences[0]
                .content
                .extensions
                .get("alguma.coisa.nova")
                .map(String::as_str),
            Some("42")
        );
    }

    #[test]
    fn corpo_maior_que_o_tecto_e_recusado() {
        let n = OtlpNormalizer::new("t").with_limits(IngestLimits {
            max_body_bytes: 8,
            ..Default::default()
        });
        let err = n
            .ingest_http("application/x-protobuf", &[0u8; 64])
            .unwrap_err();
        assert!(matches!(err, OtlpError::BodyTooLarge(64, 8)));
    }

    #[test]
    fn tecto_de_eventos_por_lote_e_respeitado() {
        let n = OtlpNormalizer::new("t").with_limits(IngestLimits {
            max_events_per_batch: 1,
            ..Default::default()
        });
        let out = n.normalize(&traces(tool_span()));
        assert_eq!(out.evidences.len(), 1);
        assert!(out.rejected_spans >= 1);
    }

    #[test]
    fn content_type_desconhecido_e_recusado() {
        let n = OtlpNormalizer::new("t");
        assert!(matches!(
            n.ingest_http("text/plain", b"x"),
            Err(OtlpError::UnsupportedContentType(_))
        ));
    }
}
