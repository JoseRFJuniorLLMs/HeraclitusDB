//! SPEC-0074 §25 (Golden) — vectores canónicos congelados.
//!
//! # Para que serve um golden vector
//!
//! O hash canónico de uma evidência é a identidade que uma prova pericial
//! fecha. Se ele mudar por acidente — um campo acrescentado no meio do codec,
//! uma variante renumerada, um `Option` que passou a ser escrito de outra
//! forma — todas as provas emitidas antes dessa mudança deixam de fechar, e
//! nada no compilador o denuncia.
//!
//! Estes testes congelam o hash de seis formas representativas. Quando um deles
//! falhar, a pergunta NÃO é "qual é o valor novo?" — é **"a mudança de formato
//! foi deliberada?"**. Se foi, sobe-se `AGENT_EVIDENCE_SCHEMA_V1` e o
//! `AGENT_CANONICAL_CODEC_V1`, e os vectores antigos passam a documentar a
//! versão antiga. Se não foi, é um defeito.
//!
//! Os vectores cobrem exactamente o que a §25 nomeia:
//!
//! ```text
//! GenAI model span          MCP tools/call        MCP result
//! human approval reference  tool error            redacted arguments
//! ```

use heraclitus_agent::canonical::{canonical_evidence_bytes, canonical_evidence_hash_hex};
use heraclitus_agent::evidence::*;
use heraclitus_agent::privacy::{self, RawContent, RedactionProfile};
use std::collections::BTreeMap;

/// Relógio fixo. Um golden vector com `SystemTime::now()` dentro não é golden.
const T: u64 = 1_700_000_000_000_000_000;

fn base(kind: AgentEvidenceKindV1) -> AgentEvidenceV1 {
    let mut e = AgentEvidenceV1::new("acme", kind, T);
    e.evidence_id = "E-GOLDEN-0001".into();
    e.trace_id = Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    e.span_id = Some("bbbbbbbbbbbbbbbb".into());
    e.run_id = Some("run-golden".into());
    e.session_id = Some("sess-golden".into());
    e.agent = AgentIdentityV1 {
        agent_id: "procurement-agent".into(),
        agent_name: Some("Procurement Agent".into()),
        framework: Some("heraclitus-golden".into()),
        framework_version: Some("1.0.0".into()),
        deployment_id: Some("inst-1".into()),
        code_revision: Some("abc123".into()),
    };
    e.human = Some(HumanIdentityRefV1 {
        subject_id: "jose@example".into(),
        issuer: Some("https://id.example".into()),
        display_hint: None,
    });
    e.source = EvidenceSourceV1 {
        source_kind: "golden".into(),
        source_instance: Some("vector".into()),
        source_sequence: Some(1),
        received_at_unix_nanos: None,
    };
    e.dedupe_key = "dedupe-golden".into();
    e
}

/// 1. Span de invocação de modelo (GenAI).
fn genai_model_span() -> AgentEvidenceV1 {
    let mut e = base(AgentEvidenceKindV1::ModelInvocationFinished);
    e.subject.protocol = Some("genai".into());
    e.subject.model_id = Some("demo-model".into());
    e.subject.model_provider = Some("demo".into());
    e.content
        .fields
        .insert("gen_ai.usage.input_tokens".into(), "412".into());
    e.content
        .fields
        .insert("gen_ai.usage.output_tokens".into(), "88".into());
    e.outcome = Some(EvidenceOutcomeV1 {
        protocol_status: Some("ok".into()),
        duration_nanos: Some(1_300_000_000),
        ..Default::default()
    });
    e
}

/// 2. `tools/call` do MCP.
fn mcp_tools_call() -> AgentEvidenceV1 {
    let mut e = base(AgentEvidenceKindV1::ToolRequested);
    e.subject.protocol = Some("mcp".into());
    e.subject.server_id = Some("finance".into());
    e.subject.tool_name = Some("send_payment".into());
    e.subject.tool_call_id = Some("call-1".into());
    e.content.content_type = Some("application/json".into());
    e.content.content_length = Some(64);
    e.content.canonical_content_hash = Some("f".repeat(64));
    e.content.fields.insert("amount".into(), "75000".into());
    e.content
        .fields
        .insert("account".into(), "vendor-8832".into());
    e
}

/// 3. Resultado de uma `tools/call`, com efeito externo.
fn mcp_result() -> AgentEvidenceV1 {
    let mut e = base(AgentEvidenceKindV1::ToolInvocationFinished);
    e.subject.protocol = Some("mcp".into());
    e.subject.server_id = Some("finance".into());
    e.subject.tool_name = Some("send_payment".into());
    e.subject.tool_call_id = Some("call-1".into());
    e.subject.external_effect_id = Some("payment-84723".into());
    e.content.canonical_content_hash = Some("a".repeat(64));
    e.outcome = Some(EvidenceOutcomeV1 {
        transport_status: Some(200),
        protocol_status: Some("ok".into()),
        duration_nanos: Some(800_000_000),
        ..Default::default()
    });
    e
}

/// 4. Referência a uma aprovação humana.
fn human_approval_reference() -> AgentEvidenceV1 {
    let mut e = base(AgentEvidenceKindV1::HumanApprovalGranted);
    e.subject.tool_name = Some("send_payment".into());
    e.subject.tool_call_id = Some("call-1".into());
    e.content.approval = Some(ApprovalProvenanceV1 {
        approval_id: "A-771".into(),
        authorization_subject_hash: "d".repeat(64),
        approver_subject: Some("finance-cfo".into()),
        approver_issuer: Some("https://id.example".into()),
        decided_at_unix_nanos: Some(T + 12_000_000_000),
    });
    e.content.policy = Some(PolicyProvenanceV1 {
        policy_id: "agent-policy".into(),
        policy_version: "v17".into(),
        policy_hash: "c".repeat(64),
        rule_id: Some("finance-large".into()),
        decision: "require_approval".into(),
        reason_code: None,
        input_projection_hash: "b".repeat(64),
        authorization_id: Some("AZ-1".into()),
        enforced: true,
    });
    e
}

/// 5. Erro de ferramenta.
fn tool_error() -> AgentEvidenceV1 {
    let mut e = base(AgentEvidenceKindV1::ErrorObserved);
    e.subject.protocol = Some("mcp".into());
    e.subject.server_id = Some("finance".into());
    e.subject.tool_name = Some("send_payment".into());
    e.outcome = Some(EvidenceOutcomeV1 {
        transport_status: Some(502),
        protocol_status: Some("error".into()),
        error_code: Some("MCP_UPSTREAM_UNAVAILABLE".into()),
        error_message: Some("connection refused".into()),
        duration_nanos: Some(30_000_000_000),
        retry_count: Some(2),
    });
    e
}

/// 6. Argumentos redigidos — o caso que prova que a redacção é determinística.
fn redacted_arguments() -> AgentEvidenceV1 {
    let mut e = base(AgentEvidenceKindV1::ToolRequested);
    e.subject.protocol = Some("mcp".into());
    e.subject.tool_name = Some("call_api".into());
    let mut fields = BTreeMap::new();
    fields.insert("amount".to_string(), "4200".to_string());
    fields.insert("api_key".to_string(), "sk-abcdefghijklmnopqrst".to_string());
    fields.insert(
        "gen_ai.prompt".to_string(),
        "numero de cartao do cliente".to_string(),
    );
    let mut headers = BTreeMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Bearer abcdefghijklmnop".to_string(),
    );
    headers.insert("X-Request-Id".to_string(), "req-1".to_string());
    let out = privacy::apply(
        &RedactionProfile::default().with_mode(CaptureModeV1::Redacted),
        &RawContent {
            content_type: Some("application/json".into()),
            body: Some(b"{\"amount\":4200}".to_vec()),
            fields,
            headers,
        },
    );
    e.content = out.content;
    e.privacy = out.privacy;
    e
}

/// Um vector: nome legível, construtor e a constante que congela o hash.
type Vector = (&'static str, fn() -> AgentEvidenceV1, &'static str);

/// Os vectores. Trocar um destes valores é declarar uma mudança de formato.
const GOLDEN: &[Vector] = &[
    (
        "genai_model_span",
        genai_model_span,
        "GOLDEN_GENAI_MODEL_SPAN",
    ),
    ("mcp_tools_call", mcp_tools_call, "GOLDEN_MCP_TOOLS_CALL"),
    ("mcp_result", mcp_result, "GOLDEN_MCP_RESULT"),
    (
        "human_approval_reference",
        human_approval_reference,
        "GOLDEN_HUMAN_APPROVAL",
    ),
    ("tool_error", tool_error, "GOLDEN_TOOL_ERROR"),
    (
        "redacted_arguments",
        redacted_arguments,
        "GOLDEN_REDACTED_ARGUMENTS",
    ),
];

// ── os hashes congelados ─────────────────────────────────────────────────────
//
// Gerados uma vez, em 2026-09-14, e daqui em diante são contrato.
const GOLDEN_GENAI_MODEL_SPAN: &str =
    "b51e29ed615aa96700dc2b092f648e140863fbb7a7a2177b93ebba5d7dfb973e";
const GOLDEN_MCP_TOOLS_CALL: &str =
    "6831cbb15dbbfa4439d708235e3352515a6562edfc7ffb11f0788684e68df187";
const GOLDEN_MCP_RESULT: &str = "fb0a4f16686ac5d65916293951644624313b7077ea57360bdba47fb8514cb22f";
const GOLDEN_HUMAN_APPROVAL: &str =
    "4796b8746e1f9885d1a7d81a404d661b3dacb5ecf52ca291a86cb9a86a92cc46";
const GOLDEN_TOOL_ERROR: &str = "047b13aff4647d7462d08e8cab2ddce36677fb543752367d52a91923f2d58c5f";
const GOLDEN_REDACTED_ARGUMENTS: &str =
    "79c35d4239445512d33164ec2505fb316a25006ac9d29bdd310aa412057c64ea";

fn esperado(nome: &str) -> &'static str {
    match nome {
        "GOLDEN_GENAI_MODEL_SPAN" => GOLDEN_GENAI_MODEL_SPAN,
        "GOLDEN_MCP_TOOLS_CALL" => GOLDEN_MCP_TOOLS_CALL,
        "GOLDEN_MCP_RESULT" => GOLDEN_MCP_RESULT,
        "GOLDEN_HUMAN_APPROVAL" => GOLDEN_HUMAN_APPROVAL,
        "GOLDEN_TOOL_ERROR" => GOLDEN_TOOL_ERROR,
        "GOLDEN_REDACTED_ARGUMENTS" => GOLDEN_REDACTED_ARGUMENTS,
        outro => panic!("vector sem constante: {outro}"),
    }
}

#[test]
fn os_hashes_canonicos_nao_mudaram() {
    let mut divergencias = Vec::new();
    for (nome, construtor, constante) in GOLDEN {
        let hash = canonical_evidence_hash_hex(&construtor());
        if hash != esperado(constante) {
            divergencias.push(format!("const {constante}: &str = \"{hash}\"; // {nome}"));
        }
    }
    assert!(
        divergencias.is_empty(),
        "O formato canónico mudou. Se foi DELIBERADO, suba o número da versão do \
         esquema e do codec, e actualize os vectores para:\n\n{}\n",
        divergencias.join("\n")
    );
}

#[test]
fn a_ordem_de_insercao_nao_muda_nenhum_vector() {
    // Constrói os mesmos campos pela ordem inversa. `BTreeMap` já normaliza; o
    // teste existe para apanhar o dia em que alguém trocar o tipo do mapa.
    for (nome, construtor, _) in GOLDEN {
        let a = construtor();
        let mut b = construtor();
        let campos: Vec<(String, String)> = b
            .content
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        b.content.fields.clear();
        for (k, v) in campos.into_iter().rev() {
            b.content.fields.insert(k, v);
        }
        assert_eq!(
            canonical_evidence_hash_hex(&a),
            canonical_evidence_hash_hex(&b),
            "{nome}"
        );
    }
}

#[test]
fn os_bytes_canonicos_nao_levam_segredo() {
    let bytes = canonical_evidence_bytes(&redacted_arguments());
    let texto = String::from_utf8_lossy(&bytes);
    for proibido in [
        "sk-abcdefghijklmnopqrst",
        "Bearer abcdefghijklmnop",
        "numero de cartao",
    ] {
        assert!(
            !texto.contains(proibido),
            "{proibido} está nos bytes canónicos"
        );
    }
    // E o que SOBREVIVE: a chave, o marcador e a classe detectada.
    assert!(texto.contains("api_key"));
    assert!(texto.contains("[REDACTED]"));
}

#[test]
fn cada_vector_tem_um_hash_distinto() {
    let mut vistos = std::collections::BTreeSet::new();
    for (nome, construtor, _) in GOLDEN {
        let h = canonical_evidence_hash_hex(&construtor());
        assert!(vistos.insert(h.clone()), "{nome} colidiu com outro vector");
    }
}

#[test]
fn os_bytes_canonicos_sao_estaveis_entre_execucoes() {
    for (nome, construtor, _) in GOLDEN {
        let a = canonical_evidence_bytes(&construtor());
        let b = canonical_evidence_bytes(&construtor());
        assert_eq!(a, b, "{nome}");
    }
}
