//! SPEC-0074 §8–§11 — o modelo canónico de evidência de agente.
//!
//! # Porque é que isto não é um `SecurityEvent`
//!
//! A SPEC-0074 §9 é explícita: *"não reutilizar `SecurityEvent` apenas para
//! encaixar o novo produto na arquitectura antiga"*. Um incidente de SOC e uma
//! tool call de agente partilham a palavra "evento" e mais nada: o incidente
//! tem severidade, ATT&CK, risco e um ciclo de vida de investigação; a tool
//! call tem identidade delegada, argumentos, autorização e efeito externo.
//! Espremer a segunda no primeiro produziria campos permanentemente vazios dos
//! dois lados e obrigaria o produto de agentes a arrastar o vocabulário do SOC
//! para a UI.
//!
//! # O que este ficheiro garante
//!
//! 1. Todos os mapas são `BTreeMap` — a ordem de iteração é a ordem
//!    lexicográfica das chaves, e não a ordem de inserção. É isto que faz o
//!    hash canónico ser estável (SPEC-0074 §25, propriedade 1).
//! 2. Nenhum campo guarda material secreto. O [`PrivacyEnvelopeV1`] descreve o
//!    que foi omitido; o que foi omitido não está aqui em lado nenhum.
//! 3. `parents` é **proveniência lógica**, não integridade de armazenamento —
//!    essa é o LSN/Merkle (SPEC-0074 §15).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Versão do esquema. Entra no hash canónico: um leitor que não conheça o
/// número recusa-se a afirmar identidade em vez de adivinhar.
pub const AGENT_EVIDENCE_SCHEMA_V1: u16 = 1;

/// Tipos mínimos de evento (SPEC-0074 §9).
///
/// A ordem das variantes é parte do formato: a tag numérica de
/// [`AgentEvidenceKindV1::tag`] entra no hash canónico, portanto variantes
/// novas acrescentam-se **no fim**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AgentEvidenceKindV1 {
    RunStarted,
    RunFinished,
    ModelInvocationStarted,
    ModelInvocationFinished,
    ToolRequested,
    ToolAuthorized,
    ToolDenied,
    ToolInvocationStarted,
    ToolInvocationFinished,
    HumanApprovalRequested,
    HumanApprovalGranted,
    HumanApprovalDenied,
    PolicyEvaluated,
    AgentOutputProduced,
    ExternalEffectObserved,
    ErrorObserved,
    ArtifactReferenced,
}

impl AgentEvidenceKindV1 {
    /// Tag estável para o codec canónico. **Nunca renumerar.**
    pub fn tag(self) -> u8 {
        match self {
            Self::RunStarted => 1,
            Self::RunFinished => 2,
            Self::ModelInvocationStarted => 3,
            Self::ModelInvocationFinished => 4,
            Self::ToolRequested => 5,
            Self::ToolAuthorized => 6,
            Self::ToolDenied => 7,
            Self::ToolInvocationStarted => 8,
            Self::ToolInvocationFinished => 9,
            Self::HumanApprovalRequested => 10,
            Self::HumanApprovalGranted => 11,
            Self::HumanApprovalDenied => 12,
            Self::PolicyEvaluated => 13,
            Self::AgentOutputProduced => 14,
            Self::ExternalEffectObserved => 15,
            Self::ErrorObserved => 16,
            Self::ArtifactReferenced => 17,
        }
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::RunStarted,
            2 => Self::RunFinished,
            3 => Self::ModelInvocationStarted,
            4 => Self::ModelInvocationFinished,
            5 => Self::ToolRequested,
            6 => Self::ToolAuthorized,
            7 => Self::ToolDenied,
            8 => Self::ToolInvocationStarted,
            9 => Self::ToolInvocationFinished,
            10 => Self::HumanApprovalRequested,
            11 => Self::HumanApprovalGranted,
            12 => Self::HumanApprovalDenied,
            13 => Self::PolicyEvaluated,
            14 => Self::AgentOutputProduced,
            15 => Self::ExternalEffectObserved,
            16 => Self::ErrorObserved,
            17 => Self::ArtifactReferenced,
            _ => return None,
        })
    }

    /// Rótulo canónico — a forma textual usada na API, na timeline e nos
    /// ficheiros do bundle. Uma única definição, pela mesma razão que
    /// [`heraclitus_core::EventKind::label`] existe: dois sítios a formatar o
    /// mesmo nome divergem e a busca deixa de encontrar o que existe.
    pub fn label(self) -> &'static str {
        match self {
            Self::RunStarted => "RunStarted",
            Self::RunFinished => "RunFinished",
            Self::ModelInvocationStarted => "ModelInvocationStarted",
            Self::ModelInvocationFinished => "ModelInvocationFinished",
            Self::ToolRequested => "ToolRequested",
            Self::ToolAuthorized => "ToolAuthorized",
            Self::ToolDenied => "ToolDenied",
            Self::ToolInvocationStarted => "ToolInvocationStarted",
            Self::ToolInvocationFinished => "ToolInvocationFinished",
            Self::HumanApprovalRequested => "HumanApprovalRequested",
            Self::HumanApprovalGranted => "HumanApprovalGranted",
            Self::HumanApprovalDenied => "HumanApprovalDenied",
            Self::PolicyEvaluated => "PolicyEvaluated",
            Self::AgentOutputProduced => "AgentOutputProduced",
            Self::ExternalEffectObserved => "ExternalEffectObserved",
            Self::ErrorObserved => "ErrorObserved",
            Self::ArtifactReferenced => "ArtifactReferenced",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        (1..=17u8)
            .filter_map(Self::from_tag)
            .find(|k| k.label() == s)
    }

    /// Todos os kinds, pela ordem das tags. Usado por testes e pela API.
    pub fn all() -> impl Iterator<Item = Self> {
        (1..=17u8).filter_map(Self::from_tag)
    }
}

/// Identidade do agente (SPEC-0074 §10.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentityV1 {
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_revision: Option<String>,
}

/// Referência a uma identidade humana (SPEC-0074 §10.2).
///
/// `display_hint` é uma *dica*, não uma fonte de verdade: quem decide quem é o
/// humano é o par `issuer` + `subject_id`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanIdentityRefV1 {
    pub subject_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_hint: Option<String>,
}

/// Delegação: o agente agiu em nome de quem (SPEC-0074 §10.3).
///
/// `authority_scope_hash` é um **hash** do âmbito autorizado, nunca o token que
/// o transporta (SPEC-0075 §2.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationRefV1 {
    pub delegation_id: String,
    pub on_behalf_of: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_scope_hash: Option<String>,
}

/// Sobre o quê é a evidência: o modelo, a ferramenta, o artefacto.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSubjectV1 {
    /// `mcp`, `http`, `genai`, `internal`...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Servidor/host da ferramenta (`finance`, `github`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    /// Correlaciona `ToolRequested -> ToolInvocationStarted ->
    /// ToolInvocationFinished` (SPEC-0074 §13).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    /// `payment_id`, `commit_sha`, `ticket_id`... (SPEC-0075 §25), só por
    /// allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_effect_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
}

/// Estado de um resultado. Deliberadamente separa transporte de protocolo
/// (SPEC-0075 §25): um HTTP 200 que devolve `isError: true` não é sucesso.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceOutcomeV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_status: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_nanos: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_count: Option<u32>,
}

/// Proveniência da decisão de policy (SPEC-0075 §18).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyProvenanceV1 {
    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    pub input_projection_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_id: Option<String>,
    /// `false` em shadow mode: a decisão foi registada mas não bloqueou nada
    /// (SPEC-0075 §24).
    pub enforced: bool,
}

/// Proveniência da aprovação humana.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalProvenanceV1 {
    pub approval_id: String,
    /// Hash do assunto exacto da autorização. É o que impede alterar os
    /// argumentos depois da aprovação (SPEC-0075 §15.2).
    pub authorization_subject_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at_unix_nanos: Option<u64>,
}

/// Conteúdo observável — o que sobra depois de o [`crate::privacy`] passar.
///
/// Os campos `*_hash` existem mesmo quando os bytes **não** foram guardados: é
/// o que permite provar mais tarde que o argumento aprovado foi o argumento
/// executado, sem nunca ter persistido o argumento (SPEC-0074 §11).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceContentV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    /// BLAKE3 do conteúdo **canónico** (hex). Presente mesmo em
    /// `METADATA_ONLY`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_content_hash: Option<String>,
    /// Bytes efectivamente persistidos. Vazio em `METADATA_ONLY`/`HASH_ONLY`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Campos tipados que sobreviveram à redacção e podem alimentar policy.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    /// Referência à decisão de policy que cobre esta evidência (SPEC-0075 §18).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyProvenanceV1>,
    /// Referência a uma aprovação humana.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalProvenanceV1>,
    /// Atributos desconhecidos, com tecto (SPEC-0074 §12): um campo opcional
    /// que ninguém previu não derruba o lote nem muda os campos canónicos que
    /// já existem.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, String>,
}

/// De onde veio a evidência — e como deduplicá-la (SPEC-0074 §14).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSourceV1 {
    /// `otlp_http`, `otlp_grpc`, `mcp_proxy`, `mcp_observe`, `gateway`,
    /// `demo`...
    pub source_kind: String,
    /// Instância concreta (ex.: `service.instance.id` do OTel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_instance: Option<String>,
    /// Sequência declarada pela origem, quando existe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at_unix_nanos: Option<u64>,
}

/// Modo de captura efectivo (SPEC-0074 §11).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureModeV1 {
    /// Default. Só metadados; nenhum corpo é persistido.
    #[default]
    MetadataOnly,
    /// Metadados + hashes de conteúdo, sem bytes.
    HashOnly,
    /// Bytes com redacção e tecto de tamanho.
    Redacted,
    /// Bytes completos. Exige configuração administrativa explícita.
    FullExplicit,
}

impl CaptureModeV1 {
    pub fn tag(self) -> u8 {
        match self {
            Self::MetadataOnly => 1,
            Self::HashOnly => 2,
            Self::Redacted => 3,
            Self::FullExplicit => 4,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::MetadataOnly => "METADATA_ONLY",
            Self::HashOnly => "HASH_ONLY",
            Self::Redacted => "REDACTED",
            Self::FullExplicit => "FULL_EXPLICIT",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "metadata_only" | "metadata-only" => Self::MetadataOnly,
            "hash_only" | "hash-only" => Self::HashOnly,
            "redacted" => Self::Redacted,
            "full_explicit" | "full-explicit" => Self::FullExplicit,
            _ => return None,
        })
    }
    /// Se este modo autoriza persistir bytes de corpo.
    pub fn persists_body(self) -> bool {
        matches!(self, Self::Redacted | Self::FullExplicit)
    }
}

/// O que foi omitido e porquê (SPEC-0074 §11).
///
/// Isto é o oposto de um campo decorativo: sem ele, um bundle em
/// `METADATA_ONLY` seria indistinguível de um bundle a que alguém apagou os
/// corpos. A auditoria tem de conseguir ver que a ausência foi **política**.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyEnvelopeV1 {
    pub capture_mode: CaptureModeV1,
    pub redaction_applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_profile_id: Option<String>,
    /// Quantos campos foram substituídos por um marcador.
    #[serde(default)]
    pub redacted_field_count: u32,
    /// Quantos bytes foram cortados por exceder o tecto configurado.
    #[serde(default)]
    pub truncated_bytes: u64,
    /// Classes de segredo que os filtros reconheceram (`bearer`, `aws_key`...).
    /// Nunca o segredo.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_classes_detected: Vec<String>,
}

/// A unidade canónica de evidência de agente (SPEC-0074 §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEvidenceV1 {
    pub schema_version: u16,
    pub evidence_id: String,
    pub observed_at_unix_nanos: u64,

    pub tenant_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    pub agent: AgentIdentityV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human: Option<HumanIdentityRefV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DelegationRefV1>,

    pub kind: AgentEvidenceKindV1,
    pub subject: EvidenceSubjectV1,
    pub content: EvidenceContentV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<EvidenceOutcomeV1>,
    pub source: EvidenceSourceV1,
    pub privacy: PrivacyEnvelopeV1,

    /// Proveniência LÓGICA (§15). Não confundir com integridade de
    /// armazenamento, que é o LSN/Merkle.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<String>,
    pub dedupe_key: String,
}

impl AgentEvidenceV1 {
    /// Esqueleto mínimo; quem constrói preenche o resto.
    pub fn new(
        tenant_id: impl Into<String>,
        kind: AgentEvidenceKindV1,
        observed_at_unix_nanos: u64,
    ) -> Self {
        Self {
            schema_version: AGENT_EVIDENCE_SCHEMA_V1,
            evidence_id: ulid::Ulid::new().to_string(),
            observed_at_unix_nanos,
            tenant_id: tenant_id.into(),
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            run_id: None,
            session_id: None,
            agent: AgentIdentityV1::default(),
            human: None,
            delegation: None,
            kind,
            subject: EvidenceSubjectV1::default(),
            content: EvidenceContentV1::default(),
            outcome: None,
            source: EvidenceSourceV1 {
                source_kind: "internal".to_string(),
                ..Default::default()
            },
            privacy: PrivacyEnvelopeV1::default(),
            parents: Vec::new(),
            dedupe_key: String::new(),
        }
    }

    /// O run a que esta evidência pertence, com uma queda de recurso explícita
    /// para o `trace_id`.
    ///
    /// A queda existe porque um exporter OTel genérico não emite `run_id`
    /// nenhum — o que ele tem é o trace. Sem esta regra, metade da timeline de
    /// um agente instrumentado só com OpenTelemetry ficaria órfã.
    pub fn effective_run_id(&self) -> Option<&str> {
        self.run_id
            .as_deref()
            .or(self.trace_id.as_deref())
            .filter(|s| !s.is_empty())
    }
}
