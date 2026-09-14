//! # Heraclitus Agent Black Box — o plano de evidência de agentes
//!
//! Implementa a **SPEC-0074** (captura e prova) e a parte determinística e sem
//! sockets da **SPEC-0075** (autorização, delegação e aprovação humana). As
//! superfícies de rede — ingestão OTLP, proxy MCP, API e consola — vivem no
//! `heraclitus-agent-gateway`, que depende deste crate. Este não abre sockets
//! (SPEC-0074 §7.1).
//!
//! ## A frase que este código tem de tornar verdadeira
//!
//! > Ligue o OpenTelemetry do seu agente ao Heraclitus. Ele regista cada
//! > execução relevante num histórico append-only verificável, liga tool calls
//! > às suas evidências e exporta um pacote que pode ser conferido offline
//! > depois, sem trocar o banco ou o framework da aplicação.
//!
//! ## Mapa
//!
//! | módulo | SPEC | papel |
//! |---|---|---|
//! | [`evidence`] | §8–§11 | o modelo canónico `AgentEvidenceV1` |
//! | [`canonical`] | §25 | codec manual e hash com separação de domínio |
//! | [`privacy`] | §11, §23 | o portão que impede observabilidade de virar fuga |
//! | [`dedupe`] | §14 | chave lógica; retransmissão não duplica |
//! | [`store`] | §15–§16 | append no HRKL v6 e `prove_lsn` no caminho real |
//! | [`otlp`] | §12 | ingestão OpenTelemetry (protobuf e JSON) |
//! | [`mcp`] | §13 | captura de tool calls MCP |
//! | [`projection`] | §20 | `RunSummary`, timeline, tool calls, aprovações |
//! | [`bundle`] | §17 | Evidence Bundle v1 |
//! | [`verifier`] | §18 | verificação offline e códigos de saída |
//! | [`policy`] | 0075 §11–§18 | policy declarativa determinística |
//! | [`action`] | 0075 §6–§16 | acção, autorização ligada ao conteúdo, aprovação |
//! | [`identity`] | 0075 §7–§8 | validação OIDC/JWT |
//! | [`config`] | §22, 0075 §29 | configuração TOML |
//! | [`metrics`] | §21, 0075 §30 | nomes de métrica, num sítio só |
//! | [`demo`] | 0076 §21–§22 | o demo canónico, sem API key externa |
//! | [`doctor`] | 0076 §23 | diagnóstico orientado a acção |
//!
//! ## O que este crate NÃO é
//!
//! Não é um SIEM, não é UEBA, não é um SOAR e não reutiliza `SecurityEvent`
//! para caber na arquitectura antiga (§4, §9). O Sentinel continua onde estava
//! e é opcional (§29).

pub mod action;
pub mod bundle;
pub mod canonical;
pub mod config;
pub mod dedupe;
pub mod demo;
pub mod doctor;
pub mod evidence;
pub mod identity;
pub mod mcp;
pub mod metrics;
pub mod otlp;
pub mod policy;
pub mod privacy;
pub mod projection;
pub mod store;
pub mod verifier;
pub mod zip;

pub use action::{
    ActionAuthorizationV1, AgentActionRequestV1, ApprovalDecisionV1, ApprovalRequestV1,
    ApprovalStore, ApprovalVerdict,
};
pub use bundle::{
    build_bundle, BundleSelectionV1, EvidenceBundleManifestV1, ExportOptions, BUNDLE_FORMAT_V1,
};
pub use canonical::{canonical_evidence_bytes, canonical_evidence_hash, hex32, unhex32};
pub use config::{AgentBlackBoxConfig, AgentGatewayConfig, GatewayMode};
pub use dedupe::{dedupe_key, DedupeIndex, DedupeVerdict};
pub use doctor::{Check, CheckStatus, DoctorReport};
pub use evidence::{
    AgentEvidenceKindV1, AgentEvidenceV1, AgentIdentityV1, ApprovalProvenanceV1, CaptureModeV1,
    DelegationRefV1, EvidenceContentV1, EvidenceOutcomeV1, EvidenceSourceV1, EvidenceSubjectV1,
    HumanIdentityRefV1, PolicyProvenanceV1, PrivacyEnvelopeV1, AGENT_EVIDENCE_SCHEMA_V1,
};
pub use policy::{
    AgentPolicyDecisionV1, AgentPolicyDocument, DeterministicAgentPolicyEngine, PolicyEvaluation,
};
pub use privacy::{RawContent, RedactionProfile};
pub use projection::{IntegrityState, RunSummary, RunTimelineEntry, ToolCallSummary};
pub use store::{
    AnyLogEvidenceStore, EvidenceLog, ProofAvailability, StorageProof, StoredEvidence,
};
pub use verifier::{verify_bundle, VerifyExit, VerifyReport};
