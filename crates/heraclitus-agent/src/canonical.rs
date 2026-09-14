//! Codec canónico da evidência de agente — a identidade lógica de um registo.
//!
//! # Porque não `serde_json::to_vec`
//!
//! Pela mesma razão que a SPEC-0050 §9 deu ao HRKL: se a identidade lógica
//! dependesse do `serde`, actualizar a biblioteca mudaria o hash de histórico
//! já selado e uma prova emitida ontem deixaria de fechar hoje. Um bundle
//! exportado em Janeiro tem de continuar a verificar em Dezembro, com um
//! binário diferente.
//!
//! Daí um codec **manual**: ordem de campos fixa, endianness declarada, uma só
//! representação válida por valor, e mapas escritos por ordem lexicográfica da
//! chave (que é o que `BTreeMap` já garante — o codec não reordena nada, só
//! depende de a estrutura ser a certa).
//!
//! # Separação de domínio
//!
//! Cada hash leva um prefixo de domínio. Sem ele, o hash de uma evidência
//! poderia ser reaproveitado como hash de conteúdo, de projecção de policy ou
//! de ficheiro de bundle por acidente — e "acidente" aqui significa uma prova
//! que fecha contra a coisa errada.

use crate::evidence::{
    AgentEvidenceV1, AgentIdentityV1, ApprovalProvenanceV1, DelegationRefV1, EvidenceContentV1,
    EvidenceOutcomeV1, EvidenceSourceV1, EvidenceSubjectV1, HumanIdentityRefV1, PolicyProvenanceV1,
    PrivacyEnvelopeV1,
};
use std::collections::BTreeMap;

/// Versão do codec. Entra no primeiro byte de cada hash canónico.
pub const AGENT_CANONICAL_CODEC_V1: u8 = 1;

/// Domínios de hash. Nunca reutilizar um prefixo noutro contexto.
pub const DOMAIN_EVIDENCE: &[u8] = b"heraclitus.agent.evidence.v1";
pub const DOMAIN_CONTENT: &[u8] = b"heraclitus.agent.content.v1";
pub const DOMAIN_DEDUPE: &[u8] = b"heraclitus.agent.dedupe.v1";
pub const DOMAIN_POLICY_INPUT: &[u8] = b"heraclitus.agent.policy.input.v1";
pub const DOMAIN_POLICY_DOC: &[u8] = b"heraclitus.agent.policy.doc.v1";
pub const DOMAIN_AUTHZ_SUBJECT: &[u8] = b"heraclitus.agent.authz.subject.v1";
pub const DOMAIN_BUNDLE_FILE: &[u8] = b"heraclitus.agent.bundle.file.v1";

/// Escritor canónico. Um `Vec<u8>` não chega porque queremos que *todos* os
/// escreventes passem pelas mesmas primitivas — um `write_str` que esqueça o
/// prefixo de comprimento abre a porta a colisões triviais (`"ab" + "c"` vs
/// `"a" + "bc"`).
#[derive(Debug, Default)]
pub struct CanonicalWriter {
    buf: Vec<u8>,
}

impl CanonicalWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(512),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// ULEB128, a mesma forma canónica do HRKL v6 (`heraclitus_log::v6::varint`).
    pub fn u64v(&mut self, v: u64) -> &mut Self {
        heraclitus_log::v6::varint::put_varint(&mut self.buf, v);
        self
    }

    pub fn u8v(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u16le(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn i64le(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.buf.push(u8::from(v));
        self
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u64v(b.len() as u64);
        self.buf.extend_from_slice(b);
        self
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    /// `Option<&str>`: um byte de presença e depois, se presente, a string.
    /// Sem o byte, `Some("")` e `None` colidiriam.
    pub fn opt_str(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            Some(v) => {
                self.u8v(1);
                self.str(v);
            }
            None => {
                self.u8v(0);
            }
        }
        self
    }

    pub fn opt_u64(&mut self, v: Option<u64>) -> &mut Self {
        match v {
            Some(x) => {
                self.u8v(1);
                self.u64v(x);
            }
            None => {
                self.u8v(0);
            }
        }
        self
    }

    pub fn opt_i64(&mut self, v: Option<i64>) -> &mut Self {
        match v {
            Some(x) => {
                self.u8v(1);
                self.i64le(x);
            }
            None => {
                self.u8v(0);
            }
        }
        self
    }

    pub fn opt_u32(&mut self, v: Option<u32>) -> &mut Self {
        self.opt_u64(v.map(u64::from))
    }

    /// Mapa de strings, por ordem lexicográfica da chave. `BTreeMap` já itera
    /// assim; o tipo do parâmetro é a garantia.
    pub fn map(&mut self, m: &BTreeMap<String, String>) -> &mut Self {
        self.u64v(m.len() as u64);
        for (k, v) in m {
            self.str(k);
            self.str(v);
        }
        self
    }

    pub fn str_list(&mut self, items: &[String]) -> &mut Self {
        self.u64v(items.len() as u64);
        for s in items {
            self.str(s);
        }
        self
    }
}

/// BLAKE3 com separação de domínio: `H(codec || len(domain) || domain || body)`.
pub fn domain_hash(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[AGENT_CANONICAL_CODEC_V1]);
    let mut lenbuf = Vec::with_capacity(4);
    heraclitus_log::v6::varint::put_varint(&mut lenbuf, domain.len() as u64);
    h.update(&lenbuf);
    h.update(domain);
    h.update(body);
    *h.finalize().as_bytes()
}

/// Hex minúsculo de 32 bytes.
pub fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Descodifica um hex de 64 caracteres. Devolve `None` para tudo o resto —
/// incluindo maiúsculas, porque a forma canónica é minúscula e aceitar duas
/// formas é aceitar dois hashes para a mesma coisa.
pub fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hexval(bytes[i * 2])?;
        let lo = hexval(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Hash de um conteúdo observado (corpo de tool call, resultado, prompt).
/// Usado mesmo quando os bytes NÃO são persistidos — é o que torna
/// `METADATA_ONLY` útil em vez de apenas seguro.
pub fn content_hash(bytes: &[u8]) -> [u8; 32] {
    domain_hash(DOMAIN_CONTENT, bytes)
}

fn write_agent(w: &mut CanonicalWriter, a: &AgentIdentityV1) {
    w.str(&a.agent_id);
    w.opt_str(a.agent_name.as_deref());
    w.opt_str(a.framework.as_deref());
    w.opt_str(a.framework_version.as_deref());
    w.opt_str(a.deployment_id.as_deref());
    w.opt_str(a.code_revision.as_deref());
}

fn write_human(w: &mut CanonicalWriter, h: Option<&HumanIdentityRefV1>) {
    match h {
        Some(h) => {
            w.u8v(1);
            w.str(&h.subject_id);
            w.opt_str(h.issuer.as_deref());
            w.opt_str(h.display_hint.as_deref());
        }
        None => {
            w.u8v(0);
        }
    }
}

fn write_delegation(w: &mut CanonicalWriter, d: Option<&DelegationRefV1>) {
    match d {
        Some(d) => {
            w.u8v(1);
            w.str(&d.delegation_id);
            w.str(&d.on_behalf_of);
            w.opt_str(d.authority_scope_hash.as_deref());
        }
        None => {
            w.u8v(0);
        }
    }
}

fn write_subject(w: &mut CanonicalWriter, s: &EvidenceSubjectV1) {
    w.opt_str(s.protocol.as_deref());
    w.opt_str(s.server_id.as_deref());
    w.opt_str(s.tool_name.as_deref());
    w.opt_str(s.tool_version.as_deref());
    w.opt_str(s.tool_call_id.as_deref());
    w.opt_str(s.model_id.as_deref());
    w.opt_str(s.model_provider.as_deref());
    w.opt_str(s.external_effect_id.as_deref());
    w.opt_str(s.artifact_ref.as_deref());
}

fn write_policy(w: &mut CanonicalWriter, p: Option<&PolicyProvenanceV1>) {
    match p {
        Some(p) => {
            w.u8v(1);
            w.str(&p.policy_id);
            w.str(&p.policy_version);
            w.str(&p.policy_hash);
            w.opt_str(p.rule_id.as_deref());
            w.str(&p.decision);
            w.opt_str(p.reason_code.as_deref());
            w.str(&p.input_projection_hash);
            w.opt_str(p.authorization_id.as_deref());
            w.bool(p.enforced);
        }
        None => {
            w.u8v(0);
        }
    }
}

fn write_approval(w: &mut CanonicalWriter, a: Option<&ApprovalProvenanceV1>) {
    match a {
        Some(a) => {
            w.u8v(1);
            w.str(&a.approval_id);
            w.str(&a.authorization_subject_hash);
            w.opt_str(a.approver_subject.as_deref());
            w.opt_str(a.approver_issuer.as_deref());
            w.opt_u64(a.decided_at_unix_nanos);
        }
        None => {
            w.u8v(0);
        }
    }
}

fn write_content(w: &mut CanonicalWriter, c: &EvidenceContentV1) {
    w.opt_str(c.content_type.as_deref());
    w.opt_u64(c.content_length);
    w.opt_str(c.canonical_content_hash.as_deref());
    w.opt_str(c.body.as_deref());
    w.map(&c.fields);
    write_policy(w, c.policy.as_ref());
    write_approval(w, c.approval.as_ref());
    w.map(&c.extensions);
}

fn write_outcome(w: &mut CanonicalWriter, o: Option<&EvidenceOutcomeV1>) {
    match o {
        Some(o) => {
            w.u8v(1);
            w.opt_i64(o.transport_status);
            w.opt_str(o.protocol_status.as_deref());
            w.opt_str(o.error_code.as_deref());
            w.opt_str(o.error_message.as_deref());
            w.opt_u64(o.duration_nanos);
            w.opt_u32(o.retry_count);
        }
        None => {
            w.u8v(0);
        }
    }
}

fn write_source(w: &mut CanonicalWriter, s: &EvidenceSourceV1) {
    w.str(&s.source_kind);
    w.opt_str(s.source_instance.as_deref());
    w.opt_u64(s.source_sequence);
    w.opt_u64(s.received_at_unix_nanos);
}

fn write_privacy(w: &mut CanonicalWriter, p: &PrivacyEnvelopeV1) {
    w.u8v(p.capture_mode.tag());
    w.bool(p.redaction_applied);
    w.opt_str(p.redaction_profile_id.as_deref());
    w.u64v(u64::from(p.redacted_field_count));
    w.u64v(p.truncated_bytes);
    w.str_list(&p.secret_classes_detected);
}

/// Os bytes canónicos de uma evidência. Ordem de campos FIXA — ver o módulo.
pub fn canonical_evidence_bytes(e: &AgentEvidenceV1) -> Vec<u8> {
    let mut w = CanonicalWriter::new();
    w.u16le(e.schema_version);
    w.str(&e.evidence_id);
    w.u64v(e.observed_at_unix_nanos);
    w.str(&e.tenant_id);
    w.opt_str(e.trace_id.as_deref());
    w.opt_str(e.span_id.as_deref());
    w.opt_str(e.parent_span_id.as_deref());
    w.opt_str(e.run_id.as_deref());
    w.opt_str(e.session_id.as_deref());
    write_agent(&mut w, &e.agent);
    write_human(&mut w, e.human.as_ref());
    write_delegation(&mut w, e.delegation.as_ref());
    w.u8v(e.kind.tag());
    write_subject(&mut w, &e.subject);
    write_content(&mut w, &e.content);
    write_outcome(&mut w, e.outcome.as_ref());
    write_source(&mut w, &e.source);
    write_privacy(&mut w, &e.privacy);
    w.str_list(&e.parents);
    w.str(&e.dedupe_key);
    w.into_bytes()
}

/// A identidade lógica de uma evidência.
pub fn canonical_evidence_hash(e: &AgentEvidenceV1) -> [u8; 32] {
    domain_hash(DOMAIN_EVIDENCE, &canonical_evidence_bytes(e))
}

/// Idem, já em hex — o que a API e os ficheiros do bundle mostram.
pub fn canonical_evidence_hash_hex(e: &AgentEvidenceV1) -> String {
    hex32(&canonical_evidence_hash(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{AgentEvidenceKindV1, CaptureModeV1};

    fn sample() -> AgentEvidenceV1 {
        let mut e = AgentEvidenceV1::new("t1", AgentEvidenceKindV1::ToolRequested, 1_700_000_000);
        e.evidence_id = "01EVID".into();
        e.agent.agent_id = "procurement-agent".into();
        e.subject.tool_name = Some("send_payment".into());
        e.privacy.capture_mode = CaptureModeV1::MetadataOnly;
        e.dedupe_key = "k".into();
        e
    }

    #[test]
    fn a_ordem_de_insercao_dos_atributos_nao_muda_o_hash() {
        let mut a = sample();
        a.content.fields.insert("amount".into(), "5000".into());
        a.content.fields.insert("account".into(), "A".into());
        let mut b = sample();
        b.content.fields.insert("account".into(), "A".into());
        b.content.fields.insert("amount".into(), "5000".into());
        assert_eq!(canonical_evidence_hash(&a), canonical_evidence_hash(&b));
    }

    #[test]
    fn um_byte_diferente_muda_o_hash() {
        let a = sample();
        let mut b = sample();
        b.subject.tool_name = Some("send_paymenu".into());
        assert_ne!(canonical_evidence_hash(&a), canonical_evidence_hash(&b));
    }

    #[test]
    fn none_e_string_vazia_nao_colidem() {
        let mut a = sample();
        a.subject.server_id = None;
        let mut b = sample();
        b.subject.server_id = Some(String::new());
        assert_ne!(canonical_evidence_hash(&a), canonical_evidence_hash(&b));
    }

    #[test]
    fn campos_desconhecidos_nao_mexem_nos_canonicos() {
        // §25 (property): uma extensão nova muda o hash da evidência (é
        // conteúdo), mas não altera a leitura dos campos tipados existentes.
        let a = sample();
        let mut b = sample();
        b.content
            .extensions
            .insert("gen_ai.request.top_k".into(), "40".into());
        assert_ne!(canonical_evidence_hash(&a), canonical_evidence_hash(&b));
        assert_eq!(a.subject.tool_name, b.subject.tool_name);
        assert_eq!(a.agent.agent_id, b.agent.agent_id);
    }

    #[test]
    fn dominios_diferentes_dao_hashes_diferentes_para_o_mesmo_corpo() {
        assert_ne!(
            domain_hash(DOMAIN_EVIDENCE, b"x"),
            domain_hash(DOMAIN_CONTENT, b"x")
        );
    }

    #[test]
    fn hex_fecha_o_ciclo() {
        let h = domain_hash(DOMAIN_EVIDENCE, b"abc");
        assert_eq!(unhex32(&hex32(&h)), Some(h));
        assert_eq!(unhex32("ZZ"), None);
        // Maiúsculas não são a forma canónica.
        assert_eq!(unhex32(&hex32(&h).to_uppercase()), None);
    }

    #[test]
    fn prefixo_de_comprimento_impede_colisao_de_concatenacao() {
        let mut a = CanonicalWriter::new();
        a.str("ab").str("c");
        let mut b = CanonicalWriter::new();
        b.str("a").str("bc");
        assert_ne!(a.into_bytes(), b.into_bytes());
    }
}
