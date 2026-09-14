//! SPEC-0074 §15–§16 — persistência da evidência no HRKL e provas de
//! armazenamento.
//!
//! # Duas integridades que NÃO são a mesma coisa (§15)
//!
//! ```text
//! parents        proveniência LÓGICA   "esta tool call veio daquele run"
//! LSN / Merkle   integridade FÍSICA    "este registo não foi alterado"
//! ```
//!
//! Uma prova de Merkle válida prova inclusão e integridade. **Não** prova que a
//! decisão foi correcta (§16.2). Este módulo devolve as duas coisas em campos
//! separados e nunca as apresenta como uma só.
//!
//! # Porque é que uma evidência acabada de gravar NÃO tem prova
//!
//! [`heraclitus_log::v6::prove_lsn`] exige um segmento **selado**: a raiz
//! lógica de um segmento ainda a crescer mudaria a cada append e uma prova
//! emitida contra ela seria inútil dez milissegundos depois. Portanto uma
//! evidência recém-ingerida fica em [`ProofAvailability::PendingSeal`] — que a
//! UI mostra como `UNVERIFIED`, nunca como `VERIFIED` (SPEC-0076 §8).

use crate::canonical::{canonical_evidence_hash, hex32};
use crate::dedupe;
use crate::evidence::AgentEvidenceV1;
use heraclitus_core::{Episode, EventKind, HeraclitusError, Lsn};
use heraclitus_log::v6::error::HARD_MAX_BLOCK_BYTES;
use heraclitus_log::v6::merkle::ProofStep;
use heraclitus_log::v6::{prove_lsn, InclusionProof, LsnProof};
use heraclitus_log::AnyLog;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Rótulo do `EventKind::Custom` que marca uma evidência de agente no log.
///
/// Um kind próprio (e não `Observation` com um atributo) é o que permite a
/// varredura filtrar sem desserializar o conteúdo de cada episódio, e o que
/// impede a evidência de agente de se misturar com o tráfego normal do banco.
pub const AGENT_EVIDENCE_KIND: &str = "AgentEvidence";

/// Atributos indexáveis gravados em cada episódio. Existem para que a busca de
/// §30 (run id, agent, tool, decisão) não exija abrir o corpo.
pub mod attr {
    pub const TENANT: &str = "agent.tenant";
    pub const RUN: &str = "agent.run";
    pub const KIND: &str = "agent.kind";
    pub const TOOL: &str = "agent.tool";
    pub const SERVER: &str = "agent.server";
    pub const HUMAN: &str = "agent.human";
    pub const DECISION: &str = "agent.decision";
    pub const EFFECT: &str = "agent.effect";
    pub const DEDUPE: &str = "agent.dedupe";
    pub const EVIDENCE_ID: &str = "agent.evidence_id";
}

/// Uma evidência tal como saiu do log: com o LSN que lhe pertence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvidence {
    pub lsn: Lsn,
    pub evidence: AgentEvidenceV1,
}

impl StoredEvidence {
    /// A identidade lógica do registo, em hex.
    pub fn record_hash(&self) -> String {
        hex32(&canonical_evidence_hash(&self.evidence))
    }
}

/// Estado da prova de armazenamento de um LSN.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProofAvailability {
    /// Há prova: o segmento está selado e a inclusão fecha contra a raiz.
    Available(StorageProof),
    /// O registo existe, mas vive no segmento activo (ainda não selado).
    /// Honesto e temporário — o worker de packing sela e a prova aparece.
    PendingSeal,
    /// O LSN não foi encontrado em segmento nenhum do manifesto.
    NotFound,
}

/// Um passo da prova de inclusão, na forma que viaja em JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStepJson {
    pub sibling: String,
    /// `true` se o irmão é o nó da ESQUERDA (ou seja, nós somos o direito).
    pub sibling_is_left: bool,
}

/// Reconstrói a prova do HRKL a partir da forma serializada, para que o
/// verificador offline use **a mesma** `verify_inclusion_proof` do motor e não
/// uma segunda implementação de Merkle (a regra do sink único da SPEC-0050
/// §27: duas implementações divergem e a prova passa a depender de qual correu).
pub fn rebuild_inclusion_proof(p: &StorageProof) -> Option<InclusionProof> {
    let mut path = Vec::with_capacity(p.inclusion_path.len());
    for step in &p.inclusion_path {
        path.push(ProofStep {
            sibling: crate::canonical::unhex32(&step.sibling)?,
            sibling_is_left: step.sibling_is_left,
        });
    }
    Some(InclusionProof {
        leaf_index: p.leaf_index,
        leaf_count: p.leaf_count,
        path,
    })
}

/// Fecha uma prova contra a raiz que ela própria declara.
pub fn proof_closes(p: &StorageProof) -> bool {
    let (Some(proof), Some(leaf), Some(root)) = (
        rebuild_inclusion_proof(p),
        crate::canonical::unhex32(&p.canonical_record_hash),
        crate::canonical::unhex32(&p.logical_root),
    ) else {
        return false;
    };
    heraclitus_log::v6::merkle::verify_inclusion_proof(&leaf, &proof, &root)
}

/// A prova pericial de um registo (SPEC-0074 §16.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProof {
    pub lsn: Lsn,
    /// Hash canónico do registo **tal como o HRKL o vê** (`StoragePayload`),
    /// que não é o mesmo que o hash canónico da evidência de agente. Os dois
    /// viajam juntos de propósito: o primeiro liga ao Merkle, o segundo ao
    /// modelo de produto.
    pub canonical_record_hash: String,
    /// O hash canónico da própria evidência (domínio `agent.evidence.v1`).
    pub canonical_evidence_hash: String,
    pub logical_root: String,
    pub segment_id: u64,
    pub generation: u32,
    /// A prova de inclusão, de baixo para cima. A direcção viaja com o irmão
    /// porque sem ela a prova não se recompõe: `H(a||b) != H(b||a)`.
    pub inclusion_path: Vec<ProofStepJson>,
    pub leaf_index: u64,
    pub leaf_count: u64,
    /// Recibo de tempo, quando a ancoragem RFC 3161 estiver configurada.
    pub timestamp_receipt: Option<String>,
    /// Se a prova fecha contra a raiz declarada. `false` aqui é um incidente.
    pub verified: bool,
}

/// Converte uma evidência num episódio do log.
///
/// O corpo é JSON canónico (`serde_json` com chaves ordenadas por construção —
/// todos os mapas do modelo são `BTreeMap`). O JSON é a forma de **transporte**
/// e leitura; a identidade lógica continua a ser o codec manual de
/// [`crate::canonical`], nunca os bytes do JSON.
pub fn evidence_to_episode(e: &AgentEvidenceV1) -> Result<Episode, HeraclitusError> {
    let body = serde_json::to_vec(e)
        .map_err(|err| HeraclitusError::Config(format!("evidência não serializa: {err}")))?;
    let mut ep = Episode::new(
        e.agent.agent_id.clone(),
        EventKind::Custom(AGENT_EVIDENCE_KIND.to_string()),
        body,
    );
    ep.session_id = e.effective_run_id().map(str::to_string).unwrap_or_default();
    ep.attrs.insert(attr::TENANT.into(), e.tenant_id.clone());
    ep.attrs
        .insert(attr::KIND.into(), e.kind.label().to_string());
    ep.attrs
        .insert(attr::EVIDENCE_ID.into(), e.evidence_id.clone());
    ep.attrs.insert(attr::DEDUPE.into(), e.dedupe_key.clone());
    if let Some(run) = e.effective_run_id() {
        ep.attrs.insert(attr::RUN.into(), run.to_string());
    }
    if let Some(t) = &e.subject.tool_name {
        ep.attrs.insert(attr::TOOL.into(), t.clone());
    }
    if let Some(s) = &e.subject.server_id {
        ep.attrs.insert(attr::SERVER.into(), s.clone());
    }
    if let Some(h) = &e.human {
        ep.attrs.insert(attr::HUMAN.into(), h.subject_id.clone());
    }
    if let Some(p) = &e.content.policy {
        ep.attrs.insert(attr::DECISION.into(), p.decision.clone());
    }
    if let Some(x) = &e.subject.external_effect_id {
        ep.attrs.insert(attr::EFFECT.into(), x.clone());
    }
    Ok(ep)
}

/// Lê a evidência de volta de um episódio, se for uma.
pub fn episode_to_evidence(ep: &Episode) -> Option<AgentEvidenceV1> {
    match &ep.kind {
        EventKind::Custom(k) if k == AGENT_EVIDENCE_KIND => {
            serde_json::from_slice(&ep.content).ok()
        }
        _ => None,
    }
}

/// O log de evidência: append e varredura.
///
/// É um trait para que o `heraclitus-agent` não dependa do `Engine` do
/// servidor (que arrasta índices, views, HTTP e o resto do banco). Quem quiser
/// evidência com índices vivos passa um adaptador sobre o `Engine`; os testes
/// e o verificador passam o [`AnyLogEvidenceStore`].
pub trait EvidenceLog: Send + Sync {
    fn append_evidence(&self, e: &AgentEvidenceV1) -> Result<Lsn, HeraclitusError>;
    fn scan_evidence(&self, from: Lsn, to: Lsn) -> Result<Vec<StoredEvidence>, HeraclitusError>;
    fn read_evidence(&self, lsn: Lsn) -> Result<Option<StoredEvidence>, HeraclitusError>;
    fn head(&self) -> Lsn;
    fn flush(&self) -> Result<(), HeraclitusError>;
    /// Prova de armazenamento para um LSN, quando o segmento já está selado.
    fn prove(&self, lsn: Lsn) -> Result<ProofAvailability, HeraclitusError>;
}

/// Implementação sobre o log do banco ([`AnyLog`]).
pub struct AnyLogEvidenceStore {
    log: Arc<AnyLog>,
}

impl AnyLogEvidenceStore {
    pub fn new(log: Arc<AnyLog>) -> Self {
        Self { log }
    }

    pub fn log(&self) -> &Arc<AnyLog> {
        &self.log
    }
}

impl EvidenceLog for AnyLogEvidenceStore {
    fn append_evidence(&self, e: &AgentEvidenceV1) -> Result<Lsn, HeraclitusError> {
        let stamped;
        let e = if e.dedupe_key.is_empty() {
            stamped = dedupe::stamp(e.clone());
            &stamped
        } else {
            e
        };
        self.log.append(evidence_to_episode(e)?)
    }

    fn scan_evidence(&self, from: Lsn, to: Lsn) -> Result<Vec<StoredEvidence>, HeraclitusError> {
        let rows = self.log.scan(from, to)?;
        Ok(rows
            .into_iter()
            .filter_map(|(lsn, ep)| {
                episode_to_evidence(&ep).map(|evidence| StoredEvidence { lsn, evidence })
            })
            .collect())
    }

    fn read_evidence(&self, lsn: Lsn) -> Result<Option<StoredEvidence>, HeraclitusError> {
        Ok(self.log.read(lsn)?.and_then(|(lsn, ep)| {
            episode_to_evidence(&ep).map(|evidence| StoredEvidence { lsn, evidence })
        }))
    }

    fn head(&self) -> Lsn {
        self.log.head()
    }

    fn flush(&self) -> Result<(), HeraclitusError> {
        self.log.flush()
    }

    fn prove(&self, lsn: Lsn) -> Result<ProofAvailability, HeraclitusError> {
        let Some(v6) = self.log.v6_arc() else {
            // O formato legado não tem `prove_lsn`. Dizê-lo é melhor do que
            // inventar uma prova: o produto promete verificação, e uma
            // verificação que não existe tem de aparecer como não existindo.
            return Ok(ProofAvailability::NotFound);
        };
        let manifest = v6.manifest();
        let Some(desc) = manifest
            .segments_v2
            .iter()
            .find(|s| s.first_lsn <= lsn && lsn <= s.last_lsn && s.record_count > 0)
        else {
            // Não está em segmento selado nenhum: ou não existe, ou ainda está
            // no activo. Distinguir os dois exige ler o log.
            return Ok(match self.log.read(lsn)? {
                Some(_) => ProofAvailability::PendingSeal,
                None => ProofAvailability::NotFound,
            });
        };
        let Some(gen) = desc.active() else {
            return Ok(ProofAvailability::NotFound);
        };
        // `location` é relativa à raiz do log, e o manifesto é dados em disco —
        // dados que um atacante com acesso ao ficheiro poderia ter escrito. A
        // mesma validação que o motor faz em `resolve_location` tem de ser
        // feita aqui: um caminho absoluto ou com `..` é corrupção, não um
        // caminho a seguir.
        let path =
            safe_join(v6.dir(), &gen.location).ok_or_else(|| HeraclitusError::Corruption {
                context: "agent evidence proof".into(),
                detail: format!(
                    "localização de geração insegura no manifesto: {}",
                    gen.location
                ),
            })?;
        let Some(proof) = prove_lsn(
            &path,
            lsn,
            HARD_MAX_BLOCK_BYTES,
            &heraclitus_log::canonical_hash_storage_payload_v6,
        )?
        else {
            return Ok(ProofAvailability::NotFound);
        };
        let evidence_hash = self
            .read_evidence(lsn)?
            .map(|s| s.record_hash())
            .unwrap_or_default();
        let verified = proof.verify();
        Ok(ProofAvailability::Available(render_proof(
            &proof,
            desc.segment_id,
            gen.generation,
            evidence_hash,
            verified,
        )))
    }
}

/// Junta uma localização declarada no manifesto à raiz do log, recusando tudo
/// o que não seja um caminho relativo simples.
fn safe_join(root: &std::path::Path, location: &str) -> Option<std::path::PathBuf> {
    use std::path::{Component, Path};
    let rel = Path::new(location);
    if rel.is_absolute()
        || rel.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return None;
    }
    Some(root.join(rel))
}

fn render_proof(
    proof: &LsnProof,
    segment_id: u64,
    generation: u32,
    canonical_evidence_hash: String,
    verified: bool,
) -> StorageProof {
    StorageProof {
        lsn: proof.lsn,
        canonical_record_hash: hex32(&proof.canonical_record_hash),
        canonical_evidence_hash,
        logical_root: hex32(&proof.logical_root),
        segment_id,
        generation,
        inclusion_path: proof
            .proof
            .path
            .iter()
            .map(|s| ProofStepJson {
                sibling: hex32(&s.sibling),
                sibling_is_left: s.sibling_is_left,
            })
            .collect(),
        leaf_index: proof.proof.leaf_index,
        leaf_count: proof.proof.leaf_count,
        timestamp_receipt: None,
        verified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::AgentEvidenceKindV1;

    fn ev() -> AgentEvidenceV1 {
        let mut e = AgentEvidenceV1::new("acme", AgentEvidenceKindV1::ToolInvocationFinished, 42);
        e.agent.agent_id = "procurement-agent".into();
        e.run_id = Some("run-1".into());
        e.subject.tool_name = Some("send_payment".into());
        e.subject.server_id = Some("finance".into());
        e.subject.external_effect_id = Some("payment-84723".into());
        dedupe::stamp(e)
    }

    #[test]
    fn episodio_preserva_a_evidencia_ida_e_volta() {
        let e = ev();
        let ep = evidence_to_episode(&e).unwrap();
        let back = episode_to_evidence(&ep).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn atributos_indexaveis_sao_gravados() {
        let ep = evidence_to_episode(&ev()).unwrap();
        assert_eq!(ep.attrs.get(attr::RUN).map(String::as_str), Some("run-1"));
        assert_eq!(
            ep.attrs.get(attr::TOOL).map(String::as_str),
            Some("send_payment")
        );
        assert_eq!(
            ep.attrs.get(attr::KIND).map(String::as_str),
            Some("ToolInvocationFinished")
        );
        assert_eq!(
            ep.attrs.get(attr::EFFECT).map(String::as_str),
            Some("payment-84723")
        );
    }

    #[test]
    fn um_episodio_normal_nao_e_lido_como_evidencia() {
        let ep = Episode::new("x", EventKind::Observation, b"{}".to_vec());
        assert!(episode_to_evidence(&ep).is_none());
    }
}
