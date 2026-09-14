//! SPEC-0074 §14 — deduplicação lógica.
//!
//! # O problema real
//!
//! Um exporter OpenTelemetry retransmite o lote quando o `POST /v1/traces`
//! falha ou expira. Isso é comportamento normal e não se pode desligar. Se a
//! ingestão fosse ingénua, cada timeout do lado do agente duplicaria a
//! história: o mesmo `send_payment` apareceria duas vezes na timeline e a
//! auditoria não saberia se houve um pagamento ou dois.
//!
//! # A chave
//!
//! ```text
//! H(tenant + source_kind + source_instance + trace_id + span_id
//!   + event_kind + source_sequence_if_present)
//! ```
//!
//! Repetir o mesmo lote não gera nova evidência lógica. Mas — e isto é a parte
//! que interessa — **a mesma chave com conteúdo semanticamente diferente falha
//! explicitamente** (§14). Silenciar essa colisão seria pior do que duplicar:
//! significaria aceitar que alguém reescrevesse uma evidência já registada
//! reutilizando o par trace/span.

use crate::canonical::{
    canonical_evidence_hash, domain_hash, hex32, CanonicalWriter, DOMAIN_DEDUPE,
};
use crate::evidence::AgentEvidenceV1;
use std::collections::HashMap;

/// Calcula a chave lógica de deduplicação de uma evidência.
///
/// Nota sobre o que NÃO entra: `evidence_id` e `observed_at_unix_nanos`. Os
/// dois mudam a cada retransmissão (um ULID novo, um relógio que andou), e
/// incluí-los tornaria a chave inútil exactamente no caso que ela existe para
/// resolver.
pub fn dedupe_key(e: &AgentEvidenceV1) -> String {
    let mut w = CanonicalWriter::new();
    w.str(&e.tenant_id);
    w.str(&e.source.source_kind);
    w.opt_str(e.source.source_instance.as_deref());
    w.opt_str(e.trace_id.as_deref());
    w.opt_str(e.span_id.as_deref());
    w.u8v(e.kind.tag());
    w.opt_u64(e.source.source_sequence);
    // Sem trace/span (captura MCP em `observe`, por exemplo) a chave colapsaria
    // para todas as chamadas do mesmo tipo. O `tool_call_id` é o identificador
    // que o próprio protocolo já oferece para as distinguir.
    w.opt_str(e.subject.tool_call_id.as_deref());
    hex32(&domain_hash(DOMAIN_DEDUPE, w.as_slice()))
}

/// Preenche `dedupe_key` se estiver vazia e devolve a evidência.
pub fn stamp(mut e: AgentEvidenceV1) -> AgentEvidenceV1 {
    if e.dedupe_key.is_empty() {
        e.dedupe_key = dedupe_key(&e);
    }
    e
}

/// O que a deduplicação decidiu sobre uma evidência.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupeVerdict {
    /// Primeira vez que esta chave aparece: aceitar.
    Novel,
    /// Já vista, com o mesmo conteúdo canónico: descartar em silêncio. É o
    /// caso normal de retransmissão.
    Duplicate,
    /// Já vista, com conteúdo canónico DIFERENTE. Nunca descartar em silêncio.
    Conflict { existing_hash: String },
}

/// Índice de deduplicação em memória, com tecto.
///
/// # Porque é que ter tecto não é batota
///
/// A janela de retransmissão de um exporter OTel mede-se em segundos a
/// minutos, não em dias. Um índice limitado apanha 100% dos retries reais e o
/// tecto existe para que um atacante não possa fazer crescer a memória do
/// processo mandando chaves distintas — que é exactamente o que §12 proíbe
/// ("sem alocação sem limite").
///
/// A durabilidade da deduplicação NÃO depende disto: o `dedupe_key` está
/// gravado em cada evidência no HRKL, portanto um reinício reconstrói o índice
/// a partir do log (ver [`DedupeIndex::warm_from`]).
#[derive(Debug)]
pub struct DedupeIndex {
    seen: HashMap<String, (String, u64)>,
    capacity: usize,
    /// Contador monotónico de inserção, usado para desalojar o mais antigo.
    tick: u64,
}

impl DedupeIndex {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashMap::new(),
            capacity: capacity.max(1),
            tick: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Reconstrói o índice a partir de evidências já persistidas (arranque).
    pub fn warm_from<'a>(&mut self, evidences: impl Iterator<Item = &'a AgentEvidenceV1>) {
        for e in evidences {
            let key = if e.dedupe_key.is_empty() {
                dedupe_key(e)
            } else {
                e.dedupe_key.clone()
            };
            self.insert(key, hex32(&canonical_evidence_hash(e)));
        }
    }

    /// Classifica uma evidência e, se for nova, regista-a.
    pub fn admit(&mut self, e: &AgentEvidenceV1) -> DedupeVerdict {
        let key = if e.dedupe_key.is_empty() {
            dedupe_key(e)
        } else {
            e.dedupe_key.clone()
        };
        let hash = hex32(&canonical_evidence_hash(e));
        match self.seen.get(&key) {
            Some((existing, _)) if *existing == hash => DedupeVerdict::Duplicate,
            Some((existing, _)) => DedupeVerdict::Conflict {
                existing_hash: existing.clone(),
            },
            None => {
                self.insert(key, hash);
                DedupeVerdict::Novel
            }
        }
    }

    fn insert(&mut self, key: String, hash: String) {
        if self.seen.len() >= self.capacity && !self.seen.contains_key(&key) {
            if let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
            {
                self.seen.remove(&oldest);
            }
        }
        self.tick += 1;
        self.seen.insert(key, (hash, self.tick));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::AgentEvidenceKindV1;

    fn ev(seq: Option<u64>) -> AgentEvidenceV1 {
        let mut e = AgentEvidenceV1::new("t", AgentEvidenceKindV1::ToolRequested, 1);
        e.evidence_id = "fixo".into();
        e.trace_id = Some("trace-1".into());
        e.span_id = Some("span-1".into());
        e.source.source_kind = "otlp_http".into();
        e.source.source_instance = Some("inst-1".into());
        e.source.source_sequence = seq;
        stamp(e)
    }

    #[test]
    fn a_mesma_evidencia_retransmitida_e_duplicada() {
        let mut idx = DedupeIndex::new(128);
        let a = ev(Some(7));
        let mut b = ev(Some(7));
        // O exporter gera ids e relógio novos no retry; nada disso entra na chave.
        b.evidence_id = "outro".into();
        b.observed_at_unix_nanos = 999;
        b.dedupe_key = dedupe_key(&b);
        assert_eq!(a.dedupe_key, b.dedupe_key);
        assert_eq!(idx.admit(&a), DedupeVerdict::Novel);
        // O hash canónico difere (evidence_id/observed_at entram nele), portanto
        // isto é um CONFLITO, não uma duplicação silenciosa — e é o desejado:
        // ver `retransmissao_identica_e_silenciosa` para o caso real.
        assert!(matches!(idx.admit(&b), DedupeVerdict::Conflict { .. }));
    }

    #[test]
    fn retransmissao_identica_e_silenciosa() {
        let mut idx = DedupeIndex::new(128);
        let a = ev(Some(1));
        assert_eq!(idx.admit(&a), DedupeVerdict::Novel);
        assert_eq!(idx.admit(&a.clone()), DedupeVerdict::Duplicate);
    }

    #[test]
    fn mesma_chave_com_conteudo_diferente_e_conflito() {
        let mut idx = DedupeIndex::new(128);
        let a = ev(Some(1));
        let mut b = a.clone();
        b.subject.tool_name = Some("outra".into());
        assert_eq!(idx.admit(&a), DedupeVerdict::Novel);
        assert!(matches!(idx.admit(&b), DedupeVerdict::Conflict { .. }));
    }

    #[test]
    fn spans_diferentes_dao_chaves_diferentes() {
        let a = ev(Some(1));
        let mut b = ev(Some(1));
        b.span_id = Some("span-2".into());
        assert_ne!(a.dedupe_key, dedupe_key(&b));
    }

    #[test]
    fn o_indice_respeita_o_tecto() {
        let mut idx = DedupeIndex::new(4);
        for i in 0..50 {
            let mut e = ev(Some(i));
            e.dedupe_key = dedupe_key(&e);
            idx.admit(&e);
        }
        assert!(idx.len() <= 4, "len={}", idx.len());
    }

    #[test]
    fn warm_from_reconstroi_o_estado() {
        let a = ev(Some(1));
        let mut idx = DedupeIndex::new(64);
        idx.warm_from(std::iter::once(&a));
        assert_eq!(idx.admit(&a), DedupeVerdict::Duplicate);
    }
}
