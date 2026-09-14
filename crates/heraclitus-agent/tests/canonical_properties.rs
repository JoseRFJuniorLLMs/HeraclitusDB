//! SPEC-0074 §25 (Property) — as propriedades do formato canónico.
//!
//! ```text
//! ordem de atributos não muda o canonical hash
//! retransmissão não duplica
//! mudar 1 byte invalida digest/proof
//! unknown fields não mudam os fields canónicos existentes
//! ```
//!
//! Aqui com input gerado, e não só com os casos que alguém se lembrou de
//! escrever: um codec manual falha nos valores que o autor não imaginou — a
//! string vazia, o mapa com uma chave que é prefixo de outra, o caracter
//! multibyte cortado ao meio.

use heraclitus_agent::canonical::{canonical_evidence_bytes, canonical_evidence_hash};
use heraclitus_agent::dedupe::{dedupe_key, DedupeIndex, DedupeVerdict};
use heraclitus_agent::evidence::{AgentEvidenceKindV1, AgentEvidenceV1};
use proptest::prelude::*;
use std::collections::BTreeMap;

fn evidencia(
    kind_tag: u8,
    fields: BTreeMap<String, String>,
    tool: Option<String>,
) -> AgentEvidenceV1 {
    let kind = AgentEvidenceKindV1::from_tag((kind_tag % 17) + 1).unwrap();
    let mut e = AgentEvidenceV1::new("t", kind, 1_700_000_000);
    e.evidence_id = "fixo".into();
    e.trace_id = Some("trace".into());
    e.span_id = Some("span".into());
    e.subject.tool_name = tool;
    e.content.fields = fields;
    e.dedupe_key = "k".into();
    e
}

/// Chaves e valores com as formas que partem codecs ingénuos.
fn texto() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("a".to_string()),
        Just("ab".to_string()),
        Just("a.b".to_string()),
        Just("ação".to_string()),
        Just("\u{0}".to_string()),
        "[a-z_.]{0,24}",
        "[\\PC]{0,24}",
    ]
}

fn mapa() -> impl Strategy<Value = BTreeMap<String, String>> {
    proptest::collection::btree_map(texto(), texto(), 0..8)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// A ordem por que os campos foram inseridos não pode mudar o hash.
    #[test]
    fn a_ordem_dos_campos_nao_muda_o_hash(kind in any::<u8>(), m in mapa()) {
        let a = evidencia(kind, m.clone(), Some("t".into()));
        let mut invertido = BTreeMap::new();
        for (k, v) in m.into_iter().rev() {
            invertido.insert(k, v);
        }
        let b = evidencia(kind, invertido, Some("t".into()));
        prop_assert_eq!(canonical_evidence_hash(&a), canonical_evidence_hash(&b));
    }

    /// Dois conteúdos diferentes não podem partilhar o hash. Em particular, o
    /// prefixo de comprimento tem de impedir que `{"ab": "c"}` colida com
    /// `{"a": "bc"}` — a colisão clássica de concatenação sem delimitador.
    #[test]
    fn conteudos_diferentes_dao_hashes_diferentes(
        kind in any::<u8>(),
        a in mapa(),
        b in mapa(),
    ) {
        prop_assume!(a != b);
        let ea = evidencia(kind, a, Some("t".into()));
        let eb = evidencia(kind, b, Some("t".into()));
        prop_assert_ne!(canonical_evidence_hash(&ea), canonical_evidence_hash(&eb));
    }

    /// Mudar um byte dos bytes canónicos muda o hash. Não é uma propriedade do
    /// nosso código (é do BLAKE3), mas prova que o hash é mesmo sobre ESTES
    /// bytes e não sobre uma projecção deles.
    #[test]
    fn mudar_um_byte_muda_o_hash(kind in any::<u8>(), m in mapa(), indice in any::<usize>()) {
        let e = evidencia(kind, m, Some("t".into()));
        let bytes = canonical_evidence_bytes(&e);
        prop_assume!(!bytes.is_empty());
        let i = indice % bytes.len();
        let mut alterado = bytes.clone();
        alterado[i] = alterado[i].wrapping_add(1);
        prop_assert_ne!(
            heraclitus_agent::canonical::domain_hash(
                heraclitus_agent::canonical::DOMAIN_EVIDENCE, &bytes),
            heraclitus_agent::canonical::domain_hash(
                heraclitus_agent::canonical::DOMAIN_EVIDENCE, &alterado)
        );
    }

    /// Uma extensão desconhecida muda o hash da evidência (é conteúdo), mas não
    /// altera nenhum campo tipado já existente.
    #[test]
    fn extensoes_desconhecidas_nao_mexem_nos_campos_tipados(
        kind in any::<u8>(),
        m in mapa(),
        chave in "[a-z.]{1,16}",
        valor in texto(),
    ) {
        let a = evidencia(kind, m.clone(), Some("send_payment".into()));
        let mut b = evidencia(kind, m, Some("send_payment".into()));
        b.content.extensions.insert(chave, valor);
        prop_assert_eq!(&a.subject.tool_name, &b.subject.tool_name);
        prop_assert_eq!(&a.content.fields, &b.content.fields);
        prop_assert_eq!(&a.agent.agent_id, &b.agent.agent_id);
        prop_assert_ne!(canonical_evidence_hash(&a), canonical_evidence_hash(&b));
    }

    /// Retransmitir a mesma evidência é sempre duplicação silenciosa, nunca
    /// conflito — para qualquer conteúdo.
    #[test]
    fn retransmitir_e_sempre_duplicado(kind in any::<u8>(), m in mapa()) {
        let mut e = evidencia(kind, m, Some("t".into()));
        e.dedupe_key = dedupe_key(&e);
        let mut idx = DedupeIndex::new(64);
        prop_assert_eq!(idx.admit(&e), DedupeVerdict::Novel);
        prop_assert_eq!(idx.admit(&e), DedupeVerdict::Duplicate);
        prop_assert_eq!(idx.admit(&e.clone()), DedupeVerdict::Duplicate);
    }

    /// A chave de deduplicação não depende do relógio nem do id: é isso que faz
    /// a retransmissão de um exporter OTel ser silenciosa.
    #[test]
    fn a_chave_ignora_relogio_e_id(kind in any::<u8>(), m in mapa(), t in any::<u64>()) {
        let a = evidencia(kind, m.clone(), Some("t".into()));
        let mut b = evidencia(kind, m, Some("t".into()));
        b.observed_at_unix_nanos = t;
        b.evidence_id = "outro".into();
        prop_assert_eq!(dedupe_key(&a), dedupe_key(&b));
    }

    /// Evidências com `span_id` diferente nunca partilham chave: caso contrário
    /// duas acções distintas do mesmo run seriam tratadas como uma só.
    #[test]
    fn spans_diferentes_nunca_colidem(kind in any::<u8>(), s1 in texto(), s2 in texto()) {
        prop_assume!(s1 != s2);
        let mut a = evidencia(kind, BTreeMap::new(), None);
        let mut b = a.clone();
        a.span_id = Some(s1);
        b.span_id = Some(s2);
        prop_assert_ne!(dedupe_key(&a), dedupe_key(&b));
    }
}
