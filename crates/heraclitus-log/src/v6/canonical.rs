//! SPEC-0050 §8–§15 — `CanonicalRecordV1` e `CanonicalRecordCodecV1`.
//!
//! # A razão de existir deste ficheiro
//!
//! A identidade lógica de um registo não pode depender de `bincode`, de
//! `serde`, do layout do Rust, de `repr(C)`, do discriminante incidental de um
//! `enum`, de padding ou da arquitectura da CPU (SPEC-0050 §9). Se dependesse,
//! recompilar o binário com outra versão do `serde` mudaria a raiz de Merkle de
//! histórico já selado — e uma prova pericial emitida ontem deixaria de fechar
//! hoje.
//!
//! Daí um codec **manual**, com ordem de campos fixa, endianness declarada e
//! uma única representação válida por valor.
//!
//! # A regra do sink único (SPEC-0050 §27)
//!
//! > É proibido manter duas implementações independentes da serialização
//! > lógica.
//!
//! O codec escreve para um [`CanonicalSink`]. `Vec<u8>` é um sink (produz os
//! bytes canónicos, para golden vectors e para prova) e [`CanonicalHashSink`] é
//! outro (alimenta o BLAKE3 incrementalmente, sem materializar o buffer). O
//! *mesmo* `encode_canonical_record` serve os dois: não há como um divergir do
//! outro sem o compilador ir junto.
//!
//! # Layout `CanonicalRecordCodecV1`
//!
//! ```text
//! lsn                u64  LE
//! record_hlc         u64  LE
//! opaque_meta        16   bytes crus
//! episode.id         16   bytes crus (ULID, big-endian — a ordem do próprio ULID)
//! episode.ts_hlc     u64  LE
//! agent_id           varint len + UTF-8
//! session_id         varint len + UTF-8
//! kind               u8 tag [+ varint len + UTF-8 se Custom]
//! content            varint len + bytes
//! embedding          u8 presença (0/1)
//!                    [+ varint hyp_count + f32 LE*  (bits canónicos)
//!                     + varint sph_count + f32 LE*
//!                     + varint euc_count + f32 LE*]
//! attrs              varint count + (varint len+UTF-8 chave, varint len+UTF-8 valor)*
//!                    por ordem lexicográfica da chave
//! parents            varint count + 16 bytes crus cada, pela ordem persistida
//! valid_from         u8 presença [+ u64 LE]
//! valid_to           u8 presença [+ u64 LE]
//! ```

use heraclitus_core::{Episode, EventId, EventKind, Lsn, ProductPoint};

use super::varint::varint_len;

/// Versão do codec canónico. Entra no `FileHeaderV6` e no
/// [`super::receipts::AttestationEnvelopeV1`]: um leitor que não conheça o
/// número recusa-se a afirmar identidade lógica em vez de adivinhar.
pub const CANONICAL_CODEC_V1: u8 = 1;

/// Separação de domínio da folha lógica (SPEC-0050 §15). O prefixo impede que o
/// mesmo hash seja reaproveitado noutro domínio (folha de Merkle, envelope de
/// atestação, digest físico) por acidente.
pub const DOMAIN_CANONICAL_RECORD: &[u8] = b"HRKL6:CANONICAL_RECORD:V1";

// ---------------------------------------------------------------------------
// Tags de EventKind (SPEC-0050 §11)
// ---------------------------------------------------------------------------

/// Tags **permanentes** para `EventKind`.
///
/// A identidade lógica não pode depender do discriminante posicional que o
/// Serde atribui: inserir uma variante a meio do `enum` deslocaria todas as
/// seguintes e mudaria a raiz de segmentos já selados. Estes números são
/// atribuídos à mão e um tag publicado **nunca** muda de significado; kinds
/// novos recebem valores novos.
pub mod kind_tag {
    pub const OBSERVATION: u8 = 0x01;
    pub const ACTION: u8 = 0x02;
    pub const MESSAGE: u8 = 0x03;
    pub const RETRIEVAL_FEEDBACK: u8 = 0x04;
    pub const FACT_DERIVED: u8 = 0x05;
    pub const DEMOTION_RECEIPT: u8 = 0x06;
    pub const CUSTOM: u8 = 0x07;
    pub const SYSTEM_METRIC: u8 = 0x08;
}

#[inline]
fn tag_of(kind: &EventKind) -> u8 {
    match kind {
        EventKind::Observation => kind_tag::OBSERVATION,
        EventKind::Action => kind_tag::ACTION,
        EventKind::Message => kind_tag::MESSAGE,
        EventKind::RetrievalFeedback => kind_tag::RETRIEVAL_FEEDBACK,
        EventKind::FactDerived => kind_tag::FACT_DERIVED,
        EventKind::DemotionReceipt => kind_tag::DEMOTION_RECEIPT,
        EventKind::Custom(_) => kind_tag::CUSTOM,
        EventKind::SystemMetric => kind_tag::SYSTEM_METRIC,
    }
}

// ---------------------------------------------------------------------------
// O sink
// ---------------------------------------------------------------------------

/// Destino de bytes canónicos.
///
/// Só `put_bytes` é abstracto; tudo o resto são métodos com corpo, para que a
/// gramática (varint, string, f32, presença) exista **uma vez** e não possa
/// divergir entre o codificador de buffer e o hasher incremental.
pub trait CanonicalSink {
    fn put_bytes(&mut self, bytes: &[u8]);

    #[inline]
    fn put_u8(&mut self, v: u8) {
        self.put_bytes(&[v]);
    }
    #[inline]
    fn put_u64_le(&mut self, v: u64) {
        self.put_bytes(&v.to_le_bytes());
    }
    #[inline]
    fn put_u32_le(&mut self, v: u32) {
        self.put_bytes(&v.to_le_bytes());
    }
    #[inline]
    fn put_varint(&mut self, v: u64) {
        let mut buf = [0u8; super::varint::MAX_VARINT_LEN];
        let n = super::varint::encode_varint_into(&mut buf, v);
        self.put_bytes(&buf[..n]);
    }
    /// `varint(len) || bytes` — a forma de qualquer sequência de comprimento
    /// variável no codec.
    #[inline]
    fn put_lp(&mut self, bytes: &[u8]) {
        self.put_varint(bytes.len() as u64);
        self.put_bytes(bytes);
    }
    #[inline]
    fn put_str(&mut self, s: &str) {
        self.put_lp(s.as_bytes());
    }
    /// `f32` em bits IEEE-754 **canonicalizados** (SPEC-0050 §14).
    #[inline]
    fn put_f32(&mut self, v: f32) {
        self.put_u32_le(canonical_f32_bits(v));
    }
    /// `Option<u64>` como byte de presença seguido do valor.
    #[inline]
    fn put_opt_u64(&mut self, v: Option<u64>) {
        match v {
            Some(x) => {
                self.put_u8(1);
                self.put_u64_le(x);
            }
            None => self.put_u8(0),
        }
    }
}

impl CanonicalSink for Vec<u8> {
    #[inline]
    fn put_bytes(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// Sink que alimenta um BLAKE3 incremental — o caminho que o `append()` usa,
/// sem alocar o buffer canónico completo (SPEC-0050 §27).
pub struct CanonicalHashSink {
    hasher: blake3::Hasher,
}

impl Default for CanonicalHashSink {
    fn default() -> Self {
        Self::new()
    }
}

impl CanonicalHashSink {
    pub fn new() -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_CANONICAL_RECORD);
        Self { hasher }
    }

    pub fn finalize(self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}

impl CanonicalSink for CanonicalHashSink {
    #[inline]
    fn put_bytes(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }
}

/// `-0.0 -> +0.0`, qualquer NaN -> quiet NaN canónico, resto -> bits originais
/// (SPEC-0050 §14).
///
/// Sem isto, dois embeddings numericamente iguais mas com sinais de zero
/// diferentes — ou com payloads de NaN diferentes, que a FPU produz sem
/// garantias — dariam registos com identidades lógicas distintas.
#[inline]
pub fn canonical_f32_bits(v: f32) -> u32 {
    if v.is_nan() {
        0x7fc0_0000
    } else if v == 0.0 {
        0
    } else {
        v.to_bits()
    }
}

// ---------------------------------------------------------------------------
// O registo canónico
// ---------------------------------------------------------------------------

/// A verdade lógica de um registo do log (SPEC-0050 §8).
///
/// `opaque_meta` **faz parte** da identidade: afecta recuperação e indexação, e
/// um rascunho anterior que o omitia permitiria alterar 16 bytes com efeito
/// operacional sem mover a raiz de Merkle.
#[derive(Debug, Clone)]
pub struct CanonicalRecordV1<'a> {
    pub lsn: Lsn,
    pub record_hlc: u64,
    pub opaque_meta: [u8; 16],
    pub episode: &'a Episode,
}

/// Escreve `record` no `sink` sob `CanonicalRecordCodecV1`.
///
/// Esta função é o contrato. Alterá-la é alterar a identidade de todos os
/// registos futuros — e por isso obriga a uma versão nova de codec, nunca a uma
/// edição no sítio.
pub fn encode_canonical_record<S: CanonicalSink + ?Sized>(
    record: &CanonicalRecordV1<'_>,
    sink: &mut S,
) {
    let ep = record.episode;

    sink.put_u64_le(record.lsn);
    sink.put_u64_le(record.record_hlc);
    sink.put_bytes(&record.opaque_meta);

    sink.put_bytes(&event_id_bytes(&ep.id));
    sink.put_u64_le(ep.ts_hlc);

    sink.put_str(&ep.agent_id);
    sink.put_str(&ep.session_id);

    sink.put_u8(tag_of(&ep.kind));
    if let EventKind::Custom(name) = &ep.kind {
        sink.put_str(name);
    }

    sink.put_lp(&ep.content);

    match &ep.embedding {
        Some(p) => {
            sink.put_u8(1);
            put_product_point(sink, p);
        }
        None => sink.put_u8(0),
    }

    // `attrs` é um `BTreeMap`, logo já itera por ordem lexicográfica — mas a
    // ordem é aqui uma exigência do formato, não um acidente do tipo (§12).
    sink.put_varint(ep.attrs.len() as u64);
    for (k, v) in ep.attrs.iter() {
        sink.put_str(k);
        sink.put_str(v);
    }

    // `parents` guarda a ordem persistida; o v1 nunca reordena (§13).
    sink.put_varint(ep.parents.len() as u64);
    for p in &ep.parents {
        sink.put_bytes(&event_id_bytes(p));
    }

    sink.put_opt_u64(ep.valid_from);
    sink.put_opt_u64(ep.valid_to);
}

#[inline]
fn put_product_point<S: CanonicalSink + ?Sized>(sink: &mut S, p: &ProductPoint) {
    // As três dimensões são explícitas — nenhuma estrutura Rust é despejada
    // directamente em disco (§14).
    sink.put_varint(p.hyp.len() as u64);
    for v in &p.hyp {
        sink.put_f32(*v);
    }
    sink.put_varint(p.sph.len() as u64);
    for v in &p.sph {
        sink.put_f32(*v);
    }
    sink.put_varint(p.euc.len() as u64);
    for v in &p.euc {
        sink.put_f32(*v);
    }
}

/// Os 16 bytes do ULID, na ordem big-endian do próprio ULID (time-ordered).
#[inline]
pub fn event_id_bytes(id: &EventId) -> [u8; 16] {
    id.0.to_bytes()
}

/// Bytes canónicos completos — para golden vectors, provas periciais e debug.
/// O caminho quente usa [`canonical_record_hash`], que não aloca.
pub fn canonical_record_bytes(record: &CanonicalRecordV1<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(estimate_canonical_len(record));
    encode_canonical_record(record, &mut out);
    out
}

/// `BLAKE3("HRKL6:CANONICAL_RECORD:V1" || CanonicalRecordCodecV1(record))`
/// (SPEC-0050 §15), calculado em streaming.
pub fn canonical_record_hash(record: &CanonicalRecordV1<'_>) -> [u8; 32] {
    let mut sink = CanonicalHashSink::new();
    encode_canonical_record(record, &mut sink);
    sink.finalize()
}

/// Estimativa superior barata do tamanho canónico, para dimensionar o `Vec` de
/// uma vez só.
fn estimate_canonical_len(record: &CanonicalRecordV1<'_>) -> usize {
    let ep = record.episode;
    let emb = ep
        .embedding
        .as_ref()
        .map(|p| 3 * super::varint::MAX_VARINT_LEN + 4 * (p.hyp.len() + p.sph.len() + p.euc.len()))
        .unwrap_or(0);
    let attrs: usize = ep
        .attrs
        .iter()
        .map(|(k, v)| k.len() + v.len() + 2 * super::varint::MAX_VARINT_LEN)
        .sum();
    8 + 8
        + 16
        + 16
        + 8
        + ep.agent_id.len()
        + ep.session_id.len()
        + 32
        + varint_len(ep.content.len() as u64)
        + ep.content.len()
        + 1
        + emb
        + super::varint::MAX_VARINT_LEN
        + attrs
        + super::varint::MAX_VARINT_LEN
        + 16 * ep.parents.len()
        + 18
}

/// Hasher incremental exposto para quem constrói o registo por partes.
///
/// Partilha as primitivas do codec por construção: é o mesmo
/// [`CanonicalSink`], só com outro destino.
pub struct CanonicalRecordHasherV1 {
    sink: CanonicalHashSink,
}

impl Default for CanonicalRecordHasherV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl CanonicalRecordHasherV1 {
    pub fn new() -> Self {
        Self {
            sink: CanonicalHashSink::new(),
        }
    }
    /// Absorve um registo inteiro. Equivalente a [`canonical_record_hash`]
    /// quando usado isoladamente.
    pub fn absorb(&mut self, record: &CanonicalRecordV1<'_>) {
        encode_canonical_record(record, &mut self.sink);
    }
    pub fn write_u64(&mut self, v: u64) {
        self.sink.put_u64_le(v);
    }
    pub fn write_string(&mut self, s: &str) {
        self.sink.put_str(s);
    }
    pub fn write_bytes(&mut self, b: &[u8]) {
        self.sink.put_lp(b);
    }
    pub fn finalize(self) -> [u8; 32] {
        self.sink.finalize()
    }
}

/// Contador de bytes: um sink que não guarda nada, só mede. Serve os testes de
/// orçamento e o `inspect` (quantos bytes lógicos tem este segmento).
#[derive(Default)]
pub struct CountingSink(pub usize);

impl CanonicalSink for CountingSink {
    #[inline]
    fn put_bytes(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ep_base() -> Episode {
        Episode {
            id: EventId(Default::default()),
            ts_hlc: 0,
            agent_id: String::new(),
            session_id: String::new(),
            kind: EventKind::Observation,
            content: Vec::new(),
            embedding: None,
            attrs: BTreeMap::new(),
            parents: Vec::new(),
            valid_from: None,
            valid_to: None,
        }
    }

    fn rec<'a>(ep: &'a Episode) -> CanonicalRecordV1<'a> {
        CanonicalRecordV1 {
            lsn: 1,
            record_hlc: 2,
            opaque_meta: [0u8; 16],
            episode: ep,
        }
    }

    #[test]
    fn sink_de_buffer_e_sink_de_hash_veem_os_mesmos_bytes() {
        let mut ep = ep_base();
        ep.agent_id = "agente".into();
        ep.content = vec![1, 2, 3];
        ep.attrs.insert("b".into(), "2".into());
        ep.attrs.insert("a".into(), "1".into());
        let r = rec(&ep);

        let bytes = canonical_record_bytes(&r);
        let direto = canonical_record_hash(&r);

        let mut sink = CanonicalHashSink::new();
        sink.put_bytes(&bytes);
        assert_eq!(
            direto,
            sink.finalize(),
            "hash incremental != hash do buffer"
        );
    }

    #[test]
    fn opaque_meta_entra_na_identidade() {
        let ep = ep_base();
        let a = canonical_record_hash(&rec(&ep));
        let b = canonical_record_hash(&CanonicalRecordV1 {
            lsn: 1,
            record_hlc: 2,
            opaque_meta: [7u8; 16],
            episode: &ep,
        });
        assert_ne!(a, b, "mudar opaque_meta tem de mover a identidade lógica");
    }

    #[test]
    fn attrs_saem_por_ordem_lexicografica() {
        let mut a = ep_base();
        a.attrs.insert("zzz".into(), "1".into());
        a.attrs.insert("aaa".into(), "2".into());
        let bytes = canonical_record_bytes(&rec(&a));
        let pos_a = bytes.windows(3).position(|w| w == b"aaa").unwrap();
        let pos_z = bytes.windows(3).position(|w| w == b"zzz").unwrap();
        assert!(pos_a < pos_z);
    }

    #[test]
    fn custom_kind_nao_colide_com_kind_nomeado() {
        let mut a = ep_base();
        a.kind = EventKind::Custom("Action".into());
        let mut b = ep_base();
        b.kind = EventKind::Action;
        assert_ne!(
            canonical_record_hash(&rec(&a)),
            canonical_record_hash(&rec(&b))
        );
    }

    #[test]
    fn zero_negativo_e_nan_sao_canonicalizados() {
        assert_eq!(canonical_f32_bits(-0.0), canonical_f32_bits(0.0));
        assert_eq!(canonical_f32_bits(f32::NAN), 0x7fc0_0000);
        assert_eq!(canonical_f32_bits(f32::from_bits(0x7fff_ffff)), 0x7fc0_0000);
        assert_eq!(canonical_f32_bits(1.5), 1.5f32.to_bits());

        let mut a = ep_base();
        a.embedding = Some(ProductPoint {
            hyp: vec![-0.0],
            sph: vec![],
            euc: vec![],
        });
        let mut b = ep_base();
        b.embedding = Some(ProductPoint {
            hyp: vec![0.0],
            sph: vec![],
            euc: vec![],
        });
        assert_eq!(
            canonical_record_hash(&rec(&a)),
            canonical_record_hash(&rec(&b))
        );
    }

    #[test]
    fn dimensoes_do_embedding_sao_explicitas() {
        // (hyp=[1.0], sph=[]) e (hyp=[], sph=[1.0]) não podem colidir.
        let mut a = ep_base();
        a.embedding = Some(ProductPoint {
            hyp: vec![1.0],
            sph: vec![],
            euc: vec![],
        });
        let mut b = ep_base();
        b.embedding = Some(ProductPoint {
            hyp: vec![],
            sph: vec![1.0],
            euc: vec![],
        });
        assert_ne!(
            canonical_record_hash(&rec(&a)),
            canonical_record_hash(&rec(&b))
        );
    }

    #[test]
    fn campos_com_prefixo_nao_colidem() {
        // agent="ab", session="" vs agent="a", session="b": o length prefix é
        // que separa. Sem ele, os dois dariam o mesmo stream.
        let mut a = ep_base();
        a.agent_id = "ab".into();
        let mut b = ep_base();
        b.agent_id = "a".into();
        b.session_id = "b".into();
        assert_ne!(
            canonical_record_hash(&rec(&a)),
            canonical_record_hash(&rec(&b))
        );
    }

    #[test]
    fn estimativa_cobre_o_tamanho_real() {
        let mut ep = ep_base();
        ep.agent_id = "a".repeat(40);
        ep.content = vec![9u8; 5000];
        ep.embedding = Some(ProductPoint {
            hyp: vec![0.5; 8],
            sph: vec![0.25; 4],
            euc: vec![1.0; 16],
        });
        ep.attrs.insert("k".into(), "v".repeat(100));
        ep.parents = vec![EventId(Default::default()); 3];
        let r = rec(&ep);
        let mut c = CountingSink::default();
        encode_canonical_record(&r, &mut c);
        assert!(
            c.0 <= estimate_canonical_len(&r),
            "estimativa {} < real {}",
            estimate_canonical_len(&r),
            c.0
        );
        assert_eq!(c.0, canonical_record_bytes(&r).len());
    }
}
