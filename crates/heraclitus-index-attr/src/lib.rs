//! heraclitus-index-attr — o índice secundário AUTOMÁTICO.
//!
//! Um banco sem índices não é um banco. Esta view indexa **todos os atributos**
//! de cada evento — `(campo, valor) -> [LSN]` — para que uma consulta por CPF,
//! CNPJ, nome ou qualquer outro campo seja O(postings), não um scan do log.
//!
//! - **Automático/inteligente:** indexa qualquer campo presente nos `attrs`; não
//!   é preciso declarar índices.
//! - **View materializada:** `apply(lsn, event)` no append (read-your-own-writes)
//!   e reconstruível por replay determinístico a partir do LSN 0.
//! - **Persistido:** `checkpoint`/`open` (bincode) — num log de milhões de nós o
//!   arranque carrega o índice e só replaya a cauda, em vez de reconstruir tudo.
//!
//! O planeador de queries usa `lookup` para resolver `WHERE n.<campo> = "v"` sem
//! varrer a janela (ver heraclitus-query::plan).

use heraclitus_core::{CanonicalKeyCodec, Episode, HeraclitusError, Lsn};
use heraclitus_views::View;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::RandomState, BTreeMap, HashMap};
use std::hash::BuildHasher;
use std::num::NonZeroU32;
use std::ops::Bound;
use std::path::Path;

/// Uma linha do diff, ao nivel do CAMPO. Ver [`AttrIndex::diff`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffCampo {
    pub campo: String,
    /// Postings deste campo dentro de `[de, ate)`.
    pub eventos: usize,
    /// Postings na janela ANTERIOR de igual duracao — o termo de comparacao.
    pub eventos_anterior: usize,
    /// Valores cujo PRIMEIRO posting cai na janela — nunca antes vistos.
    pub valores_novos: usize,
    /// Valores com pelo menos um posting na janela.
    pub valores_ativos: usize,
    /// Valores que produziram eventos na janela anterior e ZERO nesta.
    pub valores_silenciosos: usize,
    /// Valores distintos indexados sob este campo, sem limite temporal.
    pub valores_total: usize,
    /// Postings totais do campo em todo o log — junto com `valores_total` diz
    /// se o campo e QUASE-UNICO (um valor distinto por evento, como um
    /// timestamp ou um uuid). Num campo desses "valor novo" nao e sinal
    /// nenhum: todos os valores sao novos por construcao. Quem apresenta
    /// precisa de saber isto para nao somar ruido a uma manchete.
    pub postings_total: usize,
    pub topo: Vec<DiffValor>,
}

/// Um valor concreto dentro de um [`DiffCampo`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffValor {
    pub valor: String,
    /// Postings dentro da janela.
    pub eventos: usize,
    /// Postings na janela anterior de igual duracao — o termo de comparacao
    /// que torna "calou-se" e "disparou" afirmacoes com significado.
    pub anterior: usize,
    /// Postings em TODO o passado antes de `de` — distingue "novo" de "ja ca
    /// estava" mesmo quando a janela anterior esta vazia.
    pub antes: usize,
    pub novo: bool,
    /// Estava ativo na janela anterior e emudeceu nesta.
    pub silencioso: bool,
}

const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();
const SNAPSHOT_FILE: &str = "attr_index.bin";
/// Separador entre campo e valor na chave do índice (US, nunca aparece em dados).
const SEP: char = '\u{1f}';
/// Valores quase-ubíquos sem poder discriminante são ignorados (evita postings
/// gigantes que não ajudam a localizar nada).
const SKIP_VALUES: &[&str] = &["", "0", "-1", "nao", "sim", "true", "false", "null", "none"];
/// Valores maiores que isto são texto livre (descrições) — inúteis para busca
/// exata e fariam o índice explodir em RAM/disco. Identificadores e nomes
/// (CPF/CNPJ/códigos/razão social) ficam muito abaixo.
const MAX_VALUE_LEN: usize = 80;

/// Magic do checkpoint comprimido. Um ficheiro v1 (bincode cru) nunca começa
/// por estes bytes, por isso a presença dele distingue os formatos sem ambiguidade.
const MAGIC_V2: &[u8; 4] = b"HATR";
/// **v3**: o `agent_id` passou a ser indexado sob `_agent`.
///
/// A subida de versao NAO e cosmetica — e o mecanismo de correcao. Um
/// checkpoint v2 foi escrito sem `_agent`; ao carrega-lo, o indice ficava a
/// conhecer o campo apenas para os eventos que chegassem DEPOIS, e a pegada de
/// um titular respondia "1 evento" sobre um log com 200. Dizer isso a um
/// titular de dados e uma declaracao falsa, e a guarda `indexado` nao a
/// apanhava: o campo existia, so estava incompleto.
///
/// Com a versao a subir, o `open` rejeita o checkpoint antigo e reconstroi por
/// replay a partir do LSN 0 — backfill completo, sem ninguem ter de se lembrar
/// de correr nada. Custa um replay no primeiro arranque apos a atualizacao.
/// **v4**: o `kind` passou a ser indexado sob `_kind`.
///
/// Mesma mecânica da v3, e pela mesma razão: um checkpoint v3 foi escrito sem
/// `_kind`. Carregá-lo deixava o índice a conhecer o campo só para os eventos
/// que chegassem DEPOIS — e uma query `MATCH (n:Contrato)` devolveria os
/// contratos novos e escondia os antigos, em silêncio, com ar de resposta
/// completa. Num banco de auditoria, uma resposta incompleta sem aviso é pior
/// que um erro.
///
/// Subir a versão faz o `open` recusar o checkpoint antigo e reconstruir por
/// replay desde o LSN 0. Custa um replay no primeiro arranque; num log de 10M
/// isso são minutos, uma vez.
const FORMAT_LEGACY_COMPRESSED: u16 = 4;
/// v5 troca apenas o checkpoint DERIVADO para IDs densos. O log canónico não
/// muda; checkpoints v4 e v1 continuam legíveis e são internados ao abrir.
const FORMAT_CURRENT: u16 = 5;

/// Espelho do [`ResidentSnapshot`] com os postings **comprimidos**.
///
/// A estrutura (chaves, mapas) continua a ir em bincode — é texto e metadados,
/// onde os codecs de inteiros não ajudam. O que muda são as colunas de `Lsn`:
/// postings de um índice invertido são LSNs em ordem crescente estrita, o caso
/// exato em que delta+bitpack ganha muito. Com 4 KB por posting a 8 bytes cada,
/// passar para ~1 bit por LSN não é um ganho marginal.
/// Abaixo disto o cabecalho do codec nunca compensa; nem vale a pena medir.
const MIN_PARA_MEDIR: usize = 8;

/// Escolhe a forma mais curta para uma coluna de postings.
///
/// Devolve `Some(blob)` se o codec ganhar, `None` se o bincode cru for melhor.
/// A escolha e MEDIDA, nao presumida: o bincode ja codifica inteiros em varint,
/// por isso uma lista de um LSN pequeno custa-lhe 1-2 bytes, enquanto o
/// cabecalho autodescritivo do codec custa 9 antes de qualquer dado.
fn escolher_forma(v: &[Lsn]) -> Option<Vec<u8>> {
    if v.len() < MIN_PARA_MEDIR {
        return None;
    }
    let packed = hume_kernel::compression::column::encode(v);
    let plain = bincode::serde::encode_to_vec(v, BINCODE_CFG)
        .map(|b| b.len())
        .unwrap_or(usize::MAX);
    (packed.len() < plain).then_some(packed)
}

#[inline]
fn postings_estritamente_crescentes(postings: &[Lsn]) -> bool {
    postings.windows(2).all(|pair| pair[0] < pair[1])
}

/// ID reversível de `(field, value)`. O par ocupa 8 bytes em vez de uma
/// `String` de 24 bytes + alocação + os bytes repetidos do nome do campo.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct AttrKey {
    field: u32,
    value: u32,
}

/// Dicionário reversível que guarda os bytes de cada string exatamente uma vez.
///
/// `HashMap<String, id> + Vec<String>` duplicaria todos os bytes para oferecer
/// lookup e materialização. Aqui o mapa aponta para uma cadeia de IDs por hash;
/// a comparação final com o `Box<str>` torna colisões totalmente corretas.
/// `RandomState` mantém resistência a entradas adversariais.
struct StringDictionary {
    strings: Vec<Box<str>>,
    heads: HashMap<u64, NonZeroU32>,
    next_collision: Vec<Option<NonZeroU32>>,
    hash_builder: RandomState,
}

impl Default for StringDictionary {
    fn default() -> Self {
        Self {
            strings: Vec::new(),
            heads: HashMap::new(),
            next_collision: Vec::new(),
            hash_builder: RandomState::new(),
        }
    }
}

impl StringDictionary {
    #[inline]
    fn link(id: u32) -> NonZeroU32 {
        // `intern` never permits id == u32::MAX.
        NonZeroU32::new(id + 1).expect("dictionary id + 1 is non-zero")
    }

    #[inline]
    fn id_from_link(link: NonZeroU32) -> u32 {
        link.get() - 1
    }

    #[inline]
    fn hash(&self, text: &str) -> u64 {
        self.hash_builder.hash_one(text)
    }

    fn id(&self, text: &str) -> Option<u32> {
        let mut current = self.heads.get(&self.hash(text)).copied();
        while let Some(link) = current {
            let id = Self::id_from_link(link);
            if self.strings[id as usize].as_ref() == text {
                return Some(id);
            }
            current = self.next_collision[id as usize];
        }
        None
    }

    fn intern(&mut self, text: &str) -> u32 {
        if let Some(id) = self.id(text) {
            return id;
        }
        assert!(
            self.strings.len() < u32::MAX as usize,
            "attribute dictionary exhausted u32 IDs"
        );
        let id = self.strings.len() as u32;
        let hash = self.hash(text);
        let previous_head = self.heads.insert(hash, Self::link(id));
        self.strings.push(text.into());
        self.next_collision.push(previous_head);
        id
    }

    fn get(&self, id: u32) -> Option<&str> {
        self.strings.get(id as usize).map(AsRef::as_ref)
    }

    fn materialize(&self) -> Vec<String> {
        self.strings.iter().map(|s| s.to_string()).collect()
    }

    fn from_materialized(strings: Vec<String>) -> Option<Self> {
        let mut dictionary = Self::default();
        for (expected, text) in strings.into_iter().enumerate() {
            if dictionary.intern(&text) as usize != expected {
                return None; // string duplicada ou IDs não canónicos
            }
        }
        Some(dictionary)
    }
}

#[derive(Default)]
struct AttrDictionary {
    fields: StringDictionary,
    values: StringDictionary,
}

impl AttrDictionary {
    fn intern(&mut self, field: &str, value: &str) -> AttrKey {
        AttrKey {
            field: self.fields.intern(field),
            value: self.values.intern(value),
        }
    }

    fn key(&self, field: &str, value: &str) -> Option<AttrKey> {
        Some(AttrKey {
            field: self.fields.id(field)?,
            value: self.values.id(value)?,
        })
    }

    fn decode(&self, key: AttrKey) -> Option<(&str, &str)> {
        Some((self.fields.get(key.field)?, self.values.get(key.value)?))
    }
}

#[derive(Default)]
struct ResidentSnapshot {
    watermark: Lsn,
    applied: bool,
    dictionary: AttrDictionary,
    exact: HashMap<AttrKey, Vec<Lsn>>,
    numeric: HashMap<u32, BTreeMap<u64, Vec<Lsn>>>,
}

/// Checkpoint v5: dicionários reversíveis + chaves densas, com postings ainda
/// escolhidos por tamanho entre bincode e o codec de colunas do HUME.
#[derive(Serialize, Deserialize)]
struct CompressedSnapshot {
    watermark: Lsn,
    applied: bool,
    fields: Vec<String>,
    values: Vec<String>,
    /// Colunas onde o bincode varint ja e melhor -- a maioria, num indice com
    /// muitos valores quase unicos.
    exact_plain: HashMap<AttrKey, Vec<Lsn>>,
    /// Colunas onde o codec ganha. Uma chave vive num mapa OU no outro.
    ///
    /// Sao dois mapas e nao um enum por coluna porque o discriminante custa um
    /// byte POR COLUNA: com 50.000 colunas minusculas isso sozinho fazia o
    /// ficheiro crescer 5,6%. Num ficheiro dominado por metadados, a
    /// autodescricao paga-se em bytes.
    exact_packed: HashMap<AttrKey, Vec<u8>>,
    numeric_plain: HashMap<u32, BTreeMap<u64, Vec<Lsn>>>,
    numeric_packed: HashMap<u32, BTreeMap<u64, Vec<u8>>>,
}

impl From<&ResidentSnapshot> for CompressedSnapshot {
    fn from(s: &ResidentSnapshot) -> Self {
        let mut exact_plain = HashMap::new();
        let mut exact_packed = HashMap::new();
        for (k, v) in &s.exact {
            match escolher_forma(v) {
                Some(blob) => {
                    exact_packed.insert(*k, blob);
                }
                None => {
                    exact_plain.insert(*k, v.clone());
                }
            }
        }
        let mut numeric_plain: HashMap<u32, BTreeMap<u64, Vec<Lsn>>> = HashMap::new();
        let mut numeric_packed: HashMap<u32, BTreeMap<u64, Vec<u8>>> = HashMap::new();
        for (campo, por_valor) in &s.numeric {
            for (chave, v) in por_valor {
                match escolher_forma(v) {
                    Some(blob) => {
                        numeric_packed
                            .entry(*campo)
                            .or_default()
                            .insert(*chave, blob);
                    }
                    None => {
                        numeric_plain
                            .entry(*campo)
                            .or_default()
                            .insert(*chave, v.clone());
                    }
                }
            }
        }
        Self {
            watermark: s.watermark,
            applied: s.applied,
            fields: s.dictionary.fields.materialize(),
            values: s.dictionary.values.materialize(),
            exact_plain,
            exact_packed,
            numeric_plain,
            numeric_packed,
        }
    }
}

impl CompressedSnapshot {
    /// `None` se alguma coluna não descodificar — o chamador degrada para
    /// rebuild por replay, que é sempre correto por construção.
    fn expand(self) -> Option<ResidentSnapshot> {
        use hume_kernel::compression::column;
        let mut exact = self.exact_plain;
        for (k, blob) in self.exact_packed {
            exact.insert(k, column::decode(&blob)?);
        }
        let mut numeric = self.numeric_plain;
        for (campo, por_valor) in self.numeric_packed {
            let m = numeric.entry(campo).or_default();
            for (chave, blob) in por_valor {
                m.insert(chave, column::decode(&blob)?);
            }
        }
        let dictionary = AttrDictionary {
            fields: StringDictionary::from_materialized(self.fields)?,
            values: StringDictionary::from_materialized(self.values)?,
        };
        if exact.keys().any(|key| dictionary.decode(*key).is_none())
            || numeric
                .keys()
                .any(|field| dictionary.fields.get(*field).is_none())
            || exact
                .values()
                .any(|postings| !postings_estritamente_crescentes(postings))
            || numeric.values().any(|by_value| {
                by_value
                    .values()
                    .any(|postings| !postings_estritamente_crescentes(postings))
            })
        {
            return None;
        }
        Some(ResidentSnapshot {
            watermark: self.watermark,
            applied: self.applied,
            dictionary,
            exact,
            numeric,
        })
    }
}

/// Layout v4/v1 antigo, mantido exclusivamente para restore e para medir o
/// baseline. O estado residente nunca usa estas Strings compostas.
#[derive(Default, Serialize, Deserialize)]
struct LegacySnapshot {
    watermark: Lsn,
    applied: bool,
    /// `"campo\u{1f}valor" -> [LSN]` (postings em ordem crescente de LSN).
    exact: HashMap<String, Vec<Lsn>>,
    /// Índice ORDENADO por valor numérico: `campo -> valor(f64 ordenável) ->
    /// [LSN]` (padrão Qdrant de range filtering). A chave é o f64 mapeado num
    /// u64 que preserva a ordem total, para o BTreeMap poder fazer `range()`.
    /// Formato de checkpoint incompatível com o anterior: `open` degrada para
    /// rebuild por replay (correto por construção).
    numeric: HashMap<String, BTreeMap<u64, Vec<Lsn>>>,
}

#[derive(Serialize, Deserialize)]
struct LegacyCompressedSnapshot {
    watermark: Lsn,
    applied: bool,
    exact_plain: HashMap<String, Vec<Lsn>>,
    exact_packed: HashMap<String, Vec<u8>>,
    numeric_plain: HashMap<String, BTreeMap<u64, Vec<Lsn>>>,
    numeric_packed: HashMap<String, BTreeMap<u64, Vec<u8>>>,
}

impl From<&LegacySnapshot> for LegacyCompressedSnapshot {
    fn from(s: &LegacySnapshot) -> Self {
        let mut exact_plain = HashMap::new();
        let mut exact_packed = HashMap::new();
        for (key, postings) in &s.exact {
            match escolher_forma(postings) {
                Some(blob) => {
                    exact_packed.insert(key.clone(), blob);
                }
                None => {
                    exact_plain.insert(key.clone(), postings.clone());
                }
            }
        }
        let mut numeric_plain: HashMap<String, BTreeMap<u64, Vec<Lsn>>> = HashMap::new();
        let mut numeric_packed: HashMap<String, BTreeMap<u64, Vec<u8>>> = HashMap::new();
        for (field, by_value) in &s.numeric {
            for (value, postings) in by_value {
                match escolher_forma(postings) {
                    Some(blob) => {
                        numeric_packed
                            .entry(field.clone())
                            .or_default()
                            .insert(*value, blob);
                    }
                    None => {
                        numeric_plain
                            .entry(field.clone())
                            .or_default()
                            .insert(*value, postings.clone());
                    }
                }
            }
        }
        Self {
            watermark: s.watermark,
            applied: s.applied,
            exact_plain,
            exact_packed,
            numeric_plain,
            numeric_packed,
        }
    }
}

impl LegacyCompressedSnapshot {
    fn expand(self) -> Option<LegacySnapshot> {
        use hume_kernel::compression::column;
        let mut exact = self.exact_plain;
        for (key, blob) in self.exact_packed {
            exact.insert(key, column::decode(&blob)?);
        }
        let mut numeric = self.numeric_plain;
        for (field, by_value) in self.numeric_packed {
            let target = numeric.entry(field).or_default();
            for (value, blob) in by_value {
                target.insert(value, column::decode(&blob)?);
            }
        }
        if exact
            .values()
            .any(|postings| !postings_estritamente_crescentes(postings))
            || numeric.values().any(|by_value| {
                by_value
                    .values()
                    .any(|postings| !postings_estritamente_crescentes(postings))
            })
        {
            return None;
        }
        Some(LegacySnapshot {
            watermark: self.watermark,
            applied: self.applied,
            exact,
            numeric,
        })
    }
}

fn legacy_key(field: &str, value: &str) -> String {
    let mut key = String::with_capacity(field.len() + value.len() + 1);
    key.push_str(field);
    key.push(SEP);
    key.push_str(value);
    key
}

impl ResidentSnapshot {
    fn from_legacy(snapshot: LegacySnapshot) -> Option<Self> {
        let mut resident = Self {
            watermark: snapshot.watermark,
            applied: snapshot.applied,
            ..Self::default()
        };
        // HashMap iteration is randomized. Sorting gives stable IDs after every
        // restore, which keeps EXPLAIN/checkpoint materialization deterministic.
        let mut exact: Vec<_> = snapshot.exact.into_iter().collect();
        exact.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for (composite, postings) in exact {
            if !postings_estritamente_crescentes(&postings) {
                return None;
            }
            let (field, value) = composite.split_once(SEP)?;
            let key = resident.dictionary.intern(field, value);
            if resident.exact.insert(key, postings).is_some() {
                return None;
            }
        }
        let mut numeric: Vec<_> = snapshot.numeric.into_iter().collect();
        numeric.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for (field, postings) in numeric {
            if postings
                .values()
                .any(|values| !postings_estritamente_crescentes(values))
            {
                return None;
            }
            let field_id = resident.dictionary.fields.intern(&field);
            if resident.numeric.insert(field_id, postings).is_some() {
                return None;
            }
        }
        Some(resident)
    }

    fn to_legacy(&self) -> LegacySnapshot {
        let exact = self
            .exact
            .iter()
            .filter_map(|(key, postings)| {
                let (field, value) = self.dictionary.decode(*key)?;
                Some((legacy_key(field, value), postings.clone()))
            })
            .collect();
        let numeric = self
            .numeric
            .iter()
            .filter_map(|(field, postings)| {
                Some((
                    self.dictionary.fields.get(*field)?.to_owned(),
                    postings.clone(),
                ))
            })
            .collect();
        LegacySnapshot {
            watermark: self.watermark,
            applied: self.applied,
            exact,
            numeric,
        }
    }

    fn upsert_exact(&mut self, field: &str, value: &str, lsn: Lsn) -> AttrKey {
        let key = self.dictionary.intern(field, value);
        insert_sorted(self.exact.entry(key).or_default(), lsn);
        key
    }
}

// SPEC-009: a chave numérica ordenável é o `CanonicalKeyCodec::encode_f64` do
// core — ordem total correta, com colapso de NaN e normalização de -0.0→+0.0
// (o `f64_ordered` ad-hoc anterior não tratava esses casos). Para todo valor
// finito ≠ -0.0 a codificação é bit-idêntica à anterior, logo os checkpoints
// existentes permanecem legíveis.

/// Índice invertido de atributos. Persistido e reconstruível por replay.
#[derive(Default)]
pub struct AttrIndex {
    inner: ResidentSnapshot,
}

impl AttrIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Abre o índice carregando o checkpoint de `dir` (vazio se não existir).
    pub fn open(dir: impl AsRef<Path>) -> Self {
        let path = dir.as_ref().join(SNAPSHOT_FILE);
        match std::fs::read(&path) {
            Ok(bytes) => {
                // v2 (comprimido) traz magic; v1 (bincode cru) não. Ler os dois
                // não é cortesia: sem isto, o primeiro arranque depois desta
                // mudança deitava fora um checkpoint válido e reconstruía o
                // índice inteiro por replay — correto, mas caro e silencioso.
                let snap = if bytes.starts_with(MAGIC_V2) {
                    match bytes.get(4..6).map(|v| u16::from_le_bytes([v[0], v[1]])) {
                        Some(FORMAT_CURRENT) => bincode::serde::decode_from_slice::<
                            CompressedSnapshot,
                            _,
                        >(&bytes[6..], BINCODE_CFG)
                        .ok()
                        .and_then(|(snapshot, _)| snapshot.expand()),
                        Some(FORMAT_LEGACY_COMPRESSED) => {
                            bincode::serde::decode_from_slice::<LegacyCompressedSnapshot, _>(
                                &bytes[6..],
                                BINCODE_CFG,
                            )
                            .ok()
                            .and_then(|(snapshot, _)| snapshot.expand())
                            .and_then(ResidentSnapshot::from_legacy)
                        }
                        _ => None,
                    }
                } else {
                    bincode::serde::decode_from_slice::<LegacySnapshot, _>(&bytes, BINCODE_CFG)
                        .ok()
                        .and_then(|(snapshot, _)| ResidentSnapshot::from_legacy(snapshot))
                };
                match snap {
                    Some(inner) => AttrIndex { inner },
                    None => AttrIndex::new(), // corrompido -> rebuild por replay
                }
            }
            Err(_) => AttrIndex::new(),
        }
    }

    /// LSNs (ordenados) dos eventos cujo `field == value`. Vazio se nada bate.
    pub fn lookup(&self, field: &str, value: &str) -> &[Lsn] {
        self.inner
            .dictionary
            .key(field, value)
            .and_then(|key| self.inner.exact.get(&key))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// LSNs (ordenados, sem duplicados) dos eventos cujo valor NUMÉRICO de
    /// `field` cai no intervalo `[min, max]` (bounds à la `BTreeMap::range`).
    /// Vazio se o campo não tem valores numéricos indexados.
    pub fn lookup_range(&self, field: &str, min: Bound<f64>, max: Bound<f64>) -> Vec<Lsn> {
        let Some(field_id) = self.inner.dictionary.fields.id(field) else {
            return Vec::new();
        };
        let Some(by_value) = self.inner.numeric.get(&field_id) else {
            return Vec::new();
        };
        let enc = |b: Bound<f64>| match b {
            Bound::Included(v) => Bound::Included(CanonicalKeyCodec::encode_f64(v)),
            Bound::Excluded(v) => Bound::Excluded(CanonicalKeyCodec::encode_f64(v)),
            Bound::Unbounded => Bound::Unbounded,
        };
        let (lo, hi) = (enc(min), enc(max));
        // `BTreeMap::range` PANICA se o início for maior que o fim (ou se ambos
        // forem Excluded e iguais). Uma query GQL de sintaxe VÁLIDA chega aqui
        // com um intervalo vazio — p.ex. `WHERE n.v > 100 AND n.v < 10`. Como
        // este código corre com o Mutex do índice de atributos BLOQUEADO, o
        // panic ENVENENAVA-O: a partir daí todo `index_applied` falhava e o nó
        // deixava de aceitar escritas até reiniciar. Intervalo vazio ⇒ zero
        // resultados, que é a resposta correta.
        let vazio = match (&lo, &hi) {
            (Bound::Included(a), Bound::Included(b)) => a > b,
            (Bound::Included(a), Bound::Excluded(b))
            | (Bound::Excluded(a), Bound::Included(b))
            | (Bound::Excluded(a), Bound::Excluded(b)) => a >= b,
            _ => false,
        };
        if vazio {
            return Vec::new();
        }
        let mut out: Vec<Lsn> = by_value
            .range((lo, hi))
            .flat_map(|(_, postings)| postings.iter().copied())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Nº de pares (campo,valor) distintos indexados.
    pub fn keys(&self) -> usize {
        self.inner.exact.len()
    }

    /// Valores distintos indexados sob `field`, com quantos LSNs cada um.
    ///
    /// Com `field = "_agent"` responde "que fontes escrevem neste log, e
    /// quanto" — sem varrer o log, so lendo o indice.
    pub fn field_values(&self, field: &str) -> Vec<(String, usize)> {
        let Some(field_id) = self.inner.dictionary.fields.id(field) else {
            return Vec::new();
        };
        let mut v: Vec<(String, usize)> = self
            .inner
            .exact
            .iter()
            .filter(|(key, _)| key.field == field_id)
            .map(|(key, lsns)| {
                (
                    self.inner
                        .dictionary
                        .values
                        .get(key.value)
                        .expect("resident AttrKey validated")
                        .to_owned(),
                    lsns.len(),
                )
            })
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// Primeiro e ultimo LSN indexados para `(field, value)`.
    ///
    /// Os postings estao em ordem crescente por invariante do `apply`, logo sao
    /// as pontas — sem percorrer nada.
    pub fn field_span(&self, field: &str, value: &str) -> Option<(Lsn, Lsn)> {
        let l = self.lookup(field, value);
        match (l.first(), l.last()) {
            (Some(a), Some(b)) => Some((*a, *b)),
            _ => None,
        }
    }

    /// Campos indexados -> quantos valores distintos cada um tem.
    ///
    /// E o "que dados guardamos?" ao nivel do ESQUEMA, derivado do que esta
    /// mesmo no log em vez de uma folha de calculo mantida a mao — a
    /// materia-prima do registo de operacoes de tratamento (LGPD art. 37).
    pub fn fields(&self) -> BTreeMap<String, usize> {
        let mut m: BTreeMap<String, usize> = BTreeMap::new();
        for key in self.inner.exact.keys() {
            let field = self
                .inner
                .dictionary
                .fields
                .get(key.field)
                .expect("resident AttrKey validated");
            *m.entry(field.to_owned()).or_insert(0) += 1;
        }
        m
    }

    /// Quantos valores distintos existem indexados sob `field`.
    ///
    /// Serve para distinguir "nao ha dados" de "este indice nao conhece este
    /// campo" — que e a diferenca entre responder a um titular "nao temos nada
    /// sobre si" e "o nosso indice e anterior a esta funcionalidade". A
    /// primeira resposta, dada por engano, e uma declaracao falsa a um titular
    /// de dados.
    pub fn field_entries(&self, field: &str) -> usize {
        let Some(field_id) = self.inner.dictionary.fields.id(field) else {
            return 0;
        };
        self.inner
            .exact
            .keys()
            .filter(|key| key.field == field_id)
            .count()
    }

    /// Diff entre dois instantes do log: `[de, ate)`.
    ///
    /// Num log append-only nada desaparece — por isso um diff aqui NAO e "o que
    /// foi apagado". E outra coisa, e mais util a quem investiga: **o que
    /// apareceu que nunca antes existira**, e **o que existia e calou-se**.
    ///
    /// - `novo` — o primeiro posting deste valor cai dentro da janela. Um IP,
    ///   um utilizador ou um comando que o sistema nunca tinha visto.
    /// - `silencioso` — tinha postings ANTES de `de` e nenhum na janela. Numa
    ///   plataforma forense isto pesa tanto como o resto: uma fonte que se cala
    ///   pode ser o atacante a desligar o registo.
    ///
    /// Custo: uma passagem pelas chaves do indice e duas buscas binarias por
    /// chave (os postings estao ordenados por invariante do `apply`). Nao le o
    /// log — trabalha so sobre o indice.
    pub fn diff(&self, de: Lsn, ate: Lsn, topo: usize) -> Vec<DiffCampo> {
        // A janela ANTERIOR e o termo de comparacao. Sem ela, "calou-se" seria
        // "nao apareceu nesta janela", que num log com historia e verdade sobre
        // quase tudo — um numero grande, alarmante e sem informacao nenhuma.
        // Medido: numa janela de 24 h sobre este log, 527 dos 561 valores
        // "calaram-se" por essa definicao. Comparando com a janela anterior de
        // igual duracao, os que de facto pararam sao os que interessam.
        let largura = ate.saturating_sub(de);
        let ant = de.saturating_sub(largura);
        let mut por_campo: BTreeMap<String, DiffCampo> = BTreeMap::new();

        for (key, lsns) in &self.inner.exact {
            let (campo, valor) = self
                .inner
                .dictionary
                .decode(*key)
                .expect("resident AttrKey validated");
            // `partition_point` num vetor ordenado: quantos LSN sao < bound.
            let ate_i = lsns.partition_point(|l| *l < ate);
            let de_i = lsns.partition_point(|l| *l < de);
            let ant_i = lsns.partition_point(|l| *l < ant);
            let na_janela = ate_i.saturating_sub(de_i);
            let na_anterior = de_i.saturating_sub(ant_i);

            let e = por_campo
                .entry(campo.to_string())
                .or_insert_with(|| DiffCampo {
                    campo: campo.to_string(),
                    eventos: 0,
                    eventos_anterior: 0,
                    valores_novos: 0,
                    valores_ativos: 0,
                    valores_silenciosos: 0,
                    valores_total: 0,
                    postings_total: 0,
                    topo: Vec::new(),
                });
            e.valores_total += 1;
            e.postings_total += lsns.len();

            // Um valor cujo primeiro posting so aparece DEPOIS da janela ainda
            // nao existia no instante `ate` — nao pertence a este diff.
            if lsns.first().is_none_or(|f| *f >= ate) {
                continue;
            }

            let novo = de_i == 0 && na_janela > 0;
            let silencioso = na_janela == 0 && na_anterior > 0;
            e.eventos += na_janela;
            e.eventos_anterior += na_anterior;
            if na_janela > 0 {
                e.valores_ativos += 1;
                if novo {
                    e.valores_novos += 1;
                }
            }
            if silencioso {
                e.valores_silenciosos += 1;
            }

            // Um valor sem atividade nem numa janela nem na outra nao tem nada
            // a dizer sobre este intervalo — nao entra no topo.
            if na_janela > 0 || na_anterior > 0 {
                e.topo.push(DiffValor {
                    valor: valor.to_string(),
                    eventos: na_janela,
                    anterior: na_anterior,
                    antes: de_i,
                    novo,
                    silencioso,
                });
            }
        }

        let mut out: Vec<DiffCampo> = por_campo.into_values().collect();
        for c in out.iter_mut() {
            // Ordem por relevancia forense: primeiro o que nunca existiu, depois
            // o que emudeceu, e so entao o volume. Alfabetico como desempate
            // para o resultado ser estavel entre chamadas.
            c.topo.sort_by(|a, b| {
                b.novo
                    .cmp(&a.novo)
                    .then_with(|| b.silencioso.cmp(&a.silencioso))
                    .then_with(|| b.eventos.max(b.anterior).cmp(&a.eventos.max(a.anterior)))
                    .then_with(|| a.valor.cmp(&b.valor))
            });
            c.topo.truncate(topo);
        }
        out.sort_by(|a, b| {
            b.eventos
                .max(b.eventos_anterior)
                .cmp(&a.eventos.max(a.eventos_anterior))
                .then_with(|| a.campo.cmp(&b.campo))
        });
        out
    }

    pub fn is_empty(&self) -> bool {
        self.inner.exact.is_empty()
    }

    /// Tamanho que o checkpoint teria **sem** compressão de postings — o
    /// baseline v1 (bincode cru do snapshot).
    ///
    /// Existe para o `benches/compression_gain.rs` poder comparar contra a
    /// alternativa real em vez de contra um número citado de memória. O ganho
    /// da compressão varia entre −83% e zero consoante o perfil do índice;
    /// um valor fixo em documentação seria verdade num caso e mentira noutro.
    pub fn snapshot_bincode_len(&self) -> usize {
        bincode::serde::encode_to_vec(self.inner.to_legacy(), BINCODE_CFG)
            .map(|b| b.len())
            .unwrap_or(0)
    }

    /// Grava o checkpoint em `dir` (escrita atómica tmp+rename).
    pub fn save(&self, dir: impl AsRef<Path>) -> Result<(), HeraclitusError> {
        std::fs::create_dir_all(dir.as_ref())?;
        // v2: magic + versão + bincode do snapshot com as colunas comprimidas.
        let comprimido = CompressedSnapshot::from(&self.inner);
        let corpo = bincode::serde::encode_to_vec(&comprimido, BINCODE_CFG)
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        let mut bytes = Vec::with_capacity(corpo.len() + 6);
        bytes.extend_from_slice(MAGIC_V2);
        bytes.extend_from_slice(&FORMAT_CURRENT.to_le_bytes());
        bytes.extend_from_slice(&corpo);
        let dst = dir.as_ref().join(SNAPSHOT_FILE);
        let tmp = dir.as_ref().join(format!("{SNAPSHOT_FILE}.tmp"));
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &dst)?;
        Ok(())
    }
}

impl View for AttrIndex {
    fn name(&self) -> &str {
        "attr"
    }

    fn apply(&mut self, lsn: Lsn, event: &Episode) {
        // Inserção ORDENADA com dedup por LSN (binary_search): torna o apply
        // idempotente (replay que sobrepõe o watermark re-entrega LSNs já
        // aplicados → skip) E tolerante a entregas fora de ordem (dois appends
        // concorrentes podem indexar 6 antes de 5 — o guard antigo
        // `lsn <= watermark → return` DESCARTAVA o 5 para sempre, um buraco
        // silencioso na view). Mantém o invariante "postings em ordem crescente".
        // `agent_id` entra como pseudo-atributo, sob a chave reservada
        // `_agent`.
        //
        // Porquê: o `agent_id` é a chave por que a cifra em repouso deriva as
        // chaves e por que o crypto-shred apaga — no modelo do Forge é o
        // **titular** dos dados. Sem estar indexado, responder "que dados têm
        // sobre mim?" (LGPD art. 18, I e II) obrigava a varrer o log inteiro:
        // 51 segundos a 10 milhões de registos, medido. Um banco que assenta a
        // conformidade neste campo tem de conseguir procurá-lo.
        //
        // O prefixo `_` evita colisão com um atributo de utilizador chamado
        // "agent": as chaves de utilizador vêm de `event.attrs`, que nunca
        // produz `_agent`.
        {
            let a = event.agent_id.trim();
            if !a.is_empty() && a.len() <= MAX_VALUE_LEN {
                self.inner.upsert_exact("_agent", a, lsn);
            }
        }

        // O `kind` entra como pseudo-atributo sob a chave reservada `_kind`,
        // pela MESMA razão que o `_agent` — e com consequências maiores.
        //
        // `n.tipo` / `n.kind` é o predicado mais usado de toda a camada de
        // grafo: cada `MATCH (n:Contrato)` é isso. E era exatamente o campo
        // que o planner classificava como "builtin", logo **incapaz de usar
        // índice** — resolvia-se sempre por varrimento do log com pós-filtro.
        //
        // Medido a 2026-08-19 sobre o log real de 10 093 244 eventos: coletar
        // os 13 891 nós de kind `Contrato` levou **7m27s** (128 queries de
        // janela de 100k LSN), e o kind seguinte expirou. Com 21 kinds nas
        // regras de aresta, o edge-builder re-varria o log inteiro 21 vezes —
        // e nunca terminava. A construção do grafo, que é o diferencial do
        // produto, parava na prática nos ~250 mil eventos.
        //
        // O rótulo vem de `EventKind::label()` (heraclitus-core), a definição
        // única partilhada com o planner: se as duas divergissem, a procura
        // devolvia zero linhas sobre dados existentes.
        {
            let k = event.kind.label();
            let k = k.trim();
            if !k.is_empty() && k.len() <= MAX_VALUE_LEN {
                self.inner.upsert_exact("_kind", k, lsn);
            }
        }

        for (field, value) in &event.attrs {
            let v = value.trim();
            // `to_ascii_lowercase()` alocava uma `String` por atributo de cada
            // evento, so para a deitar fora a seguir. `eq_ignore_ascii_case`
            // compara sem alocar e da a mesma resposta.
            if v.len() > MAX_VALUE_LEN || SKIP_VALUES.iter().any(|s| s.eq_ignore_ascii_case(v)) {
                continue;
            }
            let key = self.inner.upsert_exact(field, v, lsn);
            // Valor numérico entra também no índice ordenado (range filtering).
            // Os SKIP_VALUES continuam de fora — "0"/"-1" ubíquos gerariam
            // postings gigantes sem poder discriminante.
            if let Ok(n) = v.parse::<f64>() {
                if n.is_finite() {
                    insert_sorted(
                        self.inner
                            .numeric
                            .entry(key.field)
                            .or_default()
                            .entry(CanonicalKeyCodec::encode_f64(n))
                            .or_default(),
                        lsn,
                    );
                }
            }
        }
        // Watermark só avança (max): regressão persistida causaria re-replay —
        // agora inócuo (idempotente), mas o avanço-só mantém a semântica exata.
        self.inner.watermark = self.inner.watermark.max(lsn);
        self.inner.applied = true;
    }

    fn watermark(&self) -> Lsn {
        self.inner.watermark
    }

    fn checkpoint(&self, dir: &Path) -> Result<(), HeraclitusError> {
        self.save(dir)
    }

    fn reset(&mut self) {
        self.inner = ResidentSnapshot::default();
    }
}

/// Insere `lsn` mantendo a posting ordenada, sem duplicar.
fn insert_sorted(v: &mut Vec<Lsn>, lsn: Lsn) {
    match v.last().copied() {
        None => v.push(lsn),
        Some(last) if last < lsn => v.push(lsn),
        Some(last) if last == lsn => {}
        Some(_) => {
            if let Err(i) = v.binary_search(&lsn) {
                v.insert(i, lsn);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind};

    fn ep(cnpj: &str, nome: &str) -> Episode {
        let mut e = Episode::new("etl", EventKind::Observation, nome.as_bytes().to_vec());
        e.attrs.insert("cnpj".into(), cnpj.into());
        e.attrs.insert("nome".into(), nome.into());
        e
    }

    /// Um evento de UMA fonte, para as janelas do `diff` terem valores
    /// distinguiveis sem depender do `ep()` acima (que fixa cnpj/nome).
    fn ev(fonte: &str) -> Episode {
        let mut e = Episode::new("etl", EventKind::Observation, b"x".to_vec());
        e.attrs.insert("fonte".into(), fonte.into());
        e
    }

    /// O que um diff num log append-only pode e nao pode afirmar.
    ///
    /// Este e o teste que impede a regressao que ja aconteceu uma vez: com
    /// "calou-se" definido como "nao apareceu nesta janela", 527 dos 561
    /// valores deste log apareciam como calados — um numero alarmante e sem
    /// informacao. O criterio tem de ser contra a JANELA ANTERIOR.
    #[test]
    fn diff_compara_com_a_janela_anterior_nao_com_todo_o_passado() {
        let mut idx = AttrIndex::new();
        // Janela anterior [0,4): A tres vezes, B uma vez.
        idx.apply(0, &ev("A"));
        idx.apply(1, &ev("A"));
        idx.apply(2, &ev("A"));
        idx.apply(3, &ev("B"));
        // Janela [4,8): A continua (mais devagar), B cala-se, C nasce.
        idx.apply(4, &ev("A"));
        idx.apply(5, &ev("C"));
        idx.apply(6, &ev("C"));
        idx.apply(7, &ev("C"));

        let d = idx.diff(4, 8, 10);
        let f = d.iter().find(|c| c.campo == "fonte").expect("campo fonte");

        assert_eq!(f.eventos, 4, "quatro eventos na janela");
        assert_eq!(f.eventos_anterior, 4, "quatro na janela anterior");
        assert_eq!(f.valores_total, 3, "A, B, C");
        assert_eq!(f.postings_total, 8);

        let v = |n: &str| f.topo.iter().find(|x| x.valor == n).unwrap();

        // C nunca existira antes: e a unica coisa NOVA.
        assert!(v("C").novo, "C aparece pela primeira vez na janela");
        assert_eq!(f.valores_novos, 1);
        assert!(!v("A").novo, "A ja ca estava");

        // B estava ativo e parou. A NAO parou — abrandou.
        assert!(v("B").silencioso, "B estava ativo antes e emudeceu");
        assert!(!v("A").silencioso, "A abrandou, nao parou");
        assert_eq!(f.valores_silenciosos, 1);

        // O termo de comparacao por valor e a janela anterior, nao o passado
        // todo — e o que permite dizer "-67%" em vez de "existiu".
        assert_eq!(v("A").eventos, 1);
        assert_eq!(v("A").anterior, 3);
    }

    /// Sem janela anterior (de = 0) nada se pode ter calado: nao havia periodo
    /// antes onde algo pudesse estar a falar. O contrario — marcar tudo o que
    /// so aparece mais tarde como "silencioso" — seria uma afirmacao inventada.
    #[test]
    fn diff_desde_o_inicio_nao_inventa_silencio() {
        let mut idx = AttrIndex::new();
        idx.apply(0, &ev("A"));
        idx.apply(1, &ev("B"));

        let d = idx.diff(0, 2, 10);
        let f = d.iter().find(|c| c.campo == "fonte").unwrap();
        assert_eq!(f.eventos_anterior, 0);
        assert_eq!(
            f.valores_silenciosos, 0,
            "sem janela anterior nao ha silencio"
        );
        assert_eq!(f.valores_novos, 2, "tudo e novo quando se comeca do zero");
    }

    /// Um valor que so nasce DEPOIS do fim da janela nao pertence ao diff — no
    /// instante `ate` ele ainda nao existia. Confundir isto faria o painel
    /// mostrar o futuro dentro de uma consulta ao passado, que e exatamente o
    /// que um AS OF tem de impedir.
    #[test]
    fn diff_ignora_o_que_so_nasce_depois_da_janela() {
        let mut idx = AttrIndex::new();
        idx.apply(0, &ev("A"));
        idx.apply(1, &ev("A"));
        idx.apply(2, &ev("FUTURO"));

        let d = idx.diff(0, 2, 10);
        let f = d.iter().find(|c| c.campo == "fonte").unwrap();
        assert!(
            !f.topo.iter().any(|v| v.valor == "FUTURO"),
            "um valor posterior a `ate` nao pode aparecer num AS OF anterior"
        );
        assert_eq!(f.valores_novos, 1, "so A");
        // `valores_total` e deliberadamente SEM limite temporal (cardinalidade
        // do campo hoje), por isso conta os dois — e a unica grandeza aqui que
        // olha para alem de `ate`.
        assert_eq!(f.valores_total, 2);
    }

    #[test]
    fn indexes_any_field_and_looks_up_fast() {
        let mut idx = AttrIndex::new();
        idx.apply(0, &ep("11222333000144", "OMEGA LTDA"));
        idx.apply(1, &ep("99888777000100", "ALFA SA"));
        idx.apply(2, &ep("11222333000144", "OMEGA LTDA")); // mesma empresa, outro evento

        assert_eq!(idx.lookup("cnpj", "11222333000144"), &[0, 2]);
        assert_eq!(idx.lookup("cnpj", "99888777000100"), &[1]);
        assert_eq!(idx.lookup("nome", "ALFA SA"), &[1]);
        assert!(idx.lookup("cnpj", "inexistente").is_empty());
        assert_eq!(idx.watermark(), 2);
    }

    #[test]
    fn replay_idempotent_no_duplicate_postings() {
        let mut idx = AttrIndex::new();
        let e = ep("11222333000144", "OMEGA LTDA");
        idx.apply(0, &e);
        idx.apply(0, &e); // replay sobreposto do MESMO lsn -> ignorado
        assert_eq!(idx.lookup("cnpj", "11222333000144"), &[0]);
    }

    #[test]
    fn out_of_order_apply_indexes_both_events() {
        // Appends concorrentes podem entregar 6 antes de 5 (o log atribui o LSN,
        // mas o index_applied corre fora de qualquer guarda de ordem). O guard
        // antigo `lsn <= watermark → return` DESCARTAVA o 5 para sempre — um
        // buraco silencioso na view que nem o replay pós-restart cobria (o
        // watermark persistido dizia 6). Ambos têm de ficar indexados, ordenados.
        let mut idx = AttrIndex::new();
        idx.apply(6, &ep("11222333000144", "OMEGA LTDA"));
        idx.apply(5, &ep("11222333000144", "OMEGA LTDA")); // atrasado, fora de ordem
        assert_eq!(idx.lookup("cnpj", "11222333000144"), &[5, 6]);
        // E o watermark não regrediu.
        assert_eq!(idx.watermark(), 6);
    }

    #[test]
    fn skips_ubiquitous_placeholder_values() {
        let mut idx = AttrIndex::new();
        let mut e = Episode::new("etl", EventKind::Observation, vec![]);
        e.attrs.insert("vencedor_flag".into(), "0".into());
        e.attrs.insert("cnpj".into(), "".into());
        idx.apply(0, &e);
        assert!(idx.lookup("vencedor_flag", "0").is_empty());
        assert!(idx.lookup("cnpj", "").is_empty());
    }

    #[test]
    fn skips_long_free_text_values() {
        let mut idx = AttrIndex::new();
        let mut e = Episode::new("etl", EventKind::Observation, vec![]);
        let desc = "objeto: ".to_string() + &"contratacao de servicos diversos ".repeat(5);
        assert!(desc.len() > 80);
        e.attrs.insert("objeto".into(), desc.clone());
        e.attrs.insert("cnpj".into(), "11222333000144".into());
        idx.apply(0, &e);
        assert!(
            idx.lookup("objeto", &desc).is_empty(),
            "texto livre não é indexado"
        );
        assert_eq!(
            idx.lookup("cnpj", "11222333000144"),
            &[0],
            "identificador curto é indexado"
        );
    }

    #[test]
    fn range_lookup_over_numeric_values() {
        // C1.6 (padrão Qdrant): WHERE n.valor > x AND n.valor < y sem scan.
        let mut idx = AttrIndex::new();
        let val = |v: &str| {
            let mut e = Episode::new("etl", EventKind::Observation, vec![]);
            e.attrs.insert("valor".into(), v.into());
            e
        };
        for (lsn, v) in [
            (0, "-50.5"),
            (1, "10"),
            (2, "99.9"),
            (3, "100"),
            (4, "3000"),
            (5, "abc"),
        ] {
            idx.apply(lsn, &val(v));
        }

        use std::ops::Bound::*;
        assert_eq!(
            idx.lookup_range("valor", Included(10.0), Included(100.0)),
            &[1, 2, 3]
        );
        assert_eq!(
            idx.lookup_range("valor", Excluded(10.0), Excluded(100.0)),
            &[2]
        );
        // Negativos ordenam corretamente (f64_ordered preserva a ordem total).
        assert_eq!(idx.lookup_range("valor", Unbounded, Excluded(0.0)), &[0]);
        assert_eq!(
            idx.lookup_range("valor", Included(100.0), Unbounded),
            &[3, 4]
        );
        // Não-numéricos ("abc") ficam fora do índice ordenado; campo inexistente = vazio.
        assert!(idx.lookup_range("outro", Unbounded, Unbounded).is_empty());

        // O checkpoint preserva o índice numérico.
        let dir = tempfile::tempdir().unwrap();
        idx.save(dir.path()).unwrap();
        let re = AttrIndex::open(dir.path());
        assert_eq!(
            re.lookup_range("valor", Included(10.0), Included(100.0)),
            &[1, 2, 3]
        );
    }

    #[test]
    fn negative_zero_unifies_with_positive_zero_in_range() {
        // Regressão do `f64_ordered` ad-hoc: "-0.0" recebia uma chave distinta de
        // "0.0", pelo que um range [0,0] perdia o evento com -0.0. O
        // CanonicalKeyCodec normaliza -0.0→+0.0, corrigindo isto.
        let mut idx = AttrIndex::new();
        let val = |v: &str| {
            let mut e = Episode::new("etl", EventKind::Observation, vec![]);
            e.attrs.insert("saldo".into(), v.into());
            e
        };
        idx.apply(0, &val("0.0"));
        idx.apply(1, &val("-0.0"));

        use std::ops::Bound::*;
        // Um range exatamente em zero deve apanhar AMBOS os eventos.
        assert_eq!(
            idx.lookup_range("saldo", Included(0.0), Included(0.0)),
            &[0, 1],
            "-0.0 e +0.0 são o mesmo número e têm de partilhar a chave"
        );
    }

    #[test]
    fn checkpoint_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut idx = AttrIndex::new();
        idx.apply(0, &ep("11222333000144", "OMEGA LTDA"));
        idx.apply(1, &ep("99888777000100", "ALFA SA"));
        idx.save(dir.path()).unwrap();

        let re = AttrIndex::open(dir.path());
        assert_eq!(re.lookup("cnpj", "11222333000144"), &[0]);
        assert_eq!(re.lookup("nome", "ALFA SA"), &[1]);
        assert_eq!(re.watermark(), 1);
    }

    #[test]
    fn rebuild_by_replay_equals_incremental() {
        // determinismo: indexar 0..N incrementalmente == reconstruir do zero.
        let build = |n: u64| {
            let mut idx = AttrIndex::new();
            for i in 0..n {
                idx.apply(i, &ep(&format!("cnpj{}", i % 3), &format!("nome{i}")));
            }
            idx
        };
        let a = build(30);
        let mut b = AttrIndex::new();
        b.reset();
        for i in 0..30u64 {
            b.apply(i, &ep(&format!("cnpj{}", i % 3), &format!("nome{i}")));
        }
        assert_eq!(a.lookup("cnpj", "cnpj0"), b.lookup("cnpj", "cnpj0"));
        assert_eq!(
            a.lookup("cnpj", "cnpj0"),
            &[0, 3, 6, 9, 12, 15, 18, 21, 24, 27]
        );
    }

    #[test]
    fn dictionary_is_reversible_and_reduces_logical_key_storage() {
        let mut index = AttrIndex::new();
        let mut lsn = 0u64;
        for field in 0..64 {
            for value in 0..128 {
                let mut event = Episode::new("etl", EventKind::Observation, Vec::new());
                event
                    .attrs
                    .insert(format!("field-{field:02}"), format!("value-{value:03}"));
                index.apply(lsn, &event);
                lsn += 1;
            }
        }

        assert_eq!(std::mem::size_of::<AttrKey>(), 8);
        assert_eq!(index.field_entries("field-17"), 128);
        assert_eq!(index.field_values("field-17").len(), 128);
        assert_eq!(index.lookup("field-17", "value-042"), &[17 * 128 + 42]);

        // Compara somente a parte que muda (chaves/dicionários); Vec<Posting>
        // e buckets do HashMap existem nos dois desenhos e cancelam-se.
        let legacy = index.inner.to_legacy();
        let legacy_key_storage: usize = legacy
            .exact
            .keys()
            .map(|key| std::mem::size_of::<String>() + key.capacity())
            .sum();
        let dictionary_string_storage = index
            .inner
            .dictionary
            .fields
            .strings
            .iter()
            .chain(&index.inner.dictionary.values.strings)
            .map(|text| std::mem::size_of::<Box<str>>() + text.len())
            .sum::<usize>();
        let dictionary_entries = index.inner.dictionary.fields.strings.len()
            + index.inner.dictionary.values.strings.len();
        let resident_key_storage = index.inner.exact.len() * std::mem::size_of::<AttrKey>()
            + dictionary_string_storage
            + dictionary_entries
                * (std::mem::size_of::<u64>()
                    + std::mem::size_of::<NonZeroU32>()
                    + std::mem::size_of::<Option<NonZeroU32>>());
        assert!(
            resident_key_storage * 3 < legacy_key_storage,
            "dense={resident_key_storage} legacy={legacy_key_storage}"
        );
    }
}

#[cfg(test)]
mod compressao_tests {
    use super::*;

    fn indice_com(n: u64) -> AttrIndex {
        let mut ix = AttrIndex::new();
        for lsn in 0..n {
            let mut ep = Episode::new(
                "a",
                heraclitus_core::EventKind::Custom("T".into()),
                b"x".to_vec(),
            );
            ep.attrs.insert("campo".into(), "valor".into());
            ep.attrs.insert("seq".into(), lsn.to_string());
            ix.apply(lsn, &ep);
        }
        ix
    }

    #[test]
    fn checkpoint_v2_faz_roundtrip_exato() {
        let dir = tempfile::tempdir().unwrap();
        let antes = indice_com(5_000);
        antes.save(dir.path()).unwrap();
        let depois = AttrIndex::open(dir.path());
        assert_eq!(
            depois.lookup("campo", "valor"),
            antes.lookup("campo", "valor")
        );
        assert_eq!(depois.lookup("campo", "valor").len(), 5_000);
    }

    #[test]
    fn o_ficheiro_gravado_e_v5() {
        let dir = tempfile::tempdir().unwrap();
        indice_com(10).save(dir.path()).unwrap();
        let bytes = std::fs::read(dir.path().join(SNAPSHOT_FILE)).unwrap();
        assert!(
            bytes.starts_with(MAGIC_V2),
            "checkpoint tem de trazer o magic v2"
        );
        assert_eq!(
            u16::from_le_bytes([bytes[4], bytes[5]]),
            FORMAT_CURRENT,
            "checkpoint novo deve usar dictionary IDs"
        );
    }

    /// Sem isto, o primeiro arranque depois desta mudanca deitava fora um
    /// checkpoint valido e reconstruia o indice inteiro por replay -- correto,
    /// mas caro e silencioso.
    #[test]
    fn checkpoint_v1_legado_continua_a_ser_lido() {
        let dir = tempfile::tempdir().unwrap();
        let ix = indice_com(200);
        // Grava no formato ANTIGO: bincode cru, sem magic.
        let cru = bincode::serde::encode_to_vec(ix.inner.to_legacy(), BINCODE_CFG).unwrap();
        std::fs::write(dir.path().join(SNAPSHOT_FILE), &cru).unwrap();

        let lido = AttrIndex::open(dir.path());
        assert_eq!(
            lido.lookup("campo", "valor").len(),
            200,
            "v1 tem de continuar legivel"
        );
    }

    #[test]
    fn checkpoint_v4_comprimido_continua_a_ser_lido() {
        let dir = tempfile::tempdir().unwrap();
        let original = indice_com(5_000);
        let legacy = original.inner.to_legacy();
        let compressed = LegacyCompressedSnapshot::from(&legacy);
        let body = bincode::serde::encode_to_vec(&compressed, BINCODE_CFG).unwrap();
        let mut bytes = Vec::with_capacity(body.len() + 6);
        bytes.extend_from_slice(MAGIC_V2);
        bytes.extend_from_slice(&FORMAT_LEGACY_COMPRESSED.to_le_bytes());
        bytes.extend_from_slice(&body);
        std::fs::write(dir.path().join(SNAPSHOT_FILE), bytes).unwrap();

        let restored = AttrIndex::open(dir.path());
        assert_eq!(restored.watermark(), original.watermark());
        assert_eq!(
            restored.lookup("campo", "valor"),
            original.lookup("campo", "valor")
        );
        assert_eq!(restored.fields(), original.fields());
        assert_eq!(restored.field_values("seq"), original.field_values("seq"));
    }

    #[test]
    fn dictionary_checkpoint_is_smaller_than_v4_for_repeated_fields() {
        let index = indice_com(20_000);
        let legacy = index.inner.to_legacy();
        let legacy_body =
            bincode::serde::encode_to_vec(LegacyCompressedSnapshot::from(&legacy), BINCODE_CFG)
                .unwrap();
        let current_body =
            bincode::serde::encode_to_vec(CompressedSnapshot::from(&index.inner), BINCODE_CFG)
                .unwrap();
        assert!(
            current_body.len() < legacy_body.len(),
            "v5={} v4={} bytes",
            current_body.len(),
            legacy_body.len()
        );
    }

    #[test]
    fn checkpoint_corrompido_degrada_para_rebuild_em_vez_de_panicar() {
        let dir = tempfile::tempdir().unwrap();
        indice_com(100).save(dir.path()).unwrap();
        let p = dir.path().join(SNAPSHOT_FILE);
        let mut bytes = std::fs::read(&p).unwrap();
        // Estraga o meio do corpo comprimido, mantendo o magic.
        let meio = bytes.len() / 2;
        bytes[meio] ^= 0xFF;
        bytes.truncate(bytes.len() - 3);
        std::fs::write(&p, &bytes).unwrap();

        let lido = AttrIndex::open(dir.path()); // nao pode entrar em panico
        assert!(lido.is_empty() || !lido.lookup("campo", "valor").is_empty());
    }

    /// Indice onde os POSTINGS dominam: poucos valores distintos, muitos
    /// eventos cada. E o caso que a compressao existe para atacar -- na pratica
    /// campos como risk_level, action_class, agent_id.
    fn indice_postings_longos(n: u64, valores: u64) -> AttrIndex {
        let mut ix = AttrIndex::new();
        for lsn in 0..n {
            let mut ep = Episode::new(
                "a",
                heraclitus_core::EventKind::Custom("T".into()),
                b"x".to_vec(),
            );
            ep.attrs
                .insert("classe".into(), format!("c{}", lsn % valores));
            ix.apply(lsn, &ep);
        }
        ix
    }

    fn tamanhos(ix: &AttrIndex) -> (u64, u64) {
        let dir = tempfile::tempdir().unwrap();
        ix.save(dir.path()).unwrap();
        let v2 = std::fs::metadata(dir.path().join(SNAPSHOT_FILE))
            .unwrap()
            .len();
        let v1 = bincode::serde::encode_to_vec(ix.inner.to_legacy(), BINCODE_CFG)
            .unwrap()
            .len() as u64;
        (v1, v2)
    }

    /// O ponto de tudo isto. Quando os postings sao longos e ordenados -- o caso
    /// que a compressao ataca -- o ganho tem de ser grande, nao marginal.
    #[test]
    fn postings_longos_encolhem_muito() {
        let (v1, v2) = tamanhos(&indice_postings_longos(50_000, 10));
        assert!(v2 * 5 < v1, "esperado >5x menor; v1={v1} v2={v2}");
    }

    /// E o contrapeso: num indice dominado por valores quase unicos, os postings
    /// sao curtos e o bincode varint ja e bom. Comprimir NAO pode piorar.
    ///
    /// A primeira versao comprimia tudo e este caso CRESCEU de 587 KB para
    /// 1.09 MB -- o cabecalho de 9 bytes por coluna aplicado a 20.000 listas de
    /// um elemento. Foi por isso que a escolha passou a ser medida por coluna.
    #[test]
    fn postings_curtos_nunca_pioram() {
        let (v1, v2) = tamanhos(&indice_com(20_000));
        assert!(v2 <= v1, "regressao: v2={v2} > v1={v1}");
    }
}

#[cfg(test)]
mod medicao_attr {
    use super::*;
    use heraclitus_core::{Episode, EventKind};
    use std::time::Instant;

    fn evento(i: usize) -> Episode {
        let mut e = Episode::new(
            "agente",
            EventKind::Observation,
            format!("evento {i}").into_bytes(),
        );
        // Atributos realistas: alguns campos, muitos valores distintos.
        e.attrs.insert(
            "cpf".into(),
            format!("{:011}", i * 7919 % 100_000_000_000u64 as usize),
        );
        e.attrs.insert(
            "tipo".into(),
            ["contrato", "aditivo", "rescisao"][i % 3].into(),
        );
        e.attrs.insert("orgao".into(), format!("org-{}", i % 50));
        e.attrs.insert("valor".into(), format!("{}", i % 10_000));
        e
    }

    /// `cargo test -p heraclitus-index-attr --lib medicao -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn custo_de_indexar_e_consultar() {
        for n in [20_000usize, 100_000] {
            let mut idx = AttrIndex::new();
            let eventos: Vec<Episode> = (0..n).map(evento).collect();

            let t0 = Instant::now();
            for (i, e) in eventos.iter().enumerate() {
                idx.apply(i as u64, e);
            }
            let indexar = t0.elapsed();

            let t1 = Instant::now();
            let mut total = 0usize;
            for i in 0..20_000 {
                total += idx.lookup("orgao", &format!("org-{}", i % 50)).len();
            }
            let consultar = t1.elapsed();

            println!(
                "n={n:>7}  indexar {:>10.3?} ({:>7.2?}/evento)  ·  20k consultas {:>10.3?} ({:>7.2?}/consulta, {total} hits)",
                indexar,
                indexar / n as u32,
                consultar,
                consultar / 20_000
            );
        }
    }

    /// A/B do desenho anterior (`String "field<SEP>value"`) contra os IDs
    /// densos. Sem limiar temporal para não tornar CI flakey; execute em
    /// release e compare também os bytes lógicos impressos.
    ///
    /// `cargo test -p heraclitus-index-attr --release dictionary_vs_composite_keys_ab -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn dictionary_vs_composite_keys_ab() {
        use std::hint::black_box;

        let pairs: Vec<(String, String, Lsn)> = (0..200_000u64)
            .map(|lsn| {
                (
                    format!("field-{:03}", lsn % 256),
                    format!("value-{lsn:09}"),
                    lsn,
                )
            })
            .collect();

        let mut dense = ResidentSnapshot::default();
        let started = Instant::now();
        for (field, value, lsn) in &pairs {
            dense.upsert_exact(field, value, *lsn);
        }
        let dense_insert = started.elapsed();

        let mut legacy = HashMap::<String, Vec<Lsn>>::new();
        let started = Instant::now();
        for (field, value, lsn) in &pairs {
            insert_sorted(legacy.entry(legacy_key(field, value)).or_default(), *lsn);
        }
        let legacy_insert = started.elapsed();

        let started = Instant::now();
        let mut dense_hits = 0u64;
        for query in 0..1_000_000usize {
            let (field, value, _) = &pairs[(query * 7919) % pairs.len()];
            let key = dense.dictionary.key(black_box(field), black_box(value));
            dense_hits ^= key
                .and_then(|key| dense.exact.get(&key))
                .and_then(|postings| postings.first())
                .copied()
                .unwrap_or_default();
        }
        let dense_lookup = started.elapsed();

        // O código anterior já reutilizava a String temporária em lookup; este
        // buffer reproduz isso para não favorecer artificialmente os IDs.
        let mut buffer = String::new();
        let started = Instant::now();
        let mut legacy_hits = 0u64;
        for query in 0..1_000_000usize {
            let (field, value, _) = &pairs[(query * 7919) % pairs.len()];
            buffer.clear();
            buffer.push_str(black_box(field));
            buffer.push(SEP);
            buffer.push_str(black_box(value));
            legacy_hits ^= legacy
                .get(buffer.as_str())
                .and_then(|postings| postings.first())
                .copied()
                .unwrap_or_default();
        }
        let legacy_lookup = started.elapsed();
        assert_eq!(dense_hits, legacy_hits);

        let dense_text_bytes: usize = dense
            .dictionary
            .fields
            .strings
            .iter()
            .chain(&dense.dictionary.values.strings)
            .map(|text| text.len())
            .sum();
        let legacy_text_bytes: usize = legacy.keys().map(|key| key.len()).sum();
        eprintln!(
            "AttrIndex IDs: insert={dense_insert:?} lookup={dense_lookup:?} utf8={dense_text_bytes}; composite: insert={legacy_insert:?} lookup={legacy_lookup:?} utf8={legacy_text_bytes}"
        );
    }
}
