//! SPEC-0050 §54–§67 — `.hrki`, o sidecar de índice do HRKL v6.
//!
//! # O que é, e sobretudo o que não é
//!
//! O `.hrki` é **derivado**: opcional, reconstruível a partir do `.hrkl`,
//! descartável, versionado, e **vinculado ao `logical_root` do segmento**
//! (§54). Isso não é decoração — é a regra que decide o comportamento em
//! desacordo:
//!
//! > Um `.hrki` cujo `logical_root` não corresponda ao segmento é **ignorado**.
//! > Nunca é tratado como corrupção do `.hrkl`. (§56)
//!
//! Um sidecar desactualizado ou adulterado degrada o desempenho — a query cai
//! no varrimento — e nunca a correção. É por isso que o pruning aqui é
//! **conservador**: pode devolver falsos positivos (blocos que afinal não
//! interessam), nunca falsos negativos.
//!
//! # Porquê existir
//!
//! Medido sobre a base real de 10 093 386 registos (2026-08-19): uma query que
//! caia no varrimento vê os 250 000 eventos mais antigos e trunca em silêncio
//! (`heraclitus-query/src/backend.rs`, `QUERY_SCAN_CAP`). O `.hrki` é o que
//! permite eliminar blocos **antes** do range read, do descomprimir e do
//! descodificar (§59) — e portanto o que torna um segmento de 10 M consultável
//! sem o ler todo.
//!
//! # A regra de privacidade que molda o formato (§64)
//!
//! Sidecars são fonte de fuga. Um zone map de strings expõe IDs, nomes,
//! sessões, tenants. Por isso:
//!
//! > **o HRKI não persiste min/max de strings arbitrárias.**
//!
//! As zone maps baseline são só numéricas — LSN, HLC, valid_from, valid_to
//! (§58). Identificadores entram apenas por filtro de igualdade, e os
//! sensíveis entram **com chave** (`keyed_blake3`, §66), de forma que o
//! sidecar nunca guarda o identificador em claro. E `attrs.*` é
//! `DO_NOT_INDEX` por omissão (§67): só campos declarados ganham estatística
//! persistente.
//!
//! # Layout
//!
//! ```text
//! HrkiHeader          96 B, com CRC próprio
//! SectionDirEntry[]   32 B cada
//! …secções…           cada uma com o seu CRC no directório
//! ```

use std::collections::BTreeSet;
use std::path::Path;

use heraclitus_core::{EventKind, Lsn};

use super::canonical::CANONICAL_CODEC_V1;
use super::error::{checked_len, corrupt, V6Result};

// ---------------------------------------------------------------------------
// Constantes de formato
// ---------------------------------------------------------------------------

pub const HRKI_MAGIC: [u8; 4] = *b"HRKI";
pub const HRKI_VERSION: u16 = 1;
pub const HRKI_HEADER_LEN: usize = 96;
pub const SECTION_ENTRY_LEN: usize = 32;

/// Tecto defensivo para o número de secções e de blocos declarados por um
/// ficheiro que pode ter sido escrito por outra coisa qualquer.
const HARD_MAX_SECTIONS: usize = 64;
const HARD_MAX_ZONES: usize = 1 << 24;
const HARD_MAX_FILTER_BYTES: usize = 64 * 1024 * 1024;

/// Tipos de secção. Os valores são **permanentes**: mudá-los invalida
/// sidecars já escritos. Um leitor que encontre um tipo desconhecido salta-o
/// pelo `length` — é isso que torna o formato extensível sem quebrar versões
/// antigas (§57).
pub mod section_type {
    pub const SEGMENT_STATS: u16 = 1;
    pub const BLOCK_ZONE_MAPS: u16 = 2;
    pub const EQUALITY_FILTERS: u16 = 3;
    pub const EVENT_KIND_BITMAP: u16 = 4;
    pub const ATTRIBUTE_METADATA: u16 = 5;
}

// ---------------------------------------------------------------------------
// Política de indexação (§65)
// ---------------------------------------------------------------------------

/// O que se pode persistir sobre um campo.
///
/// O default de tudo o que não seja declarado é [`DoNotIndex`](Self::DoNotIndex)
/// — §67. Um campo só ganha estatística por decisão explícita.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndexPolicy {
    /// Técnico e não sensível: pode entrar em claro no filtro.
    PublicTechnical,
    /// Sensível: entra como `keyed_blake3(index_key, valor)` (§66). O sidecar
    /// nunca vê o valor original.
    HashedEquality,
    /// Reservado: o sidecar inteiro seria cifrado. Não implementado nesta
    /// fase; declarar isto faz o construtor recusar, em vez de degradar em
    /// silêncio para texto em claro.
    EncryptedSidecar,
    /// Não indexar. O default.
    DoNotIndex,
}

/// A política aplicada a um segmento, e o seu hash — que vai no header para
/// que um leitor saiba que o sidecar foi construído sob outras regras.
#[derive(Debug, Clone, Default)]
pub struct IndexPolicySet {
    campos: Vec<(String, IndexPolicy)>,
}

impl IndexPolicySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn com(mut self, campo: impl Into<String>, politica: IndexPolicy) -> Self {
        self.campos.push((campo.into(), politica));
        self.campos.sort();
        self.campos.dedup_by(|a, b| a.0 == b.0);
        self
    }

    pub fn politica_de(&self, campo: &str) -> IndexPolicy {
        self.campos
            .iter()
            .find(|(c, _)| c == campo)
            .map(|(_, p)| *p)
            .unwrap_or(IndexPolicy::DoNotIndex)
    }

    /// Hash canónico da política, gravado no header. Duas políticas diferentes
    /// produzem sidecars diferentes; um leitor que compare isto sabe se o
    /// sidecar foi construído sob as regras que espera.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"HRKI:INDEX_POLICY:V1");
        for (campo, p) in &self.campos {
            h.update(&(campo.len() as u32).to_le_bytes());
            h.update(campo.as_bytes());
            h.update(&[*p as u8]);
        }
        *h.finalize().as_bytes()
    }
}

// ---------------------------------------------------------------------------
// Bloom filter imutável (§61, §62)
// ---------------------------------------------------------------------------

/// Bloom filter imutável, dimensionado na construção.
///
/// **A ausência de falso negativo é inegociável** (§62). Esta implementação
/// garante-a por construção: `contains` só devolve `false` quando algum dos
/// `k` bits está a zero, o que é impossível para um elemento inserido.
///
/// Falsos positivos são aceitáveis e esperados — custam um bloco lido a mais.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilter {
    bits: Vec<u64>,
    /// Número de funções de hash.
    k: u8,
    /// Número de bits (≤ `bits.len() * 64`).
    m: u64,
}

impl BloomFilter {
    /// Dimensiona para `n` elementos com taxa de falso positivo `fpr`.
    ///
    /// `m = -n·ln(p) / (ln2)²`, `k = (m/n)·ln2` — a parametrização clássica.
    pub fn nova(n: usize, fpr: f64) -> Self {
        let n = n.max(1) as f64;
        let p = fpr.clamp(1e-6, 0.5);
        let ln2 = std::f64::consts::LN_2;
        let m = (-(n * p.ln()) / (ln2 * ln2)).ceil().max(64.0);
        let m = (m as u64).min(HARD_MAX_FILTER_BYTES as u64 * 8);
        let k = (((m as f64) / n) * ln2).round().clamp(1.0, 16.0) as u8;
        Self {
            bits: vec![0u64; m.div_ceil(64) as usize],
            k,
            m,
        }
    }

    /// Duas funções de hash independentes derivadas de um blake3, e as
    /// restantes por double hashing (`h1 + i·h2`) — a técnica de Kirsch–
    /// Mitzenmacher, que preserva a FPR sem calcular `k` hashes.
    fn indices(&self, item: &[u8]) -> impl Iterator<Item = u64> + '_ {
        let d = blake3::hash(item);
        let b = d.as_bytes();
        let h1 = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(b[8..16].try_into().unwrap()) | 1; // ímpar
        let m = self.m;
        (0..self.k as u64).map(move |i| h1.wrapping_add(i.wrapping_mul(h2)) % m)
    }

    pub fn inserir(&mut self, item: &[u8]) {
        for idx in self.indices(item).collect::<Vec<_>>() {
            self.bits[(idx / 64) as usize] |= 1u64 << (idx % 64);
        }
    }

    /// `false` = garantidamente ausente. `true` = talvez presente.
    pub fn talvez_contenha(&self, item: &[u8]) -> bool {
        self.indices(item)
            .all(|idx| self.bits[(idx / 64) as usize] & (1u64 << (idx % 64)) != 0)
    }

    pub fn bytes_em_disco(&self) -> usize {
        9 + self.bits.len() * 8
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.k);
        out.extend_from_slice(&self.m.to_le_bytes());
        for w in &self.bits {
            out.extend_from_slice(&w.to_le_bytes());
        }
    }

    fn decode(buf: &[u8]) -> V6Result<Self> {
        const CTX: &str = "hrki bloom";
        if buf.len() < 9 {
            return Err(corrupt(CTX, "short bloom header"));
        }
        let k = buf[0];
        if k == 0 || k > 16 {
            return Err(corrupt(CTX, format!("k={k} out of range")));
        }
        let m = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        if m == 0 {
            return Err(corrupt(CTX, "m=0"));
        }
        let palavras = m.div_ceil(64) as usize;
        let precisa = palavras
            .checked_mul(8)
            .ok_or_else(|| corrupt(CTX, "bloom size overflow"))?;
        checked_len(precisa, buf.len() - 9, HARD_MAX_FILTER_BYTES, CTX)?;
        let mut bits = Vec::with_capacity(palavras);
        for i in 0..palavras {
            let o = 9 + i * 8;
            bits.push(u64::from_le_bytes(buf[o..o + 8].try_into().unwrap()));
        }
        Ok(Self { bits, k, m })
    }
}

/// `keyed_blake3(index_key, valor)` — §66.
///
/// Para identificadores sensíveis. O sidecar guarda só o derivado; quem
/// consulta tem de possuir a mesma chave para o reproduzir. Sem a chave, o
/// filtro é ruído.
pub fn keyed_equality_digest(index_key: &[u8; 32], valor: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(index_key, valor).as_bytes()
}

// ---------------------------------------------------------------------------
// Zone maps por bloco (§58, §59)
// ---------------------------------------------------------------------------

/// Estatística **numérica** de um bloco. Só isto — nada de strings (§64).
///
/// `valid_*` usam `Option` porque um evento sem valid time não é o mesmo que
/// um evento com valid time zero: um bloco onde ninguém declarou tempo do
/// mundo não pode ser eliminado por um predicado sobre tempo do mundo.
/// Os dois limites não são simétricos, e isso é deliberado (A54): `valid_to`
/// ausente é "ainda válido" e liga `tem_valid_aberto`, enquanto `valid_from`
/// ausente é "válido desde sempre" e é gravado como `Some(0)` — o mínimo do
/// domínio, indistinguível de "sempre" para o teste `t < min_valid_from`.
/// `min_valid_from: None` fica só para zonas que não observaram nada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockZoneMap {
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub min_hlc: u64,
    pub max_hlc: u64,
    pub min_valid_from: Option<u64>,
    pub max_valid_to: Option<u64>,
    /// Algum evento do bloco tem `valid_to = None` (ainda válido)?
    pub tem_valid_aberto: bool,
}

impl BlockZoneMap {
    /// Pruning por LSN. Conservador: na dúvida, devolve `true`.
    pub fn pode_conter_lsn(&self, de: Lsn, ate: Lsn) -> bool {
        de <= self.last_lsn && self.first_lsn < ate
    }

    /// Pruning por HLC.
    pub fn pode_conter_hlc(&self, de: u64, ate: u64) -> bool {
        de <= self.max_hlc && self.min_hlc <= ate
    }

    /// Pruning por tempo do mundo (`VALID AT t`).
    ///
    /// Um bloco onde nenhum evento declarou `valid_from` **não pode** ser
    /// eliminado — ausência de informação não é informação. Idem para
    /// intervalos ainda abertos.
    pub fn pode_estar_valido_em(&self, t: u64) -> bool {
        let Some(min_from) = self.min_valid_from else {
            return true; // sem valid time declarado: não se pode excluir
        };
        if t < min_from {
            return false;
        }
        if self.tem_valid_aberto {
            return true;
        }
        match self.max_valid_to {
            Some(max_to) => t < max_to,
            None => true,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.first_lsn.to_le_bytes());
        out.extend_from_slice(&self.last_lsn.to_le_bytes());
        out.extend_from_slice(&self.min_hlc.to_le_bytes());
        out.extend_from_slice(&self.max_hlc.to_le_bytes());
        // Option<u64> como (presença, valor) para o layout ficar fixo.
        out.push(u8::from(self.min_valid_from.is_some()));
        out.extend_from_slice(&self.min_valid_from.unwrap_or(0).to_le_bytes());
        out.push(u8::from(self.max_valid_to.is_some()));
        out.extend_from_slice(&self.max_valid_to.unwrap_or(0).to_le_bytes());
        out.push(u8::from(self.tem_valid_aberto));
    }

    const ENCODED_LEN: usize = 8 * 4 + 1 + 8 + 1 + 8 + 1;

    fn decode(buf: &[u8]) -> V6Result<Self> {
        if buf.len() < Self::ENCODED_LEN {
            return Err(corrupt("hrki zone map", "short zone map"));
        }
        let u = |o: usize| u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
        Ok(Self {
            first_lsn: u(0),
            last_lsn: u(8),
            min_hlc: u(16),
            max_hlc: u(24),
            min_valid_from: (buf[32] != 0).then(|| u(33)),
            max_valid_to: (buf[41] != 0).then(|| u(42)),
            tem_valid_aberto: buf[50] != 0,
        })
    }
}

// ---------------------------------------------------------------------------
// Bitmap de EventKind (§63)
// ---------------------------------------------------------------------------

/// `EventKind` tem cardinalidade pequena, portanto um bitmap bate um Bloom.
///
/// Os oito kinds nomeados ocupam bits fixos; os `Custom` — cuja cardinalidade
/// é aberta — vão para um filtro separado, como a SPEC manda.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindBitmap {
    nomeados: u16,
    custom: BloomFilter,
}

/// Bit de cada kind nomeado. Permanente: mudar invalida sidecars escritos.
fn bit_do_kind(k: &EventKind) -> Option<u16> {
    Some(match k {
        EventKind::Observation => 1 << 0,
        EventKind::Action => 1 << 1,
        EventKind::Message => 1 << 2,
        EventKind::RetrievalFeedback => 1 << 3,
        EventKind::FactDerived => 1 << 4,
        EventKind::DemotionReceipt => 1 << 5,
        EventKind::SystemMetric => 1 << 6,
        EventKind::Custom(_) => return None,
    })
}

impl KindBitmap {
    pub fn nova(n_custom_estimado: usize) -> Self {
        Self {
            nomeados: 0,
            custom: BloomFilter::nova(n_custom_estimado.max(1), 0.01),
        }
    }

    pub fn inserir(&mut self, k: &EventKind) {
        match bit_do_kind(k) {
            Some(b) => self.nomeados |= b,
            None => self.custom.inserir(k.label().as_bytes()),
        }
    }

    /// `false` = o segmento garantidamente não tem eventos deste kind.
    pub fn talvez_contenha(&self, k: &EventKind) -> bool {
        match bit_do_kind(k) {
            Some(b) => self.nomeados & b != 0,
            None => self.custom.talvez_contenha(k.label().as_bytes()),
        }
    }
}

// ---------------------------------------------------------------------------
// Header e directório de secções
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HrkiHeader {
    pub segment_id: u64,
    pub canonical_codec: u8,
    pub segment_logical_root: [u8; 32],
    pub index_policy_hash: [u8; 32],
    pub section_count: u16,
}

impl HrkiHeader {
    fn encode(&self) -> [u8; HRKI_HEADER_LEN] {
        let mut b = [0u8; HRKI_HEADER_LEN];
        b[0..4].copy_from_slice(&HRKI_MAGIC);
        b[4..6].copy_from_slice(&HRKI_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(HRKI_HEADER_LEN as u16).to_le_bytes());
        b[8..16].copy_from_slice(&self.segment_id.to_le_bytes());
        b[16] = self.canonical_codec;
        b[17..19].copy_from_slice(&self.section_count.to_le_bytes());
        // 19..24 reservado
        b[24..56].copy_from_slice(&self.segment_logical_root);
        b[56..88].copy_from_slice(&self.index_policy_hash);
        // 88..92 reservado
        let crc = super::crc32c_of(&b[..92]);
        b[92..96].copy_from_slice(&crc.to_le_bytes());
        b
    }

    fn decode(buf: &[u8]) -> V6Result<Self> {
        const CTX: &str = "hrki header";
        if buf.len() < HRKI_HEADER_LEN {
            return Err(corrupt(CTX, "short header"));
        }
        if buf[0..4] != HRKI_MAGIC {
            return Err(corrupt(CTX, "bad magic"));
        }
        let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        if version != HRKI_VERSION {
            return Err(corrupt(CTX, format!("hrki version {version} unsupported")));
        }
        let crc = u32::from_le_bytes(buf[92..96].try_into().unwrap());
        if super::crc32c_of(&buf[..92]) != crc {
            return Err(corrupt(CTX, "header crc mismatch"));
        }
        let section_count = u16::from_le_bytes(buf[17..19].try_into().unwrap());
        if section_count as usize > HARD_MAX_SECTIONS {
            return Err(corrupt(CTX, format!("{section_count} sections is absurd")));
        }
        Ok(Self {
            segment_id: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            canonical_codec: buf[16],
            segment_logical_root: buf[24..56].try_into().unwrap(),
            index_policy_hash: buf[56..88].try_into().unwrap(),
            section_count,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SectionDirEntry {
    section_type: u16,
    section_version: u16,
    offset: u64,
    length: u64,
    crc32c: u32,
}

impl SectionDirEntry {
    fn encode(&self) -> [u8; SECTION_ENTRY_LEN] {
        let mut b = [0u8; SECTION_ENTRY_LEN];
        b[0..2].copy_from_slice(&self.section_type.to_le_bytes());
        b[2..4].copy_from_slice(&self.section_version.to_le_bytes());
        b[4..12].copy_from_slice(&self.offset.to_le_bytes());
        b[12..20].copy_from_slice(&self.length.to_le_bytes());
        b[20..24].copy_from_slice(&self.crc32c.to_le_bytes());
        b
    }

    fn decode(buf: &[u8]) -> V6Result<Self> {
        if buf.len() < SECTION_ENTRY_LEN {
            return Err(corrupt("hrki section entry", "short entry"));
        }
        Ok(Self {
            section_type: u16::from_le_bytes(buf[0..2].try_into().unwrap()),
            section_version: u16::from_le_bytes(buf[2..4].try_into().unwrap()),
            offset: u64::from_le_bytes(buf[4..12].try_into().unwrap()),
            length: u64::from_le_bytes(buf[12..20].try_into().unwrap()),
            crc32c: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
        })
    }
}

// ---------------------------------------------------------------------------
// O sidecar
// ---------------------------------------------------------------------------

/// Um `.hrki` construído ou lido.
#[derive(Debug, Clone)]
pub struct Hrki {
    pub header: HrkiHeader,
    pub zonas: Vec<BlockZoneMap>,
    pub kinds: Option<KindBitmap>,
    /// Filtros de igualdade, por nome de campo.
    pub filtros: Vec<(String, BloomFilter)>,
}

impl Hrki {
    /// Elimina blocos por LSN. Devolve os índices que **podem** interessar.
    pub fn blocos_para_lsn(&self, de: Lsn, ate: Lsn) -> Vec<usize> {
        self.zonas
            .iter()
            .enumerate()
            .filter(|(_, z)| z.pode_conter_lsn(de, ate))
            .map(|(i, _)| i)
            .collect()
    }

    /// Elimina blocos por HLC.
    pub fn blocos_para_hlc(&self, de: u64, ate: u64) -> Vec<usize> {
        self.zonas
            .iter()
            .enumerate()
            .filter(|(_, z)| z.pode_conter_hlc(de, ate))
            .map(|(i, _)| i)
            .collect()
    }

    /// Elimina blocos por tempo do mundo.
    pub fn blocos_validos_em(&self, t: u64) -> Vec<usize> {
        self.zonas
            .iter()
            .enumerate()
            .filter(|(_, z)| z.pode_estar_valido_em(t))
            .map(|(i, _)| i)
            .collect()
    }

    /// `false` = o segmento garantidamente não tem este kind.
    pub fn talvez_contenha_kind(&self, k: &EventKind) -> bool {
        self.kinds.as_ref().is_none_or(|b| b.talvez_contenha(k))
    }

    /// `false` = o segmento garantidamente não tem este valor neste campo.
    ///
    /// Um campo sem filtro devolve `true`: ausência de índice nunca exclui.
    pub fn talvez_contenha(&self, campo: &str, valor: &[u8]) -> bool {
        self.filtros
            .iter()
            .find(|(c, _)| c == campo)
            .is_none_or(|(_, f)| f.talvez_contenha(valor))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut seccoes: Vec<(u16, Vec<u8>)> = Vec::new();

        if !self.zonas.is_empty() {
            let mut b = Vec::with_capacity(8 + self.zonas.len() * BlockZoneMap::ENCODED_LEN);
            b.extend_from_slice(&(self.zonas.len() as u64).to_le_bytes());
            for z in &self.zonas {
                z.encode(&mut b);
            }
            seccoes.push((section_type::BLOCK_ZONE_MAPS, b));
        }

        if let Some(k) = &self.kinds {
            let mut b = Vec::new();
            b.extend_from_slice(&k.nomeados.to_le_bytes());
            k.custom.encode(&mut b);
            seccoes.push((section_type::EVENT_KIND_BITMAP, b));
        }

        if !self.filtros.is_empty() {
            let mut b = Vec::new();
            b.extend_from_slice(&(self.filtros.len() as u32).to_le_bytes());
            for (campo, f) in &self.filtros {
                b.extend_from_slice(&(campo.len() as u32).to_le_bytes());
                b.extend_from_slice(campo.as_bytes());
                let mut fb = Vec::new();
                f.encode(&mut fb);
                b.extend_from_slice(&(fb.len() as u64).to_le_bytes());
                b.extend_from_slice(&fb);
            }
            seccoes.push((section_type::EQUALITY_FILTERS, b));
        }

        let dir_len = seccoes.len() * SECTION_ENTRY_LEN;
        let mut corpo = Vec::new();
        let mut dir = Vec::with_capacity(dir_len);
        let base = (HRKI_HEADER_LEN + dir_len) as u64;

        for (tipo, bytes) in &seccoes {
            let e = SectionDirEntry {
                section_type: *tipo,
                section_version: 1,
                offset: base + corpo.len() as u64,
                length: bytes.len() as u64,
                crc32c: super::crc32c_of(bytes),
            };
            dir.extend_from_slice(&e.encode());
            corpo.extend_from_slice(bytes);
        }

        let mut header = self.header.clone();
        header.section_count = seccoes.len() as u16;

        let mut out = Vec::with_capacity(HRKI_HEADER_LEN + dir_len + corpo.len());
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&dir);
        out.extend_from_slice(&corpo);
        out
    }

    pub fn decode(buf: &[u8]) -> V6Result<Self> {
        const CTX: &str = "hrki";
        let header = HrkiHeader::decode(buf)?;
        let n = header.section_count as usize;
        let dir_fim = HRKI_HEADER_LEN + n * SECTION_ENTRY_LEN;
        if buf.len() < dir_fim {
            return Err(corrupt(CTX, "short section directory"));
        }

        let mut zonas = Vec::new();
        let mut kinds = None;
        let mut filtros = Vec::new();

        for i in 0..n {
            let o = HRKI_HEADER_LEN + i * SECTION_ENTRY_LEN;
            let e = SectionDirEntry::decode(&buf[o..])?;
            let ini = e.offset as usize;
            let len = e.length as usize;
            let fim = ini
                .checked_add(len)
                .ok_or_else(|| corrupt(CTX, "section offset overflow"))?;
            if fim > buf.len() {
                return Err(corrupt(CTX, "section runs past end of file"));
            }
            let corpo = &buf[ini..fim];
            if super::crc32c_of(corpo) != e.crc32c {
                return Err(corrupt(
                    CTX,
                    format!("section {} crc mismatch", e.section_type),
                ));
            }

            match e.section_type {
                section_type::BLOCK_ZONE_MAPS => {
                    if corpo.len() < 8 {
                        return Err(corrupt(CTX, "short zone section"));
                    }
                    let count = u64::from_le_bytes(corpo[..8].try_into().unwrap()) as usize;
                    if count > HARD_MAX_ZONES {
                        return Err(corrupt(CTX, format!("{count} zone maps is absurd")));
                    }
                    let precisa = count
                        .checked_mul(BlockZoneMap::ENCODED_LEN)
                        .ok_or_else(|| corrupt(CTX, "zone size overflow"))?;
                    checked_len(precisa, corpo.len() - 8, HARD_MAX_FILTER_BYTES, CTX)?;
                    zonas.reserve(count);
                    for j in 0..count {
                        zonas.push(BlockZoneMap::decode(
                            &corpo[8 + j * BlockZoneMap::ENCODED_LEN..],
                        )?);
                    }
                }
                section_type::EVENT_KIND_BITMAP => {
                    if corpo.len() < 2 {
                        return Err(corrupt(CTX, "short kind bitmap"));
                    }
                    kinds = Some(KindBitmap {
                        nomeados: u16::from_le_bytes(corpo[..2].try_into().unwrap()),
                        custom: BloomFilter::decode(&corpo[2..])?,
                    });
                }
                section_type::EQUALITY_FILTERS => {
                    if corpo.len() < 4 {
                        return Err(corrupt(CTX, "short filter section"));
                    }
                    let count = u32::from_le_bytes(corpo[..4].try_into().unwrap()) as usize;
                    if count > HARD_MAX_SECTIONS * 16 {
                        return Err(corrupt(CTX, format!("{count} filters is absurd")));
                    }
                    let mut p = 4usize;
                    for _ in 0..count {
                        if p + 4 > corpo.len() {
                            return Err(corrupt(CTX, "truncated filter name"));
                        }
                        let nl = u32::from_le_bytes(corpo[p..p + 4].try_into().unwrap()) as usize;
                        p += 4;
                        checked_len(nl, corpo.len() - p, 1024, CTX)?;
                        let nome = std::str::from_utf8(&corpo[p..p + nl])
                            .map_err(|_| corrupt(CTX, "filter name is not utf-8"))?
                            .to_string();
                        p += nl;
                        if p + 8 > corpo.len() {
                            return Err(corrupt(CTX, "truncated filter body"));
                        }
                        let fl = u64::from_le_bytes(corpo[p..p + 8].try_into().unwrap()) as usize;
                        p += 8;
                        checked_len(fl, corpo.len() - p, HARD_MAX_FILTER_BYTES, CTX)?;
                        filtros.push((nome, BloomFilter::decode(&corpo[p..p + fl])?));
                        p += fl;
                    }
                }
                // Secção desconhecida: salta-se pelo `length`. É o que torna o
                // formato extensível sem quebrar leitores antigos (§57).
                _ => {}
            }
        }

        Ok(Self {
            header,
            zonas,
            kinds,
            filtros,
        })
    }

    /// Grava o sidecar ao lado do `.hrkl`.
    pub fn escrever(&self, hrkl: &Path) -> V6Result<()> {
        use std::io::Write as _;

        let path = caminho_sidecar(hrkl);
        let tmp = path.with_extension("hrki.tmp");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        file.write_all(&self.encode())?;
        file.sync_all()?;
        drop(file);
        // No Windows `rename` não substitui o destino. Como o sidecar é
        // derivado, uma queda neste intervalo deixa-o ausente (fallback para
        // scan + reconstrução), nunca deixa o HRKL incorrecto.
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        std::fs::rename(&tmp, &path)?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Lê e **valida contra o segmento** (§56).
    ///
    /// Devolve `Ok(None)` — não erro — quando o sidecar não existe, não
    /// descodifica, ou não corresponde a este segmento. É o comportamento
    /// normativo: um sidecar mau degrada desempenho, nunca correção, e **nunca**
    /// é reportado como corrupção do `.hrkl`.
    pub fn ler_validado(
        hrkl: &Path,
        segment_id: u64,
        segment_logical_root: &[u8; 32],
    ) -> Option<Self> {
        let bytes = std::fs::read(caminho_sidecar(hrkl)).ok()?;
        let h = Self::decode(&bytes).ok()?;
        if h.header.segment_id != segment_id {
            return None;
        }
        if &h.header.segment_logical_root != segment_logical_root {
            return None;
        }
        Some(h)
    }
}

/// `…/000…421.hrkl` → `…/000…421.hrki`
pub fn caminho_sidecar(hrkl: &Path) -> std::path::PathBuf {
    hrkl.with_extension("hrki")
}

// ---------------------------------------------------------------------------
// Construtor
// ---------------------------------------------------------------------------

/// Constrói um `.hrki` a partir dos blocos e eventos de um segmento selado.
pub struct HrkiBuilder {
    header: HrkiHeader,
    politica: IndexPolicySet,
    index_key: Option<[u8; 32]>,
    zonas: Vec<BlockZoneMap>,
    zona_actual: Option<BlockZoneMap>,
    kinds: KindBitmap,
    campos: Vec<(String, BTreeSet<Vec<u8>>)>,
    /// Se um único payload não pôde ser interpretado, filtros/kinds globais
    /// deixam de ser seguros: esse registo pode conter justamente o valor que
    /// pareceria ausente. Nesse caso conservamos apenas as zone maps físicas.
    has_opaque: bool,
}

impl HrkiBuilder {
    /// `index_key` é obrigatória se a política declarar algum campo
    /// [`IndexPolicy::HashedEquality`]. Sem ela o construtor recusa, em vez de
    /// silenciosamente gravar o identificador em claro.
    pub fn novo(
        segment_id: u64,
        segment_logical_root: [u8; 32],
        politica: IndexPolicySet,
        index_key: Option<[u8; 32]>,
    ) -> V6Result<Self> {
        const CTX: &str = "hrki builder";
        for (campo, p) in &politica.campos {
            match p {
                IndexPolicy::HashedEquality if index_key.is_none() => {
                    return Err(corrupt(
                        CTX,
                        format!("campo '{campo}' pede HashedEquality mas nao ha index_key"),
                    ));
                }
                IndexPolicy::EncryptedSidecar => {
                    return Err(corrupt(
                        CTX,
                        format!(
                            "campo '{campo}': ENCRYPTED_SIDECAR nao esta implementado nesta fase"
                        ),
                    ));
                }
                _ => {}
            }
        }
        Ok(Self {
            header: HrkiHeader {
                segment_id,
                canonical_codec: CANONICAL_CODEC_V1,
                segment_logical_root,
                index_policy_hash: politica.hash(),
                section_count: 0,
            },
            politica,
            index_key,
            zonas: Vec::new(),
            zona_actual: None,
            kinds: KindBitmap::nova(64),
            campos: Vec::new(),
            has_opaque: false,
        })
    }

    /// Abre um bloco novo. Os eventos seguintes contam para ele.
    pub fn iniciar_bloco(&mut self) {
        if let Some(z) = self.zona_actual.take() {
            self.zonas.push(z);
        }
        self.zona_actual = Some(BlockZoneMap {
            first_lsn: Lsn::MAX,
            last_lsn: 0,
            min_hlc: u64::MAX,
            max_hlc: 0,
            ..Default::default()
        });
    }

    /// Regista um registo cujo payload não foi descodificável.
    ///
    /// A zona do bloco continua correcta — LSN e HLC vêm do enquadramento, não
    /// do payload — mas o registo não contribui para kinds nem filtros. É o
    /// comportamento seguro: um sidecar que ignorasse o registo por completo
    /// poderia produzir uma zona demasiado estreita e **excluir** um bloco que
    /// afinal interessa, que é o único erro inaceitável aqui.
    pub fn observar_opaco(&mut self, lsn: Lsn, hlc: u64) {
        self.has_opaque = true;
        if self.zona_actual.is_none() {
            self.iniciar_bloco();
        }
        if let Some(z) = self.zona_actual.as_mut() {
            z.first_lsn = z.first_lsn.min(lsn);
            z.last_lsn = z.last_lsn.max(lsn);
            z.min_hlc = z.min_hlc.min(hlc);
            z.max_hlc = z.max_hlc.max(hlc);
            // Sem saber o valid time, o bloco não pode ser excluído por ele.
            // Auditoria 2026-09-05 (A54): isso são DUAS marcas, não uma. Sem
            // `min_valid_from = 0`, um registo opaco num bloco onde outro
            // registo declarou `valid_from = 1000` continuava a ser podado por
            // um `VALID AT 5` — o limite inferior ignorava-o por completo.
            z.min_valid_from = Some(0);
            z.tem_valid_aberto = true;
        }
    }

    /// Regista um evento no bloco corrente.
    pub fn observar(&mut self, lsn: Lsn, hlc: u64, ep: &heraclitus_core::Episode) {
        if self.zona_actual.is_none() {
            self.iniciar_bloco();
        }
        if let Some(z) = self.zona_actual.as_mut() {
            z.first_lsn = z.first_lsn.min(lsn);
            z.last_lsn = z.last_lsn.max(lsn);
            z.min_hlc = z.min_hlc.min(hlc);
            z.max_hlc = z.max_hlc.max(hlc);
            // Auditoria 2026-09-05 (A54): `valid_from` ausente quer dizer
            // "válido desde sempre" (`Episode::valid_from`), não "sem
            // informação" — e o ramo em falta produzia falsos negativos: um
            // bloco que misturasse um facto atemporal com um facto datado em
            // 1000 selava `min_valid_from = Some(1000)` e era podado por um
            // `VALID AT 5`, apesar de o atemporal ser válido nesse instante.
            // 0 é o mínimo do domínio, logo `t < 0` é falso para todo o
            // `t: u64`: marcá-lo desliga o limite inferior sem mexer no
            // formato em disco, e é mais preciso do que deixar `None` — que
            // desligaria também o limite SUPERIOR, que aqui é conhecido.
            match ep.valid_from {
                Some(v) => z.min_valid_from = Some(z.min_valid_from.map_or(v, |m| m.min(v))),
                None => z.min_valid_from = Some(0),
            }
            match ep.valid_to {
                Some(v) => z.max_valid_to = Some(z.max_valid_to.map_or(v, |m| m.max(v))),
                None => z.tem_valid_aberto = true,
            }
        }

        self.kinds.inserir(&ep.kind);

        // Built-ins também obedecem à política explícita. Não entram por
        // omissão; o worker decide, por configuração, se são técnicos em
        // claro, hashed ou não indexáveis.
        self.observar_valor("event_id", ep.id.to_string().as_bytes());
        self.observar_valor("agent_id", ep.agent_id.as_bytes());
        self.observar_valor("session_id", ep.session_id.as_bytes());

        // §67: `attrs.*` é DO_NOT_INDEX por omissão. Só entram os campos
        // declarados — e os sensíveis entram com chave (§66).
        for (campo, valor) in &ep.attrs {
            self.observar_valor(campo, valor.as_bytes());
        }
    }

    fn observar_valor(&mut self, campo: &str, valor: &[u8]) {
        match self.politica.politica_de(campo) {
            IndexPolicy::PublicTechnical => self.registar(campo, valor.to_vec()),
            IndexPolicy::HashedEquality => {
                let k = self.index_key.expect("validado no construtor");
                let d = keyed_equality_digest(&k, valor);
                self.registar(campo, d.to_vec());
            }
            IndexPolicy::EncryptedSidecar | IndexPolicy::DoNotIndex => {}
        }
    }

    fn registar(&mut self, campo: &str, valor: Vec<u8>) {
        match self.campos.iter_mut().find(|(c, _)| c == campo) {
            Some((_, s)) => {
                s.insert(valor);
            }
            None => {
                let mut s = BTreeSet::new();
                s.insert(valor);
                self.campos.push((campo.to_string(), s));
            }
        }
    }

    /// Fecha e produz o sidecar. `fpr` aplica-se aos filtros de igualdade.
    pub fn construir(mut self, fpr: f64) -> Hrki {
        if let Some(z) = self.zona_actual.take() {
            self.zonas.push(z);
        }
        // Um bloco sem eventos ficaria com first_lsn = MAX; normaliza-se para
        // não poder eliminar nada por engano.
        for z in &mut self.zonas {
            if z.first_lsn == Lsn::MAX {
                *z = BlockZoneMap::default();
                z.max_hlc = u64::MAX;
                z.last_lsn = Lsn::MAX;
            }
            if z.min_hlc == u64::MAX {
                z.min_hlc = 0;
            }
        }

        let filtros = if self.has_opaque {
            Vec::new()
        } else {
            self.campos
                .into_iter()
                .map(|(campo, valores)| {
                    let mut f = BloomFilter::nova(valores.len(), fpr);
                    for v in &valores {
                        f.inserir(v);
                    }
                    (campo, f)
                })
                .collect()
        };

        Hrki {
            header: self.header,
            zonas: self.zonas,
            kinds: (!self.has_opaque).then_some(self.kinds),
            filtros,
        }
    }
}

// ---------------------------------------------------------------------------
// Construção a partir de um segmento PACKED já publicado
// ---------------------------------------------------------------------------

/// Constrói e grava o `.hrki` de um segmento **PACKED** selado.
///
/// Corre depois de o PACKED ser publicado, e nunca no hot-path (§22, §147): o
/// sidecar é derivado, portanto a sua ausência custa desempenho e nunca
/// correção. Se falhar, quem chama regista e segue — não desfaz o packing.
///
/// A granularidade das zone maps é o **bloco**, que é o que o pruning consegue
/// eliminar antes do range read (§59).
pub fn construir_para_packed(
    packed: &std::path::Path,
    politica: &IndexPolicySet,
    index_key: Option<[u8; 32]>,
    fpr: f64,
    max_block_bytes: usize,
    decode_episode: &dyn Fn(&[u8]) -> Option<heraclitus_core::Episode>,
) -> V6Result<Hrki> {
    use super::packed::{FileSource, PackedSegmentReader, ScanCounters};

    let reader = PackedSegmentReader::open(FileSource::open(packed)?, max_block_bytes)?;
    let mut b = HrkiBuilder::novo(
        reader.header.segment_id,
        reader.logical_root(),
        politica.clone(),
        index_key,
    )?;

    let mut counters = ScanCounters::default();
    for i in 0..reader.block_count() {
        b.iniciar_bloco();
        let (hdr, corpo) = reader.read_block(i, &mut counters)?;
        // O payload é opaco para o v6, por isso quem chama fornece o
        // descodificador — o `hrki` não sabe (nem deve saber) desserializar
        // `Episode`. Um payload que não descodifique não impede o sidecar: a
        // zona do bloco continua correcta pelos LSN/HLC do próprio bloco.
        for r in super::block::decode_block_records(&hdr, &corpo)? {
            if let Some(ep) = decode_episode(r.payload) {
                b.observar(r.lsn, r.hlc, &ep);
            } else {
                b.observar_opaco(r.lsn, r.hlc);
            }
        }
    }

    let h = b.construir(fpr);
    h.escrever(packed)?;
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind};

    fn ep(kind: &str, uf: &str) -> Episode {
        let mut e = Episode::new("ag", EventKind::Custom(kind.into()), vec![]);
        e.attrs.insert("uf".into(), uf.into());
        e.attrs.insert("segredo".into(), format!("cpf-{uf}"));
        e
    }

    fn politica() -> IndexPolicySet {
        IndexPolicySet::new()
            .com("uf", IndexPolicy::PublicTechnical)
            .com("segredo", IndexPolicy::HashedEquality)
    }

    #[test]
    fn bloom_nunca_tem_falso_negativo() {
        // A propriedade inegociável (§62): tudo o que foi inserido tem de ser
        // encontrado. Falsos positivos são aceitáveis; falsos negativos não.
        let mut f = BloomFilter::nova(1000, 0.01);
        let itens: Vec<Vec<u8>> = (0..1000u32).map(|i| i.to_le_bytes().to_vec()).collect();
        for i in &itens {
            f.inserir(i);
        }
        for i in &itens {
            assert!(f.talvez_contenha(i), "falso negativo — inaceitavel");
        }
    }

    #[test]
    fn bloom_respeita_a_fpr_aproximadamente() {
        let mut f = BloomFilter::nova(2000, 0.01);
        for i in 0..2000u32 {
            f.inserir(&i.to_le_bytes());
        }
        let falsos = (100_000u32..110_000)
            .filter(|i| f.talvez_contenha(&i.to_le_bytes()))
            .count();
        // Margem generosa: o que interessa é não estar uma ordem de grandeza fora.
        assert!(falsos < 500, "fpr muito acima do pedido: {falsos}/10000");
    }

    #[test]
    fn zona_sem_valid_time_nao_pode_ser_eliminada() {
        // Ausência de informação não é informação.
        let z = BlockZoneMap {
            first_lsn: 0,
            last_lsn: 10,
            min_hlc: 0,
            max_hlc: 100,
            min_valid_from: None,
            max_valid_to: None,
            tem_valid_aberto: false,
        };
        assert!(z.pode_estar_valido_em(0));
        assert!(z.pode_estar_valido_em(u64::MAX));
    }

    #[test]
    fn zona_com_intervalo_aberto_nunca_exclui_o_futuro() {
        let z = BlockZoneMap {
            first_lsn: 0,
            last_lsn: 10,
            min_hlc: 0,
            max_hlc: 100,
            min_valid_from: Some(50),
            max_valid_to: Some(60),
            tem_valid_aberto: true,
        };
        assert!(!z.pode_estar_valido_em(49), "antes do minimo: excluivel");
        assert!(z.pode_estar_valido_em(50), "o proprio minimo esta dentro");
        assert!(z.pode_estar_valido_em(1_000_000), "ha intervalo aberto");
    }

    #[test]
    fn bloco_com_facto_atemporal_nao_pode_ser_podado_no_passado() {
        // Auditoria 2026-09-05 (A54): `valid_from = None` quer dizer "valido
        // desde sempre". Um bloco que mistura um facto atemporal com um facto
        // datado no futuro tem de sobreviver a um `VALID AT` anterior ao datado.
        let mut b = HrkiBuilder::novo(1, [0u8; 32], politica(), Some([3u8; 32])).unwrap();
        b.iniciar_bloco();
        b.observar(0, 1, &ep("Atemporal", "SP")); // valid_from = None
        let mut datado = ep("Datado", "RJ");
        datado.valid_from = Some(1000);
        b.observar(1, 2, &datado);
        let h = b.construir(0.01);

        assert_eq!(
            h.blocos_validos_em(5),
            vec![0],
            "o bloco tem um facto valido desde sempre: podar e um falso negativo"
        );
    }

    #[test]
    fn bloco_com_registo_opaco_nao_pode_ser_podado_no_passado() {
        // Auditoria 2026-09-05 (A54): o registo opaco nao declara valid time
        // nenhum, portanto o bloco tambem nao pode ser excluido pelo limite
        // INFERIOR — nao so pelo superior.
        let mut b = HrkiBuilder::novo(1, [0u8; 32], politica(), Some([3u8; 32])).unwrap();
        b.iniciar_bloco();
        b.observar_opaco(0, 1);
        let mut datado = ep("Datado", "RJ");
        datado.valid_from = Some(1000);
        b.observar(1, 2, &datado);
        let h = b.construir(0.01);

        assert_eq!(
            h.blocos_validos_em(5),
            vec![0],
            "nao se conhece o valid time do registo opaco: nao pode ser excluido"
        );
    }

    #[test]
    fn bloco_todo_datado_no_futuro_continua_a_ser_podado() {
        // Nao-regressao: alargar o limite inferior nao pode desligar o pruning
        // legitimo. Aqui NENHUM facto e valido em t = 5.
        let mut b = HrkiBuilder::novo(1, [0u8; 32], politica(), Some([3u8; 32])).unwrap();
        b.iniciar_bloco();
        for i in 0..4u64 {
            let mut e = ep("Datado", "SP");
            e.valid_from = Some(1000 + i);
            b.observar(i, i, &e);
        }
        let h = b.construir(0.01);

        assert!(
            h.blocos_validos_em(5).is_empty(),
            "nenhum facto e valido em t=5: o pruning tem de continuar a funcionar"
        );
    }

    #[test]
    fn bloco_atemporal_todo_fechado_pode_ser_podado_no_futuro() {
        // Auditoria 2026-09-05 (A54): marcar "desde sempre" como min = 0 e
        // ESTRITAMENTE mais preciso do que nao marcar nada. Antes, um bloco sem
        // nenhum `valid_from` escapava cegamente pelo ramo `None => true`;
        // agora, se todos os factos fecharam em t = 100, `VALID AT 200` poda-o.
        let mut b = HrkiBuilder::novo(1, [0u8; 32], politica(), Some([3u8; 32])).unwrap();
        b.iniciar_bloco();
        for i in 0..4u64 {
            let mut e = ep("Fechado", "SP");
            e.valid_to = Some(100);
            b.observar(i, i, &e);
        }
        let h = b.construir(0.01);

        assert!(
            h.blocos_validos_em(200).is_empty(),
            "todos os factos terminaram em t=100: nada e valido em t=200"
        );
    }

    #[test]
    fn roundtrip_completo() {
        let mut b = HrkiBuilder::novo(7, [9u8; 32], politica(), Some([3u8; 32])).unwrap();
        b.iniciar_bloco();
        for i in 0..50u64 {
            let mut e = ep("Contrato", if i % 2 == 0 { "SP" } else { "RJ" });
            e.valid_from = Some(1000 + i);
            b.observar(i, 500 + i, &e);
        }
        b.iniciar_bloco();
        for i in 50..100u64 {
            b.observar(i, 500 + i, &ep("Licitacao", "MG"));
        }
        let h = b.construir(0.01);

        let bytes = h.encode();
        let lido = Hrki::decode(&bytes).unwrap();

        assert_eq!(lido.header.segment_id, 7);
        assert_eq!(lido.header.segment_logical_root, [9u8; 32]);
        assert_eq!(lido.zonas.len(), 2);
        assert_eq!(lido.zonas[0].first_lsn, 0);
        assert_eq!(lido.zonas[0].last_lsn, 49);
        assert_eq!(lido.zonas[1].first_lsn, 50);

        // Pruning por LSN elimina o bloco certo.
        assert_eq!(lido.blocos_para_lsn(0, 10), vec![0]);
        assert_eq!(lido.blocos_para_lsn(60, 70), vec![1]);
        assert_eq!(lido.blocos_para_lsn(0, 100), vec![0, 1]);

        // Kinds.
        assert!(lido.talvez_contenha_kind(&EventKind::Custom("Contrato".into())));
        assert!(!lido.talvez_contenha_kind(&EventKind::Observation));

        // Campo público em claro.
        assert!(lido.talvez_contenha("uf", b"SP"));
        assert!(!lido.talvez_contenha("uf", b"ZZ"));
    }

    #[test]
    fn campo_sensivel_nao_aparece_em_claro_no_ficheiro() {
        // §64/§66: o sidecar não pode conter o identificador sensível.
        let mut b = HrkiBuilder::novo(1, [0u8; 32], politica(), Some([42u8; 32])).unwrap();
        b.iniciar_bloco();
        b.observar(0, 0, &ep("X", "SP"));
        let bytes = b.construir(0.01).encode();

        assert!(
            bytes.windows(6).all(|w| w != b"cpf-SP"),
            "o valor sensivel apareceu em claro no sidecar"
        );
        // E o `uf`, que é PublicTechnical, é procurável.
        let h = Hrki::decode(&bytes).unwrap();
        assert!(h.talvez_contenha("uf", b"SP"));
        // O sensível só é procurável por quem tiver a chave.
        let d = keyed_equality_digest(&[42u8; 32], b"cpf-SP");
        assert!(h.talvez_contenha("segredo", &d));
    }

    #[test]
    fn hashed_equality_sem_chave_e_recusado() {
        let r = HrkiBuilder::novo(1, [0u8; 32], politica(), None);
        assert!(
            r.is_err(),
            "declarar HashedEquality sem chave tem de falhar"
        );
    }

    #[test]
    fn attrs_nao_declarados_nao_sao_indexados() {
        // §67: o default é DO_NOT_INDEX.
        let vazia = IndexPolicySet::new();
        let mut b = HrkiBuilder::novo(1, [0u8; 32], vazia, None).unwrap();
        b.iniciar_bloco();
        b.observar(0, 0, &ep("X", "SP"));
        let h = b.construir(0.01);
        assert!(h.filtros.is_empty(), "nenhum attr devia ter sido indexado");
        // E consultar um campo sem filtro nunca exclui.
        assert!(h.talvez_contenha("uf", b"QUALQUER"));
    }

    #[test]
    fn builtins_so_entram_por_politica_explicita() {
        let p = IndexPolicySet::new()
            .com("agent_id", IndexPolicy::PublicTechnical)
            .com("session_id", IndexPolicy::PublicTechnical);
        let mut b = HrkiBuilder::novo(1, [0; 32], p, None).unwrap();
        b.iniciar_bloco();
        let mut e = ep("X", "SP");
        e.agent_id = "agente-tecnico".into();
        e.session_id = "sessao-tecnica".into();
        b.observar(0, 0, &e);
        let h = b.construir(0.01);
        assert!(h.talvez_contenha("agent_id", b"agente-tecnico"));
        assert!(!h.talvez_contenha("agent_id", b"outro"));
        assert!(h.talvez_contenha("session_id", b"sessao-tecnica"));
        assert!(!h.talvez_contenha("session_id", b"outra"));
    }

    #[test]
    fn payload_opaco_desliga_filtros_que_poderiam_dar_falso_negativo() {
        let p = IndexPolicySet::new().com("agent_id", IndexPolicy::PublicTechnical);
        let mut b = HrkiBuilder::novo(1, [0; 32], p, None).unwrap();
        b.iniciar_bloco();
        b.observar(0, 0, &ep("X", "SP"));
        b.observar_opaco(1, 1);
        let h = b.construir(0.01);
        assert!(h.kinds.is_none());
        assert!(h.filtros.is_empty());
        assert!(
            h.talvez_contenha("agent_id", b"qualquer-coisa"),
            "ausência de informação nunca pode excluir"
        );
    }

    #[test]
    fn sidecar_de_outro_segmento_e_ignorado_nao_e_erro() {
        // §56: a regra que impede um sidecar mau de parecer corrupção do log.
        let dir = tempfile::tempdir().unwrap();
        let hrkl = dir.path().join("00000000000000000042.hrkl");
        std::fs::write(&hrkl, b"nao interessa").unwrap();

        let mut b = HrkiBuilder::novo(42, [1u8; 32], IndexPolicySet::new(), None).unwrap();
        b.iniciar_bloco();
        b.observar(0, 0, &ep("X", "SP"));
        b.construir(0.01).escrever(&hrkl).unwrap();

        // Raiz certa: aceite.
        assert!(Hrki::ler_validado(&hrkl, 42, &[1u8; 32]).is_some());
        // Raiz diferente: ignorado, sem erro.
        assert!(Hrki::ler_validado(&hrkl, 42, &[2u8; 32]).is_none());
        // Segmento diferente: ignorado, sem erro.
        assert!(Hrki::ler_validado(&hrkl, 43, &[1u8; 32]).is_none());
        // Ficheiro lixo: ignorado, sem erro.
        std::fs::write(caminho_sidecar(&hrkl), b"lixo").unwrap();
        assert!(Hrki::ler_validado(&hrkl, 42, &[1u8; 32]).is_none());
    }

    #[test]
    fn seccao_corrompida_e_detectada_pelo_crc() {
        let mut b = HrkiBuilder::novo(1, [0u8; 32], politica(), Some([1u8; 32])).unwrap();
        b.iniciar_bloco();
        for i in 0..20u64 {
            b.observar(i, i, &ep("X", "SP"));
        }
        let mut bytes = b.construir(0.01).encode();
        let n = bytes.len();
        bytes[n - 5] ^= 0xFF;
        assert!(
            Hrki::decode(&bytes).is_err(),
            "crc de seccao tem de apanhar"
        );
    }

    #[test]
    fn input_malformado_nunca_entra_em_panico() {
        for tam in [0usize, 1, 4, 32, 96, 97, 200] {
            let _ = Hrki::decode(&vec![0xABu8; tam]);
        }
        let mut b = HrkiBuilder::novo(1, [0u8; 32], IndexPolicySet::new(), None).unwrap();
        b.iniciar_bloco();
        b.observar(0, 0, &ep("X", "SP"));
        let bons = b.construir(0.01).encode();
        for corte in 0..bons.len().min(300) {
            let _ = Hrki::decode(&bons[..corte]);
        }
    }
}
