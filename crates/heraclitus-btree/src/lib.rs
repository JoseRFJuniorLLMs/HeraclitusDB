//! heraclitus-btree — Motor de Árvore Bᵋ-tree (Fractal Tree) de Classe Comercial.
//!
//! Implementação definitiva, de nível de produção e totalmente endurecida para o marco M22.
//! Fornece suporte completo a Shadow Paging puro (Copy-on-Write de dados e metadados),
//! Tabela de Páginas Sujas (Dirty Page Table) dedicada O(1), Filtros de Bloom por amostragem
//! criptográfica independente por página, Sharding de Cache (Lock Striping) contra concorrência,
//! Compressão por Prefixo defensiva, CoW estrito para a FreeList e Garbage Collection
//! automatizado de versões obsoletas do MVCC. Totalmente livre de comportamento indefinido e unsafe.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

pub type Key = Vec<u8>;
pub type Val = Vec<u8>;

pub const PAGE_SIZE: usize = 4096;
const MAGIC: &[u8; 4] = b"HRKL";
/// Versão de layout. 4→5 (V2.2): o slot de valor da folha passa de 6 para
/// 8 bytes (`v_off u16 | v_len u16 | ov_len u32`) — cadeias overflow deixam
/// de estar limitadas a 64 KB. Ficheiros v4 não são migrados: o checkpoint é
/// estado DERIVADO (regenerável do log via from_map), então `deserialize`
/// rejeita versões estranhas com erro claro e o chamador reconstrói.
const VERSION: u16 = 5;
const MAX_SB_FREE_LIST: usize = 32;
const FRAGMENTATION_THRESHOLD: f32 = 0.25;
const OVERFLOW_THRESHOLD: usize = 512;
const HASH_LEN: usize = 28;
const CACHE_MEMORY_BUDGET_BYTES: usize = 64 * 1024 * 1024; // 64MB Cache
const BLOOM_FILTER_SIZE_BYTES: usize = 64; // Filtro de Bloom de 512 bits por página
const SIG_SIZE: usize = 32;
const NUM_SHARDS: usize = 32; // Expandido para 32 shards para alta concorrência multi-core

// Constantes de layout auto-documentadas para offsets físicos da página
const OFF_PAGE_TYPE: usize = 0;
const OFF_VERSION: usize = 1;
const OFF_GENERATION: usize = 3;
const OFF_LSN: usize = 11;
const OFF_SLOT_COUNT: usize = 19;
const OFF_FREE_START: usize = 21;
const OFF_PAYLOAD_END: usize = 23;
const OFF_LOW_OFF: usize = 25;
const OFF_LOW_LEN: usize = 27;
const OFF_HIGH_OFF: usize = 29;
const OFF_HIGH_LEN: usize = 31;
const OFF_BLOOM: usize = 33;
// Prefixo comum (compressão por prefixo): ocupa os 4 bytes livres entre o bloom
// (33..97, 512 bits) e o início dos slots (101). Dois u16: offset e comprimento
// do prefixo no payload da página.
const OFF_PFX_OFF: usize = 97;
const OFF_PFX_LEN: usize = 99;
const OFF_SLOTS_START: usize = 101;
const PAYLOAD_END_MAX: usize = PAGE_SIZE - SIG_SIZE;
// Limiar BRANDO de ocupação física por nó: split/flush disparam por bytes
// estimados, não só por contagem. node_cap/buffer_cap por contagem são
// fisicamente impossíveis numa página de 4 KB com chaves/valores reais
// (128 chaves × ~56 B ≈ 7 KB) — era a fonte do "Estouro físico da Página"
// no ciclo upsert→commit do from_map (bug M30, btree file-backed).
// 1536 B deixa margem para o pior caso de um cascade (buffer da raiz + folha
// alvo ≈ 2×limiar) caber na página após um único split.
const PAGE_SOFT_BUDGET: usize = 1536;

#[inline]
fn read_u16(slice: &[u8], offset: usize) -> io::Result<u16> {
    if offset.checked_add(2).is_none_or(|end| end > slice.len()) {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Leitura fora dos limites do buffer (u16)",
        ));
    }
    Ok(u16::from_le_bytes([slice[offset], slice[offset + 1]]))
}

#[inline]
fn read_u32(slice: &[u8], offset: usize) -> io::Result<u32> {
    if offset.checked_add(4).is_none_or(|end| end > slice.len()) {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Leitura fora dos limites do buffer (u32)",
        ));
    }
    Ok(u32::from_le_bytes([
        slice[offset],
        slice[offset + 1],
        slice[offset + 2],
        slice[offset + 3],
    ]))
}

#[inline]
fn read_u64(slice: &[u8], offset: usize) -> io::Result<u64> {
    if offset.checked_add(8).is_none_or(|end| end > slice.len()) {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Leitura fora dos limites do buffer (u64)",
        ));
    }
    Ok(u64::from_le_bytes([
        slice[offset],
        slice[offset + 1],
        slice[offset + 2],
        slice[offset + 3],
        slice[offset + 4],
        slice[offset + 5],
        slice[offset + 6],
        slice[offset + 7],
    ]))
}

#[inline]
fn safe_slice(data: &[u8], start: usize, len: usize) -> io::Result<&[u8]> {
    let end = start.checked_add(len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Estouro de offset aritmético")
    })?;
    if end > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Tentativa de fatiamento fora dos limites da página física",
        ));
    }
    Ok(&data[start..end])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BloomFilter {
    pub bits: [u8; BLOOM_FILTER_SIZE_BYTES],
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self {
            bits: [0u8; BLOOM_FILTER_SIZE_BYTES],
        }
    }
}

impl BloomFilter {
    pub fn clear(&mut self) {
        self.bits = [0u8; BLOOM_FILTER_SIZE_BYTES];
    }

    pub fn insert(&mut self, key: &[u8]) {
        let hash = blake3::hash(key);
        let bytes = hash.as_bytes();
        let mut pos = 0;
        for _ in 0..4 {
            let mut component = [0u8; 8];
            component.copy_from_slice(&bytes[pos..pos + 8]);
            let bit_idx = (u64::from_le_bytes(component) % 512) as usize;
            let byte_pos = bit_idx / 8;
            let bit_pos = bit_idx % 8;
            self.bits[byte_pos] |= 1 << bit_pos;
            pos += 8;
        }
    }

    pub fn contains(&self, key: &[u8]) -> bool {
        let hash = blake3::hash(key);
        let bytes = hash.as_bytes();
        let mut pos = 0;
        for _ in 0..4 {
            let mut component = [0u8; 8];
            component.copy_from_slice(&bytes[pos..pos + 8]);
            let bit_idx = (u64::from_le_bytes(component) % 512) as usize;
            let byte_pos = bit_idx / 8;
            let bit_pos = bit_idx % 8;
            if (self.bits[byte_pos] & (1 << bit_pos)) == 0 {
                return false;
            }
            pos += 8;
        }
        true
    }
}

#[derive(Debug, Default)]
pub struct TreeMetrics {
    pub cache_hits: AtomicUsize,
    pub cache_misses: AtomicUsize,
    pub write_amplification_count: AtomicUsize,
    pub read_amplification_count: AtomicUsize,
    pub active_snapshots: AtomicUsize,
    pub bloom_hits: AtomicUsize,
    pub bloom_misses: AtomicUsize,
    pub versions_pruned: AtomicUsize,
}

pub trait PageStore: Send + Sync {
    fn read_page(&self, page_id: u64, buf: &mut [u8]) -> io::Result<()>;
    fn write_page(&self, page_id: u64, buf: &[u8]) -> io::Result<()>;
    fn sync(&self) -> io::Result<()>;
    fn total_pages(&self) -> io::Result<u64>;
}

pub struct FilePageStore {
    file: std::sync::Mutex<File>,
}

impl FilePageStore {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        // truncate(false) explícito: abrir um page store existente NUNCA o
        // apaga (as páginas são a verdade); só cria se não existir.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        Ok(Self {
            file: std::sync::Mutex::new(file),
        })
    }
}

impl PageStore for FilePageStore {
    fn read_page(&self, page_id: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut f = self
            .file
            .lock()
            .map_err(|_| io::Error::other("Lock envenenado"))?;
        let offset = page_id.checked_mul(PAGE_SIZE as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Estouro aritmético no ID da página lida",
            )
        })?;
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(buf)
    }
    fn write_page(&self, page_id: u64, buf: &[u8]) -> io::Result<()> {
        let mut f = self
            .file
            .lock()
            .map_err(|_| io::Error::other("Lock envenenado"))?;
        let offset = page_id.checked_mul(PAGE_SIZE as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Estouro aritmético no ID da página escrita",
            )
        })?;
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(buf)
    }
    fn sync(&self) -> io::Result<()> {
        let f = self
            .file
            .lock()
            .map_err(|_| io::Error::other("Lock envenenado"))?;
        f.sync_all()
    }
    fn total_pages(&self) -> io::Result<u64> {
        let f = self
            .file
            .lock()
            .map_err(|_| io::Error::other("Lock envenenado"))?;
        Ok(f.metadata()?.len() / PAGE_SIZE as u64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageType {
    Superblock = 0,
    Internal = 1,
    Leaf = 2,
    Overflow = 3,
    FreeList = 4,
}

pub const FLAG_ACTIVE: u16 = 0x01;
pub const FLAG_GHOST: u16 = 0x02;
pub const FLAG_OVERFLOW: u16 = 0x04;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Slot {
    pub offset: u16,
    /// Para slots overflow: comprimento REAL da cadeia (u32 desde o layout v5
    /// — valores deixam de estar limitados a 64 KB). Para inline: len do valor.
    pub length: u32,
    pub flags: u16,
    pub overflow_page: u64,
    pub cumulative_hash: [u8; HASH_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    Upsert(Val, u64),
    Delete(u64),
}

impl Msg {
    pub fn lsn(&self) -> u64 {
        match self {
            Msg::Upsert(_, lsn) | Msg::Delete(lsn) => *lsn,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Superblock {
    pub magic: [u8; 4],
    pub version: u16,
    pub generation: u64,
    pub root_id: u64,
    pub next_page_id: u64,
    pub free_list_head: u64,
    pub free_list_len: u32,
    pub free_list: [u64; MAX_SB_FREE_LIST],
}

impl Superblock {
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; PAGE_SIZE];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..14].copy_from_slice(&self.generation.to_le_bytes());
        buf[14..22].copy_from_slice(&self.root_id.to_le_bytes());
        buf[22..30].copy_from_slice(&self.next_page_id.to_le_bytes());
        buf[30..38].copy_from_slice(&self.free_list_head.to_le_bytes());
        buf[38..42].copy_from_slice(&self.free_list_len.to_le_bytes());
        let mut pos = 42;
        for i in 0..MAX_SB_FREE_LIST {
            buf[pos..pos + 8].copy_from_slice(&self.free_list[i].to_le_bytes());
            pos += 8;
        }
        let (data, sig) = buf.split_at_mut(PAGE_SIZE - 32);
        let crc = crc32fast::hash(data);
        let hash = blake3::hash(data);
        sig[0..4].copy_from_slice(&crc.to_le_bytes());
        sig[4..32].copy_from_slice(&hash.as_bytes()[..28]);
        Ok(buf)
    }

    pub fn deserialize(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < PAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Superbloco curto",
            ));
        }
        let (data, sig) = buf.split_at(PAGE_SIZE - 32);
        let crc = read_u32(sig, 0)?;
        if crc32fast::hash(data) != crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Falha CRC32C SB",
            ));
        }
        if blake3::hash(data).as_bytes()[..HASH_LEN] != sig[4..32] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Falha Blake3 SB",
            ));
        }
        if data[0..4] != *MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Mágica inválida SB",
            ));
        }

        let version = read_u16(data, 4)?;
        let generation = read_u64(data, 6)?;
        let root_id = read_u64(data, 14)?;
        let next_page_id = read_u64(data, 22)?;
        let free_list_head = read_u64(data, 30)?;
        let free_list_len = read_u32(data, 38)?;
        let mut free_list = [0u64; MAX_SB_FREE_LIST];
        let mut pos = 42;
        for slot in free_list.iter_mut() {
            *slot = read_u64(data, pos)?;
            pos += 8;
        }
        Ok(Superblock {
            magic: *MAGIC,
            version,
            generation,
            root_id,
            next_page_id,
            free_list_head,
            free_list_len,
            free_list,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageHeader {
    pub page_type: u8,
    pub version: u16,
    pub generation: u64,
    pub lsn: u64,
    pub slot_count: u16,
    pub free_start: u16,
    pub payload_end: u16,
}

#[derive(Clone, Debug)]
pub struct DiskNode {
    pub id: u64,
    pub header: PageHeader,
    pub low_key: Option<Key>,
    pub high_key: Option<Key>,
    pub slots: Vec<Slot>,
    pub keys: Vec<Key>,
    pub vals: Vec<Val>,
    pub children: Vec<u64>,
    pub buffer: BTreeMap<Key, Vec<Msg>>,
    pub bloom: BloomFilter,
}

impl DiskNode {
    pub fn calculate_fragmentation_ratio(&self) -> f32 {
        let mut active_bytes = 0usize;
        for (i, slot) in self.slots.iter().enumerate() {
            if (slot.flags & FLAG_GHOST) == 0 && (slot.flags & FLAG_ACTIVE) != 0 {
                active_bytes += self.keys[i].len();
                if self.header.page_type == PageType::Leaf as u8 {
                    active_bytes += slot.length as usize;
                }
            }
        }
        let total_payload_bytes =
            (self.header.payload_end as usize).saturating_sub(OFF_SLOTS_START);
        if total_payload_bytes == 0 {
            return 0.0;
        }
        let dead_bytes = total_payload_bytes.saturating_sub(active_bytes);
        dead_bytes as f32 / total_payload_bytes as f32
    }

    pub fn compact_and_defragment(&mut self) -> io::Result<()> {
        let mut clean_keys = Vec::new();
        let mut clean_vals = Vec::new();
        let mut clean_slots = Vec::new();
        for (i, slot) in self.slots.iter().enumerate() {
            if (slot.flags & FLAG_GHOST) == 0 && (slot.flags & FLAG_ACTIVE) != 0 {
                clean_keys.push(self.keys[i].clone());
                if self.header.page_type == PageType::Leaf as u8 {
                    clean_vals.push(self.vals[i].clone());
                }
                let mut sanitized_slot = *slot;
                sanitized_slot.offset = 0;
                clean_slots.push(sanitized_slot);
            }
        }
        self.keys = clean_keys;
        self.vals = clean_vals;
        self.slots = clean_slots;
        self.header.slot_count = self.slots.len() as u16;
        Ok(())
    }

    pub fn rebuild_bloom_filter(&mut self) {
        self.bloom.clear();
        for key in &self.keys {
            self.bloom.insert(key);
        }
        for key in self.buffer.keys() {
            self.bloom.insert(key);
        }
    }

    pub fn estimate_memory_footprint(&self) -> usize {
        let mut size = std::mem::size_of::<Self>();
        size += self.slots.len() * std::mem::size_of::<Slot>();
        size += self.children.len() * 8;
        size += std::mem::size_of::<std::sync::RwLock<Self>>(); // Inclusão do overhead do lock do cache
        size += 32; // Overhead base estimado para alocações de nós de BTreeMap internos
        for k in &self.keys {
            size += k.len().checked_add(8).unwrap_or(k.len());
        }
        for v in &self.vals {
            size += v.len().checked_add(8).unwrap_or(v.len());
        }
        for (k, v_list) in &self.buffer {
            size += k.len().checked_add(16).unwrap_or(k.len());
            for msg in v_list {
                size += std::mem::size_of::<Msg>();
                if let Msg::Upsert(val, _) = msg {
                    size += val.len().checked_add(8).unwrap_or(val.len());
                }
            }
        }
        size
    }

    fn calculate_common_prefix(&self) -> Vec<u8> {
        if self.keys.is_empty() {
            return Vec::new();
        }
        let first = &self.keys[0];
        let mut prefix_len = first.len();
        for key in self.keys.iter().skip(1) {
            let match_len = key
                .iter()
                .zip(first.iter())
                .take_while(|(a, b)| a == b)
                .count();
            prefix_len = prefix_len.min(match_len);
            if prefix_len == 0 {
                break;
            }
        }
        first[..prefix_len].to_vec()
    }

    /// Estimativa (majorante) dos bytes que `serialize` vai ocupar — espelha o
    /// modelo de custo do serializador, sem descontar a compressão por prefixo.
    /// É o gatilho byte-aware de split/flush (ver `PAGE_SOFT_BUDGET`).
    pub fn estimate_serialized_size(&self) -> usize {
        let mut size = OFF_SLOTS_START + SIG_SIZE;
        size += self.low_key.as_ref().map_or(0, |k| k.len());
        size += self.high_key.as_ref().map_or(0, |k| k.len());
        for (i, k) in self.keys.iter().enumerate() {
            size += 42 + k.len();
            if self.header.page_type == PageType::Leaf as u8 {
                // Slots overflow não inline-izam o valor (só a cadeia externa).
                let inline = self
                    .slots
                    .get(i)
                    .is_none_or(|s| (s.flags & FLAG_OVERFLOW) == 0);
                size += 8 + if inline {
                    self.vals.get(i).map_or(0, |v| v.len())
                } else {
                    0
                };
            }
        }
        if self.header.page_type == PageType::Internal as u8 {
            size += self.children.len() * 8 + 4;
            for (k, msgs) in &self.buffer {
                size += 8 + k.len();
                for m in msgs {
                    size += match m {
                        Msg::Upsert(v, _) => 13 + v.len(),
                        Msg::Delete(_) => 9,
                    };
                }
            }
        }
        size
    }

    /// Ponto de split balanceado por BYTES (não por contagem): com valores de
    /// tamanho variável, o meio por contagem pode deixar uma metade ainda acima
    /// do orçamento físico. Devolve um índice em 1..len-1.
    fn byte_balanced_mid(&self) -> usize {
        let n = self.keys.len();
        if n < 2 {
            return n / 2;
        }
        let cost =
            |i: usize| 50 + self.keys[i].len() + self.vals.get(i).map_or(0, |v: &Val| v.len());
        let total: usize = (0..n).map(cost).sum();
        let mut acc = 0usize;
        for i in 0..n {
            acc += cost(i);
            if acc * 2 >= total {
                return (i + 1).clamp(1, n - 1);
            }
        }
        n / 2
    }

    // Decomposição modular da serialização em sub-rotinas limpas
    fn serialize_header(&self, buf: &mut [u8]) {
        buf[OFF_PAGE_TYPE] = self.header.page_type;
        buf[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&self.header.version.to_le_bytes());
        buf[OFF_GENERATION..OFF_GENERATION + 8]
            .copy_from_slice(&self.header.generation.to_le_bytes());
        buf[OFF_LSN..OFF_LSN + 8].copy_from_slice(&self.header.lsn.to_le_bytes());
        buf[OFF_SLOT_COUNT..OFF_SLOT_COUNT + 2]
            .copy_from_slice(&(self.keys.len() as u16).to_le_bytes());
        buf[OFF_BLOOM..OFF_BLOOM + BLOOM_FILTER_SIZE_BYTES].copy_from_slice(&self.bloom.bits);
    }

    fn serialize_slots_and_payload(
        &self,
        buf: &mut [u8],
        prefix: &[u8],
        slot_pos: &mut usize,
        payload_pos: &mut usize,
    ) -> io::Result<()> {
        for (i, k) in self.keys.iter().enumerate() {
            if *slot_pos + 42 > *payload_pos {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Estouro físico da Página",
                ));
            }
            let suffix = &k[prefix.len()..];

            if suffix.len() > *payload_pos || *payload_pos - suffix.len() < *slot_pos {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Estouro físico da Página",
                ));
            }
            *payload_pos -= suffix.len();
            buf[*payload_pos..*payload_pos + suffix.len()].copy_from_slice(suffix);
            let k_off = *payload_pos as u16;
            let k_len = suffix.len() as u16;

            let flags = self.slots.get(i).map(|s| s.flags).unwrap_or(FLAG_ACTIVE);
            let ov_id = self.slots.get(i).map(|s| s.overflow_page).unwrap_or(0);
            let cum_hash = self
                .slots
                .get(i)
                .map(|s| s.cumulative_hash)
                .unwrap_or([0; HASH_LEN]);

            buf[*slot_pos..*slot_pos + 2].copy_from_slice(&k_off.to_le_bytes());
            buf[*slot_pos + 2..*slot_pos + 4].copy_from_slice(&k_len.to_le_bytes());
            buf[*slot_pos + 4..*slot_pos + 6].copy_from_slice(&flags.to_le_bytes());
            buf[*slot_pos + 6..*slot_pos + 14].copy_from_slice(&ov_id.to_le_bytes());
            buf[*slot_pos + 14..*slot_pos + 42].copy_from_slice(&cum_hash);
            *slot_pos += 42;

            if self.header.page_type == PageType::Leaf as u8 {
                if *slot_pos + 8 > *payload_pos {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Estouro físico da Página",
                    ));
                }
                // Valor em overflow vive na cadeia externa (FLAG_OVERFLOW):
                // inline-izá-lo também, como antes, estourava a página para
                // qualquer valor grande. get() lê a cadeia quando a flag está on.
                let v: &[u8] = if (flags & FLAG_OVERFLOW) != 0 {
                    &[]
                } else {
                    &self.vals[i]
                };
                if v.len() > *payload_pos || *payload_pos - v.len() < *slot_pos {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Estouro físico da Página",
                    ));
                }
                *payload_pos -= v.len();
                buf[*payload_pos..*payload_pos + v.len()].copy_from_slice(v);
                let v_off = *payload_pos as u16;
                let v_len = v.len() as u16;

                buf[*slot_pos..*slot_pos + 2].copy_from_slice(&v_off.to_le_bytes());
                buf[*slot_pos + 2..*slot_pos + 4].copy_from_slice(&v_len.to_le_bytes());
                // ov_len (u32, layout v5): comprimento REAL da cadeia overflow
                // (slot.length). Sem persisti-lo, um get() pós-reopen validava
                // a cadeia contra o comprimento errado; em u16 (v4) as cadeias
                // ficavam limitadas a 64 KB.
                let ov_len: u32 = if (flags & FLAG_OVERFLOW) != 0 {
                    self.slots.get(i).map(|s| s.length).unwrap_or(0)
                } else {
                    0
                };
                buf[*slot_pos + 4..*slot_pos + 8].copy_from_slice(&ov_len.to_le_bytes());
                *slot_pos += 8;
            }
        }
        Ok(())
    }

    fn serialize_children_and_buffer(
        &self,
        buf: &mut [u8],
        prefix: &[u8],
        slot_pos: &mut usize,
        payload_pos: &mut usize,
    ) -> io::Result<()> {
        if self.header.page_type == PageType::Internal as u8 {
            for &child in &self.children {
                if *slot_pos + 8 > *payload_pos {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Estouro físico da Página",
                    ));
                }
                buf[*slot_pos..*slot_pos + 8].copy_from_slice(&child.to_le_bytes());
                *slot_pos += 8;
            }
            if *slot_pos + 4 > *payload_pos {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Estouro físico da Página",
                ));
            }
            buf[*slot_pos..*slot_pos + 4]
                .copy_from_slice(&(self.buffer.len() as u32).to_le_bytes());
            *slot_pos += 4;
            for (bk, msg_vec) in &self.buffer {
                let bk_suffix = if bk.starts_with(prefix) {
                    &bk[prefix.len()..]
                } else {
                    bk.as_slice()
                };
                if bk_suffix.len() > *payload_pos || *payload_pos - bk_suffix.len() < *slot_pos {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Estouro físico da Página",
                    ));
                }
                *payload_pos -= bk_suffix.len();
                buf[*payload_pos..*payload_pos + bk_suffix.len()].copy_from_slice(bk_suffix);
                let bk_off = *payload_pos as u16;
                let bk_len = bk_suffix.len() as u16;

                buf[*slot_pos..*slot_pos + 2].copy_from_slice(&bk_off.to_le_bytes());
                buf[*slot_pos + 2..*slot_pos + 4].copy_from_slice(&bk_len.to_le_bytes());
                *slot_pos += 4;

                buf[*slot_pos..*slot_pos + 4]
                    .copy_from_slice(&(msg_vec.len() as u32).to_le_bytes());
                *slot_pos += 4;
                for msg in msg_vec {
                    match msg {
                        Msg::Upsert(v, lsn) => {
                            if *slot_pos + 13 > *payload_pos {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "Estouro físico da Página",
                                ));
                            }
                            buf[*slot_pos] = 1;
                            *slot_pos += 1;
                            buf[*slot_pos..*slot_pos + 8].copy_from_slice(&lsn.to_le_bytes());
                            *slot_pos += 8;
                            if v.len() > *payload_pos || *payload_pos - v.len() < *slot_pos {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "Estouro físico da Página",
                                ));
                            }
                            *payload_pos -= v.len();
                            buf[*payload_pos..*payload_pos + v.len()].copy_from_slice(v);
                            let v_off = *payload_pos as u16;
                            let v_len = v.len() as u16;

                            buf[*slot_pos..*slot_pos + 2].copy_from_slice(&v_off.to_le_bytes());
                            buf[*slot_pos + 2..*slot_pos + 4].copy_from_slice(&v_len.to_le_bytes());
                            *slot_pos += 4;
                        }
                        Msg::Delete(lsn) => {
                            if *slot_pos + 9 > *payload_pos {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "Estouro físico da Página",
                                ));
                            }
                            buf[*slot_pos] = 0;
                            *slot_pos += 1;
                            buf[*slot_pos..*slot_pos + 8].copy_from_slice(&lsn.to_le_bytes());
                            *slot_pos += 8;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; PAGE_SIZE];
        self.serialize_header(&mut buf);

        let mut slot_pos = OFF_SLOTS_START;
        let mut payload_pos = PAYLOAD_END_MAX;
        let write_payload = |b: &mut [u8], item: &[u8], p: &mut usize| -> io::Result<(u16, u16)> {
            if item.len() > *p || *p - item.len() < slot_pos {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Estouro físico da Página",
                ));
            }
            *p -= item.len();
            b[*p..*p + item.len()].copy_from_slice(item);
            Ok((*p as u16, item.len() as u16))
        };

        let low_meta = match &self.low_key {
            Some(lk) => write_payload(&mut buf, lk, &mut payload_pos)?,
            None => (0, 0),
        };
        let high_meta = match &self.high_key {
            Some(hk) => write_payload(&mut buf, hk, &mut payload_pos)?,
            None => (0, 0),
        };

        buf[OFF_LOW_OFF..OFF_LOW_OFF + 2].copy_from_slice(&low_meta.0.to_le_bytes());
        buf[OFF_LOW_LEN..OFF_LOW_LEN + 2].copy_from_slice(&low_meta.1.to_le_bytes());
        buf[OFF_HIGH_OFF..OFF_HIGH_OFF + 2].copy_from_slice(&high_meta.0.to_le_bytes());
        buf[OFF_HIGH_LEN..OFF_HIGH_LEN + 2].copy_from_slice(&high_meta.1.to_le_bytes());

        let prefix = self.calculate_common_prefix();
        let (pfx_off, pfx_len) = write_payload(&mut buf, &prefix, &mut payload_pos)?;
        buf[OFF_PFX_OFF..OFF_PFX_OFF + 2].copy_from_slice(&pfx_off.to_le_bytes());
        buf[OFF_PFX_LEN..OFF_PFX_LEN + 2].copy_from_slice(&pfx_len.to_le_bytes());

        self.serialize_slots_and_payload(&mut buf, &prefix, &mut slot_pos, &mut payload_pos)?;
        self.serialize_children_and_buffer(&mut buf, &prefix, &mut slot_pos, &mut payload_pos)?;

        buf[OFF_FREE_START..OFF_FREE_START + 2].copy_from_slice(&(slot_pos as u16).to_le_bytes());
        buf[OFF_PAYLOAD_END..OFF_PAYLOAD_END + 2]
            .copy_from_slice(&(payload_pos as u16).to_le_bytes());

        let (data, sig) = buf.split_at_mut(PAGE_SIZE - 32);
        let crc = crc32fast::hash(data);
        let hash = blake3::hash(data);
        sig[0..4].copy_from_slice(&crc.to_le_bytes());
        sig[4..32].copy_from_slice(&hash.as_bytes()[..28]);
        Ok(buf)
    }

    pub fn deserialize(id: u64, buf: &[u8]) -> io::Result<Self> {
        let (data, sig) = buf.split_at(PAGE_SIZE - 32);
        if crc32fast::hash(data) != read_u32(sig, 0)? {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "CRC Falhou"));
        }
        if blake3::hash(data).as_bytes()[..HASH_LEN] != sig[4..32] {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Blake3 Falhou"));
        }
        let page_type = data[OFF_PAGE_TYPE];
        let version = read_u16(data, OFF_VERSION)?;
        // O layout físico muda entre versões (v5: slot de valor 8B). O
        // checkpoint é estado DERIVADO: uma versão estranha rejeita-se com
        // erro claro e o chamador reconstrói do log (from_map/replay).
        if version != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("layout de página v{version} incompatível (esperado v{VERSION}); reconstruir o checkpoint do log"),
            ));
        }
        let generation = read_u64(data, OFF_GENERATION)?;
        let lsn = read_u64(data, OFF_LSN)?;
        let slot_count = read_u16(data, OFF_SLOT_COUNT)? as usize;

        let free_start = read_u16(data, OFF_FREE_START)? as usize;
        let payload_end = read_u16(data, OFF_PAYLOAD_END)? as usize;
        if free_start > payload_end || payload_end > PAYLOAD_END_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Offsets estruturais da página física corrompidos ou sobrepostos",
            ));
        }

        let step = if page_type == PageType::Leaf as u8 {
            50
        } else {
            42
        };
        let slots_size = slot_count.checked_mul(step).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Slot count inválido ou corrompido",
            )
        })?;
        if OFF_SLOTS_START
            .checked_add(slots_size)
            .is_none_or(|end| end > PAGE_SIZE)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Slot count transborda o espaço livre físico da página",
            ));
        }

        let pfx_off = read_u16(data, OFF_PFX_OFF)? as usize;
        let pfx_len = read_u16(data, OFF_PFX_LEN)? as usize;
        let prefix = if pfx_len > 0 {
            safe_slice(data, pfx_off, pfx_len)?.to_vec()
        } else {
            Vec::new()
        };

        let low_off = read_u16(data, OFF_LOW_OFF)? as usize;
        let low_len = read_u16(data, OFF_LOW_LEN)? as usize;
        let low_key = if low_len > 0 {
            Some(safe_slice(data, low_off, low_len)?.to_vec())
        } else {
            None
        };
        let high_off = read_u16(data, OFF_HIGH_OFF)? as usize;
        let high_len = read_u16(data, OFF_HIGH_LEN)? as usize;
        let high_key = if high_len > 0 {
            Some(safe_slice(data, high_off, high_len)?.to_vec())
        } else {
            None
        };

        let mut bloom = BloomFilter::default();
        bloom
            .bits
            .copy_from_slice(safe_slice(data, OFF_BLOOM, BLOOM_FILTER_SIZE_BYTES)?);

        let mut pos = OFF_SLOTS_START;
        let mut keys = Vec::with_capacity(slot_count);
        let mut vals = Vec::new();
        let mut slots = Vec::with_capacity(slot_count);
        let mut children = Vec::new();
        let mut buffer = BTreeMap::new();

        // Payloads crescem para baixo a partir de PAYLOAD_END_MAX, logo os offsets
        // dos sufixos de chave são NÃO-CRESCENTES entre slots consecutivos. Um
        // offset maior que o anterior denuncia corrupção/sobreposição física.
        let mut last_offset = usize::MAX;
        for _ in 0..slot_count {
            let suf_off = read_u16(data, pos)? as usize;
            let suf_len = read_u16(data, pos + 2)? as usize;
            let flags = read_u16(data, pos + 4)?;
            let overflow_page = read_u64(data, pos + 6)?;
            let mut cumulative_hash = [0u8; HASH_LEN];
            cumulative_hash.copy_from_slice(safe_slice(data, pos + 14, HASH_LEN)?);
            pos += 42;

            if last_offset != usize::MAX && suf_off > last_offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Inconsistência de ordenação ou sobreposição física detectada nos slots",
                ));
            }
            last_offset = suf_off;

            let mut full_key = prefix.clone();
            full_key.extend_from_slice(safe_slice(data, suf_off, suf_len)?);

            keys.push(full_key);
            slots.push(Slot {
                offset: suf_off as u16,
                length: suf_len as u32,
                flags,
                overflow_page,
                cumulative_hash,
            });
            if page_type == PageType::Leaf as u8 {
                let v_off = read_u16(data, pos)? as usize;
                let v_len = read_u16(data, pos + 2)? as usize;
                let ov_len = read_u32(data, pos + 4)?;
                pos += 8;
                vals.push(safe_slice(data, v_off, v_len)?.to_vec());
                // Restaura o comprimento real: cadeia overflow (u32, v5) ou o
                // len do valor inline — para a validação do get() pós-reopen.
                if let Some(s) = slots.last_mut() {
                    s.length = if (flags & FLAG_OVERFLOW) != 0 {
                        ov_len
                    } else {
                        v_len as u32
                    };
                }
            }
        }
        if page_type == PageType::Internal as u8 {
            for _ in 0..=slot_count {
                children.push(read_u64(data, pos)?);
                pos += 8;
            }
            let buf_count = read_u32(data, pos)? as usize;
            pos += 4;
            for _ in 0..buf_count {
                let suf_off = read_u16(data, pos)? as usize;
                let suf_len = read_u16(data, pos + 2)? as usize;
                pos += 4;

                let mut full_bk = prefix.clone();
                full_bk.extend_from_slice(safe_slice(data, suf_off, suf_len)?);

                let version_count = read_u32(data, pos)? as usize;
                pos += 4;
                // Pré-alocação LIMITADA pelos bytes restantes (cada versão ocupa
                // ≥ 9 bytes): um u32 corrompido no disco não pode pedir GiBs de
                // capacidade — o loop abaixo falha com `?` no primeiro read.
                let bound = data.len().saturating_sub(pos) / 9;
                let mut msg_vec = Vec::with_capacity(version_count.min(bound));
                for _ in 0..version_count {
                    let m_type = *data.get(pos).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "m_type fora dos limites da página física",
                        )
                    })?;
                    pos += 1;
                    let m_lsn = read_u64(data, pos)?;
                    pos += 8;
                    let msg = if m_type == 1 {
                        let v_off = read_u16(data, pos)? as usize;
                        let v_len = read_u16(data, pos + 2)? as usize;
                        pos += 4;
                        Msg::Upsert(safe_slice(data, v_off, v_len)?.to_vec(), m_lsn)
                    } else {
                        Msg::Delete(m_lsn)
                    };
                    msg_vec.push(msg);
                }
                buffer.insert(full_bk, msg_vec);
            }
        }
        let header = PageHeader {
            page_type,
            version,
            generation,
            lsn,
            slot_count: slot_count as u16,
            free_start: free_start as u16,
            payload_end: payload_end as u16,
        };
        Ok(DiskNode {
            id,
            header,
            low_key,
            high_key,
            slots,
            keys,
            vals,
            children,
            buffer,
            bloom,
        })
    }

    pub fn is_leaf(&self) -> bool {
        self.header.page_type == PageType::Leaf as u8
    }
}

pub struct CacheFrame {
    pub node: Arc<std::sync::RwLock<DiskNode>>,
    pub pin_count: Arc<AtomicUsize>,
    pub last_access: AtomicU64,
    pub byte_size: usize,
    pub is_dirty: std::sync::atomic::AtomicBool,
}

pub struct PageGuard {
    pub id: u64,
    pub node: Arc<std::sync::RwLock<DiskNode>>,
    pin_count_ref: Arc<AtomicUsize>,
}

impl Drop for PageGuard {
    fn drop(&mut self) {
        self.pin_count_ref.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct BEpsilonTree {
    store: Arc<dyn PageStore>,
    active_sb_offset: AtomicU64,
    pub superblock: std::sync::RwLock<Superblock>,
    cache_shards: Vec<std::sync::Mutex<HashMap<u64, CacheFrame>>>,
    buffer_cap: usize,
    node_cap: usize,
    global_ticker: AtomicU64,
    pub total_pending_messages: AtomicUsize,
    current_cache_bytes: AtomicUsize,
    allocated_this_epoch: std::sync::Mutex<HashSet<u64>>,
    dirty_page_table: std::sync::Mutex<HashSet<u64>>,
    /// R8: páginas do último estado DURÁVEL substituídas por CoW neste epoch.
    /// Só podem ser tombstonadas/reutilizadas DEPOIS de o próximo `commit`
    /// apontar o superbloco para longe delas — sobrescrevê-las já (como antes)
    /// violava o shadow paging: um crash pré-commit deixava o superbloco
    /// durável a apontar para uma página FreeList (árvore ilegível).
    pending_recycle: std::sync::Mutex<Vec<u64>>,
    pub metrics: Arc<TreeMetrics>,
}

impl BEpsilonTree {
    pub fn open(path: impl AsRef<Path>, buffer_cap: usize, node_cap: usize) -> io::Result<Self> {
        let store = Arc::new(FilePageStore::open(path)?);
        let total = store.total_pages()?;
        let metrics = Arc::new(TreeMetrics::default());

        let mut cache_shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            cache_shards.push(std::sync::Mutex::new(HashMap::new()));
        }

        if total == 0 {
            let sb = Superblock {
                magic: *MAGIC,
                version: VERSION,
                generation: 1,
                root_id: 2,
                next_page_id: 3,
                free_list_head: 0,
                free_list_len: 0,
                free_list: [0; MAX_SB_FREE_LIST],
            };
            let header = PageHeader {
                page_type: PageType::Leaf as u8,
                version: VERSION,
                generation: 1,
                lsn: 0,
                slot_count: 0,
                free_start: 101,
                payload_end: 4064,
            };
            let root = DiskNode {
                id: 2,
                header,
                low_key: None,
                high_key: None,
                slots: Vec::new(),
                keys: Vec::new(),
                vals: Vec::new(),
                children: Vec::new(),
                buffer: BTreeMap::new(),
                bloom: BloomFilter::default(),
            };
            store.write_page(0, &sb.serialize()?)?;
            store.write_page(2, &root.serialize()?)?;
            store.sync()?;

            let tree = BEpsilonTree {
                store,
                active_sb_offset: AtomicU64::new(0),
                superblock: std::sync::RwLock::new(sb),
                cache_shards,
                buffer_cap,
                node_cap,
                global_ticker: AtomicU64::new(0),
                total_pending_messages: AtomicUsize::new(0),
                current_cache_bytes: AtomicUsize::new(0),
                allocated_this_epoch: std::sync::Mutex::new(HashSet::new()),
                dirty_page_table: std::sync::Mutex::new(HashSet::new()),
                pending_recycle: std::sync::Mutex::new(Vec::new()),
                metrics,
            };
            let size = root.estimate_memory_footprint();
            {
                let shard_idx = (2u64 % NUM_SHARDS as u64) as usize;
                let mut c = tree.cache_shards[shard_idx].lock().unwrap();
                c.insert(
                    2,
                    CacheFrame {
                        node: Arc::new(std::sync::RwLock::new(root)),
                        pin_count: Arc::new(AtomicUsize::new(0)),
                        last_access: AtomicU64::new(0),
                        byte_size: size,
                        is_dirty: std::sync::atomic::AtomicBool::new(false),
                    },
                );
                tree.current_cache_bytes.store(size, Ordering::Relaxed);
            }
            return Ok(tree);
        }
        let mut sb0 = vec![0u8; PAGE_SIZE];
        let mut sb1 = vec![0u8; PAGE_SIZE];
        store.read_page(0, &mut sb0)?;
        store.read_page(1, &mut sb1)?;
        let s0 = Superblock::deserialize(&sb0);
        let s1 = Superblock::deserialize(&sb1);
        let (sb, offset) = match (s0, s1) {
            (Ok(a), Ok(b)) => {
                if a.generation >= b.generation {
                    (a, 0)
                } else {
                    (b, PAGE_SIZE as u64)
                }
            }
            (Ok(a), Err(_)) => (a, 0),
            (Err(_), Ok(b)) => (b, PAGE_SIZE as u64),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Superblocos falharam",
                ))
            }
        };
        Ok(BEpsilonTree {
            store,
            active_sb_offset: AtomicU64::new(offset),
            superblock: std::sync::RwLock::new(sb),
            cache_shards,
            buffer_cap,
            node_cap,
            global_ticker: AtomicU64::new(0),
            total_pending_messages: AtomicUsize::new(0),
            current_cache_bytes: AtomicUsize::new(0),
            allocated_this_epoch: std::sync::Mutex::new(HashSet::new()),
            dirty_page_table: std::sync::Mutex::new(HashSet::new()),
            pending_recycle: std::sync::Mutex::new(Vec::new()),
            metrics,
        })
    }

    /// Materializa EXATAMENTE `map` em `path` — é um snapshot de estado, não um
    /// delta. Abrir a árvore existente e só fazer upsert (como antes) deixava lá
    /// as chaves que já não estão no mapa: um `POST /hvm/checkpoint` depois de um
    /// `hvm/delete` RESSUSCITAVA o registo apagado no checkpoint durável,
    /// respondendo `{"ok":true}`. O ficheiro anterior é descartado para o estado
    /// resultante ser função só do mapa recebido.
    pub fn from_map(path: &Path, map: BTreeMap<Key, Val>) -> io::Result<Self> {
        let tmp_path = path.with_extension("tmp");
        if tmp_path.exists() {
            std::fs::remove_file(&tmp_path)?;
        }
        let mut t = Self::open(&tmp_path, 1000, 128)?;
        for (k, v) in map {
            t.upsert(k, v)?;
        }
        t.commit()?;
        // Fechar para permitir o rename em Windows
        drop(t);
        std::fs::rename(&tmp_path, path)?;

        // Sync do diretório pai: sem isto o `rename` pode não sobreviver a uma
        // falha de energia e o checkpoint volta a apontar para o ficheiro antigo
        // (ou para nenhum). O erro é PROPAGADO — engoli-lo com `let _ =` fazia a
        // função reportar sucesso sobre uma barreira que não aconteceu, que é a
        // mesma classe de mentira que o `read_at` cometia. Mesmo padrão do
        // `sync_parent_dir` do heraclitus-log. No Windows não há API std
        // equivalente (o rename já é transacional no NTFS via MoveFileEx).
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            std::fs::OpenOptions::new()
                .read(true)
                .open(parent)?
                .sync_all()?;
        }

        Self::open(path, 1000, 128)
    }

    /// Checkpoint auto-contido: copia página a página o último estado
    /// COMMITADO do store para `path`. O shadow paging garante que o
    /// superbloco durável só referencia páginas já persistidas, por isso a
    /// cópia é um snapshot consistente (estado sujo não commitado fica de
    /// fora — o mesmo que uma reabertura pós-crash veria). Gravar só o
    /// superbloco, como antes, produzia um ficheiro sem as páginas da árvore,
    /// ilegível pelo `load`.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        self.store.sync()?;
        let mut f = File::create(path)?;
        let total = self.store.total_pages()?;
        let mut buf = vec![0u8; PAGE_SIZE];
        for id in 0..total {
            self.store.read_page(id, &mut buf)?;
            f.write_all(&buf)?;
        }
        f.sync_all()
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        Self::open(path, 128, 32)
    }

    fn mark_dirty(&self, id: u64) {
        let shard_idx = ((id ^ (id >> 16)) % NUM_SHARDS as u64) as usize;
        let c = self.cache_shards[shard_idx].lock().unwrap();
        if let Some(frame) = c.get(&id) {
            frame.is_dirty.store(true, Ordering::Release);
            self.dirty_page_table.lock().unwrap().insert(id);
        }
    }

    /// Re-identificação CoW: move o frame de cache de `old_id` para `new_id`,
    /// preservando pins e o estado sujo. O invariante do cache é chave ==
    /// node.id; sem esta migração o novo id ia ao disco ler uma página nunca
    /// escrita (EOF) e o id antigo continuava a servir o nó obsoleto — a causa
    /// do bug M30 do `from_map` (Storage(EOF) no 2.º upsert em ficheiro fresco).
    fn rekey_cache_frame(&self, old_id: u64, new_id: u64) {
        if old_id == new_id {
            return;
        }
        let old_shard = ((old_id ^ (old_id >> 16)) % NUM_SHARDS as u64) as usize;
        let frame = self.cache_shards[old_shard].lock().unwrap().remove(&old_id);
        if let Some(frame) = frame {
            let was_dirty = frame.is_dirty.load(Ordering::Acquire);
            let new_shard = ((new_id ^ (new_id >> 16)) % NUM_SHARDS as u64) as usize;
            self.cache_shards[new_shard]
                .lock()
                .unwrap()
                .insert(new_id, frame);
            let mut dpt = self.dirty_page_table.lock().unwrap();
            dpt.remove(&old_id);
            if was_dirty {
                dpt.insert(new_id);
            }
        }
    }

    /// Remove do cache (e da tabela de sujas) um frame cujo nó deixou de
    /// existir na árvore (ex.: filho absorvido num merge). Sem isto, se o id
    /// fosse reciclado e realocado, o cache serviria o nó morto.
    fn evict_cache_frame(&self, id: u64) {
        let shard_idx = ((id ^ (id >> 16)) % NUM_SHARDS as u64) as usize;
        if let Some(frame) = self.cache_shards[shard_idx].lock().unwrap().remove(&id) {
            self.current_cache_bytes
                .fetch_sub(frame.byte_size, Ordering::Release);
        }
        self.dirty_page_table.lock().unwrap().remove(&id);
    }

    fn acquire_node_guard(&self, id: u64) -> io::Result<PageGuard> {
        let shard_idx = ((id ^ (id >> 16)) % NUM_SHARDS as u64) as usize;
        let tick = self.global_ticker.fetch_add(1, Ordering::Relaxed);
        let root_id = self.superblock.read().unwrap().root_id;

        // Fast path: hit no cache, só o lock do shard alvo.
        {
            let c = self.cache_shards[shard_idx].lock().unwrap();
            if let Some(frame) = c.get(&id) {
                frame.pin_count.fetch_add(1, Ordering::Acquire);
                frame.last_access.store(tick, Ordering::Release);
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(PageGuard {
                    id,
                    node: Arc::clone(&frame.node),
                    pin_count_ref: Arc::clone(&frame.pin_count),
                });
            }
        }
        // R18: a evicção corre SEM o lock do shard alvo. A versão anterior
        // segurava-o e iterava TODOS os shards — auto-deadlock garantido ao
        // chegar ao próprio shard (Mutex std não é reentrante) e lock-ordering
        // cruzado entre threads. Aqui cada shard é trancado transitoriamente,
        // um de cada vez.
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        while self.current_cache_bytes.load(Ordering::Acquire) >= CACHE_MEMORY_BUDGET_BYTES {
            let mut lru_id = None;
            let mut min_tick = u64::MAX;
            let mut target_shard_idx = 0;
            for (s_idx, shard_lock) in self.cache_shards.iter().enumerate() {
                let shard = shard_lock.lock().unwrap();
                for (&cid, frame) in shard.iter() {
                    if frame.pin_count.load(Ordering::Acquire) == 0 && cid != root_id {
                        let acc = frame.last_access.load(Ordering::Acquire);
                        if acc < min_tick && !frame.is_dirty.load(Ordering::Acquire) {
                            min_tick = acc;
                            lru_id = Some(cid);
                            target_shard_idx = s_idx;
                        }
                    }
                }
            }
            if let Some(lid) = lru_id {
                let mut shard = self.cache_shards[target_shard_idx].lock().unwrap();
                // Revalida sob o lock (outra thread pode ter pinado entretanto).
                let evictable = shard
                    .get(&lid)
                    .is_some_and(|f| f.pin_count.load(Ordering::Acquire) == 0);
                if evictable {
                    if let Some(removed) = shard.remove(&lid) {
                        self.current_cache_bytes
                            .fetch_sub(removed.byte_size, Ordering::Release);
                    }
                } else {
                    break; // candidato desapareceu/foi pinado — evita loop
                }
            } else {
                break;
            }
        }

        // Leitura + decode fora de qualquer lock.
        let mut buf = vec![0u8; PAGE_SIZE];
        self.store.read_page(id, &mut buf)?;
        self.metrics
            .read_amplification_count
            .fetch_add(1, Ordering::Relaxed);
        let node = DiskNode::deserialize(id, &buf)?;
        let footprint = node.estimate_memory_footprint();

        let mut c = self.cache_shards[shard_idx].lock().unwrap();
        // Double-check: outra thread pode ter carregado a página entretanto —
        // usa o frame dela (a nossa cópia é descartada) para não duplicar.
        if let Some(frame) = c.get(&id) {
            frame.pin_count.fetch_add(1, Ordering::Acquire);
            frame.last_access.store(tick, Ordering::Release);
            return Ok(PageGuard {
                id,
                node: Arc::clone(&frame.node),
                pin_count_ref: Arc::clone(&frame.pin_count),
            });
        }
        let node_arc = Arc::new(std::sync::RwLock::new(node));
        let pin_counter = Arc::new(AtomicUsize::new(1));
        c.insert(
            id,
            CacheFrame {
                node: Arc::clone(&node_arc),
                pin_count: Arc::clone(&pin_counter),
                last_access: AtomicU64::new(tick),
                byte_size: footprint,
                is_dirty: std::sync::atomic::AtomicBool::new(false),
            },
        );
        self.current_cache_bytes
            .fetch_add(footprint, Ordering::Release);

        Ok(PageGuard {
            id,
            node: node_arc,
            pin_count_ref: pin_counter,
        })
    }

    fn allocate_id(&self) -> io::Result<u64> {
        let mut epoch = self.allocated_this_epoch.lock().unwrap();
        let mut sb = self.superblock.write().unwrap();

        let id = if sb.free_list_len > 0 {
            sb.free_list_len -= 1;
            let slot = sb.free_list_len as usize;
            let r_id = sb.free_list[slot];
            sb.free_list[slot] = 0;
            r_id
        } else if sb.free_list_head > 0 {
            let next_head = sb.free_list_head;
            let mut buf = vec![0u8; PAGE_SIZE];
            self.store.read_page(next_head, &mut buf)?;
            self.metrics
                .read_amplification_count
                .fetch_add(1, Ordering::Relaxed);

            sb.free_list_head = read_u64(&buf, 1)?;
            let count = read_u16(&buf, 9)? as usize;
            let mut pos = 11;
            for i in 0..count.min(MAX_SB_FREE_LIST) {
                sb.free_list[i] = read_u64(&buf, pos)?;
                pos += 8;
            }
            sb.free_list_len = count.min(MAX_SB_FREE_LIST) as u32;
            next_head
        } else {
            let r_id = sb.next_page_id;
            sb.next_page_id = sb
                .next_page_id
                .checked_add(1)
                .ok_or_else(|| io::Error::other("Overflow de ID de página lógicos"))?;
            r_id
        };

        if epoch.contains(&id) {
            return Err(io::Error::other(
                "Alocação dupla interceptada no epoch corrente",
            ));
        }
        epoch.insert(id);
        Ok(id)
    }

    fn recycle_id(&self, id: u64) -> io::Result<()> {
        if id <= 2 {
            return Ok(());
        }
        // Página alocada NESTE epoch nunca fez parte de um estado durável:
        // é seguro devolvê-la já à free list e realocá-la (o CoW da raiz
        // recicla o id da geração anterior a cada upsert — errar aqui, como
        // o código fazia, rebentava qualquer sequência de 2+ upserts).
        // Removê-la do epoch mantém o guard de alocação dupla coerente.
        let was_this_epoch = self.allocated_this_epoch.lock().unwrap().remove(&id);
        if !was_this_epoch {
            // R8: página referenciada pelo último superbloco DURÁVEL — o
            // tombstone fica adiado para depois do próximo commit (shadow
            // paging: nunca sobrescrever o que o estado durável ainda aponta).
            self.pending_recycle.lock().unwrap().push(id);
            return Ok(());
        }
        self.add_to_free_list(id)
    }

    /// Tombstona a página e devolve-a à free list (superbloco em memória).
    /// Chamar SÓ quando a página já não é alcançável pelo estado durável.
    fn add_to_free_list(&self, id: u64) -> io::Result<()> {
        let mut sb = self.superblock.write().unwrap();
        if (sb.free_list_len as usize) < MAX_SB_FREE_LIST {
            let mut clean_tombstone = vec![0u8; PAGE_SIZE];
            clean_tombstone[0] = PageType::FreeList as u8;
            self.store.write_page(id, &clean_tombstone)?;
            self.metrics
                .write_amplification_count
                .fetch_add(1, Ordering::Relaxed);

            let slot = sb.free_list_len as usize;
            sb.free_list[slot] = id;
            sb.free_list_len += 1;
        } else {
            let mut clean_tombstone = vec![0u8; PAGE_SIZE];
            clean_tombstone[0] = PageType::FreeList as u8;
            clean_tombstone[1..9].copy_from_slice(&sb.free_list_head.to_le_bytes());
            clean_tombstone[9..11].copy_from_slice(&(sb.free_list_len as u16).to_le_bytes());
            let mut pos = 11;
            for i in 0..MAX_SB_FREE_LIST {
                clean_tombstone[pos..pos + 8].copy_from_slice(&sb.free_list[i].to_le_bytes());
                sb.free_list[i] = 0;
                pos += 8;
            }
            self.store.write_page(id, &clean_tombstone)?;
            self.metrics
                .write_amplification_count
                .fetch_add(1, Ordering::Relaxed);
            sb.free_list_head = id;
            sb.free_list_len = 0;
        }
        Ok(())
    }

    /// R2: escreve a cadeia overflow de um valor grande (> OVERFLOW_THRESHOLD)
    /// em duas passagens — aloca todos os ids primeiro e grava cada página JÁ
    /// com o `next` definitivo. Devolve `(primeira página, hash da cadeia)`;
    /// valores inline devolvem `(0, hash-vazio)`. Partilhado pelo caminho
    /// raiz-folha (`push_msg`) e pelo cascade (`partial_flush_cascade`) — antes
    /// só o primeiro criava cadeias e um valor >~4KB rebentava a página da
    /// folha com "Estouro físico da Página" assim que a árvore ganhava
    /// profundidade (confirmado por sonda).
    fn write_value_chain(&self, v: &[u8]) -> io::Result<(u64, [u8; HASH_LEN])> {
        let mut chain_hash = blake3::Hasher::new();
        let mut target_ov_id = 0u64;
        if v.len() > OVERFLOW_THRESHOLD {
            let chunk_cap = PAGE_SIZE - 48;
            let n_chunks = v.len().div_ceil(chunk_cap);
            let mut ids = Vec::with_capacity(n_chunks);
            for _ in 0..n_chunks {
                ids.push(self.allocate_id()?);
            }
            target_ov_id = ids[0];
            for (ci, chunk) in v.chunks(chunk_cap).enumerate() {
                let next = ids.get(ci + 1).copied().unwrap_or(0);
                let mut ov_buf = vec![0u8; PAGE_SIZE];
                ov_buf[0] = PageType::Overflow as u8;
                ov_buf[1..9].copy_from_slice(&next.to_le_bytes());
                ov_buf[9..11].copy_from_slice(&(chunk.len() as u16).to_le_bytes());
                ov_buf[11..11 + chunk.len()].copy_from_slice(chunk);

                let (data, sig) = ov_buf.split_at_mut(PAGE_SIZE - 32);
                let crc = crc32fast::hash(data);
                let hash = blake3::hash(data);
                chain_hash.update(hash.as_bytes());
                sig[0..4].copy_from_slice(&crc.to_le_bytes());
                sig[4..32].copy_from_slice(&hash.as_bytes()[..28]);

                self.store.write_page(ids[ci], &ov_buf)?;
                self.metrics
                    .write_amplification_count
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        let fin_hash = chain_hash.finalize();
        let mut trunc_hash = [0u8; HASH_LEN];
        trunc_hash.copy_from_slice(&fin_hash.as_bytes()[..HASH_LEN]);
        Ok((target_ov_id, trunc_hash))
    }

    fn recycle_overflow_chain(&self, first_page_id: u64) -> io::Result<()> {
        let mut curr_id = first_page_id;
        let mut buf = vec![0u8; PAGE_SIZE];
        while curr_id > 0 {
            self.store.read_page(curr_id, &mut buf)?;
            self.metrics
                .read_amplification_count
                .fetch_add(1, Ordering::Relaxed);
            let next_id = read_u64(&buf, 1)?;
            self.recycle_id(curr_id)?;
            curr_id = next_id;
        }
        Ok(())
    }

    fn fuse_message(&self, buffer: &mut BTreeMap<Key, Vec<Msg>>, key: Key, msg: Msg) {
        let versions = buffer.entry(key).or_default();
        if let Some(last) = versions.last_mut() {
            if last.lsn() == msg.lsn() {
                *last = msg;
                return;
            }
        }
        versions.push(msg);
    }

    pub fn prune_mvcc_history(&self, oldest_active_lsn: u64) {
        let mut pruned_count: usize = 0;
        for shard_idx in 0..NUM_SHARDS {
            let c = self.cache_shards[shard_idx].lock().unwrap();
            for frame in c.values() {
                let mut node = frame.node.write().unwrap();
                if !node.is_leaf() {
                    let mut modified = false;
                    for versions in node.buffer.values_mut() {
                        if versions.len() > 1 {
                            let mut keep_idx = None;
                            for (i, msg) in versions.iter().enumerate() {
                                if msg.lsn() <= oldest_active_lsn {
                                    keep_idx = Some(i);
                                } else {
                                    break;
                                }
                            }
                            if let Some(idx) = keep_idx {
                                if idx > 0 {
                                    pruned_count =
                                        pruned_count.checked_add(idx).unwrap_or(pruned_count);
                                    versions.drain(0..idx);
                                    modified = true;
                                }
                            }
                        }
                    }
                    if modified {
                        frame.is_dirty.store(true, Ordering::Release);
                        self.dirty_page_table.lock().unwrap().insert(node.id);
                    }
                }
            }
        }
        self.metrics
            .versions_pruned
            .fetch_add(pruned_count, Ordering::Relaxed);
    }

    pub fn upsert(&mut self, key: Key, val: Val) -> io::Result<()> {
        let gen = self.superblock.read().unwrap().generation;
        self.push_msg(key, Msg::Upsert(val, gen))
    }

    pub fn delete_key(&mut self, key: &[u8]) -> io::Result<()> {
        let gen = self.superblock.read().unwrap().generation;
        self.push_msg(key.to_vec(), Msg::Delete(gen))
    }

    fn push_msg(&mut self, key: Key, msg: Msg) -> io::Result<()> {
        let root_id = self.superblock.read().unwrap().root_id;
        let root_guard = self.acquire_node_guard(root_id)?;
        let mut root = root_guard.node.write().unwrap();
        let old_root_id = root.id;

        root.id = self.allocate_id()?;
        // CoW re-identificado ⇒ o frame de cache migra já para o novo id,
        // senão mark_dirty(novo id) é no-op e o próximo acquire vai ao disco.
        self.rekey_cache_frame(old_root_id, root.id);
        let generation = self.superblock.read().unwrap().generation;
        root.header.generation = generation + 1;

        if root.is_leaf() {
            root.bloom.insert(&key);
            match &msg {
                Msg::Upsert(v, _lsn) => {
                    // V2.2 — duas passagens (ver write_value_chain, R2).
                    let (target_ov_id, trunc_hash) = self.write_value_chain(v)?;

                    match root.keys.binary_search(&key) {
                        Ok(i) => {
                            if (root.slots[i].flags & FLAG_OVERFLOW) != 0 {
                                self.recycle_overflow_chain(root.slots[i].overflow_page)?;
                            }
                            root.vals[i] = v.clone();
                            let f = if target_ov_id > 0 {
                                FLAG_ACTIVE | FLAG_OVERFLOW
                            } else {
                                FLAG_ACTIVE
                            };
                            root.slots[i] = Slot {
                                offset: 0,
                                length: v.len() as u32,
                                flags: f,
                                overflow_page: target_ov_id,
                                cumulative_hash: trunc_hash,
                            };
                        }
                        Err(i) => {
                            root.keys.insert(i, key);
                            root.vals.insert(i, v.clone());
                            let f = if target_ov_id > 0 {
                                FLAG_ACTIVE | FLAG_OVERFLOW
                            } else {
                                FLAG_ACTIVE
                            };
                            root.slots.insert(
                                i,
                                Slot {
                                    offset: 0,
                                    length: v.len() as u32,
                                    flags: f,
                                    overflow_page: target_ov_id,
                                    cumulative_hash: trunc_hash,
                                },
                            );
                        }
                    }
                }
                Msg::Delete(_) => {
                    if let Ok(i) = root.keys.binary_search(&key) {
                        if (root.slots[i].flags & FLAG_OVERFLOW) != 0 {
                            self.recycle_overflow_chain(root.slots[i].overflow_page)?;
                            root.slots[i].overflow_page = 0;
                        }
                        root.slots[i].flags |= FLAG_GHOST;
                    }
                }
            }
            // Split por contagem OU por bytes: node_cap por contagem é
            // fisicamente impossível numa página de 4 KB com payloads reais.
            if root.keys.len() >= 2
                && (root.keys.len() > self.node_cap
                    || root.estimate_serialized_size() > PAGE_SOFT_BUDGET)
            {
                self.split_root_node(&mut root)?;
                // O split publica a NOVA raiz interna e recicla o id CoW
                // intermédio; a raiz pré-CoW deste push também é reciclada.
                self.recycle_id(old_root_id)?;
            } else {
                if root.calculate_fragmentation_ratio() > FRAGMENTATION_THRESHOLD {
                    let _ = root.compact_and_defragment();
                }
                root.rebuild_bloom_filter();
                self.mark_dirty(root.id);
                self.superblock.write().unwrap().root_id = root.id;
                self.recycle_id(old_root_id)?;
            }
        } else {
            self.fuse_message(&mut root.buffer, key, msg);
            self.total_pending_messages.fetch_add(1, Ordering::Release);
            // Drena por contagem OU por bytes; cada cascade esvazia o filho
            // mais denso, por isso itera (limitado pelo fanout) até caber.
            let mut cascades = 0usize;
            while !root.buffer.is_empty()
                && (root.buffer.len() > self.buffer_cap
                    || root.estimate_serialized_size() > PAGE_SOFT_BUDGET)
                && cascades <= root.children.len()
            {
                self.partial_flush_cascade(&mut root)?;
                cascades += 1;
            }
            // Os separadores acumulados pelos splits dos filhos também têm de
            // caber na página: a raiz INTERNA divide-se quando excede o orçamento.
            if root.keys.len() >= 2 && root.estimate_serialized_size() > PAGE_SOFT_BUDGET {
                self.split_root_node(&mut root)?;
                self.recycle_id(old_root_id)?;
            } else {
                // A raiz CoW é publicada nos DOIS ramos. Antes, o ramo do cascade
                // não atualizava sb.root_id nem reciclava a raiz antiga: o
                // superbloco ficava a apontar para o id velho e a árvore lia a
                // página obsoleta do disco no acesso seguinte.
                self.mark_dirty(root.id);
                self.superblock.write().unwrap().root_id = root.id;
                self.recycle_id(old_root_id)?;
            }
        }
        Ok(())
    }

    fn split_root_node(&mut self, root: &mut DiskNode) -> io::Result<()> {
        let mid = root.byte_balanced_mid();
        let pivot = root.keys[mid].clone();
        let left_id = self.allocate_id()?;
        let right_id = self.allocate_id()?;

        let mut old_keys = std::mem::take(&mut root.keys);
        let mut old_vals = std::mem::take(&mut root.vals);
        let mut old_slots = std::mem::take(&mut root.slots);
        let mut old_children = std::mem::take(&mut root.children);
        let old_buffer = std::mem::take(&mut root.buffer);

        let mut left_buf = BTreeMap::new();
        let mut right_buf = BTreeMap::new();
        for (k, m_vec) in old_buffer {
            if k < pivot {
                left_buf.insert(k, m_vec);
            } else {
                right_buf.insert(k, m_vec);
            }
        }

        let mut right_keys = old_keys.split_off(mid);
        let right_slots = old_slots.split_off(mid);
        let right_vals = if root.is_leaf() {
            old_vals.split_off(mid)
        } else {
            Vec::new()
        };
        let right_children = if !root.is_leaf() {
            old_children.split_off(mid + 1)
        } else {
            Vec::new()
        };

        // CORREÇÃO E ENRIJECIMENTO DO SPLIT INTERNAL: O pivot sobe e é removido da chave do filho direito
        if !root.is_leaf() && !right_keys.is_empty() {
            right_keys.remove(0);
        }

        let start_idx = if root.is_leaf() { mid } else { mid + 1 };
        if !root.is_leaf() && old_children.len() > start_idx {
            let _ = old_children.split_off(start_idx);
        }

        let mut left = DiskNode {
            id: left_id,
            header: PageHeader {
                page_type: root.header.page_type,
                version: VERSION,
                generation: root.header.generation,
                lsn: root.header.lsn,
                slot_count: 0,
                free_start: 0,
                payload_end: 0,
            },
            low_key: root.low_key.clone(),
            high_key: Some(pivot.clone()),
            slots: old_slots,
            keys: old_keys,
            vals: old_vals,
            children: old_children,
            buffer: left_buf,
            bloom: BloomFilter::default(),
        };
        left.rebuild_bloom_filter();

        let mut right = DiskNode {
            id: right_id,
            header: PageHeader {
                page_type: root.header.page_type,
                version: VERSION,
                generation: root.header.generation,
                lsn: root.header.lsn,
                slot_count: 0,
                free_start: 0,
                payload_end: 0,
            },
            low_key: Some(pivot.clone()),
            high_key: root.high_key.clone(),
            slots: right_slots,
            keys: right_keys,
            vals: right_vals,
            children: right_children,
            buffer: right_buf,
            bloom: BloomFilter::default(),
        };
        right.rebuild_bloom_filter();

        self.store.write_page(left.id, &left.serialize()?)?;
        self.store.write_page(right.id, &right.serialize()?)?;
        self.metrics
            .write_amplification_count
            .fetch_add(2, Ordering::Relaxed);

        let old_root_id = root.id;
        root.header.page_type = PageType::Internal as u8;
        root.keys = vec![pivot];
        root.children = vec![left_id, right_id];
        root.buffer = BTreeMap::new();
        root.id = self.allocate_id()?;
        self.rekey_cache_frame(old_root_id, root.id);

        self.store.write_page(root.id, &root.serialize()?)?;
        self.metrics
            .write_amplification_count
            .fetch_add(1, Ordering::Relaxed);
        self.superblock.write().unwrap().root_id = root.id;
        self.recycle_id(old_root_id)?;
        Ok(())
    }

    fn partial_flush_cascade(&mut self, node: &mut DiskNode) -> io::Result<()> {
        if node.buffer.is_empty() {
            return Ok(());
        }
        let mut density = vec![0usize; node.children.len()];
        for k in node.buffer.keys() {
            let idx = node.keys.partition_point(|p| p <= k);
            if idx < density.len() {
                density[idx] += 1;
            }
        }
        let target_idx = density.iter().enumerate().max_by_key(|x| x.1).unwrap().0;
        let child_id = node.children[target_idx];

        let child_guard = self.acquire_node_guard(child_id)?;
        let mut child = child_guard.node.write().unwrap();
        let old_child_id = child.id;

        child.id = self.allocate_id()?;
        self.rekey_cache_frame(old_child_id, child.id);
        child.header.generation = node.header.generation;
        node.children[target_idx] = child.id;

        let mut rem_buf = BTreeMap::new();
        for (k, msg_vec) in std::mem::take(&mut node.buffer) {
            let idx = node.keys.partition_point(|p| p <= &k);
            if idx == target_idx {
                for msg in msg_vec {
                    self.total_pending_messages.fetch_sub(1, Ordering::Release);
                    if child.is_leaf() {
                        child.bloom.insert(&k);
                        match msg {
                            Msg::Upsert(v, _) => {
                                // R2: o cascade cria cadeia overflow para valores
                                // grandes, exatamente como o caminho raiz-folha —
                                // antes inseria SEMPRE inline e um valor >~4KB
                                // rebentava o serialize da folha.
                                let (ov_id, chain_hash) = self.write_value_chain(&v)?;
                                let flags = if ov_id > 0 {
                                    FLAG_ACTIVE | FLAG_OVERFLOW
                                } else {
                                    FLAG_ACTIVE
                                };
                                let slot = Slot {
                                    offset: 0,
                                    length: v.len() as u32,
                                    flags,
                                    overflow_page: ov_id,
                                    cumulative_hash: chain_hash,
                                };
                                match child.keys.binary_search(&k) {
                                    Ok(i) => {
                                        if (child.slots[i].flags & FLAG_OVERFLOW) != 0 {
                                            self.recycle_overflow_chain(
                                                child.slots[i].overflow_page,
                                            )?;
                                        }
                                        child.vals[i] = v;
                                        child.slots[i] = slot;
                                    }
                                    Err(i) => {
                                        child.keys.insert(i, k.clone());
                                        child.vals.insert(i, v);
                                        child.slots.insert(i, slot);
                                    }
                                }
                            }
                            Msg::Delete(_) => {
                                if let Ok(i) = child.keys.binary_search(&k) {
                                    if (child.slots[i].flags & FLAG_OVERFLOW) != 0 {
                                        self.recycle_overflow_chain(child.slots[i].overflow_page)?;
                                        child.slots[i].overflow_page = 0;
                                    }
                                    child.slots[i].flags |= FLAG_GHOST;
                                }
                            }
                        }
                    } else {
                        self.fuse_message(&mut child.buffer, k.clone(), msg);
                        self.total_pending_messages.fetch_add(1, Ordering::Release);
                    }
                }
            } else {
                rem_buf.insert(k, msg_vec);
            }
        }
        node.buffer = rem_buf;

        // R2: um filho INTERNO que recebeu mensagens pode ele próprio exceder o
        // orçamento físico (o buffer serializa inline na página de 4KB) — drena
        // recursivamente ANTES do serialize, senão um valor grande em árvores de
        // 3+ níveis rebentava aqui. Mesmo loop limitado do push_msg.
        if !child.is_leaf() {
            let mut cascades = 0usize;
            while !child.buffer.is_empty()
                && child.estimate_serialized_size() > PAGE_SOFT_BUDGET
                && cascades <= child.children.len()
            {
                self.partial_flush_cascade(&mut child)?;
                cascades += 1;
            }
        }

        if child.keys.len() >= 2
            && (child.keys.len() > self.node_cap
                || child.estimate_serialized_size() > PAGE_SOFT_BUDGET)
        {
            // V2.2: o split byte-aware vale para folhas E para filhos INTERNOS
            // (separadores + buffer também estouram a página em árvores de 3+
            // níveis; antes só as folhas dividiam e o interno rebentava no
            // serialize). split_child_node já trata os dois page_types.
            self.split_child_node(node, target_idx, &mut child)?;
            self.recycle_id(old_child_id)?;
        } else if child.is_leaf() && child.keys.len() < self.node_cap / 3 {
            self.merge_or_borrow_cascade(node, target_idx, &mut child)?;
            // Sem irmão à esquerda (idx 0) o merge é no-op: o filho CoW
            // continua vivo e tem de ser persistido pelo commit. (Se o merge
            // aconteceu, o frame foi removido e isto é no-op.)
            self.mark_dirty(child.id);
            self.recycle_id(old_child_id)?;
        } else {
            child.rebuild_bloom_filter();
            self.store.write_page(child.id, &child.serialize()?)?;
            self.metrics
                .write_amplification_count
                .fetch_add(1, Ordering::Relaxed);
            self.recycle_id(old_child_id)?;
        }
        // O pai foi mutado (ponteiro do filho CoW + buffer drenado): tem de ir
        // para a tabela de sujas, senão o commit persiste o filho novo mas o
        // pai em disco continua a apontar para o filho antigo/reciclado.
        self.mark_dirty(node.id);
        Ok(())
    }

    fn split_child_node(
        &mut self,
        parent: &mut DiskNode,
        idx: usize,
        child: &mut DiskNode,
    ) -> io::Result<()> {
        let mid = child.byte_balanced_mid();
        let pivot = child.keys[mid].clone();
        let right_id = self.allocate_id()?;

        let mut old_keys = std::mem::take(&mut child.keys);
        let mut old_slots = std::mem::take(&mut child.slots);
        let mut old_vals = std::mem::take(&mut child.vals);
        let mut old_children = std::mem::take(&mut child.children);
        let old_buffer = std::mem::take(&mut child.buffer);

        let mut left_buf = BTreeMap::new();
        let mut right_buf = BTreeMap::new();
        for (k, m_vec) in old_buffer {
            if k < pivot {
                left_buf.insert(k, m_vec);
            } else {
                right_buf.insert(k, m_vec);
            }
        }

        let mut right_keys = old_keys.split_off(mid);
        let right_slots = old_slots.split_off(mid);
        let right_vals = if child.is_leaf() {
            old_vals.split_off(mid)
        } else {
            Vec::new()
        };
        let right_children = if !child.is_leaf() {
            old_children.split_off(mid + 1)
        } else {
            Vec::new()
        };

        // CORREÇÃO E ENRIJECIMENTO DO SPLIT DE FILHO INTERNAL: Remove o pivot do filho direito
        if !child.is_leaf() && !right_keys.is_empty() {
            right_keys.remove(0);
        }

        let mut left = DiskNode {
            id: child.id,
            header: PageHeader {
                page_type: child.header.page_type,
                version: VERSION,
                generation: child.header.generation,
                lsn: child.header.lsn,
                slot_count: 0,
                free_start: 0,
                payload_end: 0,
            },
            low_key: child.low_key.clone(),
            high_key: Some(pivot.clone()),
            slots: old_slots,
            keys: old_keys,
            vals: old_vals,
            children: old_children,
            buffer: left_buf,
            bloom: BloomFilter::default(),
        };
        left.rebuild_bloom_filter();

        let mut right = DiskNode {
            id: right_id,
            header: PageHeader {
                page_type: child.header.page_type,
                version: VERSION,
                generation: child.header.generation,
                lsn: child.header.lsn,
                slot_count: right_keys.len() as u16,
                free_start: 39,
                payload_end: 4064,
            },
            low_key: Some(pivot.clone()),
            high_key: child.high_key.clone(),
            slots: right_slots,
            keys: right_keys,
            vals: right_vals,
            children: right_children,
            buffer: right_buf,
            bloom: BloomFilter::default(),
        };
        right.rebuild_bloom_filter();

        self.store.write_page(left.id, &left.serialize()?)?;
        self.store.write_page(right.id, &right.serialize()?)?;
        self.metrics
            .write_amplification_count
            .fetch_add(2, Ordering::Relaxed);
        parent.keys.insert(idx, pivot);
        parent.children.insert(idx + 1, right_id);
        // O frame de cache keyed child.id ainda aponta para este DiskNode, que
        // foi esvaziado pelos mem::take acima. Repõe nele a metade esquerda
        // (mesmo id), senão o próximo acquire devolvia um nó vazio do cache.
        *child = left;
        Ok(())
    }

    fn merge_or_borrow_cascade(
        &mut self,
        parent: &mut DiskNode,
        idx: usize,
        child: &mut DiskNode,
    ) -> io::Result<()> {
        if idx > 0 {
            let left_id = parent.children[idx - 1];
            let left_guard = self.acquire_node_guard(left_id)?;
            let mut left = left_guard.node.write().unwrap();
            let old_child_id = child.id;

            // O merge só acontece se o resultado couber no orçamento físico da
            // página — fundir às cegas estourava a folha esquerda em serialize.
            // No-op ⇒ o chamador persiste o filho como está (mark_dirty).
            if left.estimate_serialized_size() + child.estimate_serialized_size() > PAGE_SOFT_BUDGET
            {
                return Ok(());
            }

            // REAL FRAC TREE MERGE BEHAVIOR COMPLETO: Redistribui simetricamente e preserva os buffers de chaves e de mensagens pendentes
            left.keys.extend(std::mem::take(&mut child.keys));
            left.vals.extend(std::mem::take(&mut child.vals));
            left.slots.extend(std::mem::take(&mut child.slots));
            left.children.extend(std::mem::take(&mut child.children));

            for (k, m_vec) in std::mem::take(&mut child.buffer) {
                let dest = left.buffer.entry(k).or_default();
                dest.extend(m_vec);
            }

            left.high_key = child.high_key.clone();
            left.rebuild_bloom_filter();

            self.store.write_page(left.id, &left.serialize()?)?;
            self.metrics
                .write_amplification_count
                .fetch_add(1, Ordering::Relaxed);
            parent.keys.remove(idx - 1);
            parent.children.remove(idx);
            self.recycle_id(old_child_id)?;
            // O filho foi absorvido: remove o frame morto para que uma futura
            // realocação deste id não sirva o nó obsoleto do cache.
            self.evict_cache_frame(old_child_id);
            let root_id = self.superblock.read().unwrap().root_id;
            if parent.id == root_id && parent.keys.is_empty() {
                self.superblock.write().unwrap().root_id = left.id;
            }
        }
        Ok(())
    }

    fn read_overflow_chain(
        &self,
        first_page_id: u64,
        expected_length: u32,
        expected_hash: [u8; HASH_LEN],
    ) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut curr_id = first_page_id;
        let mut visited = HashSet::new();
        let mut buf = vec![0u8; PAGE_SIZE];
        let mut chain_hash = blake3::Hasher::new();

        while curr_id > 0 {
            if !visited.insert(curr_id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Ciclo detectado na cadeia de overflow",
                ));
            }
            self.store.read_page(curr_id, &mut buf)?;
            self.metrics
                .read_amplification_count
                .fetch_add(1, Ordering::Relaxed);
            let (data, sig) = buf.split_at(PAGE_SIZE - 32);
            if crc32fast::hash(data) != read_u32(sig, 0)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Checksum falhou em overflow",
                ));
            }
            let hash = blake3::hash(data);
            if hash.as_bytes()[..HASH_LEN] != sig[4..32] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Assinatura falhou em overflow",
                ));
            }

            chain_hash.update(hash.as_bytes());
            let next_id = read_u64(&buf, 1)?;
            let chunk_size = read_u16(&buf, 9)? as usize;
            out.extend_from_slice(safe_slice(&buf, 11, chunk_size)?);
            curr_id = next_id;
        }
        if out.len() != expected_length as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Tamanho total da cadeia não confere com slot.length",
            ));
        }
        let fin_hash = chain_hash.finalize();
        if fin_hash.as_bytes()[..HASH_LEN] != expected_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Fraude estrutural: Checksum acumulado da cadeia corrompido",
            ));
        }
        Ok(out)
    }

    /// Leitura com corte de visibilidade por `snapshot_generation`.
    ///
    /// HONESTIDADE SEMÂNTICA (revisão 2026-07-16): o "lsn" comparado aqui é o
    /// que `upsert`/`delete_key` carimbam nas mensagens — a **GENERATION do
    /// superbloco**, não um LSN do log do Heraclitus. Serve para snapshots
    /// relativos a commits desta árvore; NÃO passar LSNs do log (usar
    /// `get`, que lê o head, para o caso comum).
    pub fn get_snapshot(&self, key: &[u8], snapshot_generation: u64) -> io::Result<Option<Val>> {
        let root_id = self.superblock.read().unwrap().root_id;
        let mut curr_id = root_id;
        self.metrics
            .active_snapshots
            .fetch_add(1, Ordering::Acquire);
        let res = loop {
            let node_guard = self.acquire_node_guard(curr_id)?;
            let node = node_guard.node.read().unwrap();
            if let Some(low) = &node.low_key {
                if key < low.as_slice() {
                    break Ok(None);
                }
            }
            if let Some(high) = &node.high_key {
                if key >= high.as_slice() {
                    break Ok(None);
                }
            }

            if let Some(versions) = node.buffer.get(key) {
                if let Some(msg) = versions
                    .iter()
                    .rev()
                    .find(|m| m.lsn() <= snapshot_generation)
                {
                    break Ok(match msg {
                        Msg::Upsert(v, _) => Some(v.clone()),
                        Msg::Delete(_) => None,
                    });
                }
            }
            if node.is_leaf() {
                if !node.bloom.contains(key) {
                    self.metrics.bloom_hits.fetch_add(1, Ordering::Relaxed);
                    break Ok(None);
                }
                self.metrics.bloom_misses.fetch_add(1, Ordering::Relaxed);
                if let Ok(i) = node.keys.binary_search(&key.to_vec()) {
                    if (node.slots[i].flags & FLAG_GHOST) == 0 {
                        if (node.slots[i].flags & FLAG_OVERFLOW) != 0 {
                            break self
                                .read_overflow_chain(
                                    node.slots[i].overflow_page,
                                    node.slots[i].length,
                                    node.slots[i].cumulative_hash,
                                )
                                .map(Some);
                        }
                        break Ok(Some(node.vals[i].clone()));
                    }
                }
                break Ok(None);
            }
            let child_idx = node.keys.partition_point(|p| p.as_slice() <= key);
            curr_id = node.children[child_idx];
        };
        self.metrics
            .active_snapshots
            .fetch_sub(1, Ordering::Release);
        res
    }

    pub fn get(&self, key: &[u8]) -> Option<Val> {
        self.get_snapshot(key, u64::MAX).unwrap_or(None)
    }

    pub fn commit(&mut self) -> io::Result<()> {
        while self.total_pending_messages.load(Ordering::Acquire) > 0 {
            // Numa árvore de 3+ níveis as mensagens podem estar num interno
            // ABAIXO da raiz (o cascade só empurra um nível por chamada), por
            // isso desce-se até ao primeiro nó interno com buffer pendente —
            // cascatar só a raiz (buffer vazio) não progredia e o loop pendurava.
            let root_id = self.superblock.read().unwrap().root_id;
            let mut queue = vec![root_id];
            let mut target = None;
            while let Some(id) = queue.pop() {
                let guard = self.acquire_node_guard(id)?;
                let node = guard.node.read().unwrap();
                if node.is_leaf() {
                    continue;
                }
                if !node.buffer.is_empty() {
                    target = Some(id);
                    break;
                }
                queue.extend(node.children.iter().copied());
            }
            let Some(target_id) = target else {
                // Buffers todos vazios mas contador > 0: mensagens fundidas
                // (fuse_message substitui sem decrementar). Re-sincroniza em
                // vez de pendurar o commit para sempre.
                self.total_pending_messages.store(0, Ordering::Release);
                break;
            };
            let node_guard = self.acquire_node_guard(target_id)?;
            let mut node = node_guard.node.write().unwrap();
            self.partial_flush_cascade(&mut node)?;
        }

        let dirty_set = std::mem::take(&mut *self.dirty_page_table.lock().unwrap());
        if !dirty_set.is_empty() {
            for id in dirty_set {
                let shard_idx = ((id ^ (id >> 16)) % NUM_SHARDS as u64) as usize;
                let c = self.cache_shards[shard_idx].lock().unwrap();
                if let Some(frame) = c.get(&id) {
                    if frame.is_dirty.load(Ordering::Acquire) {
                        let n = frame.node.read().unwrap();
                        self.store.write_page(id, &n.serialize()?)?;
                        self.metrics
                            .write_amplification_count
                            .fetch_add(1, Ordering::Relaxed);
                        frame.is_dirty.store(false, Ordering::Release);
                    }
                }
            }
        }
        self.store.sync()?;

        let offset = self.active_sb_offset.load(Ordering::Acquire);
        let next_offset = if offset == 0 { PAGE_SIZE as u64 } else { 0 };
        let page = if next_offset == 0 { 0 } else { 1 };

        {
            let mut sb = self.superblock.write().unwrap();
            sb.generation += 1;
            self.store.write_page(page, &sb.serialize()?)?;
        }
        self.metrics
            .write_amplification_count
            .fetch_add(1, Ordering::Relaxed);
        self.store.sync()?;

        self.active_sb_offset.store(next_offset, Ordering::Release);
        // R8: o superbloco novo já está durável e não referencia as páginas CoW
        // substituídas neste epoch — agora (e só agora) é seguro tombstoná-las
        // e devolvê-las à free list. Num crash antes daqui elas ficam órfãs
        // (fuga de espaço segura), nunca corrompidas.
        let pending: Vec<u64> = std::mem::take(&mut *self.pending_recycle.lock().unwrap());
        for id in pending {
            self.add_to_free_list(id)?;
        }
        self.allocated_this_epoch.lock().unwrap().clear();
        Ok(())
    }

    pub fn verify_tree_integrity(&mut self) -> io::Result<bool> {
        let total_physical_pages = self.store.total_pages()?;
        let mut visited_nodes = HashSet::new();
        let mut visited_overflow = HashSet::new();
        let mut visited_freelist = HashSet::new();
        let mut leaf_depths = HashSet::new();
        let mut page_to_parents: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut buf = vec![0u8; PAGE_SIZE];

        let sb = self.superblock.read().unwrap();
        let mut stack = vec![(sb.root_id, None, None, 0usize)];

        while let Some((id, low_bound, high_bound, depth)) = stack.pop() {
            if !visited_nodes.insert(id) {
                return Ok(false);
            }
            if id >= sb.next_page_id {
                return Ok(false);
            }

            self.store.read_page(id, &mut buf)?;
            let node = DiskNode::deserialize(id, &buf)?;

            if node.header.generation > sb.generation {
                return Ok(false);
            }
            if !node.keys.windows(2).all(|w| w[0] < w[1]) {
                return Ok(false);
            }
            if let (Some(l), Some(nl)) = (&low_bound, &node.low_key) {
                if l != nl {
                    return Ok(false);
                }
            }
            if let (Some(h), Some(nh)) = (&high_bound, &node.high_key) {
                if h != nh {
                    return Ok(false);
                }
            }

            let free_start = read_u16(&buf, OFF_FREE_START)? as usize;
            let payload_end = read_u16(&buf, OFF_PAYLOAD_END)? as usize;
            if free_start > payload_end || payload_end > PAYLOAD_END_MAX {
                return Ok(false);
            }

            for slot in node.slots.iter() {
                if (slot.flags & FLAG_OVERFLOW) != 0 {
                    if slot.overflow_page == 0 {
                        return Ok(false);
                    }
                    let mut ov_id = slot.overflow_page;
                    let mut total_bytes_chain = 0usize;
                    while ov_id > 0 {
                        if !visited_overflow.insert(ov_id) {
                            return Ok(false);
                        }
                        let mut ov_buf = vec![0u8; PAGE_SIZE];
                        self.store.read_page(ov_id, &mut ov_buf)?;
                        if ov_buf[0] != PageType::Overflow as u8 {
                            return Ok(false);
                        }
                        total_bytes_chain += read_u16(&ov_buf, 9)? as usize;
                        ov_id = read_u64(&ov_buf, 1)?;
                    }
                    if total_bytes_chain != slot.length as usize {
                        return Ok(false);
                    }
                }
            }
            if node.is_leaf() {
                leaf_depths.insert(depth);
                if leaf_depths.len() > 1 {
                    return Ok(false);
                }
            } else {
                if node.children.len() != node.keys.len() + 1 {
                    return Ok(false);
                }
                for (idx, &child_id) in node.children.iter().enumerate() {
                    let entry = page_to_parents.entry(child_id).or_default();
                    entry.push(id);
                    if entry.len() > 1 {
                        return Ok(false);
                    }
                    let child_low = if idx == 0 {
                        node.low_key.clone()
                    } else {
                        Some(node.keys[idx - 1].clone())
                    };
                    let child_high = if idx == node.keys.len() {
                        node.high_key.clone()
                    } else {
                        Some(node.keys[idx].clone())
                    };
                    stack.push((child_id, child_low, child_high, depth + 1));
                }
            }
        }

        let mut free_id = sb.free_list_head;
        while free_id > 0 {
            if !visited_freelist.insert(free_id) || free_id >= sb.next_page_id {
                return Ok(false);
            }
            self.store.read_page(free_id, &mut buf)?;
            if buf[0] != PageType::FreeList as u8 {
                return Ok(false);
            }
            free_id = read_u64(&buf, 1)?;
        }
        for &id in &sb.free_list {
            if id > 0 {
                visited_freelist.insert(id);
            }
        }
        // R8: páginas CoW à espera do próximo commit (pending_recycle) não estão
        // na árvore nem na free list — contam como "em trânsito" na contabilidade.
        for &id in self.pending_recycle.lock().unwrap().iter() {
            if id > 0 {
                visited_freelist.insert(id);
            }
        }

        // Contabilidade (V2.2): páginas 0/1 são os superblocos; a página 2 é a
        // raiz GÉNESIS — protegida do recycle_id (id <= 2), fica órfã assim
        // que a raiz CoW muda de id, sem nunca entrar na free list. Conta-se
        // explicitamente quando não está viva na árvore nem na free list.
        let genesis_orphan =
            usize::from(!visited_nodes.contains(&2) && !visited_freelist.contains(&2));
        let total_accounted = visited_nodes.len()
            + visited_overflow.len()
            + visited_freelist.len()
            + 2
            + genesis_orphan;
        if total_accounted != total_physical_pages as usize {
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod page_roundtrip_tests {
    //! Round-trip da (de)serialização física da página, com foco na compressão
    //! por prefixo (feature M22: OFF_PFX_OFF/OFF_PFX_LEN). Sem estes testes a
    //! feature de formato de página ficava sem rede de segurança.
    use super::*;

    fn leaf(keys: &[&str], vals: &[&str]) -> DiskNode {
        DiskNode {
            id: 42,
            header: PageHeader {
                page_type: PageType::Leaf as u8,
                version: VERSION,
                generation: 7,
                lsn: 99,
                slot_count: keys.len() as u16,
                free_start: 0,
                payload_end: 0,
            },
            low_key: keys.first().map(|k| k.as_bytes().to_vec()),
            high_key: keys.last().map(|k| k.as_bytes().to_vec()),
            slots: Vec::new(),
            keys: keys.iter().map(|k| k.as_bytes().to_vec()).collect(),
            vals: vals.iter().map(|v| v.as_bytes().to_vec()).collect(),
            children: Vec::new(),
            buffer: BTreeMap::new(),
            bloom: BloomFilter::default(),
        }
    }

    #[test]
    fn common_prefix_extraction() {
        let n = leaf(
            &["prefix_alpha", "prefix_beta", "prefix_gamma"],
            &["1", "2", "3"],
        );
        assert_eq!(n.calculate_common_prefix(), b"prefix_".to_vec());
        // No shared prefix → empty.
        let m = leaf(&["apple", "banana"], &["1", "2"]);
        assert_eq!(m.calculate_common_prefix(), Vec::<u8>::new());
    }

    #[test]
    fn leaf_roundtrip_with_prefix() {
        let n = leaf(
            &["prefix_alpha", "prefix_beta", "prefix_gamma"],
            &["v1", "v2", "v3"],
        );
        let buf = n.serialize().unwrap();

        // The prefix header fields (OFF_PFX_*) must point at the real prefix.
        let pfx_len = read_u16(&buf, OFF_PFX_LEN).unwrap() as usize;
        assert_eq!(
            pfx_len,
            b"prefix_".len(),
            "OFF_PFX_LEN deve refletir o prefixo comum"
        );

        let n2 = DiskNode::deserialize(n.id, &buf).unwrap();
        assert_eq!(
            n2.keys, n.keys,
            "chaves reconstruídas com prefixo devem bater"
        );
        assert_eq!(n2.vals, n.vals);
        assert_eq!(n2.low_key, n.low_key);
        assert_eq!(n2.high_key, n.high_key);
        // Serialização determinística: re-serializar deve dar bytes idênticos.
        assert_eq!(
            n2.serialize().unwrap(),
            buf,
            "round-trip não é byte-idêntico"
        );
    }

    #[test]
    fn leaf_roundtrip_without_prefix() {
        let n = leaf(&["apple", "banana", "cherry"], &["v1", "v2", "v3"]);
        let buf = n.serialize().unwrap();
        assert_eq!(
            read_u16(&buf, OFF_PFX_LEN).unwrap(),
            0,
            "sem prefixo comum, pfx_len=0"
        );
        let n2 = DiskNode::deserialize(n.id, &buf).unwrap();
        assert_eq!(n2.keys, n.keys);
        assert_eq!(n2.vals, n.vals);
    }

    #[test]
    fn internal_roundtrip_with_buffer() {
        let mut buffer: BTreeMap<Key, Vec<Msg>> = BTreeMap::new();
        buffer.insert(b"k_msg1".to_vec(), vec![Msg::Upsert(b"x".to_vec(), 5)]);
        buffer.insert(b"k_msg2".to_vec(), vec![Msg::Delete(7)]);
        let node = DiskNode {
            id: 3,
            header: PageHeader {
                page_type: PageType::Internal as u8,
                version: VERSION,
                generation: 1,
                lsn: 10,
                slot_count: 2,
                free_start: 0,
                payload_end: 0,
            },
            low_key: Some(b"k_a".to_vec()),
            high_key: Some(b"k_b".to_vec()),
            slots: Vec::new(),
            keys: vec![b"k_a".to_vec(), b"k_b".to_vec()], // prefixo comum "k_"
            vals: Vec::new(),
            children: vec![10, 20, 30], // slot_count + 1
            buffer,
            bloom: BloomFilter::default(),
        };
        let buf = node.serialize().unwrap();
        let n2 = DiskNode::deserialize(node.id, &buf).unwrap();
        assert_eq!(n2.keys, node.keys, "separadores reconstruídos");
        assert_eq!(
            n2.children, node.children,
            "ponteiros de filhos preservados"
        );
        assert_eq!(
            n2.buffer, node.buffer,
            "mensagens do buffer (prefixo-stripped) preservadas"
        );
        assert_eq!(n2.serialize().unwrap(), buf);
    }

    // Regressão do bug M30 (corrigido): o CoW re-identificava o nó mas o frame
    // de cache ficava sob o id antigo — o 2.º upsert ia ao disco ler uma página
    // nunca escrita (Storage(EOF)). Ver `rekey_cache_frame`.
    #[test]
    fn from_map_fresh_path_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.hbt");
        let mut m = std::collections::BTreeMap::new();
        m.insert(b"k1".to_vec(), b"v1".to_vec());
        m.insert(b"k2".to_vec(), b"v2".to_vec());
        let t = super::BEpsilonTree::from_map(&path, m).unwrap();
        assert_eq!(t.get(b"k1"), Some(b"v1".to_vec()));
        assert_eq!(t.get(b"k2"), Some(b"v2".to_vec()));
    }

    // V2.2: cadeias overflow acima de 64 KB (ov_len u32 no layout v5) —
    // roundtrip com reopen do disco, onde o u16 antigo truncava o comprimento.
    #[test]
    fn overflow_values_beyond_64kb_survive_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big-vals.hbt");
        let big: Val = (0..200_000u32).map(|i| (i % 251) as u8).collect(); // ~195 KB
        let mut m = std::collections::BTreeMap::new();
        m.insert(b"gigante".to_vec(), big.clone());
        m.insert(b"pequeno".to_vec(), b"v".to_vec());
        let t = super::BEpsilonTree::from_map(&path, m).unwrap();
        assert_eq!(t.get(b"gigante"), Some(big.clone()), "cadeia >64KB legível");
        drop(t);
        let t2 = super::BEpsilonTree::load(&path).unwrap();
        assert_eq!(
            t2.get(b"gigante"),
            Some(big),
            "e sobrevive ao reopen (ov_len u32 persistido)"
        );
        assert_eq!(t2.get(b"pequeno"), Some(b"v".to_vec()));
    }

    // Exercita os caminhos profundos que o roundtrip pequeno não toca:
    // split da raiz (>node_cap=128), buffer da raiz interna, cascade no
    // commit, split de filho — e depois reabre do disco para provar que o
    // estado commitado é completo e navegável.
    #[test]
    fn from_map_many_keys_splits_and_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.hbt");
        let mut m = std::collections::BTreeMap::new();
        for i in 0..500u32 {
            m.insert(
                format!("k{i:04}").into_bytes(),
                format!("v{i:04}").into_bytes(),
            );
        }
        let t = super::BEpsilonTree::from_map(&path, m.clone()).unwrap();
        for (k, v) in &m {
            assert_eq!(t.get(k).as_ref(), Some(v), "chave presente após from_map");
        }
        drop(t);
        let t2 = super::BEpsilonTree::load(&path).unwrap();
        for (k, v) in &m {
            assert_eq!(
                t2.get(k).as_ref(),
                Some(v),
                "chave presente após reload do disco"
            );
        }
    }

    #[test]
    fn from_map_empty_fresh_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.hbt");
        let t = super::BEpsilonTree::from_map(&path, std::collections::BTreeMap::new()).unwrap();
        assert_eq!(t.get(b"nope"), None);
    }

    #[test]
    fn prefix_region_does_not_overlap_bloom() {
        // OFF_BLOOM(33) + 64 bytes de bloom termina em 97; OFF_PFX_OFF=97,
        // OFF_PFX_LEN=99, OFF_SLOTS_START=101. Sanidade do layout.
        assert_eq!(OFF_BLOOM + BLOOM_FILTER_SIZE_BYTES, OFF_PFX_OFF);
        assert_eq!(OFF_PFX_OFF + 2, OFF_PFX_LEN);
        assert_eq!(OFF_PFX_LEN + 2, OFF_SLOTS_START);
    }
}
