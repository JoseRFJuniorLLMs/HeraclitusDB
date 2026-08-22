//! SPEC-0050 §28–§40 — blocos do HRKL PACKED.
//!
//! # Porque blocos e não o segmento inteiro
//!
//! §30: nunca `compress(segment_256MB)`. Um segmento comprimido como um bloco
//! único obriga a descomprimir 256 MB para ler um registo — e mata o gate §157
//! (*point lookup* descomprime no máximo um bloco). Com blocos de 256 KiB
//! ganham-se range reads, paralelismo, block cache, pruning, descompressão
//! limitada e `GET` por intervalo em object storage.
//!
//! # `BlockHeaderV1` — 64 bytes exactos, codificados à mão
//!
//! ```text
//! Offset Size Campo
//! 0      4    magic = "HBLK"
//! 4      2    header_len = 64
//! 6      1    compression_codec
//! 7      1    flags
//! 8      4    uncompressed_len
//! 12     4    compressed_len
//! 16     4    record_count
//! 20     2    restart_interval
//! 22     2    restart_count
//! 24     8    first_lsn
//! 32     8    last_lsn
//! 40     8    base_hlc
//! 48     8    max_hlc
//! 56     4    block_crc32c
//! 60     4    dictionary_id
//! ```
//!
//! O CRC (§48) é `CRC32C(header com crc=0 || stored_block_bytes)`: cobre
//! simultaneamente o header físico e o payload comprimido, por isso corrupção
//! no codec, nos comprimentos, nos intervalos ou nos bytes é detectada por um
//! único checksum.
//!
//! # Corpo do bloco (descomprimido)
//!
//! ```text
//! [região de registos]
//!    record_meta  varint = (payload_len << 3) | flags
//!    [lsn_delta   varint]   só em SPARSE_LSN
//!    hlc          varint    delta face ao anterior (ou absoluto em HLC_ABSOLUTE)
//!    payload      bytes
//! [array de restart points]  restart_count * 24 bytes
//!    ordinal u32 | byte_offset u32 | absolute_hlc u64 | absolute_lsn u64
//! ```
//!
//! Os restart points (§39) existem para que o delta encoding não transforme uma
//! leitura pontual num varrimento de milhares de registos: do LSN chega-se ao
//! ordinal, do ordinal ao restart anterior, e daí varrem-se no máximo
//! `restart_interval - 1` registos.

use heraclitus_core::Lsn;

use super::block_directory::BlockDirectoryEntryV1;
use super::compress::{compress_block, decompress_block, CompressionCodec, PackingProfile};
use super::error::{corrupt, slice_at, V6Result, HARD_MAX_BLOCK_BYTES, HARD_MAX_RECORD_BYTES};
use super::varint::{put_varint, read_varint, read_varint_usize, varint_len};

pub const BLOCK_MAGIC: [u8; 4] = *b"HBLK";
pub const BLOCK_HEADER_LEN: usize = 64;
pub const RESTART_ENTRY_LEN: usize = 24;

/// §29: mínimo 64 KiB, default 256 KiB, máximo 1 MiB.
pub const MIN_BLOCK_TARGET: usize = 64 * 1024;
pub const DEFAULT_BLOCK_TARGET: usize = 256 * 1024;
pub const MAX_BLOCK_TARGET: usize = 1024 * 1024;

/// §39: 64 registos entre restart points.
pub const DEFAULT_RESTART_INTERVAL: u16 = 64;

/// Bits de flags do bloco.
pub mod block_flags {
    /// LSN não contíguo dentro do bloco: cada registo carrega `lsn_delta`.
    pub const SPARSE_LSN: u8 = 1 << 0;
    /// HLC não monotónico: cada registo carrega o HLC absoluto em varint.
    /// §6 — o encoder **tem** de recusar `HLC_DELTA_MONOTONIC` quando encontra
    /// `HLC[n] < HLC[n-1]`, e sinalizar o encoding alternativo explicitamente.
    pub const HLC_ABSOLUTE: u8 = 1 << 1;
    /// §40: bloco com um único registo maior que o `block_target`.
    pub const LARGE_RECORD: u8 = 1 << 2;

    pub const KNOWN: u8 = SPARSE_LSN | HLC_ABSOLUTE | LARGE_RECORD;
}

/// Bits de flags por registo em `record_meta` (§36). Reservados no v1: o writer
/// escreve zero e o reader recusa outro valor, para que uma mesma sequência de
/// registos tenha um único byte stream válido.
pub const RECORD_FLAG_BITS: u32 = 3;
const RECORD_FLAG_MASK: u64 = (1 << RECORD_FLAG_BITS) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeaderV1 {
    pub codec: CompressionCodec,
    pub flags: u8,
    pub uncompressed_len: u32,
    pub compressed_len: u32,
    pub record_count: u32,
    pub restart_interval: u16,
    pub restart_count: u16,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub base_hlc: u64,
    pub max_hlc: u64,
    pub dictionary_id: u32,
}

impl BlockHeaderV1 {
    fn encode_with_crc(&self, crc: u32) -> [u8; BLOCK_HEADER_LEN] {
        let mut b = [0u8; BLOCK_HEADER_LEN];
        b[0..4].copy_from_slice(&BLOCK_MAGIC);
        b[4..6].copy_from_slice(&(BLOCK_HEADER_LEN as u16).to_le_bytes());
        b[6] = self.codec as u8;
        b[7] = self.flags;
        b[8..12].copy_from_slice(&self.uncompressed_len.to_le_bytes());
        b[12..16].copy_from_slice(&self.compressed_len.to_le_bytes());
        b[16..20].copy_from_slice(&self.record_count.to_le_bytes());
        b[20..22].copy_from_slice(&self.restart_interval.to_le_bytes());
        b[22..24].copy_from_slice(&self.restart_count.to_le_bytes());
        b[24..32].copy_from_slice(&self.first_lsn.to_le_bytes());
        b[32..40].copy_from_slice(&self.last_lsn.to_le_bytes());
        b[40..48].copy_from_slice(&self.base_hlc.to_le_bytes());
        b[48..56].copy_from_slice(&self.max_hlc.to_le_bytes());
        b[56..60].copy_from_slice(&crc.to_le_bytes());
        b[60..64].copy_from_slice(&self.dictionary_id.to_le_bytes());
        b
    }

    /// Codifica o header **e** calcula o CRC de §48 sobre header-com-crc-zero
    /// mais os bytes armazenados.
    pub fn encode(&self, stored: &[u8]) -> [u8; BLOCK_HEADER_LEN] {
        let zeroed = self.encode_with_crc(0);
        let mut h = crate::cpm::Crc32c::new();
        h.update(&zeroed);
        h.update(stored);
        let crc = h.finalize();
        self.encode_with_crc(crc)
    }

    /// Descodifica o header e valida o CRC contra `stored`.
    ///
    /// `stored` tem de ser exactamente os `compressed_len` bytes que seguem o
    /// header — quem chama é responsável por os delimitar contra o tamanho real
    /// do ficheiro antes de aqui chegar.
    pub fn decode(buf: &[u8], stored: &[u8]) -> V6Result<Self> {
        const CTX: &str = "hrkl v6 block header";
        if buf.len() < BLOCK_HEADER_LEN {
            return Err(corrupt(CTX, "short block header"));
        }
        if buf[0..4] != BLOCK_MAGIC {
            return Err(corrupt(CTX, "bad block magic"));
        }
        let header_len = u16::from_le_bytes(buf[4..6].try_into().unwrap()) as usize;
        if header_len != BLOCK_HEADER_LEN {
            return Err(corrupt(
                CTX,
                format!("header_len {header_len} != {BLOCK_HEADER_LEN}"),
            ));
        }
        let stored_crc = u32::from_le_bytes(buf[56..60].try_into().unwrap());
        let mut zeroed = [0u8; BLOCK_HEADER_LEN];
        zeroed.copy_from_slice(&buf[..BLOCK_HEADER_LEN]);
        zeroed[56..60].fill(0);
        let mut h = crate::cpm::Crc32c::new();
        h.update(&zeroed);
        h.update(stored);
        let actual = h.finalize();
        if stored_crc != actual {
            return Err(corrupt(
                CTX,
                format!("crc32c mismatch: stored {stored_crc:#010x}, actual {actual:#010x}"),
            ));
        }

        let flags = buf[7];
        if flags & !block_flags::KNOWN != 0 {
            return Err(corrupt(
                CTX,
                format!("unknown block flag bits in {flags:#04x}"),
            ));
        }
        let hdr = Self {
            codec: CompressionCodec::from_u8(buf[6])?,
            flags,
            uncompressed_len: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            compressed_len: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            record_count: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            restart_interval: u16::from_le_bytes(buf[20..22].try_into().unwrap()),
            restart_count: u16::from_le_bytes(buf[22..24].try_into().unwrap()),
            first_lsn: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            last_lsn: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            base_hlc: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            max_hlc: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
            dictionary_id: u32::from_le_bytes(buf[60..64].try_into().unwrap()),
        };
        hdr.check_coherence(stored.len())?;
        Ok(hdr)
    }

    fn check_coherence(&self, stored_len: usize) -> V6Result<()> {
        const CTX: &str = "hrkl v6 block header";
        if self.compressed_len as usize != stored_len {
            return Err(corrupt(
                CTX,
                format!(
                    "compressed_len {} != {stored_len} stored bytes",
                    self.compressed_len
                ),
            ));
        }
        if self.uncompressed_len as usize > HARD_MAX_BLOCK_BYTES {
            return Err(corrupt(
                CTX,
                format!(
                    "uncompressed_len {} above hard maximum",
                    self.uncompressed_len
                ),
            ));
        }
        if self.record_count == 0 {
            return Err(corrupt(CTX, "empty block"));
        }
        if self.first_lsn > self.last_lsn {
            return Err(corrupt(CTX, "first_lsn > last_lsn"));
        }
        if self.base_hlc > self.max_hlc {
            return Err(corrupt(CTX, "base_hlc > max_hlc"));
        }
        if self.restart_interval == 0 {
            return Err(corrupt(CTX, "restart_interval is zero"));
        }
        let expected_restarts = self.record_count.div_ceil(self.restart_interval as u32);
        if self.restart_count as u32 != expected_restarts {
            return Err(corrupt(
                CTX,
                format!(
                    "restart_count {} != ceil({}/{})",
                    self.restart_count, self.record_count, self.restart_interval
                ),
            ));
        }
        let restart_bytes = self.restart_count as usize * RESTART_ENTRY_LEN;
        if restart_bytes > self.uncompressed_len as usize {
            return Err(corrupt(CTX, "restart array does not fit in the block"));
        }
        if !self.is_sparse_lsn() {
            let span = self.last_lsn - self.first_lsn;
            if span.saturating_add(1) != self.record_count as u64 {
                return Err(corrupt(
                    CTX,
                    "contiguous block whose LSN span does not match record_count",
                ));
            }
        }
        Ok(())
    }

    #[inline]
    pub fn is_sparse_lsn(&self) -> bool {
        self.flags & block_flags::SPARSE_LSN != 0
    }
    #[inline]
    pub fn is_hlc_absolute(&self) -> bool {
        self.flags & block_flags::HLC_ABSOLUTE != 0
    }
    #[inline]
    pub fn is_large_record(&self) -> bool {
        self.flags & block_flags::LARGE_RECORD != 0
    }

    /// Bytes da região de registos (o resto é o array de restart points).
    #[inline]
    pub fn records_region_len(&self) -> usize {
        self.uncompressed_len as usize - self.restart_count as usize * RESTART_ENTRY_LEN
    }

    pub fn to_directory_entry(&self, offset: u64) -> BlockDirectoryEntryV1 {
        BlockDirectoryEntryV1 {
            offset,
            stored_len: self.compressed_len,
            uncompressed_len: self.uncompressed_len,
            record_count: self.record_count,
            flags: self.flags as u32,
            first_lsn: self.first_lsn,
            last_lsn: self.last_lsn,
            min_hlc: self.base_hlc,
            max_hlc: self.max_hlc,
        }
    }
}

// ---------------------------------------------------------------------------
// Restart points
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPoint {
    pub ordinal: u32,
    pub byte_offset: u32,
    pub absolute_hlc: u64,
    pub absolute_lsn: Lsn,
}

impl RestartPoint {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ordinal.to_le_bytes());
        out.extend_from_slice(&self.byte_offset.to_le_bytes());
        out.extend_from_slice(&self.absolute_hlc.to_le_bytes());
        out.extend_from_slice(&self.absolute_lsn.to_le_bytes());
    }
    fn decode(buf: &[u8]) -> Self {
        Self {
            ordinal: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            byte_offset: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            absolute_hlc: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            absolute_lsn: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Um registo à espera de entrar num bloco.
#[derive(Debug, Clone)]
pub struct PendingRecord {
    pub lsn: Lsn,
    pub hlc: u64,
    pub payload: Vec<u8>,
}

/// Bloco pronto a gravar.
pub struct BuiltBlock {
    pub header: BlockHeaderV1,
    pub header_bytes: [u8; BLOCK_HEADER_LEN],
    pub stored: Vec<u8>,
    /// Bytes lógicos (soma dos payloads) — para o rácio de compressão real.
    pub logical_payload_bytes: u64,
}

impl BuiltBlock {
    pub fn total_len(&self) -> usize {
        BLOCK_HEADER_LEN + self.stored.len()
    }
}

/// Acumula registos até ao `block_target` e produz o bloco.
pub struct BlockBuilder {
    records: Vec<PendingRecord>,
    approx_uncompressed: usize,
    block_target: usize,
    restart_interval: u16,
}

impl BlockBuilder {
    pub fn new(block_target: usize, restart_interval: u16) -> Self {
        Self {
            records: Vec::new(),
            approx_uncompressed: 0,
            block_target: block_target.clamp(MIN_BLOCK_TARGET, MAX_BLOCK_TARGET),
            restart_interval: restart_interval.max(1),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn approx_bytes(&self) -> usize {
        self.approx_uncompressed
    }

    /// `true` se acrescentar `payload_len` bytes ultrapassa o alvo — sinal para
    /// o packer fechar o bloco antes de empurrar o registo.
    pub fn would_overflow(&self, payload_len: usize) -> bool {
        !self.records.is_empty() && self.approx_uncompressed + payload_len + 16 > self.block_target
    }

    pub fn push(&mut self, lsn: Lsn, hlc: u64, payload: Vec<u8>) {
        self.approx_uncompressed += payload.len() + 16;
        self.records.push(PendingRecord { lsn, hlc, payload });
    }

    /// Fecha o bloco: escolhe o encoding, serializa, comprime com fallback e
    /// carimba o CRC.
    pub fn finish(
        &mut self,
        profile: PackingProfile,
        raw_fallback_ratio: f32,
    ) -> V6Result<Option<BuiltBlock>> {
        if self.records.is_empty() {
            return Ok(None);
        }
        let records = std::mem::take(&mut self.records);
        self.approx_uncompressed = 0;
        let built = build_block(&records, self.restart_interval, profile, raw_fallback_ratio)?;
        Ok(Some(built))
    }
}

/// Serializa e comprime um conjunto de registos num bloco.
pub fn build_block(
    records: &[PendingRecord],
    restart_interval: u16,
    profile: PackingProfile,
    raw_fallback_ratio: f32,
) -> V6Result<BuiltBlock> {
    const CTX: &str = "hrkl v6 block builder";
    if records.is_empty() {
        return Err(corrupt(CTX, "cannot build an empty block"));
    }
    let restart_interval = restart_interval.max(1);
    let first_lsn = records[0].lsn;
    let last_lsn = records[records.len() - 1].lsn;
    // `base_hlc` é o MÍNIMO do bloco, não simplesmente o HLC do primeiro
    // registo: em modo monotónico as duas coisas coincidem, mas num bloco
    // HLC_ABSOLUTE (§6) um registo pode recuar no tempo, e usar o primeiro como
    // limite inferior do zone map produziria um falso negativo de pruning —
    // exactamente o que o invariante 8 proíbe.
    let base_hlc = records.iter().map(|r| r.hlc).min().unwrap();

    // Decisões de encoding — tomadas ANTES de escrever um único byte.
    let contiguous = records
        .iter()
        .enumerate()
        .all(|(i, r)| r.lsn == first_lsn.wrapping_add(i as u64));
    let monotonic_hlc = records.windows(2).all(|w| w[1].hlc >= w[0].hlc);

    let mut flags = 0u8;
    if !contiguous {
        flags |= block_flags::SPARSE_LSN;
    }
    if !monotonic_hlc {
        // §6: rejeitar HLC_DELTA_MONOTONIC e sinalizar o alternativo.
        flags |= block_flags::HLC_ABSOLUTE;
    }
    if records.len() == 1 && records[0].payload.len() > DEFAULT_BLOCK_TARGET {
        flags |= block_flags::LARGE_RECORD;
    }

    let sparse = flags & block_flags::SPARSE_LSN != 0;
    let hlc_absolute = flags & block_flags::HLC_ABSOLUTE != 0;

    let mut body = Vec::with_capacity(
        records.iter().map(|r| r.payload.len() + 12).sum::<usize>()
            + records.len().div_ceil(restart_interval as usize) * RESTART_ENTRY_LEN,
    );
    let mut restarts: Vec<RestartPoint> = Vec::new();
    let mut prev_lsn = first_lsn;
    let mut prev_hlc = records[0].hlc;
    let max_hlc = records.iter().map(|r| r.hlc).max().unwrap();

    for (i, r) in records.iter().enumerate() {
        // Num restart point o registo grava os valores ABSOLUTOS em vez de
        // deltas. É o que torna o salto de §39 possível — quem aterra ali não
        // viu nada antes — sem obrigar o varrimento sequencial a consultar o
        // array de restarts para não perder o fio. Custa ~4 bytes a cada
        // `restart_interval` registos.
        let is_restart = i.is_multiple_of(restart_interval as usize);
        if is_restart {
            restarts.push(RestartPoint {
                ordinal: i as u32,
                byte_offset: u32::try_from(body.len())
                    .map_err(|_| corrupt(CTX, "block body exceeds 4 GiB"))?,
                absolute_hlc: r.hlc,
                absolute_lsn: r.lsn,
            });
        }
        if r.payload.len() > HARD_MAX_RECORD_BYTES {
            return Err(corrupt(CTX, "record exceeds hard maximum"));
        }
        // §36: (payload_len << FLAG_BITS) | flags, para que len+flags caibam
        // normalmente num único varint.
        let meta = (r.payload.len() as u64) << RECORD_FLAG_BITS;
        put_varint(&mut body, meta);

        if sparse {
            if is_restart {
                put_varint(&mut body, r.lsn);
            } else {
                // LSN é monotónico crescente por construção do log.
                let delta = r
                    .lsn
                    .checked_sub(prev_lsn)
                    .ok_or_else(|| corrupt(CTX, "LSN went backwards"))?;
                put_varint(&mut body, delta);
            }
        }

        if hlc_absolute || is_restart {
            put_varint(&mut body, r.hlc);
        } else {
            let delta = r
                .hlc
                .checked_sub(prev_hlc)
                .ok_or_else(|| corrupt(CTX, "HLC went backwards in a monotonic block"))?;
            put_varint(&mut body, delta);
        }

        body.extend_from_slice(&r.payload);
        prev_lsn = r.lsn;
        prev_hlc = r.hlc;
    }

    let records_region_len = body.len();
    for rp in &restarts {
        rp.encode_into(&mut body);
    }

    let uncompressed_len =
        u32::try_from(body.len()).map_err(|_| corrupt(CTX, "block exceeds 4 GiB uncompressed"))?;
    let logical_payload_bytes: u64 = records.iter().map(|r| r.payload.len() as u64).sum();

    let compressed = compress_block(&body, profile, raw_fallback_ratio)?;
    let compressed_len = u32::try_from(compressed.bytes.len())
        .map_err(|_| corrupt(CTX, "block exceeds 4 GiB stored"))?;

    let header = BlockHeaderV1 {
        codec: compressed.codec,
        flags,
        uncompressed_len,
        compressed_len,
        record_count: records.len() as u32,
        restart_interval,
        restart_count: u16::try_from(restarts.len())
            .map_err(|_| corrupt(CTX, "too many restart points for u16"))?,
        first_lsn,
        last_lsn,
        base_hlc,
        max_hlc,
        dictionary_id: 0,
    };
    debug_assert_eq!(header.records_region_len(), records_region_len);
    let header_bytes = header.encode(&compressed.bytes);
    Ok(BuiltBlock {
        header,
        header_bytes,
        stored: compressed.bytes,
        logical_payload_bytes,
    })
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// Um registo lido de um bloco.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRecord<'a> {
    pub lsn: Lsn,
    pub hlc: u64,
    pub payload: &'a [u8],
}

/// Descomprime o corpo de um bloco, com o tecto de §140 aplicado.
pub fn decompress_body(
    header: &BlockHeaderV1,
    stored: &[u8],
    max_block: usize,
) -> V6Result<Vec<u8>> {
    decompress_block(
        header.codec,
        stored,
        header.uncompressed_len as usize,
        max_block,
    )
}

/// Lê os restart points do fim do corpo descomprimido.
pub fn read_restarts(header: &BlockHeaderV1, body: &[u8]) -> V6Result<Vec<RestartPoint>> {
    const CTX: &str = "hrkl v6 block restarts";
    let region = header.records_region_len();
    let mut out = Vec::with_capacity(header.restart_count as usize);
    for i in 0..header.restart_count as usize {
        let at = region + i * RESTART_ENTRY_LEN;
        let e = RestartPoint::decode(slice_at(body, at, RESTART_ENTRY_LEN, CTX)?);
        if e.byte_offset as usize >= region {
            return Err(corrupt(
                CTX,
                "restart byte_offset outside the records region",
            ));
        }
        if e.ordinal as usize != i * header.restart_interval as usize {
            return Err(corrupt(
                CTX,
                "restart ordinal does not follow restart_interval",
            ));
        }
        if e.ordinal >= header.record_count {
            return Err(corrupt(CTX, "restart ordinal beyond record_count"));
        }
        out.push(e);
    }
    if out
        .first()
        .map(|r| r.ordinal != 0 || r.byte_offset != 0)
        .unwrap_or(false)
    {
        return Err(corrupt(
            CTX,
            "first restart point must be at ordinal 0, offset 0",
        ));
    }
    Ok(out)
}

/// Descodifica todos os registos do bloco.
pub fn decode_block_records<'a>(
    header: &'a BlockHeaderV1,
    body: &'a [u8],
) -> V6Result<Vec<BlockRecord<'a>>> {
    let mut out = Vec::with_capacity(header.record_count as usize);
    let mut cur = RecordCursor::start(header, body)?;
    while let Some(r) = cur.next_record()? {
        out.push(r);
    }
    if out.len() != header.record_count as usize {
        return Err(corrupt(
            "hrkl v6 block",
            format!(
                "decoded {} records, header declares {}",
                out.len(),
                header.record_count
            ),
        ));
    }
    Ok(out)
}

/// Cursor sequencial sobre a região de registos de um bloco.
pub struct RecordCursor<'a> {
    header: &'a BlockHeaderV1,
    body: &'a [u8],
    region_end: usize,
    pos: usize,
    ordinal: u32,
    prev_lsn: Lsn,
    prev_hlc: u64,
}

impl<'a> RecordCursor<'a> {
    /// Cursor no início do bloco.
    pub fn start(header: &'a BlockHeaderV1, body: &'a [u8]) -> V6Result<Self> {
        const CTX: &str = "hrkl v6 block";
        if body.len() != header.uncompressed_len as usize {
            return Err(corrupt(CTX, "body length does not match uncompressed_len"));
        }
        Ok(Self {
            header,
            body,
            region_end: header.records_region_len(),
            pos: 0,
            ordinal: 0,
            prev_lsn: header.first_lsn,
            prev_hlc: header.base_hlc,
        })
    }

    /// Cursor posicionado num restart point — o salto de §39 que evita varrer o
    /// bloco desde o início.
    pub fn at_restart(
        header: &'a BlockHeaderV1,
        body: &'a [u8],
        rp: &RestartPoint,
    ) -> V6Result<Self> {
        let mut c = Self::start(header, body)?;
        c.pos = rp.byte_offset as usize;
        c.ordinal = rp.ordinal;
        c.prev_lsn = rp.absolute_lsn;
        c.prev_hlc = rp.absolute_hlc;
        Ok(c)
    }

    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub fn next_record(&mut self) -> V6Result<Option<BlockRecord<'a>>> {
        const CTX: &str = "hrkl v6 packed record";
        if self.ordinal >= self.header.record_count || self.pos >= self.region_end {
            return Ok(None);
        }
        let region = &self.body[..self.region_end];
        let (meta, n) = read_varint(&region[self.pos..], CTX)?;
        self.pos += n;
        let rec_flags = meta & RECORD_FLAG_MASK;
        if rec_flags != 0 {
            return Err(corrupt(CTX, "reserved record flag bits are set"));
        }
        let payload_len = usize::try_from(meta >> RECORD_FLAG_BITS)
            .map_err(|_| corrupt(CTX, "payload_len exceeds usize"))?;
        if payload_len > HARD_MAX_RECORD_BYTES {
            return Err(corrupt(CTX, "payload_len above hard maximum"));
        }

        // Num restart point os valores vêm absolutos (ver `build_block`), o que
        // permite aterrar no meio do bloco sem ter descodificado o que vem
        // antes.
        let is_restart_boundary = self
            .ordinal
            .is_multiple_of(self.header.restart_interval as u32);

        let lsn = if self.header.is_sparse_lsn() {
            let (raw, n) = read_varint(&region[self.pos..], CTX)?;
            self.pos += n;
            if is_restart_boundary {
                raw
            } else {
                self.prev_lsn
                    .checked_add(raw)
                    .ok_or_else(|| corrupt(CTX, "LSN delta overflows u64"))?
            }
        } else {
            self.header
                .first_lsn
                .checked_add(self.ordinal as u64)
                .ok_or_else(|| corrupt(CTX, "LSN overflows u64"))?
        };
        if lsn < self.header.first_lsn || lsn > self.header.last_lsn {
            return Err(corrupt(
                CTX,
                "record LSN falls outside the block's declared range",
            ));
        }

        let (hlc_raw, n) = read_varint(&region[self.pos..], CTX)?;
        self.pos += n;
        let hlc = if self.header.is_hlc_absolute() || is_restart_boundary {
            hlc_raw
        } else {
            self.prev_hlc
                .checked_add(hlc_raw)
                .ok_or_else(|| corrupt(CTX, "HLC delta overflows u64"))?
        };
        if hlc < self.header.base_hlc || hlc > self.header.max_hlc {
            return Err(corrupt(
                CTX,
                "record HLC falls outside the block's declared zone map",
            ));
        }

        let payload = slice_at(region, self.pos, payload_len, CTX)?;
        self.pos += payload_len;
        self.prev_lsn = lsn;
        self.prev_hlc = hlc;
        self.ordinal += 1;
        Ok(Some(BlockRecord { lsn, hlc, payload }))
    }
}

/// Point lookup dentro de um bloco (§77).
///
/// Do LSN ao ordinal, do ordinal ao restart anterior, e daí no máximo
/// `restart_interval - 1` registos varridos — nunca o bloco todo.
pub fn find_record_in_block<'a>(
    header: &'a BlockHeaderV1,
    body: &'a [u8],
    lsn: Lsn,
) -> V6Result<Option<BlockRecord<'a>>> {
    if lsn < header.first_lsn || lsn > header.last_lsn {
        return Ok(None);
    }
    let restarts = read_restarts(header, body)?;
    let start = if header.is_sparse_lsn() {
        // Sem ordinal derivável do LSN, os restart points guardam o LSN
        // absoluto — que dá na mesma uma busca binária.
        let idx = restarts.partition_point(|r| r.absolute_lsn <= lsn);
        restarts.get(idx.saturating_sub(1)).copied()
    } else {
        let ordinal = (lsn - header.first_lsn) as u32;
        restarts
            .get((ordinal / header.restart_interval as u32) as usize)
            .copied()
    };
    let Some(rp) = start else { return Ok(None) };

    let mut cur = RecordCursor::at_restart(header, body, &rp)?;
    let budget = header.restart_interval as u32;
    let mut seen = 0u32;
    while let Some(r) = cur.next_record()? {
        if r.lsn == lsn {
            return Ok(Some(r));
        }
        if r.lsn > lsn {
            return Ok(None);
        }
        seen += 1;
        if seen >= budget {
            // Passar daqui significaria que o restart point mentiu; parar é a
            // resposta conservadora.
            return Ok(None);
        }
    }
    Ok(None)
}

/// Estimativa do overhead físico de metadados por registo neste bloco — a
/// métrica do gate §156.
pub fn metadata_bytes_per_record(header: &BlockHeaderV1, records: &[PendingRecord]) -> f64 {
    let payload: usize = records.iter().map(|r| r.payload.len()).sum();
    let meta = header.uncompressed_len as usize - payload;
    meta as f64 / records.len() as f64
}

/// Bytes que `meta` ocuparia — útil para orçamentar sem codificar.
pub fn record_meta_len(payload_len: usize) -> usize {
    varint_len((payload_len as u64) << RECORD_FLAG_BITS)
}

/// Lê `count` varints consecutivos. Existe só para os testes de fuzz do
/// decoder de varint dentro de um corpo de bloco.
#[doc(hidden)]
pub fn debug_read_varints(buf: &[u8], count: usize) -> V6Result<Vec<u64>> {
    let mut out = Vec::new();
    let mut pos = 0;
    for _ in 0..count {
        let (v, n) = read_varint_usize(&buf[pos..], "debug")?;
        out.push(v as u64);
        pos += n;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recs(n: usize, first_lsn: u64, payload: &[u8]) -> Vec<PendingRecord> {
        (0..n)
            .map(|i| PendingRecord {
                lsn: first_lsn + i as u64,
                hlc: 1_000_000 + i as u64 * 7,
                payload: payload.to_vec(),
            })
            .collect()
    }

    fn build(records: &[PendingRecord]) -> BuiltBlock {
        build_block(
            records,
            DEFAULT_RESTART_INTERVAL,
            PackingProfile::Balanced,
            0.92,
        )
        .unwrap()
    }

    #[test]
    fn header_tem_64_bytes() {
        let b = build(&recs(4, 10, b"abc"));
        assert_eq!(b.header_bytes.len(), 64);
    }

    #[test]
    fn roundtrip_contiguo() {
        let records = recs(200, 9_000_001, b"conteudo repetido conteudo repetido");
        let b = build(&records);
        assert!(!b.header.is_sparse_lsn());
        assert!(!b.header.is_hlc_absolute());

        let hdr = BlockHeaderV1::decode(&b.header_bytes, &b.stored).unwrap();
        assert_eq!(hdr, b.header);
        let body = decompress_body(&hdr, &b.stored, HARD_MAX_BLOCK_BYTES).unwrap();
        let out = decode_block_records(&hdr, &body).unwrap();
        assert_eq!(out.len(), records.len());
        for (got, want) in out.iter().zip(&records) {
            assert_eq!(got.lsn, want.lsn);
            assert_eq!(got.hlc, want.hlc);
            assert_eq!(got.payload, &want.payload[..]);
        }
    }

    #[test]
    fn lsn_contiguo_nao_gasta_bytes_por_registo() {
        // §37: em CONTIGUOUS_LSN não há bytes de LSN por registo. Compara-se o
        // mesmo conjunto com e sem contiguidade.
        let cont = recs(100, 500, b"x");
        let mut sparse = cont.clone();
        sparse[50].lsn += 1000; // abre um buraco
        for r in sparse.iter_mut().skip(51) {
            r.lsn += 1000;
        }
        let a = build(&cont);
        let b = build(&sparse);
        assert!(!a.header.is_sparse_lsn());
        assert!(b.header.is_sparse_lsn());
        assert!(
            a.header.uncompressed_len < b.header.uncompressed_len,
            "o modo contíguo tem de ser estritamente menor: {} vs {}",
            a.header.uncompressed_len,
            b.header.uncompressed_len
        );
    }

    #[test]
    fn hlc_nao_monotonico_cai_para_absoluto_e_volta_igual() {
        let mut records = recs(70, 1, b"y");
        records[30].hlc = 1; // recua no tempo
        let b = build(&records);
        assert!(
            b.header.is_hlc_absolute(),
            "§6 exige sinalizar o encoding alternativo"
        );
        let hdr = BlockHeaderV1::decode(&b.header_bytes, &b.stored).unwrap();
        let body = decompress_body(&hdr, &b.stored, HARD_MAX_BLOCK_BYTES).unwrap();
        let out = decode_block_records(&hdr, &body).unwrap();
        for (got, want) in out.iter().zip(&records) {
            assert_eq!(got.hlc, want.hlc);
        }
    }

    #[test]
    fn roundtrip_esparso() {
        let mut records = recs(150, 77, b"esparso");
        for (i, r) in records.iter_mut().enumerate() {
            r.lsn = 77 + (i as u64) * 3; // buracos regulares
        }
        let b = build(&records);
        assert!(b.header.is_sparse_lsn());
        let hdr = BlockHeaderV1::decode(&b.header_bytes, &b.stored).unwrap();
        let body = decompress_body(&hdr, &b.stored, HARD_MAX_BLOCK_BYTES).unwrap();
        let out = decode_block_records(&hdr, &body).unwrap();
        for (got, want) in out.iter().zip(&records) {
            assert_eq!(got.lsn, want.lsn);
            assert_eq!(got.hlc, want.hlc);
        }
    }

    #[test]
    fn point_lookup_encontra_todos_os_lsn() {
        for sparse in [false, true] {
            let mut records = recs(200, 3000, b"payload de teste");
            if sparse {
                for (i, r) in records.iter_mut().enumerate() {
                    r.lsn = 3000 + i as u64 * 5;
                }
            }
            let b = build(&records);
            let hdr = BlockHeaderV1::decode(&b.header_bytes, &b.stored).unwrap();
            let body = decompress_body(&hdr, &b.stored, HARD_MAX_BLOCK_BYTES).unwrap();
            for want in &records {
                let got = find_record_in_block(&hdr, &body, want.lsn).unwrap();
                let got = got
                    .unwrap_or_else(|| panic!("sparse={sparse} lsn={} não encontrado", want.lsn));
                assert_eq!(got.hlc, want.hlc);
                assert_eq!(got.payload, &want.payload[..]);
            }
            assert!(find_record_in_block(&hdr, &body, 1).unwrap().is_none());
            assert!(find_record_in_block(&hdr, &body, u64::MAX)
                .unwrap()
                .is_none());
            if sparse {
                // Um LSN no buraco não existe.
                assert!(find_record_in_block(&hdr, &body, 3001).unwrap().is_none());
            }
        }
    }

    #[test]
    fn restart_points_batem_com_o_intervalo() {
        let records = recs(200, 1, b"z");
        let b = build_block(&records, 64, PackingProfile::Balanced, 0.92).unwrap();
        assert_eq!(b.header.restart_count, 4); // ceil(200/64)
        let hdr = BlockHeaderV1::decode(&b.header_bytes, &b.stored).unwrap();
        let body = decompress_body(&hdr, &b.stored, HARD_MAX_BLOCK_BYTES).unwrap();
        let rs = read_restarts(&hdr, &body).unwrap();
        assert_eq!(rs.len(), 4);
        assert_eq!(rs[0].ordinal, 0);
        assert_eq!(rs[1].ordinal, 64);
        assert_eq!(rs[3].ordinal, 192);
        // Cada restart tem de dar exactamente o registo desse ordinal.
        for rp in &rs {
            let mut c = RecordCursor::at_restart(&hdr, &body, rp).unwrap();
            let r = c.next_record().unwrap().unwrap();
            assert_eq!(r.lsn, records[rp.ordinal as usize].lsn);
            assert_eq!(r.hlc, records[rp.ordinal as usize].hlc);
        }
    }

    #[test]
    fn crc_apanha_corrupcao_no_header_e_no_payload() {
        let b = build(&recs(20, 1, b"abcdefgh"));
        for i in 0..BLOCK_HEADER_LEN {
            if (56..60).contains(&i) {
                continue;
            }
            let mut h = b.header_bytes;
            h[i] ^= 0xff;
            assert!(
                BlockHeaderV1::decode(&h, &b.stored).is_err(),
                "flip no header byte {i} passou"
            );
        }
        let mut s = b.stored.clone();
        s[0] ^= 0xff;
        assert!(
            BlockHeaderV1::decode(&b.header_bytes, &s).is_err(),
            "flip no payload passou"
        );
    }

    #[test]
    fn bloco_de_registo_grande() {
        let big = vec![7u8; DEFAULT_BLOCK_TARGET + 1000];
        let records = vec![PendingRecord {
            lsn: 42,
            hlc: 99,
            payload: big.clone(),
        }];
        let b = build(&records);
        assert!(b.header.is_large_record());
        assert_eq!(b.header.record_count, 1);
        let hdr = BlockHeaderV1::decode(&b.header_bytes, &b.stored).unwrap();
        let body = decompress_body(&hdr, &b.stored, HARD_MAX_BLOCK_BYTES).unwrap();
        let out = decode_block_records(&hdr, &body).unwrap();
        assert_eq!(out[0].payload, &big[..]);
    }

    #[test]
    fn builder_fecha_no_alvo() {
        let mut bb = BlockBuilder::new(MIN_BLOCK_TARGET, 64);
        let payload = vec![1u8; 4096];
        let mut n = 0u64;
        while !bb.would_overflow(payload.len()) {
            bb.push(1000 + n, 500 + n, payload.clone());
            n += 1;
            assert!(n < 1000, "o builder devia ter fechado");
        }
        assert!(bb.approx_bytes() <= MIN_BLOCK_TARGET);
        let built = bb.finish(PackingProfile::Balanced, 0.92).unwrap().unwrap();
        assert_eq!(built.header.record_count as u64, n);
        assert!(bb.is_empty());
        assert!(bb.finish(PackingProfile::Balanced, 0.92).unwrap().is_none());
    }

    #[test]
    fn header_incoerente_e_recusado() {
        let b = build(&recs(10, 5, b"abc"));
        // restart_count mentiroso
        let mut hdr = b.header;
        hdr.restart_count = 9;
        let bytes = hdr.encode(&b.stored);
        assert!(BlockHeaderV1::decode(&bytes, &b.stored).is_err());

        // bloco vazio
        let mut hdr = b.header;
        hdr.record_count = 0;
        let bytes = hdr.encode(&b.stored);
        assert!(BlockHeaderV1::decode(&bytes, &b.stored).is_err());

        // contíguo com span errado
        let mut hdr = b.header;
        hdr.last_lsn += 5;
        let bytes = hdr.encode(&b.stored);
        assert!(BlockHeaderV1::decode(&bytes, &b.stored).is_err());
    }

    #[test]
    fn flags_desconhecidas_sao_recusadas() {
        let b = build(&recs(10, 5, b"abc"));
        let mut hdr = b.header;
        hdr.flags = 0x80;
        let bytes = hdr.encode(&b.stored);
        assert!(BlockHeaderV1::decode(&bytes, &b.stored).is_err());
    }

    #[test]
    fn corpo_truncado_nao_entra_em_panico() {
        let b = build(&recs(30, 1, b"abcdefgh"));
        let hdr = BlockHeaderV1::decode(&b.header_bytes, &b.stored).unwrap();
        let body = decompress_body(&hdr, &b.stored, HARD_MAX_BLOCK_BYTES).unwrap();
        for n in 0..body.len() {
            let _ = decode_block_records(&hdr, &body[..n]);
            let _ = read_restarts(&hdr, &body[..n]);
            let _ = find_record_in_block(&hdr, &body[..n], 5);
        }
    }

    #[test]
    fn overhead_de_metadados_cai_face_aos_24_bytes_raw() {
        // §156: metadados físicos por registo em modo contíguo/monotónico têm
        // de cair >= 60% face aos 24 bytes do RAW.
        let payload = [0u8; 200];
        let records = recs(1000, 1, &payload);
        let b = build(&records);
        let per_record = metadata_bytes_per_record(&b.header, &records);
        assert!(
            per_record <= 24.0 * 0.4,
            "overhead de {per_record:.2} B/registo não cumpre o gate de 60% de redução"
        );
    }
}
