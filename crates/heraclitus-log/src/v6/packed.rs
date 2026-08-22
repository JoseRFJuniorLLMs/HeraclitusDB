//! SPEC-0050 §28, §49, §76–§77, §85, §116 — o segmento **PACKED** e a sua
//! fronteira de leitura.
//!
//! ```text
//! ┌──────────────────────────┐
//! │ FileHeaderV6             │
//! ├──────────────────────────┤
//! │ Block 0 .. Block N       │
//! ├──────────────────────────┤
//! │ Block Directory          │
//! ├──────────────────────────┤
//! │ FooterV6                 │
//! └──────────────────────────┘
//! ```
//!
//! # A fronteira de leitura é uma só
//!
//! §115: *storage não deve duplicar paths para cada motor*. O planner —
//! HUME no caminho rápido, DataFusion no fallback — fala com
//! [`BlockSource`], que esconde ficheiro local, mmap, leitura posicional e
//! object storage. §85: sobre object storage o recall deixa de ser "descarregar
//! o segmento inteiro" e passa a ser footer → directório → `GET` por intervalo
//! dos blocos que sobrevivem ao pruning.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use heraclitus_core::Lsn;

use super::block::{
    build_block, decode_block_records, decompress_body, find_record_in_block, BlockBuilder,
    BlockHeaderV1, BlockRecord, PendingRecord, BLOCK_HEADER_LEN, DEFAULT_BLOCK_TARGET,
    DEFAULT_RESTART_INTERVAL,
};
use super::block_directory::{BlockDirectory, DIR_ENTRY_LEN};
use super::canonical::CANONICAL_CODEC_V1;
use super::compress::{PackingProfile, DEFAULT_RAW_FALLBACK_RATIO};
use super::error::{corrupt, V6Result, HARD_MAX_BLOCK_BYTES};
use super::footer::{footer_flags, FooterV6, FOOTER_LEN};
use super::header::{header_flags, FileHeaderV6, PhysicalLayout, FILE_HEADER_LEN};
use super::merkle::MerkleAccumulatorV1;
use super::raw::SegmentInit;

/// Configuração de packing (SPEC-0050 §148).
#[derive(Debug, Clone, Copy)]
pub struct PackOptions {
    pub block_target_bytes: usize,
    pub restart_interval: u16,
    pub profile: PackingProfile,
    pub raw_fallback_ratio: f32,
    /// Tecto de descompressão do leitor (§140).
    pub max_block_bytes: usize,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            block_target_bytes: DEFAULT_BLOCK_TARGET,
            restart_interval: DEFAULT_RESTART_INTERVAL,
            profile: PackingProfile::Balanced,
            raw_fallback_ratio: DEFAULT_RAW_FALLBACK_RATIO,
            max_block_bytes: HARD_MAX_BLOCK_BYTES,
        }
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Estatísticas de um packing, para a telemetria de §150.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PackStats {
    pub record_count: u64,
    pub block_count: u32,
    pub logical_payload_bytes: u64,
    pub uncompressed_block_bytes: u64,
    pub stored_block_bytes: u64,
    pub physical_size: u64,
}

impl PackStats {
    /// `stored / uncompressed`. Menor é melhor; 1.0 é RAW fallback em toda a
    /// linha.
    pub fn compression_ratio(&self) -> f64 {
        if self.uncompressed_block_bytes == 0 {
            return 1.0;
        }
        self.stored_block_bytes as f64 / self.uncompressed_block_bytes as f64
    }
}

/// Escreve um segmento PACKED.
pub struct PackedSegmentWriter {
    file: File,
    opts: PackOptions,
    builder: BlockBuilder,
    directory: BlockDirectory,
    acc: MerkleAccumulatorV1,
    offset: u64,
    record_count: u64,
    min_lsn: Lsn,
    max_lsn: Lsn,
    min_hlc: u64,
    max_hlc: u64,
    next_expected_lsn: Lsn,
    contiguous: bool,
    any_non_monotonic_hlc: bool,
    stats: PackStats,
}

impl PackedSegmentWriter {
    pub fn create(path: &Path, init: SegmentInit, opts: PackOptions) -> V6Result<Self> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .open(path)?;
        let header = FileHeaderV6 {
            physical_layout: PhysicalLayout::Packed,
            canonical_codec: CANONICAL_CODEC_V1,
            flags: header_flags::CONTIGUOUS_LSN,
            segment_id: init.segment_id,
            created_hlc: init.created_hlc,
            first_lsn: init.first_lsn,
            writer_epoch: init.writer_epoch,
            storage_namespace_id: init.storage_namespace_id,
        };
        file.write_all(&header.encode())?;
        Ok(Self {
            file,
            opts,
            builder: BlockBuilder::new(opts.block_target_bytes, opts.restart_interval),
            directory: BlockDirectory::default(),
            acc: MerkleAccumulatorV1::new(),
            offset: FILE_HEADER_LEN as u64,
            record_count: 0,
            min_lsn: u64::MAX,
            max_lsn: 0,
            min_hlc: u64::MAX,
            max_hlc: 0,
            next_expected_lsn: init.first_lsn,
            contiguous: true,
            any_non_monotonic_hlc: false,
            stats: PackStats::default(),
        })
    }

    /// Acrescenta um registo. `canonical_record_hash` vem de quem sabe
    /// descodificar o payload — o packer **não** reinterpreta payloads.
    pub fn push(
        &mut self,
        lsn: Lsn,
        hlc: u64,
        payload: Vec<u8>,
        canonical_record_hash: &[u8; 32],
    ) -> V6Result<()> {
        // Um registo maior que o alvo vai sozinho para um LARGE_RECORD_BLOCK
        // (§40): não é partido entre blocos, o que simplifica recuperação,
        // random access, integridade, compressão e provas.
        if self.builder.would_overflow(payload.len()) {
            self.flush_block()?;
        }
        if lsn != self.next_expected_lsn {
            self.contiguous = false;
        }
        self.next_expected_lsn = lsn.saturating_add(1);
        if self.record_count > 0 && hlc < self.max_hlc {
            self.any_non_monotonic_hlc = true;
        }
        self.min_lsn = self.min_lsn.min(lsn);
        self.max_lsn = self.max_lsn.max(lsn);
        self.min_hlc = self.min_hlc.min(hlc);
        self.max_hlc = self.max_hlc.max(hlc);
        self.record_count += 1;
        self.acc.push_record_hash(canonical_record_hash);
        self.builder.push(lsn, hlc, payload);
        if self.builder.approx_bytes() >= self.opts.block_target_bytes {
            self.flush_block()?;
        }
        Ok(())
    }

    fn flush_block(&mut self) -> V6Result<()> {
        let Some(built) = self
            .builder
            .finish(self.opts.profile, self.opts.raw_fallback_ratio)?
        else {
            return Ok(());
        };
        self.file.write_all(&built.header_bytes)?;
        self.file.write_all(&built.stored)?;
        let entry = built.header.to_directory_entry(self.offset);
        self.stats.uncompressed_block_bytes += built.header.uncompressed_len as u64;
        self.stats.stored_block_bytes += built.stored.len() as u64;
        self.stats.logical_payload_bytes += built.logical_payload_bytes;
        self.offset += built.total_len() as u64;
        self.directory.entries.push(entry);
        Ok(())
    }

    /// Fecha o segmento: bloco pendente, directório, footer, `fsync`.
    pub fn finish(mut self) -> V6Result<(FooterV6, PackStats)> {
        self.flush_block()?;
        let dir_offset = self.offset;
        let dir_bytes = self.directory.encode();
        self.file.write_all(&dir_bytes)?;
        self.offset += dir_bytes.len() as u64;

        let mut flags = 0u32;
        if self.contiguous && self.record_count > 0 {
            flags |= footer_flags::CONTIGUOUS_LSN;
        }
        if self.any_non_monotonic_hlc {
            flags |= footer_flags::HAS_NON_MONOTONIC_HLC;
        }
        let footer = FooterV6 {
            record_count: self.record_count,
            min_lsn: if self.record_count == 0 {
                0
            } else {
                self.min_lsn
            },
            max_lsn: if self.record_count == 0 {
                0
            } else {
                self.max_lsn
            },
            min_hlc: if self.record_count == 0 {
                0
            } else {
                self.min_hlc
            },
            max_hlc: if self.record_count == 0 {
                0
            } else {
                self.max_hlc
            },
            block_count: self.directory.len() as u32,
            flags,
            block_directory_offset: dir_offset,
            block_directory_len: dir_bytes.len() as u64,
            logical_root: self.acc.finalize(),
        };
        self.file.write_all(&footer.encode())?;
        self.file.sync_all()?;

        let mut stats = self.stats;
        stats.record_count = self.record_count;
        stats.block_count = self.directory.len() as u32;
        stats.physical_size = self.offset + FOOTER_LEN as u64;
        Ok((footer, stats))
    }
}

// ---------------------------------------------------------------------------
// Fronteira de leitura
// ---------------------------------------------------------------------------

/// Origem de bytes de um segmento (§116). Esconde FS local, mmap, leitura
/// posicional e object storage por detrás de uma leitura por intervalo.
pub trait BlockSource {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read_at(&self, offset: u64, len: usize) -> V6Result<Vec<u8>>;
}

/// Segmento inteiro em memória (mmap, cache, teste).
pub struct MemorySource(pub Vec<u8>);

impl BlockSource for MemorySource {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, offset: u64, len: usize) -> V6Result<Vec<u8>> {
        let start = usize::try_from(offset)
            .map_err(|_| corrupt("hrkl v6 source", "offset exceeds usize"))?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| corrupt("hrkl v6 source", "offset+len overflows usize"))?;
        self.0.get(start..end).map(|s| s.to_vec()).ok_or_else(|| {
            corrupt(
                "hrkl v6 source",
                format!("range [{start}..{end}] past end of segment"),
            )
        })
    }
}

/// Ficheiro local com leituras posicionais — o análogo do `GET` por intervalo.
pub struct FileSource {
    file: File,
    len: u64,
}

impl FileSource {
    pub fn open(path: &Path) -> V6Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }
}

impl BlockSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_at(&self, offset: u64, len: usize) -> V6Result<Vec<u8>> {
        if offset.saturating_add(len as u64) > self.len {
            return Err(corrupt("hrkl v6 source", "range past end of segment"));
        }
        let mut buf = vec![0u8; len];
        // `&File` implementa `Read`+`Seek`, o que evita `&mut self` e permite
        // leituras concorrentes a partir de um leitor partilhado.
        let mut f = &self.file;
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(&mut buf)?;
        Ok(buf)
    }
}

/// Contadores do que uma consulta leu e do que evitou ler — a matéria-prima do
/// `EXPLAIN` de §151.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanCounters {
    pub blocks_candidate: u64,
    pub blocks_pruned: u64,
    pub blocks_read: u64,
    pub bytes_physical_read: u64,
    pub bytes_decompressed: u64,
}

/// Leitor de um segmento PACKED.
pub struct PackedSegmentReader<S: BlockSource> {
    source: S,
    pub header: FileHeaderV6,
    pub footer: FooterV6,
    pub directory: BlockDirectory,
    max_block_bytes: usize,
}

impl<S: BlockSource> PackedSegmentReader<S> {
    /// Abre o segmento lendo apenas header, footer e directório — nunca os
    /// blocos (§159: o arranque não pode exigir varrimento integral).
    pub fn open(source: S, max_block_bytes: usize) -> V6Result<Self> {
        const CTX: &str = "hrkl v6 packed open";
        let len = source.len();
        if len < (FILE_HEADER_LEN + FOOTER_LEN) as u64 {
            return Err(corrupt(CTX, "file too small to hold a header and a footer"));
        }
        let header = FileHeaderV6::decode(&source.read_at(0, FILE_HEADER_LEN)?)?;
        if header.physical_layout != PhysicalLayout::Packed {
            return Err(corrupt(CTX, "segment is not PACKED"));
        }
        let footer = FooterV6::decode(&source.read_at(len - FOOTER_LEN as u64, FOOTER_LEN)?)?;

        let dir_end = footer
            .block_directory_offset
            .checked_add(footer.block_directory_len)
            .ok_or_else(|| corrupt(CTX, "block directory range overflows u64"))?;
        if dir_end > len - FOOTER_LEN as u64 {
            return Err(corrupt(CTX, "block directory overlaps the footer"));
        }
        let dir_len = usize::try_from(footer.block_directory_len)
            .map_err(|_| corrupt(CTX, "block directory too large for this platform"))?;
        if dir_len != footer.block_count as usize * DIR_ENTRY_LEN {
            return Err(corrupt(
                CTX,
                "block_directory_len inconsistent with block_count",
            ));
        }
        let dir_bytes = source.read_at(footer.block_directory_offset, dir_len)?;
        let directory = BlockDirectory::decode(
            &dir_bytes,
            footer.block_count,
            footer.block_directory_offset,
        )?;

        let declared: u64 = directory
            .entries
            .iter()
            .map(|e| e.record_count as u64)
            .sum();
        if declared != footer.record_count {
            return Err(corrupt(
                CTX,
                format!(
                    "directory accounts for {declared} records, footer declares {}",
                    footer.record_count
                ),
            ));
        }
        Ok(Self {
            source,
            header,
            footer,
            directory,
            max_block_bytes,
        })
    }

    pub fn block_count(&self) -> usize {
        self.directory.len()
    }

    pub fn logical_root(&self) -> [u8; 32] {
        self.footer.logical_root
    }

    /// Lê e descomprime um bloco. Uma leitura física por bloco.
    pub fn read_block(
        &self,
        index: usize,
        counters: &mut ScanCounters,
    ) -> V6Result<(BlockHeaderV1, Vec<u8>)> {
        const CTX: &str = "hrkl v6 packed block";
        let entry = self
            .directory
            .entries
            .get(index)
            .ok_or_else(|| corrupt(CTX, format!("block {index} out of range")))?;
        let total = BLOCK_HEADER_LEN
            .checked_add(entry.stored_len as usize)
            .ok_or_else(|| corrupt(CTX, "block length overflows usize"))?;
        let bytes = self.source.read_at(entry.offset, total)?;
        counters.blocks_read += 1;
        counters.bytes_physical_read += total as u64;

        let header = BlockHeaderV1::decode(&bytes[..BLOCK_HEADER_LEN], &bytes[BLOCK_HEADER_LEN..])?;
        // O directório e o header do bloco têm de contar a mesma história; se
        // divergirem, um deles foi adulterado depois do CRC ter sido recalculado.
        if header.first_lsn != entry.first_lsn
            || header.last_lsn != entry.last_lsn
            || header.record_count != entry.record_count
            || header.uncompressed_len != entry.uncompressed_len
        {
            return Err(corrupt(
                CTX,
                format!("block {index} header disagrees with the directory"),
            ));
        }
        let body = decompress_body(&header, &bytes[BLOCK_HEADER_LEN..], self.max_block_bytes)?;
        counters.bytes_decompressed += body.len() as u64;
        Ok((header, body))
    }

    /// Point lookup por LSN (§77).
    ///
    /// **Invariante duro de §157:** no caminho normal descomprime no máximo um
    /// bloco. O `ScanCounters` devolvido prova-o.
    pub fn get(&self, lsn: Lsn, counters: &mut ScanCounters) -> V6Result<Option<(u64, Vec<u8>)>> {
        counters.blocks_candidate += self.directory.len() as u64;
        let Some(index) = self.directory.find_block_for_lsn(lsn) else {
            counters.blocks_pruned += self.directory.len() as u64;
            return Ok(None);
        };
        counters.blocks_pruned += self.directory.len() as u64 - 1;
        let (header, body) = self.read_block(index, counters)?;
        Ok(find_record_in_block(&header, &body, lsn)?.map(|r| (r.hlc, r.payload.to_vec())))
    }

    /// Varre `[lo, hi]` lendo apenas os blocos que sobreviveram ao pruning.
    pub fn scan_lsn_range(
        &self,
        lo: Lsn,
        hi: Lsn,
        counters: &mut ScanCounters,
    ) -> V6Result<Vec<(Lsn, u64, Vec<u8>)>> {
        let candidates = self.directory.blocks_for_lsn_range(lo, hi);
        counters.blocks_candidate += self.directory.len() as u64;
        counters.blocks_pruned += self.directory.len() as u64 - candidates.len() as u64;
        let mut out = Vec::new();
        for i in candidates {
            let (header, body) = self.read_block(i, counters)?;
            for r in decode_block_records(&header, &body)? {
                if r.lsn >= lo && r.lsn <= hi {
                    out.push((r.lsn, r.hlc, r.payload.to_vec()));
                }
            }
        }
        Ok(out)
    }

    /// Varre o segmento inteiro por ordem de LSN.
    pub fn scan_all(&self, counters: &mut ScanCounters) -> V6Result<Vec<(Lsn, u64, Vec<u8>)>> {
        let mut out = Vec::with_capacity(self.footer.record_count as usize);
        for i in 0..self.directory.len() {
            let (header, body) = self.read_block(i, counters)?;
            for r in decode_block_records(&header, &body)? {
                out.push((r.lsn, r.hlc, r.payload.to_vec()));
            }
        }
        Ok(out)
    }

    /// Aplica `f` a cada registo sem materializar o segmento todo — o caminho
    /// que o `verify --logical` e o exportador Parquet usam.
    pub fn for_each_record<F>(&self, counters: &mut ScanCounters, mut f: F) -> V6Result<()>
    where
        F: FnMut(&BlockRecord<'_>) -> V6Result<()>,
    {
        for i in 0..self.directory.len() {
            let (header, body) = self.read_block(i, counters)?;
            for r in decode_block_records(&header, &body)? {
                f(&r)?;
            }
        }
        Ok(())
    }
}

/// Abre um `.hrkl` PACKED local.
pub fn open_packed(
    path: &Path,
    max_block_bytes: usize,
) -> V6Result<PackedSegmentReader<FileSource>> {
    PackedSegmentReader::open(FileSource::open(path)?, max_block_bytes)
}

/// Constrói um bloco isolado a partir de registos — atalho para os testes e
/// para o exportador, que às vezes quer um bloco sem um segmento à volta.
pub fn build_single_block(
    records: &[PendingRecord],
    opts: &PackOptions,
) -> V6Result<super::block::BuiltBlock> {
    build_block(
        records,
        opts.restart_interval,
        opts.profile,
        opts.raw_fallback_ratio,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(i: u64) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[..8].copy_from_slice(&i.to_le_bytes());
        x
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hrkl6-packed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        let _ = std::fs::remove_file(&p);
        p
    }

    fn init() -> SegmentInit {
        SegmentInit {
            segment_id: 88,
            created_hlc: 1_000,
            first_lsn: 9_000_001,
            writer_epoch: 3,
            storage_namespace_id: [0x11; 16],
        }
    }

    fn escreve(
        path: &Path,
        n: u64,
        payload_len: usize,
        opts: PackOptions,
    ) -> (FooterV6, PackStats) {
        let mut w = PackedSegmentWriter::create(path, init(), opts).unwrap();
        for i in 0..n {
            let payload = format!("{:width$}", i, width = payload_len).into_bytes();
            w.push(9_000_001 + i, 1_700_000 + i * 3, payload, &h(i))
                .unwrap();
        }
        w.finish().unwrap()
    }

    #[test]
    fn escrever_e_reler_um_segmento_packed() {
        let path = tmp("basico.hrkl");
        let opts = PackOptions {
            block_target_bytes: super::super::block::MIN_BLOCK_TARGET,
            ..PackOptions::default()
        };
        let (footer, stats) = escreve(&path, 5_000, 120, opts);
        assert_eq!(footer.record_count, 5_000);
        assert!(footer.is_contiguous_lsn());
        assert!(
            stats.block_count > 1,
            "5000 registos de 120 B tinham de dar vários blocos"
        );

        let r = open_packed(&path, HARD_MAX_BLOCK_BYTES).unwrap();
        assert_eq!(r.footer, footer);
        assert_eq!(r.block_count(), stats.block_count as usize);

        let mut c = ScanCounters::default();
        let all = r.scan_all(&mut c).unwrap();
        assert_eq!(all.len(), 5_000);
        for (i, (lsn, hlc, _)) in all.iter().enumerate() {
            assert_eq!(*lsn, 9_000_001 + i as u64);
            assert_eq!(*hlc, 1_700_000 + i as u64 * 3);
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn point_lookup_descomprime_um_unico_bloco() {
        let path = tmp("point.hrkl");
        let opts = PackOptions {
            block_target_bytes: super::super::block::MIN_BLOCK_TARGET,
            ..PackOptions::default()
        };
        let (footer, stats) = escreve(&path, 4_000, 100, opts);
        assert!(stats.block_count >= 4);

        let r = open_packed(&path, HARD_MAX_BLOCK_BYTES).unwrap();
        for lsn in [footer.min_lsn, footer.min_lsn + 1234, footer.max_lsn] {
            let mut c = ScanCounters::default();
            let got = r.get(lsn, &mut c).unwrap();
            assert!(got.is_some(), "lsn {lsn} não encontrado");
            assert_eq!(
                c.blocks_read, 1,
                "§157: point lookup leu {} blocos",
                c.blocks_read
            );
            assert!(c.bytes_decompressed <= opts.block_target_bytes as u64 * 2);
        }
        // Um LSN fora do segmento não lê bloco nenhum.
        let mut c = ScanCounters::default();
        assert!(r.get(1, &mut c).unwrap().is_none());
        assert_eq!(c.blocks_read, 0);
        assert_eq!(c.bytes_physical_read, 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn range_selectivo_reduz_bytes_fisicos_lidos() {
        // §158: o pruning tem de reduzir blocos e bytes LIDOS, não apenas CPU.
        let path = tmp("range.hrkl");
        let opts = PackOptions {
            block_target_bytes: super::super::block::MIN_BLOCK_TARGET,
            ..PackOptions::default()
        };
        escreve(&path, 8_000, 100, opts);
        let r = open_packed(&path, HARD_MAX_BLOCK_BYTES).unwrap();

        let mut todo = ScanCounters::default();
        r.scan_all(&mut todo).unwrap();

        let mut pouco = ScanCounters::default();
        let hits = r.scan_lsn_range(9_000_100, 9_000_140, &mut pouco).unwrap();
        assert_eq!(hits.len(), 41);
        assert!(pouco.blocks_read < todo.blocks_read);
        assert!(
            pouco.bytes_physical_read * 4 < todo.bytes_physical_read,
            "pruning leu {} de {} bytes",
            pouco.bytes_physical_read,
            todo.bytes_physical_read
        );
        assert!(pouco.blocks_pruned > 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn compressao_reduz_substancialmente_em_dados_repetitivos() {
        let path = tmp("ratio.hrkl");
        let opts = PackOptions::default();
        let mut w = PackedSegmentWriter::create(&path, init(), opts).unwrap();
        for i in 0..3_000u64 {
            w.push(
                9_000_001 + i,
                1_700_000 + i,
                b"evento repetitivo ".repeat(12),
                &h(i),
            )
            .unwrap();
        }
        let (_, stats) = w.finish().unwrap();
        assert!(
            stats.compression_ratio() < 0.5,
            "§154: esperava <= 50% em corpus repetitivo, deu {:.3}",
            stats.compression_ratio()
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn dados_incompressiveis_expandem_menos_de_2_porcento() {
        // §155, apoiado no RAW fallback de §34.
        let path = tmp("incompressivel.hrkl");
        let opts = PackOptions::default();
        let mut w = PackedSegmentWriter::create(&path, init(), opts).unwrap();
        let mut logico = 0u64;
        let mut st: u64 = 0x9E37_79B9_7F4A_7C15;
        for i in 0..3_000u64 {
            let payload: Vec<u8> = (0..200)
                .map(|_| {
                    st ^= st << 13;
                    st ^= st >> 7;
                    st ^= st << 17;
                    (st >> 24) as u8
                })
                .collect();
            logico += payload.len() as u64;
            w.push(9_000_001 + i, 1_700_000 + i, payload, &h(i))
                .unwrap();
        }
        let (_, stats) = w.finish().unwrap();
        let expansao = stats.physical_size as f64 / logico as f64;
        assert!(
            expansao <= 1.02,
            "expansão de {expansao:.4} viola o gate de 2%"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn directorio_adulterado_e_recusado_na_abertura() {
        let path = tmp("adulterado.hrkl");
        let (footer, _) = escreve(&path, 500, 80, PackOptions::default());
        let mut bytes = std::fs::read(&path).unwrap();
        let at = footer.block_directory_offset as usize;
        bytes[at] ^= 0xff; // mexe no offset do primeiro bloco
        assert!(PackedSegmentReader::open(MemorySource(bytes), HARD_MAX_BLOCK_BYTES).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn bloco_adulterado_e_apanhado_na_leitura_nao_na_abertura() {
        let path = tmp("bloco-mau.hrkl");
        escreve(&path, 500, 80, PackOptions::default());
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[FILE_HEADER_LEN + BLOCK_HEADER_LEN + 5] ^= 0xff;
        let r = PackedSegmentReader::open(MemorySource(bytes), HARD_MAX_BLOCK_BYTES).unwrap();
        let mut c = ScanCounters::default();
        assert!(r.read_block(0, &mut c).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn ficheiros_truncados_nao_entram_em_panico() {
        let path = tmp("truncado.hrkl");
        escreve(&path, 300, 60, PackOptions::default());
        let bytes = std::fs::read(&path).unwrap();
        for n in (0..bytes.len()).step_by(97) {
            let _ =
                PackedSegmentReader::open(MemorySource(bytes[..n].to_vec()), HARD_MAX_BLOCK_BYTES);
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn segmento_com_um_registo_gigante() {
        let path = tmp("gigante.hrkl");
        let opts = PackOptions::default();
        let mut w = PackedSegmentWriter::create(&path, init(), opts).unwrap();
        let grande = vec![0xABu8; DEFAULT_BLOCK_TARGET * 2];
        w.push(9_000_001, 1, b"pequeno".to_vec(), &h(0)).unwrap();
        w.push(9_000_002, 2, grande.clone(), &h(1)).unwrap();
        w.push(9_000_003, 3, b"outro pequeno".to_vec(), &h(2))
            .unwrap();
        let (footer, _) = w.finish().unwrap();
        assert_eq!(footer.record_count, 3);

        let r = open_packed(&path, HARD_MAX_BLOCK_BYTES).unwrap();
        let mut c = ScanCounters::default();
        let (_, payload) = r.get(9_000_002, &mut c).unwrap().unwrap();
        assert_eq!(payload, grande);
        assert_eq!(c.blocks_read, 1);
        std::fs::remove_file(&path).ok();
    }
}
