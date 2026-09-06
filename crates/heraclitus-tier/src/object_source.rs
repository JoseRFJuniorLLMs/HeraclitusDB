//! SPEC-0050 §85 — cold range reads.
//!
//! O recall do tier frio deixa de ser
//!
//! ```text
//! baixar segmento inteiro
//! ```
//!
//! e passa a ser
//!
//! ```text
//! read footer/directory -> identify blocks -> range GET -> só os blocos que interessam
//! ```
//!
//! ## Porque é que a origem é *esparsa* e não um `read_at` assíncrono
//!
//! [`heraclitus_log::v6::BlockSource`] é síncrona por desenho: é a fronteira
//! que o leitor PACKED usa em mmap, ficheiro local e cache. Envolvê-la num
//! `block_on` para falar com o `object_store` seria pôr uma chamada bloqueante
//! dentro de um executor assíncrono — o padrão que provoca os deadlocks que já
//! custaram caro no wiring do consenso (STATUS.md, 2026-07-10).
//!
//! Em vez disso o planeamento é feito **antes**, em `async`: decide-se que
//! blocos interessam a partir do directório, descarregam-se exactamente esses
//! intervalos, e só então se abre um [`PackedSegmentReader`] sobre uma origem
//! que contém apenas o que foi descarregado. O leitor não sabe que está sobre
//! object storage; se pedir um byte que não foi planeado, recebe **erro**, não
//! zeros — a ausência é sempre audível.

use std::sync::Arc;

use heraclitus_core::HeraclitusError;
use heraclitus_core::Lsn;
use heraclitus_log::v6::block::BLOCK_HEADER_LEN;
use heraclitus_log::v6::block_directory::BlockDirectory;
use heraclitus_log::v6::error::{corrupt, V6Result};
use heraclitus_log::v6::footer::FOOTER_LEN;
use heraclitus_log::v6::header::FILE_HEADER_LEN;
use heraclitus_log::v6::{
    BlockSource, FileHeaderV6, FooterV6, PackedSegmentReader, PhysicalLayout, ScanCounters,
};
use object_store::path::Path as ObjPath;
use object_store::{GetOptions, GetRange, ObjectStore, ObjectStoreExt};

/// Quanto da cauda se sonda de uma vez ao abrir. O footer são 128 B e o
/// directório 56 B por bloco: 64 KiB cobrem ~1170 blocos, isto é, um segmento
/// de ~290 MiB com blocos de 256 KiB. Acima disso paga-se um pedido extra em
/// vez de se descarregar o objecto todo.
pub const TAIL_PROBE_BYTES: u64 = 64 * 1024;

/// Contadores do que uma leitura fria custou — e do que evitou custar.
///
/// `bytes_fetched` contra `object_size` é a métrica que justifica esta fase
/// inteira: sem range reads seriam sempre iguais.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ColdReadStats {
    pub requests: u64,
    pub bytes_fetched: u64,
    pub blocks_fetched: u64,
    pub blocks_pruned: u64,
    pub object_size: u64,
}

impl ColdReadStats {
    /// Fracção do objecto que foi mesmo transferida.
    pub fn fetch_ratio(&self) -> f64 {
        if self.object_size == 0 {
            return 0.0;
        }
        self.bytes_fetched as f64 / self.object_size as f64
    }
}

/// Origem que só contém os intervalos que foram descarregados (§85).
///
/// Declara o comprimento **total** do objecto — o leitor PACKED calcula o
/// offset do footer a partir dele — mas só serve leituras cobertas por um
/// intervalo presente.
#[derive(Debug, Clone, Default)]
pub struct SparseSource {
    total_len: u64,
    /// Ordenado por offset; nunca sobreposto.
    chunks: Vec<(u64, Vec<u8>)>,
}

impl SparseSource {
    pub fn new(total_len: u64) -> Self {
        Self {
            total_len,
            chunks: Vec::new(),
        }
    }

    /// Junta um intervalo descarregado. Intervalos idênticos ou contidos num já
    /// presente são ignorados (é o caso do header, que a sonda da cauda às
    /// vezes já cobre em segmentos minúsculos).
    pub fn insert(&mut self, offset: u64, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let end = offset + bytes.len() as u64;
        if self
            .chunks
            .iter()
            .any(|(o, b)| *o <= offset && end <= *o + b.len() as u64)
        {
            return;
        }
        self.chunks.push((offset, bytes));
        self.chunks.sort_by_key(|(o, _)| *o);
    }

    /// Bytes efectivamente retidos em memória.
    pub fn bytes_held(&self) -> u64 {
        self.chunks.iter().map(|(_, b)| b.len() as u64).sum()
    }

    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

impl BlockSource for SparseSource {
    fn len(&self) -> u64 {
        self.total_len
    }

    fn read_at(&self, offset: u64, len: usize) -> V6Result<Vec<u8>> {
        const CTX: &str = "hrkl v6 cold source";
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| corrupt(CTX, "offset+len overflows u64"))?;
        if end > self.total_len {
            return Err(corrupt(CTX, "range past end of object"));
        }
        for (o, b) in &self.chunks {
            if *o <= offset && end <= *o + b.len() as u64 {
                let start = (offset - *o) as usize;
                return Ok(b[start..start + len].to_vec());
            }
        }
        // Nunca devolver zeros: um bloco que não foi planeado é um erro de
        // planeamento, e tem de aparecer como tal.
        Err(corrupt(
            CTX,
            format!("range [{offset}..{end}) não foi descarregado deste objecto"),
        ))
    }
}

/// Leitor de um segmento PACKED que vive em object storage.
///
/// Abrir custa duas leituras pequenas (cauda + header). Cada consulta paga
/// apenas os blocos que o directório não conseguiu podar.
pub struct ColdSegmentReader {
    store: Arc<dyn ObjectStore>,
    path: ObjPath,
    object_size: u64,
    /// Header, directório e footer — o que basta para planear sem ler blocos.
    prelude: SparseSource,
    pub header: FileHeaderV6,
    pub footer: FooterV6,
    pub directory: BlockDirectory,
    max_block_bytes: usize,
    stats: ColdReadStats,
}

impl ColdSegmentReader {
    /// Abre o objecto lendo só cauda e header (§159: abrir não pode exigir
    /// varrer o segmento — muito menos transferi-lo).
    pub async fn open(
        store: Arc<dyn ObjectStore>,
        path: ObjPath,
        max_block_bytes: usize,
    ) -> Result<Self, HeraclitusError> {
        const CTX: &str = "hrkl v6 cold open";
        let mut stats = ColdReadStats::default();

        // Pedido 1: sufixo. Dá a cauda **e** o tamanho do objecto, poupando o
        // `head()` que seria um round-trip só para saber o comprimento.
        let opts = GetOptions::new().with_range(Some(GetRange::Suffix(TAIL_PROBE_BYTES)));
        let res = store
            .get_opts(&path, opts)
            .await
            .map_err(|e| store_err(&path, e))?;
        let object_size = res.meta.size;
        let tail_start = res.range.start;
        let tail = res.bytes().await.map_err(|e| store_err(&path, e))?.to_vec();
        stats.requests += 1;
        stats.bytes_fetched += tail.len() as u64;
        stats.object_size = object_size;

        if object_size < (FILE_HEADER_LEN + FOOTER_LEN) as u64 {
            return Err(corrupt(CTX, "objecto pequeno demais para header + footer"));
        }

        let mut prelude = SparseSource::new(object_size);
        prelude.insert(tail_start, tail);

        // Pedido 2: header. Só se a sonda da cauda não o cobriu já.
        if tail_start > 0 {
            let head = store
                .get_range(&path, 0..FILE_HEADER_LEN as u64)
                .await
                .map_err(|e| store_err(&path, e))?;
            stats.requests += 1;
            stats.bytes_fetched += head.len() as u64;
            prelude.insert(0, head.to_vec());
        }

        let header = FileHeaderV6::decode(&prelude.read_at(0, FILE_HEADER_LEN)?)?;
        if header.physical_layout != PhysicalLayout::Packed {
            return Err(corrupt(
                CTX,
                "range reads exigem um segmento PACKED; RAW não tem directório de blocos",
            ));
        }
        let footer =
            FooterV6::decode(&prelude.read_at(object_size - FOOTER_LEN as u64, FOOTER_LEN)?)?;

        // Pedido 3 (raro): o directório caiu fora da sonda.
        let dir_len = usize::try_from(footer.block_directory_len)
            .map_err(|_| corrupt(CTX, "directório grande demais para esta plataforma"))?;
        if prelude
            .read_at(footer.block_directory_offset, dir_len)
            .is_err()
        {
            let end = footer
                .block_directory_offset
                .checked_add(footer.block_directory_len)
                .ok_or_else(|| corrupt(CTX, "intervalo do directório transborda u64"))?;
            let dir = store
                .get_range(&path, footer.block_directory_offset..end)
                .await
                .map_err(|e| store_err(&path, e))?;
            stats.requests += 1;
            stats.bytes_fetched += dir.len() as u64;
            prelude.insert(footer.block_directory_offset, dir.to_vec());
        }
        let dir_bytes = prelude.read_at(footer.block_directory_offset, dir_len)?;
        let directory = BlockDirectory::decode(
            &dir_bytes,
            footer.block_count,
            footer.block_directory_offset,
        )?;
        // Auditoria 2026-09-05 (A05): o mesmo confronto que o leitor local faz.
        // Aqui era ainda mais frouxo — nem a soma dos `record_count` se
        // verificava —, e o `get` frio poda pelo directório *antes* de
        // transferir bloco nenhum: um `last_lsn` encolhido devolvia `Ok(None)`
        // para um LSN comitado sem sequer tocar na rede.
        directory.check_against_footer(&footer)?;

        Ok(Self {
            store,
            path,
            object_size,
            prelude,
            header,
            footer,
            directory,
            max_block_bytes,
            stats,
        })
    }

    pub fn stats(&self) -> ColdReadStats {
        self.stats
    }

    pub fn object_size(&self) -> u64 {
        self.object_size
    }

    pub fn logical_root(&self) -> [u8; 32] {
        self.footer.logical_root
    }

    /// Descarrega exactamente os blocos indicados e devolve um leitor PACKED
    /// sobre eles. Os índices vêm do directório (ou do `.hrki`, quando o
    /// chamador tem um).
    pub async fn fetch_blocks(
        &mut self,
        blocks: &[usize],
    ) -> Result<PackedSegmentReader<SparseSource>, HeraclitusError> {
        const CTX: &str = "hrkl v6 cold fetch";
        let mut source = self.prelude.clone();
        let mut ranges = Vec::with_capacity(blocks.len());
        for &i in blocks {
            let e = self
                .directory
                .entries
                .get(i)
                .ok_or_else(|| corrupt(CTX, format!("bloco {i} fora do directório")))?;
            let total = (BLOCK_HEADER_LEN as u64)
                .checked_add(e.stored_len as u64)
                .ok_or_else(|| corrupt(CTX, "comprimento de bloco transborda u64"))?;
            let end = e
                .offset
                .checked_add(total)
                .ok_or_else(|| corrupt(CTX, "intervalo de bloco transborda u64"))?;
            if end > self.object_size {
                return Err(corrupt(
                    CTX,
                    format!("bloco {i} aponta para fora do objecto"),
                ));
            }
            ranges.push(e.offset..end);
        }
        if !ranges.is_empty() {
            // `get_ranges` coalesce intervalos próximos por si: blocos
            // consecutivos viram um GET só, sem que o planeamento tenha de
            // adivinhar a política do backend.
            let got = self
                .store
                .get_ranges(&self.path, &ranges)
                .await
                .map_err(|e| store_err(&self.path, e))?;
            self.stats.requests += 1;
            self.stats.blocks_fetched += blocks.len() as u64;
            for (r, bytes) in ranges.iter().zip(got) {
                self.stats.bytes_fetched += bytes.len() as u64;
                source.insert(r.start, bytes.to_vec());
            }
        }
        self.stats.blocks_pruned += self.directory.len() as u64 - blocks.len() as u64;
        PackedSegmentReader::open(source, self.max_block_bytes)
    }

    /// Point lookup por LSN: no máximo um bloco atravessa a rede.
    pub async fn get(&mut self, lsn: Lsn) -> Result<Option<(u64, Vec<u8>)>, HeraclitusError> {
        let Some(i) = self.directory.find_block_for_lsn(lsn) else {
            self.stats.blocks_pruned += self.directory.len() as u64;
            return Ok(None);
        };
        let reader = self.fetch_blocks(&[i]).await?;
        let mut counters = ScanCounters::default();
        reader.get(lsn, &mut counters)
    }

    /// Varre `[lo, hi]` transferindo só os blocos que o directório não podou.
    pub async fn scan_lsn_range(
        &mut self,
        lo: Lsn,
        hi: Lsn,
    ) -> Result<Vec<(Lsn, u64, Vec<u8>)>, HeraclitusError> {
        let blocks = self.directory.blocks_for_lsn_range(lo, hi);
        let reader = self.fetch_blocks(&blocks).await?;
        let mut counters = ScanCounters::default();
        reader.scan_lsn_range(lo, hi, &mut counters)
    }

    /// Transfere o objecto inteiro — o que a verificação física e lógica exige,
    /// e o único caso em que isso é honesto.
    pub async fn fetch_all(
        &mut self,
    ) -> Result<PackedSegmentReader<SparseSource>, HeraclitusError> {
        let all: Vec<usize> = (0..self.directory.len()).collect();
        self.fetch_blocks(&all).await
    }
}

pub(crate) fn store_err(path: &ObjPath, e: object_store::Error) -> HeraclitusError {
    HeraclitusError::Storage(std::io::Error::other(format!("{path}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Escreve um `.hrkl` PACKED real com vários blocos e devolve os bytes.
    fn segmento_packed(dir: &std::path::Path) -> (Vec<u8>, FooterV6) {
        use heraclitus_log::v6::packed::{PackOptions, PackedSegmentWriter};
        use heraclitus_log::v6::SegmentInit;
        let path = dir.join("frio.hrkl");
        let opts = PackOptions {
            block_target_bytes: 4096,
            ..Default::default()
        };
        let init = SegmentInit {
            segment_id: 7,
            created_hlc: 1,
            first_lsn: 1_000,
            writer_epoch: 1,
            storage_namespace_id: [0x22; 16],
        };
        let mut w = PackedSegmentWriter::create(&path, init, opts).unwrap();
        for i in 0..2_000u64 {
            let mut h = [0u8; 32];
            h[..8].copy_from_slice(&i.to_le_bytes());
            w.push(1_000 + i, 10_000 + i, format!("{i:0100}").into_bytes(), &h)
                .unwrap();
        }
        let (footer, _) = w.finish().unwrap();
        (std::fs::read(&path).unwrap(), footer)
    }

    #[tokio::test]
    async fn directorio_com_intervalo_adulterado_e_recusado_ao_abrir_o_objecto() {
        // Auditoria 2026-09-05 (A05): o caminho frio poda pelo directório
        // ANTES de transferir bloco nenhum (`get` sai em `Ok(None)` sem tocar
        // na rede), e aqui nem a soma dos `record_count` era confrontada com o
        // footer. Um `last_lsn` encolhido — a região do directório não tem
        // checksum — fazia o recall responder "esse evento não existe" para um
        // LSN comitado.
        let dir = tempfile::tempdir().unwrap();
        let (bytes, footer) = segmento_packed(dir.path());
        assert!(footer.block_count >= 2, "o teste precisa de vários blocos");

        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let bom = ObjPath::from("canonical/bom.hrkl");
        store.put(&bom, bytes.clone().into()).await.unwrap();
        ColdSegmentReader::open(store.clone(), bom, 1 << 20)
            .await
            .unwrap();

        // bytes 32..40 da entrada 0 do directório = `last_lsn`.
        let mut adulterado = bytes;
        let at = footer.block_directory_offset as usize + 32;
        let encolhido = u64::from_le_bytes(adulterado[at..at + 8].try_into().unwrap()) - 8;
        adulterado[at..at + 8].copy_from_slice(&encolhido.to_le_bytes());
        let mau = ObjPath::from("canonical/mau.hrkl");
        store.put(&mau, adulterado.into()).await.unwrap();
        assert!(
            ColdSegmentReader::open(store, mau, 1 << 20).await.is_err(),
            "o objecto frio com o directório adulterado tinha de ser recusado ao abrir"
        );
    }

    #[test]
    fn origem_esparsa_serve_o_que_tem() {
        let mut s = SparseSource::new(1000);
        s.insert(100, vec![7u8; 50]);
        assert_eq!(s.read_at(100, 50).unwrap(), vec![7u8; 50]);
        assert_eq!(s.read_at(120, 10).unwrap(), vec![7u8; 10]);
        assert_eq!(s.bytes_held(), 50);
        assert_eq!(s.len(), 1000);
    }

    #[test]
    fn origem_esparsa_recusa_o_que_nao_tem_em_vez_de_inventar() {
        let mut s = SparseSource::new(1000);
        s.insert(100, vec![7u8; 50]);
        // Buraco antes, buraco depois, e um pedido a cavalo de dois intervalos.
        assert!(s.read_at(0, 10).is_err());
        assert!(s.read_at(140, 20).is_err());
        s.insert(160, vec![9u8; 10]);
        assert!(s.read_at(140, 30).is_err());
        // E nunca além do fim declarado.
        assert!(s.read_at(990, 20).is_err());
    }

    #[test]
    fn insercao_contida_e_ignorada() {
        let mut s = SparseSource::new(1000);
        s.insert(0, vec![1u8; 100]);
        s.insert(10, vec![1u8; 10]);
        assert_eq!(s.chunk_count(), 1);
        assert_eq!(s.bytes_held(), 100);
    }

    #[test]
    fn racio_de_transferencia() {
        let st = ColdReadStats {
            bytes_fetched: 25,
            object_size: 100,
            ..Default::default()
        };
        assert!((st.fetch_ratio() - 0.25).abs() < 1e-9);
        assert_eq!(ColdReadStats::default().fetch_ratio(), 0.0);
    }
}
