//! SPEC-0050 §25–§27 — o registo **RAW v6** e o segmento activo.
//!
//! ```text
//! payload_len     u32
//! record_crc32c   u32
//! lsn             u64
//! hlc             u64
//! payload         bytes
//! ```
//!
//! 24 bytes de overhead por registo, **de propósito** (§25). O v6 não tenta
//! poupar bytes no hot-path ao custo de branches, varints, compressão,
//! manutenção de dicionário e pior recovery. A poupança agressiva acontece
//! depois do seal, no packer — onde ninguém está à espera de um `fsync`.
//!
//! O CRC-32C cobre `payload_len + lsn + hlc + payload`, saltando o próprio
//! campo `crc` (§26), reutilizando o hasher acelerado por hardware que o v5 já
//! usa ([`crate::cpm`]).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use heraclitus_core::Lsn;

use super::canonical::CANONICAL_CODEC_V1;
use super::error::{corrupt, V6Result, HARD_MAX_RECORD_BYTES};
use super::footer::{footer_flags, FooterV6, FOOTER_LEN, FOOTER_MAGIC};
use super::header::{
    header_flags, FileHeaderV6, PhysicalLayout, StorageNamespaceId, FILE_HEADER_LEN,
};
use super::merkle::MerkleAccumulatorV1;

pub const RAW_RECORD_HEADER_LEN: usize = 24;

/// Codifica um registo RAW completo para `out`.
///
/// Devolve o número de bytes escritos. Não aloca: quem chama traz o buffer.
pub fn encode_raw_record_into(out: &mut Vec<u8>, lsn: Lsn, hlc: u64, payload: &[u8]) -> usize {
    let start = out.len();
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0u8; 4]); // crc, preenchido abaixo
    out.extend_from_slice(&lsn.to_le_bytes());
    out.extend_from_slice(&hlc.to_le_bytes());
    out.extend_from_slice(payload);
    let crc = raw_record_crc(&out[start..]);
    out[start + 4..start + 8].copy_from_slice(&crc.to_le_bytes());
    out.len() - start
}

pub fn encode_raw_record(lsn: Lsn, hlc: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RAW_RECORD_HEADER_LEN + payload.len());
    encode_raw_record_into(&mut out, lsn, hlc, payload);
    out
}

/// CRC-32C sobre a região autenticada — tudo menos o campo `crc`, que seria
/// auto-referencial.
#[inline]
fn raw_record_crc(record: &[u8]) -> u32 {
    let mut h = crate::cpm::Crc32c::new();
    h.update(&record[..4]); // payload_len
    h.update(&record[8..]); // lsn + hlc + payload
    h.finalize()
}

/// Resultado de descodificar uma posição do segmento RAW.
#[derive(Debug)]
pub enum RawDecoded<'a> {
    Record {
        lsn: Lsn,
        hlc: u64,
        payload: &'a [u8],
        total: usize,
    },
    Footer(Box<FooterV6>),
    /// Bytes insuficientes ou CRC falhado. **Só o segmento activo** pode ser
    /// truncado aqui (§123); num segmento já selado isto é falha dura.
    Torn,
}

/// Descodifica o registo que começa em `buf[0]`. Função pura — alvo de fuzzing
/// (§163). Nenhum input malformado pode causar panic, overflow ou alocação
/// descontrolada.
pub fn decode_raw_record(buf: &[u8]) -> RawDecoded<'_> {
    if buf.len() >= 4 && buf[..4] == FOOTER_MAGIC {
        return match FooterV6::decode(buf) {
            Ok(f) => RawDecoded::Footer(Box::new(f)),
            Err(_) => RawDecoded::Torn,
        };
    }
    if buf.len() < RAW_RECORD_HEADER_LEN {
        return RawDecoded::Torn;
    }
    let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    if len > HARD_MAX_RECORD_BYTES {
        return RawDecoded::Torn;
    }
    let Some(total) = RAW_RECORD_HEADER_LEN.checked_add(len) else {
        return RawDecoded::Torn;
    };
    if buf.len() < total {
        return RawDecoded::Torn;
    }
    let crc = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if raw_record_crc(&buf[..total]) != crc {
        return RawDecoded::Torn;
    }
    RawDecoded::Record {
        lsn: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        hlc: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        payload: &buf[RAW_RECORD_HEADER_LEN..total],
        total,
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Escritor de um segmento RAW v6.
///
/// Mantém o acumulador de Merkle vivo enquanto acrescenta: a `logical_root` sai
/// pronta no seal, sem uma segunda passagem sobre o ficheiro. Quem chama
/// fornece o `canonical_record_hash` de cada registo — o writer não sabe (nem
/// precisa de saber) descodificar payloads.
pub struct RawSegmentWriter {
    file: File,
    header: FileHeaderV6,
    acc: MerkleAccumulatorV1,
    record_count: u64,
    min_lsn: Lsn,
    max_lsn: Lsn,
    min_hlc: u64,
    max_hlc: u64,
    next_expected_lsn: Lsn,
    contiguous: bool,
    monotonic_hlc: bool,
    bytes_written: u64,
}

/// Parâmetros de criação de um segmento.
#[derive(Debug, Clone, Copy)]
pub struct SegmentInit {
    pub segment_id: u64,
    pub created_hlc: u64,
    pub first_lsn: Lsn,
    pub writer_epoch: u64,
    pub storage_namespace_id: StorageNamespaceId,
}

impl RawSegmentWriter {
    /// Cria o ficheiro e escreve o `FileHeaderV6`.
    pub fn create(path: &Path, init: SegmentInit) -> V6Result<Self> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .open(path)?;
        let header = FileHeaderV6 {
            physical_layout: PhysicalLayout::Raw,
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
            header,
            acc: MerkleAccumulatorV1::new(),
            record_count: 0,
            min_lsn: u64::MAX,
            max_lsn: 0,
            min_hlc: u64::MAX,
            max_hlc: 0,
            next_expected_lsn: init.first_lsn,
            contiguous: true,
            monotonic_hlc: true,
            bytes_written: FILE_HEADER_LEN as u64,
        })
    }

    /// Reabre um RAW activo depois de a recuperação já ter removido uma cauda
    /// rasgada. Reconstrói o acumulador canónico a partir dos bytes
    /// persistidos; continuar a escrever sem o reconstruir produziria um
    /// footer cuja raiz esquece o prefixo anterior.
    ///
    /// Segmentos selados são deliberadamente recusados. A chamada segura é
    /// `repair_active_tail` seguida desta função, e só para o ficheiro que o
    /// catálogo/nome do motor identifica como activo.
    pub fn resume(
        path: &Path,
        canonical_hasher: &dyn Fn(Lsn, u64, &[u8]) -> V6Result<[u8; 32]>,
    ) -> V6Result<Self> {
        const CTX: &str = "hrkl v6 raw resume";
        let scan = scan_raw_segment(path)?;
        if scan.footer.is_some() {
            return Err(corrupt(CTX, "refusing to resume a sealed segment"));
        }
        if scan.torn_at.is_some() {
            return Err(corrupt(
                CTX,
                "refusing to resume before the torn tail is repaired",
            ));
        }
        if scan.header.canonical_codec != CANONICAL_CODEC_V1 {
            return Err(corrupt(
                CTX,
                format!(
                    "unsupported canonical codec {}",
                    scan.header.canonical_codec
                ),
            ));
        }

        let mut acc = MerkleAccumulatorV1::new();
        let mut min_lsn = u64::MAX;
        let mut max_lsn = 0;
        let mut min_hlc = u64::MAX;
        let mut max_hlc = 0;
        let mut expected_lsn = scan.header.first_lsn;
        let mut contiguous = true;
        let mut monotonic_hlc = true;

        for record in &scan.records {
            acc.push_record_hash(&canonical_hasher(record.lsn, record.hlc, &record.payload)?);
            if record.lsn != expected_lsn {
                contiguous = false;
            }
            expected_lsn = record.lsn.saturating_add(1);
            if max_hlc != 0 && record.hlc < max_hlc {
                monotonic_hlc = false;
            }
            min_lsn = min_lsn.min(record.lsn);
            max_lsn = max_lsn.max(record.lsn);
            min_hlc = min_hlc.min(record.hlc);
            max_hlc = max_hlc.max(record.hlc);
        }

        let bytes_written = std::fs::metadata(path)?.len();
        let file = OpenOptions::new().read(true).append(true).open(path)?;
        Ok(Self {
            file,
            header: scan.header,
            acc,
            record_count: scan.records.len() as u64,
            min_lsn,
            max_lsn,
            min_hlc,
            max_hlc,
            next_expected_lsn: expected_lsn,
            contiguous,
            monotonic_hlc,
            bytes_written,
        })
    }

    /// Acrescenta um registo. `canonical_record_hash` é o hash lógico já
    /// calculado pelo chamador (que tem o `Episode` em mãos).
    pub fn append(
        &mut self,
        lsn: Lsn,
        hlc: u64,
        payload: &[u8],
        canonical_record_hash: &[u8; 32],
    ) -> V6Result<()> {
        if payload.len() > HARD_MAX_RECORD_BYTES {
            return Err(corrupt("hrkl v6 raw writer", "record exceeds hard maximum"));
        }
        let bytes = encode_raw_record(lsn, hlc, payload);
        self.file.write_all(&bytes)?;
        self.bytes_written += bytes.len() as u64;

        if lsn != self.next_expected_lsn {
            self.contiguous = false;
        }
        self.next_expected_lsn = lsn.saturating_add(1);
        if self.record_count > 0 && hlc < self.max_hlc {
            self.monotonic_hlc = false;
        }
        self.min_lsn = self.min_lsn.min(lsn);
        self.max_lsn = self.max_lsn.max(lsn);
        self.min_hlc = self.min_hlc.min(hlc);
        self.max_hlc = self.max_hlc.max(hlc);
        self.record_count += 1;
        self.acc.push_record_hash(canonical_record_hash);
        Ok(())
    }

    pub fn sync(&mut self) -> V6Result<()> {
        self.file.sync_data()?;
        Ok(())
    }

    pub fn record_count(&self) -> u64 {
        self.record_count
    }
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
    /// Próximo LSN que o writer reconstruído espera. O motor v6 impõe este
    /// contrato; o writer baixo nível continua capaz de representar segmentos
    /// esparsos usados por ferramentas de migração/forense.
    pub fn next_expected_lsn(&self) -> Lsn {
        self.next_expected_lsn
    }
    pub fn max_hlc(&self) -> Option<u64> {
        (self.record_count > 0).then_some(self.max_hlc)
    }
    pub fn header(&self) -> &FileHeaderV6 {
        &self.header
    }

    /// Sela o segmento: escreve o footer e sincroniza.
    ///
    /// §22 — o seal **não espera pela compressão**. Quem chama roda para o
    /// segmento seguinte imediatamente e delega o packing a um worker.
    pub fn seal(mut self) -> V6Result<FooterV6> {
        let mut flags = 0u32;
        if self.contiguous && self.record_count > 0 {
            flags |= footer_flags::CONTIGUOUS_LSN;
        }
        if !self.monotonic_hlc {
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
            block_count: 0,
            flags,
            block_directory_offset: 0,
            block_directory_len: 0,
            logical_root: self.acc.finalize(),
        };
        self.file.write_all(&footer.encode())?;
        self.file.sync_data()?;
        Ok(footer)
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Um registo lido de um segmento RAW.
#[derive(Debug, Clone)]
pub struct RawRecord {
    pub lsn: Lsn,
    pub hlc: u64,
    pub payload: Vec<u8>,
}

/// Resultado de varrer um segmento RAW.
pub struct RawScan {
    pub header: FileHeaderV6,
    pub records: Vec<RawRecord>,
    /// `Some` se o segmento estava selado.
    pub footer: Option<FooterV6>,
    /// Offset onde a cauda ficou rasgada (só possível no segmento activo).
    pub torn_at: Option<u64>,
}

/// Lê um segmento RAW inteiro para memória.
///
/// Serve o packer e o `verify`. O caminho de leitura quente do motor usa mmap;
/// esta função é a versão simples e auditável do mesmo percurso.
pub fn scan_raw_segment(path: &Path) -> V6Result<RawScan> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    scan_raw_bytes(&buf)
}

/// Como [`scan_raw_segment`], mas sobre bytes já em memória (mmap, objecto
/// remoto, teste).
pub fn scan_raw_bytes(buf: &[u8]) -> V6Result<RawScan> {
    let header = FileHeaderV6::decode(buf)?;
    if header.physical_layout != PhysicalLayout::Raw {
        return Err(corrupt("hrkl v6 raw scan", "segment is not RAW"));
    }
    let mut pos = FILE_HEADER_LEN;
    let mut records = Vec::new();
    let mut footer = None;
    let mut torn_at = None;
    while pos < buf.len() {
        match decode_raw_record(&buf[pos..]) {
            RawDecoded::Record {
                lsn,
                hlc,
                payload,
                total,
            } => {
                records.push(RawRecord {
                    lsn,
                    hlc,
                    payload: payload.to_vec(),
                });
                pos += total;
            }
            RawDecoded::Footer(f) => {
                let footer_end = pos
                    .checked_add(FOOTER_LEN)
                    .ok_or_else(|| corrupt("hrkl v6 raw scan", "footer offset overflows usize"))?;
                // Um footer válido sela exactamente o fim do objecto. Aceitar
                // bytes depois dele faria `verify --physical` ignorar uma
                // segunda sequência de records (ou lixo anexado) e permitiria
                // que um ficheiro com duas histórias parecesse íntegro.
                if footer_end != buf.len() {
                    return Err(corrupt(
                        "hrkl v6 raw scan",
                        "bytes found after a valid RAW footer",
                    ));
                }
                validate_raw_footer(&f, &records)?;
                footer = Some(*f);
                break;
            }
            RawDecoded::Torn => {
                // Um prefixo de footer com todos os 128 bytes presentes não
                // é uma cauda de append: é um footer completo que falhou a
                // validação (CRC/coerência). Tratá-lo como tail permitiria a
                // `verify --physical` dizer "ok" para um segmento selado
                // adulterado. Footer curto continua a ser o caso recuperável
                // de crash durante a escrita do seal.
                if buf[pos..].starts_with(&FOOTER_MAGIC) && buf.len() - pos >= FOOTER_LEN {
                    return Err(corrupt(
                        "hrkl v6 raw scan",
                        "complete footer is malformed or corrupt",
                    ));
                }
                torn_at = Some(pos as u64);
                break;
            }
        }
    }
    Ok(RawScan {
        header,
        records,
        footer,
        torn_at,
    })
}

/// Confere o que o footer RAW promete sobre os records físicos acabados de
/// ler. A raiz lógica exige o hasher do payload e é verificada em `verify`,
/// mas contagens e intervalos são metadados físicos: não há razão para aceitar
/// uma declaração que contradiz o próprio ficheiro.
fn validate_raw_footer(footer: &FooterV6, records: &[RawRecord]) -> V6Result<()> {
    const CTX: &str = "hrkl v6 raw footer";
    if footer.block_count != 0
        || footer.block_directory_offset != 0
        || footer.block_directory_len != 0
    {
        return Err(corrupt(CTX, "RAW footer declares PACKED block metadata"));
    }
    if footer.record_count != records.len() as u64 {
        return Err(corrupt(
            CTX,
            format!(
                "footer declares {} records, scanned {}",
                footer.record_count,
                records.len()
            ),
        ));
    }
    if records.is_empty() {
        if footer.min_lsn != 0 || footer.max_lsn != 0 || footer.min_hlc != 0 || footer.max_hlc != 0 {
            return Err(corrupt(CTX, "empty RAW footer has non-zero ranges"));
        }
        return Ok(());
    }

    let min_lsn = records.iter().map(|r| r.lsn).min().unwrap();
    let max_lsn = records.iter().map(|r| r.lsn).max().unwrap();
    let min_hlc = records.iter().map(|r| r.hlc).min().unwrap();
    let max_hlc = records.iter().map(|r| r.hlc).max().unwrap();
    if (footer.min_lsn, footer.max_lsn, footer.min_hlc, footer.max_hlc)
        != (min_lsn, max_lsn, min_hlc, max_hlc)
    {
        return Err(corrupt(
            CTX,
            "footer ranges disagree with scanned RAW records",
        ));
    }
    if footer.is_contiguous_lsn()
        && (!footer.lsn_span_is_contiguous()
            || !records
                .windows(2)
                .all(|w| w[1].lsn == w[0].lsn.saturating_add(1)))
    {
        return Err(corrupt(
            CTX,
            "RAW footer claims contiguous LSNs but records are not contiguous",
        ));
    }
    Ok(())
}

/// Trunca a cauda rasgada de um segmento **activo** (§123).
///
/// Recusa-se a tocar num segmento selado: corrupção interna num ficheiro que já
/// tem footer é falha dura, não é "truncar e fingir que nada aconteceu".
pub fn repair_active_tail(path: &Path) -> V6Result<Option<u64>> {
    // Não basta confiar no resultado da varredura abaixo. Se um bit rodado em
    // um registo anterior fizer `scan_raw_segment` parar antes do fim, ela não
    // chega a observar o footer que continua válido no EOF. Nesse caso o
    // ficheiro já está selado e truncá-lo em `torn_at` apagaria história.
    //
    // A presença de um footer válido no fim é a definição de segmento selado
    // (§24), independentemente de a passagem pelos registos conseguir chegar
    // até ele. Checá-lo primeiro também distingue uma cauda de footer parcial
    // (não selada, portanto recuperável) de corrupção interna num segmento
    // selado (falha dura).
    if read_footer(path)?.is_some() || footer_magic_at_eof(path)? {
        return Err(corrupt(
            "hrkl v6 raw recovery",
            "refusing to truncate a sealed segment; this is hard corruption",
        ));
    }
    let scan = scan_raw_segment(path)?;
    if scan.footer.is_some() {
        return Err(corrupt(
            "hrkl v6 raw recovery",
            "refusing to truncate a sealed segment; this is hard corruption",
        ));
    }
    match scan.torn_at {
        Some(at) => {
            let file = OpenOptions::new().write(true).open(path)?;
            file.set_len(at)?;
            file.sync_all()?;
            Ok(Some(at))
        }
        None => Ok(None),
    }
}

/// Detecta um footer que parece existir no fim mas não passa o CRC. Não o
/// tratamos como uma cauda ativa: um crash pode deixar um footer parcial, mas
/// um footer completo com magic é indistinguível de bit rot sem o catálogo e a
/// decisão segura é preservar os bytes para perícia. O motor v6 usa ainda o
/// nome/estado do ficheiro para eliminar essa ambiguidade durante o recovery.
fn footer_magic_at_eof(path: &Path) -> V6Result<bool> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len < (FILE_HEADER_LEN + FOOTER_LEN) as u64 {
        return Ok(false);
    }
    file.seek(SeekFrom::End(-(FOOTER_LEN as i64)))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    Ok(magic == FOOTER_MAGIC)
}

/// Lê apenas o footer de um ficheiro selado, sem varrer os registos.
///
/// É o que o boot precisa (§159: arrancar com HRKM válido não pode exigir scan
/// integral de cada segmento selado).
pub fn read_footer(path: &Path) -> V6Result<Option<FooterV6>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len < (FILE_HEADER_LEN + FOOTER_LEN) as u64 {
        return Ok(None);
    }
    file.seek(SeekFrom::End(-(FOOTER_LEN as i64)))?;
    let mut buf = [0u8; FOOTER_LEN];
    file.read_exact(&mut buf)?;
    match FooterV6::decode(&buf) {
        Ok(f) => Ok(Some(f)),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(i: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[0] = i;
        x
    }

    #[test]
    fn overhead_e_24_bytes() {
        let r = encode_raw_record(1, 2, b"abc");
        assert_eq!(r.len(), 24 + 3);
    }

    #[test]
    fn roundtrip_do_registo() {
        let r = encode_raw_record(9_000_001, 1_760_000_100, b"payload arbitrario");
        match decode_raw_record(&r) {
            RawDecoded::Record {
                lsn,
                hlc,
                payload,
                total,
            } => {
                assert_eq!(lsn, 9_000_001);
                assert_eq!(hlc, 1_760_000_100);
                assert_eq!(payload, b"payload arbitrario");
                assert_eq!(total, r.len());
            }
            other => panic!("esperava Record, veio {other:?}"),
        }
    }

    #[test]
    fn flip_em_qualquer_campo_da_torn() {
        let r = encode_raw_record(42, 43, b"xyz");
        for i in 0..r.len() {
            if (4..8).contains(&i) {
                continue; // o próprio campo crc
            }
            let mut c = r.clone();
            c[i] ^= 0xff;
            assert!(
                matches!(decode_raw_record(&c), RawDecoded::Torn),
                "flip no byte {i} passou"
            );
        }
    }

    #[test]
    fn buffers_truncados_nunca_entram_em_panico() {
        let r = encode_raw_record(1, 1, b"conteudo de teste");
        for n in 0..r.len() {
            let _ = decode_raw_record(&r[..n]);
        }
    }

    #[test]
    fn len_absurdo_da_torn_sem_alocar() {
        let mut r = encode_raw_record(1, 1, b"x");
        r[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(decode_raw_record(&r), RawDecoded::Torn));
    }

    #[test]
    fn escrever_selar_e_reler() {
        let dir = std::env::temp_dir().join(format!("hrkl6-raw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seg-write.hrkl");
        let _ = std::fs::remove_file(&path);

        let init = SegmentInit {
            segment_id: 7,
            created_hlc: 100,
            first_lsn: 1000,
            writer_epoch: 1,
            storage_namespace_id: [3u8; 16],
        };
        let mut w = RawSegmentWriter::create(&path, init).unwrap();
        for i in 0..10u64 {
            w.append(
                1000 + i,
                500 + i,
                format!("registo {i}").as_bytes(),
                &h(i as u8 + 1),
            )
            .unwrap();
        }
        let footer = w.seal().unwrap();
        assert_eq!(footer.record_count, 10);
        assert_eq!(footer.min_lsn, 1000);
        assert_eq!(footer.max_lsn, 1009);
        assert!(footer.is_contiguous_lsn());
        assert!(footer.lsn_span_is_contiguous());

        let scan = scan_raw_segment(&path).unwrap();
        assert_eq!(scan.records.len(), 10);
        assert_eq!(scan.footer.unwrap().logical_root, footer.logical_root);
        assert!(scan.torn_at.is_none());
        assert_eq!(read_footer(&path).unwrap().unwrap(), footer);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn cauda_rasgada_e_truncada_apenas_no_segmento_activo() {
        let dir = std::env::temp_dir().join(format!("hrkl6-torn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seg-torn.hrkl");
        let _ = std::fs::remove_file(&path);

        let init = SegmentInit {
            segment_id: 1,
            created_hlc: 1,
            first_lsn: 1,
            writer_epoch: 1,
            storage_namespace_id: [0u8; 16],
        };
        let mut w = RawSegmentWriter::create(&path, init).unwrap();
        for i in 0..5u64 {
            w.append(1 + i, i, b"abcdefgh", &h(i as u8 + 1)).unwrap();
        }
        w.sync().unwrap();
        let bom = std::fs::metadata(&path).unwrap().len();
        drop(w);

        // Meio registo a mais: escrita interrompida.
        {
            use std::io::Write as _;
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&encode_raw_record(6, 6, b"abcdefgh")[..10])
                .unwrap();
        }
        let scan = scan_raw_segment(&path).unwrap();
        assert_eq!(scan.records.len(), 5);
        assert_eq!(scan.torn_at, Some(bom));

        assert_eq!(repair_active_tail(&path).unwrap(), Some(bom));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), bom);
        assert!(repair_active_tail(&path).unwrap().is_none());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn lsn_nao_contiguo_desliga_o_flag() {
        let dir = std::env::temp_dir().join(format!("hrkl6-sparse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seg-sparse.hrkl");
        let _ = std::fs::remove_file(&path);

        let init = SegmentInit {
            segment_id: 2,
            created_hlc: 1,
            first_lsn: 100,
            writer_epoch: 1,
            storage_namespace_id: [0u8; 16],
        };
        let mut w = RawSegmentWriter::create(&path, init).unwrap();
        w.append(100, 1, b"a", &h(1)).unwrap();
        w.append(105, 2, b"b", &h(2)).unwrap(); // buraco
        let footer = w.seal().unwrap();
        assert!(!footer.is_contiguous_lsn());
        assert!(!footer.lsn_span_is_contiguous());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn footer_valido_no_meio_do_ficheiro_e_rejeitado() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("footer-no-meio.hrkl");
        let init = SegmentInit {
            segment_id: 3,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [0u8; 16],
        };
        let mut w = RawSegmentWriter::create(&path, init).unwrap();
        w.append(0, 1, b"a", &h(1)).unwrap();
        w.seal().unwrap();
        {
            use std::io::Write as _;
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(&encode_raw_record(1, 2, b"forjado"))
                .unwrap();
        }
        assert!(scan_raw_segment(&path).is_err());
        assert!(repair_active_tail(&path).is_err());
    }

    #[test]
    fn footer_completo_corrompido_nao_e_truncado_como_cauda() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("footer-corrupto.hrkl");
        let init = SegmentInit {
            segment_id: 4,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [0u8; 16],
        };
        let mut w = RawSegmentWriter::create(&path, init).unwrap();
        w.append(0, 1, b"a", &h(1)).unwrap();
        w.seal().unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        let footer_at = bytes.len() - FOOTER_LEN;
        bytes[footer_at + 104] ^= 0xFF; // CRC inválido, magic permanece.
        std::fs::write(&path, bytes).unwrap();

        assert!(read_footer(&path).unwrap().is_none());
        assert!(repair_active_tail(&path).is_err());
    }

    #[test]
    fn footer_com_metadados_incoerentes_e_rejeitado() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("footer-incoerente.hrkl");
        let init = SegmentInit {
            segment_id: 5,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [0u8; 16],
        };
        let mut w = RawSegmentWriter::create(&path, init).unwrap();
        w.append(0, 1, b"a", &h(1)).unwrap();
        w.seal().unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        let footer_at = bytes.len() - FOOTER_LEN;
        bytes[footer_at + 8..footer_at + 16].copy_from_slice(&2u64.to_le_bytes());
        bytes[footer_at + 104..footer_at + 108].fill(0);
        let crc = super::super::crc32c_of(&bytes[footer_at..]);
        bytes[footer_at + 104..footer_at + 108].copy_from_slice(&crc.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();

        assert!(scan_raw_segment(&path).is_err());
    }
}
