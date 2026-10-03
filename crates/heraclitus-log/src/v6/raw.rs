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
    /// Offset (desde o início do ficheiro) de cada registo, por ordem. Ver
    /// [`RawSegmentWriter::offset_of`]: 8 B por registo, ~136 KiB num segmento
    /// activo de 8 MiB com registos de ~500 B.
    offsets: Vec<u64>,
    /// Auditoria recursiva 2026-10-03, iteração 1: um `write_all` que falha a
    /// meio (ENOSPC, EDQUOT, EFBIG depois de uma escrita curta) deixava `k`
    /// bytes de lixo no ficheiro sem mexer em `bytes_written`; o retry do
    /// mesmo LSN caía depois do lixo, era confirmado ao cliente e ficava
    /// ilegível (o offset apontava para o lixo e o percurso parava no CRC
    /// errado) — e no arranque o `repair_active_tail` cortava-o como cauda
    /// rasgada, reutilizando o LSN. Agora o `append` corta o ficheiro de volta
    /// para `bytes_written`; se nem isso conseguir, o writer fica envenenado e
    /// recusa `append`/`seal` até a recuperação do arranque tratar da cauda.
    envenenado: bool,
    /// Injecção de falhas para os testes: escreve só os primeiros `k` bytes
    /// do próximo registo e devolve erro, como um disco que enche a meio.
    #[cfg(test)]
    falha_parcial: Option<usize>,
    /// Injecção de falhas para os testes: o próximo `sync` devolve erro sem
    /// tocar no ficheiro, como um `fsync` com EIO/ENOSPC.
    #[cfg(test)]
    pub(crate) falha_sync: bool,
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
        // O header TEM de ser durável antes de esta função devolver: o
        // `create_new` publica a entrada no directório imediatamente, mas o
        // `write_all` fica em buffers do SO, e sem este fsync uma falha de
        // energia deixava um ficheiro de segmento sem header no disco. Custa um
        // fsync por rolagem de segmento (8 MiB+), o que não se mede.
        //
        // ATENÇÃO ao que este fsync NÃO compra. Ele fecha a janela contra
        // perda de energia, não contra a morte do processo: um SIGKILL entre o
        // `create_new` acima e o `write_all` deixa na mesma um ficheiro de zero
        // bytes. Portanto a recuperação **não pode** assumir que um ficheiro de
        // segmento que existe tem header completo — uma versão anterior deste
        // comentário afirmava exactamente isso, e foi essa suposição que pôs o
        // crash-test a acusar de corrupção o que é a janela normal de um kill.
        // Quem escrever um leitor novo (replicação, restauro, doctor) tem de
        // filtrar o toco com `is_crash_stub` antes de ler o cabeçalho.
        file.sync_data()?;
        sync_parent_dir(path)?;
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
            offsets: Vec::new(),
            envenenado: false,
            #[cfg(test)]
            falha_parcial: None,
            #[cfg(test)]
            falha_sync: false,
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
        canonical_hasher: super::packer::CanonicalHasher<'_>,
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
        let mut offsets = Vec::with_capacity(scan.records.len());
        let mut offset = FILE_HEADER_LEN as u64;

        for record in &scan.records {
            offsets.push(offset);
            offset += (RAW_RECORD_HEADER_LEN + record.payload.len()) as u64;
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
        // Sem `append(true)`: no Windows esse modo abre o handle sem
        // FILE_WRITE_DATA e o `set_len` do rollback do `append` falharia
        // sempre. O cursor é posto à mão no fim (auditoria recursiva
        // 2026-10-03, iteração 1).
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.seek(SeekFrom::Start(bytes_written))?;
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
            offsets,
            envenenado: false,
            #[cfg(test)]
            falha_parcial: None,
            #[cfg(test)]
            falha_sync: false,
        })
    }

    /// Offset do registo `lsn` no ficheiro, se este writer o escreveu (ou o
    /// reconstruiu no `resume`) e os LSN forem contíguos.
    ///
    /// otimizacao-20m / auditoria 2026-09-05 (refutador de engine.rs:728/799),
    /// conferido em 2026-10-02: uma leitura pontual no segmento activo
    /// percorria o ficheiro desde o cabeçalho até ao LSN pedido — O(posição)
    /// por leitura, e o activo é onde caem as leituras mais quentes (recall
    /// sobre a memtable, AS OF recentes). Com o offset, é um `seek` e um
    /// registo.
    pub fn offset_of(&self, lsn: Lsn) -> Option<u64> {
        if !self.contiguous {
            return None;
        }
        let indice = usize::try_from(lsn.checked_sub(self.header.first_lsn)?).ok()?;
        self.offsets.get(indice).copied()
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
        self.recusar_se_envenenado()?;
        let bytes = encode_raw_record(lsn, hlc, payload);
        if let Err(e) = self.escrever(&bytes) {
            // Nenhum estado foi actualizado ainda; basta o ficheiro voltar a
            // terminar em `bytes_written` para o retry do mesmo LSN cair no
            // sítio certo. Se o corte falhar, a cauda tem lixo que só o
            // `repair_active_tail` do arranque sabe remover com segurança.
            if self.reverter_cauda().is_err() {
                self.envenenado = true;
            }
            return Err(e.into());
        }
        self.offsets.push(self.bytes_written);
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

    fn escrever(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        #[cfg(test)]
        if let Some(k) = self.falha_parcial.take() {
            self.file.write_all(&bytes[..k.min(bytes.len())])?;
            return Err(std::io::Error::other("falha parcial injectada"));
        }
        self.file.write_all(bytes)
    }

    /// Repõe o ficheiro e o cursor em `bytes_written`, descartando os bytes de
    /// uma escrita parcial.
    fn reverter_cauda(&mut self) -> std::io::Result<()> {
        self.file.set_len(self.bytes_written)?;
        self.file.seek(SeekFrom::Start(self.bytes_written))?;
        Ok(())
    }

    fn recusar_se_envenenado(&self) -> V6Result<()> {
        if self.envenenado {
            return Err(corrupt(
                "hrkl v6 raw writer",
                "writer poisoned: a partial write could not be rolled back;                  restart so recovery repairs the active tail",
            ));
        }
        Ok(())
    }

    /// `true` se uma escrita parcial não pôde ser revertida e o writer recusa
    /// novas escritas.
    pub fn is_poisoned(&self) -> bool {
        self.envenenado
    }

    pub fn sync(&mut self) -> V6Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.falha_sync) {
            return Err(std::io::Error::other("falha de fsync injectada").into());
        }
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
        // Um footer escrito depois de lixo seria inalcançável: o scan pára no
        // lixo e o `reconcile_raw` falharia depois do rename.
        self.recusar_se_envenenado()?;
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
/// Serve quem precisa mesmo do ficheiro todo: o packer, o `verify`, a migração
/// e o `resume` do writer. **Não** serve o ponto de leitura quente — para uma
/// leitura pontual ou uma janela existe [`percorrer_raw_segmento`], que faz
/// streaming e pára onde chega.
///
/// (O doc-comment anterior afirmava que "o caminho de leitura quente do motor
/// usa mmap". Era falso: `V6Log::read` chamava esta função e materializava o
/// segmento inteiro para devolver um registo. Auditoria 2026-09-05, A04.)
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

/// Decisão de quem está a visitar os registos de uma varredura em streaming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControloVarredura {
    Continuar,
    /// Já se tem o que era preciso: o resto do ficheiro não chega a ser lido.
    Parar,
}

/// Buffer de leitura do percurso em streaming. Um segmento activo vai até 8 MiB
/// por omissão; 256 KiB dão poucas syscalls sem prender memória por leitor.
const BUFFER_PERCURSO: usize = 256 * 1024;

/// Percorre os registos de um segmento RAW **em streaming**, entregando cada
/// payload por referência e parando onde quem visita mandar.
///
/// Auditoria 2026-09-05, A04/A13. O motor fazia toda a leitura RAW — pontual ou
/// por janela — com [`scan_raw_segment`], isto é, `read_to_end` do ficheiro
/// inteiro mais um `Vec<u8>` por registo, e a seguir deitava fora tudo menos o
/// que queria. Com os defaults (segmentos de 8 MiB, registos de ~500 B) uma
/// leitura pontual no segmento activo custava até 8 MiB de memcpy e ~16 000
/// alocações imediatamente descartadas. Aqui não há alocação por registo: o
/// buffer é reutilizado e quem visita decide se copia.
///
/// Devolve os **bytes do ficheiro percorridos** até parar — a medida honesta do
/// trabalho feito, e o que os testes usam para provar a paragem antecipada.
///
/// A máquina de estados é a de [`scan_raw_bytes`] e a descodificação é
/// literalmente [`decode_raw_record`], para não haver duas noções de registo
/// válido: mesmo CRC, mesmo tratamento de cauda rasgada, mesmo tecto de
/// `HARD_MAX_RECORD_BYTES`. A diferença deliberada é o que **não** acontece:
/// não corre `validate_raw_footer` nem a recusa de bytes depois do footer. Isso
/// é agora exclusivo de quem tem de o fazer — `verify_sealed`/
/// `verify_active_tail` e o boot, que confronta o tamanho do ficheiro com o
/// manifesto — exactamente como o ramo PACKED já vivia.
///
/// Correcção honesta ao que A04/A13 escreveram (revisão de A55): a troca **não**
/// se limita ao percurso parcial nem às leituras pontuais. Ao ver `FOOTER_MAGIC`
/// este laço devolve `Ok(pos)` sem olhar para o resto do footer, portanto mesmo
/// um percurso COMPLETO deixa de recusar um segmento selado cujo footer esteja
/// completo mas malformado — o `Corruption("complete footer is malformed or
/// corrupt")` que `scan_raw_bytes` dava ali deixa de acontecer. E, desde A13, o
/// que perde essa validação incidental são também os dois ramos RAW de
/// `scan_capped` (selados e cauda), não só o `read` pontual de A04. Nenhuma
/// linha se perde por isto — o footer vem depois de todos os registos — mas
/// quem quiser a garantia tem de pedir `verify_sealed`.
pub fn percorrer_raw_segmento<F>(path: &Path, mut visitar: F) -> V6Result<u64>
where
    F: FnMut(Lsn, u64, &[u8]) -> V6Result<ControloVarredura>,
{
    let file = File::open(path)?;
    let tamanho = file.metadata()?.len();
    let mut leitor = std::io::BufReader::with_capacity(BUFFER_PERCURSO, file);

    let mut cabecalho = vec![0u8; FILE_HEADER_LEN];
    let lidos = ler_ate_encher(&mut leitor, &mut cabecalho)?;
    cabecalho.truncate(lidos);
    // Um toco de crash (menos de um header) tem de dar o mesmo "short header"
    // que `scan_raw_bytes` dá — o boot filtra-o por `is_crash_stub`.
    let header = FileHeaderV6::decode(&cabecalho)?;
    if header.physical_layout != PhysicalLayout::Raw {
        return Err(corrupt("hrkl v6 raw scan", "segment is not RAW"));
    }

    let mut pos = FILE_HEADER_LEN as u64;
    let mut buf: Vec<u8> = Vec::with_capacity(RAW_RECORD_HEADER_LEN);
    loop {
        buf.clear();
        buf.resize(RAW_RECORD_HEADER_LEN, 0);
        if ler_ate_encher(&mut leitor, &mut buf)? < RAW_RECORD_HEADER_LEN {
            return Ok(pos); // fim do ficheiro ou cauda rasgada
        }
        if buf[..4] == FOOTER_MAGIC {
            return Ok(pos); // acabaram os registos
        }
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        // SPEC-0050 §140: um comprimento vindo do disco não pode chegar a um
        // `resize` sem passar por um tecto **e** pelo que resta do ficheiro. Em
        // memória o `decode_raw_record` compara com o buffer que já tem; aqui,
        // como ainda não lemos os bytes, o tecto tem de ser explícito.
        let restante = tamanho.saturating_sub(pos + RAW_RECORD_HEADER_LEN as u64);
        if len > HARD_MAX_RECORD_BYTES || len as u64 > restante {
            return Ok(pos); // cauda rasgada
        }
        buf.resize(RAW_RECORD_HEADER_LEN + len, 0);
        if ler_ate_encher(&mut leitor, &mut buf[RAW_RECORD_HEADER_LEN..])? < len {
            return Ok(pos);
        }
        match decode_raw_record(&buf) {
            RawDecoded::Record {
                lsn,
                hlc,
                payload,
                total,
            } => {
                let avanco = pos + total as u64;
                let controlo = visitar(lsn, hlc, payload)?;
                pos = avanco;
                if controlo == ControloVarredura::Parar {
                    return Ok(pos);
                }
            }
            // CRC falhado (ou um footer que não estava onde devia): é o mesmo
            // fim de percurso que `scan_raw_bytes` trata como cauda.
            RawDecoded::Footer(_) | RawDecoded::Torn => return Ok(pos),
        }
    }
}

/// Lê até encher `destino` ou acabar o ficheiro. Devolve quantos bytes leu.
///
/// Não é `read_exact`: o fim do ficheiro **não** é erro nesta camada — é o sinal
/// normal de fim de registos (ou de cauda rasgada, no segmento activo).
fn ler_ate_encher(leitor: &mut impl Read, destino: &mut [u8]) -> V6Result<usize> {
    let mut total = 0usize;
    while total < destino.len() {
        match leitor.read(&mut destino[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

/// O que uma procura pontual encontrou, e quanto do ficheiro custou.
#[derive(Debug)]
pub struct RawLookup {
    pub record: Option<RawRecord>,
    /// Bytes do ficheiro percorridos até parar.
    pub bytes_percorridos: u64,
}

/// Procura um LSN num segmento RAW, parando **no registo alvo**.
///
/// Auditoria 2026-09-05, A04: substitui o `scan_raw_segment(..).records.find(..)`
/// do caminho de leitura pontual do motor. Uma única cópia de payload em vez de
/// uma por registo do ficheiro, e em média metade dos bytes tocados.
///
/// Não pára em `lsn > alvo`, apesar de o motor v6 só escrever LSN crescentes: o
/// `RawSegmentWriter` aceita deliberadamente segmentos esparsos (ferramentas de
/// migração e perícia), e o comportamento anterior — `find` sobre todos os
/// registos do ficheiro — encontrava o alvo estivesse ele onde estivesse. A
/// paragem no alvo é a poupança que não custa nenhuma suposição nova.
/// Lê UM registo num offset conhecido (ver [`RawSegmentWriter::offset_of`]).
///
/// Mesma descodificação de [`decode_raw_record`] (CRC incluído) e os mesmos
/// tectos de comprimento de [`percorrer_raw_segmento`]. `Ok(None)` quando o
/// que está no offset não é o registo pedido (cauda rasgada, CRC, outro LSN):
/// quem chama recua para o percurso completo, que é a definição.
pub fn read_raw_record_at(path: &Path, offset: u64, alvo: Lsn) -> V6Result<Option<RawRecord>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = File::open(path)?;
    let tamanho = file.metadata()?.len();
    if offset < FILE_HEADER_LEN as u64 || offset + RAW_RECORD_HEADER_LEN as u64 > tamanho {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; RAW_RECORD_HEADER_LEN];
    file.read_exact(&mut buf)?;
    if buf[..4] == FOOTER_MAGIC {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let restante = tamanho.saturating_sub(offset + RAW_RECORD_HEADER_LEN as u64);
    if len > HARD_MAX_RECORD_BYTES || len as u64 > restante {
        return Ok(None);
    }
    buf.resize(RAW_RECORD_HEADER_LEN + len, 0);
    file.read_exact(&mut buf[RAW_RECORD_HEADER_LEN..])?;
    match decode_raw_record(&buf) {
        RawDecoded::Record {
            lsn, hlc, payload, ..
        } if lsn == alvo => Ok(Some(RawRecord {
            lsn,
            hlc,
            payload: payload.to_vec(),
        })),
        _ => Ok(None),
    }
}

pub fn find_raw_record(path: &Path, alvo: Lsn) -> V6Result<RawLookup> {
    let mut encontrado = None;
    let bytes_percorridos = percorrer_raw_segmento(path, |lsn, hlc, payload| {
        if lsn != alvo {
            return Ok(ControloVarredura::Continuar);
        }
        encontrado = Some(RawRecord {
            lsn,
            hlc,
            payload: payload.to_vec(),
        });
        Ok(ControloVarredura::Parar)
    })?;
    Ok(RawLookup {
        record: encontrado,
        bytes_percorridos,
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
        if footer.min_lsn != 0 || footer.max_lsn != 0 || footer.min_hlc != 0 || footer.max_hlc != 0
        {
            return Err(corrupt(CTX, "empty RAW footer has non-zero ranges"));
        }
        return Ok(());
    }

    let min_lsn = records.iter().map(|r| r.lsn).min().unwrap();
    let max_lsn = records.iter().map(|r| r.lsn).max().unwrap();
    let min_hlc = records.iter().map(|r| r.hlc).min().unwrap();
    let max_hlc = records.iter().map(|r| r.hlc).max().unwrap();
    if (
        footer.min_lsn,
        footer.max_lsn,
        footer.min_hlc,
        footer.max_hlc,
    ) != (min_lsn, max_lsn, min_hlc, max_hlc)
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

/// Um ficheiro curto demais para conter sequer o header é um **toco de crash**,
/// não um segmento.
///
/// `RawSegmentWriter::create` publica a entrada de directório com `create_new`
/// e só depois escreve o header. O `sync_data` que se segue torna o header
/// durável contra falha de energia, mas **não fecha esta janela contra a morte
/// do processo**: um `SIGKILL` entre as duas syscalls deixa no disco um
/// ficheiro de zero bytes (ou com meio header). A recuperação não pode, por
/// isso, assumir que "um ficheiro que existe tem header completo" — foi essa
/// suposição que pôs o crash-test a falhar com `short header`.
///
/// A fronteira é deliberadamente só o **comprimento**, e é segura porque os
/// registos começam *depois* do header: um ficheiro com menos de
/// [`FILE_HEADER_LEN`] bytes não pode conter um único registo committed, logo
/// descartá-lo não perde nada. Isto não colide com §123 ("não truncar e fingir
/// que nada aconteceu") justamente porque não há nada a truncar.
///
/// Um ficheiro com header completo mas bytes errados **não** entra aqui: isso é
/// corrupção e tem de falhar alto.
///
/// # Pré-condição
/// Esta regra só é válida para a cauda **activa** (`{id}.active.hrkl`), e é
/// isso que a torna segura. Um RAW selado chega ao disco por rename atómico de
/// um ficheiro já completo, portanto nunca nasce curto; se um deles aparecer
/// curto, encolheu — o que é corrupção, e é apanhado por
/// `validate_catalogued_generations`, que compara o tamanho físico e a contagem
/// de registos contra o manifesto. Aplicar este predicado a um segmento selado
/// trocaria essa verificação apertada por um descarte silencioso.
pub fn is_crash_stub(path: &Path) -> V6Result<bool> {
    Ok(std::fs::metadata(path)?.len() < FILE_HEADER_LEN as u64)
}

/// Trunca a cauda rasgada de um segmento **activo** (§123).
///
/// Recusa-se a tocar num segmento selado: corrupção interna num ficheiro que já
/// tem footer é falha dura, não é "truncar e fingir que nada aconteceu".
///
/// Pressupõe um segmento com header. Um toco de crash (ver [`is_crash_stub`])
/// não é reparável — não há prefixo válido para preservar — e o chamador deve
/// filtrá-lo antes, como o motor faz no arranque.
pub fn repair_active_tail(path: &Path) -> V6Result<Option<u64>> {
    // Não basta confiar no resultado da varredura abaixo. Se um bit rodado em
    // um registo anterior fizer `scan_raw_segment` parar antes do fim, ela não
    // chega a observar o footer que continua válido no EOF. Nesse caso o
    // ficheiro já está selado e truncá-lo em `torn_at` apagaria história.
    //
    // Mas os últimos 128 bytes do ficheiro só PODEM ser um footer se
    // começarem numa fronteira de registo a que a varredura não chegou
    // (`>= torn_at`). Auditoria recursiva 2026-10-03, iteração 1: a versão
    // anterior olhava para o EOF ANTES de varrer e sem esta condição. Numa
    // cauda activa sem footer, esses bytes são o fim do payload do último
    // registo — conteúdo do cliente. Um evento com `"HFTR"` em EOF-128 fazia
    // o arranque recusar para sempre ("refusing to truncate a sealed
    // segment") uma cauda que a varredura lia limpa até ao EOF.
    let scan = scan_raw_segment(path)?;
    if scan.footer.is_some() {
        return Err(corrupt(
            "hrkl v6 raw recovery",
            "refusing to truncate a sealed segment; this is hard corruption",
        ));
    }
    // Varredura limpa até ao EOF numa fronteira de registo: não há cauda nem
    // footer. Seja o que for que esteja em EOF-128, está dentro de um registo
    // com CRC válido.
    let Some(at) = scan.torn_at else {
        return Ok(None);
    };
    // A presença de um footer válido no fim é a definição de segmento selado
    // (§24), independentemente de a passagem pelos registos conseguir chegar
    // até ele. Um footer verdadeiro começa sempre em `>= torn_at` (todos os
    // registos antes de `torn_at` são íntegros e o footer vem depois deles);
    // um "footer" que comece antes está dentro de um registo válido e não sela
    // nada. Checá-lo distingue uma cauda de footer parcial (não selada,
    // portanto recuperável) de corrupção interna num segmento selado (falha
    // dura).
    let len = std::fs::metadata(path)?.len();
    let footer_cabe_depois_do_rasgo = len
        .checked_sub(FOOTER_LEN as u64)
        .is_some_and(|inicio| inicio >= at);
    if footer_cabe_depois_do_rasgo && (read_footer(path)?.is_some() || footer_magic_at_eof(path)?) {
        return Err(corrupt(
            "hrkl v6 raw recovery",
            "refusing to truncate a sealed segment; this is hard corruption",
        ));
    }
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(at)?;
    file.sync_all()?;
    Ok(Some(at))
}

/// O footer que **sela** de facto um segmento RAW: válido no EOF *e* alcançado
/// pela varredura de registos, isto é, a começar numa fronteira de registo.
///
/// Auditoria recursiva 2026-10-03, iteração 1. [`read_footer`] só descodifica
/// os últimos 128 bytes; isso basta para um RAW selado (chega ao disco por
/// rename de um ficheiro já completo), mas não para decidir se uma cauda
/// `.active` está selada: aí esses bytes podem ser o fim do payload do último
/// registo, e um cliente pode lá pôr uma imagem de footer com CRC correcto (o
/// CRC do footer não tem chave). O motor renomeava então a cauda para
/// `.g0000.raw.hrkl` e o `reconcile_raw` falhava em todos os arranques
/// seguintes ("final RAW generation has no valid footer").
///
/// O `read_footer` fica como filtro barato: a varredura só corre quando o EOF
/// já parece um footer.
pub fn read_sealing_footer(path: &Path) -> V6Result<Option<FooterV6>> {
    if read_footer(path)?.is_none() {
        return Ok(None);
    }
    Ok(scan_raw_segment(path)?.footer)
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

/// Torna durável a **entrada de directório** de um ficheiro acabado de criar.
///
/// Sem isto, o `create_new` pode não sobreviver a um crash mesmo com o
/// conteúdo já sincronizado: em POSIX o nome só é durável depois de o
/// directório ser sincronizado. Em Windows não se abre um directório como
/// `File`, portanto isto é no-op e a durabilidade do nome fica pela
/// atomicidade do NTFS — o mesmo compromisso, declarado, que o
/// `heraclitus-raft::fsync_dir` já assume.
/// Torna durável a entrada de directório de `path`.
///
/// `pub(super)` de propósito: existiam TRÊS cópias privadas disto no v6
/// (`raw`, `packer`, `receipts`) e o `engine` não tinha nenhuma — foi
/// exactamente por isso que o `rename` que publica um RAW selado ficou sem
/// fsync do directório, enquanto o manifesto que o referencia é publicado com
/// `fsync` + rename. O manifesto podia assim apontar para um nome de ficheiro
/// que uma falha de energia ainda não tinha tornado visível.
pub(super) fn sync_parent_dir(path: &Path) -> V6Result<()> {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        if let Ok(f) = File::open(dir) {
            f.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(i: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[0] = i;
        x
    }

    /// O offset que o writer regista (e reconstrói no `resume`) aponta para
    /// o mesmo registo que o percurso completo encontra; um offset errado não
    /// devolve outro registo, devolve `None` (e o motor recua para o
    /// percurso).
    #[test]
    fn offset_do_writer_le_o_mesmo_registo_que_o_percurso() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("7.active.hrkl");
        let mut w = RawSegmentWriter::create(
            &path,
            SegmentInit {
                segment_id: 7,
                created_hlc: 1,
                first_lsn: 100,
                writer_epoch: 1,
                storage_namespace_id: [3; 16],
            },
        )
        .unwrap();
        for i in 0..50u64 {
            let payload = vec![i as u8; (i as usize * 37) % 300 + 1];
            w.append(100 + i, 1_000 + i, &payload, &h(i as u8)).unwrap();
        }
        w.sync().unwrap();
        let confere = |w: &RawSegmentWriter| {
            for lsn in 100..150u64 {
                let off = w.offset_of(lsn).expect("offset conhecido");
                let directo = read_raw_record_at(&path, off, lsn).unwrap().unwrap();
                let percorrido = find_raw_record(&path, lsn).unwrap().record.unwrap();
                assert_eq!(directo.lsn, percorrido.lsn);
                assert_eq!(directo.hlc, percorrido.hlc);
                assert_eq!(directo.payload, percorrido.payload);
                // Offset de outro registo: não pode servir este LSN.
                let outro = w.offset_of(if lsn == 100 { 101 } else { 100 }).unwrap();
                assert!(read_raw_record_at(&path, outro, lsn).unwrap().is_none());
            }
            assert!(w.offset_of(99).is_none());
            assert!(w.offset_of(150).is_none());
        };
        confere(&w);
        drop(w);
        let retomado = RawSegmentWriter::resume(&path, &|_, _, _| Ok([0u8; 32])).unwrap();
        confere(&retomado);
    }

    /// Auditoria recursiva 2026-10-03, iteração 1: uma escrita parcial que
    /// falha não pode deixar lixo antes do retry do mesmo LSN — tanto num
    /// writer criado como num retomado (que no Windows abria em modo append e
    /// não conseguia cortar o ficheiro).
    #[test]
    fn escrita_parcial_falhada_e_revertida_antes_do_retry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("9.active.hrkl");
        let mut w = RawSegmentWriter::create(
            &path,
            SegmentInit {
                segment_id: 9,
                created_hlc: 1,
                first_lsn: 1,
                writer_epoch: 1,
                storage_namespace_id: [4; 16],
            },
        )
        .unwrap();
        w.append(1, 10, b"primeiro", &h(1)).unwrap();

        let verifica = |w: &mut RawSegmentWriter, lsn: u64| {
            let antes = w.bytes_written();
            w.falha_parcial = Some(7);
            assert!(w
                .append(lsn, 10 + lsn, b"retry deste registo", &h(lsn as u8))
                .is_err());
            assert!(!w.is_poisoned());
            assert_eq!(std::fs::metadata(&path).unwrap().len(), antes);
            w.append(lsn, 10 + lsn, b"retry deste registo", &h(lsn as u8))
                .unwrap();
            w.sync().unwrap();
            let off = w.offset_of(lsn).unwrap();
            let r = read_raw_record_at(&path, off, lsn)
                .unwrap()
                .expect("registo legível");
            assert_eq!(r.payload, b"retry deste registo");
            assert!(find_raw_record(&path, lsn).unwrap().record.is_some());
        };
        verifica(&mut w, 2);
        drop(w);

        // Sem cauda rasgada: o arranque não corta nada.
        assert_eq!(repair_active_tail(&path).unwrap(), None);
        let mut w = RawSegmentWriter::resume(&path, &|_, _, _| Ok([0u8; 32])).unwrap();
        verifica(&mut w, 3);
        w.append(4, 14, b"quarto", &h(4)).unwrap();
        drop(w);

        let scan = scan_raw_segment(&path).unwrap();
        assert!(scan.torn_at.is_none());
        let lsns: Vec<u64> = scan.records.iter().map(|r| r.lsn).collect();
        assert_eq!(lsns, vec![1, 2, 3, 4]);
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

    /// Escreve um segmento RAW selado com `n` registos de payload fixo e
    /// devolve o caminho. Serve os testes da procura pontual.
    fn segmento_selado_com(nome: &str, n: u64) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hrkl6-raw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(nome);
        let _ = std::fs::remove_file(&path);
        let init = SegmentInit {
            segment_id: 11,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [7u8; 16],
        };
        let mut w = RawSegmentWriter::create(&path, init).unwrap();
        for i in 0..n {
            w.append(i, 1000 + i, &[b'p'; 512], &h((i % 251) as u8 + 1))
                .unwrap();
        }
        w.seal().unwrap();
        path
    }

    #[test]
    fn procura_pontual_para_no_alvo_em_vez_de_percorrer_o_segmento_todo() {
        // Auditoria 2026-09-05, A04: a leitura pontual do motor materializava o
        // segmento INTEIRO (`read_to_end` + um `Vec` por registo) para devolver
        // um registo. Um alvo no princípio do ficheiro tem de custar o princípio
        // do ficheiro.
        let path = segmento_selado_com("seg-lookup-cedo.hrkl", 500);
        let tamanho = std::fs::metadata(&path).unwrap().len();

        let achado = find_raw_record(&path, 9).unwrap();
        assert_eq!(achado.record.as_ref().unwrap().lsn, 9);
        assert_eq!(achado.record.as_ref().unwrap().hlc, 1009);
        assert_eq!(achado.record.as_ref().unwrap().payload, vec![b'p'; 512]);
        assert!(
            achado.bytes_percorridos < tamanho / 4,
            "percorreu {} de {tamanho} bytes para o 10.º registo",
            achado.bytes_percorridos
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn procura_pontual_devolve_o_mesmo_que_o_varrimento_completo() {
        // Rede de segurança da refactorização: o leitor em streaming e o
        // leitor que materializa o ficheiro têm de concordar registo a registo,
        // e concordar também no que NÃO existe.
        let path = segmento_selado_com("seg-lookup-equiv.hrkl", 120);
        let varrido = scan_raw_segment(&path).unwrap();
        assert_eq!(varrido.records.len(), 120);
        for esperado in &varrido.records {
            let achado = find_raw_record(&path, esperado.lsn).unwrap().record;
            let achado = achado.unwrap_or_else(|| panic!("LSN {} desapareceu", esperado.lsn));
            assert_eq!(achado.lsn, esperado.lsn);
            assert_eq!(achado.hlc, esperado.hlc);
            assert_eq!(achado.payload, esperado.payload);
        }
        // Acima do máximo e (por construção) inexistente: o percurso chega ao
        // footer e devolve `None`, não um erro.
        assert!(find_raw_record(&path, 120).unwrap().record.is_none());
        assert!(find_raw_record(&path, u64::MAX).unwrap().record.is_none());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn percurso_em_streaming_para_na_cauda_rasgada_como_o_varrimento() {
        // A cauda rasgada é o caso normal do segmento activo. O percurso em
        // streaming tem de a tratar como `scan_raw_bytes`: parar, sem erro.
        let dir = std::env::temp_dir().join(format!("hrkl6-raw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seg-stream-torn.hrkl");
        let _ = std::fs::remove_file(&path);
        let init = SegmentInit {
            segment_id: 12,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [0u8; 16],
        };
        let mut w = RawSegmentWriter::create(&path, init).unwrap();
        for i in 0..5u64 {
            w.append(i, i, b"abcdefgh", &h(i as u8 + 1)).unwrap();
        }
        w.sync().unwrap();
        let bom = std::fs::metadata(&path).unwrap().len();
        drop(w);
        {
            use std::io::Write as _;
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&encode_raw_record(5, 5, b"abcdefgh")[..10])
                .unwrap();
        }

        let mut vistos = Vec::new();
        let percorridos = percorrer_raw_segmento(&path, |lsn, _, _| {
            vistos.push(lsn);
            Ok(ControloVarredura::Continuar)
        })
        .unwrap();
        assert_eq!(vistos, vec![0, 1, 2, 3, 4]);
        assert_eq!(percorridos, bom);
        assert!(find_raw_record(&path, 5).unwrap().record.is_none());

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

    /// A fronteira entre "toco de crash" e corrupção, fixada por teste.
    ///
    /// O crash-test apanhava isto de forma probabilística — só quando o kill
    /// calhava entre o `create_new` e o header chegar ao ficheiro — e por isso
    /// era lido como flakiness. Aqui fabrica-se a condição directamente, para
    /// a prova deixar de depender de o relógio ajudar.
    #[test]
    fn ficheiro_curto_demais_para_ter_header_e_um_toco_de_crash() {
        let dir = tempfile::tempdir().unwrap();

        // Zero bytes: o `create_new` publicou a entrada de directório e o
        // processo morreu antes do `write_all`.
        let vazio = dir.path().join("toco-vazio.hrkl");
        std::fs::write(&vazio, b"").unwrap();
        assert!(is_crash_stub(&vazio).unwrap());

        // Header a meio: o `write_all` foi interrompido. Continua sem poder
        // conter registo nenhum, porque os registos vêm depois do header.
        let meio = dir.path().join("toco-meio.hrkl");
        std::fs::write(&meio, vec![0u8; FILE_HEADER_LEN - 1]).unwrap();
        assert!(is_crash_stub(&meio).unwrap());
    }

    #[test]
    fn header_completo_nao_e_toco_mesmo_estando_corrompido() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("header-corrupto.hrkl");
        let init = SegmentInit {
            segment_id: 9,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [0u8; 16],
        };
        let mut w = RawSegmentWriter::create(&path, init).unwrap();
        w.append(0, 1, b"a", &h(1)).unwrap();
        w.sync().unwrap();
        drop(w);

        // Um segmento legítimo, com header completo, não é um toco.
        assert!(!is_crash_stub(&path).unwrap());

        // Estragar um byte do header mantém o comprimento — e é exactamente
        // por isso que a regra é só o comprimento. Isto é corrupção e tem de
        // falhar alto (§123), não ser silenciosamente descartado como toco.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[20] ^= 0xFF;
        std::fs::write(&path, bytes).unwrap();

        assert!(!is_crash_stub(&path).unwrap());
        assert!(
            repair_active_tail(&path).is_err(),
            "header corrompido tem de falhar alto, nao ser tratado como toco"
        );
    }

    /// Auditoria recursiva 2026-10-03, iteração 1: os últimos 128 bytes de uma
    /// cauda activa são, sem footer, o fim do payload do último registo —
    /// conteúdo do cliente. Nem um `"HFTR"` solto nem uma imagem completa de
    /// footer (CRC sem chave, portanto forjável) lá dentro podem fazer a cauda
    /// passar por selada: a varredura lê-a limpa até ao EOF.
    #[test]
    fn footer_forjado_no_payload_do_ultimo_registo_nao_sela_a_cauda() {
        let dir = tempfile::tempdir().unwrap();
        let init = SegmentInit {
            segment_id: 11,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [6u8; 16],
        };
        let imagem = FooterV6 {
            record_count: 0,
            min_lsn: 0,
            max_lsn: 0,
            min_hlc: 0,
            max_hlc: 0,
            block_count: 0,
            flags: 0,
            block_directory_offset: 0,
            block_directory_len: 0,
            logical_root: [0u8; 32],
        }
        .encode();
        // Só o magic em EOF-128; e a imagem inteira a fechar o ficheiro.
        let mut so_magic = vec![b'x'; 300];
        so_magic[300 - FOOTER_LEN..300 - FOOTER_LEN + 4].copy_from_slice(&FOOTER_MAGIC);
        let mut imagem_inteira = vec![b'x'; 300];
        imagem_inteira[300 - FOOTER_LEN..].copy_from_slice(&imagem);

        for (nome, ultimo) in [("magic", so_magic), ("imagem", imagem_inteira)] {
            let path = dir.path().join(format!("{nome}.active.hrkl"));
            let mut w = RawSegmentWriter::create(&path, init).unwrap();
            w.append(0, 1, b"primeiro", &h(1)).unwrap();
            w.append(1, 2, &ultimo, &h(2)).unwrap();
            w.sync().unwrap();
            drop(w);
            let tamanho = std::fs::metadata(&path).unwrap().len();

            let scan = scan_raw_segment(&path).unwrap();
            assert_eq!(scan.records.len(), 2, "{nome}");
            assert!(scan.footer.is_none() && scan.torn_at.is_none(), "{nome}");
            assert!(
                read_sealing_footer(&path).unwrap().is_none(),
                "{nome}: footer dentro de um registo nao sela a cauda"
            );
            assert_eq!(
                repair_active_tail(&path).unwrap(),
                None,
                "{nome}: cauda integra recusada no arranque"
            );
            assert_eq!(std::fs::metadata(&path).unwrap().len(), tamanho);
        }
    }

    /// Contraprova: com uma cauda rasgada DEPOIS de um segmento selado cujo
    /// footer começa numa fronteira de registo além do rasgo, a recusa
    /// mantém-se (o footer verdadeiro começa sempre em `>= torn_at`).
    #[test]
    fn footer_verdadeiro_alem_do_rasgo_continua_a_ser_recusado() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("12.active.hrkl");
        let init = SegmentInit {
            segment_id: 12,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [7u8; 16],
        };
        let mut w = RawSegmentWriter::create(&path, init).unwrap();
        w.append(0, 1, b"primeiro registo", &h(1)).unwrap();
        w.append(1, 2, b"segundo registo", &h(2)).unwrap();
        w.seal().unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[FILE_HEADER_LEN + 30] ^= 0xFF; // payload do 1.º registo
        std::fs::write(&path, &bytes).unwrap();

        assert!(read_sealing_footer(&path).unwrap().is_none());
        assert!(repair_active_tail(&path).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), bytes.len() as u64);
    }
}
