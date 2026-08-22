//! SPEC-0050 §23–§24 — `FileHeaderV6`, exactamente 64 bytes.
//!
//! Codec **manual**. §136 é uma regra absoluta: nenhum tipo persistido usa
//! `repr(C)` como especificação de disco. Um `write_all(as_bytes(&header))`
//! congelaria no ficheiro o padding e a endianness da máquina que o escreveu —
//! e um segmento escrito em x86-64 deixaria de abrir em ARM64.
//!
//! ```text
//! Offset Size  Campo
//! 0      4     magic = "HRKL"
//! 4      2     format_version = 6
//! 6      2     header_len = 64
//! 8      1     physical_layout
//! 9      1     canonical_codec
//! 10     2     flags
//! 12     8     segment_id
//! 20     8     created_hlc
//! 28     8     first_lsn
//! 36     8     writer_epoch
//! 44     16    storage_namespace_id
//! 60     4     header_crc32c
//! ```
//!
//! O estado *sealed* **não** vive aqui (§24): é a existência de um footer
//! válido que sela um ficheiro. Mutar o header para selar exigiria reescrever
//! bytes já sincronizados de um ficheiro append-only.

use heraclitus_core::{Lsn, SegmentId};

use super::error::{corrupt, V6Result};

pub const HRKL_MAGIC: [u8; 4] = *b"HRKL";
pub const FORMAT_VERSION_V6: u16 = 6;
pub const FILE_HEADER_LEN: usize = 64;

// SPEC-0050 §24 — `PhysicalLayout` é vocabulário publicado (o manifesto, o
// packer, o tier e a CLI têm de o ler igual), por isso vive em
// `heraclitus_core::runtime` e é reexportado aqui. Uma segunda definição neste
// módulo seria um segundo significado para o mesmo byte em disco.
pub use heraclitus_core::runtime::PhysicalLayout;

/// Bits de `flags` no header. Reservados são zero no writer e ignorados no
/// reader compatível.
pub mod header_flags {
    /// O segmento declara LSN contíguo (`max_lsn - min_lsn + 1 == count`),
    /// SPEC-0050 §5. É uma *declaração de intenção* do writer; o footer e o
    /// block directory é que a confirmam.
    pub const CONTIGUOUS_LSN: u16 = 1 << 0;
}

/// Identificador criptográfico do banco (SPEC-0050 §20). Imutável durante a
/// existência lógica da base. Um segmento copiado à mão de outra base tem
/// namespace diferente e é recusado como nativo — que é exactamente o ponto:
/// uma raiz não pode ser transplantada em silêncio.
pub type StorageNamespaceId = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeaderV6 {
    pub physical_layout: PhysicalLayout,
    pub canonical_codec: u8,
    pub flags: u16,
    pub segment_id: SegmentId,
    pub created_hlc: u64,
    pub first_lsn: Lsn,
    /// Época do writer que abriu o ficheiro — separa dois processos que
    /// disputem o mesmo directório após um crash.
    pub writer_epoch: u64,
    pub storage_namespace_id: StorageNamespaceId,
}

impl FileHeaderV6 {
    pub fn encode(&self) -> [u8; FILE_HEADER_LEN] {
        let mut b = [0u8; FILE_HEADER_LEN];
        b[0..4].copy_from_slice(&HRKL_MAGIC);
        b[4..6].copy_from_slice(&FORMAT_VERSION_V6.to_le_bytes());
        b[6..8].copy_from_slice(&(FILE_HEADER_LEN as u16).to_le_bytes());
        b[8] = self.physical_layout as u8;
        b[9] = self.canonical_codec;
        b[10..12].copy_from_slice(&self.flags.to_le_bytes());
        b[12..20].copy_from_slice(&self.segment_id.to_le_bytes());
        b[20..28].copy_from_slice(&self.created_hlc.to_le_bytes());
        b[28..36].copy_from_slice(&self.first_lsn.to_le_bytes());
        b[36..44].copy_from_slice(&self.writer_epoch.to_le_bytes());
        b[44..60].copy_from_slice(&self.storage_namespace_id);
        let crc = super::crc32c_of(&b[..60]);
        b[60..64].copy_from_slice(&crc.to_le_bytes());
        b
    }

    pub fn decode(buf: &[u8]) -> V6Result<Self> {
        const CTX: &str = "hrkl v6 file header";
        if buf.len() < FILE_HEADER_LEN {
            return Err(corrupt(CTX, "short header"));
        }
        if buf[0..4] != HRKL_MAGIC {
            return Err(corrupt(CTX, "bad magic"));
        }
        let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        if version != FORMAT_VERSION_V6 {
            return Err(corrupt(CTX, format!("format_version {version} is not v6")));
        }
        let header_len = u16::from_le_bytes(buf[6..8].try_into().unwrap()) as usize;
        if header_len != FILE_HEADER_LEN {
            return Err(corrupt(
                CTX,
                format!("header_len {header_len} != {FILE_HEADER_LEN}"),
            ));
        }
        // O CRC vem ANTES de interpretar qualquer campo variável: nada de
        // confiar em bytes que ainda não se sabe se sobreviveram ao disco.
        let stored = u32::from_le_bytes(buf[60..64].try_into().unwrap());
        let actual = super::crc32c_of(&buf[..60]);
        if stored != actual {
            return Err(corrupt(
                CTX,
                format!("crc32c mismatch: stored {stored:#010x}, actual {actual:#010x}"),
            ));
        }
        Ok(Self {
            physical_layout: PhysicalLayout::from_u8(buf[8])?,
            canonical_codec: buf[9],
            flags: u16::from_le_bytes(buf[10..12].try_into().unwrap()),
            segment_id: u64::from_le_bytes(buf[12..20].try_into().unwrap()),
            created_hlc: u64::from_le_bytes(buf[20..28].try_into().unwrap()),
            first_lsn: u64::from_le_bytes(buf[28..36].try_into().unwrap()),
            writer_epoch: u64::from_le_bytes(buf[36..44].try_into().unwrap()),
            storage_namespace_id: buf[44..60].try_into().unwrap(),
        })
    }

    /// `true` se estes bytes começam por um header v6 (magic + versão). Barato,
    /// para o dispatcher que decide entre o leitor legado v1–v5 e o v6.
    pub fn looks_like_v6(buf: &[u8]) -> bool {
        buf.len() >= 6
            && buf[0..4] == HRKL_MAGIC
            && u16::from_le_bytes([buf[4], buf[5]]) == FORMAT_VERSION_V6
    }

    pub fn declares_contiguous_lsn(&self) -> bool {
        self.flags & header_flags::CONTIGUOUS_LSN != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amostra() -> FileHeaderV6 {
        FileHeaderV6 {
            physical_layout: PhysicalLayout::Raw,
            canonical_codec: super::super::canonical::CANONICAL_CODEC_V1,
            flags: header_flags::CONTIGUOUS_LSN,
            segment_id: 812,
            created_hlc: 0x0123_4567_89ab_cdef,
            first_lsn: 87_122_991,
            writer_epoch: 7,
            storage_namespace_id: [0xAB; 16],
        }
    }

    #[test]
    fn tem_exactamente_64_bytes() {
        assert_eq!(amostra().encode().len(), 64);
    }

    #[test]
    fn roundtrip() {
        let h = amostra();
        assert_eq!(FileHeaderV6::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn cada_byte_flipado_e_apanhado_pelo_crc() {
        let bytes = amostra().encode();
        for i in 0..60 {
            let mut c = bytes;
            c[i] ^= 0xff;
            assert!(FileHeaderV6::decode(&c).is_err(), "flip no byte {i} passou");
        }
    }

    #[test]
    fn versao_errada_e_recusada() {
        let mut b = amostra().encode();
        b[4..6].copy_from_slice(&5u16.to_le_bytes());
        assert!(FileHeaderV6::decode(&b).is_err());
        assert!(!FileHeaderV6::looks_like_v6(&b));
    }

    #[test]
    fn header_curto_nao_entra_em_panico() {
        for n in 0..FILE_HEADER_LEN {
            assert!(FileHeaderV6::decode(&vec![0u8; n]).is_err());
        }
    }

    #[test]
    fn layout_desconhecido_e_recusado() {
        let mut b = amostra().encode();
        b[8] = 9;
        let crc = super::super::crc32c_of(&b[..60]);
        b[60..64].copy_from_slice(&crc.to_le_bytes());
        assert!(FileHeaderV6::decode(&b).is_err());
    }
}
