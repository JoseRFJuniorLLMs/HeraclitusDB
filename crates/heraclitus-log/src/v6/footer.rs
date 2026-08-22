//! SPEC-0050 §52 — `FooterV6`, exactamente 128 bytes.
//!
//! O footer é o que **sela** o segmento: a sua existência e validade é o
//! critério de "este ficheiro está fechado" (§24). É também onde vive a
//! `logical_root`, a autoridade de identidade do segmento.
//!
//! ```text
//! Offset Size  Campo
//! 0      4     magic = "HFTR"
//! 4      2     footer_version = 1
//! 6      2     footer_len = 128
//! 8      8     record_count
//! 16     8     min_lsn
//! 24     8     max_lsn
//! 32     8     min_hlc
//! 40     8     max_hlc
//! 48     4     block_count          (0 em RAW)
//! 52     4     flags
//! 56     8     block_directory_offset (0 em RAW)
//! 64     8     block_directory_len    (0 em RAW)
//! 72     32    logical_root
//! 104    4     footer_crc32c
//! 108    20    reserved (zeros)
//! ```
//!
//! O CRC cobre os 128 bytes com o próprio campo `crc` a zero — assim protege
//! também os `reserved`, que de outro modo seriam um canal para 20 bytes
//! arbitrários por baixo do checksum.
//!
//! §172: o footer é pequeno de propósito. Bloom filters, HLL, histogramas,
//! dicionários analíticos e planner hints pertencem ao `.hrki`.

use heraclitus_core::Lsn;

use super::error::{corrupt, V6Result};

pub const FOOTER_MAGIC: [u8; 4] = *b"HFTR";
pub const FOOTER_VERSION_V6: u16 = 1;
pub const FOOTER_LEN: usize = 128;
const CRC_OFFSET: usize = 104;

pub mod footer_flags {
    /// LSN contíguo confirmado (`max_lsn - min_lsn + 1 == record_count`).
    pub const CONTIGUOUS_LSN: u32 = 1 << 0;
    /// Pelo menos um bloco usa `HLC` absoluto por não haver monotonicidade.
    pub const HAS_NON_MONOTONIC_HLC: u32 = 1 << 1;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FooterV6 {
    pub record_count: u64,
    pub min_lsn: Lsn,
    pub max_lsn: Lsn,
    pub min_hlc: u64,
    pub max_hlc: u64,
    pub block_count: u32,
    pub flags: u32,
    pub block_directory_offset: u64,
    pub block_directory_len: u64,
    pub logical_root: [u8; 32],
}

impl FooterV6 {
    pub fn encode(&self) -> [u8; FOOTER_LEN] {
        let mut b = [0u8; FOOTER_LEN];
        b[0..4].copy_from_slice(&FOOTER_MAGIC);
        b[4..6].copy_from_slice(&FOOTER_VERSION_V6.to_le_bytes());
        b[6..8].copy_from_slice(&(FOOTER_LEN as u16).to_le_bytes());
        b[8..16].copy_from_slice(&self.record_count.to_le_bytes());
        b[16..24].copy_from_slice(&self.min_lsn.to_le_bytes());
        b[24..32].copy_from_slice(&self.max_lsn.to_le_bytes());
        b[32..40].copy_from_slice(&self.min_hlc.to_le_bytes());
        b[40..48].copy_from_slice(&self.max_hlc.to_le_bytes());
        b[48..52].copy_from_slice(&self.block_count.to_le_bytes());
        b[52..56].copy_from_slice(&self.flags.to_le_bytes());
        b[56..64].copy_from_slice(&self.block_directory_offset.to_le_bytes());
        b[64..72].copy_from_slice(&self.block_directory_len.to_le_bytes());
        b[72..104].copy_from_slice(&self.logical_root);
        // reserved [108..128] já está a zero
        let crc = super::crc32c_of(&b); // campo crc ainda zerado
        b[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        b
    }

    pub fn decode(buf: &[u8]) -> V6Result<Self> {
        const CTX: &str = "hrkl v6 footer";
        if buf.len() < FOOTER_LEN {
            return Err(corrupt(CTX, "short footer"));
        }
        let buf = &buf[..FOOTER_LEN];
        if buf[0..4] != FOOTER_MAGIC {
            return Err(corrupt(CTX, "bad magic"));
        }
        let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        if version != FOOTER_VERSION_V6 {
            return Err(corrupt(
                CTX,
                format!("footer_version {version} unsupported"),
            ));
        }
        let footer_len = u16::from_le_bytes(buf[6..8].try_into().unwrap()) as usize;
        if footer_len != FOOTER_LEN {
            return Err(corrupt(
                CTX,
                format!("footer_len {footer_len} != {FOOTER_LEN}"),
            ));
        }
        let stored = u32::from_le_bytes(buf[CRC_OFFSET..CRC_OFFSET + 4].try_into().unwrap());
        let mut zeroed = [0u8; FOOTER_LEN];
        zeroed.copy_from_slice(buf);
        zeroed[CRC_OFFSET..CRC_OFFSET + 4].fill(0);
        let actual = super::crc32c_of(&zeroed);
        if stored != actual {
            return Err(corrupt(
                CTX,
                format!("crc32c mismatch: stored {stored:#010x}, actual {actual:#010x}"),
            ));
        }

        let f = Self {
            record_count: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            min_lsn: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            max_lsn: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            min_hlc: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            max_hlc: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            block_count: u32::from_le_bytes(buf[48..52].try_into().unwrap()),
            flags: u32::from_le_bytes(buf[52..56].try_into().unwrap()),
            block_directory_offset: u64::from_le_bytes(buf[56..64].try_into().unwrap()),
            block_directory_len: u64::from_le_bytes(buf[64..72].try_into().unwrap()),
            logical_root: buf[72..104].try_into().unwrap(),
        };
        f.check_coherence()?;
        Ok(f)
    }

    /// Coerência interna: um footer que passa o CRC pode ainda assim declarar
    /// intervalos impossíveis (um atacante com poder de escrita recalcula o
    /// CRC). Estas verificações são o que impede um `record_count` absurdo de
    /// chegar a um `with_capacity`.
    fn check_coherence(&self) -> V6Result<()> {
        const CTX: &str = "hrkl v6 footer";
        if self.record_count > 0 && self.min_lsn > self.max_lsn {
            return Err(corrupt(
                CTX,
                format!("min_lsn {} > max_lsn {}", self.min_lsn, self.max_lsn),
            ));
        }
        if self.record_count > 0 && self.min_hlc > self.max_hlc {
            return Err(corrupt(CTX, "min_hlc > max_hlc"));
        }
        if self.record_count > 0 {
            let span = self.max_lsn - self.min_lsn;
            if span.saturating_add(1) < self.record_count {
                return Err(corrupt(
                    CTX,
                    format!(
                        "record_count {} exceeds LSN span {}",
                        self.record_count,
                        span + 1
                    ),
                ));
            }
        }
        if self.block_count > super::error::HARD_MAX_BLOCKS {
            return Err(corrupt(
                CTX,
                format!("block_count {} above hard maximum", self.block_count),
            ));
        }
        let expected_dir = self.block_count as u64 * super::block_directory::DIR_ENTRY_LEN as u64;
        if self.block_directory_len != expected_dir {
            return Err(corrupt(
                CTX,
                format!(
                    "block_directory_len {} != block_count {} * {}",
                    self.block_directory_len,
                    self.block_count,
                    super::block_directory::DIR_ENTRY_LEN
                ),
            ));
        }
        Ok(())
    }

    pub fn is_contiguous_lsn(&self) -> bool {
        self.flags & footer_flags::CONTIGUOUS_LSN != 0
    }

    /// `true` se `max_lsn - min_lsn + 1 == record_count` de facto (SPEC-0050
    /// §5). O flag diz o que o writer afirmou; isto verifica-o.
    pub fn lsn_span_is_contiguous(&self) -> bool {
        self.record_count > 0 && self.max_lsn - self.min_lsn + 1 == self.record_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amostra() -> FooterV6 {
        FooterV6 {
            record_count: 521_991,
            min_lsn: 87_122_991,
            max_lsn: 87_644_981,
            min_hlc: 1_760_000_100,
            max_hlc: 1_760_900_450,
            block_count: 0,
            flags: footer_flags::CONTIGUOUS_LSN,
            block_directory_offset: 0,
            block_directory_len: 0,
            logical_root: [0x5A; 32],
        }
    }

    #[test]
    fn tem_exactamente_128_bytes() {
        assert_eq!(amostra().encode().len(), 128);
    }

    #[test]
    fn roundtrip() {
        let f = amostra();
        assert_eq!(FooterV6::decode(&f.encode()).unwrap(), f);
        assert!(f.lsn_span_is_contiguous());
    }

    #[test]
    fn reserved_esta_protegido_pelo_crc() {
        let mut b = amostra().encode();
        assert_eq!(&b[108..128], &[0u8; 20]);
        b[120] = 0x99;
        assert!(
            FooterV6::decode(&b).is_err(),
            "reserved fora do CRC seria um canal encoberto"
        );
    }

    #[test]
    fn cada_byte_flipado_e_apanhado() {
        let bytes = amostra().encode();
        for i in 0..FOOTER_LEN {
            if (CRC_OFFSET..CRC_OFFSET + 4).contains(&i) {
                continue;
            }
            let mut c = bytes;
            c[i] ^= 0xff;
            assert!(FooterV6::decode(&c).is_err(), "flip no byte {i} passou");
        }
    }

    #[test]
    fn intervalos_incoerentes_sao_recusados() {
        // record_count maior que o span de LSN é impossível.
        let mut f = amostra();
        f.record_count = f.max_lsn - f.min_lsn + 2;
        assert!(FooterV6::decode(&f.encode()).is_err());

        // min > max.
        let mut f = amostra();
        f.min_lsn = f.max_lsn + 1;
        assert!(FooterV6::decode(&f.encode()).is_err());

        // directory_len que não bate com block_count.
        let mut f = amostra();
        f.block_count = 3;
        f.block_directory_len = 7;
        assert!(FooterV6::decode(&f.encode()).is_err());
    }

    #[test]
    fn footer_curto_nao_entra_em_panico() {
        for n in 0..FOOTER_LEN {
            assert!(FooterV6::decode(&vec![0u8; n]).is_err());
        }
    }
}
