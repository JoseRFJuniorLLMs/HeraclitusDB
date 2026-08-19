//! CPM-200 §2 — a via física de deteção de corrupção: **CRC-32C (Castagnoli)**.
//!
//! Desde `format::FORMAT_VERSION = 5`, **todo registo escrito e todo registo
//! lido** passa por aqui: [`crate::format::encode_record`] no worker de escrita,
//! e [`crate::format::decode_record`] em cada leitura, scan, `Log::open` e
//! `verify()`. É, por isso, um dos caminhos mais quentes do motor.
//!
//! ## Duas vias, um resultado
//!
//! O polinómio é o mesmo (`0x1EDC6F41`, refletido), o init/final XOR é o mesmo
//! (`0xFFFF_FFFF`), e o resultado é **bit-a-bit idêntico** nas duas vias:
//!
//! - **hardware** (`sse4.2`): a instrução `crc32` do x86-64, que existe desde
//!   2008 e implementa exatamente este polinómio, 8 bytes por instrução;
//! - **tabela** (fallback): a variante byte-a-byte, para CPUs sem SSE4.2 e para
//!   arquiteturas não-x86.
//!
//! A escolha é feita **uma vez**, por deteção em runtime — não em tempo de
//! compilação — para o mesmo binário correr em qualquer máquina.
//!
//! ### Porque é que isto importa (medido, 2026-08-19)
//!
//! Sonda `benches/otim_crc.rs`, blocos de 487 B (o tamanho médio real de um
//! registo, medido na carga de 20M):
//!
//! ```text
//! tabela byte-a-byte :   349 MB/s
//! SSE4.2 `crc32`     :  9544 MB/s   = 27,3x
//! ```
//!
//! Traduzido para a carga de 20 000 000 de registos: **25,4 s de CPU por
//! passagem passam a 0,9 s**. E há três passagens no ciclo de vida normal —
//! escrita, varrimento completo, `verify()`.
//!
//! ### A regra que não se pode quebrar
//!
//! Um acelerador que mude **um único bit** invalida todo o log já selado: o CRC
//! viaja no registo, e a raiz Merkle do segmento é calculada sobre a mesma
//! região autenticada. Por isso a equivalência entre as duas vias é **testada**
//! (`hardware_e_tabela_concordam`), não assumida.
//!
//! > **Nota histórica.** Este módulo continha também uma implementação completa
//! > do Canonical Record Format v2 (`CpmRecord`, TLV, encoding canónico
//! > CPM-500) — cerca de 400 linhas que nunca foram ligadas ao caminho vivo:
//! > o log escreve `format::encode_record`, não CRF v2. Foi removida em
//! > 2026-08-19 (o git preserva-a) para não deixar um segundo formato de
//! > registo, não testado em produção, na superfície que um auditor tem de ler.

/// Tabela do CRC-32C refletido (poly `0x82F63B78` = reverso de `0x1EDC6F41`).
/// Só é usada quando não há SSE4.2 — mantida porque o motor tem de correr em
/// ARM e em x86 antigo sem mudar um bit do que grava.
const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// A via lenta. `crc` é o estado corrente (pré-final-XOR).
#[inline]
fn update_tabela(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = CRC32C_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// A via rápida. Mesmo estado corrente, mesma semântica — 8 bytes por
/// instrução no miolo alinhado, byte-a-byte nas pontas.
///
/// # Safety
/// O chamador garante que o CPU tem `sse4.2` (ver [`tem_sse42`]).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn update_hardware(crc: u32, data: &[u8]) -> u32 {
    use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};
    let mut c = crc as u64;
    // `align_to` dá as pontas desalinhadas e o miolo alinhado a u64. A ordem
    // de consumo dos bytes é a mesma da via de tabela (LSB-first), que é o que
    // torna os dois resultados idênticos.
    let (pre, meio, pos) = data.align_to::<u64>();
    for &b in pre {
        c = _mm_crc32_u8(c as u32, b) as u64;
    }
    for &w in meio {
        c = _mm_crc32_u64(c, w);
    }
    for &b in pos {
        c = _mm_crc32_u8(c as u32, b) as u64;
    }
    c as u32
}

/// Deteção feita UMA vez. `is_x86_feature_detected!` já cacheia internamente,
/// mas o `OnceLock` torna isso explícito e vale para o caso não-x86.
#[cfg(target_arch = "x86_64")]
#[inline]
fn tem_sse42() -> bool {
    static SSE42: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SSE42.get_or_init(|| is_x86_feature_detected!("sse4.2"))
}

#[inline]
fn update_despachado(crc: u32, data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if tem_sse42() {
            // SAFETY: `tem_sse42()` confirmou o suporte a SSE4.2 nesta CPU.
            return unsafe { update_hardware(crc, data) };
        }
    }
    update_tabela(crc, data)
}

/// Hasher incremental de CRC-32C.
///
/// Aceita o input em pedaços descontíguos — é como o `format::encode_record` o
/// usa, para saltar o campo `crc` do próprio registo sem alocar um buffer
/// intermédio.
pub struct Crc32c(u32);

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    pub fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0 = update_despachado(self.0, data);
    }

    pub fn finalize(self) -> u32 {
        !self.0
    }
}

/// CRC-32C de uma fatia única. Valor de teste canónico:
/// `crc32c(b"123456789") == 0xE306_9283`.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut h = Crc32c::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_vector() {
        // Canonical CRC-32C check value.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0x0000_0000);
    }

    #[test]
    fn atualizacao_incremental_iguala_fatia_unica() {
        let dados: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        for corte in [0usize, 1, 7, 8, 9, 63, 64, 65, 487, 999, 1000] {
            let mut h = Crc32c::new();
            h.update(&dados[..corte]);
            h.update(&dados[corte..]);
            assert_eq!(
                h.finalize(),
                crc32c(&dados),
                "corte em {corte} mudou o resultado"
            );
        }
    }

    /// O teste que autoriza a aceleração: um bit diferente entre as duas vias
    /// invalidaria todos os CRC e todas as raízes Merkle já gravadas em disco.
    #[test]
    fn hardware_e_tabela_concordam() {
        // Tamanhos escolhidos para exercitar as pontas desalinhadas do
        // `align_to::<u64>` e o registo médio real (487 B).
        for tam in [0usize, 1, 3, 7, 8, 9, 15, 16, 17, 63, 64, 65, 487, 4096, 65_537] {
            let dados: Vec<u8> = (0..tam).map(|i| (i.wrapping_mul(31) ^ 0xA5) as u8).collect();
            let tabela = !update_tabela(0xFFFF_FFFF, &dados);
            assert_eq!(
                tabela,
                crc32c(&dados),
                "via despachada divergiu da tabela no tamanho {tam}"
            );
        }
    }

    /// A mesma verificação, mas com o input desalinhado de propósito: um offset
    /// ímpar dentro do buffer força o ramo `pre` do `align_to`.
    #[test]
    fn concordam_com_input_desalinhado() {
        let base: Vec<u8> = (0..2048u32).map(|i| (i % 253) as u8).collect();
        for offset in 1..9usize {
            let fatia = &base[offset..];
            let tabela = !update_tabela(0xFFFF_FFFF, fatia);
            assert_eq!(tabela, crc32c(fatia), "divergencia no offset {offset}");
        }
    }
}
