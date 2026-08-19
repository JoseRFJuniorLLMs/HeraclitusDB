//! Sonda: o custo do CRC-32C do FORMAT v5.
//!
//! Desde `FORMAT_VERSION = 5` **todo** registo escrito e **todo** registo lido
//! passam por `cpm::Crc32c`, que é uma tabela byte-a-byte:
//!
//! ```ignore
//! for &b in data { crc = CRC32C_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8); }
//! ```
//!
//! Isto está no caminho crítico do worker de escrita (`lib.rs:783`,
//! `format::encode_record`) e em cada leitura/scan/verify (`decode_record`).
//! O x86-64 tem a instrução `crc32` (SSE4.2) desde 2008, que faz exatamente
//! este polinómio (Castagnoli, `0x1EDC6F41`) 8 bytes de cada vez.
//!
//! Esta sonda mede as duas, com o mesmo input, e confirma que produzem o MESMO
//! valor — a aceleração não pode mudar um único bit de nada já selado no disco.
//!
//! ```bash
//! cargo bench -p heraclitus-log --bench otim_crc
//! ```

use heraclitus_log::cpm::crc32c;
use std::time::Instant;

/// CRC-32C por hardware (SSE4.2). Mesmo polinómio, mesmo init/final XOR — o
/// resultado é bit-a-bit igual ao da tabela, o que o teste de igualdade abaixo
/// verifica antes de qualquer número de desempenho ser reportado.
#[cfg(target_arch = "x86_64")]
fn crc32c_hw(data: &[u8]) -> u32 {
    #[target_feature(enable = "sse4.2")]
    unsafe fn inner(data: &[u8]) -> u32 {
        use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};
        let mut crc: u64 = 0xFFFF_FFFF;
        let (pre, meio, pos) = data.align_to::<u64>();
        for &b in pre {
            crc = _mm_crc32_u8(crc as u32, b) as u64;
        }
        for &w in meio {
            crc = _mm_crc32_u64(crc, w);
        }
        for &b in pos {
            crc = _mm_crc32_u8(crc as u32, b) as u64;
        }
        !(crc as u32)
    }
    unsafe { inner(data) }
}

#[cfg(not(target_arch = "x86_64"))]
fn crc32c_hw(data: &[u8]) -> u32 {
    crc32c(data)
}

fn main() {
    println!("\n=== Sonda: CRC-32C tabela (atual) vs SSE4.2 (disponivel) ===\n");

    #[cfg(target_arch = "x86_64")]
    if !is_x86_feature_detected!("sse4.2") {
        println!("CPU sem SSE4.2 — sonda nao aplicavel.");
        return;
    }

    // Corretude primeiro: um acelerador que mude um bit invalida todo o log.
    for tam in [0usize, 1, 7, 8, 9, 63, 64, 65, 487, 4096, 65537] {
        let dados: Vec<u8> = (0..tam).map(|i| (i.wrapping_mul(31) ^ 0xA5) as u8).collect();
        assert_eq!(
            crc32c(&dados),
            crc32c_hw(&dados),
            "divergencia de CRC no tamanho {tam}"
        );
    }
    assert_eq!(crc32c(b"123456789"), 0xE306_9283, "vetor de teste CRC-32C");
    println!("corretude: identicas em 11 tamanhos + vetor de teste 0xE3069283 ✓\n");

    // 487 B é a média medida do registo real (auditoria de 1M/10M/20M);
    // os outros tamanhos delimitam a curva.
    for tam in [487usize, 4096, 65536, 1 << 20] {
        let dados: Vec<u8> = (0..tam).map(|i| (i.wrapping_mul(31) ^ 0xA5) as u8).collect();
        let voltas = (200_000_000 / tam).max(50);

        let t = Instant::now();
        let mut acc = 0u32;
        for _ in 0..voltas {
            acc ^= crc32c(std::hint::black_box(&dados));
        }
        let d_tab = t.elapsed();
        std::hint::black_box(acc);

        let t = Instant::now();
        let mut acc = 0u32;
        for _ in 0..voltas {
            acc ^= crc32c_hw(std::hint::black_box(&dados));
        }
        let d_hw = t.elapsed();
        std::hint::black_box(acc);

        let bytes = (tam * voltas) as f64;
        let rotulo = if tam == 487 { " (registo medio real)" } else { "" };
        println!("  bloco de {tam:>7} B{rotulo}");
        println!(
            "    tabela byte-a-byte (atual) : {:>8.0} MB/s",
            bytes / 1e6 / d_tab.as_secs_f64()
        );
        println!(
            "    SSE4.2 `crc32` (disponivel): {:>8.0} MB/s   ({:.1}x)",
            bytes / 1e6 / d_hw.as_secs_f64(),
            d_tab.as_secs_f64() / d_hw.as_secs_f64()
        );
    }

    // Tradução para a carga: 20M registos x 487 B, e o CRC corre DUAS vezes
    // por registo escrito (encode_record) e uma por registo lido.
    let dados: Vec<u8> = (0..487).map(|i| (i * 31 % 251) as u8).collect();
    let voltas = 400_000;
    let t = Instant::now();
    for _ in 0..voltas {
        std::hint::black_box(crc32c(std::hint::black_box(&dados)));
    }
    let por_reg_tab = t.elapsed().as_secs_f64() / voltas as f64;
    let t = Instant::now();
    for _ in 0..voltas {
        std::hint::black_box(crc32c_hw(std::hint::black_box(&dados)));
    }
    let por_reg_hw = t.elapsed().as_secs_f64() / voltas as f64;

    println!("\n  Traducao para 20 000 000 de registos de 487 B (uma passagem):");
    println!(
        "    tabela : {:>7.1} s de CPU so em CRC",
        por_reg_tab * 20e6
    );
    println!(
        "    SSE4.2 : {:>7.1} s de CPU so em CRC   (poupanca {:.1} s por passagem)",
        por_reg_hw * 20e6,
        (por_reg_tab - por_reg_hw) * 20e6
    );
    println!("\n  Passagens: 1 na escrita + 1 por scan completo + 1 por verify().\n");
}
