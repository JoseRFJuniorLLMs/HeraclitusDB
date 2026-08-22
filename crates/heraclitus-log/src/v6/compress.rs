//! SPEC-0050 §32–§34, §140–§141 — codecs de bloco, perfis e o *raw fallback*.
//!
//! # O fallback existe porque nem tudo comprime
//!
//! §34: se `compressed_size >= raw_size * threshold` o bloco é gravado
//! como `RAW`. Sem isto, um segmento de embeddings float ou de conteúdo já
//! cifrado ficaria **maior** depois de "comprimido" — e o gate §155
//! (expansão <= 2% em dados incompressíveis) seria impossível de cumprir.
//!
//! # Protecção contra bombas
//!
//! §140/§141: `uncompressed_len` vem do disco e é, por definição, input não
//! confiável. Antes de qualquer alocação verifica-se contra o tecto configurado
//! **e** contra os bytes que restam no ficheiro. Nunca há um
//! `Vec::with_capacity(untrusted_length)`.

use super::error::{corrupt, V6Result, HARD_MAX_BLOCK_BYTES};

// SPEC-0050 §32 — os IDs de codec são publicados e nunca reutilizados com
// outro significado; por isso o `enum` vive em `heraclitus_core::runtime`,
// onde o manifesto também o lê, e é reexportado aqui.
pub use heraclitus_core::runtime::CompressionCodec;

/// Perfis de packing (SPEC-0050 §33, §149).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackingProfile {
    /// CPU mínimo, tier warm, leitura de baixa latência.
    Fast,
    /// Default: densidade boa, decode rápido, custo de packing aceitável.
    Balanced,
    /// Só fora do hot-path.
    Archive,
}

impl PackingProfile {
    pub fn codec(self) -> CompressionCodec {
        match self {
            PackingProfile::Fast => CompressionCodec::Lz4Raw,
            PackingProfile::Balanced | PackingProfile::Archive => CompressionCodec::Zstd,
        }
    }
    pub fn level(self) -> i32 {
        match self {
            PackingProfile::Fast => 1,
            PackingProfile::Balanced => 3,
            PackingProfile::Archive => 6,
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "fast" | "throughput" => Some(PackingProfile::Fast),
            "balanced" => Some(PackingProfile::Balanced),
            "archive" => Some(PackingProfile::Archive),
            _ => None,
        }
    }
}

/// §34: exigir pelo menos ~8% de poupança antes de aceitar a versão comprimida.
pub const DEFAULT_RAW_FALLBACK_RATIO: f32 = 0.92;

/// O que o packer decidiu para um bloco.
#[derive(Debug)]
pub struct Compressed {
    pub codec: CompressionCodec,
    pub bytes: Vec<u8>,
}

/// Comprime `data` sob `profile`, aplicando o raw fallback.
///
/// A decisão é tomada **por bloco**, não por segmento: um segmento pode ter
/// blocos de texto muito compressíveis a seguir a um bloco de embeddings que
/// não comprime nada, e forçar um único codec para os dois desperdiça um dos
/// dois lados.
pub fn compress_block(
    data: &[u8],
    profile: PackingProfile,
    raw_fallback_ratio: f32,
) -> V6Result<Compressed> {
    if data.is_empty() {
        return Ok(Compressed {
            codec: CompressionCodec::Raw,
            bytes: Vec::new(),
        });
    }
    let codec = profile.codec();
    let candidate = match codec {
        CompressionCodec::Raw => None,
        CompressionCodec::Zstd => Some(
            zstd::bulk::compress(data, profile.level())
                .map_err(|e| corrupt("hrkl v6 packer", format!("zstd compress failed: {e}")))?,
        ),
        CompressionCodec::Lz4Raw => Some(lz4_flex::block::compress(data)),
    };
    match candidate {
        Some(c) if (c.len() as f64) < data.len() as f64 * raw_fallback_ratio as f64 => {
            Ok(Compressed { codec, bytes: c })
        }
        // Ou não comprimiu o suficiente, ou o codec é RAW: guarda-se cru.
        _ => Ok(Compressed {
            codec: CompressionCodec::Raw,
            bytes: data.to_vec(),
        }),
    }
}

/// Descomprime `stored` sabendo que deve dar exactamente `uncompressed_len`
/// bytes.
///
/// `max_block` é o tecto configurado; `stored` já foi delimitado pelo chamador
/// contra o tamanho real do ficheiro. As duas metades de §140.
pub fn decompress_block(
    codec: CompressionCodec,
    stored: &[u8],
    uncompressed_len: usize,
    max_block: usize,
) -> V6Result<Vec<u8>> {
    const CTX: &str = "hrkl v6 block";
    let ceiling = max_block.min(HARD_MAX_BLOCK_BYTES);
    if uncompressed_len > ceiling {
        return Err(corrupt(
            CTX,
            format!("uncompressed_len {uncompressed_len} exceeds configured maximum {ceiling}"),
        ));
    }
    let out = match codec {
        CompressionCodec::Raw => {
            if stored.len() != uncompressed_len {
                return Err(corrupt(
                    CTX,
                    format!(
                        "raw block stores {} bytes but declares {uncompressed_len}",
                        stored.len()
                    ),
                ));
            }
            stored.to_vec()
        }
        CompressionCodec::Zstd => zstd::bulk::decompress(stored, uncompressed_len)
            .map_err(|e| corrupt(CTX, format!("zstd decompress failed: {e}")))?,
        CompressionCodec::Lz4Raw => lz4_flex::block::decompress(stored, uncompressed_len)
            .map_err(|e| corrupt(CTX, format!("lz4 decompress failed: {e}")))?,
    };
    // O codec pode mentir sobre o que produziu; o contrato é o declarado.
    if out.len() != uncompressed_len {
        return Err(corrupt(
            CTX,
            format!(
                "decompressed to {} bytes, header declares {uncompressed_len}",
                out.len()
            ),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dados_repetitivos_comprimem_e_voltam_iguais() {
        let data = b"heraclitus".repeat(2000);
        for profile in [
            PackingProfile::Fast,
            PackingProfile::Balanced,
            PackingProfile::Archive,
        ] {
            let c = compress_block(&data, profile, DEFAULT_RAW_FALLBACK_RATIO).unwrap();
            assert_ne!(
                c.codec,
                CompressionCodec::Raw,
                "{profile:?} devia ter comprimido"
            );
            let back =
                decompress_block(c.codec, &c.bytes, data.len(), HARD_MAX_BLOCK_BYTES).unwrap();
            assert_eq!(back, data);
        }
    }

    #[test]
    fn dados_incompressiveis_caem_para_raw_sem_crescer() {
        // xorshift64: sem runs e sem substrings repetidas ao alcance de um
        // compressor de janela pequena — o pior caso real (conteúdo já cifrado,
        // embeddings float).
        let mut st: u64 = 0x2545_F491_4F6C_DD1D;
        let data: Vec<u8> = (0..8192)
            .map(|_| {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                (st >> 24) as u8
            })
            .collect();
        let c =
            compress_block(&data, PackingProfile::Balanced, DEFAULT_RAW_FALLBACK_RATIO).unwrap();
        assert_eq!(c.codec, CompressionCodec::Raw);
        assert_eq!(
            c.bytes.len(),
            data.len(),
            "fallback não pode expandir o bloco"
        );
        let back = decompress_block(c.codec, &c.bytes, data.len(), HARD_MAX_BLOCK_BYTES).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn bloco_vazio() {
        let c = compress_block(&[], PackingProfile::Balanced, DEFAULT_RAW_FALLBACK_RATIO).unwrap();
        assert_eq!(c.codec, CompressionCodec::Raw);
        assert!(decompress_block(c.codec, &c.bytes, 0, HARD_MAX_BLOCK_BYTES)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn bomba_de_descompressao_e_recusada_antes_de_alocar() {
        let e = decompress_block(CompressionCodec::Zstd, &[1, 2, 3], usize::MAX / 2, 262_144);
        assert!(e.is_err());
        let e = decompress_block(CompressionCodec::Raw, &[1, 2, 3], 1 << 30, 262_144);
        assert!(e.is_err());
    }

    #[test]
    fn comprimento_declarado_tem_de_bater() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let c =
            compress_block(&data, PackingProfile::Balanced, DEFAULT_RAW_FALLBACK_RATIO).unwrap();
        assert!(decompress_block(c.codec, &c.bytes, data.len() + 1, HARD_MAX_BLOCK_BYTES).is_err());
    }

    #[test]
    fn codec_desconhecido_e_recusado() {
        assert!(CompressionCodec::from_u8(3).is_err());
        for v in 0..=2u8 {
            assert_eq!(CompressionCodec::from_u8(v).unwrap() as u8, v);
        }
    }

    #[test]
    fn perfis_parseiam() {
        assert_eq!(
            PackingProfile::parse("balanced"),
            Some(PackingProfile::Balanced)
        );
        assert_eq!(
            PackingProfile::parse("ARCHIVE"),
            Some(PackingProfile::Archive)
        );
        assert_eq!(PackingProfile::parse("nonsense"), None);
    }
}
