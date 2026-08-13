//! Codecs de compressão densa para colunas de inteiros (SPEC-0039 §5,
//! SPEC-0041 §4 `compression/`).
//!
//! Cada codec é um par `encode`/`decode` com roundtrip exato (testado). São
//! primitivas de referência — não estão ligadas ao caminho de storage vivo.
//!
//! - [`rle`] — Run-Length Encoding (colunas de baixa cardinalidade / com runs).
//! - [`delta`] — diferenças sucessivas (sequências monótonas: timestamps, ids).
//! - [`frame_of_reference`] — mínimo + offsets (inteiros num intervalo estreito).
//! - [`bitpack`] — empacotamento em largura mínima de bits (combina com FOR).

/// Run-Length Encoding: `[7,7,7,3,3] → [(7,3),(3,2)]`.
pub mod rle {
    /// Codifica em pares `(valor, contagem)`.
    pub fn encode(data: &[u64]) -> Vec<(u64, u32)> {
        let mut out: Vec<(u64, u32)> = Vec::new();
        for &v in data {
            match out.last_mut() {
                Some((val, count)) if *val == v => *count += 1,
                _ => out.push((v, 1)),
            }
        }
        out
    }

    /// Reconstrói a sequência original.
    pub fn decode(runs: &[(u64, u32)]) -> Vec<u64> {
        let mut out = Vec::with_capacity(runs.iter().map(|(_, c)| *c as usize).sum());
        for &(v, c) in runs {
            out.extend(std::iter::repeat_n(v, c as usize));
        }
        out
    }
}

/// Delta encoding: guarda o 1.º valor absoluto e depois as diferenças (i64,
/// para permitir sequências decrescentes).
pub mod delta {
    /// `[100,102,105] → [100, 2, 3]`.
    pub fn encode(data: &[u64]) -> Vec<i64> {
        let mut out = Vec::with_capacity(data.len());
        let mut prev: i64 = 0;
        for (i, &v) in data.iter().enumerate() {
            let v = v as i64;
            if i == 0 {
                out.push(v);
            } else {
                out.push(v - prev);
            }
            prev = v;
        }
        out
    }

    /// Reconstrói a sequência original.
    pub fn decode(deltas: &[i64]) -> Vec<u64> {
        let mut out = Vec::with_capacity(deltas.len());
        let mut acc: i64 = 0;
        for (i, &d) in deltas.iter().enumerate() {
            acc = if i == 0 { d } else { acc + d };
            out.push(acc as u64);
        }
        out
    }
}

/// Frame of Reference: subtrai o mínimo, deixando offsets pequenos (que o
/// [`super::compression::bitpack`] depois empacota bem).
pub mod frame_of_reference {
    /// Devolve `(min, offsets)`.
    pub fn encode(data: &[u64]) -> (u64, Vec<u64>) {
        let min = data.iter().copied().min().unwrap_or(0);
        let offsets = data.iter().map(|&v| v - min).collect();
        (min, offsets)
    }

    /// Reconstrói a sequência original.
    pub fn decode(min: u64, offsets: &[u64]) -> Vec<u64> {
        offsets.iter().map(|&o| min + o).collect()
    }
}

/// Bit-packing: empacota inteiros usando exatamente `bits` bits cada, num fluxo
/// contíguo de palavras de 64 bits.
pub mod bitpack {
    /// Bits mínimos para representar todos os valores (`max_value`).
    pub fn min_bits(max_value: u64) -> u32 {
        if max_value == 0 {
            1
        } else {
            64 - max_value.leading_zeros()
        }
    }

    /// Empacota `values` com `bits` bits cada (`1..=64`).
    ///
    /// # Panics
    /// Se `bits` estiver fora de `1..=64`, ou se algum valor não couber em
    /// `bits` bits.
    pub fn pack(values: &[u64], bits: u32) -> Vec<u64> {
        assert!((1..=64).contains(&bits), "bits fora de 1..=64");
        if bits == 64 {
            return values.to_vec();
        }
        let mask = (1u64 << bits) - 1;
        let total_bits = values.len() * bits as usize;
        let mut out = vec![0u64; total_bits.div_ceil(64)];
        let mut bit_pos = 0usize;
        for &v in values {
            assert!(v <= mask, "valor {v} não cabe em {bits} bits");
            let word = bit_pos / 64;
            let off = bit_pos % 64;
            out[word] |= v << off;
            if off + bits as usize > 64 {
                out[word + 1] |= v >> (64 - off);
            }
            bit_pos += bits as usize;
        }
        out
    }

    /// Desempacota `count` valores de `bits` bits cada.
    pub fn unpack(packed: &[u64], bits: u32, count: usize) -> Vec<u64> {
        assert!((1..=64).contains(&bits), "bits fora de 1..=64");
        if bits == 64 {
            return packed[..count].to_vec();
        }
        let mask = (1u64 << bits) - 1;
        let mut out = Vec::with_capacity(count);
        let mut bit_pos = 0usize;
        for _ in 0..count {
            let word = bit_pos / 64;
            let off = bit_pos % 64;
            let mut v = packed[word] >> off;
            if off + bits as usize > 64 {
                v |= packed[word + 1] << (64 - off);
            }
            out.push(v & mask);
            bit_pos += bits as usize;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rle_roundtrip() {
        let data = vec![7, 7, 7, 3, 3, 9, 9, 9, 9];
        let enc = rle::encode(&data);
        assert_eq!(enc, vec![(7, 3), (3, 2), (9, 4)]);
        assert_eq!(rle::decode(&enc), data);
        assert!(rle::encode(&[]).is_empty());
    }

    #[test]
    fn delta_roundtrip_including_decreasing() {
        let data = vec![100u64, 102, 105, 104, 1000];
        let enc = delta::encode(&data);
        assert_eq!(enc, vec![100, 2, 3, -1, 896]);
        assert_eq!(delta::decode(&enc), data);
    }

    #[test]
    fn for_roundtrip() {
        let data = vec![1000u64, 1005, 1002, 1010];
        let (min, offs) = frame_of_reference::encode(&data);
        assert_eq!(min, 1000);
        assert_eq!(offs, vec![0, 5, 2, 10]);
        assert_eq!(frame_of_reference::decode(min, &offs), data);
    }

    #[test]
    fn bitpack_roundtrip_various_widths() {
        for bits in [1u32, 3, 7, 13, 32, 63, 64] {
            let mask = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
            let values: Vec<u64> = (0..500u64).map(|i| (i.wrapping_mul(2654435761)) & mask).collect();
            let packed = bitpack::pack(&values, bits);
            let got = bitpack::unpack(&packed, bits, values.len());
            assert_eq!(got, values, "roundtrip falhou em bits={bits}");
        }
    }

    #[test]
    fn min_bits_is_tight() {
        assert_eq!(bitpack::min_bits(0), 1);
        assert_eq!(bitpack::min_bits(1), 1);
        assert_eq!(bitpack::min_bits(2), 2);
        assert_eq!(bitpack::min_bits(255), 8);
        assert_eq!(bitpack::min_bits(256), 9);
    }

    #[test]
    fn for_plus_bitpack_compose() {
        // O caso canónico: inteiros grandes num intervalo estreito → FOR reduz a
        // magnitude, bitpack empacota os offsets pequenos.
        let data: Vec<u64> = (0..1000).map(|i| 1_000_000 + (i % 50)).collect();
        let (min, offs) = frame_of_reference::encode(&data);
        let bits = bitpack::min_bits(*offs.iter().max().unwrap());
        assert!(bits <= 6, "offsets 0..49 cabem em 6 bits");
        let packed = bitpack::pack(&offs, bits);
        let unpacked = bitpack::unpack(&packed, bits, offs.len());
        assert_eq!(frame_of_reference::decode(min, &unpacked), data);
        // Densidade: 1000 valores em ~6 bits vs 64 bits ⇒ >10x menos palavras.
        assert!(packed.len() * 10 < data.len());
    }
}
