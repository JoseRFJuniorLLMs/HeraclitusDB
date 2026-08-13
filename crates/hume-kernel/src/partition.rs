//! Radix partitioning para hash joins cache-aware (SPEC-0038 §6).
//!
//! Agrupa as linhas por `bits` bits altos do hash da chave, em `2^bits` baldes,
//! usando o algoritmo clássico de dois passos (histograma → prefix-sum →
//! scatter) que produz um único array contíguo com offsets — o layout que
//! mantém cada partição a caber no cache L2/L3 durante o build/probe.

/// Resultado de um particionamento radix: baldes contíguos + offsets.
#[derive(Debug, Clone)]
pub struct Radix {
    pub bits: u32,
    /// `offsets[b]..offsets[b+1]` delimita o balde `b` em [`Radix::indices`].
    pub offsets: Vec<u32>,
    /// Índices de linha, agrupados por balde (ordem de entrada preservada).
    pub indices: Vec<u32>,
}

impl Radix {
    /// Particiona `hashes` por `bits` bits altos (`1..=16`).
    ///
    /// # Panics
    /// Se `bits` estiver fora de `1..=16`.
    pub fn build(hashes: &[u64], bits: u32) -> Self {
        assert!((1..=16).contains(&bits), "bits fora de 1..=16");
        let nb = 1usize << bits;
        let bucket_of = |h: u64| (h >> (64 - bits)) as usize;

        // Passo 1: histograma (deslocado 1 para virar offsets no prefix-sum).
        let mut offsets = vec![0u32; nb + 1];
        for &h in hashes {
            offsets[bucket_of(h) + 1] += 1;
        }
        // Passo 2: prefix-sum → posição inicial de cada balde.
        for i in 0..nb {
            offsets[i + 1] += offsets[i];
        }
        // Passo 3: scatter estável.
        let mut cursor = offsets.clone();
        let mut indices = vec![0u32; hashes.len()];
        for (i, &h) in hashes.iter().enumerate() {
            let b = bucket_of(h);
            indices[cursor[b] as usize] = i as u32;
            cursor[b] += 1;
        }
        Self { bits, offsets, indices }
    }

    /// Número de baldes (`2^bits`).
    pub fn num_buckets(&self) -> usize {
        1usize << self.bits
    }

    /// Índices de linha do balde `b`.
    pub fn bucket(&self, b: usize) -> &[u32] {
        &self.indices[self.offsets[b] as usize..self.offsets[b + 1] as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partitions_by_high_bits_and_preserves_all() {
        let hashes: Vec<u64> = (0..1000u64).map(|i| i.wrapping_mul(0x9E3779B97F4A7C15)).collect();
        let bits = 4;
        let r = Radix::build(&hashes, bits);
        assert_eq!(r.num_buckets(), 16);

        // Cada linha está no balde certo, e nenhuma se perde/duplica.
        let mut seen = vec![false; hashes.len()];
        for b in 0..r.num_buckets() {
            for &row in r.bucket(b) {
                assert_eq!((hashes[row as usize] >> (64 - bits)) as usize, b);
                assert!(!seen[row as usize], "linha duplicada");
                seen[row as usize] = true;
            }
        }
        assert!(seen.into_iter().all(|x| x), "todas as linhas presentes");
    }

    #[test]
    fn stable_order_within_bucket() {
        // Todos os hashes no mesmo balde (bit alto = 0) → ordem de entrada.
        let hashes = vec![1u64, 2, 3, 4, 5];
        let r = Radix::build(&hashes, 1);
        assert_eq!(r.bucket(0), &[0, 1, 2, 3, 4]);
        assert!(r.bucket(1).is_empty());
    }
}
