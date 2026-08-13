//! Data Sketches Engine (SPEC-0039 §7) — estruturas probabilísticas de tamanho
//! fixo para o catálogo estatístico do otimizador:
//!
//! - [`HyperLogLog`] — estima **cardinalidade** (nº de valores distintos, NDV)
//!   em memória O(2^p), sem contagem exata.
//! - [`CountMin`] — estima **frequência** de chaves (nunca subestima), para
//!   filtros de existência e deteção de heavy-hitters antes de junções.
//!
//! std-only. São primitivas de referência — **não** estão ligadas ao CBO vivo.

/// Mistura determinística de 64 bits (splitmix64) — hash de inteiros e semente.
#[inline]
pub fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// FNV-1a 64-bit para sequências de bytes.
#[inline]
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ── HyperLogLog ─────────────────────────────────────────────────────────────

/// Estimador de cardinalidade HyperLogLog com `2^p` registos (`p ∈ 4..=16`).
///
/// Erro padrão relativo ≈ `1.04 / sqrt(2^p)` (ex.: `p=14` ⇒ ~0.8 %).
#[derive(Debug, Clone)]
pub struct HyperLogLog {
    p: u32,
    registers: Vec<u8>,
}

impl HyperLogLog {
    /// Novo sketch com `2^p` registos.
    ///
    /// # Panics
    /// Se `p` estiver fora de `4..=16`.
    pub fn new(p: u32) -> Self {
        assert!((4..=16).contains(&p), "p tem de estar em 4..=16");
        Self { p, registers: vec![0u8; 1usize << p] }
    }

    /// Regista um hash de 64 bits já calculado.
    pub fn add_hash(&mut self, hash: u64) {
        let idx = (hash >> (64 - self.p)) as usize;
        let suffix = hash & ((1u64 << (64 - self.p)) - 1);
        // Posição do 1 mais significativo no sufixo (64-p bits), +1.
        let rank = if suffix == 0 {
            (64 - self.p + 1) as u8
        } else {
            (suffix.leading_zeros() - self.p + 1) as u8
        };
        if rank > self.registers[idx] {
            self.registers[idx] = rank;
        }
    }

    /// Adiciona um inteiro (hasheado com splitmix64).
    pub fn add_u64(&mut self, v: u64) {
        self.add_hash(splitmix64(v));
    }

    /// Adiciona uma sequência de bytes (hasheada com FNV-1a).
    pub fn add_bytes(&mut self, b: &[u8]) {
        self.add_hash(fnv1a(b));
    }

    /// Estimativa de cardinalidade (com correção de intervalo pequeno).
    pub fn estimate(&self) -> f64 {
        let m = self.registers.len() as f64;
        let alpha = match self.registers.len() {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };
        let sum: f64 = self.registers.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        let raw = alpha * m * m / sum;
        // Linear counting quando há muitos registos a zero (baixa cardinalidade).
        let zeros = self.registers.iter().filter(|&&r| r == 0).count();
        if raw <= 2.5 * m && zeros > 0 {
            m * (m / zeros as f64).ln()
        } else {
            raw
        }
    }

    /// Une (`OR`) outro sketch do mesmo `p` — o máximo por registo. Permite
    /// contar distintos de partições fundidas sem re-varrer os dados.
    ///
    /// # Panics
    /// Se os `p` diferirem.
    pub fn merge(&mut self, other: &HyperLogLog) {
        assert_eq!(self.p, other.p, "merge exige o mesmo p");
        for (a, b) in self.registers.iter_mut().zip(&other.registers) {
            *a = (*a).max(*b);
        }
    }
}

// ── Count-Min Sketch ────────────────────────────────────────────────────────

/// Estimador de frequência Count-Min: `d` linhas × `w` colunas. Nunca
/// **subestima** a contagem real (pode sobrestimar por colisão).
#[derive(Debug, Clone)]
pub struct CountMin {
    d: usize,
    w: usize,
    counts: Vec<u32>,
    seeds: Vec<u64>,
}

impl CountMin {
    /// Novo sketch com `d` funções de hash e `w` contadores por função.
    ///
    /// # Panics
    /// Se `d == 0` ou `w == 0`.
    pub fn new(d: usize, w: usize) -> Self {
        assert!(d > 0 && w > 0, "d e w têm de ser > 0");
        let seeds = (0..d as u64).map(|i| splitmix64(0x1234_5678 ^ i)).collect();
        Self { d, w, counts: vec![0u32; d * w], seeds }
    }

    #[inline]
    fn slot(&self, row: usize, hash: u64) -> usize {
        let h = splitmix64(hash ^ self.seeds[row]);
        row * self.w + (h % self.w as u64) as usize
    }

    /// Incrementa a contagem da chave (hash) em `n`.
    pub fn add_hash(&mut self, hash: u64, n: u32) {
        for row in 0..self.d {
            let s = self.slot(row, hash);
            self.counts[s] = self.counts[s].saturating_add(n);
        }
    }

    /// Adiciona um inteiro.
    pub fn add_u64(&mut self, v: u64, n: u32) {
        self.add_hash(splitmix64(v), n);
    }

    /// Estima a frequência de um hash (mínimo sobre as linhas).
    pub fn estimate_hash(&self, hash: u64) -> u32 {
        (0..self.d).map(|row| self.counts[self.slot(row, hash)]).min().unwrap_or(0)
    }

    /// Estima a frequência de um inteiro.
    pub fn estimate_u64(&self, v: u64) -> u32 {
        self.estimate_hash(splitmix64(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hll_estimates_cardinality_within_error() {
        let mut hll = HyperLogLog::new(14); // m=16384, erro ~0.8%
        let n = 100_000u64;
        for v in 0..n {
            hll.add_u64(v);
        }
        let est = hll.estimate();
        let rel = (est - n as f64).abs() / n as f64;
        assert!(rel < 0.03, "erro relativo {rel} demasiado alto (est={est})");
    }

    #[test]
    fn hll_low_cardinality_is_accurate() {
        let mut hll = HyperLogLog::new(12);
        for v in 0..100u64 {
            hll.add_u64(v);
        }
        let est = hll.estimate();
        // Linear counting deve dar quase exato para cardinalidade baixa.
        assert!((est - 100.0).abs() < 5.0, "est={est}");
    }

    #[test]
    fn hll_duplicates_dont_inflate() {
        let mut hll = HyperLogLog::new(12);
        for _ in 0..10_000 {
            hll.add_u64(42); // sempre o mesmo
        }
        assert!(hll.estimate() < 3.0, "um só distinto: {}", hll.estimate());
    }

    #[test]
    fn hll_merge_is_union() {
        // p=14 (m=16384): 7500 distintos ficam na zona precisa (linear counting).
        let mut a = HyperLogLog::new(14);
        let mut b = HyperLogLog::new(14);
        for v in 0..5000u64 {
            a.add_u64(v);
        }
        for v in 2500..7500u64 {
            b.add_u64(v); // sobreposição parcial → união = 0..7500
        }
        a.merge(&b);
        let rel = (a.estimate() - 7500.0).abs() / 7500.0;
        assert!(rel < 0.03, "união estimada {} (rel {rel})", a.estimate());
    }

    #[test]
    fn countmin_never_underestimates() {
        let mut cm = CountMin::new(4, 2048);
        // 200 chaves com frequências conhecidas.
        for k in 0..200u64 {
            cm.add_u64(k, (k as u32) + 1);
        }
        for k in 0..200u64 {
            let true_count = (k as u32) + 1;
            assert!(cm.estimate_u64(k) >= true_count, "subestimou k={k}");
        }
    }

    #[test]
    fn countmin_heavy_hitter_is_tight() {
        let mut cm = CountMin::new(5, 4096);
        cm.add_u64(999, 1_000_000); // heavy hitter
        for k in 0..5000u64 {
            cm.add_u64(k, 1); // ruído
        }
        let est = cm.estimate_u64(999);
        // Sobrestima no máximo pelo ruído colidido; deve ficar muito perto.
        assert!(est >= 1_000_000);
        assert!(est < 1_010_000, "sobrestimou demais: {est}");
    }
}
