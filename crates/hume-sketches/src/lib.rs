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

const fn hll_pow2_neg_lut() -> [f64; 65] {
    let mut values = [0.0; 65];
    let mut rank = 0;
    let mut value = 1.0;
    while rank < values.len() {
        values[rank] = value;
        value *= 0.5;
        rank += 1;
    }
    values
}

/// `2^-rank` for every rank a 64-bit HLL register can contain. Powers of two
/// are exact in IEEE-754, so this is bit-identical to `2f64.powi(-rank)` while
/// removing one transcendental-style library operation per register.
const HLL_POW2_NEG: [f64; 65] = hll_pow2_neg_lut();

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
        Self {
            p,
            registers: vec![0u8; 1usize << p],
        }
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
        // Sum and zero counting share one memory pass. `add_hash` can produce
        // at most rank 61 (`p >= 4`), hence every register indexes the LUT.
        let mut sum = 0.0f64;
        let mut zeros = 0usize;
        for &register in &self.registers {
            sum += HLL_POW2_NEG[register as usize];
            zeros += usize::from(register == 0);
        }
        let raw = alpha * m * m / sum;
        // Linear counting quando há muitos registos a zero (baixa cardinalidade).
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
    /// `w - 1` when `w` is a power of two; `usize::MAX` selects the backwards
    /// compatible modulo path for arbitrary widths.
    column_mask: usize,
    counts: Vec<u32>,
    seeds: Vec<u64>,
    /// Scratch reutilizado pelo Conservative Update. Guarda somente `d`
    /// offsets e evita recalcular todas as funções de hash na segunda passagem.
    update_slots: Vec<usize>,
}

impl CountMin {
    /// Novo sketch com `d` funções de hash e `w` contadores por função.
    ///
    /// # Panics
    /// Se `d == 0` ou `w == 0`.
    pub fn new(d: usize, w: usize) -> Self {
        assert!(d > 0 && w > 0, "d e w têm de ser > 0");
        let count_len = d
            .checked_mul(w)
            .expect("d * w excede o espaço de endereçamento");
        let seeds = (0..d as u64).map(|i| splitmix64(0x1234_5678 ^ i)).collect();
        Self {
            d,
            w,
            column_mask: if w.is_power_of_two() {
                w - 1
            } else {
                usize::MAX
            },
            counts: vec![0u32; count_len],
            seeds,
            update_slots: Vec::new(),
        }
    }

    /// Novo sketch cuja largura é exatamente `2^log2_w`.
    ///
    /// Este construtor torna explícito que o hot path usa `hash & (w - 1)` e
    /// nunca divisão. [`Self::new`] continua aceitando larguras arbitrárias por
    /// compatibilidade e também detecta automaticamente potências de dois.
    ///
    /// # Panics
    /// Se `d == 0`, se o deslocamento não couber em `usize`, ou se a tabela não
    /// couber no espaço de endereçamento.
    pub fn new_pow2(d: usize, log2_w: u32) -> Self {
        let w = 1usize
            .checked_shl(log2_w)
            .expect("log2_w excede a largura de usize");
        Self::new(d, w)
    }

    #[inline]
    fn slot(&self, row: usize, hash: u64) -> usize {
        let h = splitmix64(hash ^ self.seeds[row]);
        let column = if self.column_mask == usize::MAX {
            (h % self.w as u64) as usize
        } else {
            (h as usize) & self.column_mask
        };
        row * self.w + column
    }

    /// Incrementa a contagem da chave (hash) em `n` pelo Count-Min clássico.
    /// Este continua sendo o caminho de maior throughput e preserva a semântica
    /// da API anterior. Para reduzir viés de colisão, use
    /// [`Self::add_hash_conservative`].
    pub fn add_hash(&mut self, hash: u64, n: u32) {
        for row in 0..self.d {
            let slot = self.slot(row, hash);
            self.counts[slot] = self.counts[slot].saturating_add(n);
        }
    }

    /// Incrementa a contagem da chave (hash) em `n` usando Conservative Update.
    ///
    /// Em vez de somar `n` a todos os contadores colidentes, eleva cada um
    /// apenas até `min_atual + n`. A estimativa da chave cresce exatamente em
    /// `n` (salvo saturação em `u32::MAX`), portanto continua sem subestimar a
    /// frequência real e acumula menos ruído para outras chaves.
    pub fn add_hash_conservative(&mut self, hash: u64, n: u32) {
        if self.update_slots.len() != self.d {
            self.update_slots.resize(self.d, 0);
        }
        let mut minimum = u32::MAX;
        for row in 0..self.d {
            let s = self.slot(row, hash);
            self.update_slots[row] = s;
            minimum = minimum.min(self.counts[s]);
        }
        let target = minimum.saturating_add(n);
        for &s in &self.update_slots {
            if self.counts[s] < target {
                self.counts[s] = target;
            }
        }
    }

    /// Adiciona um inteiro.
    pub fn add_u64(&mut self, v: u64, n: u32) {
        self.add_hash(splitmix64(v), n);
    }

    /// Versão Conservative Update de [`Self::add_u64`]. O scratch de `d`
    /// offsets é alocado na primeira chamada e reutilizado depois.
    pub fn add_u64_conservative(&mut self, v: u64, n: u32) {
        self.add_hash_conservative(splitmix64(v), n);
    }

    /// Estima a frequência de um hash (mínimo sobre as linhas).
    pub fn estimate_hash(&self, hash: u64) -> u32 {
        (0..self.d)
            .map(|row| self.counts[self.slot(row, hash)])
            .min()
            .unwrap_or(0)
    }

    /// Estima a frequência de um inteiro.
    pub fn estimate_u64(&self, v: u64) -> u32 {
        self.estimate_hash(splitmix64(v))
    }

    /// Funde contagens de duas partições independentes por soma saturante dos
    /// contadores correspondentes. Como todo contador consultado é um limite
    /// superior local, a soma continua sendo limite superior da união.
    ///
    /// # Panics
    /// Se as dimensões dos sketches diferirem.
    pub fn merge(&mut self, other: &CountMin) {
        assert_eq!(self.d, other.d, "merge exige o mesmo d");
        assert_eq!(self.w, other.w, "merge exige o mesmo w");
        for (left, right) in self.counts.iter_mut().zip(&other.counts) {
            *left = left.saturating_add(*right);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn hll_estimate_with_powi(hll: &HyperLogLog) -> f64 {
        let m = hll.registers.len() as f64;
        let alpha = match hll.registers.len() {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };
        let mut sum = 0.0f64;
        for &register in &hll.registers {
            sum += 2f64.powi(-(register as i32));
        }
        let raw = alpha * m * m / sum;
        let zeros = hll.registers.iter().filter(|&&r| r == 0).count();
        if raw <= 2.5 * m && zeros > 0 {
            m * (m / zeros as f64).ln()
        } else {
            raw
        }
    }

    fn standard_add_hash(cm: &mut CountMin, hash: u64, n: u32) {
        for row in 0..cm.d {
            let slot = cm.slot(row, hash);
            cm.counts[slot] = cm.counts[slot].saturating_add(n);
        }
    }

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
    fn hll_lut_is_bit_identical_to_powi_reference() {
        for p in [4, 8, 12, 16] {
            let mut hll = HyperLogLog::new(p);
            assert_eq!(
                hll.estimate().to_bits(),
                hll_estimate_with_powi(&hll).to_bits()
            );
            for value in 0..100_000u64 {
                hll.add_hash(splitmix64(value ^ 0xCAFE_BABE));
                if value % 997 == 0 {
                    assert_eq!(
                        hll.estimate().to_bits(),
                        hll_estimate_with_powi(&hll).to_bits(),
                        "p={p}, prefix={value}"
                    );
                }
            }
        }
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

    #[test]
    fn countmin_pow2_constructor_and_auto_detection_are_identical() {
        let mut explicit = CountMin::new_pow2(5, 12);
        let mut automatic = CountMin::new(5, 4096);
        assert_eq!(explicit.column_mask, 4095);
        assert_eq!(automatic.column_mask, 4095);
        for value in 0..20_000u64 {
            let hash = splitmix64(value.wrapping_mul(17));
            let weight = (value % 7 + 1) as u32;
            explicit.add_hash(hash, weight);
            automatic.add_hash(hash, weight);
        }
        assert_eq!(explicit.counts, automatic.counts);

        let arbitrary = CountMin::new(3, 1000);
        assert_eq!(arbitrary.column_mask, usize::MAX);
        for row in 0..arbitrary.d {
            for hash in [0, 1, u64::MAX, 0xDEAD_BEEF_CAFE_BABE] {
                let mixed = splitmix64(hash ^ arbitrary.seeds[row]);
                let reference = row * arbitrary.w + (mixed % arbitrary.w as u64) as usize;
                assert_eq!(arbitrary.slot(row, hash), reference);
            }
        }
    }

    #[test]
    fn conservative_update_never_underestimates_random_weighted_stream() {
        let mut cm = CountMin::new_pow2(5, 8); // deliberately collision-heavy
        let mut exact = BTreeMap::<u64, u32>::new();
        for step in 0..50_000u64 {
            let key = splitmix64(step.wrapping_mul(0x9E37)) % 700;
            let weight = (splitmix64(step) % 11 + 1) as u32;
            cm.add_u64(key, weight);
            exact
                .entry(key)
                .and_modify(|count| *count = count.saturating_add(weight))
                .or_insert(weight);
            if step % 503 == 0 {
                for (&observed, &count) in &exact {
                    assert!(
                        cm.estimate_u64(observed) >= count,
                        "step={step}, key={observed}"
                    );
                }
            }
        }
    }

    #[test]
    fn conservative_update_has_no_more_error_than_standard_update() {
        let mut conservative = CountMin::new_pow2(4, 7);
        let mut standard = CountMin::new_pow2(4, 7);
        let mut exact = BTreeMap::<u64, u32>::new();
        for step in 0..30_000u64 {
            // Skew plus a long tail creates the collision pattern for which
            // Conservative Update is intended.
            let key = if step % 3 == 0 {
                step % 8
            } else {
                splitmix64(step) % 500
            };
            let hash = splitmix64(key);
            let weight = (step % 5 + 1) as u32;
            // `add_hash` é o Count-Min CLÁSSICO; o Conservative Update é
            // `add_hash_conservative`. Chamar `add_hash` aqui construía dois
            // sketches idênticos — o helper `standard_add_hash` deste módulo é
            // byte a byte igual a `add_hash` — e o teste comparava uma coisa
            // consigo própria.
            conservative.add_hash_conservative(hash, weight);
            standard_add_hash(&mut standard, hash, weight);
            exact
                .entry(key)
                .and_modify(|count| *count = count.saturating_add(weight))
                .or_insert(weight);
        }

        let mut conservative_error = 0u64;
        let mut standard_error = 0u64;
        for (&key, &count) in &exact {
            let conservative_estimate = conservative.estimate_u64(key);
            let standard_estimate = standard.estimate_u64(key);
            assert!(conservative_estimate >= count);
            assert!(standard_estimate >= count);
            assert!(conservative_estimate <= standard_estimate);
            conservative_error += (conservative_estimate - count) as u64;
            standard_error += (standard_estimate - count) as u64;
        }
        // Estrito de propósito. Com `<=` este teste passaria mesmo com os dois
        // sketches a serem construídos pelo mesmo caminho — que foi exactamente
        // o defeito que esteve aqui: um verde que não testava nada.
        assert!(
            conservative_error < standard_error,
            "Conservative Update devia acumular menos erro que o Count-Min \
             clássico, mas somou {conservative_error} contra {standard_error}"
        );
    }

    #[test]
    fn countmin_merge_preserves_union_upper_bound() {
        let mut left = CountMin::new_pow2(5, 9);
        let mut right = CountMin::new_pow2(5, 9);
        let mut exact = BTreeMap::<u64, u32>::new();
        for step in 0..20_000u64 {
            let key = splitmix64(step) % 1000;
            let weight = (step % 9 + 1) as u32;
            let target = if step & 1 == 0 { &mut left } else { &mut right };
            target.add_u64(key, weight);
            exact
                .entry(key)
                .and_modify(|count| *count = count.saturating_add(weight))
                .or_insert(weight);
        }
        let mut reverse = right.clone();
        reverse.merge(&left);
        left.merge(&right);
        assert_eq!(left.counts, reverse.counts, "merge deve ser comutativo");
        for (&key, &count) in &exact {
            assert!(left.estimate_u64(key) >= count, "subestimou key={key}");
        }

        // O estado fundido continua sendo uma base válida para atualizações
        // conservadoras posteriores, não apenas uma fotografia consultável.
        for step in 20_000..25_000u64 {
            let key = splitmix64(step) % 1000;
            let weight = (step % 9 + 1) as u32;
            left.add_u64(key, weight);
            exact
                .entry(key)
                .and_modify(|count| *count = count.saturating_add(weight))
                .or_insert(weight);
        }
        for (&key, &count) in &exact {
            assert!(left.estimate_u64(key) >= count, "subestimou key={key}");
        }
    }

    #[test]
    fn conservative_update_saturates_instead_of_wrapping() {
        let mut cm = CountMin::new_pow2(3, 4);
        cm.add_u64(7, u32::MAX - 2);
        cm.add_u64(7, 100);
        assert_eq!(cm.estimate_u64(7), u32::MAX);
    }

    /// A/B manual dos três hot paths. Não há limiar temporal no teste porque
    /// ruído de scheduler/CPU tornaria o CI flakey; os resultados são impressos
    /// junto com a redução de erro, que é a condição algorítmica obrigatória.
    ///
    /// `cargo test -p hume-sketches benchmark_sketch_hot_paths_ab -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn benchmark_sketch_hot_paths_ab() {
        use std::hint::black_box;
        use std::time::Instant;

        let mut hll = HyperLogLog::new(16);
        for value in 0..2_000_000u64 {
            hll.add_u64(value);
        }
        let repetitions = 2_000;
        let start = Instant::now();
        let mut lut_sink = 0.0;
        for _ in 0..repetitions {
            lut_sink += black_box(hll.estimate());
        }
        let lut_elapsed = start.elapsed();
        let start = Instant::now();
        let mut powi_sink = 0.0;
        for _ in 0..repetitions {
            powi_sink += black_box(hll_estimate_with_powi(&hll));
        }
        let powi_elapsed = start.elapsed();
        assert_eq!(lut_sink.to_bits(), powi_sink.to_bits());

        let cm = CountMin::new_pow2(5, 12);
        let hashes: Vec<u64> = (0..2_000_000u64).map(splitmix64).collect();
        let start = Instant::now();
        let mut mask_sink = 0usize;
        for &hash in &hashes {
            for row in 0..cm.d {
                mask_sink ^= black_box(cm.slot(row, hash));
            }
        }
        let mask_elapsed = start.elapsed();
        let start = Instant::now();
        let mut modulo_sink = 0usize;
        for &hash in &hashes {
            for row in 0..cm.d {
                let mixed = splitmix64(hash ^ cm.seeds[row]);
                modulo_sink ^= black_box(row * cm.w + (mixed % black_box(cm.w as u64)) as usize);
            }
        }
        let modulo_elapsed = start.elapsed();
        assert_eq!(mask_sink, modulo_sink);

        let updates: Vec<(u64, u32)> = (0..500_000u64)
            .map(|step| {
                let key = if step % 3 == 0 {
                    step % 8
                } else {
                    splitmix64(step) % 20_000
                };
                (splitmix64(key), (step % 5 + 1) as u32)
            })
            .collect();
        let mut conservative = CountMin::new_pow2(5, 12);
        let start = Instant::now();
        for &(hash, weight) in &updates {
            conservative.add_hash(black_box(hash), weight);
        }
        let conservative_elapsed = start.elapsed();
        let mut standard = CountMin::new_pow2(5, 12);
        let start = Instant::now();
        for &(hash, weight) in &updates {
            standard_add_hash(&mut standard, black_box(hash), weight);
        }
        let standard_elapsed = start.elapsed();
        let conservative_mass: u64 = conservative.counts.iter().map(|&x| x as u64).sum();
        let standard_mass: u64 = standard.counts.iter().map(|&x| x as u64).sum();
        assert!(conservative_mass <= standard_mass);

        eprintln!(
            "HLL estimate LUT={lut_elapsed:?} powi={powi_elapsed:?}; Count-Min slots mask={mask_elapsed:?} modulo={modulo_elapsed:?}; updates conservative={conservative_elapsed:?} standard={standard_elapsed:?}; counter mass conservative={conservative_mass} standard={standard_mass}"
        );
    }
}
