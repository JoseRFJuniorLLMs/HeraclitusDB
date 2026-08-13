//! Dimensionamento adaptativo de morsels (SPEC-0041 §2, Marco 3).
//!
//! O tamanho do bloco de varredura **não é fixo**. Começa em 8 192 linhas e é
//! escalado por uma escada `[8 192, 32 768, 65 536, 131 072]` de forma a que o
//! `DataChunk` caiba no cache L2/L3 do núcleo ativo. Duas alavancas:
//!
//! - [`MorselSizer::fit`] — escolha estática pela largura da linha: o maior
//!   tamanho da escada cujo `tamanho × bytes_por_linha` cabe no cache-alvo.
//! - [`MorselSizer::observe`] — ajuste dinâmico pela taxa de falhas de cache
//!   reportada pelo [`PipelineProfiler`]: sobe a escada quando o cache está
//!   folgado, desce quando satura.

/// Escada de tamanhos de morsel (`SPEC-0041 §2`).
pub const MORSEL_LADDER: [usize; 4] = [8_192, 32_768, 65_536, 131_072];

const MISS_HIGH: f64 = 0.10;
const MISS_LOW: f64 = 0.02;

/// Seletor de tamanho de morsel ciente do cache-alvo.
#[derive(Debug, Clone)]
pub struct MorselSizer {
    target_cache_bytes: usize,
    idx: usize,
}

impl MorselSizer {
    /// Novo seletor para um cache-alvo em bytes (ex.: 256 KiB de L2), começando
    /// no piso da escada.
    pub fn new(target_cache_bytes: usize) -> Self {
        Self { target_cache_bytes, idx: 0 }
    }

    /// Tamanho de morsel atual (topo da adaptação dinâmica).
    #[inline]
    pub fn current(&self) -> usize {
        MORSEL_LADDER[self.idx]
    }

    /// Maior tamanho da escada cujo `tamanho × bytes_por_linha` cabe no
    /// cache-alvo. Nunca abaixo do piso (8 192): um morsel mínimo amortiza o
    /// overhead de agendamento mesmo com linhas largas.
    pub fn fit(&self, bytes_per_row: usize) -> usize {
        if bytes_per_row == 0 {
            return *MORSEL_LADDER.last().unwrap();
        }
        let mut chosen = MORSEL_LADDER[0];
        for &size in MORSEL_LADDER.iter() {
            if size.saturating_mul(bytes_per_row) <= self.target_cache_bytes {
                chosen = size;
            }
        }
        chosen
    }

    /// Ajusta o tamanho corrente pela taxa de falhas de cache observada:
    /// satura (> 10 %) ⇒ desce um degrau; folgado (< 2 %) ⇒ sobe um degrau.
    /// Idempotente nos extremos da escada.
    pub fn observe(&mut self, cache_miss_rate: f64) {
        if cache_miss_rate > MISS_HIGH && self.idx > 0 {
            self.idx -= 1;
        } else if cache_miss_rate < MISS_LOW && self.idx < MORSEL_LADDER.len() - 1 {
            self.idx += 1;
        }
    }
}

/// Perfilador mínimo de pipeline: acumula linhas processadas e falhas de cache
/// para alimentar [`MorselSizer::observe`] (`SPEC-0041 §2`; no motor real os
/// contadores viriam de `perf_event_open`).
#[derive(Debug, Default, Clone)]
pub struct PipelineProfiler {
    rows: u64,
    cache_misses: u64,
}

impl PipelineProfiler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Regista um morsel processado: `rows` linhas, `misses` falhas de cache.
    pub fn record(&mut self, rows: u64, misses: u64) {
        self.rows = self.rows.saturating_add(rows);
        self.cache_misses = self.cache_misses.saturating_add(misses);
    }

    /// Falhas de cache por linha (0.0 se nada foi processado).
    pub fn miss_rate(&self) -> f64 {
        if self.rows == 0 {
            0.0
        } else {
            self.cache_misses as f64 / self.rows as f64
        }
    }

    /// Zera os contadores (início de um novo estágio).
    pub fn reset(&mut self) {
        self.rows = 0;
        self.cache_misses = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_by_row_width() {
        // Cache-alvo 256 KiB.
        let s = MorselSizer::new(256 * 1024);
        // Linhas estreitas (1 B) → cabe o maior morsel.
        assert_eq!(s.fit(1), 131_072);
        // 8 B/linha → 32 768 × 8 = 262 144 = 256 KiB (cabe exato); 65 536 estoura.
        assert_eq!(s.fit(8), 32_768);
        // Linhas largas (100 B) → nem o piso cabe → devolve o piso.
        assert_eq!(s.fit(100), 8_192);
        // bytes_por_linha desconhecido (0) → maior morsel.
        assert_eq!(s.fit(0), 131_072);
    }

    #[test]
    fn observe_climbs_and_descends() {
        let mut s = MorselSizer::new(1 << 20);
        assert_eq!(s.current(), 8_192);
        // Cache folgado: sobe degrau a degrau.
        s.observe(0.01);
        assert_eq!(s.current(), 32_768);
        s.observe(0.01);
        assert_eq!(s.current(), 65_536);
        // Satura: desce.
        s.observe(0.5);
        assert_eq!(s.current(), 32_768);
    }

    #[test]
    fn observe_clamps_at_extremes() {
        let mut s = MorselSizer::new(1 << 20);
        s.observe(0.9); // já no piso, não desce
        assert_eq!(s.current(), 8_192);
        for _ in 0..10 {
            s.observe(0.0); // sobe até ao teto e fica
        }
        assert_eq!(s.current(), 131_072);
    }

    #[test]
    fn profiler_feeds_sizer() {
        let mut p = PipelineProfiler::new();
        p.record(10_000, 50); // 0.5 % → folgado
        assert!((p.miss_rate() - 0.005).abs() < 1e-9);
        let mut s = MorselSizer::new(1 << 20);
        s.observe(p.miss_rate());
        assert_eq!(s.current(), 32_768);
        p.reset();
        assert_eq!(p.miss_rate(), 0.0);
    }
}
