//! Máscara de validade (NULL) colunar compacta (SPEC-000 §1.1, SPEC-0038 §2).
//!
//! Cada `Vector` carrega uma [`ValidityMask`] onde o bit `i` a `1` significa
//! "linha `i` é válida (não-NULL)". O caso comum — coluna sem nenhum NULL — não
//! aloca nada ([`ValidityMask::all_valid`]); a tabela `events` do motor vivo,
//! por exemplo, não tem colunas anuláveis (`analytics/vectorized.rs:50-56`).

/// Máscara de bits de validade. `bits == None` ⇒ todas as linhas válidas
/// (representação sem alocação para o caso dominante).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidityMask {
    len: usize,
    bits: Option<Vec<u64>>,
}

#[inline]
fn words_for(len: usize) -> usize {
    len.div_ceil(64)
}

#[inline]
fn ones_with_tail_cleared(len: usize) -> Vec<u64> {
    let mut w = vec![u64::MAX; words_for(len)];
    let rem = len % 64;
    if rem != 0 {
        if let Some(last) = w.last_mut() {
            *last &= (1u64 << rem) - 1;
        }
    }
    w
}

impl ValidityMask {
    /// Todas as `len` linhas válidas, sem alocação.
    pub fn all_valid(len: usize) -> Self {
        Self { len, bits: None }
    }

    /// Domínio (número de linhas).
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `true` se a linha `i` é válida (não-NULL).
    ///
    /// # Panics
    /// Se `i >= len`.
    pub fn is_valid(&self, i: usize) -> bool {
        assert!(i < self.len, "índice {i} fora do domínio {}", self.len);
        match &self.bits {
            None => true,
            Some(w) => (w[i / 64] >> (i % 64)) & 1 == 1,
        }
    }

    fn materialize(&mut self) {
        if self.bits.is_none() {
            self.bits = Some(ones_with_tail_cleared(self.len));
        }
    }

    /// Marca a linha `i` como NULL.
    pub fn set_null(&mut self, i: usize) {
        assert!(i < self.len, "índice {i} fora do domínio {}", self.len);
        self.materialize();
        if let Some(w) = &mut self.bits {
            w[i / 64] &= !(1u64 << (i % 64));
        }
    }

    /// Marca a linha `i` como válida.
    pub fn set_valid(&mut self, i: usize) {
        assert!(i < self.len, "índice {i} fora do domínio {}", self.len);
        self.materialize();
        if let Some(w) = &mut self.bits {
            w[i / 64] |= 1u64 << (i % 64);
        }
    }

    /// Número de linhas NULL.
    pub fn null_count(&self) -> usize {
        match &self.bits {
            None => 0,
            Some(w) => self.len - w.iter().map(|x| x.count_ones() as usize).sum::<usize>(),
        }
    }

    /// Número de linhas válidas.
    pub fn valid_count(&self) -> usize {
        self.len - self.null_count()
    }

    /// `true` se há pelo menos um NULL.
    pub fn has_nulls(&self) -> bool {
        self.null_count() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_valid_no_alloc() {
        let m = ValidityMask::all_valid(1000);
        assert!(!m.has_nulls());
        assert_eq!(m.valid_count(), 1000);
        assert!(m.is_valid(0) && m.is_valid(999));
    }

    #[test]
    fn set_null_and_count() {
        let mut m = ValidityMask::all_valid(130);
        m.set_null(0);
        m.set_null(65);
        m.set_null(129);
        assert_eq!(m.null_count(), 3);
        assert_eq!(m.valid_count(), 127);
        assert!(!m.is_valid(65));
        assert!(m.is_valid(64));
    }

    #[test]
    fn set_valid_restores() {
        let mut m = ValidityMask::all_valid(64);
        m.set_null(10);
        assert!(!m.is_valid(10));
        m.set_valid(10);
        assert!(m.is_valid(10));
        assert!(!m.has_nulls());
    }

    #[test]
    fn tail_bits_not_counted() {
        // len=65 → 2 palavras; os 63 bits de cauda não podem contar como válidos.
        let m = ValidityMask::all_valid(65);
        assert_eq!(m.valid_count(), 65);
        let mut m2 = m.clone();
        m2.set_null(64);
        assert_eq!(m2.valid_count(), 64);
    }

    #[test]
    #[should_panic(expected = "fora do domínio")]
    fn rejects_oob() {
        ValidityMask::all_valid(10).is_valid(10);
    }
}
