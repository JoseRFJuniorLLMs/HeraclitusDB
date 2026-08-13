//! Vetor de seleção adaptativo (SPEC-0041 §1-2, `selection/bitmap.rs`).
//!
//! O `SelectionVector` é a **moeda de troca universal** entre operadores do
//! HUME (`SPEC-0040 §5`): filtros, junções, saltos de grafo e buscas vetoriais
//! consomem e produzem o mesmo vetor de RowIDs ativos, sem materializar linhas
//! entre operadores (materialização tardia).
//!
//! A representação **adapta-se à seletividade real** medida em runtime
//! (`SPEC-0041 §2`):
//!
//! - **Alta densidade (≥ 25 % de sobrevivência)** → [`Rep::Bitmap`]: as ops
//!   booleanas (`AND`/`OR`/`NOT`) tornam-se bit a bit, diretas e *branchless*
//!   (uma palavra de 64 bits por instrução).
//! - **Baixa densidade (< 25 %)** → [`Rep::Index16`] / [`Rep::Index32`]: evita
//!   varrer milhões de bits zerados; compacta o espaço de cache e acelera a
//!   materialização tardia. `Index16` quando o domínio cabe em 16 bits
//!   (≤ 65 536 linhas por morsel), `Index32` para blocos maiores.
//!
//! Toda a lógica é `std`-only e correta por construção — validada nos testes
//! contra uma referência de força bruta (`Vec<bool>`).

/// Limiar de densidade acima do qual a representação `Bitmap` é preferida
/// (`SPEC-0041 §2`).
pub const BITMAP_DENSITY_THRESHOLD: f64 = 0.25;

/// Domínio máximo (linhas por morsel) em que os índices ainda cabem em `u16`.
pub const INDEX16_MAX_DOMAIN: usize = 1 << 16; // 65 536

/// Representação física interna do vetor de seleção.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rep {
    /// Bitmask compacto, uma palavra por 64 linhas do domínio.
    Bitmap(Vec<u64>),
    /// Lista ordenada de RowIDs ativos, cada um em 16 bits.
    Index16(Vec<u16>),
    /// Lista ordenada de RowIDs ativos, cada um em 32 bits.
    Index32(Vec<u32>),
}

/// Vetor de seleção sobre um domínio de `len` linhas (o tamanho do morsel).
///
/// Invariante: os índices ativos estão sempre em `0..len`, ordenados e sem
/// duplicados; a representação é escolhida por [`SelectionVector::optimized`].
///
/// ```
/// use hume_kernel::SelectionVector;
/// // 3 sobreviventes em 1000 linhas → baixa densidade → Index16
/// let s = SelectionVector::from_indices(1000, &[7, 42, 900]);
/// assert_eq!(s.selected(), 3);
/// assert_eq!(s.to_indices(), vec![7, 42, 900]);
/// assert!(s.is_index());
///
/// // tudo selecionado → alta densidade → Bitmap
/// let full = SelectionVector::all(1000);
/// assert_eq!(full.selected(), 1000);
/// assert!(full.is_bitmap());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionVector {
    len: usize,
    rep: Rep,
}

#[inline]
fn words_for(len: usize) -> usize {
    len.div_ceil(64)
}

impl SelectionVector {
    /// Domínio (número total de linhas do morsel).
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` se o domínio é vazio (`len == 0`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// A representação física atual (introspeção / testes).
    #[inline]
    pub fn rep(&self) -> &Rep {
        &self.rep
    }

    pub fn is_bitmap(&self) -> bool {
        matches!(self.rep, Rep::Bitmap(_))
    }

    pub fn is_index(&self) -> bool {
        matches!(self.rep, Rep::Index16(_) | Rep::Index32(_))
    }

    /// Seleção vazia sobre `len` linhas (nenhum RowID ativo).
    pub fn none(len: usize) -> Self {
        Self::from_bitmap(len, vec![0u64; words_for(len)])
    }

    /// Seleção total sobre `len` linhas (todos os RowIDs ativos).
    pub fn all(len: usize) -> Self {
        let mut words = vec![u64::MAX; words_for(len)];
        clear_tail(&mut words, len);
        Self::from_bitmap(len, words)
    }

    /// Constrói a partir de uma lista de índices (não precisa vir ordenada nem
    /// deduplicada — é normalizada). Escolhe a representação por densidade.
    ///
    /// # Panics
    /// Se algum índice for `>= len`.
    pub fn from_indices(len: usize, indices: &[u32]) -> Self {
        let mut words = vec![0u64; words_for(len)];
        for &i in indices {
            let i = i as usize;
            assert!(i < len, "índice {i} fora do domínio {len}");
            words[i / 64] |= 1u64 << (i % 64);
        }
        Self::from_bitmap(len, words)
    }

    /// Constrói a partir de um bitmap bruto (uma palavra por 64 linhas),
    /// otimizando a representação. Os bits da cauda (>= len) são ignorados.
    pub fn from_bitmap(len: usize, mut words: Vec<u64>) -> Self {
        words.resize(words_for(len), 0);
        clear_tail(&mut words, len);
        Self { len, rep: Rep::Bitmap(words) }.optimized()
    }

    /// Número de linhas ativas (RowIDs selecionados).
    pub fn selected(&self) -> usize {
        match &self.rep {
            Rep::Bitmap(w) => w.iter().map(|x| x.count_ones() as usize).sum(),
            Rep::Index16(v) => v.len(),
            Rep::Index32(v) => v.len(),
        }
    }

    /// Seletividade real = `selected / len` (0.0 se o domínio for vazio).
    pub fn selectivity(&self) -> f64 {
        if self.len == 0 {
            0.0
        } else {
            self.selected() as f64 / self.len as f64
        }
    }

    /// Materializa os RowIDs ativos, ordenados crescentemente (forma canónica).
    pub fn to_indices(&self) -> Vec<u32> {
        match &self.rep {
            Rep::Bitmap(words) => {
                let mut out = Vec::with_capacity(self.selected());
                for (wi, &word) in words.iter().enumerate() {
                    let mut w = word;
                    while w != 0 {
                        let bit = w.trailing_zeros() as usize;
                        out.push((wi * 64 + bit) as u32);
                        w &= w - 1; // limpa o bit menos significativo
                    }
                }
                out
            }
            Rep::Index16(v) => v.iter().map(|&x| x as u32).collect(),
            Rep::Index32(v) => v.clone(),
        }
    }

    /// Bitmap canónico (uma palavra por 64 linhas), independente da representação.
    pub fn to_bitmap(&self) -> Vec<u64> {
        match &self.rep {
            Rep::Bitmap(w) => w.clone(),
            Rep::Index16(_) | Rep::Index32(_) => {
                let mut words = vec![0u64; words_for(self.len)];
                for i in self.to_indices() {
                    let i = i as usize;
                    words[i / 64] |= 1u64 << (i % 64);
                }
                words
            }
        }
    }

    /// Reescolhe a representação física conforme a densidade atual
    /// (promoção/demora do `SPEC-0041 §2`). Não altera o conjunto selecionado.
    pub fn optimized(self) -> Self {
        let len = self.len;
        let selected = self.selected();
        let density = if len == 0 { 0.0 } else { selected as f64 / len as f64 };

        // Alta densidade → Bitmap.
        if density >= BITMAP_DENSITY_THRESHOLD {
            return Self { len, rep: Rep::Bitmap(self.to_bitmap()) };
        }
        // Baixa densidade → índices compactos.
        let indices = self.to_indices();
        let rep = if len <= INDEX16_MAX_DOMAIN {
            Rep::Index16(indices.into_iter().map(|x| x as u16).collect())
        } else {
            Rep::Index32(indices)
        };
        Self { len, rep }
    }

    /// Constrói a partir de índices **já ordenados, únicos e em `0..len`**,
    /// escolhendo a representação por densidade **sem materializar um bitmap
    /// denso no caso esparso**. É a base do fast-path esparso de [`and`].
    ///
    /// # Panics (só em debug)
    /// Se os índices não estiverem estritamente ordenados ou saírem do domínio.
    pub fn from_sorted_indices(len: usize, sorted: Vec<u32>) -> Self {
        debug_assert!(
            sorted.windows(2).all(|w| w[0] < w[1]),
            "from_sorted_indices exige índices estritamente crescentes"
        );
        debug_assert!(
            sorted.last().is_none_or(|&x| (x as usize) < len),
            "índice fora do domínio {len}"
        );
        let density = if len == 0 { 0.0 } else { sorted.len() as f64 / len as f64 };
        let rep = if density >= BITMAP_DENSITY_THRESHOLD {
            let mut words = vec![0u64; words_for(len)];
            for &i in &sorted {
                let i = i as usize;
                words[i / 64] |= 1u64 << (i % 64);
            }
            Rep::Bitmap(words)
        } else if len <= INDEX16_MAX_DOMAIN {
            Rep::Index16(sorted.into_iter().map(|x| x as u16).collect())
        } else {
            Rep::Index32(sorted)
        };
        Self { len, rep }
    }

    /// Interseção booleana (`AND`) com outro vetor do **mesmo domínio**.
    ///
    /// Fast-path esparso: quando ambos os operandos são representações `Index`,
    /// a interseção é um **merge de duas listas ordenadas** — O(a+b), sem tocar
    /// nos bits das linhas já cortadas. Caso contrário, cai no `AND` bit a bit
    /// sobre bitmaps densos (ótimo quando pelo menos um lado é denso).
    ///
    /// # Panics
    /// Se os domínios (`len`) diferirem.
    pub fn and(&self, other: &Self) -> Self {
        assert_eq!(self.len, other.len, "ops booleanas exigem o mesmo domínio");
        if self.is_index() && other.is_index() {
            let a = self.to_indices();
            let b = other.to_indices();
            let mut out = Vec::with_capacity(a.len().min(b.len()));
            let (mut i, mut j) = (0usize, 0usize);
            while i < a.len() && j < b.len() {
                match a[i].cmp(&b[j]) {
                    std::cmp::Ordering::Less => i += 1,
                    std::cmp::Ordering::Greater => j += 1,
                    std::cmp::Ordering::Equal => {
                        out.push(a[i]);
                        i += 1;
                        j += 1;
                    }
                }
            }
            return Self::from_sorted_indices(self.len, out);
        }
        self.zip_words(other, |a, b| a & b)
    }

    /// União booleana (`OR`) com outro vetor do **mesmo domínio**.
    ///
    /// # Panics
    /// Se os domínios (`len`) diferirem.
    pub fn or(&self, other: &Self) -> Self {
        self.zip_words(other, |a, b| a | b)
    }

    /// Complemento booleano (`NOT`): as linhas do domínio que **não** estavam
    /// selecionadas.
    pub fn not(&self) -> Self {
        let mut words = self.to_bitmap();
        for w in &mut words {
            *w = !*w;
        }
        clear_tail(&mut words, self.len);
        Self { len: self.len, rep: Rep::Bitmap(words) }.optimized()
    }

    fn zip_words(&self, other: &Self, op: impl Fn(u64, u64) -> u64) -> Self {
        assert_eq!(self.len, other.len, "ops booleanas exigem o mesmo domínio");
        let a = self.to_bitmap();
        let b = other.to_bitmap();
        let mut out = vec![0u64; a.len()];
        for i in 0..out.len() {
            out[i] = op(a[i], b[i]);
        }
        clear_tail(&mut out, self.len);
        Self { len: self.len, rep: Rep::Bitmap(out) }.optimized()
    }
}

/// Zera os bits da cauda (posições `>= len`) da última palavra, mantendo o
/// invariante de que nenhum bit fora do domínio está ativo.
#[inline]
fn clear_tail(words: &mut [u64], len: usize) {
    let rem = len % 64;
    if rem != 0 {
        if let Some(last) = words.last_mut() {
            *last &= (1u64 << rem) - 1;
        }
    }
    // Se len é múltiplo de 64, a última palavra é inteira — nada a limpar,
    // desde que words.len() == ceil(len/64) (garantido pelos construtores).
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Referência de força bruta: um domínio como `Vec<bool>`.
    fn brute(len: usize, idx: &[u32]) -> Vec<bool> {
        let mut v = vec![false; len];
        for &i in idx {
            v[i as usize] = true;
        }
        v
    }
    fn from_bools(b: &[bool]) -> Vec<u32> {
        b.iter()
            .enumerate()
            .filter(|(_, &x)| x)
            .map(|(i, _)| i as u32)
            .collect()
    }

    #[test]
    fn all_and_none() {
        let a = SelectionVector::all(200);
        assert_eq!(a.selected(), 200);
        assert!(a.is_bitmap());
        let n = SelectionVector::none(200);
        assert_eq!(n.selected(), 0);
        assert_eq!(n.to_indices(), Vec::<u32>::new());
    }

    #[test]
    fn tail_bits_never_leak() {
        // len=65 → 2 palavras; all() não pode ativar os 127 bits, só 65.
        let a = SelectionVector::all(65);
        assert_eq!(a.selected(), 65);
        assert_eq!(*a.to_indices().last().unwrap(), 64);
    }

    #[test]
    fn roundtrip_indices() {
        let idx = [0u32, 1, 63, 64, 65, 999];
        let s = SelectionVector::from_indices(1000, &idx);
        assert_eq!(s.to_indices(), idx.to_vec());
        assert_eq!(s.selected(), idx.len());
    }

    #[test]
    fn density_picks_representation() {
        // 3/1000 = 0.3% → Index16
        let sparse = SelectionVector::from_indices(1000, &[1, 2, 3]);
        assert!(sparse.is_index());
        assert!(matches!(sparse.rep(), Rep::Index16(_)));

        // 300/1000 = 30% ≥ 25% → Bitmap
        let dense_idx: Vec<u32> = (0..300).collect();
        let dense = SelectionVector::from_indices(1000, &dense_idx);
        assert!(dense.is_bitmap());

        // domínio > 65536 e esparso → Index32
        let big = SelectionVector::from_indices(200_000, &[10, 199_999]);
        assert!(matches!(big.rep(), Rep::Index32(_)));
    }

    #[test]
    fn boolean_ops_match_brute_force() {
        let len = 500;
        let ia: Vec<u32> = (0..len as u32).filter(|x| x % 3 == 0).collect();
        let ib: Vec<u32> = (0..len as u32).filter(|x| x % 5 == 0).collect();
        let a = SelectionVector::from_indices(len, &ia);
        let b = SelectionVector::from_indices(len, &ib);
        let (ba, bb) = (brute(len, &ia), brute(len, &ib));

        let and_ref: Vec<u32> = from_bools(
            &(0..len).map(|i| ba[i] && bb[i]).collect::<Vec<_>>(),
        );
        let or_ref: Vec<u32> =
            from_bools(&(0..len).map(|i| ba[i] || bb[i]).collect::<Vec<_>>());
        let not_a_ref: Vec<u32> = from_bools(&ba.iter().map(|x| !x).collect::<Vec<_>>());

        assert_eq!(a.and(&b).to_indices(), and_ref);
        assert_eq!(a.or(&b).to_indices(), or_ref);
        assert_eq!(a.not().to_indices(), not_a_ref);
    }

    #[test]
    fn sparse_and_merge_matches_brute_force() {
        // Ambos esparsos (<25%) → o fast-path de merge de listas ordenadas.
        let ia: Vec<u32> = (0..1000).filter(|x| x % 7 == 0).collect(); // ~14%
        let ib: Vec<u32> = (0..1000).filter(|x| x % 11 == 0).collect(); // ~9%
        let a = SelectionVector::from_indices(1000, &ia);
        let b = SelectionVector::from_indices(1000, &ib);
        assert!(a.is_index() && b.is_index(), "ambos devem ser esparsos");
        let got = a.and(&b);
        let expect: Vec<u32> = (0..1000).filter(|x| x % 7 == 0 && x % 11 == 0).collect();
        assert_eq!(got.to_indices(), expect);
    }

    #[test]
    fn from_sorted_indices_picks_representation() {
        let sparse = SelectionVector::from_sorted_indices(1000, vec![1, 500, 999]);
        assert!(matches!(sparse.rep(), Rep::Index16(_)));
        assert_eq!(sparse.to_indices(), vec![1, 500, 999]);
        let dense = SelectionVector::from_sorted_indices(100, (0..40).collect());
        assert!(dense.is_bitmap());
        let big = SelectionVector::from_sorted_indices(200_000, vec![7, 199_999]);
        assert!(matches!(big.rep(), Rep::Index32(_)));
    }

    #[test]
    fn double_negation_is_identity() {
        let s = SelectionVector::from_indices(300, &[5, 100, 299]);
        assert_eq!(s.not().not().to_indices(), s.to_indices());
    }

    #[test]
    fn representation_change_preserves_set() {
        // Construir esparso (Index) e denso (Bitmap) do mesmo conjunto lógico
        // via bitmap deve dar o mesmo to_indices.
        let idx: Vec<u32> = (0..1000).step_by(7).collect();
        let via_idx = SelectionVector::from_indices(1000, &idx);
        let via_bmp = SelectionVector::from_bitmap(1000, via_idx.to_bitmap());
        assert_eq!(via_idx.to_indices(), via_bmp.to_indices());
    }

    #[test]
    fn selectivity_reported() {
        let s = SelectionVector::from_indices(1000, &(0..250).collect::<Vec<_>>());
        assert!((s.selectivity() - 0.25).abs() < 1e-9);
    }

    #[test]
    #[should_panic(expected = "fora do domínio")]
    fn rejects_out_of_range_index() {
        let _ = SelectionVector::from_indices(10, &[10]);
    }

    #[test]
    #[should_panic(expected = "mesmo domínio")]
    fn rejects_mismatched_domain() {
        let a = SelectionVector::all(10);
        let b = SelectionVector::all(11);
        let _ = a.and(&b);
    }
}
