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
    /// Cardinalidade materializada junto com a representação. Bitmaps não
    /// precisam repetir `popcount` em cada consulta de seletividade/capacidade.
    selected: usize,
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
        let selected = words.iter().map(|x| x.count_ones() as usize).sum();
        Self {
            len,
            selected,
            rep: Rep::Bitmap(words),
        }
        .optimized()
    }

    /// Número de linhas ativas (RowIDs selecionados).
    #[inline]
    pub fn selected(&self) -> usize {
        self.selected
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
        let density = if len == 0 {
            0.0
        } else {
            selected as f64 / len as f64
        };

        // Alta densidade → Bitmap.
        if density >= BITMAP_DENSITY_THRESHOLD {
            return Self {
                len,
                selected,
                rep: Rep::Bitmap(self.to_bitmap()),
            };
        }
        // Baixa densidade → índices compactos.
        let indices = self.to_indices();
        let rep = if len <= INDEX16_MAX_DOMAIN {
            Rep::Index16(indices.into_iter().map(|x| x as u16).collect())
        } else {
            Rep::Index32(indices)
        };
        Self { len, selected, rep }
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
        let selected = sorted.len();
        let density = if len == 0 {
            0.0
        } else {
            selected as f64 / len as f64
        };
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
        Self { len, selected, rep }
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
        let out = match (&self.rep, &other.rep) {
            // Cada combinação esparsa opera directamente sobre a largura que
            // já está residente: sem dois `to_indices()` e sem dois temporários.
            (Rep::Index16(a), Rep::Index16(b)) => {
                intersect_sorted_by(a, b, |&x| x as u32, |&x| x as u32)
            }
            (Rep::Index32(a), Rep::Index32(b)) => intersect_sorted_by(a, b, |&x| x, |&x| x),
            (Rep::Index16(a), Rep::Index32(b)) => intersect_sorted_by(a, b, |&x| x as u32, |&x| x),
            (Rep::Index32(a), Rep::Index16(b)) => intersect_sorted_by(a, b, |&x| x, |&x| x as u32),
            // Bitmap ∩ lista testa apenas os RowIDs da lista. Converter o
            // bitmap inteiro seria precisamente o custo que a representação
            // adaptativa pretende evitar.
            (Rep::Bitmap(words), Rep::Index16(v)) | (Rep::Index16(v), Rep::Bitmap(words)) => v
                .iter()
                .map(|&x| x as u32)
                .filter(|&x| bitmap_contains(words, x))
                .collect(),
            (Rep::Bitmap(words), Rep::Index32(v)) | (Rep::Index32(v), Rep::Bitmap(words)) => v
                .iter()
                .copied()
                .filter(|&x| bitmap_contains(words, x))
                .collect(),
            (Rep::Bitmap(a), Rep::Bitmap(b)) => {
                let words = a.iter().zip(b).map(|(&left, &right)| left & right).collect();
                return Self::from_bitmap(self.len, words);
            }
        };
        Self::from_sorted_indices(self.len, out)
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
        Self::from_bitmap(self.len, words)
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
        Self::from_bitmap(self.len, out)
    }
}

#[inline]
fn bitmap_contains(words: &[u64], index: u32) -> bool {
    let index = index as usize;
    words
        .get(index / 64)
        .is_some_and(|word| word & (1u64 << (index % 64)) != 0)
}

const GALLOP_RATIO: usize = 8;

/// Primeiro índice `>= target`, partindo de `start`, com busca exponencial e
/// refinamento binário. O prefixo anterior a `start` já foi descartado.
fn gallop_lower_bound<T>(
    values: &[T],
    start: usize,
    target: u32,
    value: impl Fn(&T) -> u32 + Copy,
) -> usize {
    if start >= values.len() {
        return values.len();
    }
    intersection_probe();
    if value(&values[start]) >= target {
        return start;
    }

    let mut step = 1usize;
    while start.saturating_add(step) < values.len() {
        intersection_probe();
        if value(&values[start + step]) >= target {
            break;
        }
        step = step.saturating_mul(2);
    }

    // `start` e todas as posições até `step/2` já foram provadas menores.
    let mut lo = start
        .saturating_add(step / 2)
        .saturating_add(1)
        .min(values.len());
    let mut hi = start
        .saturating_add(step)
        .saturating_add(1)
        .min(values.len());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        intersection_probe();
        if value(&values[mid]) < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Interseção de duas listas ordenadas, possivelmente com larguras físicas
/// diferentes. Quando uma lista é muito menor, salta exponencialmente na maior;
/// em tamanhos próximos, o merge linear continua mais barato.
fn intersect_sorted_by<A, B>(
    a: &[A],
    b: &[B],
    a_value: impl Fn(&A) -> u32 + Copy,
    b_value: impl Fn(&B) -> u32 + Copy,
) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len().min(b.len()));
    if a.len().saturating_mul(GALLOP_RATIO) <= b.len() {
        let mut j = 0;
        for item in a {
            let needle = a_value(item);
            j = gallop_lower_bound(b, j, needle, b_value);
            if j == b.len() {
                break;
            }
            intersection_probe();
            if b_value(&b[j]) == needle {
                out.push(needle);
                j += 1;
            }
        }
        return out;
    }
    if b.len().saturating_mul(GALLOP_RATIO) <= a.len() {
        let mut i = 0;
        for item in b {
            let needle = b_value(item);
            i = gallop_lower_bound(a, i, needle, a_value);
            if i == a.len() {
                break;
            }
            intersection_probe();
            if a_value(&a[i]) == needle {
                out.push(needle);
                i += 1;
            }
        }
        return out;
    }

    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        intersection_probe();
        match a_value(&a[i]).cmp(&b_value(&b[j])) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                out.push(a_value(&a[i]));
                i += 1;
                j += 1;
            }
        }
    }
    out
}

#[cfg(not(test))]
#[inline(always)]
fn intersection_probe() {}

#[cfg(test)]
static INTERSECTION_PROBES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
#[inline]
fn intersection_probe() {
    INTERSECTION_PROBES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

        let and_ref: Vec<u32> = from_bools(&(0..len).map(|i| ba[i] && bb[i]).collect::<Vec<_>>());
        let or_ref: Vec<u32> = from_bools(&(0..len).map(|i| ba[i] || bb[i]).collect::<Vec<_>>());
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
    fn cardinalidade_em_cache_sobrevive_a_todas_as_operacoes() {
        let a = SelectionVector::from_indices(10_000, &(0..8_000).step_by(3).collect::<Vec<_>>());
        let b = SelectionVector::from_indices(10_000, &(0..9_000).step_by(5).collect::<Vec<_>>());
        for resultado in [a.clone(), a.and(&b), a.or(&b), a.not()] {
            let materializado = resultado.to_indices().len();
            assert_eq!(resultado.selected(), materializado);
            assert_eq!(resultado.selected(), resultado.selected());
        }
    }

    /// Exercita explicitamente as seis combinações normativas. As variantes
    /// mistas de largura podem surgir de dados/checkpoints produzidos com um
    /// tamanho de morsel anterior, mesmo que o construtor atual normalize-as.
    #[test]
    fn and_especializado_cobre_todas_as_representacoes() {
        fn selection(len: usize, rep: Rep) -> SelectionVector {
            let selected = match &rep {
                Rep::Bitmap(words) => words.iter().map(|x| x.count_ones() as usize).sum(),
                Rep::Index16(v) => v.len(),
                Rep::Index32(v) => v.len(),
            };
            SelectionVector { len, selected, rep }
        }

        let len = 200_000;
        let i16_a = selection(len, Rep::Index16(vec![1, 7, 20, 1000]));
        let i16_b = selection(len, Rep::Index16(vec![0, 7, 1000, 2000]));
        let i32_a = selection(len, Rep::Index32(vec![1, 7, 20, 1000, 100_000]));
        let i32_b = selection(len, Rep::Index32(vec![7, 1000, 90_000, 100_000]));
        let mut bitmap = vec![0u64; words_for(len)];
        for index in [7usize, 20, 90_000, 100_000] {
            bitmap[index / 64] |= 1 << (index % 64);
        }
        let dense = selection(len, Rep::Bitmap(bitmap));

        assert_eq!(i16_a.and(&i16_b).to_indices(), vec![7, 1000]);
        assert_eq!(i32_a.and(&i32_b).to_indices(), vec![7, 1000, 100_000]);
        assert_eq!(i16_a.and(&i32_b).to_indices(), vec![7, 1000]);
        assert_eq!(i32_b.and(&i16_a).to_indices(), vec![7, 1000]);
        assert_eq!(dense.and(&i16_a).to_indices(), vec![7, 20]);
        assert_eq!(i32_b.and(&dense).to_indices(), vec![7, 90_000, 100_000]);
        assert_eq!(dense.and(&dense).to_indices(), vec![7, 20, 90_000, 100_000]);
    }

    #[test]
    fn galloping_nao_varre_a_lista_grande() {
        let grande: Vec<u32> = (0..1_000_000).collect();
        let pequena: Vec<u32> = (0..100).map(|i| i * 10_000).collect();

        INTERSECTION_PROBES.store(0, std::sync::atomic::Ordering::Relaxed);
        let got = intersect_sorted_by(&pequena, &grande, |&x| x, |&x| x);
        let probes = INTERSECTION_PROBES.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(got, pequena);
        assert!(
            probes < 10_000,
            "galloping fez {probes} comparações para {}x{} elementos",
            pequena.len(),
            grande.len()
        );
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
