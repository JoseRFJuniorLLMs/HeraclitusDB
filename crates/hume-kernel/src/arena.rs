//! `ScratchAllocator` — arena bump de scratch por thread (SPEC-000 §2.1).
//!
//! Toda memória temporária de um estágio do pipeline (máscaras booleanas,
//! vetores intermédios, tabelas de hash locais) é adquirida deste alocador do
//! tipo *bump*: um incremento de ponteiro O(1). No fim do morsel/estágio, a
//! memória desaparece com um único [`ScratchAllocator::reset`] — custo O(1),
//! sem percorrer destrutores nem devolver blocos ao alocador global.
//!
//! Auditoria: classificado `VIÁVEL_EXTRAIR` (self-contained, sem quebrar
//! invariantes). É a peça de gestão de memória do `SPEC-000` que se sustenta
//! isolada, ao contrário do motor JIT que a rodeia.

use std::cell::Cell;

use crate::AlignedBuffer;

/// Arena bump de capacidade fixa, alinhada a linha de cache.
///
/// As alocações usam `&self` (mutabilidade interior via [`Cell`]) para que
/// várias regiões vivas coexistam — é o padrão clássico de bump arena. O
/// [`ScratchAllocator::reset`] exige `&mut self`, pelo que o borrow-checker
/// impede reciclar a arena enquanto qualquer região alocada ainda estiver viva.
///
/// ```
/// use hume_kernel::ScratchAllocator;
/// let mut a = ScratchAllocator::new(4096);
/// {
///     let buf = a.alloc_bytes(100, 16).unwrap();
///     assert_eq!(buf.as_ptr() as usize % 16, 0);
///     buf[0] = 7;
/// }
/// assert!(a.used() >= 100);
/// a.reset();
/// assert_eq!(a.used(), 0);
/// ```
pub struct ScratchAllocator {
    buf: AlignedBuffer,
    offset: Cell<usize>,
}

impl ScratchAllocator {
    /// Nova arena com `capacity` bytes.
    pub fn new(capacity: usize) -> Self {
        Self { buf: AlignedBuffer::new(capacity), offset: Cell::new(0) }
    }

    /// Capacidade total em bytes.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Bytes já entregues (marca-d'água do bump).
    #[inline]
    pub fn used(&self) -> usize {
        self.offset.get()
    }

    /// Aloca `n` bytes com o alinhamento pedido. Devolve `None` se a arena não
    /// tiver espaço (no motor real, o operador faria *spill* para NVMe —
    /// `SPEC-0039 §6`; aqui a política é deixar o chamador decidir).
    ///
    /// # Panics
    /// Se `align` não for potência de dois.
    // `&self -> &mut [u8]` é o contrato deliberado da bump arena (cf. `bumpalo`):
    // cada região devolvida é disjunta, o borrow atado a `&self` impede `reset`.
    #[allow(clippy::mut_from_ref)]
    pub fn alloc_bytes(&self, n: usize, align: usize) -> Option<&mut [u8]> {
        assert!(align.is_power_of_two(), "alinhamento tem de ser potência de dois");
        let cur = self.offset.get();
        let start = (cur + align - 1) & !(align - 1);
        let end = start.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        self.offset.set(end);
        let base = self.buf.as_ptr() as *mut u8;
        // SAFETY: [start,end) é disjunto de toda alocação anterior (offset é
        // monotónico) e cabe no buffer possuído. O tempo de vida do slice está
        // atado a `&self`, logo `reset(&mut self)` não pode correr enquanto
        // estiver vivo. Bytes vêm de alloc_zeroed (inicializados).
        Some(unsafe { std::slice::from_raw_parts_mut(base.add(start), n) })
    }

    /// Aloca `count` `u64` contíguos e alinhados (scratch típico de hash/agg).
    #[allow(clippy::mut_from_ref)] // mesmo contrato de bump arena de `alloc_bytes`
    pub fn alloc_u64(&self, count: usize) -> Option<&mut [u64]> {
        let bytes = count.checked_mul(8)?;
        let s = self.alloc_bytes(bytes, 8)?;
        let ptr = s.as_mut_ptr() as *mut u64;
        // SAFETY: alinhado a 8, `count` u64, bytes zero-inicializados = u64 válidos.
        Some(unsafe { std::slice::from_raw_parts_mut(ptr, count) })
    }

    /// Recicla a arena inteira em O(1) (fim do morsel/estágio).
    pub fn reset(&mut self) {
        self.offset.set(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_is_disjoint_and_aligned() {
        let a = ScratchAllocator::new(4096);
        let x = a.alloc_bytes(10, 8).unwrap();
        let x_ptr = x.as_ptr() as usize;
        x[0] = 1;
        let y = a.alloc_bytes(10, 8).unwrap();
        let y_ptr = y.as_ptr() as usize;
        y[0] = 2;
        assert_eq!(x_ptr % 8, 0);
        assert_eq!(y_ptr % 8, 0);
        assert!(y_ptr >= x_ptr + 10, "regiões têm de ser disjuntas");
        // Ambas coexistem vivas com valores independentes.
        assert_eq!(x[0], 1);
        assert_eq!(y[0], 2);
    }

    #[test]
    fn respects_alignment_request() {
        let a = ScratchAllocator::new(4096);
        let _ = a.alloc_bytes(1, 1).unwrap(); // desalinha o offset
        let b = a.alloc_bytes(8, 64).unwrap();
        assert_eq!(b.as_ptr() as usize % 64, 0);
    }

    #[test]
    fn out_of_space_returns_none() {
        let a = ScratchAllocator::new(64);
        assert!(a.alloc_bytes(32, 1).is_some());
        assert!(a.alloc_bytes(64, 1).is_none()); // não cabe
        assert!(a.alloc_bytes(16, 1).is_some()); // mas ainda há para menos
    }

    #[test]
    fn reset_reclaims_o1() {
        let mut a = ScratchAllocator::new(1024);
        {
            let _ = a.alloc_bytes(500, 1).unwrap();
        }
        assert!(a.used() >= 500);
        a.reset();
        assert_eq!(a.used(), 0);
        // Após reset, realoca do início.
        let b = a.alloc_bytes(500, 1).unwrap();
        assert_eq!(b.len(), 500);
    }

    #[test]
    fn alloc_u64_typed() {
        let a = ScratchAllocator::new(4096);
        let s = a.alloc_u64(16).unwrap();
        assert_eq!(s.len(), 16);
        assert_eq!(s.as_ptr() as usize % 8, 0);
        assert!(s.iter().all(|&x| x == 0)); // zero-inicializado
        s[3] = 42;
        assert_eq!(s[3], 42);
    }

    #[test]
    #[should_panic(expected = "potência de dois")]
    fn rejects_non_pow2_align() {
        ScratchAllocator::new(64).alloc_bytes(8, 3);
    }
}
