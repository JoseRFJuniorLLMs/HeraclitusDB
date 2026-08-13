//! Alocação de buffers contíguos alinhados a linha de cache (SPEC-0041 §4,
//! `memory/aligned_alloc.rs`).
//!
//! O motor HUME exige que todo `ColumnVector`/`Vector` aponte para memória
//! alinhada a 64 bytes (`SPEC-000 §1.1`) para que os kernels SIMD façam cargas
//! alinhadas sem *split loads* na fronteira da linha de cache. [`AlignedBuffer`]
//! encapsula essa alocação com um `Drop` que liberta em O(1).

use std::alloc::{self, Layout};
use std::ptr::NonNull;
use std::slice;

use crate::CACHE_LINE;

/// Buffer de bytes contíguo, alinhado a [`CACHE_LINE`] (64 B), zero-inicializado.
///
/// Semântica de propriedade rica ("Owned") do `SPEC-000 §2.2`: alocação
/// exclusiva, livre para mutação in-place. A libertação é O(1) (`dealloc`).
///
/// ```
/// use hume_kernel::AlignedBuffer;
/// let mut b = AlignedBuffer::new(128);
/// assert_eq!(b.len(), 128);
/// assert_eq!(b.as_ptr() as usize % 64, 0); // alinhado a linha de cache
/// b.as_mut_slice()[0] = 0xAB;
/// assert_eq!(b.as_slice()[0], 0xAB);
/// ```
pub struct AlignedBuffer {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
}

impl AlignedBuffer {
    /// Aloca `len` bytes alinhados a 64 B, zero-inicializados.
    ///
    /// # Panics
    /// Se `len == 0` (um buffer vazio não tem endereço útil) ou se o
    /// alocador do sistema falhar.
    pub fn new(len: usize) -> Self {
        assert!(len > 0, "AlignedBuffer::new exige len > 0");
        let layout = Layout::from_size_align(len, CACHE_LINE)
            .expect("layout inválido (overflow de tamanho alinhado)");
        // SAFETY: layout tem size > 0 (assert acima).
        let raw = unsafe { alloc::alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).unwrap_or_else(|| alloc::handle_alloc_error(layout));
        Self { ptr, len, layout }
    }

    /// Número de bytes do buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Sempre `false` — o construtor rejeita `len == 0`. Presente para lint.
    #[inline]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Ponteiro bruto (const) alinhado a 64 B.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Ponteiro bruto (mut) alinhado a 64 B.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Vista imutável dos bytes.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr válido, len bytes inicializados (alloc_zeroed), só leitura.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Vista mutável dos bytes.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr válido, len bytes inicializados, empréstimo &mut exclusivo.
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl std::fmt::Debug for AlignedBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBuffer")
            .field("len", &self.len)
            .field("align", &CACHE_LINE)
            .finish()
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: ptr/layout vieram de alloc_zeroed com este mesmo layout.
        unsafe { alloc::dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

// SAFETY: AlignedBuffer é dono exclusivo da alocação; mover entre threads é
// seguro e o acesso partilhado só expõe &[u8]/&mut [u8] sob as regras normais.
unsafe impl Send for AlignedBuffer {}
unsafe impl Sync for AlignedBuffer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_to_cache_line() {
        for len in [1usize, 7, 63, 64, 65, 1024, 100_000] {
            let b = AlignedBuffer::new(len);
            assert_eq!(b.len(), len);
            assert_eq!(b.as_ptr() as usize % CACHE_LINE, 0, "len={len} não alinhado");
        }
    }

    #[test]
    fn zero_initialized() {
        let b = AlignedBuffer::new(256);
        assert!(b.as_slice().iter().all(|&x| x == 0));
    }

    #[test]
    fn read_write_roundtrip() {
        let mut b = AlignedBuffer::new(64);
        for (i, byte) in b.as_mut_slice().iter_mut().enumerate() {
            *byte = i as u8;
        }
        assert_eq!(b.as_slice()[63], 63);
        assert_eq!(b.as_slice()[0], 0);
    }

    #[test]
    #[should_panic(expected = "len > 0")]
    fn rejects_zero_len() {
        let _ = AlignedBuffer::new(0);
    }
}
