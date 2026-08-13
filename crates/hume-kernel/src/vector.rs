//! Coluna tipada respaldada por memória alinhada a SIMD (SPEC-0038 §2,
//! SPEC-0041 §1).
//!
//! Um [`Vector`] é uma coluna contígua de um tipo nativo, guardada num
//! [`AlignedBuffer`] (64 B, SIMD-ready) com a sua [`ValidityMask`]. É o
//! `columns[i]` do [`crate::DataChunk`].
//!
//! Escopo honesto: cobre os tipos escalares nativos de largura fixa
//! (`Int32`/`UInt64`/`Float64`) — os que os kernels vetorizados consomem sem
//! indireção. `String` (via dicionário) e `DenseVector` (embeddings) ficam para
//! um módulo seguinte; a variante do enum está reservada mas sem armazenamento
//! aqui.

use crate::validity::ValidityMask;
use crate::{AlignedBuffer, CACHE_LINE};

/// Tipo nativo de um [`Vector`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Int32,
    UInt64,
    Float64,
}

impl DataType {
    /// Largura em bytes de um elemento.
    pub fn width(self) -> usize {
        match self {
            DataType::Int32 => 4,
            DataType::UInt64 => 8,
            DataType::Float64 => 8,
        }
    }
}

/// Coluna tipada de largura fixa.
///
/// ```
/// use hume_kernel::Vector;
/// let v = Vector::from_i32(&[1, -2, 3]);
/// assert_eq!(v.len(), 3);
/// assert_eq!(v.as_i32().unwrap(), &[1, -2, 3]);
/// assert!(v.as_u64().is_none()); // tipo não bate
/// ```
#[derive(Debug)]
pub struct Vector {
    dtype: DataType,
    len: usize,
    buf: AlignedBuffer,
    validity: ValidityMask,
}

impl Vector {
    fn build<T: Copy>(dtype: DataType, vals: &[T], write: impl Fn(&mut [u8], usize, &T)) -> Self {
        let len = vals.len();
        let nbytes = (len * dtype.width()).max(CACHE_LINE);
        let mut buf = AlignedBuffer::new(nbytes);
        {
            let dst = buf.as_mut_slice();
            for (i, v) in vals.iter().enumerate() {
                write(dst, i, v);
            }
        }
        Self { dtype, len, buf, validity: ValidityMask::all_valid(len) }
    }

    /// Constrói uma coluna `Int32`.
    pub fn from_i32(vals: &[i32]) -> Self {
        Self::build(DataType::Int32, vals, |dst, i, v| {
            dst[i * 4..i * 4 + 4].copy_from_slice(&v.to_ne_bytes());
        })
    }

    /// Constrói uma coluna `UInt64`.
    pub fn from_u64(vals: &[u64]) -> Self {
        Self::build(DataType::UInt64, vals, |dst, i, v| {
            dst[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
        })
    }

    /// Constrói uma coluna `Float64`.
    pub fn from_f64(vals: &[f64]) -> Self {
        Self::build(DataType::Float64, vals, |dst, i, v| {
            dst[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
        })
    }

    #[inline]
    pub fn dtype(&self) -> DataType {
        self.dtype
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Máscara de validade (NULLs) da coluna.
    #[inline]
    pub fn validity(&self) -> &ValidityMask {
        &self.validity
    }

    /// Máscara de validade mutável (para marcar NULLs após a construção).
    #[inline]
    pub fn validity_mut(&mut self) -> &mut ValidityMask {
        &mut self.validity
    }

    /// Vista tipada `&[i32]` (ou `None` se o tipo não bater).
    pub fn as_i32(&self) -> Option<&[i32]> {
        if self.dtype != DataType::Int32 {
            return None;
        }
        // SAFETY: buf tem `len` i32 em endianness nativa, alinhado a 64 B (≥ 4),
        // inicializado no construtor.
        Some(unsafe { std::slice::from_raw_parts(self.buf.as_ptr() as *const i32, self.len) })
    }

    /// Vista tipada `&[u64]` (ou `None` se o tipo não bater).
    pub fn as_u64(&self) -> Option<&[u64]> {
        if self.dtype != DataType::UInt64 {
            return None;
        }
        // SAFETY: idem, u64 exige alinhamento 8 ≤ 64.
        Some(unsafe { std::slice::from_raw_parts(self.buf.as_ptr() as *const u64, self.len) })
    }

    /// Vista tipada `&[f64]` (ou `None` se o tipo não bater).
    pub fn as_f64(&self) -> Option<&[f64]> {
        if self.dtype != DataType::Float64 {
            return None;
        }
        // SAFETY: idem, f64 exige alinhamento 8 ≤ 64.
        Some(unsafe { std::slice::from_raw_parts(self.buf.as_ptr() as *const f64, self.len) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i32_roundtrip_and_alignment() {
        let v = Vector::from_i32(&[i32::MIN, -1, 0, 1, i32::MAX]);
        assert_eq!(v.dtype(), DataType::Int32);
        assert_eq!(v.as_i32().unwrap(), &[i32::MIN, -1, 0, 1, i32::MAX]);
        assert_eq!(v.as_i32().unwrap().as_ptr() as usize % 64, 0);
        assert!(v.as_u64().is_none() && v.as_f64().is_none());
    }

    #[test]
    fn u64_roundtrip() {
        let v = Vector::from_u64(&[0, 1, u64::MAX, 12345]);
        assert_eq!(v.as_u64().unwrap(), &[0, 1, u64::MAX, 12345]);
    }

    #[test]
    fn f64_roundtrip() {
        let v = Vector::from_f64(&[0.0, -1.5, 42.25, f64::MAX]);
        let got = v.as_f64().unwrap();
        assert_eq!(got, &[0.0, -1.5, 42.25, f64::MAX]);
    }

    #[test]
    fn empty_vector_ok() {
        let v = Vector::from_i32(&[]);
        assert!(v.is_empty());
        assert_eq!(v.as_i32().unwrap(), &[] as &[i32]);
    }

    #[test]
    fn nulls_tracked_per_column() {
        let mut v = Vector::from_u64(&[10, 20, 30]);
        assert!(!v.validity().has_nulls());
        v.validity_mut().set_null(1);
        assert!(v.validity().has_nulls());
        assert!(!v.validity().is_valid(1));
        // O dado bruto permanece; só a máscara marca o NULL.
        assert_eq!(v.as_u64().unwrap()[1], 20);
    }

    #[test]
    fn width_matches() {
        assert_eq!(DataType::Int32.width(), 4);
        assert_eq!(DataType::UInt64.width(), 8);
        assert_eq!(DataType::Float64.width(), 8);
    }
}
