//! SPEC-0050 §139 — varint **canónico** (ULEB128 sem representações duplicadas).
//!
//! A regra é curta e inegociável: *uma quantidade lógica, um único byte stream
//! válido*. ULEB128 puro admite `0x81 0x00` e `0x01` para o mesmo `1`; se o
//! leitor aceitasse ambos, dois ficheiros com bytes diferentes descodificariam
//! para o mesmo registo — e a identidade física deixaria de ser função da
//! identidade lógica. O decoder aqui **rejeita** a forma longa.
//!
//! Rejeições obrigatórias (SPEC-0050 §138):
//!
//! - varint com mais de [`MAX_VARINT_LEN`] bytes;
//! - overflow de `u64` no último grupo;
//! - encoding não canónico (último byte `0x00` num varint multi-byte);
//! - EOF parcial (byte de continuação sem sucessor).

use super::error::{corrupt, V6Result};

/// Um `u64` nunca precisa de mais de 10 grupos de 7 bits.
pub const MAX_VARINT_LEN: usize = 10;

/// Bytes que `v` ocupa na forma canónica. Usado para orçamentar buffers sem
/// codificar duas vezes.
#[inline]
pub const fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Escreve `v` em ULEB128 canónico no fim de `out`.
#[inline]
pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Escreve `v` num buffer fixo, devolvendo quantos bytes usou.
///
/// Existe para o hot-path do packer, que não quer tocar num `Vec`.
#[inline]
pub fn encode_varint_into(buf: &mut [u8; MAX_VARINT_LEN], mut v: u64) -> usize {
    let mut n = 0;
    while v >= 0x80 {
        buf[n] = (v as u8) | 0x80;
        v >>= 7;
        n += 1;
    }
    buf[n] = v as u8;
    n + 1
}

/// Lê um varint canónico de `buf`, devolvendo `(valor, bytes consumidos)`.
///
/// `ctx` entra na mensagem de corrupção para o operador saber *que* decoder
/// falhou (bloco, diretório, registo) sem ter de correr um debugger.
#[inline]
pub fn read_varint(buf: &[u8], ctx: &'static str) -> V6Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().take(MAX_VARINT_LEN).enumerate() {
        let payload = (byte & 0x7f) as u64;
        // Grupo 10 (shift 63) só pode contribuir com 1 bit.
        if shift == 63 && payload > 1 {
            return Err(corrupt(ctx, "varint overflows u64"));
        }
        result |= payload << shift;
        if byte & 0x80 == 0 {
            // Canonicidade: um varint multi-byte cujo último grupo é 0 é a
            // forma longa de um valor mais curto.
            if i > 0 && byte == 0 {
                return Err(corrupt(
                    ctx,
                    "non-canonical varint (redundant trailing group)",
                ));
            }
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    if buf.len() >= MAX_VARINT_LEN {
        Err(corrupt(ctx, "varint longer than 10 bytes"))
    } else {
        Err(corrupt(ctx, "truncated varint (continuation bit at EOF)"))
    }
}

/// [`read_varint`] com o resultado já estreitado a `usize`, verificando o
/// estreitamento em plataformas de 32 bits (SPEC-0050 §137: *integer
/// conversion* é uma das validações obrigatórias).
#[inline]
pub fn read_varint_usize(buf: &[u8], ctx: &'static str) -> V6Result<(usize, usize)> {
    let (v, n) = read_varint(buf, ctx)?;
    let v =
        usize::try_from(v).map_err(|_| corrupt(ctx, "varint exceeds usize on this platform"))?;
    Ok((v, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_fronteiras() {
        let casos = [
            0u64,
            1,
            0x7f,
            0x80,
            0x3fff,
            0x4000,
            u32::MAX as u64,
            u64::MAX - 1,
            u64::MAX,
        ];
        for v in casos {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            assert_eq!(out.len(), varint_len(v), "varint_len diverge para {v}");
            let (got, n) = read_varint(&out, "t").unwrap();
            assert_eq!(got, v);
            assert_eq!(n, out.len());
        }
    }

    #[test]
    fn forma_longa_e_rejeitada() {
        // `1` codificado em dois grupos: 0x81 0x00.
        assert!(read_varint(&[0x81, 0x00], "t").is_err());
        // `0` codificado em dois grupos.
        assert!(read_varint(&[0x80, 0x00], "t").is_err());
        // Forma canónica dos mesmos valores passa.
        assert_eq!(read_varint(&[0x01], "t").unwrap().0, 1);
        assert_eq!(read_varint(&[0x00], "t").unwrap().0, 0);
    }

    #[test]
    fn overflow_e_rejeitado() {
        // 10 grupos com o último a contribuir 2 bits.
        let bomba = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert!(read_varint(&bomba, "t").is_err());
        // 11 grupos.
        let longo = [0x80u8; 11];
        assert!(read_varint(&longo, "t").is_err());
    }

    #[test]
    fn eof_parcial_e_rejeitado() {
        assert!(read_varint(&[0x80], "t").is_err());
        assert!(read_varint(&[], "t").is_err());
    }

    #[test]
    fn encode_into_bate_com_vec() {
        for v in [0u64, 127, 128, 300, u64::MAX] {
            let mut a = Vec::new();
            put_varint(&mut a, v);
            let mut b = [0u8; MAX_VARINT_LEN];
            let n = encode_varint_into(&mut b, v);
            assert_eq!(&b[..n], &a[..]);
        }
    }
}
