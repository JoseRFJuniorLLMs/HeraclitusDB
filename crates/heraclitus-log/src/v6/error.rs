//! Erros e limites do HRKL v6.
//!
//! SPEC-0050 §137/§140/§141: nenhum length lido de disco pode chegar a um
//! `Vec::with_capacity` sem passar por um limite configurado. Os tectos vivem
//! aqui, num sítio só, para não haver duas noções de "bloco grande demais".

use heraclitus_core::HeraclitusError;

pub type V6Result<T> = Result<T, HeraclitusError>;

/// Constrói o erro de corrupção com o contexto do decoder que falhou.
#[inline]
pub fn corrupt(context: &'static str, detail: impl Into<String>) -> HeraclitusError {
    HeraclitusError::Corruption {
        context: context.into(),
        detail: detail.into(),
    }
}

/// Tecto absoluto para `uncompressed_len` de um bloco (SPEC-0050 §140,
/// *compression bomb protection*). O default de packing é 256 KiB e o máximo
/// configurável é 1 MiB; este limite é o do **leitor** e é deliberadamente mais
/// folgado, para tolerar gerações antigas — mas continua finito.
pub const HARD_MAX_BLOCK_BYTES: usize = 64 * 1024 * 1024;

/// Tecto absoluto para um registo isolado (`LARGE_RECORD_BLOCK`).
pub const HARD_MAX_RECORD_BYTES: usize = 512 * 1024 * 1024;

/// Tecto para o número de entradas do block directory de um segmento.
/// 2^24 blocos de 64 KiB são 1 TiB — muito acima de qualquer segmento real.
pub const HARD_MAX_BLOCKS: u32 = 1 << 24;

/// Verifica que `len` cabe em `remaining` bytes de ficheiro **e** abaixo do
/// tecto — as duas metades de §140. Devolve `len` para poder ser encadeado.
#[inline]
pub fn checked_len(
    len: usize,
    remaining: usize,
    hard_max: usize,
    ctx: &'static str,
) -> V6Result<usize> {
    if len > hard_max {
        return Err(corrupt(
            ctx,
            format!("declared length {len} exceeds hard maximum {hard_max}"),
        ));
    }
    if len > remaining {
        return Err(corrupt(
            ctx,
            format!("declared length {len} exceeds {remaining} remaining bytes"),
        ));
    }
    Ok(len)
}

/// Fatia `buf[at..at+len]` com verificação de limites — a alternativa segura ao
/// indexing directo em cima de comprimentos vindos do disco.
#[inline]
pub fn slice_at<'a>(buf: &'a [u8], at: usize, len: usize, ctx: &'static str) -> V6Result<&'a [u8]> {
    buf.get(
        at..at
            .checked_add(len)
            .ok_or_else(|| corrupt(ctx, "offset+len overflows usize"))?,
    )
    .ok_or_else(|| {
        corrupt(
            ctx,
            format!("slice [{at}..+{len}] out of bounds ({} bytes)", buf.len()),
        )
    })
}
