//! O que um blob de coluna DIZ que tem nao pode virar capacidade antes de os
//! bytes que o sustentam existirem -- e descodificar uma coluna nao pode
//! materializa-la duas vezes ao mesmo tempo.
//!
//! `column::decode` ja recusa contagens absurdas, mas recusar DEPOIS de pedir a
//! memoria nao chega: a reserva e o dano. Um assert de "devolve None" passaria
//! com e sem a correccao, por isso este ficheiro mede o que realmente muda --
//! quanto se pediu ao alocador -- com um `GlobalAlloc` contador, que so pode
//! viver num binario de teste proprio.
//!
//! Ha DUAS grandezas medidas, e sao diferentes de proposito:
//!
//! - `PICO` -- a MAIOR reserva individual. Mata o defeito A53 (9 bytes de blob
//!   a pedir 4 GiB de uma vez).
//! - `PICO_VIVO` -- os bytes VIVOS (alocado menos libertado). Mata o defeito
//!   R88 (dois buffers do tamanho da coluna a coexistir): ai a maior reserva
//!   INDIVIDUAL nao muda -- antes e depois ha uma alocacao de `n*8` --, so muda
//!   quantas estao vivas ao mesmo tempo. Um assert sobre `PICO` passaria com e
//!   sem a correccao, ou seja, nao mataria a mutacao.
//!
//! Auditoria 2026-09-05, A53 e (vaga 2) R88.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use hume_kernel::compression::column::{self, Codec};

thread_local! {
    /// Maior reserva pedida nesta thread desde o ultimo reset. Thread-local e
    /// nao global: os testes correm em paralelo e um contador partilhado
    /// mediria as alocacoes dos vizinhos.
    static PICO: Cell<usize> = const { Cell::new(0) };
    /// Bytes vivos (soma dos `alloc` menos os `dealloc`) enquanto `ON`.
    /// Assinado porque um `dealloc` de memoria nascida antes do `ON` desce
    /// abaixo de zero -- so interessa o maximo, e esse nunca e afectado.
    static VIVO: Cell<isize> = const { Cell::new(0) };
    /// Maximo de `VIVO` observado. E este que distingue "uma copia da coluna"
    /// de "duas copias da coluna".
    static PICO_VIVO: Cell<isize> = const { Cell::new(0) };
    /// Portao: so contar bytes vivos durante a chamada medida. Sem isto entra
    /// o ruido do harness (buffers de saida, backtraces, panic hooks).
    static ON: Cell<bool> = const { Cell::new(false) };
}

struct Contador;

// SAFETY: delega tudo no alocador do sistema; so observa os tamanhos pedidos.
// Nota: o `realloc` por omissao do trait delega em `alloc` + `dealloc`, por
// isso o crescimento de um `Vec` tambem entra na conta.
unsafe impl GlobalAlloc for Contador {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // `try_with` e nao `with`: durante a destruicao das TLS o acesso falha,
        // e um panico dentro do alocador seria um abort.
        let _ = PICO.try_with(|p| {
            if l.size() > p.get() {
                p.set(l.size());
            }
        });
        let _ = ON.try_with(|on| {
            if on.get() {
                let _ = VIVO.try_with(|v| {
                    let novo = v.get() + l.size() as isize;
                    v.set(novo);
                    let _ = PICO_VIVO.try_with(|p| {
                        if novo > p.get() {
                            p.set(novo);
                        }
                    });
                });
            }
        });
        System.alloc(l)
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        let _ = ON.try_with(|on| {
            if on.get() {
                let _ = VIVO.try_with(|v| v.set(v.get() - l.size() as isize));
            }
        });
        System.dealloc(p, l);
    }
}

#[global_allocator]
static ALOCADOR: Contador = Contador;

/// Corre `f` com a contagem de bytes vivos ligada; devolve `(saida, pico_vivo)`.
fn medindo_vivos<T>(f: impl FnOnce() -> T) -> (T, usize) {
    VIVO.with(|v| v.set(0));
    PICO_VIVO.with(|p| p.set(0));
    ON.with(|on| on.set(true));
    let saida = f();
    ON.with(|on| on.set(false));
    let pico = PICO_VIVO.with(|p| p.get()).max(0) as usize;
    (saida, pico)
}

/// Nove bytes de disco nao podem pedir gigabytes ao alocador.
///
/// A contagem de RUNS do ramo `Rle` so era limitada por `MAX_VALORES`, um tecto
/// dimensionado para valores descodificados de 8 B; um elemento da lista de
/// runs custa 16 B (`(u64, u32)` alinhado), logo o mesmo tecto autorizava 4 GiB
/// de reserva antes de a funcao olhar para um unico byte de run. Onde ha
/// limite duro de memoria (cgroup, job object, overcommit desligado) isso e um
/// abort do alocador a partir de um blob minusculo.
#[test]
fn rle_nao_reserva_pela_contagem_de_runs_do_disco() {
    let mut hostil = vec![Codec::Rle as u8];
    hostil.extend_from_slice(&(1u64 << 28).to_le_bytes()); // n = MAX_VALORES runs
    let bytes = hostil.len();

    PICO.with(|p| p.set(0));
    let saida = column::decode(&hostil);
    let pico = PICO.with(|p| p.get());

    assert!(saida.is_none(), "blob sem runs nenhuns tem de recusar");
    assert!(
        pico < (1 << 20),
        "reservou {pico} bytes a partir de {bytes} bytes de blob"
    );
}

/// A guarda acima nao pode passar a recusar colunas legitimas: uma coluna que
/// escolhe mesmo o RLE tem de continuar a descodificar exacta.
#[test]
fn rle_legitimo_continua_a_descodificar() {
    let data = vec![99u64; 5000];
    let blob = column::encode(&data);
    assert_eq!(column::codec_of(&blob), Some(Codec::Rle));
    assert_eq!(column::decode(&blob).unwrap(), data);
}

/// O tecto `MAX_VALORES` promete "268M valores ~ 2 GB descomprimidos". O ramo
/// `DeltaBitpack` gastava o DOBRO disso: `vals` (as diferencas desempacotadas)
/// e `deltas` (a coluna inteira em i64) viviam ao mesmo tempo, e depois
/// `deltas` vivia ao mesmo tempo que o `Vec` novo do `delta::decode`. Medido a
/// 2.02x o tamanho da coluna -- ~4.3 GiB no tecto do proprio ficheiro. Com
/// limite duro de memoria isso e um abort do alocador (irrecuperavel em Rust)
/// exactamente no caminho `CompressedSnapshot::expand`, onde estava desenhada
/// a degradacao para rebuild por replay.
///
/// O tecto de 1.25x deste teste NAO e um tecto por racio blob/saida -- esse
/// seria errado e partiria colunas legitimas (um posting list ordenado com
/// deltas = 1 comprime mesmo 64x, e e o que este teste alimenta). E um tecto
/// sobre a amplificacao da propria COLUNA: uma copia viva, nao duas.
///
/// Auditoria 2026-09-05, vaga 2, R88.
#[test]
fn delta_bitpack_nao_materializa_a_coluna_duas_vezes() {
    let n = 1usize << 20;
    let data: Vec<u64> = (0..n as u64).collect(); // deltas = 1 -> bits = 1
    let blob = column::encode(&data);
    assert_eq!(
        column::codec_of(&blob),
        Some(Codec::DeltaBitpack),
        "o teste tem de exercitar o ramo delta+bitpack"
    );

    let (saida, pico_vivo) = medindo_vivos(|| column::decode(&blob));
    let out = saida.expect("coluna legitima tem de descodificar");

    // Sem isto, uma "optimizacao" que estrague os valores passaria no tecto.
    assert_eq!(out, data, "roundtrip tem de continuar exacto");
    assert!(
        pico_vivo < n * 8 + n * 2,
        "pico vivo {pico_vivo} B para uma coluna de {} B (blob {} B)",
        n * 8,
        blob.len()
    );
}

/// Irmao do anterior para o ramo `ForBitpack`, que tinha o mesmo defeito
/// (`offsets` + o `Vec` novo do `frame_of_reference::decode`) e seria esquecido
/// por uma correccao so no delta.
///
/// Auditoria 2026-09-05, vaga 2, R88.
#[test]
fn for_bitpack_nao_materializa_a_coluna_duas_vezes() {
    let n = 1usize << 20;
    // Intervalo estreito e SEM ordem: o delta e recusado (diferencas negativas)
    // e o RLE nao ganha (runs de 1 valor), logo sobra o FOR.
    let data: Vec<u64> = (0..n as u64).map(|i| 1_000_000 + (i % 7)).collect();
    let blob = column::encode(&data);
    assert_eq!(
        column::codec_of(&blob),
        Some(Codec::ForBitpack),
        "o teste tem de exercitar o ramo FOR+bitpack"
    );

    let (saida, pico_vivo) = medindo_vivos(|| column::decode(&blob));
    let out = saida.expect("coluna legitima tem de descodificar");

    assert_eq!(out, data, "roundtrip tem de continuar exacto");
    assert!(
        pico_vivo < n * 8 + n * 2,
        "pico vivo {pico_vivo} B para uma coluna de {} B (blob {} B)",
        n * 8,
        blob.len()
    );
}
