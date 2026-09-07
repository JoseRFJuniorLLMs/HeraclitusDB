//! O que um blob de coluna DIZ que tem nao pode virar capacidade antes de os
//! bytes que o sustentam existirem.
//!
//! `column::decode` ja recusa contagens absurdas, mas recusar DEPOIS de pedir a
//! memoria nao chega: a reserva e o dano. Um assert de "devolve None" passaria
//! com e sem a correccao, por isso este ficheiro mede o que realmente muda --
//! o maior pedido feito ao alocador -- com um `GlobalAlloc` contador, que so
//! pode viver num binario de teste proprio.
//!
//! Auditoria 2026-09-05, A53.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use hume_kernel::compression::column::{self, Codec};

thread_local! {
    /// Maior reserva pedida nesta thread desde o ultimo reset. Thread-local e
    /// nao global: os testes correm em paralelo e um contador partilhado
    /// mediria as alocacoes dos vizinhos.
    static PICO: Cell<usize> = const { Cell::new(0) };
}

struct Contador;

// SAFETY: delega tudo no alocador do sistema; so observa o tamanho pedido.
unsafe impl GlobalAlloc for Contador {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // `try_with` e nao `with`: durante a destruicao das TLS o acesso falha,
        // e um panico dentro do alocador seria um abort.
        let _ = PICO.try_with(|p| {
            if l.size() > p.get() {
                p.set(l.size());
            }
        });
        System.alloc(l)
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
    }
}

#[global_allocator]
static ALOCADOR: Contador = Contador;

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
