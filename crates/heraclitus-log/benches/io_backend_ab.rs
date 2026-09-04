//! SPEC-0073 §10/§11 — o benchmark A/B que decide se o `io_uring` pode ser
//! default.
//!
//! A §11 fixa o critério e a §10 fixa a matriz:
//!
//! ```text
//! §11:  throughput >= baseline × 1.10   OU   p99 <= baseline × 0.85
//!       sem regressão de durabilidade, recovery, RSS, CPU, determinismo
//!
//! §10:  queue depth  1, 4, 16, 32, 64
//!       payload      256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB
//!       durabilidade no-sync, group-commit, sync-per-batch, strict
//! ```
//!
//! Este benchmark mede o eixo **payload × durabilidade** contra os dois
//! backends. Não mede profundidade de fila nem concorrência, e a razão é
//! honesta: o backend actual submete uma operação de cada vez e espera pela
//! completion — como a §9 obriga — portanto a profundidade de fila não tem hoje
//! nenhum efeito a medir. Fabricar esse eixo agora produziria cinco colunas com
//! o mesmo número, o que é pior do que não as ter: pareceria uma matriz
//! completa.
//!
//! **Este benchmark existe para poder dizer que não.** Se o resultado for
//! "jemalloc/uring não ganha", isso é um resultado, e é o que o `mmap.rs` deste
//! repositório já registou uma vez: medido, perdeu, ficou desligado.
//!
//! Correr:
//! ```text
//! cargo bench -p heraclitus-log --features linux-io-uring --bench io_backend_ab
//! ```

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use heraclitus_log::io_backend::{LogIoBackend, PortableFileIo};
use std::fs::OpenOptions;
use std::path::Path;

/// Os payloads da §10.
const PAYLOADS: [(&str, usize); 5] = [
    ("256B", 256),
    ("1KiB", 1024),
    ("4KiB", 4096),
    ("16KiB", 16 * 1024),
    ("64KiB", 64 * 1024),
];

/// As políticas de durabilidade da §10, como número de escritas por barreira.
///
/// `strict` é uma barreira por escrita; `group-commit` agrupa; `no-sync` não
/// tem barreira nenhuma. `sync-per-batch` é o meio termo com um lote maior.
const DURABILIDADES: [(&str, usize); 4] = [
    ("no-sync", 0),
    ("group-commit", 16),
    ("sync-per-batch", 64),
    ("strict", 1),
];

fn ficheiro_novo(dir: &Path, nome: &str) -> std::fs::File {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(dir.join(nome))
        .unwrap()
}

/// Escreve `escritas` payloads, sincronizando a cada `sync_a_cada` (0 = nunca).
fn correr<B: LogIoBackend>(backend: &mut B, payload: &[u8], escritas: usize, sync_a_cada: usize) {
    for i in 0..escritas {
        backend.append_batch(payload).unwrap();
        if sync_a_cada > 0 && (i + 1) % sync_a_cada == 0 {
            backend.sync().unwrap();
        }
    }
    // Uma barreira final: sem ela, o `no-sync` não estaria a medir um caminho
    // que alguém possa usar, estaria a medir escrita sem durabilidade nenhuma.
    backend.sync().unwrap();
}

fn bench_backends(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    const ESCRITAS: usize = 256;

    for (nome_payload, tamanho) in PAYLOADS {
        let payload = vec![0xA5u8; tamanho];
        for (nome_dur, sync_a_cada) in DURABILIDADES {
            let mut grupo = c.benchmark_group(format!("io_backend/{nome_dur}"));
            grupo.throughput(Throughput::Bytes((tamanho * ESCRITAS) as u64));

            grupo.bench_with_input(
                BenchmarkId::new("portable", nome_payload),
                &payload,
                |b, p| {
                    b.iter(|| {
                        let f = ficheiro_novo(dir.path(), "portable.bin");
                        let mut backend = PortableFileIo::new(f);
                        correr(&mut backend, p, ESCRITAS, sync_a_cada);
                    })
                },
            );

            #[cfg(all(target_os = "linux", feature = "linux-io-uring"))]
            grupo.bench_with_input(BenchmarkId::new("uring", nome_payload), &payload, |b, p| {
                b.iter(|| {
                    let f = ficheiro_novo(dir.path(), "uring.bin");
                    let mut backend =
                        heraclitus_log::io_uring_backend::LinuxUringIo::novo(f, 0).unwrap();
                    correr(&mut backend, p, ESCRITAS, sync_a_cada);
                })
            });

            grupo.finish();
        }
    }
}

criterion_group!(benches, bench_backends);
criterion_main!(benches);
