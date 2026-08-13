//! Benchmark: filtro **fundido** (materialização tardia via `SelectionVector`)
//! vs. **eager** (dois `filter_record_batch` em sequência), a variar a
//! seletividade do primeiro predicado.
//!
//! Fecha o contrato de benchmark do PLANO-SPECS §6: transforma a opinião
//! "materialização tardia é ganho marginal" em números reais. Mede o algoritmo
//! puro (serial, `logical_cpus = 1`) — sem ruído de threads.
//!
//! Correr: `cargo bench -p heraclitus-analytics`

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use heraclitus_analytics::vectorized::{
    episodes_to_batches_sized, CmpOp, Literal, Predicate, VecExecutor,
};
use heraclitus_core::{Episode, EventKind};

fn dataset(n: usize) -> Vec<(u64, Episode)> {
    (0..n)
        .map(|i| {
            let mut e = Episode::new(
                if i % 2 == 0 { "alice" } else { "bob" },
                EventKind::Observation,
                Vec::new(),
            );
            e.ts_hlc = i as u64;
            (i as u64, e)
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    const N: usize = 200_000;
    let events = dataset(N);
    // Tamanho fixo de 8192 → vários batches, mas medimos o caminho serial.
    let batches = episodes_to_batches_sized(&events, 8192).unwrap();

    let mut group = c.benchmark_group("filter_chain_2preds");
    group.sample_size(20);

    // Seletividade do 1.º filtro (lsn < thr). O 2.º (agent==alice) fica em ~50%.
    for &sel in &[0.9f64, 0.5, 0.1, 0.01] {
        let thr = (sel * N as f64) as u64;
        let preds = vec![
            Predicate { column: 0, op: CmpOp::Lt, value: Literal::U64(thr) }, // p0: lsn < thr
            Predicate { column: 1, op: CmpOp::Eq, value: Literal::Str("alice".into()) }, // p1
        ];
        let mut exec = VecExecutor::new(batches.clone(), preds);
        exec.capabilities.logical_cpus = 1; // serial: mede o algoritmo, não threads

        // Sanidade: os dois caminhos têm de dar o mesmo nº de sobreviventes.
        let mid = exec.run_filter(&batches, 0).unwrap();
        let eager_rows: usize =
            exec.run_filter(&mid, 1).unwrap().iter().map(|b| b.num_rows()).sum();
        let fused_rows: usize = exec
            .run_fused_filters(&batches, &[0, 1])
            .unwrap()
            .iter()
            .map(|b| b.num_rows())
            .sum();
        assert_eq!(eager_rows, fused_rows, "eager e fused têm de coincidir (sel={sel})");

        group.bench_with_input(BenchmarkId::new("eager_2x_materialize", sel), &sel, |b, _| {
            b.iter(|| {
                let mid = exec.run_filter(black_box(&batches), 0).unwrap();
                let out = exec.run_filter(&mid, 1).unwrap();
                black_box(out.len())
            })
        });
        group.bench_with_input(BenchmarkId::new("fused_late_materialize", sel), &sel, |b, _| {
            b.iter(|| {
                let out = exec.run_fused_filters(black_box(&batches), &[0, 1]).unwrap();
                black_box(out.len())
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
