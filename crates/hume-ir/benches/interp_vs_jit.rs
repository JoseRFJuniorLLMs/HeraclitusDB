//! Benchmark: interpretador (cold tier) vs. JIT Cranelift (hot tier) do HUME-IR,
//! sobre a mesma expressão `(col0 > 900) AND (col1 == 5)`.
//!
//! Quantifica a "taxa de interpretação" — o overhead que o JIT remove — que é
//! a justificação empírica para existir um tier compilado (SPEC-0038 §3).
//!
//! Correr: `cargo bench -p hume-ir --features jit`

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use hume_ir::jit::JitFilter;
use hume_ir::{interpret_mask, Builder, ColumnData, Const, Ty};

fn bench(c: &mut Criterion) {
    const N: usize = 200_000;
    let col0: Vec<i64> = (0..N).map(|i| (i * 7 % 1100) as i64).collect();
    let col1: Vec<i64> = (0..N).map(|i| (i % 8) as i64).collect();
    let cols = [ColumnData::I64(&col0), ColumnData::I64(&col1)];

    let mut b = Builder::new();
    let c0 = b.column(0, Ty::I64);
    let k900 = b.constant(Const::I64(900));
    let gt = b.cmp_gt(c0, k900);
    let c1 = b.column(1, Ty::I64);
    let k5 = b.constant(Const::I64(5));
    let eq = b.cmp_eq(c1, k5);
    let ret = b.and(gt, eq);
    let f = b.finish(2, ret);

    let jit = JitFilter::compile(&f).unwrap();
    // Sanidade: os dois tiers coincidem.
    assert_eq!(jit.run(&cols, N), interpret_mask(&f, &cols, N).unwrap());

    let mut g = c.benchmark_group("hume_ir_filter_200k");
    g.sample_size(30);
    g.bench_function("interpret_cold", |bn| {
        bn.iter(|| black_box(interpret_mask(&f, &cols, N).unwrap().len()))
    });
    g.bench_function("jit_hot", |bn| bn.iter(|| black_box(jit.run(&cols, N).len())));
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
