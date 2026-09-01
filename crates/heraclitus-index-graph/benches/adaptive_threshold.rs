use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use heraclitus_index_graph::adaptive::{learn_threshold, LabeledFlag};

fn samples(count: usize) -> Vec<LabeledFlag> {
    (0..count)
        .map(|index| LabeledFlag {
            // Permutation-like deterministic distribution: mostly distinct,
            // with enough repeated low bits to exercise threshold groups.
            score: ((index.wrapping_mul(2_654_435_761) % count.max(1)) as f32) * 0.001,
            confirmed: index.is_multiple_of(3),
        })
        .collect()
}

fn adaptive_threshold(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_threshold_n_log_n");
    for count in [1_000usize, 10_000, 100_000] {
        let input = samples(count);
        group.bench_with_input(BenchmarkId::from_parameter(count), &input, |b, samples| {
            b.iter(|| learn_threshold(black_box(samples), black_box(1.5)));
        });
    }
    group.finish();
}

criterion_group!(benches, adaptive_threshold);
criterion_main!(benches);
