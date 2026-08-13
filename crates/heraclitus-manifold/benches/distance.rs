//! M1 criterion baseline: product-manifold distance throughput.

use criterion::{criterion_group, criterion_main, Criterion};
use heraclitus_core::ProductPoint;
use heraclitus_manifold::{project_to_ball, project_to_sphere, ProductMetric};

fn mk_point(seed: u64, a: usize, b: usize, c: usize) -> ProductPoint {
    let f = |i: usize, k: u64| {
        (((seed.wrapping_mul(k).wrapping_add(i as u64) % 1000) as f32) / 1000.0 - 0.5) * 0.8
    };
    let mut hyp: Vec<f32> = (0..a).map(|i| f(i, 31)).collect();
    let mut sph: Vec<f32> = (0..b).map(|i| f(i, 37)).collect();
    let euc: Vec<f32> = (0..c).map(|i| f(i, 41)).collect();
    project_to_ball(&mut hyp);
    project_to_sphere(&mut sph);
    ProductPoint { hyp, sph, euc }
}

fn bench_distance(c: &mut Criterion) {
    let metric = ProductMetric::default();
    let p = mk_point(7, 32, 8, 8);
    let q = mk_point(13, 32, 8, 8);
    c.bench_function("product_dist_48d", |b| {
        b.iter(|| std::hint::black_box(metric.dist(&p, &q)))
    });

    let p128 = mk_point(7, 96, 16, 16);
    let q128 = mk_point(13, 96, 16, 16);
    c.bench_function("product_dist_128d", |b| {
        b.iter(|| std::hint::black_box(metric.dist(&p128, &q128)))
    });
}

criterion_group!(benches, bench_distance);
criterion_main!(benches);
