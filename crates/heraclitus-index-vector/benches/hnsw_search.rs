//! Baseline HNSW search throughput (#6). Serve para medir o ganho do #8
//! (arena/locality) e #9 (SIMD) sobre a busca aproximada.

use criterion::{criterion_group, criterion_main, Criterion};
use heraclitus_core::{EventId, ProductPoint};
use heraclitus_index_vector::VectorIndex;
use heraclitus_manifold::{project_to_ball, project_to_sphere, ProductMetric};

// Ponto pseudo-aleatório determinístico no product-manifold (a=32, b=8, c=8).
fn mk_point(seed: u64) -> ProductPoint {
    let f = |i: usize, k: u64| {
        (((seed.wrapping_mul(k).wrapping_add(i as u64) % 1000) as f32) / 1000.0 - 0.5) * 0.8
    };
    let mut hyp: Vec<f32> = (0..32).map(|i| f(i, 31)).collect();
    let mut sph: Vec<f32> = (0..8).map(|i| f(i, 37)).collect();
    let euc: Vec<f32> = (0..8).map(|i| f(i, 41)).collect();
    project_to_ball(&mut hyp);
    project_to_sphere(&mut sph);
    ProductPoint { hyp, sph, euc }
}

fn build_index(n: usize) -> VectorIndex {
    let mut idx = VectorIndex::new(ProductMetric::default());
    for i in 0..n {
        idx.insert(EventId::new(), i as u64, mk_point(i as u64 + 1));
    }
    idx
}

fn bench_search(c: &mut Criterion) {
    let n = 5000;
    let idx = build_index(n);
    let queries: Vec<ProductPoint> = (0..64).map(|q| mk_point(1_000_000 + q)).collect();

    c.bench_function("hnsw_search_k10_n5000_d48", |b| {
        let mut qi = 0usize;
        b.iter(|| {
            let q = &queries[qi % queries.len()];
            qi += 1;
            std::hint::black_box(idx.search(q, 10, 64, None))
        })
    });
}

criterion_group!(benches, bench_search);
criterion_main!(benches);
