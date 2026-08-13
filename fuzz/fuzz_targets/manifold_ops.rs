//! Fuzz manifold operations: arbitrary float inputs must never panic and
//! must respect the ball invariant after projection.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let floats: Vec<f32> = data
        .chunks_exact(4)
        .take(32)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .filter(|f| f.is_finite())
        .collect();
    if floats.len() < 4 {
        return;
    }
    let mid = floats.len() / 2;
    let (mut a, mut b) = (floats[..mid].to_vec(), floats[mid..].to_vec());
    b.truncate(a.len());
    a.truncate(b.len());
    heraclitus_manifold::project_to_ball(&mut a);
    heraclitus_manifold::project_to_ball(&mut b);
    let _ = heraclitus_manifold::dist_hyp(&a, &b, 1.0);
    let s = heraclitus_manifold::mobius_add(&a, &b);
    let n: f32 = s.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!(n < 1.0, "ball invariant violated: {n}");
    let _ = heraclitus_manifold::exp_map0(&heraclitus_manifold::log_map0(&a));
});
