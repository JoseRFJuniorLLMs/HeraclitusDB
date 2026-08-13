//! M0 criterion baseline: append throughput under both fsync policies.

use criterion::{criterion_group, criterion_main, Criterion};
use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;

fn bench_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_append");

    for (name, policy) in [
        (
            "group_commit_5ms",
            FsyncPolicy::GroupCommit { interval_ms: 5 },
        ),
        ("fsync_always", FsyncPolicy::Always),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 256 * 1024 * 1024, policy).unwrap();
        group.bench_function(name, |b| {
            b.iter(|| {
                log.append(Episode::new(
                    "bench",
                    EventKind::Observation,
                    b"the river flows".to_vec(),
                ))
                .unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_append);
criterion_main!(benches);
