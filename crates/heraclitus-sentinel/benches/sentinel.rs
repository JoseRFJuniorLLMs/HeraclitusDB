use heraclitus_core::{Episode, EventKind, FsyncPolicy, StorageFormat};
use heraclitus_log::subscribe::attach_subscriber_with_stop;
use heraclitus_log::AnyLog;
use heraclitus_sentinel::{SecurityQueue, SecuritySubscriber, SentinelMetrics, SentinelMode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const EVENTS_PER_ROUND: usize = 1_000;
const ROUNDS: usize = 6;

fn append_batch(log: &AnyLog, count: usize) {
    for index in 0..count {
        log.append(Episode::new(
            "bench",
            EventKind::Observation,
            format!("event-{index}").into_bytes(),
        ))
        .expect("append benchmark");
    }
}

fn measure_baseline() -> Duration {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = AnyLog::open(
        StorageFormat::Legacy,
        dir.path().join("baseline"),
        64 << 20,
        FsyncPolicy::Always,
    )
    .expect("baseline log");
    let started = Instant::now();
    append_batch(&log, EVENTS_PER_ROUND);
    started.elapsed()
}

/// Measure the only Sentinel work reachable from append: broadcast delivery,
/// atomic accounting and `try_send` of an LSN. A drain keeps the bounded queue
/// empty, so this is the normative P0/P1 "no backlog" gate; normalization and
/// derived-event I/O remain outside the measured ACK path by architecture.
fn measure_subscriber() -> Duration {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = AnyLog::open(
        StorageFormat::Legacy,
        dir.path().join("subscriber"),
        64 << 20,
        FsyncPolicy::Always,
    )
    .expect("subscriber log");
    let queue = Arc::new(SecurityQueue::new(4_096).expect("queue"));
    let metrics = Arc::new(SentinelMetrics::default());
    let stop = Arc::new(AtomicBool::new(false));
    let tail = attach_subscriber_with_stop(
        &log,
        Arc::new(SecuritySubscriber::new(queue.clone(), metrics.clone())),
        stop.clone(),
    );
    let drain_queue = queue.clone();
    let drain_stop = stop.clone();
    let drain = std::thread::spawn(move || {
        while !drain_stop.load(Ordering::Acquire) || drain_queue.snapshot().depth > 0 {
            let _ = drain_queue.recv_timeout(Duration::from_millis(5));
        }
    });
    std::thread::sleep(Duration::from_millis(10));

    let started = Instant::now();
    append_batch(&log, EVENTS_PER_ROUND);
    let elapsed = started.elapsed();

    let deadline = Instant::now() + Duration::from_secs(10);
    while metrics
        .snapshot(
            true,
            SentinelMode::Observe,
            1,
            log.head(),
            log.head(),
            queue.snapshot(),
        )
        .events_seen_total
        < EVENTS_PER_ROUND as u64
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    stop.store(true, Ordering::Release);
    tail.join().expect("tail thread");
    drain.join().expect("drain thread");
    let status = metrics.snapshot(
        true,
        SentinelMode::Observe,
        1,
        log.head(),
        log.head(),
        queue.snapshot(),
    );
    assert_eq!(status.events_seen_total, EVENTS_PER_ROUND as u64);
    assert_eq!(status.queue_overflow_total, 0);
    assert_eq!(status.queue_depth, 0);
    elapsed
}

fn main() {
    let mut baseline = Duration::ZERO;
    let mut subscriber = Duration::ZERO;
    let mut round_degradations = Vec::with_capacity(ROUNDS);
    for round in 0..ROUNDS {
        // Alternate order to cancel warm-cache and scheduler bias.
        let (baseline_round, subscriber_round) = if round % 2 == 0 {
            (measure_baseline(), measure_subscriber())
        } else {
            let subscriber_round = measure_subscriber();
            (measure_baseline(), subscriber_round)
        };
        baseline += baseline_round;
        subscriber += subscriber_round;
        round_degradations
            .push((1.0 - baseline_round.as_secs_f64() / subscriber_round.as_secs_f64()) * 100.0);
    }

    let count = (EVENTS_PER_ROUND * ROUNDS) as f64;
    let baseline_rate = count / baseline.as_secs_f64();
    let subscriber_rate = count / subscriber.as_secs_f64();
    let aggregate_degradation = (1.0 - subscriber_rate / baseline_rate) * 100.0;
    round_degradations.sort_by(f64::total_cmp);
    let degradation = (round_degradations[ROUNDS / 2 - 1] + round_degradations[ROUNDS / 2]) / 2.0;
    println!(
        "sentinel P0 append-isolation: baseline={baseline_rate:.0} events/s, subscriber={subscriber_rate:.0} events/s, median_degradation={degradation:.2}%, aggregate_degradation={aggregate_degradation:.2}%"
    );
    assert!(
        degradation < 3.0,
        "SPEC-0045 P0 failed: append degradation {degradation:.2}% >= 3%"
    );
}
