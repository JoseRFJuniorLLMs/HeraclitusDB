//! heraclitus-sim — deterministic simulation tests.
//!
//! The full turmoil suite (network partition, leader kill, clock skew over
//! `heraclitus-raft`) is the M6 acceptance gate and lands with replication.
//! Until then this crate hosts simulation-friendly invariant checks that do
//! not require a network: deterministic replay equivalence under arbitrary
//! batch boundaries.

#[cfg(test)]
mod tests {
    use heraclitus_core::{Episode, EventKind, FsyncPolicy};
    use heraclitus_log::Log;

    /// Replaying the same log in different batch sizes must visit the exact
    /// same (lsn, event-id) sequence — the property every view relies on.
    #[test]
    fn replay_is_batchsize_invariant() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..97 {
            log.append(Episode::new(
                "sim",
                EventKind::Observation,
                format!("e{i}").into_bytes(),
            ))
            .unwrap();
        }

        let full: Vec<_> = log
            .scan(0, u64::MAX)
            .unwrap()
            .into_iter()
            .map(|(l, e)| (l, e.id))
            .collect();

        for chunk in [1u64, 7, 13, 50, 1000] {
            let mut acc = Vec::new();
            let mut from = 0;
            loop {
                let batch = log.scan(from, from + chunk).unwrap();
                if batch.is_empty() && from >= log.head() {
                    break;
                }
                for (l, e) in &batch {
                    acc.push((*l, e.id));
                }
                from += chunk;
            }
            assert_eq!(acc, full, "batch size {chunk} changed the replay order");
        }
    }
}
