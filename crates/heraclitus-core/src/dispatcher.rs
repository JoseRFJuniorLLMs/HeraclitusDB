//! SPEC-010 §5 / SPEC-014 — linear deterministic replay dispatcher.
//!
//! Replaces an event "bus" with a strictly ordered, single-threaded pipeline:
//! each log record is handed to every registered sink in registration order. If
//! any sink fails, the whole dispatch aborts — this is what keeps derived views
//! from silently desynchronizing their LSN (a half-applied record is a bug, not
//! a warning).

use crate::Lsn;

/// A consumer of replayed log records (a view, an index, a metrics collector).
pub trait ReplaySink: Send + Sync {
    fn sink_identifier(&self) -> &'static str;
    fn consume_log_record(&mut self, lsn: Lsn, payload: &[u8]) -> Result<(), String>;
    fn commit_checkpoint(&mut self, _lsn: Lsn) -> Result<(), String> {
        Ok(())
    }
}

/// Ordered fan-out of records to sinks. Abort-on-first-error.
#[derive(Default)]
pub struct ReplayDispatcher {
    ordered_sinks: Vec<Box<dyn ReplaySink>>,
}

impl ReplayDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn attach_sink(&mut self, sink: Box<dyn ReplaySink>) {
        self.ordered_sinks.push(sink);
    }

    pub fn sink_count(&self) -> usize {
        self.ordered_sinks.len()
    }

    /// Dispatch one record to every sink in order. A single sink failure aborts
    /// the whole dispatch (the error names the offending sink) so callers can
    /// stop replay before any view diverges.
    pub fn dispatch_record(&mut self, lsn: Lsn, payload: &[u8]) -> Result<(), String> {
        for sink in &mut self.ordered_sinks {
            sink.consume_log_record(lsn, payload).map_err(|err| {
                format!("[SPEC-ERR] replay aborted at sink '{}': {err}", sink.sink_identifier())
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    struct Counting {
        id: &'static str,
        seen: Arc<AtomicU64>,
        fail_at: Option<Lsn>,
    }
    impl ReplaySink for Counting {
        fn sink_identifier(&self) -> &'static str {
            self.id
        }
        fn consume_log_record(&mut self, lsn: Lsn, _p: &[u8]) -> Result<(), String> {
            if self.fail_at == Some(lsn) {
                return Err(format!("boom at {lsn}"));
            }
            self.seen.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn dispatches_in_order_and_aborts_on_failure() {
        let a = Arc::new(AtomicU64::new(0));
        let b = Arc::new(AtomicU64::new(0));
        let mut d = ReplayDispatcher::new();
        d.attach_sink(Box::new(Counting { id: "a", seen: a.clone(), fail_at: None }));
        d.attach_sink(Box::new(Counting { id: "b", seen: b.clone(), fail_at: Some(3) }));
        assert_eq!(d.sink_count(), 2);

        for lsn in 0..3 {
            d.dispatch_record(lsn, b"x").unwrap();
        }
        // Record 3 makes sink "b" fail → the dispatch aborts, naming the sink.
        let err = d.dispatch_record(3, b"x").unwrap_err();
        assert!(err.contains("sink 'b'"), "got: {err}");
        // Sink "a" (earlier in order) did process record 3 before "b" failed.
        assert_eq!(a.load(Ordering::Relaxed), 4);
        assert_eq!(b.load(Ordering::Relaxed), 3);
    }
}
