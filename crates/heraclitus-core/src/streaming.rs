//! SPEC-022 — reactive streaming API.
//!
//! Subscribers react to appends the instant they hit the active log head,
//! without waiting for the macro Freeze window. The engine pushes each new
//! event into the delta buffers and notifies subscribers; a slow subscriber
//! that falls behind is told to catch up from history instead of blocking the
//! write path.

use crate::{EventId, Lsn};

/// A lightweight notification handed to subscribers on each append.
#[derive(Debug, Clone)]
pub struct NotificationEvent {
    pub lsn: Lsn,
    pub event_id: EventId,
    pub agent_id: String,
}

/// Reactive subscriber contract. Implementations MUST be cheap and non-blocking
/// — heavy work belongs off the write path.
pub trait StreamSubscriber: Send + Sync {
    /// Invoked right after an append is physically synced to the active log.
    fn on_append(&self, event: &NotificationEvent);
    /// Invoked when the subscriber lagged and must catch up from `expected_lsn`.
    fn on_buffer_overflow(&self, expected_lsn: Lsn);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn subscriber_receives_notifications() {
        #[derive(Default)]
        struct Counter {
            seen: AtomicU64,
            last: AtomicU64,
        }
        impl StreamSubscriber for Counter {
            fn on_append(&self, e: &NotificationEvent) {
                self.seen.fetch_add(1, Ordering::Relaxed);
                self.last.store(e.lsn, Ordering::Relaxed);
            }
            fn on_buffer_overflow(&self, _expected: Lsn) {}
        }
        let c = Counter::default();
        for lsn in 0..5 {
            c.on_append(&NotificationEvent {
                lsn,
                event_id: EventId::new(),
                agent_id: "a".into(),
            });
        }
        assert_eq!(c.seen.load(Ordering::Relaxed), 5);
        assert_eq!(c.last.load(Ordering::Relaxed), 4);
    }
}
