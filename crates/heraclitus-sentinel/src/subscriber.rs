//! Lightweight bridge from the log tail to the bounded Sentinel queue.

use crate::metrics::SentinelMetrics;
use crate::queue::{EnqueueOutcome, SecurityQueue};
use heraclitus_core::{NotificationEvent, StreamSubscriber};
use std::sync::Arc;

pub struct SecuritySubscriber {
    queue: Arc<SecurityQueue>,
    metrics: Arc<SentinelMetrics>,
}

impl SecuritySubscriber {
    pub fn new(queue: Arc<SecurityQueue>, metrics: Arc<SentinelMetrics>) -> Self {
        Self { queue, metrics }
    }

    pub fn queue(&self) -> &Arc<SecurityQueue> {
        &self.queue
    }
}

impl StreamSubscriber for SecuritySubscriber {
    fn on_append(&self, event: &NotificationEvent) {
        // This method is deliberately limited to atomics + try_send.  Parsing,
        // disk I/O and derived appends belong to the worker thread.
        self.metrics
            .events_seen_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if matches!(
            self.queue.try_enqueue(event.lsn),
            EnqueueOutcome::Overflow { .. }
        ) {
            self.metrics
                .queue_overflow_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn on_buffer_overflow(&self, expected_lsn: heraclitus_core::Lsn) {
        self.metrics
            .queue_overflow_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.queue.request_catch_up(expected_lsn);
    }
}
