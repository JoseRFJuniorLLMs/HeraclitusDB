//! Bounded notification queue with explicit LSN catch-up.

use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, Sender, TrySendError};
use heraclitus_core::Lsn;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

const NO_CATCH_UP: u64 = u64::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Enqueued,
    Overflow { catch_up_from_lsn: Lsn },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueSnapshot {
    pub depth: usize,
    pub capacity: usize,
    pub overflow_total: u64,
    pub catch_up_from_lsn: Option<Lsn>,
}

/// The queue stores only notification LSNs.  It never stores event payloads,
/// keeping memory bounded even when producers emit large records.
pub struct SecurityQueue {
    tx: Sender<Lsn>,
    rx: Receiver<Lsn>,
    capacity: usize,
    depth: AtomicUsize,
    overflow_total: AtomicU64,
    catch_up_from: AtomicU64,
}

impl SecurityQueue {
    pub fn new(capacity: usize) -> Result<Self, &'static str> {
        if capacity == 0 {
            return Err("queue capacity must be greater than zero");
        }
        let (tx, rx) = bounded(capacity);
        Ok(Self {
            tx,
            rx,
            capacity,
            depth: AtomicUsize::new(0),
            overflow_total: AtomicU64::new(0),
            catch_up_from: AtomicU64::new(NO_CATCH_UP),
        })
    }

    pub fn receiver(&self) -> Receiver<Lsn> {
        self.rx.clone()
    }

    pub fn try_enqueue(&self, lsn: Lsn) -> EnqueueOutcome {
        // Reserve the depth before publishing so a worker cannot receive and
        // decrement before the producer has incremented the counter.
        self.depth.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(lsn) {
            Ok(()) => EnqueueOutcome::Enqueued,
            Err(TrySendError::Full(lsn)) => {
                self.depth.fetch_sub(1, Ordering::Relaxed);
                self.overflow_total.fetch_add(1, Ordering::Relaxed);
                self.request_catch_up(lsn);
                EnqueueOutcome::Overflow {
                    catch_up_from_lsn: self.catch_up_from.load(Ordering::Acquire).min(lsn),
                }
            }
            Err(TrySendError::Disconnected(lsn)) => {
                self.depth.fetch_sub(1, Ordering::Relaxed);
                // A stopped worker is equivalent to a dropped notification;
                // retaining the LSN makes restart/replay recoverable.
                self.request_catch_up(lsn);
                EnqueueOutcome::Overflow {
                    catch_up_from_lsn: lsn,
                }
            }
        }
    }

    pub fn request_catch_up(&self, from_lsn: Lsn) {
        let mut current = self.catch_up_from.load(Ordering::Acquire);
        while from_lsn < current {
            match self.catch_up_from.compare_exchange_weak(
                current,
                from_lsn,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    pub fn take_catch_up(&self) -> Option<Lsn> {
        match self.catch_up_from.swap(NO_CATCH_UP, Ordering::AcqRel) {
            NO_CATCH_UP => None,
            value => Some(value),
        }
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<Lsn, RecvTimeoutError> {
        let lsn = self.rx.recv_timeout(timeout)?;
        self.depth.fetch_sub(1, Ordering::Relaxed);
        Ok(lsn)
    }

    pub fn snapshot(&self) -> QueueSnapshot {
        QueueSnapshot {
            depth: self.depth.load(Ordering::Acquire),
            capacity: self.capacity,
            overflow_total: self.overflow_total.load(Ordering::Acquire),
            catch_up_from_lsn: match self.catch_up_from.load(Ordering::Acquire) {
                NO_CATCH_UP => None,
                value => Some(value),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_overflow_records_the_earliest_recoverable_lsn() {
        let queue = SecurityQueue::new(1).unwrap();
        assert_eq!(queue.try_enqueue(10), EnqueueOutcome::Enqueued);
        assert!(matches!(
            queue.try_enqueue(20),
            EnqueueOutcome::Overflow { .. }
        ));
        assert!(matches!(
            queue.try_enqueue(5),
            EnqueueOutcome::Overflow { .. }
        ));
        assert_eq!(queue.take_catch_up(), Some(5));
        assert_eq!(queue.snapshot().depth, 1);
        assert_eq!(queue.recv_timeout(Duration::from_millis(1)).unwrap(), 10);
        assert_eq!(queue.snapshot().depth, 0);
    }
}
