//! SPEC-016 — external analytical protocol (Arrow Flight-shaped contract).
//!
//! The zero-copy analytical surface: clients fetch streams of record batches by
//! ticket and push batches back. This module is the transport-agnostic *trait*
//! (batches as opaque byte buffers); the concrete engine binds it to gRPC +
//! Arrow IPC in `heraclitus-server`. Real Flight wiring (tonic + arrow-flight)
//! is a follow-up — the contract here is what it implements.

/// Opaque descriptor of what to fetch (an encoded query / stream id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket(pub Vec<u8>);

/// A single serialized columnar batch (Arrow IPC bytes, opaque here).
pub type BatchBytes = Vec<u8>;

pub trait FlightService: Send + Sync {
    /// Stream the batches addressed by `ticket`.
    fn do_get(&self, ticket: &Ticket) -> Result<Vec<BatchBytes>, String>;
    /// Ingest a stream of batches; returns how many were accepted.
    fn do_put(&self, batches: Vec<BatchBytes>) -> Result<usize, String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemFlight {
        store: Mutex<HashMap<Vec<u8>, Vec<BatchBytes>>>,
    }
    impl FlightService for MemFlight {
        fn do_get(&self, ticket: &Ticket) -> Result<Vec<BatchBytes>, String> {
            self.store
                .lock()
                .unwrap()
                .get(&ticket.0)
                .cloned()
                .ok_or_else(|| "unknown ticket".into())
        }
        fn do_put(&self, batches: Vec<BatchBytes>) -> Result<usize, String> {
            let n = batches.len();
            self.store.lock().unwrap().insert(b"t1".to_vec(), batches);
            Ok(n)
        }
    }

    #[test]
    fn put_then_get_roundtrips_batches() {
        let f = MemFlight::default();
        assert_eq!(f.do_put(vec![vec![1, 2], vec![3, 4]]).unwrap(), 2);
        assert_eq!(f.do_get(&Ticket(b"t1".to_vec())).unwrap(), vec![vec![1, 2], vec![3, 4]]);
        assert!(f.do_get(&Ticket(b"nope".to_vec())).is_err());
    }
}
