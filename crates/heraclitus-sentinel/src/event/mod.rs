//! Persisted security-domain event types.

mod security_event;
mod signal;

pub use security_event::{
    EntityRef, NetworkEndpoint, Outcome, SecurityCategory, SecurityEvent, SecuritySource,
};
pub use signal::{DetectorIdentity, EvidenceRef, SecuritySignal};
