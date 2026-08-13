use serde::{Deserialize, Serialize};

/// Log sequence number. Monotonic, assigned by the log at append time.
pub type Lsn = u64;

/// Segment identifier (monotonic per data dir).
pub type SegmentId = u64;

/// Event identifier: ULID — time-ordered, 128-bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(pub ulid::Ulid);

impl EventId {
    pub fn new() -> Self {
        Self(ulid::Ulid::new())
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for EventId {
    type Err = ulid::DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(ulid::Ulid::from_string(s)?))
    }
}

/// Fact identifier (also a ULID; facts are themselves log events).
pub type FactId = EventId;
