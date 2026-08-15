use thiserror::Error;

/// Error taxonomy. `Corruption` is never silently swallowed: every recovery
/// from corruption must emit a metric and a tracing event.
#[derive(Debug, Error)]
pub enum HeraclitusError {
    #[error("storage error: {0}")]
    Storage(#[from] std::io::Error),

    #[error("storage engine error: {0}")]
    StorageEngine(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("corruption detected in {context}: {detail}")]
    Corruption { context: String, detail: String },

    #[error("geometry error: {0}")]
    Geometry(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("query error: {0}")]
    Query(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("compare-and-append failed: expected lsn {expected}, head is {head}")]
    CasConflict { expected: u64, head: u64 },

    /// The same external idempotency key was reused for a different payload.
    /// Silently accepting this would turn a source-side identity collision into
    /// evidence loss, so it is a first-class conflict rather than a generic
    /// query/storage failure.
    #[error("idempotency conflict for key {key}")]
    IdempotencyConflict { key: String },
}

pub type Result<T> = std::result::Result<T, HeraclitusError>;
