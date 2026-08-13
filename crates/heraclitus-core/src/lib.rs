//! heraclitus-core — shared types, IDs, errors and config.
//!
//! Design thesis #1: the log is the truth. Everything in this crate exists to
//! describe what goes *into* the log (`Episode`), what is *derived* from it
//! (`Fact`), and how the rest of the system is configured.

pub mod artifact_registry;
pub mod canonical;
pub mod capability;
pub mod config;
pub mod consistency;
pub mod contracts;
pub mod cost;
pub mod dispatcher;
pub mod ebr;
pub mod error;
pub mod event;
pub mod flight;
pub mod format_version;
pub mod hlc;
pub mod id;
pub mod ir;
pub mod numa;
pub mod plugin;
pub mod runtime;
pub mod sandbox;
pub mod streaming;
pub mod telemetry;
pub mod vm;

pub use canonical::CanonicalKeyCodec;
pub use capability::CapabilityCatalog;
pub use config::{FsyncPolicy, HeraclitusConfig, RaftTransport, ReplicationConfig};
pub use consistency::IsolationLevel;
pub use runtime::{
    ArtifactType, DatabaseManifest, DerivedExecutionArtifact, ExecutionContext, QueryFingerprint,
    SegmentState, StorageEngine,
};
pub use streaming::{NotificationEvent, StreamSubscriber};
pub use error::HeraclitusError;
pub use event::{Episode, EventKind, Fact, ProductPoint};
pub use hlc::Hlc;
pub use id::{EventId, FactId, Lsn, SegmentId};
