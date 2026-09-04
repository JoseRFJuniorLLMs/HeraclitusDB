//! Durable state and replay utilities.

pub mod checkpoint;
pub mod replay;
pub mod snapshot;
pub mod startup;

pub use checkpoint::{CursorStore, SentinelCheckpoint, SentinelCursor};
pub use crate::cursor::CursorRejeitado;
pub use replay::{replay, ReplayReport};
pub use snapshot::{
    FusionAccumulatorState, SentinelStateSnapshot, SnapshotLoad, SnapshotStore,
    SNAPSHOT_FORMAT_VERSION,
};
pub use startup::{
    reconcile_startup_state, RebuildReason, StartupReconciliation, StateDivergenceReason,
};
