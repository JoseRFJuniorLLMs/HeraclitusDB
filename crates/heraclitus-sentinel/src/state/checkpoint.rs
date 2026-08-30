//! Durable Sentinel checkpoint metadata.
//!
//! The cursor file is the fast local replay hint.  This event-sourced
//! checkpoint is the auditable counterpart: it records the transaction LSN,
//! pipeline/detector versions and the derived-state watermarks in the log.

use heraclitus_core::{Episode, EventKind, Lsn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use crate::cursor::{CursorStore, SentinelCursor};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelCheckpoint {
    pub as_of_lsn: Lsn,
    pub next_lsn: Lsn,
    pub pipeline_version: u32,
    pub detector_versions: BTreeMap<String, String>,
    pub graph_watermark_lsn: Option<Lsn>,
    pub incident_revisions: u64,
    pub risk_revisions: u64,
}

impl SentinelCheckpoint {
    pub fn checkpoint_id(&self) -> Result<String, serde_json::Error> {
        Ok(format!(
            "ckpt-{}",
            blake3::hash(&serde_json::to_vec(self)?).to_hex()
        ))
    }

    pub fn into_episode(&self) -> Result<Episode, serde_json::Error> {
        let checkpoint_id = self.checkpoint_id()?;
        let mut episode = Episode::new(
            "sentinel",
            EventKind::Custom("SentinelCheckpoint".into()),
            serde_json::to_vec(self)?,
        );
        episode
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        episode
            .attrs
            .insert("sentinel.checkpoint_id".into(), checkpoint_id);
        episode
            .attrs
            .insert("sentinel.as_of_lsn".into(), self.as_of_lsn.to_string());
        episode.attrs.insert(
            "sentinel.pipeline_version".into(),
            self.pipeline_version.to_string(),
        );
        Ok(episode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_identity_and_episode_are_deterministic() {
        let checkpoint = SentinelCheckpoint {
            as_of_lsn: 7,
            next_lsn: 8,
            pipeline_version: 2,
            detector_versions: BTreeMap::from([(String::from("l1"), String::from("v1"))]),
            graph_watermark_lsn: Some(7),
            incident_revisions: 3,
            risk_revisions: 2,
        };
        let first = checkpoint.checkpoint_id().unwrap();
        let second = checkpoint.into_episode().unwrap();
        assert_eq!(second.attrs["sentinel.checkpoint_id"], first);
        assert_eq!(second.kind, EventKind::Custom("SentinelCheckpoint".into()));
        assert_eq!(second.agent_id, "sentinel");
    }
}
