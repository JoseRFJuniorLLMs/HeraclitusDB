//! Deterministic L1 signal envelope.

use super::EntityRef;
use heraclitus_core::{Episode, EventId, EventKind, Lsn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorIdentity {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub lsn: Lsn,
    pub event_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecuritySignal {
    pub signal_id: String,
    pub detector: DetectorIdentity,
    pub severity: u8,
    pub score: f32,
    pub subject: Option<EntityRef>,
    pub evidence: Vec<EvidenceRef>,
    pub created_at_lsn: Lsn,
    pub labels: BTreeMap<String, String>,
}

impl SecuritySignal {
    /// Stable BLAKE3 identity for the logical signal.  Length prefixes avoid
    /// concatenation ambiguities and evidence is sorted by LSN/event ID.
    pub fn deterministic_id(
        detector: &DetectorIdentity,
        subject: Option<&EntityRef>,
        evidence: &[EvidenceRef],
        window_start: Lsn,
    ) -> String {
        let mut bytes = Vec::new();
        append_part(&mut bytes, detector.id.as_bytes());
        append_part(&mut bytes, detector.version.as_bytes());
        append_part(&mut bytes, &window_start.to_le_bytes());
        if let Some(subject) = subject {
            append_part(&mut bytes, subject.kind.as_bytes());
            append_part(&mut bytes, subject.id.as_bytes());
        } else {
            append_part(&mut bytes, b"<none>");
        }
        let mut ordered = evidence.to_vec();
        ordered.sort_by(|a, b| a.lsn.cmp(&b.lsn).then_with(|| a.event_id.cmp(&b.event_id)));
        for item in ordered {
            append_part(&mut bytes, &item.lsn.to_le_bytes());
            append_part(&mut bytes, item.event_id.to_string().as_bytes());
        }
        format!("sig-{}", blake3::hash(&bytes).to_hex())
    }

    /// Persist a signal as a derived event without adding a new `EventKind`
    /// discriminant.  Evidence event IDs are ordered and deduplicated before
    /// becoming causal parents.
    pub fn into_episode(&self) -> Result<Episode, serde_json::Error> {
        let mut episode = Episode::new(
            "sentinel",
            EventKind::Custom("SecuritySignal".into()),
            serde_json::to_vec(self)?,
        );
        let mut parents: Vec<EventId> = self.evidence.iter().map(|item| item.event_id).collect();
        parents.sort_unstable();
        parents.dedup();
        episode.parents = parents;
        episode
            .attrs
            .insert("sentinel.generated".into(), "true".into());
        episode
            .attrs
            .insert("sentinel.signal_id".into(), self.signal_id.clone());
        episode.attrs.insert(
            "sentinel.created_at_lsn".into(),
            self.created_at_lsn.to_string(),
        );
        episode
            .attrs
            .insert("sentinel.detector".into(), self.detector.id.clone());
        Ok(episode)
    }
}

fn append_part(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u64).to_le_bytes());
    out.extend_from_slice(part);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_id_is_order_independent_for_evidence() {
        let detector = DetectorIdentity {
            id: "brute-force".into(),
            version: "1.0.0".into(),
        };
        let a = EventId::new();
        let b = EventId::new();
        let left = vec![
            EvidenceRef {
                lsn: 2,
                event_id: b,
            },
            EvidenceRef {
                lsn: 1,
                event_id: a,
            },
        ];
        let right = vec![
            EvidenceRef {
                lsn: 1,
                event_id: a,
            },
            EvidenceRef {
                lsn: 2,
                event_id: b,
            },
        ];
        assert_eq!(
            SecuritySignal::deterministic_id(&detector, None, &left, 1),
            SecuritySignal::deterministic_id(&detector, None, &right, 1)
        );
    }
}
