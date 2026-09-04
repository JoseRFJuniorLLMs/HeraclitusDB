//! Read-only operational compliance snapshot.
//!
//! The snapshot is derived from the append-only log and receipt manifest. It
//! never upgrades an unvalidated external token to an ICP-Brasil-valid anchor.

use crate::commit::current_watermark;
use crate::deferred::DeferredAnchorState;
use crate::privacy::{DeadlineUrgency, PrivacyState};
use crate::receipt::{load_manifest, TimestampValidationState};
use crate::regulatory::{RegulatoryState, RequirementEffect};
use crate::sovereignty::{SovereigntyAuditState, SovereigntyMode, SovereigntyVerdict};
use heraclitus_core::Lsn;
use heraclitus_log::EpisodeLog;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ComplianceDashboardError {
    #[error("recibos de compliance: {0}")]
    Receipts(String),
    #[error("estado regulatório: {0}")]
    Regulatory(String),
    #[error("estado de privacidade: {0}")]
    Privacy(String),
    #[error("estado de soberania: {0}")]
    Sovereignty(String),
    #[error("cadeia de anchors: {0}")]
    Anchors(String),
    #[error("leitura do log: {0}")]
    Storage(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceOverallStatus {
    Operational,
    AttentionRequired,
    NotYetProductionTrusted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorHealthSnapshot {
    pub receipts_total: usize,
    pub current_sealed_watermark: Lsn,
    pub last_anchor_lsn: Option<Lsn>,
    pub last_anchor_validation: Option<TimestampValidationState>,
    /// Remains `None` until a production CMS/X.509/ICP-Brasil verifier emits a
    /// dedicated trusted validation state.
    pub last_icp_brasil_valid_anchor_lsn: Option<Lsn>,
    pub unanchored_lsn_range: Option<(Lsn, Lsn)>,
    pub deferred_anchors: usize,
    pub last_deferred_anchor_digest: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlineHealthSnapshot {
    pub total: usize,
    pub overdue: usize,
    pub due_within_24h: usize,
    pub due_within_48h: usize,
    pub due_within_72h: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHoldSnapshot {
    pub hold_id: String,
    pub lsn_start: Lsn,
    pub lsn_end: Lsn,
    pub authority: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereigntyHealthSnapshot {
    pub last_observed_mode: Option<SovereigntyMode>,
    pub egress_allowed: usize,
    pub egress_denied: usize,
    pub model_allowed: usize,
    pub model_denied: usize,
    pub verified_model_activations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceDashboardSnapshot {
    pub as_of_lsn: Lsn,
    pub generated_at_unix_secs: u64,
    pub status: ComplianceOverallStatus,
    pub anchor_health: AnchorHealthSnapshot,
    pub regulatory_deadlines: DeadlineHealthSnapshot,
    pub anpd_pending_decisions: Vec<String>,
    pub legal_holds: Vec<LegalHoldSnapshot>,
    pub retention_exceptions: usize,
    pub active_policy_versions: usize,
    pub sovereignty: SovereigntyHealthSnapshot,
    /// Explicit limitation rendered by every API consumer.
    pub trust_notice: String,
}

impl ComplianceDashboardSnapshot {
    pub fn build<L: EpisodeLog + ?Sized>(
        log: &L,
        receipts_dir: impl AsRef<Path>,
        now_unix_secs: u64,
    ) -> Result<Self, ComplianceDashboardError> {
        let as_of_lsn = log.head();
        let regulatory = RegulatoryState::replay(log, as_of_lsn)
            .map_err(|error| ComplianceDashboardError::Regulatory(error.to_string()))?;
        let privacy = PrivacyState::replay(log, as_of_lsn)
            .map_err(|error| ComplianceDashboardError::Privacy(error.to_string()))?;
        let sovereignty = SovereigntyAuditState::replay(log)
            .map_err(|error| ComplianceDashboardError::Sovereignty(error.to_string()))?;
        let deferred = DeferredAnchorState::replay(log, as_of_lsn)
            .map_err(|error| ComplianceDashboardError::Anchors(error.to_string()))?;
        let receipts = load_manifest(receipts_dir)
            .map_err(|error| ComplianceDashboardError::Receipts(error.to_string()))?;
        let current_sealed_watermark = current_watermark(log);
        let last_receipt = receipts.iter().max_by_key(|receipt| receipt.lsn);
        let last_anchor_lsn = last_receipt.map(|receipt| receipt.lsn);
        let unanchored_lsn_range = match last_anchor_lsn {
            Some(last) if last < current_sealed_watermark => {
                Some((last.saturating_add(1), current_sealed_watermark))
            }
            None if current_sealed_watermark > 0 => Some((0, current_sealed_watermark)),
            _ => None,
        };
        let anchor_health = AnchorHealthSnapshot {
            receipts_total: receipts.len(),
            current_sealed_watermark,
            last_anchor_lsn,
            last_anchor_validation: last_receipt.map(|receipt| receipt.validation_state),
            // There is intentionally no trusted external state in the enum yet.
            last_icp_brasil_valid_anchor_lsn: None,
            unanchored_lsn_range,
            deferred_anchors: deferred.anchors.len(),
            last_deferred_anchor_digest: deferred.latest_digest().map(|digest| hex(&digest)),
        };

        let mut deadlines = DeadlineHealthSnapshot {
            total: privacy.deadlines.len(),
            ..DeadlineHealthSnapshot::default()
        };
        for (_, deadline) in &privacy.deadlines {
            match deadline.urgency(now_unix_secs) {
                DeadlineUrgency::Overdue => deadlines.overdue += 1,
                DeadlineUrgency::T24h => deadlines.due_within_24h += 1,
                DeadlineUrgency::T48h => deadlines.due_within_48h += 1,
                DeadlineUrgency::T72h => deadlines.due_within_72h += 1,
                DeadlineUrgency::Later | DeadlineUrgency::Completed => {}
            }
        }
        let exported_incidents: BTreeSet<_> = privacy
            .exports
            .iter()
            .map(|(_, receipt)| receipt.incident_id.as_str())
            .collect();
        let mut anpd_pending_decisions: Vec<_> = privacy
            .assessments
            .iter()
            .filter(|(_, assessment)| !exported_incidents.contains(assessment.incident_id.as_str()))
            .map(|(_, assessment)| assessment.incident_id.clone())
            .collect();
        anpd_pending_decisions.sort();
        anpd_pending_decisions.dedup();

        let mut legal_holds: Vec<_> = regulatory
            .active_holds()
            .map(|record| LegalHoldSnapshot {
                hold_id: record.hold.hold_id.clone(),
                lsn_start: record.hold.scope.lsn_start,
                lsn_end: record.hold.scope.lsn_end,
                authority: record.hold.authority.clone(),
            })
            .collect();
        legal_holds.sort_by(|left, right| left.hold_id.cmp(&right.hold_id));
        let retention_exceptions = regulatory
            .decisions
            .iter()
            .flat_map(|record| &record.decision.requirements)
            .filter(|requirement| {
                matches!(
                    requirement.effect,
                    RequirementEffect::PreventDestruction
                        | RequirementEffect::RetainForSeconds { .. }
                )
            })
            .count();

        let mut sovereignty_health = SovereigntyHealthSnapshot::default();
        for (_, decision) in &sovereignty.egress {
            sovereignty_health.last_observed_mode = Some(decision.mode);
            match decision.verdict {
                SovereigntyVerdict::Allow => sovereignty_health.egress_allowed += 1,
                SovereigntyVerdict::Deny => sovereignty_health.egress_denied += 1,
            }
        }
        for (_, decision) in &sovereignty.models {
            sovereignty_health.last_observed_mode = Some(decision.mode);
            match decision.verdict {
                SovereigntyVerdict::Allow => sovereignty_health.model_allowed += 1,
                SovereigntyVerdict::Deny => sovereignty_health.model_denied += 1,
            }
        }
        // Janelado — ver `crate::varrimento`. Esta contagem é a quinta
        // varredura completa do log dentro de UM pedido a
        // `GET /compliance/status`, cuja autenticação é opcional em loopback.
        let mut activations = 0usize;
        crate::varrimento::por_episodio(
            log,
            as_of_lsn,
            |error| ComplianceDashboardError::Storage(error.to_string()),
            |_, episode| {
                if episode.kind.label() == "SecurityModelActivation" {
                    activations += 1;
                }
                Ok(())
            },
        )?;
        sovereignty_health.verified_model_activations = activations;

        let has_production_trust = anchor_health.last_icp_brasil_valid_anchor_lsn.is_some();
        let status = if !has_production_trust {
            ComplianceOverallStatus::NotYetProductionTrusted
        } else if deadlines.overdue > 0
            || !anpd_pending_decisions.is_empty()
            || anchor_health.unanchored_lsn_range.is_some()
        {
            ComplianceOverallStatus::AttentionRequired
        } else {
            ComplianceOverallStatus::Operational
        };
        Ok(Self {
            as_of_lsn,
            generated_at_unix_secs: now_unix_secs,
            status,
            anchor_health,
            regulatory_deadlines: deadlines,
            anpd_pending_decisions,
            legal_holds,
            retention_exceptions,
            active_policy_versions: regulatory.policy_activations.len(),
            sovereignty: sovereignty_health,
            trust_notice: "Tokens externos não possuem validação CMS/X.509/ICP-Brasil nesta build; o dashboard não os apresenta como âncoras juridicamente validadas.".into(),
        })
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regulatory::{EvidenceSelector, LegalHold, RegulatoryPolicyEngine};
    use heraclitus_core::{FsyncPolicy, StorageFormat};
    use heraclitus_log::AnyLog;
    use std::sync::Arc;

    #[test]
    fn dashboard_replays_holds_and_never_claims_icp_trust() {
        let temp = tempfile::tempdir().unwrap();
        let receipts = temp.path().join("receipts");
        let log = Arc::new(
            AnyLog::open(
                StorageFormat::V6,
                temp.path().join("log"),
                4096,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        RegulatoryPolicyEngine::new(log.clone())
            .place_legal_hold(LegalHold {
                hold_id: "hold-dashboard".into(),
                scope: EvidenceSelector {
                    lsn_start: 0,
                    lsn_end: 100,
                },
                authority: "court".into(),
                reason: "litigation".into(),
                created_at_lsn: 0,
            })
            .unwrap();
        let snapshot = ComplianceDashboardSnapshot::build(log.as_ref(), receipts, 0).unwrap();
        assert_eq!(snapshot.legal_holds.len(), 1);
        assert_eq!(snapshot.legal_holds[0].hold_id, "hold-dashboard");
        assert_eq!(
            snapshot.anchor_health.last_icp_brasil_valid_anchor_lsn,
            None
        );
        assert_eq!(
            snapshot.status,
            ComplianceOverallStatus::NotYetProductionTrusted
        );
        assert!(snapshot.trust_notice.contains("não possu"));
    }
}
