//! LGPD incident assessment, versioned deadline calculation and deterministic
//! ANPD communication packages.
//!
//! This module creates drafts and evidence.  It deliberately has no API that
//! submits a package to an authority: that is an institutional human action.

use crate::regulatory::PolicyIdentity;
use heraclitus_core::{Episode, EventId, EventKind, Lsn};
use heraclitus_log::{AnyLog, EpisodeLog};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

const ASSESSMENT_EVENT: &str = "PrivacyIncidentAssessment";
const DEADLINE_EVENT: &str = "RegulatoryDeadline";
const EXPORT_EVENT: &str = "ComplianceExport";
const SECONDS_PER_DAY: u64 = 86_400;
const MAX_TEXT_BYTES: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum PrivacyError {
    #[error("objeto de privacidade inválido: {0}")]
    Invalid(String),
    #[error("serialização de privacidade: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("E/S do pacote regulatório: {0}")]
    Io(#[from] std::io::Error),
    #[error("log de privacidade: {0}")]
    Storage(String),
}

fn required(name: &str, value: &str) -> Result<(), PrivacyError> {
    if value.trim().is_empty() {
        return Err(PrivacyError::Invalid(format!("{name} vazio")));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(PrivacyError::Invalid(format!(
            "{name} excede {MAX_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn generated_episode(kind: &str, payload: Vec<u8>) -> Episode {
    let mut episode = Episode::new(
        "gov-compliance",
        EventKind::Custom(kind.to_owned()),
        payload,
    );
    episode
        .attrs
        .insert("compliance.generated".into(), "true".into());
    episode
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ComplianceEvidenceRef {
    pub lsn: Lsn,
    pub event_id: EventId,
    pub relation: String,
}

impl ComplianceEvidenceRef {
    fn validate(&self) -> Result<(), PrivacyError> {
        required("evidence relation", &self.relation)
    }
}

/// Technical assessment only.  `communication_required` is intentionally not
/// present: the engine does not replace the competent institutional authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyIncidentAssessment {
    pub assessment_id: String,
    pub incident_id: String,
    pub personal_data_involved: bool,
    pub categories: Vec<String>,
    pub estimated_subjects: Option<u64>,
    pub vulnerable_subjects: bool,
    pub sensitive_data: bool,
    pub estimated_risk: RiskLevel,
    pub evidence: Vec<ComplianceEvidenceRef>,
    pub assessed_by: String,
    pub assessed_at_lsn: Lsn,
    pub policy: PolicyIdentity,
}

impl PrivacyIncidentAssessment {
    pub fn validate(&self) -> Result<(), PrivacyError> {
        required("assessment_id", &self.assessment_id)?;
        required("incident_id", &self.incident_id)?;
        required("assessed_by", &self.assessed_by)?;
        required("policy_id", &self.policy.policy_id)?;
        required("policy version", &self.policy.version)?;
        if self.personal_data_involved && self.categories.is_empty() {
            return Err(PrivacyError::Invalid(
                "dados pessoais marcados sem categorias".into(),
            ));
        }
        if self.evidence.is_empty() {
            return Err(PrivacyError::Invalid(
                "avaliação de privacidade sem evidência".into(),
            ));
        }
        for category in &self.categories {
            required("data category", category)?;
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        Ok(())
    }

    fn to_episode(&self) -> Result<Episode, PrivacyError> {
        self.validate()?;
        let mut episode = generated_episode(ASSESSMENT_EVENT, serde_json::to_vec(self)?);
        episode.attrs.insert(
            "compliance.assessment_id".into(),
            self.assessment_id.clone(),
        );
        episode
            .attrs
            .insert("compliance.incident_id".into(), self.incident_id.clone());
        episode
            .attrs
            .insert("compliance.policy_id".into(), self.policy.policy_id.clone());
        episode.parents = self.evidence.iter().map(|item| item.event_id).collect();
        episode.parents.sort_unstable();
        episode.parents.dedup();
        Ok(episode)
    }
}

/// UTC business-day calendar. `holidays_utc_days` contains days since the Unix
/// epoch, avoiding locale/time-zone ambiguity in replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusinessCalendar {
    pub weekend_days: BTreeSet<u8>,
    pub holidays_utc_days: BTreeSet<u64>,
}

impl Default for BusinessCalendar {
    fn default() -> Self {
        Self {
            weekend_days: [5, 6].into_iter().collect(),
            holidays_utc_days: BTreeSet::new(),
        }
    }
}

impl BusinessCalendar {
    pub fn validate(&self) -> Result<(), PrivacyError> {
        if self.weekend_days.iter().any(|day| *day > 6) {
            return Err(PrivacyError::Invalid(
                "fim de semana deve usar weekday 0..=6 (segunda..domingo)".into(),
            ));
        }
        if self.weekend_days.len() == 7 {
            return Err(PrivacyError::Invalid(
                "calendário sem nenhum dia útil".into(),
            ));
        }
        Ok(())
    }

    pub fn is_business_day(&self, utc_day: u64) -> bool {
        // 1970-01-01 was Thursday (Monday = 0, Thursday = 3).
        let weekday = ((utc_day + 3) % 7) as u8;
        !self.weekend_days.contains(&weekday) && !self.holidays_utc_days.contains(&utc_day)
    }

    pub fn add_business_days(
        &self,
        timestamp_secs: u64,
        business_days: u16,
    ) -> Result<u64, PrivacyError> {
        self.validate()?;
        if business_days == 0 {
            return Err(PrivacyError::Invalid(
                "prazo regulatório deve possuir ao menos um dia útil".into(),
            ));
        }
        let seconds_in_day = timestamp_secs % SECONDS_PER_DAY;
        let mut day = timestamp_secs / SECONDS_PER_DAY;
        let mut remaining = business_days;
        while remaining > 0 {
            day = day
                .checked_add(1)
                .ok_or_else(|| PrivacyError::Invalid("overflow no calendário".into()))?;
            if self.is_business_day(day) {
                remaining -= 1;
            }
        }
        day.checked_mul(SECONDS_PER_DAY)
            .and_then(|base| base.checked_add(seconds_in_day))
            .ok_or_else(|| PrivacyError::Invalid("overflow no prazo".into()))
    }
}

#[derive(Serialize)]
struct DeadlinePolicyDigestMaterial<'a> {
    policy_id: &'a str,
    version: &'a str,
    effective_from: u64,
    authority: &'a str,
    initial_business_days: u16,
    supplementary_business_days: u16,
    legal_basis: &'a str,
    calendar: &'a BusinessCalendar,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlinePolicy {
    pub identity: PolicyIdentity,
    pub authority: String,
    pub initial_business_days: u16,
    pub supplementary_business_days: u16,
    pub legal_basis: String,
    pub calendar: BusinessCalendar,
}

impl DeadlinePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: impl Into<String>,
        version: impl Into<String>,
        effective_from: u64,
        authority: impl Into<String>,
        initial_business_days: u16,
        supplementary_business_days: u16,
        legal_basis: impl Into<String>,
        calendar: BusinessCalendar,
    ) -> Result<Self, PrivacyError> {
        let policy_id = policy_id.into();
        let version = version.into();
        let authority = authority.into();
        let legal_basis = legal_basis.into();
        let digest = deadline_policy_digest(
            &policy_id,
            &version,
            effective_from,
            &authority,
            initial_business_days,
            supplementary_business_days,
            &legal_basis,
            &calendar,
        )?;
        let policy = Self {
            identity: PolicyIdentity {
                policy_id,
                version,
                digest,
                effective_from,
            },
            authority,
            initial_business_days,
            supplementary_business_days,
            legal_basis,
            calendar,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PrivacyError> {
        required("deadline policy_id", &self.identity.policy_id)?;
        required("deadline policy version", &self.identity.version)?;
        required("authority", &self.authority)?;
        required("legal_basis", &self.legal_basis)?;
        self.calendar.validate()?;
        if self.initial_business_days == 0 || self.supplementary_business_days == 0 {
            return Err(PrivacyError::Invalid(
                "prazos inicial e complementar devem ser configurados".into(),
            ));
        }
        let expected = deadline_policy_digest(
            &self.identity.policy_id,
            &self.identity.version,
            self.identity.effective_from,
            &self.authority,
            self.initial_business_days,
            self.supplementary_business_days,
            &self.legal_basis,
            &self.calendar,
        )?;
        if expected != self.identity.digest {
            return Err(PrivacyError::Invalid(
                "digest da política de prazo não corresponde à configuração".into(),
            ));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn deadline_policy_digest(
    policy_id: &str,
    version: &str,
    effective_from: u64,
    authority: &str,
    initial_business_days: u16,
    supplementary_business_days: u16,
    legal_basis: &str,
    calendar: &BusinessCalendar,
) -> Result<[u8; 32], PrivacyError> {
    let material = DeadlinePolicyDigestMaterial {
        policy_id,
        version,
        effective_from,
        authority,
        initial_business_days,
        supplementary_business_days,
        legal_basis,
        calendar,
    };
    Ok(*blake3::hash(&serde_json::to_vec(&material)?).as_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineState {
    Pending,
    DraftReady,
    Submitted,
    SupplementPending,
    Completed,
    Overdue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegulatoryDeadline {
    pub deadline_id: String,
    pub authority: String,
    pub incident_id: String,
    pub triggered_at: u64,
    pub deadline_at: u64,
    pub supplementary_deadline_at: u64,
    pub legal_basis: String,
    pub state: DeadlineState,
    pub policy: PolicyIdentity,
}

impl RegulatoryDeadline {
    pub fn calculate(
        incident_id: impl Into<String>,
        triggered_at: u64,
        policy: &DeadlinePolicy,
    ) -> Result<Self, PrivacyError> {
        policy.validate()?;
        if triggered_at < policy.identity.effective_from {
            return Err(PrivacyError::Invalid(
                "política de prazo ainda não era efetiva no instante do gatilho".into(),
            ));
        }
        let incident_id = incident_id.into();
        required("incident_id", &incident_id)?;
        let deadline_at = policy
            .calendar
            .add_business_days(triggered_at, policy.initial_business_days)?;
        let supplementary_deadline_at = policy
            .calendar
            .add_business_days(triggered_at, policy.supplementary_business_days)?;
        let material = serde_json::to_vec(&(
            &incident_id,
            triggered_at,
            deadline_at,
            supplementary_deadline_at,
            &policy.identity,
        ))?;
        Ok(Self {
            deadline_id: format!("deadline-{}", blake3::hash(&material).to_hex()),
            authority: policy.authority.clone(),
            incident_id,
            triggered_at,
            deadline_at,
            supplementary_deadline_at,
            legal_basis: policy.legal_basis.clone(),
            state: DeadlineState::Pending,
            policy: policy.identity.clone(),
        })
    }

    fn to_episode(&self) -> Result<Episode, PrivacyError> {
        let mut episode = generated_episode(DEADLINE_EVENT, serde_json::to_vec(self)?);
        episode
            .attrs
            .insert("compliance.deadline_id".into(), self.deadline_id.clone());
        episode
            .attrs
            .insert("compliance.incident_id".into(), self.incident_id.clone());
        episode.attrs.insert(
            "compliance.deadline_at".into(),
            self.deadline_at.to_string(),
        );
        Ok(episode)
    }

    pub fn urgency(&self, now_secs: u64) -> DeadlineUrgency {
        if matches!(self.state, DeadlineState::Completed) {
            return DeadlineUrgency::Completed;
        }
        if now_secs > self.deadline_at || matches!(self.state, DeadlineState::Overdue) {
            return DeadlineUrgency::Overdue;
        }
        let remaining = self.deadline_at.saturating_sub(now_secs);
        if remaining <= 24 * 60 * 60 {
            DeadlineUrgency::T24h
        } else if remaining <= 48 * 60 * 60 {
            DeadlineUrgency::T48h
        } else if remaining <= 72 * 60 * 60 {
            DeadlineUrgency::T72h
        } else {
            DeadlineUrgency::Later
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineUrgency {
    Later,
    T72h,
    T48h,
    T24h,
    Overdue,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentPackageData {
    pub summary: String,
    pub affected_assets: Vec<String>,
    pub affected_data: BTreeMap<String, String>,
    pub mitigation_actions: Vec<String>,
    pub timeline: Vec<ComplianceEvidenceRef>,
    pub evidence_anchor_ids: Vec<String>,
}

impl IncidentPackageData {
    fn validate(&self) -> Result<(), PrivacyError> {
        required("incident summary", &self.summary)?;
        for value in self
            .affected_assets
            .iter()
            .chain(self.mitigation_actions.iter())
            .chain(self.evidence_anchor_ids.iter())
        {
            required("package item", value)?;
        }
        for evidence in &self.timeline {
            evidence.validate()?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct PrivacyExportPolicyMaterial<'a> {
    policy_id: &'a str,
    version: &'a str,
    effective_from: u64,
    allowed_json_paths: &'a BTreeSet<String>,
    denied_json_paths: &'a BTreeSet<String>,
}

/// Versioned field policy for the external package. Paths are rooted at the
/// exported documents (`assessment`, `incident`, `affected_data`,
/// `mitigation`, `timeline`). An allowed parent includes its descendants; a
/// denied path always wins and removes that field and all descendants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyExportPolicy {
    pub identity: PolicyIdentity,
    pub allowed_json_paths: BTreeSet<String>,
    pub denied_json_paths: BTreeSet<String>,
}

impl PrivacyExportPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        version: impl Into<String>,
        effective_from: u64,
        allowed_json_paths: BTreeSet<String>,
        denied_json_paths: BTreeSet<String>,
    ) -> Result<Self, PrivacyError> {
        let policy_id = policy_id.into();
        let version = version.into();
        let digest = privacy_export_policy_digest(
            &policy_id,
            &version,
            effective_from,
            &allowed_json_paths,
            &denied_json_paths,
        )?;
        let policy = Self {
            identity: PolicyIdentity {
                policy_id,
                version,
                digest,
                effective_from,
            },
            allowed_json_paths,
            denied_json_paths,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PrivacyError> {
        required("privacy export policy_id", &self.identity.policy_id)?;
        required("privacy export policy version", &self.identity.version)?;
        if self.allowed_json_paths.is_empty() {
            return Err(PrivacyError::Invalid(
                "política de exportação sem campos permitidos".into(),
            ));
        }
        for path in self
            .allowed_json_paths
            .iter()
            .chain(self.denied_json_paths.iter())
        {
            validate_json_path(path)?;
        }
        let expected = privacy_export_policy_digest(
            &self.identity.policy_id,
            &self.identity.version,
            self.identity.effective_from,
            &self.allowed_json_paths,
            &self.denied_json_paths,
        )?;
        if expected != self.identity.digest {
            return Err(PrivacyError::Invalid(
                "digest da política de exportação diverge da configuração".into(),
            ));
        }
        Ok(())
    }

    fn is_denied(&self, path: &str) -> bool {
        self.denied_json_paths
            .iter()
            .any(|denied| path == denied || path.starts_with(&format!("{denied}.")))
    }

    fn is_relevant_or_allowed(&self, path: &str) -> bool {
        self.allowed_json_paths.iter().any(|allowed| {
            path == allowed
                || path.starts_with(&format!("{allowed}."))
                || allowed.starts_with(&format!("{path}."))
        })
    }

    fn permits_value(&self, path: &str) -> bool {
        self.allowed_json_paths
            .iter()
            .any(|allowed| path == allowed || path.starts_with(&format!("{allowed}.")))
    }
}

fn validate_json_path(path: &str) -> Result<(), PrivacyError> {
    required("privacy export JSON path", path)?;
    if path.starts_with('.')
        || path.ends_with('.')
        || path.split('.').any(|part| {
            part.is_empty()
                || !part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        })
    {
        return Err(PrivacyError::Invalid(format!(
            "caminho JSON de exportação inválido: {path}"
        )));
    }
    Ok(())
}

fn privacy_export_policy_digest(
    policy_id: &str,
    version: &str,
    effective_from: u64,
    allowed_json_paths: &BTreeSet<String>,
    denied_json_paths: &BTreeSet<String>,
) -> Result<[u8; 32], PrivacyError> {
    let material = PrivacyExportPolicyMaterial {
        policy_id,
        version,
        effective_from,
        allowed_json_paths,
        denied_json_paths,
    };
    Ok(*blake3::hash(&serde_json::to_vec(&material)?).as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacySanitizationReport {
    pub policy: PolicyIdentity,
    pub included_paths: BTreeSet<String>,
    /// Paths only. Removed values are deliberately never copied to the report.
    pub removed_paths: BTreeSet<String>,
}

fn sanitize_value(
    path: &str,
    value: &serde_json::Value,
    policy: &PrivacyExportPolicy,
    report: &mut PrivacySanitizationReport,
) -> Option<serde_json::Value> {
    if policy.is_denied(path) || !policy.is_relevant_or_allowed(path) {
        report.removed_paths.insert(path.into());
        return None;
    }
    match value {
        serde_json::Value::Object(object) => {
            let mut sanitized = serde_json::Map::new();
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                if let Some(value) = sanitize_value(&child_path, child, policy, report) {
                    sanitized.insert(key.clone(), value);
                }
            }
            Some(serde_json::Value::Object(sanitized))
        }
        serde_json::Value::Array(values) => {
            if !policy.permits_value(path)
                && !policy
                    .allowed_json_paths
                    .iter()
                    .any(|allowed| allowed.starts_with(&format!("{path}.")))
            {
                report.removed_paths.insert(path.into());
                return None;
            }
            let sanitized: Vec<_> = values
                .iter()
                .filter_map(|value| sanitize_value(path, value, policy, report))
                .collect();
            report.included_paths.insert(path.into());
            Some(serde_json::Value::Array(sanitized))
        }
        _ if policy.permits_value(path) => {
            report.included_paths.insert(path.into());
            Some(value.clone())
        }
        _ => {
            report.removed_paths.insert(path.into());
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionState {
    AwaitingHumanAuthorization,
    Authorized,
    Submitted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    pub schema_version: u16,
    pub incident_id: String,
    pub assessment_id: String,
    pub policy: PolicyIdentity,
    pub export_policy: PolicyIdentity,
    pub submission_state: SubmissionState,
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnpdPackageReceipt {
    pub incident_id: String,
    pub package_digest: String,
    pub output_dir: PathBuf,
    pub files: usize,
    pub submission_state: SubmissionState,
}

impl AnpdPackageReceipt {
    fn to_episode(&self) -> Result<Episode, PrivacyError> {
        let mut episode = generated_episode(EXPORT_EVENT, serde_json::to_vec(self)?);
        episode
            .attrs
            .insert("compliance.incident_id".into(), self.incident_id.clone());
        episode.attrs.insert(
            "compliance.package_digest".into(),
            self.package_digest.clone(),
        );
        Ok(episode)
    }
}

pub struct AnpdCommunicationPackage {
    files: BTreeMap<String, Vec<u8>>,
    receipt_digest: String,
    incident_id: String,
}

impl AnpdCommunicationPackage {
    pub fn build(
        assessment: &PrivacyIncidentAssessment,
        deadline: &RegulatoryDeadline,
        data: &IncidentPackageData,
        export_policy: &PrivacyExportPolicy,
    ) -> Result<Self, PrivacyError> {
        assessment.validate()?;
        data.validate()?;
        export_policy.validate()?;
        if assessment.incident_id != deadline.incident_id {
            return Err(PrivacyError::Invalid(
                "assessment e deadline pertencem a incidentes diferentes".into(),
            ));
        }
        let mut sanitization = PrivacySanitizationReport {
            policy: export_policy.identity.clone(),
            included_paths: BTreeSet::new(),
            removed_paths: BTreeSet::new(),
        };
        let assessment_value = sanitize_value(
            "assessment",
            &serde_json::to_value(assessment)?,
            export_policy,
            &mut sanitization,
        )
        .unwrap_or_else(|| serde_json::json!({}));
        let incident_source = serde_json::json!({
            "incident_id": assessment.incident_id,
            "summary": data.summary,
            "affected_assets": data.affected_assets,
            "evidence_anchor_ids": data.evidence_anchor_ids,
        });
        let incident_value = sanitize_value(
            "incident",
            &incident_source,
            export_policy,
            &mut sanitization,
        )
        .unwrap_or_else(|| serde_json::json!({}));
        let affected_data_value = sanitize_value(
            "affected_data",
            &serde_json::to_value(&data.affected_data)?,
            export_policy,
            &mut sanitization,
        )
        .unwrap_or_else(|| serde_json::json!({}));
        let mitigation_value = sanitize_value(
            "mitigation",
            &serde_json::to_value(&data.mitigation_actions)?,
            export_policy,
            &mut sanitization,
        )
        .unwrap_or_else(|| serde_json::json!([]));
        let timeline_value = sanitize_value(
            "timeline",
            &serde_json::to_value(&data.timeline)?,
            export_policy,
            &mut sanitization,
        )
        .unwrap_or_else(|| serde_json::json!([]));

        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files.insert(
            "assessment.json".into(),
            json_file_bytes(&assessment_value)?,
        );
        files.insert("incident.json".into(), json_file_bytes(&incident_value)?);
        files.insert(
            "affected-data.json".into(),
            json_file_bytes(&affected_data_value)?,
        );
        files.insert(
            "mitigation.json".into(),
            json_file_bytes(&mitigation_value)?,
        );
        files.insert("timeline.json".into(), json_file_bytes(&timeline_value)?);
        files.insert(
            "privacy-sanitization.json".into(),
            json_file_bytes(&sanitization)?,
        );

        let safe_summary = incident_value
            .get("summary")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("[conteúdo removido pela política de exportação]");

        let report = format!(
            "# Comunicação de incidente — rascunho\n\n\
             Incidente: {}\n\n\
             Avaliação: {}\n\n\
             Autoridade: {}\n\n\
             Prazo calculado: {}\n\n\
             Estado: aguardando autorização humana.\n\n\
             ## Resumo\n\n{}\n",
            assessment.incident_id,
            assessment.assessment_id,
            deadline.authority,
            deadline.deadline_at,
            safe_summary
        );
        files.insert("report.md".into(), report.into_bytes());

        let file_digests: BTreeMap<_, _> = files
            .iter()
            .map(|(name, bytes)| (name.clone(), blake3::hash(bytes).to_hex().to_string()))
            .collect();
        let manifest = PackageManifest {
            schema_version: 1,
            incident_id: assessment.incident_id.clone(),
            assessment_id: assessment.assessment_id.clone(),
            policy: assessment.policy.clone(),
            export_policy: export_policy.identity.clone(),
            submission_state: SubmissionState::AwaitingHumanAuthorization,
            files: file_digests,
        };
        files.insert("evidence-manifest.json".into(), json_file_bytes(&manifest)?);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"heraclitus/anpd-package/v1\0");
        for (name, bytes) in &files {
            hasher.update(&(name.len() as u64).to_le_bytes());
            hasher.update(name.as_bytes());
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        Ok(Self {
            files,
            receipt_digest: format!("blake3:{}", hasher.finalize().to_hex()),
            incident_id: assessment.incident_id.clone(),
        })
    }

    pub fn write_to(
        &self,
        output_dir: impl AsRef<Path>,
    ) -> Result<AnpdPackageReceipt, PrivacyError> {
        let output_dir = output_dir.as_ref();
        if output_dir.exists() {
            self.verify_existing(output_dir)?;
        } else {
            std::fs::create_dir_all(output_dir)?;
            for (name, bytes) in &self.files {
                std::fs::write(output_dir.join(name), bytes)?;
            }
        }
        Ok(AnpdPackageReceipt {
            incident_id: self.incident_id.clone(),
            package_digest: self.receipt_digest.clone(),
            output_dir: output_dir.to_path_buf(),
            files: self.files.len(),
            submission_state: SubmissionState::AwaitingHumanAuthorization,
        })
    }

    fn verify_existing(&self, output_dir: &Path) -> Result<(), PrivacyError> {
        for (name, expected) in &self.files {
            let path = output_dir.join(name);
            let actual = std::fs::read(&path).map_err(|error| {
                PrivacyError::Invalid(format!(
                    "pacote existente incompleto em {}: {error}",
                    path.display()
                ))
            })?;
            if &actual != expected {
                return Err(PrivacyError::Invalid(format!(
                    "pacote existente diverge em {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }
}

fn json_file_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, PrivacyError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Separate object by construction: an RIPD appendix is not an incident
/// communication package and cannot be passed to the ANPD package writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RipdEvidenceAppendix {
    pub treatment_process_id: String,
    pub evidence: Vec<ComplianceEvidenceRef>,
    pub generated_at_lsn: Lsn,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivacyState {
    pub assessments: Vec<(Lsn, PrivacyIncidentAssessment)>,
    pub deadlines: Vec<(Lsn, RegulatoryDeadline)>,
    pub exports: Vec<(Lsn, AnpdPackageReceipt)>,
}

impl PrivacyState {
    pub fn replay<L: EpisodeLog + ?Sized>(log: &L, as_of_lsn: Lsn) -> Result<Self, PrivacyError> {
        let end = log.head().min(as_of_lsn.saturating_add(1));
        let rows = log
            .scan(0, end)
            .map_err(|error| PrivacyError::Storage(error.to_string()))?;
        let mut state = Self::default();
        for (lsn, episode) in rows {
            if episode
                .attrs
                .get("compliance.generated")
                .map(String::as_str)
                != Some("true")
            {
                continue;
            }
            match episode.kind.label().as_str() {
                ASSESSMENT_EVENT => {
                    let value: PrivacyIncidentAssessment =
                        serde_json::from_slice(&episode.content)?;
                    value.validate()?;
                    state.assessments.push((lsn, value));
                }
                DEADLINE_EVENT => state
                    .deadlines
                    .push((lsn, serde_json::from_slice(&episode.content)?)),
                EXPORT_EVENT => state
                    .exports
                    .push((lsn, serde_json::from_slice(&episode.content)?)),
                _ => {}
            }
        }
        Ok(state)
    }
}

#[derive(Clone)]
pub struct PrivacyIncidentEngine {
    log: Arc<AnyLog>,
}

impl PrivacyIncidentEngine {
    pub fn new(log: Arc<AnyLog>) -> Self {
        Self { log }
    }

    pub fn state(&self) -> Result<PrivacyState, PrivacyError> {
        PrivacyState::replay(self.log.as_ref(), self.log.head())
    }

    pub fn persist_assessment(
        &self,
        assessment: PrivacyIncidentAssessment,
    ) -> Result<Lsn, PrivacyError> {
        assessment.validate()?;
        let state = self.state()?;
        if let Some((lsn, existing)) = state
            .assessments
            .iter()
            .find(|(_, value)| value.assessment_id == assessment.assessment_id)
        {
            if existing == &assessment {
                return Ok(*lsn);
            }
            return Err(PrivacyError::Invalid(format!(
                "assessment_id já utilizado: {}",
                assessment.assessment_id
            )));
        }
        self.log
            .append(assessment.to_episode()?)
            .map_err(|error| PrivacyError::Storage(error.to_string()))
    }

    pub fn calculate_and_persist_deadline(
        &self,
        incident_id: impl Into<String>,
        triggered_at: u64,
        policy: &DeadlinePolicy,
    ) -> Result<(Lsn, RegulatoryDeadline), PrivacyError> {
        let deadline = RegulatoryDeadline::calculate(incident_id, triggered_at, policy)?;
        let state = self.state()?;
        if let Some((lsn, existing)) = state
            .deadlines
            .iter()
            .find(|(_, value)| value.deadline_id == deadline.deadline_id)
        {
            return Ok((*lsn, existing.clone()));
        }
        let lsn = self
            .log
            .append(deadline.to_episode()?)
            .map_err(|error| PrivacyError::Storage(error.to_string()))?;
        Ok((lsn, deadline))
    }

    pub fn generate_package(
        &self,
        assessment: &PrivacyIncidentAssessment,
        deadline: &RegulatoryDeadline,
        data: &IncidentPackageData,
        export_policy: &PrivacyExportPolicy,
        output_dir: impl AsRef<Path>,
    ) -> Result<(Lsn, AnpdPackageReceipt), PrivacyError> {
        let package = AnpdCommunicationPackage::build(assessment, deadline, data, export_policy)?;
        let receipt = package.write_to(output_dir)?;
        let state = self.state()?;
        if let Some((lsn, existing)) = state
            .exports
            .iter()
            .find(|(_, value)| value.package_digest == receipt.package_digest)
        {
            return Ok((*lsn, existing.clone()));
        }
        let lsn = self
            .log
            .append(receipt.to_episode()?)
            .map_err(|error| PrivacyError::Storage(error.to_string()))?;
        Ok((lsn, receipt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{FsyncPolicy, StorageFormat};

    fn identity() -> PolicyIdentity {
        PolicyIdentity {
            policy_id: "anpd-incident-policy".into(),
            version: "2026.1".into(),
            digest: [7; 32],
            effective_from: 0,
        }
    }

    fn assessment() -> PrivacyIncidentAssessment {
        PrivacyIncidentAssessment {
            assessment_id: "assessment-1".into(),
            incident_id: "incident-1".into(),
            personal_data_involved: true,
            categories: vec!["contact".into(), "credential".into()],
            estimated_subjects: Some(42),
            vulnerable_subjects: false,
            sensitive_data: false,
            estimated_risk: RiskLevel::High,
            evidence: vec![ComplianceEvidenceRef {
                lsn: 0,
                event_id: EventId::new(),
                relation: "source incident".into(),
            }],
            assessed_by: "privacy-officer".into(),
            assessed_at_lsn: 1,
            policy: identity(),
        }
    }

    fn deadline_policy(calendar: BusinessCalendar) -> DeadlinePolicy {
        DeadlinePolicy::new(
            "anpd-deadline",
            "resolution-15-2024/v1",
            0,
            "ANPD",
            3,
            20,
            "Resolução CD/ANPD 15/2024",
            calendar,
        )
        .unwrap()
    }

    fn export_policy() -> PrivacyExportPolicy {
        PrivacyExportPolicy::new(
            "anpd-export",
            "2026.1",
            0,
            [
                "assessment".into(),
                "incident".into(),
                "affected_data".into(),
                "mitigation".into(),
                "timeline".into(),
            ]
            .into_iter()
            .collect(),
            BTreeSet::new(),
        )
        .unwrap()
    }

    #[test]
    fn business_days_skip_weekend_and_configured_holiday() {
        // 1970-01-01 Thursday. Friday is a configured holiday, then weekend;
        // one business day lands on Monday (day 4).
        let calendar = BusinessCalendar {
            holidays_utc_days: [1].into_iter().collect(),
            ..BusinessCalendar::default()
        };
        assert_eq!(
            calendar.add_business_days(0, 1).unwrap(),
            4 * SECONDS_PER_DAY
        );
    }

    #[test]
    fn deadline_records_policy_version_and_urgency() {
        let policy = deadline_policy(BusinessCalendar::default());
        let deadline = RegulatoryDeadline::calculate("incident-1", 0, &policy).unwrap();
        // Thu + Fri + Mon + Tue = day 5.
        assert_eq!(deadline.deadline_at, 5 * SECONDS_PER_DAY);
        assert_eq!(deadline.policy.digest, policy.identity.digest);
        assert_eq!(
            deadline.urgency(deadline.deadline_at - 24 * 60 * 60),
            DeadlineUrgency::T24h
        );
        assert_eq!(
            deadline.urgency(deadline.deadline_at + 1),
            DeadlineUrgency::Overdue
        );
    }

    #[test]
    fn package_is_deterministic_retryable_and_requires_human_authorization() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("anpd-package");
        let assessment = assessment();
        let deadline = RegulatoryDeadline::calculate(
            "incident-1",
            0,
            &deadline_policy(BusinessCalendar::default()),
        )
        .unwrap();
        let data = IncidentPackageData {
            summary: "credential disclosure under investigation".into(),
            affected_assets: vec!["portal".into()],
            affected_data: [("category".into(), "credential".into())]
                .into_iter()
                .collect(),
            mitigation_actions: vec!["credential rotation".into()],
            timeline: assessment.evidence.clone(),
            evidence_anchor_ids: vec!["anchor-1".into()],
        };
        let package =
            AnpdCommunicationPackage::build(&assessment, &deadline, &data, &export_policy())
                .unwrap();
        let first = package.write_to(&output).unwrap();
        let retry = package.write_to(&output).unwrap();
        assert_eq!(first, retry);
        assert_eq!(first.files, 8);
        assert_eq!(
            first.submission_state,
            SubmissionState::AwaitingHumanAuthorization
        );
        assert!(output.join("evidence-manifest.json").is_file());
        assert!(output.join("report.md").is_file());
    }

    #[test]
    fn privacy_export_removes_denied_fields_before_writing() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("sanitized-package");
        let assessment = assessment();
        let deadline = RegulatoryDeadline::calculate(
            "incident-1",
            0,
            &deadline_policy(BusinessCalendar::default()),
        )
        .unwrap();
        let data = IncidentPackageData {
            summary: "safe summary".into(),
            affected_assets: vec!["portal".into()],
            affected_data: [
                ("category".into(), "credential".into()),
                ("cpf".into(), "000.000.000-00".into()),
            ]
            .into_iter()
            .collect(),
            mitigation_actions: vec!["rotation".into()],
            timeline: assessment.evidence.clone(),
            evidence_anchor_ids: vec![],
        };
        let policy = PrivacyExportPolicy::new(
            "anpd-export",
            "2026.2",
            0,
            [
                "assessment".into(),
                "incident".into(),
                "affected_data".into(),
                "mitigation".into(),
                "timeline".into(),
            ]
            .into_iter()
            .collect(),
            ["assessment.assessed_by".into(), "affected_data.cpf".into()]
                .into_iter()
                .collect(),
        )
        .unwrap();
        AnpdCommunicationPackage::build(&assessment, &deadline, &data, &policy)
            .unwrap()
            .write_to(&output)
            .unwrap();

        let assessment_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join("assessment.json")).unwrap())
                .unwrap();
        let affected_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join("affected-data.json")).unwrap())
                .unwrap();
        let sanitization: PrivacySanitizationReport = serde_json::from_slice(
            &std::fs::read(output.join("privacy-sanitization.json")).unwrap(),
        )
        .unwrap();
        assert!(assessment_json.get("assessed_by").is_none());
        assert!(affected_json.get("cpf").is_none());
        assert_eq!(affected_json["category"], "credential");
        assert!(sanitization
            .removed_paths
            .contains("assessment.assessed_by"));
        assert!(sanitization.removed_paths.contains("affected_data.cpf"));
        let all_files = std::fs::read_dir(&output)
            .unwrap()
            .flat_map(|entry| std::fs::read(entry.unwrap().path()).unwrap())
            .collect::<Vec<_>>();
        assert!(!String::from_utf8_lossy(&all_files).contains("000.000.000-00"));
    }

    #[test]
    fn privacy_events_replay_without_duplicate_outputs() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(
                StorageFormat::V6,
                temp.path().join("log"),
                1024,
                FsyncPolicy::Always,
            )
            .unwrap(),
        );
        let engine = PrivacyIncidentEngine::new(log.clone());
        let assessment = assessment();
        let assessment_lsn = engine.persist_assessment(assessment.clone()).unwrap();
        assert_eq!(
            engine.persist_assessment(assessment.clone()).unwrap(),
            assessment_lsn
        );
        let (_, deadline) = engine
            .calculate_and_persist_deadline(
                "incident-1",
                0,
                &deadline_policy(BusinessCalendar::default()),
            )
            .unwrap();
        let data = IncidentPackageData {
            summary: "incident summary".into(),
            affected_assets: vec![],
            affected_data: BTreeMap::new(),
            mitigation_actions: vec![],
            timeline: assessment.evidence.clone(),
            evidence_anchor_ids: vec![],
        };
        let output = temp.path().join("export");
        let (export_lsn, _) = engine
            .generate_package(&assessment, &deadline, &data, &export_policy(), &output)
            .unwrap();
        assert_eq!(
            engine
                .generate_package(&assessment, &deadline, &data, &export_policy(), &output)
                .unwrap()
                .0,
            export_lsn
        );
        let state = PrivacyState::replay(log.as_ref(), log.head()).unwrap();
        assert_eq!(state.assessments.len(), 1);
        assert_eq!(state.deadlines.len(), 1);
        assert_eq!(state.exports.len(), 1);
    }

    #[test]
    fn ripd_is_a_distinct_type_from_incident_communication() {
        let appendix = RipdEvidenceAppendix {
            treatment_process_id: "treatment-1".into(),
            evidence: assessment().evidence,
            generated_at_lsn: 7,
        };
        let json = serde_json::to_value(appendix).unwrap();
        assert!(json.get("treatment_process_id").is_some());
        assert!(json.get("incident_id").is_none());
    }
}
