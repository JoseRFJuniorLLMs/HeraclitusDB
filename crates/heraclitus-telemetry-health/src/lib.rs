//! Telemetry Health / Sensor Trust (SPEC-0071 §6, SPEC-0062).
//!
//! The immutable log remains the source of truth. This crate defines the wire
//! events emitted by collectors and a deterministic materialized view. A
//! sensor becomes `Silent` only when recorded event-time crosses its cadence;
//! querying the wall clock never mutates or changes historical answers.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use heraclitus_core::{Episode, EventKind, HeraclitusError, Lsn};
use heraclitus_views::View;
use serde::{Deserialize, Serialize};

pub const TELEMETRY_HEALTH_SCHEMA: &str = "heraclitus-telemetry-health/1.0";
pub const TELEMETRY_HEALTH_KIND: &str = "TelemetryHealth";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SensorIdentity {
    pub tenant_id: String,
    pub datasource_id: String,
    pub sensor_id: String,
}

impl SensorIdentity {
    pub fn new(
        tenant_id: impl Into<String>,
        datasource_id: impl Into<String>,
        sensor_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            datasource_id: datasource_id.into(),
            sensor_id: sensor_id.into(),
        }
    }

    fn validate(&self) -> Result<(), HeraclitusError> {
        for (name, value) in [
            ("tenant_id", &self.tenant_id),
            ("datasource_id", &self.datasource_id),
            ("sensor_id", &self.sensor_id),
        ] {
            if value.trim().is_empty() {
                return Err(HeraclitusError::Config(format!(
                    "telemetry health requer {name} nao vazio"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryHealthEnvelope {
    pub schema: String,
    pub identity: SensorIdentity,
    /// Event time supplied by the authenticated sensor/collector.
    pub emitted_at_micros: u64,
    pub event: TelemetryHealthEvent,
}

impl TelemetryHealthEnvelope {
    pub fn new(
        identity: SensorIdentity,
        emitted_at_micros: u64,
        event: TelemetryHealthEvent,
    ) -> Self {
        Self {
            schema: TELEMETRY_HEALTH_SCHEMA.into(),
            identity,
            emitted_at_micros,
            event,
        }
    }

    pub fn validate(&self) -> Result<(), HeraclitusError> {
        if self.schema != TELEMETRY_HEALTH_SCHEMA {
            return Err(HeraclitusError::Config(format!(
                "schema de telemetry health nao suportado: {}",
                self.schema
            )));
        }
        self.identity.validate()?;
        self.event.validate()
    }

    pub fn to_episode(&self) -> Result<Episode, HeraclitusError> {
        self.validate()?;
        let content = serde_json::to_vec(self)
            .map_err(|error| HeraclitusError::Serialization(error.to_string()))?;
        let mut episode = Episode::new(
            "heraclitus-forge",
            EventKind::Custom(TELEMETRY_HEALTH_KIND.into()),
            content,
        );
        episode
            .attrs
            .insert("telemetry.schema".into(), self.schema.clone());
        episode
            .attrs
            .insert("tenant_id".into(), self.identity.tenant_id.clone());
        episode
            .attrs
            .insert("datasource_id".into(), self.identity.datasource_id.clone());
        episode
            .attrs
            .insert("sensor_id".into(), self.identity.sensor_id.clone());
        episode.attrs.insert(
            "telemetry.event_type".into(),
            self.event.event_type().into(),
        );
        Ok(episode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum TelemetryHealthEvent {
    ExpectationConfigured(ExpectationConfigured),
    SensorHeartbeat(SensorHeartbeat),
    IngestionWindowClosed(IngestionWindowClosed),
    TelemetryDropRecorded(TelemetryDropRecorded),
    SchemaDriftObserved(SchemaDriftObserved),
    ParserFailureObserved(ParserFailureObserved),
    CheckpointAdvanced(CheckpointAdvanced),
    ConnectorActivated(ConnectorActivated),
    ConnectorRejected(ConnectorRejected),
    SensorClockSkewObserved(SensorClockSkewObserved),
    /// Explicit event-time barrier used to derive silence without wall-clock reads.
    HealthEvaluationTick(HealthEvaluationTick),
}

impl TelemetryHealthEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::ExpectationConfigured(_) => "ExpectationConfigured",
            Self::SensorHeartbeat(_) => "SensorHeartbeat",
            Self::IngestionWindowClosed(_) => "IngestionWindowClosed",
            Self::TelemetryDropRecorded(_) => "TelemetryDropRecorded",
            Self::SchemaDriftObserved(_) => "SchemaDriftObserved",
            Self::ParserFailureObserved(_) => "ParserFailureObserved",
            Self::CheckpointAdvanced(_) => "CheckpointAdvanced",
            Self::ConnectorActivated(_) => "ConnectorActivated",
            Self::ConnectorRejected(_) => "ConnectorRejected",
            Self::SensorClockSkewObserved(_) => "SensorClockSkewObserved",
            Self::HealthEvaluationTick(_) => "HealthEvaluationTick",
        }
    }

    fn validate(&self) -> Result<(), HeraclitusError> {
        match self {
            Self::ExpectationConfigured(value) => value.validate(),
            Self::IngestionWindowClosed(value) => value.validate(),
            Self::ConnectorActivated(value) => validate_digest(&value.connector_digest),
            Self::ConnectorRejected(value) => value
                .connector_digest
                .as_deref()
                .map_or(Ok(()), validate_digest),
            Self::CheckpointAdvanced(value) => value.validate(),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectationConfigured {
    pub heartbeat_cadence_micros: Option<u64>,
    pub max_lateness_micros: u64,
    pub minimum_events_per_window: Option<u64>,
    /// Duplicate share at or above this threshold is a storm (0..=10_000).
    pub duplicate_storm_basis_points: u16,
}

impl ExpectationConfigured {
    fn validate(&self) -> Result<(), HeraclitusError> {
        if self.heartbeat_cadence_micros == Some(0) {
            return Err(HeraclitusError::Config(
                "heartbeat_cadence_micros deve ser maior que zero".into(),
            ));
        }
        if self.duplicate_storm_basis_points > 10_000 {
            return Err(HeraclitusError::Config(
                "duplicate_storm_basis_points deve estar em 0..=10000".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorHeartbeat {
    pub observed_at_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestionWindowClosed {
    pub window_start_micros: u64,
    pub window_end_micros: u64,
    pub received: u64,
    pub parsed: u64,
    pub normalized: u64,
    pub duplicated: u64,
    pub dropped: u64,
    pub quarantined: u64,
    pub parser_errors: u64,
    pub max_observed_lateness_millis: u64,
    pub connector_digest: String,
}

impl IngestionWindowClosed {
    fn validate(&self) -> Result<(), HeraclitusError> {
        if self.window_end_micros < self.window_start_micros {
            return Err(HeraclitusError::Config(
                "janela de ingestao termina antes de iniciar".into(),
            ));
        }
        if self.normalized > self.parsed || self.parsed > self.received {
            return Err(HeraclitusError::Config(
                "contadores requerem normalized <= parsed <= received".into(),
            ));
        }
        validate_digest(&self.connector_digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryDropRecorded {
    pub count: u64,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaDriftObserved {
    pub count: u64,
    pub field: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserFailureObserved {
    pub count: u64,
    pub reason_code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointIntegrity {
    Unknown,
    Verified,
    Divergent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointAdvanced {
    pub source_sequence: Option<u64>,
    pub source_watermark: Option<String>,
    pub integrity: CheckpointIntegrity,
}

impl CheckpointAdvanced {
    fn validate(&self) -> Result<(), HeraclitusError> {
        if self.source_sequence.is_none() && self.source_watermark.is_none() {
            return Err(HeraclitusError::Config(
                "checkpoint requer source_sequence ou source_watermark".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorActivated {
    pub connector_digest: String,
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorRejected {
    pub connector_digest: Option<String>,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorClockSkewObserved {
    pub absolute_skew_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthEvaluationTick {
    pub evaluated_at_micros: u64,
}

fn validate_digest(value: &str) -> Result<(), HeraclitusError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HeraclitusError::Config(
            "connector_digest deve ter 32 bytes hexadecimais".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageStatus {
    Unknown,
    Covered,
    Partial,
    Uncovered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreshnessStatus {
    Unknown,
    Starting,
    Healthy,
    Delayed,
    Silent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompletenessStatus {
    Unknown,
    Starting,
    Complete,
    Gap,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    #[default]
    Unknown,
    Trusted,
    Degraded,
    Tampered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustStatus {
    Unknown,
    Trusted,
    Degraded,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivityStatus {
    Unknown,
    Active,
    Quiet,
    Silent,
}

/// Coarse operational state for alerting and dashboards. The dimensional
/// fields remain authoritative when a caller needs the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensorHealthStatus {
    Unknown,
    Healthy,
    Delayed,
    Silent,
    Drifted,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dimension<T> {
    pub status: T,
    pub basis_points: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HealthFindingKind {
    SensorSilent,
    EventGap,
    SchemaDrift,
    ParserFailure,
    TelemetryDropped,
    ClockSkew,
    DuplicateStorm,
    IntegrityTamper,
    ConnectorRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthFinding {
    pub kind: HealthFindingKind,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub occurrences: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCounters {
    pub received: u64,
    pub parsed: u64,
    pub normalized: u64,
    pub duplicated: u64,
    pub dropped: u64,
    pub quarantined: u64,
    pub parser_errors: u64,
    pub schema_drift: u64,
    pub sequence_gaps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryHealthSnapshot {
    pub identity: SensorIdentity,
    /// Exclusive bound, matching HeraclitusDB `AS OF LSN n` semantics.
    pub as_of_lsn: Lsn,
    pub status: SensorHealthStatus,
    pub activity: ActivityStatus,
    pub coverage: Dimension<CoverageStatus>,
    pub freshness: Dimension<FreshnessStatus>,
    pub completeness: Dimension<CompletenessStatus>,
    pub integrity: Dimension<IntegrityStatus>,
    pub trust: Dimension<TrustStatus>,
    pub connector_digest: Option<String>,
    pub last_heartbeat_micros: Option<u64>,
    pub last_window_end_micros: Option<u64>,
    pub counters: HealthCounters,
    pub findings: Vec<HealthFinding>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ReducedSensor {
    expectation: Option<(ExpectationConfigured, u64)>,
    connector_digest: Option<String>,
    connector_approved: Option<bool>,
    last_heartbeat_micros: Option<u64>,
    last_window_end_micros: Option<u64>,
    last_window_received: Option<u64>,
    last_sequence: Option<u64>,
    evaluation_micros: u64,
    counters: HealthCounters,
    findings: BTreeMap<HealthFindingKind, HealthFinding>,
    integrity: IntegrityStatus,
    clock_skew_observed: bool,
}

impl ReducedSensor {
    fn finding(&mut self, kind: HealthFindingKind, lsn: Lsn, count: u64) {
        if count == 0 {
            return;
        }
        self.findings
            .entry(kind)
            .and_modify(|finding| {
                finding.last_lsn = lsn;
                finding.occurrences = finding.occurrences.saturating_add(count);
            })
            .or_insert(HealthFinding {
                kind,
                first_lsn: lsn,
                last_lsn: lsn,
                occurrences: count,
            });
    }

    fn apply(&mut self, lsn: Lsn, envelope: &TelemetryHealthEnvelope) {
        self.evaluation_micros = self.evaluation_micros.max(envelope.emitted_at_micros);
        match &envelope.event {
            TelemetryHealthEvent::ExpectationConfigured(value) => {
                self.expectation = Some((value.clone(), envelope.emitted_at_micros));
            }
            TelemetryHealthEvent::SensorHeartbeat(value) => {
                self.last_heartbeat_micros = Some(
                    self.last_heartbeat_micros
                        .unwrap_or(0)
                        .max(value.observed_at_micros),
                );
            }
            TelemetryHealthEvent::IngestionWindowClosed(value) => {
                if self
                    .connector_digest
                    .as_ref()
                    .is_some_and(|digest| digest != &value.connector_digest)
                {
                    self.integrity = IntegrityStatus::Tampered;
                    self.finding(HealthFindingKind::IntegrityTamper, lsn, 1);
                }
                self.last_window_end_micros = Some(
                    self.last_window_end_micros
                        .unwrap_or(0)
                        .max(value.window_end_micros),
                );
                self.last_window_received = Some(value.received);
                self.counters.received = self.counters.received.saturating_add(value.received);
                self.counters.parsed = self.counters.parsed.saturating_add(value.parsed);
                self.counters.normalized =
                    self.counters.normalized.saturating_add(value.normalized);
                self.counters.duplicated =
                    self.counters.duplicated.saturating_add(value.duplicated);
                self.counters.dropped = self.counters.dropped.saturating_add(value.dropped);
                self.counters.quarantined =
                    self.counters.quarantined.saturating_add(value.quarantined);
                self.counters.parser_errors = self
                    .counters
                    .parser_errors
                    .saturating_add(value.parser_errors);
                if value.parser_errors > 0 {
                    self.finding(HealthFindingKind::ParserFailure, lsn, value.parser_errors);
                }
                if value.dropped > 0 {
                    self.finding(HealthFindingKind::TelemetryDropped, lsn, value.dropped);
                }
                if let Some((expectation, _)) = &self.expectation {
                    let duplicate_bp = ratio_basis_points(value.duplicated, value.received);
                    if duplicate_bp >= expectation.duplicate_storm_basis_points
                        && value.duplicated > 0
                    {
                        self.finding(HealthFindingKind::DuplicateStorm, lsn, value.duplicated);
                    }
                }
            }
            TelemetryHealthEvent::TelemetryDropRecorded(value) => {
                self.counters.dropped = self.counters.dropped.saturating_add(value.count);
                self.finding(HealthFindingKind::TelemetryDropped, lsn, value.count);
            }
            TelemetryHealthEvent::SchemaDriftObserved(value) => {
                self.counters.schema_drift = self.counters.schema_drift.saturating_add(value.count);
                self.finding(HealthFindingKind::SchemaDrift, lsn, value.count);
            }
            TelemetryHealthEvent::ParserFailureObserved(value) => {
                self.counters.parser_errors =
                    self.counters.parser_errors.saturating_add(value.count);
                self.finding(HealthFindingKind::ParserFailure, lsn, value.count);
            }
            TelemetryHealthEvent::CheckpointAdvanced(value) => {
                if let Some(sequence) = value.source_sequence {
                    if let Some(previous) = self.last_sequence {
                        if sequence > previous.saturating_add(1) {
                            let gap = sequence - previous - 1;
                            self.counters.sequence_gaps =
                                self.counters.sequence_gaps.saturating_add(gap);
                            self.finding(HealthFindingKind::EventGap, lsn, gap);
                        }
                    }
                    self.last_sequence = Some(self.last_sequence.unwrap_or(0).max(sequence));
                }
                match value.integrity {
                    CheckpointIntegrity::Verified
                        if self.integrity != IntegrityStatus::Tampered =>
                    {
                        self.integrity = IntegrityStatus::Trusted;
                    }
                    CheckpointIntegrity::Divergent => {
                        self.integrity = IntegrityStatus::Tampered;
                        self.finding(HealthFindingKind::IntegrityTamper, lsn, 1);
                    }
                    _ => {}
                }
            }
            TelemetryHealthEvent::ConnectorActivated(value) => {
                self.connector_digest = Some(value.connector_digest.clone());
                self.connector_approved = Some(value.approved);
                if value.approved && self.integrity == IntegrityStatus::Unknown {
                    self.integrity = IntegrityStatus::Trusted;
                }
            }
            TelemetryHealthEvent::ConnectorRejected(value) => {
                self.connector_digest = value.connector_digest.clone();
                self.connector_approved = Some(false);
                self.integrity = IntegrityStatus::Degraded;
                self.finding(HealthFindingKind::ConnectorRejected, lsn, 1);
            }
            TelemetryHealthEvent::SensorClockSkewObserved(_) => {
                self.clock_skew_observed = true;
                self.finding(HealthFindingKind::ClockSkew, lsn, 1);
            }
            TelemetryHealthEvent::HealthEvaluationTick(value) => {
                self.evaluation_micros = self.evaluation_micros.max(value.evaluated_at_micros);
            }
        }
    }

    fn snapshot(&self, identity: SensorIdentity, as_of_lsn: Lsn) -> TelemetryHealthSnapshot {
        let coverage = self.coverage();
        let freshness = self.freshness();
        let completeness = self.completeness();
        let integrity = Dimension {
            status: self.integrity,
            basis_points: match self.integrity {
                IntegrityStatus::Unknown => None,
                IntegrityStatus::Trusted => Some(10_000),
                IntegrityStatus::Degraded => Some(5_000),
                IntegrityStatus::Tampered => Some(0),
            },
        };
        let trust = combine_trust(coverage, freshness, completeness, integrity);
        let status = if integrity.status == IntegrityStatus::Tampered
            || coverage.status == CoverageStatus::Uncovered
            || completeness.status == CompletenessStatus::Gap
        {
            SensorHealthStatus::Degraded
        } else if self.findings.contains_key(&HealthFindingKind::SchemaDrift) {
            SensorHealthStatus::Drifted
        } else {
            match freshness.status {
                FreshnessStatus::Silent => SensorHealthStatus::Silent,
                FreshnessStatus::Delayed => SensorHealthStatus::Delayed,
                FreshnessStatus::Unknown | FreshnessStatus::Starting => SensorHealthStatus::Unknown,
                FreshnessStatus::Healthy if trust.status == TrustStatus::Trusted => {
                    SensorHealthStatus::Healthy
                }
                FreshnessStatus::Healthy => SensorHealthStatus::Degraded,
            }
        };
        let activity = match freshness.status {
            FreshnessStatus::Silent => ActivityStatus::Silent,
            _ if self.last_window_received == Some(0)
                && freshness.status == FreshnessStatus::Healthy =>
            {
                ActivityStatus::Quiet
            }
            _ if self.last_window_received.is_some_and(|count| count > 0) => ActivityStatus::Active,
            _ => ActivityStatus::Unknown,
        };

        TelemetryHealthSnapshot {
            identity,
            as_of_lsn,
            status,
            activity,
            coverage,
            freshness,
            completeness,
            integrity,
            trust,
            connector_digest: self.connector_digest.clone(),
            last_heartbeat_micros: self.last_heartbeat_micros,
            last_window_end_micros: self.last_window_end_micros,
            counters: self.counters.clone(),
            findings: self.findings.values().cloned().collect(),
        }
    }

    fn coverage(&self) -> Dimension<CoverageStatus> {
        match self.connector_approved {
            None => Dimension {
                status: CoverageStatus::Unknown,
                basis_points: None,
            },
            Some(false) => Dimension {
                status: CoverageStatus::Uncovered,
                basis_points: Some(0),
            },
            Some(true) => {
                let denominator = self
                    .counters
                    .received
                    .saturating_add(self.counters.schema_drift)
                    .saturating_add(self.counters.parser_errors);
                let score = if denominator == 0 {
                    10_000
                } else {
                    ratio_basis_points(self.counters.normalized, denominator)
                };
                Dimension {
                    status: if score == 10_000 {
                        CoverageStatus::Covered
                    } else {
                        CoverageStatus::Partial
                    },
                    basis_points: Some(score),
                }
            }
        }
    }

    fn freshness(&self) -> Dimension<FreshnessStatus> {
        let Some((expectation, configured_at)) = &self.expectation else {
            return Dimension {
                status: FreshnessStatus::Unknown,
                basis_points: None,
            };
        };
        let Some(cadence) = expectation.heartbeat_cadence_micros else {
            return Dimension {
                status: FreshnessStatus::Unknown,
                basis_points: None,
            };
        };
        let reference = self.last_heartbeat_micros.unwrap_or(*configured_at);
        let age = self.evaluation_micros.saturating_sub(reference);
        let (mut status, mut score) = if self.last_heartbeat_micros.is_none() && age <= cadence {
            (FreshnessStatus::Starting, 10_000)
        } else if age <= cadence {
            (FreshnessStatus::Healthy, 10_000)
        } else if age <= cadence.saturating_add(expectation.max_lateness_micros) {
            (FreshnessStatus::Delayed, 5_000)
        } else {
            (FreshnessStatus::Silent, 0)
        };
        if self.clock_skew_observed
            && matches!(status, FreshnessStatus::Healthy | FreshnessStatus::Starting)
        {
            status = FreshnessStatus::Delayed;
            score = 5_000;
        }
        Dimension {
            status,
            basis_points: Some(score),
        }
    }

    fn completeness(&self) -> Dimension<CompletenessStatus> {
        let Some((expectation, _)) = &self.expectation else {
            return Dimension {
                status: CompletenessStatus::Unknown,
                basis_points: None,
            };
        };
        if self.counters.sequence_gaps > 0
            || self
                .findings
                .contains_key(&HealthFindingKind::DuplicateStorm)
        {
            return Dimension {
                status: CompletenessStatus::Gap,
                basis_points: Some(0),
            };
        }
        match (
            expectation.minimum_events_per_window,
            self.last_window_received,
        ) {
            (None, _) => Dimension {
                status: CompletenessStatus::Unknown,
                basis_points: None,
            },
            (Some(_), None) => Dimension {
                status: CompletenessStatus::Starting,
                basis_points: None,
            },
            (Some(minimum), Some(received)) if received < minimum => Dimension {
                status: CompletenessStatus::Gap,
                basis_points: Some(ratio_basis_points(received, minimum)),
            },
            (Some(_), Some(_)) => Dimension {
                status: CompletenessStatus::Complete,
                basis_points: Some(10_000),
            },
        }
    }
}

fn ratio_basis_points(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let value = u128::from(numerator)
        .saturating_mul(10_000)
        .checked_div(u128::from(denominator))
        .unwrap_or(0)
        .min(10_000);
    value as u16
}

fn combine_trust(
    coverage: Dimension<CoverageStatus>,
    freshness: Dimension<FreshnessStatus>,
    completeness: Dimension<CompletenessStatus>,
    integrity: Dimension<IntegrityStatus>,
) -> Dimension<TrustStatus> {
    if integrity.status == IntegrityStatus::Tampered || coverage.status == CoverageStatus::Uncovered
    {
        return Dimension {
            status: TrustStatus::Untrusted,
            basis_points: Some(0),
        };
    }
    let scores = [
        coverage.basis_points,
        freshness.basis_points,
        completeness.basis_points,
        integrity.basis_points,
    ];
    if scores.iter().any(Option::is_none) {
        return Dimension {
            status: TrustStatus::Unknown,
            basis_points: None,
        };
    }
    let score = scores.into_iter().flatten().min().unwrap_or(0);
    Dimension {
        status: if score == 10_000 {
            TrustStatus::Trusted
        } else {
            TrustStatus::Degraded
        },
        basis_points: Some(score),
    }
}

/// Deterministic view. Events are retained by LSN so historical snapshots are
/// reconstructed with the same exclusive bound used by `AS OF LSN` queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TelemetryHealthGraph {
    events: BTreeMap<Lsn, TelemetryHealthEnvelope>,
    rejected_payload_lsns: BTreeSet<Lsn>,
    watermark: Lsn,
}

impl TelemetryHealthGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_envelope(
        &mut self,
        lsn: Lsn,
        envelope: TelemetryHealthEnvelope,
    ) -> Result<(), HeraclitusError> {
        envelope.validate()?;
        self.events.entry(lsn).or_insert(envelope);
        self.watermark = self.watermark.max(lsn);
        Ok(())
    }

    pub fn rejected_payload_lsns(&self) -> &BTreeSet<Lsn> {
        &self.rejected_payload_lsns
    }

    pub fn snapshot_as_of(
        &self,
        identity: &SensorIdentity,
        exclusive_lsn: Lsn,
    ) -> Option<TelemetryHealthSnapshot> {
        self.reduce_as_of(exclusive_lsn)
            .remove(identity)
            .map(|state| state.snapshot(identity.clone(), exclusive_lsn))
    }

    pub fn snapshots_as_of(&self, exclusive_lsn: Lsn) -> Vec<TelemetryHealthSnapshot> {
        self.reduce_as_of(exclusive_lsn)
            .into_iter()
            .map(|(identity, state)| state.snapshot(identity, exclusive_lsn))
            .collect()
    }

    /// SPEC-0071 §6.3a/§9.1 — a saúde agregada de um datasource inteiro.
    ///
    /// O health gate da política pergunta por um **datasource**, não por um
    /// sensor: `required_telemetry: [{datasource_class: identity, ...}]`. Um
    /// datasource tem tipicamente vários sensores, e agregar exige uma regra.
    ///
    /// **A regra é: o PIOR sensor decide.** Não a média, não a maioria.
    ///
    /// O critério é adversarial, não estatístico. Quem ataca não degrada o
    /// sensor médio — silencia o sensor que o veria. Uma média deixaria oito
    /// sensores saudáveis a esconder o nono, que é exactamente o que ficou
    /// cego. A §6.3 diz o mesmo por outras palavras: "zero ataques +
    /// datasource Silent ≠ ambiente seguro".
    ///
    /// Um datasource **sem sensores conhecidos** devolve `None`, que o
    /// chamador tem de tratar como `Unknown` — nunca como saudável. A §9.1
    /// põe `Unknown` ao lado de `Silent` de propósito.
    ///
    /// `now_micros` é passado de fora e não lido do relógio: mantém a função
    /// determinística e reconstrutível `AS OF LSN`, como tudo o resto nesta
    /// view.
    pub fn datasource_health_as_of(
        &self,
        tenant_id: &str,
        datasource_id: &str,
        exclusive_lsn: Lsn,
        now_micros: u64,
    ) -> Option<DatasourceHealth> {
        let sensores: Vec<TelemetryHealthSnapshot> = self
            .snapshots_as_of(exclusive_lsn)
            .into_iter()
            .filter(|s| {
                s.identity.tenant_id == tenant_id && s.identity.datasource_id == datasource_id
            })
            .collect();
        if sensores.is_empty() {
            return None;
        }

        let saudavel = sensores
            .iter()
            .all(|s| s.status == SensorHealthStatus::Healthy);
        // A confiança é a do sensor menos confiável. `None` conta como zero:
        // um sensor sem confiança apurada não é um sensor de confiança.
        let confianca_basis_points = sensores
            .iter()
            .map(|s| s.trust.basis_points.unwrap_or(0))
            .min()
            .unwrap_or(0);
        // A idade é a do sensor MAIS ATRASADO: o instante a partir do qual
        // deixámos de ter cobertura completa deste datasource.
        let idade_micros = sensores
            .iter()
            .map(|s| match ultima_observacao(s) {
                Some(quando) => now_micros.saturating_sub(quando),
                // Um sensor que nunca foi observado é infinitamente velho.
                None => u64::MAX,
            })
            .max()
            .unwrap_or(u64::MAX);

        Some(DatasourceHealth {
            tenant_id: tenant_id.to_string(),
            datasource_id: datasource_id.to_string(),
            as_of_lsn: exclusive_lsn,
            saudavel,
            confianca_basis_points,
            idade_micros,
            sensores: sensores.len(),
            pior_sensor: sensores
                .iter()
                .min_by_key(|s| ordem_de_gravidade(s.status))
                .map(|s| s.identity.sensor_id.clone()),
        })
    }

    pub fn state_hash_as_of(&self, exclusive_lsn: Lsn) -> [u8; 32] {
        let state = self.reduce_as_of(exclusive_lsn);
        // JSON only accepts string map keys. A sorted vector preserves the
        // BTreeMap's canonical order without stringifying composite identity.
        let canonical: Vec<_> = state.into_iter().collect();
        let bytes = serde_json::to_vec(&canonical).expect("telemetry health serializa");
        *blake3::hash(&bytes).as_bytes()
    }

    fn reduce_as_of(&self, exclusive_lsn: Lsn) -> BTreeMap<SensorIdentity, ReducedSensor> {
        let mut sensors = BTreeMap::new();
        for (lsn, envelope) in self.events.range(..exclusive_lsn) {
            sensors
                .entry(envelope.identity.clone())
                .or_insert_with(|| ReducedSensor {
                    integrity: IntegrityStatus::Unknown,
                    ..Default::default()
                })
                .apply(*lsn, envelope);
        }
        for (identity, state) in &mut sensors {
            if state.freshness().status == FreshnessStatus::Silent {
                // Derived finding: its evidence is the latest included LSN, not
                // a fabricated attack event. The status remains query-time pure.
                let lsn = self
                    .events
                    .range(..exclusive_lsn)
                    .rev()
                    .find(|(_, envelope)| &envelope.identity == identity)
                    .map(|(lsn, _)| *lsn)
                    .unwrap_or(0);
                state.finding(HealthFindingKind::SensorSilent, lsn, 1);
            }
        }
        sensors
    }
}

impl View for TelemetryHealthGraph {
    fn name(&self) -> &str {
        "telemetry-health"
    }

    fn apply(&mut self, lsn: Lsn, episode: &Episode) {
        if !matches!(&episode.kind, EventKind::Custom(kind) if kind == TELEMETRY_HEALTH_KIND) {
            self.watermark = self.watermark.max(lsn);
            return;
        }
        match serde_json::from_slice::<TelemetryHealthEnvelope>(&episode.content)
            .map_err(|error| HeraclitusError::Serialization(error.to_string()))
            .and_then(|envelope| {
                envelope.validate()?;
                Ok(envelope)
            }) {
            Ok(envelope) => {
                self.events.entry(lsn).or_insert(envelope);
            }
            Err(_) => {
                self.rejected_payload_lsns.insert(lsn);
            }
        }
        self.watermark = self.watermark.max(lsn);
    }

    fn watermark(&self) -> Lsn {
        self.watermark
    }

    fn checkpoint(&self, dir: &Path) -> Result<(), HeraclitusError> {
        let mut events = Vec::with_capacity(self.events.len());
        for (lsn, envelope) in &self.events {
            let encoded = serde_json::to_vec(envelope)
                .map_err(|error| HeraclitusError::Serialization(error.to_string()))?;
            events.push((*lsn, encoded));
        }
        heraclitus_views::ckpt::save(
            dir,
            self.name(),
            &TelemetryHealthCheckpoint {
                events,
                rejected_payload_lsns: self.rejected_payload_lsns.iter().copied().collect(),
                watermark: self.watermark,
            },
        )
    }

    fn restore(&mut self, dir: &Path) -> Result<bool, HeraclitusError> {
        let Some(snapshot) =
            heraclitus_views::ckpt::load::<TelemetryHealthCheckpoint>(dir, self.name())?
        else {
            return Ok(false);
        };
        let mut events = BTreeMap::new();
        for (lsn, encoded) in snapshot.events {
            let Ok(envelope) = serde_json::from_slice::<TelemetryHealthEnvelope>(&encoded) else {
                self.reset();
                return Ok(false);
            };
            if envelope.validate().is_err() {
                self.reset();
                return Ok(false);
            }
            events.insert(lsn, envelope);
        }
        *self = Self {
            events,
            rejected_payload_lsns: snapshot.rejected_payload_lsns.into_iter().collect(),
            watermark: snapshot.watermark,
        };
        Ok(true)
    }

    fn state_hash(&self) -> Option<[u8; 32]> {
        let bytes = serde_json::to_vec(self).ok()?;
        Some(*blake3::hash(&bytes).as_bytes())
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Bincode-friendly outer snapshot. Event envelopes stay in their canonical
/// JSON wire format because internally tagged serde enums require a
/// self-describing deserializer, which bincode intentionally is not.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TelemetryHealthCheckpoint {
    events: Vec<(Lsn, Vec<u8>)>,
    rejected_payload_lsns: Vec<Lsn>,
    watermark: Lsn,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> SensorIdentity {
        SensorIdentity::new("tenant-a", "windows-security", "sensor-01")
    }

    fn digest() -> String {
        "ab".repeat(32)
    }

    fn envelope(at: u64, event: TelemetryHealthEvent) -> TelemetryHealthEnvelope {
        TelemetryHealthEnvelope::new(id(), at, event)
    }

    fn expectation(minimum: Option<u64>) -> TelemetryHealthEvent {
        TelemetryHealthEvent::ExpectationConfigured(ExpectationConfigured {
            heartbeat_cadence_micros: Some(100),
            max_lateness_micros: 50,
            minimum_events_per_window: minimum,
            duplicate_storm_basis_points: 2_000,
        })
    }

    fn activated() -> TelemetryHealthEvent {
        TelemetryHealthEvent::ConnectorActivated(ConnectorActivated {
            connector_digest: digest(),
            approved: true,
        })
    }

    #[test]
    fn th0_missing_heartbeat_becomes_silent_only_after_recorded_time_progresses() {
        let mut graph = TelemetryHealthGraph::new();
        graph
            .apply_envelope(1, envelope(1_000, expectation(Some(0))))
            .unwrap();
        graph
            .apply_envelope(
                2,
                envelope(
                    1_151,
                    TelemetryHealthEvent::HealthEvaluationTick(HealthEvaluationTick {
                        evaluated_at_micros: 1_151,
                    }),
                ),
            )
            .unwrap();
        let snapshot = graph.snapshot_as_of(&id(), 3).unwrap();
        assert_eq!(snapshot.freshness.status, FreshnessStatus::Silent);
        assert_eq!(snapshot.status, SensorHealthStatus::Silent);
        assert_eq!(snapshot.activity, ActivityStatus::Silent);
        assert!(snapshot
            .findings
            .iter()
            .any(|finding| finding.kind == HealthFindingKind::SensorSilent));
    }

    #[test]
    fn th1_no_expectation_is_unknown_not_healthy_or_failed() {
        let mut graph = TelemetryHealthGraph::new();
        graph
            .apply_envelope(
                1,
                envelope(
                    1_000,
                    TelemetryHealthEvent::SensorHeartbeat(SensorHeartbeat {
                        observed_at_micros: 1_000,
                    }),
                ),
            )
            .unwrap();
        let snapshot = graph.snapshot_as_of(&id(), 2).unwrap();
        assert_eq!(snapshot.freshness.status, FreshnessStatus::Unknown);
        assert_eq!(snapshot.completeness.status, CompletenessStatus::Unknown);
        assert_eq!(snapshot.trust.status, TrustStatus::Unknown);
        assert_eq!(snapshot.status, SensorHealthStatus::Unknown);
    }

    #[test]
    fn th2_sequence_hole_is_a_gap() {
        let mut graph = TelemetryHealthGraph::new();
        graph
            .apply_envelope(1, envelope(10, expectation(Some(0))))
            .unwrap();
        for (lsn, sequence) in [(2, 10), (3, 13)] {
            graph
                .apply_envelope(
                    lsn,
                    envelope(
                        lsn,
                        TelemetryHealthEvent::CheckpointAdvanced(CheckpointAdvanced {
                            source_sequence: Some(sequence),
                            source_watermark: None,
                            integrity: CheckpointIntegrity::Verified,
                        }),
                    ),
                )
                .unwrap();
        }
        let snapshot = graph.snapshot_as_of(&id(), 4).unwrap();
        assert_eq!(snapshot.completeness.status, CompletenessStatus::Gap);
        assert_eq!(snapshot.counters.sequence_gaps, 2);
    }

    #[test]
    fn th3_schema_drift_reduces_coverage_without_becoming_an_attack() {
        let mut graph = TelemetryHealthGraph::new();
        graph.apply_envelope(1, envelope(10, activated())).unwrap();
        graph
            .apply_envelope(
                2,
                envelope(
                    20,
                    TelemetryHealthEvent::IngestionWindowClosed(IngestionWindowClosed {
                        window_start_micros: 10,
                        window_end_micros: 20,
                        received: 100,
                        parsed: 100,
                        normalized: 100,
                        duplicated: 0,
                        dropped: 0,
                        quarantined: 0,
                        parser_errors: 0,
                        max_observed_lateness_millis: 0,
                        connector_digest: digest(),
                    }),
                ),
            )
            .unwrap();
        let before = graph.snapshot_as_of(&id(), 3).unwrap();
        graph
            .apply_envelope(
                3,
                envelope(
                    30,
                    TelemetryHealthEvent::SchemaDriftObserved(SchemaDriftObserved {
                        count: 25,
                        field: Some("event_data.new_field".into()),
                    }),
                ),
            )
            .unwrap();
        let after = graph.snapshot_as_of(&id(), 4).unwrap();
        assert_eq!(before.coverage.basis_points, Some(10_000));
        assert!(after.coverage.basis_points < before.coverage.basis_points);
        assert_eq!(after.coverage.status, CoverageStatus::Partial);
        assert_eq!(after.status, SensorHealthStatus::Drifted);
        assert!(after
            .findings
            .iter()
            .any(|finding| finding.kind == HealthFindingKind::SchemaDrift));
    }

    #[test]
    fn th4_as_of_matches_partial_replay_bit_for_bit() {
        let events = [
            envelope(10, expectation(Some(0))),
            envelope(20, activated()),
            envelope(
                30,
                TelemetryHealthEvent::SensorHeartbeat(SensorHeartbeat {
                    observed_at_micros: 30,
                }),
            ),
        ];
        let mut full = TelemetryHealthGraph::new();
        for (index, event) in events.iter().cloned().enumerate() {
            full.apply_envelope(index as u64 + 1, event).unwrap();
        }
        let mut partial = TelemetryHealthGraph::new();
        for (index, event) in events[..2].iter().cloned().enumerate() {
            partial.apply_envelope(index as u64 + 1, event).unwrap();
        }
        assert_eq!(full.state_hash_as_of(3), partial.state_hash_as_of(3));
    }

    #[test]
    fn th5_divergent_checkpoint_is_tamper_and_untrusted() {
        let mut graph = TelemetryHealthGraph::new();
        graph.apply_envelope(1, envelope(10, activated())).unwrap();
        graph
            .apply_envelope(
                2,
                envelope(
                    20,
                    TelemetryHealthEvent::CheckpointAdvanced(CheckpointAdvanced {
                        source_sequence: Some(1),
                        source_watermark: None,
                        integrity: CheckpointIntegrity::Divergent,
                    }),
                ),
            )
            .unwrap();
        let snapshot = graph.snapshot_as_of(&id(), 3).unwrap();
        assert_eq!(snapshot.integrity.status, IntegrityStatus::Tampered);
        assert_eq!(snapshot.trust.status, TrustStatus::Untrusted);
        assert_eq!(snapshot.status, SensorHealthStatus::Degraded);
    }

    #[test]
    fn window_from_unexpected_connector_is_tamper() {
        let mut graph = TelemetryHealthGraph::new();
        graph.apply_envelope(1, envelope(10, activated())).unwrap();
        graph
            .apply_envelope(
                2,
                envelope(
                    20,
                    TelemetryHealthEvent::IngestionWindowClosed(IngestionWindowClosed {
                        window_start_micros: 10,
                        window_end_micros: 20,
                        received: 1,
                        parsed: 1,
                        normalized: 1,
                        duplicated: 0,
                        dropped: 0,
                        quarantined: 0,
                        parser_errors: 0,
                        max_observed_lateness_millis: 0,
                        connector_digest: "cd".repeat(32),
                    }),
                ),
            )
            .unwrap();
        let snapshot = graph.snapshot_as_of(&id(), 3).unwrap();
        assert_eq!(snapshot.integrity.status, IntegrityStatus::Tampered);
        assert_eq!(snapshot.trust.status, TrustStatus::Untrusted);
    }

    #[test]
    fn clock_skew_prevents_a_healthy_freshness_claim() {
        let mut graph = TelemetryHealthGraph::new();
        graph
            .apply_envelope(1, envelope(10, expectation(Some(0))))
            .unwrap();
        graph
            .apply_envelope(
                2,
                envelope(
                    20,
                    TelemetryHealthEvent::SensorHeartbeat(SensorHeartbeat {
                        observed_at_micros: 20,
                    }),
                ),
            )
            .unwrap();
        graph
            .apply_envelope(
                3,
                envelope(
                    21,
                    TelemetryHealthEvent::SensorClockSkewObserved(SensorClockSkewObserved {
                        absolute_skew_millis: 5_000,
                    }),
                ),
            )
            .unwrap();
        assert_eq!(
            graph.snapshot_as_of(&id(), 4).unwrap().freshness.status,
            FreshnessStatus::Delayed
        );
    }

    #[test]
    fn quiet_requires_healthy_sensor_and_explicit_zero_expectation() {
        let mut graph = TelemetryHealthGraph::new();
        graph
            .apply_envelope(1, envelope(10, expectation(Some(0))))
            .unwrap();
        graph.apply_envelope(2, envelope(11, activated())).unwrap();
        graph
            .apply_envelope(
                3,
                envelope(
                    20,
                    TelemetryHealthEvent::SensorHeartbeat(SensorHeartbeat {
                        observed_at_micros: 20,
                    }),
                ),
            )
            .unwrap();
        graph
            .apply_envelope(
                4,
                envelope(
                    21,
                    TelemetryHealthEvent::IngestionWindowClosed(IngestionWindowClosed {
                        window_start_micros: 20,
                        window_end_micros: 21,
                        received: 0,
                        parsed: 0,
                        normalized: 0,
                        duplicated: 0,
                        dropped: 0,
                        quarantined: 0,
                        parser_errors: 0,
                        max_observed_lateness_millis: 0,
                        connector_digest: digest(),
                    }),
                ),
            )
            .unwrap();
        let snapshot = graph.snapshot_as_of(&id(), 5).unwrap();
        assert_eq!(snapshot.freshness.status, FreshnessStatus::Healthy);
        assert_eq!(snapshot.activity, ActivityStatus::Quiet);
    }

    #[test]
    fn checkpoint_restore_preserves_history_and_hash() {
        let dir = tempfile::tempdir().unwrap();
        let mut graph = TelemetryHealthGraph::new();
        graph
            .apply_envelope(1, envelope(10, expectation(Some(0))))
            .unwrap();
        let expected = graph.state_hash();
        graph.checkpoint(dir.path()).unwrap();

        let mut restored = TelemetryHealthGraph::new();
        assert!(restored.restore(dir.path()).unwrap());
        assert_eq!(restored.state_hash(), expected);
        assert_eq!(
            restored.snapshot_as_of(&id(), 2),
            graph.snapshot_as_of(&id(), 2)
        );
    }

    #[test]
    fn malformed_payload_is_recorded_and_never_panics() {
        let mut graph = TelemetryHealthGraph::new();
        let episode = Episode::new(
            "malicious",
            EventKind::Custom(TELEMETRY_HEALTH_KIND.into()),
            b"{not-json".to_vec(),
        );
        graph.apply(7, &episode);
        assert!(graph.rejected_payload_lsns().contains(&7));
    }
}

/// SPEC-0071 §6.3a — a saúde de um datasource inteiro, agregada dos seus
/// sensores.
///
/// A regra de agregação está documentada em
/// [`TelemetryHealthGraph::datasource_health_as_of`]: o pior sensor decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasourceHealth {
    pub tenant_id: String,
    pub datasource_id: String,
    /// Limite exclusivo, como em `AS OF LSN n`.
    pub as_of_lsn: Lsn,
    /// Todos os sensores conhecidos estão `Healthy`.
    pub saudavel: bool,
    /// Confiança do sensor MENOS confiável, em basis points (0..=10_000).
    pub confianca_basis_points: u16,
    /// Idade do sensor MAIS atrasado, em microssegundos.
    pub idade_micros: u64,
    /// Quantos sensores entraram no agregado.
    pub sensores: usize,
    /// Qual deles puxou o agregado para baixo — o que se vai investigar.
    pub pior_sensor: Option<String>,
}

impl DatasourceHealth {
    /// A confiança em [0, 1], que é como a política a declara
    /// (`minimum_trust: 0.90`).
    pub fn confianca(&self) -> f32 {
        f32::from(self.confianca_basis_points) / 10_000.0
    }

    /// A idade em segundos, que é como a política a declara
    /// (`maximum_age_secs: 300`).
    pub fn idade_secs(&self) -> u64 {
        self.idade_micros / 1_000_000
    }
}

/// O instante da observação mais recente de um sensor.
///
/// A janela de ingestão é preferida ao heartbeat: um heartbeat prova que o
/// processo do conector está vivo, e uma janela fechada prova que DADOS
/// chegaram. É a segunda que a §9.1 quer saber — um conector vivo que não
/// entrega nada é precisamente o `Silent` que o gate existe para apanhar.
fn ultima_observacao(s: &TelemetryHealthSnapshot) -> Option<u64> {
    s.last_window_end_micros.or(s.last_heartbeat_micros)
}

/// Ordem de gravidade, do pior para o melhor. Só serve para escolher qual o
/// sensor a nomear no agregado.
fn ordem_de_gravidade(status: SensorHealthStatus) -> u8 {
    match status {
        SensorHealthStatus::Silent => 0,
        SensorHealthStatus::Unknown => 1,
        SensorHealthStatus::Degraded => 2,
        SensorHealthStatus::Drifted => 3,
        SensorHealthStatus::Delayed => 4,
        SensorHealthStatus::Healthy => 5,
    }
}

#[cfg(test)]
mod testes_agregado_spec0071 {
    use super::*;

    fn sensor(nome: &str) -> SensorIdentity {
        SensorIdentity::new("tenant-a", "identity", nome)
    }

    fn expectativa() -> TelemetryHealthEvent {
        TelemetryHealthEvent::ExpectationConfigured(ExpectationConfigured {
            heartbeat_cadence_micros: Some(60_000_000),
            max_lateness_micros: 30_000_000,
            minimum_events_per_window: Some(1),
            duplicate_storm_basis_points: 2_000,
        })
    }

    fn janela(fim: u64) -> TelemetryHealthEvent {
        TelemetryHealthEvent::IngestionWindowClosed(IngestionWindowClosed {
            window_start_micros: fim.saturating_sub(1_000_000),
            window_end_micros: fim,
            received: 10,
            parsed: 10,
            normalized: 10,
            duplicated: 0,
            dropped: 0,
            quarantined: 0,
            parser_errors: 0,
            max_observed_lateness_millis: 1,
            connector_digest: "ab".repeat(32),
        })
    }

    fn grafo(eventos: Vec<(SensorIdentity, u64, TelemetryHealthEvent)>) -> TelemetryHealthGraph {
        let mut g = TelemetryHealthGraph::new();
        for (lsn, (identity, at, evento)) in eventos.into_iter().enumerate() {
            g.apply_envelope(
                lsn as u64,
                TelemetryHealthEnvelope::new(identity, at, evento),
            )
            .unwrap();
        }
        g
    }

    #[test]
    fn um_datasource_sem_sensores_e_none_e_nunca_saudavel() {
        let g = grafo(vec![]);
        assert!(g
            .datasource_health_as_of("tenant-a", "identity", 100, 1_000_000)
            .is_none());
    }

    #[test]
    fn o_pior_sensor_decide_a_confianca_e_a_idade() {
        // A regra de agregacao, e a razao dela: quem ataca nao degrada o sensor
        // medio — silencia o que o veria. Uma media deixaria o sensor saudavel
        // a esconder o que ficou cego.
        let bom = sensor("okta");
        let mau = sensor("ad");
        let g = grafo(vec![
            (bom.clone(), 1, expectativa()),
            (mau.clone(), 1, expectativa()),
            // O bom entregou agora; o mau ha muito tempo.
            (bom.clone(), 900_000_000, janela(900_000_000)),
            (mau.clone(), 100_000_000, janela(100_000_000)),
        ]);
        let agora = 1_000_000_000;
        let saude = g
            .datasource_health_as_of("tenant-a", "identity", 100, agora)
            .expect("dois sensores conhecidos");

        assert_eq!(saude.sensores, 2);
        assert_eq!(
            saude.idade_micros,
            agora - 100_000_000,
            "a idade tem de ser a do sensor MAIS atrasado, nao a media nem a do melhor"
        );
        let confianca_isolada = |s: &SensorIdentity| {
            g.snapshot_as_of(s, 100)
                .unwrap()
                .trust
                .basis_points
                .unwrap_or(0)
        };
        assert_eq!(
            saude.confianca_basis_points,
            confianca_isolada(&bom).min(confianca_isolada(&mau)),
            "a confianca tem de ser a do sensor MENOS confiavel"
        );
    }

    #[test]
    fn um_sensor_nao_saudavel_arrasta_o_datasource() {
        let bom = sensor("okta");
        let calado = sensor("ad");
        let g = grafo(vec![
            (bom.clone(), 1, expectativa()),
            (calado.clone(), 1, expectativa()),
            (bom.clone(), 900_000_000, janela(900_000_000)),
            // O `calado` nunca entregou nada depois da expectativa.
            (
                calado.clone(),
                900_000_000,
                TelemetryHealthEvent::HealthEvaluationTick(HealthEvaluationTick {
                    evaluated_at_micros: 900_000_000,
                }),
            ),
        ]);
        let saude = g
            .datasource_health_as_of("tenant-a", "identity", 100, 1_000_000_000)
            .unwrap();
        assert!(
            !saude.saudavel,
            "com um sensor calado o datasource nao pode ser dado por saudavel"
        );
        assert_eq!(saude.pior_sensor.as_deref(), Some("ad"));
    }

    #[test]
    fn a_conversao_para_a_unidade_da_politica_e_a_esperada() {
        // A politica declara `minimum_trust: 0.90` e `maximum_age_secs: 300`.
        let saude = DatasourceHealth {
            tenant_id: "t".into(),
            datasource_id: "d".into(),
            as_of_lsn: 1,
            saudavel: true,
            confianca_basis_points: 9_000,
            idade_micros: 300_000_000,
            sensores: 1,
            pior_sensor: None,
        };
        assert_eq!(saude.confianca(), 0.90);
        assert_eq!(saude.idade_secs(), 300);
    }
}
