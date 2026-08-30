//! L1 deterministic detection primitives.

use crate::event::{
    DetectorIdentity, EntityRef, EvidenceRef, Outcome, SecurityEvent, SecuritySignal,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Field {
    Source,
    Category,
    Activity,
    Outcome,
    Severity,
    PrincipalId,
    UserId,
    HostId,
    ProcessId,
    ProcessName,
    SrcIp,
    DstIp,
    Attribute(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Value {
    String(String),
    Number(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionExpr {
    Eq(Field, Value),
    Ne(Field, Value),
    In(Field, Vec<Value>),
    And(Vec<DetectionExpr>),
    Or(Vec<DetectionExpr>),
    Not(Box<DetectionExpr>),
    Count {
        predicate: Box<DetectionExpr>,
        window_ms: u64,
        threshold: u64,
    },
    Sequence {
        steps: Vec<DetectionExpr>,
        within_ms: u64,
    },
    DistinctCount {
        field: Field,
        window_ms: u64,
        threshold: u64,
    },
}

impl DetectionExpr {
    pub fn eq(field: Field, value: impl Into<Value>) -> Self {
        Self::Eq(field, value.into())
    }

    pub fn validate(&self) -> Result<(), RuleCompileError> {
        match self {
            Self::Eq(_, _) | Self::Ne(_, _) | Self::In(_, _) => Ok(()),
            Self::And(items) | Self::Or(items) => {
                if items.is_empty() {
                    return Err(RuleCompileError::EmptyBoolean);
                }
                for item in items {
                    item.validate()?;
                }
                Ok(())
            }
            Self::Not(item) => item.validate(),
            Self::Count {
                predicate,
                window_ms,
                threshold,
            } => {
                if *window_ms == 0 || *threshold == 0 {
                    return Err(RuleCompileError::InvalidWindow);
                }
                predicate.validate()
            }
            Self::Sequence { steps, within_ms } => {
                if steps.is_empty() || *within_ms == 0 {
                    return Err(RuleCompileError::InvalidWindow);
                }
                for step in steps {
                    step.validate()?;
                }
                Ok(())
            }
            Self::DistinctCount {
                window_ms,
                threshold,
                ..
            } => {
                if *window_ms == 0 || *threshold == 0 {
                    return Err(RuleCompileError::InvalidWindow);
                }
                Ok(())
            }
        }
    }

    pub(crate) fn matches(&self, index: usize, events: &[(u64, SecurityEvent)]) -> EvalResult {
        match self {
            Self::Eq(field, expected) => {
                let actual = field_value(field, &events[index].1);
                EvalResult::single(
                    actual.as_ref().is_some_and(|v| values_match(v, expected)),
                    index,
                )
            }
            Self::Ne(field, expected) => {
                let actual = field_value(field, &events[index].1);
                EvalResult::single(
                    actual.as_ref().is_some_and(|v| !values_match(v, expected)),
                    index,
                )
            }
            Self::In(field, values) => {
                let actual = field_value(field, &events[index].1);
                EvalResult::single(
                    actual.as_ref().is_some_and(|value| {
                        values
                            .iter()
                            .any(|candidate| values_match(value, candidate))
                    }),
                    index,
                )
            }
            Self::And(items) => {
                let mut evidence = Vec::new();
                for item in items {
                    let result = item.matches(index, events);
                    if !result.matched {
                        return EvalResult::default();
                    }
                    evidence.extend(result.evidence);
                }
                evidence.sort_unstable();
                evidence.dedup();
                EvalResult {
                    matched: true,
                    evidence,
                }
            }
            Self::Or(items) => items
                .iter()
                .map(|item| item.matches(index, events))
                .find(|result| result.matched)
                .unwrap_or_default(),
            Self::Not(item) => EvalResult::single(!item.matches(index, events).matched, index),
            Self::Count {
                predicate,
                window_ms,
                threshold,
            } => {
                let start = events[index].1.observed_at.saturating_sub(*window_ms);
                let mut evidence = Vec::new();
                for (candidate_index, (_, event)) in events.iter().enumerate() {
                    if event.observed_at >= start
                        && event.observed_at <= events[index].1.observed_at
                        && predicate.matches(candidate_index, events).matched
                    {
                        evidence.push(candidate_index);
                    }
                }
                EvalResult {
                    matched: evidence.len() as u64 >= *threshold,
                    evidence,
                }
            }
            Self::Sequence { steps, within_ms } => {
                let anchor_time = events[index].1.observed_at;
                let start = anchor_time.saturating_sub(*within_ms);
                let mut cursor = 0usize;
                let mut evidence = Vec::new();
                for step in steps {
                    let found = (cursor..=index).find(|candidate| {
                        events[*candidate].1.observed_at >= start
                            && events[*candidate].1.observed_at <= anchor_time
                            && step.matches(*candidate, events).matched
                    });
                    let Some(found) = found else {
                        return EvalResult::default();
                    };
                    evidence.push(found);
                    cursor = found.saturating_add(1);
                }
                evidence.sort_unstable();
                evidence.dedup();
                EvalResult {
                    matched: true,
                    evidence,
                }
            }
            Self::DistinctCount {
                field,
                window_ms,
                threshold,
            } => {
                let start = events[index].1.observed_at.saturating_sub(*window_ms);
                let mut values = std::collections::BTreeSet::new();
                let mut evidence = Vec::new();
                for (candidate_index, (_, event)) in events.iter().enumerate() {
                    if event.observed_at >= start
                        && event.observed_at <= events[index].1.observed_at
                    {
                        if let Some(value) = field_value(field, event) {
                            values.insert(value);
                            evidence.push(candidate_index);
                        }
                    }
                }
                EvalResult {
                    matched: values.len() as u64 >= *threshold,
                    evidence,
                }
            }
        }
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::Number(value)
    }
}

fn values_match(actual: &Value, expected: &Value) -> bool {
    if actual == expected {
        return true;
    }
    match (actual, expected) {
        (Value::String(value), Value::Number(expected))
        | (Value::Number(expected), Value::String(value)) => {
            value.parse::<u64>().ok() == Some(*expected)
        }
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleCompileError {
    #[error("boolean detection expression cannot be empty")]
    EmptyBoolean,
    #[error("detection expression has an empty or zero window/threshold")]
    InvalidWindow,
    #[error("rule id and version are required")]
    MissingIdentity,
    #[error("unsupported Sigma feature: {0}")]
    UnsupportedFeature(String),
    #[error("invalid Sigma rule: {0}")]
    InvalidSigma(String),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct EvalResult {
    pub matched: bool,
    pub evidence: Vec<usize>,
}

impl EvalResult {
    fn single(matched: bool, index: usize) -> Self {
        Self {
            matched,
            evidence: matched.then_some(vec![index]).unwrap_or_default(),
        }
    }
}

fn field_value(field: &Field, event: &SecurityEvent) -> Option<Value> {
    match field {
        Field::Source => Some(Value::String(event.source.label())),
        Field::Category => Some(Value::String(event.category.label())),
        Field::Activity => Some(Value::String(event.activity.clone())),
        Field::Outcome => Some(Value::String(event.outcome.label())),
        Field::Severity => Some(Value::Number(event.severity as u64)),
        Field::PrincipalId => event
            .principal
            .as_ref()
            .map(|value| Value::String(value.id.clone())),
        Field::UserId => event
            .user
            .as_ref()
            .map(|value| Value::String(value.id.clone())),
        Field::HostId => event
            .host
            .as_ref()
            .map(|value| Value::String(value.id.clone())),
        Field::ProcessId => event
            .process
            .as_ref()
            .map(|value| Value::String(value.id.clone())),
        Field::ProcessName => event
            .process
            .as_ref()
            .and_then(|value| value.name.clone())
            .map(Value::String),
        Field::SrcIp => event
            .src
            .as_ref()
            .and_then(|value| value.ip.clone())
            .map(Value::String),
        Field::DstIp => event
            .dst
            .as_ref()
            .and_then(|value| value.ip.clone())
            .map(Value::String),
        Field::Attribute(name) => event.attributes.get(name).cloned().map(Value::String),
    }
}

/// True when an event is one of the Sentinel's own derived records.
pub(crate) fn is_derived(event: &SecurityEvent) -> bool {
    matches!(
        event
            .attributes
            .get("sentinel.generated")
            .map(String::as_str),
        Some("true" | "derived" | "1")
    )
}

/// Re-exported for callers that want to construct predicates without importing
/// the private evaluator details.
pub fn outcome_value(outcome: &Outcome) -> Value {
    Value::String(outcome.label())
}

/// A deterministic rule as loaded by the host.  Sigma frontends can compile
/// into this representation later; unsupported constructs must fail during
/// `validate`, never be silently discarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionRule {
    pub detector: DetectorIdentity,
    pub expression: DetectionExpr,
    pub severity: u8,
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub consume_derived: bool,
}

impl DetectionRule {
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
        expression: DetectionExpr,
        severity: u8,
    ) -> Self {
        Self {
            detector: DetectorIdentity {
                id: id.into(),
                version: version.into(),
            },
            expression,
            severity,
            labels: std::collections::BTreeMap::new(),
            consume_derived: false,
        }
    }

    pub fn validate(&self) -> Result<(), RuleCompileError> {
        if self.detector.id.trim().is_empty() || self.detector.version.trim().is_empty() {
            return Err(RuleCompileError::MissingIdentity);
        }
        self.expression.validate()
    }
}

/// In-process deterministic L1 executor.  It returns at most one logical
/// signal per rule/window invocation; the BLAKE3 signal identity makes replay
/// and retry idempotent for the same evidence.
#[derive(Debug, Clone, Default)]
pub struct RuleEngine {
    rules: Vec<DetectionRule>,
}

impl RuleEngine {
    pub fn new(rules: impl IntoIterator<Item = DetectionRule>) -> Result<Self, RuleCompileError> {
        let mut engine = Self::default();
        for rule in rules {
            engine.add_rule(rule)?;
        }
        Ok(engine)
    }

    pub fn add_rule(&mut self, rule: DetectionRule) -> Result<(), RuleCompileError> {
        rule.validate()?;
        self.rules.push(rule);
        self.rules.sort_by(|a, b| {
            a.detector
                .id
                .cmp(&b.detector.id)
                .then_with(|| a.detector.version.cmp(&b.detector.version))
        });
        Ok(())
    }

    pub fn rules(&self) -> &[DetectionRule] {
        &self.rules
    }

    pub fn evaluate(
        &self,
        window: &[(heraclitus_core::Lsn, SecurityEvent)],
    ) -> Vec<SecuritySignal> {
        let mut signals = Vec::new();
        for rule in &self.rules {
            let eligible: Vec<(heraclitus_core::Lsn, SecurityEvent)> = window
                .iter()
                .filter(|(_, event)| rule.consume_derived || !is_derived(event))
                .cloned()
                .collect();
            if eligible.is_empty() {
                continue;
            }
            let mut matched = None;
            for index in 0..eligible.len() {
                let result = rule.expression.matches(index, &eligible);
                if result.matched {
                    matched = Some(result.evidence);
                    break;
                }
            }
            let Some(indices) = matched else { continue };
            let mut evidence: Vec<EvidenceRef> = indices
                .into_iter()
                .filter_map(|index| eligible.get(index))
                .map(|(lsn, event)| EvidenceRef {
                    lsn: *lsn,
                    event_id: event.raw_event_id,
                })
                .collect();
            evidence.sort_by(|a, b| a.lsn.cmp(&b.lsn).then_with(|| a.event_id.cmp(&b.event_id)));
            evidence.dedup_by(|a, b| a.lsn == b.lsn && a.event_id == b.event_id);
            if evidence.is_empty() {
                continue;
            }
            let subject = evidence.iter().find_map(|ref_| {
                eligible
                    .iter()
                    .find(|(lsn, event)| *lsn == ref_.lsn && event.raw_event_id == ref_.event_id)
                    .and_then(|(_, event)| subject_of(event))
            });
            let window_start = evidence.first().map(|item| item.lsn).unwrap_or_default();
            let created_at_lsn = evidence.last().map(|item| item.lsn).unwrap_or(window_start);
            let signal_id = SecuritySignal::deterministic_id(
                &rule.detector,
                subject.as_ref(),
                &evidence,
                window_start,
            );
            let mut labels = rule.labels.clone();
            labels.insert("rule.id".into(), rule.detector.id.clone());
            labels.insert("rule.version".into(), rule.detector.version.clone());
            signals.push(SecuritySignal {
                signal_id,
                detector: rule.detector.clone(),
                severity: rule.severity,
                score: 1.0,
                subject,
                evidence,
                created_at_lsn,
                labels,
            });
        }
        signals
    }
}

fn subject_of(event: &SecurityEvent) -> Option<EntityRef> {
    event
        .user
        .clone()
        .or_else(|| event.principal.clone())
        .or_else(|| event.host.clone())
        .or_else(|| event.process.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{SecurityCategory, SecuritySource};
    use heraclitus_core::EventId;

    fn event(lsn: u64, outcome: Outcome) -> (u64, SecurityEvent) {
        let mut value = SecurityEvent::unmapped(EventId::new(), SecuritySource::Auditd);
        value.category = SecurityCategory::Authentication;
        value.activity = "login".into();
        value.outcome = outcome;
        value.observed_at = lsn * 1_000;
        (lsn, value)
    }

    #[test]
    fn count_rule_is_deterministic_and_skips_derived_events() {
        let rule = DetectionRule::new(
            "failed-logins",
            "1.0.0",
            DetectionExpr::Count {
                predicate: Box::new(DetectionExpr::Eq(
                    Field::Outcome,
                    Value::String("failure".into()),
                )),
                window_ms: 10_000,
                threshold: 2,
            },
            7,
        );
        let engine = RuleEngine::new([rule]).unwrap();
        let mut rows = vec![event(1, Outcome::Failure), event(2, Outcome::Failure)];
        rows[1]
            .1
            .attributes
            .insert("sentinel.generated".into(), "true".into());
        assert!(engine.evaluate(&rows).is_empty());
        rows[1].1.attributes.remove("sentinel.generated");
        let first = engine.evaluate(&rows);
        let second = engine.evaluate(&rows);
        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
        assert!(first[0].signal_id.starts_with("sig-"));
    }
}
