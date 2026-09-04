//! L1 deterministic detection primitives.

use crate::event::{
    DetectorIdentity, EntityRef, EvidenceRef, Outcome, SecurityEvent, SecuritySignal,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

    /// A maior janela temporal, em milissegundos, que esta expressão consulta.
    ///
    /// É o que torna o histórico L1 **limitável**. O comentário em
    /// `evaluate_l1` dizia que nenhum horizonte finito era seguro sem um
    /// "contrato de lateness" — mas o horizonte não é arbitrário, é derivável
    /// da própria expressão: `Count`, `Sequence` e `DistinctCount` carregam a
    /// janela explicitamente, e todos os outros nós são **pontuais** — o
    /// resultado para o evento `i` depende só do evento `i`. Uma regra sem
    /// operador temporal precisa de janela zero.
    ///
    /// Para o histórico inteiro, a fronteira segura é o máximo disto sobre
    /// todas as regras, mais a tolerância a eventos atrasados que o operador
    /// configurar. Tudo o que for mais antigo do que isso, medido a partir do
    /// evento mais recente, **não pode participar em nenhuma correspondência**
    /// que a regra ainda não tenha visto.
    pub fn max_window_ms(&self) -> u64 {
        match self {
            Self::Eq(_, _) | Self::Ne(_, _) | Self::In(_, _) => 0,
            Self::And(items) | Self::Or(items) => {
                items.iter().map(Self::max_window_ms).max().unwrap_or(0)
            }
            Self::Not(item) => item.max_window_ms(),
            Self::Count {
                predicate,
                window_ms,
                ..
            } => (*window_ms).max(predicate.max_window_ms()),
            Self::Sequence { steps, within_ms } => (*within_ms).max(
                steps
                    .iter()
                    .map(Self::max_window_ms)
                    .max()
                    .unwrap_or(0),
            ),
            Self::DistinctCount { window_ms, .. } => *window_ms,
        }
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

    #[cfg(test)]
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
#[cfg_attr(not(test), allow(dead_code))]
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

/// Bottom-up evaluation of one expression over a complete replay window.
///
/// The old evaluator called `matches` for every possible anchor.  A temporal
/// expression then scanned the complete window again, making a single rule
/// quadratic (and nested temporal expressions worse).  This plan materialises
/// one boolean per expression/event.  Counts use prefix sums in event-time
/// order, distinct counts use a sliding multiset, and sequences use sliding
/// ordered sets of matching transaction positions.
///
/// Evidence is reconstructed only for the first matching anchor, from these
/// cached booleans.  That deliberately preserves the exact evidence chosen by
/// the reference evaluator without materialising O(window^2) evidence lists.
struct ExprEvaluation<'a> {
    expr: &'a DetectionExpr,
    matched: Vec<bool>,
    children: Vec<ExprEvaluation<'a>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct EvaluationStats {
    work_units: usize,
}

type EventRef<'a> = &'a (heraclitus_core::Lsn, SecurityEvent);

impl<'a> ExprEvaluation<'a> {
    fn build(
        expr: &'a DetectionExpr,
        events: &[EventRef<'_>],
        time_order: &[usize],
        stats: &mut EvaluationStats,
    ) -> Self {
        let event_count = events.len();
        match expr {
            DetectionExpr::Eq(field, expected) => {
                stats.work_units += event_count;
                let matched = events
                    .iter()
                    .map(|(_, event)| {
                        field_value(field, event)
                            .as_ref()
                            .is_some_and(|actual| values_match(actual, expected))
                    })
                    .collect();
                Self {
                    expr,
                    matched,
                    children: Vec::new(),
                }
            }
            DetectionExpr::Ne(field, expected) => {
                stats.work_units += event_count;
                let matched = events
                    .iter()
                    .map(|(_, event)| {
                        field_value(field, event)
                            .as_ref()
                            .is_some_and(|actual| !values_match(actual, expected))
                    })
                    .collect();
                Self {
                    expr,
                    matched,
                    children: Vec::new(),
                }
            }
            DetectionExpr::In(field, values) => {
                stats.work_units += event_count;
                let matched = events
                    .iter()
                    .map(|(_, event)| {
                        field_value(field, event).as_ref().is_some_and(|actual| {
                            values
                                .iter()
                                .any(|candidate| values_match(actual, candidate))
                        })
                    })
                    .collect();
                Self {
                    expr,
                    matched,
                    children: Vec::new(),
                }
            }
            DetectionExpr::And(items) => {
                let children: Vec<_> = items
                    .iter()
                    .map(|item| Self::build(item, events, time_order, stats))
                    .collect();
                stats.work_units += event_count.saturating_mul(children.len());
                let matched = (0..event_count)
                    .map(|index| children.iter().all(|child| child.matched[index]))
                    .collect();
                Self {
                    expr,
                    matched,
                    children,
                }
            }
            DetectionExpr::Or(items) => {
                let children: Vec<_> = items
                    .iter()
                    .map(|item| Self::build(item, events, time_order, stats))
                    .collect();
                stats.work_units += event_count.saturating_mul(children.len());
                let matched = (0..event_count)
                    .map(|index| children.iter().any(|child| child.matched[index]))
                    .collect();
                Self {
                    expr,
                    matched,
                    children,
                }
            }
            DetectionExpr::Not(item) => {
                let child = Self::build(item, events, time_order, stats);
                stats.work_units += event_count;
                let matched = child.matched.iter().map(|matched| !matched).collect();
                Self {
                    expr,
                    matched,
                    children: vec![child],
                }
            }
            DetectionExpr::Count {
                predicate,
                window_ms,
                threshold,
            } => {
                let child = Self::build(predicate, events, time_order, stats);
                let mut prefix = Vec::with_capacity(event_count + 1);
                prefix.push(0_u64);
                for &index in time_order {
                    let next = prefix.last().copied().unwrap_or_default()
                        + u64::from(child.matched[index]);
                    prefix.push(next);
                }
                let matched = (0..event_count)
                    .map(|index| {
                        let anchor = events[index].1.observed_at;
                        let start = anchor.saturating_sub(*window_ms);
                        let lower = time_order
                            .partition_point(|candidate| events[*candidate].1.observed_at < start);
                        let upper = time_order.partition_point(|candidate| {
                            events[*candidate].1.observed_at <= anchor
                        });
                        prefix[upper] - prefix[lower] >= *threshold
                    })
                    .collect();
                // One prefix visit and two binary searches per anchor.  The
                // counter intentionally measures logical work rather than wall
                // time so the regression test is scheduler independent.
                stats.work_units += event_count.saturating_mul(3);
                Self {
                    expr,
                    matched,
                    children: vec![child],
                }
            }
            DetectionExpr::Sequence { steps, within_ms } => {
                let children: Vec<_> = steps
                    .iter()
                    .map(|step| Self::build(step, events, time_order, stats))
                    .collect();
                let mut active: Vec<BTreeSet<usize>> =
                    (0..children.len()).map(|_| BTreeSet::new()).collect();
                let mut matched = vec![false; event_count];
                let mut add_position = 0usize;
                let mut remove_position = 0usize;
                let mut anchor_position = 0usize;

                while anchor_position < time_order.len() {
                    let anchor_time = events[time_order[anchor_position]].1.observed_at;
                    let group_end = time_order[anchor_position..].partition_point(|candidate| {
                        events[*candidate].1.observed_at == anchor_time
                    }) + anchor_position;

                    while add_position < time_order.len()
                        && events[time_order[add_position]].1.observed_at <= anchor_time
                    {
                        let candidate = time_order[add_position];
                        for (step, set) in children.iter().zip(&mut active) {
                            if step.matched[candidate] {
                                set.insert(candidate);
                            }
                        }
                        add_position += 1;
                    }

                    let start = anchor_time.saturating_sub(*within_ms);
                    while remove_position < add_position
                        && events[time_order[remove_position]].1.observed_at < start
                    {
                        let candidate = time_order[remove_position];
                        for set in &mut active {
                            set.remove(&candidate);
                        }
                        remove_position += 1;
                    }

                    for &anchor_index in &time_order[anchor_position..group_end] {
                        let mut cursor = 0usize;
                        let mut found_all = true;
                        for set in &active {
                            if cursor > anchor_index {
                                found_all = false;
                                break;
                            }
                            let found = set.range(cursor..=anchor_index).next().copied();
                            let Some(found) = found else {
                                found_all = false;
                                break;
                            };
                            cursor = found.saturating_add(1);
                        }
                        matched[anchor_index] = found_all;
                    }
                    anchor_position = group_end;
                }
                stats.work_units += event_count.saturating_mul(children.len().saturating_add(2));
                Self {
                    expr,
                    matched,
                    children,
                }
            }
            DetectionExpr::DistinctCount {
                field,
                window_ms,
                threshold,
            } => {
                let values: Vec<Option<Value>> = events
                    .iter()
                    .map(|(_, event)| field_value(field, event))
                    .collect();
                let mut counts: HashMap<Value, usize> = HashMap::new();
                let mut matched = vec![false; event_count];
                let mut add_position = 0usize;
                let mut remove_position = 0usize;
                let mut anchor_position = 0usize;

                while anchor_position < time_order.len() {
                    let anchor_time = events[time_order[anchor_position]].1.observed_at;
                    let group_end = time_order[anchor_position..].partition_point(|candidate| {
                        events[*candidate].1.observed_at == anchor_time
                    }) + anchor_position;
                    while add_position < time_order.len()
                        && events[time_order[add_position]].1.observed_at <= anchor_time
                    {
                        if let Some(value) = &values[time_order[add_position]] {
                            *counts.entry(value.clone()).or_default() += 1;
                        }
                        add_position += 1;
                    }
                    let start = anchor_time.saturating_sub(*window_ms);
                    while remove_position < add_position
                        && events[time_order[remove_position]].1.observed_at < start
                    {
                        if let Some(value) = &values[time_order[remove_position]] {
                            let remove = counts.get(value).is_some_and(|count| *count == 1);
                            if remove {
                                counts.remove(value);
                            } else if let Some(count) = counts.get_mut(value) {
                                *count -= 1;
                            }
                        }
                        remove_position += 1;
                    }
                    let is_match = counts.len() as u64 >= *threshold;
                    for &anchor_index in &time_order[anchor_position..group_end] {
                        matched[anchor_index] = is_match;
                    }
                    anchor_position = group_end;
                }
                stats.work_units += event_count.saturating_mul(3);
                Self {
                    expr,
                    matched,
                    children: Vec::new(),
                }
            }
        }
    }

    fn evidence(&self, index: usize, events: &[EventRef<'_>]) -> EvalResult {
        if !self.matched[index] {
            return EvalResult::default();
        }
        match self.expr {
            DetectionExpr::Eq(_, _)
            | DetectionExpr::Ne(_, _)
            | DetectionExpr::In(_, _)
            | DetectionExpr::Not(_) => EvalResult::single(true, index),
            DetectionExpr::And(_) => {
                let mut evidence = Vec::new();
                for child in &self.children {
                    evidence.extend(child.evidence(index, events).evidence);
                }
                evidence.sort_unstable();
                evidence.dedup();
                EvalResult {
                    matched: true,
                    evidence,
                }
            }
            DetectionExpr::Or(_) => self
                .children
                .iter()
                .find(|child| child.matched[index])
                .map(|child| child.evidence(index, events))
                .unwrap_or_default(),
            DetectionExpr::Count { window_ms, .. } => {
                let anchor = events[index].1.observed_at;
                let start = anchor.saturating_sub(*window_ms);
                let evidence = self.children[0]
                    .matched
                    .iter()
                    .enumerate()
                    .filter_map(|(candidate, matched)| {
                        let observed_at = events[candidate].1.observed_at;
                        (*matched && observed_at >= start && observed_at <= anchor)
                            .then_some(candidate)
                    })
                    .collect();
                EvalResult {
                    matched: true,
                    evidence,
                }
            }
            DetectionExpr::Sequence { within_ms, .. } => {
                let anchor = events[index].1.observed_at;
                let start = anchor.saturating_sub(*within_ms);
                let mut cursor = 0usize;
                let mut evidence = Vec::with_capacity(self.children.len());
                for step in &self.children {
                    if cursor > index {
                        return EvalResult::default();
                    }
                    let found = (cursor..=index).find(|candidate| {
                        let observed_at = events[*candidate].1.observed_at;
                        observed_at >= start && observed_at <= anchor && step.matched[*candidate]
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
            DetectionExpr::DistinctCount {
                field, window_ms, ..
            } => {
                let anchor = events[index].1.observed_at;
                let start = anchor.saturating_sub(*window_ms);
                let evidence = events
                    .iter()
                    .enumerate()
                    .filter_map(|(candidate, (_, event))| {
                        (event.observed_at >= start
                            && event.observed_at <= anchor
                            && field_value(field, event).is_some())
                        .then_some(candidate)
                    })
                    .collect();
                EvalResult {
                    matched: true,
                    evidence,
                }
            }
        }
    }
}

fn evaluate_expression<'a>(
    expression: &'a DetectionExpr,
    events: &[EventRef<'_>],
) -> (ExprEvaluation<'a>, EvaluationStats) {
    let mut time_order: Vec<usize> = (0..events.len()).collect();
    time_order.sort_by(|left, right| {
        events[*left]
            .1
            .observed_at
            .cmp(&events[*right].1.observed_at)
            .then_with(|| left.cmp(right))
    });
    let mut stats = EvaluationStats::default();
    let evaluation = ExprEvaluation::build(expression, events, &time_order, &mut stats);
    (evaluation, stats)
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

    /// A janela que o histórico L1 tem de reter para que NENHUMA regra deste
    /// motor perca uma correspondência: o máximo de
    /// [`DetectionExpr::max_window_ms`] sobre todas as regras.
    pub fn required_window_ms(&self) -> u64 {
        self.rules
            .iter()
            .map(|rule| rule.expression.max_window_ms())
            .max()
            .unwrap_or(0)
    }

    pub fn evaluate(
        &self,
        window: &[(heraclitus_core::Lsn, SecurityEvent)],
    ) -> Vec<SecuritySignal> {
        let mut signals = Vec::new();
        for rule in &self.rules {
            // Keep only references here.  SecurityEvent owns several strings
            // and maps; cloning the complete history once per rule made peak
            // memory proportional to rules * history.
            let eligible: Vec<EventRef<'_>> = window
                .iter()
                .filter(|(_, event)| rule.consume_derived || !is_derived(event))
                .collect();
            if eligible.is_empty() {
                continue;
            }
            let (evaluation, _) = evaluate_expression(&rule.expression, &eligible);
            let Some(index) = evaluation.matched.iter().position(|matched| *matched) else {
                continue;
            };
            let indices = evaluation.evidence(index, &eligible).evidence;
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

    #[test]
    fn bottom_up_evaluator_matches_reference_for_nested_and_out_of_order_events() {
        let mut rows = vec![
            event(1, Outcome::Failure),
            event(2, Outcome::Success),
            event(3, Outcome::Failure),
            event(4, Outcome::Failure),
            event(5, Outcome::Success),
            event(6, Outcome::Failure),
            event(7, Outcome::Failure),
            event(8, Outcome::Success),
        ];
        // Transaction order and event time are intentionally different.  The
        // optimized evaluator must preserve the existing late-event semantics.
        let observed_at = [4_000, 1_000, 3_000, 3_000, 9_000, 2_000, 8_000, 5_000];
        let users = [
            "alice", "alice", "bob", "carol", "bob", "dave", "alice", "eve",
        ];
        for ((_, value), (time, user)) in rows.iter_mut().zip(observed_at.into_iter().zip(users)) {
            value.observed_at = time;
            value.attributes.insert("user-key".into(), user.into());
        }

        let failure = DetectionExpr::Eq(Field::Outcome, Value::String("failure".into()));
        let success = DetectionExpr::Eq(Field::Outcome, Value::String("success".into()));
        let expressions = vec![
            failure.clone(),
            DetectionExpr::Not(Box::new(failure.clone())),
            DetectionExpr::And(vec![
                failure.clone(),
                DetectionExpr::Ne(Field::Severity, Value::Number(99)),
            ]),
            DetectionExpr::Or(vec![success.clone(), failure.clone()]),
            DetectionExpr::Count {
                predicate: Box::new(failure.clone()),
                window_ms: 3_000,
                threshold: 3,
            },
            DetectionExpr::Count {
                predicate: Box::new(DetectionExpr::DistinctCount {
                    field: Field::Attribute("user-key".into()),
                    window_ms: 2_000,
                    threshold: 2,
                }),
                window_ms: 4_000,
                threshold: 2,
            },
            DetectionExpr::DistinctCount {
                field: Field::Attribute("user-key".into()),
                window_ms: 3_000,
                threshold: 3,
            },
            DetectionExpr::Sequence {
                steps: vec![failure.clone(), success.clone(), failure.clone()],
                within_ms: 7_000,
            },
            // More steps than positions exercises cursor > anchor without a
            // BTreeSet range panic.
            DetectionExpr::Sequence {
                steps: vec![failure.clone(), failure.clone(), failure],
                within_ms: 1_000,
            },
        ];

        let refs: Vec<EventRef<'_>> = rows.iter().collect();
        for expression in expressions {
            let (optimized, _) = evaluate_expression(&expression, &refs);
            for index in 0..rows.len() {
                let reference = expression.matches(index, &rows);
                assert_eq!(
                    optimized.matched[index], reference.matched,
                    "match differs for {expression:?} at anchor {index}"
                );
                if reference.matched {
                    assert_eq!(
                        optimized.evidence(index, &refs).evidence,
                        reference.evidence,
                        "evidence differs for {expression:?} at anchor {index}"
                    );
                }
            }
        }
    }

    #[test]
    fn count_evaluation_work_is_linear_after_single_time_ordering() {
        fn measured_work(event_count: usize) -> usize {
            let rows: Vec<_> = (0..event_count)
                .map(|index| event(index as u64 + 1, Outcome::Failure))
                .collect();
            let refs: Vec<EventRef<'_>> = rows.iter().collect();
            let expression = DetectionExpr::Count {
                predicate: Box::new(DetectionExpr::Eq(
                    Field::Outcome,
                    Value::String("failure".into()),
                )),
                window_ms: u64::MAX,
                threshold: u64::MAX,
            };
            let (_, stats) = evaluate_expression(&expression, &refs);
            stats.work_units
        }

        let small = measured_work(1_024);
        let large = measured_work(2_048);
        assert_eq!(large, small * 2);
        // The previous implementation performed 1,048,576 candidate visits
        // for the small input and 4,194,304 for the large one.  The new plan
        // performs four logical visits per row; sorting event time is done once.
        assert_eq!(small, 4 * 1_024);
    }
}

#[cfg(test)]
mod horizonte_tests {
    use super::*;

    fn pontual() -> DetectionExpr {
        DetectionExpr::Eq(Field::Outcome, Value::String("failure".into()))
    }

    #[test]
    fn nos_pontuais_nao_exigem_horizonte() {
        assert_eq!(pontual().max_window_ms(), 0);
        assert_eq!(DetectionExpr::Not(Box::new(pontual())).max_window_ms(), 0);
        assert_eq!(
            DetectionExpr::And(vec![pontual(), pontual()]).max_window_ms(),
            0
        );
    }

    #[test]
    fn o_horizonte_e_a_maior_janela_em_qualquer_profundidade() {
        let count = DetectionExpr::Count {
            predicate: Box::new(pontual()),
            window_ms: 10_000,
            threshold: 2,
        };
        let distinct = DetectionExpr::DistinctCount {
            field: Field::Outcome,
            window_ms: 60_000,
            threshold: 3,
        };
        let seq = DetectionExpr::Sequence {
            steps: vec![pontual(), count.clone()],
            within_ms: 5_000,
        };
        assert_eq!(count.max_window_ms(), 10_000);
        assert_eq!(seq.max_window_ms(), 10_000, "uma janela aninhada num passo conta");
        let aninhado = DetectionExpr::Or(vec![
            DetectionExpr::Not(Box::new(distinct.clone())),
            seq.clone(),
        ]);
        assert_eq!(aninhado.max_window_ms(), 60_000);

        let engine = RuleEngine::new([
            DetectionRule::new("a", "1.0.0", seq, 1),
            DetectionRule::new("b", "1.0.0", aninhado, 1),
        ])
        .unwrap();
        assert_eq!(engine.required_window_ms(), 60_000);
    }
}
