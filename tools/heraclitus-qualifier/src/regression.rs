//! Performance and reliability regression, and the golden release
//! (SPEC-0049 §126–§130).
//!
//! §127 is the constraint that shapes this module: *"Nenhum número universal
//! deve ser hardcoded sem dados históricos."* So the budgets are not in the
//! code. They come from a file the operator writes against their own baseline,
//! and a metric with no declared budget is reported as a change without a
//! verdict — never quietly passed.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::manifest::QualificationResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Throughput, catch-up rate: a drop is the regression.
    HigherIsBetter,
    /// Latency, recovery time, memory, restore duration: a rise is the
    /// regression. §128 puts election and restore times in this class.
    LowerIsBetter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricBudget {
    pub metric: String,
    pub direction: Direction,
    /// Fraction of the baseline the candidate may move in the bad direction
    /// before review is required. `0.10` means ten percent worse.
    pub tolerance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegressionBudgets {
    pub schema_version: u32,
    pub description: String,
    pub budgets: Vec<MetricBudget>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Improved,
    WithinBudget,
    /// Worse than the declared tolerance. §127: this triggers manual review,
    /// it is not an automatic release block.
    ReviewRequired,
    /// Present on one side only, or no budget declared.
    Undetermined,
}

#[derive(Debug, Serialize)]
pub struct MetricComparison {
    pub metric: String,
    pub baseline: Option<f64>,
    pub candidate: Option<f64>,
    pub direction: Option<Direction>,
    pub tolerance: Option<f64>,
    /// Signed fraction, positive when the candidate is worse.
    pub relative_change: Option<f64>,
    pub verdict: Verdict,
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegressionReport {
    pub schema_version: u32,
    pub generator: String,
    pub baseline_release: String,
    pub baseline_qualification_id: String,
    pub candidate_release: String,
    pub candidate_qualification_id: String,
    pub comparisons: Vec<MetricComparison>,
    pub review_required: usize,
    pub undetermined: usize,
    /// §129 — a release only replaces the golden one after full qualification,
    /// so this is the extra condition on top of "no regression".
    pub candidate_is_qualified: bool,
    pub eligible_as_golden: bool,
}

fn read_result(evidence: &Path) -> Result<QualificationResult> {
    let path = evidence.join("qualification-result.json");
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

/// Flatten every trial's metrics into `gate.metric` keys, which is what a
/// budget file names.
pub fn metrics_of(result: &QualificationResult) -> BTreeMap<String, f64> {
    let mut flat = BTreeMap::new();
    for trial in &result.trials {
        for (name, value) in &trial.metrics {
            flat.insert(format!("{}.{name}", trial.trial), *value);
        }
    }
    flat
}

/// Positive means the candidate moved in the bad direction, whatever "bad"
/// means for this metric.
pub fn relative_change(baseline: f64, candidate: f64, direction: Direction) -> Option<f64> {
    if baseline == 0.0 {
        // Dividing by a zero baseline yields infinity, which reads as a
        // catastrophic regression when it is really an absent measurement.
        return None;
    }
    let raw = (candidate - baseline) / baseline.abs();
    Some(match direction {
        Direction::HigherIsBetter => -raw,
        Direction::LowerIsBetter => raw,
    })
}

pub fn compare(
    baseline: &BTreeMap<String, f64>,
    candidate: &BTreeMap<String, f64>,
    budgets: &RegressionBudgets,
) -> Vec<MetricComparison> {
    let by_metric = budgets
        .budgets
        .iter()
        .map(|budget| (budget.metric.as_str(), budget))
        .collect::<BTreeMap<_, _>>();
    let mut names = baseline.keys().cloned().collect::<std::collections::BTreeSet<_>>();
    names.extend(candidate.keys().cloned());
    names.extend(by_metric.keys().map(|name| (*name).to_owned()));

    names
        .into_iter()
        .map(|metric| {
            let base = baseline.get(&metric).copied();
            let cand = candidate.get(&metric).copied();
            let budget = by_metric.get(metric.as_str());
            let (verdict, change, note) = match (base, cand, budget) {
                (Some(base), Some(cand), Some(budget)) => {
                    match relative_change(base, cand, budget.direction) {
                        Some(change) if change <= 0.0 => {
                            (Verdict::Improved, Some(change), None)
                        }
                        Some(change) if change <= budget.tolerance => {
                            (Verdict::WithinBudget, Some(change), None)
                        }
                        Some(change) => (Verdict::ReviewRequired, Some(change), None),
                        None => (
                            Verdict::Undetermined,
                            None,
                            Some("baseline is zero; a ratio would be meaningless".to_owned()),
                        ),
                    }
                }
                (Some(_), Some(_), None) => (
                    Verdict::Undetermined,
                    None,
                    Some("no budget declared for this metric".to_owned()),
                ),
                (None, Some(_), _) => (
                    Verdict::Undetermined,
                    None,
                    Some("metric is new in the candidate".to_owned()),
                ),
                (Some(_), None, _) => (
                    Verdict::Undetermined,
                    None,
                    Some("metric disappeared in the candidate".to_owned()),
                ),
                (None, None, _) => (
                    Verdict::Undetermined,
                    None,
                    Some("budget names a metric neither run measured".to_owned()),
                ),
            };
            MetricComparison {
                metric,
                baseline: base,
                candidate: cand,
                direction: budget.map(|budget| budget.direction),
                tolerance: budget.map(|budget| budget.tolerance),
                relative_change: change,
                verdict,
                note,
            }
        })
        .collect()
}

pub fn run(
    baseline_evidence: &Path,
    candidate_evidence: &Path,
    budgets_path: &Path,
    output: &Path,
) -> Result<RegressionReport> {
    if output.exists() {
        bail!(
            "refusing to overwrite regression report {}",
            output.display()
        );
    }
    let budgets_text = std::fs::read_to_string(budgets_path)
        .with_context(|| format!("read budgets {}", budgets_path.display()))?;
    let budgets: RegressionBudgets =
        serde_json::from_str(&budgets_text).context("parse regression budgets")?;
    if budgets.schema_version != 1 {
        bail!("unsupported budget schema {}", budgets.schema_version);
    }
    let baseline = read_result(baseline_evidence)?;
    let candidate = read_result(candidate_evidence)?;
    let comparisons = compare(&metrics_of(&baseline), &metrics_of(&candidate), &budgets);
    let review_required = comparisons
        .iter()
        .filter(|comparison| comparison.verdict == Verdict::ReviewRequired)
        .count();
    let undetermined = comparisons
        .iter()
        .filter(|comparison| comparison.verdict == Verdict::Undetermined)
        .count();
    let report = RegressionReport {
        schema_version: 1,
        generator: format!("heraclitus-qualifier/{}", env!("CARGO_PKG_VERSION")),
        baseline_release: baseline.release_version.clone(),
        baseline_qualification_id: baseline.qualification_id.clone(),
        candidate_release: candidate.release_version.clone(),
        candidate_qualification_id: candidate.qualification_id.clone(),
        comparisons,
        review_required,
        undetermined,
        candidate_is_qualified: candidate.passed,
        eligible_as_golden: candidate.passed && review_required == 0,
    };
    crate::evidence::write_json_new(output, &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budgets() -> RegressionBudgets {
        RegressionBudgets {
            schema_version: 1,
            description: "test".to_owned(),
            budgets: vec![
                MetricBudget {
                    metric: "q1_load.throughput_ops_s".to_owned(),
                    direction: Direction::HigherIsBetter,
                    tolerance: 0.10,
                },
                MetricBudget {
                    metric: "q1_load.p99_ms".to_owned(),
                    direction: Direction::LowerIsBetter,
                    tolerance: 0.10,
                },
            ],
        }
    }

    fn map(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), *value))
            .collect()
    }

    #[test]
    fn direction_decides_which_way_is_worse() {
        // Throughput falling 20% is a regression; latency falling 20% is not.
        assert_eq!(
            relative_change(100.0, 80.0, Direction::HigherIsBetter),
            Some(0.2)
        );
        assert_eq!(
            relative_change(100.0, 80.0, Direction::LowerIsBetter),
            Some(-0.2)
        );
    }

    #[test]
    fn a_throughput_drop_beyond_tolerance_asks_for_review() {
        let comparisons = compare(
            &map(&[("q1_load.throughput_ops_s", 10_000.0)]),
            &map(&[("q1_load.throughput_ops_s", 8_000.0)]),
            &budgets(),
        );
        let throughput = comparisons
            .iter()
            .find(|comparison| comparison.metric == "q1_load.throughput_ops_s")
            .unwrap();
        assert_eq!(throughput.verdict, Verdict::ReviewRequired);
        assert!((throughput.relative_change.unwrap() - 0.2).abs() < 1e-9);
    }

    #[test]
    fn a_small_move_inside_tolerance_passes_and_an_improvement_is_named() {
        let comparisons = compare(
            &map(&[("q1_load.p99_ms", 10.0), ("q1_load.throughput_ops_s", 100.0)]),
            &map(&[("q1_load.p99_ms", 10.5), ("q1_load.throughput_ops_s", 130.0)]),
            &budgets(),
        );
        let by = |name: &str| {
            comparisons
                .iter()
                .find(|comparison| comparison.metric == name)
                .unwrap()
                .verdict
        };
        assert_eq!(by("q1_load.p99_ms"), Verdict::WithinBudget);
        assert_eq!(by("q1_load.throughput_ops_s"), Verdict::Improved);
    }

    #[test]
    fn a_metric_without_a_budget_is_undetermined_never_a_silent_pass() {
        let comparisons = compare(
            &map(&[("q2_failure.restart_ms", 100.0)]),
            &map(&[("q2_failure.restart_ms", 9_000.0)]),
            &budgets(),
        );
        let restart = comparisons
            .iter()
            .find(|comparison| comparison.metric == "q2_failure.restart_ms")
            .unwrap();
        assert_eq!(restart.verdict, Verdict::Undetermined);
        assert!(restart.note.as_deref().unwrap().contains("no budget"));
    }

    #[test]
    fn the_shipped_budget_file_parses_and_names_a_direction_for_every_metric() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../qa/qualification/regression-budgets.json");
        let text = std::fs::read_to_string(&path).unwrap();
        let budgets: RegressionBudgets = serde_json::from_str(&text).unwrap();
        assert_eq!(budgets.schema_version, 1);
        assert!(!budgets.budgets.is_empty());
        for budget in &budgets.budgets {
            // A tolerance of zero forbids any movement at all, which reads as a
            // budget but behaves as a tripwire; a negative one is nonsense.
            assert!(
                budget.tolerance > 0.0 && budget.tolerance < 1.0,
                "{} has an unusable tolerance {}",
                budget.metric,
                budget.tolerance
            );
            assert!(budget.metric.contains('.'), "{}", budget.metric);
        }
    }

    #[test]
    fn a_zero_baseline_does_not_become_an_infinite_regression() {
        assert_eq!(relative_change(0.0, 5.0, Direction::LowerIsBetter), None);
        let comparisons = compare(
            &map(&[("q1_load.p99_ms", 0.0)]),
            &map(&[("q1_load.p99_ms", 5.0)]),
            &budgets(),
        );
        assert_eq!(comparisons[0].verdict, Verdict::Undetermined);
    }
}
