//! Fail-closed gate for SPEC-0045 Autonomous Mode (§114–116).
//!
//! This module does not execute actions.  It only makes it impossible for a
//! host to construct an enabled autonomous state without explicit evidence of
//! every adversarial gate and a representative false-positive benchmark.

use heraclitus_core::Lsn;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AutonomyError {
    #[error("requisito de Autonomous Mode inválido: {0}")]
    InvalidRequirement(String),
    #[error("evidência de Autonomous Mode inválida: {0}")]
    InvalidEvidence(String),
    #[error("Autonomous Mode bloqueado; gates ausentes: {0:?}")]
    GatesNotPassed(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutonomousRequirements {
    pub max_false_positive_rate: f32,
    pub min_benchmark_events: u64,
}

impl Default for AutonomousRequirements {
    fn default() -> Self {
        Self {
            max_false_positive_rate: 0.01,
            min_benchmark_events: 100_000,
        }
    }
}

impl AutonomousRequirements {
    pub fn validate(&self) -> Result<(), AutonomyError> {
        if !self.max_false_positive_rate.is_finite()
            || !(0.0..=1.0).contains(&self.max_false_positive_rate)
            || self.min_benchmark_events == 0
        {
            return Err(AutonomyError::InvalidRequirement(
                "taxa/eventos do benchmark inválidos".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateEvidence {
    pub p0_p2_passed: bool,
    pub c0_c2_passed: bool,
    pub s0_s4_passed: bool,
    pub r0_r3_passed: bool,
    pub benchmark_id: String,
    pub benchmark_events: u64,
    pub false_positive_rate: f32,
}

impl GateEvidence {
    pub fn validate(&self) -> Result<(), AutonomyError> {
        if self.benchmark_id.trim().is_empty() {
            return Err(AutonomyError::InvalidEvidence("benchmark_id vazio".into()));
        }
        if self.benchmark_events == 0
            || !self.false_positive_rate.is_finite()
            || !(0.0..=1.0).contains(&self.false_positive_rate)
        {
            return Err(AutonomyError::InvalidEvidence(
                "benchmark vazio ou taxa inválida".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutonomousMode {
    enabled: bool,
    activated_at_lsn: Lsn,
    benchmark_id: String,
}

impl AutonomousMode {
    pub fn try_enable(
        evidence: GateEvidence,
        requirements: AutonomousRequirements,
        activated_at_lsn: Lsn,
    ) -> Result<Self, AutonomyError> {
        requirements.validate()?;
        evidence.validate()?;
        let mut missing = Vec::new();
        if !evidence.p0_p2_passed {
            missing.push("P0-P2".to_owned());
        }
        if !evidence.c0_c2_passed {
            missing.push("C0-C2".to_owned());
        }
        if !evidence.s0_s4_passed {
            missing.push("S0-S4".to_owned());
        }
        if !evidence.r0_r3_passed {
            missing.push("R0-R3".to_owned());
        }
        if evidence.benchmark_events < requirements.min_benchmark_events {
            missing.push("benchmark-size".to_owned());
        }
        if evidence.false_positive_rate > requirements.max_false_positive_rate {
            missing.push("false-positive-rate".to_owned());
        }
        if !missing.is_empty() {
            return Err(AutonomyError::GatesNotPassed(missing));
        }
        Ok(Self {
            enabled: true,
            activated_at_lsn,
            benchmark_id: evidence.benchmark_id,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn activated_at_lsn(&self) -> Lsn {
        self.activated_at_lsn
    }

    pub fn benchmark_id(&self) -> &str {
        &self.benchmark_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> GateEvidence {
        GateEvidence {
            p0_p2_passed: true,
            c0_c2_passed: true,
            s0_s4_passed: true,
            r0_r3_passed: true,
            benchmark_id: "bench-2026-08".into(),
            benchmark_events: 100,
            false_positive_rate: 0.01,
        }
    }

    #[test]
    fn autonomous_mode_fails_closed_when_any_gate_or_benchmark_is_missing() {
        let mut missing = evidence();
        missing.r0_r3_passed = false;
        let error = AutonomousMode::try_enable(
            missing,
            AutonomousRequirements {
                min_benchmark_events: 100,
                ..AutonomousRequirements::default()
            },
            7,
        )
        .unwrap_err();
        assert!(matches!(error, AutonomyError::GatesNotPassed(_)));
    }

    #[test]
    fn autonomous_mode_requires_all_evidence_and_is_immutable_enabled_state() {
        let mode = AutonomousMode::try_enable(
            evidence(),
            AutonomousRequirements {
                max_false_positive_rate: 0.02,
                min_benchmark_events: 100,
            },
            42,
        )
        .unwrap();
        assert!(mode.is_enabled());
        assert_eq!(mode.activated_at_lsn(), 42);
        assert_eq!(mode.benchmark_id(), "bench-2026-08");
    }
}
