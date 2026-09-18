use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlStatus {
    Pass,
    Fail,
    Partial,
    NotApplicable,
    External,
    Unknown,
    NotAssessed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Responsibility {
    Software,
    Operator,
    Organization,
    ExternalLab,
    Shared,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormativeReference {
    pub name: String,
    pub authority: String,
    pub reference_code: String,
    pub version: String,
    pub publication_date: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRequirement {
    pub requirement_id: String,
    pub description: String,
    pub artifact_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRef {
    pub check_id: String,
    pub check_type: String,
    pub target_module: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlDefinition {
    pub control_id: String,
    pub title: String,
    pub requirement: String,
    pub responsibility: Responsibility,
    pub evidence_requirements: Vec<EvidenceRequirement>,
    pub automated_checks: Vec<CheckRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBinding {
    pub control_id: String,
    pub status: ControlStatus,
    pub evidence_description: String,
    pub artifact_digest: String,
    pub test_reference: String,
    pub assessed_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceProfile {
    pub id: String,
    pub version: String,
    pub title: String,
    pub effective_from: String,
    pub source_refs: Vec<NormativeReference>,
    pub controls: Vec<ControlDefinition>,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileEvaluationReport {
    pub profile_id: String,
    pub evaluated_at_secs: u64,
    pub controls_evaluated: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub partial_count: usize,
    pub unknown_count: usize,
    pub not_assessed_count: usize,
    pub not_applicable_count: usize,
    pub external_count: usize,
    pub bindings: Vec<EvidenceBinding>,
}

impl ComplianceProfile {
    pub fn lgpd_brazil_profile() -> Self {
        ComplianceProfile {
            id: "LGPD-BR".to_string(),
            version: "1.0".to_string(),
            title: "Lei Geral de Proteção de Dados Pessoais".to_string(),
            effective_from: "2020-09-18".to_string(),
            source_refs: vec![NormativeReference {
                name: "LGPD".to_string(),
                authority: "ANPD".to_string(),
                reference_code: "Lei 13.709/2018".to_string(),
                version: "2018".to_string(),
                publication_date: "2018-08-14".to_string(),
            }],
            controls: vec![ControlDefinition {
                control_id: "LGPD-Art46".to_string(),
                title: "Segurança dos Dados".to_string(),
                requirement: "Adoção de medidas de segurança, técnicas e administrativas".to_string(),
                responsibility: Responsibility::Organization,
                evidence_requirements: vec![],
                automated_checks: vec![],
            }],
            digest: "lgpd-hash".to_string(),
        }
    }

    pub fn ppsi_2_0_profile() -> Self {
        ComplianceProfile {
            id: "PPSI-2.0".to_string(),
            version: "2.0".to_string(),
            title: "Política Nacional de Segurança da Informação".to_string(),
            effective_from: "2026-01-01".to_string(),
            source_refs: vec![NormativeReference {
                name: "PPSI".to_string(),
                authority: "SGD/MGI".to_string(),
                reference_code: "Portaria SGD/MGI 9.511/2025 / IN SGD/MGI 4/2026".to_string(),
                version: "2.0".to_string(),
                publication_date: "2025-10-01".to_string(),
            }],
            controls: vec![ControlDefinition {
                control_id: "PPSI-C1".to_string(),
                title: "Controle de Acesso".to_string(),
                requirement: "Autenticação multifator".to_string(),
                responsibility: Responsibility::Shared,
                evidence_requirements: vec![],
                automated_checks: vec![],
            }],
            digest: "ppsi-hash".to_string(),
        }
    }

    pub fn in_gsi_si_profile() -> Self {
        ComplianceProfile {
            id: "IN-GSI-SI".to_string(),
            version: "1.0".to_string(),
            title: "Instrução Normativa GSI/PR".to_string(),
            effective_from: "2026-01-01".to_string(),
            source_refs: vec![NormativeReference {
                name: "IN-GSI".to_string(),
                authority: "GSI/PR".to_string(),
                reference_code: "IN GSI/PR 1/2020 + 9/2026".to_string(),
                version: "2026".to_string(),
                publication_date: "2026-05-01".to_string(),
            }],
            controls: vec![ControlDefinition {
                control_id: "GSI-R1".to_string(),
                title: "Gestão de Incidentes".to_string(),
                requirement: "Plano de resposta a incidentes".to_string(),
                responsibility: Responsibility::Organization,
                evidence_requirements: vec![],
                automated_checks: vec![],
            }],
            digest: "gsi-hash".to_string(),
        }
    }
}

pub fn evaluate_profile(
    profile: &ComplianceProfile,
    active_evidence: &[EvidenceBinding],
) -> ProfileEvaluationReport {
    let mut pass_count = 0;
    let mut fail_count = 0;
    let mut partial_count = 0;
    let mut unknown_count = 0;
    let mut not_assessed_count = 0;
    let mut not_applicable_count = 0;
    let mut external_count = 0;
    
    let mut bindings = Vec::new();

    let mut evidence_map: HashMap<String, EvidenceBinding> = HashMap::new();
    for evidence in active_evidence {
        evidence_map.insert(evidence.control_id.clone(), evidence.clone());
    }

    for control in &profile.controls {
        if let Some(evidence) = evidence_map.get(&control.control_id) {
            match evidence.status {
                ControlStatus::Pass => pass_count += 1,
                ControlStatus::Fail => fail_count += 1,
                ControlStatus::Partial => partial_count += 1,
                ControlStatus::Unknown => unknown_count += 1,
                ControlStatus::NotAssessed => not_assessed_count += 1,
                ControlStatus::NotApplicable => not_applicable_count += 1,
                ControlStatus::External => external_count += 1,
            }
            bindings.push(evidence.clone());
        } else {
            not_assessed_count += 1;
            bindings.push(EvidenceBinding {
                control_id: control.control_id.clone(),
                status: ControlStatus::NotAssessed,
                evidence_description: "Nenhuma evidência fornecida".to_string(),
                artifact_digest: "".to_string(),
                test_reference: "".to_string(),
                assessed_at_secs: 0,
            });
        }
    }

    ProfileEvaluationReport {
        profile_id: profile.id.clone(),
        evaluated_at_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        controls_evaluated: profile.controls.len(),
        pass_count,
        fail_count,
        partial_count,
        unknown_count,
        not_assessed_count,
        not_applicable_count,
        external_count,
        bindings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lgpd_profile_creation() {
        let profile = ComplianceProfile::lgpd_brazil_profile();
        assert_eq!(profile.id, "LGPD-BR");
        assert_eq!(profile.controls.len(), 1);
    }

    #[test]
    fn test_ppsi_profile_creation() {
        let profile = ComplianceProfile::ppsi_2_0_profile();
        assert_eq!(profile.id, "PPSI-2.0");
        assert_eq!(profile.controls.len(), 1);
    }

    #[test]
    fn test_in_gsi_profile_creation() {
        let profile = ComplianceProfile::in_gsi_si_profile();
        assert_eq!(profile.id, "IN-GSI-SI");
        assert_eq!(profile.controls.len(), 1);
    }

    #[test]
    fn test_evaluate_profile() {
        let profile = ComplianceProfile::lgpd_brazil_profile();
        let ev = EvidenceBinding {
            control_id: "LGPD-Art46".to_string(),
            status: ControlStatus::Pass,
            evidence_description: "Criptografia aplicada".to_string(),
            artifact_digest: "abcd".to_string(),
            test_reference: "test1".to_string(),
            assessed_at_secs: 100,
        };
        let report = evaluate_profile(&profile, &[ev.clone()]);
        
        assert_eq!(report.controls_evaluated, 1);
        assert_eq!(report.pass_count, 1);
        assert_eq!(report.not_assessed_count, 0);
        assert_eq!(report.bindings.len(), 1);
        assert_eq!(report.bindings[0].status, ControlStatus::Pass);
    }

    #[test]
    fn test_evaluate_profile_missing_evidence() {
        let profile = ComplianceProfile::lgpd_brazil_profile();
        let report = evaluate_profile(&profile, &[]);
        
        assert_eq!(report.controls_evaluated, 1);
        assert_eq!(report.pass_count, 0);
        assert_eq!(report.not_assessed_count, 1);
        assert_eq!(report.bindings[0].status, ControlStatus::NotAssessed);
    }

    #[test]
    fn test_evaluate_profile_not_applicable_and_external() {
        let mut profile = ComplianceProfile::lgpd_brazil_profile();
        profile.controls.push(ControlDefinition {
            control_id: "LGPD-Physical".to_string(),
            title: "Segurança Física de Instalações".to_string(),
            requirement: "Controle de portaria predial".to_string(),
            responsibility: Responsibility::Operator,
            evidence_requirements: vec![],
            automated_checks: vec![],
        });
        
        let ev1 = EvidenceBinding {
            control_id: "LGPD-Art46".to_string(),
            status: ControlStatus::NotApplicable,
            evidence_description: "Não aplicável ao escopo".to_string(),
            artifact_digest: "".to_string(),
            test_reference: "".to_string(),
            assessed_at_secs: 100,
        };
        let ev2 = EvidenceBinding {
            control_id: "LGPD-Physical".to_string(),
            status: ControlStatus::External,
            evidence_description: "Atestado de empresa de vigilância".to_string(),
            artifact_digest: "ext-123".to_string(),
            test_reference: "attest-01".to_string(),
            assessed_at_secs: 100,
        };

        let report = evaluate_profile(&profile, &[ev1, ev2]);
        assert_eq!(report.controls_evaluated, 2);
        assert_eq!(report.not_applicable_count, 1);
        assert_eq!(report.external_count, 1);
        assert_eq!(report.pass_count, 0);
        assert_eq!(report.fail_count, 0);
    }
}
