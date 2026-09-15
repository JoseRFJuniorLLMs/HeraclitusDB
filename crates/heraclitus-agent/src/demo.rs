//! SPEC-0076 §21–§22 — o demo canónico.
//!
//! # A demo, escrita por extenso
//!
//! ```text
//! 1. agente tenta usar ferramenta
//! 2. Heraclitus regista intenção
//! 3. policy exige aprovação
//! 4. humano aprova
//! 5. ferramenta executa
//! 6. resultado é registado
//! 7. timeline mostra tudo
//! 8. bundle é exportado
//! 9. um byte é adulterado
//! 10. verifier recusa o bundle adulterado
//! ```
//!
//! Este módulo produz os passos 1 a 6. Sem chave de API, sem serviço pago, sem
//! rede: é um gerador determinístico de evidência que escreve no mesmo HRKL que
//! a ingestão real usa, pelo mesmo caminho.
//!
//! # Porque determinístico
//!
//! Porque o demo é também um teste de aceitação. Se produzisse ULIDs e relógios
//! novos a cada execução, não se poderia afirmar nada sobre o resultado — e a
//! primeira coisa que um utilizador faz com `heraclitus agent demo` é comparar
//! o que vê com o que a documentação diz que vai ver.

use crate::action::{argument_digest, ActionAuthorizationV1};
use crate::dedupe;
use crate::evidence::{
    AgentEvidenceKindV1, AgentEvidenceV1, AgentIdentityV1, ApprovalProvenanceV1, EvidenceOutcomeV1,
    EvidenceSourceV1, HumanIdentityRefV1, PolicyProvenanceV1,
};
use crate::policy::{DeterministicAgentPolicyEngine, PolicyInput, PolicyValueV1};
use std::collections::BTreeMap;

/// A policy do demo. É a mesma forma que a SPEC-0075 §11 mostra.
pub const DEMO_POLICY: &str = r#"version: "agent-policy-v1"
id: "demo-policy"
revision: "v1"

defaults:
  decision: deny

rules:
  - id: vendor-lookup
    match:
      server: finance
      tool: lookup_vendor
    decision: allow

  - id: finance-small
    match:
      server: finance
      tool: send_payment
      conditions:
        - field: amount
          op: lte
          value: 5000
    decision: require_approval
    approval:
      roles: ["finance-operator"]
      ttl_seconds: 300

  - id: finance-large
    match:
      server: finance
      tool: send_payment
      conditions:
        - field: amount
          op: gt
          value: 5000
    decision: require_approval
    approval:
      roles: ["cfo"]
      ttl_seconds: 180
"#;

/// Quem o demo encena.
pub const DEMO_AGENT: &str = "procurement-agent";
pub const DEMO_TENANT: &str = "default";
pub const DEMO_HUMAN: &str = "jose@example";
pub const DEMO_APPROVER: &str = "finance-cfo";

/// O run gerado.
#[derive(Debug, Clone)]
pub struct DemoRun {
    pub run_id: String,
    pub evidences: Vec<AgentEvidenceV1>,
}

/// Gera o run canónico. `base_unix_nanos` é o relógio — explícito, para que o
/// demo seja reprodutível.
pub fn build_demo_run(base_unix_nanos: u64, run_id: &str) -> DemoRun {
    let engine = DeterministicAgentPolicyEngine::parse(DEMO_POLICY)
        .expect("a policy do demo é literal e válida");
    let mut out: Vec<AgentEvidenceV1> = Vec::new();
    let mut t = base_unix_nanos;
    let mut tick = |step: u64| {
        t += step;
        t
    };

    let push = |e: AgentEvidenceV1, out: &mut Vec<AgentEvidenceV1>| -> String {
        let mut e = e;
        e.dedupe_key = dedupe::dedupe_key(&e);
        e.evidence_id = crate::otlp::derive_evidence_id(&e.dedupe_key);
        let id = e.evidence_id.clone();
        out.push(e);
        id
    };

    let run_started = push(
        base(run_id, AgentEvidenceKindV1::RunStarted, tick(0), 0),
        &mut out,
    );

    // 1. O modelo escolhe a ferramenta.
    let mut model = base(
        run_id,
        AgentEvidenceKindV1::ModelInvocationFinished,
        tick(1_000_000_000),
        1,
    );
    model.subject.model_id = Some("demo-model".into());
    model.subject.model_provider = Some("demo".into());
    model.parents = vec![run_started.clone()];
    let model_id = push(model, &mut out);

    // 2. Consulta de fornecedor: a policy permite.
    let lookup = tool_sequence(
        &engine,
        run_id,
        "lookup_vendor",
        "call-lookup-1",
        &[],
        &mut tick,
        &model_id,
        None,
    );
    let mut lookup_last = model_id.clone();
    for e in lookup {
        lookup_last = push(e, &mut out);
    }

    // 3. Pagamento grande: a policy exige aprovação do CFO.
    let mut args = BTreeMap::new();
    args.insert("amount".to_string(), "75000".to_string());
    args.insert("account".to_string(), "vendor-8832".to_string());
    let digest = argument_digest(&args);
    let authorization = ActionAuthorizationV1 {
        authorization_id: "AZ-DEMO-1".into(),
        request_id: "call-pay-1".into(),
        policy_id: engine.document().id.clone(),
        policy_version: engine.revision().to_string(),
        policy_hash: engine.hash().to_string(),
        rule_id: "finance-large".into(),
        agent_subject: DEMO_AGENT.into(),
        human_subject: Some(DEMO_HUMAN.into()),
        resource_id: "mcp://finance/send_payment".into(),
        action: "send_payment".into(),
        argument_digest: digest.clone(),
        issued_at: base_unix_nanos / 1_000_000_000,
        expires_at: base_unix_nanos / 1_000_000_000 + 180,
        nonce: "demo-nonce".into(),
    };
    let subject_hash = authorization.subject_hash();

    let pay = tool_sequence(
        &engine,
        run_id,
        "send_payment",
        "call-pay-1",
        &[
            ("amount", PolicyValueV1::Int(75_000)),
            ("account", PolicyValueV1::Str("vendor-8832".into())),
        ],
        &mut tick,
        &lookup_last,
        Some((&authorization, &subject_hash)),
    );
    let mut last = lookup_last;
    for e in pay {
        last = push(e, &mut out);
    }

    // 4. O efeito externo e a saída do agente.
    let mut effect = base(
        run_id,
        AgentEvidenceKindV1::ExternalEffectObserved,
        tick(1_000_000_000),
        8,
    );
    effect.subject.tool_name = Some("send_payment".into());
    effect.subject.server_id = Some("finance".into());
    effect.subject.external_effect_id = Some("payment-84723".into());
    effect.parents = vec![last.clone()];
    let effect_id = push(effect, &mut out);

    let mut output = base(
        run_id,
        AgentEvidenceKindV1::AgentOutputProduced,
        tick(500_000_000),
        9,
    );
    output.parents = vec![effect_id];
    let output_id = push(output, &mut out);

    let mut finished = base(
        run_id,
        AgentEvidenceKindV1::RunFinished,
        tick(200_000_000),
        10,
    );
    finished.parents = vec![output_id];
    push(finished, &mut out);

    DemoRun {
        run_id: run_id.to_string(),
        evidences: out,
    }
}

fn base(run_id: &str, kind: AgentEvidenceKindV1, at: u64, seq: u64) -> AgentEvidenceV1 {
    let mut e = AgentEvidenceV1::new(DEMO_TENANT, kind, at);
    e.run_id = Some(run_id.to_string());
    e.session_id = Some(format!("{run_id}-session"));
    e.trace_id = Some(format!("{run_id}-trace"));
    e.agent = AgentIdentityV1 {
        agent_id: DEMO_AGENT.to_string(),
        agent_name: Some("Procurement Agent".to_string()),
        framework: Some("heraclitus-demo".to_string()),
        framework_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        ..Default::default()
    };
    e.human = Some(HumanIdentityRefV1 {
        subject_id: DEMO_HUMAN.to_string(),
        issuer: Some("demo".to_string()),
        display_hint: Some("José".to_string()),
    });
    e.source = EvidenceSourceV1 {
        source_kind: "demo".to_string(),
        source_instance: Some("heraclitus agent demo".to_string()),
        source_sequence: Some(seq),
        received_at_unix_nanos: None,
    };
    e
}

/// A sequência de uma tool call: pedido, decisão, (aprovação), execução,
/// resultado.
#[allow(clippy::too_many_arguments)]
fn tool_sequence(
    engine: &DeterministicAgentPolicyEngine,
    run_id: &str,
    tool: &str,
    call_id: &str,
    fields: &[(&str, PolicyValueV1)],
    tick: &mut impl FnMut(u64) -> u64,
    parent: &str,
    approval: Option<(&ActionAuthorizationV1, &str)>,
) -> Vec<AgentEvidenceV1> {
    let input = PolicyInput {
        server_id: "finance".into(),
        tool_name: tool.into(),
        agent_subject: DEMO_AGENT.into(),
        environment: Some("production".into()),
        protocol: Some("mcp".into()),
        fields: fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
        now_unix_seconds: 0,
    };
    let eval = engine.evaluate(&input);
    let provenance = PolicyProvenanceV1 {
        policy_id: eval.policy_id.clone(),
        policy_version: eval.policy_version.clone(),
        policy_hash: eval.policy_hash.clone(),
        rule_id: eval.rule_id.clone(),
        decision: eval.decision.label().to_string(),
        reason_code: eval.reason_code.clone(),
        input_projection_hash: eval.input_projection_hash.clone(),
        authorization_id: approval.map(|(a, _)| a.authorization_id.clone()),
        enforced: true,
    };

    let mut out = Vec::new();
    let mut requested = base(
        run_id,
        AgentEvidenceKindV1::ToolRequested,
        tick(500_000_000),
        100,
    );
    requested.subject.protocol = Some("mcp".into());
    requested.subject.server_id = Some("finance".into());
    requested.subject.tool_name = Some(tool.to_string());
    requested.subject.tool_call_id = Some(call_id.to_string());
    for (k, v) in fields {
        requested
            .content
            .fields
            .insert((*k).to_string(), v.as_text());
    }
    requested.content.canonical_content_hash = approval.map(|(a, _)| a.argument_digest.clone());
    requested.parents = vec![parent.to_string()];
    out.push(requested);

    let mut evaluated = base(
        run_id,
        AgentEvidenceKindV1::PolicyEvaluated,
        tick(50_000_000),
        101,
    );
    evaluated.subject.tool_name = Some(tool.to_string());
    evaluated.subject.server_id = Some("finance".into());
    evaluated.subject.tool_call_id = Some(call_id.to_string());
    evaluated.content.policy = Some(provenance.clone());
    out.push(evaluated);

    if let Some((_, subject_hash)) = approval {
        let prov = ApprovalProvenanceV1 {
            approval_id: "A-DEMO-1".to_string(),
            authorization_subject_hash: subject_hash.to_string(),
            approver_subject: Some(DEMO_APPROVER.to_string()),
            approver_issuer: Some("demo".to_string()),
            decided_at_unix_nanos: None,
        };
        let mut asked = base(
            run_id,
            AgentEvidenceKindV1::HumanApprovalRequested,
            tick(100_000_000),
            102,
        );
        asked.subject.tool_name = Some(tool.to_string());
        asked.subject.tool_call_id = Some(call_id.to_string());
        asked.content.approval = Some(ApprovalProvenanceV1 {
            approver_subject: None,
            approver_issuer: None,
            ..prov.clone()
        });
        asked.content.policy = Some(provenance.clone());
        out.push(asked);

        let at = tick(12_000_000_000);
        let mut granted = base(run_id, AgentEvidenceKindV1::HumanApprovalGranted, at, 103);
        granted.subject.tool_name = Some(tool.to_string());
        granted.subject.tool_call_id = Some(call_id.to_string());
        granted.content.approval = Some(ApprovalProvenanceV1 {
            decided_at_unix_nanos: Some(at),
            ..prov
        });
        granted.content.policy = Some(provenance.clone());
        out.push(granted);
    }

    let mut authorized = base(
        run_id,
        AgentEvidenceKindV1::ToolAuthorized,
        tick(50_000_000),
        104,
    );
    authorized.subject.tool_name = Some(tool.to_string());
    authorized.subject.server_id = Some("finance".into());
    authorized.subject.tool_call_id = Some(call_id.to_string());
    authorized.content.policy = Some(provenance.clone());
    out.push(authorized);

    let mut started = base(
        run_id,
        AgentEvidenceKindV1::ToolInvocationStarted,
        tick(20_000_000),
        105,
    );
    started.subject.protocol = Some("mcp".into());
    started.subject.server_id = Some("finance".into());
    started.subject.tool_name = Some(tool.to_string());
    started.subject.tool_call_id = Some(call_id.to_string());
    out.push(started);

    let mut finished = base(
        run_id,
        AgentEvidenceKindV1::ToolInvocationFinished,
        tick(800_000_000),
        106,
    );
    finished.subject.protocol = Some("mcp".into());
    finished.subject.server_id = Some("finance".into());
    finished.subject.tool_name = Some(tool.to_string());
    finished.subject.tool_call_id = Some(call_id.to_string());
    finished.outcome = Some(EvidenceOutcomeV1 {
        transport_status: Some(200),
        protocol_status: Some("ok".into()),
        duration_nanos: Some(800_000_000),
        ..Default::default()
    });
    if tool == "send_payment" {
        finished.subject.external_effect_id = Some("payment-84723".into());
    }
    out.push(finished);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection;
    use crate::store::StoredEvidence;

    fn rows() -> Vec<StoredEvidence> {
        build_demo_run(1_700_000_000_000_000_000, "01DEMO")
            .evidences
            .into_iter()
            .enumerate()
            .map(|(i, evidence)| StoredEvidence {
                lsn: i as u64 + 1,
                evidence,
            })
            .collect()
    }

    #[test]
    fn o_demo_e_deterministico() {
        let a = build_demo_run(1_700_000_000_000_000_000, "01DEMO");
        let b = build_demo_run(1_700_000_000_000_000_000, "01DEMO");
        assert_eq!(a.evidences, b.evidences);
    }

    #[test]
    fn a_timeline_do_demo_mostra_a_historia_toda() {
        let tl = projection::project_timeline(&rows(), "01DEMO");
        let kinds: Vec<&str> = tl.iter().map(|t| t.kind.as_str()).collect();
        for esperado in [
            "RunStarted",
            "ToolRequested",
            "PolicyEvaluated",
            "HumanApprovalRequested",
            "HumanApprovalGranted",
            "ToolAuthorized",
            "ToolInvocationFinished",
            "ExternalEffectObserved",
            "RunFinished",
        ] {
            assert!(kinds.contains(&esperado), "faltou {esperado}: {kinds:?}");
        }
    }

    #[test]
    fn o_pagamento_grande_exige_o_cfo() {
        let rows = rows();
        let decisoes = projection::project_policy_decisions(&rows);
        let pay = decisoes
            .iter()
            .find(|d| d.tool_name.as_deref() == Some("send_payment"))
            .unwrap();
        assert_eq!(pay.rule_id.as_deref(), Some("finance-large"));
        assert_eq!(pay.decision, "require_approval");
    }

    #[test]
    fn a_consulta_de_fornecedor_e_permitida() {
        let rows = rows();
        let decisoes = projection::project_policy_decisions(&rows);
        let lookup = decisoes
            .iter()
            .find(|d| d.tool_name.as_deref() == Some("lookup_vendor"))
            .unwrap();
        assert_eq!(lookup.decision, "allow");
    }

    #[test]
    fn as_tool_calls_do_demo_ficam_completas() {
        let calls = projection::project_tool_calls(&rows());
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|c| c.complete), "{calls:#?}");
    }

    #[test]
    fn a_aprovacao_esta_ligada_ao_hash_do_assunto() {
        let aprovacoes = projection::project_approvals(&rows());
        assert_eq!(aprovacoes.len(), 1);
        assert_eq!(aprovacoes[0].granted, Some(true));
        assert_eq!(aprovacoes[0].authorization_subject_hash.len(), 64);
        assert_eq!(
            aprovacoes[0].approver_subject.as_deref(),
            Some(DEMO_APPROVER)
        );
    }

    #[test]
    fn o_run_do_demo_e_um_sucesso_sem_pais_partidos() {
        let rows = rows();
        let runs = projection::project_runs(&rows);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, projection::RunStatus::Success);
        assert_eq!(runs[0].approvals, 1);
        assert!(projection::broken_parents(&rows).is_empty());
    }

    #[test]
    fn o_demo_nao_tem_segredo_nenhum() {
        let dump = serde_json::to_string(&rows()).unwrap();
        for proibido in ["Bearer", "sk-", "password", "api_key"] {
            assert!(!dump.contains(proibido), "{proibido} apareceu no demo");
        }
    }
}
