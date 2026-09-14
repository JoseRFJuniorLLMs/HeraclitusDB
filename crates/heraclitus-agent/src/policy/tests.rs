//! SPEC-0075 §32 — os testes obrigatórios da policy.

use super::*;

pub const POLICY_EXEMPLO: &str = r#"
version: "agent-policy-v1"
id: "agent-policy"
revision: "v17"

defaults:
  decision: deny

rules:
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

  - id: vendor-lookup
    match:
      server: finance
      tool: lookup_vendor
    decision: allow

  - id: destructive-shell
    match:
      server: shell
      tool: exec
      conditions:
        - field: command_class
          op: eq
          value: destructive
    decision: deny
"#;

fn engine() -> DeterministicAgentPolicyEngine {
    DeterministicAgentPolicyEngine::parse(POLICY_EXEMPLO).unwrap()
}

fn input(server: &str, tool: &str, fields: &[(&str, PolicyValueV1)]) -> PolicyInput {
    PolicyInput {
        server_id: server.into(),
        tool_name: tool.into(),
        agent_subject: "procurement-agent".into(),
        environment: Some("production".into()),
        protocol: Some("mcp".into()),
        fields: fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
        now_unix_seconds: 1_700_000_000,
    }
}

#[test]
fn default_deny_quando_nada_corresponde() {
    let e = engine();
    let d = e.evaluate(&input("email", "send_message", &[]));
    assert!(matches!(
        d.decision,
        AgentPolicyDecisionV1::Deny { ref reason_code, .. } if reason_code == "DEFAULT_DENY"
    ));
    assert_eq!(d.rule_id, None);
}

#[test]
fn policy_vazia_nega_tudo() {
    let e = DeterministicAgentPolicyEngine::deny_all();
    assert!(e.evaluate(&input("x", "y", &[])).decision.blocks());
}

#[test]
fn correspondencia_exacta_de_ferramenta() {
    let e = engine();
    let d = e.evaluate(&input("finance", "lookup_vendor", &[]));
    assert_eq!(d.decision, AgentPolicyDecisionV1::Allow);
    assert_eq!(d.rule_id.as_deref(), Some("vendor-lookup"));
}

#[test]
fn limiar_numerico_escolhe_o_aprovador() {
    let e = engine();
    let pequeno = e.evaluate(&input(
        "finance",
        "send_payment",
        &[("amount", PolicyValueV1::Int(4_999))],
    ));
    assert!(matches!(
        pequeno.decision,
        AgentPolicyDecisionV1::RequireApproval { ref roles, .. } if roles == &vec!["finance-operator".to_string()]
    ));
    let grande = e.evaluate(&input(
        "finance",
        "send_payment",
        &[("amount", PolicyValueV1::Int(75_000))],
    ));
    assert!(matches!(
        grande.decision,
        AgentPolicyDecisionV1::RequireApproval { ref roles, .. } if roles == &vec!["cfo".to_string()]
    ));
}

#[test]
fn a_fronteira_exacta_fica_com_a_regra_pequena() {
    let e = engine();
    let d = e.evaluate(&input(
        "finance",
        "send_payment",
        &[("amount", PolicyValueV1::Int(5_000))],
    ));
    assert_eq!(d.rule_id.as_deref(), Some("finance-small"));
}

#[test]
fn campo_ausente_nunca_satisfaz_uma_condicao() {
    // Uma acção que não declara `amount` não pode passar por "amount <= 5000".
    let e = engine();
    let d = e.evaluate(&input("finance", "send_payment", &[]));
    assert!(matches!(d.decision, AgentPolicyDecisionV1::Deny { .. }));
}

#[test]
fn decimais_nao_passam_por_f64() {
    // 0.1 + 0.2 > 0.3 em binário. Em dinheiro, não.
    let e = DeterministicAgentPolicyEngine::parse(
        r#"
version: "agent-policy-v1"
rules:
  - id: limite
    match:
      tool: pay
      conditions:
        - field: amount
          op: lte
          value: "0.3"
    decision: allow
"#,
    )
    .unwrap();
    let dentro = e.evaluate(&input(
        "x",
        "pay",
        &[("amount", PolicyValueV1::Str("0.30000000000000004".into()))],
    ));
    assert!(matches!(
        dentro.decision,
        AgentPolicyDecisionV1::Deny { .. }
    ));
    let ok = e.evaluate(&input(
        "x",
        "pay",
        &[("amount", PolicyValueV1::Str("0.3".into()))],
    ));
    assert_eq!(ok.decision, AgentPolicyDecisionV1::Allow);
}

#[test]
fn decimais_com_zeros_a_mais_sao_o_mesmo_numero() {
    let a = Decimal::parse("5000.00").unwrap();
    let b = Decimal::parse("5000").unwrap();
    assert_eq!(compare_decimal(&a, &b), std::cmp::Ordering::Equal);
    let c = Decimal::parse("007.5").unwrap();
    let d = Decimal::parse("7.50").unwrap();
    assert_eq!(compare_decimal(&c, &d), std::cmp::Ordering::Equal);
}

#[test]
fn negativos_ordenam_ao_contrario() {
    let a = Decimal::parse("-10").unwrap();
    let b = Decimal::parse("-2").unwrap();
    assert_eq!(compare_decimal(&a, &b), std::cmp::Ordering::Less);
    let zero = Decimal::parse("-0.0").unwrap();
    let z = Decimal::parse("0").unwrap();
    assert_eq!(compare_decimal(&zero, &z), std::cmp::Ordering::Equal);
}

#[test]
fn o_hash_da_policy_e_estavel_entre_leituras() {
    let a = AgentPolicyDocument::parse(POLICY_EXEMPLO).unwrap();
    let b = AgentPolicyDocument::parse(POLICY_EXEMPLO).unwrap();
    assert_eq!(a.hash(), b.hash());
}

#[test]
fn comentarios_e_indentacao_nao_mudam_o_hash() {
    let a = AgentPolicyDocument::parse(POLICY_EXEMPLO).unwrap();
    let com_comentarios = POLICY_EXEMPLO.replace(
        "  - id: vendor-lookup",
        "  # a consulta de fornecedor é inócua\n  - id: vendor-lookup",
    );
    let b = AgentPolicyDocument::parse(&com_comentarios).unwrap();
    assert_eq!(a.hash(), b.hash());
}

#[test]
fn yaml_e_json_da_mesma_policy_dao_o_mesmo_hash() {
    let doc = AgentPolicyDocument::parse(POLICY_EXEMPLO).unwrap();
    let as_json = serde_json::to_string(&serde_json::json!({
        "version": "agent-policy-v1",
        "id": "agent-policy",
        "revision": "v17",
        "defaults": { "decision": "deny" },
        "rules": [
            { "id": "finance-small",
              "match": { "server": "finance", "tool": "send_payment",
                         "conditions": [{ "field": "amount", "op": "lte", "value": 5000 }] },
              "decision": "require_approval",
              "approval": { "roles": ["finance-operator"], "ttl_seconds": 300 } },
            { "id": "finance-large",
              "match": { "server": "finance", "tool": "send_payment",
                         "conditions": [{ "field": "amount", "op": "gt", "value": 5000 }] },
              "decision": "require_approval",
              "approval": { "roles": ["cfo"], "ttl_seconds": 180 } },
            { "id": "vendor-lookup",
              "match": { "server": "finance", "tool": "lookup_vendor" },
              "decision": "allow" },
            { "id": "destructive-shell",
              "match": { "server": "shell", "tool": "exec",
                         "conditions": [{ "field": "command_class", "op": "eq", "value": "destructive" }] },
              "decision": "deny" }
        ]
    }))
    .unwrap();
    assert_eq!(
        AgentPolicyDocument::parse(&as_json).unwrap().hash(),
        doc.hash()
    );
}

#[test]
fn mudar_uma_regra_muda_o_hash() {
    let a = AgentPolicyDocument::parse(POLICY_EXEMPLO).unwrap();
    let b =
        AgentPolicyDocument::parse(&POLICY_EXEMPLO.replace("value: 5000", "value: 5001")).unwrap();
    assert_ne!(a.hash(), b.hash());
}

#[test]
fn a_ordem_dos_campos_do_input_nao_muda_a_projeccao() {
    let a = input(
        "finance",
        "send_payment",
        &[
            ("amount", PolicyValueV1::Int(5000)),
            ("account", PolicyValueV1::Str("A".into())),
        ],
    );
    let b = input(
        "finance",
        "send_payment",
        &[
            ("account", PolicyValueV1::Str("A".into())),
            ("amount", PolicyValueV1::Int(5000)),
        ],
    );
    assert_eq!(a.projection_hash(), b.projection_hash());
}

#[test]
fn o_tempo_nao_entra_na_projeccao() {
    let mut a = input("finance", "send_payment", &[]);
    let mut b = a.clone();
    a.now_unix_seconds = 1;
    b.now_unix_seconds = 999_999;
    assert_eq!(a.projection_hash(), b.projection_hash());
}

#[test]
fn avaliar_mil_vezes_da_sempre_o_mesmo() {
    let e = engine();
    let i = input(
        "finance",
        "send_payment",
        &[("amount", PolicyValueV1::Int(75_000))],
    );
    let primeiro = e.evaluate(&i);
    for _ in 0..1000 {
        assert_eq!(e.evaluate(&i), primeiro);
    }
}

#[test]
fn reconstruir_o_motor_da_a_mesma_decisao() {
    let a = engine().evaluate(&input(
        "finance",
        "send_payment",
        &[("amount", PolicyValueV1::Int(10))],
    ));
    let b = engine().evaluate(&input(
        "finance",
        "send_payment",
        &[("amount", PolicyValueV1::Int(10))],
    ));
    assert_eq!(a, b);
}

#[test]
fn operadores_de_conjunto() {
    let e = DeterministicAgentPolicyEngine::parse(
        r#"
version: "agent-policy-v1"
rules:
  - id: conhecidos
    match:
      tool: pay
      conditions:
        - field: vendor
          op: in
          value: ["v1", "v2"]
    decision: allow
"#,
    )
    .unwrap();
    assert_eq!(
        e.evaluate(&input(
            "x",
            "pay",
            &[("vendor", PolicyValueV1::Str("v1".into()))]
        ))
        .decision,
        AgentPolicyDecisionV1::Allow
    );
    assert!(e
        .evaluate(&input(
            "x",
            "pay",
            &[("vendor", PolicyValueV1::Str("v9".into()))]
        ))
        .decision
        .blocks());
}

#[test]
fn operador_exists() {
    let e = DeterministicAgentPolicyEngine::parse(
        r#"
version: "agent-policy-v1"
rules:
  - id: exige-justificacao
    match:
      tool: pay
      conditions:
        - field: justification
          op: exists
          value: true
    decision: allow
"#,
    )
    .unwrap();
    assert_eq!(
        e.evaluate(&input(
            "x",
            "pay",
            &[("justification", PolicyValueV1::Str("compra anual".into()))]
        ))
        .decision,
        AgentPolicyDecisionV1::Allow
    );
    assert!(e.evaluate(&input("x", "pay", &[])).decision.blocks());
}

#[test]
fn operador_desconhecido_e_recusado_na_leitura() {
    let e = DeterministicAgentPolicyEngine::parse(
        r#"
version: "agent-policy-v1"
rules:
  - id: r
    match:
      tool: pay
      conditions:
        - field: cmd
          op: regex
          value: ".*"
    decision: deny
"#,
    );
    assert!(e.is_err(), "regex não existe no MVP (§12)");
}

#[test]
fn require_approval_sem_papeis_e_recusada() {
    let e = DeterministicAgentPolicyEngine::parse(
        r#"
version: "agent-policy-v1"
rules:
  - id: r
    match:
      tool: pay
    decision: require_approval
"#,
    );
    assert!(e.is_err(), "aprovação sem papéis autorizaria qualquer um");
}

#[test]
fn default_allow_e_recusado() {
    let e = DeterministicAgentPolicyEngine::parse(
        r#"
version: "agent-policy-v1"
defaults:
  decision: allow
rules: []
"#,
    );
    assert!(e.is_err(), "§2.2 fail closed");
}

#[test]
fn esquema_desconhecido_e_recusado() {
    assert!(matches!(
        DeterministicAgentPolicyEngine::parse("version: \"agent-policy-v9\"\nrules: []\n"),
        Err(PolicyError::UnsupportedSchema(_))
    ));
}

#[test]
fn regra_duplicada_e_recusada() {
    let e = DeterministicAgentPolicyEngine::parse(
        r#"
version: "agent-policy-v1"
rules:
  - id: r
    match:
      tool: a
    decision: deny
  - id: r
    match:
      tool: b
    decision: deny
"#,
    );
    assert!(e.is_err());
}

#[test]
fn policy_nao_executa_nada() {
    // §31: "sem execução de shell, sem JavaScript/Lua embutido, sem template
    // eval". Um valor que pareça código é só texto.
    let e = DeterministicAgentPolicyEngine::parse(
        r#"
version: "agent-policy-v1"
rules:
  - id: r
    match:
      tool: pay
      conditions:
        - field: cmd
          op: eq
          value: "$(rm -rf /)"
    decision: deny
"#,
    )
    .unwrap();
    let d = e.evaluate(&input(
        "x",
        "pay",
        &[("cmd", PolicyValueV1::Str("$(rm -rf /)".into()))],
    ));
    assert!(matches!(d.decision, AgentPolicyDecisionV1::Deny { .. }));
}

#[test]
fn shell_destrutivo_e_negado() {
    let e = engine();
    let d = e.evaluate(&input(
        "shell",
        "exec",
        &[("command_class", PolicyValueV1::Str("destructive".into()))],
    ));
    assert_eq!(d.rule_id.as_deref(), Some("destructive-shell"));
    assert!(d.decision.blocks());
}
