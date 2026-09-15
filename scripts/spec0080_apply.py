from pathlib import Path


def rep(path: str, old: str, new: str, n: int = 1) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count < n:
        raise SystemExit(f"{path}: expected >= {n} occurrences, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, n))


action = "crates/heraclitus-agent/src/action.rs"
rep(
    action,
    "    pub authorization_id: String,\n\n    pub policy_id: String,",
    "    pub authorization_id: String,\n"
    "    /// Stable logical request identity. Same id means retry; a new id means a new operation.\n"
    "    #[serde(default)]\n"
    "    pub request_id: String,\n\n"
    "    pub policy_id: String,",
)
rep(
    action,
    "pub struct ApprovalRequestV1 {\n    pub approval_id: String,\n    pub authorization_subject_hash: String,",
    "pub struct ApprovalRequestV1 {\n"
    "    pub approval_id: String,\n"
    "    /// Logical request identity kept explicitly for mutation/replay discrimination.\n"
    "    #[serde(default)]\n"
    "    pub request_id: String,\n"
    "    pub authorization_subject_hash: String,",
)
rep(
    action,
    "        w.str(&self.rule_id);\n        w.str(&self.agent_subject);",
    "        w.str(&self.rule_id);\n        w.str(&self.request_id);\n        w.str(&self.agent_subject);",
)

old = '''        let Some((id, record)) = map
            .iter_mut()
            .find(|(_, r)| r.request.authorization_subject_hash == presented)
            .map(|(k, v)| (k.clone(), v))
        else {
            // Não há aprovação para ESTE assunto. Pode haver uma para outro —
            // e é exactamente esse o caso que tem de falhar: procurar por
            // `approval_id` em vez de por assunto deixaria passar o cenário de
            // §32 (aprovar 5000, executar 5001).
            let approved_elsewhere = map
                .values()
                .find(|r| r.state == ApprovalState::Granted)
                .map(|r| r.request.clone());
            return match approved_elsewhere {
                Some(r) => ApprovalVerdict::BindingMismatch {
                    approval_id: r.approval_id,
                    approved_subject_hash: r.authorization_subject_hash,
                    presented_subject_hash: presented,
                },
                None => ApprovalVerdict::NotFound,
            };
        };'''
new = '''        let Some((id, record)) = map
            .iter_mut()
            .find(|(_, r)| r.request.authorization_subject_hash == presented)
            .map(|(k, v)| (k.clone(), v))
        else {
            // Binding mismatch belongs to the same logical request only. A grant
            // for an unrelated request must never poison a new operation.
            let same_request = if authorization.request_id.is_empty() {
                None
            } else {
                map.values()
                    .find(|r| {
                        !r.request.request_id.is_empty()
                            && r.request.request_id == authorization.request_id
                    })
                    .map(|r| r.request.clone())
            };
            return match same_request {
                Some(r) => ApprovalVerdict::BindingMismatch {
                    approval_id: r.approval_id,
                    approved_subject_hash: r.authorization_subject_hash,
                    presented_subject_hash: presented,
                },
                None => ApprovalVerdict::NotFound,
            };
        };'''
rep(action, old, new)
rep(
    action,
    '            authorization_id: "AZ-1".into(),\n            policy_id: "agent-policy".into(),',
    '            authorization_id: "AZ-1".into(),\n            request_id: "request-1".into(),\n            policy_id: "agent-policy".into(),',
)
rep(
    action,
    '            approval_id: "A-771".into(),\n            authorization_subject_hash: a.subject_hash(),',
    '            approval_id: "A-771".into(),\n            request_id: a.request_id.clone(),\n            authorization_subject_hash: a.subject_hash(),',
)
marker = '''    #[test]
    fn uma_aprovacao_exata_sobrevive_a_mudanca_de_segundo_sem_estender_o_ttl() {'''
tests = '''    #[test]
    fn request_id_novo_define_operacao_logica_nova() {
        let a = authz("5000");
        let mut nova = a.clone();
        nova.request_id = "request-2".into();
        nova.authorization_id = "AZ-2".into();
        nova.nonce = "n2".into();
        assert_ne!(a.subject_hash(), nova.subject_hash());
    }

    #[test]
    fn operacao_identica_nova_pode_pedir_nova_aprovacao_apos_consumo() {
        let store = ApprovalStore::new();
        let primeira = authz("5000");
        store.request(request_for(&primeira, 400), 100);
        grant(&store, &primeira, 150);
        assert!(store.consume(&primeira, 200).allows_execution());
        let mut nova = primeira.clone();
        nova.request_id = "request-2".into();
        nova.authorization_id = "AZ-2".into();
        nova.nonce = "n2".into();
        assert!(matches!(store.consume(&nova, 210), ApprovalVerdict::NotFound));
        let mut pedido = request_for(&nova, 500);
        pedido.approval_id = "A-772".into();
        assert_eq!(store.request(pedido, 210).approval_id, "A-772");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn granted_de_outro_request_nao_envenena_operacao_nova() {
        let store = ApprovalStore::new();
        let primeira = authz("5000");
        store.request(request_for(&primeira, 400), 100);
        grant(&store, &primeira, 150);
        let mut outra = authz("5001");
        outra.request_id = "request-2".into();
        assert!(matches!(store.consume(&outra, 160), ApprovalVerdict::NotFound));
    }

    #[test]
    fn mesmo_request_id_mutado_continua_binding_mismatch() {
        let store = ApprovalStore::new();
        let aprovado = authz("5000");
        store.request(request_for(&aprovado, 400), 100);
        grant(&store, &aprovado, 150);
        let mut mutado = authz("5001");
        mutado.request_id = aprovado.request_id.clone();
        assert!(matches!(store.consume(&mutado, 160), ApprovalVerdict::BindingMismatch { .. }));
    }

'''
rep(action, marker, tests + marker)

gateway = "crates/heraclitus-agent-gateway/src/gateway.rs"
rep(
    gateway,
    "                let now = now_unix_seconds();\n                let authorization = ActionAuthorizationV1 {",
    "                let now = now_unix_seconds();\n"
    "                let Some(logical_request_id) = facts.tool_call_id.as_deref()\n"
    "                    .filter(|id| !id.trim().is_empty())\n"
    "                    .map(str::to_string)\n"
    "                else {\n"
    "                    return mcp_error(\n"
    "                        StatusCode::BAD_REQUEST,\n"
    "                        &facts.tool_call_id,\n"
    "                        \"MCP_REQUEST_ID_REQUIRED_FOR_APPROVAL\",\n"
    "                        \"approval-required tool calls need a stable JSON-RPC id\",\n"
    "                    );\n"
    "                };\n"
    "                let authorization = ActionAuthorizationV1 {",
)
rep(
    gateway,
    "                    authorization_id: ulid::Ulid::new().to_string(),\n                    policy_id: a.policy_id.clone(),",
    "                    authorization_id: ulid::Ulid::new().to_string(),\n                    request_id: logical_request_id.clone(),\n                    policy_id: a.policy_id.clone(),",
)
rep(
    gateway,
    "                            approval_id: ulid::Ulid::new().to_string(),\n                            authorization_subject_hash: subject_hash.clone(),",
    "                            approval_id: ulid::Ulid::new().to_string(),\n                            request_id: logical_request_id.clone(),\n                            authorization_subject_hash: subject_hash.clone(),",
)

demo = "crates/heraclitus-agent/src/demo.rs"
rep(
    demo,
    '        authorization_id: "AZ-DEMO-1".into(),\n        policy_id: engine.document().id.clone(),',
    '        authorization_id: "AZ-DEMO-1".into(),\n        request_id: "call-pay-1".into(),\n        policy_id: engine.document().id.clone(),',
)

runner = "labs/Agent-Atack-Heraclitus/runner.py"
rep(
    runner,
    "    def auth_agent(self):\n        t=os.getenv('HERACLITUS_AGENT_TOKEN','').strip(); return {'Authorization':f'Bearer {t}'} if t else {}",
    "    def auth_agent(self):\n"
    "        user=os.getenv('HERACLITUS_AGENT_USERNAME','').strip(); pw=os.getenv('HERACLITUS_AGENT_PASSWORD','')\n"
    "        if user and pw:\n"
    "            raw=base64.b64encode(f'{user}:{pw}'.encode()).decode(); return {'Authorization':f'Basic {raw}'}\n"
    "        t=os.getenv('HERACLITUS_AGENT_TOKEN','').strip(); return {'Authorization':f'Bearer {t}'} if t else {}",
)

massive = "labs/Agent-Atack-Heraclitus/runner_massive.py"
rep(
    massive,
    "        returned=None\n        if isinstance(b,dict): returned=b.get('returned')\n        ok=(s in {400,413,422}) or (s==200 and isinstance(returned,int) and returned<=5000)",
    "        returned=None\n        if isinstance(b,dict) and isinstance(b.get('summary'),dict): returned=b['summary'].get('returned')\n        ok=(s in {400,413,422}) or (s==200 and isinstance(returned,int) and returned<=1000)",
)

Path("docs/md/SPEC-new/SPEC-0080-Per-Request-Approval-Binding.md").write_text(
    """# SPEC-0080 — Per-Request Approval Binding

Status: implemented and qualification-gated.

An approval binds to policy, identity, resource, action, arguments and the stable logical request id. Same request id plus changed content is a binding mismatch. Same request id after consumption is replay. A new request id is a new operation and may request a fresh approval even when its arguments are identical to a prior operation. An unrelated granted approval cannot poison another request. Approval-required MCP calls without a stable JSON-RPC id fail closed.
"""
)
