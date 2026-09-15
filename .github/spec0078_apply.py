from pathlib import Path


def replace(path: str, old: str, new: str, count: int = 1) -> None:
    p = Path(path)
    text = p.read_text()
    actual = text.count(old)
    if actual < count:
        raise SystemExit(
            f"{path}: expected at least {count} occurrence(s), found {actual}: {old[:120]!r}"
        )
    p.write_text(text.replace(old, new, count))


# A. Approval binding: identity/content is stable; lifecycle is checked separately.
path = "crates/heraclitus-agent/src/action.rs"
replace(
    path,
    "argumentos, agente, humano, policy, validade — o hash muda e a autorização\n//! deixa de valer. Não há caminho no código que execute sem o reconferir.",
    "argumentos, agente, humano ou policy — o hash muda e a autorização\n//! deixa de valer. A validade temporal é verificada separadamente pelo lifecycle\n//! da aprovação e pela autorização apresentada; não faz parte da identidade do\n//! assunto. Não há caminho no código que execute sem ambas as verificações.",
)
replace(
    path,
    "    /// Exactamente os campos de §14: se mudar a ferramenta, o servidor, os\n"
    "    /// argumentos, o agente, o humano, a policy ou a validade, a autorização\n"
    "    /// deixa de valer. O `authorization_id` e o `nonce` NÃO entram — o assunto\n"
    "    /// é o que se aprova, não o papel em que veio escrito.\n",
    "    /// Binding estável da SPEC-0078 §3: ferramenta/servidor, argumentos,\n"
    "    /// agente, humano e policy identificam o assunto aprovado. `issued_at`,\n"
    "    /// `expires_at`, `authorization_id` e `nonce` NÃO entram: são lifecycle e\n"
    "    /// envelope efémero. Expiração continua obrigatória em `ApprovalStore` e\n"
    "    /// `is_valid_at`, mas um retry um segundo depois não muda o que o humano\n"
    "    /// aprovou.\n",
)
replace(
    path,
    "        w.str(&self.argument_digest);\n"
    "        w.u64v(self.issued_at);\n"
    "        w.u64v(self.expires_at);\n"
    "        hex32(&domain_hash(DOMAIN_AUTHZ_SUBJECT, w.as_slice()))",
    "        w.str(&self.argument_digest);\n"
    "        hex32(&domain_hash(DOMAIN_AUTHZ_SUBJECT, w.as_slice()))",
)

marker = "    fn request_for(a: &ActionAuthorizationV1, expires: u64) -> ApprovalRequestV1 {\n"
tests = r'''    #[test]
    fn o_binding_do_assunto_nao_depende_do_relogio_ou_envelope() {
        let a = authz("5000");
        let mut retry = a.clone();
        retry.authorization_id = "AZ-2".into();
        retry.nonce = "n2".into();
        retry.issued_at = 250;
        retry.expires_at = 900;
        assert_eq!(a.subject_hash(), retry.subject_hash());
    }

    #[test]
    fn uma_aprovacao_exata_sobrevive_a_mudanca_de_segundo_sem_estender_o_ttl() {
        let store = ApprovalStore::new();
        let original = authz("5000");
        store.request(request_for(&original, 400), 100);
        grant(&store, &original, 150);

        let mut retry = original.clone();
        retry.authorization_id = "AZ-retry".into();
        retry.nonce = "retry-nonce".into();
        retry.issued_at = 250;
        retry.expires_at = 550;
        assert_eq!(original.subject_hash(), retry.subject_hash());
        assert!(store.consume(&retry, 250).allows_execution());
    }

'''
replace(path, marker, tests + marker)


# B. Gateway regression reproduces the v2.0.0 failure across a second boundary.
path = "crates/heraclitus-agent-gateway/tests/gateway_end_to_end.rs"
replace(
    path,
    "    assert_eq!(status, 200);\n\n    // 3. A mesma acção exacta passa — uma vez.\n",
    "    assert_eq!(status, 200);\n\n"
    "    // SPEC-0078: o bug da v2.0.0 só aparecia quando o retry cruzava o segundo\n"
    "    // UNIX porque issued_at/expires_at eram indevidamente parte do binding.\n"
    "    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;\n\n"
    "    // 3. A mesma acção exacta passa — uma vez, mesmo noutro segundo.\n",
)

flood = r'''
#[tokio::test]
async fn flood_concorrente_de_deny_nunca_toca_o_upstream() {
    let h = harness(GatewayMode::Enforce).await;
    let antes = h.hits();
    let mut tarefas = tokio::task::JoinSet::new();
    for i in 0..64usize {
        let url = format!("{}/mcp", h.gateway_url);
        tarefas.spawn(async move {
            post_json(
                &url,
                tool_call(
                    &format!("deny-flood-{i}"),
                    "exec",
                    serde_json::json!({ "command": "rm -rf /", "attempt": i }),
                ),
                AGENT_HEADERS,
            )
            .await
            .0
        });
    }
    let mut negadas = 0usize;
    while let Some(resultado) = tarefas.join_next().await {
        assert_eq!(resultado.unwrap(), 403);
        negadas += 1;
    }
    assert_eq!(negadas, 64);
    assert_eq!(h.hits(), antes, "DENY concorrente vazou chamada ao upstream");
    assert!(
        !h.runtime.scan().unwrap().is_empty(),
        "evidence log ficou ilegível"
    );
}
'''
p = Path(path)
text = p.read_text()
if "flood_concorrente_de_deny_nunca_toca_o_upstream" not in text:
    p.write_text(text.rstrip() + "\n" + flood)


# C. Qualifier must know the same agent configuration namespaces as the server.
path = "tools/heraclitus-qualifier/src/doctor.rs"
replace(
    path,
    "use anyhow::{Context, Result};\nuse serde::Serialize;",
    "use anyhow::{Context, Result};\n"
    "use heraclitus_agent::config::{AgentBlackBoxConfig, AgentGatewayConfig};\n"
    "use serde::Serialize;",
)
replace(
    path,
    '    "v6_lakehouse_table",\n];',
    '    "v6_lakehouse_table",\n    "agent_black_box",\n    "agent_gateway",\n];',
)

nested = r'''

const AGENT_BLACK_BOX_KEYS: &[&str] = &[
    "enabled",
    "capture_mode",
    "tenant_id",
    "max_body_bytes",
    "otlp",
    "mcp",
    "redaction",
    "evidence",
    "console",
    "limits",
];
const AGENT_OTLP_KEYS: &[&str] = &["http_addr", "grpc_addr", "require_auth"];
const AGENT_MCP_KEYS: &[&str] = &["enabled", "listen_addr", "mode"];
const AGENT_REDACTION_KEYS: &[&str] = &[
    "profile",
    "deny_headers",
    "deny_fields",
    "max_field_bytes",
    "max_fields",
];
const AGENT_EVIDENCE_KEYS: &[&str] = &["rfc3161", "max_bundle_records"];
const AGENT_CONSOLE_KEYS: &[&str] = &["enabled", "addr", "basic_auth"];
const AGENT_LIMIT_KEYS: &[&str] = &[
    "max_attributes",
    "max_attribute_key_bytes",
    "max_attribute_value_bytes",
    "max_events_per_batch",
    "max_body_bytes",
    "max_queue_depth",
];
const AGENT_GATEWAY_KEYS: &[&str] = &[
    "enabled",
    "mode",
    "listen_addr",
    "upstream_url",
    "identity",
    "policy",
    "approval",
    "bypass_protection_configured",
];
const AGENT_IDENTITY_KEYS: &[&str] = &[
    "mode",
    "issuer",
    "audience",
    "jwks_path",
    "roles_claim",
    "clock_skew_seconds",
];
const AGENT_POLICY_KEYS: &[&str] = &["active", "default_decision"];
const AGENT_APPROVAL_KEYS: &[&str] = &["default_ttl_seconds"];

fn check_table_keys(
    findings: &mut Vec<Finding>,
    value: &Value,
    path: &str,
    allowed: &[&str],
) {
    let Some(table) = value.as_table() else {
        findings.push(finding(
            "configuration",
            Severity::Blocking,
            format!("{path} must be a TOML table"),
            "use the documented table shape; scalar values do not configure this server surface",
        ));
        return;
    };
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    for key in table.keys() {
        if !allowed.contains(key.as_str()) {
            findings.push(finding(
                "configuration",
                Severity::Blocking,
                format!("key {path}.{key} is not read by the server and has no effect"),
                "remove the key or correct its spelling; nested agent configuration is checked recursively",
            ));
        }
    }
}

fn check_agent_nested_keys(findings: &mut Vec<Finding>, config: &Value) {
    if let Some(agent) = config.get("agent_black_box") {
        check_table_keys(findings, agent, "agent_black_box", AGENT_BLACK_BOX_KEYS);
        for (key, allowed) in [
            ("otlp", AGENT_OTLP_KEYS),
            ("mcp", AGENT_MCP_KEYS),
            ("redaction", AGENT_REDACTION_KEYS),
            ("evidence", AGENT_EVIDENCE_KEYS),
            ("console", AGENT_CONSOLE_KEYS),
            ("limits", AGENT_LIMIT_KEYS),
        ] {
            if let Some(value) = agent.get(key) {
                check_table_keys(
                    findings,
                    value,
                    &format!("agent_black_box.{key}"),
                    allowed,
                );
            }
        }
    }
    if let Some(gateway) = config.get("agent_gateway") {
        check_table_keys(findings, gateway, "agent_gateway", AGENT_GATEWAY_KEYS);
        for (key, allowed) in [
            ("identity", AGENT_IDENTITY_KEYS),
            ("policy", AGENT_POLICY_KEYS),
            ("approval", AGENT_APPROVAL_KEYS),
        ] {
            if let Some(value) = gateway.get(key) {
                check_table_keys(
                    findings,
                    value,
                    &format!("agent_gateway.{key}"),
                    allowed,
                );
            }
        }
    }
}
'''
replace(
    path,
    "\nfn is_loopback_bind(address: &str) -> Option<bool> {",
    nested + "\nfn is_loopback_bind(address: &str) -> Option<bool> {",
)
replace(
    path,
    "    }\n\n    // ---- TLS and mTLS -----------------------------------------------------\n",
    "    }\n    check_agent_nested_keys(&mut findings, config);\n\n"
    "    // ---- TLS and mTLS -----------------------------------------------------\n",
)

semantic = r'''

    // ---- Agent plane contract --------------------------------------------
    // Unknown nested keys were rejected above before serde gets a chance to
    // ignore them. Typed parsing here then reuses the server's semantic gates.
    let core_auth_configured = string(config, "rest_basic_auth").is_some()
        || token.is_some()
        || credentials > 0;
    if let Some(raw) = config.get("agent_black_box") {
        match raw.clone().try_into::<AgentBlackBoxConfig>() {
            Ok(agent) => {
                if let Err(error) =
                    agent.validate(production, tls_configured, core_auth_configured)
                {
                    findings.push(finding(
                        "agent",
                        Severity::Blocking,
                        format!("agent_black_box is rejected by the server: {error}"),
                        "make the Agent Black Box configuration satisfy the same production gates as heraclitus-server",
                    ));
                }
            }
            Err(error) => findings.push(finding(
                "agent",
                Severity::Blocking,
                format!("agent_black_box cannot be parsed by the server: {error}"),
                "fix the table types and values before qualification",
            )),
        }
    }
    if let Some(raw) = config.get("agent_gateway") {
        match raw.clone().try_into::<AgentGatewayConfig>() {
            Ok(gateway) => {
                if let Err(error) = gateway.validate(production, tls_configured) {
                    findings.push(finding(
                        "agent",
                        Severity::Blocking,
                        format!("agent_gateway is rejected by the server: {error}"),
                        "make the Agent Policy Gateway configuration satisfy the server validation gates",
                    ));
                }
            }
            Err(error) => findings.push(finding(
                "agent",
                Severity::Blocking,
                format!("agent_gateway cannot be parsed by the server: {error}"),
                "fix the table types and values before qualification",
            )),
        }
    }
'''
replace(
    path,
    "\n    // ---- storage and filesystem ------------------------------------------\n",
    semantic + "\n    // ---- storage and filesystem ------------------------------------------\n",
)

qualifier_tests = r'''

    #[test]
    fn agent_black_box_e_gateway_sao_configuracao_real_nao_chaves_inertes() {
        let findings = diagnose_text(
            r#"
[agent_black_box]
enabled = true
capture_mode = "metadata_only"
[agent_black_box.otlp]
http_addr = "127.0.0.1:4318"
[agent_black_box.console]
addr = "127.0.0.1:8080"

[agent_gateway]
enabled = true
mode = "shadow"
listen_addr = "127.0.0.1:8787"
upstream_url = "http://127.0.0.1:9000"
"#,
        );
        assert!(!has(
            &findings,
            Severity::Blocking,
            "key \"agent_black_box\""
        ));
        assert!(!has(
            &findings,
            Severity::Blocking,
            "key \"agent_gateway\""
        ));
        assert!(!has(
            &findings,
            Severity::Blocking,
            "agent_black_box is rejected"
        ));
        assert!(!has(
            &findings,
            Severity::Blocking,
            "agent_gateway is rejected"
        ));
    }

    #[test]
    fn typo_dentro_da_configuracao_de_agente_e_blocking() {
        let findings = diagnose_text(
            "[agent_black_box]\nenabled = true\ncapture_mod = \"metadata_only\"\n",
        );
        assert!(has(
            &findings,
            Severity::Blocking,
            "agent_black_box.capture_mod"
        ));
    }

    #[test]
    fn gateway_enforce_de_producao_sem_bypass_e_recusado_com_a_mesma_semantica_do_servidor() {
        let findings = diagnose_text(
            r#"
production_mode = true
tls_cert_path = "missing-cert.pem"
tls_key_path = "missing-key.pem"
rest_basic_auth = "operator:secret"
[agent_gateway]
enabled = true
mode = "enforce"
listen_addr = "127.0.0.1:8787"
upstream_url = "https://mcp.example"
bypass_protection_configured = false
[agent_gateway.identity]
mode = "oidc"
issuer = "https://id.example"
audience = "heraclitus"
jwks_path = "/tmp/jwks.json"
"#,
        );
        assert!(has(
            &findings,
            Severity::Blocking,
            "bypass_protection_configured"
        ));
    }
'''
replace(
    path,
    "\n    #[test]\n    fn the_clock_is_always_reported_as_unverifiable_from_a_file() {",
    qualifier_tests
    + "\n    #[test]\n    fn the_clock_is_always_reported_as_unverifiable_from_a_file() {",
)

# Qualifier uses the exact public config types rather than reimplementing semantics.
path = "tools/heraclitus-qualifier/Cargo.toml"
replace(
    path,
    "heraclitus-client.workspace = true\n",
    "heraclitus-client.workspace = true\nheraclitus-agent.workspace = true\n",
)

# D. Pin the minimum rustls release carrying RUSTSEC-2026-0285's fix.
for path in [
    "crates/heraclitus-compliance/Cargo.toml",
    "crates/heraclitus-agent-gateway/Cargo.toml",
]:
    replace(
        path,
        'rustls = { version = "0.23",',
        'rustls = { version = "0.23.45",',
    )
