from pathlib import Path


def replace(path: str, old: str, new: str, count: int = 1):
    p = Path(path)
    text = p.read_text()
    if old not in text:
        raise SystemExit(f"marker not found in {path}: {old[:120]!r}")
    p.write_text(text.replace(old, new, count))

# ---------------------------------------------------------------------------
# 1) MCP gateway: authenticate before forwarding, canonicalize body semantics,
#    reject header/body disagreement and JSON-RPC batches, restrict path/method.
# ---------------------------------------------------------------------------
p = Path("crates/heraclitus-agent-gateway/src/gateway.rs")
text = p.read_text()
text = text.replace(
    "use crate::runtime::{\n",
    "use crate::auth::{self, AuthMode};\nuse crate::runtime::{\n",
    1,
)
text = text.replace(
    "    let runtime = &state.runtime;\n    GatewayCounters::bump(&runtime.gateway_counters.requests);\n    let started = now_unix_nanos();\n\n    let header_map: BTreeMap<String, String> = headers\n",
    """    let runtime = &state.runtime;
    GatewayCounters::bump(&runtime.gateway_counters.requests);
    let started = now_unix_nanos();

    // SPEC-0078 red-team: authentication is a gateway invariant, not merely a
    // Console/API concern. In OIDC/basic mode nothing reaches the upstream
    // before this succeeds. DevLocal deliberately remains open for localhost
    // development and is forbidden by production validation.
    let principal = match auth::principal_from(runtime, &headers, now_unix_seconds()) {
        Ok(p) => p,
        Err(e) => {
            return mcp_error(e.status, &None, e.code, &e.detail);
        }
    };

    // The gateway is not a generic reverse proxy. Until an additional MCP
    // transport is explicitly implemented and covered by policy tests, expose
    // only the Streamable-HTTP request endpoint we can interpret atomically.
    if uri.path() != "/mcp" {
        return mcp_error(
            StatusCode::NOT_FOUND,
            &None,
            "MCP_PATH_NOT_ALLOWED",
            "o gateway só encaminha o endpoint MCP explicitamente permitido",
        );
    }
    if method != Method::POST {
        return mcp_error(
            StatusCode::METHOD_NOT_ALLOWED,
            &None,
            "MCP_METHOD_NOT_ALLOWED",
            "o gateway aceita POST /mcp neste perfil de segurança",
        );
    }

    let mut header_map: BTreeMap<String, String> = headers
""",
    1,
)
marker = """        .collect();

    let server_id = header_map
        .get("x-heraclitus-server")
        .cloned()
        .unwrap_or_else(|| {
            state
                .upstream
                .as_ref()
                .and_then(|u| u.base().host().map(str::to_string))
                .unwrap_or_else(|| "upstream".to_string())
        });
"""
replacement = """        .collect();

    // The body is the exact JSON-RPC message the upstream will receive, so it
    // is the sole semantic authority for policy classification. Classification
    // headers are accepted only as consistency assertions.
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return mcp_error(
                StatusCode::BAD_REQUEST,
                &None,
                "MCP_REQUEST_MALFORMED",
                "o corpo de POST /mcp deve ser um objecto JSON-RPC válido",
            )
        }
    };
    if payload.is_array() {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            &None,
            "MCP_BATCH_UNSUPPORTED",
            "lotes JSON-RPC são recusados até existir enforcement atómico por item",
        );
    }
    let Some(obj) = payload.as_object() else {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            &None,
            "MCP_REQUEST_MALFORMED",
            "a raiz do pedido MCP tem de ser um objecto JSON-RPC",
        );
    };
    let body_method = obj.get("method").and_then(serde_json::Value::as_str);
    let body_tool = obj
        .get("params")
        .and_then(serde_json::Value::as_object)
        .and_then(|p| p.get("name"))
        .and_then(serde_json::Value::as_str);

    for (header, canonical) in [(mcp::HEADER_METHOD, body_method), (mcp::HEADER_NAME, body_tool)] {
        if let (Some(claimed), Some(actual)) = (header_map.get(header), canonical) {
            if claimed != actual {
                return mcp_error(
                    StatusCode::BAD_REQUEST,
                    &None,
                    "MCP_SEMANTIC_MISMATCH",
                    "os cabeçalhos de classificação contradizem o JSON-RPC que seria enviado ao upstream",
                );
            }
        }
    }
    if let Some(method) = body_method {
        header_map.insert(mcp::HEADER_METHOD.to_string(), method.to_string());
    }
    if let Some(tool) = body_tool {
        header_map.insert(mcp::HEADER_NAME.to_string(), tool.to_string());
    }

    // Server identity is derived from the configured upstream, never from an
    // attacker-controlled header. A contradictory header is rejected instead
    // of being allowed to select a weaker policy rule.
    let server_id = state
        .upstream
        .as_ref()
        .and_then(|u| u.base().host().map(str::to_string))
        .unwrap_or_else(|| "upstream".to_string());
    if let Some(claimed) = header_map.get("x-heraclitus-server") {
        if claimed != &server_id {
            return mcp_error(
                StatusCode::BAD_REQUEST,
                &None,
                "MCP_SERVER_MISMATCH",
                "x-heraclitus-server não corresponde ao upstream configurado",
            );
        }
    }
"""
if marker not in text:
    raise SystemExit("gateway server-id marker not found")
text = text.replace(marker, replacement, 1)
text = text.replace(
    """        run_id: header_map.get("x-heraclitus-run").cloned(),
        agent_id: header_map.get("x-heraclitus-agent").cloned(),
        human_subject: header_map.get("x-heraclitus-user").cloned(),
""",
    """        run_id: header_map.get("x-heraclitus-run").cloned(),
        agent_id: if principal.mode == AuthMode::DevLocal {
            header_map.get("x-heraclitus-agent").cloned()
        } else {
            Some(principal.subject.clone())
        },
        human_subject: if principal.mode == AuthMode::DevLocal {
            header_map.get("x-heraclitus-user").cloned()
        } else {
            None
        },
""",
    1,
)
# In authenticated modes environment is not caller-supplied policy truth.
text = text.replace(
    '        environment: header_map.get("x-heraclitus-environment").cloned(),\n',
    '        environment: (principal.mode == AuthMode::DevLocal)\n            .then(|| header_map.get("x-heraclitus-environment").cloned())\n            .flatten(),\n',
    1,
)
text = text.replace(
    '                                environment: header_map.get("x-heraclitus-environment").cloned(),\n',
    '                                environment: (principal.mode == AuthMode::DevLocal)\n                                    .then(|| header_map.get("x-heraclitus-environment").cloned())\n                                    .flatten(),\n',
    1,
)
p.write_text(text)

# ---------------------------------------------------------------------------
# 2) Dedupe: scope protocol call ids by authenticated agent and run.
# ---------------------------------------------------------------------------
replace(
    "crates/heraclitus-agent/src/dedupe.rs",
    """    w.opt_str(e.trace_id.as_deref());
    w.opt_str(e.span_id.as_deref());
    w.u8v(e.kind.tag());
""",
    """    w.opt_str(e.trace_id.as_deref());
    w.opt_str(e.span_id.as_deref());
    // MCP JSON-RPC ids are only unique inside a client/session. Scope the key
    // by agent and run so two principals reusing id=1 cannot hide one another.
    w.str(&e.agent.agent_id);
    w.opt_str(e.run_id.as_deref());
    w.u8v(e.kind.tag());
""",
)

# ---------------------------------------------------------------------------
# 3) OIDC: preserve organization/custom roles separately from fixed console RBAC.
# ---------------------------------------------------------------------------
p = Path("crates/heraclitus-agent-gateway/src/auth.rs")
text = p.read_text()
text = text.replace(
    """    pub roles: Vec<Role>,
    /// `true` quando o perfil é de desenvolvimento e ninguém provou nada.
""",
    """    pub roles: Vec<Role>,
    /// Claims de papel autenticados pelo OIDC, normalizados mas não reduzidos
    /// ao enum de RBAC. Policies podem exigir papéis organizacionais como cfo.
    #[serde(default)]
    pub claims_roles: Vec<String>,
    /// `true` quando o perfil é de desenvolvimento e ninguém provou nada.
""",
    1,
)
text = text.replace(
    """    pub fn require(&self, op: Operation) -> Result<(), AuthRejection> {
""",
    """    pub fn has_claim_role(&self, role: &str) -> bool {
        let wanted = role.to_ascii_lowercase().replace('-', "_");
        self.claims_roles.iter().any(|r| r == &wanted)
    }

    pub fn require(&self, op: Operation) -> Result<(), AuthRejection> {
""",
    1,
)
# Add claims_roles in non-OIDC constructors.
text = text.replace(
    """                roles: Principal::all_roles(),
                dev_local: false,
""",
    """                roles: Principal::all_roles(),
                claims_roles: Principal::all_roles().into_iter().map(|r| r.label().to_string()).collect(),
                dev_local: false,
""",
    1,
)
text = text.replace(
    """            roles: Principal::all_roles(),
            dev_local: true,
""",
    """            roles: Principal::all_roles(),
            claims_roles: Principal::all_roles().into_iter().map(|r| r.label().to_string()).collect(),
            dev_local: true,
""",
    1,
)
old_oidc = """    let mut roles: Vec<Role> = identity
        .roles
        .iter()
        .filter_map(|r| Role::parse(r))
        .collect();
"""
new_oidc = """    let mut claims_roles: Vec<String> = identity
        .roles
        .iter()
        .map(|r| r.to_ascii_lowercase().replace('-', "_"))
        .collect();
    claims_roles.sort();
    claims_roles.dedup();
    let mut roles: Vec<Role> = claims_roles.iter().filter_map(|r| Role::parse(r)).collect();
"""
if old_oidc not in text:
    raise SystemExit("OIDC role marker not found")
text = text.replace(old_oidc, new_oidc, 1)
text = text.replace(
    """        issuer: identity.issuer,
        roles,
        dev_local: false,
""",
    """        issuer: identity.issuer,
        roles,
        claims_roles,
        dev_local: false,
""",
    1,
)
# Unit-test helper constructor.
text = text.replace(
    """            roles: roles.to_vec(),
            dev_local: false,
""",
    """            roles: roles.to_vec(),
            claims_roles: roles.iter().map(|r| r.label().to_string()).collect(),
            dev_local: false,
""",
    1,
)
p.write_text(text)

# Approval rule roles use authenticated OIDC claims, with explicit system-admin override.
p = Path("crates/heraclitus-agent-gateway/src/api.rs")
text = p.read_text()
old = """    if !record.request.requested_roles.is_empty()
        && !principal.roles.iter().any(|r| {
            record
                .request
                .requested_roles
                .iter()
                .any(|want| want.eq_ignore_ascii_case(r.label()))
        })
        && !principal.roles.contains(&crate::auth::Role::SystemAdmin)
"""
new = """    if !record.request.requested_roles.is_empty()
        && !record
            .request
            .requested_roles
            .iter()
            .any(|want| principal.has_claim_role(want))
        && !principal.roles.contains(&crate::auth::Role::SystemAdmin)
"""
if old not in text:
    raise SystemExit("approval-role marker not found")
text = text.replace(old, new, 1)
text = text.replace(
    '"bypass_protection": if runtime.gateway.bypass_protection_configured { "CONFIGURED" } else { "UNKNOWN" },',
    '"bypass_protection": if runtime.gateway.bypass_protection_configured { "DECLARED" } else { "UNKNOWN" },',
    1,
)
p.write_text(text)

# Update wording in product config/docs where the assertion was described as verified-looking CONFIGURED.
for path in ["crates/heraclitus-agent/src/config.rs", "docs/agent/mcp.md"]:
    p = Path(path)
    if p.exists():
        t = p.read_text().replace("BYPASS PROTECTION: CONFIGURED", "BYPASS PROTECTION: DECLARED")
        p.write_text(t)

# ---------------------------------------------------------------------------
# 4) Regressions: header/body mismatch, batch, path allowlist and dedupe scope.
# ---------------------------------------------------------------------------
p = Path("crates/heraclitus-agent-gateway/tests/gateway_end_to_end.rs")
text = p.read_text()
if "redteam_header_body_confusion_falha_fechado" not in text:
    text += r'''

#[tokio::test]
async fn redteam_header_body_confusion_falha_fechado() {
    let h = harness(GatewayMode::Enforce).await;
    let antes = h.hits();
    let (status, body) = post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call("p0-hb", "exec", serde_json::json!({ "command": "id" })),
        &[
            ("mcp-method", "tools/call"),
            ("mcp-name", "lookup_vendor"),
            ("x-heraclitus-agent", "attacker"),
            ("x-heraclitus-run", "run-p0"),
        ],
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"]["data"]["heraclitus"]["reason_code"],
        "MCP_SEMANTIC_MISMATCH"
    );
    assert_eq!(h.hits(), antes, "confusão header/body chegou ao upstream");
}

#[tokio::test]
async fn redteam_method_header_nao_pode_disfarcar_tool_call() {
    let h = harness(GatewayMode::Enforce).await;
    let antes = h.hits();
    let (status, body) = post_json(
        &format!("{}/mcp", h.gateway_url),
        tool_call("p0-method", "exec", serde_json::json!({ "command": "id" })),
        &[
            ("mcp-method", "tools/list"),
            ("x-heraclitus-agent", "attacker"),
            ("x-heraclitus-run", "run-p0"),
        ],
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(h.hits(), antes);
}

#[tokio::test]
async fn redteam_jsonrpc_batch_nao_atravessa_sem_policy_atomica() {
    let h = harness(GatewayMode::Enforce).await;
    let antes = h.hits();
    let batch = serde_json::json!([
        tool_call("batch-1", "exec", serde_json::json!({ "command": "id" }))
    ]);
    let (status, body) = post_json(&format!("{}/mcp", h.gateway_url), batch, &[]).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"]["data"]["heraclitus"]["reason_code"],
        "MCP_BATCH_UNSUPPORTED"
    );
    assert_eq!(h.hits(), antes);
}

#[tokio::test]
async fn redteam_path_arbitrario_nao_e_reverse_proxy() {
    let h = harness(GatewayMode::Enforce).await;
    let antes = h.hits();
    let (status, body) = post_json(
        &format!("{}/admin/delete", h.gateway_url),
        serde_json::json!({"danger": true}),
        &[],
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(h.hits(), antes);
}
'''
p.write_text(text)

p = Path("crates/heraclitus-agent/src/dedupe.rs")
text = p.read_text()
if "mcp_mesmo_id_em_agentes_ou_runs_diferentes_nao_colide" not in text:
    insert = r'''

    #[test]
    fn mcp_mesmo_id_em_agentes_ou_runs_diferentes_nao_colide() {
        let mut a = AgentEvidenceV1::new("t", AgentEvidenceKindV1::ToolRequested, 1);
        a.source.source_kind = "gateway".into();
        a.source.source_instance = Some("mcp.example".into());
        a.subject.tool_call_id = Some("1".into());
        a.agent.agent_id = "agent-a".into();
        a.run_id = Some("run-a".into());
        let mut b = a.clone();
        b.agent.agent_id = "agent-b".into();
        b.run_id = Some("run-b".into());
        assert_ne!(dedupe_key(&a), dedupe_key(&b));

        let mut retry = a.clone();
        retry.evidence_id = "retry".into();
        retry.observed_at_unix_nanos = 999;
        assert_eq!(dedupe_key(&a), dedupe_key(&retry));
    }
'''
    pos = text.rfind("}\n")
    text = text[:pos] + insert + text[pos:]
p.write_text(text)

print("SPEC-0078 red-team hardening codemod applied")
