from pathlib import Path

# Ratatui 0.29 resolves lru 0.12.5, which is covered by two RustSec advisories.
p = Path("Cargo.toml")
text = p.read_text()
old = 'ratatui = "0.29"'
if old not in text:
    raise SystemExit("workspace ratatui 0.29 declaration not found")
p.write_text(text.replace(old, 'ratatui = "0.30.2"', 1))

# Oversized, redaction and dedupe paths were already covered. Add the missing
# malformed OTLP regression and prove the listener remains alive afterwards.
p = Path("crates/heraclitus-agent-gateway/tests/quickstart_otlp.rs")
text = p.read_text()
if "otlp_json_malformado_e_rejeitado_sem_derrubar_o_listener" not in text:
    text = text.rstrip() + r'''

#[tokio::test]
async fn otlp_json_malformado_e_rejeitado_sem_derrubar_o_listener() {
    let q = arrancar().await;
    let (status, _) = post(
        &format!("{}/v1/traces", q.otlp_url),
        b"{nao-e-json".to_vec(),
        "application/json",
    )
    .await;
    assert_eq!(status, 400);

    let (status, body) = post(
        &format!("{}/v1/traces", q.otlp_url),
        LOTE,
        "application/json",
    )
    .await;
    assert_eq!(
        status, 200,
        "listener nao recuperou depois de input malformado: {body}"
    );
    assert!(body["heraclitus"]["accepted"].as_u64().unwrap_or(0) > 0);
}
'''
    p.write_text(text)

# Add a one-second approval policy and an end-to-end expiration gate.
p = Path("crates/heraclitus-agent-gateway/tests/gateway_end_to_end.rs")
text = p.read_text()
if "pagamento-expira" not in text:
    marker = """  - id: shell
    match:
      tool: exec
    decision: deny
"""
    rule = """  - id: pagamento-expira
    match:
      tool: send_payment_short
    decision: require_approval
    approval:
      roles: ["cfo"]
      ttl_seconds: 1

"""
    if marker not in text:
        raise SystemExit("policy marker not found")
    text = text.replace(marker, rule + marker, 1)

if "aprovacao_expirada_nunca_toca_o_upstream" not in text:
    marker = "#[tokio::test]\nasync fn trafego_de_protocolo_nao_vira_evidencia() {"
    test = r'''#[tokio::test]
async fn aprovacao_expirada_nunca_toca_o_upstream() {
    let h = harness(GatewayMode::Enforce).await;
    let pedido = tool_call(
        "c-exp",
        "send_payment_short",
        serde_json::json!({ "amount": 75000, "account": "v1" }),
    );
    let (status, body) = post_json(
        &format!("{}/mcp", h.gateway_url),
        pedido.clone(),
        AGENT_HEADERS,
    )
    .await;
    assert_eq!(status, 202, "{body}");
    let approval_id = body["error"]["data"]["heraclitus"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = post_json(
        &format!("{}/api/v1/agent/approvals/{approval_id}/approve", h.api_url),
        serde_json::json!({}),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let antes = h.hits();
    let (status, body) = post_json(&format!("{}/mcp", h.gateway_url), pedido, AGENT_HEADERS).await;
    assert_eq!(h.hits(), antes, "aprovacao expirada chegou ao upstream");
    assert!(status == 403 || status == 202, "status {status}: {body}");
    let reason = body["error"]["data"]["heraclitus"]["reason_code"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(reason, "APPROVAL_EXPIRED", "{body}");
}

'''
    if marker not in text:
        raise SystemExit("gateway test insertion marker not found")
    text = text.replace(marker, test + marker, 1)
p.write_text(text)
