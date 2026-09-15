from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    text = p.read_text()
    if old not in text:
        raise SystemExit(f"marker not found in {path}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))

api = Path('crates/heraclitus-agent-gateway/src/api.rs')
text = api.read_text()
route_marker = '        .route("/api/v1/agent/evidence/export", post(export))\n'
route_new = route_marker + '        // SPEC-0079 — laboratório defensivo: telemetria estruturada de probes.\n        // POST é SystemAdmin; GET segue a permissão de leitura dos runs.\n        .route("/api/v1/agent/red-team/events", get(red_team_events).post(red_team_record))\n'
if '/api/v1/agent/red-team/events' not in text:
    if route_marker not in text:
        raise SystemExit('api route marker missing')
    text = text.replace(route_marker, route_new, 1)

insert_marker = '#[derive(Debug, Deserialize, Default)]\npub struct RunsQuery {'
if 'struct RedTeamInput' not in text:
    redteam = r'''#[derive(Debug, Deserialize)]
struct RedTeamInput {
    attack_id: String,
    #[serde(default)]
    campaign_id: Option<String>,
    vector: String,
    target: String,
    phase: String,
    result: String,
    #[serde(default)]
    expected: Option<String>,
    #[serde(default)]
    reason_code: Option<String>,
    #[serde(default)]
    blocked: Option<bool>,
    #[serde(default)]
    upstream_delta: Option<i64>,
    #[serde(default)]
    transport_status: Option<i64>,
    #[serde(default)]
    sequence: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct RedTeamQuery {
    campaign: Option<String>,
    limit: Option<usize>,
}

fn safe_probe_atom(label: &str, value: &str, max: usize) -> Result<(), Response> {
    if value.is_empty() || value.len() > max || value.chars().any(|c| c.is_control()) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "REDTEAM_EVENT_INVALID",
            format!("{label} vazio, grande demais ou com caracteres de controlo"),
            "envie apenas metadados curtos; payloads ofensivos e segredos não pertencem ao evidence log",
        ));
    }
    Ok(())
}

async fn red_team_record(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Json(input): Json<RedTeamInput>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    // A telemetria do laboratório é uma escrita administrativa. O Dashboard é
    // somente leitura; o runner autorizado escreve directamente na Agent API.
    if let Err(e) = principal.require(Operation::ChangeCapture) {
        return forbidden(e);
    }
    for (label, value, max) in [
        ("attack_id", input.attack_id.as_str(), 128usize),
        ("vector", input.vector.as_str(), 128usize),
        ("target", input.target.as_str(), 256usize),
        ("phase", input.phase.as_str(), 48usize),
        ("result", input.result.as_str(), 64usize),
    ] {
        if let Err(r) = safe_probe_atom(label, value, max) { return r; }
    }
    let campaign = input.campaign_id.as_deref().unwrap_or("manual");
    if let Err(r) = safe_probe_atom("campaign_id", campaign, 128) { return r; }

    let now = now_unix_nanos();
    let mut ev = heraclitus_agent::evidence::AgentEvidenceV1::new(
        runtime.config.tenant_id.clone(),
        heraclitus_agent::evidence::AgentEvidenceKindV1::ErrorObserved,
        now,
    );
    ev.run_id = Some(format!("redteam:{campaign}"));
    ev.agent = heraclitus_agent::evidence::AgentIdentityV1 {
        agent_id: "agent-atack-heraclitus".into(),
        agent_name: Some("Agent-Atack-Heraclitus".into()),
        framework: Some("heraclitus-redteam-lab".into()),
        ..Default::default()
    };
    ev.subject.protocol = Some("redteam_lab".into());
    ev.subject.server_id = Some(input.target.clone());
    ev.subject.tool_name = Some(input.vector.clone());
    ev.subject.tool_call_id = Some(input.attack_id.clone());
    ev.source = heraclitus_agent::evidence::EvidenceSourceV1 {
        source_kind: "redteam_lab".into(),
        source_instance: Some(principal.subject.clone()),
        source_sequence: input.sequence,
        received_at_unix_nanos: Some(now),
    };
    ev.privacy.capture_mode = heraclitus_agent::evidence::CaptureModeV1::MetadataOnly;
    ev.privacy.redaction_applied = true;
    ev.content.fields.insert("attack_id".into(), input.attack_id.clone());
    ev.content.fields.insert("campaign_id".into(), campaign.to_string());
    ev.content.fields.insert("vector".into(), input.vector.clone());
    ev.content.fields.insert("target".into(), input.target.clone());
    ev.content.fields.insert("phase".into(), input.phase.clone());
    ev.content.fields.insert("result".into(), input.result.clone());
    if let Some(v) = &input.expected { if v.len() <= 128 { ev.content.fields.insert("expected".into(), v.clone()); } }
    if let Some(v) = &input.reason_code { if v.len() <= 128 { ev.content.fields.insert("reason_code".into(), v.clone()); } }
    if let Some(v) = input.blocked { ev.content.fields.insert("blocked".into(), v.to_string()); }
    if let Some(v) = input.upstream_delta { ev.content.fields.insert("upstream_delta".into(), v.to_string()); }
    ev.outcome = Some(heraclitus_agent::evidence::EvidenceOutcomeV1 {
        transport_status: input.transport_status,
        protocol_status: Some(input.result.clone()),
        error_code: input.reason_code.clone(),
        ..Default::default()
    });
    ev.dedupe_key = format!(
        "redteam:{}:{}:{}:{}",
        campaign,
        input.attack_id,
        input.phase,
        input.sequence.unwrap_or(0)
    );

    match runtime.append(&ev) {
        Ok(lsn) => Json(serde_json::json!({
            "accepted": true,
            "duplicate": lsn.is_none(),
            "evidence_id": ev.evidence_id,
            "lsn": lsn,
            "capture": "METADATA_ONLY",
        })).into_response(),
        Err(e) => problem(
            StatusCode::CONFLICT,
            "REDTEAM_EVIDENCE_REJECTED",
            e.to_string(),
            "use outro attack_id/phase/sequence; evidência existente nunca é reescrita",
        ),
    }
}

async fn red_team_events(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    Query(q): Query<RedTeamQuery>,
) -> Response {
    let principal = match who(&runtime, &headers) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.require(Operation::ViewRuns) { return forbidden(e); }
    let rows = match rows_or_error(&runtime) { Ok(r) => r, Err(r) => return r };
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let mut events = Vec::new();
    let mut blocked = 0u64;
    let mut reached_upstream = 0u64;
    for row in rows.iter().rev() {
        let e = &row.evidence;
        if e.source.source_kind != "redteam_lab" { continue; }
        let campaign = e.content.fields.get("campaign_id").map(String::as_str).unwrap_or("");
        if q.campaign.as_deref().is_some_and(|wanted| wanted != campaign) { continue; }
        let is_blocked = e.content.fields.get("blocked").is_some_and(|v| v == "true");
        if is_blocked { blocked += 1; }
        let delta = e.content.fields.get("upstream_delta").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
        if delta > 0 { reached_upstream += 1; }
        events.push(serde_json::json!({
            "lsn": row.lsn,
            "record_hash": row.record_hash(),
            "evidence_id": e.evidence_id,
            "observed_at_unix_nanos": e.observed_at_unix_nanos,
            "run_id": e.run_id,
            "attack_id": e.content.fields.get("attack_id"),
            "campaign_id": e.content.fields.get("campaign_id"),
            "vector": e.content.fields.get("vector"),
            "target": e.content.fields.get("target"),
            "phase": e.content.fields.get("phase"),
            "result": e.content.fields.get("result"),
            "expected": e.content.fields.get("expected"),
            "reason_code": e.content.fields.get("reason_code"),
            "blocked": is_blocked,
            "upstream_delta": delta,
            "transport_status": e.outcome.as_ref().and_then(|o| o.transport_status),
            "capture_mode": e.privacy.capture_mode.label(),
        }));
        if events.len() >= limit { break; }
    }
    Json(serde_json::json!({
        "events": events,
        "summary": {
            "returned": events.len(),
            "blocked": blocked,
            "reached_upstream": reached_upstream,
        },
        "truth": "red-team metadata is lab-reporter evidence; native gateway decisions remain independent evidence",
    })).into_response()
}

'''
    if insert_marker not in text:
        raise SystemExit('RunsQuery marker missing')
    text = text.replace(insert_marker, redteam + insert_marker, 1)
api.write_text(text)

# End-to-end contract: the lab reporter writes metadata-only evidence and the
# read endpoint returns it with an LSN without storing the offensive payload.
testp = Path('crates/heraclitus-agent-gateway/tests/gateway_end_to_end.rs')
t = testp.read_text()
if 'redteam_lab_fica_no_hrkl_e_aparece_na_api' not in t:
    t = t.rstrip() + r'''

#[tokio::test]
async fn redteam_lab_fica_no_hrkl_e_aparece_na_api() {
    let h = harness(GatewayMode::Enforce).await;
    let (status, body) = post_json(
        &format!("{}/api/v1/agent/red-team/events", h.api_url),
        serde_json::json!({
            "attack_id": "rt-001",
            "campaign_id": "sandbox-demo",
            "vector": "mcp-policy-deny",
            "target": "mcp://sandbox/exec",
            "phase": "result",
            "result": "blocked",
            "expected": "blocked",
            "reason_code": "SHELL_DENIED",
            "blocked": true,
            "upstream_delta": 0,
            "transport_status": 403,
            "sequence": 1
        }),
        &[],
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["lsn"].as_u64().is_some(), "{body}");

    let (status, body) = get_json(&format!(
        "{}/api/v1/agent/red-team/events?campaign=sandbox-demo&limit=10",
        h.api_url
    )).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["events"][0]["attack_id"], "rt-001");
    assert_eq!(body["events"][0]["blocked"], true);
    assert_eq!(body["events"][0]["upstream_delta"], 0);
    assert_eq!(body["events"][0]["capture_mode"], "METADATA_ONLY");
    let dump = body.to_string();
    assert!(!dump.contains("rm -rf"));
    assert!(!dump.to_lowercase().contains("bearer "));
}
'''
    testp.write_text(t)

# Product documentation. Deliberately states the trust boundary: a lab report
# is sealed evidence of what the reporter claimed, not proof that the gateway
# itself observed the event.
doc = Path('docs/md/SPEC-new/SPEC-0079-Agent-Red-Team-Observability.md')
if not doc.exists():
    doc.write_text(r'''# SPEC-0079 — Agent Red-Team Observability

Status: IMPLEMENTED BY BRANCH / qualification pending.

## Goal

Make authorized adversarial tests visible and durable without pretending that
self-reported lab telemetry is the same thing as a native gateway decision.

## Contract

`POST /api/v1/agent/red-team/events` records **metadata only** in the Agent
Evidence log/HRKL. It never persists an offensive payload, credential, prompt,
Authorization header, shell command or exploit body. The writer needs the same
administrative capability used for capture changes. `GET` is read-only and uses
the ordinary run-view permission.

Each event carries `attack_id`, `campaign_id`, vector, target, phase, result,
expected result, reason code, `blocked`, `upstream_delta` and transport status.
The resulting response returns the evidence id and LSN.

## Trust boundary

A `redteam_lab` record proves that this reporter record was appended to HRKL at
that LSN. It does **not**, by itself, prove that an external effect did or did
not happen. Native `PolicyEvaluated`, `ToolDenied`, approval and
`ExternalEffectObserved` evidence remains the authoritative independent side of
the correlation. The Dashboard must show this distinction.

## Demonstration requirement

The laboratory runner uses a campaign id and unique attack ids. It performs the
real request against localhost, measures the observed response and upstream hit
delta when available, then reports only the safe metadata. The Dashboard shows
both the lab event stream and the native Agent Black Box counters/timeline.

## Safety

The reference runner is localhost-only by default and refuses non-loopback
hosts unless its source is deliberately changed. This is a qualification tool,
not a network scanner.
''')

print('SPEC-0079 patch applied')
