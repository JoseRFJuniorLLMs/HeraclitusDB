/* Heraclitus Agent Black Box — Console
 *
 * SPEC-0076 §4: cinco tarefas, e nada mais.
 *
 *   JTBD-1  ver uma execução          -> #/runs, #/runs/:id
 *   JTBD-2  entender uma acção        -> a timeline expandida
 *   JTBD-3  aprovar/negar             -> #/approvals
 *   JTBD-4  verificar integridade     -> o estado por run e por evidência
 *   JTBD-5  exportar                  -> o botão de Evidence Bundle
 *
 * §15: sem Node em produção. Isto é JavaScript simples servido pelo binário
 * Rust; não há build, não há bundler, não há dependência de runtime.
 *
 * §31: paginação por cursor. Nunca carregar todos os runs, toda a evidência ou
 * todos os resultados de ferramenta no browser.
 */

const view = document.getElementById('view');
const nav = document.getElementById('nav');
let STATUS = null;

// ── utilitários ─────────────────────────────────────────────────────────────

/** Escapa texto para HTML. Tudo o que vem da API passa por aqui: o nome de uma
 *  ferramenta ou de um agente é conteúdo escrito por terceiros. */
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function when(nanos) {
  if (!nanos) return '';
  const d = new Date(Number(nanos) / 1e6);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function whenFull(nanos) {
  if (!nanos) return '';
  return new Date(Number(nanos) / 1e6).toLocaleString();
}

function dur(nanos) {
  if (nanos === null || nanos === undefined) return '';
  const ms = Number(nanos) / 1e6;
  if (ms < 1000) return ms.toFixed(0) + ' ms';
  return (ms / 1000).toFixed(2) + ' s';
}

async function api(path, options) {
  const res = await fetch(path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, options || {}));
  const text = await res.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch (e) { body = { error: 'BAD_RESPONSE', detail: text }; }
  if (!res.ok) {
    const err = new Error((body && body.detail) || res.statusText);
    err.code = (body && body.error) || 'HTTP_' + res.status;
    err.action = body && body.operator_action;
    throw err;
  }
  return body;
}

function errorBox(e) {
  return `<div class="notice notice-error">
    <strong>${esc(e.code || 'ERROR')}</strong><br>${esc(e.message)}
    ${e.action ? `<div class="muted gap-sm">${esc(e.action)}</div>` : ''}
  </div>`;
}

function chip(state) {
  return `<span class="chip chip-${esc(state)}">${esc(state)}</span>`;
}

function decisionPill(decision, enforced) {
  if (!decision) return '';
  const shadow = enforced === false ? ' <span class="pill pill-shadow">shadow</span>' : '';
  return `<span class="pill pill-${esc(decision)}">${esc(decision)}</span>${shadow}`;
}

// ── estado global ───────────────────────────────────────────────────────────

// §28 — o que a autenticacao em vigor consegue e nao consegue provar.
//
// Sao tres estados, nao dois. O do meio e o que engana: uma senha partilhada
// fecha a porta, mas toda a gente que entra e "admin". Os papeis `approver` e
// `policy_admin`, que a 0076 separa de proposito, deixam de separar pessoa
// nenhuma — quem aprova e quem escreve a politica sao o mesmo sujeito no log.
// Dizer isto em voz alta e mais util do que um cadeado verde que mente.
function authBanner() {
  const el = document.getElementById('auth-banner');
  el.textContent = '';
  const forte = document.createElement('strong');
  let resto;
  if (STATUS.auth === 'dev_local') {
    el.className = 'banner banner-dev';
    forte.textContent = 'DEVELOPMENT PROFILE';
    resto = ' \u2014 no authentication is configured. Anyone who can reach this ' +
      'port has full access. Configure OIDC before using this outside a laptop.';
  } else if (STATUS.auth_identifies_people === false) {
    el.className = 'banner banner-dev';
    forte.textContent = 'SHARED PASSWORD';
    resto = ' \u2014 access is gated, but every session is the same subject (' +
      STATUS.principal.subject + '). Approvals and policy changes cannot be ' +
      'attributed to a person, so the approver / policy_admin separation is not ' +
      'in force. Configure OIDC before relying on this evidence for attribution.';
  } else {
    el.hidden = true;
    return;
  }
  el.appendChild(forte);
  el.appendChild(document.createTextNode(resto));
  el.hidden = false;
}

async function loadStatus() {
  STATUS = await api('/api/v1/agent/status');
  document.getElementById('footer-engine').textContent = STATUS.engine;
  authBanner();

  const state = STATUS.summary.integrity;
  const c = document.getElementById('integrity-chip');
  c.className = 'chip chip-' + state;
  c.textContent = state;

  // §33: quando a verificação falha, o produto di-lo em voz alta e não deixa
  // ninguém representar a evidência como verificada.
  const banner = document.getElementById('integrity-banner');
  if (state === 'BROKEN') {
    banner.hidden = false;
    banner.textContent =
      'INTEGRITY FAILURE\n\n' +
      'Part of the evidence could not be verified. Agent execution data remains ' +
      'available for inspection, but must not be represented as cryptographically verified.';
  } else {
    banner.hidden = true;
  }

  // §5: sem gateway, o menu encolhe. A Consola não mostra tabuleiros vazios.
  const hasGateway = STATUS.mcp_gateway !== 'DISABLED';
  nav.querySelectorAll('.hidden-when-no-gateway').forEach(a => { a.hidden = !hasGateway; });

  const pending = STATUS.summary.pending_approvals || 0;
  const badge = document.getElementById('pending-badge');
  badge.hidden = pending === 0;
  badge.textContent = pending;
}

// ── Runs ────────────────────────────────────────────────────────────────────

async function renderRuns() {
  const params = new URLSearchParams(location.hash.split('?')[1] || '');
  const q = new URLSearchParams();
  ['agent', 'status', 'tool', 'decision', 'approver'].forEach(k => {
    if (params.get(k)) q.set(k, params.get(k));
  });
  q.set('limit', '50');

  const data = await api('/api/v1/agent/runs?' + q.toString());
  const s = STATUS.summary;

  view.innerHTML = `
    <h1>Runs</h1>
    <p class="muted">What your agents did, with which identity, under which authorization.</p>

    <div class="cards">
      <div class="card"><div class="k">Runs</div><div class="v">${s.runs}</div></div>
      <div class="card"><div class="k">Tool calls</div><div class="v">${s.tool_calls}</div></div>
      <div class="card"><div class="k">Denied actions</div><div class="v">${s.denied}</div></div>
      <div class="card"><div class="k">Pending approvals</div><div class="v">${s.pending_approvals}</div></div>
      <div class="card"><div class="k">Evidence integrity</div><div class="v v-chip">${chip(s.integrity)}</div></div>
    </div>

    <form class="filters" id="filters">
      <input name="agent" placeholder="agent" value="${esc(params.get('agent') || '')}">
      <input name="tool" placeholder="tool" value="${esc(params.get('tool') || '')}">
      <input name="approver" placeholder="human approver" value="${esc(params.get('approver') || '')}">
      <select name="status">
        <option value="">any status</option>
        ${['Success', 'Failed', 'Running'].map(x =>
          `<option ${params.get('status') === x ? 'selected' : ''}>${x}</option>`).join('')}
      </select>
      <select name="decision">
        <option value="">any decision</option>
        ${['allow', 'deny', 'require_approval'].map(x =>
          `<option ${params.get('decision') === x ? 'selected' : ''}>${x}</option>`).join('')}
      </select>
      <button type="submit">Filter</button>
    </form>

    <div class="table-wrap"><table>
      <thead><tr>
        <th>Started</th><th>Agent</th><th>User</th><th>Tools</th>
        <th>Approvals</th><th>Denied</th><th>Status</th><th>Integrity</th>
      </tr></thead>
      <tbody>
        ${data.runs.length === 0
          ? `<tr><td colspan="8" class="muted">No runs yet. Point an OpenTelemetry exporter at
               <span class="mono">http://localhost:4318</span>, or run
               <span class="mono">heraclitus agent demo</span>.</td></tr>`
          : data.runs.map(r => `
            <tr class="clickable" data-run="${esc(r.run_id)}">
              <td>${when(r.started_at_unix_nanos)}</td>
              <td>${esc(r.agent_name || r.agent_id)}</td>
              <td>${esc(r.human_subject || '—')}</td>
              <td>${r.tool_calls}</td>
              <td>${r.approvals}</td>
              <td>${r.denied}</td>
              <td>${esc(String(r.status).toLowerCase())}</td>
              <td>${chip(r.integrity)}</td>
            </tr>`).join('')}
      </tbody>
    </table></div>
    <p class="muted">Showing ${data.runs.length} of ${data.total}.</p>`;

  view.querySelectorAll('tr.clickable').forEach(tr => {
    tr.addEventListener('click', () => {
      location.hash = '#/runs/' + encodeURIComponent(tr.getAttribute('data-run'));
    });
  });

  document.getElementById('filters').addEventListener('submit', ev => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const out = new URLSearchParams();
    for (const [k, v] of f.entries()) if (v) out.set(k, v);
    location.hash = '#/runs?' + out.toString();
    route();
  });
}

// ── Run detail ──────────────────────────────────────────────────────────────

async function renderRun(id) {
  const [detail, timeline] = await Promise.all([
    api('/api/v1/agent/runs/' + encodeURIComponent(id)),
    api('/api/v1/agent/runs/' + encodeURIComponent(id) + '/timeline?limit=500'),
  ]);
  const r = detail.run;

  view.innerHTML = `
    <p class="muted"><a href="#/runs">&larr; Runs</a></p>
    <h1>Run ${esc(r.run_id)}</h1>
    <dl class="kv">
      <dt>Agent</dt><dd>${esc(r.agent_name || r.agent_id)}</dd>
      <dt>User</dt><dd>${esc(r.human_subject || '—')}</dd>
      <dt>Started</dt><dd>${esc(whenFull(r.started_at_unix_nanos))}</dd>
      <dt>Status</dt><dd>${esc(String(r.status).toLowerCase())}</dd>
      <dt>Integrity</dt><dd>${chip(r.integrity)}</dd>
      <dt>LSN range</dt><dd>${r.first_lsn}..${r.last_lsn}</dd>
    </dl>

    <div class="gap-md"><button class="primary" id="export">Export Evidence Bundle</button></div>
    <div id="export-out"></div>

    <h2>Timeline</h2>
    <ul class="timeline">
      ${timeline.entries.map(entryHtml).join('')}
    </ul>
    ${timeline.next_cursor !== null && timeline.next_cursor !== undefined
      ? `<p class="muted">Showing ${timeline.entries.length} of ${timeline.total} entries.</p>` : ''}`;

  document.getElementById('export').addEventListener('click', async ev => {
    ev.target.disabled = true;
    const out = document.getElementById('export-out');
    try {
      const res = await api('/api/v1/agent/evidence/export', {
        method: 'POST', body: JSON.stringify({ run_id: id }),
      });
      out.innerHTML = `<div class="notice notice-ok">
        Bundle <span class="mono">${esc(res.bundle_id)}</span> &mdash;
        ${res.records} records, ${res.proofs_present} proofs${res.pending_seal ? `, ${res.pending_seal} pending seal` : ''}.
        <div class="gap-md"><a href="${esc(res.download)}">Download ${esc(res.file)}</a></div>
        <div class="mono gap-md">${esc(res.verify_command)}</div>
      </div>`;
    } catch (e) {
      out.innerHTML = errorBox(e);
    }
    ev.target.disabled = false;
  });
}

function entryHtml(e) {
  const bits = [];
  if (e.tool_call_id) bits.push(['tool call id', e.tool_call_id]);
  if (e.model_id) bits.push(['model', e.model_id]);
  if (e.policy_rule_id) bits.push(['policy rule', e.policy_rule_id]);
  if (e.approval_id) bits.push(['approval', e.approval_id]);
  if (e.approver_subject) bits.push(['approved by', e.approver_subject]);
  if (e.external_effect_id) bits.push(['external effect', e.external_effect_id]);
  if (e.error_code) bits.push(['error', e.error_code]);
  if (e.duration_nanos) bits.push(['duration', dur(e.duration_nanos)]);
  bits.push(['evidence id', e.evidence_id]);
  bits.push(['record hash', e.record_hash]);
  bits.push(['HRKL LSN', e.lsn]);
  bits.push(['capture mode', e.capture_mode]);
  if (e.parents && e.parents.length) bits.push(['parents', e.parents.join(', ')]);

  return `<li class="kind-${esc(e.kind)}">
    <span class="when">${esc(when(e.at_unix_nanos))}</span>
    <span class="what">${esc(e.summary)}</span>
    ${decisionPill(e.policy_decision, e.policy_enforced)}
    <details>
      <summary>details &amp; proof</summary>
      <dl class="kv">${bits.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
      <p class="gap-sm"><button data-verify="${esc(e.evidence_id)}">Verify again</button>
      <span data-proof="${esc(e.evidence_id)}" class="muted"></span></p>
    </details>
  </li>`;
}

view.addEventListener('click', async ev => {
  const id = ev.target.getAttribute && ev.target.getAttribute('data-verify');
  if (!id) return;
  const out = view.querySelector(`[data-proof="${CSS.escape(id)}"]`);
  out.textContent = ' checking…';
  try {
    const res = await api('/api/v1/agent/evidence/' + encodeURIComponent(id) + '/proof');
    if (res.state === 'AVAILABLE') {
      out.innerHTML = ` Merkle proof: <strong>${res.closes ? 'VALID' : 'INVALID'}</strong>
        &middot; logical root <span class="mono">${esc(res.proof.logical_root.slice(0, 16))}…</span>
        &middot; RFC3161: ${res.proof.timestamp_receipt ? 'PRESENT' : 'NOT CONFIGURED'}`;
    } else if (res.state && res.state.state === 'pending_seal') {
      out.textContent = ' UNVERIFIED — the segment holding this record has not been sealed yet.';
    } else {
      out.textContent = ' no proof available for this record.';
    }
  } catch (e) {
    out.innerHTML = ` <span class="fail">${esc(e.code)}: ${esc(e.message)}</span>`;
  }
});

// ── Approvals ───────────────────────────────────────────────────────────────

async function renderApprovals() {
  const data = await api('/api/v1/agent/approvals');
  const pending = data.pending || [];
  view.innerHTML = `
    <h1>Pending approvals (${pending.length})</h1>
    <p class="muted">An approval authorizes exactly one execution of exactly these arguments.
      Changing any argument after approval invalidates it.</p>
    ${!data.can_approve ? `<div class="notice">Your role cannot approve actions. You are seeing this inbox read-only.</div>` : ''}
    <div id="list">
      ${pending.length === 0
        ? '<p class="muted">Nothing waiting.</p>'
        : pending.map(approvalHtml).join('')}
    </div>`;

  view.querySelectorAll('[data-decide]').forEach(b => {
    b.addEventListener('click', async () => {
      const id = b.getAttribute('data-decide');
      const approve = b.getAttribute('data-approve') === '1';
      b.disabled = true;
      const box = b.closest('.approval');
      try {
        await api(`/api/v1/agent/approvals/${encodeURIComponent(id)}/${approve ? 'approve' : 'deny'}`, {
          method: 'POST', body: JSON.stringify({}),
        });
        box.innerHTML = `<div class="notice notice-ok">${approve ? 'Approved' : 'Denied'}. The decision is now evidence.</div>`;
        await loadStatus();
      } catch (e) {
        box.insertAdjacentHTML('beforeend', errorBox(e));
        b.disabled = false;
      }
    });
  });
}

function approvalHtml(rec) {
  const r = rec.request;
  const p = r.preview || {};
  const fields = Object.entries(p.fields || {});
  return `<div class="approval">
    <div><strong>${esc(p.agent || '—')}</strong> wants to call
      <strong>${esc(p.tool || '—')}</strong> on <strong>${esc(p.server || '—')}</strong>
      ${p.environment ? `in <strong>${esc(p.environment)}</strong>` : ''}</div>
    <dl class="kv">
      ${fields.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}
      <dt>policy rule</dt><dd>${esc(p.policy_rule || '—')}</dd>
      <dt>requires</dt><dd>${esc((r.requested_roles || []).join(', '))}</dd>
      <dt>arguments digest</dt><dd>${esc((p.argument_digest || '').slice(0, 32))}…</dd>
      <dt>expires</dt><dd>${esc(new Date(r.expires_at * 1000).toLocaleString())}</dd>
    </dl>
    <div class="muted gap-md">${esc(r.reason || '')}</div>
    <div class="actions">
      <button class="danger" data-decide="${esc(r.approval_id)}" data-approve="0">Deny</button>
      <button class="primary" data-decide="${esc(r.approval_id)}" data-approve="1">Approve</button>
    </div>
  </div>`;
}

// ── Policies ────────────────────────────────────────────────────────────────

async function renderPolicies() {
  const data = await api('/api/v1/agent/policies');
  const a = data.active;
  view.innerHTML = `
    <h1>Policy</h1>
    <dl class="kv">
      <dt>ACTIVE</dt><dd>${esc(a.id)} / ${esc(a.version)}</dd>
      <dt>hash</dt><dd>${esc(a.hash)}</dd>
      <dt>activated by</dt><dd>${esc(a.activated_by)}</dd>
      <dt>activated at</dt><dd>${a.activated_at_unix_seconds ? esc(new Date(a.activated_at_unix_seconds * 1000).toLocaleString()) : '—'}</dd>
      <dt>default</dt><dd>${esc(a.default_decision)}</dd>
      <dt>rules</dt><dd>${(a.rules || []).length}</dd>
    </dl>

    <div class="table-wrap"><table>
      <thead><tr><th>Rule</th><th>Server</th><th>Tool</th><th>Conditions</th><th>Decision</th></tr></thead>
      <tbody>${(a.rules || []).map(r => `
        <tr>
          <td>${esc(r.id)}</td>
          <td>${esc((r.match && r.match.server) || '*')}</td>
          <td>${esc((r.match && r.match.tool) || '*')}</td>
          <td class="mono">${esc(((r.match && r.match.conditions) || [])
              .map(c => `${c.field} ${c.op} ${c.value === undefined ? '' : c.value}`).join('; ') || '—')}</td>
          <td>${decisionPill(r.decision)}</td>
        </tr>`).join('')}
      </tbody>
    </table></div>

    <h2>Simulate a new policy against history</h2>
    <p class="muted">Replays the tool calls already recorded and shows what would change. Nothing is activated.</p>
    <textarea id="doc" spellcheck="false" placeholder="paste an agent-policy-v1 document (YAML or JSON)"></textarea>
    <div class="button-row">
      <button id="validate">Validate</button>
      <button id="simulate">Simulate</button>
      <button id="activate" class="primary">Activate</button>
    </div>
    <div id="policy-out"></div>`;

  const out = document.getElementById('policy-out');
  const doc = () => document.getElementById('doc').value;

  document.getElementById('validate').addEventListener('click', async () => {
    try {
      const r = await api('/api/v1/agent/policies/validate', { method: 'POST', body: JSON.stringify({ document: doc() }) });
      out.innerHTML = `<div class="notice notice-ok">VALIDATED — ${esc(r.id)} / ${esc(r.version)},
        ${r.rules} rules, hash <span class="mono">${esc(r.hash)}</span></div>`;
    } catch (e) { out.innerHTML = errorBox(e); }
  });

  document.getElementById('simulate').addEventListener('click', async () => {
    try {
      const r = await api('/api/v1/agent/policies/simulate', { method: 'POST', body: JSON.stringify({ document: doc() }) });
      out.innerHTML = `<div class="notice">
        <div class="mono">historical tool calls: ${r.historical_tool_calls}
ALLOW:               ${r.allow}
DENY:                ${r.deny}
REQUIRE_APPROVAL:    ${r.require_approval}
changed vs active:   ${r.changed_vs_active}</div>
        ${r.samples.length ? `<h2>Changed</h2>
          <div class="table-wrap"><table><thead><tr><th>Tool</th><th>Active</th><th>Candidate</th><th>Rule</th></tr></thead>
          <tbody>${r.samples.map(s => `<tr><td>${esc(s.tool)}</td><td>${esc(s.active)}</td>
            <td>${esc(s.candidate)}</td><td>${esc(s.candidate_rule || '—')}</td></tr>`).join('')}</tbody></table></div>` : ''}
      </div>`;
    } catch (e) { out.innerHTML = errorBox(e); }
  });

  document.getElementById('activate').addEventListener('click', async () => {
    if (!confirm('Activate this policy? It takes effect immediately for every new tool call.')) return;
    try {
      const r = await api('/api/v1/agent/policies/activate', { method: 'POST', body: JSON.stringify({ document: doc() }) });
      out.innerHTML = `<div class="notice notice-ok">ACTIVE — ${esc(r.version)} (${esc(r.hash)}) activated by ${esc(r.activated_by)}</div>`;
      await loadStatus();
    } catch (e) { out.innerHTML = errorBox(e); }
  });
}

// ── Settings ────────────────────────────────────────────────────────────────

async function renderSettings() {
  const s = STATUS;
  view.innerHTML = `
    <h1>Settings</h1>

    <h2>Privacy</h2>
    <p class="muted">Observability must not become a secret leak. These are the defaults; changing
      capture mode requires an administrator and is recorded.</p>
    <dl class="kv">
      <dt>Capture mode</dt><dd>${esc(s.capture.mode)}</dd>
      <dt>Prompt bodies</dt><dd>${esc(s.capture.prompt_bodies)}</dd>
      <dt>Completion bodies</dt><dd>${esc(s.capture.completion_bodies)}</dd>
      <dt>Tool args</dt><dd>${esc(s.capture.tool_args)}</dd>
      <dt>Tool results</dt><dd>${esc(s.capture.tool_results)}</dd>
      <dt>Known secret filters</dt><dd>${esc(s.capture.known_secret_filters)}</dd>
    </dl>

    <h2>Status</h2>
    <dl class="kv">
      <dt>Evidence log</dt><dd>${esc(s.evidence_log)}</dd>
      <dt>OTLP ingest</dt><dd>${esc(s.otlp_ingest)}</dd>
      <dt>MCP gateway</dt><dd>${esc(s.mcp_gateway)}</dd>
      <dt>Bypass protection</dt><dd>${esc(s.bypass_protection)}</dd>
      <dt>Policy</dt><dd>${esc(s.policy.version)} (${esc(s.policy.rules)} rules)</dd>
      <dt>Pending approvals</dt><dd>${esc(s.summary.pending_approvals)}</dd>
      <dt>RFC 3161</dt><dd>${esc(s.rfc3161)}</dd>
      <dt>Authentication</dt><dd>${esc(s.auth)}</dd>
      <dt>Your roles</dt><dd>${esc((s.principal.roles || []).join(', '))}</dd>
    </dl>

    <h2>Ingest</h2>
    <dl class="kv">
      <dt>Events</dt><dd>${esc(s.ingest.events)}</dd>
      <dt>Duplicates dropped</dt><dd>${esc(s.ingest.duplicates)}</dd>
      <dt>Conflicts refused</dt><dd>${esc(s.ingest.conflicts)}</dd>
      <dt>Rejected</dt><dd>${esc(s.ingest.rejected)}</dd>
      <dt>Non-agent spans ignored</dt><dd>${esc(s.ingest.ignored_spans)}</dd>
      <dt>Batches</dt><dd>${esc(s.ingest.batches)}</dd>
    </dl>

    <h2>Verify a bundle offline</h2>
    <p class="mono">heraclitus agent verify evidence-&lt;id&gt;.zip</p>
    <p class="muted">The verifier needs no network, no database and no server. A single changed byte fails it.</p>`;
}

// ── router ──────────────────────────────────────────────────────────────────

async function route() {
  const hash = location.hash || '#/runs';
  const path = hash.split('?')[0];
  nav.querySelectorAll('a').forEach(a => a.classList.toggle('active', hash.startsWith(a.getAttribute('href'))));
  view.innerHTML = '<p class="muted">Loading…</p>';
  try {
    await loadStatus();
    if (path.startsWith('#/runs/')) return await renderRun(decodeURIComponent(path.slice('#/runs/'.length)));
    if (path.startsWith('#/approvals')) return await renderApprovals();
    if (path.startsWith('#/policies')) return await renderPolicies();
    if (path.startsWith('#/settings')) return await renderSettings();
    return await renderRuns();
  } catch (e) {
    view.innerHTML = errorBox(e);
  }
}

window.addEventListener('hashchange', route);
route();
