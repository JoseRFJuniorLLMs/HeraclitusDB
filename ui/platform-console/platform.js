/* HeraclitusDB — Platform Console (SPEC-0077)
 *
 * A regra que governa este ficheiro é a §33: NÃO INVENTAR DADOS.
 *
 * Em concreto, e porque a distinção é fácil de perder ao escrever UI:
 *
 *     0      é um facto sobre o log — "procurei e não há nada"
 *     null   é a ausência de facto — "não consegui perguntar"
 *
 * `num()` trata-os de maneira diferente de propósito. Um `|| 0` algures neste
 * ficheiro transformaria "não sei" em "zero", e uma home que escreve `0 events`
 * sobre um banco que ela não conseguiu consultar é pior do que uma home vazia:
 * passa por informada. */

let SUMMARY = null;

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function api(path) {
  const r = await fetch(path, { headers: { accept: 'application/json' } });
  if (!r.ok) {
    let detalhe = r.statusText;
    try {
      const j = await r.json();
      detalhe = j.detail || j.error || detalhe;
    } catch (_) { /* corpo não-JSON: fica o statusText */ }
    throw new Error(`${r.status} — ${detalhe}`);
  }
  return r.json();
}

/** Um inteiro, com separadores de milhar. `null`/`undefined` viram `N/A`. */
function num(v) {
  if (v === null || v === undefined) return null;
  return Number(v).toLocaleString('en-US');
}

/** Um card. `valor === null` renderiza `N/A` e diz na classe que o é. */
function card(rotulo, valor) {
  const ausente = valor === null || valor === undefined;
  return `<div class="card"><div class="k">${esc(rotulo)}</div>` +
    `<div class="v${ausente ? ' na' : ''}">${ausente ? 'N/A' : esc(valor)}</div></div>`;
}

function bytes(n) {
  if (n === null || n === undefined) return null;
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(1)) + ' ' + u[i];
}

function quando(ms) {
  if (ms === null || ms === undefined) return null;
  return new Date(Number(ms)).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}

// ── autenticação ────────────────────────────────────────────────────────────

// §28 da 0076, aplicada aqui: são três estados, não dois. O do meio engana —
// uma senha partilhada fecha a porta e não diz quem entrou.
function authBanner() {
  const el = document.getElementById('auth-banner');
  if (!SUMMARY || !SUMMARY.auth) { el.hidden = true; return; }
  el.textContent = '';
  const forte = document.createElement('strong');
  let resto;
  if (SUMMARY.auth === 'dev_local') {
    forte.textContent = 'DEVELOPMENT PROFILE';
    resto = ' — no authentication is configured. Anyone who can reach this ' +
      'port has full access. Configure OIDC before using this outside a laptop.';
  } else if (SUMMARY.auth_identifies_people === false) {
    forte.textContent = 'SHARED PASSWORD';
    resto = ' — access is gated, but every session is the same subject. ' +
      'Nothing on this console can be attributed to a person.';
  } else {
    el.hidden = true;
    return;
  }
  el.appendChild(forte);
  el.appendChild(document.createTextNode(resto));
  el.hidden = false;
}

// ── vistas ──────────────────────────────────────────────────────────────────

function viewOverview() {
  const s = SUMMARY;
  // §10 — a home responde a "o banco está saudável, quantos dados existem,
  // qual o último LSN, qual o estado da integridade". Não a "quantos agentes
  // correram hoje": essa pergunta vive em /agent.
  const totalFontes = s.sources.length;
  const eventosDasFontes = s.sources.reduce((a, f) => a + Number(f.events || 0), 0);

  let html = `<h1>${esc(s.product)}</h1>
    <p class="muted">${esc(s.tagline)} &middot; v${esc(s.version)}</p>

    <h2>Data</h2>
    <div class="cards">
      ${card('Last LSN', num(s.last_lsn))}
      ${card('Sources', totalFontes ? num(totalFontes) : (s.last_lsn === null ? null : '0'))}
      ${card('Events in sources', totalFontes ? num(eventosDasFontes) : (s.last_lsn === null ? null : '0'))}
      ${card('Pending in memtable', num(s.memtable_pending))}
      ${card('Storage format', s.storage_format)}
    </div>`;

  html += `<h2>Integrity</h2>
    <div class="cards">
      ${card('HRKL / Merkle', rotuloEstado(s.integrity))}
      ${card('Raw bytes', bytes(s.storage.raw_bytes))}
      ${card('Packed bytes', bytes(s.storage.packed_bytes))}
      ${card('Compression', s.storage.compression_ratio === null || s.storage.compression_ratio === undefined
        ? null : (Number(s.storage.compression_ratio) * 100).toFixed(1) + '%')}
    </div>`;
  if (s.integrity_detail) {
    html += `<p class="muted gap-md">${esc(s.integrity_detail)}</p>`;
  }

  if (s.indexes.length) {
    html += `<h2>Indexes</h2><div class="cards">` +
      s.indexes.map((i) => card(i.label, num(i.count))).join('') + `</div>`;
  }

  html += `<h2>Modules</h2>` + modulesGrid(s.modules);
  return html;
}

function viewData() {
  const s = SUMMARY;
  // §11 — dados reais carregados pelo utilizador. Nenhum nome de dataset é
  // hardcoded: o que aparece aqui saiu do log.
  if (!s.sources.length) {
    return `<h1>Data</h1>
      <p class="muted">No sources found in the log.</p>
      <div class="notice">A source appears here once events carrying a source
      identifier have been appended. Load the sample dataset with
      <span class="mono">python examples/data-platform/tour.py</span>, or ingest
      your own.</div>`;
  }
  const linhas = s.sources.map((f) => `<tr>
      <td class="mono">${esc(f.id)}</td>
      <td class="num">${esc(num(f.events) ?? 'N/A')}</td>
      <td class="num">${esc(num(f.first_lsn) ?? 'N/A')}</td>
      <td class="num">${esc(num(f.last_lsn) ?? 'N/A')}</td>
      <td class="mono">${esc(quando(f.first_ms) ?? 'N/A')}</td>
      <td class="mono">${esc(quando(f.last_ms) ?? 'N/A')}</td>
    </tr>`).join('');
  return `<h1>Data</h1>
    <p class="muted">Sources present in the append-only log.</p>
    <div class="table-wrap"><table>
      <thead><tr><th>Source</th><th class="num">Events</th><th class="num">First LSN</th>
      <th class="num">Last LSN</th><th>First seen</th><th>Last seen</th></tr></thead>
      <tbody>${linhas}</tbody>
    </table></div>
    ${s.views.length ? `<h2>Views</h2><p class="mono">${s.views.map(esc).join(' &middot; ')}</p>` : ''}`;
}

function viewIntegrity() {
  const s = SUMMARY;
  // §15 — os estados são os mesmos da 0076 §33, e UNVERIFIED nunca vira
  // VERIFIED por omissão.
  return `<h1>Integrity</h1>
    <p class="muted">Every record is in an append-only log with canonical Merkle roots.</p>
    <div class="cards">
      ${card('State', rotuloEstado(s.integrity))}
      ${card('Last LSN', num(s.last_lsn))}
      ${card('Storage format', s.storage_format)}
    </div>
    ${s.integrity_detail ? `<div class="notice">${esc(s.integrity_detail)}</div>` : ''}
    <h2>Storage</h2>
    <dl class="kv">
      <dt>raw bytes</dt><dd>${esc(bytes(s.storage.raw_bytes) ?? 'N/A')}</dd>
      <dt>packed bytes</dt><dd>${esc(bytes(s.storage.packed_bytes) ?? 'N/A')}</dd>
      <dt>appended total</dt><dd>${esc(bytes(s.storage.append_bytes_total) ?? 'N/A')}</dd>
      <dt>compression ratio</dt><dd>${s.storage.compression_ratio === null || s.storage.compression_ratio === undefined
        ? 'N/A' : esc(s.storage.compression_ratio)}</dd>
    </dl>
    ${s.storage.unavailable_reason ? `<p class="muted gap-md">${esc(s.storage.unavailable_reason)}</p>` : ''}
    <h2>Offline verification</h2>
    <p class="muted">Integrity does not depend on this console being honest.
    Verify the log from a shell, against the binary of your choice:</p>
    <p class="mono">heraclitus verify &lt;data-dir&gt;</p>`;
}

// `NOTBUILT` e `NOTCONFIGURED` vêm assim do servidor porque o valor na rede é
// um identificador, não uma frase. Aqui separam-se para serem lidos — e só
// aqui: a classe CSS continua a usar o valor cru, senão um estado novo do
// servidor deixava de encontrar a sua cor.
function rotuloEstado(e) {
  if (e === 'NOTBUILT') return 'NOT BUILT';
  if (e === 'NOTCONFIGURED') return 'NOT CONFIGURED';
  return e;
}

function modulesGrid(mods) {
  if (!mods.length) return `<p class="muted">No module information available.</p>`;
  return `<div class="modules">` + mods.map((m) => `
    <div class="module">
      <div class="name">${esc(m.name)}</div>
      <div class="summary">${esc(m.summary)}</div>
      ${m.detail ? `<div class="detail">${esc(m.detail)}</div>` : ''}
      <div>
        <span class="chip chip-${esc(m.state)}">${esc(rotuloEstado(m.state))}</span>
        ${m.href ? ` <a href="${esc(m.href)}">Open &rarr;</a>` : ''}
      </div>
    </div>`).join('') + `</div>`;
}

function viewModules() {
  // §18/§38 — estados reais. NOTBUILT existe porque uma rota ausente por
  // compilação é um problema diferente de uma rota desligada na configuração.
  return `<h1>Modules</h1>
    <p class="muted">Optional surfaces over the same temporal engine.
    None of them is required to run HeraclitusDB.</p>
    ${modulesGrid(SUMMARY.modules)}`;
}

// ── roteamento ──────────────────────────────────────────────────────────────

const ROTAS = {
  overview: viewOverview,
  data: viewData,
  integrity: viewIntegrity,
  modules: viewModules,
};

function render() {
  const rota = (location.hash.replace(/^#\//, '') || 'overview').split('/')[0];
  const fn = ROTAS[rota] || viewOverview;
  const alvo = ROTAS[rota] ? rota : 'overview';
  document.querySelectorAll('#nav a').forEach((a) => {
    a.classList.toggle('active', a.dataset.route === alvo);
  });
  document.getElementById('view').innerHTML = fn();
}

async function boot() {
  try {
    SUMMARY = await api('/api/v1/platform/summary');
  } catch (e) {
    document.getElementById('view').innerHTML =
      `<h1>HeraclitusDB</h1><div class="notice notice-error">Could not read platform status: ${esc(e.message)}</div>`;
    return;
  }
  document.getElementById('footer-engine').textContent =
    `${SUMMARY.product} ${SUMMARY.version}`;

  const chip = document.getElementById('integrity-chip');
  chip.className = 'chip chip-' + SUMMARY.integrity;
  chip.textContent = rotuloEstado(SUMMARY.integrity);

  authBanner();
  render();
}

window.addEventListener('hashchange', render);
boot();
