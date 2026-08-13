# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

"""Heraclitus Console — auditoria + camada de FRAUDE sobre o HeraclitusDB.

- editor GQL -> grafo (com arestas de proveniência)
- "Fraudes": deteta os casos, AGRUPA por comunidade (proveniência partilhada)
- LINHA DO TEMPO visual (infográfica) sobre o log event-sourced: cada evento no
  eixo do tempo (ts_hlc) com marcadores + hints; clique = AS OF naquele ponto
- painéis retráteis -> grafo em tela cheia
- clique num nó -> expande proveniência; escudo Merkle

  py console/server.py            # http://127.0.0.1:7480
"""
import argparse
import json
import os
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_ROOT), "sdk", "python"))

import heraclitusdb  # noqa: E402

_DB = {"addr": "127.0.0.1:7474"}


def _client():
    return heraclitusdb.connect(_DB["addr"])


def _clean_kind(k):
    s = str(k or "")
    if s.startswith('Custom("') and s.endswith('")'):
        return s[8:-2]
    return s


def _graph_payload(db, rows, max_prov=400):
    ids, nodes = set(), []
    for r in rows:
        rid = r.get("id")
        if not rid or rid in ids:
            continue
        ids.add(rid)
        nodes.append({"id": rid, "kind": _clean_kind(r.get("kind")), "content": r.get("content", "")})
    edges = []
    if len(ids) <= max_prov:
        for rid in ids:
            for p in db.provenance(rid):
                if p in ids:
                    edges.append({"from": rid, "to": p})
    return {"nodes": nodes, "edges": edges}


def _fraudes(db):
    """Camada de fraude: nós dos casos + arestas de proveniência + GRUPOS (componentes
    conexos, i.e. fraudes ligadas por um facilitador partilhado) + linha do tempo."""
    rows = db.query("MATCH (n) RETURN n LIMIT 8000")
    rows = rows if isinstance(rows, list) else []
    fraud = [r for r in rows if isinstance(r.get("attrs"), dict) and r["attrs"].get("caso") and r.get("id")]
    ids = {r["id"] for r in fraud}

    adj = {i: set() for i in ids}
    edges = []
    seen = set()

    def _link(a, b):
        if a == b or (a, b) in seen:
            return
        edges.append({"from": a, "to": b})
        adj[a].add(b)
        adj[b].add(a)
        seen.add((a, b))
        seen.add((b, a))

    # 1) Proveniência (o laranja partilhado funde casos no mesmo grupo).
    for r in fraud:
        nid = r["id"]
        for p in db.provenance(nid):
            if p in ids:
                _link(nid, p)

    # 2) Reforço por `caso`: liga todos os nós de um caso à sua âncora (menor LSN),
    # para que cada caso apareça CONECTADO mesmo sem proveniência registada
    # (dados antigos). A proveniência continua a fundir casos diferentes.
    anchor = {}
    for r in sorted(fraud, key=lambda x: int(x.get("lsn") or 0)):
        caso = (r.get("attrs") or {}).get("caso")
        if caso and caso not in anchor:
            anchor[caso] = r["id"]
    for r in fraud:
        caso = (r.get("attrs") or {}).get("caso")
        a = anchor.get(caso)
        if a:
            _link(r["id"], a)

    # componentes conexos = grupos de fraude
    group_of, g = {}, 0
    for i in ids:
        if i in group_of:
            continue
        g += 1
        stack = [i]
        while stack:
            x = stack.pop()
            if x in group_of:
                continue
            group_of[x] = g
            stack.extend(adj[x] - set(group_of))

    nodes = []
    for r in fraud:
        nodes.append({
            "id": r["id"], "kind": _clean_kind(r.get("kind")),
            "content": r.get("content", ""), "lsn": int(r.get("lsn") or 0),
            "group": group_of.get(r["id"], 0),
            "caso": (r.get("attrs") or {}).get("caso", ""),
        })
    nodes.sort(key=lambda n: n["lsn"])
    return {"nodes": nodes, "edges": edges,
            "n_groups": len(set(group_of.values())), "n_cases": len({n["caso"] for n in nodes if n["caso"]})}


def _suggest(db, limit=8000, top=60, min_score=0.20):
    """DESCOBERTA estatística de correlações (não só o explícito).

    Para cada nó de fraude (attrs.caso) procura OUTROS nós — inclusive de outro
    caso ou nem sinalizados (o "C") — que partilham *features raras* (valores de
    atributos e tokens de conteúdo). Pesa por IDF: partilhar um sinal RARO (um
    CNPJ, um nome de laranja, um valor) vale muito; partilhar algo comum não. É a
    lógica de record-linkage / anel de fraude. Devolve arestas SUGERIDAS (com
    score 0..1 e o porquê), nunca as explícitas (mesmo caso) que já existem."""
    import math
    import re
    rows = db.query(f"MATCH (n) RETURN n LIMIT {limit}")
    rows = [r for r in rows if r.get("id")] if isinstance(rows, list) else []
    N = max(1, len(rows))
    STOP = {"ts", "ts_hlc", "generated_by", "session_id", "agent_id", "mem_kind", "severidade"}

    def feats(r):
        f = set()
        a = r.get("attrs") if isinstance(r.get("attrs"), dict) else {}
        for k, v in a.items():
            if k in STOP or k == "caso":
                continue
            val = str(v).lower().strip()
            if val:
                f.add(f"{k}={val}")
        for tok in set(re.findall(r"[a-z0-9][a-z0-9./@_-]{3,}", (r.get("content") or "").lower())):
            f.add("tok:" + tok)
        return f

    nodes = []
    for r in rows:
        a = r.get("attrs") if isinstance(r.get("attrs"), dict) else {}
        nodes.append({"id": r["id"], "kind": _clean_kind(r.get("kind")),
                      "content": (r.get("content") or "")[:120], "lsn": int(r.get("lsn") or 0),
                      "caso": a.get("caso", ""), "fraud": bool(a.get("caso")), "f": feats(r)})
    fidx = {i for i, n in enumerate(nodes) if n["fraud"]}
    if not fidx:
        return {"nodes": [], "edges": [], "n": 0, "note": "sem nós de fraude (attrs.caso)"}

    df = {}
    for n in nodes:
        for x in n["f"]:
            df[x] = df.get(x, 0) + 1

    def idf(x):
        return math.log((N + 1.0) / df.get(x, 1))

    cap = max(3, int(N * 0.12))  # ignora features quase-ubíquas (sem poder discriminante)
    inv = {}
    for i, n in enumerate(nodes):
        for x in n["f"]:
            d = df[x]
            if d < 2 or d > cap:
                continue
            inv.setdefault(x, []).append(i)

    pair = {}
    for x, mem in inv.items():
        if len(mem) < 2 or len(mem) > 50:
            continue
        fr = [i for i in mem if i in fidx]
        if not fr:  # só pares que TOCAM o anel de fraude (descobrir correlação com ele)
            continue
        w = idf(x)
        for a in fr:
            for b in mem:
                if a == b:
                    continue
                key = (a, b) if a < b else (b, a)
                pd = pair.setdefault(key, {"w": 0.0, "f": []})
                pd["w"] += w
                pd["f"].append((x, w))

    sugg = []
    for (a, b), pd in pair.items():
        na, nb = nodes[a], nodes[b]
        if na["caso"] and na["caso"] == nb["caso"]:
            continue  # mesmo caso = já explícito
        s = pd["w"] / (pd["w"] + 2.5)  # satura em 0..1
        if s < min_score:
            continue
        topf = [f for f, _ in sorted(pd["f"], key=lambda z: -z[1])[:3]]
        why = ", ".join(ff.replace("tok:", "“").replace("=", ": ") for ff in topf)
        sugg.append({"from": na["id"], "to": nb["id"], "score": round(s, 2), "why": why,
                     "cross": bool(na["fraud"] and nb["fraud"])})
    sugg.sort(key=lambda e: -e["score"])
    sugg = sugg[:top]
    used = set()
    for e in sugg:
        used.add(e["from"])
        used.add(e["to"])
    nl = [{"id": n["id"], "kind": n["kind"], "content": n["content"], "lsn": n["lsn"],
           "fraud": n["fraud"], "caso": n["caso"]}
          for n in nodes if n["id"] in used]
    return {"nodes": nl, "edges": sugg, "n": len(sugg)}


def _timeline(db, limit=8000):
    """Eventos do log no eixo do tempo. ts = ts_hlc >> 16 (millis epoch; o HLC é
    physical_millis<<16|logical). `tag` é a melhor dimensão de cor/agrupamento."""
    rows = db.query(f"MATCH (n) RETURN n LIMIT {limit}")
    rows = rows if isinstance(rows, list) else []
    out = []
    for r in rows:
        try:
            lsn = int(r.get("lsn") or 0)
        except (TypeError, ValueError):
            lsn = 0
        ts_hlc = r.get("ts_hlc")
        ts = None
        try:
            if ts_hlc:
                ts = int(ts_hlc) >> 16
        except (TypeError, ValueError):
            ts = None
        attrs = r.get("attrs") if isinstance(r.get("attrs"), dict) else {}
        tag = (attrs.get("project") or attrs.get("generated_by")
               or attrs.get("caso") or attrs.get("mem_kind") or "")
        out.append({
            "lsn": lsn,
            "ts": ts,
            "kind": _clean_kind(r.get("kind")),
            "content": (r.get("content") or "")[:200],
            "tag": str(tag),
        })
    out.sort(key=lambda e: e["lsn"])
    return {"events": out, "head": db.head(), "n": len(out)}


_PAGE = r"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Heraclitus Console</title>
<script src="vendor/vis-network.min.js"></script>
<style>
:root{
  --bg:#ffffff; --panel:#ffffff; --panel2:#f7f9fc; --line:#e6ebf2; --line2:#d4dce8;
  --ink:#1b2b40; --mut:#6b7a90; --acc:#2a7fff; --acc2:#7c5cff;
  --c1:#ff4d5e; --c2:#ff7a3d; --c3:#ffb02e; --c4:#ffd23f;
  --ok:#1e9e54; --bad:#e0474c; --radius:12px;
}
*{box-sizing:border-box} html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--ink);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;overflow:hidden}
button{font-family:inherit;cursor:pointer;border:0;border-radius:9px;font-weight:600}
.btn{background:#fff;color:var(--ink);border:1px solid var(--line2);padding:8px 12px;font-size:.82rem;transition:.15s}
.btn:hover{border-color:var(--acc);color:var(--acc);background:#f3f7ff}
.btn.acc{background:linear-gradient(135deg,var(--acc),var(--acc2));border:0;color:#fff}
.btn.warn{background:#fff7e8;border:1px solid #f0cd86;color:#a86a12}
.iconbtn{background:#fff;border:1px solid var(--line2);color:var(--mut);width:34px;height:34px;border-radius:9px;font-size:.95rem}
.iconbtn:hover{color:var(--acc);border-color:var(--acc)}

/* ---- top bar ---- */
.top{height:56px;display:flex;align-items:center;gap:12px;padding:0 16px;background:var(--panel);border-bottom:1px solid var(--line);position:relative;z-index:5}
.top .logo{font-size:1.35rem}
.top h1{font-size:1.02rem;margin:0;letter-spacing:.2px}
.top .sub{color:var(--mut);font-size:.72rem;margin-top:-2px}
.top .spacer{flex:1}
.shield{font-size:.76rem;padding:7px 13px;border-radius:20px;border:1px solid var(--line2);background:#f3f6fb;color:var(--mut);white-space:nowrap}
.shield.ok{background:#e8f6ee;border-color:#bfe6cd;color:var(--ok)}
.shield.bad{background:#fdecec;border-color:#f4c2c2;color:var(--bad)}

/* ---- main grid: sidebar | graph , timeline spans bottom ---- */
.app{height:calc(100vh - 56px);display:grid;grid-template-columns:var(--sw,360px) 1fr;grid-template-rows:1fr var(--th,210px);
  grid-template-areas:"side graph" "side timeline";transition:grid-template-columns .25s ease, grid-template-rows .25s ease}
.app.side-collapsed{--sw:0px} .app.tl-collapsed{--th:0px}

/* ---- sidebar (retrátil) ---- */
.side{grid-area:side;background:var(--panel2);border-right:1px solid var(--line);overflow:auto;display:flex;flex-direction:column;gap:12px;padding:14px;min-width:0}
.app.side-collapsed .side{padding:0;border:0}
.side .muted{color:var(--mut);font-size:.76rem;line-height:1.4}
.side textarea{width:100%;height:76px;background:#fbfdff;color:var(--ink);border:1px solid var(--line2);border-radius:10px;padding:10px;font-family:ui-monospace,Consolas,monospace;font-size:13px;resize:vertical}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:12px}
.card h3{margin:0 0 8px;font-size:.82rem;color:var(--mut);font-weight:700;text-transform:uppercase;letter-spacing:.6px}
.row{display:flex;gap:8px;flex-wrap:wrap}
.legend{display:flex;flex-wrap:wrap;gap:8px;font-size:.74rem;color:var(--ink)}
.legend i{width:11px;height:11px;border-radius:50%;display:inline-block;margin-right:5px;vertical-align:middle}
.count{font-size:.82rem;color:var(--mut)} .count b{color:var(--ink)}
.err{color:var(--bad);font-size:.8rem;white-space:pre-wrap;font-family:ui-monospace,monospace}

/* ---- graph ---- */
.graphwrap{grid-area:graph;position:relative;background:radial-gradient(1100px 560px at 30% 18%,#ffffff 0,#eef3fa 75%);min-width:0;min-height:0}
#graph{position:absolute;inset:0}
#heb{position:absolute;inset:0;display:none;width:100%;height:100%}
#heb path{cursor:pointer} #heb rect,#heb circle{cursor:pointer}
.heb-cap{position:absolute;left:14px;top:10px;font-size:.8rem;font-weight:700;color:var(--mut);z-index:2;pointer-events:none}
.floatbtns{position:absolute;top:12px;left:12px;display:flex;gap:8px;z-index:4}
.reopen{position:absolute;z-index:4;background:var(--panel);border:1px solid var(--line2);color:var(--mut);display:none}
.app.side-collapsed .reopen.side-re{display:flex;left:12px;top:52px}
.app.tl-collapsed .reopen.tl-re{display:flex;left:12px;bottom:12px}

/* ---- TIMELINE (infográfica, retrátil) ---- */
.timeline{grid-area:timeline;background:var(--panel);border-top:1px solid var(--line);position:relative;overflow:hidden;min-height:0}
.app.tl-collapsed .timeline{border:0}
.tl-head{height:36px;display:flex;align-items:center;gap:10px;padding:0 14px;border-bottom:1px solid var(--line)}
.tl-head .ttl{font-size:.8rem;font-weight:700;letter-spacing:.3px}
.tl-head .info{color:var(--mut);font-size:.74rem}
.tl-head .spacer{flex:1}
.tl-scroll{position:absolute;top:36px;left:0;right:0;bottom:0;overflow-x:auto;overflow-y:hidden}
.tl-track{position:relative;height:100%;min-width:100%;padding:0 40px;display:flex;align-items:center}
/* central gradient bar */
.tl-bar{position:absolute;left:0;right:0;top:50%;height:14px;transform:translateY(-50%);
  background:linear-gradient(90deg,var(--c1),var(--c2),var(--c3),var(--c4));border-radius:8px;opacity:.85}
.tl-fill{position:absolute;left:0;top:50%;height:14px;transform:translateY(-50%);background:#ffffff;opacity:.62;border-radius:0 8px 8px 0}
.tl-handle{position:absolute;top:50%;width:4px;height:42px;transform:translate(-50%,-50%);background:#1b2b40;border-radius:3px;box-shadow:0 0 0 2px #fff,0 1px 4px #0003;cursor:ew-resize;z-index:3}
.tl-row{position:relative;display:flex;align-items:center;gap:0;z-index:2}
/* a marker (alternates up/down) */
.mk{position:relative;display:flex;flex-direction:column;align-items:center;min-width:88px;cursor:pointer}
.mk .stem{width:2px;background:var(--line2)}
.mk .dot{width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.9rem;color:#fff;font-weight:800;box-shadow:0 3px 10px #0002;border:3px solid #fff;transition:.15s}
.mk:hover .dot{transform:scale(1.12)}
.mk.on .dot{outline:3px solid #2a7fff55}
.mk .yr{font-size:1.05rem;font-weight:800;letter-spacing:.3px}
.mk .cnt{font-size:.66rem;color:var(--mut)}
.mk.up{flex-direction:column-reverse}
.mk .meta{display:flex;flex-direction:column;align-items:center;gap:1px}
.mk .stem{height:34px}
/* hint card */
.hint{position:fixed;z-index:30;max-width:300px;background:#fff;border:1px solid var(--line2);border-radius:10px;padding:10px 12px;
  box-shadow:0 12px 34px #1b2b4022;font-size:.78rem;pointer-events:none;opacity:0;transition:opacity .1s;color:var(--ink)}
.hint.show{opacity:1}
.hint .h-yr{font-weight:800;font-size:.95rem;margin-bottom:2px}
.hint .h-kinds{color:var(--mut);font-size:.72rem;margin:4px 0}
.hint .h-sample{color:#33506f;font-style:italic;border-left:2px solid var(--acc);padding-left:7px;margin-top:5px;line-height:1.35}
.hint .h-asof{color:#b5740a;font-size:.7rem;margin-top:6px}
.tl-empty{position:absolute;inset:36px 0 0 0;display:flex;align-items:center;justify-content:center;color:var(--mut);font-size:.85rem}
</style></head><body>

<div class="top">
  <div class="logo">🌊</div>
  <div><h1>Heraclitus Console</h1><div class="sub">panta rhei — log event-sourced · proveniência · Merkle</div></div>
  <div class="spacer"></div>
  <span id="shield" class="shield">a verificar Merkle…</span>
  <button class="iconbtn" id="fs" title="Tela cheia do grafo (Esc para sair)">⛶</button>
</div>

<div class="app" id="app">
  <!-- SIDEBAR retrátil -->
  <aside class="side" id="side">
    <div class="row">
      <button id="fraud" class="btn warn">🕵 Fraudes</button>
      <button id="suggest" class="btn" title="Descobre correlações ocultas por estatística (IDF) — não só o explícito">🔮 Correlações</button>
      <button id="run" class="btn">▶ Query</button>
      <button id="verify" class="btn">🛡 Merkle</button>
    </div>
    <div class="card">
      <h3>Consulta GQL</h3>
      <textarea id="gql">MATCH (n) RETURN n LIMIT 200</textarea>
    </div>
    <div class="card">
      <h3>Estado (AS OF)</h3>
      <div class="count"><span id="asoflabel">—</span></div>
      <div class="muted" id="tlhint" style="margin-top:6px">Clique num marcador da linha do tempo: o grafo reconstrói-se naquele ponto do passado (AS OF).</div>
    </div>
    <div class="card">
      <h3>Resumo</h3>
      <div class="count"><b id="count">—</b></div>
      <div class="count" id="head" style="margin-top:4px">head —</div>
      <div class="legend" id="legend" style="margin-top:8px"></div>
    </div>
    <div class="err" id="err"></div>
    <div class="muted" style="margin-top:auto">Eixo do tempo = <code>ts_hlc</code> (relógio híbrido). Painéis retráteis ◀ ▼ ; ⛶ para tela cheia.</div>
  </aside>

  <!-- GRAFO -->
  <div class="graphwrap">
    <div id="graph"></div>
    <svg id="heb"></svg>
    <div class="heb-cap" id="hebcap"></div>
    <div class="floatbtns">
      <button class="iconbtn" id="toggleSide" title="Recolher/expandir painel lateral">◀</button>
      <button class="iconbtn" id="fit" title="Ajustar grafo">⤢</button>
    </div>
    <button class="iconbtn reopen side-re" id="reopenSide" title="Abrir painel lateral">▶</button>
    <button class="iconbtn reopen tl-re" id="reopenTl" title="Abrir linha do tempo">▲</button>
  </div>

  <!-- TIMELINE retrátil -->
  <section class="timeline" id="timeline">
    <div class="tl-head">
      <span class="ttl">⏳ Linha do tempo</span>
      <span class="info" id="tlinfo">—</span>
      <div class="spacer"></div>
      <button class="iconbtn" id="toggleTl" title="Recolher linha do tempo" style="width:28px;height:24px;font-size:.8rem">▼</button>
    </div>
    <div class="tl-scroll" id="tlscroll">
      <div class="tl-track" id="tltrack">
        <div class="tl-bar"></div><div class="tl-fill" id="tlfill"></div>
        <div class="tl-handle" id="tlhandle"></div>
        <div class="tl-row" id="tlrow"></div>
      </div>
    </div>
    <div class="tl-empty" id="tlempty">a carregar eventos…</div>
  </section>
</div>
<div class="hint" id="hint"></div>

<script>
var HEAD=0, ASOF=0, MODE='query', network=null, FRAUD=null, TL=null, BUCKETS=[];
var kindPal={}, ki=0;
var KINDP=[['#37b0ff','#0a2a44'],['#34d399','#082a20'],['#ffb02e','#3a2a08'],['#fb7185','#3a1320'],['#7c5cff','#1e1640'],['#22d3ee','#063038']];
var GROUPP=[['#37b0ff'],['#fb7185'],['#34d399'],['#ffb02e'],['#7c5cff'],['#22d3ee']];
var gNodes=new vis.DataSet(), gEdges=new vis.DataSet();
function el(i){return document.getElementById(i);}
function esc(s){return (s==null?'':String(s)).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}
function kindColor(k){ if(!kindPal[k]){ kindPal[k]=KINDP[ki%KINDP.length]; ki++; } return kindPal[k]; }
function groupColor(g){ return GROUPP[((g||1)-1)%GROUPP.length][0]; }
function post(p,b){ return fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}).then(function(r){return r.json();}); }

/* ---------- layout: painéis retráteis + tela cheia ---------- */
function setSide(open){ el('app').classList.toggle('side-collapsed',!open); el('toggleSide').textContent=open?'◀':'▶'; relayout(); }
function setTl(open){ el('app').classList.toggle('tl-collapsed',!open); el('toggleTl').textContent=open?'▼':'▲'; relayout(); }
function relayout(){ setTimeout(function(){ try{network&&network.redraw();}catch(e){} renderTimeline(); }, 260); }
el('toggleSide').onclick=function(){ setSide(el('app').classList.contains('side-collapsed')); };
el('reopenSide').onclick=function(){ setSide(true); };
el('toggleTl').onclick=function(){ setTl(false); };
el('reopenTl').onclick=function(){ setTl(true); };
var FSON=false;
el('fs').onclick=function(){ FSON=!FSON; setSide(!FSON); setTl(!FSON); };
document.addEventListener('keydown',function(e){ if(e.key==='Escape'&&FSON){ FSON=false; setSide(true); setTl(true); } });
el('fit').onclick=function(){ try{network.fit({animation:true});}catch(e){} };

/* ---------- merkle shield ---------- */
async function verifyMerkle(){ var s=el('shield');
  try{ var r=await fetch('verify'); var j=await r.json(); var m={}; try{ m=JSON.parse(j.message); }catch(e){}
    if(j.ok){ s.className='shield ok'; s.textContent='🛡 Log íntegro · '+(m.records!=null?m.records:'?')+' registos · '+(m.segments!=null?m.segments:'?')+' segmentos'; }
    else { s.className='shield bad'; s.textContent='⚠ Integridade comprometida'; }
  }catch(e){ s.className='shield bad'; s.textContent='⚠ Servidor indisponível'; } }

/* ---------- grafo ---------- */
function ensureNetwork(){ if(network) return;
  network=new vis.Network(el('graph'),{nodes:gNodes,edges:gEdges},{
    nodes:{shape:'dot',size:15,borderWidth:2,font:{color:'#1b2b40',size:12,strokeWidth:3,strokeColor:'#ffffff'}},
    edges:{color:{color:'#9aa9c2',highlight:'#2a7fff'},width:1.5,arrows:{to:{enabled:true,scaleFactor:.5}},smooth:{type:'continuous'}},
    physics:{stabilization:{iterations:160},barnesHut:{springLength:115,avoidOverlap:0.5}},interaction:{hover:true}});
  network.on('click', async function(p){ if(!p.nodes||!p.nodes.length) return; var id=p.nodes[0];
    try{ var j=await post('provenance',{id:id});
      (j.parents||[]).forEach(function(pid){ if(!gNodes.get(pid)) gNodes.add({id:pid,label:String(pid).slice(-6),color:{background:'#fff3cc',border:'#f0a000'}});
        var eid=id+'>'+pid; if(!gEdges.get(eid)) gEdges.add({id:eid,from:id,to:pid,dashes:true,width:2,color:{color:'#ffb02e'}}); });
    }catch(e){} }); }

function drawGraph(payload){ showHeb(false); gNodes.clear(); gEdges.clear(); kindPal={}; ki=0;
  (payload.nodes||[]).forEach(function(nd){ var c=kindColor(String(nd.kind||'')); var lab=(nd.content||nd.kind||nd.id);
    gNodes.add({id:nd.id,label:String(lab).slice(0,22),title:esc(nd.kind||'')+' · '+esc(nd.content||''),color:{background:c[0],border:c[1]}}); });
  (payload.edges||[]).forEach(function(e,i){ gEdges.add({id:'e'+i,from:e.from,to:e.to}); });
  ensureNetwork(); try{network.fit();}catch(e){}
  el('count').textContent=(payload.nodes||[]).length+' nó(s), '+(payload.edges||[]).length+' aresta(s)';
  el('legend').innerHTML=Object.keys(kindPal).map(function(k){return '<span><i style="background:'+kindPal[k][0]+'"></i>'+esc(k||'(sem tipo)')+'</span>';}).join('');
}
async function runQuery(){ MODE='query'; var body={gql:el('gql').value}; if(ASOF<HEAD) body.as_of=ASOF;
  el('err').textContent='Carregando…';
  try{ var j=await post('graph',body); if(j.error){el('err').textContent='Erro: '+j.error;} else if(j.plan!=null){el('err').textContent='EXPLAIN:\n'+j.plan;} else { drawGraph(j); el('err').textContent=(j.nodes||[]).length?'':'(0 linhas)'; } }
  catch(e){ el('err').textContent='Falha: '+e.message; } }

/* ---------- modo FRAUDE ---------- */
async function loadFraudes(){ el('err').textContent='Detetando fraudes…';
  try{ var j=await post('fraudes',{}); if(!(j.nodes||[]).length){ el('err').textContent='Nenhum caso (attrs.caso). Rode demo/seed.py.'; return; }
    FRAUD=j; MODE='fraud'; renderFraud(ASOF||HEAD); el('err').textContent='';
    el('tlhint').textContent=j.n_groups+' grupo(s) de fraude · '+j.n_cases+' caso(s). Arraste a linha do tempo para montar o caso.';
  }catch(e){ el('err').textContent='Falha: '+e.message; } }
function renderFraud(v){ if(!FRAUD) return; gNodes.clear(); gEdges.clear(); var ok={}, groups={};
  FRAUD.nodes.forEach(function(nd){ if(nd.lsn<=v){ ok[nd.id]=1; groups[nd.group]=1; var c=groupColor(nd.group);
    gNodes.add({id:nd.id,label:String(nd.content||nd.kind).slice(0,22),title:esc(nd.kind)+' · grupo '+nd.group+' · '+esc(nd.content),color:{background:c,border:'#0e1726'}}); }});
  FRAUD.edges.forEach(function(e,i){ if(ok[e.from]&&ok[e.to]) gEdges.add({id:'e'+i,from:e.from,to:e.to}); });
  ensureNetwork(); try{network.fit();}catch(e){}
  el('count').textContent=Object.keys(ok).length+' nó(s) · '+Object.keys(groups).length+'/'+FRAUD.n_groups+' grupo(s)';
  el('legend').innerHTML=Object.keys(groups).map(function(g){ return '<span><i style="background:'+groupColor(+g)+'"></i>Grupo '+g+'</span>'; }).join('');
}

/* ---------- DESCOBERTA de correlações — layout CIRCULAR (edge bundling) ---------- */
var LASTSUGG=null;
var HEBP=['#39d353','#1f77b4','#ff7f0e','#2ca02c','#d62728','#9467bd','#8c564b','#e377c2','#bcbd22','#17becf','#ff9896','#c5b0d5','#9edae5'];
function hebColor(i){ return HEBP[i%HEBP.length]; }
function showHeb(on){ el('heb').style.display=on?'block':'none'; el('graph').style.display=on?'none':'block'; el('hebcap').style.display=on?'block':'none'; }
function showHintRaw(text,ev){ var h=el('hint'); h.innerHTML='<div class="h-yr">🔮 Correlação</div><div class="h-sample" style="border-color:#f0a000">'+esc(text)+'</div>'; h.classList.add('show'); moveHint(ev); }

async function loadSuggest(){ el('err').textContent='A descobrir correlações ocultas…';
  try{ var j=await post('suggest',{});
    if(j.note){ el('err').textContent=j.note; return; }
    if(!(j.edges||[]).length){ el('err').textContent='Nenhuma correlação acima do limiar.'; return; }
    MODE='suggest'; FRAUD=null; LASTSUGG=j; showHeb(true); renderHEB(j);
    var cross=(j.edges||[]).filter(function(e){return e.cross;}).length;
    el('count').innerHTML='<b>'+(j.edges||[]).length+'</b> correlação(ões) · '+cross+' entre casos';
    el('err').textContent='';
  }catch(e){ el('err').textContent='Falha: '+e.message; } }

function renderHEB(j){
  var svg=el('heb'), wrap=svg.parentNode;
  var W=wrap.clientWidth||900, H=wrap.clientHeight||600;
  var cx=W/2, cy=H/2, R=Math.max(80, Math.min(W,H)/2-72);
  var nodes=(j.nodes||[]).slice(), edges=j.edges||[];
  // agrupar por caso (setores), tal como a imagem; nós sem caso = "Correlacionado (C)"
  var groups={}, order=[];
  nodes.forEach(function(n){ var g=n.caso?('Caso '+n.caso):'Correlacionado (C)';
    if(!(g in groups)){ groups[g]=[]; order.push(g); } groups[g].push(n); });
  order.sort();
  var gcolor={}; order.forEach(function(g,i){ gcolor[g]=(g.indexOf('(C)')>=0)?'#9aa9c2':hebColor(i); });
  var ord=[]; order.forEach(function(g){ groups[g].forEach(function(nd){ nd._g=g; ord.push(nd); }); });
  var n=ord.length||1, pos={};
  ord.forEach(function(nd,i){ var a=(i/n)*2*Math.PI - Math.PI/2;
    nd._x=cx+R*Math.cos(a); nd._y=cy+R*Math.sin(a); pos[nd.id]=nd; });
  var bundle=0.80, parts=['<g>'];
  edges.forEach(function(e,i){ var A=pos[e.from], B=pos[e.to]; if(!A||!B) return;
    var c1x=cx+(A._x-cx)*(1-bundle), c1y=cy+(A._y-cy)*(1-bundle);
    var c2x=cx+(B._x-cx)*(1-bundle), c2y=cy+(B._y-cy)*(1-bundle);
    var col=gcolor[A._g]||'#888', base=(0.18+0.55*(e.score||0));
    parts.push('<path d="M'+A._x.toFixed(1)+' '+A._y.toFixed(1)+'C'+c1x.toFixed(1)+' '+c1y.toFixed(1)+' '+c2x.toFixed(1)+' '+c2y.toFixed(1)+' '+B._x.toFixed(1)+' '+B._y.toFixed(1)+'" fill="none" stroke="'+col+'" stroke-width="'+(0.6+(e.score||0)*2.4).toFixed(2)+'" stroke-opacity="'+base.toFixed(2)+'" data-i="'+i+'" data-from="'+e.from+'" data-to="'+e.to+'"/>'); });
  parts.push('</g><g>');
  ord.forEach(function(nd){ var col=gcolor[nd._g]; var t=esc((nd.caso?('Caso '+nd.caso+' · '):'')+nd.kind+' · '+nd.content);
    if(nd.fraud) parts.push('<rect x="'+(nd._x-5).toFixed(1)+'" y="'+(nd._y-5).toFixed(1)+'" width="10" height="10" rx="2" fill="'+col+'" stroke="#fff" stroke-width="1.5" data-id="'+nd.id+'"><title>'+t+'</title></rect>');
    else parts.push('<circle cx="'+nd._x.toFixed(1)+'" cy="'+nd._y.toFixed(1)+'" r="5" fill="'+col+'" stroke="#fff" stroke-width="1.5" data-id="'+nd.id+'"><title>'+t+'</title></circle>'); });
  parts.push('</g>');
  svg.setAttribute('viewBox','0 0 '+W+' '+H); svg.innerHTML=parts.join('');
  el('hebcap').textContent='🔮 Correlações — '+n+' nós · '+edges.length+' ligações · agrupado por caso';
  el('legend').innerHTML=order.map(function(g){ return '<span><i style="background:'+gcolor[g]+'"></i>'+esc(g)+'</span>'; }).join('')+'<span style="flex-basis:100%"></span><span class="muted">□ fraude · ○ correlacionado (C)</span>';
  function reset(){ Array.prototype.forEach.call(svg.querySelectorAll('path'),function(p){ var e=edges[+p.getAttribute('data-i')]; p.setAttribute('stroke-opacity',(0.18+0.55*((e&&e.score)||0)).toFixed(2)); p.setAttribute('stroke-width',(0.6+((e&&e.score)||0)*2.4).toFixed(2)); }); }
  Array.prototype.forEach.call(svg.querySelectorAll('path'),function(p){
    p.addEventListener('mouseenter',function(ev){ var e=edges[+p.getAttribute('data-i')]; if(e) showHintRaw(e.score+' · '+e.why+(e.cross?' · entre casos':''),ev); p.setAttribute('stroke-opacity','0.96'); p.setAttribute('stroke-width',(1.5+(e?e.score:0)*2.6).toFixed(2)); });
    p.addEventListener('mousemove',function(ev){ moveHint(ev); });
    p.addEventListener('mouseleave',function(){ el('hint').classList.remove('show'); reset(); });
  });
  Array.prototype.forEach.call(svg.querySelectorAll('[data-id]'),function(nd){
    nd.addEventListener('mouseenter',function(){ var id=nd.getAttribute('data-id');
      Array.prototype.forEach.call(svg.querySelectorAll('path'),function(p){ var on=(p.getAttribute('data-from')===id||p.getAttribute('data-to')===id); p.setAttribute('stroke-opacity',on?'0.96':'0.04'); }); });
    nd.addEventListener('mouseleave',reset);
  });
}

/* ---------- AS OF ---------- */
function setAsof(lsn,redraw){ ASOF=Math.max(0,Math.min(HEAD,lsn|0));
  el('asoflabel').textContent=(ASOF>=HEAD)?('completo (head LSN '+HEAD+')'):('AS OF LSN '+ASOF);
  paintTimeline();
  if(redraw){ if(MODE==='fraud'&&FRAUD) renderFraud(ASOF); else runQuery(); } }

/* ---------- LINHA DO TEMPO (infográfica) ---------- */
var ICON={Observation:'◍',Memory:'🧠',MemoryTombstone:'✖',AgentEvent:'⚙',Decision:'✔',Rule:'§',Fact:'•',ProjectContext:'▣',Learning:'✦',UserPref:'☺',Tombstone:'✖'};
function fmtBucket(ts,gran){ var d=new Date(ts); var M=['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
  if(gran==='year') return ''+d.getFullYear();
  if(gran==='month') return M[d.getMonth()]+' '+d.getFullYear();
  if(gran==='day') return d.getDate()+' '+M[d.getMonth()];
  return d.getDate()+' '+M[d.getMonth()]+' '+String(d.getHours()).padStart(2,'0')+'h';
}
function bucketize(events){
  if(!events.length) return [];
  var wts=events.filter(function(e){return e.ts;});
  var useTs = wts.length >= events.length*0.5;
  var keyer, gran='lsn';
  if(useTs){ var mn=Math.min.apply(null,wts.map(function(e){return e.ts;})), mx=Math.max.apply(null,wts.map(function(e){return e.ts;}));
    var span=mx-mn, D=86400000;
    gran = span>730*D?'year': span>75*D?'month': span>2*D?'day':'hour';
    keyer=function(e){ var d=new Date(e.ts||mn);
      if(gran==='year')return d.getFullYear();
      if(gran==='month')return d.getFullYear()*100+d.getMonth();
      if(gran==='day')return Math.floor((e.ts||mn)/D);
      return Math.floor((e.ts||mn)/3600000); };
  } else { // sem tempo: ~14 baldes por faixa de LSN
    var lo=events[0].lsn, hi=events[events.length-1].lsn, w=Math.max(1,Math.ceil((hi-lo+1)/14));
    keyer=function(e){ return Math.floor((e.lsn-lo)/w); };
  }
  var map={};
  events.forEach(function(e){ var k=keyer(e); if(!map[k]) map[k]={key:k,ts:e.ts,lsnMin:e.lsn,lsnMax:e.lsn,count:0,kinds:{},sample:''};
    var b=map[k]; b.count++; b.lsnMax=Math.max(b.lsnMax,e.lsn); b.lsnMin=Math.min(b.lsnMin,e.lsn); if(e.ts&&!b.ts)b.ts=e.ts;
    b.kinds[e.kind]=(b.kinds[e.kind]||0)+1; if(!b.sample&&e.content)b.sample=e.content; });
  var arr=Object.keys(map).map(function(k){return map[k];}).sort(function(a,b){return a.lsnMin-b.lsnMin;});
  arr.forEach(function(b){ b.label = (useTs&&b.ts)? fmtBucket(b.ts,gran) : ('#'+b.lsnMin+'–'+b.lsnMax);
    var dk='',dn=0; for(var kk in b.kinds){ if(b.kinds[kk]>dn){dn=b.kinds[kk];dk=kk;} } b.dom=dk; });
  return arr;
}
async function loadTimeline(){
  try{ var j=await post('timeline_get',{}); TL=j; HEAD=j.head||HEAD;
    BUCKETS=bucketize(j.events||[]);
    el('tlinfo').textContent=(j.n||0)+' eventos · '+BUCKETS.length+' períodos · head LSN '+HEAD;
    el('tlempty').style.display=(j.events&&j.events.length)?'none':'flex';
    if(j.events&&j.events.length){ if(!ASOF) ASOF=HEAD; renderTimeline(); paintTimeline(); }
  }catch(e){ el('tlempty').textContent='falha ao carregar a linha do tempo'; }
}
function renderTimeline(){
  if(!BUCKETS.length){ return; }
  var row=el('tlrow'); var html='';
  BUCKETS.forEach(function(b,i){
    var up=(i%2===0); var c=kindColor(b.dom||'');
    var icon=ICON[b.dom]||'•';
    html+='<div class="mk '+(up?'up':'down')+'" data-i="'+i+'" data-lsn="'+b.lsnMax+'">'+
      '<div class="meta"><div class="yr">'+esc(b.label)+'</div><div class="cnt">'+b.count+' evt</div></div>'+
      '<div class="stem"></div>'+
      '<div class="dot" style="background:'+c[0]+'">'+icon+'</div>'+
    '</div>';
  });
  row.innerHTML=html;
  Array.prototype.forEach.call(row.children,function(m){
    m.onclick=function(){ setAsof(+m.getAttribute('data-lsn'),true); };
    m.onmouseenter=function(ev){ showHint(BUCKETS[+m.getAttribute('data-i')],ev); };
    m.onmousemove=function(ev){ moveHint(ev); };
    m.onmouseleave=function(){ el('hint').classList.remove('show'); };
  });
  paintTimeline();
}
function paintTimeline(){
  var frac = HEAD? (ASOF/HEAD):1;
  var track=el('tltrack'); var w=track? track.scrollWidth:0;
  el('tlfill').style.left=(frac*100)+'%'; el('tlfill').style.right=0; el('tlfill').style.width=((1-frac)*100)+'%'; el('tlfill').style.left=(frac*100)+'%';
  el('tlhandle').style.left=(frac*100)+'%';
  Array.prototype.forEach.call(el('tlrow').children,function(m){ m.classList.toggle('on', +m.getAttribute('data-lsn')<=ASOF); });
}
function showHint(b,ev){ if(!b)return; var h=el('hint');
  var kinds=Object.keys(b.kinds).map(function(k){return esc(k)+' ×'+b.kinds[k];}).join(' · ');
  h.innerHTML='<div class="h-yr">'+esc(b.label)+'</div>'+
    '<div>'+b.count+' evento(s) · LSN '+b.lsnMin+'–'+b.lsnMax+'</div>'+
    '<div class="h-kinds">'+kinds+'</div>'+
    (b.sample?('<div class="h-sample">'+esc(b.sample)+'</div>'):'')+
    '<div class="h-asof">clique → AS OF LSN '+b.lsnMax+'</div>';
  h.classList.add('show'); moveHint(ev);
}
function moveHint(ev){ var h=el('hint'); var x=ev.clientX+14, y=ev.clientY-10;
  if(x+310>window.innerWidth) x=ev.clientX-314; if(y<10)y=10; h.style.left=x+'px'; h.style.top=y+'px'; }

/* arrastar o handle = AS OF contínuo */
(function(){ var drag=false; var sc=el('tlscroll');
  function lsnAt(clientX){ var r=el('tltrack').getBoundingClientRect(); var f=(clientX - r.left + sc.scrollLeft)/r.width; f=Math.max(0,Math.min(1,f)); return Math.round(f*HEAD); }
  el('tlhandle').addEventListener('mousedown',function(e){ drag=true; e.preventDefault(); });
  sc.addEventListener('mousedown',function(e){ if(e.target.closest('.mk'))return; setAsof(lsnAt(e.clientX),true); });
  window.addEventListener('mousemove',function(e){ if(drag) setAsof(lsnAt(e.clientX),false); });
  window.addEventListener('mouseup',function(e){ if(drag){ drag=false; setAsof(ASOF,true); } });
})();

/* ---------- botões ---------- */
el('fraud').onclick=loadFraudes;
el('suggest').onclick=loadSuggest;
el('run').onclick=function(){ MODE='query'; FRAUD=null; runQuery(); };
el('verify').onclick=verifyMerkle;

window.addEventListener('load', async function(){
  try{ var r=await fetch('head'); var j=await r.json(); HEAD=j.head||0; ASOF=HEAD; el('head').textContent='head LSN '+HEAD; }catch(e){}
  await verifyMerkle();
  await loadTimeline();
  await runQuery();
  setInterval(verifyMerkle,15000);
});
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, _PAGE, "text/html; charset=utf-8")
        elif self.path.endswith("vis-network.min.js"):
            try:
                with open(os.path.join(_ROOT, "vendor", "vis-network.min.js"), "rb") as f:
                    self._send(200, f.read(), "application/javascript; charset=utf-8")
            except FileNotFoundError:
                self._send(404, json.dumps({"error": "vendor ausente"}))
        elif self.path.startswith("/head"):
            try:
                self._send(200, json.dumps({"head": _client().head()}))
            except Exception as e:  # noqa: BLE001
                self._send(200, json.dumps({"error": str(e)}))
        elif self.path.startswith("/verify"):
            try:
                self._send(200, json.dumps(_client().verify()))
            except Exception as e:  # noqa: BLE001
                self._send(200, json.dumps({"ok": False, "message": str(e)}))
        else:
            self._send(404, json.dumps({"error": "rota desconhecida"}))

    def _json(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_POST(self):
        try:
            if self.path.startswith("/provenance"):
                pid = (self._json().get("id") or "").strip()
                self._send(200, json.dumps({"parents": _client().provenance(pid)}))
            elif self.path.startswith("/fraudes"):
                self._send(200, json.dumps(_fraudes(_client()), ensure_ascii=False, default=str))
            elif self.path.startswith("/suggest"):
                self._send(200, json.dumps(_suggest(_client()), ensure_ascii=False, default=str))
            elif self.path.startswith("/timeline_get"):
                self._send(200, json.dumps(_timeline(_client()), ensure_ascii=False, default=str))
            elif self.path.startswith("/graph"):
                b = self._json()
                db = _client()
                res = db.query((b.get("gql") or "").strip(), as_of=b.get("as_of"))
                payload = _graph_payload(db, res) if isinstance(res, list) else {"plan": str(res)}
                self._send(200, json.dumps(payload, ensure_ascii=False, default=str))
            else:
                self._send(404, json.dumps({"error": "rota desconhecida"}))
        except Exception as e:  # noqa: BLE001
            self._send(200, json.dumps({"error": str(e)}))


def main():
    ap = argparse.ArgumentParser(description="Heraclitus Console")
    ap.add_argument("--addr", default="127.0.0.1:7474")
    ap.add_argument("--port", type=int, default=7480)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-open", action="store_true")
    args = ap.parse_args()
    _DB["addr"] = args.addr
    url = f"http://127.0.0.1:{args.port}"
    print(f"Heraclitus Console em {url}  (banco: {args.addr})")
    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
