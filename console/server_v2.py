# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

"""Heraclitus Console V2 — auditoria + camada de FRAUDE sobre o HeraclitusDB.

- editor GQL -> grafo (com arestas de proveniência)
- "Fraudes": deteta os casos, AGRUPA por comunidade (proveniência partilhada)
- LINHA DO TEMPO visual (infográfica) sobre o log event-sourced: cada evento no
  eixo do tempo (ts_hlc) com marcadores + hints; clique = AS OF naquele ponto
- painéis retráteis -> grafo em tela cheia
- clique num nó -> expande proveniência + painel de detalhes; escudo Merkle
- modo escuro premium com glassmorphism
- exportação JSON de dados de fraude

  py console/server_v2.py            # http://127.0.0.1:7481
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
        nodes.append({"id": rid, "kind": _clean_kind(r.get("kind")), "content": r.get("content", ""),
                      "attrs": r.get("attrs", {}), "lsn": r.get("lsn"), "ts_hlc": r.get("ts_hlc")})
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
            "attrs": r.get("attrs", {}),
            "ts_hlc": r.get("ts_hlc"),
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
        why = ", ".join(ff.replace("tok:", "\u201c").replace("=", ": ") for ff in topf)
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


def _manifold_data(db, limit=8000):
    import hashlib
    rows = db.query(f"MATCH (n) RETURN n LIMIT {limit}")
    rows = rows if isinstance(rows, list) else []
    points = []
    for r in rows:
        attrs = r.get("attrs") or {}
        emb = r.get("embedding")
        if isinstance(emb, dict) and (emb.get("hyp") or emb.get("sph") or emb.get("euc")):
            hyp = emb.get("hyp") or []
            sph = emb.get("sph") or []
            euc = emb.get("euc") or []
            coords = (hyp + sph + euc)[:3]
            if len(coords) < 3:
                coords += [0.0] * (3 - len(coords))
            x, y, z = coords[0], coords[1], coords[2]
        elif "manifold_x" in attrs:
            x, y, z = float(attrs["manifold_x"]), float(attrs["manifold_y"]), float(attrs["manifold_z"])
        else:
            # Deterministic pseudo-random coordinates based on ID and caso/cluster
            h = hashlib.md5(str(r.get("id", "")).encode()).digest()
            x = (h[0] / 255.0) * 2 - 1
            y = (h[1] / 255.0) * 2 - 1
            z = (h[2] / 255.0) * 2 - 1
            caso = attrs.get("caso") or attrs.get("cluster") or _clean_kind(r.get("kind"))
            if caso:
                ch = hashlib.md5(str(caso).encode()).digest()
                cx = (ch[0] / 255.0) * 2 - 1
                cy = (ch[1] / 255.0) * 2 - 1
                cz = (ch[2] / 255.0) * 2 - 1
                x = cx + x * 0.3
                y = cy + y * 0.3
                z = cz + z * 0.3

        points.append({
            "id": r.get("id"), "kind": _clean_kind(r.get("kind")),
            "content": (r.get("content") or "")[:100],
            "x": x, "y": y, "z": z,
            "caso": attrs.get("caso", "")
        })
    return {"points": points}


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
    out.sort(key=lambda x: x["lsn"])
    return {"events": out, "n": len(out), "head": db.head()}


def _case_of(attrs):
    """Identificador de caso de um nó (attrs.caso ou attrs.cluster), ou None."""
    return attrs.get("caso") or attrs.get("cluster")


def _event_row(r, attrs):
    """Linha de evento normalizada (lsn, ts, kind, content) a partir de um nó."""
    try:
        lsn = int(r.get("lsn") or 0)
    except (TypeError, ValueError):
        lsn = 0
    ts = None
    ts_hlc = r.get("ts_hlc")
    if ts_hlc:
        try:
            ts = int(ts_hlc) >> 16
        except (TypeError, ValueError):
            ts = None
    return {"lsn": lsn, "ts": ts, "kind": _clean_kind(r.get("kind")),
            "content": r.get("content") or ""}


def _case_list(db, limit=8000):
    # Varredura limitada (como as restantes funções): evita um full-scan do log
    # — no banco grande um MATCH sem LIMIT bate no cap de 250k e fica lento.
    rows = db.query(f"MATCH (n) RETURN n LIMIT {limit}")
    rows = rows if isinstance(rows, list) else []
    cases = set()
    for r in rows:
        caso = _case_of(r.get("attrs") or {})
        if caso:
            cases.add(str(caso))
    return {"cases": sorted(cases)}


def _case_events(db, caso, limit=8000):
    rows = db.query(f"MATCH (n) RETURN n LIMIT {limit}")
    rows = rows if isinstance(rows, list) else []
    out = []
    for r in rows:
        attrs = r.get("attrs") or {}
        if str(_case_of(attrs)) == str(caso):
            ev = _event_row(r, attrs)
            ev["attrs"] = attrs
            out.append(ev)
    out.sort(key=lambda x: x["lsn"])
    return {"events": out, "caso": caso, "n": len(out)}


def _cases_overview(db, limit=8000):
    """Todos os casos COM os seus eventos numa ÚNICA varredura — para o mapa de
    casos não cair em N+1 (uma varredura por caso)."""
    rows = db.query(f"MATCH (n) RETURN n LIMIT {limit}")
    rows = rows if isinstance(rows, list) else []
    by_case = {}
    for r in rows:
        attrs = r.get("attrs") or {}
        caso = _case_of(attrs)
        if not caso:
            continue
        by_case.setdefault(str(caso), []).append(_event_row(r, attrs))
    cases = []
    for caso in sorted(by_case):
        evs = sorted(by_case[caso], key=lambda x: x["lsn"])
        cases.append({"caso": caso, "events": evs})
    return {"cases": cases, "n": len(cases)}


_PAGE = r"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Heraclitus Console V2</title>
<meta name="description" content="Console de auditoria e detecção de fraude do HeraclitusDB — log event-sourced, proveniência e Merkle">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Raleway:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="vendor/vis-network.min.js"></script>
<script src="https://cdn.plot.ly/plotly-2.32.0.min.js"></script>
<style>
:root{
  /* Padrao gov.br / Portal da Transparencia (tema claro) */
  --bg:#ffffff; --panel:#ffffff; --panel2:#f8f9fb; --panel3:#eef2f8;
  --glass:rgba(255,255,255,0.92);
  --line:#dfe4ec; --line2:#c5cedb;
  --ink:#1c1c1c; --mut:#555f6d; --muted2:#7b8595;
  --acc:#1351b4; --acc2:#0c326f; --acc3:#168821;
  --c1:#e52207; --c2:#f29900; --c3:#ffcd07; --c4:#168821;
  --ok:#168821; --bad:#e52207; --warn:#c47000;
  --gov-deep:#071d41;
  --radius:8px; --radius-lg:12px;
  --shadow:0 6px 24px rgba(7,29,65,0.12);
  --shadow-sm:0 2px 8px rgba(7,29,65,0.08);
  --glow-acc:0 0 0 3px rgba(19,81,180,0.15);
  --glow-bad:0 0 0 3px rgba(229,34,7,0.15);
  --glow-ok:0 0 0 3px rgba(22,136,33,0.15);
}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--ink);font-family:'Raleway','Inter',system-ui,-apple-system,sans-serif;overflow:hidden;-webkit-font-smoothing:antialiased}
button{font-family:'Inter',inherit;cursor:pointer;border:0;border-radius:var(--radius);font-weight:600;transition:all .15s ease}
code,pre,textarea{font-family:'JetBrains Mono','Fira Code',ui-monospace,Consolas,monospace}

/* ---- scrollbar ---- */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--line2);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--mut)}

/* ---- buttons ---- */
.btn{background:var(--panel3);color:var(--ink);border:1px solid var(--line2);padding:7px 13px;font-size:.8rem;letter-spacing:.2px}
.btn:hover{border-color:var(--acc);color:var(--acc);background:rgba(88,166,255,0.08);box-shadow:var(--glow-acc)}
.btn.acc{background:linear-gradient(135deg,var(--acc),var(--acc2));border:0;color:#fff;box-shadow:0 4px 16px rgba(88,166,255,0.3)}
.btn.acc:hover{box-shadow:0 4px 24px rgba(88,166,255,0.5);transform:translateY(-1px)}
.btn.warn{background:rgba(227,179,65,0.12);border:1px solid rgba(227,179,65,0.3);color:var(--warn)}
.btn.warn:hover{background:rgba(227,179,65,0.2);border-color:var(--warn);box-shadow:0 0 16px rgba(227,179,65,0.2)}
.btn.danger{background:rgba(248,81,73,0.1);border:1px solid rgba(248,81,73,0.3);color:var(--bad)}
.btn.danger:hover{background:rgba(248,81,73,0.18);border-color:var(--bad)}
.btn.ok{background:rgba(63,185,80,0.12);border:1px solid rgba(63,185,80,0.3);color:var(--ok)}
.btn:disabled{opacity:.45;pointer-events:none}
.iconbtn{background:var(--panel3);border:1px solid var(--line2);color:var(--mut);width:34px;height:34px;border-radius:var(--radius);font-size:.95rem;display:flex;align-items:center;justify-content:center;padding:0}
.iconbtn:hover{color:var(--acc);border-color:var(--acc);background:rgba(88,166,255,0.08)}

/* ---- spin loader ---- */
@keyframes spin{to{transform:rotate(360deg)}}
.spin{display:inline-block;width:14px;height:14px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:6px}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.pulse{animation:pulse 1.5s ease infinite}

/* ---- top bar ---- */
.top{height:58px;display:flex;align-items:center;gap:12px;padding:0 18px;
  background:linear-gradient(90deg,var(--gov-deep),var(--acc));
  border-bottom:3px solid var(--c3);position:relative;z-index:5}
.top .logo{font-size:1.4rem;line-height:1;filter:grayscale(1) brightness(3)}
.top-title{display:flex;flex-direction:column;gap:1px}
.top h1{font-size:1.02rem;margin:0;letter-spacing:.1px;font-weight:800;color:#fff}
.top .sub{color:rgba(255,255,255,0.82);font-size:.68rem;letter-spacing:.3px;font-weight:600}
.top .spacer{flex:1}
.top-right{display:flex;align-items:center;gap:10px}

/* shield badge */
.shield{font-size:.72rem;padding:6px 12px;border-radius:20px;border:1px solid var(--line2);
  background:var(--panel3);color:var(--mut);white-space:nowrap;font-weight:600;
  transition:all .3s ease}
.shield.ok{background:rgba(63,185,80,0.12);border-color:rgba(63,185,80,0.35);color:var(--ok);box-shadow:var(--glow-ok)}
.shield.bad{background:rgba(248,81,73,0.12);border-color:rgba(248,81,73,0.35);color:var(--bad);box-shadow:var(--glow-bad)}

/* ---- main layout ---- */
.app{height:calc(100vh - 54px);display:grid;
  grid-template-columns:var(--sw,340px) 1fr;
  grid-template-rows:1fr var(--th,200px);
  grid-template-areas:"side graph" "side timeline";
  transition:grid-template-columns .28s cubic-bezier(.4,0,.2,1), grid-template-rows .28s cubic-bezier(.4,0,.2,1)}
.app.side-collapsed{--sw:0px}
.app.tl-collapsed{--th:0px}

/* ---- sidebar ---- */
.side{grid-area:side;background:var(--panel);border-right:1px solid var(--line);
  overflow-y:auto;overflow-x:hidden;display:flex;flex-direction:column;gap:10px;
  padding:14px;min-width:0;transition:padding .28s ease}
.app.side-collapsed .side{padding:0;border:0;overflow:hidden}

/* gql textarea */
.side textarea{width:100%;height:80px;background:var(--bg);color:var(--acc);
  border:1px solid var(--line2);border-radius:var(--radius);padding:10px;
  font-size:12.5px;resize:vertical;outline:none;transition:border-color .15s}
.side textarea:focus{border-color:var(--acc);box-shadow:var(--glow-acc)}

/* card */
.card{background:var(--panel3);border:1px solid var(--line);border-radius:var(--radius-lg);
  padding:12px 14px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;inset:0;border-radius:inherit;
  background:linear-gradient(135deg,rgba(255,255,255,.03) 0%,transparent 60%);pointer-events:none}
.card h3{margin:0 0 10px;font-size:.72rem;color:var(--muted2);font-weight:700;
  text-transform:uppercase;letter-spacing:.8px}

/* stat pills */
.stats-row{display:flex;gap:8px;flex-wrap:wrap}
.stat-pill{flex:1;min-width:0;background:var(--panel);border:1px solid var(--line2);
  border-radius:8px;padding:8px 10px;display:flex;flex-direction:column;gap:2px}
.stat-pill .sp-val{font-size:1.3rem;font-weight:800;color:var(--ink);line-height:1;letter-spacing:-.5px}
.stat-pill .sp-lbl{font-size:.65rem;color:var(--muted2);font-weight:600;text-transform:uppercase;letter-spacing:.5px}
.stat-pill.acc-pill .sp-val{color:var(--acc)}
.stat-pill.ok-pill .sp-val{color:var(--ok)}
.stat-pill.warn-pill .sp-val{color:var(--warn)}

.row{display:flex;gap:7px;flex-wrap:wrap}
.legend{display:flex;flex-wrap:wrap;gap:6px;font-size:.72rem;color:var(--mut)}
.legend i{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:4px;vertical-align:middle}
.count{font-size:.8rem;color:var(--mut)} .count b{color:var(--ink)}
.err{font-size:.78rem;white-space:pre-wrap;font-family:'JetBrains Mono',monospace;
  padding:8px;background:rgba(248,81,73,0.07);border:1px solid rgba(248,81,73,0.2);
  border-radius:8px;color:var(--bad)}
.err.info{color:var(--mut);background:rgba(139,148,158,0.07);border-color:var(--line2)}
.muted{color:var(--muted2);font-size:.73rem;line-height:1.5}

/* ---- graph area ---- */
.graphwrap{grid-area:graph;position:relative;
  background:radial-gradient(ellipse 120% 80% at 25% 20%,#0e1a2e 0%,#0d1117 65%);
  min-width:0;min-height:0}
#graph{position:absolute;inset:0}
#heb{position:absolute;inset:0;display:none;width:100%;height:100%}
#heb path{cursor:pointer} #heb rect,#heb circle{cursor:pointer}
.heb-cap{position:absolute;left:14px;top:10px;font-size:.78rem;font-weight:700;
  color:var(--mut);z-index:2;pointer-events:none;background:rgba(13,17,23,.7);
  padding:4px 10px;border-radius:6px;backdrop-filter:blur(4px)}
.floatbtns{position:absolute;top:12px;left:12px;display:flex;gap:6px;z-index:4}
.reopen{position:absolute;z-index:4;background:var(--glass);border:1px solid var(--line2);
  color:var(--mut);display:none;backdrop-filter:blur(8px)}
.app.side-collapsed .reopen.side-re{display:flex;left:12px;top:52px;align-items:center;justify-content:center}
.app.tl-collapsed .reopen.tl-re{display:flex;left:12px;bottom:12px;align-items:center;justify-content:center}

/* mode badge */
.mode-badge{position:absolute;top:12px;right:12px;z-index:4;font-size:.72rem;font-weight:700;
  padding:5px 12px;border-radius:20px;border:1px solid var(--line2);
  background:var(--glass);backdrop-filter:blur(8px);color:var(--mut);
  text-transform:uppercase;letter-spacing:.5px;transition:all .3s}
.mode-badge.fraud{color:var(--warn);border-color:rgba(227,179,65,0.4);background:rgba(227,179,65,0.08)}
.mode-badge.suggest{color:var(--acc2);border-color:rgba(163,113,247,0.4);background:rgba(163,113,247,0.08)}
.mode-badge.manifold{color:var(--acc3);border-color:rgba(63,185,80,0.4);background:rgba(63,185,80,0.08)}

/* ---- case timeline view ---- */
#caseTimelineView{position:absolute;inset:0;background:var(--panel);z-index:3;
  display:none;flex-direction:column;align-items:center;padding:40px 20px;
  overflow-x:auto;overflow-y:auto;backdrop-filter:blur(10px)}
#caseTimelineWrap{display:flex;align-items:center;position:relative;margin:auto 0;padding:60px 20px;min-width:max-content}
.ct-line{position:absolute;top:50%;left:0;right:0;height:4px;background:var(--line2);
  border-radius:2px;transform:translateY(-50%);z-index:1}
.ct-node{position:relative;z-index:2;display:flex;flex-direction:column;align-items:center;
  width:160px;margin:0 10px}
.ct-icon{width:48px;height:48px;border-radius:50%;background:var(--panel3);
  border:3px solid var(--acc);display:flex;align-items:center;justify-content:center;
  font-size:1.4rem;box-shadow:0 4px 12px rgba(0,0,0,0.3);margin-bottom:12px;z-index:3}
.ct-content{background:var(--bg);border:1px solid var(--line);border-radius:8px;
  padding:10px;font-size:.75rem;color:var(--ink);text-align:center;width:100%;
  box-shadow:0 4px 12px rgba(0,0,0,0.2)}
.ct-date{font-weight:bold;color:var(--mut);margin-bottom:4px;font-size:.7rem}
.ct-node.up{flex-direction:column-reverse}
.ct-node.up .ct-icon{margin-bottom:0;margin-top:12px}
.ct-stem{position:absolute;width:2px;background:var(--line2);left:50%;transform:translateX(-50%);z-index:1}
.ct-node:not(.up) .ct-stem{bottom:50%;height:40px}
.ct-node.up .ct-stem{top:50%;height:40px}

/* ---- node detail drawer ---- */
.drawer{position:absolute;right:0;top:0;bottom:0;width:280px;
  background:var(--glass);border-left:1px solid var(--line2);
  backdrop-filter:blur(12px);z-index:10;display:flex;flex-direction:column;
  transform:translateX(100%);transition:transform .25s cubic-bezier(.4,0,.2,1)}
.drawer.open{transform:translateX(0)}
.drawer-head{padding:14px 16px 12px;border-bottom:1px solid var(--line);
  display:flex;align-items:center;gap:8px}
.drawer-head .dkind{flex:1;font-size:.8rem;font-weight:700;color:var(--acc)}
.drawer-head .dclose{background:transparent;border:0;color:var(--mut);cursor:pointer;
  padding:4px;border-radius:6px;font-size:1rem;line-height:1}
.drawer-head .dclose:hover{color:var(--bad)}
.drawer-body{flex:1;overflow-y:auto;padding:14px 16px;display:flex;flex-direction:column;gap:12px}
.drawer-field{display:flex;flex-direction:column;gap:3px}
.drawer-field .df-label{font-size:.65rem;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.6px}
.drawer-field .df-val{font-size:.8rem;color:var(--ink);word-break:break-all;line-height:1.4}
.drawer-field .df-val.mono{font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--mut)}
.drawer-field .df-val.big{font-size:1rem;font-weight:700;color:var(--acc)}
.drawer-prov{display:flex;flex-direction:column;gap:4px}
.drawer-prov .dp-item{font-size:.72rem;font-family:'JetBrains Mono',monospace;
  color:var(--mut);padding:4px 8px;background:var(--panel);border-radius:6px;
  border:1px solid var(--line);cursor:pointer;transition:.1s}
.drawer-prov .dp-item:hover{color:var(--acc);border-color:var(--acc)}
.drawer-actions{padding:12px 16px;border-top:1px solid var(--line);display:flex;gap:6px}

/* ---- TIMELINE ---- */
.timeline{grid-area:timeline;background:var(--panel);border-top:1px solid var(--line);
  position:relative;overflow:hidden;min-height:0}
.app.tl-collapsed .timeline{border:0}
.tl-head{height:34px;display:flex;align-items:center;gap:10px;padding:0 14px;border-bottom:1px solid var(--line)}
.tl-head .ttl{font-size:.77rem;font-weight:700;letter-spacing:.3px;color:var(--ink)}
.tl-head .info{color:var(--muted2);font-size:.72rem}
.tl-head .spacer{flex:1}
.tl-scroll{position:absolute;top:34px;left:0;right:0;bottom:0;overflow-x:auto;overflow-y:hidden}
.tl-track{position:relative;height:100%;min-width:100%;padding:0 40px;display:flex;align-items:center}
.tl-bar{position:absolute;left:0;right:0;top:50%;height:12px;transform:translateY(-50%);
  background:linear-gradient(90deg,var(--c1),var(--c2),var(--c3),var(--c4));border-radius:6px;opacity:.7}
.tl-fill{position:absolute;left:0;top:50%;height:12px;transform:translateY(-50%);
  background:var(--panel);opacity:.75;border-radius:0 6px 6px 0}
.tl-handle{position:absolute;top:50%;width:3px;height:40px;transform:translate(-50%,-50%);
  background:var(--acc);border-radius:2px;box-shadow:0 0 0 2px var(--panel),var(--glow-acc);
  cursor:ew-resize;z-index:3}
.tl-row{position:relative;display:flex;align-items:center;z-index:2}
.mk{position:relative;display:flex;flex-direction:column;align-items:center;min-width:84px;cursor:pointer}
.mk .stem{width:2px;background:var(--line2);height:30px}
.mk .dot{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;
  justify-content:center;font-size:.85rem;color:#fff;font-weight:800;
  box-shadow:0 3px 12px rgba(0,0,0,0.4);border:2.5px solid var(--panel);transition:.15s}
.mk:hover .dot{transform:scale(1.15);box-shadow:0 4px 16px rgba(0,0,0,.5)}
.mk.on .dot{border-color:var(--acc);box-shadow:0 0 0 3px rgba(88,166,255,.25)}
.mk .yr{font-size:.95rem;font-weight:800;letter-spacing:.2px;color:var(--ink)}
.mk .cnt{font-size:.62rem;color:var(--muted2);font-weight:500}
.mk.up{flex-direction:column-reverse}
.mk .meta{display:flex;flex-direction:column;align-items:center;gap:1px}
/* hint card */
.hint{position:fixed;z-index:30;max-width:280px;background:var(--glass);
  border:1px solid var(--line2);border-radius:var(--radius-lg);padding:10px 13px;
  box-shadow:var(--shadow);font-size:.76rem;pointer-events:none;opacity:0;
  transition:opacity .12s;color:var(--ink);backdrop-filter:blur(12px)}
.hint.show{opacity:1}
.hint .h-yr{font-weight:800;font-size:.92rem;margin-bottom:3px;color:var(--acc)}
.hint .h-kinds{color:var(--muted2);font-size:.69rem;margin:4px 0}
.hint .h-sample{color:var(--mut);font-style:italic;border-left:2px solid var(--acc);
  padding-left:7px;margin-top:5px;line-height:1.4}
.hint .h-asof{color:var(--warn);font-size:.68rem;margin-top:6px;font-weight:600}
.tl-empty{position:absolute;inset:34px 0 0 0;display:flex;align-items:center;
  justify-content:center;color:var(--mut);font-size:.82rem}

/* ---- export btn state ---- */
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.card{animation:fadeIn .2s ease}
</style></head><body>

<!-- TOP BAR -->
<div class="top">
  <div class="logo">🌊</div>
  <div class="top-title">
    <h1>Heraclitus Console V2</h1>
    <div class="sub">panta rhei &mdash; log event-sourced &middot; proveniência &middot; Merkle</div>
  </div>
  <div class="spacer"></div>
  <div class="top-right">
    <span id="shield" class="shield"><span class="pulse">a verificar Merkle…</span></span>
    <button class="iconbtn" id="fs" title="Tela cheia do grafo (Esc para sair)">⛶</button>
  </div>
</div>

<div class="app" id="app">
  <!-- SIDEBAR retrátil -->
  <aside class="side" id="side">
    <!-- action buttons -->
    <div class="row">
      <button id="fraud" class="btn warn">🕵 Fraudes</button>
      <button id="mindmap" class="btn">🗂 Mapa de Casos</button>
      <button id="manifold" class="btn">🌌 Manifold 3D</button>
      <button id="suggest" class="btn">🔮 Correlações</button>
      <button id="run" class="btn acc">▶ Query</button>
      <button id="verify" class="btn">🛡 Merkle</button>
    </div>

    <!-- case timeline -->
    <div class="card" id="caseCard">
      <h3>Timeline de Caso</h3>
      <div style="display:flex;gap:6px">
        <select id="caseSelect" style="flex:1;background:var(--bg);color:var(--acc);border:1px solid var(--line2);border-radius:var(--radius);padding:6px;outline:none;font-size:12px"></select>
        <button id="plotCase" class="btn ok" style="padding:6px 12px">Plotar</button>
      </div>
    </div>

    <!-- GQL editor -->
    <div class="card">
      <h3>Consulta GQL</h3>
      <textarea id="gql" spellcheck="false">MATCH (n) RETURN n LIMIT 200</textarea>
    </div>

    <!-- stats -->
    <div class="card" id="statsCard">
      <h3>Resumo</h3>
      <div class="stats-row">
        <div class="stat-pill acc-pill">
          <span class="sp-val" id="statNodes">—</span>
          <span class="sp-lbl">Nós</span>
        </div>
        <div class="stat-pill">
          <span class="sp-val" id="statEdges">—</span>
          <span class="sp-lbl">Arestas</span>
        </div>
        <div class="stat-pill ok-pill">
          <span class="sp-val" id="statGroups">—</span>
          <span class="sp-lbl">Grupos</span>
        </div>
        <div class="stat-pill warn-pill">
          <span class="sp-val" id="statCases">—</span>
          <span class="sp-lbl">Casos</span>
        </div>
      </div>
      <div class="count" id="head" style="margin-top:10px;font-size:.72rem">head —</div>
      <div class="legend" id="legend" style="margin-top:8px"></div>
    </div>

    <!-- AS OF -->
    <div class="card">
      <h3>Estado (AS OF)</h3>
      <div class="count"><span id="asoflabel">—</span></div>
      <div class="muted" id="tlhint" style="margin-top:6px">Clique num marcador da linha do tempo: o grafo reconstrói-se naquele ponto do passado (AS OF).</div>
    </div>

    <!-- export -->
    <div class="row" id="exportRow" style="display:none">
      <button id="exportBtn" class="btn ok" style="width:100%">⬇ Exportar dados (JSON)</button>
    </div>

    <!-- status / errors -->
    <div id="err" style="display:none"></div>
    <div class="muted" style="margin-top:auto;padding-top:6px;border-top:1px solid var(--line)">
      Eixo do tempo = <code>ts_hlc</code> (relógio híbrido). Painéis retráteis ◀ ▼ ; ⛶ tela cheia.
    </div>
  </aside>

  <!-- GRAPH AREA -->
  <div class="graphwrap" id="graphwrap">
    <div id="graph"></div>
    <svg id="heb"></svg>
    <div id="caseTimelineView">
      <div id="caseTimelineWrap">
        <div class="ct-line"></div>
        <!-- nodes injeção JS -->
      </div>
    </div>
    <div id="manifold_plot" style="position:absolute;inset:0;display:none;width:100%;height:100%;z-index:2"></div>
    <div id="mindmapView" style="position:absolute;inset:0;display:none;overflow:auto;background:#ffffff;z-index:3"></div>
    <div class="heb-cap" id="hebcap"></div>
    <div class="mode-badge" id="modeBadge" style="display:none"></div>

    <!-- float controls -->
    <div class="floatbtns">
      <button class="iconbtn" id="toggleSide" title="Recolher/expandir painel lateral">◀</button>
      <button class="iconbtn" id="fit" title="Ajustar grafo">⤢</button>
    </div>
    <button class="iconbtn reopen side-re" id="reopenSide" title="Abrir painel lateral">▶</button>
    <button class="iconbtn reopen tl-re" id="reopenTl" title="Abrir linha do tempo">▲</button>

    <!-- node detail drawer -->
    <div class="drawer" id="drawer">
      <div class="drawer-head">
        <span class="dkind" id="dKind">—</span>
        <button class="dclose" id="dClose" title="Fechar">✕</button>
      </div>
      <div class="drawer-body" id="dBody"></div>
      <div class="drawer-actions">
        <button class="btn" id="dExpProv" style="flex:1;font-size:.75rem">🔗 Expandir proveniência</button>
        <button class="btn danger" id="dCenterNode" style="font-size:.75rem">⊙ Centrar</button>
      </div>
    </div>
  </div>

  <!-- TIMELINE retrátil -->
  <section class="timeline" id="timeline">
    <div class="tl-head">
      <span class="ttl">⏳ Linha do tempo</span>
      <span class="info" id="tlinfo">—</span>
      <div class="spacer"></div>
      <button class="iconbtn" id="toggleTl" title="Recolher linha do tempo" style="width:26px;height:22px;font-size:.75rem">▼</button>
    </div>
    <div class="tl-scroll" id="tlscroll">
      <div class="tl-track" id="tltrack">
        <div class="tl-bar"></div>
        <div class="tl-fill" id="tlfill"></div>
        <div class="tl-handle" id="tlhandle"></div>
        <div class="tl-row" id="tlrow"></div>
      </div>
    </div>
    <div class="tl-empty" id="tlempty">a carregar eventos…</div>
  </section>
</div>

<div class="hint" id="hint"></div>

<script>
/* ================================================================
   HERACLITUS CONSOLE V2 — JS runtime
   ================================================================ */
var HEAD=0, ASOF=0, MODE='query', network=null, FRAUD=null, TL=null, BUCKETS=[];
var kindPal={}, ki=0;
var LASTSUGG=null, LAST_PAYLOAD=null;
var _SELECTED_NODE=null;

var KINDP=[
  ['#58a6ff','#0e2a47'],['#3fb950','#0a2817'],['#e3b341','#2d2107'],
  ['#f85149','#2d0c0b'],['#a371f7','#1e1040'],['#39d9f5','#062830'],
  ['#ff9e64','#2d1a05'],['#73daca','#0a2020']
];
var GROUPP=[['#58a6ff'],['#f85149'],['#3fb950'],['#e3b341'],['#a371f7'],['#39d9f5'],['#ff9e64'],['#73daca']];
var gNodes=new vis.DataSet(), gEdges=new vis.DataSet();

function el(i){return document.getElementById(i);}
function esc(s){return (s==null?'':String(s)).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}
function kindColor(k){ if(!kindPal[k]){ kindPal[k]=KINDP[ki%KINDP.length]; ki++; } return kindPal[k]; }
function groupColor(g){ return GROUPP[((g||1)-1)%GROUPP.length][0]; }
function post(p,b){ return fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}).then(function(r){return r.json();}); }

/* ---- stats update ---- */
function updateStats(nodes,edges,groups,cases){
  el('statNodes').textContent = nodes!=null?nodes:'—';
  el('statEdges').textContent = edges!=null?edges:'—';
  el('statGroups').textContent = groups!=null?groups:'—';
  el('statCases').textContent = cases!=null?cases:'—';
}

/* ---- mode badge ---- */
function setMode(mode,label){
  MODE=mode;
  var b=el('modeBadge');
  if(label){ b.style.display='block'; b.textContent=label; b.className='mode-badge '+mode; }
  else { b.style.display='none'; }
}

/* ---- error/status ---- */
function showErr(msg,type){
  var e=el('err');
  if(!msg){ e.style.display='none'; return; }
  e.style.display='block';
  e.className=type==='info'?'err info':'err';
  e.textContent=msg;
}

/* ---- loading state ---- */
function setLoading(btnId,on,label){
  var b=el(btnId);
  if(!b)return;
  if(on){ b.disabled=true; b._orig=b.innerHTML; b.innerHTML='<span class="spin"></span>'+label; }
  else { b.disabled=false; b.innerHTML=b._orig||b.innerHTML; }
}

/* ---- layout: painéis retráteis + tela cheia ---- */
function setSide(open){ el('app').classList.toggle('side-collapsed',!open); el('toggleSide').textContent=open?'◀':'▶'; relayout(); }
function setTl(open){ el('app').classList.toggle('tl-collapsed',!open); el('toggleTl').textContent=open?'▼':'▲'; relayout(); }
function relayout(){ setTimeout(function(){ try{network&&network.redraw();}catch(e){} renderTimeline(); }, 290); }
el('toggleSide').onclick=function(){ setSide(el('app').classList.contains('side-collapsed')); };
el('reopenSide').onclick=function(){ setSide(true); };
el('toggleTl').onclick=function(){ setTl(false); };
el('reopenTl').onclick=function(){ setTl(true); };
var FSON=false;
el('fs').onclick=function(){ FSON=!FSON; setSide(!FSON); setTl(!FSON); };
document.addEventListener('keydown',function(e){
  if(e.key==='Escape'&&FSON){ FSON=false; setSide(true); setTl(true); }
  if(e.key==='Escape'){ closeDrawer(); }
  if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){ e.preventDefault(); el('run').click(); }
});
el('fit').onclick=function(){ try{network.fit({animation:{duration:400,easingFunction:'easeInOutQuad'}});}catch(e){} };

/* ---- node detail drawer ---- */
function openDrawer(nd){
  _SELECTED_NODE=nd;
  el('dKind').textContent=nd.kind||nd.id;
  var html='';
  html+='<div class="drawer-field"><div class="df-label">ID</div><div class="df-val mono">'+esc(nd.id)+'</div></div>';
  if(nd.lsn!=null) html+='<div class="drawer-field"><div class="df-label">LSN</div><div class="df-val big">'+nd.lsn+'</div></div>';
  if(nd.content) html+='<div class="drawer-field"><div class="df-label">Conteúdo</div><div class="df-val">'+esc(nd.content)+'</div></div>';
  if(nd.caso) html+='<div class="drawer-field"><div class="df-label">Caso de Fraude</div><div class="df-val" style="color:var(--warn);font-weight:700">'+esc(nd.caso)+'</div></div>';
  if(nd.group) html+='<div class="drawer-field"><div class="df-label">Grupo</div><div class="df-val" style="color:'+groupColor(nd.group)+';font-weight:700">Grupo '+nd.group+'</div></div>';
  var attrs=nd.attrs||{};
  var attrKeys=Object.keys(attrs).filter(function(k){return k!=='caso';});
  if(attrKeys.length){
    html+='<div class="drawer-field"><div class="df-label">Atributos</div>';
    attrKeys.forEach(function(k){ html+='<div style="display:flex;gap:6px;margin-top:4px;font-size:.75rem"><span style="color:var(--muted2);min-width:80px">'+esc(k)+'</span><span style="color:var(--ink)">'+esc(String(attrs[k]))+'</span></div>'; });
    html+='</div>';
  }
  el('dBody').innerHTML=html;
  el('drawer').classList.add('open');
}
function closeDrawer(){ el('drawer').classList.remove('open'); _SELECTED_NODE=null; }
el('dClose').onclick=closeDrawer;
el('dExpProv').onclick=function(){
  if(!_SELECTED_NODE)return;
  expandProv(_SELECTED_NODE.id);
};
el('dCenterNode').onclick=function(){
  if(!_SELECTED_NODE||!network)return;
  try{ network.focus(_SELECTED_NODE.id,{animation:{duration:400,easingFunction:'easeInOutQuad'},scale:1.5}); }catch(e){}
};

/* ---- merkle shield ---- */
async function verifyMerkle(){
  var s=el('shield');
  try{
    var r=await fetch('verify'); var j=await r.json(); var m={};
    try{ m=JSON.parse(j.message); }catch(e){}
    if(j.ok){
      s.className='shield ok';
      s.innerHTML='🛡 Log íntegro &middot; '+(m.records!=null?m.records:'?')+' registos &middot; '+(m.segments!=null?m.segments:'?')+' segmentos';
    } else {
      s.className='shield bad'; s.textContent='⚠ Integridade comprometida';
    }
  }catch(e){ s.className='shield bad'; s.textContent='⚠ Servidor indisponível'; }
}

/* ---- vis-network setup ---- */
function ensureNetwork(){
  if(network) return;
  network=new vis.Network(el('graph'),{nodes:gNodes,edges:gEdges},{
    nodes:{shape:'dot',size:14,borderWidth:2,
      font:{color:'#e6edf3',size:11,strokeWidth:3,strokeColor:'#0d1117'}},
    edges:{color:{color:'#30363d',highlight:'#58a6ff',hover:'#58a6ff88'},
      width:1.5,arrows:{to:{enabled:true,scaleFactor:.45}},smooth:{type:'continuous'}},
    physics:{stabilization:{iterations:180},
      barnesHut:{springLength:120,avoidOverlap:0.6,gravitationalConstant:-4000}},
    interaction:{hover:true,tooltipDelay:200}
  });
  network.on('click', async function(p){
    if(!p.nodes||!p.nodes.length){ closeDrawer(); return; }
    var id=p.nodes[0];
    var nd=gNodes.get(id);
    if(nd&&nd._raw){ openDrawer(nd._raw); }
    // expand provenance
    await expandProv(id);
  });
}

async function expandProv(id){
  try{
    var j=await post('provenance',{id:id});
    (j.parents||[]).forEach(function(pid){
      if(!gNodes.get(pid)) gNodes.add({id:pid,label:String(pid).slice(-8),
        color:{background:'#2d2107',border:'#e3b341'},
        _raw:{id:pid,kind:'Proveniência',content:'ID: '+pid}});
      var eid=id+'>'+pid;
      if(!gEdges.get(eid)) gEdges.add({id:eid,from:id,to:pid,dashes:true,width:1.5,
        color:{color:'#e3b341',highlight:'#ffa657'}});
    });
  }catch(e){}
}

function drawGraph(payload){
  showHeb(false); showManifold(false);
  gNodes.clear(); gEdges.clear(); kindPal={}; ki=0;
  LAST_PAYLOAD=payload;
  (payload.nodes||[]).forEach(function(nd){
    var c=kindColor(String(nd.kind||''));
    var lab=(nd.content||nd.kind||nd.id);
    gNodes.add({id:nd.id,label:String(lab).slice(0,24),
      title:'<div style="font-family:Inter,sans-serif;font-size:12px;color:#e6edf3;max-width:200px">'+esc(nd.kind||'')+'<br/><small style="color:#8b949e">'+esc((nd.content||'').slice(0,80))+'</small></div>',
      color:{background:c[0],border:c[1]},
      _raw:nd});
  });
  (payload.edges||[]).forEach(function(e,i){ gEdges.add({id:'e'+i,from:e.from,to:e.to}); });
  ensureNetwork(); try{network.fit({animation:{duration:500}});}catch(e){}
  updateStats((payload.nodes||[]).length,(payload.edges||[]).length,'—','—');
  el('legend').innerHTML=Object.keys(kindPal).map(function(k){
    return '<span><i style="background:'+kindPal[k][0]+'"></i>'+esc(k||'(sem tipo)')+'</span>';
  }).join('');
}

async function runQuery(){
  setMode('query',null); closeDrawer();
  var body={gql:el('gql').value};
  if(ASOF<HEAD) body.as_of=ASOF;
  showErr('Carregando…','info'); setLoading('run',true,'Query…');
  try{
    var j=await post('graph',body);
    setLoading('run',false);
    if(j.error){ showErr('Erro: '+j.error); }
    else if(j.plan!=null){ showErr('EXPLAIN:\n'+j.plan,'info'); }
    else {
      drawGraph(j);
      var n=(j.nodes||[]).length;
      showErr(n?null:'(0 linhas)','info');
    }
  }catch(e){ setLoading('run',false); showErr('Falha: '+e.message); }
}

/* ---- FRAUD mode ---- */
async function loadFraudes(){
  closeDrawer(); showErr('Detetando fraudes…','info'); setLoading('fraud',true,'Detetando…');
  try{
    var j=await post('fraudes',{});
    setLoading('fraud',false);
    if(!(j.nodes||[]).length){ showErr('Nenhum caso (attrs.caso). Rode demo/seed.py.'); return; }
    FRAUD=j; setMode('fraud','🕵 Modo Fraude'); renderFraud(ASOF||HEAD);
    showErr(null);
    updateStats(null,null,j.n_groups,j.n_cases);
    el('tlhint').textContent=j.n_groups+' grupo(s) de fraude · '+j.n_cases+' caso(s). Arraste a linha do tempo para montar o caso.';
    el('exportRow').style.display='flex';
    el('legend').innerHTML='';
  }catch(e){ setLoading('fraud',false); showErr('Falha: '+e.message); }
}

function renderFraud(v){
  if(!FRAUD) return;
  showHeb(false); showManifold(false);
  gNodes.clear(); gEdges.clear();
  var ok={}, groups={};
  FRAUD.nodes.forEach(function(nd){
    if(nd.lsn<=v){
      ok[nd.id]=1; groups[nd.group]=1;
      var c=groupColor(nd.group);
      gNodes.add({id:nd.id,label:String(nd.content||nd.kind).slice(0,24),
        title:'<div style="font-family:Inter,sans-serif;font-size:12px;color:#e6edf3">'+esc(nd.kind)+' · Grupo '+nd.group+'<br><small style="color:#8b949e">'+esc(nd.content)+'</small></div>',
        color:{background:c,border:'#0d1117'},size:16,
        _raw:nd});
    }
  });
  FRAUD.edges.forEach(function(e,i){
    if(ok[e.from]&&ok[e.to]) gEdges.add({id:'e'+i,from:e.from,to:e.to});
  });
  ensureNetwork(); try{network.fit({animation:{duration:400}});}catch(e){}
  updateStats(Object.keys(ok).length,FRAUD.edges.filter(function(e){return ok[e.from]&&ok[e.to];}).length,
    Object.keys(groups).length,FRAUD.n_cases);
  el('legend').innerHTML=Object.keys(groups).map(function(g){
    return '<span><i style="background:'+groupColor(+g)+'"></i>Grupo '+g+'</span>';
  }).join('');
}

/* ---- MANIFOLD 3D ---- */
function showManifold(on){
  el('manifold_plot').style.display=on?'block':'none';
  if(on){ var mm=el('mindmapView'); if(mm)mm.style.display='none'; el('heb').style.display='none'; el('graph').style.display='none'; el('hebcap').style.display='none'; }
  else { el('graph').style.display='block'; }
}
async function loadManifold(){
  closeDrawer(); showErr('Carregando espaço vetorial (Manifold)…','info');
  setLoading('manifold',true,'Carregando…');
  try{
    var j=await post('manifold_data',{});
    setLoading('manifold',false);
    if(!(j.points||[]).length){ showErr('Nenhum nó com embedding no banco. Rode o agente para injetar dados com vetores.'); return; }
    setMode('manifold','🌌 Manifold 3D'); FRAUD=null; LASTSUGG=null;
    showManifold(true); showErr(null);
    var trace={
      x:j.points.map(function(p){return p.x}),
      y:j.points.map(function(p){return p.y}),
      z:j.points.map(function(p){return p.z}),
      text:j.points.map(function(p){return p.kind+': '+p.content}),
      mode:'markers',
      marker:{size:5,color:j.points.map(function(p){return p.caso?1:0}),
        colorscale:[['0','#58a6ff'],['1','#f85149']],opacity:0.85,
        line:{width:0}},
      type:'scatter3d',hoverinfo:'text'
    };
    var layout={
      margin:{l:0,r:0,b:0,t:0},
      paper_bgcolor:'rgba(0,0,0,0)',plot_bgcolor:'rgba(0,0,0,0)',
      scene:{
        xaxis:{gridcolor:'#21262d',zerolinecolor:'#21262d',showbackground:false},
        yaxis:{gridcolor:'#21262d',zerolinecolor:'#21262d',showbackground:false},
        zaxis:{gridcolor:'#21262d',zerolinecolor:'#21262d',showbackground:false},
        bgcolor:'rgba(0,0,0,0)'
      },
      font:{color:'#8b949e',family:'Inter,sans-serif'}
    };
    Plotly.newPlot('manifold_plot',[trace],layout,{responsive:true,displayModeBar:false});
    updateStats(j.points.length,'—','—','—');
    showErr(null);
  }catch(e){ setLoading('manifold',false); showErr('Falha: '+e.message); }
}
el('manifold').onclick=loadManifold;

/* ---- CORRELAÇÕES (HEB) ---- */
var HEBP=['#58a6ff','#f85149','#3fb950','#e3b341','#a371f7','#39d9f5','#ff9e64','#73daca','#ffa657','#c5b0d5'];
function hebColor(i){ return HEBP[i%HEBP.length]; }

function showHeb(on){
  el('heb').style.display=on?'block':'none';
  if(on){ var mm=el('mindmapView'); if(mm)mm.style.display='none'; showManifold(false); el('hebcap').style.display='block'; }
  else { el('hebcap').style.display='none'; }
  el('graph').style.display=on?'none':'block';
}

function showHintRaw(text,ev){
  var h=el('hint');
  h.innerHTML='<div class="h-yr">🔮 Correlação</div><div class="h-sample" style="border-color:#a371f7">'+esc(text)+'</div>';
  h.classList.add('show'); moveHint(ev);
}

async function loadSuggest(){
  closeDrawer(); showErr('A descobrir correlações ocultas…','info'); setLoading('suggest',true,'Analisando…');
  try{
    var j=await post('suggest',{});
    setLoading('suggest',false);
    if(j.note){ showErr(j.note,'info'); return; }
    if(!(j.edges||[]).length){ showErr('Nenhuma correlação acima do limiar.','info'); return; }
    setMode('suggest','🔮 Correlações'); FRAUD=null; LASTSUGG=j;
    showHeb(true); renderHEB(j); showErr(null);
    var cross=(j.edges||[]).filter(function(e){return e.cross;}).length;
    updateStats((j.nodes||[]).length,(j.edges||[]).length,'—',cross+' entre casos');
  }catch(e){ setLoading('suggest',false); showErr('Falha: '+e.message); }
}

function renderHEB(j){
  var svg=el('heb'), wrap=svg.parentNode;
  var W=wrap.clientWidth||900, H=wrap.clientHeight||600;
  var cx=W/2, cy=H/2, R=Math.max(80,Math.min(W,H)/2-80);
  var nodes=(j.nodes||[]).slice(), edges=j.edges||[];
  var groups={}, order=[];
  nodes.forEach(function(n){
    var g=n.caso?('Caso '+n.caso):'Correlacionado (C)';
    if(!(g in groups)){ groups[g]=[]; order.push(g); }
    groups[g].push(n);
  });
  order.sort();
  var gcolor={}; order.forEach(function(g,i){ gcolor[g]=(g.indexOf('(C)')>=0)?'#6e7681':hebColor(i); });
  var ord=[]; order.forEach(function(g){ groups[g].forEach(function(nd){ nd._g=g; ord.push(nd); }); });
  var n=ord.length||1, pos={};
  ord.forEach(function(nd,i){ var a=(i/n)*2*Math.PI - Math.PI/2;
    nd._x=cx+R*Math.cos(a); nd._y=cy+R*Math.sin(a); pos[nd.id]=nd; });
  var bundle=0.82, parts=['<g>'];
  edges.forEach(function(e,i){
    var A=pos[e.from], B=pos[e.to]; if(!A||!B) return;
    var c1x=cx+(A._x-cx)*(1-bundle), c1y=cy+(A._y-cy)*(1-bundle);
    var c2x=cx+(B._x-cx)*(1-bundle), c2y=cy+(B._y-cy)*(1-bundle);
    var col=gcolor[A._g]||'#8b949e', base=(0.15+0.5*(e.score||0));
    parts.push('<path d="M'+A._x.toFixed(1)+' '+A._y.toFixed(1)+'C'+c1x.toFixed(1)+' '+c1y.toFixed(1)+' '+c2x.toFixed(1)+' '+c2y.toFixed(1)+' '+B._x.toFixed(1)+' '+B._y.toFixed(1)+'" fill="none" stroke="'+col+'" stroke-width="'+(0.5+(e.score||0)*2.8).toFixed(2)+'" stroke-opacity="'+base.toFixed(2)+'" data-i="'+i+'" data-from="'+e.from+'" data-to="'+e.to+'"/>');
  });
  parts.push('</g><g>');
  ord.forEach(function(nd){
    var col=gcolor[nd._g];
    var t=esc((nd.caso?('Caso '+nd.caso+' · '):'')+nd.kind+' · '+nd.content);
    if(nd.fraud) parts.push('<rect x="'+(nd._x-6).toFixed(1)+'" y="'+(nd._y-6).toFixed(1)+'" width="12" height="12" rx="2" fill="'+col+'" stroke="#0d1117" stroke-width="1.5" data-id="'+nd.id+'"><title>'+t+'</title></rect>');
    else parts.push('<circle cx="'+nd._x.toFixed(1)+'" cy="'+nd._y.toFixed(1)+'" r="5.5" fill="'+col+'" stroke="#0d1117" stroke-width="1.5" data-id="'+nd.id+'"><title>'+t+'</title></circle>');
  });
  parts.push('</g>');
  svg.setAttribute('viewBox','0 0 '+W+' '+H); svg.innerHTML=parts.join('');
  el('hebcap').textContent='🔮 Correlações — '+n+' nós · '+edges.length+' ligações · agrupado por caso';
  el('legend').innerHTML=order.map(function(g){
    return '<span><i style="background:'+gcolor[g]+'"></i>'+esc(g)+'</span>';
  }).join('')+'<span style="flex-basis:100%"></span><span class="muted">□ fraude · ○ correlacionado (C)</span>';

  function reset(){
    Array.prototype.forEach.call(svg.querySelectorAll('path'),function(p){
      var e=edges[+p.getAttribute('data-i')];
      p.setAttribute('stroke-opacity',(0.15+0.5*((e&&e.score)||0)).toFixed(2));
      p.setAttribute('stroke-width',(0.5+((e&&e.score)||0)*2.8).toFixed(2));
    });
  }
  Array.prototype.forEach.call(svg.querySelectorAll('path'),function(p){
    p.addEventListener('mouseenter',function(ev){
      var e=edges[+p.getAttribute('data-i')];
      if(e) showHintRaw(e.score+' · '+e.why+(e.cross?' · entre casos':''),ev);
      p.setAttribute('stroke-opacity','0.95'); p.setAttribute('stroke-width',(1.5+(e?e.score:0)*2.8).toFixed(2));
    });
    p.addEventListener('mousemove',function(ev){ moveHint(ev); });
    p.addEventListener('mouseleave',function(){ el('hint').classList.remove('show'); reset(); });
  });
  Array.prototype.forEach.call(svg.querySelectorAll('[data-id]'),function(nd){
    nd.addEventListener('mouseenter',function(){
      var id=nd.getAttribute('data-id');
      Array.prototype.forEach.call(svg.querySelectorAll('path'),function(p){
        var on=(p.getAttribute('data-from')===id||p.getAttribute('data-to')===id);
        p.setAttribute('stroke-opacity',on?'0.95':'0.04');
      });
    });
    nd.addEventListener('mouseleave',reset);
  });
}

/* ---- AS OF ---- */
function setAsof(lsn,redraw){
  ASOF=Math.max(0,Math.min(HEAD,lsn|0));
  el('asoflabel').textContent=(ASOF>=HEAD)?('completo (head LSN '+HEAD+')'):('AS OF LSN '+ASOF);
  paintTimeline();
  if(redraw){
    if(MODE==='fraud'&&FRAUD) renderFraud(ASOF);
    else runQuery();
  }
}

/* ---- TIMELINE (infográfica) ---- */
var ICON={Observation:'◍',Memory:'🧠',MemoryTombstone:'✖',AgentEvent:'⚙',Decision:'✔',
  Rule:'§',Fact:'•',ProjectContext:'▣',Learning:'✦',UserPref:'☺',Tombstone:'✖'};

function fmtBucket(ts,gran){
  var d=new Date(ts); var M=['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
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
  if(useTs){
    var mn=Math.min.apply(null,wts.map(function(e){return e.ts;})),
        mx=Math.max.apply(null,wts.map(function(e){return e.ts;}));
    var span=mx-mn, D=86400000;
    gran = span>730*D?'year': span>75*D?'month': span>2*D?'day':'hour';
    keyer=function(e){
      var d=new Date(e.ts||mn);
      if(gran==='year')return d.getFullYear();
      if(gran==='month')return d.getFullYear()*100+d.getMonth();
      if(gran==='day')return Math.floor((e.ts||mn)/D);
      return Math.floor((e.ts||mn)/3600000);
    };
  } else {
    var lo=events[0].lsn, hi=events[events.length-1].lsn, w=Math.max(1,Math.ceil((hi-lo+1)/14));
    keyer=function(e){ return Math.floor((e.lsn-lo)/w); };
  }
  var map={};
  events.forEach(function(e){
    var k=keyer(e);
    if(!map[k]) map[k]={key:k,ts:e.ts,lsnMin:e.lsn,lsnMax:e.lsn,count:0,kinds:{},sample:''};
    var b=map[k]; b.count++; b.lsnMax=Math.max(b.lsnMax,e.lsn); b.lsnMin=Math.min(b.lsnMin,e.lsn);
    if(e.ts&&!b.ts)b.ts=e.ts;
    b.kinds[e.kind]=(b.kinds[e.kind]||0)+1; if(!b.sample&&e.content)b.sample=e.content;
  });
  var arr=Object.keys(map).map(function(k){return map[k];}).sort(function(a,b){return a.lsnMin-b.lsnMin;});
  arr.forEach(function(b){
    b.label=(useTs&&b.ts)?fmtBucket(b.ts,gran):('#'+b.lsnMin+'–'+b.lsnMax);
    var dk='',dn=0; for(var kk in b.kinds){ if(b.kinds[kk]>dn){dn=b.kinds[kk];dk=kk;} } b.dom=dk;
  });
  return arr;
}

async function loadTimeline(){
  try{
    var j=await post('timeline_get',{});
    TL=j; HEAD=j.head||HEAD;
    BUCKETS=bucketize(j.events||[]);
    el('tlinfo').textContent=(j.n||0)+' eventos · '+BUCKETS.length+' períodos · head LSN '+HEAD;
    el('head').textContent='head LSN '+HEAD;
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
  var frac=HEAD?(ASOF/HEAD):1;
  el('tlfill').style.left=(frac*100)+'%'; el('tlfill').style.right=0;
  el('tlfill').style.width=((1-frac)*100)+'%'; el('tlfill').style.left=(frac*100)+'%';
  el('tlhandle').style.left=(frac*100)+'%';
  Array.prototype.forEach.call(el('tlrow').children,function(m){
    m.classList.toggle('on',+m.getAttribute('data-lsn')<=ASOF);
  });
}

function showHint(b,ev){
  if(!b)return; var h=el('hint');
  var kinds=Object.keys(b.kinds).map(function(k){return esc(k)+' ×'+b.kinds[k];}).join(' · ');
  h.innerHTML='<div class="h-yr">'+esc(b.label)+'</div>'+
    '<div>'+b.count+' evento(s) · LSN '+b.lsnMin+'–'+b.lsnMax+'</div>'+
    '<div class="h-kinds">'+kinds+'</div>'+
    (b.sample?('<div class="h-sample">'+esc(b.sample)+'</div>'):'')+
    '<div class="h-asof">clique → AS OF LSN '+b.lsnMax+'</div>';
  h.classList.add('show'); moveHint(ev);
}

function moveHint(ev){
  var h=el('hint'); var x=ev.clientX+16, y=ev.clientY-12;
  if(x+300>window.innerWidth) x=ev.clientX-304;
  if(y<10)y=10; h.style.left=x+'px'; h.style.top=y+'px';
}

/* arrastar o handle = AS OF contínuo */
(function(){ var drag=false; var sc=el('tlscroll');
  function lsnAt(clientX){ var r=el('tltrack').getBoundingClientRect(); var f=(clientX - r.left + sc.scrollLeft)/r.width; f=Math.max(0,Math.min(1,f)); return Math.round(f*HEAD); }
  el('tlhandle').addEventListener('mousedown',function(e){ drag=true; e.preventDefault(); });
  sc.addEventListener('mousedown',function(e){ if(e.target.closest('.mk'))return; setAsof(lsnAt(e.clientX),true); });
  window.addEventListener('mousemove',function(e){ if(drag) setAsof(lsnAt(e.clientX),false); });
  window.addEventListener('mouseup',function(e){ if(drag){ drag=false; setAsof(ASOF,true); } });
})();

/* ---------- TIMELINE DE CASO ---------- */
function showCaseView(on){
  el('caseTimelineView').style.display=on?'flex':'none';
  if(on){ var mm=el('mindmapView'); if(mm)mm.style.display='none'; showManifold(false); showHeb(false); el('graph').style.display='none'; }
}

async function loadCasesCombo(){
  try {
    var j=await post('cases_list',{});
    var s=el('caseSelect');
    s.innerHTML='<option value="">Selecione um caso...</option>';
    (j.cases||[]).forEach(function(c){
      s.innerHTML+='<option value="'+esc(c)+'">Caso '+esc(c)+'</option>';
    });
  }catch(e){}
}

el('plotCase').onclick=async function(){
  var caso=el('caseSelect').value;
  if(!caso) return;
  closeDrawer(); showErr('Carregando timeline do caso...','info');
  try{
    var j=await post('case_events',{caso:caso});
    showErr(null);
    setMode('case','🛤️ Caso '+caso); FRAUD=null; LASTSUGG=null;
    showCaseView(true);
    updateStats((j.events||[]).length,'—','—','1');
    renderCaseTimeline(j.events||[]);
  }catch(e){ showErr('Falha: '+e.message); }
};

function renderCaseTimeline(events){
  var wrap=el('caseTimelineWrap');
  var html='<div class="ct-line"></div>';
  events.forEach(function(e,i){
    var up=(i%2!==0);
    var icon=ICON[e.kind]||'•';
    var c=kindColor(e.kind);
    var date=e.ts?fmtBucket(e.ts,'hour'):('LSN '+e.lsn);
    html+=`
      <div class="ct-node ${up?'up':''}">
        <div class="ct-stem"></div>
        <div class="ct-icon" style="border-color:${c[0]};color:${c[0]}">${icon}</div>
        <div class="ct-content" style="border-left:3px solid ${c[0]}">
          <div class="ct-date">${date}</div>
          <strong>${esc(e.kind)}</strong>
          <div style="margin-top:4px;color:var(--mut)">${esc((e.content||'').slice(0,60))}</div>
        </div>
      </div>
    `;
  });
  wrap.innerHTML=html;
}

/* ---------- MAPA DE CASOS (mind map / linha do tempo) ---------- */
function showMindmap(on){
  el('mindmapView').style.display=on?'block':'none';
  if(on){ showManifold(false); showHeb(false); showCaseView(false); el('graph').style.display='none'; el('hebcap').style.display='none'; }
  else { el('graph').style.display='block'; }
}
function _trunc(s,n){ s=String(s||''); return s.length>n?s.slice(0,n-1)+'…':s; }

async function renderMindmap(){
  closeDrawer(); setMode('mindmap','🗂 Mapa de Casos'); FRAUD=null; LASTSUGG=null;
  showErr('A montar o mapa de casos…','info');
  try{
    // uma única varredura agrupada (sem N+1: era 1 + um pedido por caso)
    var ov=await post('cases_overview',{});
    var data=(ov.cases||[]);
    if(!data.length){ showErr('Sem casos para mapear (carregue dados com casos).'); return; }
    showErr(null); showMindmap(true);
    el('exportRow').style.display='flex'; LAST_PAYLOAD={mindmap:data};
    var tot=data.reduce(function(a,d){return a+d.events.length;},0);
    updateStats(tot,'—','—',data.length);
    el('mindmapView').innerHTML=drawMindmapSVG(data);
  }catch(e){ showErr('Falha: '+e.message); }
}

function drawMindmapSVG(cases){
  var MAXE=8, colW=300, padX=120;
  var maxe=cases.reduce(function(m,d){return Math.max(m,Math.min(d.events.length,MAXE));},1);
  var arm=150+maxe*30+40;                 // extensao vertical de cada ramo
  var W=Math.max((el('graphwrap')||{}).clientWidth||1200, padX*2+cases.length*colW);
  var H=arm*2+40, axisY=H/2;
  var palette=['#1351b4','#e52207','#168821','#c47000','#7e3ff2','#0095db','#d4006a','#00803b'];

  var svg='<svg width="'+W+'" height="'+H+'" viewBox="0 0 '+W+' '+H+'" xmlns="http://www.w3.org/2000/svg" font-family="Raleway,Inter,sans-serif">';
  // eixo central
  svg+='<defs><linearGradient id="axis" x1="0" x2="1"><stop offset="0" stop-color="#071d41"/><stop offset="1" stop-color="#1351b4"/></linearGradient></defs>';
  svg+='<rect x="50" y="'+(axisY-6)+'" width="'+(W-100)+'" height="12" rx="6" fill="url(#axis)"/>';
  // banner central com o titulo
  var bw=360, bx=W/2-bw/2;
  svg+='<rect x="'+bx+'" y="'+(axisY-20)+'" width="'+bw+'" height="40" rx="20" fill="#071d41" stroke="#ffcd07" stroke-width="2"/>';
  svg+='<text x="'+(W/2)+'" y="'+(axisY+6)+'" text-anchor="middle" fill="#fff" font-size="17" font-weight="800" letter-spacing="2">LINHA DO TEMPO · CASOS</text>';

  cases.forEach(function(d,i){
    var cx=padX+i*colW+colW/2, dir=(i%2===0)?-1:1, col=palette[i%palette.length];
    var pillY=axisY+dir*130, pillH=46, pillW=210, half=pillW/2;
    // ramo curvo do eixo ate' a pilula do caso
    var y0=axisY, y1=pillY-dir*pillH/2;
    svg+='<path d="M '+cx+' '+y0+' C '+cx+' '+(y0+dir*55)+' '+cx+' '+(y1-dir*45)+' '+cx+' '+y1+'" stroke="'+col+'" stroke-width="4" fill="none" stroke-linecap="round"/>';
    svg+='<circle cx="'+cx+'" cy="'+y0+'" r="7" fill="'+col+'" stroke="#fff" stroke-width="2"/>';
    // pilula do caso
    svg+='<rect x="'+(cx-half)+'" y="'+(pillY-pillH/2)+'" width="'+pillW+'" height="'+pillH+'" rx="10" fill="'+col+'"/>';
    svg+='<text x="'+cx+'" y="'+(pillY-3)+'" text-anchor="middle" fill="#fff" font-size="15" font-weight="800">Caso '+esc(_trunc(d.caso,16))+'</text>';
    svg+='<text x="'+cx+'" y="'+(pillY+15)+'" text-anchor="middle" fill="rgba(255,255,255,.85)" font-size="11" font-weight="600">'+d.events.length+' evento(s)</text>';
    // folhas (eventos)
    var evs=d.events.slice(0,MAXE);
    var startY=pillY+dir*(pillH/2+26);
    var lastY=startY+dir*((evs.length-1)*30);
    svg+='<line x1="'+cx+'" y1="'+(pillY+dir*pillH/2)+'" x2="'+cx+'" y2="'+lastY+'" stroke="'+col+'" stroke-width="2" stroke-dasharray="2 3" opacity=".5"/>';
    evs.forEach(function(e,j){
      var ey=startY+dir*j*30;
      var ic=(typeof ICON!=='undefined'&&ICON[e.kind])?ICON[e.kind]:'•';
      svg+='<circle cx="'+cx+'" cy="'+ey+'" r="5" fill="#fff" stroke="'+col+'" stroke-width="2.5"/>';
      svg+='<rect x="'+(cx+12)+'" y="'+(ey-13)+'" width="190" height="26" rx="6" fill="#f4f7fc" stroke="'+col+'" stroke-opacity=".35"/>';
      svg+='<text x="'+(cx+20)+'" y="'+(ey+4)+'" font-size="12" fill="#1c1c1c"><tspan font-weight="700">'+ic+' '+esc(_trunc(e.kind,12))+'</tspan>  <tspan fill="#555f6d">'+esc(_trunc(e.content,26))+'</tspan></text>';
    });
    if(d.events.length>MAXE){
      svg+='<text x="'+(cx+18)+'" y="'+(lastY+dir*26)+'" font-size="11" fill="'+col+'" font-weight="700">+ '+(d.events.length-MAXE)+' mais…</text>';
    }
  });
  svg+='</svg>';
  return svg;
}
el('mindmap').onclick=renderMindmap;

/* ---------- botões ---------- */
el('fraud').onclick=loadFraudes;
el('suggest').onclick=loadSuggest;
el('run').onclick=function(){ setMode('query',null); FRAUD=null; showMindmap(false); showCaseView(false); showHeb(false); showManifold(false); el('graph').style.display='block'; closeDrawer(); el('exportRow').style.display='none'; runQuery(); };
el('verify').onclick=verifyMerkle;

/* ---- export ---- */
el('exportBtn').onclick=function(){
  var data=LAST_PAYLOAD||LASTSUGG||{error:'sem dados'};
  var blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  var a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download='heraclitus-export-'+(new Date().toISOString().slice(0,16).replace(':','-'))+'.json';
  a.click(); URL.revokeObjectURL(a.href);
};

/* ---- boot ---- */
window.addEventListener('load', async function(){
  try{
    var r=await fetch('head'); var j=await r.json();
    HEAD=j.head||0; ASOF=HEAD;
    el('head').textContent='head LSN '+HEAD;
  }catch(e){}
  // dados úteis primeiro (varreduras limitadas, rápidas)
  await loadTimeline();
  await loadCasesCombo();
  await runQuery();
  // verifyMerkle recalcula o Merkle do log INTEIRO — pesado num log grande.
  // Não bloqueia o arranque; corre em background e renova-se a cada 15s.
  verifyMerkle();
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
        elif self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
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
            elif self.path.startswith("/manifold_data"):
                self._send(200, json.dumps(_manifold_data(_client()), ensure_ascii=False, default=str))
            elif self.path.startswith("/fraudes"):
                self._send(200, json.dumps(_fraudes(_client()), ensure_ascii=False, default=str))
            elif self.path.startswith("/suggest"):
                self._send(200, json.dumps(_suggest(_client()), ensure_ascii=False, default=str))
            elif self.path.startswith("/timeline_get"):
                self._send(200, json.dumps(_timeline(_client()), ensure_ascii=False, default=str))
            elif self.path.startswith("/cases_overview"):
                self._send(200, json.dumps(_cases_overview(_client()), ensure_ascii=False, default=str))
            elif self.path.startswith("/cases_list"):
                self._send(200, json.dumps(_case_list(_client()), ensure_ascii=False, default=str))
            elif self.path.startswith("/case_events"):
                b = self._json()
                caso = b.get("caso", "")
                self._send(200, json.dumps(_case_events(_client(), caso), ensure_ascii=False, default=str))
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
    ap = argparse.ArgumentParser(description="Heraclitus Console V2")
    ap.add_argument("--addr", default="127.0.0.1:7474")
    ap.add_argument("--port", type=int, default=7481)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-open", action="store_true")
    args = ap.parse_args()
    _DB["addr"] = args.addr
    url = f"http://127.0.0.1:{args.port}"
    print(f"Heraclitus Console V2 em {url}  (banco: {args.addr})")
    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
