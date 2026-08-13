# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

"""Heraclitus Console V3 — ANÁLISE de fraude por CRUZAMENTO, on-demand.

Para logs GRANDES (milhões de nós) E com a análise relacional do V2:

- JANELA de tempo (LSN): só essa fatia carrega (o motor poda -> ~0.1s). Nunca
  faz fullscan.
- CRUZAMENTO por ENTIDADE (CNPJ/código): nós que partilham o mesmo
  cnpj/cod_participante/cod_vencedor/cod_favorecido são LIGADOS — uma empresa que
  aparece numa Licitação, numa Compra e numa Transferência fica conectada. É o
  record-linkage que descobre o anel.
- PROVENIÊNCIA: arestas pai-filho (Licitacao<-Item/Participacao, etc.).
- GRUPOS: componentes conexos sobre (proveniência + cruzamento) = anéis / redes.
  Cor por grupo (ou por tipo).
- EXPANDIR = alargar a janela para trás (a proveniência aponta para trás).
- ADAPTATIVO: legenda/filtro saem do que a janela contém.

  py console/server_v3.py            # http://127.0.0.1:7482
"""
import argparse
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_ROOT), "sdk", "python"))
import heraclitusdb  # noqa: E402

_DB = {"addr": "127.0.0.1:7474"}

# Atributos que identificam uma ENTIDADE (empresa/favorecido) — a chave do
# cruzamento entre licitações, compras e transferências.
ENTITY_KEYS = ["cnpj", "cod_participante", "cod_vencedor", "cod_favorecido",
               "cnpj_vencedor", "favorecido", "contratado", "fornecedor", "id_servidor"]


def _edge_family(rel):
    """Classifica a relação persistida (edge-builder) numa família visual.
    - 'resolve' : ligação por entity resolution (CPF mascarado + nome) → MESMA_PESSOA_*
    - 'alerta'  : sinal de fraude/compliance (empresa punida, ONG impedida, expulso)
    - 'rel'     : demais relações determinísticas persistidas
    """
    r = (rel or "").upper()
    if r.startswith("MESMA_PESSOA"):
        return "resolve"
    if "PUNIDA" in r or "IMPEDIDA" in r or "EXPULSO" in r:
        return "alerta"
    return "rel"


def _client():
    return heraclitusdb.connect(_DB["addr"])


def _clean_kind(k):
    s = str(k or "")
    return s[8:-2] if s.startswith('Custom("') and s.endswith('")') else s


def _entity_of(attrs):
    """Devolve (chave, valor) da entidade identificadora do nó, se houver."""
    for k in ENTITY_KEYS:
        v = attrs.get(k)
        if v and str(v).strip() not in ("", "0", "-1"):
            return (k, str(v).strip())
    return None


def _analyze(db, lo, hi, limit, kind, focus):
    """Janela podada + cruzamento por entidade + proveniência + grupos."""
    gql = f"MATCH (n) WHERE n.lsn >= {int(lo)} AND n.lsn <= {int(hi)}"
    if kind:
        # sanitiza: o tipo é interpolado na query; remove aspas/barra para não
        # quebrar a NQL nem permitir injeção (o valor vem de um select, mas é dado).
        safe = str(kind).replace("\\", "").replace('"', "")
        gql += f' AND n.tipo = "{safe}"'
    gql += f" RETURN n LIMIT {int(limit)}"
    rows = db.query(gql)
    rows = rows if isinstance(rows, list) else []

    nodes, ids = [], set()
    for r in rows:
        rid = r.get("id")
        if not rid:
            continue
        a = r.get("attrs") or {}
        ent = _entity_of(a)
        nodes.append({
            "id": rid, "kind": _clean_kind(r.get("kind")),
            "content": (r.get("content") or "")[:120], "lsn": r.get("lsn"),
            "attrs": a, "parents": r.get("parents", []),
            "ent": (ent[1] if ent else None), "ent_key": (ent[0] if ent else None),
        })
        ids.add(rid)

    adj = {n["id"]: set() for n in nodes}
    edges = []

    def link(a, b, typ, label=""):
        if a == b:
            return
        edges.append({"from": a, "to": b, "type": typ, "label": label})
        adj[a].add(b)
        adj[b].add(a)

    # 1) PROVENIÊNCIA (pai-filho dentro da janela)
    for n in nodes:
        for p in n["parents"]:
            if p in ids:
                link(n["id"], p, "prov")

    # 2) CRUZAMENTO por ENTIDADE (mesma empresa/CNPJ -> liga; estrela p/ não virar
    #    teia O(n^2)). Ignora valores quase-ubíquos (sem poder discriminante).
    buckets = defaultdict(list)
    for n in nodes:
        if n["ent"]:
            buckets[n["ent"]].append(n["id"])
    shared = 0
    for val, members in buckets.items():
        if 2 <= len(members) <= 150:
            hub = members[0]
            for m in members[1:]:
                link(hub, m, "shared", val)
                shared += 1

    # 2b) ARESTAS PERSISTIDAS (edge-builder): RESOLVE + compliance.
    #     Sobrepõe as arestas já gravadas como eventos kind "Edge" cujos DOIS
    #     extremos (mapeados por LSN) estão na janela. São os *leads* de fraude:
    #     servidor↔cartão/expulsão (MESMA_PESSOA_*, com score) e empresa punida↔
    #     contrato (alertas). Filtra-se em Python por extremos visíveis, por isso
    #     a query pode trazer Edges de qualquer LSN ≥ lo (são acrescentados após
    #     os nós) sem virar fullscan — o LIMIT mantém-na podada.
    lsn2id = {str(n["lsn"]): n["id"] for n in nodes if n.get("lsn") is not None}
    n_resolve = n_alerta = 0
    if lsn2id:
        erows = db.query(
            f'MATCH (n) WHERE n.lsn >= {int(lo)} AND n.tipo = "Edge" '
            f'RETURN n LIMIT {int(limit)}'
        )
        erows = erows if isinstance(erows, list) else []
        for er in erows:
            ea = er.get("attrs") or {}
            a = lsn2id.get(str(ea.get("from_lsn", "")))
            b = lsn2id.get(str(ea.get("to_lsn", "")))
            if not a or not b or a == b:
                continue
            rel = ea.get("relation", "")
            fam = _edge_family(rel)
            sc = ea.get("score")
            lbl = rel + (f" · {sc}" if sc else "")
            e = {"from": a, "to": b, "type": fam, "label": lbl, "rel": rel}
            if sc:
                try:
                    e["score"] = float(sc)
                except (TypeError, ValueError):
                    pass
            if ea.get("confianca"):
                e["conf"] = ea["confianca"]
            edges.append(e)
            adj[a].add(b)
            adj[b].add(a)
            if fam == "resolve":
                n_resolve += 1
            elif fam == "alerta":
                n_alerta += 1

    # 3) GRUPOS = componentes conexos sobre (proveniência + cruzamento)
    group, g = {}, 0
    for nid in ids:
        if nid in group:
            continue
        g += 1
        stack = [nid]
        while stack:
            x = stack.pop()
            if x in group:
                continue
            group[x] = g
            stack.extend(adj[x] - set(group))
    for n in nodes:
        n["group"] = group.get(n["id"], 0)

    gsizes = Counter(n["group"] for n in nodes)
    # destaca foco (CNPJ/termo) se pedido
    foc = (focus or "").strip().lower()
    if foc:
        for n in nodes:
            blob = (str(n["ent"] or "") + " " + n["content"] + " "
                    + " ".join(str(v) for v in n["attrs"].values())).lower()
            n["hit"] = foc in blob

    return {
        "nodes": nodes, "edges": edges,
        "kinds": dict(Counter(n["kind"] for n in nodes)),
        "groups": {str(k): v for k, v in gsizes.most_common(40)},
        "n_groups": len([s for s in gsizes.values() if s > 1]),
        "n_shared": shared,
        "n_resolve": n_resolve,
        "n_alerta": n_alerta,
        "dangling": sum(1 for n in nodes for p in n["parents"] if p not in ids),
        "lo": int(lo), "hi": int(hi), "total": len(nodes),
    }


def _best(db, samples=22, win=600):
    """Amostra janelas ao longo do log e devolve o início da que tem mais
    CRUZAMENTO — nós cuja entidade (CNPJ/código) é PARTILHADA por ≥2 nós (anéis
    reais). Evita a cauda (Observações) e os blocos de pessoas únicas (sem
    cruzamento).

    `win` ≈ o tamanho de janela que a UI carrega no arranque (SIZE=500), para a
    região "melhor" ter mesmo cruzamento DENTRO da janela mostrada (B4)."""
    head = db.head()
    if head <= win:
        return {"from": 0, "head": head, "shared": 0}
    step = max(1, (head - win) // samples)
    best_off, best_score = 0, -1
    off = 0
    while off < head - win:
        try:
            rows = db.query(f"MATCH (n) WHERE n.lsn >= {off} AND n.lsn <= {off+win} RETURN n LIMIT {win}")
        except Exception:
            rows = []
        rows = rows if isinstance(rows, list) else []
        vals = Counter()
        for r in rows:
            e = _entity_of(r.get("attrs") or {})
            if e:
                vals[e[1]] += 1
        # cruzamento = nós cujo valor de entidade aparece ≥2x na janela
        shared = sum(c for c in vals.values() if c >= 2)
        if shared > best_score:
            best_score, best_off = shared, off
        off += step
    return {"from": best_off, "head": head, "shared": best_score}


def _correlate(db, lo, hi, limit, top=160, min_score=0.16):
    """Correlações ESTATÍSTICAS (record-linkage). Liga nós que partilham
    FEATURES RARAS — valores de atributos E tokens do conteúdo — ponderado por
    IDF (partilhar um sinal raro vale muito; um comum, nada). Descobre relações
    NÃO ÓBVIAS: mesma morada, mesmo valor invulgar, fragmento de nome partilhado,
    o mesmo representante — mesmo SEM CNPJ igual. É a deteção de anel para além
    do cruzamento literal."""
    rows = db.query(f"MATCH (n) WHERE n.lsn >= {int(lo)} AND n.lsn <= {int(hi)} RETURN n LIMIT {int(limit)}")
    rows = [r for r in (rows if isinstance(rows, list) else []) if r.get("id")]
    N = max(1, len(rows))
    STOP = {"base", "mes", "tipo", "chave", "ts", "ts_hlc", "generated_by",
            "session_id", "agent_id", "situacao", "vencedor_flag", "matricula"}
    tok_re = re.compile(r"[a-z0-9][a-z0-9./@_-]{4,}")

    def feats(r):
        f = set()
        a = r.get("attrs") or {}
        for k, v in a.items():
            if k in STOP:
                continue
            val = str(v).lower().strip()
            if val and val not in ("0", "-1", "nao", "não", "sim"):
                f.add(f"{k}={val}")
        for tok in set(tok_re.findall((r.get("content") or "").lower())):
            f.add("tok:" + tok)
        return f

    nodes = [{"id": r["id"], "kind": _clean_kind(r.get("kind")),
              "content": (r.get("content") or "")[:120], "lsn": r.get("lsn"),
              "attrs": r.get("attrs") or {}, "f": feats(r)} for r in rows]
    df = Counter()
    for n in nodes:
        for x in n["f"]:
            df[x] += 1
    cap = max(3, int(N * 0.10))  # ignora features quase-ubíquas (sem discriminação)
    inv = defaultdict(list)
    for i, n in enumerate(nodes):
        for x in n["f"]:
            if 2 <= df[x] <= cap:
                inv[x].append(i)

    def idf(x):
        return math.log((N + 1.0) / df.get(x, 1))

    pair = {}
    for x, mem in inv.items():
        if not (2 <= len(mem) <= 40):
            continue
        w = idf(x)
        for ii in range(len(mem)):
            for jj in range(ii + 1, len(mem)):
                pd = pair.setdefault((mem[ii], mem[jj]), {"w": 0.0, "f": []})
                pd["w"] += w
                pd["f"].append((x, w))

    sugg = []
    for (a, b), pd in pair.items():
        s = pd["w"] / (pd["w"] + 2.5)  # satura em 0..1
        if s < min_score:
            continue
        topf = [f for f, _ in sorted(pd["f"], key=lambda z: -z[1])[:3]]
        why = ", ".join(ff.replace("tok:", "“").replace("=", ": ") for ff in topf)
        sugg.append({"from": nodes[a]["id"], "to": nodes[b]["id"], "score": round(s, 2), "why": why})
    sugg.sort(key=lambda e: -e["score"])
    sugg = sugg[:top]
    used = {e["from"] for e in sugg} | {e["to"] for e in sugg}
    nl = [{"id": n["id"], "kind": n["kind"], "content": n["content"],
           "lsn": n["lsn"], "attrs": n["attrs"]} for n in nodes if n["id"] in used]
    return {"nodes": nl, "edges": sugg, "n": len(sugg)}


def _density(db, buckets=40, probe=140):
    """Minimapa da linha do tempo: amostra `buckets` pontos ao longo do log e
    conta nós-ENTIDADE por ponto — mostra ONDE estão os dados ricos (cruzamento)
    para a barra inferior virar um mapa navegável (como a do V2).

    As `buckets` queries são independentes (LSN-window pruning) — corremo-las em
    paralelo com um pool de threads (cada uma com a sua própria conexão), o que
    reduz ~12s sequenciais para ~2s."""
    head = db.head()
    if head < buckets:
        return {"head": head, "bins": []}
    step = max(1, head // buckets)

    def _probe(off):
        try:
            c = _client()
            rows = c.query(f"MATCH (n) WHERE n.lsn >= {off} AND n.lsn < {off+probe} RETURN n LIMIT {probe}")
        except Exception:
            rows = []
        rows = rows if isinstance(rows, list) else []
        ents = sum(1 for r in rows if _entity_of(r.get("attrs") or {}))
        kinds = Counter(_clean_kind(r.get("kind")) for r in rows)
        dom = kinds.most_common(1)[0][0] if kinds else ""
        return {"lsn": off, "n": len(rows), "ent": ents, "kind": dom}

    offs = [i * step for i in range(buckets)]
    with ThreadPoolExecutor(max_workers=10) as ex:
        bins = list(ex.map(_probe, offs))
    return {"head": head, "step": step, "bins": bins}


# campos de NOME (além dos identificadores) para a busca global
_NAME_KEYS = ["nome", "razao_social", "nome_favorecido", "nome_vencedor",
              "favorecido", "contratado", "fornecedor", "nome_orgao", "municipio"]


def _find(db, term, k=120):
    """Busca GLOBAL por CPF/CNPJ/nome/qualquer campo, resolvida pelo ÍNDICE
    secundário do motor (`MATCH ... WHERE n.<campo> = "v"` é O(postings), global,
    não um scan capado). Tenta os identificadores e os campos de nome; para nos
    identificadores assim que encontra (match exato)."""
    term = (term or "").strip()
    if not term:
        return {"hits": [], "n": 0}
    safe = term.replace("\\", "").replace('"', "")
    hits, via_id = [], False
    for key in ENTITY_KEYS + _NAME_KEYS:
        try:
            rows = db.query(f'MATCH (n) WHERE n.{key} = "{safe}" RETURN n LIMIT {k}')
        except Exception:  # noqa: BLE001
            rows = []
        for r in (rows if isinstance(rows, list) else []):
            if isinstance(r, dict) and r.get("lsn") is not None:
                hits.append({"id": r.get("id"), "lsn": r.get("lsn"), "via": key,
                             "content": (r.get("content") or "")[:80],
                             "kind": _clean_kind(r.get("kind"))})
        if hits and key in ENTITY_KEYS:
            via_id = True
            break
    seen, uniq = set(), []
    for h in sorted(hits, key=lambda x: -(x.get("lsn") or 0)):
        if h["id"] in seen:
            continue
        seen.add(h["id"])
        uniq.append(h)
    return {"hits": uniq, "n": len(uniq), "exact": via_id}


_PAGE = r"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Heraclitus Console V3 — Análise de Fraude</title>
<link href="https://fonts.googleapis.com/css2?family=Raleway:wght@400;600;700;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
<script src="vendor/vis-network.min.js"></script>
<script src="https://cdn.plot.ly/plotly-2.32.0.min.js"></script>
<style>
:root{ --bg:#fff; --panel2:#f4f7fc; --line:#dfe4ec; --line2:#c5cedb; --ink:#1c1c1c;
  --mut:#5a6677; --acc:#1351b4; --deep:#071d41; --yellow:#ffcd07; --ok:#168821; --bad:#e52207; }
*{box-sizing:border-box} html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--ink);font-family:'Raleway',system-ui,sans-serif;overflow:hidden}
.top{height:56px;display:flex;align-items:center;gap:12px;padding:0 18px;
  background:linear-gradient(90deg,var(--deep),var(--acc));border-bottom:3px solid var(--yellow);color:#fff}
.top b{font-size:1.05rem;font-weight:800} .top span{opacity:.85;font-size:.72rem}
.wrap{height:calc(100vh - 56px);display:grid;grid-template-columns:330px 1fr;grid-template-rows:1fr 124px;grid-template-areas:"side main" "side tl";transition:grid-template-columns .25s ease, grid-template-rows .25s ease}
.wrap>*{min-height:0}
.wrap.nosi{grid-template-columns:0 1fr}
.wrap.notl{grid-template-rows:1fr 0}
.topbtn{background:rgba(255,255,255,.15);color:#fff;border:1px solid rgba(255,255,255,.35);border-radius:6px;min-width:30px;height:28px;cursor:pointer;font-size:.82rem;padding:0 7px}
.topbtn:hover{background:rgba(255,255,255,.3)}
.reopen{position:fixed;z-index:30;background:var(--acc);color:#fff;border:0;border-radius:8px;width:34px;height:30px;cursor:pointer;display:none;box-shadow:0 2px 8px rgba(7,29,65,.22)}
.main{grid-area:main;position:relative;min-height:0;overflow:hidden}
.tlx{grid-area:tl;border-top:1px solid var(--line);background:var(--panel2);padding:6px 0 4px;display:flex;flex-direction:column;gap:3px;overflow:hidden}
.toolbar{position:absolute;top:8px;left:8px;z-index:6;display:flex;gap:6px;background:rgba(255,255,255,.93);padding:5px;border-radius:8px;border:1px solid var(--line);box-shadow:0 2px 8px rgba(7,29,65,.08)}
.toolbar button{padding:5px 11px;font-size:.74rem;border:1px solid var(--line2);background:#fff;border-radius:6px;cursor:pointer;font-weight:700}
.toolbar button.on{background:var(--acc);color:#fff;border-color:var(--acc)}
#plot3d,#mapview,#chordview{position:absolute;inset:0;display:none;background:#fff}
#e3d{position:absolute;top:8px;right:10px;z-index:7;display:none;padding:7px 13px;font-size:.76rem;
  font-weight:800;border:1px solid var(--acc);background:#fff;color:var(--acc);border-radius:8px;cursor:pointer;
  box-shadow:0 2px 8px rgba(7,29,65,.14)}
#e3d.on{background:var(--acc);color:#fff}
#chordview{padding:40px 8px 8px;text-align:center}
#dist{position:absolute;inset:0;display:none;background:#fff;padding:42px 8px 8px}
#tableview{position:absolute;inset:0;overflow:auto;display:none;background:#fff;padding:48px 12px 12px}
#tableview table{width:100%;border-collapse:collapse;font-size:.78rem}
#tableview th{position:sticky;top:0;background:#eef2fb;text-align:left;padding:6px 8px;cursor:pointer;border-bottom:2px solid var(--line2);user-select:none}
#tableview td{padding:5px 8px;border-bottom:1px solid var(--line)}
#tableview tr:hover td{background:#f4f7fc;cursor:pointer}
.cnpj{font-family:'JetBrains Mono',monospace;font-size:.72rem;color:#d4006a}
.tl-head{display:flex;justify-content:space-between;align-items:center;padding:0 14px;font-size:.66rem;color:var(--mut)}
.tl-head .ttl{font-weight:700}
.tl-right{display:flex;align-items:center;gap:8px}
.tl-scroll{flex:1;overflow-x:auto;overflow-y:hidden;min-height:0}
.tl-track{position:relative;height:100%;min-width:100%;padding:0 48px}
.tl-bar{position:absolute;left:0;right:0;top:50%;height:10px;transform:translateY(-50%);
  background:linear-gradient(90deg,var(--deep),var(--acc),#0095db,var(--ok));border-radius:6px;opacity:.5}
.winsel{position:absolute;top:50%;height:20px;transform:translateY(-50%);
  background:rgba(19,81,180,.16);border-left:2px solid var(--acc);border-right:2px solid var(--acc);
  pointer-events:none;z-index:1;border-radius:3px;transition:left .15s,width .15s}
.tl-row{position:absolute;inset:0;z-index:2}
.mk{position:absolute;top:50%;transform:translate(-50%,-50%);display:flex;flex-direction:column;align-items:center;cursor:pointer}
.mk.up{flex-direction:column-reverse}
.mk .meta{display:flex;flex-direction:column;align-items:center;gap:0;height:30px;justify-content:flex-end;margin-bottom:1px}
.mk.up .meta{justify-content:flex-start;margin-bottom:0;margin-top:1px}
.mk .yr{font-size:.72rem;font-weight:800;color:var(--ink);white-space:nowrap}
.mk .cnt{font-size:.58rem;color:var(--mut);font-weight:600;white-space:nowrap}
.mk .stem{width:2px;background:var(--line2);height:14px}
.mk .dot{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  font-size:.78rem;color:#fff;font-weight:800;box-shadow:0 3px 10px rgba(7,29,65,.32);
  border:2.5px solid var(--panel2);transition:.15s}
.mk:hover .dot{transform:scale(1.18);box-shadow:0 5px 14px rgba(7,29,65,.45)}
.mk.on .dot{border-color:var(--acc);box-shadow:0 0 0 3px rgba(19,81,180,.28)}
.axlegend{font-size:.62rem;color:var(--mut)}
.axlegend span{display:inline-flex;align-items:center;gap:3px;margin-left:8px}
.axlegend i{width:9px;height:9px;border-radius:50%;display:inline-block}
.side{background:#fff;border-right:1px solid var(--line);overflow-y:auto;padding:13px;display:flex;flex-direction:column;gap:12px}
.card{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:11px}
.card h3{margin:0 0 8px;font-size:.68rem;text-transform:uppercase;letter-spacing:.6px;color:var(--mut)}
label{font-size:.72rem;color:var(--mut);display:block;margin:6px 0 3px}
input,select{width:100%;padding:6px;border:1px solid var(--line2);border-radius:6px;font-size:.8rem;background:#fff}
input[type=range]{padding:0}
.btn{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:7px 9px;font-size:.76rem;font-weight:700;cursor:pointer}
.btn:hover{background:var(--deep)} .btn.sec{background:#fff;color:var(--acc);border:1px solid var(--acc)}
.row{display:flex;gap:6px} .row .btn{flex:1}
.toggle{display:flex;gap:4px;margin-top:6px} .toggle button{flex:1;padding:5px;font-size:.72rem;border:1px solid var(--line2);background:#fff;border-radius:6px;cursor:pointer}
.toggle button.on{background:var(--acc);color:#fff;border-color:var(--acc)}
.legend{display:flex;flex-direction:column;gap:3px;max-height:260px;overflow:auto}
.lg{display:flex;align-items:center;gap:7px;font-size:.75rem;cursor:pointer;padding:2px 4px;border-radius:5px}
.lg:hover{background:#e7eefb} .lg .dot{width:11px;height:11px;border-radius:3px;flex:none}
.lg .ct{margin-left:auto;color:var(--mut);font-variant-numeric:tabular-nums}
.stat{display:flex;justify-content:space-between;font-size:.8rem;padding:1px 0} .stat b{font-weight:800;color:var(--acc)}
.stat.bad b{color:var(--bad)}
#graph{width:100%;height:100%} .hint{font-size:.71rem;color:var(--mut);line-height:1.35}
.drawer{position:fixed;right:0;top:56px;bottom:0;width:350px;background:#fff;border-left:1px solid var(--line2);
  box-shadow:-8px 0 24px rgba(7,29,65,.1);transform:translateX(100%);transition:.2s;overflow:auto;padding:16px;z-index:9}
.drawer.open{transform:none}
.drawer .k{font-size:.68rem;color:var(--mut);text-transform:uppercase;letter-spacing:.5px;margin-top:10px}
.drawer .v{font-size:.82rem;word-break:break-word} .mono{font-family:'JetBrains Mono',monospace;font-size:.72rem}
.x{float:right;cursor:pointer;color:var(--mut);font-size:1.1rem}
.tl{position:relative;margin:2px 0} .tlbar{height:6px;background:#dfe4ec;border-radius:3px}
.tlfill{position:absolute;top:0;height:6px;background:var(--acc);border-radius:3px}
.busy{position:absolute;inset:0;display:none;align-items:center;justify-content:center;background:rgba(255,255,255,.75);font-weight:700;color:var(--acc);z-index:5}
.pill{display:inline-block;font-size:.66rem;padding:1px 6px;border-radius:9px;background:#e7eefb;color:var(--acc);font-weight:700}
.seal{font-size:.7rem;font-weight:700;padding:3px 9px;border-radius:7px;margin-right:8px;cursor:default;
  background:rgba(255,255,255,.16);color:#fff;border:1px solid rgba(255,255,255,.32);white-space:nowrap}
.seal.ok{background:rgba(22,136,33,.9);border-color:#fff}
.seal.cov{box-shadow:0 0 0 2px var(--yellow)}
.seal.off{opacity:.65}
</style></head><body>
<div class="top"><b>⬡ Heraclitus — Análise de Fraude</b>
  <span>cruzamento por entidade · grupos · on-demand</span><div style="flex:1"></div>
  <span id="seal" class="seal off" title="Carimbo de tempo RFC 3161 (heraclitus-compliance)">🔓 sem carimbo</span>
  <span id="headlbl" style="margin-right:8px">head —</span>
  <button id="tgside" class="topbtn" title="Recolher/expandir painel lateral">◀</button>
  <button id="tgfull" class="topbtn" title="Tela cheia do grafo (recolhe os painéis)">⛶</button></div>
<button id="reopenside" class="reopen" style="left:8px;top:64px" title="Abrir painel lateral">▶</button>
<button id="reopentl" class="reopen" style="right:14px;bottom:8px" title="Abrir linha do tempo">▲</button>
<div class="wrap" id="wrap">
  <aside class="side">
    <button id="hideside" class="btn sec" style="display:flex;align-items:center;justify-content:center;gap:6px">◀ Ocultar painel</button>
    <div class="card">
      <h3>Janela de tempo (LSN)</h3>
      <div class="tl"><div class="tlbar"></div><div class="tlfill" id="tlfill"></div></div>
      <label>Início: <b id="fromlbl">0</b></label>
      <input type="range" id="fromSlider" min="0" max="100" value="100">
      <label>Tamanho</label>
      <select id="size"><option value="500" selected>500</option><option value="1500">1.500</option>
        <option value="4000">4.000</option><option value="8000">8.000</option></select>
      <div class="row" style="margin-top:8px">
        <button class="btn" id="recent">⏭ Recente</button>
        <button class="btn sec" id="origins">⬅ Origens</button>
      </div>
    </div>
    <div class="card">
      <h3>Cruzar / Procurar (CNPJ, nome…)</h3>
      <input id="focus" placeholder="ex.: 90888777000122 ou Omega">
      <div class="row" style="margin-top:6px"><button class="btn" id="findbtn" title="Busca GLOBAL por CPF/CNPJ/nome/qualquer campo via índice do motor (todo o log)">🔎 Buscar (todo o log)</button></div>
      <div class="hint" id="fochint" style="margin-top:5px"></div>
    </div>
    <div class="card">
      <h3>Cor do grafo</h3>
      <div class="toggle"><button id="cgroup" class="on">por GRUPO (anel)</button><button id="ckind">por TIPO</button></div>
      <label style="margin-top:8px;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="onlyconn" checked style="width:auto">só ligados (mostra a rede/anéis, esconde nós isolados)</label>
      <label style="margin-top:6px">Filtro por tipo</label>
      <select id="kind"><option value="">(todos)</option></select>
    </div>
    <div class="card">
      <h3>Resumo da janela</h3>
      <div class="stat">Nós <b id="snodes">—</b></div>
      <div class="stat">Arestas <b id="sedges">—</b></div>
      <div class="stat">Ligações por entidade (cruzamento) <b id="sshared">—</b></div>
      <div class="stat"><span style="color:#7a3cff">Leads RESOLVE (CPF+nome)</span> <b id="sresolve" style="color:#7a3cff">—</b></div>
      <div class="stat bad"><span style="color:#d40000">⚠ Alertas compliance</span> <b id="salerta" style="color:#d40000">—</b></div>
      <div class="stat bad">Grupos / anéis (>1 nó) <b id="sgroups">—</b></div>
      <h3 id="lgttl" style="margin-top:10px">Maiores grupos</h3>
      <div class="legend" id="legend"></div>
    </div>
    <div class="card hint">
      <b>Cruzamento:</b> nós que partilham o mesmo CNPJ/código (empresa) ficam
      ligados — uma empresa que aparece numa licitação, numa compra e numa
      transferência forma um <b>grupo</b>. Linhas tracejadas = mesma entidade;
      sólidas = proveniência. Clica num nó para detalhes. <b>Origens</b> alarga a
      janela para trás. Nunca carrega tudo.
    </div>
  </aside>
  <div class="main">
    <div class="toolbar">
      <button id="vrede" class="on">🕸 Rede (cruzamento)</button>
      <button id="vcorr">🔮 Correlações</button>
      <button id="vmap">🗺 Mapa</button>
      <button id="vchord">🌀 Cordas</button>
      <button id="v3d">🧊 3D</button>
      <button id="vtab">📋 Tabela</button>
      <button id="vfit">⤢ Ajustar</button>
    </div>
    <div id="graph"></div>
    <div id="plot3d"></div>
    <button id="e3d" title="Desenhar as ligações (cruzamento/proveniência) dentro do 3D">🕸 Gerar grafo 3D</button>
    <div id="mapview"></div>
    <div id="chordview"></div>
    <div id="tableview"></div>
    <div class="busy" id="busy">a analisar…</div>
  </div>
  <div class="tlx" id="tlx">
    <div class="tl-head">
      <span class="ttl">⏳ Linha do tempo · LSN 0 → <b id="axhead">—</b> · clica num período para navegar</span>
      <span class="tl-right"><span class="axlegend" id="axlegend"></span><span id="axwin"></span><button id="tgtl" class="topbtn" style="background:#fff;color:#5a6677;border-color:var(--line2)" title="Recolher linha do tempo">▼</button></span>
    </div>
    <div class="tl-scroll" id="tlscroll">
      <div class="tl-track" id="tltrack">
        <div class="tl-bar"></div>
        <div class="winsel" id="winsel"></div>
        <div class="tl-row" id="tlrow"></div>
      </div>
    </div>
  </div>
</div>
<div class="drawer" id="drawer"><span class="x" id="dx">✕</span><div id="dbody"></div></div>
<script>
var HEAD=0, FROM=0, SIZE=500, COLOR='group', VIEW='rede', network=null, LAST={}, CORR={}, SEAL=null;
var KP=['#1351b4','#e52207','#168821','#c47000','#7e3ff2','#0095db','#d4006a','#00803b','#b35900','#5b6770'];
var ICON={licitacao:'⚖',licitacoes:'⚖',compra:'🛒',compras:'🛒',contrato:'📜',contratos:'📜',fornecedor:'🏢',vencedor:'🏆',cod_vencedor:'🏆',favorecido:'💰',cod_favorecido:'💰',despesa:'💸',despesas:'💸',empenho:'🧾',empenhos:'🧾',servidor:'👤',servidores:'👤',pessoa:'👤',orgao:'🏛',sancao:'🚫',sancoes:'🚫'};
function bicon(k){ return ICON[(k||'').toLowerCase()]||'•'; }
function bnum(n){ n=+n||0; if(n>=1e6) return (n/1e6).toFixed(n>=1e7?0:1).replace('.0','')+'M'; if(n>=1e3) return Math.round(n/1e3)+'k'; return ''+n; }
var kc={}, ki=0;
function kcolor(k){ if(!(k in kc)){ kc[k]=KP[ki%KP.length]; ki++; } return kc[k]; }
function gcolor(g){ if(!g) return '#b9c2d0'; return KP[(g*7)%KP.length]; }
function el(i){return document.getElementById(i);}
function post(p,b){return fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}).then(r=>r.json());}
function esc(s){return (s==null?'':''+s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

var nodes=new vis.DataSet(), edges=new vis.DataSet();
window.addEventListener('load', async function(){
  var j=await (await fetch('head')).json(); HEAD=j.head||0;
  el('headlbl').textContent='head LSN '+HEAD.toLocaleString('pt-BR');
  el('axhead').textContent=HEAD.toLocaleString('pt-BR');
  el('fromSlider').max=HEAD;
  loadDensity();   // barra inferior em paralelo — NÃO bloqueia o desenho do grafo
  loadSeal();      // selo de carimbo de tempo (compliance) — não bloqueia
  network=new vis.Network(el('graph'),{nodes:nodes,edges:edges},{
    nodes:{shape:'dot',size:12,font:{size:11,face:'Raleway'}},
    edges:{smooth:{type:'continuous'}},
    physics:{stabilization:{enabled:true,iterations:90,fit:true},
             barnesHut:{springLength:110,gravitationalConstant:-3200},maxVelocity:30,minVelocity:2},
    interaction:{hover:true,tooltipDelay:120}
  });
  network.on('click',function(p){ if(p.nodes.length) showNode(p.nodes[0]); });
  // arranca na regiao mais rica (nomes/CNPJ/ligacoes), nao na cauda (Observacoes)
  el('busy').style.display='flex';
  try{ var bj=await (await fetch('best')).json(); FROM=Math.max(0,(bj.from||0)); }
  catch(e){ FROM=Math.max(0,HEAD-SIZE); }
  await load();    // análise da janela (mais pesada)
});
var BINS=[];
async function loadDensity(){
  for(var attempt=0; attempt<3; attempt++){
    try{
      var d=await (await fetch('density')).json();
      var bins=(d.bins||[]).filter(b=>b.n);
      if(!bins.length){ await new Promise(r=>setTimeout(r,600)); continue; }
      BINS=bins;
      el('axhead').textContent=Number(HEAD).toLocaleString('pt-BR');
      renderTimeline(); paintWinsel();
      return;
    }catch(e){ console.error('loadDensity tentativa '+attempt+':', e); await new Promise(r=>setTimeout(r,600)); }
  }
}
function renderTimeline(){
  var row=el('tlrow'), track=el('tltrack'); if(!row) return;
  // largura do trilho: espaço suficiente p/ rótulos não colidirem (scroll horizontal)
  var sc=el('tlscroll'); var wide=Math.max(sc?sc.clientWidth:900, BINS.length*86+96);
  track.style.width=wide+'px';
  var max=Math.max(1, Math.max.apply(null, BINS.map(b=>b.n||0)));
  var seen={}, html='';
  BINS.forEach(function(b,i){
    var up=(i%2===0); var k=b.kind||'?'; var col=kcolor(k); seen[k]=1;
    var sz=(16+18*Math.sqrt((b.n||0)/max)).toFixed(0);
    var left=(100*b.lsn/Math.max(HEAD,1));
    html+='<div class="mk '+(up?'up':'down')+'" data-lsn="'+b.lsn+'" data-i="'+i+'" '+
      'title="'+esc(b.n+' nós · '+b.ent+' entidades · '+k+' · ~LSN '+Number(b.lsn).toLocaleString("pt-BR"))+'" '+
      'style="left:'+left+'%">'+
      '<div class="meta"><div class="yr">'+esc(k)+'</div><div class="cnt">'+bnum(b.n)+' nós · '+bnum(b.ent)+' ent</div></div>'+
      '<div class="stem"></div>'+
      '<div class="dot" style="background:'+col+';width:'+sz+'px;height:'+sz+'px">'+bicon(k)+'</div>'+
    '</div>';
  });
  row.innerHTML=html;
  Array.prototype.forEach.call(row.children,function(m){
    m.onclick=function(){ FROM=Math.max(0,Math.min(Math.max(0,HEAD-SIZE),+m.getAttribute('data-lsn'))); load(); };
  });
  var L=el('axlegend'); L.innerHTML='';
  Object.keys(seen).filter(k=>k&&k!=='?').slice(0,8).forEach(function(k){ L.innerHTML+='<span><i style="background:'+kcolor(k)+'"></i>'+esc(k)+'</span>'; });
  paintWinsel();
}
function paintWinsel(){
  var hi=Math.min(HEAD,FROM+SIZE);
  var pl=(100*FROM/Math.max(HEAD,1)), pw=Math.max(.6,100*(hi-FROM)/Math.max(HEAD,1));
  var ws=el('winsel'); if(ws){ ws.style.left=pl+'%'; ws.style.width=pw+'%'; }
  var row=el('tlrow'); if(row) Array.prototype.forEach.call(row.children,function(m){
    var l=+m.getAttribute('data-lsn'); m.classList.toggle('on', l>=FROM && l<=hi);
  });
}
// SELO DE CARIMBO DE TEMPO (compliance / RFC 3161): mostra o último estado
// ancorado e se a janela atual já está coberta pela prova forense.
async function loadSeal(){ try{ SEAL=await (await fetch('compliance')).json(); }catch(e){ SEAL=null; } paintSeal(); }
function paintSeal(){
  var s=el('seal'); if(!s) return;
  if(!SEAL || !SEAL.anchored){
    s.className='seal off'; s.textContent='🔓 sem carimbo';
    s.title='Daemon de compliance desligado — sem recibos RFC 3161.\\nLigar no servidor: HERACLITUS_COMPLIANCE=1 (recibos em <data_dir>/receipts).';
    return;
  }
  var hi=Math.min(HEAD,FROM+SIZE);
  var covered=(SEAL.lsn!=null && hi<=SEAL.lsn);
  var dt=SEAL.gen_unix_ms?new Date(SEAL.gen_unix_ms).toLocaleString('pt-BR'):'';
  s.className='seal ok'+(covered?' cov':'');
  s.textContent='🔒 LSN '+Number(SEAL.lsn||0).toLocaleString('pt-BR')+(covered?' · janela coberta':'');
  s.title='Carimbo de tempo RFC 3161 · ACT '+(SEAL.policy||'?')+' · '+dt+' · '+(SEAL.count||0)+' recibo(s)'
    +(covered?('\\nEsta janela (até LSN '+hi+') está DENTRO do estado carimbado — prova forense aplicável.')
             :('\\nEsta janela (até LSN '+hi+') ainda NÃO está coberta pelo último carimbo (LSN '+SEAL.lsn+').'));
}
el('size').onchange=function(){ SIZE=+this.value; FROM=Math.min(FROM,Math.max(0,HEAD-SIZE)); load(); };
el('fromSlider').oninput=function(){ FROM=+this.value; el('fromlbl').textContent=FROM.toLocaleString('pt-BR'); };
el('fromSlider').onchange=load;
el('recent').onclick=function(){ FROM=Math.max(0,HEAD-SIZE); load(); };
el('origins').onclick=function(){ FROM=Math.max(0,FROM-SIZE*4); load(); };
el('kind').onchange=load;
var _ft=null; el('focus').oninput=function(){ clearTimeout(_ft); _ft=setTimeout(load,400); };
// BUSCA GLOBAL por índice (motor): CPF/CNPJ/nome/qualquer campo em TODO o log.
async function findGlobal(){
  var term=el('focus').value.trim();
  if(!term){ load(); return; }
  var fh=el('fochint'); fh.innerHTML='<span style="color:var(--acc)">🔎 a procurar em todo o log…</span>';
  el('busy').style.display='flex';
  var j; try{ j=await post('find',{term:term}); }catch(e){ fh.textContent='falha: '+e.message; el('busy').style.display='none'; return; }
  el('busy').style.display='none';
  var hits=j.hits||[];
  if(!hits.length){ fh.innerHTML='<span style="color:var(--bad)">0 ocorrências para “'+esc(term)+'” (qualquer campo).</span>'; return; }
  var lsn=hits[0].lsn||0;
  FROM=Math.max(0,Math.min(Math.max(0,HEAD-SIZE), lsn-Math.floor(SIZE/2)));
  await load();
  fh.innerHTML='🔎 <b>'+hits.length+'</b> ocorrência(s) em todo o log'+(j.exact?' (por identificador)':'')
    +' · saltei para a 1ª (LSN '+Number(lsn).toLocaleString('pt-BR')+'). '+((LAST.nodes||[]).filter(n=>n.hit).length)+' realçada(s) aqui.';
}
el('findbtn').onclick=findGlobal;
el('focus').addEventListener('keydown',function(e){ if(e.key==='Enter'){ e.preventDefault(); findGlobal(); } });
// #1 CACHE de /correlate por janela — Correlações e Cordas partilham o mesmo
// cálculo (caro: O(features × mem²)); não recomputar ao trocar de vista.
var CORRCACHE={};
async function getCorrelate(from,hi,size){
  var key=from+'|'+hi+'|'+size;
  if(CORRCACHE[key]) return CORRCACHE[key];
  var j=await post('correlate',{from:from,to:hi,limit:size});
  CORRCACHE[key]=j;
  var ks=Object.keys(CORRCACHE); if(ks.length>12) delete CORRCACHE[ks[0]];
  return j;
}
el('onlyconn').onchange=function(){ render(LAST); };
el('cgroup').onclick=function(){ COLOR='group'; el('cgroup').classList.add('on'); el('ckind').classList.remove('on'); paint(); };
el('ckind').onclick=function(){ COLOR='kind'; el('ckind').classList.add('on'); el('cgroup').classList.remove('on'); paint(); };
el('dx').onclick=function(){ el('drawer').classList.remove('open'); };
// recolher / minimizar painéis (lateral, linha do tempo, tela cheia)
function resizeViews(){ setTimeout(function(){ try{network.fit();}catch(e){}
  try{ if(VIEW==='3d')Plotly.Plots.resize('plot3d'); if(VIEW==='map')Plotly.Plots.resize('mapview'); }catch(e){}
  try{ if(BINS.length) renderTimeline(); }catch(e){} },300); }
window.addEventListener('resize', function(){ try{ if(BINS.length) renderTimeline(); }catch(e){} });
function setSide(collapsed){ el('wrap').classList.toggle('nosi',collapsed);
  el('tgside').textContent=collapsed?'▶':'◀'; el('reopenside').style.display=collapsed?'block':'none'; resizeViews(); }
el('tgside').onclick=function(){ setSide(!el('wrap').classList.contains('nosi')); };
el('hideside').onclick=function(){ setSide(true); };
el('reopenside').onclick=function(){ setSide(false); };
el('tgtl').onclick=function(){ var c=el('wrap').classList.toggle('notl'); el('reopentl').style.display=c?'block':'none'; resizeViews(); };
el('reopentl').onclick=function(){ el('wrap').classList.remove('notl'); this.style.display='none'; resizeViews(); };
el('tgfull').onclick=function(){ var w=el('wrap'); var full=!(w.classList.contains('nosi')&&w.classList.contains('notl'));
  w.classList.toggle('nosi',full); w.classList.toggle('notl',full);
  el('tgside').textContent=full?'▶':'◀'; el('reopenside').style.display=full?'block':'none'; el('reopentl').style.display=full?'block':'none'; resizeViews(); };
// barra de ferramentas: vistas
el('vrede').onclick=function(){ setView('rede'); };
el('vcorr').onclick=function(){ setView('corr'); };
el('vmap').onclick=function(){ setView('map'); };
el('vchord').onclick=function(){ setView('chord'); };
el('v3d').onclick=function(){ setView('3d'); };
el('vtab').onclick=function(){ setView('tab'); };
el('vfit').onclick=function(){ try{network.fit({animation:true});}catch(e){} };
var EDGES3D=false;
el('e3d').onclick=function(){ EDGES3D=!EDGES3D; this.classList.toggle('on',EDGES3D);
  this.textContent=EDGES3D?'🕸 Ligações ON':'🕸 Gerar grafo 3D'; render3d(); };
function setView(v){
  VIEW=v;
  [['vrede','rede'],['vcorr','corr'],['vmap','map'],['vchord','chord'],['v3d','3d'],['vtab','tab']].forEach(function(p){ el(p[0]).classList.toggle('on',v===p[1]); });
  var gv=(v==='rede'||v==='corr');
  el('vfit').style.display = gv?'':'none';
  el('graph').style.display = gv?'block':'none';
  el('plot3d').style.display = v==='3d'?'block':'none';
  el('e3d').style.display = v==='3d'?'block':'none';
  el('mapview').style.display = v==='map'?'block':'none';
  el('chordview').style.display = v==='chord'?'block':'none';
  el('tableview').style.display = v==='tab'?'block':'none';
  if(v==='tab') renderTable();
  else if(v==='3d') render3d();
  else if(v==='map') renderMap();
  else if(v==='chord') renderChord();
  else if(v==='corr') renderCorr();
  else { render(LAST); }   // rede: restaura as arestas de cruzamento+proveniência
}
// VISTA CORDAS — diagrama circular (chord): top entidades em círculo, fitas =
// relações (cruzamento+proveniência), largura ∝ nº de ligações partilhadas.
async function renderChord(){
  el('busy').style.display='flex';
  // usa as CORRELAÇÕES (entidade<->entidade) — é o que tem ligações reais entre
  // nós (o cruzamento é hub->folha e não daria fitas).
  var hi=Math.min(HEAD,FROM+SIZE);
  var j; try{ j=await getCorrelate(FROM,hi,SIZE); }
  catch(e){ el('busy').style.display='none'; return; }
  var es=j.edges||[], byId={}; (j.nodes||[]).forEach(function(n){ byId[n.id]=n; });
  var deg={}; es.forEach(function(e){ deg[e.from]=(deg[e.from]||0)+1; deg[e.to]=(deg[e.to]||0)+1; });
  var top=Object.keys(deg).sort(function(a,b){return deg[b]-deg[a];}).slice(0,28)
            .map(function(id){return byId[id];}).filter(Boolean);
  var idx={}; top.forEach(function(n,i){ idx[n.id]=i; });
  var K=top.length;
  if(K<2){ el('chordview').innerHTML='<div class="hint" style="padding:60px">Sem correlações suficientes nesta janela para o diagrama. Usa uma janela maior (ex.: 4.000/8.000) ou outra região (barra de baixo).</div>'; el('busy').style.display='none'; return; }
  var W=920,H=660,cx=W/2,cy=H/2,R=Math.min(W,H)/2-145;
  function pt(i){ var a=(i/K)*2*Math.PI - Math.PI/2; return [cx+R*Math.cos(a), cy+R*Math.sin(a), a]; }
  var svg='<svg viewBox="0 0 '+W+' '+H+'" width="100%" height="100%" style="max-height:100%" font-family="Raleway">';
  var nrib=0;
  es.forEach(function(e){ var i=idx[e.from], jj=idx[e.to]; if(i==null||jj==null||i===jj) return;
    var A=pt(i),B=pt(jj); var col=KP[(i*3)%KP.length]; var w=(0.6+(e.score||0)*5);
    svg+='<path d="M'+A[0].toFixed(1)+' '+A[1].toFixed(1)+' Q'+cx+' '+cy+' '+B[0].toFixed(1)+' '+B[1].toFixed(1)+'" fill="none" stroke="'+col+'" stroke-width="'+w.toFixed(1)+'" stroke-opacity="0.42" stroke-linecap="round"><title>'+esc((e.score||0)+' · '+(e.why||''))+'</title></path>'; nrib++;
  });
  top.forEach(function(n,i){ var P=pt(i); var col=kcolor(n.kind);
    svg+='<circle cx="'+P[0].toFixed(1)+'" cy="'+P[1].toFixed(1)+'" r="7" fill="'+col+'" stroke="#fff" stroke-width="1.5"/>';
    var right=(P[0]>=cx); var lx=cx+(R+14)*Math.cos(P[2]), ly=cy+(R+14)*Math.sin(P[2]);
    var nm=(n.content||n.kind); if(nm.length>20) nm=nm.slice(0,19)+'…';
    svg+='<text x="'+lx.toFixed(1)+'" y="'+(ly+3).toFixed(1)+'" font-size="10.5" text-anchor="'+(right?'start':'end')+'" fill="#1c1c1c">'+esc(nm)+'</text>';
  });
  svg+='</svg>';
  el('chordview').innerHTML=svg;
  el('snodes').textContent=K+' (top)'; el('sedges').textContent=nrib+' fitas (correlações)';
  el('busy').style.display='none';
}
// centroides aproximados das 27 UFs (lat,lon) para espalhar as entidades no Brasil
var UFLL={AC:[-9.0,-70.0],AL:[-9.6,-36.6],AP:[1.0,-52.0],AM:[-3.9,-65.0],BA:[-12.5,-41.7],
  CE:[-5.2,-39.6],DF:[-15.8,-47.9],ES:[-19.6,-40.7],GO:[-15.9,-49.6],MA:[-5.0,-45.3],
  MT:[-12.6,-56.0],MS:[-20.5,-54.8],MG:[-18.5,-44.5],PA:[-3.8,-52.5],PB:[-7.1,-36.8],
  PR:[-24.5,-51.5],PE:[-8.4,-37.9],PI:[-7.3,-42.5],RJ:[-22.2,-42.7],RN:[-5.8,-36.6],
  RS:[-30.0,-53.5],RO:[-10.8,-63.0],RR:[2.0,-61.4],SC:[-27.2,-50.5],SP:[-22.2,-48.7],
  SE:[-10.6,-37.4],TO:[-10.2,-48.3]};
// nome do estado -> UF (fallback quando os dados trazem `estado` por extenso)
var NOME2UF={'acre':'AC','alagoas':'AL','amapa':'AP','amazonas':'AM','bahia':'BA',
  'ceara':'CE','distrito federal':'DF','espirito santo':'ES','goias':'GO','maranhao':'MA',
  'mato grosso':'MT','mato grosso do sul':'MS','minas gerais':'MG','para':'PA','paraiba':'PB',
  'parana':'PR','pernambuco':'PE','piaui':'PI','rio de janeiro':'RJ','rio grande do norte':'RN',
  'rio grande do sul':'RS','rondonia':'RO','roraima':'RR','santa catarina':'SC','sao paulo':'SP',
  'sergipe':'SE','tocantins':'TO'};
function _norm(s){ return (''+s).toLowerCase().trim()
  .replace(/[áàâã]/g,'a').replace(/[éê]/g,'e').replace(/í/g,'i').replace(/[óôõ]/g,'o').replace(/[úü]/g,'u').replace(/ç/g,'c'); }
// extrai a UF de um nó tentando várias chaves (sigla ou nome por extenso)
function ufOf(a){
  var keys=['uf','sigla_uf','sg_uf','uf_favorecido','uf_vencedor','uf_ug','uf_orgao','estado'];
  for(var i=0;i<keys.length;i++){ var v=a[keys[i]]; if(v==null||v==='') continue;
    var sig=(''+v).toUpperCase().trim(); if(UFLL[sig]) return sig;
    var nm=_norm(v); if(NOME2UF[nm]) return NOME2UF[nm];
  }
  return null;
}
// VISTA MAPA — espalha as entidades sobre o Brasil pela UF (estado)
function renderMap(){
  var ns=_connFilter((LAST.nodes||[]).slice());
  var pos={}, lat=[],lon=[],cs=[],tx=[]; var perUF={};
  function shash(str){ var h=2166136261; for(var i=0;i<str.length;i++){ h=Math.imul(h^str.charCodeAt(i),16777619); } return h>>>0; }
  function jit(seed,k,amp){ var h=(((seed>>>0)*2654435761)>>>0)^(k*40503); return ((h&255)/255-.5)*amp; }
  ns.forEach(function(n){ var a=n.attrs||{}; var uf=ufOf(a); var ll=uf?UFLL[uf]:null; if(!ll) return;
    // #2 agrupa por MUNICÍPIO: mesmo município -> mesmo ponto (+ micro-nuvem por nó)
    var mun=((a.municipio||a.municipio_favorecido||a.nome_municipio||'')+'').trim();
    var seed = mun?shash(uf+'|'+mun):(n.lsn>>>0);
    var la=ll[0]+jit(seed,1,3.0)+jit(n.lsn,3,0.45), lo=ll[1]+jit(seed,2,3.0)+jit(n.lsn,4,0.45);
    pos[n.id]=[la,lo]; perUF[uf]=(perUF[uf]||0)+1;
    lat.push(la); lon.push(lo);
    cs.push(COLOR==='group'?gcolor(n.group):kcolor(n.kind));
    tx.push((n.content||n.kind)+'<br>'+((a.municipio||'')+' / '+uf)+'<br>'+(a.cpf||n.ent||''));
  });
  // GRAFO SOBRE O MAPA: liga geograficamente as entidades relacionadas
  var elat=[],elon=[], nlinks=0;
  (LAST.edges||[]).forEach(function(e){ var A=pos[e.from], B=pos[e.to];
    if(A&&B){ elat.push(A[0],B[0],null); elon.push(A[1],B[1],null); nlinks++; } });
  var miss=ns.length-lat.length;
  var traces=[];
  if(elat.length) traces.push({type:'scattergeo',mode:'lines',lat:elat,lon:elon,
    line:{width:0.7,color:'rgba(126,63,242,0.4)'},hoverinfo:'skip',name:'relações'});
  traces.push({type:'scattergeo',mode:'markers',lat:lat,lon:lon,text:tx,hoverinfo:'text',
    marker:{size:6,color:cs,opacity:.85,line:{width:.3,color:'#fff'}},name:'entidades'});
  var empty=(lat.length===0);
  Plotly.react('mapview',traces,
    {title:'Relações no mapa · '+lat.length+' entidades / '+nlinks+' ligações'+(miss>0?(' · '+miss+' sem UF'):''),
     annotations: empty?[{text:'Nenhuma entidade com UF nesta janela ('+ns.length+' nós sem geolocalização).<br>O mapa precisa de <b>uf</b>/<b>estado</b> nos atributos — tenta outra janela ou a vista Rede.',
       showarrow:false,xref:'paper',yref:'paper',x:0.5,y:0.5,font:{size:13,color:'#e52207'},align:'center'}]:[],
     margin:{t:34,b:0,l:0,r:0},paper_bgcolor:'#fff',showlegend:false,
     geo:{scope:'south america',center:{lat:-14,lon:-53},projection:{type:'mercator'},
       showland:true,landcolor:'#eef3fa',showcountries:true,countrycolor:'#9fb3d6',
       coastlinecolor:'#9fb3d6',bgcolor:'#fff',lataxis:{range:[-34,7]},lonaxis:{range:[-75,-32]}}},
    {responsive:true,displayModeBar:false});
  var L=el('legend'); L.innerHTML=''; el('lgttl').textContent='Por estado (UF)';
  Object.entries(perUF).sort((a,b)=>b[1]-a[1]).forEach(function(u){
    var d=document.createElement('div'); d.className='lg';
    d.innerHTML='<span class="dot" style="background:var(--acc)"></span>'+u[0]+'<span class="ct">'+u[1]+'</span>';
    L.appendChild(d);
  });
}
function _connFilter(ns){
  if(!el('onlyconn').checked) return ns;
  var conn=new Set(); (LAST.edges||[]).forEach(e=>{conn.add(e.from);conn.add(e.to);});
  return ns.filter(n=>conn.has(n.id)||n.hit);
}
// VISTA 3D — nuvem cartesiana, grupos como clusters 3D
function render3d(){
  var ns=_connFilter((LAST.nodes||[]).slice());
  function ctr(g){ var h=((g*2654435761)>>>0); return [((h&255)/255-.5)*12,(((h>>8)&255)/255-.5)*12,(((h>>16)&255)/255-.5)*12]; }
  function jit(s,k){ var h=(((s>>>0)*2654435761)>>>0)^(k*40503); return ((h&255)/255-.5)*1.6; }
  var xs=[],ys=[],zs=[],cs=[],tx=[], pos={};
  ns.forEach(function(n){ var c=ctr(n.group); var na=n.attrs||{};
    var x=c[0]+jit(n.lsn,1), y=c[1]+jit(n.lsn,2), z=c[2]+jit(n.lsn,3);
    pos[n.id]=[x,y,z];
    xs.push(x); ys.push(y); zs.push(z);
    cs.push(COLOR==='group'?gcolor(n.group):kcolor(n.kind));
    tx.push((n.content||n.kind)+'<br>'+(na.cpf||n.ent||'')+' · grupo '+n.group);
  });
  var traces=[{type:'scatter3d',mode:'markers',x:xs,y:ys,z:zs,text:tx,hoverinfo:'text',name:'nós',
    marker:{size:4,color:cs,opacity:.85,line:{width:0}}}];
  var title='Nuvem 3D · grupos como clusters ('+ns.length+' nós)';
  if(EDGES3D){
    // desenha as ligações reais (cruzamento por entidade + proveniência) DENTRO do 3D
    var sh={x:[],y:[],z:[]}, pv={x:[],y:[],z:[]}, ne=0;
    (LAST.edges||[]).forEach(function(e){
      var a=pos[e.from], b=pos[e.to]; if(!a||!b) return; ne++;
      var t=(e.type==='shared')?sh:pv;
      t.x.push(a[0],b[0],null); t.y.push(a[1],b[1],null); t.z.push(a[2],b[2],null);
    });
    traces.push({type:'scatter3d',mode:'lines',x:sh.x,y:sh.y,z:sh.z,name:'cruzamento (mesma entidade)',
      line:{color:'#d4006a',width:2.5},opacity:.55,hoverinfo:'none'});
    traces.push({type:'scatter3d',mode:'lines',x:pv.x,y:pv.y,z:pv.z,name:'proveniência',
      line:{color:'#1351b4',width:1.6},opacity:.4,hoverinfo:'none'});
    title='Grafo 3D · '+ne+' ligações entre '+ns.length+' nós (rosa = mesma entidade · azul = proveniência)';
  }
  Plotly.react('plot3d',traces,
    {margin:{l:0,r:0,t:34,b:0},title:title,showlegend:EDGES3D,legend:{x:0,y:1,font:{size:10}},
     paper_bgcolor:'#fff',scene:{xaxis:{title:'',showspikes:false},yaxis:{title:''},zaxis:{title:''}}},
    {responsive:true,displayModeBar:false});
}
// VISTA CORRELAÇÕES — gráfico de correlação ESTATÍSTICA (record-linkage por IDF).
// Liga nós por features RARAS partilhadas (atributos + tokens do conteúdo), NAO
// so' cpf=cpf. Espessura/cor da aresta = score; hover/legenda = o "porquê".
function corrById(id){ return (CORR.nodes||[]).find(x=>x.id===id); }
async function renderCorr(){
  el('busy').style.display='flex';
  var hi=Math.min(HEAD,FROM+SIZE);
  var j; try{ j=await getCorrelate(FROM,hi,SIZE); }
  catch(e){ el('busy').style.display='none'; return; }
  CORR=j;
  nodes.clear(); edges.clear();
  (j.nodes||[]).forEach(function(n){
    var na=n.attrs||{}; var nm=(n.content||n.kind);
    var id=na.cpf||na.cnpj||na.cod_participante||na.cod_favorecido||'';
    nodes.add({id:n.id, label:(nm.length>22?nm.slice(0,21)+'…':nm)+(id?'\n'+id:''),
      title:n.kind+' · '+esc(n.content), color:{background:kcolor(n.kind),border:'#fff'},
      font:{size:10}, _d:n});
  });
  var i=0;(j.edges||[]).forEach(function(e){
    edges.add({id:'c'+(i++),from:e.from,to:e.to, width:0.5+(e.score||0)*5,
      color:{color:'#7e3ff2',opacity:0.25+0.7*(e.score||0)}, arrows:'',
      label:(e.score||0).toFixed(2), font:{size:8,color:'#7e3ff2',strokeWidth:3,strokeColor:'#fff'},
      title:'correlação '+(e.score||0)+' · porquê: '+esc(e.why||'')});
  });
  setTimeout(function(){try{network.fit({animation:false});}catch(e){}},500);
  el('snodes').textContent=(j.nodes||[]).length;
  el('sedges').textContent=(j.edges||[]).length;
  el('sshared').textContent='estatística';
  el('sgroups').textContent=(j.n||0)+' correlações';
  // top correlações + porquê na legenda lateral
  var L=el('legend'); L.innerHTML=''; el('lgttl').textContent='Top correlações (porquê)';
  if(!(j.edges||[]).length){ L.innerHTML='<div class="hint">Sem correlações ocultas nesta janela. Tenta uma janela maior ou outra região.</div>'; }
  (j.edges||[]).slice(0,20).forEach(function(e){
    var fa=corrById(e.from)||{}, ta=corrById(e.to)||{};
    var d=document.createElement('div'); d.className='lg'; d.style.cssText='font-size:.7rem;cursor:pointer;flex-wrap:wrap';
    d.innerHTML='<b style="color:#7e3ff2;min-width:26px">'+e.score+'</b> '+esc((fa.content||e.from).slice(0,18))+' ↔ '+esc((ta.content||e.to).slice(0,18))+'<div style="width:100%;color:#7e3ff2;font-size:.64rem">↳ '+esc(e.why||'')+'</div>';
    d.onclick=function(){ try{network.selectNodes([e.from,e.to]); network.fit({nodes:[e.from,e.to],animation:true});}catch(x){} showData(corrById(e.from)||fa,e.from); };
    L.appendChild(d);
  });
  el('busy').style.display='none';
}
// navegacao pela linha do tempo inferior (clica numa zona vazia do trilho)
el('tltrack').onclick=function(ev){
  if(ev.target.closest('.mk')) return;   // clique num marcador já navega
  var r=this.getBoundingClientRect(); var f=(ev.clientX-r.left)/Math.max(1,r.width);
  FROM=Math.max(0,Math.min(Math.max(0,HEAD-SIZE),Math.round(f*HEAD))); load();
};
// VISTA TABELA (nome · tipo · CPF/CNPJ · grupo · LSN), ordenavel
var SORT={col:'group',asc:false};
function renderTable(){
  var ns=(LAST.nodes||[]).slice();
  if(el('onlyconn').checked){ var conn=new Set(); (LAST.edges||[]).forEach(e=>{conn.add(e.from);conn.add(e.to);}); ns=ns.filter(n=>conn.has(n.id)||n.hit); }
  var c=SORT.col;
  ns.sort(function(a,b){ var x=a[c],y=b[c];
    if(c==='content'||c==='kind'||c==='ent'){x=(x||'')+'';y=(y||'')+'';}
    var r=(x>y?1:(x<y?-1:0)); return SORT.asc?r:-r; });
  var cols=[['content','Nome'],['kind','Tipo'],['ent','CPF / CNPJ'],['group','Grupo'],['lsn','LSN']];
  var h='<table><thead><tr>'+cols.map(function(cd){return '<th data-c="'+cd[0]+'">'+cd[1]+(SORT.col===cd[0]?(SORT.asc?' ▲':' ▼'):'')+'</th>';}).join('')+'</tr></thead><tbody>';
  ns.slice(0,400).forEach(function(n){ var na=n.attrs||{}; var id=na.cpf||n.ent||'';
    h+='<tr data-id="'+esc(n.id)+'"><td><b>'+esc(n.content||'—')+'</b></td><td>'+esc(n.kind)+'</td>'+
       '<td class="cnpj">'+esc(id)+'</td><td><span class="pill">'+n.group+'</span></td><td class="mono" style="font-size:.7rem">'+n.lsn+'</td></tr>';
  });
  h+='</tbody></table>';
  if(ns.length>400) h+='<div class="hint" style="padding:8px">a mostrar 400 de '+ns.length+' — refina a janela/filtro</div>';
  var t=el('tableview'); t.innerHTML=h;
  t.querySelectorAll('th').forEach(function(th){ th.onclick=function(){ var cc=th.getAttribute('data-c'); if(SORT.col===cc)SORT.asc=!SORT.asc; else {SORT.col=cc;SORT.asc=false;} renderTable(); }; });
  t.querySelectorAll('tr[data-id]').forEach(function(tr){ tr.onclick=function(){ showById(tr.getAttribute('data-id')); }; });
}
function showById(id){ var d=(LAST.nodes||[]).find(x=>x.id===id); if(d) showData(d,id); }

async function load(){
  el('busy').style.display='flex';
  el('fromSlider').value=FROM; el('fromlbl').textContent=FROM.toLocaleString('pt-BR');
  var hi=Math.min(HEAD,FROM+SIZE);
  var pl=(100*FROM/Math.max(HEAD,1))+'%', pw=Math.max(1,100*(hi-FROM)/Math.max(HEAD,1))+'%';
  el('tlfill').style.left=pl; el('tlfill').style.width=pw;
  paintWinsel(); paintSeal();
  el('axwin').textContent='janela '+FROM.toLocaleString('pt-BR')+' – '+hi.toLocaleString('pt-BR');
  var j=await post('window',{from:FROM,to:hi,limit:SIZE,kind:el('kind').value,focus:el('focus').value});
  LAST=j;
  // só a vista REDE precisa do grafo vis; as outras leem LAST directamente.
  // (corr/cordas fazem a sua própria chamada /correlate — não duplicar render.)
  if(VIEW==='tab') renderTable();
  else if(VIEW==='3d') render3d();
  else if(VIEW==='map') renderMap();
  else if(VIEW==='chord') renderChord();
  else if(VIEW==='corr') renderCorr();
  else render(j);
  el('busy').style.display='none';
}
function node_color(n){
  if(LAST._foc && !n.hit) return {background:'#dde3ec',border:'#cfd6e0'};
  return COLOR==='group' ? {background:gcolor(n.group),border:'#fff'} : {background:kcolor(n.kind),border:'#fff'};
}
// Estilo de aresta por família. RESOLVE (roxo, largura ∝ score, tracejada);
// alerta de compliance (vermelho grosso — salta à vista); cruzamento (rosa);
// proveniência (azul); demais relações persistidas (cinza-azul).
function edgeStyle(id, e){
  var t = e.type, base = {id:id, from:e.from, to:e.to, font:{size:8}};
  if (t==='resolve'){
    var sc = (typeof e.score==='number') ? e.score : 0.6;
    return Object.assign(base,{ dashes:true, width:1+sc*5,
      label:(e.conf||'')+(e.score?(' '+e.score):''),
      color:{color:'#7a3cff',opacity:.85}, font:{size:8,color:'#7a3cff'},
      title:'RESOLVE '+esc(e.rel||'')+' · '+(e.conf||'')+(e.score?(' (score '+e.score+')'):'')+'\\nidentidade por CPF mascarado + nome — LEAD, não prova'});
  }
  if (t==='alerta'){
    return Object.assign(base,{ width:3, label:'⚠',
      color:{color:'#d40000',opacity:.9}, font:{size:9,color:'#d40000'},
      title:'ALERTA: '+esc(e.rel||'')});
  }
  if (t==='shared'){
    return Object.assign(base,{ dashes:true, label:'⌘',
      color:{color:'#d4006a',opacity:.6}, font:{size:8,color:'#d4006a'},
      title:'mesma entidade: '+esc(e.label||'')});
  }
  if (t==='rel'){
    return Object.assign(base,{ width:1.5, label:'',
      color:{color:'#2e8b57',opacity:.7}, title:esc(e.rel||'relação')});
  }
  return Object.assign(base,{ color:{color:'#9fb3d6',opacity:.6}, title:'proveniência'});
}
function render(j){
  j._foc = !!(el('focus').value.trim());
  nodes.clear(); edges.clear();
  var onlyc = el('onlyconn').checked;
  var conn = new Set();
  (j.edges||[]).forEach(function(e){ conn.add(e.from); conn.add(e.to); });
  (j.nodes||[]).filter(function(n){ return !onlyc || conn.has(n.id) || n.hit; }).forEach(function(n){
    var nome = (n.content||'').trim();
    var na = n.attrs||{};
    var ident = na.cpf || n.ent || '';   // CPF (servidor) ou CNPJ/código (empresa)
    var nm = nome ? (nome.length>24?nome.slice(0,23)+'…':nome) : n.kind;
    var lab = nm + (ident ? ('\n'+ident) : '');
    var tip = n.kind+(n.ent?(' · '+(n.ent_key||'ent')+' '+n.ent):'')+(na.cpf?(' · CPF '+na.cpf):'')+' · grupo '+n.group+'\n'+esc(nome);
    nodes.add({id:n.id, label:lab, title:tip, color:node_color(n), borderWidth:n.hit?3:1,
               font:{size:10,multi:false}, _d:n});
  });
  var i=0;(j.edges||[]).forEach(function(e){
    edges.add(edgeStyle('e'+(i++), e));
  });
  setTimeout(function(){try{network.fit({animation:false});}catch(e){}},500);
  el('snodes').textContent=(j.nodes||[]).length;
  el('sedges').textContent=(j.edges||[]).length;
  el('sshared').textContent=j.n_shared||0;
  el('sresolve').textContent=j.n_resolve||0;
  el('salerta').textContent=j.n_alerta||0;
  el('sgroups').textContent=j.n_groups||0;
  el('fochint').textContent = j._foc ? ((j.nodes||[]).filter(n=>n.hit).length+' nó(s) correspondem (destacados).') : '';
  // legenda
  var L=el('legend'); L.innerHTML='';
  if(COLOR==='group'){
    el('lgttl').textContent='Maiores grupos (anéis)';
    Object.entries(j.groups||{}).filter(g=>g[1]>1).slice(0,18).forEach(function(g){
      var d=document.createElement('div'); d.className='lg';
      d.innerHTML='<span class="dot" style="background:'+gcolor(+g[0])+'"></span>Grupo '+g[0]+'<span class="ct">'+g[1]+' nós</span>';
      d.onclick=function(){ focusGroup(+g[0]); };
      L.appendChild(d);
    });
  } else {
    el('lgttl').textContent='Tipos';
    Object.entries(j.kinds||{}).sort((a,b)=>b[1]-a[1]).forEach(function(kv){
      var d=document.createElement('div'); d.className='lg';
      d.innerHTML='<span class="dot" style="background:'+kcolor(kv[0])+'"></span>'+esc(kv[0])+'<span class="ct">'+kv[1]+'</span>';
      d.onclick=function(){ el('kind').value=kv[0]; load(); };
      L.appendChild(d);
    });
  }
  // filtro de tipos adaptativo
  var sel=el('kind'), cur=sel.value;
  Object.keys(j.kinds||{}).forEach(function(k){ if(!Array.from(sel.options).some(o=>o.value===k)){ var o=document.createElement('option');o.value=k;o.textContent=k;sel.appendChild(o);} });
  sel.value=cur;
}
function paint(){ // recolorir sem recarregar
  (LAST.nodes||[]).forEach(function(n){ nodes.update({id:n.id,color:node_color(n)}); });
  render(LAST);
}
function focusGroup(g){
  var members=(LAST.nodes||[]).filter(n=>n.group===g).map(n=>n.id);
  network.selectNodes(members); try{network.fit({nodes:members,animation:true});}catch(e){}
}
function showNode(id){ var n=nodes.get(id); if(n&&n._d) showData(n._d,id); }
function showData(d,id){
  var a=d.attrs||{};
  // NOME em destaque no topo
  var h='<div class="v" style="font-size:1.05rem;font-weight:800">'+esc(d.content||'(sem nome)')+'</div>';
  h+='<div class="v" style="margin-top:2px"><b style="color:'+(COLOR==="group"?gcolor(d.group):kcolor(d.kind))+'">'+esc(d.kind)+'</b> <span class="pill">grupo '+d.group+'</span></div>';
  if(d.ent) h+='<div class="k">'+esc((d.ent_key||"entidade").toUpperCase())+' (chave de cruzamento)</div><div class="v mono" style="color:#d4006a;font-weight:700">'+esc(d.ent)+'</div>';
  if(a.cpf) h+='<div class="k">CPF</div><div class="v mono">'+esc(a.cpf)+'</div>';
  if(a.cargo) h+='<div class="k">Cargo</div><div class="v">'+esc(a.cargo)+'</div>';
  if(a.orgao) h+='<div class="k">Órgão</div><div class="v">'+esc(a.orgao)+'</div>';
  h+='<div class="k">ID · LSN</div><div class="v mono" style="font-size:.68rem">'+esc(d.id)+' · '+d.lsn+'</div>';
  // co-membros do grupo (a rede cruzada)
  var grp=(LAST.nodes||[]).filter(x=>x.group===d.group && x.id!==d.id);
  if(grp.length){ h+='<div class="k">Rede do grupo ('+grp.length+')</div>';
    grp.slice(0,25).forEach(function(x){ h+='<div class="v" style="font-size:.76rem">• <b>'+esc(x.kind)+'</b> '+esc(x.content.slice(0,46))+'</div>'; }); }
  var a=d.attrs||{}; var keys=Object.keys(a);
  if(keys.length){ h+='<div class="k">Atributos</div>'; keys.forEach(function(k){ h+='<div class="v" style="display:flex;gap:6px;font-size:.76rem"><span style="color:#5a6677;min-width:88px">'+esc(k)+'</span><span>'+esc(a[k])+'</span></div>'; }); }
  el('dbody').innerHTML=h; el('drawer').classList.add('open');
  if(VIEW==='rede' && nodes.get(id)){ try{network.selectNodes([id]); network.focus(id,{scale:1.3,animation:true});}catch(e){} }
}
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass

    def _json(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            return json.loads(self.rfile.read(n) or "{}")
        except json.JSONDecodeError:
            return {}

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, _PAGE, "text/html; charset=utf-8")
        elif self.path == "/favicon.ico":
            # o browser pede sempre; devolve 204 para não poluir a consola
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
        elif self.path.startswith("/best"):
            try:
                self._send(200, json.dumps(_best(_client())))
            except Exception as e:  # noqa: BLE001
                self._send(200, json.dumps({"error": str(e)}))
        elif self.path.startswith("/density"):
            try:
                self._send(200, json.dumps(_density(_client())))
            except Exception as e:  # noqa: BLE001
                self._send(200, json.dumps({"error": str(e)}))
        elif self.path.startswith("/compliance"):
            try:
                self._send(200, json.dumps(_compliance(_DB.get("receipts", ""))))
            except Exception as e:  # noqa: BLE001
                self._send(200, json.dumps({"anchored": False, "error": str(e)}))
        else:
            self._send(404, json.dumps({"error": "rota desconhecida"}))

    def do_POST(self):
        try:
            if self.path.startswith("/window"):
                b = self._json()
                out = _analyze(_client(), b.get("from", 0), b.get("to", 0),
                               b.get("limit", 1500), (b.get("kind") or "").strip(),
                               (b.get("focus") or "").strip())
                self._send(200, json.dumps(out, ensure_ascii=False, default=str))
            elif self.path.startswith("/correlate"):
                b = self._json()
                out = _correlate(_client(), b.get("from", 0), b.get("to", 0), b.get("limit", 1500))
                self._send(200, json.dumps(out, ensure_ascii=False, default=str))
            elif self.path.startswith("/find"):
                b = self._json()
                out = _find(_client(), b.get("term", ""))
                self._send(200, json.dumps(out, ensure_ascii=False, default=str))
            else:
                self._send(404, json.dumps({"error": "rota desconhecida"}))
        except Exception as e:  # noqa: BLE001
            self._send(200, json.dumps({"error": str(e)}))


def _default_receipts():
    pd = os.environ.get("ProgramData", "C:/ProgramData")
    return os.path.join(pd, "HeraclitusDB", "data", "receipts")


def _compliance(receipts_dir):
    """Último recibo de carimbo de tempo (RFC 3161) do heraclitus-compliance.
    Lê `manifest.jsonl` do diretório de recibos — liga a análise de fraude à
    prova forense. Sem daemon/recibos => {anchored: False}."""
    path = os.path.join(receipts_dir or "", "manifest.jsonl")
    if not receipts_dir or not os.path.exists(path):
        return {"anchored": False, "dir": receipts_dir}
    last, n = None, 0
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                n += 1
                try:
                    last = json.loads(line)
                except json.JSONDecodeError:
                    pass
    except OSError as e:
        return {"anchored": False, "error": str(e), "dir": receipts_dir}
    if not last:
        return {"anchored": False, "dir": receipts_dir}
    return {"anchored": True, "count": n, "lsn": last.get("lsn"),
            "gen_unix_ms": last.get("gen_unix_ms"), "policy": last.get("policy"),
            "root_hex": last.get("root_hex"), "segments": last.get("segments")}


def main():
    ap = argparse.ArgumentParser(description="Heraclitus Console V3 (análise on-demand)")
    ap.add_argument("--addr", default="127.0.0.1:7474")
    ap.add_argument("--port", type=int, default=7482)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--receipts", default=os.environ.get("HERACLITUS_RECEIPTS", "") or _default_receipts())
    args = ap.parse_args()
    _DB["addr"] = args.addr
    _DB["receipts"] = args.receipts
    print(f"Heraclitus Console V3 em http://127.0.0.1:{args.port}  (banco: {args.addr})")
    print(f"  recibos de compliance: {args.receipts}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
