#!/usr/bin/env python3
"""Massive-v2: campanha adversarial autorizada, estritamente loopback-only.

Objetivo: estressar HeraclitusDB/Agent Gateway com muitos agentes sintéticos,
ambiguidades de protocolo, corridas de approval, confusão de tipos JSON,
entradas malformadas e pressão concorrente. Nenhum payload executa shell,
acessa filesystem, ou permite alvo remoto.
"""
from __future__ import annotations

import base64
import concurrent.futures
import http.client
import json
import os
import socket
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}


def die(msg: str) -> None:
    raise SystemExit(msg)


def assert_loopback(url: str, label: str) -> None:
    u = urlsplit(url)
    if u.scheme not in {"http", "https"} or u.hostname not in LOOPBACK:
        die(f"RECUSADO: {label} deve ser loopback; veio {url!r}")


def basic(user: str, password: str) -> dict[str, str]:
    raw = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


class Lab:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.campaign = cfg.get("campaign") or f"massive-v2-{int(time.time())}"
        self.results: list[dict] = []
        for key in ("core_rest", "agent_api", "otlp", "mcp_gateway", "upstream_hits"):
            assert_loopback(cfg[key], key)
        if cfg.get("core_grpc_host", "127.0.0.1") not in LOOPBACK:
            die("RECUSADO: gRPC não é loopback")

    def request(self, base, path, method="GET", body=None, headers=None, timeout=8, max_read=2_000_000):
        u = urlsplit(base)
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
        h = {"User-Agent": "Agent-Atack-Heraclitus/massive-v2", "Accept": "application/json"}
        if headers:
            h.update(headers)
        data = None
        if body is not None:
            data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body, separators=(",", ":")).encode()
            h.setdefault("Content-Type", "application/json")
            h["Content-Length"] = str(len(data))
        t = time.perf_counter()
        try:
            conn.request(method, (u.path.rstrip("/") + path) or "/", body=data, headers=h)
            r = conn.getresponse()
            raw = r.read(max_read)
            try:
                parsed = json.loads(raw) if raw else None
            except Exception:
                parsed = raw[:500].decode("utf-8", "replace")
            return r.status, parsed, (time.perf_counter() - t) * 1000
        except Exception as e:
            return None, {"exception": type(e).__name__, "detail": str(e)[:160]}, (time.perf_counter() - t) * 1000
        finally:
            conn.close()

    def agent_auth(self):
        u = os.getenv("HERACLITUS_AGENT_USERNAME", "").strip()
        p = os.getenv("HERACLITUS_AGENT_PASSWORD", "")
        if u and p:
            return basic(u, p)
        token = os.getenv("HERACLITUS_AGENT_TOKEN", "").strip()
        return {"Authorization": f"Bearer {token}"} if token else {}

    def core_auth(self):
        u = os.getenv("HERACLITUS_CORE_USERNAME", "").strip()
        p = os.getenv("HERACLITUS_CORE_PASSWORD", "")
        return basic(u, p) if u and p else {}

    def hits(self):
        u = urlsplit(self.cfg["upstream_hits"])
        root = f"http://{u.hostname}:{u.port or 80}"
        s, b, _ = self.request(root, u.path)
        return int(b.get("hits", 0)) if s == 200 and isinstance(b, dict) else None

    def headers(self, agent="massive-agent", run=None, mcp_method="tools/call"):
        h = {
            "Content-Type": "application/json",
            "mcp-method": mcp_method,
            "X-Heraclitus-Agent": agent,
            "X-Heraclitus-Run": run or self.campaign,
            "X-Heraclitus-User": "sandbox-operator",
            "X-Heraclitus-Server": "safe-stub",
            "X-Heraclitus-Environment": "lab",
        }
        h.update(self.agent_auth())
        return h

    @staticmethod
    def tool(rid, name, args, method="tools/call"):
        return {"jsonrpc": "2.0", "id": rid, "method": method, "params": {"name": name, "arguments": args}}

    @staticmethod
    def reason(body):
        try:
            return body["error"]["data"]["heraclitus"]["reason_code"]
        except Exception:
            return None

    def record(self, name, ok, **extra):
        row = {"vector": name, "passed": bool(ok), **extra}
        self.results.append(row)
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {name:38} {json.dumps(extra, ensure_ascii=False, separators=(',',':'))}")
        # Registra apenas metadados no próprio Heraclitus. Nada de payload ofensivo.
        payload = {
            "attack_id": f"{name}-{uuid.uuid4().hex[:10]}",
            "campaign_id": self.campaign,
            "vector": name,
            "target": extra.get("target", "sandbox"),
            "phase": "result",
            "result": str(extra.get("result", "pass" if ok else "fail"))[:300],
            "expected": str(extra.get("expected", "security invariant holds"))[:300],
            "reason_code": extra.get("reason_code"),
            "blocked": extra.get("blocked"),
            "upstream_delta": extra.get("upstream_delta"),
            "transport_status": extra.get("status"),
        }
        self.request(self.cfg["agent_api"], "/api/v1/agent/red-team/events", "POST", payload, self.agent_auth())

    def deny_swarm(self, agents=256, calls=2048):
        before = self.hits()
        def one(i):
            agent = f"swarm-{i % agents:04d}"
            req = self.tool(f"shared-{i % 17}", "exec", {"marker": "SAFE_ONLY", "i": i})
            return self.request(self.cfg["mcp_gateway"], "/mcp", "POST", req, self.headers(agent, f"run-{i%31}"), timeout=15)[0]
        t = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
            statuses = list(ex.map(one, range(calls)))
        after = self.hits()
        denied = sum(x == 403 for x in statuses)
        delta = None if before is None or after is None else after - before
        self.record("multi-agent-deny-swarm", denied == calls and delta == 0,
                    status=403, blocked=True, upstream_delta=delta,
                    result=f"{denied}/{calls} denied in {(time.perf_counter()-t):.2f}s")

    def identity_collision(self, agents=256):
        before = self.hits()
        def one(i):
            # Mesmo JSON-RPC id e run em agentes diferentes. Não pode colapsar identidades.
            req = self.tool("COLLISION-ID", "exec", {"marker": "SAFE_ONLY", "agent_slot": i})
            return self.request(self.cfg["mcp_gateway"], "/mcp", "POST", req,
                                self.headers(f"identity-{i:04d}", "same-run"), timeout=12)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
            statuses = list(ex.map(one, range(agents)))
        after = self.hits(); delta = None if before is None or after is None else after-before
        self.record("cross-agent-id-collision", all(x == 403 for x in statuses) and delta == 0,
                    blocked=True, upstream_delta=delta, result=f"403={sum(x==403 for x in statuses)}/{agents}")

    def method_confusion(self):
        variants = ["Tools/Call", "TOOLS/CALL", "tools\\call", "tools%2Fcall", "tools//call", "tools/call ", " tools/call", "tools/call\u0000"]
        before = self.hits(); rows=[]
        for i, method in enumerate(variants):
            req = self.tool(f"method-{i}", "exec", {"marker": "SAFE_ONLY"}, method=method)
            s,b,_ = self.request(self.cfg["mcp_gateway"], "/mcp", "POST", req, self.headers(f"method-{i}", mcp_method=method))
            rows.append((method, s, self.reason(b)))
        after=self.hits(); delta=None if before is None or after is None else after-before
        ok = delta == 0 and all(s not in {200,201,202} for _,s,_ in rows)
        self.record("mcp-method-confusion-matrix", ok, blocked=ok, upstream_delta=delta,
                    result="; ".join(f"{m!r}:{s}" for m,s,_ in rows)[:700])

    def header_body_confusion(self):
        cases = [("ping","tools/call"),("resources/read","tools/call"),("tools/call","ping"),("prompts/get","tools/call")]
        before=self.hits(); rows=[]
        for i,(header_method,body_method) in enumerate(cases):
            req=self.tool(f"hb-{i}","exec",{"marker":"SAFE_ONLY"},method=body_method)
            s,b,_=self.request(self.cfg["mcp_gateway"],"/mcp","POST",req,self.headers(f"hb-{i}",mcp_method=header_method))
            rows.append((header_method,body_method,s,self.reason(b)))
        after=self.hits(); delta=None if before is None or after is None else after-before
        ok=delta==0 and all(s not in {200,201,202} for _,_,s,_ in rows)
        self.record("header-body-method-disagreement",ok,blocked=ok,upstream_delta=delta,result=str(rows)[:700])

    def non_tool_data_surfaces(self):
        before=self.hits(); rows=[]
        for i,m in enumerate(("resources/read","prompts/get")):
            req={"jsonrpc":"2.0","id":f"nt-{i}","method":m,"params":{"uri":"lab://synthetic"}}
            s,b,_=self.request(self.cfg["mcp_gateway"],"/mcp","POST",req,self.headers(f"nt-{i}",mcp_method=m))
            rows.append((m,s,self.reason(b)))
        after=self.hits(); delta=None if before is None or after is None else after-before
        ok=delta==0 and all(s in {400,401,403,405,422} for _,s,_ in rows)
        self.record("non-tool-data-surface-governance",ok,blocked=ok,upstream_delta=delta,result=str(rows))

    def approval_race(self, workers=48):
        rid=f"approval-race-{uuid.uuid4().hex[:8]}"
        req=self.tool(rid,"send_payment",{"amount":75000,"account":"synthetic-race"})
        s,b,_=self.request(self.cfg["mcp_gateway"],"/mcp","POST",req,self.headers("owner-agent","approval-race"))
        try: approval=b["error"]["data"]["heraclitus"]["approval_id"]
        except Exception: approval=None
        if s!=202 or not approval:
            self.record("approval-consume-race",False,status=s,result="approval not opened"); return
        a_s,_,_=self.request(self.cfg["agent_api"],f"/api/v1/agent/approvals/{approval}/approve","POST",{},self.agent_auth())
        before=self.hits()
        def one(_):
            return self.request(self.cfg["mcp_gateway"],"/mcp","POST",req,self.headers("owner-agent","approval-race"),timeout=15)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            statuses=list(ex.map(one,range(workers)))
        after=self.hits(); delta=None if before is None or after is None else after-before
        ok=a_s==200 and statuses.count(200)==1 and delta==1
        self.record("approval-consume-race",ok,upstream_delta=delta,result=f"approve={a_s}, 200={statuses.count(200)}, 403={statuses.count(403)}")

    def cross_agent_approval_theft(self):
        rid=f"approval-theft-{uuid.uuid4().hex[:8]}"
        req=self.tool(rid,"send_payment",{"amount":75000,"account":"synthetic-owner"})
        s,b,_=self.request(self.cfg["mcp_gateway"],"/mcp","POST",req,self.headers("agent-owner","theft-run"))
        try: approval=b["error"]["data"]["heraclitus"]["approval_id"]
        except Exception: approval=None
        if s!=202 or not approval:
            self.record("cross-agent-approval-theft",False,status=s,result="approval not opened"); return
        self.request(self.cfg["agent_api"],f"/api/v1/agent/approvals/{approval}/approve","POST",{},self.agent_auth())
        before=self.hits()
        s2,b2,_=self.request(self.cfg["mcp_gateway"],"/mcp","POST",req,self.headers("agent-thief","theft-run"))
        mid=self.hits()
        s3,b3,_=self.request(self.cfg["mcp_gateway"],"/mcp","POST",req,self.headers("agent-owner","theft-run"))
        after=self.hits()
        thief_delta=None if before is None or mid is None else mid-before
        total_delta=None if before is None or after is None else after-before
        ok=s2!=200 and thief_delta==0 and s3==200 and total_delta==1
        self.record("cross-agent-approval-theft",ok,blocked=(s2!=200),upstream_delta=total_delta,
                    reason_code=self.reason(b2),result=f"thief={s2},owner={s3}")

    def typed_json_binding(self):
        rid=f"typed-{uuid.uuid4().hex[:8]}"
        original=self.tool(rid,"send_payment",{"amount":75000,"account":"typed"})
        s,b,_=self.request(self.cfg["mcp_gateway"],"/mcp","POST",original,self.headers("typed-owner","typed-run"))
        try: approval=b["error"]["data"]["heraclitus"]["approval_id"]
        except Exception: approval=None
        if s!=202 or not approval:
            self.record("typed-json-approval-binding",False,status=s,result="approval not opened"); return
        self.request(self.cfg["agent_api"],f"/api/v1/agent/approvals/{approval}/approve","POST",{},self.agent_auth())
        variants=[
            {"amount":"75000","account":"typed"},
            {"amount":75000.0,"account":"typed"},
            {"amount":75000,"account":["typed"]},
            {"amount":75000,"account":{"value":"typed"}},
            {"amount":75000,"account":"typed","extra":None},
        ]
        before=self.hits(); rows=[]
        for i,args in enumerate(variants):
            req=self.tool(rid,"send_payment",args)
            ss,bb,_=self.request(self.cfg["mcp_gateway"],"/mcp","POST",req,self.headers("typed-owner","typed-run"))
            rows.append((i,ss,self.reason(bb)))
        after=self.hits(); delta=None if before is None or after is None else after-before
        ok=delta==0 and all(s != 200 for _,s,_ in rows)
        self.record("typed-json-approval-binding",ok,blocked=ok,upstream_delta=delta,result=str(rows)[:700])

    def parser_malformed_flood(self, count=512):
        samples=[b"{",b"[]",b"null",b"\xff\xfe",b'{"jsonrpc":"2.0",',b'{"method":123}',b'{"method":"tools/call","params":[]}']
        before=self.hits()
        def one(i):
            h=self.headers(f"malformed-{i%32}")
            return self.request(self.cfg["mcp_gateway"],"/mcp","POST",samples[i%len(samples)],h,timeout=10)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
            statuses=list(ex.map(one,range(count)))
        health,_,_=self.request(self.cfg["agent_api"],"/api/v1/agent/status",headers=self.agent_auth())
        after=self.hits(); delta=None if before is None or after is None else after-before
        ok=health==200 and delta==0 and all(s is not None for s in statuses)
        self.record("malformed-json-flood",ok,upstream_delta=delta,result=f"count={count},health={health},statuses={sorted(set(statuses),key=lambda x:(x is None,x))}")

    def content_type_and_http_method(self):
        before=self.hits(); rows=[]
        req=self.tool("ctype","exec",{"marker":"SAFE_ONLY"})
        for method,ctype in [("POST","text/plain"),("PUT","application/json"),("PATCH","application/json"),("POST","application/octet-stream")]:
            h=self.headers(f"ctype-{method}"); h["Content-Type"]=ctype
            s,b,_=self.request(self.cfg["mcp_gateway"],"/mcp",method,req,h)
            rows.append((method,ctype,s,self.reason(b)))
        after=self.hits(); delta=None if before is None or after is None else after-before
        ok=delta==0 and all(s not in {200,201,202} for _,_,s,_ in rows)
        self.record("http-method-content-type-confusion",ok,blocked=ok,upstream_delta=delta,result=str(rows)[:700])

    def unicode_identity(self):
        agents=["admin", "аdmin", "admіn", "ＡＤＭＩＮ", "agent\u200droot", "agent\u202eroot"]
        before=self.hits(); statuses=[]
        for i,a in enumerate(agents):
            req=self.tool(f"unicode-{i}","exec",{"marker":"SAFE_ONLY"})
            s,_,_=self.request(self.cfg["mcp_gateway"],"/mcp","POST",req,self.headers(a,"unicode-run"))
            statuses.append(s)
        after=self.hits(); delta=None if before is None or after is None else after-before
        ok=delta==0 and all(s==403 for s in statuses)
        self.record("unicode-confusable-identities",ok,blocked=ok,upstream_delta=delta,result=str(statuses))

    def otlp_malformed_swarm(self,count=256):
        samples=[b"{",b"not-json",b"\xff",b'{"resourceSpans":',b"[]"]
        def one(i):
            return self.request(self.cfg["otlp"],"/v1/traces","POST",samples[i%len(samples)],{"Content-Type":"application/json"},timeout=10)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
            statuses=list(ex.map(one,range(count)))
        s2,_,_=self.request(self.cfg["otlp"],"/v1/traces","POST",{"resourceSpans":[]},{"Content-Type":"application/json"})
        ok=s2==200 and all(s in {400,413,422} for s in statuses)
        self.record("otlp-malformed-swarm",ok,result=f"{count} malformed; healthy={s2}; statuses={sorted(set(statuses))}")

    def otlp_oversize_parallel(self,count=12):
        n=int(self.cfg.get("oversized_bytes",5*1024*1024))
        body=b'{"resourceSpans":[],"pad":"'+b"x"*n+b'"}'
        def one(_):
            return self.request(self.cfg["otlp"],"/v1/traces","POST",body,{"Content-Type":"application/json"},timeout=20,max_read=2048)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(count,12)) as ex:
            statuses=list(ex.map(one,range(count)))
        health,_,_=self.request(self.cfg["agent_api"],"/api/v1/agent/status",headers=self.agent_auth())
        ok=all(s==413 for s in statuses) and health==200
        self.record("otlp-oversize-parallel",ok,result=f"413={statuses.count(413)}/{count}, health={health}")

    def auth_plane_separation(self):
        ca=self.core_auth(); aa=self.agent_auth()
        if not ca or not aa:
            self.record("core-agent-auth-separation",True,result="SKIP: credentials not configured")
            return
        s1,_,_=self.request(self.cfg["agent_api"],"/api/v1/agent/status",headers=ca)
        s2,_,_=self.request(self.cfg["core_rest"],"/stats",headers=aa)
        ok=s1 in {401,403} and s2 in {401,403}
        self.record("core-agent-auth-separation",ok,result=f"core->agent={s1}, agent->core={s2}")

    def redteam_query_bound(self):
        s,b,_=self.request(self.cfg["agent_api"],"/api/v1/agent/red-team/events?limit=999999",headers=self.agent_auth())
        count=None
        if isinstance(b,dict):
            rows=b.get("events") or b.get("items") or b.get("rows")
            if isinstance(rows,list): count=len(rows)
            elif isinstance(b.get("returned"),int): count=b["returned"]
        ok=s==200 and (count is None or count<=1000)
        self.record("redteam-query-limit-cap",ok,status=s,result=f"returned={count}")

    def evidence_health(self):
        s,b,_=self.request(self.cfg["agent_api"],"/api/v1/agent/status",headers=self.agent_auth())
        txt=json.dumps(b,sort_keys=True) if isinstance(b,dict) else str(b)
        ok=s==200 and "HEALTHY" in txt and ('"evidence_errors": 0' in txt or '"evidence_errors":0' in txt)
        self.record("post-campaign-evidence-health",ok,status=s,result=txt[:900])

    def run(self):
        print(f"Massive-v2 campaign={self.campaign} LOOPBACK-ONLY")
        tests=[
            self.deny_swarm,
            self.identity_collision,
            self.method_confusion,
            self.header_body_confusion,
            self.non_tool_data_surfaces,
            self.approval_race,
            self.cross_agent_approval_theft,
            self.typed_json_binding,
            self.parser_malformed_flood,
            self.content_type_and_http_method,
            self.unicode_identity,
            self.otlp_malformed_swarm,
            self.otlp_oversize_parallel,
            self.auth_plane_separation,
            self.redteam_query_bound,
            self.evidence_health,
        ]
        for fn in tests:
            try:
                fn()
            except Exception as e:
                self.record(fn.__name__,False,result=f"runner exception {type(e).__name__}: {e}")
        passed=sum(bool(r["passed"]) for r in self.results)
        print(f"SUMMARY {passed}/{len(self.results)} PASS")
        return 0 if passed==len(self.results) else 2


def main():
    if len(sys.argv)>2:
        die("uso: massive_v2.py [config.json]")
    path=Path(sys.argv[1] if len(sys.argv)==2 else "config.json")
    cfg=json.loads(path.read_text())
    lab=Lab(cfg)
    rc=lab.run()
    out=Path(cfg.get("massive_v2_report","massive-v2-report.json"))
    out.write_text(json.dumps({"campaign":lab.campaign,"results":lab.results},ensure_ascii=False,indent=2))
    print(f"report={out}")
    raise SystemExit(rc)

if __name__=="__main__":
    main()
