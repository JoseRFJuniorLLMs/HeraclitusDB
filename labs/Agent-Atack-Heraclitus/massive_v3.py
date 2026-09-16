#!/usr/bin/env python3
"""Massive-v3: segunda onda adversarial loopback-only.

Amplia Massive-v2 com ambiguidades de parser, isolamento de namespace de
approvals, corrida 128-way, tempestade multiagente maior, métodos Unicode
confusáveis e limites exatos de headers de correlação. Não executa shell,
não toca filesystem do alvo e recusa qualquer endpoint fora de loopback.
"""
from __future__ import annotations

import concurrent.futures
import json
import sys
import time
import uuid
from pathlib import Path

from massive_v2 import Lab, die


class Wave3(Lab):
    def duplicate_json_keys(self):
        before = self.hits()
        raws = [
            b'{"jsonrpc":"2.0","id":"dup1","method":"ping","method":"tools/call","params":{"name":"exec","arguments":{"marker":"SAFE"}}}',
            b'{"jsonrpc":"2.0","id":"dup2","method":"tools/call","method":"ping","params":{"name":"exec","arguments":{"marker":"SAFE"}}}',
            b'{"jsonrpc":"2.0","id":"dup3","params":{"name":"lookup_vendor","name":"exec","arguments":{"marker":"SAFE"}},"method":"tools/call"}',
        ]
        statuses = []
        for i, raw in enumerate(raws):
            s, _, _ = self.request(
                self.cfg["mcp_gateway"], "/mcp", "POST", raw,
                self.headers("dup-agent", f"dup-{i}"),
            )
            statuses.append(s)
        after = self.hits()
        delta = None if before is None or after is None else after - before
        self.record(
            "duplicate-json-key-parser-differential",
            all(s == 400 for s in statuses) and delta == 0,
            blocked=True, upstream_delta=delta, result=f"statuses={statuses}",
        )

    def deep_json(self, depth=300):
        before = self.hits()
        deep = '"x"'
        for _ in range(depth):
            deep = "[" + deep + "]"
        raw = (
            '{"jsonrpc":"2.0","id":"deep","method":"tools/call",'
            '"params":{"name":"exec","arguments":{"nest":' + deep + "}}}"
        ).encode()
        s, b, _ = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", raw,
            self.headers("deep-agent", "deep-run"),
        )
        after = self.hits()
        delta = None if before is None or after is None else after - before
        self.record(
            "deep-json-300-levels",
            s in {400, 413, 422} and delta == 0,
            status=s, blocked=True, upstream_delta=delta,
            reason_code=self.reason(b), result=f"HTTP={s}",
        )

    def approval_namespace_isolation(self, agents=128):
        before = self.hits()

        def one(i):
            r = self.tool(
                "SAME-ID", "send_payment",
                {"amount": 75000, "account": f"synthetic-{i}"},
            )
            s, b, _ = self.request(
                self.cfg["mcp_gateway"], "/mcp", "POST", r,
                self.headers(f"approval-agent-{i:03d}", "SAME-RUN"),
            )
            try:
                approval = b["error"]["data"]["heraclitus"]["approval_id"]
            except Exception:
                approval = None
            return s, approval

        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
            rows = list(ex.map(one, range(agents)))
        after = self.hits()
        delta = None if before is None or after is None else after - before
        approvals = [a for _, a in rows if a]
        ok = (
            all(s == 202 for s, _ in rows)
            and len(set(approvals)) == agents
            and delta == 0
        )
        self.record(
            "128-agent-approval-namespace-isolation", ok,
            blocked=True, upstream_delta=delta,
            result=f"202={sum(s == 202 for s, _ in rows)}/{agents}; distinct={len(set(approvals))}",
        )

    def approval_atomic_128(self, workers=128):
        rid = f"mega-race-{uuid.uuid4().hex[:8]}"
        run = "mega-race"
        agent = "mega-owner"
        request = self.tool(
            rid, "send_payment", {"amount": 88000, "account": "synthetic-mega"}
        )
        s, b, _ = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", request,
            self.headers(agent, run),
        )
        try:
            approval = b["error"]["data"]["heraclitus"]["approval_id"]
        except Exception:
            approval = None
        approved = None
        if approval:
            approved, _, _ = self.request(
                self.cfg["agent_api"],
                f"/api/v1/agent/approvals/{approval}/approve",
                "POST", {}, self.agent_auth(),
            )
        before = self.hits()

        def consume(_):
            return self.request(
                self.cfg["mcp_gateway"], "/mcp", "POST", request,
                self.headers(agent, run), timeout=15,
            )[0]

        with concurrent.futures.ThreadPoolExecutor(max_workers=96) as ex:
            statuses = list(ex.map(consume, range(workers)))
        after = self.hits()
        delta = None if before is None or after is None else after - before
        ok = s == 202 and approved == 200 and statuses.count(200) == 1 and delta == 1
        self.record(
            "approval-atomic-consume-128-way", ok,
            upstream_delta=delta,
            result=f"open={s}; approve={approved}; 200={statuses.count(200)}; 403={statuses.count(403)}",
        )

    def deny_storm_4096(self, calls=4096):
        before = self.hits()

        def one(i):
            return self.request(
                self.cfg["mcp_gateway"], "/mcp", "POST",
                self.tool(f"R{i % 23}", "exec", {"marker": "SAFE", "slot": i % 7}),
                self.headers(f"rstorm-{i % 512}", f"rrun-{i % 37}"), timeout=20,
            )[0]

        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=96) as ex:
            statuses = list(ex.map(one, range(calls)))
        after = self.hits()
        health, _, _ = self.request(
            self.cfg["agent_api"], "/api/v1/agent/status", headers=self.agent_auth()
        )
        delta = None if before is None or after is None else after - before
        ok = all(s == 403 for s in statuses) and delta == 0 and health == 200
        self.record(
            "4096-request-multiagent-deny-storm", ok,
            blocked=True, upstream_delta=delta,
            result=f"403={sum(s == 403 for s in statuses)}/{calls}; health={health}; {time.perf_counter()-started:.2f}s",
        )

    def unicode_method_matrix(self):
        variants = [
            "tools∕call", "tools⁄call", "toоls/call", "tools／call",
            "Ｔｏｏｌｓ／Ｃａｌｌ", "tools/call\u2028",
        ]
        before = self.hits()
        statuses = []
        for i, method in enumerate(variants):
            r = self.tool(f"u{i}", "exec", {"marker": "SAFE"}, method=method)
            s, _, _ = self.request(
                self.cfg["mcp_gateway"], "/mcp", "POST", r,
                self.headers("unicode-proto", f"u{i}", mcp_method=method),
            )
            statuses.append(s)
        after = self.hits()
        delta = None if before is None or after is None else after - before
        self.record(
            "unicode-confusable-method-matrix",
            all(s in {400, 403} for s in statuses) and delta == 0,
            blocked=True, upstream_delta=delta, result=f"statuses={statuses}",
        )

    def correlation_header_boundary(self):
        before = self.hits()
        rows = []
        for n in (511, 512, 513, 1024, 16384):
            h = self.headers("A" * n, f"h{n}")
            s, b, _ = self.request(
                self.cfg["mcp_gateway"], "/mcp", "POST",
                self.tool(f"h{n}", "exec", {"marker": "SAFE"}), h,
            )
            rows.append((n, s, self.reason(b)))
        after = self.hits()
        delta = None if before is None or after is None else after - before
        ok = (
            rows[0][1] == 403 and rows[1][1] == 403
            and all(s == 400 for _, s, _ in rows[2:]) and delta == 0
        )
        self.record(
            "correlation-header-boundary-511-16384", ok,
            blocked=True, upstream_delta=delta, result=str(rows)[:900],
        )

    def final_health(self):
        s, b, _ = self.request(
            self.cfg["agent_api"], "/api/v1/agent/status", headers=self.agent_auth()
        )
        gateway = b.get("gateway", {}) if isinstance(b, dict) else {}
        healthy = b.get("evidence_log") if isinstance(b, dict) else None
        errors = gateway.get("evidence_errors")
        self.record(
            "massive-v3-evidence-integrity",
            s == 200 and healthy == "HEALTHY" and errors == 0,
            status=s, result=f"evidence_log={healthy}; evidence_errors={errors}",
        )

    def run_v3(self):
        print(f"Massive-v3 campaign={self.campaign} LOOPBACK-ONLY")
        tests = [
            self.duplicate_json_keys,
            self.deep_json,
            self.approval_namespace_isolation,
            self.approval_atomic_128,
            self.deny_storm_4096,
            self.unicode_method_matrix,
            self.correlation_header_boundary,
            self.final_health,
        ]
        for fn in tests:
            try:
                fn()
            except Exception as e:
                self.record(fn.__name__, False, result=f"runner exception {type(e).__name__}: {e}")
        passed = sum(bool(r["passed"]) for r in self.results)
        print(f"SUMMARY {passed}/{len(self.results)} PASS")
        return 0 if passed == len(self.results) else 2


def main():
    if len(sys.argv) > 2:
        die("uso: massive_v3.py [config.json]")
    path = Path(sys.argv[1] if len(sys.argv) == 2 else "config.json")
    cfg = json.loads(path.read_text())
    lab = Wave3(cfg)
    rc = lab.run_v3()
    out = Path(cfg.get("massive_v3_report", "massive-v3-report.json"))
    out.write_text(json.dumps({"campaign": lab.campaign, "results": lab.results}, ensure_ascii=False, indent=2))
    print(f"report={out}")
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
