#!/usr/bin/env python3
"""Deep-RedTeam-Heraclitus.

Authorized local laboratory harness for deep attack surfaces not covered well by
parser fuzzing alone: tenant isolation, privileged-operation faults, query
resource pressure, HRKL rollback/substitution and Raft transport.

Hard safety boundary:
- every network target must be loopback;
- destructive storage mutations are performed only on temporary copies;
- process killing applies only to child processes started by this runner.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


@dataclass
class Result:
    attack_id: str
    campaign: str
    target: str
    expected: str
    observed: str
    outcome: str
    severity_if_failed: str
    duration_ms: float = 0.0
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.outcome in {"PASS", "SKIP"}


def _loopback_url(url: str, label: str) -> None:
    u = urlsplit(url)
    if u.scheme not in {"http", "https"} or u.hostname not in LOOPBACK:
        raise SystemExit(f"RECUSADO: {label} deve apontar para loopback: {url!r}")


def _loopback_host(host: str, label: str) -> None:
    if host not in LOOPBACK:
        raise SystemExit(f"RECUSADO: {label} deve ser loopback: {host!r}")


def _subst(values: list[str], data_dir: Path) -> list[str]:
    return [x.replace("{data_dir}", str(data_dir)) for x in values]


def _tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(x for x in root.rglob("*") if x.is_file()):
        h.update(str(p.relative_to(root)).replace("\\", "/").encode())
        h.update(b"\0")
        with p.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
    return h.hexdigest()


class Lab:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.campaign_id = cfg.get("campaign") or f"deep-redteam-{int(time.time())}"
        self.results: list[Result] = []

        for key in ("core_rest", "agent_api", "mcp_gateway"):
            if cfg.get(key):
                _loopback_url(cfg[key], key)

        tenant = cfg.get("tenant", {})
        if tenant.get("base"):
            _loopback_url(tenant["base"], "tenant.base")

        admin = cfg.get("admin_fault", {})
        if admin.get("health_url"):
            _loopback_url(admin["health_url"], "admin_fault.health_url")

        for i, item in enumerate(cfg.get("raft", {}).get("targets", [])):
            _loopback_host(item["host"], f"raft.targets[{i}].host")

    def add(
        self,
        attack_id: str,
        campaign: str,
        target: str,
        expected: str,
        observed: str,
        outcome: str,
        severity: str,
        started: float | None = None,
        detail: str = "",
    ) -> None:
        ms = 0.0 if started is None else (time.perf_counter() - started) * 1000.0
        r = Result(attack_id, campaign, target, expected, observed, outcome, severity, ms, detail)
        self.results.append(r)
        print(
            f"[{outcome:7}] {attack_id:12} {campaign:18} "
            f"target={target} observed={observed} {detail}"
        )

    def request(
        self,
        base: str,
        path: str,
        method: str = "GET",
        body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float = 5.0,
    ) -> tuple[int | None, Any, float]:
        _loopback_url(base, "request")
        u = urlsplit(base)
        if u.scheme != "http":
            raise RuntimeError(
                "runner suporta http:// loopback; para HTTPS use terminador TLS local"
            )
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
        data = None
        h = {"User-Agent": "Deep-RedTeam-Heraclitus/1", "Accept": "application/json"}
        if headers:
            h.update(headers)
        if body is not None:
            data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
            h["Content-Length"] = str(len(data))
        started = time.perf_counter()
        try:
            conn.request(method, (u.path.rstrip("/") + path) or "/", body=data, headers=h)
            resp = conn.getresponse()
            raw = resp.read(2 * 1024 * 1024)
            parsed: Any = raw
            if raw:
                try:
                    parsed = json.loads(raw)
                except Exception:
                    parsed = raw.decode("utf-8", "replace")[:1000]
            return resp.status, parsed, (time.perf_counter() - started) * 1000
        except Exception as exc:
            return None, {"exception": type(exc).__name__, "message": str(exc)[:200]}, (
                time.perf_counter() - started
            ) * 1000
        finally:
            conn.close()

    @staticmethod
    def _auth_from_env(spec: dict[str, Any]) -> dict[str, str]:
        mode = spec.get("mode", "bearer")
        if mode == "bearer":
            value = os.getenv(spec.get("token_env", ""), "").strip()
            return {"Authorization": f"Bearer {value}"} if value else {}
        if mode == "basic":
            user = os.getenv(spec.get("user_env", ""), "").strip()
            password = os.getenv(spec.get("password_env", ""), "")
            if not user or not password:
                return {}
            raw = base64.b64encode(f"{user}:{password}".encode()).decode()
            return {"Authorization": f"Basic {raw}"}
        raise ValueError(f"unsupported auth mode: {mode}")

    def tenant_isolation(self) -> None:
        c = self.cfg.get("tenant", {})
        if not c.get("enabled", False):
            self.add(
                "TENANT-000", "tenant-isolation", "configured surfaces",
                "tenant campaign configured", "disabled", "SKIP", "CRITICAL",
                detail="enable only with two synthetic tenant identities",
            )
            return

        base = c["base"]
        ta = c["tenant_a"]
        ha = self._auth_from_env(c["auth_a"])
        hb = self._auth_from_env(c["auth_b"])
        if not ha or not hb:
            self.add(
                "TENANT-001", "tenant-isolation", base,
                "two authenticated synthetic tenant identities",
                "credential missing", "FAIL", "CRITICAL",
            )
            return

        for idx, probe in enumerate(c.get("probes", []), start=1):
            aid = f"TENANT-{idx + 1:03d}"
            path_a = probe["path"].replace("{tenant}", ta)
            allowed = set(probe.get("self_allowed_status", [200]))
            denied = set(probe.get("cross_denied_status", [401, 403, 404]))
            started = time.perf_counter()
            sa, _, _ = self.request(
                base, path_a, probe.get("method", "GET"), probe.get("body"), ha
            )
            sb, bb, _ = self.request(
                base, path_a, probe.get("method", "GET"), probe.get("body"), hb
            )
            if sa not in allowed:
                outcome = "FAIL"
                detail = f"owner request unexpectedly returned {sa}"
            elif sb in denied:
                outcome = "PASS"
                detail = "cross-tenant request denied"
            else:
                marker = probe.get("tenant_a_marker")
                leaked = bool(marker) and marker in json.dumps(bb, ensure_ascii=False)
                outcome = "FAIL" if leaked or probe.get("require_denial", True) else "FINDING"
                detail = "cross-tenant response was not denied"
            self.add(
                aid, "tenant-isolation", path_a,
                f"owner in {sorted(allowed)}, cross-tenant in {sorted(denied)}",
                f"owner={sa}, cross={sb}", outcome, "CRITICAL", started, detail,
            )

    def query_pressure(self) -> None:
        c = self.cfg.get("query", {})
        base = self.cfg.get("core_rest")
        if not c.get("enabled", False) or not base:
            self.add(
                "QUERY-000", "query-pressure", "/sql",
                "analytics lab configured", "disabled/unavailable", "SKIP", "HIGH"
            )
            return
        auth = self._auth_from_env(c.get("auth", {}))
        denied = set(c.get("mutation_denied_status", [400, 401, 403, 405, 422]))

        with tempfile.TemporaryDirectory(prefix="hrkl-redteam-sql-") as td:
            sentinel = Path(td) / "sentinel.csv"
            sentinel.write_text(
                "secret\nHERACLITUS_REDTEAM_SENTINEL\n", encoding="utf-8"
            )
            sql = (
                "CREATE EXTERNAL TABLE redteam_probe STORED AS CSV LOCATION "
                + json.dumps(str(sentinel))
            )
            started = time.perf_counter()
            s, _, _ = self.request(base, "/sql", "POST", {"sql": sql}, auth)
            self.add(
                "QUERY-001", "query-pressure", "/sql",
                f"DDL rejected with {sorted(denied)}", f"HTTP {s}",
                "PASS" if s in denied else "FAIL", "CRITICAL", started,
                "external-table read primitive must remain closed",
            )

        started = time.perf_counter()
        s, _, _ = self.request(
            base, "/sql", "POST",
            {"sql": "INSERT INTO events SELECT * FROM events"}, auth,
        )
        self.add(
            "QUERY-002", "query-pressure", "/sql",
            f"DML rejected with {sorted(denied)}", f"HTTP {s}",
            "PASS" if s in denied else "FAIL", "CRITICAL", started,
            "read-only transport must not become a write primitive",
        )

        if not c.get("stress_enabled", False):
            self.add(
                "QUERY-003", "query-pressure", "/sql",
                "bounded concurrent valid-query campaign", "stress disabled",
                "SKIP", "HIGH",
                detail="enable only in isolated performance lab",
            )
            return

        workers = max(1, min(int(c.get("workers", 4)), 32))
        rounds = max(1, min(int(c.get("rounds", 16)), 128))
        query = c.get("stress_sql", "SELECT COUNT(*) AS n FROM events")
        timeout = min(float(c.get("timeout_seconds", 10.0)), 30.0)

        def one(_: int) -> tuple[int | None, float]:
            st, _, ms = self.request(
                base, "/sql", "POST", {"sql": query}, auth, timeout
            )
            return st, ms

        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            samples = list(ex.map(one, range(rounds)))
        health, _, _ = self.request(base, "/healthz")
        statuses = [x[0] for x in samples]
        latencies = sorted(x[1] for x in samples)
        p95 = latencies[max(0, int(len(latencies) * 0.95) - 1)] if latencies else 0.0
        good = health == 200 and all(s is not None for s in statuses)
        self.add(
            "QUERY-003", "query-pressure", "/sql",
            "server survives bounded concurrent valid queries",
            f"health={health}, p95={p95:.1f}ms",
            "PASS" if good else "FAIL", "HIGH", started,
            f"workers={workers}, rounds={rounds}; not a saturation benchmark",
        )

    @staticmethod
    def _wait_health(url: str, deadline_s: float) -> bool:
        _loopback_url(url, "admin health")
        u = urlsplit(url)
        end = time.time() + deadline_s
        while time.time() < end:
            try:
                c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=0.5)
                c.request("GET", u.path or "/healthz")
                r = c.getresponse()
                r.read()
                c.close()
                if r.status == 200:
                    return True
            except Exception:
                pass
            time.sleep(0.1)
        return False

    def admin_faults(self) -> None:
        c = self.cfg.get("admin_fault", {})
        if not c.get("enabled", False):
            self.add(
                "ADMIN-000", "admin-fault", "privileged operations",
                "fault-injection driver configured", "disabled", "SKIP", "CRITICAL",
                detail="runner kills only child processes it started",
            )
            return

        seed = Path(c["seed_data_dir"]).resolve()
        if not seed.is_dir():
            self.add(
                "ADMIN-001", "admin-fault", str(seed),
                "existing isolated seed data directory", "missing", "FAIL", "CRITICAL"
            )
            return

        server_argv = list(c["server_argv"])
        op_argv = list(c["operation_argv"])
        verify_argv = list(c["verify_argv"])
        health = c["health_url"]
        _loopback_url(health, "admin_fault.health_url")
        delays = [
            max(0, min(int(x), 10_000))
            for x in c.get("kill_delays_ms", [0, 10, 50, 200])
        ]

        for i, delay in enumerate(delays, start=1):
            aid = f"ADMIN-{i:03d}"
            started = time.perf_counter()
            with tempfile.TemporaryDirectory(prefix="hrkl-admin-fault-") as td:
                root = Path(td) / "data"
                shutil.copytree(seed, root)
                env = os.environ.copy()
                env["HERACLITUS_REDTEAM_DATA_DIR"] = str(root)
                server = subprocess.Popen(
                    _subst(server_argv, root),
                    cwd=c.get("cwd") or None,
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                try:
                    if not self._wait_health(
                        health, float(c.get("ready_timeout_seconds", 10))
                    ):
                        self.add(
                            aid, "admin-fault", "server child",
                            "server reaches health before fault", "not ready",
                            "FAIL", "CRITICAL", started,
                        )
                        continue
                    op = subprocess.Popen(
                        _subst(op_argv, root),
                        cwd=c.get("cwd") or None,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    time.sleep(delay / 1000.0)
                    server.kill()
                    server.wait(timeout=5)
                    try:
                        op.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        op.kill()
                        op.wait(timeout=2)

                    verify = subprocess.run(
                        _subst(verify_argv, root),
                        cwd=c.get("cwd") or None,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=float(c.get("verify_timeout_seconds", 30)),
                    )
                    self.add(
                        aid, "admin-fault", "privileged operation",
                        "verifier reaches a defined recoverable state",
                        f"verify rc={verify.returncode}",
                        "PASS" if verify.returncode == 0 else "FAIL",
                        "CRITICAL", started,
                        f"kill_delay_ms={delay}; verifier={verify.stdout[-300:].strip()}",
                    )
                finally:
                    if server.poll() is None:
                        server.kill()
                        server.wait(timeout=5)

    def hrkl_mutation(self) -> None:
        c = self.cfg.get("hrkl", {})
        if not c.get("enabled", False):
            self.add(
                "HRKL-000", "hrkl-mutation", "offline fixture copy",
                "HRKL fixture configured", "disabled", "SKIP", "CRITICAL"
            )
            return

        fixture = Path(c["fixture_dir"]).resolve()
        cli = list(c.get("cli_argv", ["target/release/heraclitus"]))
        if not fixture.is_dir():
            self.add(
                "HRKL-001", "hrkl-mutation", str(fixture),
                "existing fixture directory", "missing", "FAIL", "CRITICAL"
            )
            return

        with tempfile.TemporaryDirectory(prefix="hrkl-mutation-") as td:
            work = Path(td) / "db"
            shutil.copytree(fixture, work)
            segments = sorted(work.rglob("*.hrkl"))
            if not segments:
                self.add(
                    "HRKL-001", "hrkl-mutation", str(work),
                    "at least one .hrkl segment", "none found", "FAIL", "CRITICAL"
                )
                return

            segment = segments[0]
            baseline = subprocess.run(
                cli + ["verify", str(segment), "--logical"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=float(c.get("timeout_seconds", 30)),
            )
            if baseline.returncode != 0:
                self.add(
                    "HRKL-001", "hrkl-mutation", segment.name,
                    "baseline segment verifies", f"rc={baseline.returncode}",
                    "FAIL", "CRITICAL",
                    detail=baseline.stdout[-300:].strip(),
                )
                return

            self.add(
                "HRKL-001", "hrkl-mutation", segment.name,
                "baseline segment verifies", "rc=0", "PASS", "CRITICAL"
            )

            raw = bytearray(segment.read_bytes())
            if len(raw) < 32:
                self.add(
                    "HRKL-002", "hrkl-mutation", segment.name,
                    "segment large enough for mutation", f"{len(raw)} bytes",
                    "SKIP", "CRITICAL"
                )
            else:
                raw[len(raw) // 2] ^= 0x01
                segment.write_bytes(raw)
                mutated = subprocess.run(
                    cli + ["verify", str(segment), "--logical"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=float(c.get("timeout_seconds", 30)),
                )
                self.add(
                    "HRKL-002", "hrkl-mutation", segment.name,
                    "single-byte mutation rejected",
                    f"rc={mutated.returncode}",
                    "PASS" if mutated.returncode != 0 else "FAIL",
                    "CRITICAL",
                    detail=mutated.stdout[-300:].strip(),
                )

        manifest_dir = fixture / "manifests"
        manifests = sorted(manifest_dir.glob("*")) if manifest_dir.is_dir() else []
        if len(manifests) < 2:
            self.add(
                "HRKL-003", "hrkl-mutation", "HRKM",
                "two manifest generations for rollback probe",
                f"{len(manifests)} generation(s)", "SKIP", "HIGH"
            )
            return

        with tempfile.TemporaryDirectory(prefix="hrkl-rollback-") as td:
            work = Path(td) / "db"
            shutil.copytree(fixture, work)
            before = _tree_digest(work)
            wm = sorted((work / "manifests").glob("*"))
            wm[-1].unlink()
            after = _tree_digest(work)
            shown = subprocess.run(
                cli + ["manifest", "show", str(work)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=float(c.get("timeout_seconds", 30)),
            )
            product_rejected = shown.returncode != 0
            expect_reject = bool(c.get("expect_local_rollback_rejection", False))
            outcome = (
                ("PASS" if product_rejected else "FAIL")
                if expect_reject
                else ("PASS" if before != after else "FAIL")
            )
            self.add(
                "HRKL-003", "hrkl-mutation", "HRKM rollback",
                "rollback distinguishable from pinned external baseline",
                f"manifest-show rc={shown.returncode}, digest_changed={before != after}",
                outcome, "HIGH",
                detail=(
                    "local integrity is not freshness; pin head/root outside mutable host"
                    if not product_rejected
                    else "local manifest open rejected rollback"
                ),
            )

    @staticmethod
    def _tcp_alive(host: str, port: int, timeout: float = 1.5) -> bool:
        _loopback_host(host, "raft")
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def raft_hostile_peer(self) -> None:
        c = self.cfg.get("raft", {})
        targets = c.get("targets", [])
        if not c.get("enabled", False) or not targets:
            self.add(
                "RAFT-000", "raft-hostile-peer", "raft transport",
                "isolated raft target configured", "disabled/unavailable",
                "SKIP", "CRITICAL"
            )
            return

        for idx, t in enumerate(targets, start=1):
            host = t["host"]
            port = int(t["port"])
            _loopback_host(host, "raft target")
            target = f"{host}:{port}"
            started = time.perf_counter()
            if not self._tcp_alive(host, port):
                self.add(
                    f"RAFT-{idx:03d}A", "raft-hostile-peer", target,
                    "raft listener reachable in lab", "closed",
                    "FAIL", "CRITICAL", started,
                )
                continue

            try:
                with socket.create_connection((host, port), timeout=2) as s:
                    s.sendall((0xFFFF_FFFF).to_bytes(4, "little"))
                    s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            time.sleep(0.05)
            alive1 = self._tcp_alive(host, port)
            self.add(
                f"RAFT-{idx:03d}B", "raft-hostile-peer", target,
                "oversized frame rejected without killing listener",
                f"listener_alive={alive1}",
                "PASS" if alive1 else "FAIL", "HIGH", started,
            )

            try:
                with socket.create_connection((host, port), timeout=2) as s:
                    payload = b"HERACLITUS_NOT_A_RAFT_RPC"
                    s.sendall(len(payload).to_bytes(4, "little") + payload)
                    s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            time.sleep(0.05)
            alive2 = self._tcp_alive(host, port)
            self.add(
                f"RAFT-{idx:03d}C", "raft-hostile-peer", target,
                "malformed peer frame cannot kill listener",
                f"listener_alive={alive2}",
                "PASS" if alive2 else "FAIL", "HIGH",
            )

            require_auth = bool(c.get("require_authenticated_transport", False))
            self.add(
                f"RAFT-{idx:03d}D", "raft-hostile-peer", target,
                (
                    "authenticated/mTLS peer boundary"
                    if require_auth
                    else "declared private-network trust boundary"
                ),
                "raw TCP connection accepted",
                "FAIL" if require_auth else "FINDING",
                "CRITICAL" if require_auth else "HIGH",
                detail=(
                    "TCP reachability is not proof of Raft RPC authorization; "
                    "qualify network isolation separately"
                ),
            )

    def run(self) -> list[Result]:
        print(f"Deep-RedTeam-Heraclitus campaign={self.campaign_id} LOOPBACK-ONLY")
        for fn in (
            self.tenant_isolation,
            self.query_pressure,
            self.admin_faults,
            self.hrkl_mutation,
            self.raft_hostile_peer,
        ):
            try:
                fn()
            except Exception as exc:
                self.add(
                    f"RUNNER-{len(self.results) + 1:03d}",
                    fn.__name__, "runner", "no unhandled exception",
                    type(exc).__name__, "FAIL", "HIGH",
                    detail=str(exc)[:300],
                )
        return self.results


def self_test() -> int:
    rejected = False
    try:
        _loopback_url("http://192.0.2.10:1234", "self-test")
    except SystemExit:
        rejected = True
    if not rejected:
        print("SELFTEST FAIL: non-loopback URL accepted")
        return 2

    with tempfile.TemporaryDirectory(prefix="hrkl-redteam-selftest-") as td:
        p = Path(td)
        (p / "a").mkdir()
        (p / "a" / "x").write_text("1")
        d1 = _tree_digest(p)
        (p / "a" / "x").write_text("2")
        d2 = _tree_digest(p)
        if d1 == d2:
            print("SELFTEST FAIL: tree digest did not change")
            return 2

    print("SELFTEST PASS")
    return 0


def load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Authorized loopback-only deep red-team harness"
    )
    ap.add_argument("--config", default="config.example.json")
    ap.add_argument("--report")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()

    lab = Lab(load(args.config))
    results = lab.run()
    summary = {
        "total": len(results),
        "pass": sum(r.outcome == "PASS" for r in results),
        "fail": sum(r.outcome == "FAIL" for r in results),
        "finding": sum(r.outcome == "FINDING" for r in results),
        "skip": sum(r.outcome == "SKIP" for r in results),
    }
    out = {
        "schema": "heraclitus-deep-redteam/1",
        "campaign": lab.campaign_id,
        "generated_at_unix": int(time.time()),
        "results": [asdict(r) for r in results],
        "summary": summary,
    }
    report = Path(args.report or f"reports/{lab.campaign_id}.json")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\nSUMMARY {summary}; report={report}")
    return 2 if summary["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
