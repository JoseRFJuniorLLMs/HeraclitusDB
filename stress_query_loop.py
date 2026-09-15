#!/usr/bin/env python3
"""
Generator de Carga e Consultas Continuas para HeraclitusDB.
Executa em loop continuo todas as consultas possiveis na API REST (stats, state, views, compliance, etc.).
"""

import time
import urllib.request
import urllib.error
import json
import threading
import sys

BASE_URL = "http://127.0.0.1:7475"

ENDPOINTS = [
    "/stats",
    "/healthz",
    "/metrics",
    "/state",
    "/compliance/status",
    "/telemetry/health",
    "/sentinel/status",
    "/security/events",
    "/security/events/counts",
    "/cases",
    "/content",
    "/verify",
    "/fontes",
    "/atributos",
    "/titular/1",
    "/titular/1/acessos",
    "/hvm/state",
]

def make_request(path):
    url = f"{BASE_URL}{path}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Heraclitus-Query-Stress/1.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status, len(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, 0
    except Exception as e:
        return 500, 0

def worker_loop(thread_id, stats_dict):
    while True:
        for ep in ENDPOINTS:
            status, size = make_request(ep)
            stats_dict["total_queries"] += 1
            if status < 400:
                stats_dict["success"] += 1
            else:
                stats_dict["errors"] += 1
            time.sleep(0.01)

def main():
    print(f"⚡ Iniciando Gerador de Consultas Continuas para HeraclitusDB ({BASE_URL})...")
    print(f"🔍 Endpoints alvo ({len(ENDPOINTS)} rotas): {', '.join(ENDPOINTS)}")
    
    stats_dict = {"total_queries": 0, "success": 0, "errors": 0}
    threads = []

    # 4 Threads concorrentes de consulta contínua
    for i in range(4):
        t = threading.Thread(target=worker_loop, args=(i, stats_dict), daemon=True)
        t.start()
        threads.append(t)

    t0 = time.time()
    try:
        while True:
            time.sleep(2)
            elapsed = time.time() - t0
            qps = stats_dict["total_queries"] / elapsed if elapsed > 0 else 0
            print(f" [LOAD GEN] Total Consultas: {stats_dict['total_queries']} | QPS Médio: {qps:.1f} req/s | Sucessos: {stats_dict['success']} | Erros: {stats_dict['errors']}")
    except KeyboardInterrupt:
        print("\nGerador de consultas interrompido.")

if __name__ == "__main__":
    main()
