#!/usr/bin/env python3
"""Um servidor MCP mínimo, para testar o Agent Gateway sem depender da Internet.

black-box-in-action.md §22 pede um script que teste o gateway ANTES de envolver
o Claude Code ou o Codex. Esse teste precisa de um upstream — e um teste cuja
primeira condição é "um serviço de terceiros tem de estar de pé" não é um teste,
é uma aposta.

Este stub não substitui o upstream real. O §3 quer, e com razão, uma integração
contra um servidor MCP verdadeiro; o que isto dá é a capacidade de separar
*"o gateway está partido"* de *"o upstream está em baixo"*, que é a distinção
que custa uma tarde quando não existe.

Fala MCP sobre HTTP com JSON-RPC 2.0. Implementa o mínimo que o §7 exige que se
consiga distinguir:

    initialize    NÃO deve gerar evidência
    tools/list    NÃO deve gerar evidência
    ping          NÃO deve gerar evidência
    tools/call    DEVE gerar evidência

As tools são deliberadamente sem efeitos colaterais: `echo` devolve o que
recebeu, `slow` dorme, `fail` devolve um erro. A terceira existe porque um teste
que só exercita o caminho feliz não prova que o gateway regista um `error` como
`error`.

    python3 scripts/mcp-upstream-stub.py --port 9911
"""

from __future__ import annotations

import argparse
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL_VERSION = "2026-07-28"

TOOLS = [
    {
        "name": "echo",
        "description": "Devolve o texto recebido. Sem efeitos colaterais.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "lookup_vendor",
        "description": "Procura um fornecedor fictício. Sem efeitos colaterais.",
        "inputSchema": {
            "type": "object",
            "properties": {"vendor": {"type": "string"}},
            "required": ["vendor"],
        },
    },
    {
        "name": "slow",
        "description": "Dorme `ms` milissegundos. Para exercitar timeouts.",
        "inputSchema": {
            "type": "object",
            "properties": {"ms": {"type": "integer"}},
            "required": ["ms"],
        },
    },
    {
        "name": "fail",
        "description": "Devolve sempre um erro de ferramenta.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

# Contadores, para o script de teste poder afirmar que o upstream FOI ou NÃO FOI
# contactado. É isto que prova a diferença entre `shadow` e `enforce`: em
# enforce+deny, este número não pode mexer.
HITS: dict[str, int] = {}
HITS_LOCK = threading.Lock()


def conta(metodo: str) -> None:
    with HITS_LOCK:
        HITS[metodo] = HITS.get(metodo, 0) + 1


def resultado(id_, payload):
    return {"jsonrpc": "2.0", "id": id_, "result": payload}


def erro(id_, codigo, mensagem):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": codigo, "message": mensagem}}


def tratar(req: dict) -> dict | None:
    metodo = req.get("method", "")
    id_ = req.get("id")
    conta(metodo)

    if metodo == "initialize":
        return resultado(
            id_,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "heraclitus-mcp-stub", "version": "1.0.0"},
            },
        )

    # Uma notificação (sem `id`) não leva resposta. O MCP manda
    # `notifications/initialized` depois do handshake.
    if id_ is None:
        return None

    if metodo == "ping":
        return resultado(id_, {})

    if metodo == "tools/list":
        return resultado(id_, {"tools": TOOLS})

    if metodo == "tools/call":
        params = req.get("params") or {}
        nome = params.get("name", "")
        args = params.get("arguments") or {}
        if nome == "echo":
            texto = str(args.get("text", ""))
            return resultado(
                id_, {"content": [{"type": "text", "text": texto}], "isError": False}
            )
        if nome == "lookup_vendor":
            fornecedor = str(args.get("vendor", ""))
            return resultado(
                id_,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "vendor": fornecedor,
                                    "status": "active",
                                    "note": "dados fictícios de um stub de teste",
                                }
                            ),
                        }
                    ],
                    "isError": False,
                },
            )
        if nome == "slow":
            time.sleep(min(int(args.get("ms", 0)), 30_000) / 1000.0)
            return resultado(
                id_, {"content": [{"type": "text", "text": "acordei"}], "isError": False}
            )
        if nome == "fail":
            return resultado(
                id_,
                {
                    "content": [{"type": "text", "text": "esta ferramenta falha sempre"}],
                    "isError": True,
                },
            )
        return erro(id_, -32602, f"tool desconhecida: {nome}")

    return erro(id_, -32601, f"método não suportado: {metodo}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"[stub] {self.address_string()} {fmt % args}", flush=True)

    def _responder(self, status: int, corpo: bytes, tipo="application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def do_GET(self):
        # Um canal só de diagnóstico do teste. NÃO faz parte do MCP: é por aqui
        # que o script pergunta "o upstream foi contactado?", e a resposta a essa
        # pergunta é o que separa `shadow` de `enforce`.
        if re.fullmatch(r"/__hits/?", self.path):
            with HITS_LOCK:
                corpo = json.dumps(dict(HITS)).encode()
            return self._responder(200, corpo)
        if re.fullmatch(r"/__reset/?", self.path):
            with HITS_LOCK:
                HITS.clear()
            return self._responder(200, b'{"ok":true}')
        return self._responder(404, b'{"error":"not found"}')

    def do_POST(self):
        tamanho = int(self.headers.get("Content-Length") or 0)
        if tamanho > 8 * 1024 * 1024:
            return self._responder(413, b'{"error":"corpo grande demais"}')
        cru = self.rfile.read(tamanho)
        try:
            pedido = json.loads(cru or b"{}")
        except json.JSONDecodeError:
            return self._responder(
                400, json.dumps(erro(None, -32700, "JSON inválido")).encode()
            )

        # Um lote JSON-RPC é uma lista.
        if isinstance(pedido, list):
            respostas = [r for r in (tratar(p) for p in pedido) if r is not None]
            if not respostas:
                return self._responder(202, b"")
            return self._responder(200, json.dumps(respostas).encode())

        resposta = tratar(pedido)
        if resposta is None:
            return self._responder(202, b"")
        return self._responder(200, json.dumps(resposta).encode())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=9911)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    servidor = ThreadingHTTPServer((args.host, args.port), Handler)
    print(
        f"stub MCP em http://{args.host}:{args.port}/  "
        f"(protocolo {PROTOCOL_VERSION}; tools: {', '.join(t['name'] for t in TOOLS)})",
        flush=True,
    )
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
