#!/usr/bin/env python3
"""Um agente de exemplo que manda evidência para o Heraclitus Agent Black Box.

SPEC-0074 §27 / SPEC-0076 §21 — o demo canónico:

    1. o agente procura um fornecedor
    2. lê o preço
    3. tenta um pagamento pequeno
    4. tenta um pagamento grande

Sem chave de API, sem serviço pago, sem rede para fora. O que este script faz é
falar OpenTelemetry com o Heraclitus exactamente como a aplicação real falaria.

    python sample.py
    python sample.py --endpoint http://localhost:4318

Porque é que isto não usa o SDK do OpenTelemetry
------------------------------------------------
Porque o objectivo é provar que **não é preciso nada** para começar. O SDK é a
forma normal de instrumentar uma aplicação a sério; aqui, um POST de JSON com a
forma OTLP mostra que a promessa de §0.1 — "se a aplicação já exporta
OpenTelemetry, o primeiro run deve aparecer sem outra dependência obrigatória" —
não esconde um passo de instalação.

Se já tiver o SDK instalado, este mesmo agente aparece na Consola com:

    export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
    opentelemetry-instrument python a-sua-aplicacao.py
"""

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
CONSOLE = os.environ.get("HERACLITUS_CONSOLE", "http://localhost:8080")


def hexid(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def now_ns() -> int:
    return time.time_ns()


def attr(key: str, value):
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": str(value)}}


def span(trace_id, span_id, parent, name, start, end, attrs, error=None):
    s = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": 1,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(end),
        "attributes": attrs,
    }
    if parent:
        s["parentSpanId"] = parent
    if error:
        s["status"] = {"code": "STATUS_CODE_ERROR", "message": error}
        s["attributes"] = attrs + [attr("error.type", "ToolError")]
    else:
        s["status"] = {"code": "STATUS_CODE_OK"}
    return s


def build_batch(run_id: str):
    trace_id = hexid(32)
    root = hexid(16)
    t0 = now_ns()

    spans = []

    # O run.
    spans.append(
        span(
            trace_id,
            root,
            None,
            "invoke_agent procurement-agent",
            t0,
            t0 + 14_000_000_000,
            [
                attr("gen_ai.operation.name", "invoke_agent"),
                attr("gen_ai.agent.id", "procurement-agent"),
                attr("gen_ai.agent.name", "Procurement Agent"),
                attr("gen_ai.system", "demo"),
                # Atributos próprios: ligam o run a uma pessoa e a um inquilino
                # sem obrigar a aplicação a falar com uma API nossa.
                attr("heraclitus.agent.run_id", run_id),
                attr("heraclitus.agent.tenant", "default"),
                attr("heraclitus.agent.human.subject", "jose@example"),
            ],
        )
    )

    # O modelo escolhe a ferramenta.
    spans.append(
        span(
            trace_id,
            hexid(16),
            root,
            "chat demo-model",
            t0 + 500_000_000,
            t0 + 1_800_000_000,
            [
                attr("gen_ai.operation.name", "chat"),
                attr("gen_ai.system", "demo"),
                attr("gen_ai.request.model", "demo-model"),
                attr("gen_ai.response.model", "demo-model"),
                attr("gen_ai.usage.input_tokens", 412),
                attr("gen_ai.usage.output_tokens", 88),
                # Isto NÃO vai ficar em claro no histórico: o portão de
                # privacidade redige o valor e guarda só a chave e o hash.
                attr("gen_ai.prompt", "pagar a fatura do fornecedor 8832"),
                attr("heraclitus.agent.run_id", run_id),
            ],
        )
    )

    # 1. Consulta de fornecedor.
    spans.append(
        span(
            trace_id,
            hexid(16),
            root,
            "execute_tool lookup_vendor",
            t0 + 2_000_000_000,
            t0 + 2_400_000_000,
            [
                attr("gen_ai.operation.name", "execute_tool"),
                attr("gen_ai.tool.name", "lookup_vendor"),
                attr("gen_ai.tool.call.id", f"{run_id}-call-1"),
                attr("heraclitus.agent.server", "finance"),
                attr("heraclitus.agent.run_id", run_id),
                attr("vendor_id", "vendor-8832"),
            ],
        )
    )

    # 2. Leitura de preço.
    spans.append(
        span(
            trace_id,
            hexid(16),
            root,
            "execute_tool read_invoice",
            t0 + 2_500_000_000,
            t0 + 2_900_000_000,
            [
                attr("gen_ai.operation.name", "execute_tool"),
                attr("gen_ai.tool.name", "read_invoice"),
                attr("gen_ai.tool.call.id", f"{run_id}-call-2"),
                attr("heraclitus.agent.server", "finance"),
                attr("heraclitus.agent.run_id", run_id),
                attr("amount", 4200),
            ],
        )
    )

    # 3. Pagamento pequeno — corre bem.
    spans.append(
        span(
            trace_id,
            hexid(16),
            root,
            "execute_tool send_payment",
            t0 + 3_200_000_000,
            t0 + 4_100_000_000,
            [
                attr("gen_ai.operation.name", "execute_tool"),
                attr("gen_ai.tool.name", "send_payment"),
                attr("gen_ai.tool.call.id", f"{run_id}-call-3"),
                attr("heraclitus.agent.server", "finance"),
                attr("heraclitus.agent.run_id", run_id),
                attr("amount", 4200),
                attr("account", "vendor-8832"),
                attr("heraclitus.agent.external_effect_id", "payment-84722"),
            ],
        )
    )

    # 4. Pagamento grande — falha no upstream. A timeline tem de o mostrar.
    spans.append(
        span(
            trace_id,
            hexid(16),
            root,
            "execute_tool send_payment",
            t0 + 5_000_000_000,
            t0 + 6_400_000_000,
            [
                attr("gen_ai.operation.name", "execute_tool"),
                attr("gen_ai.tool.name", "send_payment"),
                attr("gen_ai.tool.call.id", f"{run_id}-call-4"),
                attr("heraclitus.agent.server", "finance"),
                attr("heraclitus.agent.run_id", run_id),
                attr("amount", 75000),
                attr("account", "vendor-8832"),
            ],
            error="payment above approval threshold",
        )
    )

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        attr("service.name", "procurement-agent"),
                        attr("service.version", "1.0.0"),
                        attr("service.instance.id", "sample-1"),
                        attr("deployment.environment.name", "demo"),
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {
                            "name": "heraclitus.sample-python-agent",
                            "version": "1.0.0",
                        },
                        "spans": spans,
                    }
                ],
            }
        ]
    }


def post(endpoint: str, payload: dict) -> dict:
    url = endpoint.rstrip("/") + "/v1/traces"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8") or "{}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--endpoint", default=ENDPOINT, help="OTLP/HTTP endpoint")
    ap.add_argument("--console", default=CONSOLE, help="URL da Consola")
    ap.add_argument("--runs", type=int, default=1, help="quantos runs enviar")
    ap.add_argument(
        "--retransmit",
        action="store_true",
        help="manda o MESMO lote duas vezes, para mostrar que não duplica",
    )
    args = ap.parse_args()

    for i in range(args.runs):
        run_id = f"run-{hexid(10)}"
        batch = build_batch(run_id)
        try:
            out = post(args.endpoint, batch)
        except urllib.error.URLError as e:
            print(f"não foi possível falar com {args.endpoint}: {e}", file=sys.stderr)
            print(
                "\nO Heraclitus está a correr?\n"
                "  cd examples/agent-black-box && docker compose up -d\n",
                file=sys.stderr,
            )
            return 1

        h = out.get("heraclitus", {})
        print(
            f"run {run_id}: {h.get('accepted', '?')} evidências aceites, "
            f"{h.get('duplicated', 0)} duplicadas, "
            f"{h.get('ignoredSpans', 0)} spans ignorados"
        )

        if args.retransmit:
            again = post(args.endpoint, batch)
            hh = again.get("heraclitus", {})
            print(
                f"  retransmissão: {hh.get('accepted', 0)} aceites, "
                f"{hh.get('duplicated', 0)} duplicadas "
                "(a retransmissão não duplica a história — SPEC-0074 §14)"
            )
        if i + 1 < args.runs:
            time.sleep(0.2)

    print(f"\nAbra {args.console.rstrip('/')} para ver a timeline.")
    print("Depois:")
    print("  1. abra o run")
    print("  2. carregue em «Export Evidence Bundle»")
    print("  3. heraclitus agent verify evidence-<id>.zip")
    print("  4. mude um byte do ficheiro e verifique outra vez — tem de falhar")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
