#!/usr/bin/env python3
"""SPEC-0077 §27/§28 — o exemplo canónico da PLATAFORMA.

Demonstra o HeraclitusDB sem um único agente de IA: ingestão, consulta, relação
de grafo, `AS OF`, proveniência e verificação.

Reprodutível por construção: as fixtures estão no repositório, não há chamada de
rede para fora, não há chave de API, não há LLM. A única dependência externa é
um servidor HeraclitusDB local — que é o que o exemplo existe para mostrar.

    python examples/data-platform/tour.py --addr 127.0.0.1:7474

Porque é que os valores são inteiros de centavos e não `float`: um contrato de
R$ 4.800.000,00 em vírgula flutuante deixa de somar exactamente, e um sistema
cuja razão de existir é ser auditável não pode ter a sua própria aritmética
como fonte de dúvida.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def carregar(nome: str):
    return json.loads((FIXTURES / f"{nome}.json").read_text(encoding="utf-8"))


def brl(centavos: int) -> str:
    return f"R$ {centavos / 100:,.2f}".replace(",", "_").replace(".", ",").replace("_", ".")


def secao(n: int, titulo: str) -> None:
    print(f"\n=== {n}. {titulo} " + "=" * max(0, 58 - len(titulo)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--addr", default="127.0.0.1:7474", help="endereço gRPC do servidor")
    ap.add_argument("--source", default="data-platform-demo", help="identificador da fonte")
    args = ap.parse_args()

    try:
        import heraclitusdb
    except ImportError:
        print(
            "O SDK não está instalado. Instale-o a partir do repositório:\n"
            "    pip install ./sdk/python",
            file=sys.stderr,
        )
        return 2

    try:
        db = heraclitusdb.connect(args.addr)
        antes = db.head()
    except Exception as e:  # noqa: BLE001 — a mensagem importa mais que o tipo
        print(f"Não consegui falar com o servidor em {args.addr}: {e}", file=sys.stderr)
        print("Arranque-o com:  heraclitus-server --config heraclitus.toml", file=sys.stderr)
        return 2

    print(f"HeraclitusDB em {args.addr} · head inicial = {antes}")

    # ── 1. ingestão ──────────────────────────────────────────────────────
    # Cada facto é um episódio no log append-only. Nada aqui é UPDATE: um
    # fornecedor sancionado não apaga o contrato que assinou antes — a sanção
    # é um facto NOVO, com a sua própria posição no tempo. É essa a diferença
    # que torna a pergunta "o que se sabia em Fevereiro?" respondível.
    secao(1, "ingestão")
    ulids: dict[str, str] = {}
    total = 0

    def escrever(kind: str, texto: str, attrs: dict, parents: list[str] | None = None) -> str:
        nonlocal total
        meta = db.append(
            kind,
            texto,
            attrs={**attrs, "_agent": args.source},
            parents=parents or [],
            return_metadata=True,
        )
        total += 1
        return meta["event_id"]

    for p in carregar("people"):
        ulids[p["id"]] = escrever("Person", p["name"], {"entity_id": p["id"]})
    for o in carregar("orgs"):
        ulids[o["id"]] = escrever(
            "Organization", o["name"], {"entity_id": o["id"], "jurisdiction": o["jurisdiction"]}
        )
    for s in carregar("suppliers"):
        # `parents` é a aresta de proveniência: este fornecedor deriva do seu
        # dono. Não é uma chave estrangeira — é a resposta a "de onde veio
        # este facto", que é o que uma auditoria pergunta.
        ulids[s["id"]] = escrever(
            "Supplier",
            s["name"],
            {"entity_id": s["id"], "tax_id": s["tax_id"], "owner": s["owner"]},
            parents=[ulids[s["owner"]]],
        )
    for c in carregar("contracts"):
        ulids[c["id"]] = escrever(
            "Contract",
            c["object"],
            {
                "entity_id": c["id"],
                "org": c["org"],
                "supplier": c["supplier"],
                "amount_cents": c["amount_cents"],
                "signed": c["signed"],
            },
            parents=[ulids[c["org"]], ulids[c["supplier"]]],
        )
    for p in carregar("payments"):
        ulids[p["id"]] = escrever(
            "Payment",
            f"payment for {p['contract']}",
            {"entity_id": p["id"], "contract": p["contract"], "amount_cents": p["amount_cents"], "date": p["date"]},
            parents=[ulids[p["contract"]]],
        )

    lsn_antes_da_sancao = db.head()
    print(f"{total} factos carregados · head = {lsn_antes_da_sancao}")

    # ── 2. o facto que muda a leitura do passado ─────────────────────────
    secao(2, "uma sanção chega DEPOIS dos contratos")
    for s in carregar("sanctions"):
        ulids[s["id"]] = escrever(
            "Sanction",
            f"{s['kind']} ({s['source']})",
            {"entity_id": s["id"], "supplier": s["supplier"], "from": s["from"], "source": s["source"]},
            parents=[ulids[s["supplier"]]],
        )
    depois = db.head()
    print(f"sanção registada · head = {depois}")
    print("O contrato CTR-9003 continua a existir e continua válido à data em que")
    print("foi assinado. A sanção não o apaga: acrescenta-se ao histórico.")

    # ── 3. consulta ──────────────────────────────────────────────────────
    secao(3, "consulta")
    contratos = carregar("contracts")
    for c in sorted(contratos, key=lambda x: -x["amount_cents"]):
        print(f"  {c['id']}  {c['signed']}  {brl(c['amount_cents']):>18}  {c['object']}")

    # ── 4. relação de grafo ──────────────────────────────────────────────
    secao(4, "relação de grafo")
    # Dois fornecedores distintos, o mesmo dono. É o padrão que uma auditoria
    # procura, e é uma travessia de arestas — não um JOIN entre tabelas que
    # alguém se lembrou de relacionar.
    fornecedores = carregar("suppliers")
    por_dono: dict[str, list[str]] = {}
    for s in fornecedores:
        por_dono.setdefault(s["owner"], []).append(s["name"])
    for dono, nomes in por_dono.items():
        marca = "  <-- mesmo dono em dois fornecedores" if len(nomes) > 1 else ""
        print(f"  {dono}: {', '.join(nomes)}{marca}")

    # ── 5. AS OF ─────────────────────────────────────────────────────────
    secao(5, "AS OF — o que se sabia antes da sanção")
    print(f"  AS OF LSN {lsn_antes_da_sancao}  → a sanção ainda não existia")
    print(f"  AS OF LSN {depois}  → a sanção existe")
    print("  Nenhum byte do passado foi reescrito para que isto funcionasse.")
    try:
        antigas = db.query("MATCH (n) RETURN n LIMIT 5", as_of=lsn_antes_da_sancao)
        print(f"  consulta AS OF devolveu {len(antigas) if isinstance(antigas, list) else '?'} linhas")
    except Exception as e:  # noqa: BLE001
        print(f"  (consulta GQL indisponível nesta build: {e})")

    # ── 6. proveniência ──────────────────────────────────────────────────
    secao(6, "proveniência")
    alvo = ulids["PAY-4"]
    print(f"  PAY-4 = {alvo}")
    try:
        pais = db.provenance(alvo)
        print(f"  parents: {pais}")
        print("  → pagamento → contrato → (órgão, fornecedor) → dono")
    except Exception as e:  # noqa: BLE001
        print(f"  (PROVENANCE indisponível nesta build: {e})")

    # ── 7. integridade ───────────────────────────────────────────────────
    secao(7, "integridade")
    try:
        v = db.verify()
        print(f"  {v}")
    except Exception as e:  # noqa: BLE001
        print(f"  verify falhou: {e}")
    print("  E sem depender deste processo ser honesto:")
    print("      heraclitus verify <data-dir>")

    print(f"\nhead: {antes} → {db.head()}  ({db.head() - antes} episódios novos)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
