# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

"""Semeia VÁRIOS casos de fraude fictícios no HeraclitusDB (para a demo de grupos).

Cenário: empresas de fachada que trocam de sócio (laranja) antes de vencer licitações.
DOIS casos partilham o MESMO laranja (a "fábrica de laranjas") -> formam um GRUPO;
um terceiro caso usa outro laranja -> grupo separado. Tudo ligado por PROVENÊNCIA.

ATENÇÃO: aponte para a instância da DEMO. (Os eventos são imutáveis no log.)

  py demo/seed.py --addr 127.0.0.1:7474
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sdk", "python"))
import heraclitusdb  # noqa: E402


def _emit(db, kind, content, attrs, parents=None):
    lsn = db.append(kind, content, agent_id="demo-fraude",
                    session_id=attrs.get("caso", "x"), attrs=attrs, parents=parents or [])
    rows = db.query(f"MATCH (n) WHERE n.lsn = {lsn} RETURN n")
    return rows[0]["id"] if isinstance(rows, list) and rows else None


def _caso(db, caso, empresa, cnpj, laranja_id, laranja_nome, valor):
    emp = _emit(db, "Empresa", f"{empresa} - CNPJ {cnpj}", {"caso": caso, "cnpj": cnpj})
    troca = _emit(db, "TrocaSocietaria", f"Entra {laranja_nome} (laranja) na {empresa}",
                  {"caso": caso, "suspeita": "laranja"}, parents=[emp, laranja_id])
    licit = _emit(db, "Licitacao", f"Pregao vencido por {empresa} (R$ {valor})",
                  {"caso": caso, "valor": valor}, parents=[emp])
    _emit(db, "INSIGHT_FRAUDE",
          f"{empresa}: trocou para laranja dias antes de vencer licitacao milionaria.",
          {"caso": caso, "severidade": "CRITICA", "tipo": "fachada_licitacao"},
          parents=[troca, licit, laranja_id])
    return emp


def seed(addr):
    db = heraclitusdb.connect(addr)
    try:
        # Laranja RECORRENTE, partilhado entre 2 casos (a "fabrica de laranjas").
        maria = _emit(db, "Socio", "Maria Souza (laranja recorrente)",
                      {"caso": "rede", "laranja": "sim", "facilitador": "sim"})
        _caso(db, "A1", "Alfa Servicos LTDA", "11.222.333/0001-44", maria, "Maria Souza", "4200000")
        _caso(db, "A2", "Beta Comercio LTDA", "22.333.444/0001-55", maria, "Maria Souza", "3100000")
        # Caso separado, com outro laranja -> outro grupo.
        joao = _emit(db, "Socio", "Joao Pereira (laranja)", {"caso": "C1", "laranja": "sim"})
        _caso(db, "C1", "Gama Engenharia LTDA", "33.444.555/0001-66", joao, "Joao Pereira", "5800000")

        print("Casos de fraude semeados:")
        print("  Grupo 1 (laranja partilhado 'Maria Souza'):  A1 Alfa  +  A2 Beta")
        print("  Grupo 2 (laranja proprio 'Joao Pereira'):     C1 Gama")
        print("\nNo Console (:7480): clique em 'Fraudes' para ver os GRUPOS coloridos")
        print("e arraste a linha do tempo para ver cada caso a montar-se (AS OF).")
    finally:
        db.close()


def main():
    ap = argparse.ArgumentParser(description="Seeder da demo de fraude (HeraclitusDB)")
    ap.add_argument("--addr", default="127.0.0.1:7474")
    args = ap.parse_args()
    seed(args.addr)


if __name__ == "__main__":
    main()
