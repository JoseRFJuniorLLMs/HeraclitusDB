# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

"""Compatibilidade BI — Fase A (export).

Lê as visões materializadas do HeraclitusDB e escreve tabelas planas (CSV/Parquet)
que o Metabase / PowerBI consomem nativamente. É o caminho pragmático: 80% do valor
de adoção em minutos, sem implementar o protocolo Postgres (Fase B / pgwire).

  py bi/export_bi.py --out ./export --format csv
  py bi/export_bi.py --addr 127.0.0.1:7474 --gql "MATCH (n) RETURN n" --format parquet
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sdk", "python"))
import heraclitusdb  # noqa: E402


def export(addr, out_dir, gql, fmt):
    os.makedirs(out_dir, exist_ok=True)
    db = heraclitusdb.connect(addr)
    try:
        df = db.query_df(gql)
    finally:
        db.close()

    # achata colunas dict/list (attrs) para o BI; mantém como texto.
    for col in df.columns:
        if df[col].map(lambda v: isinstance(v, (dict, list))).any():
            df[col] = df[col].map(lambda v: v if not isinstance(v, (dict, list)) else _json(v))

    base = os.path.join(out_dir, "heraclitus_nodes")
    if fmt == "parquet":
        path = base + ".parquet"
        df.to_parquet(path, index=False)
    else:
        path = base + ".csv"
        df.to_csv(path, index=False, encoding="utf-8")
    return path, df.shape


def _json(v):
    import json
    return json.dumps(v, ensure_ascii=False, default=str)


def main():
    ap = argparse.ArgumentParser(description="Export BI (Fase A) do HeraclitusDB")
    ap.add_argument("--addr", default="127.0.0.1:7474")
    ap.add_argument("--out", default="./export")
    ap.add_argument("--gql", default="MATCH (n) RETURN n", help="view/consulta a exportar")
    ap.add_argument("--format", choices=["csv", "parquet"], default="csv")
    args = ap.parse_args()

    path, shape = export(args.addr, args.out, args.gql, args.format)
    print(f"[OK] Exportado: {path}  ({shape[0]} linhas x {shape[1]} colunas)")
    print("     Abra no Metabase/PowerBI como fonte de dados (CSV/Parquet).")


if __name__ == "__main__":
    main()
