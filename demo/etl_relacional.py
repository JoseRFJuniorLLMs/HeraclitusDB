# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

r"""ETL relacional generico (pai <- filhos) -> HeraclitusDB.

Carrega pastas multi-ficheiro do Portal onde ha' um ficheiro PAI (a entidade
principal) e ficheiros FILHOS ligados por uma chave composta. Usa o mesmo truque
de desempenho do etl_servidores: append puro + resolucao LSN->ULID em BLOCO
(zero lookups por no'), construindo as arestas `parents`.

Cobre (config DATASETS):
  202401_Licitacoes : Licitacao  <- ItemLicitacao, Participacao
  202601_Compras    : Compra     <- ItemCompra, TermoAditivo

Teia resultante:
  Licitacao  ──◄ ItemLicitacao / Participacao   (chave: Numero Licitacao+UG+Modalidade)
  Compra     ──◄ ItemCompra / TermoAditivo      (chave: Numero Contrato+UG)
  (Compra guarda tambem num_licitacao + cnpj do contratado como atributos -> cruza
   com Licitacoes e com fornecedores por consulta.)

USO (py 3.14):  py demo/etl_relacional.py --root D:\dados-governo
                py demo/etl_relacional.py --only 202601_Compras --limit 500
"""
import argparse
import csv
import glob
import os
import sys
import time
import unicodedata

csv.field_size_limit(16 * 1024 * 1024)
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "sdk", "python"))
import heraclitusdb  # noqa: E402

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(it=None, **k):
        return it if it is not None else iter(())

AGENT = "etl-relacional"
PAGE = 50000

# ── Config: (ficheiro, kind, [colunas-chave], coluna-label, {attr: coluna}) ──
# As colunas-chave de pai e filho mapeiam-se por POSICAO (mesmo valor -> mesma chave).
DATASETS = {
    "Licitacoes": {
        "parent": ("{mes}_Licitação.csv", "Licitacao",
                   ["Número Licitação", "Código UG", "Código Modalidade Compra"],
                   "Objeto",
                   {"orgao": "Nome Órgão", "modalidade": "Modalidade Compra",
                    "valor": "Valor Licitação", "situacao": "Situação Licitação",
                    "uf": "UF", "municipio": "Município", "abertura": "Data Abertura",
                    "num_licitacao": "Número Licitação"}),
        "children": [
            ("{mes}_ItemLicitação.csv", "ItemLicitacao",
             ["Número Licitação", "Código UG", "Código Modalidade Compra"],
             "Descrição",
             {"valor": "Valor Item", "qtd": "Quantidade Item",
              "vencedor": "Nome Vencedor", "cod_vencedor": "Código Vencedor"}),
            ("{mes}_ParticipantesLicitação.csv", "Participacao",
             ["Número Licitação", "Código UG", "Código Modalidade Compra"],
             "Nome Participante",
             {"cod_participante": "Código Participante", "vencedor_flag": "Flag Vencedor",
              "item": "Descrição Item Compra"}),
            ("{mes}_EmpenhosRelacionados.csv", "Empenho",
             ["Número Licitação", "Código UG", "Código Modalidade Compra"],
             "Código Empenho",
             {"valor": "Valor Empenho (R$)", "data": "Data Emissao Empenho",
              "obs": "Observação Empenho", "ug": "Nome UG", "processo": "Número Processo"}),
        ],
    },
    "Compras": {
        "parent": ("{mes}_Compras.csv", "Compra",
                   ["Número do Contrato", "Código UG"],
                   "Objeto",
                   {"orgao": "Nome Órgão", "contratado": "Nome Contratado",
                    "cnpj": "Código Contratado", "valor_inicial": "Valor Inicial Compra",
                    "valor_final": "Valor Final Compra", "modalidade": "Modalidade Compra",
                    "assinatura": "Data Assinatura Contrato", "num_licitacao": "Número Licitação"}),
        "children": [
            ("{mes}_ItemCompra.csv", "ItemCompra", ["Número Contrato", "Código UG"],
             "Descrição Item Compra", {"valor": "Valor Item", "qtd": "Quantidade Item"}),
            ("{mes}_TermoAditivo.csv", "TermoAditivo", ["Número Contrato", "Código UG"],
             "Objeto", {"numero": "Número Termo Aditivo", "data": "Data Publicação"}),
            ("{mes}_Apostilamento.csv", "Apostilamento", ["Número Contrato", "Código UG"],
             "Descrição Apostilamento",
             {"numero": "Número Apostilamento", "valor": "Valor Apostilamento",
              "data": "Data de inclusao", "situacao": "Situação Apostilamento",
              "orgao": "Nome Orgao", "ug": "Nome UG"}),
        ],
    },
}


def _norm(s):
    s = unicodedata.normalize("NFKD", s or "")
    s = "".join(c for c in s if not unicodedata.combining(c))
    return " ".join(s.lower().split())


def _resolve_cols(header_norm, names):
    """nome de coluna -> indice (igualdade normalizada; fallback 'contem')."""
    out = []
    for nm in names:
        nn = _norm(nm)
        idx = next((i for i, h in enumerate(header_norm) if h == nn), None)
        if idx is None:
            idx = next((i for i, h in enumerate(header_norm) if nn in h or h in nn), None)
        out.append(idx)
    return out


def _cell(row, i):
    return (row[i].strip() if i is not None and i < len(row) else "")


def _key(row, idxs):
    return "|".join(_cell(row, i) for i in idxs)


def _open(path):
    fh = open(path, "r", encoding="latin-1", errors="replace", newline="")
    rd = csv.reader(fh, delimiter=";", quotechar='"')
    try:
        header = next(rd)
    except StopIteration:
        fh.close()
        return None, None, None
    return fh, rd, [_norm(h) for h in header]


def _attrs(row, hn, attr_map, extra):
    a = dict(extra)
    for k, col in attr_map.items():
        idx = _resolve_cols(hn, [col])[0]
        v = _cell(row, idx)
        if v:
            a[k] = v[:120]
    return a


def load_folder(db, folder, mes, cfg, limit, build_prov, totals):
    base = os.path.basename(folder)
    pf, pkind, pkeys, plabel, pattrs = cfg["parent"]
    print(f"\n=== {base}  (pai = {pkind}) ===")

    # PASSO 1: pai (append puro, chave-composta -> LSN)
    ppath = os.path.join(folder, pf.format(mes=mes))
    key2lsn, min_lsn, max_lsn, n = {}, None, None, 0
    if os.path.exists(ppath):
        fh, rd, hn = _open(ppath)
        kidx = _resolve_cols(hn, pkeys)
        lidx = _resolve_cols(hn, [plabel])[0]
        for row in tqdm(rd, desc=f"{base}/{pkind}", unit="x"):
            if not row:
                continue
            k = _key(row, kidx)
            a = _attrs(row, hn, pattrs, {"chave": k, "tipo": pkind.lower(), "base": base, "mes": mes})
            lsn = db.append(pkind, _cell(row, lidx) or k, agent_id=AGENT, attrs=a)
            key2lsn[k] = lsn
            min_lsn = lsn if min_lsn is None else min(min_lsn, lsn)
            max_lsn = lsn if max_lsn is None else max(max_lsn, lsn)
            n += 1
            if limit and n >= limit:
                break
        fh.close()
        totals[pkind] = totals.get(pkind, 0) + n
        print(f"  {pkind}: {n}")

    # PASSO 2: resolucao LSN->ULID em bloco
    key2ulid = {}
    if build_prov and key2lsn:
        wanted, lsn2ulid, start = set(key2lsn.values()), {}, min_lsn
        with tqdm(total=max_lsn - min_lsn + 1, desc=f"{base}/ULID", unit="lsn") as bar:
            while start <= max_lsn:
                end = min(start + PAGE - 1, max_lsn)
                rows = db.query(f"MATCH (n) WHERE n.lsn >= {start} AND n.lsn <= {end} RETURN n")
                if isinstance(rows, list):
                    for r in rows:
                        if r.get("lsn") in wanted:
                            lsn2ulid[r["lsn"]] = r.get("id")
                bar.update(end - start + 1)
                start = end + 1
        key2ulid = {k: lsn2ulid[l] for k, l in key2lsn.items() if l in lsn2ulid}
        print(f"  ULIDs: {len(key2ulid)}/{len(key2lsn)}")

    # PASSO 3: filhos (parents = [ULID do pai])
    for cf, ckind, ckeys, clabel, cattrs in cfg["children"]:
        cpath = os.path.join(folder, cf.format(mes=mes))
        if not os.path.exists(cpath):
            continue
        fh, rd, hn = _open(cpath)
        kidx = _resolve_cols(hn, ckeys)
        lidx = _resolve_cols(hn, [clabel])[0]
        n, orf = 0, 0
        for row in tqdm(rd, desc=f"{base}/{ckind}", unit="x"):
            if not row:
                continue
            k = _key(row, kidx)
            u = key2ulid.get(k)
            if not u:
                orf += 1
            a = _attrs(row, hn, cattrs, {"chave": k, "tipo": ckind.lower(), "base": base, "mes": mes})
            db.append(ckind, _cell(row, lidx) or k, agent_id=AGENT, attrs=a, parents=[u] if u else [])
            n += 1
            if limit and n >= limit:
                break
        fh.close()
        totals[ckind] = totals.get(ckind, 0) + n
        print(f"  {ckind}: {n}" + (f"  ({orf} sem pai)" if orf else ""))


def main():
    ap = argparse.ArgumentParser(description="ETL relacional pai<-filhos -> HeraclitusDB")
    ap.add_argument("--root", default=r"D:\dados-governo")
    ap.add_argument("--addr", default="127.0.0.1:7474")
    ap.add_argument("--only", nargs="*", help="apenas estas pastas")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-prov", action="store_true")
    args = ap.parse_args()

    all_dirs = sorted(d for d in glob.glob(os.path.join(args.root, "*")) if os.path.isdir(d))
    folders = []
    for d in all_dirs:
        basename = os.path.basename(d)
        if basename.endswith("_Licitacoes"):
            folders.append((d, "Licitacoes"))
        elif basename.endswith("_Compras"):
            folders.append((d, "Compras"))

    if args.only:
        folders = [(d, t) for d, t in folders if os.path.basename(d) in set(args.only)]
    if not folders:
        print("Nenhuma pasta de Licitações ou Compras encontrada em", args.root)
        return

    db = heraclitusdb.connect(args.addr)
    totals, t0 = {}, time.time()
    try:
        for folder, schema_type in folders:
            base = os.path.basename(folder)
            mes = base.split("_")[0]
            load_folder(db, folder, mes, DATASETS[schema_type], args.limit, not args.no_prov, totals)
    finally:
        db.close()

    dt, tot = time.time() - t0, sum(totals.values())
    print(f"\n== CONCLUIDO em {dt/60:.1f} min ==")
    for k, v in sorted(totals.items()):
        print(f"   {k:16} {v:>8}")
    print(f"   {'TOTAL':16} {tot:>8}  ({tot/max(dt,1e-6):.0f} nos/s)")


if __name__ == "__main__":
    main()
