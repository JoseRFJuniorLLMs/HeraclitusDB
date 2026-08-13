# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

r"""ETL massivo: Servidores/Aposentados/Pensionistas (Portal) -> HeraclitusDB.

Carrega as bases de pessoal do Governo Federal (SIAPE/BACEN) modelando uma TEIA
centrada na PESSOA, ligada por proveniencia:

    Pessoa (Servidor/Aposentado/Pensionista)  ── chave: Id_SERVIDOR_PORTAL
       ├──◄ Remuneracao  (salario do mes)        parents=[Pessoa]
       ├──◄ Afastamento  (licencas)              parents=[Pessoa]
       └──◄ Observacao                           parents=[Pessoa]

Como o no' da Pessoa e' PARTILHADO, o grafo liga "quem e'" (cadastro) a "quanto
recebe" (remuneracao) e "quando se ausenta" (afastamento) — base p/ deteccao de
servidor-fantasma, salario fora da curva, etc.

DESEMPENHO (a chave da carga massiva):
  * append puro ~1300 nos/s; lookup de ULID por no' ~17 nos/s (proibido a escala).
  * Por isso: 1) append das Pessoas guardando Id->LSN em memoria (sem lookup);
              2) UMA resolucao LSN->ULID em BLOCO (query por intervalo de LSN);
              3) append de Remuneracao/Afastamento com parents=[ULID da Pessoa].
  Tudo em append puro -> ~2,7M nos em ~30-40 min.

USO (py 3.14, onde esta' o SDK/grpc):
  py demo/etl_servidores.py --root D:\dados-governo
  # opcoes:
  #   --only 202601_Servidores_BACEN     so' esta(s) pasta(s)
  #   --limit 5000                       max linhas por ficheiro (teste)
  #   --no-prov                          nao construir arestas (so' atributos)
  #   --addr 127.0.0.1:7474
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

AGENT = "etl-servidores"
PAGE = 50000  # tamanho da pagina na resolucao LSN->ULID em bloco


def _norm(s):
    s = unicodedata.normalize("NFKD", s or "")
    s = "".join(c for c in s if not unicodedata.combining(c))
    return " ".join(s.lower().split())


def _idx(header_norm, *keyword_groups):
    """indice da 1a coluna que contem TODOS os termos de um grupo (por ordem)."""
    for group in keyword_groups:
        for i, col in enumerate(header_norm):
            if all(t in col for t in group):
                return i
    return None


def _brl(v):
    s = (v or "").strip().replace("R$", "").replace(" ", "")
    if not s or s in ("0", "0,00"):
        return 0.0
    if "," in s:
        s = s.replace(".", "").replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return 0.0


def _cell(row, i):
    return (row[i].strip() if i is not None and i < len(row) else "")


def _reader(path):
    fh = open(path, "r", encoding="latin-1", errors="replace", newline="")
    rd = csv.reader(fh, delimiter=";", quotechar='"')
    try:
        header = next(rd)
    except StopIteration:
        fh.close()
        return None, None, None, None
    return fh, rd, header, [_norm(h) for h in header]


def _kind_for(folder):
    f = _norm(folder)
    if "aposentad" in f:
        return "Aposentado"
    if "pensionist" in f:
        return "Pensionista"
    return "Servidor"


# ─────────────────────────────────────────────────────────────────────────────
def load_dataset(db, folder, mes, limit, build_prov, totals, skip_cadastro=0):
    kind = _kind_for(os.path.basename(folder))
    base = os.path.basename(folder)
    print(f"\n=== {base}  (pessoa = {kind}) ===")
    if skip_cadastro:
        print(f"  RESUME: a saltar as primeiras {skip_cadastro} pessoas (ja carregadas)")

    # ---- PASSO 1: Cadastro -> Pessoas (append puro, guarda Id->LSN) ----
    cad = os.path.join(folder, f"{mes}_Cadastro.csv")
    id2lsn = {}
    min_lsn = max_lsn = None
    if os.path.exists(cad):
        fh, rd, header, hn = _reader(cad)
        i_id = _idx(hn, ("id_servidor",))
        i_nome = _idx(hn, ("nome",))
        i_cpf = _idx(hn, ("cpf",))
        i_cargo = _idx(hn, ("descricao", "cargo"), ("cargo",))
        i_org = _idx(hn, ("org_lotacao",), ("orgsup_lotacao",), ("uorg_lotacao",))
        i_mat = _idx(hn, ("matricula",))
        i_sit = _idx(hn, ("situacao",))
        n = 0
        skipped = 0
        for row in tqdm(rd, desc=f"{base}/Cadastro", unit="p"):
            if not row:
                continue
            sid = _cell(row, i_id)
            if not sid:
                continue
            if skipped < skip_cadastro:
                skipped += 1
                continue  # ja carregada num run anterior (retoma sem duplicar)
            orgao = _cell(row, i_org)
            attrs = {
                "id_servidor": sid, "cpf": _cell(row, i_cpf),
                "cargo": _cell(row, i_cargo), "orgao": orgao,
                "matricula": _cell(row, i_mat), "situacao": _cell(row, i_sit),
                "tipo": kind.lower(), "base": base, "mes": mes,
            }
            lsn = db.append(kind, _cell(row, i_nome) or sid, agent_id=AGENT, attrs=attrs)
            id2lsn[sid] = lsn
            min_lsn = lsn if min_lsn is None else min(min_lsn, lsn)
            max_lsn = max(max_lsn, lsn) if max_lsn is not None else lsn
            n += 1
            if limit and n >= limit:
                break
        fh.close()
        totals["Pessoa"] += n
        print(f"  pessoas: {n}")

    # ---- PASSO 2: resolucao LSN->ULID em BLOCO ----
    id2ulid = {}
    if build_prov and id2lsn:
        lsn2ulid = {}
        wanted = set(id2lsn.values())
        start = min_lsn
        with tqdm(total=(max_lsn - min_lsn + 1), desc=f"{base}/resolver ULID", unit="lsn") as bar:
            while start <= max_lsn:
                end = min(start + PAGE - 1, max_lsn)
                rows = db.query(f"MATCH (n) WHERE n.lsn >= {start} AND n.lsn <= {end} RETURN n")
                if isinstance(rows, list):
                    for r in rows:
                        l = r.get("lsn")
                        if l in wanted:
                            lsn2ulid[l] = r.get("id")
                bar.update(end - start + 1)
                start = end + 1
        id2ulid = {sid: lsn2ulid[l] for sid, l in id2lsn.items() if l in lsn2ulid}
        print(f"  ULIDs resolvidos: {len(id2ulid)}/{len(id2lsn)}")

    def parent_of(sid):
        u = id2ulid.get(sid)
        return [u] if u else []

    # ---- PASSO 3: Remuneracao ----
    rem = os.path.join(folder, f"{mes}_Remuneracao.csv")
    if os.path.exists(rem):
        fh, rd, header, hn = _reader(rem)
        i_id = _idx(hn, ("id_servidor",))
        i_nome = _idx(hn, ("nome",))
        i_bruta = _idx(hn, ("remuneracao basica bruta", "r$"), ("basica bruta", "r$"))
        i_liq = _idx(hn, ("apos deducoes", "r$"), ("liquida", "r$"), ("liquido", "r$"))
        n = 0
        for row in tqdm(rd, desc=f"{base}/Remuneracao", unit="r"):
            if not row:
                continue
            sid = _cell(row, i_id)
            bruta = _brl(_cell(row, i_bruta))
            liq = _brl(_cell(row, i_liq))
            attrs = {"id_servidor": sid, "bruta": f"{bruta:.2f}",
                     "liquido": f"{liq:.2f}", "tipo": "remuneracao", "base": base, "mes": mes}
            db.append("Remuneracao", f"Remuneracao {_cell(row,i_nome) or sid} R$ {liq or bruta:.2f}",
                      agent_id=AGENT, attrs=attrs, parents=parent_of(sid))
            n += 1
            if limit and n >= limit:
                break
        fh.close()
        totals["Remuneracao"] += n
        print(f"  remuneracoes: {n}")

    # ---- PASSO 4: Afastamentos ----
    afa = os.path.join(folder, f"{mes}_Afastamentos.csv")
    if os.path.exists(afa):
        fh, rd, header, hn = _reader(afa)
        i_id = _idx(hn, ("id_servidor",))
        i_ini = _idx(hn, ("data_inicio",), ("inicio",))
        i_fim = _idx(hn, ("data_fim",), ("fim",))
        n = 0
        for row in tqdm(rd, desc=f"{base}/Afastamentos", unit="a"):
            if not row:
                continue
            sid = _cell(row, i_id)
            attrs = {"id_servidor": sid, "inicio": _cell(row, i_ini),
                     "fim": _cell(row, i_fim), "tipo": "afastamento", "base": base, "mes": mes}
            db.append("Afastamento", f"Afastamento {_cell(row,i_ini)}..{_cell(row,i_fim)}",
                      agent_id=AGENT, attrs=attrs, parents=parent_of(sid))
            n += 1
            if limit and n >= limit:
                break
        fh.close()
        totals["Afastamento"] += n
        print(f"  afastamentos: {n}")

    # ---- PASSO 5: Observacoes ----
    obs = os.path.join(folder, f"{mes}_Observacoes.csv")
    if os.path.exists(obs):
        fh, rd, header, hn = _reader(obs)
        i_id = _idx(hn, ("id_servidor",))
        i_obs = _idx(hn, ("observacao",))
        n = 0
        for row in tqdm(rd, desc=f"{base}/Observacoes", unit="o"):
            if not row:
                continue
            sid = _cell(row, i_id)
            txt = _cell(row, i_obs)
            if not txt:
                continue
            db.append("Observacao", txt[:200], agent_id=AGENT,
                      attrs={"id_servidor": sid, "tipo": "observacao", "base": base, "mes": mes},
                      parents=parent_of(sid))
            n += 1
            if limit and n >= limit:
                break
        fh.close()
        totals["Observacao"] += n
        print(f"  observacoes: {n}")


def main():
    ap = argparse.ArgumentParser(description="ETL massivo Servidores -> HeraclitusDB")
    ap.add_argument("--root", default=r"D:\dados-governo")
    ap.add_argument("--addr", default="127.0.0.1:7474")
    ap.add_argument("--only", nargs="*", help="apenas estas pastas (nome exato)")
    ap.add_argument("--limit", type=int, default=0, help="max linhas por ficheiro")
    ap.add_argument("--no-prov", action="store_true", help="nao construir arestas (so' atributos)")
    ap.add_argument("--skip-cadastro", type=int, default=0,
                    help="retoma: salta as N primeiras pessoas do Cadastro (ja carregadas)")
    args = ap.parse_args()

    folders = sorted(d for d in glob.glob(os.path.join(args.root, "*")) if os.path.isdir(d))
    if args.only:
        folders = [d for d in folders if os.path.basename(d) in set(args.only)]
    if not folders:
        print("Nenhuma pasta encontrada em", args.root)
        return

    db = heraclitusdb.connect(args.addr)
    totals = {"Pessoa": 0, "Remuneracao": 0, "Afastamento": 0, "Observacao": 0}
    t0 = time.time()
    try:
        for folder in folders:
            mes = os.path.basename(folder).split("_")[0]
            load_dataset(db, folder, mes, args.limit, not args.no_prov, totals,
                         skip_cadastro=args.skip_cadastro)
    finally:
        db.close()

    dt = time.time() - t0
    tot = sum(totals.values())
    print(f"\n== CONCLUIDO em {dt/60:.1f} min ==")
    for k, v in totals.items():
        print(f"   {k:12} {v:>9}")
    print(f"   {'TOTAL':12} {tot:>9}  ({tot/max(dt,1e-6):.0f} nos/s)")


if __name__ == "__main__":
    main()
