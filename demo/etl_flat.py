# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

r"""ETL plano (tabela de 1 ficheiro) -> HeraclitusDB, resiliente e retomável.

Para datasets do Portal que vêm num único CSV achatado (sem ficheiros-filhos):
  Despesas        -> nó `Despesa`       (linha de execução orçamentária por ação)
  Transferencias  -> nó `Transferencia` (tem favorecido -> cruza com fornecedores)

Decisões:
  * Append PURO (sem arestas) -> ~1300 nós/s e à prova de crash. O cruzamento
    faz-se por ATRIBUTO (orgao / favorecido / cnpj / uf), consultável.
  * RESILIENTE: cada append tem retry com reconexão (o servidor já caiu sob
    carga); CHECKPOINT por ficheiro (JSON) -> retoma de onde parou sem duplicar.
  * Ignora pastas duplicadas terminadas em " (1)".

USO (py 3.14):
  py demo/etl_flat.py --root D:\dados-governo
  py demo/etl_flat.py --only 202601_Transferencias
  py demo/etl_flat.py --reset-ckpt   # recomeça do zero (ignora checkpoint)
"""
import argparse
import csv
import glob
import json
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

AGENT = "etl-flat"
CKPT = os.path.join(_ROOT, "data", "etl_flat_ckpt.json")

# kind -> (label_cols p/ content, {attr: coluna})
SPECS = {
    "Despesas": ("Despesa",
                 ["Nome Ação", "Nome Elemento de Despesa"],
                 {"orgao_sup": "Nome Órgão Superior", "orgao": "Nome Órgão Subordinado",
                  "ug": "Nome Unidade Gestora", "funcao": "Nome Função",
                  "programa": "Nome Programa Orçamentário", "acao": "Nome Ação",
                  "uf": "UF", "municipio": "Município",
                  "grupo_despesa": "Nome Grupo de Despesa",
                  "elemento": "Nome Elemento de Despesa",
                  "empenhado": "Valor Empenhado (R$)", "liquidado": "Valor Liquidado (R$)",
                  "pago": "Valor Pago (R$)"}),
    "Transferencias": ("Transferencia",
                       ["Nome Favorecido", "Nome Ação"],
                       {"tipo": "Tipo Transferência", "tipo_favorecido": "Tipo Favorecido",
                        "favorecido": "Nome Favorecido", "cnpj": "Código Favorecido",
                        "orgao": "Nome Órgão", "ug": "Nome Unidade Gestora",
                        "funcao": "Nome Função", "programa": "Nome Programa",
                        "acao": "Nome Ação", "uf": "UF", "municipio": "Nome Município",
                        "valor": "Valor Transferido"}),
}


def _norm(s):
    s = unicodedata.normalize("NFKD", s or "")
    s = "".join(c for c in s if not unicodedata.combining(c))
    return " ".join(s.lower().split())


def _resolve(hn, names):
    out = []
    for nm in names:
        nn = _norm(nm)
        idx = next((i for i, h in enumerate(hn) if h == nn), None)
        if idx is None:
            idx = next((i for i, h in enumerate(hn) if nn in h or h in nn), None)
        out.append(idx)
    return out


def _cell(row, i):
    return (row[i].strip() if i is not None and i < len(row) else "")


def _spec_for(folder_name):
    for key, spec in SPECS.items():
        if key.lower() in folder_name.lower():
            return key, spec
    return None, None


def _load_ckpt():
    try:
        with open(CKPT, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_ckpt(ck):
    os.makedirs(os.path.dirname(CKPT), exist_ok=True)
    tmp = CKPT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(ck, f)
    os.replace(tmp, CKPT)


class Resilient:
    """Cliente com reconexão + retry (sobrevive a connection reset / restart)."""

    def __init__(self, addr):
        self.addr = addr
        self.db = heraclitusdb.connect(addr)

    def append(self, kind, content, attrs):
        for attempt in range(8):
            try:
                return self.db.append(kind, content, agent_id=AGENT, attrs=attrs)
            except Exception as e:  # noqa: BLE001
                wait = min(2 ** attempt, 30)
                print(f"\n  [append falhou: {str(e)[:60]}] retry {attempt+1}/8 em {wait}s...")
                time.sleep(wait)
                try:
                    self.db.close()
                except Exception:
                    pass
                try:
                    self.db = heraclitusdb.connect(self.addr)
                except Exception:
                    pass
        raise RuntimeError("append falhou após 8 tentativas (servidor em baixo?)")


def load_folder(rc, folder, ckpt, totals):
    base = os.path.basename(folder)
    key, spec = _spec_for(base)
    if not spec:
        return
    kind, label_cols, attr_map = spec
    csvs = glob.glob(os.path.join(folder, "*.csv"))
    if not csvs:
        return
    path = csvs[0]
    done = ckpt.get(base, 0)
    fh = open(path, "r", encoding="latin-1", errors="replace", newline="")
    rd = csv.reader(fh, delimiter=";", quotechar='"')
    try:
        header = next(rd)
    except StopIteration:
        fh.close()
        return
    hn = [_norm(h) for h in header]
    lab = _resolve(hn, label_cols)
    cols = {k: _resolve(hn, [c])[0] for k, c in attr_map.items()}

    n = 0
    bar = tqdm(rd, desc=f"{base} (a partir de {done})", unit="x")
    for row in bar:
        if not row:
            continue
        n += 1
        if n <= done:
            continue  # já carregado (checkpoint) -> retoma sem duplicar
        a = {"tipo": kind.lower(), "base": base}
        for k, idx in cols.items():
            v = _cell(row, idx)
            if v:
                a[k] = v[:120]
        label = " · ".join(x for x in (_cell(row, i) for i in lab) if x) or kind
        rc.append(kind, label[:160], a)
        if n % 5000 == 0:
            ckpt[base] = n
            _save_ckpt(ckpt)
    fh.close()
    ckpt[base] = n
    _save_ckpt(ckpt)
    totals[kind] = totals.get(kind, 0) + (n - done)
    print(f"  {base}: {n - done} novos (total ficheiro {n})")


def main():
    ap = argparse.ArgumentParser(description="ETL plano Despesas/Transferencias -> HeraclitusDB")
    ap.add_argument("--root", default=r"D:\dados-governo")
    ap.add_argument("--addr", default="127.0.0.1:7474")
    ap.add_argument("--only", nargs="*", help="apenas estas pastas")
    ap.add_argument("--reset-ckpt", action="store_true", help="ignora o checkpoint")
    args = ap.parse_args()

    if args.reset_ckpt and os.path.exists(CKPT):
        os.remove(CKPT)

    folders = sorted(
        d for d in glob.glob(os.path.join(args.root, "*"))
        if os.path.isdir(d) and _spec_for(os.path.basename(d))[1]
        and "(1)" not in os.path.basename(d)  # ignora downloads duplicados
    )
    if args.only:
        folders = [d for d in folders if os.path.basename(d) in set(args.only)]
    if not folders:
        print("Nenhuma pasta Despesas/Transferencias (sem duplicados) encontrada.")
        return

    print(f"== ETL plano: {len(folders)} pasta(s) -> {args.addr} ==")
    print("   (pastas '(1)' duplicadas sao ignoradas)")
    rc = Resilient(args.addr)
    ckpt = _load_ckpt()
    totals, t0 = {}, time.time()
    for folder in folders:
        load_folder(rc, folder, ckpt, totals)

    dt, tot = time.time() - t0, sum(totals.values())
    print(f"\n== CONCLUIDO em {dt/60:.1f} min ==")
    for k, v in sorted(totals.items()):
        print(f"   {k:14} {v:>9}")
    print(f"   {'TOTAL':14} {tot:>9}  ({tot/max(dt,1e-6):.0f} nos/s)")


if __name__ == "__main__":
    main()
