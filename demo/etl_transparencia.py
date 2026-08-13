# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

r"""ETL do Portal da Transparencia -> HeraclitusDB (carga massiva, com proveniencia).

Modela os dados abertos do Governo Federal como uma TEIA de eventos ligados por
arestas de proveniencia (parents), em vez de despejar linhas de CSV soltas:

    Entidade (orgao)  ─┐
                        ├─►  Contrato  (objeto, valor, data)
    Entidade (forn.)  ─┘        │
            ▲                   │  (o MESMO no de fornecedor e' partilhado)
            └───────────────────┴─►  Pagamento  (valor pago, data)

Como o no' de Fornecedor (chaveado por CNPJ) e' PARTILHADO entre os contratos e
os pagamentos, o grafo conecta automaticamente "quem assinou o contrato" com
"quem recebeu o dinheiro" — o cruzamento interessante para deteccao de fraude.

────────────────────────────────────────────────────────────────────────────────
AVISO sobre o DOWNLOAD
────────────────────────────────────────────────────────────────────────────────
O https://portaldatransparencia.gov.br esta' protegido por AWS WAF ("Human
Verification"): downloads por script (curl/requests) sao bloqueados com um
desafio CAPTCHA. Por isso o Extract funciona assim:

  1. Procura os ZIP em  data/raw/  (ex.:  202401_Contratos.zip).
  2. Se faltar, TENTA descarregar; se o WAF bloquear, imprime o link oficial
     para download MANUAL e segue com o que existir localmente.

Ou seja: o caminho fiavel e' o utilizador baixar os ZIP pelo browser uma vez e
po-los em  data/raw/ . O pipeline (Transform + Load) corre sozinho a partir dai'.

Para um teste ponta-a-ponta SEM depender do portal, use  --sample  (gera CSVs
sinteticos no formato do portal).

────────────────────────────────────────────────────────────────────────────────
USO
────────────────────────────────────────────────────────────────────────────────
    # 1) teste rapido com dados sinteticos (nao precisa de internet):
    py demo/etl_transparencia.py --sample --limit 200

    # 2) carga real (depois de por os ZIP em data/raw/):
    py demo/etl_transparencia.py --mes 202401

    # opcoes uteis:
    #   --addr 127.0.0.1:7474   endereco do HeraclitusDB
    #   --mes 202401            recorte temporal (AAAAMM)
    #   --limit N               carrega no maximo N linhas por dataset (smoke test)
    #   --skip-download         nunca tentar descarregar (usa so' o que ha' em data/raw)
    #   --dry-run               le e transforma, mas NAO grava no banco
    #   --raw-dir PASTA         onde estao/ficam os ZIP e CSV (default: data/raw)
"""
import argparse
import csv
import io
import os
import sys
import time
import unicodedata
import zipfile

# csv do governo tem campos enormes (objeto de contrato) -> sobe o limite.
csv.field_size_limit(10 * 1024 * 1024)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "sdk", "python"))
import heraclitusdb  # noqa: E402

try:
    from tqdm import tqdm
except ImportError:  # progresso degrada-se a um contador simples
    def tqdm(it, **kw):
        return it

PORTAL = "https://portaldatransparencia.gov.br/download-de-dados"
AGENT = "etl-transparencia"

# Datasets: nome logico -> (segmento da URL, sufixo do ZIP).
DATASETS = {
    "contratos": ("contratos", "Contratos"),
    "despesas": ("despesas/execucao-pagamento", "Despesas_Execucao_Pagamento"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers de normalizacao / parsing (resilientes ao schema real do portal)
# ─────────────────────────────────────────────────────────────────────────────
def _norm(s):
    """minusculas, sem acentos, sem espacos duplos — para casar cabecalhos."""
    s = unicodedata.normalize("NFKD", s or "")
    s = "".join(c for c in s if not unicodedata.combining(c))
    return " ".join(s.lower().split())


def _pick(header_norm, *keyword_groups):
    """Devolve o indice da 1a coluna cujo nome contem TODOS os termos de um grupo.

    Tenta os grupos por ordem (preferencia). Devolve None se nada casar.
        _pick(h, ("nome", "contratado"), ("favorecido",))
    """
    for group in keyword_groups:
        for i, col in enumerate(header_norm):
            if all(term in col for term in group):
                return i
    return None


def _brl(value):
    """'1.234.567,89' (ou '1234,89' / '1234.89') -> float. Vazio -> 0.0."""
    s = (value or "").strip().replace("R$", "").replace(" ", "")
    if not s:
        return 0.0
    if "," in s:                       # formato pt-BR: ponto=milhar, virgula=decimal
        s = s.replace(".", "").replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return 0.0


def _cnpj(value):
    """So' digitos do CNPJ/CPF; '' se vazio/invalido."""
    d = "".join(c for c in (value or "") if c.isdigit())
    return d or ""


def _cell(row, idx):
    if idx is None or idx >= len(row):
        return ""
    return (row[idx] or "").strip()


# ─────────────────────────────────────────────────────────────────────────────
# EXTRACT
# ─────────────────────────────────────────────────────────────────────────────
def _zip_path(raw_dir, mes, sufixo):
    return os.path.join(raw_dir, f"{mes}_{sufixo}.zip")


def _try_download(url, dest):
    """Tenta descarregar; devolve True se obteve um ZIP valido, False caso contrario.

    O portal esta' atras de AWS WAF; quando bloqueia, devolve HTML (nao ZIP).
    """
    try:
        import requests
    except ImportError:
        print("    (requests indisponivel — pulo o download)")
        return False
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
        "Accept": "application/zip,application/octet-stream,*/*",
    }
    try:
        with requests.get(url, headers=headers, stream=True, timeout=60) as r:
            ctype = r.headers.get("Content-Type", "")
            if r.status_code != 200 or "zip" not in ctype and "octet" not in ctype:
                print(f"    WAF/erro: HTTP {r.status_code} ({ctype or 'sem tipo'}) — "
                      "download automatico bloqueado.")
                return False
            tmp = dest + ".part"
            total = 0
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(1 << 20):
                    f.write(chunk)
                    total += len(chunk)
            if not zipfile.is_zipfile(tmp):
                os.remove(tmp)
                print("    Resposta nao e' um ZIP (provavel pagina do WAF).")
                return False
            os.replace(tmp, dest)
            print(f"    OK — {total/1e6:.1f} MB")
            return True
    except Exception as e:  # rede/timeout/etc — nao fatal
        print(f"    falha no download: {e}")
        return False


def extract(raw_dir, mes, logical, skip_download):
    """Garante o ZIP local e devolve a lista de CSVs (bytes) dentro dele.

    Devolve [] (e instrui o download manual) se nao houver ficheiro.
    """
    seg, sufixo = DATASETS[logical]
    zpath = _zip_path(raw_dir, mes, sufixo)
    url = f"{PORTAL}/{seg}/{mes}"

    if not os.path.exists(zpath) and not skip_download:
        print(f"  [{logical}] a tentar descarregar {url} ...")
        _try_download(url, zpath)

    if not os.path.exists(zpath):
        print(f"  [{logical}] ZIP ausente: {zpath}")
        print(f"             baixe MANUALMENTE em: {url}")
        print(f"             e coloque o ficheiro em: {raw_dir}")
        return []

    out = []
    with zipfile.ZipFile(zpath) as z:
        for name in z.namelist():
            if name.lower().endswith(".csv"):
                out.append((name, z.read(name)))
    print(f"  [{logical}] {os.path.basename(zpath)} -> {len(out)} CSV(s)")
    return out


def _reader(csv_bytes):
    """Itera (header_norm, header_raw, rows) de um CSV do portal (; , latin-1)."""
    text = csv_bytes.decode("latin-1", errors="replace")
    rd = csv.reader(io.StringIO(text), delimiter=";", quotechar='"')
    try:
        header_raw = next(rd)
    except StopIteration:
        return [], [], iter(())
    header_norm = [_norm(h) for h in header_raw]
    return header_norm, header_raw, rd


# ─────────────────────────────────────────────────────────────────────────────
# LOAD — cache CNPJ/codigo -> ULID para montar as arestas (parents)
# ─────────────────────────────────────────────────────────────────────────────
class Loader:
    def __init__(self, db, dry_run=False):
        self.db = db
        self.dry = dry_run
        self.ent_cache = {}          # chave (tipo, id) -> ULID
        self.counts = {"Entidade": 0, "Contrato": 0, "Pagamento": 0}

    def _emit(self, kind, content, attrs, parents=None, want_id=False):
        """Append + (opcional) resolucao do ULID. Conta por kind."""
        self.counts[kind] = self.counts.get(kind, 0) + 1
        if self.dry:
            return f"dry-{self.counts[kind]}" if want_id else None
        lsn = self.db.append(kind, content, agent_id=AGENT, attrs=attrs,
                             parents=parents or [])
        if not want_id:
            return None
        rows = self.db.query(f"MATCH (n) WHERE n.lsn = {lsn} RETURN n")
        return rows[0]["id"] if isinstance(rows, list) and rows else None

    def ensure_entidade(self, tipo, ident, nome, extra=None):
        """No' de Entidade (orgao/fornecedor), criado uma vez e cacheado por ULID."""
        key = (tipo, ident)
        if key in self.ent_cache:
            return self.ent_cache[key]
        attrs = {"tipo": tipo, "id_ext": ident}
        if tipo == "fornecedor":
            attrs["cnpj"] = ident
        if extra:
            attrs.update(extra)
        ulid = self._emit("Entidade", f"{nome} [{tipo}]", attrs, want_id=True)
        self.ent_cache[key] = ulid
        return ulid

    def add_contrato(self, orgao_id, forn_id, objeto, attrs):
        parents = [p for p in (orgao_id, forn_id) if p]
        self._emit("Contrato", objeto or "(sem objeto)", attrs, parents=parents)

    def add_pagamento(self, orgao_id, forn_id, descr, attrs):
        parents = [p for p in (orgao_id, forn_id) if p]
        self._emit("Pagamento", descr or "(pagamento)", attrs, parents=parents)


# ─────────────────────────────────────────────────────────────────────────────
# TRANSFORM + LOAD por dataset
# ─────────────────────────────────────────────────────────────────────────────
def load_contratos(loader, csvs, mes, limit):
    n = 0
    for name, data in csvs:
        h, _raw, rows = _reader(data)
        if not h:
            continue
        # deteccao resiliente de colunas
        i_org_cod = _pick(h, ("codigo", "orgao"))
        i_org_nom = _pick(h, ("nome", "orgao"))
        i_forn_id = _pick(h, ("cnpj",), ("cpf", "cnpj"), ("codigo", "contratado"))
        i_forn_nom = _pick(h, ("nome", "contratado"), ("contratado",), ("favorecido",))
        i_obj = _pick(h, ("objeto",))
        i_num = _pick(h, ("numero", "contrato"), ("contrato",))
        i_val = _pick(h, ("valor", "inicial"), ("valor", "final"), ("valor",))
        i_data = _pick(h, ("assinatura",), ("inicio", "vigencia"), ("data",))

        bar = tqdm(rows, desc=f"contratos:{os.path.basename(name)}", unit="lin")
        for row in bar:
            if not row:
                continue
            org_nome = _cell(row, i_org_nom) or "Orgao nao informado"
            org_cod = _cell(row, i_org_cod) or _norm(org_nome)
            forn_nome = _cell(row, i_forn_nom) or "Fornecedor nao informado"
            forn_doc = _cnpj(_cell(row, i_forn_id)) or _norm(forn_nome)

            orgao_id = loader.ensure_entidade("orgao", org_cod, org_nome)
            forn_id = loader.ensure_entidade("fornecedor", forn_doc, forn_nome)

            valor = _brl(_cell(row, i_val))
            attrs = {
                "numero": _cell(row, i_num), "valor": f"{valor:.2f}",
                "data": _cell(row, i_data), "orgao": org_nome,
                "fornecedor": forn_nome, "cnpj": forn_doc, "mes": mes,
                "fonte": "contratos",
            }
            loader.add_contrato(orgao_id, forn_id, _cell(row, i_obj), attrs)
            n += 1
            if limit and n >= limit:
                bar.close()
                return n
    return n


def load_despesas(loader, csvs, mes, limit):
    n = 0
    for name, data in csvs:
        h, _raw, rows = _reader(data)
        if not h:
            continue
        i_org_nom = _pick(h, ("nome", "orgao"))
        i_org_cod = _pick(h, ("codigo", "orgao"))
        i_forn_id = _pick(h, ("cnpj",), ("cpf", "cnpj"),
                          ("codigo", "favorecido"), ("favorecido", "codigo"))
        i_forn_nom = _pick(h, ("nome", "favorecido"), ("nome", "credor"),
                           ("razao", "social"), ("credor",), ("favorecido",))
        i_val = _pick(h, ("valor", "pago"), ("pago",), ("valor",))
        i_data = _pick(h, ("data",), ("ano", "mes"))
        i_doc = _pick(h, ("documento",), ("empenho",))

        bar = tqdm(rows, desc=f"despesas:{os.path.basename(name)}", unit="lin")
        for row in bar:
            if not row:
                continue
            org_nome = _cell(row, i_org_nom) or "Orgao nao informado"
            org_cod = _cell(row, i_org_cod) or _norm(org_nome)
            forn_nome = _cell(row, i_forn_nom) or "Favorecido nao informado"
            forn_doc = _cnpj(_cell(row, i_forn_id)) or _norm(forn_nome)

            orgao_id = loader.ensure_entidade("orgao", org_cod, org_nome)
            # MESMO no' de fornecedor dos contratos (chave = CNPJ) -> liga a teia
            forn_id = loader.ensure_entidade("fornecedor", forn_doc, forn_nome)

            valor = _brl(_cell(row, i_val))
            doc = _cell(row, i_doc)
            attrs = {
                "valor": f"{valor:.2f}", "data": _cell(row, i_data),
                "documento": doc, "orgao": org_nome, "fornecedor": forn_nome,
                "cnpj": forn_doc, "mes": mes, "fonte": "despesas",
            }
            descr = f"Pagamento a {forn_nome}" + (f" (doc {doc})" if doc else "")
            loader.add_pagamento(orgao_id, forn_id, descr, attrs)
            n += 1
            if limit and n >= limit:
                bar.close()
                return n
    return n


# ─────────────────────────────────────────────────────────────────────────────
# Modo --sample: CSVs sinteticos no formato do portal (teste sem internet)
# ─────────────────────────────────────────────────────────────────────────────
def make_sample(raw_dir, mes):
    """Gera ZIPs sinteticos para validar o pipeline ponta-a-ponta."""
    os.makedirs(raw_dir, exist_ok=True)
    # Fornecedor 90... aparece em contrato E em despesa -> teia cruzada.
    contratos = (
        "Codigo Orgao;Nome Orgao;Numero do Contrato;Objeto;"
        "Codigo Contratado;Nome Contratado;Valor Inicial;Data Assinatura\r\n"
        "26000;Ministerio da Educacao;CT-001/2024;Servicos de limpeza;"
        "11222333000144;Alfa Servicos LTDA;1.200.000,00;15/01/2024\r\n"
        "26000;Ministerio da Educacao;CT-002/2024;Fornecimento de TI;"
        "90888777000122;Omega Tech LTDA;3.450.000,50;20/01/2024\r\n"
        "20000;Presidencia da Republica;CT-003/2024;Consultoria;"
        "55444333000199;Beta Consultoria LTDA;980.000,00;28/01/2024\r\n"
    )
    despesas = (
        "Codigo Orgao;Nome Orgao;Codigo Favorecido;Nome Favorecido;"
        "Documento;Valor Pago;Data\r\n"
        "26000;Ministerio da Educacao;90888777000122;Omega Tech LTDA;"
        "2024NE000123;1.725.000,25;31/01/2024\r\n"
        "26000;Ministerio da Educacao;11222333000144;Alfa Servicos LTDA;"
        "2024NE000124;600.000,00;31/01/2024\r\n"
        "20000;Presidencia da Republica;77000111000155;Gama Eventos LTDA;"
        "2024NE000125;250.000,00;25/01/2024\r\n"
    )
    for sufixo, payload in (("Contratos", contratos),
                            ("Despesas_Execucao_Pagamento", despesas)):
        zpath = _zip_path(raw_dir, mes, sufixo)
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{mes}_{sufixo}.csv", payload.encode("latin-1"))
        print(f"  sample -> {zpath}")


# ─────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="ETL Portal da Transparencia -> HeraclitusDB (com proveniencia)")
    ap.add_argument("--addr", default="127.0.0.1:7474")
    ap.add_argument("--mes", default="202401", help="recorte AAAAMM (default 202401)")
    ap.add_argument("--raw-dir", default=os.path.join(_ROOT, "data", "raw"))
    ap.add_argument("--limit", type=int, default=0, help="max. linhas por dataset (0=todas)")
    ap.add_argument("--skip-download", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="le/transforma sem gravar")
    ap.add_argument("--sample", action="store_true", help="gera CSVs sinteticos e carrega")
    args = ap.parse_args()

    os.makedirs(args.raw_dir, exist_ok=True)
    print(f"== ETL Transparencia  mes={args.mes}  addr={args.addr}  "
          f"{'DRY-RUN' if args.dry_run else 'LOAD'} ==")

    if args.sample:
        print("Gerando dados sinteticos (--sample):")
        make_sample(args.raw_dir, args.mes)
        args.skip_download = True

    # EXTRACT
    print("Extract:")
    csvs = {lg: extract(args.raw_dir, args.mes, lg, args.skip_download)
            for lg in DATASETS}
    if not any(csvs.values()):
        print("\nNada para carregar. Baixe os ZIP para data/raw/ (ou use --sample).")
        return

    # LOAD
    db = None if args.dry_run else heraclitusdb.connect(args.addr)
    loader = Loader(db, dry_run=args.dry_run)
    t0 = time.time()
    try:
        print("\nTransform + Load:")
        nc = load_contratos(loader, csvs["contratos"], args.mes, args.limit)
        nd = load_despesas(loader, csvs["despesas"], args.mes, args.limit)
    finally:
        if db:
            db.close()

    dt = time.time() - t0
    total = sum(loader.counts.values())
    print(f"\n== Concluido em {dt:.1f}s ==")
    print(f"   Contratos : {nc}")
    print(f"   Pagamentos: {nd}")
    print(f"   Entidades : {loader.counts['Entidade']} (orgaos + fornecedores unicos)")
    print(f"   Nos totais: {total}  ({total/max(dt,1e-6):.0f} nos/s)")
    if not args.dry_run:
        print("\nNo Console (:7480) explore a teia; ou via SDK:")
        print('   MATCH (e:Entidade)<-[]-(x) RETURN e, x   // fornecedor e os seus eventos')


if __name__ == "__main__":
    main()
