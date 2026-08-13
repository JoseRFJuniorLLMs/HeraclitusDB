# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

"""Semeia nós com EMBEDDINGS sintéticos no HeraclitusDB para popular o Manifold 3D.

O manifold usa três espaços de projeção:
  hyp = hiperbólico  (modelar hierarquias)
  sph = esférico     (modelar categorias / similaridade direcional)
  euc = euclidiano   (modelar distâncias brutas)

O dashboard lê os primeiros 3 valores de (hyp + sph + euc) como (x, y, z).
Este script cria clusters temáticos sintéticos para demonstrar o espaço vetorial:

  - Cluster FRAUDE       → casos sinalizados (vermelho no gráfico)
  - Cluster LICITAÇÃO    → empresas concorrentes em licitações
  - Cluster SÓCIOS       → redes de sócios e laranjas
  - Cluster PAGAMENTOS   → transações suspeitas
  - Cluster NORMAL       → eventos normais sem sinalização

  py demo/seed_manifold.py --addr 127.0.0.1:7474
"""
import argparse
import math
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sdk", "python"))
import heraclitusdb  # noqa: E402


def _vec_cluster(cx, cy, cz, spread=0.12):
    """Gera um vetor 3D em torno de um centróide (cx, cy, cz) com ruído gaussiano."""
    def g(): return random.gauss(0, spread)
    return (cx + g(), cy + g(), cz + g())


def _norm(v):
    """Normaliza um vetor para a esfera unitária (para sph)."""
    mag = math.sqrt(sum(x * x for x in v))
    if mag < 1e-9:
        return v
    return tuple(x / mag for x in v)


def _emit(db, kind, content, attrs, parents=None, hyp=None, sph=None, euc=None):
    lsn = db.append(
        kind, content,
        agent_id="demo-manifold",
        session_id=attrs.get("caso", attrs.get("cluster", "default")),
        attrs=attrs,
        parents=parents or [],
        hyp=list(hyp or []),
        sph=list(sph or []),
        euc=list(euc or []),
    )
    rows = db.query(f"MATCH (n) WHERE n.lsn = {lsn} RETURN n")
    nid = rows[0]["id"] if isinstance(rows, list) and rows else None
    return nid, lsn


# ── centróides de cada cluster (espaço 3D) ──────────────────────────────────
CLUSTERS = {
    "fraude": {
        "center": (0.8, 0.7, -0.3),
        "color": "fraude",
        "nodes": [
            ("INSIGHT_FRAUDE", "Empresa Alfa trocou para laranja antes de licitação", {"caso": "A1", "severidade": "CRITICA", "tipo": "fachada_licitacao"}),
            ("INSIGHT_FRAUDE", "Beta Comercio: sobrepreço de 340% detectado",          {"caso": "A2", "severidade": "ALTA",   "tipo": "sobrepreco"}),
            ("INSIGHT_FRAUDE", "Gama Engenharia: CNPJ fantasma na cadeia societária",  {"caso": "C1", "severidade": "CRITICA", "tipo": "cnpj_fantasma"}),
            ("INSIGHT_FRAUDE", "Delta Obras: sócio laranja João Pereira recorrente",    {"caso": "C1", "severidade": "MEDIA",  "tipo": "laranja_recorrente"}),
            ("INSIGHT_FRAUDE", "Epsilon: pagamento suspeito a empresa de fachada",      {"caso": "A1", "severidade": "ALTA",   "tipo": "pagamento_suspeito"}),
            ("INSIGHT_FRAUDE", "Zeta Consultoria: triangulação via offshore",           {"caso": "A2", "severidade": "CRITICA", "tipo": "offshore"}),
        ],
    },
    "licitacao": {
        "center": (0.1, 0.8, 0.5),
        "color": "normal",
        "nodes": [
            ("Licitacao", "Pregão 001/2024 — construção de ponte R$ 4.2M",    {"cluster": "licitacao", "valor": "4200000", "modalidade": "pregao"}),
            ("Licitacao", "Tomada de preços 022/2024 — pavimentação R$ 1.8M", {"cluster": "licitacao", "valor": "1800000", "modalidade": "tomada_precos"}),
            ("Licitacao", "Concorrência 003/2024 — hospital R$ 28M",          {"cluster": "licitacao", "valor": "28000000", "modalidade": "concorrencia"}),
            ("Licitacao", "Pregão 045/2024 — TI e infraestrutura R$ 3.1M",    {"cluster": "licitacao", "valor": "3100000", "modalidade": "pregao"}),
            ("Licitacao", "Dispensa emergência 012/2024 — ambulâncias R$ 900k",{"cluster": "licitacao", "valor": "900000", "modalidade": "dispensa"}),
            ("Licitacao", "Pregão 067/2024 — merenda escolar R$ 2.4M",        {"cluster": "licitacao", "valor": "2400000", "modalidade": "pregao"}),
        ],
    },
    "socios": {
        "center": (-0.5, 0.3, 0.7),
        "color": "normal",
        "nodes": [
            ("Socio", "Maria Souza — laranja recorrente (3 empresas)",    {"cluster": "socios", "laranja": "sim", "recorrencias": "3"}),
            ("Socio", "João Pereira — sócio fantasma CNPJ 33.444.555",   {"cluster": "socios", "laranja": "sim", "cnpj": "33.444.555/0001-66"}),
            ("Socio", "Carlos Mendes — sócio legítimo Alfa Serviços",     {"cluster": "socios", "laranja": "nao", "empresa": "alfa"}),
            ("Socio", "Ana Lima — diretora contratual Gama Engenharia",   {"cluster": "socios", "laranja": "nao", "empresa": "gama"}),
            ("Socio", "Pedro Santos — laranja apontado em 2 CPFs",        {"cluster": "socios", "laranja": "suspeito", "cpfs": "2"}),
            ("Socio", "Lucia Ferreira — representante legal Beta",        {"cluster": "socios", "laranja": "nao", "empresa": "beta"}),
        ],
    },
    "pagamentos": {
        "center": (0.4, -0.6, 0.5),
        "color": "normal",
        "nodes": [
            ("Pagamento", "TED R$ 420.000 Alfa → conta fantasma 2024-03-15", {"cluster": "pagamentos", "valor": "420000", "suspeito": "sim"}),
            ("Pagamento", "PIX R$ 87.500 remetente desconhecido 2024-04-02",  {"cluster": "pagamentos", "valor": "87500",  "suspeito": "sim"}),
            ("Pagamento", "Transferência R$ 1.2M via offshore Cayman",         {"cluster": "pagamentos", "valor": "1200000","suspeito": "sim"}),
            ("Pagamento", "Pagamento fornecedor legítimo R$ 34.000 NF 1521",   {"cluster": "pagamentos", "valor": "34000",  "suspeito": "nao"}),
            ("Pagamento", "Salários folha regular mar/2024 R$ 230.000",        {"cluster": "pagamentos", "valor": "230000", "suspeito": "nao"}),
            ("Pagamento", "Devolução licitação cancelada R$ 92.000",           {"cluster": "pagamentos", "valor": "92000",  "suspeito": "nao"}),
        ],
    },
    "normal": {
        "center": (-0.7, -0.4, -0.5),
        "color": "normal",
        "nodes": [
            ("AgentEvent",      "Verificação periódica de integridade — OK",           {"cluster": "normal", "mem_kind": "audit"}),
            ("Memory",          "Regra anti-fraude v3.2 atualizada",                   {"cluster": "normal", "mem_kind": "rule"}),
            ("Observation",     "Relatório TCU 2024-Q1 sem apontamentos críticos",     {"cluster": "normal", "mem_kind": "report"}),
            ("ProjectContext",  "Base de CNPJ atualizada — 42M empresas ativas",       {"cluster": "normal", "mem_kind": "context"}),
            ("Learning",        "Padrão laranja identificado: troca societária <30d",  {"cluster": "normal", "mem_kind": "learning"}),
            ("Fact",            "Threshold sobrepreço calibrado em 35% acima mediana", {"cluster": "normal", "mem_kind": "fact"}),
            ("Decision",        "Caso A1 encaminhado ao MP para investigação",         {"cluster": "normal", "mem_kind": "decision"}),
            ("Observation",     "Monitoramento contínuo de 1.240 contratos ativos",    {"cluster": "normal", "mem_kind": "monitor"}),
        ],
    },
}


def seed(addr, seed_val=42):
    sys.stdout.reconfigure(encoding='utf-8')
    random.seed(seed_val)
    db = heraclitusdb.connect(addr)
    total = 0
    try:
        print(f"\nConectado a {addr}")
        print("Injetando nos com embeddings no manifold...\n")

        for cluster_name, cfg in CLUSTERS.items():
            cx, cy, cz = cfg["center"]
            is_fraud = cluster_name == "fraude"
            print(f"  Cluster '{cluster_name}' ({len(cfg['nodes'])} nos)...")

            ids = []
            for kind, content, attrs in cfg["nodes"]:
                # Gera vetores em torno do centróide do cluster
                raw = _vec_cluster(cx, cy, cz, spread=0.18)

                # hyp: coordenadas hiperbólicas (vetor direto)
                hyp = list(raw)

                # sph: vetor normalizado para a esfera unitária
                sph = list(_norm(raw))

                # euc: coordenadas euclidianas com leve escala
                euc = [x * 1.5 for x in raw]

                # Adiciona flag de fraude nos attrs se aplicável
                if is_fraud and "caso" in attrs:
                    attrs.setdefault("fraude_detectada", "sim")

                nid, lsn = _emit(db, kind, content, attrs, hyp=hyp, sph=sph, euc=euc)
                ids.append(nid)
                total += 1
                preview = content[:48].encode("ascii", errors="replace").decode("ascii")
                print(f"    LSN {lsn:4d}  {kind:<20s}  {preview}")

            # Liga nós do mesmo cluster por proveniência (cria arestas no grafo)
            if len(ids) >= 2 and is_fraud:
                anchor = ids[0]
                for nid in ids[1:]:
                    if nid and anchor:
                        _emit(db, "CLUSTER_LINK",
                              f"Elo interno cluster {cluster_name}",
                              {"cluster": cluster_name, "generated_by": "seed_manifold"},
                              parents=[nid, anchor],
                              hyp=[cx, cy, cz], sph=list(_norm((cx, cy, cz))), euc=[cx * 1.5, cy * 1.5, cz * 1.5])
                        total += 1

        print(f"\n{'='*56}")
        print(f"  {total} nos injetados com embeddings em 5 clusters.")
        print(f"  Abra o Console V2 -> clique 'Manifold 3D'")
        print(f"  Vermelho = fraude, azul = normal.")
        print(f"{'='*56}\n")

    finally:
        db.close()


def main():
    ap = argparse.ArgumentParser(description="Seeder de embeddings para o Manifold 3D (HeraclitusDB)")
    ap.add_argument("--addr", default="127.0.0.1:7474")
    ap.add_argument("--seed", type=int, default=42, help="Semente aleatória (reprodutibilidade)")
    args = ap.parse_args()
    seed(args.addr, seed_val=args.seed)


if __name__ == "__main__":
    main()
