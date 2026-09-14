# examples/data-platform — o HeraclitusDB, sem agentes

O exemplo canónico da plataforma (SPEC-0077 §27/§28). Demonstra o produto sem
um único agente de IA, sem LLM, sem chave de API e sem rede para fora.

```text
ORG-1 ──contract──> SUP-100 ──owner──> PER-1
  │                                      ▲
  └────contract────> SUP-300 ──owner─────┘
                        │
                        └── sanction (CEIS, 2025-03-01)
```

Dois fornecedores diferentes com o mesmo dono; um deles sancionado **depois** de
já ter contrato e pagamento. É o padrão que uma auditoria procura — e é a razão
de o exemplo existir: num banco que sobrescreve, a pergunta *"o que é que se
sabia em Fevereiro?"* não tem resposta.

## Correr

```bash
# 1. o servidor
cargo build --release
./target/release/heraclitus-server config.toml.example

# 2. o SDK
pip install ./sdk/python

# 3. o passeio
python examples/data-platform/tour.py --addr 127.0.0.1:7474
```

Abra depois <http://localhost:8080> — a **Platform Console** mostra a fonte
`data-platform-demo` com a contagem real de eventos e o intervalo de LSN.

## O que ele mostra

| passo | capacidade |
|---|---|
| 1 | ingestão append-only, com arestas de proveniência (`parents`) |
| 2 | um facto novo que muda a leitura do passado sem o reescrever |
| 3 | consulta |
| 4 | relação de grafo — dois fornecedores, um dono |
| 5 | `AS OF LSN` — o estado antes e depois da sanção |
| 6 | `PROVENANCE` — do pagamento até ao dono do fornecedor |
| 7 | verificação de integridade, dentro e fora do processo |

## As fixtures

`fixtures/` são cinco ficheiros JSON pequenos, versionados neste repositório:
`orgs`, `people`, `suppliers`, `contracts`, `payments`, `sanctions`. São
**inventadas** e estão aqui identificadas como demonstração — nenhum dos nomes
corresponde a uma entidade real, e nenhum número deste exemplo pode aparecer
numa superfície de produto (SPEC-0077 §33).

Os valores são inteiros de centavos. Em vírgula flutuante, um contrato de
R$ 4.800.000,00 deixa de somar exactamente, e um sistema cuja razão de existir é
ser auditável não pode ter a sua própria aritmética como fonte de dúvida.

## Dados públicos a sério

Para dados reais do Portal da Transparência há `demo/baixar_transparencia.py` e
os ETL em `demo/`. Eles **precisam de rede** e por isso não são o quickstart: um
exemplo introdutório que depende de um portal externo estar de pé não é
reprodutível.

## O módulo de agentes

Está em [`examples/agent-black-box/`](../agent-black-box/), e é opcional. Este
exemplo não o usa nem precisa dele.
