# Quickstart — HeraclitusDB

SPEC-0077 §26. Este quickstart demonstra **a plataforma**. Não precisa de um
agente de IA, de um LLM, de uma chave de API nem de rede para fora.

Para o módulo de evidência de agentes, ver [`docs/agent/quickstart.md`](../agent/quickstart.md).

---

## 1. Arrancar

```bash
git clone https://github.com/JoseRFJuniorLLMs/HeraclitusDB
cd HeraclitusDB
cargo build --release
./target/release/heraclitus-server config.toml.example
```

O arranque é narrado: cada linha diz o que subiu e onde.

| porta | superfície |
|---|---|
| 8080 | Platform Console (`/`) e Agent Evidence Console (`/agent`, se o módulo estiver ligado) |
| 7474 | gRPC |
| 7475 | REST |

Abra <http://localhost:8080>.

O que vai encontrar: `Last LSN`, o formato de armazenamento, o estado de
integridade, as fontes presentes no log, e a lista de módulos com o estado real
de cada um. Num banco vazio, quase tudo é `0` ou `N/A` — de propósito. A consola
não escreve um número que não tenha lido do log.

---

## 2. Carregar dados

```bash
pip install ./sdk/python
python examples/data-platform/tour.py --addr 127.0.0.1:7474
```

As fixtures estão no repositório. O passeio ingere organizações, pessoas,
fornecedores, contratos, pagamentos e uma sanção — e mostra, pela ordem, as
capacidades que distinguem o produto.

Recarregue a consola: a fonte `data-platform-demo` aparece em **Data**, com a
contagem de eventos e o intervalo de LSN que ela realmente ocupa.

---

## 3. Consultar

```python
import heraclitusdb
db = heraclitusdb.connect("127.0.0.1:7474")

db.query("MATCH (n) RETURN n LIMIT 20")
db.head()
```

---

## 4. Consultar o passado

A capacidade que não se substitui com um backup:

```python
# o estado do banco ANTES de a sanção ter sido registada
db.query("MATCH (n) RETURN n", as_of=<lsn>)
```

Nada do passado foi reescrito para que isto funcionasse. `AS OF LSN` reconstrói
o estado a partir do log, e o log é append-only.

---

## 5. Verificar a integridade

Dentro do processo:

```python
db.verify()
```

E, o que realmente conta, **fora** dele — porque uma verificação que depende de
o servidor ser honesto não prova nada contra um servidor comprometido:

```bash
./target/release/heraclitus log-inspect ./data     # head, segmentos, raízes
./target/release/heraclitus verify    ./data       # Merkle + CRC de tudo
./target/release/heraclitus manifest show ./data   # o HRKM interno
./target/release/heraclitus prove <segmento> --lsn <n>
```

Se um byte do disco tiver sido alterado por qualquer via, isto diz.

---

## 6. Ligar módulos

Todos são opcionais; o núcleo funciona sem nenhum deles. A página **Modules** da
consola mostra o estado real de cada um, e distingue:

| estado | significa |
|---|---|
| `ENABLED` | ligado e configurado |
| `DISABLED` | compilado, desligado na configuração |
| `DEGRADED` | ligado, a funcionar mal |
| `NOT CONFIGURED` | ligado mas sem o que precisa para fazer alguma coisa |
| `NOT BUILT` | compilado para fora por uma feature do Cargo |

A distinção entre os dois últimos é operacional: um resolve-se no ficheiro de
configuração, o outro exige recompilar.

Por exemplo, o módulo de evidência de agentes:

```toml
[agent_black_box]
enabled = true
```

ou `HERACLITUS_AGENT_ENABLED=1`. Depois, <http://localhost:8080/agent>.

---

## A seguir

- [`examples/data-platform/`](../../examples/data-platform/) — o exemplo deste quickstart
- [`docs/agent/`](../agent/) — o módulo Agent Evidence & Control
- `demo/` — ETL sobre dados públicos reais (**precisa de rede**)
