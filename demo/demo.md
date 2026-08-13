# Demo HeraclitusDB — "vendo o rio fluir"

Cenário de **fraude fictícia** semeado no banco: uma **empresa de fachada** troca de sócio
(entra um **laranja**) dias antes de **vencer uma licitação milionária**. Sem terminal vazio:
roda-se a demo e mostra-se o HeraclitusDB a achar e provar a fraude.

> Corre **contra o banco em execução** (sem Docker): `127.0.0.1:7474` (gRPC) / `:7475` (REST).

## 1. Semear o cenário

```bash
py demo/seed.py --addr 127.0.0.1:7474
```
Cria 6 nós ligados por proveniência (`parents`): Empresa → Sócio → **Troca societária** →
**Laranja** → **Licitação** → **INSIGHT_FRAUDE** (aponta para troca + licitação + laranja).

## 2. Abrir o Console

```bash
py console/server.py --addr 127.0.0.1:7474
```
Abre `http://127.0.0.1:7480`: editor GQL → grafo, **slider de espaço-tempo (AS OF)** e
**escudo da Árvore de Merkle**.

## 3. O roteiro (o que mostrar)

**a) Achar a fraude por significado (Recall semântico) — funciona ao vivo:**
```python
import heraclitusdb
db = heraclitusdb.connect()
db.recall("empresa de fachada trocou socio laranja venceu licitacao", k=6)
# → devolve o cluster: "Empresa de fachada...", "Maria Souza (laranja)", "Troca societária..."
```

**b) Viagem no tempo (AS OF) — funciona ao vivo:**
No Console, arraste o **slider** para um LSN **anterior** à troca: o banco reconstrói o
passado e o nó do laranja **desaparece**. Solte no fim = agora.
```python
db.query("MATCH (n) RETURN n", as_of=100)   # estado do banco no LSN 100
```

**c) Integridade (Árvore de Merkle) — funciona ao vivo:**
O **escudo fica verde**: "Log íntegro e criptograficamente verificado".
```python
db.verify()   # {'ok': True, 'message': '{"merkle_ok":0,"records":...}'}
```

## 4. Proveniência — isola a fraude (funciona ao vivo!)

A sintaxe é `PROVENANCE ("<ulid>")` (parênteses + aspas):
```python
db.provenance("01KV7ZED...INSIGHT")
# -> ['01KV...troca', '01KV...licitacao', '01KV...laranja']  (os nós fraudados)
```
No **Console**, **clique no nó do INSIGHT** e as arestas de proveniência aparecem
(tracejadas), isolando a troca societária + a licitação + o laranja em segundos.

---

### Resumo do que está PROVADO ao vivo
- ✅ Recall semântico (acha a fraude por significado)
- ✅ AS OF LSN (reconstrução do passado no slider)
- ✅ **PROVENANCE** (isola os nós fraudados; clicável no grafo)
- ✅ Merkle verify (escudo verde de integridade)
