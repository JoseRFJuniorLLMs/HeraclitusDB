# heraclitusdb — SDK Python

Cliente Python amigável para o **HeraclitusDB** (banco de auditoria event-sourced: log
imutável, `AS OF`, Merkle, proveniência). Pensado para peritos e cientistas de dados
(Jupyter / Pandas).

## Instalar

```bash
pip install heraclitusdb            # (após publicação no PyPI)
# ou, a partir deste repo:
pip install ./sdk/python
```

## Uso

```python
import heraclitusdb
db = heraclitusdb.connect("127.0.0.1:7474")

# escrever no log (o rio); parents = arestas de proveniência (ULIDs)
lsn = db.append("Observation", "empresa X trocou de socio", attrs={"caso": "1"})

# consultar (GQL/Cypher subset)
rows = db.query('MATCH (n) RETURN n LIMIT 100')
df   = db.query_df('MATCH (n) RETURN n LIMIT 1000')     # -> pandas.DataFrame

# viagem no tempo: estado do banco num LSN do passado
passado = db.query('MATCH (n) RETURN n', as_of=1000)

# recall semântico (ANN no manifold de produto)
db.recall("empresa de fachada que venceu licitacao", k=10)

# integridade criptográfica (Árvore de Merkle)
db.verify()        # {'ok': True, 'message': '{"merkle_ok":0,...}'}

# stream do rio
for ev in db.subscribe(from_lsn=db.head()):
    print(ev["lsn"], ev["episode"])
```

## API

| Método | O quê |
|---|---|
| `connect(addr, tls=False)` | abre conexão (gRPC) |
| `append(kind, content, *, attrs, parents, agent_id, session_id, hyp/sph/euc)` | escreve episódio → LSN |
| `query(gql, *, as_of=None)` | GQL → lista de dicts (ou texto do `EXPLAIN`) |
| `query_df(gql, *, as_of=None)` | idem → `pandas.DataFrame` |
| `recall(text, k=10)` | recall semântico |
| `subscribe(from_lsn=0)` | gerador de eventos (stream) |
| `head()` | LSN da cabeça do log |
| `verify()` / `stats()` | Admin (Merkle / estatísticas) |

Notas: o cliente sobe o limite de mensagem gRPC para 256 MB (queries amplas como
`MATCH (n) RETURN n` podem devolver dezenas de MB).
