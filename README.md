<p align="center">
  <img src="img/logo.jpg" alt="HeraclitusDB Logo" width="300" />
</p>
<p align="center">
  <img src="img/logo2.jpg" alt="HeraclitusDB Banner" width="600" />
</p>

<p align="center"><b>O único banco de dados do mundo imune a fraudes retroativas.</b></p>
<p align="center"><i>Auditoria governamental e agentes de IA operando com 100% de transparência e zero de amnésia estrutural.</i></p>

<p align="center">
  <a href="#️-licença-e-modelo-comercial"><img src="https://img.shields.io/badge/license-BSL%201.1-blue" alt="BSL 1.1"></a>
  <img src="https://img.shields.io/badge/core-Rust%20stable-orange" alt="Rust stable">
  <img src="https://img.shields.io/badge/milestones-M0--M31%20%E2%9C%85-success" alt="M0-M31 completos">
  <img src="https://img.shields.io/badge/Sovereignty%20Layer-M20%20GPU%20%E2%9C%85-blueviolet" alt="M20 Sovereignty Layer GPU">
  <img src="https://img.shields.io/badge/fast%20boot-28ms-brightgreen" alt="Fast boot 28ms">
  <img src="https://img.shields.io/badge/replay-deterministico-brightgreen" alt="Replay determinístico">
  <img src="https://img.shields.io/badge/recall%4010-0.996-brightgreen" alt="recall@10=0.996">
</p>

---

## 💼 O que é o HeraclitusDB

**O único banco de dados do mundo imune a fraudes retroativas**, construído especificamente para que **auditorias governamentais** e **agentes de IA** operem com **100% de transparência** e **zero risco de amnésia estrutural**.

Todo banco de dados convencional — Postgres, Neo4j, MongoDB — compartilha o mesmo pecado original: o estado é **mutável**. Um `UPDATE` ou `DELETE` apaga a história. Quem controla o banco controla o passado. Para um auditor, um regulador ou um agente de IA que precisa confiar em sua própria memória, isso é fatal: **você nunca pode provar que os dados de ontem não foram reescritos hoje.**

O HeraclitusDB elimina completamente essa categoria de problema. A verdade primária não é o registro atual — é o **evento imutável** gravado em um log *append-only*. Nada é sobrescrito; nada é destruído. Correções são feitas anexando novos eventos. E **qualquer estado passado é reconstruível bit-a-bit** (`AS OF LSN`), com prova criptográfica infalsificável.

| Para quem | A dor atual | O que o HeraclitusDB entrega |
| :--- | :--- | :--- |
| **Órgãos de Auditoria e Fiscalização** | "Como provar que este dado não foi adulterado retroativamente?" | Log imutável + recibos Merkle (blake3). Replay determinístico reconstrói o estado exato de **qualquer** momento. Fraude retroativa torna-se **matematicamente detectável**. |
| **Agentes de IA / Memória de Agente** | Amnésia estrutural: o agente "esquece" ou tem a memória reescrita por mutações ocultas de estado. | A memória é um fluxo auditável. O agente lê o passado exato (`AS OF`), conhece a **proveniência** de cada fato e nunca é vítima de mutações invisíveis. |
| **Investigação de Fraudes / Compliance** | Cruzamento complexo de entidades, detecção de redes e relações não-dedutíveis. | Motor híbrido de grafo + vetor + texto, resolução probabilística de entidades, grafo de hipóteses (`log-odds`) e consultas causais (`WHY`). |

---

## 🛡️ Os três pilares

### 1. Imunidade a fraudes retroativas

O log é *append-only* e endereçado por conteúdo. Cada evento referencia seus pais (`parents: Vec<EventId>`) e todo o log é selado por uma cadeia de hashes blake3 (prova Merkle). **Reescrever o passado exigiria reescrever toda a cadeia subsequente** — imediatamente detectável via `db.verify()`. Validado com *injeção de falhas*: **1.000 abortos no meio do append, zero perdas**.

### 2. 100% de transparência (auditável por construção)

Toda estrutura derivada — o grafo, os índices vetoriais, os fatos semânticos — é uma **visão materializada** do log, reconstruível por *replay* determinístico a partir do LSN 0. Não existe estado oculto, nem daemons modificando dados às 3 da manhã. O que o auditor vê é exatamente o que aconteceu, na ordem exata.

### 3. Zero amnésia estrutural

O "esquecimento" aqui é uma **propriedade do índice, não destruição física do dado**. Dados frios são desindexados e movidos para *object storage* com um **recibo criptográfico de rebaixamento** (blake3 DemotionReceipt) — mas o evento original permanece no log para sempre. O sistema pode se tornar mais barato sem nunca perder a capacidade de provar o que sabia.

---

## 🏛️ Conformidade Governamental: Timestamping Legal (RFC 3161 / ICP-Brasil)

A integridade matemática (log imutável + raiz Merkle blake3) prova que o estado é **internamente** consistente. Para um tribunal, esse estado precisa ser ancorado à **hora oficial legal do país**. O crate [`heraclitus-compliance`](crates/heraclitus-compliance) constrói essa ponte — sem tocar no core, em Rust puro (sem OpenSSL/C):

- **Compromisso reproduzível.** Consolida as raízes dos segmentos selados em um único *commitment* até um watermark de LSN; deriva um imprint **SHA-256** (TSAs não aceitam blake3 — apenas OIDs registrados).
- **Timestamping assíncrono por watermark.** Um daemon ancora o estado consolidado a cada marco (N LSNs ou T minutos) — **nunca** no caminho crítico de escrita. A chamada à TSA roda em thread blocante, sem degradar QPS.
- **TSA plugável.** `LocalTsa` (em processo, prova o fluxo sem credenciais) e `HttpTsa` (requisição RFC 3161 real para TSA credenciada, e.g. SERPRO sincronizado com o Observatório Nacional).
- **Assinatura Institucional.** Trait `InstitutionalSigner` com `SoftKeySigner` (dev) e `Pkcs11Signer` (produção — chave em **HSM/PKCS#11**; certificado A1 em arquivo é rejeitado pela segurança das agências).
- **Assinaturas pós-quânticas (FIPS 204).** `MlDsaSigner` (ML-DSA-44) + `HybridSigner` (ECDSA P-256 **e** ML-DSA — quebrar qualquer um invalida o par).
- **Recibo Legal.** Token `<lsn>.tst` + `manifest.jsonl` append-only, com o commitment recomputável a partir do log imutável.

```bash
# Ancorar o estado selado (dev TSA local; usar --tsa-url para TSA real)
cargo run -p heraclitus-cli -- anchor ./data/log --receipts ./data/receipts

# Verificação forense: revalida integridade do log + todos os recibos
cargo run -p heraclitus-cli -- verify-receipts ./data/log --receipts ./data/receipts
```

O que isso prova juridicamente: *que aquele estado existia **antes** do instante oficial T* — combinado com a ordem causal interna (log + HLC), fecha a prova forense. Adulteração de um registro já carimbado altera o commitment e a verificação **falha** — fraude retroativa torna-se detectável.

> **Roadmap de acreditação.** Implementado e testado: commitment, requisição RFC 3161, TSA dev/HTTP, verificador, daemon, CLI, ML-DSA híbrido. Próximos passos (requerem âncoras de confiança do órgão): validação do `.tst` (CMS) real contra raízes ICP-Brasil; provedor concreto PKCS#11/HSM; meta-auditoria de acesso, mascaramento LGPD dinâmico, ABAC por partição, conectores SIAFI/SIAPE.

---

## 🌀 O fosso técnico: geometria aprendida do dado

O HeraclitusDB é o único banco que aceita que dados de conhecimento são **mistos**: hierarquias vivem em espaços hiperbólicos ($\mathcal{H}$), ciclos em esféricos ($\mathcal{S}$), atributos em euclidianos ($\mathcal{E}$) — simultaneamente, em uma variedade produto:

$$\mathcal{P} = \mathcal{H}^a(\kappa_1) \times \mathcal{S}^b(\kappa_2) \times \mathcal{E}^c \qquad d(x,y) = \sqrt{w_1\,d_{\mathcal{H}}^2 + w_2\,d_{\mathcal{S}}^2 + w_3\,d_{\mathcal{E}}^2}$$

O diferencial: as curvaturas $\kappa_i$, dimensões $(a, b, c)$ e pesos $w_i$ **não são decretados — são estimados a partir da distorção dos dados** e reajustados na compactação (sempre como *nova versão* do índice, trocada por watermark blue/green; o log jamais é mutado). Pinecone e Qdrant dão espaço plano. O HeraclitusDB pergunta ao seu *dado* qual a forma geométrica que ele tem.

### Contra os incumbentes

- **Neo4j — a mentira do presente absoluto.** Rei dos grafos, mas o estado é **mutável**: sobrescreve história. Sem viagem no tempo física (`AS OF LSN`), sem grafo auditável derivado do log, sem arestas probabilísticas concorrentes. Neo4j desenha grafos no presente; o HeraclitusDB *extrai* o grafo do tempo.
- **PostgreSQL + pgvector — a mentira do espaço plano.** Inteligência vetorial como *bolt-on* em espaço euclidiano estático; não aprende a geometria do dado, e travessias profundas via `WITH RECURSIVE` são caras. Confiam em tabelas mutáveis; HeraclitusDB confia no fluxo de eventos.

---

## 🗂️ Arquitetura de crates (workspace Rust)

O workspace contém **27 crates** organizados em camadas estritas — nada em storage conhece HTTP ou LLMs:

```
heraclitus-core          ← tipos compartilhados: Episode, Fact, ProductPoint, HLC, LSN,
                            VM (H-VM ISA), EBR, NUMA, plugin, sandbox, streaming, telemetria
heraclitus-log           ← o único escritor da verdade: log segmentado append-only,
                            crc32/blake3 por registro, Merkle por segmento, torn-write recovery,
                            group-commit, keystore (cifra em repouso), vm_bridge (H-VM no log),
                            zone maps (SPEC-010), stream subscribe (SPEC-022)
heraclitus-crypto        ← cifra em repouso: ChaCha20-Poly1305, KeyStore por agente
heraclitus-manifold      ← geometria produto H×S×E aprendida; Möbius, exp/log maps,
                            centróide hiperbólico, estimação de curvatura (estimate.rs)
heraclitus-memtable      ← cauda síncrona: read-your-own-writes garantido em < 1ms
heraclitus-views         ← motor de replay determinístico: trait View, checkpoints atômicos
                            (fast boot: lê estado + replaya só a cauda [watermark, head])
heraclitus-index-vector  ← HNSW sobre a variedade produto; tombstones semânticos; search_exact_gpu
heraclitus-index-graph   ← grafo temporal derivado do log; Leiden community detection;
                            assert/retract de arestas; MATCH AS OF LSN
heraclitus-index-text    ← índice BM25 invertido; fuzzy; tokenização multilíngue
heraclitus-index-attr    ← índice de atributos ordenado; range scan sem table scan (SPEC-010)
heraclitus-activation    ← ativação ACT-R O(1): Petrov-style head exato + cauda integral;
                            spreading activation; determinístico no replay (HLC, não wall-clock)
heraclitus-retrieval     ← fusão RRF: ANN ∥ BM25 ∥ ACT-R (top-200 cada) → k=60 → reranker
heraclitus-distill       ← compactação: clustering manifold → emite Fact como evento no log;
                            re-fit de curvatura; blue/green index swap; Parquet cold tier (arrow-rs)
heraclitus-tier          ← tiering: rebaixamento de itens frios; DemotionReceipt blake3;
                            escrita dupla Parquet; CompactionPolicy (delta-ratio)
heraclitus-btree         ← Bᵋ-tree (Fractal Tree) comercial: CoW shadow paging, 4KB pages,
                            overflow chains, Bloom filters, prefix compression, 32-shard cache,
                            checkpoint atômico blake3; save/load crash-safe
heraclitus-gpu           ← aceleração heterogênea (M20.3): batch distance GPU (wgpu, Intel Arc),
                            kernel WGSL produto manifold; OP_QUANTIZE na fronteira (invariância ordinal);
                            fallback CPU obrigatório; feature flag `gpu`
heraclitus-compliance    ← timestamping legal RFC 3161 / ICP-Brasil; ML-DSA-44 + ECDSA híbrido;
                            PKCS#11/HSM; daemon assíncrono; recibo juridicamente vinculante
heraclitus-query         ← parser pest (Cypher/GQL subset) fuzzado; planner rule-based;
                            EXPLAIN; AS OF LSN/TIMESTAMP; VALID AT; DIST_HYP/DIST_PRODUCT;
                            REQUIRE LSN; backend lock-free ArcSwap (M30)
heraclitus-txn           ← MVCC: Snapshot = LSN; begin_with(IsolationLevel); compare_and_append CAS
heraclitus-raft          ← replicação: v0 log-shipping pull; + feature `replication`:
                            openraft 0.9 real — eleição, quórum, failover, WAL durável em disco,
                            transporte TCP real; suíte turmoil (partição → heal → zero acks perdidos)
heraclitus-proto         ← protobuf gRPC (tonic/prost)
heraclitus-server        ← gRPC (tonic :7474) + REST (axum :7475) + boot narrado (Fedora-style):
                            spinner braille, cores ANSI, ENABLE_VTP no Windows; checkpoint periódico
                            de views; telemetria endógena (SystemMetric no log); Arrow Flight opt-in
heraclitus-client        ← cliente Rust (gRPC)
heraclitus-cli           ← CLI: bench, verify, verify-receipts, anchor, query
heraclitus-wasm          ← sandbox WASM (wasmtime): fuel metering, isolamento de memória,
                            traps contidos; WasmPluginAdapter → PluginHost do core (SPEC-025/035)
heraclitus-analytics     ← SQL OLAP (DataFusion) sobre o log; Arrow Flight data plane;
                            planner (SPEC-024); motor vetorizado (SPEC-012/013)
```

### Fluxo de dados

```
                      ┌──────────────────────────────────────────────┐
                      │                  agents / CLI                │
                      └────────┬─────────────────────────┬───────────┘
                               │ Append (gRPC)           │ Query / Recall
                               ▼                         ▼
                     ┌──────────────────┐     ┌──────────────────────┐
                     │  heraclitus-log  │     │ heraclitus-retrieval │
                     │  append-only,    │     │  RRF fuse + rerank   │
                     │  crc + blake3    │     └──────────┬───────────┘
                     └────────┬─────────┘               │ merge(memtable, views)
               tail_subscribe │                          │
           ┌──────────────────┼──────────────────────────┤
           ▼                  ▼                          │
┌────────────────┐ ┌──────────────────┐                  │
│   memtable     │ │ heraclitus-views │                  │
│ (tail, exact,  │ │  replay engine   │                  │
│  RYOW)         │ │  + checkpoints   │                  │
└────────────────┘ └────────┬─────────┘                  │
                            │ apply (deterministic)      │
       ┌──────────┬─────────┼──────────┬──────────┐      │
       ▼          ▼         ▼          ▼          ▼      │
   ┌───────┐ ┌────────┐ ┌───────┐ ┌──────────┐ ┌──────┐  │
   │vector │ │ graph  │ │ text  │ │activation│ │facts │──┘
   │(HNSW) │ │(adj +  │ │(BM25) │ │ (ACT-R)  │ │store │
   └───────┘ │ attrs) │ └───────┘ └──────────┘ └──────┘
             └────────┘
   ▲ todas as views: derivadas, apagáveis, reconstruíveis do LSN 0

background (policy-triggered, nunca daemons autônomos):
┌──────────────────────┐    emite FactDerived / DemotionReceipt
│ heraclitus-distill   │──────────────► de volta ao LOG
│ heraclitus-tier      │    (fatos são eventos do log também)
└──────────────────────┘
```

---

## ✅ Maturidade: M0–M31 completos

| Milestone | Gate de Aceitação | Status |
| :--- | :--- | :--- |
| **M0** log append-only | 1.000 injeções de crash (kill no meio do append) + fuzzing do decoder | ✅ zero perdas, Merkle estável |
| **M1** variedade produto | proptests (norma < 1, exp∘log roundtrip < 1e-4, simetria) | ✅ |
| **M2** memtable + views | replay determinístico; read-your-own-writes < 1ms | ✅ |
| **M3** ativação ACT-R | aproximação O(1) com erro < 5% vs. oráculo exato; RRF | ✅ |
| **M4** snapshots + GQL | fuzzing do parser (100k inputs, 0 panics); `EXPLAIN`; `AS OF LSN` | ✅ |
| **M5** distill + tier | roundtrip de proveniência; verificação de recibos de rebaixamento | ✅ |
| **M6** gRPC + replicação | suíte turmoil: partição → heal → zero acks perdidos | ✅ |
| **M7** benchmark | curvas QPS × recall publicadas (recall@10 = 0.996 em ef=16) | ✅ |
| **M8** motor de grafos v1 | 100% derivado do log; `NEIGHBORS` & `TRAVERSE` determinísticos | ✅ blake3 `state_hash` |
| **M9** grafo temporal | `MATCH (a)-[r]->(b) AS OF LSN X` igual ao replay parcial | ✅ assert/retract de arestas |
| **M10** motor híbrido | `FUSE` grafo + vetor + texto supera canais isolados | ✅ pesos versionados |
| **M11** resolução de entidade | clustering determinístico; merge/split reproduzíveis por replay | ✅ `RESOLVE` / `CLUSTER` |
| **M12** grafo de hipóteses | versões concorrentes de arestas coexistem; crença por log-odds | ✅ `HYPOTHESES` |
| **M13** consultas causais | `WHY` retorna a cadeia causal mínima com proveniência | ✅ rastreamento completo |
| **M14** análise de grafos | `COMMUNITY` e `METRICS` (centralidade, anomalia) estáveis | ✅ componentes conexas + z-score |
| **M15** camada de decisão | regras emitem eventos `Action` no log; idempotência via `action_id` | ✅ `DECIDE` |
| **M16** motor contrafactual | `SIMULATE ADD/REMOVE EDGE ... THEN` sem tocar no log | ✅ divergência isolada em RAM |
| **M17** grafo adaptativo | `ADAPT` aprende limiar de decisão do feedback | ✅ F1 melhora, replay-estável |
| **M18** contrato de consistência | `REQUIRE LSN >= X` falha explicitamente se backend atrasado | ✅ sem leituras obsoletas |
| **M19** boot narrado + fast-start | boot Fedora-style (cores/spinner, geometria/portas "falando"); checkpoints de view para cold-start rápido | ✅ boot · ✅ fast-start (**28ms** com snapshots) |
| **M20** H-VM + Fractal Tree + GPU (Sovereignty Layer) | reducer determinístico (equivalência sob reordenação); Bᵋ-tree (proptest vs `BTreeMap`); Top-M quantizado (invariância ordinal); **GPU dispatch wgpu validado em Intel Arc 140V** (GPU Top-M == referência CPU f64); métrica produto manifold no WGSL + `search_exact_gpu` | ✅ completo: CPU + GPU wired |
| **M22** Bᵋ-tree comercial com arquivo | CoW shadow paging; split/flush byte-aware (4KB); overflow chains; `save`/`load` crash-safe | ✅ invariante cache==node.id; stress 500 keys + reload |
| **M30** refatoração backend de query | LogBackend lock-free (bundle ArcSwap); MVCC `AS OF` único (`as_of_point`) em LogBackend/server/VirtualBackend; ts_hlc carimbado no log; read-your-writes no ACK | ✅ suíte 100% verde, 0 ignorados |
| **M31** fast boot + introspecção + operadores | compat de leitura FORMAT v2→v3→v4; checkpoint/restore dos 6 views (replay só da cauda); REST `/state` + `/verify/{seg}`; `DIST_*` e range numérico em GQL; servidor MCP | ✅ boot 28ms · Merkle verificável por segmento |

> **M20 — Sovereignty Layer (CPU + GPU completo).** H-VM (reducer determinístico + ISA bytecode persistido no log), Bᵋ-tree (Fractal Tree) com checkpoint atômico Blake3, e Top-M quantizado para invariância ordinal — tudo conectado ao `Engine` (ledger `hvm_*`). GPU dispatch wgpu validado em hardware real (Intel Arc 140V): `gpu_matches_cpu_on_hardware` e `product_gpu_matches_cpu_on_hardware` (GPU Top-M == referência CPU f64, bit-ordinal). Kernel WGSL da métrica produto manifold (Poincaré + esfera + euclídeo). `search_exact_gpu` no índice vetorial: RECALL exato na GPU + rescore f64 no CPU. Detalhes em [docs/md/M20_hvm_fractal_gpu.md](docs/md/M20_hvm_fractal_gpu.md).

> **M31 (fast boot).** Cada view persiste snapshot (`<data>/views/*.ckpt`, escrita atômica) no boot e no shutdown gracioso; próximo startup restaura e replaya **só a cauda** `(watermark, head]`. Correção nunca depende do checkpoint — sem ele, reconstrói do LSN 0. Segmentos FORMAT v2 e v3 permanecem legíveis (decode versionado por segmento). Lição operacional que motivou o milestone: carga de 136M eventos (56 GB) tornava o boot por replay total inviável.

---

## 🧨 O motor de consulta (subconjunto Cypher/GQL + operadores temporais)

Não inventamos uma linguagem. Implementamos um subconjunto estrito de Cypher/GQL — parseado com pest, fuzzado com 100k inputs sem pânico — enriquecido com operadores temporais, probabilísticos e causais:

```sql
-- Grafo + viagem no tempo (a prova contra fraudes)
MATCH (a)-[r:fraud_partner]->(b) RETURN b.id, r.type
MATCH (a)-[r]->(b) AS OF LSN 1000 RETURN *          -- o grafo como era no passado
MATCH (n) AS OF TIMESTAMP 1700000000 RETURN n

-- Bi-temporal (valid time × transaction time, SQL:2011/XTDB-style)
MATCH (n) VALID AT 1700 RETURN n                    -- quando o fato era real no mundo
MATCH (n) VALID AT 1700 AS OF LSN 500 RETURN n      -- ...conforme registrado até LSN 500

-- Busca híbrida (grafo + vetor + texto)
RECALL ("empresa de fachada vencendo licitações públicas", 5)
FUSE ("fraude", [0.5, 0.1], "anchor_node_id", 10)

-- Proveniência, causalidade e crença
PROVENANCE ("fact_id")        -- de onde este fato veio
WHY ("action_id", 5)          -- a cadeia causal mínima
HYPOTHESES ("from_id", "to_id", "fraud_partner")

-- Resolução de entidades e decisão
RESOLVE ("CPF:123")
CLUSTER ("CPF:123")
DECIDE ()

-- Contrafactual (o log nunca é tocado; a divergência é isolada em RAM)
SIMULATE REMOVE EDGE ("A1", "B1", "socio_de") THEN COMMUNITY ("A1")

-- Distâncias da variedade produto como operadores (M31, estilo pgvector)
MATCH (n) WHERE DIST_HYP([0.12]) < 0.1 RETURN n
MATCH (n) RETURN n ORDER BY DIST_PRODUCT([0.1, 0.2]) LIMIT 10

-- Range numérico resolvido pelo índice ordenado, sem scan (M31, estilo Qdrant)
MATCH (n) WHERE n.valor > 10000 AND n.valor < 200000 RETURN n

-- Contrato de consistência (M18)
REQUIRE LSN >= 5000 MATCH (n) RETURN n

-- EXPLAIN (M4)
EXPLAIN MATCH (n) WHERE n.tipo = "empresa" RETURN n LIMIT 10
```

---

## 🚀 Em 60 segundos

```bash
git clone https://github.com/JoseRFJuniorLLMs/HeraclitusDB
cd HeraclitusDB

cargo test --workspace          # todos os testes e proptests
cargo run -p heraclitus-server  # gRPC :7474 + REST :7475

# Prova criptográfica de integridade do log
cargo run -p heraclitus-cli -- verify ./data/log

# Benchmark HNSW recall × QPS
cargo run -p heraclitus-cli -- bench --n 20000 --dim 16
```

### 🐍 Python SDK

```bash
pip install ./sdk/python
```

```python
import heraclitusdb
db = heraclitusdb.connect("127.0.0.1:7474")

lsn = db.append("Observation", "empresa X alterou quadro societário", attrs={"caso": "1"})
df  = db.query_df('MATCH (n) LIMIT 1000')          # pandas.DataFrame
past_df = db.query_df('MATCH (n)', as_of=1000)     # viagem no tempo
db.recall("empresa de fachada vencendo licitação", k=10)
db.verify()                                         # validação Merkle global
```

### 🤖 Servidor MCP (memória auditável para agentes de IA)

Servidor [MCP](https://modelcontextprotocol.io) nativo (stdio) em [mcp/heraclitus_mcp.py](mcp/heraclitus_mcp.py) — qualquer cliente MCP (Claude Code, Claude Desktop etc.) pode usar o HeraclitusDB como memória de agente com prova anti-fraude. Registrado no projeto via [.mcp.json](.mcp.json).

Ferramentas: `remember` · `recall` (fusão semântica+lexical via RRF) · `query` (superfície GQL completa incluindo `AS OF`) · `why` · `provenance` · `stats` · `verify` (Merkle, log completo ou por segmento) · `state` (introspecção)

### 🔎 Introspecção operacional (REST :7475)

```bash
curl http://127.0.0.1:7475/state          # head_lsn, segmentos (versão/raiz Merkle), watermarks das views
curl http://127.0.0.1:7475/verify         # verificação Merkle do log completo
curl http://127.0.0.1:7475/verify/0       # prova pontual de UM segmento (computed_root vs stored_root)
curl http://127.0.0.1:7475/stats          # contagens das views
```

### 📊 SQL Analytics (Apache Arrow / DataFusion)

```bash
# Arrow Flight (opt-in, feature analytics)
cargo run -p heraclitus-server --features analytics
```

```sql
-- SQL OLAP sobre o log imutável (DataFusion, sem decodificar bincode à mão)
SELECT agent_id, COUNT(*) AS n FROM events GROUP BY agent_id ORDER BY n DESC

-- Parquet na camada fria: consultas via DuckDB/DataFusion sem decodificar blocos raw
SELECT * FROM 'data/cold/*.parquet' WHERE kind = 'Observation'
```

---

## 📊 Benchmarks publicados

> Capturado em 2026-07-03 em laptop Windows 11 (build release, medianas criterion). Reprodutível: `cargo bench --workspace`

### Busca vetorial — HNSW na variedade produto (gate M7)

`heraclitus-cli bench`, N = 20.000 vetores, dim = 16, tempo de build 4,8s:

| ef  | QPS    | recall@10 |
| --- | ------ | --------- |
| 16  | 8.589  | **0.996** |
| 32  | 8.734  | 0.996     |
| 64  | 10.051 | 0.996     |
| 128 | 4.181  | 0.996     |
| 256 | 2.430  | 0.996     |

`criterion` (`heraclitus-index-vector`): `hnsw_search` k=10, N=5000, d=48 → **~62,9 µs**

### Distância produto manifold (laço interno quente)

| Benchmark           | Mediana    |
| ------------------- | ---------- |
| `product_dist_48d`  | ~87,6 ns   |
| `product_dist_128d` | ~185,9 ns  |

Linearmente proporcional à dimensão, sem alocação por chamada.

### Caminho de append (trade-off de durabilidade)

| Política de durabilidade   | Mediana  |
| -------------------------- | -------- |
| `fsync_always`             | ~665 µs  |
| `group_commit` (5 ms)      | ~711 µs  |

### Boot (fast boot M31)

| Cenário                                          | Tempo    |
| ------------------------------------------------ | -------- |
| Boot com views restauradas do checkpoint         | **28–40 ms** |
| Boot a frio, replay total do LSN 0 (sem ckpt)   | escala com tamanho do log |

### Gates de integridade (CI, não velocidade)

| Gate                                    | O que prova                                               |
| --------------------------------------- | --------------------------------------------------------- |
| crash-injection (M0)                    | 1.000 abortos no meio do append, zero perdas              |
| fuzz `log_decode` / `query_parser`      | decoder e parser nunca entram em pânico (10 min cada)     |
| format compat (`v2_compat`)             | segmentos v2/v3/v4 legíveis sob o engine v4               |
| GPU self-check (`--features gpu`)       | dispatch wgpu == referência CPU f64 bit-a-bit              |

---

## 🗺️ Roadmap — ciclo de absorção técnica (concluído)

Análise de 8 bancos de referência (Qdrant, Milvus, pgvector, Memgraph, ArangoDB, Nebula, Dgraph, Chroma) + estado da arte 2025-2026. Ciclo **concluído** — tudo com suítes de testes:

| Feature absorvida | Referência | Subsistema alvo | Status |
| :--- | :--- | :--- | :--- |
| Tombstones no índice vetorial | Qdrant | `heraclitus-index-vector` | ✅ eventos `tombstone_of`; remoção lógica sem quebrar HNSW; checkpointed |
| Bi-temporal Valid Time | XTDB / SQL:2011 | convenção de `attrs` | ✅ `VALID AT t` em GQL, ortogonal ao `AS OF LSN` |
| Detecção de comunidades Leiden | leiden-rs | `heraclitus-index-graph` | ✅ `communities_leiden()` determinístico (semeado); fallback gracioso |
| Parquet na camada fria | arrow-rs | `heraclitus-tier` | ✅ dual-write no rebaixamento; SQL via DuckDB/DataFusion sem bincode raw |
| ML-DSA Híbrido (FIPS 204) | NIST PQC | `heraclitus-compliance` | ✅ `MlDsaSigner` (ML-DSA-44) + `HybridSigner` (ECDSA P-256 **e** ML-DSA) |
| Modo embarcado sem gRPC | Chroma | `heraclitus-server::Embedded` | ✅ engine completo in-process; mesmo dialeto GQL |
| Trigger de compactação por delta-ratio | Milvus | `heraclitus-tier` | ✅ `CompactionPolicy::should_compact(deleted, total)` |

**Decisões de não-absorção (o fosso defensável):** CRDTs multi-writer (underminariam a ordem total de LSN e o rastro de auditoria — rejeição definitiva); arena allocator no GraphIndex (medido: ~3× pior, travessia é random-access); `collection_id` nativo (`attrs` já oferece isso); PipeANN/DiskANN/PQ (apenas quando índice permanente exceder RAM — cargas massivas não vão para a instância em memória); GQL ISO formal (monitorar, não reescrever).

---

## 📚 Documentação

### Especificação normativa e arquitetura

| Documento | Conteúdo |
| :--- | :--- |
| [docs/md/SPEC-new/SPEC.md](docs/md/SPEC-new/SPEC.md) | Especificação normativa mestre completa (o blueprint do motor) |
| [docs/md/SPEC-new/SPEC-009-u64.md](docs/md/SPEC-new/SPEC-009-u64.md) | Camada de chaves canônicas, mapeamento denso de identidades, cache-layout CPU |
| [docs/md/SPEC-new/SPEC-010.md](docs/md/SPEC-new/SPEC-010.md) | Motores de armazenamento temporal segmentado, zone maps de disco, compilador JIT de índices efêmeros |
| [docs/md/SPEC-new/SPEC-011.md](docs/md/SPEC-new/SPEC-011.md) | Runtime de infraestrutura, abstração de storage API, gerenciamento de hardware |
| [docs/md/SPEC-new/SPEC-019-028.md](docs/md/SPEC-new/SPEC-019-028.md) | Consistência concorrente de leitura, crash recovery de cauda, replicação log-shipping, gramática HQL |
| [docs/md/SPEC-new/SPEC-029-035.md](docs/md/SPEC-new/SPEC-029-035.md) | Compatibilidade binária, replay multi-thread, NUMA, memória EBR, sandboxing WASM |
| [docs/md/ARCHITECTURE.md](docs/md/ARCHITECTURE.md) | Fluxo de dados e topologia de componentes |
| [docs/md/LOG_FORMAT.md](docs/md/LOG_FORMAT.md) | Formato binário do log (versioned v2→v4): header, record, footer, Merkle root, torn-write recovery |
| [docs/md/CONSISTENCY.md](docs/md/CONSISTENCY.md) | Modelo formal de garantias de consistência (e o que honestamente não garantimos) |
| [docs/md/GEOMETRY.md](docs/md/GEOMETRY.md) | Matemática da variedade produto + estimação de curvatura offline |
| [docs/md/ACTIVATION.md](docs/md/ACTIVATION.md) | Derivação e limites de erro da aproximação O(1) de ativação ACT-R |
| [docs/md/DEV_WINDOWS.md](docs/md/DEV_WINDOWS.md) | Setup de desenvolvimento no Windows |
| [docs/md/lean-lang.md](docs/md/lean-lang.md) | Análise do uso de Lean 4 para prova formal de propriedades críticas do motor |

### Notas técnicas dos milestones

| Documento | Conteúdo |
| :--- | :--- |
| [docs/md/M19_boot_narrado.md](docs/md/M19_boot_narrado.md) | M19: boot narrado estilo Fedora/systemd — spinner braille, ANSI/UTF-8 no Windows, `HERACLITUS_PLAIN_BOOT` |
| [docs/md/M19_fast_start.md](docs/md/M19_fast_start.md) | M19: fast-start por checkpoint de views — problema OOM com 4,6M eventos, design e gates |
| [docs/md/M20_hvm_fractal_gpu.md](docs/md/M20_hvm_fractal_gpu.md) | M20: H-VM + Fractal Tree + GPU (Sovereignty Layer) — ISA, Bᵋ-tree, dispatch wgpu validado em Intel Arc |
| [docs/md/M30_heraclitus-query_backend_rs.md](docs/md/M30_heraclitus-query_backend_rs.md) | M30: refatoração do backend de query — lock-free LogBackend, ArcSwap bundle, MVCC unificado |

### Benchmarks e auditorias

| Documento | Conteúdo |
| :--- | :--- |
| [docs/md/BENCHMARKS.md](docs/md/BENCHMARKS.md) | Metodologia de benchmark e notas de hardware |
| [benches/REPORT.md](benches/REPORT.md) | Curvas QPS × recall publicadas (M7, recall@10 = 0.996 em ef=16) |

### RFCs — Architecture Decision Records

| RFC | Tópico |
| :--- | :--- |
| [RFC-001](docs/md/RFCs/RFC-001-log-serialization.md) | Formato de serialização do log (bincode v2, episódio, versão FORMAT) |
| [RFC-002](docs/md/RFCs/RFC-002-view-persistence.md) | Estratégia de persistência de views (checkpoints atômicos, fast boot) |
| [RFC-003](docs/md/RFCs/RFC-003-replication-v0.md) | Replicação v0 (log-shipping pull-based) + openraft consenso real |
| [RFC-004](docs/md/RFCs/RFC-004-belief-aggregation.md) | Agregação de crença no grafo de hipóteses (log-odds) |
| [RFC-005](docs/md/RFCs/RFC-005-probabilistic-entity-resolution.md) | Resolução probabilística de entidades |
| [RFC-006](docs/md/RFCs/RFC-006-temporal-decay.md) | Decaimento temporal de relevância de arestas |
| [RFC-007](docs/md/RFCs/RFC-007-temporal-graph-metrics.md) | Métricas de grafo temporal |
| [RFC-008](docs/md/RFCs/RFC-008-decision-action-boundary.md) | Fronteira decisão/ação (DECIDE, idempotência por action_id) |

### READMEs dos submódulos

| Módulo | Conteúdo |
| :--- | :--- |
| [mcp/README.md](mcp/README.md) | Setup do servidor MCP e referência de ferramentas |
| [sdk/python/README.md](sdk/python/README.md) | Instalação e referência da API Python SDK |
| [sdk/python-embedded/README.md](sdk/python-embedded/README.md) | Python SDK embarcado (sem gRPC, via PyO3/maturin) |
| [windows/README.md](windows/README.md) | Build e empacotamento específicos do Windows |
| [demo/demo.md](demo/demo.md) | Demo ao vivo de detecção de fraudes |

---

## 🔒 Modelo de consistência formal

O HeraclitusDB é um sistema event-sourced com log único, totalmente ordenado e append-only por nó. Escritas são **linearizáveis no log**: `append` retorna um LSN, e a ordem de LSN *é* a verdade. Todos os índices são views materializadas assíncronas; cada view expõe um **watermark** (LSN mais alto aplicado). Leituras são **snapshot reads em um LSN**: a query carrega `snapshot_lsn` e é respondida por `merge(memtable acima do watermark, views no watermark)`.

| Propriedade | Garantia |
| :--- | :--- |
| Durabilidade (fsync=always) | Append ackado sobrevive a kill do processo e crash do SO com cache de disco limpo |
| Durabilidade (group_commit) | Append ackado pode perder no máximo o intervalo configurado (padrão 5ms) em crash total; kill do processo perde nada já escrito com CRC íntegro |
| Ordem de escrita | Ordem total por LSN; escritor único por processo; CAS append (`expected_lsn`) para workflows otimistas |
| Read-your-own-writes | Garantido: memtable indexa a cauda sincronamente no append; queries fazem merge memtable + views com dedup por LSN |
| Leituras monotônicas | Garantidas por cliente quando reutilizando snapshots com LSNs não-decrescentes |
| Leituras temporais | `AS OF LSN n` responde do estado da view no watermark ≥ n, filtrado a eventos ≤ n |
| Imutabilidade | Registros do log nunca são mutados; a única mutação de arquivo já feita é truncamento da cauda rasgada na recovery |
| Corrupção | Nunca engolida silenciosamente: sempre emite `heraclitus_corruption_recovered_total` + evento tracing |

---

## 🔌 Modo embarcado (sem gRPC)

Engine completa instanciável in-process, mesmo dialeto GQL, sem dependência de rede:

```rust
use heraclitus_server::Embedded;

let db = Embedded::open("./data")?;
let lsn = db.append("alice", "Observation", "empresa X alterou sócios", &[])?;
let rows = db.query("MATCH (n) LIMIT 100")?;
db.verify()?;
db.checkpoint()?;
```

---

## ⚖️ Licença e modelo comercial

O **núcleo** do HeraclitusDB — o motor Rust, o formato de log e a especificação geométrica — é distribuído sob a **Business Source License 1.1 (BSL 1.1)**: *código aberto com restrição comercial*.

- ✅ **Livre** para leitura, auditoria, modificação e uso em desenvolvimento, testes, pesquisa e avaliação.
- ✅ **Código-fonte sempre aberto** — alinhado com o compromisso de transparência do próprio produto.
- 💰 **Uso em produção e uso por competidores requerem licença comercial.** Fale com os autores.
- 🔓 **Data de conversão:** em **2030-06-21**, cada versão converte automaticamente para **Apache-2.0**.

Consulte o texto completo em [LICENSE](LICENSE). Para licenciamento comercial / produção / governo, contate os autores.

> Por que BSL e não Apache puro: o produto *é* a garantia de transparência e imutabilidade. Manter o código aberto e auditável é inegociável (BSL entrega isso), mas a sustentabilidade comercial exige que uso em produção e por competidores passe por licença paga. É o modelo do CockroachDB, Sentry e MariaDB.

---

**Licença:** BSL 1.1 (converte para Apache-2.0 em 2030-06-21) · Autores:

**José R F Junior**
Servidor Público Federal — Poder Executivo (Brasil)
Matrícula SIAPE nº 1.634.972
joseribamar.junior@inss.gov.br / web2ajax@gmail.com
2020–2026

> *"Panta rhei — nenhum homem pisa no mesmo rio duas vezes. E nenhum fraudador reescreve um rio que já fluiu."*
