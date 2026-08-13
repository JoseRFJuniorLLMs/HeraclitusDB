# PLANO-SPECS.md — Roteiro-âncora das especificações do HeraclitusDB

**Recriado:** 2026-07-11 · **Estado:** documento vivo (não congelado)

> **Porquê este ficheiro existe.** A [`SPEC-new/STATUS.md`](SPEC-new/STATUS.md)
> aponta repetidamente para um `PLANO-SPECS.md` como "o roteiro real" — mas o
> ficheiro **não existia no disco** (tal como `SPEC.md`, `ARCHITECTURE.md`,
> `LOG_FORMAT.md` e a pasta `RFCs/` que o `README.md` cita: `docs/md/` só continha
> `SPEC-new/`). Este documento reconstrói essa âncora a partir do que é
> **verificável no código real** (crates + testes) e no `README.md`. Ele é a
> régua contra a qual qualquer proposta em `SPEC-new/` deve ser medida antes de
> virar código.

---

## 0. Regra de ouro: RFC ≠ implementação

Os documentos em [`SPEC-new/`](SPEC-new/) são **propostas (RFCs)**, não estado do
sistema. Vários auto-declaram-se "CONGELADO", "APROVADO" ou "auditado" para
componentes que **não existem em nenhum crate** — e alguns (`SPEC-0036`,
`SPEC-0040`) são literalmente output de chat de LLM colado, abrindo com bajulação
ao interlocutor. A auditoria adversarial que produziu a `STATUS.md` confirmou
isto item a item.

**Consequência operacional:**
1. Nunca citar `SPEC-new/` como estado de implementação.
2. Toda ideia de `SPEC-new/` entra pela porta da **extração incremental** (§4),
   não como programa a construir por inteiro.
3. O estado real de maturidade é o do `README.md` (M0–M31) + a tabela da
   `STATUS.md` (SPEC-009–035 como módulos reais).

---

## 1. A tese fundadora (invariantes inegociáveis)

Qualquer spec que contrarie um destes pontos é **rejeitada por design**, por mais
elegante que seja:

| # | Invariante | Fonte |
|---|---|---|
| I1 | **Log append-only é a única verdade.** Nada é mutado; correção = novo evento. Estado passado reconstruível bit-a-bit (`AS OF LSN`) com prova Merkle blake3. | README §pilares |
| I2 | **A inteligência vive no agente, não no banco.** O banco não vira uma catedral de compiladores/JIT/cost-models adaptativos. | tese `SPEC.md` (citada na STATUS) |
| I3 | **Não inventar linguagem de consulta nova.** A superfície é **GQL** (subconjunto Cypher/GQL, `gql.pest`) + operadores temporais/causais. HQL foi **rejeitado** (SPEC-023). | README §motor de consulta |
| I4 | **Não duplicar o DataFusion.** SQL OLAP fica no DataFusion (motor Arrow maduro); o motor vetorizado próprio é só para os micro-planos `PhysicalIr` sobre o log. | `analytics/vectorized.rs:22-28` |
| I5 | **Geometria é aprendida, não decretada.** Curvaturas/dimensões/pesos da variedade produto H×S×E são estimados do dado; troca por watermark blue/green, log intocado. | README §fosso técnico |
| I6 | **Views são derivadas e descartáveis.** Todo índice reconstrói do LSN 0. Sem estado oculto, sem daemons autónomos mutando dados. | README §transparência |
| I7 | **Binary Quantization como métrica do HNSW: rejeitada permanentemente.** `sign(x)` destrói a hierarquia hiperbólica. Pre-filter com oversampling ≥30× + rescore é a única exceção. | `CLAUDE.md` (ITEM F) |
| I8 | **EVA usa NietzscheDB (intocável); projetos NOVOS usam HeraclitusDB.** | `CLAUDE.md` |

---

## 2. Estado real (a linha de base verificada)

**Maturidade:** M0–M31 completos (README), workspace ~254 testes verdes (STATUS).
26 crates em `crates/`. O que existe e funciona, resumido:

- **Núcleo imutável:** `heraclitus-log` (segmentado `.hrkl`, crc32+blake3, Merkle
  por segmento, torn-write recovery, group-commit), `heraclitus-views` (replay
  determinístico + checkpoints, fast boot 28ms), `heraclitus-memtable` (RYOW).
- **Multimodal:** índices grafo (Leiden, temporal `AS OF`), vetor (HNSW na
  variedade produto, GPU wgpu validado em Intel Arc), texto (BM25), attr (range
  scan ordenado, zone maps SPEC-010).
- **Geometria:** `heraclitus-manifold` (H×S×E, Möbius, estimação de curvatura).
- **Consenso:** `heraclitus-raft` com feature `replication` — openraft 0.9 real
  (eleição, quórum, failover, WAL durável em disco, transporte TCP, restart de
  processo provado), ligado ao servidor. Resta só um wrapper gRPC cosmético.
- **Analítica:** `heraclitus-analytics` — SQL via DataFusion **+** motor
  vetorizado v1 próprio (`vectorized.rs`, 670 l.: `SelectivityOptimizer` →
  `PhysicalIr` → `VecExecutor`, batches 1024, filter/aggregate/hash-join, Gate C).
- **Isolamento:** `heraclitus-wasm` (wasmtime, fuel metering), `heraclitus-gpu`,
  `heraclitus-compliance` (RFC 3161, ML-DSA híbrido).

**SPEC-009–035** (per STATUS): implementados como **módulos Rust reais e
testados**, a maioria já **wired** ao caminho vivo. Não são "engine de produção
completo" — são o contrato + implementação de referência.

---

## 3. Classificação do SPEC-new (o veredicto por documento)

| Doc | O que propõe | Veredicto | Ação |
|---|---|---|---|
| `SPEC-000` | ABI de execução HUME (StorageBatch/ExecutionBatch, ScratchAllocator, SSA, contrato de benchmark) | RFC/visão; nada em crate | Extrair peças isoladas (§4) |
| `SPEC-0036` | Plataforma "enterprise" (Resource/Buffer/Scheduler managers, lakehouse Iceberg, object-store S3) | RFC + output de chat | Rejeitar wholesale; ideias de resource-quota como RFC futuro |
| `SPEC-0037` | AQE, cost model multidim., pipeline push-based, JIT Cranelift, federação Postgres/Kafka | RFC/SOTA aspiracional | Rejeitar compilador+federação; ver §4/§5 |
| `SPEC-0038` | HUME-IR SSA, DataChunk, pipeline fusion, radix join, io_uring | RFC | Extrair DataChunk/late-mat/radix (§4) |
| `SPEC-0039` | HUME-IR multi-dialeto (MLIR), learned optimizer (XGBoost/TinyNN), speculative exec | RFC | Rejeitar (§5) |
| `SPEC-0040` | Kernel core + roadmap "humilhar DuckDB", benchmark 10B linhas | RFC + output de chat | Rejeitar a premissa de escala (§5) |
| `SPEC-0041` | Revisão normativa do kernel: SelectionVector adaptativo, morsel adaptativo, `hume-kernel` SIMD | RFC — **a melhor peça** | Extrair SelectionVector + morsel adaptativo (§4) |

---

## 4. Fases de execução (o que realmente se faz)

### Fase 0 — Higiene documental (barata, imediata)
- [x] Recriar este `PLANO-SPECS.md` (âncora).
- [ ] Aplicar/confirmar banner "RFC — não implementação" no topo de cada
      `SPEC-new/*.md` (a STATUS diz que foi feito em 2026-07-08/09; verificar).
- [ ] Reconciliar o `README.md`: ou repor os docs ausentes (`SPEC.md`,
      `ARCHITECTURE.md`, `LOG_FORMAT.md`, `RFCs/`, notas M19/M20/M30) ou corrigir
      os links mortos. **Documentação que aponta para o vazio é dívida.**

### Fase 1 — Extração incremental do HUME (candidatos aprovados)
Cada item é um **PR isolado contra `heraclitus-analytics`/`heraclitus-log`
existentes**, com benchmark na forma de query real do produto (§6). Ordem por
relação ganho/risco:

1. **`SelectionVector` adaptativo** (SPEC-0041): `Bitmap` (≥25% sobrevivência) vs
   `Index16/Index32` (<25%), com promoção dinâmica após cada filtro. Encaixa no
   `VecExecutor` atual. Ganho: menos varredura de bits zerados em queries
   seletivas (a maioria das queries de memória de agente é seletiva).
2. **Late materialization** com `PhysicalRowID` (SPEC-0038/0040/0041): ler só as
   colunas de predicado no scan, fetch tardio das restantes pelos RowIDs
   sobreviventes. Ganho direto no padrão "filtra muito, projeta pouco".
3. **Morsel adaptativo** (SPEC-0041): batch inicial 8k, escalado até 131k por
   taxa de cache-miss / largura de coluna. Hoje `BATCH_ROWS` é fixo em 1024.
4. **Spill-to-disk** determinístico em agregação/join grandes (SPEC-0039): já há
   `io`/tiering; falta o sub-pipeline de spill quando o join excede orçamento.

### Fase 2 — Consolidação do consenso (FECHADO 2026-07-16)
- [x] Wrapper gRPC/tonic sobre os tipos serde do `heraclitus-raft` — **feito**:
      `heraclitus-raft::grpc` (`RaftTransport` proto + `GrpcNetworkFactory`), o
      servidor escolhe TCP ou gRPC via `ReplicationConfig.transport` (default
      `tcp`, back-compat). Testado a nível de raft (cluster por gRPC) e de servidor
      (3 nós replicam+indexam por gRPC). Nota: `replication` **mantém-se
      feature-gated** (nó único é o caminho normal — não vira default).

### Fase 3 — Endurecimento "referência → produção" (adiado, deliberado)
- NUMA node-local pleno (multi-socket; hoje só pinning round-robin).
- Kernels AVX explícitos **só se** um benchmark real os justificar (os kernels
  Arrow já são SIMD por baixo — ver §5).
- Quórum distribuído para além do in-process/TCP atual.

---

## 5. Rejeições explícitas (o fosso da disciplina)

Recusas com justificação — para não serem re-litigadas a cada RFC novo:

| Proposta HUME | Porque não |
|---|---|
| **IR multi-dialeto MLIR + JIT Cranelift/LLVM/GPU por tiers** (0037/0038/0039) | Esforço de 20–50 eng-ano. O `core::ir` (LogicalPlan→PhysicalIr) chega para a carga real. Viola I2. |
| **Kernels SIMD à mão para "humilhar o DuckDB"** (0040) | Os kernels Arrow **já são SIMD**. Reescrever à mão é ganho marginal por custo enorme — a armadilha clássica. |
| **Lakehouse Iceberg/Parquet/S3 + object-store multi-nuvem** (0036) | Linha de produto inteira, ortogonal a "memória auditável de agente". Já há Parquet cold-tier suficiente (`heraclitus-tier`). |
| **Federação Postgres/Kafka/Iceberg com pushdown** (0037/0038/0039) | Idem. Nenhuma necessidade de utilizador concreta. |
| **Learned optimizer (XGBoost/TinyNN), speculative execution** (0039) | Complexidade adaptativa que viola I2. Cost-based simples já testado (`SelectivityOptimizer`). |
| **HQL — nova linguagem** (SPEC-023) | Viola I3. Já rejeitado pelo código. |
| **Benchmark de 10 mil milhões de linhas / TPC-H** (0040) | Premissa fictícia. O produto é memória de agente / grafo de fraude, não data-warehouse OLAP de 10B linhas. Ver §6. |
| **Binary Quantization no HNSW** (não-HUME, mas recorrente) | Viola I7. Destrói a hierarquia hiperbólica. |

---

## 6. Contrato de benchmark (a régua honesta)

Nenhuma extração da Fase 1 é aceite sem prova numérica **na forma de query real
do produto**, não em TPC-H sintético. Formas de carga canónicas:

- **Seletiva por atributo/agente:** `MATCH (n) WHERE n.agent_id = … AND
  n.valor > X` — o caso onde SelectionVector adaptativo + late-mat devem brilhar.
- **Temporal:** `MATCH (n) AS OF LSN k` — replay parcial + zone-map skip.
- **Grafo + vetor + relacional encadeados:** o fluxo de investigação de fraude
  (busca HNSW → salto de grafo → filtro temporal) descrito no próprio SPEC-0040 §5.
- **Escala real de referência:** a ordem de grandeza é a da VM EVA (~865K nós), e
  o caso operacional documentado no M31 (carga de 136M eventos / 56 GB que
  motivou o fast-boot) — não 10B linhas.

Gate: a extração só entra se **(a)** for bit-idêntica ao caminho atual (Gate C:
a otimização nunca muda o resultado) e **(b)** mostrar ganho medido numa dessas
formas.

---

## 7. Próxima ação recomendada

Concluída a Fase 0 (este ficheiro). O passo seguinte de maior valor é **detalhar
o candidato #1 da Fase 1 (`SelectionVector` adaptativo) como RFC pequeno e
implementável** contra o `VecExecutor` atual — com o diff mínimo, o Gate C e o
benchmark seletivo. Só depois se abre código.
