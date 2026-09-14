<p align="center">
  <img src="img/logo.jpg" alt="Heraclitus Logo" width="300" />
</p>

<h1 align="center">Heraclitus Agent Black Box</h1>

<p align="center"><b>Saiba exactamente o que o seu agente de IA fez.<br>
Prove quem autorizou. Detecte qualquer alteração posterior no histórico.</b></p>

<p align="center">
  <a href="#️-licença-e-modelo-comercial"><img src="https://img.shields.io/badge/license-BSL%201.1-blue" alt="BSL 1.1"></a>
  <img src="https://img.shields.io/badge/version-v2.0.0-brightgreen" alt="v2.0.0">
  <img src="https://img.shields.io/badge/core-Rust%20stable%202021-orange" alt="Rust stable">
  <img src="https://img.shields.io/badge/OpenTelemetry-GenAI%20semconv-blueviolet" alt="OTel GenAI">
  <img src="https://img.shields.io/badge/MCP-2026--07--28-purple" alt="MCP 2026-07-28">
  <img src="https://img.shields.io/badge/evidence-tamper--evident-success" alt="tamper-evident">
</p>

---

## O problema

Um agente de IA escolhe ferramentas, encadeia ferramentas, age em nome de uma
pessoa, usa credenciais delegadas e altera estado externo. A observabilidade
tradicional responde a *"o que aconteceu?"*. Uma auditoria precisa de mais:

```text
quem iniciou?                  qual política estava vigente?
qual agente executou?          houve aprovação humana?
em nome de quem?               qual foi o efeito externo?
qual ferramenta foi chamada?   o histórico foi alterado depois?
quais argumentos efectivos?    consigo verificar isso offline?
```

O Heraclitus regista cada execução relevante num histórico append-only
verificável, liga as tool calls às suas evidências e exporta um pacote que pode
ser conferido offline — **sem trocar a base de dados ou o framework da
aplicação**.

---

## Como se parece

```text
┌─────────────────────────────────────────────────────────────┐
│ Heraclitus Agent Black Box                   ● VERIFIED     │
├─────────────────────────────────────────────────────────────┤
│ Runs                                                        │
│                                                             │
│ 08:41  procurement-agent   7 tools   1 approval   success   │
│ 08:37  support-agent       2 tools   0 approval   success   │
│ 08:31  coding-agent        9 tools   2 denied     failed    │
└─────────────────────────────────────────────────────────────┘

Run 01J...                          Integrity: VERIFIED
──────────────────────────────────────────────────────────────
08:41:02  Run started
08:41:03  Model invocation: claude-opus-5
08:41:04  Tool requested: lookup_vendor
08:41:04  Policy: ALLOW
08:41:04  Tool result: lookup_vendor
08:41:07  Tool requested: send_payment
08:41:07  Policy: REQUIRE_APPROVAL          finance-large
08:41:19  Approved by finance-cfo
08:41:20  Tool executing: send_payment
08:41:21  External effect: payment-84723
08:41:22  Agent output
```

---

## Quickstart — cinco minutos

```bash
git clone https://github.com/JoseRFJuniorLLMs/HeraclitusDB
cd HeraclitusDB/examples/agent-black-box
docker compose up -d

export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
python sample-python-agent/sample.py
```

Abra <http://localhost:8080>.

Se a sua aplicação já exporta OpenTelemetry, a variável de ambiente é a
integração inteira. Sem Docker:

```bash
cargo run --release -p heraclitus-cli -- agent demo ./data
```

| porta | superfície |
|---|---|
| 8080 | Consola + API de evidência |
| 4318 | OTLP/HTTP |
| 4317 | OTLP/gRPC (opcional) |
| 8787 | proxy MCP (opcional) |

---

## O que é capturado

Um span sem marca GenAI **não** vira evidência de agente — o tracing HTTP normal
da aplicação não entra no histórico.

| kind | quando |
|---|---|
| `RunStarted` / `RunFinished` | o run do agente |
| `ModelInvocationStarted` / `Finished` | uma chamada ao modelo |
| `ToolRequested` | o agente pediu a ferramenta |
| `PolicyEvaluated` | a policy decidiu |
| `ToolAuthorized` / `ToolDenied` | o gateway autorizou ou recusou |
| `HumanApprovalRequested` / `Granted` / `Denied` | a decisão humana |
| `ToolInvocationStarted` / `Finished` | a execução e o resultado |
| `ExternalEffectObserved` | `payment_id`, `commit_sha`, `ticket_id`… |
| `ErrorObserved` | falha de transporte ou de protocolo |
| `AgentOutputProduced`, `ArtifactReferenced` | saída e artefactos |

Cada uma traz identidade do agente, identidade humana, delegação, hashes de
conteúdo, referência de policy e referência de aprovação. A retransmissão de um
lote OpenTelemetry **não duplica** a história.

---

## Verificar — e falhar honestamente

```bash
heraclitus agent export /var/lib/heraclitus --to evidence.zip --run run-abc123
heraclitus agent verify evidence.zip
```

```text
Bundle:           01J...
Records:          1847
LSN range:        9981..11827
File digests:     VALID
Merkle proofs:    VALID
Logical roots:    VALID
Missing records:  0
Broken parents:   0
Policy links:     17 VALID (of 17)
Approvals:        2 VALID (of 2)

VERDICT: VERIFIED
```

Mude um byte:

```bash
printf 'X' | dd of=evidence.zip bs=1 seek=900 conv=notrunc
heraclitus agent verify evidence.zip
```

```text
VERDICT: DIGEST_MISMATCH
```

…e o código de saída passa a 3. O verificador não precisa de rede, de base de
dados nem do servidor. Sem o binário, os digests continuam conferíveis com
`unzip` e `sha256sum -c`.

Os quatro estados de integridade são honestos: `VERIFIED`, `PARTIAL`,
`UNVERIFIED`, `BROKEN`. **"Não verificado" nunca vira "válido".**

---

## Autorizar, não só observar

Ponha o Heraclitus à frente dos seus servidores MCP:

```yaml
version: "agent-policy-v1"
defaults:
  decision: deny
rules:
  - id: finance-large
    match:
      server: finance
      tool: send_payment
      conditions:
        - field: amount
          op: gt
          value: 50000
    decision: require_approval
    approval:
      roles: ["cfo"]
      ttl_seconds: 180
```

```text
observe  ->  shadow  ->  enforce
```

Comece por `shadow`: a policy é avaliada e registada, e a Consola mostra
`would deny` — sem bloquear nada. Antes de activar, veja o que teria acontecido:

```bash
heraclitus agent policy simulate nova.yaml --data-dir /var/lib/heraclitus
```

```text
historical tool calls: 18442
ALLOW:               17912
DENY:                  183
REQUIRE_APPROVAL:      347
changed vs active:      81
```

**A aprovação está ligada ao conteúdo exacto.** Aprovar
`send_payment(amount=5000)` e executar `send_payment(amount=5001)` falha com
`APPROVAL_BINDING_MISMATCH`. A aprovação é de uso único e expira.

---

## Privacidade

Por omissão, `METADATA_ONLY`:

| o quê | estado |
|---|---|
| corpos de prompt | **OFF** |
| corpos de completion | **OFF** |
| argumentos de ferramenta | metadados + hash canónico |
| resultados de ferramenta | metadados + hash canónico |
| `Authorization`, `Cookie`, chaves de API | **nunca persistidos, em modo nenhum** |

A última linha não tem excepção: `FULL_EXPLICIT` autoriza guardar o corpo de uma
tool call; **não** autoriza guardar o bearer token que a acompanhava.

O produto não promete detectar todo o segredo possível. Por isso o default é não
guardar o corpo: os detectores de forma conhecida são a segunda linha, não a
primeira.

---

## Documentação do produto

| ficheiro | assunto |
|---|---|
| [`docs/agent/quickstart.md`](docs/agent/quickstart.md) | do zero ao pacote verificado |
| [`docs/agent/otel.md`](docs/agent/otel.md) | o que é capturado do OpenTelemetry |
| [`docs/agent/mcp.md`](docs/agent/mcp.md) | captura e gateway MCP |
| [`docs/agent/privacy.md`](docs/agent/privacy.md) | modos de captura e redacção |
| [`docs/agent/evidence.md`](docs/agent/evidence.md) | o Evidence Bundle e a verificação |
| [`docs/agent/policy.md`](docs/agent/policy.md) | a linguagem de policy |

Especificações: [SPEC-0074](docs/md/SPEC-new/SPEC-0074-Agent-Black-Box.md),
[SPEC-0075](docs/md/SPEC-new/SPEC-0075-Agent-Policy-Gateway.md),
[SPEC-0076](docs/md/SPEC-new/SPEC-0076-Agent-Evidence-Console.md).

---

## O motor por baixo

O Agent Black Box é a superfície. O motor é o **HeraclitusDB** — um banco de
dados append-only com raízes de Merkle canónicas, viagem no tempo determinística
e multi-indexação. Não é preciso entendê-lo para usar o produto; o resto deste
documento descreve-o, para quem quiser.

A camada **Sentinel** (SOC) continua no repositório e continua a funcionar. Não
aparece no quickstart, não é a página inicial e não é necessária para o Agent
Black Box.

---

## 💼 O que é o HeraclitusDB

O **HeraclitusDB** é um **banco de dados HTAP (Transacional e Analítico) distribuído, multi-modelo (relacional, grafo, texto e vetorial para IA), escrito em Rust**. Ele tem um foco fortíssimo em segurança de nível militar/governamental, conformidade legal, auditoria criptográfica e aceleração por hardware (GPU).

Em bancos tradicionais (PostgreSQL, Neo4j, MongoDB), comandos `UPDATE` e `DELETE` destroem a história física. Em ambientes regulados ou na memória de agentes de IA, isso cria duas vulnerabilidades críticas: **adulteração retroativa indetectável** e **amnésia estrutural invisível**.

No HeraclitusDB:
- **A verdade primária é o log de eventos**: nada é sobrescrito ou apagado. Correções ocorrem anexando novos fatos.
- **Viagem no tempo determinística bit-a-bit**: qualquer estado histórico pode ser inspecionado ou reexecutado via `AS OF LSN` ou `AS OF TIMESTAMP`.
- **Integridade verificável a frio**: qualquer manipulação física em disco é imediatamente detectada via provas Merkle canônicas (`db.verify()`).

| Para quem | A dor atual | O que o HeraclitusDB entrega |
| :--- | :--- | :--- |
| **Órgãos de Auditoria e Fiscalização** | Impossibilidade de provar que um dado histórico não foi adulterado ou forjado nos bastidores. | Log imutável + raízes Merkle + carimbos RFC 3161 com validação de cadeia ICP-Brasil e revogação offline por CRL. Fraude retroativa torna-se matematicamente impossível de ocultar. |
| **Agentes de IA e Memória Cognitiva** | Amnésia estrutural: o agente tem seu contexto sobrescrito ou perde a proveniência dos fatos ao longo do tempo. | Memória em fluxo contínuo. Leitura do passado exato (`AS OF`), proveniência causal explícita (`WHY`, `PROVENANCE`) e recuperação ativacional ACT-R O(1). |
| **Investigação de Fraudes e Compliance** | Cruzamento de dados relacionais, vetoriais e grafos com versões concorrentes de hipóteses. | Motor híbrido unificado (Grafo + Vetor + Texto + Atributos), resolução probabilística de entidades (`RESOLVE`), grafo de hipóteses (`log-odds`) e simulações contrafactuais em RAM. |
| **Defesa Cibernética e SOC Governamental** | Detecção reativa desconectada da trilha auditável de evidência e da proveniência dos dados. | Camada **Heraclitus Sentinel (L0–L6)**: normalização determinística, regras Sigma (L1), baseline comportamental (L2), correlação causal em grafo (L3), investigação LLM isolada (L4), governança e execução reversível (L5/L6). |

---

## 🛡️ Os pilares fundamentais

```
                      ┌──────────────────────────────────────────────┐
                      │              Clientes / MCP / SDK            │
                      └────────┬─────────────────────────┬───────────┘
                               │ Append (gRPC/REST)      │ Query / Recall / WHY
                               ▼                         ▼
                      ┌──────────────────┐     ┌──────────────────────┐
                      │  heraclitus-log  │     │ heraclitus-retrieval │
                      │ HRKL v6 Canonical│     │  RRF fuse + rerank   │
                      │  BLAKE3 + CRC32  │     └──────────┬───────────┘
                      └────────┬─────────┘                │ merge(memtable, views)
                tail_subscribe │                          │
            ┌──────────────────┼──────────────────────────┤
            ▼                  ▼                          │
 ┌────────────────┐ ┌──────────────────┐                  │
 │   memtable     │ │ heraclitus-views │                  │
 │ (tail, exact,  │ │  replay engine   │                  │
 │  RYOW < 1ms)   │ │  + checkpoints   │                  │
 └────────────────┘ └────────┬─────────┘                  │
                             │ apply (deterministic)      │
        ┌──────────┬─────────┼──────────┬──────────┐      │
        ▼          ▼         ▼          ▼          ▼      │
    ┌───────┐ ┌────────┐ ┌───────┐ ┌──────────┐ ┌──────┐  │
    │vector │ │ graph  │ │ text  │ │activation│ │attr  │──┘
    │(HNSW) │ │(adj +  │ │(BM25) │ │ (ACT-R)  │ │range │
    └───────┘ │ attrs) │ └───────┘ └──────────┘ └──────┘
              └────────┘
    ▲ todas as views: derivadas, apagáveis, reconstruíveis a partir do LSN 0

 ┌──────────────────────┐    emite SecurityIncident / Action
 │ heraclitus-sentinel  │──────────────► de volta ao LOG canônico
 │ (L0-L6 SOC & Threat) │    (auditoria contínua e sem efeito colateral nas escritas)
 └──────────────────────┘
```

### 1. Imunidade a Fraudes e Integridade Criptográfica
O log do HeraclitusDB é particionado em formatos **HRKL v6** (RAW ou PACKED com compressão Zstd/LZ4) com árvore Merkle BLAKE3 e manifesto `.hrkm`. Cada registro referencia seus ancestrais (`parents: Vec<EventId>`). A integridade lógica sobrevive a repacks e transições de tiering. Testado sob 1.000 injeções de crash durante escrita: **zero perdas e zero corrupções silenciosas**.

### 2. Geometria de Dados Aprendida ($\mathcal{H} \times \mathcal{S} \times \mathcal{E}$)
O HeraclitusDB rejeita a premissa do espaço euclidiano plano para grafos de conhecimento. Hierarquias são mapeadas em variedades hiperbólicas de Poincaré ($\mathcal{H}$), ciclos em esferas de Riemann ($\mathcal{S}$) e grandezas ordinais em espaços euclidianos ($\mathcal{E}$). As curvaturas $\kappa_i$ e dimensões $(a, b, c)$ são aprendidas diretamente da distorção do dado. Distâncias manifold são aceleradas em GPU via **wgpu / WGSL** com fallback determinístico CPU.

### 3. Recuperação Multi-Canal e Causalidade Bi-Temporal
Consultas realizam fusão RRF (*Reciprocal Rank Fusion*) combinando HNSW vetorial, BM25 textual ordenado e ativação ACT-R $O(1)$ determinística. O grafo suporta consultas bi-temporais (`VALID AT` vs `AS OF LSN`), rastreamento causal (`WHY`), proveniência infalsificável (`PROVENANCE`) e simulações contrafactuais puramente em memória (`SIMULATE REMOVE EDGE ... THEN`).

### 4. Soberania, Conformidade e Sentinel SOC
- **Protocolo RFC 3161 + ICP-Brasil**: Ancoragem em Autoridades Certificadoras de Tempo (ACT), validação estrita de cadeias X.509/CMS, verificação de revogação offline por CRL (com tratamento retroativo para `keyCompromise`) e assinaturas híbridas pós-quânticas ML-DSA-44 (FIPS 204).
- **Heraclitus Sentinel (SPEC-0045 & SPEC-0047)**: Monitoramento L0–L6 desacoplado de escrita, detecção Sigma L1, momentos comportamentais EWMA/Welford L2, grafo de incidentes L3, investigação AI com boundary seguro L4, e inteligência de ameaças compatível com STIX 2.1 e TLP 2.0.

---

## 🗂️ Arquitetura do Workspace Rust

O ecossistema HeraclitusDB é estruturado em **30 crates principais** organizados por camadas estritas de responsabilidade:

```
heraclitus-core          ← Tipos fundamentais: Episode, Fact, ProductPoint, HLC, LSN, EBR, VM ISA
heraclitus-log           ← Log canônico HRKL v6 (RAW, PACKED Zstd/LZ4, manifesto .hrkm, sidecar .hrki)
heraclitus-crypto        ← Cifra em repouso ChaCha20-Poly1305, KeyStore por agente, hashes BLAKE3
heraclitus-manifold      ← Geometria produto H×S×E aprendida, transformações de Möbius, mapas exp/log
heraclitus-memtable      ← Cauda síncrona: garantias de Read-Your-Own-Writes em < 1ms
heraclitus-views         ← Motor de replay determinístico e persistência atômica de checkpoints
heraclitus-index-vector  ← HNSW na variedade produto; tombstones semânticos; search_exact_gpu
heraclitus-index-graph   ← Grafo temporal derivado do log; detecção de comunidades Leiden; MATCH AS OF
heraclitus-index-text    ← Índice BM25 invertido com busca fuzzy e tokenização multilíngue
heraclitus-index-attr    ← Índice de atributos ordenado (B-Tree); range scan sem table scan
heraclitus-activation    ← Modelo de ativação ACT-R O(1) determinístico no replay com HLC
heraclitus-retrieval     ← Fusão de ranking RRF: ANN ∥ BM25 ∥ ACT-R → k=60 → reranker
heraclitus-distill       ← Compactação: clustering manifold, re-fit de curvatura e swap blue/green
heraclitus-tier          ← Tiering para Object Storage (S3/GCS), recibos DemotionReceipt e export Parquet
heraclitus-btree         ← Fractal Tree Bᵋ-tree: CoW shadow paging, 4KB pages, checkpoint BLAKE3
heraclitus-gpu           ← Aceleração heterogênea WGSL/wgpu (Intel Arc, NVIDIA, AMD) com fallback CPU
heraclitus-compliance   ← Ancoragem RFC 3161, validador ICP-Brasil X.509/CMS, CRL offline e PQC ML-DSA-44
heraclitus-sentinel     ← Plano de segurança L0-L6, Sigma L1, baseline L2, grafo L3, STIX 2.1 Threat Intel
heraclitus-query         ← Parser pest (GQL/Cypher), query planner lock-free ArcSwap, EXPLAIN, AS OF
heraclitus-txn           ← Transações e isolamento MVCC: Snapshot por LSN, compare_and_append CAS
heraclitus-raft          ← Replicação distribuída de log com OpenRaft 0.9 e tolerância a partições
heraclitus-proto         ← Interfaces Protobuf e gRPC (Tonic / Prost)
heraclitus-agent         ← Agent Black Box: evidência canónica, redacção, policy, bundle e verificação offline
heraclitus-agent-gateway ← Superfícies do produto: ingestão OTLP (:4318), proxy MCP (:8787), API e Consola (:8080)
heraclitus-server        ← Servidor gRPC (:7474), REST (:7475), boot narrado e métricas operacionais
heraclitus-client        ← Cliente nativo em Rust para gRPC
heraclitus-cli           ← CLI executável: inspect, verify, verify-receipts, anchor, prove, query, bench
heraclitus-analytics     ← Motor SQL OLAP sobre o log via Apache Arrow / DataFusion e Arrow Flight
tools/heraclitus-qualifier ← Suíte de qualificação e auditoria governamental (SPEC-0049)
tools/heraclitus-ingestor  ← Pipeline de ingestão massiva e streaming de alta velocidade
```

---

## 🏗️ Análise Estrutural Detalhada por Módulo

### 1. Motor de Armazenamento e Estruturas Core (Storage Engine)
A base de como os dados são gravados, estruturados e recuperados.

* **`heraclitus-core`**
  * **O que faz:** Contém as primitivas e abstrações fundamentais do banco de dados.
  * **Como faz:** Gerencia o tempo lógico do banco (`hlc.rs` - *Hybrid Logical Clock*), define o formato e versão (`format_version.rs`), implementa execução de Máquina Virtual para operações (`vm/interpreter.rs`), gerencia isolamento de processos (`sandbox.rs`) e alocação de memória considerando topologia de hardware (`numa.rs`).
* **`heraclitus-memtable`**
  * **O que faz:** Gerencia os dados em memória antes de serem persistidos no disco.
  * **Como faz:** Atua como um buffer transacional rápido onde as novas escritas chegam primeiro, garantindo *Read-Your-Own-Writes* (RYOW) em $< 1\text{ ms}$.
* **`heraclitus-log`**
  * **O que faz:** Implementa o log canônico append-only (WAL) garantindo a durabilidade (ACID) e a imutabilidade das transações.
  * **Como faz:** Usa formato canônico versionado **HRKL v6** (`v6/`), empacotadores otimizados (`packer.rs`), varints para compressão de inteiros, e Árvores de Merkle BLAKE3 (`merkle.rs`) para garantir que os logs não foram corrompidos ou adulterados. Possui coleta de lixo semântica (`gc.rs`) e mapeamento em disco (`mmap.rs`).
* **`heraclitus-btree`**
  * **O que faz:** Organização primária dos dados estruturados em disco.
  * **Como faz:** Implementa estruturas $B^\varepsilon$-Tree (Fractal Tree) balanceadas com *CoW shadow paging*, nós de 4KB e checkpoints BLAKE3 para permitir buscas indexadas e escaneamentos (*range scans*) eficientes.
* **`heraclitus-tier` (Tiering / Lakehouse)**
  * **O que faz:** Move dados frios e históricos do armazenamento principal para armazenamentos analíticos em nuvem (Data Lakes / Object Storage).
  * **Como faz:** Implementa integração com formatos modernos de Lakehouse, incluindo `parquet` v2, `delta` (Delta Lake), `iceberg` (Apache Iceberg v2) e `avro`. Possui rotinas de compactação (`compaction.rs`) e rebaixamento com recibos criptográficos (`demotion.rs`).

---

### 2. Multi-Indexação (Multi-Model Indexing)
O banco não se prende a um único tipo de dado, possuindo índices dedicados e especializados para diferentes cargas de trabalho:

* **`heraclitus-index-attr`**: Indexação de atributos escalares e relacionais convencionais com compressão e *range scans* em árvore balanceada sem table scans.
* **`heraclitus-index-text`**: Indexação para busca *Full-Text* com índices invertidos BM25, busca *fuzzy* e tokenização multilíngue.
* **`heraclitus-index-graph`**: Indexação para dados em Grafo, gerindo relacionamentos temporais, entidades (`entity.rs`), proveniência causal (`temporal.rs`), detecção de comunidades Leiden e tomadas de decisão em nós (`decision.rs`).
* **`heraclitus-index-vector` & `heraclitus-manifold`**:
  * **O que fazem:** Formam o motor de Banco de Dados Vetorial para Inteligência Artificial.
  * **Como fazem:** Utilizam grafos hierárquicos navegáveis (HNSW - `hnsw_search.rs` e `gate.rs`) para busca de similaridade aproximada ($k$-NN) com suporte a *tombstones*. O módulo `manifold` gerencia cálculos complexos de distâncias em espaços multidimensionais de geometria mista $\mathcal{H} \times \mathcal{S} \times \mathcal{E}$ (`distance.rs`, `estimate.rs`).

---

### 3. Computação, Consultas e Analytics (Query & Compute)
Módulos responsáveis por entender as requisições dos usuários e executá-las com altíssima performance:

* **`heraclitus-query`**
  * **O que faz:** Interpreta, otimiza e planeja a execução das consultas em dialeto Cypher/GQL.
  * **Como faz:** Usa um parser baseado em PEG (`gql.pest`) para construir a Árvore Sintática (AST). Cria um plano de execução otimizado (`plan.rs`) com suporte a operadores temporais (`AS OF`, `VALID AT`, `WHY`, `DIST_PRODUCT`) e repassa para o backend lock-free com `ArcSwap` (`backend.rs`).
* **`heraclitus-analytics`**
  * **O que faz:** Motor OLAP para consultas pesadas de Business Intelligence diretamente sobre o log.
  * **Como faz:** Execução vetorizada de consultas (`vectorized.rs`) integrada ao Apache Arrow DataFusion e interface Arrow Flight (`flight.rs`) para processamento analítico em lote.
* **`heraclitus-gpu`**
  * **O que faz:** Aceleração massiva por hardware.
  * **Como faz:** Descarrega computação paralela intensa (cálculo de distâncias manifold, quantização ordinal e agregações) diretamente na GPU via *shaders* WGSL e wgpu (`benches/gpu_vs_cpu.rs`), destravando performance para IA e Analytics com fallback seguro para CPU.

---

### 4. Distribuição e Rede (Distributed & Networking)

* **`heraclitus-raft`**
  * **O que faz:** Garante consenso distribuído, alta disponibilidade e replicação de dados.
  * **Como faz:** Implementa o algoritmo Raft via OpenRaft (`consensus.rs`). Gerencia eleições de nós líderes, replicação segura de logs duráveis (`durable.rs`) e comunicação gRPC entre réplicas com tolerância a partições de rede.
* **`heraclitus-server`**
  * **O que faz:** A porta de entrada do banco de dados para o mundo externo.
  * **Como faz:** Inicializa a API REST (`rest.rs`) e gRPC (`grpc.rs`, `flight_grpc.rs`). Gerencia o boot narrado com suporte a ANSI/UTF-8 (`boot.rs`), autenticação RBAC de usuários (`auth.rs`) e orquestração do cluster (`cluster.rs`).

---

### 5. Segurança, Conformidade e Ameaças (Security & Sentinel)
Proteção embutida de nível governamental e militar para operações críticas:

* **`heraclitus-compliance`**
  * **O que faz:** Garante obediência a regulações e provê não-repúdio (auditoria infalível).
  * **Como faz:** Implementa carimbos de tempo seguros RFC 3161 (`rfc3161.rs`, `secure_tsa.rs`), verificador estrito ICP-Brasil X.509/CMS (`icp.rs`), verificação de revogação offline por CRL (`crl.rs`), recibos criptográficos infalsificáveis (`receipt.rs`, `verify.rs`), e controles de privacidade (`privacy.rs`) e soberania (`sovereignty.rs`).
* **`heraclitus-sentinel`**
  * **O que faz:** Motor de SIEM e segurança autônoma (L0–L6) integrado nativamente no banco.
  * **Como faz:** Analisa eventos em tempo real (`event/`), executa regras Sigma (L1), calcula momentos comportamentais EWMA/Welford (L2), constrói grafos de incidentes causais (L3), realiza investigações com LLM sob contexto restrito (L4) e executa ações reversíveis (L5/L6). Processa feeds de inteligência de ameaças (`threat/feed.rs`), avalia regras de confiança (`threat/trust.rs`) e compartilha dados em conformidade com STIX 2.1 e TLP 2.0 (`threat/stix.rs`).

---

### 6. Ferramentas, SDKs e Verificação Formal

* **Ferramentas e Interfaces:**
  * **`heraclitus-cli`**: Linha de comando para inspeção, verificação Merkle, ancoragem de evidência, benchmarks e execução de queries.
  * **`tools/heraclitus-ingestor`**: Ingestor de alta performance para cargas massivas de dados em lote e streaming.
  * **`tools/heraclitus-qualifier`**: Suíte de qualificação governamental automatizada (SPEC-0049), executando testes de carga (Q1), crash-loop contra binários de release (Q2), monitoramento de *egress* e geração de SBOM CycloneDX.
  * **SDKs Oficiais**: SDK Python em rede (`sdk/python`) e SDK Python embarcado in-process via PyO3 (`sdk/python-embedded`).
  * **Servidor MCP Nativo**: Integração direta com *Model Context Protocol* (`mcp/heraclitus_mcp.py`) para agentes de IA operarem com memória não-volátil anti-fraude.
* **`lean/` (Verificação Formal de Teoremas):**
  * **O que faz:** Prova matematicamente que os algoritmos fundamentais do banco são formalmente corretos.
  * **Como faz:** Utiliza a linguagem de prova formal *Lean 4* para garantir, via deduções matemáticas formais, as invariantes do log *append-only*, dos relógios lógicos híbridos (HLC), dos mapeamentos densos de chaves e da consistência de inclusão das Árvores de Merkle.

---

## 🔄 Fluxo de Vida Completo de uma Operação

```
  [Cliente / SDK / Agente IA]
               │
               ▼ (gRPC / REST)
       1. heraclitus-server
               │ (Autenticação RBAC + TLS)
               ▼
       2. heraclitus-query
               │ (Parser pest GQL/Cypher -> AST -> Query Plan)
               ▼
       3. heraclitus-sentinel & compliance
               │ (Avaliação de segurança L0-L6 e conformidade com políticas)
               ▼
       4. Execução Multi-Modelo
          ├── Busca Relacional/Atributos  ──> heraclitus-index-attr
          ├── Busca Vetorial / Semântica ──> heraclitus-index-vector + heraclitus-gpu
          ├── Travessia / Grafo Temporal ──> heraclitus-index-graph
          └── Analytics / SQL OLAP       ──> heraclitus-analytics (DataFusion / Flight)
               │
               ▼
       5. heraclitus-raft
               │ (Consenso distribuído e aprovação por quórum do cluster)
               ▼
       6. Persistência e Durabilidade
          ├── Escrita Imediata (RAM)     ──> heraclitus-memtable (RYOW < 1ms)
          └── Log Canônico em Disco      ──> heraclitus-log (HRKL v6 + BLAKE3 Merkle Tree)
               │
               ▼ (Políticas de Tiering em Background)
       7. heraclitus-tier
          └── Dados frios e históricos   ──> Object Storage (S3/GCS/MinIO) via Parquet / Iceberg v2
```

1. **Recepção**: A operação chega via **`heraclitus-server`** (gRPC ou REST) com autenticação de sessão e validação de tokens.
2. **Planejamento**: O **`heraclitus-query`** valida a sintaxe, gera a Árvore Sintática (AST) e constrói o plano de execução físico.
3. **Auditoria em Linha**: O **`heraclitus-sentinel`** avalia a transação contra ameaças conhecidas (L1/L2), enquanto o **`heraclitus-compliance`** garante a aplicação das regras de soberania.
4. **Execução Especializada**: Conforme a natureza da query, a execução é delegada aos índices correspondentes (**`index-attr`**, **`index-vector`**, **`index-graph`** ou **`heraclitus-analytics`** acelerado por **`heraclitus-gpu`**).
5. **Consenso Distribuído**: Mutações são submetidas ao **`heraclitus-raft`**, que valida o quórum de réplicas antes do *commit*.
6. **Escrita Imutável**: O evento é refletido na **`memtable`** para leitura síncrona instantânea e registrado de forma imutável no **`heraclitus-log`** com carimbo Merkle.
7. **Ciclo de Vida e Lakehouse**: Periodicamente, o **`heraclitus-tier`** rebaixa dados históricos para Data Lakes (S3/MinIO) nos formatos Iceberg v2, Parquet e Delta Lake, emitindo recibos de rebaixamento assinados.

---

## 🚀 Como Usar

### 1. Inicialização do Servidor

```bash
# Clonar e compilar
git clone https://github.com/JoseRFJuniorLLMs/HeraclitusDB.git
cd HeraclitusDB

# Rodar a suíte completa de testes
cargo test --workspace

# Iniciar o servidor com boot narrado (gRPC na 7474, REST na 7475)
cargo run -p heraclitus-server
```

### 2. CLI de Operação e Verificação Forense

```bash
# Inspecionar manifesto de armazenamento HRKL v6
cargo run -p heraclitus-cli -- inspect ./data/log

# Verificação criptográfica completa da árvore Merkle
cargo run -p heraclitus-cli -- verify ./data/log --logical

# Gerar prova de inclusão Merkle para um LSN específico
cargo run -p heraclitus-cli -- prove ./data/log --lsn 428931

# Ancoragem de evidência RFC 3161
cargo run -p heraclitus-cli -- anchor ./data/log --receipts ./data/receipts

# Verificação de recibos com validação estrita de cadeia de confiança
cargo run -p heraclitus-cli -- verify-receipts ./data/log --receipts ./data/receipts
```

### 3. SDK Python Oficial

```bash
pip install ./sdk/python
```

```python
import heraclitusdb

# Conexão gRPC de alta performance
db = heraclitusdb.connect("127.0.0.1:7474")

# Append atômico de evento com atributos tipados
lsn = db.append(
    kind="Observation",
    content="Empresa Alfa venceu licitação sem ter funcionários registrados",
    attrs={"licitacao_id": "9921", "orgao": "Ministerio_X", "alvo": "Empresa_Alfa"}
)

# Viagem no tempo (Time-Travel Query)
df_passado = db.query_df("MATCH (n) WHERE n.alvo = 'Empresa_Alfa' RETURN n", as_of=lsn)

# Busca semântica híbrida (RRF)
resultados = db.recall("indícios de empresa fantasma em licitação pública", k=10)

# Verificação Merkle em linha
is_valid = db.verify()
print(f"Log 100% íntegro: {is_valid}")
```

### 4. Servidor MCP Nativo (Memória para Agentes de IA)

O HeraclitusDB inclui suporte oficial ao [Model Context Protocol (MCP)](https://modelcontextprotocol.io). Qualquer cliente (Claude Code, Claude Desktop, Cursor) pode utilizar o HeraclitusDB como memória auditável anti-fraude:

```json
{
  "mcpServers": {
    "heraclitus": {
      "command": "python",
      "args": ["-m", "mcp.heraclitus_mcp"],
      "cwd": "D:/DEV/HeraclitusDB"
    }
  }
}
```
Ferramentas MCP disponíveis: `remember`, `recall`, `query` (com suporte a `AS OF`), `why`, `provenance`, `stats`, `verify`, `state`.

---

## 📊 Benchmarks e Validação em Escala

Os benchmarks do HeraclitusDB são reprodutíveis via `cargo bench --workspace` e suítes de carga dedicadas.

### 1. Carga Real Massiva de 20.000.000 de Eventos (`carga_real_20m.rs`)

Testado em Windows 11 sobre drive NVMe com log particionado em segmentos de 8 MiB:

| Métrica | Resultado a 20 Milhões de Eventos |
| :--- | :--- |
| **Volume Total em Disco** | **9.755,7 MB** distribuídos em 1.164 segmentos de 8 MiB |
| **Throughput de Escrita (Escritor Único)** | **12.533 a 19.954 appends/s** (curva perfeitamente plana do início ao fim) |
| **Throughput Concorrente (8 Escritores)** | **39.217 appends/s** |
| **Varredura Completa do Log (Scan de 20M)** | **96,81 segundos** (~206.596 registros decodificados/s) |
| **Fast Boot a partir de Snapshots** | **28 a 40 milissegundos** (restaura views e replaya apenas a cauda) |

### 2. Busca Vetorial HNSW na Variedade Produto (N = 20.000, Dim = 16)

| ef Search | QPS | Recall@10 | Latência Mediana |
| :---: | :---: | :---: | :---: |
| **16** | **8.589** | **0.996** | ~62,9 µs |
| **32** | **8.734** | **0.996** | ~74,1 µs |
| **64** | **10.051** | **0.996** | ~98,5 µs |

---

## 🏛️ Qualificação e Conformidade Governamental

Através do crate [`tools/heraclitus-qualifier`](tools/heraclitus-qualifier/README.md) e das especificações **SPEC-0046** e **SPEC-0049**, o HeraclitusDB separa declarações de código de atestações formais de auditoria:

```powershell
# Executar plano de pré-voo de auditoria
cargo run -p heraclitus-qualifier -- run --profile gov-production --out qa-evidence/gov-20260901

# Verificar integridade forense do dossiê contra o hash do executável
cargo run -p heraclitus-qualifier -- verify --evidence qa-evidence/gov-20260901 --binary target/release/heraclitus-server.exe

# Diagnóstico estrito de configuração (rejeita chaves incorretas que poderiam desativar TLS)
cargo run -p heraclitus-qualifier -- doctor --config heraclitus.toml

# Gerar SBOM CycloneDX determinístico da cadeia de suprimentos
cargo run -p heraclitus-qualifier -- sbom --out bom.cdx.json
```

---

## 📚 Documentação e Especificações Técnicas

Toda a engenharia do HeraclitusDB é regida por especificações normativas estritas e documentação auditada:

### Especificações e Arquitetura
- [docs/md/SPEC-new/SPEC.md](docs/md/SPEC-new/SPEC.md) — Blueprint arquitetural e especificação mestre
- [docs/md/SPEC-new/SPEC-HRKL-0050.md](docs/md/SPEC-new/SPEC-HRKL-0050.md) — Especificação do Storage Engine HRKL v6 e Projeção Lakehouse
- [docs/md/SPEC-new/SPEC-0045.md](docs/md/SPEC-new/SPEC-0045.md) — Heraclitus Sentinel: Detecção, Investigação e Resposta Autônoma L0–L6
- [docs/md/SPEC-new/SPEC-0046.md](docs/md/SPEC-new/SPEC-0046.md) — Ancoragem Criptográfica RFC 3161, Verificador ICP-Brasil e PQC
- [docs/md/SPEC-new/SPEC-0047.md](docs/md/SPEC-new/SPEC-0047.md) — Inteligência de Ameaças, STIX 2.1 e Sanitização TLP 2.0
- [docs/md/SPEC-new/SPEC-0049.md](docs/md/SPEC-new/SPEC-0049.md) — Framework de Qualificação Governamental e Dossiês de Auditoria
- [docs/md/SPEC-new/SPEC-RESUMO.md](docs/md/SPEC-new/SPEC-RESUMO.md) — Inventário verificado de todas as SPECs contra o código-fonte
- [docs/md/SPEC-new/STATUS.md](docs/md/SPEC-new/STATUS.md) — Status detalhado da auditoria adversarial contínua
- [docs/BLOQUEIOS-PRODUCAO.md](docs/BLOQUEIOS-PRODUCAO.md) — Matriz de bloqueios para certificação de produção

### Notas de Release e Auditorias
- [docs/md/RELEASE_NOTES_v1.0.5.md](docs/md/RELEASE_NOTES_v1.0.5.md) — Patch crítico de resiliência e integridade em disco (v1.0.5)
- [docs/md/RELEASE_NOTES_v1.0.4.md](docs/md/RELEASE_NOTES_v1.0.4.md) — Versão estável v1.0.4
- [docs/md/auditorias/otimizacao-20m.md](docs/md/auditorias/otimizacao-20m.md) — Relatório da carga e otimização de 20 milhões de registros
- [docs/qualification/README.md](docs/qualification/README.md) — Procedimentos operacionais de qualificação e runbooks normativos
- [docs/runbooks/README.md](docs/runbooks/README.md) — Runbooks de sustentação em produção e recuperação de desastres

---

## ⚖️ Licença e Modelo Comercial

O **núcleo** do HeraclitusDB é distribuído sob a **Business Source License 1.1 (BSL 1.1)**:
- ✅ **Livre** para leitura, auditoria de segurança, modificação, pesquisa, testes e desenvolvimento.
- ✅ **Código-fonte 100% aberto** e verificável.
- 💰 **Uso em produção comercial requer licença.**
- 🔓 **Data de conversão:** em **2030-06-21**, todas as versões convertem automaticamente para a licença **Apache-2.0**.

Consulte o arquivo [LICENSE](LICENSE) para termos completos.

---

<p align="center">
  <b>HeraclitusDB</b> — Desenvolvido por <b>José R. F. Junior</b> (Servidor Público Federal — SIAPE nº 1.634.972)<br>
  Contato: <a href="mailto:joseribamar.junior@inss.gov.br">joseribamar.junior@inss.gov.br</a> / <a href="mailto:web2ajax@gmail.com">web2ajax@gmail.com</a>
</p>

<p align="center">
  <i>"Panta rhei — nenhum homem pisa no mesmo rio duas vezes. E nenhum fraudador reescreve um rio que já fluiu."</i>
</p>
