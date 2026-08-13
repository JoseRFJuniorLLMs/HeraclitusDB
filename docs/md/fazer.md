Com base na leitura completa e minuciosa dos documentos de especificação (`SPEC-0000` a `SPEC-0041`), do plano de ação (`PLANO-SPECS.md`) e do relatório de auditoria (`STATUS.md`), fica evidente que o projeto está em uma transição crucial: as especificações antigas (009 a 035) já foram implementadas como módulos reais testados e o foco agora é a extração incremental da arquitetura **HUME (Heraclitus Unified Micro-Execution Engine)**.

Aqui está o mapeamento exato do que precisa ser alterado, criado e executado no código do ecossistema.

---

## 1. Quais arquivos Rust têm que ser mudados?

Seguindo a diretriz do plano de engenharia de fazer uma **extração incremental via PRs isolados** (em vez de reescrever o motor do zero), os arquivos existentes que precisam ser modificados são:

* **`crates/heraclitus-analytics/src/vectorized.rs`**
* **Remover o teto estático:** Alterar a constante fixa `pub const BATCH_ROWS: usize = 1024;` para uma estratégia dinâmica de `Adaptive Morsel Size` (variando de 8.192 a 131.072 linhas com base na taxa de cache-misses e largura de coluna).


* **Refatorar o Executor:** Modificar o `VecExecutor` para suportar a nova estrutura do `SelectionVector` dinâmico, aplicando processamento *branchless* baseado em máscaras SIMD.




* **`crates/heraclitus-query/src/cost.rs`**
* **Reescrita Completa do CBO:** Substituir as heurísticas lineares atuais pelo cálculo do **Vetor de Custo Multidimensional**. O arquivo deve implementar a fórmula exata:



$$\text{Custo}_{\text{total}} = \psi_{\text{cpu}} \cdot \mathcal{C}_{\text{cpu}} + \psi_{\text{mem}} \cdot \mathcal{C}_{\text{mem}} + \psi_{\text{io}} \cdot \mathcal{C}_{\text{io}} + \psi_{\text{net}} \cdot \mathcal{C}_{\text{net}}$$



onde os sub-custos calculam *misses* de cache L1/L2/L3, latência de RAM, throughput de NVMe e custos de rede do operador `Exchange`.




* **`crates/heraclitus-query/src/plan.rs` e `src/backend.rs**`
* **Injeção do AQE:** Modificar a geração do plano físico para injetar as barreiras de materialização (*Query Stages*) exigidas pela máquina de estados do *Adaptive Query Execution*.




* **`crates/heraclitus-raft/src/lib.rs` (e submódulos de rede/consenso)**
* **Gargalo de Produção:** Adicionar um wrapper gRPC (`tonic`) cosmético sobre os tipos `serde` existentes para expor o consenso do `openraft` (que já está funcional sobre TCP) para o mundo externo de forma limpa.




* **`Cargo.toml` (Raiz do Workspace)**
* Registrar os novos crates (`hume-runtime` e `hume-kernel`) como membros oficiais do workspace Rust.





---

## 2. Quais arquivos têm que ser criados?

A microarquitetura do HUME exige o isolamento do núcleo físico em dois novos crates especializados para garantir performance de ABI e localidade de hardware.

### Novo Crate 1: `crates/hume-runtime/` (O Motor Físico)

Este crate gerencia os blocos de dados vetorizados (`DataChunk`) e os operadores físicos básicos.

* `src/lib.rs`: Exposição e inicialização da ABI e contratos do engine.
* `src/morsel/batch.rs`: Estrutura do `ExecutionBatch` e gerenciamento de colunas transientes e views imutáveis sobre o `StorageBatch`.


* `src/morsel/selection_vector.rs`: Implementação do enum adaptativo: `Bitmap(Vec<u64>)`, `Index16(Vec<u16>)` e `Index32(Vec<u32>)`.


* `src/morsel/validity_mask.rs`: Controle compacto de valores nulos (NULLs) via máscaras de bits compactas (estilo Roaring).


* `src/execution/scan.rs`: Leitor colunar de baixo nível de páginas físicas com suporte a pré-carregamento assíncrono.


* `src/execution/filter.rs`: Avaliador de predicados relacionais e lógicos *branchless*.


* `src/execution/project.rs`: Execução de projeções aritméticas e strings *in-place*.


* `src/execution/join.rs`: Motor do **Radix Hash Join** (particionamento radix por bits significativos ajustados ao tamanho do cache L2/L3 por thread).


* `src/materialization/late_fetch.rs`: Operador de lookup sob demanda focado nos RowIDs sobreviventes (`PhysicalRowID`).



### Novo Crate 2: `crates/hume-kernel/` (Os Primitivos Intrínsecos)

Um crate nativo focado em manipulação direta de memória, registradores e descompressão SIMD por hardware.

* `src/lib.rs`: Interface de funções de baixo nível do kernel.
* `src/memory/aligned_alloc.rs`: Alocador do tipo *arena bump* para buffers contíguos estritamente alinhados a 64 bytes (SIMD-ready).


* `src/simd/avx2.rs`: Loops vetorizados e máscaras de 256 bits para CPUs legadas.
* `src/simd/avx512.rs`: Loops analíticos de 512 bits (`_mm512_cmpeq_epi32_mask`) para chips modernos.


* `src/simd/neon.rs`: Loops vetorizados de 128 bits e suporte SVE para ambientes ARM64 Cloud.


* `src/compression/bitpack.rs`: Kernels de descompressão massiva ultrarrápida (FastPFor / BitPacking).


* `src/compression/streamvbyte.rs`: Decodificador VarInt vetorizado para inteiros de escala esparsa.


* `src/selection/bitmap.rs`: Operações lógicas *bitwise* diretas em registradores de hardware para `SelectionVector::Bitmap`.



---

## 3. Detalhamento Técnico: Como implementar as SPECs

Para transformar as propostas teóricas (RFCs) em código de produção real, siga rigorosamente o seguinte plano de execução em camadas:

### Passo 1: Estabilização do `DataChunk` ABI e Memória Livre de Sincronização

1. Implementar o `ScratchAllocator` em `hume-runtime`. Cada thread analítica ganha uma arena *bump allocation* vinculada ao seu nó NUMA de trabalho. Alocações temporárias operam em tempo $O(1)$ e são limpas apenas resetando o ponteiro base ao final de cada morsel.


2. Definir a estrutura do `DataChunk` contendo `Vec<Vector>`, a assinatura do `SelectionVector` e o array de IDs físicos (`PhysicalRowID`).



### Passo 2: Construção da Microarquitetura Adaptativa (*Selection Vector*)

1. Criar o mecanismo de promoção e demolição dinâmica de representação em loop:


* Se a seletividade após um filtro for **alta ($\ge 25\%$)**, o chunk adota `SelectionVector::Bitmap`, ativando loops *branchless* via instruções bitwise SIMD.


* Se for **baixa ($< 25\%$)**, converte para `SelectionVector::Index16` ou `Index32`, compactando o espaço de cache L1/L2 e pulando a varredura de bits zerados.




2. Codificar o `Adaptive Morsel Size`: o tamanho do bloco inicia em 8.192 linhas e é escalado até 131.072 linhas baseando-se no feedback do cache do processador hospedeiro.



### Passo 3: Implementação da Materialização Tardia (*Late Materialization*)

1. O operador de `Scan` deve ser modificado para ler **apenas** as colunas contidas nos predicados mais seletivos da consulta (ex: a coluna `score`).


2. O predicado é computado e gera o `SelectionVector`. O pipeline transita apenas esses IDs compactos.


3. O operador `LateFetch` intercepta o fim do pipeline e faz um lookup cirúrgico no disco/RAM (`PhysicalRowID`) para buscar as colunas remanescentes projetadas (ex: coluna `nome`), mitigando de forma agressiva a poluição do cache do processador.



### Passo 4: Implementação do Radix Hash Join Engine

1. Abandonar tabelas de hash gigantescas. O operador `join.rs` deve inspecionar as chaves e quebrá-las em subpartições (Fase Radix) baseando-se nos bits do hash.


2. O tamanho de cada partição radix resultante é calibrado estritamente para caber por inteiro dentro do cache L2 ou L3 dedicado da thread de execução, realizando o *Build & Probe* sem gerar *stalls* de memória principal.



### Passo 5: Atualização da Malha Estatística e AQE

1. Conectar a telemetria do `Pipeline Profiler` à máquina de estados do AQE.


2. Injetar barreiras lógicas na árvore de execução. Ao atingir uma barreira, coletar as estatísticas reais de cardinalidade via sketches probabilísticos (`HyperLogLog`, `TDigest`).


3. Se o desvio estatístico ultrapassar o `AdaptiveThreshold` calculado em `cost.rs`, a máquina de estados muda para `State::ReOptimize`, disparando o replanejamento dinâmico da subárvore remanescente (ex: convertendo um *Sort-Merge Join* pesado em um *Broadcast Hash Join* em tempo de execução).



### Passo 6: Validação e o Contrato de Vitória de Benchmarks

Nenhum código do ecossistema HUME será integrado à ramificação principal sem passar pelas esteiras do `heraclitus-bench` operando sob o **Contrato de Reprodutibilidade**. As variáveis de ambiente devem ser travadas (frequência de CPU em modo *performance*, afinidade de núcleo atada por thread via `core_affinity` e páginas de memória configuradas em `transparent_hugepage`).

O código modificado deve satisfazer as asserções de hardware brutas do silício:

```rust
assert!(metrics.l1_dcache_miss_rate < 0.03); // Validação de localidade L1[cite: 2]
assert!(metrics.branch_misprediction < 0.01);// Validação de lógica branchless[cite: 2]
assert!(metrics.memory_bandwidth_util > 0.85);// Validação de saturação do barramento de RAM[cite: 2]

```

Para executar as propostas lógicas das novas **RFCs (Fases de Engenharia do HUME)** de forma perfeitamente alinhada ao ecossistema estável do banco de dados, o desenvolvimento deve ser segmentado detalhadamente documento por documento.

Abaixo está o roteiro de engenharia cirúrgico, especificando arquivos a criar, modificar e as regras estritas de codificação para cada **SPEC**.

---

## SPEC-0000: ABI de Execução, Modelo Bifurcado e Ciclo de Memória

### 1. Arquivos a Criar / Modificar

* **Criar:** `crates/hume-runtime/src/morsel/batch.rs`

* **Criar:** `crates/hume-runtime/src/memory/aligned_alloc.rs`

* **Modificar:** `Cargo.toml` (raiz do workspace)



### 2. Implementação Passo a Passo

* **Representação de Dados Bifurcada:** No arquivo `batch.rs`, codifique a struct `ExecutionBatch` desacoplada do armazenamento em disco. Crie campos contendo ponteiros brutos `*mut u8` alinhados a 64 bytes para as colunas calculadas transientes e campos `*mut u64` para as máscaras de validividade `validity` (compatíveis com Roaring Bitmaps). Adicione uma referência opcional via `Option<Arc<StorageBatch>>` apontando para o bloco original imutável lido do log de persistência.


* **Mapeamento de Estados da Memória:** Implemente o enum `MemoryState` detalhando explicitamente as primitivas de propriedade: `Owned`, `Borrowed`, `Pinned`, `GPUResident`, `NetworkOwned`, `Spilled`, `Compressed` e `Encrypted`. Bloqueie mutações in-place caso o estado seja avaliado como `Borrowed` ou `Pinned`.


* **Arquitetura do `ScratchAllocator`:** No arquivo `aligned_alloc.rs`, programe um alocador do tipo *arena bump allocation* sem travas ou barreiras de sincronização global (`Mutex` ou `Arc`). Atribua uma instância thread-local deste alocador para cada worker thread ativa do pool analítico, vinculando as páginas contíguas de RAM diretamente ao nó NUMA de processamento da thread. Ao final de cada Morsel, execute uma reinicialização de overhead zero ($O(1)$) resetando o ponteiro base da arena.



---

## SPEC-0036: Subsistemas Enterprise, Pool de Buffers e Agendador

### 1. Arquivos a Criar / Modificar

* **Criar Crate Novo:** `crates/heraclitus-resource/` (adicionar `src/lib.rs`)


* **Criar Crate Novo:** `crates/heraclitus-buffer/` (adicionar `src/lib.rs`, `src/eviction.rs`, `src/prefetch.rs`)


* **Criar Crate Novo:** `crates/heraclitus-scheduler/` (adicionar `src/lib.rs`)



### 2. Implementação Passo a Passo

* **Controle de Admissão de Recursos:** Em `heraclitus-resource`, codifique as estruturas do `ResourceManager` injetadas via `ExecutionContext`. Crie regras estritas para suspender o agendamento de novas queries caso o orçamento global de memória RAM seja estourado, além de rotinas de preempção cooperativa (`Preemption & Yield`) para forçar pipelines analíticos de baixa prioridade a cederem ciclos para transações distribuídas urgentes.


* **Pool de Buffers Avançado:** No arquivo `eviction.rs` do crate de buffers, implemente a hierarquia de cache de dados utilizando a combinação do algoritmo **CLOCK-Pro** (para gerenciar páginas frias e quentes de forma distinta) e o filtro **TinyLFU** (para reter dados OLTP frequentes e impedir que grandes varreduras OLAP limpem o cache principal).


* **Pré-carregamento Inteligente:** Em `prefetch.rs`, desenvolva uma thread assíncrona encarregada de ler adiantadamente páginas no `heraclitus-object-store` com base no padrão gerado pelo operador físico analítico.


* **O Agendador Centralizado de Prioridades:** No crate `heraclitus-scheduler`, programe um agendador central de background baseado em filas de prioridade com cotas máximas de hardware, distribuindo de forma coordenada as tarefas do banco para evitar contenção de CPU:
* *Crítica:* Gravação e compactação do WAL (Log).


* *Alta:* Rebuild de índices HNSW/Grafo e fusão de memtables.


* *Média:* Serialização Parquet e metadados Iceberg.


* *Baixa:* Coleta de estatísticas da engine e Garbage Collection de Manifestos.





---

## SPEC-0037: Infraestrutura Analítica SOTA, AQE e Modelo de Custo

### 1. Arquivos a Criar / Modificar

* **Modificar:** `crates/heraclitus-query/src/cost.rs`

* **Criar Crate Novo:** `crates/heraclitus-catalog/`

* **Criar Crate Novo:** `crates/heraclitus-manifest/`


### 2. Implementação Passo a Passo

* **A Malha Matemática do Otimizador Baseado em Custos (CBO):** Reescreva o arquivo `cost.rs` para abandonar heurísticas puras baseadas em contagem linear de tuplas. Programe a equação contínua e multidimensional do custo total ponderado:



$$\text{Custo}_{\text{total}} = \psi_{\text{cpu}} \cdot \mathcal{C}_{\text{cpu}} + \psi_{\text{mem}} \cdot \mathcal{C_{\text{mem}}} + \psi_{\text{io}} \cdot \mathcal{C}_{\text{io}} + \psi_{\text{net}} \cdot \mathcal{C}_{\text{net}}$$



Escreva as funções internas calculando de forma analítica o custo de computação ($\mathcal{C}_{\text{cpu}}$ com base na largura SIMD do hardware), o custo de memória ($\mathcal{C}_{\text{mem}}$ estimando *misses* de cache L1/L2/L3 e latências de RAM física), e os custos de IO/Rede ($\mathcal{C}_{\text{io}}$ e $\mathcal{C}_{\text{net}}$ calibrados pela latência do NVMe local versus a banda de rede do operador de distribuição `Exchange`).


* **Máquina de Estados e Barreiras do AQE:** Implemente as barreiras lógicas de materialização (*Query Stages*) no pipeline físico. Insira a máquina de estados adaptativa: `State::Created` $\rightarrow$ `State::Running` $\rightarrow$ `State::CollectStatistics`. Caso o desvio estatístico de cardinalidade na barreira supere o limite aceitável (`AdaptiveThreshold`), acione dinamicamente a alternância de planos em tempo de execução, convertendo um *Sort-Merge Join* ou *Shuffled Hash Join* em um *Broadcast Hash Join* local se a tabela de um dos lados couber na RAM ativa.



---

## SPEC-0038: Unificação HUME-IR, Late Materialization e Branchless SIMD

### 1. Arquivos a Criar / Modificar

* **Criar Crate Novo:** `crates/hume-ir/` (adicionar `src/lib.rs` e `src/opcodes.rs`)


* **Criar:** `crates/hume-runtime/src/materialization/late_fetch.rs`

* **Modificar:** `crates/heraclitus-analytics/src/vectorized.rs`


### 2. Implementação Passo a Passo

* **Representação Intermediária SSA (HUME-IR):** No novo crate `hume-ir`, conceitue o construtor SSA garantindo o cumprimento de suas 5 invariantes normativas primordiais: definição única por identificador (`ValueId`), causalidade dominante na cadeia de blocos básicos, imutabilidade estrita de tipos do esquema, fusão formal de caminhos via Nós-$\Phi$ (*Phi Nodes*) e a explicitação total de efeitos colaterais por opcodes binários dedicados.


* **Pipelines de Execução *Push-Based*:** Em `vectorized.rs`, adapte o loop do motor para operar em formato de empurrão (*Push-Based*), onde operadores de origem enviam blocos de dados contínuos de memória através das worker threads do escalonador até atingirem um operador bloqueador de sincronização (*Pipeline Breaker*).


* **Lógica de Materialização Tardia (*Late Materialization*):** No arquivo `late_fetch.rs`, programe o operador encarregado de ler exclusivamente as colunas presentes nos predicados analíticos mais seletivos da consulta (gerando a filtragem inicial). Somente as referências compactas físicas dos registros sobreviventes (`PhysicalRowID`) devem trafegar pelos passos intermediários, executando a busca tardia das colunas projetadas restantes apenas no encerramento do pipeline.


* **Loops de Processamento *Branchless*:** Remova ramificações condicionais (`if` tradicionais) nos loops internos de avaliação de predicados colunares. Utilize vetores de seleção compactados gerados por hardware a partir de máscaras SIMD booleanas diretas.



---

## SPEC-0039: Multi-Dialect IR, Otimização Declarativa e Algoritmos Avançados

### 1. Arquivos a Criar / Modificar

* **Criar:** `crates/hume-ir/src/dialect.rs`

* **Criar:** `crates/hume-ir/src/pattern_engine.rs`

* **Criar:** `crates/hume-runtime/src/execution/aggregation.rs`


### 2. Implementação Passo a Passo

* **A Infraestrutura de Dialetos Modulares:** No arquivo `dialect.rs`, estruture os cinco níveis progressivos e independentes de otimização de IR inspirados em conceitos MLIR: `Logical`, `Relational`, `Vector`, `Physical` e `Machine Dialect`.


* **O Mecanismo de Casamento de Padrões (Pattern Matching):** Desenvolva a struct `RewriteRule` em `pattern_engine.rs` para mapear e transformar a árvore de instruções de forma estritamente declarativa, fundindo automaticamente sequências de filtragem e projeções analíticas concorrentes em loops unificados integrados (`Fusion Pass`).


* **Agregações e Janelas Otimizadas por Contexto:** No arquivo `aggregation.rs`, implemente a especialização algorítmica `Cache-Aware Aggregation`:
* Se a cardinalidade estimada do grupo for pequena, execute o mecanismo de **Perfect Hashing**, mapeando os índices diretamente por bitmask e garantindo imunidade total contra colisões no cache L1/L2 de cada thread.


* Para ordenação com limites, proíba ordenações totais (*Sort-Breaking*), aplicando a estratégia analítica de **Partial Heap** associada a partições SIMD.




* **Sub-pipeline Assíncrono de Despejo (*Spill-to-Disk*):** Programe uma rotina de monitoramento de memória em execução. Caso um operador de junção radix estoure o orçamento alocado pelo `ExecutionContext`, o runtime deve congelar a partição e iniciar um pipeline em background descarregando as tabelas de dispersão frias para o disco NVMe local via requisições diretas não-bloqueantes de `io_uring`.



---

## SPEC-0040 & SPEC-0041: O Núcleo do Kernel HUME Normativo

### 1. Arquivos a Criar / Modificar

* **Criar Crate Novo:** `crates/hume-kernel/` (adicionar `src/lib.rs`, `src/simd/avx512.rs`, `src/simd/neon.rs`, `src/compression/bitpack.rs`, `src/selection/bitmap.rs`)


* **Criar:** `crates/hume-runtime/src/morsel/selection_vector.rs`

* **Modificar:** `crates/hume-runtime/src/lib.rs`


### 2. Implementação Passo a Passo

```
crates/hume-kernel/src/
├── lib.rs
├── simd/
│   ├── avx512.rs   ➔ Loops de 512-bits (_mm512_cmpeq_epi32_mask)
│   └── neon.rs     ➔ Primitivas ARM de 128-bits e máscaras SVE
├── compression/
│   └── bitpack.rs  ➔ Kernels estáveis FastPFor e decodificação densa
└── selection/
    └── bitmap.rs   ➔ Operações lógicas bitwise para SelectionVector::Bitmap

```

* **A Estrutura Binária do `DataChunk` ABI:** No arquivo centralizado do runtime, consolide formalmente a assinatura binária estável do `DataChunk` contendo: a contagem viva de tuplas (`cardinality`), a capacidade alocada (`capacity`), a enumeração do hardware alvo (`Device::CPU` ou `Device::GPU`), a coleção de vetores de dados alinhados (`columns`), o enum adaptativo do vetor de seleção (`selection`) e a matriz contendo os IDs persistentes (`row_ids`).


* **O Mecanismo Híbrido de Seleção:** No arquivo `selection_vector.rs`, programe o ciclo de mutação adaptativa da estrutura física:


* **Seleção de Alta Densidade ($\ge 25\%$ de sobrevivência):** O operador colunar altera automaticamente a representação para `SelectionVector::Bitmap`, processando junções lógicasbooleanas (`AND`, `OR`, `NOT`) na velocidade máxima do silício via operações SIMD puras de hardware.


* **Seleção de Baixa Densidade ($< 25\%$ de sobrevivência):** O bloco de dados converte sua estrutura física para arrays primitivos compactos contendo índices numéricos diretos via `SelectionVector::Index16` ou `Index32`, compactando o cache e acelerando o lookup final.




* **A Camada de Intrinsecas Isoladas do Kernel:** Implemente loops de varredura especializados por arquitetura detectada no *boot* dentro do crate isolado `hume-kernel`:


* Mapeie a instrução `_mm512_cmpeq_epi32_mask` em `avx512.rs` para processadores Intel/AMD de última geração.


* Mapeie os kernels `vceqq_s32` vetorizados junto a máscaras SVE em `neon.rs` para servidores ARM64.


* Integre os algoritmos rápidos de decodificação colunar de bytes `FastPFor` e `StreamVByte` na pasta de compilação.




* **Garantia de Predicabilidade de Branches:** Estruture os loops internos de descompressão e paginação colunar para operarem sob a filosofia de padrões altamente previsíveis para a tabela de predição de saltos do processador hospedeiro, isolando ramificações estruturais inevitáveis (como checagem de limites de páginas físicas) fora das zonas analíticas críticas do motor.



---

## 3. Detalhes Tudo que Tem que Ser Feito para Fazer os SPEC (Resumo de Engenharia)

Para garantir o sucesso absoluto desse ciclo de desenvolvimento sem introduzir regressões ou instabilidades nos 254 testes verdes existentes do Heraclitus, você deve seguir o seguinte protocolo de implementação em 4 passos:

1. **Higiene Documental e Acoplamento Zero:** Rebaixe as especificações `SPEC-0000` e `SPEC-0036` a `SPEC-0041` para o status de propostas lógicas (RFCs). Não reescreva ou destrua o motor vetorizado Arrow (`vectorized.rs`) estável atual; todas as novas estruturas do HUME devem nascer isoladas dentro dos dois novos crates independentes (`hume-runtime` e `hume-kernel`).


2. **Desenvolvimento Isolado do Core Físico (Fase 1 do Roadmap):** Codifique primeiramente o alinhamento de memória a 64 bytes e as assinaturas binárias do `DataChunk`, do `SelectionVector` adaptativo (Bitmap vs. Index) e o operador deLookup tardio `LateFetch`.


3. **Desenvolvimento das Otimizações Lógicas (Fase 2 do Roadmap):** Implemente a reescrita matemática do CBO em `cost.rs` e as barreiras de controle adaptativo do AQE. Substitua gradativamente o executor interno analítico por chamadas que consumam as estruturas homogêneas criadas no `hume-runtime`.


4. **A Porteira Científica do Gate C:** Nenhuma funcionalidade ou otimização analítica será fundida no branch principal sem satisfazer simultaneamente o **Gate C** do protocolo de benchmarks em camadas:


* *Validação de Equivalência:* O plano otimizado por hardware deve produzir um resultado binário/bit-idêntico em relação à execução serial por força bruta.


* *Contrato de Vitória:* O microbenchmark deve demonstrar ganho numérico real medido diretamente sob os contadores de performance de hardware do silício (minimizando *cache-misses* L1/L2/L3 e falhas de predição de branches no processador hospedeiro).

## Pipeline `spec-new-viability-audit`: Relatório de Conclusão

A esteira de auditoria arquitetural paralela concluiu a extração, consolidação e verificação adversarial cruzada das 7 especificações propostas (`SPEC-0000` a `SPEC-0041`) contra a linha viva de código do workspace Heraclitus. O objetivo deste diagnóstico é separar o estado da arte real e implementável de devaneios de engenharia e alucinações de LLM presentes nas propostas.

---

## 1. Catálogo Canônico de Componentes Atômicos (Consolidado & Dedupado)

O processo de desduplicação consolidou as propostas atômicas espalhadas pelas specs em 5 pilares arquiteturais funcionais:

### Pilar A: Layout de Memória e ABI de Execução

* **A1. `ExecutionBatch` vs. `StorageBatch`:** Estrutura bifurcada para permitir mutações controladas em colunas transientes de runtime sem violar a imutabilidade do bloco físico original.


* **A2. `DataChunk` ABI Nátiva:** Interface binária padronizada contendo cardinalidade, capacidade, máscaras de validade e vetores contíguos de dados alinhados a 64 bytes.


* **A3. `SelectionVector` Adaptativo:** Layout híbrido de indexação lógica que alterna dinamicamente entre `Bitmap` (alta densidade) e `Index16/Index32` (baixa densidade).


* **A4. `ScratchAllocator` NUMA-Aware:** Alocador *arena bump* thread-local de custo $O(1)$ sem primitivas de sincronização global (`Mutex`, `Arc`).


* **A5. `PhysicalRowID` Intermediário:** Identificador físico composto (`segment_id` + `page_id` + `offset`) para rastreabilidade e sustentação da materialização tardia.



### Pilar B: Operadores Físicos do Kernel

* **B1. Scan Colunar Vectorized:** Mecanismo de leitura seletiva por página com suporte a pré-carregamento assíncrono inteligente.


* **B2. Filter Branchless SIMD:** Loops internos de filtragem convertidos em máscaras binárias booleanas puras para mitigar a explosão de predição de saltos da CPU.


* **B3. Radix Hash Join Engine:** Junções colunares cujas chaves são inspecionadas e quebradas em subpartições radix calibradas para caber inteiramente dentro do cache L2/L3 por thread.


* **B4. Top-K Partial Heap:** Estratégia de ordenação parcial via loops SIMD que aborta a ordenação total quando há restrições de limite (`LIMIT K`).


* **B5. Auto-Spill Sub-pipeline:** Mecanismo assíncrono apoiado em `io_uring` para serializar e descarregar partições frias para o NVMe local ao estourar o orçamento de RAM.



### Pilar C: Infraestrutura de Compilação e Dialetos de IR

* **C1. HUME-IR SSA-Form:** Linguagem intermediária fortemente tipada em formato *Static Single Assignment* com controle de fluxo unificado por Nós-$\Phi$.


* **C2. Progressão de Dialetos Modulares:** Árvore de transformação inspirada em MLIR dividida em dialetos `Logical`, `Relational`, `Vector`, `Physical` e `Machine`.


* **C3. Rule & Pattern Matching Engine:** Mecanismo declarativo de reescrita baseado em casamento de padrões para fusão de operadores (`Fusion Pass`).


* **C4. JIT Compilation Tier (Cranelift/LLVM):** Compilação Just-In-Time em camadas (*Hot* e *Super Hot*) de loops de predicados matemáticos complexos para código de máquina nativo.



### Pilar D: Governança Adaptativa de Recursos

* **D1. Máquina de Estados do AQE:** Mecanismo adaptativo que divide a query em estágios (*Query Stages*) isolados por barreiras de materialização para replanejamento estatístico em runtime.


* **D2. Vetor de Custo Multidimensional:** Equação de custo contínuo alimentada por fatores de CPU, RAM, IO, Rede, NUMA e falhas de cache do silício hospedeiro.


* **D3. Multi-Tenant ResourceManager:** Árbitro global focado em impor limites estritos de isolamento de hardware por consulta ou por inquilino.


* **D4. CLOCK-Pro / TinyLFU Buffer Pool:** Hierarquia de cache corporativa para paginação adaptativa de blocos em memória principal versus NVMe local.


* **D5. Background Scheduler Cooperativo:** Agendador centralizado de tarefas mistas (compactação do log, GC de manifestos, atualização de histogramas) baseado em prioridades.



### Pilar E: Ecossistema Lakehouse e Federação

* **E1. Apache Iceberg Manifest Manager:** Subsistema para gestão atômica de arquivos de metadados, *Manifest Lists* e transações de tabelas abertas Parquet.


* **E2. Object-Store API Unificada:** Interface de IO assíncrono para abstração nativa de storages compatíveis com S3, GCS e Azure Blob.


* **E3. Foreign Connectors Plane:** Camada unificada para federação de consultas heterogêneas com pushdown de predicados para bancos externos (Postgres/Kafka).



---

## 2. Verificação Baseada no Código Real & Auditoria Adversarial

Cruzando o catálogo canônico de propostas com o estado verificado do repositório real (254 testes verdes, zero falhas), o segundo passo da auditoria determinou os seguintes vereditos de viabilidade física:

### O Núcleo Real da Analítica

* **O Estado Atual:** O crate `heraclitus-analytics` já possui um motor vetorizado v1 funcional (`vectorized.rs`, ~670 linhas) baseado em lotes Arrow estruturados com tamanho fixo de `BATCH_ROWS = 1024` e um otimizador baseado em seletividade (`SelectivityOptimizer`). Ele consome filtros ordenados e os distribui por worker threads paralelizadas com fixação de núcleos via `core_affinity`.


* **Veredicto de Memória e ABI (Pilar A): Extração Altamente Viável.** As propostas de introdução do `DataChunk`, do layout híbrido `SelectionVector` (Bitmap vs. Index) e da localidade do `ScratchAllocator` não conflitam com a filosofia do banco. Elas funcionam como otimizações de algoritmos internos diretamente aplicáveis ao `VecExecutor` atual para mitigar a varredura de bits zerados em queries altamente seletivas.


* **Veredicto de Operadores (Pilar B): Extração Viável.** Operadores focados em localidade de hardware, como a materialização tardia via `PhysicalRowID` (ler apenas colunas de predicados no scan e fazer fetch tardio das restantes) e o particionamento Radix Hash Join, são melhorias mecânicas que se encaixam perfeitamente na infraestrutura vetorizada do projeto. O mecanismo de *Spill-to-disk* determinístico via `io_uring` aproveita de forma natural as estruturas assíncronas já existentes de mapeamento em disco (`mmap.rs`).



### A Utopia Teórica da Compilação e Federação

* **Veredicto de Compilação e Dialetos (Pilar C): Rejeitado por Incompatibilidade de Design.** A criação de uma infraestrutura SSA multi-dialeto no estilo MLIR acompanhada por geradores de código JIT baseados em Cranelift ou LLVM é um esforço estimado em 20 a 50 engenheiros-ano. Além disso, essa complexidade viola frontalmente a invariante inegociável **I2** do Heraclitus ("A inteligência vive no agente, não no banco"). O banco não deve se transformar em uma catedral de compiladores. Os loops analíticos vetorizados atuais do Arrow já utilizam otimizações SIMD nativas por baixo dos panos na velocidade do hardware.


* **Veredicto de Recursos e Governança (Pilar D): Rejeitado Parcialmente (Escopo Inflado).** O banco já possui um balanceador adaptativo funcional verificado: o `EmaCalibrator` (SPEC-032) monitora os skip-scans e reverte o planejador para varreduras de janela caso o modelo de custo degrade. Expandir isso para gerenciadores multi-tenant de cotas epools de buffers CLOCK-Pro customizados duplica funcionalidades operacionais do sistema operacional hospedeiro e infla o escopo para um patamar desnecessário ao produto real (memória auditável de agente, não um data-warehouse genérico de 10B de linhas).


* **Veredicto de Lakehouse e Federação (Pilar E): Rejeitado por Desvio de Escopo.** O Heraclitus resolve processamento OLAP SQL delegando diretamente ao **DataFusion** maduro em `heraclitus-analytics`, sem duplicar o motor. Construir conectores de federação Postgres/Kafka complexos ou um compilador nativo de manifestos Apache Iceberg de raiz destrói o fosso técnico de especialização do banco (grafo, vetor hiperbólico, log imutável Merkle auditável) para competir de forma ineficiente no mercado de query engines generalistas.



---

## 3. O Segundo Passo Adversarial (Riscos Ocultos & Dívida Técnica)

A auditoria adversarial detectou três contradições críticas entre as propostas das novas specs e o comportamento estável provado no código real:

1. **A Armadilha da Não-Reprodutibilidade do JIT vs. Prova Merkle (Quebra de Invariante I1):** O pilar analítico do Heraclitus exige reprodutibilidade bit-a-bit do estado passado (`AS OF LSN`) validado por provas criptográficas Merkle baseadas em Blake3. A introdução de compilação JIT adaptativa e execução especulativa aleatória (`Speculative Execution`) introduz caminhos de processamento assíncronos não-determinísticos que podem gerar variações sutis em pontos de flutuação ($NaN$ e representações de $-0.0/+0.0$) ou na ordem de consolidação dos lotes. Isso quebraria a equivalência de assinaturas de blocos em reinicializações frias (`cold-boot`).


2. **O Risco de Deadlock Clusterizado por Saturação do Tokio:** Conforme validado na auditoria real de estabilização do consenso Raft distribuído via rede TCP, as operações de escrita e queries concorrentes exigem isolamento estrito via `spawn_blocking` para não parquear os workers do Tokio. As novas propostas inserem gerenciadores de recursos invasivos e loops complexos de compilação JIT dentro do caminho vivo da query. Caso $N$ consultas iniciem compilações simultâneas via Cranelift, o tempo de CPU consumido travará o agendamento de tarefas do `RaftCore`, disparando falsos timeouts de batimento cardíaco (*heartbeat*), queda de líderes e cenários de *split-brain* no cluster.


3. **Ilusão de SIMD Manual:** A SPEC-0040 propõe a escrita de kernels intrínsecos manuais de AVX512 e Neon para "humilhar o DuckDB". O validador adversarial aponta que os kernels de processamento colunar subjacentes do ecossistema Apache Arrow integrados no projeto já operam com auto-vetorização e otimizações de hardware maduras. Reescrever loops de registradores à mão gera um ganho de performance marginal e introduz um risco altíssimo de falhas de segmentação (*segmentation faults*) e ponteiros corrompidos em Rust instável.



---

## 4. Matriz de Síntese Final & Roteiro de Extração Incremental

Para direcionar o time de desenvolvimento com precisão cirúrgica, a matriz abaixo consolida o parecer final da esteira analítica. Itens classificados como **Aprovados para Extração** devem ser convertidos em PRs pequenos e isolados contra o motor analítico vetorizado atual.

| Componente Proposto | Origem (Specs) | Estado Atual no Código Real | Veredicto da Auditoria | Ação Operacional Imediata (PR Isolado) |
| --- | --- | --- | --- | --- |
| **`DataChunk` ABI Layout** | `SPEC-0000`, `SPEC-0038`, `SPEC-0041` | Lotes estruturados fixos via Arrow RecordBatches.

 | **APROVADO PARA EXTRAÇÃO** | Implementar `DataChunk` minimalista em novo módulo interno reutilizável.

 |
| **`SelectionVector` Adaptativo** | `SPEC-0041` | Vetor de filtragem colunar posicional simples.

 | **APROVADO PARA EXTRAÇÃO** | Adicionar enum `SelectionVector` com promoção dinâmica Bitmap vs. Index.

 |
| **Late Materialization** | `SPEC-0038`, `SPEC-0040` | Materialização total sem poda colunar adiantada.

 | **APROVADO PARA EXTRAÇÃO** | Modificar o scan inicial para extrair `PhysicalRowID` e adiar fetch de colunas de projeção.

 |
| **Radix Hash Join Engine** | `SPEC-0038`, `SPEC-0041` | Hash Join padrão operando sobre lotes inteiros.

 | **APROVADO PARA EXTRAÇÃO** | Desenvolver mini-tabelas de hash locais baseadas nos bits significativos da chave.

 |
| **`ScratchAllocator` Arena** | `SPEC-0000` | Alocações dinâmicas padrão do sistema por lote.

 | **APROVADO PARA EXTRAÇÃO** | Implementar alocador *arena bump* de thread-local focado em localidade NUMA.

 |
| **Vetor de Custo Multidimensional** | `SPEC-0000`, `SPEC-0036`, `SPEC-0037` | Modelo baseado em seletividade e calibrador EMA ativo.

 | **MODIFICAÇÃO PARCIAL** | Expandir o arquivo `cost.rs` incorporando fatores reais de peso de cache medidos.

 |
| **Compilador JIT (Cranelift/LLVM)** | `SPEC-0037`, `SPEC-0038`, `SPEC-0039` | Interpretação estável de bytecode via VM WASM isolada.

 | **REJEITADO POR DESIGN** | Manutenção do motor vetorizado baseado em Arrow. Vetar Cranelift no core.

 |
| **Infraestrutura MLIR SSA-Form** | `SPEC-0038`, `SPEC-0039` | AST direta gerada por Pest acoplada ao `PhysicalIr`.

 | **REJEITADO POR DESIGN** | Manter o pipeline atual `LogicalPlan` $\rightarrow$ `PhysicalIr` sem dialetos complexos.

 |
| **Apache Iceberg Lakehouse** | `SPEC-0036` | Persistência colunar e tiering frio genérico ativo.

 | **REJEITADO POR ESCOPO** | Vetar gerenciadores de manifestos. Delegar persistência analítica pesada ao DataFusion.

 |
| **Federação Cross-Engine** | `SPEC-0037`, `SPEC-0038` | Superfície homogênea estável baseada em GQL pura.

 | **REJEITADO POR ESCOPO** | Manter foco em queries locais de grafo e vetores de alta performance. Rejeitar pushdowns externos.

 |
| **Wrapper gRPC para Consenso** | `STATUS.md` | Consenso Raft e replicação provados via sockets TCP nativos.

 | **APROVADO (DÍVIDA TÉCNICA)** | Escrever wrapper gRPC/tonic cosmético sobre os tipos serde do `heraclitus-raft`.

 |

### Conclusão do Parecer

O plano estratégico foi limpo de componentes inflados. A equipe de engenharia deve focar estritamente na **Fase 1 de Extração Incremental do HUME** (ABI de dados, vetor de seleção híbrido e materialização tardia), injetando essas otimizações diretamente no `VecExecutor` existente dentro de `heraclitus-analytics`. Qualquer modificação deve respeitar o **Gate C**, provando equivalência de resultados bit-idêntica e redução real medida de falhas de cache de CPU no silício real antes do merge.