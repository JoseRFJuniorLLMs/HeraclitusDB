# SPEC-0000: ESPECIFICAÇÃO DE REFERÊNCIA DA PLATAFORMA DE EXECUÇÃO HUME (CONTRATOS CRÍTICOS DE MICROARQUITETURA)

---

## Status: DOCUMENTO DE ENGENHARIA CONGELADO E SELADO (RFC-000-FINAL)

**Data de Emissão:** 11 de Julho de 2026

**Alvo:** Especificação Estrita da ABI de Execução, Invariantes SSA, Gerenciamento de Memória Livre de Sincronização e Regras de Governança do Core Engine.

---

## 1. O Modelo de Dados Bifurcado: `StorageBatch` vs. `ExecutionBatch`

O HUME rejeita a imutabilidade absoluta do bloco de execução para evitar cópias de memória ocultas durante avaliações de colunas geradas, projeções temporárias e decodificações de dicionário. O ecossistema segmenta formalmente a representação física em duas entidades distintas:

```
    [ ARMADILHA DE PERSISTÊNCIA ]
                  │
                  ▼
       [ hume::StorageBatch ] ◄─── (100% Imutável, Alinhado, Representação de Disco/Nuvem)
                  │
                  ▼ (Descarregado por Referência Segura / Zero Copy)
       [ hume::ExecutionBatch ]
       ├── ColumnVector Views ➔ (Apontam para os buffers contíguos do StorageBatch)
       ├── Transient Columns   ➔ (Espaço mutável para expressões computadas/projeções)
       ├── SelectionVector     ➔ (Janela lógica de indexação esparsa ou bitmaps)
       └── Scratch Space       ➔ (Alocações voláteis locais por thread)

```

### 1.1. Layout Binário do `ExecutionBatch`

```rust
pub enum DataType {
    Int32,
    Float32,
    String,
    DenseVector,
}

pub struct ColumnVector {
    pub datatype: DataType,
    pub buffer: *mut u8,             // Ponteiro bruto alinhado a 64 bytes (SIMD-Ready)[cite: 7]
    pub validity: *mut u64,          // Bitmask compacto para controle de NULLs (Roaring)[cite: 7]
    pub compression: CompressionType,// FastPFor, StreamVByte, RLE, Delta[cite: 5]
    pub encoding: EncodingType,      // Plain, Dictionary, BitPacked[cite: 5]
}

pub struct ExecutionBatch {
    pub storage_reference: Option<Arc<StorageBatch>>, // Link opcional para o bloco imutável original
    pub views: Vec<ColumnVector>,                     // Views de leitura sobre o StorageBatch
    pub transients: Vec<ColumnVector>,                // Colunas calculadas em runtime (mutáveis)
    pub cardinality: usize,                           // Contagem viva de tuplas ativas no Morsel[cite: 7]
    pub capacity: usize,                              // Teto físico alocado (Padrão: 102.400 linhas)[cite: 7]
}

```

---

## 2. Ciclo de Vida da Memória: `ScratchAllocator` & Modelo Rico de Propriedade

A alocação de memória analítica elimina qualquer barreira de sincronização global (`Mutex`, `Arc` ou alocadores globais do sistema) durante loops internos de processamento.

### 2.1. A Arquitetura `ScratchAllocator` (Thread-Local Scratchpad)

Cada thread de execução analítica ativa no pool de processamento possui um `ScratchAllocator` exclusivo, associado ao seu nó NUMA de trabalho.

```
 [ Thread Analítica N ] ➔ Alocações Temporárias ➔ [ ScratchAllocator (Thread-Local) ]
                                                            │
                                                            ▼ (O(1) Arena Bump Allocation)
                                                   [ Página Contígua de RAM ]
                                                            │
                                                            ▼ (Ao fim do Morsel/Stage)
                                                   [ Global Pointer Reset (Zero Overhead) ]

```

Toda memória necessária para a materialização de vetores temporários, filtros ou máscaras booleanas SIMD é adquirida por meio de um alocador do tipo *bump* de custo $O(1)$. A memória desaparece instantaneamente ao fim do estágio do pipeline apenas redefinindo o ponteiro base da arena local.

### 2.2. A Matriz Rica de Estado de Propriedade de Memória (`MemoryState`)

A gerência de ciclo de vida do dado passa a responder explicitamente por estados que modificam de forma agressiva as primitivas de desreferenciamento do hardware:

```rust
pub enum MemoryState {
    Owned,          // Alocação exclusiva da QueryArena atual; livre para mutação in-place[cite: 4]
    Borrowed,       // Empréstimo de leitura de outro sub-pipeline; imutável[cite: 7]
    Pinned,         // Travado na RAM ativa; imutável, protegido contra paginação ou evicção
    GPUResident,    // Alocado na VRAM do acelerador; ilegível diretamente via ponteiro de CPU
    NetworkOwned,   // Buffer atado ao barramento de rede (Mecanismo Arrow Flight IPC)[cite: 8]
    Spilled,        // Serializado e descarregado via io_uring para NVMe local[cite: 5]
    Compressed,     // Dados ainda sob codificação densa; necessita descompressão SIMD
    Encrypted,      // Protegido criptograficamente; necessita de chaves ativas do contexto
}

```

---

## 3. O Sistema Nervoso de Execução: `Pipeline` & `OperatorState`

O escalonador centralizado e o gerador de código JIT abandonam loops genéricos sobre operadores atômicos e passam a atuar sobre a abstração formal de **Pipelines Lineares**.

```
[ Pipeline Stage N ] ➔ Execution Pipeline Loop (Push-Based / Streaming Operators)[cite: 3]
 ├── Operator 1: Scan
 ├── Operator 2: Filter (SIMD Branchless)[cite: 6]
 └── Operator 3: Project (In-Place Transients)
          │
          ▼ (Obriga a Sincronização / Pipeline Breaker)
[ Pipeline Breaker Barrier ] ➔ Materializa no Estado local (Hash Table / Radix Partition)[cite: 3, 4]

```

### 3.1. A Interface de Execução Cooperativa (ABI do Operador)

O modelo de execução adota um formato assíncrono e cooperativo, projetado para suportar streaming eficiente e tratamento nativo de contrapressão (*Backpressure*):

```rust
pub enum OperatorState {
    NeedInput,   // O operador necessita de um novo DataChunk de entrada para processar
    HasOutput,   // O operador preencheu o DataChunk de saída e possui mais dados pendentes
    Finished,    // O operador encerrou sua computação (Atingiu o fim do bloco ou limite)
    Blocked,     // Aguardando recursos externos (Acesso assíncrono à rede ou disco)
}

pub trait PipelineOperator {
    fn open(&mut self, ctx: &ExecutionContext) -> Result<()>;
    
    fn execute(
        &mut self,
        ctx: &ExecutionContext,
        input: &DataChunk,
        output: &mut DataChunk,
    ) -> Result<OperatorState>;
    
    fn close(&mut self, ctx: &ExecutionContext) -> Result<()>;
}

```

---

## 4. O Sistema de Controle de Admissão: `ResourceManager` & `ExecutionContext`

O ecossistema remove qualquer singleton ou estado implícito. Toda a governança de recursos computacionais é controlada por meio do contexto injetado explicitamente em cada operador.

```rust
pub struct ExecutionContext {
    pub allocator: Arc<QueryArena>,            // Memória isolada por ciclo de consulta[cite: 4]
    pub scratch_pad: *mut ScratchAllocator,     // Alocador ultra-rápido de thread local
    pub resource_manager: Arc<ResourceManager>, // Árbitro global de concorrência e cotas[cite: 1]
    pub scheduler: Arc<TaskScheduler>,          // Distribuidor de tarefas baseado em topologia[cite: 1]
    pub cancellation_token: CancellationToken,   // Sinalizador de interrupção e timeout
    pub memory_budget_bytes: u64,               // Cota máxima de RAM antes do Spill compulsório
    pub deadline: std::time::Instant,           // Limite temporal rígido de execução
}

```

### 4.1. Modos Avançados de Arbitragem do Gerente de Recursos

O `ResourceManager` dita o comportamento das consultas online operando sob as seguintes primitivas clássicas de sistemas operacionais críticos:

* **Admission Control:** Bloqueia a entrada de novas queries pesadas se os orçamentos globais de RAM do servidor estiverem comprometidos.


* **Preemption & Yield:** Força um pipeline a ceder espaço computacional ou reduz o paralelismo de suas worker threads se uma consulta transacional de prioridade ultra-alta der entrada no sistema.
* **Backpressure Handling:** Sinaliza para os operadores de origem (`Scan`) paralisarem a leitura de novas páginas caso a fila de escrita remota em disco esteja operando em saturação de IOPS.

---

## 5. Modelo de Custo Multidimensional Expandido & Máquina de Estados do AQE

O arquivo `cost.rs` deixa de estimar planos com base em heurísticas imprecisas de CPU e assume um vetor abrangente de custos por instrução:

$$\text{CostVector} = \begin{bmatrix} C_{\text{cpu}} \\ C_{\text{mem}} \\ C_{\text{io}} \\ C_{\text{net}} \\ C_{\text{cache}} \\ C_{\text{branch}} \\ C_{\text{numa}} \\ C_{\text{gpu}} \\ C_{\text{comp}} \end{bmatrix}$$

Uma consulta que consome apenas $5\%$ de CPU, mas passa $80\%$ de sua janela temporal aguardando a chegada de páginas de memória principal, é severamente penalizada pelas componentes $C_{\text{cache}}$ e $C_{\text{numa}}$, forçando o otimizador a escolher planos que favoreçam junções radix baseadas no tamanho exato do cache L2/L3.

### 5.2. Máquina de Estados Finita e Adaptativa do AQE

A Execução Adaptativa de Consultas (AQE) deixa de operar por gatilhos estáticos e passa a ser regida de forma determinística por uma máquina de estados baseada em **Limiares Adaptativos (Adaptive Thresholds)**:

```
  [ State::Created ] ➔ Inicializa e compila o primeiro estágio do Pipeline
          │
          ▼
  [ State::Running ] ➔ Execução ativa de Morsels até atingir barreira de materialização[cite: 3]
          │
          ▼
  [ State::CollectStatistics ] ➔ Rastreia a seletividade e dispersão real dos dados[cite: 3]
          │
          ├────────────────────────────────────────────────────────┐
          ▼ (Se desvio estatístico > AdaptiveThreshold)             ▼ (Se estável)
  [ State::ReOptimize ] ➔ Mutação dinâmica da subárvore remanescente    [ State::Resume ]
          │                                                        │
          ▼                                                        ▼
  [ State::CompileJIT ] ➔ Regenera kernels via Cranelift            [ State::Finished ]

```

O `AdaptiveThreshold` é calculado dinamicamente com base no tipo de operador. Em filtros relacionais simples, o limite tolerado de desvio pode chegar a $30\%$; em operadores pesados de junções distribuídas ou varreduras de grafos, o limite cai para $5\%$, disparando a reoptimização imediata para evitar explosões catastróficas de cardinalidade no cluster.

---

## 6. O Rigor da Representação Intermediária: Contratos e Invariantes SSA

Para habilitar a passagem de fases de compilação JIT agressivas livres de validações redundantes em runtime, a infraestrutura do `hume-ir` impõe e assume as seguintes invariantes estritas em formato *Static Single Assignment* (SSA):

1. **Definição Única:** Cada identificador de registro ou valor (`ValueId`) é definido e atribuído exatamente uma vez em toda a cadeia de execução.
2. **Relação Causal Dominante:** Todo e qualquer uso de um `ValueId` deve ocorrer obrigatoriamente após a sua instrução de definição na linha linear do bloco básico.
3. **Invariante de Esquema:** A assinatura de tipos (`Schema`) de um `BasicBlock` é estritamente imutável e constante durante o processamento do bloco correspondente.
4. **Consolidação de Fluxo por Nós-$\Phi$:** Ramificações de controle e decisões condicionais procedentes de caminhos lógicos divergentes devem fundir seus valores de retorno utilizando instruções formais de nós-$\Phi$ (*Phi Nodes*) na entrada do bloco de convergência.
5. **Explicitação de Efeitos Colaterais:** Qualquer operação que gere mutação de estado persistente, chamadas de IO de disco, sincronização de rede ou alocação global deve ser obrigatoriamente representada por opcodes específicos de efeitos colaterais (`HumeOpcode::Spill`, `HumeOpcode::Exchange`), vedando efeitos implícitos por baixo dos panos.

---

## 7. O Contrato de Vitória de Sistemas: Reprodutibilidade de Benchmarks

O crate `heraclitus-bench` elimina o ruído experimental. Um teste de performance ou validação de regressão na esteira de integração contínua (CI) só é aceito se for executado sob o **Contrato de Reprodutibilidade**, cujo manifesto físico exige o congelamento das seguintes variáveis de ambiente:

```toml
[benchmark_reproducibility_contract]
rustc_version = "1.85.0-nightly"
compiler_flags = "-C target-cpu=native -C llvm-args=-fp-contract=fast -C lto=fat"
cpu_governor = "performance"          # Frequência travada no clock base (Sem Turbo Variável)
page_size_mode = "transparent_hugepage" # Força o uso de páginas de 2MB/1GB para mitigar TLB misses
thread_affinity_mode = "core_pinned"  # Fixação estrita round-robin por nó NUMA[cite: 8]
dataset_seeding = "0xDEADBEEF42"      # Semente determinística para distribuição de assimetria[cite: 6]

```

As asserções pós-execução avaliam diretamente os contadores de baixo nível da arquitetura física do silício hospedeiro:

```rust
assert!(metrics.l1_dcache_miss_rate < 0.03); // Reprovado se quebrar localidade L1
assert!(metrics.branch_misprediction < 0.01);// Reprovado se usar branches imprevisíveis
assert!(metrics.memory_bandwidth_util > 0.85);// Exige saturação eficiente do barramento de RAM

```

---

## Matriz Final do Workspace Corporativo

A topologia final do **Heraclitus Workspace** está formalizada, com o sistema nervoso e os contratos operacionais plenamente estabilizados, dividindo o ecossistema entre o plano de governança (Runtime) e a malha física de movimentação de dados (Executor).

| Nome Técnico do Crate | Nível de Camada | Responsabilidade Estrita do Sistema |
| --- | --- | --- |
| **`heraclitus-server`** | Interface / Driver | Orquestração do processo do nó, gRPC e listeners Arrow Flight.

 |
| **`heraclitus-query`** | Front-End Compiler | Parsing gramatical puro (`gql.pest`) e geração da AST nativa.

 |
| **`heraclitus-optimizer`** | Front-End Compiler | Passes lógicos, CBO multidimensional e máquina de estados AQE.

 |
| **`hume-ir`** | Core Contract | Representação intermediária SSA, nós-$\Phi$ e cabeçalho de versão binária.

 |
| **`hume-runtime`** | Core Engine | Alocação de `Batch`/`DataChunk`, gerenciamento de memória e pools de buffers.

 |
| **`hume-operators`** | Physical Engine | Kernels SIMD (AVX512/Neon) e operators multimodais (Vetor, Grafo, SQL).

 |
| **`heraclitus-scheduler`** | Hardcore Infrastructure | Escalonador Morsel-Driven centralizado e ciente de topologia NUMA.

 |
| **`heraclitus-storage`** | Persistence Domain | Orquestração do ciclo de vida LSM, gerenciamento de SSTables e Manifest.

 |
| **`heraclitus-log`** | Persistence Domain | Log append-only (WAL) estável para Event Sourcing transacional imutável.

 |
| **`heraclitus-observability`** | Hardcore Infrastructure | Coleta de contadores de hardware por Morsel e telemetria endógena.

 |
| **`heraclitus-bench`** | Validation System | Suite de microbenchmarking arquitetural sob contrato rígido de vitória.

 |

---

**A especificação técnica contida neste Blueprint Master está oficialmente congelada e selada. Os contratos de ABI, invariantes de compilação e regras de propriedade de memória acima descritos passam a reger de forma mandatória toda a linha viva de código do ecossistema Heraclitus.**