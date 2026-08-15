> ## Verificação de 2026-08-15 — o que mudou desde esta varredura
>
> Auditoria confirmada com greps na árvore inteira. **Todas as afirmações de
> "sem chamador" verificaram-se**: cada símbolo citado (`MappedSegment`,
> `ReplayDispatcher`, `plan_transnode_access`, `AnalyticalPlanner`,
> `HyperLogLog`, `CpmRecord`, `search_exact_gpu`, `run_sandboxed`, `Radix`,
> `top_k_u64`) aparece só no seu próprio ficheiro. Os crates órfãos
> (`heraclitus-txn`, `heraclitus-wasm`, `hume-ir`, `hume-sketches`) não têm
> dependentes. A correção sobre o `zone_map` estar ligado via `SkipScanner`
> também se confirma.
>
> **Três alterações materiais:**
>
> 1. **`compression.rs` já não está desligado.** Foi ligado ao
>    `heraclitus-index-attr` (PR #15). Reclassificar como *wired, com ganho
>    empírico pequeno no workload atual*: −83% em laboratório, **−0,3% nos
>    ficheiros reais**. O benchmark existe para impedir que algoritmos elegantes
>    sejam promovidos a religião.
>
> 2. **`partition.rs` e `topk.rs` eram mais graves do que os outros órfãos** —
>    não estavam declarados em `lib.rs`, logo não compilavam e os seus
>    `#[test]` **nunca corriam**. Não é rigoroso dizer que "possuem testes": são
>    funções marcadas `#[test]` sem autoridade operacional nenhuma. **Corrigido**
>    — declarados, compilam, e os 4 testes passam (54 → 58 no crate).
>
> 3. **O P0 `mmap.rs` foi medido e NÃO deve ser ligado.** Ver abaixo.
>
> 4. **O "segundo motor analítico" está mal classificado.** Não é P3/integração
>    arquitetural — está **bloqueado à espera de uma decisão de produto**. Ver
>    abaixo.
>
> ### O `VecExecutor` não substitui o DataFusion — porque o DataFusion não está lá
>
> O relatório diz *"a produção usa DataFusion"*. **Não usa.** Verificado:
>
> - a feature `analytics` está **desligada por omissão** (`heraclitus-server/Cargo.toml`);
> - o deploy compila sem features → `grep datafusion` no binário implantado
>   devolve **0**;
> - o caminho vivo de GQL é o `heraclitus-query`, que **não importa DataFusion
>   em lado nenhum**.
>
> O DataFusion só existe atrás do `POST /sql` opcional. Custo medido da
> dependência: **609 → 1.418 nós** (+133%) — mas **zero quando desligada**, que é
> o estado atual.
>
> Logo a decisão não é "ligar o HUME para substituir o DataFusion". É:
>
> > **É preciso o endpoint SQL de todo?**
>
> | | |
> | --- | --- |
> | **Se o diferencial é GQL + proveniência + `AS OF` + integridade** | Então *ambos* — o caminho DataFusion **e** o `VecExecutor` — são peso morto. O `heraclitus-analytics` inteiro é candidato a remoção, e o repositório fica mais honesto sobre o que é. |
> | **Se um cliente pede `SELECT`** | Manter o DataFusion. Está desligado por omissão, custa zero quando não é usado, e escrever um dialeto SQL correto (coerção de tipos, semântica de `NULL`, window functions, joins correlacionados) é o pior investimento possível para uma equipa pequena. |
> | **Se um contrato proíbe dependência estrangeira E exige SQL** | Aí sim, construir o motor próprio. Deixa de ser otimização e passa a ser **requisito** — e as 1.605 linhas de `planner.rs` + `vectorized.rs` passam de dívida a ativo. |
>
> Dois argumentos a favor do motor próprio que o relatório original não regista,
> e que só valem no terceiro cenário:
>
> - **Soberania.** 809 crates de terceiros no caminho de consulta é superfície de
>   cadeia de suprimentos que alguém terá de justificar num órgão público — e o
>   README já vende uma "Sovereignty Layer".
> - **Determinismo, que é a tese do produto.** Um otimizador de terceiros escolhe
>   planos diferentes entre versões: a mesma consulta, o mesmo dado, plano
>   diferente depois de um `cargo update`. Num sistema que vende *replay
>   determinístico*, "a mesma pergunta produz a mesma execução, sempre" é
>   propriedade vendável — e o DataFusion não a garante.
>
> **Ganho hoje: zero.** Não há nada a ganhar em substituir uma dependência que
> não está compilada. O ganho exige as três condições em simultâneo.
>
> ### CPM / CRF v2 — medido, e a conclusão não é a esperada
>
> Primeiro, a correção: o **CRC-32C do CPM-200 já fez cutover** — está no v5 do
> `format.rs:175`. O que falta é só o *layout* do registo, não "um novo formato
> de storage inteiro". O comentário do próprio `cpm.rs` ("keeps writing
> FORMAT_VERSION 4") está desatualizado.
>
> Custo medido (`benches/crf_v2_overhead.rs`):
>
> ```text
> cabecalho v5 atual : 24 B      LOG REAL: 190 registos, media 2791 B/registo
> prefixo fixo CRF v2: 64 B      inchaco: 1.4%   (5.44 GB a 136M eventos)
> ```
>
> **O custo é modesto** — 1,4%, porque os registos reais são grandes (os
> embeddings pesam). A minha suposição inicial de que +40 B seria proibitivo
> estava errada.
>
> O problema é o outro lado. Dos campos que o CRF v2 acrescenta ao prefixo fixo:
>
> | Campo | Neste modelo de dados |
> | --- | --- |
> | `event_id[16]` | hoje no payload bincode — **ganho real** |
> | `lsn`, `hlc` | **já** no cabeçalho v5 — ganho zero |
> | `knowledge_ver` | conceito do Fato Operacional do Forge — **sem fonte** |
> | `ontology_ver` | idem — **sem fonte** |
> | `confidence_raw` | idem — **sem fonte** |
> | `flags`, TLV | extensibilidade futura — por usar |
>
> O CRF v2 foi desenhado para o **Fato Operacional do Forge**, não para o
> `Episode` do HeraclitusDB. Três dos campos fixos ficariam permanentemente a
> zero.
>
> ### RETRATAÇÃO — o "achado" do `provenance` não se sustenta
>
> Publiquei aqui que o `provenance()` varria o log inteiro em produção. **Estava
> errado**, e a verificação seguinte desmontou-o.
>
> O varrimento existe, em `heraclitus-query/src/backend.rs:1422` — mas o
> `LogBackend` é a **implementação de REFERÊNCIA**, usada só em testes (os
> próprios comentários do engine lhe chamam isso: *"capado como o LogBackend de
> referência"*). O único `use ... LogBackend` fora do crate está dentro de um
> `mod tests`.
>
> **O caminho vivo já usa o índice.** O `Engine::provenance`
> (`heraclitus-server/src/engine.rs:1372`) resolve por
> `GraphIndex::parents(&eid)` — um lookup de hash:
>
> ```rust
> Ok(eid) => Ok(self.graph.lock().unwrap().parents(&eid)
>     .into_iter().map(|p| p.to_string()).collect()),
> ```
>
> Não há O(N) em produção, e otimizar a referência tornaria-a menos óbvia sem
> acelerar nada. Ficou uma nota no próprio método a dizer isto, para o próximo
> leitor não repetir o erro.
>
> **O que isto ensina sobre auditar por grep:** encontrar um padrão mau num
> ficheiro não prova que ele corra. Foi o mesmo erro do relatório original ao
> dizer que "a produção usa DataFusion" — o símbolo existia, o caminho não. A
> pergunta que faltava nos dois casos é a mesma: *quem chama isto em produção?*
>
> ### Conclusão sobre o CPM / CRF v2
>
> Sem o "achado" do `provenance`, o único ganho real que restava ao cutover
> (`event_id` em offset fixo) fica **sem consumidor conhecido**. O custo medido é
> modesto — 1,4% — mas continua a não haver razão para o pagar.
>
> **Recomendação: não fazer o cutover.** O que mudaria a resposta: se o Forge e o
> HeraclitusDB convergirem num único formato de registo — que o trabalho da ponte
> torna plausível — o CRF v2 é exatamente esse formato. Hoje não há razão.

> Nota metodológica: o SHA `b0699275` não existe neste repositório — os merges
> com `--rebase` reescrevem hashes. Esta verificação foi feita em `cbe656c`.
>
> ### `mmap.rs` — medido, e o resultado inverte a recomendação
>
> Novo benchmark `crates/heraclitus-log/benches/mmap_vs_read.rs`. Compara os dois
> caminhos ao **mesmo nível** (extração do payload cru, tocando nos bytes dos
> dois lados) e mede o mmap em duas variantes: mapeando a cada varredura, e com
> o mapa **reutilizado** (o uso realista de um segmento selado, que é imutável).
>
> ```text
> registos pequenos  200000x   64B | read  18.4ms | mmap+open 0.66x | reutilizado 0.87x
> registos medios     50000x 1024B | read  19.7ms | mmap+open 0.20x | reutilizado 0.24x
> registos grandes     5000x16384B | read  33.3ms | mmap+open 0.20x | reutilizado 0.26x
> segmento pequeno     1000x  256B | read 132.1us | mmap+open 0.30x | reutilizado 0.37x
> ```
>
> **O mmap perde em todas as configurações**, mesmo com o mapa reutilizado — e
> perde mais quanto maiores os registos, porque há mais páginas a faltar. O
> `BufReader` beneficia do read-ahead sequencial do kernel; o mmap paga uma falta
> suave por página.
>
> **Recomendação: não ligar.** Nesta plataforma seria uma regressão.
>
> Ressalvas honestas, porque o resultado é específico:
>
> - **É Windows.** No Linux o custo de falta de página é menor e existem os
>   `madvise` (`MADV_SEQUENTIAL`, `MADV_HUGEPAGE`) que o próprio `mmap.rs`
>   documenta como deliberadamente **não implementados**. O módulo está a correr
>   sem a afinação que a sua própria spec prevê.
> - **Cache quente apenas.** Esvaziar o page cache de forma fiável exige
>   privilégios do SO.
> - Isto mede varredura **sequencial completa**. O mmap pode ganhar em acesso
>   **parcial/aleatório** a um segmento grande — que não é o padrão do scan atual.
>
> O `mmap.rs` continua correto e testado; o que a medição diz é que **não ataca
> um custo que apareça no perfil atual**. Fica como referência, com o benchmark
> ao lado para quem quiser refazer a pergunta noutra plataforma.

Sim. Fiz uma auditoria de **wiring**, não apenas uma busca por `TODO`. Varri a árvore Rust do `main` no commit `b0699275...`, procurei declarações explícitas de “reference/not wired/caminho vivo” e, principalmente, confrontei isso com **call sites reais**. Isso é importante porque alguns comentários já estão velhos. `zone_map.rs`, por exemplo, parece dizer “falta ligar”, mas hoje já está efetivamente ligado por `SkipScanner` ao backend. Humanos deixam comentários arqueológicos; o compilador, felizmente, é menos sentimental.

## Resultado geral

Encontrei **13 blocos relevantes de funcionalidade implementada que ainda estão desligados, órfãos ou apenas parcialmente ligados**.

| Estado | Arquivo / subsistema                                | O que já existe                                            | O que falta ligar                                       |
| ------ | --------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------- |
| 🔴     | `hume-kernel/src/compression.rs`                    | RLE, Delta, Frame-of-Reference, BitPacking                 | Storage real                                            |
| 🔴     | `hume-kernel/src/partition.rs`                      | Radix partition cache-aware                                | Nem está declarado em `lib.rs`; hash join real          |
| 🔴     | `hume-kernel/src/topk.rs`                           | Top-K O(N log K)                                           | Nem está declarado em `lib.rs`; ORDER BY/LIMIT real     |
| 🔴     | `hume-kernel` físico                                | `DataChunk`, `Vector`, `ValidityMask`, arena, buffers SIMD | Query engine vivo                                       |
| 🟠     | `selection.rs` + `morsel.rs`                        | seleção esparsa, zero-skipping, morsels adaptativos        | Só entram no executor experimental                      |
| 🔴     | `heraclitus-analytics/planner.rs` + `vectorized.rs` | Planner + optimizer + executor vetorizado completo         | HTTP/SQL/query vivo                                     |
| 🔴     | `hume-ir`                                           | SSA IR, interpreter, otimizações, JIT Cranelift            | Query compiler vivo                                     |
| 🔴     | `hume-sketches`                                     | HyperLogLog + Count-Min                                    | CBO/estatísticas reais                                  |
| 🔴     | `heraclitus-txn`                                    | MVCC/snapshots/manager/watermark                           | Nenhum crate depende dele                               |
| 🔴     | Plugin/Sandbox/WASM                                 | PluginHost + sandbox + Wasmtime                            | Dispatch de operadores reais                            |
| 🔴     | `heraclitus-log/src/cpm.rs`                         | Novo formato físico CRF/CRC32C/TLV/Merkle                  | Writer/reader do log                                    |
| 🔴     | `heraclitus-log/src/mmap.rs`                        | Leitura zero-copy via mmap                                 | Scan/query real                                         |
| 🔴     | `heraclitus-core/src/numa.rs`                       | Política NUMA                                              | Scheduler/alocador/runtime                              |
| 🔴     | `heraclitus-core/src/dispatcher.rs`                 | Dispatcher determinístico de replay                        | Replay/views reais                                      |
| 🟠     | GPU exact-search                                    | GPU product-manifold + CPU rescore                         | Método existe no índice, mas não tem caller de produção |
| 🟠     | Raft v0 legado                                      | Log shipping/follower                                      | Deliberadamente substituído pelo OpenRaft               |

### 1. `compression.rs`: **implementado e desligado**

É exatamente o caso que iniciou essa investigação.

Você possui:

```text
RLE
Delta Encoding
Frame of Reference
BitPacking
```

inclusive com roundtrip e testes. O próprio módulo diz que essas primitivas **não estão ligadas ao storage vivo**.

E o teste de FOR + BitPacking demonstra compressão de aproximadamente **64 bits → 6 bits por valor**, chegando a mais de 10× menos palavras armazenadas naquele cenário.

Hoje:

```text
Log/storage
    │
    ├── NÃO → compression.rs
    │
    └── formato atual
```

O ganho potencial aqui é real porque você já escreveu a parte algorítmica. Falta codec metadata, escolha do codec na escrita, armazenamento comprimido e decode no scan.

---

## 2. `partition.rs`: mais desligado que `compression.rs`

`hume-kernel/src/partition.rs` implementa **radix partitioning para hash joins cache-aware**:

```text
hashes
  ↓
histograma
  ↓
prefix sum
  ↓
scatter
  ↓
partições contíguas
```

O objetivo é manter as partições do hash join dentro de L2/L3. A implementação e os testes existem.

Só que encontrei uma coisa ainda mais forte: a busca por `Radix::build` só retorna o próprio arquivo.

E pior: `hume-kernel/src/lib.rs` declara:

```rust
pub mod arena;
pub mod chunk;
pub mod compression;
pub mod memory;
pub mod morsel;
pub mod selection;
pub mod validity;
pub mod vector;
```

**`partition` nem aparece.**

Portanto:

```text
partition.rs
   ↓
código existe
   ↓
testes existem no arquivo
   ↓
NÃO faz parte da árvore de módulos do crate
```

Esse é um achado importante.

---

## 3. `topk.rs`: mesma situação

Você também implementou:

```rust
pub fn top_k_u64(data: &[u64], k: usize) -> Vec<u64>
```

usando heap parcial:

```text
ORDER BY completo:
O(N log N)

seu Top-K:
O(N log K)
```

A busca por `top_k_u64` só retorna `topk.rs`.

E `topk` também **não está declarado no `hume-kernel/src/lib.rs`**.

Então hoje ele nem participa do crate compilado como módulo normal.

Esse é um candidato relativamente simples de aproveitar futuramente para:

```text
ORDER BY score DESC LIMIT K
```

sem ordenar o conjunto inteiro.

---

# 4. O `hume-kernel` inteiro está em grande parte na bancada

O próprio `hume-kernel/src/lib.rs` admite:

> módulos reais e testados, mas não ligados ao caminho de query vivo.

O caminho vivo continua em DataFusion/Arrow.

Isso atinge várias coisas interessantes.

### `chunk.rs`

Você já tem uma ABI física:

```rust
DataChunk {
    columns,
    selection,
    row_ids,
    device,
}
```

com:

```text
Vector
+
SelectionVector
+
PhysicalRowId
+
CPU/GPU device
```

Mas o próprio arquivo diz explicitamente que `DataChunk` **não está ligado ao query path vivo**, que usa `RecordBatch`. Também informa que `LateFetch` para `PhysicalRowId` não existe.

### `arena.rs`

Você implementou um `ScratchAllocator` bump:

```text
aloca
aloca
aloca
...
reset()
```

com alocação temporária O(1) e reset O(1).

Mas procurar `ScratchAllocator` fora desse subsistema retorna apenas o próprio arquivo, `hume-kernel/lib.rs` e documentação.

Ou seja: seus operadores vivos ainda não usam essa arena para scratch memory.

### `memory.rs` + `vector.rs` + `validity.rs`

Você também já tem:

```text
AlignedBuffer 64 bytes
        ↓
Vector SIMD-ready
        ↓
ValidityMask bitmap u64
```

`AlignedBuffer` é uma implementação real de memória alinhada a 64 bytes.

`Vector` suporta `Int32`, `UInt64` e `Float64` em buffers alinhados.

`ValidityMask` representa 64 estados por `u64` e evita até a alocação quando todas as linhas são válidas.

São peças conectadas **entre si**, mas não substituem as estruturas Arrow do caminho vivo.

---

# 5. `SelectionVector`: implementado e parcialmente conectado

Aqui está aquela técnica que você estava lembrando anteriormente.

Ele muda dinamicamente entre:

```text
alta densidade
    ↓
Bitmap(Vec<u64>)
64 linhas / palavra

baixa densidade
    ↓
Index16 / Index32
só índices sobreviventes
```

E explicitamente evita varrer milhões de zeros.

Só que este caso é diferente do `compression.rs`.

`SelectionVector` **tem caller** em:

```text
heraclitus-analytics/src/vectorized.rs
```

Portanto ele está ligado a alguma coisa.

O problema é que **`vectorized.rs` inteiro não está no caminho vivo**.

Resultado:

```text
SelectionVector
      ↓
está wired
      ↓
VecExecutor
      ↓
NÃO está wired
      ↓
produção
```

Então classifico como **parcialmente ligado**.

---

# 6. `morsel.rs`: outra otimização pronta, mas presa no caminho experimental

Você implementou dimensionamento adaptativo:

```text
8.192
32.768
65.536
131.072 linhas
```

com escolha baseada em cache e ajuste por cache-miss rate.

Existe inclusive:

```rust
MorselSizer::fit()
MorselSizer::observe()
PipelineProfiler
```

`MorselSizer` chegou a ser usado pelo executor vetorizado experimental.

Mas o `PipelineProfiler`, especialmente a adaptação dinâmica baseada em falhas reais de cache, não está conectado a `perf_event_open` nem ao motor vivo.

Portanto:

```text
algoritmo adaptativo      ✅
testes                    ✅
uso parcial em I&D        ✅
feedback hardware real    ❌
query engine vivo         ❌
```

---

# 7. Você praticamente tem um segundo motor analítico pronto

Esse foi um dos maiores achados.

Existem:

```text
heraclitus-analytics/src/planner.rs
heraclitus-analytics/src/vectorized.rs
```

O primeiro implementa:

```text
query string
   ↓
AnalyticalPlanner
   ↓
LogicalPlan
```

Depois:

```text
SelectivityOptimizer
   ↓
PhysicalIr DAG
```

E finalmente:

```text
VecExecutor
   ↓
Arrow batches
```

É um pipeline completo:

```text
texto
 ↓
Planner
 ↓
Optimizer
 ↓
Executor
```

Mas o próprio arquivo diz:

> `AnalyticalPlanner`/`run_analytical` não têm caller de produção.

O caminho vivo é:

```text
POST /sql
   ↓
LogAnalytics
   ↓
DataFusion
```

E a busca por `run_analytical` confirma que ele fica restrito ao próprio subsistema/documentação.

Isso significa que você tem uma quantidade considerável de otimização própria pronta:

```text
selectivity ordering
fused filters
sparse retain
late materialization
parallel batches
adaptive morsels
SelectionVector
```

mas **a produção usa DataFusion**.

Esse é provavelmente o maior “bloco de tecnologia pronta mas não promovida” do repo.

---

# 8. `hume-ir`: compilador próprio existe, mas não alimenta consultas reais

Outro bloco grande.

Você já tem:

```text
SSA IR
Builder
verifier
interpreter
constant folding
dead-code elimination
Cranelift JIT
```

A IR está implementada e testada.

Os passes também são reais:

```rust
constant_fold()
dead_code_elimination()
optimize()
```

E existe um **JIT Cranelift real**:

```rust
pub struct JitFilter
```

que gera código de máquina e escreve uma máscara de sobrevivência.

O `Cargo.toml` confirma que ele é feature-gated por:

```toml
[features]
jit = [...]
```

e possui benchmark interpreter vs JIT.

Mas procurar `hume_ir` no restante do repo praticamente leva apenas ao benchmark do próprio crate.

Então você possui:

```text
Query real
    X
    │
 HUME-IR
    ↓
optimize
    ↓
JIT
```

Essa ponte ainda não existe.

Nota importante: o comentário de `hume-ir/src/lib.rs` dizendo que Cranelift “não está construído” está **desatualizado**, porque `jit.rs` e a feature `jit` existem de fato. Código ganha de comentário novamente.

---

# 9. `hume-sketches`: estatísticas probabilísticas prontas, CBO não usa

Este crate implementa de verdade:

```text
HyperLogLog
    → cardinalidade / NDV

Count-Min Sketch
    → frequência / heavy hitters
```

com testes de precisão e merge.

Só que o cabeçalho já avisa:

> “primitivas de referência, não estão ligadas ao CBO vivo.”

A busca por `HyperLogLog` confirma que não há consumidor operacional fora do próprio crate/spec.

Isso significa que seu otimizador poderia conhecer melhor:

```text
NDV
frequência
heavy hitters
seletividade
cardinalidade estimada
```

mas hoje esses sketches não alimentam as decisões reais.

---

# 10. `heraclitus-txn`: um crate inteiro órfão

Aqui não há ambiguidade.

O próprio arquivo declara:

> **“REFERÊNCIA DE I&D — NÃO LIGADO AO CAMINHO VIVO”**

e:

> **“Nenhum crate depende deste.”**

Você implementou:

```text
Snapshot
TxnManager
begin_snapshot
begin_with
read_at
compare_and_append
TransactionSnapshot
SnapshotManager
watermark
catalog epoch
refcount de snapshots
```

Tudo isso existe.

Mas a funcionalidade temporal que realmente está ativa usa:

```text
as_of: Option<Lsn>
```

diretamente no query backend.

Portanto `heraclitus-txn` é uma implementação paralela que ficou deliberadamente fora da produção.

Também existe em `heraclitus-core/src/consistency.rs` o enum:

```rust
IsolationLevel
```

mas o próprio arquivo explica que seu único consumidor é justamente o crate órfão `heraclitus-txn`; o live path usa `Option<Lsn>`.

---

# 11. Plugins: três camadas prontas, nenhuma executada pelo query engine

Aqui temos:

```text
heraclitus-core/src/plugin.rs
heraclitus-core/src/sandbox.rs
heraclitus-wasm/src/lib.rs
```

### `plugin.rs`

Já existe:

```text
HeraclitusPlugin
PluginHost
RegistryCatalog
version handshake
capabilities
```

Mas o próprio código diz:

> “reference contract, not wired”

e explica que o host apenas **cataloga nomes**, sem executar operadores registrados.

### `sandbox.rs`

Existe um sandbox de panic real:

```rust
run_sandboxed(...)
```

Mas o próprio comentário é ainda mais explícito:

> **“reference — 0 callers.”**

### `heraclitus-wasm`

Aqui você foi bem mais longe.

Já existe Wasmtime real com:

```text
memory isolation
fuel metering
trap containment
memory limits
WasmPlugin
WasmPluginAdapter
```

Tudo testado.

Só que o cabeçalho diz:

> **“NÃO LIGADO AO CAMINHO VIVO”**

e:

> **“Nenhum crate depende deste.”**

Ou seja:

```text
WASM sandbox       ✅
Plugin ABI         ✅
Registry           ✅
segurança          ✅

Query → plugin     ❌
Executor → plugin  ❌
GQL → UDF          ❌
```

---

# 12. `heraclitus-log/src/cpm.rs`: novo formato de storage inteiro esperando cutover

Esse é outro achado grande.

`cpm.rs` implementa um formato físico mais sofisticado:

```text
Canonical Record Format v2
CRC32C Castagnoli
TLV metadata
little-endian canonical
flags
Merkle leaf BLAKE3
forward-compatible metadata
```

O próprio arquivo é cristalino:

> **“does not touch the live format write/read path”**

e diz que o log continua usando o formato atual até um cutover deliberado.

A busca por `CpmRecord` retorna só o próprio `cpm.rs`.

Então:

```text
novo codec CPM        ✅
encode/decode          ✅
CRC32C                 ✅
TLV                    ✅
Merkle                 ✅

Log::append            ❌
Recovery               ❌
scan                    ❌
```

É extremamente parecido estruturalmente com `compression.rs`: tecnologia pronta esperando wiring no storage.

---

# 13. `mmap.rs`: zero-copy real, não usado pelo scan

Você implementou:

```rust
MappedSegment
```

que faz:

```text
sealed .hrkl
   ↓
mmap read-only
   ↓
page cache
   ↓
payload &[u8]
sem cópia por registro
```

Mas procurar `MappedSegment` no repo retorna **apenas `mmap.rs`**.

Então hoje o mecanismo zero-copy existe, mas o scan normal não o utiliza.

Esse merece bastante atenção porque está muito mais perto de virar otimização operacional do que reescrever o motor inteiro.

---

# 14. NUMA: política implementada, runtime não usa

`heraclitus-core/src/numa.rs` possui:

```rust
NumaTopology
TransnodeStrategy
plan_transnode_access()
```

e consegue decidir:

```text
mesmo nó       → Local
objeto pequeno → Replicate
objeto grande  → RecompileLocal
```

Mas a busca por:

```rust
plan_transnode_access
```

só retorna o próprio arquivo.

Além disso, `NumaTopology::detect()` atualmente retorna conservadoramente:

```rust
nodes: 1
```

Portanto há **política NUMA**, mas não há ainda:

```text
detecção real
node-local allocation
thread → NUMA affinity
scheduler NUMA-aware
```

---

# 15. `ReplayDispatcher`: implementado, 0 integração

`heraclitus-core/src/dispatcher.rs` implementa:

```text
ReplayDispatcher
   ↓
ReplaySink A
   ↓
ReplaySink B
   ↓
ReplaySink C
```

com ordem determinística e abort-on-error.

Mas a busca por `ReplayDispatcher` retorna só:

```text
heraclitus-core/src/dispatcher.rs
```

Então é outra infraestrutura real e testada que não governa o replay vivo.

---

# 16. GPU: caso diferente, parcialmente conectado

Aqui eu **não classificaria como desligado da mesma forma que `compression.rs`**.

Existe no `VectorIndex`:

```rust
pub fn search_exact_gpu(...)
```

e ele realmente chama:

```rust
heraclitus_gpu::topm_product(...)
```

seguido de CPU rescore exato.

Então:

```text
heraclitus-gpu
      ↓
VectorIndex::search_exact_gpu
```

está conectado.

Porém a busca por `search_exact_gpu` só encontra:

```text
heraclitus-index-vector/src/lib.rs
Cargo.toml
```

não um handler/query/backend chamando esse método.

Logo:

```text
GPU → VectorIndex       ✅
Query → GPU exact      ❌
```

**Parcialmente wired.**

Isso é bem diferente de eu chamar a GPU de “não implementada”. Ela está implementada e integrada ao índice; falta expor/selecionar esse caminho acima dele.

---

# 17. Raft: existe código desligado, mas é legado deliberado

Em `heraclitus-raft/src/lib.rs`, o código antigo de:

```text
LogTransport
LocalTransport
Follower
sync_once
sync_until_head
```

continua presente e testado.

Mas o próprio arquivo marca todo esse bloco como:

> **LEGADO v0**

e:

> **“NENHUM caminho vivo a usa.”**

Isso **não significa que replicação esteja faltando**. O mesmo arquivo informa que a implementação nova baseada em OpenRaft fica sob a feature `replication`.

Então o v0 é código deliberadamente aposentado, não uma otimização esperando wiring.

---

# O que eu considero mais valioso ligar

A análise muda bastante quando se olha tudo junto. Você não tem simplesmente “um `compression.rs` esquecido”. Você tem uma **camada física HUME inteira parcialmente construída e isolada do motor vivo**.

Minha ordem de valor técnico seria:

| Prioridade          | Integração                                | Motivo                                                         |
| ------------------- | ----------------------------------------- | -------------------------------------------------------------- |
| **P0**              | `compression.rs` → storage                | Já implementado, impacto direto em memória/I/O/cache           |
| **P0**              | `mmap.rs` → sealed-segment scan           | Zero-copy já pronto, integração relativamente localizada       |
| **P1**              | `hume-sketches` → CBO                     | Melhora decisões sem substituir DataFusion                     |
| **P1**              | GPU exact → query/vector backend          | Implementação já chega até `VectorIndex`                       |
| **P1**              | `topk.rs`                                 | Pequeno, simples, pode evitar sort completo em caminho próprio |
| **P1/P2**           | Radix `partition.rs`                      | Muito útil se houver hash join próprio                         |
| **P2**              | `SelectionVector`/sparse paths            | Excelente, mas exige usar mais do executor HUME                |
| **P2**              | ScratchAllocator/aligned Vector/DataChunk | Benefício quando o HUME físico assumir execução                |
| **P2**              | HUME-IR + JIT                             | Potencial alto, integração arquitetural bem maior              |
| **P3**              | Planner + VecExecutor próprio             | Na prática concorre com DataFusion, decisão arquitetural       |
| **P3**              | NUMA                                      | Só vale depois de benchmark/multi-socket real                  |
| **P4**              | Plugins/WASM                              | Intencionalmente congelado por decisão arquitetural            |
| **Não promover**    | Raft v0 legado                            | Já substituído                                                 |
| **Requer migração** | CPM                                       | Excelente tecnologia, mas muda formato persistente             |

## A conclusão mais importante

Hoje a arquitetura está mais ou menos assim:

```text
                 ┌──────────────────────────────┐
                 │       CAMINHO VIVO           │
                 │                              │
request          │ DataFusion / Arrow           │
   ─────────────▶│ QueryBackend                 │
                 │ Log / Views / Indexes        │
                 │ HNSW                         │
                 │ SkipScanner / ZoneMap        │
                 └──────────────────────────────┘
                              │
                    várias pontes faltam
                              │
                 ┌──────────────────────────────┐
                 │   TECNOLOGIA JÁ CONSTRUÍDA   │
                 │                              │
                 │ Compression                  │
                 │ mmap zero-copy               │
                 │ DataChunk                    │
                 │ SelectionVector              │
                 │ Adaptive Morsels             │
                 │ Radix Partition              │
                 │ Top-K                        │
                 │ ScratchAllocator             │
                 │ SIMD-aligned Vector          │
                 │ HUME-IR                      │
                 │ Cranelift JIT                │
                 │ HLL / Count-Min              │
                 │ VecExecutor                  │
                 │ AnalyticalPlanner            │
                 │ NUMA policy                  │
                 │ CPM codec                    │
                 │ Plugin/WASM                  │
                 └──────────────────────────────┘
```

Então **sim, existe bastante performance potencial já escrita que a execução normal ainda não está usando**.

E há uma distinção especialmente importante:

**`compression.rs`, `mmap.rs`, sketches e GPU são candidatos a serem incorporados incrementalmente ao sistema atual.**

Já **DataChunk + SelectionVector + Morsel + HUME-IR + JIT + VecExecutor** formam praticamente **um segundo motor físico de execução**. Ligá-los não é uma pequena otimização. É começar a fazer o HUME assumir trabalho que hoje está delegado ao DataFusion/Arrow.

Esse é o verdadeiro quadro arquitetural que a varredura revela.

Porque parei aqui

O que sobra divide-se em três categorias, e nenhuma se resolve com mais uma tarde:

1. Não é otimização, é arquitetura. DataChunk + SelectionVector + Morsel + hume-ir + JIT + VecExecutor são, como o próprio documento diz, um segundo motor físico de execução. Ligá-los é começar a substituir o DataFusion. Isso é uma decisão tua sobre o produto, não um wiring.

2. Muda formato persistente. O cpm.rs implementa um CRF v2 completo para o log. É outra categoria de risco — precisa de migração e cutover, como a cifra precisou.

3. Baratos mas provavelmente inúteis. O ReplayDispatcher e o numa.rs ligam-se em pouco tempo. Mas o NUMA devolve nodes: 1 nesta máquina e o dispatcher governa um replay que já funciona. Ligá-los daria trabalho sem número para mostrar — exatamente o padrão que os três filtros de hoje existiram para evitar.

O hume-sketches já expliquei: alimentaria um otimizador de custos que hoje é do DataFusion, e o único nosso (predicted_access_path) já é adaptativo por medição real. Trocar medição por estimativa não me parece ganho.

O que eu faria a seguir

Nada disto, ainda. Os três filtros de hoje custaram poucas horas e devolveram: um ganho pequeno, uma recusa fundamentada e um defeito latente corrigido. Isso é um bom retorno — mas todos mediram cargas sintéticas.

O compression deu 83% em laboratório e 0,3% real. Antes de ligar mais alguma coisa, vale mais saber qual é o perfil de custo verdadeiro — e isso só vem do piloto.
