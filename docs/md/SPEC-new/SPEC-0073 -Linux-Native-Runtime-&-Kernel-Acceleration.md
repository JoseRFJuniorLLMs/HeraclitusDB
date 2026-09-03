# SPEC-0073 — Linux Native Runtime & Kernel Acceleration

**Status:** Proposed
**Prioridade:** P0 / Arquitetural
**Escopo:** HeraclitusDB Production Runtime
**Plataforma Tier 1:** Linux x86_64 e Linux aarch64
**Compatibilidade secundária:** Windows x86_64 best-effort
**Dependências conceituais:** SPEC-0033, SPEC-0038, SPEC-0039, SPEC-0043, SPEC-0049, SPEC-0050, SPEC-0072
**Princípio central:** Linux-native, benchmark-driven, durability-preserving.

---

# 0. Decisão arquitetural

O HeraclitusDB SHALL adotar **Linux como plataforma oficial de produção, qualificação, desempenho e operação**.

O objetivo desta SPEC não é simplesmente fazer o código "compilar em Linux". O projeto já possui capacidade de compilação e testes em Linux.

O objetivo é transformar o runtime em:

> **um banco de dados nativamente otimizado para o kernel Linux, mantendo as semânticas canônicas do HeraclitusDB desacopladas das implementações específicas do sistema operacional.**

A política de plataforma passa a ser:

| Plataforma     | Classificação | Compilação | Testes | Performance | Produção homologada |
| -------------- | ------------- | ---------: | -----: | ----------: | ------------------: |
| Linux x86_64   | Tier 1        |       MUST |   MUST |        MUST |                MUST |
| Linux aarch64  | Tier 1        |       MUST |   MUST |        MUST |                MUST |
| Windows x86_64 | Tier 3        |     SHOULD | SHOULD |         NÃO |                 NÃO |
| macOS          | Dev only      |        MAY |    MAY |         NÃO |                 NÃO |
| Outros Unix    | Best effort   |        MAY |    NÃO |         NÃO |                 NÃO |

Windows não deve bloquear nenhuma otimização Linux Tier 1.

Entretanto, nenhum componente canônico de:

* formato HRKL;
* replay;
* LSN;
* HLC;
* transações;
* Raft;
* checkpoints;
* integridade;
* determinismo;
* recuperação;

poderá depender semanticamente de Linux.

---

# 1. Objetivos

Esta SPEC MUST:

1. criar uma camada explícita de abstração de plataforma;
2. introduzir fast paths específicos para Linux;
3. qualificar `io_uring` como possível backend do WAL;
4. introduzir políticas reais de `madvise`;
5. implementar topologia NUMA real;
6. expandir CPU affinity;
7. qualificar allocator otimizado;
8. otimizar networking gRPC/Raft;
9. formalizar dispatch SIMD x86_64/aarch64;
10. criar runtime oficial systemd;
11. detectar limites de cgroups v2;
12. introduzir profiling Linux sistemático;
13. transformar o CI Linux de "compila" para "executa e sobrevive";
14. criar gates objetivos de benchmark;
15. preservar completamente durabilidade e recovery.

---

# 2. Não objetivos

Esta SPEC SHALL NOT:

* remover imediatamente suporte de compilação Windows;
* espalhar chamadas `libc` pelo workspace;
* substituir algoritmos corretos por lock-free sem prova;
* ativar `O_DIRECT` indiscriminadamente;
* assumir que `mmap` é mais rápido que `read`;
* assumir que `io_uring` é mais rápido que o writer atual;
* compilar releases portáveis exclusivamente com `target-cpu=native`;
* ativar AVX-512 sem runtime dispatch;
* desabilitar `fsync`;
* enfraquecer `overflow-checks`;
* alterar formato HRKL;
* alterar semântica de LSN;
* alterar propriedades de deterministic replay;
* alterar garantia de acknowledged durability.

---

# 3. Invariantes inegociáveis

## I-1 — Canonicalidade

O log HRKL continua sendo a única fonte canônica de verdade.

## I-2 — Durabilidade

Uma otimização Linux SHALL NOT permitir que um append seja reconhecido como durable antes da barreira de durabilidade exigida pela configuração atual.

Formalmente:

```text
ACK(durable)
    ⇒
bytes necessários recuperáveis após crash
```

## I-3 — Determinismo

Para o mesmo log canônico:

```text
Replay(L0..Ln)
```

MUST produzir o mesmo estado lógico independentemente de:

```text
std::fs
io_uring
mmap
pread
NUMA
jemalloc
glibc malloc
AVX2
AVX-512
NEON
SVE
```

## I-4 — Fallback

Toda otimização específica de hardware/kernel MUST possuir:

```text
capability detection
        ↓
fast path
        ↓
fallback correto
```

## I-5 — Benchmark obrigatório

Nenhum fast path SHALL tornar-se default apenas por ser teoricamente mais sofisticado.

Promoção exige:

```text
implementação
    ↓
benchmark A/B
    ↓
correctness
    ↓
crash qualification
    ↓
performance gate
    ↓
default
```

---

# 4. Camada de plataforma

Criar uma fronteira arquitetural única.

Preferência:

```text
crates/heraclitus-platform/
```

Estrutura:

```text
heraclitus-platform/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── capabilities.rs
    ├── io.rs
    ├── memory.rs
    ├── network.rs
    ├── cpu.rs
    ├── numa.rs
    ├── process.rs
    ├── portable/
    │   ├── io.rs
    │   ├── memory.rs
    │   └── network.rs
    └── linux/
        ├── io.rs
        ├── uring.rs
        ├── mmap.rs
        ├── numa.rs
        ├── network.rs
        ├── cgroup.rs
        ├── process.rs
        └── telemetry.rs
```

Alternativamente, caso uma nova crate gere dependência circular, a camada MAY viver em:

```text
heraclitus-core::platform
```

A decisão deverá minimizar dependências ascendentes.

---

# 5. Regra contra `libc` dispersa

Código como:

```rust
unsafe {
    libc::madvise(...);
}
```

SHALL NOT aparecer arbitrariamente em:

```text
heraclitus-sentinel
heraclitus-query
heraclitus-index-vector
heraclitus-server
heraclitus-tier
```

A chamada deve ser encapsulada:

```rust
platform::memory::advise(...)
```

ou equivalente.

Todo bloco `unsafe` introduzido nesta SPEC MUST possuir comentário:

```text
SAFETY:
- pré-condições;
- lifetime;
- alinhamento;
- ownership;
- motivo pelo qual é seguro.
```

---

# 6. Capability Catalog Linux

Expandir o catálogo existente para refletir recursos reais.

Exemplo conceitual:

```rust
pub struct LinuxCapabilities {
    pub kernel_version: KernelVersion,

    pub io_uring: bool,
    pub io_uring_fast_poll: bool,
    pub io_uring_sqpoll_permitted: bool,

    pub numa_nodes: usize,
    pub physical_cpus: usize,
    pub logical_cpus: usize,

    pub transparent_hugepages: HugePageState,

    pub avx2: bool,
    pub fma: bool,
    pub avx512f: bool,

    pub neon: bool,
    pub sve: bool,

    pub cgroup_v2: bool,

    pub reuseport: bool,
}
```

Startup MUST registrar:

```text
platform=linux
kernel=...
arch=x86_64|aarch64

io_uring=true|false

numa_nodes=N

simd=scalar|avx2|avx512|neon|sve

allocator=glibc|jemalloc|...

cgroup_v2=true|false
```

Sem transformar o boot num desfile de 300 linhas de log.

---

# 7. Backend de I/O do log

O atual writer SHALL permanecer como baseline.

Criar contrato interno equivalente a:

```rust
trait LogIoBackend {
    fn append_batch(...);
    fn sync(...);
    fn truncate(...);
    fn read_at(...);
}
```

Backends:

```text
PortableFileIo
LinuxUringIo
```

Inicialmente:

```text
PortableFileIo = default
LinuxUringIo    = experimental
```

---

# 8. Backend `io_uring`

Implementar um backend Linux de `io_uring` sem alterar a semântica pública do `Log`.

A implementação SHOULD explorar:

* submission batching;
* completion queue batching;
* vectored writes;
* fixed/registered files quando vantajoso;
* registered buffers quando vantajoso;
* async fsync/fdatasync;
* queue depth configurável.

Não implementar inicialmente:

```text
SQPOLL
IOPOLL
busy polling agressivo
```

Esses recursos ficam atrás de benchmark adicional.

---

# 9. Semântica de durability no `io_uring`

O backend MUST preservar exatamente a relação:

```text
write submitted
      ↓
write completed
      ↓
durability barrier completed
      ↓
committed/durable LSN publicado
      ↓
client ACK
```

É proibido:

```text
submit fsync
     ↓
ACK
     ↓
completion chega depois
```

O completion da barreira de durabilidade MUST acontecer antes da publicação do estado durable.

---

# 10. Benchmark obrigatório do `io_uring`

Comparar:

```text
PortableFileIo
versus
LinuxUringIo
```

Matrix mínima:

### Queue depth

```text
1
4
16
32
64
```

### Payload

```text
256 B
1 KiB
4 KiB
16 KiB
64 KiB
```

### Concorrência

```text
1
4
16
64
```

### Durability

```text
no-sync
group-commit
sync-per-batch
strict
```

Medir:

```text
events/s
MiB/s

p50
p95
p99
p99.9

CPU/event
syscalls/event
context-switch/event

fsync latency

RSS

recovery time
```

---

# 11. Gate para tornar `io_uring` default

`LinuxUringIo` MAY tornar-se default somente se:

```text
throughput >= baseline × 1.10
```

OU:

```text
p99 <= baseline × 0.85
```

sem regressão relevante de:

```text
durabilidade
recovery
RSS
CPU
determinismo
```

Pequenos ganhos inferiores ao ruído experimental não justificam aumentar complexidade operacional.

---

# 12. Memory-mapped I/O e `madvise`

O módulo mmap existente deve ser expandido com uma política de acesso explícita.

Criar:

```rust
enum AccessPattern {
    Sequential,
    Random,
    Immediate,
    HugeSequential,
    Default,
}
```

Mapeamento Linux sugerido:

```text
Sequential
    → MADV_SEQUENTIAL

Random
    → MADV_RANDOM

Immediate
    → MADV_WILLNEED

HugeSequential
    → MADV_SEQUENTIAL
    + MADV_HUGEPAGE
```

`MADV_POPULATE_READ` MAY ser experimental quando suportado.

---

# 13. Proibição de `WILLNEED` global

Não executar:

```text
MADV_WILLNEED
```

sobre toda a base no startup.

Isso poderia converter:

```text
startup optimization
```

em:

```text
page-cache eviction generator
```

O prefetch deve operar em janelas limitadas.

Configuração:

```toml
[linux.memory]
mmap_advice = "auto"
prefetch_window_mb = 64
```

---

# 14. Política de mmap

O fato de um segmento ser imutável não implica que mmap seja mais rápido.

Manter dois caminhos:

```text
pread/read
mmap
```

Selecionados por perfil medido.

Exemplo:

```text
sequential full scan
    → read/pread provavelmente preferível

random sparse access
    → mmap candidato forte

index probing
    → mmap + MADV_RANDOM candidato
```

A política final MUST resultar de benchmark Linux.

---

# 15. Streaming do lakehouse

Antes de `O_DIRECT`, eliminar materializações integrais do exportador.

O caminho desejado será:

```text
HRKL segment
    ↓
bounded RecordBatch
    ↓
Parquet writer
    ↓
bounded RecordBatch
    ↓
Parquet writer
    ↓
stream / multipart upload
```

Em vez de:

```text
segment
    ↓
Vec<Episode> gigante
    ↓
RecordBatch gigante
    ↓
Vec<u8> gigante
```

---

# 16. Memória limitada no export

Adicionar:

```toml
[lakehouse]
export_batch_rows = 8192
export_memory_budget_mb = 256
```

O exporter MUST obedecer budget aproximadamente constante com crescimento do segmento.

Objetivo:

```text
RAM(export)
≈ O(batch)
```

não:

```text
RAM(export)
≈ O(segment)
```

---

# 17. Digest físico streaming

Eliminar leitura integral redundante do segmento apenas para calcular digest quando possível.

Preferência:

```text
open segment
    ↓
stream records
    ↓
update physical digest
    ↓
export
```

Caso o digest físico já seja autenticado e publicado em metadata canônica apropriada, reutilizá-lo somente quando a cadeia de confiança permitir.

---

# 18. `O_DIRECT`

`O_DIRECT` não será default.

Criar backend experimental apenas para workloads bulk onde o page cache possivelmente causa double buffering.

Candidatos:

```text
cold tier
large compaction
backup
bulk export
bulk restore
```

Não usar inicialmente para:

```text
hot WAL
small random queries
metadata
manifest
cursor
checkpoint
```

---

# 19. Requisitos de `O_DIRECT`

A implementação MUST respeitar:

* alinhamento de buffer;
* alinhamento de offset;
* alinhamento de tamanho;
* filesystem constraints;
* fallback transparente.

Qualquer erro como:

```text
EINVAL
unsupported filesystem
alignment violation
```

MUST permitir fallback seguro para buffered I/O quando configurado.

---

# 20. Allocator Linux

Introduzir suporte experimental a:

```text
jemalloc
```

preferencialmente via:

```text
tikv-jemallocator
```

O allocator global deve ser configurado exclusivamente no executável servidor.

Exemplo conceitual:

```rust
#[cfg(all(
    target_os = "linux",
    feature = "linux-jemalloc"
))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc =
    tikv_jemallocator::Jemalloc;
```

Crates de biblioteca SHALL NOT definir allocator global.

---

# 21. Benchmark de allocator

Comparar:

```text
system allocator
jemalloc
```

e MAY:

```text
mimalloc
```

Cenários:

```text
write-heavy
query-heavy
mixed
Sentinel ON
HNSW ON
analytics ON
64+ concurrent clients
```

Medir:

```text
throughput
p99
RSS
peak RSS
fragmentation
resident-after-idle
CPU
allocations/s
```

jemalloc torna-se default Linux somente se houver ganho comprovado.

---

# 22. Topologia NUMA real

Substituir a detecção conservadora atual por descoberta real no Linux.

A topologia deverá identificar:

```text
NUMA node
CPU
core
socket
logical CPU
```

Exemplo:

```rust
pub struct NumaNode {
    pub id: usize,
    pub cpus: Vec<usize>,
    pub total_memory_bytes: u64,
}
```

---

# 23. CPU affinity

Expandir a afinidade já existente nos workers analíticos para pools relevantes.

Pools candidatos:

```text
query
analytics
vector search
Sentinel
background compaction
packing
Raft
WAL
```

Não aplicar pinning cego.

A política MUST permitir:

```toml
[linux.cpu]
affinity = "auto"
```

Valores:

```text
off
auto
strict
```

---

# 24. NUMA scheduling

Em host multi-NUMA:

```text
worker
    ↓
assigned NUMA node
    ↓
CPU local
    ↓
scratch/arena local
```

Deve existir preferência por execução próxima aos dados.

---

# 25. NUMA memory locality

CPU pinning sozinho não é NUMA awareness.

Implementar ou qualificar:

```text
first-touch allocation
mbind()
set_mempolicy()
```

ou camada equivalente.

Buffers grandes MAY ser node-local.

Candidatos:

```text
query scratch
analytics arenas
vector index shards
decompression buffers
large temporary buffers
```

---

# 26. Política de artefatos trans-NUMA

Preservar a política conceitual existente:

```text
small remote artifact
    → replicate local

large remote artifact
    → prefer local reconstruction

same node
    → direct
```

O threshold MUST ser parametrizável e benchmarkado.

---

# 27. Proibição de remover Mutex por estética

Nenhum `Mutex` será substituído apenas porque "lock-free é mais rápido".

Primeiro:

```text
perf
contention profiling
flamegraph
off-CPU profiling
```

Depois classificar.

---

# 28. Estratégias permitidas de concorrência

Conforme o tipo de estado:

### Contadores/watermarks

```text
AtomicU64
AtomicUsize
AtomicBool
```

### Read-mostly snapshots

```text
ArcSwap
RCU-like publication
```

### Maps altamente concorrentes

```text
sharding
DashMap
```

### State machines ordenadas

Preferir:

```text
single-owner worker
message passing
```

a espalhar mutabilidade lock-free.

---

# 29. Sentinel

Especialmente no Sentinel:

```text
cursor
behavior state
fusion state
incident state
graph state
```

não devem virar atomics genéricos.

A SPEC-0072 continua governando consistência de cursor/replay/snapshot.

Esta SPEC apenas poderá otimizar sincronização depois que:

```text
correctness
+
restart
+
snapshot
```

estiverem comprovados.

---

# 30. Networking Linux

Criar camada socket configurável usando abstração adequada, preferencialmente:

```text
socket2
```

quando Tokio/Tonic não expuserem determinada opção.

Configuração:

```toml
[network]
tcp_nodelay = true
reuse_port = "auto"
recv_buffer_bytes = 0
send_buffer_bytes = 0
```

`0` significa autotuning do kernel.

---

# 31. TCP_NODELAY

Aplicar/qualificar `TCP_NODELAY` especialmente em:

```text
Raft RPC
small control RPCs
```

Benchmark:

```text
commit latency
heartbeat latency
AppendEntries latency
p99 consensus
CPU
network packets
```

---

# 32. SO_REUSEPORT

`SO_REUSEPORT` MAY ser ativado para:

```text
public gRPC
REST
Arrow Flight
```

se benchmarks demonstrarem accept/listener contention.

Não é automaticamente prioridade para Raft.

Para Raft, `SO_REUSEPORT` só entra mediante evidência de ganho.

---

# 33. TCP buffers

Não hard-code:

```text
SO_RCVBUF = 16MB
SO_SNDBUF = 16MB
```

por superstição.

Default:

```text
kernel autotuning
```

Override apenas quando:

```text
high bandwidth
high RTT
dedicated network
benchmark evidence
```

---

# 34. SIMD runtime dispatch

Nunca depender exclusivamente de:

```text
-C target-cpu=native
```

para releases distribuídos.

Modelo oficial:

```text
scalar
   ↓
runtime detection
   ├ AVX2/FMA
   ├ AVX-512
   ├ NEON
   └ SVE
```

Toda implementação otimizada MUST produzir resultado compatível com o fallback escalar dentro das tolerâncias matemáticas formalmente definidas.

---

# 35. x86_64

Prioridade:

```text
scalar
AVX2 + FMA
AVX-512
```

AVX-512 MUST considerar:

* possível redução de clock;
* tamanho do vetor;
* workload;
* CPU concreta.

AVX-512 não será escolhido apenas porque existe.

---

# 36. aarch64

Linux ARM64 é Tier 1.

Implementar/qualificar:

```text
NEON
SVE quando disponível
```

O objetivo é suportar eficientemente:

```text
AWS Graviton
Ampere
ARM server
future sovereign appliances
```

---

# 37. Build profiles

O release portátil continuará utilizando baseline seguro.

Manter inicialmente:

```toml
[profile.release]
lto = "thin"
codegen-units = 1
overflow-checks = true
```

Fat LTO MUST passar por benchmark antes de substituir Thin LTO.

---

# 38. `target-cpu=native`

Criar perfil separado:

```text
portable
native
```

Exemplo de artefatos:

```text
heraclitus-server-linux-x86_64
heraclitus-server-linux-aarch64
```

e build local opcional:

```text
heraclitus-server-linux-native
```

O build `native` não deve ser distribuído como universal.

---

# 39. `panic = abort`

Não mudar nesta SPEC automaticamente.

`panic=abort` altera fault semantics, não apenas tamanho/performance.

A decisão pertence à qualificação da SPEC-0049.

---

# 40. Runtime oficial systemd

Criar:

```text
packaging/systemd/heraclitusdb.service
```

O runtime oficial Linux será:

```text
heraclitus-server
```

e não um wrapper paralelo equivalente ao SCM.

---

# 41. Requisitos do unit file

O unit MUST possuir política explícita para:

```text
Restart
RestartSec
TimeoutStopSec
LimitNOFILE
WorkingDirectory
EnvironmentFile
User
Group
```

Hardening SHOULD considerar:

```text
NoNewPrivileges
PrivateTmp
ProtectHome
ProtectSystem
RestrictAddressFamilies
CapabilityBoundingSet
```

sem impedir acesso legítimo a:

```text
data directory
log directory
cold tier
config
TLS material
```

---

# 42. Lifecycle Linux

Servidor MUST tratar corretamente:

```text
SIGTERM
SIGINT
```

SIGTERM:

```text
stop accepting new work
      ↓
finish bounded in-flight operations
      ↓
flush required durable state
      ↓
close background workers
      ↓
exit 0
```

---

# 43. SIGKILL

SIGKILL não permite cleanup.

Portanto:

```text
kill -9
```

deve ser tratado exclusivamente pelo recovery subsequente.

Teste obrigatório:

```text
start
append workload
SIGKILL
restart
verify canonical state
continue append
```

---

# 44. systemd watchdog

MAY ser implementado:

```text
WatchdogSec
sd_notify
```

somente após existir health model apropriado.

O watchdog SHALL NOT considerar o processo saudável apenas porque existe um PID.

---

# 45. cgroups v2

O runtime Linux MUST detectar cgroups v2.

Ao executar em container:

```text
host RAM ≠ usable RAM
host CPU ≠ usable CPU
```

Logo, memory budgets devem considerar:

```text
memory.max
memory.high
```

e CPU:

```text
cpu.max
cpuset
```

---

# 46. EffectiveResourceLimits

Criar modelo equivalente a:

```rust
pub struct EffectiveResourceLimits {
    pub memory_bytes: u64,
    pub cpu_quota: Option<f64>,
    pub allowed_cpus: Vec<usize>,
}
```

O runtime MUST preferir limites efetivos do cgroup quando mais restritivos que recursos físicos.

---

# 47. Uso dos limites

Os limites detectados devem alimentar:

```text
query memory budget
analytics workers
compaction concurrency
Sentinel buffers
cache sizing
lakehouse batches
HNSW temporary memory
```

Evitar OOMKill por assumir que toda RAM física pertence ao processo.

---

# 48. Observabilidade Linux

Criar modo de qualificação, não necessariamente ligado permanentemente, utilizando:

```text
perf
eBPF
procfs
sysfs
```

quando disponível.

---

# 49. Métricas de kernel relevantes

Durante qualification coletar:

```text
major page faults
minor page faults

context switches
CPU migrations

block I/O latency
fsync latency

TCP retransmits
socket queue pressure

scheduler latency

off-CPU time

RSS
page cache
dirty pages
```

---

# 50. Perf / flamegraph

Todo P0/P1 de performance deverá possuir evidência baseada em:

```text
CPU flamegraph
```

e, quando concorrência for suspeita:

```text
off-CPU flamegraph
```

"parece lento" não constitui profiling.

---

# 51. Configuração Linux

Adicionar seção:

```toml
[linux]
profile = "auto"

[linux.io]
backend = "auto"
queue_depth = 32

[linux.memory]
mmap_advice = "auto"
prefetch_window_mb = 64
hugepages = "auto"

[linux.cpu]
affinity = "auto"
numa = "auto"

[linux.allocator]
backend = "auto"

[linux.network]
reuse_port = "auto"
tcp_nodelay = true
```

---

# 52. Semântica de `auto`

`auto` significa:

```text
detect capability
      ↓
consult qualified policy
      ↓
choose known-safe backend
```

Não:

```text
experimentar aleatoriamente em produção.
```

---

# 53. Override operacional

Toda otimização Linux importante MUST poder ser desligada sem recompilar.

Exemplos:

```text
HERACLITUS_IO_BACKEND=portable
HERACLITUS_NUMA=off
HERACLITUS_MMAP_ADVICE=off
HERACLITUS_REUSEPORT=off
```

Isso é essencial para diagnóstico e rollback.

---

# 54. Startup telemetry

Registrar uma única linha estruturada ou pequeno conjunto:

```text
linux_runtime:
  kernel=6.x
  arch=x86_64
  io=uring
  allocator=jemalloc
  numa_nodes=2
  affinity=auto
  simd=avx2
  cgroup=v2
```

Não esconder escolha automática.

---

# 55. Windows

`heraclitus-service` passa a:

```text
Tier 3
legacy operational convenience
```

Não receberá trabalho específico de performance.

Mudanças de formato e correctness ainda devem permanecer compatíveis enquanto Windows for suportado.

---

# 56. Não remover Windows imediatamente

Nesta SPEC:

```text
Windows support SHALL NOT be deleted.
```

A prioridade apenas muda.

Isso permite:

* desenvolvimento local;
* troubleshooting;
* clientes;
* testes de portabilidade;
* redução de risco durante migração.

---

# 57. CI Linux

Expandir o CI atual com um job:

```text
linux-runtime
```

Esse job MUST executar o binário real.

---

# 58. Linux runtime smoke

Gate mínimo:

```text
build heraclitus-server
      ↓
start process
      ↓
wait readiness
      ↓
append
      ↓
query
      ↓
SIGTERM
      ↓
restart
      ↓
query persisted data
```

---

# 59. Crash CI

Adicionar:

```text
start
append
SIGKILL
restart
verify
append again
verify
```

O teste não pode usar apenas chamadas in-process se o objetivo é qualificar lifecycle do Linux.

---

# 60. Linux matrix

CI normal SHOULD cobrir:

```text
x86_64 Linux
```

CI/release adicional MUST qualificar:

```text
aarch64 Linux
```

quando infraestrutura runner estiver disponível.

Cross-compile sozinho não substitui execução real.

---

# 61. Kernel qualification

Definir kernels suportados.

Exemplo inicial:

```text
minimum supported kernel: TBD por teste
recommended production kernel: LTS moderno
```

O agente NÃO deve inventar versão mínima antes de verificar dependências reais de `io_uring`.

O backend portable deverá permitir execução em kernel Linux sem recursos modernos opcionais.

---

# 62. Máquina dedicada de benchmark

Performance oficial não deverá ser comparada através de runners compartilhados GitHub Actions.

Criar qualification host com especificação congelada:

```text
CPU
RAM
NUMA topology
NVMe
filesystem
kernel
governor
THP state
```

---

# 63. Perf environment

Registrar obrigatoriamente:

```text
uname -a
lscpu
numactl --hardware
lsblk
mount
filesystem
kernel cmdline
CPU governor
THP state
```

junto ao resultado.

---

# 64. Datasets de qualificação

Mínimo:

```text
small:
1M events

medium:
20M events

large:
100M events

soak/extreme:
1B events
```

O gate de 1B MAY ficar fora do CI diário.

---

# 65. Workloads

### W1 — append

```text
100% append
```

### W2 — read

```text
100% query
```

### W3 — mixed

```text
70% read
30% append
```

### W4 — analytics

```text
large scan/filter
```

### W5 — vector

```text
HNSW search
```

### W6 — Sentinel

```text
ingestion + security pipeline
```

### W7 — cluster

```text
3-node Raft
```

---

# 66. Métricas oficiais

Para todo benchmark relevante:

```text
throughput
p50
p95
p99
p99.9

CPU
RSS

disk read/write
IOPS

context switches
page faults

recovery time
startup time
```

---

# 67. Gate de regressão

Nenhuma otimização poderá degradar:

```text
throughput > 5%
```

ou:

```text
p99 > 10%
```

em workload crítico não relacionado sem justificativa documentada.

---

# 68. Startup

Esta SPEC MUST ser integrada à correção da SPEC-0072.

Linux optimization não justifica:

```text
scan completo no startup
```

quando snapshot + tail replay deveriam bastar.

Primeiro reduzir trabalho.

Depois acelerar o trabalho restante.

---

# 69. Princípio de prioridade

Sempre preferir:

```text
ler 1 GB mais rápido
```

a:

```text
ler 100 GB desnecessariamente de maneira extremamente otimizada.
```

Portanto:

```text
algorithmic reduction
>
I/O optimization
>
microoptimization
```

---

# 70. Crash matrix

Para cada backend de I/O:

```text
portable
io_uring
```

testar crash:

```text
antes do write
durante write
após write
antes sync
durante sync
após sync
antes ACK
após ACK
```

Verificar:

```text
no acknowledged durable record lost
no fabricated record
no invalid head
no invalid manifest publication
```

---

# 71. Power-loss qualification

Quando hardware de teste permitir:

```text
power-loss injection
VM hard-off
device fault simulation
```

deve fazer parte da SPEC-0049 combinada com esta SPEC.

---

# 72. Filesystems

Qualificação mínima SHOULD comparar:

```text
ext4
XFS
```

Outros MAY ser adicionados.

Nunca presumir que:

```text
rename
fsync
O_DIRECT
fallocate
```

possuem custo idêntico em todos filesystems.

---

# 73. Segurança

Otimizações Linux MUST preservar:

```text
file permissions
TLS
secret handling
sandbox boundaries
auditability
immutable log semantics
```

Nenhum ganho de benchmark permite desabilitar mecanismos de segurança por default.

---

# 74. Supply chain

Novas dependências como:

```text
io-uring crate
libc
socket2
jemallocator
```

MUST passar por:

```text
cargo audit
license review
dependency tree review
```

Evitar adicionar um framework enorme para executar uma única syscall.

---

# 75. Sequência de implementação

O agente SHALL executar por fases.

## Fase A — Foundation

1. criar camada platform;
2. definir capabilities;
3. adicionar Linux detection;
4. preservar fallbacks;
5. adicionar testes unitários.

Nenhuma mudança de performance default.

---

## Fase B — Memory

6. implementar `madvise`;
7. adicionar AccessPattern;
8. benchmark mmap/read;
9. criar métricas page fault/page cache.

---

## Fase C — I/O

10. criar `LogIoBackend`;
11. adaptar writer atual como PortableFileIo;
12. provar equivalência;
13. implementar LinuxUringIo;
14. executar benchmark;
15. crash qualify.

Somente depois decidir default.

---

## Fase D — Lakehouse

16. export streaming;
17. batches limitados;
18. digest streaming;
19. eliminar materializações integrais evitáveis;
20. benchmark;
21. só então experimentar `O_DIRECT`.

---

## Fase E — CPU/NUMA

22. detectar topologia;
23. integrar cpuset/cgroup;
24. expandir affinity;
25. implementar locality;
26. introduzir NUMA arenas seletivas;
27. benchmark 1-node vs 2-node.

---

## Fase F — Allocator

28. integrar jemalloc feature;
29. benchmark;
30. medir fragmentação;
31. promover somente se vencedor.

---

## Fase G — Network

32. TCP_NODELAY;
33. socket configuration;
34. SO_REUSEPORT experimental;
35. Raft benchmark;
36. public API benchmark.

---

## Fase H — SIMD

37. validar scalar;
38. AVX2/FMA;
39. AVX-512;
40. NEON;
41. SVE quando disponível;
42. runtime dispatch;
43. cross-path correctness.

---

## Fase I — Operations

44. systemd unit;
45. SIGTERM;
46. SIGKILL qualification;
47. cgroups v2;
48. Linux runtime CI;
49. aarch64 release path.

---

# 76. Arquivos a auditar

Obrigatoriamente:

```text
Cargo.toml

crates/heraclitus-core/
crates/heraclitus-log/
crates/heraclitus-log/src/mmap.rs
crates/heraclitus-log/src/v6/

crates/heraclitus-tier/
crates/heraclitus-tier/src/lakehouse/

crates/heraclitus-analytics/
crates/hume-kernel/

crates/heraclitus-index-vector/

crates/heraclitus-raft/
crates/heraclitus-raft/src/grpc.rs
crates/heraclitus-raft/src/net.rs

crates/heraclitus-server/
crates/heraclitus-server/src/bin/service.rs

crates/heraclitus-sentinel/

.github/workflows/ci.yml
```

---

# 77. Arquivos novos sugeridos

```text
crates/heraclitus-platform/
    Cargo.toml
    src/lib.rs
    src/capabilities.rs
    src/io.rs
    src/memory.rs
    src/cpu.rs
    src/network.rs
    src/linux/mod.rs
    src/linux/uring.rs
    src/linux/mmap.rs
    src/linux/numa.rs
    src/linux/network.rs
    src/linux/cgroup.rs

packaging/systemd/
    heraclitusdb.service

docs/runbooks/
    linux-production.md
    linux-performance.md
```

O agente poderá alterar a organização caso o dependency graph recomende solução melhor.

---

# 78. Testes obrigatórios

Criar testes para:

```text
platform capability detection

madvise fallback

CPU affinity

NUMA topology parser

cgroup v2 parser

socket options

portable I/O vs io_uring equivalence

io_uring crash recovery

SIGTERM restart

SIGKILL restart

allocator-independent deterministic replay

SIMD vs scalar equivalence

streaming lakehouse export

bounded lakehouse memory
```

---

# 79. Testes de equivalência

Para mesma sequência de eventos:

```text
PortableFileIo
LinuxUringIo
```

devem gerar estado lógico idêntico.

Mesmo princípio:

```text
scalar
AVX2
AVX-512
NEON
```

e:

```text
glibc allocator
jemalloc
```

---

# 80. Artefato de benchmark

Cada otimização promovida deve gerar JSON equivalente a:

```json
{
  "commit": "...",
  "kernel": "...",
  "arch": "...",
  "cpu": "...",
  "filesystem": "...",
  "backend": "...",
  "workload": "...",
  "throughput_eps": 0,
  "p50_us": 0,
  "p99_us": 0,
  "p999_us": 0,
  "rss_bytes": 0,
  "cpu_percent": 0
}
```

Resultados devem ser comparáveis entre commits.

---

# 81. Proibições explícitas

O agente SHALL NOT:

```text
desabilitar fsync para ganhar benchmark

remover overflow-checks sem auditoria

ativar target-cpu=native no release universal

ativar AVX-512 sem fallback

usar O_DIRECT em todo arquivo

carregar toda a base com WILLNEED

trocar Mutex por Atomic sem prova

usar unsafe sem documentar invariantes

alterar HRKL para encaixar io_uring

alterar lógica de LSN

tratar SIGKILL como graceful shutdown

medir benchmark oficial em GitHub shared runner
```

---

# 82. Definition of Done

A SPEC-0073 estará concluída quando:

### Plataforma

* Linux x86_64 for oficialmente Tier 1.
* Linux aarch64 for oficialmente Tier 1.
* Windows estiver claramente Tier 3.
* runtime Linux usar `heraclitus-server`.

### Abstração

* fast paths Linux estiverem encapsulados.
* crates de domínio não espalharem `libc`.

### I/O

* writer atual existir como baseline.
* io_uring possuir backend funcional.
* equivalência e crash recovery estiverem comprovados.
* backend default for decidido por benchmark.

### Memory

* `madvise` estiver funcional.
* políticas sequential/random existirem.
* mmap vs buffered I/O possuir benchmarks Linux.

### Lakehouse

* export não materializar segmentos inteiros desnecessariamente.
* memória for limitada por batch.
* digest não exigir leitura integral redundante quando evitável.

### NUMA

* topologia real for detectada.
* affinity respeitar CPU/cgroup.
* locality tiver benchmark multi-NUMA.

### Allocator

* allocator alternativo tiver sido qualificado.
* default for decidido por dados.

### Networking

* TCP_NODELAY estiver qualificado.
* REUSEPORT permanecer condicional a benchmark.
* buffers permanecerem configuráveis/autotuned.

### SIMD

* runtime dispatch existir.
* scalar fallback continuar canônico.
* x86_64 e aarch64 estiverem cobertos.

### Operations

* unit systemd oficial existir.
* SIGTERM estiver correto.
* SIGKILL + restart estiver provado.
* cgroups v2 forem considerados no resource budgeting.

### CI

* processo real Linux for executado.
* restart persistente for testado.
* crash persistente for testado.

### Performance

* nenhum fast path default existir sem evidência.
* benchmarks forem reproduzíveis.
* regressões críticas forem bloqueadas.

---

# 83. Resultado arquitetural esperado

Ao final desta SPEC, a arquitetura deverá ser:

```text
                       HeraclitusDB
                            │
                Semântica canônica portátil
                            │
           ┌────────────────┴────────────────┐
           │                                 │
     Linux Production                   Portable
       Runtime                           Fallback
           │
   ┌───────┼────────┬────────┬─────────┐
   │       │        │        │         │
io_uring madvise   NUMA    SIMD     network
   │       │        │        │         │
   └───────┴────────┴────────┴─────────┘
                    │
                  Kernel
                   Linux
```

O Linux deixa de ser apenas:

```text
"um sistema onde HeraclitusDB compila"
```

e passa a ser:

```text
"o sistema operacional para o qual
HeraclitusDB é arquitetado, medido,
qualificado e otimizado em produção."
```

---

# 84. Princípio final

Esta SPEC estabelece a seguinte prioridade de engenharia:

```text
1. reduzir trabalho desnecessário
2. reduzir bytes movimentados
3. reduzir alocações e cópias
4. melhorar locality
5. melhorar batching
6. explorar kernel Linux
7. explorar hardware específico
8. micro-otimizar
```

Consequentemente:

```text
O(N) desnecessário
```

nunca deve ser preservado apenas para depois ser executado mais rápido com:

```text
io_uring + AVX-512 + NUMA + hugepages.
```

A arquitetura primeiro elimina o trabalho.

Depois faz o trabalho inevitável tão rápido quanto o hardware e o kernel permitirem.

---

# 85. Ordem executiva de prioridade

## P0

```text
Linux platform abstraction
SPEC-0072 startup/replay integration
streaming lakehouse
madvise
io_uring experimental
SIMD runtime dispatch
Linux process lifecycle
```

## P1

```text
jemalloc qualification
NUMA real
CPU locality
cgroups v2
TCP_NODELAY
Linux runtime CI
aarch64 qualification
```

## P2

```text
SO_REUSEPORT
O_DIRECT
hugepage tuning
fat LTO benchmark
advanced socket tuning
```

## P3

```text
SQPOLL
IOPOLL
IRQ affinity
advanced eBPF steering
hardware-specific appliance profiles
```

Nenhum item P2 ou P3 deverá atrasar os invariantes de correctness, recovery ou os ganhos algorítmicos P0.
