1. Compilador / IR / JIT (o "coração" do HUME)
HUME-IR em SSA — ValueId definição-única, dominância, nós-Φ, opcodes de efeito (Spill/Exchange) (SPEC-000 §6, 0038 §1)
HUME-IR multi-dialeto (MLIR) — dialetos Logical/Relational/Vector/Physical/Machine com lowering progressivo (0039 §2)
Rule & pattern-matching engine — RewriteRule, Fusion Pass, Join Reorder, Predicate Pushdown (0039 §3)
JIT tiers — Cranelift baseline + LLVM + GPU CUDA/HIP, com hotness profiling (interpreter→hot→super-hot) (0037 §4, 0038 §3)
Adaptive code-gen plane (multi-backend lowering) (0038 §1)
Vector register allocator + loop fission (pressão de registos) (0039 §4)

2. Motor de execução física (operadores)
Scan colunar real (prefetch assíncrono, decode SIMD) — hoje o ColumnScan só clona a fonte
Filter branchless SIMD (máscara + compress) — o nosso é scalar, não SIMD
Project in-place (SPEC-000 §3)
LateFetch com resolução de PhysicalRowID — só existe o struct, não o operador
Radix Hash Join (partições dimensionadas ao cache L2/L3) — só há hash join genérico
Cache-aware HashAggregate (perfect hashing para grupos pequenos) (0039 §6)
Top-K sort-breaking (partial heap, O(N log K)) (0039 §6)
Window engine (ROW_NUMBER/RANK/LEAD/LAG/SUM OVER) (0039 §6)
Incremental / delta execution (0039 §6)
Push-based / morsel-driven com work-stealing NUMA (0037 §3, 0038 §5)
PipelineOperator ABI (open/execute/close, OperatorState) (SPEC-000 §3)
Pipeline fusion / operator fusion (0038 §3)
3. AQE / otimização adaptativa
Máquina de estados AQE (Created→Running→CollectStatistics→ReOptimize→CompileJIT) (SPEC-000 §5.2)
Troca dinâmica de joins (Sort-Merge/Shuffled Hash → Broadcast) (0037 §1)
Coalescência dinâmica de partições (0037 §1)
Otimização de skew (subdivisão de partições assimétricas) (0037 §1)
Speculative execution (corrida de estratégias) (0039 §8)

4. Custo / estatística / aprendizado
CostVector multidimensional (9-D: cpu/mem/io/net/cache/branch/numa/gpu/comp) (SPEC-000 §5, 0037 §2)
Learned cost model (regressão / XGBoost / Tiny NN) (0038 §7, 0039 §7)
Statistics engine (histogramas, NDV, seletividade, skew) (0036)
Data sketches (HyperLogLog, TDigest, Count-Min, Cuckoo/Quotient) (0039 §7)
Auto-tuning closed loop (telemetria → coeficientes) (0038 §7)

5. Memória / concorrência
MemoryState — matriz de 8 estados (Owned/Borrowed/Pinned/GPUResident/NetworkOwned/Spilled/Compressed/Encrypted) (SPEC-000 §2.2)
Query Arenas NUMA-aware (blocos 4MB node-local, arena.reset() O(1)) (0038 §5) — só temos o ScratchAllocator básico
ExecutionContext (injeção de allocator/scheduler/deadline/budget) (SPEC-000 §4)
Spill automático para NVMe (0039 §6)
StorageBatch vs ExecutionBatch (modelo bifurcado zero-copy) (SPEC-000 §1) — só temos o DataChunk unificado

6. Infraestrutura operacional
ResourceManager (cotas CPU/RAM/IOPS/GPU, multi-tenant, admission/preemption/backpressure) (SPEC-000 §4, 0036)
BufferManager (CLOCK-Pro + TinyLFU, prefetching inteligente) (0036 §5)
Background scheduler (compaction/GC/Iceberg, filas de prioridade) (0036 §6, 0039 §8)
Async IO (io_uring / NVMe direct, prefetch queue) (0038 §8)
Prefetch predictor (sequential / random-vector / graph) (0039 §8)

7. Kernels SIMD / compressão
hume-kernel SIMD explícito (avx2.rs/avx512.rs/neon.rs) — o crate existe mas é std-only, sem SIMD à mão
Codecs de compressão (FastPFor/SIMD-BP128, StreamVByte/VarInt-G8IU, Roaring bitmaps) (0039 §5, 0040.1 §4)
Compressão adaptativa por página (entropia → RLE/Dictionary/Delta+BitPack/FOR) (0037 §5)
Hardware profile catalog (calibração Sapphire/Genoa/Graviton4/M4) (0039 §4)
Kernels SIMD por arquitetura (simd_eq_i32, simd_contains_str) (0038 §4)

8. Lakehouse / storage frio
Lakehouse engine (Iceberg, camada COLD) (0036)
heraclitus-manifest (Manifest Lists/Files, orphan detection, snapshot GC) (0036)
heraclitus-object-store (S3/MinIO/Ceph/R2/GCS/Azure) (0036)
Escrita Parquet atómica de tabelas abertas (0036)

9. Federação / streaming
Query Federation Plane (Postgres pushdown, Iceberg, Kafka) (0037 §6, 0038 §9)
Capabilities catalog (StorageCapabilities/ForeignCapabilities para pushdown) (0038 §9, 0039 §9)
Arrow Flight transports para federação (0037 §6)
Stream-to-table joins + unificação streaming/batch (0037, 0038 §9, 0039 §9)

10. Consenso distribuído avançado
Leader leases (leituras lineares locais) (0036 §3)
Follower reads com HLC (0036 §3)
OCC + Raft + EBR (resolução de conflitos distribuídos) (0036 §3)
Operador Exchange (shuffle distribuído entre nós) (0036)

11. Observabilidade
heraclitus-observability (Prometheus, OpenTelemetry tracing, stats por operador físico) (0036)

12. Benchmark / reprodutibilidade
Contrato de reprodutibilidade (rustc pinado, target-cpu=native, cpu governor, hugepages, thread affinity) (SPEC-000 §7)
Painel de perf counters (perf_event_open: L1 miss<3%, branch mispredict<1%, RAM>85%) (SPEC-000 §7, 0040 §3)
Protocolo de 3 zonas (A: L1/L2 1M linhas · B: RAM 100M · C: cold 10B) (0040.1 §6) — só fiz 1 criterion bench

13. Multimodal no pipeline
Vector operator dialect (HNSW/Top-K dentro do pipeline colunar) (0040.1 §7 marco 8)
Graph operator dialect (varredura de adjacência sobre RowIDs) (0040.1 §7 marco 9)
(o HNSW/grafo já existem no HeraclitusDB, mas fora do pipeline HUME unificado)

14. Crates que as specs mandavam criar e não existem
hume-ir · hume-runtime · hume-operators · heraclitus-scheduler · heraclitus-optimizer · heraclitus-statistics · heraclitus-execution · heraclitus-resource · heraclitus-buffer · heraclitus-manifest · heraclitus-object-store · heraclitus-bench · heraclitus-storage

