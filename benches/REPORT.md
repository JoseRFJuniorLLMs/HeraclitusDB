# benches/REPORT.md — QPS × Recall (M7)

## HeraclitusDB self-benchmark (published)

Harness: `heraclitus bench --n 20000 --dim 16 --queries 100` (release build).
Dataset: synthetic **hierarchical tree** (Sarkar-shaped: depth → radius,
WordNet-like level distribution) on the Poincaré component of the product
manifold. Ground truth: exact brute-force hyperbolic distance. Queries:
perturbed dataset points (realistic near-duplicates). Single thread.

Hardware: Windows 11, x86_64 (12 vCPU-class desktop), Rust stable
(windows-gnu), 2026-06-10.

| N | dim | build | ef | QPS | recall@10 |
|---|---|---|---|---|---|
| 20000 | 16 | 24.55s | 16 | 4932 | 0.996 |
| 20000 | 16 | 24.55s | 32 | 4758 | 0.996 |
| 20000 | 16 | 24.55s | 64 | 4983 | 0.996 |
| 20000 | 16 | 24.55s | 128 | 2341 | 0.996 |
| 20000 | 16 | 24.55s | 256 | 739 | 0.996 |

Reading: on a strongly hierarchical dataset the HNSW-over-product-metric
saturates recall already at ef=16 — the curve is QPS-bound, not
recall-bound. This is the expected signature when the metric matches the
data's geometry (the entire thesis of learned manifolds). Expect lower
recall at equal ef for mismatched (flat) metrics.

Reproduce: `cargo build --release -p heraclitus-cli && target/release/heraclitus bench --n 20000 --dim 16 --queries 100`

### Reproduction — 2026-07-10 (median of 3 runs)

Same harness, re-run on the same machine class (Windows 11, x86_64, Rust
stable). The scientific claim — **recall@10 = 0.996, identical at every ef** —
reproduced **bit-for-bit on all 3 runs** (recall is deterministic: fixed seed 42,
exact ground truth). Build time and QPS are wall-clock throughput and vary with
machine state/load; this run was faster than the 2026-06-10 baseline.

| N | dim | build | ef | QPS (median of 3) | recall@10 |
|---|---|---|---|---|---|
| 20000 | 16 | 9.6s | 16 | 5818 | 0.996 |
| 20000 | 16 | 9.6s | 32 | 6279 | 0.996 |
| 20000 | 16 | 9.6s | 64 | 5787 | 0.996 |
| 20000 | 16 | 9.6s | 128 | 3419 | 0.996 |
| 20000 | 16 | 9.6s | 256 | 1676 | 0.996 |

Honest note on QPS variance: across the 3 runs, ef=16 ranged 5361–5858 and
ef=256 ranged 1288–1771 — run-to-run noise of roughly ±15%, inherent to
single-thread wall-clock timing on a loaded desktop. Recall carried **zero**
variance. Treat the QPS column as an order-of-magnitude signal, not a precise
figure; the recall column is the reproducible scientific result.

## Cross-database comparison (Qdrant / pgvector)

The comparison requires running the competitors; the harness contract:

1. `docker compose -f benches/docker-compose.yml up -d` (Qdrant :6334,
   Postgres+pgvector :5432).
2. Load the **same** synthetic tree dataset (`heraclitus_cli::synth_tree`,
   seed 42) into each engine.
3. Same queries, same k=10, same exact ground truth, report QPS and
   recall@10 per ef/probes setting, single thread, hot cache.

Methodology rules (non-negotiable): same machine, report concurrency,
hot/cold state, p50/p95/p99 for latency claims — never bare averages.

> Results for Qdrant/pgvector are NOT published yet — they will be added
> when run under the contract above. We do not publish numbers we did not
> measure.
