# HeraclitusDB v1.0.0 — "fable-5"

**Data:** 2026-07-16

A primeira versão estável do HeraclitusDB — uma base de dados **multimodal,
event-sourced e append-only**: o log imutável é a única verdade, tudo o resto
(grafo, vetor, texto, atributos) é uma *view* derivada e reconstruível, com
prova Merkle blake3 e reprodutibilidade bit-a-bit `AS OF LSN`.

---

## Superfície genuinamente ligada (o que 1.0 entrega)

- **Núcleo imutável:** `heraclitus-log` (segmentos `.hrkl`, crc32 + Merkle
  blake3 por segmento, group-commit, recuperação de torn-write, skip-scan por
  zone-maps), `heraclitus-views` (replay determinístico + checkpoints, fast
  boot), `heraclitus-memtable` (read-your-writes).
- **Consulta multimodal (GQL):** grafo (Leiden/CC via `COMMUNITY`, temporal
  `AS OF`, `neighbors`/`traverse`/`match_edges`, `DECIDE`/`ADAPT`, resolução de
  entidades), atributos (range + zone-maps), texto (BM25), vetor (HNSW na
  variedade produto H×S×E; GPU opcional), `WHY`, telemetria endógena.
- **Consenso (feature `replication`):** raft real (openraft) — eleição, quórum,
  failover, raft-log durável, restart de processo, sobre **TCP e gRPC**. O
  **ledger soberano H-VM (M20)** replica em cluster.
- **SQL analítico (feature `analytics`):** `POST /sql` sobre o log via DataFusion.
- **Cold tier (feature `tier`):** demote de segmentos selados para object store
  (local **ou GCS/S3**) com espelho Parquet + recibo Merkle; recall round-trip;
  compaction em background.
- **Consolidação (feature `distill`):** destilação de `Fact`s a partir de
  clusters de embeddings, pelo caminho de append unificado.
- **Conformidade:** ancoragem RFC 3161 / ICP-Brasil, verificação forense de
  recibos, crypto-shred, chaves com permissões restritas (0600/0700 no Unix).

## Correções de segurança/robustez nesta versão

- **gRPC do raft:** teto de mensagem elevado de 4MB → 256MiB (senão um seguidor
  atrasado com snapshot grande nunca recuperaria).
- **REST:** recusa expor escritas duráveis (`/hvm/*`, `/tier/demote`, `/sql`)
  sem autenticação num endereço não-loopback.
- **Reactor:** `/verify`, `/tier/demote`, `/tier/fetch` movidos para
  `spawn_blocking` (não congelam o servidor / os health-probes).
- **CLI forense:** `verify`/`verify-receipts` devolvem código de saída **1** em
  qualquer falha de integridade (scripts podem gatear com `&&`).
- **Durabilidade do consenso:** o state-machine falha ALTO (em vez de esconder)
  se o meta ficar à frente do log após um crash na janela de group-commit.
- **Recência ACT-R:** o `recall` passa a usar o relógio físico (não o LSN) — o
  decay de recência deixa de estar morto.
- **Revisão R1–R25:** ~25 bugs do caminho vivo corrigidos com sondas de
  regressão ativas (GraphMatch, Bᵋ-tree, ORDER BY, truncate atómico do log,
  paginação de scans, `spawn_blocking` no admin, temporal re-assert, auth
  constant-time, entre outros).

## Invariantes (o fosso de disciplina)

`I1` log append-only é a verdade · `I2` a inteligência vive no agente, não no
banco · `I4` não duplicar o DataFusion · `I6` views reconstroem do LSN 0 ·
Gate C: otimização = resultado bit-idêntico + ganho medido.

## Limitações conhecidas / adiado (ver `docs/md/falta_fazer.md`)

- **Evicção de índices / libertar RAM** — o demote é hoje uma CÓPIA (o segmento
  fica nos índices em RAM); a evicção verdadeira colide com I6 e precisa de
  desenho próprio.
- **Cluster para tier/distill** — guardados sob replicação até haver object
  store partilhado / cursor distribuído.
- **A verificar (auditoria §6):** integridade em `fetch_cold`, compaction do WAL
  do raft, e alguns itens `LOW` (RRF tie-break, chaves não-UTF-8, campos do
  espelho Parquet). Nenhum é bloqueador da superfície ligada.
- **Adiado por design:** NUMA node-local pleno, kernels AVX explícitos, GPU no
  `nearest` (até haver benchmark), mTLS no transporte raft (LAN privada por ora).

## Feature flags

`replication` (consenso raft) · `analytics` (SQL/DataFusion) · `tier`
(cold-storage; `tier-gcp`/`tier-aws` para nuvem) · `distill` (consolidação) ·
`gpu` (RECALL GPU). O servidor de **nó único** é o caminho por omissão.

## Build

Toolchain **msvc** por omissão (o gnu requer `dlltool` do mingw). Testado verde:
workspace + `replication`/`analytics`/`tier`.

---

*Cortado com Claude (fable-5). Trilho completo de decisões em `docs/md/DECISAO-P*.md`,
`falta.md` (histórico) e `falta_fazer.md` (roteiro vivo).*
