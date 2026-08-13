# DECISÃO P3 — o destino do `heraclitus-txn` / `IsolationLevel` (SPEC-019)

**Registada:** 2026-07-16 · **Estado:** decisão firme (sem garfo em aberto)
**Fonte:** auditoria de wiring 2026-07-16 (grafo de dependências + grep de callers)

> Resolve o item **P3** do plano de auditoria: *"ligar o `TxnManager` ao caminho
> append/query, ou rebaixar"*.

---

## 1. O facto que força a decisão

A `STATUS.md` afirmava **SPEC-019 "✅ wired via `TxnManager::begin_with`"**. Falso:

- `heraclitus-txn` é um **crate órfão** — nenhum `Cargo.toml` o lista como dep
  (só o dele próprio). O `IsolationLevel` (`core::consistency`) tem como **único
  consumidor** o `heraclitus-txn`. Nada disto está no caminho vivo.
- **Mas a capacidade que a SPEC-019 descreve já está ligada por outra via:** o
  `heraclitus-query::QueryBackend` recebe `as_of: Option<Lsn>` em **todos** os
  métodos de leitura (`scan`/`recall`/`nearest`/`neighbors`/`community`/…),
  resolvido do GQL `AS OF LSN|SNAPSHOT` (`AsOf::{Lsn,Timestamp}`). Ou seja, o
  `HistoricalSnapshot(l)` da SPEC-019 **≡** GQL `AS OF LSN l`, e funciona
  ponta-a-ponta (o skip-scan por zone map da SPEC-010 já o exercita).

---

## 2. Decisão: REBAIXAR (não ligar)

`heraclitus-txn` (`TxnManager`/`Snapshot`/`read_at`/`SnapshotManager`) e o enum
`core::consistency::IsolationLevel` ficam como **referência de I&D**. Ligar o
`TxnManager` ao caminho append/query seria **redundante e pior**:

1. **`AS OF` já está ligado** via GQL — `HistoricalSnapshot` não precisa do
   `TxnManager`.
2. **Os outros níveis são degenerados** neste sistema: o log é single-writer
   append-only, logo *committed = fsync-acked = `head()`*; `ReadCommitted`,
   `Repeatable` e `Streaming` colapsam todos em "lê no head atual". Não há
   sessão de escrita multi-statement a que prender níveis de isolamento (cada
   `execute` GQL é single-shot).
3. **`read_at` é mais pobre** que o caminho vivo: faz `log.scan` cru, enquanto as
   *views* já fazem a leitura `AS OF` com merge da memtable + índices.
4. **A única peça não-redundante** — o watermark de GC do `SnapshotManager`
   (piso abaixo do qual se pode compactar sem quebrar um leitor vivo) — **não tem
   consumidor**: o log nunca apaga (só o `tier` frio, que não está ligado), e as
   views reconstroem de checkpoints. Ligá-lo agora seria construir para ninguém.

**Discordância preservada:** o contra-argumento é "expor `IsolationLevel` dá uma
API tipada de isolamento ao cliente". Rejeitado: duplicaria o GQL `AS OF` para o
único nível não-degenerado (Historical). Se um dia existir uma sessão de leitura
multi-statement ou um GC que respeite leitores vivos, reabre-se a P3 — e aí o
`SnapshotManager` já está escrito e testado, pronto a ligar.

Nada é apagado. `heraclitus-txn` continua membro do workspace como referência de
§3.11 (MVCC-sobre-LSN) + SPEC-019.

---

## 3. Ações aplicadas

- Banner "referência — não ligado" no topo de `heraclitus-txn/src/lib.rs` e nota
  de wiring em `heraclitus-core/src/consistency.rs`; corrigido o doc-comment
  enganoso de `TxnManager::begin_with` ("SPEC-019 wired" → "reference").
- `STATUS.md`: linha 019 corrigida (capacidade ligada via GQL; enum/`TxnManager`
  = referência) e nota na linha 011 (`txn::SnapshotManager` e
  `DerivedExecutionArtifact` são referência/órfãos).
