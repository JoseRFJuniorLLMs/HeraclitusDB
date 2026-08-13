# P5 — Ligar o ledger H-VM (M20) a uma superfície REST

**Registada:** 2026-07-16 · **Estado:** feito e testado (é um *wire*, não um rebaixamento)
**Fonte:** auditoria de wiring 2026-07-16

> Resolve o item **P5**: *"expor endpoint do H-VM ledger (traz o `heraclitus-btree`
> ao uso)"*. Ao contrário de P1/P3/P4, aqui a decisão foi **ligar** — o M20 é uma
> capacidade real e não-duplicativa, apenas sem porta.

---

## 1. O que estava por ligar

O `Engine` já expunha o ledger H-VM (M20 — "Sovereignty Layer": KV durável cujas
escritas são bytecode `VmInstruction` no mesmo log append-only, lido por replay
determinístico): `hvm_upsert`, `hvm_delete`, `hvm_state`, `hvm_checkpoint`. Estava
**implementado e testado** (`m20_hvm_ledger_through_engine_survives_reopen_and_checkpoints`)
mas **sem qualquer endpoint** em proto/CLI/client/REST — logo referência. E como o
único uso do `heraclitus-btree` (2563 LOC) é o `hvm_checkpoint` (materializa o
ledger num Bᵋ-tree), o btree ficava arrastado para referência também.

## 2. O que foi ligado

Superfície REST (consistente com a rota `POST /sql` do P1; admin-gated pela mesma
Basic Auth do router):

| Rota | Efeito |
|---|---|
| `GET /hvm/state` | espaço KV + LSNs como JSON (chaves/valores UTF-8 lossy) |
| `POST /hvm/upsert` `{key,val}` | append de `Upsert` ao log → `{lsn}` |
| `POST /hvm/delete` `{key}` | append de `Delete` ao log → `{lsn}` |
| `POST /hvm/checkpoint` | materializa o Bᵋ-tree em `<data_dir>/hvm.hbt` → `{ok,path}` |

O `checkpoint` **traz o `heraclitus-btree` ao caminho vivo**.

### Decisões de desenho (segurança e correção)

1. **Sem caminho do cliente.** `hvm_checkpoint(path)` aceita um caminho arbitrário
   — expor isso por HTTP seria escrita-onde-quiser (path traversal). O endpoint usa
   `Engine::hvm_checkpoint_default()`, que escreve **sempre** em
   `<data_dir>/hvm.hbt` (derivado do server, nunca do pedido).
2. **Escritas recusadas sob replicação (409).** As escritas H-VM appendam bytecode
   direto ao log local, **fora do router de consenso** (o mesmo padrão que a
   auditoria apanhou na telemetria). Em cluster isso divergiria entre nós, por isso
   `Engine::is_replicated()` faz o endpoint recusar upsert/delete/checkpoint quando
   a replicação está ativa — em vez de deixar o ledger divergir em silêncio.
   Roteá-las pelo consenso (empacotar `VmInstruction` como `Episode` replicável) é
   um follow-up honesto, fora do escopo de P5.
3. **`spawn_blocking`.** `hvm_state` faz replay do log (bloqueante) e as escritas
   fazem `fsync` — tudo corre em `spawn_blocking`, nunca no reactor do tokio.

## 3. Verificação

- `engine::hvm_checkpoint_default_writes_under_data_dir_and_is_not_replicated` —
  checkpoint fica sob o `data_dir`, o Bᵋ-tree recarrega com o valor certo, e
  `is_replicated()` é falso no nó autónomo. ✅
- `rest::hvm_state_json_reflects_the_ledger` — a vista JSON do estado reflete
  upsert/delete. ✅
- `m20_hvm_ledger...` (existente) continua verde. ✅
- Compilado e corrido sob a toolchain **msvc** (o `dlltool` do gnu está em falta —
  gap de ambiente, não do código).
