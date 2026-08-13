# DECISÃO P4 — o destino do sistema de plugins / sandbox WASM (SPEC-025/035)

**Registada:** 2026-07-16 · **Estado:** decisão firme (sem garfo em aberto)
**Fonte:** auditoria de wiring 2026-07-16 (grafo de dependências + grep de callers)

> Resolve o item **P4**: *"linkar `heraclitus-wasm` no servidor para os plugins
> correrem de facto, ou rebaixar"*.

---

## 1. O facto que força a decisão

A `STATUS.md` afirmava **SPEC-025 "✅ wired via WASM"** e **SPEC-035 "✅ sandbox
WASM real"**. Falso enquanto "ligado":

- `heraclitus-wasm` é **órfão** — nenhum `Cargo.toml` o lista como dep.
- `core::plugin::PluginHost` só **cataloga nomes** de capacidades
  (`RegistryCatalog { index_types, compressors, operators }` = `Vec<String>`).
  **Nada** no query/executor **invoca** um operador registado — não há sítio de
  execução. O único consumidor do `PluginHost` é o crate órfão `heraclitus-wasm`.
- `core::sandbox::run_sandboxed` (a barreira de pânico) tem **0 callers**.
- A ABI de UDF do `WasmPlugin` é um `(i64,i64)->i64` de brinquedo.

O isolamento em si é real e testado **em unidade** (memória, fuel metering →
loop infinito vira `Err`, traps contidos, módulo inválido rejeitado). O que não
existe é qualquer ligação ao caminho vivo.

---

## 2. Decisão: REBAIXAR (não ligar)

`heraclitus-wasm`, `core::plugin` e `core::sandbox` ficam como **referência de
I&D**. "Linkar o crate no servidor" **não** faria plugins correrem: os nomes
iriam para um catálogo que ninguém consulta. Correr plugins a sério exige uma
**feature inteira**, não uma ligação:

1. Uma **superfície de query** para invocar um UDF (ex.: `WHERE wasm:scorer(a,b) >
   k`) — não existe na gramática GQL.
2. **Dispatch no executor** que resolva o operador contra o `RegistryCatalog` e
   chame o `WasmPlugin`.
3. Uma **ABI de UDF a sério** (tipos, arrays, erros) — não o `(i64,i64)->i64`.

E, acima disto, uma **decisão sobre a invariante I2** ("a inteligência vive no
agente, não no banco"): correr WASM de terceiros dentro do banco é exatamente a
"catedral" que a I2 desencoraja — tensão que o próprio `core::plugin.rs` e
`core::sandbox.rs` já admitem no código.

**Discordância preservada:** o argumento a favor é "UDFs em sandbox são uma
extensão legítima e segura (o fuel metering prova-o)". Válido em teoria, mas sem
uma necessidade de utilizador concreta e sem sítio de execução, ligar agora é
construir infraestrutura para ninguém — e contra a I2. Se surgir um caso real de
UDF, reabre-se a P4; a sandbox (isolamento/fuel/traps) já está escrita e testada,
pronta a servir de motor de execução.

Nada é apagado. Os crates continuam membros do workspace como referência de
SPEC-025/035.

---

## 3. Ações aplicadas

- Banner "referência — não ligado" no topo de `heraclitus-wasm/src/lib.rs`; notas
  de wiring em `core::plugin` e `core::sandbox` (que já eram honestos quanto ao
  âmbito).
- `STATUS.md`: linhas **025** e **035** corrigidas (referência / real só em
  unidade). Corrigidas também **026** (`CapabilityCatalog`) e **033**
  (`numa`/`pin_workers`), cujo único consumidor é o `VecExecutor` — que a P1 já
  marcou como referência —, logo estavam falsamente "wired".
