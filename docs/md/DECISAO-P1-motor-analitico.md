# DECISÃO P1 — o destino do motor analítico vetorizado

**Registada:** 2026-07-16 · **Estado:** decisão (parte firme) + 1 garfo de produto em aberto
**Fonte:** auditoria de wiring 2026-07-16 (grafo de dependências Cargo + grep de callers por símbolo)

> Esta decisão resolve o item **P1** do plano de auditoria: *"o motor vetorizado
> foi trabalho para produção ou para gaveta?"*. É medida contra as invariantes do
> [PLANO-SPECS.md](PLANO-SPECS.md) (I2, I4) e contra o benchmark real do projeto.

---

## 1. O facto que força a decisão

O crate `heraclitus-analytics` contém **dois** motores analíticos e **ambos estão
desligados** (nenhum handler do servidor, CLI ou GQL os alcança; o crate é
`optional = true`, feature `analytics`, off por default):

| | `LogAnalytics` (DataFusion) | Motor bespoke (`VecExecutor`) |
|---|---|---|
| Linguagem | SQL completo | mini-SQL: `SELECT [WHERE] [GROUP BY [SUM]]`, só `= > <`, só `AND` |
| Schema | 10 colunas (inclui `attrs_json`, valid-time) | 5 colunas (`lsn, agent_id, kind, ts_hlc, content_len`) |
| Estado | completo, correto, **sancionado pela I4** | subconjunto que **duplica** o DataFusion |
| Performance | madura (kernels Arrow SIMD) | fused-filter **perdeu o benchmark** (mais lento que eager em todas as seletividades); salvo com fast-path esparso + gating adaptativo |
| Nicho próprio | — | filtro seletivo → **já coberto** pelo attr index + zone-map skip-scan (SPEC-010, ligado) |
| Pushdown ao log | não (materializa tudo) | **também não** (recebe `&[(Lsn, Episode)]` já materializado) |
| Callers de produção | 0 (só via `Embedded::analytics`, também desligado) | **0** |

Além disso: o **GQL não tem superfície de agregação** (`GROUP BY`/`COUNT`/`SUM` não
existem na gramática). Ou seja, hoje **não há nenhuma via de query analítica ligada**.

---

## 2. Decisão firme (independente do garfo)

**O motor bespoke (`AnalyticalPlanner` SPEC-024 + `SelectivityOptimizer` SPEC-012 +
`VecExecutor` SPEC-013 + `run_analytical`) é REBAIXADO a referência.**

Porquê:
1. **Viola I4** ("não duplicar o DataFusion") se promovido — é um subconjunto
   estrito de SQL que o DataFusion já faz, sobre um schema mais pobre.
2. **Argumento de performance negativo/não-provado** — o próprio benchmark do
   projeto (`benches/fused_vs_sequential.rs`) matou o fused-filter; foi salvo com
   gating, mas nunca demonstrou vitória numa query real do produto.
3. **O nicho que o justificaria já está servido** — filtro seletivo por
   `agent_id`/`session_id` é o attr index + zone-map skip-scan (SPEC-010), ligado.
4. **A vantagem teórica (late-mat + pushdown) não está realizada** — o motor
   recebe episódios já materializados; não salta segmentos do log.

**Discordância preservada (anti-bajulação):** o contra-argumento legítimo é
"é o *nosso* motor, mantém o HUME em produção". Rejeitado por razões técnicas, não
de investimento: manter código vivo só porque foi caro é a falácia do custo
afundado. O trabalho **não se apaga** — fica como referência de I&D.

`hume-kernel` (`SelectionVector`, `MorselSizer`, radix, topk, compression) e
`hume-ir` (SSA + Cranelift JIT) **ficam como referência** (substrato de I&D; não
ligados ao core, honrando I2). Nada disto é apagado.

---

## 3. Garfo de produto em aberto (a resposta é do dono)

**O HeraclitusDB precisa de uma superfície de agregação (`GROUP BY/COUNT/SUM`) sobre
o log de eventos?**

- **SIM → ligar o `LogAnalytics` (DataFusion).** É a via sancionada pela I4,
  completa e correta. Wiring pequeno: uma rota real (`POST /sql` REST **ou** op
  gRPC admin) atrás da feature `analytics`, sem depender do `Embedded` desligado.
  Adiciona uma capacidade **nova** (o GQL não agrega). Caveat de produção:
  `LogAnalytics::from_log` materializa o log inteiro por chamada — mitigar com
  `as_of`/limites/admin-only antes de expor a sério.
- **NÃO → GQL-only, rebaixar também o DataFusion.** Superfície = GQL +
  attr/texto/vetor, que já cobre memória-de-agente. Tese mais pura, menos código,
  menos dependências (DataFusion sai do caminho). Escolher só se agregação OLAP
  sobre eventos não é necessidade real de utilizador.

Recomendação: **SIM (ligar o DataFusion)** — preserva a capacidade a custo baixo e
sem violar invariantes; a menos que se confirme que o produto nunca agrega eventos.

---

## 4. Ações concretas do rebaixamento (a aplicar após confirmação)

Independentes do garfo (executar já, quando houver OK):
1. Cabeçalho honesto em `heraclitus-analytics/src/vectorized.rs` e `planner.rs`:
   marcar como **referência de I&D — não ligado ao caminho vivo** (hoje os doc-
   comments sugerem "wired end-to-end").
2. Corrigir a `SPEC-new/STATUS.md`: a linha 012/013 ("✅ engine v1 wired") e o
   parágrafo de resumo passam a "**referência, não ligado**" (ver auditoria).

Se o garfo for **SIM**:
3. Rota `POST /sql` (axum, feature `analytics`) → `LogAnalytics::from_log(as_of)`
   → `.sql(q)`, admin-gated; ou op `admin` gRPC equivalente.

Se o garfo for **NÃO**:
3. Rebaixar também `LogAnalytics`/feature `analytics` a referência e removê-la do
   caminho de exposição (mantendo o código).
