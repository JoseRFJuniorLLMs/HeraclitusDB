# HeraclitusDB v1.0.4 — "fable-5"

**Data:** 2026-07-28

Patch **CRÍTICO** sobre a [v1.0.3](RELEASE_NOTES_v1.0.3.md), publicado no mesmo
dia: a auditoria continuou depois de a v1.0.3 sair e encontrou mais um caminho
de **perda silenciosa e permanente** — desta vez nas **views derivadas**.

> ### ⚠️ Quem instalou a v1.0.3 deve atualizar
> A v1.0.3 continua a ser recomendada face à v1.0.2 (corrigiu perda de registos
> no log), mas **não** traz esta correção. O defeito abaixo dispara num modo de
> arranque **documentado para operadores** (recuperação / carga em massa).

**Sem mudanças de API nem de formato em disco.**

---

## Correção

### Views — arrancar com o replay saltado tornava-as órfãs *(CRÍTICO)*

Arrancar com **`HERACLITUS_SKIP_VIEW_REPLAY=1`** (ou `HERACLITUS_LOG_ONLY=1`)
podia deixar **todos os eventos até um dado LSN invisíveis às views derivadas,
de forma permanente e silenciosa**. A cadeia:

1. nesse modo, o boot regista as views mas **não** chama `catch_up` — as views
   ficam **vazias**. O `ViewRegistry::open`, porém, **já carregou os watermarks
   altos** do `watermarks.json` da corrida anterior;
2. o **checkpoint periódico** (300 s por omissão) e o de **shutdown** não olham
   a esse modo: gravam snapshots **vazios** sob aqueles watermarks altos;
3. no arranque normal seguinte, o `catch_up` só repõe o watermark quando
   `restore()` devolve `false` — e um snapshot **vazio-mas-presente** devolve
   `true`. O watermark sobrevive e replaya-se apenas `(W, head]`.

Resultado: tudo `≤ W` deixa de existir para `vector`, `text`, `graph`,
`tgraph`, `entity` e `activation` — **sem erro nem aviso**, recuperável apenas
com um `view rebuild` explícito. O log em si **nunca é afetado** (a verdade
está intacta; o que se perde é o material derivado).

**Correção:** novo `ViewRegistry::reset_watermarks()`, chamado no ramo de
skip-replay do boot. Views vazias passam a declarar watermark **0**, o que torna
qualquer checkpoint posterior seguro e faz o próximo arranque normal reconstruir
a partir do LSN 0. *(commit `9c7b71c`)*

---

## Testes

- **`skip_replay_then_checkpoint_does_not_orphan_events`** — reproduz a cadeia
  completa (arranque normal → arranque com replay saltado + checkpoint →
  arranque normal) e exige que a view volte a conter o log inteiro.
  Verificado que **falha sem a correção** (`só 0 de 30 eventos ficaram
  indexados`) e passa com ela.
  *Nota metodológica: uma asserção sobre o **watermark** NÃO apanha este bug —
  ele fica "certo" nos dois casos, e é exatamente essa a mentira. A asserção
  tem de ser sobre os eventos efetivamente indexados.*
- **`stress_many_rolls_survives_reopen_and_verify`** — endurece a cobertura do
  fix do roll da v1.0.3: 16 escritores concorrentes, payloads de tamanho
  variável, 50+ rolls; exige `scan` completo, nenhum LSN trocado, cadeia Merkle
  consistente e o índice **reconstruído do disco ao reabrir** a ver o mesmo.
  Medido fora da suite com **206 e 280 rolls** e as três políticas de fsync —
  sempre 0 perdidos, 0 trocados. *(commit `6019957`)*

---

**Instalação/upgrade:** substituir o binário. Formatos de log, checkpoint e WAL
**inalterados** — rolling upgrade seguro, sem migração.

> **Se já usou o modo skip-replay numa versão ≤ 1.0.3:** as views podem estar
> incompletas em disco. Um `view rebuild` (ou apagar os `*.ckpt` e o
> `watermarks.json` e deixar o arranque reconstruir do LSN 0) repõe o estado —
> o log tem tudo o que é preciso.
