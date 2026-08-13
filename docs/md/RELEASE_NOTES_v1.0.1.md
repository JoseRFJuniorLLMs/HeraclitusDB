# HeraclitusDB v1.0.1 — "fable-5"

**Data:** 2026-07-21

Patch de manutenção sobre a [v1.0.0](RELEASE_NOTES_v1.0.0.md): fecha os bugs que
restavam da auditoria de código Rust (§6.2 do `docs/md/falta_fazer.md`), rodada
recursiva focada no código novo pós-1.0. **Só correções** — sem mudanças de API
nem de formato; atualizar é seguro e recomendado. Verificado verde (msvc).

---

## Correções

### Cold tier

- **Integridade no recall (`fetch_cold`).** O recall de um segmento frio não
  validava o objeto contra o recibo — um objeto truncado ou com bit-flip (corpo
  curto de um backend remoto, disk rot) era re-indexado como se fosse válido.
  Agora `fetch_cold` corre `scan_and_root` e recusa (`Corruption`) qualquer
  objeto cujo `record_count` + `blake3_root` não confiram com o recibo.
  *(commit `e7ac08d`)*
- **Espelho Parquet bi-temporal + embedding.** O espelho Parquet do cold tier
  omitia `valid_from`/`valid_to` e o `embedding`, por isso o analytics sobre o
  Parquet tratava tudo como sempre-válido e não via o vetor do episódio.
  Adicionadas três colunas **nuláveis**: `valid_from`/`valid_to` (`UInt64`;
  `NULL` = aberto, distinto de um `0` real) e `embedding_json` (`Utf8`; JSON do
  `ProductPoint`, `NULL` se ausente). Additivo — leitores existentes não quebram.
  *(commit `43a259d`)*

### Consenso (raft)

- **Resiliência do servidor gRPC a erros de `accept()`.** Um erro do listener
  (ex.: `EMFILE` sob exaustão de file descriptors) terminava
  `serve_with_incoming` e derrubava o nó do cluster até restart. O incoming
  stream passa a saltar erros de `accept()` e continuar a servir — o mesmo
  recua-e-continua do transporte TCP puro. *(commit `e7ac08d`)*

### Recuperação / determinismo

- **Desempate determinístico no `rrf_fuse`.** A fusão RRF ordenava só por score
  com candidatos vindos de um `HashMap` (seed SipHash) — empates (comuns)
  ficavam em ordem não-determinística e o corte `RECALL_N`/top-k variava entre
  execuções. Desempate estável por `EventId`. *(commit `e7ac08d`)*

### Servidor (H-VM ledger)

- **`GET /hvm/state`: chaves não-UTF-8 deixam de colapsar.** As chaves do ledger
  H-VM passavam por `from_utf8_lossy` — dois bytes binários distintos viravam a
  mesma string (`U+FFFD`), colidiam na chave do mapa JSON e uma entrada
  sobrescrevia a outra (desaparecia em silêncio). Novo esquema **injetivo**:
  UTF-8 legível quando possível, senão `hex:<hex>` (aplicado a chave e valor).
  *(commit `bf9da9a`)*

---

## Estado da auditoria

Com esta versão, a **§6.2 da auditoria não tem nenhum bug em aberto**. O que
resta em `docs/md/falta_fazer.md` é trabalho arquitetural (evicção real dos
índices quentes — o "esquecimento", que colide com a invariante I6 e precisa de
desenho), follow-ups de otimização (§3), e decisões de dono (bucket GCS na
nuvem, benchmark de GPU, mTLS no transporte raft).

## Verificação

`cargo test` verde (msvc): `heraclitus-tier` (8), `heraclitus-server` hvm (6),
`heraclitus-retrieval` (6), `heraclitus-raft` (replicação compila). Build
`--release` de `heraclitus-server` + `heraclitus-cli` OK.
