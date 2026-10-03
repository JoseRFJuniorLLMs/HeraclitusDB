# Correções de Auditorias — 2026-10-03

Base: `a2e671f` (conclusão da ronda 2 de 2026-10-02). Ramo: `fix/auditorias-2026-10-02`.  
Documento complementar a [`CORRECOES-AUDITORIAS-2026-10-02.md`](CORRECOES-AUDITORIAS-2026-10-02.md) e [`CORRECOES-AUDITORIAS-2026-10-01.md`](CORRECOES-AUDITORIAS-2026-10-01.md).

---

## 1. Método e Auditoria Recursiva

Após as rondas 1 e 2 de auditoria e estabilização de produção, foi executado um ciclo de **auditoria recursiva multi-agente** com verificação adversarial independente em 5 rondas consecutivas (Rondas 3 a 7). Cada achado potencial foi submetido a três critérios de refutação antes de qualquer correção de código:
1. **Correção:** O comportamento observado viola uma invariante contratual formal (SPEC, RFC ou garantia do banco)?
2. **Reprodução:** Existe prova de conceito determinística ou teste que falhe no estado atual?
3. **Impacto:** O problema afeta produção ou caminhos públicos suportados, sem falsos positivos ou suposições inválidas?

Todas as correções implementadas foram acompanhadas de testes unitários ou de integração de regressão, validados com execução offline estrita.

---

## 2. Matriz de Correções (Rondas 3 a 7)

| Ronda | Commit | Crate | Defeito Confirmado | Correção Implementada | Teste de Regressão |
|---|---|---|---|---|---|
| **3** | `b2822e6` | `heraclitus-compliance` | Manifesto e diretório desincronizados permitiam cauda malformada em evidência de conformidade. | Sincronização obrigatória de diretório com manifesto e rejeição explícita de registros truncados na cauda. | `manifesto_cauda_malformada_recusa` |
| **3** | `181de92` | `heraclitus-crypto` | Arquivo de chave simétrica corrompido com tamanho diferente de 32 bytes era tratado como crypto-shred (falso positivo de deleção legal). | Erro de tamanho classificado como `InvalidData` de integridade, impedindo interpretação como chave destruída. | `chave_tamanho_invalido_e_erro_dados` |
| **3** | `27a2c4f` | `heraclitus-views` | Snapshot vazio com watermark 0 fazia o replay subsequente pular ou duplicar o LSN 0 em reinicializações repetidas. | Reinicialização explícita do cursor da view quando watermark é 0, garantindo replay determinístico do LSN 0. | `empty_checkpoint_still_receives_first_lsn_zero`, `restored_zero_watermark_does_not_accumulate` |
| **3** | `c732acd` | `heraclitus-raft` | Truncamento do WAL em recuperação de falha ocorria antes de validar o metadado comprometido (`committed`), arriscando perda de dados comprometidos. | Validação prévia da fronteira contígua antes de truncar o WAL no arranque. | `invalid_meta_does_not_modify_a_torn_wal` |
| **4** | `6e2135d` | `heraclitus-agent-gateway` | Admissão prematura de evidência no índice de deduplicação antes de confirmar gravação no log (`SPEC-0074 §14`). Falha no log deixava chave como duplicado falso em memória. | Coordenação em voo (`InFlightGuard`): a chave só é inserida no índice após o retorno do log; retries e falhas liberam a reserva em voo via Condvar. | `inflight_dedupe_retries_and_failures` |
| **4** | `8e64d66` | `heraclitus-tier` | `compact_cold_prepared` no tier legado utilizava `PUT` incondicional sobre `cold/<segment>-cN.hrkl`, permitindo sobrescrever geração ativa com raiz Merkle divergente. | Verificação de existência e correspondência da raiz Merkle antes de sobrescrever; rejeição com erro caso a raiz divirja. | `compact_cold_refuses_to_overwrite_divergent_generation` |
| **4** | `bc0c335` | `heraclitus-tier` | Scratch de repack compartilhado entre invocações; `collect_cold_locations` silenciava erros transitórios no `HEAD` de sidecars HRKI, reportando limpeza perfeita indevida. | Diretório temporário exclusivo por invocação de repack; retenção de erros transitórios no relatório de GC frio (`ColdCollectReport`). | `spec0050_cold_repack`, `sidecar_transient_error_retained` |
| **5** | `5a12c5c` | `heraclitus-agent-gateway` | Mensagem de erro de conflito em voo exibia chave vazia para evidências sem campo `dedupe_key` pré-estampado; mutex suscetível a poisoning no drop. | Exibição da chave calculada (`{key}`) na mensagem de erro; guarda de drop resiliente a lock poisoning (`unwrap_or_else`). | `unstamped_dedupe_key_conflict_error_contains_computed_key` |
| **5** | `5a12c5c` | `heraclitus-raft` | Recuperação do WAL quando `last_purged` era `None` permitia falsos positivos se faltasse o início do log sem registro de purga. | Exigência de que o log não purgado inicie em 0 ou 1 e seja estritamente contínuo até `committed.index`. | `unpurged_missing_prefix_fails_validation_on_open` |
| **5** | `5a12c5c` | `heraclitus-tier` | No Windows NTFS, `remove_dir_all` de diretórios de scratch temporários podia falhar com violação de compartilhamento. | Fallback para remoção arquivo por arquivo antes da exclusão do diretório em `LimpezaDir::drop`. | Testes de ciclo de vida de compilação e teste no Windows |
| **6** | `9b0d679` | `heraclitus-crypto` | Arquivo de chave com tamanho > 32 bytes causava spin-wait desnecessário de 100ms em `get_or_create` e reportava erro de "artefacto de crash". | Detecção imediata de arquivos maiores que 32 bytes com retorno rápido (`fail-fast`) do erro original de `InvalidData: expected 32`. | `get_or_create_fails_fast_on_oversized_key_file` |
| **7** | `7b53db9` | `heraclitus-views` | Condição de laço `while cur <= head` no replay de views executava varredura vazia de I/O (`scan_capped(head, head, 256)`) na fronteira final ou em logs vazios. | Alinhamento da condição para limite superior exclusivo `while cur < head`, idêntico ao `rebuild` e à semântica canônica de `head()`. | `wipe_and_replay_is_deterministic`, `empty_view_replays_from_zero_despite_persisted_watermark` |

---

## 3. Estado das Suítes de Testes

Todas as suítes de testes dos crates afetados foram executadas e validadas:

- **`heraclitus-agent-gateway`**: 23/23 testes aprovados.
- **`heraclitus-crypto`**: 17/17 testes aprovados.
- **`heraclitus-raft`**: 24/24 testes aprovados (incluindo features de replicação e durabilidade).
- **`heraclitus-tier`**: 100/100 testes aprovados (82 testes unitários + 5 de repack + 6 de object storage + 7 de lakehouse).
- **`heraclitus-views`**: 20/20 testes aprovados (incluindo `catch_up_com_extra`, `ckpt_integridade`, `fast_boot`, `rebuild_nao_salta_buraco`, `skip_replay`).
- **`heraclitus-compliance`**: 178/178 testes aprovados.

Total: **362 testes aprovados** sem falhas ou regressões.

---

## 4. Conformidade com Especificações (SPECs)

- **SPEC-0050 (Cold Tier Immutability & Repack):**
  - Garantida imutabilidade dupla na publicação de segmentos e metadados Parquet (`put_immutable_segment`, `put_immutable_parquet`).
  - Repacks isolados em diretórios temporários atômicos por execução, eliminando interferência concorrente de arquivos scratch.
  - Recusa formal de sobrescrita de gerações compactadas legadas quando a raiz Merkle calculada diverge da raiz registrada.
- **SPEC-0074 & SPEC-0085 (Agent Evidence Gateway & In-Flight Flood):**
  - Deduplicação atômica em voo (`InFlightGuard`): evidências concorrentes com mesma chave aguardam resolução sem corromper o índice.
  - Gravação garantida: a evidência só se torna durável na memória de deduplicação após confirmação de escrita pelo `EvidenceLog`.
  - Mensagens de erro de conflito exibem a chave canônica calculada, assegurando auditabilidade forense.
- **Raft Durabilidade e Recuperação:**
  - Validação estrita da cobertura da fronteira comprometida antes de qualquer mutação ou truncamento do WAL.
  - Detecção imediata de registros ausentes ou corrompidos sem registro de purga.
- **Views e Checkpoints:**
  - Limite de varredura exclusivo alinhado (`cur < head`), evitando overhead de I/O em logs vazios ou completamente consumidos.
  - Checkpoint v1 com cabeçalho, CRC32 e integridade de formato preservada.
