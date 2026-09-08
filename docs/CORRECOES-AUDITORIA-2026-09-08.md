# Correções da auditoria parcial — 2026-09-08

Base: `e669f7794e2065decf3434819d2748cc1b0390ff`. Alterações locais; sem commit, push ou deploy nesta fase.

## Alcance e honestidade

Este documento fecha as correções dos problemas confirmados na inspeção parcial. **Não certifica a leitura integral dos 336 arquivos Rust inventariados (162.850 linhas)** nem ausência de outros defeitos. O inventário é um registro de arquivos e hashes, não cobertura de revisão. O relatório original está em `D:/DEV/audits/heraclitusdb-2026-09-08-e669f77/RELATORIO-PARCIAL.md`.

## Alterações implementadas

| Área | Problema e correção | Limite/contrato |
| --- | --- | --- |
| Query | Varredura por páginas de LSN; filtros antes do limite de resultados; detecção de excesso em backends e atalhos; ordenação não usa mais um prefixo silenciosamente truncado. | Acima do teto de resultados intermediários a consulta retorna erro explícito; não foi implementado top-k global para toda ordenação. |
| Query | União dos postings de kinds ASCII-case-insensitive; fallback para labels não indexáveis no servidor. | Não é normalização Unicode de labels. |
| Query | `ts_hlc` reconhecido como campo nativo; limites LSN fracionários/negativos não recebem pushdown inexato; `recall(0)` vazio. | Limites não representáveis com segurança permanecem no filtro. |
| Query | `ORDER BY` resolve a variável: extremidades `.id` viram `from`/`to`; variável desconhecida é rejeitada. | Propriedades de extremidades não suportadas geram erro. |
| Btree | Leituras de geração histórica rejeitadas em vez de devolver folhas atuais; contador de snapshots protegido por RAII. | `get_snapshot` aceita apenas a visão atual (`u64::MAX`); isto não implementa MVCC histórico da árvore. |
| Sentinel L1 | Todas as ocorrências são processadas, com deduplicação por identidade do sinal. | Testes e fixture de baseline atualizados para a semântica correta. |
| Sentinel temporal | Horizontes aninhados são somados com saturação. | Inclui regressão com evidência necessária fora do antigo horizonte máximo. |
| Ações externas | Restrições autorizadas conferidas contra o registro persistido; tentativa durável antes do efeito; resultado reutilizado; tentativa ambígua impede repetição inclusive após reinício; identidade do dono da tentativa conferida após append. | Resultado ambíguo requer reconciliação. Não oferece exactly-once em sistemas externos arbitrários; o destino deve persistir idempotência e o host distribuído deve deduplicar globalmente. |
| Sigma | `logsource` não vazio é rejeitado explicitamente, pois não há mapeamento implementado. | Mudança intencional de compatibilidade: não remover restrições de uma regra apenas para fazê-la compilar. |
| Crypto | Chave e diretório sincronizados antes de publicar chave no cache, incluindo abertura/concorrência entre instâncias. | Sem simulação física de perda de energia nesta fase. |
| GroupCommit | Legacy e V6 sincronizam cauda suja mesmo sem novos appends; V6 registra falha da sincronização e bloqueia operações subsequentes. | ACK GroupCommit não equivale a durabilidade imediata; usar Always ou flush para barreira explícita. |

## Candidato sem correção especulativa

A ausência de `begin_indexing` no callback Raft não demonstrou, isoladamente, o buraco de watermark suspeitado: a aplicação examinada é serializada e checkpoints usam watermarks próprios das materializações. Nenhum patch especulativo foi aplicado. Isto não prova segurança de todas as interleavings, snapshots ou mutações do cluster; a hipótese exige reprodução adicional.

## Validação executada

Com Rust local, dependências travadas e `--target-dir D:/DEV/HeraclitusDB/target --jobs 2`:

- Testes unitários: btree 17; crypto 7; log 228; query 63; sentinel 262 — **577 aprovados**.
- Servidor com `--features replication --lib`: **85 aprovados**.
- Integrações dedicadas: `historical_reads` (1), `audit_semantics` (3) e `execution_once` (3; incluindo tentativa concorrente retornada pelo sink): **7 aprovados**. Total das execuções acima: **669 testes aprovados**.
- Clippy dos seis pacotes afetados, servidor com replication e `--all-targets -- -D warnings`: aprovado, inclusive após a última regressão adicional.
- `cargo fmt --all -- --check` e `git diff --check`: aprovados. Git emitiu apenas avisos de conversão LF/CRLF.

Comandos reproduzíveis (PowerShell, na raiz do projeto):

```powershell
cargo test --locked --target-dir D:/DEV/HeraclitusDB/target --jobs 2 -p heraclitus-query -p heraclitus-sentinel -p heraclitus-btree -p heraclitus-crypto -p heraclitus-log --lib -- --test-threads=2
cargo test --locked --target-dir D:/DEV/HeraclitusDB/target --jobs 2 -p heraclitus-server --features replication --lib --quiet -- --test-threads=2
cargo test --locked --target-dir D:/DEV/HeraclitusDB/target --jobs 2 -p heraclitus-sentinel --test execution_once -p heraclitus-query --test audit_semantics -p heraclitus-btree --test historical_reads
cargo clippy --locked --target-dir D:/DEV/HeraclitusDB/target --jobs 2 -p heraclitus-server --features replication -p heraclitus-query -p heraclitus-sentinel -p heraclitus-btree -p heraclitus-crypto -p heraclitus-log --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Não executados: suíte release completa, todas as features do workspace, qualificação GPU/Linux, falhas físicas de disco/energia e teste distribuído real de troca de líder durante efeito externo. Nenhum serviço ou dado de produção foi alterado.

A memória automática não pôde ser gravada: `D:/DEV/scripts/Codex-mem.cmd` não existe neste ambiente. Não foi criado arquivo substituto de memória nem iniciado serviço.
