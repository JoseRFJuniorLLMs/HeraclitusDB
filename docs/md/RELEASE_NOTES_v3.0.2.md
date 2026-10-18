# HeraclitusDB v3.0.2 — Integridade do log, grafos, consultas e replicação

**Data:** 2026-10-18  
**Linha:** 3.x

Esta versão corrige os achados das duas auditorias de 16/10/2026: a auditoria
do motor (B1–B6, B9, R1) e a auditoria GPT de grafos, consultas e índices
(G1–G7). Também repõe verde o CI de cadeia de suprimentos e do SDK Python.

## Correções

### Log canônico (HRKL v6 e legado)

- **B1:** um bit trocado a meio da cauda ativa já não apaga registros
  confirmados. O arranque só trunca uma escrita realmente interrompida: o frame
  no rasgo passa do EOF e não há registro íntegro depois dele com o LSN
  seguinte, nem footer íntegro no EOF que declare esse LSN. Qualquer outro caso
  é `Corruption`, com o arquivo preservado. Vale para o V6 e para o segmento
  ativo do legado.
- **B2:** um RAW selado corrompido já não faz `scan` devolver `Ok` com buraco
  nem `read` devolver `Ok(None)` para LSN confirmados. O percurso RAW diz por
  que parou. Um selado tem de chegar ao footer com a sua contagem de registros.
  A janela de um scan abaixo do head tem de ser contígua, e a varredura
  filtrada (diário administrativo) também confere os RAW selados e a cauda.
- **B5:** uma escrita interrompida cujo payload traz uma imagem de footer volta
  a recuperar, em vez de recusar o arranque para sempre.
- **B6:** um segmento corrompido já não trava as filas de packing e de sidecar
  HRKI. Cada falha é registrada com o segmento, os demais continuam e o
  primeiro erro é devolvido no fim da passagem. O packer deixou de diagnosticar
  um CRC como "segmento por selar".

### Replicação

- **B3:** episódios replicados já não são gravados com `ts_hlc = 0`. O líder
  põe o seu relógio na entrada e a máquina de estados carimba no apply
  `max(ts_anterior + 1, relógio_da_entrada)`, igual em todos os nós. `AS OF
  TIMESTAMP` dá o mesmo resultado num nó autônomo e num cluster.

### Grafos, consultas e índices

- **G1:** relações usam uma identidade `e2` com comprimentos dos componentes em bytes. Delimitadores e Unicode deixam de provocar colisões de topologia, hipóteses e retrações.
- **G2:** cada período transacional de uma relação conserva sua própria validade do mundo. `MATCH ... VALID AT ... AS OF ...` e os LSNs de `NEIGHBORS` consultam o mesmo período histórico.
- **G3:** fingerprint temporal v2 inclui validade do mundo atual e arquivada, política, hipóteses, mapeamentos e métricas; strings, coleções e `Option` têm codificação delimitada.
- **G4:** comparações e ordenação GQL preservam inteiros nativos e literais grandes. HLCs adjacentes, limites de `u64`, `ASC`/`DESC` e `LIMIT` deixam de ser confundidos pela conversão para `f64`. Ranges sem representação exata recuam para scan.
- **G5:** igualdades com espaços externos recuam para o scan canônico. O índice continua sendo uma otimização; o resultado mantém a semântica exata do valor gravado.
- **G6:** `_agent` e `_kind` são reservados na ingestão pública e ignorados como atributos do cliente durante replay. Relatórios por titular revalidam o `agent_id` canônico dos postings.
- **G7:** tombstones vetoriais registram o LSN da primeira retirada. HNSW, busca exata e candidatos da memtable usam a mesma regra temporal: em `AS OF LSN b`, a retirada só se aplica quando `tombstone_lsn < b`.

### CLI `heraclitus top`

- **B4:** removido o fallback que, em erro de conexão, repetia o pedido em
  HTTP claro para o `nameserver` de `/etc/resolv.conf`, com a credencial de
  administração.
- **B9:** um 401 passa a ser erro. Acabou a escalada silenciosa para
  `security-admin`, a leitura implícita de tokens por variáveis de ambiente ou
  arquivos, e os caminhos de segredos de desenvolvimento embutidos.
- **R1:** a tabela de provas formais deixou de ser fixa no código. O estado vem
  de `--proof-status <json>` (schema `heraclitus.proof-status.v1`); sem esse
  arquivo, tudo aparece como `NOT_VERIFIED`.
- **Falso-verde:** métricas de storage e contadores de falha do Sentinel
  ausentes aparecem como `N/D`/`UNKNOWN`, não como 0.

### Cadeia de suprimentos e SDK

- `quinn-proto` 0.11.19 e `rustls` 0.23.46 corrigem RUSTSEC-2026-0338 a 0342 e
  0346 a 0349 (exaustão de memória e panics no QUIC; dados após rejeição ECH e
  descompressão Brotli de certificados antes da autenticação no TLS).
- SDK Python: stubs gRPC regenerados com o RPC `AppendBatch`.

## Atualização e compatibilidade

- O log canônico não muda de formato. **Mas o arranque fica mais estrito:**
  uma cauda corrompida a meio, uma cauda zerada a partir do rasgo e um `.active`
  selado com o comprimento do último registro estragado passam a recusar o
  arranque com `Corruption`, sem alterar bytes, em vez de truncar. Restaure o
  segmento de backup ou de uma réplica. Se o erro indicar uma imagem de footer
  forjada no payload (a mensagem cita `a valid footer at EOF`) e o último
  registro não foi confirmado, corte o arquivo no offset do rasgo indicado.
- `scan`, `read` e a varredura filtrada passam a devolver `Corruption` onde
  antes devolviam `Ok` com linhas a menos ou `Ok(None)`. Consumidores que
  tratavam essas respostas como "não existe" passam a ver o erro.
- Os checkpoints derivados de atributos anteriores a v7, do grafo anteriores a `HTGR0002` e vetoriais sem a versão temporal 2 são recusados e reconstruídos por replay automático. O primeiro arranque pode demorar mais.
- IDs de relações e fingerprints temporais mudam de versão. Consumidores que guardam esses IDs devem voltar a consultá-los a partir da tupla origem/destino/tipo. Não compare fingerprints das duas versões como se usassem o mesmo schema.
- O tipo Rust `Edge.closed_intervals` passa a conter `EdgeInterval`, com transaction time e valid time. O AST adiciona a variante `Int` para literais exatos; consumidores Rust com matches exaustivos precisam tratar a variante.
- A API `tombstone_event` mantém a retirada imediata; ingestão temporal usa `tombstone_event_at`. Buscas históricas estão disponíveis por `search_as_of` e `search_exact_as_of`.
- Replicação (feature `replication`): **não faça atualização nó a nó.** As
  entradas novas levam o relógio do líder num envelope à frente do episódio, e
  um nó 3.0.1 não as consegue descodificar (o apply para com erro). Pare o
  cluster, atualize todos os nós e só então volte a arrancar. Um nó 3.0.2 aplica
  normalmente as entradas antigas, sem envelope, que já estejam no raft-log.
- `heraclitus top`: quem dependia da escalada automática para
  `security-admin` tem de passar a credencial explicitamente (`--pass-file`).
  A tabela de provas exige `--proof-status`.

## Fora desta versão

- **B7:** o trabalho "verificação do seal fora do mutex" em
  `heraclitus-log/src/v6/engine.rs` não compilava e não entra; está guardado no
  ramo `wip/checkout-principal-2026-10-18`.
- **B8, B10–B13** e as otimizações **O1–O10** da auditoria do motor continuam
  abertos (detalhe em `docs/AUDITORIA-2026-10-16.md`).
- A fila de exportação Parquet (`heraclitus-tier`) ainda interrompe no primeiro
  segmento com erro, o mesmo padrão corrigido no B6 para packing e HRKI.
- `heraclitus top` ainda tem um default de credencial fixa
  (`--user admin --pass ...`) e não há job de CI que gere o `proof-status.json`.

## Validação

- Regressões: `crates/heraclitus-log/tests/hrkl_v6_bitrot_nao_trunca.rs` e
  `bitrot_nao_trunca.rs` (B1, B2, B5, B6), `heraclitus-raft` (B3),
  `heraclitus-cli` (B4, B9, R1) e
  `crates/heraclitus-{index-graph,query,server}/tests/regressao_gpt_2026_10_16.rs`
  (G1–G7). As de B1–B6 e B3 falham com o código antigo reposto e com cada peça
  da correção sabotada (`docs/CORRECOES-AUDITORIA-2026-10-16-B1-B2-B5-B6.md`).
- Os resultados locais (Windows) e do CI (Linux) desta versão estão no
  [relatório de validação](VALIDACAO_v3.0.2.md). A publicação de código-fonte
  não substitui a qualificação dos binários produzidos pelo workflow de
  release.
