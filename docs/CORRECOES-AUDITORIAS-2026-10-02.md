# Correções de auditorias — 2026-10-02

Base: `cda5ba5` (correções de 2026-10-01, ver `CORRECOES-AUDITORIAS-2026-10-01.md`). Ramo: `fix/auditorias-2026-10-02`. Esta nota não substitui a matriz anterior; regista o que esta ronda fechou e o que continua aberto.

## Método

Três revisores percorreram todas as auditorias (`AUDITORIA-GERAL-HERACLITUSDB-2026-10-01.md`, `GPT-SOL-6-1.md`, `docs/md/auditorias/boot.md`, `otimizacao-20m.md`, `append-lento-com-o-crescimento.md`, `BUGS.md`, `falta.md`, `fazer.md`, `falta_fazer.md`, `SPEC-new/AUDITORIA.md`, `AUDITORIA-PRODUCAO-FORGE-2026-08-14.md`, `AUDITORIA-2026-09-05.md`, `AUDITORIA-RECURSIVA-2026-09-05.md`, `CORRECOES-AUDITORIA-2026-09-08.md`, `SPEC-new/ROADMAP-GOV-BR.md`). Cada item foi conferido contra o código em `cda5ba5`. Itens já corrigidos não foram reabertos. Cada correção abaixo tem um teste de regressão; nas marcadas com (S), o teste foi confirmado a falhar com o código antigo reposto (sabotagem).

## Corrigido nesta ronda

| Origem | Defeito confirmado no código | Correção | Teste |
|---|---|---|---|
| F10 residual (geral 10-01) | Flight DoGet entregava o log inteiro sem token, sem RBAC e sem rasto. Com `access_credentials` era o único caminho não autenticado aos dados. | Mesmo interceptor Bearer do gRPC (papel Reader). Meta-auditoria de cada DoGet. Loopback verificado ANTES do bind. Construtor privado. | `flight_protocol.rs` |
| Encontrado na conferência | Flight abortava com um Episode acima de 16 MiB, embora a linha Arrow só leve metadados. Um append grande partia para sempre a exportação de qualquer intervalo que o incluísse. | O evento grande sai sozinho no seu lote. | `flight_nao_aborta_com_evento_maior_que_16_mib` |
| boot.md P1-C/P1-F | O `AttrIndex` era regravado inteiro (com fsync) em cada arranque e em cada checkpoint, sem eventos novos. A cauda começava no watermark inclusivo. | A cauda começa em `watermark+1`. Marca de sujo: arranque e checkpoint só gravam se houve mudança. | `attr_checkpoint_noop.rs` (S) |
| Produção exige `audit_queries` | O REST não meta-auditava nada. `/titular/:id/acessos` (LGPD art. 18) omitia os acessos REST. | Middleware de meta-auditoria (sondas operacionais excluídas). O `/sql` audita o texto SQL. | `meta_auditoria_tests` |
| SPEC-0089 §2/§6 | REST approve/deny do Sentinel gravava a aprovação sem `execute_admin` e sem `audit_admin` (o gRPC já usava ambos). | Mesmo protocolo e auditoria do gRPC. | suíte do servidor |
| F09 / A07 | `/sql` com orçamento de 256 MiB (o documentado é 128) e sem tecto de concorrência. Saída JSON clonada. | 128 MiB, semáforo de 2 (429 quando ocupado), descodificação directa para `Vec`. | `sql_tests` |
| F09/F10 (f) | Um único tecto de 256 MiB para todos os métodos gRPC. | Pedidos até 64 MiB. Tectos por campo: GQL 1 MiB, `arg` admin 1 MiB, attrs 1024 / 1 MiB. | suíte do servidor |
| falta_fazer.md:101 | NEAREST/RECALL com AS OF faziam over-fetch fixo (k×4) e devolviam menos de `k` linhas em silêncio. `k` sem tecto (u32). Hidratação antes do corte. | O fetch cresce até haver `k` sobreviventes. `MAX_TOP_K = 10 000`. Só os `k` finais são hidratados. | `nearest_as_of.rs` (S) |
| Minor (BUGS) | Um pânico no scan do catch-up do Subscribe acabava o stream como EOF limpo. | Envia erro. | suíte do servidor |
| falta_fazer.md:197-202 | Replicação aceite com `fsync=group_commit`: um crash deixava o nó sem arrancar. | `validate_security` exige `fsync = always` com replicação. | `replication_requires_fsync_always` |
| falta_fazer.md:106 | Sem override por ambiente para a replicação. | `HERACLITUS_RAFT_*` (id, addr, peers, bootstrap, transport, dirs, TLS). | `replicacao_configura_se_por_ambiente` |
| falta_fazer.md:314 | RPCs Raft (TCP e gRPC) sem timeout nenhum: um par mudo prendia o replicador para sempre. | Prazo `hard_ttl` do openraft; expira como `Unreachable`. | `rpc_a_um_par_mudo_expira_no_hard_ttl` |
| falta_fazer.md:92 | Raft gRPC criava Endpoint + TCP + handshake mTLS por RPC. | Canal em cache por ligação, largado após erro. | lib raft (feature replication) |
| Encontrado na conferência (boot.md streaming restore) | Checkpoints das views eram bincode cru (sem magic, versão nem CRC), lidos com `fs::read` inteiro. Um bit trocado descodificava em silêncio e o pico de RAM duplicava. | Formato v1: magic, versão, CRC32 e comprimento. CRC verificado em streaming ANTES de descodificar, descodificação em streaming, compatível com o formato antigo, aviso quando recusado. | `ckpt_integridade.rs` |
| Regressão de A01 | `trusted_admin.recover` decifrava o log INTEIRO em cada arranque. | Scan podado por `agent_id` (o Bloom só salta segmentos com ausência provada); varredura completa no log legado. | `reconciliacao_no_v6_com_recover_podado` |
| SPEC-0089 §9 | `AdminState::Reconciled` nunca era usado: uma operação UNKNOWN ficava presa para sempre. | `Admin op="admin-reconcile"` (desfecho + evidência + quem reconciliou), auditado e aceite pelo `recover`. | `reconciliacao_no_*` |
| Encontrado na conferência | Um `error` gravado era reportado como UNKNOWN, e o retry pedia reconciliação de uma operação já com desfecho. | Estado `Failed`; o retry devolve a falha gravada sem re-executar. | `efeito_com_erro_fica_failed_*` |
| SPEC-0089 §14 | `shred_effect` ignorava o token: um token de legal hold destruía a chave de qualquer titular. | O token leva o tipo da operação autorizada e o shred verifica-o. Gate de código: `KeyStore::shred` só é chamado do `shred_effect`. | `shred_effect_recusa_token_de_outra_operacao`, `gate_shred_unico.rs` |
| falta_fazer.md:241-244 | Schema SQL do analytics divergia do Parquet do cold tier (valid time 0 em vez de NULL; sem `parents_json`/`embedding_json`). | Alinhado com o Parquet. | `sql_group_by_over_the_log` |
| boot.md P0-D | O checkpoint segurava o lock do registry durante a serialização de TODAS as views; os appends esperavam pela soma. | Barreira e lock tomados por view e largados entre views (cada snapshot leva o seu watermark de autoridade). O JSON descreve os snapshots em disco. | suíte do servidor |
| 10-01 pendência 3 (d) | Nomes X.509 comparados por DER cru (nameConstraints, CRLs por emissor, âncoras, SID, ESS). Quebrava a interoperação e, nas subtrees EXCLUÍDAS, permitia contornar a exclusão recodificando o nome. | Comparador RFC 5280 §7.1 (tipo de string, capitalização, espaços insignificantes), com chave canónica nos mapas de CRL e âncoras. | `nomes.rs`, `testes_dn_rfc5280`, `crl_com_o_nome_do_emissor_noutra_codificacao_e_encontrada` |
| 10-01 pendência 3 (d) | `consultar` re-verificava a assinatura de todas as CRLs em cada consulta. | Cache só de sucessos, com chave = chave pública do emissor + algoritmo + tbs + assinatura. | `assinatura_da_crl_e_verificada_uma_vez_e_reaproveitada` |
| GPT-SOL §5 / 09-08 (g) | `ORDER BY <campo> LIMIT k` materializava até 250 000 episódios e recalculava a chave dentro do comparador. | Acumulador top-k (~2k candidatos), chave calculada uma vez, desempate pela ordem de chegada (igual à ordenação estável). | `top_k_e_identico_a_ordenacao_completa` |
| falta.md R13 | `resolve_lsn_from_consensus_index` O(n), sem chamadores. | Removido (e a secção do bench que o media). | — |
| BUGS.md:2311 | `Hlc::skew_ms` sem chamadores: o skew não era observável. | Gauge `heraclitus_hlc_skew_ms` em `/metrics`. | — |
| GPT-SOL §5 P2 / falta_fazer.md:81 | `GET /hvm/state` replayava o log inteiro (em janelas de 100 000 episódios) em cada pedido. | Estado em cache com cursor; só a cauda nova é aplicada; invalidado em shred, rebuild e demote; janela de 4096. | `hvm_state_incremental_e_igual_ao_replay_integral` |
| Encontrado na conferência | O padrão de relação do GQL ordenava e projetava todas as arestas candidatas, sem tecto. | O mesmo `QUERY_SCAN_CAP` do padrão de nó. | suíte de query |
| AUDITORIA-2026-09-05 §5 #7 | Um seal falhado deixava o V6 sem segmento ativo até reiniciar, e as leituras também caíam. | Seal publicado com falha a criar o seguinte: o próximo append recupera. Falha antes do commit: estado degradado com motivo (`hrkl_degraded`) e mensagem explícita. As leituras de LSN selado continuam. | `falha_a_criar_o_segmento_seguinte_recupera_no_proximo_append` (S) |
| boot.md P0/P1 | Em modo serviço só o fim de cada fase ficava no log; o replay não mostrava progresso. | Início de fase registado; progresso do replay a cada 10 s com ritmo e estimativa. | — |
| boot.md streaming restore | `attr_index.bin` lido inteiro para memória no arranque. | CRC e descodificação em streaming no formato corrente. | `attr_checkpoint_ilegivel` |
| boot.md P2 "compact text" | O restauro do índice de texto tinha três cópias das postings em memória no pico. | Checkpoint v2 (arrays por documento primeiro), descodificado diretamente para listas comprimidas e validado no caminho; o formato antigo continua a ler-se. | `checkpoint_no_layout_antigo_continua_a_restaurar`, `checkpoint_v2_com_posting_fora_de_ordem_degrada` |
| boot.md P1-C | O arranque varria e decifrava o log duas vezes (views e índice de atributos). | Uma só passagem (`catch_up_com`) alimenta os dois. | `catch_up_com_extra.rs` |
| otimizacao-20m §3.5/§3.7 | Releitura do registo acabado de escrever no `append_idempotent`; cópia profunda de cada episódio para a memtable; `format!` por atributo por evento no grafo. | Id do próprio Episode; posse passada à memtable; chave montada num buffer e alocada só quando é nova. | suíte do servidor, `heraclitus-index-graph` |

## Revisão adversarial desta ronda (2026-10-03)

Depois dos commits acima, uma revisão independente só de leitura reviu as alterações por áreas (Flight/REST, gRPC/engine/query, Raft/checkpoints, X.509, top-k, administração, engine/boot, armazenamento). Cada achado foi testado por três refutadores com critérios diferentes (correção, reprodução, impacto/pré-existência). Resultado: 23 achados levantados, **14 confirmados**, 9 refutados. Os 14 foram todos corrigidos com teste de regressão:

| Gravidade | Defeito (nos commits desta ronda) | Correção |
|---|---|---|
| crítico | `admin-reconcile` reutilizava a chave do ALVO como chave da própria reconciliação. Com um alvo inexistente, gravava dois resultados para a mesma chave e o arranque seguinte recusava o diário: o servidor deixava de arrancar. | Chave própria derivada do alvo; o protocolo recusa reconciliar a operação em execução. (S) |
| alto | `reconcile` confiava no diário em memória (reservas sem intenção no log; resultados que entraram mas reportaram falha) e gravava resultados órfãos ou duplicados. | Consulta o diário no LOG: sem intenção recusa; com resultado, adota-o. |
| médio | Quem pediu a operação não conseguia reconciliá-la (conflito de digest). | Chave derivada. (S) |
| médio | Sob GroupCommit (o default), o worker de fsync convertia o segmento pendente num `sync_error` permanente que bloqueava escritas e leituras. | O seal já faz fsync: `dirty` é limpo antes de tentar o segmento seguinte, e o worker não envenena o motor sem segmento ativo. (S) |
| médio | O tecto do padrão de relação contava as arestas candidatas antes do WHERE e do LIMIT. | Conta as que passam o filtro; sem ORDER BY, o LIMIT corta antes. |
| médio | O texto da meta-auditoria REST usava o caminho codificado e omitia a query: titulares com caracteres codificados não apareciam no relatório de acessos. | Caminho e query descodificados. |
| médio | Um cliente que desligasse a meio contornava a meta-auditoria REST (o efeito corre em `spawn_blocking`). | Handler e auditoria correm numa tarefa desacoplada do pedido. |
| médio | Aprovações do Sentinel pelo REST passaram a ser recusadas em cluster (o `execute_admin` recusa em nós replicados). | Em cluster mantém-se o caminho anterior, com meta-auditoria. |
| baixo | Approve/deny recusados antes do protocolo não deixavam auditoria. | O middleware audita-os. |
| baixo | O Flight auditava `ok=true` antes da admissão (um "Flight busy" ficava registado como leitura). | Auditoria depois da admissão. |
| baixo | `CABECALHO + corpo` do checkpoint podia transbordar (pânico com `overflow-checks`). | `checked_add`. |
| baixo | Três testes não provavam o que diziam: pré-bind do Flight, tecto de `k` e cache de CRL. | Mensagem pré-bind distinta e testada; teste da cache conta chamadas ao verificador; comentário do tecto de `k` corrigido (não é medido). |

O caso do cliente que desliga não tem teste automático: provocar o EOF a meio do handler de forma determinística exige controlo do socket que os testes atuais não têm.

Corrigido depois da primeira ronda, e revisto nas rondas seguintes:

- **Índice de offsets do segmento ativo V6** (`05814c2`): a leitura pontual vai direta ao registo.
- **`AppendBatch`** (`7185faf`): vários appends numa só ida e volta.

**Segunda ronda** (sobre as correções e os commits novos): 5 confirmados, todos corrigidos em `bb9b010`.

- A chave da reconciliação derivada só do alvo bloqueava para sempre um alvo depois de uma tentativa falhada. Agora há validação antes da intenção e a chave é o hash do pedido completo.
- Dentro de um lote, as dimensões de embedding misturadas eram aceites com o índice vazio.
- A validação do lote não incluía as regras do engine nem chaves repetidas (`Engine::validar_append`).
- Em estado degradado, as varreduras omitiam em silêncio LSN confirmados mas não catalogados. Agora falham alto.

**Terceira ronda:** 1 confirmado, de gravidade baixa. O relatório de acessos do titular engolia o erro de varredura e respondia 200 com uma lista vazia. Agora responde 503 e indica o erro (`55d67cb`).

**Quarta ronda** (fecho, sobre `55d67cb`): 0 confirmados. Os dois levantados foram refutados por 3/3: o limite de 100 resultados do relatório é intencional, e o 503 também cobre um `JoinError`. A revisão convergiu.

## Continua aberto (não declarar encerrado)

1. **Exige decisão ou infraestrutura externa:** HSM/PKCS#11 e atestação de destruição; ACT credenciada e raízes ICP-Brasil oficiais; bucket WORM; homologação institucional e RIPD; cluster real (reconciliação administrativa distribuída, `/tier/demote` com store partilhado, que também é recusado pelo `execute_admin` em nós replicados); soak de 20 M em hardware alvo.
2. **Arquitetura (L):**
   - teto global, evicção e spill dos índices residentes;
   - snapshots fora de lock (COW);
   - snapshot Raft em streaming;
   - provas de inclusão HRKL no pacote forense e integração do `heraclitus-forensic` como export/verify de produção;
   - árvore completa de políticas X.509 (RFC 5280 §6.1) e normalização NFKC completa da RFC 4518.
3. **Código médio ainda por fazer:**
   - verificação do seal V6 fora do mutex do writer (hoje relê o segmento três vezes no seal);
   - reparação a quente de um seal falhado antes do commit (hoje degrada e exige arranque, por desenho);
   - `Arc<Episode>` ponta a ponta (o log ainda clona uma vez no `append_stamped`);
   - compactação do cold tier v6;
   - distill em cluster;
   - AAD do AEAD com `event_id` (exige versão de formato);
   - `MemoryBudget`/cancelamento no motor de query;
   - catch-up por interesse (uma view nova ainda força replay desde 0).
4. **Decisão do dono:**
   - política four-eyes: que operações exigem dois aprovadores, se o modo de produção a torna obrigatória, e onde fica a aprovação durável;
   - Miri/Loom na CI: exige descarregar o componente; o `unsafe` real (mmap, io_uring, memória da plataforma) é FFI que o Miri não executa.

## Validação

- Por crate: core, log (lib e integração), views, attr, vector, text, graph, activation, telemetry-health, analytics, compliance, query, servidor (com `analytics`) e raft (lib com `replication`). Os resultados finais estão na mensagem de cada commit.
- `cargo fmt --all -- --check` limpo. Clippy com `-D warnings -D clippy::debug_assert_with_mut_call` nos crates alterados, com as features `analytics` e `replication`; o `--all-features` da CI inclui features dependentes de plataforma (io_uring, GPU) que não correm neste Windows.
- Teste de sabotagem (o teste falha com o código antigo reposto) feito nas correções marcadas (S).
- **Não executados nesta sessão:** testes de integração do raft e do servidor com a feature `replication`, cuja execução foi bloqueada pelas permissões do ambiente. Têm de ser corridos antes de integrar.
- Compilações feitas sem informação de debug e sem compilação incremental, por falta de espaço em disco. Nenhum serviço instalado foi reiniciado e nenhum dado de produção foi usado.
