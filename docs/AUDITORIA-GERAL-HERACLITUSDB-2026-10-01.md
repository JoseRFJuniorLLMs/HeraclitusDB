# Auditoria geral do HeraclitusDB — 01/10/2026

Projeto: `D:\DEV\HeraclitusDB`. Commit: `e354a99c0651438981722600ddb5a0801a5c530d`. Versão: 3.0.1. Data no fuso America/Sao_Paulo.

**Conclusão:** há auditorias com correções ainda pendentes. A auditoria mais recente está na raiz (`GPT-SOL-6-1.md`), foi adicionada pelo último commit e continua aplicável: suas seis reproduções de defeitos passaram novamente contra os fontes atuais. Em `docs/md`, as pendências mais relevantes para RAM estão em `auditorias/boot.md` e `auditorias/otimizacao-20m.md`, mas vários trechos antigos já foram superados pelo código. Esta rodada também confirmou uma fuga de diretório por junction e identificou omissão dos pais causais no hash de idempotência.

O primeiro bloqueio é a ordem das operações administrativas destrutivas: falta ligar um protocolo de intenção durável antes do efeito. Para RAM, os alvos prioritários são materialização de SQL/Flight, checkpoints integrais e retenção de histórico/índices em memória.

## Alcance e método

- Inventário por `rg --files`: 395 arquivos Rust e 87 arquivos Markdown em `docs/md`, com filtros excluindo target, graphify-out e node_modules. É inventário, não leitura integral de cada arquivo.
- Revisão orientada a risco: documentação de auditorias, configuração, servidor gRPC/REST, administração, crypto, forensic, analytics/Flight, log legado/V6, views, índices, memtable, telemetria e inicialização Sentinel. Evidências com hash de 25 fontes consultados acompanham a entrega; outros trechos também foram consultados.
- Grafo existente de 05/09 usado para navegação. Seu Python registrado não executou por acesso negado; vocabulário e travessia foram consultados em PowerShell. Tokens: auth, memory, cache, append, replay, tenant, security, audit, snapshot, scan, query, bounded. As conclusões abaixo foram conferidas nos fontes atuais, pois o grafo é anterior ao commit auditado.
- Reproduções executadas em projeto isolado dentro desta conversa, com dependências locais e lock da evidência anterior. Builds, testes e dados temporários ficaram em `work/`. Nenhum serviço instalado, dado de cliente, configuração de produção ou código do repositório foi alterado.
- P0: bloqueio de garantia administrativa essencial. P1: falha relevante de segurança, correção ou disponibilidade. P2: melhoria de escala/manutenção. Essas prioridades não são pontuações CVSS.

## 0. O que já foi auditado e ainda falta no código

| Documento | Conferência no código atual | Situação |
|---|---|---|
| `GPT-SOL-6-1.md`, 01/10, na raiz | Último commit adicionou somente relatório e ZIP; seis diagnósticos de defeitos continuam reproduzíveis | **Pendente:** A01–A08 da auditoria, com alcances descritos abaixo |
| `docs/md/auditorias/boot.md` | `VectorIndex::save_checkpoint` clona o índice; texto expande postings; registry checkpointa todas as views; telemetria retém histórico | **Pendente:** reduzir pico do checkpoint, dirty/incremental, serialização fora de locks e estado de telemetria materializado |
| Mesmo `boot.md` | V6 possui scan por segmento e `scan_lsn_range`; registry mantém nomes/watermarks em vetores; snapshot restaurado é autoridade | **Já tratado no código:** não reabrir essas críticas antigas como ausências atuais |
| `docs/md/auditorias/otimizacao-20m.md`, 19/08 | Texto usa delta-varint em RAM; atributos internam strings; defaults usam 8 MiB; CRC hardware e leitura posicional presentes | **Parcialmente superado:** compressão/internação já existem; spill/budgets gerais e checkpoint econômico continuam oportunidades |
| `docs/md/auditorias/append-lento-com-o-crescimento.md`, 16/08 | Default é 8 MiB; COW integral ainda existe no log legado | **Mitigação aplicada:** não recomendar novamente trocar 256 por 8 MiB; índice em blocos legado permanece melhoria |
| `docs/md/SPEC-new/SPEC-0072-Incremental.md` | Header ainda PROPOSED, mas boot do Sentinel possui recovery/snapshot/cursor e referências explícitas à SPEC | **Documento atrasado:** proposta antiga não prova ausência da implementação atual; qualificação completa não foi reexecutada |
| `docs/md/AUDITORIA_RECURSIVA_R10_HERACLITUS_SPEC_VERIFY.md` | Afirma ausência de manifesto/workspace/CI; raiz atual tem Cargo.toml, Cargo.lock e workflows | **Achado antigo superado:** bloqueio de workspace não se aplica a este checkout |
| `docs/AUDITORIA-2026-09-05.md` e `docs/AUDITORIA-RECURSIVA-2026-09-05.md` | KeyStore tem lock compartilhado/exclusivo e recusa chave zero; B-tree protege split de slots internos; testes crypto de shred passaram | **Reparos encontrados:** não confundir antigos bugs do KeyStore com os novos bugs de SoftwareKeyProvider |
| `docs/CORRECOES-AUDITORIA-2026-09-08.md` | DDL/DML SQL bloqueados; query/GroupCommit e checkpoints contêm os reparos descritos nos caminhos consultados | Correções documentadas existem; top-k global e demais limites continuam explicitamente fora de algumas garantias |
| `docs/md/SPEC-new/ROADMAP-GOV-BR.md` | Protocolo 0089 não integrado a shred/hold; busca por 0086–0091 não encontrou entradas em STATUS.md | **Pendente:** integração e matriz de estado. O roadmap corretamente se declara desenho, não produto concluído |

Não foi revalidado cada item de todas as auditorias antigas. A tabela indica somente os itens confrontados nesta rodada. Data de arquivo não foi tomada como prova de implementação.

## 1. Memória: o que otimizar primeiro

| Ordem | Problema atual / evidência | Mudança recomendada | Gate de validação |
|---|---|---|---|
| 1 | SQL: `analytics/src/lib.rs:143,221,246` acumula colunas, usa SessionContext padrão e coleta todos os resultados; `server/src/rest.rs:1421` testa 10 mil linhas depois | Pool de memória limitado, admissão global, spill, streaming e limites por bytes/linhas durante produção do resultado. Orçamento também para sort/join/aggregate | RSS máximo e p99 com joins, resultados grandes, concorrência e cancelamento |
| 2 | Flight: `server/src/flight_grpc.rs:66` chama scan de todo o log antes do stream | Produtor paginado, canal limitado, backpressure, cancelamento e limite por bytes | Primeiro batch antes do fim da leitura; RAM proporcional à janela, incluindo cliente lento |
| 3 | Checkpoints: `index-vector/src/lib.rs:658` clona nodes/ids/lsns e cria buffer serializado; `index-text/src/lib.rs:671` descomprime postings; `views/src/lib.rs:34` serializa em Vec | Serialização progressiva, preservar compressão em disco quando adequado, dirty/generation por view e snapshots consistentes capturados sob lock curto | RSS durante checkpoint e p99 de append; igualdade após crash/restart e replay |
| 4 | Memtable: `memtable/src/lib.rs:36` limita por contagem; `core/src/config.rs:715` default 100 mil; `server/src/engine.rs:725` clona Episode | Limite adicional por bytes e tamanho de evento, ajuste da capacidade à carga, compartilhamento seguro de Episode. Pruning só quando watermark realmente garante indexação | Read-your-own-writes e igualdade de consultas; RSS com conteúdos pequenos/grandes |
| 5 | Telemetria: `telemetry-health/src/lib.rs:803,930,989` retém envelopes, reprocessa histórico e serializa todos novamente | Estado atual incremental por sensor, checkpoints históricos e replay de cauda; histórico canônico no log | Consulta de estado atual independente do total histórico; AS OF equivalente |
| 6 | Índices derivados continuam residentes; texto comprimido e atributos internados não significam spill ou teto global | Política configurável de indexação de campos/kinds, partes frias em disco e cache com teto. Primeiro medir bytes por índice e cardinalidade | Mesmos resultados/recall; memória controlada com alta cardinalidade e longas retenções |
| 7 | HNSW usa marcas de visita por thread: `index-vector/src/lib.rs:81,127`; marca custa 4 B por nó por thread que toca no índice | Scratch pool limitado ou estruturas proporcionais ao conjunto visitado, se benchmarks justificarem | Ex.: 20M nós implicam 80 MB de marcas por thread, antes de nodes; preservar recall e latência |

**Cuidado com números históricos:** `otimizacao-20m.md` mediu aproximadamente 2,02 KB/evento com views em agosto. O texto e os atributos mudaram desde então; não usar essa taxa como consumo atual. A carga de 20M mediu o log legado e GroupCommit, não o default V6 atual com fsync Always. Não foi medido RSS nesta rodada e não há promessa de porcentagem de economia.

**Infraestrutura versus integração:** `core/src/runtime.rs:575` já possui `MemoryBudget`. Busca por MemoryBudget/ExecutionSandbox/try_reserve em server e analytics não encontrou consumo desses mecanismos; sua existência no core não impõe orçamento aos caminhos SQL/Flight descritos.

**Limites de mensagens:** gRPC aceita até 256 MiB (`server/src/lib.rs:367`), além de alocações de decode/indexação. Não é RAM máxima do processo. Avaliar teto por método/evento e admissão antes de cargas caras; não apenas aumentar ou diminuir um número sem medir.

## 2 e 3. Bugs e segurança

### F01 — P0: efeito administrativo antes de intenção durável

Fontes: `server/src/grpc.rs:291,467,481`; `server/src/engine.rs:756,780,2041`; `server/src/rest.rs:1263`; `server/src/trusted_admin.rs:303`.

Admin aplica RBAC, executa e depois chama audit_admin, que pode somente registrar warning se append falhar. REST de eliminação chama shred. O protocolo novo é instanciado no Engine, mas não está ligado a essas operações. Não foram encontrados consumidores produtivos de validate/create_execution_token/record_completion ou um execute_admin. O marcador de rebuild e eventos Legal Hold têm funções reais, mas não substituem intenção administrativa autorizada, durável e reconciliável.

Correção: executor único com autorização, intenção fsync/quórum antes do efeito, reserva de idempotência, token ligado à operação, resultado durável e recuperação de UNKNOWN no boot. Testar crash em cada transição. Fsync Always e auditoria ligada não corrigem a ordem efeito → registro.

### F02 — P1: digest e validação do protocolo administrativo incompletos

Fontes: `trusted_admin.rs:161,311,378,414,424`.

O digest omite parameters_digest/política e concatena strings sem comprimento. Reproduzido: operação/idempotência `ab/c` e `a/bc` têm o mesmo digest quando o restante é igual. validate aceita Reader sem política de aprovação; token público aceita LSN arbitrário; active_operations insere por operation_id mas consulta/remove por idempotency_key. Estado fica em RAM e validate não reserva operação em andamento.

Correção: estrutura canônica completa com separação de domínio; políticas e identidade resolvidas pelo servidor; idempotência durável e atômica; token emitido somente depois da confirmação de persistência. **Não foi demonstrado bypass remoto do RBAC atual:** esse módulo ainda não é a barreira dos handlers.

### F03 — P1: rotação e destruição atingem a chave errada

Fontes: `crypto/src/provider.rs:288,393,422,437`.

SoftwareKeyProvider mantém uma master key por tenant. Rotate substitui a chave e perde unwrap histórico; destroy remove por tenant, ignorando a identidade/época da referência antiga. As duas falhas foram reproduzidas novamente.

Correção: resolver a referência completa `(tenant,key_id,epoch)`, conservar épocas autorizadas e destruir somente a referência exata; evitar corridas entre chave e época. Provider é de desenvolvimento/teste e não foi encontrado como substituto do KeyStore do servidor. Não atribuir essa perda histórica à implementação produtiva sem demonstrar integração.

### F04 — P1: metadados do envelope não autenticados automaticamente

Fontes: `crypto/src/provider.rs:188,251`.

Alterar tenant, key_id, época e algoritmo conserva a decifragem quando chave e AAD externo são iguais. Diagnóstico reexecutado. Correção: header canônico no AAD e rejeição de algoritmo/referência divergentes, com versionamento explícito. Não foi provada decifragem entre tenants que possuam chaves diferentes.

### F05 — P1: sucesso do verificador não comprova origem, assinatura ou timestamp

Fontes: `forensic/src/verifier.rs:56`; `forensic/src/package.rs:87`; `forensic/src/manifest.rs:4`.

verify aceita pacote com assinatura/token inválidos, prova merkle.json nem sequer JSON, raiz SHA-256 inválida e leaves_count incoerente. manifest.sha256 pode faltar. Reproduzido. Hashes internos verificam consistência de algumas partes, mas não autenticam o emissor; o compromisso dos hashes de objetos não é prova de inclusão no HRKL.

Correção: resultados por verificação e perfis estritos; checar assinatura/timestamp com âncoras de confiança apropriadas, esquema, tamanho e provas reais. O crate forense novo não foi encontrado integrado como export/verify produtivo do servidor/CLI na rastreabilidade desta rodada.

### F06 — P1: cadeia de custódia aceita segunda gênese e não vincula terminal

Fontes: `forensic/src/manifest.rs:104`; `forensic/src/verifier.rs:144`.

compute_hash omite terminal_or_node. Segunda entrada step_index=0 pode ter predecessor arbitrário; ordem sequencial não é exigida. Diagnóstico reexecutado. Correção: serialização canônica completa, gênese única, índices consecutivos, encadeamento e regras temporais explícitas. SHA-256 externo confiável do arquivo detectaria mutação isolada; o defeito não é quebra desse hash.

### F07 — P1: fuga de diretório por junction — hipótese anterior agora reproduzida

Fontes: `forensic/src/verifier.rs:29,93`; `forensic/src/package.rs:51,62`.

A validação só examina componentes lexicais. Em teste Windows, `package/linked` foi uma junction para diretório irmão `outside`, ambos criados para a sonda. add_object_data/build escreveu `outside/object.bin`, e verify aceitou a leitura desse objeto. Caminho relativo válido não garante confinamento real.

Impacto: pacote/diretório controlado por atacante pode redirecionar leitura e escrita para fora da raiz, dentro das permissões do processo. Não foi demonstrada exposição remota ou exfiltração por endpoint; teste não acessou arquivos existentes do usuário.

Correção: abertura confinada à raiz por handles e rejeição de reparse points/links ao longo do caminho, protegendo também contra troca entre checagem e uso. Testar links de arquivo/diretório e corrida. canonicalize isolado não fecha TOCTOU. Impor budgets de bytes e contagem e hash por streaming; fs::read de objetos também permite picos grandes.

### F08 — P1: idempotência ignora pais causais — achado adicional por fluxo estático

Fontes: `server/src/grpc.rs:116,128`; `server/src/engine.rs:2344–2379`; `core/src/event.rs:90`.

gRPC aceita parents e encaminha o Episode a append_idempotent. O hash canônico contém agent/session/kind/content/embedding/attrs/valid_from/valid_to, mas omite parents. Com a mesma chave e demais campos iguais, mudar a proveniência ainda satisfaz a comparação e retorna o LSN antigo com deduplicated=true, em vez de conflito. Os pais novos são silenciosamente ignorados.

Correção: incluir parents na identidade do pedido e definir se sua ordem é semanticamente relevante. Testar troca/inclusão/remoção de pais e restart. Como a mudança altera hashes de idempotência já persistidos, definir compatibilidade/migração; não apenas trocar o cálculo e quebrar retries antigos. **Não foi executada reprodução pelo Engine nesta rodada:** conclusão baseada no caminho completo lido, não no teste feliz antigo de alteração de content.

### F09 — P1: SQL tem orçamento de entrada, mas execução/saída sem teto efetivo

Fontes: `analytics/src/lib.rs:143,173,221,246`; `server/src/rest.rs:1374,1411,1421`.

REST admite 2M linhas/~256 MiB, porém bytes são estimados e conferidos depois de janelas de 50 mil. collect e JSON acumulam saída inteira antes da checagem de 10 mil resultados. Joins podem expandir a saída; consultas simultâneas multiplicam materialização e intermediários. Timeout SQL não cobre construção da tabela. Não foi executado teste de OOM.

Correção detalhada na seção de memória. DDL/DML já são bloqueados por SQLOptions: não reportar a antiga leitura arbitrária por CREATE EXTERNAL TABLE como falha atual. Analytics é feature opt-in.

### F10 — P1: Flight carrega todo o log e não compartilha autenticação

Fontes: `server/src/flight_grpc.rs:66,151`; `server/src/lib.rs:949`.

DoGet faz scan integral e cria batches antes de começar a transmissão. BATCH_ROWS limita o fio, não a leitura acumulada. Handshake não é implementado; não há auth nesse serviço. Boot recusa Flight não-loopback, o que limita a exposição a consumidores locais; a função pública serve_flight não aplica a guarda por si. Não há prova de listener remoto aceito pelo boot normal.

Correção: paginação/backpressure/admissão e autenticação/RBAC coerentes se a superfície for ampliada; guarda também na API de bind. Analytics e flight_addr são opt-in.

### F11 — P1 de disponibilidade: checkpoint multiplica RAM e segura locks

Fontes: `server/src/engine.rs:833,866`; `views/src/lib.rs:426`; `index-vector/src/lib.rs:658`; `index-text/src/lib.rs:671`; `telemetry-health/src/lib.rs:989`.

A barreira de indexação protege consistência, mas serialização ainda ocorre segurando locks das views/índices. Registry não pula views limpas; vector clona objetos e cria outro buffer; texto expande postings; telemetria produz cópia codificada completa. Uma base que cabe durante ingestão pode sofrer pico no checkpoint. Não foi quantificado RSS ou parada de append nesta rodada.

Correção: dirty/generation, snapshots imutáveis consistentes, serialização progressiva fora do lock. Não remover barreiras nem usar watermark adiantado para ganhar velocidade. Backup/restauração e crash devem produzir o mesmo estado.

### F12 — P2: retenção e reprocessamento da telemetria

Fontes: `telemetry-health/src/lib.rs:803,838,930`.

Estado retém todo histórico de envelopes e cada snapshots_as_of o reduz novamente, inclusive antes de filtrar datasource. Para sensores Silent há buscas reversas adicionais por sensor. Cresce em RAM e custo de consulta. Corrigir com estado atual incremental e índice/histórico reconstruível por log, preservando AS OF.

### F13 — P2: memtable por contagem e ausência de teto global dos índices

Fontes: `core/src/config.rs:715`; `memtable/src/lib.rs:36`; `server/src/engine.rs:725`; estruturas de texto, vetor e atributos.

100 mil Episode clonados podem ter custos muito diferentes conforme conteúdo, embedding e atributos. Compressão de postings de texto e internamento de atributos já existem, mas as estruturas seguem residentes. Recomendações específicas na seção 1; dimensionar cada índice, não só bytes do log.

### F14 — P2: manutenção/documentação e gate de formato

`cargo fmt --all -- --check` falhou, incluindo `crates/heraclitus-cli/src/top.rs:418`. STATUS.md não possui entradas encontradas para 0086–0091, enquanto o roadmap o chama de autoridade. Atualizar matriz SPEC → implementação → consumidor → gate → qualificação. Os achados superados da tabela inicial precisam de nota de validade, sem apagar o histórico.

## Controles existentes que a auditoria confirmou

- `core/src/config.rs:1341`: REST administrativo exige loopback; gRPC fora de loopback exige auth/TLS; Raft remoto exige gRPC mTLS.
- Modo produção exige Always, cifra em repouso, auditoria, principals separados e TSA externa HTTPS; os testes production_profile_is_fail_closed e security_validation_rejects_public_plaintext_surfaces passaram nesta rodada.
- RBAC nos handlers, identidade autenticada no append, aprovação Sentinel vinculada ao principal e proteção de namespaces reservados constam dos caminhos consultados. Falhas do módulo administrativo novo não equivalem a bypass do RBAC atual.
- KeyStore de produção agora serializa shred/leitura e recusa chaves zero; testes de concorrência passaram. É implementação diferente de SoftwareKeyProvider.
- Views restauradas usam watermark do snapshot; guarda impede checkpoint de índices não materializados. Scan V6 sequencial existe.
- CI contém testes debug/release, clippy para debug_assert com mutação e supply-chain. A presença do workflow não comprova execução bem-sucedida no commit atual; nenhum status remoto de CI foi consultado.

## 4. Ordem prática das melhorias

1. Fechar F01/F02: protocolo administrativo efetivamente integrado, durável e reconciliável.
2. Corrigir F03/F04 antes de integrar o provider novo; corrigir F05/F06/F07 antes de apresentar pacotes como evidência autenticada.
3. Corrigir F08 com compatibilidade de hashes; ampliar casos negativos de idempotência.
4. Fechar F09/F10 e medir memória/concorrência/cancelamento com features analytics/Flight habilitadas.
5. Reduzir pico e bloqueio de checkpoints; em seguida telemetria e memória residente dos índices/memtable.
6. Atualizar documentação e formatação; manter regressões debug e release, testes de adulteração, crash e isolamento por filesystem.

Otimizações posteriores: top-k em ORDER BY com LIMIT quando semanticamente aplicável; cache H-VM incremental por watermark; pushdown de projeção/predicado em analytics; índice legado em blocos para reduzir COW. Não recomendar de novo CRC hardware, 8 MiB, compressão residente de texto, internamento de atributos ou scan V6 como se estivessem ausentes.

## Validação desta rodada

**Execuções novas, offline e com lock preservado:**

- Core: 60 testes unitários aprovados.
- Crypto: 10 testes unitários aprovados.
- Forensic: 6 testes unitários aprovados.
- Sonda isolada: 10 testes aprovados, sendo **8 diagnósticos de defeitos** e 2 testes originais do módulo administrativo incluído. Os seis diagnósticos anteriores foram reexecutados; adicionados digest com fronteiras ambíguas e junction Windows.
- Total: 76 unitários do produto + 10 da sonda. Teste diagnóstico aprovado significa comportamento defeituoso observado.
- `cargo fmt --all -- --check`: exit 1; saída incluída nas evidências.
- `git diff --check`: sem erros; status rastreado permaneceu sem alterações. Quatro arquivos/artefatos já não rastreados foram preservados.

Não executados: testes de todo workspace ou server/log/query nesta rodada, todas as features, SQL/Flight em runtime, benchmark de memória, crash/power-loss, fuzzing/Miri/loom, GPU/Linux, cluster real, pentest externo e consulta atualizada RustSec/dependências. Os 481 testes mencionados no relatório anterior são **resultado histórico**, não validação nova. Nada aqui certifica ausência de outros defeitos nos 395 Rust inventariados.

## Reprodução e evidências

O ZIP desta entrega contém fonte/lock da sonda, logs desta rodada, fonte-hash dos componentes consultados e o gate de formato. Extrair em pasta de trabalho e executar, no diretório `audit-probe`:

```powershell
cargo test --offline --locked --target-dir ../cargo-target --jobs 2 -- --test-threads=2
```

As dependências e o módulo administrativo apontam para `D:/DEV/HeraclitusDB`. Adaptar os paths se o checkout mudar. O teste de junction é específico para Windows e utiliza somente diretórios temporários novos. Os testes são evidências dos defeitos atuais, não devem ser transformados em gates positivos sem inverter as expectativas após as correções.

**Entrega: auditoria, recomendações e evidências. Nenhuma correção aplicada ao HeraclitusDB.**
