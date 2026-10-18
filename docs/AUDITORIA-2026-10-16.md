# Auditoria HeraclitusDB — 2026-10-16

**Alvo:** `D:\DEV\HeraclitusDB` · `main` = `HEAD` = `79c9fa5` (ramo `fix/auditorias-2026-10-02`) · release auditada: tag **`v3.0.1` = `04bb227`** (2026-09-17).
**Working tree:** WIP não commitado em `crates/heraclitus-log/src/v6/engine.rs` (+86/−3).
**Entrega:** este relatório + sondas em [`auditoria-2026-10-16-sondas/`](auditoria-2026-10-16-sondas/). Nenhum código do produto foi alterado, nenhum serviço foi tocado.

> Convenção: **P0** perda de dados confirmados / bloqueio de garantia essencial; **P1** falha relevante de integridade, segurança ou correção; **P2** disponibilidade/robustez ou segurança com pré-condição; **P3** funcional/menor. "Sonda" = teste que **passa quando o defeito é observado**.

---

## 0. Resumo executivo

| # | Achado | Gravidade | Estado |
|---|---|---|---|
| B1 | **HRKL v6:** um bit trocado no meio da cauda ativa faz o arranque **truncar registos já confirmados com `fsync=Always`** (100 → 33) e reutilizar os LSN | **P0** | Reproduzido |
| B2 | **HRKL v6:** um bit trocado num RAW selado faz `scan` devolver `Ok` com buraco (187/200) e `read` devolver `Ok(None)` para LSN confirmados | **P1** | Reproduzido |
| B3 | **Replicação Raft:** todo episódio replicado é gravado com `ts_hlc = 0` em todos os nós | **P1** | Reproduzido (3 nós) |
| B4 | **`heraclitus top` (v3.0.1):** em erro de ligação envia `Authorization: Basic security-admin:<token>` em HTTP claro para o servidor DNS de `/etc/resolv.conf` | **P1** | Código lido |
| B6 | Um único RAW selado corrompido trava o packing (e, por arrasto, HRKI/Parquet/GC) de todos os segmentos seguintes | **P2** | Reproduzido |
| R1 | **Release v3.0.1:** tabela "Provas Formais Lean 4 — PROVED" é fixa no código; os 5 projetos Lean têm `sorry`, 2 provas não existem, 1 axioma é contraditório | **P1** | Verificado |
| R2 | `main` tem 118 commits (≈19 mil linhas em `crates/`) após o tag e continua `version = "3.0.1"`; *nightly* de qualificação falha há 9 noites; working tree não compila | **P1** | Verificado |

O código foi muito endurecido pelas rondas de 09-05 a 10-04 (vi dezenas de correções corretas e bem testadas). Os defeitos novos concentram-se em quatro sítios: o **caminho de leitura em streaming do V6** (introduzido pelas otimizações A04/A13), a **recuperação da cauda**, o **caminho replicado** e a **funcionalidade nova da v3.0.1** (`top`).

---

## 1. Alcance, método e cobertura (honesta)

- **Inventário:** 411 arquivos `.rs` (209 201 linhas, ~21 mil de testes/benches) e ~200 `.md` do projeto (79 mil linhas, excluindo `node_modules`).
- **Leitura integral, linha a linha:** `v6/engine.rs` (produção), `v6/raw.rs`, `v6/manifest.rs`, `v6/gc.rs`, `v6/packed.rs`, `v6/packer.rs`; `heraclitus-crypto/src/lib.rs`; `heraclitus-raft/src/durable.rs` e a máquina de estados de `consensus.rs`; `heraclitus-server/src/trusted_admin.rs`, `auth.rs`, partes centrais de `engine.rs` (boot, append, idempotência, shred, checkpoints, nearest, AS OF), `rest.rs` (auth/RBAC/meta-auditoria), `grpc.rs` (append/batch/query/subscribe/admin), `cluster.rs` (submissão); `heraclitus-views/src/lib.rs`; `heraclitus-memtable`; `heraclitus-agent-gateway` (`gateway.rs`, `upstream.rs`); `heraclitus-tier` (`demotion.rs`, `fetch_cold`); `heraclitus-cli/src/top.rs` (partes da v3.0.1); todo o diretório `lean/`.
- **Varredura dirigida (grep + leitura de trechos):** `unsafe`, truncamentos `as u16/u32`, validações de tamanho, `scan_capped`, `as_of`, `ts_hlc`, ligação de credenciais, chamadores de GC/packing.
- **Não lidos integralmente:** `heraclitus-sentinel` (≈12 mil linhas), `heraclitus-compliance` (ICP/TSA/CRL, ≈10 mil), `heraclitus-query` (planner/backend), índices vetor/texto/grafo, analytics, hume-*, ferramentas (`qualifier`, `ingestor`). **Não há afirmação de ausência de defeitos nesses módulos.**
- **Docs cruzadas:** release notes v3.0.0/v3.0.1, `AUDITORIA-GERAL-…-10-01`, `CORRECOES-AUDITORIAS-10-01/02/03`, `STATUS.md`, `README.md`.
- **Execução:** sondas compiladas contra uma **cópia limpa do HEAD** (`git archive`, fora do repositório), porque o working tree não compila (B7).

---

## 2. Bugs

### B1 — P0 · Bit rot no meio da cauda ativa V6 → arranque apaga registos confirmados

**Onde:** `crates/heraclitus-log/src/v6/raw.rs:900-945` (`repair_active_tail`), chamado por `v6/engine.rs:595`; mesmo padrão no legado em `crates/heraclitus-log/src/lib.rs:1065-1091`.

**O quê:** `scan_raw_bytes` para no primeiro frame com CRC inválido e devolve `torn_at`. `repair_active_tail` faz `set_len(torn_at)` sem distinguir uma **escrita rasgada** (só pode ser o último frame, que se estende além do EOF) de **corrupção a meio** (o frame cabe no ficheiro e há frames válidos depois).

**Reprodução** (`sonda_bitrot_no_meio_da_cauda_activa_trunca_confirmados`): 100 appends com `FsyncPolicy::Always`, inverter 1 byte a 1/3 do ficheiro ativo.
- Com o log aberto: `scan(0, 100)` → `Ok(33)`, sem erro.
- Ao reabrir: `head` passa de **100 para 33**. Os 67 registos confirmados e fsyncados são apagados e os LSN 33..99 são **reutilizados** pelos próximos appends.

**Consequências:** perda permanente e silenciosa; as views/attr têm watermark à frente do log e ignoram os LSN reutilizados; idempotência e réplicas divergem; a prova (bytes corrompidos) é destruída.

**Correção:** só truncar quando o frame em `torn_at` declara um comprimento que ultrapassa o EOF **e** não existe nenhum frame válido depois (varredura de ressincronização por `lsn = esperado + k`). Caso contrário: `Corruption`, preservar o ficheiro e recusar arrancar (mesma política dos segmentos não-últimos do legado e do WAL Raft). Aplicar no V6 e no legado.

### B2 — P1 · Bit rot num RAW selado V6 → `scan`/`read` omitem LSN confirmados sem erro

**Onde:** `v6/raw.rs:646-707` (`percorrer_raw_segmento`: CRC falhado, comprimento impossível ou leitura curta → `return Ok(pos)`), usado por `v6/engine.rs:1022` (`read` selado), `1232-1251` (scan selado) e `1299-1330` (scan da cauda).

**Reprodução** (`sonda_bitrot_em_raw_selado_v6_scan_e_read`): 200 appends em segmentos de 4 KiB (7 RAW selados), inverter 1 byte no meio de um selado. `scan(0, 200)` → **`Ok` com 187 linhas**. `read(lsn)` → **`Ok(None)` para 13 LSN < head**.

**Por que importa:** o arranque não verifica payloads por desenho (§159), não há *scrubber* periódico (só `/verify` sob pedido, `engine.rs:3294`) e `catch_up`, `rebuild`, o índice de atributos, o `Subscribe`, o snapshot Raft e o relatório LGPD do titular **usam todos `scan_capped`**. O diário administrativo (`trusted_admin::recover`) usa `scan_builtin_eq_capped`, cujo ramo RAW (`scan_raw_segment`) também para no rasgo e ignora o `torn_at`. As views são reconstruídas sem esses eventos e o titular recebe um relatório incompleto com 200 OK. O legado tem a regressão coberta (`tests/crc_nao_e_engolido.rs`), o V6 não. O doc-comment em `raw.rs:641-645` e `engine.rs:1221-1231` afirma "Nenhuma linha se perde por isto", o que é falso para um registo corrompido a meio.

**Correção:** no streaming, distinguir "fim limpo" de "parei antes do fim". Num segmento **selado**, parar antes do footer ou antes de `record_count` é `Corruption`. Na cauda, a janela `[seg_from, end)` tem de ser coberta por completo (todo LSN < `head` do instantâneo foi escrito antes); faltar algum é `Corruption`. Acrescentar ao V6 a sonda equivalente a `crc_nao_e_engolido`.

### B3 — P1 · Replicação: `ts_hlc = 0` em todos os episódios replicados

**Onde:** `heraclitus-server/src/engine.rs:3017-3019` → `cluster.rs:251` (`episode_bytes(&ep)`, com `ep.ts_hlc = 0` vindo de `Episode::new`) → `heraclitus-raft/src/consensus.rs:461-486` (`apply`) → `append_replicated` (`heraclitus-log/src/lib.rs:2368`, `v6/engine.rs:728`). Este caminho preserva o `ts_hlc` recebido e só faz `hlc.observe(0)`. Nenhum ponto do caminho replicado carimba o HLC.

**Reprodução** (`sonda_ts_hlc_replicado`, cluster in-process de 3 nós, feature `replication`): os 5 episódios têm `ts_hlc = [0,0,0,0,0]` **nos três nós**.

**Efeitos:** `AS OF TIMESTAMP` deixa de funcionar (`engine.rs:3987-4018`: `lsn_for_timestamp` devolve sempre `head`); `ts_ms`/`lsn_em`/`diff` por tempo e `t_ms` do titular ficam a 0; a ativação ACT-R regista todos os acessos no instante 0; `min_hlc`/`max_hlc` dos segmentos ficam a 0. A retenção regulatória (`engine.rs:2620-2625`) filtra `ts_ms == 0` e trataria todo `RetainForSeconds` como não expirado. Hoje isso não se nota, porque `execute_admin` recusa o shred em nós replicados (`engine.rs:2374`), mas passa a importar quando a administração distribuída existir.

**Correção:** carimbar de forma **determinística no `apply`** (igual em todos os nós): o líder põe o relógio físico na entrada e a máquina de estados calcula `ts = max(ts_anterior + 1, relógio_da_entrada)`. Carimbar no líder antes de propor não garante monotonia por índice Raft com propostas concorrentes. Gate: sonda acima mais AS OF TIMESTAMP igual entre nó autónomo e cluster.

### B4 — P1 · `heraclitus top` envia o token admin em claro para o servidor DNS

**Onde:** `heraclitus-cli/src/top.rs:3474-3496` (`fetch_with_fallback`), `3687-3696` (`get_wsl_host_ip`). **Presente no tag v3.0.1.**

**O quê:** em qualquer erro de ligação, o cliente lê o primeiro `nameserver` de `/etc/resolv.conf`. Isso só é o host Windows dentro do WSL. Num Linux comum é o resolvedor DNS (router, DNS corporativo, 8.8.8.8). O cliente repete o pedido em **HTTP claro** para `<nameserver>:7475`, primeiro com a credencial do utilizador e depois com `security-admin:<token>` (`find_secret_token`).

**Impacto:** quem controla o DNS da rede (DHCP, Wi-Fi, rede de laboratório) recolhe a credencial de administração de segurança apenas escutando a porta 7475.

**Correção:** remover o fallback, ou ativá-lo só com flag explícita, só em WSL detetado (`/proc/sys/fs/binfmt_misc/WSLInterop`), e nunca com credenciais.

### B5 — P2 · Escrita rasgada cujo payload contém uma imagem de footer bloqueia o arranque para sempre

**Onde:** `v6/raw.rs:954-960` (`footer_no_eof_alem_do_rasgo`), chamado por `repair_active_tail` (`raw.rs:935`).

**O quê:** o CRC do footer não tem chave, por isso um cliente pode pôr no `content` uma imagem válida de `FooterV6`. Se um `write()` grande for cortado logo a seguir a essa imagem (SIGKILL/OOM: o Linux corta em fronteira de página), o EOF-128 "parece" um footer depois do rasgo. O arranque recusa então com **"refusing to truncate a sealed segment"**, sempre. A correção da iteração 1 (10-03) cobriu só o registo **completo**.

**Reprodução:** `sonda_cauda_rasgada_com_imagem_de_footer_no_payload_bloqueia_arranque` → `ARRANQUE RECUSADO`.

**Correção:** é a mesma regra de B1. Se o frame em `torn_at` declara um comprimento que ultrapassa o EOF, a "imagem" está dentro dele e a cauda é rasgada (truncar). Só um footer que começa **exatamente** numa fronteira alcançada (`EOF−128 == torn_at`) sela.

### B6 — P2 · Um RAW selado corrompido trava o packing de toda a base

**Onde:** `v6/engine.rs:1852-1939` (`pack_pending`, `?` em `pack_segment`) e `2005-2088` (`build_pending_hrki`). A mensagem vem de `packer.rs:115-118`.

**Reprodução** (`sonda_um_raw_corrompido_trava_a_fila_de_packing`): com o segmento 1 corrompido, duas passagens dão `Err("refusing to pack an unsealed segment")` e **a fila fica com os 6 segmentos [1..6]**. A mensagem engana: o segmento está selado, mas o `scan_raw_segment` para no CRC e não vê o footer.

**Efeito:** nada mais é empacotado; por consequência também não há HRKI, Parquet nem GC das gerações, e o disco cresce. O sintoma visível é um `warn` a cada 30 s.

**Correção:** isolar a falha por segmento (registar, quarentenar, continuar a fila) e corrigir a mensagem (`Corruption` com offset).

### B7 — P2 · O working tree não compila

`cargo check -p heraclitus-log`: **3 erros** no WIP de `v6/engine.rs`: `E0432` (`receipts::physical_digest_of_bytes` não existe, linha 51) e `E0063` (`V6State.selado_por_publicar` linha 623, `V6Log.seal_concluido` linha 676 sem inicializar). É a correção "seal fora do mutex" da lista *Continua aberto* (10-02), interrompida a meio. Quem compilar a partir desta pasta não consegue gerar binário. Concluir o WIP ou guardá-lo num ramo.

### B8 — P3 · REST abre como Admin quando só existe `auth_token` (gRPC)

**Onde:** `heraclitus-server/src/rest.rs:351-362` com `auth.rs:56-58` (`com_papeis = !access_credentials.is_empty()`).

**O quê:** com `auth_token` configurado e sem `rest_basic_auth`/`access_credentials`, o REST resolve todo pedido como `rest-sem-auth` com papel **Admin**, enquanto o gRPC exige o token. Atenuantes verificados: o arranque emite o aviso "sem auth (loopback) — escritas locais … abertas" (`server/src/lib.rs:434-437`), o REST fora de loopback exige `rest_basic_auth`, e `production_mode` também o exige (`core/src/config.rs:1505-1515`). O risco fica restrito a perfis não produtivos: qualquer processo ou utilizador local (máquina multiutilizador, contentores no mesmo *netns*) pode ler tudo e chamar `/titular/:id/eliminar`.

**Correção:** com qualquer credencial configurada, o REST exige credencial; como mínimo, recusar arrancar nesta combinação.

### B9 — P2 · `top` escala para `security-admin` sem avisar e embute caminhos de segredos de desenvolvimento

**Onde:** `top.rs:3456-3468` e `3642-3672`. Em resposta 401, o cliente lê o token de variáveis de ambiente ou de ficheiros e repete como `security-admin`, incluindo os caminhos fixos **`D:\HeraclitusDB\secrets-v1\admin.token`, `writer.token`** e `/mnt/d/…` no binário de release. Um `writer.token` é usado como `security-admin`. Quem corre `top` com credencial de leitura acaba a operar como admin sem o saber.

### B10 — P2 · WAL Raft sem checksum por registo

**Onde:** `heraclitus-raft/src/durable.rs:321-388`.
- Um bit trocado num payload que ainda descodifica em bincode é aceite em silêncio.
- Um bit no prefixo de comprimento parece "cauda rasgada" e o `set_len` corta entradas fsyncadas e já reconhecidas ao líder acima de `meta.committed` (que é persistido com atraso). Isso viola a segurança do Raft.
- `fsync_dir` ignora o erro (`durable.rs:74-78`), e o voto pode não ser durável sem que ninguém saiba.

**Correção:** CRC32C por frame; a mesma regra "torn só se o frame se estende além do EOF"; propagar o erro de `fsync_dir` em Unix.

### B11 — P3 · `agent_id` longo quebra a cifra em repouso desse agente

**Onde:** `heraclitus-crypto/src/lib.rs:299-303`: o nome do ficheiro é `hex(agent_id) + ".key"`. Com mais de ~125 bytes o nome passa de 255 caracteres. **Sonda:** com 130 bytes, `get_or_create` → `Err(os error 123)`. Não há limite de tamanho de `agent_id` no servidor, e com `encryption_at_rest` (obrigatório em produção) todos os appends desse agente falham sempre. **Correção:** usar um hash (blake3) como nome quando o `agent_id` é longo, mantendo o formato hex para os curtos (compatibilidade), e validar o tamanho à entrada.

### B12 — P3 · `/tier/fetch` devolve episódios cifrados

**Onde:** `heraclitus-tier/src/lib.rs:466-505` (v1) e `demotion.rs:233-252` (v2): usam `decode_episode_payload` sem decifrar, porque `decrypt_storage_episode_in_place` é `pub(crate)` no log. Com cifra em repouso, o conteúdo e os atributos chegam selados (`HRKLENC2…`). O v2 também não confere contagem e raiz contra o recibo; o v1 confere.

### B13 — P3 (desenho/doc) · Envelope v1 pode substituir um v2 novo

**Onde:** `crypto/src/lib.rs:191-201`. O leitor escolhe a AAD pelo magic, por isso **qualquer** blob v1 antigo do agente pode ser colado no lugar de um blob **v2** novo. O doc (`lib.rs:25-30`) diz apenas "no lugar de outro blob v1". Correção: persistir um corte (LSN/HLC) a partir do qual v1 é recusado, gravado depois de `migrate-encrypt`.

### Menores

- `append_replicated` (`lib.rs:2368`, `v6/engine.rs:728`) considera idempotente qualquer episódio com o mesmo `id`, mesmo com conteúdo diferente; o correto seria comparar o hash canónico.
- `Memtable::prune_below` (`memtable/src/lib.rs:84-97`) para no primeiro LSN acima do watermark mesmo com inserções fora de ordem. `text_search` faz *substring* e mistura escala de tf com BM25 (hoje sem chamador no servidor).
- `PinRegistry` (`gc.rs:58-118`) não é usado por nenhum leitor. No Windows o `remove_file` de um ficheiro aberto pelo Rust (FILE_SHARE_DELETE) **funciona**, e o comentário em `engine.rs:2287-2292` (sharing violation → órfão) não descreve esse caso. O risco fica limitado pelo *grace period* por omissão.
- O comentário de `packed.rs:328` diz que `&File` permite leituras concorrentes partilhadas; `seek + read_exact` não é atómico. Hoje cada leitura abre o seu próprio `FileSource`, portanto o problema é latente.

---

## 3. Otimizações (ordem por impacto)

| # | Onde | Problema medido no código | Mudança | Gate |
|---|---|---|---|---|
| O1 | `server/engine.rs:827-845` (linha 841) | Cada append toma o **mutex único do `ViewRegistry`** e aplica as 7 views (inserção HNSW incluída) dentro dele: as escritas ficam serializadas pelo índice mais lento, e a ordem de aplicação ao vivo difere da do replay | Indexador único em ordem de LSN (resolve também a ordem), ou locks por view com aplicação paralela entre views; manter RYOW pela memtable | Throughput de append com 1/8/64 escritores; `state_hash` ao vivo = rebuild |
| O2 | `v6/manifest.rs:629-663`; `engine.rs:2684` e todos os `before = state.manifest.clone()` | O HRKM inteiro (O(nº segmentos)) é **clonado sob o mutex e reescrito com fsync a cada seal**, pack, HRKI e legal hold; `next_generation()` faz `read_dir` a cada commit. Com 1 TB e segmentos de 8 MiB são ~125 mil descritores por seal | Manifesto incremental (delta + compactação periódica) ou segmentos maiores por omissão; clone fora do lock; contador de geração em memória | Latência p99 de append durante o seal com 10⁵ segmentos |
| O3 | `v6/engine.rs:1449-1463, 1518-1570` | `scan_builtin_eq_capped` lê RAW selados inteiros para RAM e varre a **cauda ativa inteira sob o mutex do writer** (até 8 MiB de leitura + decode, appends parados) | Streaming como em `tentar_varrer`; ler a cauda fora do lock com o instantâneo de `head` | Appends durante `recover` / consultas por `agent_id` |
| O4 | `v6/engine.rs:1025-1031` | Cada leitura pontual PACKED reabre o ficheiro e relê e descodifica header, footer e diretório; a hidratação de K resultados paga isso K vezes | Cache LRU de `PackedSegmentReader` por (caminho, geração), invalidada por GC/quarentena | Latência de `RECALL`/`NEAREST` com hidratação |
| O5 | `server/engine.rs:2938-2950` | O hash de idempotência serializa `content` e `embedding` em **JSON** (bytes como arrays de números, ~3,5× o tamanho) a cada append idempotente | blake3 incremental com prefixos de comprimento; nova versão do atributo de hash (aceitar o antigo, como já se faz com `legacy_hash`) | RAM/latência com payloads de MiB |
| O6 | `server/engine.rs:2441-2551` | O crypto-shred segura `index_gate` em **escrita** durante o rebuild integral das views e do attr: as escritas param por O(log) | Rebuild seletivo do titular ou nova geração de views em paralelo com troca atómica | Indisponibilidade de escrita durante o shred |
| O7 | `raft/durable.rs:499-506`; `consensus.rs:366-421, 555-563` | `save_committed` faz tmp+fsync+rename+fsync dir a cada avanço de commit; o snapshot tem o log inteiro 3–4× em RAM (payload, bytes, clone em `current_snapshot`, clone em `get_current_snapshot`) | Persistência preguiçosa do `committed` (opcional no openraft); snapshot em streaming com `Arc<[u8]>` | fsyncs/s por commit; RSS no `install_snapshot` |
| O8 | `v6/raw.rs:781-798` | Leitura pontual num RAW selado ainda não empacotado é O(posição): os offsets só existem para a cauda | Guardar os `offsets` do writer no seal (em memória) até ao pack | `read` nos 30 s entre seal e pack |
| O9 | `tier/demotion.rs:128-137` | `publish_generation` tem o segmento inteiro em RAM mais `bytes.clone()` | `Bytes` partilhado/streaming multipart | RSS do demote |
| O10 | `server/engine.rs:1101-1109` | `hvm_state` clona o estado KV completo a cada pedido | Devolver `Arc<VmState>` | — |

A nota da auditoria de 10-01 sobre o pico de RAM dos checkpoints já foi tratada (checkpoints em streaming e views limpas); não a reabrir.

---

## 4. Docs × código — divergências

| Documento | Afirmação | Realidade |
|---|---|---|
| `RELEASE_NOTES_v3.0.1.md:27-28` | "propriedades matemáticas provadas … (`PROVED`)" para 7 provas | Ver R1: `sorry` em todos os projetos, 2 inexistentes, axioma falso; a UI é uma tabela fixa |
| `RELEASE_NOTES_v3.0.1.md:31-32` | "Eliminação estrita de falso-verde: sem resposta válida → `UNKNOWN`/`N/D`" | `top.rs:3777-3833` usa `unwrap_or(0)` e `available.unwrap_or(true)`: falhas ausentes aparecem como 0 (verde) |
| `RELEASE_NOTES_v3.0.0.md` | "A evidência relevante deve … ser vinculável ao estado/binário que a produziu" | A versão não muda há 118 commits e nenhum `build.rs` embute o commit (R2) |
| `v6/raw.rs:641-645`, `v6/engine.rs:1221-1231` | "Nenhuma linha se perde por isto" | Perdem-se todas as linhas do segmento a partir do registo corrompido (B2) |
| `STATUS.md` (atualização 10-03), "Raft Durabilidade" | "proteção contra corrupção em arranque" | O WAL não tem CRC; um prefixo corrompido corta entradas reconhecidas (B10) |
| `server/engine.rs:174-175` | "`legacy` continua sendo o default" | O default é **V6** (`core/src/config.rs:711`, com teste) |
| `crypto/src/lib.rs:25-30` | v1 só pode ser colado "no lugar de outro blob v1" | Também no lugar de um v2 (B13) |
| `server/engine.rs:2287-2292` | No Windows o `remove_file` de um ficheiro aberto falha → órfão | Ficheiros abertos pelo std com FILE_SHARE_DELETE são removíveis |
| `CORRECOES-AUDITORIAS-2026-10-02.md` §"Continua aberto" | "verificação do seal V6 fora do mutex" por fazer | Em curso como WIP e quebrado (B7) |
| `crc_nao_e_engolido.rs`, `bitrot_nao_trunca.rs` | Regressões de CRC/bit rot "corrigidas" | Cobrem só o log **legado**; o V6 (default) não tem as equivalentes |

---

## 5. Auditoria da release v3.0.1

**Conteúdo do tag `04bb227`:** o `heraclitus top` com 9 abas (SPECs 0078–0085), que é também o único código novo desta release.

| # | Item | Achado |
|---|---|---|
| R1 | **Provas formais** | `top.rs:1671-1760` desenha 7 linhas verdes "PROVED" fixas. Em `lean/`: **ProofAppendOnly** — `truncate_consistent` = `sorry`; `replay_deterministic` é `x = x` (`rfl`). **ProofMerkleTree** — o único teorema é `sorry`, e o axioma `combine_hash_injective` é **falso** para a definição `combine_hash h1 h2 = h1 + h2` (`1+2 = 2+1` ⇒ `1 = 2`), o que torna o sistema inconsistente. **ProofDeterministicReplay** — o teorema 2 é `sorry` e o teorema 1 é `x = x`. **ProofDenseMap** — 3 de 5 são `sorry`, incluindo o trivial `empty_is_valid`, e a UI descreve-a como "Hazard pointers & lock-free", que nada tem a ver com o modelo. **ProofHLC** — a causalidade é `sorry`. **ProofApprovalIdempotence** e **ProofToolCallIsolation** não existem. Nenhum workflow corre `lake build`. Recomendação: mostrar o estado real (`SORRY`, `NOT_IMPLEMENTED`), gerado pelo CI, nunca fixo no código. |
| R2 | **Versão** | `main` = HEAD tem 118 commits após o tag (+18 967/−1 374 linhas em 101 ficheiros de `crates/`) com `version = "3.0.1"`. A instalação WSL em `8d3d78d` anuncia-se "3.0.1" sem o ser. Fazer *bump* (3.0.2-dev/3.1.0) e embutir o commit e o estado *dirty* no binário (`build.rs`). |
| R3 | **Qualificação** | "Qualification preflight nightly" **falha todas as noites desde ≥ 2026-10-07** (9 falhas, 10-08 cancelada). O job `release-binary-crash-loop` termina `SOAK_Failed operations=114824 errors=0`. Sem erros de operação, a falha vem de um gate de `soak.rs:482-517`: crescimento de recursos (RSS/FD/threads), deriva de p99, integridade pós-soak ou *head* regredido. O `report.json` está no artefacto do run 38871651957 (não descarregado nesta auditoria). O CI de `79c9fa5` estava em curso no momento da auditoria. |
| R4 | **Segurança do `top`** | B4 (fuga do token para o DNS) e B9 (escalada silenciosa e caminhos de segredo fixos) estão **presentes no tag**. |
| R5 | **Defeitos do motor presentes no tag** | B1, B2, B3, B5 e B11 já existiam em `v3.0.1` (o `percorrer_raw_segmento` vem de A04/A13, de 09-05). |
| R6 | **Higiene** | `release/linux-x86_64/heraclitus-server` (ignorado pelo git) é de 2026-09-04, anterior ao v3.0.0. |

**Veredito sobre a v3.0.1:** a release não deve ser apresentada como "provada" nem como "sem falso-verde". Antes da próxima versão de produção é preciso corrigir B1–B4 (integridade e segurança), fazer *bump* de versão com proveniência do commit, e ter o *nightly* de qualificação verde.

---

## 6. Validação desta ronda

**Executado** (cópia limpa do HEAD, target isolado, offline, Windows):
- `cargo check -p heraclitus-log` no working tree: **falha com 3 erros** (B7).
- `cargo test -p heraclitus-log -p heraclitus-crypto` na cópia limpa: **381 passaram, 0 falharam** (inclui as sondas, que passam por observarem o defeito). A suíte existente não deteta B1, B2, B5, B6 nem B11.
- Sondas (todas reproduziram o defeito):
  - `heraclitus-log`: `sonda_bitrot_no_meio_da_cauda_activa_trunca_confirmados` (B1), `sonda_bitrot_em_raw_selado_v6_scan_e_read` (B2), `sonda_cauda_rasgada_com_imagem_de_footer_no_payload_bloqueia_arranque` (B5), `sonda_um_raw_corrompido_trava_a_fila_de_packing` (B6).
  - `heraclitus-raft --features replication`: `sonda_ts_hlc_replicado` (B3).
  - `heraclitus-crypto`: `sonda_agent_id_longo_falha_get_or_create` (B11).
- `gh run list` / `gh run view --log-failed` (leitura) para o *nightly* (R3).

**Não executado:** suíte completa do workspace, servidor com `replication`/`analytics`/`tier`, Linux/GPU/io_uring, fuzz/Miri/loom, carga/soak, `cargo audit` atualizado, download do `report.json` do *nightly*. B4, B8, B9, B10, B12 e B13 foram confirmados por leitura de código, sem execução.

### Como reproduzir as sondas

1. Extrair o HEAD fora do repositório: `git archive HEAD crates Cargo.toml Cargo.lock rust-toolchain.toml tools sim fuzz verus sdk benches examples bench | tar -x -C <pasta>`.
2. Copiar `auditoria-2026-10-16-sondas/heraclitus-log_tests_sonda_auditoria_v6.rs` para `<pasta>/crates/heraclitus-log/tests/sonda_auditoria_v6.rs` e `heraclitus-crypto_tests_sonda_auditoria.rs` para `<pasta>/crates/heraclitus-crypto/tests/sonda_auditoria.rs`; colar o teste de `heraclitus-raft_consensus_sonda_ts_hlc.rs.txt` dentro de `mod tests` de `crates/heraclitus-raft/src/consensus.rs`.
3. Correr com um `CARGO_TARGET_DIR` próprio:
   - `cargo test -p heraclitus-log --offline --test sonda_auditoria_v6 -- --nocapture`
   - `cargo test -p heraclitus-crypto --offline --test sonda_auditoria -- --nocapture`
   - `cargo test -p heraclitus-raft --features replication --offline --lib sonda_ts_hlc_replicado -- --nocapture`

Depois de cada correção, inverter a asserção da sonda e transformá-la em teste de regressão (e fazer o teste de sabotagem, como nas rondas anteriores).

## 7. Ordem sugerida

1. **B1 + B5** (uma única regra de "torn" em `raw.rs`, com o mesmo padrão em `lib.rs` e `durable.rs` → também B10).
2. **B2** (streaming que falha alto) + sondas V6 equivalentes às do legado; **B6** (fila tolerante a falhas).
3. **B3** (carimbo determinístico no apply) antes de qualquer uso de replicação com AS OF.
4. **B4/B9** num patch do `top`, e **R1** (tabela de provas gerada pelo CI). **B7** (concluir ou separar o WIP).
5. **R2/R3**: *bump* de versão + commit embutido; investigar o `report.json` do *nightly*.
6. B8, B11, B12, B13; depois as otimizações O1–O5.
