# Relatório geral — 2 de setembro de 2026

> Esta versão **substitui** a de manhã. Vários pontos dela estavam errados, e
> estão corrigidos abaixo com a evidência que os desmentiu. O critério aqui é:
> nada entra sem ter sido verificado contra o código ou contra o serviço a
> correr. Onde não verifiquei, digo que não verifiquei.

## Veredito executivo

A base técnica é sólida e está mais perto do fim do que o relatório da manhã
sugeria. O que bloqueia não é arquitetura — é que **o repositório não compilava
com o conjunto de features que o próprio CI exige**, e isso invalidava qualquer
afirmação de qualificação. Esse bloqueio foi resolvido hoje.

- **Corrigido hoje:** build com `--all-features`, 30 `unsafe transmute` no
  ingestor, e o checkpoint que cegava o banco 23% do tempo.
- **Por resolver, com dono claro:** PGWire e a qualificação externa.
- **A riscar da lista:** a armadilha de 32× no WAL mede código que a produção
  não executa.

---

## As três correções ao relatório da manhã

### 1. A carga de dados estava completa — procurou-se no sítio errado

A versão da manhã dizia que a carga «não pode ser marcada como concluída» e que
não se encontrava nenhum artefacto de ~6 GB. Encontrou-se:

| | Relatório da manhã | Verificado |
|---|---|---|
| Eventos | 2.805.027 | **8.604.294** |
| Em disco | «nenhum artefacto de ~6 GB» | **8,84 GiB** (1394 segmentos `.hrkl`) |
| Localização | procurou em `D:\DEV` e `%ProgramData%` | **`D:\HeraclitusDB\data`** |

O `data_dir` real vem da variável de máquina `HERACLITUS_DATA_DIR`. O
`%ProgramData%\HeraclitusDB\data` tem dois ficheiros vazios — era esse o
«diretório padrão com 2.374 bytes».

A soma dos 16 agentes em `/fontes` dá **exactamente** 8.604.295 = `head_lsn`:
nenhum LSN por explicar. A ingestão correu de 2026-09-01 06:53:09 a 11:44:58
(4,86 h, 491 ev/s) e fechou de forma ordeira — os quatro datasets de ficheiro
único que correram por último batem ao registo com a fonte (CEIS 23.014,
Expulsões 4.055, CEPIM 3.556, CNEP 1.695), e o `receipts` foi escrito 8 segundos
depois do último evento.

**O que falta na carga não são dados, é uma etapa.** O passo 6 do
`reset-e-carga.ps1` — `edge-builder`, resolução de entidades e arestas do grafo
— nunca correu: não existe agente `edge-builder` em `/fontes`. Daí
`tgraph_edges: 0` e `entity_keys: 0` com 8,6 M nós indexados. Os nós estão lá; o
grafo não tem uma única aresta.

### 2. O CORS estava a funcionar

A versão da manhã, e a minha primeira verificação, diziam que o CORS estava
desligado. Estava mal medido: headers CORS só são emitidos em resposta a um
pedido que traga `Origin`.

```
Origin: http://localhost:9337  ->  access-control-allow-origin: http://localhost:9337
Origin: http://evil.example    ->  (nenhum header)
```

Configurado, activo, e a recusar origens não autorizadas. A configuração do
serviço vem de variáveis `HERACLITUS_*` de máquina — que é o mecanismo previsto
em `service.rs` — e não de um TOML. O `ImagePath` sem argumentos é o desenho
correcto, não uma falha.

Nota lateral: `HERACLITUS_CONFIG` não está definida, portanto o
`config.carga.toml` **nunca foi lido**. As variáveis em vigor contradizem-no
(`fsync=always` contra o `group_commit` que o ficheiro pedia; cifra ligada
contra `false`). Foi por isso que a carga correu a 491 ev/s em vez dos 1760 do
benchmark.

### 3. O Telemetry Health está implementado mas não implantado

A rota existe e está registada. O serviço a correr devolve **404** porque o
binário é de 2026-09-01 06:10 e o merge `c2b7845` é de 2026-09-02 08:56 — o
serviço é 27 horas mais velho que a funcionalidade. Não é uma lacuna de código;
é um redeploy por fazer.

O commit `66f0e41` (política ANCHOR_BEHIND) também **não** está incorporado:
vive no ramo `docs/anchor-behind-policy`; o `main` do Forge está em `9e44161`.

---

## O bloqueio que ninguém tinha visto

**`crates/heraclitus-distill/src/centroid_index.rs` nunca foi commitado.** Zero
linhas de histórico em todo o repositório, e não existia em lado nenhum do
disco. O `lib.rs` declarava `mod centroid_index;` e usava três tipos dele.

Origem: commit `71ff74e`, 2026-09-01 06:06, com a mensagem
`docs: update README.md with full specs...` — que na verdade acrescentou 206
linhas a `heraclitus-distill/src/lib.rs`. A mensagem não descrevia o que o
commit fazia, e o ficheiro em falta passou despercebido.

Consequência: `cargo build/test/clippy --workspace --all-features` falhava em
qualquer clone limpo. O `ci.yml` corre exactamente isso. **O CI não podia estar
verde no main.** E nada disto podia ser qualificado, porque não compilava.

**Resolvido.** O módulo foi reconstruído a partir do contrato de uso, e o
projeto tinha um oráculo forte para o validar: o teste
`indice_de_centroides_e_exercitado_e_equivale_ao_brute_force` exige que a
VP-tree com sobreposição *dirty* produza exactamente o mesmo agrupamento que a
varredura exaustiva — mesmos membros, centróides bit a bit iguais, mesmo
desempate — e que faça menos distâncias do que ela. Passa.

---

## O defeito operacional com mais impacto

**O checkpoint cegava o banco 23% do tempo.** Medido, não inferido:

```
GET /stats às 18:32:06   ->  69 400 ms
janela de checkpoint     ->  18:30:55 a 18:32:05  (70 s, 1,97 GiB)
```

Cada view segurava o seu mutex enquanto serializava **e escrevia** o snapshot
para disco. A cada 300 segundos, durante ~70, qualquer leitor dos índices ficava
preso. Era isto — e não lentidão do banco — que punha o `/stats` a 44 s, o
`/state` a 53 s, e o arranque de sessão da memória do Claude a 8 minutos.

Duas correcções:

1. **`Mutex` → `RwLock` nos sete índices.** `View::checkpoint` recebe `&self`:
   só lê. Estava a usar-se exclusão mútua para uma operação de leitura. Agora o
   checkpoint e as leituras partilham o lock; só `apply`/`restore`/`reset`
   excluem. A migração é auto-verificável — escolher `.read()` onde é preciso
   `&mut` é erro de compilação, nunca incorreção silenciosa.
2. **`/stats` e `/state` saíram do reactor** para `spawn_blocking`, como o
   `verify` já estava. Sem isto, cada pedido bloqueado prendia um fio do
   reactor: meia dúzia de scrapes de monitorização esgotavam o pool e o servidor
   inteiro deixava de responder, `/healthz` incluído. Mediu-se um pico de 7,1 s
   no `/healthz` durante um checkpoint.

O risco óbvio — largar o lock e o estado mexer-se — não se aplica:
`Registry::checkpoint` corre com o mutex do *registry* seguro, e `apply()`
precisa desse mesmo mutex, portanto os watermarks não podem divergir dos bytes.

---

## Estado do roadmap, verificado

O roadmap da versão da manhã misturava dois produtos. **Fabric, Content Hub,
Case Management e SOAR são do Heraclitus-Forge**, não do banco. Para o
HeraclitusDB o quadro é mais curto.

| Marco | Estado | Verificação |
|---|---|---|
| Modelo canónico (0051) | ✅ | `5765e04` e `9e44161` em `main` do Forge |
| HDB2/HFB2 | ✅ | idem |
| Telemetry Health (0062) | 🟢 código feito | crate compila; **404 em produção** — falta redeploy |
| ANCHOR_BEHIND | 🟡 | política escrita, **não fundida** (`66f0e41` fora do main) |
| Connector Fabric (0052) | 🔴 | `fabric.rs:111` recusa arrancar sem `--demo`; corre em `tempdir` com chave efémera |
| Content Hub (0053) | 🔴 | 0 ocorrências de `ContentHub`/`content_hub` nos dois repositórios |
| Case Management (0059) | 🔴 | 0 ocorrências de `CaseAggregate`/`case_management` |
| SOAR (0048) | 🟡 | Sentinel existe; 0 ocorrências de `SoarOrchestrator`/`PlaybookIr`/`SecretResolver` |

## A lista P0 da auditoria, reavaliada contra o código

| # | Item | Verificado a 2026-09-02 |
|---|---|---|
| 1 | Qualificação externa 0049 | Máquina existe e é grande (`soak.rs`, `crash.rs`, `egress.rs`, `doctor.rs`, `sbom.rs`, `evidence.rs` + `qa/qualification/`). **Nunca foi corrida a sério.** |
| 2 | CI + supply chain | **Já existe**: `actions/attest` (proveniência SLSA), sigstore, SBOM, CycloneDX, `security-release.yml`, `qualification-nightly.yml` |
| 3 | Raft na matriz de testes | **Já existe**: `ci.yml` corre `--all-features` (activa `replication`); o nightly corre `-p heraclitus-raft --all-features` |
| 4 | Eliminar transmutes + Miri | ✅ **transmutes feitos hoje** (30 → 0). Miri continua por correr |
| 5 | Armadilha de 32× no WAL | **Obsoleto.** O default já era 8 MiB; a causa estrutural está em `impl Log` (legado). Os benchmarks usam `Log::open`; a produção corre v6/HRKI. O próprio repositório o diz em `corrupcao_nunca_entra_em_panico.rs:27` |
| 6 | PGWire | **Ausente**. 0 ocorrências |
| 7 | OCI/Helm/Operator | Dockerfile, compose e chart Helm escritos hoje — **nunca construídos** (ver ressalvas) |
| 8 | Build enterprise única | Por fazer |
| 9 | ACT ICP-Brasil real | Precisa de entidade externa |
| 10 | 0051→0062 | Trabalho do Forge |

Seis dos dez estavam feitos, obsoletos ou já existiam. Trabalhar a lista às
cegas teria sido desperdício.

---

## O que mudou no repositório hoje

Tudo na árvore de trabalho, **nada commitado**.

| Alteração | Verificação |
|---|---|
| `centroid_index.rs` reconstruído (novo) | 4 testes incl. oráculo de equivalência; clippy `-D warnings`; fmt |
| 30 `unsafe transmute` removidos (6 ficheiros do ingestor) | check + clippy + fmt limpos |
| `Mutex` → `RwLock` nos índices; `checkpoint`/`watermark`/`name` e as contagens do `stats` em `.read()` | 49 testes; clippy `-D warnings`; fmt |
| `stats` e `state` em `spawn_blocking` | idem |
| `Dockerfile`, `.dockerignore`, `deploy/compose.yaml`, chart Helm | **só sintaxe YAML validada** |

E o gate que interessa: **`cargo check --workspace --all-features` termina.**

---

## Ressalvas — o que não está provado

- **O empacotamento nunca foi construído.** A máquina não tem Docker, helm nem
  kubectl. Validou-se a sintaxe YAML dos ficheiros não-templated; os templates
  Helm não foram sequer passados por `helm lint`. A primeira construção faz
  parte da revisão, não é uma formalidade.
- **A correcção do checkpoint não foi medida em produção.** Está correcta por
  construção e passa a suíte, mas o serviço a correr ainda tem o binário antigo.
  Só um redeploy e uma medição durante um checkpoint fecham a prova.
- **`/verify` não termina.** Um Merkle completo de 8,6 M eventos / 6,4 GiB
  excedeu 50 minutos sem concluir. Não acusou corrupção — não chegou ao fim.
  Para um produto cuja tese é provar integridade, isto é um problema por si só,
  e um obstáculo directo a um soak de 168 h.
- **O `heraclitus-ingestor` tem 0 testes.** Os testes «passam» mas não provam
  nada; a garantia ali é o compilador e o clippy.
- **`cargo fmt --all --check` falha no main**, em `auth.rs`, `grpc.rs`,
  `rest.rs:2123` e três ficheiros do ingestor (rustfmt 1.9.0). Nenhum é
  consequência do trabalho de hoje.
- **`Shared::state_hash` não está reencaminhado** (`engine.rs`). Todas as views
  registadas devolvem `None` no dígito de determinismo que o trait descreve como
  «acceptance gate». É exactamente a classe de falha que o comentário ao lado já
  documenta para `checkpoint`/`restore`. Não foi mexido — merece decisão própria.

## Sequência recomendada

1. **Rever o diff de hoje.** É grande e toca no caminho de checkpoint.
2. **Redeploy** — traz o `/telemetry/health` e permite medir a correcção do
   checkpoint.
3. **Correr a qualificação a sério** e assinar o pacote de evidência. A máquina
   existe; falta premir o botão. É o maior retorno por unidade de esforço em
   todo o projeto.
4. **Construir a imagem e o chart** — a primeira construção é a revisão deles.
5. **Decidir o `edge-builder`**: a carga está a metade sem as arestas. É
   append-only e idempotente (`edge_id` determinístico), portanto corre sobre o
   que já lá está, sem reingerir.
6. **PGWire.** Maior retorno de adopção, e o único item da lista que é projecto
   e não execução.
