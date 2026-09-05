# Auditoria HeraclitusDB — estado a 2026-09-05

Este documento existe porque a lista de achados da primeira vaga nunca foi
escrita em lado nenhum: viveu só no transcript, e recuperá-la custou várias
tentativas. **Um achado que não está num ficheiro não existe na próxima sessão.**

> **Aviso de validade.** Veredictos de auditoria expiram. A primeira vaga correu
> a 31/08; a 04/09, **seis dos dez achados confirmados já estavam corrigidos**
> por trabalho entretanto feito. Antes de agir sobre qualquer linha desta tabela,
> **relê o código**. Nunca apliques uma correcção a partir de um relatório.

---

## 1. Corrigido

### Segurança e autorização

| # | Defeito | Onde | Prova |
|---|---|---|---|
| 19 | Sem credenciais, **todo** o pedido gRPC recebia `AccessRole::Admin` — e o caso *loopback sem auth* não imprimia linha nenhuma no arranque | `server/src/lib.rs` | linha de arranque explícita |
| 3 | O `approver` de uma aprovação humana vinha do **corpo do pedido**: qualquer chamador registava uma aprovação em nome de outra pessoa | `server/src/auth.rs`, `rest.rs`, `grpc.rs` | 3 testes, 2 mutações |
| 2 | A superfície REST **não tinha autorização nenhuma** — zero referências a `AccessRole` — e expunha escritas duráveis e operações que o gRPC reserva a Admin | `server/src/rest.rs`, `auth.rs` | 7 testes, 2 mutações |

**Sobre o #2.** O problema de fundo era *assimetria*, não ausência de
autenticação. As duas superfícies passam a resolver credenciais pela mesma
política (`Authenticator::resolver`); as `access_credentials` valem no REST como
`Basic <principal>:<token>`; e `papel_exigido` mapeia (método, caminho) → papel
com **omissão Admin**, tal como o `_ => AccessRole::Admin` do gRPC — uma rota
nova que ninguém classifique fica protegida, não exposta.

*Não parte implantações*: o gatilho é existirem credenciais **com papéis**. Com
só o `auth_token` legado não há papel para contornar e nada muda.

### Pânico e recursos

| # | Defeito | Onde |
|---|---|---|
| 25 | `max_lsn - min_lsn + 1` transbordava; com `overflow-checks` na release é **pânico** — e no caminho que existe para *rejeitar* um segmento corrompido | `log/src/v6/footer.rs` |
| — | `ZMAP_HEADER_LEN + len` com `len` do sidecar: pânico em vez de descartar | `log/src/skip_scan.rs` |
| — | `HEADER_LEN + corpo_len` do snapshot: matava o **arranque** do Sentinel | `sentinel/src/state/snapshot.rs` |
| — | `Vec::with_capacity(footer.record_count)` sem tecto físico (em Rust uma falha de alocação **aborta** o processo) | `log/src/v6/packed.rs` |

### Durabilidade e perda de dados

| # | Defeito | Onde |
|---|---|---|
| 9 | `persist_migration_receipt` fazia `rename` sem `sync_parent_dir` — a função gémea logo acima já o fazia | `log/src/v6/receipts.rs` |
| 11 | A chave do *sighting* era marcada **antes** do append: um `Err` transitório perdia a evidência para sempre, em silêncio | `sentinel/src/lib.rs` |
| 7 | *(parcial)* A colisão de caminho era verificada **depois** de destruir o segmento activo | `log/src/v6/engine.rs` |
| — | **Um** evento com `observed_at` no futuro apagava todo o `rule_history` do L1: a régua da poda era o próprio dado ingerido | `sentinel/src/lib.rs` |
| — | TOCTOU: caminho resolvido sob o *lock*, ficheiro aberto depois; um `seal` concorrente fazia desaparecer um LSN **já comitado** da resposta LGPD | `log/src/v6/engine.rs` |

### Conformidade (RFC 3161 / X.509)

| Defeito | Onde |
|---|---|
| Uma CRL de **uma partição** passava por lista completa do emissor → "não revogado" sobre quem está revogado noutra. `verificar_ambito` lia 4 dos 6 campos do `IssuingDistributionPoint` | `compliance/src/crl.rs` |
| As extensões do TSTInfo eram descodificadas com a etiqueta `[1] IMPLICIT` ainda posta: **todo** o carimbo legítimo com extensões era recusado, e a verificação de criticidade nunca corria | `compliance/src/icp.rs` |

---

## 2. O achado crítico, e o gate que faltava

`WandCursor::new` inicializava o cursor **dentro de um `debug_assert!`**. Essa
macro não avalia a expressão em release: a chamada que descodifica o primeiro
*posting* **desaparecia da build de produção**. Todos os cursores nasciam vazios
e a pesquisa BM25/WAND devolvia zero resultados, sem erro e sem log.

`cargo test -p heraclitus-index-text --release` falhava em **3 testes**,
incluindo o próprio oráculo de equivalência. Em debug passavam todos.

O oráculo existia e estava certo. **Nunca tinha corrido no perfil em que o
produto é enviado** — nenhum job de CI corria `cargo test --release`.

Duas defesas novas em `.github/workflows/ci.yml`:

- `-D clippy::debug_assert_with_mut_call` (verificado: apanha este bug exacto);
- um job `cargo test --workspace --all-features --locked --release`.

`debug_assert!` é a única assimetria entre os dois perfis que muda **semântica**.

---

## 3. Já corrigido antes desta sessão *(verificado contra o código, não assumido)*

| # | Defeito | Como ficou |
|---|---|---|
| 4 | Alocação pelo `record_count` do ficheiro | `.min(body.len())` limita pelo tamanho físico |
| 6 | `rename` do seal sem fsync de `segments/` | `sync_parent_dir` a seguir ao rename |
| 12 | `rule_history` sem tecto e reavaliada por inteiro | podado ao horizonte que o *ruleset* exige; clone profundo removido |
| 18 | `GET /replay?executar=1` corria o rebuild completo | 405 — um GET não muta |
| 24 | Sanitizador aceitava `..` | nome só de pontos recusado |
| 26 | Export parquet materializava o segmento inteiro | lotes, memória O(lote) |

## 4. Refutado

**#5** — «a truncagem da cauda corta no primeiro registo mau». Falso: o `offset`
só avança **depois** de um registo descodificar com sucesso, logo `valid_len` é
exactamente o fim do último registo bom.

---

## 4b. Vaga 3 — descoberta em 6 superfícies novas (2026-09-05)

Seis agentes, zero mortos. **Dois críticos.** O da query foi corrigido nesta
ronda porque está no caminho por omissão (nó único, não só cluster).

### Corrigido nesta ronda

| Gravidade | Defeito | Onde | Prova |
|---|---|---|---|
| **crítica** | `attr_lookup`/`attr_range_lookup` devolviam `Some(vazio)` para valores nunca indexados (`SKIP_VALUES`: `sim`, `true`, `0`, `nao`…; ou texto > 80 B). O planner tomava o vazio como resposta final → **zero linhas sobre dados reais** | `query/plan.rs` + `server/engine.rs` | 2 testes, mutação `left:0 right:1`; predicado `valor_indexavel` unificado entre ingest e consulta |
| média | `rsaEncryption` recusado — a RFC 3370 §3.2 impõe-no em CMS e o OpenSSL emite-o | `compliance/algoritmos.rs`, `icp.rs` | 3 testes; tolerância **limitada ao CMS**, X.509 continua a exigir OID combinado |
| média | Checkpoint da activation não persistia `proximo_slot`; restore deixava o buffer circular a apontar para o slot errado | `activation/lib.rs` | 1 teste + mutação; **derivado de `n`**, sem mudar o formato |
| média | `GET /titular/:id` bloqueava o reactor tokio | `server/rest.rs` | `spawn_blocking`, como os outros 57 handlers |
| **crítica** | `skip_normals` descartava episódios replicados no primeiro arranque durável sobre log não-vazio; e `cluster::spawn` a falhar degradava para escrita local não replicada, acked | `raft/consensus.rs`, `server/lib.rs` | **recusa arrancar** em ambos os casos (a máquina de estados assume que possui o log desde o LSN 0); teste + mutação; sem mudança de formato |
| alta | `ColdTier::compact_cold_prepared` recompactava sem autenticar os bytes contra o recibo de origem — corrupção "lavada" | `tier/lib.rs` | autentica com `scan_and_root`; teste + mutação |
| alta | HNSW podia deixar um nó órfão quando os vizinhos alcançáveis estão todos tombstoned | `index-vector/lib.rs` | liga ao entry como recurso; teste + mutação |
| alta | `GraphIndex`/`TextIndex` entravam em pânico em restore em vez de degradar | `index-graph`, `index-text` | valida coerência → `Ok(false)` (rebuild); teste + mutação no TextIndex |
| média | Checkpoint HNSW não validava ids de vizinhos contra `nodes.len()` | `index-vector/lib.rs` | valida no restore; teste + mutação |

### Vaga 3 — em aberto

| Gravidade | Defeito | Onde | Porque fica |
|---|---|---|---|
| alta | Rótulos de nó (`MATCH (a:Pessoa)`) parseados e **descartados** pelo planner | `query/plan.rs:127` | **Decisão semântica:** o grafo temporal trata nós como ids de entidade, sem *kind*. O que `:Pessoa` significa num padrão de relação (kind do episódio? tipo de entidade? não suportado?) não está definido. Um fix errado é pior que nenhum. |
| média | systemd `READY=1` antes do `bind`; SCM Windows reporta `Running`/`Stopped` cedo; `LakehousePublisher` revarre todo o Parquet | plataforma | Específicos de plataforma / perf, não correcção de dados. |

**Sobre o crítico do raft:** a máquina de estados assume que possui o log desde o
LSN 0 (`install_snapshot` usa `lsn = índice`). Em vez de espalhar aritmética de
offset frágil por `apply`/`install_snapshot`, o fix **recusa arrancar** um nó
durável sobre um log com episódios não-raft, e o servidor recusa arrancar se a
replicação configurada não subir — fechando o ciclo que suja o log. Sem mudança
de formato.

---

## 5. Em aberto (vagas 1–2)

| Gravidade | Defeito | Nota |
|---|---|---|
| alta | **#7, janela pós-`seal`** | Depois de `seal()` o writer foi consumido e não há o que repor sem reabrir o ficheiro. Fechar a janela é uma **decisão de desenho** do motor de armazenamento — improvisar rollback ali arrisca perda de dados, que é pior do que a necessidade de reiniciar. |

### Lacunas de cobertura, ditas por extenso

- **#11 não tem teste.** Não há API pública para carregar indicadores e conduzir
  a avaliação de ameaças; provar a correcção exige montagem integrada grande.
  Está corrigido por simetria com o caminho dos *signals*, que faz a ordem certa
  na mesma função.
- **O TOCTOU não tem teste determinista.** A janela não é injectável sem um
  *hook*, e um teste de corrida que falha 1 em N é pior do que nenhum.

---

## 6. Método — o que funcionou

1. **Verificar → reproduzir → corrigir → mutar.** Uma correcção sem um teste que
   morra ao revertê-la não está provada. O pânico do #25 e o bug do WAND foram
   *reproduzidos* antes de serem tocados.
2. **Procurar o irmão.** Quase todos os defeitos tinham gémeos: a função ao lado
   que já fazia `sync_parent_dir`, o caminho dos *signals* que já marcava a chave
   depois do append, o `_ => Admin` do gRPC que faltava ao REST. Uma assimetria
   entre duas funções irmãs é o sinal mais barato que existe.
3. **Auditar o próprio trabalho.** Quatro dos achados desta vaga estão em código
   escrito nesta mesma linhagem de sessões. Incluir o código novo na varredura
   não é cerimónia.
4. **Contar os agentes que morrem.** Numa vaga anterior, 13 de 24 agentes
   morreram no limite semanal — incluindo **todos** os refutadores. Aritmética de
   workflow que não lê o campo `failures` conta mortos como refutações.
