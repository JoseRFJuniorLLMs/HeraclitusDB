# AUDITORIA RECURSIVA R10 — HeraclitusDB / HUME

**Repositório:** `JoseRFJuniorLLMs/crates`  
**HEAD auditado:** `6f0edddce810253c4ac983ef8baf0132c3663335`  
**Data:** 2026-08-31 (America/Sao_Paulo)  
**Método:** auditoria estática recursiva em 10 passes, com confirmação cruzada no HEAD atual.

> Esta auditoria separa defeitos confirmáveis por inspeção do código de hipóteses que ainda exigem execução. O objetivo não é produzir um relatório bonito; é produzir alvos reproduzíveis para uma segunda IA tentar derrubar.

---

## 1. Veredito executivo

O código contém várias decisões de segurança maduras, especialmente nos gates de produção, integridade de segmentos, TLS/mTLS, RBAC, tratamento de bit rot e validação de evidência criptográfica.

Mesmo assim, **o HEAD atual não deve ser tratado como pronto para homologação de alta criticidade** antes da correção dos itens P0/P1 abaixo.

Resumo:

| Classe | Quantidade | Situação |
|---|---:|---|
| BLOCKER | 1 | workspace/reprodutibilidade |
| CRITICAL | 2 | split-brain por fail-open Raft; UB via API JIT safe |
| HIGH | 5 | crypto-shred concorrente; permissões de chave fail-open; record oversized legado; alinhamento arena; gap de assurance/CI |
| MEDIUM | 4 | mmap/EOF de corrupção; auditoria fail-open; resource budgeting; colisão do marcador de cifra |
| LOW | 1 | métrica de fila pode divergir via receiver público |

---

# 2. As 10 iterações recursivas

## R1 — Topologia, workspace e reprodutibilidade

Objetivo:
- descobrir a unidade real de build;
- verificar manifestos;
- verificar se o repositório é reproduzível isoladamente.

Resultado principal:
- não existe `Cargo.toml` na raiz do repositório;
- crates como `heraclitus-retrieval/Cargo.toml` usam `version.workspace = true`, `edition.workspace = true` e dependências `{ workspace = true }`.

Conclusão:
- no estado atual deste repositório, um clone isolado não contém o manifesto pai necessário para resolver a herança de workspace;
- se o repositório foi intencionalmente publicado como subárvore de outro workspace, esse workspace externo precisa ser versionado e documentado como dependência formal.

---

## R2 — `unsafe`, FFI, JIT e memória

Foram buscados:
- blocos `unsafe`;
- raw pointers;
- FFI;
- transmute;
- arenas;
- alocadores;
- JIT;
- invariantes escondidos atrás de APIs safe.

Achados:
- `JitFilter::run` é uma API `safe` com precondições de memory safety não verificadas;
- `ScratchAllocator::alloc_bytes` promete alinhamento arbitrário power-of-two, mas o backing buffer só garante 64 bytes.

---

## R3 — Persistência, formato, CRC, Merkle e corrupção

Foram cruzados:
- encoder x decoder;
- limites de tamanho;
- recovery;
- truncamento;
- mmap;
- tratamento de `Torn`;
- roll de segmento.

Achados:
- encoder legado aceita payload que o decoder rejeita;
- `MappedSegment::records()` não diferencia footer limpo de corrupção/torn;
- `MappedSegment::open()` é safe, embora dependa de uma precondição de segurança externa.

Ponto positivo:
- o recovery atual recusa truncar corrupção em segmento não ativo e preserva o arquivo para perícia.

---

## R4 — Concorrência, atomics e invariantes compartilhadas

Foram buscados:
- `Atomic*`;
- `Relaxed`;
- `DashMap`;
- locks;
- check-then-act;
- caches;
- filas;
- TOCTOU.

Achado principal:
- `KeyStore::shred()` não serializa a exclusão da chave com `get()`/`get_or_create()`.

Achado latente:
- `SecurityQueue::receiver()` entrega um `Receiver` cru; leituras feitas por ele não decrementam o contador `depth`.

---

## R5 — Rede, gRPC, REST, Flight e limites

Foram verificados:
- bind não-loopback;
- TLS;
- mTLS;
- autenticação;
- tamanhos de mensagem;
- chamadas bloqueantes;
- endpoints mutáveis.

Falsos positivos refutados:
- REST sem auth fora de loopback não é um bug atual: `validate_security()` exige REST administrativo em loopback;
- gRPC não-loopback exige autenticação e TLS;
- Raft não-loopback exige gRPC mTLS;
- o bug histórico de 4 MiB no transporte Raft gRPC está corrigido no código atual.

Risco restante:
- política de `resource budgeting` não está centralizada para `k`, profundidade e custo máximo de query.

---

## R6 — Autenticação, autorização e segredos

Pontos positivos:
- Bearer é associado a principal;
- RBAC é explícito;
- comparação de token usa comparação constante;
- produção exige principals separados;
- token legado é proibido em produção;
- REST administrativo é loopback;
- gRPC remoto exige TLS.

Achado:
- a proteção Unix dos arquivos/diretório de chave é best-effort e ignora erro de `set_permissions`.

---

## R7 — Criptografia, crypto-shred e compliance

Foram verificados:
- AEAD;
- nonce;
- AAD;
- keystore;
- shred;
- trust store;
- TSA;
- CRL;
- modos soberanos.

Pontos positivos:
- ChaCha20-Poly1305;
- nonce aleatório;
- `agent_id` como AAD;
- produção exige TSA HTTPS, trust store e CRLs.

Achados:
- corrida `shred/get`;
- permissões fail-open;
- detecção de ciphertext por magic prefix pode classificar plaintext legado escolhido como ciphertext.

---

## R8 — Parsing, inputs e exaustão de recursos

Foram buscados:
- tamanhos sem teto;
- profundidades;
- `k`;
- `Vec::with_capacity(k)`;
- parsers;
- scans;
- limites de mensagens.

Resultado:
- há bons caps locais (`QUERY_SCAN_CAP`, HRKI etc.);
- o AST aceita `k` e profundidades sem um teto global;
- o RPC de recall normaliza `k >= 1`, mas não impõe teto explícito.

Classificação:
- MEDIUM até um teste dinâmico provar OOM/DoS em um backend vivo.

---

## R9 — Crash, failover, consenso e recuperação

Achado crítico:
- se `config.replication` está configurado e `cluster::spawn()` falha, o servidor registra warning e continua;
- como o `ReplRouter` não é instalado, `Engine::append()` volta ao caminho local;
- isso permite que um nó que deveria pertencer a um cluster passe a aceitar escrita fora do consenso.

Conclusão:
- replicação configurada precisa ser fail-closed.

Achado adicional:
- meta-auditoria ignora erro de append.

---

## R10 — CI, supply chain e prova de build

No HEAD auditado:
- nenhum status de CI associado ao commit;
- `.github/workflows` não está presente;
- não foi localizado `Cargo.lock` na árvore;
- não foi localizado `deny.toml`;
- não foi localizado `rust-toolchain`/`rust-toolchain.toml`;
- o workspace raiz necessário também não está no repositório.

Isso é um gap de assurance, não prova de vulnerabilidade de runtime.

---

# 3. Achados consolidados

## F-001 — BLOCKER — Workspace raiz ausente

**Componentes**
- raiz do repo
- manifests que usam herança de workspace

**Evidência**
`heraclitus-retrieval/Cargo.toml` contém:

```toml
version.workspace = true
edition.workspace = true

[dependencies]
heraclitus-core = { workspace = true }
serde = { workspace = true }
```

Mas não existe `Cargo.toml` na raiz do repositório auditado.

**Impacto**
- build isolado não reproduzível;
- `cargo metadata` não possui a fonte do workspace;
- CI, `cargo test --workspace`, `cargo deny`, SBOM e lockfile não podem ser demonstrados a partir deste repositório sozinho.

**Correção**
1. restaurar/versionar o `Cargo.toml` raiz;
2. versionar `Cargo.lock` para o produto/binários;
3. definir `[workspace.package]`, `[workspace.dependencies]` e `members`;
4. adicionar README de build reproduzível.

**Gate**
```bash
cargo metadata --locked --format-version 1
cargo check --workspace --all-targets --all-features --locked
```

---

## F-002 — CRITICAL — Replicação Raft falha aberta para modo standalone

**Arquivo**
`heraclitus-server/src/lib.rs`

**Símbolo**
`serve_with`

**Padrão**
```rust
match cluster::spawn(...).await {
    Ok((handle, tasks)) => {
        engine.set_replication(handle);
        ...
    }
    Err(e) => {
        boot.warn_line(...);
        None
    }
}
```

Se `cluster::spawn` falha, o processo continua.

`Engine::append()` só usa consenso quando `self.replication.get()` contém um router. Sem ele, o caminho local continua disponível.

**Impacto**
- escrita fora do consenso;
- split-brain;
- LSN/state divergentes;
- evidência forense diferente por nó;
- violação direta do contrato de replicação.

**Correção**
- `config.replication.is_some()` + falha de `cluster::spawn` => `Err` fatal;
- não abrir listeners mutáveis antes de o cluster estar operacional;
- health/readiness deve ficar `NOT_READY` enquanto o nó não tiver entrado no cluster.

**Teste obrigatório**
injetar falha determinística em `cluster::spawn` e provar que:
- `serve_with()` retorna erro;
- nenhuma chamada `append` é aceita;
- nenhum listener mutável fica disponível.

---

## F-003 — CRITICAL — `JitFilter::run` é safe, mas depende de precondições unsafe

**Arquivo**
`hume-ir/src/jit.rs`

**Símbolo**
`JitFilter::run`

A documentação exige:
- `cols` cobrir todas as colunas da IR;
- cada coluna possuir pelo menos `n` elementos.

Mesmo assim a função é:

```rust
pub fn run(&self, cols: &[ColumnData], n: usize) -> Vec<u32>
```

O JIT gerado faz loads nativos por ponteiro:
- lê `cols[idx]` por aritmética de ponteiro;
- lê `col_ptr[row * 8]`;
- não há bounds check.

**Impacto**
um chamador 100% safe consegue violar a precondição e induzir leitura fora dos limites no código nativo.

Isso quebra a regra básica de abstração segura do Rust: safe code não pode exigir do chamador uma obrigação cuja violação cause UB.

**Correção recomendada**
`JitFilter` deve guardar no compile:
- maior índice de coluna;
- tipo esperado por coluna;
- schema mínimo.

`run()` deve:
1. validar `cols.len()`;
2. validar variante `I64/F64`;
3. validar `slice.len() >= n`;
4. validar `n <= u32::MAX` se os resultados continuam sendo `u32`;
5. retornar `Result<Vec<u32>, IrError>`.

Alternativa inferior:
- tornar `run` `unsafe fn`, documentando formalmente `# Safety`.

**Testes**
- IR referencia coluna 1, mas `cols` contém apenas coluna 0;
- coluna possui 1 item e `n=2`;
- IR espera F64, caller fornece I64;
- rodar harness com ASan;
- comparar JIT x interpretador em property tests.

---

## F-004 — HIGH — Corrida em `KeyStore::shred` pode ressuscitar chave na cache

**Arquivo**
`heraclitus-crypto/src/lib.rs`

**Símbolos**
- `KeyStore::get`
- `KeyStore::get_or_create`
- `KeyStore::shred`

Sequência possível:

1. thread A: `shred()` faz `cache.remove(agent)`;
2. antes de A remover o arquivo, thread B chama `get(agent)`;
3. B lê a chave ainda existente do disco;
4. B reinsere a chave no `DashMap`;
5. A zera/remove o arquivo e retorna `Ok(true)`;
6. chamadas posteriores a `get(agent)` recebem a chave da cache.

**Impacto**
- `shred()` pode reportar sucesso sem tornar os dados indecriptáveis dentro do processo;
- viola diretamente a propriedade de crypto-erasure prometida.

**Correção**
usar serialização por `agent_id`:
- mutex/lock striping por agente; ou
- estado geracional/tombstone atômico.

Invariante:
> depois que `shred(agent)` retorna sucesso, nenhum `get/get_or_create` pode devolver a geração antiga da chave.

---

## F-005 — HIGH — Permissões de keystore são fail-open

**Arquivo**
`heraclitus-crypto/src/lib.rs`

As funções:

```rust
restrict_dir_perms(...)
restrict_file_perms(...)
```

fazem:

```rust
let _ = std::fs::set_permissions(...);
```

O erro é descartado.

O arquivo é criado com `OpenOptions::create_new(true)` sem `OpenOptionsExt::mode(0o600)`.

**Impacto**
se o chmod falhar, o código continua e escreve a chave em claro mesmo sem ter conseguido aplicar a proteção que a documentação promete.

**Correção Unix**
- criar arquivo já com `mode(0o600)`;
- criar diretório já com `mode(0o700)`;
- propagar qualquer erro ao inicializar/gerar chave;
- verificar permissões após criação.

**Windows**
- implementar ACL explícita para perfil/serviço;
- ou impedir `production_mode` sem um backend de ACL validado.

---

## F-006 — HIGH — Encoder legado pode gravar record que o próprio decoder rejeita

**Arquivos**
- `heraclitus-log/src/format.rs`
- `heraclitus-log/src/lib.rs`

`encode_record`:
```rust
(payload.len() as u32)
```

sem limite.

`decode_record`:
```rust
if len > 512 * 1024 * 1024 {
    return Decoded::Torn;
}
```

O writer legado serializa o payload e chama `encode_record` sem verificar o mesmo limite.

**Impacto**
um payload grande pode:
- ser aceito pelo encoder;
- ser persistido/fsync;
- tornar-se ilegível na reabertura;
- ser interpretado como `Torn`;
- no segmento ativo, cair no caminho de repair/truncate.

Há ainda truncamento de comprimento se `payload.len() > u32::MAX`.

**Correção**
criar uma única constante canônica:

```rust
pub const MAX_RECORD_PAYLOAD: usize = ...;
```

e exigir o limite:
- antes da serialização pesada;
- no encoder;
- no decoder;
- na API de append.

`encode_record` deve retornar `Result`.

---

## F-007 — HIGH — `ScratchAllocator` não garante alinhamento > 64 bytes

**Arquivos**
- `hume-kernel/src/arena.rs`
- `hume-kernel/src/memory.rs`

`AlignedBuffer` garante alinhamento de 64 bytes.

`alloc_bytes(n, align)` aceita qualquer potência de dois e arredonda apenas o **offset**:

```rust
let start = (cur + align - 1) & !(align - 1);
```

Esse cálculo só funciona para alinhamentos maiores que o backing se o endereço base já estiver alinhado ao mesmo valor, o que não é garantido.

Exemplo:
- base = 64 mod 128;
- `start = 128`;
- `base + 128` continua = 64 mod 128.

**Impacto**
- contrato público de alinhamento falso;
- downstream pode fazer cast/SIMD acreditando em alinhamento que não existe;
- potencial UB em código que usar instruções/tipos com exigência superior.

**Correção**
Opção A:
- rejeitar `align > CACHE_LINE`.

Opção B:
- calcular padding com o **endereço absoluto**;
- usar aritmética checked;
- garantir capacidade considerando o padding real.

Também corrigir:
```rust
cur + align - 1
```
para forma checked.

---

## F-008 — MEDIUM — `MappedSegment` expõe invariantes de `unsafe` por API safe e mascara `Torn` como EOF

**Arquivo**
`heraclitus-log/src/mmap.rs`

`MappedSegment::open(path)` é `safe`, mas a própria documentação diz que o caller precisa garantir que o arquivo é sealed/imutável porque truncamento externo durante mmap viola o safety contract.

Além disso:

```rust
match decode_record(...) {
    Decoded::Record(...) => Some(...),
    _ => None,
}
```

Logo:
- `Footer` => `None`;
- `Torn`/CRC inválido => `None`.

**Impacto atual**
baixo/médio porque o próprio módulo afirma não estar ligado ao scan vivo.

**Risco se promovido**
- corrupção pode parecer um stream legitimamente mais curto;
- uma API safe depende de precondição externa não expressa pelo tipo.

**Correção**
- `MappedSegment::open(SealedSegmentHandle)` em vez de path arbitrário;
- ou tornar o construtor `unsafe` se não houver forma de provar o invariável;
- iterator deve ser `Iterator<Item = Result<Record, Corruption>>`;
- footer limpo e `Torn` precisam ser estados distintos.

---

## F-009 — MEDIUM — Meta-auditoria é fail-open e silenciosa

**Arquivo**
`heraclitus-server/src/engine.rs`

`audit_query` e `audit_admin` fazem:

```rust
let _ = self.append(e);
```

Produção exige `audit_queries=true`, mas erro de append da auditoria é descartado.

**Impacto**
em disco cheio, falha de consenso ou falha física:
- operação pode acontecer;
- registro imutável de auditoria pode não existir;
- nenhuma evidência obrigatória é produzida pelo próprio método.

**Correção**
política diferenciada:
- operação administrativa mutável: fail-closed se o audit append falhar;
- query read-only: pode ser fail-open, mas deve degradar health e incrementar contador persistente/telemetria;
- nunca descartar o erro silenciosamente.

---

## F-010 — MEDIUM — `k` e profundidades não possuem budget global

**Arquivos**
- `heraclitus-query/src/ast.rs`
- `heraclitus-server/src/grpc.rs`
- backends de query

O parser converte inteiros diretamente para `k`/depth sem limite global.

O RPC `Recall` garante apenas `k >= 1`.

**Impacto potencial**
- CPU excessiva;
- heap excessiva em implementações que fazem `with_capacity(k)`;
- traversals muito caros;
- DoS por cliente autenticado.

**Correção**
definir budgets canônicos:
- `MAX_QUERY_K`;
- `MAX_TRAVERSE_DEPTH`;
- `MAX_QUERY_TEXT_BYTES`;
- `MAX_VECTOR_DIMS`;
- `MAX_RESULT_BYTES`;
- deadline/cancellation.

Validação deve acontecer antes de entrar no backend.

---

## F-011 — MEDIUM — Magic prefix de cifra pode colidir com plaintext legado

**Arquivos**
- `heraclitus-crypto/src/lib.rs`
- `heraclitus-log/src/lib.rs`

`is_encrypted(blob)` decide apenas por:

```text
HRKLENC1 + tamanho mínimo
```

Conteúdo legado em claro é arbitrário. Portanto um payload escolhido que comece por esse prefixo pode ser classificado como ciphertext quando o log for lido com keystore habilitado.

Cenários:
- sem chave: registro plaintext pode aparecer como `[shredded]`;
- com chave do agente: tentativa de AEAD pode falhar como “assinatura inválida”.

**Correção**
o estado `encrypted` deve ser parte explícita/versionada do envelope físico, não inferido do conteúdo do usuário.

---

## F-012 — HIGH assurance gap — Sem prova automatizada de CI/supply chain no HEAD

**Observado**
- nenhum status de CI no HEAD;
- sem `.github/workflows`;
- sem `Cargo.lock` visível;
- sem `deny.toml`;
- sem `rust-toolchain`;
- workspace raiz ausente.

**Impacto**
não é uma vulnerabilidade por si só.

Mas impede provar continuamente:
- build;
- testes;
- Clippy;
- fmt;
- advisories;
- licenças;
- fontes duplicadas;
- Miri;
- fuzz;
- supply chain;
- SBOM.

**Correção**
CI mínima no próprio commit:
- fmt;
- clippy `-D warnings`;
- test workspace/all-features/locked;
- cargo audit;
- cargo deny;
- cargo machete;
- cargo geiger;
- Miri para crates unsafe;
- fuzz smoke;
- gitleaks;
- SBOM CycloneDX;
- artefato assinado + provenance/SLSA.

---

## F-013 — LOW / LATENTE — `SecurityQueue::receiver()` quebra a métrica `depth`

**Arquivo**
`heraclitus-sentinel/src/queue.rs`

`recv_timeout()` decrementa `depth`.

Mas:
```rust
pub fn receiver(&self) -> Receiver<Lsn> {
    self.rx.clone()
}
```

Quem consumir pelo receiver bruto remove item da fila sem decrementar `depth`.

A busca no HEAD não encontrou caller de `.receiver()`, então hoje é latente.

**Correção**
- remover o receiver bruto;
- fornecer wrapper tracked;
- ou eliminar `depth` manual e consultar `rx.len()` quando apropriado.

---

# 4. Pontos fortes confirmados

A auditoria também encontrou controles que merecem permanecer:

1. gRPC não-loopback exige autenticação + TLS.
2. Raft não-loopback exige gRPC mTLS.
3. REST administrativo é forçado a loopback.
4. produção exige `fsync=always`.
5. produção exige cifra em repouso e auditoria.
6. produção exige principals RBAC separados.
7. token legado é proibido em produção.
8. TSA HTTP é recusada em produção.
9. produção exige trust store e CRLs.
10. corrupção em segmento legado não ativo falha alto e preserva evidência.
11. Raft gRPC atual configura teto ampliado de mensagem.
12. pesquisas por padrões de segredo encontraram vetores de teste, não uma chave privada real confirmada.

---

# 5. Ordem de correção recomendada

## P0 — antes de qualquer benchmark/homologação

- F-001 workspace raiz/reprodutibilidade;
- F-002 Raft fail-open;
- F-003 JIT safe → UB.

## P1 — segurança/durabilidade

- F-004 crypto-shred race;
- F-005 permissões do keystore;
- F-006 record size legado;
- F-007 alinhamento da arena;
- F-012 CI/supply-chain gate.

## P2 — hardening

- F-008 mmap;
- F-009 auditoria fail-open;
- F-010 resource budgets;
- F-011 marcador de cifra.

## P3

- F-013 métrica da fila.

---

# SPEC-VERIFY-R10 — Verificação Independente da Auditoria Recursiva

**Status:** proposta de gate de confirmação  
**Objetivo:** uma segunda IA deve tentar **refutar**, e não apenas confirmar, os achados F-001..F-013.  
**Commit-base obrigatório:** `6f0edddce810253c4ac983ef8baf0132c3663335`

---

## S0. Regra de independência

A IA verificadora deve:

1. fazer checkout exato do SHA;
2. não assumir que esta auditoria está correta;
3. localizar cada símbolo novamente;
4. reproduzir quando possível;
5. registrar comando, saída, arquivo e função;
6. classificar cada item como:
   - `CONFIRMADO`;
   - `REFUTADO`;
   - `INCONCLUSIVO`;
7. se refutar, explicar qual invariante/caller/validação invalida o cenário;
8. não modificar o código antes de terminar o diagnóstico inicial.

---

## S1. Gate de identidade do código

Executar:

```bash
git rev-parse HEAD
git status --porcelain
git ls-tree -r --name-only HEAD > tree.txt
```

Aceitação:
- HEAD exatamente igual ao SHA da SPEC;
- árvore limpa;
- qualquer diferença invalida comparação direta e deve gerar `ESCOPO_DIVERGENTE`.

---

## S2. Gate de workspace

Executar:

```bash
test -f Cargo.toml
cargo metadata --format-version 1
cargo metadata --manifest-path heraclitus-retrieval/Cargo.toml --format-version 1
```

Confirmar/refutar F-001.

Se existir um workspace externo exigido pelo projeto:
- identificá-lo;
- mostrar documentação que o torna parte formal do build;
- provar build reproduzível do zero.

---

## S3. Gate de compilação e baseline

Depois de restaurar o workspace canônico, executar:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Relatório:
- número de crates;
- número de testes;
- falhas;
- warnings;
- features não cobertas.

---

## S4. Verificação F-003 — JIT memory safety

Criar testes adversariais:

### Caso A — coluna ausente
IR referencia `Column(1, I64)`, caller fornece somente coluna 0.

### Caso B — coluna curta
IR referencia coluna 0, slice possui 1 elemento, `n=2`.

### Caso C — tipo divergente
IR compila coluna como F64, caller fornece `ColumnData::I64`.

Executar em configuração adequada:

```bash
RUSTFLAGS="-Zsanitizer=address" \
cargo +nightly test -p hume-ir --target <host-target> -- --nocapture
```

Se ASan não for possível:
- usar Valgrind/Dr. Memory;
- instrumentar guard pages;
- provar estaticamente se a API safe alcança raw load sem validação.

**Critério**
F-003 só pode ser `REFUTADO` se a IA provar uma validação anterior obrigatória que todo caller safe é incapaz de contornar.

---

## S5. Verificação F-007 — alinhamento da arena

Testar:

```rust
for align in [128, 256, 4096, 65536] {
    // repetir alocações para evitar coincidência fortuita do allocator
    assert_eq!(ptr as usize % align, 0);
}
```

Também testar overflow:

```rust
alloc_bytes(1, 1usize << (usize::BITS - 1))
```

A IA deve analisar o endereço absoluto, não apenas o offset.

---

## S6. Verificação F-004 — corrida de crypto-shred

Criar harness com barreiras/hooks determinísticos:

Thread A:
1. remove cache;
2. pausa antes de remover arquivo.

Thread B:
1. chama `get(agent)`;
2. lê arquivo;
3. reinsere na cache.

Thread A:
4. remove arquivo;
5. retorna.

Depois:

```rust
assert_eq!(ks.get(agent), None);
```

O teste deve falhar no código vulnerável e passar após a correção.

Executar também:
- `get_or_create` concorrente com `shred`;
- 1000 ciclos;
- TSAN se toolchain suportar;
- stress em filesystem real.

---

## S7. Verificação F-005 — permissões

Unix:

```bash
umask 022
```

Validar:
- diretório `0700`;
- chave `0600`;
- erro de chmod não pode ser ignorado.

Criar um `FsOps`/filesystem mock que faça `set_permissions` falhar.

Critério:
- criação da chave precisa falhar fechada;
- nenhum byte secreto pode ser escrito se as permissões não puderem ser garantidas.

Windows:
- documentar ACL efetiva;
- validar que apenas identidade do serviço/administradores autorizados leem a chave.

---

## S8. Verificação F-006 — oversized legacy record

Teste estático obrigatório:
- confirmar que encoder e decoder usam limites diferentes.

Teste dinâmico:
1. criar payload `512 MiB + 1`;
2. chamar o caminho legado de append;
3. exigir erro **antes** do write;
4. se append retornar sucesso, fechar;
5. reabrir;
6. provar se o LSN continua legível.

Também testar:
- `u32::MAX`;
- `u32::MAX + 1` quando ambiente permitir;
- record maior que `segment_max_bytes`.

**Aceitação futura**
nenhuma API pode confirmar durabilidade de um registro que o decoder canônico rejeita.

---

## S9. Verificação F-002 — Raft fail-closed

Injetar falha em `cluster::spawn`:
- cert inválido;
- porta inválida;
- peer inalcançável;
- storage do raft corrompido;
- mock explícito.

Com `config.replication = Some(...)`, verificar:

```text
serve_with(...) -> Err
```

e:

```text
nenhum append local aceito
```

Teste adicional:
- matar/jam transport no boot;
- nó não pode reaparecer como standalone escritor.

---

## S10. Verificação F-008 — mmap/corrupção

### Contrato safe
A IA deve provar uma das duas coisas:
- `MappedSegment::open` só é alcançável com um handle que garante imutabilidade;
- ou o caller safe pode fornecer path arbitrário.

### `Torn` x footer
Criar segmento:
- record 0 válido;
- record 1 CRC adulterado.

Iterator deve produzir:
```text
Ok(record0)
Err(Corruption)
```

e não simplesmente EOF.

---

## S11. Verificação F-009 — auditoria fail-open

Injetar falha de append:
- disk full;
- poisoned writer;
- erro do router Raft.

Executar operação administrativa.

Registrar:
- operação aconteceu?
- `AuditAdmin` existe?
- erro foi propagado?
- health mudou?

**Gate recomendado**
operação administrativa mutável não pode concluir `OK` se o evento de auditoria obrigatório não puder ser comprometido no log.

---

## S12. Verificação F-010 — resource budgeting

Fuzz/property tests com:

```text
k = 0
k = 1
k = 10
k = 250000
k = usize::MAX
depth = usize::MAX
vector dims = 0 / huge
query text = múltiplos MB
```

Critério:
- rejeição precoce;
- `InvalidArgument`/erro de query;
- sem alocação proporcional ao valor fornecido antes do clamp;
- sem panic;
- sem OOM;
- respeitar deadline/cancellation.

---

## S13. Verificação F-011 — magic prefix de cifra

Criar episódio legado plaintext cujo `content` seja:

```text
HRKLENC1xxxxxxxxxxxxxxxx
```

Depois abrir log com keystore habilitado.

Verificar:
- conteúdo não pode virar `[shredded]`;
- conteúdo não pode gerar falso erro de AEAD;
- marker criptográfico deve vir do formato, não dos bytes controlados pelo usuário.

---

## S14. Supply chain

Obrigatório:

```bash
cargo audit
cargo deny check
cargo tree -d
cargo machete
```

Além disso:
- `cargo geiger`;
- gitleaks;
- SBOM CycloneDX/SPDX;
- provenance do binário;
- assinatura do artefato;
- lista de crates com `unsafe`;
- advisories transitivos;
- licenças incompatíveis;
- dependências Git não pinadas;
- dependências path fora do repo.

---

## S15. Miri, sanitizers, fuzzing e concurrency

### Miri
Rodar nos crates sem JIT/FFI incompatível:

```bash
cargo +nightly miri test -p hume-kernel
cargo +nightly miri test -p heraclitus-crypto
cargo +nightly miri test -p heraclitus-log
```

### Fuzz
Targets mínimos:
- `decode_record`;
- footer/header;
- canonical v6;
- parsers GQL;
- threat/STIX;
- compliance ASN.1/TSA;
- H-VM decoder.

### Concorrência
- Loom onde possível;
- stress de KeyStore;
- queue;
- append/group commit;
- catalog ArcSwap;
- Raft apply/snapshot.

---

## S16. Fault injection

Executar:

- `kill -9` durante append;
- kill durante roll;
- kill durante checkpoint;
- kill durante pack RAW→PACKED;
- disk full;
- fsync error;
- partial write;
- bit flip em record;
- bit flip em footer;
- segmento truncado;
- chave incompleta após crash;
- perda do líder;
- partition;
- follower atrasado;
- snapshot grande;
- restore total.

Invariante:
> falha nunca pode ser convertida silenciosamente em histórico válido diferente.

---

## S17. Prova final de determinismo

Em duas máquinas/processos limpos:

1. copiar o mesmo log;
2. rebuild desde LSN 0;
3. obter state hashes;
4. comparar:
   - graph;
   - attr;
   - text;
   - vector;
   - temporal;
   - activation;
   - Sentinel derived state.

Gate:
```text
hash_A == hash_B
```

---

# 6. Formato obrigatório do relatório da IA verificadora

Para cada finding:

```markdown
## F-00X

Status: CONFIRMADO | REFUTADO | INCONCLUSIVO
Severidade revisada: ...
Commit: ...
Arquivo(s): ...
Símbolo(s): ...

### Evidência estática
...

### Reprodução
Comando:
...

Saída:
...

### Tentativa de refutação
...

### Conclusão
...

### Teste de regressão proposto
...
```

A IA verificadora deve terminar com:

```text
P0_CONFIRMADOS=
P1_CONFIRMADOS=
REFUTADOS=
INCONCLUSIVOS=
BUILD_REPRODUZIVEL=true|false
MIRI=pass|fail|not-run
ASAN=pass|fail|not-run
FUZZ=pass|fail|not-run
CARGO_AUDIT=pass|fail|not-run
CARGO_DENY=pass|fail|not-run
RAFT_FAIL_CLOSED=pass|fail
CRYPTO_SHRED_LINEARIZABLE=pass|fail
VEREDITO=REPROVADO|CONDICIONAL|APROVADO
```

---

# 7. Critério de aprovação

A revisão independente só pode declarar **APROVADO** se:

- F-001 resolvido;
- F-002 resolvido e teste de fail-closed verde;
- F-003 resolvido e teste adversarial/sanitizer verde;
- F-004 linearizável;
- F-005 permissões fail-closed;
- F-006 encoder/decoder com limite único;
- F-007 contrato de alinhamento verdadeiro;
- nenhum P0/P1 novo;
- workspace compila `--all-targets --all-features --locked`;
- CI reproduz esses gates;
- audit/deny sem bloqueadores;
- recovery/fault injection não converte corrupção em sucesso silencioso.

**Regra final:** documentação ou comentário não satisfaz gate de segurança. O gate precisa ser demonstrado por tipo, validação, teste ou comportamento observável.
