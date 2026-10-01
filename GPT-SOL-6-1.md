# Auditoria Rust × Markdown — HeraclitusDB

**Data:** 01/10/2026, America/Sao_Paulo.
**Projeto:** `D:\DEV\HeraclitusDB`.
**Commit inspecionado:** `a17f35626fa831106ec664ef846c8a39c855f51a`.
**Versão declarada:** 3.0.1. **Auditor:** GPT-6.1 SOL.

## 1. Conclusão

Há problemas reais. O principal bloqueio é a administração privilegiada: crypto-shred e Legal Hold ainda não usam o protocolo durável exigido pela SPEC-0089. O módulo novo existe, mas não garante, por si só, intenção durável antes do efeito nem recuperação/idempotência após reinício.

As implementações novas de criptografia e perícia também têm defeitos reproduzíveis: rotação perde acesso a chaves históricas; uma referência antiga pode destruir a chave atual; o envelope aceita alteração de metadados sem invalidar a decifragem; o verificador forense aceita assinatura, timestamp e prova inválidos. Os controles atuais de TLS/RBAC e vários reparos de auditorias anteriores estão presentes: não devem ser confundidos com essas lacunas novas.

**Recomendação:** não promover as implementações das SPECs 0086–0089 a garantias de produção antes de corrigir os itens de prioridade P0/P1 abaixo. Isso não significa que todo o banco esteja inutilizável: parte dos problemas está em APIs novas de biblioteca ainda sem consumidor no servidor.

## 2. Método, alcance e limites

- Inventário: **393 arquivos Rust próprios**, excluindo `target` e `node_modules`; destes, **346 em `crates/`, somando 168.832 linhas não vazias** segundo `Get-Content | Measure-Object -Line`. Inventário Markdown: **157 arquivos próprios**, excluindo caches do graphify e dependências; **137 em `docs/`**.
- Revisão orientada a risco, com leitura de trechos e rastreamento de chamadas em servidor, autenticação, configuração, crypto, administração confiável, forensic, analytics, log, query, checkpoints, Raft e H-VM. **Inventariar não equivale a revisar integralmente os 393 arquivos. Esta auditoria não certifica ausência de defeitos no restante.**
- Cruzamento principal: `README.md`, `SECURITY.md`, `docs/md/SPEC-new/STATUS.md`, `ROADMAP-GOV-BR.md`, SPECs 0086/0087/0089/0090, `docs/CORRECOES-AUDITORIA-2026-09-08.md` e relatórios de desempenho em `docs/md/auditorias/`.
- Skill graphify aplicada ao grafo existente; vocabulário selecionado: `auth tenant append verify query budget sandbox checkpoint raft privacy audit decrypt`. O Python registrado em `.graphify_python` retornou acesso negado; consulta de nós/arestas feita diretamente em PowerShell. O grafo serviu para navegação; as conclusões foram conferidas no código atual, não presumidas a partir do cache.
- Reprodução em projeto separado, dentro de `work/audit-probe`, referenciando os crates locais e o arquivo original `trusted_admin.rs`. Nenhuma correção foi aplicada ao código do banco. A segunda execução foi iniciada com uma cópia do `Cargo.lock` original para conservar as versões das dependências utilizadas.
- Não foram consultados dados de clientes, executadas operações nos serviços instalados, feitas alterações em configuração de produção, commit, push ou deploy.
- Severidade: **P0** = bloqueio de garantia essencial; **P1** = falha de segurança/correção/recursos relevante; **P2** = melhoria ou defeito de impacto mais restrito. Não são pontuações CVSS.

## 3. Achados priorizados

| ID | Prioridade | Achado | Situação / alcance |
|---|---|---|---|
| A01 | P0 | Administração destrutiva fora do protocolo durável | Confirmado por fluxo do servidor; lacuna já prevista no roadmap |
| A02 | P1 | Validação e identidade da intenção administrativa incompletas | Reprodução na API nova; sem integração destrutiva atual |
| A03 | P1 | Rotação perde histórico; destroy ignora época/chave | Duas reproduções; SoftwareKeyProvider de desenvolvimento |
| A04 | P1 | Metadados do envelope V2 não autenticados | Reprodução; biblioteca nova sem consumidor no servidor encontrado |
| A05 | P1 | Verificador forense aceita provas de confiança inválidas | Reprodução; crate forense ainda sem integração export/verify encontrada no CLI/servidor |
| A06 | P1 | Cadeia de custódia aceita segundo início e omite terminal do hash | Reprodução; crate forense |
| A07 | P1 | SQL limita resultado somente depois de coletar tudo | Confirmado por fluxo; feature `analytics`, desativada por padrão |
| A08 | P1 | Flight carrega todo o log antes de transmitir | Confirmado por fluxo; `analytics` + `flight_addr` opt-in, loopback obrigatório no boot |

### A01 — Crypto-shred e Legal Hold ainda não exigem AdminIntent durável

**Evidência:** `crates/heraclitus-server/src/grpc.rs:291`, `:325`, `:467`, `:481`; `engine.rs:756`, `:780`, `:2041`; `rest.rs:1263`, `:1289`; `trusted_admin.rs:303` e `:424`.

O RPC Admin verifica RBAC, executa a operação e só depois chama `audit_admin`. Essa auditoria apenas avisa se o append falhar. A exclusão REST chama `engine.shred` diretamente. `shred` grava um marcador de reconstrução e, depois do efeito, um recibo de privacidade; esse marcador protege reconstrução, mas não registra principal, autorização, parâmetros e intenção administrativa exigidos pela SPEC. Os eventos próprios de Legal Hold também não substituem o protocolo de execução privilegiada.

Não há implementação de `execute_admin` no módulo inspecionado, nem chamada produtiva de `validate`, `create_execution_token` ou `record_completion` encontrada. `Engine` apenas mantém uma instância nova do gerenciador. `audit_admin_strict` também não está ligado aos entrypoints; quando `audit_admin=false`, retorna `Ok(0)` e, mesmo ligado, faz `append`, sem barreira explícita adicional para GroupCommit.

**Impacto:** uma operação irreversível pode ocorrer sem a evidência administrativa durável completa. Depois de falha, o sistema não oferece o ciclo de reconciliação especificado para essa operação. O modo produção exige `fsync=Always` e auditoria ligada, mas isso não corrige a ordem efeito → auditoria.

**Contrato MD:** SPEC-0089 §§1–7 exige intenção antes do efeito, token interno, resultado durável ou UNKNOWN recuperável. `ROADMAP-GOV-BR.md:25` classifica essa SPEC como P0 BLOCKER e sua Fase A ainda manda migrar shred e Legal Hold. Portanto, é uma lacuna reconhecida, não evidência de que a documentação declara a feature concluída.

**Correção:** implementar um único executor que valide, grave intenção com barreira de durabilidade/quórum, reserve idempotência, emita token vinculado à operação, execute e persista resultado; reconstruir o estado no boot. Tornar as primitivas destrutivas inacessíveis sem esse token. Testar falha em cada transição e reinício com intenção sem resultado.

### A02 — Digest, autorização e estado do protocolo novo são insuficientes

**Evidência:** `trusted_admin.rs:161`, `:311`, `:341`, `:378`, `:414`, `:424`.

`compute_intent_digest` omite `parameters_digest` e a política de aprovação. Alterar esses campos preserva o digest. Além disso, concatena strings sem delimitação de comprimento: pares como operation/idempotency `ab`/`c` e `a`/`bc` produzem o mesmo prefixo com o restante igual; isso é ambiguidade de serialização, não colisão do BLAKE3.

`validate` não verifica os papéis do solicitante e aceita uma destruição com contexto Reader se não houver `approval_policy`. Aprovações são avaliadas por strings fornecidas pelo chamador; a função não verifica assinatura ou resolve identidade/papéis em fonte autenticada. `create_execution_token` é público e aceita um LSN arbitrário sem consultar o log. O mapa ativo é preenchido por `operation_id`, enquanto consulta/remoção usam `idempotency_key`. Os mapas ficam só em RAM, e validar não reserva atomicamente uma operação em execução.

**Reprodução:** `admin_digest_omits_parameters_and_accepts_unprivileged_context` confirma digest inalterado, validação Reader aceita, token com LSN 999 e consulta pela chave idempotente sem estado correspondente.

**Impacto:** integrar esse módulo como está criaria uma aparência de controle sem os invariantes necessários. **Não foi demonstrado bypass remoto do RBAC atual por esse módulo:** os entrypoints ainda não o utilizam.

**Correção:** hash de estrutura canônica completa, com separação de domínio; política escolhida pelo servidor; identidade de aprovadores autenticada; reserva atômica e durável; token criado somente dentro do executor após confirmação de persistência; chave consistente para armazenamento e consulta.

### A03 — SoftwareKeyProvider destrói histórico na rotação e ignora KeyRef

**Evidência:** `crates/heraclitus-crypto/src/provider.rs:287`, `:389`, `:414`, `:437`.

O mapa armazena uma única chave mestre por tenant. `rotate` substitui essa chave; `unwrap_data_key` escolhe somente pelo tenant, sem resolver a época. `destroy` remove a chave do tenant sem verificar `key_id` ou `epoch` da referência recebida.

**Reproduções:** `rotation_loses_historical_key`: wrap → unwrap funciona → rotate → unwrap antigo falha. `destroying_stale_key_destroys_current_epoch`: wrap antigo → rotate → wrap novo → destroy da referência antiga → unwrap novo falha.

**Contrato MD:** SPEC-0086 §7 estabelece que a época histórica permanece decifrável depois da rotação. A API atual também difere da proposta: roda por tenant, enquanto a SPEC propõe referência de chave.

**Impacto:** perda de acesso histórico e destruição da época errada. O próprio código classifica esse provider como software para testes/dev; não foi encontrado seu uso no KeyStore produtivo. Essa distinção reduz a exposição atual, mas não elimina o defeito.

**Correção:** armazenar chaves por `(tenant, key_id, epoch)`; manter épocas antigas até destruição autorizada; validar a referência completa em unwrap/destroy; sincronizar criação/rotação/wrap para evitar chave mestre e epoch de momentos diferentes. Acrescentar testes de rotação histórica e referência stale antes de integrar ao servidor.

### A04 — Envelope V2 permite alterar tenant, chave, época e algoritmo

**Evidência:** `provider.rs:188`, `:195`, `:202`, `:251`.

A cifra autentica somente o `aad` passado pelo chamador. Tenant, key_id, epoch e algorithm são serializados depois da cifra e não entram automaticamente nesse AAD. `open` lê o header, confere apenas `aad_digest` e usa ChaCha20-Poly1305 independentemente do texto em `algorithm`.

**Reprodução:** `envelope_accepts_modified_tenant_key_epoch_and_algorithm` altera esses quatro campos mantendo comprimento, nonce, ciphertext e AAD. O header refletiu a adulteração e o plaintext continuou sendo aceito.

**Impacto:** metadados declarados pelo envelope não têm a integridade sugerida por uma estrutura criptográfica. Não se demonstrou decifragem entre tenants com chaves diferentes; a prova mostra alteração aceita quando a chave e o AAD fornecidos permanecem iguais. Um consumidor que construa AAD completo externamente pode impor proteção adicional, mas a API não obriga isso.

**Correção:** incluir o header canônico e uma identificação de versão/domínio no AAD; validar algoritmo e referência esperados; rejeitar metadados divergentes. Preservar compatibilidade com formato explícito, sem reinterpretar envelopes antigos silenciosamente.

### A05 — Verificação forense não valida assinatura, timestamp nem prova HRKL

**Evidência:** `crates/heraclitus-forensic/src/verifier.rs:56–174`, `package.rs:87–104`, `manifest.rs:18–20`.

O verificador compara hashes de objetos e alguns campos de custódia. Não lê `proofs/merkle.json`, não verifica `signatures` nem `trusted_timestamps`, não valida `schema_version`, `root_sha256`, `leaves_count` ou tamanho declarado de objeto. `manifest.sha256` é opcional. A suposta raiz Merkle é BLAKE3 da concatenação dos hashes textuais de objetos: um compromisso do conjunto, sem caminho de inclusão que o vincule ao HRKL de origem.

**Reprodução:** `forensic_accepts_invalid_signature_timestamp_and_proofs` constrói pacote com assinatura/token inválidos, raiz SHA-256 inválida e contagem 999; substitui a prova por bytes que nem são JSON; `verify()` retorna sucesso. Remover `manifest.sha256` também não impede sucesso.

**Contrato MD:** SPEC-0087 §§5/11 e gates exigem prova de inclusão, timestamp verificado e rejeição de mutações de provas; o README corretamente mantém essa capacidade como roadmap.

**Impacto:** sucesso dessa API não significa origem autenticada, assinatura válida ou hora confiável. Recalcular um checksum dentro do próprio pacote não autentica o emissor. A ausência de checksum pode ser compatível com algum perfil futuro, mas hoje não há perfil/relatório distinguindo essas verificações.

**Correção:** resultado estruturado por verificação, com estados verificado/não fornecido/não suportado/inválido; perfis estritos que recusam provas obrigatórias ausentes; validação offline de confiança/assinatura/timestamp; provas reais HRKL e compromisso externo confiável. Mutacionar independentemente cada componente nos testes.

### A06 — Custódia aceita reset da cadeia; terminal não entra no hash

**Evidência:** `manifest.rs:104–117`, `verifier.rs:135–154`.

`compute_hash` omite `terminal_or_node`. O verificador compara o elo anterior somente quando `step_index > 0`, mas não exige que índices avancem sequencialmente nem que apenas a primeira entrada tenha índice zero. Uma segunda entrada zero com predecessor arbitrário passa.

**Reprodução:** `custody_hash_omits_terminal_and_chain_accepts_second_genesis` demonstra ambas as propriedades em pacote aceito.

**Limite:** o SHA-256 de todo o arquivo de custódia detecta alteração isolada do terminal se o digest original do manifesto for confiável. O problema é o encadeamento interno e a falta de autenticação externa do manifesto em A05; não se afirma quebra de SHA-256.

**Correção:** hash canônico de todos os campos de custódia relevantes; sequência estrita; uma única gênese com predecessor vazio; ausência de duplicatas; regras de ordem temporal apropriadas. Testar reset, salto, repetição, troca de nó e truncamento.

### A07 — Limites SQL não limitam o pico total de execução

**Evidência:** `crates/heraclitus-analytics/src/lib.rs:120`, `:143`, `:221`, `:246`; `crates/heraclitus-server/src/rest.rs:1374`, `:1382`, `:1411`, `:1426`.

Há orçamento de entrada de 2 milhões de linhas / aproximadamente 256 MiB no REST. Porém a biblioteca usa `SessionContext::new`, faz `collect()` de todos os batches e serializa tudo para JSON antes de o handler rejeitar resultados acima de 10.000 linhas. Uma consulta que expanda resultados, por exemplo um produto cartesiano, não é limitada pelo tamanho da entrada. Não foi encontrada admissão global de consultas analíticas concorrentes nem pool de memória configurado nesse caminho.

A materialização também verifica orçamento apenas depois de uma janela de 50.000 episódios: o limite em bytes é aproximado e pode ser ultrapassado durante a leitura/clonagem da janela. O timeout de 30 segundos envolve a execução SQL, depois da construção da tabela; não cobre essa construção.

**Impacto:** pico de memória/CPU desproporcional, inclusive por usuário autenticado, e concorrência multiplicando os custos. **Não foi executada consulta destinada a esgotar RAM**, nem benchmark que quantifique o pico neste ambiente.

**Correção:** streaming de batches com limite de linhas e bytes antes de coleção/JSON; pool de memória limitado, spill e cancelamento cooperativo; semáforo global e, quando implementados tenants, orçamento por tenant; checar bytes incrementalmente e limitar tamanho de janela por bytes. `LIMIT` de saída sozinho não limita memória de sort/join/aggregate intermediário.

### A08 — Flight transmite em batches, mas materializa o log inteiro primeiro

**Evidência:** `crates/heraclitus-server/src/flight_grpc.rs:66–89`, `:151–169`; `crates/heraclitus-server/src/lib.rs:949–965`.

`DoGet` chama `log.scan(0,to)`, produz todos os RecordBatches e só depois cria o stream. Batches de 1024 linhas controlam o fio, não a RAM da leitura. Não há orçamento nesse caminho. Também não há autenticação Flight; o boot corretamente recusa endereço não-loopback.

**Impacto:** log grande pode consumir a memória do processo antes de enviar o primeiro lote. Um processo local pode ler os dados e provocar esse trabalho se Flight estiver habilitado. **Não há evidência de exposição remota pelo boot normal**, devido à guarda de loopback; redes/proxies externos não foram examinados. A função pública `serve_flight` não aplica essa guarda sozinha: um integrador precisa respeitá-la.

**Contrato MD:** SPEC-0090 §9 pede memória, resultado, concorrência e autenticação compartilhados. Essa SPEC é uma proposta; o código atual ainda não entrega essas garantias.

**Correção:** produtor paginado com canal limitado, backpressure e cancelamento quando o cliente fecha; tamanho de página em bytes; budgets e RBAC antes de permitir consumo fora de loopback; guarda também na API de abertura do listener.

## 4. Hipóteses adicionais — não contar como exploração confirmada

1. **Shred concorrente com escrita/Legal Hold:** `engine.rs:2041–2209` faz verificação regulatória, destruição e reconstrução sem adquirir a barreira exclusiva `index_gate` usada nos checkpoints. Há intervalos entre capturar `head`, reconstruir índice e substituir `self.attr` em que appends/holds podem se intercalar. Requer teste determinístico com barreiras: conferir hold inserido após a checagem e append durante a reconstrução. Não afirmar perda de dados ou bypass sem reproduzir a interleaving completa.
2. **Symlink/junction em pacote:** `verifier.rs:29–44` valida componentes lexicais, depois `fs::read` segue links; `package.rs:51–65` escreve por caminhos também lexicais. Um diretório de pacote não confiável com links pode sair da raiz. Não foi montada exploração de filesystem nesta rodada. Fazer testes com symlink/reparse point; resolver arquivos sob handle da raiz e recusar links, com proteção contra troca entre validação e abertura.
3. **Verificador sem budgets de arquivos:** `fs::read` de manifesto/objeto/custódia não tem teto; objetos são carregados inteiros. Medir e impor limites de manifesto, contagem, tamanho e bytes acumulados; calcular hashes por streaming. Não foi feito teste de OOM.

## 5. Melhorias e eficiência

| Prioridade | Melhoria | Evidência e tradeoff | Como medir/validar |
|---|---|---|---|
| P1 | Eliminar materialização integral em Flight e limitar SQL durante execução | A07/A08; reduz RAM e tempo até primeiro resultado | RSS máximo, p95/p99, bytes, tempo até primeiro batch; cliente cancelando e consultas simultâneas |
| P2 | Publicação incremental do índice legado | `heraclitus-log/src/lib.rs:1372–1404` copia todo o vetor do segmento ativo por lote: custo O(n) por lote, O(n²/B) ao preencher segmento | Bench `append_scaling`; comparar append e point read, leitores concorrentes e vários tamanhos de segmento |
| P2 | Cache incremental de H-VM por watermark | `engine.rs:953` chama `vm_bridge::replay_vm`; este varre todo o log em páginas e seleciona frames H-VM | Comparar leitura quente/fria com 1M/20M eventos; preservar equivalência e invalidar/reconstruir após restart/shred |
| P2 | SQL sobre fonte colunar com projeção/predicado pushdown | `LogAnalytics::from_log_capped` recria colunas de todo o intervalo, mesmo para consulta seletiva | Bytes lidos, CPU, alocações, RSS; igualdade de resultado/AS OF entre caminhos |
| P2 | Top-k para ORDER BY com LIMIT quando semanticamente aplicável | `heraclitus-query/src/plan.rs:1357` ordena vetor materializado; relatório de 08/09 declara teto intermediário e ausência de top-k global | Mesmo resultado com empates/NULL/direção; comparar O(n log k), RSS e latência |
| P2 | Checkpoints fora de locks prolongados quando seguro | `engine.rs:833`, `:866` mantém locks dos índices/views durante serialização/persistência | p99 de append durante checkpoint; snapshot consistente, watermark correto e replay de cauda |

**Não repetir uma recomendação antiga já adotada:** o relatório `append-lento-com-o-crescimento.md` de 16/08 criticava 256 MiB. O relatório `otimizacao-20m.md` de 19/08 registra a adoção/validação de 8 MiB, e `HeraclitusConfig::default` hoje usa **8 MiB**. O COW continua existindo no backend legado; o default reduz seu alcance. Não transferir números de GroupCommit para garantias de `Always`, nem os ganhos históricos para hardware/carga atual sem medir.

Outras melhorias de manutenção:

- Documentar o estado real de 0086–0091 em `STATUS.md`, incluindo componentes existentes, integração produtiva, testes e bloqueios. O roadmap o chama de autoridade, mas a busca desta rodada não encontrou entradas para esses números no STATUS.
- Definir um tipo explícito de resultado de verificação forense; evitar que `Ok(manifest)` seja interpretado como verificação institucional completa.
- `AdminContext::new` deriva request_id somente dos segundos atuais; operações criadas no mesmo segundo repetem identificador. Usar ID único e correlação persistida.
- Descrever `provider_signature = "sig-software-..."` (`provider.rs:455`) como marcador de desenvolvimento: não é assinatura criptográfica verificável.
- Isolar claramente APIs de referência/dev e consumidores produtivos; evitar promover scaffolding apenas porque compila e seus testes felizes passam.

## 6. Controles encontrados e problemas antigos que não foram reabertos

- `config.rs:1341–1375`: REST exige loopback; gRPC fora de loopback exige autenticação/TLS; Raft fora de loopback exige gRPC mTLS. Produção exige fsync Always, cifra em repouso, auditoria e principals separados. Portanto não reportar TCP Raft desprotegido como configuração produtiva aceita.
- `auth.rs:95`: metadados Authorization duplicados são recusados; `grpc.rs` aplica papéis por operação; aprovações Sentinel vinculam identidade ao principal autenticado.
- `config.rs:1320`: digest de credencial exige ASCII hexadecimal; a possibilidade isolada de slicing Unicode em `auth::decode_digest` não demonstra entrada explorável pelo caminho normal de configuração validada.
- `analytics/src/lib.rs:233`: SQLOptions proíbe DDL, DML e statements. Não reabrir a antiga leitura arbitrária de arquivo via `CREATE EXTERNAL TABLE` como se esse bloqueio não existisse.
- `engine.rs:833/866`: barreira de indexação antes de checkpoints; marcas recusam persistir índices incompletos após boot com replay saltado.
- `engine.rs:2132`: Legal Hold/decisão regulatória/classificação/retention são consultados antes de shred; a corrida potencial da seção 4 não significa ausência do gate.
- `docs/CORRECOES-AUDITORIA-2026-09-08.md` delimita corretamente GroupCommit, ações externas, Sigma e snapshots históricos B-tree. Suas contagens de testes são históricas e não foram usadas como resultado desta auditoria.
- Não foram encontrados `todo!`/`unimplemented!` produtivos nos resultados da busca geral em Rust; os `unimplemented!` examinados em `query/plan.rs` são mocks de teste. Ocorrência textual de `unsafe` também não foi tratada como vulnerabilidade automática.

## 7. Validação realizada

Rust local: `rustc 1.96.0 (ac68faa20 2026-05-25)`; Cargo 1.96.0. Dependências resolvidas offline, sem atualizar o `Cargo.lock` do repositório.

**Reproduções independentes:** 8 testes aprovados: **6 diagnósticos que demonstram os defeitos atuais** + 2 testes já existentes do módulo `trusted_admin.rs` incluído. Aprovação dos diagnósticos significa que o comportamento defeituoso foi observado, não que ele está corrigido. Reexecução com versões preservadas do lock original: mesmos 8 aprovados.

Os nomes dos seis diagnósticos estão nas seções dos achados. Código e lock da reprodução, inventário de hashes e saída de formatação acompanham `auditoria-evidencias.zip`. Os paths dos crates no Cargo.toml são locais para `D:/DEV/HeraclitusDB`; adaptar apenas o caminho ao reproduzir em outra máquina.

```powershell
# Na raiz D:\DEV\HeraclitusDB
cargo test --offline --locked --jobs 2 -p heraclitus-crypto -p heraclitus-forensic -p heraclitus-server --lib -- --test-threads=2
cargo test --offline --locked --jobs 2 -p heraclitus-core -p heraclitus-log -p heraclitus-query -p heraclitus-btree --lib -- --test-threads=2
cargo fmt --all -- --check
git diff --check

# Reprodução independente; executar na pasta extraída audit-probe
cargo test --offline --locked --target-dir D:/DEV/HeraclitusDB/target --jobs 2 -- --test-threads=2
```

**Suítes do repositório:** ambas as execuções terminaram com código 0, **481 testes unitários aprovados**, sem falhas: crypto 10; forensic 6; server 96; core 60; log 228; query 64; btree 17. Servidor com features padrão (`agent`), sem `replication`, `analytics`, GPU ou tier. O target configurado para essas execuções foi `D:/cargo-target`; as reproduções usaram explicitamente `D:/DEV/HeraclitusDB/target`. A listagem posterior de testes foi utilizada para registrar as contagens dos pacotes cujo output longo foi truncado; não foi tratada como nova execução de testes.

**Formatação:** `cargo fmt --all -- --check` retornou **1**, com diferenças existentes, incluindo `crates/heraclitus-cli/src/top.rs`. O gate não está limpo nesta revisão. Nenhuma formatação automática foi aplicada. `git diff --check` não encontrou diferenças inválidas nos arquivos rastreados no momento da execução.

**Não executado:** suíte inteira do workspace e todas as features; analytics/Flight em runtime; benchmark de RSS/CPU; GPU; Linux/io_uring; cluster distribuído com troca real de líder; falha física de disco/energia; auditoria atualizada de dependências/RustSec; pentest externo; validação com certificados/carimbos institucionais reais. Nenhuma conclusão deste relatório depende de inventar resultados desses checks.

## 8. Ordem prática de correção

1. Fechar A01/A02 e testar intenção, resultado, reconciliação e idempotência com falha/injeção de crash antes de ampliar operações privilegiadas.
2. Corrigir preservação por epoch, destroy exato e AAD do envelope antes de integrar o provider novo.
3. Corrigir o significado de sucesso do verificador, provas reais e custódia antes de oferecer o pacote como evidência independente de confiança.
4. Limitar memória e concorrência em SQL/Flight; fazer benchmarks de pico com cancelamento e múltiplos clientes.
5. Atualizar STATUS/matriz SPEC → código → gate; corrigir formatação; avaliar otimizações com baseline, resultados equivalentes e mesma política de durabilidade.

**Entrega:** relatório de auditoria e evidências. O código do HeraclitusDB não foi corrigido nesta tarefa.
