SPEC-gemini-3.8.md

## Especificação de Execução: Auditoria Recursiva Profunda em 10 Iterações (HeraclitusDB)

**Autor:** Gemini Engine Protocol
**Propósito:** Fornecer um protocolo estrito, determinístico e técnico para execução automatizada em LLM local (via Ollama, vLLM, LM Studio ou agentes autônomos), garantindo análise exaustiva e eliminando respostas superficiais ou generalistas.

---

## 1. Diretrizes Globais de Comportamento para o Modelo Local

1. **Anti-Alucinação e Rastreabilidade de Código:**

   - Proibido inventar métodos, structs, campos ou erros que não estejam presentes nos arquivos do repositório.
   - Todo defeito apontado DEVE indicar: `caminho_do_arquivo`, `identificador_da_funcao_ou_struct`, o mecanismo da falha (ex.: condição de corrida, pânico não tratado, desalocação prematura, violação de invariant) e uma sugestão concreta de patch em Rust.
2. **Invariante de Contexto Recursivo:**

   - Cada iteração deve produzir um log de achados estruturado.
   - A iteração $N$ ($N \ge 2$) deve ler o log gerado na iteração $N-1$, verificando se os subsistemas auditados anteriormente violam garantias exigidas pelo módulo atual.
3. **Critérios de Severidade:**

   - **P0 (Crítico):** Corrupção silenciosa de dados, quebra de atomicidade em disco, pânico em runtime, data race ou vulnerabilidade explorável sem autenticação.
   - **P1 (Alto):** Vazamento de recursos (file descriptors, memória heap), contenção severa de locks (latência > 1s), inconsistência transitória de réplicas ou quebra de invariantes formais Lean.
   - **P2 (Médio):** Falha de edge case em parsing, overhead excessivo de serialização, ausência de timeouts em canais e débitos técnicos impeditivos para uso corporativo.

---

## 2. Detalhamento das 10 Iterações de Auditoria

### Iteração 1: Engine de Armazenamento Central e I/O de Baixo Nível

* **Escopo de Arquivos:**
  `crates/heraclitus-log/src/v6/engine.rs`, `packer.rs`, `block.rs`, `block_directory.rs`, `manifest.rs`, `store.rs`, `mmap.rs`, `verify.rs`, `doctor.rs` e `crates/heraclitus-platform/src/odirect.rs`.
* **Roteiro de Análise:**
  1. **Atomicidade e Sequência de Flush:** Mapear o ciclo exato em que blocos selados (`.hrkb`) são gerados e o momento exato em que o manifesto (`manifest.rs`) recebe escrita. Verificar se há janelas onde metadados são comitados antes da persistência física via `fsync`/`fdatasync`.
  2. **Crash Recovery sob Corte de Energia:** Avaliar se `doctor.rs` consegue reconstruir o estado sem pânico caso um bloco seja interrompido na metade de sua escrita ou se ocorre corrupção irrecuperável.
  3. **Contenção no Roll de Segmentos:** Analisar o uso de `parking_lot::RwLock` ou mutexes globais em `engine.rs` durante a rotação de arquivos de escrita em cargas massivas (10M+ registros).
  4. **Skip Scan e Detecção de Bitrot:** Inspecionar `verify.rs` para identificar se divergências de CRC/Merkle interrompem o loop ou alocam buffers indefinidamente.

### Iteração 2: Estruturas em Memória, Concorrência e Coleta de Lixo

* **Escopo de Arquivos:**
  `crates/heraclitus-memtable/src/*`, `crates/heraclitus-btree/src/*`, `crates/heraclitus-core/src/ebr.rs`, `hlc.rs`, `consistency.rs` e `contracts.rs`.
* **Roteiro de Análise:**
  1. **Epoch-Based Reclamation (EBR):** Verificar se threads de leitura com alta latência podem reter épocas antigas indefinidamente, provocando vazamento de memória silencioso (picos de RSS).
  2. **Concorrência Lock-Free / Fine-Grained:** Auditar as árvores B-Tree e Memtables em busca de data races, ABA problems em ponteiros atômicos ou contenção desnecessária em inserções paralelas.
  3. **Hybrid Logical Clock (HLC):** Checar o avanço do relógio lógico e se skew temporal do sistema operacional pode violar a monotonicidade das leituras transacionais.

### Iteração 3: Verificação Cruzada Modelo Formal (Lean) vs. Código Rust

* **Escopo de Arquivos:**
  `lean/ProofAppendOnly/*`, `lean/ProofDenseMap/*`, `lean/ProofHLC/*`, `lean/ProofMerkleTree/*` e confronto direto com os arquivos Rust equivalentes em `crates/heraclitus-core/` e `crates/heraclitus-log/`.
* **Roteiro de Análise:**
  1. **Equivalência Semântica:** Comparar os teoremas provados em Lean (ex.: invariante de que um log append-only nunca muta índices passados) com os métodos de truncamento, reciclagem e compactação do Rust.
  2. **Mapeamento de Lacunas (Proof-to-Code Gap):** Identificar premissas que a prova formal assume como verdadeiras (como I/O ideal sem falha de hardware ou ordem sequencial estrita de CPU) que a implementação Rust viola na prática com operações assíncronas no Tokio.

### Iteração 4: Motor Analítico, Vetorização e Compilação Hume

* **Escopo de Arquivos:**
  `crates/hume-ir/src/*`, `crates/hume-kernel/src/*`, `crates/hume-sketches/src/*`, `crates/heraclitus-analytics/src/*` e `crates/heraclitus-gpu/src/*`.
* **Roteiro de Análise:**
  1. **Compilação JIT e Segurança:** Analisar a emissão de código de máquina e bytecode do Hume IR. Checar se existem vulnerabilidades de estouro de buffer ou leitura fora de limites nos kernels nativos.
  2. **Vetorização SIMD e Fallbacks:** Auditar kernels SIMD (AVX2, AVX-512, NEON) em `hume-kernel/src/vector.rs` e validar se há fallbacks escalares seguros caso a instrução de hardware não esteja disponível em tempo de execução.
  3. **Gerenciamento de Arenas de Memória:** Checar se o `chunk.rs` e `arena.rs` liberam memória corretamente após a conclusão de queries agregadas de alto volume.

### Iteração 5: Índices Especializados (Grafos e Vetores)

* **Escopo de Arquivos:**
  `crates/heraclitus-index-vector/src/*`, `crates/heraclitus-index-graph/src/*`, `crates/heraclitus-index-text/src/*`, `crates/heraclitus-index-attr/src/*` e `crates/heraclitus-manifold/src/*`.
* **Roteiro de Análise:**
  1. **Algoritmo HNSW Concorrente:** Checar se a construção do grafo de proximidade vetorial tolera mutações concorrentes sem deixar arestas unidirecionais órfãs, e se a perda de precisão de busca (recall drop) ocorre sob inserções contínuas.
  2. **Deadlocks em Grafos Temporais:** Auditar a travessia de arestas direcionadas temporais em `temporal.rs` para detectar ordens inconsistentes de aquisição de travas em vértices adjacentes.
  3. **Consistência de Índices Secundários:** Mapear a sincronização entre a escrita no log primário e a atualização dos índices invertidos de texto e atributos.

### Iteração 6: Consenso Distribuído, Replicação e Tolerância a Partição

* **Escopo de Arquivos:**
  `crates/heraclitus-raft/src/*`, `crates/heraclitus-proto/src/*`, `sim/heraclitus-sim/src/*` e confronto com `lean/ProofDeterministicReplay.lean`.
* **Roteiro de Análise:**
  1. **Reconfiguração Dinâmica de Membros:** Auditar a transição de Joint Consensus no Raft em caso de partição de rede. Checar se há risco de eleição de dois líderes em termos sobrepostos (*split-brain*).
  2. **Snapshot Transfer vs. WAL Truncation:** Verificar se a transferência de snapshot para nós defasados sincroniza perfeitamente com a remoção de segmentos compactados em disco.
  3. **Replay Determinístico:** Validar se a ordem de aplicação de comandos da máquina de estados do Raft garante invariância exata de hash em nós réplica.

### Iteração 7: Conformidade Jurídica, Criptografia e Carimbo de Tempo

* **Escopo de Arquivos:**
  `crates/heraclitus-compliance/src/*`, `crates/heraclitus-crypto/src/*` e `crates/heraclitus-telemetry-health/src/*`.
* **Roteiro de Análise:**
  1. **Protocolo RFC 3161 / ICP-Brasil:** Analisar os módulos `rfc3161.rs`, `tsa.rs` e `secure_tsa.rs`. Verificar validação de cadeias X.509, checagem de revogação via CRL e manipulação segura de ASN.1 DER.
  2. **Garantia de Imutabilidade e Varrimento:** Auditar `varrimento.rs` e `receipt.rs` para confirmar se qualquer mutação em registros antigos é detectada via árvores Merkle sem falso-positivo.
  3. **Soberania e Sanitização de Dados:** Checar a aplicação de máscaras dinâmicas de dados sensíveis (LGPD/GDPR) em `privacy.rs` e isolamento de tenants.

### Iteração 8: Governança de Agentes IA e Gateway de Interceptação

* **Escopo de Arquivos:**
  `crates/heraclitus-agent/src/*`, `crates/heraclitus-agent-gateway/src/*`, `crates/heraclitus-core/src/sandbox.rs` e diretório `mcp/*`.
* **Roteiro de Análise:**
  1. **Ciclo de Vida de Sessões MCP:** Mapear o encerramento de conexões em `gateway.rs`. Checar se sessões órfãs retêm sockets TCP, file descriptors ou instâncias de subprocessos pendentes no runtime Tokio.
  2. **Controle de Políticas e Sandbox:** Inspecionar o parser e enforcement de regras em `policy/mod.rs` e `sandbox.rs`. Garantir que não há bypass na validação de ações perigosas de agentes.
  3. **Evidenciamento e Não-Repúdio:** Checar se a gravação de chamadas de ferramentas (*tool calling*) no ledger imutável é síncrona com a autorização da ação do agente.

### Iteração 9: SIEM/EDR Sentinel e Integração Lakehouse

* **Escopo de Arquivos:**
  `crates/heraclitus-sentinel/src/*`, `crates/heraclitus-tier/src/*` e subdiretórios `lakehouse/` (parquet, iceberg, delta).
* **Roteiro de Análise:**
  1. **Motor de Regras Sigma e STIX:** Auditar o compilador e executor de regras Sigma em `sigma.rs` e parsing de inteligência de ameaças STIX em `threat/stix.rs`. Identificar vulnerabilidades de negação de serviço (ReDoS ou exaustão de pilha em árvores de decisão).
  2. **Exportação Concorrente para Lakehouse:** Analisar `parquet_export.rs`, `iceberg.rs` e `delta.rs`. Garantir que a demotivação de dados frios para formatos colunares não cause race conditions com compactadores do storage interno.

### Iteração 10: Síntese Crítica, Homologação e Commercial Readiness

* **Escopo de Arquivos:**
  `docs/md/BUGS.md`, `docs/md/falta.md`, `docs/md/comercial/certificacoes.md`, scripts de deploy (`deploy/`) e todos os relatórios das iterações 1 a 9.
* **Roteiro de Análise e Emissão:**
  1. **Consolidação Geral dos Defeitos:** Agrupar todos os bugs P0, P1 e P2 encontrados no código real, com tabela unificada de severidade, arquivo e impacto operacional.
  2. **Diagnóstico de Viabilidade Comercial:** Mapear os requisitos estritos que faltam para o produto ser comercializável em contas Enterprise e órgãos públicos (Governo/Judiciário):
     - Modularização em SKUs claros (Audit Core vs. Sentinel vs. Lakehouse).
     - Mecanismos corporativos de autenticação (SSO, OIDC, SAML, RBAC/ABAC granular).
     - SDKs homologados além de Python (Go, TypeScript, Java/.NET).
     - Automação de Day-2 Operations (Kubernetes Operator, CRDs, backups com RPO=0 e painéis Grafana/Prometheus).
     - Certificações compulsórias (SOC 2 Tipo II, ISO 27001, PenTest independente).
  3. **Geração do Artefato Final:** Escrever e persistir o arquivo `RELATORIO-gemini-5.8.md`.

---

## 3. Template de Prompt de Execução para cada Iteração

Ao rodar localmente com seu modelo de linguagem, utilize a seguinte estrutura de prompt substituindo as variáveis:

```text
Você é o auditor líder do projeto HeraclitusDB executando a [NÚMERO DA ITERAÇÃO] conforme definido no SPEC-gemini.md.

Escopo desta iteração:
- Crates/Diretórios: [LISTAR DIRETÓRIOS CONFORME O SPEC]
- Arquivos-chave a analisar: [LISTAR ARQUIVOS DA ITERAÇÃO]

Diretrizes obrigatórias:
1. Audite o código-fonte linha por linha e identifique falhas reais de concorrência, quebra de atomicidade, alocação de memória ou discrepâncias com provas formais.
2. Não faça resumos genéricos. Aponte: Arquivo, Função/Trecho, Problema Técnico Real, Nível de Severidade (P0/P1/P2) e a Solução Recomendada em Rust.
3. Considere os achados da iteração anterior para checar quebras de premissas entre subsistemas.

Execute a análise profunda agora.
```
