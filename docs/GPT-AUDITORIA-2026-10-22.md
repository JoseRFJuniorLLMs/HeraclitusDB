# GPT-AUDITORIA — Especificação de correções e qualificação

**Data:** 2026-10-22 (America/Sao_Paulo)
**Projeto:** HeraclitusDB
**Branch/commit inspecionado:** `main` / `a4b638f4410efba1ff38b45c64e6516f459364b3` (`v3.0.3`)
**Autor da revisão:** GPT
**Estado:** especificação proposta; **nenhuma correção de produto implementada neste documento**
**Escopo:** segurança, privacidade, integridade da trilha de auditoria, isolamento de dados, semântica de streams, robustez e eficiência de consultas.

> **Importante:** os resultados abaixo provêm de **três passadas de revisão estática** (código, fluxo de chamadas e contraprova por contratos/testes). Não representam execução dos testes nem reprodução de falhas em produção. No ambiente desta revisão, `cargo`/`rustc` não estavam disponíveis. A versão referida é um snapshot; revalidar os números de linha e o comportamento se o HEAD mudar.

## 1. Objetivo e critérios de classificação

Esta especificação transforma a reauditoria em requisitos verificáveis, sem converter hipóteses em bugs confirmados.

Prioridades usadas:

- **P1:** proteção de dados, autorização ou exigência de auditoria crítica, especialmente em implantação com dados sensíveis;
- **P2:** correção contratual, robustez, disponibilidade ou escalabilidade com pré-condições;
- **P3:** clareza de API, comportamento-limite ou otimização dependente de medição.

Estados de evidência:

- **CONFIRMADO (estático):** o comportamento está no código atual; impacto em execução ainda precisa de teste;
- **CONDICIONAL:** ocorre somente sob um modelo de uso/configuração declarado;
- **HIPÓTESE:** mecanismo plausível sem cenário de falha reproduzido;
- **NÃO BUG:** comportamento deliberado no contrato atual ou limitação conhecida.

### Passadas recursivas

1. **Fonte:** localizar implementação, validações, erros e cotas.
2. **Chamadores e limites de confiança:** percorrer REST/gRPC/Flight, principal autenticado, armazenamento e consumidores.
3. **Contraprova:** procurar testes e decisões documentadas que refutem ou reduzam a conclusão inicial; corrigir a classificação.

## 2. Matriz consolidada de achados

| ID | Assunto | Classificação revisada | Prioridade | Ação |
|---|---|---|---|---|
| AUD-01 | Texto bruto/decodificado de consultas em eventos de auditoria | CONFIRMADO; risco de dados sensíveis | P1 | Política de minimização e mascaramento |
| AUD-02 | `audit_query` ignora falha de append; `audit_admin` só adverte | CONFIRMADO; mecanismo best-effort | P1 para operações reguladas | Política explícita de durabilidade |
| AUTH-01 | `Subscribe` lê episódios de todo o log com papel `Reader` | CONDICIONAL ao uso multiusuário/tenant | P1 para aplicações por paciente | Isolamento ou gateway autorizado |
| IDEM-01 | Chave do append comum tem espaço de nomes global | CONFIRMADO; contrato a definir | P2 | Escopo de chave e migração |
| STR-01 | `ok=true` no Flight/Subscribe indica admissão, não conclusão | CONFIRMADO; semântica ambígua | P2 | Eventos distintos por fase |
| IPC-01 | `IpcFlightService::do_put` só importa `agent_id`/`kind` | NÃO BUG no contrato implementado | P3 | Documentar importação mínima |
| RAFT-01 | Falha persistente do `accept` gRPC sem backoff visível | HIPÓTESE de spin | P2 | Teste de injeção e backoff se confirmado |
| HLC-01 | Saturação de contador no máximo de `u64` | NÃO BUG prático; limite conhecido | P3 | Documentar propriedade de monotonia |
| SQL-01 | Materialização integral de colunas antes da execução SQL | CONFIRMADO; cotas impedem crescimento sem limite | P2 | Pushdown/streaming e benchmark |
| FLT-01 | Exportação de metadados hidrata episódios completos | CONFIRMADO; oportunidade de eficiência | P2 | Leitura projetada sem conteúdo |
| RES-01 | Semáforos estáticos compartilhados no processo | CONFIRMADO; possível contenção intencional | P3 | Medir e decidir escopo |
| TEST-01 | Cobertura adversarial para esses contratos | LACUNAS ESPECÍFICAS; CI/testes já existem | P2 | Ampliar regressões |

## 3. Requisitos funcionais e de segurança

### AUD-01 — Minimização e proteção dos registros de consulta

**Evidência:**

- `crates/heraclitus-server/src/rest.rs`, `texto_de_auditoria`: registra método, caminho e parâmetros de URI decodificados, até 500 caracteres;
- `crates/heraclitus-server/src/grpc.rs`: registra texto GQL e de consulta/recall em chamadas auditadas;
- `crates/heraclitus-server/src/engine.rs`, `audit_query`: persiste o texto num episódio `AuditQuery`.

**Observação de contraprova:** a decodificação do identificador é intencional: permite localizar acesso ao titular em relatórios LGPD. Não substituir indiscriminadamente por uma URL completamente anônima, pois isso poderia quebrar a rastreabilidade de acesso já esperada.

**Requisitos:**

1. Definir campos estruturados de evento: `principal`, operação, rota, instante, resultado e identificador do titular quando autorizado e necessário.
2. Não persistir credenciais, tokens, chaves, senhas e segredos recebidos por query string, path, cabeçalho ou parâmetros GQL.
3. Separar identificadores necessários a relatórios do titular dos detalhes livres da consulta; avaliar pseudonimização e controle de acesso à auditoria.
4. Definir política específica para dados de saúde (medicamentos, diagnósticos e histórico clínico), inclusive retenção e visualização da trilha.
5. Manter funcionamento dos relatórios existentes de acesso ao titular.

**Aceite:** testes com `%XX`, `+`, `subject_id`, `access_token`, `password` e texto clínico; o relatório identifica o acesso legítimo ao titular sem expor segredos no conteúdo bruto de `AuditQuery`.

### AUD-02 — Contrato de persistência da meta-auditoria

**Evidência:** `crates/heraclitus-server/src/engine.rs`, `audit_query`, `audit_admin`, `audit_admin_strict`; middleware em `crates/heraclitus-server/src/rest.rs`.

**Comportamento atual:** `audit_query` descarta o erro de `append_internal`; `audit_admin` exibe aviso; `audit_admin_strict` devolve `Result`. A tarefa assíncrona do REST espera pela chamada, mas isso não garante que a gravação tenha sido concluída com sucesso.

**Requisitos:**

1. Documentar quais operações aceitam auditoria best-effort e quais exigem **fail-closed**.
2. Fornecer resultado/recibo observável da persistência quando a política exigir confirmação.
3. Instrumentar contadores e alertas para falhas de auditoria, sem registrar segredos em mensagens de erro.
4. Não alterar a semântica do diário durável `TrustedAdmin` sem verificar seus próprios contratos de intenção e resultado.
5. Evitar que falha no evento de auditoria gere *retry* cego de uma operação de negócio já confirmada; formalizar ordenação, idempotência e recuperação.

**Aceite:** simular falha de append de auditoria para consultas e operações administrativas; testar separadamente o modo best-effort e as operações estritas, inclusive reinício e consulta posterior aos recibos.

### AUTH-01 — Isolamento dos registros na integração com aplicações

**Evidência:** `crates/heraclitus-core/src/config.rs`, `AccessRole::allows`; `crates/heraclitus-server/src/grpc.rs`, `subscribe` e `episode_json`; `crates/heraclitus-server/src/flight_grpc.rs`, `do_get`.

**Precisão:** `Subscribe` pode transmitir conteúdo e atributos do log completo a um principal com papel `Reader`. O Flight `DoGet` analisado expõe **metadados**, e não o conteúdo completo. TLS, autenticação, validações de bind e RBAC já existem; a ausência de filtro por paciente não equivale a acesso público não autenticado.

**Requisitos condicionais para apps multi-tenant:**

1. Não entregar credenciais `Reader` de âmbito global diretamente a pacientes/dispositivos de usuários finais.
2. Enforçar autorização de objeto por paciente/tenant na camada de aplicação ou criar uma API filtrada explicitamente autorizada.
3. Cobrir histórico, assinatura em tempo real, recuperação após atraso e exportação de metadados com a mesma política.
4. Impedir inferência lateral de existência de outros pacientes por campos de metadados, contagens, eventos e mensagens de erro.
5. Testar isolamento com dois pacientes, dois principais e um cuidador com autorização delegada.

**Aceite:** não há conteúdo ou metadado de outro tenant em qualquer fluxo acessível ao paciente; tentativas inválidas são negadas e auditáveis. Para uma implantação de serviço único confiável, registrar formalmente a fronteira de confiança adotada.

### IDEM-01 — Espaço de nomes de chaves idempotentes

**Evidência:** `crates/heraclitus-server/src/engine.rs`, `append_idempotent`, usa `lookup(IDEMPOTENCY_KEY_ATTR, key)` e compara hashes; a identidade autenticada é anexada no caminho gRPC. O diário do `TrustedAdmin` já tem escopo por tenant/principal/chave em sua lógica própria.

**Requisitos:**

1. Escolher e documentar se a chave de append ordinário é **global** ou específica de `(tenant, principal, chave)`.
2. Se mudar o escopo, versionar índice/atributo para permitir resolução de chaves antigas e novas sem dupla gravação.
3. Preservar o retorno idempotente de retries legítimos e a detecção de payload conflitante.
4. Não alterar o escopo do `TrustedAdmin` por engano.

**Aceite:** matriz de casos: mesmo principal/mesma chave/mesmo payload; mesmo principal/payload diferente; principais diferentes/mesma chave; reinício e replay do índice.

### STR-01 — Semântica auditável do ciclo de vida de streams

**Evidência:** `crates/heraclitus-server/src/flight_grpc.rs`, `do_get`, registra `ok=true` após admissão e antes da execução de `scan_capped`; `crates/heraclitus-server/src/grpc.rs`, `subscribe`, audita antes da entrega.

**Precisão:** `ok=true` no ponto atual pode significar **aceito**, não **entrega concluída**. Isso não prova perda ou corrupção de dados.

**Requisitos:**

1. Explicitar `accepted`, `completed`, `failed` e `cancelled` quando a aplicação exigir comprovante de entrega.
2. Vincular esses eventos por identificador de solicitação e principal, sem registrar payload sensível.
3. Não declarar `completed` apenas por abrir um stream; diferenciar EOF normal, erro de scan e cancelamento do consumidor.
4. Considerar duração potencialmente ilimitada de `Subscribe` e, nesse caso, registrar início, falha/cancelamento e marcos de progresso definidos.

**Aceite:** stream bem-sucedido, corrupção/erro de leitura após admissão, desconexão no meio do lote e cliente lento devem gerar estados coerentes, sem duplicidade enganosa de `completed`.

## 4. Robustez, contratos e desempenho

### IPC-01 — Esclarecer importação mínima, sem classificar como defeito

`crates/heraclitus-analytics/src/flight.rs`, `IpcFlightService::do_put`, exige somente `agent_id` e `kind` e cria `Episode` com conteúdo vazio. O teste existente comprova esse contrato de duas colunas. A operação `do_put` do Flight gRPC de rede está não implementada; não afirmar corrupção na rede.

**Aceite documental:** declarar que o método cria novos episódios mínimos, **não** faz restauração fiel, migração ou *round-trip* de conteúdo, atributos e IDs. Se for necessário um importador fiel, criar especificação separada e testes de equivalência.

### RAFT-01 — Tratamento de erro permanente no accept

`crates/heraclitus-raft/src/grpc.rs`: `TcpListenerStream` usa `filter_map` que descarta erros de `accept` sem pausa explícita. Outro listener TCP do projeto usa espera curta em falhas.

**Hipótese:** em erro permanente de recursos (p.ex. `EMFILE`), pode haver repetição excessiva. Não afirmar consumo elevado de CPU sem injeção de falha.

**Aceite:** injetar erros de `accept`; medir CPU, frequência de tentativas e capacidade de recuperação. Se confirmado, aplicar backoff limitado, métricas e recuperação sem interromper definitivamente o listener.

### HLC-01 — Limite de saturação

`crates/heraclitus-core/src/hlc.rs`: operações com `saturating_add` permitem valor repetido no máximo de `u64`; o teste atual já admite não decrescimento. O caso não constitui falha prática identificada em operação normal.

**Aceite documental:** descrever precisamente a propriedade garantida, inclusive na borda `u64::MAX`. Não alterar o algoritmo sem teste de compatibilidade e ordenação.

### SQL-01 — Planejamento incremental sob orçamento

`crates/heraclitus-analytics/src/lib.rs`, `from_log_capped`, monta vetores de várias colunas ao percorrer o log antes da consulta. O REST usa limites de materialização (incluindo máximo de linhas e orçamento de memória). Há admissão controlada; **não alegar OOM ilimitado**.

**Proposta:** avaliar pushdown de projeção, predicado e agregação, com streaming ou leitura em blocos, preservando equivalência de resultado e os mesmos limites de segurança.

**Aceite:** comparar latência, RSS e correção de `COUNT(*)`, filtros seletivos e projeções, em logs grandes e com várias requisições simultâneas. Confirmar que limites continuam efetivos quando não houver pushdown possível.

### FLT-01 — Exportação projetada de metadados

`crates/heraclitus-server/src/flight_grpc.rs`, `do_get`, percorre episódios inteiros e calcula `resident_bytes`, mas o schema exportado contém `lsn`, `agent_id`, `kind`, `ts`, `content_len`.

**Proposta:** interface de scan/projeção capaz de obter metadados e comprimento sem manter conteúdo/embedding completos em memória, quando suportado pelo layout do log.

**Aceite:** mesmas linhas/ordem do exportador atual, consumo de memória inferior para payloads grandes, tratamento igual para registros danificados e cancelamentos.

### RES-01 — Contenção entre serviços por orçamento global

Semáforos estáticos (`OnceLock<Arc<Semaphore>>`) aparecem no caminho SQL/analytics e Flight. Isso limita sessões globalmente no processo; pode ser intencional para proteção de recursos.

**Aceite:** benchmark com várias instâncias/serviços no mesmo processo. Decidir explicitamente entre cota global, por instância ou hierárquica; manter um limite global de memória para evitar regressão de segurança.

## 5. Testes de regressão propostos

| Teste | Módulo | Expectativa |
|---|---|---|
| `audit_redacts_secrets_preserves_subject_lookup` | REST/Engine | Segredos não aparecem e o relatório de titular funciona |
| `audit_append_failure_follows_policy` | Engine/REST | Resultado da operação segue política definida e a falha é observável |
| `reader_cannot_cross_tenant_boundary` | gRPC/gateway | Identidade A não lê dados de B via histórico ou live tail |
| `idempotency_scoped_principals_and_replay` | Engine | Colisões, retries e migração respeitam o contrato |
| `flight_audit_lifecycle_scan_error` | Flight | Erro pós-admissão não é relatado como conclusão |
| `subscribe_audit_lifecycle_cancellation` | gRPC | Cancelamento não é registrado como entrega integral |
| `raft_accept_error_backoff_recovery` | Raft | Falhas persistentes não causam spin excessivo; recupera |
| `sql_large_log_aggregate_budget` | Analytics | Consulta e limite de recurso são previsíveis e corretos |
| `flight_metadata_large_payload_memory` | Flight | Metadados corretos com pico de RSS controlado |
| `ipc_put_minimal_episode_contract` | Analytics IPC | API permanece explícita sobre conteúdo vazio |

**Critérios de homologação:**

1. `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features` e testes de workspace aprovados em ambiente Rust reproduzível.
2. Testes de falha/concorrência executados com resultados anexados ao PR, incluindo logs de erro sanitizados.
3. Testes negativos de isolamento e de privacidade com payloads sintéticos; não usar dados reais de pacientes.
4. Benchmarks antes/depois para SQL, Flight e concorrência; não adotar mudanças sem ganhos medidos ou justificativa de segurança.
5. Revisão de compatibilidade de dados/índices antes de alterar formato de auditoria ou escopo de idempotência.

## 6. Ordem sugerida de implementação

1. **Marco A — Privacidade e autorização:** AUD-01 e AUTH-01; definir o modelo de identidade e tenant usado pela aplicação consumidora.
2. **Marco B — Evidência durável:** AUD-02 e STR-01; alinhar garantias de registros de auditoria ao contrato de cada operação.
3. **Marco C — Contratos e recuperação:** IDEM-01, documentação IPC-01 e testes RAFT-01/HLC-01.
4. **Marco D — Eficiência comprovada:** SQL-01, FLT-01 e RES-01, condicionados a benchmarks.

Cada mudança deve ter PR próprio ou série pequena e reversível, testes e plano de migração quando o formato persistido mudar. Não misturar otimizações de desempenho com correções de segurança numa única alteração difícil de auditar.

## 7. Proteções existentes preservadas

A reauditoria identificou controles que **não** devem ser apresentados como ausentes:

- Validações de segurança para interfaces não-loopback, autenticação e TLS.
- Requisitos de produção para encriptação em repouso, política de `fsync`, auditoria e RBAC.
- Limites de memória/linhas e admissão para SQL e Flight.
- SQL de leitura com restrições contra DDL/DML.
- Diário durável específico no protocolo `TrustedAdmin`.
- CI, testes e qualificação já existentes; a demanda é por cenários adversariais adicionais.

## 8. Fecho e rastreabilidade

**Conclusão da terceira passada:** o risco mais relevante para um app de agendamento de medicamentos com EVA/Gemini Live é a fronteira entre credenciais do servidor e dados de pacientes, seguida por minimização dos dados de auditoria e garantia de persistência quando exigida. Os demais itens são correções contratuais, hipóteses a reproduzir ou melhorias de performance.

**Correções do parecer preliminar:**

1. **IPC:** retirar rótulo de perda inesperada de dados; importação mínima intencional.
2. **Flight/Subscribe:** `ok=true` antes do stream é sinal de admissão, não prova falsa de conclusão, salvo se o contrato prometer entrega completa.
3. **Idempotência:** delimitar ao append comum; diário do `TrustedAdmin` possui escopo próprio.
4. **SQL:** reconhecer explicitamente limites de memória e admissão já existentes.
5. **HLC:** classificar saturação extrema como limite conhecido, não bug de produção confirmado.
6. **CI/benchmarks:** reconhecer a infraestrutura já existente; propor cobertura adversarial específica.

**Arquivos-base inspecionados:**

- `crates/heraclitus-server/src/{engine.rs,rest.rs,grpc.rs,flight_grpc.rs,trusted_admin.rs}`
- `crates/heraclitus-core/src/{config.rs,hlc.rs}`
- `crates/heraclitus-analytics/src/{lib.rs,flight.rs}`
- `crates/heraclitus-raft/src/grpc.rs`
- `.github/workflows/ci.yml`

**Referências internas de contexto:** `docs/AUDITORIA-2026-10-16.md` e `docs/md/VALIDACAO_v3.0.3.md`. Essas auditorias têm escopos/commits distintos; os achados deste documento não substituem automaticamente o histórico anterior.
