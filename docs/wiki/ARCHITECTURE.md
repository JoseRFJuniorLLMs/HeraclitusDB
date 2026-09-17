# Arquitetura

## Visão geral

O HeraclitusDB é organizado como um workspace Rust modular. O princípio arquitetural central é simples: **o log é a fonte canônica; índices, views e superfícies analíticas são projeções derivadas**.

```text
                         CLIENTES / SDK / APIs
                                  │
                      ┌───────────┴───────────┐
                      ▼                       ▼
                 INGESTÃO                  QUERY
                      │                       │
                      ▼                       ▼
             ┌─────────────────┐      ┌───────────────┐
             │  LOG CANÔNICO   │─────▶│   RETRIEVAL   │
             │ HRKL • LSN/HLC  │      │ graph/text/   │
             │ BLAKE3 • Merkle │      │ vector/attrs  │
             └────────┬────────┘      └───────┬───────┘
                      │ replay                │
                      ▼                       │
             ┌─────────────────┐              │
             │      VIEWS      │◀─────────────┘
             │ materializadas  │
             └───────┬─────────┘
                     │
         ┌───────────┼────────────┐
         ▼           ▼            ▼
     ANALYTICS     AGENTS       SENTINEL
```

## Camadas

### 1. Fundamentos

`heraclitus-core` concentra tipos fundamentais e contratos compartilhados. O workspace inclui tipos temporais, identificadores, estruturas de eventos e primitivas usadas por outros crates.

### 2. Persistência canônica

`heraclitus-log` é a base do histórico persistido. O design append-only permite que correções sejam registradas como novos eventos, preservando a sequência física e lógica.

`heraclitus-crypto` e `heraclitus-compliance` complementam essa camada com criptografia, evidência e controles associados à integridade.

### 3. Estado derivado

`heraclitus-memtable` atende o estado recente. `heraclitus-views` executa replay e materialização. O objetivo é permitir que estruturas auxiliares sejam descartadas e reconstruídas a partir do histórico canônico.

### 4. Índices

- `heraclitus-index-vector`: recuperação vetorial.
- `heraclitus-index-graph`: relações e travessias em grafo.
- `heraclitus-index-text`: recuperação textual.
- `heraclitus-index-attr`: filtros e consultas por atributos.
- `heraclitus-activation`: mecanismos de ativação/memória.
- `heraclitus-btree`: estruturas ordenadas especializadas.

### 5. Recuperação e consulta

`heraclitus-retrieval` combina sinais de múltiplos índices. `heraclitus-query` fornece a camada de consulta. `heraclitus-analytics` amplia a superfície para workloads analíticos.

### 6. Distribuição e tiering

`heraclitus-raft` implementa a camada de replicação. `heraclitus-tier` separa políticas de armazenamento por camada. Esses componentes devem ser avaliados conforme a topologia e o perfil de disponibilidade exigidos.

### 7. Aceleração

`heraclitus-gpu` e os componentes HUME (`hume-kernel`, `hume-ir`, `hume-sketches`) concentram mecanismos especializados de execução e aceleração. O build portátil e o build otimizado por máquina devem permanecer claramente diferenciados.

### 8. Agentes e segurança

`heraclitus-agent` e `heraclitus-agent-gateway` tratam memória, políticas e fronteiras de execução para agentes. `heraclitus-sentinel` concentra capacidades de segurança cibernética e correlação. `heraclitus-case` e `heraclitus-content` apoiam organização de evidências e conteúdo.

### 9. Plataforma e operação

`heraclitus-server`, `heraclitus-client`, `heraclitus-cli`, `heraclitus-proto` e `heraclitus-platform` expõem as superfícies de serviço e operação. `heraclitus-telemetry-health` cobre aspectos de saúde e telemetria.

## Fluxo de escrita

```text
entrada → validação → evento → append no log → confirmação → atualização do estado recente → views/índices
```

A persistência canônica deve preceder qualquer estrutura derivada cuja perda possa ser reconstruída.

## Fluxo de leitura

```text
consulta → planner/query → índices/views/memtable → fusão de resultados → resposta + proveniência
```

Consultas temporais devem especificar claramente o instante lógico ou a referência histórica utilizada.

## Propriedades arquiteturais desejadas

- replay determinístico;
- separação entre verdade canônica e cache/índice;
- integridade verificável;
- degradação explícita quando módulos opcionais não estão disponíveis;
- operação local sem dependência obrigatória de serviços externos;
- auditabilidade de ações humanas e automatizadas;
- modularidade suficiente para implantação por perfil de risco.

## Limites

A existência de um crate ou feature não significa que todos os cenários de produção estejam automaticamente qualificados. O estado de maturidade deve ser confrontado com a documentação de qualificação, runbooks e bloqueios de produção.
