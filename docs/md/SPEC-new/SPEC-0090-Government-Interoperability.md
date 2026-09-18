# SPEC-0090 — Government Interoperability Surface

**Status:** Draft / Proposed  
**Data:** 18/09/2026  
**Classe:** Interoperability / SQL / BI / Data Exchange  
**Prioridade:** P1  
**Dependências:** SPEC-0037, SPEC-0042, SPEC-0050-HRKL  
**Alvos:** heraclitus-analytics, heraclitus-server, heraclitus-client  
**Princípio:** *Integração pública deve usar protocolos estáveis e formatos abertos antes de criar conectores proprietários para cada ferramenta.*

---

## 0. Decisão

Prioridade de interoperabilidade:

1. completar Arrow Flight necessário;
2. oferecer PostgreSQL wire protocol para leitura analítica;
3. manter Parquet/Iceberg/Delta como intercâmbio lakehouse;
4. adicionar conectores específicos somente onde protocolo aberto não resolver.

Não criar dependência do core em Power BI, Superset, DBeaver, Tableau, OpenSearch ou produto semelhante.

## 1. PostgreSQL wire

Implementar endpoint opcional compatível com subconjunto documentado do protocolo PostgreSQL.

Objetivo inicial: read-only analytics.

Não prometer compatibilidade total com PostgreSQL.

~~~text
Supported v1:
- startup/auth
- simple query
- prepared statements básicos
- row description
- data rows
- cancel
- TLS
- SELECT
- EXPLAIN limitado

Not supported v1:
- DDL arbitrário
- stored procedures
- extensions
- PostgreSQL catalog completo
- replication protocol
~~~

## 2. SQL authority

SQL é planejado/executado pelo motor analítico existente.

O wire protocol é transporte, não novo banco relacional.

~~~text
PostgreSQL client
      |
      v
pgwire adapter
      |
      v
Heraclitus SQL planner / DataFusion
      |
      v
HRKL projections / Lakehouse
~~~

## 3. Segurança

- TLS configurável e obrigatório em production profile;
- autenticação integrada ao identity layer;
- tenant derivado da identidade, nunca de parâmetro livre;
- query budgets;
- read-only por padrão;
- audit principal propagado;
- sem trust em application_name para identidade.

## 4. Arrow Flight

Completar apenas RPCs necessários e declarar explicitamente os não suportados.

Cada método não implementado retorna Unimplemented, nunca sucesso vazio.

Flight deve compartilhar:

- auth;
- tenant;
- budgets;
- query cancellation;
- telemetry;
- audit principal.

## 5. Lakehouse

Manter:

- Parquet;
- Iceberg;
- Delta.

Adicionar compactação de small files conforme dívida já identificada na SPEC-0050 §175.

Objetivo operacional configurável de arquivos consolidados deve ser medido, não hardcoded universalmente.

## 6. OpenSearch/Elasticsearch

Connector separado.

Fluxos permitidos:

~~~text
Heraclitus -> connector -> OpenSearch
external -> connector -> Heraclitus
~~~

Nenhum connector pode tornar OpenSearch autoridade sobre a evidência canônica.

## 7. BI

Ferramentas BI devem conectar por:

- PostgreSQL wire;
- Arrow/Flight quando suportado;
- Parquet/lakehouse.

Um script específico para Power BI pode existir como exemplo, não como dependência arquitetural.

## 8. Semântica temporal

Interfaces devem expor, quando aplicável:

- AS OF LSN;
- AS OF TIMESTAMP/HLC;
- snapshot id.

Ferramenta que não suporta extensão sintática pode usar views/functions documentadas.

## 9. Resource budgets

Configurações globais iniciais:

~~~text
max_rows
max_result_bytes
max_query_time
max_concurrent_queries_per_tenant
max_k
max_graph_depth
memory_budget
spill_budget
~~~

Valores default devem ser definidos por benchmark e perfil, não pela SPEC como números eternos.

## 10. Compatibilidade

Criar matriz pública:

~~~text
Client                Connect   Query   Prepared   TLS   Notes
psql                  ...
DBeaver               ...
Power BI              ...
Superset              ...
Trino connector       ...
~~~

Somente marcar PASS após teste real automatizado/manual reproduzível.

## 11. Testes

1. autenticação inválida;
2. tenant crossing;
3. query cancellation;
4. result cap;
5. timeout;
6. prepared statement;
7. malformed protocol;
8. TLS downgrade recusado em produção;
9. SQL equivalente via HTTP e pgwire retorna snapshot equivalente;
10. restart não muda semântica temporal;
11. cliente psql real;
12. pelo menos dois clientes BI/SQL reais no qualifier de interoperabilidade.

## 12. DoD

- pgwire read-only funcional;
- auth/tenant/budgets compartilhados;
- Flight surface documentada e testada;
- small-file compaction especificada/implementada no plano adequado;
- matriz de clientes;
- connector OpenSearch fora do core;
- nenhuma alegação ANSI/PostgreSQL completa sem suíte que a prove.
