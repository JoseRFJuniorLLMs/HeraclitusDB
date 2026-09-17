# Glossário

## ACT-R

Modelo cognitivo de ativação usado em partes do ecossistema para priorização/recuperação de memória.

## Air-gapped

Ambiente isolado de redes externas. Exige cadeia própria de artefatos, atualizações, indicadores, relógio, certificados e procedimentos de transferência.

## Append-only

Modelo em que novos fatos são anexados ao histórico em vez de sobrescrever registros anteriores.

## BLAKE3

Função criptográfica de hash usada pelo projeto em mecanismos de integridade.

## Checkpoint

Estado materializado usado para reduzir custo de reconstrução sem substituir o log canônico.

## HLC

Hybrid Logical Clock. Combina propriedades de relógios físicos e lógicos para ordenar eventos distribuídos.

## HRKL

Formato/log canônico do HeraclitusDB utilizado para persistência da história de eventos.

## HUME

Família de componentes de execução e otimização do ecossistema HeraclitusDB, incluindo `hume-kernel`, `hume-ir` e `hume-sketches`.

## LSN

Log Sequence Number. Identificador monotônico utilizado para localizar uma posição no histórico.

## Materialized View

Estrutura derivada do log que mantém uma representação otimizada do estado para leitura.

## Merkle Tree

Estrutura de hashes hierárquica que permite verificar integridade de conjuntos de dados de forma eficiente.

## Proveniência

Informação que permite explicar de onde um dado veio, por quais transformações passou e em qual contexto foi produzido.

## Replay

Processo de reaplicar eventos do log para reconstruir estado, views ou índices.

## RPO

Recovery Point Objective. Quantidade máxima de perda de dados aceitável após uma falha.

## RTO

Recovery Time Objective. Tempo máximo aceitável para recuperação de um serviço.

## RRF

Reciprocal Rank Fusion. Técnica de combinação de rankings usada em recuperação híbrida.

## SBOM

Software Bill of Materials. Inventário de componentes e dependências presentes em um artefato de software.

## Sentinel

Subsistema do HeraclitusDB voltado à segurança cibernética, correlação, investigação e resposta auditável.

## Supply-chain

Cadeia de origem, dependências, build, assinatura, distribuição e promoção de artefatos de software.

## View derivada

Qualquer estrutura reconstruível a partir do histórico canônico, como índice, projeção ou materialização.

## Workload

Perfil de uso do sistema: ingestão, leitura, analytics, busca, investigação, SOC, memória de agentes etc.
