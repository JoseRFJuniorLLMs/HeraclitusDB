# HeraclitusDB v3.0.1 — Operations & Security Command Center

**Data:** 2026-09-17  
**Linha:** 3.x  
**Status do software:** Release 3.0.1  

## Visão Geral

A v3.0.1 introduz o **Heraclitus Operations & Security Command Center** no CLI (`heraclitus top`), transformando o monitor de terminal em uma console completa de operações, segurança cibernética e auditoria regulatória em tempo real, alinhada às SPECs 0078, 0079, 0080, 0081, 0082, 0083, 0084 e 0085.

## Principais Novidades

### 1. Arquitetura em 9 Abas Especializadas
1. **Overview**: LSN, throughput de escrita/leitura, latência de barramento, estado Raft, defasagem Sentinel, integridade de evidências dos agentes, contadores de alarmes ativos e painel de **Provas Formais Lean 4**.
2. **Pipelines**: Inspeção e diagnóstico dos 9 workers contínuos do sistema (HRKL Packing, Lakehouse Parquet, HRKI Sidecar, CRC Integrity, Canonical Verify, Sentinel SOC Pipeline, Agent Evidence Log, Red Team Adversarial Probes, RFC 3161 TSA Anchor) com seleção interativa (`↑/↓`).
3. **Storage**: Métricas físicas de LSM/HRKL, taxas de compressão zstd, profundidade de filas de pack e leituras a frio.
4. **Queries**: QPS, distribuição p50/p95/p99 de latência e consumo de recursos por comando.
5. **Raft**: Papel do nó, liderança de consenso, índice comitado/aplicado e sincronização de réplicas.
6. **Security**: Monitoramento do Sentinel SOC, postura de ameaças e **Tabela de Alarmes em Tempo Real** com ciclo de vida e detecção de deltas.
7. **Agents**: KPIs do Agent Gateway MCP, aprovações humanas em voo, proteção contra bypass e **Tabela ao Vivo de Eventos Adversariais (Red Team)**.
8. **Indexes**: Vetores HNSW, índices de texto invertido, grafos temporais e ativação neural.
9. **Compliance**: Selos RFC 3161 ICP-Brasil, Watermarks criptográficos, prazos regulatórios (LGPD/GDPR) e invariantes de não-repúdio.

### 2. Top Banner Permanente
- Exibição ininterrupta no cabeçalho em todas as abas: status do banco (`ONLINE`/`OFFLINE`), LSN atual, taxa de transferência, latência Sentinel, saúde do Agent Gateway, taxa de defesa contra ataques, integridade lógica/física (CRC, Canonical, Evidence) e indicador crítico imediato de vazamento de fronteira (`BOUNDARY LEAK DETECTED` sob `upstream_delta > 0`).

### 3. Tabela de Invariantes Formais Lean 4
- Rastreamento explícito das propriedades matemáticas provadas: `ProofAppendOnly`, `ProofMerkleTree`, `ProofDeterministicReplay`, `ProofDenseMap`, `ProofHLC`, `ProofApprovalIdempotence`, `ProofToolCallIsolation` (`PROVED`), e `ProofRFC3161Seal` (`TESTED`).

### 4. Contrato de Telemetria e Transparência
- Eliminação estrita de falso-verde: qualquer subsistema ou métrica sem resposta válida é rotulada como `UNKNOWN` ou `N/D`.
