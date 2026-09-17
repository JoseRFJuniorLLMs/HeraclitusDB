# Governo & Soberania

## Proposta para o setor público

O HeraclitusDB foi concebido para organizações em que dados precisam ser não apenas disponíveis, mas **explicáveis, rastreáveis, recuperáveis e verificáveis ao longo do tempo**.

No setor público, isso é relevante porque decisões administrativas, registros de sistemas, evidências de segurança, dados de fiscalização e ações automatizadas podem precisar ser reconstruídos meses ou anos depois. Um banco que entrega apenas o estado atual responde mal a esse requisito.

## Princípios institucionais

### Soberania

O núcleo é escrito em Rust e pode ser implantado em infraestrutura própria. A arquitetura não pressupõe dependência obrigatória de SaaS externo, API proprietária ou LLM remoto para o funcionamento do núcleo de dados.

### Auditabilidade

O log canônico append-only preserva sequência e histórico. Views e índices são derivados. Esse desenho facilita replay, inspeção temporal e produção de trilhas de evidência.

### Defesa em profundidade

A arquitetura separa persistência, criptografia, compliance, índices, query, agentes, Sentinel e superfícies de serviço. A separação permite aplicar controles por camada e reduzir o raio de impacto de falhas.

### Interoperabilidade

O sistema inclui superfícies de serviço e componentes independentes para ingestão, consulta, analytics e integração. A adoção governamental deve privilegiar formatos, APIs e artefatos exportáveis para reduzir aprisionamento tecnológico.

### Transparência técnica

O repositório contém código, documentação de qualificação, runbooks, auditorias e bloqueios conhecidos de produção. A estratégia recomendada é expor critérios objetivos de maturidade em vez de esconder limitações atrás de linguagem comercial.

## Casos de uso institucionais

| Área | Exemplo de uso |
|---|---|
| Controle e auditoria | preservar histórico de alterações e comprovar origem de registros |
| Segurança cibernética | correlacionar eventos, incidentes, ações e evidências |
| Fiscalização | cruzar entidades, relações, texto e séries temporais |
| Inteligência de dados | recuperação híbrida em bases institucionais |
| IA governada | registrar contexto, ferramentas, aprovações e resultados de agentes |
| Governança de dados | reconstruir estados anteriores e manter proveniência |
| Investigação | navegar relações, hipóteses e fatos sem perder temporalidade |

## Modelo de adoção recomendado

### 1. Laboratório

Validar build, ingestão, consulta, replay, integridade, exportação e operação sem dados sensíveis.

### 2. Prova de conceito institucional

Usar conjunto de dados representativo, definir modelo de ameaça e medir throughput, latência, recuperação, consumo de recursos e capacidade operacional.

### 3. Qualificação

Executar testes de falha, corrupção, backup/restore, atualização/rollback, supply-chain, observabilidade, segurança e resposta a incidentes.

### 4. Piloto controlado

Operar com escopo delimitado, dados classificados adequadamente, responsáveis definidos e critérios de saída documentados.

### 5. Produção

Somente após aceite formal dos requisitos técnicos, jurídicos, de segurança, continuidade e governança aplicáveis ao órgão.

## Ambientes desconectados e restritos

O HeraclitusDB é orientado a cenários on-premises e pode ser preparado para redes restritas. Em ambientes air-gapped, a equipe responsável deve garantir cadeia offline de artefatos, dependências vendorizadas ou espelhadas, atualização controlada, sincronização de indicadores, gestão de chaves, relógio confiável e procedimentos de importação/exportação auditáveis.

## Referenciais brasileiros

A arquitetura pode ser mapeada a controles e requisitos relacionados a LGPD, segurança da informação, segurança cibernética, gestão de riscos, ICP-Brasil e políticas internas de cada órgão. Esse mapeamento deve ser tratado como **engenharia de controles**, não como alegação automática de conformidade jurídica ou certificação.

## Identidade institucional

A documentação adota uma estética sóbria, linguagem administrativa clara e foco em soberania, integridade e prestação de contas. Deliberadamente não utiliza brasões, marcas `gov.br` ou símbolos oficiais, porque aparência institucional não deve ser confundida com vínculo oficial.
