# Segurança & Compliance

## Objetivo

O HeraclitusDB trata integridade, proveniência e evidência como propriedades de arquitetura, não como funcionalidades cosméticas adicionadas depois. Para ambientes públicos e regulados, isso reduz a dependência de confiança implícita em administradores, aplicações e bancos intermediários.

## Controles técnicos

### Integridade

O projeto utiliza mecanismos baseados em BLAKE3, árvores Merkle, CRC e estruturas de manifesto para detectar alterações inesperadas em artefatos persistidos e apoiar verificação independente.

### Criptografia

O workspace possui camada criptográfica própria e separada. Chaves, algoritmos, rotação, backup e procedimentos de recuperação devem ser definidos no plano operacional do órgão e testados antes da produção.

### Temporalidade e proveniência

LSN/HLC, replay e histórico append-only permitem associar uma resposta não apenas ao conteúdo, mas ao estado histórico do sistema que a produziu.

### Agentes de IA

A arquitetura inclui componentes para gateway, policy e evidência de agentes. O objetivo é registrar e controlar chamadas de ferramentas, aprovações e efeitos de automações, evitando que ações de IA se tornem uma caixa-preta administrativa.

### SOC e resposta

O Heraclitus Sentinel é a camada voltada à segurança cibernética. Sua implantação deve seguir segregação de privilégios, regras de contenção, revisão humana para ações de alto impacto e armazenamento verificável das evidências produzidas.

## Supply-chain

O repositório inclui workflows dedicados a CI, qualificação e supply-chain. Em implantação institucional recomenda-se exigir, conforme o risco:

- build reproduzível ou verificável;
- SBOM por release;
- assinatura de artefatos;
- registro do commit e toolchain usados no build;
- inventário de dependências;
- análise de vulnerabilidades;
- política para dependências críticas;
- trilha de promoção entre ambientes;
- retenção dos artefatos usados em produção.

## Resposta a vulnerabilidades

Existe documentação específica em [`../security/vulnerability-response.md`](../security/vulnerability-response.md). Achados exploráveis não devem ser publicados prematuramente em issues públicas. O fluxo institucional deve incluir triagem, severidade, mitigação, correção, validação, comunicação e evidência do encerramento.

## Matriz de referenciais

A tabela abaixo indica **possíveis pontos de mapeamento técnico**. Não representa certificação ou parecer jurídico.

| Referencial | Relação técnica possível |
|---|---|
| LGPD | rastreabilidade, controles de acesso, retenção, governança e evidência de tratamento |
| ISO/IEC 27001 | gestão de ativos, logging, controle de acesso, continuidade, vulnerabilidades e supply-chain |
| NIST CSF | Identify, Protect, Detect, Respond e Recover por meio de inventário, proteção, Sentinel e runbooks |
| Segurança cibernética no setor público | segmentação, observabilidade, resposta, gestão de vulnerabilidades e continuidade |
| ICP-Brasil / carimbo do tempo | uso dos componentes de compliance quando configurados para evidência temporal |
| SBOM / software supply-chain | workflows, rastreabilidade de builds e documentação de release |

## Classificação da informação

Antes da adoção, o órgão deve responder:

1. Que classes de informação serão armazenadas?
2. Há dados pessoais, sigilosos ou classificados?
3. Quem pode consultar o histórico completo?
4. Quem pode administrar chaves e políticas?
5. Por quanto tempo eventos e evidências devem ser retidos?
6. O que pode ser exportado e em quais formatos?
7. Quais componentes podem acessar redes externas?

O fato de o banco ser auditável não elimina obrigações de minimização, segregação, retenção e controle de acesso.

## Modelo de ameaça mínimo

Considere pelo menos:

- adulteração de arquivos em repouso;
- operador privilegiado malicioso;
- credencial comprometida;
- corrupção parcial de disco;
- replay ou reordenação indevida de eventos;
- dependência comprometida na cadeia de build;
- ação autônoma indevida de agente;
- exfiltração por interfaces de consulta;
- perda de chaves;
- falha simultânea de infraestrutura e observabilidade.

## Princípio operacional

Segurança demonstrável exige evidência. Portanto, cada controle crítico deve ter um teste, um artefato de verificação e um responsável. Política sem prova executável é apenas um PDF esperando ser esquecido numa pasta de rede.
