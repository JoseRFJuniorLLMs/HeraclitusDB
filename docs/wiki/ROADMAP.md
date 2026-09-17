# Roadmap e Maturidade

## Objetivo

O roadmap do HeraclitusDB deve comunicar duas coisas diferentes: **o que existe no código** e **o que ainda precisa ser provado em condições de produção**. Misturar essas categorias cria expectativas erradas e dificulta avaliação institucional.

## Matriz de maturidade

| Área | Situação documental | Próximo objetivo |
|---|---|---|
| Log canônico / histórico | núcleo do produto | ampliar provas de crash, corrupção e recuperação |
| Views e replay | implementados no workspace | qualificação contínua de determinismo e rebuild |
| Índices graph/text/vector/attr | implementados | benchmarks públicos e perfis de capacidade |
| Query e analytics | implementados/modulares | matrizes de compatibilidade e cargas representativas |
| Criptografia/compliance | componentes dedicados | ampliar validação operacional e documentação de chaves |
| Replicação | componente dedicado | cenários de partição, quorum, failover e DR |
| GPU/HUME | aceleração especializada | portabilidade, fallback e benchmarks reprodutíveis |
| Agent Gateway | componente dedicado | hardening de policies, isolamento e evidência |
| Sentinel | componente dedicado | qualificação progressiva de detecção e resposta |
| Supply-chain | workflows dedicados | consolidar release assinado, SBOM e provenance |
| Operação air-gapped | objetivo explícito | kit offline reproduzível e runbooks completos |

## Prioridades para governo

### P0 — Evidência e produção

- fechar todos os bloqueios de produção documentados;
- demonstrar backup/restore e disaster recovery;
- executar testes recorrentes de crash e corrupção;
- garantir release reproduzível e identificável;
- consolidar SBOM, assinatura e provenance;
- manter política de vulnerabilidades operacional.

### P1 — Operação institucional

- perfis de implantação de referência;
- baseline de observabilidade;
- matriz de capacidade por hardware;
- documentação de atualização e rollback;
- controles de acesso e segregação de funções por superfície;
- pacote de instalação para redes restritas.

### P2 — Integração e ecossistema

- exemplos de ingestão para dados públicos e eventos de segurança;
- conectores institucionais;
- SDKs e exemplos mínimos por linguagem suportada;
- exportação de evidências e dados em formatos interoperáveis;
- modelos de dashboards e investigação.

### P3 — Pesquisa e diferenciação

- HUME e otimizações microarquiteturais;
- GPU e geometria especializada;
- investigação assistida por modelos locais;
- raciocínio temporal/causal mais rico;
- provas formais de invariantes críticos.

## Critério para promover uma capacidade

Uma capacidade só deve subir de “experimental/em qualificação” para “produção” quando houver:

1. implementação versionada;
2. testes automatizados adequados;
3. benchmark ou critério funcional objetivo;
4. teste de falha relevante;
5. documentação operacional;
6. observabilidade;
7. procedimento de rollback/recuperação;
8. análise de segurança;
9. evidência reprodutível do resultado.

## Governança do roadmap

Specs descrevem intenção. Código demonstra implementação. Testes demonstram propriedades específicas. Qualificação demonstra comportamento sob cenários de operação. Nenhum desses artefatos substitui os demais.

Essa separação é especialmente importante para projetos complexos: uma SPEC de 80 páginas pode ser excelente e ainda assim não reinicia um nó quebrado sozinha, por mais que a literatura técnica tenha fé em si mesma.
