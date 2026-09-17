# Documentação do HeraclitusDB

Bem-vindo ao portal documental versionado do HeraclitusDB.

## Entrada recomendada

- **Visão institucional:** [`wiki/Home.md`](wiki/Home.md)
- **Governo e soberania:** [`wiki/GOVERNMENT.md`](wiki/GOVERNMENT.md)
- **Arquitetura:** [`wiki/ARCHITECTURE.md`](wiki/ARCHITECTURE.md)
- **Segurança e compliance:** [`wiki/SECURITY-COMPLIANCE.md`](wiki/SECURITY-COMPLIANCE.md)
- **Implantação:** [`wiki/DEPLOYMENT.md`](wiki/DEPLOYMENT.md)
- **Operações:** [`wiki/OPERATIONS.md`](wiki/OPERATIONS.md)
- **Roadmap:** [`wiki/ROADMAP.md`](wiki/ROADMAP.md)
- **FAQ:** [`wiki/FAQ.md`](wiki/FAQ.md)
- **Glossário:** [`wiki/GLOSSARY.md`](wiki/GLOSSARY.md)

## Documentação técnica existente

- [`getting-started/`](getting-started/) — início rápido.
- [`qualification/`](qualification/) — qualificação e evidências técnicas.
- [`runbooks/`](runbooks/) — operação e recuperação.
- [`security/`](security/) — segurança e resposta a vulnerabilidades.
- [`agent/`](agent/) — componentes relacionados a agentes.
- [`TELEMETRY_HEALTH.md`](TELEMETRY_HEALTH.md) — saúde e telemetria.
- [`BLOQUEIOS-PRODUCAO.md`](BLOQUEIOS-PRODUCAO.md) — pendências relevantes para produção.
- [`AUDITORIA-2026-09-05.md`](AUDITORIA-2026-09-05.md) — auditoria técnica.
- [`AUDITORIA-RECURSIVA-2026-09-05.md`](AUDITORIA-RECURSIVA-2026-09-05.md) — auditoria recursiva detalhada.

## Convenção de maturidade

A documentação institucional usa quatro rótulos conceituais:

- **Implementado** — presente no código e utilizável conforme configuração.
- **Opcional** — depende de feature, módulo ou configuração.
- **Em qualificação** — implementado, mas ainda sujeito a provas adicionais para produção.
- **Roadmap/pesquisa** — direção técnica, não promessa operacional.

## Para avaliação institucional

A ordem recomendada de leitura é:

```text
Home → Governo → Arquitetura → Segurança → Implantação → Operações → Roadmap
```

Depois, confronte a visão institucional com a qualificação, os runbooks e os bloqueios de produção. O objetivo é que a documentação comercial e a realidade do repositório contem a mesma história, um conceito surpreendentemente revolucionário em software corporativo.
