# HeraclitusDB Wiki

> **Plataforma Soberana de Dados Verificáveis para o Setor Público**

Esta wiki organiza a documentação institucional, técnica e operacional do HeraclitusDB. Ela foi estruturada para três públicos: gestores e arquitetos de governo, equipes técnicas responsáveis por implantação/operação e pesquisadores ou auditores que precisam compreender as propriedades verificáveis do sistema.

## Visão executiva

O HeraclitusDB é uma plataforma de dados temporal e multi-modelo cujo estado primário é um log append-only. O desenho busca preservar história, proveniência, integridade e capacidade de reconstrução ao mesmo tempo em que oferece componentes de recuperação textual, vetorial, grafo, atributos, analytics, agentes de IA e defesa cibernética.

A proposta central pode ser resumida em quatro princípios:

1. **A história não é sobrescrita.** Correções e mudanças são novos eventos.
2. **Estruturas derivadas são reconstruíveis.** Índices e views não substituem a fonte canônica.
3. **A evidência deve ser verificável.** Integridade, proveniência e replay não dependem apenas da confiança no servidor.
4. **IA e automação precisam de governança.** Ações, chamadas de ferramentas e decisões automatizadas devem produzir trilhas de evidência.

## Mapa da documentação

| Área | Página |
|---|---|
| Posicionamento institucional | [Governo & Soberania](GOVERNMENT.md) |
| Design do sistema | [Arquitetura](ARCHITECTURE.md) |
| Segurança, evidência e referenciais | [Segurança & Compliance](SECURITY-COMPLIANCE.md) |
| Instalação e topologias | [Implantação](DEPLOYMENT.md) |
| Produção, observabilidade e recuperação | [Operações](OPERATIONS.md) |
| Evolução e maturidade | [Roadmap](ROADMAP.md) |
| Dúvidas recorrentes | [FAQ](FAQ.md) |
| Vocabulário | [Glossário](GLOSSARY.md) |

## Para órgãos públicos

O HeraclitusDB foi desenhado para cenários em que simplesmente armazenar dados não basta. Casos típicos incluem auditoria, controle, investigação, trilhas de decisão, segurança cibernética, análise temporal, memória verificável de agentes e preservação de evidências.

O modelo recomendado de adoção é incremental:

```text
Prova técnica → laboratório controlado → qualificação → piloto institucional → produção
```

Antes de produção devem ser avaliados, no mínimo, classificação da informação, modelo de ameaça, requisitos legais, segregação de funções, retenção, backup, recuperação de desastre, gestão de chaves, observabilidade, capacidade, supply-chain e processo de resposta a vulnerabilidades.

## Maturidade e linguagem institucional

Esta documentação distingue:

- **Implementado:** código presente no workspace e utilizável conforme configuração.
- **Opcional:** disponível por feature, módulo ou configuração específica.
- **Em qualificação:** possui implementação, mas ainda depende de critérios/provas de produção.
- **Roadmap/pesquisa:** direção técnica ainda não tratada como garantia operacional.

Essa distinção é deliberada. Material institucional sério precisa explicar limites, não escondê-los em letras pequenas que ninguém lê até o incidente.

## Aviso de independência

O HeraclitusDB é um projeto independente e não constitui software oficial, homologado ou endossado pelo Governo Federal brasileiro. A identidade desta documentação usa linguagem e organização adequadas ao setor público, sem reproduzir brasões, marcas oficiais ou elementos que possam sugerir vínculo institucional inexistente.
