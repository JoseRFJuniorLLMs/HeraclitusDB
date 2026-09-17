<p align="center">
  <img src="img/logo.jpg" alt="HeraclitusDB" width="220" />
</p>

<h1 align="center">HeraclitusDB</h1>

<p align="center"><strong>Plataforma Soberana de Dados Verificáveis para o Setor Público</strong></p>

<p align="center">
  Dados temporais • Auditoria criptográfica • Busca multimodal • IA governada • SOC soberano
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.1-1351B4" alt="version 3.0.1" />
  <img src="https://img.shields.io/badge/core-Rust%202021-071D41" alt="Rust 2021" />
  <img src="https://img.shields.io/badge/license-BUSL--1.1-168821" alt="BUSL 1.1" />
  <img src="https://img.shields.io/badge/history-append--only-0C326F" alt="append only" />
  <img src="https://img.shields.io/badge/integrity-BLAKE3%20%2B%20Merkle-168821" alt="BLAKE3 Merkle" />
  <img src="https://img.shields.io/badge/target-Linux%20%7C%20On--Prem%20%7C%20Air--Gapped-071D41" alt="deployment targets" />
</p>

> **Posicionamento institucional.** O HeraclitusDB é um projeto independente, concebido para requisitos típicos de governo, infraestrutura crítica e ambientes regulados. Não é produto oficial, homologado ou endossado pelo Governo Federal brasileiro. Referências a normas e estruturas de governança indicam objetivos de engenharia e mapeamento de controles, não certificação automática.

---

## Missão

O HeraclitusDB foi desenhado para um problema que bancos tradicionais tratam mal: **preservar a história, a proveniência e a verificabilidade dos dados sem abrir mão de busca, analytics, grafo, vetores e automação por IA**.

Em vez de considerar o estado atual como única verdade, o HeraclitusDB usa um log canônico append-only. Correções são novos fatos. Estados anteriores podem ser reconstruídos. Índices e views são derivados e reconstruíveis. A integridade pode ser verificada independentemente do servidor que produziu a resposta.

```text
                          HERACLITUSDB
                               │
       ┌───────────────────────┼────────────────────────┐
       │                       │                        │
       ▼                       ▼                        ▼
   DATA CORE              INTELLIGENCE              SENTINEL
 append-only             graph/vector/text       security analytics
 temporal state           causal retrieval        governed response
 provenance               agent memory            evidence trail
       │                       │                        │
       └─────────────── VERIFIABLE HISTORY ───────────┘
                    Merkle • BLAKE3 • LSN/HLC
```

## Por que isso importa ao setor público

| Necessidade institucional | Como o HeraclitusDB aborda |
|---|---|
| **Auditabilidade** | log append-only, LSN/HLC, replay e trilha de proveniência |
| **Integridade de evidências** | hashes BLAKE3, árvores Merkle, CRC e mecanismos de verificação offline |
| **Soberania tecnológica** | núcleo em Rust, execução on-premises, operação local e desenho compatível com ambientes restritos |
| **Investigação e controle** | grafo temporal, texto, vetor, atributos e fusão de recuperação |
| **IA com governança** | gateway de agentes, políticas, evidências de chamadas e trilha de decisão |
| **Defesa cibernética** | Heraclitus Sentinel para ingestão, correlação, investigação e resposta auditável |
| **Preservação histórica** | consultas `AS OF`, views reconstruíveis e histórico físico não sobrescrito |

## Capacidades principais

### Núcleo de dados

- Log canônico **HRKL**, append-only, com LSN/HLC.
- Views materializadas reconstruíveis a partir do log.
- Índices especializados para **grafo**, **texto**, **vetores** e **atributos**.
- Memtable para leitura recente e garantias de consistência operacional.
- Query layer e analytics com componentes dedicados no workspace.
- Replicação Raft, tiering, GPU e analytics como capacidades modulares/feature-gated.

### Segurança e evidência

- Integridade criptográfica e verificação independente.
- Criptografia e camada de compliance dedicadas.
- Pipeline de CI, qualificação noturna e supply-chain no próprio repositório.
- Política documentada de resposta a vulnerabilidades.
- Arquitetura orientada a execução controlada e rastreabilidade de agentes de IA.

### Inteligência e investigação

- Recuperação híbrida com sinais textuais, vetoriais, de grafo e atributos.
- Temporalidade e proveniência como propriedades nativas do modelo.
- Componentes para casos, conteúdo, analytics, agentes e Sentinel.
- Base para workloads de fraude, controle, auditoria, conhecimento e SOC.

## Arquitetura do workspace

O workspace Rust `3.0.1` organiza o sistema em crates especializados, entre eles:

```text
heraclitus-core              tipos fundamentais e tempo lógico
heraclitus-log               log canônico e persistência
heraclitus-crypto            primitivas criptográficas
heraclitus-compliance        evidência e controles de conformidade
heraclitus-memtable          estado recente
heraclitus-views             replay e materialização
heraclitus-index-vector      índice vetorial
heraclitus-index-graph       grafo temporal
heraclitus-index-text        recuperação textual
heraclitus-index-attr        índices de atributos
heraclitus-retrieval         fusão de recuperação
heraclitus-query             linguagem/camada de consulta
heraclitus-analytics         analytics
heraclitus-raft              replicação
heraclitus-gpu               aceleração por GPU
heraclitus-agent             memória/controle de agentes
heraclitus-agent-gateway     policy gateway para agentes
heraclitus-sentinel          defesa cibernética
heraclitus-platform          superfície integrada da plataforma
hume-kernel / hume-ir        infraestrutura de execução HUME
```

A lista canônica de membros está em [`Cargo.toml`](Cargo.toml).

## Início rápido

```bash
git clone https://github.com/JoseRFJuniorLLMs/HeraclitusDB.git
cd HeraclitusDB
cargo build --release
```

Depois do build, consulte o guia mantido no repositório:

- [`docs/getting-started/quickstart.md`](docs/getting-started/quickstart.md)
- [`docs/wiki/DEPLOYMENT.md`](docs/wiki/DEPLOYMENT.md)
- [`docs/wiki/OPERATIONS.md`](docs/wiki/OPERATIONS.md)

## Portal de documentação

A documentação institucional foi organizada como uma wiki versionada junto do código:

| Página | Conteúdo |
|---|---|
| **[Home](docs/wiki/Home.md)** | visão executiva e mapa da documentação |
| **[Governo & Soberania](docs/wiki/GOVERNMENT.md)** | posicionamento para administração pública |
| **[Arquitetura](docs/wiki/ARCHITECTURE.md)** | camadas, fluxo de dados e componentes |
| **[Segurança & Compliance](docs/wiki/SECURITY-COMPLIANCE.md)** | controles, evidência e matriz normativa |
| **[Implantação](docs/wiki/DEPLOYMENT.md)** | on-premises, redes restritas e air-gapped |
| **[Operações](docs/wiki/OPERATIONS.md)** | observabilidade, backup, DR e runbooks |
| **[Roadmap](docs/wiki/ROADMAP.md)** | maturidade e evolução do produto |
| **[FAQ](docs/wiki/FAQ.md)** | perguntas técnicas e institucionais |
| **[Glossário](docs/wiki/GLOSSARY.md)** | termos do ecossistema Heraclitus |

## Modelo de implantação pública

```text
Fontes institucionais
        │
        ▼
 Ingestão / APIs / SDK
        │
        ▼
┌───────────────────────────────┐
│          HeraclitusDB         │
│  HRKL • Views • Query • RAG   │
│  Agent Gateway • Sentinel     │
└───────────────┬───────────────┘
                │
     ┌──────────┼───────────┐
     ▼          ▼           ▼
 Auditoria   Analytics   Investigação
     │          │           │
     └──── Evidência verificável ────┘
```

O desenho prioriza **on-premises**, segmentação de rede, operação offline quando necessário, preservação de evidência, reconstrução determinística e separação entre dado canônico e estruturas derivadas.

## Referenciais de governança

O projeto possui componentes e documentação que podem ser mapeados a requisitos de:

- LGPD e princípios de governança de dados;
- ISO/IEC 27001 e gestão de controles de segurança;
- NIST Cybersecurity Framework;
- práticas brasileiras de segurança da informação e segurança cibernética aplicáveis ao setor público;
- ICP-Brasil e carimbo do tempo, quando configurados os componentes correspondentes;
- SBOM, assinatura, rastreabilidade de build e supply-chain.

**Importante:** aderência técnica a controles não equivale, por si só, a homologação, certificação jurídica ou autorização para tratamento de determinada classe de informação.

## Estado do projeto

O HeraclitusDB é um projeto de engenharia em evolução ativa. Alguns componentes são núcleo estável do workspace; outros são opcionais, experimentais, condicionados por feature ou ainda estão em processo de qualificação para produção. Para avaliação séria, use conjuntamente:

- [`docs/BLOQUEIOS-PRODUCAO.md`](docs/BLOQUEIOS-PRODUCAO.md)
- [`docs/qualification/`](docs/qualification/)
- [`docs/runbooks/`](docs/runbooks/)
- [`docs/security/`](docs/security/)
- [Wiki de maturidade e roadmap](docs/wiki/ROADMAP.md)

## Licença

O workspace declara licença **BUSL-1.1**. Consulte [`LICENSE`](LICENSE) para os termos completos e as condições aplicáveis ao uso, distribuição e mudança futura de licença.

## Segurança

Relatos de vulnerabilidade devem seguir a política documentada em [`docs/security/vulnerability-response.md`](docs/security/vulnerability-response.md). Evite publicar detalhes exploráveis em issues públicas antes da coordenação de correção.

## Autoria e citação

Consulte [`CITATION.cff`](CITATION.cff) para dados de citação acadêmica e autoria do projeto.

---

<p align="center"><strong>HeraclitusDB</strong><br/>Infraestrutura para dados que precisam continuar sendo verdade amanhã.</p>
