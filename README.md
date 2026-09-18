<p align="center">
  <img src="img/logo.jpg" alt="HeraclitusDB" width="220" />
</p>

<h1 align="center">HeraclitusDB</h1>

<p align="center"><strong>Sovereign Trust, Evidence & Data Platform</strong></p>

<p align="center">
  Plataforma soberana de dados, evidência, auditoria e segurança para ambientes governamentais e regulados.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.1-1351B4" alt="version 3.0.1" />
  <img src="https://img.shields.io/badge/core-Rust%202021-071D41" alt="Rust 2021" />
  <img src="https://img.shields.io/badge/license-BUSL--1.1-168821" alt="BUSL 1.1" />
  <img src="https://img.shields.io/badge/history-append--only-0C326F" alt="append only" />
  <img src="https://img.shields.io/badge/integrity-BLAKE3%20%2B%20Merkle-168821" alt="BLAKE3 Merkle" />
  <img src="https://img.shields.io/badge/evidence-RFC%203161%20ready-1351B4" alt="RFC 3161" />
  <img src="https://img.shields.io/badge/deployment-On--Prem%20%7C%20Air--Gap-071D41" alt="deployment targets" />
</p>

> **Posicionamento institucional.** O HeraclitusDB é um projeto independente. Foi concebido para requisitos típicos do setor público, infraestrutura crítica e ambientes regulados, mas não é produto oficial, homologado, certificado ou endossado pelo Governo Federal brasileiro. Mapeamentos normativos e mecanismos técnicos não equivalem, por si só, a conformidade institucional, fé pública, certificação ou admissibilidade jurídica.

---

## O que é o HeraclitusDB

O HeraclitusDB não pretende ser apenas mais um banco de dados.

Ele foi projetado como uma **camada de confiança** entre sistemas que produzem dados e pessoas, órgãos ou agentes que precisam provar o que aconteceu.

A ideia é simples:

~~~text
Sistemas institucionais
        |
        v
     INGEST
        |
        v
    PRESERVE
        |
        v
      PROVE
        |
        v
     CONTROL
        |
        v
      AUDIT
        |
        v
EXPORT VERIFIABLE EVIDENCE
~~~

SIAFI, SEI, ERPs, aplicações administrativas, SOCs, sistemas policiais, plataformas de IA e bancos tradicionais podem continuar fazendo aquilo para que foram construídos.

O HeraclitusDB entra ao lado deles para preservar história, proveniência, evidência e decisão.

---

## A nova identidade do projeto

O produto passa a ser organizado em torno de cinco capacidades fundamentais:

| Capacidade | Pergunta que o sistema deve responder |
|---|---|
| **Preservar** | O que aconteceu, em qual ordem e em qual estado histórico? |
| **Provar** | Estes dados são os mesmos que foram registrados originalmente? |
| **Controlar** | Quem pode executar uma ação sensível e sob quais condições? |
| **Auditar** | Quem fez o quê, quando, em nome de quem e com qual resultado? |
| **Exportar evidência** | Um terceiro consegue verificar a prova sem confiar cegamente no servidor original? |

Essa orientação muda o papel do banco.

~~~text
                     HERACLITUSDB
                          |
        +-----------------+-----------------+
        |                 |                 |
        v                 v                 v
    DATA PLANE        SECURITY PLANE      TRUST PLANE
    HRKL / Raft       Sentinel / Agents   Merkle / RFC3161
    Views / Query     Policy / Approval   Crypto / Compliance
        |                 |                 |
        +-----------------+-----------------+
                          |
                          v
                    EVIDENCE PLANE
                 Provenance / Custody
                Proofs / Legal Hold
                          |
                          v
                 INTEROPERABILITY
             SQL / Flight / Lakehouse
~~~

---

## Por que isso importa

Em sistemas tradicionais, a pergunta comum é:

> Qual é o valor atual?

Em sistemas de auditoria, segurança e investigação, as perguntas são diferentes:

> Qual era o valor naquele momento?  
> Quem o alterou?  
> O estado anterior ainda pode ser reconstruído?  
> O registro foi adulterado?  
> O operador tinha autorização?  
> A ação foi aprovada por quem?  
> A prova continua verificável fora do sistema?

O HeraclitusDB foi construído para tornar essas perguntas propriedades do sistema, e não uma coleção de convenções espalhadas por logs, planilhas e boa vontade humana.

---

## Casos de uso

### Auditoria e controle

- trilhas imutáveis de sistemas administrativos;
- reconstrução temporal de estados;
- auditoria de decisões e operações privilegiadas;
- preservação de eventos contábeis, financeiros e operacionais;
- detecção de alterações retroativas incompatíveis com a história registrada.

### Segurança cibernética

- ingestão e correlação de eventos de segurança;
- investigação temporal;
- grafo de incidentes;
- regras Sigma e threat intelligence;
- investigação assistida por IA;
- resposta governada e auditável;
- evidência de ações executadas por agentes.

### Perícia e cadeia de custódia

O roadmap GOV-BR adiciona uma camada forense dedicada para:

- pacote de evidência verificável;
- cadeia de custódia;
- SHA-256 + BLAKE3;
- prova de inclusão Merkle;
- carimbo do tempo;
- assinatura institucional;
- verificador offline;
- relatório técnico derivado da prova estruturada.

Esse trabalho está especificado na **SPEC-0087** e não deve ser tratado como concluído enquanto o código e os gates correspondentes não existirem.

### IA governada

O Agent Gateway e o plano de evidência de agentes permitem que chamadas de ferramentas sejam observadas, avaliadas por política, bloqueadas, aprovadas e registradas.

O objetivo não é confiar em um agente porque ele “parece inteligente”.

O objetivo é poder reconstruir:

~~~text
agent
  |
request
  |
policy decision
  |
approval
  |
tool execution
  |
result
  |
evidence
~~~

---

# O que existe hoje

Esta seção descreve capacidades presentes no código atual. O arquivo **docs/md/SPEC-new/STATUS.md** continua sendo a autoridade detalhada sobre maturidade e lacunas.

## HRKL: história canônica append-only

O HRKL é o núcleo persistente do HeraclitusDB.

A linha atual inclui:

- log append-only;
- LSN e HLC;
- CRC-32C em formatos recentes;
- raízes Merkle com BLAKE3;
- formato HRKL v6;
- modos RAW e PACKED;
- manifesto HRKM;
- índices laterais HRKI;
- migração de formatos anteriores;
- tiering e lifecycle;
- exportação para lakehouse.

O estado derivado pode ser reconstruído. A história canônica não é tratada como cache descartável.

## Consulta e analytics

O workspace inclui:

- índices de texto;
- índice vetorial;
- grafo temporal;
- atributos;
- recuperação híbrida;
- consultas temporais;
- integração analítica com Apache DataFusion;
- rota SQL;
- Arrow Flight parcial;
- Parquet, Iceberg e Delta no plano lakehouse.

O roadmap de interoperabilidade está na **SPEC-0090**.

## Replicação

O projeto inclui consenso Raft sobre openraft, com transportes TCP e gRPC, snapshots e mecanismos de fail-closed quando o cluster é configurado para exigir consenso.

Isso não elimina a necessidade de qualificação física, testes de perda de host, partição real de rede e exercícios independentes.

## Compliance e tempo confiável

O crate heraclitus-compliance já contém infraestrutura para:

- RFC 3161;
- validação CMS;
- cadeia X.509;
- EKU;
- imprint;
- nonce;
- política;
- CRLs offline;
- TrustStore configurável;
- cliente HTTPS estrito para TSA;
- Legal Hold persistente;
- crypto-shredding.

**Limite atual importante:** o repositório não distribui confiança institucional pronta. Âncoras reais ICP-Brasil devem ser instaladas e verificadas pelo operador, e a interoperabilidade com uma ACT real precisa ser qualificada externamente.

## Sentinel

O Heraclitus Sentinel reúne funções de:

~~~text
L0  normalização
L1  regras
L2  baseline
L3  correlação/grafo
L4  investigação assistida
L5  política
L6  execução governada
~~~

Threat Intelligence, TAXII/MISP e outros componentes possuem diferentes graus de implementação e integração. O STATUS.md deve ser consultado antes de qualquer claim de produção.

## Agent Evidence & Gateway

O projeto inclui:

- proxy MCP;
- modos observe, shadow e enforce;
- aprovação humana;
- proteção contra replay;
- expiração;
- binding de identidade;
- evidência persistente;
- red-team telemetry;
- barreiras contra flood e bypass lógico dentro do perímetro controlado.

Nenhuma camada de software pode impedir um agente de contornar o gateway se o operador lhe entregar credenciais e rota de rede direta para o upstream. A topologia continua fazendo parte do modelo de segurança.

---

# GOV-BR: a próxima camada de confiança

As SPECs 0086–0091 reorganizam a evolução do projeto em torno de confiança institucional.

| SPEC | Objetivo | Status |
|---|---|---|
| **SPEC-0086** | HSM/PKCS#11, KeyProvider, chaves por tenant, rotação e destruição controlada | Proposed |
| **SPEC-0087** | pacote forense e cadeia de custódia verificável | Proposed |
| **SPEC-0088** | compliance profiles as code para ambiente governamental | Proposed |
| **SPEC-0089** | protocolo administrativo fail-closed com Durable Intent | **P0 / Blocker** |
| **SPEC-0090** | PostgreSQL wire, Flight e interoperabilidade aberta | Proposed |
| **SPEC-0091** | WORM, retenção externa e Legal Hold reforçado | Proposed |

Veja o roadmap consolidado em:

**[ROADMAP-GOV-BR.md](docs/md/SPEC-new/ROADMAP-GOV-BR.md)**

---

## SPEC-0089: Trusted Administration

Esta é a prioridade arquitetural imediata.

O princípio é:

~~~text
NO DURABLE INTENT
      =>
NO PRIVILEGED SIDE EFFECT
~~~

Uma futura operação crítica deverá seguir:

~~~text
Authenticate
    |
Authorize
    |
Policy
    |
Approvals
    |
Durable AdminIntent
    |
fsync / quorum
    |
Execute
    |
Durable AdminResult
    |
Reconcile if necessary
~~~

Isso é especialmente relevante para:

- crypto-shred;
- Legal Hold;
- rotação ou destruição de chaves;
- retenção;
- exportação forense;
- mudanças críticas de configuração;
- operações administrativas destrutivas.

O objetivo é eliminar a classe de sistema que executa primeiro e tenta explicar depois.

---

## SPEC-0086: HSM e domínio criptográfico por órgão

A arquitetura proposta introduz uma fronteira KeyProvider:

~~~text
KeyProvider
   |
   +-- Software
   +-- PKCS#11 / HSM
   +-- Institutional KMS
   +-- Test Provider
~~~

Em ambientes endurecidos, chaves privadas podem permanecer não exportáveis dentro do HSM.

A separação multi-tenant prevista passa a ser criptográfica, não apenas lógica:

~~~text
Tenant A -> KEK-A -> DEKs-A
Tenant B -> KEK-B -> DEKs-B
Tenant C -> KEK-C -> DEKs-C
~~~

A indisponibilidade de um HSM exigido pela política deve falhar fechado, sem fallback silencioso para arquivo local.

---

## SPEC-0087: evidência que sai do banco ainda sendo verificável

O objetivo do plano forense é produzir um pacote semelhante a:

~~~text
EvidencePackage/
├── manifest.json
├── evidence/
├── provenance/
├── proofs/
├── certificates/
├── sbom/
└── report/
~~~

O manifesto estruturado é a autoridade. PDF é apresentação.

O verificador deve conseguir determinar offline:

~~~text
PACKAGE STRUCTURE      PASS
OBJECT DIGESTS         PASS
CUSTODY CHAIN          PASS
MERKLE PROOF           PASS
TIMESTAMP              VERIFIED / UNVERIFIED
SIGNATURE              VERIFIED / UNVERIFIED
OVERALL TECHNICAL      VERIFIED / PARTIAL / FAILED
~~~

Ausência de confiança externa nunca deve virar PASS por entusiasmo.

---

## SPEC-0088: compliance como evidência, não como selo

O HeraclitusDB não deve afirmar simplesmente:

~~~text
COMPLIANT = true
~~~

O modelo proposto trabalha controle por controle:

~~~text
PASS
FAIL
PARTIAL
NOT_APPLICABLE
EXTERNAL
UNKNOWN
NOT_ASSESSED
~~~

Perfis governamentais poderão mapear requisitos como LGPD, PPSI, GSI, ICP-Brasil e regras internas do órgão.

Cada PASS automatizado deve apontar para evidência concreta de build, teste, configuração ou qualificação.

Processos que dependem do operador, da organização ou de laboratório externo continuam explicitamente marcados como tais.

---

## SPEC-0091: Legal Hold além do próprio processo

Nenhum programa executando no mesmo host consegue prometer honestamente resistência absoluta ao administrador que controla kernel, disco, binário e configuração.

Por isso o roadmap prevê uma fronteira externa:

~~~text
Heraclitus Legal Hold
        +
Immutable Store
        +
WORM / Object Retention
        +
separate credentials
        +
receipts
        +
external verification
~~~

Isso permite distinguir:

- imutabilidade lógica;
- retenção física externa;
- verificação da retenção;
- qualificação do ambiente.

---

# Interoperabilidade

O HeraclitusDB não quer exigir que cada órgão adote um ecossistema proprietário para consultar seus próprios dados.

A estratégia é priorizar protocolos e formatos abertos:

~~~text
HeraclitusDB
   |
   +-- Native API
   +-- gRPC
   +-- Arrow Flight
   +-- PostgreSQL wire         [roadmap]
   +-- Parquet
   +-- Iceberg
   +-- Delta
~~~

Ferramentas como Power BI, DBeaver, Superset, Trino e plataformas analíticas devem preferencialmente chegar pelos protocolos comuns, sem colocar SDKs específicos de cada fornecedor dentro do core.

---

# Arquitetura do workspace

O workspace Rust 3.0.1 é dividido em crates especializados.

~~~text
heraclitus-core              tipos, runtime e tempo lógico
heraclitus-log               HRKL, persistência e integridade
heraclitus-crypto            criptografia
heraclitus-compliance        confiança, recibos, TSA e retenção
heraclitus-memtable          estado recente
heraclitus-views             materializações
heraclitus-index-vector      índice vetorial
heraclitus-index-graph       grafo temporal
heraclitus-index-text        recuperação textual
heraclitus-index-attr        atributos
heraclitus-retrieval         fusão de recuperação
heraclitus-query             camada de consulta
heraclitus-analytics         DataFusion e analytics
heraclitus-raft              consenso e replicação
heraclitus-gpu               aceleração
heraclitus-agent             governança de agentes
heraclitus-agent-gateway     policy gateway
heraclitus-sentinel          segurança e investigação
heraclitus-case              casos
heraclitus-content           conteúdo e playbooks
heraclitus-platform          superfície integrada
hume-kernel / hume-ir        infraestrutura experimental HUME
~~~

A lista canônica está em [Cargo.toml](Cargo.toml).

---

# Modelo de implantação

~~~text
                  SISTEMAS DO ÓRGÃO
                        |
         +--------------+--------------+
         |              |              |
        APIs           Logs          Events
         |              |              |
         +--------------+--------------+
                        |
                        v
                +----------------+
                |  HeraclitusDB  |
                +----------------+
                        |
         +--------------+--------------+
         |              |              |
         v              v              v
      AUDIT          SECURITY       ANALYTICS
         |              |              |
         +--------------+--------------+
                        |
                        v
                 TRUST / EVIDENCE
                        |
           +------------+------------+
           |                         |
           v                         v
    Internal Verification      External Evidence
                               ACT / HSM / WORM
                               when configured
~~~

O projeto prioriza:

- on-premises;
- redes segmentadas;
- ambientes sem Internet;
- operação soberana;
- reconstrução determinística;
- evidência local verificável;
- dependências externas explícitas em vez de escondidas.

---

# Casos de uso institucionais possíveis

O HeraclitusDB é especialmente adequado para avaliação em cenários onde **a história importa tanto quanto o estado atual**:

- trilhas de auditoria de sistemas administrativos;
- custódia de eventos e evidências digitais;
- controle interno e corregedoria;
- segurança cibernética;
- investigação de fraude;
- registros de agentes de IA;
- processos com necessidade de reconstrução temporal;
- preservação de logs de infraestrutura crítica;
- integração lakehouse onde o dado canônico precisa permanecer verificável.

Cada caso exige análise jurídica, de segurança, privacidade e arquitetura do órgão. A existência da tecnologia não decide sozinha se aquele uso é permitido.

---

# Maturidade: linguagem de claims

O projeto adota cinco níveis conceituais:

~~~text
DESIGNED
IMPLEMENTED
TESTED
QUALIFIED
EXTERNALLY ATTESTED
~~~

Eles não são sinônimos.

Exemplos:

- uma SPEC escrita está DESIGNED, não IMPLEMENTED;
- código com testes pode estar TESTED, mas não QUALIFIED;
- suporte PKCS#11 não significa HSM homologado;
- RFC 3161 implementado não significa ACT real qualificada;
- Legal Hold lógico não significa WORM físico;
- perfil PPSI não significa órgão conforme;
- pacote forense não garante admissibilidade judicial.

Essa distinção é parte do produto, não uma nota de rodapé.

---

# Início rápido

~~~bash
git clone https://github.com/JoseRFJuniorLLMs/HeraclitusDB.git
cd HeraclitusDB
cargo build --release
~~~

Documentação de início:

- [Quickstart](docs/getting-started/quickstart.md)
- [Deployment](docs/wiki/DEPLOYMENT.md)
- [Operations](docs/wiki/OPERATIONS.md)

---

# Documentação

| Documento | Conteúdo |
|---|---|
| **[Wiki Home](docs/wiki/Home.md)** | visão executiva |
| **[Government](docs/wiki/GOVERNMENT.md)** | soberania e setor público |
| **[Architecture](docs/wiki/ARCHITECTURE.md)** | arquitetura |
| **[Security & Compliance](docs/wiki/SECURITY-COMPLIANCE.md)** | controles e evidência |
| **[Deployment](docs/wiki/DEPLOYMENT.md)** | implantação |
| **[Operations](docs/wiki/OPERATIONS.md)** | operação e runbooks |
| **[Roadmap](docs/wiki/ROADMAP.md)** | evolução |
| **[ROADMAP-GOV-BR](docs/md/SPEC-new/ROADMAP-GOV-BR.md)** | confiança, evidência e interoperabilidade |
| **[SPEC-STATUS](docs/md/SPEC-new/STATUS.md)** | estado real das especificações |
| **[SPEC-RESUMO](docs/md/SPEC-new/SPEC-RESUMO.md)** | inventário verificado |
| **[Production blockers](docs/BLOQUEIOS-PRODUCAO.md)** | bloqueios conhecidos |
| **[Qualification](docs/qualification/)** | provas e gates |
| **[Security](docs/security/)** | segurança e vulnerabilidades |

---

# GOV-BR Specs

- [SPEC-0046 — Government Compliance](docs/md/SPEC-new/SPEC-0046.md)
- [SPEC-0048 — Orchestrator & Forensic Evidence Plane](docs/md/SPEC-new/SPEC-0048.md)
- [SPEC-0049 — Production & Security Qualification](docs/md/SPEC-new/SPEC-0049.md)
- [SPEC-0050 — HRKL](docs/md/SPEC-new/SPEC-0050-HRKL.md)
- [SPEC-0086 — Government Trust & Key Management](docs/md/SPEC-new/SPEC-0086-Government-Trust-Key-Management.md)
- [SPEC-0087 — Forensic Evidence & Chain of Custody](docs/md/SPEC-new/SPEC-0087-Forensic-Evidence-Chain-of-Custody.md)
- [SPEC-0088 — Government Compliance Profiles](docs/md/SPEC-new/SPEC-0088-Government-Compliance-Profiles.md)
- [SPEC-0089 — Trusted Administration Protocol](docs/md/SPEC-new/SPEC-0089-Trusted-Administration-Protocol.md)
- [SPEC-0090 — Government Interoperability](docs/md/SPEC-new/SPEC-0090-Government-Interoperability.md)
- [SPEC-0091 — Immutable External Storage & Legal Hold](docs/md/SPEC-new/SPEC-0091-Immutable-External-Storage-Legal-Hold.md)

---

# Segurança

Relatos de vulnerabilidade devem seguir:

[docs/security/vulnerability-response.md](docs/security/vulnerability-response.md)

Evite divulgar publicamente detalhes exploráveis antes da coordenação da correção.

---

# Licença

O workspace declara licença **BUSL-1.1**.

Consulte [LICENSE](LICENSE) para os termos completos.

---

# Autoria e citação

Consulte [CITATION.cff](CITATION.cff).

---

<p align="center">
  <strong>HeraclitusDB</strong><br/>
  Preserve o fato. Prove a história. Controle a ação.
</p>
