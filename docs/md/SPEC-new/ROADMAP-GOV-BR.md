# HeraclitusDB GOV-BR — Roadmap de Confiança, Evidência e Interoperabilidade

**Data:** 18/09/2026  
**Status:** Roadmap arquitetural — não representa implementação concluída

Este documento organiza as SPECs existentes e novas numa única história de produto: uma plataforma soberana de dados, evidência, auditoria e segurança voltada a ambientes públicos e regulados.

## 1. O que já existe como fundação

- SPEC-0046 — Government Compliance Plane;
- SPEC-0048 — Orchestrator & Forensic Evidence Plane;
- SPEC-0049 — qualificação e provas de produção;
- SPEC-0050-HRKL — log, integridade, tiering e lifecycle;
- SPEC-0074 a 0085 — Agent Evidence, approvals, MCP e barreiras adversariais.

Esses documentos não significam que todos os seus itens estejam implementados. STATUS.md continua sendo a autoridade sobre estado real.

## 2. Novas SPECs

| SPEC | Tema | Prioridade | Resultado esperado |
|---|---|---:|---|
| 0086 | Government Trust & Key Management | P0 | HSM/PKCS#11, chaves por tenant, rotação e destruição controlada |
| 0087 | Forensic Evidence & Chain of Custody | P0 | pacote forense verificável, custódia, Merkle, SHA-256/BLAKE3, assinatura |
| 0088 | Government Compliance Profiles as Code | P0/P1 | PPSI/GSI/LGPD e perfis versionados com evidência |
| 0089 | Trusted Administration Protocol | P0 BLOCKER | durable intent antes de operação privilegiada, fail-closed e reconcile |
| 0090 | Government Interoperability | P1 | PostgreSQL wire, Flight, formatos abertos, BI sem plugins no core |
| 0091 | Immutable External Storage & Legal Hold | P1 | WORM/object retention, receipts e fronteira externa de imutabilidade |

## 3. Ordem recomendada de implementação

~~~text
0089 Trusted Administration
        |
        +--> 0086 Key Management / HSM
        |         |
        |         +--> 0087 Forensic Evidence
        |
        +--> 0091 WORM / Legal Hold

0046 Compliance ----------------> 0088 Profiles as Code

0037/0042/0050 -----------------> 0090 Interoperability
~~~

### Fase A — confiança administrativa
1. SPEC-0089;
2. migrar shred e Legal Hold;
3. fault injection e crash recovery.

### Fase B — chaves
1. SPEC-0086;
2. SoftwareKeyProvider;
3. SoftHSM/PKCS#11;
4. HSM real em laboratório;
5. tenant key domains.

### Fase C — evidência
1. SPEC-0087;
2. heraclitus-forensic;
3. pacote offline;
4. verifier;
5. timestamp/assinatura;
6. relatório.

### Fase D — retenção forte
1. SPEC-0091;
2. modelar cold locations no HRKM;
3. backend immutable;
4. receipts;
5. qualificação.

### Fase E — compliance e integração
1. SPEC-0088;
2. perfis gov-br;
3. SPEC-0090;
4. pgwire;
5. Flight;
6. BI/lakehouse.

## 4. Claims de produto permitidos somente por evidência

O projeto deve distinguir:

~~~text
DESIGNED
IMPLEMENTED
TESTED
QUALIFIED
EXTERNALLY ATTESTED
~~~

Exemplos:

- possuir parser PKCS#11 não significa HSM qualificado;
- possuir RFC 3161 não significa interoperabilidade provada com ACT real;
- possuir Legal Hold lógico não significa proteção contra root;
- possuir mapeamento PPSI não significa órgão conforme;
- possuir pacote forense não garante admissibilidade judicial.

## 5. Meta de produto

O objetivo não é substituir PostgreSQL, SIEMs, sistemas de processo ou ferramentas periciais em todas as funções.

O posicionamento técnico é uma camada de confiança capaz de:

~~~text
INGEST
  |
PRESERVE
  |
PROVE
  |
CONTROL
  |
AUDIT
  |
EXPORT VERIFIABLE EVIDENCE
~~~

Sistemas de negócio continuam a existir. HeraclitusDB oferece o plano de integridade, evidência e observabilidade verificável.

## 6. Gate de uma futura linha GOV

Uma distribuição/perfil GOV só deve ser anunciada como tal quando, no mínimo:

- operações críticas passarem pela SPEC-0089;
- chave de produção puder usar provider não exportável;
- pacote forense possuir verifier independente;
- perfis de compliance mostrarem UNKNOWN/EXTERNAL honestamente;
- Legal Hold tiver semântica externa quando configurado;
- qualifier publicar artefatos reproduzíveis;
- gates físicos/externos continuarem declarados UNQUALIFIED enquanto não executados.

O produto ganha credibilidade precisamente quando se recusa a transformar documentação em certificação imaginária.
