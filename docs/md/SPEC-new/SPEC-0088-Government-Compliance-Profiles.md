# SPEC-0088 — Government Compliance Profiles as Code

**Status:** Draft / Proposed  
**Data:** 18/09/2026  
**Classe:** Government Compliance / Controls as Code / Privacy / Security  
**Prioridade:** P0/P1  
**Dependências:** SPEC-0046, SPEC-0049  
**Alvos:** heraclitus-compliance, heraclitus-platform, Dashboard  
**Princípio:** *Compliance não é um booleano. É um conjunto versionado de controles, evidências, exceções e responsabilidades.*

---

## 0. Decisão arquitetural

O HeraclitusDB não deve exibir selo genérico COMPLIANT.

Deve exibir, por controle:

~~~text
PASS
FAIL
PARTIAL
NOT_APPLICABLE
EXTERNAL
UNKNOWN
NOT_ASSESSED
~~~

Esta SPEC complementa a SPEC-0046 com perfis versionados e evidência de implementação.

## 1. Referenciais iniciais

O perfil gov-br deve permitir mapear, sem congelar a legislação no código:

- LGPD — Lei 13.709/2018;
- PPSI 2.0, instituído pela Portaria SGD/MGI 9.511/2025, em vigor desde 01/01/2026;
- ciclo PPSI 2026, conforme IN SGD/MGI 4/2026;
- estrutura de gestão de SI da IN GSI/PR 1/2020, considerando alterações posteriores, inclusive IN GSI/PR 9/2026;
- Política Nacional de Segurança da Informação e normativos vigentes aplicáveis;
- Decreto 10.046/2019 quando aplicável à governança/compartilhamento de dados;
- documentos ICP-Brasil aplicáveis;
- controles internos e política do órgão.

Referências mudam. Por isso o perfil é dado versionado, não enum Rust eterna.

## 2. ComplianceProfile

~~~rust
pub struct ComplianceProfile {
    pub id: String,
    pub version: String,
    pub effective_from: String,
    pub source_refs: Vec<NormativeReference>,
    pub controls: Vec<ControlDefinition>,
    pub digest: [u8; 32],
}
~~~

## 3. ControlDefinition

~~~rust
pub struct ControlDefinition {
    pub control_id: String,
    pub title: String,
    pub requirement: String,
    pub responsibility: Responsibility,
    pub evidence_requirements: Vec<EvidenceRequirement>,
    pub automated_checks: Vec<CheckRef>,
}
~~~

Responsibility:

~~~text
SOFTWARE
OPERATOR
ORGANIZATION
EXTERNAL_LAB
SHARED
~~~

Isso impede o banco de assumir crédito por processo organizacional que ele não controla.

## 4. EvidenceBinding

Todo PASS automatizado deve apontar para evidência.

Exemplos:

~~~text
control: AUDIT-FAIL-CLOSED
evidence:
  test: admin_op_refuses_when_audit_unavailable
  build_sha: ...
  artifact_digest: ...
  qualifier_run: ...
~~~

Controle sem evidência = NOT_ASSESSED ou UNKNOWN, nunca PASS decorativo.

## 5. Perfis

Estrutura sugerida:

~~~text
compliance/profiles/
├── gov-br-base/
├── ppsi-2.0/
├── lgpd/
├── icp-brasil/
└── organization/
~~~

Perfis podem compor-se, mas conflitos devem ser explícitos.

## 6. Classificação de dados

O motor de política deve suportar classes configuráveis.

Preset inicial pode representar:

~~~text
PUBLIC
INTERNAL
RESTRICTED
SPECIFIC
PERSONAL
SENSITIVE_PERSONAL
CLASSIFIED_EXTERNAL_POLICY
~~~

Os nomes legais exatos pertencem ao perfil/política do órgão. O core trabalha com tags e regras.

## 7. Políticas executáveis

Exemplos:

~~~yaml
control_id: GOV-DATA-EXPORT-001
when:
  classification: SPECIFIC
action: export
require:
  - authenticated_principal
  - purpose
  - approval
  - audit_intent
deny_if:
  - legal_hold_conflict
~~~

Política MUST produzir decisão explicável:

~~~text
ALLOW because controls X,Y satisfied
DENY because approval Z absent
~~~

## 8. Privacidade

Capacidades de plataforma:

- field classification;
- pseudonymization;
- tokenization;
- field-level encryption;
- redaction;
- retention policy;
- purpose metadata;
- access audit;
- crypto-shredding quando juridicamente aplicável.

O software não deve declarar anonimização irreversível sem método e avaliação específica.

## 9. PPSI 2.0

Criar perfil versionado separado.

O perfil não deve copiar o texto integral de normas para o repositório. Deve mapear identificadores, requisitos técnicos e evidências.

Atualização do PPSI gera nova versão do perfil, preservando a versão anterior para auditoria histórica.

## 10. Dashboard

Tela mínima:

~~~text
Profile: gov-br / ppsi-2.0@2026.1

PASS             34
PARTIAL           7
EXTERNAL          9
UNKNOWN           2
FAIL              1

Control                 Status       Evidence
AUDIT-001               PASS         Q-2026-0918-...
HSM-001                 EXTERNAL     lab required
DR-003                  UNKNOWN      no exercise attached
~~~

Proibido converter EXTERNAL em PASS.

## 11. Evidence snapshot

Uma avaliação de compliance deve ser congelável:

~~~text
ComplianceAssessment
- profile digest
- config digest
- build digest
- test/qualifier digest
- timestamp
- results
- exceptions
~~~

Isso permite provar o que significava compliance na data da avaliação.

## 12. Exceções

ExceptionRecord:

- control;
- justificativa;
- autoridade;
- prazo;
- risco aceito;
- compensating controls;
- assinatura;
- expiração.

Exceção vencida muda o controle para FAIL/UNKNOWN conforme política. Não permanece verde eternamente.

## 13. Testes

1. perfil adulterado falha digest;
2. PASS sem evidência é recusado;
3. perfil novo não altera avaliação histórica;
4. EXTERNAL nunca é promovido automaticamente;
5. exceção expirada deixa de satisfazer controle;
6. política conflitante falha fechada;
7. classificação acompanha export;
8. redaction é auditada;
9. configuração diferente produz assessment digest diferente.

## 14. Definition of Done

- schema versionado;
- loader assinado/digestado;
- gov-br-base;
- ppsi-2.0 inicial;
- integração com qualifier;
- dashboard de evidência;
- export de assessment;
- teste de upgrade de perfil;
- documentação clara: software evidence != certificação institucional.
