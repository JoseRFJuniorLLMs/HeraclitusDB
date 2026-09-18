# SPEC-0089 — Trusted Administration Protocol

**Status:** Draft / Proposed  
**Data:** 18/09/2026  
**Classe:** Administrative Security / Fail-Closed Audit / Two-Phase Intent  
**Prioridade:** P0 — BLOCKER  
**Dependências:** SPEC-0050-HRKL, SPEC-0074 a SPEC-0085, SPEC-0086  
**Alvos:** heraclitus-server, heraclitus-log, heraclitus-compliance  
**Princípio:** *Uma operação privilegiada não pode produzir efeito irreversível antes de existir evidência durável da intenção autorizada.*

---

## 0. Motivação

O código atual possui operações em que a auditoria é best-effort e o erro de append pode ser descartado.

Para query isso pode ser uma decisão operacional.

Para operação administrativa destrutiva, não pode.

Esta SPEC cria um único caminho autoritativo para administração privilegiada.

## 1. Invariante central

~~~text
NO DURABLE INTENT
      =>
NO PRIVILEGED SIDE EFFECT
~~~

E, quando a ação termina:

~~~text
SIDE EFFECT
      =>
DURABLE RESULT OR RECOVERABLE UNKNOWN
~~~

## 2. Operações abrangidas

No mínimo:

- crypto-shred;
- criação/remoção de Legal Hold;
- rotação/destruição de chaves;
- alteração de política de retenção;
- alteração de provider de chave;
- exportação forense privilegiada;
- mudança de configuração de segurança;
- promoção de nó/ação de cluster quando classificada como crítica;
- aprovação humana de ação irreversível;
- purge/GC administrativo fora da rotina normal.

## 3. API única

~~~rust
pub fn execute_admin<T>(
    &self,
    ctx: AdminContext,
    op: AdminOperation,
    f: impl FnOnce(&AdminExecutionToken) -> Result<T, AdminError>,
) -> Result<AdminOutcome<T>, AdminError>
~~~

Chamadores NÃO devem poder invocar implementação destrutiva diretamente sem token interno não construível externamente.

## 4. Fases

### Fase 1 — Validate

- autenticação;
- autorização;
- tenant;
- policy;
- Legal Hold;
- approvals;
- idempotency key;
- resource budget;
- preconditions.

Nenhum side effect.

### Fase 2 — Durable Intent

Persistir AdminIntent contendo:

~~~text
operation_id
principal
tenant
operation kind
target digest
parameters digest
reason
policy decision
approval refs
idempotency key
expected pre-state
~~~

A persistência deve satisfazer a durability policy aplicável: fsync local e/ou quorum.

### Fase 3 — Execute

Somente após DurableIntent confirmado.

### Fase 4 — Durable Result

Persistir:

~~~text
AdminResult
operation_id
status
post-state digest
provider receipts
error class
completed_at
~~~

## 5. Estados

~~~text
PROPOSED
AUTHORIZED
INTENT_DURABLE
EXECUTING
SUCCEEDED
FAILED
UNKNOWN
RECONCILED
~~~

UNKNOWN é válido e preferível a inventar sucesso depois de crash.

## 6. Crash recovery

No boot, operações INTENT_DURABLE sem Result entram no reconciler.

O reconciler:

1. verifica o estado real do alvo;
2. consulta provider externo se aplicável;
3. decide FAILED, SUCCEEDED ou UNKNOWN;
4. grava ReconciliationResult.

Nunca reexecutar operação não idempotente apenas porque o resultado está ausente.

## 7. Idempotência

AdminOperation MUST possuir operation_id e idempotency_key.

Repetir a mesma chave:

- mesmo digest → retorna estado existente;
- digest diferente → conflito e DENY.

## 8. Auditoria de query

audit_query pode permanecer best-effort se política assim definir, mas:

- falha deve gerar métrica;
- deve emitir warning estruturado;
- não pode compartilhar semântica com admin critical audit.

Separar claramente:

~~~text
AuditClass::OperationalQuery
AuditClass::PrivilegedAdmin
AuditClass::SecurityEvidence
~~~

## 9. Four-eyes

Operações podem declarar:

~~~rust
ApprovalPolicy {
    min_distinct_approvers: 2,
    requester_may_approve: false,
    required_roles: [...]
}
~~~

A aprovação liga-se ao digest de AdminIntent.

Alterar qualquer parâmetro invalida aprovação.

## 10. Quorum e Raft

Em cluster:

- intenção crítica deve respeitar o modo de durabilidade configurado;
- perda de quorum antes de Intent → DENY;
- perda após Intent e antes de Result → UNKNOWN/reconcile;
- nó isolado não pode executar operação que exige quorum.

## 11. Backpressure

Disco cheio, erro de I/O ou backlog crítico:

~~~text
critical admin action => DENY
~~~

A API retorna razão auditável. Não tenta salvar “depois”.

## 12. Resource budgeting

Antes de execução:

- limite de tamanho de request;
- timeout;
- custo estimado;
- max result bytes;
- max traversal/query k quando a operação envolve consulta;
- limite de concorrência por principal/tenant.

Isso impede que canal administrativo vire superfície trivial de OOM/DoS.

## 13. Testes obrigatórios

1. disco de auditoria indisponível → shred NÃO executa;
2. falha de quorum → hold removal NÃO executa;
3. crash após Intent antes do side effect;
4. crash durante side effect;
5. crash após side effect antes do Result;
6. replay idempotente;
7. mesma idempotency key com parâmetros diferentes → DENY;
8. aprovação para digest A não vale para digest B;
9. requester não conta como segundo aprovador;
10. Result append falha → estado UNKNOWN e reconciler;
11. teste concorrente 128-way;
12. teste de disco cheio/fault injection;
13. nenhum endpoint admin contorna execute_admin.

## 14. Migração

Etapa 1: criar API e testes.

Etapa 2: migrar shred e Legal Hold.

Etapa 3: migrar key rotation, retention, exports.

Etapa 4: tornar funções destrutivas internas/private.

Etapa 5: gate estático/grep no CI para impedir novos chamadores proibidos.

## 15. Definition of Done

- audit_admin best-effort não é autoridade para ação crítica;
- todas as operações listadas usam execute_admin;
- durable intent precede efeito;
- crash recovery/reconciler;
- idempotência;
- four-eyes;
- fault injection;
- cluster/quorum tests;
- documentação operacional;
- qualifier possui cenário específico.
