# SPEC-0081 — Approval Pending Idempotency

**Status:** IMPLEMENTED / QUALIFIED

## Achado
Em campanha massiva repetida, o mesmo request lógico ainda pendente era corretamente reconhecido pelo `ApprovalStore`, porém o Gateway caía no ramo genérico e respondia HTTP 403 `APPROVAL_PENDING`. Isso preservava segurança, mas quebrava idempotência e confundia espera legítima com recusa.

## Contrato
- primeiro pedido que exige aprovação: `202 APPROVAL_PENDING`;
- retry exato enquanto continua pendente: o mesmo `202`, mesmo `approval_id`, zero efeito upstream e nenhuma segunda aprovação;
- após grant: exatamente uma execução;
- após consumo: replay continua 403;
- argumentos/agent/request diferentes continuam sujeitos ao binding normal.

A correção é fail-closed se o índice disser `Pending` mas o registro desaparecer antes de construir a resposta.
