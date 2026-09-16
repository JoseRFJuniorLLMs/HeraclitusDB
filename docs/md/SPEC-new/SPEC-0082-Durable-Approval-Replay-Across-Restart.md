# SPEC-0082 — Durable Approval Replay Across Restart

**Status:** IMPLEMENTED / QUALIFICATION REQUIRED

## Achado reproduzido em sandbox
Uma ação `send_payment` foi aprovada, executada uma vez e corretamente recusada como `APPROVAL_REPLAYED` antes do restart. Depois de reiniciar o mesmo binário com o mesmo diretório HRKL, o mesmo request lógico voltou a `202 APPROVAL_PENDING`, porque `AgentRuntime::warm()` reconstruía dedupe mas aquecia `ApprovalStore` com lista vazia. Uma nova aprovação humana poderia portanto autorizar novamente a mesma operação lógica.

## Invariantes
- `ToolAuthorized` persistido é o commit durável de que o approval foi consumido.
- No arranque, o Gateway reconstrói um ledger `(authorization_subject_hash -> approval_id)` a partir de `ToolAuthorized`.
- O mesmo subject após restart retorna `APPROVAL_REPLAYED`, sem novo approval e sem upstream.
- Uma operação logicamente nova continua possível porque `request_id` faz parte do subject hash.
- Em `ENFORCE`, se `ToolAuthorized` não puder ser gravado, a chamada externa não acontece. É preferível consumir uma aprovação sem efeito externo e exigir recuperação manual a executar sem commit durável de autorização.

## Limite deliberado
Aprovação concedida mas ainda não consumida não é automaticamente restaurada como grant após crash. Ela deve voltar a exigir decisão humana. Isso é fail-closed.

## Gates
- unit: subject consumido reconstruído continua `AlreadyUsed`;
- gateway E2E completo;
- clippy deny warnings;
- live sandbox: approve -> execute once -> restart -> exact retry = 403 `APPROVAL_REPLAYED`, upstream delta 0.
