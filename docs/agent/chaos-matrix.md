# Matriz de caos — o que fica ambíguo, e o que não fica

SPEC-0075 §33 e SPEC-0074 §24.

> Para cada cenário, documentar estado externo possível.

Um gateway que autoriza acções com efeito no mundo tem de dizer, por extenso, o
que acontece se morrer a meio. Fingir que não morre é pior do que morrer.

A regra que governa a tabela toda: **a evidência é append-only, e o que não
chegou ao log não aconteceu para o produto.** A ambiguidade que sobra é a do
sistema externo, não a do histórico.

---

## Falhas do gateway

| # | O processo morre… | Evidência no HRKL | Estado externo | Depois do reinício |
|---:|---|---|---|---|
| 1 | depois de avaliar a policy, antes do append | nada | **nada aconteceu** | o agente repete; a policy reavalia, deterministicamente, para a mesma decisão |
| 2 | depois do append de `ToolRequested`/`PolicyEvaluated`, antes do upstream | pedido e decisão registados, sem execução | **nada aconteceu** | a timeline mostra um pedido sem resultado; o retry do agente é deduplicado por `tool_call_id` |
| 3 | depois da resposta do upstream, antes do append do resultado | pedido e decisão registados, sem resultado | **a acção EXECUTOU** | ambíguo por natureza: a timeline mostra a lacuna, e o `external_effect_id` do upstream é a única reconciliação possível |
| 4 | com uma aprovação pendente | `HumanApprovalRequested` registado | nada aconteceu | a aprovação volta a aparecer na caixa de entrada quando for repedida; o pedido antigo expira |
| 5 | depois de a aprovação ser concedida, antes de ser consumida | `HumanApprovalGranted` registado | nada aconteceu | **a aprovação volta a ficar pendente** — ver abaixo |
| 6 | a meio de um append (SIGKILL) | o HRKL recupera a cauda; um registo não confirmado não existe | conforme 1–3 | `verify` fecha contra a raiz; nenhuma prova aponta para registo não durável |

### O caso 5, por extenso

O registo de aprovações é um índice em memória reconstruído do log no arranque.
O log tem `HumanApprovalGranted`; **não** tem "consumida" — esse facto só existe
depois de a execução acontecer. Reconstruir "concedida" a partir do log
reabriria a janela de reutilização que a §15.3 fecha.

Portanto o reinício volta a pedir a aprovação. É o lado seguro: pedir duas vezes
incomoda uma pessoa; executar duas vezes move dinheiro.

### O caso 3, por extenso

É o único caso genuinamente ambíguo, e é ambíguo em qualquer sistema que fale
com um sistema externo que não prove idempotência. O que o produto faz:

1. `ToolInvocationStarted` está no log, `ToolInvocationFinished` não.
2. A Consola mostra a tool call como **incompleta** (`complete: false`).
3. Se o upstream devolveu um identificador de efeito antes da falha, ele não
   chegou ao log — a reconciliação tem de ser feita contra o sistema externo.

O que o produto **não** faz: inventar um resultado, nem marcar a chamada como
bem-sucedida por o upstream ter respondido `200` a alguém que já não existe.

---

## Retransmissão e duplicação

| # | Cenário | Resultado |
|---:|---|---|
| 7 | o exporter OTel retransmite o mesmo lote | descartado em silêncio; `agent_ingest_duplicates_total` sobe |
| 8 | o exporter retransmite depois de o Heraclitus reiniciar | idem — o índice é reconstruído do log no arranque |
| 9 | duas evidências diferentes com a mesma chave lógica | **recusado explicitamente**; `agent_ingest_conflicts_total` sobe |
| 10 | o agente repete a mesma tool call com os mesmos argumentos | não cria segunda aprovação; a aprovação existente aplica-se |
| 11 | o agente repete com argumentos **diferentes** | `APPROVAL_BINDING_MISMATCH`, ou uma aprovação nova — nunca a antiga |

O caso 9 é o que distingue deduplicação de sobrescrita. Silenciá-lo permitiria a
alguém reescrever evidência já registada reutilizando o par trace/span.

---

## Falhas do upstream

| # | Cenário | HTTP devolvido | Evidência |
|---:|---|---:|---|
| 12 | upstream em baixo | 502 | `ErrorObserved` com `MCP_UPSTREAM_UNAVAILABLE` |
| 13 | upstream demora mais do que o timeout | 502 | idem; **o estado externo é ambíguo** — o pedido pode ter chegado |
| 14 | upstream devolve `isError: true` | o status do upstream | `ToolInvocationFinished` com `protocol_status: "error"` |
| 15 | upstream devolve mais bytes do que o tecto | 502 | `ErrorObserved`; a resposta não é persistida |

O 13 é o 3 com outra causa. Um timeout **não** é prova de que nada aconteceu.

---

## Falhas de policy e de identidade

| # | Cenário | Decisão |
|---:|---|---|
| 16 | o ficheiro de policy desapareceu no arranque | o servidor **recusa arrancar** com o caminho configurado inválido |
| 17 | a policy activa é inválida ao recarregar pela API | a activação falha; **a anterior continua activa** |
| 18 | não há policy configurada | `deny` — o documento vazio nega tudo |
| 19 | o JWKS não abre em produção | o servidor recusa arrancar; sem chaves não há validação |
| 20 | o token expirou entre a avaliação e a execução | a autorização expira com ele; `APPROVAL_EXPIRED` |

Nenhuma linha desta tabela tem `allow` como resposta a uma falha. É o §2.2
escrito em casos concretos.

---

## O que não é prometido

**Exactly-once sobre sistemas externos.** Os casos 3 e 13 não têm solução do
lado do gateway. O que existe é:

- um `action_request_id` estável, para o upstream poder deduplicar se souber;
- um `external_effect_id` por allowlist, para reconciliar depois;
- uma timeline que mostra a lacuna em vez de a fechar com um palpite.

Um produto que prometesse exactly-once aqui estaria a prometer uma coisa que
depende inteiramente do sistema do outro lado.

---

## Como testar

Os cenários 1–3, 7–11 e 12–20 têm cobertura automática:

```bash
cargo test -p heraclitus-agent --test evidence_end_to_end
cargo test -p heraclitus-agent-gateway --test gateway_end_to_end
cargo test -p heraclitus-agent-gateway --test quickstart_otlp
```

O cenário 6 (SIGKILL a meio de um append) é coberto pelo gate de injecção de
crash do próprio HRKL, que é onde a garantia vive:

```bash
CRASH_ITERS=1000 cargo test -p heraclitus-log --test crash_injection -- --nocapture
```
