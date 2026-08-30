# Resposta a incidente

Suspeita de comprometimento, corrupção, ou perda de dados reconhecidos como
duráveis. Este runbook decide o que fazer nos primeiros minutos, quando ainda é
possível estragar a prova.

## Regra que domina os primeiros cinco minutos

**Não repare antes de preservar.**

O instinto é reconstruir o índice, reiniciar o serviço, apagar o segmento
corrompido. Cada uma dessas ações destrói prova. Num sistema cuja proposta é
produzir evidência jurídica, destruir prova durante a resposta é o pior
resultado possível — pior do que o incidente.

Ordem: **DETETAR → ISOLAR → REPORTAR → recuperar ou falhar fechado** (§29).

## Classificar antes de agir

| sinal | classe | ação imediata |
|---|---|---|
| `heraclitus verify` falha num segmento selado | corrupção canónica | isolar; **não** reconstruir |
| `storage doctor` acusa índice inconsistente | estado derivado | reconstruível; ver abaixo |
| evento reconhecido como durável ausente após restart | **perda silenciosa** | pior classe; ver abaixo |
| dois líderes / histórias divergentes | split brain | parar escritas em todos os nós |
| acesso não autorizado nos registos de auditoria | comprometimento | preservar e rodar credenciais |
| `verify-receipts` falha | cadeia de compliance | preservar; a raiz antiga pode estar carimbada |

## Corrupção de estado derivado

O caso benigno. Enquanto a fonte canónica estiver íntegra, todo o estado
derivado é reconstruível (PQ4):

```bash
heraclitus verify $DATA --logical      # PRIMEIRO: a fonte está íntegra?
heraclitus rebuild-index $DATA         # só se a linha acima passou   # ESCREVE
```

A ordem não é negociável. Reconstruir índices a partir de um log corrompido
produz um índice *consistente* com dados errados — e apaga o sintoma que
permitia detetá-lo.

## Corrupção da fonte canónica

Aqui não se reconstrói nada localmente.

1. **Parar a progressão.** Pare escritas nesse nó. Um log canónico corrompido
   que continua a crescer enterra a fronteira do dano.
2. **Identificar o intervalo afetado:**
   ```bash
   heraclitus log-inspect $DATA
   heraclitus verify $DATA --logical
   heraclitus inspect <segmento>
   ```
3. **Reportar integridade falhada** — não engula o erro num retry.
4. **Recuperar de réplica ou backup**, nunca reconstruindo os bytes em falta.
   Nunca fabrique evidência que não existe: um evento reconstruído "porque
   devia estar lá" é falso, e num contexto forense é pior do que uma lacuna
   assumida.

## Perda silenciosa de dados reconhecidos

Um evento que o servidor confirmou como durável e que desapareceu após
reinício viola PQ2 e é motivo de reprovação da release inteira (§114).

1. Preserve o data-dir **inteiro**, tal como está. Copie o disco, não os
   ficheiros.
2. Preserve os registos do processo — o servidor regista o que descartou na
   recuperação.
3. Reproduza:
   ```bash
   heraclitus-qualifier crash-loop --server-binary <o binário exato> \
       --root /tmp/repro --cycles 200 --durability always \
       --report /tmp/crash-repro.json
   ```
   O relatório distingue o que interessa: `missing_acknowledgements` é a
   violação; `unacknowledged_attempts` não é — um append que nunca recebeu
   resposta pode legitimamente não existir.
4. Escale como defeito bloqueante. Não é uma anomalia operacional.

## Split brain

1. **Parar escritas em todos os nós.** Não escolha um vencedor por instinto.
2. Comparar histórias comprometidas por LSN entre os nós.
3. Se divergirem em entradas já comprometidas, é o cenário que §53 proíbe:
   preserve os dois lados antes de tocar em qualquer um.
4. Reconstruir a partir de uma história, com a decisão registada: quem decidiu,
   com que critério, o que se perdeu.

## Comprometimento

1. **Preservar antes de rodar.** Os registos de auditoria são a prova de quem
   acedeu a quê. Copie-os primeiro.
2. Rodar credenciais RBAC e tokens:
   ```bash
   heraclitus init-credentials /etc/heraclitus/credentials-novo   # ESCREVE
   ```
3. Rodar TLS/mTLS ([certificate-rotation.md](certificate-rotation.md)).
4. Responder à pergunta difícil: **que dados foram lidos?** Se
   `audit_queries = true`, está no log. Se não estava ligado, a resposta é "não
   sabemos" — e vai no relatório assim, sem adornos.
5. Se houve exposição de dados pessoais, o prazo de notificação começou a
   contar. É decisão do responsável nomeado em
   [disaster-recovery.md](disaster-recovery.md), não da equipa técnica.

## Se a causa for uma vulnerabilidade no produto

Passe para [vulnerability-response.md](vulnerability-response.md). Uma
vulnerabilidade corrigida gera teste de regressão (§93, PQ14) — sem exceção
quando é tecnicamente possível.

## Fecho

Todo incidente termina com:

- linha temporal do que aconteceu, com LSNs e horas;
- classe (das seis da tabela);
- que prova foi preservada e onde está;
- o que estava errado neste runbook.

A última linha é a que o torna melhor da próxima vez.
