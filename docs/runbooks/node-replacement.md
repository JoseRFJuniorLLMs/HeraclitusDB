# Substituição de nó

Um nó do cluster morreu e não volta. Este runbook põe outro no lugar sem
partir a história replicada.

Implementa SPEC-0049 §56.

## Antes: confirmar que o cluster ainda tem quórum

```bash
curl -fsS http://<nó vivo>:7475/stats
```

Se **ainda há maioria**, o cluster continua a aceitar escritas e a substituição
é uma operação de rotina — faça-a com calma.

Se **já não há maioria**, o cluster deve estar a recusar escritas. Isso é o
comportamento correto (§55): falhar fechado é preferível a corromper. Não force
escritas nesse estado e não tente "reduzir o cluster" para restabelecer maioria
artificialmente — é assim que se produzem duas histórias.

## Contagem de membros

Um cluster com número **par** de votantes não sobrevive a perder um nó: 4 nós
precisam de 3 para maioria, tal como 5. Ao substituir, mantenha o total ímpar.
O `heraclitus-qualifier doctor` assinala isto como Warning na configuração.

## Sequência

**1. Remover o nó morto da configuração** dos nós vivos, antes de adicionar o
novo. Adicionar primeiro faz o cluster passar por um estado com dois membros em
falta em vez de um.

**2. Aprovisionar a máquina nova.** [installation.md](installation.md) passos
1–4, com a **mesma versão** dos restantes nós. Um nó novo numa versão diferente
transforma uma substituição em upgrade rolling não planeado.

**3. `node_id` novo, nunca reutilizado.** Reutilizar o identificador do nó
morto faz o cluster acreditar que o nó voltou — com um log vazio. O nó novo é
um membro novo.

**4. Juntar ao cluster** e deixar apanhar o log.

**5. Medir o catch-up.** Não avance enquanto o nó novo não estiver alinhado:

```bash
curl -fsS http://<nó novo>:7475/stats     # head aproxima-se do do líder?
```

Registe o `catchup_ms`. §128 quer a taxa de catch-up comparada entre releases —
um nó que demora o dobro do que demorava é uma regressão de fiabilidade, mesmo
que nada tenha falhado.

**6. Validar o nó novo isoladamente.**

```bash
heraclitus storage doctor $DATA
heraclitus verify $DATA --logical
```

A raiz canónica do nó novo tem de conferir. Um seguidor que replicou bytes mas
não verifica é um seguidor que não serve para failover.

## Depois de um failover, verificar o que não se vê

Trocar de líder não pode duplicar efeitos externos (§57). Se o Sentinel estiver
ligado num modo que atua, confirme que a mudança de líder **não** repetiu
ações: uma sessão revogada duas vezes, um IP bloqueado duas vezes. A
idempotência existe para isto, mas confirmá-la depois de um failover real é
diferente de confiar que existe.

## Descomissionar a máquina antiga

Só depois do passo 6. E não a apague enquanto houver hipótese de o disco ser
prova de um incidente — ver [incident-response.md](incident-response.md).
