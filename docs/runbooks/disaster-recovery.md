# Disaster recovery

O sítio A desapareceu. Este runbook põe o serviço de pé no sítio B.

Implementa SPEC-0049 §68–§71.

## Pré-requisitos que têm de existir *antes* do desastre

Nenhum destes se arranja durante a emergência:

- [ ] cópia verificada no sítio B, com idade conhecida;
- [ ] **keystore no sítio B**, por um caminho separado da cópia
      ([backup.md](backup.md)) — sem ela o restore produz bytes ilegíveis;
- [ ] binário da versão em produção disponível offline, com digest;
- [ ] credenciais de acesso ao sítio B que **não** dependem do sítio A
      (§69 lista "perda de credenciais" como cenário próprio);
- [ ] este runbook impresso ou acessível sem o sítio A.

## Autoridade de decisão

Declarar DR não é decisão técnica. Escreva aqui, antes de precisar:

- **quem declara** o desastre e ativa este procedimento;
- **quem pode autorizar** perda de dados dentro do RPO;
- **quem comunica** a titulares e reguladores, e em que prazo.

Um procedimento que não nomeia estas três pessoas transforma-se numa reunião
no pior momento possível.

## Sequência

```text
SÍTIO A  →  perda total  →  SÍTIO B  →  restore  →  validação  →  retoma
```

**1. Parar o cronómetro do RPO.** Registe a hora do último evento que se sabe
ter chegado ao sítio A e a hora do último evento na cópia. A diferença é o RPO
medido.

**2. Arrancar o cronómetro do RTO.** Corre até o passo 6 passar por inteiro.

**3. Preservar a evidência.** Antes de reconstruir seja o que for: se houver
qualquer hipótese de o desastre ter sido causado por um ataque, os discos do
sítio A são prova. Ver [incident-response.md](incident-response.md).

**4. Instalar no sítio B.** [installation.md](installation.md), passos 1–5, com
o binário e o digest que guardou.

**5. Repor.** [restore.md](restore.md) por inteiro, incluindo a tabela de
validação. Não salte a verificação de recibos: uma cadeia de compliance partida
descobre-se agora ou descobre-se numa auditoria.

**6. Validar antes de anunciar.** O serviço só está reposto quando:

```bash
heraclitus storage doctor $DATA          # CLEAN
heraclitus verify $DATA --logical        # raiz canónica confere
heraclitus verify-receipts $DATA         # recibos verificam
curl -fsS http://127.0.0.1:7475/stats    # head coerente com a cópia
```

...e uma escrita real é aceite e relida.

**7. Retomar o serviço.** Só depois do 6.

## Recuperação bare-metal (MissionCritical, §63)

Para o nível MissionCritical o cenário é mais duro: assume-se o cluster
original **destruído**, sem depender de nenhum metadado local sobrevivente. Na
prática isso significa que a recuperação não pode precisar de nada que só
existia no sítio A — nem um ficheiro de configuração, nem um `node_id`, nem um
certificado que estava só naquela máquina.

Teste isto explicitamente: faça o drill numa máquina que nunca fez parte do
cluster, com acesso apenas ao bundle e à keystore.

## Cenários a exercitar (§69)

| cenário | o que testa |
|---|---|
| perda do datacenter | o caminho completo acima |
| perda do cluster (infra de pé) | reconstrução sem reinstalar o SO |
| perda do armazenamento | a cópia é mesmo suficiente |
| **perda de credenciais** | existe caminho de recuperação que não depende dos segredos perdidos |
| isolamento de rede | o sítio B funciona sem falar com o A |
| operador indisponível | outra pessoa consegue executar este runbook |

O penúltimo e o último são os que quase nunca se testam e os que mais custam.

## Depois

Registe, no relatório do incidente:

- RPO **medido** e RTO **medido** (§66, §67 — medidos, não configurados);
- que passos deste runbook estavam errados, faltavam, ou tiveram de ser
  descobertos na altura;
- se o drill foi executado por alguém que não escreveu o procedimento (§118).

A terceira linha é a que valida o runbook. Sem ela, isto é um documento
proposto.
