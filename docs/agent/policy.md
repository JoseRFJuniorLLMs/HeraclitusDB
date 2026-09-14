# Policy — autorização determinística

SPEC-0075 §11–§18.

## Os dois princípios

### Policy is code, model output is data (§2.1)

Nada do que um LLM produz altera a policy. O avaliador vê campos tipados,
explicitamente projectados por quem chama — nunca o texto do modelo, nunca o
payload em bruto.

### Fail closed (§2.2)

Se a acção é protegida e a policy não pode ser avaliada, a decisão é `DENY`.
Nunca `ALLOW because policy service unavailable`. Um documento vazio nega tudo;
`defaults.decision: allow` é **recusado na leitura**, com uma mensagem que diz
porquê.

## O documento

```yaml
version: "agent-policy-v1"
id: "agent-policy"
revision: "v17"

defaults:
  decision: deny

rules:
  - id: finance-small
    match:
      server: finance
      tool: send_payment
      conditions:
        - field: amount
          op: lte
          value: 5000
    decision: require_approval
    approval:
      roles: ["finance-operator"]
      ttl_seconds: 300

  - id: finance-large
    match:
      server: finance
      tool: send_payment
      conditions:
        - field: amount
          op: gt
          value: 5000
    decision: require_approval
    approval:
      roles: ["cfo"]
      ttl_seconds: 180

  - id: destructive-shell
    match:
      server: shell
      tool: exec
      conditions:
        - field: command_class
          op: eq
          value: destructive
    decision: deny
```

O mesmo documento pode ser escrito em JSON. Os dois produzem o **mesmo**
`policy_hash`, porque o hash é do documento interpretado e não dos bytes do
ficheiro: comentários e indentação não mudam o que estava em vigor.

## Regras

A primeira regra que corresponde ganha. Sem correspondência, o default.

### Correspondência

| campo | efeito |
|---|---|
| `server` | igualdade exacta com o servidor da ferramenta |
| `tool` | igualdade exacta com o nome da ferramenta |
| `agent` | igualdade exacta com o subject do agente |
| `environment` | igualdade exacta (`production`, `staging`) |
| `protocol` | `mcp`, `http` |
| `conditions` | todas têm de passar |

Um campo ausente numa condição **nunca** a satisfaz. Uma regra
`amount <= 5000` não pode passar sobre uma acção que não declarou `amount`
nenhum.

### Operadores

```text
eq  neq  lt  lte  gt  gte  in  not_in  prefix  suffix  contains  exists
```

Sem regex, no MVP. Um motor de regex sobre input hostil é uma superfície de
negação de serviço que uma fronteira de autorização não pode ter. Uma condição
com `op: regex` é recusada na leitura, não ignorada em silêncio.

### Decimais

Comparados **sobre os dígitos**, nunca convertidos para vírgula flutuante.

```text
0.1 + 0.2 > 0.3      verdadeiro em binário
0.1 + 0.2 > 0.3      falso em dinheiro
```

Uma policy de pagamentos não pode depender de qual dos dois o compilador
escolheu. `5000.00`, `5000` e `005000.0000` são o mesmo número.

## Decisões

| decisão | bloqueia em `enforce` |
|---|---|
| `allow` | não |
| `deny` | **sim** |
| `require_approval` | **sim**, até haver aprovação válida |
| `rate_limit` | **sim**, com `retry_after_ms` |
| `redact` | não — actua sobre o conteúdo registado |
| `sandbox_hint` | não — é uma dica para quem executa |

`require_approval` sem `approval.roles` é recusada na leitura: autorizaria
qualquer pessoa a aprovar.

## Aprovação ligada ao conteúdo

> Uma aprovação para `send_payment(amount=5000, account=A)` **não** autoriza
> `send_payment(amount=50000, account=B)`.

Isto não é uma verificação feita "com cuidado" no sítio certo. É um hash do
assunto, calculado antes de pedir a aprovação e reconferido antes de executar:

```text
policy_id + policy_version + policy_hash + rule_id
+ agent_subject + human_subject
+ resource_id + action + argument_digest
+ issued_at + expires_at
```

Se qualquer um mudar, o hash muda e a autorização deixa de valer. Não há
caminho no código que execute sem o reconferir.

Além disso, a aprovação é **de uso único** e **expira**. As duas coisas existem
pelo mesmo motivo: uma aprovação reutilizável é uma credencial, e uma credencial
sem prazo é uma credencial permanente que ninguém emitiu de propósito.

Códigos de recusa:

```text
APPROVAL_PENDING            APPROVAL_EXPIRED
APPROVAL_DENIED             APPROVAL_REPLAYED
APPROVAL_NOT_FOUND          APPROVAL_BINDING_MISMATCH
```

## Ciclo de vida

```text
DRAFT -> VALIDATED -> SIMULATED -> ACTIVE -> RETIRED
```

Uma policy `ACTIVE` é imutável. Alterá-la gera uma versão e um hash novos.

```bash
heraclitus agent policy validate policy.yaml
heraclitus agent policy simulate policy.yaml --data-dir /var/lib/heraclitus
```

```text
historical tool calls: 18442
ALLOW:               17912
DENY:                  183
REQUIRE_APPROVAL:      347
changed vs active:      81
```

A simulação reavalia o histórico que a SPEC-0074 já registou. **Nada é
activado.** Activar é uma operação administrativa, exige o papel `policy_admin`
e fica registada.

```bash
curl -X POST http://localhost:8080/api/v1/agent/policies/activate \
  -H 'Content-Type: application/json' \
  --data-binary @- <<< "{\"document\": $(jq -Rs . < policy.yaml)}"
```

Se o documento for inválido, a policy anterior **continua activa**.

## Modos

```text
observe -> shadow -> enforce
```

| modo | avalia | bloqueia | `enforced` na evidência |
|---|---|---|---|
| `observe` | não | não | ausente |
| `shadow` | sim | **não** | `false` |
| `enforce` | sim | sim | `true` |

`shadow` é o modo que torna a adopção possível: a organização vê `would deny`
durante uma semana antes de alguma coisa partir.

## Segurança do ficheiro

```text
tamanho máximo 1 MiB, 20 000 linhas, 16 níveis de aninhamento
parse estrito
sem includes remotos
sem execução de shell
sem JavaScript/Lua embutido
sem template eval arbitrário
sem âncoras, aliases, tags ou merge keys de YAML
```

> Policy declarativa deve continuar dados, não virar mecanismo de RCE.

O leitor de YAML é um subconjunto estrito escrito para este efeito: mapas,
listas e escalares. Âncoras (`&x` / `*x`) — o vector da "bomba YAML" — são
recusadas por nome, não ignoradas.

## Proveniência

Cada decisão persistida leva:

```text
policy_id  policy_version  policy_hash  rule_id
decision  reason_code  input_projection_hash
authorization_id / approval_id  enforced
```

O `input_projection_hash` identifica **sobre que inputs** a decisão foi tomada,
sem guardar os inputs. O tempo não entra na projecção: duas avaliações iguais em
instantes diferentes têm de dar o mesmo hash.

## Determinismo

Mesmos inputs canónicos + mesma versão de policy ⇒ mesma decisão. Isto exclui,
por construção: ordem de mapas, locale, fuso horário, thread, reinício, ordem de
`HashMap` e aleatoriedade. O tempo, quando necessário, entra como **input
explícito**.
