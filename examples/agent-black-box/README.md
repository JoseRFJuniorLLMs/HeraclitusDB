# Heraclitus Agent Black Box — quickstart

**Know exactly what your AI agent did. Prove who authorized it. Detect if the
history was changed.**

Cinco minutos, um contentor, um volume. Sem migrar base de dados, sem trocar o
framework do agente, sem GPU, sem cluster, sem linguagem de consulta própria.

---

## 1. Ligar

```bash
cd examples/agent-black-box
docker compose up -d
```

A Consola fica em <http://localhost:8080>, o receptor OpenTelemetry em
<http://localhost:4318>.

## 2. Mandar um agente lá para dentro

Se a sua aplicação já exporta OpenTelemetry, basta apontá-la:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

Se não tiver nada à mão, o exemplo faz de agente:

```bash
python sample-python-agent/sample.py
```

Não precisa de instalar nada: o script usa só a biblioteca padrão do Python.

## 3. Ver

Abra <http://localhost:8080>. Deve ver:

```
1 run
4 tool calls
integrity VERIFIED
```

Clique no run para a timeline: o modelo a escolher a ferramenta, cada chamada,
o resultado, o efeito externo e o erro do pagamento grande. Expanda uma linha
para ver os hashes, o LSN e a prova de Merkle.

> **Nota sobre `UNVERIFIED`.** Logo depois de ingerir, os registos vivem no
> segmento activo, que ainda não foi selado — e uma prova de inclusão contra uma
> raiz que ainda muda seria inútil. O produto diz `UNVERIFIED` em vez de dizer
> verde, e passa a `VERIFIED` quando o segmento sela. É de propósito: "não
> verificado" nunca vira "válido".

## 4. Exportar e verificar

No detalhe do run, carregue em **Export Evidence Bundle**. Depois, na máquina
onde tem o binário:

```bash
heraclitus agent verify evidence-01J....zip
```

```text
Bundle:           01J...
Records:          14
LSN range:        1..14
File digests:     VALID
Merkle proofs:    VALID
Logical roots:    VALID
Missing records:  0
Broken parents:   0

VERDICT: VERIFIED
```

Sem o binário, os digests continuam conferíveis com ferramentas banais:

```bash
unzip -d bundle evidence-01J....zip
cd bundle && sha256sum -c SHA256SUMS
```

## 5. A parte que importa: partir

```bash
# mude um byte qualquer do ficheiro
printf 'X' | dd of=evidence-01J....zip bs=1 seek=900 conv=notrunc
heraclitus agent verify evidence-01J....zip; echo "exit=$?"
```

```text
VERDICT: DIGEST_MISMATCH
exit=3
```

É isto que o produto vende. Não é que a história esteja guardada — é que uma
história alterada **não consegue passar por verificada**.

---

## Sem Docker

```bash
cargo run --release -p heraclitus-cli -- agent demo ./data
cargo run --release -p heraclitus-cli -- agent export ./data --to evidence.zip
cargo run --release -p heraclitus-cli -- agent verify evidence.zip
```

`agent demo` cria um run completo — consulta de fornecedor, pagamento que exige
aprovação do CFO, aprovação, execução, efeito externo — sem rede e sem chave de
API nenhuma.

---

## A seguir: controlar, não só observar

Até aqui o Heraclitus **regista**. Para o pôr a **autorizar**, ligue o Policy
Gateway (SPEC-0075):

```yaml
# no docker-compose.yml
HERACLITUS_AGENT_GATEWAY_ENABLED: "1"
HERACLITUS_AGENT_GATEWAY_MODE: "shadow"      # observe -> shadow -> enforce
HERACLITUS_AGENT_GATEWAY_UPSTREAM: "http://o-seu-servidor-mcp:9000"
HERACLITUS_AGENT_POLICY: "/etc/heraclitus/agent-policy.yaml"
```

e aponte o agente ao proxy (`http://localhost:8787`) em vez de ao servidor MCP.

```yaml
version: "agent-policy-v1"
defaults:
  decision: deny
rules:
  - id: finance-large
    match:
      server: finance
      tool: send_payment
      conditions:
        - field: amount
          op: gt
          value: 50000
    decision: require_approval
    approval:
      roles: ["cfo"]
      ttl_seconds: 180
```

**Comece sempre por `shadow`.** Nesse modo a policy é avaliada e registada, mas
nada é bloqueado: a Consola mostra `would deny` / `would require approval`
durante uma semana antes de alguma coisa partir. Só depois `enforce`.

Antes de activar uma policy nova, veja o que ela teria feito:

```bash
heraclitus agent policy simulate nova-policy.yaml --data-dir ./data
```

```text
historical tool calls: 18442
ALLOW:               17912
DENY:                  183
REQUIRE_APPROVAL:      347
changed vs active:      81
```

---

## Privacidade

Por omissão, `METADATA_ONLY`:

| o quê | estado |
|---|---|
| corpos de prompt | **OFF** |
| corpos de completion | **OFF** |
| argumentos de ferramenta | metadados + hash |
| resultados de ferramenta | metadados + hash |
| `Authorization`, `Cookie`, chaves de API | **nunca persistidos, em modo nenhum** |

A última linha não tem excepção: `FULL_EXPLICIT` autoriza guardar o corpo de uma
tool call; **não** autoriza guardar o bearer token que a acompanhava.

Ver [`docs/agent/privacy.md`](../../docs/agent/privacy.md).

---

## O que verificar quando alguma coisa não bate certo

```bash
heraclitus agent doctor ./data --config /etc/heraclitus/config.toml
```

```text
[  OK  ] data directory              /var/lib/heraclitus é gravável
[  OK  ] evidence log                HRKL aberto, head LSN 1847
[ WARN ] current integrity           14 registos; nenhum segmento selado ainda
         -> a prova aparece quando o segmento sela
[  OK  ] OTLP listener               HTTP em 0.0.0.0:4318
[ SKIP ] OTLP/gRPC                   não configurado (adiado para 0074.1)
[  OK  ] console                     em 0.0.0.0:8080
[ SKIP ] gateway mode                o Policy Gateway está desligado
[ WARN ] identity provider           dev_local — sem autenticação
         -> não use este perfil fora de uma máquina de desenvolvimento
```

---

## Documentação

| ficheiro | assunto |
|---|---|
| [`docs/agent/quickstart.md`](../../docs/agent/quickstart.md) | este guia, em detalhe |
| [`docs/agent/otel.md`](../../docs/agent/otel.md) | o que é capturado do OpenTelemetry |
| [`docs/agent/mcp.md`](../../docs/agent/mcp.md) | captura e proxy MCP |
| [`docs/agent/privacy.md`](../../docs/agent/privacy.md) | modos de captura e redacção |
| [`docs/agent/evidence.md`](../../docs/agent/evidence.md) | o Evidence Bundle e a verificação |
| [`docs/agent/policy.md`](../../docs/agent/policy.md) | a linguagem de policy |
