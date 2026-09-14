# Quickstart — Heraclitus Agent Black Box

> **Saiba exactamente o que o seu agente de IA fez. Prove quem autorizou.
> Detecte qualquer alteração posterior no histórico.**

Este guia leva de zero a um pacote pericial verificado. Cinco minutos, se já
tiver Docker.

---

## O problema

Um agente de IA escolhe ferramentas, encadeia ferramentas, age em nome de uma
pessoa, usa credenciais delegadas e altera estado externo. A observabilidade
tradicional responde a *"o que aconteceu?"*. O que uma auditoria precisa é:

```text
quem iniciou?                  qual política estava vigente?
qual agente executou?          houve aprovação humana?
em nome de quem?               qual foi o efeito externo?
qual ferramenta foi chamada?   o histórico foi alterado depois?
quais argumentos efectivos?    consigo verificar isso offline?
```

---

## 1. Ligar

```bash
git clone https://github.com/JoseRFJuniorLLMs/HeraclitusDB
cd HeraclitusDB/examples/agent-black-box
docker compose up -d
```

| porta | superfície |
|---|---|
| 8080 | Consola + API de evidência |
| 4318 | OTLP/HTTP |
| 4317 | OTLP/gRPC (opcional, desligado por omissão) |
| 8787 | proxy MCP (opcional, desligado por omissão) |

Confirme:

```bash
curl -s http://localhost:8080/api/v1/agent/status | head -20
```

## 2. Apontar o agente

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

Se a aplicação já exporta OpenTelemetry, é só isto. Nenhuma biblioteca nova,
nenhum SDK proprietário, nenhuma alteração ao código do agente.

Sem nada à mão:

```bash
python sample-python-agent/sample.py
```

## 3. Ver

<http://localhost:8080>

```text
┌─────────────────────────────────────────────────────────────┐
│ Heraclitus Agent Black Box                   ● VERIFIED     │
├─────────────────────────────────────────────────────────────┤
│ Runs                                                        │
│                                                             │
│ 08:41  procurement-agent   4 tools   0 approval   failed    │
└─────────────────────────────────────────────────────────────┘
```

Abra o run:

```text
08:41:02 Run started
08:41:03 Model invocation: demo-model
08:41:04 Tool executing: lookup_vendor
08:41:04 Tool result: lookup_vendor
08:41:07 Tool executing: send_payment
08:41:08 Tool result: send_payment
08:41:12 Error: ToolError
08:41:16 Run finished
```

Cada linha expande para os ids de correlação, os hashes, o LSN, a referência de
policy, a de aprovação e o estado da prova.

## 4. Exportar

Pela Consola, botão **Export Evidence Bundle**. Ou pela linha de comandos:

```bash
heraclitus agent export /var/lib/heraclitus --to evidence.zip --run run-abc123
```

## 5. Verificar — offline

```bash
heraclitus agent verify evidence.zip
```

```text
Bundle:           01J...
Records:          14
LSN range:        1..14
Capture mode:     METADATA_ONLY
File digests:     VALID
Merkle proofs:    VALID
Logical roots:    VALID
Timestamp proofs: 0 VALID
Missing records:  0
Broken parents:   0
Policy links:     0 VALID (of 0)
Approvals:        0 VALID (of 0)

VERDICT: VERIFIED
```

Para automação:

```bash
heraclitus agent verify evidence.zip --json
```

Códigos de saída — **são contrato**:

| código | significado |
|---:|---|
| 0 | `VERIFIED` |
| 2 | `INVALID_BUNDLE` |
| 3 | `DIGEST_MISMATCH` |
| 4 | `PROOF_FAILURE` |
| 5 | `UNSUPPORTED_VERSION` |
| 6 | `INCOMPLETE_SELECTION` |
| 7 | `ATTESTATION_FAILURE` |

## 6. Partir

```bash
cp evidence.zip adulterado.zip
printf 'X' | dd of=adulterado.zip bs=1 seek=900 conv=notrunc 2>/dev/null
heraclitus agent verify adulterado.zip; echo "exit=$?"
```

```text
VERDICT: DIGEST_MISMATCH
exit=3
```

---

## Sem Docker, sem rede, sem chave de API

```bash
cargo run --release -p heraclitus-cli -- agent demo ./data
```

```text
Demo run created: 01JXYZ...
Evidence records: 20
Console: http://localhost:8080/runs/01JXYZ...
Evidence integrity: VERIFIED
```

O demo encena o fluxo completo de §49 da SPEC-0076: o agente pede a ferramenta,
a policy exige aprovação do CFO, o humano aprova, a ferramenta executa, o efeito
externo é registado.

---

## O que fazer a seguir

| quero… | leia |
|---|---|
| perceber o que é capturado do OTel | [`otel.md`](otel.md) |
| pôr o Heraclitus à frente de servidores MCP | [`mcp.md`](mcp.md) |
| decidir o que é persistido | [`privacy.md`](privacy.md) |
| perceber o pacote pericial | [`evidence.md`](evidence.md) |
| escrever regras de autorização | [`policy.md`](policy.md) |

---

## Diagnóstico

```bash
heraclitus agent doctor ./data --config /etc/heraclitus/config.toml
```

Cada verificação que não passa diz **o que fazer**, não só que falhou.
