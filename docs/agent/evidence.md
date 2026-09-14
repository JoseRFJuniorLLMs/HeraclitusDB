# Evidence Bundle — o pacote pericial

SPEC-0074 §17 e §18.

## O que é

Um ZIP que um perito abre numa máquina que não é a nossa, sem rede, sem o
Heraclitus instalado, e a partir do qual decide uma coisa: **este histórico foi
alterado depois de gravado, sim ou não?**

## Layout

```text
evidence-<bundle-id>.zip
├── manifest.json          autoritativo: selecção, digests, raízes lógicas
├── timeline.ndjson        uma evidência completa por linha, com o seu LSN
├── identities.json        agentes, humanos e delegações distintos
├── tool-calls.json        o trio Requested -> Started -> Finished reconstruído
├── approvals.json         aprovações humanas e a que assunto se ligam
├── policy-decisions.json  decisões de policy com proveniência
├── roots.json             raízes lógicas dos segmentos tocados
├── proofs/
│   └── <evidence-id>.json prova de inclusão de Merkle por registo
├── attestations/
│   └── README.txt         estado da ancoragem RFC 3161
├── SHA256SUMS             conveniência: `sha256sum -c`
└── README.txt             como verificar, e o que o pacote prova
```

### Três decisões de formato

1. **NDJSON e JSON, não um formato binário nosso.** Se o verificador
   desaparecesse, um perito com Python ainda leria tudo.
2. **Os digests estão em dois sítios.** `manifest.json` é a prova;
   `SHA256SUMS` é a conveniência que `sha256sum -c` já sabe ler. O verificador
   recusa o pacote se os dois discordarem.
3. **ZIP com método STORE, sem compressão.** É o único método que qualquer
   leitor de ZIP suporta desde 1989. Para um artefacto pericial, a
   transparência ganha ao tamanho.

## Exportar

```bash
# tudo
heraclitus agent export /var/lib/heraclitus --to evidence.zip

# um run
heraclitus agent export /var/lib/heraclitus --to evidence.zip --run run-abc123

# uma janela de tempo (nanos Unix)
heraclitus agent export /var/lib/heraclitus --to evidence.zip \
  --from 1757800000000000000 --until 1757900000000000000
```

Pela API:

```bash
curl -X POST http://localhost:8080/api/v1/agent/evidence/export \
  -H 'Content-Type: application/json' \
  -d '{"run_id":"run-abc123"}'
```

A escrita é **atómica**: escreve-se para `<destino>.zip.tmp` e só depois se
renomeia. Um bundle interrompido a meio nunca aparece como concluído.

## Verificar

```bash
heraclitus agent verify evidence.zip
heraclitus agent verify evidence.zip --json
```

O verificador faz, por esta ordem:

1. **Digests.** Cada ficheiro declarado existe e bate. E cada ficheiro presente
   está declarado — sem esta segunda metade, acrescentar um ficheiro ao ZIP
   passaria despercebido.
2. **Registos.** A timeline tem o número de registos que o manifesto declara.
3. **Provas.** Cada prova fecha contra a raiz que declara, a raiz está em
   `roots.json`, e o registo a que a prova se refere está na timeline **com o
   hash canónico que a prova declara**. É esta terceira ligação que torna a
   alteração de um byte detectável.
4. **Proveniência.** Pais em falta, decisões de policy sem proveniência
   completa, aprovações sem ligação ao assunto.

### Códigos de saída

```text
0 VERIFIED               4 PROOF_FAILURE
2 INVALID_BUNDLE         5 UNSUPPORTED_VERSION
3 DIGEST_MISMATCH        6 INCOMPLETE_SELECTION
                         7 ATTESTATION_FAILURE
```

São contrato. Um script pericial gateia com eles.

### Sem o binário

```bash
unzip -d bundle evidence.zip
cd bundle && sha256sum -c SHA256SUMS
```

Isto confere os digests. As provas de Merkle exigem o verificador — ou uma
reimplementação do acumulador canónico do HRKL v6, que está especificado na
SPEC-0050 §16–§18.

## `VERIFIED`, `PARTIAL`, `UNVERIFIED`, `BROKEN`

| estado | significado |
|---|---|
| `VERIFIED` | tudo o que o contrato exige passou |
| `PARTIAL` | evidência válida, mas faltam provas — tipicamente segmentos ainda não selados |
| `UNVERIFIED` | a verificação necessária ainda não correu |
| `BROKEN` | digest, prova ou raiz falhou |

> **"Não verificado" nunca vira "válido" só porque a UI gosta de verde.**

Um bundle exportado imediatamente depois da ingestão sai `PARTIAL`: os registos
ainda vivem no segmento activo, e uma prova de inclusão contra uma raiz que
ainda muda seria inútil. Quando o segmento sela — o worker de packing trata
disso, ou `heraclitus agent demo` sela à mão — as provas aparecem.

## O que um bundle prova, e o que não prova

**Prova:** que os registos incluídos estavam no histórico append-only com o
conteúdo exacto que ali aparece, e que esse histórico não foi alterado depois.

**Não prova:** que as decisões registadas foram correctas. Uma prova de Merkle
válida prova inclusão e integridade; a correcção da decisão é outra pergunta, e
o produto não finge respondê-la.

## Ancoragem no tempo (RFC 3161)

Desligada por omissão:

```toml
[agent_black_box.evidence]
rfc3161 = false
```

Quando desligada, `attestations/README.txt` di-lo por extenso em vez de a pasta
simplesmente não existir — um bundle sem `attestations/` levantaria a pergunta
"foi removida?".

As provas de Merkle continuam válidas sem ancoragem: provam **integridade e
inclusão**, não a hora.

## Tecto

Por omissão, 200 000 registos por bundle:

```toml
[agent_black_box.evidence]
max_bundle_records = 200000
```

Um `export` sem tecto sobre um log grande é uma forma acidental de negação de
serviço a si próprio.
