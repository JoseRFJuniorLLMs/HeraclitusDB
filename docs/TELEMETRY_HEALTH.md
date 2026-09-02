# Telemetry Health / Sensor Trust

O módulo `heraclitus-telemetry-health` materializa a saúde de sensores a partir
do log imutável. Ele não consulta relógio de parede e não altera fatos de
origem: a mesma sequência de eventos produz o mesmo snapshot, inclusive em
replay e em consultas históricas.

## Contrato de entrada

Cada evento é um `Episode` com `EventKind::Custom("TelemetryHealth")` e conteúdo
JSON no schema `heraclitus-telemetry-health/1.0`. A identidade é obrigatória e
composta por `tenant_id`, `datasource_id` e `sensor_id`.

Eventos aceitos:

- `ExpectationConfigured`: cadência, tolerância de atraso, volume mínimo e
  limiar de duplicação;
- `SensorHeartbeat`: prova explícita de vida do sensor;
- `IngestionWindowClosed`: contadores da janela e digest do conector;
- `TelemetryDropRecorded`, `SchemaDriftObserved` e `ParserFailureObserved`;
- `CheckpointAdvanced`: sequência/watermark e resultado de integridade;
- `ConnectorActivated` e `ConnectorRejected`;
- `SensorClockSkewObserved`;
- `HealthEvaluationTick`: avanço explícito do tempo de evento para avaliar
  silêncio de forma determinística.

Payload inválido não interrompe replay: seu LSN entra na coleção de rejeitados
da view. Digests de conectores têm exatamente 32 bytes em hexadecimal. Uma
janela com digest diferente do conector ativo é classificada como adulteração.

O golden `forge_sensor_heartbeat_v1.json` é a saída canônica do serializador do
Heraclitus-Forge. A CI do consumidor desserializa, valida, reserializa byte a
byte e aplica esse envelope à view, fechando a fronteira entre os repositórios.

## Estado derivado

O snapshot preserva dimensões separadas, sem colapsar ausência de evidência em
saúde:

| Dimensão | Estados |
| --- | --- |
| Coverage | `Unknown`, `Covered`, `Partial`, `Uncovered` |
| Freshness | `Unknown`, `Starting`, `Healthy`, `Delayed`, `Silent` |
| Completeness | `Unknown`, `Starting`, `Complete`, `Gap` |
| Integrity | `Unknown`, `Trusted`, `Degraded`, `Tampered` |
| Trust | `Unknown`, `Trusted`, `Degraded`, `Untrusted` |
| Activity | `Unknown`, `Active`, `Quiet`, `Silent` |

Para alertas e dashboards há também um estado operacional agregado:
`Unknown`, `Healthy`, `Delayed`, `Silent`, `Drifted` ou `Degraded`. As dimensões
continuam sendo a explicação autoritativa desse resumo.

`Quiet` só existe quando há janela explicitamente vazia e o sensor continua
fresco. `Silent` requer uma expectativa configurada e avanço de tempo gravado
no próprio log. Clock skew impede uma alegação de freshness saudável. Lacunas
de sequência ou tempestades de duplicados degradam completude. Adulteração ou
conector não aprovado torna o resultado não confiável.

## Consulta

O servidor expõe:

```text
GET /telemetry/health
GET /telemetry/health?tenant_id=acme&datasource_id=windows&sensor_id=s-01
GET /telemetry/health?as_of_lsn=42000
```

`as_of_lsn` é limite exclusivo: `AS OF LSN n` considera somente eventos com
`lsn < n`. Sem o parâmetro, a consulta usa o head atual. A resposta inclui o
schema `heraclitus-telemetry-health-snapshot/1.0`, o limite consultado e os
snapshots ordenados pela identidade.

## Responsabilidade do produtor

O Connector Fabric/Forge deve emitir estes eventos no caminho quente. A view
não inventa heartbeats, relógio, expectativas, digests ou checkpoints. Essa
separação mantém o banco como fonte de verdade auditável e permite comparar um
snapshot histórico com um replay parcial bit a bit.

## Cenários de aceitação

- TH0: ausência de heartbeat após a cadência gravada resulta em `Silent`;
- TH1: sem expectativa, o resultado permanece `Unknown`;
- TH2: salto na sequência produz `Gap`;
- TH3: schema drift reduz coverage sem ser rotulado automaticamente como ataque;
- TH4: `AS OF` coincide com replay parcial do mesmo prefixo;
- TH5: checkpoint divergente produz `Tampered` e `Untrusted`.
