# SPEC-0072 - Instant Recovery, Incremental Views & Zero-Stall Checkpointing

**Status:** PROPOSTA PARA IMPLEMENTAÇÃO
**Prioridade:** P0 / BLOQUEADOR DE ESCALA
**Área:** Storage, Recovery, Materialized Views, Checkpointing, Telemetry
**Produto:** HeraclitusDB
**Objetivo:** tornar startup, replay, checkpoint e recuperação previsíveis e escaláveis para bases com dezenas ou centenas de milhões de eventos, preservando integralmente o modelo append-only e o replay determinístico.

---

# 1. Contexto

O HeraclitusDB utiliza o log append-only como fonte canônica de verdade e reconstrói índices e views derivadas por replay determinístico.

Esse modelo é correto, porém a implementação atual apresenta problemas de escala quando o banco contém milhões de episódios.

Uma base real com aproximadamente:

* 8,6 milhões de eventos;
* aproximadamente 8,8 GiB;
* storage format v6;

expôs comportamento de startup extremamente lento após a introdução de uma nova materialized view.

A auditoria identificou múltiplas causas independentes e cumulativas.

Esta SPEC define a correção estrutural dessas causas.

---

# 2. Problemas confirmados

## P0-A - `V6Log::scan_capped()` usa point lookup para range scan

O caminho atual executa conceitualmente:

```rust
for lsn in from..end {
    self.read(lsn)?;
}
```

Isto transforma um scan sequencial em milhões de leituras individuais.

Em segmentos RAW, `read(lsn)` pode provocar novo scan do segmento.

Em segmentos PACKED, pode ocorrer reabertura e procura repetida.

Um replay completo com milhões de eventos não pode ser implementado como uma sequência de point lookups.

---

## P0-B - ViewRegistry possui bookkeeping caro no hot path

Durante replay, o registry executa repetidamente operações equivalentes a:

```rust
v.name()
HashMap<String, Lsn>::get(...)
v.apply(...)
v.name().to_string()
HashMap<String, Lsn>::insert(...)
```

O wrapper `Shared<T>` precisa adquirir o mutex da view para obter seu nome.

Isto cria:

* milhões de locks desnecessários;
* milhões de hashes;
* milhões de acessos ao `HashMap`;
* potencialmente milhões de alocações temporárias de `String`.

O nome e o cursor de cada view devem ser metadados estáveis do registry, e não consultados dinamicamente em cada evento.

---

## P0-C - Checkpoint e watermark não formam uma transação

Os snapshots das views e `watermarks.json` são persistidos separadamente.

É possível ocorrer:

```text
activation.ckpt = LSN 8.500.000
watermarks.json = LSN 8.000.000
```

caso haja crash entre as duas operações.

No restart, uma view pode restaurar estado mais novo e receber cursor antigo do registry.

Para views não idempotentes, isto pode provocar reaplicação de eventos.

A `ActivationStore` é explicitamente não idempotente, pois `apply()` incrementa informações de frequência e acesso.

Portanto esta condição pode gerar corrupção lógica silenciosa do estado derivado.

---

## P0-D - Checkpoint periódico bloqueia atualização das views

`checkpoint_views()` mantém o mutex global do `ViewRegistry` enquanto executa checkpoints potencialmente grandes.

Enquanto esse mutex permanece ocupado, caminhos de ingestão que precisam atualizar as views podem ficar bloqueados.

O uso de `spawn_blocking()` não resolve esse problema.

Ele apenas evita bloquear um worker Tokio.

Não elimina a contenção do mutex interno.

---

## P1-A - Checkpoint completo executado a cada 300 segundos

O valor padrão atual é:

```text
checkpoint_interval_secs = 300
```

Isso significa potencial serialização integral das views a cada cinco minutos.

À medida que o banco cresce, o custo do checkpoint também cresce.

A operação não pode continuar sendo proporcional ao tamanho integral das views quando nenhuma ou poucas alterações ocorreram.

---

## P1-B - Checkpoints utilizam clones e buffers integrais

Diversas views implementam persistência utilizando padrões equivalentes a:

```rust
let snapshot = state.clone();
let bytes = bincode::serde::encode_to_vec(&snapshot, ...)?;
write_all(&bytes)?;
```

Esse padrão pode exigir simultaneamente:

```text
estado residente
+
clone do estado
+
buffer serializado
```

Em estruturas grandes, isso multiplica o pico de RAM.

---

## P1-C - AttrIndex executa replay separado

As materialized views executam um scan do log.

Depois, `AttrIndex` pode executar outro scan do mesmo intervalo.

O mesmo episódio é:

```text
lido
decodificado
descartado

e posteriormente

lido novamente
decodificado novamente
```

Isso deve ser unificado.

---

## P1-D - TelemetryHealthGraph duplica histórico

A Telemetry Health mantém internamente eventos históricos utilizados para reconstruir estado `AS OF`.

O próprio HRKL já contém esse histórico.

A view não deve se transformar em um segundo event store.

Seu estado principal deve ser materializado e incremental.

---

## P1-E - Consultas Telemetry podem depender do histórico completo

O estado atual de sensores deve ser uma materialized view.

Consultar o estado atual de um sensor não pode exigir percorrer todos os eventos históricos desse sensor.

---

# 3. Objetivo arquitetural

O caminho desejado deve ser:

```text
HRKL v6
   |
   v
Sequential Range Scanner
   |
   v
Replay Dispatcher
   |
   +---- Vector
   |
   +---- Text
   |
   +---- Graph
   |
   +---- TemporalGraph
   |
   +---- Entity
   |
   +---- Activation
   |
   +---- Telemetry Health
   |
   +---- AttrIndex
```

Um episódio deve ser:

```text
lido uma vez
decodificado uma vez
distribuído para os consumidores interessados
```

Não devem existir dois scans independentes do mesmo intervalo quando isso puder ser evitado.

---

# 4. Invariantes obrigatórios

Nenhuma otimização desta SPEC pode violar os seguintes princípios.

## 4.1 Log como fonte da verdade

O HRKL continua sendo a única fonte canônica de verdade.

Views e índices são sempre derivados.

---

## 4.2 Replay determinístico

Para qualquer view:

```text
wipe
+
replay LSN 0..N
```

deve produzir exatamente o mesmo estado que:

```text
execução incremental normal até N
```

Quando existir `state_hash()`:

```text
hash_live == hash_replay
```

obrigatoriamente.

---

## 4.3 Recuperação após crash

Um crash em qualquer ponto do processo de checkpoint não pode gerar:

* perda de eventos;
* duplicação lógica;
* watermark incorreto;
* view parcialmente restaurada considerada válida.

---

## 4.4 Nenhuma alteração do formato HRKL sem necessidade

Não modificar o formato persistente HRKL v6 apenas para resolver o replay.

O scanner deve aproveitar as estruturas existentes.

---

## 4.5 Rust Stable

Toda implementação deve compilar em Rust Stable.

Não introduzir dependência de nightly.

---

# 5. Fase 1 - Corrigir `V6Log::scan_capped`

## 5.1 Requisito

`scan_capped()` não pode chamar `read(lsn)` em loop.

É proibido:

```rust
while lsn < end {
    self.read(lsn)?;
    lsn += 1;
}
```

---

## 5.2 RAW segments

Para segmento RAW:

1. abrir o segmento uma única vez;
2. executar scan sequencial;
3. selecionar apenas registros dentro do range;
4. parar ao atingir `max`.

Pseudoimplementação:

```rust
for segment in overlapping_segments(from, end) {
    match segment.format {
        Raw => {
            let scanned = scan_raw_segment_once(...)?;

            for record in scanned.records {
                if record.lsn < from {
                    continue;
                }

                if record.lsn >= end {
                    break;
                }

                output.push(record);

                if output.len() == max {
                    return Ok(output);
                }
            }
        }
    }
}
```

---

## 5.3 PACKED segments

Reutilizar o range scanner já existente.

Preferencialmente:

```rust
reader.scan_lsn_range(...)
```

Não implementar um segundo decoder PACKED apenas para esta SPEC.

---

## 5.4 Manifest

`DatabaseManifest::find_segment_for_lsn()` já possui busca eficiente.

Não substituir o binary search sem evidência de profiler.

---

## 5.5 Métricas

Adicionar contadores de scan:

```rust
struct ScanMetrics {
    segments_read: u64,
    blocks_read: u64,
    blocks_pruned: u64,
    records_decoded: u64,
    bytes_read: u64,
    bytes_decompressed: u64,
}
```

O scanner deve permitir instrumentação sem alterar a semântica da API pública.

---

# 6. Fase 2 - Remover bookkeeping textual do ViewRegistry

## 6.1 Estrutura desejada

Substituir hot-path baseado em:

```rust
HashMap<String, Lsn>
```

por estrutura indexada:

```rust
struct RegisteredView {
    name: &'static str,
    watermark: Lsn,
    dirty: bool,
    view: Box<dyn View>,
}
```

Alternativamente, usar identificador enum ou inteiro estável:

```rust
enum ViewId {
    Vector,
    Text,
    Graph,
    TemporalGraph,
    Entity,
    Activation,
    TelemetryHealth,
}
```

---

## 6.2 Restrição

Durante replay de um episódio não pode haver:

```rust
String::from(...)
.to_string()
HashMap<String, ...>
v.name()
```

dentro do loop interno.

---

## 6.3 Loop esperado

O replay deve se aproximar de:

```rust
for registered in &mut self.views {
    if lsn > registered.watermark {
        registered.view.apply(lsn, episode);
        registered.watermark = lsn;
        registered.dirty = true;
    }
}
```

---

## 6.4 Persistência

`watermarks.json` pode continuar existindo para:

* compatibilidade;
* diagnóstico;
* inspeção humana.

Mas deve ser materializado fora do hot path.

---

# 7. Fase 3 - Tornar checkpoints crash-consistent

## 7.1 Correção mínima obrigatória

Após uma view restaurar seu próprio checkpoint:

```rust
if view.restore(dir)? {
    registry.watermark = view.watermark();
}
```

O watermark contido no snapshot restaurado é autoridade para o estado daquele snapshot.

---

## 7.2 Não confiar cegamente em `watermarks.json`

Um arquivo global antigo nunca pode provocar replay sobreposto sobre snapshot mais novo de uma view não idempotente.

---

## 7.3 Solução recomendada

Implementar checkpoint por geração.

Estrutura sugerida:

```text
views/
    checkpoint-00000041/
        manifest.json
        vector.ckpt
        text.ckpt
        graph.ckpt
        tgraph.ckpt
        entity.ckpt
        activation.ckpt
        telemetry-health.ckpt

    checkpoint-00000042/
        ...

    CURRENT
```

---

## 7.4 Manifest

Exemplo:

```json
{
  "generation": 42,
  "created_at_lsn": 8604302,
  "views": {
    "vector": {
      "watermark": 8604302,
      "file": "vector.ckpt"
    },
    "activation": {
      "watermark": 8604302,
      "file": "activation.ckpt"
    }
  }
}
```

---

## 7.5 Commit atômico

Fluxo:

```text
criar checkpoint-42.tmp/
        |
        v
escrever snapshots
        |
        v
fsync dos arquivos
        |
        v
escrever manifest
        |
        v
fsync
        |
        v
rename checkpoint-42.tmp -> checkpoint-42
        |
        v
CURRENT.tmp = 42
        |
        v
fsync
        |
        v
rename CURRENT.tmp -> CURRENT
```

Até a atualização de `CURRENT`, a geração anterior permanece oficial.

---

## 7.6 Crash injection obrigatório

Testar crash em cada boundary:

```text
antes de vector
depois de vector
depois de text
depois de graph
depois de activation
antes de manifest
depois de manifest
antes de CURRENT
depois de CURRENT
```

Após cada crash:

```text
restart
+
recovery
+
state_hash
```

deve produzir exatamente o mesmo estado esperado.

---

# 8. Fase 4 - Zero-stall checkpointing

## 8.1 Regra

Serialização e I/O pesado não podem ocorrer segurando o mutex global de atualização das views.

---

## 8.2 Estratégia

Separar:

```text
captura lógica do estado
```

de:

```text
serialização + escrita + fsync
```

Objetivo:

```text
lock curto
snapshot consistente
unlock
serialização fora do caminho de escrita
```

---

## 8.3 Opções válidas

O agente pode escolher entre:

### A. Copy-on-write com `Arc`

ou

### B. Estruturas immutable/persistent

ou

### C. Snapshot específico por view

ou

### D. Double-buffering

A decisão deve ser justificada por benchmark e simplicidade operacional.

---

## 8.4 Proibido

Não resolver o problema apenas aumentando:

```text
checkpoint_interval_secs
```

Isso mascara o defeito.

---

# 9. Fase 5 - Dirty checkpointing

Cada view deve possuir:

```rust
dirty: bool
```

Uma view sem mudanças desde o último checkpoint não deve ser serializada novamente.

Fluxo:

```text
apply()
  -> dirty = true

checkpoint concluído
  -> dirty = false
```

---

## 9.1 Watermark sem dirty

Se nenhum episódio relevante para determinada view foi aplicado, não criar novo arquivo gigante apenas porque o head global avançou.

---

# 10. Fase 6 - Interesse seletivo por view

Introduzir conceito de interesse.

Exemplo:

```rust
pub enum ViewInterest {
    All,
    EventKind(&'static [&'static str]),
    Predicate(fn(&Episode) -> bool),
}
```

ou solução equivalente com custo mínimo no hot path.

---

## 10.1 Telemetry

Telemetry Health deve declarar interesse apenas em episódios:

```text
EventKind::Custom(TELEMETRY_HEALTH_KIND)
```

---

## 10.2 Vector

Vector deve ignorar rapidamente episódios sem embedding.

---

## 10.3 Entity

Entity pode ignorar episódios que não contenham:

```text
entity_key
er_op
```

---

## 10.4 Objetivo futuro

Permitir que metadata de segmentos, HRKI ou zone maps evitem até a decodificação de blocos irrelevantes.

Não é obrigatório implementar toda a poda física nesta SPEC, mas a API criada não pode impedir essa evolução.

---

# 11. Fase 7 - Unificar AttrIndex ao replay

O AttrIndex não deve disparar um segundo full scan depois de o registry já ter percorrido os mesmos episódios.

Criar dispatcher equivalente a:

```rust
for episode in scanner {
    views.apply(lsn, &episode);
    attr.apply(lsn, &episode);
}
```

Cada episódio deve ser decodificado apenas uma vez no startup normal.

---

# 12. Fase 8 - Corrigir TelemetryHealthGraph

## 12.1 Estado atual

A view não deve manter uma cópia integral do histórico apenas para reconstruir estado atual.

O HRKL já contém esse histórico.

---

## 12.2 Estrutura desejada

Algo equivalente a:

```rust
struct TelemetryHealthGraph {
    sensors: BTreeMap<SensorIdentity, ReducedSensor>,
    rejected_payload_lsns: BTreeSet<Lsn>,
    watermark: Lsn,
}
```

---

## 12.3 Apply incremental

Cada evento deve atualizar apenas o sensor correspondente.

```rust
fn apply(&mut self, lsn: Lsn, event: &Episode) {
    if !is_telemetry_health(event) {
        self.watermark = self.watermark.max(lsn);
        return;
    }

    let sensor = parse_sensor(event)?;

    self.sensors
        .entry(sensor.identity)
        .or_default()
        .apply(sensor);

    self.watermark = self.watermark.max(lsn);
}
```

---

## 12.4 Query atual

Consulta de sensor atual:

```text
O(log S)
```

ou aproximadamente O(1) dependendo da estrutura.

Consulta de todos os sensores:

```text
O(S)
```

onde S é quantidade de sensores.

Não pode ser O(T), onde T é quantidade histórica de eventos.

---

## 12.5 AS OF

Histórico `AS OF` deve utilizar:

```text
snapshot reduzido periódico
+
tail replay
```

ou scanner seletivo diretamente sobre HRKL.

Não manter duplicação completa do ledger dentro da view.

---

# 13. Fase 9 - Streaming checkpoints

Eliminar gradualmente padrões:

```rust
encode_to_vec(entire_snapshot)
```

para snapshots grandes.

Preferir:

```text
File
  +
BufWriter
  +
streaming encoder
```

ou implementação equivalente.

---

## 13.1 VectorIndex

Não duplicar integralmente:

```text
nodes
ids
lsns
```

antes de iniciar a serialização, se for tecnicamente evitável.

---

## 13.2 TextIndex

Não expandir postings compactos em representação significativamente maior apenas para checkpoint.

Persistir preferencialmente em formato próximo ao residente.

---

## 13.3 Graph

Evitar múltiplos clones completos de adjacências e bitmaps.

---

# 14. Fase 10 - Replay batch adaptativo

Remover dependência rígida de:

```text
100.000 episódios
```

como única configuração.

Introduzir configuração:

```text
replay_batch_events
```

Default inicial sugerido:

```text
16.384
```

O valor final deve ser escolhido por benchmark.

---

## 14.1 Requisitos

Benchmarkar pelo menos:

```text
4k
8k
16k
32k
64k
100k
```

medindo:

* throughput;
* RSS máximo;
* CPU;
* bytes/s;
* latência de checkpoint;
* tempo total de boot.

---

# 15. Fase 11 - Instrumentação de boot

O operador não pode ficar olhando uma linha parada sem saber se o banco morreu ou está trabalhando.

Durante replay emitir periodicamente:

```text
Replay views
  from_lsn:       0
  head_lsn:       8604302
  scanned:        1430000
  progress:       16.62%
  events_sec:     412870
  mib_sec:        389
  segments_read:  22
  blocks_read:    1450
```

---

## 15.1 Por view

Registrar na inicialização:

```text
vector:
  checkpoint: restored
  watermark: 8604000

text:
  checkpoint: restored
  watermark: 8604302

telemetry-health:
  checkpoint: missing
  watermark: 0
```

O motivo de rebuild deve ficar explícito.

---

## 15.2 Checkpoint inválido

Nunca degradar silenciosamente para replay completo.

Registrar:

```text
checkpoint telemetry-health rejected:
reason = incompatible_format
action = rebuild_from_lsn_0
```

---

# 16. Fase 12 - Windows Service readiness

O serviço não deve anunciar `RUNNING` antes de o banco estar realmente operacional.

Fluxo desejado:

```text
START_PENDING
    |
    v
open log
    |
    v
restore/replay
    |
    v
bind REST
    |
    v
bind gRPC
    |
    v
readiness = true
    |
    v
RUNNING
```

Durante boot longo atualizar:

```text
dwCheckPoint
dwWaitHint
```

quando aplicável.

---

# 17. Estados operacionais

Introduzir estado explícito:

```rust
enum EngineReadiness {
    Starting,
    Recovering,
    WarmingUp,
    Ready,
    Degraded,
}
```

Endpoint de health deve diferenciar:

```text
process alive
```

de:

```text
database ready
```

---

# 18. Compatibilidade

A implementação deve preservar:

* APIs públicas existentes sempre que possível;
* determinismo;
* suporte ao storage legacy;
* storage v6;
* `HERACLITUS_LOG_ONLY`;
* `HERACLITUS_SKIP_VIEW_REPLAY`;
* privacy rebuild;
* embedded mode;
* server mode.

Alterações incompatíveis devem ser justificadas explicitamente.

---

# 19. Testes obrigatórios

## 19.1 Unit

Criar testes específicos para:

```text
V6 range scanner
ViewRegistry cursor
dirty view
checkpoint generations
restore watermark
Telemetry incremental reduction
```

---

## 19.2 Replay determinism

Para cada view:

```text
build live
hash A

wipe views

replay from 0
hash B

assert A == B
```

---

## 19.3 Tail recovery

```text
checkpoint @ 900k
append até 1M
restart
```

Deve replayar apenas:

```text
900001..1000000
```

---

## 19.4 New view

Simular instalação de view nova em banco com 10M episódios.

Confirmar:

* apenas a view nova começa em watermark 0;
* views antigas não são reaplicadas;
* o scanner físico percorre o log apenas uma vez;
* episódios só são entregues às views cujo cursor exige aplicação.

---

## 19.5 Activation crash test

Obrigatório.

```text
build activation até N
checkpoint parcial
inject crash
restart
recover
```

Comparar:

```text
ActivationRecord.n
recent
first_access
state_hash
```

com reconstrução limpa desde LSN 0.

Devem ser idênticos.

---

## 19.6 Checkpoint under load

Executar ingestão contínua enquanto checkpoint ocorre.

Medir latência de append.

Checkpoint não pode causar pausa global prolongada.

---

# 20. Benchmark obrigatório

Criar benchmark reproduzível para:

```text
1M
10M
50M
```

eventos sintéticos.

Quando recursos locais não permitirem 50M, manter harness preparado e executar pelo menos 10M.

---

## 20.1 Medidas

Registrar:

```text
cold boot sem checkpoint
cold boot com checkpoint
tail replay 100k
tail replay 1M
events/sec
MiB/sec
peak RSS
CPU time
checkpoint duration
append p50
append p95
append p99
```

---

# 21. Acceptance Gates

## GATE 1 - Nenhum point lookup em range scan

`V6Log::scan_capped()` não pode chamar `read(lsn)` para cada registro.

---

## GATE 2 - Zero alocação textual por evento no registry

Durante replay:

```text
0 String allocations/event
```

para manutenção de watermark.

---

## GATE 3 - Zero lookup textual de nome por evento

O nome da view deve ser resolvido no registro, não durante cada apply.

---

## GATE 4 - Crash consistency

Crash em qualquer etapa do checkpoint deve resultar após restart em:

```text
state_hash == clean_rebuild_state_hash
```

---

## GATE 5 - Activation exata

Nenhum evento pode ser contado duas vezes após crash/restart.

---

## GATE 6 - Single physical replay

Views + AttrIndex devem utilizar uma única leitura física do intervalo quando ambos precisarem do mesmo replay.

---

## GATE 7 - Checkpoint sem stall prolongado

Meta:

```text
checkpoint induced append stall < 10 ms
```

em cenário de teste definido.

Se hardware ou estruturas atuais impossibilitarem atingir 10 ms imediatamente, o agente deve:

1. medir;
2. documentar;
3. demonstrar redução substancial;
4. deixar arquitetura compatível com zero-stall futuro.

Não aceitar simplesmente segundos de bloqueio global.

---

## GATE 8 - Telemetry query independente do histórico

Consulta do estado atual não pode crescer linearmente com o número total histórico de eventos.

---

## GATE 9 - RAM limitada

Replay paginado não pode materializar milhões de episódios simultaneamente.

---

## GATE 10 - Startup observável

Nenhuma fase acima de 5 segundos pode permanecer sem atualização periódica de progresso.

---

# 22. Meta de performance

Em máquina de desenvolvimento moderna com SSD NVMe, alvo arquitetural:

```text
10M eventos

checkpoint válido:
boot < 5 s

tail replay 100k:
< 1 s desejável

tail replay 1M:
> 500k eventos/s

full replay:
limitado por decoder/indexação real,
não por point lookup ou bookkeeping do registry
```

Esses valores são metas de engenharia, não devem ser falsificados por sleeps, lazy loading incorreto ou declaração prematura de readiness.

---

# 23. Restrições para o agente de IA

O agente NÃO deve:

1. alterar simultaneamente módulos não relacionados;
2. remover testes existentes para fazer a suíte passar;
3. desabilitar views como "solução";
4. mudar o storage format v6 sem necessidade demonstrada;
5. substituir replay determinístico por cache não verificável;
6. confiar em wall clock durante reconstrução;
7. simplesmente aumentar o intervalo de checkpoint;
8. esconder falhas de checkpoint;
9. ignorar erros de restore;
10. declarar melhoria sem benchmark;
11. adicionar `unsafe` sem justificativa técnica;
12. adicionar dependências pesadas sem necessidade;
13. comprometer `state_hash`;
14. quebrar backward compatibility silenciosamente.

---

# 24. Estratégia obrigatória de implementação

O agente deve trabalhar em commits ou passos lógicos separados.

## Passo 1

Adicionar testes que reproduzam:

```text
slow v6 range scan
snapshot/watermark mismatch
Activation duplicate replay
```

Quando possível, os testes devem falhar antes da correção.

---

## Passo 2

Corrigir range scanner v6.

Executar suíte.

Benchmarkar.

---

## Passo 3

Refatorar ViewRegistry.

Executar suíte.

Benchmarkar novamente.

---

## Passo 4

Corrigir protocolo de restore/checkpoint.

Executar fault injection.

---

## Passo 5

Remover checkpoint sob lock prolongado.

Medir append latency durante checkpoint.

---

## Passo 6

Unificar AttrIndex ao dispatcher.

Confirmar single physical scan.

---

## Passo 7

Refatorar Telemetry Health.

Comparar semanticamente resultados antigos e novos.

---

## Passo 8

Implementar instrumentation/readiness.

---

## Passo 9

Executar suite completa:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Caso o workspace possua features incompatíveis entre si, documentar e executar a matriz válida existente no projeto.

---

# 25. Relatório final obrigatório do agente

Ao concluir, produzir:

```text
SPEC-0072-REPORT.md
```

contendo:

## Arquivos alterados

Lista exata.

## Root causes corrigidas

Para cada P0/P1.

## Arquitetura anterior

Descrição curta.

## Arquitetura nova

Descrição curta.

## Benchmarks

Tabela before/after.

Exemplo:

| Cenário              | Antes | Depois | Ganho |
| -------------------- | ----: | -----: | ----: |
| scan v6 10M          |   ... |    ... |   ... |
| boot checkpoint      |   ... |    ... |   ... |
| replay 1M            |   ... |    ... |   ... |
| peak RSS             |   ... |    ... |   ... |
| checkpoint pause p99 |   ... |    ... |   ... |

## Fault injection

Listar todos os crash points testados.

## Correctness

Listar hashes/resultados comparados.

## Débitos remanescentes

Qualquer item desta SPEC não implementado deve ser explicitamente marcado como:

```text
NOT IMPLEMENTED
```

com justificativa.

Não utilizar expressões vagas como:

```text
future optimization
should be fine
probably fixed
```

---

# 26. Definição de pronto

A SPEC só pode ser considerada concluída quando:

```text
[ ] V6 range scan é sequencial
[ ] read(lsn) não é usado como implementação de range
[ ] ViewRegistry não aloca String por evento
[ ] ViewRegistry não adquire mutex para descobrir nome por evento
[ ] snapshot restaurado controla seu próprio watermark
[ ] crash durante checkpoint não duplica Activation
[ ] checkpoint não segura registry lock durante I/O pesado
[ ] dirty views não são reserializadas sem necessidade
[ ] AttrIndex compartilha replay físico
[ ] Telemetry mantém estado reduzido incremental
[ ] query atual de Telemetry não reprocessa histórico inteiro
[ ] replay batch é configurável
[ ] boot mostra progresso
[ ] serviço só fica Ready quando banco estiver operacional
[ ] testes de fault injection passam
[ ] testes de replay determinístico passam
[ ] benchmark before/after está documentado
[ ] cargo fmt passa
[ ] cargo clippy passa
[ ] cargo test passa
```

---

# 27. Princípio final

O HeraclitusDB deve continuar aceitando a seguinte propriedade:

> qualquer estado derivado pode ser destruído e reconstruído deterministicamente a partir do ledger.

Mas essa propriedade não significa que:

> toda inicialização deve reler todo o ledger.

Recovery correto e recovery eficiente são requisitos independentes.

O objetivo desta SPEC é fazer com que o custo normal de restart seja proporcional à **cauda ainda não materializada**, e não ao tamanho histórico total da base.

Para uma base com:

```text
100 milhões de eventos
checkpoint em 99.999.500
```

o restart normal deve pensar em:

```text
500 eventos
```

e não em:

```text
100.000.000 eventos.
```

Esse é o contrato de escalabilidade desta SPEC.
