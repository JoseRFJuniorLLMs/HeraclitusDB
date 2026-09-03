# SPEC-0072 — Sentinel Fast Restart, Durable Cursor Reconciliation e Linux Runtime Qualification

**Status:** PROPOSED
**Prioridade:** CRITICAL
**Componentes:** `heraclitus-sentinel`, `heraclitus-log`, `heraclitus-server`
**Compatibilidade:** HRKL legado + HRKL v6
**Objetivo:** eliminar replay integral desnecessário no boot, impedir divergência silenciosa entre cursor e log canônico e qualificar formalmente a execução persistente em Linux.

---

# 1. Problema

O caminho atual de inicialização do Heraclitus Sentinel possui três propriedades que, combinadas, tornam o startup de bases grandes progressivamente caro e podem impedir completamente a inicialização após determinadas condições de restart.

## 1.1 Full scan obrigatório em todo boot

A inicialização do Sentinel executa conceitualmente:

```rust
load_security_state(...)
    -> log.scan(0, log.head())
```

independentemente de existir:

* cursor persistido;
* checkpoint do Sentinel;
* estado derivado já materializado;
* shutdown anterior limpo;
* milhões de eventos já processados anteriormente.

Isso viola o princípio arquitetural do HeraclitusDB segundo o qual views derivadas devem possuir:

```text
snapshot/checkpoint
        +
replay somente da cauda
```

e não:

```text
restart
        =
replay integral desde LSN 0
```

Consequência:

```text
T_boot ≈ O(total_events)
```

quando o comportamento desejado é:

```text
T_boot ≈ O(snapshot_size + tail_since_snapshot)
```

---

# 2. Diagnóstico do cursor

O seguinte código:

```rust
cursor.next_lsn = lsn.saturating_add(1);
```

**NÃO deve ser alterado nem tratado como bug.**

Mexer no `saturating_add(1)` (por exemplo, removendo o `+1` ou tentando retroceder para `lsn`) criaria um replay repetido do último evento a cada restart ou catch-up e uma fábrica inesgotável de bugs idempotentes.

O contrato de numeração do log canônico e do Sentinel é:

```text
head     = próximo LSN disponível para append (limite superior exclusivo do log)
next_lsn = próximo LSN a ser consumido/processado (limite superior exclusivo do cursor)
```

Portanto:

```text
evento processado = N
next_lsn          = N + 1
```

é estritamente correto e matematicamente necessário.

### Exemplo concreto:

```text
LSNs gravados no log: 0, 1, 2, 3, 4
log.head():           5

Último evento processado pelo Sentinel: 4
cursor.next_lsn:                        5
```

Ao reiniciar ou consultar a cauda com intervalo `[next_lsn, head)`:

```text
[5, 5) -> intervalo vazio -> 0 eventos a processar
```

Se o cursor guardasse `4` (sem o `+1`):

```text
[4, 5) -> evento 4 seria re-lido e re-processado no próximo arranque!
```

Em um motor de segurança (Sentinel) que emite `SecuritySignal`, cria revisões de `SecurityIncident` e acumula contadores de frequência em `BehavioralEngine`, o re-processamento espúrio do último evento causaria:

1. Duplicação de alertas e sinais derivados;
2. Contaminação de baselines comportamentais (incremento indevido de contadores);
3. Exigência artificial de rotinas defensivas de desduplicação (idempotência frágil) em toda a pipeline para mascarar um erro de cursor.

Portanto:

```text
cursor.next_lsn == head
```

NÃO é um off-by-one nem erro de fronteira. É o **estado exato de sincronização completa (caught-up)**.

### O alvo real da SPEC-0072

O problema NUNCA foi o `+1` do cursor. O buraco arquitetural é composto por três fatores reais:

1. **Ausência de estado persistido derivado do Sentinel**: o servidor possuía apenas `cursor.json`, sem nenhum snapshot do estado interno (grafo de segurança, baselines comportamentais, regras, fusão de evidências).
2. **Full scan obrigatório de boot**: o método `load_security_state` executava incondicionalmente `log.scan(0, log.head())` em todo arranque, reconstruindo tudo do zero mesmo com cursor caught-up.
3. **Ausência de reconciliação estruturada de durabilidade**: quando uma anomalia real de crash ou restauração deixa `cursor.next_lsn > head`, o servidor abortava imediatamente ou forçava gambiarras manuais.

---

# 3. Divergência cursor > head

O problema real e patológico é a condição:

```text
cursor.next_lsn > log.head()
```

O código legado considerava isso erro fatal imediato:

```rust
if cursor.next_lsn > log.head() {
    return Err(SentinelError::Cursor(...));
}
```

Essa condição é de fato anormal, pois viola o invariante de que um consumidor derivado não pode ter processado eventos além do head do log canônico.

Entretanto, a resposta do servidor NÃO deve ser:

1. Fazer `cursor.next_lsn = cursor.next_lsn.min(log.head())` silenciosamente (ocultaria corrupção ou perda de dados);
2. Apagar cegamente o cursor e o estado em todo arranque;
3. Fingir que a divergência nunca aconteceu;
4. Abortar o processo sem mecanismo de recuperação automática no modo `rebuild`;
5. Considerar a base irrecuperável antes de tentar reconciliação determinística contra o log canônico.

### Causas raízes da divergência:

* **Crash com perda de tail não-fsyncada**: o cursor foi escrito com fsync mais recente do que o segmento do log canônico (inversão da ordem de durabilidade);
* **Restauração parcial de backup**: restore do diretório de dados onde o log canônico foi restaurado para um ponto no tempo mais antigo que o diretório `sentinel/`;
* **Rollback de storage subjacente**: snapshots de VM ou storage que reverteram o volume do log sem reverter o volume do Sentinel (ou vice-versa);
* **Reutilização acidental de diretório** por instâncias distintas;
* **Corrupção de metadados do log**.

---

# 4. Invariantes obrigatórios

## INV-1 — Exclusividade do head

Sempre:

```text
0 <= next_lsn
```

e durante operação normal:

```text
next_lsn <= head
```

Quando:

```text
next_lsn == head
```

o Sentinel está caught-up.

---

## INV-2 — Cursor nunca prova durabilidade do log

A existência de:

```text
sentinel/cursor.json
```

NÃO constitui prova de que os LSNs correspondentes continuam presentes no log canônico.

O log é a autoridade.

```text
canonical log > Sentinel cursor
```

sempre.

---

## INV-3 — Nenhum clamp silencioso

É proibido:

```rust
cursor.next_lsn = cursor.next_lsn.min(log.head());
```

sem processo explícito de reconciliação.

Isso esconderia perda de dados.

---

## INV-4 — Estado Sentinel é derivado

Todo estado Sentinel persistido fora do log:

* cache;
* snapshot;
* cursor;
* índice;
* sidecar;

MUST ser reconstruível a partir do log canônico.

Nenhum desses artefatos pode virar nova source of truth.

---

## INV-5 — Boot proporcional à cauda

Com snapshot válido:

```text
custo de boot ∝ eventos posteriores ao watermark
```

e NÃO ao tamanho total da base.

---

# 5. Novo modelo de estado persistente

Criar:

```rust
SentinelStateSnapshot
```

com versão explícita.

Exemplo conceitual:

```rust
pub struct SentinelStateSnapshot {
    pub format_version: u32,
    pub pipeline_version: u32,

    pub applied_until_exclusive: Lsn,
    pub canonical_head_at_snapshot: Lsn,

    pub rule_state: ...,
    pub behavior_state: ...,
    pub graph_state: ...,
    pub fusion_state: ...,

    pub signal_ids: ...,
    pub derived_sources: ...,
    pub incident_revision_ids: ...,
    pub risk_revision_ids: ...,
    pub l4_ids: ...,

    pub digest: [u8; 32],
}
```

O snapshot deve conter somente estado necessário para retomada.

Não deve conter objetos que possam ser recalculados trivialmente ou dados brutos sem necessidade.

---

# 6. Localização

Usar diretório derivado:

```text
<data_dir>/sentinel/
```

Arquivos:

```text
cursor.json
state.snapshot
state.snapshot.tmp
```

Opcionalmente:

```text
state.snapshot.prev
```

para rollback de snapshot inválido.

---

# 7. Publicação atômica do snapshot

A publicação MUST seguir:

```text
1. serializar snapshot
2. calcular BLAKE3
3. escrever state.snapshot.tmp
4. flush
5. fsync/sync_all
6. rename atômico
7. sync do diretório quando suportado
```

Em POSIX:

```text
rename(tmp, final)
```

deve ser usado como replace atômico.

No Windows deve existir o fallback compatível com a semântica já usada pelo `CursorStore`.

---

# 8. Checksum

Todo snapshot MUST possuir digest.

Preferencialmente:

```text
BLAKE3(
    format_version ||
    pipeline_version ||
    applied_until_exclusive ||
    serialized_state
)
```

No boot:

```text
snapshot inválido
        ->
descartar snapshot derivado
        ->
rebuild canônico
```

Jamais alterar o log por causa de snapshot inválido.

---

# 9. Novo algoritmo de boot

Substituir o comportamento atual por:

```text
OPEN CANONICAL LOG
        │
        ▼
read head
        │
        ▼
load cursor
        │
        ▼
load Sentinel snapshot
        │
        ├── válido ──────────────┐
        │                        │
        │                        ▼
        │                 restore state
        │                        │
        │                        ▼
        │             replay [watermark, head)
        │
        └── ausente/inválido
                 │
                 ▼
          streaming rebuild
                 │
                 ▼
          create snapshot
```

---

# 10. Remover full materialization

É PROIBIDO no boot normal:

```rust
log.scan(0, log.head())
```

para carregar toda a base em um único `Vec`.

Substituir por replay janelado:

```rust
let mut from = watermark;

while from < head {
    let rows = log.scan_capped(
        from,
        head,
        REPLAY_BATCH,
    )?;

    if rows.is_empty() {
        break;
    }

    ...

    from = last_lsn + 1;
}
```

Configuração sugerida:

```rust
sentinel.replay_batch_events
```

Default inicial:

```text
8192
```

O valor final deve ser definido por benchmark.

---

# 11. Streaming rebuild

Mesmo quando nenhum snapshot existir, o rebuild desde LSN 0 MUST ser streaming.

Proibido:

```text
Vec<todos_os_eventos_da_base>
```

Permitido:

```text
batch 0
batch 1
batch 2
...
batch N
```

Memória de replay deve permanecer limitada pelo tamanho do estado materializado mais o batch atual.

---

# 12. Filtragem antecipada

Durante rebuild do Sentinel, evitar desserialização completa sempre que possível.

Filtrar primeiramente por:

```text
agent_id == "sentinel"
```

e:

```text
EventKind::Custom(...)
```

relevante.

Quando HRKL v6 + HRKI estiver disponível, o Sentinel SHOULD utilizar skip/index metadata para evitar leitura de segmentos que comprovadamente não contêm eventos Sentinel.

Entretanto:

```text
HRKI é otimização
```

e nunca requisito de correção.

Fallback obrigatório:

```text
scan_capped
```

---

# 13. Tipos relevantes no rebuild

Restaurar apenas os eventos necessários:

```text
SecurityEvent
SecuritySignal
SecurityIncident
SecurityRiskAssessment
SentinelCheckpoint
SecurityInvestigation
SecurityActionProposal
SecurityPolicyDecision
SecurityActionResult
SecurityAiInvocation
SecurityApproval
SecurityModelUpdate
SecurityRulesetUpdate
SecurityFeedback
```

Eventos não relacionados ao Sentinel devem ser descartados imediatamente durante o replay.

---

# 14. Reconciliação do estado de startup (3-way reconciliation)

O startup do Sentinel não pode olhar para o cursor isoladamente, pois o cursor registra apenas o progresso do stream, enquanto o estado em memória (grafo de segurança, baselines comportamentais, regras) depende do snapshot.

A reconciliação é uma **reconciliação tripartite (3-way)** entre:

1. **`head`**: limite superior exclusivo do log canônico (`log.head()`);
2. **`watermark` ($W$)**: LSN até o qual o snapshot de estado é válido (`snapshot.applied_until_exclusive`), ou `0` caso o snapshot esteja ausente ou corrompido;
3. **`cursor` ($C$)**: próximo LSN esperado pelo cursor persistido (`cursor.next_lsn`).

Criar função explícita:

```rust
pub fn reconcile_startup_state(
    log: &AnyLog,
    cursor: SentinelCursor,
    snapshot: Option<&SentinelStateSnapshot>,
) -> Result<StartupReconciliation, SentinelError>
```

Resultado:

```rust
pub enum StartupReconciliation {
    /// Estado 100% sincronizado (watermark == head && cursor == head).
    /// Nenhum replay necessário; inicialização instantânea O(1).
    Synchronized {
        cursor: SentinelCursor,
    },

    /// Snapshot válido restaurado até `watermark`.
    /// Replay necessário apenas sobre a cauda [watermark, head).
    CatchUpTail {
        watermark: Lsn,
        head: Lsn,
        cursor: SentinelCursor,
    },

    /// Snapshot ausente ou corrompido.
    /// Rebuild canônico em streaming sobre [0, head).
    RebuildCanonical {
        head: Lsn,
        reason: RebuildReason,
    },

    /// Divergência patológica detectada (ex: cursor > head, watermark > head, cursor < watermark).
    DivergenceDetected {
        reason: StateDivergenceReason,
    },
}
```

---

# 15. Matriz de casos de reconciliação

Durante operação normal, o invariante é:

```text
watermark <= cursor.next_lsn <= head
```

### Caso 1 — Sincronizado (Warm Instant Boot)

```text
snapshot válido com watermark == head
cursor.next_lsn == head
```

* **Resultado**: `Synchronized`.
* **Ação**: Restaura snapshot. Replay da cauda: `[head, head) = 0 eventos`.
* **Custo**: $O(\text{snapshot\_size})$, startup sub-segundo mesmo em base de 100M eventos.

---

### Caso 2 — Cauda pendente pós-restart (Warm Tail Replay)

```text
snapshot válido com watermark < head
cursor.next_lsn <= head
```

* **Resultado**: `CatchUpTail`.
* **Ação**:
  1. Restaura o snapshot em memória (estado íntegro até `watermark`);
  2. Executa replay janelado da cauda canônica no intervalo `[watermark, head)`;
  3. Atualiza os motores internos (grafo, baselines, regras, fusão);
  4. O cursor avança de `watermark` até `head`;
  5. Ao atingir `head`, comita `cursor.next_lsn = head`.
* **Custo**: $O(\text{head} - \text{watermark}) = O(\text{tail})$.

---

### Caso 3 — Primeiro boot ou snapshot ausente/corrompido (Cold Rebuild)

```text
snapshot ausente ou digest inválido
```

* **Resultado**: `RebuildCanonical`.
* **Ação**:
  1. Descarta qualquer snapshot corrompido (sem tocar no log canônico);
  2. Executa streaming rebuild janelado em batches `[0, head)`;
  3. Ao final do rebuild, gera e publica atomicamente um novo `state.snapshot` com `watermark = head`;
  4. Comita `cursor.next_lsn = head`.
* **Custo**: $O(\text{total\_events})$, mas limitado em memória pelo tamanho do batch e do estado.

---

### Caso 4 — Divergência patológica (DivergenceDetected)

Ocorre em qualquer uma das seguintes violações de invariante:

1. `cursor.next_lsn > head` (cursor avançou além do log canônico);
2. `snapshot.applied_until_exclusive > head` (snapshot à frente do log);
3. `cursor.next_lsn < snapshot.applied_until_exclusive` (cursor regrediu atrás do snapshot).

* **Resultado**: `DivergenceDetected`.
* **Ação**: NÃO abortar imediatamente no modo padrão `rebuild`.
* **Telemetria**:
  ```text
  sentinel_divergence_total += 1
  ```
  Registrando:
  ```text
  cursor_next_lsn
  snapshot_watermark
  canonical_head
  pipeline_version
  data_dir
  ```

---

# 16. Recovery de cursor ahead

Ao detectar:

```text
cursor > head
```

seguir:

```text
1. preservar cursor divergente para auditoria;
2. verificar snapshot;
3. verificar SentinelCheckpoint canônico;
4. encontrar último estado comprovável no log;
5. reconstruir estado derivado quando necessário;
6. gerar novo cursor somente a partir do log canônico;
7. publicar novo snapshot;
8. continuar startup.
```

Salvar artefato antigo como:

```text
cursor.divergent.<timestamp>.json
```

ou equivalente determinístico/auditável.

---

# 17. Strict mode

Adicionar:

```toml
[sentinel.recovery]
cursor_policy = "rebuild"
```

Valores:

```text
strict
rebuild
```

## strict

```text
cursor > head
        ->
startup failure
```

adequado a ambientes forenses nos quais nenhuma recuperação automática pode ocorrer.

## rebuild

```text
cursor > head
        ->
rebuild derivado a partir do log canônico
```

Default recomendado:

```text
rebuild
```

porque nenhuma informação derivada é source of truth.

A divergência MUST permanecer registrada em telemetria.

---

# 18. Não inventar LSN

Recovery nunca pode fazer:

```rust
cursor.next_lsn = head;
```

sem reconstruir/validar estado.

O cursor final MUST representar processamento efetivamente comprovado.

---

# 19. Ordem de durabilidade

Auditar todos os caminhos em que o Sentinel atualiza:

```text
canonical log
derived Sentinel events
cursor
snapshot
```

A ordem MUST garantir que uma posição derivada nunca seja publicada como durável antes das informações das quais ela depende.

Modelo:

```text
canonical event durable
        ↓
derived work complete
        ↓
derived event durable, quando aplicável
        ↓
snapshot durable
        ↓
cursor durable
        ↓
public status watermark
```

A implementação real pode agrupar operações, mas deve provar equivalência a essa relação happens-before.

---

# 20. Auditoria do Log durability boundary

O agente MUST localizar, para cada backend:

```text
legacy Log
HRKL v6
```

o momento exato em que:

```text
head()
```

avança.

Verificar se esse avanço ocorre:

```text
antes ou depois
```

da barreira que garante durabilidade necessária segundo a configuração ativa.

Criar documentação explícita:

```rust
/// `head()` is the exclusive upper bound of canonically visible LSNs.
/// ...
```

e diferenciar, se necessário:

```text
visible_head
durable_head
```

Caso o engine já garanta que `head()` representa apenas dados suficientemente duráveis para o contrato existente, não criar segundo contador desnecessariamente.

Primeiro provar.

Depois alterar.

---

# 21. Crash window matrix

Criar testes para crash nos seguintes pontos:

```text
C0 antes do append canônico
C1 depois do append canônico
C2 depois da derivação Sentinel
C3 depois da escrita do snapshot.tmp
C4 depois do fsync do snapshot.tmp
C5 depois do rename do snapshot
C6 antes do cursor commit
C7 depois do cursor commit
C8 antes da publicação next_lsn_publicado
C9 depois da publicação
```

Após restart:

```text
cursor <= head
```

ou:

```text
divergência detectada + recovery auditável
```

e nunca:

```text
perda silenciosa
duplicação lógica
estado Sentinel impossível
```

---

# 22. Idempotência

Executar o mesmo replay:

```text
10 vezes
```

deve resultar nos mesmos:

```text
SecurityEvent IDs
SecuritySignal IDs
incident revision IDs
risk revision IDs
graph state
fusion state
cursor
snapshot digest
```

quando o estado lógico não muda.

---

# 23. Eliminar reconstrução dupla

Hoje o boot pode:

```text
scan completo
        +
reconstrução de histories
        +
reavaliação L1
        +
rebuild L2
        +
replay signals
        +
catch-up
```

A implementação nova MUST garantir que cada intervalo de LSN seja aplicado uma única vez por subsistema durante startup.

Adicionar instrumentação:

```text
sentinel_boot_events_scanned_total
sentinel_boot_events_applied_total
sentinel_boot_tail_events_total
sentinel_boot_snapshot_restored
sentinel_boot_snapshot_watermark
sentinel_boot_rebuild_total
```

---

# 24. Instrumentação de boot

Medir separadamente:

```text
sentinel.cursor_load_ms
sentinel.snapshot_load_ms
sentinel.snapshot_verify_ms
sentinel.state_restore_ms
sentinel.tail_replay_ms
sentinel.total_boot_ms
```

E contadores:

```text
sentinel_boot_full_rebuild_total
sentinel_cursor_ahead_total
sentinel_snapshot_corrupt_total
sentinel_snapshot_version_mismatch_total
sentinel_snapshot_rejected_total
```

---

# 25. Logging obrigatório

Exemplo:

```text
[ OK ] Sentinel snapshot
       watermark=19,998,443
       head=20,000,000
       tail=1,557
       restore=41ms
```

Nunca apenas:

```text
starting sentinel...
```

por minutos sem informar a fase responsável.

---

# 26. Linux não usa heraclitus-service

Formalizar o contrato arquitetural entre sistemas operacionais:

## Windows

```text
heraclitus-service.exe
        ->
Windows Service Control Manager (SCM)
```

O binário `heraclitus-service.exe` é compilado condicionalmente sob `#[cfg(windows)]`, dialoga com a API do SCM (`services.msc`, `StartServiceCtrlDispatcher`), escreve logs rolantes em disco e roda como conta de serviço NT SERVICE.

## Linux

```text
heraclitus-server
        ->
systemd
```

No Linux, o gerenciador de serviços nativo é o **systemd**. O daemon oficial é o próprio executável principal:

```text
heraclitus-server
```

supervisionado como serviço do systemd do tipo `simple`. O binário `heraclitus-service` NÃO deve ser portado nem utilizado como daemon Linux.

---

# 27. Unit systemd oficial

Adicionar ao repositório o arquivo canônico de serviço systemd:

```text
packaging/systemd/heraclitusdb.service
```

Especificação do unit:

```ini
[Unit]
Description=HeraclitusDB Event-Sourced Memory & Security Engine
Documentation=https://github.com/web2a/HeraclitusDB
After=network.target local-fs.target
Wants=network-online.target

[Service]
Type=simple
User=heraclitus
Group=heraclitus

# O servidor aceita o caminho do arquivo de configuração como primeiro argumento posicional
ExecStart=/usr/bin/heraclitus-server /etc/heraclitusdb/heraclitus.toml

# Sinal padrão de término enviado pelo systemctl stop é SIGTERM
KillSignal=SIGTERM
KillMode=mixed
TimeoutStopSec=30s

# Reinicialização automática em caso de crash (SIGSEGV, SIGKILL externo, etc.)
Restart=on-failure
RestartSec=2s

# Limites de recursos para operação de alta volumetria (I/O, sockets, mmap e descritores de arquivo)
LimitNOFILE=1048576
LimitMEMLOCK=infinity
TasksMax=65536

# Proteções de sandbox recomendadas para servidores governamentais
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

# Diretórios padrão gerenciados pelo systemd
RuntimeDirectory=heraclitusdb
StateDirectory=heraclitusdb
LogsDirectory=heraclitusdb

[Install]
WantedBy=multi-user.target
```

---

# 28. Linux signal handling e graceful shutdown

Para que o daemon funcione corretamente sob systemd, a manipulação de sinais em Linux MUST ser corrigida e qualificada:

```text
SIGTERM -> systemctl stop (parada graciosa)
SIGINT  -> Ctrl+C no terminal (interrupção graciosa)
SIGKILL -> kill -9 (abrupção sem aviso)
```

### Problema identificado no código atual:

No arquivo [`crates/heraclitus-server/src/main.rs`](file:///D:/DEV/HeraclitusDB/crates/heraclitus-server/src/main.rs#L12-L15):

```rust
heraclitus_server::serve(config, async {
    let _ = tokio::signal::ctrl_c().await;
})
```

O servidor escuta apenas `tokio::signal::ctrl_c()`. No Linux, o `ctrl_c()` captura `SIGINT`, mas o `systemctl stop` envia `SIGTERM`!

Sem o tratamento explícito de `SIGTERM`:

1. O comando `systemctl stop` não aciona o futuro de shutdown gracioso;
2. O servidor fica bloqueado até o `TimeoutStopSec` expirar (default 90s);
3. O systemd é forçado a enviar `SIGKILL`, matando o processo no meio de operações de disco;
4. O checkpoint final do Sentinel e o flush ordenado de views deixam de ser executados.

### Correção obrigatória:

Configurar o shutdown para esperar `SIGINT` OU `SIGTERM` em ambientes Unix:

```rust
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => signal.recv().await,
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
```

Sob `SIGTERM` (shutdown gracioso):

* Finalizar requisições em trânsito;
* Cancelar tasks de background (telemetria, GC, compliance);
* Executar `sentinel_runtime.checkpoint()` e salvar `state.snapshot` com `watermark = head`;
* Flush e sync de buffers do log canônico.

Sob `SIGKILL` (crash não controlado):

* Nenhuma chance de salvar estado;
* O próximo boot MUST recuperar-se deterministicamente a partir do log canônico e do snapshot anterior via reconciliação tripartite.

---

# 29. CI Linux existente não é qualificação operacional

A compilação Linux já existe no repositório. O workflow [`.github/workflows/ci.yml`](file:///D:/DEV/HeraclitusDB/.github/workflows/ci.yml) já roda `cargo clippy`, `cargo test` e `cargo fmt` sobre runners `ubuntu-latest`.

Entretanto, **compilar em runner efêmero do GitHub Actions não constitui qualificação operacional Linux equivalente à severidade do produto.**

A compilação no CI NÃO reproduz:

1. **Base persistente de vários GiB**: runners de CI rodam testes unitários isolados com diretórios temporários vazios ou fixtures microscópicas de alguns kilobytes;
2. **Ciclo de vida de reinicialização real**: múltiplos starts e stops sobre o MESMO diretório de dados em filesystem persistente (ext4/xfs);
3. **Queda abrupta via `kill -9`**: processo terminado sob alta taxa contínua de escrita (in-flight appends) para validar se o storage v6 e o Sentinel reiniciam sem corrupção;
4. **Recuperação de cursores antigos e snapshots**: comportamento diante de discrepâncias de durabilidade e corrupção de artefatos derivados;
5. **Supervisão sob systemd**: execução real de um daemon sob cgroups, limites de descritores (`LimitNOFILE`), entrega de sinais (`SIGTERM`) e reinício automático.

Esse é o buraco operacional que a SPEC-0072 fecha: criar uma qualificação de runtime Linux formal, com testes de integração e cenários de falha com severidade de produto de infraestrutura crítica.

---

# 30. Gate Linux L0 — build

No Ubuntu:

```bash
cargo build --release -p heraclitus-server --locked
```

---

# 31. Gate Linux L1 — server smoke

Executar:

```text
heraclitus-server
```

como processo real.

Verificar:

```text
process stays alive
REST responde
gRPC responde
append funciona
query funciona
shutdown SIGTERM funciona
restart funciona
```

---

# 32. Gate Linux L2 — persisted restart

Procedimento:

```text
start
append N events
wait Sentinel catch-up
shutdown
start novamente no MESMO data_dir
```

Assert:

```text
second_boot_events_scanned << total_events
```

quando snapshot existir.

---

# 33. Gate Linux L3 — SIGKILL

Procedimento:

```text
start
append continuamente
kill -9
restart
```

Verificar:

```text
log verify = OK
Sentinel starts
cursor <= head após recovery
nenhum logical duplicate
```

---

# 34. Gate Linux L4 — stale cursor

Construir deliberadamente:

```text
head = 1000
cursor.next_lsn = 1100
```

Resultado esperado em `rebuild`:

```text
divergência detectada
artefato antigo preservado
rebuild canônico
startup concluído
cursor final <= head novo
```

Em `strict`:

```text
startup aborta com erro explícito
```

---

# 35. Gate Linux L5 — corrupt cursor

Testar:

```text
JSON truncado
JSON inválido
pipeline version mismatch
arquivo vazio
```

Nenhum caso pode resultar em estado silenciosamente inventado.

---

# 36. Gate Linux L6 — corrupt snapshot

Testar:

```text
payload truncado
digest incorreto
versão desconhecida
watermark > head
pipeline mismatch
```

Resultado:

```text
snapshot rejeitado
rebuild derivado
log preservado
```

---

# 37. Gate Linux L7 — large database & persistent storage qualification

Executar qualificação de escala sobre storage persistente Linux real (partição montada ext4 ou xfs com fsync ativo, sem uso de tmpfs ou ramdisk):

### Carga de qualificação:

* **Dataset mínimo**: 20 milhões de eventos (múltiplos GiB de log canônico em HRKL v6 e legado);
* **População**: mix realista de telemetria bruta e eventos derivados de segurança;
* **Cenários encadeados de restart sobre o MESMO diretório de dados persistente**:
  1. *Cold boot*: arranque inicial sem snapshot existente (rebuild streaming e criação do snapshot 0);
  2. *Warm clean boot*: restart gracioso com Sentinel caught-up (snapshot no shutdown, 0 eventos de cauda);
  3. *Warm dirty boot*: restart após shutdown com cauda pendente não materializada ($T = 1.000$ eventos);
  4. *Crash boot*: encerramento forçado com `kill -9` durante ingestão concorrente pesada;
  5. *Divergent boot*: injeção de cursor adiantado (`cursor.next_lsn > head`) simulando rollback de volume.

### Métricas obrigatórias a aferir e registrar:

* `wall_time_ms` (tempo real de inicialização até o servidor ficar `Ready`);
* `cpu_time_ms` (tempo de CPU em user e system space);
* `peak_rss_bytes` (RSS máximo durante o replay — deve permanecer limitado);
* `io_bytes_read` e `io_bytes_written` (via `/proc/[pid]/io` no Linux);
* `events_scanned` (deve ser $\approx T$, nunca $N$ em warm boots);
* `tail_size` (número exato de eventos entre `watermark` e `head`).

---

# 38. Critério de complexidade

Para banco com:

```text
N eventos totais
T eventos após snapshot
```

o warm boot MUST se comportar aproximadamente como:

```text
O(T)
```

e não:

```text
O(N)
```

---

# 39. Gate de regressão

Criar teste que falhe caso alguém reintroduza:

```rust
log.scan(0, log.head())
```

no caminho normal de boot Sentinel.

A validação pode ser comportamental.

Exemplo:

```text
10M eventos
snapshot watermark = 9,999,990
tail = 10

events scanned durante restore <= limite pequeno
```

Não depender apenas de grep do source code.

---

# 40. Teste de restart sem novos eventos

Este caso é obrigatório porque é fácil mascarar bugs usando tail notifications.

Procedimento:

```text
1. criar base;
2. Sentinel caught-up;
3. shutdown;
4. restart;
5. NÃO realizar append.
```

O Sentinel deve restaurar estado integral corretamente mesmo sem qualquer novo evento disparando subscriber.

---

# 41. Teste de subscriber race

Testar eventos chegando enquanto ocorre boot catch-up.

Não pode haver:

```text
gap
double apply
cursor regression
cursor leap
```

Propriedade:

```text
cada LSN canônico relevante é logicamente aplicado exatamente uma vez.
```

---

# 42. Concorrência dos workers

O cursor continua sendo um watermark global.

Nenhum worker pode publicar:

```text
next_lsn = N + 1
```

se o trabalho necessário de um LSN anterior ainda não estiver completo.

Se o processamento permanecer serializado pelo mutex atual, documentar a propriedade.

Se for paralelizado futuramente, usar contiguous commit watermark.

Exemplo:

```text
processed:
100 ✓
101 ✓
102 pendente
103 ✓
104 ✓

published cursor MUST ser:
102
```

e jamais:

```text
105
```

---

# 43. Backpressure

O mecanismo de catch-up deve continuar bounded.

Nenhuma correção desta SPEC pode trocar:

```text
boot lento
```

por:

```text
OOM durante replay
```

---

# 44. Snapshot cadence

Adicionar configuração:

```toml
[sentinel]
snapshot_interval_events = 100000
snapshot_interval_secs = 300
```

Não é necessário obedecer aos dois simultaneamente.

Snapshot deve ocorrer quando pelo menos um limiar for atingido, respeitando rate limiting.

Valores finais definidos por benchmark.

---

# 45. Snapshot no shutdown

Em shutdown limpo:

```text
SHOULD
```

tentar publicar snapshot final.

Mas a correção MUST funcionar mesmo quando:

```text
SIGKILL
power loss
process abort
```

impedirem esse snapshot.

Portanto snapshot no shutdown é otimização, não requisito de consistência.

---

# 46. Pipeline version

Se:

```text
snapshot.pipeline_version != config.pipeline_version
```

o snapshot deve ser rejeitado.

Dependendo da semântica dos detectores:

```text
rebuild desde LSN 0
```

pode ser necessário.

Nunca reinterpretar silenciosamente estado de uma pipeline usando outra versão.

---

# 47. Migração

Bases atuais possuem apenas:

```text
cursor.json
```

O primeiro boot após adoção desta SPEC pode exigir rebuild do estado Sentinel.

Fluxo:

```text
snapshot ausente
        ->
bounded canonical rebuild
        ->
publish snapshot
```

Os boots seguintes usarão:

```text
snapshot + tail
```

Não alterar o formato HRKL por causa desta SPEC.

---

# 48. Compatibilidade

Nenhuma mudança obrigatória em:

```text
Episode
LSN
HRKL record layout
Merkle commitments
AS OF semantics
```

O snapshot Sentinel permanece derivado e descartável.

---

# 49. Arquivos principais a modificar

Obrigatórios para auditoria:

```text
crates/heraclitus-sentinel/src/lib.rs
crates/heraclitus-sentinel/src/cursor.rs
crates/heraclitus-sentinel/src/state/checkpoint.rs
crates/heraclitus-sentinel/src/state/replay.rs
crates/heraclitus-sentinel/src/metrics.rs

crates/heraclitus-log/src/lib.rs
crates/heraclitus-log/src/v6/engine.rs

crates/heraclitus-server/src/lib.rs
crates/heraclitus-server/src/main.rs

.github/workflows/ci.yml
```

Novos módulos sugeridos:

```text
crates/heraclitus-sentinel/src/state/snapshot.rs
crates/heraclitus-sentinel/tests/restart_recovery.rs
crates/heraclitus-sentinel/tests/cursor_reconciliation.rs
crates/heraclitus-server/tests/linux_runtime.rs
packaging/systemd/heraclitusdb.service
```

O agente deve adaptar nomes à estrutura encontrada, não criar duplicação arquitetural.

---

# 50. Auditoria recursiva obrigatória

Antes de alterar código, o agente deve executar quatro passagens.

## Passagem 1 — Call graph

Mapear:

```text
main
 -> server startup
 -> log open
 -> Engine
 -> views
 -> SentinelRuntime::start
 -> load_security_state
 -> subscriber
 -> process_until
 -> CursorStore::commit
```

Registrar todos os scans realizados no boot.

---

## Passagem 2 — LSN semantics

Mapear todos os usos de:

```text
head()
next_lsn
processed_lsn
as_of_lsn
watermark
scan
scan_capped
```

Classificar cada limite como:

```text
inclusive
exclusive
```

Eliminar ambiguidades documentais.

---

## Passagem 3 — durability

Mapear:

```text
write
flush
sync_data
sync_all
rename
manifest publication
head publication
cursor commit
snapshot commit
```

para:

```text
legacy
HRKL v6
Windows
Linux/POSIX
```

---

## Passagem 4 — runtime

Executar:

```text
fresh DB
large DB
clean restart
SIGTERM restart
SIGKILL restart
cursor ahead
cursor corrupt
snapshot corrupt
```

em Linux.

Somente depois considerar a implementação concluída.

---

# 51. Proibições

O agente NÃO pode corrigir a falha fazendo somente:

```rust
if cursor.next_lsn > log.head() {
    cursor.next_lsn = log.head();
}
```

NÃO pode:

```text
desligar Sentinel
ignorar cursor
apagar cursor em todo startup
desabilitar fsync
remover checkpoints
transformar erro em warning e continuar
```

NÃO pode reduzir garantias de:

```text
durabilidade
imutabilidade
determinismo
idempotência
auditabilidade
```

para melhorar benchmark.

---

# 52. Critérios de aceite funcionais

A SPEC está concluída somente se:

* [ ] `cursor.next_lsn == head` for reconhecido como estado válido;
* [ ] `cursor.next_lsn < head` fizer catch-up somente da cauda;
* [ ] `cursor.next_lsn > head` possuir recovery auditável;
* [ ] snapshot válido evitar replay integral;
* [ ] snapshot inválido provocar rebuild seguro;
* [ ] nenhum full `Vec` do log for necessário para boot Sentinel;
* [ ] startup sem append posterior funcionar;
* [ ] SIGKILL não deixar o Sentinel irrecuperável;
* [ ] logical events não forem duplicados;
* [ ] pipeline version mismatch for tratado;
* [ ] legacy e v6 passarem;
* [ ] Linux passar runtime qualification;
* [ ] Windows continuar compilando/funcionando.

---

# 53. Critérios de aceite de desempenho

Para base grande e Sentinel caught-up:

```text
warm restart
```

não pode escanear novamente toda a base.

Gate primário:

```text
scanned_events <= tail_events + bounded_metadata_overhead
```

Não usar somente tempo absoluto porque hardware e filesystem variam.

Gate secundário:

```text
warm_boot_time / cold_rebuild_time
```

deve demonstrar redução significativa.

---

# 54. Critérios de memória

Durante replay:

```text
peak temporary replay memory
```

deve ser aproximadamente limitado por:

```text
batch_size
+
materialized Sentinel state
+
bounded indexes
```

e não pelo número total de episódios do log.

---

# 55. CI final

Obrigatório:

```bash
cargo fmt --all --check

cargo clippy \
  --workspace \
  --all-targets \
  --all-features \
  --locked \
  -- -D warnings

cargo test \
  --workspace \
  --all-features \
  --locked
```

Além dos novos gates:

```text
sentinel restart
cursor reconciliation
snapshot recovery
Linux runtime
SIGKILL recovery
large-tail replay
```

---

# 56. Definition of Done

A SPEC-0072 somente pode ser marcada como DONE quando for demonstrado que:

```text
1. o +1 do cursor permanece semanticamente correto;

2. cursor > head não causa perda silenciosa nem exige intervenção manual
   no modo rebuild;

3. Sentinel não lê toda a base em cada restart;

4. snapshot + tail produz exatamente o mesmo estado lógico que replay LSN 0;

5. o comportamento foi exercitado por processo real em Linux;

6. SIGTERM e SIGKILL possuem recovery comprovado;

7. o custo de warm boot deixou de crescer linearmente com o tamanho histórico
   da base;

8. legacy e HRKL v6 mantêm equivalência semântica;

9. nenhuma garantia de integridade ou imutabilidade foi relaxada.
```

---

# 57. Resultado arquitetural esperado

Antes:

```text
20M eventos

restart
   ↓
scan 0..20M
   ↓
rebuild Sentinel
   ↓
server disponível
```

Depois:

```text
20M eventos
snapshot @ 19,999,800
head     = 20,000,000

restart
   ↓
restore snapshot
   ↓
replay 200 eventos
   ↓
server disponível
```

A diferença arquitetural fundamental é:

```text
ANTES
boot depende da idade da base

DEPOIS
boot depende apenas da quantidade de trabalho ainda não materializado
```

Esse é o contrato que o HeraclitusDB deve oferecer para permanecer operacional quando a base deixar de ser pequena.
