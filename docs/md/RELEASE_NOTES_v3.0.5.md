# HeraclitusDB v3.0.5 — rascunho

Em preparação. Cada PR do ciclo acrescenta aqui a sua entrada.

## Desempenho

- `MATCH (n) WHERE n.agent_id = "x"` deixa de varrer o log. Resolve pelo
  índice de atributos (`_agent` para os eventos gerais e o novo `_agent_ev`
  para os `AgentEvidence`), hidrata pela ordem do LSN e pára no `LIMIT`. No
  soak nightly de 20/10/2026 esta consulta passava de 23 para 557 ms de p50
  entre 9,6 mil e 81,8 mil eventos, porque o skip-scan por zone map não salta
  nada quando o agente aparece em todos os segmentos. O resultado é o mesmo
  do varrimento. Continuam a varrer: o agente `hvm` (frames H-VM, fora do
  índice), valores com espaço nas pontas ou acima de 80 bytes, e o arranque
  com o replay das views saltado.
- O EXPLAIN mostra `BuiltinIndex` quando a consulta toma esse caminho.
- O `recall` deixa de pontuar todos os eventos no canal de ativação ACT-R.
  `ActivationStore::top_k` percorre os registos por limite superior
  decrescente (`score ≤ ln(n) − d·ln(now − último acesso)`) e pára quando o
  limite do próximo fica abaixo do k-ésimo score. O resultado é o mesmo da
  ordenação total, incluindo o desempate por id. Com um acesso por evento,
  que é o caso de cada episódio novo, pontua só `k` registos. O índice é
  derivado: o checkpoint da view não muda. Custa uma entrada ordenada por
  registo (um `u64` e o `EventId`) em memória.

## Atualização

- O índice de atributos passa ao formato v8. No primeiro arranque o
  checkpoint v7 é recusado e o índice é reconstruído a partir do log (uma
  vez; o log não muda). Em bases grandes este arranque demora mais.
- `_agent_ev` passa a ser um atributo reservado, como `_agent` e `_kind`: um
  `Append` que o traga em `attrs` é recusado.
- Cada `AgentEvidence` acrescenta um posting (o agente) ao índice de
  atributos, o mesmo custo que a chave de idempotência já tinha. O envelope
  de alta cardinalidade continua fora (SPEC-0085).

## Qualificação

- O gate de memória do soak aceita um segundo orçamento, em bytes de RSS por
  evento retido (`memory_growth_budget_bytes_per_retained_event`). Com ele,
  um RSS que sobe acima do orçamento por hora passa se a memória por evento
  gravado ficar dentro do orçamento nas duas metades da janela; o nightly usa
  8 KiB. Memória a crescer sem eventos novos continua a falhar. Os perfis
  longos não o usam.
- O gate de threads aceita um único degrau pequeno depois da estabilização,
  mesmo na segunda metade da janela, e regista o motivo no relatório.

## Memória

- Medição por índice em `crates/heraclitus-server/tests/memoria_por_indice.rs`
  (ver `docs/qualification/MEMORIA-INDICES-2026-10-21.md`).
- O índice de propriedades do grafo deixa de guardar os atributos internos
  `__heraclitus_*` (únicos por evento): 724 → 149 B por evento. O restore
  descarta-os de checkpoints antigos.
- O índice de atributos deixa de indexar o hash de idempotência:
  446 → 236 B por evento. Formato v9 (um checkpoint v8 ou anterior é
  reconstruído do log no primeiro arranque; com a v8 do mesmo ciclo, é uma
  só reconstrução para quem vem da 3.0.4).
- Teto de memória dos índices: cada índice estima os seus bytes residentes
  (dentro de ±7% do alocador na carga do soak); o servidor amostra-os a cada
  `index_memory_sample_secs` (30 s), publica
  `heraclitus_index_resident_bytes{index=...}` e `index_memory` no `/stats`, e
  aplica `index_memory_budget_bytes` (sem teto por omissão). Com
  `index_memory_policy = "reject_writes"`, os appends de clientes recebem
  `RESOURCE_EXHAUSTED` (repetível) enquanto a memória estiver acima do teto;
  escritas internas e replicação nunca são recusadas. Variante nova
  `HeraclitusError::ResourceExhausted`.

## Leituras

- Leitura pontual num segmento RAW selado e ainda não empacotado deixa de
  percorrer o ficheiro desde o início (auditoria 2026-10-16, O8): o seal
  guarda os offsets que o writer já tinha, e a leitura faz um `seek`. O LSN
  no offset é sempre conferido; sem offsets (depois de um restart, ou com
  mais de 64 segmentos à espera de pack) recua para o percurso completo.
- O commit do manifesto HRKM deixa de listar o directório a cada seal, pack,
  HRKI e legal hold para saber o número da geração (auditoria 2026-10-16,
  O2, parte): um contador em memória, lido do disco no primeiro commit e
  esquecido se um commit falhar. Fica por fazer o resto do O2 (o manifesto
  inteiro ainda é clonado e reescrito a cada commit).

## Raft

- O `committed` do Raft deixa de ser gravado com dois fsyncs a cada avanço
  (auditoria 2026-10-16, O7). Vai para o `meta.bin` no primeiro valor, a
  cada 1 024 entradas de avanço, depois de 1 s desde a última escrita, quando
  o voto é gravado e quando o log fecha. O Raft não exige que ele seja
  durável (o openraft recupera-o do líder); aqui serve de defesa extra na
  abertura, que continua válida com um valor ligeiramente mais antigo. As
  entradas reconhecidas continuam com fsync no `append`.
