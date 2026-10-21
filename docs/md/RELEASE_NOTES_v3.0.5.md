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
