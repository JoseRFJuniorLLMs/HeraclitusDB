# HeraclitusDB v3.0.3 — Latência gRPC e binários qualificados

**Data:** 2026-10-19  
**Linha:** 3.x

A v3.0.3 é a v3.0.2 com a correção que faltava para a qualificar. A v3.0.2 foi
publicada só como código-fonte: o workflow de release recusou-se a produzir os
binários porque o gate de qualificação (o crash-loop do pacote Linux) excedeu
o tempo limite. Todas as correções da
[v3.0.2](RELEASE_NOTES_v3.0.2.md) estão incluídas e continuam válidas.

## Correções

- **Latência gRPC (regressão desde `cda5ba5`, 2026-10-02):** os sockets aceites
  pelo servidor gRPC voltaram a ter `TCP_NODELAY`. O servidor abre o próprio
  listener (`serve_with_incoming*`), e nesse caminho o `tcp_nodelay(true)` do
  builder do tonic não se aplica. Com o Nagle ligado, cada resposta curta
  esperava o ACK atrasado do cliente: uma consulta que dentro do processo leva
  menos de 1 ms levava ~45 ms por gRPC, e o `admin stats` ~49 ms. Medido
  depois da correção: 2,6 ms e 7,8 ms. Afetava todos os clientes (SDK Python,
  CLI, `heraclitus-client`, qualifier). Corrigido também no Arrow Flight, no
  OTLP/gRPC do agent gateway e no lado servidor do transporte Raft.
- **Gate de qualificação:** o crash-loop de 40 ciclos que o workflow de release
  corre sobre o pacote Linux tinha passado de ~1,5 minutos (v3.0.0) para mais
  de 60, contra um limite de 30. Medido no WSL (Linux) com 8 ciclos: 136 s antes
  e 21 s depois, com o mesmo volume de appends confirmados.
- **Leitura pontual na cauda (HRKL v6):** uma janela pequena (`MATCH (n) WHERE
  n.lsn = X`) começa no offset do registo, que o writer já conhece, e o
  percurso para no fim da janela, em vez de ler a cauda (e cada RAW selado
  ainda não empacotado) até ao EOF. Uma janela de um registo passa a ler um ou
  dois registos.

## Atualização e compatibilidade

- Sem alterações de formato nem de API em relação à v3.0.2. As notas de
  compatibilidade da v3.0.2 aplicam-se (arranque mais estrito, ids e
  fingerprints novos, cluster `replication` sem atualização nó a nó).
- Quem instalou a v3.0.2 a partir do código-fonte deve atualizar: a latência
  gRPC afeta todas as chamadas curtas.

## Validação

Ver o [relatório de validação](VALIDACAO_v3.0.3.md).
