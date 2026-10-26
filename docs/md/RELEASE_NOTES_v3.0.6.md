# HeraclitusDB v3.0.6 — autorização de efeitos externos e cadeia de fornecimento

Data: 2026-10-25. Inclui tudo o que estava preparado para a v3.0.5, que não
chegou a ser publicada: escala das consultas, teto de memória dos índices e
Raft em streaming — ver `docs/md/RELEASE_NOTES_v3.0.5.md`, que por sua vez
inclui a v3.0.4 (`docs/md/RELEASE_NOTES_v3.0.4.md`). Binários e pacotes
(.deb, .rpm, tarball) são compilados no GitHub Actions.

O que acrescenta:

- Protocolo `external-intent-v1`, para um consumidor externo (o MachiavelliDB)
  autorizar e fechar no Heraclitus cada efeito que aplica no seu próprio banco.
- `tokio` 1.53.3 (RUSTSEC-2026-0386) e uma aceitação temporária, verificada
  pelo CI, do RUSTSEC-2026-0387.
- Dois testes instáveis corrigidos (portas do cluster e retenção regulatória).

## Autorização de efeitos externos (`external-intent-v1`)

Três operações novas no RPC `Admin`:

- `external-intent-v1` grava a intenção `{version, operation_id, consumer,
  source_sequence, payload_digest, expires_ms}` com `execute_admin` e devolve o
  recibo `{intent, principal, tenant, intent_lsn}`. A expiração tem de estar
  entre 1 ms e 5 min no futuro. Repetir a mesma intenção devolve o recibo já
  gravado, mesmo depois de expirar; o consumidor confere a expiração antes do
  seu commit.
- `external-status-v1` devolve `absent`, `authorized` ou `completed`, com o
  recibo e o resultado, para o consumidor reconciliar depois de uma falha em
  vez de repetir às cegas.
- `external-result-v1` grava o desfecho `{receipt, applied, local_sequence,
  result_digest}`, só se o recibo for exatamente o recibo durável e
  `local_sequence > source_sequence`.

Isolado por tenant e principal. A mesma chave com outro conteúdo é recusada.
Um registo `UNKNOWN` ou falhado falha fechado e pede reconciliação. É recusado
sem credenciais configuradas (`local-loopback`) e, como todo o
`execute_admin`, num nó replicado. O recibo autoriza; não afirma que o efeito
externo aconteceu e não traz prova Merkle.

Testado com reinício entre intenção e resultado, e ponta a ponta com o
MachiavelliDB 1.0.0-alpha.2 contra um servidor real: autorização,
repetição idempotente, Heraclitus parado e recuperação do consumidor depois de
um SIGKILL.

## Segurança e dependências

- **RUSTSEC-2026-0386**: `tokio` 1.53.1 → 1.53.3. Os construtores seguros de
  `AsyncFd` violavam a I/O safety; o workspace não usa `AsyncFd`.
- **RUSTSEC-2026-0387** (`crypto-bigint` 0.5.5, operações que deviam ser de
  tempo constante): aceitação **temporária**. A correção só existe no 0.7.6,
  que exige migrar o `p256` de 0.13 para 0.14. Até lá, um passo do
  `supply-chain` falha se o `crypto-bigint` 0.5.5 chegar por outro caminho que
  não o `p256`, se sair do grafo (para obrigar a retirar a exceção), ou se uma
  chave privada de curva elíptica aparecer fora do `SoftKeySigner` e do
  `LocalTsa` (ambos só de desenvolvimento; produção assina no HSM via
  PKCS#11) ou do `test_pki` (`#[cfg(test)]`).

## Testes

- Cluster: as portas Raft dos testes deixam de vir do `bind(0)`, que outro
  teste em paralelo podia receber antes de o nó a abrir (`AddrInUse` no CI).
  Saem de 20000..30000, abaixo das gamas efémeras.
- Retenção regulatória: o teste espera pelo carimbo real da avaliação em vez
  de um `sleep` fixo. No WSL2 o NTP faz o relógio recuar ~1,35 s, e o carimbo
  HLC ficava à frente do relógio. O veto estava certo; não mudou.

## Atualização

- Sem mudança de formato desde a v3.0.5: as intenções externas usam o diário
  administrativo existente (`AdminOperationKind::Custom`).
- As três operações `external-*-v1` exigem o papel Admin. Um consumidor como o
  MachiavelliDB precisa hoje de uma credencial Admin; falta um papel dedicado.
