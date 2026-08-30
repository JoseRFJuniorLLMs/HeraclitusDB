# HeraclitusDB Qualification Operations

Este diretório contém os procedimentos operacionais da SPEC-0049. Eles
descrevem como produzir evidência; não declaram nenhuma release qualificada.
Um runbook só conta como **validado** depois de executado, revisto e anexado a
uma atestação assinada no gate `runbooks`.

Runbooks normativos:

- [Execução e cadeia de custódia](runbooks/qualification-run.md)
- [Crash, corrupção e power-loss](runbooks/failure-injection.md)
- [Upgrade e rollback](runbooks/upgrade-rollback.md)
- [Raft e perda de nó](runbooks/raft-failover.md)
- [Backup, restore e disaster recovery](runbooks/backup-restore-dr.md)
- [Instalação, update e recovery air-gapped](runbooks/airgap.md)
- [Q3 e red team](runbooks/security-red-team.md)

Os runbooks **de operação** — para quem mantém o sistema em produção, não para
quem produz evidência — estão em [`docs/runbooks/`](../runbooks/README.md), os
onze que a §117 nomeia.

## Onde está cada peça

| peça | caminho |
|---|---|
| planos consumidos pelo `heraclitus-qualifier` | `qa/qualification/plans/` |
| matrizes executáveis (ataque, Raft, upgrade, workloads) | `qa/qualification/matrices/` |
| perfis de soak 6h/24h/72h/168h | `qa/qualification/soak/` |
| harnesses de laboratório | `qa/qualification/harness/` |
| atestações assinadas e âncoras de confiança | `qa/qualification/attestations/`, `qa/qualification/trust/` |
| orçamentos de regressão | `qa/qualification/regression-budgets.json` |
| configuração de referência para o doctor | `qa/qualification/configs/` |

## O que o projeto corre sozinho, e o que exige um laboratório

Esta separação é a coisa mais importante deste diretório. Confundi-la produz
uma qualificação que parece completa e não é.

**Automatizado no repositório** — corre em CI ou num posto de trabalho:

| gate | como |
|---|---|
| Q1 carga | `heraclitus-qualifier load` (ramp, burst, seis lanes, verify final) |
| Q2 crash | `heraclitus-qualifier crash-loop` contra o binário de release |
| corrupção | `heraclitus-qualifier corrupt` + `Invoke-CorruptionMatrix.ps1` |
| soak | `heraclitus-qualifier soak` com os perfis de `qa/qualification/soak/` |
| Q6 restore | `Invoke-Q6Restore.ps1` |
| Q4 upgrade | `Invoke-UpgradeMatrix.ps1` |
| SBOM, build manifest, proveniência | `sbom` + `.github/workflows/release-supply-chain.yml` |
| fuzzing e corpus | `fuzz/`, lane de CI |
| configuração | `heraclitus-qualifier doctor` |
| egress no host | `heraclitus-qualifier egress-monitor` |

**Exige um laboratório, e não pode ser fingido aqui**:

| gate | porquê |
|---|---|
| `power_loss` | cortar energia é do hipervisor ou da PDU, não de um processo (§25) |
| `q5_node_loss` | perder um *host*, cortar a rede, parar um disco — `Invoke-RaftFailureMatrix.ps1` define o contrato e julga; a falha vem de fora |
| `zero_egress` | a **ausência** de egress prova-se com tap de rede independente; o monitor local só prova que houve |
| `red_team` | §35 quer equipa diferente da que implementou |
| `long_soak` 168h | tempo real em hardware de referência |
| `dr`, `airgap_install`, `airgap_update` | infraestrutura, não código |
| `runbooks` | §118: executados por quem não os escreveu |

Correr o plano governamental sem estas atestações produz `Unqualified` com
exit code 2 — que é o resultado correto, e não um falso PASS.

## Sequência de uma qualificação

```bash
# 1. exercitar a automação toda antes de gastar tempo de laboratório
heraclitus-qualifier run --plan qa/qualification/plans/lab-preflight.toml \
    --out qa-evidence/preflight-<data>

# 2. o plano do nível pretendido
heraclitus-qualifier run --profile gov-production \
    --out qa-evidence/gov-<data> \
    --history qa-evidence/qualification-history.jsonl

# 3. verificar o dossiê, e o binário contra ele
heraclitus-qualifier verify --evidence qa-evidence/gov-<data> \
    --binary target/release/heraclitus-server

# 4. comparar com a golden release
heraclitus-qualifier regression --baseline qa-evidence/<golden> \
    --candidate qa-evidence/gov-<data> \
    --budgets qa/qualification/regression-budgets.json --out regression.json
```

O passo 2 grava no histórico **qualquer que seja o resultado**. §109: uma falha
não se apaga quando é corrigida.
