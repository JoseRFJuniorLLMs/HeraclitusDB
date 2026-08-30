# Runbooks de produção

A SPEC-0049 §117 exige que uma release governamental seja acompanhada destes
onze procedimentos. Estão aqui, e não em `docs/qualification/`, porque servem
uma audiência diferente: `docs/qualification/runbooks/` diz ao **laboratório**
como produzir evidência; estes dizem ao **operador** como manter o sistema de
pé às três da manhã.

| runbook | quando |
|---|---|
| [installation.md](installation.md) | primeira instalação, ou uma máquina nova |
| [upgrade.md](upgrade.md) | subir de versão |
| [rollback.md](rollback.md) | a versão nova falhou |
| [backup.md](backup.md) | rotina de cópia |
| [restore.md](restore.md) | repor a partir de uma cópia |
| [disaster-recovery.md](disaster-recovery.md) | o sítio inteiro desapareceu |
| [node-replacement.md](node-replacement.md) | um nó do cluster morreu |
| [certificate-rotation.md](certificate-rotation.md) | TLS/mTLS a expirar ou comprometido |
| [incident-response.md](incident-response.md) | suspeita de comprometimento ou corrupção |
| [vulnerability-response.md](vulnerability-response.md) | chegou um relato de vulnerabilidade |
| [air-gap-update.md](air-gap-update.md) | atualizar sem rede |

## O que "validado" significa aqui

§118: um runbook crítico **deve ser executado por alguém que não o escreveu**.
Enquanto isso não acontecer, estes ficheiros são procedimentos *propostos*, não
procedimentos *validados*, e o gate `runbooks` da qualificação governamental
continua por satisfazer.

A razão é a de sempre: quem escreveu o procedimento tem o contexto todo na
cabeça e não vê os buracos. Um passo como

> "restaure normalmente"

parece completo a quem o escreveu e é inútil para quem chega novo. Registe cada
execução em `qa/qualification/attestations/runbooks.json` com quem executou, em
que data, e o que teve de descobrir sozinho porque o texto não dizia.

## Convenções

- `$DATA` — o `data_dir` do serviço.
- `$BIN` — a pasta dos binários (`D:\HeraclitusDB\bin` no Windows).
- Comandos de leitura (`verify`, `storage doctor`, `manifest show`) nunca
  alteram nada e podem correr contra produção a qualquer momento.
- Comandos que escrevem estão marcados **ESCREVE** no passo respetivo.
