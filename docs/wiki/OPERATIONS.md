# Operações

## Objetivo operacional

Operar o HeraclitusDB significa preservar três coisas ao mesmo tempo: **disponibilidade, integridade e capacidade de explicar o que aconteceu**. Em ambientes públicos, recuperar o serviço sem recuperar a trilha de evidência pode ser insuficiente.

## Rotina diária

A equipe de operação deve acompanhar:

- disponibilidade das superfícies de serviço;
- saúde de storage e espaço livre;
- latência e throughput de ingestão;
- backlog de views/índices;
- erros de verificação de integridade;
- estado de replicação quando habilitada;
- falhas de autenticação/autorização;
- alertas do Sentinel;
- sucesso de backup e cópia externa;
- versão, commit e configuração efetivamente carregados.

## Observabilidade

O workspace inclui `heraclitus-telemetry-health`. A integração institucional deve produzir métricas, logs e traces suficientes para reconstruir incidentes sem exigir acesso irrestrito ao conteúdo sensível.

Separar:

1. **telemetria de infraestrutura**: CPU, memória, disco, rede, file descriptors;
2. **telemetria de serviço**: requests, latência, erros, filas, timeouts;
3. **telemetria de dados**: LSN, segmentos, checkpoints, lag e verificações;
4. **telemetria de segurança**: autenticação, políticas, incidentes e ações;
5. **telemetria de release**: versão, hash, commit, feature set e configuração.

## Backup e restauração

Backup só é confiável depois de restauração testada. O procedimento deve registrar:

- escopo dos dados e metadados;
- consistência do ponto de recuperação;
- chaves necessárias;
- checksums/hashes;
- local e domínio de falha da cópia;
- tempo de restauração medido;
- resultado da verificação após restore.

Uma restauração deve terminar com validação funcional **e** validação de integridade.

## Continuidade e DR

Defina RPO e RTO por serviço consumidor. Para cada cenário crítico, mantenha runbook executável:

| Cenário | Resposta esperada |
|---|---|
| processo encerrado abruptamente | reinício + recovery + verificação |
| perda de nó | failover conforme topologia |
| corrupção de segmento | detecção, isolamento e recuperação |
| perda de storage | restore a partir de cópia validada |
| release defeituoso | rollback com preservação do log |
| chave indisponível | procedimento de contingência controlado |
| comprometimento | contenção, coleta de evidência, rotação e recuperação |

## Atualização

Toda atualização deve possuir:

1. release identificado;
2. changelog técnico;
3. avaliação de migração de formato;
4. backup prévio validado;
5. teste em ambiente representativo;
6. janela e responsável;
7. critério de abortar;
8. procedimento de rollback;
9. verificação pós-upgrade.

## Runbooks

O repositório mantém runbooks em [`../runbooks/`](../runbooks/). Eles devem ser considerados documentação operacional viva e versionados junto do código que alteram.

## Incidentes

Durante um incidente:

- preserve logs e artefatos antes de ações destrutivas;
- registre horário, operador, comando/ação e motivo;
- evite “corrigir” apagando a evidência;
- capture hashes dos artefatos relevantes;
- diferencie recuperação do serviço de encerramento da causa raiz;
- após estabilização, produza análise técnica e ações preventivas.

## Critério de produção

Consulte também [`../BLOQUEIOS-PRODUCAO.md`](../BLOQUEIOS-PRODUCAO.md) e [`../qualification/`](../qualification/). Um ambiente não deve ser classificado como “produção pronta” apenas porque iniciou sem erro e respondeu a uma query feliz. Computadores são muito cooperativos até o primeiro disco morrer às 3h17.
