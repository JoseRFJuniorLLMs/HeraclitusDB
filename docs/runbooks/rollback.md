# Rollback

A versão nova está de pé e está errada. Este runbook devolve o serviço à versão
anterior sem perder o que foi escrito entretanto — ou diz-lhe, cedo, que isso
não é possível.

## Decidir antes de agir: o rollback é possível?

Faça esta pergunta **primeiro**, porque a resposta muda tudo:

| situação | rollback |
|---|---|
| só o binário mudou, o formato em disco não | **sim**, direto |
| a versão nova escreveu num formato que a antiga não lê | **não** — é preciso restore |
| correu `heraclitus migrate-v6` e já se escreveu no destino v6 | **não** para o destino; a origem legada continua intacta |

A migração v1–v5 → v6 é o caso feliz disfarçado de caso mau: ela **nunca toca
na origem**, por isso o "rollback" é simplesmente voltar a apontar o serviço ao
diretório legado com `storage_format = "legacy"`. O que se perde são as
escritas feitas na base v6 depois da migração — que é exatamente porque §48
manda declarar `rollback_supported = false` **antes** de instalar.

## Rollback do binário

```powershell
Stop-Service HeraclitusDB
Copy-Item "$BIN\heraclitus-service.exe.bak-<carimbo>" $BIN\heraclitus-service.exe -Force   # ESCREVE
heraclitus-qualifier doctor --config C:\ProgramData\Heraclitus\heraclitus.toml
Start-Service HeraclitusDB
```

O `doctor` aqui não é cerimónia: se a versão nova introduziu uma chave de
configuração que a antiga não conhece, o servidor antigo pode recusar arrancar
ou — pior — ignorá-la. O doctor lê o TOML em bruto e diz-lhe qual chave ficou
inerte.

Depois, sempre:

```bash
heraclitus storage doctor $DATA
heraclitus verify $DATA --logical
```

## Rollback num cluster

Ordem inversa à do upgrade: **líder primeiro**, seguidores depois. Isso força
uma eleição imediata, enquanto ainda há maioria na versão antiga, em vez de
deixar um líder novo a replicar para seguidores antigos.

Entre cada nó, confirme que o quórum se manteve. Se perder quórum a meio, pare:
um cluster sem maioria deve **recusar escritas** (§55), e forçar escritas nesse
estado é como se produz histórias divergentes.

## Quando o rollback não é possível

Vá para [restore.md](restore.md). A sequência é:

1. parar o serviço;
2. repor o backup pré-upgrade **para um destino novo**;
3. validar o restore por inteiro (as sete linhas da tabela de validação);
4. apontar o serviço ao destino reposto;
5. registar o **RPO medido** — as escritas entre o backup e o momento da
   reversão perderam-se, e o número exato tem de constar do incidente.

## O que nunca fazer

- **Não** faça downgrade do binário por cima de um formato novo "para ver se
  dá". Os layouts recusam abrir a raiz um do outro de propósito; forçar isso é
  como se corrompe uma base que ainda estava boa.
- **Não** apague o diretório da versão nova antes de o restore estar validado.
  Enquanto o passo 3 não passa, a base nova ainda pode ser a melhor cópia que
  existe.
- **Não** trate um rollback como não-evento. §109: a falha entra no histórico
  de qualificação e fica lá depois de corrigida.
