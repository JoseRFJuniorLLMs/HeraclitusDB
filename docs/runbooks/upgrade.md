# Upgrade

## Regra que precede tudo

**PQ9 — o upgrade tem de ser testado sobre dados reais da versão anterior.**
Um upgrade validado numa base vazia não valida nada: o que parte é sempre a
leitura do que já lá estava.

E **PQ10 — uma migração irreversível declara-se antes de correr**, não depois.

## Antes

1. **Backup completo e verificado** ([backup.md](backup.md)). Não é
   formalidade: é a única saída se o passo 4 correr mal.
2. **Restore testado desse backup** num destino descartável. §48 exige-o
   explicitamente quando a migração não permite rollback.
3. Ler as notas da versão e responder a uma pergunta: **`rollback_supported`
   é verdadeiro ou falso?** Se for falso, é preciso reconhecimento explícito do
   operador antes de continuar.
4. Verificar a matriz de compatibilidade: `N-1 → N` é suportado; `N-2 → N`
   pode não ser. Saltar versões sem confirmar isto é como se descobre, às
   03:17, que o caminho era `1.2 → 1.3 → 1.4`.

## Migração de formato v1–v5 → HRKL v6

Esta é a migração que mais gente vai encontrar, porque `v6` passou a ser o
default. Um binário novo sobre uma base legada **recusa arrancar** — de
propósito, e a mensagem de erro nomeia o ficheiro legado e dá as duas saídas.

```bash
heraclitus migrate-v6 /var/lib/heraclitus/log /var/lib/heraclitus-v6    # ESCREVE (só no destino)
```

Garantias que o driver faz cumprir mecanicamente:

- **a origem fica byte a byte intacta** — pode haver um carimbo RFC 3161 ou uma
  perícia a apontar para o hash antigo; apagar o legado é decisão sua, depois
  de conferir os recibos;
- **o destino tem de não existir** — migrar para dentro de uma base povoada
  misturaria duas histórias;
- **a identidade v6 é recomputada, nunca herdada** — cada segmento deixa um
  recibo com a raiz legada e a raiz lógica v6 lado a lado;
- **a contiguidade de LSN é verificada** — um buraco entre segmentos é erro
  duro;
- **uma cauda rasgada recusa migrar** em vez de migrar metade. Nesse caso abra
  a base uma vez com o motor legado (`storage_format = "legacy"`), deixe-o
  recuperar, e volte a correr.

Não use `--no-verify`. Troca minutos de CPU por uma classe inteira de falhas
silenciosas: a migração recomputa a identidade canónica do zero, por isso um
erro no codec produziria um segmento v6 *plausível* e errado, que só apareceria
quando alguém tentasse provar um LSN meses depois.

A alternativa, se não quiser migrar agora, é fixar `storage_format = "legacy"`.
É suportado e legível — mas fica sem packing, HRKI, tier frio e lakehouse.

## Sequência num nó único

```powershell
Stop-Service HeraclitusDB
# trocar o binário (guardar o anterior!)
Copy-Item $BIN\heraclitus-service.exe "$BIN\heraclitus-service.exe.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
Copy-Item <novo> $BIN\heraclitus-service.exe -Force                     # ESCREVE
heraclitus-qualifier doctor --config C:\ProgramData\Heraclitus\heraclitus.toml
Start-Service HeraclitusDB
```

O `doctor` entre a troca e o arranque apanha o caso em que a versão nova
renomeou ou passou a exigir uma chave de configuração.

## Upgrade rolling num cluster

Só se o protocolo declarar compatibilidade rolling. A ordem é sempre
**seguidores primeiro, líder por último**:

```text
A antigo, B antigo, C antigo
  → A novo, B antigo, C antigo      (A é seguidor)
  → A novo, B novo,  C antigo
  → tudo novo                        (C, o líder, por último)
```

Entre cada passo, e antes de avançar:

```bash
curl -fsS http://<nó>:7475/stats     # o nó novo entrou e apanhou o log?
heraclitus verify $DATA --logical    # a raiz confere no nó novo?
```

Durante a janela de versões mistas, nada disto pode acontecer (§45): protocolo
incompatível, corrupção de dados, split brain, replicação inválida. Se aparecer
algum, **pare e reverta** ([rollback.md](rollback.md)) — não "vá até ao fim
para uniformizar".

## Depois

```bash
heraclitus storage doctor $DATA          # status: CLEAN
heraclitus verify $DATA --logical
heraclitus verify-receipts $DATA         # a cadeia de compliance sobreviveu
curl -fsS http://127.0.0.1:7475/stats    # head não regrediu
```

E uma escrita real. Um servidor que arranca e serve leituras pode ter perdido o
caminho de escrita.

## Injeção de falha no upgrade

A qualificação interrompe o upgrade a 10, 25, 50, 75 e 90% e testa a
recuperação (§49). Em produção a lição prática é a mesma: se o upgrade for
interrompido a meio, **não arranque o serviço** — reponha o binário anterior e
valide o estado antes de tentar outra vez.
