# Backup

## A regra que governa este runbook

**PQ7 — um backup só é válido depois de um restore testado.** Um `.tar.gz` que
nunca foi reposto é esperança comprimida, não uma cópia de segurança. Este
runbook termina obrigatoriamente em [restore.md](restore.md).

## O que entra na cópia

| caminho | entra | porquê |
|---|---|---|
| `$DATA/log/` | **sim** | é a fonte canónica; tudo o resto reconstrói-se a partir daqui |
| `$DATA/manifests/` (HRKM) | **sim** | gerações, filas e watermark |
| `$DATA/*.hrki` | opcional | sidecars de índice; reconstruíveis com `rebuild-index` |
| `$DATA/views/` | opcional | estado derivado; reconstrói por replay |
| `$DATA/receipts/` | **sim** | recibos de compliance; **não** são reconstruíveis |
| `$DATA/keys/` | **NÃO** | ver abaixo |

### A keystore fica de fora, e é deliberado

Guardar `data/keys/` dentro do backup cifrado destrói o objetivo da cifra: quem
obtiver o backup obtém as chaves que o decifram. Este bug existiu e foi
corrigido (PR #13, commit `5b3bb0b`) — era grave precisamente por ser
silencioso: o backup parecia completo e continuava a proteger nada.

A keystore faz um **percurso separado**: cofre de chaves ou HSM, com o seu
próprio ciclo de rotação e o seu próprio controlo de acesso. Um restore precisa
das duas metades, e é suposto precisar.

## Executar

```powershell
./windows/heraclitus-backup.ps1 backup -Source $DATA -BackupRoot D:\backups   # ESCREVE
```

O script produz um diretório com data e hora e um manifesto com o digest de
cada ficheiro (§60).

## Verificar — não é opcional

```powershell
./windows/heraclitus-backup.ps1 verify -BackupPath D:\backups\<carimbo>
```

Isto confere manifesto, hashes, tamanhos e presença dos ficheiros obrigatórios
(§61). Um backup que não verifica é lixo que ocupa espaço e dá falsa segurança;
apague-o e volte a correr.

## Tipos suportados

- **full** — o que o script acima faz.
- **cópia offline/remota** — sincronize o diretório verificado para o segundo
  sítio. Verifique **outra vez no destino**: a corrupção acontece em trânsito.
- **incremental / baseado em snapshot** — não implementado. Está declarado como
  limitação conhecida em vez de sugerido, porque §59 manda documentar o que
  realmente existe.

## Cadência e drills

§71: um ambiente produtivo tem de ter uma rotina de **restore drill**, e a
existência de backups sem drill deve gerar alerta operacional.

Cadência mínima recomendada:

| ação | frequência |
|---|---|
| backup completo | diário |
| `verify` do backup | a cada backup |
| **restore drill completo** | mensal |
| drill de DR entre sítios | trimestral |

Registe cada drill: data, quem executou, RPO medido, RTO medido. "Medido", não
"configurado" (§66, §67) — o número que interessa é o que o cronómetro mostrou,
não o que o documento de política prometeu.

## Alerta de backup obsoleto

§136 pede que o servidor exponha `backup_age` e `last_restore_test` entre as
métricas de auto-saúde, e §137 quer que um backup obsoleto produza um
`HeraclitusHealthIncident`.

**Isso ainda não está implementado.** O `/stats` de hoje devolve o estado do
armazenamento (`head`, `storage_format`, contadores HRKL), não o estado do
backup. Até estar, o alarme tem de vir de fora: uma tarefa agendada que olha
para a data da pasta de backup mais recente e para o registo do último drill, e
dispara quando passam 24 h e 30 dias respetivamente.

Registar isto como lacuna em vez de descrever o comportamento desejado é
deliberado — um runbook que manda ler uma métrica inexistente é pior do que um
que não a menciona.
