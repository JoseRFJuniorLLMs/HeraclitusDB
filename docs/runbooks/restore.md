# Restore

Repor a partir de uma cópia, e **provar** que ficou reposto. A prova é a parte
que costuma faltar.

## Antes de tocar em alguma coisa

1. **Não reponha por cima da base viva.** Reponha para um destino novo e só
   depois troque. Um restore que sobrescreve o original destrói a única cópia
   que ainda podia ser boa.
2. Confirme que tem as **duas metades**: o backup e a keystore, que viajam
   separadas ([backup.md](backup.md)). Sem a keystore, um backup cifrado
   restaura-se e não se lê.
3. Arranque o cronómetro. O RTO mede-se do início da recuperação até ao serviço
   **validado** (§67), não até ao processo arrancar.

## Sequência

```powershell
# 1. Verificar a cópia antes de confiar nela
./windows/heraclitus-backup.ps1 verify -BackupPath D:\backups\<carimbo>

# 2. Repor para um destino NOVO                                      # ESCREVE
./windows/heraclitus-backup.ps1 restore -BackupPath D:\backups\<carimbo> -Destination D:\restore\<carimbo>

# 3. Diagnóstico de armazenamento antes de arrancar o servidor
heraclitus storage doctor D:\restore\<carimbo>

# 4. Raiz canónica
heraclitus verify D:\restore\<carimbo> --logical
```

Só depois destes quatro é que se aponta o serviço ao diretório reposto.

## Validação do restore (§64)

Restaurar sem verificar é copiar ficheiros. Confira, por esta ordem:

| o quê | como | falha significa |
|---|---|---|
| head do LSN | `curl /stats` → `head` | contagem abaixo do esperado = perda |
| contagem de eventos | `heraclitus log-inspect $DEST` | idem |
| raízes Merkle | `heraclitus verify $DEST --logical` | corrupção ou cópia incompleta |
| hashes amostrados | `heraclitus prove <segmento> --lsn <n>` | o evento não é o mesmo evento |
| recibos de compliance | `heraclitus verify-receipts $DEST` | a cadeia jurídica partiu-se |
| índices derivados | `heraclitus storage doctor $DEST` | ver política abaixo |
| serve consultas | `heraclitus-qualifier load --target ... --ramp-percent 100` | arrancou mas não serve |

## Política de índices derivados (§65)

Índices derivados (`.hrki`, `views/`) podem ser **repostos** ou
**reconstruídos** — desde que o comportamento esteja documentado, e está:

- se vieram no backup, são usados;
- se não vieram ou o doctor os marca inconsistentes, reconstroem-se por replay
  do log canónico:

```bash
heraclitus rebuild-index D:\restore\<carimbo>          # ESCREVE (só sidecars)
```

A propriedade que torna isto seguro é PQ4: enquanto a fonte canónica estiver
íntegra, todo o estado derivado é reconstruível. Se o log canónico **não**
estiver íntegro, reconstruir índices é a coisa errada a fazer — vá para
[incident-response.md](incident-response.md).

## Registar o que se mediu

No fim, escreva os dois números:

- **RPO medido** — distância entre o último evento reposto e o último evento
  que existia antes da perda;
- **RTO medido** — cronómetro do passo "antes de tocar" até o último check da
  tabela passar.

§66/§67 e PQ8 pedem os valores **medidos**, não os configurados. Um relatório
que diz "RPO: 15 minutos" porque a política diz 15 minutos não é evidência.

## Restore para máquina vazia

A qualificação exige repor num ambiente **vazio** (§62): máquina limpa →
instalar → repor → replay → verificar → servir. O harness automatiza a
sequência e sela a evidência:

```powershell
./qa/qualification/harness/Invoke-Q6Restore.ps1 -BackupPath <...> -OutputDirectory <...>
```

Para `MissionCritical` o cenário é mais duro (§63): assume-se o cluster
original **destruído**, sem depender de nenhum metadado local sobrevivente. Ver
[disaster-recovery.md](disaster-recovery.md).
