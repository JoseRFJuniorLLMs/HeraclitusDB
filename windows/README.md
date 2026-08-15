# HeraclitusDB como serviço Windows

`heraclitus-service.exe` executa o mesmo motor do servidor no Service Control
Manager, com auto-start, parada graciosa e log diário. Instalações novas usam a
conta virtual de menor privilégio `NT SERVICE\HeraclitusDB`, nunca LocalSystem.

## Build

```powershell
cargo +stable-x86_64-pc-windows-msvc build --release `
  -p heraclitus-server --bin heraclitus-service --locked
cargo +stable-x86_64-pc-windows-msvc build --release `
  -p heraclitus-cli --bin heraclitus --locked
```

## Instalar e operar

Em PowerShell elevado:

```powershell
.\windows\heraclitus-service.ps1 install
.\windows\heraclitus-service.ps1 status
.\windows\heraclitus-service.ps1 logs
```

O perfil padrão continua de desenvolvimento em loopback. Para homologação,
prepare primeiro um data-dir cifrado e credenciais novas.

## Migração de um diretório antigo em plaintext

Nunca apenas ligue `HERACLITUS_ENCRYPTION=true` sobre segmentos antigos: isso
cifra os appends novos, mas não reescreve o passado. Com o serviço parado:

```powershell
target\release\heraclitus migrate-encrypt `
  D:\HeraclitusDB\data `
  D:\HeraclitusDB\data-encrypted-v1
```

A origem é verificada e preservada. O destino precisa não existir e recebe
novos segmentos cifrados + keystore; LSN, EventId e HLC são preservados. Views
não são copiadas e serão reconstruídas no primeiro boot.

## Credenciais sem segredo no terminal

```powershell
target\release\heraclitus init-credentials D:\HeraclitusDB\secrets-v1
```

O comando cria `credentials.json` com hashes BLAKE3 e tokens separados. Não
imprime nenhum token. Mova `admin.token` para cofre/offline depois do bootstrap.

## Aplicar perfil seguro

```powershell
.\windows\heraclitus-production.ps1 apply `
  -Profile homologation `
  -DataDir D:\HeraclitusDB\data-encrypted-v1 `
  -SecretsDir D:\HeraclitusDB\secrets-v1
```

O script aplica ACLs, conta virtual, `fsync=always`, RBAC, meta-auditoria,
encryption-at-rest e configura `HERACLITUS_TOKEN_FILE` no perfil do usuário.
Abra um terminal novo depois da aplicação.

`-Profile production` também liga o gate fail-closed e exige uma TSA HTTPS real
e `-RestAuthFile` dentro de `SecretsDir`. O serviço recebe apenas o caminho em
`HERACLITUS_REST_AUTH_FILE`; a senha não é copiada para variável de ambiente ou
para o repositório. Isso não deve ser usado com TSA de laboratório.

## Backup e restore

```powershell
.\windows\heraclitus-backup.ps1 backup `
  -BackupRoot D:\HeraclitusDB\backups `
  -HeraclitusCli D:\DEV\HeraclitusDB\target\release\heraclitus.exe

.\windows\heraclitus-backup.ps1 verify `
  -BackupPath D:\HeraclitusDB\backups\heraclitus-backup-<UTC> `
  -HeraclitusCli D:\DEV\HeraclitusDB\target\release\heraclitus.exe

.\windows\heraclitus-backup.ps1 restore `
  -BackupPath D:\HeraclitusDB\backups\heraclitus-backup-<UTC> `
  -Destination D:\HeraclitusDB\restore-drill-<UTC>
```

O backup para o serviço de forma graciosa, copia e gera manifesto SHA-256. O
restore nunca apaga nem sobrescreve: o destino precisa não existir.
Como o backup inclui o keystore necessário ao restore, o volume de backup deve
ter cifra de volume/cofre e acesso segregado; em produção, use também cópia
imutável e off-site conforme o RPO/RTO do órgão.

## Upgrade local transacional

Para atualizar uma instalação antiga que ainda usa dados em plaintext, existe
um fluxo único e fail-safe. Ele exige PowerShell elevado e preserva origem e
binário anterior, migra para um data-dir novo cifrado, cria credenciais, aplica
o perfil de homologação e só conclui depois de backup, restore e restart:

```powershell
.\windows\deploy-local-homologation.ps1
```

Todos os destinos precisam ser novos; o script nunca apaga nem sobrescreve
data-dirs. Em falha, restaura ambiente, conta e binário anteriores e volta a
iniciar o serviço original. Parâmetros permitem usar caminhos diferentes.

## Variáveis relevantes

| Variável | Uso |
| --- | --- |
| `HERACLITUS_DATA_DIR` | data-dir ativo |
| `HERACLITUS_GRPC_ADDR` | gRPC; padrão `127.0.0.1:7474` |
| `HERACLITUS_REST_ADDR` | REST administrativo; sempre loopback |
| `HERACLITUS_FSYNC` | produção exige `always` |
| `HERACLITUS_CREDENTIALS_FILE` | JSON com principals, roles e hashes |
| `HERACLITUS_TOKEN_FILE` | token do cliente; nunca lido pelo servidor |
| `HERACLITUS_ENCRYPTION` | cifra por titular |
| `HERACLITUS_AUDIT_QUERIES` | meta-auditoria de consultas |
| `HERACLITUS_CONFIG` | TOML opcional lido pelo serviço |
| `HERACLITUS_PRODUCTION` | ativa gates estritos |

Fora de loopback, gRPC exige autenticação e TLS. Raft entre máquinas exige gRPC
com mTLS. O REST administrativo nunca aceita bind público.
