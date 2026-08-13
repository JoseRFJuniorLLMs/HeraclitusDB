# HeraclitusDB como serviço do Windows

O binário **`heraclitus-service.exe`** corre o mesmo motor do `heraclitus-server`,
mas conduzido pelo **Service Control Manager (SCM)** do Windows. Resultado: aparece
no **Gerenciador de Tarefas → aba Serviços** (e em `services.msc`), arranca sozinho
no boot, sobrevive ao logoff e responde a *start/stop* do Windows. Como um serviço
não tem consola, o **log de execução** é escrito num ficheiro rotativo diário em
`%ProgramData%\HeraclitusDB\logs`.

## 1. Compilar

```powershell
$env:PATH = "D:\DEV\tools\as-only;$env:PATH"
cargo +stable-x86_64-pc-windows-gnu build --release -p heraclitus-server --bin heraclitus-service
```

Binário: `target\release\heraclitus-service.exe`.

## 2. Instalar e arrancar (pede UAC uma vez)

```powershell
cd D:\DEV\HeraclitusDB\windows
.\heraclitus-service.ps1 install
```

O script auto-eleva, regista o serviço (auto-start) e arranca-o.

## 3. Ver o log de execução em tempo real

```powershell
.\heraclitus-service.ps1 logs        # segue o log (Ctrl+C para sair)
.\heraclitus-service.ps1 status      # estado + PID
```

## 4. Parar / remover

```powershell
.\heraclitus-service.ps1 stop
.\heraclitus-service.ps1 uninstall
```

## Comandos nativos do Windows (equivalentes)

```powershell
Start-Service HeraclitusDB
Stop-Service  HeraclitusDB
Get-Service   HeraclitusDB
sc.exe query  HeraclitusDB
```

Ou diretamente pelo binário (PowerShell **como Administrador**):

```powershell
.\target\release\heraclitus-service.exe install
.\target\release\heraclitus-service.exe uninstall
.\target\release\heraclitus-service.exe console   # primeiro plano, para debug
.\target\release\heraclitus-service.exe status
```

## Configuração

O serviço não recebe argumentos do SCM; configura-se por **variáveis de ambiente
de sistema** (ou aceita os padrões). As variáveis são lidas no arranque:

| Variável | Padrão (serviço) | Função |
|---|---|---|
| `HERACLITUS_DATA_DIR` | `%ProgramData%\HeraclitusDB\data` | log append-only + views |
| `HERACLITUS_GRPC_ADDR` | `127.0.0.1:7474` | endpoint gRPC |
| `HERACLITUS_REST_ADDR` | `127.0.0.1:7475` | endpoint REST (admin) |
| `HERACLITUS_LOG_DIR` | `%ProgramData%\HeraclitusDB\logs` | log de execução |
| `HERACLITUS_FSYNC` | `always` | `always` ou `group_commit:<ms>` |

Para mudar uma porta de forma persistente para o serviço:

```powershell
[Environment]::SetEnvironmentVariable('HERACLITUS_GRPC_ADDR','0.0.0.0:7474','Machine')
Restart-Service HeraclitusDB
```

## Notas

- O serviço corre como **LocalSystem**. Os caminhos default vivem em
  `%ProgramData%` justamente para o serviço nunca escrever em `System32`
  (o diretório de trabalho que o SCM impõe).
- A paragem é **graciosa**: o SCM envia `Stop`, que é encaminhado para um
  *shutdown* limpo do `serve()` (fecha o gRPC, aborta o REST) — sem perda de
  escritas confirmadas, fiel à durabilidade do log.
