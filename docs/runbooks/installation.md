# Instalação

Pré-requisitos, sequência, e a validação que prova que ficou instalado — não
que os ficheiros foram copiados.

## 1. Verificar o artefacto antes de o abrir

Nunca instale um pacote que não verificou. O bundle traz o seu próprio digest e
a proveniência Sigstore.

```bash
sha256sum -c heraclitus-<versão>-linux-x86_64.tar.gz.sha256
gh attestation verify heraclitus-<versão>-linux-x86_64.tar.gz --repo <owner>/HeraclitusDB
```

Num ambiente sem rede, use o bundle offline e o `Test-OfflineBundle.ps1`:

```powershell
./qa/qualification/harness/Test-OfflineBundle.ps1 -BundlePath <caminho>
```

Se a assinatura ou o digest não conferem, **pare aqui**. Um artefacto que não
verifica não se instala "só para testar".

## 2. Escolher o formato de armazenamento

`storage_format = "v6"` é o default e é o que se quer numa instalação nova.
`"legacy"` só faz sentido quando já existem recibos RFC 3161 emitidos sobre a
raiz física antiga — nesse caso leia [upgrade.md](upgrade.md) antes de migrar.

Os dois layouts **recusam abrir a raiz um do outro**, de propósito. Uma
instalação nova nunca vê esse erro; uma atualização mal feita vê-o logo no
arranque, que é onde deve ver.

## 3. Escrever a configuração

Comece por `qa/qualification/configs/reference-loopback.toml` e endureça-o. Uma
instalação governamental precisa, no mínimo:

```toml
data_dir = "/var/lib/heraclitus"
storage_format = "v6"
segment_max_bytes = 8388608          # dentro da janela medida de 4-16 MiB

grpc_addr = "0.0.0.0:7474"
rest_addr = "127.0.0.1:7475"         # admin fica em loopback

tls_cert_path = "/etc/heraclitus/tls/server.crt"
tls_key_path  = "/etc/heraclitus/tls/server.key"
tls_client_ca_path = "/etc/heraclitus/tls/clients-ca.crt"   # mTLS

production_mode = true
encryption_at_rest = true
audit_queries = true
telemetry_interval_secs = 0

[fsync]
mode = "always"
```

As credenciais **não** se escrevem à mão. Gere-as:

```bash
heraclitus init-credentials /etc/heraclitus/credentials   # ESCREVE
```

Isto produz `credentials.json` e os tokens em ficheiros separados, sem os
imprimir no terminal — o histórico da shell é o sítio errado para um token de
Admin.

## 4. Qualificar a configuração antes de arrancar

Uma release qualificada não torna toda a configuração segura (§138). Corra o
doctor contra a **sua** configuração:

```bash
heraclitus-qualifier doctor --config /etc/heraclitus/heraclitus.toml
```

Exit code 0 e `blocking=0` é o requisito para prosseguir. O doctor lê o TOML em
bruto, por isso apanha o erro que um parser tipado engole: uma chave mal
escrita como `tls_key` em vez de `tls_key_path` aparece como **Blocking**, e
não como um servidor silenciosamente sem TLS.

## 5. Arrancar

Linux (systemd) ou Windows (SCM):

```powershell
./windows/heraclitus-service.ps1 install -BinaryPath $BIN\heraclitus-service.exe -ConfigPath C:\ProgramData\Heraclitus\heraclitus.toml
Start-Service HeraclitusDB
```

## 6. Provar que está instalado

Copiar ficheiros não é instalar. Estes quatro passos são o critério de aceite:

```bash
curl -fsS http://127.0.0.1:7475/healthz          # panta rhei
curl -fsS http://127.0.0.1:7475/stats            # storage_format, head
heraclitus storage doctor $DATA                  # status: CLEAN
heraclitus verify $DATA --logical                # raiz canónica confere
```

Depois escreva e leia de facto — um servidor que arranca e não aceita escritas
passa nos três primeiros:

```bash
heraclitus-qualifier load --target http://127.0.0.1:7474 \
    --profile mixed --operations-per-stage 200 --concurrency 4 \
    --ramp-percent 100 --report /tmp/install-smoke.json
```

## 7. Antes de declarar o serviço em produção

- [ ] backup configurado e **um restore já testado** ([restore.md](restore.md)) —
      §PQ7: um backup sem restore testado não é um backup;
- [ ] rotação de certificados agendada ([certificate-rotation.md](certificate-rotation.md));
- [ ] `heraclitus-qualifier doctor` sem findings Blocking;
- [ ] relógio do host sincronizado (o doctor não consegue verificar isto por si
      — anexe a atestação de time-sync ao gate `runbooks`).
