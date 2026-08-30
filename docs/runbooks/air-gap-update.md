# Atualização air-gapped

Atualizar sem rede. Implementa SPEC-0049 §94–§100.

## A regra que define o ambiente

§97: uma instalação air-gapped **não pode tentar** DNS, download de pacotes,
verificação de licença, telemetria, verificação de updates ou descoberta remota
de modelos. Não "não deve conseguir" — não pode *tentar*. Uma tentativa
falhada é na mesma uma tentativa, e §98 trata qualquer ligação não autorizada
como reprovação do gate.

Na configuração, isso traduz-se em:

```toml
telemetry_interval_secs = 0
compliance_tsa_mode = "offline"     # se compliance estiver ligada
v6_lakehouse_path = "/var/lib/heraclitus-lakehouse"   # local, nunca s3:// ou gs://
```

O `heraclitus-qualifier doctor` assinala cada um destes como Warning de air-gap
quando aponta para fora.

## Preparar o bundle (fora do air gap)

```powershell
./release/New-OfflineBundle.ps1 -Version <versão> -OutputDirectory <destino>   # ESCREVE
```

O bundle traz binários, dependências, SBOM, manifestos, assinaturas, âncoras de
confiança e documentação. Transporte-o pelo meio aprovado (suporte físico
controlado, com cadeia de custódia registada — o suporte faz parte da prova).

## Verificar **antes** de instalar, dentro do air gap

§96: assinatura do bundle, assinatura do manifesto, hashes dos artefactos,
integridade do SBOM e compatibilidade de versão têm de ser verificáveis
**localmente**, sem chamar ninguém.

```powershell
./qa/qualification/harness/Test-OfflineBundle.ps1 -BundlePath <caminho>
```

Se falhar, pare. Um bundle que não verifica dentro do air gap não se instala
"porque veio do sítio certo" — o ponto do air gap é não confiar na proveniência
declarada.

## Sequência do update (§99)

```text
estado atual
   ↓
verificar bundle          ← já feito acima
   ↓
preflight                 ← heraclitus-qualifier doctor contra a config atual
   ↓
BACKUP                    ← backup.md, verificado
   ↓
upgrade                   ← upgrade.md
   ↓
validar                   ← storage doctor + verify + escrita real
```

O backup entre o preflight e o upgrade não é opcional: sem rede, não há
"descarregar outra vez a versão anterior".

## Provar zero egress

Duas linhas de defesa, e a distinção entre elas importa.

**No host**, o monitor observa as sockets do processo:

```bash
heraclitus-qualifier egress-monitor \
    --program ./install.sh \
    --duration-seconds 900 --sample-interval-ms 200 \
    --report egress.json
```

Ele **prova que houve egress** — um avistamento de um endpoint remoto fora da
allowlist reprova, com timestamp. Ele **não prova que não houve**: amostra
tabelas de sockets, por isso uma ligação que abre e fecha entre duas amostras
não deixa rasto. O próprio relatório declara essa limitação.

**Fora do host**, o tap de rede independente é o que prova a ausência. É essa
atestação assinada que o gate `zero_egress` consome:

```powershell
./qa/qualification/harness/Invoke-AirgapQualification.ps1 `
    -MonitorReport <relatório do isolador> -OutputDirectory <evidência>
```

Confundir os dois é o erro que torna uma qualificação de air gap inútil.

## Rollback offline (§100)

Quando o rollback é suportado, tem de ser possível **sem internet**. Isso
significa manter, dentro do air gap:

- o binário da versão anterior, com o digest;
- o backup pré-upgrade, verificado;
- a keystore correspondente.

Sem os três, "rollback suportado" é uma afirmação sobre o software que a
instalação não consegue exercer. Ver [rollback.md](rollback.md).

## Fecho

Registe, para o gate `airgap_update`:

- digest do bundle e resultado da verificação local;
- relatório de egress do host **e** do tap independente;
- backup usado e resultado do restore drill mais recente;
- validação pós-update.
