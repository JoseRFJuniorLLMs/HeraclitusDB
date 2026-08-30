# heraclitus-qualifier

Implementação da suíte de qualificação da SPEC-0049. O binário executa planos
de laboratório, captura o ambiente e o grafo de build, liga todo resultado ao
SHA-256 exato do binário e sela o dossiê com um índice Merkle. O diretório de
saída deve ser novo; nenhum comando sobrescreve evidência anterior.

O qualificador separa duas afirmações diferentes:

- **suíte implementada**: automação, políticas, workloads, corrupção,
  manifests, atestações e verificação existem;
- **release qualificada**: todos os gates exigidos para aquele nível possuem
  evidência válida para o binário informado.

Assim, executar um plano governamental sem power-loss físico, red team ou
air-gap produz corretamente `Unqualified` (exit code 2), nunca um falso PASS.

## Uso

```powershell
cargo run --offline -p heraclitus-qualifier -- gates --level government-production

# --profile corre um plano do repositório sem editar código (§110), para que um
# terceiro consiga reproduzir a execução tal como está publicada.
cargo run --offline -p heraclitus-qualifier -- run `
  --profile gov-production --out qa-evidence/gov-20260829 `
  --history qa-evidence/qualification-history.jsonl

cargo run --offline -p heraclitus-qualifier -- verify `
  --evidence qa-evidence/gov-20260829 `
  --binary target/release/heraclitus-server.exe
```

`--binary` re-calcula o SHA-256 e exige que seja o binário qualificado. §121: um
binário alterado depois da qualificação perde-a, e isto transforma essa frase
num erro em vez de uma promessa.

### Ensaios

```powershell
# dataset SOC determinístico + manifesto de proveniência
cargo run --offline -p heraclitus-qualifier -- workload `
  --profile mixed --seed 428931 --events 100000 --out workload.jsonl

# Q1 contra um deployment real: ramp 10..150%, seis lanes e verify final
cargo run --offline -p heraclitus-qualifier -- load `
  --target http://127.0.0.1:7474 --profile mixed --seed 428931 `
  --operations-per-stage 10000 --concurrency 32 --report q1-load.json

# Q2: arranca o BINÁRIO DE RELEASE, carrega, mata-o a meio, reabre e relê
# TODOS os appends que o servidor confirmou. É a §24 executada, não descrita.
cargo run --offline -p heraclitus-qualifier -- crash-loop `
  --server-binary target/release/heraclitus-server.exe `
  --root qa-evidence/crash-run --cycles 50 --durability always `
  --report q2-crash.json

# Soak com o gate de fuga da §20: ignora a janela de aquecimento e ajusta a
# reta só ao troço estabilizado, para separar cache a encher de fuga.
cargo run --offline -p heraclitus-qualifier -- soak `
  --target http://127.0.0.1:7474 --pid <pid do servidor> `
  --profile qa/qualification/soak/24h.json --report soak-24h.json

# Zero egress no próprio host (§97-§98)
cargo run --offline -p heraclitus-qualifier -- egress-monitor `
  --program ./install.ps1 --duration-seconds 900 --report egress.json

# corrupção sempre aplicada a uma cópia, nunca ao input
cargo run --offline -p heraclitus-qualifier -- corrupt `
  --input segment.hrkl --output corrupted.hrkl --mode flip-bit --seed 42

# SBOM CycloneDX determinístico do grafo Cargo.lock
cargo run --offline -p heraclitus-qualifier -- sbom --out bom.cdx.json
```

### Configuração, histórico, regressão e painel

```powershell
# §138-§140 — uma release qualificada não torna toda a configuração segura.
# Lê o TOML em BRUTO: uma chave mal escrita (tls_key em vez de tls_key_path)
# aparece como Blocking em vez de virar um servidor silenciosamente sem TLS.
cargo run --offline -p heraclitus-qualifier -- doctor --config heraclitus.toml

# §109 — histórico append-only. Não existe comando para apagar, e é a
# funcionalidade: uma falha corrigida continua no registo.
cargo run --offline -p heraclitus-qualifier -- history record `
  --evidence qa-evidence/gov-20260829 --history qa-evidence/qualification-history.jsonl
cargo run --offline -p heraclitus-qualifier -- history list `
  --history qa-evidence/qualification-history.jsonl

# §126-§129 — regressão contra um baseline, com orçamentos declarados à parte.
cargo run --offline -p heraclitus-qualifier -- regression `
  --baseline qa-evidence/<golden> --candidate qa-evidence/<novo> `
  --budgets qa/qualification/regression-budgets.json --out regression.json

# §108 — contrato de dados do painel. Métrica que não foi medida sai `null`,
# para o painel poder distinguir SEM INCIDENTES de DADOS INDISPONÍVEIS (§135).
cargo run --offline -p heraclitus-qualifier -- dashboard `
  --evidence qa-evidence/gov-20260829 --out dashboard.json
```

## Planos e atestações

- `qa/qualification/plans/development.toml`: CI, integração, lint e fuzz curto.
- `qa/qualification/plans/lab-preflight.toml`: corre **tudo o que o projeto
  consegue correr sozinho** — inclui crash-loop contra o binário e o doctor da
  configuração. Nível `development`, de propósito: exercita a automação, não
  qualifica a release.
- `qa/qualification/plans/release-candidate.toml`: adiciona benchmark, crash,
  upgrade, SBOM e assinatura.
- `qa/qualification/plans/government-production.toml`: enumera todos os gates
  governamentais e consome atestações assinadas de laboratório.

Uma atestação externa só passa quando:

1. o `gate_id`, release e SHA-256 do binário coincidem;
2. todos os artefatos declarados existem e possuem tamanho/hash corretos;
3. um verificador criptográfico configurado retorna sucesso;
4. a própria atestação declara `passed`.

Os stdout/stderr do verificador, a assinatura e cada artefato atestado são
copiados para o dossiê antes do selo final.

## Saída

Cada execução produz, no mínimo:

```text
qualification-plan.toml
qualification-manifest.json
environment-manifest.json
build-manifest.json
qualification-result.json
qualification-report.md
qualification-commitment.json
trials/<gate>/...
evidence-index.json
evidence-index.sha256
```

`verify` recusa arquivos adicionados, removidos ou alterados; confere os
sidecars, o Merkle root, a identidade da release e o invariante de status.

### O compromisso (§121-§122)

A vinculação é feita em duas camadas, e a razão é uma circularidade que se
resolve por ordem, não por engenho:

1. `qualification-commitment.json` é escrito **antes** do selo e cobre o binário
   da release, o build manifest, o resultado, o relatório e o SBOM. Depois disso
   ele próprio é um artefacto, e o Merkle root passa a cobrir o compromisso.
2. O `evidence_root` não pode aparecer dentro do ficheiro que ele hasheia, por
   isso o triplo da §122 (`release_digest`, `evidence_root`, `report_digest`) é
   **derivado** na verificação, a partir do índice selado.

Pôr a raiz dentro do ficheiro que a produz seria circular, e uma raiz
autorreferente que ninguém consegue recomputar não é um compromisso.

## O que o dossiê NÃO prova

Três limites que o próprio código declara nos relatórios, para que ninguém os
descubra tarde:

- **`crash-loop` não é power-loss** (§25). Matar o processo deixa a page cache
  do SO intacta. O gate `power_loss` é um ensaio separado, atestado por fora.
- **`egress-monitor` prova egress, não a ausência dele** (§98). Amostra tabelas
  de sockets; uma ligação que abre e fecha entre duas amostras não deixa rasto.
  A ausência prova-se com o tap de rede independente.
- **`source_digest` cobre apenas ficheiros versionados.** Um clone do commit
  contém exatamente esses; incluir ficheiros não versionados produzia um digest
  que nenhum terceiro conseguia recomputar (§111). O estado não versionado é
  reportado — `untracked_files` no manifesto — e vira limitação declarada acima
  de Development.

O script `heraclitus-qualifier.ps1` permanece apenas como runner legado de Q2;
novas qualificações devem usar o binário Rust.
