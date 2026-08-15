# Auditoria de produção — HeraclitusDB + Heraclitus-Forge

**Data:** 2026-08-14

**HeraclitusDB:** `1.0.5`

**Heraclitus-Forge:** `1.0.0`

**Contexto:** ingestão e custódia de logs gerais de servidores de órgão público.

## Veredicto executivo

| Escopo | Veredicto | Condição |
| --- | --- | --- |
| Código HeraclitusDB 1.0.5 | **APROVADO** | suítes integrais, análise estática e segurança verdes |
| Código Heraclitus-Forge 1.0.0 | **APROVADO** | suítes Rust/Python, assinaturas e supply chain verdes |
| Contrato DB ↔ Forge | **APROVADO** | E2E autenticado, cifrado, idempotente e recuperável |
| Registry privado do Forge | **APROVADO** | 5/5 artefatos Ed25519 válidos; repositório GitHub privado |
| Homologação local descartável | **APROVADA** | ingestão, retry, crash/restart, RBAC e inspeção física aprovados |
| Serviço Windows atualmente instalado | **PENDENTE** | UAC foi cancelado; permanece no perfil legado íntegro |
| Go-live em órgão público | **CONDICIONAL** | depende dos gates institucionais e da infraestrutura-alvo |

O software e a integração estão tecnicamente aprovados para homologação
controlada. Não existe base técnica ou jurídica para chamar o ambiente final do
órgão de aprovado antes de cumprir os gates externos deste documento. Um teste
local não substitui RIPD/LGPD, TSA/ICP-Brasil, PKI/HSM, dimensionamento,
segregação de funções e aceite formal.

## Correções aplicadas

### HeraclitusDB

- idempotência `Append` persistente e atômica, inclusive após restart;
- conflito fail-closed quando a mesma chave idempotente recebe outro payload;
- cifra de conteúdo, atributos e embeddings por `agent_id`, com
  crypto-shredding e rebuild determinístico de views;
- RBAC separado em `reader`, `writer`, `auditor` e `admin`;
- tokens armazenados apenas por hash e comparados em tempo constante;
- auditoria registra o principal autenticado, sem registrar o segredo;
- TLS/mTLS em gRPC e Raft, com recusa de configuração insegura fora de loopback;
- gates de produção para `fsync=always`, cifra, RBAC, auditoria e TSA;
- segredo REST lido por arquivo protegido, nunca por variável plaintext;
- SDK Python com token-file, mTLS, deadlines e erros gRPC normalizados;
- comandos não destrutivos `migrate-encrypt` e `init-credentials`;
- serviço Windows em conta virtual de menor privilégio, ACLs e rollback;
- backup com manifesto SHA-256, verificação e restore sem sobrescrita;
- upgrade local transacional com preservação da origem e binário anterior.

### Heraclitus-Forge e ponte

- `.hdb`, cadeia BLAKE3 e assinatura Ed25519 verificados antes da exportação;
- contrato versionado `forge-heraclitusdb/1` e fato `operational-fact/1.0`;
- atestado de custódia obrigatório e rejeição antes do primeiro `Append`;
- chave idempotente determinística e checkpoint com lock + fsync;
- retry limitado e seguro entre ACK e checkpoint;
- `actor.id`, `agent_id` e `session_id` pseudonimizados por HMAC com domínios
  distintos; origem e alvo não vazam no WAL;
- quarentena XChaCha20-Poly1305 interoperável entre Rust e Python;
- gateway, demos, loaders e dashboard em modo fail-closed por padrão;
- `bincode` removido do protocolo de rede do Forge;
- registry assinado, licença proprietária e política de segurança;
- token do writer por arquivo e TLS/mTLS obrigatório fora de loopback.

### Supply chain

- Rust fixado em `1.96.0`; fuzz fixado em `nightly-2026-02-17`;
- GitHub Actions fixadas por SHA, permissões mínimas e Dependabot;
- Gitleaks no CI e varredura integral do histórico;
- locks Rust/Python reproduzíveis; lock Python exige hashes;
- `fmt`, Clippy com `-D warnings`, Ruff e auditorias de dependência no CI.

## Evidência executada

| Prova | Resultado |
| --- | --- |
| HeraclitusDB `cargo test --workspace --all-features --locked` | aprovado, incluindo unitários, integração e doc-tests |
| HeraclitusDB `cargo fmt` e Clippy estrito | aprovado, zero warning |
| HeraclitusDB SDK Python | 6/6 aprovados; Ruff aprovado |
| Heraclitus-Forge Rust | 29/29 aprovados |
| Heraclitus-Forge Python/cross-language | 57/57 aprovados; testes `live` ficam opt-in |
| Forge Ruff | lint e formato aprovados |
| Forge registry | 5/5 assinaturas Ed25519 válidas |
| Forge `pip-audit` | nenhuma vulnerabilidade conhecida |
| Forge RustSec | 134 dependências; nenhuma ocorrência |
| HeraclitusDB RustSec | 744 dependências; nenhuma vulnerabilidade não aceita |
| Gitleaks HeraclitusDB | 231 commits e 31,49 MB; zero leak |
| Gitleaks Forge | 30 commits e 618,63 KB; zero leak |
| Fuzz sanitizado | 4.317.427 execuções; zero crash |
| Scripts Windows | todos analisados pelo parser PowerShell |

As três exceções RustSec do HeraclitusDB não representam uma vulnerabilidade
explorável conhecida neste release, mas permanecem registradas:

- `RUSTSEC-2026-0235`: `rkyv` aparece no lock histórico, mas foi provado ausente
  do grafo resolvido de build;
- `RUSTSEC-2025-0141`: `bincode` está sem manutenção; uso interno será migrado
  em evolução de formato controlada;
- `RUSTSEC-2024-0436`: `paste` é transitivo de Arrow e está sem manutenção.

## Prova E2E real DB ↔ Forge

Um servidor descartável foi iniciado com RBAC, cifra, `fsync=always` e
meta-auditoria. A ponte usou um `.hdb` assinado real.

- primeira ingestão: 9 fatos novos;
- retry imediato: 0 novos e 9 deduplicados;
- consulta: 9 fatos e cadeia de custódia completa;
- principal `writer` impedido de executar operação `admin`;
- verificação administrativa: íntegra;
- inspeção física: 77 valores sensíveis procurados e 0 encontrados em claro;
- processo morto à força para simular crash;
- restart: `head=11`, 11 registros e integridade válida;
- retry pós-crash: 0 novos e 9 deduplicados;
- consulta pós-crash: os mesmos 9 fatos;
- nova inspeção física: 77 valores e 0 ocorrências plaintext.

Essa prova cobre o caminho que será usado quando chegar um log de cliente/fonte
nova. O onboarding obrigatório está descrito no contrato do Forge e inclui
amostra minimizada, conector versionado, testes negativos/drift, assinatura,
dry-run, E2E descartável e aceite humano antes de `--apply`.

## Estado da implantação nesta máquina

O serviço existente foi preservado porque as solicitações do UAC foram
canceladas. Nenhuma troca parcial ocorreu.

- serviço `HeraclitusDB`: `Running`, inicialização automática;
- conta atual: `LocalSystem` (perfil legado, não aprovado);
- data-dir atual: `D:\HeraclitusDB\data`;
- log atual: `head=163`, 163 registros, 3 segmentos;
- CRC e raízes Merkle: válidos;
- perfil seguro ainda ausente: cifra, RBAC, `fsync=always` e meta-auditoria não
  estão ativados no serviço instalado;
- destinos seguros não foram criados; a origem continua intacta.

Binários release auditados:

| Artefato | SHA-256 |
| --- | --- |
| `heraclitus.exe` | `8676CAFD1501E7833BDB2B2BE5A5D5F667BB6AEA422CA54775B6D0795B893A69` |
| `heraclitus-server.exe` | `69D371B631600D13089939EC055A28A25588763CE17018CC135D6CCDADA1B3C0` |
| `heraclitus-service.exe` staged | `2E3ED625A47949F81FAF72FA3808499510EED823872D5C002531EB8F456A7BB1` |

Para fechar o único gate local, executar como Administrador:

```powershell
D:\DEV\HeraclitusDB\windows\deploy-local-homologation.ps1
```

O script migra para `D:\HeraclitusDB\data-encrypted-v1`, gera segredos em
`D:\HeraclitusDB\secrets-v1`, troca o binário, aplica a conta virtual, prova
backup/restore/restart e restaura o perfil anterior automaticamente em falha.

## Gates externos obrigatórios para o órgão

1. Aprovar RIPD, base legal, finalidade, minimização, retenção e descarte por
   classe de log com jurídico e encarregado LGPD.
2. Provisionar TSA RFC 3161/ICP-Brasil real e validar CMS contra raízes oficiais;
   `LocalTsa` é somente laboratório.
3. Provisionar PKI/mTLS e cofre/HSM, com identidades distintas para writer,
   auditor e admin; ensaiar rotação, expiração e revogação.
4. Executar carga, soak, failover e restore no volume alvo e aprovar RPO/RTO.
5. Aplicar hardening, EDR, firewall, SIEM, backup imutável/off-site e resposta a
   incidentes conforme as normas do órgão.
6. Aprovar humanamente cada conector/fonte e documentar o aceite.

Somente após esses seis gates e a implantação local/servidor-alvo segura o
estado pode mudar de **CONDICIONAL** para **APROVADO PARA GO-LIVE**.
