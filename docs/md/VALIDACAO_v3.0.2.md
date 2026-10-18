# Validação — HeraclitusDB v3.0.2

Ramo `release/v3.0.2`, base `main` em `122a8d7`. Notas da versão em
[RELEASE_NOTES_v3.0.2.md](RELEASE_NOTES_v3.0.2.md).

## O que a versão integra

| Origem | Conteúdo | Commit |
|---|---|---|
| `fix/auditoria-2026-10-16-b1-b2-b5-b6` (já em `main`) | B1, B2, B5, B6 no `heraclitus-log` | `122a8d7` |
| `claude/top-auditoria-b4-b9-r1` | B4, B9, R1 e falso-verde no `heraclitus top` | merge `1c2aff4` |
| trabalho do GPT por commitar no checkout principal | G1–G7 e versão 3.0.2 | `d61bb11` |
| trabalho da sessão B3 por commitar | B3, `ts_hlc` no apply do Raft | `02a5842` |
| esta release | stubs Python, `quinn-proto`/`rustls`, fmt e teste do G1 | `be85243`, `e5f135f`, `d23c983` |

O trabalho que estava por commitar ficou salvaguardado, inalterado, nos ramos
`wip/checkout-principal-2026-10-18` (inclui o WIP B7, que **não** entra) e
`wip/b3-raft-ts-hlc-2026-10-18`.

## Execução local (Windows, toolchain 1.96.0)

| Verificação | Resultado |
|---|---|
| `cargo check --workspace --all-targets` | sem erros nem avisos |
| `cargo fmt --all --check` | limpo |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings -D clippy::debug_assert_with_mut_call` | limpo |
| `cargo test -p heraclitus-log` | 373 aprovados, 0 reprovados |
| `cargo test -p heraclitus-index-attr` | 30 aprovados |
| `cargo test -p heraclitus-index-graph` | 57 aprovados |
| `cargo test -p heraclitus-index-vector` | 32 aprovados |
| `cargo test -p heraclitus-query` | 86 aprovados (70 unitários + integração) |
| `cargo test -p heraclitus-cli` | 39 aprovados |
| `cargo test -p heraclitus-server` | 158 aprovados |
| `cargo test -p heraclitus-raft --features replication` | 29 aprovados |
| `cargo test -p heraclitus-server --features replication --lib cluster::` | 5 aprovados |
| `cargo audit --deny warnings` (com as exceções documentadas do CI) | limpo |
| passos rkyv e chave privada RSA do job `supply-chain` | passam |
| SDK Python: geração dos stubs, `ruff check`, `ruff format --check`, `pytest`, `pip-audit --strict` | sem drift; 6 testes; sem vulnerabilidades |

Sabotagem:

- B1/B2/B5/B6: ver
  [CORRECOES-AUDITORIA-2026-10-16-B1-B2-B5-B6.md](../CORRECOES-AUDITORIA-2026-10-16-B1-B2-B5-B6.md)
  (15 mutações no código, 5 no veto do footer).
- B3: sem o carimbo no apply,
  `ts_hlc_replicado_carimbado_monotono_e_igual_nos_tres_nos` falha com
  `ts_hlc a 0: [0, 0, 0, 0, 0]`, o defeito da auditoria.

Uma regressão encontrada e corrigida na integração:
`heraclitus-query::tests::edge_match_ordena_antes_do_limit` fixava a ordem
lexicográfica dos ids de relação no formato antigo; com os ids `e2` do G1 o
maior id é outro. O teste passou a conferir a ordem contra os próprios ids.

## Não coberto localmente

- A suíte `cargo test --workspace --all-features` completa e os gates Linux
  (release, crash injection, `v2_compat`, GPU build) correm no CI do GitHub
  (`CI`, em pushes para `release/**` e `main`).
- Os binários assinados, o SBOM e a proveniência são produzidos pelo workflow
  `Release supply chain` quando a release é publicada.
- Qualificação longa (soak, nightly) e plataformas além de Windows/Linux.
