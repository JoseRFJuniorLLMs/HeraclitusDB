# Validação — HeraclitusDB v3.0.3

Ramo `release/v3.0.3`, base `main` em `16c84dc` (v3.0.2). Notas em
[RELEASE_NOTES_v3.0.3.md](RELEASE_NOTES_v3.0.3.md); a validação da v3.0.2,
que esta versão inclui, está em [VALIDACAO_v3.0.2.md](VALIDACAO_v3.0.2.md).

## Porque existe

A publicação da release v3.0.2 disparou o workflow `Release supply chain`
(run 39171377572), que falhou no passo *Qualify the extracted Linux package by
killing and restarting it* por exceder o limite de 30 minutos. Nada foi
assinado nem anexado.

Diagnóstico:

1. Os registos do servidor no artefacto `rc-qualification-failure` mostram cada
   arranque pronto em ~0,5 s e sem erros, mas cada ciclo de 3 a 4 minutos (12
   ciclos em 30 minutos). Na v3.0.0 os 40 ciclos levaram 1 min 38 s.
2. O nightly `release-binary-crash-loop` mostra o crash-loop rápido em 24/09 e
   02/10 e com 61 minutos em 16/10. Entre os dois há um único commit,
   `cda5ba5`.
3. Cada ciclo verifica cada append confirmado com
   `MATCH (n) WHERE n.lsn = X RETURN n LIMIT 1`. Medido: ~45 ms por consulta
   via gRPC, ~0,4 ms dentro do processo; `Snapshot` (pedido vazio) 1,7 ms. Um
   perfil com `perf` mostra o servidor quase parado durante as consultas: era
   espera, não CPU.
4. `cda5ba5` passou o servidor gRPC a `serve_with_incoming_shutdown` sobre um
   listener próprio, onde o `tcp_nodelay(true)` do builder não se aplica. Nagle
   ligado mais ACK atrasado dá os ~40 ms.

## Execução

| Verificação | Resultado |
|---|---|
| Latência gRPC (SDK Python → servidor de release no WSL) | `Query` 44,8 → 2,6 ms; `admin stats` 49,5 → 7,8 ms; `Snapshot` 1,7 → 1,5 ms |
| Crash-loop de 8 ciclos no WSL (concorrência 8, `fsync always`) | 136 s (base `16c84dc`) → 21 s, appends confirmados equivalentes, 0 em falta |
| Crash-loop de 40 ciclos no WSL com os parâmetros do workflow | condição `jq` do workflow satisfeita (verificado em Python) |
| `cargo test -p heraclitus-log` | 374 aprovados |
| `cargo test -p heraclitus-server` | 159 aprovados |
| `cargo test -p heraclitus-agent-gateway` | 78 aprovados |
| `cargo test -p heraclitus-raft --features replication` | 30 aprovados |
| `cargo test -p heraclitus-client` | 3 aprovados |
| `cargo clippy` dos cinco crates, `--all-targets --all-features -D warnings` | limpo |
| `cargo fmt --all --check` | limpo |

Sabotagem:

| Retirado | Teste que falha |
|---|---|
| `with_nodelay` no servidor gRPC/Flight | `os_sockets_aceites_pelo_grpc_tem_tcp_nodelay` |
| `set_nodelay` no transporte Raft | `os_sockets_aceites_pelo_transporte_tem_tcp_nodelay` |
| `with_nodelay` no OTLP/gRPC | `os_sockets_aceites_pelo_otlp_grpc_tem_tcp_nodelay` |
| offset de partida na cauda | `consulta_pontual_por_lsn_le_um_registo_e_nao_o_segmento` |
| paragem no fim da janela na cauda | idem |
| paragem no fim da janela no RAW selado | idem |

Um teste de latência ponta a ponta com cliente e servidor no mesmo processo
não reproduziu o atraso (a resposta sai numa única escrita) e foi descartado:
não falhava com a correção retirada. Os testes ficaram no ponto onde o defeito
está, a opção no socket aceite.

A correção de leitura pontual na cauda é independente da latência: não muda o
tempo do gate (a regressão era a espera de rede), mas tira uma leitura de até
8 MiB por consulta pontual.

## Não coberto localmente

- A suíte completa (`cargo test --workspace --all-features`) e os gates Linux
  correm no CI do PR.
- Os binários assinados, o SBOM e a proveniência são produzidos pelo workflow
  `Release supply chain` na publicação.
