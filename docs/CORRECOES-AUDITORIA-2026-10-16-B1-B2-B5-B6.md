# Auditoria 2026-10-16 — correções B1, B2, B5 e B6

Base: `79c9fa5`. Trabalho no ramo `fix/auditoria-2026-10-16-b1-b2-b5-b6`,
em `D:\tmp\heraclitus-b1b2b5b6`. O WIP do diretório principal não foi incorporado
nem editado. A correção tem três commits:

1. `917732c` — a correção inicial;
2. `f758a81` — continuação que retirou duas proteções de `917732c` (a exceção
   dos bytes zerados e o veto do footer no EOF) e concluiu a validação;
3. o commit que repõe o **veto do footer no EOF**, por decisão do responsável
   (perda silenciosa de um registro confirmado é P0; recusa de arranque sem
   perda é P2). A exceção dos bytes zerados continua retirada.

## Comportamento

- **B1/B5:** V6 e legado usam a mesma classificação de escrita incompleta.
  Um frame completo com CRC inválido causa `Corruption`, sem alterar os bytes.
  Um comprimento que passa do EOF só permite truncar quando a ressincronização
  não encontra registros íntegros posteriores com LSN esperado + k.
  Cabeçalhos ou footers parcialmente escritos continuam recuperáveis.
- **Fronteira do footer:** só um footer alcançado pelo percurso dos registros
  pode selar. Uma imagem no payload de um frame interrompido nunca sela.
- **Veto do footer no EOF (reposto):** se, depois do rasgo, um footer íntegro
  fecha o arquivo e declara o LSN que o frame rasgado devia ter, há história
  confirmada depois do rasgo: é um `.active` que caiu entre o seal e o rename,
  com o `payload_len` do último registro estragado para lá do EOF. O arranque
  recusa com `Corruption` (`a valid footer at EOF declares LSNs …`), sem
  truncar. Sem o veto, o último registro confirmado e o footer que o prova eram
  cortados em silêncio e o LSN voltava a ser atribuído. Vale no V6 e no legado.
  A imagem da sonda B5 (`record_count = 0`) não declara LSN nenhum e continua
  sendo cauda: recupera.
- **Preço do veto, aceito de propósito:** o CRC do footer não tem chave, e um
  cliente pode pôr no payload uma imagem que declare o LSN do próprio registro.
  Se um crash cortar essa escrita exatamente depois da imagem, o arranque recusa
  em vez de truncar — falha fechada, sem alterar bytes. O operador corta o
  arquivo no offset do rasgo indicado no erro e o arranque volta (coberto por
  teste).
- **Bytes zerados:** removida a exceção de `917732c`. Um frame zerado que cabe
  no arquivo não declara extensão além do EOF e é preservado como corrupção.
- **B2:** o percurso RAW informa por que terminou; um selado precisa alcançar
  o footer com sua contagem de registros. Varreduras limitadas podem parar
  deliberadamente após entregar o limite. A janela pedida abaixo do head do
  instantâneo deve ser contígua, e uma leitura pontual abaixo do head retorna
  o registro ou um erro. A varredura filtrada também verifica os RAW selados e
  a cobertura/ordem dos LSN da cauda sob o mutex do writer.
- **B6:** cada falha é registrada com o segmento; packing e HRKI continuam os
  demais trabalhos. Os resultados bem-sucedidos são publicados, o segmento
  defeituoso permanece pendente e o primeiro erro é devolvido ao fim da rodada.
  Um CRC inválido no packer indica o offset e a causa, sem diagnosticá-lo como
  um segmento por selar.

## Regressões

As quatro sondas V6 da auditoria foram convertidas em regressões em
[`hrkl_v6_bitrot_nao_trunca.rs`](../crates/heraclitus-log/tests/hrkl_v6_bitrot_nao_trunca.rs).
O cenário B1 de reabertura está separado do cenário B2 de leitura da cauda,
para que uma asserção não impeça a execução da outra prova. Há cobertura
adicional para a fila HRKI, recuperação do legado, ressincronização por LSN,
footer sem fronteira, bytes zerados e término/contagem de um percurso selado.

O veto do footer tem quatro regressões:

| Teste | O que prova |
|---|---|
| `rasgo::tests::footer_no_eof_so_veta_se_declarar_o_lsn_esperado` | A regra veta só quando o footer declara o LSN esperado; um footer que acaba antes dele, ou vazio, não veta. |
| `v6::raw::tests::comprimento_estragado_no_ultimo_registo_de_um_selado_nao_e_truncado` | V6: `.active` selado com o comprimento do último registro estragado recusa, não sela e fica intacto. |
| `bitrot_nao_trunca::comprimento_estragado_no_ultimo_registo_de_um_selado_recusa_abrir` | Legado: o último segmento selado no mesmo caso recusa abrir e fica intacto (com contraprova de que abre sem a corrupção). |
| `hrkl_v6_bitrot_nao_trunca::imagem_de_footer_que_declara_o_lsn_cortado_recusa_sem_perda` | O preço: a imagem forjada que declara o LSN recusa sem alterar bytes, e cortar no rasgo devolve o arranque. |

`cauda_rasgada_com_imagem_de_footer_no_payload_recupera` voltou a ser só a
sonda B5 original (`record_count = 0`), que recupera; o caso `record_count = 2`
que `f758a81` lhe tinha juntado é o teste do preço acima.

## Validação

Ambiente: Windows, `CARGO_TARGET_DIR=D:\tmp\heraclitus-b1b2b5b6-target`,
`TEMP=TMP=D:\tmp`, `CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`. O diretório
temporário padrão do sandbox produzia `PermissionDenied` em operações de
armazenamento; os testes foram executados novamente com o temporário acima,
sem modificar o produto para contornar o ambiente.

### Código antigo reposto

O arquivo de regressões V6 foi copiado, sem alterações, para o worktree auxiliar
em `79c9fa5`. Executado:

```powershell
cargo test -p heraclitus-log --offline --test hrkl_v6_bitrot_nao_trunca -- --test-threads=1
```

Resultado: **0 aprovados, 7 reprovados**, por asserções dos defeitos, com
compilação concluída normalmente. Inclui as quatro sondas invertidas:

| Defeito | Resultado observado em `79c9fa5` |
|---|---|
| B1 | Reabertura aceita corrupção e reduz o head de 100 para 33. |
| B2 | Scan retorna `Ok` com 187 de 200 linhas. |
| B5 | Imagem de footer dentro da escrita incompleta impede a reabertura. |
| B6 | Packer retorna o diagnóstico enganoso `unsealed`; a regressão isolada da fila é comprovada por S12. |
| B2, cauda | Scan aceita um registro confirmado corrompido. |
| B2, LSN | Frames íntegros com LSN duplicado são aceitos apesar do LSN ausente. |
| B6, HRKI | Fila restante `[1, 2, 3, 4, 5, 6]`, em vez de somente `[1]`. |

### Sabotagem isolada

Cada mutação foi aplicada individualmente ao código corrigido e desfeita ao
terminar o teste, inclusive em caso de falha do comando. Só foi aceita como
prova uma execução que compilou, rodou exatamente o teste escolhido e falhou
por asserção; falha de compilação ou `PermissionDenied` não conta.

**15/15 mutações detectadas**, todas com saída 101 do `cargo test`:

| # | Proteção removida ou sabotada | Regressão que falhou |
|---|---|---|
| S1 | Classificação da cauda no reparo V6 | `bitrot_no_meio_da_cauda_activa_nao_trunca_confirmados` |
| S2 | Classificação da cauda no legado | `bitrot_no_meio_do_segmento_ativo_recusa_abrir_em_vez_de_truncar` |
| S3 | Rejeição de frame completo com CRC inválido | `rasgo::tests::frame_que_cabe_e_corrupcao` |
| S4 | Ressincronização por LSN após comprimento inválido | `comprimento_estragado_a_meio_da_cauda_nao_e_truncado` |
| S5 | Footer no payload passa a selar a escrita incompleta | `cauda_rasgada_com_imagem_de_footer_no_payload_recupera` |
| S6 | Percurso selado aceita EOF/rasgo sem footer | `percurso_em_streaming_para_na_cauda_rasgada_como_o_varrimento` |
| S7 | Percurso ignora contagem divergente no footer | `percurso_selado_exige_footer_e_contagem_mesmo_com_todos_os_payloads_legiveis` |
| S8 | Leitura RAW selada volta a retornar `Ok(None)` abaixo do head | `bitrot_em_raw_selado_falha_alto_no_scan_e_no_read` |
| S9 | Scan deixa de exigir janela contígua | `bitrot_na_cauda_falha_no_scan_no_read_e_no_scan_filtrado` |
| S10 | Scan filtrado deixa de exigir cobertura da cauda | `bitrot_na_cauda_falha_no_scan_no_read_e_no_scan_filtrado` |
| S11 | Scan filtrado deixa de exigir footer do RAW selado | `bitrot_em_raw_selado_falha_alto_no_scan_e_no_read` |
| S12 | Packing interrompe a fila no primeiro erro | `um_raw_corrompido_nao_trava_a_fila_de_packing` |
| S13 | Packer volta a diagnosticar CRC como `unsealed` | `um_raw_corrompido_nao_trava_a_fila_de_packing` |
| S14 | HRKI interrompe a fila no primeiro erro | `um_packed_corrompido_nao_trava_a_fila_de_hrki` |
| S15 | Scan filtrado conta frames sem conferir seus LSN | `lsn_duplicado_com_crc_integro_na_cauda_nao_esconde_um_confirmado` |

S12 e S14 reproduzem a fila residual `[1, 2, 3, 4, 5, 6]`, em vez de `[1]`.
S1 e S2 reproduzem o head 33 em vez de 100. S8 reproduz `read(87) = Ok(None)`
abaixo do head 200. A restauração do código é seguida pela suíte completa.

### Sabotagem do veto do footer

Mesmo método, sobre o código com o veto reposto, correndo `--lib` e os testes
`hrkl_v6_bitrot_nao_trunca`, `bitrot_nao_trunca` e `hrkl_v6_crash`. Todas
compilaram e saíram com 101:

| # | Sabotagem | Regressões que falharam |
|---|---|---|
| V1 | A regra deixa de consultar o footer no EOF | as quatro regressões do veto |
| V2 | V6: `footer_declara` nunca declara | `comprimento_estragado_no_ultimo_registo_de_um_selado_nao_e_truncado`, `imagem_de_footer_que_declara_o_lsn_cortado_recusa_sem_perda` |
| V3 | Legado: `footer_declara` nunca declara | `comprimento_estragado_no_ultimo_registo_de_um_selado_recusa_abrir` |
| V4 | Veto sem limite superior (`min <= esperado`) | `footer_no_eof_so_veta_se_declarar_o_lsn_esperado` |
| V5 | V4 + V6 sem o filtro `record_count > 0` | `cauda_rasgada_com_imagem_de_footer_no_payload_recupera` (o veto engoliria a sonda B5) |

Na V4 sozinha a sonda B5 continua recuperando porque a imagem também é
excluída pelo filtro `record_count > 0`: são duas condições independentes, e
a V5 mostra que o teste B5 parte quando ambas faltam.

### Verificações finais

| Verificação | Resultado |
|---|---|
| `cargo test -p heraclitus-log --offline` | Saída 0: **371 aprovados, 0 reprovados**; inclui testes de crash, concorrência e as regressões. |
| `cargo fmt --check` | Saída 0, sem diferenças. |
| `cargo clippy -p heraclitus-log --all-targets --offline -- -D warnings` | Saída 0, sem avisos. |
| `git -c core.whitespace=trailing-space,space-before-tab,cr-at-eol diff --check` | Saída 0; respeita os CRLF já existentes em `raw.rs`. |
| `graphify update .` | Atualização AST concluída conforme instrução do repositório. |

Depois do commit do veto, sobre o mesmo ambiente:

| Verificação | Resultado |
|---|---|
| `cargo test -p heraclitus-log --offline` | Saída 0: **373 aprovados, 0 reprovados**. |
| `cargo fmt --check` | Saída 0. |
| `cargo clippy -p heraclitus-log --all-targets --offline -- -D warnings` | Saída 0. O campo `footer_declara` passou a usar o alias `FooterDeclara` (`type_complexity`). |
| `git -c core.whitespace=trailing-space,space-before-tab,cr-at-eol diff --check` | Saída 0. |

O SHA-256 do `engine.rs` do diretório principal foi conferido no início e ao
fim: `9D854AE669294B65654DE90ECFEF31D514674EB7370B5E1DFB9C4C89C0DD3251`.
Os arquivos de produto editados nesta continuação pertencem ao worktree
isolado. Não foi executado push. O escopo dos testes é `heraclitus-log` no
Windows; as suítes de `heraclitus-server` e `heraclitus-tier` não foram rodadas.

### Entrega do commit

O sandbox recusou a criação de
`D:\DEV\HeraclitusDB\.git\worktrees\heraclitus-b1b2b5b6\index.lock` com
`Permission denied`. A tentativa de anexar o worktree pelo aplicativo também
falhou. Assim, o ramo do worktree original permanece em `917732c`, com os
arquivos corrigidos no diretório de trabalho.

A continuação é commitada com a identidade Claude em metadados Git separados,
dentro de `D:\tmp`, usando os objetos existentes somente para leitura. O
bundle incremental `D:\tmp\heraclitus-b1b2b5b6-conclusao.bundle` contém esse
commit e exige `917732c` como base. Não duplica o checkout nem inclui o WIP do
diretório principal. Sua importação no repositório original exige um shell
com permissão de escrita nos metadados desse repositório.

Importado depois: o ramo avançou de `917732c` para `f758a81` (avanço simples;
a árvore do commit do bundle é idêntica ao diretório de trabalho). O commit do
veto vem por cima de `f758a81`. Sem push.
