# SPEC-RESUMO — inventário verificado do HeraclitusDB

**Auditado em:** 2026-08-21  
**Regra de leitura:** uma SPEC só é “feita” quando há evidência de código, testes
executados e integração declarada. RFC, módulo de referência e decisão de
arquitetura não são sinónimos de implementação completa.

## Divergências corrigidas neste resumo

1. Não existem ficheiros individuais `SPEC-0001.md` a `SPEC-0035.md` em
   `SPEC-new/`. Há apenas registos parciais em `STATUS.md` e
   `PLANO-SPECS.md`.
2. A SPEC-0050 existe no disco como `SPEC-HRKL-0050.md`, não
   `SPEC-0050.md`.
3. `SPECs 0051.md` contém o roadmap SPEC-0051 a SPEC-0070 e não constava do
   resumo anterior.
4. Os documentos `SPEC-new/` são propostas/RFCs salvo quando o código e os
   testes abaixo demonstram um recorte implementado.

## Estado por grupo

| SPEC | Estado verificado | Observação |
| --- | --- | --- |
| 0000, 0036–0041 | RFC / proposta | Não tratar como implementação completa. O plano só aprova extrações pequenas e compatíveis; HQL, JIT/MLIR e a premissa de 10B linhas continuam rejeitados. |
| 0001–0035 | Inventário incompleto | Os documentos-fonte não estão nesta pasta. `STATUS.md` registra módulos 009–035 com estados diferentes de integração; SPEC-023 foi rejeitada por design. |
| 0042 | **Concluída como decisão** | O Marco 0 mediu HUME versus DataFusion e decidiu manter DataFusion como motor vivo; HUME permanece em pausa. |
| 0043 | Parcial / draft normativo | Há fundações relacionadas, mas o documento não está concluído nem libera um router HUME. |
| 0044 | Pendente | Otimização de microarquitetura ainda é proposta; AVX explícito depende de benchmark real. |
| 0045 | Pendente | Não há crate Sentinel, funil SOC ou IR de detecção implementados. |
| 0046 | Parcial | `heraclitus-compliance` cobre âncora/recibos RFC 3161; ainda faltam StrictAirGap, cadeia ICP-Brasil validada e o plano regulatório completo. |
| 0047 | Pendente | Não há integração STIX/TAXII/MISP ou Threat-Sync. |
| 0048 | Pendente | Não há orquestrador, playbooks tipados, motor de aprovação ou plano forense completo. |
| 0049 | Parcial | CI, fuzz e testes existem; Q1–Q6, qualificador, restauro, red-team e matrizes operacionais continuam pendentes. |
| 0050 | **Parcial relevante — Fases 0–3 como biblioteca** | HRKL v6 tem RAW, PACKED, manifesto `.hrkm`, gerações e GC. O writer/leitor normal ainda não usa v6; Fases 4–8 continuam abertas. |
| 0051–0070 | Propostas | Roadmap de segurança pós-0050 em `SPECs 0051.md`; não há estado de implementação individual confirmado nesta auditoria. |

## SPEC-0050 — progresso confirmado nesta auditoria

- Fases 0–3 estão presentes em `crates/heraclitus-log/src/v6/`:
  codec canónico/Merkle, RAW, PACKED, manifesto `.hrkm` e política de GC.
- O vetor dourado do manifesto HRKM foi corrigido para os bytes efetivamente
  produzidos pelo formato atual.
- A CLI agora fornece:
  - `heraclitus inspect <segmento.hrkl>` — relatório HRKL v6 somente leitura;
  - `heraclitus verify <diretório>` — comportamento legado preservado;
  - `heraclitus verify <segmento.hrkl>` — verificação física v6 com erro e
    código de saída não-zero em corrupção de bloco.
- Ainda não expor `prove --lsn` ou verificação lógica na CLI: ambos exigem o
  resolvedor canónico oficial de `opaque_meta + Episode`. Inventar um hash de
  bytes produziria prova forense inválida.

## Validações executadas

- `cargo test --offline -p heraclitus-log` — passou, incluindo golden,
  manifesto, propriedades HRKL v6 e compatibilidade legada coberta.
- `cargo test --offline -p heraclitus-cli` — 6 testes passaram, incluindo
  inspect/verify v6 e corrupção de bloco PACKED.
- `cargo clippy --offline -p heraclitus-cli --all-targets -- -D warnings` —
  passou.
- O Clippy de todos os targets de `heraclitus-log` ainda falha em avisos
  pré-existentes nos benchmarks `carga_real_1m` e `carga_real_20m`; não foi
  alterado nesta entrega.

## Ordem de execução atual

1. Fechar a integração segura da SPEC-0050: resolver canónico público, prova e
   verificação lógica, depois writer/reopen e matriz de compatibilidade v1–v5.
2. Concluir a qualificação mensurável da SPEC-0049 antes de abrir plataformas
   SOC grandes.
3. Só então extrair itens de SPEC-0044/0041 que tenham benchmark real e Gate C.
