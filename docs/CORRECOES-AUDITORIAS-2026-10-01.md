# Correções de auditorias — 2026-10-01

Base auditada: `e354a99c0651438981722600ddb5a0801a5c530d` (v3.0.1). Integrados os commits concorrentes até `ef4b6f5168dd83436c3abd5f62db830fa15e2fea` antes da aplicação. Esta nota atualiza o estado; relatórios históricos continuam preservados.

## Implementação desta rodada

| Origem / achado | Alteração | Alcance e limite |
|---|---|---|
| GPT-SOL A01; geral F01 | Intenção administrativa e resultado no log, flush antes do efeito, reserva durável de idempotência e recuperação no boot; wrappers REST/gRPC | Interrupção entre efeito e resultado retorna UNKNOWN e exige reconciliação; mutações administrativas em cluster são recusadas até protocolo distribuído |
| A02 / F02 | Digest canônico vincula operação, identidade, tenant, papéis, parâmetros, motivo e política; aprovações exigem testemunho autenticado no mesmo tenant | O embedding confiável registra testemunhos; um campo enviado no pedido não concede autorização |
| A03 / F03 | Provider preserva épocas anteriores; destroy e unwrap exigem KeyRef exata; época destruída não é recriada; zeroização | Provider de software continua em memória; não constitui HSM ou atestação externa |
| A04 / F04 | Envelope novo v3 autentica o cabeçalho completo e AAD; wrapped key autentica referência | V2 somente por `open_legacy_v2` com referência externa confiável; migração explícita |
| A05 / F05 | Checksum, objetos, limites, compromissos, prova de objetos, assinatura e timestamp verificados; confiança externa fornecida pelo operador | Perfil `object-digests/1` comprova integridade do pacote, não inclusão HRKL; sucesso sem confiança não declara origem institucional |
| A06 / F06 | Custódia canônica vincula node/terminal, passo inicial, continuidade e timestamp | Custódia antiga usa outro digest; nova validação estrita não aceita reset |
| F07 | Acesso confinado com handles sem links/reparse; escrita create_new recusa sobrescrita de hardlink | Diretório raiz deve ser escolhido pelo chamador; pacote existente não é sobrescrito |
| F08 | Idempotência de append inclui pais causais; migração aceita hash antigo somente com pais persistidos idênticos | Retry com pais diferentes é conflito |
| A07 / F09 | Entrada SQL 128 MiB; pool de execução 256 MiB; duas sessões; 10.000 linhas/32 MiB de saída | Pool controla alocações participantes do DataFusion; não é garantia de RSS total |
| A08 / F10 | Flight gRPC produz incrementalmente; duas transmissões; fila de dois lotes; bind sem auth limitado a loopback | API IPC síncrona mantém Vec final limitado a 128 MiB e não acumula todos os batches |
| boot.md / F11 | Checkpoints streaming de vector/text/graph/attr; attr comprime uma coluna por vez; buffers 64 KiB; views limpas não são regravadas | Consistência ainda exige locks; snapshots verdadeiramente incrementais/COW fora de locks permanecem arquitetura |
| boot.md / F12 | Telemetria materializa estado por sensor; histórico canônico no log; cauda até 1024 eventos/8 MiB; AS OF via replay limitado | Quantidade de sensores distintos continua determinando o estado residente |
| otimização / F13 | Memtable com orçamento por bytes, padrão 64 MiB além do teto de eventos; indexação precede evicção | Estimativa conservadora, não RSS; eviction/spill global dos índices ainda exige projeto |
| boot.md | Windows SCM permanece StartPending com heartbeat até engine e listeners prontos | Serviço instalado não foi reiniciado nesta rodada |
| bloqueios / ESSCertID | Binding SHA-1/SHA-256/384/512 com certificado assinante; issuer/serial e atributos duplicados validados | Testes locais usam PKI sintética |
| bloqueios / policy extensions | policyMappings/policyConstraints/inhibitAnyPolicy não suportados são recusados mesmo não críticos, sem waiver | Recusa segura; não é implementação da árvore completa de políticas RFC 5280 |
| falta_fazer / hash do grafo | Hash v2 inclui índice de atributos com ordem determinística | Nós que comparam hashes precisam de versão coordenada |
| F14 | Formatação do workspace e matriz SPEC-0086–0091 atualizada | Documentos de proposta não são promoção automática a produção |

## Auditorias antigas e decisões preservadas

- Auditoria recursiva de 2026-09-05/R10: a revisão inicial desta tarefa constatou correções já presentes para os achados antigos; não os reabre como novos defeitos. Evidência e exceções constam em `AUDITORIA-GERAL-HERACLITUSDB-2026-10-01.md` entregue com a tarefa.
- `docs/md/BUGS.md`, `falta.md`, `fazer.md`, release notes e SPEC-new/AUDITORIA mantêm histórico de versões. A referência atual é esta matriz junto de `falta_fazer.md` e `BLOQUEIOS-PRODUCAO.md`; texto antigo dizendo “pendente” não prova ausência na versão atual.
- `auditorias/append-lento-com-o-crescimento.md`, `otimizacao-20m.md`: cache de leitura posicional, CRC acelerado, scan v6 sequencial, postings comprimidos, interning e modo de restart já existiam na base. Esta rodada altera os picos de checkpoint/replay e telemetria.
- Auditoria de produção Forge e plano de homologação exigem evidência do ambiente real. Testes deste checkout não substituem homologação.
- Decisões P1–P5 (motor, HVM, WASM, transações, GPU), NUMA/AVX e funcionalidades distribuídas adiadas não são declaradas implementadas por esta correção.

## Pendências que não podem ser declaradas encerradas

1. Teto global/evicção/spill dos índices quentes, reidratação e snapshots fora de locks; replay conjunto views/attr em uma passagem; benchmark real de 20 milhões.
2. Inclusão de objetos em HRKL com raiz externa confiável, reconciliação administrativa distribuída e atestação verificável de destruição em provider real.
3. Árvore completa de políticas X.509, comparação de nomes RFC 4518, cache de CRLs e interoperabilidade com token de ACT credenciada.
4. Instalação de raízes oficiais com conferência fora de banda; certificados/CRLs/credenciais de HSM e bucket WORM; aceite institucional e laboratório externo.
5. Arquitetura de snapshots raft em streaming, ledger HVM incremental, funcionalidades Flight adicionais e referências de I&D exigem implementação/qualificação própria. Transporte gRPC Raft já tem caminho mTLS no código atual; documentação antiga “sem TLS” não descreve esse caminho, e configuração real deve ser verificada.

## Compatibilidade e operação

Não apagar logs ou checkpoints para “corrigir” uma falha. Novos checkpoints conservam formatos de vector/text/graph/attr; telemetria passa a `telemetry-health-v2` e reconstrói a view se o novo checkpoint estiver ausente. Hash do grafo muda para v2. Envelope v3 e custódia canônica precisam de migração explícita. Operação UNKNOWN não deve ser repetida automaticamente. Os testes são executados em diretórios temporários; nenhum serviço ou dado de produção foi usado.

## Dependências

`cargo audit --no-fetch --json` encontrou RUSTSEC-2026-0235 (`rkyv 0.7.46`) e RUSTSEC-2023-0071 (`rsa 0.9.10`) na base local. `cargo tree -i rkyv --all-features` não encontrou dependência ativa no alvo local. RSA em produção é verificação pública; chaves privadas/signing da PKI sintética estão nos testes. O aviso RSA não tem versão corrigida nessa base. Estes fatos não equivalem a consulta atualizada à rede nem a aprovação irrestrita de todas as dependências.

A consulta gRPC `Admin(op="admin-operation-state", arg={"idempotency_key":"..."})` permite ao administrador consultar seu estado durável após restart. UNKNOWN continua sem retry automático.

## Validação

Antes da integração: 987 testes aprovados em 14 crates; 14 benchmarks ignorados. Analytics: 26 aprovados; servidor com analytics/tier: 108 aprovados (incluem repetição dos testes default); Flight gRPC: 3 aprovados. A primeira execução de analytics revelou perda de especificidade da mensagem de orçamento; corrigida e reexecutada. Compilações iniciais com debug completo falharam por falta de disco, não por teste; caches da tarefa removidos e perfil sem debug/incremental usado.

Após integração no D:\DEV\HeraclitusDB: `cargo clippy -- -D warnings` aprovado em todos os 17 crates alterados (incluindo analytics, tier, server e cli); `cargo fmt --all -- --check` aprovado limpo; testes de integração do `flight_protocol`, `heraclitus-forensic` (12/12) e `heraclitus-telemetry-health` (27/27) executados e aprovados com sucesso.

Não executados: soak/carga institucional de 20 milhões; Miri/fuzz longo; upgrade ou restart do serviço instalado; validação com ACT/HSM/bucket reais. A memória automática `Codex-mem.cmd` ficou indisponível: Python configurado ausente e runtime alternativo sem grpc; nenhum serviço foi reiniciado para contornar isso.
