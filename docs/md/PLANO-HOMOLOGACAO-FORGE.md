# Plano faseado de homologação HeraclitusDB + Heraclitus-Forge

**Objetivo:** disponibilizar a dupla para logs de servidores de órgão público,
com rastreabilidade técnica e sem confundir aprovação de software com
certificação jurídica/infraestrutural.

## Fase 0 — baseline e congelamento — concluída

- inventariar branches, versões, dependências e superfícies;
- reproduzir suítes existentes;
- preservar dados e artefatos não relacionados.

**Gate:** baseline reproduzível e nenhum teste silenciosamente ignorado.

## Fase 1 — cadeia de custódia e exactly-once — concluída

- verificar `.hdb` e assinatura antes de exportar;
- persistir idempotência de `Append` de forma atômica;
- testar crash entre ACK e checkpoint;
- preservar raiz, assinatura, evidence hash e proveniência no destino.

**Gate:** tamper falha fechado e retry não duplica.

## Fase 2 — LGPD e proteção dos dados — concluída

- cifrar conteúdo, attrs e embeddings por titular;
- pseudonimizar `actor.id` por HMAC;
- pseudonimizar `session_id` por HMAC com domínio separado;
- implementar crypto-shredding e rebuild de views;
- cifrar/autenticar quarentena e eliminar PII de respostas/logs.

**Gate:** bytes em disco não revelam a amostra e shred permanece após restart.

## Fase 3 — identidade e rede — concluída

- RBAC separado (`reader`, `writer`, `auditor`, `admin`);
- token armazenado somente como hash no servidor;
- TLS/mTLS no gRPC e no Raft fora de loopback;
- REST administrativo restrito a loopback e auditado.

**Gate:** configurações públicas inseguras são recusadas no boot.

## Fase 4 — qualidade e supply chain — concluída

- fmt/clippy/Ruff estritos;
- testes all-features, crash injection e compatibilidade;
- auditoria Rust/Python e lock Python com hashes;
- fuzz de log, query e manifold;
- CI com privilégios mínimos.

**Gate:** todas as suítes locais e CI verdes; exceções RustSec documentadas.

## Fase 5 — contrato DB↔Forge — concluída

- Forge `1.0.x` ↔ HeraclitusDB/SDK `1.0.5`;
- envelope `forge-heraclitusdb/1`;
- Fato `operational-fact/1.0`;
- API `heraclitus.v1`;
- regras de evolução e onboarding de fonte nova.

**Gate:** versão incompatível é rejeitada antes do primeiro Append.

## Fase 6 — operação local e recuperação — implementação concluída; ativação pendente

- corrigir serviço Windows e perfil de menor privilégio;
- gerar configuração segura sem versionar segredos;
- implementar e testar backup consistente + restore em diretório novo;
- validar health/readiness, logs e integridade após restart;
- migrar ou iniciar diretório cifrado novo; dados históricos plaintext não são
  retrocifrados automaticamente.
- executar o upgrade transacional local após aprovação do UAC.

**Gate:** restore íntegro, serviço reinicia e smoke test lê o mesmo evento.

**Estado em 2026-08-14:** fluxo implementado e validado em instância
descartável; o serviço ativo foi preservado porque o UAC foi cancelado.

## Fase 7 — E2E e GitHub — E2E concluído; publicação em execução

- rodar ponte contra servidor descartável autenticado — concluído;
- repetir teste de retry/crash e consulta da cadeia de custódia — concluído;
- varrer histórico, segredos e arquivos operacionais — concluído;
- confirmar Forge privado no GitHub — concluído;
- commit/merge em `main`, push, CI verde e proteção de branch;
- fazer backup do serviço local, implantar binário e executar smoke pós-deploy.

**Gate:** SHA implantado = SHA no GitHub; banco local íntegro e bridge em dia.

## Fase 8 — homologação externa do órgão — responsabilidade compartilhada

- RIPD/LGPD, retenção e base legal;
- TSA RFC 3161/ICP-Brasil e validação CMS oficial;
- PKI/HSM/cofre, rotação/revogação e segregação de funções;
- carga/failover/RPO/RTO no ambiente alvo;
- hardening, EDR, firewall, backup imutável e resposta a incidentes;
- aceite humano de cada conector e fonte.

**Gate final:** aprovação formal do jurídico, encarregado LGPD, segurança e dono
do serviço. Nenhum teste local pode substituir este aceite.
