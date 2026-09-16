# HeraclitusDB v3.0.0 — Hardened Agent Evidence & Production Qualification

**Data:** 2026-09-16  
**Linha:** 3.x  
**Status do software:** Release 3.0.0  
**Status de qualificação:** a versão incorpora a infraestrutura automatizada de qualificação da SPEC-0049, mas `GovernmentProduction` e `MissionCritical` continuam condicionados às atestações de laboratório externo exigidas pela própria SPEC.

## Visão geral

A v3.0.0 consolida o hardening do plano Agent, a observabilidade de campanhas adversariais autorizadas e o processo formal de qualificação de produção. O objetivo desta versão não é declarar o sistema "invulnerável". É tornar propriedades de segurança, integridade e recuperação reproduzíveis, auditáveis e ligadas ao binário testado.

## Segurança e Agent Gateway

- approval binding vinculado à identidade autenticada;
- approvals single-use, com rejeição de replay, expiração, mutação e consumo concorrente atômico;
- `ENFORCE` recusa inicialização quando as superfícies Core necessárias não estão protegidas;
- o corpo JSON-RPC é a autoridade para classificação MCP, evitando divergência entre hints de header e a ação real;
- parsing fail-closed para JSON ambíguo, chaves duplicadas e profundidade excessiva;
- limites explícitos para correlation headers;
- métodos MCP data-bearing passam pela governança de policy;
- identidade usada pela policy é derivada da topologia/configuração confiável, não de header fornecido pelo caller;
- separação entre credenciais Core, Agent e upstream;
- remoção de credenciais sensíveis antes do forwarding ao upstream;
- reforço da deduplicação/evidência e das corridas de approval.

## Red-team observável

A release incorpora o laboratório adversarial loopback-only e a persistência segura de metadados de campanha:

- `POST /api/v1/agent/red-team/events` persiste o resultado seguro da tentativa e devolve LSN;
- `GET /api/v1/agent/red-team/events` é somente leitura e limitado;
- a evidência `redteam_lab` é complementar, nunca substitui `PolicyEvaluated`, `ToolDenied`, approvals e efeitos externos nativos;
- nenhum modo remoto é fornecido ao laboratório adversarial;
- o upstream sintético não executa shell ou filesystem do alvo.

### Campanhas de regressão incorporadas

A linha endurecida foi exercitada com campanhas que incluem:

- 2.048 DENYs concorrentes sem efeito no upstream;
- colisões de identidade entre centenas de agentes;
- `resources/read` e `prompts/get` governados em ENFORCE;
- approval race 48-way e 128-way com exatamente uma execução válida;
- tentativa de uso de approval por outro agente;
- mutações tipadas do JSON de uma ação aprovada;
- centenas de JSONs malformados concorrentes;
- payloads OTLP oversized em paralelo;
- duplicate JSON keys;
- JSON com profundidade extrema;
- 4.096 requests destrutivos entre centenas de identidades;
- métodos Unicode/confusáveis;
- limites exatos de correlation headers 511/512/513+;
- persistência da rejeição de replay após restart limpo e após `SIGKILL`.

Esses resultados qualificam invariantes concretos da campanha; não equivalem a uma alegação universal de ausência de vulnerabilidades.

## Qualificação de produção

A v3.0.0 mantém a SPEC-0049 como contrato de qualificação. A automação do repositório cobre, entre outros:

- Q1 carga realista e ramp/burst;
- Q2 crash-loop e corrupção controlada;
- soak automatizado;
- Q4 upgrade/rollback preflight;
- Q6 backup/restore;
- fuzzing e corpus de regressão;
- doctor/configuração;
- SBOM, build manifest e proveniência;
- egress monitor local;
- verificação de integridade e artefatos de evidência.

## O que continua exigindo laboratório externo

A versão do software é 3.0.0, mas isso não elimina provas físicas que não podem ser honestamente simuladas por CI. Continuam exigindo atestação separada conforme SPEC-0049:

- power loss real ou controlado por hipervisor/PDU;
- perda física de host e falhas de rede/disco para Q5;
- prova independente de zero-egress;
- red team por equipe diferente da implementadora quando exigido pelo nível;
- soak prolongado de 168 horas em hardware de referência;
- disaster recovery multi-site;
- instalação e atualização air-gapped em infraestrutura de laboratório;
- execução independente dos runbooks operacionais.

Na ausência dessas atestações, o resultado correto da qualificação governamental permanece `Unqualified`, em vez de produzir um PASS fictício.

## Versionamento

O workspace Rust passa para:

```text
3.0.0
```

`Cargo.lock`, badge do README, exemplos de imagem Docker e o plano `release-candidate` são sincronizados com a mesma versão.

## Compatibilidade e histórico

Referências documentais que registram funcionalidades originalmente introduzidas em v2.0.0 permanecem intactas. A v3.0.0 é uma evolução da linha anterior, não uma reescrita retroativa do histórico de implementação.

## Princípio da release

A regra operacional permanece simples:

```text
segurança não é HTTP 403;
integridade não é processo vivo;
backup não é arquivo existente;
qualificação não é cargo test verde.
```

A evidência relevante deve demonstrar o efeito real, sobreviver a restart e ser vinculável ao estado/binário que a produziu.
