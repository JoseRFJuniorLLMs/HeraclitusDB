# Heraclitus v2.0.0 — Agent Black Box

**Pivô de produto.** O primeiro produto vendável deixa de ser "um banco de
dados" e passa a ser:

> **Uma caixa-preta verificável para agentes de IA: regista o que um agente
> fez, com que identidade, que ferramentas accionou, que autorizações existiam,
> e permite provar depois que o histórico não foi adulterado.**

O HeraclitusDB continua a ser o motor. O comprador não precisa de entender HRKL,
Merkle, Bε-tree, DataFusion ou Raft para obter o primeiro valor.

Implementa as SPEC-0074, SPEC-0075 e SPEC-0076.

---

## Incluído

### SPEC-0074 — Agent Black Box (captura e prova)

- **`crates/heraclitus-agent`** — o modelo canónico `AgentEvidenceV1` com 17
  tipos de evento, codec manual com separação de domínio, e um hash lógico que
  não depende do `serde`, do layout do Rust nem da arquitectura da CPU.
- **Ingestão OpenTelemetry** em `POST /v1/traces` (`:4318`), protobuf e JSON,
  com as GenAI Semantic Conventions mapeadas para campos tipados. Um span sem
  marca GenAI é ignorado — o tracing HTTP normal da aplicação não entra no
  histórico de evidência, e o produto não se ingere a si próprio.
- **Portão de privacidade** com quatro modos (`METADATA_ONLY` por omissão) e uma
  lista de negação que **nenhum modo dispensa**: `Authorization`, `Cookie`,
  `Set-Cookie`, chaves de API e tokens nunca são persistidos. Nove classes de
  segredo com forma conhecida são detectadas e substituídas pelo marcador; a
  classe é registada, o valor não.
- **Deduplicação lógica**: a retransmissão de um lote OTLP não duplica a
  história. A mesma chave com conteúdo semanticamente diferente falha
  explicitamente em vez de sobrescrever evidência já registada.
- **Persistência em HRKL v6** com `prove_lsn` no caminho real de prova.
- **Evidence Bundle v1**: ZIP com método STORE, manifesto autoritativo,
  `timeline.ndjson`, projecções, raízes lógicas, provas de inclusão por registo
  e `SHA256SUMS`. Escrita atómica — um bundle interrompido nunca aparece como
  concluído.
- **Verificador offline** (`heraclitus agent verify`), sem rede, sem base de
  dados e sem servidor, com os códigos de saída de §18 como contrato.
- **Captura MCP** (`2026-07-28`, HTTP) com o trio
  `ToolRequested → ToolInvocationStarted → ToolInvocationFinished`
  correlacionado por `tool_call_id`.

### SPEC-0075 — Agent Policy Gateway (controlo e aprovação)

- **Policy declarativa determinística** em `agent-policy-v1` (YAML ou JSON, mesmo
  hash). Doze operadores, sem regex. Decimais comparados sobre os dígitos, nunca
  em vírgula flutuante: `0.1 + 0.2 > 0.3` é verdade em binário e mentira em
  dinheiro.
- **Fail closed por construção**: o documento vazio nega tudo, e
  `defaults.decision: allow` é recusado na leitura com a razão por extenso.
- **Proxy MCP** com os três modos `observe → shadow → enforce`. Em `shadow` a
  decisão é avaliada e registada com `enforced=false`, e nada é bloqueado.
- **Aprovação ligada ao conteúdo exacto**: o hash do assunto cobre ferramenta,
  servidor, argumentos, agente, humano, policy e validade. Aprovar
  `send_payment(amount=5000)` e executar `amount=5001` falha com
  `APPROVAL_BINDING_MISMATCH`. A aprovação é de uso único e expira.
- **Validação OIDC/JWT** com allowlist de emissores, audiência, `exp`, `nbf`,
  `kid`/JWKS, tolerância de relógio e allowlist de algoritmos (RS256, ES256,
  HS256). O algoritmo é decidido pela chave configurada, não pelo token — a
  confusão de algoritmo é recusada.
- **Simulação histórica** de uma policy candidata contra as tool calls já
  registadas, antes de activar.
- **Ficheiro de policy é dados, não um mecanismo de RCE**: sem âncoras, aliases,
  tags, includes remotos, shell, JavaScript, Lua ou template eval; com tectos de
  tamanho, linhas e profundidade.

### SPEC-0076 — Consola, empacotamento e produto

- **Consola embutida no binário** (`:8080`): Runs, Run detail com timeline,
  Evidence detail com prova, Approval inbox, Policy, Settings. Sem Node em
  produção, sem CDN, sem recurso externo; CSP `default-src 'none'`.
- **Quatro estados de integridade honestos** — `VERIFIED`, `PARTIAL`,
  `UNVERIFIED`, `BROKEN`. Evidência num segmento ainda não selado aparece como
  `UNVERIFIED`, nunca verde.
- **RBAC** com `viewer`, `auditor`, `approver`, `policy_admin`, `system_admin`.
  `approver` e `policy_admin` são separados: quem escreve a regra não a dispensa.
- **`heraclitus agent demo`** — o fluxo completo (pedido, policy, aprovação do
  CFO, execução, efeito externo) sem chave de API externa e sem rede.
- **`heraclitus agent doctor`** — diagnóstico em que cada verificação que não
  passa diz **o que fazer**.
- **Quickstart Docker** em `examples/agent-black-box` com um agente Python de
  exemplo que usa só a biblioteca padrão.
- **README pivotado**: problema, quickstart, o que é capturado, verificação,
  gateway, privacidade — e só depois a arquitectura do motor.

---

## O que NÃO mudou

- O formato canónico do log. **Não há formato novo de HRKL nesta versão.** A
  evidência de agente é um `EventKind::Custom("AgentEvidence")` num log v6
  normal, e um banco da 1.0.x continua a abrir e a verificar.
- O Sentinel (SOC) e os endpoints `/sentinel/*`. Continuam a funcionar. Deixam
  de liderar o quickstart e deixam de governar a prioridade P0 — não foram
  apagados nem depreciados.
- As portas históricas 7474 (gRPC) e 7475 (REST de administração).
- Os controlos de supply chain: SBOM, checksums, provenance.

---

## Compatibilidade e limitações

- **OTLP/gRPC não está incluído.** Esta versão serve OTLP/HTTP (protobuf e
  JSON). A SPEC-0074 §30 permite o adiamento desde que documentado; está em
  `docs/agent/otel.md`. Efeito prático para a maioria das instalações: nenhum —
  `OTEL_EXPORTER_OTLP_ENDPOINT=http://host:4318` usa `http/protobuf` por
  omissão. Quem tiver o exporter fixado em gRPC define
  `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`.
- **O plano de agentes está ligado na compilação e desligado na configuração.**
  `HERACLITUS_AGENT_ENABLED=0` é o default da imagem: um servidor não abre
  listeners que ninguém pediu.
- **`RATE_LIMIT` e `SANDBOX_HINT` são decisões declaráveis mas não têm
  enforcement próprio** além de recusar a chamada (`429`) e de propagar a dica.
  A SPEC-0075 §13 marca-os assim de propósito; `SANDBOX_HINT` não implementa um
  hipervisor universal.
- **O registo de aprovações vive em memória** e é reconstruído do log no
  arranque. Consequência honesta: uma aprovação concedida e **não consumida**
  antes de um crash volta a ficar pendente depois do reinício. É o lado seguro
  do trade-off.
- **Exactly-once sobre sistemas externos não é prometido.** Um retry com a mesma
  acção não cria nova aprovação, mas se o upstream não provar idempotência o
  estado externo pode ficar ambíguo. A matriz de caos documenta-o em vez de o
  esconder.
- **Não se promete detectar todo o segredo possível.** Os detectores apanham as
  formas conhecidas. A defesa primária é `METADATA_ONLY`.
- **`PARTIAL` é o resultado esperado** de um bundle exportado logo depois da
  ingestão: os registos ainda estão no segmento activo. As provas aparecem
  quando o segmento sela.
- Os gates de adopção da SPEC-0076 §42 (cinco instalações externas, três
  utilizadores a voltar, uma integração de terceiros) e o teste de onboarding
  humano de §45 são medições de campo. **Não estão cumpridos** e não podem ser
  cumpridos por código.

---

## Actualização a partir da 1.0.x

Nenhuma migração de dados é necessária. Um banco v6 existente abre normalmente e
a evidência antiga continua a verificar.

Para ligar o produto novo:

```bash
docker run --rm -e HERACLITUS_AGENT_ENABLED=1 \
  -p 8080:8080 -p 4318:4318 \
  -v heraclitus-data:/var/lib/heraclitus heraclitus:2.0.0
```

ou, no TOML:

```toml
[agent_black_box]
enabled = true
capture_mode = "metadata_only"

[agent_black_box.otlp]
http_addr = "0.0.0.0:4318"
```

Em `production_mode = true`, um listener fora de loopback exige TLS e
autenticação, e o gateway exige OIDC. `heraclitus agent doctor` mostra o estado
destes gates antes de alguém os descobrir em produção.

---

## Verificação

```bash
cargo test -p heraclitus-agent -p heraclitus-agent-gateway
```

A cadeia inteira é testada sobre um HRKL v6 real, não sobre duplos: apêndice,
selagem, prova de inclusão, exportação, verificação `VERIFIED`, adulteração de
um byte, verificação recusada. O gateway é testado sobre HTTP real contra um
servidor MCP falso, com um contador que prova que uma acção negada **não chega
ao upstream**.
