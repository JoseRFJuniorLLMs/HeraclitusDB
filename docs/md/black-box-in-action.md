# black-box-in-action.md

# Heraclitus Agent Black Box in Action

**Status:** implementação/teste operacional
**Objetivo:** provar o Agent Black Box com agentes reais, usando Claude Code e Codex como clientes MCP e o HeraclitusDB como gateway/evidence store.

---

## 0. Objetivo

Este documento não cria um novo produto e não altera o posicionamento principal do HeraclitusDB.

O objetivo é testar, com tráfego real:

```text
Claude Code / Codex
        │
        │ MCP tools/call
        ▼
Heraclitus Agent Gateway :8787
        │
        ├── captura a chamada
        ├── identifica o agente
        ├── registra argumentos/hash
        ├── avalia policy quando configurado
        ├── pode permitir / negar / pedir aprovação
        └── grava evidência no HRKL
        │
        ▼
Servidor MCP upstream real
        │
        ▼
resposta
        │
        ▼
Heraclitus registra resultado/evidência
```

O teste precisa demonstrar:

1. Claude Code usando uma ferramenta MCP através do Heraclitus.
2. Codex usando uma ferramenta MCP através do mesmo Heraclitus.
3. O Heraclitus diferenciando os agentes.
4. `tools/call` aparecendo como evidência persistida.
5. O upstream continuando funcional.
6. `observe`, `shadow` e, depois, `enforce` funcionando conforme o contrato.
7. Evidence Bundle podendo ser exportado e verificado.

---

# 1. Não confundir o que será testado

O Heraclitus não intercepta magicamente qualquer ação interna do Claude Code ou Codex.

Este teste cobre inicialmente:

```text
Claude Code -> MCP -> Heraclitus -> MCP upstream
Codex       -> MCP -> Heraclitus -> MCP upstream
```

Deve funcionar para chamadas MCP reais.

Não considerar como coberto nesta etapa:

```text
Claude Code Read/Edit/Write/Bash internos
Codex shell/edit internos
operações que não passem pelo MCP Gateway
```

Esses fluxos exigem adaptadores específicos posteriores.

---

# 2. Componentes existentes que devem ser reutilizados

Não reimplementar o gateway.

O repositório já possui:

```text
crates/heraclitus-agent/
crates/heraclitus-agent-gateway/
ui/agent-console/
docs/agent/
examples/agent-black-box/
```

O servidor já reconhece:

```text
HERACLITUS_AGENT_ENABLED
HERACLITUS_AGENT_TENANT
HERACLITUS_AGENT_CAPTURE_MODE
HERACLITUS_AGENT_OTLP_HTTP_ADDR
HERACLITUS_AGENT_OTLP_GRPC_ADDR
HERACLITUS_AGENT_CONSOLE_ADDR
HERACLITUS_AGENT_GATEWAY_ENABLED
HERACLITUS_AGENT_GATEWAY_MODE
HERACLITUS_AGENT_GATEWAY_UPSTREAM
HERACLITUS_AGENT_POLICY
```

O gateway atual opera em:

```text
observe
shadow
enforce
```

Semântica:

```text
observe = registra; não avalia policy; não bloqueia
shadow  = avalia policy; registra; NÃO bloqueia
enforce = avalia e efetivamente bloqueia/autoriza
```

---

# 3. Upstream MCP para o teste

Usar um servidor MCP real e inofensivo para a primeira integração.

Sugestão inicial:

```text
Context7
https://mcp.context7.com/mcp
```

O Heraclitus deve ser configurado com a base:

```text
https://mcp.context7.com
```

E Claude/Codex devem apontar para:

```text
http://127.0.0.1:8787/mcp
```

Isso é necessário porque o proxy combina:

```text
base upstream + path_and_query recebido
```

Portanto:

```text
http://127.0.0.1:8787/mcp
        ↓
https://mcp.context7.com/mcp
```

Antes de concluir a implementação, verificar se o endpoint atual do upstream continua válido.

---

# 4. Ativar o Heraclitus Agent Gateway

Arquivo base:

```text
examples/agent-black-box/docker-compose.yml
```

O quickstart atual deixa o gateway desligado.

Alterar para um perfil de teste como:

```yaml
services:
  heraclitus:
    environment:
      HERACLITUS_AGENT_ENABLED: "1"
      HERACLITUS_AGENT_TENANT: "default"
      HERACLITUS_AGENT_CAPTURE_MODE: "metadata_only"
      HERACLITUS_AGENT_OTLP_HTTP_ADDR: "0.0.0.0:4318"
      HERACLITUS_AGENT_CONSOLE_ADDR: "0.0.0.0:8080"

      HERACLITUS_AGENT_GATEWAY_ENABLED: "1"
      HERACLITUS_AGENT_GATEWAY_MODE: "observe"
      HERACLITUS_AGENT_GATEWAY_UPSTREAM: "https://mcp.context7.com"

    ports:
      - "8080:8080"
      - "4318:4318"
      - "8787:8787"
```

Não ativar `enforce` no primeiro teste.

Subir:

```bash
cd examples/agent-black-box
docker compose down
docker compose up -d --build
```

Verificar:

```bash
docker compose ps
curl -fsS http://localhost:8080/api/v1/agent/status
```

Critério:

```text
Heraclitus iniciado
Agent plane habilitado
Gateway escutando em :8787
Console/API disponível
```

---

# 5. Headers de correlação

O gateway já entende:

```text
X-Heraclitus-Agent
X-Heraclitus-Run
X-Heraclitus-Trace
X-Heraclitus-User
X-Heraclitus-Server
X-Heraclitus-Environment
```

Usar no teste pelo menos:

### Claude Code

```text
X-Heraclitus-Agent: claude-code
X-Heraclitus-User: jose
X-Heraclitus-Server: context7
X-Heraclitus-Environment: development
```

### Codex

```text
X-Heraclitus-Agent: codex
X-Heraclitus-User: jose
X-Heraclitus-Server: context7
X-Heraclitus-Environment: development
```

Não persistir bearer tokens nem segredos.

---

# 6. Configurar Claude Code

O agente implementador deve primeiro conferir a sintaxe disponível na versão instalada do Claude Code.

A configuração desejada é um servidor MCP HTTP chamado, por exemplo:

```text
heraclitus-context7
```

apontando para:

```text
http://127.0.0.1:8787/mcp
```

Com headers equivalentes a:

```text
X-Heraclitus-Agent = claude-code
X-Heraclitus-User = jose
X-Heraclitus-Server = context7
X-Heraclitus-Environment = development
```

Forma esperada nas versões que suportam `claude mcp add`:

```bash
claude mcp add \
  --transport http \
  --scope project \
  --header "X-Heraclitus-Agent: claude-code" \
  --header "X-Heraclitus-User: jose" \
  --header "X-Heraclitus-Server: context7" \
  --header "X-Heraclitus-Environment: development" \
  heraclitus-context7 \
  http://127.0.0.1:8787/mcp
```

No PowerShell, usar linha única se necessário.

Depois verificar:

```bash
claude mcp list
claude mcp get heraclitus-context7
```

Se a versão instalada usar outro formato de configuração, adaptar sem alterar a arquitetura do teste.

---

# 7. Testar Claude Code

Prompt sugerido:

```text
Use obrigatoriamente o servidor MCP heraclitus-context7 para consultar
uma documentação técnica atual. Não responda somente com conhecimento interno.
```

Objetivo:

```text
Claude
  ↓
initialize/tools/list
  ↓
Heraclitus
  ↓
upstream
```

`initialize`, `tools/list` e `ping` NÃO precisam aparecer como evidência.

Depois, quando ocorrer:

```text
tools/call
```

isso DEVE gerar evidência.

Confirmar no Heraclitus:

```text
agent = claude-code
server = context7
tool = <nome real da tool>
status = success/error conforme resposta
```

---

# 8. Configurar Codex

O agente implementador deve conferir a sintaxe exata da versão atual do Codex instalada na máquina.

Objetivo de configuração:

```text
servidor MCP: heraclitus_context7
url: http://127.0.0.1:8787/mcp
```

Com headers:

```text
X-Heraclitus-Agent = codex
X-Heraclitus-User = jose
X-Heraclitus-Server = context7
X-Heraclitus-Environment = development
```

Formato esperado em versões que usam `~/.codex/config.toml`:

```toml
[mcp_servers.heraclitus_context7]
url = "http://127.0.0.1:8787/mcp"
enabled = true
required = true

http_headers = {
  "X-Heraclitus-Agent" = "codex",
  "X-Heraclitus-User" = "jose",
  "X-Heraclitus-Server" = "context7",
  "X-Heraclitus-Environment" = "development"
}
```

Se a versão corrente usar um esquema diferente, adaptar para produzir a mesma topologia.

Verificar com o comando MCP suportado pela versão instalada.

---

# 9. Testar Codex

Prompt sugerido:

```text
Use obrigatoriamente o servidor MCP heraclitus_context7 para consultar
uma documentação técnica atual. Não responda apenas usando conhecimento interno.
```

Confirmar que a chamada real passa por:

```text
Codex
  ↓
http://127.0.0.1:8787/mcp
  ↓
Heraclitus Gateway
  ↓
Context7
```

No Heraclitus deve aparecer:

```text
agent = codex
```

separado das chamadas anteriores:

```text
agent = claude-code
```

---

# 10. Critério mínimo do teste OBSERVE

Ao final da fase `observe`, deve existir evidência real equivalente a:

```text
14:21:04  claude-code  <tool>  SUCCESS
14:23:41  codex        <tool>  SUCCESS
```

Para cada `tools/call`, registrar no mínimo:

```text
agent id
run id se disponível
user se fornecido
server id
tool name
argument digest / argumentos permitidos pelo capture mode
timestamps
status/result metadata
LSN
integrity/proof state
```

O gateway deve encaminhar a chamada ao upstream sem alterar a semântica MCP.

---

# 11. Testar SHADOW

Depois que `observe` estiver estável:

```yaml
HERACLITUS_AGENT_GATEWAY_MODE: "shadow"
```

Reiniciar o serviço.

Critério:

```text
policy é avaliada
resultado é registrado
would deny / would require approval pode aparecer
chamada NÃO é bloqueada
```

Se nenhuma policy explícita estiver carregada, observar o comportamento da policy default atual e registrar isso claramente no teste.

Não considerar `shadow` aprovado se uma tool real for bloqueada.

---

# 12. Adicionar policy explícita

Criar um arquivo de teste, por exemplo:

```text
examples/agent-black-box/agent-policy.yaml
```

Exemplo conceitual:

```yaml
version: "agent-policy-v1"

defaults:
  decision: deny

rules:
  - id: allow-context7-query
    match:
      server: context7
      tool: query-docs
    decision: allow
```

A tool exata precisa ser obtida do upstream real. Não hardcodar `query-docs` sem conferir o `tools/list` atual.

Montar a policy no container e configurar:

```yaml
HERACLITUS_AGENT_POLICY: "/etc/heraclitus/agent-policy.yaml"
```

Primeiro continuar em:

```text
shadow
```

Somente após comprovar o comportamento passar para:

```text
enforce
```

---

# 13. Testar ENFORCE

Só ativar depois de:

```text
observe OK
shadow OK
policy explicitamente validada
upstream funcionando
```

Configurar:

```yaml
HERACLITUS_AGENT_GATEWAY_MODE: "enforce"
```

A implementação atual pode exigir a declaração de bypass protection em perfil de produção.

Para laboratório local, respeitar os gates reais da configuração atual e NÃO contorná-los silenciosamente.

O teste deve conter pelo menos:

### Caso permitido

```text
policy -> ALLOW
MCP call -> upstream
resultado -> sucesso
evidência -> ToolRequested + PolicyEvaluated + ToolAuthorized/execução conforme implementação
```

### Caso negado

```text
policy -> DENY
upstream NÃO deve receber a chamada
cliente recebe erro MCP válido
evidência registra ToolDenied
```

### Caso aprovação humana, se suportado no fluxo usado

```text
policy -> REQUIRE_APPROVAL
chamada não executa antes da aprovação
approval id registrado
mesmos argumentos/digest necessários para executar depois
```

---

# 14. Verificar que o HRKL recebeu evidência real

Não basta a UI mostrar uma linha.

Confirmar no backend que a evidência foi persistida via `EngineEvidenceStore` / log canônico e recebeu LSN real.

Critérios:

```text
head LSN avança
scan/read encontra AgentEvidenceV1
dedupe não cria duplicatas para retry idêntico
proof aparece quando o segmento correspondente estiver selado
```

Não considerar uma estrutura apenas em memória como evidência aprovada.

---

# 15. Evidence Bundle

Depois dos testes com Claude Code e Codex, exportar evidência.

Exemplo:

```bash
heraclitus agent export /var/lib/heraclitus \
  --to evidence-black-box-test.zip
```

Se a CLI exigir seleção por run, usar os run ids produzidos no teste.

Verificar:

```bash
heraclitus agent verify evidence-black-box-test.zip
```

Esperado:

```text
VERDICT: VERIFIED
```

Se o segmento ainda não estiver selado, documentar honestamente `UNVERIFIED`/`PARTIAL` conforme o contrato atual e aguardar/forçar apenas pelos mecanismos suportados pelo projeto.

---

# 16. Teste de adulteração

Depois de um bundle validado:

```bash
cp evidence-black-box-test.zip evidence-tampered.zip
printf 'X' | dd of=evidence-tampered.zip bs=1 seek=900 conv=notrunc
heraclitus agent verify evidence-tampered.zip
```

O bundle adulterado NÃO pode retornar `VERIFIED`.

Esperado:

```text
DIGEST_MISMATCH
```

ou outro erro de integridade equivalente definido pelo contrato atual.

---

# 17. O que deve aparecer na Console

A Console de agentes deve tornar óbvio que são agentes diferentes:

```text
Claude Code
Codex
```

Para cada run/tool call:

```text
agent
tool
server
user
policy result
enforced yes/no
approval quando houver
status
LSN
proof status
```

Não inventar dados que o gateway não recebeu.

---

# 18. Testar retries/deduplicação

Repetir um lote/chamada idêntica quando tecnicamente possível.

Verificar:

```text
mesma dedupe key + mesmo conteúdo -> Duplicate, sem nova evidência lógica
mesma dedupe key + conteúdo diferente -> erro explícito
```

Não aceitar reescrita silenciosa de evidência.

---

# 19. Segurança e privacidade

No laboratório inicial usar:

```text
metadata_only
```

Nunca logar:

```text
Authorization
Cookie
Set-Cookie
access_token
refresh_token
API key
client secret
```

Se o upstream MCP exigir autenticação, manter o segredo apenas no transporte/configuração necessária e confirmar que não aparece no HRKL nem no Evidence Bundle.

---

# 20. Limitação atual importante

O teste MCP NÃO prova captura completa da atividade de Claude Code ou Codex.

Atualmente:

```text
Claude/Codex -> MCP tool -> Heraclitus     CAPTURA
Claude/Codex -> ferramenta interna         NÃO CAPTURA
```

Exemplos não cobertos automaticamente:

```text
Claude Read
Claude Edit
Claude Write
Claude Bash
Codex shell
Codex edit
```

Não declarar “captura total do agente” depois deste teste.

O claim correto é:

> O Heraclitus captura, registra e pode controlar as chamadas de ferramentas MCP que passam pelo Agent Gateway.

---

# 21. Próxima extensão: captura nativa dos coding agents

Depois do MVP MCP funcionar, investigar adaptadores específicos.

Objetivo futuro:

```text
Claude Code hooks/events
        ↓
Heraclitus Agent Evidence

Codex execution/events
        ↓
Heraclitus Agent Evidence

MCP calls
        ↓
Heraclitus Agent Gateway
```

Somente implementar isso após confirmar mecanismos oficiais/estáveis oferecidos por cada cliente.

Não monkey-patch processos, não interceptar credenciais e não depender de scraping de terminal como arquitetura principal.

---

# 22. Script de teste desejável

Criar futuramente, se fizer sentido:

```text
scripts/test-agent-black-box-mcp.sh
```

Responsabilidades:

```text
verificar Heraclitus
verificar porta 8787
verificar upstream MCP
executar handshake MCP simples
executar tools/list
executar uma tools/call segura
consultar API de evidência
confirmar incremento de evidência
```

Esse script deve testar o gateway independentemente de Claude/Codex antes dos testes manuais.

---

# 23. Não quebrar o produto principal

Este trabalho não deve desfazer a separação definida pela SPEC-0077.

O Agent Black Box continua sendo módulo.

Portanto:

```text
HeraclitusDB = produto/plataforma principal
Agent Black Box = módulo Agent Evidence & Control
```

O teste deve funcionar mesmo se a home global do HeraclitusDB deixar de ser a Agent Console.

Rota futura esperada:

```text
/        -> Platform Console
/agent   -> Agent Evidence Console
```

Enquanto a migração ainda não estiver concluída, aceitar a rota atual sem reintroduzir o pivô comercial.

---

# 24. Critérios de aceitação

Este documento está concluído somente quando:

```text
[ ] Heraclitus inicia com Agent Gateway habilitado.
[ ] :8787 aceita MCP HTTP.
[ ] upstream MCP real funciona através do proxy.
[ ] Claude Code usa o upstream através do Heraclitus.
[ ] Codex usa o upstream através do Heraclitus.
[ ] chamadas Claude aparecem como agent=claude-code.
[ ] chamadas Codex aparecem como agent=codex.
[ ] tools/call gera evidência persistida no HRKL.
[ ] initialize/tools/list/ping não poluem a evidência.
[ ] observe registra e não bloqueia.
[ ] shadow avalia e não bloqueia.
[ ] enforce permite uma ação autorizada.
[ ] enforce bloqueia uma ação negada.
[ ] argumentos/digest são registrados conforme capture mode.
[ ] tokens/segredos não aparecem na evidência.
[ ] LSN real é atribuído.
[ ] Evidence Bundle é exportável.
[ ] bundle válido passa no verifier.
[ ] bundle adulterado falha no verifier.
[ ] regressão dos testes existentes não ocorre.
```

---

# 25. Definition of Done para o agente implementador

Além dos testes funcionais:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Executar também os gates específicos do repositório relevantes ao `heraclitus-agent`, `heraclitus-agent-gateway` e `heraclitus-server`.

Entregar junto:

```text
comandos exatos usados
versão do Claude Code testada
versão do Codex testada
servidor MCP upstream usado
capturas/logs de evidência relevantes
run ids
LSNs
resultado do Evidence Bundle verifier
limitações encontradas
```

Não marcar como concluído apenas porque a UI abriu.

---

# 26. Resultado esperado

Ao final, deve ser possível demonstrar ao vivo:

```text
1. abrir Claude Code
2. pedir uma operação que exija MCP
3. Claude chama Heraclitus
4. Heraclitus encaminha ao MCP upstream
5. resposta volta ao Claude
6. abrir Agent Evidence Console
7. mostrar a chamada gravada
8. abrir Codex
9. repetir
10. mostrar agent=codex separado
11. exportar bundle
12. verificar bundle offline
13. adulterar bundle
14. verifier detectar adulteração
```

Essa é a primeira demonstração real do valor do Agent Black Box.

Não é uma demo sintética de `procurement-agent`.

É tráfego de dois coding agents reais, de fornecedores diferentes, atravessando a mesma camada independente de evidência do HeraclitusDB.
