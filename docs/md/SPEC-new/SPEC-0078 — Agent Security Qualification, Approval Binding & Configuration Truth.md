# SPEC-0078 — Agent Security Qualification, Approval Binding & Configuration Truth

**Status:** PROPOSED — CORRECTIVE / P0  
**Prioridade:** P0 antes de qualquer recomendação de produção com agentes capazes de provocar efeitos externos  
**Baseline:** `413ef341aca63280e59fe7d74296cc6e41de592f`  
**Depende de:** SPEC-0049, SPEC-0074, SPEC-0075, SPEC-0076 e SPEC-0077  
**Escopo:** Agent Black Box, Agent Policy Gateway, qualifier, supply chain e gates adversariais de release

---

## 0. Decisão

A v2.0.0 demonstrou que o desenho central do plano de agentes é correto, mas um ensaio de instalação e ataque sobre o artefato distribuído encontrou três divergências que impedem tratar a implementação como qualificada para produção:

1. uma aprovação humana concedida para uma ação exatamente igual pode falhar no retry com `APPROVAL_BINDING_MISMATCH` porque o hash inclui timestamps regenerados;
2. `heraclitus-qualifier doctor` declara `[agent_black_box]` inerte embora o servidor leia e execute essa configuração;
3. o gate RustSec do `main` detectou dependências que não satisfazem a política de supply chain.

Esta SPEC transforma esses achados em invariantes mecânicas e acrescenta gates de regressão derivados do ensaio adversarial real.

A regra é simples:

```text
não basta o desenho ser seguro;
o binário distribuído, o qualificador e o CI têm de concordar sobre o que o produto faz.
```

---

## 1. Não objetivo

Esta SPEC **não** promete detectar perfeitamente prompt injection, não transforma HeraclitusDB em EDR, hipervisor, IdP ou sandbox universal e não cria uma certificação governamental fictícia.

O modelo de ameaça permanece o da SPEC-0075:

```text
o raciocínio do agente pode estar comprometido.
```

Logo a autorização crítica não depende de o LLM declarar que uma ação é segura.

---

## 2. Modelo de ameaça

O atacante pode controlar ou influenciar:

- prompt e contexto recebido pelo agente;
- argumentos sugeridos para tools;
- repetição e concorrência de chamadas;
- lotes OTLP malformados, duplicados ou excessivos;
- tentativas de reutilizar uma aprovação;
- ordem e tempo entre pedir, aprovar e executar;
- nomes desconhecidos em configuração;
- um agente que tente alcançar diretamente o upstream.

O atacante **não** recebe por hipótese:

- segredo administrativo do Core;
- material privado de TLS;
- credencial do upstream que, em topologia qualificada, pertence apenas ao gateway;
- capacidade de reescrever retroativamente segmentos HRKL já persistidos.

---

## 3. Invariante A — binding estável da aprovação

### 3.1 Problema confirmado

`ActionAuthorizationV1::subject_hash()` inclui atualmente:

```text
issued_at
expires_at
```

O gateway reconstrói `ActionAuthorizationV1` em cada tentativa e preenche esses campos a partir do relógio daquele momento. Portanto:

```text
mesma tool
mesmo servidor
mesmos argumentos
mesmo agente
mesmo humano
mesma policy
+ retry um segundo depois
=
hash diferente
```

Isto contradiz o contrato funcional de aprovação.

### 3.2 O binding correto

O hash que identifica **o assunto aprovado** deve cobrir apenas identidade e conteúdo estáveis:

```text
policy_id
policy_version
policy_hash
rule_id
agent_subject
human_subject
resource_id
action
argument_digest
```

Não entram no binding:

```text
authorization_id
nonce
issued_at
expires_at
```

Tempo continua sendo segurança, mas é verificado como lifecycle, não como identidade do conteúdo.

### 3.3 Expiração

A aprovação mantém `requested_at` e `expires_at` próprios em `ApprovalRequestV1`.

O retry **não pode estender a validade**. Se um pedido pendente/granted existe para o mesmo subject, seu `expires_at` original governa o fluxo.

### 3.4 Single-use

Uma aprovação concedida permite no máximo uma execução efetiva.

Após consumo:

```text
mesma ação exata => APPROVAL_REPLAYED ou nova aprovação explícita
```

Nunca uma segunda execução silenciosa.

### 3.5 Mismatch obrigatório

Qualquer alteração em:

```text
tool
server
argumentos
agent principal
human principal
policy id/version/hash/rule
```

deve continuar falhando com `APPROVAL_BINDING_MISMATCH` ou exigir novo pedido, nunca herdar a aprovação antiga.

### 3.6 Upgrade

Uma aprovação não consumida criada por uma release que usava o binding temporal antigo **não é migrada para uma autorização válida automaticamente**.

Na dúvida:

```text
fail closed
```

A atualização pode exigir nova aprovação humana. Segurança prevalece sobre continuidade de uma credencial efêmera.

---

## 4. Invariante B — o teste não pode depender do mesmo segundo

O teste E2E existente podia passar porque pedido, aprovação e retry ocorriam dentro do mesmo segundo UNIX.

Gates novos devem provar explicitamente:

1. duas autorizações com o mesmo assunto e timestamps diferentes têm o mesmo binding;
2. argumentos diferentes têm binding diferente;
3. uma aprovação concedida continua válida para o mesmo assunto depois de o relógio avançar, desde que ainda não expirada;
4. após expiração, a mesma ação não executa;
5. após consumo, retry não executa novamente.

Teste que só passa por coincidência de relógio não é teste de segurança. É superstição automatizada.

---

## 5. Invariante C — verdade única de configuração

### 5.1 Problema confirmado

O servidor lê as tabelas:

```toml
[agent_black_box]
[agent_gateway]
```

mas o qualifier mantém uma lista separada de chaves top-level e atualmente pode reportá-las como:

```text
not read by the server and has no effect
```

Isto é um falso `BLOCKING`.

### 5.2 Regra

Se o servidor lê uma chave, o qualifier nunca pode classificá-la como inerte.

Mas simplesmente liberar a tabela inteira também é incorreto, porque esconderia typos internos.

O doctor deve conhecer:

```text
agent_black_box
  enabled
  capture_mode
  tenant_id
  max_body_bytes
  otlp
  mcp
  redaction
  evidence
  console
  limits

agent_gateway
  enabled
  mode
  listen_addr
  upstream_url
  identity
  policy
  approval
  bypass_protection_configured
```

E validar recursivamente as subchaves relevantes.

### 5.3 Typos continuam bloqueantes

Exemplo:

```toml
[agent_black_box]
capture_mod = "metadata_only"
```

não pode ser aceito silenciosamente.

Resultado esperado:

```text
BLOCKING: unknown/inert nested configuration key
```

### 5.4 Semântica de produção

Quando possível sem duplicar duas implementações divergentes, o qualifier deve alinhar seus gates com `AgentBlackBoxConfig::validate` e `AgentGatewayConfig::validate`:

- listener público em produção exige os controles previstos;
- gateway em produção exige OIDC;
- `enforce` exige bypass protection declarado;
- gateway habilitado exige upstream;
- TTL de aprovação não pode ser zero;
- `full_explicit` em produção exige proteção adequada;
- ingestão e console não podem ser confundidos com o Core REST.

A lista de chaves e a semântica devem ter testes de contrato contra regressão.

---

## 6. Invariante D — supply chain sem findings novos escondidos

O CI deve continuar executando:

```text
cargo audit --deny warnings
```

Uma nova vulnerabilidade não será resolvida adicionando `--ignore` por conveniência.

Para cada finding novo existem somente três saídas aceitáveis:

1. atualizar/remover a dependência vulnerável;
2. provar mecanicamente que ela não participa do artefato executável e documentar a contenção;
3. se nenhuma correção existe e a dependência é necessária, registrar aceitação de risco explícita, estreita, com condição automática de revogação.

### 6.1 Findings que motivaram esta SPEC

O gate detectou:

```text
RUSTSEC-2026-0285  rustls 0.23.43  -> corrigir para >= 0.23.45
RUSTSEC-2026-0253  lru 0.12.5
RUSTSEC-2026-0002  lru 0.12.5
```

A implementação deve eliminar esses findings do grafo/lock qualificado ou substituí-los por contenção mecanicamente comprovada. Preferência: upgrade/remoção, não ignore.

---

## 7. Invariante E — deny significa zero efeitos externos

Em `GatewayMode::Enforce`:

```text
DENY               => upstream hits = 0
REQUIRE_APPROVAL    => upstream hits = 0 enquanto pendente
APPROVED exact      => upstream hits += 1
REPLAY              => upstream hits não aumenta
BINDING_MISMATCH    => upstream hits não aumenta
```

Isto deve ser medido por contador no servidor upstream falso, não inferido pelo status HTTP.

---

## 8. Invariante F — bypass protection é topologia, não checkbox mágico

A flag `bypass_protection_configured=true` é uma declaração operacional, não cria isolamento por si só.

Uma implantação qualificada deve garantir:

```text
agent não possui credencial direta do upstream
network egress impede caminho direto quando aplicável
upstream aceita identidade/credencial apresentada pelo gateway
segredos de upstream não aparecem no contexto do agente
```

O produto nunca deve dizer `ENFORCED` apenas porque a flag está ligada se a topologia real não foi verificada pelo operador.

---

## 9. Invariante G — ingestão hostil não compromete evidência

Gates derivados do ensaio real:

### 9.1 Malformed OTLP

Payload inválido:

```text
=> 4xx
=> processo vivo
=> nenhuma corrupção do log
```

### 9.2 Payload oversized

Acima do limite configurado:

```text
=> 413 / rejeição equivalente
=> nenhum append parcial
```

### 9.3 Redaction

Campos sensíveis por default, incluindo prompt e segredo sintético:

```text
=> não aparecem em claro na timeline/evidence API
```

### 9.4 Deduplicação

Retransmitir exatamente o mesmo batch:

```text
primeiro => accepted > 0
segundo  => accepted = 0, duplicated > 0
```

O histórico não duplica tool calls nem runs.

---

## 10. Invariante H — concorrência adversarial

Deve existir um gate com múltiplas chamadas concorrentes de uma ação proibida.

Aceitação mínima:

```text
N tentativas DENY concorrentes
N respostas negadas
0 chamadas ao upstream
processo permanece saudável
log permanece legível/verificável
```

O valor de N em CI deve ser suficiente para detectar race conditions sem transformar cada PR em teste de carga de meia hora. Um stress maior pode ficar no nightly.

---

## 11. Invariante I — autenticação e segregação

Uma implantação de produção não reutiliza uma única credencial humana para todos os planos.

Deve permanecer separada a autoridade de:

```text
Core admin
Core writer/application
Core auditor/reader
Agent gateway identity
Agent console/approver
upstream tool credential
```

O Core não deve vazar sua credencial para Agent Gateway, dashboard ou upstream.

---

## 12. Mudanças obrigatórias de código

### 12.1 `heraclitus-agent`

- corrigir algoritmo de `ActionAuthorizationV1::subject_hash()`;
- manter expiração fora do binding;
- testes unitários explícitos para estabilidade temporal, mismatch, expiry e single-use.

### 12.2 `heraclitus-agent-gateway`

- fortalecer `gateway_end_to_end.rs` para que o fluxo aprovado não dependa do mesmo segundo;
- provar zero upstream hit em deny/pending/mismatch/replay;
- adicionar stress concorrente curto para DENY;
- preservar fail-closed em erro de policy.

### 12.3 `heraclitus-qualifier`

- reconhecer `agent_black_box` e `agent_gateway` como superfícies reais do servidor;
- validar recursivamente nested keys;
- adicionar testes contra falso inert e contra typo interno;
- alinhar findings de produção com gates do servidor sem mascarar diferença de escopo.

### 12.4 Supply chain

- atualizar/remover dependências que geram `RUSTSEC-2026-0285`, `RUSTSEC-2026-0253` e `RUSTSEC-2026-0002`;
- manter `cargo audit --deny warnings` verde;
- não adicionar novos ignores sem justificativa técnica e gate de revogação.

### 12.5 Qualificação integrada

Adicionar um gate reproduzível que cubra, no mínimo:

```text
exact approval after time change
mutated approval binding
single-use approval
concurrent deny flood
malformed OTLP
oversized OTLP
redaction
OTLP dedupe
qualifier/server schema agreement
cargo audit
```

---

## 13. Compatibilidade

A mudança de binding não altera o formato dos argumentos, o protocolo MCP nem o HRKL.

Ela altera a semântica do `authorization_subject_hash` para novas aprovações.

Regra de upgrade:

```text
aprovação antiga não consumida pode ser invalidada e solicitada novamente.
```

Não existe migração automática que transforme uma aprovação velha em nova autorização.

---

## 14. Telemetria de regressão

Os contadores existentes devem continuar distinguindo:

```text
policy deny
shadow deny
require approval
approval expired
approval replay rejected
upstream error
```

Se houver contador específico para binding mismatch, ele deve ser adicionado apenas se isso não criar uma segunda fonte de verdade. A evidência `ToolDenied` e o `reason_code` continuam obrigatórios.

---

## 15. Gates de aceitação

A SPEC só muda para `IMPLEMENTED` quando todos forem verdadeiros:

```text
[ ] subject hash é estável através de timestamps diferentes
[ ] amount/tool/server/principal/policy mutado não herda aprovação
[ ] approval exact executa uma vez
[ ] approval replay não toca upstream
[ ] approval expired não toca upstream
[ ] qualifier aceita tabelas reais de agent config
[ ] qualifier bloqueia typo nested
[ ] rustls vulnerável não está no lock/grafo qualificado
[ ] findings lru não permanecem sem resolução/containment comprovado
[ ] cargo audit --deny warnings passa
[ ] workspace tests debug passam
[ ] workspace tests release passam
[ ] clippy -D warnings passa
[ ] fmt passa
[ ] malformed/oversized OTLP não derruba o processo
[ ] redaction não revela prompt/segredo sintético
[ ] retransmissão OTLP é deduplicada
[ ] flood concorrente de DENY produz zero upstream hit
[ ] CI do branch/PR fica verde
```

---

## 16. Critério de recomendação operacional

Após os gates acima, a conclusão permitida é:

> HeraclitusDB possui controles testados para registrar e interpor ações de agentes dentro da topologia configurada.

Não é permitido afirmar:

> HeraclitusDB é imune a qualquer ataque de agente.

Nenhum sistema sério recebe esse certificado por força de adjetivo.

---

## 17. Entrega

A implementação desta SPEC deve resultar em:

1. correções de código;
2. testes de regressão;
3. supply chain verde;
4. qualifier coerente com o servidor;
5. documentação atualizada;
6. evidência de CI associada ao commit/PR;
7. alteração do status desta SPEC de `PROPOSED` para `IMPLEMENTED` somente após os gates passarem.
