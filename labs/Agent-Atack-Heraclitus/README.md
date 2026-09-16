# Agent-Atack-Heraclitus

Laboratório adversarial **autorizado e loopback-only** para HeraclitusDB. O nome mantém a grafia solicitada do projeto (`Atack`). A ferramenta faz requisições reais contra Core REST, Agent API, OTLP e MCP Gateway, mede o efeito no upstream sintético e envia apenas metadados seguros para `POST /api/v1/agent/red-team/events` quando a SPEC-0079 estiver disponível.

## Regra de segurança

O runner encerra antes de qualquer teste se um endpoint não for `localhost`, `127.0.0.1` ou `::1`. Não existe flag `--allow-remote`. O stub não executa comandos, filesystem, subprocessos ou chamadas externas. Ferramentas perigosas usam apenas marcadores inofensivos como `echo HERACLITUS_REDTEAM_SHOULD_NOT_EXECUTE`.

## O que testa

- REST sem credencial, credencial errada e credencial válida opcional por variáveis de ambiente.
- Reachability da superfície gRPC, sem confundir reachability com prova de autorização.
- OTLP JSON malformado e payload acima do limite, seguido de verificação de sobrevivência.
- `exec` bloqueado em ENFORCE e prova por `upstream_delta`.
- ferramenta benigna autorizada.
- JSON-RPC batch misto para procurar bypass.
- `resources/read` e `prompts/get` para observar cobertura de evidência.
- fluxo de aprovação, consumo único, replay e mutação de argumentos.
- flood concorrente de DENY.
- reload de policy inválida.
- path traversal no download de bundles sem ler o corpo.
- header de identidade grande seguido de health check.

## Credenciais

Nunca entram em arquivo de configuração nem no relatório. Se quiser testar o caminho autenticado do Core:

```bash
export HERACLITUS_CORE_USERNAME='admin'
read -s HERACLITUS_CORE_PASSWORD && export HERACLITUS_CORE_PASSWORD
```

Para Agent API com OIDC/Bearer:

```bash
read -s HERACLITUS_AGENT_TOKEN && export HERACLITUS_AGENT_TOKEN
```

## Demo

Se o seu HeraclitusDB já usa um upstream MCP próprio, apenas ajuste `config.example.json`. Para um laboratório totalmente sintético, aponte o Gateway para o stub e rode:

```bash
python3 stub_upstream.py --port 19000
./run_demo.sh config.example.json
```

A saída imprime PASS/FAIL, HTTP status, se foi bloqueado, delta real de chamadas no upstream e o LSN retornado pelo HeraclitusDB quando a telemetria Red Team é persistida.

## Evidência, sem truques

`redteam_lab` é o depoimento do runner selado no HRKL. Ele deve ser correlacionado com evidência nativa do HeraclitusDB como `PolicyEvaluated`, `ToolDenied`, approvals e `ExternalEffectObserved`. O Dashboard R10 mostra essa diferença explicitamente.
