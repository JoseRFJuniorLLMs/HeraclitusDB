# Privacidade — o que é persistido, e o que nunca é

SPEC-0074 §11 e §23.

> **Observabilidade não pode virar vazamento de segredo.**

## Duas classes de dados

| classe | exemplo | política |
|---|---|---|
| conteúdo | argumentos de ferramenta, prompt, resultado | tecto + redacção, conforme o modo |
| credencial | `Authorization`, `Cookie`, `sk-...`, chave AWS | **NUNCA persistida, em modo nenhum** |

A segunda linha não tem excepção. `FULL_EXPLICIT` autoriza guardar o corpo de
uma tool call; **não** autoriza guardar o bearer token que a acompanhava. Um
administrador pode decidir aceitar o risco do primeiro; o segundo não é um risco
que lhe pertença — é a credencial de outra pessoa.

## Modos de captura

```text
METADATA_ONLY   (default)   metadados + hash canónico; nenhum corpo
HASH_ONLY                   idem, explicitamente sem campos tipados de corpo
REDACTED                    corpos com redacção e tecto de tamanho
FULL_EXPLICIT               corpos completos; exige configuração administrativa
```

```toml
[agent_black_box]
capture_mode = "metadata_only"
```

ou

```bash
HERACLITUS_AGENT_CAPTURE_MODE=metadata_only
```

### O que `METADATA_ONLY` guarda

```text
content_length
content_type
canonical_content_hash      <- BLAKE3 dos bytes ORIGINAIS
redaction_applied
redaction_profile_id
```

O hash é calculado sobre os bytes originais, **antes** de qualquer corte. É isso
que permite provar mais tarde que o argumento aprovado foi o argumento
executado, sem nunca ter persistido o argumento.

## Prompts e completions

Os campos `gen_ai.prompt`, `gen_ai.completion`, `gen_ai.input.messages` e
`gen_ai.output.messages` estão na lista de negação por omissão. A **chave**
sobrevive — a auditoria precisa de saber que houve um prompt — o **valor** não.

```json
{
  "fields": {
    "gen_ai.prompt": "[REDACTED]",
    "gen_ai.tool.name": "send_payment",
    "gen_ai.usage.input_tokens": "412"
  }
}
```

## Cabeçalhos sempre negados

```text
authorization  proxy-authorization  cookie  set-cookie
x-api-key  x-auth-token  x-amz-security-token  mcp-session-token
```

Configurável — para **acrescentar**, não para remover:

```toml
[agent_black_box.redaction]
deny_headers = ["authorization", "cookie", "set-cookie", "x-api-key", "x-empresa-token"]
```

## Campos sempre negados

Comparação por substring, deliberadamente grosseira: em caso de dúvida, redigir.

```text
password  passwd  secret  client_secret  api_key  apikey
access_token  refresh_token  id_token  private_key  token
credential  credentials  authorization  prompt  completion
```

Um campo chamado `tokenizer_name` perder o valor é um incómodo; um campo chamado
`oauth_token` sobreviver é um incidente.

## Detectores de segredo

Além das listas de nomes, o conteúdo é examinado por formas conhecidas:

| classe | forma |
|---|---|
| `bearer` | `Bearer ` |
| `basic` | `Basic ` |
| `openai_style_key` | `sk-...` com 20+ caracteres |
| `aws_access_key_id` | `AKIA`/`ASIA` + 16 |
| `github_token` | `ghp_`, `gho_`, `github_pat_` |
| `slack_token` | `xoxb-`, `xoxp-`, `xapp-` |
| `private_key_block` | `-----BEGIN ... PRIVATE KEY` |
| `jwt_like` | três segmentos base64url começados por `eyJ` |
| `cookie_header` | `Cookie:` / `Set-Cookie:` |

Quando um detector dispara, o valor é substituído por `[REDACTED]` e a **classe**
é registada:

```json
"privacy": {
  "capture_mode": "REDACTED",
  "redaction_applied": true,
  "redacted_field_count": 2,
  "secret_classes_detected": ["bearer", "aws_access_key_id"]
}
```

A auditoria fica a saber que ali passou um bearer token, sem o guardar.

### O que isto NÃO promete

Detectar todo o segredo possível. Um segredo com forma inédita passa pelos
detectores. É por isso que o default é `METADATA_ONLY`: a defesa primária é
**não guardar o corpo**; os detectores são a segunda linha, não a primeira.

Sem regex, de propósito: um motor de regex sobre input hostil é uma superfície
de negação de serviço que uma fronteira de autorização não pode ter.

## Um corpo com segredo não é guardado, mesmo num modo que o permitiria

A lista de negação ganha ao modo. Se `FULL_EXPLICIT` estiver ligado e o corpo
contiver um bearer token, o corpo é descartado e a classe é registada.

## Gates de produção

Com `production_mode = true`:

- `capture_mode = "full_explicit"` exige TLS **e** autenticação configurados —
  os corpos capturados passam a ser dados sensíveis em repouso;
- qualquer listener que não seja loopback exige TLS e autenticação;
- o gateway exige `identity.mode = "oidc"` com emissor, audiência e JWKS.

`heraclitus agent doctor` mostra o estado destes gates antes de alguém descobrir
em produção.

## O que a Consola mostra

```text
Capture mode:          METADATA_ONLY
Prompt bodies:         OFF
Completion bodies:     OFF
Tool args:             METADATA_ONLY
Tool results:          METADATA_ONLY
Known secret filters:  ON
```

## O que o Evidence Bundle leva

O modo de captura viaja no manifesto. Sem ele, um bundle em `METADATA_ONLY`
seria indistinguível de um bundle a que alguém apagou os corpos — e a auditoria
tem de conseguir ver que a ausência foi **política**.
