# Identidade de commit

O `git config` global continua a ser o do Frederico. O agente assina apenas
o commit que ele cria.

| Quem | `user.name` | `user.email` |
|---|---|---|
| Cursor / Grok | `cursoragent` | `199161495+cursoragent@users.noreply.github.com` |
| Gemini | `Gemini` | `gemini@cursor.com` |
| GPT | `GPT` | `gpt@cursor.com` |
| Claude | `Claude` | `81847+claude@users.noreply.github.com` |

```bash
git -c user.name="cursoragent" -c user.email="199161495+cursoragent@users.noreply.github.com" commit -m "mensagem"
```

`grok@cursor.com` nao esta ligado a nenhuma conta GitHub, por isso nao
aparece na lista de contribuidores. O email do `cursoragent` e o mesmo
criterio que faz o Cursor aparecer no NeuralIA.
