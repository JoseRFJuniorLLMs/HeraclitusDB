# Fuzzing e corpus de regressão

Implementa a SPEC-0049 §39–§41.

## Alvos

| alvo | superfície | porque existe |
|---|---|---|
| `log_decode` | frames do WAL legado | bytes de disco que podem estar rasgados ou adulterados |
| `v6_decode` | codec canónico HRKL v6, manifesto, HRKI, blocos PACKED | mesma razão, no formato por omissão |
| `query_parser` | GQL | a única superfície onde texto de um cliente vira plano de execução |
| `manifold_ops` | operações da variedade | aritmética hiperbólica sobre entrada arbitrária |
| `config_parse` | TOML de configuração e `validate_security` | o instalador air-gapped lê um ficheiro que um operador escreveu |
| `rfc3161_decode` | DER de carimbo de tempo | os bytes vêm de uma **autoridade externa**, no momento em que se constrói uma cadeia de conformidade |

Superfícies que a §39 lista e que **ainda não têm alvo, porque ainda não
existem no produto**: STIX, TAXII e OCSF (SPEC-0047, pendente), playbook YAML
(SPEC-0048, pendente), e o manifesto forense. Não há alvo de fuzz para código
que não foi escrito; quando essas SPECs entrarem, o alvo entra com elas.

O `rest_payload` e as mensagens gRPC são cobertos indiretamente: ambos
desserializam para os mesmos tipos que `config_parse` e `v6_decode` exercitam.
Um alvo dedicado a HTTP exigiria arrancar o servidor dentro do fuzzer, o que
troca cobertura por ordens de grandeza de execuções por segundo — a Q3
(campanha de ataque) cobre essa camada com tráfego real.

## Correr

```bash
cargo +nightly-2026-02-17 fuzz run config_parse -- -max_total_time=600
```

O CI corre `log_decode`, `query_parser`, `manifold_ops`, `v6_decode`,
`config_parse` e `rfc3161_decode` com orçamento curto a cada PR, e a campanha
longa fica no lane noturno.

## Corpus de regressão (§41)

**Todo crash descoberto entra no corpus e nunca sai.**

Quando o fuzzer encontra um crash:

1. o input mínimo (`fuzz/artifacts/<alvo>/crash-*`) é guardado;
2. copia-se para `fuzz/corpus/<alvo>/` com um nome estável — o SHA-1 do
   conteúdo, que é o que o libFuzzer já usa;
3. corrige-se o defeito **e escreve-se um teste unitário** no crate afetado,
   por causa da §93 (toda vulnerabilidade corrigida gera regressão);
4. o input fica no corpus permanentemente.

O passo 4 é o que costuma ser esquecido. Um corpus podado "porque já está
corrigido" perde exatamente os inputs que provaram ser capazes de partir o
parser, e a próxima refatoração reintroduz o defeito sem que ninguém note. O
corpus é uma dívida acumulada de propósito: cresce, não encolhe.

`fuzz/corpus/` está versionado. Uma entrada só sai do repositório se o **alvo**
desaparecer.

## Sementes iniciais

`config_parse` e `rfc3161_decode` vêm com corpus semeado à mão. Um fuzzer que
arranca do zero gasta a maior parte do orçamento a redescobrir que a entrada
tem de parecer TOML ou DER; as sementes põem-no a explorar o que interessa
desde o primeiro segundo.

As sementes de `config_parse` cobrem o que o `doctor` e o `validate_security`
tratam de facto: a configuração de referência, CORS com `*`, o FPR do Bloom nos
dois extremos, a contradição `sentinel.enabled`/`mode`, modo autónomo, formato
legado, `segment_max_bytes` no limite do `u64`, e TOML truncado a meio de uma
tabela.

As de `rfc3161_decode` são **estruturais, não válidas**, de propósito: um corpus
só com tokens bem formados nunca visita o caminho de erro, que é onde um
descodificador DER parte. Incluem comprimento em forma longa, comprimento
indefinido, `SEQUENCE` truncada a meio e um comprimento declarado maior do que
o buffer.
