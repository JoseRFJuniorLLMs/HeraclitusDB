# SPEC-0050 Fase 7 (`PackedEpisodeV1`) — o gate de §204, medido

**Data:** 2026-08-24 · **Harness:** `cargo bench -p heraclitus-log --bench hrkl_v6_ab`
**Parâmetros:** 60 000 eventos × 5 corridas por formato, ordem A/B alternada,
segmentos de 8 MiB, `fsync=always`, perfil de packing `Balanced`
**Corpus:** `operational-v1` — logs de 8 serviços × 8 rotas, 5 attrs por evento,
embeddings em 1 de cada 16 · `blake3 = c6a242ea…6b32` (idêntico nas 10 corridas)

## A pergunta

§204 não descreve a Fase 7 como trabalho pendente. Descreve-a como **condicional**:

> *"Somente após benchmarks demonstrarem benefício além de Zstd."*

A pré-condição é uma medição. Este ficheiro é essa medição.

## Resultado

| gate | métrica | limite | medido | |
|---|---|---|---|---|
| §153 hot write | regressão de débito v6 vs v5 | ≤ 3% | **0.00%** (v6 é +5.06% mais rápido) | PASS |
| §154 compressão | `packed / raw` | ≤ 50% | **21.95%** (35 066 652 → 7 697 810 B) | PASS |
| §155 incompressível | expansão do PACKED | ≤ 2% | fallback RAW, expansão **0** | PASS |

Medianas de 5 corridas:

| | débito | append p99 | flush |
|---|---|---|---|
| v5 legado | 421 append/s | 6.932 ms | 0.165 ms |
| v6 RAW | 443 append/s | 4.423 ms | 0.112 ms |

§155 não corre neste harness; é coberto pelos testes
`v6::compress::tests::dados_incompressiveis_caem_para_raw_sem_crescer` e
`v6::packed::tests::dados_incompressiveis_expandem_menos_de_2_porcento`, que
usam xorshift64 (sem runs nem substrings ao alcance da janela) — o pior caso
real, que é conteúdo já cifrado e embeddings float.

## Decisão: **o gate não abre. A Fase 7 não é implementada.**

O Zstd no perfil `Balanced` deixa **21.95%** dos bytes RAW — comprime 4.56×
num corpus operacional real. Um codec físico estruturado com dicionários
adaptativos estaria a disputar essa quinta parte que resta, e teria de a ganhar
contra três custos que não são hipotéticos:

1. **Um encoding físico novo em disco**, com o seu próprio versionamento,
   golden vectors, fuzzing e matriz de compatibilidade.
2. **Um ciclo de vida de dicionários** — §45 já avisa que "o dicionário não
   deve piorar o arquivo", o que implica medir e por vezes descartar.
3. **A interacção com a cifra em repouso (§47).** Dicionários partilhados entre
   registos de agentes diferentes atravessam a fronteira que a cifra por
   `agent_id` existe para manter.

Nada disto se justifica por um teto de 21.95%.

## O que abriria o gate

A decisão é sobre a evidência disponível, não sobre a ideia. Reabrir exige uma
medição, não um argumento:

- **um corpus onde o Zstd falhe** — §154 medido acima de, digamos, 60% num
  workload real de produção (payloads de alta entropia, ou registos tão pequenos
  que a metadata domine);
- **§156 (Metadata Gate) a falhar** — se a metadata por registo PACKED não
  descer os 60% exigidos num corpus contíguo, é sinal de que o problema está no
  encoding estrutural e não no compressor, que é exactamente o que a Fase 7
  ataca;
- **um protótipo que meça `PackedEpisodeV1` contra Zstd no mesmo corpus** e
  ganhe por margem que pague os três custos acima.

## Honestidade sobre estes números

- **Um corpus, não vários.** `operational-v1` é dados em forma de log, que são
  muito compressíveis. Outro corpus daria outro §154. Mas §204 põe o ónus em
  *demonstrar benefício além do Zstd* — a ausência de demonstração mantém o gate
  fechado; não é o gate que tem de provar que deve continuar fechado.
- **Os números de débito são ruidosos.** As corridas legadas variaram entre 256
  e 843 append/s (`fsync=always` numa máquina de desenvolvimento Windows). A
  mediana de 5 atenua, mas o `+5.06%` não deve ser lido como uma medida precisa
  — a leitura defensável é "v6 não regride". O número de **compressão**, esse, é
  contagem determinística de bytes a partir dos `PackReceipt`, sem ruído.
- **Fase 8** (§205) não precisa de gate: o texto da spec abre com "Opcional:".

## JSON bruto

```json
{"compression":{"max_packed_raw_ratio":0.5,"packed_bytes":7697810,"packed_raw_ratio":0.21951938839213964,"pass":true,"raw_bytes":35066652,"records":60000,"segments":5},"corpus":"operational-v1","corpus_digest_blake3":"c6a242eaf499b595b8f4dd6daec5ff43add5c938bd42bc6c1346a49bd7dc6b32","events_per_run":60000,"fsync":"always","hot_write":{"max_regression_pct":3.0,"pass":true,"regression_pct":0.0,"signed_throughput_delta_pct":5.059631417170163},"pack_profile":"balanced","pass":true,"runs":5,"schema":"hrkl-v6-ab-result/1","segment_bytes":8388608,"v5":{"median_flush_ns":165300,"median_run_append_p99_ns":6932000,"median_throughput_append_s":421.3012078654371},"v6_raw":{"median_flush_ns":112000,"median_run_append_p99_ns":4423500,"median_throughput_append_s":442.6174961395142}}
```

Reproduzir:

```bash
HERACLITUS_AB_EVENTS=60000 HERACLITUS_AB_RUNS=5 cargo bench -p heraclitus-log --bench hrkl_v6_ab
```
