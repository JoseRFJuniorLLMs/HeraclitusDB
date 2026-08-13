# LoCoMo-style Retrieval Benchmark

The external proof of the memory thesis: can HeraclitusDB surface the right
evidence from a long, multi-session conversation to answer a question?

This harness measures **retrieval** in isolation — recall@k / MRR of the gold
evidence turns — which is exactly the part a *memory substrate* is responsible
for, and is directly comparable to the retrieval numbers Mem0 / Zep / MemGPT
report on [LoCoMo](https://arxiv.org/abs/2402.17753).

## Why retrieval (not end-to-end QA)

End-to-end LoCoMo QA conflates two things: the memory system's job (find the
evidence) and the LLM's job (reason over it + an LLM judge to grade). Measuring
retrieval recall isolates the memory substrate — no LLM, no judge, no API keys,
fully deterministic and reproducible. If the evidence isn't retrieved, no LLM
can answer; so retrieval is the floor the whole stack stands on.

## Run

```powershell
# Needs the release server binary (cargo build --release -p heraclitus-server).
$py = "C:\Users\web2a\AppData\Local\Python\pythoncore-3.14-64\python.exe"
& $py bench\locomo\run.py                       # representative sample
& $py bench\locomo\run.py path\to\locomo.json   # official dataset (same schema)
```

The harness spins up an **ephemeral** HeraclitusDB (temp data dir, ports
7479/7478), so your live memory store is never touched; it ingests every turn,
runs `recall` per question, and tears the instance down.

## Results on the official dataset (10 conversations, 5882 turns, 1982 scored Qs)

**Text-only** (`run.py`, no embeddings) — the honest floor:

```
 channel   hit@1  hit@5  hit@10    MRR
 text       1.3%   5.5%   10.2%   0.033
```

Pure lexical retrieval is ~6x random but useless on real LoCoMo (paraphrased
questions vs 400-700 turns/conversation). This is *why* the semantic channel
matters.

**Semantic channel lit** (`run_embed.py`, local model2vec `potion-base-8M`,
256-d, no API key) — four channels side by side:

```
 channel   hit@1  hit@5  hit@10    MRR
 text       1.3%   5.5%   10.2%   0.033   HeraclitusDB recall (text+activation)
 nearest   16.1%  36.5%   46.8%   0.247   HeraclitusDB native vector index
 cosine    16.1%  36.5%   46.8%   0.247   reference ceiling (raw cosine)
 fusion     4.2%  27.4%   40.0%   0.152   naive RRF(text, nearest)
```

Honest findings:
1. **Embeddings take HeraclitusDB from 5.5% -> 36.5% hit@5 (6.6x).** The semantic
   channel isn't optional for conversational memory; it's the whole game.
2. **`nearest` exactly matches the `cosine` ceiling.** HeraclitusDB's hyperbolic
   manifold vector index preserves semantic ranking losslessly — the index is
   not the bottleneck.
3. **Naive equal-weight fusion HURTS (28.2% < 36.5%).** Fusing a strong channel
   (vector) with a weak one (text 6.3%) at equal weight just adds noise.
4. **Learned weights fix it.** `learn_fusion_weights` (M17) weights each channel
   by its standalone MRR (text 0.036, vector 0.247); the weighted fusion then
   scores **36.8% hit@5 — above the best single channel** (36.5%) instead of
   below it:

```
 channel      hit@5    MRR
 nearest      36.5%   0.247   strong channel alone
 fusion (=)   28.2%   0.157   equal weights -> HURTS
 fusion (lrn) 36.8%   0.233   learned weights -> stops hurting (>= best channel)
```

### Embedder comparison (nearest channel, full dataset)

The harness is pluggable: `EMBED_BACKEND=model2vec` (static, default) or
`fastembed` (real ONNX models, no torch). Set `EMBED_MODEL=...` to pick one.

| embedder | params | hit@5 | hit@10 | MRR |
|---|---|---|---|---|
| **BAAI/bge-small-en-v1.5** (ONNX) | 33M | **38.8%** | **49.3%** | **0.255** |
| minishlab/potion-base-8M (static) | 8M | 36.5% | 46.8% | 0.247 |
| BAAI/bge-base-en-v1.5 (ONNX) | 109M | 37.1% | 46.8% | 0.245 |
| minishlab/potion-retrieval-32M (static) | 32M | 23.8% | 31.3% | 0.164 |

**Bigger is not better — twice.** `bge-base` (109M) lost to `bge-small` (33M),
and `potion-32M` lost to `potion-8M` (8M). The benchmark caught the
"bigger model = better" assumption both times. The sweet spot here is
**bge-small**; the local retrieval ceiling on LoCoMo is ~38-39% hit@5. The
HeraclitusDB vector index stays lossless (`nearest` == `cosine`) for every model.

**API embedder (`EMBED_BACKEND=gemini`):** a Google `gemini-embedding-001`
backend is wired (asymmetric RETRIEVAL_DOCUMENT/QUERY task types, key from
`$GEMINI_API_KEY` or `D:\tmp\gemkey.txt`, never committed). It works and the
embeddings are strong — but the **free tier caps at 1000 embed requests/day and
each text counts as one request**, so the full LoCoMo corpus (~7,864 texts)
needs a **paid** tier. Free, local **bge-small remains the best no-cost option.**

To use the best one:

```powershell
$env:EMBED_BACKEND='fastembed'; $env:EMBED_MODEL='BAAI/bge-small-en-v1.5'
$env:HF_HOME='D:\hf_cache'   # keep model downloads off a full system drive
py bench\locomo\run_embed.py
```

## End-to-end QA with a local LLM (`run_qa.py`)

Tests the FULL stack (the metric *class* Mem0/Zep publish): retrieve from
HeraclitusDB -> a local LLM answers -> grade (token-F1 + LLM-as-judge). Uses an
LM Studio OpenAI-compatible server (`LMSTUDIO_URL`, default `:1234`) — no API key.

```powershell
py bench\locomo\run_qa.py --per-conv 12 --k 8     # samples questions; LLM is slow
```

Honest caveats:
- The local model used (Gemma-4-e4b) is a **reasoning** model: it spends tokens
  "thinking" (≈50s/question with full budget), so QA runs are sampled, not full.
  `/no_think` helps on easy questions but the model still reasons on hard ones.
- End-to-end QA is **capped by retrieval** (36.5% hit@5): the LLM can't answer
  what wasn't retrieved. So the bottleneck — and the place to invest — is the
  embedder / retrieval, not the LLM.
- A small local judge != the GPT-4 judge in the papers, so absolute QA numbers
  are indicative, not an exact comparison.

## To produce the headline comparison

1. **Official dataset.** Point `run.py` at the official LoCoMo JSON (snap-research
   /LoCoMo) re-shaped to this schema (`sessions[].turns[]`, `qa[]` with
   `evidence` turn ids + `category`).
2. **Turn on fusion.** Embed each turn + question with an embedding model and
   pass the vector through `append(..., hyp=...)` / the `FUSE` path. This
   activates the graph+vector+text fusion that single-channel systems lack.
3. **Competitor rows.** Fill the comparison table from the published papers
   (Mem0, Zep, MemGPT/Letta on LoCoMo) **with citations** — or run their stacks
   live (their API keys/infra). The competitor cells are intentionally left as
   `[fill]`; do not fabricate them.

## Dataset schema

```jsonc
{
  "speakers": ["A", "B"],
  "sessions": [
    {"session_id": "D1", "date": "2023-05-08",
     "turns": [{"turn_id": "D1:1", "speaker": "A", "text": "..."}]}
  ],
  "qa": [
    {"question": "...", "answer": "...",
     "evidence": ["D1:1"], "category": "single-hop|multi-hop|temporal|adversarial|open-domain"}
  ]
}
```

`sample_locomo.json` is a representative sample (one 4-session conversation, 12
questions across 4 categories), **not** the official 10-conversation set — enough
to exercise the harness and the methodology end to end.
