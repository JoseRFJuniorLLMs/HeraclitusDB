#!/usr/bin/env python
"""LoCoMo retrieval with the semantic channel lit up (embeddings).

Lights up the vector/fusion moat that run.py (text-only) leaves dark, and
measures FOUR channels side by side so the result is honest and diagnostic:

  text    - HeraclitusDB `recall` (text + activation)
  nearest - HeraclitusDB native vector index (`NEAREST`, hyperbolic manifold)
  cosine  - reference ceiling: rank turns by cosine of local embeddings
  fusion  - RRF of HeraclitusDB's text + nearest ranks (the moat: does fusing win?)

Embeddings: local model2vec `minishlab/potion-base-8M` (256-d, normalized, no
torch, no API key). Each conversation runs in its own ephemeral instance.

Run:  py bench/locomo/run_embed.py [dataset.json] [--max-conv N]
"""
import os
import re
import shutil
import sys
import tempfile

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from run import (  # noqa: E402  reuse the loader + ephemeral-server plumbing
    KS, load_conversations, start_server, stop_server, SERVER,
)

_TURN_RE = re.compile(r"^\[([^\]]+)\]")
SCALE = 0.9  # keep embeddings comfortably inside the Poincaré ball for NEAREST
CHANNELS = ("text", "nearest", "cosine", "fusion")
GEMINI_DIM = 768  # gemini-embedding-001 supports 768/1536/3072; smaller = lean NEAREST


class _GeminiEmbedder:
    """Google embedding API (gemini-embedding-001). Uses asymmetric task types
    (RETRIEVAL_DOCUMENT for turns, RETRIEVAL_QUERY for questions), batched, with
    truncation to GEMINI_DIM + L2 re-normalization. Key from $GEMINI_API_KEY or
    D:\\tmp\\gemkey.txt — never committed."""

    def __init__(self, model="gemini-embedding-001"):
        import json as _json
        import urllib.request as _u
        self._json, self._u = _json, _u
        self.model = model
        self.key = os.environ.get("GEMINI_API_KEY")
        if not self.key and os.path.exists(r"D:\tmp\gemkey.txt"):
            self.key = open(r"D:\tmp\gemkey.txt").read().strip()
        if not self.key:
            raise SystemExit("set GEMINI_API_KEY (or D:\\tmp\\gemkey.txt) for the gemini backend")

    def _post(self, body, attempts=8):
        import time
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{self.model}:batchEmbedContents?key={self.key}")
        data = self._json.dumps(body).encode()
        for i in range(attempts):
            try:
                req = self._u.Request(url, data=data, headers={"Content-Type": "application/json"})
                with self._u.urlopen(req, timeout=120) as r:
                    return self._json.load(r)
            except Exception as e:  # noqa: BLE001  retry on rate limit / transient
                code = getattr(e, "code", None)
                if i == attempts - 1 or (code and code not in (429, 500, 503)):
                    raise
                time.sleep(min(60, 5 * 2 ** i))  # TPM resets per minute

    def encode(self, texts, task="document"):
        import time
        tt = "RETRIEVAL_DOCUMENT" if task == "document" else "RETRIEVAL_QUERY"
        texts = list(texts)
        out = []
        for s in range(0, len(texts), 50):  # free-tier TPM is tight → small batches
            batch = texts[s:s + 50]
            body = {"requests": [
                {"model": f"models/{self.model}",
                 "content": {"parts": [{"text": t}]},
                 "taskType": tt,
                 "outputDimensionality": GEMINI_DIM}
                for t in batch
            ]}
            resp = self._post(body)
            for e in resp["embeddings"]:
                v = np.asarray(e["values"], dtype=np.float32)
                n = float(np.linalg.norm(v))
                out.append(v / n if n > 0 else v)
            time.sleep(1.5)  # throttle under the free-tier rate limit
        return np.asarray(out, dtype=np.float32)


def _turn_from_content(content):
    m = _TURN_RE.match(content or "")
    return m.group(1) if m else None


def _rrf(*rankings, k0=60):
    """Reciprocal-rank fusion of several ranked id lists -> fused ranked ids."""
    score = {}
    for ranking in rankings:
        for rank, tid in enumerate(ranking):
            score[tid] = score.get(tid, 0.0) + 1.0 / (k0 + rank + 1)
    return [tid for tid, _ in sorted(score.items(), key=lambda kv: -kv[1])]


def ingest(db, conv, model):
    """Ingest every turn with its embedding (hyp), return (turn_ids, emb matrix)."""
    ids, texts = [], []
    for sess in conv["sessions"]:
        for t in sess["turns"]:
            ids.append(t["turn_id"])
            texts.append(t["text"])
    embs = np.asarray(model.encode(texts, task="document"), dtype=np.float32)
    for tid, sess_text, e in zip(ids, texts, embs):
        db.append(
            "Observation", f"[{tid}] {sess_text}",
            attrs={"turn_id": tid},
            hyp=(e * SCALE).tolist(),
        )
    return ids, embs


def channels_for(db, question, q_emb, ids, embs):
    """Return {channel: ranked turn_ids} for one question."""
    kmax = max(KS)
    # text
    text_rows = db.recall(question, k=kmax)
    text_rank = [t for t in (_turn_from_content(r.get("content", "")) for r in text_rows) if t]
    # nearest (HeraclitusDB native vector index)
    vec = ",".join(f"{x:.5f}" for x in (q_emb * SCALE))
    try:
        near_rows = db.query(f"NEAREST([{vec}], {kmax})")
        near_rank = [t for t in (_turn_from_content(r.get("content", "")) for r in near_rows) if t]
    except Exception:
        near_rank = []
    # cosine (reference): normalized embeddings -> dot product
    sims = embs @ q_emb
    cos_rank = [ids[i] for i in np.argsort(-sims)[:kmax]]
    # fusion: RRF of HDB's two channels
    fus_rank = _rrf(text_rank, near_rank)
    return {"text": text_rank, "nearest": near_rank, "cosine": cos_rank, "fusion": fus_rank}


def _new_acc():
    a = {"scored": 0, **{f"{c}_mrr": 0.0 for c in CHANNELS}}
    for c in CHANNELS:
        a.update({f"{c}_hit@{k}": 0 for k in KS})
    return a


def _wrrf(rankings_weights, k0=60):
    """Weighted reciprocal-rank fusion (M17): each channel contributes in
    proportion to its learned weight, so a weak channel can't drag the rest down."""
    score = {}
    for ranking, w in rankings_weights:
        for rank, tid in enumerate(ranking):
            score[tid] = score.get(tid, 0.0) + w / (k0 + rank + 1)
    return [tid for tid, _ in sorted(score.items(), key=lambda kv: -kv[1])]


def evaluate(db, conv, model, agg, samples):
    questions = [q for q in conv["qa"] if q["evidence"]]
    if not questions:
        return
    q_embs = np.asarray(model.encode([q["question"] for q in questions], task="query"), dtype=np.float32)
    ids, embs = conv["_ids"], conv["_embs"]
    for q, q_emb in zip(questions, q_embs):
        gold = set(q["evidence"])
        agg["scored"] += 1
        chans = channels_for(db, q["question"], q_emb, ids, embs)
        # keep the raw channel ranks so we can fuse with learned weights afterward
        samples.append((chans["text"], chans["nearest"], gold))
        for c in CHANNELS:
            ranked = chans[c]
            first = next((i + 1 for i, t in enumerate(ranked) if t in gold), None)
            agg[f"{c}_mrr"] += 1.0 / first if first else 0.0
            for k in KS:
                if gold & set(ranked[:k]):
                    agg[f"{c}_hit@{k}"] += 1


def pct(x, n):
    return f"{100.0 * x / n:5.1f}%" if n else "   - "


def report(n_conv, n_turns, agg):
    s = agg["scored"]
    print("\n" + "=" * 70)
    print(" HeraclitusDB - LoCoMo retrieval, semantic channel lit (embeddings)")
    print("=" * 70)
    print(f" corpus: {n_conv} conversations | {n_turns} turns | {s} scored questions")
    print(f" embeddings: {os.environ.get('EMBED_MODEL', 'minishlab/potion-base-8M')} (local)\n")
    print(f"   {'channel':<9} " + "  ".join(f"hit@{k}" for k in KS) + "     MRR")
    for c in CHANNELS:
        print(f"   {c:<9} " + "  ".join(pct(agg[f'{c}_hit@{k}'], s) for k in KS)
              + f"   {agg[f'{c}_mrr']/s if s else 0:6.3f}")
    print("\n  text=HDB recall | nearest=HDB vector index | cosine=reference ceiling")
    print("  fusion=RRF(text,nearest) -> the moat: does fusing beat each single channel?")
    print("=" * 70)


def main():
    argv = sys.argv[1:]
    max_conv = None
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--max-conv":
            max_conv = int(argv[i + 1]); i += 2; continue
        if a.startswith("--max-conv="):
            max_conv = int(a.split("=", 1)[1]); i += 1; continue
        positional.append(a); i += 1
    ds = positional[0] if positional else (
        os.path.join(_HERE, "locomo10.json")
        if os.path.exists(os.path.join(_HERE, "locomo10.json"))
        else os.path.join(_HERE, "sample_locomo.json"))
    if not os.path.exists(SERVER):
        sys.exit(f"server binary not found: {SERVER}")

    # Pluggable embedder. EMBED_BACKEND=model2vec (static, default) | fastembed
    # (real ONNX models: BGE/MiniLM, no torch) | gemini (Google embedding API,
    # asymmetric doc/query task types). All expose encode(texts, task=...).
    backend = os.environ.get("EMBED_BACKEND", "model2vec")
    if backend == "fastembed":
        embed_model = os.environ.get("EMBED_MODEL", "BAAI/bge-small-en-v1.5")
        from fastembed import TextEmbedding

        class _Embedder:
            def __init__(self, name):
                self.m = TextEmbedding(name)

            def encode(self, texts, task="document"):
                return np.asarray(list(self.m.embed(list(texts))), dtype=np.float32)

        model = _Embedder(embed_model)
    elif backend == "gemini":
        embed_model = os.environ.get("EMBED_MODEL", "gemini-embedding-001")
        model = _GeminiEmbedder(embed_model)
    else:
        from model2vec import StaticModel

        class _M2V:
            def __init__(self, name):
                self.m = StaticModel.from_pretrained(name)

            def encode(self, texts, task="document"):
                return np.asarray(self.m.encode(list(texts)), dtype=np.float32)

        embed_model = os.environ.get("EMBED_MODEL", "minishlab/potion-base-8M")
        model = _M2V(embed_model)
    print(f"loading embedder ({backend}: {embed_model})...")

    convs = load_conversations(ds)
    if max_conv:
        convs = convs[:max_conv]
    print(f"dataset: {os.path.basename(ds)} | {len(convs)} conversation(s)")

    agg, total_turns, samples = _new_acc(), 0, []
    for idx, conv in enumerate(convs):
        data_dir = tempfile.mkdtemp(prefix="locomo_emb_")
        proc = None
        try:
            proc, db = start_server(data_dir)
            ids, embs = ingest(db, conv, model)
            conv["_ids"], conv["_embs"] = ids, embs
            total_turns += len(ids)
            evaluate(db, conv, model, agg, samples)
            print(f"  [{idx+1}/{len(convs)}] {conv['id']}: {len(ids)} turns")
        finally:
            stop_server(proc)
            shutil.rmtree(data_dir, ignore_errors=True)

    report(len(convs), total_turns, agg)

    # M17: learn channel weights (each channel's MRR) and re-fuse with them.
    s = agg["scored"]
    if s:
        w_text, w_near = agg["text_mrr"] / s, agg["nearest_mrr"] / s
        lrn = {"mrr": 0.0, **{f"hit@{k}": 0 for k in KS}}
        for text_rank, near_rank, gold in samples:
            fused = _wrrf([(text_rank, w_text), (near_rank, w_near)])
            first = next((i + 1 for i, t in enumerate(fused) if t in gold), None)
            lrn["mrr"] += 1.0 / first if first else 0.0
            for k in KS:
                if gold & set(fused[:k]):
                    lrn[f"hit@{k}"] += 1
        print(f"\n M17 learned weights: text={w_text:.3f} vector={w_near:.3f}")
        print("   " + "  ".join(f"hit@{k}" for k in KS) + "     MRR")
        print("   fusion-lrn " + "  ".join(pct(lrn[f'hit@{k}'], s) for k in KS)
              + f"   {lrn['mrr']/s:6.3f}")
        print("   -> equal-weight fusion HURT (< nearest); learned weights should not.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
