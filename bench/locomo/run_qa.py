#!/usr/bin/env python
"""LoCoMo end-to-end QA over HeraclitusDB + a local LLM (LM Studio / Gemma).

Tests the FULL stack — the metric class Mem0/Zep publish: retrieve memories from
HeraclitusDB, let the LLM answer, grade the answer. No API key: uses the local
LM Studio OpenAI-compatible server.

Pipeline per question:
  1. embed the question (model2vec) and retrieve top-k turns via HeraclitusDB
     NEAREST (the strong vector channel).
  2. the LLM answers using ONLY those excerpts.
  3. grade two ways: token-F1 vs gold (deterministic) AND LLM-as-judge.

Questions are sampled (the local LLM is slow). Run:
  py bench/locomo/run_qa.py [--per-conv 12] [--max-conv N] [--k 8]

Honest caveat: a small local judge (Gemma) is noisier than the GPT-4 judge in the
Mem0/Zep papers, so absolute numbers are INDICATIVE, not an exact comparison.
"""
import json
import os
import random
import re
import shutil
import sys
import tempfile
import urllib.request

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from run import load_conversations, start_server, stop_server, SERVER  # noqa: E402
from run_embed import SCALE  # noqa: E402

LLM_URL = os.environ.get("LMSTUDIO_URL", "http://localhost:1234/v1/chat/completions")
LLM_MODEL = os.environ.get("LMSTUDIO_MODEL", "google/gemma-4-e4b")
_TURN_RE = re.compile(r"^\[[^\]]+\]\s*")
_WORD_RE = re.compile(r"\w+")


def llm(messages, max_tokens=128):
    body = json.dumps({"model": LLM_MODEL, "messages": messages,
                       "temperature": 0, "max_tokens": max_tokens}).encode()
    req = urllib.request.Request(LLM_URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)["choices"][0]["message"]["content"].strip()


def ingest_qa(db, conv, model):
    """Ingest turns with the session date + speaker in the content (so the LLM can
    answer 'when' questions), embedding the plain text for retrieval."""
    ids, texts, contents = [], [], []
    for sess in conv["sessions"]:
        date = sess.get("date", "")
        for t in sess["turns"]:
            ids.append(t["turn_id"])
            texts.append(t["text"])
            contents.append(f"[{t['turn_id']}] ({date}) {t['speaker']}: {t['text']}")
    embs = np.asarray(model.encode(texts), dtype=np.float32)
    for tid, content, e in zip(ids, contents, embs):
        db.append("Observation", content, attrs={"turn_id": tid}, hyp=(e * SCALE).tolist())
    return ids, embs


def retrieve(db, q_emb, k):
    vec = ",".join(f"{x:.5f}" for x in (q_emb * SCALE))
    try:
        rows = db.query(f"NEAREST([{vec}], {k})")
    except Exception:
        return []
    return [r.get("content", "") for r in (rows if isinstance(rows, list) else [])]


def answer(question, excerpts):
    # `/no_think` must be at the very start of a single user turn (a system message
    # before it stops Gemma-4 from recognizing it). Disables the reasoning trace.
    ctx = "\n".join(f"- {_TURN_RE.sub('', e)}" for e in excerpts)
    prompt = ("/no_think\nAnswer the question from the conversation excerpts below. "
              "Reply with a short phrase only; if the excerpts don't contain the answer, "
              f"reply 'Not mentioned'.\n\nExcerpts:\n{ctx}\n\nQuestion: {question}\nAnswer:")
    # Gemma-4 reasons anyway on hard questions despite /no_think; give it room to
    # finish reasoning AND emit the answer in `content`.
    return llm([{"role": "user", "content": prompt}], max_tokens=512)


def token_f1(pred, gold):
    p, g = set(_WORD_RE.findall(pred.lower())), set(_WORD_RE.findall(gold.lower()))
    if not p or not g:
        return 0.0
    inter = len(p & g)
    if not inter:
        return 0.0
    prec, rec = inter / len(p), inter / len(g)
    return 2 * prec * rec / (prec + rec)


def judge(question, gold, pred):
    prompt = ("/no_think\nYou grade a QA answer. Reply with only YES or NO.\n"
              f"Question: {question}\nGold answer: {gold}\nPredicted answer: {pred}\n"
              "Does the prediction convey the same information as the gold? Reply YES or NO.")
    return "YES" in llm([{"role": "user", "content": prompt}], max_tokens=256).strip().upper()


def sample_qa(qa, per_conv, rng):
    have_ev = [q for q in qa if q.get("evidence")]
    by_cat = {}
    for q in have_ev:
        by_cat.setdefault(q["category"], []).append(q)
    picked = []
    for cat, items in by_cat.items():
        rng.shuffle(items)
    # round-robin across categories up to per_conv
    cats = list(by_cat)
    i = 0
    while len(picked) < per_conv and any(by_cat[c] for c in cats):
        c = cats[i % len(cats)]
        if by_cat[c]:
            picked.append(by_cat[c].pop())
        i += 1
    return picked


def main():
    argv = sys.argv[1:]
    per_conv, max_conv, k = 12, None, 8
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--per-conv":
            per_conv = int(argv[i + 1]); i += 2; continue
        if a == "--max-conv":
            max_conv = int(argv[i + 1]); i += 2; continue
        if a == "--k":
            k = int(argv[i + 1]); i += 2; continue
        i += 1

    ds = os.path.join(_HERE, "locomo10.json")
    if not os.path.exists(ds):
        ds = os.path.join(_HERE, "sample_locomo.json")
    if not os.path.exists(SERVER):
        sys.exit(f"server binary not found: {SERVER}")
    # sanity: LLM reachable
    try:
        llm([{"role": "user", "content": "ok"}], max_tokens=2)
    except Exception as e:
        sys.exit(f"local LLM not reachable at {LLM_URL}: {e}")

    from model2vec import StaticModel
    print("loading embedder...")
    model = StaticModel.from_pretrained("minishlab/potion-base-8M")
    convs = load_conversations(ds)
    if max_conv:
        convs = convs[:max_conv]
    rng = random.Random(0)

    cats = {}
    tot = {"n": 0, "f1": 0.0, "f1_hit": 0, "judge_hit": 0}
    for idx, conv in enumerate(convs):
        picks = sample_qa(conv["qa"], per_conv, rng)
        if not picks:
            continue
        data_dir = tempfile.mkdtemp(prefix="locomo_qa_")
        proc = None
        try:
            proc, db = start_server(data_dir)
            ids, embs = ingest_qa(db, conv, model)
            q_embs = np.asarray(model.encode([q["question"] for q in picks]), dtype=np.float32)
            for q, qe in zip(picks, q_embs):
                ex = retrieve(db, qe, k)
                pred = answer(q["question"], ex)
                f1 = token_f1(pred, q["answer"])
                jhit = judge(q["question"], q["answer"], pred)
                cat = q["category"]
                c = cats.setdefault(cat, {"n": 0, "f1": 0.0, "f1_hit": 0, "judge_hit": 0})
                for bucket in (c, tot):
                    bucket["n"] += 1
                    bucket["f1"] += f1
                    bucket["f1_hit"] += 1 if f1 >= 0.5 else 0
                    bucket["judge_hit"] += 1 if jhit else 0
            print(f"  [{idx+1}/{len(convs)}] {conv['id']}: {len(picks)} q evaluated (running n={tot['n']})")
        finally:
            stop_server(proc)
            shutil.rmtree(data_dir, ignore_errors=True)

    n = tot["n"]
    print("\n" + "=" * 64)
    print(" HeraclitusDB + Gemma-4-e4b (local) - LoCoMo end-to-end QA")
    print("=" * 64)
    print(f" sampled {n} questions | retrieval k={k} (HDB NEAREST) | judge=local Gemma\n")
    print(f"   {'category':<12} {'n':>3}   F1     F1>=.5   judge-acc")
    for cat, c in sorted(cats.items()):
        cn = c["n"]
        print(f"   {cat:<12} {cn:>3}  {c['f1']/cn:5.2f}  {100*c['f1_hit']/cn:5.1f}%   {100*c['judge_hit']/cn:5.1f}%")
    print(f"   {'OVERALL':<12} {n:>3}  {tot['f1']/n:5.2f}  {100*tot['f1_hit']/n:5.1f}%   {100*tot['judge_hit']/n:5.1f}%")
    print("=" * 64)
    print(" judge-acc = local-Gemma-judged QA accuracy (indicative; not the GPT-4 judge of Mem0/Zep)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
