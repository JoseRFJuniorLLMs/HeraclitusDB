#!/usr/bin/env python
"""LoCoMo retrieval benchmark for HeraclitusDB.

Measures the *memory substrate's* job in isolation — does it surface the right
evidence turns for a question? — via retrieval recall@k / MRR. Directly
comparable to the retrieval the Mem0 / Zep / MemGPT pipelines rely on.

Each LoCoMo conversation is an INDEPENDENT memory: it is ingested into its own
**ephemeral** HeraclitusDB instance (temp data dir, alt ports) so conversations
never cross-contaminate and your live memory store is never touched.

Run:  py bench/locomo/run.py [dataset.json]
      (defaults to the official locomo10.json beside this file, else the sample)

Caveat (honest): the channel measured is text + activation. The vector/fusion
moat needs an embedding model on ingest (see README) — this is a conservative
lower bound.
"""
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, os.path.join(_REPO, "sdk", "python"))
import heraclitusdb  # noqa: E402

# Ephemeral instances + model downloads can write a lot; keep them off a full
# system drive. Override BENCH_TMP; default to D:\tmp when present.
_BENCH_TMP = os.environ.get("BENCH_TMP") or (r"D:\tmp" if os.path.isdir(r"D:\tmp") else None)
if _BENCH_TMP:
    os.makedirs(_BENCH_TMP, exist_ok=True)
    tempfile.tempdir = _BENCH_TMP
# Redirect the HuggingFace cache to D: too (model2vec downloads embedders there).
if os.path.isdir("D:\\") and not os.environ.get("HF_HOME"):
    os.environ["HF_HOME"] = r"D:\hf_cache"

SERVER = os.path.join(_REPO, "target", "release", "heraclitus-server.exe")
GRPC_ADDR = "127.0.0.1:7479"
REST_ADDR = "127.0.0.1:7478"
KS = (1, 3, 5, 10)
_TURN_RE = re.compile(r"^\[([^\]]+)\]")
_DIA_RE = re.compile(r"D\d+:\d+")
_CATEGORIES = {
    "1": "multi-hop",
    "2": "temporal",
    "3": "open-domain",
    "4": "single-hop",
    "5": "adversarial",
}


# ── dataset loading / schema adaptation ──────────────────────────────────────
def _parse_evidence(ev):
    """Official LoCoMo evidence is a stringified list like "['D1:3', 'D1:5']"."""
    if isinstance(ev, list):
        items = ev
    else:
        try:
            items = ast.literal_eval(str(ev))
            if not isinstance(items, list):
                items = [items]
        except (ValueError, SyntaxError):
            items = _DIA_RE.findall(str(ev))
    out = []
    for it in items:
        out += _DIA_RE.findall(str(it))
    return out


def _adapt_official(conv):
    """Map one official LoCoMo conversation to the internal harness format."""
    c = conv["conversation"]
    sessions = []
    i = 1
    while f"session_{i}" in c:
        turns = [
            {"turn_id": t.get("dia_id", ""), "speaker": t.get("speaker", ""),
             "text": t.get("text", "")}
            for t in c[f"session_{i}"]
            if t.get("text") and t.get("dia_id")
        ]
        sessions.append({"session_id": f"D{i}", "date": c.get(f"session_{i}_date_time", ""),
                         "turns": turns})
        i += 1
    qa = []
    for q in conv.get("qa", []):
        qa.append({
            "question": q.get("question", ""),
            "answer": str(q.get("answer", "")),
            "evidence": _parse_evidence(q.get("evidence", [])),
            "category": _CATEGORIES.get(str(q.get("category", "")), str(q.get("category", "?"))),
        })
    return {"id": conv.get("sample_id", "?"), "sessions": sessions, "qa": qa}


def load_conversations(path):
    """Return a list of conversations in internal format (handles both schemas)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):  # official LoCoMo = list of conversations
        return [_adapt_official(c) for c in data]
    return [{"id": data.get("conversation_id", "sample"),
             "sessions": data["sessions"], "qa": data["qa"]}]


# ── ephemeral server ─────────────────────────────────────────────────────────
def start_server(data_dir):
    env = dict(os.environ)
    env.update(HERACLITUS_DATA_DIR=data_dir, HERACLITUS_GRPC_ADDR=GRPC_ADDR,
               HERACLITUS_REST_ADDR=REST_ADDR)
    proc = subprocess.Popen([SERVER], env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    db = heraclitusdb.connect(GRPC_ADDR)
    for _ in range(80):
        try:
            db.head()
            return proc, db
        except Exception:
            if proc.poll() is not None:
                raise RuntimeError("server exited during startup")
            time.sleep(0.3)
    proc.terminate()
    raise RuntimeError(f"server at {GRPC_ADDR} not ready in time")


def stop_server(proc):
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


# ── ingest + evaluate one conversation ──────────────────────────────────────
def ingest(db, conv):
    n = 0
    for sess in conv["sessions"]:
        for t in sess["turns"]:
            db.append("Observation", f"[{t['turn_id']}] {t['speaker']}: {t['text']}",
                      attrs={"turn_id": t["turn_id"], "session": sess["session_id"]})
            n += 1
    return n


def retrieved_turns(db, question, k):
    rows = db.recall(question, k=k)
    out = []
    for r in rows if isinstance(rows, list) else []:
        m = _TURN_RE.match(r.get("content", "") or "")
        if m:
            out.append(m.group(1))
    return out


def _new_acc():
    a = {"n": 0, "scored": 0, "mrr": 0.0}
    a.update({f"hit@{k}": 0 for k in KS})
    a.update({f"rec@{k}": 0.0 for k in KS})
    return a


def evaluate(db, qa, agg, per_cat):
    for item in qa:
        gold = set(item["evidence"])
        cat = item.get("category", "?")
        c = per_cat.setdefault(cat, _new_acc())
        agg["n"] += 1
        c["n"] += 1
        if not gold:  # open-domain / adversarial without a retrievable turn
            continue
        agg["scored"] += 1
        c["scored"] += 1
        ranked = retrieved_turns(db, item["question"], max(KS))
        first = next((i + 1 for i, t in enumerate(ranked) if t in gold), None)
        mrr = 1.0 / first if first else 0.0
        agg["mrr"] += mrr
        c["mrr"] += mrr
        for k in KS:
            topk = set(ranked[:k])
            agg[f"hit@{k}"] += 1 if gold & topk else 0
            c[f"hit@{k}"] += 1 if gold & topk else 0
            agg[f"rec@{k}"] += len(gold & topk) / len(gold)
            c[f"rec@{k}"] += len(gold & topk) / len(gold)


# ── report ───────────────────────────────────────────────────────────────────
def pct(x, n):
    return f"{100.0 * x / n:5.1f}%" if n else "   - "


def report(n_conv, n_turns, agg, per_cat):
    s = agg["scored"]
    print("\n" + "=" * 66)
    print(" HeraclitusDB - LoCoMo retrieval benchmark")
    print("=" * 66)
    print(f" corpus: {n_conv} conversations | {n_turns} turns | "
          f"{agg['n']} questions ({s} with retrievable evidence)")
    print(" channel: text + activation (no embedding model) - conservative\n")
    print(" Overall (scored on questions with evidence turns)")
    print("   hit@1  hit@3  hit@5  hit@10    MRR    evidence-recall@5")
    print("   " + " ".join(pct(agg[f'hit@{k}'], s) for k in KS)
          + f"   {agg['mrr']/s if s else 0:5.3f}   {pct(agg['rec@5'], s)}\n")
    print(" By category")
    print(f"   {'category':<12} {'n':>4} {'scored':>6}  " + " ".join(f'hit@{k}' for k in KS) + "    MRR")
    for cat, c in sorted(per_cat.items()):
        sc = c["scored"]
        print(f"   {cat:<12} {c['n']:>4} {sc:>6}  "
              + " ".join(pct(c[f'hit@{k}'], sc) for k in KS)
              + f"   {c['mrr']/sc if sc else 0:5.3f}")
    print("\n Comparison (competitor rows = published headline, fill from paper; do not fabricate)")
    print(f"   {'system':<16} {'metric':>16}   note")
    print(f"   {'HeraclitusDB':<16} {pct(agg['hit@5'], s):>16}   retrieval hit@5, text-only (this harness)")
    print(f"   {'Mem0 / Zep / ..':<16} {'[fill]':>16}   LLM-judged QA accuracy (different metric - see README)")
    print("=" * 66)


def main():
    default = os.path.join(_HERE, "locomo10.json")
    ds_path = sys.argv[1] if len(sys.argv) > 1 else (
        default if os.path.exists(default) else os.path.join(_HERE, "sample_locomo.json"))
    if not os.path.exists(SERVER):
        sys.exit(f"server binary not found: {SERVER}\nbuild: cargo build --release -p heraclitus-server")
    convs = load_conversations(ds_path)
    print(f"dataset: {os.path.basename(ds_path)} | {len(convs)} conversation(s)")

    agg, per_cat, total_turns = _new_acc(), {}, 0
    for idx, conv in enumerate(convs):
        data_dir = tempfile.mkdtemp(prefix="locomo_hdb_")
        proc = None
        try:
            proc, db = start_server(data_dir)
            n = ingest(db, conv)
            total_turns += n
            evaluate(db, conv["qa"], agg, per_cat)
            print(f"  [{idx+1}/{len(convs)}] {conv['id']}: {n} turns, {len(conv['qa'])} qa")
        finally:
            stop_server(proc)
            shutil.rmtree(data_dir, ignore_errors=True)

    report(len(convs), total_turns, agg, per_cat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
