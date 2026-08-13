#!/usr/bin/env python
"""HeraclitusDB MCP server — expose the event-sourced memory substrate to agents.

A native Model Context Protocol (stdio) server that lets any MCP client (Claude
Desktop/Code, etc.) use HeraclitusDB as agent memory: append episodes, recall
semantically, run the full GQL surface (graph / temporal / fusion / causal /
decision), and trace provenance — all over the running gRPC service.

Run:
    py mcp/heraclitus_mcp.py            # talks to 127.0.0.1:7474 (override: HERACLITUS_ADDR)

The intelligence lives in the agent; this server is just the doorway to the river.
"""
import json
import os
import sys

# The HeraclitusDB Python SDK lives next to this file, under ../sdk/python.
_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_ROOT), "sdk", "python"))

import heraclitusdb  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

ADDR = os.environ.get("HERACLITUS_ADDR", "127.0.0.1:7474")
EMBED_MODEL = os.environ.get("HERACLITUS_EMBED_MODEL", "BAAI/bge-small-en-v1.5")
BALL_SCALE = 0.9  # keep embeddings inside the Poincaré ball (matches the benchmark)

# Keep the embedding-model download off a full system drive (reuse the cache).
if os.path.isdir("D:\\") and not os.environ.get("HF_HOME"):
    os.environ["HF_HOME"] = r"D:\hf_cache"

_EMBEDDER = None


def _embed(text: str):
    """Embed text with a local model (bge-small via fastembed) -> Poincaré-ball
    point for HeraclitusDB's vector channel. Returns None if embeddings are
    unavailable (the server then degrades to text-only — old memories still work)."""
    global _EMBEDDER
    try:
        import numpy as np
        if _EMBEDDER is None:
            from fastembed import TextEmbedding
            _EMBEDDER = TextEmbedding(EMBED_MODEL)
        v = np.asarray(next(iter(_EMBEDDER.embed([text]))), dtype=np.float32)
        n = float(np.linalg.norm(v))
        if n > 0:
            v = v / n
        return [float(x * BALL_SCALE) for x in v]
    except Exception:
        return None


def _rrf_merge(*ranked_lists, k0=60):
    """Reciprocal-rank fusion of row lists keyed by id -> merged rows (best first)."""
    score, row_by_id = {}, {}
    for rows in ranked_lists:
        for rank, r in enumerate(rows or []):
            rid = r.get("id")
            if rid is None:
                continue
            score[rid] = score.get(rid, 0.0) + 1.0 / (k0 + rank + 1)
            row_by_id.setdefault(rid, r)
    order = sorted(score, key=lambda rid: -score[rid])
    return [row_by_id[rid] for rid in order]


mcp = FastMCP(
    "heraclitusdb",
    instructions=(
        "HeraclitusDB is an event-sourced memory substrate for agents: an "
        "append-only log of episodes with derived graph, vector, text and "
        "causal views. Use `remember` to persist knowledge, `recall` for "
        "semantic search, `query` to run GQL (graph traversal, temporal AS OF, "
        "fusion, hypotheses, causal WHY, communities), and `why`/`provenance` "
        "to explain where a fact came from. Nothing is ever overwritten — "
        "memory evolves by appending."
    ),
)


def _db():
    """Open a fresh connection to the running HeraclitusDB gRPC service."""
    return heraclitusdb.connect(ADDR)


def _err(action: str, exc: Exception) -> dict:
    """Actionable error payload (guides the agent toward a fix)."""
    return {
        "error": f"{action} failed: {exc}",
        "hint": (
            f"Is the HeraclitusDB service running at {ADDR}? "
            "Check `Get-Service HeraclitusDB` (Windows) or set HERACLITUS_ADDR."
        ),
    }


@mcp.tool()
def remember(
    text: str,
    kind: str = "learning",
    project: str = "",
    tags: str = "",
    parents: str = "",
) -> dict:
    """Append a memory to the log (the single source of truth). Never overwrites.

    Args:
        text: The fact / observation / decision to remember.
        kind: One of learning | decision | rule | fact | user | observation.
        project: Optional project/namespace this memory belongs to.
        tags: Optional comma-separated tags (e.g. "build,windows").
        parents: Optional comma-separated event ULIDs that caused this memory
                 (provenance edges — power WHY / causal traces later).

    Returns:
        {"lsn": <int>, "id": <ULID or null>, "embedded": <bool>} — the log
        position, server id, and whether a semantic vector was stored.
    """
    parent_ids = [p.strip() for p in parents.split(",") if p.strip()]
    attrs = {"generated_by": "mcp", "mem_kind": kind}
    if project:
        attrs["project"] = project
    if tags:
        attrs["tags"] = tags
    # Embed the memory so `recall` can find it semantically (not just by keyword).
    hyp = _embed(text)
    try:
        with _db() as d:
            lsn = d.append(
                "Observation", text, attrs=attrs, parents=parent_ids,
                hyp=hyp or [],
            )
            # Best-effort read-back of the server-assigned id (useful for parents).
            eid = None
            try:
                rows = d.query(f"MATCH (n) WHERE n.lsn = {lsn} RETURN n LIMIT 1")
                if isinstance(rows, list) and rows:
                    eid = rows[0].get("id")
            except Exception:
                pass
            return {"lsn": lsn, "id": eid, "embedded": hyp is not None}
    except Exception as exc:  # noqa: BLE001
        return _err("remember", exc)


@mcp.tool()
def recall(query: str, limit: int = 10) -> list | dict:
    """Recall memories by meaning, not just keywords.

    Fuses two channels (reciprocal-rank fusion): the semantic vector channel
    (embeds the query and runs the manifold ANN over embedded memories) and the
    lexical/activation channel (covers memories stored before embeddings, and
    exact-term matches). New memories are found by meaning; old ones still by text.

    Args:
        query: Natural-language text to search the memory for.
        limit: Max rows to return (default 10).

    Returns:
        A list of matching episodes (most relevant first), each with id, lsn,
        content and score.
    """
    try:
        with _db() as d:
            # semantic vector channel (embedded memories)
            vec_rows = []
            qv = _embed(query)
            if qv is not None:
                vec = ",".join(f"{x:.5f}" for x in qv)
                try:
                    vec_rows = d.query(f"NEAREST([{vec}], {limit})") or []
                except Exception:
                    vec_rows = []
            # lexical + activation channel (all memories)
            text_rows = d.recall(query, k=limit)
            text_rows = text_rows if isinstance(text_rows, list) else []
            merged = _rrf_merge(vec_rows, text_rows)
            return merged[:limit] if merged else text_rows[:limit]
    except Exception as exc:  # noqa: BLE001
        return _err("recall", exc)


@mcp.tool()
def query(gql: str) -> str:
    """Run a GQL/Cypher-subset statement against HeraclitusDB. The power tool.

    Supported statements (all reads accept a trailing `AS OF LSN <n>` snapshot,
    and any query may be prefixed with `REQUIRE LSN >= <n>` to fail fast if the
    backend has not caught up):

      MATCH (n) WHERE n.attr = "x" RETURN n            -- scan/filter
      MATCH (a)-[r:socio_de]->(b) AS OF LSN 100 RETURN *   -- temporal edge match
      RECALL ("text", 5)                               -- two-stage retrieval
      NEAREST ([0.1, 0.2], 10)                          -- vector ANN
      PROVENANCE ("01K...")                             -- causal parents
      NEIGHBORS ("node" [, "edge_type"])                -- 1-hop graph
      TRAVERSE ("node", depth)                          -- BFS
      FUSE ("text", [vec], "anchor", k)                 -- graph+vector+text fusion
      RESOLVE ("CPF:111") / CLUSTER ("entity")          -- entity resolution
      HYPOTHESES ("from", "to", "type")                 -- competing edge beliefs
      WHY ("event_id" [, depth])                        -- minimal causal chain
      COMMUNITY ("node") / METRICS ("node")             -- analytics (fraud rings)
      DECIDE ()                                         -- rules → Action events
      SIMULATE ADD/REMOVE EDGE ("a","b","type") THEN <q>   -- counterfactual
      ADAPT ()                                          -- learn thresholds from feedback
      EXPLAIN <stmt>                                    -- show the plan

    Args:
        gql: The GQL statement to execute.

    Returns:
        The query result as a JSON string. The shape depends on the statement:
        a JSON array of rows (MATCH/NEIGHBORS/FUSE/...), an object
        (RESOLVE/HYPOTHESES/WHY/COMMUNITY/DECIDE/ADAPT), the plan text (EXPLAIN),
        or null (e.g. HYPOTHESES on a non-existent edge).
    """
    try:
        with _db() as d:
            return json.dumps(d.query(gql), ensure_ascii=False, indent=2)
    except Exception as exc:  # noqa: BLE001
        return json.dumps(_err("query", exc), ensure_ascii=False)


@mcp.tool()
def why(event_id: str, max_depth: int = 64) -> dict:
    """Explain an event: the minimal causal chain behind it over the provenance DAG.

    Args:
        event_id: The ULID of the event/fact to explain.
        max_depth: Max provenance hops to walk back (default 64).

    Returns:
        {"target", "roots" (the original observations), "steps":[{id, depth,
        causes}]} — the causes are exactly the provenance pointers.
    """
    try:
        with _db() as d:
            return d.query(f'WHY ("{event_id}", {int(max_depth)})')
    except Exception as exc:  # noqa: BLE001
        return _err("why", exc)


@mcp.tool()
def provenance(event_id: str) -> list | dict:
    """Direct provenance: the ULIDs of the episodes that caused `event_id`.

    Args:
        event_id: The ULID whose parents (provenance edges) to return.

    Returns:
        A list of parent ULIDs (empty for a root observation).
    """
    try:
        with _db() as d:
            return d.provenance(event_id)
    except Exception as exc:  # noqa: BLE001
        return _err("provenance", exc)


@mcp.tool()
def stats() -> dict:
    """Server health and view statistics (head LSN, indexed counts, active views).

    Returns:
        A dict of server stats (or {ok, message} if the payload isn't JSON).
    """
    try:
        with _db() as d:
            res = d.stats()
            msg = res.get("message", "") if isinstance(res, dict) else str(res)
            try:
                return json.loads(msg)
            except (ValueError, TypeError):
                return res if isinstance(res, dict) else {"message": msg}
    except Exception as exc:  # noqa: BLE001
        return _err("stats", exc)


REST_ADDR = os.environ.get("HERACLITUS_REST_ADDR", "127.0.0.1:7475")


def _rest_get(path: str) -> dict:
    """GET no admin REST do servidor (introspecção: /state, /verify/<id>)."""
    import urllib.request

    with urllib.request.urlopen(f"http://{REST_ADDR}{path}", timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


@mcp.tool()
def verify(segment: int = -1) -> dict:
    """Cryptographic integrity check (Merkle/Blake3) of the log.

    With no argument, verifies the WHOLE log (every sealed segment's recomputed
    Merkle root must match its footer). With a segment id, verifies just that
    segment and returns its roots — the `heraclitus_verify_segment` pattern.

    Args:
        segment: Segment id to verify, or -1 (default) for the whole log.

    Returns:
        Whole log: {"segments", "records", "merkle_ok"}. One segment:
        {"found", "id", "version", "sealed", "records", "computed_root",
        "stored_root", "valid"}.
    """
    try:
        if segment >= 0:
            return _rest_get(f"/verify/{int(segment)}")
        with _db() as d:
            res = d.verify()
            return res if isinstance(res, dict) else {"result": res}
    except Exception as exc:  # noqa: BLE001
        return _err("verify", exc)


@mcp.tool()
def state() -> dict:
    """Operational introspection in one call: `heraclitus_state()`.

    Returns:
        {"head_lsn", "sealed_segments": [{id, version, sealed, base_lsn,
        max_lsn, blake3_root}], "views": {"watermarks", "min_watermark"},
        "log_only"} — what an operator needs to diagnose boot/replay/lag
        without reading service logs.
    """
    try:
        return _rest_get("/state")
    except Exception as exc:  # noqa: BLE001
        return _err("state", exc)


if __name__ == "__main__":
    mcp.run()  # stdio transport
