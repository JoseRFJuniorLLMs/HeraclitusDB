# HeraclitusDB — Native MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server (stdio) that
exposes HeraclitusDB to any MCP client (Claude Code, Claude Desktop, …) as agent
memory. It talks to the running gRPC service (`127.0.0.1:7474`) via the bundled
Python SDK — so an agent gets append-only memory, semantic recall, the full GQL
surface (graph / temporal / fusion / causal / decision) and provenance, with no
custom glue.

> *Panta rhei* — the intelligence lives in the agent; this is the doorway to the river.

## Tools

| Tool | Read/Write | What it does |
|------|-----------|--------------|
| `remember(text, kind, project, tags, parents)` | write | Append a memory (never overwrites) **and embed it** (bge-small) so it's searchable by meaning. Returns `{lsn, id, embedded}`. |
| `recall(query, limit)` | read | **Semantic recall by meaning, not just keywords** — fuses the vector channel (manifold ANN over embedded memories) with the lexical/activation channel (covers older, non-embedded memories). |
| `query(gql)` | read/write | Run any GQL: `MATCH … AS OF`, `NEIGHBORS`, `TRAVERSE`, `FUSE`, `RESOLVE`, `HYPOTHESES`, `WHY`, `COMMUNITY`, `METRICS`, `DECIDE`, `SIMULATE … THEN …`, `ADAPT`, `REQUIRE LSN >= n`, `EXPLAIN`. Returns JSON. |
| `why(event_id, max_depth)` | read | Minimal causal chain over the provenance DAG. |
| `provenance(event_id)` | read | Direct causal parents of an event. |
| `stats()` | read | Server health / view counts / head LSN. |

## Run

```powershell
# Needs the HeraclitusDB service running (it serves gRPC on 127.0.0.1:7474).
$py = "C:\Users\web2a\AppData\Local\Python\pythoncore-3.14-64\python.exe"
& $py D:\DEV\HeraclitusDB\mcp\heraclitus_mcp.py        # stdio
```

Address override: set `HERACLITUS_ADDR` (default `127.0.0.1:7474`); embedder via
`HERACLITUS_EMBED_MODEL` (default `BAAI/bge-small-en-v1.5`).
Dependencies: `mcp`, `grpcio`, plus `fastembed` + `numpy` for semantic recall
(`& $py -m pip install mcp grpcio fastembed numpy`). If `fastembed` is missing,
the server degrades gracefully to text-only recall. (`bge-small` is the best
free local embedder measured on LoCoMo — see `bench/locomo/`.)

Smoke test (protocol-level, read-only):

```powershell
& $py D:\DEV\HeraclitusDB\mcp\test_mcp.py     # → "ALL OK"
```

## Wire into Claude

**Claude Code** (CLI):

```powershell
claude mcp add heraclitusdb -- `
  "C:\Users\web2a\AppData\Local\Python\pythoncore-3.14-64\python.exe" `
  "D:\DEV\HeraclitusDB\mcp\heraclitus_mcp.py"
```

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "heraclitusdb": {
      "command": "C:\\Users\\web2a\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe",
      "args": ["D:\\DEV\\HeraclitusDB\\mcp\\heraclitus_mcp.py"],
      "env": { "HERACLITUS_ADDR": "127.0.0.1:7474" }
    }
  }
}
```

Then the agent can: *"remember that X, then later recall it"*, *"why did fact Y
get derived?"*, *"find the fraud community around node Z"* — all backed by the
auditable, append-only log.
