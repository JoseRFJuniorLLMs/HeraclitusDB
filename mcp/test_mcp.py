"""Protocol-level smoke test for the HeraclitusDB MCP server.

Spawns heraclitus_mcp.py over stdio, lists the tools, and calls a few read-only
ones against the live gRPC service. Run: py mcp/test_mcp.py
"""
import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_HERE = os.path.dirname(os.path.abspath(__file__))


async def main() -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(_HERE, "heraclitus_mcp.py")],
        env=os.environ.copy(),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = (await session.list_tools()).tools
            names = sorted(t.name for t in tools)
            print(f"tools ({len(names)}): {names}")
            assert names == ["provenance", "query", "recall", "remember", "stats", "why"], names

            # stats (read-only) — proves the server reaches the live DB.
            r = await session.call_tool("stats", {})
            txt = r.content[0].text
            print("stats:", txt[:160])
            assert "head" in txt or "views" in txt, "stats missing expected fields"

            # query EXPLAIN (read-only, deterministic) — proves GQL passthrough.
            r = await session.call_tool("query", {"gql": "EXPLAIN MATCH (n) RETURN n"})
            assert not r.isError, f"query errored: {r.content[0].text[:200]}"
            print("explain:", r.content[0].text[:80].replace("\n", " "))
            assert "ScanFilter" in r.content[0].text

            # recall (read-only) — proves semantic retrieval path.
            r = await session.call_tool("recall", {"query": "HeraclitusDB", "limit": 2})
            print("recall:", r.content[0].text[:120])

    print("ALL OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
