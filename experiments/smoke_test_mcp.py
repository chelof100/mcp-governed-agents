# -*- coding: utf-8 -*-
"""
Smoke test for P9 Sprint 0: launch the toy MCP server and call each of
the 5 tools through the official `mcp` Python client. Verifies that:

  - The MCP SDK installs and imports cleanly
  - stdio transport works on this machine
  - `tools/list` returns the expected 5 tools
  - `tools/call` returns deterministic results for each

Used as the gate for Sprint 1 (proxy implementation).
"""
from __future__ import annotations

import asyncio
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from mcp import StdioServerParameters
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client


EXPECTED_TOOLS = [
    "read_file", "query_api", "write_data", "delete_record", "admin_action",
]

CALL_FIXTURES = [
    ("read_file",     {"path": "/tmp/x.log"}),
    ("query_api",     {"endpoint": "/v1/users"}),
    ("write_data",    {"target": "db.users", "payload": "name=alice"}),
    ("delete_record", {"record_id": "user-42"}),
    ("admin_action",  {"action": "rotate_keys"}),
]


async def main() -> int:
    server_path = os.path.join(_ROOT, "proxy", "toy_server.py")
    params = StdioServerParameters(
        command=sys.executable,
        args=[server_path],
    )

    print("=" * 64)
    print("P9 Sprint 0 -- MCP smoke test")
    print(f"  Server: {server_path}")
    print("=" * 64)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = (await session.list_tools()).tools
            tool_names = sorted(t.name for t in tools)
            print(f"\n[tools/list] -> {tool_names}")
            missing = set(EXPECTED_TOOLS) - set(tool_names)
            if missing:
                print(f"  MISSING: {missing}")
                return 1

            print("\n[tools/call]")
            failures = 0
            for name, args in CALL_FIXTURES:
                result = await session.call_tool(name, args)
                if result.isError:
                    print(f"   {name:<14s} ERROR: {result.content!r}")
                    failures += 1
                    continue
                # Extract textual content
                payload = "".join(
                    getattr(c, "text", "") for c in result.content
                )
                ok = payload.startswith("[mock]")
                tag = "OK  " if ok else "FAIL"
                print(f"   {tag} {name:<14s} -> {payload[:60]}")
                if not ok:
                    failures += 1

            print("=" * 64)
            print(f"Result: {'PASSED' if failures == 0 else f'{failures} FAILED'}")
            return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
