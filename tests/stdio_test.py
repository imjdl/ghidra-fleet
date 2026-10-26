"""MCP stdio protocol test: spawn the real server as ZCode would and talk MCP.

Verifies: clean JSON-RPC on stdout despite the embedded JVM (fd guard),
tool listing, and a few real tool calls end-to-end.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if not os.environ.get("GHIDRA_INSTALL_DIR"):
    print("ERROR: 请先设置 GHIDRA_INSTALL_DIR=<你的 Ghidra 安装目录> 再运行测试")
    raise SystemExit(1)
# keep test runs on the repo's project dir (reuses cache, stays out of ~)
os.environ.setdefault("GHIDRA_FLEET_PROJECT_DIR", str(ROOT / "projects"))


def text_of(result) -> str:
    try:
        return str(result.content[0].text)
    except Exception:
        return str(result)


async def main() -> None:
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    py = str(ROOT / ".venv" / "Scripts" / "python.exe")
    if not Path(py).exists():  # POSIX venv layout
        py = str(ROOT / ".venv" / "bin" / "python")
    transport = StdioTransport(
        command=py,
        args=["-m", "ghidra_fleet"],
        env={
            "GHIDRA_INSTALL_DIR": os.environ["GHIDRA_INSTALL_DIR"],
            "GHIDRA_FLEET_PROJECT_DIR": os.environ["GHIDRA_FLEET_PROJECT_DIR"],
        },
        cwd=str(ROOT),
    )
    async with Client(transport) as client:
        tools = await client.list_tools()
        names = sorted(t.name for t in tools)
        print(f"[PASS] initialize + tools/list: {len(tools)} tools")
        assert "analyze_binaries" in names and "decompile_function" in names

        r = await client.call_tool("list_binaries", {})
        body = text_of(r)
        print(f"[PASS] list_binaries: {body[:160]}")
        assert "where.exe" in body.lower()

        r = await client.call_tool(
            "list_functions", {"binary": "where.exe", "limit": 5}
        )
        print(f"[PASS] list_functions: {text_of(r)[:160]}")

        r = await client.call_tool(
            "decompile_function", {"binary": "where.exe", "function": "entry"}
        )
        code = text_of(r)
        print(f"[PASS] decompile_function(entry): {code[:100]}...")
        assert "ERROR" not in code[:200]

        r = await client.call_tool(
            "find_in_all_binaries", {"kind": "string", "query": "Windows", "limit_per_binary": 3}
        )
        out = text_of(r)
        print(f"[PASS] find_in_all_binaries: {out[:160]}")
        assert "=== " in out

    print("\nSTDIO PROTOCOL TEST PASSED")


if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)
