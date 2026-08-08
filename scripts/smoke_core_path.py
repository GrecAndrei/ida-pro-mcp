#!/usr/bin/env python3
"""Core-path smoke for the public agent workflow (live IDA required).

Exercises:
  ida_open_binary → ida_session_state → ida_find → ida_decompile →
  ida_write_finding → optional ida_index_functions/ida_semantic_search

Usage:
  python scripts/smoke_core_path.py --binary /path/to/bin
  python scripts/smoke_core_path.py --binary /path/to/bin --with-nl

Exit 0 on success. This is intentionally small — not the 1000-action matrix.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))


class _ToolClient:
    """Uniform ``call_tool(tool, args) -> payload dict`` adapter.

    ``ida_pro_mcp.cli.MCPStdioClient`` speaks raw JSON-RPC (``call(method,
    params)``) and returns the top-level response; the scripts/ helper client
    (``mcp_client.MCPClient``) already unwraps the tool payload from the MCP
    result.  This wrapper hides both shapes from the rest of the smoke.
    """

    def __init__(self, client, *, payload: bool = True):
        self._client = client
        self._payload = payload

    def call_tool(self, tool: str, args: dict) -> dict:
        if not self._payload:
            return self._client.call(tool, args)
        resp = self._client.call("tools/call", {"name": tool, "arguments": args})
        if not isinstance(resp, dict) or "result" not in resp:
            return resp if isinstance(resp, dict) else {"error": "no response"}
        result = resp["result"]
        content = result.get("content") or []
        if content and isinstance(content[0], dict):
            try:
                return json.loads(content[0].get("text", "{}"))
            except (TypeError, ValueError):
                return {"_raw": str(content[0].get("text", ""))[:500]}
        return result


def _call(client, tool: str, args: dict, label: str) -> dict:
    t0 = time.time()
    res = client.call_tool(tool, args)
    dt = time.time() - t0
    ok = not (isinstance(res, dict) and res.get("error"))
    status = "OK" if ok else "FAIL"
    print(f"{status:4} {label:40} {dt:6.2f}s")
    if not ok:
        print(json.dumps(res, indent=2, default=str)[:2000])
        raise SystemExit(f"core path failed at {label}")
    return res if isinstance(res, dict) else {"result": res}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True, help="Path to binary to open")
    ap.add_argument("--with-nl", action="store_true", help="Also run indexing + semantic search")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 2

    # Prefer the package CLI client; fall back to the scripts/ helper client.
    # Both are wrapped so the rest of the script only sees call_tool(tool, args).
    try:
        from ida_pro_mcp.cli import MCPStdioClient
        raw = MCPStdioClient([sys.executable, "-m", "ida_pro_mcp.host.server"])
        raw.call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke_core_path"},
            },
        )
        client = _ToolClient(raw)
    except Exception:
        try:
            from mcp_client import MCPClient  # scripts/ helper (scripts/ is on sys.path)

            client = _ToolClient(MCPClient())
        except Exception as e:
            print(
                "No MCP client available. Run against a live host via your MCP client, "
                f"or install the package client. Import error: {e}",
                file=sys.stderr,
            )
            return 2

    print(f"core-path smoke binary={binary}")
    try:
        created = _call(
            client,
            "ida_open_binary",
            {"binary_path": str(binary)},
            "ida_open_binary",
        )
        created_sid = created.get("session_id") or created.get("sid")
        if not created_sid:
            # Session may still be active (ida_session_state targets it), so
            # this is a diagnostic warning, not a hard failure.
            print(
                "WARNING: ida_open_binary returned no session id: "
                f"{json.dumps(created, default=str)[:300]}",
                file=sys.stderr,
            )

        _call(client, "ida_session_state", {}, "ida_session_state")

        find_res = _call(
            client,
            "ida_find",
            {"query": "main", "limit": 5},
            "ida_find",
        )
        addr = None
        items = find_res.get("items") or []
        if items and isinstance(items[0], dict):
            addr = items[0].get("addr") or items[0].get("ea")
        if not addr:
            # Fall back to the first listed function if no match has an address.
            data_res = _call(
                client,
                "ida_list_functions",
                {"limit": 1},
                "ida_list_functions",
            )
            funcs = data_res.get("functions") or data_res.get("items") or []
            if funcs and isinstance(funcs[0], dict):
                addr = funcs[0].get("addr") or funcs[0].get("ea")

        if addr:
            _call(
                client,
                "ida_decompile",
                {"address": str(addr)},
                "ida_decompile",
            )
            _call(
                client,
                "ida_write_finding",
                {
                    "address": str(addr),
                    "category": "smoke",
                    "title": "core_path_smoke",
                    "confidence": 0.5,
                },
                "ida_write_finding",
            )

        if args.with_nl:
            _call(
                client,
                "ida_index_functions",
                {},
                "ida_index_functions",
            )
            _call(
                client,
                "ida_semantic_search",
                {"query": "entry point or main", "mode": "quick", "limit": 5},
                "ida_semantic_search",
            )

        print("core-path smoke PASSED")
        return 0
    finally:
        try:
            _call(client, "ida_close_session", {}, "ida_close_session")
        except SystemExit:
            pass
        except Exception as e:
            print(f"session cleanup: {e}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
