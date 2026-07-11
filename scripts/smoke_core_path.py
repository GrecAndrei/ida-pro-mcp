#!/usr/bin/env python3
"""Core-path smoke for Tier A agent workflow (live IDA required).

Exercises:
  session.create → state → analysis.wait → search.find →
  (optional) intelligence.index_fast → search.nl → code.decompile →
  blackboard.write → session.close

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
    ap.add_argument("--with-nl", action="store_true", help="Also run index_fast + search.nl")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 2

    # Prefer package CLI client if present; fall back to scripts helper.
    try:
        from ida_pro_mcp.cli import MCPClient  # type: ignore
        client = MCPClient()
    except Exception:
        try:
            from scripts.mcp_client import MCPClient  # type: ignore
            client = MCPClient()
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
            "session",
            {"action": "create", "binary_path": str(binary)},
            "session.create",
        )
        created.get("session_id") or created.get("sid")

        _call(client, "session", {"action": "state"}, "session.state")
        _call(client, "analysis", {"action": "wait"}, "analysis.wait")

        find_res = _call(
            client,
            "search",
            {"action": "find", "pattern": "main", "limit": 5},
            "search.find",
        )
        addr = None
        items = find_res.get("items") or []
        if items and isinstance(items[0], dict):
            addr = items[0].get("addr") or items[0].get("ea")
        if not addr:
            # fall back to first function via data.functions if available
            data_res = _call(
                client,
                "data",
                {"action": "functions", "count": 1},
                "data.functions",
            )
            funcs = data_res.get("functions") or data_res.get("items") or []
            if funcs and isinstance(funcs[0], dict):
                addr = funcs[0].get("addr") or funcs[0].get("ea")

        if addr:
            _call(
                client,
                "code",
                {"action": "decompile", "addrs": str(addr)},
                "code.decompile",
            )
            _call(
                client,
                "blackboard",
                {
                    "action": "write",
                    "addr": str(addr),
                    "category": "smoke",
                    "title": "core_path_smoke",
                    "confidence": 0.5,
                },
                "blackboard.write",
            )

        if args.with_nl:
            _call(
                client,
                "intelligence",
                {"action": "index_fast"},
                "intelligence.index_fast",
            )
            _call(
                client,
                "search",
                {"action": "nl", "query": "entry point or main", "mode": "quick", "limit": 5},
                "search.nl",
            )

        print("core-path smoke PASSED")
        return 0
    finally:
        if True:
            try:
                _call(client, "session", {"action": "close"}, "session.close")
            except SystemExit:
                pass
            except Exception as e:
                print(f"session.close cleanup: {e}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
