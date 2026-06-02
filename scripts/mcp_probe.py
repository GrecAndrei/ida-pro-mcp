"""Tiny stdio wrapper for the ida-pro-mcp server.

Run a real MCP round-trip without needing a full MCP client. Useful for
sanity-checking the server during development: initialize, list tools,
optionally invoke a single tools/call and print the result.

Usage:
    # list all advertised tools
    python scripts/mcp_probe.py

    # call a specific tool
    python scripts/mcp_probe.py --call segments --args '{"action":"list","_qol_mode":"tiny"}'

    # pretty-print the result
    python scripts/mcp_probe.py --call segments --args '{"action":"list"}' --pretty

The script invokes ``ida_mcp_stdio.py`` from the repo root and pipes a
handful of JSON-RPC messages over its stdin. The server is stateless, so
calling fixups-style actions on a missing IDB returns SESSION_REQUIRED.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STDIO_SCRIPT = REPO_ROOT / "ida_mcp_stdio.py"


def build_payload(call_name: str | None, call_args: dict | None) -> list[dict]:
    msgs: list[dict] = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp_probe", "version": "1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"limit": 200}},
    ]
    if call_name:
        msgs.append(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": call_name,
                    "arguments": call_args or {},
                },
            }
        )
    return msgs


def run(payload: list[dict]) -> list[dict]:
    proc = subprocess.run(
        [sys.executable, str(STDIO_SCRIPT)],
        input="\n".join(json.dumps(m) for m in payload) + "\n",
        capture_output=True,
        text=True,
        timeout=10,
    )
    responses: list[dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            responses.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return responses


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--call", help="Tool name to invoke (e.g. segments)")
    parser.add_argument(
        "--args",
        help="JSON object of tool arguments",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print tool/call results",
    )
    parser.add_argument(
        "--show-only",
        choices=["init", "list", "call", "all"],
        default="all",
        help="Limit which responses are printed",
    )
    args = parser.parse_args()

    call_args: dict | None = None
    if args.args:
        call_args = json.loads(args.args)
    payload = build_payload(args.call, call_args)
    responses = run(payload)

    show_map = {"init": (1,), "list": (2,), "call": (3,), "all": None}
    wanted = show_map[args.show_only]
    for resp in responses:
        if wanted is not None and resp.get("id") not in wanted:
            continue
        if args.pretty:
            print(json.dumps(resp, indent=2, sort_keys=True))
        else:
            print(json.dumps(resp))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
