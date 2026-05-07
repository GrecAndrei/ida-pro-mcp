#!/usr/bin/env python3
"""Minimal real MCP stdio client for ida-pro-mcp server."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys


class MCPStdioClient:
    def __init__(self, cmd: list[str]):
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._id = 0

    def call(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        req = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            req["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if not line:
            err = ""
            if self.proc.stderr is not None:
                err = self.proc.stderr.read()
            raise RuntimeError(f"MCP connection closed; stderr: {err[:2000]}")
        return json.loads(line)

    def close(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser(description="Real stdio MCP client smoke test")
    ap.add_argument("--binary", required=True, help="Binary path for session.create")
    args = ap.parse_args()

    client = MCPStdioClient([sys.executable, "-m", "ida_pro_mcp.server"])
    try:
        init = client.call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "real-client", "version": "0.1"}})
        print("initialize:", "error" not in init)

        tools = client.call("tools/list", {})
        print("tools/list:", "error" not in tools)

        create = client.call("tools/call", {"name": "session", "arguments": {"action": "create", "binary_path": args.binary}})
        print("session.create:", "error" not in create)

        meta = client.call("tools/call", {"name": "idb", "arguments": {"action": "meta"}})
        print("idb.meta:", "error" not in meta)
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
