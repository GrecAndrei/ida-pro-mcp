#!/usr/bin/env python3
"""Ephemeral CLI for driving the ida-pro-mcp server from shell scripts.

This is a thin JSON-safe wrapper around the existing stdio MCP server. It
starts the server only for the duration of the request, forwards JSON input
without shell interpolation, and exits immediately after printing a response.
"""

from __future__ import annotations

import argparse
import json
import os
import socket as _socket_mod
import subprocess
import sys
import tempfile
import time

from ida_pro_mcp import __version__
import threading
from dataclasses import dataclass
from typing import Any, Optional

_DAEMON_SOCKET = os.path.join(tempfile.gettempdir(), "ida-mcp-daemon.sock")


def _load_json_arg(value: Optional[str], *, label: str) -> Any:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON for {label}: {exc}") from exc


def _read_stdin_json(*, label: str) -> Any:
    raw = sys.stdin.read()
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON from stdin for {label}: {exc}") from exc


@dataclass
class _StderrTail:
    lines: list[str]
    limit: int = 40

    def push(self, text: str) -> None:
        self.lines.append(text)
        if len(self.lines) > self.limit:
            del self.lines[: len(self.lines) - self.limit]

    def text(self) -> str:
        return "\n".join(self.lines)


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
        self._stderr = _StderrTail([])
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        if self.proc.stderr is None:
            return
        for line in self.proc.stderr:
            self._stderr.push(line.rstrip("\n"))

    def send(self, request: dict[str, Any]) -> dict:
        if self.proc.stdin is None or self.proc.stdout is None:
            raise SystemExit("MCP process pipes are unavailable")
        self.proc.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            method = str(request.get("method", "request"))
            self._raise_closed(method)
        return json.loads(line)

    def call(self, method: str, params: Any = None, *, request_id: int | None = None) -> dict:
        if not method or not isinstance(method, str):
            raise SystemExit("method must be a non-empty string")
        rid = request_id if request_id is not None else self._next_id()
        req = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            req["params"] = params
        return self.send(req)

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _raise_closed(self, method: str) -> None:
        stderr = self._stderr.text()
        self.close()
        raise SystemExit(
            f"MCP server closed before responding to {method}.\n{stderr}".strip()
        )


def _server_cmd() -> list[str]:
    return [sys.executable, "-m", "ida_pro_mcp.host.server"]


def _print_json(value: Any, *, pretty: bool) -> None:
    if pretty:
        print(json.dumps(value, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def _normalize_tool_result(response: dict) -> Any:
    if "result" not in response:
        return response
    result = response["result"]
    content = result.get("content", [])
    if not isinstance(content, list) or not content:
        return result

    normalized_items = []
    for item in content:
        if not isinstance(item, dict):
            normalized_items.append(item)
            continue
        text = item.get("text")
        if not isinstance(text, str):
            normalized_items.append(item)
            continue
        try:
            normalized_items.append(json.loads(text))
        except json.JSONDecodeError:
            normalized_items.append({"text": text, "isError": bool(result.get("isError"))})

    if len(normalized_items) == 1:
        return normalized_items[0]
    return {"content": normalized_items, "isError": bool(result.get("isError"))}


def _daemon_is_running() -> bool:
    if not os.path.exists(_DAEMON_SOCKET):
        return False
    try:
        s = _socket_mod.socket(_socket_mod.AF_UNIX, _socket_mod.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect(_DAEMON_SOCKET)
        s.close()
        return True
    except Exception:
        return False


def _start_daemon() -> None:
    if os.path.exists(_DAEMON_SOCKET):
        os.unlink(_DAEMON_SOCKET)
    subprocess.Popen(
        [sys.executable, "-m", "ida_pro_mcp.host.server", "--daemon"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        close_fds=True,
    )
    deadline = time.time() + 10.0
    while not _daemon_is_running():
        if time.time() > deadline:
            raise SystemExit("Daemon did not start within 10 seconds")
        time.sleep(0.1)


def _daemon_call(tool_name: str, args: dict[str, Any]) -> dict:
    request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": args},
    }
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "ida-pro-mcp-cli", "version": __version__},
        },
    }
    s = _socket_mod.socket(_socket_mod.AF_UNIX, _socket_mod.SOCK_STREAM)
    s.settimeout(15.0)
    try:
        s.connect(_DAEMON_SOCKET)
        payload = (
            json.dumps(initialize, separators=(",", ":")) + "\n" +
            json.dumps(request, separators=(",", ":")) + "\n"
        )
        s.sendall(payload.encode("utf-8"))
        s.shutdown(_socket_mod.SHUT_WR)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        if not data:
            raise SystemExit("Daemon returned empty response")
        lines = [l.strip() for l in data.decode("utf-8").split("\n") if l.strip()]
        if not lines:
            raise SystemExit("Daemon returned no valid JSON lines")
        return json.loads(lines[-1])
    finally:
        s.close()


def _handle_background_mode(args):
    action = str(args.name or "list").strip().lower()
    payload = None
    if args.stdin_json:
        payload = _read_stdin_json(label="background")
    elif args.payload is not None:
        payload = _load_json_arg(args.payload, label="payload")
    tool_args: dict = payload if isinstance(payload, dict) else {}
    if tool_args:
        tool_args = dict(tool_args)
    else:
        tool_args = {}
    tool_args["action"] = action

    if action == "submit":
        if not tool_args.get("script") and not tool_args.get("tool_call"):
            raise SystemExit("background submit requires payload with 'script' or 'tool_call'")

    if action in ("result", "cancel", "wait"):
        task_id = tool_args.get("task_id")
        if not task_id:
            raise SystemExit(f"background {action} requires 'task_id' in payload")

    if not _daemon_is_running():
        _start_daemon()

    response = _daemon_call("background", tool_args)
    _print_json(_normalize_tool_result(response), pretty=args.pretty)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ephemeral JSON-safe CLI for ida-pro-mcp",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ida-pro-mcp-cli rpc tools/list '{}'\n"
            "  ida-pro-mcp-cli tool session '{\"action\":\"status\"}'\n"
            "  ida-pro-mcp-cli raw '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}'\n"
            "  ida-pro-mcp-cli intelligence status\n"
            "  ida-pro-mcp-cli capsule semantic-summary project.sideband --json\n"
            "  ida-pro-mcp-cli background submit '{\"script\":\"print(idc.get_idb_path())\"}'\n"
            "  ida-pro-mcp-cli background status\n"
            "  ida-pro-mcp-cli background result '{\"task_id\":\"abc123\"}'\n"
        ),
    )
    parser.add_argument(
        "mode",
        choices=("rpc", "tool", "raw", "tools-list", "intelligence", "capsule", "background"),
        help="Request type to execute",
    )
    parser.add_argument("name", nargs="?", help="RPC method or MCP tool name")
    parser.add_argument(
        "payload",
        nargs="?",
        help="JSON request params, tool args, or a full JSON-RPC object",
    )
    parser.add_argument(
        "--stdin-json",
        action="store_true",
        help="Read the JSON payload from stdin instead of argv",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    parser.add_argument(
        "--request-id",
        type=int,
        default=None,
        help="Override JSON-RPC request id",
    )
    parser.add_argument(
        "extra",
        nargs="*",
        help="Additional args (used by capsule mode)",
    )
    if "capsule" in sys.argv[1:2]:
        args, unknown = parser.parse_known_args()
    else:
        args = parser.parse_args()
        unknown = []

    payload = None
    if args.mode != "capsule":
        if args.stdin_json:
            payload = _read_stdin_json(label=args.mode)
        elif args.payload is not None:
            payload = _load_json_arg(args.payload, label="payload")

    if args.mode == "capsule":
        from ida_pro_mcp.capsule.cli import main as capsule_main

        capsule_args = []
        if args.name:
            capsule_args.append(args.name)
        if args.payload is not None:
            capsule_args.append(args.payload)
        capsule_args.extend(args.extra)
        capsule_args.extend(unknown)
        return int(capsule_main(capsule_args))

    client = MCPStdioClient(_server_cmd())
    try:
        client.call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "ida-pro-mcp-cli", "version": __version__},
            },
            request_id=1,
        )

        if args.mode == "raw":
            if not isinstance(payload, dict):
                raise SystemExit("raw mode requires a full JSON-RPC object payload")
            if "jsonrpc" not in payload:
                payload["jsonrpc"] = "2.0"
            if "id" not in payload and args.request_id is not None:
                payload["id"] = args.request_id
            response = client.send(payload)
            _print_json(response, pretty=args.pretty)
            return 0

        if args.mode == "tools-list":
            response = client.call("tools/list", payload if isinstance(payload, dict) else {})
            _print_json(response, pretty=args.pretty)
            return 0

        if not args.name:
            raise SystemExit(f"{args.mode} mode requires a method/tool name")

        if args.mode == "rpc":
            response = client.call(args.name, payload if payload is not None else {}, request_id=args.request_id)
            _print_json(response, pretty=args.pretty)
            return 0

        if args.mode == "tool":
            response = client.call(
                "tools/call",
                {"name": args.name, "arguments": payload if payload is not None else {}},
                request_id=args.request_id,
            )
            _print_json(_normalize_tool_result(response), pretty=args.pretty)
            return 0

        if args.mode == "intelligence":
            action = str(args.name or "status").strip().lower()
            action_map = {
                "status": "intelligence_status",
                "embedder_status": "embedder_status",
                "anchor_status": "anchor_status",
                "doctor": "embedder_status",
            }
            mapped = action_map.get(action, action)
            if mapped not in {
                "intelligence_status",
                "embedder_status",
                "anchor_status",
                "refresh_anchors",
                "classify_text",
                "classify_function",
                "index_function",
                "index_batch",
                "similar_functions",
                "export_index_summary",
                "evidence_card",
            }:
                raise SystemExit(f"unsupported intelligence action: {action}")
            tool_args = payload if isinstance(payload, dict) else {}
            tool_args = dict(tool_args)
            tool_args["action"] = mapped
            if action == "doctor":
                tool_args.setdefault("probe", True)
                tool_args.setdefault("deep_hash", False)
            response = client.call(
                "tools/call",
                {"name": "intelligence", "arguments": tool_args},
                request_id=args.request_id,
            )
            _print_json(_normalize_tool_result(response), pretty=args.pretty)
            return 0

        if args.mode == "background":
            return _handle_background_mode(args)

        raise SystemExit(f"unsupported mode: {args.mode}")
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
