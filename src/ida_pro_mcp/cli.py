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
import threading
import time
from dataclasses import dataclass
from typing import Any

from ida_pro_mcp import __version__

_DAEMON_SOCKET = os.path.join(tempfile.gettempdir(), "ida-mcp-daemon.sock")


def _load_json_arg(value: str | None, *, label: str) -> Any:
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
        rid = request.get("id")
        # The server can emit unsolicited notifications (e.g. usage
        # `notifications/message`) on the same stdout stream.  Only a response
        # carrying our request id is a valid reply; skip anything else so a
        # stray notification is never misread as the answer.
        while True:
            line = self.proc.stdout.readline()
            if not line:
                method = str(request.get("method", "request"))
                self._raise_closed(method)
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rid is not None and msg.get("id") != rid:
                continue
            return msg

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
    # _daemon_is_running() uses a short 0.3s connect timeout, so a healthy but
    # momentarily saturated daemon can produce a false negative.  Never unlink
    # a socket a daemon might still be serving on — that would orphan the live
    # daemon (it can never accept again) while a second one starts.
    if _daemon_is_running():
        return
    if os.path.exists(_DAEMON_SOCKET):
        try:
            probe = _socket_mod.socket(_socket_mod.AF_UNIX, _socket_mod.SOCK_STREAM)
            probe.settimeout(1.0)
            probe.connect(_DAEMON_SOCKET)
            probe.close()
            return  # a daemon answered the slower probe; leave it alone
        except Exception:
            pass
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


def _daemon_call(tool_name: str, args: dict[str, Any], *, timeout: float | None = 30.0) -> dict:
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
    s.settimeout(10.0)  # connect deadline
    try:
        s.connect(_DAEMON_SOCKET)
        # The daemon handles requests synchronously and can block for the
        # caller-supplied timeout (e.g. `background wait timeout=120`), so
        # widen the recv window after connect; timeout=None means block.
        s.settimeout(timeout)
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
        lines = [ln.strip() for ln in data.decode("utf-8").split("\n") if ln.strip()]  # noqa: E741
        if not lines:
            raise SystemExit("Daemon returned no valid JSON lines")
        return json.loads(lines[-1])
    finally:
        s.close()


def _handle_background_mode(args):
    action = str(args.name or "list").strip().lower()
    script_file = getattr(args, "file", None)

    if action == "submit" and script_file:
        try:
            with open(script_file) as f:
                script = f.read()
        except Exception as e:
            raise SystemExit(f"Cannot read file {script_file}: {e}") from e
        tool_args = {"action": action, "script": script}
    else:
        payload = None
        if args.stdin_json:
            payload = _read_stdin_json(label="background")
        elif args.payload is not None:
            payload = _load_json_arg(args.payload, label="payload")
        tool_args: dict = payload if isinstance(payload, dict) else {}
        tool_args = dict(tool_args) if tool_args else {}
        tool_args["action"] = action

    if args.session_id:
        tool_args["session_id"] = args.session_id

    if action == "submit" and not tool_args.get("script") and not tool_args.get("tool_call"):
        raise SystemExit("background submit requires --file, or payload with 'script' or 'tool_call'")

    if action in ("result", "cancel", "wait"):
        task_id = tool_args.get("task_id")
        if not task_id:
            raise SystemExit(f"background {action} requires 'task_id' in payload")

    if not _daemon_is_running():
        _start_daemon()

    if action == "wait":
        # `background wait` blocks on the daemon up to the user-supplied
        # timeout, so the CLI socket must outlive it (plus a small grace for
        # the daemon to write the response).  With no timeout the daemon waits
        # until the task finishes, so the CLI blocks too (timeout=None).
        try:
            user_to = tool_args.get("timeout")
            wait_timeout: float | None = (
                float(user_to) + 30.0 if user_to not in (None, "") else None
            )
        except (TypeError, ValueError):
            wait_timeout = None
        response = _daemon_call("background", tool_args, timeout=wait_timeout)
    else:
        response = _daemon_call("background", tool_args)
    _print_json(_normalize_tool_result(response), pretty=args.pretty)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ephemeral JSON-safe CLI for ida-pro-mcp",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ida-pro-mcp-cli rpc tools/list '{}'\n"
            "  ida-pro-mcp-cli tool session '{\"action\":\"status\"}'\n"
            "  ida-pro-mcp-cli raw '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}'\n"
            "  ida-pro-mcp-cli intelligence status\n"
            "  ida-pro-mcp-cli background submit '{\"tool_call\":{\"tool\":\"session\",\"args\":{\"action\":\"status\"}}}'\n"
            "  ida-pro-mcp-cli background status\n"
            "  ida-pro-mcp-cli background result '{\"task_id\":\"abc123\"}'\n"
        ),
    )
    parser.add_argument(
        "mode",
        choices=("rpc", "tool", "raw", "tools-list", "intelligence", "background"),
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
        "--file",
        type=str,
        default=None,
        help="Read script content from file (background submit mode)",
    )
    parser.add_argument(
        "--session",
        type=str,
        default=None,
        dest="session_id",
        help="IDA session ID for background tasks",
    )
    args = parser.parse_args(argv)

    # background mode talks only to the daemon socket; it never touches the
    # stdio client, so dispatch it before spawning a throwaway server
    # subprocess (which would otherwise boot the whole host on every call).
    if args.mode == "background":
        return _handle_background_mode(args)

    payload = None
    if args.stdin_json:
        payload = _read_stdin_json(label=args.mode)
    elif args.payload is not None:
        payload = _load_json_arg(args.payload, label="payload")
    elif args.mode == "raw" and args.name is not None:
        # raw mode takes the full JSON-RPC object as the second positional
        # argument (documented in the epilog): mode raw '<json>'.
        payload = _load_json_arg(args.name, label="payload")

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
            # Must mirror the action Literal in ida_mcp/tools/intelligence.py
            # exactly; drift here makes valid actions impossible via the CLI
            # while advertising actions the tool rejects.
            if mapped not in {
                "intelligence_status",
                "embedder_status",
                "reranker_status",
                "anchor_status",
                "refresh_anchors",
                "classify_text",
                "classify_function",
                "index_function",
                "index_batch",
                "index_fast",
                "index_range",
                "similar_functions",
                "semantic_search",
                "blackboard_search",
                "export_index_summary",
                "function_families",
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

        raise SystemExit(f"unsupported mode: {args.mode}")
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
