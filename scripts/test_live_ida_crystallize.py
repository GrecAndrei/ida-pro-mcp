#!/usr/bin/env python3
"""E2E live-session smoke against a real binary in real IDA.

Creates a session, drives a few real tool calls (search/code/blackboard), then
reads session state, snapshots the session, lists sessions and closes.

The former ``session(action="crystallize_mined_macros")`` step has no handler
anywhere in the codebase (nor do ``get_activity_log`` / ``list_skills`` as
session actions), so this flow was retargeted to the real session surface:
``state`` / ``snapshot`` / ``list``.

Usage: python scripts/test_live_ida_crystallize.py --binary /path/to/bin
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time

# Setup project paths dynamically
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

class MCPTestClient:
    def __init__(self, timeout: int = 120):
        self.proc = None
        self.stdout_queue = queue.Queue()
        self.request_id = 0
        self.timeout = timeout
        self._write_lock = threading.Lock()

    def start(self) -> bool:
        env = os.environ.copy()
        # Fallback to scanning common default paths if IDA_DIR is not set in environment
        if "IDA_DIR" not in env:
            common_paths = [
                os.path.expanduser("~/ida-pro-9.3"),
                os.path.expanduser("~/ida-pro-9.2"),
                "/opt/ida-pro-9.3",
                "/opt/ida-pro-9.2",
                "/usr/local/ida-pro",
                "/Applications/IDA Pro 9.3/Contents/MacOS",
                "/Applications/IDA Pro 9.2/Contents/MacOS",
            ]
            # Only pin IDA_DIR to an install that actually exists; otherwise
            # leave it unset and let the server auto-detect IDA.
            for path in common_paths:
                if os.path.isdir(path):
                    env["IDA_DIR"] = path
                    break
        env["IDA_MCP_STARTUP_TIMEOUT"] = str(self.timeout)

        # Start the real MCP server
        self.proc = subprocess.Popen(
            [sys.executable, "-u", "ida_mcp_stdio.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=PROJECT_ROOT,
            bufsize=0,
            env=env,
        )

        def read_stdout():
            for line in self.proc.stdout:
                self.stdout_queue.put(line)

        def read_stderr():
            for line in self.proc.stderr:
                decoded = line.decode("utf-8", errors="replace").strip()
                if decoded:
                    print(f"[IDA-STDERR] {decoded}", file=sys.stderr)

        threading.Thread(target=read_stdout, daemon=True).start()
        threading.Thread(target=read_stderr, daemon=True).start()

        time.sleep(0.5)

        # Send initialize request
        resp = self._call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "live-crystallize-test", "version": "1.0.0"},
            },
            timeout=30,
        )
        return "result" in resp

    def _call(self, method: str, params: dict, timeout: int = 60) -> dict:
        with self._write_lock:
            self.request_id += 1
            request_id = self.request_id
            req = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            self.proc.stdin.write((json.dumps(req) + "\n").encode("utf-8"))
            self.proc.stdin.flush()

        start = time.time()
        while time.time() - start < timeout:
            try:
                line = self.stdout_queue.get(timeout=1)
                resp = json.loads(line.decode("utf-8"))
                if resp.get("id") == request_id:
                    return resp
            except queue.Empty:
                if self.proc.poll() is not None:
                    return {"error": "Server died"}
            except json.JSONDecodeError:
                continue
        return {"error": "Timeout"}

    def call_tool(self, tool: str, **args) -> dict:
        resp = self._call("tools/call", {"name": tool, "arguments": args})
        if "result" not in resp:
            return {"_error": resp.get("error", "Unknown error")}

        result = resp["result"]
        if result.get("isError"):
            content = result.get("content", [{}])[0].get("text", "{}")
            try:
                return json.loads(content)
            except Exception:
                return {"error": True, "message": content}

        content = result.get("content", [{}])[0].get("text", "{}")
        try:
            return json.loads(content)
        except Exception:
            return {"_raw": content}

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()


def _first_function_addr(payload) -> str | None:
    """Pull the first function address out of data(action='functions')."""
    val = payload.get("functions") if isinstance(payload, dict) else None
    if isinstance(val, str):
        for ln in val.splitlines():
            ln = ln.strip()
            if ln:
                return ln.split()[0]
    return None


def main():
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True, help="Path to a binary to analyze (no fixture ships in the repo)")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()

    binary = args.binary
    if not os.path.isfile(binary):
        print(f"FATAL: binary not found: {binary}", file=sys.stderr)
        sys.exit(1)

    client = MCPTestClient(timeout=args.timeout)
    print("Starting MCP Server with real IDA Pro...")
    if not client.start():
        print("Failed to initialize MCP Server")
        client.stop()
        sys.exit(1)

    print("MCP Server started successfully.")

    try:
        # 1. Create a session on the real binary (launches real IDA in background)
        print(f"\n[1] Creating session on binary: {os.path.basename(binary)}...")
        session_res = client.call_tool("session", action="create", binary_path=binary, force_new=True)
        print("Session creation response:")
        print(json.dumps(session_res, indent=2))

        sid = session_res.get("session", {}).get("session_id") or session_res.get("session_id")
        if not sid:
            print("Failed to get session ID!")
            return

        # Resolve a real function address so the flow works on any binary.
        data_res = client.call_tool("data", action="functions", count=3)
        addr = _first_function_addr(data_res) or "0x140001000"

        # 2. Simulate repeating high-value flow on the live binary
        # We loop 2 times:
        #   - search(action="find", query="main")
        #   - code(action="disasm", addr=<first function>)
        #   - blackboard(action="write", title="live finding", content="...")
        print("\n[2] Executing live tool calls on real IDA database...")
        for iter_num in range(1, 3):
            print(f"\n--- Iteration {iter_num} ---")

            print("  > Calling search(find, query='main')...")
            search_res = client.call_tool("search", action="find", query="main")
            print(f"    Search response: {json.dumps(search_res)}")

            print(f"  > Calling code(disasm, addr='{addr}')...")
            code_res = client.call_tool("code", action="disasm", addr=addr)
            print(f"    Code response: {json.dumps(code_res)}")

            print("  > Calling blackboard(write)...")
            bb_res = client.call_tool("blackboard", action="write",
                                       title=f"Live Finding {iter_num}",
                                       content=f"Observed code flow at {addr} during iteration {iter_num}",
                                       category="triage")
            print(f"    Blackboard response: ok={bb_res.get('ok')}")

        # 3. Read current session state (replaces the old get_activity_log action,
        #    which has no session handler).
        print("\n[3] Reading session state...")
        state_res = client.call_tool("session", action="state", session_id=sid)
        print(json.dumps(state_res, indent=2))

        # 4. Snapshot the session (replaces the nonexistent crystallize action).
        print("\n[4] Snapshotting session...")
        snapshot_res = client.call_tool("session", action="snapshot", session_id=sid)
        print(json.dumps(snapshot_res, indent=2))

        # 5. List sessions (replaces the nonexistent list_skills session action).
        print("\n[5] Listing sessions...")
        sessions_res = client.call_tool("session", action="list")
        print(json.dumps(sessions_res, indent=2))

        # 6. Clean up by closing the session
        print("\n[6] Closing IDA Session...")
        client.call_tool("session", action="close", session_id=sid)

    finally:
        print("\nStopping MCP Server...")
        client.stop()
        print("Done.")


if __name__ == "__main__":
    main()
