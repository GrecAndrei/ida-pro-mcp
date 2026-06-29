#!/usr/bin/env python3
"""E2E script to run live macro crystallization against a real binary in real IDA."""

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
TEST_BINARY = os.path.join(PROJECT_ROOT, "tests", "data", "test_binary.exe")

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
                "/home/grec-alexander/ida-pro-9.3",  # Original local path
                "/home/grec-alexander/ida-pro-9.2",
                "/opt/ida-pro-9.3",
                "/opt/ida-pro-9.2",
                os.path.expanduser("~/ida-pro-9.3"),
                os.path.expanduser("~/ida-pro-9.2"),
                "/Applications/IDA Pro 9.3/Contents/MacOS",
                "/Applications/IDA Pro 9.2/Contents/MacOS",
            ]
            for path in common_paths:
                if os.path.isdir(path):
                    env["IDA_DIR"] = path
                    break
            else:
                env["IDA_DIR"] = "/home/grec-alexander/ida-pro-9.3"
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


def main():
    client = MCPTestClient(timeout=120)
    print("Starting MCP Server with real IDA Pro...")
    if not client.start():
        print("Failed to initialize MCP Server")
        client.stop()
        sys.exit(1)

    print("MCP Server started successfully.")

    try:
        # 1. Create a session on the real binary (launches real IDA in background)
        print(f"\n[1] Creating session on binary: {os.path.basename(TEST_BINARY)}...")
        session_res = client.call_tool("session", action="create", binary_path=TEST_BINARY, force_new=True)
        print("Session creation response:")
        print(json.dumps(session_res, indent=2))

        sid = session_res.get("session", {}).get("session_id")
        if not sid:
            print("Failed to get session ID!")
            return

        # 2. Simulate repeating high-value flow on the live binary
        # We will loop 2 times:
        #   - search(action="find", query="main")
        #   - code(action="disasm", addr="0x140010108")  # Correctly mapped address for test_binary.exe
        #   - blackboard(action="write", title="live finding", content="...")
        print("\n[2] Executing live tool calls on real IDA database...")
        for iter_num in range(1, 3):
            print(f"\n--- Iteration {iter_num} ---")

            print("  > Calling search(find, query='main')...")
            search_res = client.call_tool("search", action="find", query="main")
            print(f"    Search response: {json.dumps(search_res)}")

            print("  > Calling code(disasm, addr='0x140010108')...")
            code_res = client.call_tool("code", action="disasm", addr="0x140010108")
            print(f"    Code response: {json.dumps(code_res)}")

            print("  > Calling blackboard(write)...")
            bb_res = client.call_tool("blackboard", action="write",
                                       title=f"Live Finding {iter_num}",
                                       content=f"Observed code flow at 0x140010108 during iteration {iter_num}",
                                       category="triage")
            print(f"    Blackboard response: ok={bb_res.get('ok')}")

        # Get activity log
        print("\n[*] Retrieving current activity log from host session...")
        log_res = client.call_tool("session", action="get_activity_log", session_id=sid)
        print(json.dumps(log_res, indent=2))

        # 3. Trigger crystallization
        print("\n[3] Triggering crystallization on the real logged sequence...")
        crystallize_res = client.call_tool("session",
                                           action="crystallize_mined_macros",
                                           session_id=sid,
                                           min_support=2)
        print("\nCrystallization Response:")
        print(json.dumps(crystallize_res, indent=2))

        # 4. List all crystallized skills to show it's saved in Capsule DB
        print("\n[4] Querying skill database...")
        skills_res = client.call_tool("session", action="list_skills", session_id=sid)
        print(json.dumps(skills_res, indent=2))

        # 5. Clean up by closing the session
        print("\n[5] Closing IDA Session...")
        client.call_tool("session", action="close", session_id=sid)

    finally:
        print("\nStopping MCP Server...")
        client.stop()
        print("Done.")


if __name__ == "__main__":
    main()
