import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time


class MCPClient:
    def __init__(self, command, args, env=None):
        self.process = subprocess.Popen(
            [command] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            bufsize=0,
            env=env,
        )
        self.response_queue = queue.Queue()
        self.request_id = 1
        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()

    def _reader_loop(self):
        while True:
            line = self.process.stdout.readline()
            if not line:
                break
            try:
                resp = json.loads(line.decode("utf-8"))
                if "id" in resp:
                    self.response_queue.put(resp)
                else:
                    print(f"\n[Server Log] {resp}")
            except Exception:
                pass

    def call(self, method, params, timeout=60):
        req_id = self.request_id
        self.request_id += 1
        request = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        payload = (json.dumps(request) + "\n").encode("utf-8")
        self.process.stdin.write(payload)
        self.process.stdin.flush()

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                resp = self.response_queue.get(timeout=1)
                if resp.get("id") == req_id:
                    return resp
                self.response_queue.put(resp)
            except queue.Empty:
                if self.process.poll() is not None:
                    return {"error": "Server process exited"}
                continue
        return {"error": "Timeout"}

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()


def check_result(label, resp):
    if "error" in resp:
        print(f"[FAIL] {label}: {resp}")
        return False
    result = resp.get("result")
    if isinstance(result, dict) and result.get("isError"):
        print(f"[FAIL] {label}: {json.dumps(result, indent=2)}")
        return False
    print(f"[OK] {label}")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="tests/data/test_binary.exe")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    binary_path = os.path.abspath(args.binary)
    if not os.path.exists(binary_path):
        print(f"[FAIL] Binary not found: {binary_path}")
        return 1

    print("[*] Starting MCP server via ida_mcp_stdio.py...")
    env = os.environ.copy()
    env.setdefault("IDA_MCP_STARTUP_TIMEOUT", str(args.timeout))
    client = MCPClient(sys.executable, ["-u", "ida_mcp_stdio.py"], env=env)
    try:
        init_resp = client.call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "manual-probe", "version": "1.0.0"},
            },
            timeout=30,
        )
        if not check_result("initialize", init_resp):
            return 1

        tools_resp = client.call("tools/list", {}, timeout=30)
        if check_result("tools/list", tools_resp):
            tools = tools_resp.get("result", {}).get("tools", [])
            missing_schema = [t["name"] for t in tools if not t.get("inputSchema")]
            if missing_schema:
                print(f"[WARN] tools without inputSchema: {', '.join(missing_schema)}")

        session_resp = client.call(
            "tools/call",
            {"name": "session", "arguments": {"action": "create", "binary_path": binary_path}},
            timeout=args.timeout,
        )
        if not check_result("session/create", session_resp):
            return 1

        probes = [
            ("idb/meta", {"name": "idb", "arguments": {"action": "meta"}}),
            ("funcs/create", {"name": "funcs", "arguments": {"action": "create", "addr": "0x140001000"}}),
            ("data/functions", {"name": "data", "arguments": {"action": "functions", "count": 5}}),
            ("calc/eval", {"name": "calc", "arguments": {"action": "eval", "expr": "0x1000 + 0x20"}}),
            ("calc/convert", {"name": "calc", "arguments": {"action": "convert", "value": "0x41"}}),
            ("search/name", {"name": "search", "arguments": {"action": "name", "pattern": "*main*", "limit": 5}}),
        ]

        for label, payload in probes:
            resp = client.call("tools/call", payload, timeout=args.timeout)
            ok = check_result(label, resp)
            if not ok:
                return 1

        print("[*] Probe complete.")
        return 0
    finally:
        client.stop()


if __name__ == "__main__":
    raise SystemExit(main())
