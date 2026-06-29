import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time


class MCPClient:
    def __init__(self, command, args):
        self.process = subprocess.Popen(
            [command] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            bufsize=0,
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
            except Exception:
                continue

    def call(self, method, params, timeout=120):
        req_id = self.request_id
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }
        self.process.stdin.write((json.dumps(request) + "\n").encode("utf-8"))
        self.process.stdin.flush()

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                resp = self.response_queue.get(timeout=1)
                if resp.get("id") == req_id:
                    return resp
            except queue.Empty:
                if self.process.poll() is not None:
                    return {"error": "Server process exited"}
        return {"error": "Timeout"}

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()


def _extract_tool_result(resp):
    if "result" not in resp:
        return resp
    content = resp["result"].get("content", [])
    for item in content:
        if item.get("type") == "text":
            try:
                return json.loads(item.get("text", "{}"))
            except Exception:
                return {"raw": item.get("text", "")}
    return resp


def main():
    parser = argparse.ArgumentParser(description="Test session arch/loader options.")
    parser.add_argument("--binary", required=True, help="Target binary path")
    parser.add_argument("--processor", help="Processor name (e.g. metapc)")
    parser.add_argument("--flags", type=int, help="Processor flags (idaapi.SETPROC_*)")
    parser.add_argument("--bitness", type=int, choices=[16, 32, 64], help="Bitness")
    parser.add_argument("--endian", choices=["le", "be"], help="Endian")
    parser.add_argument("--loader", help="Loader name override")
    parser.add_argument("--value", help="Loader options string or JSON dict")
    parser.add_argument("--reanalyze", action="store_true", help="Force reanalysis after options apply")
    parser.add_argument("--post-processor", help="Processor name to set after session create")
    args = parser.parse_args()

    target_binary = os.path.abspath(args.binary)
    if not os.path.exists(target_binary):
        print(f"Error: {target_binary} not found.")
        return 2

    loader_value = None
    if args.value:
        try:
            loader_value = json.loads(args.value)
        except json.JSONDecodeError:
            loader_value = args.value

    client = MCPClient(sys.executable, ["-u", "ida_mcp_stdio.py"])
    init_res = client.call(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "arch-loader-test"},
        },
    )
    if "error" in init_res:
        print(f"Initialize failed: {init_res}")
        client.stop()
        return 2

    session_args = {"action": "create", "binary_path": target_binary}
    if args.processor:
        session_args["processor"] = args.processor
    if args.flags is not None:
        session_args["flags"] = args.flags
    if args.bitness is not None:
        session_args["bitness"] = args.bitness
    if args.endian:
        session_args["endian"] = args.endian
    if args.loader:
        session_args["loader"] = args.loader
    if loader_value is not None:
        session_args["value"] = loader_value
    if args.reanalyze:
        session_args["reanalyze"] = True

    session_res = client.call("tools/call", {"name": "session", "arguments": session_args})
    if "error" in session_res:
        print(f"Session creation failed: {session_res}")
        client.stop()
        return 2

    if args.post_processor:
        post_res = client.call(
            "tools/call",
            {"name": "analysis", "arguments": {"action": "set_architecture", "processor": args.post_processor}},
        )
        post_out = _extract_tool_result(post_res)
        if post_out.get("error"):
            print(json.dumps(post_out, indent=2))
            client.stop()
            return 1

    options_res = client.call("tools/call", {"name": "analysis", "arguments": {"action": "get_options"}})
    options = _extract_tool_result(options_res)
    print(json.dumps(options, indent=2))

    client.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
