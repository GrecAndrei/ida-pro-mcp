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
        self.pending_by_id = {}
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
                pass

    def call(self, method, params, timeout=120):
        req_id = self.request_id
        self.request_id += 1
        request = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        self.process.stdin.write((json.dumps(request) + "\n").encode("utf-8"))
        self.process.stdin.flush()

        if req_id in self.pending_by_id:
            return self.pending_by_id.pop(req_id)

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                resp = self.response_queue.get(timeout=1)
                if resp.get("id") == req_id:
                    return resp
                if "id" in resp:
                    self.pending_by_id[resp["id"]] = resp
            except queue.Empty:
                if self.process.poll() is not None:
                    return {"error": "Server process exited"}
                continue
        # One final late-response check to handle race at deadline.
        if req_id in self.pending_by_id:
            return self.pending_by_id.pop(req_id)
        return {"error": "Timeout"}

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()


def decode_content(resp):
    if "result" not in resp:
        return resp
    result = resp.get("result", {})
    if isinstance(result, dict) and "content" in result:
        content = result.get("content", [])
        for item in content:
            if item.get("type") == "text":
                try:
                    return json.loads(item.get("text", ""))
                except Exception:
                    return item.get("text")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="tests/data/test_binary.exe")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--out", default="ida_mcp_cache/tool_sweep_results.json")
    cli_args = parser.parse_args()

    binary_path = os.path.abspath(cli_args.binary)
    if not os.path.exists(binary_path):
        print(f"[FAIL] Binary not found: {binary_path}")
        return 1

    env = os.environ.copy()
    env.setdefault("IDA_MCP_STARTUP_TIMEOUT", str(cli_args.timeout))

    client = MCPClient(sys.executable, ["-u", "ida_mcp_stdio.py"], env=env)
    try:
        init_resp = client.call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "tool-sweep", "version": "1.0.0"},
            },
            timeout=30,
        )
        if "error" in init_resp:
            print(init_resp)
            return 1

        session_resp = client.call(
            "tools/call",
            {"name": "session", "arguments": {"action": "create", "binary_path": binary_path, "force_new": True}},
            timeout=cli_args.timeout,
        )
        if "error" in session_resp:
            print(session_resp)
            return 1

        entry_addr = None
        entry_resp = client.call("tools/call", {"name": "idb", "arguments": {"action": "entrypoints"}}, timeout=60)
        entry_data = decode_content(entry_resp)
        if isinstance(entry_data, list):
            entry_addr = entry_data[0]["address"] if entry_data else None
        elif isinstance(entry_data, dict):
            entries = entry_data.get("entries") or entry_data.get("entrypoints") or entry_data.get("data")
            if isinstance(entries, list) and entries:
                entry_addr = entries[0].get("address") or entries[0].get("addr")

        if not entry_addr:
            func_resp = client.call("tools/call", {"name": "data", "arguments": {"action": "functions", "count": 1}}, timeout=60)
            func_data = decode_content(func_resp)
            funcs = func_data.get("functions") if isinstance(func_data, dict) else None
            if funcs:
                entry_addr = funcs[0].get("addr")

        if not entry_addr:
            entry_addr = "0x0"

        tool_calls = [
            ("bookmarks", {"action": "list"}),
            ("analysis", {"action": "get_options"}),
            ("idb", {"action": "meta"}),
            ("code", {"action": "disasm", "addr": entry_addr}),
            ("data", {"action": "functions", "count": 1}),
            ("data", {"action": "bulk_query", "items": [{"kind": "functions", "count": 1}, {"kind": "imports", "count": 1}]}),
            ("query", {"action": "data", "subaction": "functions", "args": {"count": 1}}),
            ("search", {"action": "name", "pattern": "*main*", "limit": 5}),
            ("types", {"action": "list", "count": 3}),
            ("memory", {"action": "read", "addr": entry_addr, "size": 16}),
            ("modify", {"action": "comment", "addr": entry_addr, "value": "probe comment"}),
                        ("misc", {"action": "python", "expr": "1+1"}),
            ("debug", {"action": "regs"}),
            ("funcs", {"action": "info", "addr": entry_addr}),
            ("segments", {"action": "list"}),
            ("project", {"action": "get_cwd"}),
            ("misc", {"action": "plugin_list"}),
            ("trace", {"action": "get"}),
            ("fixups", {"action": "list"}),
            ("data_ops", {"action": "make_code", "addr": entry_addr}),
            ("agent", {"action": "explore_address", "addr": entry_addr}),
            ("agent", {"action": "context_pack", "addr": entry_addr}),
            ("microcode", {"action": "get", "addr": entry_addr}),
            ("graph", {"action": "cfg", "addr": entry_addr}),
            ("bridgerag", {"action": "bridges", "func_name": "wWinMainCRTStartup", "bridge_types": ["apis"]}),
            ("agent", {"action": "cfg_stats"}),
            ("bulk", {"action": "comment", "items": [{"addr": entry_addr, "value": "probe bulk"}]}),
            ("ctree", {"action": "get", "addr": entry_addr}),
                        ("lumina", {"action": "status"}),
            ("symbols", {"action": "status"}),
            ("patterns", {"action": "list_sigs"}),
                        ("static_trace", {"action": "eval_expr", "addr": entry_addr}),
            ("export", {"action": "json"}),
            ("history", {"action": "list"}),
            ("xref_analysis", {"action": "dependency_graph", "addr": entry_addr, "depth": 1, "direction": "forward", "limit": 20}),
            ("entropy", {"action": "section"}),
            ("imports_deep", {"action": "api_sets"}),
            ("comment_mgr", {"action": "get_context", "addr": entry_addr}),
            ("nav", {"action": "cursor"}),
            ("colorize", {"action": "palette"}),
            ("trace_analysis", {"action": "analyze_coverage"}),
            ("hooks", {"action": "suggest", "addr": entry_addr}),
                                    ("calc", {"action": "eval", "expr": "0x1000 + 0x20"}),
            ("calc", {"action": "align", "value": entry_addr, "size": 0x10}),
            ("calc", {"action": "deref", "addr": entry_addr, "type": "u32"}),
            ("calc", {"action": "chain", "addr": entry_addr, "offsets": "0x0,0x0"}),
            ("coverage", {"action": "report"}),
            ("wiki", {"action": "list_topics"}),
            ("yara_hunt", {"action": "list_rules"}),
        ]

        results = {"entry_addr": entry_addr, "tools": {}, "calls": []}
        for idx, (tool, tool_args) in enumerate(tool_calls):
            t0 = time.time()
            call_args = dict(tool_args)
            resp = client.call("tools/call", {"name": tool, "arguments": call_args}, timeout=cli_args.timeout)
            elapsed_ms = int((time.time() - t0) * 1000)
            key = f"{idx:02d}:{tool}"
            call_entry = {
                "index": idx,
                "tool": tool,
                "request": call_args,
                "response": decode_content(resp),
                "elapsed_ms": elapsed_ms,
            }
            if tool == "debug" and isinstance(call_entry["response"], dict):
                if call_entry["response"].get("error") is True and call_entry["response"].get("code") == "DEBUGGER_NOT_RUNNING":
                    call_entry["expected_in_headless"] = True
            results["tools"][key] = call_entry
            results["calls"].append(call_entry)
        os.makedirs(os.path.dirname(cli_args.out), exist_ok=True)
        with open(cli_args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        print(f"[OK] Wrote results to {cli_args.out}")
        return 0
    finally:
        client.stop()


if __name__ == "__main__":
    raise SystemExit(main())
