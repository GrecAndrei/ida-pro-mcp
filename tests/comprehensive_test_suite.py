import sys
import os
import json
import subprocess
import threading
import time
import queue

class MCPClient:
    def __init__(self, command, args):
        self.process = subprocess.Popen(
            [command] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            text=True
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
                resp = json.loads(line)
                if "id" in resp:
                    self.response_queue.put(resp)
            except:
                pass

    def call(self, method, params, timeout=30):
        req_id = self.request_id
        self.request_id += 1
        request = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                resp = self.response_queue.get(timeout=1)
                if resp.get("id") == req_id:
                    return resp
                else:
                    self.response_queue.put(resp)
            except queue.Empty:
                if self.process.poll() is not None:
                    return {"error": "Server process exited"}
                continue
        return {"error": "Timeout"}

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()

TEST_CASES = {
    "idb": {"action": "meta"},
    "code": {"action": "disasm", "addrs": "main"},
    "data": {"action": "functions"},
    "search": {"action": "bytes", "pattern": "48 89"},
    "types": {"action": "list"},
    "memory": {"action": "read", "addr": "main", "size": 16},
    "modify": {"action": "comment", "addr": "main", "text": "Test comment"},
    "misc": {"action": "bookmarks"},
    "debug": {"action": "regs"},
    "funcs": {"action": "set_name", "addr": "main", "name": "main_retest"},
    "segments": {"action": "list"},
    "project": {"action": "save"},
    "plugins": {"action": "list"},
    "trace": {"action": "get"},
    "fixups": {"action": "list"},
    "data_ops": {"action": "undefine", "addr": "main"}, # Undefine then redefine
    "agent": {"action": "analyze_function", "addr": "main"},
    "microcode": {"action": "get", "addr": "main"},
    "graph": {"action": "cfg", "addr": "main"},
    "bulk": {"action": "comment", "items": [{"addr": "main", "value": "Bulk test"}]},
    "ctree": {"action": "get", "addr": "main"},
        "lumina": {"action": "status"},
    "symbols": {"action": "status"},
    "patterns": {"action": "generate", "addr": "main"},
        "emulate": {"action": "eval_expr", "expr": "1+1"},
    "export": {"action": "headers", "path": "test.h"},
    "history": {"action": "list"},
    "strings_xref": {"action": "analyze", "addr": "main"},
    "entropy": {"action": "section"},
    "imports_deep": {"action": "thunks"},
    "comments_ai": {"action": "get_context", "addr": "main"},
    "nav": {"action": "interesting"},
    "colorize": {"action": "get", "addr": "main"},
    "trace_analysis": {"action": "report"},
    "hooks": {"action": "suggest"},
        "calc": {"action": "eval", "expr": "main + 0x10"},
    "coverage": {"action": "report"},
    "wiki": {"action": "list_topics"},
    "yara_hunt": {"action": "compile", "rules": "rule test { condition: true }"}
}

def main():
    target = os.path.abspath("test_target.exe")
    client = MCPClient(sys.executable, ["-u", "ida_mcp_stdio.py"])
    
    print("[*] Initializing...")
    client.call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "tester", "version": "1.0.0"}})
    
    print("[*] Creating session...")
    client.call("tools/call", {"name": "session", "arguments": {"action": "create", "binary_path": target}})
    
    results = {}
    
    for tool, args in TEST_CASES.items():
        print(f"[*] Testing {tool}...", end=" ", flush=True)
        res = client.call("tools/call", {"name": tool, "arguments": args}, timeout=60)
        
        if "error" in res:
            print("FAILED (Transport Error)")
            results[tool] = {"status": "error", "error": res["error"]}
        else:
            inner_res_str = res.get("result", {}).get("content", [{}])[0].get("text", "{{}}")
            try:
                inner_res = json.loads(inner_res_str)
                if inner_res.get("error"):
                    print(f"FAILED ({inner_res.get('code', 'UNKNOWN')})")
                    results[tool] = {"status": "fail", "response": inner_res}
                else:
                    print("OK")
                    results[tool] = {"status": "pass"}
            except:
                print("FAILED (Invalid Response)")
                results[tool] = {"status": "fail", "raw": inner_res_str}

    client.stop()
    
    print("\n" + "="*40)
    print("COMPREHENSIVE TEST REPORT")
    print("="*40)
    
    passed = [t for t, r in results.items() if r["status"] == "pass"]
    failed = [t for t, r in results.items() if r["status"] != "pass"]
    
    print(f"PASSED: {len(passed)}")
    print(f"FAILED: {len(failed)}")
    
    if failed:
        print("\nFailures:")
        for t in failed:
            r = results[t]
            msg = r.get("error") or r.get("response", {}).get("message") or "Unknown error"
            print(f"- {t}: {msg}")

    with open("test_results.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
