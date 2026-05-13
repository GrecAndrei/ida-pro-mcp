import sys
import os
import json
import subprocess
import threading
import time
import queue
import argparse

class MCPClient:
    def __init__(self, command, args):
        self.process = subprocess.Popen(
            [command] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr, # Forward stderr to see server logs
            bufsize=0
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
                resp = json.loads(line.decode('utf-8'))
                if "id" in resp:
                    self.response_queue.put(resp)
                else:
                    # Notification or other
                    print(f"\n[Server Log] {resp}")
            except Exception as e:
                # Might be raw text if server is messy
                pass

    def call(self, method, params, timeout=60):
        req_id = self.request_id
        self.request_id += 1
        
        request = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params
        }
        
        self.process.stdin.write((json.dumps(request) + "\n").encode('utf-binary' if sys.platform == 'win32' and False else 'utf-8'))
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", nargs="?", help="Tool name to call")
    parser.add_argument("kv_args", nargs="*", help="Arguments as key=value pairs (e.g., action=meta)")
    parser.add_argument("--binary", default="test_target.exe", help="Target binary")
    args_cmd = parser.parse_args()

    # Kill stale IDA processes
    print("[*] Cleaning up stale IDA processes...")
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/IM", "ida*", "/T"], capture_output=True)
    else:
        subprocess.run(["pkill", "-9", "ida"], capture_output=True)

    target_binary = os.path.abspath(args_cmd.binary)
    if not os.path.exists(target_binary):
        print(f"Error: {target_binary} not found.")
        return

    print(f"[*] Starting MCP server via ida_mcp_stdio.py...")
    client = MCPClient(sys.executable, ["-u", "ida_mcp_stdio.py"])

    print("[*] Initializing...")
    init_res = client.call("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "1.0.0"}
    })
    
    if "error" in init_res:
        print(f"Initialization failed: {init_res}")
        client.stop()
        return

    print("[*] Creating session...")
    session_res = client.call("tools/call", {
        "name": "session",
        "arguments": {
            "action": "create",
            "binary_path": target_binary
        }
    })
    
    if "error" in session_res or (isinstance(session_res.get("result"), dict) and session_res["result"].get("isError")):
        print(f"Session creation failed: {session_res}")
        client.stop()
        return

    if args_cmd.tool:
        tool_args = {}
        for kv in args_cmd.kv_args:
            if "=" in kv:
                k, v = kv.split("=", 1)
                # Simple type conversion
                if v.lower() == "true": v = True
                elif v.lower() == "false": v = False
                elif v.isdigit(): v = int(v)
                elif v.startswith("[") and v.endswith("]"): # Simple list support
                    try: v = json.loads(v.replace("'", "\""))
                    except: pass
                tool_args[k] = v
        
        if not tool_args and args_cmd.tool == "idb":
            tool_args = {"action": "meta"}
            
        print(f"[*] Calling {args_cmd.tool} with {tool_args}...")
        res = client.call("tools/call", {
            "name": args_cmd.tool,
            "arguments": tool_args
        }, timeout=120)
        
        if "result" in res and "content" in res["result"]:
            for content in res["result"]["content"]:
                if content["type"] == "text":
                    try:
                        inner = json.loads(content["text"])
                        print(json.dumps(inner, indent=2))
                    except:
                        print(content["text"])
        else:
            print(json.dumps(res, indent=2))
    else:
        print("\n" + "="*60)
        print("INTERACTIVE TOOL TESTER")
        print("="*60)
        print("Enter tool name (e.g., 'idb') and then arguments as JSON.")
        print("Type 'exit' to quit.")

        while True:
            try:
                tool_name = input("\nTool name > ").strip()
                if tool_name.lower() in ('exit', 'quit'):
                    break
                if not tool_name:
                    continue
                
                args_str = input("Args (JSON, default {\"action\": \"meta\"}) > ").strip()
                if not args_str:
                    tool_args = {"action": "meta"} if tool_name == "idb" else {}
                else:
                    try:
                        tool_args = json.loads(args_str)
                    except Exception as e:
                        print(f"Invalid JSON: {e}")
                        continue
                
                print(f"[*] Calling {tool_name} with {tool_args}...")
                res = client.call("tools/call", {
                    "name": tool_name,
                    "arguments": tool_args
                }, timeout=120)
                
                if "result" in res and "content" in res["result"]:
                    for content in res["result"]["content"]:
                        if content["type"] == "text":
                            try:
                                inner = json.loads(content["text"])
                                print(json.dumps(inner, indent=2))
                            except:
                                print(content["text"])
                else:
                    print(json.dumps(res, indent=2))
                    
            except KeyboardInterrupt:
                break
            except EOFError:
                break
            except Exception as e:
                print(f"Error: {e}")

    client.stop()
    print("[*] Client stopped.")

if __name__ == "__main__":
    main()
