import subprocess, json, time, os, socket, threading

def manual_test():
    server_py = r"C:\Users\Alexander\AppData\Local\ida-pro-mcp\ida_mcp_stdio.py"
    venv_py = r"C:\Users\Alexander\AppData\Local\ida-pro-mcp\.venv\Scripts\python.exe"
    target = r"C:\Users\Alexander\Downloads\ida-pro-mcp\test_target.exe"
    
    print(f"Lauching Server: {server_py}")
    proc = subprocess.Popen([venv_py, "-u", server_py], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def read_line_with_timeout(timeout=30): # 30s timeout
        result = [None]
        def target_read():
            try:
                result[0] = proc.stdout.readline()
            except: pass
            
        t = threading.Thread(target=target_read)
        t.daemon = True
        t.start()
        t.join(timeout)
        return result[0]

    def send(req):
        print(f"\nSEND: {json.dumps(req)}")
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        
        line = read_line_with_timeout(30) # 30s timeout
        
        if not line:
            print("TIMEOUT or EOF")
            return None
        print(f"RECV: {line.strip()}")
        return json.loads(line)

    try:
        # Initialize
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        
        # Create Session
        print("\nCreating session...")
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "session", "arguments": {"action": "create", "binary_path": target}}})
        
        # Call idb:meta
        print("\nCalling idb:meta...")
        res = send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "idb", "arguments": {"action": "meta"}}})
        
        if res and "result" in res and res["result"].get("isError"):
             print("\n--- ERROR ---")
             content = res["result"].get("content", [{}])[0]
             print(content.get("text", "No details"))

    finally:
        print("\nTerminating server...")
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except:
            proc.kill()

if __name__ == "__main__": manual_test()