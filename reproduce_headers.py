import subprocess
import json
import sys
import os
import time

def test_headers():
    server_path = "ida_mcp_stdio.py"
    cmd = [sys.executable, server_path]

    env = os.environ.copy()

    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )

    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"}
        }
    }

    body = json.dumps(req).encode('utf-8')
    # Send with Content-Length and NO trailing newline
    msg = f"Content-Length: {len(body)}\r\n\r\n".encode('utf-8') + body

    print(f"Sending {len(msg)} bytes...")
    process.stdin.write(msg)
    process.stdin.flush()

    print("Waiting for response...")
    try:
        # Try to read line
        # If server hangs, this will timeout
        stdout, stderr = process.communicate(timeout=5)
        print("Stdout received:")
        print(stdout.decode())
        print("Stderr received:")
        print(stderr.decode())
    except subprocess.TimeoutExpired:
        print("TIMEOUT: Server did not respond (likely hung waiting for newline)")
        process.kill()

if __name__ == "__main__":
    test_headers()
