"""
Persistent IDA Server Script
This script runs INSIDE `idat` and listens on a TCP socket for JSON requests.
It executes tools from `api_consolidated.py` and returns JSON responses.
"""

import sys
import os
import json
import socket
import traceback
import threading
import time

# Ensure we can import our modules
# The runner injects the path, but we verify it here
try:
    import idaapi
    import ida_auto
    import ida_pro
except ImportError:
    print("Error: This script must be run inside IDA Pro (idat)", file=sys.stderr)
    sys.exit(1)

# Import our API tools
try:
    from ida_pro_mcp.ida_mcp.api_consolidated import (
        idb, code, data, search, types, memory, modify, misc, debug, agent
    )
    from ida_pro_mcp.ida_mcp.error_handling import make_error, MCPError
except ImportError:
    # Ensure src is in path (server_script.py is in src/ida_pro_mcp/)
    src_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if src_root not in sys.path:
        sys.path.append(src_root)
    
    from ida_pro_mcp.ida_mcp.api_consolidated import (
        idb, code, data, search, types, memory, modify, misc, debug, agent
    )
    from ida_pro_mcp.ida_mcp.error_handling import make_error, MCPError

# Map tool names to functions
TOOLS = {
    "idb": idb, "code": code, "data": data, "search": search, "types": types,
    "memory": memory, "modify": modify, "misc": misc, "debug": debug, "agent": agent
}

def handle_request(request):
    """Execute a tool request and return the result."""
    try:
        tool_name = request.get("tool")
        args = request.get("args", {})

        if not tool_name:
            return make_error(MCPError.INVALID_ARGS, "Tool name required")

        if tool_name not in TOOLS:
            return make_error(MCPError.TOOL_NOT_FOUND, f"Unknown tool: {tool_name}")

        # Execute tool
        func = TOOLS[tool_name]
        result = func(**args)
        return result

    except Exception as e:
        traceback.print_exc()
        return make_error(MCPError.UNKNOWN, str(e), details={"traceback": traceback.format_exc()})

def run_server(port):
    """Run the TCP server."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to localhost
    try:
        server_sock.bind(('127.0.0.1', port))
        server_sock.listen(1)
        print(f"IDA Server listening on port {port}")
    except Exception as e:
        print(f"Failed to bind port {port}: {e}")
        return

    # Auto-analysis checking thread
    analysis_done = False

    def wait_analysis():
        nonlocal analysis_done
        if os.environ.get("IDA_WAIT_ANALYSIS", "1") == "1":
            print("Waiting for auto-analysis in background...")
            ida_auto.auto_wait()
            print("Analysis complete.")
        analysis_done = True

    threading.Thread(target=wait_analysis, daemon=True).start()

    while True:
        try:
            conn, addr = server_sock.accept()
            with conn:
                # Read length prefix (4 bytes)
                length_bytes = b""
                while len(length_bytes) < 4:
                    chunk = conn.recv(4 - len(length_bytes))
                    if not chunk: break
                    length_bytes += chunk

                if len(length_bytes) < 4: continue

                msg_len = int.from_bytes(length_bytes, 'big')

                # Read JSON body
                data = b""
                while len(data) < msg_len:
                    chunk = conn.recv(min(4096, msg_len - len(data)))
                    if not chunk: break
                    data += chunk

                if not data: continue

                # Parse request
                try:
                    request = json.loads(data.decode('utf-8'))

                    # Handle special commands
                    req_type = request.get("type")

                    if req_type == "ping":
                        response = {"pong": True, "analyzing": not analysis_done}
                    elif req_type == "shutdown":
                        break
                    else:
                        # Capture stdout/stderr for tool output
                        import io
                        capture_io = io.StringIO()
                        old_stdout, old_stderr = sys.stdout, sys.stderr
                        try:
                            sys.stdout = capture_io
                            sys.stderr = capture_io
                            response = handle_request(request)
                        finally:
                            sys.stdout = old_stdout
                            sys.stderr = old_stderr

                        # Append captured output if any
                        output = capture_io.getvalue()
                        if output and isinstance(response, dict):
                            response["_stdout"] = output

                except json.JSONDecodeError:
                    response = make_error(MCPError.INVALID_ARGS, "Invalid JSON")

                # Send response
                resp_bytes = json.dumps(response, default=str).encode('utf-8')
                resp_len = len(resp_bytes).to_bytes(4, 'big')
                conn.sendall(resp_len + resp_bytes)

        except Exception as e:
            print(f"Connection error: {e}")

    server_sock.close()

if __name__ == "__main__":
    # Get port from environment or args
    port = int(os.environ.get("IDA_MCP_PORT", 13337))

    # Do NOT wait for auto-analysis before starting server
    # The client will connect and can query status

    run_server(port)
    ida_pro.qexit(0)
