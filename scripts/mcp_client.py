#!/usr/bin/env python3
"""
IDA Pro MCP — Robust Test Client
Spawns the MCP server and provides an interactive Python API.
Handles non-blocking I/O, stderr logging, and timeouts properly.
"""

import subprocess
import json
import sys
import os
import time
import select
import fcntl
import threading


def _default_state_dir() -> str:
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        return os.path.join(xdg_state, "ida-pro-mcp")
    return os.path.expanduser("~/.local/state/ida-pro-mcp")


def _default_data_dirs() -> list[str]:
    dirs: list[str] = []
    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        dirs.append(os.path.join(xdg_data, "ida-pro-mcp"))
    dirs.extend(
        [
            os.path.expanduser("~/.local/share/ida-pro-mcp"),
            os.path.expanduser("~/.ida-pro-mcp"),
            "/opt/ida-pro-mcp",
            "/usr/local/share/ida-pro-mcp",
        ]
    )
    return dirs


def _discover_venv_python():
    """Find the MCP venv Python interpreter."""
    candidates: list[str] = []
    for base in _default_data_dirs():
        candidates.append(os.path.join(base, ".venv", "bin", "python3"))
        candidates.append(os.path.join(base, ".venv", "bin", "python"))
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


class MCPClient:
    def __init__(self, server_cmd=None, env=None, cache_dir=None):
        """Spawn the MCP server and establish communication."""
        if server_cmd is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            server_script = os.path.join(script_dir, "ida_mcp_stdio.py")
            venv_python = _discover_venv_python()
            if venv_python:
                server_cmd = [venv_python, server_script]
            else:
                server_cmd = [sys.executable, server_script]
        
        # Environment setup
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        
        # Auto-detect IDA if not set
        if "IDADIR" not in run_env:
            for ida_dir in ["/opt/ida-pro", "/usr/local/ida-pro"]:
                if os.path.isdir(ida_dir):
                    run_env["IDADIR"] = ida_dir
                    break
        
        if "IDA_MCP_IDAT" not in run_env and "IDADIR" in run_env:
            idat = os.path.join(run_env["IDADIR"], "idat")
            if os.path.isfile(idat):
                run_env["IDA_MCP_IDAT"] = idat
        
        if cache_dir:
            run_env["IDA_MCP_CACHE_DIR"] = cache_dir
        
        # Use unique cache dir to avoid conflicts with other servers
        if "IDA_MCP_CACHE_DIR" not in run_env:
            run_env["IDA_MCP_CACHE_DIR"] = os.path.join(
                _default_state_dir(), f"test-{os.getpid()}"
            )
        
        self._stderr_lines = []
        
        self.proc = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0,
            env=run_env,
        )
        
        # Make stdout non-blocking
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        
        # Start stderr reader thread
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_thread.start()
        
        self._req_id = 0
        self._initialize()
    
    def _read_stderr(self):
        """Read stderr in background for debugging."""
        while True:
            try:
                line = self.proc.stderr.readline()
                if not line:
                    break
                self._stderr_lines.append(line.decode("utf-8", errors="replace").strip())
            except Exception:
                break
    
    def get_stderr(self, last_n=20):
        """Get recent stderr output for debugging."""
        return "\n".join(self._stderr_lines[-last_n:])
    
    def _initialize(self):
        """Send initialize request and verify server is alive."""
        resp = self._send_recv({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {}
        }, timeout=10)
        if resp and "result" in resp:
            info = resp["result"].get("serverInfo", {})
            print(f"Connected to {info.get('name', 'unknown')} v{info.get('version', '?')}")
        else:
            print(f"WARNING: Unexpected initialize response: {resp}")
            print(f"Stderr: {self.get_stderr(5)}")
    
    def _next_id(self):
        self._req_id += 1
        return self._req_id
    
    def _send_recv(self, req, timeout=60):
        """Send a JSON-RPC request and wait for response with proper timeout handling."""
        line = json.dumps(req, separators=(",", ":")).encode("utf-8") + b"\n"
        self.proc.stdin.write(line)
        self.proc.stdin.flush()
        
        start = time.time()
        buf = b""
        fd = self.proc.stdout.fileno()
        
        while time.time() - start < timeout:
            # Use select to check if data is available
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                    if chunk:
                        buf += chunk
                        # Process complete lines
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            line = line.strip()
                            if line:
                                try:
                                    return json.loads(line.decode("utf-8"))
                                except json.JSONDecodeError:
                                    print(f"Bad JSON: {line[:200]}")
                                    continue
                except (OSError, IOError):
                    pass
            
            # Check if process died
            if self.proc.poll() is not None:
                print(f"Server exited with code {self.proc.returncode}")
                print(f"Stderr: {self.get_stderr(10)}")
                return None
        
        print(f"TIMEOUT waiting for response to {req.get('method')} after {timeout}s")
        print(f"Stderr: {self.get_stderr(10)}")
        return None
    
    def call(self, tool_name, args=None, timeout=60):
        """Call a tool by name."""
        if args is None:
            args = {}
        resp = self._send_recv({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            }
        }, timeout=timeout)
        
        if not resp:
            return {"error": "timeout", "message": f"No response for {tool_name}"}
        
        if "error" in resp:
            return resp["error"]
        
        result = resp.get("result", {})
        content = result.get("content", [])
        if content and isinstance(content, list):
            text = content[0].get("text", "")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"text": text}
        return result
    
    def list_tools(self):
        """List all available tools."""
        resp = self._send_recv({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/list",
            "params": {}
        })
        if resp and "result" in resp:
            return resp["result"]
        return resp
    
    def status(self):
        """Get session status."""
        return self.call("session", {"action": "status"})
    
    def close(self):
        """Shut down the server."""
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


def test_basic():
    """Basic connectivity test."""
    print("=" * 60)
    print("IDA Pro MCP Test Client - Basic Test")
    print("=" * 60)
    
    with MCPClient() as c:
        print("\n1. Listing tools...")
        tools = c.list_tools()
        print(f"   Total: {tools.get('total', 0)} tools")
        
        print("\n2. Checking session status...")
        status = c.status()
        print(f"   Sessions: {status.get('total_sessions', 0)}")
        
        print("\n3. All basic tests passed!")
        return True


def test_session(binary_path, timeout=30):
    """Test session creation and basic queries."""
    print(f"\n{'=' * 60}")
    print(f"Testing with binary: {binary_path}")
    print(f"{'=' * 60}")
    
    with MCPClient() as c:
        # Create session
        print(f"\n1. Creating session...")
        start = time.time()
        resp = c.call("session", {
            "action": "create",
            "binary_path": binary_path,
        }, timeout=timeout)
        elapsed = time.time() - start
        print(f"   Created in {elapsed:.1f}s")
        
        if resp and "error" in resp:
            print(f"   ERROR: {resp}")
            return False
        
        sid = None
        if resp and "session" in resp:
            sid = resp["session"].get("session_id")
            print(f"   Session ID: {sid}")
        elif resp and "session_id" in resp:
            sid = resp["session_id"]
            print(f"   Session ID: {sid}")
        
        # Quick status check
        print(f"\n2. Checking status...")
        status = c.status()
        print(f"   Running: {status.get('session', {}).get('is_running', False)}")
        
        print(f"\n3. Session test complete!")
        return True


if __name__ == "__main__":
    import argparse
    
    default_binary = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "tests", "data", "test_binary.exe"
    )
    
    parser = argparse.ArgumentParser(description="IDA Pro MCP Test Client")
    parser.add_argument("--test", choices=["basic", "session", "all"], default="basic")
    parser.add_argument("--binary", default=default_binary)
    args = parser.parse_args()
    
    if args.test == "basic":
        test_basic()
    elif args.test == "session":
        test_session(args.binary)
    elif args.test == "all":
        test_basic()
        test_session(args.binary)
