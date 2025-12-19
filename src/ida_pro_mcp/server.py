#!/usr/bin/env python3
"""
IDA Pro MCP Server - Unified Entry Point

Supports:
1. Standard IO (stdio) mode for MCP clients (Claude, Cursor, etc.)
2. HTTP Daemon mode for background service

Usage:
    ida-pro-mcp                 # Run in stdio mode (default)
    ida-pro-mcp --daemon        # Run in HTTP daemon mode
    ida-pro-mcp --http          # Alias for --daemon
"""

import os
import sys
import json
import time
import subprocess
import threading
import argparse
import logging
import hashlib
import glob
import warnings
import io
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

# =============================================================================
# SHARED UTILITIES
# =============================================================================

class SimpleLock:
    """Cross-platform file lock without external dependencies."""

    def __init__(self, path: str):
        self.lock_file = path + ".mcp.lock"
        self.locked = False
        self.pid = os.getpid()

    def acquire(self, timeout: int = 10) -> bool:
        """Acquire the lock. Returns True if successful."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                # Atomic create - fails if exists
                fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, f"{self.pid}:{time.time()}".encode())
                os.close(fd)
                self.locked = True
                return True
            except FileExistsError:
                # Check if lock is stale (older than 5 minutes)
                if self._is_stale():
                    self._force_release()
                    continue
                time.sleep(0.1)
            except Exception:
                time.sleep(0.1)
        return False

    def release(self):
        """Release the lock."""
        if self.locked and os.path.exists(self.lock_file):
            try:
                os.remove(self.lock_file)
            except:
                pass
            self.locked = False

    def is_locked(self) -> bool:
        """Check if the file is currently locked."""
        return os.path.exists(self.lock_file)

    def is_owned_by_self(self) -> bool:
        """True if the lock exists and is held by this PID."""
        info = self.get_owner_info()
        return bool(info and info.get("pid") == self.pid)

    def _is_stale(self) -> bool:
        """Check if lock is stale (older than 5 minutes)."""
        try:
            if os.path.exists(self.lock_file):
                mtime = os.path.getmtime(self.lock_file)
                return time.time() - mtime > 300  # 5 minutes
        except:
            pass
        return False

    def _force_release(self):
        """Force release a stale lock."""
        try:
            os.remove(self.lock_file)
        except:
            pass

    def get_owner_info(self) -> Optional[Dict]:
        """Get info about who holds the lock."""
        try:
            if os.path.exists(self.lock_file):
                with open(self.lock_file, 'r') as f:
                    data = f.read().strip()
                    parts = data.split(':')
                    if len(parts) >= 2:
                        return {
                            "pid": int(parts[0]),
                            "locked_at": datetime.fromtimestamp(float(parts[1])).isoformat()
                        }
        except:
            pass
        return None

    def __enter__(self):
        if not self.acquire():
            raise RuntimeError("Could not acquire lock")
        return self

    def __exit__(self, *args):
        self.release()

class Session:
    """Represents an active IDB analysis session."""

    def __init__(self, session_id: str, idb_path: str, binary_path: str):
        self.session_id = session_id
        self.idb_path = idb_path
        self.binary_path = binary_path
        self.created_at = datetime.now()
        self.last_used = datetime.now()
        self.lock = SimpleLock(idb_path)

    def touch(self):
        """Update last used timestamp."""
        self.last_used = datetime.now()

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "idb_path": self.idb_path,
            "binary_path": self.binary_path,
            "created_at": self.created_at.isoformat(),
            "last_used": self.last_used.isoformat(),
            "is_locked": self.lock.is_locked()
        }

class SessionManager:
    """Manages multiple IDB analysis sessions."""

    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        self.sessions: Dict[str, Session] = {}
        self.session_dir = os.path.join(cache_dir, "sessions")
        os.makedirs(self.session_dir, exist_ok=True)

    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        import random
        import string
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    def _get_session_idb_path(self, binary_path: str, session_id: str) -> str:
        """Get the IDB path for a session."""
        base = os.path.basename(binary_path)
        # Store session IDBs in the session directory
        return os.path.join(self.session_dir, f"{base}.{session_id}.i64")

    def discover_idbs(self, binary_path: str) -> List[Dict]:
        """Find all existing IDBs for a binary file."""
        results = []
        base_name = os.path.basename(binary_path)

        # Check for standard IDBs in same directory
        for ext in ['.i64', '.idb']:
            # Direct IDB
            idb_path = binary_path + ext
            if os.path.exists(idb_path):
                lock = SimpleLock(idb_path)
                results.append({
                    "path": idb_path,
                    "type": "standard",
                    "last_modified": datetime.fromtimestamp(os.path.getmtime(idb_path)).isoformat(),
                    "size_mb": round(os.path.getsize(idb_path) / 1024 / 1024, 2),
                    "in_use": lock.is_locked(),
                    "owner": lock.get_owner_info()
                })

            # Also check without extension
            base = os.path.splitext(binary_path)[0]
            idb_path2 = base + ext
            if os.path.exists(idb_path2) and idb_path2 != idb_path:
                lock = SimpleLock(idb_path2)
                results.append({
                    "path": idb_path2,
                    "type": "standard",
                    "last_modified": datetime.fromtimestamp(os.path.getmtime(idb_path2)).isoformat(),
                    "size_mb": round(os.path.getsize(idb_path2) / 1024 / 1024, 2),
                    "in_use": lock.is_locked(),
                    "owner": lock.get_owner_info()
                })

        # Check for session IDBs in session directory
        pattern = os.path.join(self.session_dir, f"{base_name}.*.i64")
        for idb_path in glob.glob(pattern):
            lock = SimpleLock(idb_path)
            # Extract session ID from filename
            parts = os.path.basename(idb_path).rsplit('.', 2)
            session_id = parts[1] if len(parts) >= 3 else "unknown"
            results.append({
                "path": idb_path,
                "type": "session",
                "session_id": session_id,
                "last_modified": datetime.fromtimestamp(os.path.getmtime(idb_path)).isoformat(),
                "size_mb": round(os.path.getsize(idb_path) / 1024 / 1024, 2),
                "in_use": lock.is_locked(),
                "owner": lock.get_owner_info()
            })

        return results

    def create_session(self, binary_path: str, use_existing: Optional[str] = None) -> Session:
        """Create a new session or resume an existing one."""
        session_id = self._generate_session_id()

        if use_existing:
            # User wants to use an existing IDB
            idb_path = use_existing
        else:
            # Create new session-specific IDB path
            idb_path = self._get_session_idb_path(binary_path, session_id)

        session = Session(session_id, idb_path, binary_path)
        self.sessions[session_id] = session

        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        session = self.sessions.get(session_id)
        if session:
            session.touch()
        return session

    def list_sessions(self) -> List[Dict]:
        """List all active sessions."""
        return [s.to_dict() for s in self.sessions.values()]

    def close_session(self, session_id: str):
        """Close a session and release its lock."""
        session = self.sessions.pop(session_id, None)
        if session:
            session.lock.release()

# =============================================================================
# ERROR CODES
# =============================================================================

class MCPError:
    """Structured error codes for LLM understanding."""
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    FILE_LOCKED = "FILE_LOCKED"
    FILE_CORRUPT = "FILE_CORRUPT"
    IDA_NOT_FOUND = "IDA_NOT_FOUND"
    IDA_CRASHED = "IDA_CRASHED"
    IDA_TIMEOUT = "IDA_TIMEOUT"
    IDA_LICENSE = "IDA_LICENSE"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    SESSION_LOCKED = "SESSION_LOCKED"
    SESSION_REQUIRED = "SESSION_REQUIRED"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    INVALID_ARGS = "INVALID_ARGS"
    DECOMPILE_FAILED = "DECOMPILE_FAILED"

def make_error(code: str, message: str, recoverable: bool = False, details: dict = None) -> dict:
    """Create a structured error response."""
    result = {
        "error": True,
        "code": code,
        "message": message,
        "recoverable": recoverable
    }
    if recoverable:
        result["retry_after_seconds"] = 5
    if details:
        result["details"] = details
    return result

# =============================================================================
# TOOLS LIST (Shared)
# =============================================================================

TOOLS = [
    "session", "idb", "code", "data", "search", "types", "memory", "modify",
    "misc", "debug", "funcs", "segments", "files", "plugins", "trace",
    "fixups", "data_ops", "agent", "microcode", "graph", "bulk",
    "ctree", "diff", "lumina", "symbols", "patterns", "structs",
    "emulate", "export", "history", "strings_xref", "entropy",
    "imports_deep", "comments_ai", "nav", "colorize", "trace_analysis",
    "hooks", "taint", "coverage"
]

TOOL_DESCRIPTIONS = {
    "session": "Session management: discover, create, list, switch, close.",
    "idb": "IDB metadata and navigation.",
    "code": "Decompilation, disassembly, and code flow.",
    "data": "List and query binary data (functions, globals, strings).",
    "search": "Search for patterns, bytes, and references.",
    "types": "Manage type information, structures, and enums.",
    "memory": "Read and write raw memory.",
    "modify": "Rename, comment, patch.",
    "agent": "High-level analysis helpers.",
    # ... (Others omitted for brevity but available via get_tools_list)
}

# =============================================================================
# BASE SERVER CLASS
# =============================================================================

class BaseIDAServer:
    def __init__(self):
        self.ida_dir = os.environ.get("IDADIR", "")
        self.idat_exe = self._find_idat()
        self.cache_dir = os.path.join(os.path.expanduser("~"), ".ida_mcp_cache")
        # server.py is in src/ida_pro_mcp/, so api_consolidated is in ./ida_mcp/
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.api_path = os.path.join(self.script_dir, "ida_mcp")

        os.makedirs(self.cache_dir, exist_ok=True)
        self.session_mgr = SessionManager(self.cache_dir)
        self.current_session: Optional[Session] = None

    def _find_idat(self) -> str:
        if self.ida_dir:
            for name in ["idat.exe", "idat64.exe", "idat"]:
                path = os.path.join(self.ida_dir, name)
                if os.path.exists(path):
                    return path
        candidates = [
            r"C:\Program Files\IDA Professional 9.2\idat.exe",
            r"C:\Program Files\IDA Pro 9.2\idat.exe",
            r"C:\Program Files\IDA Professional 9.0\idat.exe",
            r"/opt/ida/idat",
            r"/Applications/IDA Pro.app/Contents/MacOS/idat"
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return ""

    def _check_idb_exists(self, filepath: str) -> Optional[str]:
        for ext in ['.i64', '.idb']:
            idb_path = filepath + ext
            if os.path.exists(idb_path):
                return idb_path
            base = os.path.splitext(filepath)[0]
            idb_path2 = base + ext
            if os.path.exists(idb_path2):
                return idb_path2
        return None

    def call_tool(self, tool_name: str, idb_path: str, **kwargs) -> Dict[str, Any]:
        """Execute a tool via idat.exe"""
        start_time = time.time()
        target = idb_path
        binary_for_new = None

        if not target.endswith(('.i64', '.idb')):
            existing = self._check_idb_exists(target)
            if existing:
                target = existing

        if not os.path.exists(target):
            if self.current_session and self.current_session.idb_path == idb_path:
                binary_for_new = self.current_session.binary_path
                if not os.path.exists(binary_for_new):
                    return make_error(MCPError.FILE_NOT_FOUND, f"Binary not found: {binary_for_new}")
                os.makedirs(os.path.dirname(target), exist_ok=True)
            else:
                return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {target}")

        if not self.idat_exe:
            return make_error(MCPError.IDA_NOT_FOUND, "idat.exe not found. Set IDADIR environment variable.")

        lock = SimpleLock(target)
        acquired_here = False

        # Locking logic
        if lock.is_locked():
            if not lock.is_owned_by_self():
                if not lock.acquire(timeout=30):
                    owner = lock.get_owner_info()
                    return make_error(MCPError.FILE_LOCKED, f"IDB locked by {owner}", recoverable=True, details={"owner": owner})
                acquired_here = True
        else:
            if not lock.acquire(timeout=30):
                return make_error(MCPError.FILE_LOCKED, "IDB locked", recoverable=True)
            acquired_here = True

        try:
            escaped_api_path = self.api_path.replace('\\', '\\\\')
            args_json = json.dumps(kwargs)
            output_file = os.path.join(self.cache_dir, f"mcp_result_{os.getpid()}_{threading.get_ident()}.json")
            escaped_output = output_file.replace('\\', '\\\\')

            script = f'''import json
import sys
sys.path.insert(0, "{escaped_api_path}")
try:
    from api_consolidated import {tool_name}
    kwargs = json.loads('{args_json}')
    result = {tool_name}(**kwargs)
except Exception as e:
    result = {{"error": str(e), "traceback": __import__("traceback").format_exc()}}
with open("{escaped_output}", "w") as f:
    json.dump(result, f, default=str)
import ida_pro
ida_pro.qexit(0)
'''
            script_file = os.path.join(self.cache_dir, f"mcp_script_{os.getpid()}_{threading.get_ident()}.py")
            with open(script_file, 'w', encoding='utf-8') as f:
                f.write(script)

            cmd = [self.idat_exe, "-A", f"-S{script_file}", binary_for_new if binary_for_new else target]
            if binary_for_new:
                cmd[-1] = binary_for_new # Use binary as input, -o output is handled by IDA default or needs -o
                # IDA default: creates IDB in same dir. Session logic handles this.
                # Actually, if creating new IDB from binary, we might need -o if it's in a cache dir.
                # But our session_mgr creates a path. IDA takes input file.
                # If target (IDB) doesn't exist, we run on binary. IDA creates IDB.
                # If we want specific IDB path, we use -o
                cmd = [self.idat_exe, "-A", f"-S{script_file}", f"-o{target}", binary_for_new]
            else:
                cmd = [self.idat_exe, "-A", f"-S{script_file}", target]

            proc = subprocess.run(cmd, capture_output=True, timeout=120)

            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    result = json.load(f)
                result["_execution_time"] = round(time.time() - start_time, 2)
                return result
            else:
                return make_error(MCPError.IDA_CRASHED, "No output from IDA", details={"stderr": proc.stderr.decode('utf-8', 'ignore')})

        except subprocess.TimeoutExpired:
            return make_error(MCPError.IDA_TIMEOUT, "Operation timed out", recoverable=True)
        except Exception as e:
            return make_error(MCPError.IDA_CRASHED, str(e))
        finally:
            for f in [script_file, output_file]:
                if os.path.exists(f):
                    try: os.remove(f)
                    except: pass
            if acquired_here:
                lock.release()

# =============================================================================
# STDIO MODE
# =============================================================================

class StdioServer(BaseIDAServer):
    def handle_session_tool(self, action: str, arguments: dict) -> dict:
        if action == "discover":
            binary = arguments.get("binary_path", "")
            if not binary: return make_error(MCPError.INVALID_ARGS, "binary_path required")
            return {"existing_idbs": self.session_mgr.discover_idbs(binary)}
        elif action == "create":
            binary = arguments.get("binary_path", "")
            use_existing = arguments.get("use_existing")
            if not binary: return make_error(MCPError.INVALID_ARGS, "binary_path required")

            # Verify paths
            if not os.path.exists(binary):
                return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {binary}")
            if use_existing:
                if not os.path.exists(use_existing):
                    return make_error(MCPError.FILE_NOT_FOUND, f"IDB not found: {use_existing}")
                # Check lock on existing
                lock = SimpleLock(use_existing)
                if lock.is_locked() and not lock.is_owned_by_self():
                    return make_error(MCPError.FILE_LOCKED, "IDB in use by another session")

            session = self.session_mgr.create_session(binary, use_existing)
            if not session.lock.acquire(timeout=5):
                 return make_error(MCPError.FILE_LOCKED, "Could not acquire lock")
            self.current_session = session
            return {"created": True, "session": session.to_dict()}
        elif action == "list":
            return {"sessions": self.session_mgr.list_sessions(), "current": self.current_session.to_dict() if self.current_session else None}
        elif action == "switch":
            sid = arguments.get("session_id", "")
            sess = self.session_mgr.get_session(sid)
            if not sess: return make_error(MCPError.SESSION_NOT_FOUND, "Session not found")
            self.current_session = sess
            return {"switched": True, "session": sess.to_dict()}
        elif action == "close":
            sid = arguments.get("session_id", "") or (self.current_session.session_id if self.current_session else "")
            if not sid: return make_error(MCPError.INVALID_ARGS, "session_id required")
            self.session_mgr.close_session(sid)
            if self.current_session and self.current_session.session_id == sid:
                self.current_session = None
            return {"closed": True, "session_id": sid}
        return make_error(MCPError.INVALID_ARGS, "Unknown session action")

    def run(self):
        # Suppress warnings and redirect stderr for stdio JSON-RPC purity
        warnings.filterwarnings("ignore")
        sys.stderr = io.StringIO()

        # Windows binary mode
        if os.name == "nt":
            try:
                import msvcrt
                msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
                msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            except: pass

        stdin, stdout = sys.stdin.buffer, sys.stdout.buffer

        while True:
            try:
                line = stdin.readline()
                if not line: break
                req = json.loads(line.decode('utf-8'))

                # Protocol
                if req.get("method") == "initialize":
                    res = {"jsonrpc": "2.0", "id": req["id"], "result": {
                        "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                        "serverInfo": {"name": "ida-pro-mcp", "version": "2.0.0"}
                    }}
                elif req.get("method") == "tools/list":
                    tools_list = []
                    for t in TOOLS:
                        tools_list.append({
                            "name": t,
                            "description": TOOL_DESCRIPTIONS.get(t, f"IDA {t}"),
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "idb": {"type": "string"},
                                    "action": {"type": "string"}
                                },
                                "required": ["action"] if t == "session" else ["idb", "action"]
                            }
                        })
                    res = {"jsonrpc": "2.0", "id": req["id"], "result": {"tools": tools_list}}
                elif req.get("method") == "tools/call":
                    params = req.get("params", {})
                    name = params.get("name")
                    args = params.get("arguments", {})

                    if name == "session":
                        result = self.handle_session_tool(args.get("action"), args)
                    else:
                        idb = args.pop("idb", None)
                        if not idb and self.current_session:
                            idb = self.current_session.idb_path

                        if not idb:
                            result = make_error(MCPError.SESSION_REQUIRED, "No IDB specified and no active session")
                        else:
                            result = self.call_tool(name, idb, **args)

                    res = {"jsonrpc": "2.0", "id": req["id"], "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}}
                else:
                    res = None # Notifications or unknown

                if res:
                    stdout.write(json.dumps(res).encode('utf-8') + b"\n")
                    stdout.flush()
            except:
                continue

# =============================================================================
# HTTP DAEMON MODE
# =============================================================================

class DaemonServer(BaseIDAServer):
    def __init__(self, host: str, port: int, workers: int):
        super().__init__()
        self.host = host
        self.port = port
        self.workers = workers

    def run(self):
        # Setup logging to console since we are not in stdio mode
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
        logger = logging.getLogger("ida-mcp")

        logger.info(f"Starting IDA MCP Daemon on {self.host}:{self.port}")
        logger.info(f"IDA Dir: {self.ida_dir}")

        server_instance = self # Closure for handler

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                logger.info(f"{self.address_string()} - {format % args}")

            def do_POST(self):
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = json.loads(self.rfile.read(length).decode())

                    action = body.get("action")
                    if action == "tool" or action in TOOLS:
                        tool = action if action in TOOLS else body.get("tool")
                        idb = body.get("idb")
                        args = body.get("args", {})
                        if action in TOOLS:
                             # If action IS the tool name, other body keys are args
                             args = {k:v for k,v in body.items() if k not in ["action", "idb"]}

                        if not idb:
                            self.send_error(400, "idb required")
                            return

                        res = server_instance.call_tool(tool, idb, **args)
                        self.send_json(res)
                    else:
                        self.send_error(400, f"Unknown action: {action}")
                except Exception as e:
                    self.send_error(500, str(e))

            def send_json(self, data):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

        httpd = HTTPServer((self.host, self.port), Handler)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--daemon", "--http", action="store_true", help="Run in HTTP Daemon mode")
    parser.add_argument("--port", type=int, default=13337, help="Port for Daemon mode (default: 13337)")
    parser.add_argument("--host", default="127.0.0.1", help="Host for Daemon mode")
    parser.add_argument("--workers", type=int, default=4, help="Workers for Daemon mode")
    args = parser.parse_args()

    if args.daemon:
        server = DaemonServer(args.host, args.port, args.workers)
        server.run()
    else:
        server = StdioServer()
        server.run()

if __name__ == "__main__":
    main()
