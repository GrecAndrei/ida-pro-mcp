#!/usr/bin/env python3
"""
IDA Pro MCP Server - Stdio Wrapper for Antigravity IDE

This script wraps the IDA MCP daemon as a proper MCP server using
stdio-based JSON-RPC protocol for integration with Google Antigravity IDE.

Features:
- Receives MCP tool calls via stdin
- Spawns idat.exe workers to execute tools
- Returns results via stdout

Usage in mcp_config.json:
{
  "mcpServers": {
    "ida-pro-mcp": {
      "type": "stdio",
      "command": "python",
      "args": ["C:\\path\\to\\ida_mcp_stdio.py"],
      "env": {"IDADIR": "C:\\Program Files\\IDA Professional 9.2"}
    }
  }
}
"""

import json
import sys
import os
import io
import threading
import subprocess
import time
import warnings
from typing import Any, Dict, Optional
from pathlib import Path

# Suppress ALL warnings to prevent them from corrupting the JSON stream
warnings.filterwarnings("ignore")

# Redirect stderr to devnull to prevent any stray output
sys.stderr = io.StringIO()

# List of available tools
TOOLS = [
    "idb", "code", "data", "search", "types", "memory", "modify",
    "misc", "funcs", "segments", "files", "plugins", "trace",
    "fixups", "data_ops", "agent", "microcode", "graph", "bulk"
]

# Tool descriptions for MCP discovery
TOOL_DESCRIPTIONS = {
    "idb": "Get IDB metadata, segments, cursor position, entrypoints",
    "code": "Decompile, disassemble, get xrefs, basic blocks, call graph",
    "data": "List functions, globals, strings, imports, exports",
    "search": "Find bytes, patterns, strings, references, instructions",
    "types": "Manage types, structs, enums, function prototypes",
    "memory": "Read/write memory at addresses",
    "modify": "Rename, comment, set types, patch assembly",
    "misc": "Execute Python/IDC, load signatures, manage bookmarks",
    "funcs": "Create, delete, modify function definitions",
    "segments": "List, add, delete, modify segments",
    "files": "Open, save, close databases, batch analysis",
    "plugins": "List and run IDA plugins",
    "trace": "Get/clear execution traces",
    "fixups": "Manage relocations/fixups",
    "data_ops": "Create data, arrays, strings, code",
    "agent": "High-level analysis helpers",
    "microcode": "Access Hex-Rays intermediate representation",
    "graph": "Export call graphs and CFGs",
    "bulk": "Bulk rename, comment, type operations"
}


class IDAMCPServer:
    """MCP server that routes tool calls to idat.exe workers."""
    
    def __init__(self):
        self.ida_dir = os.environ.get("IDADIR", "")
        self.idat_exe = self._find_idat()
        self.cache_dir = os.path.join(os.path.expanduser("~"), ".ida_mcp_cache")
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.api_path = os.path.join(self.script_dir, "src", "ida_pro_mcp", "ida_mcp")
        
        # Create cache dir
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Current IDB path (set by user)
        self.current_idb: Optional[str] = None
    
    def _find_idat(self) -> str:
        """Find idat.exe executable."""
        if self.ida_dir:
            for name in ["idat.exe", "idat64.exe", "idat"]:
                path = os.path.join(self.ida_dir, name)
                if os.path.exists(path):
                    return path
        
        # Try common paths
        candidates = [
            r"C:\Program Files\IDA Professional 9.2\idat.exe",
            r"C:\Program Files\IDA Pro 9.2\idat.exe",
            r"C:\Program Files\IDA Professional 9.0\idat.exe",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        
        return ""
    
    def _check_idb_exists(self, filepath: str) -> Optional[str]:
        """Check if IDB already exists for this file."""
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
        """Execute a tool from api_consolidated.py on an IDB file."""
        start_time = time.time()
        
        # Find or create IDB
        target = idb_path
        if not idb_path.endswith(('.i64', '.idb')):
            existing = self._check_idb_exists(idb_path)
            if existing:
                target = existing
        
        if not os.path.exists(target):
            return {"error": f"File not found: {target}"}
        
        if not self.idat_exe:
            return {"error": "idat.exe not found. Set IDADIR environment variable."}
        
        # Escape paths for Windows
        escaped_api_path = self.api_path.replace('\\', '\\\\')
        
        # Serialize kwargs as JSON
        args_json = json.dumps(kwargs)
        
        # Create output file path
        output_file = os.path.join(self.cache_dir, f"mcp_result_{os.getpid()}_{threading.get_ident()}.json")
        escaped_output = output_file.replace('\\', '\\\\')
        
        # Generate script
        script = f'''import json
import sys

sys.path.insert(0, "{escaped_api_path}")

from api_consolidated import {tool_name}

try:
    kwargs = json.loads('{args_json}')
    result = {tool_name}(**kwargs)
except Exception as e:
    result = {{"error": str(e), "traceback": __import__("traceback").format_exc()}}

with open("{escaped_output}", "w") as f:
    json.dump(result, f, default=str)

import ida_pro
ida_pro.qexit(0)
'''
        
        # Write script to file
        script_file = os.path.join(self.cache_dir, f"mcp_script_{os.getpid()}_{threading.get_ident()}.py")
        
        try:
            with open(script_file, 'w', encoding='utf-8') as f:
                f.write(script)
            
            cmd = [self.idat_exe, "-A", f"-S{script_file}", target]
            
            proc = subprocess.run(cmd, capture_output=True, timeout=120)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    result = json.load(f)
                result["_execution_time"] = time.time() - start_time
                return result
            else:
                return {
                    "error": "Tool execution produced no output",
                    "returncode": proc.returncode
                }
        
        except subprocess.TimeoutExpired:
            return {"error": "Tool execution timed out (120s)"}
        except Exception as e:
            return {"error": str(e)}
        finally:
            for f in [script_file, output_file]:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except:
                    pass
    
    def get_tools_list(self) -> list:
        """Return list of available tools in MCP format."""
        tools = []
        for tool_name in TOOLS:
            tools.append({
                "name": tool_name,
                "description": TOOL_DESCRIPTIONS.get(tool_name, f"IDA Pro {tool_name} tool"),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "idb": {
                            "type": "string",
                            "description": "Path to IDB file or binary"
                        },
                        "action": {
                            "type": "string",
                            "description": "Action to perform within this tool"
                        }
                    },
                    "required": ["idb", "action"]
                }
            })
        return tools
    
    def handle_request(self, request: dict) -> dict:
        """Handle a single MCP request."""
        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})
        
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "ida-pro-mcp",
                        "version": "1.0.0"
                    }
                }
            }
        
        elif method == "notifications/initialized":
            return None  # No response needed
        
        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": self.get_tools_list()
                }
            }
        
        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            
            if tool_name not in TOOLS:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Unknown tool: {tool_name}"
                    }
                }
            
            idb_path = arguments.pop("idb", self.current_idb or "")
            if not idb_path:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Missing required parameter: idb"
                    }
                }
            
            # Execute tool
            result = self.call_tool(tool_name, idb_path, **arguments)
            
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2, default=str)
                        }
                    ]
                }
            }
        
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
    
    def run(self):
        """Main event loop - read from stdin, write to stdout."""
        # Use binary mode to avoid Windows encoding issues
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        
        stdin = sys.stdin.buffer
        stdout = sys.stdout.buffer
        
        while True:
            try:
                line = stdin.readline()
                if not line:
                    break
                
                line = line.decode('utf-8').strip()
                if not line:
                    continue
                
                request = json.loads(line)
                response = self.handle_request(request)
                
                if response is not None:
                    out = json.dumps(response, separators=(',', ':'))
                    stdout.write((out + "\n").encode('utf-8'))
                    stdout.flush()
            
            except json.JSONDecodeError:
                continue
            except KeyboardInterrupt:
                break
            except Exception:
                pass


if __name__ == "__main__":
    server = IDAMCPServer()
    server.run()

