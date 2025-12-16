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

# List of available tools (32 total)
TOOLS = [
    "idb", "code", "data", "search", "types", "memory", "modify",
    "misc", "debug", "funcs", "segments", "files", "plugins", "trace",
    "fixups", "data_ops", "agent", "microcode", "graph", "bulk",
    "ctree", "diff", "lumina", "symbols", "patterns", "structs",
    # Session B tools (30-35)
    "strings_xref", "entropy", "imports_deep", "comments_ai", "nav", "colorize",
    "emulate", "export", "history"
]

# Tool descriptions for MCP discovery - detailed for LLM comprehension
TOOL_DESCRIPTIONS = {
    "idb": """IDB database metadata and navigation.
Actions: meta (get file path, module name, base address, size, MD5/SHA256 hashes), segments (list all binary segments with permissions), cursor (get current address in IDA), entrypoints (list program entry points).
Required: idb (path to IDB or binary file), action (one of the above).""",

    "code": """Decompilation, disassembly, and code flow analysis.
Actions: decompile (get Hex-Rays pseudocode), disassemble (get assembly), xrefs_to (find references TO an address), xrefs_from (find references FROM an address), basic_blocks (get control flow blocks), graph (get call graph).
Required: idb, action. Optional: addrs (address or list of addresses), depth (for graph traversal).""",

    "data": """List and query binary data structures.
Actions: functions (list all functions with addr/name/size), globals (list global variables), strings (list all strings with addresses), imports (list imported functions), exports (list exported symbols).
Required: idb, action. Optional: query (filter pattern), offset/count (pagination).""",

    "search": """Search for patterns, bytes, and references in the binary.
Actions: bytes (search hex pattern like '90 90 ??'), string (search text), immediate (find numeric constants), name (search symbol names), pattern (search with wildcards).
Required: idb, action. Optional: query (search pattern), start/end (address range).""",

    "types": """Manage type information, structures, and enums.
Actions: list (list all local types), get (get type definition), define (create new type from C declaration), get_members (get struct fields), apply (apply type to address), search_structs (find structs by field name).
Required: idb, action. Optional: name (type name), decl (C declaration), addr (for apply).""",

    "memory": """Read and write raw memory at addresses.
Actions: read (read bytes from address), write (write bytes to address).
Required: idb, action, addr (hex address). For read: size (bytes to read). For write: data (hex bytes).""",

    "modify": """Modify IDB annotations - rename, comment, patch.
Actions: rename (rename function/variable), comment (add comment), set_type (set type annotation), patch (patch bytes/assembly).
Required: idb, action, addr. For rename: name. For comment: text. For set_type: type_str. For patch: data or asm.""",

    "misc": """Miscellaneous utilities - Python execution, signatures, bookmarks.
Actions: python (execute Python code in IDA), idc (run IDC script), load_sig (load FLIRT signature), bookmarks (manage IDA bookmarks).
Required: idb, action. For python/idc: code. For load_sig: path or name.""",

    "debug": """Debugger control: process state, breakpoints, registers, memory.
Actions: start (launch debugger), stop (terminate process), continue (resume execution), step (single step), step_into, step_over, run_to (run to address), get_regs (get registers), set_reg (set register), read_mem (read debugger memory), write_mem (write debugger memory), add_bp (add breakpoint), del_bp (delete breakpoint), list_bp (list breakpoints), enable_bp (enable/disable breakpoint), threads (list threads).
Required: idb, action. Optional: addr, reg, value, size, data, enabled, tid.""",

    "funcs": """Create and modify function definitions.
Actions: create (define new function at address), delete (undefine function), set_flags (set function flags like FUNC_NORET), set_name (rename function), add_comment (add function comment).
Required: idb, action, addr. Optional: name, flags, comment.""",

    "segments": """Manage binary segments.
Actions: list (list all segments), add (create segment), delete (remove segment), set_attr (modify segment attribute).
Required: idb, action. For add: start, end, name, sclass. For set_attr: attr, value.""",

    "files": """Database and file I/O operations.
Actions: save (save IDB), close (close database), open (open file in IDA), batch (analyze multiple files), export (export to file).
Required: idb, action. For batch: paths (list of files). For open: path.""",

    "plugins": """IDA plugin management.
Actions: list (list available plugins), run (execute a plugin).
Required: idb, action. For run: name (plugin name).""",

    "trace": """Debugger trace management.
Actions: get (get execution trace), clear (clear trace buffer), set_options (configure tracing).
Required: idb, action. For set_options: enable_insn, enable_func, enable_bblk (booleans).""",

    "fixups": """Relocation and fixup management.
Actions: list (list all fixups/relocations), get (get fixup at address), add (create fixup), delete (remove fixup).
Required: idb, action. For get/add/delete: addr. For add: target, fixup_type.""",

    "data_ops": """Create data items in the database.
Actions: make_data (define data at address), make_array (create array), make_string (define string), undefine (remove definition), make_code (convert to code).
Required: idb, action, addr. Optional: size, count (for array), str_type (string encoding).""",

    "agent": """High-level analysis helpers for comprehensive exploration.
Actions: analyze_function (get full function analysis with decompilation, xrefs, strings), explore_address (get context around an address), find_references (trace data/code references), search_all (universal search across names, strings, bytes).
Required: idb, action. Optional: addr, query, depth.""",

    "microcode": """Access Hex-Rays microcode intermediate representation.
Actions: get (get microcode overview), blocks (get micro-blocks), instructions (get micro-instructions).
Required: idb, action, addr (function address). Optional: maturity (optimization level 0-7).""",

    "graph": """Export control flow and call graphs.
Actions: callgraph (generate function call graph), cfg (generate function CFG).
Required: idb, action, addr. Optional: depth, direction (down/up/both), format (json/dot).""",

    "bulk": """Bulk operations for batch modifications.
Actions: rename (batch rename from list), comment (batch add comments), set_type (batch set types), import_json (import annotations from file), export_json (export annotations).
Required: idb, action. For rename/comment/set_type: items (list of {addr, value} dicts). For import/export: path.""",

    "ctree": """Access Hex-Rays CTree (decompiler AST) for deep code analysis.
Actions: get (get full CTree structure), traverse (tree structure with depth), find_calls (find function calls with optional filter), find_vars (list local variables/args), find_strings (string references in function), find_conditions (if/while/for statements).
Required: idb, action, addr (function address). Optional: query (filter for find_calls), depth (traversal depth).""",

    "diff": """Binary comparison and diffing for patch analysis.
Actions: functions (compare two functions by decompilation), bytes (compare byte ranges), signatures (find similar functions by code signature), names (list all named items for export), summary (database statistics for comparison).
Required: idb, action. For functions: addr1, addr2. For bytes: addr1 (start:end), addr2. For signatures: addr1, threshold (0.0-1.0).""",

    "lumina": """Interact with Hex-Rays Lumina cloud for function recognition.
Actions: pull (pull function names from Lumina), push (push annotations to Lumina), status (check connection), history (function history), search (search Lumina by name).
Required: idb, action. For pull/push: addr (specific) or push_all=True. For search: query. Note: Requires Lumina license.""",

    "symbols": """Load and manage debug symbols (PDB, DWARF, COFF).
Actions: load_pdb (load PDB file), load_dwarf (parse DWARF info), status (check symbol status), apply (apply type at address), export (export symbols to file).
Required: idb, action. For load_pdb: path (optional, auto-detects). For export: path.""",

    "patterns": """FLIRT-like pattern generation and matching.
Actions: generate (create pattern from function), match (find functions by pattern), list_sigs (list available FLIRT sigs), apply_sig (apply signature file), create_sig (create signature metadata).
Required: idb, action. For generate/create_sig: addr. For match: pattern (hex with ?? wildcards). For apply_sig: name.""",

    "structs": """Automatic structure recovery and struct management.
Actions: recover (recover struct from function usage), analyze_usage (analyze memory accesses), list (list all structs), create (create from C declaration), apply (apply struct at address).
Required: idb, action. For recover/apply: addr. For create: decl (C code). For apply: name (struct name).""",

    # Session B tools (30-35)
    "strings_xref": """Advanced string analysis with xref chains and encoding detection.
Actions: analyze (deep analysis of string at address), xref_chain (trace string references through callers), detect_encoded (find encrypted/encoded strings), find_format (find format strings with args), clusters (group strings by calling function).
Required: idb, action. For analyze/xref_chain: addr. Optional: query, depth.""",

    "entropy": """Entropy analysis for detecting packed/encrypted regions.
Actions: section (entropy for each segment), region (entropy for address range), packed_detect (detect packed sections), crypto_detect (find crypto constants/S-boxes), compare (compare entropy of two regions).
Required: idb, action. For region/compare: addr. Optional: size, threshold, end_addr.""",

    "imports_deep": """Deep import analysis with thunk resolution and delay imports.
Actions: thunks (resolve import thunks), delay (list delay-loaded imports), forwarded (detect forwarded exports), ordinal (resolve ordinal imports), api_sets (resolve API Set redirections), resolve (resolve import at address).
Required: idb, action. Optional: query (DLL filter), addr.""",

    "comments_ai": """AI-optimized comment management with structured formats.
Actions: get_context (all comments around address), set_structured (set formatted comment), bulk_set (set multiple from JSON), export_md (export to markdown), import_md (import from markdown), summary (commenting coverage stats).
Required: idb, action. For set: addr, text. For bulk: items (JSON). For export/import: path.""",

    "nav": """Navigation helpers for bookmarks and interesting addresses.
Actions: bookmarks (list marked positions), add_bookmark (add mark), del_bookmark (remove mark), goto (get address context), history (navigation history), cursor (current position), interesting (find crypto/packer/anti-analysis).
Required: idb, action. For bookmark ops: addr, slot. For goto: addr.""",

    "colorize": """Code region coloring and highlighting.
Actions: set_func (color entire function), set_range (color address range), set_insn (color single instruction), get (get color at address), clear (remove coloring), palette (get color names), highlight_pattern (highlight byte pattern matches).
Required: idb, action. For set ops: addr, color. For range: end_addr. For pattern: pattern.""",
    "emulate": """Code emulation and snippet execution.
Actions: snippet (trace code from address), appcall (call function with args - needs debugger), trace (static trace through function), decrypt_strings (find encrypted string patterns), eval_expr (evaluate value at address).
Required: idb, action. For snippet/trace: addr, max_steps. For appcall: func_name or addr, args.""",

    "export": """Export IDB data in various formats.
Actions: listing (assembly listing), html (HTML report), idc (IDC script), json (JSON metadata), binexport (BinDiff format), headers (C headers).
Required: idb, action. For listing/html/idc/json/headers: path (output file).""",

    "history": """Database version control and undo management.
Actions: undo (undo operations), redo (redo operations), list (show undo/redo status), snapshot (create named checkpoint), restore (restore from snapshot), diff (show changes).
Required: idb, action. For undo/redo: count. For snapshot/restore: name."""
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

