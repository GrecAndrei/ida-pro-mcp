#!/usr/bin/env python3
"""
IDA Pro MCP Server - Session-Based Architecture

Features:
- Session-based IDB management (multiple LLMs can analyze same binary)
- Multi-instance support (switch between multiple open files)
- File locking to prevent conflicts
- Structured error codes for LLM understanding
- Automatic IDB discovery and selection

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
import glob
import uuid
from typing import Any, Dict, Optional, List
from pathlib import Path
from datetime import datetime

# Suppress ALL warnings to prevent them from corrupting the JSON stream
warnings.filterwarnings("ignore")

# Redirect stderr to devnull to prevent any stray output
sys.stderr = io.StringIO()


# =============================================================================
# CONSTANTS - Avoid magic numbers scattered throughout code
# =============================================================================

# Timeouts (in seconds)
LOCK_TIMEOUT_DEFAULT = 10
LOCK_TIMEOUT_EXTENDED = 30
LOCK_STALE_THRESHOLD = 300  # 5 minutes
IDA_EXECUTION_TIMEOUT = 300  # 5 minutes

# Limits
LOG_TAIL_LINES = 50
ERROR_STDERR_LIMIT = 1000
SESSION_ID_LENGTH = 8

# Cache management
CACHE_MAX_SIZE_MB = 500  # Maximum cache directory size in MB
CACHE_CLEANUP_AGE_HOURS = 24  # Remove temp files older than this
TEMP_FILE_MAX_AGE = 3600  # 1 hour in seconds

# Retry intervals (in seconds)
LOCK_RETRY_INTERVAL = 0.1
ERROR_RETRY_AFTER = 5


# =============================================================================
# SESSION MANAGEMENT
# =============================================================================

class SimpleLock:
    """Cross-platform file lock without external dependencies.
    
    Uses atomic file creation for locking. Handles stale locks from crashed processes.
    
    Thread Safety:
        This class is NOT thread-safe. Each thread should create its own SimpleLock instance.
        The lock is process-level (file-based), not thread-level.
        For thread safety within a process, use threading.Lock in addition to this.
    """
    
    def __init__(self, path: str):
        self.lock_file = path + ".mcp.lock"
        self.locked = False
        self.pid = os.getpid()
        self._fd = None  # File descriptor for atomic operations
    
    def acquire(self, timeout: int = LOCK_TIMEOUT_DEFAULT) -> bool:
        """Acquire the lock. Returns True if successful.
        
        Uses atomic file creation (O_CREAT | O_EXCL) to prevent race conditions.
        Handles stale locks from crashed processes by checking modification time.
        """
        start = time.time()
        while time.time() - start < timeout:
            try:
                # Atomic create - fails if file exists
                fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                try:
                    os.write(fd, f"{self.pid}:{time.time()}".encode())
                finally:
                    os.close(fd)
                self.locked = True
                return True
            except FileExistsError:
                # Lock file exists - check if it's stale
                if self._check_and_remove_stale():
                    # Stale lock was removed, retry immediately
                    continue
                time.sleep(LOCK_RETRY_INTERVAL)
            except OSError as e:
                # Handle other OS errors (permission denied, etc.)
                time.sleep(LOCK_RETRY_INTERVAL)
        return False
    
    def release(self):
        """Release the lock by removing the lock file."""
        if self.locked:
            try:
                if os.path.exists(self.lock_file):
                    os.remove(self.lock_file)
            except OSError:
                pass  # Ignore errors during cleanup
            finally:
                self.locked = False
    
    def is_locked(self) -> bool:
        """Check if the file is currently locked (lock file exists)."""
        return os.path.exists(self.lock_file)
    
    def _check_and_remove_stale(self) -> bool:
        """Check if lock is stale and remove it atomically.
        
        Returns True if:
          - The lock file doesn't exist (can proceed with acquisition)
          - A stale lock was successfully removed
        Returns False if:
          - The lock exists and is not stale
          - The lock is stale but removal failed
          
        Uses atomic rename-to-temp + delete pattern to avoid TOCTOU races.
        """
        try:
            if not os.path.exists(self.lock_file):
                # No lock file - caller can proceed with acquisition
                return True
            
            mtime = os.path.getmtime(self.lock_file)
            if time.time() - mtime <= LOCK_STALE_THRESHOLD:
                return False  # Lock is not stale
            
            # Lock appears stale - try to remove it atomically
            # Generate a unique temp name to avoid collisions
            temp_name = f"{self.lock_file}.stale.{os.getpid()}.{time.time()}"
            try:
                # Atomic rename - if this succeeds, we "own" the stale lock
                os.rename(self.lock_file, temp_name)
                # Now safely delete the renamed file
                os.remove(temp_name)
                return True
            except FileNotFoundError:
                # Another process already removed it - we can proceed
                return True
            except OSError:
                # Rename failed (another process may have grabbed it)
                # Clean up temp file if it exists
                try:
                    if os.path.exists(temp_name):
                        os.remove(temp_name)
                except OSError:
                    pass
                return False
        except OSError:
            return False
    
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
        except (OSError, ValueError, IndexError):
            pass
        return None
    
    def force_release(self):
        """Force release a lock, even if we don't own it.
        
        Use with caution - only for cleaning up stale locks.
        """
        try:
            if os.path.exists(self.lock_file):
                os.remove(self.lock_file)
        except OSError:
            pass
    
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
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=SESSION_ID_LENGTH))
    
    def _get_session_idb_path(self, binary_path: str, session_id: str) -> str:
        """Get the IDB path for a session."""
        base = os.path.basename(binary_path)
        # Store session IDBs in the session directory
        return os.path.join(self.session_dir, f"{base}.{session_id}.i64")
    
    def discover_idbs(self, binary_path: str) -> List[Dict]:
        """Find all existing IDBs for a binary file."""
        results = []
        base_name = os.path.basename(binary_path)
        dir_path = os.path.dirname(os.path.abspath(binary_path))
        
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
    
    # File errors
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    FILE_LOCKED = "FILE_LOCKED"
    FILE_CORRUPT = "FILE_CORRUPT"
    
    # IDA errors
    IDA_NOT_FOUND = "IDA_NOT_FOUND"
    IDA_CRASHED = "IDA_CRASHED"
    IDA_TIMEOUT = "IDA_TIMEOUT"
    IDA_LICENSE = "IDA_LICENSE"
    
    # Session errors
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    SESSION_LOCKED = "SESSION_LOCKED"
    SESSION_REQUIRED = "SESSION_REQUIRED"
    
    # Tool errors
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    INVALID_ARGS = "INVALID_ARGS"
    DECOMPILE_FAILED = "DECOMPILE_FAILED"

def make_error(code: str, message: str, recoverable: bool = False, details: dict = None) -> dict:
    """Create a structured error response.
    
    Args:
        code: Error code from MCPError class
        message: Human-readable error message
        recoverable: If True, suggests the operation can be retried
        details: Optional dict with additional context
    
    Returns:
        Structured error dict with consistent format
    """
    result = {
        "error": True,
        "code": code,
        "message": message,
        "recoverable": recoverable
    }
    if recoverable:
        result["retry_after_seconds"] = ERROR_RETRY_AFTER
    if details:
        result["details"] = details
    return result


# =============================================================================
# TOOLS LIST
# =============================================================================

# List of available tools (39 total - includes session_manager)
TOOLS = [
    "session",  # Session management tool
    "idb", "code", "data", "search", "types", "memory", "modify",
    "misc", "debug", "funcs", "segments", "files", "plugins", "trace",
    "fixups", "data_ops", "agent", "microcode", "graph", "bulk",
    "ctree", "diff", "lumina", "symbols", "patterns", "structs",
    "emulate", "export", "history",
    "strings_xref", "entropy", "imports_deep", "comments_ai", "nav", "colorize",
    "trace_analysis", "hooks", "taint", "coverage"
]

# Tool descriptions for MCP discovery
TOOL_DESCRIPTIONS = {
    "session": """Session management for multi-file and multi-LLM workflows.
Actions: 
- discover (find existing IDBs for a binary, shows which are in use)
- create (create new session - either new IDB or use existing)
- list (list active sessions)
- switch (switch to a different session)
- close (close a session and release locks)
Required: action. 
For discover/create: binary_path. 
For create: use_existing (optional path to existing IDB).
For switch/close: session_id.
Returns session info with lock status.""",

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
Required: idb, action. For undo/redo: count. For snapshot/restore: name.""",

    "trace_analysis": """Post-mortem execution trace analysis.
Actions: import_trace (load trace file), analyze_coverage (calculate coverage from trace), find_loops (detect hot loops), extract_api_calls (API call sequence), basic_blocks_hit (per-function block coverage).
Required: idb, action. For most actions: path or trace_data (list of addresses).""",

    "hooks": """API hook suggestions and script generation.
Actions: suggest (category-based hook suggestions), generate_frida (Frida JS script), generate_detours (MS Detours C++ template), find_targets (interesting hook points), inline_hooks (trampoline points).
Required: idb, action. For suggest: category (network|file|crypto|registry|process). For generate: addr or func_name.""",

    "taint": """Static taint/data flow analysis using Hex-Rays.
Actions: trace_arg (follow argument flow), trace_return (find return value usage), find_sinks (reachable dangerous functions), data_flow (function inputs/outputs), slice (backward slice from instruction).
Required: idb, action, addr. For trace_arg: arg_num. For find_sinks: depth.""",

    "coverage": """Code coverage import and analysis.
Actions: import_drcov (DynamoRIO format), import_lighthouse (simple address list), highlight (color covered code), report (function coverage), uncovered (find important missed functions).
Required: idb, action. For import/highlight: path. For report: addr. Optional: color (green|yellow|red)."""
}


# =============================================================================
# MCP SERVER
# =============================================================================

class IDAMCPServer:
    """MCP server with session management and multi-instance support."""
    
    def __init__(self):
        # Get IDA directory from environment or auto-detect
        self.ida_dir = os.environ.get("IDADIR", "")
        if not self.ida_dir:
            self.ida_dir = self._detect_ida_dir()
        
        self.idat_exe = self._find_idat()
        
        # Use user-specific cache directory (cross-platform)
        self.cache_dir = os.environ.get(
            "IDA_MCP_CACHE", 
            os.path.join(os.path.expanduser("~"), ".ida_mcp_cache")
        )
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.api_path = os.path.join(self.script_dir, "src", "ida_pro_mcp", "ida_mcp")
        
        # Create cache dir
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Session manager
        self.session_mgr = SessionManager(self.cache_dir)
        
        # Current active session
        self.current_session: Optional[Session] = None
    
    def _detect_ida_dir(self) -> str:
        """Auto-detect IDA installation directory."""
        if sys.platform == "win32":
            candidates = [
                r"C:\Program Files\IDA Professional 9.2",
                r"C:\Program Files\IDA Pro 9.2",
                r"C:\Program Files\IDA Professional 9.1",
                r"C:\Program Files\IDA Professional 9.0",
                r"C:\Program Files (x86)\IDA Pro",
            ]
        elif sys.platform == "darwin":
            candidates = [
                "/Applications/IDA Pro 9.2/ida.app/Contents/MacOS",
                "/Applications/IDA Pro.app/Contents/MacOS",
            ]
        else:  # Linux
            candidates = [
                "/opt/ida",
                "/opt/idapro",
                os.path.expanduser("~/ida"),
            ]
        
        for c in candidates:
            if os.path.exists(c):
                return c
        return ""
    
    def _find_idat(self) -> str:
        """Find idat executable (headless IDA)."""
        if sys.platform == "win32":
            exe_names = ["idat.exe", "idat64.exe"]
        else:
            exe_names = ["idat64", "idat"]
        
        # Search in configured ida_dir first
        if self.ida_dir:
            for name in exe_names:
                path = os.path.join(self.ida_dir, name)
                if os.path.exists(path):
                    return path
        
        # Fallback: search in auto-detected directories
        # Reuse the detection logic to avoid duplication
        detected_dir = self._detect_ida_dir()
        if detected_dir and detected_dir != self.ida_dir:
            for name in exe_names:
                path = os.path.join(detected_dir, name)
                if os.path.exists(path):
                    return path
        
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
    
    def handle_session_tool(self, action: str, arguments: dict) -> dict:
        """Handle session management actions."""
        
        # Support multiple param names for binary path
        binary_path = arguments.get("binary_path") or arguments.get("idb") or arguments.get("path") or ""
        
        if action == "discover":
            if not binary_path:
                return make_error(MCPError.INVALID_ARGS, "binary_path (or idb/path) required")
            if not os.path.exists(binary_path):
                return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {binary_path}")
            
            idbs = self.session_mgr.discover_idbs(binary_path)
            return {
                "binary": binary_path,
                "existing_idbs": idbs,
                "count": len(idbs),
                "note": "Use 'create' action to start a session. Specify 'use_existing' to use an existing IDB."
            }
        
        elif action == "create":
            use_existing = arguments.get("use_existing")
            
            if not binary_path:
                return make_error(MCPError.INVALID_ARGS, "binary_path (or idb/path) required")
            if not os.path.exists(binary_path):
                return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {binary_path}")
            
            # Check if use_existing is locked
            if use_existing:
                lock = SimpleLock(use_existing)
                if lock.is_locked():
                    owner = lock.get_owner_info()
                    return make_error(
                        MCPError.FILE_LOCKED,
                        f"IDB is in use by another session",
                        recoverable=True,
                        details={"owner": owner}
                    )
            
            session = self.session_mgr.create_session(binary_path, use_existing)
            
            # Acquire lock
            if not session.lock.acquire(timeout=5):
                return make_error(MCPError.FILE_LOCKED, "Could not acquire lock", recoverable=True)
            
            self.current_session = session
            
            return {
                "created": True,
                "session": session.to_dict(),
                "note": "Session is now active. Use session_id or omit 'idb' param to use this session."
            }
        
        elif action == "list":
            return {
                "sessions": self.session_mgr.list_sessions(),
                "current": self.current_session.to_dict() if self.current_session else None
            }
        
        elif action == "switch":
            session_id = arguments.get("session_id", "")
            if not session_id:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            
            session = self.session_mgr.get_session(session_id)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session not found: {session_id}")
            
            self.current_session = session
            return {
                "switched": True,
                "session": session.to_dict()
            }
        
        elif action == "close":
            session_id = arguments.get("session_id", "")
            if not session_id and self.current_session:
                session_id = self.current_session.session_id
            
            if not session_id:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            
            self.session_mgr.close_session(session_id)
            
            if self.current_session and self.current_session.session_id == session_id:
                self.current_session = None
            
            return {"closed": True, "session_id": session_id}
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown session action: {action}")
    
    def call_tool(self, tool_name: str, idb_path: str, **kwargs) -> Dict[str, Any]:
        """Execute a tool from api_consolidated.py on an IDB file.
        
        Args:
            tool_name: Name of the tool function to call
            idb_path: Path to IDB file or binary
            **kwargs: Arguments to pass to the tool
            
        Returns:
            Result dict from tool, or structured error dict
        """
        start_time = time.time()
        
        # Find or create IDB
        target = idb_path
        if not idb_path.endswith(('.i64', '.idb')):
            existing = self._check_idb_exists(idb_path)
            if existing:
                target = existing
        
        if not os.path.exists(target):
            return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {target}")
        
        if not self.idat_exe:
            return make_error(MCPError.IDA_NOT_FOUND, "idat.exe not found. Set IDADIR environment variable.")
        
        # Try to acquire lock for this IDB
        # The acquire() method handles stale lock detection internally
        lock = SimpleLock(target)
        lock_acquired = lock.acquire(timeout=LOCK_TIMEOUT_EXTENDED)
        
        if not lock_acquired:
            owner = lock.get_owner_info()
            return make_error(
                MCPError.FILE_LOCKED,
                f"IDB is locked by another process",
                recoverable=True,
                details={"owner": owner}
            )
        
        # Initialize temp file paths
        script_file = None
        output_file = None
        args_file = None
        log_file = None
        cwd = None
        success = False
        
        try:
            # Create unique temp files (collision-safe using UUID)
            unique_id = f"{os.getpid()}_{threading.get_ident()}_{uuid.uuid4().hex[:12]}"
            script_file = os.path.join(self.cache_dir, f"mcp_script_{unique_id}.py")
            output_file = os.path.join(self.cache_dir, f"mcp_result_{unique_id}.json")
            args_file = os.path.join(self.cache_dir, f"mcp_args_{unique_id}.json")
            
            # Enable IDA logging for debugging
            log_file = os.path.join(self.cache_dir, f"mcp_ida_{unique_id}.log")
            
            # Write arguments to separate JSON file (UTF-8, safe from escaping issues)
            with open(args_file, 'w', encoding='utf-8') as f:
                json.dump(kwargs, f, ensure_ascii=False, indent=2)
            
            # Escape paths for Windows
            escaped_api_path = self.api_path.replace('\\', '\\\\')
            escaped_output = output_file.replace('\\', '\\\\')
            escaped_args = args_file.replace('\\', '\\\\')
            
            # Generate script that reads args from file
            script = f'''import json
import sys

sys.path.insert(0, "{escaped_api_path}")

from api_consolidated import {tool_name}

try:
    # Read arguments from JSON file (safe from escaping issues)
    with open("{escaped_args}", "r", encoding="utf-8") as f:
        kwargs = json.load(f)
    result = {tool_name}(**kwargs)
except Exception as e:
    result = {{"error": str(e), "traceback": __import__("traceback").format_exc()}}

with open("{escaped_output}", "w", encoding="utf-8") as f:
    json.dump(result, f, default=str)

import ida_pro
ida_pro.qexit(0)
'''
            
            # Write script to file
            with open(script_file, 'w', encoding='utf-8') as f:
                f.write(script)
            
            # Determine working directory (stable environment)
            ida_dir = self.ida_dir if self.ida_dir else os.path.dirname(self.idat_exe)
            cwd = ida_dir if os.path.isdir(ida_dir) else None
            
            # Build explicit environment
            env = os.environ.copy()
            if self.ida_dir:
                env["IDADIR"] = self.ida_dir
                # Ensure ida_dir is in PATH
                path_entries = env.get("PATH", "").split(os.pathsep)
                if self.ida_dir not in path_entries:
                    env["PATH"] = self.ida_dir + os.pathsep + env.get("PATH", "")
            
            # Build command with optional logging
            cmd = [self.idat_exe, "-A"]
            if log_file:
                cmd.append(f"-L{log_file}")
            cmd.extend([f"-S{script_file}", target])
            
            # Using shell=False (default) for security - paths with spaces are handled
            # correctly because subprocess passes list elements as separate arguments,
            # unlike shell mode which would require quoting
            proc = subprocess.run(cmd, capture_output=True, timeout=IDA_EXECUTION_TIMEOUT, cwd=cwd, env=env)
            
            # Check for common error patterns in stderr
            stderr_text = proc.stderr.decode('utf-8', errors='ignore')
            stderr_lower = stderr_text.lower()
            
            if proc.returncode != 0:
                if "license" in stderr_lower:
                    return make_error(MCPError.IDA_LICENSE, "IDA license issue detected")
                elif "access denied" in stderr_lower or "locked" in stderr_lower:
                    return make_error(MCPError.FILE_LOCKED, "File access denied", recoverable=True)
                elif "corrupt" in stderr_lower:
                    return make_error(MCPError.FILE_CORRUPT, "IDB appears to be corrupt")
            
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    result = json.load(f)
                result["_execution_time"] = round(time.time() - start_time, 2)
                result["_session"] = self.current_session.session_id if self.current_session else None
                success = True
                return result
            else:
                # Build detailed error with diagnostics
                details = {
                    "returncode": proc.returncode,
                    "stderr": stderr_text[:ERROR_STDERR_LIMIT] if stderr_text else "",
                    "idat_exe": self.idat_exe,
                    "cwd": cwd,
                    "idadir_set": bool(self.ida_dir)
                }
                
                # Include last N lines of IDA log if enabled
                if log_file and os.path.exists(log_file):
                    try:
                        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            details["ida_log_tail"] = "".join(lines[-LOG_TAIL_LINES:])
                    except OSError:
                        pass
                
                return make_error(
                    MCPError.IDA_CRASHED,
                    "IDA crashed or produced no output",
                    details=details
                )
        
        except subprocess.TimeoutExpired:
            details = {
                "timeout": IDA_EXECUTION_TIMEOUT,
                "idat_exe": self.idat_exe,
                "cwd": cwd,
                "idadir_set": bool(self.ida_dir)
            }
            return make_error(MCPError.IDA_TIMEOUT, f"Operation timed out ({IDA_EXECUTION_TIMEOUT}s)", recoverable=True, details=details)
        except OSError as e:
            return make_error(MCPError.IDA_CRASHED, f"OS error: {e}")
        except Exception as e:
            return make_error(MCPError.IDA_CRASHED, f"Unexpected error: {e}")
        finally:
            # Always clean up temp files
            self._cleanup_temp_files(
                script_file, output_file, args_file, log_file,
                keep_log_on_failure=not success
            )
            
            # Release lock if we acquired it
            if lock_acquired:
                lock.release()
    
    def _cleanup_temp_files(self, script_file: str, output_file: str, args_file: str, 
                           log_file: str, keep_log_on_failure: bool = True):
        """Clean up temporary files created during tool execution.
        
        Args:
            script_file: Path to temporary script file
            output_file: Path to output JSON file
            args_file: Path to arguments JSON file
            log_file: Path to IDA log file
            keep_log_on_failure: If True, keep log file when operation failed
        """
        # Always clean these files
        for f in [script_file, output_file, args_file]:
            if f:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except OSError:
                    pass
        
        # Conditionally clean log file
        if log_file:
            # Determine if operation succeeded (output file was created)
            operation_succeeded = output_file and os.path.exists(output_file)
            # Keep log file only on failure if requested
            should_keep_log = keep_log_on_failure and not operation_succeeded
            
            if not should_keep_log:
                try:
                    if os.path.exists(log_file):
                        os.remove(log_file)
                except OSError:
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
                            "description": "Path to IDB file or binary (optional if session is active)"
                        },
                        "action": {
                            "type": "string",
                            "description": "Action to perform within this tool"
                        }
                    },
                    "required": ["action"] if tool_name == "session" else ["idb", "action"]
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
                        "version": "2.0.0"  # Version bump for session support
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
            
            # Handle session tool specially
            if tool_name == "session":
                action = arguments.get("action", "")
                result = self.handle_session_tool(action, arguments)
            else:
                # Get IDB path - from args, current session, or error
                idb_path = arguments.pop("idb", None)
                
                if not idb_path:
                    if self.current_session:
                        idb_path = self.current_session.idb_path
                    else:
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": json.dumps(make_error(
                                        MCPError.SESSION_REQUIRED,
                                        "No IDB specified and no active session. Use 'session' tool to create one, or specify 'idb' parameter."
                                    ), indent=2)
                                }]
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
        # Use binary mode to avoid encoding issues
        if sys.platform == "win32":
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
                # Invalid JSON - skip this request
                continue
            except KeyboardInterrupt:
                # User requested shutdown
                break
            except UnicodeDecodeError:
                # Invalid UTF-8 input - skip
                continue
            except IOError:
                # I/O error (pipe closed, etc.) - exit
                break
            except Exception:
                # Log other errors but continue processing
                # In production, this could log to a file
                pass
        
        # Cleanup: release all session locks and clean up stale lock files
        self._cleanup_on_exit()
    
    def _cleanup_on_exit(self):
        """Clean up resources when the server exits."""
        # Release all session locks
        for session in self.session_mgr.sessions.values():
            try:
                session.lock.release()
            except Exception:
                pass
        
        # Clean up stale lock files in the cache directory
        try:
            lock_pattern = os.path.join(self.cache_dir, "*.mcp.lock")
            for lock_file in glob.glob(lock_pattern):
                try:
                    # Only remove stale locks (older than threshold)
                    if os.path.exists(lock_file):
                        mtime = os.path.getmtime(lock_file)
                        if time.time() - mtime > LOCK_STALE_THRESHOLD:
                            os.remove(lock_file)
                except OSError:
                    pass
        except OSError:
            pass
        
        # Clean up old temp files (older than configured age)
        # Use os.listdir for better performance than multiple glob calls
        try:
            temp_prefixes = ("mcp_script_", "mcp_result_", "mcp_args_", "mcp_ida_")
            cutoff_time = time.time() - TEMP_FILE_MAX_AGE
            
            for filename in os.listdir(self.cache_dir):
                if filename.startswith(temp_prefixes):
                    filepath = os.path.join(self.cache_dir, filename)
                    try:
                        if os.path.isfile(filepath) and os.path.getmtime(filepath) < cutoff_time:
                            os.remove(filepath)
                    except OSError:
                        pass
        except OSError:
            pass


if __name__ == "__main__":
    server = IDAMCPServer()
    server.run()
