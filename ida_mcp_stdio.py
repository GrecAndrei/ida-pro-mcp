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
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    INTEGER_OVERFLOW = "INTEGER_OVERFLOW"


def validate_path(path: str, base_allowed: Optional[List[str]] = None) -> Optional[str]:
    """Validate a file path against directory traversal attacks.
    
    Args:
        path: Path to validate
        base_allowed: Optional list of allowed base directories
        
    Returns:
        Normalized path if valid, None if invalid
    """
    if not path:
        return None
    
    # Normalize the path
    try:
        normalized = os.path.normpath(os.path.abspath(path))
    except (ValueError, OSError):
        return None
    
    # Check for null byte injection
    if '\x00' in path:
        return None
    
    # Check for directory traversal - after normpath, ".." should be resolved
    # If the original path had ".." and the resolved path goes outside the
    # current directory tree, we should reject it
    if '..' in path:
        # Ensure resolved path doesn't escape to parent directories
        # by checking if the resolved path starts with the current working dir
        # or is an absolute path that was intended
        cwd = os.path.abspath(os.getcwd())
        if not normalized.startswith(cwd) and not os.path.isabs(path):
            return None
    
    # If base directories specified, ensure path is within one of them
    if base_allowed:
        in_allowed = any(normalized.startswith(os.path.normpath(base)) for base in base_allowed)
        if not in_allowed:
            return None
    
    return normalized


def validate_address(addr_str: str) -> Optional[int]:
    """Validate and parse an address string, checking for integer overflow.
    
    Args:
        addr_str: Address as hex string, decimal string, or name
        
    Returns:
        Integer address if valid, None if invalid
    """
    if not addr_str:
        return None
    
    try:
        # Try hex format
        if addr_str.lower().startswith('0x'):
            val = int(addr_str, 16)
        elif addr_str.isdigit():
            val = int(addr_str)
        else:
            # Could be a symbol name - let IDA resolve it
            return 0  # Special marker for "needs IDA resolution"
        
        # Check for 64-bit overflow
        if val < 0 or val > 0xFFFFFFFFFFFFFFFF:
            return None
        
        return val
    except (ValueError, OverflowError):
        return None


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

# List of available tools (40 total - includes session)
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

WHEN TO USE: Prefer this over raw IDAPython when you need:
- Hex-Rays decompilation with automatic error handling
- Clean xref enumeration (no manual iterator management)
- Callgraph traversal with depth limits (prevents infinite loops)

Actions:
- decompile: Get Hex-Rays pseudocode for function(s)
- disasm: Get assembly listing with comments
- xrefs_to: Find all references TO an address (callers, data refs)
- xrefs_from: Find all references FROM an address (callees)
- xrefs_to_field: Find references to a struct field (format: "struct.field")
- callees: Get functions called by target function
- callers: Get functions that call target function  
- blocks: Get basic blocks in function
- analyze: Comprehensive analysis (decompile + xrefs + strings)
- callgraph: Generate function call graph (use max_depth to limit)
- find_paths: Find call paths between two functions
- strings_in_func: Get string references in function

Required: idb, action.
Optional: addrs/addr (hex like "0x401000", decimal, or symbol name), max_depth (default 5), max_items (default 1000).

RESPONSE FORMAT:
- Lists return array of dicts with 'addr', 'name', etc.
- Addresses are hex strings like "0x401000"
- Errors include 'error' key with message""",

    "data": """List and query binary data structures.

WHEN TO USE: Prefer this over raw IDAPython when you need:
- Paginated results that fit in context window
- Filtered results without writing filter code
- Consistent JSON output format

Actions:
- functions: List all functions with addr/name/size
- globals: List global variables
- strings: List all strings with addresses
- imports: List imported functions (by DLL)
- exports: List exported symbols

Required: idb, action.
Optional: query (filter pattern with * wildcards), offset (pagination start), count (items per page, default 100).

RESPONSE FORMAT:
- Returns dict with action name as key (e.g., {"functions": [...]})
- Each item has 'addr' (hex string), 'name', 'size'
- Paginated responses include 'total' count""",

    "search": """Search for patterns, bytes, and references in the binary.

WHEN TO USE: Prefer this over raw IDAPython when you need:
- Byte pattern search with wildcards (like "48 83 EC ?? 48 8B")
- Cross-reference searches without iterator boilerplate
- String literal searches across the binary

Actions:
- bytes: Search hex byte pattern (use ?? for wildcards)
- string: Search for text literals
- immediate: Find numeric constant values
- name: Search symbol names (supports * wildcards)
- pattern: IDA-style pattern search
- data_ref: Find data references to address
- code_ref: Find code references to address

Required: idb, action.
Optional: query/pattern (search term), start/end (address range to search).

BYTE PATTERN FORMAT: "48 83 EC ?? 48 8B" - use ?? for single-byte wildcards""",

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

WARNING: The 'python' action executes arbitrary code. Use only when no other tool suffices.

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

    "agent": """High-level analysis helpers designed for LLM workflows.

WHEN TO USE: Prefer this for first-pass analysis or comprehensive exploration.
This tool combines multiple operations into context-efficient responses.
Ideal for: "Tell me everything about function X" or "What's interesting in this binary?"

Actions:
- analyze_function: Get full analysis (decompile + xrefs + strings + comments)
- explore_address: Get context around an address (surrounding code, data refs)
- find_references: Trace reference chains (who calls this? what does it call?)
- search_all: Universal search across names, strings, and bytes in one call

EXAMPLES:
  # Comprehensive function analysis - best for first look at a function
  agent(idb="sample.i64", action="analyze_function", addr="0x401234")
  # Returns: {decompiled_code, callers, callees, strings_used, comments, signature}

  # Quick context around an unknown address
  agent(idb="sample.i64", action="explore_address", addr="0x405000")
  # Returns: {type (code/data/unknown), surrounding_bytes, xrefs_in, xrefs_out}

  # Universal search - searches names, strings, and bytes at once
  agent(idb="sample.i64", action="search_all", query="password")
  # Returns: {name_matches, string_matches, comment_matches}

Required: idb, action.
Optional: addr (target address), query (search term), depth (for reference tracing, default 3).

RESPONSE FORMAT: Returns comprehensive dict with multiple analysis sections.
Responses are optimized for LLM context windows.""",

    "microcode": """Access Hex-Rays microcode intermediate representation.
Actions: get (get microcode overview), blocks (get micro-blocks), instructions (get micro-instructions).
Required: idb, action, addr (function address). Optional: maturity (optimization level 0-7).""",

    "graph": """Export control flow and call graphs.
Actions: callgraph (generate function call graph), cfg (generate function CFG).
Required: idb, action, addr. Optional: depth, direction (down/up/both), format (json/dot).""",

    "bulk": """Bulk operations for batch modifications.

WHEN TO USE: Prefer this when making multiple similar changes instead of calling
modify() repeatedly. Saves context tokens and provides partial failure handling.

Actions: rename (batch rename from list), comment (batch add comments), set_type (batch set types), import_json (import annotations from file), export_json (export annotations).

EXAMPLES:
  # Batch rename multiple functions at once
  bulk(idb="sample.i64", action="rename", items=[
    {"addr": "0x401000", "value": "init_config"},
    {"addr": "0x401100", "value": "parse_data"},
    {"addr": "0x401200", "value": "cleanup"}
  ])

Required: idb, action. For rename/comment/set_type: items (list of {addr, value} dicts). For import/export: path.

RESPONSE FORMAT: Returns {success: [...], failed: [...]} with partial success support.""",

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

# Minimal per-action required parameter hints used for validation and LLM-facing docs
ACTION_REQUIRED_PARAMS = {
    "session": {
        "discover": ["binary_path"],
        "create": ["binary_path"],
        "switch": ["session_id"],
        "close": ["session_id"],
    },
    "code": {
        "decompile": ["addrs"],
        "disasm": ["addrs"],
        "xrefs_to": ["addrs"],
        "xrefs_from": ["addrs"],
        "xrefs_to_field": ["addrs", "field_name"],
        "callees": ["addrs"],
        "callers": ["addrs"],
        "blocks": ["addrs"],
        "analyze": ["addrs"],
        "callgraph": ["addrs"],
        "find_paths": ["addr", "target"],
        "strings_in_func": ["addrs"],
    },
    "data": {},
    "search": {
        "bytes": ["pattern"],
        "string": ["query"],
        "immediate": ["query"],
        "name": ["query"],
        "pattern": ["pattern"],
        "data_ref": ["addr"],
        "code_ref": ["addr"],
    },
    "types": {
        "get": ["name"],
        "define": ["decl"],
        "get_members": ["name"],
        "apply": ["addr", "name"],
        "search_structs": ["query"],
    },
    "memory": {"read": ["addr", "size"], "write": ["addr", "data"]},
    "modify": {
        "rename": ["addr", "name"],
        "comment": ["addr", "text"],
        "set_type": ["addr", "type_str"],
        "patch": ["addr", "data"],
    },
    "misc": {"python": ["code"], "idc": ["code"], "load_sig": ["path"], "bookmarks": []},
    "debug": {
        "start": ["path"],
        "run_to": ["addr"],
        "add_bp": ["addr"],
        "del_bp": ["addr"],
        "enable_bp": ["addr"],
        "set_reg": ["reg", "value"],
        "read_mem": ["addr", "size"],
        "write_mem": ["addr", "data"],
    },
    "funcs": {
        "create": ["addr"],
        "delete": ["addr"],
        "set_flags": ["addr"],
        "set_name": ["addr", "name"],
        "add_comment": ["addr", "comment"],
    },
    "segments": {"add": ["start", "end", "name"], "delete": ["name"], "set_attr": ["name", "attr", "value"]},
    "files": {"open": ["path"], "batch": ["paths"], "export": ["path"]},
    "plugins": {"run": ["name"]},
    "trace": {},
    "fixups": {"get": ["addr"], "add": ["addr", "target", "fixup_type"], "delete": ["addr"]},
    "data_ops": {
        "make_data": ["addr"],
        "make_array": ["addr", "count"],
        "make_string": ["addr"],
        "undefine": ["addr"],
        "make_code": ["addr"],
    },
    "agent": {
        "analyze_function": ["addr"],
        "explore_address": ["addr"],
        "find_references": ["addr"],
        "search_all": ["query"],
    },
    "microcode": {"get": ["addr"], "blocks": ["addr"], "instructions": ["addr"]},
    "graph": {"callgraph": ["addr"], "cfg": ["addr"]},
    "bulk": {
        "rename": ["items"],
        "comment": ["items"],
        "set_type": ["items"],
        "import_json": ["path"],
        "export_json": ["path"],
    },
    "ctree": {
        "get": ["addr"],
        "traverse": ["addr"],
        "find_calls": ["addr"],
        "find_vars": ["addr"],
        "find_strings": ["addr"],
        "find_conditions": ["addr"],
    },
    "diff": {"functions": ["addr1", "addr2"], "bytes": ["addr1", "addr2"], "signatures": ["addr1"]},
    "lumina": {"pull": ["addr"], "push": ["addr"], "history": ["addr"], "search": ["query"]},
    "symbols": {"apply": ["addr", "name"], "export": ["path"]},
    "patterns": {"generate": ["addr"], "match": ["pattern"], "apply_sig": ["name"], "create_sig": ["addr"]},
    "structs": {"recover": ["addr"], "analyze_usage": ["addr"], "create": ["decl"], "apply": ["addr", "name"]},
    "strings_xref": {"analyze": ["addr"], "xref_chain": ["addr"]},
    "entropy": {"region": ["addr", "size"], "compare": ["addr", "target"]},
    "imports_deep": {"resolve": ["addr"]},
    "comments_ai": {"get_context": ["addr"], "set_structured": ["addr", "text"], "bulk_set": ["items"], "export_md": ["path"], "import_md": ["path"]},
    "nav": {"add_bookmark": ["addr"], "del_bookmark": ["addr"], "goto": ["addr"]},
    "colorize": {"set_func": ["addr", "color"], "set_range": ["addr", "end_addr", "color"], "set_insn": ["addr", "color"], "get": ["addr"], "clear": ["addr"], "highlight_pattern": ["pattern"]},
    "emulate": {"snippet": ["addr"], "appcall": ["addr"], "trace": ["addr"], "eval_expr": ["addr"]},
    "export": {"listing": ["path"], "html": ["path"], "idc": ["path"], "json": ["path"], "binexport": ["path"], "headers": ["path"]},
    "history": {"snapshot": ["name"], "restore": ["name"]},
    "hooks": {"suggest": ["category"], "generate_frida": ["addr"], "generate_detours": ["addr"], "inline_hooks": ["addr"]},
    "taint": {"trace_arg": ["addr", "arg_num"], "trace_return": ["addr"], "find_sinks": ["addr"], "data_flow": ["addr"], "slice": ["addr"]},
    "coverage": {"import_drcov": ["path"], "import_lighthouse": ["path"], "highlight": ["path"], "report": ["addr"]},
}

PLACEHOLDER_VALUES = {
    "idb": "sample.i64",
    "binary_path": "/path/to/binary.exe",
    "session_id": "SESSION1234",
    "addr": "0x401000",
    "addr1": "0x401000",
    "addr2": "0x402000",
    "addrs": ["0x401000"],
    "target": "0x402000",
    "pattern": "48 8B ??",
    "query": "*main*",
    "path": "/tmp/output.json",
    "paths": ["/tmp/a.bin", "/tmp/b.bin"],
    "items": [{"addr": "0x401000", "value": "new_name"}],
    "name": "symbol_name",
    "decl": "int foo(int a);",
    "text": "comment",
    "comment": "comment",
    "data": "90 90",
    "size": 16,
    "count": 1,
    "arg_num": 0,
    "color": "0x66ff66",
    "category": "network",
    "field_name": "struct.field",
    "fixup_type": "off32",
    "start": "0x400000",
    "end": "0x401000",
    "end_addr": "0x401000",
}

COMMON_PROPERTIES = {
    "binary_path": {"type": "string", "description": "Path to binary to analyze or discover sessions for."},
    "session_id": {"type": "string", "description": "Session identifier returned by the session tool."},
    "idb": {"type": "string", "description": "Path to IDB or input binary. Optional when a session is active."},
    "action": {"type": "string", "description": "Action to perform within the tool."},
    "addr": {"type": "string", "description": "Single address (hex string like 0x401000 or symbol name)."},
    "addrs": {
        "oneOf": [
            {"type": "string", "description": "Single address."},
            {"type": "array", "items": {"type": "string"}, "description": "List of addresses."},
        ]
    },
    "target": {"type": "string", "description": "Secondary address/target for path searches or comparisons."},
    "addr1": {"type": "string", "description": "First address for diff/compare actions."},
    "addr2": {"type": "string", "description": "Second address for diff/compare actions."},
    "start": {"type": "string", "description": "Start address for segment or range operations."},
    "end": {"type": "string", "description": "End address for segment or range operations."},
    "end_addr": {"type": "string", "description": "End address for color/range operations."},
    "path": {"type": "string", "description": "File path used by export/import actions."},
    "paths": {"type": "array", "items": {"type": "string"}, "description": "List of file paths (batch/open/import)."},
    "items": {"type": "array", "items": {"type": "object"}, "description": "Batch payload (e.g., rename/comment lists)."},
    "pattern": {"type": "string", "description": "Byte or search pattern (supports ?? wildcards for bytes)."},
    "query": {"type": "string", "description": "Search/filter text (supports * wildcards in many actions)."},
    "name": {"type": "string", "description": "Symbol/type/struct name depending on action."},
    "decl": {"type": "string", "description": "C declaration or definition text."},
    "text": {"type": "string", "description": "Comment or structured text payload."},
    "data": {"type": "string", "description": "Hex-encoded bytes for write/patch operations."},
    "size": {"type": "integer", "description": "Size in bytes (reads, entropy regions, etc.)."},
    "count": {"type": "integer", "description": "Pagination count or item count depending on action."},
    "offset": {"type": "integer", "description": "Pagination offset or starting index."},
    "field_name": {"type": "string", "description": "Struct field name (e.g., MyStruct.field) for xrefs_to_field."},
    "fixup_type": {"type": "string", "description": "Fixup/relocation type when creating fixups."},
    "color": {"type": "string", "description": "RGB color (hex) for colorize actions."},
    "category": {"type": "string", "description": "Category hint (network/file/crypto/registry/process) for hooks."},
    "arg_num": {"type": "integer", "description": "Argument index for taint/trace_arg actions."},
    "reg": {"type": "string", "description": "Register name for debugger register actions."},
    "value": {"type": ["string", "integer"], "description": "Value used for register or attribute setters."},
}

SCHEMA_PROPERTY_KEYS = {
    "idb",
    "action",
    "binary_path",
    "session_id",
    "addr",
    "addrs",
    "addr1",
    "addr2",
    "target",
    "start",
    "end",
    "end_addr",
    "path",
    "paths",
    "items",
    "pattern",
    "query",
    "name",
    "decl",
    "text",
    "data",
    "size",
    "count",
    "offset",
    "field_name",
    "fixup_type",
    "color",
    "category",
    "arg_num",
    "reg",
    "value",
}

MAX_EXAMPLES_PER_TOOL = 2


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

        # Active server process management
        self.server_process = None
        self.server_port = 0
        self.server_sock = None

        # Ensure cleanup of child processes
        import atexit
        atexit.register(self._cleanup_server)
    
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

    def _get_free_port(self):
        """Get a free ephemeral port."""
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def _start_server(self, target_path: str):
        """Start the persistent IDA server."""
        if self.server_process:
            if self.server_process.poll() is None:
                return  # Already running
            self._cleanup_server()

        self.server_port = self._get_free_port()
        server_script = os.path.join(os.path.dirname(self.api_path), "server_script.py")

        if not os.path.exists(server_script):
            # Fallback to local
            server_script = os.path.join(self.script_dir, "src", "ida_pro_mcp", "server_script.py")

        env = os.environ.copy()
        if self.ida_dir:
            env["IDADIR"] = self.ida_dir
            path_entries = env.get("PATH", "").split(os.pathsep)
            if self.ida_dir not in path_entries:
                env["PATH"] = self.ida_dir + os.pathsep + env.get("PATH", "")

        env["IDA_MCP_PORT"] = str(self.server_port)
        # Ensure server waits for analysis
        env["IDA_WAIT_ANALYSIS"] = "1"

        cmd = [self.idat_exe, "-A", f"-S{server_script}", target_path]

        # Start process detached but tracked
        if sys.platform == "win32":
            self.server_process = subprocess.Popen(
                cmd,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                stdout=subprocess.DEVNULL, # Suppress noisy IDA output
                stderr=subprocess.DEVNULL,
                env=env
            )
        else:
            self.server_process = subprocess.Popen(
                cmd,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env
            )

        # Wait for port to be ready
        import socket
        start = time.time()
        while time.time() - start < 30: # Wait up to 30s for IDA to load
            if self.server_process.poll() is not None:
                raise RuntimeError(f"IDA process died immediately (code {self.server_process.returncode})")

            try:
                s = socket.create_connection(("127.0.0.1", self.server_port), timeout=0.1)
                s.close()
                return # Ready
            except (ConnectionRefusedError, OSError):
                time.sleep(0.5)

        raise RuntimeError("Timed out waiting for IDA server to start")

    def _cleanup_server(self):
        """Kill the server process."""
        if self.server_process:
            # Try graceful shutdown via RPC first
            try:
                self._send_rpc({"type": "shutdown"})
            except:
                pass

            if self.server_process.poll() is None:
                try:
                    self.server_process.terminate()
                    try:
                        self.server_process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.server_process.kill()
                except:
                    pass
            self.server_process = None

    def _send_rpc(self, request: dict) -> dict:
        """Send JSON request to IDA server via TCP."""
        import socket
        import struct

        if not self.server_process or self.server_process.poll() is not None:
            raise RuntimeError("IDA server is not running")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("127.0.0.1", self.server_port))

            # Send length-prefixed JSON
            data = json.dumps(request).encode("utf-8")
            s.sendall(len(data).to_bytes(4, 'big') + data)

            # Read response length
            len_bytes = b""
            while len(len_bytes) < 4:
                chunk = s.recv(4 - len(len_bytes))
                if not chunk: raise EOFError("Connection closed")
                len_bytes += chunk

            resp_len = int.from_bytes(len_bytes, 'big')

            # Read response body
            resp_data = b""
            while len(resp_data) < resp_len:
                chunk = s.recv(min(4096, resp_len - len(resp_data)))
                if not chunk: raise EOFError("Connection closed")
                resp_data += chunk

            return json.loads(resp_data.decode("utf-8"))

        finally:
            s.close()
    
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
        """Execute a tool from api_consolidated.py via RPC.
        
        Args:
            tool_name: Name of the tool function to call
            idb_path: Path to IDB file or binary
            **kwargs: Arguments to pass to the tool
            
        Returns:
            Result dict from tool, or structured error dict
        """
        start_time = time.time()
        
        # Input validation: validate idb_path against path traversal
        validated_path = validate_path(idb_path)
        if validated_path is None:
            return make_error(MCPError.PATH_TRAVERSAL, f"Invalid path: {idb_path}")
        
        # Find or create IDB
        target = validated_path
        if not validated_path.endswith(('.i64', '.idb')):
            existing = self._check_idb_exists(validated_path)
            if existing:
                target = existing
        
        if not os.path.exists(target):
            return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {target}")
        
        if not self.idat_exe:
            return make_error(MCPError.IDA_NOT_FOUND, "idat.exe not found. Set IDADIR environment variable.")
        
        # Validate address parameters if present
        for addr_param in ['addr', 'addrs', 'start', 'end', 'target']:
            if addr_param in kwargs:
                addr_val = kwargs[addr_param]
                if isinstance(addr_val, str):
                    validated = validate_address(addr_val)
                    if validated is None:
                        return make_error(MCPError.INTEGER_OVERFLOW, f"Invalid address in {addr_param}: {addr_val}")
                elif isinstance(addr_val, list):
                    for a in addr_val:
                        if isinstance(a, str):
                            validated = validate_address(a)
                            if validated is None:
                                return make_error(MCPError.INTEGER_OVERFLOW, f"Invalid address: {a}")
        
        # Ensure server is running
        try:
            if not self.server_process or self.server_process.poll() is not None:
                self._start_server(target)
        except Exception as e:
            return make_error(MCPError.IDA_CRASHED, f"Failed to start IDA server: {e}")
            
        # Send RPC
        try:
            result = self._send_rpc({
                "tool": tool_name,
                "args": kwargs
            })
            
            result["_execution_time"] = round(time.time() - start_time, 2)
            result["_session"] = self.current_session.session_id if self.current_session else None
            return result
            
        except Exception as e:
            return make_error(MCPError.IDA_CRASHED, f"RPC failed: {e}")
    
    def get_tools_list(self) -> list:
        """Return list of available tools in MCP format with action enums."""
        # Define valid actions for each tool (Issue #31 - Missing enum for actions)
        TOOL_ACTIONS = {
            "session": ["discover", "create", "list", "switch", "close"],
            "idb": ["meta", "segments", "cursor", "entrypoints"],
            "code": ["decompile", "disasm", "xrefs_to", "xrefs_from", "xrefs_to_field", "callees", "callers", "blocks", "analyze", "callgraph", "find_paths", "strings_in_func"],
            "data": ["functions", "globals", "strings", "imports", "exports"],
            "search": ["bytes", "string", "immediate", "name", "pattern", "data_ref", "code_ref"],
            "types": ["list", "get", "define", "get_members", "apply", "search_structs"],
            "memory": ["read", "write"],
            "modify": ["rename", "comment", "set_type", "patch"],
            "misc": ["python", "idc", "load_sig", "bookmarks"],
            "debug": ["start", "stop", "continue", "step", "step_into", "step_over", "run_to", "get_regs", "set_reg", "read_mem", "write_mem", "add_bp", "del_bp", "list_bp", "enable_bp", "threads"],
            "funcs": ["create", "delete", "set_flags", "set_name", "add_comment"],
            "segments": ["list", "add", "delete", "set_attr"],
            "files": ["save", "close", "open", "batch", "export"],
            "plugins": ["list", "run"],
            "trace": ["get", "clear", "set_options"],
            "fixups": ["list", "get", "add", "delete"],
            "data_ops": ["make_data", "make_array", "make_string", "undefine", "make_code"],
            "agent": ["analyze_function", "explore_address", "find_references", "search_all"],
            "microcode": ["get", "blocks", "instructions"],
            "graph": ["callgraph", "cfg"],
            "bulk": ["rename", "comment", "set_type", "import_json", "export_json"],
            "ctree": ["get", "traverse", "find_calls", "find_vars", "find_strings", "find_conditions"],
            "diff": ["functions", "bytes", "signatures", "names", "summary"],
            "lumina": ["pull", "push", "status", "history", "search"],
            "symbols": ["load_pdb", "load_dwarf", "status", "apply", "export"],
            "patterns": ["generate", "match", "list_sigs", "apply_sig", "create_sig"],
            "structs": ["recover", "analyze_usage", "list", "create", "apply"],
            "strings_xref": ["analyze", "xref_chain", "detect_encoded", "find_format", "clusters"],
            "entropy": ["section", "region", "packed_detect", "crypto_detect", "compare"],
            "imports_deep": ["thunks", "delay", "forwarded", "ordinal", "api_sets", "resolve"],
            "comments_ai": ["get_context", "set_structured", "bulk_set", "export_md", "import_md", "summary"],
            "nav": ["bookmarks", "add_bookmark", "del_bookmark", "goto", "history", "cursor", "interesting"],
            "colorize": ["set_func", "set_range", "set_insn", "get", "clear", "palette", "highlight_pattern"],
            "emulate": ["snippet", "appcall", "trace", "decrypt_strings", "eval_expr"],
            "export": ["listing", "html", "idc", "json", "binexport", "headers"],
            "history": ["undo", "redo", "list", "snapshot", "restore", "diff"],
            "trace_analysis": ["import_trace", "analyze_coverage", "find_loops", "extract_api_calls", "basic_blocks_hit"],
            "hooks": ["suggest", "generate_frida", "generate_detours", "find_targets", "inline_hooks"],
            "taint": ["trace_arg", "trace_return", "find_sinks", "data_flow", "slice"],
            "coverage": ["import_drcov", "import_lighthouse", "highlight", "report", "uncovered"],
        }

        def build_action_hint(tool: str) -> str:
            actions = TOOL_ACTIONS.get(tool, [])
            required = ACTION_REQUIRED_PARAMS.get(tool, {})
            hints = []
            for action in actions:
                reqs = required.get(action, [])
                if reqs:
                    hints.append(f"{action} (requires: {', '.join(reqs)})")
                else:
                    hints.append(f"{action} (no extra params)")
            return "; ".join(hints)

        def build_examples(tool: str) -> list:
            examples = []
            actions = TOOL_ACTIONS.get(tool, [])
            required = ACTION_REQUIRED_PARAMS.get(tool, {})
            for action in actions[:MAX_EXAMPLES_PER_TOOL]:
                example = {"action": action}
                if tool != "session":
                    example["idb"] = PLACEHOLDER_VALUES["idb"]
                for param in required.get(action, []):
                    example[param] = PLACEHOLDER_VALUES.get(param, f"<{param}>")
                examples.append(example)
            return examples

        tools = []
        for tool_name in TOOLS:
            schema = {
                "type": "object",
                "properties": {
                    key: value
                    for key, value in COMMON_PROPERTIES.items()
                    if key in SCHEMA_PROPERTY_KEYS
                },
                "required": ["action"] if tool_name == "session" else ["idb", "action"],
            }

            # Add per-action hints to the action description
            action_hint = build_action_hint(tool_name)
            if action_hint and "action" in schema["properties"]:
                base_desc = schema["properties"]["action"].get("description", "Action to perform within this tool")
                schema["properties"]["action"]["description"] = f"{base_desc} Supported: {action_hint}"
            
            # Add enum for valid actions if available
            if tool_name in TOOL_ACTIONS:
                schema["properties"]["action"]["enum"] = TOOL_ACTIONS[tool_name]

            # Provide lightweight examples so LLMs see the expected shape quickly
            examples = build_examples(tool_name)
            if examples:
                schema["examples"] = examples
            
            tools.append({
                "name": tool_name,
                "description": TOOL_DESCRIPTIONS.get(tool_name, f"IDA Pro {tool_name} tool"),
                "inputSchema": schema
            })
        return tools
    
    def handle_request(self, request: dict) -> dict:
        """Handle a single MCP request."""
        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})

        def wrap_result(payload: dict | list | str) -> dict:
            structured = payload if isinstance(payload, dict) else {"result": payload}
            if isinstance(payload, dict):
                is_error = bool(payload.get("error") or payload.get("code") or payload.get("isError"))
            else:
                is_error = False
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(payload, indent=2, default=str),
                        }
                    ],
                    "structuredContent": structured,
                    "isError": is_error,
                },
            }
        
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
                if not action:
                    return wrap_result(make_error(MCPError.INVALID_ARGS, "action is required for session tool"))
                required_params = ACTION_REQUIRED_PARAMS.get("session", {}).get(action, [])
                # Explicit empty strings are treated as missing to encourage concrete values from LLMs.
                # Empty collections are allowed because some actions legitimately accept empty lists.
                missing = [p for p in required_params if arguments.get(p) in (None, "")]
                if missing:
                    return wrap_result(
                        make_error(
                            MCPError.INVALID_ARGS,
                            f"Missing required parameters for session.{action}: {', '.join(missing)}",
                        )
                    )
                result = self.handle_session_tool(action, arguments)
            else:
                action = arguments.get("action", "")
                if not action:
                    return wrap_result(make_error(MCPError.INVALID_ARGS, "action is required"))

                required_params = ACTION_REQUIRED_PARAMS.get(tool_name, {}).get(action, [])
                # Explicit empty strings are treated as missing to encourage concrete values from LLMs.
                # Empty collections are allowed because some actions legitimately accept empty lists.
                missing = [p for p in required_params if arguments.get(p) in (None, "")]
                if missing:
                    return wrap_result(
                        make_error(
                            MCPError.INVALID_ARGS,
                            f"Missing required parameters for {tool_name}.{action}: {', '.join(missing)}",
                        )
                    )

                # Get IDB path - from args, current session, or error
                idb_path = arguments.pop("idb", None)
                
                if not idb_path:
                    if self.current_session:
                        idb_path = self.current_session.idb_path
                    else:
                        return wrap_result(
                            make_error(
                                MCPError.SESSION_REQUIRED,
                                "No IDB specified and no active session. Use 'session' tool to create one, or specify 'idb' parameter.",
                            )
                        )
                
                # Execute tool
                result = self.call_tool(tool_name, idb_path, **arguments)
            
            return wrap_result(result)
        
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
