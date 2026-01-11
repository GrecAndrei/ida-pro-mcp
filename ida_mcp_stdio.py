#!/usr/bin/env python3
"""
IDA Pro MCP Server - Synchronous Robust Edition
"""

import json
import sys
import os

# =============================================================================
# STREAM ISOLATION - Redirect stdout to stderr immediately
# =============================================================================
_real_stdout = sys.stdout
sys.stdout = sys.stderr

import io
import threading
import subprocess
import time
import warnings
import glob
import uuid
from typing import Any, Dict, Optional, List, Union
from pathlib import Path
from datetime import datetime

# Robust Path Setup
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "src"))

# Debug Logging for Bridge
CACHE_DIR = os.path.join(SCRIPT_DIR, "ida_mcp_cache")
os.makedirs(CACHE_DIR, exist_ok=True)
BRIDGE_LOG = os.path.join(CACHE_DIR, "bridge.log")

def log_rpc(msg):
    try:
        with open(BRIDGE_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except: pass

# Import truncation middleware
try:
    from ida_pro_mcp.ida_mcp.truncation import truncate_response
except ImportError:
    def truncate_response(resp, **kwargs): return resp

# Suppress ALL warnings
warnings.filterwarnings("ignore")

# =============================================================================
# CONSTANTS & ERRORS
# =============================================================================

class MCPError:
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    FILE_LOCKED = "FILE_LOCKED"
    IDA_TIMEOUT = "IDA_TIMEOUT"
    IDA_CRASHED = "IDA_CRASHED"
    SESSION_REQUIRED = "SESSION_REQUIRED"
    INVALID_ARGS = "INVALID_ARGS"

def make_error(code: str, message: str, recoverable: bool = False, details: dict = None) -> dict:
    res = {"error": True, "code": code, "message": message, "recoverable": recoverable}
    if details: res["details"] = details
    return res

def validate_path(path: str) -> Optional[str]:
    if not path or '\x00' in path: return None
    return os.path.normpath(os.path.abspath(path))

# =============================================================================
# SESSION MANAGEMENT
# =============================================================================

class Session:
    def __init__(self, session_id: str, idb_path: str, binary_path: str):
        self.session_id = session_id
        self.idb_path = idb_path
        self.binary_path = binary_path
        self.created_at = datetime.now()
    def to_dict(self) -> dict:
        return {"session_id": self.session_id, "idb_path": self.idb_path, "binary_path": self.binary_path}

class SessionManager:
    def __init__(self, cache_dir: str):
        self.sessions: Dict[str, Session] = {}
        self.session_dir = os.path.join(cache_dir, "sessions")
        os.makedirs(self.session_dir, exist_ok=True)
    def create_session(self, binary_path: str, use_existing: Optional[str] = None) -> Session:
        sid = ''.join(uuid.uuid4().hex[:8].upper())
        # Use SID-specific name to avoid collisions and track metadata easily
        idb_name = f"SID_{sid}_{os.path.basename(binary_path)}.i64"
        idb_path = use_existing or os.path.join(self.session_dir, idb_name)
        session = Session(sid, idb_path, binary_path)
        self.sessions[sid] = session
        return session
    def discover_sessions(self) -> List[Session]:
        sessions = []
        pattern = os.path.join(self.session_dir, "SID_*.i64")
        for path in glob.glob(pattern):
            base = os.path.basename(path)
            if not base.startswith("SID_") or len(base) < 12:
                continue
            sid = base[4:12]
            if sid not in self.sessions:
                self.sessions[sid] = Session(sid, path, "")
            sessions.append(self.sessions[sid])
        return sessions
    def delete_session(self, sid: str) -> bool:
        if sid in self.sessions:
            session = self.sessions.pop(sid)
            # Cleanup actual IDB and all associated SID files (bookmarks, logs, etc.)
            base_pattern = os.path.join(self.session_dir, f"SID_{sid}*")
            for f in glob.glob(base_pattern):
                try: os.remove(f)
                except: pass
            return True
        return False

class BookmarkManager:
    def __init__(self, session_dir: str):
        self.session_dir = session_dir

    def _get_path(self, sid: str) -> str:
        return os.path.join(self.session_dir, f"SID_{sid}_bookmarks.json")

    def load(self, sid: str) -> List[dict]:
        path = self._get_path(sid)
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except: return []
        return []

    def save(self, sid: str, bookmarks: List[dict]):
        path = self._get_path(sid)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(bookmarks, f, indent=2)

    def add(self, sid: str, data: dict) -> dict:
        if not data.get("addr"): return make_error(MCPError.INVALID_ARGS, "addr required")
        bookmarks = self.load(sid)
        max_id = max([b.get("id", 0) for b in bookmarks]) if bookmarks else 0
        
        tags = data.get("tags", [])
        if isinstance(tags, str): tags = [t.strip() for t in tags.split(",") if t.strip()]

        new_bm = {
            "id": max_id + 1,
            "addr": data.get("addr"),
            "name": data.get("name", f"Mark at {data.get('addr')}"),
            "notes": data.get("notes", ""),
            "category": data.get("category", "general"),
            "priority": int(data.get("priority", 3)),
            "tags": tags,
            "timestamp": datetime.now().isoformat(),
        }
        
        for i, bm in enumerate(bookmarks):
            if bm["addr"] == data.get("addr"):
                new_bm["id"] = bm["id"]
                bookmarks[i] = new_bm
                self.save(sid, bookmarks)
                return {"ok": True, "updated": True, "bookmark": new_bm}
        
        bookmarks.append(new_bm)
        self.save(sid, bookmarks)
        return {"ok": True, "bookmark": new_bm}

    def list(self, sid: str, filters: dict) -> dict:
        bookmarks = self.load(sid)
        f_cat = filters.get("category")
        f_tag = filters.get("tag")
        f_pri = filters.get("priority")
        
        filtered = bookmarks
        if f_cat: filtered = [b for b in filtered if b.get("category") == f_cat]
        if f_tag: filtered = [b for b in filtered if f_tag in b.get("tags", [])]
        if f_pri: filtered = [b for b in filtered if b.get("priority", 0) >= int(f_pri)]
        
        return {"ok": True, "bookmarks": filtered, "total": len(bookmarks), "count": len(filtered)}

    def delete(self, sid: str, data: dict) -> dict:
        bid = data.get("id")
        addr = data.get("addr")
        if not bid and not addr: return make_error(MCPError.INVALID_ARGS, "id or addr required")
        
        bookmarks = self.load(sid)
        original_len = len(bookmarks)
        if bid:
            bookmarks = [b for b in bookmarks if b.get("id") != int(bid)]
        else:
            bookmarks = [b for b in bookmarks if b.get("addr") != addr]
            
        if len(bookmarks) < original_len:
            self.save(sid, bookmarks)
            return {"ok": True, "deleted": original_len - len(bookmarks)}
        return make_error(MCPError.FILE_NOT_FOUND, "Bookmark not found")

    def update(self, sid: str, data: dict) -> dict:
        bid = data.get("id")
        if not bid: return make_error(MCPError.INVALID_ARGS, "id required")
        
        bookmarks = self.load(sid)
        for i, bm in enumerate(bookmarks):
            if bm.get("id") == int(bid):
                for key in ["name", "notes", "category", "priority", "tags", "addr"]:
                    if key in data:
                        val = data[key]
                        if key == "tags" and isinstance(val, str):
                            val = [t.strip() for t in val.split(",") if t.strip()]
                        bookmarks[i][key] = val
                self.save(sid, bookmarks)
                return {"ok": True, "bookmark": bookmarks[i]}
        return make_error(MCPError.FILE_NOT_FOUND, "Bookmark not found")

    def clear(self, sid: str) -> dict:
        self.save(sid, [])
        return {"ok": True}

    def find(self, sid: str, query: str) -> dict:
        bookmarks = self.load(sid)
        query = query.lower()
        results = []
        for b in bookmarks:
            if (query in b.get("name", "").lower() or 
                query in b.get("notes", "").lower() or 
                any(query in t.lower() for t in b.get("tags", []))):
                results.append(b)
        return {"ok": True, "results": results, "count": len(results)}

    def export(self, sid: str) -> dict:
        bookmarks = self.load(sid)
        if not bookmarks: return {"ok": True, "report": "No bookmarks found."}
        
        lines = [f"# Forensic Research Report - Session {sid}", ""]
        for b in sorted(bookmarks, key=lambda x: x.get("priority", 3)):
            prio = "⭐" * (6 - b.get("priority", 3))
            lines.append(f"## [{b['id']}] {b['name']} @ {b['addr']} {prio}")
            lines.append(f"- **Category**: {b.get('category', 'general')}")
            if b.get("tags"): lines.append(f"- **Tags**: {', '.join(b['tags'])}")
            lines.append(f"- **Time**: {b.get('timestamp')}")
            lines.append("")
            lines.append(b.get("notes", "No notes provided."))
            lines.append("")
            lines.append("---")
            lines.append("")
            
        return {"ok": True, "report": "\n".join(lines)}

# =============================================================================
# TOOLS REGISTRY
# =============================================================================

TOOLS = [
    # Core session and batch tools (host-side)
    "session", "bookmarks", "batch",
    # Analysis configuration
    "analysis",
    # Unified query/edit hubs (delegating to sub-tools)
    "query", "edit",
    # Primary data access tools
    "idb", "code", "data", "search", "types", "memory",
    # Modification tools
    "modify", "funcs", "segments", "bulk",
    # Utilities
    "misc", "calc", "nav",
    # Debugging and tracing
    "debug", "trace", "coverage", "trace_analysis",
    # Project and file management
    "project",
    # Advanced analysis
    "agent", "microcode", "graph", "ctree", "taint", "emulate", "entropy",
    # Structure and type recovery
    "structs", "strings_xref", "imports_deep", "patterns", "symbols",
    # Differential and comparison
    "diff", "lumina",
    # Export and annotation
    "export", "history", "comments_ai", "colorize", "data_ops", "fixups",
    # Instrumentation
    "hooks",
    # Documentation and YARA
    "wiki", "yara_hunt"
]

TOOL_DESCRIPTIONS = {
    # Core session tools (host-side, no IDA process required)
    "session": "Session management. Actions: discover, create, list, switch, close, status.",
    "bookmarks": "Enhanced session-correlated bookmarking. Actions: add, list, delete, update, clear, find, export.",
    "batch": "Run multiple tool calls in a single request. Arguments: calls[], continue_on_error.",
    
    # Analysis configuration
    "analysis": "Analysis configuration and reanalysis. Actions: get_options, set_options, set_processor, set_loader_options, reanalyze.",
    
    # Unified query/edit hubs
    "query": "Unified read-only query hub. Actions: data, search, strings_xref, imports_deep, symbols, patterns, idb.",
    "edit": "Unified write/edit hub. Actions: modify, funcs, segments, data_ops, fixups, colorize, comments_ai, bulk.",
    
    # Primary data access
    "idb": "Database metadata and segment information. Actions: meta, summary, segments, entrypoints, bookmarks.",
    "code": "Code logic, decompilation, and flow analysis. Actions: decompile, disasm, xrefs_to, xrefs_from, xrefs_to_field, callees, callers, blocks, analyze, callgraph, export, find_paths, strings_in_func.",
    "data": "Function listing, global variables, strings, imports, and exports. Actions: functions, globals, strings, imports, exports, lookup, bulk_query.",
    "search": "Pattern and reference search. Actions: bytes, string, immediate, name, insns, text, operand, comment, data_ref, code_ref.",
    "types": "Type Library (TIL) and prototype management. Actions: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header.",
    "memory": "Direct database memory access. Actions: read, write.",
    
    # Modification tools
    "modify": "Rename, comment, set types, and patch assembly. Actions: rename, comment, set_type, patch_asm.",
    "funcs": "Function boundary management. Actions: create, delete, set_flags, set_name, add_comment, list, info.",
    "segments": "Segment management. Actions: list, add, delete, set_attr, set_perms, move.",
    "bulk": "Bulk rename/comment/type operations. Actions: rename, comment, apply_type, rename_stack, import_annotations, export_annotations.",
    
    # Utilities
    "misc": "Utilities. Actions: python, idc, load_sig. Use python for full IDAPython access.",
    "calc": "Mathematical and address resolution. Actions: eval, offset, convert, resolve, deref, chain, align.",
    "nav": "Navigation and triage. Actions: goto, cursor, interesting.",
    
    # Debugging and tracing
    "debug": "Debugger control and dynamic analysis. Actions: start, stop, continue, step_into, step_over, run_to, run_until, breakpoints, add_bp, del_bp, enable_bp, regs, set_reg, threads, modules, callstack, read_mem, write_mem.",
    "trace": "Execution tracing. Actions: get, clear, set_options.",
    "coverage": "Code coverage import and analysis. Actions: import_drcov, import_lighthouse, highlight, report, uncovered, filter.",
    "trace_analysis": "Execution trace processing. Actions: import_trace, analyze_coverage, find_loops, extract_api_calls, basic_blocks_hit.",
    
    # Project and file management
    "project": "Project I/O and file operations. Actions: save, close, open, load_binary, list_recent, get_cwd, set_cwd, list_dir, exists, read, write, sessions, batch.",
    
    # Advanced analysis
    "agent": "High-level analysis orchestrator. Actions: analyze_function, explore_address, find_references, search_all, search_structs, context_pack.",
    "microcode": "Hex-Rays Microcode (IR) access. Actions: get, blocks, instructions.",
    "graph": "Topological visualization (CFG, callgraph). Actions: callgraph, cfg, xref_graph.",
    "ctree": "Hex-Rays AST (CTree) analysis. Actions: get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow.",
    "taint": "Static data flow and vulnerability analysis. Actions: find_arg_usage, trace_return, find_sinks, data_flow, backward_trace, slice.",
    "emulate": "Static tracing and emulation. Actions: static_trace, appcall, decrypt_strings, eval_expr.",
    "entropy": "Entropy and packing detection. Actions: section, region, packed_detect, crypto_detect, compare, window, summary.",
    
    # Structure and type recovery
    "structs": "Structure recovery and reconstruction. Actions: recover, analyze_usage, list, create, add_member, apply, reconstruct_vtable.",
    "strings_xref": "Deep string analysis. Actions: analyze, xref_chain, detect_encoded, find_format, clusters.",
    "imports_deep": "Advanced import resolution. Actions: thunks, delay, forwarded, ordinal, api_sets, resolve.",
    "patterns": "Signature and pattern matching. Actions: generate, match, list_sigs, apply_sig, create_sig.",
    "symbols": "PDB/DWARF symbol management. Actions: load_pdb, load_dwarf, status, apply, export.",
    
    # Differential and comparison
    "diff": "Binary differential analysis. Actions: functions, bytes, signatures, summary, export_binexport.",
    "lumina": "Lumina server interaction. Actions: pull, push, status, history, search.",
    
    # Export and annotation
    "export": "Database export. Actions: listing, html, idc, json, binexport, headers.",
    "history": "Undo/redo and snapshots. Actions: undo, redo, list, snapshot, restore, diff.",
    "comments_ai": "Structured AI annotation. Actions: get_context, set_structured, bulk_set, export_md, import_md, summary.",
    "colorize": "Visual highlighting. Actions: set_func, set_range, set_insn, get, clear, palette, highlight_pattern.",
    "data_ops": "Data type conversion. Actions: make_data, make_array, make_string, undefine, make_code.",
    "fixups": "Relocation/fixup management. Actions: list, get, add, delete.",
    
    # Instrumentation
    "hooks": "Hook suggestion and script generation. Actions: suggest, generate_frida, generate_detours, find_targets, inline_hooks.",
    
    # Documentation and YARA
    "wiki": "Built-in documentation system. Actions: list_topics, read, search, sections, index.",
    "yara_hunt": "YARA pattern matching. Actions: scan, compile, list_rules."
}

TOOL_ACTIONS = {
    # Core session tools
    "session": ["discover", "create", "list", "switch", "close", "status"],
    "bookmarks": ["add", "list", "delete", "update", "clear", "find", "export"],
    
    # Analysis configuration
    "analysis": ["get_options", "set_options", "set_processor", "set_loader_options", "reanalyze"],
    
    # Unified query/edit hubs
    "query": ["data", "search", "strings_xref", "imports_deep", "symbols", "patterns", "idb"],
    "edit": ["modify", "funcs", "segments", "data_ops", "fixups", "colorize", "comments_ai", "bulk"],
    
    # Primary data access (corrected idb actions to match actual implementation)
    "idb": ["meta", "summary", "segments", "entrypoints", "bookmarks"],
    "code": ["decompile", "disasm", "xrefs_to", "xrefs_from", "xrefs_to_field", "callees", "callers", "blocks", "analyze", "callgraph", "export", "find_paths", "strings_in_func"],
    "data": ["functions", "globals", "strings", "imports", "exports", "lookup", "bulk_query"],
    "search": ["bytes", "string", "immediate", "name", "insns", "text", "operand", "comment", "data_ref", "code_ref"],
    "types": ["list", "get", "set_prototype", "parse_decl", "declare", "apply", "search_structs", "infer", "read_struct", "import_header"],
    "memory": ["read", "write"],
    
    # Modification tools
    "modify": ["rename", "comment", "set_type", "patch_asm"],
    "funcs": ["create", "delete", "set_flags", "set_name", "add_comment", "list", "info"],
    "segments": ["list", "add", "delete", "set_attr", "set_perms", "move"],
    "bulk": ["rename", "comment", "apply_type", "rename_stack", "import_annotations", "export_annotations"],
    
    # Utilities
    "misc": ["python", "idc", "load_sig"],
    "calc": ["eval", "offset", "convert", "resolve", "deref", "chain", "align"],
    "nav": ["goto", "cursor", "interesting"],
    
    # Debugging and tracing
    "debug": ["start", "stop", "continue", "step_into", "step_over", "run_to", "run_until", "breakpoints", "add_bp", "del_bp", "enable_bp", "regs", "set_reg", "threads", "modules", "callstack", "read_mem", "write_mem"],
    "trace": ["get", "clear", "set_options"],
    "coverage": ["import_drcov", "import_lighthouse", "highlight", "report", "uncovered", "filter"],
    "trace_analysis": ["import_trace", "analyze_coverage", "find_loops", "extract_api_calls", "basic_blocks_hit"],
    
    # Project and file management
    "project": ["save", "close", "open", "load_binary", "list_recent", "get_cwd", "set_cwd", "list_dir", "exists", "read", "write", "sessions", "batch"],
    
    # Advanced analysis
    "agent": ["analyze_function", "explore_address", "find_references", "search_all", "search_structs", "context_pack"],
    "microcode": ["get", "blocks", "instructions"],
    "graph": ["callgraph", "cfg", "xref_graph"],
    "ctree": ["get", "traverse", "find_calls", "find_vars", "find_strings", "find_conditions", "get_logic_flow"],
    "taint": ["find_arg_usage", "trace_return", "find_sinks", "data_flow", "backward_trace", "slice"],
    "emulate": ["static_trace", "appcall", "decrypt_strings", "eval_expr"],
    "entropy": ["section", "region", "packed_detect", "crypto_detect", "compare", "window", "summary"],
    
    # Structure and type recovery
    "structs": ["recover", "analyze_usage", "list", "create", "add_member", "apply", "reconstruct_vtable"],
    "strings_xref": ["analyze", "xref_chain", "detect_encoded", "find_format", "clusters"],
    "imports_deep": ["thunks", "delay", "forwarded", "ordinal", "api_sets", "resolve"],
    "patterns": ["generate", "match", "list_sigs", "apply_sig", "create_sig"],
    "symbols": ["load_pdb", "load_dwarf", "status", "apply", "export"],
    
    # Differential and comparison
    "diff": ["functions", "bytes", "signatures", "summary", "export_binexport"],
    "lumina": ["pull", "push", "status", "history", "search"],
    
    # Export and annotation
    "export": ["listing", "html", "idc", "json", "binexport", "headers"],
    "history": ["undo", "redo", "list", "snapshot", "restore", "diff"],
    "comments_ai": ["get_context", "set_structured", "bulk_set", "export_md", "import_md", "summary"],
    "colorize": ["set_func", "set_range", "set_insn", "get", "clear", "palette", "highlight_pattern"],
    "data_ops": ["make_data", "make_array", "make_string", "undefine", "make_code"],
    "fixups": ["list", "get", "add", "delete"],
    
    # Instrumentation
    "hooks": ["suggest", "generate_frida", "generate_detours", "find_targets", "inline_hooks"],
    
    # Documentation and YARA
    "wiki": ["list_topics", "read", "search", "sections", "index"],
    "yara_hunt": ["scan", "compile", "list_rules"]
}

TOOL_ARG_SCHEMAS = {
    "session": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["session"]},
        "binary_path": {"type": "string", "description": "Path to target binary"},
        "use_existing": {"type": "string", "description": "Existing IDB path to reuse"},
        "session_id": {"type": "string", "description": "Session ID for switch/close"},
    },
    "bookmarks": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["bookmarks"]},
        "addr": {"type": "string"},
        "id": {"type": "integer"},
        "name": {"type": "string"},
        "notes": {"type": "string"},
        "category": {"type": "string"},
        "priority": {"type": "integer"},
        "tags": {"type": ["array", "string"], "items": {"type": "string"}},
        "query": {"type": "string"},
    },
    "funcs": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["funcs"]},
        "addr": {"type": "string"},
        "end": {"type": "string"},
        "name": {"type": "string"},
        "flags": {"type": "integer"},
        "comment": {"type": "string"},
        "repeatable": {"type": "boolean"},
        "query": {"type": "string"},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
        "named_only": {"type": "boolean"},
        "include_prototype": {"type": "boolean"},
        "include_stack": {"type": "boolean"},
    },
    "calc": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["calc"]},
        "expr": {"type": "string"},
        "addr": {"type": "string"},
        "target": {"type": "string"},
        "value": {"type": ["string", "integer"]},
        "type": {"type": "string"},
        "size": {"type": "integer"},
        "offsets": {"type": ["array", "string"], "items": {"type": "string"}},
    },
    "search": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["search"]},
        "pattern": {"type": "string"},
        "query": {"type": "string"},
        "limit": {"type": "integer"},
        "offset": {"type": "integer"},
        "start": {"type": "string"},
        "end": {"type": "string"},
    },
    "memory": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["memory"]},
        "addr": {"type": "string"},
        "type": {"type": "string", "enum": ["bytes", "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "f32", "f64", "ptr", "string"]},
        "size": {"type": "integer"},
        "data": {"type": "string"},
    },
    "misc": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["misc"]},
        "expr": {"type": "string"},
        "code": {"type": "string"},
        "name": {"type": "string"},
    },
    "analysis": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["analysis"]},
        "options": {"type": "object"},
        "processor": {"type": "string"},
        "flags": {"type": "integer"},
        "loader": {"type": "string"},
        "value": {"type": "string"},
        "start": {"type": "string"},
        "end": {"type": "string"},
    },
    "data": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["data"]},
        "query": {"type": "string"},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
        "items": {"type": "array", "items": {"type": "object"}},
    },
    "segments": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["segments"]},
        "start": {"type": "string"},
        "end": {"type": "string"},
        "name": {"type": "string"},
        "sclass": {"type": "string"},
        "attr": {"type": "string"},
        "value": {"type": ["string", "integer"]},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
    },
    "agent": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["agent"]},
        "addr": {"type": "string"},
        "query": {"type": "string"},
        "depth": {"type": "integer"},
        "include_pseudocode": {"type": "boolean"},
        "max_items": {"type": "integer"},
        "use_cache": {"type": "boolean"},
    },
    "query": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["query"]},
        "subaction": {"type": "string"},
        "args": {"type": "object"},
    },
    "edit": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["edit"]},
        "subaction": {"type": "string"},
        "args": {"type": "object"},
    },
    "ctree": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["ctree"]},
        "addr": {"type": "string"},
        "query": {"type": "string"},
        "depth": {"type": "integer"},
    },
    "entropy": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["entropy"]},
        "addr": {"type": "string"},
        "size": {"type": "integer"},
        "threshold": {"type": "number"},
        "end_addr": {"type": "string"},
        "window": {"type": "integer"},
        "step": {"type": "integer"},
        "limit": {"type": "integer"},
    },
    "emulate": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["emulate"]},
        "addr": {"type": "string"},
        "func_name": {"type": "string"},
        "args": {"type": "array"},
        "max_steps": {"type": "integer"},
        "follow_calls": {"type": "boolean"},
        "max_depth": {"type": "integer"},
        "include_blocks": {"type": "boolean"},
        "expr": {"type": "string"},
    },
    "taint": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["taint"]},
        "addr": {"type": "string"},
        "arg_num": {"type": "integer"},
        "depth": {"type": "integer"},
        "max_hits": {"type": "integer"},
    },
    "wiki": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["wiki"]},
        "topic": {"type": "string"},
        "query": {"type": "string"},
        "section": {"type": "string"},
        "offset": {"type": "integer"},
        "limit": {"type": "integer"},
        "include_snippets": {"type": "boolean"},
        "context_lines": {"type": "integer"},
    },
    "batch": {
        "calls": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "arguments": {"type": "object"},
                },
                "required": ["name"],
            },
        },
        "continue_on_error": {"type": "boolean"},
    },
}

def build_input_schema(tool_name: str) -> dict:
    props = {}
    required = []
    if tool_name in TOOL_ARG_SCHEMAS:
        props.update(TOOL_ARG_SCHEMAS[tool_name])
    elif tool_name in TOOL_ACTIONS:
        props["action"] = {"type": "string", "enum": TOOL_ACTIONS[tool_name]}
    if tool_name not in ("session", "bookmarks", "wiki", "batch") and "idb" not in props:
        props["idb"] = {"type": "string", "description": "Path to IDB file or binary"}
    if "action" in props:
        required.append("action")
    return {"type": "object", "properties": props, "required": required}

# =============================================================================
# MCP SERVER
# =============================================================================

class IDAMCPServer:
    def __init__(self):
        self.ida_dir = self._detect_ida_dir()
        self.idat_exe = self._find_idat()
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.cache_dir = os.path.join(self.script_dir, "ida_mcp_cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.session_mgr = SessionManager(self.cache_dir)
        self.bookmark_mgr = BookmarkManager(self.session_mgr.session_dir)       
        self.current_session = None
        self.session_runtimes = {}
    
    def _detect_ida_dir(self):
        env_dir = os.environ.get("IDADIR") or os.environ.get("IDA_DIR")
        if env_dir and os.path.exists(env_dir):
            return env_dir
        cands = [r"C:\Program Files\IDA Professional 9.2", r"C:\Program Files\IDA Pro 9.2"]
        for c in cands:
            if os.path.exists(c): return c
        return ""

    def _find_idat(self):
        env_idat = os.environ.get("IDA_MCP_IDAT")
        if env_idat and os.path.exists(env_idat):
            return env_idat
        if not self.ida_dir: return ""
        for name in ["idat64.exe", "idat.exe", "ida64.exe", "ida.exe"]:
            p = os.path.join(self.ida_dir, name)
            if os.path.exists(p): return p
        return ""

    def _get_ida_diagnostics(self, stdout_log=None):
        out_log = stdout_log or os.path.join(self.cache_dir, "ida_stdout.log")
        if os.path.exists(out_log):
            try:
                with open(out_log, "r", encoding="utf-8", errors="ignore") as f:
                    return "".join(f.readlines()[-20:])
            except: pass
        return "No log available."

    def _nuclear_reset(self, idb_path):
        # Only clean up temporary files (.id0, .id1, etc) for THIS specific IDB
        # to avoid nuking other concurrent sessions' data.
        if idb_path:
            base = idb_path.rsplit('.', 1)[0]
            for ext in [".id0", ".id1", ".id2", ".id3", ".id4", ".nam", ".til", ".mcp.lock"]:
                try:
                    p = base + ext
                    if os.path.exists(p): 
                        os.remove(p)
                        log_rpc(f"Cleaned up temp file: {p}")
                except: pass

    def _send_rpc_raw(self, request, port, timeout=5):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", port))
            data = json.dumps(request).encode("utf-8")
            s.sendall(len(data).to_bytes(4, 'big') + data)
            s.settimeout(60)
            lb = b""
            while len(lb) < 4:
                c = s.recv(4 - len(lb))
                if not c: raise EOFError()
                lb += c
            rl = int.from_bytes(lb, 'big')
            rd = b""
            while len(rd) < rl:
                c = s.recv(min(4096, rl - len(rd)))
                if not c: raise EOFError()
                rd += c
            return json.loads(rd.decode("utf-8"))
        finally: s.close()

    def _start_server(self, session):
        self._nuclear_reset(session.idb_path)
        
        # Validate IDA installation
        if not self.idat_exe or not os.path.exists(self.idat_exe):
            return make_error(MCPError.FILE_NOT_FOUND, f"IDA executable not found. Checked: {self.ida_dir}")
        
        # DYNAMIC PORT ASSIGNMENT
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 0))
        server_port = sock.getsockname()[1]
        sock.close()

        log_rpc(f"Assigned dynamic port: {server_port}")
        
        script_path = os.path.join(SCRIPT_DIR, "src", "ida_pro_mcp", "server_script.py")
        
        # Environment for IDA
        env = os.environ.copy()
        env["IDADIR"] = self.ida_dir
        env["IDA_MCP_PORT"] = str(server_port)
        env["IDA_MCP_BYPASS_SYNC"] = "1"
        env["IDA_MCP_SESSION_ID"] = session.session_id
        env["IDA_MCP_CACHE_DIR"] = self.cache_dir
        sid_tag = session.session_id
        log_file = os.path.join(self.cache_dir, f"ida_mcp_{sid_tag}.log")
        stdout_log = os.path.join(self.cache_dir, f"ida_stdout_{sid_tag}.log")
        stderr_log = os.path.join(self.cache_dir, f"ida_stderr_{sid_tag}.log")
        
        # Launch IDA: Open existing IDB if present, otherwise analyze binary
        if os.path.exists(session.idb_path):
            log_rpc(f"Opening existing session IDB: {session.idb_path}")
            cmd = [
                self.idat_exe,
                "-A",
                f"-S{script_path}",
                f"-L{log_file}",
                session.idb_path
            ]
        else:
            log_rpc(f"Creating new IDB for binary: {session.binary_path} -> {session.idb_path}")
            # Ensure session directory exists
            os.makedirs(os.path.dirname(session.idb_path), exist_ok=True)
            cmd = [
                self.idat_exe,
                "-A",
                f"-o{session.idb_path}",
                f"-S{script_path}",
                f"-L{log_file}",
                session.binary_path
            ]
        
        log_rpc(f"Launching IDA: {' '.join(cmd)}")
        
        stdout_fh = open(stdout_log, "a", encoding="utf-8")
        stderr_fh = open(stderr_log, "a", encoding="utf-8")
        server_process = subprocess.Popen(
            cmd,
            stdout=stdout_fh,
            stderr=stderr_fh,
            env=env
        )

        # WAIT FOR STARTUP using ping
        startup_timeout = int(os.environ.get("IDA_MCP_STARTUP_TIMEOUT", "90"))
        start_time = time.time()
        while time.time() - start_time < startup_timeout:
            exit_code = server_process.poll()
            if exit_code is not None:
                diag = self._get_ida_diagnostics(stdout_log)
                return make_error(MCPError.IDA_CRASHED, f"IDA exited with code {exit_code}", details={"log": diag})

            try:
                res = self._send_rpc_raw({"type": "ping"}, server_port, timeout=0.5)
                if res.get("pong"):
                    log_rpc(f"IDA server is READY for {session.idb_path}")
                    runtime = {
                        "process": server_process,
                        "port": server_port,
                        "idb_path": session.idb_path,
                        "stdout_log": stdout_log,
                        "stderr_log": stderr_log,
                        "log_handles": [stdout_fh, stderr_fh],
                    }
                    self.session_runtimes[session.session_id] = runtime
                    return {"ok": True, "idb_path": session.idb_path}
            except:
                pass
            time.sleep(0.5)

        return make_error(MCPError.IDA_TIMEOUT, f"IDA failed to initialize within {startup_timeout}s.")

    def _cleanup_runtime(self, sid):
        runtime = self.session_runtimes.pop(sid, None)
        if not runtime:
            return
        proc = runtime.get("process")
        port = runtime.get("port")
        if proc:
            try:
                self._send_rpc_raw({"type": "shutdown"}, port, timeout=1)
            except:
                pass
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except:
                    proc.kill()
        for fh in runtime.get("log_handles", []):
            try:
                fh.close()
            except:
                pass

    def _cleanup_all_runtimes(self):
        for sid in list(self.session_runtimes.keys()):
            self._cleanup_runtime(sid)

    def call_tool(self, tool_name, idb_path, **kwargs):
        path = validate_path(idb_path)
        if not path:
            return make_error(MCPError.INVALID_ARGS, "Invalid path")

        # Find the session associated with this IDB path
        session = None
        for s in self.session_mgr.sessions.values():
            if os.path.normpath(s.idb_path) == os.path.normpath(path):
                session = s
                break

        if not session:
            # Fallback: check if the path is actually the binary path of the current session
            if self.current_session and os.path.normpath(path) == os.path.normpath(self.current_session.binary_path):
                session = self.current_session
            else:
                return make_error(MCPError.FILE_NOT_FOUND, f"No session found for IDB: {path}")

        runtime = self.session_runtimes.get(session.session_id)
        if not runtime or not runtime.get("process") or runtime["process"].poll() is not None:
            log_rpc(f"Session start/restart needed: {session.session_id} -> {session.idb_path}")
            start_res = self._start_server(session)
            if "error" in start_res:
                return start_res
            runtime = self.session_runtimes.get(session.session_id)

        try:
            res = self._send_rpc_raw({"tool": tool_name, "args": kwargs}, runtime["port"])
            return truncate_response(res)
        except Exception as e:
            proc = runtime.get("process")
            exit_code = proc.poll() if proc else None
            if exit_code is not None:
                return make_error(
                    MCPError.IDA_CRASHED,
                    f"IDA exited with code {exit_code}",
                    details={"log": self._get_ida_diagnostics(runtime.get("stdout_log"))},
                )
            return make_error(MCPError.IDA_CRASHED, str(e))

    def _execute_tool(self, tool_name, args):
        args = dict(args or {})
        if tool_name == "session":
            action = args.get("action")
            if action == "create":
                path = args.get("binary_path")
                if not path or not os.path.exists(path):
                    return make_error(MCPError.FILE_NOT_FOUND, str(path))
                use_existing = args.get("use_existing")
                self.current_session = self.session_mgr.create_session(path, use_existing=use_existing)
                return {"ok": True, "session": self.current_session.to_dict()}
            if action == "discover":
                sessions = [s.to_dict() for s in self.session_mgr.discover_sessions()]
                return {"ok": True, "sessions": sessions}
            if action == "list":
                sessions = [s.to_dict() for s in self.session_mgr.sessions.values()]
                return {"ok": True, "sessions": sessions}
            if action == "switch":
                sid = args.get("session_id")
                if sid in self.session_mgr.sessions:
                    self.current_session = self.session_mgr.sessions[sid]
                    return {"ok": True, "session": self.current_session.to_dict()}
                return make_error(MCPError.INVALID_ARGS, f"Session {sid} not found")
            if action == "close":
                sid = args.get("session_id") or (self.current_session.session_id if self.current_session else None)
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                self._cleanup_runtime(sid)
                closed = self.session_mgr.delete_session(sid)
                if closed and self.current_session and self.current_session.session_id == sid:
                    self.current_session = None
                return {"ok": closed, "session_id": sid}
            if action == "status":
                session = self.current_session.to_dict() if self.current_session else None
                return {"ok": True, "session": session}
            return make_error(MCPError.INVALID_ARGS, f"Unsupported session action: {action}")

        if tool_name == "bookmarks":
            if not self.current_session:
                return make_error(MCPError.SESSION_REQUIRED, "Call session action=create first")
            action = args.get("action")
            sid = self.current_session.session_id
            if action == "add":
                return self.bookmark_mgr.add(sid, args)
            if action == "list":
                return self.bookmark_mgr.list(sid, args)
            if action == "delete":
                return self.bookmark_mgr.delete(sid, args)
            if action == "update":
                return self.bookmark_mgr.update(sid, args)
            if action == "clear":
                return self.bookmark_mgr.clear(sid)
            if action == "find":
                return self.bookmark_mgr.find(sid, args.get("query", ""))
            if action == "export":
                return self.bookmark_mgr.export(sid)
            return make_error(MCPError.INVALID_ARGS, f"Unsupported bookmark action: {action}")

        ip = args.pop("idb", self.current_session.idb_path if self.current_session else None)
        if not ip:
            return make_error(MCPError.SESSION_REQUIRED, "Call session action=create first")
        return self.call_tool(tool_name, ip, **args)

    def _handle_batch(self, args):
        calls = args.get("calls", [])
        if not isinstance(calls, list):
            return make_error(MCPError.INVALID_ARGS, "calls must be a list")
        continue_on_error = bool(args.get("continue_on_error", False))
        results = []
        for idx, call in enumerate(calls):
            name = call.get("name") if isinstance(call, dict) else None
            call_args = call.get("arguments", {}) if isinstance(call, dict) else {}
            if not name:
                res = make_error(MCPError.INVALID_ARGS, "call name required")
            else:
                res = self._execute_tool(name, call_args)
            results.append({"index": idx, "name": name, "result": res})
            if "error" in res and not continue_on_error:
                break
        return {"ok": True, "results": results, "count": len(results)}

    def handle_request(self, req):
        m, rid, p = req.get("method"), req.get("id"), req.get("params", {})
        if m == "initialize": return {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "ida-pro-mcp", "version": "3.0.0"}}}
        if rid is None: return None
        if m == "tools/list":
            tools = [{"name": t, "description": TOOL_DESCRIPTIONS.get(t, ""), "inputSchema": build_input_schema(t)} for t in TOOLS]
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}}
        if m == "tools/call":
            tn, args = p.get("name"), p.get("arguments", {})
            if tn == "batch":
                res = self._handle_batch(args)
            else:
                res = self._execute_tool(tn, args)
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}], "isError": "error" in res}}
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}}

    def run(self):
        if sys.platform == "win32":
            import msvcrt
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            msvcrt.setmode(_real_stdout.fileno(), os.O_BINARY)
        rs, si = _real_stdout.buffer, sys.stdin.buffer
        while True:
            try:
                line = si.readline()
                if not line: break
                line = line.strip()
                if not line: continue
                req = json.loads(line.decode('utf-8'))
                resp = self.handle_request(req)
                if resp:
                    output = (json.dumps(resp) + "\n").encode('utf-8')
                    rs.write(output); rs.flush()
            except: continue

if __name__ == "__main__":
    try: server = IDAMCPServer(); server.run()
    except Exception as e: sys.stderr.write(f"Error: {e}\n"); sys.exit(1)
