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
import re
import fnmatch
import threading
import subprocess
import time
import warnings
import glob
import uuid
import shlex
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
    except:
        pass


# Import truncation middleware
try:
    from ida_pro_mcp.ida_mcp.truncation import truncate_response, continue_truncated
except ImportError:
    try:
        import importlib.util

        _trunc_path = os.path.join(
            SCRIPT_DIR, "src", "ida_pro_mcp", "ida_mcp", "truncation.py"
        )
        _spec = importlib.util.spec_from_file_location("ida_mcp_truncation", _trunc_path)
        if _spec and _spec.loader:
            _module = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(_module)
            truncate_response = _module.truncate_response
            continue_truncated = _module.continue_truncated
        else:
            raise ImportError("Unable to load truncation module")
    except Exception:

        def truncate_response(resp, **kwargs):
            return resp

        def continue_truncated(*_args, **_kwargs):
            return {
                "error": True,
                "code": "NOT_IMPLEMENTED",
                "message": "Truncation middleware unavailable",
            }

# Import smart pattern matching (regex auto-detection)
try:
    from ida_pro_mcp.ida_mcp.utils import _is_regex, smart_match, compile_smart_pattern
except ImportError:
    # Inline fallback for standalone mode
    def _is_regex(pattern):
        if not pattern:
            return False
        if pattern.startswith("/") and pattern.count("/") >= 2:
            return True
        for ind in (r"\d", r"\w", r"\s", r"\b", r"\D", r"\W", r"\S", r"\B"):
            if ind in pattern:
                return True
        if re.search(r"\\[.^$*+?{}()|[\]\\]", pattern):
            return True
        if set("^$+{}()|").intersection(pattern):
            return True
        if re.search(r"\[.+\]", pattern):
            return True
        return False

    def compile_smart_pattern(pattern, case_sensitive=False):
        if not pattern:
            return lambda _t: True
        regex = None
        if pattern.startswith("/") and pattern.count("/") >= 2:
            ls = pattern.rfind("/")
            body, fs = pattern[1:ls], pattern[ls+1:]
            flags = 0
            for c in fs:
                if c == "i": flags |= re.IGNORECASE
                elif c == "m": flags |= re.MULTILINE
                elif c == "s": flags |= re.DOTALL
            try:
                regex = re.compile(body, flags or (0 if case_sensitive else re.IGNORECASE))
            except re.error:
                pass
        elif _is_regex(pattern):
            try:
                regex = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
            except re.error:
                pass
        if regex is not None:
            return lambda _t, _r=regex: bool(_r.search(_t))
        if "*" in pattern or "?" in pattern:
            pl = pattern.lower()
            return lambda _t, _p=pl: fnmatch.fnmatch(_t.lower(), _p)
        if case_sensitive:
            return lambda _t, _p=pattern: _p in _t
        pl = pattern.lower()
        return lambda _t, _p=pl: _p in _t.lower()

    def smart_match(pattern, text, case_sensitive=False):
        return compile_smart_pattern(pattern, case_sensitive)(text)


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


def make_error(
    code: str, message: str, recoverable: bool = False, details: dict = None
) -> dict:
    res = {"error": True, "code": code, "message": message, "recoverable": recoverable}
    if details:
        res["details"] = details
    return res


def validate_path(path: str) -> Optional[str]:
    if not path or "\x00" in path:
        return None
    return os.path.normpath(os.path.abspath(path))


# =============================================================================
# SESSION MANAGEMENT
# =============================================================================


class Session:
    def __init__(
        self,
        session_id: str,
        idb_path: str,
        binary_path: str,
        analysis_options: Optional[dict] = None,
        analysis_applied: bool = False,
        ida_args: Optional[List[str]] = None,
        created_at: Optional[datetime] = None,
        last_accessed: Optional[datetime] = None,
    ):
        self.session_id = session_id
        self.idb_path = idb_path
        self.binary_path = binary_path
        self.analysis_options = analysis_options or {}
        self.analysis_applied = bool(analysis_applied)
        self.ida_args = ida_args or []
        self.created_at = created_at or datetime.now()
        self.last_accessed = last_accessed or datetime.now()

    def update_access(self):
        """Update last accessed timestamp"""
        self.last_accessed = datetime.now()

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "idb_path": self.idb_path,
            "binary_path": self.binary_path,
            "analysis_options": self.analysis_options,
            "analysis_applied": self.analysis_applied,
            "ida_args": self.ida_args,
            "binary_exists": bool(self.binary_path and os.path.exists(self.binary_path)),
            "idb_exists": bool(self.idb_path and os.path.exists(self.idb_path)),
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        """Load session from metadata dict"""
        created = (
            datetime.fromisoformat(data["created_at"]) if "created_at" in data else None
        )
        accessed = (
            datetime.fromisoformat(data["last_accessed"])
            if "last_accessed" in data
            else None
        )
        return cls(
            data["session_id"],
            data["idb_path"],
            data.get("binary_path", ""),
            data.get("analysis_options", {}) or {},
            data.get("analysis_applied", False),
            data.get("ida_args", []) or [],
            created,
            accessed,
        )


class SessionManager:
    def __init__(self, cache_dir: str):
        self.sessions: Dict[str, Session] = {}
        self.cache_dir = cache_dir
        self.session_dir = os.path.join(cache_dir, "sessions")
        os.makedirs(self.session_dir, exist_ok=True)
        # Auto-load existing sessions on startup
        self._load_sessions()

    def _get_metadata_path(self, sid: str) -> str:
        """Get path to session metadata file"""
        return os.path.join(self.session_dir, f"SID_{sid}_metadata.json")

    def _save_metadata(self, session: Session):
        """Persist session metadata to disk"""
        path = self._get_metadata_path(session.session_id)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(session.to_dict(), f, indent=2)
        except Exception as e:
            log_rpc(f"Failed to save session metadata: {e}")

    def _load_sessions(self):
        """Load all existing sessions from metadata files"""
        pattern = os.path.join(self.session_dir, "SID_*_metadata.json")
        for meta_path in glob.glob(pattern):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    session = Session.from_dict(data)
                    # Always load the session - IDB might not exist yet if session is new
                    # We'll let IDA create it on first use
                    self.sessions[session.session_id] = session
                    log_rpc(f"Loaded session {session.session_id} from metadata")
            except Exception as e:
                log_rpc(f"Failed to load session metadata from {meta_path}: {e}")
        self._load_orphaned_idbs()

    def _extract_sid(self, path: str) -> Optional[str]:
        base = os.path.basename(path)
        match = re.match(r"SID_([A-Za-z0-9]{8})", base)
        return match.group(1) if match else None

    def _guess_binary_name(self, sid: str, filename: str) -> str:
        prefix = f"SID_{sid}_"
        if filename.startswith(prefix):
            name = filename[len(prefix) :]
            return os.path.splitext(name)[0]
        return ""

    def _load_orphaned_idbs(self):
        """Recover sessions from IDB files missing metadata."""
        pattern = os.path.join(self.session_dir, "SID_*.*")
        for idb_path in glob.glob(pattern):
            if not idb_path.lower().endswith((".i64", ".idb")):
                continue
            sid = self._extract_sid(idb_path)
            if not sid or sid in self.sessions:
                continue
            binary_guess = self._guess_binary_name(sid, os.path.basename(idb_path))
            session = Session(sid, idb_path, binary_guess or "")
            self.sessions[sid] = session
            self._save_metadata(session)
            log_rpc(f"Recovered orphaned session {sid} from {idb_path}")

    def create_session(
        self,
        binary_path: str,
        use_existing: Optional[str] = None,
        analysis_options: Optional[dict] = None,
        idb_path: Optional[str] = None,
        ida_args: Optional[List[str]] = None,
    ) -> Session:
        sid = "".join(uuid.uuid4().hex[:8].upper())
        # Use SID-specific name to avoid collisions and track metadata easily
        idb_base = os.path.basename(binary_path) if binary_path else f"session_{sid}"
        idb_name = f"SID_{sid}_{idb_base}.i64"
        resolved_idb = idb_path or use_existing or os.path.join(self.session_dir, idb_name)
        if resolved_idb and os.path.isdir(resolved_idb):
            resolved_idb = os.path.join(resolved_idb, idb_name)
        if resolved_idb and not os.path.splitext(resolved_idb)[1]:
            resolved_idb = f"{resolved_idb}.i64"
        session = Session(
            sid,
            resolved_idb,
            binary_path or "",
            analysis_options=analysis_options,
            analysis_applied=False,
            ida_args=ida_args or [],
        )
        self.sessions[sid] = session
        # Persist metadata immediately
        self._save_metadata(session)
        return session

    def get_session(self, sid: str) -> Optional[Session]:
        """Get session and update last_accessed timestamp"""
        session = self.sessions.get(sid)
        if session:
            session.update_access()
            self._save_metadata(session)
        return session

    def find_session_by_path(self, path: str) -> Optional[Session]:
        """Find a session by binary_path or idb_path (normalized comparison)."""
        norm = os.path.normpath(os.path.abspath(path))
        for s in self.sessions.values():
            if s.binary_path and os.path.normpath(os.path.abspath(s.binary_path)) == norm:
                return s
            if s.idb_path and os.path.normpath(os.path.abspath(s.idb_path)) == norm:
                return s
        return None

    def discover_sessions(self, query: str = "") -> List[Session]:
        """Return all active sessions, optionally filtered by query.

        The *query* is matched against session_id, binary_path and idb_path
        using automatic regex / glob / substring detection.
        """
        if not query:
            return list(self.sessions.values())
        matcher = compile_smart_pattern(query, case_sensitive=False)
        result = []
        for s in self.sessions.values():
            searchable = f"{s.session_id} {s.binary_path} {s.idb_path}"
            if matcher(searchable):
                result.append(s)
        return result

    def delete_session(self, sid: str) -> bool:
        session = self.sessions.pop(sid, None)
        deleted = False
        # Cleanup actual IDB and all associated SID files (bookmarks, logs, metadata, etc.)
        base_pattern = os.path.join(self.session_dir, f"SID_{sid}*")
        for f in glob.glob(base_pattern):
            try:
                os.remove(f)
                deleted = True
                log_rpc(f"Deleted session file: {f}")
            except Exception as e:
                log_rpc(f"Failed to delete {f}: {e}")
        for log_name in (f"ida_mcp_{sid}.log", f"ida_stdout_{sid}.log", f"ida_stderr_{sid}.log"):
            log_path = os.path.join(self.cache_dir, log_name)
            if os.path.exists(log_path):
                try:
                    os.remove(log_path)
                    deleted = True
                    log_rpc(f"Deleted session log: {log_path}")
                except Exception as e:
                    log_rpc(f"Failed to delete {log_path}: {e}")
        return bool(session) or deleted


class BookmarkManager:
    def __init__(self, session_dir: str):
        self.session_dir = session_dir

    def _get_path(self, sid: str) -> str:
        return os.path.join(self.session_dir, f"SID_{sid}_bookmarks.json")

    def load(self, sid: str) -> List[dict]:
        path = self._get_path(sid)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except:
                return []
        return []

    def save(self, sid: str, bookmarks: List[dict]):
        path = self._get_path(sid)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bookmarks, f, indent=2)

    def add(self, sid: str, data: dict) -> dict:
        if not data.get("addr"):
            return make_error(MCPError.INVALID_ARGS, "addr required")
        bookmarks = self.load(sid)
        max_id = max([b.get("id", 0) for b in bookmarks]) if bookmarks else 0

        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

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
        f_query = filters.get("query")

        filtered = bookmarks
        if f_cat:
            cat_matcher = compile_smart_pattern(f_cat, case_sensitive=False)
            filtered = [b for b in filtered if cat_matcher(b.get("category", ""))]
        if f_tag:
            tag_matcher = compile_smart_pattern(f_tag, case_sensitive=False)
            filtered = [b for b in filtered if any(tag_matcher(t) for t in b.get("tags", []))]
        if f_pri:
            filtered = [b for b in filtered if b.get("priority", 0) >= int(f_pri)]
        if f_query:
            q_matcher = compile_smart_pattern(f_query, case_sensitive=False)
            filtered = [
                b for b in filtered
                if q_matcher(b.get("name", ""))
                or q_matcher(b.get("notes", ""))
                or q_matcher(b.get("addr", ""))
            ]

        return {
            "ok": True,
            "bookmarks": filtered,
            "total": len(bookmarks),
            "count": len(filtered),
        }

    def delete(self, sid: str, data: dict) -> dict:
        bid = data.get("id")
        addr = data.get("addr")
        if not bid and not addr:
            return make_error(MCPError.INVALID_ARGS, "id or addr required")

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
        if not bid:
            return make_error(MCPError.INVALID_ARGS, "id required")

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
        matcher = compile_smart_pattern(query, case_sensitive=False)
        results = []
        for b in bookmarks:
            if (
                matcher(b.get("name", ""))
                or matcher(b.get("notes", ""))
                or any(matcher(t) for t in b.get("tags", []))
                or matcher(b.get("addr", ""))
                or matcher(b.get("category", ""))
            ):
                results.append(b)
        return {"ok": True, "results": results, "count": len(results)}

    def export(self, sid: str) -> dict:
        bookmarks = self.load(sid)
        if not bookmarks:
            return {"ok": True, "report": "No bookmarks found."}

        lines = [f"# Forensic Research Report - Session {sid}", ""]
        for b in sorted(bookmarks, key=lambda x: x.get("priority", 3)):
            prio = "⭐" * (6 - b.get("priority", 3))
            lines.append(f"## [{b['id']}] {b['name']} @ {b['addr']} {prio}")
            lines.append(f"- **Category**: {b.get('category', 'general')}")
            if b.get("tags"):
                lines.append(f"- **Tags**: {', '.join(b['tags'])}")
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
    "session",
    "truncation",
    "bookmarks",
    "batch",
    # Analysis configuration
    "analysis",
    # Unified query/edit hubs (delegating to sub-tools)
    "query",
    "edit",
    # Primary data access tools
    "idb",
    "code",
    "data",
    "search",
    "types",
    "memory",
    # Modification tools
    "modify",
    "funcs",
    "segments",
    "bulk",
    # Utilities
    "misc",
    "calc",
    "nav",
    # Debugging and tracing
    "debug",
    "trace",
    "coverage",
    "trace_analysis",
    # Project and file management
    "project",
    # Advanced analysis
    "agent",
    "microcode",
    "graph",
    "ctree",
    "taint",
    "emulate",
    "entropy",
    # Structure and type recovery
    "structs",
    "imports_deep",
    "patterns",
    "symbols",
    # Differential and comparison
    "diff",
    "lumina",
    # Export and annotation
    "export",
    "history",
    "comments_ai",
    "colorize",
    "data_ops",
    "fixups",
    # Instrumentation
    "hooks",
    # Documentation and YARA
    "wiki",
    "yara_hunt",
    # --- New LLM-optimized tools ---
    # Security & vulnerability analysis
    "vuln_scan",
    "gadgets",
    "c2_detect",
    # Deobfuscation & crypto
    "deobfuscate",
    "crypto_id",
    # ABI & calling conventions
    "abi",
    # Summarization & classification
    "summarize",
    "classify",
    # Function comparison
    "compare",
    # Stack analysis
    "stack_analysis",
    # Protocol analysis
    "protocol",
    # Intelligent annotation
    "annotation",
    # Deep cross-reference analysis
    "xref_analysis",
    # String operations
    "string_ops",
    # CFG analysis
    "cfg_analysis",
    # Binary info
    "binary_info",
    # LLM helpers
    "llm_helpers",
]

TOOL_DESCRIPTIONS = {
    # Core session tools (host-side, no IDA process required)
    "session": "Session management. Actions: discover, create (auto-detects existing sessions for same binary or IDB, supports processor/bitness/endian/loader params, analysis_options, idb_path, ida_args, and force_new), get (single session lookup by ID with runtime status), list (supports limit/offset for pagination, query for regex/glob/substring filtering, includes runtime status), switch (by session_id or binary_path), close (PERMANENTLY DELETES session and all associated files including IDB), status (shows current session with runtime info), rebuild (recreate IDB with new analysis options and recovery controls). Once a session is created or switched, all other tools automatically use it without requiring the 'idb' parameter.",
    "truncation": "Continuation helper for auto-truncated responses. Actions: continue (retrieve next chunk by token/field).",
    "bookmarks": "Enhanced session-correlated bookmarking. Actions: add, list, delete, update, clear, find (supports regex/glob/substring in name, notes, tags, addr, category), export.",
    "batch": "Run multiple tool calls in a single request. Arguments: calls[], continue_on_error.",
    # Analysis configuration
    "analysis": "Analysis configuration and reanalysis. Actions: get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze.",
    # Unified query/edit hubs
    "query": "Unified read-only query hub. Actions: data, search, imports_deep, symbols, patterns, idb.",
    "edit": "Unified write/edit hub. Actions: modify, funcs, segments, data_ops, fixups, colorize, comments_ai, bulk.",
    # Primary data access
    "idb": "Database metadata and segment information. Actions: meta, summary, segments, entrypoints, bookmarks.",
    "code": "Code logic, decompilation, and flow analysis. Actions: decompile, disasm, xrefs_to, xrefs_from, xrefs_to_field, callees, callers, blocks, analyze, callgraph, export, find_paths, strings_in_func.",
    "data": "Function listing, global variables, strings, imports, and exports. Actions: functions, globals, strings, imports, exports, lookup, bulk_query. Supports include_prototype, include_xrefs, min_size, named_only filters. Query patterns auto-detect regex (e.g. ^init, \\w+alloc), glob (*alloc*), or plain substring.",
    "search": "Pattern and reference search. Actions: bytes, string, immediate, name, insns, text, operand, comment, data_ref, code_ref, regex, func_by_sig. Supports case_sensitive, include_context. Pattern auto-detects regex (e.g. mov.*eax$, \\bfoo\\b), glob, or plain substring.",
    "types": "Type Library (TIL) and prototype management. Actions: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header.",
    "memory": "Direct database memory access. Actions: read, write.",
    # Modification tools
    "modify": "Rename, comment, set types, and patch assembly. Actions: rename, comment (regular/repeatable/anterior/posterior), set_type, patch_asm (assembles instruction(s) and patches bytes, supports multi-line separated by semicolons).",
    "funcs": "Function boundary management. Actions: create (auto-converts bytes to code, supports end address, flags, and force deletion of overlaps), delete (finds containing function if addr is inside one), set_flags, set_name (alias: rename), add_comment, list (supports regex/glob/substring query filtering), info (detailed function info with optional prototype and stack frame).",
    "segments": "Segment management. Actions: list, add, delete, set_attr, set_perms, move, info.",
    "bulk": "Bulk rename/comment/type operations. Actions: rename, comment, apply_type, rename_stack, import_annotations, export_annotations. Supports continue_on_error.",
    # Utilities
    "misc": "Utilities. Actions: python, idc, load_sig, cache_stats, read_file, write_file. Use python for full IDAPython access. read_file/write_file for host filesystem I/O.",
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
    "imports_deep": "Advanced import resolution. Actions: thunks, delay, forwarded, ordinal, api_sets, resolve.",
    "patterns": "Signature and pattern matching. Actions: generate, match, list_sigs, apply_sig, create_sig.",
    "symbols": "PDB/DWARF symbol management. Actions: load_pdb, load_dwarf, status, apply, export.",
    # Differential and comparison
    "diff": "Binary differential analysis. Actions: functions, bytes, signatures, summary, export_binexport.",
    "lumina": "Lumina server interaction. Actions: pull, push, status, history, search.",
    # Export and annotation
    "export": "Database export. Actions: listing, html, idc, json, binexport, headers.",
    "history": "Undo/redo and snapshots. Actions: undo, redo, list, snapshot, restore, diff.",
    "comments_ai": "AI-optimized comment management. Actions: get_context, set_structured, bulk_set, export_md, import_md, summary.",
    "colorize": "Visual highlighting. Actions: set_func, set_range, set_insn, get, clear, palette, highlight_pattern.",
    "data_ops": "Data type conversion. Actions: make_data, make_array, make_string, undefine, make_code.",
    "fixups": "Relocation/fixup management. Actions: list, get, add, delete.",
    # Instrumentation
    "hooks": "Hook suggestion and script generation. Actions: suggest, generate_frida, generate_detours, find_targets, inline_hooks.",
    # Documentation and YARA
    "wiki": "Built-in documentation system. Actions: list_topics, read, search, sections, index.",
    "yara_hunt": "YARA pattern matching. Actions: scan, compile, list_rules.",
    # --- New LLM-optimized tools ---
    "vuln_scan": "Automated vulnerability scanner. Compact output: 'addr [severity] CWE func: description'. Actions: buffer_overflow, format_string, integer_overflow, use_after_free, command_injection, race_condition, null_deref, info_leak, auth_bypass, hardcoded_creds, scan_all, classify. Filter by severity param.",
    "deobfuscate": "Deobfuscation analysis. Compact output per finding. Actions: detect_encoding, xor_scan (auto-decode with single-byte keys), stack_strings (char-by-char construction), opaque_predicates, control_flow_flatten, dead_code, api_hashing, dynamic_dispatch, anti_disasm, decode_attempt (provide key or auto-detect).",
    "crypto_id": "Crypto algorithm identification via known constants (AES S-box, SHA-256, CRC32, etc). Actions: identify, constants, key_schedule, block_cipher, hash_detect, rng_detect, asymmetric, custom_crypto, encoding, checksums.",
    "abi": "ABI and calling convention analysis. Actions: detect, stack_args, reg_args, return_type, varargs, struct_return, tail_calls, prologue, epilogue, abi_violations.",
    "summarize": "LLM-friendly summarization with compact output. Actions: binary, function, segment, imports_by_category, strings_by_category, complexity, call_hierarchy, data_flow, security_posture, statistics.",
    "compare": "Function comparison and similarity. Actions: functions (side-by-side diff), blocks, apis, strings, constants, structure, semantics, batch_compare, find_clones, changelog.",
    "stack_analysis": "Stack frame analysis. Actions: frame, buffers, canary, alignment, spills, usage, variables, arrays, uninitialized, summary.",
    "classify": "Function purpose classification. Actions: function, binary, all_functions, library_code, wrappers, callbacks, initializers, error_handlers, hot_functions, orphans.",
    "protocol": "Network protocol analysis. Query supports regex. Actions: detect, parsers, serializers, handlers, endpoints, tls_config, socket_flow, packet_struct, magic_numbers, state_machine.",
    "c2_detect": "C2/malware behavior detection. Actions: indicators, persistence, evasion, injection, exfiltration, lateral_movement, privilege_escalation, capabilities, config_extract, ioc_extract.",
    "gadgets": "ROP/JOP/COP gadget discovery. Query supports regex. x86/x64 + ARM/AArch64. Actions: rop, jop, cop, syscall, write_what_where, stack_pivot, shellcode_space, mitigations, seh_handlers, pivot_chains.",
    "annotation": "Intelligent bulk annotation (writes to DB, supports dry_run). Actions: auto_comment, label_loops, label_branches, mark_dangerous, annotate_constants, tag_functions, document_args, mark_error_paths, propagate_names, cleanup.",
    "xref_analysis": "Deep cross-reference analysis. Actions: call_chain, common_callers, common_callees, hub_functions, leaf_functions, recursive, dominator, influence, dependency_graph, dead_functions.",
    "string_ops": "Advanced string analysis. Query supports regex. Actions: decode_all, find_urls, find_paths, find_registry, find_ips, find_emails, find_commands, encoding_stats, multilingual, suspicious.",
    "cfg_analysis": "Control flow graph metrics. Actions: complexity, loops, branches, paths, dominators, post_dominators, back_edges, natural_loops, irreducible, flatten_detect.",
    "binary_info": "Binary metadata analysis. Actions: headers, sections, relocations, resources, debug_info, compiler, linker, timestamps, checksums, overlay.",
    "llm_helpers": "LLM workflow helpers. Actions: context_window (token-budgeted context), function_digest, binary_digest, explain_address, suggest_next, progress_report, focus_area, question_answer, guided_analysis, cheatsheet.",
}

TOOL_ACTIONS = {
    # Core session tools
    "session": ["discover", "create", "get", "list", "switch", "close", "status", "rebuild"],
    "truncation": ["continue"],
    "bookmarks": ["add", "list", "delete", "update", "clear", "find", "export"],
    # Analysis configuration
    "analysis": [
        "get_options",
        "set_options",
        "set_processor",
        "set_loader_options",
        "set_architecture",
        "reanalyze",
    ],
    # Unified query/edit hubs (LLM-friendly entry points)
    "query": ["data", "search", "idb", "code", "types"],
    "edit": ["rename", "comment", "type", "patch", "create_func", "bulk"],
    # Primary data access
    "idb": ["meta", "summary", "segments", "entrypoints", "bookmarks"],
    "code": [
        "decompile",
        "disasm",
        "xrefs_to",
        "xrefs_from",
        "xrefs_to_field",
        "callees",
        "callers",
        "blocks",
        "analyze",
        "callgraph",
        "export",
        "find_paths",
        "strings_in_func",
    ],
    "data": [
        "functions",
        "globals",
        "strings",
        "imports",
        "exports",
        "lookup",
        "bulk_query",
    ],
    "search": [
        "bytes",
        "string",
        "immediate",
        "name",
        "insns",
        "text",
        "operand",
        "comment",
        "data_ref",
        "code_ref",
        "regex",
        "func_by_sig",
        "find",
        "callers",
        "callees",
        "api",
        "vulnerable",
        "constants",
    ],
    "types": [
        "list",
        "get",
        "set_prototype",
        "parse_decl",
        "declare",
        "apply",
        "search_structs",
        "infer",
        "read_struct",
        "import_header",
    ],
    "memory": ["read", "write"],
    # Modification tools
    "modify": ["rename", "comment", "set_type", "patch_asm"],
    "funcs": [
        "create",
        "delete",
        "set_flags",
        "set_name",
        "rename",
        "add_comment",
        "list",
        "info",
    ],
    "segments": ["list", "add", "delete", "set_attr", "set_perms", "move", "info"],
    "bulk": [
        "rename",
        "comment",
        "apply_type",
        "rename_stack",
        "import_annotations",
        "export_annotations",
    ],
    # Utilities
    "misc": ["python", "idc", "load_sig", "cache_stats", "read_file", "write_file"],
    "calc": ["eval", "offset", "convert", "resolve", "deref", "chain", "align"],
    "nav": ["goto", "cursor", "interesting"],
    # Debugging and tracing
    "debug": [
        "start",
        "stop",
        "continue",
        "step_into",
        "step_over",
        "run_to",
        "run_until",
        "breakpoints",
        "add_bp",
        "del_bp",
        "enable_bp",
        "regs",
        "set_reg",
        "threads",
        "modules",
        "callstack",
        "read_mem",
        "write_mem",
    ],
    "trace": ["get", "clear", "set_options"],
    "coverage": [
        "import_drcov",
        "import_lighthouse",
        "highlight",
        "report",
        "uncovered",
        "filter",
    ],
    "trace_analysis": [
        "import_trace",
        "analyze_coverage",
        "find_loops",
        "extract_api_calls",
        "basic_blocks_hit",
    ],
    # Project and file management
    "project": [
        "save",
        "close",
        "open",
        "load_binary",
        "list_recent",
        "get_cwd",
        "set_cwd",
        "list_dir",
        "exists",
        "read",
        "write",
        "sessions",
        "batch",
    ],
    # Advanced analysis (LLM-friendly)
    "agent": [
        "analyze_function",
        "explore_address",
        "find_references",
        "search_all",
        "search_structs",
        "context_pack",
        "quick",
        "rename_suggestions",
        "batch_context",
        "similar",
    ],
    "microcode": ["get", "blocks", "instructions"],
    "graph": ["callgraph", "cfg", "xref_graph"],
    "ctree": [
        "get",
        "traverse",
        "find_calls",
        "find_vars",
        "find_strings",
        "find_conditions",
        "get_logic_flow",
    ],
    "taint": [
        "find_arg_usage",
        "trace_return",
        "find_sinks",
        "data_flow",
        "backward_trace",
        "slice",
    ],
    "emulate": ["static_trace", "appcall", "decrypt_strings", "eval_expr"],
    "entropy": [
        "section",
        "region",
        "packed_detect",
        "crypto_detect",
        "compare",
        "window",
        "summary",
    ],
    # Structure and type recovery
    "structs": [
        "recover",
        "analyze_usage",
        "list",
        "create",
        "add_member",
        "apply",
        "reconstruct_vtable",
    ],
    "imports_deep": ["thunks", "delay", "forwarded", "ordinal", "api_sets", "resolve"],
    "patterns": [
        "generate",
        "match",
        "list_sigs",
        "apply_sig",
        "create_sig",
        "matched",
    ],
    "symbols": ["load_pdb", "load_dwarf", "status", "apply", "export"],
    # Differential and comparison
    "diff": ["functions", "bytes", "signatures", "summary", "export_binexport"],
    "lumina": ["pull", "push", "status", "history", "search", "get_metadata"],
    # Export and annotation
    "export": ["listing", "html", "idc", "json", "binexport", "headers"],
    "history": ["undo", "redo", "list", "snapshot", "restore", "diff"],
    "comments_ai": [
        "get_context",
        "set_structured",
        "bulk_set",
        "export_md",
        "import_md",
        "summary",
    ],
    "colorize": [
        "set_func",
        "set_range",
        "set_insn",
        "get",
        "clear",
        "palette",
        "highlight_pattern",
    ],
    "data_ops": ["make_data", "make_array", "make_string", "undefine", "make_code"],
    "fixups": ["list", "get", "add", "delete"],
    # Instrumentation
    "hooks": [
        "suggest",
        "generate_frida",
        "generate_detours",
        "find_targets",
        "inline_hooks",
    ],
    # Documentation and YARA
    "wiki": ["list_topics", "read", "search", "sections", "index"],
    "yara_hunt": ["scan", "compile", "list_rules"],
    # --- New LLM-optimized tools ---
    "vuln_scan": [
        "buffer_overflow", "format_string", "integer_overflow", "use_after_free",
        "command_injection", "race_condition", "null_deref", "info_leak",
        "auth_bypass", "hardcoded_creds", "scan_all", "classify",
    ],
    "deobfuscate": [
        "detect_encoding", "xor_scan", "stack_strings", "opaque_predicates",
        "control_flow_flatten", "dead_code", "api_hashing", "dynamic_dispatch",
        "anti_disasm", "decode_attempt",
    ],
    "crypto_id": [
        "identify", "constants", "key_schedule", "block_cipher", "hash_detect",
        "rng_detect", "asymmetric", "custom_crypto", "encoding", "checksums",
    ],
    "abi": [
        "detect", "stack_args", "reg_args", "return_type", "varargs",
        "struct_return", "tail_calls", "prologue", "epilogue", "abi_violations",
    ],
    "summarize": [
        "binary", "function", "segment", "imports_by_category", "strings_by_category",
        "complexity", "call_hierarchy", "data_flow", "security_posture", "statistics",
    ],
    "compare": [
        "functions", "blocks", "apis", "strings", "constants", "structure",
        "semantics", "batch_compare", "find_clones", "changelog",
    ],
    "stack_analysis": [
        "frame", "buffers", "canary", "alignment", "spills",
        "usage", "variables", "arrays", "uninitialized", "summary",
    ],
    "classify": [
        "function", "binary", "all_functions", "library_code", "wrappers",
        "callbacks", "initializers", "error_handlers", "hot_functions", "orphans",
    ],
    "protocol": [
        "detect", "parsers", "serializers", "handlers", "endpoints",
        "tls_config", "socket_flow", "packet_struct", "magic_numbers", "state_machine",
    ],
    "c2_detect": [
        "indicators", "persistence", "evasion", "injection", "exfiltration",
        "lateral_movement", "privilege_escalation", "capabilities", "config_extract", "ioc_extract",
    ],
    "gadgets": [
        "rop", "jop", "cop", "syscall", "write_what_where",
        "stack_pivot", "shellcode_space", "mitigations", "seh_handlers", "pivot_chains",
    ],
    "annotation": [
        "auto_comment", "label_loops", "label_branches", "mark_dangerous",
        "annotate_constants", "tag_functions", "document_args", "mark_error_paths",
        "propagate_names", "cleanup",
    ],
    "xref_analysis": [
        "call_chain", "common_callers", "common_callees", "hub_functions",
        "leaf_functions", "recursive", "dominator", "influence",
        "dependency_graph", "dead_functions",
    ],
    "string_ops": [
        "decode_all", "find_urls", "find_paths", "find_registry", "find_ips",
        "find_emails", "find_commands", "encoding_stats", "multilingual", "suspicious",
    ],
    "cfg_analysis": [
        "complexity", "loops", "branches", "paths", "dominators",
        "post_dominators", "back_edges", "natural_loops", "irreducible", "flatten_detect",
    ],
    "binary_info": [
        "headers", "sections", "relocations", "resources", "debug_info",
        "compiler", "linker", "timestamps", "checksums", "overlay",
    ],
    "llm_helpers": [
        "context_window", "function_digest", "binary_digest", "explain_address",
        "suggest_next", "progress_report", "focus_area", "question_answer",
        "guided_analysis", "cheatsheet",
    ],
}

TOOL_ARG_SCHEMAS = {
    "session": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["session"]},
        "binary_path": {"type": "string", "description": "Path to target binary"},
        "use_existing": {"type": "string", "description": "Existing IDB path to reuse"},
        "idb_path": {"type": "string", "description": "Existing IDB path (alias of use_existing)"},
        "force_new": {"type": "boolean", "description": "Force creation of a new session even if one exists"},
        "analysis_options": {"type": "object", "description": "Advanced analysis options payload"},
        "ida_args": {"type": ["string", "array"], "items": {"type": "string"}},
        "session_id": {"type": "string", "description": "Session ID for switch/close"},
        "query": {
            "type": "string",
            "description": "Filter sessions by name/path (supports regex, glob, substring)",
        },
        "processor": {"type": "string"},
        "flags": {"type": "integer"},
        "loader": {"type": "string"},
        "value": {"type": ["string", "object"]},
        "loader_options": {"type": ["string", "object"]},
        "bitness": {"type": "integer"},
        "endian": {"type": "string"},
        "reanalyze": {"type": "boolean"},
        "options": {"type": "object"},
        "analysis_actions": {"type": "array", "items": {"type": "object"}},
        "apply_once": {"type": "boolean"},
        "recover": {"type": "boolean"},
        "backup_on_recover": {"type": "boolean"},
        "aggressive_cleanup": {"type": "boolean"},
        "start": {"type": ["string", "integer"]},
        "end": {"type": ["string", "integer"]},
        "baseaddr": {"type": ["string", "integer"]},
        "start_ea": {"type": ["string", "integer"]},
        "min_ea": {"type": ["string", "integer"]},
        "max_ea": {"type": ["string", "integer"]},
        "limit": {
            "type": "integer",
            "description": "Max sessions to return (list action)",
        },
        "offset": {
            "type": "integer",
            "description": "Skip first N sessions (list action)",
        },
    },
    "truncation": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["truncation"]},
        "token": {"type": "string"},
        "field": {"type": "string"},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
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
        "force": {"type": "boolean"},
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
    "memory": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["memory"]},
        "addr": {"type": "string"},
        "type": {
            "type": "string",
            "enum": [
                "bytes",
                "u8",
                "u16",
                "u32",
                "u64",
                "s8",
                "s16",
                "s32",
                "s64",
                "f32",
                "f64",
                "ptr",
                "string",
            ],
        },
        "size": {"type": "integer"},
        "data": {"type": "string"},
    },
    "misc": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["misc"]},
        "expr": {"type": "string", "description": "Python expression or IDC script to evaluate"},
        "code": {"type": "string", "description": "Multi-line Python code to execute"},
        "name": {"type": "string", "description": "Signature name for load_sig"},
        "path": {"type": "string", "description": "File path for read_file/write_file"},
        "content": {"type": "string", "description": "Content to write for write_file"},
        "encoding": {"type": "string", "description": "File encoding (default: utf-8). Use 'binary' for hex-encoded binary data."},
    },
    "analysis": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["analysis"]},
        "options": {"type": "object"},
        "processor": {"type": "string"},
        "flags": {"type": "integer"},
        "loader": {"type": "string"},
        "value": {"type": ["string", "object"]},
        "bitness": {"type": "integer"},
        "endian": {"type": "string"},
        "start": {"type": "string"},
        "end": {"type": "string"},
    },
    "data": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["data"]},
        "query": {"type": "string"},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
        "include_prototype": {"type": "boolean"},
        "include_xrefs": {"type": "boolean"},
        "min_size": {"type": "integer"},
        "named_only": {"type": "boolean"},
        "items": {"type": "array", "items": {"type": "object"}},
    },
    "search": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["search"]},
        "pattern": {"type": "string"},
        "query": {"type": "string"},
        "limit": {"type": "integer"},
        "offset": {"type": "integer"},
        "start": {"type": "string"},
        "end": {"type": "string"},
        "case_sensitive": {"type": "boolean"},
        "include_context": {"type": "boolean"},
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
        "args": {"type": "array", "items": {"type": "string"}},
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
    "bulk": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["bulk"]},
        "items": {"type": "array", "items": {"type": "object"}},
        "path": {"type": "string"},
        "continue_on_error": {"type": "boolean"},
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
    # idb parameter is now completely optional - uses current_session automatically
    # Only include it in schema for documentation, never required
    if (
        tool_name not in ("session", "bookmarks", "wiki", "batch")
        and "idb" not in props
    ):
        props["idb"] = {
            "type": "string",
            "description": "Optional: Path to IDB file or binary. If not provided, uses the current active session.",
        }
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
        cands = [
            r"C:\Program Files\IDA Professional 9.2",
            r"C:\Program Files\IDA Pro 9.2",
        ]
        for c in cands:
            if os.path.exists(c):
                return c
        return ""

    def _find_idat(self):
        env_idat = os.environ.get("IDA_MCP_IDAT")
        if env_idat and os.path.exists(env_idat):
            return env_idat
        if not self.ida_dir:
            return ""
        for name in ["idat64.exe", "idat.exe", "ida64.exe", "ida.exe"]:
            p = os.path.join(self.ida_dir, name)
            if os.path.exists(p):
                return p
        return ""

    def _get_ida_diagnostics(self, stdout_log=None):
        out_log = stdout_log or os.path.join(self.cache_dir, "ida_stdout.log")
        if os.path.exists(out_log):
            try:
                with open(out_log, "r", encoding="utf-8", errors="ignore") as f:
                    return "".join(f.readlines()[-20:])
            except:
                pass
        return "No log available."

    def _normalize_ida_args(self, ida_args: Optional[Union[str, List[str]]]) -> List[str]:
        if ida_args is None:
            return []
        if isinstance(ida_args, str):
            parts = shlex.split(ida_args)
        elif isinstance(ida_args, list):
            parts = []
            for p in ida_args:
                if p is None:
                    continue
                part = str(p)
                # Explicitly reject empty entries after normalization.
                if part == "":
                    raise ValueError("ida_args cannot include empty entries")
                parts.append(part)
        else:
            raise ValueError("ida_args must be a string or list of strings")
        cleaned = []
        # Reserved for server-managed script/log/output IDB wiring.
        forbidden_prefixes = ("-S", "-L", "-o")
        for arg in parts:
            if "\x00" in arg:
                raise ValueError("ida_args cannot include null bytes")
            # Args are passed via subprocess list (no shell), so metacharacters aren't interpreted.
            if any(
                (ord(ch) < 32 and ch not in ("\t", "\n", "\r")) or ch == "\x7f"
                for ch in arg
            ):
                raise ValueError("ida_args cannot include control characters")
            if any(arg.startswith(prefix) for prefix in forbidden_prefixes):
                raise ValueError(f"ida_args cannot include {arg} (reserved by server)")
            if arg == "-A":
                log_rpc("Ignoring redundant -A flag in ida_args")
                continue
            cleaned.append(arg)
        return cleaned

    def _build_ida_command(self, session, log_file, script_path, use_existing_idb: bool):
        cmd = [self.idat_exe, "-A"]
        cmd.extend(session.ida_args or [])
        cmd.append(f"-S{script_path}")
        cmd.append(f"-L{log_file}")
        if use_existing_idb:
            cmd.append(session.idb_path)
        else:
            cmd.append(f"-o{session.idb_path}")
            if session.binary_path:
                cmd.append(session.binary_path)
        return cmd

    def _backup_idb(self, idb_path: str) -> Optional[str]:
        if not idb_path or not os.path.exists(idb_path):
            return None
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{idb_path}.corrupt.{timestamp}"
        try:
            os.replace(idb_path, backup_path)
            log_rpc(f"Backed up corrupt IDB to {backup_path}")
            return backup_path
        except Exception as e:
            log_rpc(f"Failed to backup corrupt IDB {idb_path}: {e}")
        return None

    def _nuclear_reset(self, idb_path, aggressive: bool = False):
        if not idb_path:
            return

        base = idb_path.rsplit(".", 1)[0]

        lock_exts = [
            ".mcp.lock",  # Legacy MCP session lock for exclusive IDB access
            ".lock",
        ]
        all_exts = [
            ".id0",
            ".id1",
            ".id2",
            ".id3",
            ".id4",
            ".nam",
            ".til",
            ".idb_info",
            ".seg",
            ".sig",
            ".ids",
        ]

        cleanup_exts = all_exts if aggressive else lock_exts
        for ext in cleanup_exts:
            try:
                p = base + ext
                if os.path.exists(p):
                    os.remove(p)
                    log_rpc(f"Cleaned up temp file: {p}")
            except Exception as e:
                log_rpc(f"Failed to clean up {base + ext}: {e}")

        if aggressive and os.path.exists(idb_path):
            try:
                if os.path.getsize(idb_path) < 100:
                    log_rpc(f"IDB appears corrupted (too small): {idb_path}")
                    os.remove(idb_path)
                    log_rpc(f"Removed corrupted IDB: {idb_path}")
            except Exception as e:
                log_rpc(f"Failed to check IDB size: {e}")

    def _send_rpc_raw(self, request, port, timeout=5):
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", port))
            data = json.dumps(request).encode("utf-8")
            s.sendall(len(data).to_bytes(4, "big") + data)
            s.settimeout(60)
            lb = b""
            while len(lb) < 4:
                c = s.recv(4 - len(lb))
                if not c:
                    raise EOFError()
                lb += c
            rl = int.from_bytes(lb, "big")
            rd = b""
            while len(rd) < rl:
                c = s.recv(min(4096, rl - len(rd)))
                if not c:
                    raise EOFError()
                rd += c
            return json.loads(rd.decode("utf-8"))
        finally:
            s.close()

    def _start_server(self, session):
        opts = session.analysis_options or {}
        self._nuclear_reset(session.idb_path, aggressive=bool(opts.get("aggressive_cleanup")))

        # Validate IDA installation
        if not self.idat_exe or not os.path.exists(self.idat_exe):
            return make_error(
                MCPError.FILE_NOT_FOUND,
                f"IDA executable not found. Checked: {self.ida_dir}",
            )

        # DYNAMIC PORT ASSIGNMENT
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
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
        use_existing_idb = os.path.exists(session.idb_path)
        if use_existing_idb:
            log_rpc(f"Opening existing session IDB: {session.idb_path}")
        else:
            log_rpc(
                f"Creating new IDB for binary: {session.binary_path} -> {session.idb_path}"
            )
            # Ensure session directory exists
            os.makedirs(os.path.dirname(session.idb_path), exist_ok=True)
        cmd = self._build_ida_command(session, log_file, script_path, use_existing_idb)

        log_rpc(f"Launching IDA: {' '.join(cmd)}")

        stdout_fh = open(stdout_log, "a", encoding="utf-8")
        stderr_fh = open(stderr_log, "a", encoding="utf-8")
        server_process = subprocess.Popen(
            cmd, stdout=stdout_fh, stderr=stderr_fh, env=env
        )

        # WAIT FOR STARTUP using ping
        startup_timeout = int(os.environ.get("IDA_MCP_STARTUP_TIMEOUT", "90"))
        start_time = time.time()
        ida_crashed = False
        while time.time() - start_time < startup_timeout:
            exit_code = server_process.poll()
            if exit_code is not None:
                ida_crashed = True
                break

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
                    apply_res = self._apply_session_options(session, runtime)
                    if apply_res.get("error"):
                        return apply_res
                    return {
                        "ok": True,
                        "idb_path": session.idb_path,
                        "current_options": apply_res.get("current_options"),
                    }
            except:
                pass
            time.sleep(0.5)

        if ida_crashed:
            diag = self._get_ida_diagnostics(stdout_log)
            if "library init failed" in diag.lower() or "err 2" in diag:
                return self._attempt_session_recovery(session, diag, server_port)
            return make_error(
                MCPError.IDA_CRASHED,
                f"IDA exited with code {exit_code}",
                details={"log": diag},
            )

        return make_error(
            MCPError.IDA_TIMEOUT, f"IDA failed to initialize within {startup_timeout}s."
        )

    def _launch_and_wait(self, session, server_port):
        script_path = os.path.join(SCRIPT_DIR, "src", "ida_pro_mcp", "server_script.py")
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

        use_existing_idb = os.path.exists(session.idb_path)
        if use_existing_idb:
            log_rpc(f"Opening existing session IDB: {session.idb_path}")
        else:
            log_rpc(
                f"Creating new IDB for binary: {session.binary_path} -> {session.idb_path}"
            )
            os.makedirs(os.path.dirname(session.idb_path), exist_ok=True)
        cmd = self._build_ida_command(session, log_file, script_path, use_existing_idb)

        stdout_fh = open(stdout_log, "a", encoding="utf-8")
        stderr_fh = open(stderr_log, "a", encoding="utf-8")
        server_process = subprocess.Popen(
            cmd, stdout=stdout_fh, stderr=stderr_fh, env=env
        )

        startup_timeout = int(os.environ.get("IDA_MCP_STARTUP_TIMEOUT", "90"))
        start_time = time.time()
        while time.time() - start_time < startup_timeout:
            exit_code = server_process.poll()
            if exit_code is not None:
                return {
                    "error": True,
                    "exit_code": exit_code,
                    "log": self._get_ida_diagnostics(stdout_log),
                }

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

        return {"error": True, "reason": "timeout"}

    def _attempt_session_recovery(self, session, diag, server_port):
        opts = session.analysis_options or {}
        if opts.get("recover") is False:
            return make_error(
                MCPError.IDA_CRASHED,
                "IDA failed with 'library init failed' and recovery is disabled.",
                details={"log": diag, "recovery_attempted": False},
            )
        log_rpc("Detected 'library init failed err 2' - attempting recovery...")
        self._cleanup_runtime(session.session_id)
        time.sleep(1)

        backup_path = None
        if opts.get("backup_on_recover", True):
            backup_path = self._backup_idb(session.idb_path)
        self._nuclear_reset(session.idb_path, aggressive=True)

        if not session.binary_path or not os.path.exists(session.binary_path):
            return make_error(
                MCPError.FILE_NOT_FOUND,
                "Recovery requires the original binary path (missing or invalid).",
                details={
                    "binary_path": session.binary_path,
                    "backup": backup_path,
                    "log": diag,
                },
            )

        session.analysis_applied = False
        self.session_mgr._save_metadata(session)

        result = self._launch_and_wait(session, server_port)
        if "error" in result:
            return make_error(
                MCPError.IDA_CRASHED,
                "IDA failed to recover the session after cleanup.",
                details={"log": diag, "backup": backup_path, "recovery_attempted": True},
            )

        runtime = self.session_runtimes.get(session.session_id)
        if runtime:
            apply_res = self._apply_session_options(session, runtime)
            if apply_res.get("error"):
                return apply_res
            result["current_options"] = apply_res.get("current_options")

        if backup_path:
            result["backup"] = backup_path
        return result

    def _apply_session_options(self, session, runtime):
        opts = session.analysis_options or {}
        if not opts:
            return {"ok": True}
        if session.analysis_applied and opts.get("apply_once", True):
            log_rpc(f"Skipping analysis options for session {session.session_id} (already applied)")
            return {"ok": True, "skipped": True, "note": "analysis_options already applied"}

        port = runtime.get("port")
        if not port:
            return make_error(MCPError.IDA_CRASHED, "Missing runtime port")

        actions = []
        options_payload = {}
        if isinstance(opts.get("options"), dict):
            options_payload.update(opts.get("options") or {})
        for key in ("baseaddr", "start_ea", "min_ea", "max_ea"):
            if key in opts and opts[key] is not None:
                options_payload[key] = opts[key]
        if options_payload:
            actions.append({"action": "set_options", "options": options_payload})

        if any(k in opts for k in ("processor", "bitness", "endian", "flags")):
            action_args = {"action": "set_architecture"}
            for k in ("processor", "bitness", "endian", "flags"):
                if k in opts and opts[k] is not None:
                    action_args[k] = opts[k]
            actions.append(action_args)

        loader_value = opts.get("value")
        if loader_value is None and "loader_options" in opts:
            loader_value = opts.get("loader_options")
        if loader_value is not None:
            loader_args = {"action": "set_loader_options", "value": loader_value}
            if opts.get("loader"):
                loader_args["loader"] = opts["loader"]
            actions.append(loader_args)

        extra_actions = opts.get("analysis_actions")
        if isinstance(extra_actions, list):
            for action_args in extra_actions:
                if isinstance(action_args, dict) and action_args.get("action"):
                    actions.append(action_args)

        reanalyze = opts.get("reanalyze")

        for action_args in actions:
            res = self._send_rpc_raw({"tool": "analysis", "args": action_args}, port)
            if res.get("error"):
                return res

        if actions and (reanalyze is None or reanalyze):
            reanalyze_args = {"action": "reanalyze"}
            if opts.get("start") is not None:
                reanalyze_args["start"] = opts.get("start")
            if opts.get("end") is not None:
                reanalyze_args["end"] = opts.get("end")
            res = self._send_rpc_raw({"tool": "analysis", "args": reanalyze_args}, port)
            if res.get("error"):
                return res

        if opts.get("apply_once", True):
            session.analysis_applied = True
        self.session_mgr._save_metadata(session)
        return {"ok": True}

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
            if self.current_session and os.path.normpath(path) == os.path.normpath(
                self.current_session.binary_path
            ):
                session = self.current_session
            else:
                return make_error(
                    MCPError.FILE_NOT_FOUND, f"No session found for IDB: {path}"
                )

        runtime = self.session_runtimes.get(session.session_id)
        if (
            not runtime
            or not runtime.get("process")
            or runtime["process"].poll() is not None
        ):
            log_rpc(
                f"Session start/restart needed: {session.session_id} -> {session.idb_path}"
            )
            start_res = self._start_server(session)
            if "error" in start_res:
                return start_res
            runtime = self.session_runtimes.get(session.session_id)

        try:
            res = self._send_rpc_raw(
                {"tool": tool_name, "args": kwargs}, runtime["port"]
            )
            return truncate_response(res)
        except Exception as e:
            proc = runtime.get("process")
            exit_code = proc.poll() if proc else None
            if exit_code is not None:
                return make_error(
                    MCPError.IDA_CRASHED,
                    f"IDA exited with code {exit_code}",
                    details={
                        "log": self._get_ida_diagnostics(runtime.get("stdout_log"))
                    },
                )
            return make_error(MCPError.IDA_CRASHED, str(e))

    def _execute_tool(self, tool_name, args):
        args = dict(args or {})
        if tool_name == "session":
            action = args.get("action")
            if action == "create":
                binary_path = args.get("binary_path")
                idb_path = args.get("idb_path") or args.get("use_existing")
                if idb_path == "":
                    idb_path = None
                force_new = bool(args.get("force_new"))

                analysis_options = {}
                if isinstance(args.get("analysis_options"), dict):
                    analysis_options.update(args.get("analysis_options") or {})
                for key in (
                    "processor",
                    "flags",
                    "loader",
                    "value",
                    "loader_options",
                    "bitness",
                    "endian",
                    "reanalyze",
                    "options",
                    "start",
                    "end",
                    "analysis_actions",
                    "apply_once",
                    "recover",
                    "backup_on_recover",
                    "aggressive_cleanup",
                    "baseaddr",
                    "start_ea",
                    "min_ea",
                    "max_ea",
                ):
                    if key in args:
                        analysis_options[key] = args.get(key)

                ida_args = None
                if "ida_args" in args:
                    try:
                        ida_args = self._normalize_ida_args(args.get("ida_args"))
                    except ValueError as e:
                        return make_error(MCPError.INVALID_ARGS, str(e))

                if binary_path:
                    if not os.path.isabs(binary_path):
                        binary_path = os.path.abspath(binary_path)
                    args["binary_path"] = binary_path
                    if not os.path.exists(binary_path):
                        if not idb_path or not os.path.exists(idb_path):
                            return make_error(
                                MCPError.FILE_NOT_FOUND,
                                f"Binary not found: {binary_path}",
                                details={
                                    "binary_path": binary_path,
                                    "hint": "Provide an absolute path to an existing binary file or an existing idb_path.",
                                },
                            )

                if idb_path:
                    if not os.path.isabs(idb_path):
                        idb_path = os.path.abspath(idb_path)
                    ext = os.path.splitext(idb_path)[1].lower()
                    if ext and ext not in (".i64", ".idb"):
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "idb_path must point to a .i64 or .idb file",
                            details={"idb_path": idb_path},
                        )

                if not binary_path and not idb_path:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "binary_path or idb_path is required",
                        details={"hint": "Provide a binary path for new analysis or an existing IDB to recover."},
                    )

                existing = None
                if binary_path:
                    existing = self.session_mgr.find_session_by_path(binary_path)
                if not existing and idb_path:
                    existing = self.session_mgr.find_session_by_path(idb_path)
                if (
                    existing
                    and not force_new
                    and (not idb_path or os.path.normpath(existing.idb_path) == os.path.normpath(idb_path))
                ):
                    self.current_session = existing
                    existing.update_access()
                    if analysis_options:
                        existing.analysis_options.update(analysis_options)
                        existing.analysis_applied = False
                    if ida_args is not None:
                        existing.ida_args = ida_args
                    self.session_mgr._save_metadata(existing)
                    return {
                        "ok": True,
                        "session": existing.to_dict(),
                        "note": "Reusing existing session. Use force_new=true to create a new session.",
                    }

                if not analysis_options:
                    analysis_options = None
                self.current_session = self.session_mgr.create_session(
                    binary_path or "",
                    use_existing=idb_path,
                    analysis_options=analysis_options,
                    ida_args=ida_args,
                )
                return {"ok": True, "session": self.current_session.to_dict()}
            if action == "discover":
                self.session_mgr._load_orphaned_idbs()
                q = args.get("query", "")
                sessions = [s.to_dict() for s in self.session_mgr.discover_sessions(query=q)]
                return {"ok": True, "sessions": sessions, "count": len(sessions)}
            if action == "get":
                sid = args.get("session_id")
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                session = self.session_mgr.get_session(sid)
                if not session:
                    return make_error(MCPError.INVALID_ARGS, f"Session {sid} not found")
                runtime = self.session_runtimes.get(sid)
                is_running = bool(
                    runtime
                    and runtime.get("process")
                    and runtime["process"].poll() is None
                )
                result = session.to_dict()
                result["is_running"] = is_running
                if is_running:
                    result["port"] = runtime.get("port")
                return {"ok": True, "session": result}
            if action == "list":
                all_sessions = list(self.session_mgr.sessions.values())

                # Filter by query (regex/glob/substring auto-detected)
                q = args.get("query", "")
                if q:
                    matcher = compile_smart_pattern(q, case_sensitive=False)
                    all_sessions = [
                        s for s in all_sessions
                        if matcher(f"{s.session_id} {s.binary_path} {s.idb_path}")
                    ]

                # Sort by last_accessed (most recent first)
                all_sessions.sort(key=lambda s: s.last_accessed, reverse=True)

                # Pagination
                limit = args.get("limit", 50)  # Default to 50
                offset = args.get("offset", 0)

                total = len(all_sessions)
                paginated = (
                    all_sessions[offset : offset + limit]
                    if limit > 0
                    else all_sessions[offset:]
                )

                # Include runtime status for each session
                session_dicts = []
                for s in paginated:
                    d = s.to_dict()
                    runtime = self.session_runtimes.get(s.session_id)
                    d["is_running"] = bool(
                        runtime
                        and runtime.get("process")
                        and runtime["process"].poll() is None
                    )
                    session_dicts.append(d)

                return {
                    "ok": True,
                    "sessions": session_dicts,
                    "total": total,
                    "count": len(session_dicts),
                    "offset": offset,
                    "limit": limit,
                }
            if action == "switch":
                sid = args.get("session_id")
                if not sid:
                    # Try to find by binary_path
                    path = args.get("binary_path")
                    if path:
                        found = self.session_mgr.find_session_by_path(path)
                        if found:
                            sid = found.session_id
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id or binary_path required")
                session = self.session_mgr.get_session(sid)
                if session:
                    self.current_session = session
                    return {"ok": True, "session": self.current_session.to_dict()}
                return make_error(MCPError.INVALID_ARGS, f"Session {sid} not found")
            if action == "close":
                sid = args.get("session_id") or (
                    self.current_session.session_id if self.current_session else None
                )
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required (or have an active session)")
                self._cleanup_runtime(sid)
                closed = self.session_mgr.delete_session(sid)
                if (
                    closed
                    and self.current_session
                    and self.current_session.session_id == sid
                ):
                    self.current_session = None
                return {"ok": closed, "session_id": sid}
            if action == "status":
                if self.current_session:
                    result = self.current_session.to_dict()
                    runtime = self.session_runtimes.get(self.current_session.session_id)
                    result["is_running"] = bool(
                        runtime
                        and runtime.get("process")
                        and runtime["process"].poll() is None
                    )
                else:
                    result = None
                return {"ok": True, "session": result, "total_sessions": len(self.session_mgr.sessions)}
            if action == "rebuild":
                sid = args.get("session_id") or (
                    self.current_session.session_id if self.current_session else None
                )
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                session = self.session_mgr.get_session(sid)
                if not session:
                    return make_error(MCPError.INVALID_ARGS, f"Session {sid} not found")

                analysis_options = {}
                for key in ("processor", "flags", "loader", "value", "bitness", "endian", "reanalyze"):
                    if key in args:
                        analysis_options[key] = args.get(key)
                if not analysis_options:
                    analysis_options = None

                self._cleanup_runtime(sid)
                if os.path.exists(session.idb_path):
                    try:
                        os.remove(session.idb_path)
                    except Exception as e:
                        return make_error(MCPError.FILE_LOCKED, f"Failed to remove IDB: {e}")
                session.analysis_options = analysis_options or {}
                self.session_mgr._save_metadata(session)

                start_res = self._start_server(session)
                if "error" in start_res:
                    return start_res
                self.current_session = session
                return {
                    "ok": True,
                    "session": session.to_dict(),
                    "idb_path": session.idb_path,
                    "current_options": start_res.get("current_options"),
                }
            return make_error(
                MCPError.INVALID_ARGS, f"Unsupported session action: {action}"
            )

        if tool_name == "truncation":
            action = args.get("action")
            if action == "continue":
                token = args.get("token")
                if not token:
                    return make_error(MCPError.INVALID_ARGS, "token required")
                result = continue_truncated(
                    token,
                    field=args.get("field"),
                    offset=args.get("offset"),
                    count=args.get("count"),
                )
                if result.get("error"):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        result.get("message", "Invalid continuation request"),
                        details={k: v for k, v in result.items() if k != "error"},
                    )
                return result
            return make_error(MCPError.INVALID_ARGS, f"Unsupported truncation action: {action}")

        if tool_name == "bookmarks":
            if not self.current_session:
                return make_error(
                    MCPError.SESSION_REQUIRED,
                    "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
                )
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
            return make_error(
                MCPError.INVALID_ARGS, f"Unsupported bookmark action: {action}"
            )

        ip = args.pop(
            "idb", self.current_session.idb_path if self.current_session else None
        )
        if not ip:
            return make_error(
                MCPError.SESSION_REQUIRED,
                "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
            )
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
        if m == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "ida-pro-mcp", "version": "3.0.0"},
                },
            }
        if rid is None:
            return None
        if m == "tools/list":
            tools = [
                {
                    "name": t,
                    "description": TOOL_DESCRIPTIONS.get(t, ""),
                    "inputSchema": build_input_schema(t),
                }
                for t in TOOLS
            ]
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}}
        if m == "tools/call":
            tn, args = p.get("name"), p.get("arguments", {})
            if tn == "batch":
                res = self._handle_batch(args)
            else:
                res = self._execute_tool(tn, args)
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(res, indent=2)}],
                    "isError": "error" in res,
                },
            }
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "error": {"code": -32601, "message": "Method not found"},
        }

    def run(self):
        if sys.platform == "win32":
            import msvcrt

            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            msvcrt.setmode(_real_stdout.fileno(), os.O_BINARY)
        rs, si = _real_stdout.buffer, sys.stdin.buffer
        while True:
            try:
                line = si.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                req = json.loads(line.decode("utf-8"))
                resp = self.handle_request(req)
                if resp:
                    output = (json.dumps(resp) + "\n").encode("utf-8")
                    rs.write(output)
                    rs.flush()
            except:
                continue


if __name__ == "__main__":
    try:
        server = IDAMCPServer()
        server.run()
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)
