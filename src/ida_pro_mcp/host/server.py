#!/usr/bin/env python3
"""
MCP Server: IDAMCPServer — the main JSON-RPC stdio server.
"""
import os
import sys
import json
import time
import re
import struct
import subprocess
import threading
import sqlite3
import hashlib
import copy
import shutil
import tempfile
import warnings
import atexit
import signal
import glob
import difflib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from pathlib import Path
import shlex

# Suppress ALL warnings
warnings.filterwarnings("ignore")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

from .resources import list_resources, ResourceResolver
from .audit import AuditLogger
from .rate_limit import RateLimiter
from .intelligence import get_assembler
from .config import (
    CACHE_DIR,
    BRIDGE_LOG,
    log_rpc,
    RUNTIME_LEASE_TTL,
    RUNTIME_LEASE_HEARTBEAT_SECONDS,
    PROCESS_TERMINATION_TIMEOUT_SECONDS,
    _RUNTIME_LEASE_RE,
    SEMANTIC_INDEX_VERSION,
    SEMANTIC_INDEX_DB_NAME,
    SEMANTIC_INDEX_MAX_WORKERS,
    SEMANTIC_INDEX_WAIT_SECONDS,
    SEMANTIC_GADGET_SOURCE_ACTIONS,
    SEMANTIC_INDEX_SOURCE_LIMIT,
    SEMANTIC_INDEX_MAX_QUERY_WORKERS,
    _bounded_int,
    _coerce_bool,
    _env_bool,
    _parse_str_list,
    _parse_line_range,
    _normalize_session_id,
    _select_runtime_dir,
    _is_writable_dir,
    MAX_BATCH_CALLS,
    MAX_BATCH_PAYLOAD_BYTES,
    MAX_LIST_LIMIT,
    MAX_LIST_OFFSET,
    MAX_TAGS_PER_SESSION,
    MAX_TAG_LEN,
    MAX_NOTE_LEN,
    MAX_NAME_LEN,
    MAX_WIKI_RESULTS,
    WIKI_SEMANTIC_GROUPS,
    _POINTER_NOTE_SIGNAL_TOOLS_STRONG,
    _POINTER_NOTE_SIGNAL_TOOLS_HINT,
    _POINTER_NOTE_HEX_RE,
    _POINTER_NOTE_MATH_RE,
    _POINTER_NOTE_SIGNAL_KEYWORDS,
    _POINTER_NOTE_SIGNAL_MAX_DEPTH,
    _POINTER_NOTE_SIGNAL_MAX_LIST_ITEMS,
    _POINTER_NOTE_SIGNAL_MAX_DICT_ITEMS,
    _POINTER_NOTE_MAX_SIGNAL_MULTIPLIER,
    LLM_POINTER_SAFETY_NOTE,
    _COMPACT_DROP,
    _COMPACT_META_KEYS,
    _COMPACT_DETAIL_LIST_KEYS,
    CONTEXT_DENSITY_DEFAULT_BUDGET,
    CONTEXT_DENSITY_COMPACT_THRESHOLD,
    CONTEXT_DENSITY_MAX_CODE_PREVIEW,
    CONTEXT_DENSITY_MAX_HEX_PREVIEW,
    CONTEXT_DENSITY_MAX_XREF_ITEMS,
    EMBEDDING_FIRST_MODE,
    ALLOW_HEURISTIC_FALLBACKS,
)
from .context_density import ContextDensityOptimizer
from .errors import MCPError, make_error
from .patterns import compile_smart_pattern, smart_match, GlobalFactsDatabase
from .insight_index import InsightIndex
from .session import Session, SessionManager, BookmarkManager
from .schemas import (
    TOOLS,
    TOOL_DESCRIPTIONS,
    TOOL_ACTIONS,
    TOOL_ARG_SCHEMAS,
    ARG_ALIASES_BY_TOOL,
    ACTION_ALIASES_BY_TOOL,
    ADVERTISED_TOOLS,
    HIDDEN_TOOLS_IN_LIST,
    _resolve_tool_alias,
    _normalize_alias_lookup_key,
    _strip_balanced_wrappers,
    ACTION_PREFIX_RE,
    ACTION_STRIP_CHARS,
    _WRAPPER_PAIRS,
    WRAPPER_ACTIONS,
    build_input_schema,
    build_input_schema_lean,
    build_input_schema_ultra,
    build_tool_description_ultra,
    build_tool_description_lean,
    classify_tool_category,
    sanitize_schema_for_vertex,
)
from .arch_profile import normalize_arch_options, infer_binary_arch_profile
from .chip_db import find_chip_profile
from .symbol_db import SymbolDB
from .vuln_db import VULN_PATTERNS
from .server_args import ServerArgsMixin
from .server_runtime import ServerRuntimeMixin
from .server_response import ServerResponseMixin
from .server_semantic import ServerSemanticMixin
from .server_wiki import ServerWikiMixin
from .server_threat_hunt import ServerThreatHuntMixin
from .server_blackboard import ServerBlackboardMixin
from .server_predictor import ServerPredictorMixin
from .server_workflow import ServerWorkflowMixin

# Import truncation middleware
try:
    from ida_pro_mcp.ida_mcp.truncation import truncate_response, continue_truncated
except ImportError:
    try:
        import importlib.util
        import os as _os
        _trunc_path = _os.path.join(
            _os.path.dirname(_os.path.abspath(__file__)), "..", "ida_mcp", "truncation.py"
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

# =============================================================================
# MCP SERVER
# =============================================================================


class IDAMCPServer(ServerArgsMixin, ServerResponseMixin, ServerSemanticMixin, ServerWikiMixin, ServerThreatHuntMixin, ServerBlackboardMixin, ServerPredictorMixin, ServerWorkflowMixin, ServerRuntimeMixin):
    """
    JSON-RPC stdio server for the IDA Pro MCP.
    """

    _atexit_registered = False
    _blackboard_module = None
    _blackboard_store = None

    def __init__(self):
        mode = str(os.environ.get("IDA_MCP_RESPONSE_MODE", "compact")).strip().lower()
        if mode not in {"compact", "full"}:
            mode = "compact"
        qol_mode = str(os.environ.get("IDA_MCP_QOL_MODE", "balanced")).strip().lower()
        if qol_mode not in {"tiny", "balanced", "debug"}:
            qol_mode = "balanced"
        tools_list_mode = (
            str(os.environ.get("IDA_MCP_TOOLS_LIST_MODE", "full")).strip().lower()
        )
        if tools_list_mode not in {"ultra", "lean", "full"}:
            tools_list_mode = "full"
        detail_level = (
            str(os.environ.get("IDA_MCP_ERROR_DETAIL_LEVEL", "basic")).strip().lower()
        )
        if detail_level not in {"none", "basic", "full"}:
            detail_level = "basic"
        self.default_response_mode = mode
        self.default_qol_mode = qol_mode
        self.default_tools_list_mode = tools_list_mode
        self.default_error_detail_level = detail_level
        self.default_batch_compact = _env_bool("IDA_MCP_BATCH_COMPACT", True)
        # Heavy response enrichments are useful but can inflate context usage.
        # Keep disabled by default; callers can opt in via env.
        self.enable_response_enrichment = _env_bool("IDA_MCP_RESPONSE_ENRICH", True)
        self.default_table_mode = _env_bool("IDA_MCP_TABLE_COMPACT", False)
        self.default_compact_max_items = _bounded_int(
            os.environ.get("IDA_MCP_COMPACT_MAX_ITEMS", 48),
            48,
            min_value=1,
            max_value=10_000,
        )
        self.default_compact_max_string = _bounded_int(
            os.environ.get("IDA_MCP_COMPACT_MAX_STRING", 1400),
            1400,
            min_value=64,
            max_value=500_000,
        )
        self.default_compact_char_budget = _bounded_int(
            os.environ.get("IDA_MCP_COMPACT_CHAR_BUDGET", 30_000),
            30_000,
            min_value=500,
            max_value=2_000_000,
        )
        self.default_truncate_tokens = _bounded_int(
            os.environ.get("IDA_MCP_TRUNCATE_TOKENS", 2000),
            2000,
            min_value=500,
            max_value=200_000,
        )
        self.default_wiki_read_limit = _bounded_int(
            os.environ.get("IDA_MCP_WIKI_DEFAULT_LIMIT", 140),
            140,
            min_value=0,
            max_value=5000,
        )
        self._qol_profiles = {
            "tiny": {
                "mode": "compact",
                "max_items": 24,
                "max_string": 800,
                "char_budget": 12_000,
                "drop_empty": True,
                "drop_false": True,
                "drop_ok": False,
                "dedupe_counts": True,
                "strip_meta": True,
                "table_mode": False,
                "batch_compact": True,
                "error_details": "none",
            },
            "balanced": {
                "mode": self.default_response_mode,
                "max_items": self.default_compact_max_items,
                "max_string": self.default_compact_max_string,
                "char_budget": self.default_compact_char_budget,
                "drop_empty": True,
                "drop_false": True,
                "drop_ok": False,
                "dedupe_counts": True,
                "strip_meta": True,
                "table_mode": self.default_table_mode,
                "batch_compact": self.default_batch_compact,
                "error_details": self.default_error_detail_level,
            },
            "debug": {
                "mode": "full",
                "max_items": 10_000,
                "max_string": 500_000,
                "char_budget": 0,
                "drop_empty": False,
                "drop_false": False,
                "drop_ok": False,
                "dedupe_counts": False,
                "strip_meta": False,
                "table_mode": False,
                "batch_compact": False,
                "error_details": "full",
            },
        }
        self._next_cache: Dict[str, Dict[str, Any]] = {}
        self._next_cache_ttl_seconds = 1800
        self._activity_log: List[Dict[str, Any]] = []
        self._activity_log_max = 4000
        self._pointer_note_interval_seconds = _bounded_int(
            os.environ.get("IDA_MCP_POINTER_NOTE_INTERVAL", 900),
            900,
            min_value=60,
            max_value=86_400,
        )
        self._pointer_note_min_signal = _bounded_int(
            os.environ.get("IDA_MCP_POINTER_NOTE_MIN_SIGNAL", 3),
            3,
            min_value=1,
            max_value=20,
        )
        self._pointer_note_last_shown_at = 0.0
        self._pointer_note_pending_signal = 0.0
        self._guardrail_strict_writes = _env_bool("IDA_MCP_GUARDRAIL_STRICT_WRITES", False)
        # Controls whether tools/list returns the full monolithic description/schema payload.
        # Default OFF for context efficiency in LLM clients.
        self.monolithic_tool_descriptions = _env_bool(
            "IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS",
            False,
        )
        # Translation layer for Google Vertex AI / Gemini API schema compatibility
        self.vertex_compat = _env_bool(
            "IDA_MCP_VERTEX_COMPAT",
            False,
        )
        self.ida_dir = self._detect_ida_dir()
        self.idat_exe = self._find_idat()
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        preferred_cache = (
            os.environ.get("IDA_MCP_CACHE_DIR")
            or os.environ.get("IDA_MCP_DATA_DIR")
            or CACHE_DIR
        )
        self.cache_dir = _select_runtime_dir(preferred_cache)
        os.makedirs(self.cache_dir, exist_ok=True)
        self.session_mgr = SessionManager(self.cache_dir)
        self.bookmark_mgr = BookmarkManager(self.session_mgr.session_dir)
        self.audit = AuditLogger(base_dir=os.path.join(self.cache_dir, "audit"))
        self.rate_limiter = RateLimiter()
        self.assembler = get_assembler()  # bge-code-v1 intelligence layer
        # Usage intelligence — passive observer and learner (started in run())
        try:
            from .usage_intelligence import UsageIntelligence
            self._usage_intel = UsageIntelligence(
                audit_dir=os.path.join(self.cache_dir, "audit"),
                notify_fn=None,  # injected in run() once _rs is available
            )
        except Exception:
            self._usage_intel = None
        self._last_injected_entries: List[Dict[str, Any]] = []
        self._last_query_bridges: List[str] = []
        self._call_counter = 0
        self._macro_path = os.path.join(self.cache_dir, "session_macros.json")
        self._runtime_lease_dir = os.path.join(self.cache_dir, "runtime_leases")
        os.makedirs(self._runtime_lease_dir, exist_ok=True)
        self._session_macros: Dict[str, Dict[str, Any]] = {}
        self.current_session = None
        self.session_runtimes = {}
        self._runtime_lock = threading.RLock()
        self._semantic_index_lock = threading.RLock()
        self._shutdown = False
        self._shutdown_requested = False
        self._lease_thread_stop = threading.Event()
        self._lease_thread: Optional[threading.Thread] = None
        self._analysis_engines: Dict[str, Any] = {}  # session_id -> AnalysisEngine
        self._wiki_cache: Dict[str, Any] = {
            "root": "",
            "expires": 0.0,
            "topics": {},
            "pages": [],
        }
        self._wiki_cache_ttl = 5.0
        self._wiki_embed_cache: Dict[str, List[float]] = {}
        self._wiki_embed_cache_max = 512
        self._tools_list_cache: Dict[str, tuple] = {}
        self._context_density_optimizer = ContextDensityOptimizer(
            budget_tokens=CONTEXT_DENSITY_DEFAULT_BUDGET,
            compact_threshold=CONTEXT_DENSITY_COMPACT_THRESHOLD,
            max_code_preview=CONTEXT_DENSITY_MAX_CODE_PREVIEW,
            max_hex_preview=CONTEXT_DENSITY_MAX_HEX_PREVIEW,
            max_xref_items=CONTEXT_DENSITY_MAX_XREF_ITEMS,
        )
        # VOERA L1 / L2 memory tiers
        self._insight_index = InsightIndex(
            persistence_path=os.path.join(self.cache_dir, "insight_index.json")
        )
        self._global_facts = GlobalFactsDatabase(
            db_path=os.path.join(self.cache_dir, "global_facts.db")
        )
        self._register_lifecycle_handlers()
        self._start_runtime_lease_heartbeat()
        self._adopt_or_cleanup_stale_runtime_leases()
        self._load_session_macros()













        # Do NOT raise SystemExit or KeyboardInterrupt - let run() loop exit gracefully











    @staticmethod





















    def call_tool(self, tool_name, idb_path, **kwargs):
        session = self._resolve_session_from_idb_ref(idb_path)
        if not session:
            return make_error(
                MCPError.FILE_NOT_FOUND,
                f"No session found for idb reference: {idb_path}",
                hint="Use session_id, SID_* IDB id, binary/idb path, or create/switch a session first.",
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
            rpc_args = {
                k: v
                for k, v in kwargs.items()
                if not (isinstance(k, str) and k.startswith("_"))
            }
            try:
                allowed = set((TOOL_ARG_SCHEMAS.get(tool_name) or {}).keys())
                if allowed:
                    rpc_args = {k: v for k, v in rpc_args.items() if k in allowed}
            except Exception:
                pass
            res = self._send_rpc_raw(
                {"tool": tool_name, "args": rpc_args}, runtime["port"]
            )
            if isinstance(res, dict) and "error" not in res and "ok" not in res:
                res = {"ok": True, **res}
            res = truncate_response(res, max_tokens=self.default_truncate_tokens)
            # MemRL observation for IDA-side tools
            if isinstance(res, dict):
                self._observe_memrl(
                    tool_name,
                    str(kwargs.get("action") or ""),
                    res,
                )
            return res
        except Exception as e:
            proc = runtime.get("process")
            exit_code = proc.poll() if proc else None
            if exit_code is not None:
                return make_error(
                    MCPError.IDA_CRASHED,
                    f"IDA exited with code {exit_code}",
                    details={
                        "log": self._get_ida_diagnostics(
                            runtime.get("stdout_log"),
                            runtime.get("stderr_log"),
                        )
                    },
                )
            return make_error(MCPError.IDA_CRASHED, str(e))

    def _handle_misc_health(self, args: dict) -> dict:
        verbose = bool(args.get("verbose", False))
        wiki_root = self._resolve_wiki_root()
        wiki_available = bool(wiki_root and os.path.isdir(wiki_root))
        idat_path = self.idat_exe or ""
        idat_exists = bool(idat_path and os.path.exists(idat_path))
        runtime_states = []
        running = 0
        stale = 0
        for sid, runtime in self.session_runtimes.items():
            alive = bool(runtime and runtime.is_alive())
            if alive:
                running += 1
            else:
                stale += 1
            if verbose:
                runtime_states.append(
                    {
                        "session_id": sid,
                        "alive": alive,
                        "port": runtime.port if runtime else None,
                    }
                )

        payload = {
            "ok": True,
            "action": "health",
            "server": {"name": "ida-pro-mcp", "version": "3.0.0"},
            "runtime": {
                "cache_dir": self.cache_dir,
                "cache_writable": _is_writable_dir(self.cache_dir),
                "cache_exists": os.path.isdir(self.cache_dir),
            },
            "ida": {
                "ida_dir": self.ida_dir,
                "idat_path": idat_path or None,
                "idat_found": idat_exists,
            },
            "sessions": {
                "total": len(self.session_mgr.discover_sessions()),
                "active": self.current_session.session_id
                if self.current_session
                else None,
                "runtime_processes": {
                    "tracked": len(self.session_runtimes),
                    "running": running,
                    "stale": stale,
                },
            },
            "wiki": {"root": wiki_root or None, "available": wiki_available},
            "tools": {"registered": len(TOOLS)},
        }
        if verbose:
            payload["sessions"]["runtimes"] = runtime_states
        return payload

    def _grep_value_lines(self, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [line for line in value.splitlines() if line.strip()]
        if isinstance(value, list):
            out: list[str] = []
            for item in value:
                if isinstance(item, str):
                    out.extend([line for line in item.splitlines() if line.strip()])
                elif isinstance(item, dict):
                    out.append(
                        json.dumps(item, ensure_ascii=False, separators=(",", ":"))
                    )
                else:
                    s = str(item).strip()
                    if s:
                        out.append(s)
            return out
        if isinstance(value, dict):
            out: list[str] = []
            for k, v in value.items():
                if isinstance(v, str):
                    for line in v.splitlines():
                        line = line.strip()
                        if line:
                            out.append(line)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str) and item.strip():
                            out.append(item.strip())
            if out:
                return out
            return [json.dumps(value, ensure_ascii=False, separators=(",", ":"))]
        s = str(value).strip()
        return [s] if s else []

    def _grep_collect_lines(
        self, payload: Any, field: Optional[str] = None
    ) -> tuple[list[str], str]:
        if field and isinstance(payload, dict):
            return self._grep_value_lines(payload.get(field)), field
        if isinstance(payload, dict):
            preferred_fields = (
                "sessions",
                "bookmarks",
                "macros",
                "items",
                "results",
                "matches",
                "functions",
                "findings",
                "usages",
                "callers",
                "callees",
                "content",
                "sections",
                "names",
                "strings",
                "imports",
                "code_refs",
                "data_refs",
            )
            for key in preferred_fields:
                if key in payload:
                    lines = self._grep_value_lines(payload.get(key))
                    if lines:
                        return lines, key
            return self._grep_value_lines(payload), "payload"
        return self._grep_value_lines(payload), "payload"

    def _handle_tool_grep_action(self, tool_name: str, args: dict) -> dict:
        source_action, source_err = self._wrapper_source_action(tool_name, args, "grep")
        if source_err:
            return source_err

        explicit_pattern = args.get("grep") or args.get("grep_pattern")
        grep_pattern = explicit_pattern or args.get("pattern") or args.get("query")
        if not isinstance(grep_pattern, str) or not grep_pattern.strip():
            return make_error(
                MCPError.INVALID_ARGS,
                "grep pattern required",
                hint="Set grep='...' (or grep_pattern/pattern/query) with action='grep'.",
            )
        grep_pattern = grep_pattern.strip()

        grep_regex = _coerce_bool(args.get("grep_regex"), False)
        grep_case_sensitive = _coerce_bool(args.get("grep_case_sensitive"), False)
        grep_invert = _coerce_bool(args.get("grep_invert"), False)
        grep_field = args.get("grep_field")
        if grep_field is not None and not isinstance(grep_field, str):
            return make_error(MCPError.INVALID_ARGS, "grep_field must be a string")
        grep_limit = _bounded_int(
            args.get("grep_limit", 200), 200, min_value=1, max_value=5000
        )
        grep_offset = _bounded_int(
            args.get("grep_offset", 0), 0, min_value=0, max_value=500000
        )

        child_args = self._strip_wrapper_args(args)
        if explicit_pattern is None:
            child_args.pop("pattern", None)
            child_args.pop("query", None)
        child_args["action"] = source_action

        source_payload = self._execute_tool(tool_name, child_args)
        if isinstance(source_payload, dict) and source_payload.get("error"):
            return source_payload

        lines, used_field = self._grep_collect_lines(source_payload, grep_field)
        if grep_regex:
            flags = 0 if grep_case_sensitive else re.IGNORECASE
            try:
                rx = re.compile(grep_pattern, flags)
            except re.error as e:
                return make_error(MCPError.INVALID_ARGS, f"Invalid grep regex: {e}")
            matched = [line for line in lines if bool(rx.search(line)) != grep_invert]
        else:
            needle = grep_pattern if grep_case_sensitive else grep_pattern.lower()
            matched = []
            for line in lines:
                hay = line if grep_case_sensitive else line.lower()
                found = needle in hay
                if found != grep_invert:
                    matched.append(line)

        total = len(matched)
        page = matched[grep_offset : grep_offset + grep_limit]
        is_truncated = (grep_offset + len(page)) < total

        return {
            "ok": True,
            "action": "grep",
            "tool": tool_name,
            "source_action": source_action,
            "field": used_field,
            "pattern": grep_pattern,
            "matches": "\n".join(page),
            "source_count": len(lines),
            "count": len(page),
            "total": total,
            "offset": grep_offset,
            "truncated": is_truncated,
            "next_offset": (grep_offset + len(page)) if is_truncated else None,
        }

    def _handle_tool_pick_action(self, tool_name: str, args: dict) -> dict:
        source_action, source_err = self._wrapper_source_action(tool_name, args, "pick")
        if source_err:
            return source_err
        fields = _parse_str_list(args.get("pick_fields"))
        if not fields:
            fields = _parse_str_list(args.get("_response_fields"))
        if not fields:
            return make_error(
                MCPError.INVALID_ARGS,
                "action='pick' requires pick_fields",
                hint=f"Example: {tool_name}(action='pick', source_action='list', pick_fields='functions,count').",
            )
        omit = set(_parse_str_list(args.get("pick_omit")))

        child_args = self._strip_wrapper_args(args)
        child_args["action"] = source_action
        source_payload = self._execute_tool(tool_name, child_args)
        if isinstance(source_payload, dict) and source_payload.get("error"):
            return source_payload
        if not isinstance(source_payload, dict):
            return make_error(
                MCPError.INVALID_ARGS,
                "pick wrapper requires source payload object",
                hint="Pick is top-level field projection; use grep/head/tail for line-oriented payloads.",
            )

        selected = {}
        missing: List[str] = []
        for key in fields:
            if key in source_payload:
                selected[key] = source_payload.get(key)
            else:
                missing.append(key)
        for key in omit:
            selected.pop(key, None)

        out = {
            "ok": True,
            "action": "pick",
            "tool": tool_name,
            "source_action": source_action,
            "picked": list(selected.keys()),
            **selected,
        }
        if missing:
            out["missing_fields"] = missing
        return out

    def _handle_tool_head_tail_action(
        self, tool_name: str, args: dict, *, tail: bool = False
    ) -> dict:
        wrapper_name = "tail" if tail else "head"
        source_action, source_err = self._wrapper_source_action(
            tool_name, args, wrapper_name
        )
        if source_err:
            return source_err

        default_n = 20
        n_key = "tail_n" if tail else "head_n"
        n = _bounded_int(
            args.get(n_key, default_n), default_n, min_value=1, max_value=5000
        )
        field = args.get("grep_field") or args.get("field")
        if field is not None and not isinstance(field, str):
            return make_error(MCPError.INVALID_ARGS, "field must be a string")

        child_args = self._strip_wrapper_args(args)
        child_args["action"] = source_action
        source_payload = self._execute_tool(tool_name, child_args)
        if isinstance(source_payload, dict) and source_payload.get("error"):
            return source_payload

        items, used_field, item_kind = self._collect_wrapper_items(
            source_payload, field
        )
        total = len(items)
        if tail:
            page = items[max(0, total - n) :]
            offset = max(0, total - len(page))
        else:
            page = items[:n]
            offset = 0

        lines = [self._lineify_item(item) for item in page]
        lines = [line for line in lines if line]
        is_truncated = len(page) < total
        out = {
            "ok": True,
            "action": wrapper_name,
            "tool": tool_name,
            "source_action": source_action,
            "field": used_field,
            "matches": "\n".join(lines),
            "count": len(page),
            "total": total,
            "offset": offset,
            "truncated": is_truncated,
            "next_offset": (offset + len(page))
            if (not tail and is_truncated)
            else None,
        }
        if _coerce_bool(args.get("include_items"), False):
            out["items"] = page if item_kind == "list" else lines
        return out

    def _handle_tool_next_action(self, tool_name: str, args: dict) -> dict:
        token = args.get("next_token") or args.get("token") or args.get("cursor")
        if not isinstance(token, str) or not token.strip():
            return make_error(
                MCPError.INVALID_ARGS,
                "action='next' requires next_token (or token/cursor)",
                hint=f"Use the next_token returned by {tool_name} or wrapper actions with truncated=true.",
            )
        token = token.strip()
        self._prune_next_cache()
        entry = self._next_cache.get(token)
        if not entry:
            return make_error(
                MCPError.TRUNCATION_TOKEN_INVALID,
                f"next token '{token}' not found or expired",
                hint="Re-run the original paginated call to get a fresh next_token.",
            )
        cached_tool = str(entry.get("tool") or "")
        if cached_tool and cached_tool != tool_name:
            return make_error(
                MCPError.INVALID_ARGS,
                f"next token belongs to tool '{cached_tool}', not '{tool_name}'",
            )

        child_args = dict(entry.get("args") or {})
        child_args["action"] = entry.get("action")
        child_args["offset"] = entry.get("next_offset", child_args.get("offset", 0))

        overrides = dict(args or {})
        for key in ("action", "next_token", "token", "cursor"):
            overrides.pop(key, None)
        child_args.update(overrides)
        result = self._execute_tool(tool_name, child_args)
        if isinstance(result, dict):
            result = dict(result)
            result["continued_from"] = token
        return result

    def _handle_tool_stats_action(self, tool_name: str, args: dict) -> dict:
        source_action, source_err = self._wrapper_source_action(
            tool_name, args, "stats"
        )
        if source_err:
            return source_err
        include_payload = _coerce_bool(args.get("stats_include_payload"), False)

        child_args = self._strip_wrapper_args(args)
        child_args["action"] = source_action
        source_payload = self._execute_tool(tool_name, child_args)
        if isinstance(source_payload, dict) and source_payload.get("error"):
            return source_payload

        try:
            serialized = json.dumps(
                source_payload, ensure_ascii=False, separators=(",", ":")
            )
        except Exception:
            serialized = str(source_payload)
        items, used_field, item_kind = self._collect_wrapper_items(source_payload)
        top_keys: List[str] = []
        if isinstance(source_payload, dict):
            top_keys = list(source_payload.keys())[:64]
        stats = {
            "type": type(source_payload).__name__,
            "top_level_keys": top_keys,
            "line_count": len(
                [line for line in serialized.splitlines() if line.strip()]
            ),
            "char_count": len(serialized),
            "item_count": len(items),
            "item_field": used_field,
            "item_kind": item_kind,
            "has_error": bool(
                isinstance(source_payload, dict) and source_payload.get("error")
            ),
            "truncated": bool(
                isinstance(source_payload, dict) and source_payload.get("truncated")
            ),
        }
        out = {
            "ok": True,
            "action": "stats",
            "tool": tool_name,
            "source_action": source_action,
            "stats": stats,
        }
        if include_payload:
            out["payload"] = source_payload
        return out

    def _execute_tool(self, tool_name, args):
        start_ts = time.perf_counter()
        original_tool_name = tool_name
        resolved_tool = _resolve_tool_alias(tool_name)

        # ---- Rate Limiting ----
        allowed, reason = self.rate_limiter.check(resolved_tool)
        if not allowed:
            self.audit.log(
                tool=resolved_tool,
                action=str(args.get("action", "")) if isinstance(args, dict) else "",
                args=args if isinstance(args, dict) else {},
                result=None,
                latency_ms=0.0,
                session_id=getattr(self.current_session, "session_id", None) if self.current_session else None,
                error=f"rate_limited: {reason}",
            )
            return make_error(
                MCPError.INVALID_ARGS,
                f"Rate limit exceeded: {reason}",
                hint="Reduce call frequency or increase limits via IDA_MCP_RATE_LIMIT_* env vars.",
            )

        result = self._execute_tool_inner(resolved_tool, original_tool_name, args)
        sid = getattr(self.current_session, "session_id", None) if self.current_session else None
        latency_ms = (time.perf_counter() - start_ts) * 1000.0
        action_name = str(args.get("action", "")) if isinstance(args, dict) else ""
        guardrail_mode = self._guardrail_mode_from_args(args) if isinstance(args, dict) else "assist"
        guardrail_blocked = False
        error_str = None
        if isinstance(result, dict):
            err = result.get("error")
            if isinstance(err, dict):
                guardrail_blocked = (
                    err.get("code") == MCPError.INVALID_ARGS
                    and "guardrail" in str(err.get("message", "")).lower()
                )
                error_str = str(err)[:500]
            elif err is not None:
                error_str = str(err)[:500]
        self.audit.log(
            tool=resolved_tool,
            action=action_name,
            args=args if isinstance(args, dict) else {},
            result=result,
            latency_ms=latency_ms,
            session_id=sid,
            guardrail_mode=guardrail_mode,
            guardrail_blocked=guardrail_blocked,
            error=error_str,
        )
        # Live observation for usage intelligence
        if self._usage_intel and sid:
            try:
                addr = (args.get("addr") or args.get("address")) if isinstance(args, dict) else None
                self._usage_intel.observe(
                    resolved_tool, action_name, sid,
                    latency_ms=latency_ms, error=error_str, addr=addr,
                )
            except Exception:
                pass
        return result

    def _execute_tool_inner(self, tool_name, original_tool_name, args):
        if tool_name not in TOOLS:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Unknown tool '{tool_name}'",
                hint="Call tools/list to see available tools.",
            )
        if args is None:
            args = {}
        if not isinstance(args, dict):
            return make_error(MCPError.INVALID_ARGS, "arguments must be an object")
        args = self._normalize_tool_call_args(tool_name, args)

        # ---- Active Blackboard Kernel (preflight) ----
        sid = getattr(self.current_session, "session_id", None) if self.current_session else None
        pre = {"decision": "allow"}

        high_impact_tools = {
            "modify",
            "funcs",
            "segments",
            "bulk",
            "annotation",
            "memory",
            "patch",
            "edit",
        }
        # Never block state-persistence helpers; they are the mechanism to satisfy obligations.
        if tool_name in {"blackboard", "session", "bookmarks", "batch", "predictor", "workflow"}:
            pre = {"decision": "allow"}
        if pre.get("decision") == "block_high_impact":
            # Guardrail should only hard-block high-impact write surfaces.
            if tool_name not in high_impact_tools:
                pre = {"decision": "allow"}
        if pre.get("decision") == "block_high_impact":
            hint = pre.get("hint", "Resolve required receipts via supporting read/exploration actions before high-impact writes.")
            return make_error(
                MCPError.INVALID_ARGS,
                "Action blocked by active blackboard obligations (session state contract)",
                hint=hint,
                details={
                    "blocked_by": pre.get("blocked_by", []),
                    "required_receipts": pre.get("required_receipts", []),
                    "attention_debt": pre.get("debt", 0.0),
                },
            )
        
        # ---- Silent Tool Rerouting ----
        action = args.get("action", "")
        reroute_applied = False
        try:
            from .auto_nudge import get_reroute
            reroute = get_reroute(tool_name, str(action) if action else "", args)
            if reroute:
                new_tool, new_args = reroute
                new_args["_rerouted_from"] = f"{tool_name}.{action}"
                tool_name = new_tool
                args = new_args
                action = new_args.get("action", "")
                reroute_applied = True
                # Wire MemRL feedback: mark this reroute as successful
                try:
                    from .auto_nudge import record_tool_call as nudge_record
                    idb_key = (self.current_session.idb_path if self.current_session else "")
                    nudge_record(idb_key, "_reroute", f"{tool_name}.{action}", 
                                addr=args.get("addr"), query=args.get("query"))
                except Exception:
                    pass
        except Exception:
            pass
        
        # ---- Stuck Detection (UsageIntelligence DriftDetector) ----
        action = args.get("action", "")
        try:
            sid_for_drift = (getattr(self.current_session, "session_id", None)
                             if self.current_session else None)
            ui = getattr(self, "_usage_intel", None)
            if sid_for_drift and ui and ui.is_running():
                signals = ui.drift.check(sid_for_drift)
                # Only block on LOOP — other signals are warnings, not blockers
                for sig in signals:
                    if sig.get("type") == "LOOP" and sig.get("severity") == "warning":
                        return {
                            "ok": False,
                            "error": {"code": "STUCK_LOOP", "message": sig["message"]},
                            "_nudge": {
                                "type": "stuck",
                                "signal": sig["type"],
                                "suggestion": "Try a different approach. Read ida://state for orientation.",
                            },
                        }
        except Exception:
            pass
        
        action = args.get("action")
        if isinstance(action, str):
            action = action.strip()
            args["action"] = action
            native_actions = set(TOOL_ACTIONS.get(tool_name, []) or [])
            has_wrapper_source = any(
                key in args
                for key in ("source_action", "target_action", "on", "subaction")
            )
            if action in WRAPPER_ACTIONS:
                use_wrapper = action not in native_actions
                if action in ("grep", "pick", "head", "tail", "stats"):
                    use_wrapper = use_wrapper or has_wrapper_source
                elif action == "next":
                    use_wrapper = use_wrapper or any(
                        key in args for key in ("next_token", "token", "cursor")
                    )
                if use_wrapper:
                    if action == "grep":
                        return self._handle_tool_grep_action(tool_name, args)
                    if action == "pick":
                        return self._handle_tool_pick_action(tool_name, args)
                    if action == "head":
                        return self._handle_tool_head_tail_action(
                            tool_name, args, tail=False
                        )
                    if action == "tail":
                        return self._handle_tool_head_tail_action(
                            tool_name, args, tail=True
                        )
                    if action == "next":
                        return self._handle_tool_next_action(tool_name, args)
                    if action == "stats":
                        return self._handle_tool_stats_action(tool_name, args)

        guardrail_mode = self._guardrail_mode_from_args(args)
        strict_guardrails = self._guardrail_strict_writes or guardrail_mode == "enforce"
        if strict_guardrails:
            risky_tools = {"modify", "bulk", "annotation", "funcs", "segments", "memory", "data_ops"}
            risky_actions = {
                "patch_asm",
                "rename",
                "set_type",
                "comment",
                "apply_type",
                "rename_stack",
                "write",
                "make_code",
                "make_data",
                "delete",
                "set_name",
                "set_attr",
                "set_perms",
                "set_flags",
            }
            ack = _coerce_bool(args.get("_guardrail_ack"), False)
            signal = self._compute_pointer_note_signal(tool_name, args, {})
            act = str(args.get("action") or "").strip().lower()
            if (
                not ack
                and tool_name in risky_tools
                and (act in risky_actions or signal >= 2.0)
            ):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "Guardrail strict mode blocked a risky write without acknowledgement",
                    hint="Retry with _guardrail_ack=true or disable IDA_MCP_GUARDRAIL_STRICT_WRITES.",
                    details={
                        "tool": tool_name,
                        "action": act,
                        "signal": round(signal, 3),
                        "guardrail_mode": guardrail_mode,
                    },
                )
            if ack:
                pass  # guardrail ack noted
        if tool_name == "wiki":
            return self._handle_wiki(args)
        if tool_name == "misc":
            action = args.get("action")
            if action == "health":
                return self._handle_misc_health(args)
            # New plugin actions under misc.
            if action == "plugin_list":
                args["action"] = "list"
                tool_name = "plugins"
            elif action == "plugin_run":
                args["action"] = "run"
                tool_name = "plugins"
            # Backward compatibility for callers still using plugins(...).
            elif original_tool_name == "plugins":
                if action in ("list", "run"):
                    tool_name = "plugins"
                else:
                    return make_error(
                        MCPError.ACTION_NOT_FOUND,
                        f"Unsupported plugins action: '{action}'",
                        hint="Use misc(action='plugin_list') or misc(action='plugin_run', name='...', arg=0).",
                    )
        if tool_name == "project":
            action = args.get("action")
            # Consolidate generic host file I/O into misc.
            if action == "read":
                args["action"] = "read_file"
                tool_name = "misc"
            elif action == "write":
                args["action"] = "write_file"
                tool_name = "misc"
            elif action == "sessions":
                return make_error(
                    MCPError.NOT_IMPLEMENTED,
                    "Use 'session' tool for session management",
                    hint="sessions/list is handled by the host-level session tool.",
                )
            elif action == "batch":
                return make_error(
                    MCPError.NOT_IMPLEMENTED,
                    "Use host-level batch/session orchestration for multi-file analysis",
                    hint="Use batch(calls=[...]) and session actions instead of project(action='batch').",
                )

        if tool_name == "session":
            action = args.get("action")

            def _sid_arg(
                key: str = "session_id", allow_current: bool = True
            ) -> tuple[Optional[str], Optional[dict]]:
                raw_sid = args.get(key)
                if raw_sid is None and allow_current and self.current_session:
                    raw_sid = self.current_session.session_id
                if raw_sid is None:
                    return None, None
                sid = _normalize_session_id(raw_sid)
                if sid:
                    return sid, None
                # Compatibility: treat short/simple alnum values as "not found",
                # while still rejecting clearly malformed/path-like payloads.
                raw_txt = str(raw_sid).strip()
                if raw_txt and re.fullmatch(r"[A-Za-z0-9]+", raw_txt):
                    return raw_txt.upper(), None
                return None, make_error(
                    MCPError.INVALID_ARGS, "Invalid session_id format"
                )

            if action == "create":
                binary_path = args.get("binary_path")
                if "idb_path" in args or "use_existing" in args:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "The idb_path and use_existing parameters were removed from session create",
                        details={
                            "hint": "Use session(action='create', binary_path='...') instead; IDB creation/reuse is automatic."
                        },
                    )
                force_new = bool(args.get("force_new"))

                if binary_path is not None and not isinstance(binary_path, str):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "binary_path must be a string",
                        details={
                            "hint": "Provide a path string, e.g. session(action='create', binary_path='/abs/path/to/binary')."
                        },
                    )

                analysis_options = {}
                raw_analysis_options = args.get("analysis_options")
                if raw_analysis_options is not None and not isinstance(raw_analysis_options, dict):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "analysis_options must be an object",
                        details={"analysis_options_type": type(raw_analysis_options).__name__},
                    )
                if isinstance(raw_analysis_options, dict):
                    analysis_options.update(raw_analysis_options or {})

                architecture = args.get("architecture")
                if architecture is not None and not isinstance(architecture, dict):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "architecture must be an object",
                        details={"architecture_type": type(architecture).__name__},
                    )
                if isinstance(architecture, dict):
                    arch_aliases = {
                        "arch": "processor",
                        "proc": "processor",
                        "architecture": "processor",
                        "bits": "bitness",
                        "endianness": "endian",
                    }
                    for k, v in architecture.items():
                        canon = arch_aliases.get(str(k), str(k))
                        if canon in ("processor", "bitness", "endian", "loader", "flags", "loader_options", "value"):
                            if canon in analysis_options and analysis_options[canon] != v:
                                return make_error(
                                    MCPError.INVALID_ARGS,
                                    f"Conflicting architecture value for '{canon}'",
                                    details={"analysis_options": analysis_options.get(canon), "architecture": v},
                                )
                            analysis_options[canon] = v

                merged_keys = (
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
                )
                for key in merged_keys:
                    if key in args:
                        top_val = args.get(key)
                        if key in analysis_options and analysis_options[key] != top_val:
                            return make_error(
                                MCPError.INVALID_ARGS,
                                f"Conflicting value for '{key}' between top-level and analysis_options/architecture",
                                details={"top_level": top_val, "analysis_options": analysis_options.get(key)},
                            )
                        analysis_options[key] = top_val

                analysis_options, arch_meta = normalize_arch_options(analysis_options)

                preload_keys = {"processor", "bitness", "endian", "loader", "value", "loader_options", "flags"}
                has_preload_request = any(k in analysis_options and analysis_options.get(k) is not None for k in preload_keys)

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
                        return make_error(
                            MCPError.FILE_NOT_FOUND,
                            f"Binary not found: {binary_path}",
                            details={
                                "binary_path": binary_path,
                                "hint": "Provide an absolute path to an existing binary file.",
                            },
                        )
                    # Raw-binary profile inference to avoid metapc/default dead-ends.
                    if analysis_options.get("processor") is None:
                        inferred = infer_binary_arch_profile(binary_path)
                        arch_meta = dict(arch_meta or {})
                        arch_meta["inferred_profile"] = inferred
                        if inferred.get("memory_map"):
                            arch_meta["memory_map"] = inferred.get("memory_map")
                        if inferred.get("peripheral_addresses"):
                            arch_meta["peripheral_addresses"] = inferred.get("peripheral_addresses")
                        if inferred.get("processor"):
                            # Deterministic inference from explicit profile (e.g. known headers/vector table).
                            arch_meta["inference_applied"] = True
                            analysis_options["processor"] = inferred.get("processor")
                            if inferred.get("bitness") is not None:
                                analysis_options.setdefault("bitness", inferred.get("bitness"))
                            if inferred.get("endian"):
                                analysis_options.setdefault("endian", inferred.get("endian"))
                            # Apply load base for chip-specific formats (e.g. AIC WFFW at 0x120000).
                            if inferred.get("load_base") is not None:
                                analysis_options.setdefault("baseaddr", inferred["load_base"])
                                arch_meta["load_base_applied"] = True
                                arch_meta["load_base"] = hex(inferred["load_base"])
                            if inferred.get("chip_family"):
                                arch_meta["chip_family"] = inferred["chip_family"]
                                analysis_options.setdefault("chip_family", inferred.get("chip_family"))
                                if inferred.get("memory_map"):
                                    analysis_options.setdefault("memory_map", inferred.get("memory_map"))
                                if inferred.get("peripheral_addresses"):
                                    analysis_options.setdefault("peripheral_addresses", inferred.get("peripheral_addresses"))
                                prof = find_chip_profile(str(inferred.get("chip_family") or "")) or {}
                                if prof.get("post_load_actions"):
                                    analysis_options.setdefault("post_load_actions", prof.get("post_load_actions"))
                        else:
                            # For raw blobs with no deterministic header/vector-table, apply the
                            # top-ranked candidate. Any heuristic recommendation beats IDA's
                            # metapc/64 default on a raw binary. Gate only on the candidate
                            # having valid processor/bitness/endian fields.
                            candidates = inferred.get("candidates") if isinstance(inferred.get("candidates"), list) else []
                            top = candidates[0] if candidates and isinstance(candidates[0], dict) else {}
                            nxt = candidates[1] if len(candidates) > 1 and isinstance(candidates[1], dict) else {}
                            try:
                                top_conf = float(top.get("confidence", 0.0) or 0.0)
                            except Exception:
                                top_conf = 0.0
                            try:
                                next_conf = float(nxt.get("confidence", 0.0) or 0.0)
                            except Exception:
                                next_conf = 0.0
                            margin = max(0.0, top_conf - next_conf)
                            can_apply = bool(
                                top.get("processor")
                                and top.get("bitness") in {16, 32, 64}
                                and str(top.get("endian") or "").lower() in {"little", "big"}
                                and inferred.get("file_kind") == "raw"
                            )
                            if can_apply:
                                analysis_options["processor"] = top.get("processor")
                                analysis_options.setdefault("bitness", top.get("bitness"))
                                analysis_options.setdefault("endian", top.get("endian"))
                                arch_meta["inference_applied"] = True
                                arch_meta["inference_apply_reason"] = "raw_binary_top_candidate"
                                arch_meta["inference_apply_confidence"] = round(top_conf, 3)
                                arch_meta["inference_apply_margin"] = round(margin, 3)
                            else:
                                arch_meta["inference_applied"] = False

                if not binary_path:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "binary_path is required",
                        details={
                            "hint": "Provide a binary path, e.g. session(action='create', binary_path='/abs/path/to/binary')."
                        },
                    )

                existing = None
                if binary_path:
                    existing = self.session_mgr.find_session_by_path(binary_path)
                if existing and not force_new and not has_preload_request:
                    # Update the REAL session through the manager, not the shallow copy
                    update_kwargs = {"analysis_applied": False}
                    if analysis_options:
                        merged_opts = dict(existing.analysis_options)
                        merged_opts.update(analysis_options)
                        update_kwargs["analysis_options"] = merged_opts
                    if ida_args is not None:
                        update_kwargs["ida_args"] = ida_args
                    updated = self.session_mgr.update_session(
                        existing.session_id, **update_kwargs
                    )
                    if updated is None:
                        return make_error(
                            MCPError.SESSION_NOT_FOUND,
                            f"Session '{existing.session_id}' disappeared during reuse",
                        )
                    self.current_session = updated
                    return {
                        "ok": True,
                        "session": updated.to_dict(),
                        "note": "Reusing existing session. Use force_new=true to create a new session.",
                    }

                create_note = None
                if existing and not force_new and has_preload_request:
                    create_note = (
                        "Created a fresh session because architecture/loader options were provided; "
                        "reusing an old IDB can preserve previous metapc/default analysis state."
                    )

                if not analysis_options:
                    analysis_options = None

                tags = args.get("tags", [])
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(",") if t.strip()]
                tags = tags[:MAX_TAGS_PER_SESSION]
                notes = str(args.get("notes", ""))[:MAX_NOTE_LEN]

                self.current_session = self.session_mgr.create_session(
                    binary_path or "",
                    analysis_options=analysis_options,
                    ida_args=ida_args,
                    tags=tags,
                    notes=notes,
                )
                out = {"ok": True, "session": self.current_session.to_dict()}
                imported_symbol_count = 0
                cross_session_imported = 0
                try:
                    inferred = arch_meta.get("inferred_profile") if isinstance(arch_meta, dict) else {}
                    chip = str((inferred or {}).get("chip_family") or (arch_meta or {}).get("chip_family") or "").strip()
                    if chip:
                        sdb = SymbolDB()
                        imported_symbol_count = sum(
                            int(row.get("symbol_count") or 0)
                            for row in sdb.stats_by_chip()
                            if str(row.get("chip_family") or "").strip().lower() == chip.lower()
                        )
                except Exception:
                    imported_symbol_count = 0
                try:
                    cross_session_imported = self._import_cross_session_hypotheses(self.current_session)
                except Exception:
                    cross_session_imported = 0
                if create_note:
                    out["note"] = create_note
                if arch_meta:
                    out["architecture_profile"] = arch_meta
                    chip_family = arch_meta.get("chip_family")
                    if chip_family:
                        out["chip_family"] = chip_family
                        prof = find_chip_profile(str(chip_family)) or {}
                        out["bootstrap_report"] = {
                            "status": "scheduled",
                            "chip_family": chip_family,
                            "post_load_actions": prof.get("post_load_actions", []),
                            "note": "Bootstrap runs automatically when the IDA session runtime is started.",
                        }
                    inferred = arch_meta.get("inferred_profile") if isinstance(arch_meta, dict) else None
                    if isinstance(inferred, dict):
                        candidates = inferred.get("candidates") if isinstance(inferred.get("candidates"), list) else []
                        if candidates:
                            out["architecture_recommendations"] = [
                                {
                                    "tool": "analysis",
                                    "arguments": {
                                        "action": "set_architecture",
                                        "processor": c.get("processor"),
                                        "bitness": c.get("bitness"),
                                        "endian": c.get("endian"),
                                    },
                                    "confidence": c.get("confidence"),
                                    "reason": c.get("reason"),
                                }
                                for c in candidates[:3]
                                if isinstance(c, dict) and c.get("processor")
                            ]
                        elif not candidates:
                            out["architecture_recommendations"] = [
                                {
                                    "tool": "analysis",
                                    "arguments": {
                                        "action": "set_architecture",
                                        "processor": "arm",
                                        "bitness": 32,
                                        "endian": "little",
                                    },
                                    "confidence": 0.2,
                                    "reason": "raw binary ambiguous; apply explicit architecture before deep analysis",
                                }
                            ]
                out["imported_symbol_count"] = int(imported_symbol_count)
                out["cross_session_imported"] = int(cross_session_imported)
                return out
            if action == "discover":
                self.session_mgr._load_orphaned_idbs()
                q = args.get("query", "")
                sessions = [
                    s.to_dict() for s in self.session_mgr.discover_sessions(query=q)
                ]
                return {"ok": True, "sessions": sessions, "count": len(sessions)}
            if action == "get":
                raw_sid = args.get("session_id")
                if not raw_sid:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "session_id required",
                        hint="Provide a session_id. Use session(action='list') to see available sessions.",
                    )
                sid = _normalize_session_id(raw_sid)
                if not sid:
                    raw_txt = str(raw_sid).strip()
                    if raw_txt and re.fullmatch(r"[A-Za-z0-9]+", raw_txt):
                        sid = raw_txt.upper()
                    else:
                        return make_error(
                            MCPError.INVALID_ARGS, "Invalid session_id format"
                        )
                session = self.session_mgr.get_session(sid)
                if not session:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND,
                        f"Session '{sid}' not found",
                        hint="Use session(action='list') to see available sessions.",
                    )
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
                # Use locked manager method instead of direct dict access
                limit = _bounded_int(
                    args.get("limit", 50), 50, min_value=0, max_value=MAX_LIST_LIMIT
                )
                offset = _bounded_int(
                    args.get("offset", 0), 0, min_value=0, max_value=MAX_LIST_OFFSET
                )
                q = args.get("query", "")
                result = self.session_mgr.list_sessions(
                    query=q, offset=offset, limit=limit
                )

                # Augment with runtime status
                session_dicts = []
                for d in result["sessions"]:
                    runtime = self.session_runtimes.get(d["session_id"])
                    d["is_running"] = bool(
                        runtime
                        and runtime.get("process")
                        and runtime["process"].poll() is None
                    )
                    session_dicts.append(d)

                return {
                    "ok": True,
                    "sessions": session_dicts,
                    "total": result["total"],
                    "count": len(session_dicts),
                    "offset": offset,
                    "limit": limit,
                }
            if action == "switch":
                old_idb = getattr(self.current_session, "idb_path", None) if self.current_session else None
                sid = args.get("session_id")
                if not sid:
                    # Try to find by binary_path
                    path = args.get("binary_path")
                    if path:
                        found = self.session_mgr.find_session_by_path(path)
                        if found:
                            sid = found.session_id
                if not sid:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "session_id or binary_path required",
                        hint="Provide session_id or binary_path. Use session(action='list') to see sessions.",
                    )
                normalized_sid = _normalize_session_id(sid)
                if normalized_sid:
                    sid = normalized_sid
                else:
                    raw_txt = str(sid).strip()
                    if raw_txt and re.fullmatch(r"[A-Za-z0-9]+", raw_txt):
                        sid = raw_txt.upper()
                    else:
                        return make_error(
                            MCPError.INVALID_ARGS, "Invalid session_id format"
                        )
                session = self.session_mgr.get_session(sid)
                if session:
                    self.current_session = session
                    new_idb = getattr(session, "idb_path", None)
                    if old_idb and new_idb and old_idb != new_idb:
                        _trigger_session_diff(old_idb, new_idb)
                    return {"ok": True, "session": self.current_session.to_dict()}
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            if action == "close":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "session_id required (or have an active session)",
                        hint="Provide session_id or create/switch to a session first.",
                    )
                self._export_session_hypotheses_to_symbol_db(sid)
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
                    session_meta = getattr(self.current_session, "metadata", None) or {}
                    result["analysis_ready"] = bool(
                        isinstance(session_meta, dict)
                        and session_meta.get("indexing_complete")
                    )
                    # Inject recent blackboard into session status so LLM sees it by default
                    try:
                        import importlib.util
                        bb_path = os.path.join(SCRIPT_DIR, "..", "ida_mcp", "tools", "blackboard.py")
                        bb_path = os.path.abspath(bb_path)
                        spec = importlib.util.spec_from_file_location("_host_blackboard_status", bb_path)
                        mod = importlib.util.module_from_spec(spec)
                        mod.__dict__["tool"] = lambda f: f
                        mod.__dict__["idaread"] = lambda f: f
                        mod.__dict__["idawrite"] = lambda f: f
                        mod.__dict__["IDAError"] = Exception
                        spec.loader.exec_module(mod)
                        idb_p = getattr(self.current_session, "idb_path", None) if self.current_session else None
                        bb_p = (idb_p + ".blackboard.db") if idb_p else None
                        store = mod.BlackboardStore(db_path=bb_p)
                        entries = store.list(limit=8)
                        if entries:
                            result["working_memory"] = entries
                            result["working_memory_count"] = len(entries)
                    except Exception:
                        pass
                else:
                    result = None
                return {
                    "ok": True,
                    "session": result,
                    "total_sessions": len(self.session_mgr.sessions),
                }
            if action == "rebuild":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "session_id required",
                        hint="Provide session_id or create/switch to a session first.",
                    )
                session = self.session_mgr.get_session(sid)
                if not session:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )

                analysis_options = {}
                for key in (
                    "processor",
                    "flags",
                    "loader",
                    "value",
                    "bitness",
                    "endian",
                    "reanalyze",
                ):
                    if key in args:
                        analysis_options[key] = args.get(key)
                if not analysis_options:
                    analysis_options = None

                self._cleanup_runtime(sid)
                if os.path.exists(session.idb_path):
                    try:
                        os.remove(session.idb_path)
                    except Exception as e:
                        return make_error(
                            MCPError.FILE_LOCKED, f"Failed to remove IDB: {e}"
                        )

                # Update the REAL session via manager, not the deepcopy
                self.session_mgr.update_session(
                    sid, analysis_options=analysis_options or {}, analysis_applied=False
                )
                # Refetch so we have the canonical object for _start_server
                session = self.session_mgr.get_session(sid)
                if session is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND,
                        f"Session '{sid}' disappeared during rebuild",
                    )

                start_res = self._start_server(session)
                if "error" in start_res:
                    return start_res
                self.current_session = session
                return {
                    "ok": True,
                    "session": session.to_dict(),
                    "idb_path": session.idb_path,
                    "current_options": start_res.get("current_options"),
                    "bootstrap_report": start_res.get("bootstrap_report"),
                }
            if action == "update":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                update_kwargs = {
                    k: v for k, v in args.items() if k not in ("action", "session_id")
                }
                if "tags" in update_kwargs and isinstance(update_kwargs["tags"], str):
                    update_kwargs["tags"] = [
                        t.strip() for t in update_kwargs["tags"].split(",") if t.strip()
                    ]
                if "notes" in update_kwargs:
                    update_kwargs["notes"] = str(update_kwargs.get("notes", ""))[
                        :MAX_NOTE_LEN
                    ]
                if "auto_name" in update_kwargs:
                    update_kwargs["auto_name"] = str(
                        update_kwargs.get("auto_name", "")
                    ).strip()[:MAX_NAME_LEN]
                result = self.session_mgr.update_session(sid, **update_kwargs)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "session": result.to_dict()}
            if action == "rename":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                new_name = args.get("name") or args.get("new_name")
                if not new_name:
                    return make_error(MCPError.INVALID_ARGS, "name required")
                new_name = str(new_name).strip()[:MAX_NAME_LEN]
                result = self.session_mgr.rename_session(sid, new_name)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "session": result.to_dict()}
            if action == "duplicate":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                result = self.session_mgr.duplicate_session(sid)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "session": result.to_dict()}
            if action == "export_session":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                exported_hypotheses = self._export_session_hypotheses_to_symbol_db(sid)
                result = self.session_mgr.export_session(sid)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "exported": result, "exported_hypotheses": int(exported_hypotheses)}
            if action == "import_session":
                data = args.get("data")
                if not data or not isinstance(data, dict):
                    return make_error(MCPError.INVALID_ARGS, "data dict required")
                result = self.session_mgr.import_session(data)
                return {"ok": True, "session": result.to_dict()}
            if action == "archive":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                result = self.session_mgr.archive_session(sid)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "session": result.to_dict()}
            if action == "unarchive":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                result = self.session_mgr.unarchive_session(sid)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "session": result.to_dict()}
            if action == "tag":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                tag = args.get("tag")
                if not tag:
                    return make_error(MCPError.INVALID_ARGS, "tag required")
                tag = str(tag).strip()[:MAX_TAG_LEN]
                if not tag:
                    return make_error(MCPError.INVALID_ARGS, "tag required")
                result = self.session_mgr.tag_session(sid, tag)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "session": result.to_dict()}
            if action == "untag":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                tag = args.get("tag")
                if not tag:
                    return make_error(MCPError.INVALID_ARGS, "tag required")
                result = self.session_mgr.untag_session(sid, tag)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "session": result.to_dict()}
            if action == "find_by_tag":
                tag = args.get("tag")
                if not tag:
                    return make_error(MCPError.INVALID_ARGS, "tag required")
                sessions = [s.to_dict() for s in self.session_mgr.find_by_tag(tag)]
                return {"ok": True, "sessions": sessions, "count": len(sessions)}
            if action == "add_note":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                note = args.get("note", "")
                if not note:
                    return make_error(MCPError.INVALID_ARGS, "note required")
                note = str(note)[:MAX_NOTE_LEN]
                result = self.session_mgr.add_note(sid, note)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "session": result.to_dict()}
            if action == "clear_notes":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                result = self.session_mgr.clear_notes(sid)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "session": result.to_dict()}
            if action == "cleanup_stale":
                max_age = _bounded_int(
                    args.get("max_age_days", 30), 30, min_value=1, max_value=3650
                )
                deleted = self.session_mgr.cleanup_stale(max_age_days=max_age)
                return {"ok": True, "deleted_sids": deleted, "count": len(deleted)}
            if action == "stats":
                return {"ok": True, "stats": self.session_mgr.get_stats()}
            if action == "validate":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                result = self.session_mgr.validate_session(sid)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "validation": result}
            if action == "bulk_delete":
                sids = args.get("session_ids", [])
                if not sids:
                    return make_error(
                        MCPError.INVALID_ARGS, "session_ids list required"
                    )
                if not isinstance(sids, list):
                    return make_error(
                        MCPError.INVALID_ARGS, "session_ids must be a list"
                    )
                cleaned_sids = []
                for raw_sid in sids[:MAX_BATCH_CALLS]:
                    sid = _normalize_session_id(raw_sid)
                    if not sid:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            f"Invalid session_id in list: {raw_sid}",
                        )
                    cleaned_sids.append(sid)
                results = self.session_mgr.bulk_delete(cleaned_sids)
                # Clear current session if it was deleted
                if (
                    self.current_session
                    and self.current_session.session_id in cleaned_sids
                ):
                    self.current_session = None
                return {"ok": True, "results": results}
            if action == "bulk_tag":
                sids = args.get("session_ids", [])
                tag = args.get("tag")
                if not sids:
                    return make_error(
                        MCPError.INVALID_ARGS, "session_ids list required"
                    )
                if not tag:
                    return make_error(MCPError.INVALID_ARGS, "tag required")
                if not isinstance(sids, list):
                    return make_error(
                        MCPError.INVALID_ARGS, "session_ids must be a list"
                    )
                cleaned_sids = []
                for raw_sid in sids[:MAX_BATCH_CALLS]:
                    sid = _normalize_session_id(raw_sid)
                    if not sid:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            f"Invalid session_id in list: {raw_sid}",
                        )
                    cleaned_sids.append(sid)
                tag = str(tag).strip()[:MAX_TAG_LEN]
                if not tag:
                    return make_error(MCPError.INVALID_ARGS, "tag required")
                results = self.session_mgr.bulk_tag(cleaned_sids, tag)
                return {"ok": True, "results": results}
            if action == "search_notes":
                query = args.get("query", "")
                if not query:
                    return make_error(MCPError.INVALID_ARGS, "query required")
                sessions = [s.to_dict() for s in self.session_mgr.search_notes(query)]
                return {"ok": True, "sessions": sessions, "count": len(sessions)}
            if action == "recent":
                n = _bounded_int(
                    args.get("n", 5), 5, min_value=1, max_value=MAX_LIST_LIMIT
                )
                sessions = [s.to_dict() for s in self.session_mgr.get_recent(n)]
                return {"ok": True, "sessions": sessions, "count": len(sessions)}
            if action == "oldest":
                n = _bounded_int(
                    args.get("n", 5), 5, min_value=1, max_value=MAX_LIST_LIMIT
                )
                sessions = [s.to_dict() for s in self.session_mgr.get_oldest(n)]
                return {"ok": True, "sessions": sessions, "count": len(sessions)}
            if action == "snapshot":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                snapshot_res = self.session_mgr.snapshot_session(sid)
                if snapshot_res is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                return {"ok": True, "session_id": sid, "snapshot_id": snapshot_res.get("snapshot_id"), "message": snapshot_res.get("message", "")}
            if action == "restore_snapshot":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                snapshot_id = args.get("snapshot_id")
                if not snapshot_id:
                    return make_error(MCPError.INVALID_ARGS, "snapshot_id required")
                result = self.session_mgr.restore_snapshot(sid, snapshot_id)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND,
                        f"Snapshot '{snapshot_id}' not found for session '{sid}'",
                    )
                return {"ok": True, "session": result.to_dict()}
            if action == "merge":
                sid1 = _normalize_session_id(
                    args.get("session_id") or args.get("target_id")
                )
                sid2 = _normalize_session_id(args.get("source_id"))
                if not sid1 or not sid2:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "session_id (or target_id) and source_id required",
                    )
                result = self.session_mgr.merge_sessions(sid1, sid2)
                if result is None:
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, "One or both sessions not found"
                    )
                return {"ok": True, "session": result.to_dict()}
            if action == "crystallize_skill":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                name = str(args.get("name") or "").strip()
                description = str(args.get("description") or "").strip()
                if not name:
                    return make_error(MCPError.INVALID_ARGS, "name required")
                if not description:
                    return make_error(MCPError.INVALID_ARGS, "description required")
                steps = args.get("steps")
                if not isinstance(steps, list) or not steps:
                    return make_error(MCPError.INVALID_ARGS, "steps must be a non-empty list")
                tags = args.get("tags")
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(",") if t.strip()]
                if tags is not None and not isinstance(tags, list):
                    return make_error(MCPError.INVALID_ARGS, "tags must be a list or comma-separated string")
                memrl_reward = args.get("memrl_reward")
                if memrl_reward is not None:
                    try:
                        memrl_reward = float(memrl_reward)
                    except (TypeError, ValueError):
                        return make_error(MCPError.INVALID_ARGS, "memrl_reward must be a number")
                return self.session_mgr.crystallize_skill(
                    sid,
                    name=name,
                    description=description,
                    steps=steps,
                    tags=tags,
                    memrl_reward=memrl_reward,
                )
            if action == "rate_skill":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                skill_id = str(args.get("skill_id") or "").strip()
                if not skill_id:
                    return make_error(MCPError.INVALID_ARGS, "skill_id required")
                reward = args.get("reward")
                try:
                    reward_f = float(reward)
                except (TypeError, ValueError):
                    return make_error(MCPError.INVALID_ARGS, "reward must be a number")
                return self.session_mgr.rate_skill(sid, skill_id=skill_id, reward=reward_f)
            if action == "list_skills":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                min_q = args.get("min_q", 0.0)
                try:
                    min_q = float(min_q)
                except (TypeError, ValueError):
                    return make_error(MCPError.INVALID_ARGS, "min_q must be a number")
                include_global = _coerce_bool(args.get("global_skills"), True)
                return self.session_mgr.list_skills(
                    sid,
                    min_q=min_q,
                    global_skills=include_global,
                )
            if action == "suggest_strategy":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                context = str(args.get("context") or "")
                return self.session_mgr.suggest_strategy(sid, context=context)
            if action == "log_activity":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                tool = str(args.get("tool") or "").strip()
                tool_action = str(args.get("tool_action") or args.get("activity_action") or args.get("activity") or "").strip()
                if not tool_action:
                    tool_action = str(args.get("action_name") or args.get("name") or "").strip()
                if not tool_action:
                    tool_action = str(args.get("log_action") or "").strip()
                if not tool_action:
                    tool_action = str(args.get("event") or "").strip()
                # Preferred field name is 'activity_action', but keep compatibility.
                if not tool:
                    return make_error(MCPError.INVALID_ARGS, "tool required")
                if not tool_action:
                    return make_error(MCPError.INVALID_ARGS, "activity_action required")
                result = str(args.get("result") or "")
                return self.session_mgr.log_activity(sid, tool=tool, action=tool_action, result=result)
            if action == "get_activity_log":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                limit = _bounded_int(args.get("limit", 20), 20, min_value=1, max_value=500)
                return self.session_mgr.get_activity_log(sid, limit=limit)
            if action == "notebook_append":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                entry = str(args.get("note") or args.get("entry") or "").strip()
                if not entry:
                    return make_error(MCPError.INVALID_ARGS, "entry (or note) required")
                section = str(args.get("section") or "").strip() or None
                return self.session_mgr.notebook_append(sid, entry=entry, section=section)
            if action == "notebook_read":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                lines = args.get("lines")
                lines = str(lines).strip() if lines is not None else None
                return self.session_mgr.notebook_read(sid, lines=lines)
            if action == "notebook_section":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                section_name = str(args.get("section") or args.get("name") or "").strip()
                if not section_name:
                    return make_error(MCPError.INVALID_ARGS, "section required")
                return self.session_mgr.notebook_section(sid, section_name=section_name)
            if action == "track_hypothesis":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                statement = str(args.get("statement") or "").strip()
                if not statement:
                    return make_error(MCPError.INVALID_ARGS, "statement required")
                evidence_for = args.get("evidence_for")
                if isinstance(evidence_for, str):
                    evidence_for = [s.strip() for s in evidence_for.split(",") if s.strip()]
                evidence_against = args.get("evidence_against")
                if isinstance(evidence_against, str):
                    evidence_against = [s.strip() for s in evidence_against.split(",") if s.strip()]
                confidence = args.get("confidence", 0.5)
                try:
                    confidence = float(confidence)
                except (TypeError, ValueError):
                    return make_error(MCPError.INVALID_ARGS, "confidence must be a number")
                return self.session_mgr.track_hypothesis(
                    sid,
                    statement=statement,
                    evidence_for=evidence_for,
                    evidence_against=evidence_against,
                    confidence=confidence,
                )
            if action == "confirm_hypothesis":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                hid = str(args.get("hypothesis_id") or args.get("id") or "").strip()
                if not hid:
                    return make_error(MCPError.INVALID_ARGS, "hypothesis_id required")
                evidence = args.get("evidence")
                if isinstance(evidence, str):
                    evidence = [s.strip() for s in evidence.split(",") if s.strip()]
                return self.session_mgr.confirm_hypothesis(sid, hid=hid, evidence=evidence)
            if action == "refute_hypothesis":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                hid = str(args.get("hypothesis_id") or args.get("id") or "").strip()
                if not hid:
                    return make_error(MCPError.INVALID_ARGS, "hypothesis_id required")
                reason = str(args.get("reason") or "").strip()
                if not reason:
                    return make_error(MCPError.INVALID_ARGS, "reason required")
                evidence = args.get("evidence")
                if isinstance(evidence, str):
                    evidence = [s.strip() for s in evidence.split(",") if s.strip()]
                return self.session_mgr.refute_hypothesis(
                    sid,
                    hid=hid,
                    reason=reason,
                    evidence=evidence,
                )
            if action == "list_hypotheses":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                status = str(args.get("status") or "").strip() or None
                return self.session_mgr.list_hypotheses(sid, status=status)
            if action == "dashboard":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                return self.session_mgr.dashboard(sid)
            if action == "get_phase":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                return self.session_mgr.get_phase(sid)
            if action == "advance_phase":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                return self.session_mgr.advance_phase(sid)
            if action == "link_session":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                other_sid = _normalize_session_id(args.get("other_session_id") or args.get("other_sid") or args.get("target_session_id"))
                if not other_sid:
                    return make_error(MCPError.INVALID_ARGS, "other_session_id required")
                return self.session_mgr.link_session(sid, other_sid=other_sid)
            if action == "cross_reference_sessions":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                return self.session_mgr.cross_reference_sessions(sid)
            if action == "list_snapshots":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                return self.session_mgr.list_snapshots(sid)
            if action == "bootstrap_init":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                overwrite = _coerce_bool(args.get("overwrite"), False)
                decay_lambda = args.get("decay_lambda", 0.03)
                min_bootstrap_weight = args.get("min_bootstrap_weight", 0.1)
                try:
                    decay_lambda = float(decay_lambda)
                    min_bootstrap_weight = float(min_bootstrap_weight)
                except (TypeError, ValueError):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "decay_lambda and min_bootstrap_weight must be numeric",
                    )
                return self.session_mgr.bootstrap_init(
                    sid,
                    overwrite=overwrite,
                    decay_lambda=decay_lambda,
                    min_bootstrap_weight=min_bootstrap_weight,
                )
            if action == "bootstrap_run_tournament":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                rounds = _bounded_int(args.get("rounds", 200), 200, min_value=1, max_value=50000)
                seed = _bounded_int(args.get("seed", 1337), 1337, min_value=0, max_value=2_147_483_647)
                return self.session_mgr.bootstrap_run_tournament(
                    sid,
                    rounds=rounds,
                    seed=seed,
                )
            if action == "bootstrap_compute_blend":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                if "session_samples" not in args:
                    return make_error(MCPError.INVALID_ARGS, "session_samples required")
                session_samples = _bounded_int(
                    args.get("session_samples"),
                    0,
                    min_value=0,
                    max_value=100_000_000,
                )
                return self.session_mgr.bootstrap_compute_blend(
                    sid,
                    session_samples=session_samples,
                )
            if action == "bootstrap_status":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                return self.session_mgr.bootstrap_status(sid)
            if action == "bootstrap_ingest_outcome":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                if "predicted" not in args:
                    return make_error(MCPError.INVALID_ARGS, "predicted required")
                if "observed" not in args:
                    return make_error(MCPError.INVALID_ARGS, "observed required")
                try:
                    predicted = float(args.get("predicted"))
                    observed = int(args.get("observed"))
                except (TypeError, ValueError):
                    return make_error(MCPError.INVALID_ARGS, "predicted must be float and observed must be int")
                skill_id = str(args.get("skill_id") or "").strip() or None
                delay_seconds = _bounded_int(args.get("delay_seconds", 0), 0, min_value=0, max_value=31_536_000)
                return self.session_mgr.bootstrap_ingest_outcome(
                    sid,
                    predicted=predicted,
                    observed=observed,
                    skill_id=skill_id,
                    delay_seconds=delay_seconds,
                )
            if action == "bootstrap_open_dispute":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                claim_id = str(args.get("claim_id") or "").strip()
                reason = str(args.get("reason") or "").strip()
                if not claim_id:
                    return make_error(MCPError.INVALID_ARGS, "claim_id required")
                if not reason:
                    return make_error(MCPError.INVALID_ARGS, "reason required")
                if "predicted" not in args:
                    return make_error(MCPError.INVALID_ARGS, "predicted required")
                try:
                    predicted = float(args.get("predicted"))
                except (TypeError, ValueError):
                    return make_error(MCPError.INVALID_ARGS, "predicted must be float")
                skill_id = str(args.get("skill_id") or "").strip() or None
                return self.session_mgr.bootstrap_open_dispute(
                    sid,
                    claim_id=claim_id,
                    predicted=predicted,
                    reason=reason,
                    skill_id=skill_id,
                )
            if action == "bootstrap_list_disputes":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                status = str(args.get("status") or "").strip() or None
                return self.session_mgr.bootstrap_list_disputes(sid, status=status)
            if action == "bootstrap_resolve_dispute":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                dispute_id = str(args.get("dispute_id") or "").strip()
                if not dispute_id:
                    return make_error(MCPError.INVALID_ARGS, "dispute_id required")
                if "observed" not in args:
                    return make_error(MCPError.INVALID_ARGS, "observed required")
                try:
                    observed = int(args.get("observed"))
                except (TypeError, ValueError):
                    return make_error(MCPError.INVALID_ARGS, "observed must be int")
                delay_seconds = _bounded_int(args.get("delay_seconds", 0), 0, min_value=0, max_value=31_536_000)
                return self.session_mgr.bootstrap_resolve_dispute(
                    sid,
                    dispute_id=dispute_id,
                    observed=observed,
                    delay_seconds=delay_seconds,
                )
            if action == "bootstrap_summary":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                return self.session_mgr.bootstrap_summary(sid)
            if action == "bootstrap_snapshot":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                name = str(args.get("name") or "").strip()
                return self.session_mgr.bootstrap_snapshot(sid, name=name)
            if action == "bootstrap_list_snapshots":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                limit = _bounded_int(args.get("limit", 50), 50, min_value=1, max_value=1000)
                offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
                return self.session_mgr.bootstrap_list_snapshots(
                    sid,
                    limit=limit,
                    offset=offset,
                )
            if action == "bootstrap_drift_report":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=1000)
                return self.session_mgr.bootstrap_drift_report(sid, window=window)
            if action == "bootstrap_simulate_batch":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                n = _bounded_int(args.get("n", 500), 500, min_value=1, max_value=200000)
                seed = _bounded_int(args.get("seed", 2026), 2026, min_value=0, max_value=2_147_483_647)
                positive_rate = args.get("positive_rate", 0.5)
                try:
                    positive_rate = float(positive_rate)
                except (TypeError, ValueError):
                    return make_error(MCPError.INVALID_ARGS, "positive_rate must be numeric")
                return self.session_mgr.bootstrap_simulate_batch(
                    sid,
                    n=n,
                    seed=seed,
                    positive_rate=positive_rate,
                )
            if action == "bootstrap_prune_data":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                max_outcomes = _bounded_int(args.get("max_outcomes", 1000), 1000, min_value=1, max_value=200000)
                max_disputes = _bounded_int(args.get("max_disputes", 500), 500, min_value=1, max_value=50000)
                max_snapshots = _bounded_int(args.get("max_snapshots", 2000), 2000, min_value=1, max_value=100000)
                return self.session_mgr.bootstrap_prune_data(
                    sid,
                    max_outcomes=max_outcomes,
                    max_disputes=max_disputes,
                    max_snapshots=max_snapshots,
                )
            if action == "bootstrap_export_metrics":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                status = str(args.get("status") or "all").strip().lower()
                since = str(args.get("since") or "").strip()
                until = str(args.get("until") or "").strip()
                limit = _bounded_int(args.get("limit", 5000), 5000, min_value=1, max_value=200000)
                return self.session_mgr.bootstrap_export_metrics(
                    sid,
                    status=status,
                    since=since,
                    until=until,
                    limit=limit,
                )
            if action == "bootstrap_summary_detailed":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                top_policies = _bounded_int(args.get("top_policies", 10), 10, min_value=1, max_value=50)
                return self.session_mgr.bootstrap_summary_detailed(sid, top_policies=top_policies)
            if action == "bootstrap_calibration_report":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                min_bin_n = _bounded_int(args.get("min_bin_n", 20), 20, min_value=1, max_value=1000000)
                return self.session_mgr.bootstrap_calibration_report(sid, min_bin_n=min_bin_n)
            if action == "bootstrap_update_baseline":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                window = _bounded_int(args.get("window", 50), 50, min_value=5, max_value=10000)
                percentile = args.get("percentile", 95.0)
                try:
                    percentile = float(percentile)
                except (TypeError, ValueError):
                    return make_error(MCPError.INVALID_ARGS, "percentile must be numeric")
                return self.session_mgr.bootstrap_update_baseline(
                    sid,
                    window=window,
                    percentile=percentile,
                )
            if action == "bootstrap_evaluate_alerts":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=10000)
                return self.session_mgr.bootstrap_evaluate_alerts(sid, window=window)
            if action == "bootstrap_mitigation_plan":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=10000)
                return self.session_mgr.bootstrap_mitigation_plan(sid, window=window)
            if action == "bootstrap_apply_mitigation":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=10000)
                max_actions = _bounded_int(args.get("max_actions", 4), 4, min_value=1, max_value=10)
                dry_run = _coerce_bool(args.get("dry_run"), False)
                return self.session_mgr.bootstrap_apply_mitigation(
                    sid,
                    window=window,
                    max_actions=max_actions,
                    dry_run=dry_run,
                )
            if action == "bootstrap_mitigation_history":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=5000)
                offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
                return self.session_mgr.bootstrap_mitigation_history(sid, limit=limit, offset=offset)
            if action == "bootstrap_mitigation_effectiveness":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                window = _bounded_int(args.get("window", 50), 50, min_value=1, max_value=10000)
                return self.session_mgr.bootstrap_mitigation_effectiveness(sid, window=window)
            if action == "bootstrap_policy_reweight":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                window = _bounded_int(args.get("window", 50), 50, min_value=1, max_value=10000)
                max_shift = args.get("max_shift", 0.08)
                try:
                    max_shift = float(max_shift)
                except (TypeError, ValueError):
                    return make_error(MCPError.INVALID_ARGS, "max_shift must be numeric")
                dry_run = _coerce_bool(args.get("dry_run"), False)
                return self.session_mgr.bootstrap_policy_reweight(
                    sid,
                    window=window,
                    max_shift=max_shift,
                    dry_run=dry_run,
                )
            if action == "bootstrap_policy_reweight_history":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=5000)
                offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
                return self.session_mgr.bootstrap_policy_reweight_history(sid, limit=limit, offset=offset)
            if action == "bootstrap_autopilot":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                window = _bounded_int(args.get("window", 30), 30, min_value=2, max_value=10000)
                dry_run = _coerce_bool(args.get("dry_run"), False)
                return self.session_mgr.bootstrap_autopilot(sid, window=window, dry_run=dry_run)
            if action == "bootstrap_set_autopilot_policy":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                cooldown_seconds = _bounded_int(args.get("cooldown_seconds", 300), 300, min_value=0, max_value=86400)
                daily_budget = _bounded_int(args.get("daily_budget", 100), 100, min_value=1, max_value=100000)
                max_live_actions = _bounded_int(args.get("max_live_actions", 4), 4, min_value=1, max_value=10)
                rollback_on_regression = _coerce_bool(args.get("rollback_on_regression"), True)
                return self.session_mgr.bootstrap_set_autopilot_policy(
                    sid,
                    cooldown_seconds=cooldown_seconds,
                    daily_budget=daily_budget,
                    max_live_actions=max_live_actions,
                    rollback_on_regression=rollback_on_regression,
                )
            if action == "bootstrap_get_autopilot_policy":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                return self.session_mgr.bootstrap_get_autopilot_policy(sid)
            if action == "bootstrap_rollback_last_reweight":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                return self.session_mgr.bootstrap_rollback_last_reweight(sid)
            if action == "bootstrap_plan_status":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                return self.session_mgr.bootstrap_plan_status(sid)
            if action == "bootstrap_readiness_gate":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                min_tournament_rounds = _bounded_int(args.get("min_tournament_rounds", 1000), 1000, min_value=1, max_value=10_000_000)
                min_snapshots = _bounded_int(args.get("min_snapshots", 10), 10, min_value=1, max_value=100_000)
                min_outcomes = _bounded_int(args.get("min_outcomes", 200), 200, min_value=1, max_value=10_000_000)
                max_open_disputes = _bounded_int(args.get("max_open_disputes", 25), 25, min_value=0, max_value=1_000_000)
                max_ece = args.get("max_ece", 0.2)
                try:
                    max_ece = float(max_ece)
                except (TypeError, ValueError):
                    return make_error(MCPError.INVALID_ARGS, "max_ece must be numeric")
                return self.session_mgr.bootstrap_readiness_gate(
                    sid,
                    min_tournament_rounds=min_tournament_rounds,
                    min_snapshots=min_snapshots,
                    min_outcomes=min_outcomes,
                    max_ece=max_ece,
                    max_open_disputes=max_open_disputes,
                )
            if action == "bootstrap_record_readiness":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                tag = str(args.get("tag") or "").strip()
                return self.session_mgr.bootstrap_record_readiness(sid, tag=tag)
            if action == "bootstrap_readiness_history":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=10000)
                offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
                return self.session_mgr.bootstrap_readiness_history(sid, limit=limit, offset=offset)
            if action == "bootstrap_readiness_trend":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                window = _bounded_int(args.get("window", 50), 50, min_value=2, max_value=10000)
                return self.session_mgr.bootstrap_readiness_trend(sid, window=window)
            if action == "bootstrap_readiness_regression_guard":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                window = _bounded_int(args.get("window", 50), 50, min_value=2, max_value=10000)
                auto_snapshot = _coerce_bool(args.get("auto_snapshot"), True)
                return self.session_mgr.bootstrap_readiness_regression_guard(
                    sid,
                    window=window,
                    auto_snapshot=auto_snapshot,
                )
            if action == "bootstrap_finalize_report":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                trend_window = _bounded_int(args.get("trend_window", 50), 50, min_value=2, max_value=10000)
                effectiveness_window = _bounded_int(args.get("effectiveness_window", 50), 50, min_value=1, max_value=10000)
                return self.session_mgr.bootstrap_finalize_report(
                    sid,
                    trend_window=trend_window,
                    effectiveness_window=effectiveness_window,
                )
            if action == "macro_set":
                macro_name = self._normalize_macro_name(
                    args.get("name") or args.get("macro")
                )
                if not macro_name:
                    return make_error(
                        MCPError.INVALID_ARGS, "name required for macro_set"
                    )
                macro_payload = args.get("data")
                if macro_payload is None:
                    macro_payload = args.get("macro_data")
                if macro_payload is None:
                    macro_payload = {
                        k: v
                        for k, v in args.items()
                        if k
                        not in (
                            "action",
                            "name",
                            "macro",
                            "data",
                            "macro_data",
                            "run_action",
                        )
                    }
                if not isinstance(macro_payload, dict):
                    return make_error(
                        MCPError.INVALID_ARGS, "macro payload must be an object"
                    )
                macro_key = macro_name.lower()
                self._session_macros[macro_key] = {
                    "name": macro_name,
                    "data": macro_payload,
                    "updated_at": datetime.now().isoformat(timespec="seconds"),
                }
                self._save_session_macros()
                return {
                    "ok": True,
                    "action": "macro_set",
                    "name": macro_name,
                    "data": macro_payload,
                }
            if action == "macro_get":
                macro_name = self._normalize_macro_name(
                    args.get("name") or args.get("macro")
                )
                if not macro_name:
                    return make_error(
                        MCPError.INVALID_ARGS, "name required for macro_get"
                    )
                entry = self._session_macros.get(macro_name.lower())
                if not entry:
                    return make_error(
                        MCPError.FILE_NOT_FOUND, f"Macro '{macro_name}' not found"
                    )
                return {"ok": True, "action": "macro_get", **entry}
            if action == "macro_list":
                macros = sorted(
                    [
                        {
                            "name": entry.get("name") or key,
                            "updated_at": entry.get("updated_at"),
                            "keys": sorted((entry.get("data") or {}).keys())[:32],
                        }
                        for key, entry in self._session_macros.items()
                        if isinstance(entry, dict)
                    ],
                    key=lambda m: str(m.get("name", "")).lower(),
                )
                return {
                    "ok": True,
                    "action": "macro_list",
                    "macros": macros,
                    "count": len(macros),
                }
            if action == "macro_delete":
                macro_name = self._normalize_macro_name(
                    args.get("name") or args.get("macro")
                )
                if not macro_name:
                    return make_error(
                        MCPError.INVALID_ARGS, "name required for macro_delete"
                    )
                removed = self._session_macros.pop(macro_name.lower(), None)
                if removed is None:
                    return make_error(
                        MCPError.FILE_NOT_FOUND, f"Macro '{macro_name}' not found"
                    )
                self._save_session_macros()
                return {"ok": True, "action": "macro_delete", "name": macro_name}
            if action == "macro_run":
                macro_name = self._normalize_macro_name(
                    args.get("name") or args.get("macro")
                )
                if not macro_name:
                    return make_error(
                        MCPError.INVALID_ARGS, "name required for macro_run"
                    )
                entry = self._session_macros.get(macro_name.lower())
                if not entry:
                    return make_error(
                        MCPError.FILE_NOT_FOUND, f"Macro '{macro_name}' not found"
                    )
                base_args = dict(entry.get("data") or {})
                run_action = (
                    args.get("run_action") or base_args.get("action") or "create"
                )
                if not isinstance(run_action, str) or not run_action.strip():
                    return make_error(
                        MCPError.INVALID_ARGS, "invalid run_action for macro_run"
                    )
                run_action = run_action.strip()
                if run_action.startswith("macro_"):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "macro_run cannot execute macro_* actions",
                    )
                if run_action not in TOOL_ACTIONS["session"]:
                    return make_error(
                        MCPError.ACTION_NOT_FOUND,
                        f"Unsupported run_action '{run_action}' for macro_run",
                        hint=f"Valid session actions: {', '.join(TOOL_ACTIONS['session'])}",
                    )
                run_args = dict(base_args)
                for k, v in args.items():
                    if k in ("action", "name", "macro", "run_action"):
                        continue
                    run_args[k] = v
                run_args["action"] = run_action
                run_result = self._execute_tool("session", run_args)
                if isinstance(run_result, dict) and not run_result.get("error"):
                    run_result = dict(run_result)
                    run_result["macro"] = macro_name
                    run_result["run_action"] = run_action
                return run_result
            if action == "recent_workset":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "session_id required (or have an active session)",
                    )
                if not self.session_mgr.session_exists(sid):
                    return make_error(
                        MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                    )
                n = _bounded_int(args.get("n", 20), 20, min_value=1, max_value=200)
                include_bookmarks = _coerce_bool(args.get("include_bookmarks"), True)
                include_items = _coerce_bool(args.get("include_items"), False)
                return self._build_recent_workset(
                    sid,
                    n=n,
                    include_bookmarks=include_bookmarks,
                    include_items=include_items,
                )
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported session action: '{action}'",
                hint=f"Valid session actions: {', '.join(TOOL_ACTIONS['session'])}",
            )

        if tool_name == "truncation":
            action = args.get("action")
            if action == "continue":
                token = args.get("token")
                if not token:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "token required",
                        hint="Provide the 'token' from a previous truncated response's _continue field.",
                    )
                result = continue_truncated(
                    token,
                    field=args.get("field"),
                    offset=args.get("offset"),
                    count=args.get("count"),
                )
                if result.get("error"):
                    return make_error(
                        MCPError.TRUNCATION_TOKEN_INVALID,
                        result.get("message", "Invalid continuation request"),
                        details={k: v for k, v in result.items() if k != "error"},
                    )
                return result
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported truncation action: '{action}'",
                hint="The only valid action is 'continue'.",
            )

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
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported bookmark action: '{action}'",
                hint=f"Valid bookmark actions: {', '.join(TOOL_ACTIONS['bookmarks'])}",
            )

        if tool_name == "threat_hunt":
            return self._handle_threat_hunt(args)

        if tool_name == "predictor":
            return self._handle_predictor(args)

        if tool_name == "workflow":
            return self._handle_workflow(args)

        if tool_name == "blackboard":
            return self._handle_blackboard(args)

        if tool_name == "gadgets" and str(args.get("action") or "").strip() == "semantic_find":
            return self._handle_gadgets_semantic_find(args)

        legacy_threat_tools = {
            "trace",
            "trace_analysis",
            "coverage",
            "agent",
        }
        if tool_name in legacy_threat_tools:
            bridged = dict(args or {})
            legacy_action = str(bridged.get("action") or "").strip()
            bridged["action"] = "legacy"
            bridged["legacy_tool"] = tool_name
            if legacy_action:
                bridged["legacy_action"] = legacy_action
            bridged.setdefault("legacy_passthrough", True)
            bridged.setdefault("include_evidence", False)
            bridged.setdefault("profile", "balanced")
            result = self._handle_threat_hunt(bridged)
            if isinstance(result, dict) and result.get("ok"):
                result = dict(result)
                result["legacy_tool"] = tool_name
                if legacy_action:
                    result["legacy_action"] = legacy_action
            return result

        ip = args.pop(
            "idb", self.current_session.idb_path if self.current_session else None
        )
        if not ip:
            return make_error(
                MCPError.SESSION_REQUIRED,
                "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
            )
        return self.call_tool(tool_name, ip, **args)

    def handle_request(self, req):
        m, rid, p = req.get("method"), req.get("id"), req.get("params", {})
        if m == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                    },
                    "serverInfo": {"name": "ida-pro-mcp", "version": "3.0.0"},
                },
            }
        if rid is None:
            return None
        if m == "tools/list":
            mode = self.default_tools_list_mode
            if self.monolithic_tool_descriptions:
                mode = "full"
            tool_name_prefix = str(p.get("prefix", "") or "").strip().lower()
            tool_name_contains = str(p.get("contains", "") or "").strip().lower()
            tool_category = str(p.get("category", "") or "").strip().lower()
            sort_by = str(p.get("sort", "name") or "name").strip().lower()
            if sort_by not in {"name", "category"}:
                sort_by = "name"
            descending = _coerce_bool(p.get("descending"), False)
            limit = _bounded_int(p.get("limit", 0), 0, min_value=0, max_value=5000)
            offset = _bounded_int(p.get("offset", 0), 0, min_value=0, max_value=500000)

            tools = self._build_tools_list_catalog(mode)
            if tool_name_prefix:
                tools = [
                    t
                    for t in tools
                    if str(t.get("name", "")).lower().startswith(tool_name_prefix)
                ]
            if tool_name_contains:
                tools = [
                    t
                    for t in tools
                    if tool_name_contains in str(t.get("name", "")).lower()
                ]
            if tool_category:
                tools = [
                    t
                    for t in tools
                    if str(t.get("category", "")).lower() == tool_category
                ]

            if sort_by == "category":
                tools = sorted(
                    tools,
                    key=lambda t: (str(t.get("category", "")), str(t.get("name", ""))),
                    reverse=descending,
                )
            else:
                tools = sorted(
                    tools, key=lambda t: str(t.get("name", "")), reverse=descending
                )

            total = len(tools)
            if limit > 0:
                tools_page = tools[offset : offset + limit]
                next_offset = (
                    (offset + len(tools_page))
                    if (offset + len(tools_page)) < total
                    else None
                )
            else:
                tools_page = tools[offset:]
                next_offset = None
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "tools": tools_page,
                    "getting_started": {
                        "intent": "If you are an LLM new to this MCP, run these first.",
                        "first_calls": [
                            "ida://state",
                            "llm_helpers(action='bootstrap')",
                            "llm_helpers(action='cheatsheet')",
                            "blackboard(action='frontier', limit=10)",
                        ],
                    },
                    "mode": mode,
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                    "next_offset": next_offset,
                },
            }
        if m == "tools/call":
            tn, args = p.get("name"), p.get("arguments", {})
            resolved_tn = _resolve_tool_alias(tn)
            if isinstance(args, dict):
                call_args, response_opts = self._extract_response_options(args)
            else:
                call_args = args
                response_opts = self._default_response_options()
            if resolved_tn == "batch":
                if not isinstance(call_args, dict):
                    res = make_error(
                        MCPError.INVALID_ARGS, "arguments must be an object"
                    )
                else:
                    res = self._handle_batch(call_args)
            else:
                res = self._execute_tool(tn, call_args)
                # MemRL observation: compare next call bridges with injected entries
                if isinstance(call_args, dict):
                    self._observe_memrl(
                        resolved_tn or str(tn or ""),
                        str(call_args.get("action") or ""),
                        res if isinstance(res, dict) else {},
                    )
                    res = self._cache_next_page(resolved_tn or "", call_args, res)
                    self._record_activity(resolved_tn or "", call_args, res)
            res = self._prepare_response_payload(
                res,
                response_opts,
                tool_name=resolved_tn or str(tn or ""),
                call_args=call_args,
            )
            is_error = bool(isinstance(res, dict) and res.get("error"))
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": self._serialize_payload(res, response_opts),
                        }
                    ],
                    "isError": is_error,
                },
            }
        if m == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "resources": list_resources(),
                },
            }
        if m == "resources/read":
            uri = p.get("uri", "")
            resolver = ResourceResolver(
                lambda name, kwargs: self._execute_tool(name, kwargs),
                insight_index=self._insight_index,
                global_facts=self._global_facts,
                session_mgr=self.session_mgr,
                engine=self._analysis_engines.get(
                    getattr(self, "current_session", None) or ""
                ),
                bb_path=os.path.join(
                    self.cache_dir,
                    f"{getattr(self, 'current_session', '') or ''}.blackboard.db"
                ),
                usage_intel=getattr(self, "_usage_intel", None),
            )
            resource = resolver.read(uri)
            if resource is None:
                return {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {"code": -32602, "message": f"Resource not found: {uri}"},
                }
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": resource.get("mimeType", "application/json"),
                            "text": resource.get("text", ""),
                        }
                    ],
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
        self._rs = rs  # store for _send_notification
        # Now that _rs is available, wire notify_fn into usage intelligence and start it
        if self._usage_intel:
            self._usage_intel._notify = self._send_notification
            self._usage_intel.start()
        try:
            while True:
                if self._shutdown_requested:
                    break
                try:
                    line = si.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    req_obj = None
                    req_id = None
                    try:
                        req_obj = json.loads(line.decode("utf-8"))
                        if isinstance(req_obj, dict):
                            req_id = req_obj.get("id")
                    except Exception as e:
                        err = {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {"code": -32700, "message": f"Parse error: {e}"},
                        }
                        output = (
                            json.dumps(err, ensure_ascii=False, separators=(",", ":"))
                            + "\n"
                        ).encode("utf-8")
                        rs.write(output)
                        rs.flush()
                        continue
                    try:
                        resp = self.handle_request(req_obj)
                    except Exception as e:
                        resp = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {"code": -32000, "message": f"Internal server error: {e}"},
                        }
                    if resp:
                        output = (
                            json.dumps(resp, ensure_ascii=False, separators=(",", ":"))
                            + "\n"
                        ).encode("utf-8")
                        rs.write(output)
                        rs.flush()
                except Exception as e:
                    if self._shutdown_requested:
                        break
                    err = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32000, "message": f"Unhandled server loop error: {e}"},
                    }
                    try:
                        output = (
                            json.dumps(err, ensure_ascii=False, separators=(",", ":"))
                            + "\n"
                        ).encode("utf-8")
                        rs.write(output)
                        rs.flush()
                    except Exception:
                        pass
                    continue
        finally:
            self.shutdown()

    def _send_notification(self, notification: dict) -> None:
        """Send an unsolicited MCP notification to the client (no id field = notification)."""
        try:
            rs = getattr(self, "_rs", None)
            if rs is None:
                return
            output = (
                json.dumps(notification, ensure_ascii=False, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            rs.write(output)
            rs.flush()
        except Exception:
            pass


def _trigger_session_diff(old_idb: str, new_idb: str) -> None:
    import threading
    def _diff():
        try:
            from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, FunctionEmbeddingIndex
        except ImportError:
            return
        try:
            embedder = BgeCodeEmbedder()
            new_idx = FunctionEmbeddingIndex(new_idb + ".embeddings.db", embedder)
            old_idx = FunctionEmbeddingIndex(old_idb + ".embeddings.db", embedder)
            if new_idx.size == 0 or old_idx.size == 0:
                return
            new_only = []
            for ea, vec in list(new_idx._cache.items())[:200]:
                matches = old_idx.similar_vec(vec, top_k=1, threshold=0.0)
                if not matches:
                    new_only.append(ea)
            if new_only:
                try:
                    from ida_pro_mcp.ida_mcp.tools.blackboard import BlackboardStore
                    store = BlackboardStore()
                    store.write(
                        title=f"Session diff: {len(new_only)} new/changed functions vs previous session",
                        content=str(new_only[:20]),
                        category="session_diff",
                        tags=["auto", "diff", "session"],
                        confidence=0.8,
                        source="session_diff",
                    )
                except Exception:
                    pass
        except Exception:
            pass
    threading.Thread(target=_diff, daemon=True, name="session-diff").start()


if __name__ == "__main__":
    try:
        server = IDAMCPServer()
        server.run()
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)
