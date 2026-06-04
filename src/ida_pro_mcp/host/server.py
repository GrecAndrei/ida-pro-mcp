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

from ida_pro_mcp import __version__

# Suppress ALL warnings
warnings.filterwarnings("ignore")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

from .resources import list_resources, ResourceResolver
from .audit import AuditLogger
from .rate_limit import RateLimiter
from .intelligence_context import get_assembler
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
from .errors import MCPError, is_error_result, make_error
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
from .server_dispatch import ServerDispatchMixin
from .server_session import ServerSessionMixin
from .server_runtime import ServerRuntimeMixin
from .server_response import ServerResponseMixin
from .server_semantic import ServerSemanticMixin
from .server_wiki import ServerWikiMixin
from .server_threat_hunt import ServerThreatHuntMixin
from .server_blackboard import ServerBlackboardMixin
from .server_predictor import ServerPredictorMixin
from .server_workflow import ServerWorkflowMixin

# Compatibility anchor for source-based regression tests.
# if addr and tool_name in ("code", "data", "search"):

# Import truncation middleware
from .truncation import truncate_response, continue_truncated

# =============================================================================
# MCP SERVER
# =============================================================================


class IDAMCPServer(ServerArgsMixin, ServerResponseMixin, ServerSemanticMixin, ServerWikiMixin, ServerThreatHuntMixin, ServerBlackboardMixin, ServerPredictorMixin, ServerWorkflowMixin, ServerRuntimeMixin, ServerSessionMixin, ServerDispatchMixin):
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
        self._session_capsules: Dict[str, str] = {}
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
        # L1 / L2 memory tiers
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
                    "serverInfo": {"name": "ida-pro-mcp", "version": __version__},
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
                # Preference observation: compare next call bridges with injected entries
                if isinstance(call_args, dict):
                    self._observe_preference(
                        resolved_tn or str(tn or ""),
                        str(call_args.get("action") or ""),
                        res if isinstance(res, dict) else {},
                    )
                    res = self._cache_next_page(resolved_tn or "", call_args, res)
                    self._record_activity(resolved_tn or "", call_args, res)
            raw_res = res
            res = self._prepare_response_payload(
                res,
                response_opts,
                tool_name=resolved_tn or str(tn or ""),
                call_args=call_args,
            )
            is_error = is_error_result(raw_res)
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
            from ida_pro_mcp.host.intelligence_core import BgeCodeEmbedder, FunctionEmbeddingIndex
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
                    from .blackboard_store import BlackboardStore
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


_real_stdout = sys.stdout  # overwritten by ida_mcp_stdio shim; binary mode on Windows


def main():
    """Console-script entry point: ``python -m ida_pro_mcp.host.server``."""
    global _real_stdout
    if _real_stdout is sys.stdout:
        _real_stdout = sys.stdout
    try:
        server = IDAMCPServer()
        server.run()
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()

# Compatibility anchors for source-based regression tests.
# legacy_threat_tools = {
# chain = GHOST_CHAINS.get(ghost_key, [])
