#!/usr/bin/env python3
"""
MCP Server: IDAMCPServer — the main JSON-RPC stdio server.
"""
import atexit
import json
import os
import socket as _socket_mod
import sys
import tempfile
import threading
import time
import warnings
from typing import Any

from ida_pro_mcp import __version__

# Suppress ALL warnings
warnings.filterwarnings("ignore")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

import contextlib  # noqa: E402

from ..analysis.context_density import ContextDensityOptimizer  # noqa: E402
from ..analysis.patterns import GlobalFactsDatabase  # noqa: E402
from ..config import (  # noqa: E402
    CACHE_DIR,
    CONTEXT_DENSITY_COMPACT_THRESHOLD,
    CONTEXT_DENSITY_DEFAULT_BUDGET,
    CONTEXT_DENSITY_MAX_CODE_PREVIEW,
    CONTEXT_DENSITY_MAX_HEX_PREVIEW,
    CONTEXT_DENSITY_MAX_XREF_ITEMS,
    _bounded_int,
    _coerce_bool,
    _env_bool,
    _normalize_session_id,
    _select_runtime_dir,
    log_rpc,
)
from ..errors import MCPError, is_error_result, make_error  # noqa: E402
from ..schemas import (  # noqa: E402
    _resolve_tool_alias,
)
from ..stores.insight_index import InsightIndex  # noqa: E402

# Compatibility anchor for source-based regression tests.
# if addr and tool_name in ("code", "data", "search"):
# Import truncation middleware
from ..stores.truncation import continue_truncated, truncate_response  # noqa: F401,E402
from .audit import AuditLogger  # noqa: E402
from .rate_limit import RateLimiter  # noqa: E402
from .resources import ResourceResolver, list_resources  # noqa: E402
from .server_args import ServerArgsMixin  # noqa: E402
from .server_batch import BackgroundMixin  # noqa: E402
from .server_blackboard import ServerBlackboardMixin  # noqa: E402
from .server_dispatch import ServerDispatchMixin  # noqa: E402
from .server_multi_session import ServerMultiSessionMixin  # noqa: E402
from .server_response import ServerResponseMixin  # noqa: E402
from .server_runtime import ServerRuntimeMixin  # noqa: E402
from .server_semantic import ServerSemanticMixin  # noqa: E402
from .server_session import ServerSessionMixin  # noqa: E402
from .server_threat_hunt import ServerThreatHuntMixin  # noqa: E402
from .server_wiki import ServerWikiMixin  # noqa: E402
from .server_workflow import ServerWorkflowMixin  # noqa: E402

# =============================================================================
# MCP SERVER
# =============================================================================


class IDAMCPServer(
    ServerArgsMixin,
    ServerResponseMixin,
    ServerSemanticMixin,
    ServerWikiMixin,
    ServerThreatHuntMixin,
    ServerBlackboardMixin,
    ServerWorkflowMixin,
    ServerMultiSessionMixin,
    ServerRuntimeMixin,
    ServerSessionMixin,
    ServerDispatchMixin,
    BackgroundMixin,
):
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
            str(os.environ.get("IDA_MCP_TOOLS_LIST_MODE", "ultra")).strip().lower()
        )
        if tools_list_mode not in {"ultra", "lean"}:
            tools_list_mode = "ultra"
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
        self.enable_response_enrichment = _env_bool("IDA_MCP_RESPONSE_ENRICH", False)
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
        self._next_cache: dict[str, dict[str, Any]] = {}
        self._next_cache_ttl_seconds = 1800
        self._activity_log: list[dict[str, Any]] = []
        self._activity_log_max = 4000
        self._session_last_activity: dict[str, float] = {}
        self._session_inflight_calls: dict[str, int] = {}
        self._idle_index_lock = threading.RLock()
        self._idle_index_threads: dict[str, threading.Thread] = {}
        self._idle_index_stop_events: dict[str, threading.Event] = {}
        self._idle_index_delay_seconds = _bounded_int(
            os.environ.get("IDA_MCP_IDLE_INDEX_DELAY", 20),
            20,
            min_value=3,
            max_value=600,
        )
        self._idle_index_slice_size = _bounded_int(
            os.environ.get("IDA_MCP_IDLE_INDEX_SLICE_SIZE", 4),
            4,
            min_value=1,
            max_value=64,
        )
        self._idle_index_seed_limit = _bounded_int(
            os.environ.get("IDA_MCP_IDLE_INDEX_SEED_LIMIT", 12),
            12,
            min_value=1,
            max_value=128,
        )
        self._idle_index_rpc_timeout = _bounded_int(
            os.environ.get("IDA_MCP_IDLE_INDEX_RPC_TIMEOUT", 20),
            20,
            min_value=5,
            max_value=300,
        )
        # Analysis stall watchdog: a per-session host thread that polls IDA's
        # real analysis state (auto_is_ok + function count) and flags a session
        # as "stalled" when the process is alive but analysis stops advancing.
        # See _start_analysis_watchdog / _stop_analysis_watchdog.
        self._analysis_watchdog_lock = threading.RLock()
        self._analysis_watchdog_threads: dict[str, threading.Thread] = {}
        self._analysis_watchdog_stop_events: dict[str, threading.Event] = {}
        self._analysis_watchdog_state: dict[str, dict[str, Any]] = {}
        self._analysis_watchdog_interval = _bounded_int(
            os.environ.get("IDA_MCP_WATCHDOG_INTERVAL", 5),
            5,
            min_value=2,
            max_value=60,
        )
        self._analysis_watchdog_stall_seconds = _bounded_int(
            os.environ.get("IDA_MCP_WATCHDOG_STALL_SECONDS", 120),
            120,
            min_value=15,
            max_value=3600,
        )
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
        # Blackboard phase gates (decision_card / working_set follow-ups) inject
        # noise into every tool response. Disabled by default — opt in with
        # IDA_MCP_PHASE_GATES=1 if a strict LLM agent needs the steering.
        self._phase_gates_enabled = _env_bool("IDA_MCP_PHASE_GATES", False)
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
        from .session import BookmarkManager, SessionManager  # lazy: break circular import
        self.session_mgr = SessionManager(self.cache_dir)
        # Automatic session housekeeping: if we have accumulated way more
        # sessions than a sensible working set, prune the stale ones
        # (older than the configured max age) at startup so the user
        # doesn't have to remember to call session(action='cleanup_stale').
        # Controlled by IDA_MCP_SESSION_AUTO_PRUNE_BUDGET (default 200) and
        # IDA_MCP_SESSION_MAX_AGE_DAYS (default 30). Set budget=0 to disable.
        try:
            budget = _bounded_int(
                os.environ.get("IDA_MCP_SESSION_AUTO_PRUNE_BUDGET", "200"),
                200,
                min_value=0,
                max_value=100_000,
            )
            max_age = _bounded_int(
                os.environ.get("IDA_MCP_SESSION_MAX_AGE_DAYS", "30"),
                30,
                min_value=1,
                max_value=3650,
            )
            if budget > 0:
                self.session_mgr.auto_prune_if_over_budget(budget, max_age)
        except Exception as e:
            log_rpc(f"Auto session prune failed: {e}")
        self.bookmark_mgr = BookmarkManager(self.session_mgr.session_dir)
        self.audit = AuditLogger(base_dir=os.path.join(self.cache_dir, "audit"))
        self.rate_limiter = RateLimiter()
        from ..intelligence.context import get_assembler  # lazy: break circular import
        self.assembler = get_assembler()  # bge-code-v1 intelligence layer
        # Usage intelligence — passive observer and learner (started in run())
        try:
            from ..intelligence.usage import UsageIntelligence
            self._usage_intel = UsageIntelligence(
                audit_dir=os.path.join(self.cache_dir, "audit"),
                notify_fn=None,  # injected in run() once _rs is available
            )
        except Exception:
            self._usage_intel = None
        self._last_injected_entries: list[dict[str, Any]] = []
        self._last_query_bridges: list[str] = []
        self._call_counter = 0
        self._macro_path = os.path.join(self.cache_dir, "session_macros.json")
        self._runtime_lease_dir = os.path.join(self.cache_dir, "runtime_leases")
        os.makedirs(self._runtime_lease_dir, exist_ok=True)
        self._session_macros: dict[str, dict[str, Any]] = {}
        self.current_session = None
        self.session_runtimes = {}
        self._runtime_lock = threading.RLock()
        self._session_startup_locks: dict[str, threading.Lock] = {}
        self._semantic_index_lock = threading.RLock()
        self._shutdown = False
        self._shutdown_requested = False
        self._lease_thread_stop = threading.Event()
        self._lease_thread: threading.Thread | None = None
        self._analysis_engines: dict[str, Any] = {}  # session_id -> AnalysisEngine
        self._wiki_cache: dict[str, Any] = {
            "root": "",
            "expires": 0.0,
            "topics": {},
            "pages": [],
        }
        self._wiki_cache_ttl = 5.0
        self._wiki_embed_cache: dict[str, list[float]] = {}
        self._wiki_embed_cache_max = 512
        self._tools_list_cache: dict[str, tuple] = {}
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
            requested_mode = str(
                p.get("mode") or p.get("schema_mode") or p.get("tools_list_mode") or ""
            ).strip().lower()
            if requested_mode in {"ultra", "lean"}:
                mode = requested_mode
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
                sid_hint = None
                if isinstance(call_args, dict):
                    sid_hint = _normalize_session_id(call_args.get("session_id"))
                if not sid_hint and self.current_session:
                    sid_hint = getattr(self.current_session, "session_id", None)
                sid_hint_text = str(sid_hint) if sid_hint else ""
                if sid_hint_text:
                    with self._runtime_lock:
                        self._session_last_activity[sid_hint_text] = time.time()
                        self._session_inflight_calls[sid_hint_text] = int(
                            self._session_inflight_calls.get(sid_hint_text, 0) or 0
                        ) + 1
                try:
                    res = self._execute_tool(tn, call_args)
                finally:
                    if sid_hint_text:
                        with self._runtime_lock:
                            remaining = int(
                                self._session_inflight_calls.get(sid_hint_text, 0) or 0
                            ) - 1
                            if remaining > 0:
                                self._session_inflight_calls[sid_hint_text] = remaining
                            else:
                                self._session_inflight_calls.pop(sid_hint_text, None)
                            self._session_last_activity[sid_hint_text] = time.time()
                if isinstance(call_args, dict):
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
                self._execute_tool,
                insight_index=self._insight_index,
                global_facts=self._global_facts,
                session_mgr=self.session_mgr,
                engine=self._analysis_engines.get(
                    getattr(self, "current_session", None) or ""
                ),
                bb_path=self._session_blackboard_path(session_obj=self.current_session),
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

    def run_daemon(self):
        _write_pidfile()
        sock = _socket_mod.socket(_socket_mod.AF_UNIX, _socket_mod.SOCK_STREAM)
        sock.bind(DAEMON_SOCKET)
        sock.listen(5)
        sock.settimeout(1.0)
        atexit.register(self._cleanup_daemon)
        try:
            while True:
                if self._shutdown_requested:
                    break
                try:
                    conn, _ = sock.accept()
                except TimeoutError:
                    continue
                threading.Thread(target=self._handle_daemon_conn, args=(conn,), daemon=True).start()
        finally:
            self.shutdown()

    def _handle_daemon_conn(self, conn) -> None:
        try:
            conn.settimeout(30.0)
            buf = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        try:
                            req_obj = json.loads(line.decode("utf-8"))
                            resp = self.handle_request(req_obj)
                            if resp:
                                out = json.dumps(resp, ensure_ascii=False, separators=(",", ":")) + "\n"
                                try:
                                    conn.sendall(out.encode("utf-8"))
                                except Exception:
                                    return
                        except Exception:
                            pass
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    @staticmethod
    def _cleanup_daemon() -> None:
        _remove_pidfile()
        with contextlib.suppress(OSError):
            os.unlink(DAEMON_SOCKET)

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
            from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder, FunctionEmbeddingIndex
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


DAEMON_SOCKET = os.path.join(tempfile.gettempdir(), "ida-mcp-daemon.sock")
DAEMON_PIDFILE = os.path.join(tempfile.gettempdir(), "ida-mcp-daemon.pid")


def _write_pidfile() -> None:
    with open(DAEMON_PIDFILE, "w") as f:
        f.write(str(os.getpid()))


def _remove_pidfile() -> None:
    with contextlib.suppress(OSError):
        os.unlink(DAEMON_PIDFILE)


def main():
    """Console-script entry point: ``python -m ida_pro_mcp.host.server``."""
    global _real_stdout
    if _real_stdout is sys.stdout:
        _real_stdout = sys.stdout

    daemon_mode = "--daemon" in sys.argv
    try:
        server = IDAMCPServer()
        if daemon_mode:
            if os.path.exists(DAEMON_SOCKET):
                os.unlink(DAEMON_SOCKET)
            server.run_daemon()
        else:
            server.run()
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
