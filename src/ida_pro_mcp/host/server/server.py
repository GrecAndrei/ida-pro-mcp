#!/usr/bin/env python3
"""
MCP Server: IDAMCPServer — the main JSON-RPC stdio server.
"""
import atexit
import contextvars
import json
import os
import socket as _socket_mod
import sys
import tempfile
import threading
import time
import uuid
from typing import Any

from ida_pro_mcp import __version__

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

_VERTEX_COMPAT_CLIENT_MARKERS = ("gemini", "antigravity", "opencode")

import contextlib  # noqa: E402

from ..agent_operations import (  # noqa: E402
    adapt_agent_error_payload,
    build_agent_help,
    get_agent_operation,
    translate_public_batch_arguments,
)
from ..analysis.context_density import ContextDensityOptimizer  # noqa: E402
from ..analysis.patterns import GlobalFactsDatabase  # noqa: E402
from ..config import (  # noqa: E402
    ANALYSIS_CONFIRM_POLLS,
    CACHE_DIR,
    CHECKPOINT_SAVE_SECONDS,
    CONTEXT_DENSITY_COMPACT_THRESHOLD,
    CONTEXT_DENSITY_DEFAULT_BUDGET,
    CONTEXT_DENSITY_MAX_CODE_PREVIEW,
    CONTEXT_DENSITY_MAX_HEX_PREVIEW,
    CONTEXT_DENSITY_MAX_XREF_ITEMS,
    LARGE_IDB_SHUTDOWN_GRACE_SECONDS,
    SAFE_MODE_POLL_SECONDS,
    SAFE_MODE_WATCH_SECONDS,
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
from .audit import AuditLogger  # noqa: E402
from .rate_limit import RateLimiter  # noqa: E402
from .server_args import ServerArgsMixin  # noqa: E402
from .server_batch import BackgroundMixin  # noqa: E402
from .server_blackboard import ServerBlackboardMixin  # noqa: E402
from .server_client_state import (  # noqa: E402
    ServerClientStateMixin,
    _ClientRequestState,
)
from .server_dispatch import ServerDispatchMixin  # noqa: E402
from .server_multi_session import ServerMultiSessionMixin  # noqa: E402
from .server_r2 import ServerR2Mixin  # noqa: E402
from .server_response import ServerResponseMixin  # noqa: E402
from .server_runtime import ServerRuntimeMixin  # noqa: E402
from .server_semantic import ServerSemanticMixin  # noqa: E402
from .server_session import ServerSessionMixin  # noqa: E402
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
    ServerBlackboardMixin,
    ServerWorkflowMixin,
    ServerMultiSessionMixin,
    ServerRuntimeMixin,
    ServerSessionMixin,
    ServerR2Mixin,
    ServerDispatchMixin,
    BackgroundMixin,
    ServerClientStateMixin,
):
    """
    JSON-RPC stdio server for the IDA Pro MCP.
    """

    _atexit_registered = False
    _blackboard_module = None
    _blackboard_store = None

    # Cap on per-session InsightIndex instances kept in memory. When exceeded
    # the oldest (by dict insertion order) index is persisted and evicted so a
    # long-lived daemon process does not accumulate one unbounded index per
    # session forever.
    _MAX_INSIGHT_INDEXES = 32

    @property
    def _last_spawn_error(self):
        return self._client_request_state().last_spawn_error

    @_last_spawn_error.setter
    def _last_spawn_error(self, value) -> None:
        self._client_request_state().last_spawn_error = value

    def _insight_index_for_session(self, session=None) -> InsightIndex:
        session = session if session is not None else getattr(self, "current_session", None)
        sid = str(getattr(session, "session_id", "") or "").strip().upper()
        if not sid:
            sid = "_GLOBAL"
        indexes = getattr(self, "_insight_indexes", None)
        if not isinstance(indexes, dict):
            self._insight_indexes = {}
            indexes = self._insight_indexes
        if sid not in indexes:
            index_dir = os.path.join(self.cache_dir, "insight_indexes")
            os.makedirs(index_dir, exist_ok=True)
            with self._insight_index_lock:
                # Re-check under the lock: another thread may have created it.
                if sid not in indexes:
                    # Evict the oldest cached index when at the cap so a
                    # long-lived daemon does not accumulate unbounded
                    # per-session state.
                    while len(indexes) >= self._MAX_INSIGHT_INDEXES:
                        _oldest_sid, _oldest = next(iter(indexes.items()))
                        with contextlib.suppress(Exception):
                            _oldest.save()
                        del indexes[_oldest_sid]
                    indexes[sid] = InsightIndex(
                        persistence_path=os.path.join(index_dir, f"{sid}.json")
                    )
        return indexes[sid]

    @property
    def _insight_index(self) -> InsightIndex:
        return self._insight_index_for_session()

    @_insight_index.setter
    def _insight_index(self, value: InsightIndex) -> None:
        session = getattr(self, "current_session", None)
        sid = str(getattr(session, "session_id", "") or "").strip().upper() or "_GLOBAL"
        if not isinstance(getattr(self, "_insight_indexes", None), dict):
            self._insight_indexes = {}
        self._insight_indexes[sid] = value

    @property
    def vertex_compat(self) -> bool:
        return self._client_request_state().vertex_compat

    @vertex_compat.setter
    def vertex_compat(self, value: Any) -> None:
        self._client_request_state().vertex_compat = bool(value)

    def __init__(self):
        # A ContextVar is empty in newly spawned daemon threads.  Seed the
        # construction thread for regular stdio and direct in-process callers.
        self._client_request_state_var: contextvars.ContextVar[_ClientRequestState | None] = (
            contextvars.ContextVar(
                f"ida_mcp_client_request_state_{id(self):x}", default=None
            )
        )
        self._client_request_state_var.set(_ClientRequestState())
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
        tool_surface = str(os.environ.get("IDA_MCP_TOOL_SURFACE", "agent")).strip().lower()
        if tool_surface not in {"agent", "legacy"}:
            tool_surface = "agent"
        detail_level = (
            str(os.environ.get("IDA_MCP_ERROR_DETAIL_LEVEL", "basic")).strip().lower()
        )
        if detail_level not in {"none", "basic", "full"}:
            detail_level = "basic"
        self.default_response_mode = mode
        self.default_qol_mode = qol_mode
        self.default_tools_list_mode = tools_list_mode
        self.tool_surface = tool_surface
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
        # Lifecycle knobs, exposed as instance attributes so per-session paths
        # (server_session / server_runtime) read them via getattr with the
        # module constant as fallback. All parsed tolerantly in config.py so a
        # malformed env value degrades to the default instead of crashing.
        self.safe_mode_poll_seconds = SAFE_MODE_POLL_SECONDS
        self.safe_mode_watch_seconds = SAFE_MODE_WATCH_SECONDS
        self.analysis_confirm_polls = ANALYSIS_CONFIRM_POLLS
        self.checkpoint_save_seconds = CHECKPOINT_SAVE_SECONDS
        self.large_idb_shutdown_grace_seconds = LARGE_IDB_SHUTDOWN_GRACE_SECONDS
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
        self.default_vertex_compat = _env_bool(
            "IDA_MCP_VERTEX_COMPAT",
            False,
        )
        self.vertex_compat = self.default_vertex_compat
        # structuredContent duplicates the text block in many MCP clients.
        # Keep it opt-in for machine consumers that need exact field access.
        self.include_structured_content = _env_bool(
            "IDA_MCP_STRUCTURED_CONTENT",
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
        # sessions than a sensible working set, prune them at startup so the
        # user doesn't have to remember to call session(action='cleanup_stale').
        # Controlled by IDA_MCP_SESSION_AUTO_PRUNE_BUDGET (default 200),
        # IDA_MCP_SESSION_MAX_AGE_DAYS (default 30), and
        # IDA_MCP_SESSION_PRUNE_MIN_IDLE_DAYS (default 7 — budget-bounding
        # never deletes a session accessed more recently than this, so the
        # active working set can never be wiped by a shared-cache construction).
        # Set budget=0 to disable.
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
            min_idle = _bounded_int(
                os.environ.get("IDA_MCP_SESSION_PRUNE_MIN_IDLE_DAYS", "7"),
                7,
                min_value=0,
                max_value=3650,
            )
            if budget > 0:
                self.session_mgr.auto_prune_if_over_budget(
                    budget, max_age, min_idle_days=min_idle
                )
        except Exception as e:
            log_rpc(f"Auto session prune failed: {e}")
        # Restore the per-session analysis gate AFTER auto-prune so sessions
        # deleted for budget/age are never gated. A session whose metadata
        # records 'complete' resumes ungated; every other session resumes
        # gated in safe mode so a half-analyzed IDB is never exposed to
        # full-binary analysis after a host restart (D3-F1).
        self._restore_analysis_gates_from_metadata()
        self.bookmark_mgr = BookmarkManager(self.session_mgr.session_dir)
        self.audit = AuditLogger(base_dir=os.path.join(self.cache_dir, "audit"))
        # AuditLogger.close() is idempotent, so registering it atexit covers
        # every exit path (normal shutdown, exceptions, os._exit paths).
        atexit.register(self.audit.close)
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
        # Per-session count of enriched responses already served, used to
        # honor the "session resume context: first 2 calls only" gate.
        self._session_resume_calls: dict[str, int] = {}
        self._session_resume_calls_lock = threading.Lock()
        # Runtime leases are shared by independently launched MCP hosts that
        # use the same durable cache.  This identity prevents one live host
        # from cleaning up another live host's IDA process.
        self._runtime_owner_id = uuid.uuid4().hex
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
        self._wiki_cache: dict[str, Any] = {
            "root": "",
            "expires": 0.0,
            "topics": {},
            "pages": [],
        }
        self._wiki_cache_ttl = 5.0
        self._wiki_cache_lock = threading.Lock()
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
        self._insight_indexes: dict[str, InsightIndex] = {}
        self._insight_index_lock = threading.Lock()
        self._global_facts = GlobalFactsDatabase(
            db_path=os.path.join(self.cache_dir, "global_facts.db")
        )
        self._register_lifecycle_handlers()
        self._start_runtime_lease_heartbeat()
        self._adopt_or_cleanup_stale_runtime_leases()
        self._load_session_macros()

    # ------------------------------------------------------------------
    # Analysis-gate persistence & restart restore
    #
    # The safe-mode state sets (_pending_analysis / _analysis_complete_sessions)
    # are in-memory and lazily initialized, so a host restart starts with an
    # empty gate. The gate is persisted per-session in metadata['analysis_gate']
    # on every pending/complete transition by the server_session mixin
    # (_mark_analysis_pending/_mark_analysis_complete/_persist_analysis_gate —
    # this module does not shadow those). This module owns the pieces the
    # mixin does not: restoring the gate in __init__ so a half-analyzed IDB
    # stays gated after a restart (D3-F1) while a completed IDB resumes
    # ungated, writing the final gate at shutdown, arming the completion
    # watcher on a restored session's first touch (restore never spawns), and
    # stopping completion watchers/background spawns during teardown.
    # ------------------------------------------------------------------

    def _restore_analysis_gates_from_metadata(self) -> None:
        """Rehydrate the per-session analysis gate from persisted metadata.

        'complete' resumes ungated; 'pending' or an absent record resumes
        gated (fail-safe: an unverified IDB is never exposed to full-binary
        analysis). Watchers are deliberately NOT spawned here — a restarted
        host may have hundreds of loaded sessions whose runtimes are dead, so
        each would only spin a polling thread until its re-arm window. The
        watcher is armed on the session's first touch via
        _arm_analysis_watcher_if_needed.
        """
        sessions = getattr(self.session_mgr, "sessions", None)
        if not isinstance(sessions, dict):
            return
        with self._analysis_state_lock():
            for sid, session in sessions.items():
                meta = getattr(session, "metadata", None)
                gate = meta.get("analysis_gate") if isinstance(meta, dict) else None
                if gate == "complete":
                    complete = getattr(self, "_analysis_complete_sessions", None)
                    if not isinstance(complete, set):
                        self._analysis_complete_sessions = set()
                        complete = self._analysis_complete_sessions
                    complete.add(sid)
                else:
                    pending = getattr(self, "_pending_analysis", None)
                    if not isinstance(pending, set):
                        self._pending_analysis = set()
                        pending = self._pending_analysis
                    pending.add(sid)

    def _persist_analysis_gates_on_shutdown(self) -> None:
        """Write the final gate for every tracked session before teardown.

        Must run BEFORE _stop_analysis_completion_watchers so the in-memory
        pending/complete sets still reflect the final state. Delegates the
        per-session write to the server_session mixin's _persist_analysis_gate
        (the canonical metadata['analysis_gate'] writer).
        """
        sessions = getattr(self.session_mgr, "sessions", None)
        if not isinstance(sessions, dict):
            return
        for sid, session in sessions.items():
            if self._analysis_is_complete(sid):
                self._persist_analysis_gate(session, "complete")
            elif self._safe_mode_active(sid):
                self._persist_analysis_gate(session, "pending")

    def _arm_analysis_watcher_if_needed(self, sid: str) -> None:
        """Arm the analysis-completion watcher for a pending session.

        Restore-at-startup never spawns watchers. The first touch that can
        make progress on a still-pending session — a status/state poll or a
        re-open — calls this to spawn the single completion watcher.
        """
        with self._analysis_state_lock():
            pending = getattr(self, "_pending_analysis", None)
            if not (isinstance(pending, set) and sid in pending):
                return
            watchers = getattr(self, "_analysis_watchers", None)
            if isinstance(watchers, set) and sid in watchers:
                return
        self._spawn_analysis_watcher(sid)

    def _stop_analysis_completion_watchers(self) -> None:
        """Stop analysis-completion watchers and background runtime spawns.

        The completion watchers (ida-an-<sid>) self-terminate on their next
        poll once their session leaves _pending_analysis, so clearing the
        pending markers is the deterministic stop signal. Background runtime
        spawns (ida-bg-<sid>) observe _shutdown_requested and bail before
        launching. This runs BEFORE the h02 runtime teardown so a background
        thread cannot re-spawn an IDA process after _cleanup_all_runtimes has
        finished killing them. The collections are cleared defensively
        (getattr + isinstance): safe-mode bookkeeping lives in server_session
        and evolves independently, so a missing/renamed collection is a no-op.
        """
        with self._analysis_state_lock():
            pending = getattr(self, "_pending_analysis", None)
            if isinstance(pending, set):
                pending.clear()
            watchers = getattr(self, "_analysis_watchers", None)
            if isinstance(watchers, set):
                watchers.clear()
            in_flight = getattr(self, "_analysis_complete_in_flight", None)
            if isinstance(in_flight, set):
                in_flight.clear()
            bg_errors = getattr(self, "_background_load_errors", None)
            if isinstance(bg_errors, dict):
                bg_errors.clear()

    def shutdown(self) -> None:
        """Deterministic shutdown: persist gates, stop watchers, then teardown."""
        if self._shutdown:
            return
        self._shutdown_requested = True
        with contextlib.suppress(Exception):
            self._persist_analysis_gates_on_shutdown()
        with contextlib.suppress(Exception):
            self._stop_analysis_completion_watchers()
        super().shutdown()













        # Do NOT raise SystemExit or KeyboardInterrupt - let run() loop exit gracefully











































    def handle_request(self, req):
        m, rid, p = req.get("method"), req.get("id"), req.get("params", {})
        if m == "initialize":
            client_info = p.get("clientInfo") if isinstance(p, dict) else None
            client_name = (
                str(client_info.get("name") or "").strip().lower()
                if isinstance(client_info, dict)
                else ""
            )
            if client_name and any(marker in client_name for marker in _VERTEX_COMPAT_CLIENT_MARKERS):
                # Existing Gemini configs may predate the installer setting
                # IDA_MCP_VERTEX_COMPAT. Detect the client during protocol
                # negotiation so its schemas and result formatting are still
                # compatible.
                self.vertex_compat = True
                self._tools_list_cache.clear()
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
                    "surface": self.tool_surface,
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                    "next_offset": next_offset,
                },
            }
        if m == "tools/call":
            tn, args = p.get("name"), p.get("arguments", {})
            public_tool_name = str(tn or "")
            operation = get_agent_operation(tn)
            resolved_tn = _resolve_tool_alias(tn)
            if isinstance(args, dict):
                call_args, response_opts = self._extract_response_options(args)
            else:
                call_args = args
                response_opts = self._default_response_options()

            # Agent SSO: a per-call ``agent`` tag is host-level identity, not
            # an IDA argument. Pop it before operation validation / policy so
            # it never reaches the backend, and validate it against the realm.
            agent_tag = None
            if isinstance(call_args, dict):
                agent_tag = str(call_args.pop("agent", "") or "").strip() or None

            precomputed_result = None
            if operation is not None:
                validation_error = operation.validate(call_args)
                if validation_error:
                    precomputed_result = validation_error
                elif operation.help_only:
                    precomputed_result = build_agent_help(call_args)
                else:
                    # The public operation is validated before translation.
                    # Backend calls still pass through their normal policy and
                    # RPC admission layers after this mapping.
                    tn, call_args = operation.to_backend_call(call_args)
                    resolved_tn = _resolve_tool_alias(tn)

            if precomputed_result is not None:
                res = precomputed_result
            elif resolved_tn == "batch":
                if not isinstance(call_args, dict):
                    res = make_error(
                        MCPError.INVALID_ARGS, "arguments must be an object"
                    )
                elif operation is not None and operation.name == "ida_batch":
                    call_args, batch_error = translate_public_batch_arguments(call_args)
                    res = (
                        batch_error
                        if batch_error
                        else self._call_as_agent(
                            agent_tag, lambda: self._handle_batch(call_args)
                        )
                    )
                else:
                    res = self._call_as_agent(
                        agent_tag, lambda: self._handle_batch(call_args)
                    )
            else:
                bind_err = (
                    self._bind_agent_call(agent_tag)
                    if agent_tag is not None
                    else None
                )
                if bind_err is not None:
                    res = bind_err
                else:
                    sid_hint_text = ""
                    try:
                        sid_hint = None
                        if isinstance(call_args, dict):
                            sid_hint = _normalize_session_id(
                                call_args.get("session_id")
                            )
                        if not sid_hint and self.current_session:
                            sid_hint = getattr(self.current_session, "session_id", None)
                        sid_hint_text = str(sid_hint) if sid_hint else ""
                        if sid_hint_text:
                            with self._runtime_lock:
                                self._session_last_activity[sid_hint_text] = time.time()
                                self._session_inflight_calls[sid_hint_text] = int(
                                    self._session_inflight_calls.get(sid_hint_text, 0) or 0
                                ) + 1
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
                        if agent_tag is not None:
                            self._unbind_agent_call()
                if isinstance(call_args, dict):
                    res = self._cache_next_page(resolved_tn or "", call_args, res)
                    self._record_activity(resolved_tn or "", call_args, res)
            raw_res = res
            if operation is not None:
                res = adapt_agent_error_payload(res, operation.name)
            res = self._prepare_response_payload(
                res,
                response_opts,
                tool_name=public_tool_name if operation is not None else (resolved_tn or str(tn or "")),
                call_args=call_args,
            )
            is_error = is_error_result(raw_res)
            # Text blocks are for models and people, so keep source code and
            # multiline strings readable for every MCP client. Structured
            # output is opt-in because sending both doubles context usage.
            safe_res = self._json_safe_value(res)
            structured = safe_res if isinstance(safe_res, dict) else {"result": safe_res}
            content_text = self._render_payload_text(safe_res)
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": content_text,
                    }
                ],
                "isError": is_error,
            }
            if self.include_structured_content:
                result["structuredContent"] = structured
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": result,
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
        print("ida-pro-mcp server ready", file=sys.stderr, flush=True)
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
        print("ida-pro-mcp daemon ready", file=sys.stderr, flush=True)
        sock = _socket_mod.socket(_socket_mod.AF_UNIX, _socket_mod.SOCK_STREAM)
        sock.bind(DAEMON_SOCKET)
        # A daemon can serve many independent MCP clients.  A larger backlog
        # avoids connection refusal bursts while IDA sessions are starting.
        sock.listen(128)
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
        state_token = self._begin_client_connection()
        try:
            # Keep long-lived MCP connections alive.  The old 30 second socket
            # timeout escaped the receive loop and disconnected idle clients.
            conn.settimeout(1.0)
            buf = b""
            while True:
                try:
                    chunk = conn.recv(65536)
                except TimeoutError:
                    if self._shutdown_requested:
                        break
                    continue
                if not chunk:
                    break
                buf += chunk
                # Bound the receive buffer: a peer that streams a gigantic
                # newline-less blob must not grow memory without limit.
                if len(buf) > _MAX_DAEMON_LINE_BYTES:
                    log_rpc("Daemon client line exceeded buffer cap; closing connection")
                    break
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        req_obj = None
                        try:
                            req_obj = json.loads(line.decode("utf-8"))
                            resp = self.handle_request(req_obj)
                            if resp:
                                out = json.dumps(resp, ensure_ascii=False, separators=(",", ":")) + "\n"
                                try:
                                    conn.sendall(out.encode("utf-8"))
                                except Exception:
                                    return
                        except Exception as exc:
                            error = {
                                "jsonrpc": "2.0",
                                "id": req_obj.get("id") if isinstance(req_obj, dict) else None,
                                "error": {
                                    "code": -32000,
                                    "message": f"Internal server error: {exc}",
                                },
                            }
                            with contextlib.suppress(Exception):
                                conn.sendall(
                                    (json.dumps(error, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
                                )
        except Exception as exc:
            log_rpc(f"Daemon client connection failed: {exc}")
        finally:
            with contextlib.suppress(Exception):
                conn.close()
            self._end_client_connection(state_token)

    @staticmethod
    def _cleanup_daemon() -> None:
        # Unlink the socket only if the recorded pid is still our own: a live
        # daemon that replaced us (or a fresh one that reclaimed a stale
        # socket) must never have its socket yanked out from under it.
        if _read_daemon_pidfile() == os.getpid():
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


_real_stdout = sys.stdout  # overwritten by ida_mcp_stdio shim; binary mode on Windows


DAEMON_SOCKET = os.path.join(tempfile.gettempdir(), "ida-mcp-daemon.sock")
DAEMON_PIDFILE = os.path.join(tempfile.gettempdir(), "ida-mcp-daemon.pid")

# Cap on a single daemon-client line (bytes buffered before a newline) so a
# peer streaming an unbounded newline-less blob cannot exhaust memory.
_MAX_DAEMON_LINE_BYTES = 4 * 1024 * 1024


def _write_pidfile() -> None:
    with open(DAEMON_PIDFILE, "w") as f:
        f.write(str(os.getpid()))


def _remove_pidfile() -> None:
    with contextlib.suppress(OSError):
        os.unlink(DAEMON_PIDFILE)


def _read_daemon_pidfile() -> int | None:
    """Return the pid recorded in DAEMON_PIDFILE, or None if absent/garbage.

    Never raises: a malformed or unreadable pidfile simply reads as "no
    recorded pid" (treated as stale at daemon start).
    """
    try:
        with open(DAEMON_PIDFILE, encoding="utf-8") as f:
            raw = f.read().strip()
        if not raw:
            return None
        pid = int(raw)
        return pid if pid > 0 else None
    except (OSError, ValueError):
        return None


def _pid_is_live(pid: int | None) -> bool:
    """Best-effort liveness probe for *pid* via ``os.kill(pid, 0)``.

    Signal 0 performs the permissions/Existence check without sending a
    signal. A pid that does not exist (ProcessLookupError) is dead; a pid we
    may not signal but that exists (PermissionError) is alive; a bogus pid
    (OSError/EINVAL, e.g. above pid_max) is treated as dead.
    """
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def main():
    """Console-script entry point: ``python -m ida_pro_mcp.host.server``."""
    global _real_stdout
    if _real_stdout is sys.stdout:
        _real_stdout = sys.stdout

    daemon_mode = "--daemon" in sys.argv
    if daemon_mode:
        # A second daemon must never reclaim a live daemon's socket. The
        # pidfile is authoritative: probe the recorded pid BEFORE touching
        # the socket. A live pid refuses to start (fail fast, before the
        # heavy IDAMCPServer construction); a stale pidfile (dead pid) is
        # reclaimed together with the stale socket it guarded.
        existing_pid = _read_daemon_pidfile()
        if _pid_is_live(existing_pid):
            sys.stderr.write(
                f"ida-pro-mcp daemon already running (pid {existing_pid}); "
                f"refusing to start a second instance\n"
            )
            sys.exit(1)
        _remove_pidfile()
        with contextlib.suppress(OSError):
            if os.path.exists(DAEMON_SOCKET):
                os.unlink(DAEMON_SOCKET)
    try:
        # Auto-enable the in-process native retrieval backend when
        # libmcp_llama.so is present and no backend is pinned.  The HTTP
        # llama-server path remains the fallback.  This runs only here, never
        # in tests (which construct IDAMCPServer directly).
        try:
            from ida_pro_mcp.host.intelligence.native import bootstrap_native_backend

            _native_report = bootstrap_native_backend()
            if _native_report.get("enabled"):
                sys.stderr.write(f"native retrieval backend: {_native_report.get('lib')}\n")
        except Exception as _native_exc:
            sys.stderr.write(f"native backend bootstrap skipped: {_native_exc}\n")
        server = IDAMCPServer()
        if daemon_mode:
            server.run_daemon()
        else:
            server.run()
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
