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


class IDAMCPServer(ServerArgsMixin, ServerResponseMixin, ServerSemanticMixin, ServerWikiMixin, ServerThreatHuntMixin, ServerBlackboardMixin, ServerPredictorMixin, ServerWorkflowMixin):
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

    def _runtime_lease_path(self, sid: str) -> str:
        return os.path.join(self._runtime_lease_dir, f"SID_{sid}.lease.json")

    def _write_runtime_lease_record(self, path: str, lease: dict) -> None:
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(lease, f, indent=2)
            os.replace(tmp, path)
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass

    def _write_runtime_lease(self, sid: str, runtime: dict) -> None:
        proc = runtime.get("process")
        if not proc:
            return
        lease = {
            "session_id": sid,
            "pid": int(proc.pid),
            "port": int(runtime.get("port") or 0),
            "idat_exe": str(self.idat_exe or ""),
            "updated_at": time.time(),
        }
        path = self._runtime_lease_path(sid)
        self._write_runtime_lease_record(path, lease)

    def _remove_runtime_lease(self, sid: str) -> None:
        try:
            os.remove(self._runtime_lease_path(sid))
        except OSError:
            pass

    def _kill_stale_pid(self, pid: int) -> bool:
        """Best-effort terminate a stale PID.

        Returns True when PID is already absent or was terminated.
        Returns False when the process state cannot be verified or terminated.
        """
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except Exception:
            return False
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return True
        except Exception:
            return False
        deadline = time.time() + PROCESS_TERMINATION_TIMEOUT_SECONDS
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            except Exception:
                return False
            time.sleep(0.1)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return True
        except Exception:
            return False
        try:
            os.kill(pid, 0)
            return False
        except ProcessLookupError:
            return True
        except Exception:
            return False

    def _is_expected_ida_process(self, pid: int, lease: dict) -> bool:
        if pid <= 0:
            return False
        if sys.platform != "linux":
            return True
        expected_path = str(
            lease.get("idat_exe") or getattr(self, "idat_exe", "") or ""
        ).strip()
        proc_exe = f"/proc/{pid}/exe"
        proc_cmdline = f"/proc/{pid}/cmdline"
        expected_names = {n.lower() for n in self._ida_binary_names()}
        if expected_path:
            expected_path = os.path.realpath(os.path.expanduser(expected_path))
            expected_names.add(os.path.basename(expected_path).lower())
        try:
            actual_exe = os.path.realpath(proc_exe)
        except Exception:
            actual_exe = ""
        if actual_exe:
            base = os.path.basename(actual_exe).lower()
            if base in expected_names:
                return True
            if expected_path:
                try:
                    if (
                        os.path.exists(expected_path)
                        and os.path.exists(actual_exe)
                        and os.path.samefile(expected_path, actual_exe)
                    ):
                        return True
                except Exception:
                    pass
        try:
            with open(proc_cmdline, "rb") as f:
                cmdline = f.read().decode("utf-8", errors="ignore")
        except Exception:
            return False
        parts = [p for p in cmdline.split("\x00") if p]
        if not parts:
            return False
        first = os.path.basename(parts[0]).lower()
        if first in expected_names:
            return True
        for part in parts:
            if os.path.basename(part).lower() in expected_names:
                return True
        return False

    def _cleanup_stale_runtime_leases(self) -> None:
        try:
            entries = os.listdir(self._runtime_lease_dir)
        except Exception:
            return
        now = time.time()
        for name in entries:
            m = _RUNTIME_LEASE_RE.fullmatch(name)
            if not m:
                continue
            path = os.path.join(self._runtime_lease_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lease = json.load(f)
            except Exception:
                try:
                    os.remove(path)
                except OSError:
                    pass
                continue
            sid = _normalize_session_id(lease.get("session_id"))
            sid_from_name = m.group(1)
            if not sid or sid != sid_from_name:
                # Malformed/mismatched lease metadata: drop it and do not signal any PID.
                try:
                    os.remove(path)
                except OSError:
                    pass
                continue
            try:
                pid = int(lease.get("pid") or 0)
            except Exception:
                pid = 0
            try:
                updated = float(lease.get("updated_at") or 0.0)
            except Exception:
                updated = 0.0
            with self._runtime_lock:
                tracked = bool(sid and sid in self.session_runtimes)
            if tracked:
                continue
            expired = (now - updated) > RUNTIME_LEASE_TTL
            with self._runtime_lock:
                tracked_after = bool(sid and sid in self.session_runtimes)
            if tracked_after:
                continue
            if not expired:
                continue
            if pid <= 0:
                try:
                    os.remove(path)
                except OSError:
                    pass
                continue
            if not self._is_expected_ida_process(pid, lease):
                log_rpc(f"Skipping stale lease cleanup for non-IDA pid={pid} sid={sid}")
                continue
            killed = self._kill_stale_pid(pid)
            if killed:
                try:
                    os.remove(path)
                except OSError:
                    pass
            else:
                # Keep lease for retry, but back off immediate repeated kill attempts.
                lease["updated_at"] = now
                lease["last_error"] = "terminate_failed"
                self._write_runtime_lease_record(path, lease)

    def _adopt_or_cleanup_stale_runtime_leases(self) -> None:
        # Backward-compatible alias; method now only performs cleanup.
        self._cleanup_stale_runtime_leases()

    def _lease_heartbeat_loop(self) -> None:
        while True:
            if self._lease_thread_stop.wait(RUNTIME_LEASE_HEARTBEAT_SECONDS):
                break
            if self._shutdown_requested:
                break
            with self._runtime_lock:
                runtime_items = list(self.session_runtimes.items())
            for sid, runtime in runtime_items:
                if self._shutdown_requested:
                    break
                with self._runtime_lock:
                    if self.session_runtimes.get(sid) is not runtime:
                        continue
                proc = runtime.get("process")
                if not proc:
                    continue
                if proc.poll() is None:
                    self._write_runtime_lease(sid, runtime)
                else:
                    self._remove_runtime_lease(sid)

    def _start_runtime_lease_heartbeat(self) -> None:
        if self._lease_thread and self._lease_thread.is_alive():
            return
        self._lease_thread = threading.Thread(
            target=self._lease_heartbeat_loop,
            name="ida-mcp-runtime-lease-heartbeat",
            daemon=True,
        )
        self._lease_thread.start()

    def _stop_runtime_lease_heartbeat(self) -> None:
        self._lease_thread_stop.set()
        t = self._lease_thread
        if t and t.is_alive():
            t.join(timeout=1.0)

    def _register_lifecycle_handlers(self) -> None:
        if not IDAMCPServer._atexit_registered:
            atexit.register(self.shutdown)
            IDAMCPServer._atexit_registered = True
        for sig_name in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, sig_name, None)
            if sig is None:
                continue
            try:
                signal.signal(sig, self._handle_termination_signal)
            except Exception as e:
                log_rpc(f"Failed to register handler for {sig_name}: {e}")

    def _handle_termination_signal(self, signum, frame):
        self._shutdown_requested = True
        self._lease_thread_stop.set()
        # Do NOT raise SystemExit or KeyboardInterrupt - let run() loop exit gracefully

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        self._shutdown_requested = True
        self._stop_runtime_lease_heartbeat()
        self._cleanup_all_runtimes()
        # Stop all analysis engines
        for engine in list(getattr(self, "_analysis_engines", {}).values()):
            try:
                engine.stop()
            except Exception:
                pass
        # Stop usage intelligence
        if getattr(self, "_usage_intel", None):
            try:
                self._usage_intel.stop()
            except Exception:
                pass
        # Persist VOERA memory tiers
        try:
            if hasattr(self, "_insight_index"):
                self._insight_index.save()
        except Exception as e:
            log_rpc(f"Failed to save insight index: {e}")
        try:
            if hasattr(self, "_global_facts"):
                self._global_facts.close()
        except Exception as e:
            log_rpc(f"Failed to close global facts DB: {e}")
        try:
            if hasattr(self, "assembler") and self.assembler is not None:
                self.assembler.stop()
        except Exception as e:
            log_rpc(f"Failed to stop intelligence embedder: {e}")

    def _ida_binary_names(self) -> List[str]:
        if sys.platform == "win32":
            return ["idat64.exe", "idat.exe", "ida64.exe", "ida.exe"]
        return ["idat64", "idat", "ida64", "ida"]

    def _is_executable_file(self, path: str) -> bool:
        if not path:
            return False
        if not os.path.isfile(path):
            return False
        if os.name == "nt":
            return True
        return os.access(path, os.X_OK)

    def _detect_ida_dir(self):
        for env_name in ("IDADIR", "IDA_DIR"):
            env_dir = os.environ.get(env_name)
            if not env_dir:
                continue
            env_dir = os.path.realpath(os.path.expanduser(env_dir))
            if os.path.isdir(env_dir):
                return env_dir
            if self._is_executable_file(env_dir):
                return os.path.dirname(env_dir)

        env_idat = os.environ.get("IDA_MCP_IDAT")
        if env_idat:
            env_idat = os.path.realpath(os.path.expanduser(env_idat))
            if self._is_executable_file(env_idat):
                return os.path.dirname(env_idat)

        cands: List[str] = []
        if sys.platform == "win32":
            cands.extend(
                [
                    r"C:\Program Files\IDA Professional 9.2",
                    r"C:\Program Files\IDA Pro 9.2",
                    r"C:\Program Files\IDA Professional 9.1",
                    r"C:\Program Files\IDA Pro 9.1",
                    r"C:\Program Files\IDA Professional 9.0",
                    r"C:\Program Files\IDA Pro 9.0",
                    r"C:\Program Files\IDA Professional",
                    r"C:\Program Files\IDA Pro",
                ]
            )
        elif sys.platform == "linux":
            home = str(Path.home())
            patterns = [
                "/opt/ida*",
                "/opt/IDA*",
                "/opt/idapro*",
                "/opt/IDAPro*",
                "/usr/local/ida*",
                "/usr/local/IDA*",
                "/usr/local/idapro*",
                "/usr/local/IDAPro*",
                os.path.join(home, "ida*"),
                os.path.join(home, "IDA*"),
                os.path.join(home, "idapro*"),
                os.path.join(home, "IDAPro*"),
            ]
            for pattern in patterns:
                cands.extend(glob.glob(pattern))
        else:
            # macOS and other Unix-like platforms
            cands.extend(
                [
                    "/Applications/IDA Professional 9.2.app/Contents/MacOS",
                    "/Applications/IDA Pro 9.2.app/Contents/MacOS",
                    "/Applications/IDA Professional.app/Contents/MacOS",
                    "/Applications/IDA Pro.app/Contents/MacOS",
                ]
            )

        binary_names = self._ida_binary_names()
        for c in cands:
            c = os.path.realpath(os.path.expanduser(c))
            if not os.path.isdir(c):
                continue
            for name in binary_names:
                if self._is_executable_file(os.path.join(c, name)):
                    return c

        for name in binary_names:
            resolved = shutil.which(name)
            if resolved:
                return os.path.dirname(os.path.realpath(resolved))
        return ""

    def _find_idat(self):
        env_idat = os.environ.get("IDA_MCP_IDAT")
        if env_idat:
            env_idat = os.path.realpath(os.path.expanduser(env_idat))
            if self._is_executable_file(env_idat):
                return env_idat

        if not self.ida_dir:
            self.ida_dir = self._detect_ida_dir()

        for name in self._ida_binary_names():
            if self.ida_dir:
                p = os.path.join(self.ida_dir, name)
                if self._is_executable_file(p):
                    return p
            resolved = shutil.which(name)
            if resolved and self._is_executable_file(resolved):
                return os.path.realpath(resolved)

        if not self.ida_dir:
            return ""
        return ""

    def _tail_text_file(self, path: Optional[str], tail_lines: int = 40) -> str:
        if not path:
            return ""
        if not os.path.exists(path):
            return ""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            return "".join(lines[-max(1, int(tail_lines)) :]).strip()
        except Exception:
            return ""

    def _get_ida_diagnostics(
        self, stdout_log=None, stderr_log=None, tail_lines: int = 40
    ):
        out_log = stdout_log or os.path.join(self.cache_dir, "ida_stdout.log")
        err_log = stderr_log
        if err_log is None and out_log:
            # Best effort: derive sibling stderr path for per-session logs.
            err_guess = out_log.replace("ida_stdout_", "ida_stderr_")
            if err_guess != out_log:
                err_log = err_guess
        out_tail = self._tail_text_file(out_log, tail_lines=tail_lines)
        err_tail = self._tail_text_file(err_log, tail_lines=tail_lines)
        if not out_tail and not err_tail:
            return "No log available."
        blocks = []
        if out_tail:
            blocks.append(f"[stdout]\n{out_tail}")
        if err_tail:
            blocks.append(f"[stderr]\n{err_tail}")
        return "\n\n".join(blocks)

    def _extract_library_init_failure(self, diag: str) -> Optional[dict]:
        if not isinstance(diag, str) or not diag.strip():
            return None
        low = diag.lower()
        has_phrase = ("library init failed" in low) or (
            "library initialization failed" in low
        )
        err_code = None
        m_err = re.search(r"\berr(?:or)?\s*[:=]?\s*(\d+)\b", low)
        if m_err:
            try:
                err_code = int(m_err.group(1))
            except Exception:
                err_code = None
        has_err2 = bool(re.search(r"\berr(?:or)?\s*[:=]?\s*2\b", low))
        if not has_phrase and not has_err2:
            return None

        causes: List[str] = []
        hints: List[str] = []
        if (
            "cannot open shared object file" in low
            or "no such file or directory" in low
            or "failed to load shared library" in low
        ):
            causes.append("Missing shared runtime library (loader error).")
            hints.append(
                "Verify IDA runtime dependencies are installed and loadable (ldd on idat64)."
            )
        if "glibcxx" in low or "cxxabi" in low:
            causes.append("C++ runtime ABI mismatch (libstdc++ / libc++ conflict).")
            hints.append(
                "Unset conflicting LD_LIBRARY_PATH entries or use system-compatible libstdc++."
            )
        if "qt.qpa.plugin" in low or "xcb" in low or "qt platform plugin" in low:
            causes.append("Qt platform/plugin initialization failure.")
            hints.append(
                "Check Qt plugin paths and system GUI/runtime deps (e.g. xcb plugin packages)."
            )
        if (
            "wrong elf class" in low
            or "bad cpu type" in low
            or "exec format error" in low
        ):
            causes.append("Binary/runtime architecture mismatch.")
            hints.append(
                "Use the correct IDA binary for host architecture and compatible target runtime."
            )
        if "permission denied" in low:
            causes.append(
                "Filesystem permission error while loading runtime components."
            )
            hints.append(
                "Fix file execute/read permissions on IDA installation and plugins."
            )
        if "plugin" in low and "failed" in low:
            causes.append(
                "A plugin failed during startup and broke library initialization."
            )
            hints.append("Disable third-party plugins and retry startup.")
        if "python" in low and ("init" in low or "module" in low):
            causes.append("Embedded Python/runtime initialization mismatch.")
            hints.append(
                "Ensure no conflicting PYTHONHOME/PYTHONPATH overrides are injected."
            )
        if not causes:
            causes.append("Generic library initialization failure.")
            hints.append("Inspect stdout/stderr tails for missing dependency details.")

        return {
            "detected": True,
            "error_code": err_code,
            "err2": bool(has_err2 or (err_code == 2)),
            "causes": causes,
            "recommendations": hints,
        }

    def _is_library_init_err2(self, diag: str) -> bool:
        info = self._extract_library_init_failure(diag)
        if not info:
            return False
        if info.get("error_code") == 2:
            return True
        if info.get("err2"):
            return True
        # Preserve previous behavior: phrase alone still triggers recovery path.
        return bool(info.get("detected"))

    def _normalize_ida_args(
        self, ida_args: Optional[Union[str, List[str]]]
    ) -> List[str]:
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

    @staticmethod
    def _pop_first(mapping: dict, keys: List[str], default: Any = None) -> Any:
        for key in keys:
            if key in mapping:
                return mapping.pop(key)
        return default

    def _load_session_macros(self):
        self._session_macros = {}
        try:
            with open(self._macro_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except FileNotFoundError:
            return
        except Exception:
            return
        if not isinstance(raw, dict):
            return
        for key, value in raw.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            name = str(value.get("name") or key).strip()
            data = value.get("data")
            if not name or not isinstance(data, dict):
                continue
            self._session_macros[key.lower()] = {
                "name": name,
                "data": data,
                "updated_at": value.get("updated_at"),
            }

    def _save_session_macros(self):
        try:
            tmp = self._macro_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._session_macros, f, indent=2, ensure_ascii=False)
            os.replace(tmp, self._macro_path)
        except Exception:
            pass

    def _normalize_macro_name(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        name = str(value).strip()
        if not name:
            return None
        name = re.sub(r"\s+", " ", name)[:80]
        return name or None

    def _record_activity(
        self,
        tool_name: str,
        call_args: Any,
        result: Any,
        *,
        session_id: Optional[str] = None,
    ):
        if not isinstance(call_args, dict):
            return
        if not isinstance(result, dict) or result.get("error"):
            return
        sid = session_id
        if not sid:
            sid = _normalize_session_id(call_args.get("session_id"))
        if not sid and self.current_session:
            sid = self.current_session.session_id
        if not sid:
            return

        action = call_args.get("action")
        if not isinstance(action, str):
            action = ""

        # Auto-nudge tracking — use UsageIntelligence.observe if available, else auto_nudge
        try:
            ui = getattr(self, "_usage_intel", None)
            if ui:
                ui.observe(
                    tool_name, action,
                    session_id=sid or "",
                    addr=call_args.get("addr"),
                )
            else:
                from .auto_nudge import record_tool_call
                record_tool_call(
                    sid,
                    tool_name,
                    action,
                    addr=call_args.get("addr"),
                    query=call_args.get("query") or call_args.get("pattern"),
                )
        except Exception:
            pass

        addresses: List[str] = []
        if isinstance(result.get("items"), list):
            for item in result["items"][:16]:
                if not isinstance(item, dict):
                    continue
                addr = item.get("address") or item.get("addr")
                if addr is None and isinstance(item.get("address_ea"), int):
                    addr = hex(item.get("address_ea"))
                if isinstance(addr, str) and addr.startswith("0x"):
                    addresses.append(addr.lower())
        matches = result.get("matches")
        if isinstance(matches, str):
            addresses.extend(re.findall(r"0x[0-9a-fA-F]+", matches)[:16])
        deduped_addresses: List[str] = []
        seen = set()
        for addr in addresses:
            a = addr.lower()
            if a in seen:
                continue
            seen.add(a)
            deduped_addresses.append(a)

        entry = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "session_id": sid,
            "tool": tool_name,
            "action": action,
            "addresses": deduped_addresses[:8],
            "topic": result.get("resolved_topic") or result.get("topic"),
            "target": result.get("target")
            or result.get("query")
            or result.get("pattern"),
        }
        self._activity_log.append(entry)
        if len(self._activity_log) > self._activity_log_max:
            self._activity_log = self._activity_log[-self._activity_log_max :]

        # Also persist into session skill/activity store so dashboard counters,
        # phase progression, and dead-end detection reflect real tool usage.
        try:
            self.session_mgr.log_activity(
                sid,
                tool=tool_name,
                action=action or "",
                result=json.dumps(
                    {
                        "addresses": deduped_addresses[:4],
                        "topic": entry.get("topic"),
                        "target": entry.get("target"),
                    },
                    ensure_ascii=False,
                )[:400],
            )
        except Exception:
            pass

        # MemRL auto-reward: when the LLM navigates to an address we previously
        # suggested, record an implicit accept reward (~0.7) to close the feedback
        # loop without requiring explicit LLM cooperation.  This is the missing
        # link that keeps Q-values from being frozen at their initial 0.5.
        if deduped_addresses:
            try:
                from ida_pro_mcp.ida_mcp.tools.memrl import MemRLBank
                bank = MemRLBank()
                for addr in deduped_addresses[:4]:
                    bank.auto_reward_for_addr(addr, reward=0.7)
            except Exception:
                pass

    def _build_recent_workset(
        self,
        sid: str,
        n: int,
        include_bookmarks: bool,
        include_items: bool,
    ) -> dict:
        n = _bounded_int(n, 20, min_value=1, max_value=200)
        entries: List[Dict[str, Any]] = []
        seen = set()
        for row in reversed(self._activity_log):
            if row.get("session_id") != sid:
                continue
            key = (
                row.get("tool"),
                row.get("action"),
                tuple(row.get("addresses") or []),
                row.get("topic"),
                row.get("target"),
            )
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                {
                    "kind": "activity",
                    "ts": row.get("ts"),
                    "tool": row.get("tool"),
                    "action": row.get("action"),
                    "addresses": row.get("addresses") or [],
                    "topic": row.get("topic"),
                    "target": row.get("target"),
                }
            )
            if len(entries) >= n:
                break

        if include_bookmarks:
            bm_res = self.bookmark_mgr.list(sid, {"limit": max(1, n), "offset": 0})
            for bm in bm_res.get("bookmarks", [])[:n]:
                if not isinstance(bm, dict):
                    continue
                entries.append(
                    {
                        "kind": "bookmark",
                        "ts": bm.get("timestamp"),
                        "address": bm.get("addr"),
                        "name": bm.get("name"),
                        "category": bm.get("category"),
                        "tags": bm.get("tags") or [],
                    }
                )
                if len(entries) >= (n * 2):
                    break

        lines: List[str] = []
        for item in entries:
            if item.get("kind") == "bookmark":
                lines.append(
                    f"{item.get('ts', '')}  bookmark  {item.get('address', '')}  {item.get('name', '')}".strip()
                )
                continue
            addr_part = ",".join(item.get("addresses") or [])
            tail_parts = [item.get("tool"), item.get("action")]
            if addr_part:
                tail_parts.append(addr_part)
            if item.get("topic"):
                tail_parts.append(str(item.get("topic")))
            elif item.get("target"):
                tail_parts.append(str(item.get("target")))
            tail = "  ".join([p for p in tail_parts if p])
            lines.append(f"{item.get('ts', '')}  {tail}".strip())

        out = {
            "ok": True,
            "action": "recent_workset",
            "session_id": sid,
            "workset": "\n".join(lines),
            "count": len(entries),
        }
        if include_items:
            out["items"] = entries
        return out

    def _json_safe_value(self, value: Any) -> Any:
        """Recursively convert non-JSON-safe values to safe representations."""
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except Exception:
                return {"_bytes_hex": value.hex()}
        if isinstance(value, bytearray):
            return self._json_safe_value(bytes(value))
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                try:
                    key = k if isinstance(k, str) else str(k)
                except Exception:
                    key = "<non_string_key>"
                out[key] = self._json_safe_value(v)
            return out
        if isinstance(value, (list, tuple)):
            return [self._json_safe_value(v) for v in value]
        if isinstance(value, set):
            return [self._json_safe_value(v) for v in value]
        return value

    def _serialize_payload(self, payload: Any, opts: dict) -> str:
        payload = self._json_safe_value(payload)
        if opts.get("mode") == "full":
            return json.dumps(payload, ensure_ascii=False, indent=2)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def _build_ida_command(
        self, session, log_file, script_path, use_existing_idb: bool
    ):
        cmd = [self.idat_exe, "-A"]
        cmd.extend(session.ida_args or [])

        # For new databases, inject processor/loader CLI flags so IDA loads
        # with the correct architecture from the start instead of defaulting
        # to metapc and requiring a post-load switch.
        if not use_existing_idb:
            opts = session.analysis_options or {}
            ida_prefixes = {str(a)[:2] for a in (session.ida_args or [])}
            if opts.get("processor") and "-p" not in ida_prefixes:
                cmd.append(f"-p{opts['processor']}")
            if opts.get("loader") and "-T" not in ida_prefixes:
                cmd.append(f"-T{opts['loader']}")
            # Apply inferred load base so IDA maps the binary at the correct
            # address from the start (e.g. AIC8800D80 WFFW at 0x120000).
            if opts.get("baseaddr") is not None and "-b" not in ida_prefixes:
                try:
                    # IDA -b flag is in 16-byte paragraphs, not bytes.
                    paragraphs = int(opts["baseaddr"]) // 16
                    cmd.append(f"-b{paragraphs:#x}")
                except (TypeError, ValueError):
                    pass
            # skip_analysis=true: pass -c to create IDB without running auto-analysis.
            # Use for large/raw binaries where analysis blocks indefinitely.
            # After session create, call analysis(action='run') to trigger manually.
            if opts.get("skip_analysis") or opts.get("no_analysis"):
                if "-c" not in (session.ida_args or []):
                    cmd.append("-c")

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

    def _cleanup_stale_idb_family(self, idb_path: str) -> None:
        """Remove stale sidecar files that can block fresh IDB creation."""
        if not idb_path:
            return
        base, ext = os.path.splitext(idb_path)
        family_exts = [
            ".id0",
            ".id1",
            ".nam",
            ".til",
            ".dmp",
            ".asm",
            ".i64",
            ".idb",
        ]
        for fam_ext in family_exts:
            path = f"{base}{fam_ext}"
            if not os.path.exists(path):
                continue
            try:
                os.remove(path)
                log_rpc(f"Removed stale IDB artifact: {path}")
            except Exception as e:
                log_rpc(f"Failed to remove stale IDB artifact {path}: {e}")

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
            data = json.dumps(request, separators=(",", ":")).encode("utf-8")
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
        preload_keys = {"processor", "bitness", "endian", "loader", "value", "loader_options", "flags"}
        has_preload_request = any(k in opts and opts.get(k) is not None for k in preload_keys)
        self._nuclear_reset(
            session.idb_path, aggressive=bool(opts.get("aggressive_cleanup"))
        )

        # Validate IDA installation
        if not self.idat_exe or not self._is_executable_file(self.idat_exe):
            return make_error(
                MCPError.FILE_NOT_FOUND,
                "IDA executable not found. Set IDADIR or IDA_MCP_IDAT, or ensure idat64/idat is in PATH.",
                details={"ida_dir": self.ida_dir, "idat_exe": self.idat_exe},
            )

        # DYNAMIC PORT ASSIGNMENT
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        server_port = sock.getsockname()[1]
        sock.close()

        log_rpc(f"Assigned dynamic port: {server_port}")

        # server_script.py lives next to host/, not inside host/src/
        script_path = os.path.join(os.path.dirname(SCRIPT_DIR), "server_script.py")

        # Environment for IDA
        env = os.environ.copy()
        ida_runtime_dir = self.ida_dir or os.path.dirname(self.idat_exe)
        if ida_runtime_dir:
            env["IDADIR"] = ida_runtime_dir
        env["IDA_MCP_PORT"] = str(server_port)
        env["IDA_MCP_BYPASS_SYNC"] = "1"
        env["IDA_MCP_SESSION_ID"] = session.session_id
        env["IDA_MCP_CACHE_DIR"] = self.cache_dir
        env["IDA_MCP_PRE_ANALYSIS_OPTS"] = json.dumps(session.analysis_options or {})
        env["IDA_MCP_FORCE_PRE_ANALYSIS_OPTS"] = "1" if has_preload_request else "0"

        # Determine whether to open existing IDB or create new one
        use_existing_idb = os.path.exists(session.idb_path)
        env["IDA_MCP_USE_EXISTING_IDB"] = "1" if use_existing_idb else "0"

        sid_tag = session.session_id
        log_file = os.path.join(self.cache_dir, f"ida_mcp_{sid_tag}.log")
        stdout_log = os.path.join(self.cache_dir, f"ida_stdout_{sid_tag}.log")
        stderr_log = os.path.join(self.cache_dir, f"ida_stderr_{sid_tag}.log")

        # Launch IDA: Open existing IDB if present, otherwise analyze binary
        if use_existing_idb:
            log_rpc(f"Opening existing session IDB: {session.idb_path}")
        else:
            log_rpc(
                f"Creating new IDB for binary: {session.binary_path} -> {session.idb_path}"
            )
            # Ensure session directory exists
            os.makedirs(os.path.dirname(session.idb_path), exist_ok=True)
            self._cleanup_stale_idb_family(session.idb_path)
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
                    with self._runtime_lock:
                        self.session_runtimes[session.session_id] = runtime
                    self._write_runtime_lease(session.session_id, runtime)
                    apply_res = self._apply_session_options(session, runtime)
                    if apply_res.get("error"):
                        return apply_res
                    # Kick off heavy indexing in background so session create returns fast
                    self._background_index(session.session_id, server_port)
                    return {
                        "ok": True,
                        "idb_path": session.idb_path,
                        "current_options": apply_res.get("current_options"),
                        "bootstrap_report": apply_res.get("bootstrap_report"),
                        "analysis_in_progress": True,
                        "hint": "IDA is auto-analyzing the binary. Poll session(action='status') to check readiness, or start querying once analysis completes.",
                    }
            except Exception:
                pass
            time.sleep(0.5)

        if ida_crashed:
            diag = self._get_ida_diagnostics(stdout_log, stderr_log)
            if self._is_library_init_err2(diag):
                return self._attempt_session_recovery(session, diag, server_port)
            lib_init = self._extract_library_init_failure(diag)
            details = {"log": diag}
            if lib_init:
                details["library_init"] = lib_init
            return make_error(
                MCPError.IDA_CRASHED,
                f"IDA exited with code {exit_code}",
                details=details,
            )

        return make_error(
            MCPError.IDA_TIMEOUT, f"IDA failed to initialize within {startup_timeout}s."
        )

    def _launch_and_wait(self, session, server_port, sanitize_env: bool = False):
        script_path = os.path.join(os.path.dirname(SCRIPT_DIR), "server_script.py")
        env = os.environ.copy()
        ida_runtime_dir = self.ida_dir or os.path.dirname(self.idat_exe)
        if ida_runtime_dir:
            env["IDADIR"] = ida_runtime_dir
        env["IDA_MCP_PORT"] = str(server_port)
        env["IDA_MCP_BYPASS_SYNC"] = "1"
        env["IDA_MCP_SESSION_ID"] = session.session_id
        env["IDA_MCP_CACHE_DIR"] = self.cache_dir
        env["IDA_MCP_PRE_ANALYSIS_OPTS"] = json.dumps(session.analysis_options or {})
        opts = session.analysis_options or {}
        preload_keys = {"processor", "bitness", "endian", "loader", "value", "loader_options", "flags"}
        has_preload_request = any(k in opts and opts.get(k) is not None for k in preload_keys)
        env["IDA_MCP_FORCE_PRE_ANALYSIS_OPTS"] = "1" if has_preload_request else "0"
        use_existing_idb = os.path.exists(session.idb_path)
        env["IDA_MCP_USE_EXISTING_IDB"] = "1" if use_existing_idb else "0"
        if sanitize_env:
            for k in (
                "LD_LIBRARY_PATH",
                "DYLD_LIBRARY_PATH",
                "PYTHONHOME",
                "PYTHONPATH",
                "QT_PLUGIN_PATH",
                "QT_QPA_PLATFORM_PLUGIN_PATH",
            ):
                env.pop(k, None)
        sid_tag = session.session_id
        log_file = os.path.join(self.cache_dir, f"ida_mcp_{sid_tag}.log")
        stdout_log = os.path.join(self.cache_dir, f"ida_stdout_{sid_tag}.log")
        stderr_log = os.path.join(self.cache_dir, f"ida_stderr_{sid_tag}.log")

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
                diag = self._get_ida_diagnostics(stdout_log, stderr_log)
                return {
                    "error": True,
                    "exit_code": exit_code,
                    "log": diag,
                    "library_init": self._extract_library_init_failure(diag),
                    "sanitize_env": sanitize_env,
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
                    with self._runtime_lock:
                        self.session_runtimes[session.session_id] = runtime
                    self._write_runtime_lease(session.session_id, runtime)
                    return {"ok": True, "idb_path": session.idb_path}
            except Exception:
                pass
            time.sleep(0.5)

        return {"error": True, "reason": "timeout"}

    def _attempt_session_recovery(self, session, diag, server_port):
        opts = session.analysis_options or {}
        lib_init = self._extract_library_init_failure(diag)
        if opts.get("recover") is False:
            details = {"log": diag, "recovery_attempted": False}
            if lib_init:
                details["library_init"] = lib_init
            return make_error(
                MCPError.IDA_CRASHED,
                "IDA failed with 'library init failed' and recovery is disabled.",
                details=details,
            )
        if lib_init:
            log_rpc(
                f"Detected library init failure (err={lib_init.get('error_code')}) "
                f"causes={lib_init.get('causes')} - attempting recovery..."
            )
        else:
            log_rpc("Detected library init failure - attempting recovery...")
        self._cleanup_runtime(session.session_id)
        time.sleep(1)

        backup_path = None
        if opts.get("backup_on_recover", True):
            backup_path = self._backup_idb(session.idb_path)
        self._nuclear_reset(
            session.idb_path, aggressive=bool(opts.get("aggressive_cleanup", True))
        )

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
        if "error" in result and result.get("library_init"):
            # One extra attempt with sanitized runtime env to avoid host LD/Python contamination.
            retry_result = self._launch_and_wait(
                session, server_port, sanitize_env=True
            )
            if "error" not in retry_result:
                result = retry_result
            else:
                result["sanitized_retry"] = retry_result
        if "error" in result:
            details = {"log": diag, "backup": backup_path, "recovery_attempted": True}
            if lib_init:
                details["library_init"] = lib_init
            if isinstance(result.get("sanitized_retry"), dict):
                details["sanitized_retry"] = {
                    "exit_code": result["sanitized_retry"].get("exit_code"),
                    "library_init": result["sanitized_retry"].get("library_init"),
                }
            return make_error(
                MCPError.IDA_CRASHED,
                "IDA failed to recover the session after cleanup.",
                details=details,
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
            log_rpc(
                f"Skipping analysis options for session {session.session_id} (already applied)"
            )
            return {
                "ok": True,
                "skipped": True,
                "note": "analysis_options already applied",
            }

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

        bootstrap_knowledge = {"chip_family": None, "imported_symbol_count": 0}
        bootstrap_report = None
        try:
            chip_res = self._send_rpc_raw(
                {"tool": "knowledge", "args": {"action": "chip_identify"}},
                port,
            )
            if isinstance(chip_res, dict) and not chip_res.get("error"):
                prof = chip_res.get("profile")
                if isinstance(prof, dict) and prof.get("chip_family"):
                    bootstrap_knowledge["chip_family"] = prof.get("chip_family")
            import_res = self._send_rpc_raw(
                {
                    "tool": "knowledge",
                    "args": {
                        "action": "import_symbols",
                        "min_confidence": float(opts.get("symbol_import_min_confidence", 0.8)),
                        "limit": int(opts.get("symbol_import_limit", 200)),
                    },
                },
                port,
            )
            if isinstance(import_res, dict) and not import_res.get("error"):
                bootstrap_knowledge["imported_symbol_count"] = int(import_res.get("imported", 0) or 0)
        except Exception:
            pass

        try:
            chip_family = str(opts.get("chip_family") or bootstrap_knowledge.get("chip_family") or "").strip()
            if chip_family:
                fw_args = {
                    "chip_family": chip_family,
                    "load_base": opts.get("baseaddr"),
                    "memory_map": opts.get("memory_map") or [],
                    "peripheral_addresses": opts.get("peripheral_addresses") or [],
                    "post_load_actions": opts.get("post_load_actions") or [],
                }
                fw_res = self._send_rpc_raw({"tool": "firmware_bootstrap", "args": fw_args}, port)
                if isinstance(fw_res, dict) and not fw_res.get("error"):
                    bootstrap_report = fw_res
        except Exception:
            bootstrap_report = None

        if opts.get("apply_once", True):
            session.analysis_applied = True
        self.session_mgr._save_metadata(session)
        current_options = {}
        try:
            current_options = self._send_rpc_raw(
                {"tool": "analysis", "args": {"action": "get_options"}}, port
            )
        except Exception:
            pass

        # Strict verification for architecture-sensitive loads.
        try:
            expected_proc = opts.get("processor")
            expected_bits = opts.get("bitness")
            expected_end = opts.get("endian")
            got = current_options.get("result") if isinstance(current_options, dict) else None
            if isinstance(got, dict):
                got_proc = str(got.get("procname") or "").strip().lower()
                got_bits = got.get("app_bitness")
                got_be = got.get("is_be")
                mismatches = []
                if expected_proc is not None:
                    eproc = str(expected_proc).strip().lower()
                    if got_proc and got_proc != eproc:
                        mismatches.append(f"processor expected={eproc} got={got_proc}")
                if expected_bits is not None:
                    try:
                        if int(got_bits) != int(expected_bits):
                            mismatches.append(f"bitness expected={expected_bits} got={got_bits}")
                    except Exception:
                        mismatches.append(f"bitness expected={expected_bits} got={got_bits}")
                if expected_end is not None:
                    end_norm = str(expected_end).strip().lower()
                    want_be = end_norm in ("be", "big", "big_endian", "big-endian", "bigendian", "1", "true")
                    if got_be is not None and bool(got_be) != bool(want_be):
                        mismatches.append(f"endian expected={'be' if want_be else 'le'} got={'be' if bool(got_be) else 'le'}")
                if mismatches:
                    return make_error(
                        MCPError.IDA_ERROR,
                        "Architecture preload did not stick after analysis option application",
                        details={
                            "mismatches": mismatches,
                            "expected": {"processor": expected_proc, "bitness": expected_bits, "endian": expected_end},
                            "current_options": got,
                            "hint": "Create a fresh session with architecture block and avoid reusing existing IDBs for incompatible binaries.",
                        },
                    )
        except Exception:
            pass
        return {
            "ok": True,
            "current_options": current_options if not current_options.get("error") else None,
            "bootstrap_knowledge": bootstrap_knowledge,
            "bootstrap_report": bootstrap_report,
        }

    def _background_index(self, session_id: str, server_port: int):
        """Run schemaboot + turboquant + mbagcn indexing in background thread."""
        import threading

        def _run():
            log_rpc(f"[bg-index] Starting background indexing for {session_id}")
            try:
                self._send_rpc_raw(
                    {"tool": "schemaboot", "args": {"action": "ingest"}},
                    server_port,
                    timeout=60.0,
                )
                log_rpc(f"[bg-index] schemaboot complete for {session_id}")
            except Exception as e:
                log_rpc(f"[bg-index] schemaboot failed (non-fatal): {e}")
            try:
                self._send_rpc_raw(
                    {"tool": "turboquant", "args": {"action": "ingest"}},
                    server_port,
                    timeout=120.0,
                )
                log_rpc(f"[bg-index] turboquant complete for {session_id}")
            except Exception as e:
                log_rpc(f"[bg-index] turboquant failed (non-fatal): {e}")
            try:
                self._send_rpc_raw(
                    {"tool": "mbagcn", "args": {"action": "stats"}},
                    server_port,
                    timeout=30.0,
                )
                log_rpc(f"[bg-index] mbagcn complete for {session_id}")
            except Exception as e:
                log_rpc(f"[bg-index] mbagcn failed (non-fatal): {e}")
            # Mark indexing as complete in session metadata
            try:
                sess = self.session_mgr.sessions.get(session_id)
                if sess:
                    sess.metadata = dict(sess.metadata or {})
                    sess.metadata["indexing_complete"] = True
                    self.session_mgr._save_metadata(sess)
            except Exception:
                pass
            log_rpc(f"[bg-index] Background indexing finished for {session_id}")
            # Start the analysis engine for this session
            try:
                from .analysis_engine import AnalysisEngine
                bb_path = os.path.join(self.cache_dir, f"{session_id}.blackboard.db")
                proposals_path = os.path.join(self.cache_dir, f"{session_id}.proposals.db")
                engine = AnalysisEngine(
                    session_id=session_id,
                    rpc_fn=lambda tool, args: self._send_rpc_raw(
                        {"tool": tool, "args": args}, server_port, timeout=30.0
                    ),
                    notify_fn=self._send_notification,
                    bb_path=bb_path,
                    proposals_path=proposals_path,
                    embeddings_dir=self.cache_dir,
                )
                engine.start()
                self._analysis_engines[session_id] = engine
                log_rpc(f"[bg-index] Analysis engine started for {session_id}")
            except Exception as e:
                log_rpc(f"[bg-index] Analysis engine failed to start (non-fatal): {e}")

        threading.Thread(target=_run, daemon=True, name=f"bg-index-{session_id}").start()

    def _cleanup_runtime(self, sid):
        with self._runtime_lock:
            runtime = self.session_runtimes.pop(sid, None)
        self._remove_runtime_lease(sid)
        if not runtime:
            return
        proc = runtime.get("process")
        port = runtime.get("port")
        if proc:
            try:
                self._send_rpc_raw({"type": "shutdown"}, port, timeout=1)
            except Exception:
                pass
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
        for fh in runtime.get("log_handles", []):
            try:
                fh.close()
            except Exception:
                pass

    def _cleanup_all_runtimes(self):
        with self._runtime_lock:
            runtime_sids = list(self.session_runtimes.keys())
        for sid in runtime_sids:
            self._cleanup_runtime(sid)
        self._adopt_or_cleanup_stale_runtime_leases()

    def _resolve_session_from_idb_ref(self, idb_ref: Any) -> Optional[Session]:
        """Resolve idb references from session id, SID_* idb id/name, path, or basename."""
        if not isinstance(idb_ref, str):
            return None
        raw = idb_ref.strip()
        if not raw:
            return None

        sid = _normalize_session_id(raw)
        if sid:
            session = self.session_mgr.get_session(sid)
            if session:
                return session

        base = os.path.basename(raw)
        # SID_* filenames encode the canonical 8-char session id (SESSION_ID_RE).
        sid_match = re.match(r"^SID_([A-Za-z0-9]{8})(?:_|$)", base)
        if sid_match:
            session = self.session_mgr.get_session(sid_match.group(1).upper())
            if session:
                return session

        found = self.session_mgr.find_session_by_path(raw)
        if found:
            return found

        wanted = base.lower()
        if not wanted:
            return None
        for session in self.session_mgr.discover_sessions():
            if os.path.basename(session.idb_path or "").lower() == wanted:
                return session
        return None

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
