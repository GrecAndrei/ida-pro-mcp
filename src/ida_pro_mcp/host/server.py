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


class IDAMCPServer:
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

    def _prune_next_cache(self):
        if not self._next_cache:
            return
        now = time.time()
        expired = [
            token
            for token, row in self._next_cache.items()
            if (now - float(row.get("created_at", 0.0)))
            > float(self._next_cache_ttl_seconds)
        ]
        for token in expired:
            self._next_cache.pop(token, None)

    def _parse_action_tail_tokens(self, tail: str) -> dict:
        parsed: Dict[str, Any] = {}
        if not tail:
            return parsed
        try:
            tokens = shlex.split(tail)
        except Exception:
            tokens = tail.split()
        positional: List[str] = []
        for token in tokens:
            if "=" in token:
                k, v = token.split("=", 1)
                key = _normalize_alias_lookup_key(k)
                val = _strip_balanced_wrappers(v)
                if key and key not in parsed:
                    parsed[key] = val
            else:
                cleaned = _strip_balanced_wrappers(token)
                if cleaned:
                    positional.append(cleaned)
        if positional:
            parsed.setdefault("_positional", " ".join(positional).strip())
        return parsed

    def _clean_action_text(self, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        text = ACTION_PREFIX_RE.sub("", text)
        text = text.strip().strip(",").strip()
        # Handle malformed fragments like action\":\"lookup addr=0x...
        text = text.strip(ACTION_STRIP_CHARS)
        text = ACTION_PREFIX_RE.sub("", text)
        text = text.strip().strip(",")
        # Keep multi-token action strings intact here so key=value tails survive tokenization;
        # individual tokens are cleaned in _parse_action_tail_tokens().
        if re.search(r"\s", text):
            return text
        return _strip_balanced_wrappers(text)

    def _normalize_field_variants(self, tool_name: str, out: dict) -> dict:
        """Accept high-noise LLM value wrappers for known fields without changing caller intent."""
        if not isinstance(out, dict):
            return out
        normalized = dict(out)
        wrapper_fields = {
            "action",
            "legacy_tool",
            "legacy_action",
            "profile",
            "scan_profile",
            "query",
            "pattern",
            "addr",
            "addrs",
            "session_id",
            "binary_path",
            "name",
            "tag",
            "snapshot_id",
            "source_id",
            "target_id",
            "field_name",
            "target",
        }
        schema = TOOL_ARG_SCHEMAS.get(tool_name, {})
        wrapper_fields.update(str(k) for k in schema.keys())
        for key, value in list(normalized.items()):
            if key not in wrapper_fields:
                continue
            if not isinstance(value, str):
                continue
            text = value.strip()
            if not text:
                continue
            cleaned = _strip_balanced_wrappers(text)
            if cleaned and cleaned != text:
                normalized[key] = cleaned
                value = cleaned
            # Accept bracketed list-like singletons such as "[0x401000]" as scalar.
            if key in {"addr", "pattern", "query", "session_id", "binary_path"}:
                if (
                    isinstance(value, str)
                    and value.startswith("[")
                    and value.endswith("]")
                ):
                    inner = value[1:-1].strip()
                    if inner and "," not in inner:
                        normalized[key] = _strip_balanced_wrappers(inner)
        # For array-like address fields, gracefully normalize common malformed scalar wrappers.
        if "addrs" in normalized and isinstance(normalized["addrs"], str):
            text = normalized["addrs"].strip()
            if "," in text and not (text.startswith("{") and text.endswith("}")):
                normalized["addrs"] = [
                    _strip_balanced_wrappers(part.strip())
                    for part in text.split(",")
                    if part.strip()
                ]
                return normalized
            if text.startswith("[") and text.endswith("]"):
                inner = text[1:-1].strip()
                if inner:
                    if "," in inner:
                        normalized["addrs"] = [
                            _strip_balanced_wrappers(part.strip())
                            for part in inner.split(",")
                            if part.strip()
                        ]
                    else:
                        normalized["addrs"] = _strip_balanced_wrappers(inner)
        return normalized

    def _normalize_tool_call_args(self, tool_name: str, args: dict) -> dict:
        out = dict(args or {})
        valid_actions = TOOL_ACTIONS.get(tool_name, [])
        lower_map = {a.lower(): a for a in valid_actions}
        lower_map.update(ACTION_ALIASES_BY_TOOL.get(tool_name, {}))

        arg_aliases = ARG_ALIASES_BY_TOOL.get(tool_name, {})
        if arg_aliases:
            for raw_key in list(out.keys()):
                if not isinstance(raw_key, str):
                    continue
                normalized_key = _normalize_alias_lookup_key(raw_key)
                canonical_key = arg_aliases.get(normalized_key)
                if canonical_key and canonical_key not in out:
                    out[canonical_key] = out.pop(raw_key)

        action = out.get("action")
        if isinstance(action, dict):
            nested = dict(action)
            out.pop("action", None)
            for k, v in nested.items():
                out.setdefault(k, v)
            action = out.get("action")

        if isinstance(action, str):
            action_text = self._clean_action_text(action)
            if action_text.startswith("{") and action_text.endswith("}"):
                try:
                    payload = json.loads(action_text)
                except Exception:
                    payload = None
                if isinstance(payload, dict):
                    for k, v in payload.items():
                        out.setdefault(k, v)
                    action_text = self._clean_action_text(payload.get("action", ""))

            if action_text:
                parts = action_text.split(None, 1)
                base = self._clean_action_text(parts[0])
                if base.endswith("()"):
                    base = base[:-2]
                base = _strip_balanced_wrappers(base)
                mapped = lower_map.get(base.lower(), base)
                out["action"] = mapped
                if len(parts) > 1:
                    parsed_tail = self._parse_action_tail_tokens(parts[1].strip())
                    if arg_aliases:
                        normalized_tail = {}
                        for key, value in parsed_tail.items():
                            if isinstance(key, str):
                                canonical_key = arg_aliases.get(
                                    _normalize_alias_lookup_key(key), key
                                )
                            else:
                                canonical_key = key
                            normalized_tail[canonical_key] = value
                        parsed_tail = normalized_tail
                    for k, v in parsed_tail.items():
                        out.setdefault(k, v)
                    positional = parsed_tail.get("_positional")
                    if isinstance(positional, str) and positional:
                        schema = TOOL_ARG_SCHEMAS.get(tool_name, {})
                        if mapped in ("read", "sections") and tool_name == "wiki":
                            out.setdefault("topic", positional)
                        elif mapped == "search":
                            out.setdefault("query", positional)
                        # setdefault preserves any explicit addr/addrs supplied by the caller
                        # and only fills the positional fallback when those keys are absent.
                        elif "addrs" in schema:
                            out.setdefault("addrs", positional)
                        elif "addr" in schema:
                            out.setdefault("addr", positional)
                        elif "pattern" in schema:
                            out.setdefault("pattern", positional)
                    out.pop("_positional", None)
            else:
                out.pop("action", None)
        elif action is not None and valid_actions:
            out.pop("action", None)

        if "action" not in out and valid_actions:
            for candidate_key in ("subaction",):
                candidate = out.get(candidate_key)
                if isinstance(candidate, str):
                    mapped = lower_map.get(self._clean_action_text(candidate).lower())
                    if mapped:
                        out["action"] = mapped
                        break

        # Compatibility cleanup: many clients send wrapper/meta keys to direct
        # tool actions. Keep them for wrapper actions, otherwise drop unknown
        # wrapper noise so strict tool signatures don't fail with INVALID_ARGS.
        action_name = out.get("action")
        if not (isinstance(action_name, str) and action_name in WRAPPER_ACTIONS):
            # Always strip wrapper-only helper keys for direct actions, even if
            # a broad schema includes them. This keeps noisy client payloads
            # (empty grep/pick/head/next fields) from polluting tool calls.
            wrapper_noise = {
                "source_action", "target_action", "on", "subaction",
                "grep", "grep_pattern", "grep_regex", "grep_case_sensitive",
                "grep_invert", "grep_field", "grep_limit", "grep_offset",
                "pick_fields", "pick_omit", "head_n", "tail_n",
                "next_token", "token", "cursor", "stats_include_payload",
            }
            for k in tuple(wrapper_noise):
                if k == "subaction" and tool_name == "query":
                    continue
                if tool_name == "truncation" and k in {"token", "next_token", "cursor"}:
                    continue
                out.pop(k, None)
        return self._normalize_field_variants(tool_name, out)

    def _wrapper_source_action(
        self, tool_name: str, args: dict, wrapper_action: str
    ) -> tuple[Optional[str], Optional[dict]]:
        native_actions = set(TOOL_ACTIONS.get(tool_name, []) or [])
        source_action = (
            args.get("source_action")
            or args.get("target_action")
            or args.get("on")
            or args.get("subaction")
        )
        if not source_action or not isinstance(source_action, str):
            # Prefer list-style source if available, so head/grep/pick can be used tersely.
            if "list" in native_actions:
                return "list", None
            return None, make_error(
                MCPError.INVALID_ARGS,
                f"action='{wrapper_action}' requires source_action",
                hint=(
                    f"Example: {tool_name}(action='{wrapper_action}', source_action='list'). "
                    "Aliases: on, target_action, subaction."
                ),
            )
        source_action = source_action.strip()
        if not source_action:
            return None, make_error(
                MCPError.INVALID_ARGS, "source_action cannot be empty"
            )
        if source_action in WRAPPER_ACTIONS and source_action not in native_actions:
            return None, make_error(
                MCPError.INVALID_ARGS,
                f"source_action cannot be '{source_action}'",
                hint=f"Use a concrete tool action first, then action='{wrapper_action}'.",
            )
        return source_action, None

    def _strip_wrapper_args(self, args: dict) -> dict:
        child_args = dict(args or {})
        for key in (
            "source_action",
            "target_action",
            "on",
            "subaction",
            "grep",
            "grep_pattern",
            "grep_regex",
            "grep_case_sensitive",
            "grep_invert",
            "grep_field",
            "grep_limit",
            "grep_offset",
            "pick_fields",
            "pick_omit",
            "head_n",
            "tail_n",
            "next_token",
            "token",
            "cursor",
            "stats_include_payload",
        ):
            child_args.pop(key, None)
        return child_args

    def _lineify_item(self, item: Any) -> str:
        if isinstance(item, str):
            return item.strip()
        if isinstance(item, dict):
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if item is None:
            return ""
        return str(item).strip()

    def _collect_wrapper_items(
        self, payload: Any, field: Optional[str] = None
    ) -> tuple[list[Any], str, str]:
        if isinstance(payload, dict):
            if field:
                value = payload.get(field)
                if isinstance(value, str):
                    return (
                        [line for line in value.splitlines() if line.strip()],
                        field,
                        "string",
                    )
                if isinstance(value, list):
                    return list(value), field, "list"
                if value is None:
                    return [], field, "list"
                return [value], field, "list"
            for key in (
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
            ):
                if key not in payload:
                    continue
                value = payload.get(key)
                if isinstance(value, str):
                    return (
                        [line for line in value.splitlines() if line.strip()],
                        key,
                        "string",
                    )
                if isinstance(value, list):
                    return list(value), key, "list"
            return [payload], "payload", "list"
        if isinstance(payload, list):
            return list(payload), "payload", "list"
        if isinstance(payload, str):
            return (
                [line for line in payload.splitlines() if line.strip()],
                "payload",
                "string",
            )
        if payload is None:
            return [], "payload", "list"
        return [payload], "payload", "list"

    def _cache_next_page(self, tool_name: str, args: dict, payload: Any) -> Any:
        if not isinstance(payload, dict) or payload.get("error"):
            return payload
        if not _coerce_bool(payload.get("truncated"), False):
            return payload
        try:
            offset = int(payload.get("offset", args.get("offset", 0)) or 0)
            count = int(payload.get("count", 0) or 0)
            total = int(payload.get("total", 0) or 0)
        except Exception:
            return payload
        next_offset = payload.get("next_offset")
        if next_offset is None and total > (offset + count):
            next_offset = offset + count
        try:
            next_offset = int(next_offset)
        except Exception:
            return payload
        if next_offset <= offset:
            return payload

        self._prune_next_cache()
        token = uuid.uuid4().hex[:12].upper()
        action = args.get("action")
        if not isinstance(action, str) or not action.strip():
            return payload
        cache_args = dict(args)
        cache_args.pop("next_token", None)
        cache_args.pop("token", None)
        cache_args.pop("cursor", None)
        self._next_cache[token] = {
            "tool": tool_name,
            "action": action,
            "args": cache_args,
            "next_offset": next_offset,
            "created_at": time.time(),
        }
        out = dict(payload)
        out["next_token"] = token
        out["next_offset"] = next_offset
        return out

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

    def _extract_response_options(self, args: Any) -> tuple[dict, dict]:
        if not isinstance(args, dict):
            return {}, self._default_response_options()

        exec_args = dict(args)
        opts = self._default_response_options()

        qol_mode = self._pop_first(exec_args, ["_qol_mode", "qol_mode"], None)
        if isinstance(qol_mode, str):
            qol_mode = qol_mode.strip().lower()
        if qol_mode in {"tiny", "balanced", "debug"}:
            profile = self._qol_profiles.get(qol_mode, {})
            if profile:
                opts.update(profile)
        else:
            qol_mode = self.default_qol_mode
            profile = self._qol_profiles.get(qol_mode, {})
            if profile:
                opts.update(profile)
        opts["qol_mode"] = qol_mode

        mode = self._pop_first(exec_args, ["_response_mode", "response_mode"], None)
        compact_toggle = self._pop_first(exec_args, ["_compact", "compact"], None)
        if compact_toggle is not None:
            mode = "compact" if _coerce_bool(compact_toggle, True) else "full"
        if isinstance(mode, str):
            mode = mode.strip().lower()
        if mode not in {"compact", "full"}:
            mode = opts.get("mode", self.default_response_mode)
        opts["mode"] = mode
        compact_mode = mode == "compact"

        detail_level = self._pop_first(exec_args, ["_error_details"], None)
        if detail_level is None:
            detail_level = (
                opts.get("error_details", self.default_error_detail_level)
                if compact_mode
                else "full"
            )
        if isinstance(detail_level, str):
            detail_level = detail_level.strip().lower()
        if detail_level not in {"none", "basic", "full"}:
            detail_level = "basic" if compact_mode else "full"
        opts["error_details"] = detail_level

        opts["fields"] = _parse_str_list(
            self._pop_first(exec_args, ["_response_fields"], None)
        )
        opts["omit"] = _parse_str_list(
            self._pop_first(exec_args, ["_response_omit"], None)
        )

        max_items_raw = self._pop_first(exec_args, ["_response_max_items"], None)
        max_string_raw = self._pop_first(exec_args, ["_response_max_string"], None)
        char_budget_raw = self._pop_first(exec_args, ["_response_char_budget"], None)

        opts["max_items"] = (
            _bounded_int(
                max_items_raw,
                int(opts.get("max_items", self.default_compact_max_items)),
                min_value=1,
                max_value=10_000,
            )
            if compact_mode or max_items_raw is not None
            else 10_000
        )
        opts["max_string"] = (
            _bounded_int(
                max_string_raw,
                int(opts.get("max_string", self.default_compact_max_string)),
                min_value=64,
                max_value=500_000,
            )
            if compact_mode or max_string_raw is not None
            else 500_000
        )
        opts["char_budget"] = (
            _bounded_int(
                char_budget_raw,
                int(opts.get("char_budget", self.default_compact_char_budget)),
                min_value=500,
                max_value=2_000_000,
            )
            if compact_mode or char_budget_raw is not None
            else 0
        )

        opts["drop_empty"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_drop_empty"], None),
            bool(opts.get("drop_empty", compact_mode)),
        )
        opts["drop_false"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_drop_false"], None),
            bool(opts.get("drop_false", compact_mode)),
        )
        opts["drop_ok"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_drop_ok"], None),
            bool(opts.get("drop_ok", compact_mode)),
        )
        opts["dedupe_counts"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_dedupe_counts"], None),
            bool(opts.get("dedupe_counts", compact_mode)),
        )
        opts["strip_meta"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_strip_meta"], None),
            bool(opts.get("strip_meta", compact_mode)),
        )
        opts["table_mode"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_table"], None),
            bool(
                opts.get(
                    "table_mode", self.default_table_mode if compact_mode else False
                )
            ),
        )
        opts["batch_compact"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_batch_compact"], None),
            bool(
                opts.get(
                    "batch_compact",
                    self.default_batch_compact if compact_mode else False,
                )
            ),
        )
        # Universal output filtering (applies to ALL tools)
        opts["output_grep"] = self._pop_first(exec_args, ["output_grep"], None)
        opts["output_head"] = self._pop_first(exec_args, ["output_head"], None)
        opts["output_tail"] = self._pop_first(exec_args, ["output_tail"], None)
        opts["output_skip"] = self._pop_first(exec_args, ["output_skip"], None)
        opts["output_path"] = self._pop_first(exec_args, ["output_path"], None)
        opts["output_pluck"] = self._pop_first(exec_args, ["output_pluck"], None)
        return exec_args, opts

    def _default_response_options(self) -> dict:
        return {
            "mode": self.default_response_mode,
            "fields": [],
            "omit": [],
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
            "output_grep": None,
            "output_head": None,
            "output_tail": None,
            "output_skip": None,
            "output_path": None,
            "output_pluck": None,
        }

    def _compact_error_details(self, details: Any, opts: dict) -> Any:
        level = opts.get("error_details", "basic")
        if level == "full":
            return details
        if level == "none":
            return None
        if not isinstance(details, dict):
            return details
        max_items = max(1, int(opts.get("max_items", 20)))
        max_string = max(64, int(opts.get("max_string", 512)))
        out = {}
        for key, value in details.items():
            if key in _COMPACT_META_KEYS:
                continue
            if isinstance(value, str):
                if len(value) > max_string:
                    out[key] = (
                        f"{value[:max_string]}...(+{len(value) - max_string} chars)"
                    )
                else:
                    out[key] = value
                continue
            if isinstance(value, list):
                keep = value[:max_items]
                out[key] = keep
                if len(value) > len(keep):
                    out[f"{key}_more"] = len(value) - len(keep)
                continue
            out[key] = value

        for key in _COMPACT_DETAIL_LIST_KEYS:
            value = out.get(key)
            if isinstance(value, list) and len(value) > max_items:
                out[key] = value[:max_items]
                out[f"{key}_more"] = len(value) - max_items
        return out or None

    def _maybe_tableify(self, value: Any, opts: dict) -> Any:
        if not opts.get("table_mode"):
            return value
        if not isinstance(value, list):
            return value
        if len(value) < 4:
            return value
        rows = [item for item in value if isinstance(item, dict)]
        if len(rows) != len(value):
            return value
        common = None
        for row in rows:
            keys = tuple(row.keys())
            if common is None:
                common = keys
            elif keys != common:
                return value
        if not common:
            return value
        if len(common) > 24:
            return value
        max_items = max(1, int(opts.get("max_items", len(rows))))
        sliced = rows[:max_items]
        table_rows = [[row.get(col) for col in common] for row in sliced]
        table = {"columns": list(common), "rows": table_rows, "count": len(table_rows)}
        if len(rows) > len(sliced):
            table["total"] = len(rows)
        return table

    def _compact_value(self, value: Any, opts: dict) -> Any:
        max_items = max(1, int(opts.get("max_items", 10_000)))
        max_string = max(64, int(opts.get("max_string", 500_000)))

        if isinstance(value, dict):
            out = {}
            for key, raw in value.items():
                if opts.get("strip_meta") and key in _COMPACT_META_KEYS:
                    continue
                if key == "ok" and raw is True and opts.get("drop_ok"):
                    continue
                if key == "details":
                    compact_details = self._compact_error_details(raw, opts)
                    if compact_details is None and opts.get("drop_empty"):
                        continue
                    out[key] = compact_details
                    continue
                compacted = self._compact_value(raw, opts)
                if compacted is _COMPACT_DROP and raw is False and key == "firmware_detected":
                    # Keep explicit false for workflow metadata contracts.
                    compacted = False
                if compacted is _COMPACT_DROP:
                    continue
                out[key] = compacted

            if opts.get("dedupe_counts"):
                list_lengths = [len(v) for v in out.values() if isinstance(v, list)]
                if (
                    "count" in out
                    and isinstance(out["count"], int)
                    and out["count"] in list_lengths
                ):
                    out.pop("count", None)
                if out.get("offset") == 0:
                    out.pop("offset", None)
                if isinstance(out.get("count"), int) and out.get("total") == out.get(
                    "count"
                ):
                    out.pop("total", None)
                if isinstance(out.get("count"), int) and out.get("limit") == out.get(
                    "count"
                ):
                    out.pop("limit", None)
                if isinstance(out.get("items"), list) and out.get("next_offset") == len(
                    out["items"]
                ):
                    out.pop("next_offset", None)
                if isinstance(out.get("results"), list) and out.get("count") == len(
                    out["results"]
                ):
                    out.pop("count", None)
                # Prefer compact text form when both are present unless caller explicitly requests items.
                requested_fields = set(opts.get("fields") or [])
                if (
                    "functions" in out
                    and isinstance(out.get("functions"), str)
                    and isinstance(out.get("items"), list)
                    and "items" not in requested_fields
                ):
                    out.pop("items", None)
            if not out and opts.get("drop_empty"):
                return _COMPACT_DROP
            return out

        if isinstance(value, list):
            value = self._maybe_tableify(value, opts)
            if isinstance(value, dict):
                return self._compact_value(value, opts)
            trimmed = value[:max_items]
            out = []
            for item in trimmed:
                compacted = self._compact_value(item, opts)
                if compacted is _COMPACT_DROP:
                    continue
                out.append(compacted)
            if not out and opts.get("drop_empty"):
                return _COMPACT_DROP
            return out

        if isinstance(value, str):
            if len(value) > max_string:
                return f"{value[:max_string]}...(+{len(value) - max_string} chars)"
            if value == "" and opts.get("drop_empty"):
                return _COMPACT_DROP
            return value
        if value is None and opts.get("drop_empty"):
            return _COMPACT_DROP
        if value is False and opts.get("drop_false"):
            return _COMPACT_DROP
        return value

    def _project_top_level_fields(self, payload: Any, opts: dict) -> Any:
        if not isinstance(payload, dict):
            return payload
        fields = set(opts.get("fields") or [])
        omit = set(opts.get("omit") or [])
        always_keep = {
            "error",
            "code",
            "message",
            "hint",
            "_truncated",
            "_continue",
            "workflow_meta",
        }
        if fields:
            keep = fields.union(always_keep)
            projected = {k: v for k, v in payload.items() if k in keep}
        else:
            projected = dict(payload)
        for key in omit:
            if key in always_keep:
                continue
            projected.pop(key, None)
        return projected

    def _compact_batch_result(self, payload: Any, opts: dict) -> Any:
        if not opts.get("batch_compact"):
            return payload
        if not isinstance(payload, dict):
            return payload
        results = payload.get("results")
        if not isinstance(results, list):
            return payload
        compact_results = []
        for item in results:
            if not isinstance(item, dict):
                compact_results.append(item)
                continue
            raw_result = item.get("result")
            is_error = bool(isinstance(raw_result, dict) and raw_result.get("error"))
            entry = {
                # Keep compact external key as `tool` for readability (source batch rows use `name`).
                "tool": item.get("name"),
                "ok": not is_error,
                "data": raw_result,
            }
            compact_results.append(entry)
        out = {"results": compact_results}
        if isinstance(payload.get("summary"), dict):
            out["summary"] = payload.get("summary")
        if payload.get("error"):
            out["error"] = payload.get("error")
        # Preserve additional top-level metadata (for example workflow_meta)
        # so callers can still reason about execution path in compact mode.
        for k, v in payload.items():
            if k in {"results", "summary", "error"}:
                continue
            out.setdefault(k, v)
        return out

    def _pointer_note_signal_from_text(self, text: str) -> float:
        if not text:
            return 0.0
        s = text.strip()
        if not s:
            return 0.0
        lowered = s.lower()
        score = 0.0
        hex_matches = list(_POINTER_NOTE_HEX_RE.finditer(s))
        if hex_matches:
            score += 1.0
        if _POINTER_NOTE_MATH_RE.search(s):
            score += 2.0
        if len(hex_matches) >= 2:
            score += 1.0
        if any(k in lowered for k in _POINTER_NOTE_SIGNAL_KEYWORDS):
            score += 1.0
        return score

    def _pointer_note_signal_from_value(self, value: Any, depth: int = 0) -> float:
        if depth > _POINTER_NOTE_SIGNAL_MAX_DEPTH:
            return 0.0
        if isinstance(value, str):
            return self._pointer_note_signal_from_text(value)
        if isinstance(value, int):
            return 0.5 if value >= 0x1000 else 0.0
        if isinstance(value, list):
            return sum(
                self._pointer_note_signal_from_value(v, depth + 1)
                for v in value[:_POINTER_NOTE_SIGNAL_MAX_LIST_ITEMS]
            )
        if isinstance(value, dict):
            score = 0.0
            for idx, (k, v) in enumerate(value.items()):
                if idx >= _POINTER_NOTE_SIGNAL_MAX_DICT_ITEMS:
                    break
                child_score = self._pointer_note_signal_from_value(v, depth + 1)
                if isinstance(k, str):
                    kl = k.lower()
                    if child_score > 0 and any(
                        sig in kl for sig in _POINTER_NOTE_SIGNAL_KEYWORDS
                    ):
                        score += 1.0
                score += child_score
            return score
        return 0.0

    def _compute_pointer_note_signal(
        self, tool_name: str, call_args: Any, payload: Any
    ) -> float:
        score = 0.0
        tn = str(tool_name or "").strip().lower()
        if tn in _POINTER_NOTE_SIGNAL_TOOLS_STRONG:
            score += 2.0
        elif tn in _POINTER_NOTE_SIGNAL_TOOLS_HINT:
            score += 1.0
        if isinstance(call_args, dict):
            for idx, (k, v) in enumerate(call_args.items()):
                if idx >= 20:
                    break
                if isinstance(k, str):
                    kl = k.lower()
                    if kl.startswith("_"):
                        continue
                    if any(sig in kl for sig in _POINTER_NOTE_SIGNAL_KEYWORDS):
                        score += 1.0
                score += self._pointer_note_signal_from_value(v)
        if isinstance(payload, dict):
            payload_focus: Dict[str, Any] = {}
            for key in (
                "address",
                "addr",
                "target",
                "query",
                "pattern",
                "matches",
                "items",
            ):
                if key in payload:
                    val = payload.get(key)
                    if val not in (None, "", [], {}):
                        payload_focus[key] = val
            score += self._pointer_note_signal_from_value(payload_focus)
        return min(score, 10.0)

    def _should_include_pointer_note(
        self, tool_name: str, call_args: Any, payload: Any
    ) -> bool:
        if isinstance(payload, dict) and payload.get("error"):
            return False
        signal = self._compute_pointer_note_signal(tool_name, call_args, payload)
        if signal > 0:
            self._pointer_note_pending_signal = min(
                float(self._pointer_note_min_signal)
                * _POINTER_NOTE_MAX_SIGNAL_MULTIPLIER,
                self._pointer_note_pending_signal + signal,
            )
        else:
            self._pointer_note_pending_signal = max(
                0.0, self._pointer_note_pending_signal - 0.25
            )
            return False
        if self._pointer_note_pending_signal < float(self._pointer_note_min_signal):
            return False
        now = time.time()
        if self._pointer_note_last_shown_at > 0 and (
            now - self._pointer_note_last_shown_at
        ) < float(self._pointer_note_interval_seconds):
            return False
        self._pointer_note_last_shown_at = now
        self._pointer_note_pending_signal = 0.0
        return True

    def _validate_address_lockstep(self, call_args: Any, payload: Any) -> list[dict]:
        """Detect addresses in call_args that do not appear in previous payload output."""
        if not isinstance(call_args, dict):
            return []
        requested = self._collect_hex_addresses(call_args, max_items=12)
        if not requested:
            return []
        available = self._collect_hex_addresses(payload, max_items=50)
        available_set = set(available)
        warnings: list[dict] = []
        for addr in requested:
            if addr not in available_set:
                warnings.append(
                    {
                        "addr": addr,
                        "warning": "This address was not present in the previous tool output. Verify with calc/memory before reasoning.",
                        "suggested_verification": {
                            "tool": "calc",
                            "arguments": {"action": "deref", "addr": addr, "type": "u32"},
                        },
                    }
                )
        return warnings

    def _assemble_and_inject_context(
        self,
        tool_name: str,
        action: str,
        payload: dict,
        addr: str,
    ) -> None:
        """
        Build a context_pack via the intelligence layer (bge-code-v1) and inject
        it into the payload so the LLM receives relevant context alongside results.
        Replaces the cartographer + attention_kernel + cognitive_layer pipeline.
        """
        if not isinstance(payload, dict) or payload.get("error"):
            return
        if tool_name in {"session", "blackboard", "batch", "truncation", "wiki",
                         "predictor", "workflow"}:
            return

        try:
            session_id = (
                getattr(self.current_session, "session_id", None)
                if self.current_session else "default"
            )
            idb_path = (
                getattr(self.current_session, "idb_path", None)
                if self.current_session else None
            )
            bb_store = self._get_blackboard_store()
            pack = self.assembler.assemble(
                tool=tool_name,
                action=action,
                payload=payload,
                addr=addr,
                session_id=session_id or "default",
                idb_path=idb_path or "",
                bb_store=bb_store,
            )
            if pack:
                # Only inject context_pack in full mode — it's verbose
                if opts.get("mode") == "full":
                    payload["context_pack"] = pack
                elif pack.get("top_entries"):
                    # In compact mode, only inject the top entry titles (not full content)
                    payload["_context"] = [e.get("title", "") for e in pack["top_entries"][:3] if e.get("title")]
        except Exception:
            pass

    def _observe_memrl(self, tool_name: str, action: str, payload: dict) -> None:
        """No-op stub — MemRL feedback now runs via auto_reward_for_addr in _record_activity."""
        pass

    def _collect_hex_addresses(self, value: Any, max_items: int = 8) -> list[str]:
        found: list[str] = []

        def _push(addr_text: str) -> None:
            if not addr_text:
                return
            norm = addr_text.lower()
            if not norm.startswith("0x"):
                return
            if norm in found:
                return
            found.append(norm)

        def _walk(v: Any, depth: int = 0) -> None:
            if len(found) >= max_items or depth > 3:
                return
            if isinstance(v, str):
                for m in _POINTER_NOTE_HEX_RE.finditer(v):
                    _push(m.group(0))
            elif isinstance(v, int):
                if v >= 0x1000:
                    _push(hex(v))
            elif isinstance(v, list):
                for item in v[:12]:
                    _walk(item, depth + 1)
                    if len(found) >= max_items:
                        break
            elif isinstance(v, dict):
                for idx, (_, item) in enumerate(v.items()):
                    if idx >= 24:
                        break
                    _walk(item, depth + 1)
                    if len(found) >= max_items:
                        break

        _walk(value)
        return found[:max_items]

    def _guardrail_mode_from_args(self, call_args: Any) -> str:
        """Resolve per-call guardrail mode: assist|enforce|off."""
        mode = ""
        if isinstance(call_args, dict):
            mode = str(call_args.get("_guardrail_mode") or "").strip().lower()
        if mode in {"off", "none", "disable", "disabled"}:
            return "off"
        if mode in {"enforce", "strict", "block"}:
            return "enforce"
        return "assist"

    def _guardrail_reason_tags(self, tool_name: str, call_args: Any, payload: Any) -> list[str]:
        tags: list[str] = []
        tn = str(tool_name or "").lower()
        if tn in {"code", "xref_analysis", "graph", "ctree", "static_trace", "memory", "calc"}:
            tags.append("address-heavy-tool")
        if isinstance(call_args, dict):
            keys = {str(k).lower() for k in call_args.keys()}
            if {"addr", "address", "target"} & keys:
                tags.append("explicit-address-arg")
            if {"offset", "offsets", "base", "size"} & keys:
                tags.append("offset-arithmetic")
        addrs = self._collect_hex_addresses(call_args)
        if len(addrs) < 2:
            addrs.extend([a for a in self._collect_hex_addresses(payload) if a not in addrs])
        if len(addrs) >= 2:
            tags.append("multiple-hex-addresses")
        return tags

    def _apply_output_filters(self, payload: Any, opts: dict) -> Any:
        """Apply universal output filtering (grep, head, tail, skip, path, pluck)."""
        import re as _re

        # Path extraction: extract a nested field from a dict
        path = opts.get("output_path")
        if path and isinstance(payload, dict):
            current = payload
            for part in str(path).split("."):
                if isinstance(current, dict):
                    current = current.get(part)
                elif isinstance(current, list) and part.isdigit():
                    idx = int(part)
                    current = current[idx] if 0 <= idx < len(current) else None
                else:
                    current = None
                if current is None:
                    break
            payload = current if current is not None else {}

        # If payload is a list, apply head/tail/skip/grep/pluck
        if isinstance(payload, list):
            skip = opts.get("output_skip")
            if skip is not None:
                try:
                    payload = payload[int(skip):]
                except Exception:
                    pass

            head = opts.get("output_head")
            if head is not None:
                try:
                    payload = payload[:int(head)]
                except Exception:
                    pass

            tail = opts.get("output_tail")
            if tail is not None:
                try:
                    payload = payload[-int(tail):]
                except Exception:
                    pass

            grep = opts.get("output_grep")
            if grep:
                try:
                    pattern = _re.compile(str(grep), _re.IGNORECASE)
                    payload = [x for x in payload if pattern.search(str(x))]
                except Exception:
                    pass

            pluck = opts.get("output_pluck")
            if pluck:
                try:
                    key = str(pluck)
                    payload = [
                        x.get(key) if isinstance(x, dict) else x
                        for x in payload
                    ]
                except Exception:
                    pass

        # If payload is a dict with a list inside, try to apply grep to common list fields
        elif isinstance(payload, dict) and opts.get("output_grep"):
            pattern_str = opts.get("output_grep")
            try:
                pattern = _re.compile(str(pattern_str), _re.IGNORECASE)
                for k, v in list(payload.items()):
                    if isinstance(v, list):
                        payload[k] = [x for x in v if pattern.search(str(x))]
            except Exception:
                pass

        return payload

    def _build_llm_execution_directive(self, payload: dict) -> Optional[str]:
        """Build a compact directive from tool-first gating fields."""
        if not isinstance(payload, dict):
            return None
        must_call = bool(payload.get("must_call_before_answer"))
        req = payload.get("required_followup_call")
        if not isinstance(req, dict):
            req = None
        if not must_call and not req:
            return None

        call_txt = "code.callers"
        if req:
            tool = str(req.get("tool") or "").strip()
            action = str(req.get("action") or "").strip()
            if tool and action:
                call_txt = f"{tool}.{action}"

        if must_call:
            return (
                f"MCP_REQUIRED_CALL: Execute `{call_txt}` before concluding. "
                "Do not finalize claims until new tool evidence is incorporated."
            )
        return (
            f"MCP_RECOMMENDED_CALL: Prefer `{call_txt}` before final answer "
            "and cite returned evidence."
        )

    def _prepare_response_payload(
        self,
        payload: Any,
        opts: dict,
        *,
        tool_name: str = "",
        call_args: Any = None,
    ) -> Any:
        include_pointer_note = self._should_include_pointer_note(
            tool_name, call_args, payload
        )
        action_name = ""
        if isinstance(call_args, dict):
            action_name = str(call_args.get("action") or "")
        if not action_name:
            action_name = str(opts.get("action") or "")
        # Apply universal output filters first
        payload = self._apply_output_filters(payload, opts)
        payload = self._json_safe_value(payload)
        full_mode = opts.get("mode") == "full"
        if full_mode:
            if isinstance(payload, dict):
                payload = dict(payload)
                if include_pointer_note:
                    reason_tags = self._guardrail_reason_tags(tool_name, call_args, payload)
                    guardrail_mode = self._guardrail_mode_from_args(call_args)
                    payload.setdefault("llm_pointer_note", LLM_POINTER_SAFETY_NOTE)
                    payload.setdefault("llm_guardrail_mode", guardrail_mode)
                    payload.setdefault("llm_guardrail_reason_tags", reason_tags)
                    # Address lockstep: warn about unseen addresses
                    lockstep_warnings = self._validate_address_lockstep(call_args, payload)
                    if lockstep_warnings:
                        payload.setdefault("llm_address_lockstep_warnings", lockstep_warnings)
            compacted = payload
        else:
            projected = self._project_top_level_fields(payload, opts)
            compacted = self._compact_value(projected, opts)
            if compacted is _COMPACT_DROP:
                compacted = {}
            compacted = self._compact_batch_result(compacted, opts)
            budget = int(opts.get("char_budget", 0) or 0)
            if budget > 0 and isinstance(compacted, dict):
                compacted = truncate_response(compacted, max_tokens=budget)

        # ---- Context Density Auto-Compaction Middleware ----
        # Skip if the caller explicitly requests raw output.
        raw_requested = False
        if isinstance(call_args, dict):
            raw_requested = _coerce_bool(call_args.get("raw"), False)
        if not raw_requested and compacted is not None:
            try:
                serialized_size = len(
                    json.dumps(compacted, ensure_ascii=False, separators=(",", ":"))
                )
                if serialized_size > CONTEXT_DENSITY_COMPACT_THRESHOLD:
                    compacted = self._context_density_optimizer.compact_response(
                        compacted,
                        budget_tokens=opts.get(
                            "char_budget", CONTEXT_DENSITY_DEFAULT_BUDGET
                        ),
                    )
            except Exception:
                # Fail-safe: never let compaction break the response path
                pass
        # ------------------------------------------------------

        if isinstance(compacted, dict):
            compacted = dict(compacted)
            if include_pointer_note:
                reason_tags = self._guardrail_reason_tags(tool_name, call_args, compacted)
                guardrail_mode = self._guardrail_mode_from_args(call_args)
                compacted.setdefault("llm_pointer_note", LLM_POINTER_SAFETY_NOTE)
                compacted.setdefault("llm_guardrail_mode", guardrail_mode)
                compacted.setdefault("llm_guardrail_reason_tags", reason_tags)
            if self.enable_response_enrichment:
                # ---- Auto-Nudge Injection ----
                try:
                    nudge = None
                    ui = getattr(self, "_usage_intel", None)
                    if ui:
                        # Primary: UsageIntelligence predictions (trained on real audit data)
                        preds = ui.predict_next(tool_name, action_name, top_k=4)
                        if preds:
                            from .auto_nudge import suggest_smart_tools
                            behavior_tags = (compacted.get("behavior_tags") or
                                             compacted.get("tags") or [])
                            static = suggest_smart_tools(tool_name, action_name,
                                                         compacted, behavior_tags)
                            # Merge: UI predictions first, then static suggestions not already covered
                            ui_set = {f"{p['tool']}:{p['action']}" for p in preds}
                            merged = [f"{p['tool']}:{p['action']}  p={p['probability']:.2f}  eff={p['effectiveness']:.2f}"
                                      for p in preds]
                            for s in static[:3]:
                                ta = s.split("=")[0] if "=" in s else s
                                if ta not in ui_set:
                                    merged.append(s)
                            nudge = {"suggested_next": merged[:5], "source": "usage_intelligence"}
                    else:
                        from .auto_nudge import get_nudge
                        idb_key = (self.current_session.idb_path if self.current_session else "")
                        nudge = get_nudge(
                            idb_key,
                            tool_name,
                            action_name,
                            compacted,
                            call_args if isinstance(call_args, dict) else {},
                        )
                    if nudge:
                        compacted["_nudge"] = nudge
                except Exception:
                    pass

            # ---- Signal-Specific Directives ----
            # Precise, copy-pasteable tool calls based on what was found in this response.
            try:
                from .response_enrichment import build_signal_directives
                func_addr = ""
                if isinstance(call_args, dict):
                    func_addr = str(call_args.get("addr") or call_args.get("addrs") or "")
                    if isinstance(func_addr, list):
                        func_addr = func_addr[0] if func_addr else ""
                directives = build_signal_directives(
                    tool_name, action_name, compacted, func_addr=func_addr
                )
                if directives:
                    # High-priority directives become the execution directive
                    high = [d for d in directives if d["priority"] == "high"]
                    if high:
                        top = high[0]
                        compacted["llm_execution_directive"] = (
                            f"REQUIRED: {top['call']}  ← {top['reason']}"
                        )
                    compacted["_next_calls"] = directives
            except Exception:
                pass

            # ---- Explicit tool-first directive ----
            try:
                directive = self._build_llm_execution_directive(compacted)
                if directive:
                    compacted.setdefault("llm_execution_directive", directive)
            except Exception:
                pass
            
            # ---- Address Patching ----
            try:
                if tool_name == "code" and action_name in ("decompile", "semantic_decompile", "disasm"):
                    from .response_enrichment import patch_addresses
                    if "pseudocode" in compacted:
                        pseudo_key = "pseudocode"
                    elif "code" in compacted:
                        pseudo_key = "code"
                    else:
                        pseudo_key = "disassembly"
                    if pseudo_key in compacted:
                        compacted[pseudo_key] = patch_addresses(compacted[pseudo_key])
            except Exception:
                pass
            
            if self.enable_response_enrichment:
                # ---- Auto-Digest ----
                try:
                    if tool_name == "code" and action_name in ("decompile", "semantic_decompile"):
                        from .response_enrichment import digest_decompiled
                        if "pseudocode" in compacted:
                            pseudo_key = "pseudocode"
                        elif "code" in compacted:
                            pseudo_key = "code"
                        else:
                            pseudo_key = "output"
                        if pseudo_key in compacted and isinstance(compacted[pseudo_key], str):
                            addr = (call_args or {}).get("addr", "") if isinstance(call_args, dict) else ""
                            # Try to get SchemaBoot attributes for richer classification
                            schema_attrs = None
                            try:
                                if addr and hasattr(self, '_insight_index') and self._insight_index:
                                    func_data = self._insight_index.get_function(addr) if hasattr(self._insight_index, 'get_function') else None
                                    if func_data:
                                        schema_attrs = func_data
                            except Exception:
                                pass
                            digest = digest_decompiled(compacted[pseudo_key], func_addr=addr, schema_attrs=schema_attrs)
                            if digest and any(digest.values()):
                                compacted["_digest"] = digest
                except Exception:
                    pass
            
            if self.enable_response_enrichment:
                # ---- Session Resume ----
                try:
                    if hasattr(self, 'session_mgr') and self.current_session:
                        from .response_enrichment import build_session_resume
                        sid = self.current_session.session_id
                        # Only inject on first few calls
                        if call_args and isinstance(call_args, dict):
                            call_count = call_args.get("_call_seq", 0)
                            if not isinstance(call_count, int) or call_count <= 2:
                                resume = build_session_resume(self.session_mgr, sid)
                                if resume:
                                    compacted["_session_resume"] = resume
                except Exception:
                    pass
            
            if self.enable_response_enrichment:
                # ---- Ghost Chain Inlining ----
                try:
                    addr = (call_args or {}).get("addr", "") if isinstance(call_args, dict) else ""
                    ghost_action = action_name
                    if tool_name == "code" and addr and ghost_action in ("decompile", "semantic_decompile"):
                        from .response_enrichment import GHOST_CHAINS
                    else:
                        GHOST_CHAINS = {}
                    ghost_results = {}
                    ghost_key = (tool_name, ghost_action)
                    
                    # Phase 1: Basic companions (callers, callees, strings)
                    for ghost_tool, ghost_args_template in GHOST_CHAINS.get(ghost_key, []):
                        ghost_args = dict(ghost_args_template)
                        for k, v in ghost_args.items():
                            if isinstance(v, str):
                                v = v.replace("__ADDR__", str(addr))
                                ghost_args[k] = v
                        try:
                            ghost_res = self._execute_tool(ghost_tool, ghost_args)
                            if isinstance(ghost_res, dict) and ghost_res.get("ok"):
                                key_name = ghost_args.get("action", ghost_tool)
                                if "callers" in key_name:
                                    items = ghost_res.get("callers", ghost_res.get("matches", ghost_res.get("results", [])))
                                    ghost_results["callers"] = items[:5] if isinstance(items, list) else str(items)[:200]
                                elif "callees" in key_name:
                                    items = ghost_res.get("callees", ghost_res.get("matches", ghost_res.get("results", [])))
                                    ghost_results["callees"] = items[:5] if isinstance(items, list) else str(items)[:200]
                                elif "strings" in key_name:
                                    items = ghost_res.get("strings", ghost_res.get("matches", ghost_res.get("results", [])))
                                    ghost_results["strings"] = items[:5] if isinstance(items, list) else str(items)[:200]
                                elif "calls" in key_name:
                                    items = ghost_res.get("calls", ghost_res.get("results", []))
                                    ghost_results["api_calls"] = items[:5] if isinstance(items, list) else str(items)[:200]
                                else:
                                    ghost_results[key_name] = str(ghost_res)[:200]
                        except Exception:
                            pass
                    
                    # Phase 2: BridgeRAG multi-hop relation discovery
                    try:
                        bridge_res = self._execute_tool("bridgerag", {
                            "action": "bridges",
                            "func_ea": addr,
                            "bridge_types": ["apis", "strings"],
                        })
                        if isinstance(bridge_res, dict) and bridge_res.get("ok"):
                            bridges = bridge_res.get("bridges", {})
                            if bridges:
                                ghost_results["bridge_entities"] = {
                                    "apis": bridges.get("apis", [])[:5],
                                    "strings": bridges.get("strings", [])[:5],
                                    "note": "Shared APIs/strings with other functions. Use bridgerag.search for full discovery."
                                }
                    except Exception:
                        pass
                    
                    # Phase 3: MbaGCN structural similarity
                    try:
                        mbagcn_res = self._execute_tool("mbagcn", {
                            "action": "similar",
                            "addr": addr,
                            "top_k": 3,
                        })
                        if isinstance(mbagcn_res, dict) and mbagcn_res.get("ok"):
                            similar = mbagcn_res.get("results", [])
                            if similar:
                                ghost_results["structurally_similar"] = [
                                    {"addr": s.get("ea", ""), "name": s.get("name", ""),
                                     "similarity": s.get("similarity", 0)}
                                    for s in similar[:3]
                                ]
                                ghost_results["structurally_similar_note"] = (
                                    "These functions have similar CFG structure. They may share behavior. "
                                    "Use code.decompile on them to investigate."
                                )
                    except Exception:
                        pass
                    
                    # Phase 4: InsightIndex behavior-tag discovery
                    try:
                        idx = getattr(self, '_insight_index', None)
                        if idx and hasattr(idx, 'query_by_tags'):
                            # Try to get tags for this function
                            func_attrs = idx.get_function(addr) if hasattr(idx, 'get_function') else None
                            tags = func_attrs.get("behavior_tags", []) if func_attrs else []
                            if not tags:
                                # Fall back to L2 global facts
                                if hasattr(self, '_global_facts'):
                                    tags = []
                            if tags:
                                related = idx.query_by_tags(tags[:3], mode="or") if hasattr(idx, 'query_by_tags') else []
                                if related:
                                    ghost_results["same_behavior_tags"] = {
                                        "tags": tags,
                                        "functions": [str(r)[:80] for r in related[:5]],
                                        "note": "Other functions with the same behavior tags. May be part of the same component."
                                    }
                    except Exception:
                        pass
                    
                    # Phase 5: L2 GlobalFactsDatabase compiler/API pattern lookup
                    try:
                        gf = getattr(self, '_global_facts', None)
                        if gf and hasattr(gf, 'query_facts'):
                            # Query for compiler signatures
                            compiler_facts = gf.query_facts(category="compiler_signature", limit=3)
                            api_facts = gf.query_facts(category="common_api", limit=5)
                            if compiler_facts:
                                ghost_results["compiler_info"] = [f.get("fact_value", "")[:100] for f in compiler_facts]
                            if api_facts:
                                ghost_results["known_api_patterns"] = [f.get("fact_key", "")[:80] for f in api_facts]
                    except Exception:
                        pass
                    
                    # Phase 6: TurboQuant embedding similarity
                    try:
                        tq_res = self._execute_tool("turboquant", {
                            "action": "query",
                            "query_key": addr,
                            "top_k": 3,
                        })
                        if isinstance(tq_res, dict) and tq_res.get("ok"):
                            tq_similar = tq_res.get("results", [])
                            if tq_similar:
                                ghost_results["embedding_similar"] = [
                                    {"key": s.get("key", ""), "score": s.get("score", 0)}
                                    for s in tq_similar[:3]
                                ]
                    except Exception:
                        pass
                    
                    # Phase 7: C2 risk scoring (ML-powered, deterministic)
                    try:
                        c2_res = self._execute_tool("string_ops", {
                            "action": "score_c2",
                            "addr": addr,
                        })
                        if isinstance(c2_res, dict) and c2_res.get("ok"):
                            c2_risk = c2_res.get("c2_risk")
                            if isinstance(c2_risk, dict) and c2_risk.get("overall_score", 0) > 0:
                                ghost_results["c2_risk"] = c2_risk
                    except Exception:
                        pass
                    
                    if ghost_results:
                        compacted["_inline"] = ghost_results
                except Exception:
                    pass
            
            # ---- Auto-Advance Phase ----
            try:
                if hasattr(self, 'session_mgr') and self.current_session:
                    sid = self.current_session.session_id
                    data = self.session_mgr._load_skills(sid)
                    activity_log = data.get("activity_log", [])
                    # Count decompiles, imports analyzed, xrefs traced
                    decompile_count = sum(1 for e in activity_log if e.get("action") in ("decompile", "semantic_decompile"))
                    import_count = sum(1 for e in activity_log if e.get("tool") == "imports_deep" or e.get("tool") == "data" and e.get("action") == "imports")
                    # Check phase thresholds
                    from .session import _ANALYSIS_PHASES
                    session = self.session_mgr.sessions.get(sid)
                    if session:
                        current_phase = session.phase
                        phases = sorted(_ANALYSIS_PHASES.keys(), key=lambda p: _ANALYSIS_PHASES[p]["order"])
                        try:
                            idx = phases.index(current_phase)
                            if idx < len(phases) - 1:
                                next_phase = phases[idx + 1]
                                threshold = _ANALYSIS_PHASES[next_phase].get("threshold", {})
                                if (decompile_count >= threshold.get("functions_decompiled", 999) and
                                    import_count >= threshold.get("imports_analyzed", 999)):
                                    session.phase = next_phase
                                    self.session_mgr._save_metadata(session)
                        except (ValueError, IndexError):
                            pass
            except Exception:
                pass
            
            # ---- Auto-Blackboard ----
            try:
                from .response_enrichment import auto_blackboard_write
                addr = (call_args or {}).get("addr", "") if isinstance(call_args, dict) else ""
                bb_entries = auto_blackboard_write(tool_name, str(opts.get("action", "")), compacted, addr)
                bb_written = 0
                if bb_entries:
                    # Write to blackboard with dedup check: skip entries whose
                    # addr+category+title already exist to avoid unbounded noise.
                    try:
                        bb_store = self._get_blackboard_store()
                        for entry in bb_entries:
                            e_addr = str(entry.get("addr", addr) or "")
                            e_title = str(entry.get("name") or entry.get("title") or "")
                            e_category = str(entry.get("category") or "general")
                            if not e_title:
                                continue
                            # Skip if identical entry already exists
                            if bb_store and bb_store.exists(e_addr, e_category, e_title):
                                continue
                            wr = self._execute_tool("blackboard", {
                                "action": "write",
                                "addr": e_addr,
                                "title": e_title,
                                "content": str(entry.get("notes") or entry.get("content") or ""),
                                "category": e_category,
                                "tags": entry.get("tags") or [],
                                "confidence": float(entry.get("confidence", 0.6)),
                            })
                            if isinstance(wr, dict) and wr.get("ok"):
                                bb_written += 1
                    except Exception:
                        pass

                # LLM-visible state-sync guidance: make blackboard usage explicit.
                if isinstance(compacted, dict):
                    if bb_entries:
                        compacted.setdefault(
                            "llm_state_sync",
                            {
                                "blackboard_entries_suggested": len(bb_entries),
                                "blackboard_entries_written": bb_written,
                                "recommended_next": {
                                    "tool": "blackboard",
                                    "arguments": {"action": "list"},
                                },
                            },
                        )
                    else:
                        # Periodic reminder for long analysis chains to externalize state.
                        if tool_name in {"code", "search", "xref_analysis", "threat_hunt", "predictor"}:
                            compacted.setdefault(
                                "llm_state_sync_hint",
                                {
                                    "message": "Persist important findings to blackboard to avoid context-loss.",
                                    "tool": "blackboard",
                                    "arguments": {
                                        "action": "write",
                                        "name": "finding_summary",
                                        "notes": "<concise finding>",
                                        "category": "analysis",
                                        "priority": 3,
                                    },
                                },
                            )
            except Exception:
                pass

            # ---- State Contract Enforcement ----
            try:
                if (
                    hasattr(self, "session_mgr")
                    and self.current_session
                    and tool_name not in {"session", "blackboard", "batch", "predictor", "workflow"}
                ):
                    sid = self.current_session.session_id
                    contract = self.session_mgr.check_state_contract(sid, window=16)
                    if isinstance(contract, dict) and contract.get("ok") and not contract.get("contract_met"):
                        # Only show reminder every 16 calls to reduce bloat
                        compacted.setdefault(
                            "llm_state_contract_reminder",
                            {
                                "message": f"No blackboard write in last {contract.get('window_size', 16)} calls. Persist findings to maintain state.",
                                "recommended_action": contract.get("recommended_action"),
                                "contract_met": False,
                            },
                        )
            except Exception:
                pass

            # ---- Confidence Gate ----
            try:
                if isinstance(compacted, dict):
                    conf = compacted.get("confidence")
                    if conf is not None:
                        try:
                            conf_val = float(conf)
                            if conf_val < 0.5:
                                compacted.setdefault(
                                    "llm_low_confidence_gate",
                                    {
                                        "confidence": conf_val,
                                        "threshold": 0.5,
                                        "message": "Result confidence is below threshold. Verify before acting.",
                                        "verification_actions": [
                                            {"tool": "calc", "arguments": {"action": "eval", "expr": "1+1"}},
                                            {"tool": "memory", "arguments": {"action": "read", "addr": "0x0", "size": 16}},
                                        ],
                                    },
                                )
                        except Exception:
                            pass
            except Exception:
                pass

            # ---- Intelligence Layer: assemble real context and inject ----
            try:
                if isinstance(compacted, dict):
                    addr = ""
                    if isinstance(call_args, dict):
                        addr = str(call_args.get("addr") or call_args.get("addrs") or "")
                    self._assemble_and_inject_context(
                        tool_name, action_name, compacted, addr
                    )
            except Exception:
                pass
        return compacted

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
                    cmd.append(f"-b{int(opts['baseaddr']):#x}")
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

    def _semantic_index_db_path(self, session_id: str) -> str:
        """Return the per-session SQLite path used for semantic gadget indexing."""
        artifact_dir = self.session_mgr.get_session_artifact_dir(session_id, create=True)
        return os.path.join(artifact_dir, SEMANTIC_INDEX_DB_NAME)

    def _semantic_index_fingerprint(self, session: Session) -> str:
        """Build a stable content/version fingerprint used to validate cached indexes."""
        hasher = hashlib.sha256()
        hasher.update(struct.pack(">I", SEMANTIC_INDEX_VERSION))
        for path in (session.idb_path, session.binary_path):
            raw = str(path or "")
            hasher.update(raw.encode("utf-8", errors="ignore"))
            try:
                st = os.stat(raw)
                hasher.update(struct.pack(">Q", int(st.st_size)))
                hasher.update(struct.pack(">Q", int(st.st_mtime_ns)))
            except OSError:
                hasher.update(struct.pack(">Q", 0))
                hasher.update(struct.pack(">Q", 0))
        return hasher.hexdigest()

    def _semantic_index_connect(self, db_path: str) -> sqlite3.Connection:
        """Open a tuned SQLite connection for semantic gadget index reads/writes."""
        conn = sqlite3.connect(db_path, timeout=max(1.0, SEMANTIC_INDEX_WAIT_SECONDS))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _semantic_index_ensure_schema(self, conn: sqlite3.Connection) -> None:
        """Create semantic index schema objects if they do not exist yet."""
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS gadgets (
                source_action TEXT NOT NULL,
                addr TEXT NOT NULL,
                insns INTEGER NOT NULL,
                gadget TEXT NOT NULL,
                norm_text TEXT NOT NULL,
                tokens TEXT NOT NULL,
                digest BLOB NOT NULL,
                PRIMARY KEY (source_action, addr, digest)
            );
            CREATE INDEX IF NOT EXISTS idx_gadgets_source_action ON gadgets(source_action);
            """
        )

    def _semantic_index_meta(self, conn: sqlite3.Connection) -> dict[str, str]:
        """Read semantic index metadata as a flat key/value map."""
        rows = conn.execute("SELECT key, value FROM meta").fetchall()
        return {str(k): str(v) for k, v in rows}

    def _semantic_index_put_meta(self, conn: sqlite3.Connection, meta: dict[str, Any]) -> None:
        """Replace semantic index metadata with the supplied values."""
        conn.execute("DELETE FROM meta")
        conn.executemany(
            "INSERT INTO meta(key, value) VALUES(?, ?)",
            [(str(k), str(v)) for k, v in meta.items()],
        )

    def _semantic_extract_gadget_rows(
        self, action: str, payload: Any
    ) -> list[tuple[str, int, str]]:
        """Extract normalized (addr, insns, gadget text) rows from gadget tool payloads."""
        rows: list[tuple[str, int, str]] = []
        if not isinstance(payload, dict):
            return rows
        gadgets = payload.get("gadgets")
        if isinstance(gadgets, list):
            for item in gadgets:
                if not isinstance(item, dict):
                    continue
                addr = str(item.get("addr") or "").strip()
                text = str(item.get("gadget") or "").strip()
                if not addr or not text:
                    continue
                insns = _bounded_int(item.get("insns", 0), 0, min_value=0, max_value=4096)
                rows.append((addr, insns, text))
            return rows
        if action == "pivot_chains":
            categories = payload.get("categories")
            if not isinstance(categories, dict):
                return rows
            for cat_payload in categories.values():
                if not isinstance(cat_payload, dict):
                    continue
                cat_gadgets = cat_payload.get("gadgets")
                if not isinstance(cat_gadgets, list):
                    continue
                for item in cat_gadgets:
                    if not isinstance(item, dict):
                        continue
                    addr = str(item.get("addr") or "").strip()
                    text = str(item.get("gadget") or "").strip()
                    if not addr or not text:
                        continue
                    insns = _bounded_int(
                        item.get("insns", 0), 0, min_value=0, max_value=4096
                    )
                    rows.append((addr, insns, text))
        return rows

    def _semantic_index_rebuild(
        self,
        session: Session,
        source_actions: list[str],
        source_limit: int,
        max_insns: int,
    ) -> dict[str, Any]:
        """Rebuild and persist the semantic gadget index for a session."""
        db_path = self._semantic_index_db_path(session.session_id)
        fingerprint = self._semantic_index_fingerprint(session)
        indexed_rows: list[tuple[str, str, int, str, str, str, bytes]] = []
        errors: list[dict[str, Any]] = []
        for source_action in source_actions:
            result = self.call_tool(
                "gadgets",
                session.idb_path,
                action=source_action,
                limit=source_limit,
                max_insns=max_insns,
            )
            if isinstance(result, dict) and result.get("error"):
                errors.append(
                    {
                        "action": source_action,
                        "code": result.get("code"),
                        "message": result.get("message") or result.get("error"),
                    }
                )
                continue
            for addr, insns, gadget_text in self._semantic_extract_gadget_rows(
                source_action, result
            ):
                norm_text = re.sub(r"\s+", " ", gadget_text.lower()).strip()
                tokens = sorted(set(re.findall(r"[a-z0-9_]+", norm_text)))
                token_blob = ",".join(tokens)
                digest = hashlib.sha256(
                    struct.pack(">I", int(insns))
                    + source_action.encode("utf-8", errors="ignore")
                    + b"\0"
                    + addr.encode("utf-8", errors="ignore")
                    + b"\0"
                    + gadget_text.encode("utf-8", errors="ignore")
                ).digest()
                indexed_rows.append(
                    (
                        source_action,
                        addr,
                        int(insns),
                        gadget_text,
                        norm_text,
                        token_blob,
                        digest,
                    )
                )

        with self._semantic_index_lock:
            conn = self._semantic_index_connect(db_path)
            try:
                self._semantic_index_ensure_schema(conn)
                conn.execute("DELETE FROM gadgets")
                if indexed_rows:
                    conn.executemany(
                        """
                        INSERT OR IGNORE INTO gadgets(
                            source_action, addr, insns, gadget, norm_text, tokens, digest
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        indexed_rows,
                    )
                self._semantic_index_put_meta(
                    conn,
                    {
                        "version": str(SEMANTIC_INDEX_VERSION),
                        "fingerprint": fingerprint,
                        "built_at": str(int(time.time())),
                        "source_actions": ",".join(source_actions),
                        "source_limit": str(source_limit),
                        "max_insns": str(max_insns),
                    },
                )
                conn.commit()
            finally:
                conn.close()
        return {
            "db_path": db_path,
            "fingerprint": fingerprint,
            "rows_indexed": len(indexed_rows),
            "errors": errors,
        }

    def _handle_gadgets_semantic_find(self, args: dict) -> dict:
        """Handle gadgets(action='semantic_find') using a cached per-session index."""
        query = str(args.get("query") or "").strip()
        if not query:
            return make_error(MCPError.INVALID_ARGS, "query required")
        source_actions = _parse_str_list(args.get("source_actions"))
        if not source_actions:
            source_actions = list(SEMANTIC_GADGET_SOURCE_ACTIONS)
        source_actions = [str(a).strip() for a in source_actions if str(a).strip()]
        source_actions = list(dict.fromkeys(source_actions))
        invalid_actions = [
            a for a in source_actions if a not in set(SEMANTIC_GADGET_SOURCE_ACTIONS)
        ]
        if invalid_actions:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Unsupported semantic source action(s): {', '.join(invalid_actions)}",
                hint=(
                    "Use source_actions from: "
                    + ", ".join(SEMANTIC_GADGET_SOURCE_ACTIONS)
                ),
            )
        limit = _bounded_int(args.get("limit", 50), 50, min_value=1, max_value=2000)
        offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=200000)
        min_score = _bounded_int(args.get("min_score", 1), 1, min_value=0, max_value=1000)
        source_limit = _bounded_int(
            args.get("source_limit", SEMANTIC_INDEX_SOURCE_LIMIT),
            SEMANTIC_INDEX_SOURCE_LIMIT,
            min_value=50,
            max_value=100000,
        )
        max_insns = _bounded_int(args.get("max_insns", 6), 6, min_value=2, max_value=32)

        idb_ref = args.get("idb")
        if idb_ref is None and self.current_session:
            idb_ref = self.current_session.idb_path
        session = self._resolve_session_from_idb_ref(idb_ref)
        if not session:
            return make_error(
                MCPError.SESSION_REQUIRED,
                "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
            )

        db_path = self._semantic_index_db_path(session.session_id)
        wanted_fingerprint = self._semantic_index_fingerprint(session)
        rebuild_index = _coerce_bool(args.get("rebuild_index"), False) or not os.path.exists(
            db_path
        )
        index_meta: dict[str, str] = {}

        with self._semantic_index_lock:
            if not rebuild_index:
                conn = self._semantic_index_connect(db_path)
                try:
                    self._semantic_index_ensure_schema(conn)
                    index_meta = self._semantic_index_meta(conn)
                finally:
                    conn.close()
                rebuild_index = (
                    index_meta.get("version") != str(SEMANTIC_INDEX_VERSION)
                    or index_meta.get("fingerprint") != wanted_fingerprint
                    or index_meta.get("source_actions", "")
                    != ",".join(source_actions)
                    or index_meta.get("source_limit") != str(source_limit)
                    or index_meta.get("max_insns") != str(max_insns)
                )

        rebuild_info = None
        if rebuild_index:
            rebuild_info = self._semantic_index_rebuild(
                session, source_actions, source_limit, max_insns
            )

        with self._semantic_index_lock:
            conn = self._semantic_index_connect(db_path)
            try:
                self._semantic_index_ensure_schema(conn)
                index_meta = self._semantic_index_meta(conn)
                placeholders = ",".join("?" for _ in source_actions)
                rows = conn.execute(
                    f"""
                    SELECT source_action, addr, insns, gadget, norm_text, tokens
                    FROM gadgets
                    WHERE source_action IN ({placeholders})
                    """,
                    tuple(source_actions),
                ).fetchall()
            finally:
                conn.close()

        min_similarity = max(0.0, min(1.0, float(min_score) / 1000.0))
        query_lower = query.lower()
        query_tokens = set(re.findall(r"[a-z0-9_]+", query_lower))

        ranked: list[tuple[float, tuple[Any, Any, Any, Any, Any, Any]]] = []
        embedding_failed = False
        query_vec: Optional[List[float]] = None
        embedder = None
        if EMBEDDING_FIRST_MODE:
            try:
                from .intelligence import BgeCodeEmbedder
                embedder = BgeCodeEmbedder()
                query_vec = embedder.embed(query)
            except Exception:
                embedding_failed = True
        for row in rows:
            norm_text = str(row[4] or "")
            sim = 0.0
            if embedder is not None and query_vec is not None and norm_text:
                try:
                    row_vec = embedder.embed(norm_text)
                    sim = float(embedder.cosine(query_vec, row_vec))
                except Exception:
                    sim = 0.0
            elif not embedding_failed:
                token_blob = str(row[5] or "")
                row_tokens = set(token_blob.split(",")) if token_blob else set()
                inter = len(query_tokens.intersection(row_tokens))
                union = len(query_tokens.union(row_tokens)) if row_tokens else len(query_tokens)
                sim = (float(inter) / float(max(1, union))) if union else 0.0
            if sim >= min_similarity:
                ranked.append((sim, row))

        def _rank_sort_key(
            item: tuple[float, tuple[Any, Any, Any, Any, Any, Any]]
        ) -> tuple[float, str, str]:
            sim, row = item
            source_action = str(row[0] or "")
            addr = str(row[1] or "")
            return (-sim, source_action, addr)

        ranked.sort(key=_rank_sort_key)
        total = len(ranked)
        page = ranked[offset : offset + limit]
        matches = [
            {
                "source_action": str(row[0]),
                "addr": str(row[1]),
                "insns": int(row[2]),
                "gadget": str(row[3]),
                "score": int(round(sim * 1000)),
                "similarity": round(sim, 4),
            }
            for sim, row in page
        ]
        truncated = (offset + len(matches)) < total
        out = {
            "ok": True,
            "action": "semantic_find",
            "query": query,
            "matches": matches,
            "count": len(matches),
            "total": total,
            "offset": offset,
            "truncated": truncated,
            "next_offset": (offset + len(matches)) if truncated else None,
            "index": {
                "version": index_meta.get("version"),
                "fingerprint": index_meta.get("fingerprint"),
                "source_actions": source_actions,
                "db_path": db_path,
            },
        }
        if rebuild_info:
            out["index_refresh"] = {
                "rows_indexed": rebuild_info.get("rows_indexed", 0),
                "errors": rebuild_info.get("errors", []),
            }
        return out

    def _resolve_wiki_root(self) -> str:
        env_path = os.environ.get("IDA_MCP_WIKI_DIR")
        candidates: List[str] = []
        if env_path:
            candidates.append(os.path.realpath(os.path.expanduser(env_path)))

        script_dir = os.path.realpath(SCRIPT_DIR)
        cwd = os.path.realpath(os.getcwd())
        home = os.path.realpath(str(Path.home()))

        candidates.extend(
            [
                os.path.join(script_dir, "docs", "wiki"),
                os.path.join(script_dir, "src", "ida_pro_mcp", "docs", "wiki"),
                os.path.join(os.path.dirname(script_dir), "docs", "wiki"),
                os.path.join(cwd, "docs", "wiki"),
                os.path.join(home, ".ida-pro-mcp", "wiki"),
                os.path.join(home, ".local", "share", "ida-pro-mcp", "wiki"),
            ]
        )

        seen = set()
        for cand in candidates:
            cand = os.path.realpath(cand)
            if cand in seen:
                continue
            seen.add(cand)
            if os.path.isdir(cand):
                return cand
        return ""

    def _wiki_parse_headers(self, lines: List[str]) -> List[dict]:
        headers = []
        for idx, line in enumerate(lines, 1):
            strip = line.strip()
            if strip.startswith("#"):
                level = strip.count("#")
                text = strip.lstrip("#").strip()
                headers.append({"level": level, "text": text, "line": idx})
        return headers

    def _wiki_tokenize(self, text: str) -> List[str]:
        if not text:
            return []
        return re.findall(r"[a-z0-9_]+", text.lower())

    def _wiki_stem_token(self, token: str) -> str:
        t = token.strip().lower()
        if len(t) <= 3:
            return t
        for suffix in ("ing", "ed", "es", "s"):
            if t.endswith(suffix) and len(t) - len(suffix) >= 3:
                stem = t[: -len(suffix)]
                if suffix == "ing" and stem.endswith("c"):
                    # tracing -> trace, mimicking simple English recovery.
                    stem += "e"
                return stem
        return t

    def _wiki_embed_text(self, text: str) -> Optional[List[float]]:
        txt = (text or "").strip()
        if not txt:
            return None
        key = txt[:2048].lower()
        cached = self._wiki_embed_cache.get(key)
        if cached is not None:
            return cached
        try:
            from .intelligence import BgeCodeEmbedder
            embedder = BgeCodeEmbedder()
            vec = embedder.embed(key)
        except Exception:
            return None
        if len(self._wiki_embed_cache) >= self._wiki_embed_cache_max:
            # simple FIFO-ish eviction
            try:
                self._wiki_embed_cache.pop(next(iter(self._wiki_embed_cache)))
            except Exception:
                self._wiki_embed_cache.clear()
        self._wiki_embed_cache[key] = vec
        return vec

    def _wiki_expand_semantic_terms(self, query_tokens: List[str]) -> set[str]:
        raw = {self._wiki_stem_token(t) for t in query_tokens if t}
        expanded = set(raw)
        for group in WIKI_SEMANTIC_GROUPS:
            stemmed_group = {self._wiki_stem_token(item) for item in group}
            if raw.intersection(stemmed_group):
                expanded.update(stemmed_group)
        return expanded

    def _wiki_semantic_search_pages(
        self,
        pages: List[dict],
        query: str,
        *,
        max_results: int,
        category_filter: Any = None,
        include_snippets: bool = False,
        context_lines: int = 2,
    ) -> List[dict]:
        query_lower = query.lower().strip()
        query_tokens = self._wiki_tokenize(query_lower)
        expanded_terms = self._wiki_expand_semantic_terms(query_tokens)
        scored: List[dict] = []
        for page in pages:
            if not self._wiki_match_category(page["topic"], category_filter):
                continue

            base_score, reasons = self._wiki_score_page(
                page, query_lower, query_tokens, fuzzy=True
            )
            page_tokens = page.get("stemmed_tokens")
            # Defensive fallback: keeps semantic search working if an older cache entry
            # (without stemmed_tokens) is present during rolling updates/tests.
            if not isinstance(page_tokens, set):
                page_tokens = {
                    self._wiki_stem_token(t) for t in page.get("tokens", set())
                }
            semantic_hits = sorted(expanded_terms.intersection(page_tokens))
            if semantic_hits:
                base_score += (len(semantic_hits) * 14) + 20
                reasons.append("semantic_overlap")

            if base_score <= 0:
                continue

            entry = {
                "topic": page["topic"],
                "title": page["title"],
                "category": page["category"],
                "score": base_score,
                "matched_on": reasons[:4],
            }
            if semantic_hits:
                entry["semantic_hits"] = semantic_hits[:10]
            if include_snippets:
                snippet_terms = (
                    " ".join(sorted(semantic_hits[:4])).strip() or query_lower
                )
                snippet_tokens = self._wiki_tokenize(snippet_terms)
                entry["matches"] = self._wiki_extract_snippets(
                    page["text"], snippet_terms, snippet_tokens, context_lines
                )
            scored.append(entry)
        scored.sort(key=lambda x: (-x["score"], x["topic"]))
        return scored[:max_results]

    def _wiki_get_index(self, wiki_root: str, force: bool = False) -> dict:
        now = time.time()
        cache = self._wiki_cache
        if (
            not force
            and cache.get("root") == wiki_root
            and now < float(cache.get("expires", 0.0))
        ):
            return cache

        topics: Dict[str, List[str]] = {}
        pages: List[dict] = []
        if wiki_root and os.path.isdir(wiki_root):
            for root, _, files in os.walk(wiki_root):
                rel_dir = os.path.relpath(root, wiki_root)
                category = "root" if rel_dir == "." else rel_dir.replace(os.sep, "/")
                for filename in sorted(files):
                    if not filename.endswith(".md"):
                        continue
                    full_path = os.path.join(root, filename)
                    try:
                        with open(
                            full_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            text = f.read()
                    except OSError:
                        continue
                    page_name = filename[:-3]
                    topic = (
                        page_name if category == "root" else f"{category}/{page_name}"
                    )
                    lines = text.splitlines()
                    headers = self._wiki_parse_headers([line + "\n" for line in lines])
                    title = headers[0]["text"] if headers else page_name
                    header_text = " ".join(h["text"] for h in headers).lower()
                    topics.setdefault(category, []).append(page_name)
                    text_to_tokenize = f"{topic} {title} {header_text} {text[:4000]}"
                    raw_tokens = self._wiki_tokenize(text_to_tokenize)
                    pages.append(
                        {
                            "topic": topic,
                            "topic_lower": topic.lower(),
                            "topic_basename": page_name.lower(),
                            "category": category,
                            "title": title,
                            "title_lower": title.lower(),
                            "headers": headers,
                            "header_text_lower": header_text,
                            "path": full_path,
                            "text": text,
                            "text_lower": text.lower(),
                            "line_count": len(lines),
                            "tokens": set(raw_tokens),
                            "stemmed_tokens": {
                                self._wiki_stem_token(t) for t in raw_tokens
                            },
                            "semantic_title_text": f"{topic} {title} {header_text}".strip(),
                            "semantic_body_text": text[:4000],
                        }
                    )

        for category in list(topics.keys()):
            topics[category] = sorted(set(topics[category]))
        pages.sort(key=lambda p: p["topic"])

        cache.update(
            {
                "root": wiki_root,
                "expires": now + self._wiki_cache_ttl,
                "topics": topics,
                "pages": pages,
            }
        )
        return cache

    def _wiki_normalize_topic(
        self, topic_name: Any
    ) -> tuple[Optional[str], Optional[dict]]:
        normalized = str(topic_name or "").strip().replace("\\", "/")
        if not normalized:
            return None, make_error(MCPError.INVALID_ARGS, "topic required")
        if os.path.isabs(normalized):
            return None, make_error(
                MCPError.INVALID_ARGS, "Absolute topic paths are not allowed"
            )
        if normalized.startswith("/"):
            normalized = normalized.lstrip("/")
        if normalized.endswith(".md"):
            normalized = normalized[:-3]
        parts = [p for p in normalized.split("/") if p]
        if not parts or any(p in (".", "..") for p in parts):
            return None, make_error(MCPError.INVALID_ARGS, "Invalid wiki topic path")
        return "/".join(parts), None

    def _normalize_wiki_args(self, args: dict) -> dict:
        """
        Accept tolerant wiki call shapes often produced by LLMs:
        - action: "read topic=tools/query"
        - action: "read QuickStart"
        - action: "{\"action\":\"read\",\"topic\":\"tools/query\"}"
        """
        out = dict(args or {})
        raw_action = out.get("action")
        if not isinstance(raw_action, str):
            return out
        action_text = raw_action.strip()
        if not action_text:
            return out

        # Handle JSON stuffed into action field.
        if action_text.startswith("{") and action_text.endswith("}"):
            try:
                payload = json.loads(action_text)
            except Exception:
                payload = None
            if isinstance(payload, dict):
                for k, v in payload.items():
                    out.setdefault(k, v)
                out["action"] = str(payload.get("action", "")).strip()
                return out

        parts = action_text.split(None, 1)
        base = parts[0].strip()
        if base not in TOOL_ACTIONS["wiki"]:
            return out

        out["action"] = base
        tail = parts[1].strip() if len(parts) > 1 else ""
        if tail:
            positional: List[str] = []
            for token in shlex.split(tail):
                if "=" in token:
                    k, v = token.split("=", 1)
                    key = k.strip()
                    val = v.strip()
                    if key and val and key not in out:
                        out[key] = val
                else:
                    rng_start, rng_end = _parse_line_range(token)
                    if (
                        base in ("read", "sections")
                        and (rng_start is not None or rng_end is not None)
                        and not out.get("lines")
                    ):
                        out["lines"] = token
                    else:
                        positional.append(token)

            if positional:
                joined = " ".join(positional).strip()
                if joined:
                    if base in ("read", "sections") and not out.get("topic"):
                        out["topic"] = joined
                    elif base == "search" and not out.get("query"):
                        out["query"] = joined

        # Tolerate callers that accidentally pass topic in `idb` for wiki actions.
        if base in ("read", "sections") and not out.get("topic"):
            maybe_topic = out.get("idb")
            if isinstance(maybe_topic, str):
                candidate = maybe_topic.strip()
                if (
                    candidate
                    and not os.path.isabs(candidate)
                    and not re.search(
                        r"\.(i64|idb|exe|dll|so|dylib|bin)$", candidate, re.IGNORECASE
                    )
                ):
                    out["topic"] = candidate
        return out

    def _wiki_generated_tool_doc(self, tool_name: str) -> Optional[str]:
        if not isinstance(tool_name, str):
            return None
        tool_name = tool_name.strip().lower()
        if tool_name.startswith("tools/"):
            tool_name = tool_name.split("/", 1)[1]
        if tool_name.endswith(".md"):
            tool_name = tool_name[:-3]
        if tool_name not in TOOLS:
            return None

        action_list = TOOL_ACTIONS.get(tool_name, [])
        schema = TOOL_ARG_SCHEMAS.get(tool_name, {})
        key_params = [p for p in schema.keys() if p not in ("action",)]
        key_params = key_params[:16]

        lines = [
            f"# {tool_name.upper()} Tool Manual",
            "",
            "## What It Does",
            TOOL_DESCRIPTIONS.get(tool_name, "No description available."),
            "",
            "## Actions",
        ]
        if action_list:
            for action in action_list:
                lines.append(f"- `{action}`")
        else:
            lines.append("- See tool source")

        lines.extend(["", "## Key Parameters"])
        if key_params:
            for param in key_params:
                lines.append(f"- `{param}`")
        else:
            lines.append("- None")

        sample_args = {"action": action_list[0] if action_list else "help"}
        for param in key_params[:3]:
            sample_args[param] = "<value>"

        lines.extend(
            [
                "",
                "## Examples",
                "```json",
                json.dumps(sample_args, indent=2),
                "```",
                "",
                "## Failure Modes",
                "- Invalid arguments or missing required fields.",
                "- Unsupported action name.",
                "- Runtime/tool-specific failures returned by server.",
            ]
        )
        return "\n".join(lines) + "\n"

    def _wiki_match_category(self, topic: str, category_filter: Any) -> bool:
        if not category_filter:
            return True
        if isinstance(category_filter, str):
            categories = [
                c.strip().strip("/").lower() for c in category_filter.split(",")
            ]
        elif isinstance(category_filter, list):
            categories = [str(c).strip().strip("/").lower() for c in category_filter]
        else:
            categories = [str(category_filter).strip().strip("/").lower()]
        categories = [c for c in categories if c]
        if not categories:
            return True

        topic_lower = topic.lower()
        for category in categories:
            if category == "root":
                if "/" not in topic_lower:
                    return True
                continue
            if topic_lower == category or topic_lower.startswith(f"{category}/"):
                return True
        return False

    def _wiki_extract_snippets(
        self,
        text: str,
        query_lower: str,
        query_tokens: List[str],
        context_lines: int,
        max_snippets: int = 5,
    ) -> List[dict]:
        lines = text.splitlines()
        snippets: List[dict] = []
        if not lines:
            return snippets
        terms = [query_lower] + [t for t in query_tokens if len(t) >= 3]
        terms = [t for t in terms if t]
        if not terms:
            return snippets
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if not any(term in line_lower for term in terms):
                continue
            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)
            snippets.append({"line": i + 1, "snippet": "\n".join(lines[start:end])})
            if len(snippets) >= max_snippets:
                break
        return snippets

    def _wiki_score_page(
        self,
        page: dict,
        query_lower: str,
        query_tokens: List[str],
        fuzzy: bool,
    ) -> tuple[int, List[str]]:
        reasons: List[str] = []
        qvec = self._wiki_embed_text(query_lower) if EMBEDDING_FIRST_MODE else None
        title_text = str(page.get("semantic_title_text") or "").strip()
        body_text = str(page.get("semantic_body_text") or "").strip()
        title_vec = self._wiki_embed_text(title_text) if qvec is not None else None
        body_vec = self._wiki_embed_text(body_text) if qvec is not None else None
        if qvec is not None and title_vec is not None:
            try:
                from .intelligence import BgeCodeEmbedder
                s_title = float(BgeCodeEmbedder.cosine(qvec, title_vec))
                s_body = float(BgeCodeEmbedder.cosine(qvec, body_vec)) if body_vec is not None else 0.0
                sim = (0.7 * s_title) + (0.3 * s_body)
                if fuzzy and len(query_lower) >= 3 and sim < 0.2:
                    topic_lower = str(page.get("topic_lower") or "")
                    title_lower = str(page.get("title_lower") or "")
                    base_lower = str(page.get("topic_basename") or "")
                    ratio = max(
                        difflib.SequenceMatcher(None, query_lower, topic_lower).ratio(),
                        difflib.SequenceMatcher(None, query_lower, title_lower).ratio(),
                        difflib.SequenceMatcher(None, query_lower, base_lower).ratio(),
                    )
                    if ratio >= 0.7:
                        sim = max(sim, ratio * 0.5)
                        reasons.append("lexical_similarity")
                if s_title > 0.25:
                    reasons.append("embedding_title")
                if s_body > 0.2:
                    reasons.append("embedding_body")
                return int(round(max(0.0, min(1.0, sim)) * 1000.0)), reasons
            except Exception:
                pass

        # Deterministic non-heuristic fallback: token Jaccard similarity.
        page_tokens = page.get("tokens", set())
        q_tokens = set(query_tokens)
        inter = len(page_tokens.intersection(q_tokens)) if isinstance(page_tokens, set) else 0
        union = len(page_tokens.union(q_tokens)) if isinstance(page_tokens, set) else len(q_tokens)
        sim = (float(inter) / float(max(1, union))) if union else 0.0
        if inter > 0:
            reasons.append("token_overlap")
        if sim <= 0.0 and fuzzy and len(query_lower) >= 3:
            topic_lower = str(page.get("topic_lower") or "")
            title_lower = str(page.get("title_lower") or "")
            base_lower = str(page.get("topic_basename") or "")
            ratio = max(
                difflib.SequenceMatcher(None, query_lower, topic_lower).ratio(),
                difflib.SequenceMatcher(None, query_lower, title_lower).ratio(),
                difflib.SequenceMatcher(None, query_lower, base_lower).ratio(),
            )
            if ratio >= 0.7:
                sim = ratio * 0.5
                reasons.append("lexical_similarity")
        return int(round(sim * 1000.0)), reasons

    def _wiki_search_pages(
        self,
        pages: List[dict],
        query: str,
        *,
        max_results: int,
        category_filter: Any = None,
        include_snippets: bool = False,
        context_lines: int = 2,
        fuzzy: bool = True,
    ) -> List[dict]:
        query_lower = query.lower().strip()
        query_tokens = self._wiki_tokenize(query_lower)
        scored: List[dict] = []
        for page in pages:
            if not self._wiki_match_category(page["topic"], category_filter):
                continue
            score, reasons = self._wiki_score_page(
                page, query_lower, query_tokens, fuzzy
            )
            if score <= 0:
                continue
            entry = {
                "topic": page["topic"],
                "title": page["title"],
                "category": page["category"],
                "score": score,
                "matched_on": reasons[:4],
            }
            if include_snippets:
                entry["matches"] = self._wiki_extract_snippets(
                    page["text"], query_lower, query_tokens, context_lines
                )
            scored.append(entry)
        scored.sort(key=lambda x: (-x["score"], x["topic"]))
        return scored[:max_results]

    def _wiki_related_topics(
        self, current_topic: str, pages: List[dict], max_items: int = 6
    ) -> List[str]:
        current = current_topic.lower()
        current_page = None
        for page in pages:
            if page["topic_lower"] == current:
                current_page = page
                break
        if not current_page:
            return []
        related = []
        for page in pages:
            if page["topic_lower"] == current:
                continue
            if page["category"] == current_page["category"]:
                related.append(page["topic"])
        return related[:max_items]

    def _wiki_resolve_topic(
        self, normalized_topic: str, pages: List[dict], strict: bool = False
    ) -> Optional[dict]:
        if not pages:
            return None
        wanted = normalized_topic.lower()
        by_topic = {p["topic_lower"]: p for p in pages}
        exact = by_topic.get(wanted)
        if exact:
            return exact
        if strict:
            return None

        if "/" not in wanted:
            if wanted in TOOLS:
                tool_topic = f"tools/{wanted}"
                if tool_topic in by_topic:
                    return by_topic[tool_topic]
            basename_matches = [p for p in pages if p["topic_basename"] == wanted]
            if len(basename_matches) == 1:
                return basename_matches[0]
            if len(basename_matches) > 1:
                for page in basename_matches:
                    if page["category"] == "tools":
                        return page
            slug = wanted.replace("-", "_").replace(" ", "_")
            if slug != wanted:
                slug_matches = [p for p in pages if p["topic_basename"] == slug]
                if slug_matches:
                    return slug_matches[0]
        return None

    def _handle_wiki(self, args: dict) -> dict:
        args = self._normalize_wiki_args(args)
        action = args.get("action")
        if action not in TOOL_ACTIONS["wiki"]:
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported wiki action: '{action}'",
                hint=(
                    f"Valid wiki actions: {', '.join(TOOL_ACTIONS['wiki'])}. "
                    "Examples: wiki(action='read', topic='tools/query'), "
                    "wiki(action='search', query='session'), "
                    "wiki(action='read', topic='tools/query', lines='20-60')."
                ),
            )

        wiki_root = self._resolve_wiki_root()
        wiki_index = self._wiki_get_index(wiki_root)
        topics: Dict[str, List[str]] = wiki_index.get("topics", {})
        pages: List[dict] = wiki_index.get("pages", [])

        verbose = bool(args.get("verbose", False))
        default_limit = (
            self.default_wiki_read_limit if action == "read" and not verbose else 0
        )
        q_limit = _bounded_int(
            args.get("limit", default_limit),
            default_limit,
            min_value=0,
            max_value=2000,
        )
        q_offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=200000)
        context_lines = _bounded_int(
            args.get("context_lines", 2), 2, min_value=0, max_value=10
        )
        include_snippets = bool(args.get("include_snippets", False))
        category_filter = args.get("category")
        max_results = _bounded_int(
            args.get("max_results", 20 if verbose else 8),
            20 if verbose else 8,
            min_value=1,
            max_value=MAX_WIKI_RESULTS,
        )
        fuzzy = bool(args.get("fuzzy", True))
        strict_topic = bool(args.get("strict_topic", False))
        include_related = bool(args.get("include_related", True if verbose else False))

        if action == "list_topics":
            if topics:
                counts = {category: len(items) for category, items in topics.items()}
                return {
                    "ok": True,
                    "categories": topics,
                    "counts": counts,
                    "total_pages": sum(counts.values()),
                }
            return {
                "ok": True,
                "categories": {"tools": sorted(TOOLS)},
                "total_pages": len(TOOLS),
                "note": "Wiki markdown files not found; serving generated tool docs.",
            }

        if action == "index":
            if topics:
                summary = {
                    "category_count": len(topics),
                    "total_pages": len(pages),
                    "wiki_root": wiki_root,
                }
                return {"ok": True, "categories": topics, "summary": summary}
            return {
                "ok": True,
                "categories": {"tools": sorted(TOOLS)},
                "summary": {
                    "category_count": 1,
                    "total_pages": len(TOOLS),
                    "wiki_root": None,
                },
            }

        if action in ("search", "semantic_search"):
            query = (args.get("query") or args.get("topic") or "").strip()
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required")
            if pages:
                if action == "semantic_search":
                    matches = self._wiki_semantic_search_pages(
                        pages,
                        query,
                        max_results=max_results,
                        category_filter=category_filter,
                        include_snippets=include_snippets,
                        context_lines=context_lines,
                    )
                else:
                    matches = self._wiki_search_pages(
                        pages,
                        query,
                        max_results=max_results,
                        category_filter=category_filter,
                        include_snippets=include_snippets,
                        context_lines=context_lines,
                        fuzzy=fuzzy,
                    )
            else:
                matches = []
                for tool_name in TOOLS:
                    text = self._wiki_generated_tool_doc(tool_name) or ""
                    q_lower = query.lower()
                    if q_lower in tool_name.lower() or q_lower in text.lower():
                        matches.append(
                            {
                                "topic": f"tools/{tool_name}",
                                "title": f"{tool_name.upper()} Tool Manual",
                                "category": "tools",
                                "score": 1,
                                "matched_on": ["fallback_tool_doc"],
                            }
                        )
                matches = matches[:max_results]
            response = {
                "ok": True,
                "action": action,
                "query": query,
                "matches": matches,
                "count": len(matches),
            }
            return response

        topic_name, topic_err = self._wiki_normalize_topic(args.get("topic"))
        if topic_err:
            return topic_err

        resolved_page = self._wiki_resolve_topic(
            topic_name or "", pages, strict=strict_topic
        )
        content: Optional[str] = None
        source = "generated"
        resolved_topic = topic_name
        title = None
        category = "tools"
        if resolved_page:
            content = resolved_page["text"]
            source = "markdown"
            resolved_topic = resolved_page["topic"]
            title = resolved_page["title"]
            category = resolved_page["category"]
        else:
            fallback = self._wiki_generated_tool_doc(topic_name or "")
            if fallback is not None:
                content = fallback
                source = "generated"
                normalized_tool = (topic_name or "").split("/")[-1].lower()
                resolved_topic = (
                    f"tools/{normalized_tool}" if normalized_tool else topic_name
                )
                title = (
                    f"{normalized_tool.upper()} Tool Manual"
                    if normalized_tool
                    else "Generated Tool Manual"
                )
                category = "tools"
            else:
                suggestions: List[str] = []
                if pages and topic_name:
                    suggestions = [
                        m["topic"]
                        for m in self._wiki_search_pages(
                            pages,
                            topic_name,
                            max_results=6,
                            category_filter=category_filter,
                            include_snippets=False,
                            fuzzy=True,
                        )
                    ]
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    f"Wiki topic '{topic_name}' not found",
                    details={
                        "wiki_root": wiki_root or None,
                        "suggestions": suggestions,
                    },
                    hint="Use wiki(action='search', query='...') or set IDA_MCP_WIKI_DIR.",
                )

        lines = content.splitlines(keepends=True)
        headers = self._wiki_parse_headers(lines)
        available_sections = [
            {
                "index": idx + 1,
                "title": h["text"],
                "level": h["level"],
                "line": h["line"],
            }
            for idx, h in enumerate(headers)
        ]

        if action == "sections":
            if not verbose:
                return {
                    "ok": True,
                    "topic": topic_name,
                    "resolved_topic": resolved_topic,
                    "source": source,
                    "title": title,
                    "sections": [h["title"] for h in available_sections],
                    "count": len(available_sections),
                }
            return {
                "ok": True,
                "topic": topic_name,
                "resolved_topic": resolved_topic,
                "source": source,
                "title": title,
                "headers": available_sections,
                "count": len(available_sections),
            }

        section = args.get("section")
        content_lines = lines
        section_filter = None
        section_start_line = 1
        if section:
            target_header = None
            if isinstance(section, int) or (
                isinstance(section, str) and str(section).strip().isdigit()
            ):
                section_idx = int(section) - 1
                if 0 <= section_idx < len(headers):
                    target_header = headers[section_idx]
            else:
                section_lower = str(section).strip().lower()
                for header in headers:
                    if section_lower == header["text"].strip().lower():
                        target_header = header
                        break
                if target_header is None:
                    for header in headers:
                        if section_lower in header["text"].strip().lower():
                            target_header = header
                            break
                if target_header is None and fuzzy and section_lower:
                    best_ratio = 0.0
                    best_header = None
                    for header in headers:
                        ratio = difflib.SequenceMatcher(
                            None, section_lower, header["text"].strip().lower()
                        ).ratio()
                        if ratio > best_ratio:
                            best_ratio = ratio
                            best_header = header
                    if best_ratio >= 0.74:
                        target_header = best_header

            if target_header is None:
                details_payload = (
                    {"available_sections": available_sections[:50]}
                    if verbose
                    else {
                        "available_sections": [
                            s["title"] for s in available_sections[:20]
                        ]
                    }
                )
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Section '{section}' not found",
                    details=details_payload,
                )

            section_filter = target_header["text"]
            section_start_line = int(target_header["line"])
            start_idx = section_start_line - 1
            end_idx = len(lines)
            for header in headers:
                if header["line"] <= section_start_line:
                    continue
                if header["level"] <= target_header["level"]:
                    end_idx = int(header["line"]) - 1
                    break
            content_lines = lines[start_idx:end_idx]

        line_sel_start, line_sel_end = _parse_line_range(args.get("lines"))
        if args.get("line_start") is not None:
            line_sel_start = _bounded_int(
                args.get("line_start"), 1, min_value=1, max_value=2_000_000
            )
        if args.get("line_end") is not None:
            line_sel_end = _bounded_int(
                args.get("line_end"), 1, min_value=1, max_value=2_000_000
            )
        has_line_window = (line_sel_start is not None) or (line_sel_end is not None)

        total_lines = len(content_lines)
        if has_line_window:
            section_abs_start = section_start_line
            section_abs_end = section_start_line + max(0, total_lines - 1)

            abs_start_req = (
                line_sel_start if line_sel_start is not None else section_abs_start
            )
            abs_end_req = line_sel_end if line_sel_end is not None else section_abs_end
            if abs_end_req < abs_start_req:
                abs_start_req, abs_end_req = abs_end_req, abs_start_req

            abs_start = max(section_abs_start, abs_start_req)
            abs_end = min(section_abs_end, abs_end_req)

            if total_lines <= 0 or abs_end < abs_start:
                slice_lines = []
                absolute_start = section_abs_start
                absolute_end = section_abs_start
            else:
                local_start = abs_start - section_abs_start
                local_end_exclusive = abs_end - section_abs_start + 1
                slice_lines = content_lines[local_start:local_end_exclusive]
                absolute_start = abs_start
                absolute_end = abs_end
        else:
            start = min(q_offset, total_lines)
            end = total_lines if q_limit <= 0 else min(total_lines, start + q_limit)
            slice_lines = content_lines[start:end]
            absolute_start = section_start_line + start
            absolute_end = (
                absolute_start + len(slice_lines) - 1 if slice_lines else absolute_start
            )
        result = {
            "ok": True,
            "topic": topic_name,
            "resolved_topic": resolved_topic,
            "title": title,
            "content": "".join(slice_lines),
            "line_range": f"{absolute_start}-{absolute_end}",
        }
        if verbose:
            result.update(
                {
                    "source": source,
                    "category": category,
                    "total_lines_in_topic": len(lines),
                    "headers": [h["text"] for h in headers[:100]],
                    "available_sections": available_sections[:100],
                }
            )
        if section_filter:
            result["section_filter"] = section_filter
        if include_related and pages and resolved_topic:
            result["related_topics"] = self._wiki_related_topics(resolved_topic, pages)
        if (not has_line_window) and q_limit > 0 and end < total_lines:
            result["_truncated"] = True
            result["next_offset"] = end
            result["lines_remaining"] = total_lines - end
            result["hint"] = (
                "Use wiki(action='read', topic='...', offset=next_offset, limit=...)"
            )
        return result

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

    def _threat_hunt_step(
        self, ip: str, tool: str, action: str, step_args: Optional[dict] = None
    ) -> dict:
        payload_args = dict(step_args or {})
        payload_args["action"] = action
        payload_args["idb"] = ip
        try:
            result = self.call_tool(tool, ip, **payload_args)
        except Exception as e:
            return {
                "ok": False,
                "tool": tool,
                "action": action,
                "error": str(e),
            }
        if isinstance(result, dict) and result.get("error"):
            return {
                "ok": False,
                "tool": tool,
                "action": action,
                "error": result.get("message")
                or result.get("error")
                or "unknown error",
                "code": result.get("code"),
                "payload": result,
            }
        return {
            "ok": True,
            "tool": tool,
            "action": action,
            "payload": result,
        }

    def _threat_hunt_extract_findings(self, step: dict) -> list[dict]:
        payload = step.get("payload")
        if not isinstance(payload, dict):
            return []
        out: list[dict] = []
        tool = str(step.get("tool", ""))
        action = str(step.get("action", ""))

        # Recursive extractor: collect any dict node that has an address and text-like field.
        def _walk(node):
            if isinstance(node, dict):
                keys = set(node.keys())
                has_addr = any(k in keys for k in ("addr", "address", "ea"))
                has_text = any(k in keys for k in ("text", "description", "summary", "title", "name", "value"))
                if has_addr and has_text:
                    e = dict(node)
                    e.setdefault("tool", tool)
                    e.setdefault("action", action)
                    out.append(e)
                for v in node.values():
                    _walk(v)
            elif isinstance(node, list):
                for it in node:
                    _walk(it)

        _walk(payload)

        for key in (
            "findings",
            "items",
            "matches",
            "results",
            "indicators",
            "iocs",
            "apis",
            "loops",
        ):
            val = payload.get(key)
            if isinstance(val, list):
                for entry in val:
                    if isinstance(entry, dict):
                        e = dict(entry)
                    else:
                        e = {"value": entry}
                    e.setdefault("tool", tool)
                    e.setdefault("action", action)
                    out.append(e)

        if not out and any(k in payload for k in ("summary", "count", "total")):
            out.append(
                {
                    "tool": tool,
                    "action": action,
                    "summary": payload.get("summary"),
                    "count": payload.get("count", payload.get("total", 0)),
                }
            )
        return out

    def _threat_hunt_vuln_db_pass(self, ip: str, limit: int = 120) -> list[dict]:
        """
        Deterministic first-pass scan using structured vulnerability pattern DB.
        Uses existing search surfaces to avoid IDA-runtime coupling in host process.
        """
        findings: list[dict] = []
        # Query broad signals once, then score against pattern indicators.
        s_vuln = self._threat_hunt_step(ip, "search", "vulnerable", {"limit": min(200, limit)})
        s_const = self._threat_hunt_step(ip, "search", "constants", {"limit": min(200, limit)})
        s_api = self._threat_hunt_step(ip, "search", "api", {"pattern": "*", "limit": min(200, limit)})
        corpus = []
        for st in (s_vuln, s_const, s_api):
            for row in self._threat_hunt_extract_findings(st):
                corpus.append(row)
        for row in corpus:
            text = " ".join(str(row.get(k) or "") for k in ("summary", "name", "title", "value", "kind", "type", "indicator", "description")).lower()
            if not text:
                continue
            for pat in VULN_PATTERNS:
                hit = 0
                for fn in pat.indicator_functions:
                    if fn.lower() in text:
                        hit += 1
                for s in pat.indicator_strings:
                    if s.lower() in text:
                        hit += 1
                for p in pat.indicator_patterns:
                    if p.lower() in text:
                        hit += 1
                if hit <= 0:
                    continue
                finding = dict(row)
                finding["tool"] = "vuln_db"
                finding["action"] = "pattern_match"
                finding["type"] = "vuln_pattern"
                finding["pattern_id"] = pat.id
                finding["pattern_name"] = pat.name
                finding["cwe_id"] = pat.cwe_id
                finding["severity"] = pat.severity
                finding["remediation"] = pat.remediation
                finding["support_count"] = max(int(finding.get("support_count", 1) or 1), hit)
                findings.append(finding)
        findings.sort(key=lambda x: (str(x.get("severity", "")), int(x.get("support_count", 1))), reverse=True)
        return findings[:limit]

    def _severity_classify(self, finding: dict) -> str:
        text = " ".join(
            str(finding.get(k) or "")
            for k in ("summary", "name", "title", "value", "kind", "type", "indicator", "description")
        ).lower()
        if ("network" in text or "http" in text or "socket" in text) and ("no auth" in text or "unauth" in text or "without auth" in text):
            return "Critical"
        if any(k in text for k in ("crypto misuse", "hardcoded key", "weak random", "insecure cipher", "buffer overflow", "format string", "command injection")):
            return "High"
        if any(k in text for k in ("anti-debug", "anti vm", "obfuscation", "packed")):
            return "Medium"
        return "Low"

    def _correlate_findings(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        """Group findings by 4KB page and emit hotspots when 3+ findings hit same page."""
        page_groups: dict[int, list[dict]] = {}
        for f in findings:
            try:
                a = str(f.get("addr") or f.get("address") or f.get("ea") or "").strip()
                if not a:
                    continue
                ai = int(a, 16) if a.lower().startswith("0x") else int(a)
                pg = ai & ~0xFFF
                page_groups.setdefault(pg, []).append(f)
            except Exception:
                continue
        hotspots = []
        for pg, rows in page_groups.items():
            if len(rows) < 3:
                continue
            score = sum(float(r.get("ml_score", 0.0) or 0.0) for r in rows)
            sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            sev = max((self._severity_classify(r) for r in rows), key=lambda s: sev_rank.get(s, 1))
            hotspots.append({
                "page": hex(pg),
                "finding_count": len(rows),
                "combined_score": round(score, 4),
                "severity": sev,
            })
        hotspots.sort(key=lambda x: (x["combined_score"], x["finding_count"]), reverse=True)
        return findings, hotspots

    def _synthesize_attack_paths(self, findings: list[dict]) -> list[dict]:
        """A -> B -> C synthesis from finding call relationships when available."""
        by_addr: dict[int, list[dict]] = {}
        for f in findings:
            try:
                a = str(f.get("addr") or f.get("address") or f.get("ea") or "").strip()
                if not a:
                    continue
                ai = int(a, 16) if a.lower().startswith("0x") else int(a)
                by_addr.setdefault(ai, []).append(f)
            except Exception:
                continue
        paths = []
        for f in findings:
            callees = f.get("callees") or f.get("calls") or []
            if not isinstance(callees, list):
                continue
            a_txt = str(f.get("title") or f.get("summary") or f.get("name") or "A")
            for c in callees[:10]:
                c_addr_txt = ""
                if isinstance(c, dict):
                    c_addr_txt = str(c.get("addr") or c.get("ea") or "").strip()
                else:
                    c_addr_txt = str(c).split()[0]
                if not c_addr_txt:
                    continue
                try:
                    ci = int(c_addr_txt, 16) if c_addr_txt.lower().startswith("0x") else int(c_addr_txt)
                except Exception:
                    continue
                linked = by_addr.get(ci, [])
                for f2 in linked[:3]:
                    c_txt = str(f2.get("title") or f2.get("summary") or f2.get("name") or "C")
                    paths.append({
                        "chain": f"{a_txt} -> {c_addr_txt} -> {c_txt}",
                        "from": str(f.get("addr") or f.get("address") or f.get("ea") or ""),
                        "via": c_addr_txt,
                        "to": str(f2.get("addr") or f2.get("address") or f2.get("ea") or ""),
                    })
        return paths[:100]

    def _threat_hunt_score_finding(self, finding: dict, freq: int = 1) -> float:
        """Embedding-first threat ranking with deterministic non-heuristic fallback."""
        if not isinstance(finding, dict):
            return 0.0
        text = " ".join(
            str(finding.get(k) or "")
            for k in ("summary", "name", "title", "value", "kind", "type", "indicator")
        ).lower()
        addr = str(finding.get("addr") or finding.get("address") or finding.get("ea") or "")
        if EMBEDDING_FIRST_MODE and text:
            try:
                from .intelligence import BgeCodeEmbedder
                embedder = BgeCodeEmbedder()
                query_vec = embedder.embed(text)
                anchors = [
                    "malware command and control beaconing persistence injection",
                    "memory corruption vulnerability overflow format string unsafe copy",
                    "obfuscation evasion anti debug anti vm packed encrypted payload",
                    "crypto misuse hardcoded key weak random insecure cipher mode",
                    "suspicious network exfiltration downloader shellcode loader",
                ]
                sims = []
                for a in anchors:
                    av = embedder.embed(a)
                    sims.append(BgeCodeEmbedder.cosine(query_vec, av))
                emb_score = max(sims) if sims else 0.0
                corroboration = min(0.2, 0.05 * max(0, freq - 1))
                structural = 0.05 if addr else 0.0
                return round(float(emb_score) + corroboration + structural, 4)
            except Exception:
                pass

        # Deterministic fallback: no lexical keyword heuristics.
        if not ALLOW_HEURISTIC_FALLBACKS:
            base = 0.1 if text else 0.0
            structural = 0.05 if addr else 0.0
            corroboration = min(0.2, 0.05 * max(0, freq - 1))
            return round(base + structural + corroboration, 4)

        # Legacy fallback path can still be explicitly enabled by env.
        tool = str(finding.get("tool") or "").lower()
        action = str(finding.get("action") or "").lower()
        score = 0.0
        if tool in {"yara_hunt", "crypto_id", "deobfuscate"}:
            score += 1.4
        elif tool in {"trace_analysis", "coverage", "trace"}:
            score += 1.1
        elif tool in {"search", "string_ops", "xref_analysis"}:
            score += 0.9
        if action in {"identify", "find_c2", "ioc_extract", "vulnerable", "detect"}:
            score += 1.0
        if action in {"analyze_coverage", "find_loops"}:
            score += 0.6
        if addr:
            score += 0.35
        score += min(1.5, 0.35 * max(0, freq - 1))
        return round(score, 4)

    def _threat_hunt_legacy_route(
        self, legacy_tool: str, legacy_action: str, args: dict
    ) -> tuple[str, list[tuple[str, str, dict]], dict]:
        tool = str(legacy_tool or "").strip().lower()
        action = str(legacy_action or "").strip().lower()
        profile = (
            str(args.get("profile") or args.get("scan_profile") or "balanced")
            .strip()
            .lower()
        )
        if profile not in {"quick", "balanced", "deep"}:
            profile = "balanced"

        mapped_module = "findings"
        steps: list[tuple[str, str, dict]] = []
        if tool in {"trace", "trace_analysis", "coverage"}:
            mapped_module = "tracing"
            trace_map = {
                "get": [("trace", "get", {})],
                "clear": [("trace", "clear", {})],
                "set_options": [
                    (
                        "trace",
                        "set_options",
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ],
                "import_trace": [
                    (
                        "trace_analysis",
                        "import_trace",
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ],
                "analyze_coverage": [("trace_analysis", "analyze_coverage", {})],
                "find_loops": [("trace_analysis", "find_loops", {})],
                "extract_api_calls": [("trace_analysis", "extract_api_calls", {})],
                "basic_blocks_hit": [("trace_analysis", "basic_blocks_hit", {})],
                "import_drcov": [
                    (
                        "coverage",
                        "import_drcov",
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ],
                "import_lighthouse": [
                    (
                        "coverage",
                        "import_lighthouse",
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ],
                "highlight": [
                    (
                        "coverage",
                        "highlight",
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ],
                "report": [("coverage", "report", {})],
                "uncovered": [("coverage", "uncovered", {})],
                "filter": [
                    (
                        "coverage",
                        "filter",
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ],
            }
            steps = trace_map.get(
                action,
                [
                    ("trace", "get", {}),
                    ("trace_analysis", "analyze_coverage", {}),
                    ("coverage", "report", {}),
                ],
            )
        elif tool in {"gadgets", "search"}:
            mapped_module = "vuln"
            if tool == "gadgets" and action:
                steps = [
                    (
                        "gadgets",
                        action,
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ]
            elif tool == "search" and action in {
                "vulnerable",
                "constants",
                "api",
                "find",
                "regex",
            }:
                passthrough = {
                    k: v
                    for k, v in args.items()
                    if k not in {"action", "legacy_tool", "legacy_action", "idb"}
                }
                steps = [("search", action, passthrough)]
            else:
                steps = [
                    ("gadgets", "find_rop", {}),
                    ("search", "vulnerable", {}),
                ]
        else:
            mapped_module = "malware"
            if (
                tool in {"c2_detect", "deobfuscate", "crypto_id", "yara_hunt"}
                and action
            ):
                steps = [
                    (
                        tool,
                        action,
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ]
            elif tool == "classify" and action:
                steps = [
                    (
                        "classify",
                        action,
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ]
            elif tool == "summarize" and action in {
                "security_posture",
                "statistics",
                "binary",
                "function",
            }:
                steps = [
                    (
                        "summarize",
                        action,
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ]
            elif tool == "agent" and action in {"search_all", "find_references"}:
                steps = [
                    (
                        "agent",
                        action,
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ]
            elif tool == "protocol" and action:
                steps = [
                    (
                        "protocol",
                        action,
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ]
            elif tool == "xref_analysis" and action:
                steps = [
                    (
                        "xref_analysis",
                        action,
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ]
            elif tool == "string_ops" and action:
                steps = [
                    (
                        "string_ops",
                        action,
                        {
                            k: v
                            for k, v in args.items()
                            if k
                            not in {"action", "legacy_tool", "legacy_action", "idb"}
                        },
                    )
                ]
            else:
                steps = [
                    ("deobfuscate", "stack_strings", {}),
                    ("deobfuscate", "api_hashing", {}),
                    ("crypto_id", "identify", {}),
                    ("yara_hunt", "list_rules", {}),
                ]

        return (
            mapped_module,
            steps,
            {"legacy_tool": tool or None, "legacy_action": action or None},
        )

    def _handle_threat_hunt(self, args: dict) -> dict:
        action = str(args.get("action") or "run").strip().lower()
        profile = (
            str(args.get("profile") or args.get("scan_profile") or "balanced")
            .strip()
            .lower()
        )
        if (
            action in {"quick", "deep"}
            and "profile" not in args
            and "scan_profile" not in args
        ):
            profile = action
            action = "run"
        if action == "findings":
            action = "run"
        if profile not in {"quick", "balanced", "deep"}:
            profile = "balanced"

        include_vuln = _coerce_bool(
            args.get("include_vuln"), action in {"run", "vuln", "legacy"}
        )
        include_malware = _coerce_bool(
            args.get("include_malware"), action in {"run", "malware", "legacy"}
        )
        include_tracing = _coerce_bool(
            args.get("include_tracing"), action in {"run", "tracing", "legacy"}
        )
        if action == "vuln":
            include_vuln, include_malware, include_tracing = True, False, False
        elif action == "malware":
            include_vuln, include_malware, include_tracing = False, True, False
        elif action == "tracing":
            include_vuln, include_malware, include_tracing = False, False, True

        if not (include_vuln or include_malware or include_tracing):
            # Default: enable all modules for 'run' action
            if action in {"run", "legacy"}:
                include_vuln = include_malware = include_tracing = True
            else:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "No threat_hunt modules enabled",
                    hint="Enable at least one of include_vuln/include_malware/include_tracing or use action run|vuln|malware|tracing.",
                )

        idb_path = args.get(
            "idb", self.current_session.idb_path if self.current_session else None
        )
        if not idb_path:
            return make_error(
                MCPError.SESSION_REQUIRED,
                "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
            )

        limit = _bounded_int(args.get("limit", 120), 120, min_value=1, max_value=1000)
        max_steps = _bounded_int(
            args.get("max_steps", 24), 24, min_value=1, max_value=128
        )
        include_evidence = _coerce_bool(args.get("include_evidence"), False)

        step_plan: list[tuple[str, str, dict]] = []
        legacy_meta: dict = {}
        if action == "legacy":
            module, legacy_steps, legacy_meta = self._threat_hunt_legacy_route(
                str(args.get("legacy_tool") or args.get("tool") or ""),
                str(args.get("legacy_action") or args.get("source_action") or ""),
                args,
            )
            include_vuln = module == "vuln"
            include_malware = module == "malware"
            include_tracing = module == "tracing"
            step_plan.extend(legacy_steps)

        if include_malware and not step_plan:
            step_plan.extend(
                [
                    ("deobfuscate", "stack_strings", {}),
                    ("deobfuscate", "api_hashing", {}),
                    ("crypto_id", "identify", {}),
                    ("yara_hunt", "list_rules", {}),
                ]
            )

        if include_tracing and not step_plan:
            step_plan.extend(
                [
                    ("trace", "get", {}),
                    ("trace_analysis", "analyze_coverage", {}),
                    ("trace_analysis", "find_loops", {}),
                    ("coverage", "report", {}),
                ]
            )

        step_plan = step_plan[:max_steps]
        steps: list[dict] = []
        raw_findings: list[dict] = []
        # First-pass vuln DB signal injection before orchestrated modules.
        vuln_seed = self._threat_hunt_vuln_db_pass(idb_path, limit=max(20, min(limit, 200)))
        if vuln_seed:
            raw_findings.extend(vuln_seed)
        for tool, step_action, step_args in step_plan:
            st = self._threat_hunt_step(idb_path, tool, step_action, step_args)
            steps.append(
                {
                    "tool": tool,
                    "action": step_action,
                    "ok": bool(st.get("ok")),
                    "error": st.get("error"),
                }
            )
            if st.get("ok"):
                raw_findings.extend(self._threat_hunt_extract_findings(st))
            elif include_evidence:
                raw_findings.append(
                    {
                        "tool": tool,
                        "action": step_action,
                        "error": st.get("error"),
                        "code": st.get("code"),
                    }
                )

        dedup: dict[str, dict] = {}
        dedup_freq: dict[str, int] = {}
        for f in raw_findings:
            if not isinstance(f, dict):
                continue
            addr = str(f.get("addr") or f.get("address") or f.get("ea") or "")
            kind = str(f.get("type") or f.get("kind") or f.get("action") or "")
            text = str(
                f.get("name")
                or f.get("title")
                or f.get("summary")
                or f.get("value")
                or ""
            )
            key = f"{f.get('tool', '')}|{kind}|{addr}|{text}".strip().lower()
            if not key:
                continue
            if key not in dedup:
                dedup[key] = f
                dedup_freq[key] = 1
            else:
                dedup_freq[key] = dedup_freq.get(key, 1) + 1

        ranked_findings: list[dict] = []
        for k, f in dedup.items():
            row = dict(f)
            row["ml_score"] = self._threat_hunt_score_finding(row, dedup_freq.get(k, 1))
            row["support_count"] = dedup_freq.get(k, 1)
            row["severity"] = self._severity_classify(row)
            ranked_findings.append(row)
        ranked_findings.sort(key=lambda x: (x.get("ml_score", 0.0), x.get("support_count", 1)), reverse=True)
        findings = ranked_findings[:limit]
        findings, hotspots = self._correlate_findings(findings)
        attack_paths = self._synthesize_attack_paths(findings)
        ok_steps = sum(1 for s in steps if s.get("ok"))
        failed_steps = len(steps) - ok_steps
        out = {
            "ok": True,
            "action": "legacy" if action == "legacy" else "run",
            "profile": profile,
            "pipeline": {
                "modules": {
                    "vuln": include_vuln,
                    "malware": include_malware,
                    "tracing": include_tracing,
                },
                "steps_total": len(steps),
                "steps_ok": ok_steps,
                "steps_failed": failed_steps,
            },
            "steps": steps,
            "findings": findings,
            "count": len(findings),
            "total_raw_findings": len(raw_findings),
            "deduped": max(0, len(raw_findings) - len(findings)),
            "hotspots": hotspots,
            "attack_paths": attack_paths,
        }
        if legacy_meta:
            out["legacy"] = legacy_meta
        if include_evidence:
            out["evidence"] = {
                "raw_findings": raw_findings[: min(300, len(raw_findings))]
            }
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

    def _predict_next_tool_from_activity(
        self, activity_log: list[dict], limit: int = 5
    ) -> list[dict]:
        """2nd-order Markov predictor with recency weighting and phase/exploration priors."""
        if not activity_log:
            return []

        seq = [
            f"{str(e.get('tool') or '').strip()}.{str(e.get('action') or '').strip()}"
            for e in activity_log
            if e.get("tool") and e.get("action")
        ]
        seq = [s for s in seq if s and s != "."]
        if not seq:
            return []

        global_counts = Counter(seq)
        first_order: dict[str, Counter] = {}
        second_order: dict[tuple[str, str], Counter] = {}
        n = len(seq)
        for i in range(n - 1):
            src = seq[i]
            dst = seq[i + 1]
            # Recency decay: last 5 transitions get 2x, next 5 get 1.5x, older 1x.
            dist_from_tail = (n - 2) - i
            w = 2.0 if dist_from_tail < 5 else (1.5 if dist_from_tail < 10 else 1.0)
            first_order.setdefault(src, Counter())[dst] += w
            if i >= 1:
                key2 = (seq[i - 1], src)
                second_order.setdefault(key2, Counter())[dst] += w

        current = seq[-1]
        prev = seq[-2] if len(seq) > 1 else ""
        local_first = first_order.get(current, Counter())
        local_second = second_order.get((prev, current), Counter()) if prev else Counter()
        total_global = max(1.0, float(sum(global_counts.values())))
        total_first = max(1.0, float(sum(local_first.values())))
        total_second = max(1.0, float(sum(local_second.values())))

        candidates = set(global_counts.keys()) | set(local_first.keys()) | set(local_second.keys())
        scored: list[dict] = []
        seen_tools = {s.split(".", 1)[0] for s in seq if "." in s}
        phase = str(getattr(self.current_session, "phase", "") or "").strip().lower()
        for cand in candidates:
            p_second = float(local_second.get(cand, 0.0)) / total_second
            p_first = float(local_first.get(cand, 0.0)) / total_first
            p_global = global_counts.get(cand, 0) / total_global
            has_second = sum(local_second.values()) > 0
            # 2nd-order primary; fallback to 1st-order if cold start.
            base_score = (0.65 * p_second + 0.20 * p_first + 0.15 * p_global) if has_second else (0.75 * p_first + 0.25 * p_global)
            tool, action = cand.split(".", 1) if "." in cand else (cand, "")
            exploration_bonus = 0.15 if tool and tool not in seen_tools else 0.0
            phase_bonus = 0.0
            if phase == "triage" and tool in {"firmware_view", "workflow"}:
                phase_bonus = 0.10
            elif phase == "deep_analysis" and tool in {"code", "types", "taint"}:
                phase_bonus = 0.10
            score = base_score + exploration_bonus + phase_bonus
            scored.append(
                {
                    "tool": tool,
                    "action": action,
                    "score": round(score, 4),
                    "evidence": {
                        "transition_hits_first_order": float(local_first.get(cand, 0.0)),
                        "transition_hits_second_order": float(local_second.get(cand, 0.0)),
                        "global_hits": int(global_counts.get(cand, 0)),
                        "current": current,
                        "prev": prev,
                        "has_second_order": bool(has_second),
                        "exploration_bonus": exploration_bonus,
                        "phase_bonus": phase_bonus,
                        "phase": phase or None,
                    },
                }
            )

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[: max(1, limit)]

    def _get_blackboard_store(self):
        """
        Return a BlackboardStore scoped to the current session's IDB path.
        Creates a new store object per session so binaries don't share findings.
        Falls back to the cached global store when no session is active.
        """
        try:
            if IDAMCPServer._blackboard_module is None:
                import importlib.util
                bb_path = os.path.join(SCRIPT_DIR, "..", "ida_mcp", "tools", "blackboard.py")
                bb_path = os.path.abspath(bb_path)
                spec = importlib.util.spec_from_file_location("_host_blackboard", bb_path)
                mod = importlib.util.module_from_spec(spec)
                mod.__dict__["tool"] = lambda f: f
                mod.__dict__["idaread"] = lambda f: f
                mod.__dict__["idawrite"] = lambda f: f
                mod.__dict__["IDAError"] = Exception
                spec.loader.exec_module(mod)
                IDAMCPServer._blackboard_module = mod
            mod = IDAMCPServer._blackboard_module
            # Per-binary scoping: derive path from current session IDB
            idb = None
            if self.current_session and getattr(self.current_session, "idb_path", None):
                idb = self.current_session.idb_path + ".blackboard.db"
            return mod.BlackboardStore(db_path=idb)
        except Exception:
            # Last-resort fallback: global store
            if IDAMCPServer._blackboard_store is None:
                try:
                    IDAMCPServer._blackboard_store = IDAMCPServer._blackboard_module.BlackboardStore()
                except Exception:
                    return None
            return IDAMCPServer._blackboard_store

    def _binary_sha256(self, binary_path: str) -> str:
        try:
            if not binary_path or not os.path.exists(binary_path):
                return ""
            h = hashlib.sha256()
            with open(binary_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _export_session_hypotheses_to_symbol_db(self, sid: str, session_obj=None) -> int:
        try:
            sess = session_obj or self.session_mgr.get_session(sid)
            if not sess:
                return 0
            hyps = self.session_mgr.get_high_confidence_hypotheses(sid, min_confidence=0.8)
            if not hyps:
                return 0
            bin_hash = self._binary_sha256(str(getattr(sess, "binary_path", "") or ""))
            chip = str((getattr(sess, "analysis_options", {}) or {}).get("chip_family") or "").strip()
            baseaddr = 0
            try:
                raw_base = (getattr(sess, "analysis_options", {}) or {}).get("baseaddr")
                if isinstance(raw_base, str):
                    baseaddr = int(raw_base, 0)
                elif raw_base is not None:
                    baseaddr = int(raw_base)
            except Exception:
                baseaddr = 0
            sdb = SymbolDB()
            count = 0
            for h in hyps:
                text = str(h.get("statement") or h.get("title") or "").strip()
                if not text:
                    continue
                m = re.search(r"0x[0-9a-fA-F]+", text)
                if not m:
                    continue
                try:
                    addr = int(m.group(0), 16)
                except Exception:
                    continue
                addr_offset = addr - baseaddr if baseaddr and addr >= baseaddr else addr
                conf = float(h.get("confidence", 0.8) or 0.8)
                rid = sdb.upsert_hypothesis(
                    binary_hash=bin_hash,
                    chip_family=chip,
                    addr_offset=int(addr_offset),
                    hypothesis_text=text,
                    confidence=conf,
                    source_session=sid,
                    source_binary=str(getattr(sess, "binary_path", "") or ""),
                )
                if rid:
                    count += 1
            return int(count)
        except Exception:
            return 0

    def _import_cross_session_hypotheses(self, session_obj) -> int:
        try:
            if not session_obj:
                return 0
            bin_hash = self._binary_sha256(str(getattr(session_obj, "binary_path", "") or ""))
            chip = str((getattr(session_obj, "analysis_options", {}) or {}).get("chip_family") or "").strip()
            sdb = SymbolDB()
            hits = sdb.query_hypotheses(binary_hash=bin_hash, chip_family=chip, limit=200)
            if not hits:
                return 0
            baseaddr = 0
            try:
                raw_base = (getattr(session_obj, "analysis_options", {}) or {}).get("baseaddr")
                if isinstance(raw_base, str):
                    baseaddr = int(raw_base, 0)
                elif raw_base is not None:
                    baseaddr = int(raw_base)
            except Exception:
                baseaddr = 0
            bb_path = str(getattr(session_obj, "idb_path", "") or "") + ".blackboard.db"
            store = IDAMCPServer._blackboard_module.BlackboardStore(db_path=bb_path) if IDAMCPServer._blackboard_module else self._get_blackboard_store()
            if store is None:
                return 0
            imported = 0
            for row in hits:
                title = str(row.get("hypothesis_text") or "").strip()
                if not title:
                    continue
                off = int(row.get("addr_offset", 0) or 0)
                addr = hex((baseaddr + off) if baseaddr else off)
                if store.exists_similar(addr, "hypothesis", title):
                    continue
                store.write(
                    title=title,
                    content=f"Imported from prior session ({row.get('source_session', '')})",
                    category="hypothesis",
                    addr=addr,
                    tags=["cross_session", "symboldb"],
                    confidence=float(row.get("confidence", 0.8) or 0.8),
                    source="symbol_db.import",
                    source_type="cross_session",
                )
                imported += 1
            return int(imported)
        except Exception:
            return 0

    def _handle_blackboard(self, args: dict) -> dict:
        """Host-side blackboard handler so it works without IDA runtime."""
        store = self._get_blackboard_store()
        if store is None:
            return make_error(MCPError.IDA_ERROR, "BlackboardStore unavailable")
        action = str(args.get("action") or "list").strip().lower()
        if action == "write":
            title = str(args.get("name") or args.get("title") or "").strip()
            if not title:
                return make_error(MCPError.INVALID_ARGS, "name/title required for write")
            # Parse Cartographer-μ metadata if provided
            bridges_raw = str(args.get("bridges") or "")
            bridges = [b.strip() for b in bridges_raw.split(",") if b.strip()]
            schema_str = str(args.get("schema") or "")
            schema = {}
            if schema_str:
                try:
                    schema = json.loads(schema_str)
                except Exception:
                    pass
            vector = args.get("vector")
            quantized = args.get("quantized")
            q_signs = args.get("q_signs")
            norm = float(args.get("norm", 0.0))
            q_value = float(args.get("q_value", 0.5))
            call_idx = int(args.get("call_idx", 0))
            eid = store.write(
                title=title,
                content=str(args.get("notes") or args.get("content") or ""),
                category=str(args.get("category") or "general"),
                addr=str(args.get("addr") or ""),
                tags=[t.strip() for t in str(args.get("tags") or "").split(",") if t.strip()],
                confidence=float(args.get("confidence", 0.5)),
                bridges=bridges,
                schema=schema,
                vector=vector,
                quantized=quantized,
                q_signs=q_signs,
                norm=norm,
                q_value=q_value,
                call_idx=call_idx,
            )
            return {"ok": True, "entry_id": eid, "action": "write"}
        if action == "list":
            entries = store.list(
                category=str(args.get("category") or "").strip() or None,
                addr=str(args.get("addr") or "").strip() or None,
                tag=str(args.get("tag") or "").strip() or None,
                min_confidence=float(args.get("min_confidence", 0.0)),
                limit=_bounded_int(args.get("limit", 100), 100, min_value=1, max_value=1000),
                offset=_bounded_int(args.get("offset", 0), 0, min_value=0),
            )
            return {"ok": True, "entries": entries, "count": len(entries)}
        if action == "search":
            query = str(args.get("query") or args.get("pattern") or "").strip()
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query/pattern required for blackboard search")
            entries = store.semantic_search(
                query=query,
                top_k=_bounded_int(args.get("limit", 20), 20, min_value=1, max_value=500),
                threshold=float(args.get("threshold", 0.4)),
                category=str(args.get("category") or "").strip() or None,
                include_resolved=bool(args.get("include_resolved", True)),
                include_contradicted=bool(args.get("include_contradicted", False)),
            )
            return {"ok": True, "query": query, "entries": entries, "count": len(entries)}
        if action == "read":
            entry = store.read(str(args.get("entry_id") or ""))
            if entry is None:
                return make_error(MCPError.INVALID_ARGS, "Entry not found")
            return {"ok": True, "entry": entry}
        if action == "update":
            entry_id = str(args.get("entry_id") or "").strip()
            if not entry_id:
                return make_error(MCPError.INVALID_ARGS, "entry_id required")
            updates = {
                k: v
                for k, v in (args or {}).items()
                if k
                not in {
                    "action",
                    "entry_id",
                }
            }
            if not updates:
                return make_error(MCPError.INVALID_ARGS, "No update fields provided")
            ok = store.update(entry_id, **updates)
            return {"ok": ok, "action": "update", "entry_id": entry_id} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found or no valid fields")
        if action == "delete":
            ok = store.delete(str(args.get("entry_id") or ""))
            return {"ok": ok, "action": "delete"}
        if action == "clear":
            count = store.clear(category=str(args.get("category") or "").strip() or None)
            return {"ok": True, "deleted": count}
        if action == "stats":
            return {"ok": True, **store.stats()}
        if action == "merge":
            result = store.auto_merge(
                addr=str(args.get("addr") or "").strip(),
                category=str(args.get("category") or "").strip(),
                similarity_threshold=float(args.get("similarity_threshold", 0.85)),
            )
            return {"ok": True, **result}
        if action == "prune":
            result = store.prune(
                max_entries=_bounded_int(args.get("max_entries", 1000), 1000, min_value=1, max_value=100000),
                min_q_value=float(args.get("min_q_value", 0.0)),
                older_than_days=int(args.get("older_than_days", 0)),
            )
            return {"ok": True, **result}
        if action == "contradict":
            eid = str(args.get("entry_id") or "").strip()
            reason = str(args.get("reason") or "").strip()
            if not eid or not reason:
                return make_error(MCPError.INVALID_ARGS, "entry_id and reason required")
            ok = store.contradict(eid, reason)
            return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{eid}' not found")
        if action == "resolve":
            eid = str(args.get("entry_id") or "").strip()
            if not eid:
                return make_error(MCPError.INVALID_ARGS, "entry_id required")
            ok = store.mark_resolved(eid)
            return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{eid}' not found")
        if action == "next_target":
            targets = store.next_target(limit=int(args.get("limit") or 5))
            return {"ok": True, "targets": targets, "count": len(targets),
                    "note": "Highest-priority unexplored addresses. Use code(action='decompile') on the top target."}
        if action == "frontier":
            try:
                from .frontier import FrontierEngine
                emb_db = os.path.join(self.cache_dir, "embeddings.sqlite3")
                fe = FrontierEngine(emb_db, getattr(store, "db_path", None))
                results = fe.frontier(limit=_bounded_int(args.get("limit", 20), 20, min_value=1, max_value=200))
                return {"ok": True, "frontier": results, "count": len(results)}
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"frontier unavailable: {e}")
        if action == "add_evidence":
            entry_id = str(args.get("entry_id") or "").strip()
            evidence_type = str(args.get("evidence_type") or args.get("type") or "").strip()
            value = str(args.get("value") or "").strip()
            if not entry_id or not evidence_type or not value:
                return make_error(MCPError.INVALID_ARGS, "entry_id, evidence_type/type, and value required")
            ok = store.add_evidence(entry_id, evidence_type=evidence_type, value=value, weight=float(args.get("weight", 1.0)))
            return {"ok": ok, "entry_id": entry_id} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found")
        if action == "calibrate":
            entry_id = str(args.get("entry_id") or "").strip()
            if not entry_id:
                return make_error(MCPError.INVALID_ARGS, "entry_id required")
            new_conf = store.calibrate_confidence(entry_id)
            if new_conf is None:
                return make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found")
            return {"ok": True, "entry_id": entry_id, "confidence": new_conf}
        if action == "campaign_summary":
            return {"ok": True, "summary": store.campaign_summary()}
        if action == "auto_tag_propagate":
            updated = store.auto_tag_propagate()
            return {"ok": True, "updated": int(updated)}
        if action in ("start_crawler", "stop_crawler", "crawler_status", "accept", "reject"):
            # Delegate to the tool module which owns the crawler singleton
            mod = IDAMCPServer._blackboard_module
            if mod is None:
                return make_error(MCPError.IDA_ERROR, "BlackboardStore unavailable")
            crawler = mod._BackgroundCrawler.instance()
            if action == "start_crawler":
                crawler.start(notify_fn=self._send_notification)
                return {"ok": True, "running": crawler.is_running(),
                        "note": "Crawler uses frontier targets and runs agent(action='quick') every 0.5s."}
            elif action == "stop_crawler":
                crawler.stop()
                return {"ok": True, "running": False}
            elif action == "crawler_status":
                proposals = crawler.pending_proposals()
                return {"ok": True, "running": crawler.is_running(),
                        "pending_proposals": len(proposals), "proposals_pending": len(proposals),
                        "addresses_visited": crawler.visited_count(), "proposals": proposals[:10]}
            elif action == "accept":
                pid = str(args.get("proposal_id") or "").strip()
                if not pid:
                    return make_error(MCPError.INVALID_ARGS, "proposal_id required")
                eid = crawler.accept(pid)
                return {"ok": bool(eid), "entry_id": eid} if eid else make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found")
            elif action == "reject":
                pid = str(args.get("proposal_id") or "").strip()
                if not pid:
                    return make_error(MCPError.INVALID_ARGS, "proposal_id required")
                ok = crawler.reject(pid)
                return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found")
        if action == "attention_status":
            return {"ok": True, "note": "attention_kernel replaced by intelligence.py"}
        if action == "attention_policy_upsert":
            return {"ok": True, "action": "attention_policy_upsert",
                    "note": "attention_kernel replaced by intelligence.py"}
        if action in ("accept_proposal", "reject_proposal"):
            sid = self.current_session.session_id if self.current_session else ""
            engine = self._analysis_engines.get(sid)
            if not engine:
                return make_error(MCPError.NOT_FOUND, "No analysis engine running for current session")
            pid = str(args.get("proposal_id") or "").strip()
            if not pid:
                return make_error(MCPError.INVALID_PARAMS, "proposal_id required")
            if action == "accept_proposal":
                scope = str(args.get("scope") or "all").strip()
                selected_ids = args.get("selected_ids") or []
                result = engine.proposals.accept(pid, scope=scope, selected_ids=selected_ids)
                if result is None:
                    return make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found or already processed")
                # Apply accepted items based on proposal type
                applied = self._apply_proposal(result, engine)
                self._send_notification({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": "ida://state"},
                })
                self._send_notification({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": "ida://proposals"},
                })
                return {"ok": True, "proposal_id": pid, "accepted_items": len(result.get("accepted_items", [])), "applied": applied}
            else:
                bb_path = os.path.join(self.cache_dir, f"{sid}.blackboard.db")
                ok = engine.proposals.reject(pid, bb_path=bb_path)
                if not ok:
                    return make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found or already processed")
                self._send_notification({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": "ida://proposals"},
                })
                return {"ok": True, "proposal_id": pid}
        return make_error(
            MCPError.ACTION_NOT_FOUND,
            f"Unsupported blackboard action: '{action}'",
            hint="Valid actions: write, read, list, search, update, delete, clear, stats, merge, prune, contradict, resolve, next_target, start_crawler, stop_crawler, crawler_status, accept, reject, accept_proposal, reject_proposal, add_evidence, calibrate, campaign_summary, auto_tag_propagate",
        )

    def _apply_proposal(self, proposal: dict, engine) -> dict:
        """Apply accepted proposal items to IDA (renames, annotations, etc.)."""
        ptype = proposal.get("proposal_type", "")
        items = proposal.get("accepted_items", [])
        applied = {"renamed": 0, "annotated": 0, "errors": []}
        for item in items:
            addr = item.get("addr", "")
            try:
                if ptype == "rename_batch":
                    name = item.get("suggested_name", "")
                    if addr and name:
                        self._execute_tool("modify", {"action": "rename", "addr": addr, "name": name})
                        applied["renamed"] += 1
                elif ptype == "annotation_batch":
                    comment = item.get("comment", "")
                    if addr and comment:
                        self._execute_tool("modify", {"action": "comment", "addr": addr, "comment": comment})
                        applied["annotated"] += 1
                elif ptype == "cross_session":
                    name = item.get("suggested_name", "")
                    if addr and name:
                        self._execute_tool("modify", {"action": "rename", "addr": addr, "name": name})
                        applied["renamed"] += 1
            except Exception as e:
                applied["errors"].append({"addr": addr, "error": str(e)})
        # Push state update after applying
        self._send_notification({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": {"uri": "ida://state"},
        })
        return applied

    def _handle_predictor(self, args: dict) -> dict:
        action = str(args.get("action") or "suggest_next_tool").strip()
        sid = args.get("session_id")
        if not sid and self.current_session:
            sid = self.current_session.session_id
        if not sid:
            return make_error(
                MCPError.SESSION_REQUIRED,
                "No active session. Create/switch session first or pass session_id.",
            )
        if not self.session_mgr.session_exists(str(sid)):
            return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")

        limit = _bounded_int(args.get("limit", 5), 5, min_value=1, max_value=20)
        recent_n = _bounded_int(args.get("recent_n", 30), 30, min_value=5, max_value=200)
        context = str(args.get("context") or "").strip()

        activity = self.session_mgr.get_activity_log(str(sid), limit=recent_n)
        if isinstance(activity, dict) and activity.get("error"):
            return activity
        log = list((activity or {}).get("log") or [])

        if action == "suggest_next_tool":
            seq_suggestions = self._predict_next_tool_from_activity(log, limit=limit)

            # Augment with UsageIntelligence predictions (trained on real audit data)
            if getattr(self, "_usage_intel", None) and log:
                try:
                    last = log[-1] if log else {}
                    last_tool = last.get("tool", "")
                    last_action = last.get("action", "")
                    if last_tool:
                        ui_preds = self._usage_intel.predict_next(last_tool, last_action, top_k=limit)
                        # Merge: UI predictions get a "usage_intelligence" source tag
                        existing_keys = {(r.get("tool"), r.get("action")) for r in seq_suggestions}
                        for p in ui_preds:
                            key = (p["tool"], p["action"])
                            if key not in existing_keys:
                                seq_suggestions.append({
                                    "tool": p["tool"],
                                    "action": p["action"],
                                    "score": p["score"],
                                    "probability": p["probability"],
                                    "effectiveness": p["effectiveness"],
                                    "source": "usage_intelligence",
                                    "blended_confidence": round(p["score"], 4),
                                })
                            else:
                                # Boost existing suggestion with UI score
                                for r in seq_suggestions:
                                    if r.get("tool") == p["tool"] and r.get("action") == p["action"]:
                                        r["ui_score"] = p["score"]
                                        r["ui_effectiveness"] = p["effectiveness"]
                                        r["blended_confidence"] = round(
                                            (r.get("blended_confidence", r.get("score", 0)) + p["score"]) / 2, 4
                                        )
                    # Also check for drift signals
                    sid_str = str(sid)
                    drift = self._usage_intel.drift.check(sid_str)
                    if drift:
                        seq_suggestions = [{"drift_warning": d["message"],
                                            "signal": d["type"],
                                            "severity": d["severity"]}
                                           for d in drift[:2]] + seq_suggestions
                except Exception:
                    pass
            strategy = self.session_mgr.suggest_strategy(str(sid), context=context)
            strategy_rows = []
            strategy_confidence = 0.5
            bootstrap_prior = 0.5
            if isinstance(strategy, dict) and not strategy.get("error"):
                bootstrap_prior = float(strategy.get("bootstrap_prior", 0.5))
                for s in (strategy.get("suggestions") or [])[:limit]:
                    score = float(s.get("score", s.get("q_value", 0.0)))
                    blended = float(s.get("blended_score", score))
                    strategy_confidence = max(strategy_confidence, blended)
                    strategy_rows.append(
                        {
                            "skill_id": s.get("skill_id"),
                            "score": score,
                            "blended_score": blended,
                            "blend_weights": s.get("blend_weights", {}),
                            "bootstrap_prior": s.get("bootstrap_prior", bootstrap_prior),
                            "source": s.get("source", "local"),
                            "tags": s.get("tags", []),
                        }
                    )
            for row in seq_suggestions:
                base = float(row.get("score", 0.0))
                row["blended_confidence"] = round((0.7 * base) + (0.3 * bootstrap_prior), 4)

            # Augment with schemaboot-driven next targets (unanalyzed interesting functions)
            next_targets = []
            idb_path = getattr(self.current_session, "idb_path", None) if self.current_session else None
            if idb_path:
                try:
                    from .intelligence import get_assembler
                    asm = get_assembler()
                    next_targets = asm.suggest_next_targets(idb_path, limit=3)
                except Exception:
                    pass

            return {
                "ok": True,
                "session_id": sid,
                "model": "markov_plus_qvalue",
                "suggestions": seq_suggestions,
                "strategy_suggestions": strategy_rows,
                "next_targets": next_targets,  # schemaboot-ranked unanalyzed functions
                "strategy_confidence": round(strategy_confidence, 4),
                "bootstrap_prior": round(bootstrap_prior, 4),
                "activity_window": len(log),
                "context": context,
            }

        if action == "recommend_bundle":
            tool_res = self._handle_predictor(
                {
                    "action": "suggest_next_tool",
                    "session_id": sid,
                    "limit": limit,
                    "recent_n": recent_n,
                    "context": context,
                }
            )
            if not isinstance(tool_res, dict) or tool_res.get("error"):
                return tool_res
            focus_res = self._handle_predictor(
                {
                    "action": "suggest_focus",
                    "session_id": sid,
                    "limit": limit,
                    "recent_n": recent_n,
                    "context": context,
                }
            )
            if not isinstance(focus_res, dict) or focus_res.get("error"):
                return focus_res
            addr_res = self._handle_predictor(
                {
                    "action": "suggest_next_address",
                    "session_id": sid,
                    "limit": limit,
                    "recent_n": recent_n,
                    "context": context,
                }
            )
            if not isinstance(addr_res, dict) or addr_res.get("error"):
                return addr_res
            stall_res = self._handle_predictor(
                {
                    "action": "risk_of_stall",
                    "session_id": sid,
                    "recent_n": recent_n,
                    "context": context,
                }
            )
            if not isinstance(stall_res, dict) or stall_res.get("error"):
                return stall_res

            return {
                "ok": True,
                "session_id": sid,
                "action": "recommend_bundle",
                "bundle": {
                    "tool_suggestions": tool_res.get("suggestions", []),
                    "strategy_suggestions": tool_res.get("strategy_suggestions", []),
                    "focus_pivots": focus_res.get("focus_pivots", []),
                    "address_suggestions": addr_res.get("suggestions", []),
                    "stall_risk": {
                        "risk_score": stall_res.get("risk_score"),
                        "dead_end_detected": stall_res.get("dead_end_detected"),
                        "entropy": stall_res.get("entropy"),
                    },
                },
                "summary": {
                    "tool_count": len(tool_res.get("suggestions", []) or []),
                    "focus_count": len(focus_res.get("focus_pivots", []) or []),
                    "address_count": len(addr_res.get("suggestions", []) or []),
                    "stall_risk": stall_res.get("risk_score"),
                },
            }

        if action == "detect_stuck":
            dead_end = self.session_mgr._detect_dead_end(log)
            return {
                "ok": True,
                "session_id": sid,
                "stuck": bool(dead_end),
                "signal": dead_end or {},
                "activity_window": len(log),
            }

        if action == "suggest_focus":
            dead_end = self.session_mgr._detect_dead_end(log)
            phase = self.session_mgr.get_phase(str(sid))
            phase_tools = []
            if isinstance(phase, dict) and not phase.get("error"):
                phase_tools = list(phase.get("suggested_tools") or [])

            pivots = []
            if dead_end and isinstance(dead_end, dict):
                dtype = str(dead_end.get("type") or "")
                if dtype == "repeated_decompile":
                    pivots = ["code:callers", "code:callees", "xref_analysis:dependency_graph"]
                elif dtype == "repeated_search":
                    pivots = ["search:structured", "schemaboot:query", "string_ops:indicators"]
                elif dtype == "tool_loop":
                    pivots = ["graph:cfg", "classify:function", "threat_hunt:quick"]

            if not pivots:
                pivots = [f"{t}:*" for t in phase_tools[:5]] if phase_tools else ["data:functions", "code:decompile", "search:name"]

            # Embedding-guided pivots from analyst context: map intent text to likely function targets.
            context_text = str(context or "").strip()
            embedding_focus = []
            if context_text:
                try:
                    idb_path = getattr(self.current_session, "idb_path", None) if self.current_session else None
                    if idb_path:
                        from .intelligence import get_assembler
                        asm = get_assembler()
                        idx = asm._get_index(idb_path)
                        if getattr(idx, "size", 0) > 0:
                            q_vec = asm._embedder.embed(context_text[:500])
                            hits = idx.search(q_vec, top_k=max(6, min(9, max(1, limit) * 3)), threshold=0.0)
                            if hits:
                                vals = sorted(float(h.get("similarity") or 0.0) for h in hits)
                                q50 = vals[len(vals) // 2]
                                q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
                                gate = q50 + max(0.0, q75 - q50)
                                hits = [h for h in hits if float(h.get("similarity") or 0.0) >= gate]
                            for h in hits:
                                ea = str(h.get("ea") or "").strip()
                                if not ea:
                                    continue
                                embedding_focus.append(
                                    {
                                        "pivot": f"code:smart_decompile:{ea}",
                                        "similarity": round(float(h.get("similarity") or 0.0), 4),
                                        "name": h.get("name") or ea,
                                    }
                                )
                except Exception:
                    embedding_focus = []

            return {
                "ok": True,
                "session_id": sid,
                "focus_pivots": pivots[:limit],
                "embedding_focus": embedding_focus,
                "phase": phase.get("phase") if isinstance(phase, dict) else None,
                "dead_end": dead_end or {},
            }

        if action == "suggest_next_address":
            # Primary: blackboard next_target (priority queue with time decay + xref boost)
            bb_targets = []
            try:
                sid_str = str(sid)
                bb_path = os.path.join(self.cache_dir, f"{sid_str}.blackboard.db")
                if os.path.exists(bb_path):
                    import importlib.util as _ilu
                    _bb_path = os.path.join(
                        os.path.dirname(os.path.abspath(__file__)),
                        "..", "ida_mcp", "tools", "blackboard.py"
                    )
                    _spec = _ilu.spec_from_file_location("_pred_bb", os.path.abspath(_bb_path))
                    _bmod = _ilu.module_from_spec(_spec)
                    _bmod.__dict__.update({"tool": lambda f: f, "idaread": lambda f: f,
                                           "idawrite": lambda f: f, "IDAError": Exception})
                    _spec.loader.exec_module(_bmod)
                    store = _bmod.BlackboardStore(db_path=bb_path)
                    raw_targets = store.next_target(limit=limit)
                    for t in raw_targets:
                        bb_targets.append({
                            "addr": t["addr"],
                            "reason": f"{t['category']}: {t['title'][:60]}",
                            "priority_score": t["priority_score"],
                            "source": "blackboard",
                            "tool": "code",
                            "action": "smart_decompile",
                        })
            except Exception:
                pass

            # Secondary: schemaboot + embedding index
            idb_path = getattr(self.current_session, "idb_path", None) if self.current_session else None
            schema_targets = []
            if idb_path:
                try:
                    from .intelligence import get_assembler
                    asm = get_assembler()
                    schema_targets = asm.suggest_next_targets(idb_path, limit=limit)
                except Exception:
                    pass

            # Merge: blackboard first, then schemaboot for any not already covered
            bb_addrs = {t["addr"] for t in bb_targets}
            merged = list(bb_targets)
            for t in schema_targets:
                if t.get("addr") not in bb_addrs:
                    t["source"] = "schemaboot"
                    merged.append(t)

            # Embedding-guided expansion from context when address set is sparse.
            context_text = str(context or "").strip()
            if context_text and len(merged) < limit:
                try:
                    idb_path = getattr(self.current_session, "idb_path", None) if self.current_session else None
                    if idb_path:
                        from .intelligence import get_assembler
                        asm = get_assembler()
                        idx = asm._get_index(idb_path)
                        if getattr(idx, "size", 0) > 0:
                            q_vec = asm._embedder.embed(context_text[:500])
                            hits = idx.search(q_vec, top_k=max(limit * 3, 6), threshold=0.0)
                            if hits:
                                vals = sorted(float(h.get("similarity") or 0.0) for h in hits)
                                q50 = vals[len(vals) // 2]
                                q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
                                gate = q50 + max(0.0, q75 - q50)
                                hits = [h for h in hits if float(h.get("similarity") or 0.0) >= gate]
                            known = {str(t.get("addr") or "") for t in merged}
                            for h in hits:
                                ea = str(h.get("ea") or "").strip()
                                if not ea or ea in known:
                                    continue
                                merged.append(
                                    {
                                        "addr": ea,
                                        "reason": f"context semantic match ({context_text[:48]})",
                                        "tool": "code",
                                        "action": "smart_decompile",
                                        "source": "embedding_context",
                                        "similarity": round(float(h.get("similarity") or 0.0), 4),
                                    }
                                )
                                known.add(ea)
                                if len(merged) >= limit:
                                    break
                except Exception:
                    pass

            # Fallback: recent addresses from activity log
            if not merged:
                addrs = []
                for e in log:
                    if not isinstance(e, dict):
                        continue
                    for k in ("addr", "address", "ea"):
                        v = e.get(k)
                        if v and str(v).startswith("0x"):
                            a = str(v).lower()
                            if a not in addrs:
                                addrs.append(a)
                if addrs:
                    merged = [{"addr": addrs[-1], "reason": "recent focus — check callers",
                               "tool": "code", "action": "callers", "source": "activity_log"}]

            return {
                "ok": True,
                "session_id": sid,
                "suggestions": merged[:limit],
                "sources_used": list({t.get("source", "unknown") for t in merged}),
                "note": (
                    "Ranked by blackboard priority (confidence x time_decay x xref_boost). "
                    "Use blackboard(action='next_target') for the full priority queue."
                ) if bb_targets else (
                    "No blackboard entries yet. Run schemaboot(action='ingest') for smarter suggestions."
                ),
            }

        if action == "risk_of_stall":
            dead_end = self.session_mgr._detect_dead_end(log)
            # Sequence entropy: low variety in recent tools -> high stall risk
            recent_tools = [f"{e.get('tool','')}.{e.get('action','')}" for e in log[-20:] if isinstance(e, dict)]
            unique_tools = len(set(recent_tools))
            total_recent = max(1, len(recent_tools))
            entropy = unique_tools / total_recent
            stall_score = 0.0
            if dead_end:
                stall_score += 0.5
            stall_score += max(0.0, 0.5 - entropy)
            return {
                "ok": True,
                "session_id": sid,
                "risk_score": round(min(1.0, stall_score), 3),
                "entropy": round(entropy, 3),
                "dead_end_detected": bool(dead_end),
                "recent_tool_variety": unique_tools,
                "recent_tool_total": total_recent,
            }

        if action == "explain_decision":
            # Explain why a tool/action was suggested, based on real activity state
            target_tool = str(args.get("target_tool") or "").strip()
            target_action = str(args.get("target_action") or "").strip()

            # Derive actual feature contributions from the session's activity log
            recent_tools = [
                f"{e.get('tool','')}.{e.get('action','')}"
                for e in log[-20:] if isinstance(e, dict)
            ]
            from collections import Counter
            tool_freq = Counter(recent_tools)
            ta_key = f"{target_tool}.{target_action}"

            explanations = []
            weights = {
                "markov_transition_probability": 0.0,
                "usage_pattern": 0.0,
                "strategy_weight": 0.0,
                "blackboard_coverage_gap": 0.0,
            }
            # 1. How often has this tool:action appeared in recent history?
            freq = tool_freq.get(ta_key, 0)
            total = max(1, len(recent_tools))
            if freq > 0:
                weights["usage_pattern"] = min(1.0, float(freq) / float(total))
                explanations.append({
                    "feature": "recent_frequency",
                    "count": freq,
                    "ratio": round(freq / total, 3),
                    "reason": f"Called {freq}x in last {total} tool calls",
                })
            # 2. Is this a natural next step from the last tool?
            if recent_tools:
                last = recent_tools[-1]
                NATURAL_NEXT = {
                    "code.decompile": ["crypto_id.identify", "code.callers", "code.callees",
                                        "annotation.mark_dangerous", "xref_analysis.call_chain"],
                    "search.api": ["code.decompile", "xref_analysis.call_chain"],
                    "search.find": ["code.decompile", "data.functions"],
                    "code.callers": ["code.decompile", "xref_analysis.call_chain"],
                }
                if ta_key in NATURAL_NEXT.get(last, []):
                    weights["markov_transition_probability"] = 0.8
                    explanations.append({
                        "feature": "natural_next_step",
                        "after": last,
                        "reason": f"Typical follow-up after {last}",
                    })
            # 3. Is this suggested by an active dangerous pattern?
            idb_path = getattr(self.current_session, "idb_path", None) if self.current_session else None
            if idb_path:
                try:
                    from .intelligence import get_assembler
                    asm = get_assembler()
                    targets = asm.suggest_next_targets(idb_path, limit=5)
                    if targets and target_tool == "code" and target_action == "decompile":
                        top = targets[0]
                        weights["blackboard_coverage_gap"] = 0.7
                        explanations.append({
                            "feature": "schemaboot_interest",
                            "top_target": top.get("ea"),
                            "reason": f"Unanalyzed function with {top.get('reason', 'high interest score')}",
                        })
                except Exception:
                    pass
            try:
                strategy = self.session_mgr.suggest_strategy(str(sid), context=f"{target_tool}:{target_action}")
                if isinstance(strategy, dict) and not strategy.get("error"):
                    suggs = strategy.get("suggestions") or []
                    if suggs:
                        weights["strategy_weight"] = max(
                            float(s.get("blended_score", s.get("score", 0.0)) or 0.0)
                            for s in suggs[:5]
                            if isinstance(s, dict)
                        )
            except Exception:
                pass

            if not explanations:
                explanations.append({
                    "feature": "no_strong_signal",
                    "reason": f"No specific signal in activity log for {target_tool}.{target_action}",
                })

            return {
                "ok": True,
                "session_id": sid,
                "target_tool": target_tool,
                "target_action": target_action,
                "activity_window": len(log),
                "explanations": explanations,
                "signal_weights": {k: round(float(v), 4) for k, v in weights.items()},
            }

        if action == "feedback":
            target_tool = str(args.get("tool") or args.get("target_tool") or "").strip().lower()
            target_action = str(args.get("target_action") or "").strip().lower()
            outcome = str(args.get("outcome") or "").strip().lower()
            if not target_tool or not target_action:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "feedback requires tool and target_action",
                    hint="Example: predictor(action='feedback', tool='search', target_action='find', outcome='helpful')",
                )
            if outcome not in {"helpful", "not_helpful"}:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "outcome must be 'helpful' or 'not_helpful'",
                )
            delta = 0.05 if outcome == "helpful" else -0.05
            meta = self.session_mgr.macro_get(str(sid), "__predictor_feedback") or {}
            if not isinstance(meta, dict):
                meta = {}
            key = f"{target_tool}.{target_action}"
            row = meta.get(key) if isinstance(meta.get(key), dict) else {"weight": 0.5, "count": 0}
            row["weight"] = max(0.0, min(1.0, float(row.get("weight", 0.5)) + delta))
            row["count"] = int(row.get("count", 0)) + 1
            row["last_outcome"] = outcome
            meta[key] = row
            self.session_mgr.macro_set(str(sid), "__predictor_feedback", meta)
            return {
                "ok": True,
                "session_id": sid,
                "tool": target_tool,
                "target_action": target_action,
                "outcome": outcome,
                "updated_weight": round(float(row["weight"]), 4),
                "feedback_count": int(row["count"]),
            }

        return make_error(
            MCPError.ACTION_NOT_FOUND,
            f"Unsupported predictor action: '{action}'",
            hint=f"Valid predictor actions: {', '.join(TOOL_ACTIONS.get('predictor', []))}",
        )

    def _normalize_batch_call(
        self, call: Any, idx: int
    ) -> tuple[Optional[str], Any, Optional[dict]]:
        """
        Normalize one batch entry.
        Supported forms:
        - "tool:action" / "tool"
        - {"name": "...", "arguments": {...}} (or args)
        - {"tool": "...", "action": "...", ...inline_args}
        """
        if isinstance(call, str):
            raw = call.strip()
            if not raw:
                return (
                    None,
                    {},
                    make_error(MCPError.INVALID_ARGS, f"Call at index {idx} is empty"),
                )
            if ":" in raw:
                name, action = raw.split(":", 1)
                name = name.strip()
                action = action.strip()
                if not name:
                    return (
                        None,
                        {},
                        make_error(
                            MCPError.INVALID_ARGS,
                            f"Call at index {idx} missing tool name",
                        ),
                    )
                call_args = {"action": action} if action else {}
                return name, call_args, None
            return raw, {}, None
        if not isinstance(call, dict):
            return (
                None,
                {},
                make_error(
                    MCPError.INVALID_ARGS,
                    f"Call at index {idx} must be an object or string",
                ),
            )

        name = call.get("name", call.get("tool"))
        call_args = call.get("arguments", call.get("args"))
        if call_args is None:
            call_args = {}
        if not isinstance(call_args, dict):
            return name, call_args, None

        if "action" not in call_args and isinstance(call.get("action"), str):
            call_args = dict(call_args)
            call_args["action"] = call.get("action")
        passthrough = {
            k: v
            for k, v in call.items()
            if k not in {"name", "tool", "arguments", "args", "action"}
        }
        if passthrough:
            call_args = dict(call_args)
            for k, v in passthrough.items():
                call_args.setdefault(k, v)
        return name, call_args, None

    def _handle_workflow(self, args: dict) -> dict:
        action = str(args.get("action") or "triage_fast").strip().lower()
        profile = str(args.get("profile") or "balanced").strip().lower()
        if profile not in {"quick", "balanced", "deep"}:
            profile = "balanced"
        limit = _bounded_int(args.get("limit", 20), 20, min_value=1, max_value=100)
        addr = str(args.get("addr") or "").strip()
        dry_run = _coerce_bool(args.get("dry_run"), False)
        include_tools = [t.strip().lower() for t in _parse_str_list(args.get("include_tools")) if t and str(t).strip()]
        exclude_tools = [t.strip().lower() for t in _parse_str_list(args.get("exclude_tools")) if t and str(t).strip()]
        include_tools = list(dict.fromkeys(include_tools))
        exclude_tools = list(dict.fromkeys(exclude_tools))

        step_plan: list[dict] = []
        workflow_meta: dict = {"version": 1, "action": action, "profile": profile}

        def _detect_firmware_mode() -> tuple[bool, str, bool]:
            """Best-effort firmware detection with fallback to IDB metadata."""
            overview_failed = False
            raw_binary_mode = False
            try:
                overview = self._execute_tool("idb", {"action": "overview"})
                if isinstance(overview, dict):
                    arch_profile = overview.get("architecture_profile") if isinstance(overview.get("architecture_profile"), dict) else {}
                    if isinstance(arch_profile, dict):
                        raw_binary_mode = bool(arch_profile.get("raw_binary_mode", False))
                    if bool(overview.get("firmware_detected")):
                        return True, "idb_overview", raw_binary_mode
                    # Keep overview as the authoritative trigger unless fallback
                    # can positively detect raw/firmware from explicit filetype metadata.
                    overview_trigger = "idb_overview"
                else:
                    return False, "idb_overview_non_dict", raw_binary_mode
            except Exception:
                overview_failed = True
            if overview_failed:
                return False, "idb_overview_error", raw_binary_mode
            try:
                meta = self._execute_tool("idb", {"action": "meta"})
                if isinstance(meta, dict):
                    ft_info = meta.get("file_type_info") if isinstance(meta.get("file_type_info"), dict) else {}
                    ft_name = str(
                        meta.get("file_type_effective")
                        or ft_info.get("effective")
                        or meta.get("file_type")
                        or ""
                    ).strip().lower()
                    ft_id = meta.get("file_type_id")
                    raw_binary_mode = raw_binary_mode or ft_name in {"raw", "unknown", "bin", "binary", ""}
                    if not ft_name and ft_id is None:
                        return False, overview_trigger, raw_binary_mode
                    if ft_name in {"raw", "unknown", "bin", "binary", ""}:
                        return True, "idb_meta_filetype", raw_binary_mode
                    try:
                        ft_num = int(ft_id) if ft_id is not None else None
                    except Exception:
                        ft_num = None
                    if ft_num in {0, 17}:
                        return True, "idb_meta_filetype", raw_binary_mode
                    return False, overview_trigger, raw_binary_mode
                return False, overview_trigger, raw_binary_mode
            except Exception:
                return False, overview_trigger, raw_binary_mode

        def _workflow_binary_stats() -> dict:
            """Best-effort stats used to gate fragile workflow steps."""
            try:
                s = self._execute_tool("idb", {"action": "summary"})
                if isinstance(s, dict):
                    return {
                        "functions": int(s.get("functions", 0) or 0),
                        "imports": int(s.get("imports", 0) or 0),
                    }
            except Exception:
                pass
            return {"functions": 0, "imports": 0}
        if action == "audit_plan":
            calls_in = args.get("planned_calls")
            calls_raw: list = []
            source_desc = "provided"
            if isinstance(calls_in, list):
                calls_raw = calls_in
            else:
                compose_targets = _parse_str_list(args.get("workflow_actions"))
                if compose_targets:
                    compose_result = self._handle_workflow(
                        {
                            "action": "compose",
                            "workflow_actions": compose_targets,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(compose_result, dict) or compose_result.get("error"):
                        return compose_result
                    calls_raw = compose_result.get("planned_calls") if isinstance(compose_result.get("planned_calls"), list) else []
                    source_desc = "compose"
                else:
                    target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
                    if not target_action:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "audit_plan requires planned_calls, workflow_actions, or workflow_action",
                            hint="Example: workflow(action='audit_plan', workflow_action='recon_sweep')",
                        )
                    if target_action in {"plan", "explain", "estimate", "compose", "prioritize", "execute_plan", "audit_plan", "catalog"}:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "audit_plan target must be executable workflow",
                            hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                        )
                    plan_result = self._handle_workflow(
                        {
                            "action": "plan",
                            "workflow_action": target_action,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(plan_result, dict) or plan_result.get("error"):
                        return plan_result
                    calls_raw = plan_result.get("planned_calls") if isinstance(plan_result.get("planned_calls"), list) else []
                    source_desc = "plan"

            normalized_calls: list[dict] = []
            invalid_calls: list[int] = []
            missing_calls: list[str] = []
            duplicate_keys: dict[str, int] = {}
            risk_hints: list[str] = []
            tool_counts: dict[str, int] = {}
            seen_keys: set[tuple[str, str]] = set()
            for idx, call in enumerate(calls_raw):
                name, call_args, normalize_err = self._normalize_batch_call(call, idx)
                if normalize_err or not isinstance(name, str) or not name.strip() or not isinstance(call_args, dict):
                    invalid_calls.append(idx)
                    continue
                n = name.strip()
                a = str(call_args.get("action") or "").strip()
                if n not in TOOL_ACTIONS:
                    invalid_calls.append(idx)
                    missing_calls.append(f"{n}.{a}" if a else n)
                    continue
                if a and a not in {str(x).strip() for x in TOOL_ACTIONS.get(n, [])}:
                    invalid_calls.append(idx)
                    missing_calls.append(f"{n}.{a}")
                    continue
                key = (n, a)
                normalized_calls.append({"name": n, "arguments": call_args})
                tool_counts[n] = int(tool_counts.get(n, 0)) + 1
                key_str = f"{n}.{a}"
                if key in seen_keys:
                    duplicate_keys[key_str] = int(duplicate_keys.get(key_str, 1)) + 1
                else:
                    seen_keys.add(key)
                if n in {"threat_hunt", "deobfuscate", "search"} and a in {"malware", "vuln", "api_hashing", "vulnerable"}:
                    risk_hints.append(f"high-risk step present: {key_str}")

            warnings: list[str] = []
            if invalid_calls:
                warnings.append(f"invalid_call_entries={len(invalid_calls)} at indexes {invalid_calls[:10]}")
            if missing_calls:
                warnings.append(f"unknown_tool_or_action: {missing_calls[:10]}")
            if duplicate_keys:
                dup = ", ".join(f"{k}x{v}" for k, v in sorted(duplicate_keys.items())[:8])
                warnings.append(f"duplicate_steps_detected: {dup}")
            if len(normalized_calls) > 100:
                warnings.append("large_plan: more than 100 executable calls")
            if not normalized_calls:
                warnings.append("no_executable_calls")

            score = max(0, 100 - len(invalid_calls) * 10 - len(duplicate_keys) * 5 - max(0, len(normalized_calls) - 50))
            health = "good" if score >= 80 else ("fair" if score >= 60 else "poor")

            return {
                "ok": True,
                "action": "audit_plan",
                "dry_run": True,
                "source": source_desc,
                "audit": {
                    "health": health,
                    "score": score,
                    "raw_call_count": len(calls_raw),
                    "executable_call_count": len(normalized_calls),
                    "invalid_call_count": len(invalid_calls),
                    "duplicate_step_count": len(duplicate_keys),
                    "tool_counts": tool_counts,
                    "warnings": warnings,
                    "risk_hints": list(dict.fromkeys(risk_hints)),
                },
                "planned_calls": normalized_calls,
                "summary": {
                    "action": "audit_plan",
                    "health": health,
                    "score": score,
                    "source": source_desc,
                },
                "workflow_meta": {
                    "version": 1,
                    "action": "audit_plan",
                    "dry_run": True,
                    "source": source_desc,
                    "step_count": len(normalized_calls),
                },
            }
        elif action == "execute_plan":
            continue_on_error = _coerce_bool(args.get("continue_on_error"), True)
            max_steps = _bounded_int(args.get("max_steps", 50), 50, min_value=1, max_value=200)
            calls_in = args.get("planned_calls")
            calls_raw: list = []
            source_desc = "provided"
            if isinstance(calls_in, list):
                calls_raw = calls_in
            else:
                compose_targets = _parse_str_list(args.get("workflow_actions"))
                if compose_targets:
                    compose_result = self._handle_workflow(
                        {
                            "action": "compose",
                            "workflow_actions": compose_targets,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(compose_result, dict) or compose_result.get("error"):
                        return compose_result
                    calls_raw = compose_result.get("planned_calls") if isinstance(compose_result.get("planned_calls"), list) else []
                    source_desc = "compose"
                else:
                    target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
                    if not target_action:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "execute_plan requires planned_calls, workflow_actions, or workflow_action",
                            hint="Example: workflow(action='execute_plan', workflow_action='triage_fast', continue_on_error=true)",
                        )
                    if target_action in {"plan", "explain", "estimate", "compose", "prioritize", "execute_plan", "catalog"}:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "execute_plan target must be executable workflow",
                            hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                        )
                    plan_result = self._handle_workflow(
                        {
                            "action": "plan",
                            "workflow_action": target_action,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(plan_result, dict) or plan_result.get("error"):
                        return plan_result
                    calls_raw = plan_result.get("planned_calls") if isinstance(plan_result.get("planned_calls"), list) else []
                    source_desc = "plan"

            normalized_calls: list[dict] = []
            for idx, call in enumerate(calls_raw):
                name, call_args, normalize_err = self._normalize_batch_call(call, idx)
                if normalize_err or not isinstance(name, str) or not name.strip() or not isinstance(call_args, dict):
                    continue
                normalized_calls.append({"name": name.strip(), "arguments": call_args})

            requested_steps = len(normalized_calls)
            truncated = False
            if len(normalized_calls) > max_steps:
                normalized_calls = normalized_calls[:max_steps]
                truncated = True

            if not normalized_calls:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "No executable calls found in plan",
                    hint="Provide planned_calls with valid tool/action entries, or use workflow_action/workflow_actions.",
                )

            step_results: list[dict] = []
            calls_out: list[dict] = []
            completed = 0
            had_error = False
            blocked = False
            for idx, step in enumerate(normalized_calls):
                name = str(step.get("name") or "").strip()
                call_args = step.get("arguments") if isinstance(step.get("arguments"), dict) else {}
                if blocked:
                    step_results.append(
                        {
                            "index": idx,
                            "tool": name,
                            "args": call_args,
                            "outcome": "skipped",
                            "elapsed_ms": 0,
                            "recovery_hint": "Previous dependency-like step failed; rerun after fixing earlier error.",
                        }
                    )
                    continue
                t0 = time.time()
                try:
                    res = self._execute_tool(name, dict(call_args))
                except Exception as e:
                    res = {"error": True, "message": str(e)}
                elapsed_ms = int((time.time() - t0) * 1000)
                is_err = isinstance(res, dict) and bool(res.get("error"))
                calls_out.append({"name": name, "arguments": call_args, "result": res})
                step_results.append(
                    {
                        "index": idx,
                        "tool": name,
                        "args": call_args,
                        "outcome": "error" if is_err else "ok",
                        "elapsed_ms": elapsed_ms,
                        "recovery_hint": (
                            "Check address/args and retry this step manually."
                            if is_err
                            else ""
                        ),
                    }
                )
                if is_err:
                    had_error = True
                    # Conservative dependency gate for clearly chained operations.
                    if name in {"query", "batch"}:
                        blocked = True
                    if not continue_on_error:
                        break
                else:
                    completed += 1

            return {
                "ok": True,
                "action": "execute_plan",
                "source": source_desc,
                "calls": calls_out,
                "step_results": step_results,
                "summary": {
                    "requested_steps": requested_steps,
                    "executed_steps": len(step_results),
                    "completed_steps": completed,
                    "error_steps": len([s for s in step_results if s.get("outcome") == "error"]),
                    "skipped_steps": len([s for s in step_results if s.get("outcome") == "skipped"]),
                    "truncated": truncated,
                    "continue_on_error": continue_on_error,
                },
                "execution_meta": {
                    "action": "execute_plan",
                    "source": source_desc,
                    "requested_steps": requested_steps,
                    "executed_steps": len(step_results),
                    "truncated": truncated,
                    "continue_on_error": continue_on_error,
                },
            }
        elif action == "prioritize":
            mode = str(args.get("priority_mode") or "coverage").strip().lower()
            if mode not in {"original", "coverage", "risk_first"}:
                mode = "coverage"
            calls_in = args.get("planned_calls")
            calls: list[dict] = []
            source_desc = "provided"
            if isinstance(calls_in, list):
                calls = [c for c in calls_in if isinstance(c, dict)]
            else:
                compose_targets = _parse_str_list(args.get("workflow_actions"))
                if compose_targets:
                    compose_result = self._handle_workflow(
                        {
                            "action": "compose",
                            "workflow_actions": compose_targets,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(compose_result, dict) or compose_result.get("error"):
                        return compose_result
                    calls_raw = compose_result.get("planned_calls")
                    calls = [c for c in calls_raw if isinstance(c, dict)] if isinstance(calls_raw, list) else []
                    source_desc = "compose"
                else:
                    target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
                    if not target_action:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "prioritize requires planned_calls, workflow_actions, or workflow_action",
                            hint="Example: workflow(action='prioritize', workflow_action='recon_sweep', priority_mode='coverage')",
                        )
                    if target_action in {"plan", "explain", "estimate", "compose", "prioritize", "catalog"}:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "prioritize target must be executable workflow",
                            hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                        )
                    plan_result = self._handle_workflow(
                        {
                            "action": "plan",
                            "workflow_action": target_action,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(plan_result, dict) or plan_result.get("error"):
                        return plan_result
                    calls_raw = plan_result.get("planned_calls")
                    calls = [c for c in calls_raw if isinstance(c, dict)] if isinstance(calls_raw, list) else []
                    source_desc = "plan"

            def _priority_key(c: dict) -> tuple[int, int, str]:
                name = str(c.get("name") or "").strip().lower()
                action_name = str((c.get("arguments") or {}).get("action") or "").strip().lower() if isinstance(c.get("arguments"), dict) else ""
                call = f"{name}.{action_name}"
                source_count = int(c.get("source_count") or 1)
                if mode == "original":
                    return (0, 0, call)
                if mode == "risk_first":
                    risk_order = {
                        "threat_hunt.malware": 0,
                        "threat_hunt.vuln": 0,
                        "search.vulnerable": 1,
                        "deobfuscate.api_hashing": 1,
                        "crypto_id.identify": 2,
                        "protocol.detect": 2,
                    }
                    return (risk_order.get(call, 50), -source_count, call)
                # coverage
                return (-source_count, 0 if name in {"idb", "data"} else 1, call)

            prioritized = list(calls)
            if mode != "original":
                prioritized.sort(key=_priority_key)

            annotated = []
            for idx, c in enumerate(prioritized):
                out = dict(c)
                out["priority_index"] = idx
                out["priority_mode"] = mode
                annotated.append(out)

            return {
                "ok": True,
                "action": "prioritize",
                "dry_run": True,
                "priority_mode": mode,
                "source": source_desc,
                "planned_calls": annotated,
                "summary": {
                    "action": "prioritize",
                    "priority_mode": mode,
                    "step_count": len(annotated),
                    "source": source_desc,
                },
                "workflow_meta": {
                    "version": 1,
                    "action": "prioritize",
                    "dry_run": True,
                    "priority_mode": mode,
                    "source": source_desc,
                    "step_count": len(annotated),
                },
            }
        elif action == "compose":
            raw_actions = _parse_str_list(args.get("workflow_actions"))
            if not raw_actions:
                single = str(args.get("workflow_action") or args.get("target_action") or "").strip()
                if single:
                    raw_actions = [single]
            target_actions = [str(a).strip().lower() for a in raw_actions if str(a).strip()]
            target_actions = list(dict.fromkeys(target_actions))
            if not target_actions:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "compose requires workflow_actions",
                    hint="Example: workflow(action='compose', workflow_actions=['triage_fast','vuln_audit'])",
                )
            if any(a in {"plan", "explain", "estimate", "compose", "catalog"} for a in target_actions):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "compose targets must be executable workflows only",
                    hint="Use workflow_actions from: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                )

            merged_calls: list[dict] = []
            seen_keys: set[tuple[str, str]] = set()
            source_map: dict[tuple[str, str], list[str]] = {}
            composed_meta: list[dict] = []

            for target_action in target_actions:
                plan_args = dict(args)
                plan_args["action"] = "plan"
                plan_args["workflow_action"] = target_action
                if not addr:
                    plan_args.pop("addr", None)
                plan_result = self._handle_workflow(plan_args)
                if not isinstance(plan_result, dict) or plan_result.get("error"):
                    return plan_result
                calls = plan_result.get("planned_calls")
                if not isinstance(calls, list):
                    calls = []
                meta = plan_result.get("workflow_meta") if isinstance(plan_result.get("workflow_meta"), dict) else {}
                composed_meta.append(
                    {
                        "action": target_action,
                        "step_count": len(calls),
                        "firmware_detected": bool(meta.get("firmware_detected", False)),
                        "plan_diagnostics": list(meta.get("plan_diagnostics", [])) if isinstance(meta.get("plan_diagnostics"), list) else [],
                    }
                )
                for call in calls:
                    if not isinstance(call, dict):
                        continue
                    name = str(call.get("name") or "").strip()
                    args_obj = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
                    action_name = str((args_obj or {}).get("action") or "").strip()
                    key = (name, action_name)
                    source_map.setdefault(key, [])
                    if target_action not in source_map[key]:
                        source_map[key].append(target_action)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    merged_calls.append(call)

            annotated_calls = []
            for idx, call in enumerate(merged_calls):
                if not isinstance(call, dict):
                    continue
                name = str(call.get("name") or "").strip()
                args_obj = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
                action_name = str((args_obj or {}).get("action") or "").strip()
                key = (name, action_name)
                sources = source_map.get(key, [])
                out_call = dict(call)
                out_call["sources"] = sources
                out_call["source_count"] = len(sources)
                out_call["index"] = idx
                annotated_calls.append(out_call)

            return {
                "ok": True,
                "action": "compose",
                "requested_action": "compose",
                "planned_actions": target_actions,
                "dry_run": True,
                "dedup_enabled": True,
                "planned_calls": annotated_calls,
                "summary": {
                    "action": "compose",
                    "planned_actions": target_actions,
                    "step_count": len(annotated_calls),
                    "source_workflows": len(target_actions),
                },
                "workflow_meta": {
                    "version": 1,
                    "action": "compose",
                    "dry_run": True,
                    "composed_actions": target_actions,
                    "component_workflows": composed_meta,
                    "step_count": len(annotated_calls),
                },
            }
        elif action == "estimate":
            target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
            if not target_action:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "estimate requires workflow_action",
                    hint="Example: workflow(action='estimate', workflow_action='recon_sweep', profile='balanced')",
                )
            if target_action in {"plan", "explain", "estimate"}:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "estimate cannot target plan/explain/estimate",
                    hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                )
            plan_args = dict(args)
            plan_args["action"] = "plan"
            plan_args["workflow_action"] = target_action
            plan_result = self._handle_workflow(plan_args)
            if not isinstance(plan_result, dict) or plan_result.get("error"):
                return plan_result
            calls = plan_result.get("planned_calls")
            if not isinstance(calls, list):
                calls = []

            tool_categories = {
                "idb": "orientation",
                "data": "discovery",
                "string_ops": "ioc_hunt",
                "threat_hunt": "threat_hunt",
                "deobfuscate": "deobfuscation",
                "crypto_id": "crypto",
                "yara_hunt": "signature_hunt",
                "gadgets": "exploit_surface",
                "search": "search",
                "protocol": "protocol",
                "summarize": "summary",
                "firmware_view": "firmware",
                "llm_helpers": "guidance",
                "code": "code",
                "xref_analysis": "graph",
                "compare": "diff",
            }
            category_counts: dict[str, int] = {}
            unique_tools = set()
            for c in calls:
                if not isinstance(c, dict):
                    continue
                name = str(c.get("name") or "").strip()
                if not name:
                    continue
                unique_tools.add(name)
                cat = tool_categories.get(name, "other")
                category_counts[cat] = int(category_counts.get(cat, 0)) + 1

            meta = plan_result.get("workflow_meta") if isinstance(plan_result.get("workflow_meta"), dict) else {}
            firmware_detected = bool(meta.get("firmware_detected", False))
            step_count = len(calls)
            complexity = "low" if step_count <= 4 else ("medium" if step_count <= 7 else "high")
            risk_score = 0
            plan_text = " ".join(
                f"{str(c.get('name') or '').strip()}.{str((c.get('arguments') or {}).get('action') or '').strip()}"
                for c in calls
                if isinstance(c, dict)
            ).strip()
            if EMBEDDING_FIRST_MODE and plan_text:
                try:
                    from .intelligence import BgeCodeEmbedder
                    embedder = BgeCodeEmbedder()
                    qv = embedder.embed(plan_text)
                    anchors = [
                        "low risk orientation metadata summary listing imports",
                        "medium risk protocol and threat triage suspicious indicators",
                        "high risk exploit vulnerability deobfuscation patch and malware deep analysis",
                    ]
                    sims = [float(embedder.cosine(qv, embedder.embed(a))) for a in anchors]
                    if sims:
                        risk_score = int(round(max(0.0, min(1.0, max(sims))) * 100.0))
                except Exception:
                    risk_score = 0
            if risk_score <= 0:
                # Deterministic fallback by plan breadth only (no heuristic keyword weights).
                risk_score = int(round(min(100.0, (float(step_count) / 12.0) * 100.0)))
            if firmware_detected:
                risk_score = min(100, risk_score + 6)

            return {
                "ok": True,
                "action": "estimate",
                "requested_action": "estimate",
                "planned_action": target_action,
                "dry_run": True,
                "estimate": {
                    "complexity": complexity,
                    "risk_score": risk_score,
                    "step_count": step_count,
                    "unique_tool_count": len(unique_tools),
                    "firmware_detected": firmware_detected,
                    "category_counts": category_counts,
                },
                "planned_calls": calls,
                "workflow_meta": meta,
                "summary": {
                    "action": "estimate",
                    "workflow_action": target_action,
                    "complexity": complexity,
                    "risk_score": risk_score,
                },
            }
        elif action == "explain":
            target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
            if not target_action:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "explain requires workflow_action",
                    hint="Example: workflow(action='explain', workflow_action='triage_fast', profile='balanced')",
                )
            if target_action in {"plan", "explain"}:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "explain cannot target plan/explain",
                    hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                )
            plan_args = dict(args)
            plan_args["action"] = "plan"
            plan_args["workflow_action"] = target_action
            plan_result = self._handle_workflow(plan_args)
            if not isinstance(plan_result, dict) or plan_result.get("error"):
                return plan_result
            calls = plan_result.get("planned_calls")
            if not isinstance(calls, list):
                calls = []

            rationale_by_call = {
                "idb.overview": "Establishes binary orientation and high-signal context before deep tooling.",
                "idb.meta": "Captures format/arch/base metadata used by downstream interpretation.",
                "data.functions": "Builds a function inventory for navigation and prioritization.",
                "data.imports": "Highlights external capability surface and potential behavior anchors.",
                "string_ops.find_urls": "Extracts direct network indicators for quick IOC triage.",
                "threat_hunt.quick": "Runs a fast heuristic pass to surface high-priority suspicious regions.",
                "string_ops.find_c2": "Targets command-and-control indicators in strings and references.",
                "deobfuscate.stack_strings": "Recovers runtime-built strings hidden from static string tables.",
                "deobfuscate.api_hashing": "Flags and resolves hashed API dispatch patterns common in malware.",
                "crypto_id.identify": "Identifies cryptographic primitives and likely key-handling hotspots.",
                "yara_hunt.list_rules": "Enumerates available rules to align hunts with known families.",
                "threat_hunt.malware": "Performs malware-focused threat hunting profile.",
                "gadgets.rop": "Maps exploit-relevant gadget surface for memory corruption risk analysis.",
                "search.vulnerable": "Finds dangerous API/use patterns tied to common vulnerability classes.",
                "protocol.detect": "Locates protocol parsers/handlers and potential attack boundaries.",
                "threat_hunt.vuln": "Performs vulnerability-focused threat hunting profile.",
                "search.structured": "Uses schema-guided retrieval to find semantically constrained candidates.",
                "summarize.security_posture": "Produces consolidated risk and mitigation posture snapshot.",
                "firmware_view.triage_snapshot": "Aggregates load/vector/MMIO hints for firmware-first orientation.",
                "llm_helpers.guided_analysis": "Provides stepwise guidance for deeper targeted follow-up.",
                "code.disasm": "Gets opcode-level view at target address for patch semantics.",
                "code.xrefs_to": "Shows inbound dependency impact into the patch location.",
                "code.xrefs_from": "Shows outbound behavior impact from patched block.",
                "xref_analysis.dependency_graph": "Summarizes near-neighbor call/data dependencies around patch.",
                "compare.functions": "Captures structural/functional differences for regression risk review.",
            }
            explained_steps = []
            for idx, call in enumerate(calls):
                if not isinstance(call, dict):
                    continue
                name = str(call.get("name") or "").strip()
                args_obj = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
                action_name = str((args_obj or {}).get("action") or "").strip()
                key = f"{name}.{action_name}"
                explained_steps.append(
                    {
                        "index": idx,
                        "tool": name,
                        "action": action_name,
                        "call": key,
                        "rationale": rationale_by_call.get(
                            key,
                            "Included by workflow profile as a high-value analysis step.",
                        ),
                    }
                )

            return {
                "ok": True,
                "action": "explain",
                "requested_action": "explain",
                "planned_action": target_action,
                "dry_run": True,
                "planned_calls": calls,
                "explained_steps": explained_steps,
                "summary": {
                    "action": "explain",
                    "workflow_action": target_action,
                    "step_count": len(explained_steps),
                },
                "workflow_meta": plan_result.get("workflow_meta", {}),
            }
        elif action == "plan":
            target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
            if not target_action:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "plan requires workflow_action",
                    hint="Example: workflow(action='plan', workflow_action='recon_sweep', profile='deep')",
                )
            if target_action == "plan":
                return make_error(
                    MCPError.INVALID_ARGS,
                    "plan cannot target plan",
                    hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                )
            plan_args = dict(args)
            plan_args["action"] = target_action
            plan_args["dry_run"] = True
            plan_result = self._handle_workflow(plan_args)
            if isinstance(plan_result, dict):
                plan_result.setdefault("requested_action", "plan")
                plan_result.setdefault("planned_action", target_action)
            return plan_result
        elif action == "catalog":
            catalog = {
                "triage_fast": {
                    "description": "Fast binary orientation + IOC/threat quick pass; firmware-aware auto-injection.",
                    "requires_addr": False,
                    "firmware_aware": True,
                    "default_profile": "balanced",
                    "supports_filters": True,
                    "supports_dry_run": True,
                },
                "malware_deep": {
                    "description": "Deeper malware-oriented hunting with deobfuscation and crypto triage.",
                    "requires_addr": False,
                    "firmware_aware": False,
                    "default_profile": "balanced",
                    "supports_filters": True,
                    "supports_dry_run": True,
                },
                "vuln_audit": {
                    "description": "Vulnerability-focused audit: gadgets, dangerous patterns, protocol surface.",
                    "requires_addr": False,
                    "firmware_aware": False,
                    "default_profile": "balanced",
                    "supports_filters": True,
                    "supports_dry_run": True,
                },
                "recon_sweep": {
                    "description": "Broad recon pass combining orientation, structured retrieval, protocol, and security posture.",
                    "requires_addr": False,
                    "firmware_aware": True,
                    "default_profile": "balanced",
                    "supports_filters": True,
                    "supports_dry_run": True,
                },
                "patch_review": {
                    "description": "Patch-impact review focused on one address and its xref/dependency neighborhood.",
                    "requires_addr": True,
                    "firmware_aware": False,
                    "default_profile": "balanced",
                    "supports_filters": True,
                    "supports_dry_run": True,
                },
            }
            return {
                "ok": True,
                "action": "catalog",
                "workflow_catalog": catalog,
                "supports_plan_action": True,
                "supports_explain_action": True,
                "supports_estimate_action": True,
                "supports_compose_action": True,
                "supports_prioritize_action": True,
                "supports_execute_plan_action": True,
                "supports_audit_plan_action": True,
                "supported_profiles": ["quick", "balanced", "deep"],
                "supported_filters": ["include_tools", "exclude_tools"],
                "supports_dry_run": True,
            }
        elif action == "triage_fast":
            firmware_detected, firmware_detected_trigger, raw_binary_mode = _detect_firmware_mode()
            wf_stats = _workflow_binary_stats()
            has_functions = int(wf_stats.get("functions", 0)) > 0

            step_plan = [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"name": "idb", "arguments": {"action": "meta"}},
                {"name": "data", "arguments": {"action": "functions", "count": limit}},
                {"name": "data", "arguments": {"action": "imports", "count": limit}},
                {"name": "search", "arguments": {"action": "nl" if has_functions else "find", "query": "entrypoint parser auth decode crypto", "limit": limit}},
                {"name": "string_ops", "arguments": {"action": "find_urls", "limit": limit}},
                {
                    "name": "threat_hunt",
                    "arguments": {
                        "action": "run",
                        "limit": limit,
                        "profile": profile,
                        "include_vuln": True,
                        "include_malware": True,
                        "include_tracing": True,
                    },
                },
                {"name": "blackboard", "arguments": {"action": "frontier", "limit": min(limit, 10)}},
            ]
            if firmware_detected or raw_binary_mode:
                step_plan.insert(2, {"name": "firmware_view", "arguments": {"action": "triage_snapshot"}})
                step_plan.append({"name": "llm_helpers", "arguments": {"action": "guided_analysis"}})
            workflow_meta["firmware_mode"] = "enabled" if (firmware_detected or raw_binary_mode) else "disabled"
            workflow_meta["firmware_detected"] = firmware_detected
            workflow_meta["raw_binary_mode"] = raw_binary_mode
            workflow_meta["trigger"] = firmware_detected_trigger
            workflow_meta["has_functions"] = has_functions
        elif action == "malware_deep":
            step_plan = [
                {"name": "string_ops", "arguments": {"action": "find_c2", "limit": limit}},
                {"name": "search", "arguments": {"action": "nl", "query": "beacon c2 command parser persistence injection", "limit": limit}},
                {"name": "deobfuscate", "arguments": {"action": "stack_strings", "limit": limit}},
                {"name": "deobfuscate", "arguments": {"action": "api_hashing", "limit": limit}},
                {"name": "crypto_id", "arguments": {"action": "identify", "limit": limit}},
                {"name": "yara_hunt", "arguments": {"action": "list_rules"}},
                {"name": "threat_hunt", "arguments": {"action": "malware", "limit": limit, "profile": profile}},
            ]
        elif action == "vuln_audit":
            step_plan = [
                {"name": "gadgets", "arguments": {"action": "rop", "limit": limit}},
                {"name": "search", "arguments": {"action": "nl", "query": "input validation memcpy strcpy length check auth bypass", "limit": limit}},
                {"name": "search", "arguments": {"action": "vulnerable", "limit": limit}},
                {"name": "protocol", "arguments": {"action": "detect", "limit": limit}},
                {"name": "threat_hunt", "arguments": {"action": "vuln", "limit": limit, "profile": profile}},
            ]
        elif action == "recon_sweep":
            firmware_detected, firmware_detected_trigger, raw_binary_mode = _detect_firmware_mode()
            wf_stats = _workflow_binary_stats()
            has_functions = int(wf_stats.get("functions", 0)) > 0

            step_plan = [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"name": "idb", "arguments": {"action": "meta"}},
                {"name": "data", "arguments": {"action": "functions", "count": limit}},
                {"name": "search", "arguments": {"action": "nl" if has_functions else "find", "query": "dispatcher parser crypto network auth", "limit": limit}},
                {"name": "search", "arguments": {"action": "structured", "limit": limit}},
                {"name": "blackboard", "arguments": {"action": "frontier", "limit": min(limit, 10)}},
                {"name": "protocol", "arguments": {"action": "detect", "limit": limit}},
                {"name": "summarize", "arguments": {"action": "security_posture", "max_items": limit}},
                {
                    "name": "threat_hunt",
                    "arguments": {
                        "action": "run",
                        "limit": limit,
                        "profile": profile,
                        "include_vuln": True,
                        "include_malware": True,
                        "include_tracing": True,
                    },
                },
            ]
            if firmware_detected or raw_binary_mode:
                step_plan.insert(2, {"name": "firmware_view", "arguments": {"action": "triage_snapshot"}})
                step_plan.append({"name": "llm_helpers", "arguments": {"action": "guided_analysis"}})
            workflow_meta["firmware_mode"] = "enabled" if (firmware_detected or raw_binary_mode) else "disabled"
            workflow_meta["firmware_detected"] = firmware_detected
            workflow_meta["raw_binary_mode"] = raw_binary_mode
            workflow_meta["trigger"] = firmware_detected_trigger
            workflow_meta["has_functions"] = has_functions
        elif action == "patch_review":
            if not addr:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "patch_review requires addr",
                    hint="Provide workflow(action='patch_review', addr='0x401000')",
                )
            step_plan = [
                {"name": "code", "arguments": {"action": "disasm", "addr": addr}},
                {"name": "code", "arguments": {"action": "xrefs_to", "addr": addr, "limit": limit}},
                {"name": "code", "arguments": {"action": "xrefs_from", "addr": addr, "limit": limit}},
                {"name": "xref_analysis", "arguments": {"action": "dependency_graph", "addr": addr, "depth": 1, "limit": limit}},
                {"name": "compare", "arguments": {"action": "functions", "addr": addr, "addr2": addr}},
            ]
        else:
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported workflow action: '{action}'",
                hint="Valid workflow actions: audit_plan, execute_plan, prioritize, compose, estimate, explain, plan, catalog, triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
            )

        available_tools = sorted(
            {
                str(step.get("name") or "").strip().lower()
                for step in step_plan
                if str(step.get("name") or "").strip()
            }
        )
        unknown_include_tools = [t for t in include_tools if t not in set(available_tools)]
        unknown_exclude_tools = [t for t in exclude_tools if t not in set(available_tools)]
        conflicting_tools = [t for t in include_tools if t in set(exclude_tools)]

        if include_tools:
            step_plan = [
                step
                for step in step_plan
                if str(step.get("name") or "").strip().lower() in set(include_tools)
            ]
        if exclude_tools:
            step_plan = [
                step
                for step in step_plan
                if str(step.get("name") or "").strip().lower() not in set(exclude_tools)
            ]

        # Capability gating: prune unavailable tool/actions so workflows degrade gracefully.
        unavailable_steps: list[str] = []
        gated_plan: list[dict] = []
        for step in step_plan:
            tool_name = str(step.get("name") or "").strip().lower()
            action_name = str((step.get("arguments") or {}).get("action") or "").strip().lower()
            if tool_name not in TOOL_ACTIONS:
                unavailable_steps.append(f"{tool_name}.{action_name or '*'} (tool unavailable)")
                continue
            if action_name and action_name not in {str(a).strip().lower() for a in TOOL_ACTIONS.get(tool_name, [])}:
                unavailable_steps.append(f"{tool_name}.{action_name} (action unavailable)")
                continue
            gated_plan.append(step)
        step_plan = gated_plan

        workflow_meta["dry_run"] = dry_run
        workflow_meta["available_tools"] = available_tools
        workflow_meta["include_tools"] = include_tools
        workflow_meta["exclude_tools"] = exclude_tools
        workflow_meta["unknown_include_tools"] = unknown_include_tools
        workflow_meta["unknown_exclude_tools"] = unknown_exclude_tools
        workflow_meta["conflicting_tools"] = conflicting_tools
        workflow_meta["step_count"] = len(step_plan)
        workflow_meta["step_tools"] = [str(step.get("name") or "") for step in step_plan]
        workflow_meta["step_actions"] = [
            f"{str(step.get('name') or '')}.{str((step.get('arguments') or {}).get('action') or '')}"
            for step in step_plan
        ]
        workflow_meta["step_calls"] = [
            {
                "tool": str(step.get("name") or ""),
                "action": str((step.get("arguments") or {}).get("action") or ""),
            }
            for step in step_plan
        ]
        plan_diagnostics: list[str] = []
        if unknown_include_tools:
            plan_diagnostics.append(f"include_tools not in this workflow plan: {', '.join(unknown_include_tools)}")
        if unknown_exclude_tools:
            plan_diagnostics.append(f"exclude_tools not in this workflow plan: {', '.join(unknown_exclude_tools)}")
        if conflicting_tools:
            plan_diagnostics.append(
                f"tools listed in both include_tools and exclude_tools: {', '.join(conflicting_tools)}"
            )
        if unavailable_steps:
            plan_diagnostics.append(
                f"pruned unavailable workflow steps: {', '.join(unavailable_steps[:12])}"
            )
        if not step_plan:
            plan_diagnostics.append("No workflow steps remain after filtering.")
        workflow_meta["plan_diagnostics"] = plan_diagnostics

        if dry_run:
            return {
                "ok": True,
                "dry_run": True,
                "planned_calls": step_plan,
                "summary": {
                    "action": action,
                    "profile": profile,
                    "step_count": len(step_plan),
                    "dry_run": True,
                    "plan_diagnostics": plan_diagnostics,
                },
                "workflow_meta": workflow_meta,
            }

        if not step_plan:
            return make_error(
                MCPError.INVALID_ARGS,
                "Workflow plan is empty after include/exclude filtering",
                hint="Adjust include_tools/exclude_tools, or use dry_run=true to preview plan changes.",
            )

        batch_result = self._handle_batch({"calls": step_plan, "continue_on_error": True})
        if isinstance(batch_result, dict):
            batch_result.setdefault("workflow_meta", workflow_meta)
            if isinstance(batch_result.get("summary"), dict):
                batch_result["summary"].setdefault("workflow_meta", workflow_meta)
        return batch_result

    def _handle_batch(self, args):
        calls = args.get("calls", [])
        if not isinstance(calls, list):
            return make_error(
                MCPError.INVALID_ARGS,
                "calls must be a list of call objects or 'tool:action' strings",
            )
        if not calls:
            return make_error(
                MCPError.BATCH_EMPTY,
                "No calls provided in batch",
                hint="Provide at least one call: batch(calls=[{name: 'tool', arguments: {...}}])",
            )
        if len(calls) > MAX_BATCH_CALLS:
            return make_error(
                MCPError.BATCH_TOO_LARGE,
                f"Too many batch calls ({len(calls)}, max {MAX_BATCH_CALLS})",
                hint=f"Split into multiple batch requests of {MAX_BATCH_CALLS} or fewer calls.",
            )

        try:
            payload_size = len(json.dumps(calls, separators=(",", ":")))
        except Exception:
            payload_size = MAX_BATCH_PAYLOAD_BYTES + 1
        if payload_size > MAX_BATCH_PAYLOAD_BYTES:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Batch payload too large ({payload_size} bytes, max {MAX_BATCH_PAYLOAD_BYTES})",
            )

        continue_on_error = bool(args.get("continue_on_error", False))
        results = []
        for idx, call in enumerate(calls):
            name, call_args, normalize_err = self._normalize_batch_call(call, idx)
            if normalize_err:
                res = normalize_err
            resolved_name = _resolve_tool_alias(name)

            if normalize_err:
                results.append({"index": idx, "name": name, "result": res})
                if res.get("error") and not continue_on_error:
                    break
                continue
            elif not name:
                res = make_error(
                    MCPError.INVALID_ARGS,
                    f"Call at index {idx} missing name field",
                    hint="Each batch call must have a name field specifying the tool.",
                )
            elif not isinstance(name, str):
                res = make_error(
                    MCPError.INVALID_ARGS, f"Call at index {idx} has non-string name"
                )
            elif resolved_name == "batch":
                res = make_error(
                    MCPError.INVALID_ARGS, "Nested batch calls are not allowed"
                )
            elif resolved_name not in TOOLS:
                res = make_error(
                    MCPError.INVALID_ARGS,
                    f"Unknown tool {name} in batch call at index {idx}",
                    hint=f"Valid tools include: {', '.join(TOOLS[:10])}... Use tools/list for full list.",
                )
            elif call_args is None:
                call_args = {}
                res = self._execute_tool(name, call_args)
            elif not isinstance(call_args, dict):
                res = make_error(
                    MCPError.INVALID_ARGS,
                    f"Call at index {idx} has non-object arguments",
                )
            else:
                cleaned_args, _ = self._extract_response_options(call_args)
                res = self._execute_tool(name, cleaned_args)
                if isinstance(cleaned_args, dict):
                    res = self._cache_next_page(
                        resolved_name or name, cleaned_args, res
                    )
                    self._record_activity(resolved_name or name, cleaned_args, res)
            results.append({"index": idx, "name": name, "result": res})
            if res.get("error") and not continue_on_error:
                break
        errors = sum(
            1
            for item in results
            if isinstance(item.get("result"), dict) and item["result"].get("error")
        )
        return {
            "ok": True,
            "results": results,
            "count": len(results),
            "summary": {
                "total": len(results),
                "ok": len(results) - errors,
                "errors": errors,
                "stopped_on_error": bool(
                    errors and not continue_on_error and len(results) < len(calls)
                ),
            },
        }

    def _build_tools_list_catalog(self, mode: str) -> list[dict]:
        cache_key = (mode,)
        cached = self._tools_list_cache.get(cache_key)
        if cached and cached[0] == cache_key:
            return cached[1]

        def _tool_description(tool_name: str, tool_mode: str) -> str:
            if tool_mode == "full":
                desc = TOOL_DESCRIPTIONS.get(tool_name, "")
            elif tool_mode == "lean":
                desc = build_tool_description_lean(tool_name)
            else:
                desc = build_tool_description_ultra(tool_name)
            desc_text = str(desc or "").strip()
            if desc_text:
                return desc_text
            fallback = (
                desc if tool_mode == "full" else TOOL_DESCRIPTIONS.get(tool_name, "")
            )
            fallback_text = str(fallback or "").strip()
            if fallback_text:
                return fallback_text
            return f"Use wiki(topic='tools/{tool_name}') for usage."

        catalog: list[dict] = []
        for t in TOOLS:
            if t in HIDDEN_TOOLS_IN_LIST:
                continue
            if mode == "full":
                schema = build_input_schema(t)
            elif mode == "lean":
                schema = build_input_schema_lean(t)
            else:
                schema = build_input_schema_ultra(t)
            schema = dict(schema) if isinstance(schema, dict) else {}

            if getattr(self, "vertex_compat", False):
                schema = sanitize_schema_for_vertex(schema)

            schema.setdefault("type", "object")

            if not getattr(self, "vertex_compat", False):
                schema.setdefault("properties", {})
                schema.setdefault("required", [])

            catalog.append(
                {
                    "name": t,
                    "description": _tool_description(t, mode),
                    "inputSchema": schema,
                    "category": classify_tool_category(t),
                }
            )

        self._tools_list_cache[cache_key] = (cache_key, catalog)
        return catalog

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
                    req = json.loads(line.decode("utf-8"))
                    resp = self.handle_request(req)
                    if resp:
                        output = (
                            json.dumps(resp, ensure_ascii=False, separators=(",", ":"))
                            + "\n"
                        ).encode("utf-8")
                        rs.write(output)
                        rs.flush()
                except Exception:
                    if self._shutdown_requested:
                        break
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
