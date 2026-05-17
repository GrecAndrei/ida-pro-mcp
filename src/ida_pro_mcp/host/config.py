#!/usr/bin/env python3
"""
Host configuration: runtime directories, environment parsing, logging.
"""
import os
import sys
import tempfile
import shutil
import uuid
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union


def _default_runtime_dir() -> str:
    if sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return os.path.realpath(os.path.join(root, "ida-pro-mcp"))
    if sys.platform == "darwin":
        return os.path.realpath(
            os.path.join(
                str(Path.home()), "Library", "Application Support", "ida-pro-mcp"
            )
        )
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        return os.path.realpath(os.path.join(xdg_state, "ida-pro-mcp"))
    return os.path.realpath(
        os.path.join(str(Path.home()), ".local", "state", "ida-pro-mcp")
    )


def _resolve_runtime_dir() -> str:
    explicit = os.environ.get("IDA_MCP_CACHE_DIR") or os.environ.get("IDA_MCP_DATA_DIR")
    if explicit:
        return os.path.realpath(os.path.expanduser(explicit))
    return _default_runtime_dir()


def _is_writable_dir(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, f".ida_mcp_probe_{uuid.uuid4().hex}")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        return True
    except Exception:
        return False


def _select_runtime_dir(preferred: str) -> str:
    candidates: List[str] = []
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        preferred,
        _default_runtime_dir(),
        os.path.join(tempfile.gettempdir(), "ida-pro-mcp"),
        os.path.join(script_dir, "ida_mcp_cache"),
    ):
        candidate = os.path.realpath(os.path.expanduser(candidate))
        if candidate not in candidates:
            candidates.append(candidate)
    for candidate in candidates:
        if _is_writable_dir(candidate):
            return candidate
    return os.path.realpath(os.path.join(script_dir, "ida_mcp_cache"))


def _migrate_legacy_runtime_dir(target_dir: str):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    legacy_dir = os.path.join(script_dir, "ida_mcp_cache")
    if not os.path.isdir(legacy_dir):
        return
    if os.path.realpath(legacy_dir) == os.path.realpath(target_dir):
        return
    try:
        os.makedirs(target_dir, exist_ok=True)
    except Exception:
        return
    try:
        for name in os.listdir(legacy_dir):
            src = os.path.join(legacy_dir, name)
            dst = os.path.join(target_dir, name)
            if os.path.exists(dst):
                continue
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)
    except Exception:
        pass


# Resolve cache directory
CACHE_DIR = _select_runtime_dir(_resolve_runtime_dir())
_migrate_legacy_runtime_dir(CACHE_DIR)
os.makedirs(CACHE_DIR, exist_ok=True)
BRIDGE_LOG = os.path.join(CACHE_DIR, "bridge.log")

# Runtime lease configuration
RUNTIME_LEASE_TTL = max(15, int(os.environ.get("IDA_MCP_RUNTIME_LEASE_TTL", "75")))
_DEFAULT_RUNTIME_LEASE_HEARTBEAT_SECONDS = max(2, RUNTIME_LEASE_TTL // 3)
RUNTIME_LEASE_HEARTBEAT_SECONDS = max(
    2,
    int(
        os.environ.get(
            "IDA_MCP_RUNTIME_LEASE_HEARTBEAT",
            str(_DEFAULT_RUNTIME_LEASE_HEARTBEAT_SECONDS),
        )
    ),
)
PROCESS_TERMINATION_TIMEOUT_SECONDS = max(
    1.0, float(os.environ.get("IDA_MCP_PROCESS_TERMINATION_TIMEOUT", "2.0"))
)
_RUNTIME_LEASE_RE = re.compile(r"^SID_([A-Za-z0-9]{8})\.lease\.json$")

# Semantic index configuration
SEMANTIC_INDEX_VERSION = 1
SEMANTIC_INDEX_DB_NAME = f"semantic_asm_index_v{SEMANTIC_INDEX_VERSION}.sqlite3"
SEMANTIC_INDEX_MAX_WORKERS = max(
    1, int(os.environ.get("IDA_MCP_SEMANTIC_INDEX_WORKERS", "2"))
)
SEMANTIC_INDEX_WAIT_SECONDS = max(
    0.0, float(os.environ.get("IDA_MCP_SEMANTIC_INDEX_WAIT_SECONDS", "3.0"))
)
SEMANTIC_GADGET_SOURCE_ACTIONS = (
    "rop",
    "jop",
    "cop",
    "syscall",
    "write_what_where",
    "stack_pivot",
)
SEMANTIC_INDEX_SOURCE_LIMIT = max(
    50, int(os.environ.get("IDA_MCP_SEMANTIC_INDEX_SOURCE_LIMIT", "3000"))
)
SEMANTIC_SCORE_SUBSTRING_MATCH = 48
SEMANTIC_SCORE_PATTERN_MATCH = 120
SEMANTIC_SCORE_PER_TOKEN = 12
SEMANTIC_INDEX_MAX_QUERY_WORKERS = 8

# Session / operation limits
MAX_BATCH_CALLS = 50
MAX_BATCH_PAYLOAD_BYTES = 512 * 1024

# Rate limiting defaults
RATE_LIMIT_PER_TOOL = float(os.environ.get("IDA_MCP_RATE_LIMIT_PER_TOOL", "10.0"))
RATE_LIMIT_GLOBAL = float(os.environ.get("IDA_MCP_RATE_LIMIT_GLOBAL", "30.0"))
RATE_LIMIT_BURST = int(os.environ.get("IDA_MCP_RATE_LIMIT_BURST", "20"))

MAX_LIST_LIMIT = 200
MAX_LIST_OFFSET = 100_000
MAX_TAGS_PER_SESSION = 64
MAX_TAG_LEN = 64
MAX_NOTE_LEN = 16_384
MAX_NAME_LEN = 256
SESSION_ID_RE = re.compile(r"^[A-Z0-9]{8}$")
MAX_SESSION_ID_RETRIES = 1024
MAX_SNAPSHOT_ID_RETRIES = 128
MAX_SNAPSHOTS_PER_SESSION = 50
MAX_WIKI_RESULTS = 200

# Context density optimizer defaults
CONTEXT_DENSITY_DEFAULT_BUDGET = 30000
CONTEXT_DENSITY_COMPACT_THRESHOLD = 10240  # bytes
CONTEXT_DENSITY_MAX_CODE_PREVIEW = 5
CONTEXT_DENSITY_MAX_HEX_PREVIEW = 3
CONTEXT_DENSITY_MAX_XREF_ITEMS = 20

_POINTER_NOTE_SIGNAL_TOOLS_STRONG = {"calc", "memory"}
_POINTER_NOTE_SIGNAL_TOOLS_HINT = {"data", "code", "nav", "search", "debug", "batch"}
_POINTER_NOTE_HEX_RE = re.compile(r"0x[0-9a-fA-F]{3,}")
_POINTER_NOTE_MATH_RE = re.compile(
    r"0x[0-9a-fA-F]{3,}\s*(?:\+|\-|\*|/|<<|>>)\s*(?:0x[0-9a-fA-F]{1,}|[0-9]+)"
)
_POINTER_NOTE_SIGNAL_KEYWORDS = (
    "addr",
    "address",
    "ea",
    "offset",
    "base",
    "ptr",
    "pointer",
    "deref",
    "index",
    "stride",
    "chain",
)
_POINTER_NOTE_SIGNAL_MAX_DEPTH = 2
_POINTER_NOTE_SIGNAL_MAX_LIST_ITEMS = 8
_POINTER_NOTE_SIGNAL_MAX_DICT_ITEMS = 12
_POINTER_NOTE_MAX_SIGNAL_MULTIPLIER = 2.0
LLM_POINTER_SAFETY_NOTE = "DO NOT CALCULATE POINTERS OR ADDRESSES MENTALLY; ALWAYS USE THE CALC/MEMORY TOOL FOR ADDRESS MATH OR POINTER CHAINING."

_COMPACT_DROP = object()
_COMPACT_META_KEYS = {
    "traceback",
    "raw_bytes",
    "hexdump_full",
    "raw_request",
    "raw_response",
    "debug_log",
}
_COMPACT_DETAIL_LIST_KEYS = {
    "available_tools",
    "available_actions",
    "available_args",
    "required_args",
}

WIKI_SEMANTIC_GROUPS: tuple[tuple[str, ...], ...] = (
    ("trace", "tracing", "runtime", "execution", "path", "flow", "behavior"),
    ("debug", "debugger", "breakpoint", "register", "step", "stepping"),
    ("decompile", "decompiler", "pseudocode", "hl", "highlevel"),
    ("search", "find", "lookup", "query", "locate"),
    ("rename", "naming", "symbol", "label"),
    ("xref", "crossref", "reference", "references", "caller", "callee"),
    ("patch", "modify", "write", "rewrite"),
    ("vulnerability", "security", "exploit", "sink", "source"),
)

# Ranking/inference policy
# Default is embedding-first to avoid brittle keyword/threshold heuristics.
EMBEDDING_FIRST_MODE = str(os.environ.get("IDA_MCP_EMBEDDING_FIRST_MODE", "true")).strip().lower() in {"1", "true", "yes", "on", "enabled"}
ALLOW_HEURISTIC_FALLBACKS = str(os.environ.get("IDA_MCP_ALLOW_HEURISTIC_FALLBACKS", "false")).strip().lower() in {"1", "true", "yes", "on", "enabled"}


_log_file_handle = None


def log_rpc(msg):
    global _log_file_handle
    try:
        if _log_file_handle is None:
            _log_file_handle = open(BRIDGE_LOG, "a", encoding="utf-8")
        _log_file_handle.write(f"[{datetime.now().isoformat()}] {msg}\n")
        _log_file_handle.flush()
    except Exception:
        pass


# Input coercion helpers
def _bounded_int(
    raw: Any,
    default: int,
    *,
    min_value: int = 0,
    max_value: int = 2_000_000_000,
) -> int:
    try:
        v = int(raw)
    except Exception:
        return default
    if v < min_value:
        return min_value
    if v > max_value:
        return max_value
    return v


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    return s in {"1", "true", "yes", "on", "enabled"}


def _env_bool(name: str, default: bool = False) -> bool:
    return _coerce_bool(os.environ.get(name), default)


def _parse_str_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if x is not None]
    if isinstance(value, str):
        if not value.strip():
            return []
        return [x.strip() for x in value.split(",") if x.strip()]
    return [str(value)]


def _parse_line_range(value: Any) -> tuple[Optional[int], Optional[int]]:
    if value is None:
        return (None, None)
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return (int(value[0]) if value[0] is not None else None,
                int(value[1]) if value[1] is not None else None)
    s = str(value).strip()
    if not s:
        return (None, None)
    if "-" in s:
        parts = s.split("-", 1)
        start = int(parts[0]) if parts[0].strip() else None
        end = int(parts[1]) if parts[1].strip() else None
        return (start, end)
    return (int(s), None)


def _normalize_session_id(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    sid = value.strip().upper()
    if not SESSION_ID_RE.fullmatch(sid):
        return None
    return sid


def _parse_iso_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        # Handle Z suffix
        s = str(value).strip().replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return None


def validate_path(path: str) -> Optional[str]:
    if not path or "\x00" in path:
        return None
    # Reject paths containing '..' components before normalization
    if ".." in Path(path).parts:
        return None
    resolved = os.path.normpath(os.path.abspath(path))
    # Resolve symlinks (defense-in-depth: realpath should never produce '..')
    try:
        return os.path.realpath(resolved)
    except (OSError, ValueError):
        return resolved
