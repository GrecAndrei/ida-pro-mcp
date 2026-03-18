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
import difflib
import threading
import subprocess
import time
import warnings
import glob
import uuid
import shlex
import copy
import shutil
import tempfile
from typing import Any, Dict, Optional, List, Union
from pathlib import Path
from datetime import datetime, timedelta

# Robust Path Setup
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "src"))

# Runtime data/cache directories (outside repo by default)
def _default_runtime_dir() -> str:
    if sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return os.path.realpath(os.path.join(root, "ida-pro-mcp"))
    if sys.platform == "darwin":
        return os.path.realpath(os.path.join(str(Path.home()), "Library", "Application Support", "ida-pro-mcp"))
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        return os.path.realpath(os.path.join(xdg_state, "ida-pro-mcp"))
    return os.path.realpath(os.path.join(str(Path.home()), ".local", "state", "ida-pro-mcp"))


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
    for candidate in (
        preferred,
        _default_runtime_dir(),
        os.path.join(tempfile.gettempdir(), "ida-pro-mcp"),
        os.path.join(SCRIPT_DIR, "ida_mcp_cache"),
    ):
        candidate = os.path.realpath(os.path.expanduser(candidate))
        if candidate not in candidates:
            candidates.append(candidate)
    for candidate in candidates:
        if _is_writable_dir(candidate):
            return candidate
    return os.path.realpath(os.path.join(SCRIPT_DIR, "ida_mcp_cache"))


def _migrate_legacy_runtime_dir(target_dir: str):
    legacy_dir = os.path.join(SCRIPT_DIR, "ida_mcp_cache")
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
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
    except Exception:
        # Best effort migration only.
        pass


CACHE_DIR = _select_runtime_dir(_resolve_runtime_dir())
_migrate_legacy_runtime_dir(CACHE_DIR)
os.makedirs(CACHE_DIR, exist_ok=True)
BRIDGE_LOG = os.path.join(CACHE_DIR, "bridge.log")


def log_rpc(msg):
    try:
        with open(BRIDGE_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
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
    _SEMANTIC_CANONICALS = {
        "find": "search",
        "lookup": "search",
        "locate": "search",
        "discover": "search",
        "query": "search",
        "match": "search",
        "decompiler": "decompile",
        "decompiled": "decompile",
        "pseudocode": "decompile",
        "hexrays": "decompile",
        "ctree": "decompile",
        "routine": "function",
        "procedure": "function",
        "proc": "function",
        "method": "function",
        "subroutine": "function",
        "global": "data",
        "variable": "data",
        "memory": "data",
        "xref": "reference",
        "ref": "reference",
        "refs": "reference",
        "callsite": "reference",
        "caller": "reference",
        "callee": "reference",
        "literal": "string",
        "text": "string",
        "api": "import",
        "symbol": "import",
        "extern": "import",
    }
    # Ignore semantic fallback for very short one-word queries to reduce false positives.
    _SEMANTIC_SINGLE_TOKEN_MIN_LEN = 5
    # Conservative typo tolerance: catches small misspellings without broad overmatching.
    _SEMANTIC_FUZZY_CUTOFF = 0.86

    def _normalize_semantic_token(token: str) -> str:
        tok = token.lower().strip()
        if not tok:
            return tok
        for suffix in ("ing", "ers", "ies", "ied", "er", "ed", "es", "s"):
            if len(tok) > 4 and tok.endswith(suffix):
                if suffix in ("ies", "ied"):
                    tok = tok[:-3] + "y"
                else:
                    tok = tok[: -len(suffix)]
                break
        return _SEMANTIC_CANONICALS.get(tok, tok)

    def _semantic_tokenize(text: str):
        if not text:
            return []
        tokens = []
        for raw in re.findall(r"[a-z0-9_]+", text.lower()):
            for part in raw.split("_"):
                tok = _normalize_semantic_token(part)
                if len(tok) >= 2:
                    tokens.append(tok)
        return tokens

    def _compile_semantic_matcher(pattern: str):
        query_tokens = _semantic_tokenize(pattern)
        if not query_tokens:
            return None
        if (
            len(query_tokens) == 1
            and len(query_tokens[0]) < _SEMANTIC_SINGLE_TOKEN_MIN_LEN
            and " " not in pattern
        ):
            return None

        query_set = set(query_tokens)
        # For path/file-like queries with a delimiter and exactly two tokens
        # (e.g. "test.exe"), require both tokens to reduce broad matches.
        pathlike_query = len(query_set) == 2 and bool(re.search(r"[./\\:_-]", pattern))
        if pathlike_query:
            overlap_needed = 2
        else:
            overlap_needed = max(1, (len(query_set) + 1) // 2)
        fuzzy_tokens = [tok for tok in query_set if len(tok) >= _SEMANTIC_SINGLE_TOKEN_MIN_LEN]

        def _semantic_matches(text: str) -> bool:
            text_tokens = set(_semantic_tokenize(text))
            if not text_tokens:
                return False
            overlap = len(query_set.intersection(text_tokens))
            if overlap >= overlap_needed:
                return True
            if not fuzzy_tokens:
                return False
            fuzzy_hits = 0
            for qtok in fuzzy_tokens:
                if difflib.get_close_matches(qtok, text_tokens, n=1, cutoff=_SEMANTIC_FUZZY_CUTOFF):
                    fuzzy_hits += 1
                    if overlap + fuzzy_hits >= overlap_needed:
                        return True
            return False

        return _semantic_matches

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
        semantic_match = _compile_semantic_matcher(pattern)
        if semantic_match is None:
            return lambda _t, _p=pl: _p in _t.lower()
        return lambda _t, _p=pl, _sem=semantic_match: (_p in _t.lower()) or _sem(_t)

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
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    SESSION_REQUIRED = "SESSION_REQUIRED"
    INVALID_ARGS = "INVALID_ARGS"
    ACTION_NOT_FOUND = "ACTION_NOT_FOUND"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    BATCH_EMPTY = "BATCH_EMPTY"
    BATCH_TOO_LARGE = "BATCH_TOO_LARGE"
    BOOKMARK_NOT_FOUND = "BOOKMARK_NOT_FOUND"
    TRUNCATION_TOKEN_EXPIRED = "TRUNCATION_TOKEN_EXPIRED"
    TRUNCATION_TOKEN_INVALID = "TRUNCATION_TOKEN_INVALID"
    TRUNCATION_FIELD_MISSING = "TRUNCATION_FIELD_MISSING"
    RPC_CONNECTION_ERROR = "RPC_CONNECTION_ERROR"


# Default hints for host-side error codes so every error guides the LLM
_HOST_ERROR_HINTS = {
    MCPError.FILE_NOT_FOUND: "The file does not exist. Verify the path is correct.",
    MCPError.FILE_LOCKED: "The IDB or file is locked. Close other IDA instances first.",
    MCPError.IDA_TIMEOUT: "IDA took too long to start. Increase IDA_MCP_STARTUP_TIMEOUT or check IDA installation.",
    MCPError.IDA_CRASHED: "IDA exited unexpectedly. Check the log for details.",
    MCPError.NOT_IMPLEMENTED: "This action is not available in the current runtime/build.",
    MCPError.SESSION_REQUIRED: "No active session. Create one with session(action='create', binary_path='...').",
    MCPError.INVALID_ARGS: "Invalid arguments. Check the tool description for valid parameters.",
    MCPError.ACTION_NOT_FOUND: "Unknown action. Check the tool description for valid actions.",
    MCPError.SESSION_NOT_FOUND: "Session not found. Use session(action='list') to see available sessions.",
    MCPError.BATCH_EMPTY: "The batch call list is empty. Provide at least one call.",
    MCPError.BATCH_TOO_LARGE: "Too many batch calls. Limit to 50 calls per batch.",
    MCPError.BOOKMARK_NOT_FOUND: "Bookmark not found. Use bookmarks(action='list') to see bookmarks.",
    MCPError.TRUNCATION_TOKEN_EXPIRED: "Continuation token expired. Re-run the original query.",
    MCPError.TRUNCATION_TOKEN_INVALID: "Invalid continuation token. Check the token value.",
    MCPError.TRUNCATION_FIELD_MISSING: "Requested field not in truncated response.",
    MCPError.RPC_CONNECTION_ERROR: "Cannot connect to IDA. The process may have crashed.",
}


def make_error(
    code: str, message: str, recoverable: bool = False, details: dict = None,
    hint: str = None,
) -> dict:
    res = {"error": True, "code": code, "message": message, "recoverable": recoverable}
    resolved_hint = hint or _HOST_ERROR_HINTS.get(code)
    if resolved_hint:
        res["hint"] = resolved_hint
    if details:
        res["details"] = details
    return res


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


SESSION_ID_RE = re.compile(r"^[A-Z0-9]{8}$")
MAX_BATCH_CALLS = 50
MAX_BATCH_PAYLOAD_BYTES = 512 * 1024
MAX_LIST_LIMIT = 200
MAX_LIST_OFFSET = 100_000
MAX_TAGS_PER_SESSION = 64
MAX_TAG_LEN = 64
MAX_NOTE_LEN = 16_384
MAX_NAME_LEN = 256
MAX_SESSION_ID_RETRIES = 1024
MAX_SNAPSHOT_ID_RETRIES = 128
MAX_WIKI_RESULTS = 200
WIKI_SEMANTIC_GROUPS: tuple[tuple[str, ...], ...] = (
    ("trace", "tracing", "runtime", "execution", "path", "flow", "behavior"),
    ("debug", "debugger", "breakpoint", "register", "step", "stepping"),
    ("decompile", "decompiler", "pseudocode", "hl", "highlevel"),
    ("search", "find", "lookup", "query", "locate"),
    ("rename", "naming", "symbol", "label"),
    ("xref", "crossref", "reference", "references", "caller", "callee"),
    ("patch", "modify", "edit", "write", "rewrite"),
    ("vulnerability", "security", "exploit", "taint", "sink", "source"),
)
TOOL_ALIASES = {
    "plugins": "misc",
    "xfer_analysis": "xref_analysis",
}
WRAPPER_ACTIONS = ("grep", "pick", "head", "tail", "next", "stats")
ACTION_PREFIX_RE = re.compile(r"^action[\s\"']*[:=][\s\"']*", re.IGNORECASE)
ACTION_STRIP_CHARS = "\"'"
ADVERTISED_TOOLS = [
    "session",
    "truncation",
    "bookmarks",
    "batch",
    "wiki",
    "analysis",
    "query",
    "edit",
    "idb",
    "code",
    "data",
    "search",
    "types",
    "memory",
    "modify",
    "funcs",
    "segments",
    "bulk",
    "misc",
    "calc",
    "nav",
    "project",
    "debug",
    "trace",
    "coverage",
    "agent",
    "summarize",
    "classify",
    "compare",
    "vuln_scan",
]
HIDDEN_TOOLS_IN_LIST = {"plugins", "xfer_analysis"}
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


def _normalize_session_id(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    sid = value.strip().upper()
    if not SESSION_ID_RE.fullmatch(sid):
        return None
    return sid


def _parse_iso_datetime(value: Any) -> Optional[datetime]:
    """Best-effort ISO datetime parser for persisted metadata."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _bounded_int(
    value: Any,
    default: int,
    *,
    min_value: int,
    max_value: int,
) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    if parsed < min_value:
        return min_value
    if parsed > max_value:
        return max_value
    return parsed


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _env_bool(name: str, default: bool = False) -> bool:
    return _coerce_bool(os.environ.get(name), default=default)


def _parse_str_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(",")]
        return [p for p in parts if p]
    if isinstance(value, (list, tuple, set)):
        out = []
        for item in value:
            s = str(item).strip()
            if s:
                out.append(s)
        return out
    s = str(value).strip()
    return [s] if s else []


def _parse_line_range(value: Any) -> tuple[Optional[int], Optional[int]]:
    """
    Parse flexible line selectors:
      - "10-40", "10:40", "10..40"
      - "25" (single line)
      - "10-" (start only)
      - "-40" (end only)
    Returns (start, end), where each may be None.
    """
    if value is None:
        return None, None
    if isinstance(value, int):
        n = max(1, int(value))
        return n, n
    s = str(value).strip()
    if not s:
        return None, None
    if s.isdigit():
        n = max(1, int(s))
        return n, n
    m = re.fullmatch(r"(\d+)\s*(?:-|\.\.|:)\s*(\d+)", s)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if a > b:
            a, b = b, a
        return max(1, a), max(1, b)
    m = re.fullmatch(r"(\d+)\s*(?:-|\.\.|:)\s*", s)
    if m:
        return max(1, int(m.group(1))), None
    m = re.fullmatch(r"\s*(?:-|\.\.|:)\s*(\d+)", s)
    if m:
        return None, max(1, int(m.group(1)))
    return None, None


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
        tags: Optional[List[str]] = None,
        notes: str = "",
        auto_name: str = "",
    ):
        self.session_id = session_id
        self.idb_path = idb_path
        self.binary_path = binary_path
        self.analysis_options = analysis_options or {}
        self.analysis_applied = bool(analysis_applied)
        self.ida_args = ida_args or []
        self.created_at = created_at or datetime.now()
        self.last_accessed = last_accessed or datetime.now()
        self.tags = tags or []
        self.notes = notes
        self.auto_name = auto_name or self._derive_auto_name()

    def _derive_auto_name(self) -> str:
        """Derive a human-friendly name from the binary path."""
        if self.binary_path:
            return os.path.basename(self.binary_path)
        if self.idb_path:
            base = os.path.basename(self.idb_path)
            # Strip SID prefix if present
            if base.startswith("SID_") and "_" in base[4:]:
                base = base.split("_", 2)[-1]
            return os.path.splitext(base)[0]
        return f"session_{self.session_id}"

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
            "tags": self.tags,
            "notes": self.notes,
            "auto_name": self.auto_name,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        """Load session from metadata dict"""
        sid = _normalize_session_id(data.get("session_id"))
        if not sid:
            raise ValueError("invalid or missing session_id")
        idb_path = data.get("idb_path")
        if idb_path is None:
            idb_path = ""
        elif not isinstance(idb_path, str):
            raise ValueError("idb_path must be a string")
        created = _parse_iso_datetime(data.get("created_at"))
        accessed = _parse_iso_datetime(data.get("last_accessed"))
        return cls(
            sid,
            idb_path,
            data.get("binary_path", ""),
            data.get("analysis_options", {}) or {},
            data.get("analysis_applied", False),
            data.get("ida_args", []) or [],
            created,
            accessed,
            data.get("tags", []) or [],
            data.get("notes", ""),
            data.get("auto_name", ""),
        )


class SessionManager:
    def __init__(self, cache_dir: str):
        self._lock = threading.RLock()
        self.sessions: Dict[str, Session] = {}
        self.cache_dir = cache_dir
        self.session_dir = os.path.join(cache_dir, "sessions")
        self._snapshots: Dict[str, List[dict]] = {}  # sid -> list (in-memory only, lost on restart)
        os.makedirs(self.session_dir, exist_ok=True)
        # Auto-load existing sessions on startup
        self._load_sessions()

    def _sanitize_tags(self, tags: Optional[List[Any]]) -> List[str]:
        if not tags:
            return []
        cleaned: List[str] = []
        for tag in tags:
            if tag is None:
                continue
            t = str(tag).strip()
            if not t:
                continue
            if len(t) > MAX_TAG_LEN:
                t = t[:MAX_TAG_LEN]
            if t not in cleaned:
                cleaned.append(t)
            if len(cleaned) >= MAX_TAGS_PER_SESSION:
                break
        return cleaned

    def _sanitize_note(self, note: str) -> str:
        if not note:
            return ""
        return str(note)[:MAX_NOTE_LEN]

    def _sanitize_name(self, name: str) -> str:
        if not name:
            return ""
        return str(name).strip()[:MAX_NAME_LEN]

    def _new_session_id(self) -> str:
        for _ in range(MAX_SESSION_ID_RETRIES):
            sid = uuid.uuid4().hex[:8].upper()
            if sid not in self.sessions:
                return sid
        raise RuntimeError(
            f"failed to allocate unique session id after {MAX_SESSION_ID_RETRIES} retries"
        )

    def _get_metadata_path(self, sid: str) -> str:
        """Get path to session metadata file"""
        return os.path.join(self.session_dir, f"SID_{sid}_metadata.json")

    def _save_metadata(self, session: Session):
        """Persist session metadata to disk (atomic write)"""
        path = self._get_metadata_path(session.session_id)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(session.to_dict(), f, indent=2)
            os.replace(tmp, path)
        except Exception as e:
            log_rpc(f"Failed to save session metadata: {e}")
            try:
                os.remove(tmp)
            except OSError:
                pass

    def _load_sessions(self):
        """Load all existing sessions from metadata files"""
        pattern = os.path.join(self.session_dir, "SID_*_metadata.json")
        for meta_path in glob.glob(pattern):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    session = Session.from_dict(data)
                    if not _normalize_session_id(session.session_id):
                        log_rpc(f"Skipping metadata with invalid session_id: {meta_path}")
                        continue
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
        tags: Optional[List[str]] = None,
        notes: str = "",
    ) -> Session:
        with self._lock:
            sid = self._new_session_id()
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
                tags=self._sanitize_tags(tags),
                notes=self._sanitize_note(notes),
            )
            self.sessions[sid] = session
            # Persist metadata immediately
            self._save_metadata(session)
            return session

    def get_session(self, sid: str) -> Optional[Session]:
        """Get session and update last_accessed timestamp"""
        with self._lock:
            session = self.sessions.get(sid)
            if session:
                session.update_access()
                self._save_metadata(session)
                return copy.copy(session)
            return None

    def find_session_by_path(self, path: str) -> Optional[Session]:
        """Find a session by binary_path or idb_path (normalized comparison)."""
        with self._lock:
            norm = os.path.realpath(os.path.abspath(path))
            for s in self.sessions.values():
                if s.binary_path and os.path.realpath(os.path.abspath(s.binary_path)) == norm:
                    return copy.copy(s)
                if s.idb_path and os.path.realpath(os.path.abspath(s.idb_path)) == norm:
                    return copy.copy(s)
            return None

    def discover_sessions(self, query: str = "") -> List[Session]:
        """Return all active sessions, optionally filtered by query.

        The *query* is matched against session_id, binary_path, idb_path,
        auto_name, tags, and notes using automatic regex / glob / substring detection.
        """
        with self._lock:
            if not query:
                return [copy.copy(s) for s in self.sessions.values()]
            matcher = compile_smart_pattern(query, case_sensitive=False)
            result = []
            for s in self.sessions.values():
                tags_str = " ".join(s.tags) if s.tags else ""
                searchable = f"{s.session_id} {s.binary_path} {s.idb_path} {s.auto_name} {tags_str} {s.notes}"
                if matcher(searchable):
                    result.append(copy.copy(s))
            return result

    def _delete_session_unlocked(self, sid: str) -> bool:
        """Delete a session without acquiring the lock (caller must hold _lock)."""
        session = self.sessions.pop(sid, None)
        self._snapshots.pop(sid, None)
        deleted = False
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

    def delete_session(self, sid: str) -> bool:
        with self._lock:
            return self._delete_session_unlocked(sid)

    # --- New feature methods ---

    def update_session(self, sid: str, **kwargs) -> Optional[Session]:
        """Update session fields."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            for key, value in kwargs.items():
                if hasattr(session, key) and key not in ("session_id", "created_at"):
                    if key == "tags":
                        value = self._sanitize_tags(value if isinstance(value, list) else [value])
                    elif key == "notes":
                        value = self._sanitize_note(value)
                    elif key == "auto_name":
                        value = self._sanitize_name(value)
                    setattr(session, key, value)
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def rename_session(self, sid: str, new_name: str) -> Optional[Session]:
        """Set a custom auto_name."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.auto_name = self._sanitize_name(new_name)
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def duplicate_session(self, sid: str) -> Optional[Session]:
        """Clone a session with a new SID."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            new_sid = self._new_session_id()
            new_session = Session(
                new_sid,
                session.idb_path,
                session.binary_path,
                analysis_options=dict(session.analysis_options),
                analysis_applied=session.analysis_applied,
                ida_args=list(session.ida_args),
                tags=list(session.tags),
                notes=session.notes,
                auto_name=f"{session.auto_name} (copy)",
            )
            self.sessions[new_sid] = new_session
            self._save_metadata(new_session)
            return copy.copy(new_session)

    def export_session(self, sid: str) -> Optional[dict]:
        """Export session metadata as a portable dict."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            data = session.to_dict()
            data["_exported_at"] = datetime.now().isoformat()
            return data

    def import_session(self, data: dict) -> Session:
        """Import a session from exported dict."""
        with self._lock:
            # Generate a new SID to avoid collisions
            new_sid = self._new_session_id()
            data_copy = dict(data)
            data_copy["session_id"] = new_sid
            data_copy.pop("_exported_at", None)
            session = Session.from_dict(data_copy)
            self.sessions[new_sid] = session
            self._save_metadata(session)
            return copy.copy(session)

    def archive_session(self, sid: str) -> Optional[Session]:
        """Mark session as archived."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            if "archived" not in session.tags:
                session.tags.append("archived")
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def unarchive_session(self, sid: str) -> Optional[Session]:
        """Remove archived tag."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.tags = [t for t in session.tags if t != "archived"]
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def list_archived(self) -> List[Session]:
        """List archived sessions."""
        with self._lock:
            return [copy.copy(s) for s in self.sessions.values() if "archived" in s.tags]

    def list_active(self) -> List[Session]:
        """List non-archived sessions."""
        with self._lock:
            return [copy.copy(s) for s in self.sessions.values() if "archived" not in s.tags]

    def get_session_age(self, sid: str) -> Optional[timedelta]:
        """Return timedelta since creation."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            return datetime.now() - session.created_at

    def get_session_idle_time(self, sid: str) -> Optional[timedelta]:
        """Return timedelta since last access."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            return datetime.now() - session.last_accessed

    def cleanup_stale(self, max_age_days: int = 30) -> List[str]:
        """Delete sessions older than max_age_days. Returns list of deleted SIDs."""
        with self._lock:
            cutoff = datetime.now() - timedelta(days=max_age_days)
            stale = [sid for sid, s in self.sessions.items() if s.last_accessed < cutoff]
            for sid in stale:
                self._delete_session_unlocked(sid)
            return stale

    def get_stats(self) -> dict:
        """Return statistics about sessions."""
        with self._lock:
            total = len(self.sessions)
            if total == 0:
                return {"total": 0, "active": 0, "archived": 0, "avg_age_days": 0, "tags": {}}
            archived = sum(1 for s in self.sessions.values() if "archived" in s.tags)
            now = datetime.now()
            ages = [(now - s.created_at).total_seconds() for s in self.sessions.values()]
            avg_age_days = (sum(ages) / len(ages)) / 86400 if ages else 0
            tag_counts: Dict[str, int] = {}
            for s in self.sessions.values():
                for t in s.tags:
                    tag_counts[t] = tag_counts.get(t, 0) + 1
            return {
                "total": total,
                "active": total - archived,
                "archived": archived,
                "avg_age_days": round(avg_age_days, 2),
                "tags": tag_counts,
            }

    def _tag_session_unlocked(self, sid: str, tag: str) -> Optional[Session]:
        """Add a tag without acquiring the lock (caller must hold _lock)."""
        session = self.sessions.get(sid)
        if not session:
            return None
        if tag not in session.tags:
            session.tags.append(tag)
        session.update_access()
        self._save_metadata(session)
        return copy.copy(session)

    def tag_session(self, sid: str, tag: str) -> Optional[Session]:
        """Add a tag to a session."""
        with self._lock:
            cleaned = self._sanitize_tags([tag])
            if not cleaned:
                return None
            return self._tag_session_unlocked(sid, cleaned[0])

    def untag_session(self, sid: str, tag: str) -> Optional[Session]:
        """Remove a tag from a session."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.tags = [t for t in session.tags if t != tag]
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def find_by_tag(self, tag: str) -> List[Session]:
        """Find sessions by tag."""
        with self._lock:
            return [copy.copy(s) for s in self.sessions.values() if tag in s.tags]

    def add_note(self, sid: str, note: str) -> Optional[Session]:
        """Append to notes."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            note = self._sanitize_note(note)
            if session.notes:
                combined = f"{session.notes}\n{note}"
            else:
                combined = note
            session.notes = self._sanitize_note(combined)
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def clear_notes(self, sid: str) -> Optional[Session]:
        """Clear notes."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.notes = ""
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def set_binary_path(self, sid: str, path: str) -> Optional[Session]:
        """Update binary path."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.binary_path = path
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def set_idb_path(self, sid: str, path: str) -> Optional[Session]:
        """Update IDB path."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.idb_path = path
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def bulk_delete(self, sids: List[str]) -> dict:
        """Delete multiple sessions at once."""
        with self._lock:
            results = {}
            for sid in sids:
                results[sid] = self._delete_session_unlocked(sid)
            return results

    def bulk_tag(self, sids: List[str], tag: str) -> dict:
        """Tag multiple sessions."""
        with self._lock:
            cleaned = self._sanitize_tags([tag])
            if not cleaned:
                return {sid: False for sid in sids}
            safe_tag = cleaned[0]
            results = {}
            for sid in sids:
                result = self._tag_session_unlocked(sid, safe_tag)
                results[sid] = result is not None
            return results

    def search_notes(self, query: str) -> List[Session]:
        """Search across all session notes."""
        with self._lock:
            matcher = compile_smart_pattern(query, case_sensitive=False)
            return [copy.copy(s) for s in self.sessions.values() if s.notes and matcher(s.notes)]

    def get_recent(self, n: int = 5) -> List[Session]:
        """Get N most recently accessed sessions."""
        with self._lock:
            sorted_sessions = sorted(self.sessions.values(), key=lambda s: s.last_accessed, reverse=True)
            return [copy.copy(s) for s in sorted_sessions[:n]]

    def get_oldest(self, n: int = 5) -> List[Session]:
        """Get N oldest sessions."""
        with self._lock:
            sorted_sessions = sorted(self.sessions.values(), key=lambda s: s.created_at)
            return [copy.copy(s) for s in sorted_sessions[:n]]

    def session_exists(self, sid: str) -> bool:
        """Check if a session exists."""
        with self._lock:
            return sid in self.sessions

    def count(self) -> int:
        """Return total session count."""
        with self._lock:
            return len(self.sessions)

    def merge_sessions(self, sid1: str, sid2: str) -> Optional[Session]:
        """Merge metadata (tags, notes) from sid2 into sid1."""
        with self._lock:
            s1 = self.sessions.get(sid1)
            s2 = self.sessions.get(sid2)
            if not s1 or not s2:
                return None
            for tag in s2.tags:
                if tag not in s1.tags:
                    s1.tags.append(tag)
            if s2.notes:
                if s1.notes:
                    s1.notes += "\n" + s2.notes
                else:
                    s1.notes = s2.notes
            s1.update_access()
            self._save_metadata(s1)
            return copy.copy(s1)

    def snapshot_session(self, sid: str) -> Optional[str]:
        """Save a point-in-time snapshot of session metadata. Returns snapshot_id.
        Note: Snapshots are stored in memory only and lost on process restart."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            seen = {s.get("_snapshot_id") for s in self._snapshots.get(sid, [])}
            snapshot_id = None
            for _ in range(MAX_SNAPSHOT_ID_RETRIES):
                candidate = uuid.uuid4().hex[:8]
                if candidate not in seen:
                    snapshot_id = candidate
                    break
            if snapshot_id is None:
                log_rpc(
                    f"Failed to allocate snapshot id for session {sid} after {MAX_SNAPSHOT_ID_RETRIES} retries"
                )
                return None
            snapshot = session.to_dict()
            snapshot["_snapshot_id"] = snapshot_id
            snapshot["_snapshot_time"] = datetime.now().isoformat()
            if sid not in self._snapshots:
                self._snapshots[sid] = []
            self._snapshots[sid].append(snapshot)
            return snapshot_id

    def restore_snapshot(self, sid: str, snapshot_id: str) -> Optional[Session]:
        """Restore from a snapshot.
        Note: Snapshots are stored in memory only and lost on process restart."""
        with self._lock:
            snapshots = self._snapshots.get(sid, [])
            snap = None
            for s in snapshots:
                if s.get("_snapshot_id") == snapshot_id:
                    snap = s
                    break
            if not snap:
                return None
            data = {k: v for k, v in snap.items() if not k.startswith("_snapshot")}
            data["session_id"] = sid
            restored = Session.from_dict(data)
            self.sessions[sid] = restored
            self._save_metadata(restored)
            return copy.copy(restored)

    def validate_session(self, sid: str) -> Optional[dict]:
        """Validate session integrity (check paths, metadata)."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            issues = []
            if session.binary_path and not os.path.exists(session.binary_path):
                issues.append(f"Binary not found: {session.binary_path}")
            if session.idb_path and not os.path.exists(session.idb_path):
                issues.append(f"IDB not found: {session.idb_path}")
            meta_path = self._get_metadata_path(sid)
            if not os.path.exists(meta_path):
                issues.append("Metadata file missing")
            if not session.session_id:
                issues.append("Empty session_id")
            if session.created_at > datetime.now():
                issues.append("created_at is in the future")
            return {
                "session_id": sid,
                "valid": len(issues) == 0,
                "issues": issues,
            }


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
            except Exception:
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
        return make_error(MCPError.BOOKMARK_NOT_FOUND, "Bookmark not found")

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
        return make_error(MCPError.BOOKMARK_NOT_FOUND, "Bookmark not found")

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
    "plugins",
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
    "xfer_analysis",
    # String operations
    "string_ops",
    # CFG analysis
    "cfg_analysis",
    # Binary info
    "binary_info",
    # LLM helpers
    "llm_helpers",
]

# Keep tools/list compact for LLM context windows while preserving backward-compatible calls.
HIDDEN_TOOLS_IN_LIST = {t for t in TOOLS if t not in ADVERTISED_TOOLS}.union({"plugins", "xfer_analysis"})


_EXTRA_TOOL_ALIASES = {
    "analysis_tool": "analysis",
    "annotate": "annotation",
    "annotations": "annotation",
    "assembler": "code",
    "assembly": "code",
    "bookmarks_tool": "bookmarks",
    "code_tool": "code",
    "database": "idb",
    "decompiler": "code",
    "decomp": "code",
    "diag": "misc",
    "disasm": "code",
    "disassembly": "code",
    "fn": "funcs",
    "func": "funcs",
    "function": "funcs",
    "functions": "funcs",
    "graphs": "graph",
    "helper": "llm_helpers",
    "helpers": "llm_helpers",
    "hexrays": "code",
    "i_db": "idb",
    "ida": "idb",
    "imports": "imports_deep",
    "lookup": "data",
    "notes": "bookmarks",
    "plugins_tool": "misc",
    "python": "misc",
    "queries": "query",
    "rename": "edit",
    "scanner": "vuln_scan",
    "searches": "search",
    "segment": "segments",
    "session_tool": "session",
    "strings": "string_ops",
    "symbols_tool": "symbols",
    "trace_analyze": "trace_analysis",
    "xref": "xref_analysis",
    "xrefs": "xref_analysis",
}


def _snake_variants(value: str) -> set[str]:
    base = str(value or "").strip().lower()
    if not base:
        return set()
    out = {
        base,
        base.replace("-", "_"),
        base.replace(" ", "_"),
        base.replace("_", "-"),
        base.replace("_", ""),
        base.replace("_", "."),
        base.replace("_", "/"),
    }
    if base.endswith("s") and len(base) > 3:
        out.add(base[:-1])
    else:
        out.add(f"{base}s")
    out.add(f"{base}_tool")
    out.add(f"{base}_tools")
    out.add(f"tool_{base}")
    out.add(f"tools_{base}")
    return {x for x in out if x}


def _camel_variants(value: str) -> set[str]:
    words = [w for w in str(value or "").replace("-", "_").split("_") if w]
    if len(words) <= 1:
        return set()
    pascal = "".join(w.capitalize() for w in words)
    camel = words[0].lower() + "".join(w.capitalize() for w in words[1:])
    return {camel, pascal}


def _build_tool_aliases(tools: list[str], explicit: dict[str, str]) -> dict[str, str]:
    candidates: Dict[str, set[str]] = {}
    for tool in tools:
        for alias in _snake_variants(tool).union(_camel_variants(tool)):
            candidates.setdefault(alias, set()).add(tool)
    for alias, target in (explicit or {}).items():
        candidates.setdefault(str(alias).strip().lower(), set()).add(str(target).strip().lower())
    resolved: dict[str, str] = {}
    for alias, targets in candidates.items():
        if len(targets) == 1:
            target = next(iter(targets))
            if alias != target:
                resolved[alias] = target
    return resolved


TOOL_ALIASES = _build_tool_aliases(TOOLS, {**TOOL_ALIASES, **_EXTRA_TOOL_ALIASES})

TOOL_DESCRIPTIONS = {
    # Core session tools (host-side, no IDA process required)
    "session": "Session lifecycle + runtime context hub. Actions: discover/create/get/list/switch/close/status/rebuild/update/rename/duplicate/export/import/archive/tag/note/stats/validate/snapshot/merge/macros/recent_workset. IDB is optional: after create/switch, tools use active session. If provided, idb accepts session ID, SID_* IDB id, binary path, or full IDB path.",
    "truncation": "Continuation helper for auto-truncated responses. Actions: continue (retrieve next chunk by token/field).",
    "bookmarks": "Enhanced session-correlated bookmarking. Actions: add, list, delete, update, clear, find (supports regex/glob/substring in name, notes, tags, addr, category), export.",
    "batch": "Run multiple tool calls in a single request. Supports shorthand calls like 'tool:action' and inline {name, action, ...args} objects. Returns compact per-call rows + summary.",
    # Analysis configuration
    "analysis": "Analysis configuration and reanalysis. Actions: get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze.",
    # Unified query/edit hubs
    "query": "Unified read-only query hub. Actions: data, search, idb, code, types, imports_deep, symbols, patterns.",
    "edit": "Unified write/edit hub. Quick actions: rename, comment, type, patch, create_func, bulk.",
    # Primary data access
    "idb": "Database metadata and segment information. Actions: meta, summary, segments, entrypoints, bookmarks, overview.",
    "code": "Code logic, decompilation, and flow analysis. Actions: decompile, disasm, xrefs_to, xrefs_from, xrefs_to_field, callees, callers, blocks, analyze, callgraph, export, find_paths, strings_in_func.",
    "data": "Function listing, global variables, strings, imports, and exports. Actions: functions, globals, strings, imports, exports, lookup, bulk_query. Supports include_prototype, include_xrefs, min_size, named_only filters. Query patterns auto-detect regex (e.g. ^init, \\w+alloc), glob (*alloc*), or plain substring.",
    "search": "Pattern and reference search. Actions: bytes, string, immediate, name, insns, text, operand, comment, data_ref, code_ref, regex, func_by_sig, find, callers, callees, api, vulnerable, constants, decompiled. Supports case_sensitive, include_context. Pattern auto-detects regex (e.g. mov.*eax$, \\bfoo\\b), glob, or plain substring.",
    "types": "Type Library (TIL) and prototype management. Actions: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header.",
    "memory": "Direct database memory access. Actions: read, write, hexdump.",
    # Modification tools
    "modify": "Rename, comment, set types, and patch assembly. Actions: rename, comment (regular/repeatable/anterior/posterior), set_type, patch_asm (assembles instruction(s) and patches bytes, supports multi-line separated by semicolons).",
    "funcs": "Function boundary management. Actions: create (auto-converts bytes to code, supports end address, flags, and force deletion of overlaps), delete (finds containing function if addr is inside one), set_flags, set_name (alias: rename), add_comment, list (supports regex/glob/substring query filtering), info (detailed function info with optional prototype and stack frame).",
    "segments": "Segment management. Actions: list, add, delete, set_attr, set_perms, move, info.",
    "bulk": "Bulk rename/comment/type operations. Actions: rename, comment, apply_type, rename_stack, import_annotations, export_annotations. Supports continue_on_error.",
    # Utilities
    "misc": "Utilities. Actions: python, idc, load_sig, cache_stats, read_file, write_file, plugin_list, plugin_run, health. Use python for full IDAPython access. read_file/write_file for host filesystem I/O. plugin_* manages IDA plugins. health runs host diagnostics without requiring a session.",
    "calc": "Mathematical and address resolution. Actions: eval, offset, convert, resolve, deref, chain, align.",
    "nav": "Navigation and triage. Actions: goto, cursor, interesting.",
    # Debugging and tracing
    "debug": "Debugger control and dynamic analysis. Actions: start, stop, continue, step_into, step_over, run_to, run_until, breakpoints, add_bp, del_bp, enable_bp, regs, set_reg, threads, modules, callstack, read_mem, write_mem.",
    "trace": "Execution tracing. Actions: get, clear, set_options.",
    "coverage": "Code coverage import and analysis. Actions: import_drcov, import_lighthouse, highlight, report, uncovered, filter.",
    "trace_analysis": "Execution trace processing. Actions: import_trace, analyze_coverage, find_loops, extract_api_calls, basic_blocks_hit.",
    # Project and file management
    "project": "Project I/O and file operations. Actions: save, close, open, load_binary, list_recent, get_cwd, set_cwd, list_dir, exists. Legacy actions read/write map to misc read_file/write_file.",
    "plugins": "Legacy compatibility plugin surface. Actions: list, run. Preferred entrypoint: misc(action=plugin_list|plugin_run).",
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
    "wiki": "Built-in documentation system with ranked and semantic search, fuzzy topic resolution, section navigation, related-topic discovery, and generated fallback docs. Actions: list_topics, read, search, semantic_search, sections, index.",
    "yara_hunt": "YARA pattern matching. Actions: scan, compile, list_rules.",
    # --- New LLM-optimized tools ---
    "vuln_scan": "Automated vulnerability scanner. Actions: buffer_overflow, format_string, integer_overflow, use_after_free, command_injection, race_condition, null_deref, info_leak, auth_bypass, hardcoded_creds, scan_all, classify, osv_query. Returns compact findings + structured items with severity/confidence, pagination, and optional OSV enrichment.",
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
    "xfer_analysis": "Alias of xref_analysis (compatibility typo, not advertised in tools/list).",
    "string_ops": "Advanced string analysis. Query supports regex. Actions: decode_all, find_urls, find_paths, find_registry, find_ips, find_emails, find_commands, encoding_stats, multilingual, suspicious.",
    "cfg_analysis": "Control flow graph metrics. Actions: complexity, loops, branches, paths, dominators, post_dominators, back_edges, natural_loops, irreducible, flatten_detect.",
    "binary_info": "Binary metadata analysis. Actions: headers, sections, relocations, resources, debug_info, compiler, linker, timestamps, checksums, overlay.",
    "llm_helpers": "LLM workflow helpers. Actions: context_window (token-budgeted context), function_digest, binary_digest, explain_address, suggest_next, progress_report, focus_area, question_answer, guided_analysis, cheatsheet.",
}

TOOL_ACTIONS = {
    # Core session tools
    "session": ["discover", "create", "get", "list", "switch", "close", "status", "rebuild",
                "update", "rename", "duplicate", "export_session", "import_session",
                "archive", "unarchive", "tag", "untag", "find_by_tag", "add_note",
                "clear_notes", "cleanup_stale", "stats", "validate",
                "bulk_delete", "bulk_tag", "search_notes", "recent", "oldest",
                "snapshot", "restore_snapshot", "merge",
                "macro_set", "macro_get", "macro_list", "macro_delete", "macro_run",
                "recent_workset"],
    "truncation": ["continue"],
    "bookmarks": ["add", "list", "delete", "update", "clear", "find", "export"],
    "batch": ["run"],
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
    "query": ["data", "search", "idb", "code", "types", "imports_deep", "symbols", "patterns"],
    "edit": ["rename", "comment", "type", "patch", "create_func", "bulk"],
    # Primary data access
    "idb": ["meta", "summary", "segments", "entrypoints", "bookmarks", "overview"],
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
        "decompiled",
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
    "memory": ["read", "write", "hexdump"],
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
    "misc": [
        "python",
        "idc",
        "load_sig",
        "cache_stats",
        "read_file",
        "write_file",
        "plugin_list",
        "plugin_run",
        "health",
    ],
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
    ],
    "plugins": ["list", "run"],
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
    "wiki": ["list_topics", "read", "search", "semantic_search", "sections", "index"],
    "yara_hunt": ["scan", "compile", "list_rules"],
    # --- New LLM-optimized tools ---
    "vuln_scan": [
        "buffer_overflow", "format_string", "integer_overflow", "use_after_free",
        "command_injection", "race_condition", "null_deref", "info_leak",
        "auth_bypass", "hardcoded_creds", "scan_all", "classify", "osv_query",
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
    "xfer_analysis": [
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
        "tags": {
            "type": ["array", "string"],
            "items": {"type": "string"},
            "description": "Tags for the session (create action). Comma-separated string or array.",
        },
        "notes": {
            "type": "string",
            "description": "Free-form notes for the session (create action).",
        },
        "name": {"type": "string", "description": "Name for macro_* actions or rename action."},
        "macro": {"type": "string", "description": "Alias for macro name in macro_* actions."},
        "data": {"type": "object", "description": "Macro payload for macro_set."},
        "macro_data": {"type": "object", "description": "Alias for macro payload in macro_set."},
        "run_action": {"type": "string", "description": "Session action to execute for macro_run (default from macro or create)."},
        "n": {"type": "integer", "description": "Count for recent/oldest/recent_workset actions."},
        "include_bookmarks": {"type": "boolean", "description": "Include bookmark entries in recent_workset."},
        "include_items": {"type": "boolean", "description": "Include structured items in recent_workset response."},
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
        "include_items": {"type": "boolean"},
        "include_xrefs": {"type": "boolean"},
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
        "arg": {"type": "integer", "description": "Plugin argument for plugin_run"},
        "path": {"type": "string", "description": "File path for read_file/write_file"},
        "content": {"type": "string", "description": "Content to write for write_file"},
        "encoding": {"type": "string", "description": "File encoding (default: utf-8). Use 'binary' for hex-encoded binary data."},
        "verbose": {"type": "boolean", "description": "Include per-runtime details for health action."},
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
        "addr": {"type": "string"},
        "limit": {"type": "integer"},
        "offset": {"type": "integer"},
        "start": {"type": "string"},
        "end": {"type": "string"},
        "case_sensitive": {"type": "boolean"},
        "include_context": {"type": "boolean"},
        "include_items": {"type": "boolean"},
        "include_breakdown": {"type": "boolean"},
        "timeout_ms": {"type": "integer"},
        "max_functions": {"type": "integer"},
        "sample": {"type": "boolean"},
        "sample_max_funcs": {"type": "integer"},
    },
    "vuln_scan": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["vuln_scan"]},
        "addr": {"type": "string", "description": "Address or function scope for scanning."},
        "limit": {"type": "integer", "description": "Max findings to return (capped for context safety)."},
        "offset": {"type": "integer", "description": "Skip first N ranked findings."},
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
            "description": "Optional severity filter.",
        },
        "include_context": {
            "type": "boolean",
            "description": "Include compact decompiled context when available.",
        },
        "osv_coordinates": {
            "type": "array",
            "items": {"type": "string"},
            "description": "OSV package coordinates (ecosystem:name@version or pkg:purl). Used by osv_query and optional scan_all enrichment.",
        },
        "osv_ecosystem": {
            "type": "string",
            "description": "Default OSV ecosystem for shorthand coordinates like name@version.",
        },
        "osv_endpoint": {
            "type": "string",
            "description": "OSV endpoint/base URL (default: https://api.osv.dev).",
        },
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
    "idb": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["idb"]},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
    },
    "code": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["code"]},
        "addrs": {"type": ["array", "string"], "items": {"type": "string"}},
        "addr": {"type": "string"},
        "max_items": {"type": "integer"},
        "max_depth": {"type": "integer"},
        "format": {"type": "string"},
        "disasm_style": {"type": "string", "enum": ["csmini", "classic", "annotated"]},
        "include_bytes": {"type": "boolean"},
        "end": {"type": "string"},
        "limit": {"type": "integer"},
        "field_name": {"type": "string"},
        "target": {"type": "string"},
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
        "lines": {
            "type": "string",
            "description": "Line selector such as '10-40', '25', '10-', or '-40'.",
        },
        "line_start": {"type": "integer"},
        "line_end": {"type": "integer"},
        "offset": {"type": "integer"},
        "limit": {"type": "integer"},
        "max_results": {"type": "integer"},
        "category": {"type": ["string", "array"], "items": {"type": "string"}},
        "fuzzy": {"type": "boolean"},
        "strict_topic": {"type": "boolean"},
        "include_related": {"type": "boolean"},
        "include_snippets": {"type": "boolean"},
        "context_lines": {"type": "integer"},
        "verbose": {
            "type": "boolean",
            "description": "Include full structural metadata in wiki responses.",
        },
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
                "type": ["object", "string"],
                "description": "Each item can be 'tool:action', {name, arguments}, or {name, action, ...args}.",
            },
        },
        "continue_on_error": {"type": "boolean"},
    },
}

_ACTION_ALIAS_HINTS = {
    "add": {"append", "insert", "create"},
    "analyze": {"analyse", "inspect"},
    "bookmarks": {"marks"},
    "callers": {"incoming_calls", "who_calls"},
    "callees": {"outgoing_calls", "calls"},
    "comment": {"set_comment", "annotate"},
    "create": {"new", "make"},
    "decompile": {"pseudo", "pseudocode"},
    "decompile_func": {"decompile", "pseudo"},
    "delete": {"remove", "rm", "del"},
    "disasm": {"asm", "assembly", "disassemble", "listing"},
    "entrypoints": {"entries"},
    "export": {"dump"},
    "find": {"search", "query", "lookup"},
    "functions": {"funcs", "function_list"},
    "get": {"show", "view", "read", "info"},
    "health": {"diagnostics", "diag"},
    "imports": {"imports_list"},
    "info": {"details", "describe"},
    "list": {"ls", "enumerate", "all"},
    "lookup": {"resolve", "find_addr", "find_address"},
    "meta": {"metadata"},
    "name": {"symbol"},
    "plugin_list": {"plugins", "list_plugins"},
    "plugin_run": {"run_plugin", "exec_plugin"},
    "read": {"load"},
    "recent": {"latest"},
    "regex": {"regexp"},
    "rename": {"set_name"},
    "run": {"execute", "exec"},
    "scan_all": {"scan", "full_scan"},
    "search": {"find", "query", "lookup"},
    "set_attr": {"set_attribute"},
    "set_flags": {"flags"},
    "set_name": {"rename"},
    "set_options": {"configure"},
    "set_perms": {"permissions", "set_permissions"},
    "status": {"state"},
    "strings": {"strs"},
    "summary": {"overview"},
    "switch": {"use"},
    "write": {"save"},
    "xrefs_from": {"refs_from", "xrefs_out"},
    "xrefs_to": {"refs_to", "xrefs_in"},
}

_COMMON_ARG_ALIAS_HINTS = {
    "action": {"cmd", "command", "op", "operation", "tool_action"},
    "addr": {"address", "ea", "va", "offset"},
    "addrs": {"addr", "address", "addresses", "ea", "eas", "vas"},
    "args": {"arguments", "params", "parameters"},
    "binary_path": {"binary", "file", "path", "target"},
    "calls": {"steps", "requests"},
    "count": {"limit", "max", "max_items", "n"},
    "data": {"payload", "value"},
    "end": {"end_addr", "stop", "to"},
    "idb": {"database"},
    "idb_path": {"idb", "database", "database_path"},
    "limit": {"count", "max", "max_items", "n"},
    "max_items": {"limit", "count", "max", "n"},
    "name": {"func_name", "symbol", "label"},
    "notes": {"description"},
    "offset": {"skip"},
    "pattern": {"query", "needle", "match"},
    "query": {"q", "search", "pattern"},
    "session_id": {"sid", "session"},
    "source_action": {"on", "target_action", "subaction", "source"},
    "start": {"from", "start_addr"},
    "target": {"to"},
    "topic": {"doc", "page"},
}

_TOOL_SPECIFIC_ARG_ALIASES = {
    "code": {
        "addrs": {"addr", "address", "addresses", "ea", "eas"},
        "max_items": {"count", "max"},
    },
    "data": {
        "query": {"name", "symbol", "lookup"},
    },
    "search": {
        "pattern": {"query", "needle"},
    },
}


def _build_action_aliases() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for tool_name, actions in TOOL_ACTIONS.items():
        alias_map: dict[str, str] = {}
        for action in actions:
            candidates = _snake_variants(action).union(_camel_variants(action))
            candidates.update(_ACTION_ALIAS_HINTS.get(action, set()))
            if action.startswith("get_"):
                candidates.add(action.replace("get_", "show_", 1))
            if action.startswith("set_"):
                candidates.add(action.replace("set_", "update_", 1))
            if action.startswith("find_"):
                candidates.add(action.replace("find_", "search_", 1))
            if action.startswith("list_"):
                candidates.add(action.replace("list_", "get_", 1))
            for alias in candidates:
                key = str(alias).strip().lower()
                if not key:
                    continue
                existing = alias_map.get(key)
                if existing and existing != action:
                    alias_map.pop(key, None)
                    continue
                alias_map[key] = action
        for action in actions:
            alias_map.pop(action.lower(), None)
        out[tool_name] = alias_map
    return out


def _build_tool_arg_aliases() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for tool_name in TOOLS:
        canonical_keys = set(TOOL_ARG_SCHEMAS.get(tool_name, {}).keys())
        canonical_keys.add("action")
        canonical_keys.update(_TOOL_SPECIFIC_ARG_ALIASES.get(tool_name, {}).keys())
        alias_map: dict[str, str] = {}
        # Sort for deterministic alias conflict resolution across processes/runs.
        for canonical in sorted(canonical_keys):
            candidates = _snake_variants(canonical).union(_camel_variants(canonical))
            # Keep argument aliasing conservative: avoid automatic singular/plural flips,
            # because some tools intentionally use both (e.g. tag vs tags, note vs notes).
            if canonical.endswith("s") and len(canonical) > 3:
                candidates.discard(canonical[:-1])
            else:
                candidates.discard(f"{canonical}s")
            candidates.update(_COMMON_ARG_ALIAS_HINTS.get(canonical, set()))
            candidates.update(_TOOL_SPECIFIC_ARG_ALIASES.get(tool_name, {}).get(canonical, set()))
            for alias in candidates:
                key = str(alias).strip().lower()
                if not key:
                    continue
                existing = alias_map.get(key)
                if existing and existing != canonical:
                    alias_map.pop(key, None)
                    continue
                alias_map[key] = canonical
        for canonical, explicit_aliases in _TOOL_SPECIFIC_ARG_ALIASES.get(tool_name, {}).items():
            for alias in explicit_aliases:
                alias_key = alias.strip().lower()
                if alias_key and alias_key != canonical.lower():
                    alias_map[alias_key] = canonical
        for canonical in canonical_keys:
            alias_map.pop(canonical.lower(), None)
        out[tool_name] = alias_map
    return out


ACTION_ALIASES_BY_TOOL = _build_action_aliases()
ARG_ALIASES_BY_TOOL = _build_tool_arg_aliases()

GLOBAL_RESPONSE_CONTROLS = {
    "_response_mode": {
        "type": "string",
        "enum": ["compact", "full"],
        "description": "Output mode. compact is default and reduces token usage.",
    },
    "_compact": {
        "type": "boolean",
        "description": "Shortcut for compact/full mode toggle.",
    },
    "_response_fields": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "Optional top-level field projection (comma-separated string or list).",
    },
    "_response_omit": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "Optional top-level field omission list.",
    },
    "_response_max_items": {
        "type": "integer",
        "description": "Max list items retained in compact mode.",
    },
    "_response_max_string": {
        "type": "integer",
        "description": "Max string length retained in compact mode.",
    },
    "_response_char_budget": {
        "type": "integer",
        "description": "Approximate max output chars before truncation middleware applies.",
    },
    "_response_table": {
        "type": "boolean",
        "description": "Convert repetitive list-of-object payloads into {columns,rows}.",
    },
    "_response_batch_compact": {
        "type": "boolean",
        "description": "Compact batch envelopes in compact mode.",
    },
    "_error_details": {
        "type": "string",
        "enum": ["none", "basic", "full"],
        "description": "Controls verbosity of error details.",
    },
    "_qol_mode": {
        "type": "string",
        "enum": ["tiny", "balanced", "debug"],
        "description": "QoL profile shortcut for response compaction presets.",
    },
}


GLOBAL_WRAPPER_ACTION_CONTROLS = {
    "source_action": {
        "type": "string",
        "description": "For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).",
    },
    "target_action": {"type": "string"},
    "on": {"type": "string"},
    "subaction": {"type": "string"},
    "grep": {
        "type": "string",
        "description": "Grep pattern (substring by default; regex if grep_regex=true).",
    },
    "grep_pattern": {"type": "string"},
    "grep_regex": {"type": "boolean"},
    "grep_case_sensitive": {"type": "boolean"},
    "grep_invert": {"type": "boolean"},
    "grep_field": {
        "type": "string",
        "description": "Optional top-level source field to grep (e.g. matches, functions, content).",
    },
    "grep_limit": {"type": "integer"},
    "grep_offset": {"type": "integer"},
    "pick_fields": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "For action='pick': top-level fields to include.",
    },
    "pick_omit": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "For action='pick': top-level fields to omit after pick_fields.",
    },
    "head_n": {"type": "integer"},
    "tail_n": {"type": "integer"},
    "next_token": {"type": "string"},
    "token": {"type": "string"},
    "cursor": {"type": "string"},
    "stats_include_payload": {"type": "boolean"},
    "_qol_mode": {
        "type": "string",
        "enum": ["tiny", "balanced", "debug"],
        "description": "QoL response profile preset.",
    },
    "qol_mode": {
        "type": "string",
        "enum": ["tiny", "balanced", "debug"],
    },
}


def _action_enum_with_grep(tool_name: str) -> list[str]:
    actions = list(TOOL_ACTIONS.get(tool_name, []) or [])
    for wrapper_action in WRAPPER_ACTIONS:
        if wrapper_action not in actions:
            actions.append(wrapper_action)
    return actions


def build_input_schema(tool_name: str) -> dict:
    props = {}
    required = []
    if tool_name in TOOL_ARG_SCHEMAS:
        props.update(TOOL_ARG_SCHEMAS[tool_name])
    elif tool_name in TOOL_ACTIONS:
        props["action"] = {"type": "string", "enum": TOOL_ACTIONS[tool_name]}
    for key, schema in GLOBAL_RESPONSE_CONTROLS.items():
        props.setdefault(key, schema)
    # idb parameter is now completely optional - uses current_session automatically
    # Only include it in schema for documentation, never required
    if (
        tool_name not in ("session", "bookmarks", "wiki", "batch")
        and "idb" not in props
    ):
        props["idb"] = {
            "type": "string",
            "description": "Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.",
        }
    if "action" in props:
        action_schema = props.get("action")
        if isinstance(action_schema, dict):
            action_schema = dict(action_schema)
            action_schema["enum"] = _action_enum_with_grep(tool_name)
            props["action"] = action_schema
        for key, schema in GLOBAL_WRAPPER_ACTION_CONTROLS.items():
            props.setdefault(key, schema)
        required.append("action")
    return {"type": "object", "properties": props, "required": required}


def _lean_prop_schema(prop_name: str, schema: Any) -> dict:
    """
    Produce an ultra-lean per-parameter schema for tools/list.
    Keep action enum, but collapse other fields to just a basic type.
    """
    if not isinstance(schema, dict):
        return {"type": "string"}

    out: dict[str, Any] = {}
    raw_type = schema.get("type")
    if isinstance(raw_type, str):
        out["type"] = raw_type
    elif isinstance(raw_type, list):
        # Prefer a concrete scalar-ish type to avoid noisy anyOf-style payloads.
        preferred = None
        for t in ("string", "integer", "number", "boolean", "array", "object"):
            if t in raw_type:
                preferred = t
                break
        out["type"] = preferred or "string"
    elif prop_name == "action":
        out["type"] = "string"
    else:
        out["type"] = "string"

    if prop_name == "action":
        enum_vals = schema.get("enum")
        if isinstance(enum_vals, list):
            out["enum"] = enum_vals
    return out


def build_input_schema_lean(tool_name: str) -> dict:
    """
    Build a minimal input schema for tools/list to reduce prompt/context overhead.
    Preserves essential per-tool argument fields while stripping verbose text.
    """
    props = {}
    required = []
    if tool_name in TOOL_ARG_SCHEMAS:
        for k, v in TOOL_ARG_SCHEMAS[tool_name].items():
            props[k] = _lean_prop_schema(k, v)
    elif tool_name in TOOL_ACTIONS:
        props["action"] = {"type": "string", "enum": TOOL_ACTIONS[tool_name]}
    if tool_name not in ("session", "bookmarks", "wiki", "batch"):
        props["idb"] = {"type": "string"}
    if "action" in props:
        action_schema = props.get("action")
        if isinstance(action_schema, dict):
            action_schema = dict(action_schema)
            action_schema["enum"] = _action_enum_with_grep(tool_name)
            props["action"] = action_schema
        for key, schema in GLOBAL_WRAPPER_ACTION_CONTROLS.items():
            props.setdefault(key, _lean_prop_schema(key, schema))
        required.append("action")
    return {"type": "object", "properties": props, "required": required}


def build_input_schema_ultra(tool_name: str) -> dict:
    """
    Build a very small schema for tools/list to minimize startup context.
    Keeps only the essential invocation shape (action enum + optional idb).
    """
    if tool_name == "batch":
        return {
            "type": "object",
            "properties": {
                "calls": {"type": "array", "items": {"type": ["object", "string"]}},
                "continue_on_error": {"type": "boolean"},
            },
            "required": ["calls"],
        }
    if tool_name == "truncation":
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": TOOL_ACTIONS["truncation"]},
                "token": {"type": "string"},
            },
            "required": ["action"],
        }

    props: Dict[str, Any] = {}
    required: List[str] = []
    action_enum = TOOL_ACTIONS.get(tool_name)
    if action_enum:
        props["action"] = {"type": "string", "enum": _action_enum_with_grep(tool_name)}
        required.append("action")
    if tool_name not in ("session", "bookmarks", "wiki", "batch", "truncation"):
        props["idb"] = {
            "type": "string",
            "description": "Optional. session_id, SID_* id, binary path, or full IDB path.",
        }
    return {"type": "object", "properties": props, "required": required}


def build_tool_description_ultra(tool_name: str) -> str:
    """Return a tiny wiki-first routing hint for ultra tools/list mode."""
    if tool_name == "wiki":
        return "Wiki index + docs. Start with wiki(action='index')."
    if tool_name == "session":
        return "Session hub. IDB is optional after create/switch."
    if tool_name == "batch":
        return "Batch hub. Use calls as 'tool:action' or {name,action,...}."
    return f"Use wiki(topic='tools/{tool_name}') for usage."


def build_tool_description_lean(tool_name: str) -> str:
    """Return a short description without embedded action lists."""
    full = str(TOOL_DESCRIPTIONS.get(tool_name, "") or "").strip()
    if not full:
        return ""
    if "Actions:" in full:
        full = full.split("Actions:", 1)[0].strip()
    full = re.sub(r"\s+", " ", full).strip(" .")
    if not full:
        return ""
    if len(full) > 140:
        full = full[:137].rstrip() + "..."
    return full + "."


# =============================================================================
# MCP SERVER
# =============================================================================


class IDAMCPServer:
    def __init__(self):
        mode = str(os.environ.get("IDA_MCP_RESPONSE_MODE", "compact")).strip().lower()
        if mode not in {"compact", "full"}:
            mode = "compact"
        qol_mode = str(os.environ.get("IDA_MCP_QOL_MODE", "balanced")).strip().lower()
        if qol_mode not in {"tiny", "balanced", "debug"}:
            qol_mode = "balanced"
        tools_list_mode = str(os.environ.get("IDA_MCP_TOOLS_LIST_MODE", "ultra")).strip().lower()
        if tools_list_mode not in {"ultra", "lean", "full"}:
            tools_list_mode = "ultra"
        detail_level = str(os.environ.get("IDA_MCP_ERROR_DETAIL_LEVEL", "basic")).strip().lower()
        if detail_level not in {"none", "basic", "full"}:
            detail_level = "basic"
        self.default_response_mode = mode
        self.default_qol_mode = qol_mode
        self.default_tools_list_mode = tools_list_mode
        self.default_error_detail_level = detail_level
        self.default_batch_compact = _env_bool("IDA_MCP_BATCH_COMPACT", True)
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
                "drop_ok": True,
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
                "drop_ok": True,
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
        # Controls whether tools/list returns the full monolithic description/schema payload.
        # Default OFF for context efficiency in LLM clients.
        self.monolithic_tool_descriptions = _env_bool(
            "IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS",
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
        self._macro_path = os.path.join(self.cache_dir, "session_macros.json")
        self._session_macros: Dict[str, Dict[str, Any]] = {}
        self.current_session = None
        self.session_runtimes = {}
        self._wiki_cache: Dict[str, Any] = {
            "root": "",
            "expires": 0.0,
            "topics": {},
            "pages": [],
        }
        self._wiki_cache_ttl = 5.0
        self._load_session_macros()

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
            return "".join(lines[-max(1, int(tail_lines)):]).strip()
        except Exception:
            return ""

    def _get_ida_diagnostics(self, stdout_log=None, stderr_log=None, tail_lines: int = 40):
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
        has_phrase = ("library init failed" in low) or ("library initialization failed" in low)
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
            hints.append("Verify IDA runtime dependencies are installed and loadable (ldd on idat64).")
        if "glibcxx" in low or "cxxabi" in low:
            causes.append("C++ runtime ABI mismatch (libstdc++ / libc++ conflict).")
            hints.append("Unset conflicting LD_LIBRARY_PATH entries or use system-compatible libstdc++.")
        if "qt.qpa.plugin" in low or "xcb" in low or "qt platform plugin" in low:
            causes.append("Qt platform/plugin initialization failure.")
            hints.append("Check Qt plugin paths and system GUI/runtime deps (e.g. xcb plugin packages).")
        if "wrong elf class" in low or "bad cpu type" in low or "exec format error" in low:
            causes.append("Binary/runtime architecture mismatch.")
            hints.append("Use the correct IDA binary for host architecture and compatible target runtime.")
        if "permission denied" in low:
            causes.append("Filesystem permission error while loading runtime components.")
            hints.append("Fix file execute/read permissions on IDA installation and plugins.")
        if "plugin" in low and "failed" in low:
            causes.append("A plugin failed during startup and broke library initialization.")
            hints.append("Disable third-party plugins and retry startup.")
        if "python" in low and ("init" in low or "module" in low):
            causes.append("Embedded Python/runtime initialization mismatch.")
            hints.append("Ensure no conflicting PYTHONHOME/PYTHONPATH overrides are injected.")
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
            if (now - float(row.get("created_at", 0.0))) > float(self._next_cache_ttl_seconds)
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
                key = str(k).strip()
                val = str(v).strip()
                if key and key not in parsed:
                    parsed[key] = val
            else:
                positional.append(token)
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
        return text

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
                normalized_key = raw_key.strip().lower()
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
                base = base.strip("\"',")
                mapped = lower_map.get(base.lower(), base)
                out["action"] = mapped
                if len(parts) > 1:
                    parsed_tail = self._parse_action_tail_tokens(parts[1].strip())
                    if arg_aliases:
                        normalized_tail = {}
                        for key, value in parsed_tail.items():
                            if isinstance(key, str):
                                canonical_key = arg_aliases.get(key.strip().lower(), key)
                            else:
                                canonical_key = key
                            normalized_tail[canonical_key] = value
                        parsed_tail = normalized_tail
                    for k, v in parsed_tail.items():
                        out.setdefault(k, v)
                    positional = parsed_tail.get("_positional")
                    if isinstance(positional, str) and positional:
                        if mapped in ("read", "sections") and tool_name == "wiki":
                            out.setdefault("topic", positional)
                        elif mapped == "search":
                            out.setdefault("query", positional)
                        elif "pattern" in TOOL_ARG_SCHEMAS.get(tool_name, {}):
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
        return out

    def _wrapper_source_action(self, tool_name: str, args: dict, wrapper_action: str) -> tuple[Optional[str], Optional[dict]]:
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
            return None, make_error(MCPError.INVALID_ARGS, "source_action cannot be empty")
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
                    return [line for line in value.splitlines() if line.strip()], field, "string"
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
                    return [line for line in value.splitlines() if line.strip()], key, "string"
                if isinstance(value, list):
                    return list(value), key, "list"
            return [payload], "payload", "list"
        if isinstance(payload, list):
            return list(payload), "payload", "list"
        if isinstance(payload, str):
            return [line for line in payload.splitlines() if line.strip()], "payload", "string"
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
            "target": result.get("target") or result.get("query") or result.get("pattern"),
        }
        self._activity_log.append(entry)
        if len(self._activity_log) > self._activity_log_max:
            self._activity_log = self._activity_log[-self._activity_log_max :]

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
                    f"{item.get('ts','')}  bookmark  {item.get('address','')}  {item.get('name','')}".strip()
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
            lines.append(f"{item.get('ts','')}  {tail}".strip())

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

        opts["fields"] = _parse_str_list(self._pop_first(exec_args, ["_response_fields"], None))
        opts["omit"] = _parse_str_list(self._pop_first(exec_args, ["_response_omit"], None))

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
            bool(opts.get("table_mode", self.default_table_mode if compact_mode else False)),
        )
        opts["batch_compact"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_batch_compact"], None),
            bool(opts.get("batch_compact", self.default_batch_compact if compact_mode else False)),
        )
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
            "drop_ok": True,
            "dedupe_counts": True,
            "strip_meta": True,
            "table_mode": self.default_table_mode,
            "batch_compact": self.default_batch_compact,
            "error_details": self.default_error_detail_level,
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
                    out[key] = f"{value[:max_string]}...(+{len(value) - max_string} chars)"
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
                if compacted is _COMPACT_DROP:
                    continue
                out[key] = compacted

            if opts.get("dedupe_counts"):
                list_lengths = [len(v) for v in out.values() if isinstance(v, list)]
                if "count" in out and isinstance(out["count"], int) and out["count"] in list_lengths:
                    out.pop("count", None)
                if out.get("offset") == 0:
                    out.pop("offset", None)
                if isinstance(out.get("count"), int) and out.get("total") == out.get("count"):
                    out.pop("total", None)
                if isinstance(out.get("count"), int) and out.get("limit") == out.get("count"):
                    out.pop("limit", None)
                if isinstance(out.get("items"), list) and out.get("next_offset") == len(out["items"]):
                    out.pop("next_offset", None)
                if isinstance(out.get("results"), list) and out.get("count") == len(out["results"]):
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
        if fields:
            always_keep = {"error", "code", "message", "hint", "_truncated", "_continue"}
            keep = fields.union(always_keep)
            projected = {k: v for k, v in payload.items() if k in keep}
        else:
            projected = dict(payload)
        for key in omit:
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
        return out

    def _prepare_response_payload(self, payload: Any, opts: dict) -> Any:
        if opts.get("mode") == "full":
            return payload
        projected = self._project_top_level_fields(payload, opts)
        compacted = self._compact_value(projected, opts)
        if compacted is _COMPACT_DROP:
            compacted = {}
        compacted = self._compact_batch_result(compacted, opts)
        budget = int(opts.get("char_budget", 0) or 0)
        if budget > 0 and isinstance(compacted, dict):
            compacted = truncate_response(compacted, max_tokens=budget)
        return compacted

    def _serialize_payload(self, payload: Any, opts: dict) -> str:
        if opts.get("mode") == "full":
            return json.dumps(payload, ensure_ascii=False, indent=2)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

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
        self._nuclear_reset(session.idb_path, aggressive=bool(opts.get("aggressive_cleanup")))

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

        script_path = os.path.join(SCRIPT_DIR, "src", "ida_pro_mcp", "server_script.py")

        # Environment for IDA
        env = os.environ.copy()
        ida_runtime_dir = self.ida_dir or os.path.dirname(self.idat_exe)
        if ida_runtime_dir:
            env["IDADIR"] = ida_runtime_dir
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
        script_path = os.path.join(SCRIPT_DIR, "src", "ida_pro_mcp", "server_script.py")
        env = os.environ.copy()
        ida_runtime_dir = self.ida_dir or os.path.dirname(self.idat_exe)
        if ida_runtime_dir:
            env["IDADIR"] = ida_runtime_dir
        env["IDA_MCP_PORT"] = str(server_port)
        env["IDA_MCP_BYPASS_SYNC"] = "1"
        env["IDA_MCP_SESSION_ID"] = session.session_id
        env["IDA_MCP_CACHE_DIR"] = self.cache_dir
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
                    self.session_runtimes[session.session_id] = runtime
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
        self._nuclear_reset(session.idb_path, aggressive=bool(opts.get("aggressive_cleanup", True)))

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
            retry_result = self._launch_and_wait(session, server_port, sanitize_env=True)
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
        for sid in list(self.session_runtimes.keys()):
            self._cleanup_runtime(sid)

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
            res = self._send_rpc_raw(
                {"tool": tool_name, "args": kwargs}, runtime["port"]
            )
            return truncate_response(res, max_tokens=self.default_truncate_tokens)
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
                page_tokens = {self._wiki_stem_token(t) for t in page.get("tokens", set())}
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
                snippet_terms = " ".join(sorted(semantic_hits[:4])).strip() or query_lower
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
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            text = f.read()
                    except OSError:
                        continue
                    page_name = filename[:-3]
                    topic = page_name if category == "root" else f"{category}/{page_name}"
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
                            "stemmed_tokens": {self._wiki_stem_token(t) for t in raw_tokens},
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

    def _wiki_normalize_topic(self, topic_name: Any) -> tuple[Optional[str], Optional[dict]]:
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
                    and not re.search(r"\.(i64|idb|exe|dll|so|dylib|bin)$", candidate, re.IGNORECASE)
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
            categories = [c.strip().strip("/").lower() for c in category_filter.split(",")]
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
        topic_lower = page["topic_lower"]
        title_lower = page["title_lower"]
        header_text_lower = page["header_text_lower"]
        text_lower = page["text_lower"]
        tokens = page["tokens"]

        score = 0
        reasons: List[str] = []
        if query_lower == topic_lower:
            score += 500
            reasons.append("exact_topic")
        elif topic_lower.endswith(f"/{query_lower}") or query_lower == page["topic_basename"]:
            score += 380
            reasons.append("basename_match")
        if query_lower in topic_lower:
            score += 220
            reasons.append("topic_contains")
        if query_lower in title_lower:
            score += 180
            reasons.append("title_contains")
        if query_lower in header_text_lower:
            score += 120
            reasons.append("header_contains")
        if query_lower in text_lower:
            score += 70
            reasons.append("content_contains")

        for token in query_tokens:
            if token in tokens:
                score += 8
            if token in topic_lower:
                score += 20
            if token in title_lower:
                score += 15
            if token in header_text_lower:
                score += 10
            if token in text_lower:
                score += 3

        if fuzzy and len(query_lower) >= 3:
            ratio = max(
                difflib.SequenceMatcher(None, query_lower, topic_lower).ratio(),
                difflib.SequenceMatcher(None, query_lower, title_lower).ratio(),
                difflib.SequenceMatcher(None, query_lower, page["topic_basename"]).ratio(),
            )
            if ratio >= 0.72:
                score += int(ratio * 120)
                reasons.append("fuzzy")

        return score, reasons

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
            score, reasons = self._wiki_score_page(page, query_lower, query_tokens, fuzzy)
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
            self.default_wiki_read_limit
            if action == "read" and not verbose
            else 0
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
            {"index": idx + 1, "title": h["text"], "level": h["level"], "line": h["line"]}
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
                    else {"available_sections": [s["title"] for s in available_sections[:20]]}
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

            abs_start_req = line_sel_start if line_sel_start is not None else section_abs_start
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
            result["hint"] = "Use wiki(action='read', topic='...', offset=next_offset, limit=...)"
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
                "active": self.current_session.session_id if self.current_session else None,
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
                    out.append(json.dumps(item, ensure_ascii=False, separators=(",", ":")))
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

    def _grep_collect_lines(self, payload: Any, field: Optional[str] = None) -> tuple[list[str], str]:
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
        grep_limit = _bounded_int(args.get("grep_limit", 200), 200, min_value=1, max_value=5000)
        grep_offset = _bounded_int(args.get("grep_offset", 0), 0, min_value=0, max_value=500000)

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

    def _handle_tool_head_tail_action(self, tool_name: str, args: dict, *, tail: bool = False) -> dict:
        wrapper_name = "tail" if tail else "head"
        source_action, source_err = self._wrapper_source_action(tool_name, args, wrapper_name)
        if source_err:
            return source_err

        default_n = 20
        n_key = "tail_n" if tail else "head_n"
        n = _bounded_int(args.get(n_key, default_n), default_n, min_value=1, max_value=5000)
        field = args.get("grep_field") or args.get("field")
        if field is not None and not isinstance(field, str):
            return make_error(MCPError.INVALID_ARGS, "field must be a string")

        child_args = self._strip_wrapper_args(args)
        child_args["action"] = source_action
        source_payload = self._execute_tool(tool_name, child_args)
        if isinstance(source_payload, dict) and source_payload.get("error"):
            return source_payload

        items, used_field, item_kind = self._collect_wrapper_items(source_payload, field)
        total = len(items)
        if tail:
            page = items[max(0, total - n):]
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
            "next_offset": (offset + len(page)) if (not tail and is_truncated) else None,
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
        source_action, source_err = self._wrapper_source_action(tool_name, args, "stats")
        if source_err:
            return source_err
        include_payload = _coerce_bool(args.get("stats_include_payload"), False)

        child_args = self._strip_wrapper_args(args)
        child_args["action"] = source_action
        source_payload = self._execute_tool(tool_name, child_args)
        if isinstance(source_payload, dict) and source_payload.get("error"):
            return source_payload

        try:
            serialized = json.dumps(source_payload, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            serialized = str(source_payload)
        items, used_field, item_kind = self._collect_wrapper_items(source_payload)
        top_keys: List[str] = []
        if isinstance(source_payload, dict):
            top_keys = list(source_payload.keys())[:64]
        stats = {
            "type": type(source_payload).__name__,
            "top_level_keys": top_keys,
            "line_count": len([line for line in serialized.splitlines() if line.strip()]),
            "char_count": len(serialized),
            "item_count": len(items),
            "item_field": used_field,
            "item_kind": item_kind,
            "has_error": bool(isinstance(source_payload, dict) and source_payload.get("error")),
            "truncated": bool(isinstance(source_payload, dict) and source_payload.get("truncated")),
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
        original_tool_name = tool_name
        tool_name = TOOL_ALIASES.get(tool_name, tool_name)
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
        action = args.get("action")
        if isinstance(action, str):
            action = action.strip()
            args["action"] = action
            native_actions = set(TOOL_ACTIONS.get(tool_name, []) or [])
            has_wrapper_source = any(
                key in args for key in ("source_action", "target_action", "on", "subaction")
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
                        return self._handle_tool_head_tail_action(tool_name, args, tail=False)
                    if action == "tail":
                        return self._handle_tool_head_tail_action(tool_name, args, tail=True)
                    if action == "next":
                        return self._handle_tool_next_action(tool_name, args)
                    if action == "stats":
                        return self._handle_tool_stats_action(tool_name, args)
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
            def _sid_arg(key: str = "session_id", allow_current: bool = True) -> tuple[Optional[str], Optional[dict]]:
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
                return None, make_error(MCPError.INVALID_ARGS, "Invalid session_id format")

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

                tags = args.get("tags", [])
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(",") if t.strip()]
                tags = tags[:MAX_TAGS_PER_SESSION]
                notes = str(args.get("notes", ""))[:MAX_NOTE_LEN]

                self.current_session = self.session_mgr.create_session(
                    binary_path or "",
                    use_existing=idb_path,
                    analysis_options=analysis_options,
                    ida_args=ida_args,
                    tags=tags,
                    notes=notes,
                )
                return {"ok": True, "session": self.current_session.to_dict()}
            if action == "discover":
                self.session_mgr._load_orphaned_idbs()
                q = args.get("query", "")
                sessions = [s.to_dict() for s in self.session_mgr.discover_sessions(query=q)]
                return {"ok": True, "sessions": sessions, "count": len(sessions)}
            if action == "get":
                raw_sid = args.get("session_id")
                if not raw_sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required",
                                     hint="Provide a session_id. Use session(action='list') to see available sessions.")
                sid = _normalize_session_id(raw_sid)
                if not sid:
                    raw_txt = str(raw_sid).strip()
                    if raw_txt and re.fullmatch(r"[A-Za-z0-9]+", raw_txt):
                        sid = raw_txt.upper()
                    else:
                        return make_error(MCPError.INVALID_ARGS, "Invalid session_id format")
                session = self.session_mgr.get_session(sid)
                if not session:
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found",
                                     hint="Use session(action='list') to see available sessions.")
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
                limit = _bounded_int(args.get("limit", 50), 50, min_value=0, max_value=MAX_LIST_LIMIT)
                offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=MAX_LIST_OFFSET)

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
                    return make_error(MCPError.INVALID_ARGS, "session_id or binary_path required",
                                     hint="Provide session_id or binary_path. Use session(action='list') to see sessions.")
                normalized_sid = _normalize_session_id(sid)
                if normalized_sid:
                    sid = normalized_sid
                else:
                    raw_txt = str(sid).strip()
                    if raw_txt and re.fullmatch(r"[A-Za-z0-9]+", raw_txt):
                        sid = raw_txt.upper()
                    else:
                        return make_error(MCPError.INVALID_ARGS, "Invalid session_id format")
                session = self.session_mgr.get_session(sid)
                if session:
                    self.current_session = session
                    return {"ok": True, "session": self.current_session.to_dict()}
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
            if action == "close":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required (or have an active session)",
                                     hint="Provide session_id or create/switch to a session first.")
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
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required",
                                     hint="Provide session_id or create/switch to a session first.")
                session = self.session_mgr.get_session(sid)
                if not session:
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")

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
            if action == "update":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                update_kwargs = {k: v for k, v in args.items() if k not in ("action", "session_id")}
                if "tags" in update_kwargs and isinstance(update_kwargs["tags"], str):
                    update_kwargs["tags"] = [t.strip() for t in update_kwargs["tags"].split(",") if t.strip()]
                if "notes" in update_kwargs:
                    update_kwargs["notes"] = str(update_kwargs.get("notes", ""))[:MAX_NOTE_LEN]
                if "auto_name" in update_kwargs:
                    update_kwargs["auto_name"] = str(update_kwargs.get("auto_name", "")).strip()[:MAX_NAME_LEN]
                result = self.session_mgr.update_session(sid, **update_kwargs)
                if result is None:
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
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
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
                return {"ok": True, "session": result.to_dict()}
            if action == "duplicate":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                result = self.session_mgr.duplicate_session(sid)
                if result is None:
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
                return {"ok": True, "session": result.to_dict()}
            if action == "export_session":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                result = self.session_mgr.export_session(sid)
                if result is None:
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
                return {"ok": True, "exported": result}
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
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
                return {"ok": True, "session": result.to_dict()}
            if action == "unarchive":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                result = self.session_mgr.unarchive_session(sid)
                if result is None:
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
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
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
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
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
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
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
                return {"ok": True, "session": result.to_dict()}
            if action == "clear_notes":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                result = self.session_mgr.clear_notes(sid)
                if result is None:
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
                return {"ok": True, "session": result.to_dict()}
            if action == "cleanup_stale":
                max_age = _bounded_int(args.get("max_age_days", 30), 30, min_value=1, max_value=3650)
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
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
                return {"ok": True, "validation": result}
            if action == "bulk_delete":
                sids = args.get("session_ids", [])
                if not sids:
                    return make_error(MCPError.INVALID_ARGS, "session_ids list required")
                if not isinstance(sids, list):
                    return make_error(MCPError.INVALID_ARGS, "session_ids must be a list")
                cleaned_sids = []
                for raw_sid in sids[:MAX_BATCH_CALLS]:
                    sid = _normalize_session_id(raw_sid)
                    if not sid:
                        return make_error(MCPError.INVALID_ARGS, f"Invalid session_id in list: {raw_sid}")
                    cleaned_sids.append(sid)
                results = self.session_mgr.bulk_delete(cleaned_sids)
                # Clear current session if it was deleted
                if self.current_session and self.current_session.session_id in cleaned_sids:
                    self.current_session = None
                return {"ok": True, "results": results}
            if action == "bulk_tag":
                sids = args.get("session_ids", [])
                tag = args.get("tag")
                if not sids:
                    return make_error(MCPError.INVALID_ARGS, "session_ids list required")
                if not tag:
                    return make_error(MCPError.INVALID_ARGS, "tag required")
                if not isinstance(sids, list):
                    return make_error(MCPError.INVALID_ARGS, "session_ids must be a list")
                cleaned_sids = []
                for raw_sid in sids[:MAX_BATCH_CALLS]:
                    sid = _normalize_session_id(raw_sid)
                    if not sid:
                        return make_error(MCPError.INVALID_ARGS, f"Invalid session_id in list: {raw_sid}")
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
                n = _bounded_int(args.get("n", 5), 5, min_value=1, max_value=MAX_LIST_LIMIT)
                sessions = [s.to_dict() for s in self.session_mgr.get_recent(n)]
                return {"ok": True, "sessions": sessions, "count": len(sessions)}
            if action == "oldest":
                n = _bounded_int(args.get("n", 5), 5, min_value=1, max_value=MAX_LIST_LIMIT)
                sessions = [s.to_dict() for s in self.session_mgr.get_oldest(n)]
                return {"ok": True, "sessions": sessions, "count": len(sessions)}
            if action == "snapshot":
                sid, sid_err = _sid_arg()
                if sid_err:
                    return sid_err
                if not sid:
                    return make_error(MCPError.INVALID_ARGS, "session_id required")
                snapshot_id = self.session_mgr.snapshot_session(sid)
                if snapshot_id is None:
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
                return {"ok": True, "session_id": sid, "snapshot_id": snapshot_id}
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
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Snapshot '{snapshot_id}' not found for session '{sid}'")
                return {"ok": True, "session": result.to_dict()}
            if action == "merge":
                sid1 = _normalize_session_id(args.get("session_id") or args.get("target_id"))
                sid2 = _normalize_session_id(args.get("source_id"))
                if not sid1 or not sid2:
                    return make_error(MCPError.INVALID_ARGS, "session_id (or target_id) and source_id required")
                result = self.session_mgr.merge_sessions(sid1, sid2)
                if result is None:
                    return make_error(MCPError.SESSION_NOT_FOUND, "One or both sessions not found")
                return {"ok": True, "session": result.to_dict()}
            if action == "macro_set":
                macro_name = self._normalize_macro_name(args.get("name") or args.get("macro"))
                if not macro_name:
                    return make_error(MCPError.INVALID_ARGS, "name required for macro_set")
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
                    return make_error(MCPError.INVALID_ARGS, "macro payload must be an object")
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
                macro_name = self._normalize_macro_name(args.get("name") or args.get("macro"))
                if not macro_name:
                    return make_error(MCPError.INVALID_ARGS, "name required for macro_get")
                entry = self._session_macros.get(macro_name.lower())
                if not entry:
                    return make_error(MCPError.FILE_NOT_FOUND, f"Macro '{macro_name}' not found")
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
                return {"ok": True, "action": "macro_list", "macros": macros, "count": len(macros)}
            if action == "macro_delete":
                macro_name = self._normalize_macro_name(args.get("name") or args.get("macro"))
                if not macro_name:
                    return make_error(MCPError.INVALID_ARGS, "name required for macro_delete")
                removed = self._session_macros.pop(macro_name.lower(), None)
                if removed is None:
                    return make_error(MCPError.FILE_NOT_FOUND, f"Macro '{macro_name}' not found")
                self._save_session_macros()
                return {"ok": True, "action": "macro_delete", "name": macro_name}
            if action == "macro_run":
                macro_name = self._normalize_macro_name(args.get("name") or args.get("macro"))
                if not macro_name:
                    return make_error(MCPError.INVALID_ARGS, "name required for macro_run")
                entry = self._session_macros.get(macro_name.lower())
                if not entry:
                    return make_error(MCPError.FILE_NOT_FOUND, f"Macro '{macro_name}' not found")
                base_args = dict(entry.get("data") or {})
                run_action = args.get("run_action") or base_args.get("action") or "create"
                if not isinstance(run_action, str) or not run_action.strip():
                    return make_error(MCPError.INVALID_ARGS, "invalid run_action for macro_run")
                run_action = run_action.strip()
                if run_action.startswith("macro_"):
                    return make_error(MCPError.INVALID_ARGS, "macro_run cannot execute macro_* actions")
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
                    return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
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
                MCPError.ACTION_NOT_FOUND, f"Unsupported session action: '{action}'",
                hint=f"Valid session actions: {', '.join(TOOL_ACTIONS['session'])}",
            )

        if tool_name == "truncation":
            action = args.get("action")
            if action == "continue":
                token = args.get("token")
                if not token:
                    return make_error(MCPError.INVALID_ARGS, "token required",
                                     hint="Provide the 'token' from a previous truncated response's _continue field.")
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
            return make_error(MCPError.ACTION_NOT_FOUND, f"Unsupported truncation action: '{action}'",
                             hint="The only valid action is 'continue'.")

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
                MCPError.ACTION_NOT_FOUND, f"Unsupported bookmark action: '{action}'",
                hint=f"Valid bookmark actions: {', '.join(TOOL_ACTIONS['bookmarks'])}",
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

    def _normalize_batch_call(self, call: Any, idx: int) -> tuple[Optional[str], Any, Optional[dict]]:
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
                return None, {}, make_error(MCPError.INVALID_ARGS, f"Call at index {idx} is empty")
            if ":" in raw:
                name, action = raw.split(":", 1)
                name = name.strip()
                action = action.strip()
                if not name:
                    return None, {}, make_error(MCPError.INVALID_ARGS, f"Call at index {idx} missing tool name")
                call_args = {"action": action} if action else {}
                return name, call_args, None
            return raw, {}, None
        if not isinstance(call, dict):
            return None, {}, make_error(MCPError.INVALID_ARGS, f"Call at index {idx} must be an object or string")

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

    def _handle_batch(self, args):
        calls = args.get("calls", [])
        if not isinstance(calls, list):
            return make_error(MCPError.INVALID_ARGS, "calls must be a list of call objects or 'tool:action' strings")
        if not calls:
            return make_error(MCPError.BATCH_EMPTY, "No calls provided in batch",
                             hint="Provide at least one call: batch(calls=[{name: 'tool', arguments: {...}}])")
        if len(calls) > MAX_BATCH_CALLS:
            return make_error(MCPError.BATCH_TOO_LARGE, f"Too many batch calls ({len(calls)}, max {MAX_BATCH_CALLS})",
                             hint=f"Split into multiple batch requests of {MAX_BATCH_CALLS} or fewer calls.")

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
            resolved_name = TOOL_ALIASES.get(name, name) if isinstance(name, str) else name

            if normalize_err:
                results.append({"index": idx, "name": name, "result": res})
                if res.get("error") and not continue_on_error:
                    break
                continue
            elif not name:
                res = make_error(MCPError.INVALID_ARGS, f"Call at index {idx} missing name field",
                                hint="Each batch call must have a name field specifying the tool.")
            elif not isinstance(name, str):
                res = make_error(MCPError.INVALID_ARGS, f"Call at index {idx} has non-string name")
            elif name == "batch":
                res = make_error(MCPError.INVALID_ARGS, "Nested batch calls are not allowed")
            elif resolved_name not in TOOLS:
                res = make_error(MCPError.INVALID_ARGS, f"Unknown tool {name} in batch call at index {idx}",
                                hint=f"Valid tools include: {', '.join(TOOLS[:10])}... Use tools/list for full list.")
            elif call_args is None:
                call_args = {}
                res = self._execute_tool(name, call_args)
            elif not isinstance(call_args, dict):
                res = make_error(MCPError.INVALID_ARGS, f"Call at index {idx} has non-object arguments")
            else:
                cleaned_args, _ = self._extract_response_options(call_args)
                res = self._execute_tool(name, cleaned_args)
                if isinstance(cleaned_args, dict):
                    res = self._cache_next_page(resolved_name or name, cleaned_args, res)
                    self._record_activity(resolved_name or name, cleaned_args, res)
            results.append({"index": idx, "name": name, "result": res})
            if res.get("error") and not continue_on_error:
                break
        errors = sum(1 for item in results if isinstance(item.get("result"), dict) and item["result"].get("error"))
        return {
            "ok": True,
            "results": results,
            "count": len(results),
            "summary": {
                "total": len(results),
                "ok": len(results) - errors,
                "errors": errors,
                "stopped_on_error": bool(errors and not continue_on_error and len(results) < len(calls)),
            },
        }

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
            mode = self.default_tools_list_mode
            if self.monolithic_tool_descriptions:
                mode = "full"
            tools = [
                {
                    "name": t,
                    "description": (
                        TOOL_DESCRIPTIONS.get(t, "")
                        if mode == "full"
                        else (
                            build_tool_description_lean(t)
                            if mode == "lean"
                            else build_tool_description_ultra(t)
                        )
                    ),
                    "inputSchema": (
                        build_input_schema(t)
                        if mode == "full"
                        else (
                            build_input_schema_lean(t)
                            if mode == "lean"
                            else build_input_schema_ultra(t)
                        )
                    ),
                }
                for t in TOOLS
                if t not in HIDDEN_TOOLS_IN_LIST
            ]
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools, "mode": mode}}
        if m == "tools/call":
            tn, args = p.get("name"), p.get("arguments", {})
            if isinstance(args, dict):
                call_args, response_opts = self._extract_response_options(args)
            else:
                call_args = args
                response_opts = self._default_response_options()
            if tn == "batch":
                if not isinstance(call_args, dict):
                    res = make_error(MCPError.INVALID_ARGS, "arguments must be an object")
                else:
                    res = self._handle_batch(call_args)
            else:
                res = self._execute_tool(tn, call_args)
                if isinstance(call_args, dict):
                    resolved_tn = TOOL_ALIASES.get(tn, tn) if isinstance(tn, str) else tn
                    res = self._cache_next_page(resolved_tn or "", call_args, res)
                    self._record_activity(resolved_tn or "", call_args, res)
            res = self._prepare_response_payload(res, response_opts)
            is_error = bool(isinstance(res, dict) and res.get("error"))
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "content": [{"type": "text", "text": self._serialize_payload(res, response_opts)}],
                    "isError": is_error,
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
                    output = (json.dumps(resp, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
                    rs.write(output)
                    rs.flush()
            except Exception:
                continue


if __name__ == "__main__":
    try:
        server = IDAMCPServer()
        server.run()
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)
