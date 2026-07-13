"""
Intelligence layer for IDA Pro MCP.

Provides local embedding models through llama-server.

Architecture:
  BgeCodeEmbedder      — compatibility name for the model-profile embedder
  FunctionEmbeddingIndex — per-binary SQLite embedding store
  BehaviorClassifier   — zero-shot via cosine sim to anchor descriptions
  ContextAssembler     — orchestrates everything, produces context_pack per call

Environment variables:
  IDA_MCP_EMBED_SERVER_BIN   path to llama-server binary
  IDA_MCP_EMBED_MODEL        path to .gguf file
  IDA_MCP_EMBED_PORT         port (default: random 18100-19000)
  IDA_MCP_EMBED_THREADS      CPU threads (default: cpu_count // 2)
  IDA_MCP_EMBED_BATCH_THREADS CPU threads for batched indexing (default: up to 16)
  IDA_MCP_EMBED_PARALLEL     llama.cpp embedding slots (default: CPU-adaptive, up to 4)
  IDA_MCP_EMBED_CTX          context tokens (default: 2048)
  IDA_MCP_EMBED_IDLE_TIMEOUT seconds to retain an idle embedding server (default: 15)
  IDA_MCP_DECOMP_DOCUMENT_FRACTION fraction of context used by full-decomp documents (default: 0.20)
  IDA_MCP_DECOMP_DOCUMENT_CHARS explicit full-decomp document character budget
  IDA_MCP_EMBED_DISABLED     set to 1 to disable semantic embeddings

Manual override:
  The installer (or a user) may write an `embedder.json` file under the
  install root / cache dir / user config dir to pin a specific model and
  server binary. This is the only way to override discovery when the
  defaults are not on PATH and env vars cannot be set. See
  `write_embedder_state()` and `_read_embedder_state()` for the schema.

Discovery:
  `_find_llama_server()` and `_find_model()` are fully cross-platform.
  On Windows they look under the install root, %LOCALAPPDATA%\\Programs,
  %USERPROFILE%\\scoop\\apps\\llama.cpp, %ProgramFiles%\\llama.cpp\\bin
  and other conventional locations, and they accept `llama-server.exe`
  alongside the bare `llama-server` name everywhere.
"""

from __future__ import annotations

import atexit
import contextlib
import glob
import hashlib
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .embeddings import NOISE_WORDS, FunctionEmbeddingIndex  # noqa: F401
from .model_profiles import (
    BGE_CODE_V1,
    EmbeddingModelProfile,
    get_model_profile,
    model_dimension,
    profile_from_model,
)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_SCRIPT_DIR))

try:
    from ..config import CACHE_DIR
except ImportError:
    try:
        from host.config import CACHE_DIR
    except ImportError:
        CACHE_DIR = os.path.join(os.path.expanduser("~"), ".local", "state", "ida-pro-mcp")

os.makedirs(CACHE_DIR, exist_ok=True)
_EMBED_LEASE_FILE = os.path.join(CACHE_DIR, "ida-mcp-embed-server-lease.json")
_MODEL_PATH_CACHE: tuple[str, str] | None = None


def hash_file(path: str, max_bytes: int | None = None) -> str:
    h = hashlib.sha256()
    read_bytes = 0
    with open(path, "rb") as f:
        while True:
            chunk_size = 1024 * 1024
            if max_bytes is not None:
                remaining = max_bytes - read_bytes
                if remaining <= 0:
                    break
                chunk_size = min(chunk_size, remaining)
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            read_bytes += len(chunk)
    return h.hexdigest()


def _file_fingerprint(path: str, deep_hash: bool = False) -> dict:
    out = {
        "path": path,
        "exists": False,
        "size": 0,
        "mtime_ns": 0,
        "sha256_head_16mb": "",
    }
    if not path or not os.path.isfile(path):
        return out
    st = os.stat(path)
    out["exists"] = True
    out["size"] = int(st.st_size)
    out["mtime_ns"] = int(st.st_mtime_ns)
    try:
        out["sha256_head_16mb"] = hash_file(path, max_bytes=16 * 1024 * 1024)
    except OSError:
        out["sha256_head_16mb"] = ""
    if deep_hash:
        try:
            out["sha256_full"] = hash_file(path)
        except OSError:
            out["sha256_full"] = ""
    return out


def model_fingerprint(path: str, deep_hash: bool = False) -> dict:
    return _file_fingerprint(path, deep_hash=deep_hash)


def server_fingerprint(path: str, deep_hash: bool = False) -> dict:
    return _file_fingerprint(path, deep_hash=deep_hash)

def _install_root() -> str:
    """Compute the installer-managed install root.

    Mirrors `installer.runtime.get_install_root()` but is inlined here so the
    host does not pull in installer (which would create a circular import —
    the installer itself imports this module).
    """
    override = os.environ.get("IDA_PRO_MCP_HOME")
    if override:
        return os.path.realpath(os.path.expanduser(override))
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            str(Path.home()), "AppData", "Local"
        )
        return os.path.realpath(os.path.join(base, "ida-pro-mcp"))
    return os.path.realpath(
        os.path.join(str(Path.home()), ".local", "share", "ida-pro-mcp")
    )


def _llama_server_binary_names() -> tuple[str, ...]:
    """Return the platform-appropriate binary name variants for llama-server."""
    if sys.platform == "win32":
        return ("llama-server.exe", "llama-server")
    return ("llama-server", "llama-server.exe")


def _is_executable(path: str) -> bool:
    """Cross-platform 'is this a runnable binary' check.

    On Windows `os.access(path, os.X_OK)` is a no-op (any existing file
    passes), so we also require a recognized executable extension.
    """
    if not path or not os.path.isfile(path):
        return False
    if sys.platform == "win32":
        low = path.lower()
        return low.endswith((".exe", ".bat", ".cmd"))
    return os.access(path, os.X_OK)


EMBEDDER_STATE_FILE = "embedder.json"


def _read_embedder_state() -> dict:
    """Load the optional manual-override `embedder.json` config file.

    The file may live in any of (first match wins):
      1. <install_root>/embedder.json      — written by the installer
      2. <cache_dir>/embedder.json         — runtime override
      3. <user-config>/ida-pro-mcp/embedder.json
         - Windows: %APPDATA%\\ida-pro-mcp
         - POSIX:   $XDG_CONFIG_HOME/ida-pro-mcp  or  ~/.config/ida-pro-mcp
    """
    candidates: list[str] = []
    with contextlib.suppress(Exception):
        candidates.append(os.path.join(_install_root(), EMBEDDER_STATE_FILE))
    with contextlib.suppress(Exception):
        candidates.append(os.path.join(CACHE_DIR, EMBEDDER_STATE_FILE))
    try:
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA") or os.path.join(
                str(Path.home()), "AppData", "Roaming"
            )
            candidates.append(os.path.join(appdata, "ida-pro-mcp", EMBEDDER_STATE_FILE))
        else:
            xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
                str(Path.home()), ".config"
            )
            candidates.append(os.path.join(xdg, "ida-pro-mcp", EMBEDDER_STATE_FILE))
    except Exception:
        pass
    for p in candidates:
        if not p or not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            data.setdefault("_source", p)
            return data
    return {}


def _select_state_path(value: Any) -> str:
    """Resolve a `embedder.json` override into a concrete file path.

    Accepts a single string or a list of strings (the first existing file
    wins). Expands ~ and env vars. Returns "" if nothing usable.
    """
    if value is None or value is False:
        return ""
    if isinstance(value, str):
        candidates: list[str] = [value]
    elif isinstance(value, list):
        candidates = [str(x) for x in value if x]
    else:
        return ""
    for c in candidates:
        try:
            expanded = os.path.expandvars(os.path.expanduser(c))
        except Exception:
            continue
        if os.path.isfile(expanded):
            return os.path.abspath(expanded)
    return ""


def write_embedder_state(
    install_root: str | os.PathLike,
    *,
    model_path: str = "",
    server_bin: str = "",
    profile: str = "",
    disabled: bool | None = None,
) -> str:
    """Persist a manual embedder override to `<install_root>/embedder.json`.

    Mirrors the installer pattern used for `ida-install.json` so a user (or
    a future installer subcommand) can pin the llama-server binary and the
    bge-code-v1 GGUF without relying on env vars or PATH.

    Returns the path of the written file.
    """
    root = os.fspath(install_root)
    os.makedirs(root, exist_ok=True)
    state_path = os.path.join(root, EMBEDDER_STATE_FILE)
    payload: dict[str, Any] = {
        "updated_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
    }
    if model_path:
        payload["model_path"] = os.path.abspath(os.path.expanduser(model_path))
    if server_bin:
        payload["server_bin"] = os.path.abspath(os.path.expanduser(server_bin))
    if profile:
        selected = get_model_profile(profile)
        if selected is None and profile != "custom":
            raise ValueError(f"unknown embedding model profile: {profile}")
        payload["profile"] = profile
    if disabled is not None:
        payload["disabled"] = bool(disabled)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return state_path


def _find_llama_server() -> str:
    """Locate llama-server binary.

    Resolution order:
      1. `IDA_MCP_EMBED_SERVER_BIN` env var (string or `;`-separated list)
      2. Manual override in `embedder.json` (`server_bin`)
      3. Install root: `<install_root>/bin/llama-server[.exe]`,
         `<install_root>/llama-server[.exe]`
      4. Per-platform conventional install dirs
         - Linux:  `~/.local/bin`, `/usr/local/bin`, `/usr/bin`
         - macOS:  `/usr/local/bin`, `/opt/homebrew/bin`, `/opt/local/bin`
         - Windows: %ProgramFiles%\\llama.cpp\\bin,
                    %ProgramFiles(x86)%\\llama.cpp\\bin,
                    %LOCALAPPDATA%\\Programs\\llama.cpp\\bin,
                    %USERPROFILE%\\scoop\\apps\\llama.cpp\\current,
                    %USERPROFILE%\\scoop\\apps\\llama.cpp\\current\\bin
      5. `shutil.which()` for both `llama-server` and `llama-server.exe`
      6. Project-local: `<project>/bin/llama-server[.exe]`,
         `<project>/llama-server[.exe]`
    """
    def _accept(path: str) -> str:
        if not path:
            return ""
        try:
            expanded = os.path.expandvars(os.path.expanduser(path))
        except Exception:
            return ""
        if _is_executable(expanded):
            return os.path.abspath(expanded)
        # Allow directory pointers: if a directory is supplied, scan it.
        if os.path.isdir(expanded):
            for n in _llama_server_binary_names():
                cand = os.path.join(expanded, n)
                if _is_executable(cand):
                    return os.path.abspath(cand)
        return ""

    # 1) explicit env var (string or list)
    env_val = os.environ.get("IDA_MCP_EMBED_SERVER_BIN", "")
    if env_val:
        for piece in re.split(r"[;:]", env_val):
            out = _accept(piece.strip())
            if out:
                return out

    # 2) embedder.json manual override
    state = _read_embedder_state()
    manual = _select_state_path(state.get("server_bin"))
    if manual:
        return manual

    # 3–4) install root and per-platform conventional directories
    install_root = _install_root()
    home = str(Path.home())
    roots: list[str] = [install_root, os.path.join(install_root, "bin")]
    if sys.platform == "win32":
        roots.extend(
            [
                os.path.join(home, "scoop", "apps", "llama.cpp", "current"),
                os.path.join(home, "scoop", "apps", "llama.cpp", "current", "bin"),
                os.path.join(
                    os.environ.get("ProgramFiles", r"C:\Program Files"),
                    "llama.cpp",
                    "bin",
                ),
                os.path.join(
                    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                    "llama.cpp",
                    "bin",
                ),
                os.path.join(
                    os.environ.get("LOCALAPPDATA", ""), "Programs", "llama.cpp", "bin"
                ),
                os.path.join(
                    os.environ.get("LOCALAPPDATA", ""), "Programs", "llama.cpp"
                ),
            ]
        )
    elif sys.platform == "darwin":
        roots.extend(
            [
                os.path.join(home, ".local", "bin"),
                "/usr/local/bin",
                "/opt/homebrew/bin",
                "/opt/local/bin",
                "/usr/bin",
            ]
        )
    else:
        roots.extend(
            [
                os.path.join(home, ".local", "bin"),
                "/usr/local/bin",
                "/usr/bin",
            ]
        )

    seen: set[str] = set()
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for n in _llama_server_binary_names():
            cand = os.path.join(root, n)
            ap = os.path.abspath(cand)
            if ap in seen:
                continue
            seen.add(ap)
            if _is_executable(cand):
                return ap

    # 5) PATH lookup for both name variants
    for n in _llama_server_binary_names():
        resolved = shutil.which(n)
        if resolved and _is_executable(resolved):
            return os.path.abspath(resolved)

    # 6) project-local candidates
    for n in _llama_server_binary_names():
        for c in (
            os.path.join(_PROJECT_ROOT, "bin", n),
            os.path.join(_PROJECT_ROOT, n),
        ):
            if _is_executable(c):
                return os.path.abspath(c)

    return ""  # semantic embeddings remain unavailable


def _find_model() -> str:
    """Locate the embedding GGUF model.

    Resolution order:
      1. `IDA_MCP_EMBED_MODEL` env var (string or `;`-separated list)
      2. Manual override in `embedder.json` (`model_path`)
      3. Project-local model files matching the selected profile
      4. Install-root model files matching the selected profile
      5. User home: `~/models`, `~/Downloads`, `~/Documents`
      6. Hugging Face cache snapshots matching the selected profile
    """
    global _MODEL_PATH_CACHE
    state = _read_embedder_state()
    requested_profile = str(
        os.environ.get("IDA_MCP_EMBED_PROFILE") or state.get("profile") or "bge-code-v1"
    ).strip().lower()
    requested_profile = (get_model_profile(requested_profile) or BGE_CODE_V1).key
    cache_key = requested_profile
    if _MODEL_PATH_CACHE is not None and _MODEL_PATH_CACHE[0] == cache_key:
        return _MODEL_PATH_CACHE[1]

    # 1) explicit env var
    env_val = os.environ.get("IDA_MCP_EMBED_MODEL", "")
    if env_val:
        for piece in re.split(r"[;:]", env_val):
            cand = piece.strip()
            if not cand:
                continue
            try:
                expanded = os.path.expandvars(os.path.expanduser(cand))
            except Exception:
                continue
            if os.path.isfile(expanded):
                selected = os.path.abspath(expanded)
                _MODEL_PATH_CACHE = (cache_key, selected)
                return selected

    # 2) embedder.json manual override
    manual = _select_state_path(state.get("model_path"))
    state_profile = str(state.get("profile") or "").strip().lower()
    if state_profile:
        state_profile = (get_model_profile(state_profile) or BGE_CODE_V1).key
    if manual and (
        (
            not state_profile
            and profile_from_model(manual).key == requested_profile
        )
        or state_profile == requested_profile
    ):
        _MODEL_PATH_CACHE = (cache_key, manual)
        return manual

    home = str(Path.home())
    install_root = _install_root()
    candidates: list[str] = []
    profile = get_model_profile(requested_profile) or BGE_CODE_V1
    model_filenames = profile.filename_patterns
    if not model_filenames:
        _MODEL_PATH_CACHE = (cache_key, "")
        return ""
    bases = [_PROJECT_ROOT, install_root, os.path.join(install_root, "models"),
             os.path.join(home, "models"),
             os.path.join(home, "Downloads"),
             os.path.join(home, "Documents")]
    for base in bases:
        if not base:
            continue
        for pattern in model_filenames:
            candidates.extend(glob.glob(os.path.join(base, pattern)))

    seen: set[str] = set()
    for c in candidates:
        try:
            p = os.path.abspath(c)
        except Exception:
            continue
        if p in seen:
            continue
        seen.add(p)
        if os.path.isfile(p):
            _MODEL_PATH_CACHE = (cache_key, p)
            return p

    # 6) Hugging Face cache snapshots for local model files
    hf_root = os.path.join(home, ".cache", "huggingface", "hub")
    if os.path.isdir(hf_root):
        for p in glob.glob(
            os.path.join(hf_root, "models--*", "snapshots", "*", model_filenames[0])
        ):
            if os.path.isfile(p):
                selected = os.path.abspath(p)
                _MODEL_PATH_CACHE = (cache_key, selected)
                return selected

    _MODEL_PATH_CACHE = (cache_key, "")
    return ""


def _safe_int_env(key: str, default: str) -> int:
    try:
        return int(os.environ.get(key, default))
    except (ValueError, TypeError):
        return int(default)


def _safe_float_env(key: str, default: str) -> float:
    try:
        return float(os.environ.get(key, default))
    except (ValueError, TypeError):
        return float(default)


def _available_cpu_count() -> int:
    """Return CPUs usable by this process, respecting Linux CPU affinity."""
    get_affinity = getattr(os, "sched_getaffinity", None)
    if get_affinity is not None:
        try:
            count = len(get_affinity(0))
            if count > 0:
                return count
        except OSError:
            pass
    return max(1, os.cpu_count() or 1)


_EMBED_CPU_COUNT = _available_cpu_count()
EMBED_CTX = _safe_int_env("IDA_MCP_EMBED_CTX", "2048")
EMBED_CHARS_PER_TOKEN = _safe_float_env("IDA_MCP_EMBED_CHARS_PER_TOKEN", "3.0")
DECOMP_DOCUMENT_FRACTION = _safe_float_env("IDA_MCP_DECOMP_DOCUMENT_FRACTION", "0.20")
DECOMP_DOCUMENT_CHARS = _safe_int_env("IDA_MCP_DECOMP_DOCUMENT_CHARS", "0")
EMBED_THREADS = _safe_int_env(
    "IDA_MCP_EMBED_THREADS",
    str(max(1, _EMBED_CPU_COUNT // 2))
)
# Indexing submits multiple full function signatures at once.  llama.cpp can
# use more CPU threads for that batch work than for latency-sensitive one-off
# semantic queries.  Cap the default so high-core machines remain usable.
EMBED_BATCH_THREADS = _safe_int_env(
    "IDA_MCP_EMBED_BATCH_THREADS",
    str(min(16, _EMBED_CPU_COUNT)),
)
# An array sent to llama.cpp's /embeddings endpoint only runs concurrently
# when it has multiple sequence slots.  ``--parallel 1`` made our client-side
# batches effectively serial and could turn a small fast-index commit into a
# minute-long request.  Slots consume KV cache, so remain conservative.
EMBED_PARALLEL = max(1, min(4, _safe_int_env(
    "IDA_MCP_EMBED_PARALLEL", str(max(1, _EMBED_CPU_COUNT // 4))
)))
EMBED_REQUEST_TIMEOUT = _safe_float_env("IDA_MCP_EMBED_REQUEST_TIMEOUT", "5.0")
# A batch contains full decompilations, so it can legitimately take longer
# than the interactive single-query deadline.  Keep the two independently
# tunable: search stays responsive while indexing can complete on CPU-only
# hosts.
EMBED_BATCH_REQUEST_TIMEOUT = _safe_float_env(
    "IDA_MCP_EMBED_BATCH_REQUEST_TIMEOUT", "60.0"
)
EMBED_LOCK_TIMEOUT = _safe_float_env("IDA_MCP_EMBED_LOCK_TIMEOUT", "30.0")
EMBED_MAX_REQUESTS = _safe_int_env("IDA_MCP_EMBED_MAX_REQUESTS", "512")
EMBED_MAX_RSS_MB = _safe_int_env("IDA_MCP_EMBED_MAX_RSS_MB", "0")
EMBED_MAX_RSS_GROWTH_MB = _safe_int_env("IDA_MCP_EMBED_MAX_RSS_GROWTH_MB", "768")
EMBED_MAX_FAILURES = _safe_int_env("IDA_MCP_EMBED_MAX_FAILURES", "2")
# Keep the large CPU model process only while it is useful.  Some llama.cpp
# builds can retain a busy worker after a cancelled request, so an idle
# server is both unnecessary memory pressure and a reliability risk.
EMBED_IDLE_TIMEOUT = max(0.0, _safe_float_env("IDA_MCP_EMBED_IDLE_TIMEOUT", "15.0"))
# An explicit operation can spend a little time decompiling before its first
# embedding request.  Give that first request a longer grace period; every
# completed request switches back to the normal short idle timeout above.
EMBED_ACTIVATION_GRACE_TIMEOUT = max(
    EMBED_IDLE_TIMEOUT,
    _safe_float_env("IDA_MCP_EMBED_ACTIVATION_GRACE_TIMEOUT", "60.0"),
)
EMBED_DISABLED = os.environ.get("IDA_MCP_EMBED_DISABLED", "") in ("1", "true", "yes")
INTEL_PROFILE = os.environ.get("IDA_MCP_INTEL_PROFILE", "") in ("1", "true", "yes")

_EMBED_LEASE_SCHEMA = 2


def _embed_request_lock_path() -> str:
    """Keep the queue lock colocated with an overridable lease file."""
    return _EMBED_LEASE_FILE + ".request.lock"


def _embed_start_lock_path() -> str:
    """Serialize lease check/start across independent MCP host processes."""
    return _EMBED_LEASE_FILE + ".startup.lock"


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _process_command(pid: int) -> str:
    if sys.platform.startswith("linux"):
        try:
            return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(
                "utf-8", errors="replace"
            ).strip()
        except OSError:
            return ""
    return ""


def _process_start_token(pid: int) -> str:
    if sys.platform.startswith("linux"):
        try:
            fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
            return fields[21] if len(fields) > 21 else ""
        except OSError:
            return ""
    return ""


def _process_rss_bytes(pid: int) -> int:
    if sys.platform.startswith("linux"):
        try:
            for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            pass
    return 0


class EmbeddingQueueTimeout(TimeoutError):
    """The shared embedder is busy, but has not failed or been abandoned."""


class _InterProcessLock:
    """Small cross-platform advisory file lock with a bounded wait."""

    def __init__(self, path: str, timeout: float):
        self.path = path
        self.timeout = max(0.0, timeout)
        self.handle = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.handle = open(self.path, "a+b")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    self.handle.seek(0)
                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    self.handle.close()
                    self.handle = None
                    raise EmbeddingQueueTimeout("embedding request queue is busy") from None
                time.sleep(0.05)

    def __exit__(self, exc_type, exc, tb):
        if self.handle is None:
            return False
        try:
            if sys.platform == "win32":
                import msvcrt
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None
        return False


_IDENT_RE = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]{2,}\b')
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _identifier_terms(ident: str) -> list[str]:
    terms: list[str] = []
    for chunk in re.split(r"[_\W]+", str(ident or "")):
        if not chunk:
            continue
        split = [p for p in _CAMEL_BOUNDARY_RE.split(chunk) if p]
        if len(split) == 1:
            terms.append(chunk)
        else:
            terms.extend(split)
    return terms


def _extract_signature(pseudocode: str, max_idents: int = 40) -> str:
    """
    Extract a compact behavioral signature from decompiled pseudocode.

    Keeps only meaningful identifiers (function calls, constants, API names)
    and drops noise tokens so the embedding focuses on behavioral content.
    This gives ~5-10x better cosine similarity against short behavior anchors
    than embedding the full pseudocode.

    Example: "int aes_encrypt(uint8_t *buf, uint32_t *rk) { sub_bytes(state); ..."
    → "aes_encrypt sub_bytes shift_rows mix_columns add_round_key key_schedule"
    """
    idents = _IDENT_RE.findall(pseudocode)
    seen: set = set()
    out: list = []
    for ident in idents:
        for term in _identifier_terms(ident):
            lo = term.lower()
            if lo in NOISE_WORDS or lo in seen:
                continue
            seen.add(lo)
            out.append(term)
            if len(out) >= max_idents:
                return " ".join(out)
    return " ".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Explicit unavailable result when llama-server or the model is absent
# ─────────────────────────────────────────────────────────────────────────────

class _EmbedResult:
    """Result of an embedding call.

    Production invariant: ``vector`` is *always* from the declared
    ``backend``.  When ``ok`` is False, ``vector`` is None and callers
    MUST surface the failure rather than proceed as if nothing happened.
    The old TF-IDF fallback violated this by returning garbage vectors
    whenever the model was unavailable.
    """

    __slots__ = ("vector", "backend", "ok")

    def __init__(self, vector: list[float] | None, backend: str, ok: bool):
        self.vector = vector
        self.backend = backend
        self.ok = ok

    def __repr__(self) -> str:
        return f"_EmbedResult(backend={self.backend!r}, ok={self.ok})"


# ─────────────────────────────────────────────────────────────────────────────
# BgeCodeEmbedder — profile-aware llama-server subprocess manager
# ─────────────────────────────────────────────────────────────────────────────

class BgeCodeEmbedder:
    """
    Manages a llama-server subprocess for the selected embedding profile.
    Lazy start on first embed() call.  Thread-safe singleton per process.

    No silent fallback: if the model binary or server is unavailable,
    ``embed()`` returns an ``_EmbedResult`` with ``ok=False`` so that
    callers can surface the degraded state to the user rather than
    proceeding with garbage vectors.
    """

    _instance: BgeCodeEmbedder | None = None
    _lock = threading.Lock()

    def __new__(cls) -> BgeCodeEmbedder:
        with cls._lock:
            if cls._instance is None:
                obj = super().__new__(cls)
                obj._init()
                cls._instance = obj
        return cls._instance

    def _init(self) -> None:
        self._server_bin   = _find_llama_server()
        self._model_path   = _find_model()
        state = _read_embedder_state()
        requested_profile = os.environ.get("IDA_MCP_EMBED_PROFILE") or state.get("profile")
        self._profile: EmbeddingModelProfile = profile_from_model(
            self._model_path, str(requested_profile or "")
        )
        self._dimension = model_dimension(self._model_path, self._profile)
        self._port: int | None = None
        self._proc: subprocess.Popen | None = None
        self._ready        = False
        self._start_lock   = threading.Lock()
        self._use_llama    = (bool(self._server_bin) and bool(self._model_path)
                              and not EMBED_DISABLED)
        # Cached anchor embeddings for BehaviorClassifier
        self._anchor_cache: dict[str, list[float]] = {}
        # Full decompilations are much longer than search snippets, so keep
        # the cap CPU-adaptive.  Start at the server's slot count, though: a
        # 1/2/3/4 ramp wastes RPCs without making a batch safer.
        adaptive_max_batch = max(1, min(4, _EMBED_CPU_COUNT // 4))
        self._max_batch_size = max(
            1,
            min(32, _safe_int_env("IDA_MCP_EMBED_MAX_BATCH", str(adaptive_max_batch))),
        )
        self._batch_size = max(
            1,
            min(
                self._max_batch_size,
                _safe_int_env(
                    "IDA_MCP_EMBED_BATCH", str(min(self._max_batch_size, EMBED_PARALLEL))
                ),
            ),
        )
        self._batch_lock = threading.Lock()
        self._owns_proc = False
        self._stop_registered = False
        self._consecutive_rpc_failures = 0
        self._max_rpc_failures = max(1, EMBED_MAX_FAILURES)
        self._last_batch_timeout = False
        self._last_recycle_reason = ""
        self._identity_cache: dict[str, Any] | None = None
        self._idle_lock = threading.Lock()
        self._idle_timer: threading.Timer | None = None
        self._idle_generation = 0

    def status(self, probe: bool = False, deep_hash: bool = False) -> dict:
        server_ready = bool(self._ready)
        probe_error = ""
        if probe:
            if not server_ready and self._use_llama:
                server_ready = bool(self._start_server())
            elif self._port:
                try:
                    req = urllib.request.urlopen(f"http://127.0.0.1:{self._port}/health", timeout=2)
                    _hr = req.read()
                    server_ready = b'"status":"ok"' in _hr or b'"ok"' in _hr
                    self._ready = server_ready
                except Exception as exc:
                    server_ready = False
                    probe_error = str(exc)
            else:
                try:
                    if os.path.isfile(_EMBED_LEASE_FILE):
                        with open(_EMBED_LEASE_FILE, encoding="utf-8") as f:
                            lease = json.load(f)
                        lease_port = int(lease.get("port") or 0)
                        if lease_port > 0:
                            req = urllib.request.urlopen(
                                f"http://127.0.0.1:{lease_port}/health", timeout=2
                            )
                            if b'"status":"ok"' in req.read():
                                self._port = lease_port
                                self._ready = True
                                self._owns_proc = False
                                self._use_llama = True
                                server_ready = True
                except Exception as exc:
                    probe_error = str(exc)

        return {
            "backend": self.backend,
            "use_llama": bool(self._use_llama),
            "disabled_by_env": bool(EMBED_DISABLED),
            "server_bin": self._server_bin,
            "server_bin_exists": bool(self._server_bin and os.path.isfile(self._server_bin)),
            "model_path": self._model_path,
            "model_exists": bool(self._model_path and os.path.isfile(self._model_path)),
            "ready": bool(server_ready),
            "port": self._port,
            "owns_process": bool(self._owns_proc),
            "dim": self.dim,
            "profile": self._profile.key,
            "profile_name": self._profile.display_name,
            "model_license": self._profile.license,
            "query_document_prompts": bool(
                self._profile.query_prefix or self._profile.document_prefix
            ),
            "batch_size": int(self._batch_size),
            "max_batch_size": int(self._max_batch_size),
            "max_input_chars": self.max_input_chars,
            "decomp_document_chars": self.decomp_document_chars,
            "consecutive_rpc_failures": int(self._consecutive_rpc_failures),
            "last_recycle_reason": self._last_recycle_reason,
            "fingerprints": {
                "model": model_fingerprint(self._model_path, deep_hash=deep_hash),
                "server": server_fingerprint(self._server_bin, deep_hash=deep_hash),
            },
            "probe_error": probe_error,
        }

    # ── subprocess management ──────────────────────────────────────────────

    def _pick_port(self) -> int:
        env = os.environ.get("IDA_MCP_EMBED_PORT", "")
        if env and env.isdigit():
            return int(env)
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _lease_identity(self) -> dict[str, Any]:
        cached = getattr(self, "_identity_cache", None)
        if cached is not None:
            return dict(cached)
        model = model_fingerprint(self._model_path)
        server = server_fingerprint(self._server_bin)
        identity = {
            "profile": self._profile.key,
            "dimension": self.dim,
            "model_path": os.path.realpath(self._model_path) if self._model_path else "",
            "model_size": int(model.get("size") or 0),
            "model_mtime_ns": int(model.get("mtime_ns") or 0),
            "model_sha256_head": str(model.get("sha256_head_16mb") or ""),
            "server_path": os.path.realpath(self._server_bin) if self._server_bin else "",
            "server_size": int(server.get("size") or 0),
            "server_mtime_ns": int(server.get("mtime_ns") or 0),
        }
        self._identity_cache = identity
        return dict(identity)

    @staticmethod
    def _read_lease() -> dict[str, Any]:
        try:
            with open(_EMBED_LEASE_FILE, encoding="utf-8") as handle:
                lease = json.load(handle)
            return lease if isinstance(lease, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _write_lease(lease: dict[str, Any]) -> None:
        """Atomically publish a lease so readers never observe partial JSON."""
        directory = os.path.dirname(_EMBED_LEASE_FILE) or "."
        os.makedirs(directory, exist_ok=True)
        temporary = (
            f"{_EMBED_LEASE_FILE}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(lease, handle)
            os.replace(temporary, _EMBED_LEASE_FILE)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(temporary)

    @staticmethod
    def _server_json(port: int, endpoint: str, timeout: float = 2.0) -> Any:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/{endpoint.lstrip('/')}", timeout=timeout
        ) as response:
            return json.loads(response.read())

    def _lease_matches(self, lease: dict[str, Any]) -> bool:
        try:
            if int(lease.get("schema") or 0) != _EMBED_LEASE_SCHEMA:
                return False
            pid = int(lease.get("pid") or 0)
            owner_pid = int(lease.get("owner_pid") or 0)
            port = int(lease.get("port") or 0)
        except (TypeError, ValueError):
            return False
        if not _pid_alive(pid) or not _pid_alive(owner_pid) or port <= 0:
            return False
        expected_start = str(lease.get("process_start_token") or "")
        if expected_start and _process_start_token(pid) != expected_start:
            return False
        expected_owner_start = str(lease.get("owner_start_token") or "")
        if expected_owner_start and _process_start_token(owner_pid) != expected_owner_start:
            return False
        identity = self._lease_identity()
        for key, expected in identity.items():
            if lease.get(key) != expected:
                return False
        if lease.get("recycle_requested"):
            return False
        try:
            health = self._server_json(port, "health")
            if not isinstance(health, dict) or health.get("status") != "ok":
                return False
            props = self._server_json(port, "props")
            served_model = os.path.realpath(str(props.get("model_path") or ""))
            if served_model != identity["model_path"]:
                return False
        except Exception:
            return False
        return True

    def _pid_is_expected_server(self, pid: int, lease: dict[str, Any] | None = None) -> bool:
        command = _process_command(pid)
        if not command:
            # On platforms without process-command inspection, only terminate
            # a process represented by a current, identity-bearing lease.
            return bool(lease and int(lease.get("schema") or 0) == _EMBED_LEASE_SCHEMA)
        server_path = str((lease or {}).get("server_path") or self._server_bin or "")
        model_path = str((lease or {}).get("model_path") or self._model_path or "")
        return bool(
            "llama-server" in command
            and "--embedding" in command
            and (not server_path or server_path in command)
            and (not model_path or model_path in command)
        )

    def _retire_lease_process(self, lease: dict[str, Any], reason: str) -> None:
        try:
            pid = int(lease.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        if pid > 0 and _pid_alive(pid) and self._pid_is_expected_server(pid, lease):
            with contextlib.suppress(OSError):
                os.kill(pid, 15)
            deadline = time.monotonic() + 3.0
            while _pid_alive(pid) and time.monotonic() < deadline:
                time.sleep(0.05)
            if _pid_alive(pid):
                with contextlib.suppress(OSError):
                    os.kill(pid, 9)
        with contextlib.suppress(OSError):
            current = self._read_lease()
            if not current or current.get("pid") == lease.get("pid"):
                os.unlink(_EMBED_LEASE_FILE)
        self._last_recycle_reason = reason
        self._ready = False
        if getattr(self, "_proc", None) is not None and getattr(self._proc, "pid", None) == pid:
            # Popen.poll() reaps a terminated direct child.  Without it, a
            # timeout/recycle path can leave zombies under a long-lived host.
            with contextlib.suppress(Exception):
                self._proc.wait(timeout=0.1)
            self._proc = None
        self._owns_proc = False

    def _cancel_idle_shutdown(self) -> None:
        """Cancel a pending idle retirement before embedding work begins."""
        lock = getattr(self, "_idle_lock", None)
        if lock is None:
            return
        with lock:
            self._idle_generation += 1
            timer = self._idle_timer
            self._idle_timer = None
        if timer is not None:
            timer.cancel()

    def _schedule_idle_shutdown(self, timeout: float | None = None) -> None:
        """Retire an unused local server without affecting another host's lease."""
        delay = EMBED_IDLE_TIMEOUT if timeout is None else max(0.0, timeout)
        if delay <= 0.0:
            return
        lock = getattr(self, "_idle_lock", None)
        if lock is None:
            return
        with lock:
            self._idle_generation += 1
            generation = self._idle_generation
            previous = self._idle_timer
            timer = threading.Timer(delay, self._shutdown_if_idle, args=(generation,))
            timer.daemon = True
            self._idle_timer = timer
        if previous is not None:
            previous.cancel()
        timer.start()

    def _shutdown_if_idle(self, generation: int) -> None:
        lock = getattr(self, "_idle_lock", None)
        if lock is None:
            return
        with lock:
            if generation != self._idle_generation:
                return
            self._idle_timer = None
        # A request can have crossed the process boundary immediately before
        # this callback.  Ask llama.cpp before stopping anything.
        if self._server_has_active_slots():
            self._schedule_idle_shutdown()
            return
        self.stop()

    def _server_has_active_slots(self) -> bool:
        if not self._port or not self._read_lease():
            return False
        try:
            slots = self._server_json(self._port, "slots")
            return bool(
                isinstance(slots, list)
                and any(bool(slot.get("is_processing")) for slot in slots if isinstance(slot, dict))
            )
        except Exception:
            return False

    def _rss_limit_bytes(self) -> int:
        if EMBED_MAX_RSS_MB > 0:
            return EMBED_MAX_RSS_MB * 1024 * 1024
        try:
            model_size = os.path.getsize(self._model_path)
        except OSError:
            model_size = 0
        return max(2 * 1024**3, int(model_size * 2.0) + 512 * 1024**2)

    def _record_success_and_maybe_recycle(self) -> None:
        lease = self._read_lease()
        if not lease or not self._lease_matches(lease):
            return
        pid = int(lease.get("pid") or 0)
        rss = _process_rss_bytes(pid)
        baseline = int(lease.get("baseline_rss") or 0)
        count = int(lease.get("request_count") or 0) + 1
        lease.update({"request_count": count, "rss": rss, "updated_at": time.time()})
        reason = ""
        if EMBED_MAX_REQUESTS > 0 and count >= EMBED_MAX_REQUESTS:
            reason = f"request limit reached ({count})"
        elif rss and rss > self._rss_limit_bytes():
            reason = f"RSS limit exceeded ({rss // (1024 * 1024)} MiB)"
        elif baseline and rss - baseline > EMBED_MAX_RSS_GROWTH_MB * 1024 * 1024:
            reason = f"RSS growth exceeded ({(rss - baseline) // (1024 * 1024)} MiB)"
        if reason:
            self._retire_lease_process(lease, reason)
            return
        with contextlib.suppress(OSError):
            self._write_lease(lease)

    def _start_server(self) -> bool:
        with self._start_lock:
            try:
                with _InterProcessLock(_embed_start_lock_path(), EMBED_LOCK_TIMEOUT):
                    return self._start_server_locked()
            except EmbeddingQueueTimeout:
                # A peer is starting or replacing the shared server.  Do not
                # race it by spawning another process; a later call can attach.
                return False

    def _start_server_locked(self) -> bool:
        with contextlib.nullcontext():
            if self._ready:
                return True
            # Reuse existing shared embed server when available.
            # Check this regardless of _use_llama — paths may not have
            # been available at init time but a server is already running.
            lease = self._read_lease()
            if lease and self._lease_matches(lease):
                self._port = int(lease["port"])
                self._ready = True
                self._owns_proc = False
                self._use_llama = True
                return True
            if lease:
                self._retire_lease_process(lease, "stale or incompatible lease")
            # Re-check paths: they may not have been available at init
            # (e.g. embedder.json written after singleton creation).
            if not self._use_llama:
                self._server_bin = _find_llama_server()
                self._model_path = _find_model()
                state = _read_embedder_state()
                requested_profile = os.environ.get("IDA_MCP_EMBED_PROFILE") or state.get("profile")
                self._profile = profile_from_model(self._model_path, str(requested_profile or ""))
                self._dimension = model_dimension(self._model_path, self._profile)
                self._identity_cache = None
                self._use_llama = (
                    bool(self._server_bin) and bool(self._model_path)
                    and not EMBED_DISABLED
                )
            if not self._use_llama:
                return False
            self._port = self._pick_port()
            cmd = [
                self._server_bin,
                "--model",    self._model_path,
                "--embedding",
                "--port",     str(self._port),
                "--ctx-size", str(EMBED_CTX),
                "--batch-size", str(max(EMBED_CTX, 2048)),
                "--ubatch-size", str(min(max(256, EMBED_CTX // 4), 512)),
                "--pooling", "mean",
                "--parallel", str(min(EMBED_PARALLEL, self._max_batch_size)),
                "--threads",  str(EMBED_THREADS),
                "--threads-batch", str(EMBED_BATCH_THREADS),
                "--n-predict", "0",
                "--log-disable",
            ]
            try:
                # Ensure shared libraries are findable (e.g. libllama-server-impl.so
                # in non-standard locations like /usr/local/lib/ollama).
                _env = os.environ.copy()
                _lib_dir = os.path.dirname(self._server_bin)
                _existing = _env.get("LD_LIBRARY_PATH", "")
                _paths = [p for p in (_existing.split(":") + [_lib_dir]) if p]
                _env["LD_LIBRARY_PATH"] = ":".join(_paths)
                # Also search common install dirs for the shared lib
                for _d in ("/usr/local/lib/ollama", "/usr/local/lib"):
                    _so = os.path.join(_d, "libllama-server-impl.so")
                    if os.path.isfile(_so) and _d not in _paths:
                        _paths.append(_d)
                _env["LD_LIBRARY_PATH"] = ":".join(_paths)
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=_env,
                )
                self._owns_proc = True
                if isinstance(self._proc.pid, int) and not self._stop_registered:
                    atexit.register(self.stop)
                    self._stop_registered = True
            except OSError:
                self._ready = False
                return False

            # Wait for server ready (up to 60s — model load takes ~10s on this CPU)
            deadline = time.time() + 60.0
            while time.time() < deadline:
                time.sleep(1.0)
                try:
                    req = urllib.request.urlopen(
                        f"http://127.0.0.1:{self._port}/health", timeout=2
                    )
                    if b'"status":"ok"' in req.read():
                        self._ready = True
                        try:
                            pid = self._proc.pid if self._proc else 0
                            payload = {
                                "schema": _EMBED_LEASE_SCHEMA,
                                "pid": pid,
                                "owner_pid": os.getpid(),
                                "owner_start_token": _process_start_token(os.getpid()),
                                "process_start_token": _process_start_token(pid),
                                "port": self._port,
                                "baseline_rss": _process_rss_bytes(pid),
                                "request_count": 0,
                                "updated_at": time.time(),
                            }
                            payload.update(self._lease_identity())
                            self._write_lease(payload)
                        except Exception:
                            pass
                        return True
                except Exception:
                    pass
                if self._proc.poll() is not None:
                    self._ready = False
                    return False

            self._ready = False
            return False

    def stop(self) -> None:
        self._cancel_idle_shutdown()
        owned_pid = self._proc.pid if self._owns_proc and self._proc else None
        try:
            with open(_EMBED_LEASE_FILE, encoding="utf-8") as f:
                lease = json.load(f)
            lease_pid = int(lease.get("pid") or 0)
            if int(lease.get("owner_pid") or 0) == os.getpid() and lease_pid > 0:
                owned_pid = owned_pid or lease_pid
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            lease_pid = 0
        if owned_pid and self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()
                with contextlib.suppress(Exception):
                    self._proc.wait(timeout=2)
        elif owned_pid and self._proc is None:
            try:
                os.kill(owned_pid, 15)
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    try:
                        os.kill(owned_pid, 0)
                    except OSError:
                        break
                    time.sleep(0.05)
                else:
                    os.kill(owned_pid, 9)
            except OSError:
                pass
        if owned_pid:
            try:
                if lease_pid == owned_pid:
                    os.unlink(_EMBED_LEASE_FILE)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                pass
        self._ready = False
        self._proc = None
        self._owns_proc = False

    def ensure_ready(self) -> bool:
        """Explicitly start or attach to the shared embedding server.

        Routine tool enrichment must not make a cold model start.  Callers
        that genuinely need semantic work (indexing or semantic search) use
        this entry point first; the server then retires if no request arrives.
        """
        self._cancel_idle_shutdown()
        ready = bool(self._start_server())
        if ready:
            self._schedule_idle_shutdown(EMBED_ACTIVATION_GRACE_TIMEOUT)
        return ready

    # ── embedding ──────────────────────────────────────────────────────────

    @staticmethod
    def _extract_embedding(item):
        """Extract a plain float list from an embedding response item.

        Handles both the old dict format {"data": [{"embedding": [...]}]}
        and the new list format [{"embedding": [[...]]}] where the vector
        may be nested inside an outer list-of-lists.
        """
        if not isinstance(item, dict):
            return None
        vec = item.get("embedding")
        if vec is None:
            return None
        if isinstance(vec, list) and vec and isinstance(vec[0], list):
            vec = vec[0]
        if not isinstance(vec, list) or not vec:
            return None
        return [float(x) for x in vec]

    def _request_embeddings(
        self,
        texts: list[str],
        *,
        purpose: str,
        timeout: float,
    ) -> list[list[float]] | None:
        if not texts:
            return []
        # Do not make ordinary tools pay for a cold model start.  Explicit
        # indexing/search calls activate the backend with ensure_ready();
        # incidental context/behavior enrichment simply degrades gracefully.
        if not self._ready:
            return None
        self._cancel_idle_shutdown()
        try:
            with _InterProcessLock(
                _embed_request_lock_path(), min(EMBED_LOCK_TIMEOUT, timeout)
            ):
                # With the request lock held, an already-processing slot can
                # only be an abandoned request from a timed-out/older client.
                if self._server_has_active_slots():
                    self._retire_lease_process(
                        self._read_lease(), "abandoned embedding request"
                    )
                    return None
                profile = getattr(self, "_profile", BGE_CODE_V1)
                formatted = [profile.format_text(text, purpose) for text in texts]
                payload: str | list[str] = formatted[0] if len(formatted) == 1 else formatted
                body = json.dumps({"input": payload, "encoding_format": "float"}).encode()
                req = urllib.request.Request(
                    f"http://127.0.0.1:{self._port}/embeddings",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read())
            if isinstance(data, dict):
                rows = data.get("data") or []
            elif isinstance(data, list):
                rows = data
            else:
                rows = []
            if len(rows) != len(texts):
                raise RuntimeError("embedding response count mismatch")
            if all(isinstance(row, dict) and isinstance(row.get("index"), int) for row in rows):
                rows = sorted(rows, key=lambda row: row["index"])
            out: list[list[float]] = []
            for row in rows:
                vec = self._extract_embedding(row) if isinstance(row, dict) else None
                if vec is None:
                    raise RuntimeError("no embedding in response")
                vec = [x for x in vec if math.isfinite(x)]
                if not vec:
                    raise RuntimeError("empty embedding in response")
                if self.dim and len(vec) != self.dim:
                    raise RuntimeError(
                        f"embedding dimension mismatch: expected {self.dim}, got {len(vec)}"
                    )
                norm = math.sqrt(sum(x * x for x in vec)) or 1.0
                out.append([x / norm for x in vec])
            self._consecutive_rpc_failures = 0
            self._record_success_and_maybe_recycle()
            return out
        except EmbeddingQueueTimeout:
            # Another valid client owns the single-server queue.  This is a
            # load-shedding event, never evidence that the server is wedged.
            return None
        except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError) as exc:
            if isinstance(exc, (TimeoutError, socket.timeout)):
                self._last_batch_timeout = True
                self._retire_lease_process(self._read_lease(), "embedding request timeout")
            self._consecutive_rpc_failures += 1
            if self._consecutive_rpc_failures >= self._max_rpc_failures:
                # Transient failure — mark not-ready but allow retry.
                self._ready = False
                self._consecutive_rpc_failures = 0
            return None
        finally:
            # Even a failed request may leave a llama.cpp worker spinning.
            # The bounded idle lifecycle makes that state self-healing.
            if self._ready:
                self._schedule_idle_shutdown()

    def _llama_embed(self, text: str, purpose: str = "document") -> list[float] | None:
        rows = self._request_embeddings(
            [text], purpose=purpose, timeout=EMBED_REQUEST_TIMEOUT
        )
        return rows[0] if rows else None

    def _llama_embed_batch(
        self, texts: list[str], purpose: str = "document"
    ) -> list[list[float]] | None:
        if not texts:
            return []
        self._last_batch_timeout = False
        return self._request_embeddings(
            texts,
            purpose=purpose,
            timeout=max(EMBED_REQUEST_TIMEOUT, EMBED_BATCH_REQUEST_TIMEOUT),
        )

    def embed(self, text: str, purpose: str = "document") -> _EmbedResult:
        """Return an :class:`_EmbedResult` for *text*.

        When the real model is unavailable, ``result.ok`` is False and
        ``result.vector`` is None — callers MUST check this.  There is
        no silent fallback to a weaker backend.
        """
        if self._use_llama:
            vec = self._llama_embed(text, purpose=purpose)
            if vec is not None:
                return _EmbedResult(vec, self.backend, True)
        return _EmbedResult(None, "unavailable", False)

    def embed_vector(self, text: str, purpose: str = "document") -> list[float] | None:
        """Convenience wrapper returning the embedding vector or None.

        Use this when you only need the vector and want None to mean
        "embedding unavailable" without inspecting the full result object.
        """
        result = self.embed(text, purpose=purpose)
        return result.vector if result.ok else None

    def embed_query(self, text: str) -> _EmbedResult:
        return self.embed(text, purpose="query")

    def embed_query_vector(self, text: str) -> list[float] | None:
        return self.embed_vector(text, purpose="query")

    def embed_document(self, text: str) -> _EmbedResult:
        return self.embed(text, purpose="document")

    def embed_documents(self, texts: list[str]) -> list[_EmbedResult]:
        return self.embed_batch(texts, purpose="document")

    def embed_batch(
        self, texts: list[str], purpose: str = "document"
    ) -> list[_EmbedResult]:
        """Batch version of :meth:`embed`.  Each text gets its own result
        object so callers can identify exactly which items failed."""
        if not texts:
            return []
        if not self._use_llama:
            return [_EmbedResult(None, "unavailable", False) for _ in texts]
        out: list[_EmbedResult] = []

        def embed_chunk(chunk: list[str]) -> list[_EmbedResult]:
            if not chunk:
                return []
            vecs = self._llama_embed_batch(chunk, purpose=purpose)
            if vecs is not None:
                self._last_batch_timeout = False
                with self._batch_lock:
                    max_batch = int(getattr(self, "_max_batch_size", 32) or 32)
                    if self._batch_size < max_batch and len(chunk) == self._batch_size:
                        self._batch_size += 1
                return [_EmbedResult(v, self.backend, True) for v in vecs]
            # llama-server does not reliably cancel work when an HTTP client
            # times out. Never enqueue recursive retries behind abandoned work;
            # the timed-out server has already been recycled.
            if getattr(self, "_last_batch_timeout", False):
                with self._batch_lock:
                    self._batch_size = max(1, min(self._batch_size, len(chunk) // 2 or 1))
            return [_EmbedResult(None, "unavailable", False) for _ in chunk]

        i = 0
        while i < len(texts):
            with self._batch_lock:
                bs = self._batch_size
            chunk = texts[i : i + bs]
            out.extend(embed_chunk(chunk))
            i += len(chunk)
            if not self._ready and self._last_recycle_reason:
                out.extend(
                    _EmbedResult(None, "unavailable", False)
                    for _ in texts[i:]
                )
                break
        return out

    @property
    def dim(self) -> int:
        return int(getattr(self, "_dimension", 0) or 0)

    @property
    def max_input_chars(self) -> int:
        """Conservative character budget derived from the configured context."""
        usable_tokens = max(512, EMBED_CTX - 128)
        return max(1024, min(32768, int(usable_tokens * max(1.0, EMBED_CHARS_PER_TOKEN))))

    @property
    def decomp_document_chars(self) -> int:
        """Signal-dense full-decomp document budget used during indexing."""
        if DECOMP_DOCUMENT_CHARS > 0:
            return max(1024, min(self.max_input_chars, DECOMP_DOCUMENT_CHARS))
        fraction = max(0.1, min(1.0, DECOMP_DOCUMENT_FRACTION))
        return max(1024, min(self.max_input_chars, int(self.max_input_chars * fraction)))

    @property
    def backend(self) -> str:
        profile = getattr(self, "_profile", BGE_CODE_V1)
        return profile.key if self._use_llama else "unavailable"

    @property
    def embedding_format(self) -> str:
        profile = getattr(self, "_profile", BGE_CODE_V1)
        prompt_hash = hashlib.sha256(
            f"{profile.query_prefix}\0{profile.document_prefix}\0{profile.suffix}".encode()
        ).hexdigest()[:12]
        return f"profile-v1:{profile.key}:{prompt_hash}"

    @staticmethod
    def cosine(a: list[float], b: list[float]) -> float:
        from .helpers import cosine_similarity
        return cosine_similarity(a, b)


# ─────────────────────────────────────────────────────────────────────────────
# BehaviorClassifier — zero-shot RE behavior detection
# ─────────────────────────────────────────────────────────────────────────────

class BehaviorClassifier:
    """
    Zero-shot behavior classification via cosine similarity to anchor texts.
    Each anchor is a dense description of what that behavior looks like in
    decompiled C pseudocode.  Anchors are embedded once and cached.

    Replaces the fake Q-value labeling, hardcoded rule sets, and
    untrained pattern matchers.
    """

    # Anchors are written as pseudo-code patterns so a code embedding profile
    # can compare them against actual decompiled pseudocode.
    ANCHORS: dict[str, str] = {
        "crypto_symmetric": "state = load_block(input); round = 0; while (round < nr) { state ^= round_keys[round]; sub_bytes(state, sbox); shift_rows(state); if (round != nr - 1) mix_columns(state, gf_mul); round++; } store_block(out, state ^ round_keys[nr]); key_schedule(key, round_keys);",
        "crypto_hash": "ctx->h0 = 0x67452301; ctx->h1 = 0xefcdab89; while (len >= 64) { compress_block(ctx, block); block += 64; len -= 64; } pad_and_finalize(ctx); digest[0] = bswap32(ctx->h0); digest[1] = bswap32(ctx->h1); if (hmac) inner_outer_hash(ctx, key_block);",
        "network_http": "sock = connect_tcp(host, port); req = format(\"POST %s HTTP/1.1\", path); add_header(req, \"Host\", host); add_header(req, \"User-Agent\", ua); send(sock, req, strlen(req), 0); recv_until_headers(sock, buf); parse_status_line(buf); if (chunked) decode_chunked(sock, body); close_socket(sock);",
        "network_raw": "s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); addr.sin_port = htons(port); addr.sin_addr.s_addr = inet_addr(ip); if (connect(s, &addr, sizeof(addr)) == 0) { n = recv(s, rx, sizeof(rx), 0); if (n > 0) send(s, tx, tx_len, 0); } closesocket(s);",
        "process_injection": "h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid); remote = VirtualAllocEx(h, 0, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE); WriteProcessMemory(h, remote, payload, sz, &written); th = CreateRemoteThread(h, 0, 0, remote, 0, 0, 0); WaitForSingleObject(th, INFINITE); CloseHandle(th); CloseHandle(h);",
        "file_operations": "fd = CreateFileW(path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0); ReadFile(fd, buf, size, &n, 0); parse_record(buf, n); WriteFile(fd, out, out_len, &m, 0); MoveFileW(tmp, path); DeleteFileW(backup); CloseHandle(fd);",
        "anti_debug": "if (IsDebuggerPresent()) return 0; CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg); t0 = __rdtsc(); suspicious_loop(); t1 = __rdtsc(); if (t1 - t0 > limit) flag_debugger(); NtQueryInformationProcess(proc, ProcessDebugPort, &port, sizeof(port), 0);",
        "anti_vm": "cpuid(1, &eax, &ebx, &ecx, &edx); if (ecx & HYPERVISOR_BIT) vm = 1; cpuid(0x40000000, &vendor); if (strstr(vendor, \"VMware\") || strstr(vendor, \"VBox\")) vm = 1; if (mac_oui_matches_vm(nic_mac) || registry_has_vm_keys()) vm = 1;",
        "persistence": "RegCreateKeyExW(HKCU, \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\", ...); RegSetValueExW(run_key, \"Updater\", 0, REG_SZ, exe_path, len); CreateServiceW(scm, name, name, SERVICE_AUTO_START, SERVICE_WIN32_OWN_PROCESS, ...); StartServiceW(svc, 0, 0);",
        "evasion": "for (i = 0; i < blob_len; ++i) blob[i] ^= key[i & 0xf]; Sleep(delay_ms); VirtualProtect(code, len, PAGE_EXECUTE_READWRITE, &old); memset(headers, 0, 0x200); if (sandbox_signals()) return; jump_to_decrypted_payload(blob);",
        "string_decrypt": "for (i = 0; i < enc_len; ++i) { out[i] = enc[i] ^ rolling_key; rolling_key = rotl8(rolling_key + i, 1); } out[enc_len] = 0; if (looks_printable(out)) cache_string(id, out); else wipe_buffer(out, enc_len);",
        "c2_communication": "beacon = json_build(host_id, pid, uptime, version); body = base64_encode(beacon); http_post(c2_url, body, headers); cmd = parse_response(resp); if (cmd.type == EXEC) exec_command(cmd.arg); else if (cmd.type == DOWNLOAD) fetch_payload(cmd.url);",
        "privilege_escalation": "OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &tok); LookupPrivilegeValueW(0, SeDebugPrivilege, &luid); AdjustTokenPrivileges(tok, 0, &tp, sizeof(tp), 0, 0); if (token_is_elevated(tok)) spawn_as_system(command);",
        "memory_manipulation": "ptr = VirtualAlloc(0, sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE); memcpy(ptr, src, sz); VirtualProtect(ptr, sz, PAGE_EXECUTE_READ, &old); fn = (void(*)())ptr; fn(); mmap_region = mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);",
        "rop_gadget": "for (ea = text_start; ea < text_end; ++ea) { if (is_ret(insn[ea])) { collect_gadget(ea - 6, ea); if (matches(\"pop reg; pop reg; ret\")) score++; } } chain = build_rop_chain(stack_pivot, gadgets, syscall_stub);",
        "heap_spray": "for (i = 0; i < 0x2000; ++i) { buf = malloc(chunk); memset(buf, 0x41, chunk); memcpy(buf + nop_len, shellcode, sc_len); array[i] = buf; } trigger_uaf_or_oob(array);",
        "use_after_free": "obj = alloc_obj(sz); init_obj(obj); free(obj); if (condition) { obj->vtable->dispatch(obj, arg); memcpy(obj->buf, input, len); } dangling pointer dereference after free indicates temporal memory bug;",
        "buffer_overflow": "char tmp[128]; len = read_input(src, 0x400); memcpy(tmp, src, len); if (len > sizeof(tmp)) stack_corruption = 1; strcpy(dst, user); strcat(dst, suffix); missing bounds checks around copy operations and fixed-size local buffers;",
        "format_string_vuln": "fmt = recv_user_string(sock); if (fmt) { printf(fmt); syslog(LOG_ERR, fmt); snprintf(out, 256, fmt, user1, user2); } user-controlled format string reaches variadic sink without literal format guard;",
        "race_condition": "if (!global_lock) init_lock(); if (shared_flag) update_shared_state(); pthread_create(&t1, 0, worker, ctx); pthread_create(&t2, 0, worker, ctx); check_then_use(file_path); open(file_path); rename(file_path, backup); state mutation happens without synchronized critical section;",
        "integer_overflow": "count = read_u32(pkt + 4); size = count * elem_size; buf = malloc(size); if (size < count) overflow = 1; for (i = 0; i < count; ++i) copy_elem(buf + i * elem_size, src); truncation or wraparound in arithmetic before allocation/copy;",
        "path_traversal": "snprintf(path, sizeof(path), \"%s/%s\", base_dir, user_name); if (strstr(user_name, \"..\")) warn_only(); fopen(path, \"wb\"); extract_archive(entry_name, base_dir); insufficient canonicalization allows writes outside intended root;",
    }
    ANCHOR_MIN_CONFIDENCE: dict[str, float] = {
        "buffer_overflow": 0.35,
        "use_after_free": 0.35,
        "format_string_vuln": 0.35,
        "integer_overflow": 0.35,
        "path_traversal": 0.35,
    }
    # Module-level singleton so anchors are loaded exactly once per process.
    _shared: BehaviorClassifier | None = None
    _shared_lock = threading.Lock()

    @classmethod
    def instance(cls, embedder: BgeCodeEmbedder) -> BehaviorClassifier:
        with cls._shared_lock:
            if cls._shared is None:
                cls._shared = cls(embedder)
            elif cls._shared._embedder is not embedder:
                # Rebind the shared classifier when the embedding backend changes.
                # This keeps anchor similarity scores aligned with the active embedder.
                cls._shared._embedder = embedder
                cls._shared.clear_cache()
        return cls._shared

    def __init__(self, embedder: BgeCodeEmbedder):
        self._embedder = embedder
        self._anchor_embs: dict[str, list[float]] = {}
        self._anchor_lock = threading.Lock()
        self._anchor_generation = 0

    def clear_cache(self) -> None:
        """Drop all cached anchor embeddings.

        Useful when the embedder backend changes or when tests need to force
        a cold-start path without recreating the singleton.
        """
        with self._anchor_lock:
            self._anchor_generation += 1
            self._anchor_embs.clear()

    def refresh_anchors(self, behaviors: list[str] | None = None) -> None:
        """Pre-warm the anchor cache.

        If `behaviors` is omitted, all anchors are refreshed. Otherwise only the
        named behaviors are re-embedded.
        """
        targets = behaviors or list(self.ANCHORS.keys())
        with self._anchor_lock:
            generation = self._anchor_generation
        for behavior in targets:
            self._get_anchor(behavior, generation=generation)

    def _get_anchor(self, behavior: str, generation: int | None = None) -> list[float] | None:
        """
        Return cached anchor embedding or compute it.
        NEVER holds the lock during embed — that was causing full serialization.
        """
        with self._anchor_lock:
            if behavior in self._anchor_embs:
                return self._anchor_embs[behavior]
            current_generation = self._anchor_generation
        if generation is None:
            generation = current_generation
        # Compute outside the lock so other calls aren't blocked
        try:
            result = self._embedder.embed(self.ANCHORS[behavior])
            # Production always returns _EmbedResult; some tests mock the
            # embedder to return a raw list. Treat anything without .ok
            # as an unavailable embedding.
            if hasattr(result, "ok"):
                if not result.ok or result.vector is None:
                    return None
                vec = result.vector
            elif isinstance(result, list):
                vec = result
            else:
                return None
        except Exception:
            return None
        with self._anchor_lock:
            if generation != self._anchor_generation:
                return self._anchor_embs.get(behavior)
            self._anchor_embs.setdefault(behavior, vec)
        return self._anchor_embs.get(behavior)

    def classify_vec(
        self,
        query_vec: list[float],
        threshold: float = 0.25,
        top_k: int = 4,
        block: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Classify a pre-computed embedding vector against all behavior anchors.

        block=False (default): uses only anchors already in cache — returns
            immediately when anchors have not been explicitly refreshed.
        block=True: embeds any missing anchors inline — complete results
            but may take up to 14 × embed_time on the first call.
        """
        # Snapshot cached anchors without holding the lock during scoring
        with self._anchor_lock:
            cached = dict(self._anchor_embs)

        results = []
        for behavior in self.ANCHORS:
            anchor = cached.get(behavior)
            if anchor is None:
                if not block:
                    continue  # skip unloaded anchor rather than blocking
                anchor = self._get_anchor(behavior)
                if anchor is None:
                    continue
            sim = BgeCodeEmbedder.cosine(query_vec, anchor)
            min_thr = float(threshold or 0.0) if threshold is not None else 0.0
            if threshold >= 0.20:
                min_thr = max(min_thr, float(self.ANCHOR_MIN_CONFIDENCE.get(behavior, 0.30)))
            if sim >= min_thr:
                results.append({"behavior": behavior, "confidence": round(sim, 4)})

        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results[:top_k]

    @staticmethod
    def _anchor_explain(anchor_text: str, query_text: str) -> list[str]:
        phrases = [p.strip() for p in anchor_text.split(";") if p.strip()]
        q_tokens = set(re.findall(r"[A-Za-z0-9_]+", (query_text or "").lower()))
        scored: list[tuple[int, str]] = []
        for ph in phrases:
            p_tokens = set(re.findall(r"[A-Za-z0-9_]+", ph.lower()))
            scored.append((len(q_tokens.intersection(p_tokens)), ph))
        scored.sort(key=lambda x: x[0], reverse=True)
        top = [ph for ov, ph in scored if ov > 0][:3]
        if len(top) < 3:
            for _, ph in scored:
                if ph not in top:
                    top.append(ph)
                if len(top) >= 3:
                    break
        return top[:3]

    @staticmethod
    def _text_tokens(text: str) -> set[str]:
        out: set[str] = set()
        for raw in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", str(text or "")):
            low_raw = raw.lower()
            if low_raw and low_raw not in NOISE_WORDS:
                out.add(low_raw)
        for raw in _IDENT_RE.findall(str(text or "")):
            for term in _identifier_terms(raw):
                low = term.lower()
                if low and low not in NOISE_WORDS:
                    out.add(low)
        for literal in re.findall(r"%[0-9.]*[a-zA-Z]|\.\.|0x[0-9a-fA-F]+", str(text or "")):
            out.add(literal.lower())
        return out

    def classify(
        self,
        text: str,
        threshold: float = 0.25,
        max_tokens: int = 3000,
        top_k: int = 4,
        block: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Zero-shot behavior classification of decompiled pseudocode.
        Embeds text and delegates to classify_vec.

        Each result carries a ``backend`` field so callers can tell whether
        the score came from the selected local profile or from a failed embedding. No
        keyword-bonus is applied on top of the embedding score — the cosine
        similarity is the confidence.
        """
        if not text or not text.strip():
            return []
        query = _extract_signature(text[:max_tokens]) or text[:max_tokens]
        embed_query = getattr(self._embedder, "embed_query", None)
        result = embed_query(query) if callable(embed_query) else self._embedder.embed(query)
        if not result.ok or result.vector is None:
            return []
        rows = self.classify_vec(result.vector, threshold=threshold, top_k=top_k, block=block)
        if not rows and not block:
            rows = self.classify_vec(result.vector, threshold=threshold, top_k=top_k, block=True)
        for row in rows:
            row["backend"] = result.backend
            b = str(row.get("behavior") or "")
            row["explain"] = self._anchor_explain(self.ANCHORS.get(b, ""), query)
        rows.sort(key=lambda x: x.get("confidence", 0.0), reverse=True)
        return rows

    def anchor_coverage_report(self, min_similarity: float = 0.4, max_funcs: int = 5000) -> dict[str, Any]:
        """Report how many functions match each anchor above min_similarity."""
        rows = []
        try:
            import idautils
            funcs = list(idautils.Functions())[:max(1, int(max_funcs))]
        except Exception:
            funcs = []
        cache: list[tuple[int, list[float]]] = []
        for ea in funcs:
            try:
                import ida_hexrays
                cfunc = ida_hexrays.decompile(ea)
                if not cfunc:
                    continue
                sig = _extract_signature(str(cfunc)[:3000]) or str(cfunc)[:1200]
                result = self._embedder.embed(sig)
                if result.ok and result.vector is not None:
                    cache.append((ea, result.vector))
            except Exception:
                continue
        for label in self.ANCHORS:
            anc = self._get_anchor(label)
            if anc is None:
                rows.append({"label": label, "hit_count": 0, "top_example": None})
                continue
            best = (0.0, None)
            hits = 0
            for ea, qv in cache:
                sim = BgeCodeEmbedder.cosine(qv, anc)
                if sim >= float(min_similarity):
                    hits += 1
                    if sim > best[0]:
                        best = (sim, ea)
            rows.append({
                "label": label,
                "hit_count": hits,
                "top_example": hex(best[1]) if best[1] is not None else None,
            })
        return {"anchors": rows, "min_similarity": float(min_similarity), "function_count": len(cache)}


# ─────────────────────────────────────────────────────────────────────────────
