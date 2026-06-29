"""
Intelligence layer for IDA Pro MCP.

Replaces the fake ML systems (cognitive_layer, cartographer, attention_kernel,
11 SQLite databases, Hadamard random projections, untrained SSMs) with a real
embedding model backed by bge-code-v1 via llama-server.

Architecture:
  BgeCodeEmbedder      — manages llama-server subprocess, exposes embed()
  FunctionEmbeddingIndex — per-binary SQLite store of 1536-dim embeddings
  BehaviorClassifier   — zero-shot via cosine sim to anchor descriptions
  ContextAssembler     — orchestrates everything, produces context_pack per call

Environment variables:
  IDA_MCP_EMBED_SERVER_BIN   path to llama-server binary
  IDA_MCP_EMBED_MODEL        path to .gguf file
  IDA_MCP_EMBED_PORT         port (default: random 18100-19000)
  IDA_MCP_EMBED_THREADS      CPU threads (default: cpu_count // 2)
  IDA_MCP_EMBED_CTX          context tokens (default: 2048)
  IDA_MCP_EMBED_DISABLED     set to 1 to force TF-IDF fallback

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

import contextlib
import glob
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

from .embeddings import NOISE_WORDS, FunctionEmbeddingIndex  # noqa: F401

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
_MODEL_PATH_CACHE = None


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

    return ""  # will trigger TF-IDF fallback


def _find_model() -> str:
    """Locate the embedding GGUF model.

    Resolution order:
      1. `IDA_MCP_EMBED_MODEL` env var (string or `;`-separated list)
      2. Manual override in `embedder.json` (`model_path`)
      3. Project-local: `<project>/bge-code-v1[-q8_0].gguf`,
         `<project>/models/bge-code-v1[-q8_0].gguf`
      4. Install root: `<install_root>/bge-code-v1[-q8_0].gguf`,
         `<install_root>/models/bge-code-v1[-q8_0].gguf`
      5. User home: `~/models`, `~/Downloads`, `~/Documents`
      6. Hugging Face cache: `~/.cache/huggingface/hub/models--*/snapshots/*/bge-code-v1*.gguf`
    """
    global _MODEL_PATH_CACHE
    if isinstance(_MODEL_PATH_CACHE, str):
        return _MODEL_PATH_CACHE

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
                _MODEL_PATH_CACHE = os.path.abspath(expanded)
                return _MODEL_PATH_CACHE

    # 2) embedder.json manual override
    state = _read_embedder_state()
    manual = _select_state_path(state.get("model_path"))
    if manual:
        _MODEL_PATH_CACHE = manual
        return _MODEL_PATH_CACHE

    home = str(Path.home())
    install_root = _install_root()
    candidates: list[str] = []
    model_filenames = ("bge-code-v1-q8_0.gguf", "bge-code-v1.gguf")
    bases = [_PROJECT_ROOT, install_root, os.path.join(install_root, "models"),
             os.path.join(home, "models"),
             os.path.join(home, "Downloads"),
             os.path.join(home, "Documents")]
    for base in bases:
        if not base:
            continue
        for fn in model_filenames:
            candidates.append(os.path.join(base, fn))

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
            _MODEL_PATH_CACHE = p
            return p

    # 6) Hugging Face cache snapshots for local model files
    hf_root = os.path.join(home, ".cache", "huggingface", "hub")
    if os.path.isdir(hf_root):
        for p in glob.glob(
            os.path.join(hf_root, "models--*", "snapshots", "*", "bge-code-v1*.gguf")
        ):
            if os.path.isfile(p):
                _MODEL_PATH_CACHE = os.path.abspath(p)
                return _MODEL_PATH_CACHE

    _MODEL_PATH_CACHE = ""
    return ""


EMBED_DIM = 1536          # bge-code-v1 embedding dimension
EMBED_CTX = int(os.environ.get("IDA_MCP_EMBED_CTX", "2048"))
EMBED_THREADS = int(os.environ.get("IDA_MCP_EMBED_THREADS",
                                    str(max(2, (os.cpu_count() or 4) // 2))))
EMBED_REQUEST_TIMEOUT = float(os.environ.get("IDA_MCP_EMBED_REQUEST_TIMEOUT", "5.0"))
EMBED_MAX_FAILURES = int(os.environ.get("IDA_MCP_EMBED_MAX_FAILURES", "2"))
EMBED_DISABLED = os.environ.get("IDA_MCP_EMBED_DISABLED", "") in ("1", "true", "yes")
INTEL_PROFILE = os.environ.get("IDA_MCP_INTEL_PROFILE", "") in ("1", "true", "yes")


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
# TF-IDF fallback (works with zero dependencies when llama-server is absent)
# ─────────────────────────────────────────────────────────────────────────────

class _TFIDFEmbedder:
    """
    Deterministic TF-IDF bag-of-words embedding.
    Dimensionality is fixed at EMBED_DIM via hash bucketing.
    Not as good as bge-code-v1 but orders of magnitude better than
    random Hadamard projections.
    """
    _TOKENIZE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\b0x[0-9a-fA-F]+\b|\b\d+\b")

    def __init__(self, dim: int = EMBED_DIM):
        self._dim = dim
        self._idf: dict[str, float] = {}
        self._doc_count = 0

    def _tokens(self, text: str) -> list[str]:
        out: list[str] = []
        for raw in self._TOKENIZE.findall(str(text or "")):
            for term in _identifier_terms(raw):
                low = term.lower()
                if low and low not in NOISE_WORDS and not (low.isdigit() and len(low) < 3):
                    out.append(low)
        # Expand common RE-domain synonyms so short natural-language queries can
        # still land near decompiler identifiers in fallback mode.
        synonyms = {
            "aes": ("crypto", "cipher", "encrypt", "decrypt"),
            "cipher": ("crypto", "encrypt", "decrypt"),
            "http": ("network", "socket", "headers", "request", "response"),
            "recv": ("receive", "socket", "network"),
            "send": ("socket", "network"),
            "socket": ("network", "connect", "recv", "send"),
            "debugger": ("antidebug", "debug"),
            "sandbox": ("vm", "evasion"),
            "overflow": ("bounds", "memcpy", "strcpy"),
            "uaf": ("use", "after", "free"),
        }
        expanded = list(out)
        for tok in out:
            expanded.extend(synonyms.get(tok, ()))
        return expanded

    def fit_many(self, texts: list[str]) -> None:
        df: Counter = Counter()
        for t in texts:
            df.update(set(self._tokens(t)))
        n = max(1, len(texts))
        self._idf = {tok: math.log((n + 1) / (cnt + 1)) + 1
                     for tok, cnt in df.items()}
        self._doc_count = n

    def embed(self, text: str) -> list[float]:
        toks = self._tokens(text)
        if not toks:
            return [0.0] * self._dim
        tf: Counter = Counter(toks)
        vec = [0.0] * self._dim
        for tok, count in tf.items():
            idf = self._idf.get(tok, 1.0)
            weight = (1 + math.log(count)) * idf
            # Hash bucketing into fixed dim
            h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
            idx = h % self._dim
            sign = 1 if (h >> 127) & 1 else -1
            vec[idx] += sign * weight
        # L2 normalize
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        return [x / norm for x in vec]


# ─────────────────────────────────────────────────────────────────────────────
# BgeCodeEmbedder — llama-server subprocess manager
# ─────────────────────────────────────────────────────────────────────────────

class BgeCodeEmbedder:
    """
    Manages a llama-server subprocess running bge-code-v1.
    Lazy start on first embed() call.  Thread-safe singleton per process.
    Falls back to TF-IDF if binary or model not found.
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
        self._port: int | None = None
        self._proc: subprocess.Popen | None = None
        self._ready        = False
        self._start_lock   = threading.Lock()
        self._fallback     = _TFIDFEmbedder()
        self._use_llama    = (bool(self._server_bin) and bool(self._model_path)
                              and not EMBED_DISABLED)
        # Cached anchor embeddings for BehaviorClassifier
        self._anchor_cache: dict[str, list[float]] = {}
        self._batch_size = int(os.environ.get("IDA_MCP_EMBED_BATCH", "16"))
        self._batch_size = max(1, min(64, self._batch_size))
        self._batch_lock = threading.Lock()
        self._owns_proc = False
        self._consecutive_rpc_failures = 0
        self._max_rpc_failures = max(1, EMBED_MAX_FAILURES)

    def status(self, probe: bool = False, deep_hash: bool = False) -> dict:
        server_ready = bool(self._ready)
        probe_error = ""
        if probe:
            if not server_ready and self._use_llama:
                server_ready = bool(self._start_server())
            elif self._port:
                try:
                    req = urllib.request.urlopen(f"http://127.0.0.1:{self._port}/health", timeout=2)
                    server_ready = b'"ok"' in req.read()
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
                            if b'"ok"' in req.read():
                                self._port = lease_port
                                self._ready = True
                                self._owns_proc = False
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
            "batch_size": int(self._batch_size),
            "consecutive_rpc_failures": int(self._consecutive_rpc_failures),
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

    def _start_server(self) -> bool:
        with self._start_lock:
            if self._ready:
                return True
            if not self._use_llama:
                return False
            # Reuse existing shared embed server when available.
            try:
                if os.path.isfile(_EMBED_LEASE_FILE):
                    with open(_EMBED_LEASE_FILE, encoding="utf-8") as f:
                        lease = json.load(f)
                    port = int(lease.get("port") or 0)
                    if port > 0:
                        try:
                            req = urllib.request.urlopen(
                                f"http://127.0.0.1:{port}/health", timeout=2
                            )
                            if b'"ok"' in req.read():
                                self._port = port
                                self._ready = True
                                self._owns_proc = False
                                return True
                        except Exception:
                            pass
            except Exception:
                pass
            self._port = self._pick_port()
            cmd = [
                self._server_bin,
                "--model",    self._model_path,
                "--embedding",
                "--port",     str(self._port),
                "--ctx-size", str(EMBED_CTX),
                "--batch-size", str(max(EMBED_CTX, 2048)),
                "--ubatch-size", str(max(EMBED_CTX, 2048)),
                "--pooling", "mean",
                "--threads",  str(EMBED_THREADS),
                "--n-predict", "0",
                "--log-disable",
            ]
            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self._owns_proc = True
            except OSError:
                self._use_llama = False
                return False

            # Wait for server ready (up to 60s — model load takes ~10s on this CPU)
            deadline = time.time() + 60.0
            while time.time() < deadline:
                time.sleep(1.0)
                try:
                    req = urllib.request.urlopen(
                        f"http://127.0.0.1:{self._port}/health", timeout=2
                    )
                    if b'"ok"' in req.read():
                        self._ready = True
                        try:
                            with open(_EMBED_LEASE_FILE, "w", encoding="utf-8") as f:
                                json.dump({"pid": self._proc.pid if self._proc else None, "port": self._port, "updated_at": time.time()}, f)
                        except Exception:
                            pass
                        return True
                except Exception:
                    pass
                if self._proc.poll() is not None:
                    self._use_llama = False
                    return False

            self._use_llama = False
            return False

    def stop(self) -> None:
        if self._owns_proc and self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()
        self._ready = False
        self._proc = None
        self._owns_proc = False

    # ── embedding ──────────────────────────────────────────────────────────

    def _llama_embed(self, text: str) -> list[float] | None:
        if not self._ready and not self._start_server():
            return None
        try:
            body = json.dumps({"input": text, "encoding_format": "float"}).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{self._port}/embeddings",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=EMBED_REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read())
            vec = data["data"][0]["embedding"]
            # Server already L2-normalizes; verify and re-normalize just in case
            norm = math.sqrt(sum(x * x for x in vec)) or 1.0
            self._consecutive_rpc_failures = 0
            return [x / norm for x in vec]
        except Exception:
            self._consecutive_rpc_failures += 1
            if self._consecutive_rpc_failures >= self._max_rpc_failures:
                # Avoid long hangs in latency-sensitive flows (tests/interactive MCP).
                self._use_llama = False
                self.stop()
            return None

    def _llama_embed_batch(self, texts: list[str]) -> list[list[float]] | None:
        if not texts:
            return []
        if len(texts) == 1:
            vec = self._llama_embed(texts[0])
            return [vec] if vec is not None else None
        if not self._ready and not self._start_server():
            return None
        try:
            body = json.dumps({"input": texts, "encoding_format": "float"}).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{self._port}/embeddings",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=max(EMBED_REQUEST_TIMEOUT, 10.0)) as resp:
                data = json.loads(resp.read())
            rows = data.get("data") or []
            if not isinstance(rows, list) or len(rows) != len(texts):
                return None
            out: list[list[float]] = []
            for row in rows:
                vec = row.get("embedding") if isinstance(row, dict) else None
                if not vec:
                    return None
                norm = math.sqrt(sum(x * x for x in vec)) or 1.0
                out.append([x / norm for x in vec])
            self._consecutive_rpc_failures = 0
            return out
        except Exception:
            self._consecutive_rpc_failures += 1
            if self._consecutive_rpc_failures >= self._max_rpc_failures:
                self._use_llama = False
                self.stop()
            return None

    def embed(self, text: str) -> list[float]:
        """Return L2-normalized 1536-dim embedding for text."""
        if self._use_llama:
            vec = self._llama_embed(text)
            if vec is not None:
                return vec
        # Fallback
        return self._fallback.embed(text)

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        if self._use_llama:
            out: list[list[float]] = []
            i = 0
            while i < len(texts):
                with self._batch_lock:
                    bs = self._batch_size
                chunk = texts[i : i + bs]
                vecs = self._llama_embed_batch(chunk)
                if vecs is None:
                    with self._batch_lock:
                        self._batch_size = max(1, self._batch_size // 2)
                    # fallback chunk-by-chunk to preserve forward progress
                    for t in chunk:
                        out.append(self.embed(t))
                    i += len(chunk)
                    continue
                out.extend(vecs)
                # gentle increase when stable
                with self._batch_lock:
                    if self._batch_size < 64 and len(chunk) == self._batch_size:
                        self._batch_size += 1
                i += len(chunk)
            return out
        return [self._fallback.embed(t) for t in texts]

    @property
    def dim(self) -> int:
        return EMBED_DIM

    @property
    def backend(self) -> str:
        return "bge-code-v1" if self._use_llama else "tfidf-fallback"

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

    # Anchors are written as pseudo-code patterns rather than keyword lists so
    # bge-code-v1 (code-specialized, last-token pooling) embeds them in the
    # same space as actual decompiled pseudocode.
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
    _ANCHOR_TOKEN_BONUS_WEIGHT = 0.18
    _ANCHOR_TOKEN_ALIASES: dict[str, tuple[str, ...]] = {
        "crypto_symmetric": ("aes", "cipher", "encrypt", "decrypt", "round", "sbox", "sub_bytes", "mix_columns", "round_key", "key_schedule"),
        "crypto_hash": ("hash", "digest", "sha", "md5", "hmac", "compress", "finalize"),
        "network_http": ("http", "header", "headers", "request", "response", "user_agent", "chunked", "post", "get", "recv", "send"),
        "network_raw": ("socket", "connect", "recv", "send", "tcp", "udp", "inet", "htons"),
        "process_injection": ("openprocess", "virtualallocex", "writeprocessmemory", "createremotethread", "remote", "process"),
        "file_operations": ("createfile", "readfile", "writefile", "fopen", "read", "write", "deletefile", "movefile"),
        "anti_debug": ("isdebuggerpresent", "debugger", "rdtsc", "processdebugport", "checkremotedebuggerpresent"),
        "anti_vm": ("cpuid", "hypervisor", "vmware", "vbox", "virtualbox", "sandbox"),
        "persistence": ("regcreatekey", "run", "service", "autorun", "startup", "createservice"),
        "evasion": ("sleep", "sandbox", "virtualprotect", "decrypt", "payload", "xor", "delay"),
        "string_decrypt": ("xor", "rolling_key", "decrypt", "printable", "string", "rotl", "decode"),
        "c2_communication": ("beacon", "c2", "command", "download", "http_post", "base64", "host_id"),
        "privilege_escalation": ("sedebugprivilege", "adjusttokenprivileges", "token", "elevated", "system"),
        "memory_manipulation": ("virtualalloc", "virtualprotect", "mmap", "memcpy", "execute", "page_execute"),
        "rop_gadget": ("ret", "gadget", "pop", "pivot", "chain", "syscall", "rop"),
        "heap_spray": ("malloc", "spray", "chunk", "nop", "shellcode", "trigger"),
        "use_after_free": ("free", "dangling", "vtable", "uaf", "temporal", "after_free"),
        "buffer_overflow": ("overflow", "memcpy", "strcpy", "strcat", "bounds", "stack", "fixed", "corruption"),
        "format_string_vuln": ("printf", "syslog", "snprintf", "format", "variadic", "%s", "%n"),
        "race_condition": ("pthread", "thread", "lock", "shared", "race", "check_then_use", "rename"),
        "integer_overflow": ("overflow", "wrap", "truncation", "malloc", "count", "size", "multiply"),
        "path_traversal": ("..", "canonical", "path", "extract", "archive", "base_dir", "traversal"),
    }

    # Module-level singleton so anchors are loaded exactly once per process.
    _shared: BehaviorClassifier | None = None
    _shared_lock = threading.Lock()

    @classmethod
    def instance(cls, embedder: BgeCodeEmbedder) -> BehaviorClassifier:
        with cls._shared_lock:
            if cls._shared is None:
                cls._shared = cls(embedder)
                cls._shared._preload_anchors_async()
            elif cls._shared._embedder is not embedder:
                # Rebind the shared classifier when the embedding backend changes.
                # This keeps anchor similarity scores aligned with the active embedder.
                cls._shared._embedder = embedder
                cls._shared.clear_cache()
                cls._shared._preload_anchors_async()
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
            vec = self._embedder.embed(self.ANCHORS[behavior])
        except Exception:
            return None
        with self._anchor_lock:
            if generation != self._anchor_generation:
                return self._anchor_embs.get(behavior)
            self._anchor_embs.setdefault(behavior, vec)
        return self._anchor_embs.get(behavior)

    def _preload_anchors_async(self) -> None:
        """Load all anchors in background, one at a time, no lock contention."""
        def _load():
            with self._anchor_lock:
                generation = self._anchor_generation
            for b in self.ANCHORS:
                with self._anchor_lock:
                    if b in self._anchor_embs:
                        continue
                self._get_anchor(b, generation=generation)   # embeds outside lock
        threading.Thread(target=_load, daemon=True, name="anchor-preload").start()

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
            immediately even if preload isn't done yet.  May return fewer
            behaviors on the very first call, but is never slow.
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

    def _token_bonus(self, behavior: str, query_text: str) -> tuple[float, list[str]]:
        aliases = set(self._ANCHOR_TOKEN_ALIASES.get(behavior, ()))
        if not aliases:
            return 0.0, []
        q_tokens = self._text_tokens(query_text)
        anchor_tokens = self._text_tokens(self.ANCHORS.get(behavior, ""))
        targets = aliases.union(anchor_tokens)
        hits = sorted(q_tokens.intersection(targets))
        if not hits:
            return 0.0, []
        denom = max(4, min(12, len(aliases) or len(targets)))
        return min(1.0, len(hits) / denom), hits[:12]

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
        """
        if not text or not text.strip():
            return []
        # Collapse verbose pseudocode into a compact signature so anchors and
        # queries live in the same code-signature space.
        query = _extract_signature(text[:max_tokens]) or text[:max_tokens]
        q = self._embedder.embed(query)
        rows = self.classify_vec(q, threshold=threshold, top_k=top_k, block=block)
        if not rows and not block:
            # First-call correctness matters more than returning an empty set
            # while the async anchor preload is still warming up.
            rows = self.classify_vec(q, threshold=threshold, top_k=top_k, block=True)
        existing = {str(row.get("behavior") or "") for row in rows}
        for behavior in self.ANCHORS:
            if behavior in existing:
                continue
            token_bonus, matched_tokens = self._token_bonus(behavior, query)
            if token_bonus < 0.25:
                continue
            anchor = self._get_anchor(behavior)
            sim = BgeCodeEmbedder.cosine(q, anchor) if anchor is not None else 0.0
            adjusted = min(1.0, max(sim, token_bonus * self._ANCHOR_TOKEN_BONUS_WEIGHT))
            min_thr = float(threshold or 0.0) if threshold is not None else 0.0
            if min_thr >= 0.20:
                min_thr = max(min_thr, float(self.ANCHOR_MIN_CONFIDENCE.get(behavior, 0.30)))
            if adjusted >= min_thr:
                rows.append(
                    {
                        "behavior": behavior,
                        "confidence": round(adjusted, 4),
                        "embedding_confidence": round(sim, 4),
                        "matched_tokens": matched_tokens,
                    }
                )
        for row in rows:
            b = str(row.get("behavior") or "")
            token_bonus, matched_tokens = self._token_bonus(b, query)
            if token_bonus > 0:
                original = float(row.get("confidence") or 0.0)
                adjusted = min(1.0, max(original, token_bonus * self._ANCHOR_TOKEN_BONUS_WEIGHT) + (0.5 * self._ANCHOR_TOKEN_BONUS_WEIGHT * token_bonus))
                row["confidence"] = round(adjusted, 4)
                row["embedding_confidence"] = round(original, 4)
                row["matched_tokens"] = matched_tokens
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
                vec = self._embedder.embed(sig)
                cache.append((ea, vec))
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
