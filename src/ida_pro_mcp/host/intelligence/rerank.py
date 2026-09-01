"""Cross-encoder reranker — llama-server ``--rerank`` subprocess manager.

Stage 2 of the retrieval pipeline.  The embedding index (Stage 1) recalls a
wider candidate pool cheaply; the reranker re-scores each ``(query, doc)``
pair with full cross-attention so the top of the returned list is *correct*,
not just nearby.  This is what makes the results worth reading.

Lifecycle mirrors :class:`BgeCodeEmbedder` exactly — the reranker is a
second, independent llama-server process (llama.cpp serves ``--embedding``
and ``--rerank`` as mutually exclusive modes, so it cannot share the embed
server's process).  It reuses the same lease / idle-shutdown / activation-
grace / request-lock / recycling machinery, on its own lease file, so two
MCP hosts sharing one install do not fight over the reranker any more than
they do over the embedder.

Configuration (env, with the ``rerank`` section of the install
``embedder.json`` state file as override — see ``_read_rerank_state``):
  IDA_MCP_RERANK_DISABLED   set to 1/true to disable reranking entirely
  IDA_MCP_RERANK_ENABLED    set to 1/true to force-enable (default: on when
                            a rerank GGUF is installed)
  IDA_MCP_RERANK_MODEL      path to a rerank .gguf (string or `;` list)
  IDA_MCP_RERANK_PROFILE    qwen3-reranker-0.6b | bge-reranker-v2-gemma |
                            qwen3-reranker-4b | bge-reranker-v2-m3
  IDA_MCP_RERANK_PORT       fixed port (default: random)
  IDA_MCP_RERANK_CTX        context tokens per (query, doc) pair (default:
                            1024 — the standard cap for bge/qwen3-reranker
                            models; raise for very long documents on GPU)
  IDA_MCP_RERANK_THREADS    CPU threads (default: cpu_count // 2)
  IDA_MCP_RERANK_BATCH_THREADS prompt/prefill threads (default: up to 16)
  IDA_MCP_RERANK_CHUNK      documents per /rerank request (default: 8) — llama
                            .cpp sizes buffers for the whole request, so chunk
                            to bound peak memory on large pools
  IDA_MCP_RERANK_PARALLEL   slots (default: 2; build 99111b1 needs at least 2
                            for distinct rerank scores)
  IDA_MCP_RERANK_DOC_CHARS  per-document truncation for the /rerank payload
  IDA_MCP_RERANK_GPU        1/true to offload to a detected Vulkan device
  IDA_MCP_RERANK_START_TIMEOUT    health-poll deadline for a cold server start
                            (default: 60s)
  IDA_MCP_RERANK_START_LOCK_TIMEOUT inter-process lock budget for a cold start
                            (default: 75s; must exceed START_TIMEOUT so a
                            concurrent host's first rerank does not spuriously
                            time out)
  IDA_MCP_RERANK_MAX_CANDIDATES default recall pool the search passes here
  IDA_MCP_RERANK_TIMEOUT    per-request deadline (default: 30s)
  IDA_MCP_RERANK_IDLE_TIMEOUT seconds to retain an idle rerank server
"""

from __future__ import annotations

import atexit
import contextlib
import glob
import hashlib
import json
import os
import socket
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from .core import (
    CACHE_DIR,
    EMBED_ACTIVATION_GRACE_TIMEOUT,
    EmbeddingQueueTimeout,
    _detect_gpu_device,
    _find_llama_server,
    _install_root,
    _InterProcessLock,
    _lease_pid,
    _llama_context_layout,
    _pid_alive,
    _process_command,
    _process_rss_bytes,
    _process_start_token,
    _read_embedder_state,
    _safe_float_env,
    _safe_int_env,
    _select_state_path,
    _split_env_paths,
    model_fingerprint,
    server_fingerprint,
)
from .rerank_profiles import (
    RERANK_MODEL_PROFILES,
    get_rerank_model_profile,
    profile_from_rerank_model,
)

RERANK_LEASE_FILE = os.path.join(CACHE_DIR, "ida-mcp-rerank-server-lease.json")
_RERANK_LEASE_SCHEMA = 1

# Keep rerank defaults in the same family as the embedder so one CPU-bound
# laptop can host both 0.6B-class models without thrashing.
RERANK_THREADS = _safe_int_env(
    "IDA_MCP_RERANK_THREADS", str(max(1, (os.cpu_count() or 4) // 2))
)
# Prompt/prefill parallelism.  Rerank is prefill-bound (every pair is a fresh
# forward pass), so give the batch worker threads the same headroom the
# embedder does; --threads stays at half cores to leave room for the MCP host.
RERANK_BATCH_THREADS = _safe_int_env(
    "IDA_MCP_RERANK_BATCH_THREADS",
    str(min(16, max(1, os.cpu_count() or 4))),
)
# Documents per /rerank request.  llama.cpp sizes its compute buffers for the
# whole request batch, so a 64-document pool can balloon RSS to 5+ GB and OOM a
# small laptop.  Chunking keeps the physical batch (and therefore peak memory)
# bounded while the pool size stays large; the request lock already serializes
# clients so the extra round-trips are safe.
RERANK_CHUNK_SIZE = max(1, _safe_int_env("IDA_MCP_RERANK_CHUNK", "8"))
# Two slots is the safe default for the larger cross-encoder; raise this when
# the machine has the memory headroom.
# llama.cpp build 99111b1 returns collapsed/identical scores for /rerank with
# one slot. Preserve the minimum viable quality even when an operator sets a
# too-low environment value; higher values remain capped for memory safety.
RERANK_PARALLEL = max(2, min(4, _safe_int_env("IDA_MCP_RERANK_PARALLEL", "2")))
RERANK_DOC_CHARS = _safe_int_env("IDA_MCP_RERANK_DOC_CHARS", "6000")
RERANK_REQUEST_TIMEOUT = _safe_float_env("IDA_MCP_RERANK_TIMEOUT", "30.0")
RERANK_BATCH_REQUEST_TIMEOUT = _safe_float_env("IDA_MCP_RERANK_BATCH_TIMEOUT", "120.0")
RERANK_LOCK_TIMEOUT = _safe_float_env("IDA_MCP_RERANK_LOCK_TIMEOUT", "45.0")
# The cross-process startup lock (see _start_server) is held across the whole
# spawn + health-poll critical section.  Its timeout must clear that window, or
# a second host cold-starting concurrently fails its first rerank with
# RerankQueueTimeout even though the first host is starting fine.  The request
# lock (RERANK_LOCK_TIMEOUT) guards a request-sized critical section and keeps
# its own, shorter budget.
RERANK_START_DEADLINE = _safe_float_env("IDA_MCP_RERANK_START_TIMEOUT", "60.0")
RERANK_START_LOCK_TIMEOUT = _safe_float_env("IDA_MCP_RERANK_START_LOCK_TIMEOUT", "75.0")
RERANK_MAX_REQUESTS = _safe_int_env("IDA_MCP_RERANK_MAX_REQUESTS", "512")
RERANK_MAX_RSS_MB = _safe_int_env("IDA_MCP_RERANK_MAX_RSS_MB", "0")
# A rerank server (larger model + context-sized KV) legitimately grows a few
# GB past its model file; the embedder's tight growth budget would recycle it
# after the first request.
RERANK_MAX_RSS_GROWTH_MB = _safe_int_env("IDA_MCP_RERANK_MAX_RSS_GROWTH_MB", "2048")
RERANK_MAX_FAILURES = _safe_int_env("IDA_MCP_RERANK_MAX_FAILURES", "2")
RERANK_IDLE_TIMEOUT = max(0.0, _safe_float_env("IDA_MCP_RERANK_IDLE_TIMEOUT", "15.0"))
# Default recall pool the semantic search hands to the reranker.
RERANK_MAX_CANDIDATES = max(8, _safe_int_env("IDA_MCP_RERANK_MAX_CANDIDATES", "64"))
# Cache exact (query, chunk) scores. Keys contain only a digest, so large
# pseudocode documents do not remain resident in the host; values are just a
# handful of float/index pairs. Set to 0 to disable if model output is
# intentionally nondeterministic.
RERANK_CACHE_MAX = max(0, _safe_int_env("IDA_MCP_RERANK_CACHE", "128"))

_TRUE = ("1", "true", "yes", "on")


def _rerank_cache_key(query: str, documents: list[str]) -> str:
    """Hash one exact rerank chunk without delimiter ambiguities."""
    digest = hashlib.sha256()
    digest.update(len(documents).to_bytes(8, "big"))
    for value in (query, *documents):
        encoded = value.encode("utf-8", errors="replace")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _rerank_enabled() -> bool:
    disabled = os.environ.get("IDA_MCP_RERANK_DISABLED", "").strip().lower()
    if disabled in _TRUE:
        return False
    forced = os.environ.get("IDA_MCP_RERANK_ENABLED", "").strip().lower()
    if forced in _TRUE:
        return True
    # The installer persists the component-level choice in embedder.json.
    # Environment flags remain the explicit operator override; otherwise
    # honor the state file before falling back to the historical default.
    try:
        configured = _read_rerank_state().get("enabled")
    except Exception:
        configured = None
    if isinstance(configured, bool):
        return configured
    if configured is not None:
        configured_text = str(configured).strip().lower()
        if configured_text in _TRUE:
            return True
        if configured_text in ("0", "false", "no", "off"):
            return False
    # Default: on when a model is installed. Discovery stays lazy so an
    # absent model just leaves the reranker inert (status reports it).
    return True


def _read_rerank_state() -> dict:
    """Load the ``rerank`` override section from the install ``embedder.json``.

    Kept in the same file as the embedder so the installer writes one config
    document; the ``rerank`` key is a nested dict with ``model_path``,
    ``profile`` and ``enabled``.
    """
    state = _read_embedder_state()
    sub = state.get("rerank")
    if isinstance(sub, dict):
        return dict(sub)
    return {}


def _find_rerank_model() -> str:
    """Locate the cross-encoder GGUF.

    Resolution order (mirrors ``core._find_model``):
      1. `IDA_MCP_RERANK_MODEL` env var (string or `;`-separated list)
      2. `rerank.model_path` in the install state file
      3. Project-local / install / home / Downloads / Documents files
         matching the selected profile
      4. Hugging Face cache snapshots
      5. Fallback: any known reranker profile's model, so the feature works
         out of the box when only one reranker family is installed.
    """
    state = _read_rerank_state()
    requested_profile = str(
        os.environ.get("IDA_MCP_RERANK_PROFILE") or state.get("profile")
        or "qwen3-reranker-0.6b"
    ).strip().lower()
    requested_profile = (get_rerank_model_profile(requested_profile)
                         or next(iter(RERANK_MODEL_PROFILES.values()))).key

    # 1) explicit env var
    env_val = os.environ.get("IDA_MCP_RERANK_MODEL", "")
    if env_val:
        for piece in _split_env_paths(env_val):
            piece = piece.strip()
            if not piece:
                continue
            try:
                expanded = os.path.expandvars(os.path.expanduser(piece))
            except Exception:
                continue
            if os.path.isfile(expanded):
                return os.path.abspath(expanded)

    # 2) state file manual override
    manual = _select_state_path(state.get("model_path"))
    state_profile = str(state.get("profile") or "").strip().lower()
    state_profile_obj = get_rerank_model_profile(state_profile)
    if manual:
        # An installer-saved profile is authoritative even when the user
        # chose a custom filename. Without that metadata, retain the legacy
        # filename/GGUF inference guard so a stale state path cannot silently
        # activate a different model family.
        if state_profile_obj is not None and state_profile_obj.key == requested_profile:
            return manual
        if not state_profile and profile_from_rerank_model(manual).key == requested_profile:
            return manual

    home = str(Path.home())
    install_root = _install_root()
    bases = [
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        install_root,
        os.path.join(install_root, "models"),
        os.path.join(home, "models"),
        os.path.join(home, "Downloads"),
        os.path.join(home, "Documents"),
    ]
    profile = get_rerank_model_profile(requested_profile) or next(iter(RERANK_MODEL_PROFILES.values()))
    if profile.filename_patterns:
        found = _scan_bases(bases, profile.filename_patterns)
        if found:
            return found

    # 4) Hugging Face cache snapshots
    hf_root = os.path.join(home, ".cache", "huggingface", "hub")
    if os.path.isdir(hf_root):
        if profile.filename_patterns:
            for p in glob.glob(os.path.join(hf_root, "models--*", "snapshots", "*",
                                            profile.filename_patterns[0])):
                if os.path.isfile(p):
                    return os.path.abspath(p)

    # 5) fallback: any known reranker profile (prefer default-profile order)
    seen: set[str] = set()
    for prof in RERANK_MODEL_PROFILES.values():
        for base in bases:
            if not base:
                continue
            for pattern in prof.filename_patterns:
                for c in glob.glob(os.path.join(base, pattern)):
                    try:
                        p = os.path.abspath(c)
                    except Exception:
                        continue
                    if p in seen or not os.path.isfile(p):
                        continue
                    seen.add(p)
                    return p
    # also scan HF cache for any reranker
    if os.path.isdir(hf_root):
        for prof in RERANK_MODEL_PROFILES.values():
            if not prof.filename_patterns:
                continue
            for p in glob.glob(os.path.join(hf_root, "models--*", "snapshots", "*",
                                            prof.filename_patterns[0])):
                if os.path.isfile(p) and os.path.abspath(p) not in seen:
                    return os.path.abspath(p)
    return ""


def _scan_bases(bases: list[str], patterns: tuple[str, ...]) -> str:
    candidates: list[str] = []
    for base in bases:
        if not base:
            continue
        for pattern in patterns:
            candidates.extend(glob.glob(os.path.join(base, pattern)))
    # Prefer Q4_K_M over Q8_0 when both exist (see core._prefer_q4).
    try:
        from .core import _model_quant_rank

        candidates.sort(key=_model_quant_rank)
    except Exception:
        pass
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
            return p
    return ""


def _rerank_request_lock_path() -> str:
    return RERANK_LEASE_FILE + ".request.lock"


def _rerank_start_lock_path() -> str:
    return RERANK_LEASE_FILE + ".startup.lock"


class RerankQueueTimeout(TimeoutError):
    """The shared reranker is busy, but has not failed or been abandoned."""


class _RerankInterProcessLock(_InterProcessLock):
    """Inter-process lock that surfaces contention as ``RerankQueueTimeout``.

    The shared lock raises ``EmbeddingQueueTimeout``; without translation the
    reranker's busy case would fall through to the generic error handler and
    be misclassified as a request timeout — retiring a healthy shared server
    on lock contention.
    """

    def __enter__(self):
        try:
            return super().__enter__()
        except EmbeddingQueueTimeout as exc:
            raise RerankQueueTimeout(str(exc)) from None


class Reranker:
    """Manages a llama-server ``--rerank`` subprocess.

    Thread-safe process-wide singleton.  ``ensure_ready()`` starts or attaches
    to the shared server; ``rerank()`` POSTs one query against N documents and
    returns relevance scores.  Cold-start latency inside the activation-grace
    window is never mistaken for a wedged server.
    """

    _instance: Reranker | None = None
    _lock = threading.Lock()

    def __new__(cls) -> Reranker:
        # Native in-process backend (see core.BgeCodeEmbedder.__new__ for the
        # same routing rationale).  Every ``Reranker()`` call site — semantic
        # search, reranker_status, function families — transparently uses the
        # native library when the host bootstrap enabled it; HTTP is fallback.
        if cls is Reranker:
            try:
                from .native import NativeReranker, prefer_native_rerank

                if prefer_native_rerank():
                    return NativeReranker()
            except Exception:
                pass
        with cls._lock:
            if cls._instance is None:
                obj = super().__new__(cls)
                obj._init()
                cls._instance = obj
        return cls._instance

    @classmethod
    def reset(cls, model_path: str = "") -> Reranker:
        """Replace the singleton, optionally pinned to a specific model path.

        Lets callers switch rerank models at runtime (benchmarks, A/B tests,
        `ida_python` exploration) without restarting the process.  The old
        singleton is stopped and its lease torn down first.
        """
        if cls is Reranker:
            try:
                from .native import NativeReranker, prefer_native_rerank

                if prefer_native_rerank():
                    return NativeReranker.reset(model_path)
            except Exception:
                pass
        with cls._lock:
            if cls._instance is not None:
                previous = cls._instance
                cls._instance = None
                with contextlib.suppress(Exception):
                    previous.stop()
            obj = super().__new__(cls)
            obj._init()
            if model_path:
                obj._model_path = os.path.abspath(os.path.expanduser(model_path))
                obj._profile = profile_from_rerank_model(
                    obj._model_path,
                    str(os.environ.get("IDA_MCP_RERANK_PROFILE") or ""),
                )
                obj._use_llama = bool(
                    obj._server_bin
                    and obj._model_path
                    and os.path.isfile(obj._model_path)
                    and _rerank_enabled()
                )
                obj._identity_cache = None
                obj._ctx = min(
                    max(512, _safe_int_env("IDA_MCP_RERANK_CTX", "1024")),
                    obj._profile.max_context,
                )
            cls._instance = obj
            return obj

    def _init(self) -> None:
        self._server_bin = _find_llama_server()
        self._model_path = _find_rerank_model()
        state = _read_rerank_state()
        requested_profile = os.environ.get("IDA_MCP_RERANK_PROFILE") or state.get("profile")
        self._profile = profile_from_rerank_model(self._model_path, str(requested_profile or ""))
        self._port: int | None = None
        self._proc: subprocess.Popen | None = None
        self._ready = False
        self._start_lock = threading.Lock()
        self._use_llama = bool(self._server_bin and self._model_path and _rerank_enabled())
        self._owns_proc = False
        self._stop_registered = False
        self._consecutive_rpc_failures = 0
        self._max_rpc_failures = max(1, RERANK_MAX_FAILURES)
        self._last_batch_timeout = False
        self._last_recycle_reason = ""
        self._identity_cache: dict[str, Any] | None = None
        self._server_started_at = 0.0
        self._idle_lock = threading.Lock()
        self._idle_timer: threading.Timer | None = None
        self._idle_generation = 0
        self._score_cache: dict[str, list[dict[str, Any]]] = {}
        self._score_cache_lock = threading.Lock()
        self._score_inflight: dict[str, threading.Event] = {}
        # Default ctx is 1024 — the standard cap for reranker models
        # (bge-reranker / qwen3-reranker) and the same default the native
        # backend uses.  A rerank pair is the query plus a bounded document
        # (the search path truncates each doc to RERANK_DOC_BUDGET_CHARS), so
        # 1024 keeps the KV cache and the physical batch small on CPU.  The
        # profile max would size the compute buffers for 8k tokens and waste
        # gigabytes on a laptop.
        # Clamp the env var to a sane floor (mirrors native.py) so a mis-set
        # IDA_MCP_RERANK_CTX=0/negative does not pass --ctx-size 0 /
        # --ubatch-size 0 to llama-server.
        self._ctx = min(
            max(512, _safe_int_env("IDA_MCP_RERANK_CTX", "1024")),
            self._profile.max_context,
        )

    # ── status ────────────────────────────────────────────────────────────

    @property
    def backend(self) -> str:
        return "local"

    @property
    def dim(self) -> int:
        return 0

    def status(self, probe: bool = False) -> dict:
        server_ready = bool(self._ready)
        if probe:
            server_ready = bool(self.ensure_ready())
        return {
            "backend": self.backend,
            "enabled": bool(self._use_llama),
            "profile": self._profile.key,
            "profile_name": self._profile.display_name,
            "family": self._profile.family,
            "model_license": self._profile.license,
            "server_bin": self._server_bin,
            "server_bin_exists": bool(self._server_bin and os.path.isfile(self._server_bin)),
            "model_path": self._model_path,
            "model_exists": bool(self._model_path and os.path.isfile(self._model_path)),
            "ready": bool(server_ready),
            "port": self._port,
            "owns_process": bool(self._owns_proc),
            "ctx": self._ctx,
            "max_candidates": RERANK_MAX_CANDIDATES,
            "last_recycle_reason": self._last_recycle_reason,
        }

    # ── lease plumbing (mirrors BgeCodeEmbedder, own lease file) ─────────

    @staticmethod
    def _read_lease() -> dict[str, Any]:
        try:
            with open(RERANK_LEASE_FILE, encoding="utf-8") as handle:
                lease = json.load(handle)
            return lease if isinstance(lease, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _write_lease(lease: dict[str, Any]) -> None:
        directory = os.path.dirname(RERANK_LEASE_FILE) or "."
        os.makedirs(directory, exist_ok=True)
        temporary = f"{RERANK_LEASE_FILE}.{os.getpid()}.{threading.get_ident()}.tmp"
        try:
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(lease, handle)
            os.replace(temporary, RERANK_LEASE_FILE)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(temporary)

    @staticmethod
    def _server_json(port: int, endpoint: str, timeout: float = 2.0) -> Any:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/{endpoint.lstrip('/')}", timeout=timeout
        ) as response:
            return json.loads(response.read())

    def _lease_identity(self) -> dict[str, Any]:
        cached = getattr(self, "_identity_cache", None)
        if cached is not None:
            return dict(cached)
        model = model_fingerprint(self._model_path)
        server = server_fingerprint(self._server_bin)
        identity = {
            "profile": self._profile.key,
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

    def _lease_matches(self, lease: dict[str, Any]) -> bool:
        if not isinstance(lease, dict):
            return False
        try:
            if int(lease.get("schema") or 0) != _RERANK_LEASE_SCHEMA:
                return False
            pid = _lease_pid(lease.get("pid"))
            owner_pid = _lease_pid(lease.get("owner_pid"))
            port = int(lease.get("port") or 0)
        except (TypeError, ValueError):
            return False
        if not _pid_alive(pid) or not _pid_alive(owner_pid) or port <= 0:
            return False
        expected_start = str(lease.get("process_start_token") or "").strip()
        if expected_start and _process_start_token(pid) != expected_start:
            return False
        expected_owner_start = str(lease.get("owner_start_token") or "").strip()
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
            # A lease proves that a server existed, not that this PID still
            # belongs to it. Refuse to signal when process identity cannot be
            # inspected; the next startup can reclaim the lease safely.
            return False
        expected_start = str((lease or {}).get("process_start_token") or "").strip()
        if expected_start and _process_start_token(pid) != expected_start:
            return False
        server_path = str((lease or {}).get("server_path") or self._server_bin or "")
        model_path = str((lease or {}).get("model_path") or self._model_path or "")
        return bool(
            "llama-server" in command
            and "--rerank" in command
            and (not server_path or server_path in command)
            and (not model_path or model_path in command)
        )

    def _retire_lease_process(self, lease: dict[str, Any], reason: str) -> None:
        try:
            pid = _lease_pid(lease.get("pid"))
        except (TypeError, ValueError):
            pid = 0
        can_remove_lease = pid <= 0 or not _pid_alive(pid)
        if pid > 0 and not can_remove_lease and self._pid_is_expected_server(pid, lease):
            with contextlib.suppress(OSError):
                os.kill(pid, 15)
            deadline = time.monotonic() + 3.0
            while _pid_alive(pid) and time.monotonic() < deadline:
                time.sleep(0.05)
            if _pid_alive(pid):
                with contextlib.suppress(OSError):
                    os.kill(pid, 9)
            can_remove_lease = not _pid_alive(pid)
        if can_remove_lease:
            with contextlib.suppress(OSError):
                current = self._read_lease()
                if not current or current == lease:
                    os.unlink(RERANK_LEASE_FILE)
        self._last_recycle_reason = reason
        self._ready = False
        if getattr(self, "_proc", None) is not None and getattr(self._proc, "pid", None) == pid:
            with contextlib.suppress(Exception):
                self._proc.wait(timeout=0.1)
            self._proc = None
        self._owns_proc = False

    def _cancel_idle_shutdown(self) -> None:
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
        delay = RERANK_IDLE_TIMEOUT if timeout is None else max(0.0, timeout)
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
        if RERANK_MAX_RSS_MB > 0:
            return RERANK_MAX_RSS_MB * 1024 * 1024
        try:
            model_size = os.path.getsize(self._model_path)
        except OSError:
            model_size = 0
        # Context-sized KV + batch buffers on top of the model file: give the
        # reranker 4x the model size plus a floor, not the embedder's 2x+512.
        # Measured on this box with the real benchmark (12 queries, 16-candidate
        # pools, 8-doc chunks at ctx 1024, --parallel 2): RSS *ratchets* with
        # request size (llama.cpp allocates a fresh compute buffer per distinct
        # larger batch and never frees the old one — verified flat-plateau at
        # 1752 MiB over 12 identical requests, but climbing to 4.15 GiB on the
        # varied benchmark corpus). The differential growth check catches real
        # leaks; this absolute floor just has to clear the worst legitimate
        # peak. 4 GiB sat ~150 MiB under the measured peak and recycled a
        # healthy server mid-benchmark; 5 GiB leaves ~0.85 GiB of headroom
        # without ever approaching this box's RAM ceiling.
        return max(5 * 1024**3, int(model_size * 5.0) + 1024 * 1024**2)

    def _record_success_and_maybe_recycle(self) -> None:
        lease = self._read_lease()
        if not lease or not self._lease_matches(lease):
            return
        pid = int(lease.get("pid") or 0)
        rss = _process_rss_bytes(pid)
        prev_rss = int(lease.get("rss") or 0)
        count = int(lease.get("request_count") or 0) + 1
        lease.update({"request_count": count, "rss": rss, "updated_at": time.time()})
        reason = ""
        if RERANK_MAX_REQUESTS > 0 and count >= RERANK_MAX_REQUESTS:
            reason = f"request limit reached ({count})"
        elif rss and rss > self._rss_limit_bytes():
            reason = f"RSS limit exceeded ({rss // (1024 * 1024)} MiB)"
        elif prev_rss and rss - prev_rss > RERANK_MAX_RSS_GROWTH_MB * 1024 * 1024:
            # Differential growth since the PREVIOUS request, not startup: the
            # first pool legitimately allocates the compute graph (RSS steps up
            # once and plateaus — measured 0.9->1.6 GB then flat), so measuring
            # against baseline false-positives and recycles a healthy server
            # after its first big pool.  This catches leaks (memory that keeps
            # growing request over request) without punishing one-time growth.
            reason = (
                f"RSS grew {(rss - prev_rss) // (1024 * 1024)} MiB "
                f"since last request"
            )
        if reason:
            self._retire_lease_process(lease, reason)
            return
        with contextlib.suppress(OSError):
            self._write_lease(lease)

    # ── subprocess management ─────────────────────────────────────────────

    def _pick_port(self) -> int:
        env = os.environ.get("IDA_MCP_RERANK_PORT", "")
        if env and env.isdigit():
            return int(env)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _start_server(self) -> bool:
        with self._start_lock:
            try:
                with _RerankInterProcessLock(_rerank_start_lock_path(), RERANK_START_LOCK_TIMEOUT):
                    return self._start_server_locked()
            except RerankQueueTimeout:
                return False

    def _start_server_locked(self) -> bool:
        with contextlib.nullcontext():
            if self._ready:
                return True
            lease = self._read_lease()
            if lease and self._lease_matches(lease):
                self._port = int(lease["port"])
                self._ready = True
                self._owns_proc = False
                self._use_llama = True
                self._server_started_at = time.monotonic()
                return True
            if lease:
                self._retire_lease_process(lease, "stale or incompatible rerank lease")
            if not self._use_llama:
                self._server_bin = _find_llama_server()
                self._model_path = _find_rerank_model()
                state = _read_rerank_state()
                requested_profile = os.environ.get("IDA_MCP_RERANK_PROFILE") or state.get("profile")
                self._profile = profile_from_rerank_model(self._model_path, str(requested_profile or ""))
                self._identity_cache = None
                self._use_llama = bool(self._server_bin and self._model_path and _rerank_enabled())
            if not self._use_llama:
                return False
            self._port = self._pick_port()
            # Keep the rerank context as the per-pair budget. The shared
            # layout helper keeps this in lockstep with the embedder.
            slot_ctx, parallel, total_ctx = _llama_context_layout(
                self._ctx, RERANK_PARALLEL
            )
            cmd = [
                self._server_bin,
                "--model", self._model_path,
                "--rerank",
                "--port", str(self._port),
                "--ctx-size", str(total_ctx),
                "--batch-size", str(slot_ctx),
                # The physical batch must be >= the largest (query+doc) pair.
                # The embedder's ubatch=512 works for many short snippets but a
                # rerank pair is a full decompilation (~700-2000 tokens), and
                # llama.cpp errors with HTTP 500 "input too large" when ubatch
                # is smaller.  Use ctx so any pair fits; docs are capped at
                # RERANK_DOC_CHARS so the KV/compute cost stays bounded.
                "--ubatch-size", str(slot_ctx),
                # --parallel 1 collapses /rerank to one identical score per
                # document on build 99111b1, so keep at least two slots.
                "--parallel", str(parallel),
                "--threads", str(RERANK_THREADS),
                "--threads-batch", str(RERANK_BATCH_THREADS),
                "--n-predict", "0",
                "--log-disable",
            ]
            # A Vulkan-enabled llama.cpp build auto-selects the GPU when no
            # --device is given.  On the UHD 620 iGPU the reranker is
            # pathological (shader compile per sequence length, and
            # vk::Queue::submit: ErrorDeviceLost at large ubatch).  CPU is the
            # reliable default; the GPU is opt-in via IDA_MCP_RERANK_GPU=1.
            if os.environ.get("IDA_MCP_RERANK_GPU", "").strip().lower() in _TRUE:
                gpu_device = _detect_gpu_device(self._server_bin)
                if gpu_device:
                    cmd += ["--device", gpu_device]
                else:
                    cmd += ["--device", "none"]
            else:
                cmd += ["--device", "none"]
            try:
                _env = os.environ.copy()
                _lib_dir = os.path.dirname(self._server_bin)
                _existing = _env.get("LD_LIBRARY_PATH", "")
                _paths = [p for p in (_existing.split(":") + [_lib_dir]) if p]
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
                self._server_started_at = time.monotonic()
                if isinstance(self._proc.pid, int) and not self._stop_registered:
                    atexit.register(self.stop)
                    self._stop_registered = True
            except OSError:
                self._ready = False
                return False

            deadline = time.time() + RERANK_START_DEADLINE
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
                                "schema": _RERANK_LEASE_SCHEMA,
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
            self._abandon_owned_server("health poll timed out")
            return False

    def _abandon_owned_server(self, reason: str) -> None:
        """Kill a server we spawned but could not bring healthy.

        The start-timeout path has no lease to retire (a lease is only written
        once the health poll succeeds), so a hung llama-server would otherwise
        be orphaned forever: every subsequent ``_start_server_locked`` would
        Popen a fresh one over the top, and ``stop()`` never reaps the earlier
        process.  Terminate it here and drop the reference so the next cold
        start is clean.
        """
        proc = self._proc
        if proc is not None and self._owns_proc:
            if proc.poll() is None:
                with contextlib.suppress(Exception):
                    proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    with contextlib.suppress(Exception):
                        proc.kill()
                        proc.wait(timeout=2)
        self._proc = None
        self._owns_proc = False
        self._last_recycle_reason = reason

    def stop(self) -> None:
        self._cancel_idle_shutdown()
        owned_pid = self._proc.pid if self._owns_proc and self._proc else None
        try:
            with open(RERANK_LEASE_FILE, encoding="utf-8") as f:
                lease = json.load(f)
            if not isinstance(lease, dict):
                lease = {}
            lease_pid = _lease_pid(lease.get("pid"))
            owner_pid = _lease_pid(lease.get("owner_pid"))
            owner_start = str(lease.get("owner_start_token") or "").strip()
            owner_matches = owner_pid == os.getpid() and (
                not owner_start or _process_start_token(owner_pid) == owner_start
            )
            if owner_matches and lease_pid > 0:
                owned_pid = owned_pid or lease_pid
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            lease_pid = 0
        lease_process_stopped = False
        if owned_pid and self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
                lease_process_stopped = True
            except Exception:
                self._proc.kill()
                try:
                    self._proc.wait(timeout=2)
                except Exception:
                    pass
                else:
                    lease_process_stopped = True
        elif owned_pid and self._proc:
            lease_process_stopped = True
        elif owned_pid and self._proc is None and self._pid_is_expected_server(owned_pid, lease):
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
            else:
                lease_process_stopped = not _pid_alive(owned_pid)
        if owned_pid:
            try:
                if (
                    lease_process_stopped
                    and lease_pid == owned_pid
                    and lease
                    and self._read_lease() == lease
                ):
                    os.unlink(RERANK_LEASE_FILE)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                pass
        self._ready = False
        self._proc = None
        self._owns_proc = False

    def ensure_ready(self) -> bool:
        """Start or attach to the shared reranker.  Idle it out afterwards."""
        self._cancel_idle_shutdown()
        ready = bool(self._start_server())
        if ready:
            self._schedule_idle_shutdown(EMBED_ACTIVATION_GRACE_TIMEOUT)
        return ready

    # ── rerank ────────────────────────────────────────────────────────────

    @staticmethod
    def _truncate_doc(text: str, limit: int) -> str:
        return text[:limit]

    def _request_rerank(
        self, query: str, documents: list[str], *, timeout: float
    ) -> list[dict[str, Any]] | None:
        if not documents or not self._ready:
            return None
        self._cancel_idle_shutdown()
        in_activation_grace = (
            time.monotonic() - self._server_started_at
        ) < EMBED_ACTIVATION_GRACE_TIMEOUT
        if in_activation_grace:
            timeout = max(timeout, EMBED_ACTIVATION_GRACE_TIMEOUT)
        try:
            with _RerankInterProcessLock(
                _rerank_request_lock_path(), min(RERANK_LOCK_TIMEOUT, timeout)
            ):
                # No abandoned-slot retire here.  The request lock already
                # serializes every client, so any active slot under the lock is
                # our own just-finished request.  On a slow model (a 2.6B Q4 on
                # an 8-core CPU takes ~20 s per pair) that slot can still read
                # as "processing" a moment after the HTTP response returns —
                # retiring the server then would recycle a perfectly healthy
                # one.  A genuinely wedged server is handled by the request
                # timeout path below.
                docs = [self._truncate_doc(str(d), RERANK_DOC_CHARS) for d in documents]
                # No top_k in the request: llama.cpp build 99111b1 shifts the
                # returned document indices by one when top_k is present.  The
                # candidate pool is bounded (RERANK_MAX_CANDIDATES), so asking
                # for every score and mapping by index is free.
                body = json.dumps(
                    {
                        "query": str(query),
                        "documents": docs,
                    }
                ).encode()
                req = urllib.request.Request(
                    f"http://127.0.0.1:{self._port}/rerank",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read())
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list):
                raise RuntimeError("rerank response missing results")
            out: list[dict[str, Any]] = []
            for item in results:
                if not isinstance(item, dict):
                    continue
                try:
                    index = int(item.get("index"))
                except (TypeError, ValueError):
                    continue
                score = item.get("relevance_score")
                if score is None:
                    score = item.get("score")
                try:
                    score = float(score)
                except (TypeError, ValueError):
                    continue
                out.append({"index": index, "score": score})
            out.sort(key=lambda x: x["score"], reverse=True)
            indices = [item["index"] for item in out]
            expected_indices = set(range(len(documents)))
            if len(out) != len(documents) or set(indices) != expected_indices:
                raise RuntimeError("rerank response indices mismatch")
            self._consecutive_rpc_failures = 0
            self._record_success_and_maybe_recycle()
            return out
        except RerankQueueTimeout:
            return None
        except Exception as exc:
            if isinstance(exc, (TimeoutError, socket.timeout)):
                self._last_batch_timeout = True
                if not in_activation_grace:
                    self._retire_lease_process(
                        self._read_lease(), "rerank request timeout"
                    )
            self._consecutive_rpc_failures += 1
            if self._consecutive_rpc_failures >= self._max_rpc_failures:
                self._ready = False
                self._consecutive_rpc_failures = 0
            return None
        finally:
            if self._ready:
                self._schedule_idle_shutdown()

    def _request_rerank_cached(
        self, query: str, documents: list[str], *, timeout: float
    ) -> list[dict[str, Any]] | None:
        """Reuse exact HTTP rerank chunks and collapse concurrent duplicates."""
        if not documents:
            return []
        if RERANK_CACHE_MAX <= 0:
            return self._request_rerank(query, documents, timeout=timeout)

        # _request_rerank applies this same cap before sending the payload;
        # key the effective input so long-document spelling differences past
        # the model boundary do not create useless duplicate requests.
        capped = [self._truncate_doc(str(doc), RERANK_DOC_CHARS) for doc in documents]
        cache_key = _rerank_cache_key(str(query), capped)
        owner = False
        wait_event: threading.Event | None = None
        with self._score_cache_lock:
            cached = self._score_cache.get(cache_key)
            if cached is not None:
                return [dict(item) for item in cached]
            wait_event = self._score_inflight.get(cache_key)
            if wait_event is None:
                wait_event = threading.Event()
                self._score_inflight[cache_key] = wait_event
                owner = True
        if not owner:
            if wait_event is not None:
                wait_event.wait(timeout=max(1.0, float(timeout)))
            with self._score_cache_lock:
                cached = self._score_cache.get(cache_key)
            return [dict(item) for item in cached] if cached is not None else None

        try:
            scored = self._request_rerank(query, documents, timeout=timeout)
            if scored is not None:
                snapshot = [dict(item) for item in scored]
                with self._score_cache_lock:
                    if len(self._score_cache) >= RERANK_CACHE_MAX:
                        try:
                            self._score_cache.pop(next(iter(self._score_cache)))
                        except Exception:
                            self._score_cache.clear()
                    self._score_cache[cache_key] = snapshot
            return scored
        finally:
            with self._score_cache_lock:
                event = self._score_inflight.pop(cache_key, None)
                if event is not None:
                    event.set()

    def rerank(
        self,
        query: str,
        documents: list[str],
        *,
        top_k: int | None = None,
        deadline: float | None = None,
    ) -> list[dict[str, Any]] | None:
        """Score ``(query, document)`` pairs.

        Returns ``[{index, score}, ...]`` sorted by score descending (index is
        the position in ``documents``), or ``None`` when the reranker is
        unavailable, the request failed, or the ``deadline`` (a
        ``time.monotonic()`` timestamp) expired mid-pool.  Callers treat
        ``None`` as "keep the recall order" — reranking is a quality boost,
        never a hard gate.  An expired deadline is checked before each chunk so
        a CPU-bound pool still yields back to the caller's search budget.
        """
        if not documents:
            return []
        # Auto-recover: a recycled server (RSS ceiling after many pools, idle
        # shutdown, a mid-request timeout) leaves _ready=False.  Restart once
        # so reranking keeps working across a long session instead of silently
        # no-oping for the rest of the process lifetime.  ensure_ready holds
        # the start lock, so concurrent callers don't stampede the restart.
        if not self._ready:
            if not getattr(self, "_use_llama", False):
                return None
            try:
                if not self.ensure_ready():
                    return None
            except Exception:
                return None
        # Chunk the pool: llama.cpp sizes its compute buffers for the whole
        # request batch, so a large pool can balloon RSS (a 64-doc pool at
        # ctx 4096 measured ~5.4 GB on a 0.6B model).  Scoring in bounded
        # slices keeps peak memory proportional to the chunk, not the pool.
        # Indices are chunk-relative, so offset them before merging.  A chunk
        # failure keeps the recall order (None), never a partial reorder.
        chunk = max(1, RERANK_CHUNK_SIZE)
        merged: list[dict[str, Any]] = []
        for start in range(0, len(documents), chunk):
            if deadline is not None and time.monotonic() >= deadline:
                return None
            part = documents[start:start + chunk]
            scored = self._request_rerank_cached(
                query,
                part,
                timeout=RERANK_REQUEST_TIMEOUT,
            )
            if not scored:
                return None
            for item in scored:
                merged.append(
                    {"index": int(item["index"]) + start, "score": item["score"]}
                )
        merged.sort(key=lambda x: x["score"], reverse=True)
        if top_k and top_k > 0:
            return merged[: int(top_k)]
        return merged
