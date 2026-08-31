"""In-process native llama.cpp retrieval backend (embed + rerank).

Replaces the two full ``llama-server`` HTTP subprocesses with a single
in-process shared library (``libmcp_llama.so``, built from
``src/ida_pro_mcp/native`` against a trimmed llama.cpp) loaded via **ctypes**
— no subprocess, no HTTP, no JSON, no lease/lock files, and one
``llama_encode`` batch per call instead of per-chunk round trips.

Two classes mirror the existing backends' public APIs exactly, so the
pipeline (``FunctionEmbeddingIndex``, semantic search, function families)
works unchanged:

  :class:`NativeEmbedder`  — drop-in for ``core.BgeCodeEmbedder``
  :class:`NativeReranker`  — drop-in for ``rerank.Reranker``

Selection: set ``IDA_MCP_BACKEND=native`` to force native, or leave unset —
the factory helpers (:func:`native_embedder_available`,
:func:`native_reranker_available`) report whether the library and matching
model are present so the host can prefer it with the HTTP backend as fallback.
When the library is missing or a model fails to load, both classes degrade exactly like the
HTTP path: ``_EmbedResult(ok=False)`` / ``None``, never garbage vectors.

The library must be found at:
  1. ``IDA_MCP_NATIVE_LIB`` env var (explicit path)
  2. ``<install_root>/bin/libmcp_llama.so`` (installed layout)
  3. ``<project>/src/ida_pro_mcp/native/build/libmcp_llama.so`` (dev builds)
  4. ``ctypes.util.find_library``
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import math
import os
import threading
import time
from typing import Any

from .core import (
    EMBED_CHARS_PER_TOKEN,
    EMBED_CTX,
    _available_cpu_count,
    _find_llama_server,
    _find_model,
    _install_root,
    _safe_float_env,
    _safe_int_env,
)
from .helpers import _EmbedResult, decomp_document_char_budget
from .model_profiles import profile_from_model
from .rerank import (
    RERANK_CHUNK_SIZE,  # noqa: F401  (kept for import parity with rerank.py)
    RERANK_DOC_CHARS,
    RERANK_REQUEST_TIMEOUT,
    _find_rerank_model,
)
from .rerank_profiles import profile_from_rerank_model

_TRUE = ("1", "true", "yes", "on")

NATIVE_CTX = max(512, _safe_int_env("IDA_MCP_NATIVE_CTX", str(EMBED_CTX)))
# Native inference runs inside the MCP host, alongside IDA and request
# workers.  Using every logical CPU by default makes concurrent indexing and
# interactive calls fight the host (and is often slower than a smaller pool).
# Match the HTTP backends' adaptive half-affinity default and cap the implicit
# value on very large machines; an explicit env override remains authoritative.
NATIVE_THREADS = _safe_int_env(
    "IDA_MCP_NATIVE_THREADS",
    str(max(1, min(16, _available_cpu_count() // 2))),
)
# Rerank pairs are (query + template + doc); the doc cap below mirrors the
# HTTP path's RERANK_DOC_CHARS but is clamped to fit the native context.
NATIVE_DOC_CHARS = _safe_int_env("IDA_MCP_NATIVE_DOC_CHARS", str(RERANK_DOC_CHARS))
NATIVE_REQUEST_TIMEOUT = _safe_float_env("IDA_MCP_NATIVE_TIMEOUT", str(RERANK_REQUEST_TIMEOUT))
NATIVE_RERANK_CACHE_MAX = max(
    0, _safe_int_env("IDA_MCP_NATIVE_RERANK_CACHE", "128")
)


def _rerank_cache_key(query: str, docs: list[str]) -> str:
    """Return an unambiguous digest for one exact rerank input.

    Delimiter-only concatenation is not injective when user-controlled text
    contains the delimiter (for example ``query='a\\0b', doc='c'`` versus
    ``query='a', doc='b\\0c'``). Length-prefix every field so a cache hit can
    never silently return scores for a different query/document pool.
    """
    digest = hashlib.sha256()
    fields = [query, *docs]
    digest.update(len(docs).to_bytes(8, "big"))
    for value in fields:
        encoded = value.encode("utf-8", errors="replace")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _backend_requested() -> str:
    return os.environ.get("IDA_MCP_BACKEND", "").strip().lower()


def _native_opted_in() -> bool:
    """True when the ``IDA_MCP_NATIVE`` flag is set (set by the host startup
    bootstrap when the library is present, or by the user explicitly)."""
    return os.environ.get("IDA_MCP_NATIVE", "").strip().lower() in _TRUE


_NATIVE_REQUESTED = ("native", "llama-native", "cpp") + _TRUE


def _backend_requests_native() -> bool:
    requested = _backend_requested()
    if not requested or requested in ("auto",):
        return False  # not an explicit choice → let the flag decide
    return requested in _NATIVE_REQUESTED


def prefer_native_embed() -> bool:
    """Decide whether ``BgeCodeEmbedder()`` should resolve to native.

    Explicit ``IDA_MCP_BACKEND=native`` forces it; ``=http``/``=llama``/etc.
    disables it.  Otherwise the ``IDA_MCP_NATIVE`` flag (set by the host
    bootstrap) opts in when the library is present and embedding is not
    disabled.  A user who explicitly chose the cloud backend
    (``IDA_MCP_EMBED_BACKEND=gemini`` or ``embedder.json`` backend) is never
    routed to native — the gemini branch in ``BgeCodeEmbedder._init`` is
    consulted only when this returns False.  Tests never set the flag, so
    they stay on the HTTP path.
    """
    requested = _backend_requested()
    if requested and requested not in ("auto",):
        return _backend_requests_native()
    if not _native_opted_in():
        return False
    if os.environ.get("IDA_MCP_EMBED_DISABLED", "").strip().lower() in _TRUE:
        return False
    try:
        from .core import _resolve_backend

        if _resolve_backend() == "gemini":
            return False
    except Exception:
        pass
    return native_embedder_available()


def prefer_native_rerank() -> bool:
    """Decide whether ``Reranker()`` should resolve to native.  Same rules as
    :func:`prefer_native_embed`, plus the reranker's own enable flag."""
    requested = _backend_requested()
    if requested and requested not in ("auto",):
        return _backend_requests_native()
    if not _native_opted_in():
        return False
    try:
        from .rerank import _rerank_enabled

        if not _rerank_enabled():
            return False
    except Exception:
        pass
    return native_reranker_available()


def bootstrap_native_backend() -> dict:
    """Host-startup hook: auto-enable the native backend.

    Called once from the real server entrypoint (never from tests).  When the
    library and at least one retrieval model are present and the user has not
    pinned a backend, sets
    ``IDA_MCP_NATIVE=1`` in the process env — which also propagates to spawned
    idat children (``env = os.environ.copy()``).  A missing library is a
    no-op, so the HTTP backend remains the fallback.
    """
    requested = _backend_requested()
    if requested and requested not in ("auto",):
        return {"enabled": False, "reason": f"backend pinned to {requested!r}", "lib": ""}
    embedder_ready = native_embedder_available()
    reranker_ready = native_reranker_available()
    if not embedder_ready and not reranker_ready:
        return {
            "enabled": False,
            "reason": "native library or retrieval models not found",
            "lib": "",
            "embedder": False,
            "reranker": False,
        }
    if not _native_opted_in():
        os.environ["IDA_MCP_NATIVE"] = "1"
    return {
        "enabled": True,
        "lib": _find_native_lib(),
        "embedder": embedder_ready,
        "reranker": reranker_ready,
    }


def _find_native_lib() -> str:
    """Locate ``libmcp_llama.so`` (see module docstring for the search order)."""
    env = os.environ.get("IDA_MCP_NATIVE_LIB", "").strip()
    if env:
        if os.path.isfile(env):
            return os.path.abspath(env)
    install_root = _install_root()
    bases = [
        os.path.join(install_root, "bin"),
        # dev builds land here via src/ida_pro_mcp/native/build
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "native", "build",
        ),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "native", "build"),
    ]
    names = ("libmcp_llama.so", "libmcp_llama.dylib", "mcp_llama.dll")
    for base in bases:
        for name in names:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                return os.path.abspath(p)
    for name in names:
        found = ctypes.util.find_library(name)
        if found:
            return found
    return ""


class _NativeLib:
    """ctypes wrapper for ``libmcp_llama.so`` — process-wide singleton."""

    _instance: _NativeLib | None = None
    _lock = threading.Lock()

    def __new__(cls) -> _NativeLib:
        with cls._lock:
            if cls._instance is None:
                obj = super().__new__(cls)
                obj._load()
                cls._instance = obj
        return cls._instance

    @classmethod
    def reset(cls) -> _NativeLib:
        with cls._lock:
            cls._instance = None
        return cls()

    def _load(self) -> None:
        self.path = ""
        self.lib = None
        self.error = ""
        path = _find_native_lib()
        if not path:
            self.error = "libmcp_llama.so not found (IDA_MCP_NATIVE_LIB / install bin / native build)"
            return
        try:
            lib = ctypes.CDLL(path)
        except OSError as exc:
            self.error = f"failed to load {path}: {exc}"
            return
        self.path = path
        self.lib = lib
        lib.mcp_llama_version.restype = ctypes.c_char_p
        lib.mcp_llama_version.argtypes = []
        lib.mcp_err_message.restype = ctypes.c_char_p
        lib.mcp_err_message.argtypes = [ctypes.c_int]

        lib.mcp_embed_new.restype = ctypes.c_void_p
        lib.mcp_embed_new.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        lib.mcp_embed_free.argtypes = [ctypes.c_void_p]
        lib.mcp_embed_dim.restype = ctypes.c_int
        lib.mcp_embed_dim.argtypes = [ctypes.c_void_p]
        lib.mcp_embed_encode.restype = ctypes.c_int
        lib.mcp_embed_encode.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_float),
        ]

        lib.mcp_rerank_new.restype = ctypes.c_void_p
        lib.mcp_rerank_new.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        lib.mcp_rerank_free.argtypes = [ctypes.c_void_p]
        lib.mcp_rerank_score.restype = ctypes.c_int
        lib.mcp_rerank_score.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_float),
        ]

    def __getattr__(self, name: str) -> Any:
        lib = object.__getattribute__(self, "lib")
        if lib is None:
            raise AttributeError(name)
        return getattr(lib, name)


def native_embedder_available() -> bool:
    """True when the native library and embedding model are usable."""
    lib = _NativeLib()
    if lib.lib is None:
        return False
    model = _find_model()
    return bool(model and os.path.isfile(model))


def native_reranker_available() -> bool:
    """True when the native library and reranker model are usable."""
    lib = _NativeLib()
    if lib.lib is None:
        return False
    model = _find_rerank_model()
    return bool(model and os.path.isfile(model))


class NativeEmbedder:
    """In-process embedding backend — drop-in for ``core.BgeCodeEmbedder``."""

    _instance: NativeEmbedder | None = None
    _lock = threading.Lock()

    def __new__(cls) -> NativeEmbedder:
        with cls._lock:
            if cls._instance is None:
                obj = super().__new__(cls)
                obj._init()
                cls._instance = obj
        return cls._instance

    @classmethod
    def reset(cls, model_path: str = "") -> NativeEmbedder:
        """Replace the singleton, optionally pinned to a specific model path."""
        with cls._lock:
            if cls._instance is not None:
                previous = cls._instance
                cls._instance = None
                with __import__("contextlib").suppress(Exception):
                    previous.stop()
            obj = super().__new__(cls)
            obj._init()
            if model_path:
                # _init opens the discovered default so the no-argument path
                # remains identical. A pinned reset must release that handle
                # before opening the requested model, otherwise every model
                # switch leaks a full llama context and its KV cache.
                obj.stop()
                obj._model_path = os.path.abspath(os.path.expanduser(model_path))
                obj._profile = profile_from_model(
                    obj._model_path,
                    str(os.environ.get("IDA_MCP_EMBED_PROFILE") or ""),
                )
                obj._open()
            cls._instance = obj
            return obj

    def _init(self) -> None:
        self._use_native = False
        self._ready = False
        self._handle: int | None = None
        self._dim = 0
        self._native_lib: Any | None = None
        self._lock = threading.Lock()
        # Idempotent embedding cache: repeated queries/candidates in an
        # interactive session never pay a second native inference.  Bounded
        # FIFO; vectors are ~4-6 KB each, so 4096 entries stay well under
        # 32 MB per session.
        self._vec_cache: dict[tuple[int, str, str], list[float]] = {}
        self._vec_cache_max = 4096
        self._vec_cache_lock = threading.Lock()
        # Only one native inference owns a missing key at a time. Concurrent
        # callers wait for that result instead of multiplying CPU-bound model
        # work during a burst of identical searches.
        self._vec_inflight: dict[tuple[int, str, str], threading.Event] = {}
        # Cache entries are scoped to the currently-open native handle.  The
        # generation also protects against an allocator reusing the same
        # opaque pointer after a stop/reopen cycle.
        self._generation = 0
        self._server_bin = _find_llama_server() or ""  # kept for status parity
        self._model_path = _find_model()
        state = None
        try:
            from .core import _read_embedder_state

            state = _read_embedder_state()
        except Exception:
            pass
        requested_profile = os.environ.get("IDA_MCP_EMBED_PROFILE") or (
            (state or {}).get("profile")
        )
        self._profile = profile_from_model(self._model_path, str(requested_profile or ""))
        self._ctx = max(512, _safe_int_env("IDA_MCP_EMBED_CTX", str(NATIVE_CTX)))
        self._open()

    def _open(self) -> None:
        with self._lock:
            if self._use_native and self._ready and self._handle:
                return
            lib = _NativeLib()
            if lib.lib is None or not self._model_path or not os.path.isfile(self._model_path):
                self._use_native = False
                self._ready = False
                return
            handle = lib.mcp_embed_new(
                self._model_path.encode("utf-8"),
                max(1, int(NATIVE_THREADS)),
                self._ctx,
            )
            if not handle:
                self._use_native = False
                self._ready = False
                return
            # Keep the CDLL wrapper alive for as long as the opaque handle is
            # alive. This makes an explicit _NativeLib.reset() harmless to
            # already-open contexts (otherwise ctypes may unload the old .so).
            self._native_lib = lib
            self._handle = handle
            self._dim = int(lib.mcp_embed_dim(handle) or 0)
            self._use_native = True
            self._ready = True

    @property
    def backend(self) -> str:
        with self._lock:
            return "native-llama" if self._use_native else "unavailable"

    @property
    def dim(self) -> int:
        with self._lock:
            return int(self._dim or 0)

    @property
    def embedding_format(self) -> str:
        prompt_hash = hashlib.sha256(
            f"{self._profile.query_prefix}\0{self._profile.document_prefix}\0{self._profile.suffix}".encode()
        ).hexdigest()[:12]
        return f"native-v1:{self._profile.key}:{prompt_hash}"

    @property
    def max_input_chars(self) -> int:
        usable_tokens = max(512, self._ctx - 128)
        return max(1024, min(32768, int(usable_tokens * max(1.0, EMBED_CHARS_PER_TOKEN))))

    @property
    def decomp_document_chars(self) -> int:
        return decomp_document_char_budget(
            self.max_input_chars,
            explicit_chars=_safe_int_env("IDA_MCP_DECOMP_DOCUMENT_CHARS", "0"),
            fraction=_safe_float_env("IDA_MCP_DECOMP_DOCUMENT_FRACTION", "0.20"),
        )

    def status(self, probe: bool = False, deep_hash: bool = False) -> dict:
        with self._lock:
            use_native = bool(self._use_native)
            ready = bool(self._ready and self._handle)
            dim = int(self._dim or 0)
            lib = self._native_lib
        if lib is None:
            lib = _NativeLib()
        return {
            "backend": "native-llama" if use_native else "unavailable",
            "use_llama": use_native,
            "disabled_by_env": False,
            "server_bin": self._server_bin,
            "server_bin_exists": bool(self._server_bin and os.path.isfile(self._server_bin)),
            "model_path": self._model_path,
            "model_exists": bool(self._model_path and os.path.isfile(self._model_path)),
            "ready": ready,
            "port": None,
            "owns_process": True,
            "dim": dim,
            "profile": self._profile.key,
            "profile_name": self._profile.display_name,
            "model_license": self._profile.license,
            "query_document_prompts": bool(
                self._profile.query_prefix or self._profile.document_prefix
            ),
            "batch_size": 0,
            "max_batch_size": 0,
            "max_input_chars": self.max_input_chars,
            "decomp_document_chars": self.decomp_document_chars,
            "native_lib": (lib.path if lib else ""),
            "native_lib_exists": bool(lib and lib.path),
        }

    def ensure_ready(self) -> bool:
        with self._lock:
            if self._use_native and self._ready and self._handle:
                return True
        self._open()
        with self._lock:
            return bool(self._use_native and self._ready and self._handle)

    def stop(self) -> None:
        # Take the encode lock so a background thread mid-_encode cannot read
        # the handle, then have it freed underneath llama.cpp (use-after-free).
        with self._lock:
            self._generation += 1
            if self._handle:
                lib = self._native_lib or _NativeLib()
                if lib.lib is not None:
                    with __import__("contextlib").suppress(Exception):
                        lib.mcp_embed_free(self._handle)
            self._handle = None
            self._native_lib = None
            self._ready = False
            self._use_native = False
        with self._vec_cache_lock:
            self._vec_cache.clear()

    def _format(self, text: str, purpose: str) -> str:
        return self._profile.format_text(str(text), purpose=purpose)

    def _encode(self, texts: list[str], purpose: str = "document") -> list[list[float]] | None:
        if not texts:
            return None
        # Snapshot the opaque handle and readiness under the same lock used by
        # stop() and _open().  Checking _handle before taking the lock leaves a
        # stop() window where the call can pass the check and then invoke C with
        # a handle that has just been freed.
        with self._lock:
            if not self._use_native or not self._ready or not self._handle:
                return None
            handle = self._handle
            dim = int(self._dim or 0)
            generation = int(self._generation)
            lib = self._native_lib or _NativeLib()
            if lib.lib is None:
                return None
        formatted = [self._format(t, purpose) for t in texts]
        # Guard against a single over-long doc overflowing the context.
        cap = self.max_input_chars
        formatted = [t[:cap] for t in formatted]
        if dim <= 0:
            return None
        keys = [(generation, purpose, t) for t in formatted]
        with self._vec_cache_lock:
            cached = [self._vec_cache.get(k) for k in keys]
        if all(v is not None for v in cached):
            with self._lock:
                if (
                    not self._use_native
                    or not self._ready
                    or self._handle != handle
                    or self._generation != generation
                ):
                    return None
            return [list(v) for v in cached]  # type: ignore[misc]
        # Claim missing keys under the cache lock. A call may own several
        # unique keys (which still get one batched native inference), while a
        # duplicate key in this or another call becomes a waiter.
        owners: list[int] = []
        waiters: list[tuple[int, threading.Event]] = []
        claimed_keys: set[tuple[int, str, str]] = set()
        with self._vec_cache_lock:
            for i, value in enumerate(cached):
                if value is not None:
                    continue
                key = keys[i]
                # Duplicate inputs in one batch share the first owner's
                # inference; they are not waiters (which would otherwise wait
                # on an event this same call has not yet signalled).
                if key in claimed_keys:
                    continue
                event = self._vec_inflight.get(key)
                if event is None:
                    event = threading.Event()
                    self._vec_inflight[key] = event
                    owners.append(i)
                    claimed_keys.add(key)
                else:
                    waiters.append((i, event))

        # Waiters never call the model themselves. A bounded wait prevents a
        # broken owner from holding an unrelated request forever; the owner
        # still completes and signals its event in the finally block below.
        for _index, event in waiters:
            event.wait(timeout=max(1.0, float(NATIVE_REQUEST_TIMEOUT)))
        if waiters:
            with self._vec_cache_lock:
                for i, _event in waiters:
                    cached[i] = self._vec_cache.get(keys[i])
            if any(cached[i] is None for i, _event in waiters):
                return None

        owner_keys = [keys[i] for i in owners]
        new_vecs: list[list[float]] = []
        try:
            if owners:
                missing = [formatted[i] for i in owners]
                n = len(missing)
                arr = (ctypes.c_char_p * n)(
                    *(s.encode("utf-8", errors="replace") for s in missing)
                )
                out = (ctypes.c_float * (n * dim))()
                with self._lock:
                    # Revalidate after formatting/cache work; stop() may have
                    # run in that gap and replaced/freed the original handle.
                    if (
                        not self._use_native
                        or not self._ready
                        or self._handle != handle
                        or self._generation != generation
                    ):
                        return None
                    # stop() cannot free ``handle`` until this call returns.
                    rc = lib.mcp_embed_encode(handle, arr, n, out)
                if rc != 0:
                    return None
                # The llama-server path L2-normalizes pooled embeddings
                # (common_embd_normalize); native returns the raw pooled vector.
                # Normalize here to keep stored vectors comparable to HTTP.
                for i in range(n):
                    row = [float(out[i * dim + j]) for j in range(dim)]
                    norm = math.sqrt(sum(x * x for x in row)) or 1.0
                    new_vecs.append([x / norm for x in row])
                # Use the same lock ordering as stop() (handle/generation
                # first, cache second). A recheck prevents an encode finishing
                # just before stop() from publishing old-generation vectors.
                with self._lock:
                    if (
                        not self._use_native
                        or not self._ready
                        or self._handle != handle
                        or self._generation != generation
                    ):
                        return None
                    with self._vec_cache_lock:
                        for i, vec in zip(owners, new_vecs, strict=True):
                            if len(self._vec_cache) >= self._vec_cache_max:
                                try:
                                    self._vec_cache.pop(next(iter(self._vec_cache)))
                                except Exception:
                                    self._vec_cache.clear()
                            self._vec_cache[keys[i]] = vec
            vecs = []
            for i in range(len(formatted)):
                value = cached[i]
                if value is None:
                    # Every owner was inserted above; this is defensive only.
                    with self._vec_cache_lock:
                        value = self._vec_cache.get(keys[i])
                if value is None:
                    return None
                vecs.append(list(value))
            return vecs
        finally:
            if owner_keys:
                with self._vec_cache_lock:
                    for key in owner_keys:
                        event = self._vec_inflight.pop(key, None)
                        if event is not None:
                            event.set()

    def embed(self, text: str, purpose: str = "document") -> _EmbedResult:
        vecs = self._encode([str(text)], purpose=purpose)
        if vecs:
            return _EmbedResult(vecs[0], self.backend, True)
        return _EmbedResult(None, "unavailable", False)

    def embed_vector(self, text: str, purpose: str = "document") -> list[float] | None:
        result = self.embed(text, purpose=purpose)
        return result.vector if result.ok else None

    def embed_query(self, text: str) -> _EmbedResult:
        return self.embed(text, purpose="query")

    def embed_query_vector(self, text: str) -> list[float] | None:
        return self.embed_vector(text, purpose="query")

    def embed_document(self, text: str) -> _EmbedResult:
        return self.embed(text, purpose="document")

    def embed_documents(self, texts: list[str]) -> list[_EmbedResult]:
        return self.embed_batch(list(texts), purpose="document")

    def embed_batch(self, texts: list[str], purpose: str = "document") -> list[_EmbedResult]:
        if not texts:
            return []
        vecs = self._encode(list(texts), purpose=purpose)
        if vecs is None:
            return [_EmbedResult(None, "unavailable", False) for _ in texts]
        return [_EmbedResult(v, self.backend, True) for v in vecs]

    @staticmethod
    def cosine(a: list[float], b: list[float]) -> float:
        from .helpers import cosine_similarity

        return cosine_similarity(a, b)


class NativeReranker:
    """In-process cross-encoder reranker — drop-in for ``rerank.Reranker``."""

    _instance: NativeReranker | None = None
    _lock = threading.Lock()

    def __new__(cls) -> NativeReranker:
        with cls._lock:
            if cls._instance is None:
                obj = super().__new__(cls)
                obj._init()
                cls._instance = obj
        return cls._instance

    @classmethod
    def reset(cls, model_path: str = "") -> NativeReranker:
        with cls._lock:
            if cls._instance is not None:
                previous = cls._instance
                cls._instance = None
                with __import__("contextlib").suppress(Exception):
                    previous.stop()
            obj = super().__new__(cls)
            obj._init()
            if model_path:
                # See NativeEmbedder.reset: _init may have opened the
                # discovered model, so close it before the explicit override.
                obj.stop()
                obj._model_path = os.path.abspath(os.path.expanduser(model_path))
                obj._profile = profile_from_rerank_model(
                    obj._model_path,
                    str(os.environ.get("IDA_MCP_RERANK_PROFILE") or ""),
                )
                # _init computed _ctx from the default-discovered model's
                # profile; recompute against the override so a custom profile
                # with a smaller max_context actually caps the buffer.
                obj._ctx = max(
                    512,
                    min(
                        _safe_int_env("IDA_MCP_RERANK_CTX", "1024"),
                        obj._profile.max_context,
                    ),
                )
                obj._open()
            cls._instance = obj
            return obj

    def _init(self) -> None:
        self._use_native = False
        self._ready = False
        self._handle: int | None = None
        self._native_lib: Any | None = None
        self._lock = threading.Lock()
        self._generation = 0
        self._server_bin = _find_llama_server() or ""  # kept for status parity
        self._model_path = _find_rerank_model()
        state = None
        try:
            from .rerank import _read_rerank_state

            state = _read_rerank_state()
        except Exception:
            pass
        requested_profile = os.environ.get("IDA_MCP_RERANK_PROFILE") or (
            (state or {}).get("profile")
        )
        self._profile = profile_from_rerank_model(
            self._model_path, str(requested_profile or "")
        )
        # Per-sequence budget for cross-encoder pairs.  1024 tokens is the
        # standard cap for reranker models (bge/qwen3-reranker): enough for
        # the query plus the decisive head of a function's pseudocode, while
        # keeping CPU latency bounded.  The embedder keeps the larger
        # NATIVE_CTX (2048) because its documents carry the full signal.
        self._ctx = max(
            512,
            min(
                _safe_int_env("IDA_MCP_RERANK_CTX", "1024"),
                self._profile.max_context,
            ),
        )
        self._score_cache: dict[str, list[float]] = {}
        self._score_cache_lock = threading.Lock()
        self._score_inflight: dict[str, threading.Event] = {}
        self._open()

    def _open(self) -> None:
        with self._lock:
            if self._use_native and self._ready and self._handle:
                return
            lib = _NativeLib()
            if lib.lib is None or not self._model_path or not os.path.isfile(self._model_path):
                self._use_native = False
                self._ready = False
                return
            handle = lib.mcp_rerank_new(
                self._model_path.encode("utf-8"),
                max(1, int(NATIVE_THREADS)),
                self._ctx,
            )
            if not handle:
                self._use_native = False
                self._ready = False
                return
            self._native_lib = lib
            self._handle = handle
            self._use_native = True
            self._ready = True

    @property
    def backend(self) -> str:
        with self._lock:
            return "native-llama" if self._use_native else "unavailable"

    @property
    def _use_llama(self) -> bool:
        # Call sites (e.g. tools/search/semantic.py) gate reranking on the
        # HTTP backend's "_use_llama" flag; expose the native readiness under
        # the same name so those gates just work.
        with self._lock:
            return bool(self._use_native)

    def status(self, probe: bool = False) -> dict:
        with self._lock:
            use_native = bool(self._use_native)
            ready = bool(self._ready and self._handle)
            lib = self._native_lib
        if lib is None:
            lib = _NativeLib()
        return {
            "backend": "native-llama" if use_native else "unavailable",
            "enabled": use_native,
            "profile": self._profile.key,
            "profile_name": self._profile.display_name,
            "family": self._profile.family,
            "model_license": self._profile.license,
            "server_bin": self._server_bin,
            "server_bin_exists": bool(self._server_bin and os.path.isfile(self._server_bin)),
            "model_path": self._model_path,
            "model_exists": bool(self._model_path and os.path.isfile(self._model_path)),
            "ready": ready,
            "port": None,
            "owns_process": True,
            "ctx": self._ctx,
            "max_candidates": 0,
            "last_recycle_reason": "",
            "native_lib": (lib.path if lib else ""),
            "native_lib_exists": bool(lib and lib.path),
        }

    def ensure_ready(self) -> bool:
        with self._lock:
            if self._use_native and self._ready and self._handle:
                return True
        self._open()
        with self._lock:
            return bool(self._use_native and self._ready and self._handle)

    def stop(self) -> None:
        # Take the score lock so a background thread mid-_score cannot read the
        # handle, then have it freed underneath llama.cpp (use-after-free).
        with self._lock:
            self._generation += 1
            if self._handle:
                lib = self._native_lib or _NativeLib()
                if lib.lib is not None:
                    with __import__("contextlib").suppress(Exception):
                        lib.mcp_rerank_free(self._handle)
            self._handle = None
            self._native_lib = None
            self._ready = False
            self._use_native = False
        with self._score_cache_lock:
            self._score_cache.clear()

    def _score(self, query: str, docs: list[str]) -> list[float] | None:
        if not docs:
            return None
        cache_key = _rerank_cache_key(query, docs)
        owner = False
        wait_event: threading.Event | None = None
        with self._score_cache_lock:
            cached = self._score_cache.get(cache_key)
            if cached is not None:
                return list(cached)
            if NATIVE_RERANK_CACHE_MAX > 0:
                wait_event = self._score_inflight.get(cache_key)
                if wait_event is None:
                    wait_event = threading.Event()
                    self._score_inflight[cache_key] = wait_event
                    owner = True
        if NATIVE_RERANK_CACHE_MAX > 0 and not owner:
            if wait_event is not None:
                wait_event.wait(timeout=max(1.0, float(NATIVE_REQUEST_TIMEOUT)))
            with self._score_cache_lock:
                cached = self._score_cache.get(cache_key)
            return list(cached) if cached is not None else None
        try:
            with self._lock:
                if not self._use_native or not self._ready or not self._handle:
                    return None
                handle = self._handle
                generation = self._generation
                lib = self._native_lib or _NativeLib()
                if lib.lib is None:
                    return None
            n = len(docs)
            arr = (ctypes.c_char_p * n)(
                *(d.encode("utf-8", errors="replace") for d in docs)
            )
            out = (ctypes.c_float * n)()
            with self._lock:
                if not self._use_native or not self._ready or self._handle != handle:
                    return None
                rc = lib.mcp_rerank_score(
                    handle, query.encode("utf-8", errors="replace"), arr, n, out
                )
            if rc != 0:
                return None
            scores = [float(out[i]) for i in range(n)]
            if NATIVE_RERANK_CACHE_MAX > 0:
                # Match stop()'s lock ordering (handle/generation first,
                # cache second) so a completed old-generation score can never
                # repopulate the cache after a stop/reopen.
                with self._lock:
                    if (
                        not self._use_native
                        or not self._ready
                        or self._handle != handle
                        or self._generation != generation
                    ):
                        return list(scores)
                    with self._score_cache_lock:
                        if len(self._score_cache) >= NATIVE_RERANK_CACHE_MAX:
                            try:
                                self._score_cache.pop(next(iter(self._score_cache)))
                            except Exception:
                                self._score_cache.clear()
                        self._score_cache[cache_key] = scores
            return list(scores)
        finally:
            if owner and wait_event is not None:
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
        the position in ``documents``), or ``None`` when unavailable/failed.
        Mirrors ``rerank.Reranker.rerank`` semantics: ``None`` means "keep the
        recall order", never a partial reorder.  A single native call scores
        the whole pool (no HTTP chunk round trips); ``deadline`` (a
        ``time.monotonic()`` timestamp) is honored once before the call.
        """
        if not documents:
            return []
        with self._lock:
            use_native = bool(self._use_native)
        if not use_native:
            return None
        with self._lock:
            ready = bool(self._ready and self._handle)
        if not ready and not self.ensure_ready():
            return None
        if deadline is not None and time.monotonic() >= deadline:
            return None
        docs = [str(d)[: max(256, int(NATIVE_DOC_CHARS))] for d in documents]
        scores = self._score(str(query), docs)
        if scores is None:
            return None
        out = [{"index": i, "score": float(s)} for i, s in enumerate(scores)]
        out.sort(key=lambda x: float(x["score"]), reverse=True)
        if top_k and top_k > 0:
            return out[: int(top_k)]
        return out
