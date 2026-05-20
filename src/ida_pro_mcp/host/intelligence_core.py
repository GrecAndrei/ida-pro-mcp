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
"""

from __future__ import annotations

import hashlib
import atexit
import json
import math
import os
import re
import sqlite3
import struct
import subprocess
import threading
import time
import uuid
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .intelligence_helpers import compact_policy_blob, derive_focus_candidates, prune_policy_store

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_SCRIPT_DIR))
_EMBED_LEASE_FILE = os.path.join("/tmp", "ida-mcp-embed-server.json")
_MODEL_PATH_CACHE = None

def _find_llama_server() -> str:
    """Locate llama-server binary from env, project dir, or PATH."""
    env = os.environ.get("IDA_MCP_EMBED_SERVER_BIN", "")
    if env and os.path.isfile(env):
        return env
    # Known locations relative to project
    candidates = [
        os.path.join(_PROJECT_ROOT, ".opencode-swarm", "llama-server"),
        os.path.join(os.path.expanduser("~"), "Downloads", "possibly",
                     "llama.cpp", "build-serm", "bin", "llama-server"),
        "/usr/local/bin/llama-server",
        "/usr/bin/llama-server",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return ""  # will trigger TF-IDF fallback


def _find_model() -> str:
    """Locate the embedding GGUF from env or common locations."""
    global _MODEL_PATH_CACHE
    if isinstance(_MODEL_PATH_CACHE, str):
        return _MODEL_PATH_CACHE
    env = os.environ.get("IDA_MCP_EMBED_MODEL", "")
    if env and os.path.isfile(env):
        _MODEL_PATH_CACHE = env
        return env
    candidates = [
        os.path.join(_PROJECT_ROOT, ".opencode-swarm", "bge-code-v1-q8_0.gguf"),
        os.path.join(os.path.dirname(_SCRIPT_DIR), "..", "..", ".opencode-swarm",
                     "bge-code-v1-q8_0.gguf"),
        os.path.join(os.path.expanduser("~"), "Downloads", "bge-code-v1-q8_0.gguf"),
        os.path.join(os.path.expanduser("~"), "models", "bge-code-v1-q8_0.gguf"),
        os.path.join(os.path.expanduser("~"), ".cache", "huggingface", "bge-code-v1-q8_0.gguf"),
    ]
    for c in candidates:
        p = os.path.abspath(c)
        if os.path.isfile(p):
            _MODEL_PATH_CACHE = p
            return p
    # Glob search in ~/Downloads and ~/models
    import glob
    for search_root in (
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.path.join(os.path.expanduser("~"), "models"),
    ):
        for p in glob.glob(os.path.join(search_root, "**", "bge-code-v1*.gguf"), recursive=True):
            if os.path.isfile(p):
                _MODEL_PATH_CACHE = p
                return p
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


_NOISE_IDENTS = frozenset({
    "int", "char", "void", "uint", "size", "len", "buf", "ptr", "tmp", "ret",
    "var", "idx", "for", "while", "return", "NULL", "sizeof", "unsigned",
    "signed", "long", "short", "struct", "else", "true", "false", "bool",
    "this", "auto", "const", "static", "inline", "extern", "typedef",
    "goto", "break", "continue", "switch", "case", "default",
    "result", "value", "data", "type", "flag", "mode", "count", "num",
    "out", "res", "src", "dst", "key", "val", "arg", "msg", "str",
    "memcpy", "memset", "memcmp", "memmove", "malloc", "calloc", "free",
    "printf", "sprintf", "strcpy", "strlen", "strcat", "strcmp",
})

_IDENT_RE = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]{2,}\b')


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
        lo = ident.lower()
        if lo in _NOISE_IDENTS:
            continue
        if ident not in seen:
            seen.add(ident)
            out.append(ident)
            if len(out) >= max_idents:
                break
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
        self._idf: Dict[str, float] = {}
        self._doc_count = 0

    def _tokens(self, text: str) -> List[str]:
        return self._TOKENIZE.findall(text.lower())

    def fit_many(self, texts: List[str]) -> None:
        df: Counter = Counter()
        for t in texts:
            df.update(set(self._tokens(t)))
        n = max(1, len(texts))
        self._idf = {tok: math.log((n + 1) / (cnt + 1)) + 1
                     for tok, cnt in df.items()}
        self._doc_count = n

    def embed(self, text: str) -> List[float]:
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

    _instance: Optional["BgeCodeEmbedder"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "BgeCodeEmbedder":
        with cls._lock:
            if cls._instance is None:
                obj = super().__new__(cls)
                obj._init()
                cls._instance = obj
        return cls._instance

    def _init(self) -> None:
        self._server_bin   = _find_llama_server()
        self._model_path   = _find_model()
        self._port: Optional[int] = None
        self._proc: Optional[subprocess.Popen] = None
        self._ready        = False
        self._start_lock   = threading.Lock()
        self._fallback     = _TFIDFEmbedder()
        self._use_llama    = (bool(self._server_bin) and bool(self._model_path)
                              and not EMBED_DISABLED)
        # Cached anchor embeddings for BehaviorClassifier
        self._anchor_cache: Dict[str, List[float]] = {}
        self._batch_size = int(os.environ.get("IDA_MCP_EMBED_BATCH", "16"))
        self._batch_size = max(1, min(64, self._batch_size))
        self._batch_lock = threading.Lock()
        self._owns_proc = False
        self._consecutive_rpc_failures = 0
        self._max_rpc_failures = max(1, EMBED_MAX_FAILURES)

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
                    with open(_EMBED_LEASE_FILE, "r", encoding="utf-8") as f:
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

    def _llama_embed(self, text: str) -> Optional[List[float]]:
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

    def _llama_embed_batch(self, texts: List[str]) -> Optional[List[List[float]]]:
        if not texts:
            return []
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
            out: List[List[float]] = []
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

    def embed(self, text: str) -> List[float]:
        """Return L2-normalized 1536-dim embedding for text."""
        if self._use_llama:
            vec = self._llama_embed(text)
            if vec is not None:
                return vec
        # Fallback
        return self._fallback.embed(text)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        if self._use_llama:
            out: List[List[float]] = []
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
    def cosine(a: List[float], b: List[float]) -> float:
        return sum(x * y for x, y in zip(a, b))


# ─────────────────────────────────────────────────────────────────────────────
# FunctionEmbeddingIndex — per-binary SQLite embedding store
# ─────────────────────────────────────────────────────────────────────────────

class FunctionEmbeddingIndex:
    """
    Stores 1536-dim float32 embeddings of decompiled functions,
    one SQLite database per binary (<idb_path>.embeddings.db).

    Replaces MbaGCN (untrained random SSM) and TurboQuant (quantization
    of tabular features it was never designed for).
    """

    def __init__(self, db_path: str, embedder: BgeCodeEmbedder):
        self._db_path = db_path
        self._embedder = embedder
        self._cache: Dict[str, List[float]] = {}  # ea_hex → embedding
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        self._load_cache()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS func_embeddings (
                    ea       TEXT PRIMARY KEY,
                    name     TEXT,
                    dim      INTEGER,
                    vec_blob BLOB NOT NULL,
                    pseudo_hash TEXT,
                    indexed_at  REAL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fe_name ON func_embeddings(name)")
            conn.commit()

    def _load_cache(self) -> None:
        """Load all stored embeddings into RAM for fast cosine search."""
        try:
            with self._conn() as conn:
                for row in conn.execute("SELECT ea, vec_blob FROM func_embeddings"):
                    ea, blob = row
                    n = len(blob) // 4
                    self._cache[ea] = list(struct.unpack(f"{n}f", blob))
        except Exception:
            pass

    def _pack(self, vec: List[float]) -> bytes:
        return struct.pack(f"{len(vec)}f", *vec)

    def _unpack(self, blob: bytes) -> List[float]:
        n = len(blob) // 4
        return list(struct.unpack(f"{n}f", blob))

    def _phash(self, text: str) -> str:
        return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()[:16]

    def index(self, func_ea: str, name: str, pseudocode: str) -> None:
        """Embed and store a function. Skips if pseudocode unchanged."""
        ph = self._phash(pseudocode)
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT pseudo_hash FROM func_embeddings WHERE ea=?", (func_ea,)
                ).fetchone()
                if row and row[0] == ph:
                    return  # unchanged
        except Exception:
            pass

        vec = self._embedder.embed(pseudocode)
        blob = self._pack(vec)
        self._cache[func_ea] = vec
        try:
            with self._conn() as conn:
                conn.execute("""
                    INSERT INTO func_embeddings(ea, name, dim, vec_blob, pseudo_hash, indexed_at)
                    VALUES(?,?,?,?,?,?)
                    ON CONFLICT(ea) DO UPDATE SET
                        name=excluded.name,
                        vec_blob=excluded.vec_blob,
                        pseudo_hash=excluded.pseudo_hash,
                        indexed_at=excluded.indexed_at
                """, (func_ea, name, len(vec), blob, ph, time.time()))
                conn.commit()
        except Exception:
            pass

    def index_async(self, func_ea: str, name: str, pseudocode: str) -> None:
        """Non-blocking index: fire-and-forget in background thread."""
        ph = self._phash(pseudocode)
        if self._cache.get(func_ea) is not None:
            # Check if we already have this exact pseudocode
            try:
                with self._conn() as conn:
                    row = conn.execute(
                        "SELECT pseudo_hash FROM func_embeddings WHERE ea=?", (func_ea,)
                    ).fetchone()
                    if row and row[0] == ph:
                        return
            except Exception:
                pass
        t = threading.Thread(target=self.index, args=(func_ea, name, pseudocode), daemon=True)
        t.start()

    def similar_vec(
        self,
        query_vec: List[float],
        top_k: int = 5,
        exclude_ea: Optional[str] = None,
        threshold: float = 0.6,
    ) -> List[Dict[str, Any]]:
        """Return top-k most similar functions given a pre-computed query vector."""
        if not self._cache:
            return []
        # Snapshot to avoid RuntimeError if background _store_vec thread
        # writes to _cache while we iterate (GIL alone doesn't protect iteration).
        try:
            snapshot = list(self._cache.items())
        except RuntimeError:
            return []
        scored: List[Tuple[float, str]] = []
        for ea, vec in snapshot:
            if ea == exclude_ea:
                continue
            sim = BgeCodeEmbedder.cosine(query_vec, vec)
            if sim >= threshold:
                scored.append((sim, ea))
        scored.sort(reverse=True)
        if not scored:
            return []
        top_eas = [ea for _, ea in scored[:top_k]]
        names: Dict[str, str] = {}
        try:
            with self._conn() as conn:
                ph = ",".join("?" * len(top_eas))
                for row in conn.execute(
                    f"SELECT ea, name FROM func_embeddings WHERE ea IN ({ph})", top_eas
                ):
                    names[row[0]] = row[1] or row[0]
        except Exception:
            pass
        return [
            {"ea": ea, "name": names.get(ea, ea), "similarity": round(sim, 4)}
            for sim, ea in scored[:top_k]
        ]

    def similar(
        self,
        pseudocode: str,
        top_k: int = 5,
        exclude_ea: Optional[str] = None,
        threshold: float = 0.6,
    ) -> List[Dict[str, Any]]:
        """Return top-k most similar functions by cosine similarity."""
        if not self._cache:
            return []
        q = self._embedder.embed(pseudocode)
        scored: List[Tuple[float, str]] = []
        for ea, vec in self._cache.items():
            if ea == exclude_ea:
                continue
            sim = BgeCodeEmbedder.cosine(q, vec)
            if sim >= threshold:
                scored.append((sim, ea))
        scored.sort(reverse=True)
        if not scored:
            return []
        # Fetch names for top results
        top_eas = [ea for _, ea in scored[:top_k]]
        names: Dict[str, str] = {}
        try:
            with self._conn() as conn:
                ph = ",".join("?" * len(top_eas))
                for row in conn.execute(
                    f"SELECT ea, name FROM func_embeddings WHERE ea IN ({ph})",
                    top_eas
                ):
                    names[row[0]] = row[1] or row[0]
        except Exception:
            pass
        return [
            {"ea": ea, "name": names.get(ea, ea), "similarity": round(sim, 4)}
            for sim, ea in scored[:top_k]
        ]

    @property
    def size(self) -> int:
        return len(self._cache)


# ─────────────────────────────────────────────────────────────────────────────
# PreferenceMemoryBank — shared learned-ranking backend for MemRL
# ─────────────────────────────────────────────────────────────────────────────

REWARD_ACCEPT = 1.0
REWARD_PARTIAL = 0.5
REWARD_NEUTRAL = 0.0
REWARD_REJECT = -0.5
REWARD_DANGEROUS = -1.0

Q_FLOOR = -1.0
Q_CEILING = 1.0
DEFAULT_ALPHA = 0.15


class PreferenceMemoryBank:
    """
    SQLite-backed intent/expression utility memory.

    This is the canonical runtime backend for MemRL-style ranking and
    suggestion tracking. The legacy `ida_mcp.tools.memrl` module remains as a
    compatibility surface for tests and direct imports.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.path.join(os.path.expanduser("~"), ".ida-pro-mcp", "memrl.db")
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memrl_triplets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    intent_key TEXT NOT NULL,
                    experience_key TEXT NOT NULL,
                    intent_z BLOB,
                    experience_meta TEXT,
                    q_value REAL NOT NULL DEFAULT 0.5,
                    visit_count INTEGER NOT NULL DEFAULT 0,
                    last_updated REAL NOT NULL,
                    UNIQUE(intent_key, experience_key)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_intent ON memrl_triplets(intent_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_experience ON memrl_triplets(experience_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_q_value ON memrl_triplets(q_value)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memrl_suggestions (
                    suggestion_id TEXT PRIMARY KEY,
                    intent_key TEXT NOT NULL,
                    experience_key TEXT NOT NULL,
                    source_tool TEXT DEFAULT '',
                    source_action TEXT DEFAULT '',
                    context_addr TEXT DEFAULT '',
                    experience_meta TEXT,
                    q_value REAL NOT NULL DEFAULT 0.5,
                    initial_q REAL NOT NULL DEFAULT 0.5,
                    reward REAL,
                    feedback_type TEXT,
                    feedback_timestamp REAL,
                    created_at REAL NOT NULL,
                    last_updated REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sug_intent ON memrl_suggestions(intent_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sug_created ON memrl_suggestions(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sug_feedback ON memrl_suggestions(feedback_type)")
            conn.commit()

    def record(
        self,
        intent_key: str,
        experience_key: str,
        intent_z: Optional[bytes] = None,
        experience_meta: Optional[dict] = None,
        initial_q: float = 0.5,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO memrl_triplets
                (intent_key, experience_key, intent_z, experience_meta, q_value, visit_count, last_updated)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(intent_key, experience_key) DO UPDATE SET
                    visit_count = visit_count + 1,
                    last_updated = excluded.last_updated
                """,
                (
                    intent_key,
                    experience_key,
                    intent_z,
                    json.dumps(experience_meta) if experience_meta else None,
                    initial_q,
                    time.time(),
                ),
            )
            conn.commit()

    def update_q(
        self,
        intent_key: str,
        experience_key: str,
        reward: float,
        alpha: float = DEFAULT_ALPHA,
    ) -> float:
        reward = max(Q_FLOOR, min(Q_CEILING, reward))
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT q_value FROM memrl_triplets WHERE intent_key = ? AND experience_key = ?",
                (intent_key, experience_key),
            )
            row = cur.fetchone()
            if row is None:
                new_q = reward
                self.record(intent_key, experience_key, initial_q=new_q)
                return new_q
            old_q = float(row[0])
            new_q = max(Q_FLOOR, min(Q_CEILING, old_q + alpha * (reward - old_q)))
            cur.execute(
                """
                UPDATE memrl_triplets
                SET q_value = ?, last_updated = ?, visit_count = visit_count + 1
                WHERE intent_key = ? AND experience_key = ?
                """,
                (new_q, time.time(), intent_key, experience_key),
            )
            conn.commit()
            return new_q

    def batch_update_q(
        self,
        intent_key: str,
        experience_keys: List[str],
        rewards: List[float],
        alpha: float = DEFAULT_ALPHA,
    ) -> Dict[str, float]:
        return {
            ek: self.update_q(intent_key, ek, reward=r, alpha=alpha)
            for ek, r in zip(experience_keys, rewards)
        }

    def two_phase_retrieve(
        self,
        intent_key: str,
        candidate_pool: List[Dict[str, Any]],
        top_k: int = 10,
        lambda_explore: float = 0.3,
        similarity_key: str = "score",
    ) -> List[Dict[str, Any]]:
        if not candidate_pool:
            return []
        with self._conn() as conn:
            cur = conn.cursor()
            sims = [float(c.get(similarity_key, 0.0) or 0.0) for c in candidate_pool]
            n = len(sims)
            sim_mean = sum(sims) / n if n else 0.0
            sim_std = math.sqrt(sum((s - sim_mean) ** 2 for s in sims) / n) if n > 1 else 1.0
            if sim_std < 1e-9:
                sim_std = 1.0
            q_vals: List[float] = []
            for c in candidate_pool:
                exp_key = c.get("ea", c.get("name", str(id(c))))
                cur.execute(
                    "SELECT q_value FROM memrl_triplets WHERE intent_key = ? AND experience_key = ?",
                    (intent_key, exp_key),
                )
                row = cur.fetchone()
                q_vals.append(float(row[0]) if row else 0.5)
            q_mean = sum(q_vals) / n if n else 0.0
            q_std = math.sqrt(sum((q - q_mean) ** 2 for q in q_vals) / n) if n > 1 else 1.0
            if q_std < 1e-9:
                q_std = 1.0
        scored: List[Tuple[Dict[str, Any], float, float]] = []
        for c, sim, q in zip(candidate_pool, sims, q_vals):
            norm_sim = (sim - sim_mean) / sim_std
            norm_q = (q - q_mean) / q_std
            final_score = (1.0 - lambda_explore) * norm_sim + lambda_explore * norm_q
            scored.append((c, final_score, q))
        scored.sort(key=lambda x: x[1], reverse=True)
        out: List[Dict[str, Any]] = []
        for c, final_score, q in scored[:top_k]:
            merged = dict(c)
            merged["memrl_score"] = round(final_score, 4)
            merged["q_value"] = round(q, 4)
            out.append(merged)
        return out

    def get_q(self, intent_key: str, experience_key: str) -> float:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT q_value FROM memrl_triplets WHERE intent_key = ? AND experience_key = ?",
                (intent_key, experience_key),
            ).fetchone()
            return float(row[0]) if row else 0.5

    def ingest_suggestion(
        self,
        intent_key: str,
        experience_key: str,
        source_tool: str = "",
        source_action: str = "",
        context_addr: str = "",
        experience_meta: Optional[dict] = None,
        initial_q: float = 0.5,
    ) -> str:
        suggestion_id = uuid.uuid4().hex[:12]
        now = time.time()
        self.record(
            intent_key=intent_key,
            experience_key=experience_key,
            experience_meta=experience_meta,
            initial_q=initial_q,
        )
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO memrl_suggestions
                (suggestion_id, intent_key, experience_key, source_tool, source_action,
                 context_addr, experience_meta, q_value, initial_q, created_at, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    suggestion_id,
                    intent_key,
                    experience_key,
                    source_tool,
                    source_action,
                    context_addr,
                    json.dumps(experience_meta) if experience_meta else None,
                    initial_q,
                    initial_q,
                    now,
                    now,
                ),
            )
            conn.commit()
        return suggestion_id

    def auto_reward_for_addr(
        self,
        addr: str,
        reward: float = 0.7,
        alpha: float = DEFAULT_ALPHA,
        max_age_seconds: float = 1800.0,
    ) -> int:
        cutoff = time.time() - max_age_seconds
        updated = 0
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT suggestion_id, intent_key, experience_key, q_value
                FROM memrl_suggestions
                WHERE context_addr = ?
                  AND (feedback_type IS NULL OR feedback_type = 'neutral')
                  AND created_at >= ?
                ORDER BY created_at DESC
                LIMIT 5
                """,
                (addr, cutoff),
            )
            rows = cur.fetchall()
            now = time.time()
            for suggestion_id, intent_key, experience_key, old_q in rows:
                old_q = float(old_q or 0.5)
                new_q = max(Q_FLOOR, min(Q_CEILING, old_q + alpha * (reward - old_q)))
                cur.execute(
                    """
                    UPDATE memrl_suggestions
                    SET q_value = ?, reward = ?, feedback_type = 'auto_accept',
                        feedback_timestamp = ?, last_updated = ?
                    WHERE suggestion_id = ?
                    """,
                    (new_q, reward, now, now, suggestion_id),
                )
                self.update_q(intent_key, experience_key, reward, alpha)
                updated += 1
            conn.commit()
        return updated

    @staticmethod
    def _classify_reward(reward: float) -> str:
        if reward >= 0.8:
            return "accept"
        if reward >= 0.3:
            return "partial"
        if reward >= -0.2:
            return "neutral"
        if reward >= -0.8:
            return "reject"
        return "dangerous"

    def process_feedback(
        self,
        suggestion_id: str,
        reward: float,
        alpha: float = DEFAULT_ALPHA,
    ) -> Dict[str, Any]:
        reward = max(Q_FLOOR, min(Q_CEILING, reward))
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT intent_key, experience_key, q_value FROM memrl_suggestions WHERE suggestion_id = ?",
                (suggestion_id,),
            )
            row = cur.fetchone()
            if row is None:
                return {"ok": False, "error": f"Suggestion not found: {suggestion_id}"}
            intent_key, experience_key, old_q = str(row[0]), str(row[1]), float(row[2])
            td_error = reward - old_q
            new_q = max(Q_FLOOR, min(Q_CEILING, old_q + alpha * td_error))
            now = time.time()
            cur.execute(
                """
                UPDATE memrl_suggestions
                SET q_value = ?, reward = ?, feedback_type = ?,
                    feedback_timestamp = ?, last_updated = ?
                WHERE suggestion_id = ?
                """,
                (new_q, reward, self._classify_reward(reward), now, now, suggestion_id),
            )
            conn.commit()
        self.update_q(intent_key, experience_key, reward, alpha)
        return {
            "ok": True,
            "suggestion_id": suggestion_id,
            "old_q": round(old_q, 4),
            "new_q": round(new_q, 4),
            "reward": reward,
            "td_error": round(td_error, 4),
            "alpha": alpha,
            "feedback_type": self._classify_reward(reward),
        }

    def suggest_best(
        self,
        query_embedding: Optional[List[float]],
        candidate_pool: List[Dict[str, Any]],
        intent_key: str = "",
        top_k: int = 10,
        lambda_explore: float = 0.3,
        similarity_key: str = "score",
        epsilon: float = 0.0,
    ) -> List[Dict[str, Any]]:
        if not candidate_pool:
            return []
        if epsilon > 0:
            bucket = int(hashlib.md5((str(time.time()) + intent_key).encode()).hexdigest(), 16) % 1000
            if bucket < int(epsilon * 1000):
                selected = candidate_pool[: min(top_k, len(candidate_pool))]
                for s in selected:
                    s["memrl_score"] = 0.0
                    s["q_value"] = self.get_q(intent_key, s.get("ea", s.get("name", str(id(s)))))
                return selected
        return self.two_phase_retrieve(
            intent_key=intent_key,
            candidate_pool=candidate_pool,
            top_k=top_k,
            lambda_explore=lambda_explore,
            similarity_key=similarity_key,
        )

    def get_suggestion(self, suggestion_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT suggestion_id, intent_key, experience_key,
                       source_tool, source_action, context_addr,
                       experience_meta, q_value, initial_q,
                       reward, feedback_type, feedback_timestamp,
                       created_at, last_updated
                FROM memrl_suggestions WHERE suggestion_id = ?
                """,
                (suggestion_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "suggestion_id": row[0],
                "intent_key": row[1],
                "experience_key": row[2],
                "source_tool": row[3],
                "source_action": row[4],
                "context_addr": row[5],
                "experience_meta": json.loads(row[6]) if row[6] else None,
                "q_value": round(float(row[7]), 4),
                "initial_q": round(float(row[8]), 4),
                "reward": row[9],
                "feedback_type": row[10],
                "feedback_timestamp": row[11],
                "created_at": row[12],
                "last_updated": row[13],
            }

    def list_suggestions(self, intent_key: str = "", limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        with self._conn() as conn:
            cur = conn.cursor()
            if intent_key:
                cur.execute(
                    """
                    SELECT suggestion_id, intent_key, experience_key,
                           source_tool, source_action, context_addr,
                           q_value, feedback_type, created_at
                    FROM memrl_suggestions WHERE intent_key = ?
                    ORDER BY created_at DESC LIMIT ? OFFSET ?
                    """,
                    (intent_key, limit, offset),
                )
                rows = cur.fetchall()
                total = conn.execute(
                    "SELECT COUNT(*) FROM memrl_suggestions WHERE intent_key = ?",
                    (intent_key,),
                ).fetchone()[0] or 0
            else:
                cur.execute(
                    """
                    SELECT suggestion_id, intent_key, experience_key,
                           source_tool, source_action, context_addr,
                           q_value, feedback_type, created_at
                    FROM memrl_suggestions ORDER BY created_at DESC LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
                rows = cur.fetchall()
                total = conn.execute("SELECT COUNT(*) FROM memrl_suggestions").fetchone()[0] or 0
            suggestions = [
                {
                    "suggestion_id": r[0],
                    "intent_key": r[1],
                    "experience_key": r[2],
                    "source_tool": r[3],
                    "source_action": r[4],
                    "context_addr": r[5],
                    "q_value": round(float(r[6]), 4),
                    "feedback_type": r[7],
                    "created_at": r[8],
                }
                for r in rows
            ]
            return {"ok": True, "suggestions": suggestions, "total": int(total), "count": len(suggestions)}

    def stats(self) -> Dict[str, Any]:
        with self._conn() as conn:
            cur = conn.cursor()
            total, avg_q, max_q, min_q = cur.execute(
                "SELECT COUNT(*), AVG(q_value), MAX(q_value), MIN(q_value) FROM memrl_triplets"
            ).fetchone()
            total_visits = cur.execute("SELECT SUM(visit_count) FROM memrl_triplets").fetchone()[0] or 0
            unique_intents = cur.execute("SELECT COUNT(DISTINCT intent_key) FROM memrl_triplets").fetchone()[0] or 0
            total_suggestions = cur.execute("SELECT COUNT(*) FROM memrl_suggestions").fetchone()[0] or 0
            feedback_count = cur.execute(
                "SELECT COUNT(*) FROM memrl_suggestions WHERE feedback_type IS NOT NULL"
            ).fetchone()[0] or 0
            feedback_dist = {
                r[0]: r[1]
                for r in cur.execute(
                    "SELECT feedback_type, COUNT(*) FROM memrl_suggestions WHERE feedback_type IS NOT NULL GROUP BY feedback_type"
                ).fetchall()
            }
            top_q = [
                {
                    "intent_key": r[0],
                    "experience_key": r[1],
                    "q_value": round(float(r[2]), 4),
                    "visit_count": r[3],
                }
                for r in cur.execute(
                    "SELECT intent_key, experience_key, q_value, visit_count FROM memrl_triplets ORDER BY q_value DESC LIMIT 5"
                ).fetchall()
            ]
            bottom_q = [
                {
                    "intent_key": r[0],
                    "experience_key": r[1],
                    "q_value": round(float(r[2]), 4),
                    "visit_count": r[3],
                }
                for r in cur.execute(
                    "SELECT intent_key, experience_key, q_value, visit_count FROM memrl_triplets ORDER BY q_value ASC LIMIT 5"
                ).fetchall()
            ]
            recent_qs = [r[0] for r in cur.execute(
                "SELECT q_value FROM memrl_triplets ORDER BY last_updated DESC LIMIT 100"
            ).fetchall()]
            recent_n = len(recent_qs)
            recent_avg = sum(recent_qs) / recent_n if recent_n else 0.0
            recent_std = math.sqrt(sum((q - recent_avg) ** 2 for q in recent_qs) / recent_n) if recent_n > 1 else 0.0
            histogram = {"[-1.0, -0.5)": 0, "[-0.5, 0.0)": 0, "[0.0, 0.5)": 0, "[0.5, 1.0]": 0}
            for (qv,) in cur.execute("SELECT q_value FROM memrl_triplets").fetchall():
                if qv < -0.5:
                    histogram["[-1.0, -0.5)"] += 1
                elif qv < 0.0:
                    histogram["[-0.5, 0.0)"] += 1
                elif qv < 0.5:
                    histogram["[0.0, 0.5)"] += 1
                else:
                    histogram["[0.5, 1.0]"] += 1
            return {
                "ok": True,
                "total_triplets": int(total or 0),
                "unique_intents": int(unique_intents),
                "avg_q_value": round(float(avg_q), 4) if avg_q is not None else 0.0,
                "max_q_value": round(float(max_q), 4) if max_q is not None else 0.0,
                "min_q_value": round(float(min_q), 4) if min_q is not None else 0.0,
                "total_visits": int(total_visits),
                "total_suggestions": int(total_suggestions),
                "feedback_count": int(feedback_count),
                "feedback_rate": round(feedback_count / total_suggestions, 4) if total_suggestions else 0.0,
                "feedback_distribution": feedback_dist,
                "recent_q_avg": round(recent_avg, 4),
                "recent_q_std": round(recent_std, 4),
                "q_value_histogram": histogram,
                "top_q_memories": top_q,
                "bottom_q_memories": bottom_q,
            }

    def top_memories(self, intent_key: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            cur = conn.cursor()
            if intent_key:
                rows = cur.execute(
                    """
                    SELECT intent_key, experience_key, q_value, visit_count, experience_meta
                    FROM memrl_triplets WHERE intent_key = ? ORDER BY q_value DESC LIMIT ?
                    """,
                    (intent_key, limit),
                ).fetchall()
            else:
                rows = cur.execute(
                    """
                    SELECT intent_key, experience_key, q_value, visit_count, experience_meta
                    FROM memrl_triplets ORDER BY q_value DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            return [
                {
                    "intent_key": r[0],
                    "experience_key": r[1],
                    "q_value": round(float(r[2]), 4),
                    "visit_count": r[3],
                    "meta": json.loads(r[4]) if r[4] else None,
                }
                for r in rows
            ]

    def clear(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM memrl_triplets")
            conn.execute("DELETE FROM memrl_suggestions")
            conn.commit()

    def prune_low_q(self, threshold: float = -0.5) -> int:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM memrl_triplets WHERE q_value < ?", (threshold,))
            pruned = cur.rowcount
            conn.commit()
            return int(pruned)


def emit_memrl_suggestion(
    source_tool: str,
    source_action: str,
    addr: str,
    value: str,
    db_path: Optional[str] = None,
) -> str:
    bank = PreferenceMemoryBank(db_path=db_path)
    intent_key = f"{source_tool}:{source_action}:{addr}"
    experience_key = f"{source_tool}:{source_action}:{addr}:{value[:64]}"
    return bank.ingest_suggestion(
        intent_key=intent_key,
        experience_key=experience_key,
        source_tool=source_tool,
        source_action=source_action,
        context_addr=addr,
        experience_meta={"value": value},
        initial_q=0.5,
    )


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
    ANCHORS: Dict[str, str] = {
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
    ANCHOR_MIN_CONFIDENCE: Dict[str, float] = {
        "buffer_overflow": 0.35,
        "use_after_free": 0.35,
        "format_string_vuln": 0.35,
        "integer_overflow": 0.35,
        "path_traversal": 0.35,
    }

    # Module-level singleton so anchors are loaded exactly once per process.
    _shared: Optional["BehaviorClassifier"] = None
    _shared_lock = threading.Lock()

    @classmethod
    def instance(cls, embedder: "BgeCodeEmbedder") -> "BehaviorClassifier":
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
        self._anchor_embs: Dict[str, List[float]] = {}
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

    def refresh_anchors(self, behaviors: Optional[List[str]] = None) -> None:
        """Pre-warm the anchor cache.

        If `behaviors` is omitted, all anchors are refreshed. Otherwise only the
        named behaviors are re-embedded.
        """
        targets = behaviors or list(self.ANCHORS.keys())
        with self._anchor_lock:
            generation = self._anchor_generation
        for behavior in targets:
            self._get_anchor(behavior, generation=generation)

    def _get_anchor(self, behavior: str, generation: Optional[int] = None) -> Optional[List[float]]:
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
        query_vec: List[float],
        threshold: float = 0.25,
        top_k: int = 4,
        block: bool = False,
    ) -> List[Dict[str, Any]]:
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
            min_thr = max(float(threshold or 0.0), float(self.ANCHOR_MIN_CONFIDENCE.get(behavior, 0.30)))
            if sim >= min_thr:
                results.append({"behavior": behavior, "confidence": round(sim, 4)})

        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results[:top_k]

    @staticmethod
    def _anchor_explain(anchor_text: str, query_text: str) -> List[str]:
        phrases = [p.strip() for p in anchor_text.split(";") if p.strip()]
        q_tokens = set(re.findall(r"[A-Za-z0-9_]+", (query_text or "").lower()))
        scored: List[tuple[int, str]] = []
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

    def classify(
        self,
        text: str,
        threshold: float = 0.25,
        max_tokens: int = 3000,
        top_k: int = 4,
        block: bool = False,
    ) -> List[Dict[str, Any]]:
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
        for row in rows:
            b = str(row.get("behavior") or "")
            row["explain"] = self._anchor_explain(self.ANCHORS.get(b, ""), query)
        return rows

    def _classify_impl(
        self,
        q: List[float],
        threshold: float = 0.25,
        top_k: int = 4,
        block: bool = True,
    ) -> List[Dict[str, Any]]:
        """Internal compatibility wrapper for older call sites."""
        return self.classify_vec(q, threshold=threshold, top_k=top_k, block=block)

    def anchor_coverage_report(self, min_similarity: float = 0.4, max_funcs: int = 5000) -> Dict[str, Any]:
        """Report how many functions match each anchor above min_similarity."""
        rows = []
        try:
            funcs = list(idautils.Functions())[:max(1, int(max_funcs))]
        except Exception:
            funcs = []
        cache: List[Tuple[int, List[float]]] = []
        for ea in funcs:
            try:
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
