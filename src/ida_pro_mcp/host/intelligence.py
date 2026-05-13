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
    env = os.environ.get("IDA_MCP_EMBED_MODEL", "")
    if env and os.path.isfile(env):
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
            return p
    # Glob search in ~/Downloads and ~/models
    import glob
    for search_root in (
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.path.join(os.path.expanduser("~"), "models"),
    ):
        for p in glob.glob(os.path.join(search_root, "**", "bge-code-v1*.gguf"), recursive=True):
            if os.path.isfile(p):
                return p
    return ""


EMBED_DIM = 1536          # bge-code-v1 embedding dimension
EMBED_CTX = int(os.environ.get("IDA_MCP_EMBED_CTX", "2048"))
EMBED_THREADS = int(os.environ.get("IDA_MCP_EMBED_THREADS",
                                    str(max(2, (os.cpu_count() or 4) // 2))))
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
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            vec = data["data"][0]["embedding"]
            # Server already L2-normalizes; verify and re-normalize just in case
            norm = math.sqrt(sum(x * x for x in vec)) or 1.0
            return [x / norm for x in vec]
        except Exception:
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
            with urllib.request.urlopen(req, timeout=60) as resp:
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
            return out
        except Exception:
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
        # Short code-signature anchors — 15-30 tokens each.
        # Long code blocks were taking 1-9s per anchor to embed.
        # These are dense enough to give 0.6-0.8 cosine similarity
        # on matching decompiled pseudocode.
        "crypto_symmetric":
            "sub_bytes shift_rows mix_columns add_round_key key_schedule "
            "sbox[256] round_keys[44] AES_encrypt AES_decrypt xor_block rotate",

        "crypto_hash":
            "MD5_update SHA1_compress SHA256_round h0 h1 h2 h3 "
            "hash_block digest_final HMAC_init 0x67452301 0xEFCDAB89",

        "network_http":
            "send_http_request recv_response HTTP_GET HTTP_POST "
            "User_Agent Content_Type url_encode http_connect 443 80",

        "network_raw":
            "socket AF_INET SOCK_STREAM connect send recv bind listen "
            "inet_addr htons IPPROTO_TCP WSASocket WSAConnect",

        "process_injection":
            "VirtualAllocEx WriteProcessMemory CreateRemoteThread "
            "OpenProcess PROCESS_ALL_ACCESS shellcode inject PAGE_EXECUTE_READWRITE",

        "file_operations":
            "CreateFileW ReadFile WriteFile CloseHandle fopen fread fwrite "
            "GetTempPath FindFirstFile FindNextFile DeleteFile MoveFile",

        "anti_debug":
            "IsDebuggerPresent CheckRemoteDebuggerPresent NtQueryInformationProcess "
            "OutputDebugString RDTSC timing_check heap_flag int3 exception_filter",

        "anti_vm":
            "CPUID hypervisor_bit VMware VirtualBox cpuid_vendor_check "
            "mac_address disk_size registry_vm_key sandbox_detect",

        "persistence":
            "RegSetValueEx HKLM Run CreateService SERVICE_AUTO_START "
            "schtasks AddToStartup InstallService StartService bootkit",

        "evasion":
            "Sleep NtDelayExecution VirtualProtect PAGE_EXECUTE_READWRITE "
            "xor_decode memset pe_header junk_nop packed_stub reflective_load",

        "string_decrypt":
            "xor_decrypt decode_loop rolling_key encrypted_string "
            "stack_string deobfuscate cleartext_buffer decrypt_stub",

        "c2_communication":
            "c2_beacon send_beacon http_post gate_php hardcoded_ip "
            "base64_encode heartbeat_interval parse_command execute_cmd",

        "privilege_escalation":
            "AdjustTokenPrivileges SeDebugPrivilege LookupPrivilegeValue "
            "ImpersonateLoggedOnUser UAC_bypass token_elevation SYSTEM",

        "memory_manipulation":
            "VirtualAlloc VirtualProtect mprotect PAGE_EXECUTE_READWRITE "
            "shellcode_exec memcpy mmap rwx_allocation heap_spray",
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
        threshold: float = 0.35,
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
            if sim >= threshold:
                results.append({"behavior": behavior, "confidence": round(sim, 4)})

        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results[:top_k]

    def classify(
        self,
        text: str,
        threshold: float = 0.35,
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
        return self.classify_vec(q, threshold=threshold, top_k=top_k, block=block)

    def _classify_impl(
        self,
        q: List[float],
        threshold: float = 0.35,
        top_k: int = 4,
        block: bool = True,
    ) -> List[Dict[str, Any]]:
        """Internal compatibility wrapper for older call sites."""
        return self.classify_vec(q, threshold=threshold, top_k=top_k, block=block)


# ─────────────────────────────────────────────────────────────────────────────
# ContextAssembler — the brain
# ─────────────────────────────────────────────────────────────────────────────

# Rule-based next actions for detected behaviors

# ─────────────────────────────────────────────────────────────────────────────
# Deterministic API pattern analysis
# ─────────────────────────────────────────────────────────────────────────────

_INTERESTING_APIS: Dict[str, frozenset] = {
    "process_injection": frozenset({
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThread", "RtlCreateUserThread", "NtWriteVirtualMemory",
    }),
    "memory_exec": frozenset({
        "VirtualAlloc", "VirtualProtect", "mmap", "mprotect",
    }),
    "network": frozenset({
        "socket", "connect", "send", "recv", "bind", "listen", "accept",
        "WSASocket", "WSAConnect", "WSASend", "WSARecv",
        "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "WinHttpReadData",
        "URLDownloadToFile",
    }),
    "crypto_winapi": frozenset({
        "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptDeriveKey",
        "CryptGenKey", "CryptImportKey", "CryptAcquireContext",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptCreateHash",
    }),
    "persistence": frozenset({
        "RegSetValue", "RegSetValueEx", "RegCreateKey", "RegOpenKey",
        "CreateService", "OpenService", "StartService", "ChangeServiceConfig",
    }),
    "anti_debug": frozenset({
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugString",
        "NtSetInformationThread",
    }),
    "privilege": frozenset({
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
        "ImpersonateLoggedOnUser", "DuplicateTokenEx",
    }),
    "process_spawn": frozenset({
        "CreateProcess", "CreateProcessW", "CreateProcessA",
        "ShellExecute", "ShellExecuteEx", "WinExec",
        "NtCreateProcess",
    }),
    "file_ops": frozenset({
        "CreateFile", "CreateFileW", "ReadFile", "WriteFile", "DeleteFile",
        "MoveFile", "CopyFile", "FindFirstFile",
    }),
}

_ALL_INTERESTING: frozenset = frozenset().union(*_INTERESTING_APIS.values())

_API_COMBOS: List[Tuple[frozenset, List[Dict[str, Any]]]] = [
    (frozenset({"VirtualAllocEx", "WriteProcessMemory"}), [
        {"tool": "annotation", "action": "mark_dangerous",
         "reason": "VirtualAllocEx + WriteProcessMemory = classic process injection"},
        {"tool": "xref_analysis", "action": "call_chain",
         "reason": "Trace injection chain to find where shellcode originates"},
        {"tool": "code", "action": "callers",
         "reason": "Find what triggers this injection"},
    ]),
    (frozenset({"CreateRemoteThread"}), [
        {"tool": "annotation", "action": "mark_dangerous",
         "reason": "CreateRemoteThread — remote code execution"},
        {"tool": "code", "action": "callers",
         "reason": "Trace where the target process handle comes from"},
    ]),
    (frozenset({"CryptEncrypt"}) | frozenset({"BCryptEncrypt"}) | frozenset({"CryptHashData"}), [
        {"tool": "crypto_id", "action": "identify",
         "reason": "Windows CNG/CryptoAPI in use — identify algorithm"},
    ]),
    (frozenset({"WSASocket"}) | frozenset({"InternetOpen"}) | frozenset({"WinHttpOpen"}), [
        {"tool": "string_ops", "action": "find_urls",
         "reason": "Network API — extract hardcoded URLs"},
        {"tool": "string_ops", "action": "find_ips",
         "reason": "Extract hardcoded IP addresses"},
    ]),
    (frozenset({"socket", "connect"}), [
        {"tool": "string_ops", "action": "find_ips",
         "reason": "Raw socket — find target IPs"},
    ]),
    (frozenset({"RegSetValueEx"}) | frozenset({"CreateService"}), [
        {"tool": "search", "action": "api", "pattern": "*Reg*",
         "reason": "Registry/service persistence — find related writes across binary"},
    ]),
    (frozenset({"IsDebuggerPresent"}) | frozenset({"CheckRemoteDebuggerPresent"})
     | frozenset({"NtQueryInformationProcess"}), [
        {"tool": "annotation", "action": "mark_dangerous",
         "reason": "Anti-debugging — patch or note for analysis bypass"},
    ]),
    (frozenset({"AdjustTokenPrivileges"}), [
        {"tool": "annotation", "action": "mark_dangerous",
         "reason": "Token privilege manipulation — privilege escalation"},
        {"tool": "xref_analysis", "action": "call_chain",
         "reason": "Trace escalation path"},
    ]),
    (frozenset({"CreateProcess", "CreateProcessW"}) | frozenset({"ShellExecuteEx"}), [
        {"tool": "string_ops", "action": "find_commands",
         "reason": "Process spawning — extract command-line arguments"},
        {"tool": "code", "action": "callers",
         "reason": "Find what triggers process creation"},
    ]),
]

_STRING_LIT_RE = re.compile(r'"([^"]{4,120})"')
_HEX_CONST_RE  = re.compile(r'\b(0x[0-9A-Fa-f]{6,})\b')
_CRYPTO_CONSTS = frozenset({
    "0x67452301", "0xefcdab89", "0x98badcfe",
    "0x6a09e667", "0xbb67ae85", "0x3c6ef372",
    "0x428a2f98", "0x71374491",
    "0xd76aa478", "0xe8c7b756",
})


def _extract_api_calls(pseudocode: str) -> List[str]:
    found: List[str] = []
    seen: set = set()
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\b", pseudocode):
        name = m.group(1)
        if name in _ALL_INTERESTING and name not in seen:
            seen.add(name)
            found.append(name)
    return found[:30]


def _extract_string_refs(pseudocode: str) -> List[str]:
    raw = _STRING_LIT_RE.findall(pseudocode)
    interesting = [
        s for s in raw
        if any(kw in s.lower() for kw in (
            "http", "https", "ftp", "\\\\", "cmd", "powershell",
            ".exe", ".dll", ".bat", ".ps1", "hkey", "software\\",
            "run", "service", "password", "admin", "token",
        )) or re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}", s)
    ]
    return (interesting or raw)[:8]


def _detect_crypto_constants(pseudocode: str) -> List[str]:
    hits = [h.lower() for h in _HEX_CONST_RE.findall(pseudocode)
            if h.lower() in _CRYPTO_CONSTS]
    return list(set(hits))[:5]


def _actions_from_apis(apis: List[str], addr: str) -> List[Dict[str, Any]]:
    api_set = frozenset(apis)
    actions: List[Dict[str, Any]] = []
    seen: set = set()
    for required, combo_actions in _API_COMBOS:
        if required & api_set:
            for act in combo_actions:
                key = f"{act['tool']}:{act['action']}"
                if key not in seen:
                    seen.add(key)
                    a = dict(act)
                    if addr and act.get("tool") in (
                        "annotation", "xref_analysis", "crypto_id",
                        "code", "string_ops",
                    ):
                        a.setdefault("addr", addr)
                    actions.append(a)
    return actions[:6]


def _actions_from_schemaboot(attrs: Dict[str, Any], addr: str) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    xor        = attrs.get("xor_count", 0)
    entropy    = attrs.get("entropy", 0.0)
    cyclomatic = attrs.get("cyclomatic_complexity", 0)
    xrefs_in   = attrs.get("incoming_xrefs", 0)

    if xor > 5:
        actions.append({
            "tool": "crypto_id", "action": "identify", "addr": addr,
            "reason": f"{xor} XOR instructions — possible custom encryption or obfuscation",
        })
    if entropy > 6.0:
        actions.append({
            "tool": "entropy", "action": "region", "addr": addr,
            "reason": f"Entropy {entropy:.1f} — may process packed or encrypted data",
        })
    if cyclomatic > 15:
        actions.append({
            "tool": "code", "action": "blocks", "addr": addr,
            "reason": f"Cyclomatic complexity {cyclomatic} — possible state machine or protocol parser",
        })
    if xrefs_in == 0:
        actions.append({
            "tool": "search", "action": "data_ref", "addr": addr,
            "reason": "No direct callers — may be invoked via function pointer or vtable",
        })
    elif xrefs_in > 20:
        actions.append({
            "tool": "code", "action": "callers", "addr": addr,
            "reason": f"{xrefs_in} callers — widely used utility, renaming will improve the whole analysis",
        })
    return actions[:4]


class ContextAssembler:
    """
    Per-call context assembly.  Replaces cognitive_layer, cartographer_mu,
    and attention_kernel with a clean, honest pipeline:

      1. Blackboard: addr-matched past findings
      2. Embedding similarity: similar functions in this binary
      3. Zero-shot behavior classification: what does this function do?
      4. Rule-based next actions: what should the LLM do next?
      5. Stuck detection: has the LLM been spinning here?

    Produces a compact `context_pack` injected into every relevant response.
    """

    def __init__(self):
        self._embedder   = BgeCodeEmbedder()
        # Shared singleton classifier — anchors loaded once across all instances
        self._classifier = BehaviorClassifier.instance(self._embedder)
        # Per-binary embedding indexes keyed by idb_path
        self._indexes: Dict[str, FunctionEmbeddingIndex] = {}
        self._idx_lock   = threading.Lock()
        # Activity tracking for stuck detection (in-memory, per session)
        self._activity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._activity_lock = threading.Lock()
        self._related_addr_graph: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
        self._related_addr_lock = threading.Lock()
        self._retrieval_metrics: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._retrieval_metrics_lock = threading.Lock()
        self._session_semantic_threshold: Dict[str, float] = {}
        self._semantic_threshold_lock = threading.Lock()
        self._focus_feedback: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._focus_feedback_lock = threading.Lock()
        self._pending_focus: Dict[str, Dict[str, Any]] = {}
        self._pending_focus_lock = threading.Lock()
        self._session_call_outcomes: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._session_call_outcomes_lock = threading.Lock()
        self._session_store_binding: Dict[str, str] = {}
        self._store_binding_lock = threading.Lock()
        # Cache blackboard entry embeddings by stable key to avoid repeated
        # re-embedding the same rows on every decompile call.
        self._bb_entry_vec_cache: Dict[str, Tuple[List[float], float]] = {}
        self._bb_entry_vec_cache_lock = threading.Lock()
        self._bb_entry_cache_ttl_sec = 900.0
        self._bb_entry_cache_max = 4000
        self._bb_cache_hits = 0
        self._bb_cache_misses = 0
        self._bb_cache_stats_lock = threading.Lock()
        self._last_housekeeping_ts = 0.0
        self._housekeeping_lock = threading.Lock()
        self._pending_focus_ttl_sec = 420.0
        self._related_graph_max_edges = 1200
        self._semantic_circuit_breaker_until: Dict[str, int] = {}
        self._circuit_breaker_lock = threading.Lock()
        self._session_stats_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._stats_cache_lock = threading.Lock()
        self._stats_cache_ttl_sec = 1.5
        self._source_policy_cache: Dict[str, Tuple[Tuple[int, int, int, int], Dict[str, Dict[str, Any]]]] = {}
        self._policy_cache_lock = threading.Lock()
        self._perf_buckets: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._perf_lock = threading.Lock()
        self._policy_save_due_at: Dict[str, float] = {}
        self._policy_save_inflight: set = set()
        self._policy_save_lock = threading.Lock()
        self._policy_save_debounce_sec = 0.35
        self._semantic_result_cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
        self._semantic_result_cache_lock = threading.Lock()
        self._semantic_result_cache_ttl_sec = 3.0
        self._semantic_budget_cache: Dict[str, Tuple[float, int]] = {}
        self._semantic_budget_lock = threading.Lock()

    def _behavior_classifier(self) -> BehaviorClassifier:
        """Return the shared classifier, re-binding it if the embedder changed.

        Test doubles can inject a classifier without an `_embedder` attribute;
        those are left untouched so unit tests can isolate the enrichment path.
        """
        classifier = getattr(self, "_classifier", None)
        if classifier is None:
            classifier = BehaviorClassifier.instance(self._embedder)
            self._classifier = classifier
            return classifier
        classifier_embedder = getattr(classifier, "_embedder", None)
        if classifier_embedder is not None and classifier_embedder is not self._embedder:
            classifier = BehaviorClassifier.instance(self._embedder)
            self._classifier = classifier
        return classifier

    def _get_index(self, idb_path: str) -> FunctionEmbeddingIndex:
        with self._idx_lock:
            if idb_path not in self._indexes:
                db = idb_path + ".embeddings.db"
                self._indexes[idb_path] = FunctionEmbeddingIndex(db, self._embedder)
        return self._indexes[idb_path]

    # ── blackboard retrieval ──────────────────────────────────────────────

    def _get_bb_entries(self, addr: str, bb_store) -> List[Dict[str, Any]]:
        """Fetch blackboard entries relevant to this address."""
        if bb_store is None or not addr:
            return []
        try:
            entries = bb_store.list(addr=addr, limit=5)
            return entries or []
        except Exception:
            return []

    def _merge_related_findings(
        self,
        pack: Dict[str, Any],
        entries: List[Dict[str, Any]],
        source: str,
        session_id: str = "",
    ) -> None:
        """
        Merge findings into pack['related_findings'] with deterministic ranking.

        Ranking priority:
          1) evidence source: address_linked > relation_linked > api_linked > semantic_linked
          2) confidence
          3) updated_at recency
        """
        if not entries:
            return
        policy = self._session_source_policy(session_id) if session_id else {}
        p_src = policy.get(source, {}) if isinstance(policy, dict) else {}
        min_conf = float(p_src.get("min_confidence", 0.0) or 0.0)
        max_take = int(p_src.get("max_take", 8) or 8)
        weight = float(p_src.get("weight", 1.0) or 1.0)
        filtered_entries = [
            e for e in entries
            if float(e.get("confidence") or 0.0) >= min_conf
        ]
        if max_take > 0:
            filtered_entries = sorted(
                filtered_entries,
                key=lambda e: (
                    float(e.get("confidence") or 0.0),
                    float(e.get("updated_at") or 0.0),
                ),
                reverse=True,
            )[:max_take]
        if not filtered_entries:
            return
        src_rank = {
            "address_linked": 4,
            "relation_linked": 3,
            "api_linked": 2,
            "semantic_linked": 1,
        }
        merged: Dict[str, Dict[str, Any]] = {}
        for existing in pack.get("related_findings", []):
            e = dict(existing)
            e.setdefault("retrieval_source", "address_linked")
            merged[str(e.get("id") or hashlib.md5(json.dumps(e, sort_keys=True).encode()).hexdigest())] = e
        for entry in filtered_entries:
            e = dict(entry)
            e["retrieval_source"] = source
            e["retrieval_weight"] = round(weight, 3)
            key = str(e.get("id") or hashlib.md5(json.dumps(e, sort_keys=True).encode()).hexdigest())
            prev = merged.get(key)
            if prev is None:
                merged[key] = e
                continue
            prev_rank = src_rank.get(str(prev.get("retrieval_source") or "semantic_linked"), 0)
            new_rank = src_rank.get(source, 0)
            if new_rank > prev_rank:
                merged[key] = e
                continue
            if new_rank == prev_rank:
                if float(e.get("confidence") or 0.0) > float(prev.get("confidence") or 0.0):
                    merged[key] = e

        ranked = sorted(
            merged.values(),
            key=lambda x: (
                src_rank.get(str(x.get("retrieval_source") or "semantic_linked"), 0),
                float(x.get("retrieval_weight") or 1.0),
                float(x.get("confidence") or 0.0),
                float(x.get("updated_at") or 0.0),
            ),
            reverse=True,
        )
        pack["related_findings"] = ranked[:8]
        if session_id:
            try:
                with self._retrieval_metrics_lock:
                    metrics = self._retrieval_metrics[session_id]
                    key_total = f"{source}.total"
                    key_accepted = f"{source}.accepted"
                    key_kept = f"{source}.kept"
                    metrics[key_total] = int(metrics.get(key_total, 0)) + len(entries)
                    metrics[key_accepted] = int(metrics.get(key_accepted, 0)) + len(filtered_entries)
                    kept = sum(1 for e in filtered_entries if any(
                        (r.get("id") and r.get("id") == e.get("id"))
                        for r in pack.get("related_findings", [])
                    ))
                    metrics[key_kept] = int(metrics.get(key_kept, 0)) + kept
                self._invalidate_session_caches(session_id)
                self._schedule_policy_save(session_id)
            except Exception:
                pass

    def _invalidate_session_caches(self, session_id: str) -> None:
        if not session_id:
            return
        with self._stats_cache_lock:
            self._session_stats_cache.pop(session_id, None)
        with self._policy_cache_lock:
            self._source_policy_cache.pop(session_id, None)
        with self._semantic_result_cache_lock:
            if session_id:
                stale = [k for k in self._semantic_result_cache.keys() if k.startswith(f"{session_id}:")]
                for k in stale[:128]:
                    self._semantic_result_cache.pop(k, None)

    def _perf_start(self) -> float:
        return time.perf_counter()

    def _perf_end(self, session_id: str, bucket: str, t0: float) -> None:
        if not INTEL_PROFILE or not session_id:
            return
        dt_ms = (time.perf_counter() - t0) * 1000.0
        with self._perf_lock:
            b = self._perf_buckets[session_id]
            b[f"{bucket}.count"] = float(b.get(f"{bucket}.count", 0.0) + 1.0)
            b[f"{bucket}.sum_ms"] = float(b.get(f"{bucket}.sum_ms", 0.0) + dt_ms)
            b[f"{bucket}.max_ms"] = max(float(b.get(f"{bucket}.max_ms", 0.0)), dt_ms)

    def _session_retrieval_stats(self, session_id: str) -> Dict[str, Any]:
        if not session_id:
            return {}
        try:
            now = time.time()
            with self._stats_cache_lock:
                cached = self._session_stats_cache.get(session_id)
                if cached and (now - cached[0] <= self._stats_cache_ttl_sec):
                    return dict(cached[1])
            with self._retrieval_metrics_lock:
                metrics = dict(self._retrieval_metrics.get(session_id, {}))
            if not metrics:
                return {}
            out: Dict[str, Any] = {}
            sources = ["address_linked", "relation_linked", "api_linked", "semantic_linked"]
            for src in sources:
                total = int(metrics.get(f"{src}.total", 0))
                accepted = int(metrics.get(f"{src}.accepted", 0))
                kept = int(metrics.get(f"{src}.kept", 0))
                if total <= 0:
                    continue
                out[src] = {
                    "total": total,
                    "accepted": accepted,
                    "kept": kept,
                    "accept_rate": round(accepted / max(1, total), 3),
                    "hit_rate": round(kept / max(1, total), 3),
                }
            out["semantic_threshold"] = self._get_semantic_threshold(session_id)
            out["source_policy"] = self._session_source_policy(session_id)
            out["focus_feedback"] = self._focus_feedback_stats(session_id)
            with self._stats_cache_lock:
                self._session_stats_cache[session_id] = (now, dict(out))
            return out
        except Exception:
            return {}

    def _focus_feedback_stats(self, session_id: str) -> Dict[str, Any]:
        if not session_id:
            return {}
        try:
            with self._focus_feedback_lock:
                m = dict(self._focus_feedback.get(session_id, {}))
            suggested = int(m.get("suggested", 0))
            followed = int(m.get("followed", 0))
            successful = int(m.get("successful", 0))
            failed = int(m.get("failed", 0))
            out: Dict[str, Any] = {
                "suggested": suggested,
                "followed": followed,
                "successful": successful,
                "failed": failed,
                "follow_rate": round(followed / max(1, suggested), 3),
                "success_rate": round(successful / max(1, followed), 3),
            }
            action_stats: Dict[str, Dict[str, float]] = {}
            for k, v in m.items():
                if not k.startswith("action."):
                    continue
                # action.<tool:action>.<ok|fail>
                parts = k.split(".")
                if len(parts) != 3:
                    continue
                ta = parts[1]
                bucket = action_stats.setdefault(ta, {"ok": 0.0, "fail": 0.0})
                bucket[parts[2]] = float(v)
            if action_stats:
                per_action = {}
                for ta, vals in action_stats.items():
                    ok = vals.get("ok", 0.0)
                    fail = vals.get("fail", 0.0)
                    total = ok + fail
                    if total <= 0:
                        continue
                    per_action[ta] = {
                        "success_rate": round(ok / total, 3),
                        "samples": int(total),
                    }
                if per_action:
                    out["per_action"] = per_action
            return out
        except Exception:
            return {}

    def _run_housekeeping(self, session_id: str) -> None:
        """Periodic cleanup for pending focus and relation graph bounds."""
        now = time.time()
        if now - self._last_housekeeping_ts < 30.0:
            return
        if not self._housekeeping_lock.acquire(blocking=False):
            return
        try:
            self._last_housekeeping_ts = now
            # Expire stale pending focus suggestions.
            with self._pending_focus_lock:
                stale = [
                    sid for sid, rec in self._pending_focus.items()
                    if now - float(rec.get("ts") or 0.0) > self._pending_focus_ttl_sec
                ]
                for sid in stale:
                    self._pending_focus.pop(sid, None)

            # Bound relation graph size per session.
            if session_id:
                with self._related_addr_lock:
                    graph = self._related_addr_graph.get(session_id)
                    if graph:
                        total_edges = sum(len(v) for v in graph.values())
                        if total_edges > self._related_graph_max_edges:
                            # Drop smallest-degree nodes first.
                            nodes = sorted(graph.items(), key=lambda kv: len(kv[1]))
                            drop_budget = total_edges - self._related_graph_max_edges
                            for node, nbrs in nodes:
                                if drop_budget <= 0:
                                    break
                                drop_budget -= len(nbrs)
                                graph.pop(node, None)
        except Exception:
            pass
        finally:
            self._housekeeping_lock.release()

    def _collect_intelligence_health(self, session_id: str) -> Dict[str, Any]:
        """Compact health telemetry for adaptive intelligence quality."""
        out: Dict[str, Any] = {}
        try:
            with self._bb_cache_stats_lock:
                hits = int(self._bb_cache_hits)
                misses = int(self._bb_cache_misses)
            total = hits + misses
            out["bb_cache"] = {
                "entries": len(self._bb_entry_vec_cache),
                "hit_rate": round(hits / max(1, total), 3),
                "ops": total,
            }
            with self._pending_focus_lock:
                pending = self._pending_focus.get(session_id, {}) if session_id else {}
            if pending:
                age = time.time() - float(pending.get("ts") or time.time())
                out["pending_focus"] = {
                    "tool": pending.get("tool"),
                    "action": pending.get("action"),
                    "age_sec": round(age, 2),
                }
            with self._related_addr_lock:
                rel_nodes = len(self._related_addr_graph.get(session_id, {})) if session_id else 0
            out["relation_graph"] = {"nodes": rel_nodes}
            out["semantic_cache"] = {"entries": len(self._semantic_result_cache)}
            with self._policy_save_lock:
                out["policy_save_queue"] = len(self._policy_save_due_at)
            if session_id:
                out["semantic_threshold"] = self._get_semantic_threshold(session_id)
                out["semantic_circuit_open"] = self._semantic_circuit_open(session_id)
                out["semantic_budget"] = self._adaptive_semantic_budget(session_id, default_max=24)
                if INTEL_PROFILE:
                    with self._perf_lock:
                        b = dict(self._perf_buckets.get(session_id, {}))
                    perf = {}
                    for k in ("assemble", "decompile_enrich", "search_enrich"):
                        c = float(b.get(f"{k}.count", 0.0))
                        s = float(b.get(f"{k}.sum_ms", 0.0))
                        m = float(b.get(f"{k}.max_ms", 0.0))
                        if c > 0:
                            perf[k] = {"avg_ms": round(s / c, 3), "max_ms": round(m, 3), "count": int(c)}
                    if perf:
                        out["perf"] = perf
        except Exception:
            return {}
        return out

    def _policy_store_path(self, idb_path: str) -> str:
        if idb_path:
            return idb_path + ".focus_policy.json"
        return os.path.join(os.path.expanduser("~"), ".ida-pro-mcp", "focus_policy.json")

    def _compact_policy_blob(self, sess_blob: Dict[str, Any]) -> Dict[str, Any]:
        return compact_policy_blob(sess_blob)

    def _prune_policy_store(self, data: Dict[str, Any], max_sessions: int = 24) -> Dict[str, Any]:
        return prune_policy_store(data, max_sessions=max_sessions)

    def _bind_session_store(self, session_id: str, idb_path: str) -> None:
        if not session_id or not idb_path:
            return
        with self._store_binding_lock:
            self._session_store_binding[session_id] = self._policy_store_path(idb_path)

    def _load_session_policy(self, session_id: str, idb_path: str) -> None:
        if not session_id:
            return
        self._bind_session_store(session_id, idb_path)
        try:
            path = self._policy_store_path(idb_path)
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and int(data.get("schema_version") or 1) < 2:
                data = self._prune_policy_store(data)
            sess = data.get("sessions", {}).get(session_id)
            if not isinstance(sess, dict):
                return
            with self._retrieval_metrics_lock:
                if session_id not in self._retrieval_metrics or not self._retrieval_metrics[session_id]:
                    self._retrieval_metrics[session_id] = dict(sess.get("retrieval_metrics") or {})
            with self._focus_feedback_lock:
                if session_id not in self._focus_feedback or not self._focus_feedback[session_id]:
                    self._focus_feedback[session_id] = dict(sess.get("focus_feedback") or {})
            with self._semantic_threshold_lock:
                if session_id not in self._session_semantic_threshold:
                    thr = float(sess.get("semantic_threshold") or 0.5)
                    self._session_semantic_threshold[session_id] = max(0.35, min(0.75, thr))
            self._invalidate_session_caches(session_id)
        except Exception:
            return

    def _save_session_policy(self, session_id: str) -> None:
        if not session_id:
            return
        try:
            with self._store_binding_lock:
                path = self._session_store_binding.get(session_id)
            if not path:
                return
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data: Dict[str, Any] = {"sessions": {}}
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if not isinstance(data, dict):
                        data = {"sessions": {}}
                except Exception:
                    data = {"sessions": {}}
            sessions = data.setdefault("sessions", {})
            with self._retrieval_metrics_lock:
                rm = dict(self._retrieval_metrics.get(session_id, {}))
            with self._focus_feedback_lock:
                ff = dict(self._focus_feedback.get(session_id, {}))
            with self._semantic_threshold_lock:
                thr = float(self._session_semantic_threshold.get(session_id, 0.5))
            sessions[session_id] = {
                "retrieval_metrics": rm,
                "focus_feedback": ff,
                "semantic_threshold": thr,
                "saved_at": time.time(),
            }
            data = self._prune_policy_store(data)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, sort_keys=True)
            self._invalidate_session_caches(session_id)
        except Exception:
            return

    def _schedule_policy_save(self, session_id: str, force: bool = False) -> None:
        """Debounce policy saves to reduce disk churn in bursty sessions."""
        if not session_id:
            return
        now = time.time()
        with self._policy_save_lock:
            due = now if force else (now + self._policy_save_debounce_sec)
            prev = self._policy_save_due_at.get(session_id)
            if prev is None or due < prev:
                self._policy_save_due_at[session_id] = due
            if session_id in self._policy_save_inflight:
                return
            self._policy_save_inflight.add(session_id)

        def _worker(sid: str) -> None:
            try:
                while True:
                    with self._policy_save_lock:
                        due_at = self._policy_save_due_at.get(sid)
                    if due_at is None:
                        break
                    wait = due_at - time.time()
                    if wait > 0:
                        time.sleep(min(wait, 0.1))
                        continue
                    self._save_session_policy(sid)
                    with self._policy_save_lock:
                        # If no newer deadline was scheduled while saving, clear and exit.
                        latest = self._policy_save_due_at.get(sid)
                        if latest is None or latest <= due_at:
                            self._policy_save_due_at.pop(sid, None)
                            break
            finally:
                with self._policy_save_lock:
                    self._policy_save_inflight.discard(sid)

        threading.Thread(target=_worker, args=(session_id,), daemon=True).start()

    def flush_policy_saves(self, session_id: str = "") -> None:
        """Force-flush pending debounced policy saves (best-effort)."""
        targets: List[str]
        with self._policy_save_lock:
            if session_id:
                targets = [session_id]
            else:
                targets = list(self._policy_save_due_at.keys())
            for sid in targets:
                self._policy_save_due_at[sid] = time.time()
        for sid in targets:
            self._schedule_policy_save(sid, force=True)

    def _record_focus_suggestion(self, session_id: str, focus: Dict[str, Any]) -> None:
        if not session_id or not focus:
            return
        try:
            with self._focus_feedback_lock:
                m = self._focus_feedback[session_id]
                m["suggested"] = int(m.get("suggested", 0)) + 1
            self._invalidate_session_caches(session_id)
            with self._pending_focus_lock:
                self._pending_focus[session_id] = {
                    "tool": focus.get("tool"),
                    "action": focus.get("action"),
                    "ts": time.time(),
                }
            self._schedule_policy_save(session_id)
        except Exception:
            return

    def _consume_focus_follow(self, session_id: str, tool: str, action: str) -> bool:
        if not session_id:
            return False
        try:
            with self._pending_focus_lock:
                pending = self._pending_focus.pop(session_id, None)
            if not pending:
                return False
            followed = (pending.get("tool") == tool and pending.get("action") == action)
            if followed:
                with self._focus_feedback_lock:
                    m = self._focus_feedback[session_id]
                    m["followed"] = int(m.get("followed", 0)) + 1
                self._invalidate_session_caches(session_id)
            return followed
        except Exception:
            return False

    def _record_focus_outcome(self, session_id: str, tool: str, action: str, success: bool) -> None:
        if not session_id:
            return
        try:
            ta = f"{tool}:{action}"
            with self._focus_feedback_lock:
                m = self._focus_feedback[session_id]
                if success:
                    m["successful"] = int(m.get("successful", 0)) + 1
                    m[f"action.{ta}.ok"] = int(m.get(f"action.{ta}.ok", 0)) + 1
                else:
                    m["failed"] = int(m.get("failed", 0)) + 1
                    m[f"action.{ta}.fail"] = int(m.get(f"action.{ta}.fail", 0)) + 1
            self._invalidate_session_caches(session_id)
            self._schedule_policy_save(session_id)
        except Exception:
            return

    def _focus_action_bias(self, session_id: str, tool: str, action: str) -> float:
        if not session_id:
            return 1.0
        try:
            ta = f"{tool}:{action}"
            with self._focus_feedback_lock:
                m = dict(self._focus_feedback.get(session_id, {}))
            ok = int(m.get(f"action.{ta}.ok", 0))
            fail = int(m.get(f"action.{ta}.fail", 0))
            total = ok + fail
            if total < 3:
                return 1.0
            rate = ok / max(1, total)
            # Map 0..1 success rate to 0.8..1.25 bias
            return round(0.8 + rate * 0.45, 3)
        except Exception:
            return 1.0

    def _session_source_policy(self, session_id: str) -> Dict[str, Dict[str, Any]]:
        """Adaptive source policy tuned from per-session retrieval outcomes."""
        base = {
            "address_linked": {"weight": 1.4, "min_confidence": 0.0, "max_take": 8},
            "relation_linked": {"weight": 1.2, "min_confidence": 0.25, "max_take": 6},
            "api_linked": {"weight": 1.0, "min_confidence": 0.35, "max_take": 5},
            "semantic_linked": {"weight": 0.9, "min_confidence": 0.45, "max_take": 4},
        }
        if not session_id:
            return base
        try:
            with self._retrieval_metrics_lock:
                metrics = dict(self._retrieval_metrics.get(session_id, {}))
            fp = (
                int(metrics.get("address_linked.total", 0)),
                int(metrics.get("relation_linked.total", 0)),
                int(metrics.get("api_linked.total", 0)),
                int(metrics.get("semantic_linked.total", 0)),
            )
            with self._policy_cache_lock:
                cached = self._source_policy_cache.get(session_id)
                if cached and cached[0] == fp:
                    return dict(cached[1])
            for src, cfg in base.items():
                total = int(metrics.get(f"{src}.total", 0))
                kept = int(metrics.get(f"{src}.kept", 0))
                if total < 6:
                    continue
                hit_rate = kept / max(1, total)
                if hit_rate < 0.25:
                    cfg["weight"] = round(max(0.5, float(cfg["weight"]) - 0.2), 3)
                    cfg["min_confidence"] = round(min(0.9, float(cfg["min_confidence"]) + 0.08), 3)
                    cfg["max_take"] = max(2, int(cfg["max_take"]) - 1)
                elif hit_rate > 0.7:
                    cfg["weight"] = round(min(1.8, float(cfg["weight"]) + 0.15), 3)
                    cfg["min_confidence"] = round(max(0.0, float(cfg["min_confidence"]) - 0.05), 3)
                    cfg["max_take"] = min(8, int(cfg["max_take"]) + 1)
            with self._policy_cache_lock:
                self._source_policy_cache[session_id] = (fp, dict(base))
            return base
        except Exception:
            return base

    def _derive_analysis_focus(
        self,
        pack: Dict[str, Any],
        addr: str,
        session_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Derive a single best next focus action for the current step using:
        - adaptive source policy
        - observed retrieval richness
        - structural risk signals
        """
        if not addr:
            return None
        try:
            cands = self._derive_focus_candidates(pack, addr, session_id)
            if cands:
                return cands[0]
            return None
        except Exception:
            return None

    def _build_llm_action_card(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        """
        Compact, execution-ready card intended for direct LLM consumption.
        Keeps one primary call + two fallbacks with concrete args.
        """
        focus = pack.get("analysis_focus") or {}
        alts = list(pack.get("analysis_focus_alternatives") or [])
        primary = None
        if focus.get("tool") and focus.get("action"):
            primary = {
                "call": {
                    "tool": focus.get("tool"),
                    "action": focus.get("action"),
                    "addr": focus.get("addr") or addr,
                    "pattern": focus.get("pattern"),
                },
                "why": focus.get("reason") or "best next step",
            }
        fallbacks = []
        for a in alts[:2]:
            if not (a.get("tool") and a.get("action")):
                continue
            fallbacks.append(
                {
                    "call": {
                        "tool": a.get("tool"),
                        "action": a.get("action"),
                        "addr": a.get("addr") or addr,
                        "pattern": a.get("pattern"),
                    },
                    "why": a.get("reason") or "fallback",
                }
            )
        return {
            "primary": primary,
            "fallbacks": fallbacks,
            "stop_condition": "stop when new related_findings or hit_details appear",
        }

    def _build_llm_uncertainty(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        """Expose explicit uncertainty so LLM can avoid over-claiming."""
        risk = "low"
        checks: List[str] = []
        rf = pack.get("related_findings") or []
        if len(rf) == 0:
            checks.append("no_related_findings")
        sem_thr = float(((pack.get("retrieval_stats") or {}).get("semantic_threshold") or 0.5))
        sem_open = bool(((pack.get("intelligence_health") or {}).get("semantic_circuit_open")))
        if sem_open:
            checks.append("semantic_circuit_open")
        if sem_thr >= 0.65:
            checks.append("strict_semantic_threshold")
        if checks:
            risk = "medium"
        if "semantic_circuit_open" in checks and len(rf) == 0:
            risk = "high"
        return {
            "risk": risk,
            "checks": checks,
            "instruction": "state uncertainty and run primary action before concluding behavior",
        }

    def _build_llm_evidence_snippets(self, pack: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Small provenance-tied facts for LLM responses."""
        out: List[Dict[str, Any]] = []
        for api in (pack.get("api_calls") or [])[:5]:
            out.append({"fact": f"API observed: {api}", "source": "decompile/api_extract"})
        st = pack.get("structural") or {}
        if st.get("entropy") is not None:
            out.append({"fact": f"Entropy: {st.get('entropy')}", "source": "schemaboot"})
        if st.get("xor_count"):
            out.append({"fact": f"XOR count: {st.get('xor_count')}", "source": "schemaboot"})
        for f in (pack.get("related_findings") or [])[:3]:
            ttl = str(f.get("title") or "finding")
            out.append({"fact": ttl, "source": f"blackboard/{f.get('retrieval_source') or 'unknown'}"})
        return out[:8]

    def _build_llm_tool_call_contract(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        """Strict call contract the LLM can emit with low ambiguity."""
        focus = pack.get("analysis_focus") or {}
        primary = {
            "tool": focus.get("tool") or "code",
            "action": focus.get("action") or "callers",
            "addr": focus.get("addr") or addr,
        }
        if focus.get("pattern"):
            primary["pattern"] = focus.get("pattern")
        return {
            "format": "json",
            "required_fields": ["tool", "action"],
            "optional_fields": ["addr", "pattern", "limit"],
            "primary": primary,
            "example": {"tool": primary["tool"], "action": primary["action"], "addr": primary.get("addr")},
        }

    def _build_llm_failover_route(self, pack: Dict[str, Any], addr: str) -> List[Dict[str, Any]]:
        """Fallback route when primary call yields weak/empty signal."""
        alts = list(pack.get("analysis_focus_alternatives") or [])
        route = []
        for a in alts[:2]:
            if not (a.get("tool") and a.get("action")):
                continue
            route.append(
                {
                    "if": "primary_empty_or_low_signal",
                    "call": {
                        "tool": a.get("tool"),
                        "action": a.get("action"),
                        "addr": a.get("addr") or addr,
                        "pattern": a.get("pattern"),
                    },
                    "expect": "new hit_details or related_findings",
                }
            )
        if not route:
            route.append(
                {
                    "if": "primary_empty_or_low_signal",
                    "call": {"tool": "code", "action": "callees", "addr": addr},
                    "expect": "graph expansion",
                }
            )
        return route

    def _build_llm_response_style_guard(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        """Claim-style guardrails to keep LLM outputs evidence-backed."""
        evid_n = len(pack.get("llm_evidence") or [])
        unc = pack.get("llm_uncertainty") or {}
        risk = str(unc.get("risk") or "low")
        mode = "assertive" if evid_n >= 3 and risk == "low" else "cautious"
        return {
            "mode": mode,
            "must_include": [
                "at least one cited evidence fact",
                "explicit next verification call when uncertainty is medium/high",
            ],
            "forbidden": [
                "definitive malware/vuln claims without cited evidence",
                "omitting uncertainty when risk is high",
            ],
        }

    def _compile_question_tool_plan(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        """Deterministic question->tool first-step compiler for RE workflows."""
        apis = set(pack.get("api_calls") or [])
        structural = pack.get("structural") or {}
        if {"VirtualAllocEx", "WriteProcessMemory"}.intersection(apis):
            return {
                "intent": "malware_triage",
                "first_calls": [
                    {"tool": "code", "action": "callers", "addr": addr},
                    {"tool": "xref_analysis", "action": "call_chain", "addr": addr},
                ],
            }
        if float(structural.get("entropy") or 0.0) >= 6.0:
            return {
                "intent": "packed_or_obfuscated",
                "first_calls": [
                    {"tool": "code", "action": "blocks", "addr": addr},
                    {"tool": "search", "action": "semantic", "addr": addr},
                ],
            }
        return {
            "intent": "function_understanding",
            "first_calls": [
                {"tool": "code", "action": "decompile", "addr": addr},
                {"tool": "code", "action": "callers", "addr": addr},
            ],
        }

    def _evidence_budget_gate(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        """Block high-risk claims unless evidence budget is satisfied."""
        evid = list(pack.get("llm_evidence") or [])
        apis = set(pack.get("api_calls") or [])
        claim_type = "general"
        required = 1
        if {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}.intersection(apis):
            claim_type = "malware_behavior"
            required = 2
        if any("overflow" in str(x.get("fact", "")).lower() for x in evid):
            claim_type = "vulnerability"
            required = 3
        met = len(evid) >= required
        out = {
            "claim_type": claim_type,
            "required_evidence": required,
            "observed_evidence": len(evid),
            "claim_blocked": not met,
        }
        if not met:
            out["required_followup_call"] = {"tool": "code", "action": "callers", "addr": addr}
        return out

    def _dead_end_escalation(self, session_id: str, addr: str, pack: Dict[str, Any]) -> Dict[str, Any]:
        with self._activity_lock:
            recent = list(self._activity.get(session_id, []))[-12:]
        if not recent:
            return {"loop_detected": False}
        same_addr = sum(1 for r in recent if r.get("addr") == addr)
        repetitive = sum(1 for r in recent if f"{r.get('tool')}:{r.get('action')}" in ("code:decompile", "search:semantic"))
        no_findings = not bool(pack.get("related_findings") or pack.get("hit_details"))
        loop = same_addr >= 4 and repetitive >= 4 and no_findings
        if not loop:
            return {"loop_detected": False}
        return {
            "loop_detected": True,
            "required_followup_call": {"tool": "xref_analysis", "action": "call_chain", "addr": addr},
            "secondary": {"tool": "firmware_view", "action": "campaign", "start": addr, "end": addr},
        }

    def _mcp_value_score(self, session_id: str, pack: Dict[str, Any]) -> float:
        with self._session_call_outcomes_lock:
            o = self._session_call_outcomes[session_id]
            calls = int(o.get("calls", 0))
            wins = int(o.get("wins", 0))
        base = wins / max(1, calls)
        lift = 0.1 if (pack.get("related_findings") or pack.get("hit_details")) else 0.0
        return round(min(1.0, base + lift), 3)

    def _record_call_outcome(self, session_id: str, pack: Dict[str, Any]) -> None:
        with self._session_call_outcomes_lock:
            o = self._session_call_outcomes[session_id]
            o["calls"] = int(o.get("calls", 0)) + 1
            if pack.get("related_findings") or pack.get("hit_details") or pack.get("analysis_focus"):
                o["wins"] = int(o.get("wins", 0)) + 1

    def _mode_profile(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        apis = set(pack.get("api_calls") or [])
        if {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}.intersection(apis):
            return {"mode": "triage_mode", "mandatory_sequence": ["code.decompile", "code.callers", "xref_analysis.call_chain"]}
        if pack.get("structural") and float((pack.get("structural") or {}).get("entropy") or 0.0) >= 6.0:
            return {"mode": "firmware_mode", "mandatory_sequence": ["firmware_view.region_profile", "firmware_view.pointer_clusters", "firmware_view.carve_plan"]}
        return {"mode": "analysis_mode", "mandatory_sequence": ["code.decompile", "code.callers"]}

    # --- 10 LLM-first feature payloads ---
    def _llm_query_intent(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        apis = set(pack.get("api_calls") or [])
        if {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}.intersection(apis):
            return {"intent": "malware_behavior", "confidence": 0.82}
        if float((pack.get("structural") or {}).get("entropy") or 0.0) >= 6.0:
            return {"intent": "obfuscation_or_packer", "confidence": 0.74}
        return {"intent": "function_understanding", "confidence": 0.62}

    def _llm_required_evidence_sources(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        src = set()
        if pack.get("api_calls"):
            src.add("api_extract")
        if pack.get("structural"):
            src.add("schemaboot")
        if pack.get("related_findings"):
            src.add("blackboard")
        return {"required_min": 2, "observed": sorted(src), "met": len(src) >= 2}

    def _llm_claim_templates(self) -> Dict[str, str]:
        return {
            "safe_claim": "Observed: {facts}. Likely: {inference}. Verify with: {next_call}.",
            "uncertain_claim": "Signals are incomplete ({checks}). Run: {next_call} before concluding.",
        }

    def _llm_call_sequence(self, pack: Dict[str, Any], addr: str) -> List[Dict[str, Any]]:
        seq = []
        prim = ((pack.get("llm_action_card") or {}).get("primary") or {}).get("call") or {}
        if prim.get("tool") and prim.get("action"):
            seq.append({"step": 1, **prim})
        for i, fb in enumerate((pack.get("llm_failover_route") or [])[:2], start=2):
            c = fb.get("call") or {}
            if c.get("tool") and c.get("action"):
                seq.append({"step": i, **c})
        if not seq:
            seq.append({"step": 1, "tool": "code", "action": "callers", "addr": addr})
        return seq

    def _llm_refusal_policy(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        blocked = bool((pack.get("evidence_budget") or {}).get("claim_blocked"))
        return {
            "must_refuse_definitive_claim": blocked,
            "reason": "insufficient_evidence" if blocked else "none",
        }

    def _llm_tool_cooldowns(self, session_id: str) -> Dict[str, Any]:
        with self._activity_lock:
            recent = list(self._activity.get(session_id, []))[-10:]
        counts: Dict[str, int] = {}
        for r in recent:
            k = f"{r.get('tool')}:{r.get('action')}"
            counts[k] = counts.get(k, 0) + 1
        cooled = [k for k, c in counts.items() if c >= 4]
        return {"avoid_repeating": cooled, "window": 10}

    def _llm_context_capsule(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        return {
            "addr": addr,
            "apis": (pack.get("api_calls") or [])[:5],
            "top_findings": [str(x.get("title") or "") for x in (pack.get("related_findings") or [])[:3]],
            "focus": ((pack.get("analysis_focus") or {}).get("action") or "unknown"),
        }

    def _llm_verification_checklist(self, pack: Dict[str, Any], addr: str) -> List[str]:
        checks = [
            f"run code.callers at {addr}",
            f"run xref_analysis.call_chain at {addr}",
        ]
        if not pack.get("related_findings"):
            checks.append("write one blackboard note for newly verified behavior")
        return checks

    def _llm_next_best_question(self, pack: Dict[str, Any]) -> str:
        if not pack.get("related_findings"):
            return "Which caller path reaches this behavior first?"
        if not pack.get("structural"):
            return "What structural signals (entropy/xor/loops) support this hypothesis?"
        return "What is the minimum evidence to confirm or refute this behavior?"

    def _llm_auto_notes(self, pack: Dict[str, Any]) -> List[str]:
        notes = []
        for f in (pack.get("related_findings") or [])[:2]:
            notes.append(f"note: {f.get('title')}")
        for a in (pack.get("api_calls") or [])[:2]:
            notes.append(f"api: {a}")
        return notes

    def _build_llm_nudge(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        """Strong, explicit nudge that makes tool-first behavior obvious."""
        must_call = bool(pack.get("must_call_before_answer"))
        req = pack.get("required_followup_call") or ((pack.get("llm_action_card") or {}).get("primary") or {}).get("call") or {}
        call_txt = f"{req.get('tool')}.{req.get('action')}" if req.get("tool") and req.get("action") else "code.callers"
        protocol = [
            "Do not conclude yet.",
            f"Run required MCP call now: {call_txt}",
            "Only after call result, update hypothesis and confidence.",
        ]
        if not must_call:
            protocol = [
                "Prefer MCP-first: run one call before final answer.",
                f"Recommended call: {call_txt}",
                "Use returned evidence snippets in your conclusion.",
            ]
        return {
            "must_call": must_call,
            "required_call": req if req else {"tool": "code", "action": "callers", "addr": addr},
            "protocol": protocol,
            "short": protocol[1],
        }

    def _focus_explainability(self, cands: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Explain why top focus won vs alternatives."""
        if not cands:
            return {}
        top = cands[0]
        out: Dict[str, Any] = {
            "selected": f"{top.get('tool')}:{top.get('action')}",
            "selected_score": float(top.get("score") or 0.0),
            "selected_reason": top.get("reason") or "",
        }
        if len(cands) > 1:
            second = cands[1]
            out["runner_up"] = f"{second.get('tool')}:{second.get('action')}"
            out["score_margin"] = round(float(top.get("score") or 0.0) - float(second.get("score") or 0.0), 3)
        return out

    def _semantic_circuit_open(self, session_id: str) -> bool:
        if not session_id:
            return False
        with self._circuit_breaker_lock:
            return int(self._semantic_circuit_breaker_until.get(session_id, 0)) > int(time.time())

    def _adaptive_semantic_budget(self, session_id: str, default_max: int = 24) -> int:
        """Dynamically tune semantic candidate budget using quality/perf signals."""
        if not session_id:
            return default_max
        now = time.time()
        with self._semantic_budget_lock:
            cached = self._semantic_budget_cache.get(session_id)
            if cached and (now - cached[0] <= 2.0):
                return int(cached[1])
        budget = int(default_max)
        try:
            stats = self._session_retrieval_stats(session_id)
            sem = stats.get("semantic_linked") or {}
            hit = float(sem.get("hit_rate") or 0.0)
            health = self._collect_intelligence_health(session_id)
            perf = (health.get("perf") or {}).get("decompile_enrich") or {}
            avg_ms = float(perf.get("avg_ms") or 0.0)

            if hit >= 0.7:
                budget += 8
            elif hit <= 0.25:
                budget -= 6
            if avg_ms > 70.0:
                budget -= 5
            elif avg_ms > 0 and avg_ms < 20.0:
                budget += 3
            if self._semantic_circuit_open(session_id):
                budget = min(budget, 8)
        except Exception:
            pass
        budget = max(8, min(48, budget))
        with self._semantic_budget_lock:
            self._semantic_budget_cache[session_id] = (now, budget)
        return budget

    def _update_semantic_circuit_breaker(self, session_id: str) -> None:
        """Open semantic circuit briefly when quality is persistently weak."""
        if not session_id:
            return
        try:
            stats = self._session_retrieval_stats(session_id)
            sem = stats.get("semantic_linked") or {}
            sem_total = int(sem.get("total") or 0)
            sem_hit = float(sem.get("hit_rate") or 0.0)
            health = self._collect_intelligence_health(session_id)
            cache_hit = float((health.get("bb_cache") or {}).get("hit_rate") or 0.0)
            if sem_total >= 10 and sem_hit < 0.2 and cache_hit < 0.15:
                with self._circuit_breaker_lock:
                    self._semantic_circuit_breaker_until[session_id] = int(time.time()) + 120
        except Exception:
            return

    def _derive_focus_candidates(
        self,
        pack: Dict[str, Any],
        addr: str,
        session_id: str,
    ) -> List[Dict[str, Any]]:
        try:
            policy = self._session_source_policy(session_id)
            stats = self._session_retrieval_stats(session_id)
            return derive_focus_candidates(
                pack=pack,
                addr=addr,
                policy=policy,
                stats=stats,
                bias_fn=lambda t, a: self._focus_action_bias(session_id, t, a),
            )
        except Exception:
            return []

    def _get_semantic_threshold(self, session_id: str) -> float:
        if not session_id:
            return 0.5
        with self._semantic_threshold_lock:
            return float(self._session_semantic_threshold.get(session_id, 0.5))

    def _tune_semantic_threshold(self, session_id: str) -> None:
        """
        Tune semantic threshold from observed semantic hit-rate.
        """
        if not session_id:
            return
        try:
            stats = self._session_retrieval_stats(session_id)
            sem = stats.get("semantic_linked") if isinstance(stats, dict) else None
            if not sem:
                return
            total = int(sem.get("total") or 0)
            hit_rate = float(sem.get("hit_rate") or 0.0)
            if total < 6:
                return
            with self._semantic_threshold_lock:
                cur = float(self._session_semantic_threshold.get(session_id, 0.5))
                nxt = cur
                if hit_rate < 0.35:
                    nxt = min(0.75, cur + 0.03)
                elif hit_rate > 0.75:
                    nxt = max(0.35, cur - 0.03)
                if abs(nxt - cur) >= 0.005:
                    self._session_semantic_threshold[session_id] = round(nxt, 3)
                    self._invalidate_session_caches(session_id)
                    self._schedule_policy_save(session_id)
        except Exception:
            return

    def _get_bb_by_api_signals(
        self,
        bb_store,
        api_calls: List[str],
        addr: str,
        top_k: int = 4,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve blackboard findings related to the same behavior signal (APIs/tags),
        not just exact address matches.
        """
        if bb_store is None or not api_calls:
            return []
        try:
            ranked: List[Tuple[int, float, Dict[str, Any]]] = []
            seen_ids: set = set()
            # Query per API tag; blackboard tags are stored as JSON arrays and
            # list(tag=...) already supports LIKE matching.
            for api in api_calls[:8]:
                for entry in bb_store.list(tag=api, limit=6):
                    eid = entry.get("id")
                    if not eid or eid in seen_ids:
                        continue
                    seen_ids.add(eid)
                    eaddr = str(entry.get("addr") or "")
                    same_addr_penalty = 0 if (addr and eaddr and eaddr != addr) else 1
                    conf = float(entry.get("confidence") or 0.0)
                    ranked.append((same_addr_penalty, -int(conf * 1000), entry))
            ranked.sort(key=lambda x: (x[0], x[1]))
            return [e for _, _, e in ranked[:top_k]]
        except Exception:
            return []

    def _record_related_addresses(self, session_id: str, anchor_addr: str, related_addrs: List[str]) -> None:
        """Record caller/callee/xref relations observed in tool outputs."""
        if not session_id or not anchor_addr or not related_addrs:
            return
        try:
            with self._related_addr_lock:
                graph = self._related_addr_graph[session_id]
                for other in related_addrs:
                    if not other or other == anchor_addr:
                        continue
                    graph[anchor_addr].add(other)
                    graph[other].add(anchor_addr)
        except Exception:
            pass

    def _get_bb_by_related_addresses(
        self,
        session_id: str,
        addr: str,
        bb_store,
        top_k: int = 4,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve blackboard findings from addresses related through recent
        caller/callee/xref exploration in this session.
        """
        if bb_store is None or not session_id or not addr:
            return []
        try:
            with self._related_addr_lock:
                neighbors = list(self._related_addr_graph.get(session_id, {}).get(addr, set()))
            if not neighbors:
                return []
            out: List[Dict[str, Any]] = []
            seen: set = set()
            for naddr in neighbors[:8]:
                for entry in bb_store.list(addr=naddr, limit=3):
                    eid = entry.get("id")
                    if not eid or eid in seen:
                        continue
                    seen.add(eid)
                    out.append(entry)
                    if len(out) >= top_k:
                        return out
            return out
        except Exception:
            return []

    def _cached_bb_entry_vec(self, entry: Dict[str, Any]) -> Optional[List[float]]:
        """Get or compute cached embedding vector for a blackboard entry."""
        text = f"{entry.get('title', '')} {entry.get('content', '')}".strip()
        if not text:
            return None
        entry_id = str(entry.get("id") or "")
        updated = str(entry.get("updated_at") or "")
        cache_key = f"{entry_id}:{updated}:{hashlib.md5(text[:800].encode()).hexdigest()}"
        now = time.time()
        with self._bb_entry_vec_cache_lock:
            cached = self._bb_entry_vec_cache.get(cache_key)
            if cached is not None:
                vec, ts = cached
                if now - ts <= self._bb_entry_cache_ttl_sec:
                    with self._bb_cache_stats_lock:
                        self._bb_cache_hits += 1
                    return vec
                self._bb_entry_vec_cache.pop(cache_key, None)
        with self._bb_cache_stats_lock:
            self._bb_cache_misses += 1
        vec = self._embedder.embed(text[:400])
        with self._bb_entry_vec_cache_lock:
            # Keep cache bounded and evict oldest/expired entries.
            if len(self._bb_entry_vec_cache) >= self._bb_entry_cache_max:
                stale_keys = [k for k, (_, ts) in self._bb_entry_vec_cache.items()
                              if now - ts > self._bb_entry_cache_ttl_sec]
                for k in stale_keys:
                    self._bb_entry_vec_cache.pop(k, None)
                if len(self._bb_entry_vec_cache) >= self._bb_entry_cache_max:
                    oldest = sorted(self._bb_entry_vec_cache.items(), key=lambda kv: kv[1][1])
                    drop_n = max(1, self._bb_entry_cache_max // 4)
                    for k, _ in oldest[:drop_n]:
                        self._bb_entry_vec_cache.pop(k, None)
            self._bb_entry_vec_cache[cache_key] = (vec, now)
        return vec

    def _cached_bb_entry_vecs(self, entries: List[Dict[str, Any]]) -> Dict[str, List[float]]:
        """
        Vectorize many blackboard entries with cache-first micro-batching.
        Returns mapping of entry_id -> vector.
        """
        out: Dict[str, List[float]] = {}
        misses: List[Tuple[str, str, str]] = []  # (cache_key, text, entry_id)
        now = time.time()
        with self._bb_entry_vec_cache_lock:
            for entry in entries:
                text = f"{entry.get('title', '')} {entry.get('content', '')}".strip()
                if not text:
                    continue
                entry_id = str(entry.get("id") or "")
                updated = str(entry.get("updated_at") or "")
                cache_key = f"{entry_id}:{updated}:{hashlib.md5(text[:800].encode()).hexdigest()}"
                cached = self._bb_entry_vec_cache.get(cache_key)
                if cached is not None and (now - cached[1] <= self._bb_entry_cache_ttl_sec):
                    out[entry_id or cache_key] = cached[0]
                    with self._bb_cache_stats_lock:
                        self._bb_cache_hits += 1
                else:
                    misses.append((cache_key, text[:400], entry_id or cache_key))
                    with self._bb_cache_stats_lock:
                        self._bb_cache_misses += 1
        if misses:
            texts = [m[1] for m in misses]
            vecs = self._embedder.embed_batch(texts)
            with self._bb_entry_vec_cache_lock:
                for (cache_key, _text, entry_id), vec in zip(misses, vecs):
                    if len(self._bb_entry_vec_cache) >= self._bb_entry_cache_max:
                        oldest = sorted(self._bb_entry_vec_cache.items(), key=lambda kv: kv[1][1])
                        for k, _ in oldest[: max(1, self._bb_entry_cache_max // 5)]:
                            self._bb_entry_vec_cache.pop(k, None)
                    self._bb_entry_vec_cache[cache_key] = (vec, now)
                    out[entry_id] = vec
        return out

    def _semantic_candidates(
        self,
        all_entries: List[Dict[str, Any]],
        api_calls: Optional[List[str]],
        max_entries: int,
    ) -> List[Dict[str, Any]]:
        """Adaptive candidate prefilter before semantic scoring."""
        if not all_entries:
            return []
        api_set = set(api_calls or [])
        scored: List[Tuple[float, Dict[str, Any]]] = []
        now = time.time()
        for e in all_entries:
            conf = float(e.get("confidence") or 0.0)
            upd = float(e.get("updated_at") or 0.0)
            recency = 1.0 / (1.0 + max(0.0, now - upd) / 86400.0)
            tags = set(e.get("tags") or [])
            api_overlap = 1.0 if (api_set and tags.intersection(api_set)) else 0.0
            score = conf * 0.55 + recency * 0.25 + api_overlap * 0.2
            scored.append((score, e))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:max_entries]]

    def _get_bb_semantic_vec(
        self,
        query_vec: List[float],
        bb_store,
        top_k: int = 3,
        threshold: float = 0.5,
        max_entries: int = 20,
        api_calls: Optional[List[str]] = None,
        session_id: str = "",
    ) -> List[Dict[str, Any]]:
        """
        Semantic blackboard retrieval using a pre-computed query vector.
        Caps at max_entries to keep latency bounded: each entry requires one embed call.
        """
        if bb_store is None:
            return []
        try:
            cache_key = ""
            if session_id:
                qh = hashlib.md5(json.dumps(query_vec[:32]).encode()).hexdigest()[:12]
                ah = hashlib.md5("|".join(sorted(api_calls or [])).encode()).hexdigest()[:8]
                cache_key = f"{session_id}:{qh}:{ah}:{threshold:.3f}:{max_entries}:{top_k}"
                with self._semantic_result_cache_lock:
                    cached = self._semantic_result_cache.get(cache_key)
                    if cached and (time.time() - cached[0] <= self._semantic_result_cache_ttl_sec):
                        return list(cached[1])

            all_entries = bb_store.list(limit=max(max_entries * 3, 30))
            if not all_entries:
                return []
            candidates = self._semantic_candidates(all_entries, api_calls, max_entries=max_entries)
            scored = []
            vecs = self._cached_bb_entry_vecs(candidates)
            for entry in candidates:
                entry_id = str(entry.get("id") or "")
                emb = vecs.get(entry_id)
                if emb is None:
                    continue
                sim = BgeCodeEmbedder.cosine(query_vec, emb)
                if sim >= threshold:
                    scored.append((sim, entry))
            scored.sort(reverse=True)
            out = [e for _, e in scored[:top_k]]
            if cache_key:
                with self._semantic_result_cache_lock:
                    if len(self._semantic_result_cache) > 300:
                        self._semantic_result_cache.clear()
                    self._semantic_result_cache[cache_key] = (time.time(), out)
            return out
        except Exception:
            return []

    def _get_bb_semantic(
        self,
        pseudocode: str,
        bb_store,
        top_k: int = 3,
        threshold: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """
        Find semantically relevant blackboard entries using embedding similarity.
        Falls back gracefully if store is empty or embedder is slow.
        """
        if bb_store is None or not pseudocode:
            return []
        try:
            all_entries = bb_store.list(limit=100)
            if not all_entries:
                return []
            q = self._embedder.embed(pseudocode[:2000])
            scored = []
            for entry in all_entries:
                text = f"{entry.get('title', '')} {entry.get('content', '')}"
                if not text.strip():
                    continue
                emb = self._embedder.embed(text[:500])
                sim = BgeCodeEmbedder.cosine(q, emb)
                if sim >= threshold:
                    scored.append((sim, entry))
            scored.sort(reverse=True)
            return [e for _, e in scored[:top_k]]
        except Exception:
            return []

    # ── stuck detection ──────────────────────────────────────────────────

    def record_call(self, session_id: str, tool: str, action: str, addr: str) -> None:
        with self._activity_lock:
            log = self._activity[session_id]
            log.append({"tool": tool, "action": action, "addr": addr, "ts": time.time()})
            # Keep last 50 calls
            if len(log) > 50:
                self._activity[session_id] = log[-50:]

    def check_stuck(
        self,
        session_id: str,
        addr: str,
        tool: str,
        action: str,
    ) -> Optional[Dict[str, Any]]:
        with self._activity_lock:
            log = list(self._activity.get(session_id, []))
        if len(log) < 4:
            return None

        # Same address analyzed 3+ times
        if addr:
            addr_hits = sum(1 for e in log[-20:] if e.get("addr") == addr)
            if addr_hits >= 3:
                return {
                    "type": "repeated_address",
                    "address": addr,
                    "count": addr_hits,
                    "message": f"This address has been analyzed {addr_hits} times. "
                               "Consider exploring callers, callees, or cross-references.",
                    "pivot_suggestions": [
                        f"code(action='callers', addr='{addr}')",
                        f"code(action='callees', addr='{addr}')",
                        f"xref_analysis(action='call_chain', addr='{addr}')",
                        "data(action='imports') — review imports for context",
                    ],
                }

        # Same tool:action repeated 5+ times in last 15 calls
        recent = log[-15:]
        ta = f"{tool}:{action}"
        ta_count = sum(1 for e in recent if f"{e['tool']}:{e['action']}" == ta)
        if ta_count >= 5:
            pivots = {
                "code:decompile":   ["code:callers", "code:callees", "search:semantic"],
                "search:find":      ["schemaboot:query", "data:imports", "code:decompile"],
                "code:disasm":      ["code:decompile", "code:blocks", "ctree:get"],
            }
            return {
                "type": "repeated_tool",
                "tool_action": ta,
                "count": ta_count,
                "message": f"Called {ta} {ta_count} times recently. Try a different approach.",
                "pivot_suggestions": pivots.get(ta, [
                    "blackboard(action='list') — review what you've found so far",
                    "predictor(action='suggest_focus') — get focus suggestions",
                ]),
            }

        return None

    # ── main entry point ─────────────────────────────────────────────────

    def assemble(
        self,
        tool: str,
        action: str,
        payload: Dict[str, Any],
        addr: str,
        session_id: str,
        idb_path: str,
        bb_store=None,
    ) -> Dict[str, Any]:
        """
        Build a context_pack for injection into the tool response.
        Non-blocking: slow operations (embedding new function) are async.
        Returns empty dict if nothing meaningful to inject.
        """
        t_all = self._perf_start()
        pack: Dict[str, Any] = {}

        self._load_session_policy(session_id, idb_path)
        self._run_housekeeping(session_id)
        followed_focus = self._consume_focus_follow(session_id, tool, action)

        # Record for stuck detection
        self.record_call(session_id, tool, action, addr)

        # ── 1. Address-matched blackboard findings
        bb_addr = self._get_bb_entries(addr, bb_store)
        if bb_addr:
            self._merge_related_findings(pack, bb_addr, "address_linked", session_id=session_id)

        # ── 2. Decompile-specific enrichment
        is_decompile = (tool == "code" and
                        action in ("decompile", "semantic_decompile", "decompile_chain"))
        pseudocode = ""
        if is_decompile:
            pseudocode = (payload.get("code") or payload.get("pseudocode") or
                          payload.get("output") or "")
            # For decompile_chain, grab the main pseudocode
            if not pseudocode and isinstance(payload.get("results"), list):
                for r in payload["results"]:
                    pseudocode = r.get("pseudocode") or r.get("code") or ""
                    if pseudocode:
                        break

        if pseudocode and len(pseudocode.strip()) > 80:
            t_dec = self._perf_start()
            try:
                self._enrich_decompile(pack, payload, pseudocode, addr, idb_path, bb_store, session_id)
            except Exception:
                pass
            self._perf_end(session_id, "decompile_enrich", t_dec)

        # ── 2b. Search/xref result enrichment ─────────────────────────────
        # When a search returns a list of addresses, enrich each with
        # schemaboot structural data so the LLM doesn't need extra tool calls
        # to assess which hits are interesting.
        is_search = tool in ("search", "xref_analysis", "code") and action in (
            "find", "api", "callers", "callees", "xrefs_to", "xrefs_from",
            "data_ref", "code_ref", "name", "string", "bytes",
            "call_chain", "common_callers", "hub_functions",
        )
        if is_search and idb_path:
            t_search = self._perf_start()
            try:
                # Collect addresses from the result payload
                hit_addrs: List[str] = []
                for key in ("matches", "items", "results", "callers", "callees",
                            "xrefs", "refs", "addresses", "functions"):
                    val = payload.get(key)
                    if isinstance(val, list):
                        for item in val:
                            if isinstance(item, str) and item.startswith("0x"):
                                hit_addrs.append(item)
                            elif isinstance(item, dict):
                                for k in ("ea", "addr", "address", "from", "to"):
                                    v = item.get(k)
                                    if v and str(v).startswith("0x"):
                                        hit_addrs.append(str(v))
                                        break
                if hit_addrs:
                    if addr:
                        self._record_related_addresses(session_id, addr, hit_addrs)
                    enriched = self._enrich_address_list(hit_addrs, idb_path)
                    if enriched:
                        pack["hit_details"] = enriched
            except Exception:
                pass
            self._perf_end(session_id, "search_enrich", t_search)

        # ── 2c. Suggest next unanalyzed targets (after any tool call) ─────
        # Use schemaboot to recommend high-interest functions not yet seen.
        if idb_path and len(self._indexes.get(idb_path, type("X", (), {"_cache": {}})())._cache
                            if False else []) >= 0:
            try:
                # Only inject next_targets occasionally — every 5 calls per session
                with self._activity_lock:
                    n_calls = len(self._activity.get(session_id, []))
                if n_calls % 5 == 0 and n_calls > 0:
                    targets = self.suggest_next_targets(idb_path, limit=3)
                    if targets:
                        pack["suggested_targets"] = targets
            except Exception:
                pass

        # ── 3. Stuck detection
        stuck = self.check_stuck(session_id, addr, tool, action)
        if stuck:
            pack["stuck"] = stuck

        if followed_focus:
            success = bool(
                pack.get("related_findings")
                or pack.get("hit_details")
                or pack.get("similar_functions")
                or pack.get("api_calls")
                or pack.get("analysis_focus")
            )
            self._record_focus_outcome(session_id, tool, action, success)

        health = self._collect_intelligence_health(session_id)
        if health:
            pack["intelligence_health"] = health

        if addr:
            pack["compiled_plan"] = self._compile_question_tool_plan(pack, addr)
            budget = self._evidence_budget_gate(pack, addr)
            pack["evidence_budget"] = budget
            escalation = self._dead_end_escalation(session_id, addr, pack)
            pack["dead_end_escalation"] = escalation
            # default-to-call policy: force at least one call under uncertainty/blocks
            must_call = bool(budget.get("claim_blocked") or escalation.get("loop_detected") or (pack.get("llm_uncertainty") or {}).get("risk") in ("medium", "high"))
            pack["must_call_before_answer"] = must_call
            req = budget.get("required_followup_call") or escalation.get("required_followup_call")
            if must_call and req:
                pack["required_followup_call"] = req
            pack["mode_profile"] = self._mode_profile(pack)

        self._record_call_outcome(session_id, pack)
        pack["mcp_value_score"] = self._mcp_value_score(session_id, pack)

        self._perf_end(session_id, "assemble", t_all)

        return pack

    def _query_schemaboot(self, idb_path: str, addr: str) -> Optional[Dict[str, Any]]:
        """Pull structural attributes from schemaboot for this function address."""
        if not idb_path or not addr:
            return None
        db = idb_path + ".schemaboot.db"
        if not os.path.exists(db):
            return None
        try:
            ea = int(addr, 16) if addr.startswith("0x") else int(addr)
            conn = sqlite3.connect(db)
            cur = conn.cursor()
            cur.execute("""
                SELECT ea, name, size, entropy, bb_count, cyclomatic_complexity,
                       incoming_xrefs, outgoing_xrefs, call_count, xor_count,
                       api_count, string_count, has_loops
                FROM function_attrs WHERE ea = ?
            """, (ea,))
            row = cur.fetchone()
            # Also fetch API list from junction table
            apis: List[str] = []
            if row:
                cur.execute(
                    "SELECT api_name FROM function_apis WHERE func_ea = ? LIMIT 60",
                    (ea,),
                )
                apis = [r[0] for r in cur.fetchall()]
            conn.close()
            if not row:
                return None
            return {
                "ea": hex(row[0]),
                "name": row[1],
                "size": row[2],
                "entropy": float(row[3] or 0),
                "bb_count": row[4],
                "cyclomatic_complexity": row[5],
                "incoming_xrefs": row[6],
                "outgoing_xrefs": row[7],
                "call_count": row[8],
                "xor_count": row[9],
                "api_count": row[10],
                "string_count": row[11],
                "has_loops": bool(row[12]),
                "known_apis": apis,
            }
        except Exception:
            return None

    def _enrich_decompile(
        self,
        pack: Dict[str, Any],
        payload: Dict[str, Any],
        pseudocode: str,
        addr: str,
        idb_path: str,
        bb_store,
        session_id: str,
    ) -> None:
        """
        Decompile-specific enrichment.  Deterministic first, embeddings second.

        Priority order:
          1. Deterministic API call extraction from pseudocode text (instant, high signal)
          2. Schemaboot structural attributes (fast SQL — xor_count, entropy, xrefs)
          3. Blackboard addr-match (fast SQL — past findings at this address)
          4. Function embedding + similarity search (slow, grows over session)
          5. Semantic blackboard retrieval (slow, only if bb_store populated)
        """
        func_name = payload.get("name") or f"sub_{addr}"

        # ── Step 1: Deterministic API extraction (no ML, instant) ─────────
        api_calls: List[str] = []
        string_refs: List[str] = []
        crypto_consts: List[str] = []
        try:
            api_calls    = _extract_api_calls(pseudocode)
            string_refs  = _extract_string_refs(pseudocode)
            crypto_consts = _detect_crypto_constants(pseudocode)
        except Exception:
            pass

        # ── Step 2: Schemaboot structural attributes (fast SQL) ──────────
        sb_attrs: Optional[Dict[str, Any]] = None
        try:
            sb_attrs = self._query_schemaboot(idb_path, addr)
            # Merge API list from schemaboot with what we found in pseudocode
            if sb_attrs and sb_attrs.get("known_apis"):
                extra = [a for a in sb_attrs["known_apis"] if a not in api_calls]
                api_calls = (api_calls + extra)[:40]
        except Exception:
            pass

        # ── Step 3: Surface the extracted facts ───────────────────────────
        if api_calls:
            pack["api_calls"] = api_calls
        if string_refs:
            pack["string_refs"] = string_refs
        if crypto_consts:
            pack["crypto_constants_detected"] = crypto_consts

        if sb_attrs:
            structural: Dict[str, Any] = {}
            if sb_attrs.get("incoming_xrefs") is not None:
                structural["xref_count"] = sb_attrs["incoming_xrefs"]
            if sb_attrs.get("xor_count", 0) > 0:
                structural["xor_count"] = sb_attrs["xor_count"]
            if sb_attrs.get("entropy", 0) > 0:
                structural["entropy"] = round(sb_attrs["entropy"], 2)
            if sb_attrs.get("cyclomatic_complexity", 0) > 0:
                structural["cyclomatic_complexity"] = sb_attrs["cyclomatic_complexity"]
            if sb_attrs.get("has_loops"):
                structural["has_loops"] = True
            if sb_attrs.get("bb_count", 0) > 0:
                structural["bb_count"] = sb_attrs["bb_count"]
            if structural:
                pack["structural"] = structural

        # ── Step 3b: Behavior classification via the shared zero-shot classifier
        # This is intentionally separate from API/structural extraction so the
        # response can expose both deterministic and semantic signals.
        behavior_hits: List[Dict[str, Any]] = []
        if pseudocode.strip():
            try:
                behavior_hits = self._behavior_classifier().classify(
                    pseudocode,
                    threshold=0.35,
                    top_k=4,
                    block=True,
                )
            except Exception:
                behavior_hits = []
        if behavior_hits:
            pack["behavior_classifications"] = behavior_hits
            pack["behavior_tags"] = [hit.get("behavior") for hit in behavior_hits if hit.get("behavior")]

        # ── Step 4: Rule-based actions from API patterns + structural attrs
        actions: List[Dict[str, Any]] = []
        seen_act: set = set()
        try:
            for act in _actions_from_apis(api_calls, addr):
                key = f"{act['tool']}:{act['action']}"
                if key not in seen_act:
                    seen_act.add(key)
                    actions.append(act)
        except Exception:
            pass
        try:
            if sb_attrs:
                for act in _actions_from_schemaboot(sb_attrs, addr):
                    key = f"{act['tool']}:{act['action']}"
                    if key not in seen_act:
                        seen_act.add(key)
                        actions.append(act)
        except Exception:
            pass
        # Always suggest callers if we haven't already
        if f"code:callers" not in seen_act and addr:
            actions.append({
                "tool": "code", "action": "callers", "addr": addr,
                "reason": "See what calls this function",
            })
        if actions:
            pack["suggested_next_actions"] = actions[:6]


        # -- Step 4b: Auto-blackboard -- write dangerous findings automatically --
        # The LLM should not have to manually blackboard every dangerous finding.
        if bb_store is not None and addr and api_calls:
            try:
                _DANGEROUS_COMBOS = [
                    ({"VirtualAllocEx", "WriteProcessMemory"}, "process_injection",
                     "Process injection", ["injection", "shellcode", "dangerous"]),
                    ({"CreateRemoteThread"}, "remote_exec",
                     "Remote thread creation", ["injection", "dangerous"]),
                    ({"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                      "NtQueryInformationProcess"}, "anti_debug",
                     "Anti-debugging", ["anti_debug", "evasion"]),
                    ({"AdjustTokenPrivileges"}, "privilege_escalation",
                     "Privilege escalation", ["privesc", "dangerous"]),
                    ({"RegSetValueEx", "CreateService"}, "persistence",
                     "Persistence mechanism", ["persistence"]),
                ]
                api_set = set(api_calls)
                for required, category, label, tags in _DANGEROUS_COMBOS:
                    if required & api_set:
                        matched = sorted(required & api_set)
                        title = f"{label} at {addr}"
                        if not bb_store.exists(addr, category, title):
                            bb_store.write(
                                title=title,
                                content=(
                                    f"Function {func_name} ({addr}) uses: "
                                    f"{', '.join(matched)}. Detected automatically."
                                ),
                                category=category,
                                addr=addr,
                                tags=tags,
                                confidence=0.92,
                            )
            except Exception:
                pass

        # ── Step 5: Embedding-based function similarity (background-safe) ─
        query_vec: Optional[List[float]] = None
        if idb_path:
            try:
                query_vec = self._embedder.embed(pseudocode[:3000])
                idx = self._get_index(idb_path)
                # Update cache + persist async
                idx._cache[addr] = query_vec
                blob = idx._pack(query_vec)
                ph   = idx._phash(pseudocode)
                def _persist(ea=addr, name=func_name, b=blob, p=ph, v=query_vec):
                    try:
                        with idx._conn() as conn:
                            conn.execute(
                                """INSERT INTO func_embeddings
                                   (ea, name, dim, vec_blob, pseudo_hash, indexed_at)
                                   VALUES(?,?,?,?,?,?)
                                   ON CONFLICT(ea) DO UPDATE SET
                                       name=excluded.name, vec_blob=excluded.vec_blob,
                                       pseudo_hash=excluded.pseudo_hash,
                                       indexed_at=excluded.indexed_at""",
                                (ea, name, len(v), b, p, time.time()),
                            )
                            conn.commit()
                    except Exception:
                        pass
                threading.Thread(target=_persist, daemon=True).start()

                # Similarity search over in-memory cache (instant)
                cache_snap = list(idx._cache.items())
                if len(cache_snap) > 1:
                    scored = sorted(
                        [(BgeCodeEmbedder.cosine(query_vec, v), ea)
                         for ea, v in cache_snap if ea != addr],
                        reverse=True,
                    )
                    top = [(sim, ea) for sim, ea in scored[:3] if sim >= 0.6]
                    if top:
                        top_eas = [ea for _, ea in top]
                        names: Dict[str, str] = {}
                        try:
                            with idx._conn() as conn:
                                ph2 = ",".join("?" * len(top_eas))
                                for row in conn.execute(
                                    f"SELECT ea, name FROM func_embeddings WHERE ea IN ({ph2})",
                                    top_eas,
                                ):
                                    names[row[0]] = row[1] or row[0]
                        except Exception:
                            pass
                        pack["similar_functions"] = [
                            {"ea": ea, "name": names.get(ea, ea), "similarity": round(sim, 4)}
                            for sim, ea in top
                        ]
            except Exception:
                pass

        # ── Step 6: Cross-address blackboard retrieval (callgraph-linked) ─
        if bb_store is not None and addr and session_id:
            try:
                rel_bb = self._get_bb_by_related_addresses(session_id, addr, bb_store, top_k=4)
                if rel_bb:
                    self._merge_related_findings(pack, rel_bb, "relation_linked", session_id=session_id)
            except Exception:
                pass

        # ── Step 7: Cross-address blackboard retrieval (API/tag linked) ───
        if bb_store is not None and api_calls:
            try:
                api_bb = self._get_bb_by_api_signals(bb_store, api_calls, addr, top_k=4)
                if api_bb:
                    self._merge_related_findings(pack, api_bb, "api_linked", session_id=session_id)
            except Exception:
                pass

        # ── Step 8: Semantic blackboard retrieval (if bb_store populated) ─
        if query_vec is not None and bb_store is not None and not self._semantic_circuit_open(session_id):
            try:
                sem_thr = self._get_semantic_threshold(session_id)
                # Use stored vectors in the new blackboard (fast cosine scan, no re-embedding)
                if hasattr(bb_store, "semantic_search"):
                    # New blackboard: vectors already stored, O(n) cosine scan
                    sig = _extract_signature(pseudocode, max_idents=40) or pseudocode[:512]
                    sem_bb = bb_store.semantic_search(
                        query=sig,
                        top_k=5,
                        threshold=sem_thr,
                    )
                    # Exclude the entry for this exact address to avoid self-reference
                    sem_bb = [e for e in sem_bb if e.get("addr") != addr][:3]
                else:
                    # Legacy blackboard: embed on-the-fly
                    sem_budget = self._adaptive_semantic_budget(session_id, default_max=24)
                    sem_bb = self._get_bb_semantic_vec(
                        query_vec,
                        bb_store,
                        top_k=3,
                        threshold=sem_thr,
                        max_entries=sem_budget,
                        api_calls=api_calls,
                        session_id=session_id,
                    )
                if sem_bb:
                    self._merge_related_findings(pack, sem_bb, "semantic_linked", session_id=session_id)
            except Exception:
                pass

        self._tune_semantic_threshold(session_id)
        self._update_semantic_circuit_breaker(session_id)
        stats = self._session_retrieval_stats(session_id)
        if stats:
            pack["retrieval_stats"] = stats
        alts = self._derive_focus_candidates(pack, addr, session_id)
        if alts:
            pack["analysis_focus"] = alts[0]
            self._record_focus_suggestion(session_id, alts[0])
            if len(alts) > 1:
                pack["analysis_focus_alternatives"] = alts[1:3]
            explain = self._focus_explainability(alts)
            if explain:
                pack["analysis_focus_explain"] = explain

        # LLM-first payloads: action card, uncertainty, and provenance snippets.
        if addr:
            pack["llm_action_card"] = self._build_llm_action_card(pack, addr)
            pack["llm_tool_call_contract"] = self._build_llm_tool_call_contract(pack, addr)
            pack["llm_failover_route"] = self._build_llm_failover_route(pack, addr)
        pack["llm_uncertainty"] = self._build_llm_uncertainty(pack)
        evid = self._build_llm_evidence_snippets(pack)
        if evid:
            pack["llm_evidence"] = evid
        pack["llm_response_style_guard"] = self._build_llm_response_style_guard(pack)
        if addr:
            pack["llm_query_intent"] = self._llm_query_intent(pack)
            pack["llm_required_evidence_sources"] = self._llm_required_evidence_sources(pack)
            pack["llm_claim_templates"] = self._llm_claim_templates()
            pack["llm_call_sequence"] = self._llm_call_sequence(pack, addr)
            pack["llm_refusal_policy"] = self._llm_refusal_policy(pack)
            pack["llm_tool_cooldowns"] = self._llm_tool_cooldowns(session_id)
            pack["llm_context_capsule"] = self._llm_context_capsule(pack, addr)
            pack["llm_verification_checklist"] = self._llm_verification_checklist(pack, addr)
            pack["llm_next_best_question"] = self._llm_next_best_question(pack)
            pack["llm_auto_notes"] = self._llm_auto_notes(pack)
            pack["llm_nudge"] = self._build_llm_nudge(pack, addr)



    def _enrich_address_list(
        self,
        addresses: List[str],
        idb_path: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Enrich a list of addresses with schemaboot structural data.
        Used to annotate search/xref results without extra tool calls.
        Returns a list of enriched entries (only for addresses that exist in schemaboot).
        """
        if not addresses or not idb_path:
            return []
        db = idb_path + ".schemaboot.db"
        if not os.path.exists(db):
            return []
        try:
            eas: List[int] = []
            for a in addresses[:limit]:
                try:
                    eas.append(int(a, 16) if str(a).startswith("0x") else int(a))
                except (ValueError, TypeError):
                    pass
            if not eas:
                return []
            conn = sqlite3.connect(db)
            cur = conn.cursor()
            ph = ",".join("?" * len(eas))
            cur.execute(f"""
                SELECT ea, name, size, entropy, cyclomatic_complexity,
                       xor_count, incoming_xrefs, api_count, has_loops
                FROM function_attrs WHERE ea IN ({ph})
            """, eas)
            rows = {row[0]: row for row in cur.fetchall()}
            # Fetch APIs for these functions
            cur.execute(f"""
                SELECT func_ea, api_name FROM function_apis
                WHERE func_ea IN ({ph}) LIMIT 200
            """, eas)
            apis_by_ea: Dict[int, List[str]] = {}
            for func_ea, api_name in cur.fetchall():
                apis_by_ea.setdefault(func_ea, []).append(api_name)
            conn.close()

            enriched = []
            for a_str in addresses[:limit]:
                try:
                    ea_int = int(a_str, 16) if str(a_str).startswith("0x") else int(a_str)
                except (ValueError, TypeError):
                    continue
                row = rows.get(ea_int)
                if not row:
                    continue
                entry: Dict[str, Any] = {
                    "ea":   hex(row[0]),
                    "name": row[1],
                }
                if row[2]:
                    entry["size"] = row[2]
                if float(row[3] or 0) > 4.5:
                    entry["entropy"] = round(float(row[3]), 2)
                if (row[4] or 0) > 5:
                    entry["cyclomatic"] = row[4]
                if (row[5] or 0) > 3:
                    entry["xor_count"] = row[5]
                if row[6] is not None:
                    entry["callers"] = row[6]
                apis = [a for a in apis_by_ea.get(ea_int, [])
                        if a in _ALL_INTERESTING][:5]
                if apis:
                    entry["dangerous_apis"] = apis
                if row[8]:
                    entry["has_loops"] = True
                enriched.append(entry)
            return enriched
        except Exception:
            return []


    def suggest_next_targets(
        self,
        idb_path: str,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Recommend unanalyzed functions worth examining next, ranked by
        interest score derived from schemaboot structural attributes:
          - xor_count  (obfuscation / custom crypto indicator)
          - entropy    (packed / encrypted content)
          - cyclomatic_complexity (complex logic)
          - api_count  (rich behaviour)
          - unnamed    (prefer sub_XXXXX targets over already-named ones)

        Excludes functions already in the embedding index (already seen).
        Returns an empty list if schemaboot has not been ingested yet.
        """
        if not idb_path:
            return []
        db = idb_path + ".schemaboot.db"
        if not os.path.exists(db):
            return []

        # Functions already indexed (= already decompiled this session)
        try:
            idx = self._get_index(idb_path)
            analyzed = set(idx._cache.keys())
        except Exception:
            analyzed = set()

        try:
            conn = sqlite3.connect(db)
            cur = conn.cursor()
            # Pull candidates ordered by interest score.
            # Prefer unnamed (sub_*) functions — named ones are probably understood.
            cur.execute("""
                SELECT ea, name,
                       xor_count, entropy, cyclomatic_complexity,
                       api_count, incoming_xrefs, string_count, has_loops
                FROM function_attrs
                WHERE size > 64
                ORDER BY
                    (xor_count * 4 +
                     CAST(entropy * 3 AS INTEGER) +
                     cyclomatic_complexity * 2 +
                     api_count) DESC
                LIMIT 200
            """)
            rows = cur.fetchall()

            # Fetch top dangerous-API functions separately
            cur.execute("""
                SELECT DISTINCT fa.ea, fa.name, fa.xor_count, fa.entropy,
                       fa.cyclomatic_complexity, fa.api_count, fa.incoming_xrefs,
                       fa.string_count, fa.has_loops
                FROM function_attrs fa
                JOIN function_apis fapi ON fapi.func_ea = fa.ea
                WHERE fapi.api_name IN (
                    'VirtualAllocEx','WriteProcessMemory','CreateRemoteThread',
                    'IsDebuggerPresent','AdjustTokenPrivileges',
                    'RegSetValueEx','CreateService',
                    'WSASocket','InternetOpen','WinHttpOpen'
                )
                LIMIT 50
            """)
            danger_rows = cur.fetchall()
            conn.close()
        except Exception:
            return []

        seen_eas: set = set()
        results: List[Dict[str, Any]] = []

        def _add(row, reason: str):
            ea_int = row[0]
            ea = hex(ea_int)
            if ea in analyzed or ea in seen_eas:
                return
            seen_eas.add(ea)
            xor   = row[2] or 0
            entr  = float(row[3] or 0)
            cc    = row[4] or 0
            apis  = row[5] or 0
            xrefs = row[6] or 0
            score = xor * 4 + entr * 3 + cc * 2 + apis
            results.append({
                "ea":    ea,
                "name":  row[1] or f"sub_{ea_int:X}",
                "reason": reason,
                "interest_score": round(score, 1),
                "xor_count":  xor,
                "entropy":    round(entr, 2),
                "cyclomatic": cc,
                "api_count":  apis,
                "callers":    xrefs,
            })

        # Dangerous-API functions first (highest priority)
        for row in danger_rows:
            _add(row, "calls dangerous API")
            if len(results) >= limit:
                break

        # Then high-score unnamed functions
        for row in rows:
            if len(results) >= limit:
                break
            name = row[1] or ""
            reason = (
                f"xor={row[2]}, entropy={row[3]:.1f}"
                if (row[2] or 0) > 3 or float(row[3] or 0) > 5.5
                else f"complexity={row[4]}, apis={row[5]}"
            )
            _add(row, reason)

        results.sort(key=lambda x: x["interest_score"], reverse=True)
        return results[:limit]


    def bulk_index(self, functions: List[Dict[str, Any]], idb_path: str) -> int:
        """
        Index a batch of functions (e.g. after schemaboot ingest).
        Each dict: {ea, name, pseudocode}.
        Returns count indexed.
        """
        if not idb_path or not functions:
            return 0
        idx = self._get_index(idb_path)
        count = 0
        for f in functions:
            pseudo = f.get("pseudocode") or f.get("code") or ""
            ea = str(f.get("ea") or f.get("addr") or "")
            name = str(f.get("name") or ea)
            if pseudo and ea:
                idx.index(ea, name, pseudo)
                count += 1
        return count

    def stop(self) -> None:
        """Shut down the llama-server subprocess cleanly."""
        self.flush_policy_saves()
        # Give background save workers a short chance to flush.
        time.sleep(0.05)
        self._embedder.stop()

    @property
    def status(self) -> Dict[str, Any]:
        return {
            "backend": self._embedder.backend,
            "llama_server_bin": self._embedder._server_bin or "not found",
            "model_path": self._embedder._model_path or "not found",
            "model_ready": self._embedder._ready,
            "embed_dim": EMBED_DIM,
            "indexes": {
                idb: {"functions_indexed": idx.size}
                for idb, idx in self._indexes.items()
            },
            "policy_save_queue": len(self._policy_save_due_at),
            "embed_batch_size": getattr(self._embedder, "_batch_size", 1),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Module-level singleton access
# ─────────────────────────────────────────────────────────────────────────────

_assembler: Optional[ContextAssembler] = None
_assembler_lock = threading.Lock()


def get_assembler() -> ContextAssembler:
    global _assembler
    with _assembler_lock:
        if _assembler is None:
            _assembler = ContextAssembler()
    return _assembler


def _shutdown_intelligence_singleton() -> None:
    global _assembler
    try:
        if _assembler is not None:
            _assembler.stop()
    except Exception:
        pass


atexit.register(_shutdown_intelligence_singleton)
