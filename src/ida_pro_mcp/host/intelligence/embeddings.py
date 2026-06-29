"""Embedding index storage helpers for intelligence core."""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import sqlite3
import threading
import time
from collections import Counter
from contextlib import closing, suppress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .helpers import cosine_similarity as _cosine

logger = logging.getLogger(__name__)


_SEARCH_TOKEN_RE = re.compile(r"0x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]{1,}|\b\d+\b")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

# Consolidated noise-word set used by both text-search tokenisation and
# signature extraction.  Kept in one place to avoid drift between the two
# subsystems.  Imported by ``intelligence/core.py``.
NOISE_WORDS = frozenset({
    "the", "and", "for", "with", "this", "that", "from", "into", "while",
    "void", "char", "int", "uint", "long", "short", "bool", "true", "false",
    "const", "struct", "class", "return", "case", "break", "default", "null",
    "auto", "static", "extern", "signed", "unsigned", "size", "len", "buf",
    "ptr", "tmp", "ret", "arg", "args", "result", "value", "values", "data",
    "var", "vars", "out", "dst", "src", "count", "index", "idx",
    "NULL", "sizeof", "else", "inline", "typedef", "goto", "continue",
    "switch", "type", "flag", "mode", "num", "res", "val", "msg",
    "str", "memcpy", "memset", "memcmp", "memmove", "malloc", "calloc",
    "free", "printf", "sprintf", "strcpy", "strlen", "strcat", "strcmp",
})

_SEARCH_NOISE_TOKENS = NOISE_WORDS

_TOKEN_SYNONYMS: Dict[str, Tuple[str, ...]] = {
    "aes": ("crypto", "cipher", "encrypt", "decrypt"),
    "cipher": ("crypto", "encrypt", "decrypt"),
    "encrypt": ("crypto", "cipher"),
    "decrypt": ("crypto", "cipher", "xor"),
    "hash": ("digest", "sha", "md5"),
    "digest": ("hash", "sha", "md5"),
    "http": ("network", "socket", "header", "headers", "request", "response"),
    "https": ("http", "network", "socket"),
    "recv": ("receive", "socket", "network"),
    "send": ("socket", "network"),
    "socket": ("network", "connect", "recv", "send"),
    "connect": ("network", "socket"),
    "file": ("open", "read", "write", "path"),
    "registry": ("persistence", "autorun"),
    "service": ("persistence", "autorun"),
    "debugger": ("antidebug", "anti", "debug"),
    "vm": ("virtual", "sandbox"),
    "sandbox": ("vm", "evasion"),
    "overflow": ("bounds", "memcpy", "strcpy"),
    "uaf": ("use", "after", "free"),
    "format": ("printf", "syslog", "snprintf"),
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_file_head_sha256(path: str, max_bytes: int = 16 * 1024 * 1024) -> str:
    if not path or not os.path.isfile(path):
        return ""
    h = hashlib.sha256()
    read_bytes = 0
    with open(path, "rb") as f:
        while read_bytes < max_bytes:
            chunk = f.read(min(1024 * 1024, max_bytes - read_bytes))
            if not chunk:
                break
            h.update(chunk)
            read_bytes += len(chunk)
    return h.hexdigest()


def _safe_stat(path: str) -> tuple[int, int]:
    if not path or not os.path.isfile(path):
        return 0, 0
    st = os.stat(path)
    return int(st.st_size), int(st.st_mtime_ns)


def _split_identifier_token(token: str) -> List[str]:
    """Split RE identifiers into searchable semantic pieces."""
    raw = str(token or "").strip()
    if not raw:
        return []
    if raw.lower().startswith("0x") or raw.isdigit():
        return [raw.lower()]
    parts: List[str] = []
    for chunk in re.split(r"[_\W]+", raw):
        if not chunk:
            continue
        split = [sub for sub in _CAMEL_BOUNDARY_RE.split(chunk) if sub]
        if len(split) == 1:
            parts.append(chunk.lower())
        else:
            parts.extend(sub.lower() for sub in split)
    return parts


def _expand_query_tokens(tokens: set[str]) -> set[str]:
    expanded = set(tokens)
    for tok in list(tokens):
        expanded.update(_TOKEN_SYNONYMS.get(tok, ()))
    return expanded


def _idf_scores(docs: List[set[str]]) -> Dict[str, float]:
    df: Counter[str] = Counter()
    for doc in docs:
        df.update(doc)
    total = max(1, len(docs))
    return {tok: math.log((total + 1.0) / (cnt + 0.5)) + 1.0 for tok, cnt in df.items()}


def _weighted_token_score(query_tokens: set[str], row_tokens: set[str], idf: Dict[str, float]) -> Tuple[float, List[str]]:
    if not query_tokens or not row_tokens:
        return 0.0, []
    expanded = _expand_query_tokens(query_tokens)
    direct = query_tokens.intersection(row_tokens)
    indirect = (expanded - query_tokens).intersection(row_tokens)
    numerator = sum(idf.get(tok, 1.0) for tok in direct)
    numerator += 0.55 * sum(idf.get(tok, 1.0) for tok in indirect)
    denominator = sum(idf.get(tok, 1.0) for tok in query_tokens) or 1.0
    coverage = min(1.0, numerator / denominator)
    precision = min(1.0, numerator / (sum(idf.get(tok, 1.0) for tok in row_tokens) or 1.0))
    score = (0.82 * coverage) + (0.18 * precision)
    return score, sorted(direct.union(indirect))[:16]


def _normalize_search_text(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "").strip().lower())


def _tokenize_search_text(text: str, max_tokens: int = 96) -> List[str]:
    seen = set()
    out: List[str] = []
    for raw in _SEARCH_TOKEN_RE.findall(str(text or "").replace("_", " ")):
        for low in _split_identifier_token(raw):
            if low in seen or low in _SEARCH_NOISE_TOKENS:
                continue
            if low.isdigit() and len(low) < 3:
                continue
            seen.add(low)
            out.append(low)
            if len(out) >= max_tokens:
                return out
    for raw in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", str(text or "")):
        low = raw.lower()
        if low in seen or low in _SEARCH_NOISE_TOKENS:
            continue
        for part in [low] + _split_identifier_token(raw):
            if part in seen or part in _SEARCH_NOISE_TOKENS:
                continue
            seen.add(part)
            out.append(part)
            if len(out) >= max_tokens:
                return out
    return out


def _extract_signature_text(pseudocode: str, max_tokens: int = 96) -> str:
    return " ".join(_tokenize_search_text(pseudocode, max_tokens=max_tokens))


def _clip_signature(text: str, max_len: int = 160) -> str:
    compact = re.sub(r"\s+", " ", str(text or "").strip())
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3] + "..."


class FunctionEmbeddingIndex:
    """
    Stores 1536-dim float32 embeddings of decompiled functions,
    one SQLite database per binary (<idb_path>.embeddings.db).

    Replaces the spectral-CFG encoder (MbaGCN — untrained random SSM)
    and TurboQuant (quantization of tabular features it was never
    designed for).
    """

    INDEX_SCHEMA_VERSION = 2

    def __init__(self, db_path: str, embedder: Any):
        self._embedder = embedder
        self._cache: Dict[str, List[float]] = {}  # ea_hex -> embedding
        self._cache_lock = threading.Lock()

        try:
            from ..config import CACHE_DIR
        except ImportError:
            try:
                from host.config import CACHE_DIR
            except ImportError:
                CACHE_DIR = os.path.join(os.path.expanduser("~"), ".local", "state", "ida-pro-mcp")

        self._db_path = db_path
        try:
            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            # Try to connect and execute a command to verify write access
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.close()
            self._init_db()
        except (sqlite3.OperationalError, OSError, PermissionError):
            h = hashlib.sha256(os.path.abspath(db_path).encode("utf-8")).hexdigest()[:16]
            fallback_dir = os.path.join(CACHE_DIR, "fallback_indexes")
            os.makedirs(fallback_dir, exist_ok=True)
            self._db_path = os.path.join(fallback_dir, f"{h}.embeddings.db")
            self._init_db()

        self._init_meta()
        try:
            if self.needs_rebuild(self._embedder):
                with closing(sqlite3.connect(self._db_path)) as rebuild_conn:
                    rebuild_conn.execute("PRAGMA journal_mode=WAL")
                    rebuild_conn.execute("BEGIN")
                    rebuild_conn.execute("DELETE FROM func_embeddings")
                    now = _now_iso()
                    base = {
                        "index_schema_version": str(self.INDEX_SCHEMA_VERSION),
                        "signature_extractor_version": "v1",
                        "anchor_set_hash": "",
                        "created_at": now,
                        "updated_at": now,
                        "source_idb_path": self._source_idb_path(),
                        "source_binary_path": "",
                        "source_fingerprint": self._source_fingerprint(),
                    }
                    base.update(self._embedder_meta_snapshot())
                    for k, v in base.items():
                        self._meta_set(rebuild_conn, k, v)
                    rebuild_conn.commit()
                self._cache.clear()
        except Exception as e:
            logger.exception("needs_rebuild transaction failed: %s", e)
            raise
        self._load_cache()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS func_embeddings (
                    ea       TEXT PRIMARY KEY,
                    name     TEXT,
                    dim      INTEGER,
                    vec_blob BLOB NOT NULL,
                    pseudo_hash TEXT,
                    indexed_at  REAL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fe_name ON func_embeddings(name)")
            # Additive migration for semantic provenance fields.
            cols = {str(row[1]) for row in conn.execute("PRAGMA table_info(func_embeddings)").fetchall()}
            if "source_kind" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN source_kind TEXT DEFAULT 'function'")
            if "source_hash" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN source_hash TEXT")
            if "signature_text" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN signature_text TEXT")
            if "signature_hash" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN signature_hash TEXT")
            conn.commit()

    def _meta_set(self, conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            """
            INSERT INTO embedding_meta(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (key, value),
        )

    def _meta_get(self, conn: sqlite3.Connection, key: str) -> Optional[str]:
        row = conn.execute("SELECT value FROM embedding_meta WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        return str(row[0])

    def _source_idb_path(self) -> str:
        p = self._db_path
        suffix = ".embeddings.db"
        if p.endswith(suffix):
            return p[: -len(suffix)]
        return p

    def _source_fingerprint(self) -> str:
        src = self._source_idb_path()
        if src and os.path.isfile(src):
            st = os.stat(src)
            return hashlib.sha256(f"{src}:{st.st_size}:{st.st_mtime_ns}".encode()).hexdigest()
        return hashlib.sha256(src.encode("utf-8")).hexdigest() if src else ""

    def _embedder_meta_snapshot(self) -> Dict[str, str]:
        backend = str(getattr(self._embedder, "backend", "unknown"))
        dim = str(getattr(self._embedder, "dim", 0) or 0)
        model_path = ""
        server_bin = ""
        try:
            status = getattr(self._embedder, "status", None)
            if callable(status):
                st = status(probe=False)
                model_path = str(st.get("model_path") or "")
                server_bin = str(st.get("server_bin") or "")
        except Exception:
            pass
        if not model_path:
            model_path = str(getattr(self._embedder, "_model_path", "") or "")
        if not server_bin:
            server_bin = str(getattr(self._embedder, "_server_bin", "") or "")
        model_size, _ = _safe_stat(model_path)
        server_size, _ = _safe_stat(server_bin)
        return {
            "embedding_backend": backend,
            "embedding_dim": dim,
            "model_path": model_path,
            "model_size": str(model_size),
            "model_sha256_head": _safe_file_head_sha256(model_path),
            "server_bin": server_bin,
            "server_size": str(server_size),
            "server_sha256_head": _safe_file_head_sha256(server_bin),
        }

    def _init_meta(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS embedding_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            now = _now_iso()
            base = {
                "index_schema_version": str(self.INDEX_SCHEMA_VERSION),
                "signature_extractor_version": "v1",
                "anchor_set_hash": "",
                "created_at": now,
                "updated_at": now,
                "source_idb_path": self._source_idb_path(),
                "source_binary_path": "",
                "source_fingerprint": self._source_fingerprint(),
            }
            base.update(self._embedder_meta_snapshot())
            for k, v in base.items():
                if self._meta_get(conn, k) is None:
                    self._meta_set(conn, k, v)
            self._meta_set(conn, "updated_at", now)
            conn.commit()

    def metadata(self) -> Dict[str, Any]:
        with self._conn() as conn:
            rows = conn.execute("SELECT key, value FROM embedding_meta").fetchall()
        out: Dict[str, Any] = {str(k): str(v) for k, v in rows}
        for key in ("index_schema_version", "embedding_dim", "model_size", "server_size"):
            if key in out:
                with suppress(Exception):
                    out[key] = int(out[key])
        return out

    def recent_functions(self, limit: int = 64) -> List[Dict[str, Any]]:
        """Return most recently indexed function refs for capsule snapshots."""
        rows: List[Dict[str, Any]] = []
        try:
            with self._conn() as conn:
                for row in conn.execute(
                    """
                    SELECT ea, name, indexed_at, signature_hash
                    FROM func_embeddings
                    ORDER BY indexed_at DESC
                    LIMIT ?
                    """,
                    (max(1, int(limit)),),
                ):
                    rows.append(
                        {
                            "ea": str(row[0]),
                            "name": str(row[1] or row[0]),
                            "indexed_at": row[2],
                            "signature_hash": str(row[3] or ""),
                        }
                    )
        except Exception:
            return []
        return rows

    def capsule_state(
        self,
        *,
        anchor_metadata: Optional[Dict[str, Any]] = None,
        thresholds: Optional[Dict[str, Any]] = None,
        recent_limit: int = 64,
    ) -> Dict[str, Any]:
        """Build a capsule-ready embedding state payload."""
        meta = self.metadata()
        model_head = str(meta.get("model_sha256_head") or "")
        index_metadata = {
            "implementation": "FunctionEmbeddingIndex",
            "db_path": self._db_path,
            "index_schema_version": int(meta.get("index_schema_version") or self.INDEX_SCHEMA_VERSION),
            "source_idb_path": str(meta.get("source_idb_path") or ""),
            "source_binary_path": str(meta.get("source_binary_path") or ""),
            "source_fingerprint": str(meta.get("source_fingerprint") or ""),
            "embedding_backend": str(meta.get("embedding_backend") or ""),
            "function_count": int(self.size),
            "updated_at": str(meta.get("updated_at") or _now_iso()),
        }
        return {
            "backend": str(meta.get("embedding_backend") or getattr(self._embedder, "backend", "unknown")),
            "model_path": str(meta.get("model_path") or ""),
            "model_hash": model_head,
            "embedding_dim": int(meta.get("embedding_dim") or getattr(self._embedder, "dim", 0) or 0),
            "index_metadata": index_metadata,
            "anchor_metadata": anchor_metadata or {},
            "last_indexed_functions": self.recent_functions(limit=recent_limit),
            "thresholds": thresholds or {},
            "created_at": str(meta.get("created_at") or _now_iso()),
            "updated_at": _now_iso(),
        }

    def verify_metadata(self, current_embedder: Any) -> Dict[str, Any]:
        stored = self.metadata()
        current_backend = str(getattr(current_embedder, "backend", "unknown"))
        current_dim = int(getattr(current_embedder, "dim", 0) or 0)
        current = {
            "embedding_backend": current_backend,
            "embedding_dim": current_dim,
        }
        mismatches: Dict[str, Dict[str, Any]] = {}
        if str(stored.get("embedding_backend", "")) != current_backend:
            mismatches["embedding_backend"] = {
                "stored": stored.get("embedding_backend"),
                "current": current_backend,
            }
        try:
            stored_dim = int(stored.get("embedding_dim", 0) or 0)
        except Exception:
            stored_dim = 0
        if stored_dim != current_dim:
            mismatches["embedding_dim"] = {"stored": stored_dim, "current": current_dim}
        return {
            "ok": not mismatches,
            "mismatches": mismatches,
            "stored": stored,
            "current": current,
        }

    def needs_rebuild(self, current_embedder: Any, source_fingerprint: str | None = None) -> bool:
        chk = self.verify_metadata(current_embedder)
        if chk["mismatches"]:
            return True
        if source_fingerprint is None:
            source_fingerprint = self._source_fingerprint()
        stored = chk.get("stored", {})
        return str(stored.get("source_fingerprint", "")) != str(source_fingerprint or "")

    def _load_cache(self) -> None:
        """Load all stored embeddings into RAM for fast cosine search."""
        from .helpers import unpack_floats
        try:
            with self._conn() as conn:
                for row in conn.execute("SELECT ea, vec_blob FROM func_embeddings"):
                    ea, blob = row
                    with self._cache_lock:
                        self._cache[ea] = unpack_floats(blob)
        except Exception:
            pass

    def _pack(self, vec: List[float]) -> bytes:
        from .helpers import pack_floats
        return pack_floats(vec)

    def _unpack(self, blob: bytes) -> List[float]:
        from .helpers import unpack_floats
        return unpack_floats(blob)

    def _phash(self, text: str) -> str:
        return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()[:16]

    def _row_meta_for_eas(self, eas: List[str]) -> Dict[str, Dict[str, Any]]:
        if not eas:
            return {}
        rows: Dict[str, Dict[str, Any]] = {}
        try:
            with self._conn() as conn:
                ph = ",".join("?" * len(eas))
                for row in conn.execute(
                    f"SELECT ea, name, signature_text, indexed_at FROM func_embeddings WHERE ea IN ({ph})",
                    eas,
                ):
                    rows[str(row[0])] = {
                        "name": str(row[1] or row[0]),
                        "signature_text": str(row[2] or ""),
                        "indexed_at": row[3],
                    }
        except Exception:
            return {}
        return rows

    def index(self, func_ea: str, name: str, pseudocode: str) -> None:
        """Embed and store a function. Skips if pseudocode unchanged."""
        ph = self._phash(pseudocode)
        signature_text = _extract_signature_text(pseudocode)
        signature_hash = self._phash(signature_text or pseudocode)
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT pseudo_hash, name, signature_hash, signature_text FROM func_embeddings WHERE ea=?",
                    (func_ea,),
                ).fetchone()
                if row and row[0] == ph:
                    stored_sig_hash = str(row[2] or "") if len(row) > 2 else ""
                    stored_sig_text = str(row[3] or "") if len(row) > 3 else ""
                    if row[1] == name and stored_sig_hash == signature_hash and stored_sig_text == signature_text:
                        return  # completely unchanged
                    conn.execute(
                        "UPDATE func_embeddings SET name=?, signature_text=?, signature_hash=?, indexed_at=? WHERE ea=?",
                        (name, signature_text, signature_hash, time.time(), func_ea),
                    )
                    self._meta_set(conn, "updated_at", _now_iso())
                    conn.commit()
                    return
        except Exception:
            pass

        vec = self._embedder.embed(pseudocode)
        blob = self._pack(vec)
        with self._cache_lock:
            self._cache[func_ea] = vec
        src_hash = hashlib.sha256(f"{func_ea}:{ph}".encode()).hexdigest()[:24]
        try:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO func_embeddings(
                        ea, name, dim, vec_blob, pseudo_hash, indexed_at, source_kind, source_hash, signature_text, signature_hash
                    )
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(ea) DO UPDATE SET
                        name=excluded.name,
                        dim=excluded.dim,
                        vec_blob=excluded.vec_blob,
                        pseudo_hash=excluded.pseudo_hash,
                        indexed_at=excluded.indexed_at,
                        source_kind=excluded.source_kind,
                        source_hash=excluded.source_hash,
                        signature_text=excluded.signature_text,
                        signature_hash=excluded.signature_hash
                    """,
                    (
                        func_ea,
                        name,
                        len(vec),
                        blob,
                        ph,
                        time.time(),
                        "function",
                        src_hash,
                        signature_text,
                        signature_hash,
                    ),
                )
                self._meta_set(conn, "updated_at", _now_iso())
                self._meta_set(conn, "source_fingerprint", self._source_fingerprint())
                for k, v in self._embedder_meta_snapshot().items():
                    self._meta_set(conn, k, v)
                conn.commit()
        except Exception:
            pass

    def index_async(self, func_ea: str, name: str, pseudocode: str) -> None:
        """Non-blocking index: fire-and-forget in background thread."""
        ph = self._phash(pseudocode)
        signature_text = _extract_signature_text(pseudocode)
        signature_hash = self._phash(signature_text or pseudocode)
        with self._cache_lock:
            cached_vec = self._cache.get(func_ea)
        if cached_vec is not None:
            # Check if we already have this exact pseudocode
            try:
                with self._conn() as conn:
                    row = conn.execute(
                        "SELECT pseudo_hash, name, signature_hash, signature_text FROM func_embeddings WHERE ea=?",
                        (func_ea,),
                    ).fetchone()
                    if row and row[0] == ph and row[1] == name and str(row[2] or "") == signature_hash and str(row[3] or "") == signature_text:
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
        with self._cache_lock:
            if not self._cache:
                return []
            snapshot = list(self._cache.items())
        scored: List[Tuple[float, str]] = []
        for ea, vec in snapshot:
            if ea == exclude_ea:
                continue
            sim = _cosine(query_vec, vec)
            if sim >= threshold:
                scored.append((sim, ea))
        scored.sort(reverse=True)
        if not scored:
            return []
        top_eas = [ea for _, ea in scored[:top_k]]
        meta = self._row_meta_for_eas(top_eas)
        return [
            {
                "ea": ea,
                "name": meta.get(ea, {}).get("name", ea),
                "similarity": round(sim, 4),
                "signature": _clip_signature(str(meta.get(ea, {}).get("signature_text") or "")),
            }
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
        with self._cache_lock:
            if not self._cache:
                return []
            cache_items = list(self._cache.items())
        q = self._embedder.embed(pseudocode)
        scored: List[Tuple[float, str]] = []
        for ea, vec in cache_items:
            if ea == exclude_ea:
                continue
            sim = _cosine(q, vec)
            if sim >= threshold:
                scored.append((sim, ea))
        scored.sort(reverse=True)
        if not scored:
            return []
        # Fetch names for top results
        top_eas = [ea for _, ea in scored[:top_k]]
        meta = self._row_meta_for_eas(top_eas)
        return [
            {
                "ea": ea,
                "name": meta.get(ea, {}).get("name", ea),
                "similarity": round(sim, 4),
                "signature": _clip_signature(str(meta.get(ea, {}).get("signature_text") or "")),
            }
            for sim, ea in scored[:top_k]
        ]

    def search_text(
        self,
        query: str,
        top_k: int = 10,
        threshold: float = 0.0,
        exclude_ea: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Rank indexed functions by lexical overlap over stored signatures and names."""
        q_norm = _normalize_search_text(query)
        q_tokens = set(_tokenize_search_text(query, max_tokens=48))
        if not q_norm and not q_tokens:
            return []

        raw_rows: List[Tuple[str, str, str, Any, set[str], str]] = []
        try:
            with self._conn() as conn:
                for row in conn.execute(
                    "SELECT ea, name, signature_text, indexed_at FROM func_embeddings"
                ):
                    ea = str(row[0])
                    if exclude_ea and ea == exclude_ea:
                        continue
                    name = str(row[1] or ea)
                    signature_text = str(row[2] or "")
                    blob = f"{name} {signature_text}".strip()
                    if not blob:
                        continue
                    raw_rows.append((ea, name, signature_text, row[3], set(_tokenize_search_text(blob, max_tokens=160)), blob))
        except Exception:
            return []

        idf = _idf_scores([r[4] for r in raw_rows])
        rows: List[Dict[str, Any]] = []
        try:
            for ea, name, signature_text, indexed_at, row_tokens, blob in raw_rows:
                if not row_tokens:
                    continue
                blob_norm = _normalize_search_text(blob)
                token_score, matched = _weighted_token_score(q_tokens, row_tokens, idf)
                exact = 1.0 if q_norm and q_norm in blob_norm else 0.0
                name_norm = name.lower()
                prefix = 0.35 if q_norm and (name_norm.startswith(q_norm) or any(tok.startswith(q_norm) for tok in row_tokens)) else 0.0
                name_bonus = 0.25 if q_tokens and q_tokens.issubset(row_tokens.intersection(set(_tokenize_search_text(name, max_tokens=64)))) else 0.0
                score = round((exact * 1.25) + token_score + prefix + name_bonus, 4)
                if score < float(threshold):
                    continue
                rows.append(
                    {
                        "ea": ea,
                        "name": name,
                        "score": score,
                        "exact_match": bool(exact),
                        "matched_tokens": matched,
                        "signature": _clip_signature(signature_text),
                        "indexed_at": indexed_at,
                    }
                )
        except Exception:
            return []

        rows.sort(
            key=lambda r: (
                float(r.get("score") or 0.0),
                len(r.get("matched_tokens") or []),
                float(r.get("indexed_at") or 0.0),
            ),
            reverse=True,
        )
        return rows[: max(1, int(top_k))]

    def hybrid_search(
        self,
        query: str,
        top_k: int = 10,
        threshold: float = 0.0,
        exclude_ea: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Blend semantic similarity with lexical signature overlap."""
        if not query:
            return []

        semantic_hits: List[Dict[str, Any]] = []
        lexical_hits = self.search_text(
            query,
            top_k=max(max(1, int(top_k)) * 6, 48),
            threshold=0.0,
            exclude_ea=exclude_ea,
        )
        try:
            query_text = _extract_signature_text(query, max_tokens=64) or str(query)
            query_vec = self._embedder.embed(query_text)
            semantic_hits = self.similar_vec(
                query_vec,
                top_k=max(max(1, int(top_k)) * 6, 48),
                exclude_ea=exclude_ea,
                threshold=0.0,
            )
        except Exception:
            semantic_hits = []

        sem_max = max((float(h.get("similarity") or 0.0) for h in semantic_hits), default=1.0) or 1.0
        lex_max = max((float(h.get("score") or 0.0) for h in lexical_hits), default=1.0) or 1.0
        merged: Dict[str, Dict[str, Any]] = {}

        for hit in semantic_hits:
            ea = str(hit.get("ea") or "")
            if not ea:
                continue
            merged[ea] = {
                "ea": ea,
                "name": hit.get("name") or ea,
                "similarity": round(float(hit.get("similarity") or 0.0), 4),
                "lexical_score": 0.0,
                "exact_match": False,
                "matched_tokens": [],
                "signature": hit.get("signature") or "",
            }

        for hit in lexical_hits:
            ea = str(hit.get("ea") or "")
            if not ea:
                continue
            row = merged.setdefault(
                ea,
                {
                    "ea": ea,
                    "name": hit.get("name") or ea,
                    "similarity": 0.0,
                    "lexical_score": 0.0,
                    "exact_match": False,
                    "matched_tokens": [],
                    "signature": hit.get("signature") or "",
                },
            )
            row["name"] = row.get("name") or hit.get("name") or ea
            row["lexical_score"] = round(max(float(row.get("lexical_score") or 0.0), float(hit.get("score") or 0.0)), 4)
            row["exact_match"] = bool(row.get("exact_match") or hit.get("exact_match"))
            row["matched_tokens"] = sorted(set(list(row.get("matched_tokens") or []) + list(hit.get("matched_tokens") or [])))[:12]
            if not row.get("signature"):
                row["signature"] = hit.get("signature") or ""

        q_tokens = set(_tokenize_search_text(query, max_tokens=48))
        ranked: List[Dict[str, Any]] = []
        for row in merged.values():
            sem_norm = float(row.get("similarity") or 0.0) / sem_max if sem_max > 0 else 0.0
            lex_norm = float(row.get("lexical_score") or 0.0) / lex_max if lex_max > 0 else 0.0
            exact_bonus = 0.12 if row.get("exact_match") else 0.0
            matched = set(row.get("matched_tokens") or [])
            token_coverage = len(q_tokens.intersection(matched)) / max(1, len(q_tokens)) if q_tokens else 0.0
            score = (0.54 * sem_norm) + (0.38 * lex_norm) + (0.08 * token_coverage) + exact_bonus
            row["score"] = round(score, 4)
            row["rank_reason"] = {
                "semantic": round(sem_norm, 4),
                "lexical": round(lex_norm, 4),
                "token_coverage": round(token_coverage, 4),
                "exact": bool(row.get("exact_match")),
            }
            if float(row.get("score") or 0.0) >= float(threshold):
                ranked.append(row)

        ranked.sort(
            key=lambda r: (
                float(r.get("score") or 0.0),
                float(r.get("similarity") or 0.0),
                float(r.get("lexical_score") or 0.0),
            ),
            reverse=True,
        )
        return ranked[: max(1, int(top_k))]

    def search(
        self,
        query_or_vec: Any,
        top_k: int = 10,
        threshold: float = 0.0,
        exclude_ea: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Compatibility entrypoint for semantic or hybrid function search."""
        if isinstance(query_or_vec, (list, tuple)):
            try:
                vec = [float(v) for v in query_or_vec]
            except Exception:
                return []
            return self.similar_vec(vec, top_k=top_k, exclude_ea=exclude_ea, threshold=threshold)
        return self.hybrid_search(str(query_or_vec or ""), top_k=top_k, threshold=threshold, exclude_ea=exclude_ea)

    def cache_store(self, ea: str, vec: List[float]) -> None:
        with self._cache_lock:
            self._cache[ea] = vec

    def cache_snapshot(self) -> List[Tuple[str, List[float]]]:
        with self._cache_lock:
            return list(self._cache.items())

    def cache_keys(self) -> set:
        with self._cache_lock:
            return set(self._cache.keys())

    @property
    def size(self) -> int:
        with self._cache_lock:
            return len(self._cache)

