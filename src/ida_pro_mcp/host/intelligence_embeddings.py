"""Embedding index storage helpers for intelligence core."""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def _cosine(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


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
        self._db_path = db_path
        self._embedder = embedder
        self._cache: Dict[str, List[float]] = {}  # ea_hex -> embedding
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._init_db()
        self._init_meta()
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
            return hashlib.sha256(f"{src}:{st.st_size}:{st.st_mtime_ns}".encode("utf-8")).hexdigest()
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
                try:
                    out[key] = int(out[key])
                except Exception:
                    pass
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
        sig_hash = self._phash(pseudocode)
        src_hash = hashlib.sha256(f"{func_ea}:{sig_hash}".encode("utf-8")).hexdigest()[:24]
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
                        None,
                        sig_hash,
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
        # Snapshot to avoid RuntimeError if background thread writes to _cache while we iterate.
        try:
            snapshot = list(self._cache.items())
        except RuntimeError:
            return []
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
            sim = _cosine(q, vec)
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
                    top_eas,
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


@dataclass
class SemanticObject:
    kind: str
    stable_ref: str
    title: str
    text: str
    metadata: dict


class SemanticObjectIndex:
    """
    Generic semantic object index for mixed object kinds (function/gadget/etc).
    Stored in SQLite with optional vector search using the configured embedder.
    """

    INDEX_SCHEMA_VERSION = 1
    _TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")

    def __init__(self, db_path: str, embedder: Any):
        self._db_path = db_path
        self._embedder = embedder
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _pack(self, vec: List[float]) -> bytes:
        return struct.pack(f"{len(vec)}f", *vec)

    def _unpack(self, blob: bytes) -> List[float]:
        n = len(blob) // 4
        return list(struct.unpack(f"{n}f", blob))

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS semantic_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS semantic_objects (
                    kind TEXT NOT NULL,
                    stable_ref TEXT NOT NULL,
                    title TEXT NOT NULL,
                    text TEXT NOT NULL,
                    norm_text TEXT NOT NULL,
                    tokens TEXT NOT NULL,
                    vec_blob BLOB,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (kind, stable_ref)
                );

                CREATE INDEX IF NOT EXISTS idx_semantic_kind ON semantic_objects(kind);
                """
            )
            conn.execute(
                """
                INSERT INTO semantic_meta(key, value) VALUES('index_schema_version', ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (str(self.INDEX_SCHEMA_VERSION),),
            )
            conn.commit()

    def _tokenize(self, text: str) -> List[str]:
        return sorted(set(self._TOKEN_RE.findall((text or "").lower())))

    def upsert_object(self, obj: SemanticObject) -> None:
        text = obj.text or ""
        norm = re.sub(r"\s+", " ", text.lower()).strip()
        tokens = ",".join(self._tokenize(text))
        vec_blob = None
        try:
            vec_blob = self._pack(self._embedder.embed(text))
        except Exception:
            vec_blob = None
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO semantic_objects(
                    kind, stable_ref, title, text, norm_text, tokens, vec_blob, metadata_json, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(kind, stable_ref) DO UPDATE SET
                    title=excluded.title,
                    text=excluded.text,
                    norm_text=excluded.norm_text,
                    tokens=excluded.tokens,
                    vec_blob=excluded.vec_blob,
                    metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at
                """,
                (
                    obj.kind,
                    obj.stable_ref,
                    obj.title or obj.stable_ref,
                    text,
                    norm,
                    tokens,
                    vec_blob,
                    json_dumps_safe(obj.metadata or {}),
                    time.time(),
                ),
            )
            conn.commit()

    def search_text(
        self,
        query: str,
        kind: Optional[str] = None,
        top_k: int = 10,
        threshold: float = 0.0,
    ) -> List[Dict[str, Any]]:
        q_tokens = set(self._tokenize(query))
        if not q_tokens:
            return []
        params: List[Any] = []
        sql = "SELECT kind, stable_ref, title, text, tokens, metadata_json FROM semantic_objects"
        if kind:
            sql += " WHERE kind=?"
            params.append(kind)
        rows: List[Dict[str, Any]] = []
        with self._conn() as conn:
            for row in conn.execute(sql, tuple(params)):
                row_tokens = set(str(row[4] or "").split(",")) if row[4] else set()
                if not row_tokens:
                    continue
                overlap = len(q_tokens.intersection(row_tokens))
                score = overlap / max(1, len(q_tokens))
                if score < float(threshold):
                    continue
                rows.append(
                    {
                        "kind": str(row[0]),
                        "stable_ref": str(row[1]),
                        "title": str(row[2]),
                        "score": round(score, 4),
                        "metadata": json_loads_safe(str(row[5] or "{}")),
                    }
                )
        rows.sort(key=lambda r: r["score"], reverse=True)
        return rows[: max(1, int(top_k))]

    def search_vec(
        self,
        query_vec: List[float],
        kind: Optional[str] = None,
        top_k: int = 10,
        threshold: float = 0.4,
    ) -> List[Dict[str, Any]]:
        params: List[Any] = []
        sql = "SELECT kind, stable_ref, title, vec_blob, metadata_json FROM semantic_objects WHERE vec_blob IS NOT NULL"
        if kind:
            sql += " AND kind=?"
            params.append(kind)
        rows: List[Dict[str, Any]] = []
        with self._conn() as conn:
            for row in conn.execute(sql, tuple(params)):
                blob = bytes(row[3]) if row[3] is not None else b""
                if not blob:
                    continue
                vec = self._unpack(blob)
                score = _cosine(query_vec, vec)
                if score < float(threshold):
                    continue
                rows.append(
                    {
                        "kind": str(row[0]),
                        "stable_ref": str(row[1]),
                        "title": str(row[2]),
                        "similarity": round(float(score), 4),
                        "metadata": json_loads_safe(str(row[4] or "{}")),
                    }
                )
        rows.sort(key=lambda r: r["similarity"], reverse=True)
        return rows[: max(1, int(top_k))]

    def semantic_search(
        self,
        query: str,
        kind: Optional[str] = None,
        top_k: int = 10,
        threshold: float = 0.4,
    ) -> List[Dict[str, Any]]:
        try:
            qvec = self._embedder.embed(query)
            rows = self.search_vec(qvec, kind=kind, top_k=top_k, threshold=threshold)
            if rows:
                return rows
        except Exception:
            pass
        return self.search_text(query, kind=kind, top_k=top_k, threshold=max(0.0, threshold / 2.0))

    @property
    def size(self) -> int:
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM semantic_objects").fetchone()
        return int(row[0] if row else 0)


def json_dumps_safe(value: Any) -> str:
    import json

    try:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    except Exception:
        return "{}"


def json_loads_safe(raw: str) -> dict:
    import json

    try:
        out = json.loads(raw)
        return out if isinstance(out, dict) else {}
    except Exception:
        return {}
