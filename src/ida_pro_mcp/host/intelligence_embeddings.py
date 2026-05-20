"""Embedding index storage helpers for intelligence core."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


def _cosine(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


class FunctionEmbeddingIndex:
    """
    Stores 1536-dim float32 embeddings of decompiled functions,
    one SQLite database per binary (<idb_path>.embeddings.db).

    Replaces MbaGCN (untrained random SSM) and TurboQuant (quantization
    of tabular features it was never designed for).
    """

    def __init__(self, db_path: str, embedder: Any):
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
