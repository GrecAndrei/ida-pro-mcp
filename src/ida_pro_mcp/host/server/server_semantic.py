"""
Server semantic-index and gadget discovery helpers.

Extracted from host/server.py to keep the main server class smaller and make the
semantic index logic easier to navigate.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import sqlite3
import struct
import time
from typing import Any

from ..config import (
    EMBEDDING_FIRST_MODE,
    SEMANTIC_GADGET_SOURCE_ACTIONS,
    SEMANTIC_INDEX_DB_NAME,
    SEMANTIC_INDEX_SOURCE_LIMIT,
    SEMANTIC_INDEX_VERSION,
    SEMANTIC_INDEX_WAIT_SECONDS,
    _bounded_int,
    _coerce_bool,
    _parse_str_list,
)
from ..errors import MCPError, is_error_result, make_error
from .session import Session

# Query-time row-vector memoization: norm_text -> embedding vector. Repeated
# semantic_find queries re-embed each row only once ever (not once per query);
# vectors are best-effort persisted into the SQLite index (vector BLOB column)
# so the cache also survives process restarts. Thread-safety comes from the
# GIL for dict get/set; a benign duplicate compute on a cache miss is fine.
_GADGET_VEC_CACHE: dict[str, list[float]] = {}


def _pack_vector(vec: list[float]) -> bytes | None:
    """Pack an embedding vector into a compact BLOB (or None when unusable)."""
    if not vec:
        return None
    try:
        return struct.pack(f"<{len(vec)}f", *[float(v) for v in vec])
    except Exception:
        return None


def _unpack_vector(blob) -> list[float] | None:
    """Unpack a stored vector BLOB back into a list of floats (or None)."""
    if not blob:
        return None
    try:
        count = len(blob) // 4
        if count == 0 or count * 4 != len(blob):
            return None
        return list(struct.unpack(f"<{count}f", blob))
    except Exception:
        return None


class ServerSemanticMixin:
    """Mixin for semantic gadget indexing and retrieval."""

    def _semantic_index_db_path(self, session_id: str) -> str:
        """Return the per-session SQLite path used for semantic gadget indexing."""
        artifact_dir = self.session_mgr.get_session_artifact_dir(session_id, create=True)
        return os.path.join(artifact_dir, SEMANTIC_INDEX_DB_NAME)

    def _semantic_index_fingerprint(self, session: Session) -> str:
        """Build a stable content/version fingerprint used to validate cached indexes."""
        hasher = hashlib.sha256()
        hasher.update(struct.pack(">I", SEMANTIC_INDEX_VERSION))
        for path in (session.idb_path, session.binary_path):
            raw = str(path or "")
            hasher.update(raw.encode("utf-8", errors="ignore"))
            try:
                st = os.stat(raw)
                hasher.update(struct.pack(">Q", int(st.st_size)))
                hasher.update(struct.pack(">Q", int(st.st_mtime_ns)))
            except OSError:
                hasher.update(struct.pack(">Q", 0))
                hasher.update(struct.pack(">Q", 0))
        return hasher.hexdigest()

    def _semantic_index_connect(self, db_path: str) -> sqlite3.Connection:
        """Open a tuned SQLite connection for semantic gadget index reads/writes."""
        conn = sqlite3.connect(db_path, timeout=max(1.0, SEMANTIC_INDEX_WAIT_SECONDS))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _semantic_index_ensure_schema(self, conn: sqlite3.Connection) -> None:
        """Create semantic index schema objects if they do not exist yet."""
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS gadgets (
                source_action TEXT NOT NULL,
                addr TEXT NOT NULL,
                insns INTEGER NOT NULL,
                gadget TEXT NOT NULL,
                norm_text TEXT NOT NULL,
                tokens TEXT NOT NULL,
                digest BLOB NOT NULL,
                vector BLOB,
                PRIMARY KEY (source_action, addr, digest)
            );
            CREATE INDEX IF NOT EXISTS idx_gadgets_source_action ON gadgets(source_action);
            """
        )
        # Indexes built before the vector BLOB column existed lack it; add it
        # best-effort so row-vector memoization survives restarts on those DBs.
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("ALTER TABLE gadgets ADD COLUMN vector BLOB")

    def _semantic_index_meta(self, conn: sqlite3.Connection) -> dict[str, str]:
        """Read semantic index metadata as a flat key/value map."""
        rows = conn.execute("SELECT key, value FROM meta").fetchall()
        return {str(k): str(v) for k, v in rows}

    def _semantic_index_put_meta(self, conn: sqlite3.Connection, meta: dict[str, Any]) -> None:
        """Replace semantic index metadata with the supplied values."""
        conn.execute("DELETE FROM meta")
        conn.executemany(
            "INSERT INTO meta(key, value) VALUES(?, ?)",
            [(str(k), str(v)) for k, v in meta.items()],
        )

    def _semantic_extract_gadget_rows(
        self, payload: Any
    ) -> list[tuple[str, int, str]]:
        """Extract normalized (addr, insns, gadget text) rows from gadget tool payloads."""
        rows: list[tuple[str, int, str]] = []
        if not isinstance(payload, dict):
            return rows
        gadgets = payload.get("gadgets")
        if not isinstance(gadgets, list):
            return rows
        for item in gadgets:
            if not isinstance(item, dict):
                continue
            addr = str(item.get("addr") or "").strip()
            text = str(item.get("gadget") or "").strip()
            if not addr or not text:
                continue
            insns = _bounded_int(item.get("insns", 0), 0, min_value=0, max_value=4096)
            rows.append((addr, insns, text))
        return rows

    def _semantic_index_rebuild(
        self,
        session: Session,
        source_actions: list[str],
        source_limit: int,
        max_insns: int,
    ) -> dict[str, Any]:
        """Rebuild and persist the semantic gadget index for a session."""
        db_path = self._semantic_index_db_path(session.session_id)
        fingerprint = self._semantic_index_fingerprint(session)
        indexed_rows: list[tuple[str, str, int, str, str, str, bytes, bytes | None]] = []
        errors: list[dict[str, Any]] = []
        for source_action in source_actions:
            result = self.call_tool(
                "gadgets",
                session.idb_path,
                action=source_action,
                limit=source_limit,
                max_insns=max_insns,
            )
            if isinstance(result, dict) and is_error_result(result):
                errors.append(
                    {
                        "action": source_action,
                        "code": result.get("code"),
                        "message": result.get("message") or result.get("error"),
                    }
                )
                continue
            if not isinstance(result, dict) or not isinstance(result.get("gadgets"), list):
                # A tool response the extractor cannot use (non-dict, or missing
                # the 'gadgets' list) must surface as a per-action error rather
                # than silently indexing zero rows — which would make a broken
                # source action look like "this gadget class does not exist".
                errors.append(
                    {
                        "action": source_action,
                        "code": MCPError.INTERNAL,
                        "message": "gadgets tool returned no usable 'gadgets' list",
                    }
                )
                continue
            for addr, insns, gadget_text in self._semantic_extract_gadget_rows(
                result
            ):
                norm_text = re.sub(r"\s+", " ", gadget_text.lower()).strip()
                tokens = sorted(set(re.findall(r"[a-z0-9_]+", norm_text)))
                token_blob = ",".join(tokens)
                digest = hashlib.sha256(
                    struct.pack(">I", int(insns))
                    + source_action.encode("utf-8", errors="ignore")
                    + b"\0"
                    + addr.encode("utf-8", errors="ignore")
                    + b"\0"
                    + gadget_text.encode("utf-8", errors="ignore")
                ).digest()
                indexed_rows.append(
                    (
                        source_action,
                        addr,
                        int(insns),
                        gadget_text,
                        norm_text,
                        token_blob,
                        digest,
                        # Best-effort: persist any embedding already computed for
                        # this row in the module cache. New embeddings are never
                        # computed here — that would make a rebuild synchronously
                        # re-embed the whole gadget corpus.
                        _pack_vector(_GADGET_VEC_CACHE.get(norm_text)),
                    )
                )

        if not indexed_rows and errors:
            first_error = errors[0]
            return make_error(
                str(first_error.get("code") or MCPError.INTERNAL),
                str(first_error.get("message") or "Semantic gadget index rebuild failed"),
                details={
                    "source_actions": source_actions,
                    "errors": errors,
                    "db_path": db_path,
                },
            )

        with self._semantic_index_lock:
            conn = self._semantic_index_connect(db_path)
            try:
                self._semantic_index_ensure_schema(conn)
                conn.execute("DELETE FROM gadgets")
                if indexed_rows:
                    conn.executemany(
                        """
                        INSERT OR IGNORE INTO gadgets(
                            source_action, addr, insns, gadget, norm_text, tokens, digest, vector
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        indexed_rows,
                    )
                self._semantic_index_put_meta(
                    conn,
                    {
                        "version": str(SEMANTIC_INDEX_VERSION),
                        "fingerprint": fingerprint,
                        "built_at": str(int(time.time())),
                        "source_actions": ",".join(source_actions),
                        "source_limit": str(source_limit),
                        "max_insns": str(max_insns),
                    },
                )
                conn.commit()
            finally:
                conn.close()
        return {
            "ok": True,
            "db_path": db_path,
            "fingerprint": fingerprint,
            "rows_indexed": len(indexed_rows),
            "errors": errors,
        }

    def _handle_gadgets_semantic_find(self, args: dict) -> dict:
        """Handle gadgets(action='semantic_find') using a cached per-session index."""
        query = str(args.get("query") or "").strip()
        if not query:
            return make_error(MCPError.INVALID_ARGS, "query required")
        source_actions = _parse_str_list(args.get("source_actions"))
        if not source_actions:
            source_actions = list(SEMANTIC_GADGET_SOURCE_ACTIONS)
        source_actions = [str(a).strip() for a in source_actions if str(a).strip()]
        source_actions = list(dict.fromkeys(source_actions))
        invalid_actions = [
            a for a in source_actions if a not in set(SEMANTIC_GADGET_SOURCE_ACTIONS)
        ]
        if invalid_actions:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Unsupported semantic source action(s): {', '.join(invalid_actions)}",
                hint=(
                    "Use source_actions from: "
                    + ", ".join(SEMANTIC_GADGET_SOURCE_ACTIONS)
                ),
            )
        limit = _bounded_int(args.get("limit", 50), 50, min_value=1, max_value=2000)
        offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=200000)
        min_score = _bounded_int(args.get("min_score", 1), 1, min_value=0, max_value=1000)
        source_limit = _bounded_int(
            args.get("source_limit", SEMANTIC_INDEX_SOURCE_LIMIT),
            SEMANTIC_INDEX_SOURCE_LIMIT,
            min_value=50,
            max_value=100000,
        )
        max_insns = _bounded_int(args.get("max_insns", 6), 6, min_value=2, max_value=32)

        idb_ref = args.get("idb")
        if idb_ref is None and self.current_session:
            idb_ref = self.current_session.idb_path
        session = self._resolve_session_from_idb_ref(idb_ref)
        if not session:
            return make_error(
                MCPError.SESSION_REQUIRED,
                "No active session. Create one first with: ida_open_binary(binary_path='path/to/binary')",
            )
        # A cached index is per-session and unencrypted; a connection must never
        # read another connection's session's gadget rows. This guard also runs
        # before _semantic_index_db_path, so a foreign session's artifact dir is
        # not created as a side effect either. (The rebuild path already goes
        # through call_tool, which applies the same guard.)
        ownership_error = self._ensure_client_owns_session(session)
        if ownership_error:
            return ownership_error

        db_path = self._semantic_index_db_path(session.session_id)
        wanted_fingerprint = self._semantic_index_fingerprint(session)
        rebuild_index = _coerce_bool(args.get("rebuild_index"), False) or not os.path.exists(
            db_path
        )
        index_meta: dict[str, str] = {}

        with self._semantic_index_lock:
            if not rebuild_index:
                conn = self._semantic_index_connect(db_path)
                try:
                    self._semantic_index_ensure_schema(conn)
                    index_meta = self._semantic_index_meta(conn)
                finally:
                    conn.close()
                rebuild_index = (
                    index_meta.get("version") != str(SEMANTIC_INDEX_VERSION)
                    or index_meta.get("fingerprint") != wanted_fingerprint
                    or index_meta.get("source_actions", "")
                    != ",".join(source_actions)
                    or index_meta.get("source_limit") != str(source_limit)
                    or index_meta.get("max_insns") != str(max_insns)
                )

        rebuild_info = None
        if rebuild_index:
            # Single-flight: hold the (reentrant) index lock across the whole
            # rebuild so two concurrent semantic_find calls that both see a
            # stale/missing index cannot each rebuild (double embedding + a
            # DELETE/re-INSERT race). The rebuild itself re-acquires the lock
            # for its DB write, which is fine for an RLock.
            with self._semantic_index_lock:
                rebuild_info = self._semantic_index_rebuild(
                    session, source_actions, source_limit, max_insns
                )
            if is_error_result(rebuild_info):
                return rebuild_info

        with self._semantic_index_lock:
            conn = self._semantic_index_connect(db_path)
            try:
                self._semantic_index_ensure_schema(conn)
                index_meta = self._semantic_index_meta(conn)
                placeholders = ",".join("?" for _ in source_actions)
                rows = conn.execute(
                    f"""
                    SELECT source_action, addr, insns, gadget, norm_text, tokens, vector
                    FROM gadgets
                    WHERE source_action IN ({placeholders})
                    """,
                    tuple(source_actions),
                ).fetchall()
            finally:
                conn.close()

        min_similarity = max(0.0, min(1.0, float(min_score) / 1000.0))
        query_lower = query.lower()
        query_tokens = set(re.findall(r"[a-z0-9_]+", query_lower))

        ranked: list[tuple[float, tuple[Any, Any, Any, Any, Any, Any, Any]]] = []
        query_vec: list[float] | None = None
        embedder = None
        if EMBEDDING_FIRST_MODE:
            try:
                from ..intelligence.core import BgeCodeEmbedder
                embedder = BgeCodeEmbedder()
                query_vec = embedder.embed_vector(query)
                # Warm the module cache from vectors persisted by a previous
                # process, so the first query after a restart does not re-embed
                # the whole gadget corpus.
                if rows:
                    for row in rows:
                        norm_text = str(row[4] or "")
                        if not norm_text or norm_text in _GADGET_VEC_CACHE:
                            continue
                        stored = _unpack_vector(row[6])
                        if stored is not None:
                            _GADGET_VEC_CACHE[norm_text] = stored
            except Exception:
                # Embedding is best-effort: fall through to token matching.
                embedder = None
                query_vec = None
        for row in rows:
            norm_text = str(row[4] or "")
            sim = 0.0
            if embedder is not None and query_vec is not None and norm_text:
                try:
                    row_vec = _GADGET_VEC_CACHE.get(norm_text)
                    if row_vec is None:
                        row_vec = embedder.embed_vector(norm_text)
                        if row_vec is None:
                            raise RuntimeError("embedding unavailable")
                        _GADGET_VEC_CACHE[norm_text] = row_vec
                    sim = float(embedder.cosine(query_vec, row_vec))
                except Exception:
                    sim = 0.0
            elif embedder is None or query_vec is None:
                token_blob = str(row[5] or "")
                row_tokens = set(token_blob.split(",")) if token_blob else set()
                inter = len(query_tokens.intersection(row_tokens))
                union = len(query_tokens.union(row_tokens)) if row_tokens else len(query_tokens)
                sim = (float(inter) / float(max(1, union))) if union else 0.0
            if sim >= min_similarity:
                ranked.append((sim, row))

        def _rank_sort_key(
            item: tuple[float, tuple[Any, Any, Any, Any, Any, Any, Any]]
        ) -> tuple[float, str, str]:
            sim, row = item
            source_action = str(row[0] or "")
            addr = str(row[1] or "")
            return (-sim, source_action, addr)

        ranked.sort(key=_rank_sort_key)
        total = len(ranked)
        page = ranked[offset : offset + limit]
        matches = [
            {
                "source_action": str(row[0]),
                "addr": str(row[1]),
                "insns": int(row[2]),
                "gadget": str(row[3]),
                "score": int(round(sim * 1000)),
                "similarity": round(sim, 4),
            }
            for sim, row in page
        ]
        truncated = (offset + len(matches)) < total
        out = {
            "ok": True,
            "action": "semantic_find",
            "query": query,
            "matches": matches,
            "count": len(matches),
            "total": total,
            "offset": offset,
            "truncated": truncated,
            "next_offset": (offset + len(matches)) if truncated else None,
            "index": {
                "version": index_meta.get("version"),
                "fingerprint": index_meta.get("fingerprint"),
                "source_actions": source_actions,
                "db_path": db_path,
            },
        }
        if rebuild_info:
            out["index_refresh"] = {
                "rows_indexed": rebuild_info.get("rows_indexed", 0),
                "errors": rebuild_info.get("errors", []),
            }
            out["note"] = (
                "Semantic index was rebuilt for this query and can take a while; "
                "subsequent queries reuse the cached index."
            )
        return out
