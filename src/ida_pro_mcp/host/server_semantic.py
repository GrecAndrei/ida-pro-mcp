"""
Server semantic-index and gadget discovery helpers.

Extracted from host/server.py to keep the main server class smaller and make the
semantic index logic easier to navigate.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import struct
import time
from typing import Any, List, Optional

from .config import (
    _bounded_int,
    _coerce_bool,
    EMBEDDING_FIRST_MODE,
    SEMANTIC_GADGET_SOURCE_ACTIONS,
    SEMANTIC_INDEX_DB_NAME,
    SEMANTIC_INDEX_SOURCE_LIMIT,
    SEMANTIC_INDEX_VERSION,
    SEMANTIC_INDEX_WAIT_SECONDS,
    _parse_str_list,
)
from .errors import MCPError, make_error


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
                PRIMARY KEY (source_action, addr, digest)
            );
            CREATE INDEX IF NOT EXISTS idx_gadgets_source_action ON gadgets(source_action);
            """
        )

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
        self, action: str, payload: Any
    ) -> list[tuple[str, int, str]]:
        """Extract normalized (addr, insns, gadget text) rows from gadget tool payloads."""
        rows: list[tuple[str, int, str]] = []
        if not isinstance(payload, dict):
            return rows
        gadgets = payload.get("gadgets")
        if isinstance(gadgets, list):
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
        if action == "pivot_chains":
            categories = payload.get("categories")
            if not isinstance(categories, dict):
                return rows
            for cat_payload in categories.values():
                if not isinstance(cat_payload, dict):
                    continue
                cat_gadgets = cat_payload.get("gadgets")
                if not isinstance(cat_gadgets, list):
                    continue
                for item in cat_gadgets:
                    if not isinstance(item, dict):
                        continue
                    addr = str(item.get("addr") or "").strip()
                    text = str(item.get("gadget") or "").strip()
                    if not addr or not text:
                        continue
                    insns = _bounded_int(
                        item.get("insns", 0), 0, min_value=0, max_value=4096
                    )
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
        indexed_rows: list[tuple[str, str, int, str, str, str, bytes]] = []
        errors: list[dict[str, Any]] = []
        for source_action in source_actions:
            result = self.call_tool(
                "gadgets",
                session.idb_path,
                action=source_action,
                limit=source_limit,
                max_insns=max_insns,
            )
            if isinstance(result, dict) and result.get("error"):
                errors.append(
                    {
                        "action": source_action,
                        "code": result.get("code"),
                        "message": result.get("message") or result.get("error"),
                    }
                )
                continue
            for addr, insns, gadget_text in self._semantic_extract_gadget_rows(
                source_action, result
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
                    )
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
                            source_action, addr, insns, gadget, norm_text, tokens, digest
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
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
                "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
            )

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
            rebuild_info = self._semantic_index_rebuild(
                session, source_actions, source_limit, max_insns
            )

        with self._semantic_index_lock:
            conn = self._semantic_index_connect(db_path)
            try:
                self._semantic_index_ensure_schema(conn)
                index_meta = self._semantic_index_meta(conn)
                placeholders = ",".join("?" for _ in source_actions)
                rows = conn.execute(
                    f"""
                    SELECT source_action, addr, insns, gadget, norm_text, tokens
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

        ranked: list[tuple[float, tuple[Any, Any, Any, Any, Any, Any]]] = []
        embedding_failed = False
        query_vec: Optional[List[float]] = None
        embedder = None
        if EMBEDDING_FIRST_MODE:
            try:
                from .intelligence_core import BgeCodeEmbedder
                embedder = BgeCodeEmbedder()
                query_vec = embedder.embed(query)
            except Exception:
                embedding_failed = True
        for row in rows:
            norm_text = str(row[4] or "")
            sim = 0.0
            if embedder is not None and query_vec is not None and norm_text:
                try:
                    row_vec = embedder.embed(norm_text)
                    sim = float(embedder.cosine(query_vec, row_vec))
                except Exception:
                    sim = 0.0
            elif not embedding_failed:
                token_blob = str(row[5] or "")
                row_tokens = set(token_blob.split(",")) if token_blob else set()
                inter = len(query_tokens.intersection(row_tokens))
                union = len(query_tokens.union(row_tokens)) if row_tokens else len(query_tokens)
                sim = (float(inter) / float(max(1, union))) if union else 0.0
            if sim >= min_similarity:
                ranked.append((sim, row))

        def _rank_sort_key(
            item: tuple[float, tuple[Any, Any, Any, Any, Any, Any]]
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
        return out
