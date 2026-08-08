"""Persistent cross-session symbol knowledge database."""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
import time
from typing import Any


def _data_root() -> str:
    xdg = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.environ.get("IDA_MCP_CACHE_DIR") or os.environ.get("IDA_MCP_DATA_DIR") or os.path.join(xdg, "ida-pro-mcp")


def _default_db_path() -> str:
    root = _data_root()
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, "symbol_kb.db")


def _confine_db_path(db_path: str) -> str:
    """Confine a caller-supplied symbol DB path to the trusted data root.

    Mirrors the memory-tool filesystem sandbox: directories are only ever
    created inside the data root, and ``..`` traversal is rejected. An
    out-of-root path is accepted only when its parent already exists (opening
    an existing shared DB, or creating a new DB in an existing directory) — a
    read-tier call must never fabricate directories anywhere on the host.
    """
    root = os.path.realpath(_data_root())
    raw = str(db_path).strip()
    if not raw:
        return _default_db_path()
    expanded = os.path.expanduser(raw)
    candidate = os.path.realpath(expanded) if os.path.isabs(expanded) else os.path.realpath(os.path.join(root, expanded))
    if ".." in expanded.split(os.sep):
        raise ValueError(f"symbol db_path must not contain '..': {db_path!r}")
    if candidate == root or candidate.startswith(root + os.sep):
        os.makedirs(os.path.dirname(candidate) or root, exist_ok=True)
        return candidate
    parent = os.path.dirname(candidate)
    if not os.path.isdir(parent):
        raise ValueError(
            f"symbol db_path is outside the data root and its parent does not exist: {candidate!r}"
        )
    return candidate


class SymbolDB:
    _initialized_paths = set()
    # Guards _initialized_paths across concurrent SymbolDB() constructions;
    # without it two threads can race both calling _init_db on a fresh DB.
    _init_lock = threading.Lock()

    def __init__(self, db_path: str | None = None):
        self.db_path = _confine_db_path(db_path or _default_db_path())
        with SymbolDB._init_lock:
            if (
                self.db_path not in SymbolDB._initialized_paths
                or not os.path.exists(self.db_path)
                or os.path.getsize(self.db_path) == 0
            ):
                self._init_db()
                SymbolDB._initialized_paths.add(self.db_path)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        conn = self._conn()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS symbols (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    symbol_name TEXT NOT NULL,
                    source_session TEXT,
                    source_binary TEXT,
                    source_addr TEXT,
                    chip_family TEXT,
                    fingerprint TEXT NOT NULL,
                    callgraph_hash TEXT,
                    strings_json TEXT DEFAULT '[]',
                    embedding_json TEXT,
                    confidence REAL DEFAULT 1.0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(symbol_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_symbols_fp ON symbols(fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_symbols_chip ON symbols(chip_family)")
            # Enforce uniqueness so concurrent upserts cannot both SELECT-miss
            # and INSERT duplicate rows for the same (symbol_name, fingerprint).
            # A legacy DB may already hold duplicates; merge them first.
            try:
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_symbols_uniq ON symbols(symbol_name, fingerprint)"
                )
            except sqlite3.IntegrityError:
                conn.execute(
                    """
                    DELETE FROM symbols
                    WHERE id NOT IN (
                        SELECT MAX(id) FROM symbols GROUP BY symbol_name, fingerprint
                    )
                    """
                )
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_symbols_uniq ON symbols(symbol_name, fingerprint)"
                )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hypotheses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    binary_hash TEXT NOT NULL,
                    chip_family TEXT,
                    addr_offset INTEGER NOT NULL,
                    hypothesis_text TEXT NOT NULL,
                    confidence REAL DEFAULT 0.8,
                    source_session TEXT,
                    source_binary TEXT,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hyp_hash ON hypotheses(binary_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hyp_chip ON hypotheses(chip_family)")
            conn.commit()
        finally:
            conn.close()

    def _update_symbol(self, conn: sqlite3.Connection, row_id: int, payload: dict[str, Any], now: float) -> int:
        conn.execute(
            """
            UPDATE symbols
            SET updated_at=?, source_session=?, source_binary=?, source_addr=?, chip_family=?,
                callgraph_hash=?, strings_json=?, embedding_json=?, confidence=?
            WHERE id=?
            """,
            (
                now,
                payload["source_session"],
                payload["source_binary"],
                payload["source_addr"],
                payload["chip_family"],
                payload["callgraph_hash"],
                payload["strings_json"],
                payload["embedding_json"],
                payload["confidence"],
                row_id,
            ),
        )
        conn.commit()
        return row_id

    def upsert_symbol(self, row: dict[str, Any]) -> int:
        now = time.time()
        _conf = row.get("confidence")
        payload = {
            "symbol_name": row.get("symbol_name") or "",
            "source_session": row.get("source_session") or "",
            "source_binary": row.get("source_binary") or "",
            "source_addr": row.get("source_addr") or "",
            "chip_family": row.get("chip_family") or "",
            "fingerprint": row.get("fingerprint") or "",
            "callgraph_hash": row.get("callgraph_hash") or "",
            "strings_json": json.dumps(row.get("strings") or []),
            "embedding_json": json.dumps(row.get("embedding") or []),
            # A deliberately zero-confidence symbol must stay 0 — only an
            # absent value falls back to the default.
            "confidence": float(_conf) if _conf is not None else 1.0,
        }
        if not payload["symbol_name"] or not payload["fingerprint"]:
            return 0
        with contextlib.closing(self._conn()) as conn:
            existing = conn.execute(
                "SELECT id FROM symbols WHERE symbol_name=? AND fingerprint=?",
                (payload["symbol_name"], payload["fingerprint"]),
            ).fetchone()
            if existing:
                return self._update_symbol(conn, int(existing[0]), payload, now)
            try:
                cur = conn.execute(
                    """
                    INSERT INTO symbols(symbol_name, source_session, source_binary, source_addr, chip_family,
                                        fingerprint, callgraph_hash, strings_json, embedding_json, confidence, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload["symbol_name"],
                        payload["source_session"],
                        payload["source_binary"],
                        payload["source_addr"],
                        payload["chip_family"],
                        payload["fingerprint"],
                        payload["callgraph_hash"],
                        payload["strings_json"],
                        payload["embedding_json"],
                        payload["confidence"],
                        now,
                        now,
                    ),
                )
                conn.commit()
                return int(cur.lastrowid or 0)
            except sqlite3.IntegrityError:
                # A concurrent writer inserted the same (symbol_name, fingerprint)
                # between our SELECT and INSERT. The UNIQUE index makes the race
                # safe — merge into the existing row instead of duplicating.
                existing = conn.execute(
                    "SELECT id FROM symbols WHERE symbol_name=? AND fingerprint=?",
                    (payload["symbol_name"], payload["fingerprint"]),
                ).fetchone()
                if existing:
                    return self._update_symbol(conn, int(existing[0]), payload, now)
                raise

    def query_symbols(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        q = f"%{str(query or '').strip()}%"
        with contextlib.closing(self._conn()) as conn:
            rows = conn.execute(
                """
                SELECT symbol_name, source_binary, source_addr, chip_family, fingerprint, callgraph_hash, strings_json, confidence
                FROM symbols
                WHERE symbol_name LIKE ? OR strings_json LIKE ?
                ORDER BY confidence DESC, updated_at DESC
                LIMIT ?
                """,
                (q, q, int(limit)),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "symbol_name": r[0],
                    "source_binary": r[1],
                    "source_addr": r[2],
                    "chip_family": r[3],
                    "fingerprint": r[4],
                    "callgraph_hash": r[5],
                    "strings": json.loads(r[6] or "[]"),
                    "confidence": float(r[7] or 0.0),
                }
            )
        return out

    def lookup_by_fingerprint(self, fingerprint: str, limit: int = 5) -> list[dict[str, Any]]:
        with contextlib.closing(self._conn()) as conn:
            rows = conn.execute(
                """
                SELECT symbol_name, source_binary, source_addr, chip_family, fingerprint, callgraph_hash, strings_json, embedding_json, confidence
                FROM symbols
                WHERE fingerprint=?
                ORDER BY confidence DESC, updated_at DESC
                LIMIT ?
                """,
                (fingerprint, int(limit)),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "symbol_name": r[0],
                    "source_binary": r[1],
                    "source_addr": r[2],
                    "chip_family": r[3],
                    "fingerprint": r[4],
                    "callgraph_hash": r[5],
                    "strings": json.loads(r[6] or "[]"),
                    "embedding": json.loads(r[7] or "[]"),
                    "confidence": float(r[8] or 0.0),
                }
            )
        return out

    def stats_by_chip(self) -> list[dict[str, Any]]:
        with contextlib.closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT chip_family, COUNT(*) FROM symbols GROUP BY chip_family ORDER BY COUNT(*) DESC"
            ).fetchall()
        return [{"chip_family": r[0] or "unknown", "symbol_count": int(r[1])} for r in rows]

    def upsert_hypothesis(
        self,
        *,
        binary_hash: str,
        addr_offset: int,
        hypothesis_text: str,
        confidence: float = 0.8,
        chip_family: str = "",
        source_session: str = "",
        source_binary: str = "",
    ) -> int:
        if not binary_hash or not hypothesis_text:
            return 0
        now = time.time()
        _conf = confidence if confidence is not None else 0.8
        with contextlib.closing(self._conn()) as conn:
            existing = conn.execute(
                "SELECT id FROM hypotheses WHERE binary_hash=? AND addr_offset=? AND hypothesis_text=?",
                (str(binary_hash), int(addr_offset), str(hypothesis_text)),
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE hypotheses
                    SET confidence=?, chip_family=?, source_session=?, source_binary=?, created_at=?
                    WHERE id=?
                    """,
                    (
                        float(_conf),
                        str(chip_family or ""),
                        str(source_session or ""),
                        str(source_binary or ""),
                        now,
                        int(existing[0]),
                    ),
                )
                conn.commit()
                return int(existing[0])
            cur = conn.execute(
                """
                INSERT INTO hypotheses(binary_hash, chip_family, addr_offset, hypothesis_text, confidence, source_session, source_binary, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(binary_hash),
                    str(chip_family or ""),
                    int(addr_offset),
                    str(hypothesis_text),
                    float(_conf),
                    str(source_session or ""),
                    str(source_binary or ""),
                    now,
                ),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def query_hypotheses(self, *, binary_hash: str = "", chip_family: str = "", limit: int = 200) -> list[dict[str, Any]]:
        where = []
        params: list[Any] = []
        if binary_hash:
            where.append("binary_hash=?")
            params.append(str(binary_hash))
        if chip_family:
            where.append("LOWER(chip_family)=LOWER(?)")
            params.append(str(chip_family))
        if not where:
            return []
        params.append(int(limit))
        sql = (
            "SELECT binary_hash, chip_family, addr_offset, hypothesis_text, confidence, source_session, source_binary, created_at "
            f"FROM hypotheses WHERE {' AND '.join(where)} ORDER BY confidence DESC, created_at DESC LIMIT ?"
        )
        with contextlib.closing(self._conn()) as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "binary_hash": r[0],
                    "chip_family": r[1] or "",
                    "addr_offset": int(r[2] or 0),
                    "hypothesis_text": r[3] or "",
                    "confidence": float(r[4] or 0.0),
                    "source_session": r[5] or "",
                    "source_binary": r[6] or "",
                    "created_at": float(r[7] or 0.0),
                }
            )
        return out
