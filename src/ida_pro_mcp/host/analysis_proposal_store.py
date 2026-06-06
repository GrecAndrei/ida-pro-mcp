#!/usr/bin/env python3
"""SQLite-backed proposal queue used by the analysis engine."""

from __future__ import annotations

import json
import threading
import time
import uuid
from contextlib import closing
from typing import Dict, List, Optional


class ProposalStore:
    """
    Thread-safe in-memory + SQLite-backed proposal queue.

    Proposal types:
      rename_batch    — suggest renaming N functions
      annotation_batch — suggest adding comments to N functions
      hypothesis      — engine believes X about address Y
      cross_session   — N functions match a previous session
      vuln            — taint trace found a dangerous sink
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self):
        import sqlite3
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with closing(self._conn()) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS proposals (
                    id TEXT PRIMARY KEY,
                    proposal_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT,
                    items TEXT,          -- JSON list of {addr, name, reason, ...}
                    confidence REAL DEFAULT 0.5,
                    created_at REAL,
                    status TEXT DEFAULT 'pending',  -- pending/accepted/rejected
                    accepted_ids TEXT,   -- JSON list of accepted item ids
                    session_id TEXT
                )
            """)
            conn.commit()

    def add(self, proposal_type: str, title: str, summary: str,
            items: List[Dict], confidence: float = 0.5,
            session_id: str = "") -> str:
        pid = uuid.uuid4().hex[:12]
        with closing(self._conn()) as conn:
            conn.execute(
                "INSERT INTO proposals VALUES (?,?,?,?,?,?,?,?,?,?)",
                (pid, proposal_type, title, summary,
                 json.dumps(items), confidence, time.time(),
                 "pending", "[]", session_id)
            )
            conn.commit()
        return pid

    def list_pending(self) -> List[Dict]:
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT id,proposal_type,title,summary,items,confidence,created_at,session_id "
                "FROM proposals WHERE status='pending' ORDER BY confidence DESC"
            ).fetchall()
        return [
            {"id": r[0], "proposal_type": r[1], "title": r[2], "summary": r[3],
             "items": json.loads(r[4] or "[]"), "confidence": r[5],
             "created_at": r[6], "session_id": r[7]}
            for r in rows
        ]

    def accept(self, proposal_id: str, scope: str = "all",
               selected_ids: Optional[List[str]] = None) -> Optional[Dict]:
        """Accept a proposal. Returns the proposal dict with accepted items."""
        with closing(self._conn()) as conn:
            row = conn.execute(
                "SELECT id,proposal_type,title,items FROM proposals WHERE id=? AND status='pending'",
                (proposal_id,)
            ).fetchone()
            if not row:
                return None
            items = json.loads(row[3] or "[]")
            if scope == "selected" and selected_ids:
                accepted = [it for it in items if it.get("id") in selected_ids]
            else:
                accepted = items
            conn.execute(
                "UPDATE proposals SET status='accepted', accepted_ids=? WHERE id=?",
                (json.dumps([it.get("id") for it in accepted]), proposal_id)
            )
            conn.commit()
        return {"id": row[0], "proposal_type": row[1], "title": row[2],
                "accepted_items": accepted}

    def reject(self, proposal_id: str, bb_path: str = "") -> bool:
        """Reject a proposal and write a dead_end entry to the blackboard."""
        with closing(self._conn()) as conn:
            row = conn.execute(
                "SELECT id,proposal_type,title,items FROM proposals WHERE id=? AND status='pending'",
                (proposal_id,)
            ).fetchone()
            if not row:
                return False
            conn.execute(
                "UPDATE proposals SET status='rejected' WHERE id=?",
                (proposal_id,)
            )
            conn.commit()

        # Rejection feedback: write dead_end entries so engine doesn't re-propose
        if bb_path:
            try:
                items = json.loads(row[3] or "[]")
                import sqlite3 as _sq3
                with closing(_sq3.connect(bb_path, timeout=5)) as bconn:
                    bconn.execute("PRAGMA journal_mode=WAL")
                    for item in items[:10]:
                        addr = item.get("addr", "")
                        if not addr:
                            continue
                        # Check if dead_end already exists for this addr
                        existing = bconn.execute(
                            "SELECT id FROM blackboard WHERE addr=? AND category='dead_end'",
                            (addr,)
                        ).fetchone()
                        if existing:
                            continue
                        bconn.execute(
                            "INSERT OR IGNORE INTO blackboard "
                            "(id, category, title, content, addr, confidence, "
                            "created_at, updated_at, q_value, source, source_type, "
                            "resolved, tags, evidence) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                uuid.uuid4().hex[:8], "dead_end",
                                f"Rejected: {row[2][:60]}",
                                f"Proposal '{row[1]}' was rejected by LLM",
                                addr, 0.1,
                                time.time(), time.time(), 0.1,
                                "engine.rejected", "engine_rejected",
                                1,  # resolved=1 so it's excluded from next_target
                                json.dumps(["rejected", row[1]]),
                                json.dumps([{"type": "rejection", "value": proposal_id,
                                             "weight": 0.0, "ts": time.time()}]),
                            )
                        )
                    bconn.commit()
            except Exception:
                pass
        return True

    def count_pending(self) -> int:
        with closing(self._conn()) as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM proposals WHERE status='pending'"
            ).fetchone()[0]


# ── Analysis Engine ───────────────────────────────────────────────────────────

