"""
Blackboard: Persistent stateful context for reverse engineering analysis.

The Detective's Blackboard — a persistent notepad where the analyst (or LLM)
can offload hypotheses, findings, and working memory without clogging context
windows.  All data is deterministic and stored locally.

Actions:
  write   - Pin a finding/hypothesis to the blackboard
  read    - Retrieve a specific entry or category
  list    - List all entries (optionally filtered by category)
  clear   - Remove all entries or a specific category
  delete  - Remove a single entry by ID
  update  - Modify an existing entry
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from typing import Dict, List, Optional

try:
    from ._common import *
except ImportError:
    try:
        from _common import *  # type: ignore[import-not-found]
    except ImportError:
        pass

if "tool" not in globals():
    tool = lambda f: f  # type: ignore
if "idaread" not in globals():
    idaread = lambda f: f  # type: ignore
if "idawrite" not in globals():
    idawrite = lambda f: f  # type: ignore
if "IDAError" not in globals():
    IDAError = Exception  # type: ignore


class BlackboardStore:
    """SQLite-backed persistent blackboard for analysis context."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.path.join(os.path.expanduser("~"), ".ida-pro-mcp", "blackboard.db")
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blackboard (
                    id TEXT PRIMARY KEY,
                    category TEXT NOT NULL DEFAULT 'general',
                    title TEXT NOT NULL,
                    content TEXT,
                    addr TEXT,
                    tags TEXT,
                    confidence REAL DEFAULT 0.5,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            # Migration: add Cartographer-μ columns if missing
            existing_cols = {
                row[1] for row in conn.execute(
                    "PRAGMA table_info(blackboard)"
                ).fetchall()
            }
            migrations = [
                ("bridges", "TEXT DEFAULT '{}'"),
                ("schema", "TEXT DEFAULT '{}'"),
                ("vector", "BLOB"),
                ("quantized", "BLOB"),
                ("q_signs", "BLOB"),
                ("norm", "REAL DEFAULT 0.0"),
                ("q_value", "REAL DEFAULT 0.5"),
                ("call_idx", "INTEGER DEFAULT 0"),
            ]
            for col, dtype in migrations:
                if col not in existing_cols:
                    conn.execute(f"ALTER TABLE blackboard ADD COLUMN {col} {dtype}")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_category ON blackboard(category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_addr ON blackboard(addr)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_tags ON blackboard(tags)")
            conn.commit()

    def write(
        self,
        title: str,
        content: str = "",
        category: str = "general",
        addr: str = "",
        tags: List[str] = None,
        confidence: float = 0.5,
        bridges: List[str] = None,
        schema: Dict[str, Any] = None,
        vector: bytes = None,
        quantized: bytes = None,
        q_signs: bytes = None,
        norm: float = 0.0,
        q_value: float = 0.5,
        call_idx: int = 0,
    ) -> str:
        entry_id = str(uuid.uuid4())[:8]
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO blackboard (
                    id, category, title, content, addr, tags, confidence,
                    created_at, updated_at, bridges, schema, vector, quantized,
                    q_signs, norm, q_value, call_idx
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry_id,
                    category,
                    title,
                    content,
                    addr,
                    json.dumps(tags or []),
                    confidence,
                    now,
                    now,
                    json.dumps(bridges or []),
                    json.dumps(schema or {}),
                    vector,
                    quantized,
                    q_signs,
                    norm,
                    q_value,
                    call_idx,
                ),
            )
            conn.commit()
        return entry_id

    def read(self, entry_id: str) -> Optional[Dict]:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM blackboard WHERE id = ?", (entry_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_dict(row)

    def list(
        self,
        category: Optional[str] = None,
        addr: Optional[str] = None,
        tag: Optional[str] = None,
        min_confidence: float = 0.0,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict]:
        conditions = ["confidence >= ?"]
        params = [min_confidence]
        if category:
            conditions.append("category = ?")
            params.append(category)
        if addr:
            conditions.append("addr = ?")
            params.append(addr)
        if tag:
            conditions.append("tags LIKE ?")
            params.append(f'%"{tag}"%')

        where = "WHERE " + " AND ".join(conditions)
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                f"SELECT * FROM blackboard {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            )
            return [self._row_to_dict(r) for r in cur.fetchall()]

    def update(self, entry_id: str, **kwargs) -> bool:
        allowed = {"title", "content", "category", "addr", "tags", "confidence"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        updates["updated_at"] = time.time()
        if "tags" in updates:
            updates["tags"] = json.dumps(updates["tags"])
        sets = ", ".join(f"{k} = ?" for k in updates)
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                f"UPDATE blackboard SET {sets} WHERE id = ?",
                (*updates.values(), entry_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def delete(self, entry_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM blackboard WHERE id = ?", (entry_id,))
            conn.commit()
            return cur.rowcount > 0

    def clear(self, category: Optional[str] = None) -> int:
        with self._conn() as conn:
            cur = conn.cursor()
            if category:
                cur.execute("DELETE FROM blackboard WHERE category = ?", (category,))
            else:
                cur.execute("DELETE FROM blackboard")
            conn.commit()
            return cur.rowcount

    def stats(self) -> Dict:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*), COUNT(DISTINCT category), AVG(confidence) FROM blackboard")
            total, cats, avg_conf = cur.fetchone()
            cur.execute("SELECT category, COUNT(*) FROM blackboard GROUP BY category")
            by_cat = {r[0]: r[1] for r in cur.fetchall()}
            return {
                "total_entries": total or 0,
                "categories": cats or 0,
                "avg_confidence": round(avg_conf or 0, 3),
                "by_category": by_cat,
            }

    def auto_merge(self, addr: str = "", category: str = "", similarity_threshold: float = 0.85) -> Dict:
        """Detect and merge duplicate entries by addr+category+title similarity."""
        with self._conn() as conn:
            cur = conn.cursor()
            conditions = ["1=1"]
            params: list = []
            if addr:
                conditions.append("addr = ?")
                params.append(addr)
            if category:
                conditions.append("category = ?")
                params.append(category)
            where = "WHERE " + " AND ".join(conditions)
            cur.execute(f"SELECT * FROM blackboard {where} ORDER BY updated_at DESC", params)
            rows = cur.fetchall()

        entries = [self._row_to_dict(r) for r in rows]
        merged_count = 0
        kept_ids: set = set()

        for i, entry in enumerate(entries):
            if entry["id"] in kept_ids:
                continue
            for other in entries[i + 1 :]:
                if other["id"] in kept_ids:
                    continue
                # Simple similarity: same addr/category and title containment
                if (
                    entry.get("addr") == other.get("addr")
                    and entry.get("category") == other.get("category")
                ):
                    t1 = str(entry.get("title") or "").lower().strip()
                    t2 = str(other.get("title") or "").lower().strip()
                    sim = 0.0
                    if t1 and t2:
                        if t1 in t2 or t2 in t1:
                            sim = 0.9
                        elif t1.split()[0] == t2.split()[0]:
                            sim = 0.85
                    if sim >= similarity_threshold:
                        # Merge: keep newer, delete older
                        self.delete(other["id"])
                        kept_ids.add(other["id"])
                        merged_count += 1
        return {"merged": merged_count, "remaining": len(entries) - merged_count}

    def _row_to_dict(self, row) -> Dict:
        return {
            "id": row[0],
            "category": row[1],
            "title": row[2],
            "content": row[3],
            "addr": row[4],
            "tags": json.loads(row[5]) if row[5] else [],
            "confidence": row[6],
            "created_at": row[7],
            "updated_at": row[8],
            "bridges": json.loads(row[9]) if row[9] else [],
            "schema": json.loads(row[10]) if row[10] else {},
            "vector": row[11],
            "quantized": row[12],
            "q_signs": row[13],
            "norm": row[14] or 0.0,
            "q_value": row[15] if row[15] is not None else 0.5,
            "call_idx": row[16] or 0,
        }


@tool
@idawrite
def blackboard(
    action: str = "list",
    entry_id: str = "",
    title: str = "",
    content: str = "",
    category: str = "general",
    addr: str = "",
    tags: Optional[List[str]] = None,
    confidence: float = 0.5,
    tag: str = "",
    min_confidence: float = 0.0,
    limit: int = 100,
    offset: int = 0,
    db_path: str = "",
    **kwargs,
) -> dict:
    """
    Persistent stateful context store for analysis hypotheses and findings.

    Actions:
      write   - Pin a finding. Returns entry_id.
      read    - Get a single entry by ID.
      list    - List entries with optional filters.
      update  - Modify an existing entry.
      delete  - Remove a single entry.
      clear   - Remove all entries (or by category).
      stats   - Show aggregate statistics.

    Examples:
        blackboard(action="write", title="Buffer overflow at 0x401234",
                   content="Unchecked strcpy into stack buffer", addr="0x401234",
                   category="vuln", tags=["overflow", "strcpy"], confidence=0.9)
        blackboard(action="list", category="vuln", limit=10)
        blackboard(action="read", entry_id="abc123")
        blackboard(action="clear", category="vuln")
    """
    store = BlackboardStore(db_path=db_path or None)

    if action == "write":
        if not title:
            return {"ok": False, "error": "title required for write"}
        eid = store.write(title, content, category, addr, tags, confidence)
        return {"ok": True, "entry_id": eid, "action": "write"}

    elif action == "read":
        if not entry_id:
            return {"ok": False, "error": "entry_id required for read"}
        entry = store.read(entry_id)
        if entry is None:
            return {"ok": False, "error": f"Entry '{entry_id}' not found"}
        return {"ok": True, "entry": entry}

    elif action == "list":
        entries = store.list(
            category=category if category != "general" else None,
            addr=addr or None,
            tag=tag or None,
            min_confidence=min_confidence,
            limit=limit,
            offset=offset,
        )
        return {"ok": True, "entries": entries, "count": len(entries)}

    elif action == "update":
        if not entry_id:
            return {"ok": False, "error": "entry_id required for update"}
        ok = store.update(entry_id, **kwargs)
        if not ok:
            return {"ok": False, "error": f"Entry '{entry_id}' not found or no changes"}
        return {"ok": True, "entry_id": entry_id, "action": "update"}

    elif action == "delete":
        if not entry_id:
            return {"ok": False, "error": "entry_id required for delete"}
        ok = store.delete(entry_id)
        if not ok:
            return {"ok": False, "error": f"Entry '{entry_id}' not found"}
        return {"ok": True, "entry_id": entry_id, "action": "delete"}

    elif action == "clear":
        count = store.clear(category=category if category != "general" else None)
        return {"ok": True, "deleted": count}

    elif action == "stats":
        return {"ok": True, **store.stats()}

    elif action == "merge":
        result = store.auto_merge(addr=addr, category=category if category != "general" else "")
        return {"ok": True, **result}

    else:
        return {"ok": False, "error": f"Unknown action: {action}"}
