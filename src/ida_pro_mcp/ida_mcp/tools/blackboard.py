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


def _resolve_db_path(db_path: Optional[str] = None) -> str:
    """
    Resolve blackboard DB path.  Prefer per-binary scoping (same pattern as
    schemaboot/turboquant) so findings from binary A don't pollute binary B.
    Falls back to a global path if IDA is not running.
    """
    if db_path:
        return db_path
    # Try to get the current IDB path from IDA
    try:
        import idc as _idc
        p = _idc.get_idb_path()
        if p:
            return p + ".blackboard.db"
    except Exception:
        pass
    # Global fallback (host-side / no IDA session)
    return os.path.join(os.path.expanduser("~"), ".ida-pro-mcp", "blackboard.db")


class BlackboardStore:
    """SQLite-backed persistent blackboard for analysis context."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = _resolve_db_path(db_path)
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

    def prune(
        self,
        max_entries: int = 1000,
        min_q_value: float = 0.0,
        older_than_days: int = 0,
    ) -> Dict:
        """Evict low-quality or old entries to cap DB size."""
        with self._conn() as conn:
            cur = conn.cursor()
            conditions = ["1=1"]
            params: list = []
            if min_q_value > 0:
                conditions.append("q_value < ?")
                params.append(min_q_value)
            if older_than_days > 0:
                cutoff = time.time() - (older_than_days * 86400)
                conditions.append("updated_at < ?")
                params.append(cutoff)
            where = "WHERE " + " AND ".join(conditions)
            # Count how many we'd delete
            cur.execute(f"SELECT COUNT(*) FROM blackboard {where}", params)
            would_delete = cur.fetchone()[0]
            # Get total count
            cur.execute("SELECT COUNT(*) FROM blackboard")
            total = cur.fetchone()[0]
            # If total exceeds max, delete oldest/lowest-q first
            to_delete = max(0, total - max_entries)
            if to_delete > 0:
                cur.execute(
                    f"""SELECT id FROM blackboard {where}
                    ORDER BY q_value ASC, updated_at ASC LIMIT ?""",
                    (*params, to_delete),
                )
                ids = [r[0] for r in cur.fetchall()]
                for eid in ids:
                    cur.execute("DELETE FROM blackboard WHERE id = ?", (eid,))
                conn.commit()
                return {"pruned": len(ids), "remaining": total - len(ids), "reason": "capacity"}
            elif would_delete > 0:
                cur.execute(f"DELETE FROM blackboard {where}", params)
                conn.commit()
                return {"pruned": would_delete, "remaining": total - would_delete, "reason": "quality"}
            return {"pruned": 0, "remaining": total, "reason": "none"}

    def exists(self, addr: str, category: str, title: str) -> bool:
        """
        Check if an entry with the same addr+category+title already exists.
        Used to prevent duplicate auto-writes without a full merge pass.
        """
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT 1 FROM blackboard WHERE addr = ? AND category = ? AND title = ? LIMIT 1",
                (addr, category, title),
            )
            return cur.fetchone() is not None

    def auto_merge(self, addr: str = "", category: str = "", similarity_threshold: float = 0.85) -> Dict:
        """
        Detect and merge duplicate entries by addr+category+title similarity.

        Similarity uses Jaccard on word tokens rather than first-word matching
        so "buffer overflow at 0x401234" and "buffer read at 0x502000" no
        longer get incorrectly merged (they share 'buffer' but Jaccard ≈ 0.2).
        """
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
        deleted_ids: set = set()

        def _jaccard_words(a: str, b: str) -> float:
            wa = set(a.lower().split())
            wb = set(b.lower().split())
            if not wa or not wb:
                return 0.0
            return len(wa & wb) / len(wa | wb)

        for i, entry in enumerate(entries):
            if entry["id"] in deleted_ids:
                continue
            for other in entries[i + 1:]:
                if other["id"] in deleted_ids:
                    continue
                if (
                    entry.get("addr") == other.get("addr")
                    and entry.get("category") == other.get("category")
                ):
                    t1 = str(entry.get("title") or "")
                    t2 = str(other.get("title") or "")
                    # Exact match OR high Jaccard similarity on title tokens
                    if t1 == t2 or _jaccard_words(t1, t2) >= similarity_threshold:
                        self.delete(other["id"])
                        deleted_ids.add(other["id"])
                        merged_count += 1
        return {"merged": merged_count, "remaining": len(entries) - merged_count}

    def _row_to_dict(self, row) -> Dict:
        # Binary blob columns (vector/quantized/q_signs) are Cartographer-μ
        # internals — never return them in MCP responses because:
        #   (a) bytes aren't JSON-serializable → crash if non-None
        #   (b) they're meaningless to the LLM
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
            # row[10] schema, row[11-13] binary blobs — omitted from output
            "q_value": row[15] if row[15] is not None else 0.5,
        }


@tool
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
    max_entries: int = 1000,
    min_q_value: float = 0.0,
    older_than_days: int = 0,
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
      prune   - Evict low-Q or old entries to cap DB size.
      merge   - Deduplicate similar entries.

    Examples:
        blackboard(action="write", title="Buffer overflow at 0x401234",
                   content="Unchecked strcpy into stack buffer", addr="0x401234",
                   category="vuln", tags=["overflow", "strcpy"], confidence=0.9)
        blackboard(action="list", category="vuln", limit=10)
        blackboard(action="read", entry_id="abc123")
        blackboard(action="clear", category="vuln")
        blackboard(action="prune", max_entries=500, min_q_value=0.1)
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
        # Pass category as-is; None means "all categories".
        # Previously "general" was silently converted to None, making it
        # impossible to list only the "general" category specifically.
        entries = store.list(
            category=category or None,
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
        # Build update dict from named parameters (they're captured in the
        # function signature, NOT in **kwargs, so we must forward explicitly).
        update_fields: Dict = {}
        if title:
            update_fields["title"] = title
        if content:
            update_fields["content"] = content
        if category:
            update_fields["category"] = category
        if addr:
            update_fields["addr"] = addr
        if tags is not None:
            update_fields["tags"] = tags
        if confidence != 0.5:   # non-default
            update_fields["confidence"] = confidence
        # Also pass through any extra kwargs not in the signature
        update_fields.update(kwargs)
        if not update_fields:
            return {"ok": False, "error": "No fields to update. Pass title, content, category, addr, tags, or confidence."}
        ok = store.update(entry_id, **update_fields)
        if not ok:
            return {"ok": False, "error": f"Entry '{entry_id}' not found"}
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

    elif action == "prune":
        result = store.prune(max_entries=max_entries, min_q_value=min_q_value, older_than_days=older_than_days)
        return {"ok": True, **result}

    else:
        return {"ok": False, "error": f"Unknown action: {action}"}
