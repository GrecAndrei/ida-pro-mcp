"""
Blackboard: Persistent, self-maintaining analysis context for firmware RE.

Extended schema supports:
  - region       : annotated memory regions (addr_start, addr_end)
  - ioc          : IOCs (ip, port, key, magic, url) with ioc_type + value fields
  - dead_end     : resolved/skip markers so you don't revisit
  - dependency   : "must understand X before Y" task graph
  - data_flow    : register/variable state at a function boundary
  - contradiction: marks a prior entry as contradicted with reason
  - hypothesis   : auto-generated from BehaviorClassifier
  - cluster      : behavioral cluster summaries
  - rename_suggestion : propagated rename candidates
  - pointer/string/entropy/address/pointer_chain/deref : auto-captured

Background crawler (start_crawler / stop_crawler) follows xrefs from known
addresses, finds new ones, and proposes them via MCP notification.

Actions:
  write, read, list, search, update, delete, clear, stats, prune, merge
  contradict     - Mark an entry as contradicted
  next_target    - Return highest-priority unexplored address
  start_crawler  - Start background xref crawler
  stop_crawler   - Stop background xref crawler
  crawler_status - Show crawler state and pending proposals
  accept         - Accept a crawler proposal (writes to blackboard)
  reject         - Reject a crawler proposal
"""

from __future__ import annotations

import json
import os
import sqlite3
import struct
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

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
    if db_path:
        return db_path
    try:
        import idc as _idc
        p = _idc.get_idb_path()
        if p:
            return p + ".blackboard.db"
    except Exception:
        pass
    xdg = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    root = (
        os.environ.get("IDA_MCP_CACHE_DIR")
        or os.environ.get("IDA_MCP_DATA_DIR")
        or os.path.join(xdg, "ida-pro-mcp")
    )
    return os.path.join(root, "blackboard.db")


def _get_embedder():
    try:
        from ida_pro_mcp.host.intelligence import BgeCodeEmbedder
        return BgeCodeEmbedder()
    except ImportError:
        try:
            from host.intelligence import BgeCodeEmbedder  # type: ignore
            return BgeCodeEmbedder()
        except ImportError:
            return None


def _pack_vec(vec: List[float]) -> bytes:
    return struct.pack(f"{len(vec)}f", *vec)


def _unpack_vec(blob: bytes) -> List[float]:
    n = len(blob) // 4
    return list(struct.unpack(f"{n}f", blob))


def _cosine(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


class BlackboardStore:
    """SQLite-backed blackboard with extended firmware RE schema."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = _resolve_db_path(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blackboard (
                    id           TEXT PRIMARY KEY,
                    category     TEXT NOT NULL DEFAULT 'general',
                    title        TEXT NOT NULL,
                    content      TEXT,
                    addr         TEXT,
                    addr_end     TEXT,
                    tags         TEXT,
                    confidence   REAL DEFAULT 0.5,
                    created_at   REAL NOT NULL,
                    updated_at   REAL NOT NULL,
                    q_value      REAL DEFAULT 0.5,
                    source       TEXT DEFAULT 'manual',
                    vector       BLOB,
                    resolved     INTEGER DEFAULT 0,
                    contradicted INTEGER DEFAULT 0,
                    contradiction_reason TEXT,
                    ioc_type     TEXT,
                    ioc_value    TEXT,
                    depends_on   TEXT,
                    blocks_addr  TEXT,
                    register     TEXT,
                    reg_type     TEXT
                )
            """)
            existing = {r[1] for r in conn.execute("PRAGMA table_info(blackboard)").fetchall()}
            for col, dtype in [
                ("addr_end", "TEXT"),
                ("resolved", "INTEGER DEFAULT 0"),
                ("contradicted", "INTEGER DEFAULT 0"),
                ("contradiction_reason", "TEXT"),
                ("ioc_type", "TEXT"),
                ("ioc_value", "TEXT"),
                ("depends_on", "TEXT"),
                ("blocks_addr", "TEXT"),
                ("register", "TEXT"),
                ("reg_type", "TEXT"),
                # Legacy compat
                ("bridges", "TEXT DEFAULT '{}'"),
                ("schema", "TEXT DEFAULT '{}'"),
                ("quantized", "BLOB"),
                ("q_signs", "BLOB"),
                ("norm", "REAL DEFAULT 0.0"),
                ("call_idx", "INTEGER DEFAULT 0"),
            ]:
                if col not in existing:
                    conn.execute(f"ALTER TABLE blackboard ADD COLUMN {col} {dtype}")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_category ON blackboard(category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_addr ON blackboard(addr)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_tags ON blackboard(tags)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_resolved ON blackboard(resolved)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_ioc ON blackboard(ioc_type)")
            conn.commit()

    def _embed_text(self, text: str) -> Optional[bytes]:
        embedder = _get_embedder()
        if embedder is None:
            return None
        try:
            return _pack_vec(embedder.embed(text))
        except Exception:
            return None

    def write(
        self,
        title: str,
        content: str = "",
        category: str = "general",
        addr: str = "",
        addr_end: str = "",
        tags: Optional[List[str]] = None,
        confidence: float = 0.5,
        source: str = "manual",
        embed: bool = True,
        ioc_type: str = "",
        ioc_value: str = "",
        depends_on: str = "",
        blocks_addr: str = "",
        register: str = "",
        reg_type: str = "",
        **_legacy_kwargs,
    ) -> str:
        entry_id = str(uuid.uuid4())[:8]
        now = time.time()
        vector_blob = None
        if embed:
            vector_blob = self._embed_text(f"{title} {content}".strip())
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO blackboard
                    (id, category, title, content, addr, addr_end, tags, confidence,
                     created_at, updated_at, q_value, source, vector,
                     ioc_type, ioc_value, depends_on, blocks_addr, register, reg_type)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                entry_id, category, title, content, addr, addr_end,
                json.dumps(tags or []), confidence,
                now, now, confidence, source, vector_blob,
                ioc_type, ioc_value, depends_on, blocks_addr, register, reg_type,
            ))
            conn.commit()
        return entry_id

    def read(self, entry_id: str) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM blackboard WHERE id = ?", (entry_id,)).fetchone()
            return self._row_to_dict(row) if row else None

    def list(
        self,
        category: Optional[str] = None,
        addr: Optional[str] = None,
        tag: Optional[str] = None,
        min_confidence: float = 0.0,
        limit: int = 100,
        offset: int = 0,
        include_resolved: bool = True,
        include_contradicted: bool = False,
        ioc_type: Optional[str] = None,
    ) -> List[Dict]:
        conditions = ["confidence >= ?"]
        params: list = [min_confidence]
        if category:
            conditions.append("category = ?")
            params.append(category)
        if addr:
            conditions.append("addr = ?")
            params.append(addr)
        if tag:
            conditions.append("tags LIKE ?")
            params.append(f'%"{tag}"%')
        if not include_resolved:
            conditions.append("resolved = 0")
        if not include_contradicted:
            conditions.append("contradicted = 0")
        if ioc_type:
            conditions.append("ioc_type = ?")
            params.append(ioc_type)
        where = "WHERE " + " AND ".join(conditions)
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM blackboard {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def semantic_search(
        self,
        query: str,
        top_k: int = 10,
        threshold: float = 0.4,
        category: Optional[str] = None,
        include_resolved: bool = True,
        include_contradicted: bool = False,
    ) -> List[Dict]:
        embedder = _get_embedder()
        if embedder is None:
            q = query.lower()
            with self._conn() as conn:
                rows = conn.execute("SELECT * FROM blackboard ORDER BY updated_at DESC LIMIT 200").fetchall()
            results = []
            for row in rows:
                d = self._row_to_dict(row)
                if not include_resolved and d.get("resolved"):
                    continue
                if not include_contradicted and d.get("contradicted"):
                    continue
                text = f"{d.get('title','')} {d.get('content','')}".lower()
                if q in text:
                    d["similarity"] = 1.0
                    results.append(d)
            return results[:top_k]

        try:
            q_vec = embedder.embed(query)
        except Exception:
            return []

        conditions = ["vector IS NOT NULL"]
        params: list = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        if not include_resolved:
            conditions.append("resolved = 0")
        if not include_contradicted:
            conditions.append("contradicted = 0")
        where = "WHERE " + " AND ".join(conditions)

        with self._conn() as conn:
            rows = conn.execute(f"SELECT * FROM blackboard {where}", params).fetchall()
            # d[1] is the column name (d[0] is the cid integer)
            col_names = [d[1] for d in conn.execute("PRAGMA table_info(blackboard)").fetchall()]
        vec_idx = col_names.index("vector") if "vector" in col_names else -1

        scored = []
        for row in rows:
            d = self._row_to_dict(row)
            blob = row[vec_idx] if vec_idx >= 0 and vec_idx < len(row) else None
            if not blob:
                continue
            try:
                vec = _unpack_vec(blob)
                sim = _cosine(q_vec, vec)
                if sim >= threshold:
                    d["similarity"] = round(sim, 4)
                    scored.append(d)
            except Exception:
                continue

        scored.sort(key=lambda x: x["similarity"], reverse=True)
        return scored[:top_k]

    def contradict(self, entry_id: str, reason: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE blackboard SET contradicted=1, contradiction_reason=?, updated_at=? WHERE id=?",
                (reason, time.time(), entry_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def mark_resolved(self, entry_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE blackboard SET resolved=1, updated_at=? WHERE id=?",
                (time.time(), entry_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def next_target(self, limit: int = 5) -> List[Dict]:
        """
        Return highest-priority unexplored addresses.

        Priority score = confidence * (1 - resolved) * (1 - contradicted)
        Boosted by:
          - dependency entries that are now unblocked (depends_on resolved)
          - high xref count (more callers = more important)
          - not yet in any cluster (unexplored territory)

        Returns addresses sorted by priority descending.
        """
        with self._conn() as conn:
            # Get all unresolved, non-contradicted entries with addresses
            rows = conn.execute("""
                SELECT id, addr, category, title, confidence, depends_on
                FROM blackboard
                WHERE resolved=0 AND contradicted=0 AND addr != '' AND addr IS NOT NULL
                ORDER BY confidence DESC
                LIMIT 200
            """).fetchall()

            # Get resolved addresses to check dependency satisfaction
            resolved_addrs = {
                r[0] for r in conn.execute(
                    "SELECT addr FROM blackboard WHERE resolved=1 AND addr != ''"
                ).fetchall()
            }

        scored = []
        seen_addrs: set = set()
        for row in rows:
            eid, addr, cat, title, conf, depends_on = row
            if addr in seen_addrs:
                continue
            seen_addrs.add(addr)

            score = float(conf or 0.5)

            # Boost if dependency is satisfied
            if depends_on and depends_on in resolved_addrs:
                score *= 1.5
            elif depends_on and depends_on not in resolved_addrs:
                score *= 0.3  # blocked — deprioritize

            # Boost hypotheses and dependencies (actionable)
            if cat in ("hypothesis", "dependency", "data_flow"):
                score *= 1.2
            # Deprioritize auto-captured low-signal entries
            if cat in ("pointer", "string") and conf < 0.7:
                score *= 0.5

            scored.append({
                "addr": addr,
                "title": title,
                "category": cat,
                "confidence": conf,
                "priority_score": round(score, 3),
                "entry_id": eid,
                "depends_on": depends_on or None,
            })

        scored.sort(key=lambda x: x["priority_score"], reverse=True)
        return scored[:limit]

    def update(self, entry_id: str, **kwargs) -> bool:
        allowed = {"title", "content", "category", "addr", "addr_end", "tags",
                   "confidence", "q_value", "resolved", "ioc_type", "ioc_value",
                   "depends_on", "blocks_addr", "register", "reg_type"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        updates["updated_at"] = time.time()
        if "tags" in updates:
            updates["tags"] = json.dumps(updates["tags"])
        if "title" in updates or "content" in updates:
            existing = self.read(entry_id)
            if existing:
                t = updates.get("title", existing.get("title", ""))
                c = updates.get("content", existing.get("content", ""))
                blob = self._embed_text(f"{t} {c}".strip())
                if blob:
                    updates["vector"] = blob
        sets = ", ".join(f"{k} = ?" for k in updates)
        with self._conn() as conn:
            cur = conn.execute(
                f"UPDATE blackboard SET {sets} WHERE id = ?",
                (*updates.values(), entry_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def delete(self, entry_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM blackboard WHERE id = ?", (entry_id,))
            conn.commit()
            return cur.rowcount > 0

    def clear(self, category: Optional[str] = None) -> int:
        with self._conn() as conn:
            if category:
                cur = conn.execute("DELETE FROM blackboard WHERE category = ?", (category,))
            else:
                cur = conn.execute("DELETE FROM blackboard")
            conn.commit()
            return cur.rowcount

    def stats(self) -> Dict:
        with self._conn() as conn:
            total, cats, avg_conf = conn.execute(
                "SELECT COUNT(*), COUNT(DISTINCT category), AVG(confidence) FROM blackboard"
            ).fetchone()
            by_cat = dict(conn.execute(
                "SELECT category, COUNT(*) FROM blackboard GROUP BY category"
            ).fetchall())
            embedded = conn.execute(
                "SELECT COUNT(*) FROM blackboard WHERE vector IS NOT NULL"
            ).fetchone()[0]
            resolved = conn.execute(
                "SELECT COUNT(*) FROM blackboard WHERE resolved=1"
            ).fetchone()[0]
            contradicted = conn.execute(
                "SELECT COUNT(*) FROM blackboard WHERE contradicted=1"
            ).fetchone()[0]
            iocs = conn.execute(
                "SELECT ioc_type, COUNT(*) FROM blackboard WHERE ioc_type != '' AND ioc_type IS NOT NULL GROUP BY ioc_type"
            ).fetchall()
        return {
            "total_entries": total or 0,
            "categories": cats or 0,
            "avg_confidence": round(avg_conf or 0, 3),
            "by_category": by_cat,
            "embedded_entries": embedded or 0,
            "resolved": resolved or 0,
            "contradicted": contradicted or 0,
            "iocs": dict(iocs),
        }

    def prune(self, max_entries: int = 1000, min_q_value: float = 0.0, older_than_days: int = 0) -> Dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM blackboard").fetchone()[0]
            conditions = ["1=1"]
            params: list = []
            if min_q_value > 0:
                conditions.append("q_value < ?")
                params.append(min_q_value)
            if older_than_days > 0:
                conditions.append("updated_at < ?")
                params.append(time.time() - older_than_days * 86400)
            where = "WHERE " + " AND ".join(conditions)
            to_delete = max(0, total - max_entries)
            if to_delete > 0:
                ids = [r[0] for r in conn.execute(
                    f"SELECT id FROM blackboard {where} ORDER BY q_value ASC, updated_at ASC LIMIT ?",
                    (*params, to_delete),
                ).fetchall()]
                for eid in ids:
                    conn.execute("DELETE FROM blackboard WHERE id = ?", (eid,))
                conn.commit()
                return {"pruned": len(ids), "remaining": total - len(ids)}
            elif params:
                cur = conn.execute(f"DELETE FROM blackboard {where}", params)
                conn.commit()
                return {"pruned": cur.rowcount, "remaining": total - cur.rowcount}
        return {"pruned": 0, "remaining": total}

    def exists_similar(self, addr: str, category: str, title: str, threshold: float = 0.85) -> bool:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT title FROM blackboard WHERE addr = ? AND category = ?",
                (addr, category),
            ).fetchall()
        if not rows:
            return False
        wa = set(title.lower().split())
        for (t,) in rows:
            wb = set(t.lower().split())
            if wa and wb and len(wa & wb) / len(wa | wb) >= threshold:
                return True
        return False

    def auto_merge(self, addr: str = "", category: str = "", similarity_threshold: float = 0.85) -> Dict:
        with self._conn() as conn:
            conditions = ["1=1"]
            params: list = []
            if addr:
                conditions.append("addr = ?")
                params.append(addr)
            if category:
                conditions.append("category = ?")
                params.append(category)
            rows = conn.execute(
                f"SELECT * FROM blackboard WHERE {' AND '.join(conditions)} ORDER BY updated_at DESC",
                params,
            ).fetchall()
        entries = [self._row_to_dict(r) for r in rows]
        deleted: set = set()

        def _jaccard(a: str, b: str) -> float:
            wa, wb = set(a.lower().split()), set(b.lower().split())
            return len(wa & wb) / len(wa | wb) if wa and wb else 0.0

        for i, e in enumerate(entries):
            if e["id"] in deleted:
                continue
            for o in entries[i + 1:]:
                if o["id"] in deleted:
                    continue
                if e.get("addr") == o.get("addr") and e.get("category") == o.get("category"):
                    if _jaccard(str(e.get("title", "")), str(o.get("title", ""))) >= similarity_threshold:
                        self.delete(o["id"])
                        deleted.add(o["id"])
        return {"merged": len(deleted), "remaining": len(entries) - len(deleted)}

    def _row_to_dict(self, row) -> Dict:
        if row is None:
            return {}
        if not hasattr(self, "_col_cache"):
            with self._conn() as conn:
                # PRAGMA table_info returns (cid, name, type, notnull, dflt, pk)
                self._col_cache = [d[1] for d in conn.execute("PRAGMA table_info(blackboard)").fetchall()]
        d: Dict = {}
        for i, col in enumerate(self._col_cache):
            if i < len(row):
                d[col] = row[i]
        d["tags"] = json.loads(d.get("tags") or "[]")
        for k in ("vector", "quantized", "q_signs"):
            d.pop(k, None)
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Background Crawler
# ─────────────────────────────────────────────────────────────────────────────

class _BackgroundCrawler:
    """
    Follows xrefs from known blackboard addresses, discovers new functions,
    classifies them, and proposes them as blackboard entries.

    Proposals are queued in _pending. The LLM can accept/reject via
    blackboard(action="accept"|"reject", proposal_id=...).

    When a proposal is accepted, it's written to the blackboard.
    When running inside IDA, it also sends an MCP notification so the LLM
    sees a popup-style prompt.
    """

    _instance: Optional["_BackgroundCrawler"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pending: Dict[str, Dict] = {}  # proposal_id -> proposal
        self._visited: set = set()
        self._notify_fn = None  # injected by server to send MCP notifications

    @classmethod
    def instance(cls, db_path: Optional[str] = None) -> "_BackgroundCrawler":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
            return cls._instance

    def start(self, notify_fn=None) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        if notify_fn:
            self._notify_fn = notify_fn
        self._thread = threading.Thread(
            target=self._crawl_loop, daemon=True, name="bb-crawler"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def pending_proposals(self) -> List[Dict]:
        return list(self._pending.values())

    def accept(self, proposal_id: str) -> Optional[str]:
        p = self._pending.pop(proposal_id, None)
        if not p:
            return None
        store = BlackboardStore(self._db_path)
        return store.write(
            title=p["title"],
            content=p.get("content", ""),
            category=p.get("category", "general"),
            addr=p.get("addr", ""),
            tags=p.get("tags", []),
            confidence=p.get("confidence", 0.6),
            source="crawler.accepted",
        )

    def reject(self, proposal_id: str) -> bool:
        return bool(self._pending.pop(proposal_id, None))

    def _crawl_loop(self) -> None:
        """Main crawler loop: runs every 30s, follows xrefs from known addresses."""
        while not self._stop_event.wait(30):
            try:
                self._crawl_step()
            except Exception:
                pass

    def _crawl_step(self) -> None:
        store = BlackboardStore(self._db_path)
        # Get all known addresses from the blackboard
        entries = store.list(limit=500, include_resolved=False)
        known_addrs = {e["addr"] for e in entries if e.get("addr")}

        try:
            import idautils
            import idaapi
            import idc
            import ida_funcs
        except ImportError:
            return  # Not running inside IDA

        new_proposals = []

        for addr_str in list(known_addrs)[:50]:  # cap per cycle
            if self._stop_event.is_set():
                break
            try:
                ea = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            except (ValueError, TypeError):
                continue

            if ea in self._visited:
                continue
            self._visited.add(ea)

            # Follow xrefs FROM this address
            try:
                for xref in idautils.XrefsFrom(ea, 0):
                    target = xref.to
                    target_hex = hex(target)
                    if target_hex in known_addrs or target in self._visited:
                        continue
                    fn = ida_funcs.get_func(target)
                    if not fn:
                        continue
                    fname = idc.get_func_name(fn.start_ea) or target_hex
                    # Skip already-named library functions
                    if not fname.startswith("sub_") and not fname.startswith("0x"):
                        continue

                    # Classify the target function
                    behavior_tags = []
                    try:
                        import ida_hexrays
                        cfunc = ida_hexrays.decompile(fn.start_ea)
                        if cfunc:
                            pseudo = str(cfunc)
                            try:
                                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
                            except ImportError:
                                from host.intelligence import BgeCodeEmbedder, BehaviorClassifier  # type: ignore
                            embedder = BgeCodeEmbedder()
                            classifier = BehaviorClassifier.instance(embedder)
                            hits = classifier.classify(pseudo, threshold=0.4, top_k=2, block=False)
                            behavior_tags = [h["behavior"] for h in hits]
                    except Exception:
                        pass

                    if not behavior_tags:
                        continue  # Only propose if we have something interesting to say

                    pid = str(uuid.uuid4())[:8]
                    proposal = {
                        "proposal_id": pid,
                        "addr": hex(fn.start_ea),
                        "title": f"Discovered via xref from {addr_str}: {fname} [{', '.join(behavior_tags)}]",
                        "content": f"Reachable from {addr_str}. Behavior: {', '.join(behavior_tags)}",
                        "category": behavior_tags[0] if behavior_tags else "general",
                        "tags": ["crawler", "xref"] + behavior_tags,
                        "confidence": 0.65,
                        "source_addr": addr_str,
                        "behavior_tags": behavior_tags,
                    }
                    self._pending[pid] = proposal
                    new_proposals.append(proposal)
            except Exception:
                continue

        # Send MCP notification for new proposals
        if new_proposals and self._notify_fn:
            try:
                self._notify_fn({
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {
                        "level": "info",
                        "logger": "blackboard.crawler",
                        "data": {
                            "message": f"Crawler found {len(new_proposals)} new interesting functions",
                            "proposals": [
                                {
                                    "proposal_id": p["proposal_id"],
                                    "addr": p["addr"],
                                    "title": p["title"],
                                    "behavior_tags": p["behavior_tags"],
                                }
                                for p in new_proposals[:5]
                            ],
                            "action": "Use blackboard(action='accept', proposal_id=...) or blackboard(action='reject', proposal_id=...) for each proposal.",
                        },
                    },
                })
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Auto-capture helpers (called by memory.py and calc.py)
# ─────────────────────────────────────────────────────────────────────────────

def auto_capture_memory(result: Dict, addr: str = "", db_path: Optional[str] = None) -> None:
    try:
        store = BlackboardStore(db_path=db_path)
        action = result.get("_action", "")
        ptrs = result.get("pointers") or result.get("pointer_list") or []
        if ptrs and isinstance(ptrs, list):
            for p in ptrs[:20]:
                if not isinstance(p, dict):
                    continue
                ptr_addr = str(p.get("addr") or p.get("ea") or "")
                target = str(p.get("target") or p.get("value") or "")
                name = str(p.get("name") or "")
                if not ptr_addr or not target:
                    continue
                title = f"Pointer {ptr_addr} → {target}" + (f" ({name})" if name else "")
                if not store.exists_similar(ptr_addr, "pointer", title):
                    store.write(title=title, content=json.dumps(p), category="pointer",
                                addr=ptr_addr, tags=["auto", "pointer", "memory"],
                                confidence=0.8, source="memory.auto")
        strings = result.get("strings") or []
        if strings and isinstance(strings, list):
            for s in strings[:30]:
                if not isinstance(s, dict):
                    continue
                s_addr = str(s.get("addr") or s.get("ea") or "")
                value = str(s.get("value") or s.get("string") or "")
                if not value or len(value) < 4:
                    continue
                title = f"String @ {s_addr}: {value[:80]}"
                if not store.exists_similar(s_addr, "string", title):
                    store.write(title=title, content=value, category="string",
                                addr=s_addr, tags=["auto", "string", "memory"],
                                confidence=0.7, source="memory.auto")
        entropy = result.get("entropy")
        if entropy and isinstance(entropy, (int, float)) and entropy > 7.0:
            title = f"High entropy region @ {addr} (H={entropy:.2f})"
            if not store.exists_similar(addr, "entropy", title):
                store.write(title=title,
                            content=f"Shannon entropy {entropy:.4f} — likely packed/encrypted",
                            category="entropy", addr=addr,
                            tags=["auto", "entropy", "packed"],
                            confidence=0.75, source="memory.auto")
    except Exception:
        pass


def auto_capture_calc(result: Dict, db_path: Optional[str] = None) -> None:
    try:
        store = BlackboardStore(db_path=db_path)
        action = result.get("_action", "")
        resolved = result.get("resolved") or result.get("va") or result.get("address")
        if resolved:
            addr_str = str(resolved)
            name = str(result.get("name") or result.get("symbol") or "")
            title = f"Resolved address: {addr_str}" + (f" ({name})" if name else "")
            if not store.exists_similar(addr_str, "address", title):
                store.write(title=title,
                            content=json.dumps({k: v for k, v in result.items() if k != "_action"}),
                            category="address", addr=addr_str,
                            tags=["auto", "calc", "resolved"],
                            confidence=0.85, source="calc.auto")
        chain = result.get("chain") or result.get("pointer_chain") or []
        if chain and isinstance(chain, list) and len(chain) >= 2:
            start = str(chain[0].get("addr") or chain[0]) if isinstance(chain[0], dict) else str(chain[0])
            end_item = chain[-1]
            end = str(end_item.get("addr") or end_item) if isinstance(end_item, dict) else str(end_item)
            title = f"Pointer chain {start} → ... → {end} ({len(chain)} hops)"
            if not store.exists_similar(start, "pointer_chain", title):
                store.write(title=title, content=json.dumps(chain),
                            category="pointer_chain", addr=start,
                            tags=["auto", "calc", "chain", "pointer"],
                            confidence=0.8, source="calc.auto")
        deref_val = result.get("value") or result.get("deref")
        deref_addr = result.get("addr") or result.get("address")
        if deref_val and deref_addr and action in ("deref", "chain"):
            title = f"Deref {deref_addr} = {deref_val}"
            if not store.exists_similar(str(deref_addr), "deref", title):
                store.write(title=title, content=json.dumps(result),
                            category="deref", addr=str(deref_addr),
                            tags=["auto", "calc", "deref"],
                            confidence=0.75, source="calc.auto")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# MCP tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def blackboard(
    action: str = "list",
    entry_id: str = "",
    title: str = "",
    content: str = "",
    category: str = "general",
    addr: str = "",
    addr_end: str = "",
    tags: Optional[List[str]] = None,
    confidence: float = 0.5,
    tag: str = "",
    query: str = "",
    min_confidence: float = 0.0,
    limit: int = 100,
    offset: int = 0,
    db_path: str = "",
    max_entries: int = 1000,
    min_q_value: float = 0.0,
    older_than_days: int = 0,
    top_k: int = 10,
    threshold: float = 0.4,
    reason: str = "",
    proposal_id: str = "",
    ioc_type: str = "",
    ioc_value: str = "",
    depends_on: str = "",
    blocks_addr: str = "",
    register: str = "",
    reg_type: str = "",
    include_resolved: bool = False,
    include_contradicted: bool = False,
    **kwargs,
) -> dict:
    """
    Persistent, self-maintaining analysis context for firmware RE.

    Extended categories: region, ioc, dead_end, dependency, data_flow,
    contradiction, hypothesis, cluster, rename_suggestion, pointer, string,
    entropy, address, pointer_chain, deref, session_diff.

    Actions:
      write          - Pin a finding. Returns entry_id.
      read           - Get entry by ID.
      list           - List entries (filter by category, addr, tag).
      search         - Semantic search (bge-code-v1 cosine or substring fallback).
      update         - Modify an entry.
      delete         - Remove an entry.
      clear          - Remove all (or by category).
      stats          - Counts, categories, IOCs, resolved/contradicted.
      prune          - Evict low-quality or old entries.
      merge          - Deduplicate similar entries.
      contradict     - Mark entry as contradicted with reason.
      resolve        - Mark entry as resolved/dead-end.
      next_target    - Return highest-priority unexplored addresses.
      start_crawler  - Start background xref crawler.
      stop_crawler   - Stop background xref crawler.
      crawler_status - Show crawler state and pending proposals.
      accept         - Accept a crawler proposal (writes to blackboard).
      reject         - Reject a crawler proposal.

    Firmware RE examples:
      # Annotate a memory region
      blackboard(action="write", category="region", title="TCP/IP stack",
                 addr="0x80400000", addr_end="0x80410000", confidence=0.85)

      # Record an IOC
      blackboard(action="write", category="ioc", title="Hardcoded C2 IP",
                 ioc_type="ip_port", ioc_value="192.168.100.1:8080",
                 addr="0x80412340", confidence=0.99)

      # Mark a dead end
      blackboard(action="write", category="dead_end",
                 title="0x8041500 is memset wrapper — skip",
                 addr="0x8041500")
      blackboard(action="resolve", entry_id="abc123")

      # Record a dependency
      blackboard(action="write", category="dependency",
                 title="Must understand 0x8040100 before 0x8041200",
                 addr="0x8041200", depends_on="0x8040100")

      # Record data flow
      blackboard(action="write", category="data_flow",
                 title="r3 into 0x8041200 = packet buffer ptr",
                 addr="0x8041200", register="r3", reg_type="packet_buffer*")

      # Contradict a prior hypothesis
      blackboard(action="contradict", entry_id="abc123",
                 reason="Found it calls malloc — not a custom allocator")

      # Get next analysis target
      blackboard(action="next_target")

      # Start background crawler
      blackboard(action="start_crawler")
    """
    store = BlackboardStore(db_path=db_path or None)

    if action == "write":
        if not title:
            return {"ok": False, "error": "title required"}
        eid = store.write(
            title, content, category, addr, addr_end, tags, confidence,
            source="manual", ioc_type=ioc_type, ioc_value=ioc_value,
            depends_on=depends_on, blocks_addr=blocks_addr,
            register=register, reg_type=reg_type,
        )
        return {"ok": True, "entry_id": eid}

    elif action == "read":
        if not entry_id:
            return {"ok": False, "error": "entry_id required"}
        entry = store.read(entry_id)
        return {"ok": True, "entry": entry} if entry else {"ok": False, "error": f"Entry '{entry_id}' not found"}

    elif action == "list":
        entries = store.list(
            category=category or None, addr=addr or None,
            tag=tag or None, min_confidence=min_confidence,
            limit=limit, offset=offset,
            include_resolved=include_resolved,
            include_contradicted=include_contradicted,
            ioc_type=ioc_type or None,
        )
        return {"ok": True, "entries": entries, "count": len(entries)}

    elif action == "search":
        if not query:
            return {"ok": False, "error": "query required"}
        results = store.semantic_search(
            query=query, top_k=top_k, threshold=threshold,
            category=category or None,
            include_resolved=include_resolved,
            include_contradicted=include_contradicted,
        )
        return {"ok": True, "results": results, "count": len(results)}

    elif action == "update":
        if not entry_id:
            return {"ok": False, "error": "entry_id required"}
        fields: Dict = {}
        if title: fields["title"] = title
        if content: fields["content"] = content
        if category and category != "general": fields["category"] = category
        if addr: fields["addr"] = addr
        if tags is not None: fields["tags"] = tags
        if confidence != 0.5: fields["confidence"] = confidence
        fields.update({k: v for k, v in kwargs.items()
                       if k in {"title","content","category","addr","confidence","q_value","resolved"}})
        if not fields:
            return {"ok": False, "error": "No fields to update"}
        ok = store.update(entry_id, **fields)
        return {"ok": ok} if ok else {"ok": False, "error": f"Entry '{entry_id}' not found"}

    elif action == "delete":
        if not entry_id:
            return {"ok": False, "error": "entry_id required"}
        ok = store.delete(entry_id)
        return {"ok": ok} if ok else {"ok": False, "error": f"Entry '{entry_id}' not found"}

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

    elif action == "contradict":
        if not entry_id:
            return {"ok": False, "error": "entry_id required"}
        if not reason:
            return {"ok": False, "error": "reason required"}
        ok = store.contradict(entry_id, reason)
        return {"ok": ok} if ok else {"ok": False, "error": f"Entry '{entry_id}' not found"}

    elif action == "resolve":
        if not entry_id:
            return {"ok": False, "error": "entry_id required"}
        ok = store.mark_resolved(entry_id)
        return {"ok": ok} if ok else {"ok": False, "error": f"Entry '{entry_id}' not found"}

    elif action == "next_target":
        targets = store.next_target(limit=limit or 5)
        return {"ok": True, "targets": targets, "count": len(targets),
                "note": "Highest-priority unexplored addresses. Use code(action='decompile') on the top target."}

    elif action == "start_crawler":
        crawler = _BackgroundCrawler.instance(db_path=db_path or None)
        crawler.start()
        return {"ok": True, "running": crawler.is_running(),
                "note": "Crawler follows xrefs from known blackboard addresses every 30s. Use crawler_status to see proposals."}

    elif action == "stop_crawler":
        crawler = _BackgroundCrawler.instance()
        crawler.stop()
        return {"ok": True, "running": False}

    elif action == "crawler_status":
        crawler = _BackgroundCrawler.instance()
        proposals = crawler.pending_proposals()
        return {
            "ok": True,
            "running": crawler.is_running(),
            "pending_proposals": len(proposals),
            "proposals": proposals[:10],
            "note": "Use blackboard(action='accept', proposal_id=...) or blackboard(action='reject', proposal_id=...) for each proposal.",
        }

    elif action == "accept":
        if not proposal_id:
            return {"ok": False, "error": "proposal_id required"}
        crawler = _BackgroundCrawler.instance()
        eid = crawler.accept(proposal_id)
        return {"ok": bool(eid), "entry_id": eid} if eid else {"ok": False, "error": f"Proposal '{proposal_id}' not found"}

    elif action == "reject":
        if not proposal_id:
            return {"ok": False, "error": "proposal_id required"}
        crawler = _BackgroundCrawler.instance()
        ok = crawler.reject(proposal_id)
        return {"ok": ok} if ok else {"ok": False, "error": f"Proposal '{proposal_id}' not found"}

    else:
        return {"ok": False, "error": f"Unknown action: {action}"}
