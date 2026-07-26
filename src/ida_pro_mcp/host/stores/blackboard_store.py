"""Blackboard SQLite store — extracted from the legacy IDA plugin package.

Hosts the :class:`BlackboardStore` class used by the standalone host server
to persist firmware RE findings, hypotheses, IOCs, and knowledge-graph
nodes. The plugin-only tool entry point, auto-capture helpers, and
background crawler live elsewhere in the host package.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import sqlite3
import tempfile
import time
import uuid
from contextlib import closing
from typing import Any

from ..intelligence.helpers import quantile as _quantile

_INTERNAL_WORKSPACE_CATEGORIES = frozenset(
    {"evidence_gravity", "wm_now", "quest_log", "proposal_feedback"}
)
_INTERNAL_WORKSPACE_SOURCE_TYPES = frozenset(
    {"evidence_gravity", "gravity", "auto_enrich", "proposal_feedback"}
)


def _resolve_db_path(db_path: str | None = None) -> str:
    if db_path is not None:
        resolved = str(db_path).strip()
        if not resolved:
            raise ValueError("blackboard db_path is required")
        return resolved
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
    for candidate in (root, os.path.join(tempfile.gettempdir(), "ida-pro-mcp")):
        try:
            os.makedirs(candidate, exist_ok=True)
            probe = os.path.join(candidate, ".write_probe")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            os.unlink(probe)
            return os.path.join(candidate, "blackboard.db")
        except Exception:
            continue
    return os.path.join(root, "blackboard.db")


def _get_embedder():
    try:
        from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder
        return BgeCodeEmbedder()
    except ImportError:
        try:
            from host.intelligence.core import BgeCodeEmbedder  # type: ignore
            return BgeCodeEmbedder()
        except ImportError:
            return None


def _pack_vec(vec: list[float]) -> bytes:
    from .intelligence.helpers import pack_floats
    return pack_floats(vec)


def _unpack_vec(blob: bytes) -> list[float]:
    from .intelligence.helpers import unpack_floats
    return unpack_floats(blob)


def _cosine(a: list[float], b: list[float]) -> float:
    from .intelligence.helpers import dot_product
    return dot_product(a, b)


class BlackboardStore:
    """SQLite-backed blackboard with extended firmware RE schema."""

    def __init__(self, db_path: str | None = None):
        primary_path = _resolve_db_path(db_path)
        self.db_path = primary_path
        try:
            parent = os.path.dirname(self.db_path) or "."
            os.makedirs(parent, exist_ok=True)
            # Verify writability by connecting to the primary path
            with closing(self._conn()):
                pass
            self._init_db()
        except (sqlite3.OperationalError, OSError, PermissionError):
            try:
                from .config import CACHE_DIR
            except ImportError:
                try:
                    from host.config import CACHE_DIR
                except ImportError:
                    xdg = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
                    CACHE_DIR = os.path.join(xdg, "ida-pro-mcp")

            h = hashlib.sha256(os.path.abspath(primary_path).encode("utf-8")).hexdigest()[:16]
            fallback_dir = os.path.join(CACHE_DIR, "fallback_indexes")
            os.makedirs(fallback_dir, exist_ok=True)
            self.db_path = os.path.join(fallback_dir, f"{h}.blackboard.db")
            self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with closing(self._conn()) as conn:
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
                    reg_type     TEXT,
                    -- v3 fields
                    evidence     TEXT DEFAULT '[]',  -- JSON list of {type,value,weight}
                    source_type  TEXT DEFAULT 'manual',  -- engine_classifier|engine_taint|engine_cross_session|human|crawler
                    version      INTEGER DEFAULT 1,  -- incremented on every update
                    entropy      REAL DEFAULT 0.0,   -- byte entropy of region (0-8)
                    xref_count   INTEGER DEFAULT 0,  -- number of callers (for seeding)
                    calibrated   INTEGER DEFAULT 0   -- 1 if confidence has been calibrated
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
                # v3
                ("evidence", "TEXT DEFAULT '[]'"),
                ("source_type", "TEXT DEFAULT 'manual'"),
                ("version", "INTEGER DEFAULT 1"),
                ("entropy", "REAL DEFAULT 0.0"),
                ("xref_count", "INTEGER DEFAULT 0"),
                ("calibrated", "INTEGER DEFAULT 0"),
                # Investigation-workspace fields. Legacy rows remain valid.
                ("kind", "TEXT DEFAULT 'finding'"),
                ("status", "TEXT DEFAULT 'open'"),
                ("priority", "REAL DEFAULT 0.5"),
                ("fingerprint", "TEXT DEFAULT ''"),
                # Legacy compat
                ("bridges", "TEXT DEFAULT '{}'"),
                ("schema", "TEXT DEFAULT '{}'"),
                ("quantized", "BLOB"),
                ("q_signs", "BLOB"),
                ("norm", "REAL DEFAULT 0.0"),
                ("call_idx", "INTEGER DEFAULT 0"),
                # When confidence decay last ran for this row. Kept separate
                # from updated_at so decaying an entry does not make it look
                # freshly edited.
                ("decayed_at", "REAL"),
            ]:
                if col not in existing:
                    conn.execute(f"ALTER TABLE blackboard ADD COLUMN {col} {dtype}")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_category ON blackboard(category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_addr ON blackboard(addr)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_tags ON blackboard(tags)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_resolved ON blackboard(resolved)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_ioc ON blackboard(ioc_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_source_type ON blackboard(source_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_xref ON blackboard(xref_count)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_kind_status ON blackboard(kind, status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_fingerprint ON blackboard(fingerprint)")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_bb_fingerprint_unique "
                "ON blackboard(fingerprint) WHERE fingerprint != ''"
            )
            conn.execute("UPDATE blackboard SET status='resolved' WHERE resolved=1 AND status='open'")
            conn.execute("UPDATE blackboard SET status='rejected' WHERE contradicted=1 AND status='open'")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS finding_events (
                    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id   TEXT NOT NULL,
                    event      TEXT NOT NULL,
                    details    TEXT DEFAULT '{}',
                    created_at REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_events_entry ON finding_events(entry_id, seq)")
            conn.commit()

    def _get_embedder(self):
        return _get_embedder()

    def _embed_text(self, text: str) -> bytes | None:
        embedder = self._get_embedder()
        if embedder is None:
            return None
        try:
            vec = embedder.embed_vector(text)
            if vec is None:
                raise RuntimeError("embedding unavailable")
            return _pack_vec(vec)
        except Exception:
            return None



    def write(
        self,
        title: str,
        content: str = "",
        category: str = "general",
        addr: str = "",
        addr_end: str = "",
        tags: builtins.list[str] | None = None,
        confidence: float = 0.5,
        source: str = "manual",
        embed: bool = False,
        ioc_type: str = "",
        ioc_value: str = "",
        depends_on: str = "",
        blocks_addr: str = "",
        register: str = "",
        reg_type: str = "",
        evidence: builtins.list[dict] | None = None,
        source_type: str = "",
        entropy: float = 0.0,
        xref_count: int = 0,
        kind: str = "finding",
        status: str = "open",
        priority: float = 0.5,
        fingerprint: str = "",
        **_legacy_kwargs,
    ) -> str:
        kind = str(kind or "finding").strip().lower()
        status = str(status or "open").strip().lower()
        if kind not in {"finding", "hypothesis", "question", "task", "decision"}:
            raise ValueError("kind must be finding, hypothesis, question, task, or decision")
        if status not in {"open", "confirmed", "resolved", "rejected"}:
            raise ValueError("status must be open, confirmed, resolved, or rejected")
        entry_id = str(uuid.uuid4())[:8]
        now = time.time()
        vector_blob = None
        if embed:
            vector_blob = self._embed_text(f"{title} {content}".strip())
        # source_type defaults to source for backward compat
        if not source_type:
            source_type = source
        with closing(self._conn()) as conn:
            conn.execute("""
                INSERT INTO blackboard
                    (id, category, title, content, addr, addr_end, tags, confidence,
                     created_at, updated_at, q_value, source, vector,
                     ioc_type, ioc_value, depends_on, blocks_addr, register, reg_type,
                     evidence, source_type, entropy, xref_count, version,
                     kind, status, priority, fingerprint, resolved, contradicted)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                entry_id, category, title, content, addr, addr_end,
                json.dumps(tags or []), confidence,
                now, now, confidence, source, vector_blob,
                ioc_type, ioc_value, depends_on, blocks_addr, register, reg_type,
                json.dumps(evidence or []), source_type, entropy, xref_count, 1,
                kind, status, priority, fingerprint,
                int(status == "resolved"), int(status == "rejected"),
            ))
            conn.commit()
        self._record_event(entry_id, "created", {"kind": kind, "status": status})
        return entry_id

    @staticmethod
    def _finding_key(title: str, category: str, addr: str) -> tuple[str, str, str]:
        """Return the stable identity used to coalesce repeated observations."""
        normalized_title = " ".join(str(title).lower().split())
        normalized_category = str(category or "general").strip().lower()
        normalized_addr = str(addr or "").strip().lower()
        return normalized_title, normalized_category, normalized_addr

    @classmethod
    def _finding_fingerprint(cls, title: str, category: str, addr: str, kind: str) -> str:
        key = (*cls._finding_key(title, category, addr), str(kind or "finding").strip().lower())
        return hashlib.sha256("\x1f".join(key).encode("utf-8")).hexdigest()[:24]

    def _record_event(self, entry_id: str, event: str, details: dict[str, Any] | None = None) -> None:
        with closing(self._conn()) as conn:
            conn.execute(
                "INSERT INTO finding_events(entry_id, event, details, created_at) VALUES (?,?,?,?)",
                (entry_id, event, json.dumps(details or {}, sort_keys=True, ensure_ascii=True), time.time()),
            )
            conn.commit()

    def upsert_finding(
        self,
        title: str,
        content: str = "",
        category: str = "general",
        addr: str = "",
        tags: builtins.list[str] | None = None,
        confidence: float = 0.5,
        evidence: builtins.list[dict] | None = None,
        source: str = "manual",
        kind: str = "finding",
        status: str = "open",
        priority: float = 0.5,
    ) -> dict[str, Any]:
        """Create a finding or merge it into the same address/category/title."""
        key = self._finding_key(title, category, addr)
        fingerprint = self._finding_fingerprint(title, category, addr, kind)
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT * FROM blackboard WHERE fingerprint=? OR "
                "(lower(category)=? AND lower(COALESCE(addr,''))=?) "
                "ORDER BY updated_at DESC LIMIT 200",
                (fingerprint, key[1], key[2]),
            ).fetchall()
        existing = next(
            (row for row in (self._row_to_dict(item) for item in rows)
             if row.get("fingerprint") == fingerprint or (
                 self._finding_key(row.get("title", ""), row.get("category", ""), row.get("addr", "")) == key
                 and str(row.get("kind") or "finding") == str(kind or "finding")
             )),
            None,
        )
        clean_tags = sorted({str(tag).strip() for tag in (tags or []) if str(tag).strip()})
        clean_evidence = [item for item in (evidence or []) if isinstance(item, dict)]
        if existing is None:
            try:
                entry_id = self.write(
                    title=title,
                    content=content,
                    category=category,
                    addr=addr,
                    tags=clean_tags,
                    confidence=max(0.0, min(1.0, float(confidence))),
                    evidence=clean_evidence,
                    source=source,
                    source_type=source,
                    embed=False,
                    kind=kind,
                    status=status,
                    priority=max(0.0, min(1.0, float(priority))),
                    fingerprint=fingerprint,
                )
            except sqlite3.IntegrityError:
                # Another client recorded the same observation between our
                # lookup and insert. Re-read and merge into the winner.
                return self.upsert_finding(
                    title=title,
                    content=content,
                    category=category,
                    addr=addr,
                    tags=clean_tags,
                    confidence=confidence,
                    evidence=clean_evidence,
                    source=source,
                    kind=kind,
                    status=status,
                    priority=priority,
                )
            return {"entry_id": entry_id, "created": True, "version": 1}

        # Serialize read/merge/write so simultaneous LLM clients cannot lose
        # each other's evidence through a last-writer-wins update.
        with closing(self._conn()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM blackboard WHERE fingerprint=? ORDER BY updated_at DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if row is None:
                row = conn.execute(
                    "SELECT * FROM blackboard WHERE id=?",
                    (str(existing["id"]),),
                ).fetchone()
            self._col_cache = [item[1] for item in conn.execute("PRAGMA table_info(blackboard)").fetchall()]
            current = self._row_to_dict(row) if row else existing
            merged_tags = sorted(set(current.get("tags") or []) | set(clean_tags))
            merged_evidence = list(current.get("evidence") or [])
            seen_evidence = {json.dumps(item, sort_keys=True, ensure_ascii=True) for item in merged_evidence}
            for item in clean_evidence:
                marker = json.dumps(item, sort_keys=True, ensure_ascii=True)
                if marker not in seen_evidence:
                    merged_evidence.append(item)
                    seen_evidence.add(marker)
            current_status = str(current.get("status") or "open")
            merged_status = status if current_status == "open" and status != "open" else current_status
            merged_content = str(current.get("content") or "")
            if str(content).strip() and str(content).strip() != merged_content.strip():
                merged_content = str(content).strip()
            now = time.time()
            conn.execute(
                "UPDATE blackboard SET content=?, tags=?, evidence=?, confidence=?, priority=?, "
                "kind=?, status=?, resolved=?, contradicted=?, fingerprint=?, updated_at=?, version=? WHERE id=?",
                (
                    merged_content,
                    json.dumps(merged_tags),
                    json.dumps(merged_evidence),
                    max(float(current.get("confidence") or 0.0), 0.0, min(1.0, float(confidence))),
                    max(float(current.get("priority") or 0.0), 0.0, min(1.0, float(priority))),
                    kind,
                    merged_status,
                    int(merged_status == "resolved"),
                    int(merged_status == "rejected"),
                    fingerprint,
                    now,
                    int(current.get("version") or 1) + 1,
                    str(current["id"]),
                ),
            )
            conn.commit()
        self._record_event(str(current["id"]), "observation_merged", {"source": source})
        refreshed = self.read(str(current["id"])) or current
        return {
            "entry_id": str(current["id"]),
            "created": False,
            "version": int(refreshed.get("version") or 1),
        }

    def read(self, entry_id: str) -> dict | None:
        with closing(self._conn()) as conn:
            row = conn.execute("SELECT * FROM blackboard WHERE id = ?", (entry_id,)).fetchone()
            return self._row_to_dict(row) if row else None

    def list(
        self,
        category: str | None = None,
        addr: str | None = None,
        tag: str | None = None,
        min_confidence: float = 0.0,
        limit: int = 100,
        offset: int = 0,
        include_resolved: bool = True,
        include_contradicted: bool = False,
        ioc_type: str | None = None,
        kind: str | None = None,
        status: str | None = None,
    ) -> builtins.list[dict]:
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
        if kind:
            conditions.append("kind = ?")
            params.append(kind)
        if status:
            conditions.append("status = ?")
            params.append(status)
        where = "WHERE " + " AND ".join(conditions)
        with closing(self._conn()) as conn:
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
        category: str | None = None,
        include_resolved: bool = True,
        include_contradicted: bool = False,
    ) -> builtins.list[dict]:
        def lexical_search() -> builtins.list[dict]:
            q = query.lower()
            terms = {term for term in q.split() if len(term) > 1}
            with closing(self._conn()) as conn:
                rows = conn.execute("SELECT * FROM blackboard ORDER BY updated_at DESC LIMIT 200").fetchall()
            results = []
            for row in rows:
                d = self._row_to_dict(row)
                if not include_resolved and d.get("resolved"):
                    continue
                if not include_contradicted and d.get("contradicted"):
                    continue
                if category and d.get("category") != category:
                    continue
                text = f"{d.get('title','')} {d.get('content','')}".lower()
                matched = sum(1 for term in terms if term in text)
                if q in text or (terms and matched):
                    d["similarity"] = 1.0 if q in text else round(matched / len(terms), 4)
                    results.append(d)
            results.sort(key=lambda item: (item["similarity"], item.get("updated_at", 0)), reverse=True)
            return results[:top_k]

        with closing(self._conn()) as conn:
            has_vectors = bool(
                conn.execute("SELECT 1 FROM blackboard WHERE vector IS NOT NULL LIMIT 1").fetchone()
            )
        if not has_vectors:
            return lexical_search()

        embedder = self._get_embedder()
        if embedder is None:
            return lexical_search()

        try:
            q_vec = embedder.embed_vector(query)
            if q_vec is None:
                raise RuntimeError("embedding unavailable")
        except Exception:
            return lexical_search()

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

        with closing(self._conn()) as conn:
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

        if not scored:
            return lexical_search()
        scored.sort(key=lambda x: x["similarity"], reverse=True)
        return scored[:top_k]

    def contradict(self, entry_id: str, reason: str) -> bool:
        with closing(self._conn()) as conn:
            cur = conn.execute(
                "UPDATE blackboard SET contradicted=1, status='rejected', contradiction_reason=?, updated_at=? WHERE id=?",
                (reason, time.time(), entry_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def mark_resolved(self, entry_id: str) -> bool:
        with closing(self._conn()) as conn:
            cur = conn.execute(
                "UPDATE blackboard SET resolved=1, status='resolved', updated_at=? WHERE id=?",
                (time.time(), entry_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def add_evidence(self, entry_id: str, evidence_type: str, value: str,
                     weight: float = 1.0) -> bool:
        """
        Append a structured evidence record to an entry.

        evidence_type: 'constant', 'string', 'import', 'xref', 'decompile',
                       'classifier', 'taint', 'cross_session', 'human'
        value: the evidence value (e.g. '0x63636363', 'AES_KEY_SCHEDULE', ...)
        weight: 0.0–1.0, how strongly this evidence supports the conclusion
        """
        entry = self.read(entry_id)
        if not entry:
            return False
        ev_list = entry.get("evidence") or []
        ev_list.append({"type": evidence_type, "value": str(value),
                        "weight": round(float(weight), 3),
                        "ts": round(time.time(), 1)})
        return self.update(entry_id, evidence=ev_list)

    def calibrate_confidence(self, entry_id: str) -> float | None:
        """
        Recalculate confidence from evidence weights.

        confidence = weighted average of evidence weights, clamped to [0.1, 0.99].
        Marks entry as calibrated=1.
        """
        entry = self.read(entry_id)
        if not entry:
            return None
        ev_list = entry.get("evidence") or []
        if not ev_list:
            return entry.get("confidence")
        weights = [e.get("weight", 0.5) for e in ev_list]
        new_conf = round(max(0.1, min(0.99, sum(weights) / len(weights))), 3)
        self.update(entry_id, confidence=new_conf, calibrated=1)
        return new_conf

    def decay_stale_confidence(self, half_life_days: float = 14.0, min_confidence: float = 0.1) -> int:
        """Reduce confidence on entries that haven't been updated recently.

        Uses exponential decay: conf *= exp(-elapsed_days * ln(2) / half_life_days).
        Entries with evidence or calibration are decayed more slowly (0.5x rate).
        Returns the number of entries updated.

        ``elapsed`` is measured from the later of the last edit and the last
        decay run, so repeated runs compound correctly instead of re-applying
        the full age each time. Only ``decayed_at`` is written: updating
        ``updated_at`` here would both make a stale entry sort as the most
        recently touched and reset its own age, so it could never decay twice.
        """
        import math
        now = time.time()
        decay_rate = math.log(2) / max(half_life_days, 1.0)
        updated = 0
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT id, confidence, updated_at, decayed_at, calibrated, "
                "json_extract(COALESCE(evidence, '[]'), '$') as ev "
                "FROM blackboard WHERE confidence > ?",
                (min_confidence,),
            ).fetchall()
            for row in rows:
                eid, conf, updated_at, decayed_at, calibrated, ev_json = row
                if conf is None or conf <= min_confidence:
                    continue
                since = max(updated_at or now, decayed_at or 0.0)
                elapsed_days = (now - since) / 86400
                if elapsed_days < 1:
                    continue
                rate = decay_rate * (0.5 if calibrated or (ev_json and ev_json != '[]') else 1.0)
                new_conf = round(max(min_confidence, conf * math.exp(-elapsed_days * rate)), 3)
                if new_conf < conf - 0.01:
                    conn.execute(
                        "UPDATE blackboard SET confidence=?, decayed_at=? WHERE id=?",
                        (new_conf, now, eid),
                    )
                    updated += 1
            conn.commit()
        return updated

    def campaign_summary(self) -> dict:
        """
        High-level summary of the RE campaign state.

        Returns: coverage, top findings by category, active hypotheses,
        confirmed IOCs, open vulns, dead ends, and a recommended next action.
        """
        with closing(self._conn()) as conn:
            total = conn.execute("SELECT COUNT(*) FROM blackboard").fetchone()[0]
            resolved = conn.execute("SELECT COUNT(*) FROM blackboard WHERE resolved=1").fetchone()[0]
            contradicted = conn.execute("SELECT COUNT(*) FROM blackboard WHERE contradicted=1").fetchone()[0]
            active = total - resolved - contradicted

            by_cat = dict(conn.execute(
                "SELECT category, COUNT(*) FROM blackboard GROUP BY category"
            ).fetchall())

            top_conf = conn.execute(
                "SELECT title, addr, confidence, category, source_type "
                "FROM blackboard WHERE resolved=0 AND contradicted=0 "
                "ORDER BY confidence DESC LIMIT 5"
            ).fetchall()

            iocs = conn.execute(
                "SELECT ioc_type, ioc_value, addr, confidence "
                "FROM blackboard WHERE category='ioc' AND resolved=0 "
                "ORDER BY confidence DESC LIMIT 10"
            ).fetchall()

            vulns = conn.execute(
                "SELECT title, addr, confidence "
                "FROM blackboard WHERE category='vuln' AND resolved=0 "
                "ORDER BY confidence DESC LIMIT 5"
            ).fetchall()

            # Evidence quality
            ev_rows = conn.execute(
                "SELECT evidence FROM blackboard WHERE evidence != '[]' AND evidence IS NOT NULL"
            ).fetchall()
            total_evidence = sum(len(json.loads(r[0] or "[]")) for r in ev_rows)

            # Source type breakdown
            source_types = dict(conn.execute(
                "SELECT source_type, COUNT(*) FROM blackboard GROUP BY source_type"
            ).fetchall())

        # Recommend next action
        if by_cat.get("vuln", 0) > 0:
            next_action = "Investigate open vulnerabilities — read ida://blackboard/next_target"
        elif by_cat.get("hypothesis", 0) > 0:
            next_action = "Confirm or contradict open hypotheses"
        elif by_cat.get("ioc", 0) > 0:
            next_action = "Trace IOC origins — use taint analysis"
        else:
            next_action = "Start analysis — read ida://state for orientation"

        return {
            "total_entries": total,
            "active_entries": active,
            "resolved": resolved,
            "contradicted": contradicted,
            "by_category": by_cat,
            "source_types": source_types,
            "total_evidence_records": total_evidence,
            "top_findings": [
                {"title": r[0], "addr": r[1], "confidence": r[2],
                 "category": r[3], "source_type": r[4]}
                for r in top_conf
            ],
            "iocs": [
                {"type": r[0], "value": r[1], "addr": r[2], "confidence": r[3]}
                for r in iocs
            ],
            "vulns": [
                {"title": r[0], "addr": r[1], "confidence": r[2]}
                for r in vulns
            ],
            "recommended_next_action": next_action,
        }

    def auto_tag_propagate(self) -> int:
        """
        Propagate tags from high-confidence entries to same-address entries.

        If address 0x401000 has a 'crypto_symmetric' tag with confidence > 0.8,
        all other entries at 0x401000 get that tag added.

        Returns number of entries updated.
        """
        with closing(self._conn()) as conn:
            # Get high-confidence entries with tags and addresses
            rows = conn.execute(
                "SELECT addr, tags FROM blackboard "
                "WHERE confidence > 0.8 AND addr != '' AND addr IS NOT NULL "
                "AND tags != '[]' AND tags IS NOT NULL"
            ).fetchall()

        # Build addr → tag set map
        addr_tags: dict[str, set] = {}
        for addr, tags_json in rows:
            try:
                tags = json.loads(tags_json or "[]")
                if addr not in addr_tags:
                    addr_tags[addr] = set()
                addr_tags[addr].update(t for t in tags if t not in ("manual", "engine", "crawler"))
            except Exception:
                pass

        if not addr_tags:
            return 0

        updated = 0
        with closing(self._conn()) as conn:
            for addr, new_tags in addr_tags.items():
                if not new_tags:
                    continue
                target_rows = conn.execute(
                    "SELECT id, tags FROM blackboard WHERE addr=? AND confidence <= 0.8",
                    (addr,)
                ).fetchall()
                for eid, tags_json in target_rows:
                    try:
                        existing = set(json.loads(tags_json or "[]"))
                        merged = existing | new_tags
                        if merged != existing:
                            conn.execute(
                                "UPDATE blackboard SET tags=?, updated_at=? WHERE id=?",
                                (json.dumps(sorted(merged)), time.time(), eid)
                            )
                            updated += 1
                    except Exception:
                        pass
            conn.commit()
        return updated

    def next_target(self, limit: int = 5, rpc_fn=None, query: str | None = None) -> builtins.list[dict]:
        """
        Return highest-priority unexplored addresses.

        Priority score = confidence * category_boost * dependency_factor * time_decay
          * (1 + xref_boost)

        Time decay: score *= exp(-age_days * 0.05)  — halves every ~14 days
        Xref boost: +0.1 per 10 callers (capped at +0.5)
        Dependency: blocked entries get 0.3x, satisfied deps get 1.5x

        When the blackboard has < 5 entries with addresses, seeds from
        xref-ranked unnamed functions via rpc_fn (if provided).
        """
        import math

        embedder = None
        query_vec = None
        if query and query.strip():
            try:
                embedder = self._get_embedder()
                if embedder is not None:
                    query_vec = embedder.embed_vector(query)
                    if query_vec is None:
                        raise RuntimeError("embedding unavailable")
            except Exception:
                pass

        with closing(self._conn()) as conn:
            rows = conn.execute("""
                SELECT id, addr, category, title, confidence, depends_on,
                       created_at, xref_count, entropy, source_type, vector, content,
                       priority, kind, status
                FROM blackboard
                WHERE resolved=0 AND contradicted=0 AND addr != '' AND addr IS NOT NULL
                ORDER BY confidence DESC
                LIMIT 500
            """).fetchall()

            resolved_addrs = {
                r[0] for r in conn.execute(
                    "SELECT addr FROM blackboard WHERE resolved=1 AND addr != ''"
                ).fetchall()
            }

        now = time.time()
        scored = []
        seen_addrs: set = set()

        # Build adaptive baselines from current unresolved frontier.
        conf_vals = [float(r[4] or 0.0) for r in rows]
        xref_vals = [float(r[7] or 0.0) for r in rows]
        ent_vals = [float(r[8] or 0.0) for r in rows]
        q_conf50 = _quantile(conf_vals, 0.50, default=0.5)
        q_conf75 = _quantile(conf_vals, 0.75, default=0.7)
        q_xref50 = _quantile(xref_vals, 0.50, default=0.0)
        q_xref75 = _quantile(xref_vals, 0.75, default=1.0)
        q_ent50 = _quantile(ent_vals, 0.50, default=0.0)
        q_ent75 = _quantile(ent_vals, 0.75, default=1.0)

        for row in rows:
            eid, addr, cat, title, conf, depends_on, created_at, xref_count, entropy, source_type, vector_blob, content, priority, kind, status = row
            if addr in seen_addrs:
                continue
            seen_addrs.add(addr)

            # Calculate query similarity if query is provided
            query_similarity = 0.0
            if query and query.strip():
                if query_vec is not None and vector_blob is not None:
                    try:
                        vec = _unpack_vec(vector_blob)
                        query_similarity = _cosine(query_vec, vec)
                    except Exception:
                        pass
                else:
                    # Fallback to lexical/keyword check
                    text = f"{title or ''} {content or ''}".lower()
                    if query.lower() in text:
                        query_similarity = 0.5

            # Adaptive confidence baseline around current frontier distribution.
            score = max(1e-6, float(conf or 0.5))
            score *= 0.5 + max(0.0, min(1.0, float(priority or 0.5)))

            # Time decay: smooth half-life derived from confidence spread.
            age_days = (now - (created_at or now)) / 86400
            conf_spread = max(1e-3, q_conf75 - q_conf50)
            half_life_days = max(5.0, min(45.0, 14.0 + (conf_spread * 40.0)))
            score *= math.exp(-age_days * (math.log(2.0) / half_life_days))

            # Dependency factor (preserve hard gating semantics).
            if depends_on and depends_on in resolved_addrs:
                score *= 1.25
            elif depends_on and depends_on not in resolved_addrs:
                score *= 0.35

            # Category prior from observed category quality in this frontier.
            if cat:
                cat_rows = [r for r in rows if str(r[2] or "") == str(cat)]
                if cat_rows:
                    cat_conf = [float(r[4] or 0.0) for r in cat_rows]
                    cat_prior = _quantile(cat_conf, 0.50, default=score)
                    base_prior = _quantile(conf_vals, 0.50, default=0.5)
                    if base_prior > 0:
                        score *= max(0.5, min(1.6, cat_prior / base_prior))

            # Adaptive xref/entropy multipliers from current distributions.
            xref = float(xref_count or 0.0)
            xref_iqr = max(1e-3, q_xref75 - q_xref50)
            xref_sig = 1.0 / (1.0 + math.exp(-((xref - q_xref50) / xref_iqr)))
            score *= (0.85 + 0.55 * xref_sig)

            ent = float(entropy or 0.0)
            ent_iqr = max(1e-3, q_ent75 - q_ent50)
            ent_sig = 1.0 / (1.0 + math.exp(-((ent - q_ent50) / ent_iqr)))
            score *= (0.9 + 0.25 * ent_sig)

            # Blend with query similarity if query is active
            if query and query.strip():
                score = 0.6 * max(0.0, query_similarity) + 0.4 * score

            scored.append({
                "addr": addr,
                "title": title,
                "category": cat,
                "confidence": conf,
                "priority_score": round(score, 4),
                "entry_id": eid,
                "depends_on": depends_on or None,
                "xref_count": xref_count or 0,
                "entropy": entropy or 0.0,
                "source_type": source_type or "manual",
                "kind": kind or "finding",
                "status": status or "open",
                "age_days": round(age_days, 1),
                "semantic_similarity": round(query_similarity, 4) if (query and query.strip()) else None,
            })

        scored.sort(key=lambda x: x["priority_score"], reverse=True)
        result = scored[:limit]

        # Seed with xref-ranked unnamed functions if blackboard is sparse
        if len(result) < limit and rpc_fn:
            try:
                seeded = self._seed_from_xrefs(rpc_fn, seen_addrs, limit - len(result))
                result.extend(seeded)
            except Exception:
                pass

        return result

    def _seed_from_xrefs(self, rpc_fn, seen_addrs: set, limit: int) -> builtins.list[dict]:
        """Seed next_target with xref-ranked unnamed functions when blackboard is sparse."""
        try:
            funcs_result = rpc_fn("data", {"action": "functions", "count": 200})
            funcs = funcs_result.get("functions", []) if isinstance(funcs_result, dict) else []
        except Exception:
            return []

        parsed_funcs = []
        if isinstance(funcs, str):
            for line in funcs.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = [p for p in line.split("  ") if p]
                if len(parts) < 4:
                    continue
                addr = parts[0].strip()
                xref_count = 0
                name = parts[3].strip()
                for p in parts:
                    if p.startswith("xrefs="):
                        try:
                            xref_count = int(p.split("=", 1)[1])
                        except Exception:
                            xref_count = 0
                        break
                parsed_funcs.append({"addr": addr, "name": name, "xref_count": xref_count})
        elif isinstance(funcs, list):
            parsed_funcs = funcs

        candidates = []
        for fn in parsed_funcs:
            name = fn.get("name", "")
            if not (name.startswith(("sub_", "j_"))):
                continue
            addr = fn.get("start_ea") or fn.get("addr")
            if not addr:
                continue
            addr_hex = hex(addr) if isinstance(addr, int) else str(addr)
            if addr_hex in seen_addrs:
                continue
            # Use xref_count from function data if available
            xref_count = fn.get("xref_count") or fn.get("callers_count") or 0
            candidates.append({
                "addr": addr_hex,
                "title": f"Unnamed: {name}",
                "category": "seed",
                "confidence": 0.4,
                "priority_score": round(0.4 + min(0.4, xref_count / 20 * 0.1), 4),
                "entry_id": None,
                "depends_on": None,
                "xref_count": xref_count,
                "entropy": 0.0,
                "source_type": "seed",
                "age_days": 0.0,
            })

        candidates.sort(key=lambda x: x["priority_score"], reverse=True)
        return candidates[:limit]

    def update(self, entry_id: str, embed: bool = False, **kwargs) -> bool:
        allowed = {"title", "content", "category", "addr", "addr_end", "tags",
                   "confidence", "q_value", "resolved", "ioc_type", "ioc_value",
                   "depends_on", "blocks_addr", "register", "reg_type",
                   "evidence", "source_type", "entropy", "xref_count", "calibrated",
                   "kind", "status", "priority", "fingerprint", "contradicted",
                   "contradiction_reason"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        with closing(self._conn()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM blackboard WHERE id=?", (entry_id,)).fetchone()
            if row is None:
                conn.rollback()
                return False
            self._col_cache = [item[1] for item in conn.execute("PRAGMA table_info(blackboard)").fetchall()]
            current = self._row_to_dict(row)
            if "tags" in updates and isinstance(updates["tags"], list):
                updates["tags"] = sorted(
                    set(current.get("tags") or [])
                    | {str(tag).strip() for tag in updates["tags"] if str(tag).strip()}
                )
            if "evidence" in updates and isinstance(updates["evidence"], list):
                merged_evidence = list(current.get("evidence") or [])
                seen = {json.dumps(item, sort_keys=True, ensure_ascii=True) for item in merged_evidence}
                for item in updates["evidence"]:
                    if not isinstance(item, dict):
                        continue
                    marker = json.dumps(item, sort_keys=True, ensure_ascii=True)
                    if marker not in seen:
                        merged_evidence.append(item)
                        seen.add(marker)
                updates["evidence"] = merged_evidence
            updates["updated_at"] = time.time()
            updates["version"] = int(current.get("version") or 1) + 1
            if "tags" in updates:
                updates["tags"] = json.dumps(updates["tags"])
            if "evidence" in updates:
                updates["evidence"] = json.dumps(updates["evidence"])
            if embed and ("title" in updates or "content" in updates):
                t = updates.get("title", current.get("title", ""))
                c = updates.get("content", current.get("content", ""))
                blob = self._embed_text(f"{t} {c}".strip())
                if blob:
                    updates["vector"] = blob
            sets = ", ".join(f"{k} = ?" for k in updates)
            cur = conn.execute(
                f"UPDATE blackboard SET {sets} WHERE id = ?",
                (*updates.values(), entry_id),
            )
            conn.commit()
            ok = cur.rowcount > 0
        if ok:
            self._record_event(
                entry_id,
                "updated",
                {"fields": sorted(k for k in updates if k not in {"updated_at", "version"})},
            )
        return ok

    def transition(
        self,
        entry_id: str,
        status: str,
        reason: str = "",
        content: str | None = None,
        confidence: float | None = None,
        priority: float | None = None,
        tags: builtins.list[str] | None = None,
    ) -> dict[str, Any] | None:
        """Apply one explicit lifecycle transition and retain an audit event."""
        status = str(status or "open").strip().lower()
        if status not in {"open", "confirmed", "resolved", "rejected"}:
            raise ValueError("status must be open, confirmed, resolved, or rejected")
        existing = self.read(entry_id)
        if existing is None:
            return None
        updates: dict[str, Any] = {
            "status": status,
            "resolved": int(status == "resolved"),
            "contradicted": int(status == "rejected"),
            "contradiction_reason": reason if status == "rejected" else "",
        }
        if content is not None:
            updates["content"] = content
        if confidence is not None:
            updates["confidence"] = max(0.0, min(1.0, float(confidence)))
        if priority is not None:
            updates["priority"] = max(0.0, min(1.0, float(priority)))
        if tags is not None:
            updates["tags"] = sorted({str(tag).strip() for tag in tags if str(tag).strip()})
        self.update(entry_id, embed=False, **updates)
        self._record_event(entry_id, f"status:{status}", {"reason": reason} if reason else {})
        return self.read(entry_id)

    def workspace_brief(self, limit: int = 8) -> dict[str, Any]:
        """Return a compact, actionable snapshot of the investigation."""
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT * FROM blackboard WHERE contradicted=0 "
                "AND lower(category) NOT IN ("
                + ",".join("?" for _ in _INTERNAL_WORKSPACE_CATEGORIES)
                + ") AND lower(COALESCE(source_type, '')) NOT IN ("
                + ",".join("?" for _ in _INTERNAL_WORKSPACE_SOURCE_TYPES)
                + ") "
                "ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'confirmed' THEN 1 ELSE 2 END, "
                "priority DESC, confidence DESC, updated_at DESC LIMIT 500",
                (
                    *sorted(_INTERNAL_WORKSPACE_CATEGORIES),
                    *sorted(_INTERNAL_WORKSPACE_SOURCE_TYPES),
                ),
            ).fetchall()
            conflicts = conn.execute(
                "SELECT * FROM blackboard WHERE contradicted=1 OR status='rejected' "
                "ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
            recent_events = conn.execute(
                "SELECT entry_id, event, details, created_at FROM finding_events "
                "ORDER BY seq DESC LIMIT ?", (limit,)
            ).fetchall()
        entries = [self._row_to_dict(row) for row in rows]

        def brief(entry: dict[str, Any]) -> dict[str, Any]:
            result = {
                "id": entry.get("id"),
                "kind": entry.get("kind") or "finding",
                "status": entry.get("status") or ("resolved" if entry.get("resolved") else "open"),
                "title": entry.get("title"),
                "address": entry.get("addr") or None,
                "confidence": entry.get("confidence"),
                "priority": entry.get("priority"),
            }
            if entry.get("depends_on"):
                result["depends_on"] = entry["depends_on"]
            return result

        open_items = [item for item in entries if (item.get("status") or "open") == "open"]
        questions = [item for item in open_items if (item.get("kind") or "finding") in {"question", "hypothesis", "task"}]
        confirmed = [item for item in entries if (item.get("status") or "open") == "confirmed"]
        return {
            "counts": {
                "total": len(entries) + len(conflicts),
                "open": len(open_items),
                "confirmed": len(confirmed),
                "conflicts": len(conflicts),
                "questions": len(questions),
            },
            "focus": [brief(item) for item in (questions or open_items)[:limit]],
            "confirmed": [brief(item) for item in confirmed[:limit]],
            "conflicts": [brief(self._row_to_dict(row)) for row in conflicts],
            "recent_activity": [
                {
                    "entry_id": row[0],
                    "event": row[1],
                    "details": json.loads(row[2] or "{}"),
                    "created_at": row[3],
                }
                for row in recent_events
            ],
        }

    def semantic_index(self, category: str | None = None) -> dict[str, Any]:
        conditions = []
        params: list = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        with closing(self._conn()) as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM blackboard {where}", params).fetchone()[0]
            embedded = conn.execute(
                f"SELECT COUNT(*) FROM blackboard {where + (' AND ' if where else 'WHERE ')} vector IS NOT NULL",
                params,
            ).fetchone()[0]
            missing = max(0, int(total) - int(embedded))
        return {
            "total": int(total),
            "embedded": int(embedded),
            "missing_vectors": int(missing),
            "category": category or "",
            "db_path": self.db_path,
        }

    def semantic_rebuild(self, category: str | None = None, force: bool = False, limit: int = 5000) -> dict[str, Any]:
        embedder = self._get_embedder()
        if embedder is None:
            return {"ok": False, "error": "embedder unavailable"}
        conditions = []
        params: list = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        if not force:
            conditions.append("vector IS NULL")
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        rebuilt = 0
        with closing(self._conn()) as conn:
            rows = conn.execute(
                f"SELECT id, title, content FROM blackboard {where} ORDER BY updated_at DESC LIMIT ?",
                (*params, int(limit)),
            ).fetchall()
            for row in rows:
                eid = str(row[0])
                text = f"{row[1] or ''} {row[2] or ''}".strip()
                if not text:
                    continue
                blob = self._embed_text(text)
                if not blob:
                    continue
                conn.execute(
                    "UPDATE blackboard SET vector=?, updated_at=? WHERE id=?",
                    (blob, time.time(), eid),
                )
                rebuilt += 1
            conn.commit()
        return {"ok": True, "rebuilt": rebuilt, "category": category or "", "forced": bool(force)}

    def delete(self, entry_id: str) -> bool:
        with closing(self._conn()) as conn:
            cur = conn.execute("DELETE FROM blackboard WHERE id = ?", (entry_id,))
            conn.commit()
            return cur.rowcount > 0

    def clear(self, category: str | None = None) -> int:
        with closing(self._conn()) as conn:
            if category:
                cur = conn.execute("DELETE FROM blackboard WHERE category = ?", (category,))
            else:
                cur = conn.execute("DELETE FROM blackboard")
            conn.commit()
            return cur.rowcount

    def stats(self) -> dict:
        with closing(self._conn()) as conn:
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
            source_types = dict(conn.execute(
                "SELECT source_type, COUNT(*) FROM blackboard WHERE source_type IS NOT NULL GROUP BY source_type"
            ).fetchall())
            ev_rows = conn.execute(
                "SELECT evidence FROM blackboard WHERE evidence != '[]' AND evidence IS NOT NULL"
            ).fetchall()
            total_evidence = sum(len(json.loads(r[0] or "[]")) for r in ev_rows)
            calibrated = conn.execute(
                "SELECT COUNT(*) FROM blackboard WHERE calibrated=1"
            ).fetchone()[0]
        return {
            "total_entries": total or 0,
            "categories": cats or 0,
            "avg_confidence": round(avg_conf or 0, 3),
            "by_category": by_cat,
            "embedded_entries": embedded or 0,
            "resolved": resolved or 0,
            "contradicted": contradicted or 0,
            "iocs": dict(iocs),
            "source_types": source_types,
            "total_evidence_records": total_evidence,
            "calibrated_entries": calibrated or 0,
        }

    def prune(self, max_entries: int = 1000, min_q_value: float = 0.0, older_than_days: int = 0) -> dict:
        with closing(self._conn()) as conn:
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
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT title FROM blackboard WHERE addr = ? AND category = ?",
                (addr, category),
            ).fetchall()
        if not rows:
            return False
        wa = set(title.lower().split())
        sims: list[float] = []
        for (t,) in rows:
            wb = set(t.lower().split())
            if wa and wb:
                sims.append(len(wa & wb) / len(wa | wb))
        if not sims:
            return False
        adaptive_gate = threshold
        try:
            q50 = _quantile(sims, 0.50, default=threshold)
            q75 = _quantile(sims, 0.75, default=threshold)
            adaptive_gate = max(0.5, min(0.99, q75 + (q75 - q50)))
        except Exception:
            adaptive_gate = threshold
        return max(sims) >= adaptive_gate

    def auto_merge(self, addr: str = "", category: str = "", similarity_threshold: float = 0.85) -> dict:
        with closing(self._conn()) as conn:
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

        pair_sims: list[float] = []
        for i, e in enumerate(entries):
            for o in entries[i + 1:]:
                if e.get("addr") == o.get("addr") and e.get("category") == o.get("category"):
                    pair_sims.append(_jaccard(str(e.get("title", "")), str(o.get("title", ""))))
        dyn_thr = similarity_threshold
        if pair_sims:
            q50 = _quantile(pair_sims, 0.50, default=similarity_threshold)
            q75 = _quantile(pair_sims, 0.75, default=similarity_threshold)
            dyn_thr = max(0.5, min(0.99, q75 + (q75 - q50)))

        for i, e in enumerate(entries):
            if e["id"] in deleted:
                continue
            for o in entries[i + 1:]:
                if o["id"] in deleted:
                    continue
                if e.get("addr") == o.get("addr") and e.get("category") == o.get("category"):
                    if _jaccard(str(e.get("title", "")), str(o.get("title", ""))) >= dyn_thr:
                        self.delete(o["id"])
                        deleted.add(o["id"])
        return {"merged": len(deleted), "remaining": len(entries) - len(deleted)}

    def _row_to_dict(self, row) -> dict:
        if row is None:
            return {}
        if not hasattr(self, "_col_cache"):
            with closing(self._conn()) as conn:
                # PRAGMA table_info returns (cid, name, type, notnull, dflt, pk)
                self._col_cache = [d[1] for d in conn.execute("PRAGMA table_info(blackboard)").fetchall()]
        d: dict = {}
        for i, col in enumerate(self._col_cache):
            if i < len(row):
                d[col] = row[i]
        d["tags"] = json.loads(d.get("tags") or "[]")
        d["evidence"] = json.loads(d.get("evidence") or "[]")
        for k in ("vector", "quantized", "q_signs"):
            d.pop(k, None)
        return d
