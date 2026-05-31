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
import hashlib
import os
import sqlite3
import struct
import tempfile
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

def _quantile(vals: List[float], q: float, default: float = 0.0) -> float:
    if not vals:
        return float(default)
    s = sorted(float(v) for v in vals)
    if len(s) == 1:
        return s[0]
    idx = int(round((len(s) - 1) * max(0.0, min(1.0, float(q)))))
    idx = max(0, min(len(s) - 1, idx))
    return float(s[idx])


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
        parent = os.path.dirname(self.db_path) or "."
        try:
            os.makedirs(parent, exist_ok=True)
        except Exception:
            fallback_root = os.path.join(tempfile.gettempdir(), "ida-pro-mcp")
            os.makedirs(fallback_root, exist_ok=True)
            self.db_path = os.path.join(fallback_root, os.path.basename(self.db_path) or "blackboard.db")
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_source_type ON blackboard(source_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_xref ON blackboard(xref_count)")
            conn.commit()

    def _embed_text(self, text: str) -> Optional[bytes]:
        embedder = _get_embedder()
        if embedder is None:
            return None
        try:
            return _pack_vec(embedder.embed(text))
        except Exception:
            return None

    def _sync_entry_to_capsule(self, entry: Dict[str, Any], vector_blob: Optional[bytes]) -> None:
        capsule_path = str(os.environ.get("IDA_MCP_CAPSULE", "") or "").strip()
        if not capsule_path:
            return
        try:
            from ida_pro_mcp.capsule import CapsuleStore
        except Exception:
            return
        try:
            with CapsuleStore.open(capsule_path) as cap:
                if not cap.is_initialized():
                    cap.init(project_name="ida-session", created_by="ida-pro-mcp-blackboard")
                idx_id = "blackboard-" + uuid.uuid5(uuid.NAMESPACE_URL, self.db_path).hex[:16]
                embedder = _get_embedder()
                backend = str(getattr(embedder, "backend", "unknown")) if embedder is not None else "unknown"
                dim = int(getattr(embedder, "dim", 1536) or 1536) if embedder is not None else 1536
                cap.add_semantic_index(
                    kind="blackboard",
                    backend=backend,
                    dim=dim,
                    model_id="",
                    source_fingerprint=self.db_path,
                    metadata={"db_path": self.db_path},
                    index_id=idx_id,
                )
                text = f"{entry.get('title', '')}\n{entry.get('content', '')}".strip()
                thash = hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()
                vsha = ""
                if vector_blob:
                    vsha = cap.store_semantic_vector(vector_blob, dim=dim, dtype="float32")
                cap.upsert_semantic_item(
                    index_id=idx_id,
                    kind="blackboard_entry",
                    stable_ref=str(entry.get("id") or ""),
                    title=str(entry.get("title") or ""),
                    text_hash=thash,
                    vector_sha256=vsha,
                    metadata={
                        "category": entry.get("category"),
                        "addr": entry.get("addr"),
                        "confidence": entry.get("confidence"),
                        "source_type": entry.get("source_type"),
                        "updated_at": entry.get("updated_at"),
                    },
                )
        except Exception:
            return

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
        evidence: Optional[List[Dict]] = None,
        source_type: str = "",
        entropy: float = 0.0,
        xref_count: int = 0,
        **_legacy_kwargs,
    ) -> str:
        entry_id = str(uuid.uuid4())[:8]
        now = time.time()
        vector_blob = None
        if embed:
            vector_blob = self._embed_text(f"{title} {content}".strip())
        # source_type defaults to source for backward compat
        if not source_type:
            source_type = source
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO blackboard
                    (id, category, title, content, addr, addr_end, tags, confidence,
                     created_at, updated_at, q_value, source, vector,
                     ioc_type, ioc_value, depends_on, blocks_addr, register, reg_type,
                     evidence, source_type, entropy, xref_count, version)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                entry_id, category, title, content, addr, addr_end,
                json.dumps(tags or []), confidence,
                now, now, confidence, source, vector_blob,
                ioc_type, ioc_value, depends_on, blocks_addr, register, reg_type,
                json.dumps(evidence or []), source_type, entropy, xref_count, 1,
            ))
            conn.commit()
        self._sync_entry_to_capsule(
            {
                "id": entry_id,
                "title": title,
                "content": content,
                "category": category,
                "addr": addr,
                "confidence": confidence,
                "source_type": source_type or "manual",
                "updated_at": now,
            },
            vector_blob,
        )
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

    def calibrate_confidence(self, entry_id: str) -> Optional[float]:
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

    def campaign_summary(self) -> Dict:
        """
        High-level summary of the RE campaign state.

        Returns: coverage, top findings by category, active hypotheses,
        confirmed IOCs, open vulns, dead ends, and a recommended next action.
        """
        with self._conn() as conn:
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
        with self._conn() as conn:
            # Get high-confidence entries with tags and addresses
            rows = conn.execute(
                "SELECT addr, tags FROM blackboard "
                "WHERE confidence > 0.8 AND addr != '' AND addr IS NOT NULL "
                "AND tags != '[]' AND tags IS NOT NULL"
            ).fetchall()

        # Build addr → tag set map
        addr_tags: Dict[str, set] = {}
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
        with self._conn() as conn:
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

    def next_target(self, limit: int = 5, rpc_fn=None) -> List[Dict]:
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

        with self._conn() as conn:
            rows = conn.execute("""
                SELECT id, addr, category, title, confidence, depends_on,
                       created_at, xref_count, entropy, source_type
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
            eid, addr, cat, title, conf, depends_on, created_at, xref_count, entropy, source_type = row
            if addr in seen_addrs:
                continue
            seen_addrs.add(addr)

            # Adaptive confidence baseline around current frontier distribution.
            score = max(1e-6, float(conf or 0.5))

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
                "age_days": round(age_days, 1),
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

    def _seed_from_xrefs(self, rpc_fn, seen_addrs: set, limit: int) -> List[Dict]:
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
            if not (name.startswith("sub_") or name.startswith("j_")):
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

    def update(self, entry_id: str, **kwargs) -> bool:
        allowed = {"title", "content", "category", "addr", "addr_end", "tags",
                   "confidence", "q_value", "resolved", "ioc_type", "ioc_value",
                   "depends_on", "blocks_addr", "register", "reg_type",
                   "evidence", "source_type", "entropy", "xref_count", "calibrated"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        updates["updated_at"] = time.time()
        updates["version"] = (self.read(entry_id) or {}).get("version", 1) + 1
        if "tags" in updates:
            updates["tags"] = json.dumps(updates["tags"])
        if "evidence" in updates:
            updates["evidence"] = json.dumps(updates["evidence"])
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
            ok = cur.rowcount > 0
        if ok:
            entry = self.read(entry_id)
            if entry:
                vec_blob = None
                try:
                    with self._conn() as conn:
                        row = conn.execute("SELECT vector FROM blackboard WHERE id=?", (entry_id,)).fetchone()
                        vec_blob = row[0] if row and row[0] else None
                except Exception:
                    vec_blob = None
                self._sync_entry_to_capsule(entry, vec_blob)
        return ok

    def semantic_index(self, category: Optional[str] = None) -> Dict[str, Any]:
        conditions = []
        params: list = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        with self._conn() as conn:
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

    def semantic_rebuild(self, category: Optional[str] = None, force: bool = False, limit: int = 5000) -> Dict[str, Any]:
        embedder = _get_embedder()
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
        with self._conn() as conn:
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
        sims: List[float] = []
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

        pair_sims: List[float] = []
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
        d["evidence"] = json.loads(d.get("evidence") or "[]")
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
    _instances_by_key: Dict[str, "_BackgroundCrawler"] = {}
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pending: Dict[str, Dict] = {}  # proposal_id -> proposal
        self._visited: set = set()
        self._work_queue: List[str] = []
        self._parents: Dict[str, str] = {}
        self._visited_count: int = 0
        self._notify_fn = None  # injected by server to send MCP notifications

    @classmethod
    def instance(cls, db_path: Optional[str] = None) -> "_BackgroundCrawler":
        with cls._lock:
            key = str(db_path or "").strip().lower()
            if key:
                inst = cls._instances_by_key.get(key)
                if inst is None:
                    inst = cls(db_path)
                    cls._instances_by_key[key] = inst
                cls._instance = inst
                return inst
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

    def visited_count(self) -> int:
        return int(self._visited_count)

    def accept(self, proposal_id: str) -> Optional[str]:
        p = self._pending.pop(proposal_id, None)
        if not p:
            return None
        store = BlackboardStore(self._db_path)
        conf = float(p.get("confidence", 0.6) or 0.6)
        return store.write(
            title=p["title"],
            content=p.get("content", ""),
            category=p.get("category", "hypothesis"),
            addr=p.get("addr", ""),
            tags=p.get("tags", []),
            confidence=min(1.0, conf + 0.1),
            source="crawler.accepted",
        )

    def reject(self, proposal_id: str) -> bool:
        p = self._pending.pop(proposal_id, None)
        if not p:
            return False
        # Demote confidence for existing hypothesis entries at this address.
        try:
            store = BlackboardStore(self._db_path)
            addr = str(p.get("addr") or "").strip()
            if addr:
                rows = store.list(category="hypothesis", addr=addr, include_resolved=True, include_contradicted=True, limit=20)
                for e in rows:
                    eid = str(e.get("id") or e.get("entry_id") or "").strip()
                    old = float(e.get("confidence", 0.5) or 0.5)
                    if eid:
                        store.update(eid, confidence=max(0.0, old - 0.15))
        except Exception:
            pass
        return True

    def _crawl_loop(self) -> None:
        """Main crawler loop: frontier -> agent quick -> hypothesis proposal every 0.5s."""
        while not self._stop_event.wait(0.5):
            try:
                self._crawl_step()
            except Exception:
                pass

    def _crawl_step(self) -> None:
        store = BlackboardStore(self._db_path)
        try:
            # Restore queue/visited snapshot when resuming.
            st = store.list(category="crawler_state", include_resolved=True, include_contradicted=True, limit=1)
            if st:
                import json as _json
                meta = _json.loads(str(st[0].get("content") or "{}"))
                if isinstance(meta, dict):
                    if not self._visited and isinstance(meta.get("visited"), list):
                        self._visited = set(str(x) for x in meta.get("visited", []))
                    if not self._work_queue and isinstance(meta.get("queue"), list):
                        self._work_queue = [str(x) for x in meta.get("queue", []) if str(x)]
                    if not self._parents and isinstance(meta.get("parents"), dict):
                        self._parents = {str(k): str(v) for k, v in meta.get("parents", {}).items()}
        except Exception:
            pass
        try:
            f_res = blackboard(action="frontier", db_path=self._db_path or "", limit=25)
            frontier = f_res.get("results", []) if isinstance(f_res, dict) else []
            if frontier and isinstance(frontier[0], dict) and "addr" not in frontier[0]:
                frontier = []
        except Exception:
            frontier = []
        if not frontier:
            try:
                frontier = store.next_target(limit=25)
            except Exception:
                frontier = []
        addr_str = ""
        discovery_path = []
        # Prefer in-session queue expansion first.
        while self._work_queue and not addr_str:
            cand = self._work_queue.pop(0)
            if cand and cand not in self._visited:
                addr_str = cand
        if not addr_str:
            next_target = None
            for t in frontier:
                addr = str(t.get("addr") or "").strip()
                if not addr or addr in self._visited:
                    continue
                next_target = t
                break
            if not next_target:
                return
            addr_str = str(next_target.get("addr") or "").strip()

        # Reconstruct caller -> callee chain.
        cur = addr_str
        hop = 0
        while cur and hop < 8:
            discovery_path.append(cur)
            cur = self._parents.get(cur, "")
            hop += 1
        discovery_path = list(reversed(discovery_path))

        self._visited.add(addr_str)
        self._visited_count += 1
        findings = []
        quick = {}
        try:
            from .agent import agent as _agent_tool  # type: ignore
            quick = _agent_tool(action="quick", addr=addr_str)
            findings = quick.get("findings") if isinstance(quick, dict) else []
            if not isinstance(findings, list):
                findings = []
        except Exception:
            findings = []
        # Expand graph traversal from discovered callees.
        try:
            for c in (quick.get("callees") or []):
                c_addr = ""
                if isinstance(c, dict):
                    c_addr = str(c.get("addr") or c.get("ea") or "").strip()
                else:
                    c_addr = str(c).strip().split()[0]
                if not c_addr or c_addr in self._visited or c_addr in self._work_queue:
                    continue
                self._parents[c_addr] = addr_str
                self._work_queue.append(c_addr)
                if len(self._work_queue) >= 50:
                    break
            if len(self._work_queue) > 50:
                self._work_queue = self._work_queue[:50]
        except Exception:
            pass

        if not findings:
            try:
                import json as _json
                store.write(
                    title="crawler_state",
                    content=_json.dumps({
                        "visited": sorted(list(self._visited))[:400],
                        "queue": self._work_queue[:50],
                        "parents": self._parents,
                    }),
                    category="crawler_state",
                    tags=["crawler"],
                    confidence=1.0,
                    source="crawler.state",
                )
            except Exception:
                pass
            return
        summary = str(findings[0])[:220]
        pid = str(uuid.uuid4())[:8]
        proposal = {
            "proposal_id": pid,
            "addr": addr_str,
            "title": f"Crawler quick analysis @ {addr_str}",
            "content": summary,
            "category": "hypothesis",
            "tags": ["crawler", "quick"],
            "confidence": 0.65,
            "source_addr": addr_str,
            "behavior_tags": quick.get("labels", []) if isinstance(quick, dict) else [],
            "discovery_path": discovery_path,
        }
        self._pending[pid] = proposal
        try:
            store.write(
                title=proposal["title"],
                content=proposal["content"],
                category="hypothesis",
                addr=proposal["addr"],
                tags=proposal["tags"],
                confidence=float(proposal["confidence"]),
                source="crawler.auto",
                source_type="crawler",
            )
            import json as _json
            store.write(
                title="crawler_state",
                content=_json.dumps({
                    "visited": sorted(list(self._visited))[:400],
                    "queue": self._work_queue[:50],
                    "parents": self._parents,
                }),
                category="crawler_state",
                tags=["crawler"],
                confidence=1.0,
                source="crawler.state",
            )
        except Exception:
            pass

        # Send MCP notification for new proposals
        if self._notify_fn:
            try:
                self._notify_fn({
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {
                        "level": "info",
                        "logger": "blackboard.crawler",
                        "data": {
                            "message": "Crawler generated 1 quick-analysis proposal",
                            "proposals": [{"proposal_id": proposal["proposal_id"], "addr": proposal["addr"], "title": proposal["title"], "behavior_tags": proposal.get("behavior_tags", [])}],
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
    # v3 fields
    evidence: Optional[List[Dict]] = None,
    source_type: str = "",
    entropy: float = 0.0,
    xref_count: int = 0,
    evidence_type: str = "",
    evidence_value: str = "",
    evidence_weight: float = 1.0,
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
      export_symbols - Export named functions into persistent symbol knowledge DB.
      import_symbols - Import high-confidence symbol matches from knowledge DB.

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
            evidence=evidence or [], source_type=source_type or "manual",
            entropy=entropy, xref_count=xref_count,
        )
        # Async label propagation: only when inside IDA (idc module available)
        # and confidence is high enough to be worth propagating
        if addr and confidence >= 0.6 and source_type not in ("propagated", "engine_frontier"):
            try:
                import idc as _idc_check  # noqa: F401 — only start thread if IDA is available
                import threading as _thr
                def _propagate():
                    try:
                        from ida_pro_mcp.host.frontier import FrontierEngine
                    except ImportError:
                        try:
                            from host.frontier import FrontierEngine  # type: ignore
                        except ImportError:
                            return
                    try:
                        idb_path = ""
                        try:
                            import idc as _idc
                            idb_path = _idc.get_idb_path() or ""
                        except Exception:
                            pass
                        if not idb_path:
                            return  # no IDB path — skip propagation
                        emb_db = idb_path + ".embeddings.db"
                        import os as _os
                        if not _os.path.exists(emb_db):
                            return  # no embeddings indexed yet — skip
                        fe = FrontierEngine(emb_db, store.db_path)
                        if fe.refresh() >= 3:
                            fe.propagate_labels()
                    except Exception:
                        pass
                _thr.Thread(target=_propagate, daemon=True, name="bb-propagate").start()
            except ImportError:
                pass  # not inside IDA — skip propagation
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

    elif action == "semantic_index":
        stats = store.semantic_index(category=category or None)
        return {"ok": True, **stats}

    elif action == "semantic_rebuild":
        force = bool(kwargs.get("force", False))
        result = store.semantic_rebuild(
            category=category or None,
            force=force,
            limit=int(limit or 5000),
        )
        return result

    elif action == "related_by_behavior":
        if not query:
            return {"ok": False, "error": "query required"}
        thr = threshold
        try:
            thr = float(threshold)
        except Exception:
            thr = 0.4
        hits = store.semantic_search(
            query=query,
            top_k=max(1, int(top_k or 10)),
            threshold=max(0.0, thr),
            category=category or None,
            include_resolved=include_resolved,
            include_contradicted=include_contradicted,
        )
        out = []
        for h in hits:
            tags = h.get("tags") or []
            if isinstance(tags, str):
                try:
                    tags = json.loads(tags)
                except Exception:
                    tags = []
            out.append(
                {
                    "entry_id": h.get("id"),
                    "title": h.get("title"),
                    "addr": h.get("addr"),
                    "category": h.get("category"),
                    "confidence": h.get("confidence"),
                    "similarity": h.get("similarity"),
                    "tags": tags,
                }
            )
        return {
            "ok": True,
            "behavior": query,
            "results": out,
            "count": len(out),
        }

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
        # Optional semantic rerank: when query is provided, blend queue priority with embedding similarity.
        if query:
            sem_hits = store.semantic_search(
                query=query,
                top_k=max(limit or 5, 10),
                threshold=max(0.2, float(threshold or 0.4) - 0.1),
                include_resolved=False,
                include_contradicted=False,
            )
            sim_by_addr = {}
            for h in sem_hits:
                a = str(h.get("addr") or "").strip()
                if a:
                    sim_by_addr[a] = float(h.get("similarity") or 0.0)
            if sim_by_addr:
                for t in targets:
                    a = str(t.get("addr") or "").strip()
                    sim = sim_by_addr.get(a, 0.0)
                    base = float(t.get("priority_score") or 0.0)
                    t["semantic_similarity"] = round(sim, 4)
                    t["blended_priority"] = round((0.78 * base) + (0.22 * sim), 4)
                targets = sorted(
                    targets,
                    key=lambda x: (float(x.get("blended_priority") or 0.0), float(x.get("priority_score") or 0.0)),
                    reverse=True,
                )
        return {
            "ok": True,
            "targets": targets,
            "count": len(targets),
            "query": query or None,
            "note": (
                "Highest-priority unexplored addresses. With query set, ranking blends queue priority "
                "and embedding similarity."
            ),
        }

    elif action == "start_crawler":
        crawler = _BackgroundCrawler.instance(db_path=db_path or None)
        crawler.start()
        return {"ok": True, "running": crawler.is_running(),
                "note": "Crawler uses frontier targets and runs agent(action='quick') every 0.5s. Use crawler_status to see proposals."}

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
            "proposals_pending": len(proposals),
            "addresses_visited": crawler.visited_count(),
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

    elif action == "add_evidence":
        if not entry_id:
            return {"ok": False, "error": "entry_id required"}
        if not evidence_type or not evidence_value:
            return {"ok": False, "error": "evidence_type and evidence_value required"}
        ok = store.add_evidence(entry_id, evidence_type, evidence_value, evidence_weight)
        return {"ok": ok}

    elif action == "calibrate":
        if not entry_id:
            return {"ok": False, "error": "entry_id required"}
        new_conf = store.calibrate_confidence(entry_id)
        return {"ok": new_conf is not None, "confidence": new_conf}

    elif action == "campaign_summary":
        return {"ok": True, **store.campaign_summary()}

    elif action == "auto_tag_propagate":
        updated = store.auto_tag_propagate()
        return {"ok": True, "updated": updated}

    # ── Knowledge Graph write actions ─────────────────────────────────────────
    elif action in ("add_system", "add_struct", "add_gap", "fill_gap",
                    "add_state_machine", "add_peripheral", "add_attack_surface",
                    "kg_summary", "kg_systems", "kg_gaps", "kg_structs",
                    "kg_state_machines", "kg_attack_surface", "kg_peripherals"):
        try:
            import importlib.util as _ilu, os as _os
            _kg_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                                     "..", "..", "host", "knowledge_graph.py")
            _spec = _ilu.spec_from_file_location("_bb_kg", _os.path.abspath(_kg_path))
            _kgmod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_kgmod)
            kg = _kgmod.KnowledgeGraph(db_path=store.db_path)
        except Exception as e:
            return {"ok": False, "error": f"KnowledgeGraph unavailable: {e}"}

        if action == "add_system":
            if not title:
                return {"ok": False, "error": "title required (system name)"}
            members = kwargs.get("members") or []
            entry_points = kwargs.get("entry_points") or []
            exit_points = kwargs.get("exit_points") or []
            sid = kg.add_system(title, members=members, description=content,
                                entry_points=entry_points, exit_points=exit_points,
                                tags=tags or [], confidence=confidence)
            return {"ok": True, "system_id": sid}

        elif action == "add_struct":
            if not title:
                return {"ok": False, "error": "title required (struct name)"}
            members_data = kwargs.get("members") or []
            size = int(kwargs.get("size_bytes") or 0)
            sid = kg.add_struct(title, members=members_data, size_bytes=size,
                                confidence=confidence)
            return {"ok": True, "struct_id": sid}

        elif action == "add_gap":
            if not title:
                return {"ok": False, "error": "title required (expected capability)"}
            hints = kwargs.get("hints") or []
            gap_type = kwargs.get("gap_type") or "capability"
            binary_type = kwargs.get("binary_type") or ""
            gid = kg.add_gap(title, why=content, hints=hints,
                             priority=confidence, gap_type=gap_type,
                             binary_type=binary_type)
            return {"ok": True, "gap_id": gid}

        elif action == "fill_gap":
            gap_id = kwargs.get("gap_id") or entry_id
            if not gap_id:
                return {"ok": False, "error": "gap_id or entry_id required"}
            filled_by = addr or kwargs.get("filled_by") or ""
            ok = kg.fill_gap(gap_id, filled_by)
            return {"ok": ok}

        elif action == "add_state_machine":
            if not title:
                return {"ok": False, "error": "title required (state machine name)"}
            state_var = addr or kwargs.get("state_var") or ""
            states = kwargs.get("states") or []
            sid = kg.add_state_machine(title, state_var=state_var, states=states,
                                       confidence=confidence)
            return {"ok": True, "state_machine_id": sid}

        elif action == "add_peripheral":
            if not addr:
                return {"ok": False, "error": "addr required (MMIO base address)"}
            periph_type = kwargs.get("periph_type") or "unknown"
            drivers = kwargs.get("drivers") or []
            pid = kg.add_peripheral(addr, name=title, periph_type=periph_type,
                                    drivers=drivers, confidence=confidence)
            return {"ok": True, "peripheral_id": pid}

        elif action == "add_attack_surface":
            if not addr:
                return {"ok": False, "error": "addr required (entry point address)"}
            reachable_from = kwargs.get("reachable_from") or "unknown"
            input_type = kwargs.get("input_type") or "unknown"
            call_stack = kwargs.get("call_stack") or []
            aid = kg.add_attack_surface(addr, name=title,
                                        reachable_from=reachable_from,
                                        input_type=input_type,
                                        call_stack=call_stack,
                                        confidence=confidence)
            return {"ok": True, "attack_surface_id": aid}

        elif action == "kg_summary":
            return {"ok": True, **kg.summary()}
        elif action == "kg_systems":
            return {"ok": True, "systems": kg.list_systems()}
        elif action == "kg_gaps":
            resolved_flag = kwargs.get("resolved", False)
            return {"ok": True, "gaps": kg.list_gaps(resolved=bool(resolved_flag))}
        elif action == "kg_structs":
            return {"ok": True, "structs": kg.list_structs()}
        elif action == "kg_state_machines":
            return {"ok": True, "state_machines": kg.list_state_machines()}
        elif action == "kg_attack_surface":
            return {"ok": True, "attack_surface": kg.list_attack_surface()}
        elif action == "kg_peripherals":
            return {"ok": True, "peripherals": kg.list_peripherals()}

    elif action == "frontier":
        # Return ranked unvisited functions from FrontierEngine.
        # Requires embeddings to be indexed (code(action='decompile') or schemaboot).
        try:
            from ida_pro_mcp.host.frontier import FrontierEngine
        except ImportError:
            from host.frontier import FrontierEngine  # type: ignore
        idb_path = ""
        try:
            import idc as _idc
            idb_path = _idc.get_idb_path() or ""
        except Exception:
            pass
        emb_db = (idb_path + ".embeddings.db") if idb_path else ""
        fe = FrontierEngine(emb_db, store.db_path)
        n = fe.refresh()
        if n < 3:
            return {
                "ok": True, "frontier": [], "count": 0,
                "note": "Not enough indexed embeddings. Decompile some functions first.",
            }
        # Gather xref/entropy hints from blackboard
        xref_counts: dict = {}
        entropy_map: dict = {}
        try:
            import sqlite3 as _sq3
            with _sq3.connect(store.db_path, timeout=5) as conn:
                for row in conn.execute(
                    "SELECT addr, xref_count, entropy FROM blackboard "
                    "WHERE addr != '' AND addr IS NOT NULL"
                ):
                    if row[0]:
                        xref_counts[row[0]] = int(row[1] or 0)
                        entropy_map[row[0]] = float(row[2] or 0.0)
        except Exception:
            pass
        results = fe.frontier(limit=limit, xref_counts=xref_counts, entropy_map=entropy_map)
        lines = [
            f"{r['addr']}  {r['name']}  score={r['score']:.3f}  "
            f"cluster={r['cluster']}  proximity={r['proximity']:.3f}"
            + (f"  near='{r['nearest_label_title'][:30]}'" if r.get("nearest_label_title") else "")
            for r in results
        ]
        return {
            "ok": True,
            "frontier": "\n".join(lines),
            "items": results,
            "count": len(results),
            "indexed": n,
            "note": (
                "Ranked by: proximity to labeled functions (embedding cosine) + "
                "xref count + entropy + cluster coverage. "
                "Use code(action='smart_decompile') on top results."
            ),
        }

    elif action == "coverage":
        # Coverage map: analyzed/visited/unvisited counts + per-cluster breakdown.
        try:
            from ida_pro_mcp.host.frontier import FrontierEngine
        except ImportError:
            from host.frontier import FrontierEngine  # type: ignore
        idb_path = ""
        try:
            import idc as _idc
            idb_path = _idc.get_idb_path() or ""
        except Exception:
            pass
        emb_db = (idb_path + ".embeddings.db") if idb_path else ""
        fe = FrontierEngine(emb_db, store.db_path)
        n = fe.refresh()
        if n < 1:
            return {
                "ok": True,
                "coverage_pct": 0.0,
                "total_indexed": 0,
                "analyzed": 0,
                "unvisited": 0,
                "note": "No embeddings indexed yet.",
            }
        return {"ok": True, **fe.coverage()}

    elif action == "propagate_labels":
        # Propagate LLM blackboard labels to embedding-similar neighbors.
        # Writes 'propagated' source_type entries for neighbors within cosine threshold.
        try:
            from ida_pro_mcp.host.frontier import FrontierEngine
        except ImportError:
            from host.frontier import FrontierEngine  # type: ignore
        idb_path = ""
        try:
            import idc as _idc
            idb_path = _idc.get_idb_path() or ""
        except Exception:
            pass
        emb_db = (idb_path + ".embeddings.db") if idb_path else ""
        fe = FrontierEngine(emb_db, store.db_path)
        n = fe.refresh()
        if n < 3:
            return {"ok": True, "propagated": 0, "note": "Not enough embeddings."}
        new_entries = fe.propagate_labels()
        return {
            "ok": True,
            "propagated": len(new_entries),
            "entries": new_entries[:20],
            "note": (
                f"Propagated {len(new_entries)} labels to embedding neighbors "
                f"(threshold={FrontierEngine.PROPAGATE_THRESHOLD}, "
                f"decay={FrontierEngine.PROPAGATE_DECAY}). "
                "Use blackboard(action='list', source_type='propagated') to review."
            ),
        }
    elif action == "export_symbols":
        try:
            from .knowledge import knowledge
        except Exception:
            from knowledge import knowledge  # type: ignore
        return knowledge(action="export_session", min_confidence=min_confidence, **kwargs)
    elif action == "import_symbols":
        try:
            from .knowledge import knowledge
        except Exception:
            from knowledge import knowledge  # type: ignore
        return knowledge(action="import_symbols", min_confidence=min_confidence, limit=limit, **kwargs)

    else:
        return {"ok": False, "error": f"Unknown action: {action}"}
