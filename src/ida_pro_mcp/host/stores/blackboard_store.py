"""Investigation workspace: what the analyst concluded, asked, and ruled out.

The store keeps three kinds of record about a binary, in one SQLite table:

``findings`` / ``hypotheses`` / ``questions`` / ``tasks`` / ``decisions``
    Positive claims and the open threads around them.
``examined`` entries
    Negative results. "I read this function, it is a CRT wrapper, skip it."
    These are cheap to write and prevent the single most expensive failure
    mode in a long investigation: re-deriving the same nothing.
``code_anchors``
    A digest of the code each claim was made against. When the code at an
    address changes, every claim anchored to the old text is marked stale
    rather than continuing to look authoritative.

Design notes that are easy to get wrong and are therefore load-bearing:

* Merging accumulates *evidence*, not *confidence*. A repeat observation
  carries the newest confidence, not the highest one seen — otherwise
  confidence ratchets upward every time anyone restates a claim.
* Opposed assertions are never merged. Recording "rejected" over a
  "confirmed" claim keeps both rows and links them as a conflict, because a
  memory that silently overwrites its own contradictions is worse than no
  memory.
* Target selection is a set of named strategies that each return a reason
  string, not one opaque score. A ranking nobody can explain is a ranking
  nobody can debug.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import math
import os
import re
import sqlite3
import tempfile
import time
import uuid
from contextlib import closing
from typing import Any

from ..intelligence.helpers import dot_product, pack_floats, unpack_floats

KINDS = frozenset({"finding", "hypothesis", "question", "task", "decision", "examined"})
STATUSES = frozenset({"open", "confirmed", "resolved", "rejected"})
VERDICTS = frozenset({"interesting", "boring", "unclear"})
ANCHOR_KINDS = frozenset({"decompile", "disassemble"})
STRATEGIES = ("unresolved", "stale", "conflict", "coverage", "frontier")

#: Kinds that represent an open thread the analyst still owes an answer to.
OPEN_THREAD_KINDS = frozenset({"question", "hypothesis", "task"})

#: Status pairs that must never be silently merged into one row.
_OPPOSED_STATUS = frozenset({("confirmed", "rejected"), ("rejected", "confirmed")})

# Rows written by internal enrichment passes rather than by the analyst.
# They are real data but they are noise in a human-facing brief.
_INTERNAL_WORKSPACE_CATEGORIES = frozenset(
    {"evidence_gravity", "wm_now", "quest_log", "proposal_feedback"}
)
_INTERNAL_WORKSPACE_SOURCE_TYPES = frozenset(
    {"evidence_gravity", "gravity", "auto_enrich", "proposal_feedback"}
)

_WS_RUN = re.compile(r"\s+")
_NON_SYMBOL = re.compile(r"[^0-9a-z]+")

#: Tag written into IDB comments so a later import can tell which annotations
#: this tool produced and not re-adopt its own output as a fresh discovery.
COMMENT_MARKER = "[mcp:{entry_id}]"
_MARKER_RE = re.compile(r"\[mcp:([0-9a-f-]{4,})\]")

#: Names IDA generates when it has nothing to say about a function.
AUTO_NAME_PREFIXES = ("sub_", "j_", "loc_", "nullsub_", "unknown_libname_")


def is_auto_name(name: str) -> bool:
    name = str(name or "").strip()
    return not name or name.startswith(AUTO_NAME_PREFIXES)


def symbol_from_title(title: str, max_len: int = 60) -> str:
    """Derive a C identifier from a finding's prose title.

    "Packet receive handler" becomes ``packet_receive_handler``. Returns ""
    when nothing usable survives, which the caller must treat as "do not
    rename" rather than as a name.
    """
    slug = _NON_SYMBOL.sub("_", str(title or "").lower()).strip("_")
    if not slug:
        return ""
    if slug[0].isdigit():
        slug = "f_" + slug
    return slug[:max_len].rstrip("_")


def marker_for(entry_id: str) -> str:
    return COMMENT_MARKER.format(entry_id=entry_id)


def entry_id_in(text: str) -> str:
    """Return the finding id embedded in an IDB comment, or ""."""
    match = _MARKER_RE.search(str(text or ""))
    return match.group(1) if match else ""


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


def normalize_addr(addr: Any) -> str:
    """Return a canonical ``0x...`` form so ``0X401000`` and ``0x401000`` match."""
    if addr is None:
        return ""
    if isinstance(addr, int):
        return hex(addr)
    text = str(addr).strip().lower()
    if not text:
        return ""
    if text.startswith("0x"):
        body = text[2:].lstrip("0") or "0"
        return "0x" + body
    return text


def code_digest(text: str) -> str:
    """Digest the code a claim was made against.

    Only whitespace is normalised away. Any other textual change — including
    a rename or a retyped variable — counts as drift, because in this domain a
    rename *is* a change in understanding. The digest is a "re-check this"
    signal, not proof that behaviour changed, and it is deliberately eager:
    a staleness flag that never fires is worse than one that occasionally
    asks a question already answered.
    """
    normalized = _WS_RUN.sub(" ", str(text or "")).strip()
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()[:16]


def _jaccard(a: str, b: str) -> float:
    wa, wb = set(str(a).lower().split()), set(str(b).lower().split())
    return len(wa & wb) / len(wa | wb) if wa and wb else 0.0


def _clamp01(value: Any, default: float = 0.5) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


class BlackboardStore:
    """SQLite-backed investigation workspace for one session."""

    def __init__(self, db_path: str | None = None):
        primary_path = _resolve_db_path(db_path)
        self.db_path = primary_path
        # Set by next_target()/targets() so a caller can report whether a
        # semantic query actually reached the ranking.
        self.last_query_applied: bool | None = None
        self.last_query_error: str = ""
        try:
            parent = os.path.dirname(self.db_path) or "."
            os.makedirs(parent, exist_ok=True)
            with closing(self._conn()):
                pass
            self._init_db()
        except (sqlite3.OperationalError, OSError, PermissionError):
            try:
                from ..config import CACHE_DIR
            except ImportError:
                xdg = os.environ.get("XDG_STATE_HOME") or os.path.join(
                    os.path.expanduser("~"), ".local", "state"
                )
                CACHE_DIR = os.path.join(xdg, "ida-pro-mcp")
            h = hashlib.sha256(os.path.abspath(primary_path).encode("utf-8")).hexdigest()[:16]
            fallback_dir = os.path.join(CACHE_DIR, "fallback_indexes")
            os.makedirs(fallback_dir, exist_ok=True)
            self.db_path = os.path.join(fallback_dir, f"{h}.blackboard.db")
            self._init_db()

    # ------------------------------------------------------------------
    # Connection and schema
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def close(self) -> None:
        """No persistent handle is held; present so callers can be symmetric."""
        return None

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
                    evidence     TEXT DEFAULT '[]',
                    source_type  TEXT DEFAULT 'manual',
                    version      INTEGER DEFAULT 1,
                    entropy      REAL DEFAULT 0.0,
                    xref_count   INTEGER DEFAULT 0,
                    calibrated   INTEGER DEFAULT 0
                )
            """)
            existing = {r["name"] for r in conn.execute("PRAGMA table_info(blackboard)").fetchall()}
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
                ("evidence", "TEXT DEFAULT '[]'"),
                ("source_type", "TEXT DEFAULT 'manual'"),
                ("version", "INTEGER DEFAULT 1"),
                ("entropy", "REAL DEFAULT 0.0"),
                ("xref_count", "INTEGER DEFAULT 0"),
                ("calibrated", "INTEGER DEFAULT 0"),
                ("kind", "TEXT DEFAULT 'finding'"),
                ("status", "TEXT DEFAULT 'open'"),
                ("priority", "REAL DEFAULT 0.5"),
                ("fingerprint", "TEXT DEFAULT ''"),
                # Legacy columns kept so old databases still open cleanly.
                ("bridges", "TEXT DEFAULT '{}'"),
                ("schema", "TEXT DEFAULT '{}'"),
                ("quantized", "BLOB"),
                ("q_signs", "BLOB"),
                ("norm", "REAL DEFAULT 0.0"),
                ("call_idx", "INTEGER DEFAULT 0"),
                # Kept separate from updated_at so decaying an entry does not
                # make it look freshly edited (and so it can decay twice).
                ("decayed_at", "REAL"),
                # Anchoring: which code this claim was made against.
                ("anchor_kind", "TEXT DEFAULT ''"),
                ("anchor_digest", "TEXT DEFAULT ''"),
                ("stale", "INTEGER DEFAULT 0"),
                ("stale_reason", "TEXT DEFAULT ''"),
                # Disagreement: ids of entries this one contradicts.
                ("conflicts_with", "TEXT DEFAULT '[]'"),
                # Coverage verdict, for kind='examined'.
                ("verdict", "TEXT DEFAULT ''"),
                # IDB round-trip: when this claim was last written into the
                # database, and under what symbol.
                ("published_at", "REAL"),
                ("published_symbol", "TEXT DEFAULT ''"),
            ]:
                if col not in existing:
                    conn.execute(f"ALTER TABLE blackboard ADD COLUMN {col} {dtype}")
            for stmt in (
                "CREATE INDEX IF NOT EXISTS idx_bb_category ON blackboard(category)",
                "CREATE INDEX IF NOT EXISTS idx_bb_addr ON blackboard(addr)",
                "CREATE INDEX IF NOT EXISTS idx_bb_tags ON blackboard(tags)",
                "CREATE INDEX IF NOT EXISTS idx_bb_resolved ON blackboard(resolved)",
                "CREATE INDEX IF NOT EXISTS idx_bb_ioc ON blackboard(ioc_type)",
                "CREATE INDEX IF NOT EXISTS idx_bb_source_type ON blackboard(source_type)",
                "CREATE INDEX IF NOT EXISTS idx_bb_xref ON blackboard(xref_count)",
                "CREATE INDEX IF NOT EXISTS idx_bb_kind_status ON blackboard(kind, status)",
                "CREATE INDEX IF NOT EXISTS idx_bb_fingerprint ON blackboard(fingerprint)",
                "CREATE INDEX IF NOT EXISTS idx_bb_stale ON blackboard(stale)",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_bb_fingerprint_unique "
                "ON blackboard(fingerprint) WHERE fingerprint != ''",
            ):
                conn.execute(stmt)
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
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_finding_events_entry ON finding_events(entry_id, seq)"
            )
            conn.execute("""
                CREATE TABLE IF NOT EXISTS code_anchors (
                    addr      TEXT NOT NULL,
                    kind      TEXT NOT NULL,
                    digest    TEXT NOT NULL,
                    seen_at   REAL NOT NULL,
                    PRIMARY KEY (addr, kind)
                )
            """)
            conn.commit()

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    def _get_embedder(self):
        return _get_embedder()

    def _embed_text(self, text: str) -> bytes | None:
        embedder = self._get_embedder()
        if embedder is None:
            return None
        try:
            vec = embedder.embed_vector(text)
            if vec is None:
                return None
            return pack_floats(vec)
        except Exception:
            return None

    @staticmethod
    def _row_to_dict(row) -> dict:
        if row is None:
            return {}
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        d["evidence"] = json.loads(d.get("evidence") or "[]")
        d["conflicts_with"] = json.loads(d.get("conflicts_with") or "[]")
        for k in ("vector", "quantized", "q_signs"):
            d.pop(k, None)
        return d

    @staticmethod
    def _finding_key(title: str, category: str, addr: str) -> tuple[str, str, str]:
        """The stable identity used to coalesce repeated observations."""
        normalized_title = " ".join(str(title).lower().split())
        normalized_category = str(category or "general").strip().lower()
        return normalized_title, normalized_category, normalize_addr(addr)

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

    # ------------------------------------------------------------------
    # Code anchors and staleness
    # ------------------------------------------------------------------

    def current_anchor(self, addr: str, kind: str = "") -> dict[str, Any] | None:
        """Return the most recently observed code digest for ``addr``."""
        naddr = normalize_addr(addr)
        if not naddr:
            return None
        sql = "SELECT addr, kind, digest, seen_at FROM code_anchors WHERE addr=?"
        params: builtins.list[Any] = [naddr]
        if kind:
            sql += " AND kind=?"
            params.append(str(kind))
        # Prefer decompiled text over raw disassembly: it is the stronger signal.
        sql += " ORDER BY CASE kind WHEN 'decompile' THEN 0 ELSE 1 END, seen_at DESC LIMIT 1"
        with closing(self._conn()) as conn:
            row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def observe_code(self, addr: str, kind: str, text: str = "", digest: str = "") -> dict[str, Any]:
        """Record the code currently at ``addr`` and flag claims that predate it.

        Called after any operation that renders code for an address. When the
        digest differs from the one previously seen, every non-stale entry at
        that address whose anchor matches the *old* digest is marked stale —
        including examination verdicts, since "boring" is a claim about code
        that has now changed.
        """
        naddr = normalize_addr(addr)
        kind = str(kind or "").strip().lower()
        if not naddr or kind not in ANCHOR_KINDS:
            return {"ok": False, "reason": "addr and a known anchor kind are required"}
        new_digest = digest or code_digest(text)
        if not new_digest:
            return {"ok": False, "reason": "no code text to anchor"}

        now = time.time()
        with closing(self._conn()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT digest FROM code_anchors WHERE addr=? AND kind=?", (naddr, kind)
            ).fetchone()
            previous = row["digest"] if row else ""
            conn.execute(
                "INSERT INTO code_anchors(addr, kind, digest, seen_at) VALUES (?,?,?,?) "
                "ON CONFLICT(addr, kind) DO UPDATE SET digest=excluded.digest, seen_at=excluded.seen_at",
                (naddr, kind, new_digest, now),
            )
            marked: builtins.list[str] = []
            if previous and previous != new_digest:
                reason = f"code at {naddr} changed since this was recorded"
                rows = conn.execute(
                    "SELECT id FROM blackboard WHERE addr=? AND anchor_kind=? AND anchor_digest=? AND stale=0",
                    (naddr, kind, previous),
                ).fetchall()
                marked = [r["id"] for r in rows]
                if marked:
                    conn.execute(
                        "UPDATE blackboard SET stale=1, stale_reason=? WHERE id IN ("
                        + ",".join("?" for _ in marked)
                        + ")",
                        (reason, *marked),
                    )
            conn.commit()

        for eid in marked:
            self._record_event(eid, "stale", {"addr": naddr, "anchor_kind": kind})
        return {
            "ok": True,
            "addr": naddr,
            "kind": kind,
            "digest": new_digest,
            "changed": bool(previous and previous != new_digest),
            "stale_marked": len(marked),
        }

    def stale_entries(self, limit: int = 20) -> builtins.list[dict]:
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT * FROM blackboard WHERE stale=1 AND contradicted=0 "
                "ORDER BY confidence DESC, updated_at DESC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def clear_stale(self, entry_id: str) -> bool:
        """Re-anchor an entry to the current code and drop its stale flag."""
        entry = self.read(entry_id)
        if not entry:
            return False
        anchor = self.current_anchor(str(entry.get("addr") or ""))
        with closing(self._conn()) as conn:
            conn.execute(
                "UPDATE blackboard SET stale=0, stale_reason='', anchor_kind=?, anchor_digest=? WHERE id=?",
                (
                    (anchor or {}).get("kind", entry.get("anchor_kind") or ""),
                    (anchor or {}).get("digest", entry.get("anchor_digest") or ""),
                    entry_id,
                ),
            )
            conn.commit()
        return True

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

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
        verdict: str = "",
        anchor_kind: str = "",
        anchor_digest: str = "",
        **_legacy_kwargs,
    ) -> str:
        kind = str(kind or "finding").strip().lower()
        status = str(status or "open").strip().lower()
        verdict = str(verdict or "").strip().lower()
        if kind not in KINDS:
            raise ValueError("kind must be one of: " + ", ".join(sorted(KINDS)))
        if status not in STATUSES:
            raise ValueError("status must be open, confirmed, resolved, or rejected")
        if verdict and verdict not in VERDICTS:
            raise ValueError("verdict must be interesting, boring, or unclear")

        naddr = normalize_addr(addr)
        # Anchor the claim to whatever code was last rendered at this address,
        # so a later change can invalidate it.
        if naddr and not anchor_digest:
            anchor = self.current_anchor(naddr)
            if anchor:
                anchor_kind = anchor_kind or str(anchor.get("kind") or "")
                anchor_digest = str(anchor.get("digest") or "")

        entry_id = str(uuid.uuid4())[:8]
        now = time.time()
        vector_blob = self._embed_text(f"{title} {content}".strip()) if embed else None
        if not source_type:
            source_type = source
        with closing(self._conn()) as conn:
            conn.execute("""
                INSERT INTO blackboard
                    (id, category, title, content, addr, addr_end, tags, confidence,
                     created_at, updated_at, q_value, source, vector,
                     ioc_type, ioc_value, depends_on, blocks_addr, register, reg_type,
                     evidence, source_type, entropy, xref_count, version,
                     kind, status, priority, fingerprint, resolved, contradicted,
                     verdict, anchor_kind, anchor_digest, stale, stale_reason, conflicts_with)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,'','[]')
            """, (
                entry_id, category, title, content, naddr, addr_end,
                json.dumps(tags or []), _clamp01(confidence),
                now, now, _clamp01(confidence), source, vector_blob,
                ioc_type, ioc_value, normalize_addr(depends_on), blocks_addr, register, reg_type,
                json.dumps(evidence or []), source_type, entropy, xref_count, 1,
                kind, status, _clamp01(priority), fingerprint,
                int(status == "resolved"), int(status == "rejected"),
                verdict, anchor_kind, anchor_digest,
            ))
            conn.commit()
        self._record_event(entry_id, "created", {"kind": kind, "status": status})
        return entry_id

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
        """Create a claim, or merge it into the matching one.

        Two claims match when their (title, category, address, kind) agree
        after normalisation. On a match the evidence lists union, tags union,
        and priority takes the higher value — but confidence takes the *newest*
        value rather than the highest, and opposed statuses are refused: a
        rejection landing on a confirmation is stored as its own row and linked
        as a conflict for the analyst to resolve.
        """
        key = self._finding_key(title, category, addr)
        naddr = key[2]
        fingerprint = self._finding_fingerprint(title, category, addr, kind)
        clean_tags = sorted({str(tag).strip() for tag in (tags or []) if str(tag).strip()})
        clean_evidence = [item for item in (evidence or []) if isinstance(item, dict)]
        status = str(status or "open").strip().lower()

        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT * FROM blackboard WHERE fingerprint=? OR "
                "(lower(category)=? AND lower(COALESCE(addr,''))=?) "
                "ORDER BY updated_at DESC LIMIT 200",
                (fingerprint, key[1], naddr),
            ).fetchall()
        existing = next(
            (row for row in (self._row_to_dict(item) for item in rows)
             if row.get("fingerprint") == fingerprint or (
                 self._finding_key(row.get("title", ""), row.get("category", ""), row.get("addr", "")) == key
                 and str(row.get("kind") or "finding") == str(kind or "finding")
             )),
            None,
        )

        if existing is None:
            try:
                entry_id = self.write(
                    title=title,
                    content=content,
                    category=category,
                    addr=addr,
                    tags=clean_tags,
                    confidence=confidence,
                    evidence=clean_evidence,
                    source=source,
                    source_type=source,
                    embed=False,
                    kind=kind,
                    status=status,
                    priority=priority,
                    fingerprint=fingerprint,
                )
            except sqlite3.IntegrityError:
                # Another client recorded the same observation between our
                # lookup and insert. Re-read and merge into the winner.
                return self.upsert_finding(
                    title=title, content=content, category=category, addr=addr,
                    tags=clean_tags, confidence=confidence, evidence=clean_evidence,
                    source=source, kind=kind, status=status, priority=priority,
                )
            return {"entry_id": entry_id, "created": True, "version": 1, "conflict": None}

        existing_status = str(existing.get("status") or "open")
        if (existing_status, status) in _OPPOSED_STATUS:
            return self._record_conflicting_claim(
                existing=existing,
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

        # Serialize read/merge/write so simultaneous clients cannot lose each
        # other's evidence through a last-writer-wins update.
        with closing(self._conn()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM blackboard WHERE fingerprint=? ORDER BY updated_at DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if row is None:
                row = conn.execute(
                    "SELECT * FROM blackboard WHERE id=?", (str(existing["id"]),)
                ).fetchone()
            current = self._row_to_dict(row) if row else existing
            merged_tags = sorted(set(current.get("tags") or []) | set(clean_tags))
            merged_evidence = builtins.list(current.get("evidence") or [])
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
                "kind=?, status=?, resolved=?, contradicted=?, fingerprint=?, updated_at=?, version=? "
                "WHERE id=?",
                (
                    merged_content,
                    json.dumps(merged_tags),
                    json.dumps(merged_evidence),
                    # Newest assertion wins. Taking the maximum would let
                    # confidence ratchet upward on every restatement.
                    _clamp01(confidence),
                    max(_clamp01(current.get("priority"), 0.0), _clamp01(priority)),
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
            "conflict": None,
        }

    def _record_conflicting_claim(self, existing: dict[str, Any], **claim) -> dict[str, Any]:
        """Store an opposed assertion beside the one it contradicts."""
        # No fingerprint: the unique index must not collapse the two rows, and
        # the disagreement is the point.
        entry_id = self.write(
            title=claim["title"],
            content=claim["content"],
            category=claim["category"],
            addr=claim["addr"],
            tags=claim["tags"],
            confidence=claim["confidence"],
            evidence=claim["evidence"],
            source=claim["source"],
            source_type=claim["source"],
            kind=claim["kind"],
            status=claim["status"],
            priority=claim["priority"],
            fingerprint="",
        )
        reason = (
            f"{claim['status']} here contradicts {existing.get('status')} "
            f"on the same claim ({existing.get('id')})"
        )
        self.link_conflict(entry_id, str(existing["id"]), reason)
        return {
            "entry_id": entry_id,
            "created": True,
            "version": 1,
            "conflict": {
                "with": str(existing["id"]),
                "their_status": existing.get("status"),
                "your_status": claim["status"],
                "reason": reason,
                "resolve_with": "ida_update_finding",
            },
        }

    def link_conflict(self, entry_a: str, entry_b: str, reason: str = "") -> bool:
        """Record that two entries make incompatible claims. Symmetric."""
        if not entry_a or not entry_b or entry_a == entry_b:
            return False
        with closing(self._conn()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = {
                r["id"]: r for r in conn.execute(
                    "SELECT id, conflicts_with FROM blackboard WHERE id IN (?,?)", (entry_a, entry_b)
                ).fetchall()
            }
            if len(rows) != 2:
                conn.rollback()
                return False
            for this, other in ((entry_a, entry_b), (entry_b, entry_a)):
                links = json.loads(rows[this]["conflicts_with"] or "[]")
                if other not in links:
                    links.append(other)
                conn.execute(
                    "UPDATE blackboard SET conflicts_with=?, updated_at=? WHERE id=?",
                    (json.dumps(links), time.time(), this),
                )
            conn.commit()
        for eid, other in ((entry_a, entry_b), (entry_b, entry_a)):
            self._record_event(eid, "conflict", {"with": other, "reason": reason})
        return True

    def conflicts(self, limit: int = 20) -> builtins.list[dict]:
        """Return entries that contradict another entry, newest first."""
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT * FROM blackboard WHERE conflicts_with != '[]' AND conflicts_with IS NOT NULL "
                "ORDER BY updated_at DESC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Coverage: what was looked at and set aside
    # ------------------------------------------------------------------

    def record_examination(
        self,
        addr: str,
        verdict: str = "boring",
        note: str = "",
        name: str = "",
        source: str = "manual",
    ) -> dict[str, Any]:
        """Record that an address was read and judged, including "nothing here".

        One examination per address; a later verdict replaces the earlier one
        and the change is kept in the event log.
        """
        naddr = normalize_addr(addr)
        if not naddr:
            raise ValueError("address is required to record an examination")
        verdict = str(verdict or "boring").strip().lower()
        if verdict not in VERDICTS:
            raise ValueError("verdict must be interesting, boring, or unclear")
        title = f"examined {name}".strip() if name else f"examined {naddr}"

        with closing(self._conn()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT id, verdict FROM blackboard WHERE kind='examined' AND addr=? LIMIT 1",
                (naddr,),
            ).fetchone()
            existing_id = row["id"] if row else None
            previous = row["verdict"] if row else ""
            conn.commit()

        anchor = self.current_anchor(naddr) or {}
        if existing_id:
            with closing(self._conn()) as conn:
                conn.execute(
                    "UPDATE blackboard SET verdict=?, content=?, title=?, updated_at=?, "
                    "version=version+1, stale=0, stale_reason='', anchor_kind=?, anchor_digest=? "
                    "WHERE id=?",
                    (
                        verdict, note, title, time.time(),
                        str(anchor.get("kind") or ""), str(anchor.get("digest") or ""),
                        existing_id,
                    ),
                )
                conn.commit()
            self._record_event(
                existing_id, "examined", {"verdict": verdict, "previous": previous, "addr": naddr}
            )
            return {"entry_id": existing_id, "address": naddr, "verdict": verdict, "created": False}

        entry_id = self.write(
            title=title,
            content=note,
            category="coverage",
            addr=naddr,
            confidence=0.6 if verdict == "boring" else 0.4,
            kind="examined",
            status="resolved" if verdict == "boring" else "open",
            priority=0.1 if verdict == "boring" else 0.5,
            source=source,
            source_type=source,
            verdict=verdict,
            fingerprint=self._finding_fingerprint(title, "coverage", naddr, "examined"),
        )
        return {"entry_id": entry_id, "address": naddr, "verdict": verdict, "created": True}

    def examination(self, addr: str) -> dict[str, Any] | None:
        """Return the recorded verdict for an address, if it has been examined."""
        naddr = normalize_addr(addr)
        if not naddr:
            return None
        with closing(self._conn()) as conn:
            row = conn.execute(
                "SELECT * FROM blackboard WHERE kind='examined' AND addr=? LIMIT 1", (naddr,)
            ).fetchone()
        if row is None:
            return None
        entry = self._row_to_dict(row)
        return {
            "entry_id": entry.get("id"),
            "address": naddr,
            "verdict": entry.get("verdict") or "unclear",
            "note": entry.get("content") or "",
            "stale": bool(entry.get("stale")),
            "examined_at": entry.get("updated_at"),
        }

    def coverage(self) -> dict[str, Any]:
        """Counts of examined addresses by verdict."""
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT verdict, COUNT(*) AS n FROM blackboard WHERE kind='examined' GROUP BY verdict"
            ).fetchall()
        by_verdict = {str(r["verdict"] or "unclear"): int(r["n"]) for r in rows}
        return {"examined": sum(by_verdict.values()), "by_verdict": by_verdict}

    # ------------------------------------------------------------------
    # IDB round-trip
    # ------------------------------------------------------------------

    def publishable(self, limit: int = 50, include_published: bool = False) -> builtins.list[dict]:
        """Confirmed, addressed claims that belong in the database itself.

        The IDB is the artifact an analyst opens; a conclusion that lives only
        in this store is a conclusion they never see. Republishing is skipped
        unless the claim changed after it was last written, so running the
        export repeatedly is cheap and idempotent.
        """
        sql = (
            "SELECT * FROM blackboard WHERE status='confirmed' AND contradicted=0 "
            "AND stale=0 AND kind != 'examined' AND addr != '' AND addr IS NOT NULL "
            "AND (conflicts_with = '[]' OR conflicts_with IS NULL) "
        )
        if not include_published:
            sql += "AND (published_at IS NULL OR published_at < updated_at) "
        sql += "ORDER BY confidence DESC, updated_at DESC LIMIT ?"
        with closing(self._conn()) as conn:
            rows = conn.execute(sql, (max(1, int(limit)),)).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def mark_published(self, entry_id: str, symbol: str = "") -> bool:
        with closing(self._conn()) as conn:
            cur = conn.execute(
                "UPDATE blackboard SET published_at=?, published_symbol=? WHERE id=?",
                (time.time(), symbol, entry_id),
            )
            conn.commit()
            ok = cur.rowcount > 0
        if ok:
            self._record_event(entry_id, "published", {"symbol": symbol} if symbol else {})
        return ok

    def comment_for(self, entry: dict[str, Any], max_len: int = 400) -> str:
        """Render a finding as the IDB comment that will carry it."""
        title = str(entry.get("title") or "").strip()
        content = str(entry.get("content") or "").strip()
        confidence = entry.get("confidence")
        head = title
        if confidence is not None:
            head += f" (confidence {round(float(confidence), 2)})"
        body = f"{head}\n{content}".strip() if content else head
        marker = marker_for(str(entry.get("id") or ""))
        room = max_len - len(marker) - 1
        if len(body) > room:
            body = body[: max(0, room - 1)].rstrip() + "…"
        return f"{body} {marker}"

    def adopt_annotation(
        self,
        addr: str,
        name: str = "",
        comment: str = "",
        source: str = "idb",
    ) -> dict[str, Any] | None:
        """Record understanding that already exists in the IDB as a finding.

        Skips anything this tool wrote: a comment carrying our own marker is
        our own output, and adopting it back would manufacture a second,
        independent-looking claim out of one.
        """
        naddr = normalize_addr(addr)
        if not naddr:
            return None
        text = str(comment or "").strip()
        if entry_id_in(text):
            return None
        named = not is_auto_name(name)
        if not named and not text:
            return None

        title = text.splitlines()[0].strip() if text else f"{name} (named in the IDB)"
        title = title[:120]
        return self.upsert_finding(
            title=title,
            content=text if text else "",
            category="idb",
            addr=naddr,
            kind="finding",
            status="confirmed",
            # Someone recorded this deliberately, but this tool did not verify
            # it and cannot tell an analyst's rename from a FLIRT match.
            confidence=0.5,
            priority=0.3,
            tags=["from-idb"],
            source=source,
            evidence=[{"type": "idb_symbol", "value": name}] if named else [],
        )

    # ------------------------------------------------------------------
    # Recall: what the workspace already knows about these addresses
    # ------------------------------------------------------------------

    def recall(
        self,
        addrs: builtins.list[str] | tuple[str, ...],
        limit: int = 6,
        include_open_threads: bool = True,
    ) -> dict[str, Any]:
        """Return prior knowledge about a set of addresses.

        This is the read path that runs *without being asked* — findings the
        model already recorded, verdicts it already reached, and questions it
        left open. Recording knowledge that never comes back is the failure
        this exists to prevent, so it is deliberately cheap and deterministic:
        exact address matches only, no embeddings, no network, bounded work.
        """
        wanted = [a for a in (normalize_addr(x) for x in (addrs or [])) if a]
        # Preserve caller order, drop duplicates.
        seen: set[str] = set()
        ordered = [a for a in wanted if not (a in seen or seen.add(a))][:16]
        result: dict[str, Any] = {
            "addresses": ordered,
            "examined": [],
            "findings": [],
            "open_threads": [],
        }
        if not ordered:
            return result

        placeholders = ",".join("?" for _ in ordered)
        with closing(self._conn()) as conn:
            rows = conn.execute(
                f"SELECT * FROM blackboard WHERE addr IN ({placeholders}) "
                "AND lower(COALESCE(source_type,'')) NOT IN ("
                + ",".join("?" for _ in _INTERNAL_WORKSPACE_SOURCE_TYPES)
                + ") ORDER BY confidence DESC, updated_at DESC LIMIT 200",
                (*ordered, *sorted(_INTERNAL_WORKSPACE_SOURCE_TYPES)),
            ).fetchall()

        rank = {addr: i for i, addr in enumerate(ordered)}
        entries = [self._row_to_dict(r) for r in rows]
        entries.sort(key=lambda e: (rank.get(str(e.get("addr") or ""), 99), -float(e.get("confidence") or 0.0)))

        for entry in entries:
            kind = str(entry.get("kind") or "finding")
            status = str(entry.get("status") or "open")
            if kind == "examined":
                if len(result["examined"]) < limit:
                    result["examined"].append({
                        "address": entry.get("addr"),
                        "verdict": entry.get("verdict") or "unclear",
                        "note": (entry.get("content") or "")[:160],
                        "stale": bool(entry.get("stale")),
                    })
                continue
            item = {
                "id": entry.get("id"),
                "kind": kind,
                "status": status,
                "title": entry.get("title"),
                "address": entry.get("addr"),
                "confidence": entry.get("confidence"),
            }
            if entry.get("stale"):
                item["stale"] = entry.get("stale_reason") or "code changed since this was recorded"
            if entry.get("conflicts_with"):
                item["conflicts_with"] = entry["conflicts_with"]
            if include_open_threads and kind in OPEN_THREAD_KINDS and status == "open":
                if len(result["open_threads"]) < limit:
                    result["open_threads"].append(item)
            elif len(result["findings"]) < limit:
                result["findings"].append(item)

        result["counts"] = {
            "findings": len(result["findings"]),
            "open_threads": len(result["open_threads"]),
            "examined": len(result["examined"]),
        }
        return result

    def recall_lines(self, addrs: builtins.list[str], limit: int = 4) -> builtins.list[str]:
        """Render :meth:`recall` as a few one-line hints for a compact payload."""
        data = self.recall(addrs, limit=limit)
        lines: builtins.list[str] = []
        for item in data["examined"]:
            note = f" — {item['note']}" if item["note"] else ""
            flag = " [stale]" if item.get("stale") else ""
            lines.append(f"already examined {item['address']}: {item['verdict']}{note}{flag}")
        for item in data["findings"] + data["open_threads"]:
            parts = [f"{item['kind']}/{item['status']}: {item['title']}"]
            if item.get("address"):
                parts.append(f"@ {item['address']}")
            line = " — ".join(parts)
            if item.get("stale"):
                line += " [stale: code changed since this was recorded]"
            if item.get("conflicts_with"):
                line += f" [conflicts with {', '.join(item['conflicts_with'])}]"
            lines.append(line)
        return lines[: max(1, int(limit))]

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

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
        verdict: str | None = None,
        stale_only: bool = False,
    ) -> builtins.list[dict]:
        conditions = ["confidence >= ?"]
        params: builtins.list[Any] = [min_confidence]
        if category:
            conditions.append("category = ?")
            params.append(category)
        if addr:
            conditions.append("addr = ?")
            params.append(normalize_addr(addr))
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
        if verdict:
            conditions.append("verdict = ?")
            params.append(verdict)
        if stale_only:
            conditions.append("stale = 1")
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
        """Vector search over entries, falling back to keyword overlap.

        The fallback is not a silent downgrade: entries returned lexically
        carry a ``similarity`` derived from term overlap and a ``match``
        field naming which path produced them.
        """
        def lexical_search() -> builtins.list[dict]:
            q = query.lower()
            terms = {term for term in q.split() if len(term) > 1}
            with closing(self._conn()) as conn:
                rows = conn.execute(
                    "SELECT * FROM blackboard ORDER BY updated_at DESC LIMIT 200"
                ).fetchall()
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
                    d["match"] = "lexical"
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
        params: builtins.list[Any] = []
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

        scored = []
        for row in rows:
            blob = row["vector"]
            if not blob:
                continue
            try:
                sim = dot_product(q_vec, unpack_floats(blob))
            except Exception:
                continue
            if sim >= threshold:
                d = self._row_to_dict(row)
                d["similarity"] = round(sim, 4)
                d["match"] = "semantic"
                scored.append(d)

        if not scored:
            return lexical_search()
        scored.sort(key=lambda x: x["similarity"], reverse=True)
        return scored[:top_k]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def update(self, entry_id: str, embed: bool = False, **kwargs) -> bool:
        allowed = {
            "title", "content", "category", "addr", "addr_end", "tags",
            "confidence", "q_value", "resolved", "ioc_type", "ioc_value",
            "depends_on", "blocks_addr", "register", "reg_type",
            "evidence", "source_type", "entropy", "xref_count", "calibrated",
            "kind", "status", "priority", "fingerprint", "contradicted",
            "contradiction_reason", "verdict", "anchor_kind", "anchor_digest",
            "stale", "stale_reason",
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        with closing(self._conn()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM blackboard WHERE id=?", (entry_id,)).fetchone()
            if row is None:
                conn.rollback()
                return False
            current = self._row_to_dict(row)
            if "tags" in updates and isinstance(updates["tags"], builtins.list):
                updates["tags"] = sorted(
                    set(current.get("tags") or [])
                    | {str(tag).strip() for tag in updates["tags"] if str(tag).strip()}
                )
            if "evidence" in updates and isinstance(updates["evidence"], builtins.list):
                merged_evidence = builtins.list(current.get("evidence") or [])
                seen = {json.dumps(item, sort_keys=True, ensure_ascii=True) for item in merged_evidence}
                for item in updates["evidence"]:
                    if not isinstance(item, dict):
                        continue
                    marker = json.dumps(item, sort_keys=True, ensure_ascii=True)
                    if marker not in seen:
                        merged_evidence.append(item)
                        seen.add(marker)
                updates["evidence"] = merged_evidence
            if "addr" in updates:
                updates["addr"] = normalize_addr(updates["addr"])
            # Any deliberate revision re-anchors the claim to the code as it
            # stands now, so a stale flag the analyst has acted on clears.
            if "stale" not in updates and current.get("stale"):
                anchor = self.current_anchor(str(updates.get("addr") or current.get("addr") or "")) or {}
                if anchor:
                    updates["stale"] = 0
                    updates["stale_reason"] = ""
                    updates["anchor_kind"] = str(anchor.get("kind") or "")
                    updates["anchor_digest"] = str(anchor.get("digest") or "")
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
                f"UPDATE blackboard SET {sets} WHERE id = ?", (*updates.values(), entry_id)
            )
            conn.commit()
            ok = cur.rowcount > 0
        if ok:
            self._record_event(
                entry_id, "updated",
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
        if status not in STATUSES:
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
            updates["confidence"] = _clamp01(confidence)
        if priority is not None:
            updates["priority"] = _clamp01(priority)
        if tags is not None:
            updates["tags"] = sorted({str(tag).strip() for tag in tags if str(tag).strip()})
        self.update(entry_id, embed=False, **updates)
        self._record_event(entry_id, f"status:{status}", {"reason": reason} if reason else {})
        return self.read(entry_id)

    def contradict(self, entry_id: str, reason: str) -> bool:
        with closing(self._conn()) as conn:
            cur = conn.execute(
                "UPDATE blackboard SET contradicted=1, status='rejected', "
                "contradiction_reason=?, updated_at=? WHERE id=?",
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

    def add_evidence(self, entry_id: str, evidence_type: str, value: str, weight: float = 1.0) -> bool:
        """Append a structured observation supporting an entry."""
        entry = self.read(entry_id)
        if not entry:
            return False
        ev_list = entry.get("evidence") or []
        ev_list.append({
            "type": evidence_type,
            "value": str(value),
            "weight": round(_clamp01(weight, 1.0), 3),
            "ts": round(time.time(), 1),
        })
        return self.update(entry_id, evidence=ev_list)

    def calibrate_confidence(self, entry_id: str) -> float | None:
        """Set confidence to the mean weight of the attached evidence.

        This is an averaging heuristic, not calibration against outcomes:
        nothing here has been validated against whether the claim held up.
        It is useful only because evidence weights are assigned by the same
        caller that wrote the claim, so it surfaces claims whose author was
        privately unsure. Treat the result as a prior, not a probability.
        """
        entry = self.read(entry_id)
        if not entry:
            return None
        ev_list = entry.get("evidence") or []
        if not ev_list:
            return entry.get("confidence")
        weights = [_clamp01(e.get("weight"), 0.5) for e in ev_list]
        new_conf = round(max(0.1, min(0.99, sum(weights) / len(weights))), 3)
        self.update(entry_id, confidence=new_conf, calibrated=1)
        return new_conf

    def decay_stale_confidence(self, half_life_days: float = 14.0, min_confidence: float = 0.1) -> int:
        """Reduce confidence on entries nobody has touched recently.

        Anchor drift is the primary staleness signal; this is the weaker,
        time-based one, kept for claims at addresses whose code was never
        re-rendered. Entries with evidence or calibration decay at half rate.

        ``elapsed`` is measured from the later of the last edit and the last
        decay run so repeated runs compound instead of re-applying the full age.
        Only ``decayed_at`` is written: touching ``updated_at`` would make a
        stale entry sort as the most recently edited and reset its own age.
        """
        now = time.time()
        decay_rate = math.log(2) / max(half_life_days, 1.0)
        updated = 0
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT id, confidence, updated_at, decayed_at, calibrated, evidence "
                "FROM blackboard WHERE confidence > ?",
                (min_confidence,),
            ).fetchall()
            for row in rows:
                conf = row["confidence"]
                if conf is None or conf <= min_confidence:
                    continue
                since = max(row["updated_at"] or now, row["decayed_at"] or 0.0)
                elapsed_days = (now - since) / 86400
                if elapsed_days < 1:
                    continue
                ev_json = row["evidence"]
                supported = bool(row["calibrated"]) or bool(ev_json and ev_json != "[]")
                rate = decay_rate * (0.5 if supported else 1.0)
                new_conf = round(max(min_confidence, conf * math.exp(-elapsed_days * rate)), 3)
                if new_conf < conf - 0.01:
                    conn.execute(
                        "UPDATE blackboard SET confidence=?, decayed_at=? WHERE id=?",
                        (new_conf, now, row["id"]),
                    )
                    updated += 1
            conn.commit()
        return updated

    # ------------------------------------------------------------------
    # Target selection
    # ------------------------------------------------------------------

    def targets(
        self,
        strategy: str = "unresolved",
        limit: int = 5,
        rpc_fn=None,
        query: str | None = None,
    ) -> dict[str, Any]:
        """Suggest what to look at next, using one named, explainable strategy.

        ``unresolved``
            Open questions, hypotheses, and tasks whose blocking address is
            already resolved, then recorded-but-unverified findings.
        ``stale``
            Claims whose underlying code changed after they were written.
        ``conflict``
            Entries that contradict another entry and need reconciling.
        ``coverage``
            Frequently-called functions with no finding and no examination.
            Requires ``rpc_fn`` to read the function inventory.
        ``frontier``
            Unexamined neighbours of confirmed findings. Requires ``rpc_fn``.

        Every candidate carries a ``reason`` naming why it was chosen. There is
        no blended score: a ranking the caller cannot explain is one nobody can
        debug, and the previous implementation's six hand-tuned coefficients
        were never calibrated against whether the suggestion paid off.
        """
        strategy = str(strategy or "unresolved").strip().lower()
        if strategy not in STRATEGIES:
            raise ValueError("strategy must be one of: " + ", ".join(STRATEGIES))
        limit = max(1, min(100, int(limit or 5)))

        builder = {
            "unresolved": self._targets_unresolved,
            "stale": self._targets_stale,
            "conflict": self._targets_conflict,
            "coverage": self._targets_coverage,
            "frontier": self._targets_frontier,
        }[strategy]
        candidates = builder(limit=limit, rpc_fn=rpc_fn)

        if query and str(query).strip():
            candidates = self._filter_by_query(candidates, str(query).strip())

        return {
            "strategy": strategy,
            "targets": candidates[:limit],
            "count": len(candidates[:limit]),
        }

    def _filter_by_query(
        self, candidates: builtins.list[dict], query: str
    ) -> builtins.list[dict]:
        """Rank candidates by keyword overlap with a theme, keeping all of them.

        Filtering would hide work; this only reorders, and records the overlap
        so the caller can see how weak the match was.
        """
        terms = {t for t in query.lower().split() if len(t) > 1}
        if not terms:
            return candidates
        for item in candidates:
            text = f"{item.get('title','')} {item.get('reason','')} {item.get('category','')}".lower()
            hits = sum(1 for t in terms if t in text)
            item["query_overlap"] = round(hits / len(terms), 3)
        return sorted(candidates, key=lambda i: i.get("query_overlap", 0.0), reverse=True)

    def _resolved_addrs(self) -> set:
        with closing(self._conn()) as conn:
            return {
                r["addr"] for r in conn.execute(
                    "SELECT addr FROM blackboard WHERE status IN ('resolved','confirmed') "
                    "AND addr != '' AND addr IS NOT NULL"
                ).fetchall()
            }

    def _targets_unresolved(self, limit: int, rpc_fn=None) -> builtins.list[dict]:
        resolved = self._resolved_addrs()
        placeholders = ",".join("?" for _ in OPEN_THREAD_KINDS)
        with closing(self._conn()) as conn:
            rows = conn.execute(
                f"SELECT * FROM blackboard WHERE kind IN ({placeholders}) AND status='open' "
                "AND contradicted=0 ORDER BY priority DESC, confidence DESC, updated_at DESC LIMIT 200",
                tuple(sorted(OPEN_THREAD_KINDS)),
            ).fetchall()
            unverified = conn.execute(
                "SELECT * FROM blackboard WHERE kind='finding' AND status='open' AND contradicted=0 "
                "AND confidence < 0.6 ORDER BY priority DESC, updated_at DESC LIMIT 100"
            ).fetchall()

        out: builtins.list[dict] = []
        blocked: builtins.list[dict] = []
        for row in rows:
            entry = self._row_to_dict(row)
            depends_on = normalize_addr(entry.get("depends_on") or "")
            item = self._target_item(entry, reason=f"open {entry.get('kind')}")
            if depends_on and depends_on not in resolved:
                item["reason"] = f"open {entry.get('kind')}, blocked on {depends_on}"
                item["blocked_on"] = depends_on
                blocked.append(item)
                continue
            if depends_on:
                item["reason"] = f"open {entry.get('kind')}, dependency {depends_on} is resolved"
            out.append(item)

        for row in unverified:
            if len(out) >= limit:
                break
            entry = self._row_to_dict(row)
            out.append(self._target_item(
                entry,
                reason=f"recorded at confidence {round(float(entry.get('confidence') or 0), 2)}, never verified",
            ))
        # Blocked items rank last: they are real work, just not yet actionable.
        return out + blocked

    def _targets_stale(self, limit: int, rpc_fn=None) -> builtins.list[dict]:
        return [
            self._target_item(entry, reason=entry.get("stale_reason") or "code changed since this was recorded")
            for entry in self.stale_entries(limit=limit * 2)
        ]

    def _targets_conflict(self, limit: int, rpc_fn=None) -> builtins.list[dict]:
        out = []
        for entry in self.conflicts(limit=limit * 2):
            others = ", ".join(entry.get("conflicts_with") or [])
            out.append(self._target_item(entry, reason=f"contradicts {others}; needs reconciling"))
        return out

    def _targets_coverage(self, limit: int, rpc_fn=None) -> builtins.list[dict]:
        """Frequently-called functions nobody has looked at yet.

        Auto-named functions (``sub_``, ``j_``, …) come first: a name means
        either IDA matched a library signature or someone already understood
        the function, and neither is a good use of the next turn. If the
        binary has symbols and nothing is auto-named, this falls back to every
        unexamined function and says so in the reason, rather than returning
        nothing on a symbolised target.
        """
        functions = self._function_inventory(rpc_fn)
        if not functions:
            return []
        with closing(self._conn()) as conn:
            known = {
                r["addr"] for r in conn.execute(
                    "SELECT DISTINCT addr FROM blackboard WHERE addr != '' AND addr IS NOT NULL"
                ).fetchall()
            }

        def is_auto_named(name: str) -> bool:
            return not name or name.startswith(("sub_", "j_", "loc_", "nullsub_", "unknown_libname_"))

        fresh = [
            fn for fn in functions
            if normalize_addr(fn.get("addr")) and normalize_addr(fn.get("addr")) not in known
        ]
        unnamed = [fn for fn in fresh if is_auto_named(str(fn.get("name") or ""))]
        pool, named_fallback = (unnamed, False) if unnamed else (fresh, True)

        out = []
        for fn in sorted(pool, key=lambda f: -int(f.get("xref_count") or 0)):
            addr = normalize_addr(fn.get("addr"))
            xrefs = int(fn.get("xref_count") or 0)
            reason = f"{xrefs} callers, never examined" if xrefs else "never examined"
            if named_fallback:
                reason += "; no auto-named functions left to prefer"
            out.append({
                "address": addr,
                "entry_id": None,
                "kind": "candidate",
                "status": "open",
                "title": fn.get("name") or addr,
                "category": "coverage",
                "confidence": None,
                "reason": reason,
                "xref_count": xrefs,
            })
            if len(out) >= limit * 2:
                break
        return out

    def _targets_frontier(self, limit: int, rpc_fn=None) -> builtins.list[dict]:
        """Unexamined neighbours of what is already confirmed."""
        if rpc_fn is None:
            return []
        with closing(self._conn()) as conn:
            anchors = conn.execute(
                "SELECT id, addr, title FROM blackboard WHERE status='confirmed' "
                "AND addr != '' AND addr IS NOT NULL ORDER BY confidence DESC LIMIT 12"
            ).fetchall()
            known = {
                r["addr"] for r in conn.execute(
                    "SELECT DISTINCT addr FROM blackboard WHERE addr != '' AND addr IS NOT NULL"
                ).fetchall()
            }
        out: builtins.list[dict] = []
        seen: set[str] = set()
        for anchor in anchors:
            for direction in ("callers", "callees"):
                for neighbour in self._neighbours(rpc_fn, anchor["addr"], direction):
                    naddr = normalize_addr(neighbour)
                    if not naddr or naddr in known or naddr in seen:
                        continue
                    seen.add(naddr)
                    verb = "calls into" if direction == "callers" else "is called by"
                    out.append({
                        "address": naddr,
                        "entry_id": None,
                        "kind": "candidate",
                        "status": "open",
                        "title": naddr,
                        "category": "frontier",
                        "confidence": None,
                        "reason": f"{verb} confirmed \"{anchor['title']}\" at {anchor['addr']}",
                        "anchor_entry_id": anchor["id"],
                    })
            if len(out) >= limit * 2:
                break
        return out

    @staticmethod
    def _target_item(entry: dict[str, Any], reason: str) -> dict[str, Any]:
        item = {
            "address": entry.get("addr") or None,
            "entry_id": entry.get("id"),
            "kind": entry.get("kind") or "finding",
            "status": entry.get("status") or "open",
            "title": entry.get("title"),
            "category": entry.get("category"),
            "confidence": entry.get("confidence"),
            "priority": entry.get("priority"),
            "reason": reason,
        }
        if entry.get("stale"):
            item["stale"] = True
        if entry.get("conflicts_with"):
            item["conflicts_with"] = entry["conflicts_with"]
        return item

    @staticmethod
    def _neighbours(rpc_fn, addr: str, direction: str) -> builtins.list[str]:
        try:
            result = rpc_fn("code", {"action": direction, "addrs": addr})
        except Exception:
            return []
        if not isinstance(result, dict):
            return []
        found: builtins.list[str] = []
        for value in result.values():
            if isinstance(value, builtins.list):
                for item in value:
                    if isinstance(item, dict):
                        candidate = item.get("addr") or item.get("address") or item.get("ea")
                        if candidate:
                            found.append(str(candidate))
                    elif isinstance(item, (str, int)):
                        found.append(str(item))
        return found[:32]

    def _function_inventory(self, rpc_fn) -> builtins.list[dict]:
        """Fetch functions from the live IDA session, tolerating both shapes."""
        if rpc_fn is None:
            return []
        try:
            result = rpc_fn("data", {"action": "functions", "count": 200})
        except Exception:
            return []
        funcs = result.get("functions", []) if isinstance(result, dict) else []
        if isinstance(funcs, builtins.list):
            out = []
            for fn in funcs:
                if not isinstance(fn, dict):
                    continue
                addr = fn.get("start_ea") or fn.get("addr")
                if addr is None:
                    continue
                out.append({
                    "addr": hex(addr) if isinstance(addr, int) else str(addr),
                    "name": fn.get("name") or "",
                    "xref_count": fn.get("xref_count") or fn.get("callers_count") or 0,
                })
            return out
        if isinstance(funcs, str):
            out = []
            for line in funcs.splitlines():
                parts = [p for p in line.strip().split("  ") if p]
                if len(parts) < 4:
                    continue
                xref_count = 0
                for p in parts:
                    if p.startswith("xrefs="):
                        try:
                            xref_count = int(p.split("=", 1)[1])
                        except ValueError:
                            xref_count = 0
                        break
                out.append({"addr": parts[0].strip(), "name": parts[3].strip(), "xref_count": xref_count})
            return out
        return []

    def next_target(self, limit: int = 5, rpc_fn=None, query: str | None = None) -> builtins.list[dict]:
        """Compatibility shim over :meth:`targets`.

        Runs ``unresolved`` and tops up from ``coverage`` when the workspace is
        too sparse to have opinions yet. Kept because several resource handlers
        and the legacy tool surface call it positionally.
        """
        self.last_query_applied = None if not (query and str(query).strip()) else True
        self.last_query_error = ""
        found = self.targets("unresolved", limit=limit, rpc_fn=rpc_fn, query=query)["targets"]
        if len(found) < limit and rpc_fn is not None:
            topup = self.targets("coverage", limit=limit - len(found), rpc_fn=rpc_fn, query=query)
            found = found + topup["targets"]
        # Legacy callers read ``addr``/``priority_score``; keep both spellings.
        for rank, item in enumerate(found[:limit]):
            item.setdefault("addr", item.get("address"))
            item.setdefault("priority_score", round(1.0 - rank * 0.01, 4))
            item.setdefault("source_type", "seed" if item.get("entry_id") is None else "workspace")
        return found[:limit]

    # ------------------------------------------------------------------
    # Briefing
    # ------------------------------------------------------------------

    def workspace_brief(self, limit: int = 8) -> dict[str, Any]:
        """A compact snapshot of the investigation, plus a prose rendering."""
        limit = max(1, min(50, int(limit or 8)))
        cat_placeholders = ",".join("?" for _ in _INTERNAL_WORKSPACE_CATEGORIES)
        src_placeholders = ",".join("?" for _ in _INTERNAL_WORKSPACE_SOURCE_TYPES)
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT * FROM blackboard WHERE contradicted=0 AND kind != 'examined' "
                f"AND lower(category) NOT IN ({cat_placeholders}) "
                f"AND lower(COALESCE(source_type, '')) NOT IN ({src_placeholders}) "
                "ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'confirmed' THEN 1 ELSE 2 END, "
                "priority DESC, confidence DESC, updated_at DESC LIMIT 500",
                (*sorted(_INTERNAL_WORKSPACE_CATEGORIES), *sorted(_INTERNAL_WORKSPACE_SOURCE_TYPES)),
            ).fetchall()
            conflict_rows = conn.execute(
                "SELECT * FROM blackboard WHERE contradicted=1 OR status='rejected' "
                "OR (conflicts_with != '[]' AND conflicts_with IS NOT NULL) "
                "ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
            recent_events = conn.execute(
                "SELECT entry_id, event, details, created_at FROM finding_events "
                "ORDER BY seq DESC LIMIT ?", (limit,)
            ).fetchall()
        entries = [self._row_to_dict(row) for row in rows]
        conflicts = [self._row_to_dict(row) for row in conflict_rows]
        stale = self.stale_entries(limit=limit)
        cover = self.coverage()

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
            if entry.get("stale"):
                result["stale"] = entry.get("stale_reason") or True
            if entry.get("conflicts_with"):
                result["conflicts_with"] = entry["conflicts_with"]
            return result

        open_items = [item for item in entries if (item.get("status") or "open") == "open"]
        questions = [item for item in open_items if (item.get("kind") or "finding") in OPEN_THREAD_KINDS]
        confirmed = [item for item in entries if (item.get("status") or "open") == "confirmed"]

        payload = {
            "counts": {
                "total": len(entries) + len(conflicts),
                "open": len(open_items),
                "confirmed": len(confirmed),
                "conflicts": len(conflicts),
                "questions": len(questions),
                "stale": len(stale),
                "examined": cover["examined"],
            },
            "focus": [brief(item) for item in (questions or open_items)[:limit]],
            "confirmed": [brief(item) for item in confirmed[:limit]],
            "conflicts": [brief(item) for item in conflicts],
            "stale": [brief(item) for item in stale],
            "coverage": cover,
            "recent_activity": [
                {
                    "entry_id": row["entry_id"],
                    "event": row["event"],
                    "details": json.loads(row["details"] or "{}"),
                    "created_at": row["created_at"],
                }
                for row in recent_events
            ],
        }
        payload["brief"] = self._render_brief(payload)
        return payload

    @staticmethod
    def _render_brief(payload: dict[str, Any]) -> str:
        """Turn the structured brief into a case file readable on turn one.

        A model starting a session should not have to parse four JSON arrays
        to learn where the last one got to. This states what is established,
        what is open, what is contested, what needs re-checking, and what to
        do next — in the order an analyst would ask.
        """
        counts = payload["counts"]
        cover = payload["coverage"]
        if not counts["total"] and not cover["examined"]:
            return (
                "Workspace is empty — nothing recorded or examined yet.\n\n"
                "Next: ida_overview to orient, then ida_next_target(strategy='coverage')."
            )

        lines: builtins.list[str] = []

        def loc(item: dict) -> str:
            return f"{item['address']} " if item.get("address") else ""

        def conf(item: dict) -> str:
            value = item.get("confidence")
            return f" ({round(float(value), 2)})" if value is not None else ""

        def section(title: str, items: builtins.list[dict], render) -> None:
            if not items:
                return
            lines.append("")
            lines.append(f"{title}:")
            lines.extend(f"  - {render(item)}" for item in items)

        # --- headline -----------------------------------------------------
        parts = []
        if counts["confirmed"]:
            parts.append(f"{counts['confirmed']} confirmed")
        if counts["open"]:
            parts.append(f"{counts['open']} open")
        if counts["conflicts"]:
            parts.append(f"{counts['conflicts']} contested")
        if counts["stale"]:
            parts.append(f"{counts['stale']} stale")
        state = ", ".join(parts) if parts else "nothing settled yet"
        lines.append(f"{counts['total']} recorded items: {state}.")

        if cover["examined"]:
            by_verdict = ", ".join(
                f"{n} {v}" for v, n in sorted(cover["by_verdict"].items(), key=lambda kv: -kv[1])
            )
            lines.append(
                f"{cover['examined']} addresses examined and set aside ({by_verdict}) — "
                "do not re-read these without a reason."
            )

        # --- the case ------------------------------------------------------
        section(
            "Established", payload["confirmed"],
            lambda i: f"{loc(i)}{i['title']}{conf(i)}"
            + (f"  [stale: {i['stale']}]" if i.get("stale") else ""),
        )
        section(
            "Open", payload["focus"],
            lambda i: f"{loc(i)}[{i['kind']}] {i['title']}"
            + (f" — blocked on {i['depends_on']}" if i.get("depends_on") else ""),
        )
        section(
            "Contested — two claims here cannot both hold", payload["conflicts"],
            lambda i: f"{loc(i)}{i['title']} — recorded {i['status']}"
            + (f", contradicts {', '.join(i['conflicts_with'])}" if i.get("conflicts_with") else ""),
        )
        section(
            "Needs re-checking — the code changed after these were written",
            payload["stale"],
            lambda i: f"{loc(i)}{i['title']}{conf(i)}",
        )

        # --- what to do ----------------------------------------------------
        lines.append("")
        if payload["conflicts"]:
            lines.append(
                "Next: reconcile the contested claims with ida_update_finding before "
                "building on either side."
            )
        elif payload["stale"]:
            lines.append(
                "Next: re-read the entries above — ida_next_target(strategy='stale') "
                "lists them with their addresses."
            )
        elif payload["focus"]:
            blocked = [i for i in payload["focus"] if i.get("depends_on")]
            if len(blocked) == len(payload["focus"]):
                lines.append(
                    "Next: every open item is blocked. Resolve a dependency, or "
                    "ida_next_target(strategy='coverage') for unrelated ground."
                )
            else:
                lines.append("Next: take an unblocked open item above.")
        elif payload["confirmed"]:
            lines.append(
                "Next: ida_next_target(strategy='frontier') to expand from what is "
                "confirmed, or publish it with ida_publish_findings."
            )
        else:
            lines.append("Next: ida_next_target(strategy='coverage') for unexamined functions.")
        return "\n".join(lines)

    def campaign_summary(self) -> dict:
        """Legacy summary shape, derived from the same data as the brief."""
        brief = self.workspace_brief(limit=5)
        stats = self.stats()
        with closing(self._conn()) as conn:
            iocs = conn.execute(
                "SELECT ioc_type, ioc_value, addr, confidence FROM blackboard "
                "WHERE category='ioc' AND resolved=0 ORDER BY confidence DESC LIMIT 10"
            ).fetchall()
            vulns = conn.execute(
                "SELECT title, addr, confidence FROM blackboard "
                "WHERE category='vuln' AND resolved=0 ORDER BY confidence DESC LIMIT 5"
            ).fetchall()
        return {
            "total_entries": stats["total_entries"],
            "active_entries": stats["total_entries"] - stats["resolved"] - stats["contradicted"],
            "resolved": stats["resolved"],
            "contradicted": stats["contradicted"],
            "by_category": stats["by_category"],
            "source_types": stats["source_types"],
            "total_evidence_records": stats["total_evidence_records"],
            "top_findings": brief["confirmed"],
            "iocs": [dict(r) for r in iocs],
            "vulns": [dict(r) for r in vulns],
            "brief": brief["brief"],
        }

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def semantic_index(self, category: str | None = None) -> dict[str, Any]:
        conditions = []
        params: builtins.list[Any] = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        with closing(self._conn()) as conn:
            total = conn.execute(f"SELECT COUNT(*) AS n FROM blackboard {where}", params).fetchone()["n"]
            embedded = conn.execute(
                f"SELECT COUNT(*) AS n FROM blackboard {where}{' AND' if where else 'WHERE'} vector IS NOT NULL",
                params,
            ).fetchone()["n"]
        return {
            "ok": True,
            "total": total,
            "embedded": embedded,
            "missing": max(0, total - embedded),
            "category": category or "",
        }

    def semantic_rebuild(self, category: str | None = None, force: bool = False, limit: int = 5000) -> dict[str, Any]:
        conditions = [] if force else ["vector IS NULL"]
        params: builtins.list[Any] = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        with closing(self._conn()) as conn:
            rows = conn.execute(
                f"SELECT id, title, content FROM blackboard {where} LIMIT ?", (*params, int(limit))
            ).fetchall()
        rebuilt = 0
        skipped = 0
        for row in rows:
            blob = self._embed_text(f"{row['title'] or ''} {row['content'] or ''}".strip())
            if not blob:
                skipped += 1
                continue
            with closing(self._conn()) as conn:
                conn.execute(
                    "UPDATE blackboard SET vector=? WHERE id=?", (blob, row["id"])
                )
                conn.commit()
            rebuilt += 1
        result = {
            "ok": True,
            "rebuilt": rebuilt,
            "category": category or "",
            "forced": bool(force),
        }
        if skipped:
            result["skipped"] = skipped
            result["note"] = "Embedding backend unavailable for the skipped entries."
        return result

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
            head = conn.execute(
                "SELECT COUNT(*) AS total, COUNT(DISTINCT category) AS cats, "
                "AVG(confidence) AS avg_conf FROM blackboard"
            ).fetchone()
            by_cat = {r["category"]: r["n"] for r in conn.execute(
                "SELECT category, COUNT(*) AS n FROM blackboard GROUP BY category"
            ).fetchall()}
            scalars = conn.execute(
                "SELECT "
                "SUM(CASE WHEN vector IS NOT NULL THEN 1 ELSE 0 END) AS embedded, "
                "SUM(resolved) AS resolved, "
                "SUM(contradicted) AS contradicted, "
                "SUM(stale) AS stale, "
                "SUM(calibrated) AS calibrated "
                "FROM blackboard"
            ).fetchone()
            iocs = {r["ioc_type"]: r["n"] for r in conn.execute(
                "SELECT ioc_type, COUNT(*) AS n FROM blackboard "
                "WHERE ioc_type != '' AND ioc_type IS NOT NULL GROUP BY ioc_type"
            ).fetchall()}
            source_types = {r["source_type"]: r["n"] for r in conn.execute(
                "SELECT source_type, COUNT(*) AS n FROM blackboard "
                "WHERE source_type IS NOT NULL GROUP BY source_type"
            ).fetchall()}
            ev_rows = conn.execute(
                "SELECT evidence FROM blackboard WHERE evidence != '[]' AND evidence IS NOT NULL"
            ).fetchall()
        total_evidence = sum(len(json.loads(r["evidence"] or "[]")) for r in ev_rows)
        return {
            "total_entries": head["total"] or 0,
            "categories": head["cats"] or 0,
            "avg_confidence": round(head["avg_conf"] or 0, 3),
            "by_category": by_cat,
            "embedded_entries": scalars["embedded"] or 0,
            "resolved": scalars["resolved"] or 0,
            "contradicted": scalars["contradicted"] or 0,
            "stale": scalars["stale"] or 0,
            "iocs": iocs,
            "source_types": source_types,
            "total_evidence_records": total_evidence,
            "calibrated_entries": scalars["calibrated"] or 0,
            "coverage": self.coverage(),
        }

    def prune(self, max_entries: int = 1000, min_q_value: float = 0.0, older_than_days: int = 0) -> dict:
        """Drop the least valuable entries down to ``max_entries``.

        Ranks by ``confidence``. The legacy ``q_value`` column is written once
        at insert as a copy of confidence and never updated, so ordering by it
        ranked every entry by a constant; ``min_q_value`` is kept as the
        parameter name for compatibility and applied to confidence.

        Conflicting and stale entries are never pruned automatically: they are
        low-confidence precisely because they need attention.
        """
        with closing(self._conn()) as conn:
            total = conn.execute("SELECT COUNT(*) AS n FROM blackboard").fetchone()["n"]
            conditions = ["stale = 0", "(conflicts_with = '[]' OR conflicts_with IS NULL)"]
            params: builtins.list[Any] = []
            if min_q_value > 0:
                conditions.append("confidence < ?")
                params.append(min_q_value)
            if older_than_days > 0:
                conditions.append("updated_at < ?")
                params.append(time.time() - older_than_days * 86400)
            where = "WHERE " + " AND ".join(conditions)
            to_delete = max(0, total - max_entries)
            if to_delete > 0:
                ids = [r["id"] for r in conn.execute(
                    f"SELECT id FROM blackboard {where} ORDER BY confidence ASC, updated_at ASC LIMIT ?",
                    (*params, to_delete),
                ).fetchall()]
                for eid in ids:
                    conn.execute("DELETE FROM blackboard WHERE id = ?", (eid,))
                conn.commit()
                return {"pruned": len(ids), "remaining": total - len(ids)}
            if params:
                cur = conn.execute(f"DELETE FROM blackboard {where}", params)
                conn.commit()
                return {"pruned": cur.rowcount, "remaining": total - cur.rowcount}
        return {"pruned": 0, "remaining": total}

    def exists_similar(self, addr: str, category: str, title: str, threshold: float = 0.85) -> bool:
        """True when a near-identical title already exists at this address.

        A fixed threshold on token overlap. The previous version derived the
        gate from the quantiles of the very sample it was testing, so a set of
        uniformly dissimilar titles produced a low gate and reported a match.
        """
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT title FROM blackboard WHERE addr = ? AND category = ?",
                (normalize_addr(addr), category),
            ).fetchall()
        if not rows:
            return False
        return any(_jaccard(title, r["title"]) >= threshold for r in rows)

    def auto_merge(self, addr: str = "", category: str = "", similarity_threshold: float = 0.85) -> dict:
        """Collapse near-duplicate titles at the same address and category."""
        conditions = ["1=1"]
        params: builtins.list[Any] = []
        if addr:
            conditions.append("addr = ?")
            params.append(normalize_addr(addr))
        if category:
            conditions.append("category = ?")
            params.append(category)
        with closing(self._conn()) as conn:
            rows = conn.execute(
                f"SELECT * FROM blackboard WHERE {' AND '.join(conditions)} ORDER BY updated_at DESC",
                params,
            ).fetchall()
        entries = [self._row_to_dict(r) for r in rows]
        deleted: set = set()
        for i, e in enumerate(entries):
            if e["id"] in deleted:
                continue
            for o in entries[i + 1:]:
                if o["id"] in deleted:
                    continue
                # Never merge away a row that records a disagreement.
                if o.get("conflicts_with") or e.get("conflicts_with"):
                    continue
                if e.get("addr") != o.get("addr") or e.get("category") != o.get("category"):
                    continue
                if _jaccard(str(e.get("title", "")), str(o.get("title", ""))) >= similarity_threshold:
                    self.delete(o["id"])
                    deleted.add(o["id"])
        return {"merged": len(deleted), "remaining": len(entries) - len(deleted)}
