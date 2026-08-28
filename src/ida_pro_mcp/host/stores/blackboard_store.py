"""Investigation memory: what the analyst concluded, asked, and ruled out.

This is the storage core of the unified analysis-memory subsystem. The old
single-table ``blackboard`` store has been rebuilt into a small relational
layout:

``findings``
    Analyst memory. Positive claims, open threads, proposals and negative
    results ("examined" rows) live here as one typed model, with a single
    ``status`` column whose lifecycle is ``proposed → open → confirmed →
    resolved`` or ``→ rejected``. ``resolved`` / ``contradicted`` /
    ``conflicts_with`` are *derived at read time* rather than stored, so a row
    can never disagree with its own status flag.
``links``
    The disagreement table. Opposed assertions are never merged away; the two
    rows survive and a ``conflict`` link records who disputes whom. The reason
    text lives in the link's ``note`` and in the event log.
``finding_events``
    Audit log. Every lifecycle transition and structural edit is retained so a
    brief can say how the investigation got here.
``code_anchors``
    A digest of the code each claim was made against. When the code at an
    address changes, every non-stale entry anchored to the old text is marked
    stale rather than continuing to look authoritative.
``bb_tasks`` / ``bb_machinery``
    Machinery that used to hide inside the memory table: durable task-runner
    state (crawler progress, trace tasks) and key/value governance state
    (wm_now snapshots, quest log, phase/policy state, evidence snapshots).
``findings_embeddings``
    A side table written out-of-band. No CRUD RPC ever blocks on it: the write
    and update paths call the ``embed_enqueue`` hook (a no-op by default);
    ``embed=True`` additionally computes and stores a vector synchronously.

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
* The schema is versioned with ``PRAGMA user_version`` and migrated by an
  idempotent runner, so a database written by the single-table era opens
  cleanly and its rows are adopted into the new layout exactly once.
"""

from __future__ import annotations

import builtins
import contextlib
import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Callable

from ..intelligence.helpers import batch_cosine_similarity, pack_floats, unpack_floats

logger = logging.getLogger(__name__)

KINDS = frozenset({"finding", "hypothesis", "question", "task", "decision", "examined"})
#: 'proposed' is written by the crawler / trace / proposal machinery and must be
#: explicitly accepted or rejected before it becomes part of the analyst's
#: lifecycle (open/confirmed/resolved/rejected).
STATUSES = frozenset({"proposed", "open", "confirmed", "resolved", "rejected"})
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

#: Current schema version. Migrations are keyed by the user_version they land on.
SCHEMA_VERSION = 3
#: SQLite busy timeout in milliseconds. Writes use BEGIN IMMEDIATE and wait here
#: rather than failing with SQLITE_BUSY when several clients touch one workspace.
_DB_BUSY_TIMEOUT_MS = 30_000


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


# ---------------------------------------------------------------------------
# Schema migrations
# ---------------------------------------------------------------------------

class _Rollback(Exception):
    """Internal signal: roll back the current write transaction."""


def _migrate_0001_initial_schema(conn: sqlite3.Connection) -> None:
    """Create the redesigned tables. Idempotent (IF NOT EXISTS)."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id               TEXT PRIMARY KEY,
            kind             TEXT NOT NULL DEFAULT 'finding',
            status           TEXT NOT NULL DEFAULT 'open',
            category         TEXT NOT NULL DEFAULT 'general',
            title            TEXT NOT NULL,
            content          TEXT,
            addr             TEXT,
            addr_end         TEXT,
            tags             TEXT DEFAULT '[]',
            confidence       REAL DEFAULT 0.5,
            priority         REAL DEFAULT 0.5,
            q_value          REAL DEFAULT 0.5,
            source           TEXT DEFAULT 'manual',
            source_type      TEXT DEFAULT 'manual',
            evidence         TEXT DEFAULT '[]',
            fingerprint      TEXT DEFAULT '',
            ioc_type         TEXT,
            ioc_value        TEXT,
            depends_on       TEXT,
            blocks_addr      TEXT,
            register         TEXT,
            reg_type         TEXT,
            entropy          REAL DEFAULT 0.0,
            xref_count       INTEGER DEFAULT 0,
            calibrated       INTEGER DEFAULT 0,
            verdict          TEXT DEFAULT '',
            anchor_kind      TEXT DEFAULT '',
            anchor_digest    TEXT DEFAULT '',
            stale            INTEGER DEFAULT 0,
            stale_reason     TEXT DEFAULT '',
            rejected_reason  TEXT DEFAULT '',
            version          INTEGER DEFAULT 1,
            created_at       REAL NOT NULL,
            updated_at       REAL NOT NULL,
            decayed_at       REAL,
            published_at     REAL,
            published_symbol TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS links (
            entry_a    TEXT NOT NULL,
            entry_b    TEXT NOT NULL,
            type       TEXT NOT NULL DEFAULT 'conflict',
            reason     TEXT DEFAULT '',
            note       TEXT DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (entry_a, entry_b, type)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_events (
            seq        INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id   TEXT NOT NULL,
            event      TEXT NOT NULL,
            details    TEXT DEFAULT '{}',
            created_at REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS code_anchors (
            addr      TEXT NOT NULL,
            kind      TEXT NOT NULL,
            digest    TEXT NOT NULL,
            seen_at   REAL NOT NULL,
            PRIMARY KEY (addr, kind)
        )
    """)
    # These two tables are owned by blackboard_orchestration.MachineryDB
    # (_machinery_schema); this migration must pre-create them with EXACTLY
    # that layout, otherwise the orchestration's CREATE TABLE IF NOT EXISTS
    # becomes a no-op and its INSERTs fail on missing columns (task_type,
    # namespace/key), degrading the machinery to in-memory state.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bb_tasks (
            task_id    TEXT PRIMARY KEY,
            task_type  TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'pending',
            payload    TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bb_machinery (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            namespace  TEXT NOT NULL DEFAULT '',
            key        TEXT NOT NULL,
            value      TEXT NOT NULL DEFAULT '{}',
            updated_at REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings_embeddings (
            entry_id   TEXT PRIMARY KEY,
            vector     BLOB NOT NULL,
            model      TEXT DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
    """)

    for stmt in (
        "CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)",
        "CREATE INDEX IF NOT EXISTS idx_findings_addr ON findings(addr)",
        "CREATE INDEX IF NOT EXISTS idx_findings_tags ON findings(tags)",
        "CREATE INDEX IF NOT EXISTS idx_findings_kind_status ON findings(kind, status)",
        "CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)",
        "CREATE INDEX IF NOT EXISTS idx_findings_stale ON findings(stale)",
        "CREATE INDEX IF NOT EXISTS idx_findings_ioc ON findings(ioc_type)",
        "CREATE INDEX IF NOT EXISTS idx_findings_source_type ON findings(source_type)",
        "CREATE INDEX IF NOT EXISTS idx_findings_xref ON findings(xref_count)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint_unique "
        "ON findings(fingerprint) WHERE fingerprint != ''",
        "CREATE INDEX IF NOT EXISTS idx_links_a ON links(entry_a)",
        "CREATE INDEX IF NOT EXISTS idx_links_b ON links(entry_b)",
        "CREATE INDEX IF NOT EXISTS idx_finding_events_entry ON finding_events(entry_id, seq)",
        "CREATE INDEX IF NOT EXISTS idx_bb_tasks_status ON bb_tasks(status)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_bb_machinery_ns_key "
        "ON bb_machinery(namespace, key)",
    ):
        conn.execute(stmt)


def _migrate_legacy_blackboard(conn: sqlite3.Connection) -> None:
    """Adopt rows from the pre-redesign single ``blackboard`` table exactly once."""
    rows = conn.execute("SELECT * FROM blackboard").fetchall()
    if not rows:
        return
    now = time.time()
    for row in rows:
        d = dict(row)
        entry_id = str(d.get("id") or "")
        if not entry_id:
            continue
        status = str(d.get("status") or "open").strip().lower()
        if status not in STATUSES:
            status = "open"
        if int(d.get("resolved") or 0) and status == "open":
            status = "resolved"
        if int(d.get("contradicted") or 0) and status == "open":
            status = "rejected"
        kind = str(d.get("kind") or "finding").strip().lower()
        if kind not in KINDS:
            kind = "finding"
        tags = d.get("tags") or "[]"
        if not isinstance(tags, str):
            tags = json.dumps(tags or [])
        evidence = d.get("evidence") or "[]"
        if not isinstance(evidence, str):
            evidence = json.dumps(evidence or [])
        priority = float(d.get("priority") if d.get("priority") is not None else 0.5)
        confidence = float(d.get("confidence") if d.get("confidence") is not None else 0.5)
        q_value = float(d.get("q_value") if d.get("q_value") is not None else confidence)
        source_type = str(d.get("source_type") or "").strip() or str(d.get("source") or "manual")
        conn.execute(
            """
            INSERT OR IGNORE INTO findings
                (id, kind, status, category, title, content, addr, addr_end, tags,
                 confidence, priority, q_value, source, source_type, evidence, fingerprint,
                 ioc_type, ioc_value, depends_on, blocks_addr, register, reg_type,
                 entropy, xref_count, calibrated, verdict, anchor_kind, anchor_digest,
                 stale, stale_reason, rejected_reason, version, created_at, updated_at,
                 decayed_at, published_at, published_symbol)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                entry_id, kind, status,
                str(d.get("category") or "general"), str(d.get("title") or ""),
                d.get("content"), d.get("addr"), d.get("addr_end"), tags,
                confidence, priority, q_value,
                str(d.get("source") or "manual"), source_type, evidence,
                str(d.get("fingerprint") or ""),
                d.get("ioc_type"), d.get("ioc_value"), d.get("depends_on"), d.get("blocks_addr"),
                d.get("register"), d.get("reg_type"),
                float(d.get("entropy") or 0.0), int(d.get("xref_count") or 0),
                int(d.get("calibrated") or 0), str(d.get("verdict") or ""),
                str(d.get("anchor_kind") or ""), str(d.get("anchor_digest") or ""),
                int(d.get("stale") or 0), str(d.get("stale_reason") or ""),
                str(d.get("contradiction_reason") or ""),
                int(d.get("version") or 1),
                float(d.get("created_at") or now), float(d.get("updated_at") or now),
                d.get("decayed_at"), d.get("published_at"),
                str(d.get("published_symbol") or ""),
            ),
        )
        try:
            conflicts = json.loads(d.get("conflicts_with") or "[]")
        except (TypeError, ValueError):
            conflicts = []
        if isinstance(conflicts, list):
            for other in conflicts:
                other = str(other)
                if other and other != entry_id:
                    conn.execute(
                        "INSERT OR IGNORE INTO links(entry_a, entry_b, type, reason, note, created_at, updated_at) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (entry_id, other, "conflict",
                         "migrated from legacy conflicts_with", "migrated from legacy conflicts_with",
                         now, now),
                    )
        vector = d.get("vector")
        if vector:
            with contextlib.suppress(sqlite3.Error):
                conn.execute(
                    "INSERT OR IGNORE INTO findings_embeddings(entry_id, vector, model, created_at, updated_at) "
                    "VALUES (?,?,?,?,?)",
                    (entry_id, sqlite3.Binary(vector), "", now, now),
                )


def _create_blackboard_compat_view(conn: sqlite3.Connection) -> None:
    """Expose ``blackboard`` as a view over ``findings`` for legacy direct SQL.

    The redesign splits the single table into findings + side tables, so the
    old table name no longer exists as a table. A few legacy callers (and
    host tests that age rows by ``UPDATE blackboard SET updated_at=?``) still
    speak the old name directly; an INSTEAD OF UPDATE trigger lands those
    writes on the findings row. This is a migration seam, not the storage
    model: all new code reads and writes ``findings``.
    """
    cols = [str(r[1]) for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
    if not cols:
        return
    conn.execute("DROP VIEW IF EXISTS blackboard")
    conn.execute("CREATE VIEW blackboard AS SELECT * FROM findings")
    set_clause = ", ".join(f"{c}=NEW.{c}" for c in cols)
    conn.execute("DROP TRIGGER IF EXISTS trg_blackboard_compat_update")
    conn.execute(
        "CREATE TRIGGER trg_blackboard_compat_update INSTEAD OF UPDATE ON blackboard "
        f"BEGIN UPDATE findings SET {set_clause} WHERE id=NEW.id; END"
    )


def _migrate_0002_split_findings(conn: sqlite3.Connection) -> None:
    """Migrate legacy single-table data into the new layout, then drop it."""
    legacy = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='blackboard'"
    ).fetchone()
    if legacy:
        _migrate_legacy_blackboard(conn)
        conn.execute("DROP TABLE blackboard")
    _create_blackboard_compat_view(conn)


def _migrate_0003_embedding_metadata(conn: sqlite3.Connection) -> None:
    """Record the vector space used by each stored embedding.

    Older rows have no model identity and remain readable as legacy vectors,
    but new writes must carry both identity and dimension so a changed model
    cannot silently rank against incompatible vectors.
    """
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(findings_embeddings)")}
    if "embedding_dim" not in columns:
        conn.execute("ALTER TABLE findings_embeddings ADD COLUMN embedding_dim INTEGER NOT NULL DEFAULT 0")
    if "text_hash" not in columns:
        conn.execute("ALTER TABLE findings_embeddings ADD COLUMN text_hash TEXT NOT NULL DEFAULT ''")
    conn.execute(
        "UPDATE findings_embeddings SET embedding_dim = length(vector) / 4 "
        "WHERE embedding_dim = 0 AND vector IS NOT NULL"
    )


#: Ordered by the user_version each migration lands on.
_MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    1: _migrate_0001_initial_schema,
    2: _migrate_0002_split_findings,
    3: _migrate_0003_embedding_metadata,
}


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring the database to SCHEMA_VERSION. Each migration runs in its own
    transaction and only advances ``PRAGMA user_version`` after it succeeds, so
    a failed or interrupted migration re-runs idempotently from the same point.
    """
    current = int(conn.execute("PRAGMA user_version").fetchone()[0] or 0)
    for version in sorted(_MIGRATIONS):
        if version <= current:
            continue
        fn = _MIGRATIONS[version]
        conn.execute("BEGIN IMMEDIATE")
        try:
            fn(conn)
            conn.execute(f"PRAGMA user_version={version}")
            conn.commit()
        except BaseException:
            conn.rollback()
            raise


class BlackboardStore:
    """SQLite-backed investigation memory for one session.

    Connections are cached per thread with a busy timeout, and every write
    runs as exactly one ``BEGIN IMMEDIATE`` transaction so concurrent clients
    of one workspace coalesce instead of clobbering each other.
    """

    def __init__(self, db_path: str | None = None):
        primary_path = _resolve_db_path(db_path)
        self.db_path = primary_path
        self._local = threading.local()
        # Set by next_target()/targets() so a caller can report whether a
        # semantic query actually reached the ranking.
        self.last_query_applied: bool | None = None
        self.last_query_error: str = ""
        # Set by the coverage strategy so callers can be honest when the
        # function inventory is empty or no live IDA session is available.
        self.last_coverage_note: str = ""
        # Out-of-band embedding enqueue hook. The write/update paths call this with
        # (entry_id, text) after every insert/update; by default it is a no-op
        # so no CRUD RPC ever blocks on embedding. The host may replace it
        # with a function that enqueues into a background embedding worker.
        # Passing embed=True to write()/update() also embeds synchronously.
        self.embed_enqueue: Callable[[str, str], None] = lambda entry_id, text: None
        try:
            parent = os.path.dirname(self.db_path) or "."
            os.makedirs(parent, exist_ok=True)
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
            self._local.conn = None
            self._init_db()

    # ------------------------------------------------------------------
    # Connection and schema
    # ------------------------------------------------------------------

    def _new_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=float(_DB_BUSY_TIMEOUT_MS) / 1000.0)
        conn.row_factory = sqlite3.Row
        # Autocommit mode; every transaction is opened explicitly (see _tx) so
        # the connection's transaction state is never ambiguous.
        conn.isolation_level = None
        conn.execute(f"PRAGMA busy_timeout={_DB_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._new_conn()
            self._local.conn = conn
            return conn
        try:
            # A probe that raises if a legacy caller closed the shared handle
            # (e.g. `with closing(store._conn())`). Re-open in that case.
            conn.execute("SELECT 1").fetchone()
        except sqlite3.ProgrammingError:
            conn = self._new_conn()
            self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close this thread's cached connection, if any."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            finally:
                self._local.conn = None

    def _init_db(self) -> None:
        _migrate(self._conn())

    @contextmanager
    def _tx(self):
        """One write transaction: BEGIN IMMEDIATE … COMMIT, rolling back on error."""
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    def _get_embedder(self):
        return _get_embedder()

    @staticmethod
    def _embedding_identity(embedder: Any, dimension: int = 0) -> str:
        """Return a stable identity for the current embedding vector space."""
        backend = getattr(embedder, "backend", "unknown")
        if callable(backend):
            backend = backend()
        fmt = getattr(embedder, "embedding_format", "")
        if callable(fmt):
            fmt = fmt()
        parts = [str(backend or "unknown")]
        if fmt:
            parts.append(str(fmt))
        # Prompt format alone does not identify a local vector space: two
        # different GGUF files can share a profile, dimension, and prefixes.
        # Include file identity without hashing the whole model on every
        # blackboard query. A replacement at the same path changes size or
        # mtime and therefore cannot silently reuse old vectors.
        model_path = getattr(embedder, "_model_path", "") or getattr(embedder, "model_path", "")
        if model_path:
            try:
                stat = os.stat(os.fspath(model_path))
                parts.append(
                    f"model:{os.path.realpath(os.fspath(model_path))}:"
                    f"{int(stat.st_size)}:{int(stat.st_mtime_ns)}"
                )
            except (OSError, TypeError, ValueError):
                parts.append(f"model:{model_path}")
        if dimension:
            parts.append(str(dimension))
        return "|".join(parts)

    @staticmethod
    def _embedding_text(
        title: str,
        content: str,
        category: str = "",
        tags: Any = None,
        evidence: Any = None,
    ) -> str:
        """Build the canonical document text used for blackboard retrieval."""
        tag_values = tags if isinstance(tags, builtins.list) else []
        evidence_values = evidence if isinstance(evidence, builtins.list) else []
        evidence_text = " ".join(
            " ".join(str(value) for value in item.values())
            for item in evidence_values
            if isinstance(item, dict)
        )
        return (
            f"title: {title} category: {category} tags: {' '.join(map(str, tag_values))} "
            f"content: {content} evidence: {evidence_text}"
        ).strip()

    def _embed_text(self, text: str) -> bytes | None:
        embedder = self._get_embedder()
        if embedder is None:
            return None
        try:
            document_fn = getattr(embedder, "embed_document_vector", None)
            if callable(document_fn):
                vec = document_fn(text)
            else:
                document_fn = getattr(embedder, "embed_document", None)
                if callable(document_fn):
                    result = document_fn(text)
                    vec = getattr(result, "vector", result)
                else:
                    try:
                        vec = embedder.embed_vector(text, purpose="document")
                    except TypeError:
                        vec = embedder.embed_vector(text)
            if vec is None:
                return None
            return pack_floats(vec)
        except Exception:
            return None

    def _enqueue_embedding(self, entry_id: str, text: str) -> None:
        """Best-effort handoff to the asynchronous embedding worker.

        The finding is already durable when this hook runs. A worker outage
        must therefore not turn a successful CRUD operation into an error or
        make callers retry and create duplicate observations.
        """
        try:
            self.embed_enqueue(entry_id, text)
        except Exception:
            logger.exception("blackboard embedding enqueue failed for %s", entry_id)

    def _store_embedding(self, entry_id: str, blob: bytes, text: str = "") -> None:
        """Upsert one entry's vector into the embeddings side table."""
        dimension = len(blob) // 4
        embedder = self._get_embedder()
        model = self._embedding_identity(embedder, dimension) if embedder is not None else ""
        text_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16] if text else ""
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO findings_embeddings "
                "(entry_id, vector, model, embedding_dim, text_hash, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(entry_id) DO UPDATE SET vector=excluded.vector, model=excluded.model, "
                "embedding_dim=excluded.embedding_dim, text_hash=excluded.text_hash, updated_at=excluded.updated_at",
                (entry_id, sqlite3.Binary(blob), model, dimension, text_hash, time.time(), time.time()),
            )

    def _row_to_dict(self, row) -> dict:
        """Convert a findings row to an entry dict.

        ``resolved`` / ``contradicted`` are derived from the single status
        column so a row can never disagree with itself; ``conflicts_with`` is
        derived from the links table and attached by :meth:`_hydrate`.
        """
        if row is None:
            return {}
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        d["evidence"] = json.loads(d.get("evidence") or "[]")
        status = str(d.get("status") or "open")
        d["resolved"] = int(status == "resolved")
        d["contradicted"] = int(status == "rejected")
        d.setdefault("conflicts_with", [])
        if not d.get("rejected_reason"):
            d["rejected_reason"] = ""
        d.pop("_vec", None)
        d.pop("_embedding_model", None)
        d.pop("_embedding_dim", None)
        d.pop("vector", None)
        return d

    def _hydrate(self, rows, conn: sqlite3.Connection | None = None) -> builtins.list[dict]:
        """Convert rows to entry dicts and attach read-time derived fields.

        ``conflicts_with`` requires the links table, so it is computed once per
        batch here rather than once per row.
        """
        entries = [self._row_to_dict(r) for r in rows]
        if not entries:
            return entries
        ids = [str(e["id"]) for e in entries]
        own = conn is None
        if own:
            conn = self._conn()
        placeholders = ",".join("?" for _ in ids)
        # link_conflict stores both directions, so the same neighbour arrives
        # twice here; dedupe with a set before attaching.
        link_rows = conn.execute(
            f"SELECT entry_a, entry_b FROM links "
            f"WHERE entry_a IN ({placeholders}) OR entry_b IN ({placeholders})",
            (*ids, *ids),
        ).fetchall()
        conflict_map: dict[str, set[str]] = {}
        for lr in link_rows:
            a, b = str(lr["entry_a"]), str(lr["entry_b"])
            conflict_map.setdefault(a, set()).add(b)
            conflict_map.setdefault(b, set()).add(a)
        for e in entries:
            e["conflicts_with"] = sorted(conflict_map.get(str(e["id"]), set()))
        return entries

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
        conn = self._conn()
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
        conn = self._conn()
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
        with self._tx() as conn:
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
                    "SELECT id FROM findings WHERE addr=? AND anchor_kind=? AND anchor_digest=? AND stale=0",
                    (naddr, kind, previous),
                ).fetchall()
                marked = [r["id"] for r in rows]
                if marked:
                    conn.execute(
                        "UPDATE findings SET stale=1, stale_reason=? WHERE id IN ("
                        + ",".join("?" for _ in marked)
                        + ")",
                        (reason, *marked),
                    )
            else:
                reason = ""

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
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM findings WHERE stale=1 AND status != 'rejected' "
            "ORDER BY confidence DESC, updated_at DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
        return self._hydrate(rows, conn)

    def clear_stale(self, entry_id: str) -> bool:
        """Re-anchor an entry to the current code and drop its stale flag."""
        entry = self.read(entry_id)
        if not entry:
            return False
        anchor = self.current_anchor(str(entry.get("addr") or ""))
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE findings SET stale=0, stale_reason='', anchor_kind=?, anchor_digest=? WHERE id=?",
                (
                    (anchor or {}).get("kind", entry.get("anchor_kind") or ""),
                    (anchor or {}).get("digest", entry.get("anchor_digest") or ""),
                    entry_id,
                ),
            )
            ok = cur.rowcount > 0
        return ok

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
            raise ValueError("status must be proposed, open, confirmed, resolved, or rejected")
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
        # Embedding runs before the write transaction so a slow embedder never
        # holds the workspace write lock.
        embedding_text = self._embedding_text(title, content, category, tags, evidence)
        vector_blob = self._embed_text(embedding_text) if embed else None
        if not source_type:
            source_type = source
        with self._tx() as conn:
            conn.execute(
                """
                INSERT INTO findings
                    (id, kind, status, category, title, content, addr, addr_end, tags,
                     confidence, priority, q_value, source, source_type, evidence, fingerprint,
                     ioc_type, ioc_value, depends_on, blocks_addr, register, reg_type,
                     entropy, xref_count, calibrated, verdict, anchor_kind, anchor_digest,
                     stale, stale_reason, rejected_reason, version, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    entry_id, kind, status, category, title, content, naddr, addr_end,
                    json.dumps(tags or []), _clamp01(confidence), _clamp01(priority),
                    _clamp01(confidence), source, source_type, json.dumps(evidence or []),
                    fingerprint,
                    ioc_type, ioc_value, normalize_addr(depends_on), blocks_addr, register, reg_type,
                    entropy, xref_count, 0, verdict, anchor_kind, anchor_digest,
                    0, "", "", 1, now, now,
                ),
            )
        if vector_blob:
            self._store_embedding(entry_id, vector_blob, embedding_text)
        self._enqueue_embedding(entry_id, embedding_text)
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
        if status not in STATUSES:
            raise ValueError("status must be proposed, open, confirmed, resolved, or rejected")

        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM findings WHERE fingerprint=? OR "
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
        with self._tx() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE fingerprint=? ORDER BY updated_at DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if row is None:
                row = conn.execute(
                    "SELECT * FROM findings WHERE id=?", (str(existing["id"]),)
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
                "UPDATE findings SET content=?, tags=?, evidence=?, confidence=?, priority=?, "
                "kind=?, status=?, fingerprint=?, updated_at=?, version=? "
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
                    fingerprint,
                    now,
                    int(current.get("version") or 1) + 1,
                    str(current["id"]),
                ),
            )
        merged_embedding_text = self._embedding_text(
            current.get("title", title),
            merged_content,
            current.get("category", category),
            merged_tags,
            merged_evidence,
        )
        self._enqueue_embedding(str(current["id"]), merged_embedding_text)
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
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT id FROM findings WHERE id IN (?,?)", (entry_a, entry_b)
            ).fetchall()
            if len(rows) != 2:
                return False
            now = time.time()
            for this, other in ((entry_a, entry_b), (entry_b, entry_a)):
                conn.execute(
                    "INSERT INTO links(entry_a, entry_b, type, reason, note, created_at, updated_at) "
                    "VALUES (?,?,'conflict',?,?,?,?) "
                    "ON CONFLICT(entry_a, entry_b, type) DO UPDATE SET note=excluded.note, updated_at=excluded.updated_at",
                    (this, other, reason, reason, now, now),
                )
        for eid, other in ((entry_a, entry_b), (entry_b, entry_a)):
            self._record_event(eid, "conflict", {"with": other, "reason": reason})
        return True

    def conflicts(self, limit: int = 20) -> builtins.list[dict]:
        """Return entries involved in a disagreement, newest first.

        An entry counts as contested when it participates in a conflict link or
        was transitioned to ``rejected`` outright (no link exists yet).
        """
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM findings WHERE status='rejected' "
            "OR id IN (SELECT entry_a FROM links UNION SELECT entry_b FROM links) "
            "ORDER BY updated_at DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
        return self._hydrate(rows, conn)

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

        conn = self._conn()
        row = conn.execute(
            "SELECT id, verdict FROM findings WHERE kind='examined' AND addr=? LIMIT 1",
            (naddr,),
        ).fetchone()
        existing_id = row["id"] if row else None
        previous = row["verdict"] if row else ""

        anchor = self.current_anchor(naddr) or {}
        if existing_id:
            with self._tx() as c:
                c.execute(
                    "UPDATE findings SET verdict=?, content=?, title=?, updated_at=?, "
                    "version=version+1, stale=0, stale_reason='', anchor_kind=?, anchor_digest=? "
                    "WHERE id=?",
                    (
                        verdict, note, title, time.time(),
                        str(anchor.get("kind") or ""), str(anchor.get("digest") or ""),
                        existing_id,
                    ),
                )
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
        conn = self._conn()
        row = conn.execute(
            "SELECT * FROM findings WHERE kind='examined' AND addr=? LIMIT 1", (naddr,)
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
        conn = self._conn()
        rows = conn.execute(
            "SELECT verdict, COUNT(*) AS n FROM findings WHERE kind='examined' GROUP BY verdict"
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
            "SELECT * FROM findings WHERE status='confirmed' AND stale=0 "
            "AND kind != 'examined' AND addr != '' AND addr IS NOT NULL "
            "AND NOT EXISTS (SELECT 1 FROM links l WHERE l.entry_a=findings.id OR l.entry_b=findings.id) "
        )
        if not include_published:
            sql += "AND (published_at IS NULL OR published_at < updated_at) "
        sql += "ORDER BY confidence DESC, updated_at DESC LIMIT ?"
        conn = self._conn()
        rows = conn.execute(sql, (max(1, int(limit)),)).fetchall()
        return self._hydrate(rows, conn)

    def mark_published(self, entry_id: str, symbol: str = "") -> bool:
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE findings SET published_at=?, published_symbol=? WHERE id=?",
                (time.time(), symbol, entry_id),
            )
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
        conn = self._conn()
        rows = conn.execute(
            f"SELECT * FROM findings WHERE addr IN ({placeholders}) "
            "AND lower(COALESCE(source_type,'')) NOT IN ("
            + ",".join("?" for _ in _INTERNAL_WORKSPACE_SOURCE_TYPES)
            + ") ORDER BY confidence DESC, updated_at DESC LIMIT 200",
            (*ordered, *sorted(_INTERNAL_WORKSPACE_SOURCE_TYPES)),
        ).fetchall()

        rank = {addr: i for i, addr in enumerate(ordered)}
        entries = self._hydrate(rows, conn)
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
        conn = self._conn()
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (entry_id,)).fetchone()
        if row is None:
            return None
        return self._hydrate([row], conn)[0]

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
            conditions.append("status != 'resolved'")
        if not include_contradicted:
            conditions.append("status != 'rejected'")
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
        conn = self._conn()
        rows = conn.execute(
            f"SELECT * FROM findings {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            (*params, int(limit), int(offset)),
        ).fetchall()
        return self._hydrate(rows, conn)

    def semantic_search(
        self,
        query: str,
        top_k: int = 10,
        threshold: float = 0.4,
        category: str | None = None,
        include_resolved: bool = True,
        include_contradicted: bool = False,
    ) -> builtins.list[dict]:
        """Hybrid vector/keyword search over investigation memory.

        Query and document prompts are kept distinct when the embedder
        supports them. Stored vectors are only compared within the same
        embedding identity and dimension; legacy rows without identity remain
        eligible when their dimensions match. Keyword retrieval scans all
        eligible findings, so recent rows cannot hide older relevant evidence.
        """
        top_k = max(1, int(top_k or 1))
        q = " ".join(str(query or "").lower().split())
        terms = set(re.findall(r"[a-z0-9_]{2,}", q))
        conn = self._conn()

        def _filtered_findings() -> builtins.list[sqlite3.Row]:
            conditions: builtins.list[str] = []
            params: builtins.list[Any] = []
            if category:
                conditions.append("category = ?")
                params.append(category)
            if not include_resolved:
                conditions.append("status != 'resolved'")
            if not include_contradicted:
                conditions.append("status != 'rejected'")
            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            return conn.execute(
                f"SELECT * FROM findings {where} ORDER BY updated_at DESC", params
            ).fetchall()

        def _lexical_candidates() -> builtins.list[dict]:
            candidates: builtins.list[dict] = []
            for row in _filtered_findings():
                d = self._row_to_dict(row)
                title = str(d.get("title") or "").lower()
                content = str(d.get("content") or "").lower()
                tags = " ".join(map(str, d.get("tags") or [])).lower()
                evidence = " ".join(
                    " ".join(str(value) for value in item.values()).lower()
                    for item in (d.get("evidence") or [])
                    if isinstance(item, dict)
                )
                searchable = " ".join((title, content, str(d.get("category") or ""), tags, evidence))
                matched = {term for term in terms if term in searchable}
                phrase = bool(q and q in searchable)
                if not phrase and not matched:
                    continue
                similarity = 1.0 if phrase else (len(matched) / len(terms) if terms else 0.0)
                d["similarity"] = round(similarity, 4)
                d["lexical_similarity"] = round(similarity, 4)
                d["match"] = "lexical"
                d["rank_reason"] = (
                    "exact phrase in finding text" if phrase
                    else f"matched {len(matched)}/{len(terms)} query terms"
                )
                # Similarity is the primary signal; title/tag hits are useful
                # tie-breakers without changing the public similarity value.
                d["_lexical_priority"] = (
                    (2 if phrase else 0)
                    + sum(2 for term in matched if term in title)
                    + sum(1 for term in matched if term in tags)
                    + sum(1 for term in matched if term in str(d.get("category") or "").lower())
                )
                candidates.append(d)
            candidates.sort(
                key=lambda item: (
                    item["similarity"], item["_lexical_priority"],
                    item.get("confidence", 0.0), item.get("updated_at", 0.0),
                ),
                reverse=True,
            )
            return candidates

        lexical = _lexical_candidates()
        lexical_by_id = {str(item["id"]): item for item in lexical}

        try:
            embedder = self._get_embedder()
            if embedder is None:
                return lexical[:top_k]
            query_fn = getattr(embedder, "embed_query_vector", None)
            if callable(query_fn):
                q_vec = query_fn(query)
            else:
                try:
                    q_vec = embedder.embed_vector(query, purpose="query")
                except TypeError:
                    q_vec = embedder.embed_vector(query)
            if q_vec is None:
                raise RuntimeError("embedding unavailable")
        except Exception:
            return lexical[:top_k]

        q_dim = len(q_vec)
        model = self._embedding_identity(embedder, q_dim)
        rows = conn.execute(
            "SELECT f.*, fe.vector AS _vec, fe.model AS _embedding_model, "
            "fe.embedding_dim AS _embedding_dim "
            "FROM findings f JOIN findings_embeddings fe ON fe.entry_id = f.id "
            "ORDER BY f.updated_at DESC"
        ).fetchall()
        pairs: list[tuple[sqlite3.Row, list[float]]] = []
        for row in rows:
            finding = dict(row)
            if category and finding.get("category") != category:
                continue
            if not include_resolved and finding.get("status") == "resolved":
                continue
            if not include_contradicted and finding.get("status") == "rejected":
                continue
            blob = row["_vec"]
            if not blob:
                continue
            try:
                vector = unpack_floats(blob)
            except Exception:
                continue
            stored_dim = int(finding.get("_embedding_dim") or len(vector))
            stored_model = str(finding.get("_embedding_model") or "")
            if stored_dim != q_dim or (stored_model and stored_model != model):
                continue
            pairs.append((row, vector))

        if not pairs:
            return lexical[:top_k]

        semantic_by_id: dict[str, dict] = {}
        sims = batch_cosine_similarity(q_vec, [vec for _, vec in pairs])
        for sim, (row, _vector) in zip(sims, pairs, strict=True):
            if sim < threshold:
                continue
            d = self._row_to_dict(row)
            lexical_item = lexical_by_id.get(str(d["id"]))
            lexical_similarity = float((lexical_item or {}).get("similarity") or 0.0)
            d["similarity"] = round(sim, 4)
            d["lexical_similarity"] = round(lexical_similarity, 4)
            d["score"] = round(max(0.0, min(1.0, 0.7 * max(0.0, sim) + 0.3 * lexical_similarity)), 4)
            d["match"] = "semantic"
            d["rank_reason"] = f"semantic cosine {sim:.3f}"
            semantic_by_id[str(d["id"])] = d

        if not semantic_by_id:
            return lexical[:top_k]

        scored = builtins.list(semantic_by_id.values())
        # A lexical-only hit is valuable when it has no vector yet; include it
        # in a hybrid result set rather than dropping newly written evidence.
        for item in lexical:
            if str(item["id"]) in semantic_by_id:
                continue
            item["score"] = round(0.3 * float(item["similarity"]), 4)
            item["match"] = "hybrid"
            item["rank_reason"] = f"lexical fallback ({item['rank_reason']})"
            scored.append(item)
        scored.sort(
            key=lambda item: (
                item.get("score", 0.0), item.get("similarity", 0.0),
                item.get("confidence", 0.0), item.get("updated_at", 0.0),
            ),
            reverse=True,
        )
        scored = scored[:top_k]

        # Attach the derived conflicts_with field for the returned entries.
        ids = [str(item["id"]) for item in scored]
        if ids:
            placeholders = ",".join("?" for _ in ids)
            link_rows = conn.execute(
                f"SELECT entry_a, entry_b FROM links "
                f"WHERE entry_a IN ({placeholders}) OR entry_b IN ({placeholders})",
                (*ids, *ids),
            ).fetchall()
            cmap: dict[str, set[str]] = {}
            for link in link_rows:
                a, b = str(link["entry_a"]), str(link["entry_b"])
                cmap.setdefault(a, set()).add(b)
                cmap.setdefault(b, set()).add(a)
            for item in scored:
                item["conflicts_with"] = sorted(cmap.get(str(item["id"]), set()))
        for item in scored:
            item.pop("_lexical_priority", None)
        return scored

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def update(self, entry_id: str, embed: bool = False, **kwargs) -> bool:
        allowed = {
            "title", "content", "category", "addr", "addr_end", "tags",
            "confidence", "q_value", "ioc_type", "ioc_value",
            "depends_on", "blocks_addr", "register", "reg_type",
            "evidence", "source_type", "entropy", "xref_count", "calibrated",
            "kind", "status", "priority", "fingerprint", "rejected_reason",
            "verdict", "anchor_kind", "anchor_digest", "stale", "stale_reason",
            "source", "published_at", "published_symbol",
        }
        # Legacy aliases: resolved/contradicted/contradiction_reason were
        # stored columns in the single-table era and are derived now. Map them
        # so older callers keep working while the redesign lands.
        if "contradiction_reason" in kwargs:
            kwargs["rejected_reason"] = kwargs.pop("contradiction_reason")
        if "resolved" in kwargs:
            resolved = bool(kwargs.pop("resolved"))
            if resolved and "status" not in kwargs:
                kwargs["status"] = "resolved"
        if "contradicted" in kwargs:
            contradicted = bool(kwargs.pop("contradicted"))
            if contradicted and "status" not in kwargs:
                kwargs["status"] = "rejected"
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False

        with self._tx() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (entry_id,)).fetchone()
            if row is None:
                raise _Rollback()
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
            if "status" in updates:
                new_status = str(updates["status"] or "").strip().lower()
                updates["status"] = new_status
                if new_status != "rejected":
                    updates["rejected_reason"] = ""
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
            if "rejected_reason" in updates and not str(updates["rejected_reason"] or "").strip():
                updates["rejected_reason"] = ""
            sets = ", ".join(f"{k} = ?" for k in updates)
            cur = conn.execute(
                f"UPDATE findings SET {sets} WHERE id = ?", (*updates.values(), entry_id)
            )
            ok = cur.rowcount > 0

        embedding_changed = {"title", "content", "category", "tags", "evidence"}.intersection(updates)
        if embedding_changed:
            refreshed = self.read(entry_id) or current
            text = self._embedding_text(
                refreshed.get("title", ""),
                refreshed.get("content", ""),
                refreshed.get("category", ""),
                refreshed.get("tags", []),
                refreshed.get("evidence", []),
            )
            if embed:
                blob = self._embed_text(text)
                if blob:
                    self._store_embedding(entry_id, blob, text)
            self._enqueue_embedding(entry_id, text)
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
            raise ValueError("status must be proposed, open, confirmed, resolved, or rejected")
        existing = self.read(entry_id)
        if existing is None:
            return None
        updates: dict[str, Any] = {
            "status": status,
            "rejected_reason": reason if status == "rejected" else "",
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
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE findings SET status='rejected', rejected_reason=?, updated_at=?, version=version+1 "
                "WHERE id=?",
                (reason, time.time(), entry_id),
            )
            ok = cur.rowcount > 0
            if ok:
                # Store the reason in any conflict links this entry participates
                # in, so the disagreement trail carries it.
                conn.execute(
                    "UPDATE links SET note=?, updated_at=? WHERE type='conflict' "
                    "AND (entry_a=? OR entry_b=?)",
                    (reason, time.time(), entry_id, entry_id),
                )
        if ok:
            self._record_event(entry_id, "status:rejected", {"reason": reason} if reason else {})
        return ok

    def mark_resolved(self, entry_id: str) -> bool:
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE findings SET status='resolved', updated_at=?, version=version+1 WHERE id=?",
                (time.time(), entry_id),
            )
            ok = cur.rowcount > 0
        if ok:
            self._record_event(entry_id, "status:resolved", {})
        return ok

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
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT id, confidence, updated_at, decayed_at, calibrated, evidence "
                "FROM findings WHERE confidence > ?",
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
                        "UPDATE findings SET confidence=?, decayed_at=? WHERE id=?",
                        (new_conf, now, row["id"]),
                    )
                    updated += 1
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
            Requires ``rpc_fn`` to read the function inventory. When the
            inventory is empty or ``rpc_fn`` is None the result carries a
            ``note`` saying so instead of silently pretending there is nothing
            to look at.
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

        result = {
            "strategy": strategy,
            "targets": candidates[:limit],
            "count": len(candidates[:limit]),
        }
        if strategy == "coverage" and self.last_coverage_note:
            result["note"] = self.last_coverage_note
        return result

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
        conn = self._conn()
        return {
            r["addr"] for r in conn.execute(
                "SELECT addr FROM findings WHERE status IN ('resolved','confirmed') "
                "AND addr != '' AND addr IS NOT NULL"
            ).fetchall()
        }

    def _targets_unresolved(self, limit: int, rpc_fn=None) -> builtins.list[dict]:
        resolved = self._resolved_addrs()
        placeholders = ",".join("?" for _ in OPEN_THREAD_KINDS)
        conn = self._conn()
        rows = conn.execute(
            f"SELECT * FROM findings WHERE kind IN ({placeholders}) AND status='open' "
            "ORDER BY priority DESC, confidence DESC, updated_at DESC LIMIT 200",
            tuple(sorted(OPEN_THREAD_KINDS)),
        ).fetchall()
        unverified = conn.execute(
            "SELECT * FROM findings WHERE kind='finding' AND status='open' "
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

        Coverage is the one strategy that depends on a live IDA session. When
        ``rpc_fn`` is None or the function inventory comes back empty, the
        result is empty *and* a ``last_coverage_note`` explains why, so a
        caller never mistakes "could not look" for "nothing to look at".
        """
        self.last_coverage_note = ""
        if rpc_fn is None:
            self.last_coverage_note = (
                "No live IDA session (rpc_fn is None), so the function inventory "
                "could not be read; coverage targets are unavailable."
            )
            return []
        functions = self._function_inventory(rpc_fn)
        if not functions:
            self.last_coverage_note = (
                "The IDA function inventory is empty; there are no coverage candidates yet."
            )
            return []
        conn = self._conn()
        known = {
            r["addr"] for r in conn.execute(
                "SELECT DISTINCT addr FROM findings WHERE addr != '' AND addr IS NOT NULL"
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
        conn = self._conn()
        anchors = conn.execute(
            "SELECT id, addr, title FROM findings WHERE status='confirmed' "
            "AND addr != '' AND addr IS NOT NULL ORDER BY confidence DESC LIMIT 12"
        ).fetchall()
        known = {
            r["addr"] for r in conn.execute(
                "SELECT DISTINCT addr FROM findings WHERE addr != '' AND addr IS NOT NULL"
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

    def next_target(self, limit: int = 5, rpc_fn=None, query: str | None = None, strategy: str = "unresolved") -> builtins.list[dict]:
        """Compatibility shim over :meth:`targets`.

        By default runs ``unresolved`` and tops up from ``coverage`` when the
        workspace is too sparse to have opinions yet. A caller may pass an
        explicit ``strategy`` (any of :data:`STRATEGIES`, e.g. ``frontier``),
        which is honored directly without the coverage top-up. Kept because
        several resource handlers and the legacy tool surface call it
        positionally.
        """
        self.last_query_applied = None if not (query and str(query).strip()) else True
        self.last_query_error = ""
        if strategy not in STRATEGIES:
            raise ValueError("strategy must be one of: " + ", ".join(STRATEGIES))
        if strategy != "unresolved":
            return self.targets(strategy, limit=limit, rpc_fn=rpc_fn, query=query)["targets"][:limit]
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
        conn = self._conn()
        # Proposals (status 'proposed') are deliberately excluded: they have
        # their own accept/reject machinery and are not part of the analyst's
        # established memory until accepted.
        rows = conn.execute(
            "SELECT * FROM findings WHERE status NOT IN ('rejected', 'proposed') "
            "AND kind != 'examined' "
            f"AND lower(category) NOT IN ({cat_placeholders}) "
            f"AND lower(COALESCE(source_type, '')) NOT IN ({src_placeholders}) "
            "ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'confirmed' THEN 1 ELSE 2 END, "
            "priority DESC, confidence DESC, updated_at DESC LIMIT 500",
            (*sorted(_INTERNAL_WORKSPACE_CATEGORIES), *sorted(_INTERNAL_WORKSPACE_SOURCE_TYPES)),
        ).fetchall()
        conflict_rows = conn.execute(
            "SELECT * FROM findings WHERE status='rejected' "
            "OR id IN (SELECT entry_a FROM links UNION SELECT entry_b FROM links) "
            "ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        recent_events = conn.execute(
            "SELECT entry_id, event, details, created_at FROM finding_events "
            "ORDER BY seq DESC LIMIT ?", (limit,)
        ).fetchall()
        entries = self._hydrate(rows, conn)
        conflicts = self._hydrate(conflict_rows, conn)
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
        conn = self._conn()
        iocs = conn.execute(
            "SELECT ioc_type, ioc_value, addr, confidence FROM findings "
            "WHERE category='ioc' AND status != 'resolved' ORDER BY confidence DESC LIMIT 10"
        ).fetchall()
        vulns = conn.execute(
            "SELECT title, addr, confidence FROM findings "
            "WHERE category='vuln' AND status != 'resolved' ORDER BY confidence DESC LIMIT 5"
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

    def delete(self, entry_id: str) -> bool:
        """Delete an entry and cascade its links, events, and embeddings."""
        with self._tx() as conn:
            cur = conn.execute("DELETE FROM findings WHERE id = ?", (entry_id,))
            ok = cur.rowcount > 0
            conn.execute("DELETE FROM links WHERE entry_a = ? OR entry_b = ?", (entry_id, entry_id))
            conn.execute("DELETE FROM finding_events WHERE entry_id = ?", (entry_id,))
            conn.execute("DELETE FROM findings_embeddings WHERE entry_id = ?", (entry_id,))
        return ok

    def clear(self, category: str | None = None) -> int:
        with self._tx() as conn:
            if category:
                cur = conn.execute("DELETE FROM findings WHERE category = ?", (category,))
            else:
                cur = conn.execute("DELETE FROM findings")
            count = cur.rowcount
        return count

    def stats(self) -> dict:
        """SQL-aggregated workspace statistics."""
        conn = self._conn()
        head = conn.execute(
            "SELECT "
            "COUNT(*) AS total, "
            "COUNT(DISTINCT category) AS cats, "
            "AVG(confidence) AS avg_conf, "
            "SUM(CASE WHEN status='resolved' THEN 1 ELSE 0 END) AS resolved, "
            "SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) AS contradicted, "
            "SUM(CASE WHEN status IN ('open','proposed') THEN 1 ELSE 0 END) AS unresolved, "
            "SUM(stale) AS stale, "
            "SUM(calibrated) AS calibrated "
            "FROM findings"
        ).fetchone()
        by_cat = {r["category"]: r["n"] for r in conn.execute(
            "SELECT category, COUNT(*) AS n FROM findings GROUP BY category"
        ).fetchall()}
        iocs = {r["ioc_type"]: r["n"] for r in conn.execute(
            "SELECT ioc_type, COUNT(*) AS n FROM findings "
            "WHERE ioc_type != '' AND ioc_type IS NOT NULL GROUP BY ioc_type"
        ).fetchall()}
        source_types = {r["source_type"]: r["n"] for r in conn.execute(
            "SELECT source_type, COUNT(*) AS n FROM findings "
            "WHERE source_type IS NOT NULL GROUP BY source_type"
        ).fetchall()}
        embedded = conn.execute("SELECT COUNT(*) AS n FROM findings_embeddings").fetchone()["n"]
        ev_rows = conn.execute(
            "SELECT evidence FROM findings WHERE evidence != '[]' AND evidence IS NOT NULL"
        ).fetchall()
        total_evidence = sum(len(json.loads(r["evidence"] or "[]")) for r in ev_rows)
        return {
            "total_entries": head["total"] or 0,
            "categories": head["cats"] or 0,
            "avg_confidence": round(head["avg_conf"] or 0, 3),
            "by_category": by_cat,
            "embedded_entries": embedded or 0,
            "resolved": head["resolved"] or 0,
            "contradicted": head["contradicted"] or 0,
            "unresolved": head["unresolved"] or 0,
            "stale": head["stale"] or 0,
            "iocs": iocs,
            "source_types": source_types,
            "total_evidence_records": total_evidence,
            "calibrated_entries": head["calibrated"] or 0,
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
        conn = self._conn()
        total = conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
        conditions = [
            "stale = 0",
            "NOT EXISTS (SELECT 1 FROM links l WHERE l.entry_a=findings.id OR l.entry_b=findings.id)",
        ]
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
                f"SELECT id FROM findings {where} ORDER BY confidence ASC, updated_at ASC LIMIT ?",
                (*params, to_delete),
            ).fetchall()]
            with self._tx() as c:
                for eid in ids:
                    c.execute("DELETE FROM findings WHERE id = ?", (eid,))
                    c.execute("DELETE FROM links WHERE entry_a = ? OR entry_b = ?", (eid, eid))
                    c.execute("DELETE FROM finding_events WHERE entry_id = ?", (eid,))
                    c.execute("DELETE FROM findings_embeddings WHERE entry_id = ?", (eid,))
            return {"pruned": len(ids), "remaining": total - len(ids)}
        if params:
            with self._tx() as c:
                cur = c.execute(f"DELETE FROM findings {where}", params)
            return {"pruned": cur.rowcount, "remaining": total - cur.rowcount}
        return {"pruned": 0, "remaining": total}

    def exists_similar(self, addr: str, category: str, title: str, threshold: float = 0.85) -> bool:
        """True when a near-identical title already exists at this address.

        A fixed threshold on token overlap. The previous version derived the
        gate from the quantiles of the very sample it was testing, so a set of
        uniformly dissimilar titles produced a low gate and reported a match.
        """
        conn = self._conn()
        rows = conn.execute(
            "SELECT title FROM findings WHERE addr = ? AND category = ?",
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
        conn = self._conn()
        rows = conn.execute(
            f"SELECT * FROM findings WHERE {' AND '.join(conditions)} ORDER BY updated_at DESC",
            params,
        ).fetchall()
        entries = self._hydrate(rows, conn)
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
