"""Legacy workspace-layout resolution and adoption for the rebuilt analysis memory.

This module owns everything about *where* the per-binary analysis memory lives
and *how* findings from older releases get moved into it. It depends on bb01's
store API (the migration runner that brings a workspace up to the current
schema); the store, in turn, depends on this module for the layout and row
mapping. The two evolve in lock-step but are independently testable.

Responsibilities
----------------
``resolve``
    Compute the binary-scoped workspace path ``{cache_dir}/blackboards/sha256-{digest}.db``
    under the host cache dir. The layout is preserved from the pre-rebuild host —
    the workspace always lives at ``cache/blackboards/sha256-{digest}.db`` and
    ``IDA_MCP_BLACKBOARD_ROOT`` does not move it. Falls back to the legacy
    ``<idb>.blackboard.db`` sidecar and then to a per-session
    ``{cache_dir}/{sid}.blackboard.db`` exactly as the pre-rebuild host did, so
    existing deployments keep resolving to the same file.

``adopt`` / ``seed``
    One-time adoption of the two legacy layouts into the shared workspace:
    per-session ``sha256-{digest}-{sid}.db`` files and the ``<idb>.blackboard.db``
    sidecar. Candidates are merged newest-first with INSERT OR IGNORE (a row
    that exists in both sources keeps its original id and is never overwritten)
    and adoption only ever runs against an empty workspace. The check-then-act
    resolve+seed pair is guarded by a module lock so two threads opening the
    same binary concurrently cannot both seed. When a source is a true
    pre-rebuild single-bag db, its rows are routed through the transform into
    the current schema (findings / bb_machinery / links); when it already speaks
    the current schema the tables are copied directly.

``transform``
    Old-schema read/transform. A pre-rebuild ``blackboard`` single-bag table is
    read read-only and mapped into the new model:
      * status is derived from the ``resolved`` / ``contradicted`` booleans
        when the row has no usable ``status`` column;
      * a meaningful ``ioc_type`` becomes an ``ioc:{type}`` tag (and promotes a
        generic ``general`` category to ``ioc``);
      * ``contradiction_reason`` is renamed ``rejected_reason``;
      * internal machinery categories (``evidence_gravity``, ``wm_now``,
        ``quest_log``, ``proposal_feedback``, ``trace_task``, ``crawler_state``)
        are split out so they can live in ``bb_machinery``;
      * storage-only legacy columns (``vector``, ``quantized``, ``bridges``,
        ``schema``, ``entropy``, ``xref_count``, ...) are dropped.
    ``apply_transform`` writes those normalized rows into a target DB with
    INSERT OR IGNORE against whatever tables exist (``findings`` + ``links`` +
    ``bb_machinery`` for the current store, or the ``blackboard`` bag for a
    legacy-format target), so it is safe to run before and after the store
    rewrite lands.

Path confinement
----------------
``IDA_MCP_BLACKBOARD_ROOT``, else the current IDB's directory, else the host
cache dir (in that order) is the root that caller-supplied file paths must
resolve under; ``..`` traversal and symlinked components are rejected, matching
the memory tool's filesystem sandbox.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import threading
import time
from typing import Any

#: Env var that overrides where blackboard files and workspaces live.
BLACKBOARD_ROOT_ENV = "IDA_MCP_BLACKBOARD_ROOT"
#: Sub-directory (under the base) that holds the binary-digest workspaces.
BLACKBOARDS_SUBDIR = "blackboards"

#: Lifecycle statuses the rebuilt model accepts; ``proposed`` is preserved by
#: the transform even though legacy rows never carried it.
_STATUSES = frozenset({"open", "confirmed", "resolved", "rejected", "proposed"})
_KINDS = frozenset({"finding", "hypothesis", "question", "task", "decision", "examined"})

#: Internal categories that are machinery, not analyst memory. Rows with these
#: categories are routed to ``bb_machinery`` by the transform.
LEGACY_MACHINERY_CATEGORIES = frozenset(
    {
        "evidence_gravity",
        "wm_now",
        "quest_log",
        "proposal_feedback",
        "trace_task",
        "crawler_state",
    }
)

#: Storage-only columns the new entry dict drops. ``contradiction_reason`` is
#: handled separately (renamed ``rejected_reason``).
LEGACY_DROPPED_COLUMNS = frozenset(
    {
        "vector",
        "ioc_type",
        "ioc_value",
        "depends_on",
        "blocks_addr",
        "register",
        "reg_type",
        "entropy",
        "xref_count",
        "calibrated",
        "bridges",
        "schema",
        "quantized",
        "q_signs",
        "norm",
        "call_idx",
        "decayed_at",
    }
)

#: Canonical keys of a normalized finding, in insertion order.
_ENTRY_KEYS = (
    "id",
    "kind",
    "status",
    "category",
    "title",
    "content",
    "addr",
    "addr_end",
    "tags",
    "confidence",
    "created_at",
    "updated_at",
    "q_value",
    "priority",
    "source",
    "source_type",
    "evidence",
    "conflicts_with",
    "resolved",
    "contradicted",
    "verdict",
    "stale",
    "stale_reason",
    "rejected_reason",
    "published_at",
    "published_symbol",
    "anchor_kind",
    "anchor_digest",
    "fingerprint",
    "version",
)

#: Generic ``ioc_type`` values that do not convey a real indicator and are
#: therefore not surfaced as an ``ioc:`` tag.
_GENERIC_IOC_TYPES = frozenset({"", "none", "n/a", "na", "unknown", "generic", "-", "general"})

#: Column renames applied when writing into a legacy-format ``blackboard`` table
#: (which has no ``rejected_reason`` column).
_LEGACY_ALIASES = {"rejected_reason": "contradiction_reason"}

#: Module-level lock guarding the resolve+seed check-then-act pair and the path
#: cache, so concurrent first-opens of the same binary cannot both adopt.
_RESOLVE_LOCK = threading.Lock()
_PATH_CACHE: dict[tuple, str] = {}


# ---------------------------------------------------------------------------
# Small value helpers
# ---------------------------------------------------------------------------


def _truthy(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _json_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    text = str(value).strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else []
    except (ValueError, TypeError):
        return [p.strip() for p in text.replace("\n", ",").split(",") if p.strip()]


def _encode_value(value: Any) -> Any:
    """Encode a normalized value for storage in a TEXT/JSON or scalar column."""
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    if isinstance(value, bool):
        return int(value)
    return value


# ---------------------------------------------------------------------------
# Binary identity
# ---------------------------------------------------------------------------


def binary_sha256(binary_path: str) -> str:
    """Full-file SHA-256 of a binary, or ``""`` when it cannot be read."""
    try:
        if not binary_path or not os.path.exists(binary_path):
            return ""
        h = hashlib.sha256()
        with open(binary_path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Workspace-layout resolution
# ---------------------------------------------------------------------------


def _workspace_base(cache_dir: str = "") -> str:
    """The base directory that holds the ``blackboards`` sub-directory.

    The binary-digest workspace layout is preserved: it always lives under the
    host cache dir as ``cache/blackboards/sha256-{digest}.db``. (``IDA_MCP_BLACKBOARD_ROOT``
    does not move the workspace; it only bounds file actions — see
    :func:`workspace_root` / :func:`confine_path`.)
    """
    return os.path.realpath(cache_dir) if cache_dir else ""


def _binary_cache_key(binary_path: str, cache_dir: str = "") -> tuple:
    """Cache key for a resolved workspace path.

    Includes the binary's identity (path + size + mtime) *and* the workspace
    base, so two servers with different cache dirs never share a cache entry.
    """
    try:
        stat = os.stat(binary_path)
        ident = (os.path.realpath(binary_path), stat.st_size, stat.st_mtime_ns)
    except OSError:
        ident = (os.path.realpath(binary_path), 0, 0)
    return (*ident, os.path.realpath(cache_dir) if cache_dir else "")


def clear_workspace_cache() -> None:
    """Drop the resolved-path cache (test isolation / env changes)."""
    with _RESOLVE_LOCK:
        _PATH_CACHE.clear()


def resolve_workspace_path(
    binary_path: str = "",
    cache_dir: str = "",
    idb_path: str = "",
    session_id: str = "",
) -> str:
    """Resolve the analysis-memory workspace path for a session.

    Order of preference, matching the pre-rebuild host:

    1. Binary-scoped shared workspace ``{cache_dir}/blackboards/sha256-{digest}.db``
       when the binary exists and its digest can be computed. The first open
       (guarded by a module lock) adopts legacy layouts into the workspace.
    2. Legacy sidecar ``<idb_path>.blackboard.db`` next to the IDB.
    3. Per-session ``{cache_dir}/{sid}.blackboard.db``.
    4. ``""`` when nothing is available.
    """
    binary = str(binary_path or "").strip()
    base = _workspace_base(cache_dir)
    if binary and os.path.isfile(binary):
        with _RESOLVE_LOCK:
            cache = _PATH_CACHE
            key = _binary_cache_key(binary, cache_dir)
            workspace = cache.get(key)
            if not workspace:
                digest = binary_sha256(binary)
                if digest and base:
                    blackboards_dir = os.path.join(base, BLACKBOARDS_SUBDIR)
                    try:
                        os.makedirs(blackboards_dir, exist_ok=True)
                    except OSError:
                        blackboards_dir = ""
                    if blackboards_dir:
                        workspace = os.path.join(blackboards_dir, f"sha256-{digest}.db")
                        seed_shared_workspace(workspace, digest, cache_dir, idb_path, root=base)
                        cache[key] = workspace
            if workspace:
                return workspace
    idb = str(idb_path or "").strip()
    if idb:
        return idb + ".blackboard.db"
    sid = str(session_id or "").strip()
    if sid:
        return os.path.join(cache_dir, f"{sid}.blackboard.db")
    return ""


# ---------------------------------------------------------------------------
# Legacy layout adoption
# ---------------------------------------------------------------------------


def _blackboards_dirs(cache_dir: str = "", root: str = "") -> list[str]:
    """Directories that may hold per-session legacy workspace files."""
    dirs: list[str] = []
    for base in (root, cache_dir):
        if base:
            d = os.path.join(base, BLACKBOARDS_SUBDIR)
            if d not in dirs:
                dirs.append(d)
    return dirs


def _legacy_candidates(digest: str, cache_dir: str = "", root: str = "", idb_path: str = "") -> list[str]:
    """Candidate legacy workspaces: per-session dbs plus the IDB sidecar."""
    candidates: list[str] = []
    for d in _blackboards_dirs(cache_dir, root):
        try:
            for name in os.listdir(d):
                if name.startswith(f"sha256-{digest}-") and name.endswith(".db"):
                    candidates.append(os.path.join(d, name))
        except OSError:
            continue
    idb = str(idb_path or "").strip()
    if idb:
        legacy = idb + ".blackboard.db"
        if os.path.isfile(legacy):
            candidates.append(legacy)
    seen: set[str] = set()
    out: list[str] = []
    for p in candidates:
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            out.append(p)
    return out


def _workspace_has_rows(workspace_path: str) -> bool:
    """True when the workspace already holds findings (never re-adopt then)."""
    path = str(workspace_path or "")
    if not path or not os.path.isfile(path):
        return False
    try:
        with sqlite3.connect(path) as conn:
            tables = {
                str(r[0])
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            for table in ("findings", "blackboard"):
                if table in tables:
                    n = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                    if n > 0:
                        return True
            return False
    except sqlite3.Error:
        return False


def _list_tables(conn: sqlite3.Connection) -> set[str]:
    try:
        return {
            str(r[0])
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
    except sqlite3.Error:
        return set()


def _table_columns(conn: sqlite3.Connection) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name in _list_tables(conn):
        with contextlib.suppress(sqlite3.Error):
            out[name] = [str(r[1]) for r in conn.execute(f'PRAGMA table_info("{name}")').fetchall()]
    return out


def _init_new_schema(target_path: str) -> bool:
    """Bring an empty workspace up to the current schema via bb01's migration runner.

    The migration runner creates the ``findings`` / ``links`` / ``bb_machinery``
    / ``bb_tasks`` tables and the ``blackboard`` compatibility view. It is only
    called on a workspace with no tables, so the legacy-migration step inside
    the runner has nothing to do. Returns False when the runner is unavailable
    so callers can fall back to a raw copy.
    """
    try:
        from ..stores.blackboard_store import _migrate as _bb_migrate
    except Exception:
        return False
    conn = None
    try:
        conn = sqlite3.connect(target_path)
        conn.row_factory = sqlite3.Row
        conn.isolation_level = None
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _bb_migrate(conn)
        return True
    except Exception:
        return False
    finally:
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()


def _backup_source(source_path: str, target_path: str) -> None:
    """Raw fallback: copy a whole source db into an empty target."""
    try:
        with sqlite3.connect(source_path) as sconn, sqlite3.connect(target_path) as tconn:
            sconn.backup(tconn)
    except sqlite3.Error:
        pass


def _merge_same_schema_rows(source_path: str, target_path: str, exclude: frozenset[str] = frozenset()) -> None:
    """Copy rows from one workspace db into another without clobbering.

    Every table (except ``sqlite_%``) present in both databases is copied with
    INSERT OR IGNORE, so a row that already exists keeps its original id.
    """
    try:
        with sqlite3.connect(target_path) as target, sqlite3.connect(source_path) as source:
            tables = _list_tables(source)
            target_cols = _table_columns(target)
            for table in tables:
                if table in exclude:
                    continue
                try:
                    cols = [str(c[1]) for c in source.execute(f'PRAGMA table_info("{table}")').fetchall()]
                    insert_cols = [c for c in cols if c in set(target_cols.get(table) or [])]
                    if not insert_cols:
                        continue
                    col_sql = ",".join(f'"{c}"' for c in insert_cols)
                    placeholders = ",".join("?" * len(insert_cols))
                    rows = source.execute(f'SELECT {col_sql} FROM "{table}"').fetchall()
                    if rows:
                        target.executemany(
                            f'INSERT OR IGNORE INTO "{table}" ({col_sql}) VALUES ({placeholders})',
                            rows,
                        )
                except sqlite3.Error:
                    continue
            target.commit()
    except sqlite3.Error:
        pass


def _merge_legacy_source(source_path: str, target_path: str) -> None:
    """Merge one legacy source into the target workspace, schema-aware.

    A true pre-rebuild source (a ``blackboard`` table with no ``findings``) is
    routed through the row transform so its rows land in ``findings`` /
    ``bb_machinery`` / ``links``; a source that already speaks the current
    schema is copied table-for-table with INSERT OR IGNORE. A fresh target is
    brought up to the current schema first (via bb01's migration runner) so
    adoption never depends on the store opening a legacy-format file.
    """
    try:
        with sqlite3.connect(target_path) as tconn, sqlite3.connect(source_path) as sconn:
            source_tables = _list_tables(sconn)
            target_tables = _list_tables(tconn)
    except sqlite3.Error:
        return
    if "blackboard" in source_tables and "findings" not in source_tables:
        # True pre-rebuild single-bag source.
        if "findings" not in target_tables:
            if not _init_new_schema(target_path):
                # bb01 migration runner unavailable: fall back to a raw copy so
                # no data is lost (the store will upgrade the file on open).
                _backup_source(source_path, target_path)
                return
        apply_transform(source_path, target_path)
        _merge_same_schema_rows(source_path, target_path, exclude={"blackboard"})
        return
    # Same-schema copy (both current-schema, or a legacy target still holding the bag).
    if not target_tables:
        if not _init_new_schema(target_path):
            _backup_source(source_path, target_path)
            return
    _merge_same_schema_rows(source_path, target_path)


def adopt_legacy_layouts(
    workspace_path: str,
    digest: str,
    cache_dir: str = "",
    idb_path: str = "",
    root: str | None = None,
) -> dict[str, Any]:
    """Adopt findings from earlier workspace layouts into the shared db.

    Returns a report dict::

        {"adopted": [abs paths], "seeded": int, "skipped_reason": str|None}

    Only an empty workspace is seeded; a workspace that already holds rows is
    left untouched (``skipped_reason="non_empty_workspace"``). Candidates are
    merged newest-first with INSERT OR IGNORE, so nothing ever overwrites a row
    that is already present.
    """
    root = root if root is not None else _workspace_base(cache_dir)
    report: dict[str, Any] = {"adopted": [], "seeded": 0, "skipped_reason": None}
    if _workspace_has_rows(workspace_path):
        report["skipped_reason"] = "non_empty_workspace"
        return report
    candidates = _legacy_candidates(digest, cache_dir, root, idb_path)
    if not candidates:
        report["skipped_reason"] = "no_candidates"
        return report
    try:
        ordered = sorted(candidates, key=os.path.getmtime, reverse=True)
    except OSError:
        report["skipped_reason"] = "stat_failed"
        return report
    for src in ordered:
        _merge_legacy_source(src, workspace_path)
        report["adopted"].append(os.path.abspath(src))
        report["seeded"] += 1
    return report


def seed_shared_workspace(
    workspace_path: str,
    digest: str,
    cache_dir: str = "",
    idb_path: str = "",
    root: str | None = None,
) -> dict[str, Any]:
    """Alias for :func:`adopt_legacy_layouts` kept for call-site symmetry."""
    return adopt_legacy_layouts(workspace_path, digest, cache_dir, idb_path, root=root)


# ---------------------------------------------------------------------------
# Old-schema read / transform
# ---------------------------------------------------------------------------


def _meaningful_ioc(value: Any) -> bool:
    v = str(value or "").strip().lower()
    return bool(v) and v not in _GENERIC_IOC_TYPES and len(v) <= 64


def normalize_legacy_row(raw: dict[str, Any]) -> dict[str, Any]:
    """Map one legacy single-bag row into the canonical entry dict.

    * ``status`` is preserved when the row already has a usable value;
      otherwise it is derived from ``resolved`` (-> ``resolved``) and
      ``contradicted`` (-> ``rejected``) booleans.
    * A meaningful ``ioc_type`` becomes an ``ioc:{type}`` tag and promotes a
      generic ``general`` category to ``ioc``.
    * ``contradiction_reason`` is renamed ``rejected_reason`` (kept only for
      rejected rows).
    * Storage-only legacy columns (``vector``, ``quantized``, ``bridges``,
      ``schema``, ``entropy``, ``xref_count``, ...) are dropped.
    """
    raw_status = str(raw.get("status") or "").strip().lower()
    if raw_status not in _STATUSES:
        raw_status = ""
    resolved_flag = _truthy(raw.get("resolved")) or raw_status == "resolved"
    contradicted_flag = _truthy(raw.get("contradicted")) or raw_status == "rejected"
    if raw_status:
        status = raw_status
    elif resolved_flag:
        status = "resolved"
    elif contradicted_flag:
        status = "rejected"
    else:
        status = "open"

    kind = str(raw.get("kind") or "finding").strip().lower()
    if kind not in _KINDS:
        kind = "finding"

    category = str(raw.get("category") or "general").strip() or "general"
    tags = _json_list(raw.get("tags"))
    ioc_type = str(raw.get("ioc_type") or "").strip()
    if _meaningful_ioc(ioc_type):
        tag = f"ioc:{ioc_type}"
        if tag not in tags:
            tags.append(tag)
        if category in {"", "general"}:
            category = "ioc"

    entry: dict[str, Any] = {
        "id": str(raw.get("id") or "").strip(),
        "kind": kind,
        "status": status,
        "category": category,
        "title": str(raw.get("title") or "").strip(),
        "content": str(raw.get("content") or ""),
        "addr": str(raw.get("addr") or "").strip(),
        "addr_end": str(raw.get("addr_end") or "").strip(),
        "tags": tags,
        "confidence": _float(raw.get("confidence"), 0.5),
        "created_at": _float(raw.get("created_at"), 0.0),
        "updated_at": _float(raw.get("updated_at"), 0.0),
        "q_value": _float(raw.get("q_value"), 0.5),
        "priority": _float(raw.get("priority"), 0.5),
        "source": str(raw.get("source") or "manual"),
        "source_type": str(raw.get("source_type") or raw.get("source") or "manual"),
        "evidence": _json_list(raw.get("evidence")),
        "conflicts_with": _json_list(raw.get("conflicts_with")),
        "resolved": int(resolved_flag or status == "resolved"),
        "contradicted": int(contradicted_flag or status == "rejected"),
        "verdict": str(raw.get("verdict") or "").strip().lower(),
        "stale": int(_truthy(raw.get("stale"))),
        "stale_reason": str(raw.get("stale_reason") or ""),
        "published_at": raw.get("published_at"),
        "published_symbol": str(raw.get("published_symbol") or ""),
        "anchor_kind": str(raw.get("anchor_kind") or ""),
        "anchor_digest": str(raw.get("anchor_digest") or ""),
        "fingerprint": str(raw.get("fingerprint") or ""),
        "version": _int(raw.get("version"), 1),
    }
    if status == "rejected":
        entry["rejected_reason"] = str(
            raw.get("contradiction_reason") or raw.get("rejected_reason") or ""
        )
    return entry


def transform_legacy_db(source_path: str) -> dict[str, Any]:
    """Read an old-schema single-bag DB and return normalized rows.

    Returns ``{"findings": [...], "machinery": [...], "source": str, "total": int}``.
    Analyst rows land in ``findings``; rows whose category is internal machinery
    (``evidence_gravity``, ``wm_now``, ``quest_log``, ``proposal_feedback``,
    ``trace_task``, ``crawler_state``) land in ``machinery`` so they can be
    stored in ``bb_machinery`` rather than as analyst memory. The source is
    opened read-only and never migrated in place.
    """
    source = str(source_path or "")
    if not source or not os.path.isfile(source):
        return {"findings": [], "machinery": [], "source": source, "total": 0}
    try:
        conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        conn = sqlite3.connect(source)
        conn.row_factory = sqlite3.Row
    try:
        cols = [str(r[1]) for r in conn.execute("PRAGMA table_info(blackboard)").fetchall()]
        if not cols:
            return {"findings": [], "machinery": [], "source": source, "total": 0}
        rows = conn.execute("SELECT * FROM blackboard").fetchall()
    except sqlite3.Error:
        return {"findings": [], "machinery": [], "source": source, "total": 0}
    finally:
        conn.close()

    findings: list[dict[str, Any]] = []
    machinery: list[dict[str, Any]] = []
    for row in rows:
        entry = normalize_legacy_row(dict(row))
        if entry.get("category") in LEGACY_MACHINERY_CATEGORIES:
            machinery.append(entry)
        else:
            findings.append(entry)
    return {
        "findings": findings,
        "machinery": machinery,
        "source": source,
        "total": len(findings) + len(machinery),
    }


def _insert_entries(
    conn: sqlite3.Connection,
    table: str,
    entries: list[dict[str, Any]],
    table_cols: dict[str, list[str]],
) -> int:
    """INSERT OR IGNORE normalized entries into one target table.

    Only columns the table actually has are written, so the same rows insert
    cleanly into either the current ``findings`` table or the legacy
    ``blackboard`` bag (with ``rejected_reason`` aliased to
    ``contradiction_reason`` there). Returns the number of rows actually
    inserted (id collisions are ignored, never overwriting).
    """
    available = set(table_cols.get(table) or [])
    before = conn.total_changes
    for entry in entries:
        cols: list[str] = []
        values: list[Any] = []
        for key in _ENTRY_KEYS:
            if key not in entry:
                continue
            col = key if key in available else _LEGACY_ALIASES.get(key, "")
            if not col or col not in available:
                continue
            cols.append(col)
            values.append(_encode_value(entry[key]))
        if not cols:
            continue
        col_sql = ",".join(f'"{c}"' for c in cols)
        placeholders = ",".join("?" * len(cols))
        conn.execute(
            f'INSERT OR IGNORE INTO "{table}" ({col_sql}) VALUES ({placeholders})',
            values,
        )
    return conn.total_changes - before


def _insert_machinery(conn: sqlite3.Connection, machinery: list[dict[str, Any]]) -> int:
    """Write machinery rows into the ``bb_machinery`` key/value table.

    Each legacy machinery row becomes one key/value pair
    ``{category}:{id} -> {payload JSON}`` so the raw payload (crawler state,
    evidence snapshots, quest-log entries, ...) survives the migration intact.
    """
    before = conn.total_changes
    now = time.time()
    for m in machinery:
        key = f"{m.get('category') or 'machinery'}:{m.get('id') or ''}"
        payload = {k: v for k, v in m.items() if k not in {"id", "category"}}
        conn.execute(
            "INSERT OR IGNORE INTO bb_machinery(key, value, updated_at) VALUES (?,?,?)",
            (key, json.dumps(payload, ensure_ascii=True, sort_keys=True), _float(m.get("updated_at"), now)),
        )
    return conn.total_changes - before


def _insert_conflict_links(conn: sqlite3.Connection, findings: list[dict[str, Any]]) -> int:
    """Recreate ``links`` rows from a legacy finding's ``conflicts_with`` ids."""
    if "links" not in _list_tables(conn):
        return 0
    before = conn.total_changes
    now = time.time()
    for entry in findings:
        entry_id = str(entry.get("id") or "")
        conflicts = entry.get("conflicts_with") or []
        if not entry_id or not isinstance(conflicts, list):
            continue
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
    return conn.total_changes - before


def apply_transform(source_path: str, target_path: str) -> dict[str, Any]:
    """Transform a legacy source DB and insert the rows into a target DB.

    Findings are written to the ``findings`` table when the target has one,
    else to the ``blackboard`` bag. Legacy ``conflicts_with`` ids become
    ``links`` rows, and machinery rows go to ``bb_machinery`` (key/value) when
    present, else to the ``blackboard`` bag (so nothing is dropped). All writes
    use INSERT OR IGNORE keyed on the entry id.
    """
    data = transform_legacy_db(source_path)
    findings = data.get("findings") or []
    machinery = data.get("machinery") or []
    if not findings and not machinery:
        return {"written": 0, "findings": 0, "machinery": 0, "source": source_path}
    try:
        with sqlite3.connect(target_path) as conn:
            table_cols = _table_columns(conn)
            written_f = 0
            if findings:
                if "findings" in table_cols:
                    written_f = _insert_entries(conn, "findings", findings, table_cols)
                elif "blackboard" in table_cols:
                    written_f = _insert_entries(conn, "blackboard", findings, table_cols)
                _insert_conflict_links(conn, findings)
            written_m = 0
            if machinery:
                if "bb_machinery" in table_cols:
                    written_m = _insert_machinery(conn, machinery)
                elif "blackboard" in table_cols:
                    written_m = _insert_entries(conn, "blackboard", machinery, table_cols)
            conn.commit()
    except sqlite3.Error:
        return {"written": 0, "findings": 0, "machinery": 0, "error": True, "source": source_path}
    return {
        "written": written_f + written_m,
        "findings": written_f,
        "machinery": written_m,
        "source": source_path,
    }


# ---------------------------------------------------------------------------
# Path confinement
# ---------------------------------------------------------------------------


def workspace_root(cache_dir: str = "", idb_path: str = "", env: str | None = None) -> str | None:
    """Root directory that blackboard file actions may read/write.

    Mirrors the memory tool's sandbox: ``IDA_MCP_BLACKBOARD_ROOT``, else the
    current IDB's directory, else the host cache dir.
    """
    env_root = env if env is not None else os.environ.get(BLACKBOARD_ROOT_ENV)
    if env_root:
        try:
            return os.path.realpath(os.path.expanduser(str(env_root)))
        except Exception:
            return None
    idb = str(idb_path or "").strip()
    if idb:
        try:
            return os.path.realpath(os.path.dirname(idb))
        except Exception:
            pass
    if cache_dir:
        return os.path.realpath(cache_dir)
    return None


def _path_escapes(path: str, root: str) -> bool:
    """True when ``path`` is not contained under ``root``."""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return True
    return rel.startswith("..") or os.path.isabs(rel)


def path_has_symlink(abs_path: str, allowed_root: str) -> bool:
    """True when any path component between ``allowed_root`` and ``abs_path`` is a symlink."""
    if not abs_path or not allowed_root:
        return True
    try:
        rel = os.path.relpath(abs_path, allowed_root)
    except ValueError:
        return True
    if rel.startswith("..") or os.path.isabs(rel):
        return True
    current = allowed_root
    for part in rel.split(os.sep):
        if not part:
            continue
        current = os.path.join(current, part)
        if os.path.islink(current):
            return True
    return False


def confine_path(raw_path: str, root: str | None) -> tuple[str, str | None]:
    """Resolve a caller-supplied path inside the blackboard root.

    Returns ``(canonical, error)``. ``canonical`` is a real path under ``root``
    when OK; otherwise it is empty and ``error`` explains why. ``..`` traversal,
    absolute paths outside the root, and symlinked components are rejected.
    Symlinks are rejected before any resolution, so a symlink cannot smuggle a
    path out of the root even when its target stays inside.
    """
    path = str(raw_path or "").strip()
    if not path:
        return "", "path required"
    if not root:
        return "", (
            "blackboard file action: no allowed root configured "
            f"(set {BLACKBOARD_ROOT_ENV} or open a session)."
        )
    joined = os.path.join(root, path)
    if _path_escapes(joined, root):
        return "", "blackboard file action: path escapes allowed root"
    if path_has_symlink(joined, root):
        return "", "blackboard file action: symbolic links are not allowed in path"
    try:
        canonical = os.path.realpath(joined)
    except Exception:
        return "", "blackboard file action: invalid path"
    if _path_escapes(canonical, root):
        return "", "blackboard file action: path escapes allowed root"
    return canonical, None
