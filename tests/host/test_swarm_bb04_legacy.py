"""bb04 — workspace-layout resolution and legacy adoption (blackboard_legacy.py).

Pins the rebuilt behavior of the standalone legacy-adoption module:

* binary-digest workspace path resolution with path confinement;
* one-time adoption of per-session ``sha256-{digest}-{sid}.db`` and
  ``<idb>.blackboard.db`` workspaces (newest-first, INSERT OR IGNORE, never
  overwrite, threading-safe) into the current ``findings``-based schema;
* old-schema read/transform mapping legacy single-bag rows into the new model
  (status derived from resolved/contradicted booleans, ioc_type -> category tag,
  machinery categories -> bb_machinery, legacy storage columns dropped).

No live IDA is required: the module is driven with raw SQLite fixtures (a
``_make_legacy_db`` helper builds the pre-rebuild schema directly) and the
standalone host ``BlackboardStore`` as the current-schema target.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading

import pytest

from ida_pro_mcp.host.server import blackboard_legacy as bl
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore

# Columns the last pre-rebuild store could have created on the single bag.
_LEGACY_COLUMNS = [
    "id", "category", "title", "content", "addr", "addr_end", "tags",
    "confidence", "created_at", "updated_at", "q_value", "source", "vector",
    "resolved", "contradicted", "contradiction_reason", "ioc_type", "ioc_value",
    "depends_on", "blocks_addr", "register", "reg_type", "evidence",
    "source_type", "version", "entropy", "xref_count", "calibrated", "bridges",
    "schema", "quantized", "q_signs", "norm", "call_idx", "decayed_at",
    "kind", "status", "priority", "fingerprint", "verdict", "stale",
    "stale_reason", "conflicts_with", "published_at", "published_symbol",
    "anchor_kind", "anchor_digest",
]


@pytest.fixture(autouse=True)
def _isolate_cache(monkeypatch, tmp_path):
    """Each test gets a fresh workspace cache and env override."""
    bl.clear_workspace_cache()
    monkeypatch.delenv(bl.BLACKBOARD_ROOT_ENV, raising=False)


def _make_legacy_db(path, rows):
    """Create a pre-rebuild single-bag DB from a list of row dicts."""
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE blackboard (" + ",".join(f'"{c}" TEXT' for c in _LEGACY_COLUMNS) + ")"
        )
        for row in rows:
            cols = [c for c in _LEGACY_COLUMNS if c in row]
            conn.execute(
                "INSERT INTO blackboard (" + ",".join(f'"{c}"' for c in cols) + ") VALUES ("
                + ",".join("?" * len(cols)) + ")",
                [row[c] for c in cols],
            )
        conn.commit()
    return path


def _row(overrides=None):
    base = {
        "id": "aaaa1111",
        "category": "general",
        "title": "Legacy finding",
        "content": "content",
        "addr": "0x401000",
        "addr_end": "",
        "tags": '["auto"]',
        "confidence": 0.5,
        "created_at": 1000.0,
        "updated_at": 1000.0,
        "q_value": 0.5,
        "source": "manual",
        "evidence": "[]",
        "source_type": "manual",
        "version": 1,
    }
    base.update(overrides or {})
    return base


# ---------------------------------------------------------------------------
# binary_sha256
# ---------------------------------------------------------------------------


def test_binary_sha256_matches_hashlib_and_is_empty_for_missing(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"migrate-me")
    assert bl.binary_sha256(str(binary)) == hashlib.sha256(b"migrate-me").hexdigest()
    assert bl.binary_sha256(str(tmp_path / "nope.bin")) == ""


# ---------------------------------------------------------------------------
# Workspace-layout resolution
# ---------------------------------------------------------------------------


def test_resolve_shared_digest_workspace_path(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"resolve-me")
    digest = hashlib.sha256(b"resolve-me").hexdigest()
    path = bl.resolve_workspace_path(str(binary), str(tmp_path / "cache"))
    assert path == str(tmp_path / "cache" / "blackboards" / f"sha256-{digest}.db")


def test_resolve_keeps_workspace_under_cache_dir_even_with_blackboard_root_env(
    tmp_path, monkeypatch
):
    # The binary-digest workspace layout is preserved: IDA_MCP_BLACKBOARD_ROOT
    # must NOT move the workspace (it only bounds file actions via workspace_root).
    root = tmp_path / "ws"
    monkeypatch.setenv(bl.BLACKBOARD_ROOT_ENV, str(root))
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"root-me")
    digest = hashlib.sha256(b"root-me").hexdigest()
    cache = tmp_path / "cache"
    path = bl.resolve_workspace_path(str(binary), str(cache))
    assert path == str(cache / "blackboards" / f"sha256-{digest}.db")
    assert not str(path).startswith(str(root))
    # The env var still bounds file actions:
    assert bl.workspace_root(str(cache), "") == str(root)


def test_resolve_fallback_idb_sidecar_then_session_then_empty(tmp_path):
    idb = str(tmp_path / "a.i64")
    assert bl.resolve_workspace_path("", str(tmp_path / "cache"), idb_path=idb) == idb + ".blackboard.db"
    session = bl.resolve_workspace_path("", str(tmp_path / "cache"), session_id="SESS-X")
    assert session == str(tmp_path / "cache" / "SESS-X.blackboard.db")
    assert bl.resolve_workspace_path("", str(tmp_path / "cache")) == ""


def test_resolve_is_idempotent_and_adopts_exactly_once(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"once-me")
    digest = hashlib.sha256(b"once-me").hexdigest()
    legacy = tmp_path / "cache" / "blackboards" / f"sha256-{digest}-sess1.db"
    _make_legacy_db(legacy, [_row({"id": "bb000001", "title": "Only finding"})])

    cache_dir = str(tmp_path / "cache")
    first = bl.resolve_workspace_path(str(binary), cache_dir)
    second = bl.resolve_workspace_path(str(binary), cache_dir)
    assert first == second
    with sqlite3.connect(first) as conn:
        count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    assert count == 1


# ---------------------------------------------------------------------------
# Legacy adoption (pinned: per-session + idb sidecar, newest-first, never overwrite)
# ---------------------------------------------------------------------------


def test_adopt_per_session_workspaces_into_shared_workspace(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"adopt-me")
    digest = hashlib.sha256(b"adopt-me").hexdigest()
    shared_dir = tmp_path / "cache" / "blackboards"
    shared_dir.mkdir(parents=True)
    _make_legacy_db(
        shared_dir / f"sha256-{digest}-aaaa1111.db",
        [_row({"id": "sess0001", "title": "Finding from session A", "addr": "0x401000"})],
    )
    _make_legacy_db(
        shared_dir / f"sha256-{digest}-bbbb2222.db",
        [_row({"id": "sess0002", "title": "Finding from session B", "addr": "0x402000"})],
    )

    workspace = bl.resolve_workspace_path(str(binary), str(tmp_path / "cache"))
    assert workspace.endswith(f"sha256-{digest}.db")
    store = BlackboardStore(workspace)
    titles = {e["title"] for e in store.list(limit=50)}
    assert {"Finding from session A", "Finding from session B"} <= titles


def test_adopt_legacy_idb_sidecar_into_shared_workspace(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"legacy-me")
    idb_path = str(tmp_path / "a.i64")
    _make_legacy_db(idb_path + ".blackboard.db", [_row({"id": "side0001", "title": "Sidecar finding"})])

    workspace = bl.resolve_workspace_path(str(binary), str(tmp_path / "cache"), idb_path=idb_path)
    store = BlackboardStore(workspace)
    assert "Sidecar finding" in {e["title"] for e in store.list(limit=50)}


def test_adopt_newest_first_wins_id_collisions(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"collide")
    digest = hashlib.sha256(b"collide").hexdigest()
    shared_dir = tmp_path / "cache" / "blackboards"
    shared_dir.mkdir(parents=True)
    old = shared_dir / f"sha256-{digest}-old0000.db"
    new = shared_dir / f"sha256-{digest}-new0000.db"
    _make_legacy_db(old, [_row({"id": "deadbeef", "title": "Older claim"})])
    _make_legacy_db(new, [_row({"id": "deadbeef", "title": "Newer claim"})])
    os.utime(old, (1000.0, 1000.0))
    os.utime(new, (2000.0, 2000.0))

    workspace = bl.resolve_workspace_path(str(binary), str(tmp_path / "cache"))
    store = BlackboardStore(workspace)
    rows = store.list(limit=50)
    by_id = {e["id"]: e for e in rows}
    assert len(rows) == 1
    assert by_id["deadbeef"]["title"] == "Newer claim"


def test_adopt_never_overwrites_existing_workspace_rows(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"keep-me")
    digest = hashlib.sha256(b"keep-me").hexdigest()
    shared_dir = tmp_path / "cache" / "blackboards"
    shared_dir.mkdir(parents=True)
    shared_path = shared_dir / f"sha256-{digest}.db"
    fresh = BlackboardStore(str(shared_path))
    fresh.write(title="Fresh finding", content="written by the new session")
    _make_legacy_db(
        shared_dir / f"sha256-{digest}-old0000.db",
        [_row({"id": "old00001", "title": "Old finding"})],
    )

    workspace = bl.resolve_workspace_path(str(binary), str(tmp_path / "cache"))
    assert workspace == str(shared_path)
    store = BlackboardStore(workspace)
    titles = {e["title"] for e in store.list(limit=50)}
    assert "Fresh finding" in titles
    assert "Old finding" not in titles


def test_adopt_report_shapes(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"report")
    digest = hashlib.sha256(b"report").hexdigest()
    shared_dir = tmp_path / "cache" / "blackboards"
    shared_dir.mkdir(parents=True)
    legacy = shared_dir / f"sha256-{digest}-sess1.db"
    _make_legacy_db(legacy, [_row({"id": "rep00001", "title": "Report finding"})])

    workspace = str(shared_dir / f"sha256-{digest}.db")
    report = bl.seed_shared_workspace(workspace, digest, str(tmp_path / "cache"))
    assert report["seeded"] == 1
    assert len(report["adopted"]) == 1
    assert report["skipped_reason"] is None

    # Second call: workspace now has rows -> skipped.
    report2 = bl.adopt_legacy_layouts(workspace, digest, str(tmp_path / "cache"))
    assert report2["seeded"] == 0
    assert report2["skipped_reason"] == "non_empty_workspace"


def test_adopt_produces_current_schema_workspace_readable_by_store(tmp_path):
    """Adoption writes straight into the current schema, so opening the store
    never depends on the legacy-migration step (which drops the legacy table)."""
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"schema")
    digest = hashlib.sha256(b"schema").hexdigest()
    shared_dir = tmp_path / "cache" / "blackboards"
    shared_dir.mkdir(parents=True)
    _make_legacy_db(
        shared_dir / f"sha256-{digest}-sess1.db",
        [
            _row({"id": "sc000001", "title": "Schema finding", "resolved": 1}),
            _row({"id": "sc000002", "title": "Schema rejected", "contradicted": 1}),
        ],
    )

    workspace = bl.resolve_workspace_path(str(binary), str(tmp_path / "cache"))
    with sqlite3.connect(workspace) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "findings" in tables  # current schema, not a legacy bag
    assert "blackboard" not in tables  # the bag is a view at most
    store = BlackboardStore(workspace)
    by_id = {e["id"]: e for e in store.list(limit=50, include_contradicted=True)}
    assert by_id["sc000001"]["status"] == "resolved"
    assert by_id["sc000002"]["status"] == "rejected"


def test_adopt_is_thread_safe(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"threads")
    digest = hashlib.sha256(b"threads").hexdigest()
    shared_dir = tmp_path / "cache" / "blackboards"
    shared_dir.mkdir(parents=True)
    _make_legacy_db(
        shared_dir / f"sha256-{digest}-sess1.db",
        [_row({"id": "thr00001", "title": "Thread finding"})],
    )

    cache_dir = str(tmp_path / "cache")
    results: list[str] = []
    errors: list[Exception] = []

    def _open():
        try:
            results.append(bl.resolve_workspace_path(str(binary), cache_dir))
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(exc)

    threads = [threading.Thread(target=_open) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(set(results)) == 1
    with sqlite3.connect(results[0]) as conn:
        count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    assert count == 1


# ---------------------------------------------------------------------------
# Old-schema transform
# ---------------------------------------------------------------------------


def test_transform_derives_status_from_booleans(tmp_path):
    src = _make_legacy_db(
        tmp_path / "src.db",
        [
            _row({"id": "t0000001", "title": "Claim settled", "resolved": 1}),
            _row({"id": "t0000002", "title": "Claim contradicted", "contradicted": 1, "contradiction_reason": "newer evidence"}),
            _row({"id": "t0000003", "title": "Claim open", "resolved": 0, "contradicted": 0}),
            _row({"id": "t0000004", "title": "Explicit status", "status": "confirmed"}),
        ],
    )
    data = bl.transform_legacy_db(str(src))
    assert data["total"] == 4
    by_id = {e["id"]: e for e in data["findings"]}
    assert by_id["t0000001"]["status"] == "resolved"
    assert by_id["t0000001"]["resolved"] == 1
    assert by_id["t0000002"]["status"] == "rejected"
    assert by_id["t0000002"]["contradicted"] == 1
    assert by_id["t0000002"]["rejected_reason"] == "newer evidence"
    assert by_id["t0000003"]["status"] == "open"
    assert by_id["t0000004"]["status"] == "confirmed"


def test_transform_ioc_type_becomes_category_tag_when_meaningful(tmp_path):
    src = _make_legacy_db(
        tmp_path / "src.db",
        [
            _row({"id": "ioc00001", "title": "C2 beacon", "ioc_type": "ip", "ioc_value": "1.2.3.4"}),
            _row({"id": "ioc00002", "title": "Generic IOC", "ioc_type": "unknown"}),
            _row({"id": "ioc00003", "title": "Keeps category", "category": "firmware", "ioc_type": "file"}),
        ],
    )
    data = bl.transform_legacy_db(str(src))
    by_id = {e["id"]: e for e in data["findings"]}
    assert "ioc:ip" in by_id["ioc00001"]["tags"]
    assert by_id["ioc00001"]["category"] == "ioc"
    assert "ioc:file" in by_id["ioc00003"]["tags"]
    assert by_id["ioc00003"]["category"] == "firmware"
    assert not any(t.startswith("ioc:") for t in by_id["ioc00002"]["tags"])


def test_transform_drops_legacy_storage_columns(tmp_path):
    src = _make_legacy_db(
        tmp_path / "src.db",
        [_row({"id": "drop0001", "title": "Clean row", "entropy": 7.9, "xref_count": 12, "register": "r3", "ioc_value": "x"})],
    )
    entry = bl.transform_legacy_db(str(src))["findings"][0]
    for col in ("vector", "ioc_value", "register", "entropy", "xref_count", "bridges", "schema", "norm", "decayed_at"):
        assert col not in entry, f"legacy column {col} must be dropped"
    assert entry["title"] == "Clean row"


def test_transform_routes_machinery_categories_to_machinery(tmp_path):
    src = _make_legacy_db(
        tmp_path / "src.db",
        [
            _row({"id": "m0000001", "title": "evidence gravity 0x1", "category": "evidence_gravity", "content": "{}"}),
            _row({"id": "m0000002", "title": "memory compiler snapshot", "category": "wm_now", "content": "{}"}),
            _row({"id": "m0000003", "title": "quest entry", "category": "quest_log", "content": "{}"}),
            _row({"id": "m0000004", "title": "feedback", "category": "proposal_feedback", "content": "{}"}),
            _row({"id": "m0000005", "title": "trace_task from x", "category": "trace_task", "content": "{}"}),
            _row({"id": "m0000006", "title": "crawler_state", "category": "crawler_state", "content": '{"visited": []}'}),
            _row({"id": "m0000007", "title": "real finding", "category": "hypothesis", "content": "claim"}),
        ],
    )
    data = bl.transform_legacy_db(str(src))
    mach = {e["id"]: e for e in data["machinery"]}
    assert set(mach) == {"m0000001", "m0000002", "m0000003", "m0000004", "m0000005", "m0000006"}
    findings = {e["id"]: e for e in data["findings"]}
    assert set(findings) == {"m0000007"}
    assert findings["m0000007"]["category"] == "hypothesis"


def test_transform_opaque_raw_blob_riscv_scenario(tmp_path):
    """A RISC-V raw-blob firmware investigation keeps its opaque detail intact."""
    src = _make_legacy_db(
        tmp_path / "src.db",
        [
            _row({
                "id": "risc0001",
                "title": "Raw blob dispatch reads length at +0x10",
                "category": "general",
                "ioc_type": "file",
                "content": (
                    "Raw ROM blob (opaque, no ELF): word at offset 0x10 used as "
                    "length; bytes 0x44.. unparsed; vector table at 0x80000000."
                ),
                "addr": "0x8020A0C0",
                "addr_end": "0x8020A0F0",
                "tags": '["firmware","riscv","blob"]',
                "resolved": 1,
                "entropy": 7.94,
                "vector": b"\x00\x01",
            }),
            _row({
                "id": "risc0002",
                "title": "Unparsed peripheral window",
                "category": "general",
                "content": "MMIO window unparsed: reads land in opaque region unk_8020B000.",
                "addr": "0x8020B000",
            }),
        ],
    )
    data = bl.transform_legacy_db(str(src))
    by_id = {e["id"]: e for e in data["findings"]}
    blob = by_id["risc0001"]
    assert blob["status"] == "resolved"
    assert blob["addr"] == "0x8020A0C0"
    assert blob["addr_end"] == "0x8020A0F0"
    assert "Raw blob" in blob["title"]
    assert "opaque, no ELF" in blob["content"]
    assert blob["tags"] == ["firmware", "riscv", "blob", "ioc:file"]
    assert blob["category"] == "ioc"
    assert "vector" not in blob
    assert "entropy" not in blob
    assert by_id["risc0002"]["addr"] == "0x8020B000"


# ---------------------------------------------------------------------------
# apply_transform into current-schema targets
# ---------------------------------------------------------------------------


def test_apply_transform_into_current_schema_target(tmp_path):
    src = _make_legacy_db(
        tmp_path / "src.db",
        [
            _row({"id": "app00001", "title": "Adopted finding", "addr": "0x401000", "resolved": 1}),
            _row({"id": "app00002", "title": "gravity", "category": "evidence_gravity", "content": "{}"}),
        ],
    )
    target = tmp_path / "target.db"
    assert bl._init_new_schema(str(target)) is True

    first = bl.apply_transform(str(src), str(target))
    assert first["findings"] == 1
    assert first["machinery"] == 1
    assert first["written"] == 2

    # Idempotent: re-applying inserts nothing new (INSERT OR IGNORE).
    second = bl.apply_transform(str(src), str(target))
    assert second["written"] == 0

    with sqlite3.connect(target) as conn:
        findings = conn.execute("SELECT title, status FROM findings").fetchall()
        machinery = conn.execute("SELECT key, value FROM bb_machinery").fetchall()
    assert ("Adopted finding", "resolved") in findings
    assert machinery and machinery[0][0].startswith("evidence_gravity:app00002")
    payload = json.loads(machinery[0][1])
    assert payload["title"] == "gravity"


def test_apply_transform_migrates_conflicts_to_links(tmp_path):
    src = _make_legacy_db(
        tmp_path / "src.db",
        [_row({"id": "cnf00001", "title": "Claim A", "conflicts_with": '["cnf00002"]'})],
    )
    target = tmp_path / "target.db"
    assert bl._init_new_schema(str(target)) is True
    bl.apply_transform(str(src), str(target))
    with sqlite3.connect(target) as conn:
        links = conn.execute(
            "SELECT entry_a, entry_b, type FROM links WHERE type='conflict'"
        ).fetchall()
    assert ("cnf00001", "cnf00002", "conflict") in links


def test_apply_transform_into_store_workspace(tmp_path):
    src = _make_legacy_db(
        tmp_path / "src.db",
        [_row({"id": "leg00001", "title": "Moved finding", "addr": "0x402000", "contradicted": 1, "contradiction_reason": "refuted"})],
    )
    target = tmp_path / "target.db"
    store = BlackboardStore(str(target))
    result = bl.apply_transform(str(src), str(target))
    assert result["findings"] == 1
    entry = store.read("leg00001")
    assert entry["status"] == "rejected"
    assert entry["rejected_reason"] == "refuted"


def test_lifecycle_proposed_to_confirmed_contradicted_to_resolved(tmp_path):
    """Adopt a legacy row, then walk the full lifecycle over the store."""
    src = _make_legacy_db(
        tmp_path / "src.db",
        [_row({"id": "life0001", "title": "Lifecycle claim", "addr": "0x403000", "status": "proposed"})],
    )
    target = tmp_path / "target.db"
    store = BlackboardStore(str(target))
    bl.apply_transform(str(src), str(target))

    eid = "life0001"
    assert store.read(eid)["status"] == "proposed"

    # proposed -> confirmed (analyst verified).
    store.transition(eid, "confirmed")
    assert store.read(eid)["status"] == "confirmed"
    assert store.read(eid)["contradicted"] == 0

    # confirmed -> rejected via contradiction.
    assert store.contradict(eid, "a second experiment refuted it") is True
    rejected = store.read(eid)
    assert rejected["status"] == "rejected"
    assert rejected["contradicted"] == 1

    # rejected -> resolved (the analyst reconciled the contradiction).
    assert store.mark_resolved(eid) is True
    resolved = store.read(eid)
    assert resolved["status"] == "resolved"
    assert resolved["resolved"] == 1


# ---------------------------------------------------------------------------
# Path confinement
# ---------------------------------------------------------------------------


def test_workspace_root_order_env_then_idb_dir_then_cache(tmp_path, monkeypatch):
    cache = str(tmp_path / "cache")
    idb = str(tmp_path / "idbs" / "a.i64")
    # 1. env wins.
    monkeypatch.setenv(bl.BLACKBOARD_ROOT_ENV, str(tmp_path / "env"))
    assert bl.workspace_root(cache, idb) == str(tmp_path / "env")
    # 2. IDB dir.
    monkeypatch.delenv(bl.BLACKBOARD_ROOT_ENV, raising=False)
    assert bl.workspace_root(cache, idb) == str(tmp_path / "idbs")
    # 3. cache.
    assert bl.workspace_root(cache, "") == str(tmp_path / "cache")
    assert bl.workspace_root("", "") is None


def test_confine_path_rejects_escape_absolute_and_symlink(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    inside = tmp_path / "ws" / "notes.json"
    outside = tmp_path / "outside.json"
    outside.write_text("x")
    real = root / "real.json"
    real.write_text("y")

    canonical, err = bl.confine_path("notes.json", str(root))
    assert err is None
    assert canonical == str(inside)

    _, err = bl.confine_path("../../escape.json", str(root))
    assert err is not None and "escapes allowed root" in err

    _, err = bl.confine_path(str(outside), str(root))
    assert err is not None and "escapes allowed root" in err

    _, err = bl.confine_path("notes.json", None)
    assert err is not None and "no allowed root" in err

    # Symlinked components are rejected outright, even when the target stays
    # inside the root (a symlink cannot smuggle a path out of the sandbox).
    link = root / "link.json"
    link.symlink_to(real)
    _, err = bl.confine_path(str(link), str(root))
    assert err is not None and "symbolic links" in err

    esc = root / "esc.json"
    esc.symlink_to(outside)
    _, err = bl.confine_path(str(esc), str(root))
    assert err is not None and "symbolic links" in err
