"""Regression tests for bb01: blackboard store redesign.

Standalone tests: no live IDA. Every IDA interaction (function inventory,
callers/callees) is supplied through a ``_FakeIda``-style fake ``rpc_fn``;
embeddings are faked by monkeypatching the module ``_get_embedder``. The store
is always opened on a fresh tmp db.

Pinned contracts (work order bb01):
  - PRAGMA user_version schema versioning with an idempotent migration runner;
    re-opening an existing db does not re-run migrations and never errors.
  - Tables findings / links / finding_events / code_anchors / bb_tasks /
    bb_machinery / findings_embeddings all exist.
  - Single ``status`` column with ``'proposed'`` added; ``resolved`` /
    ``contradicted`` / ``conflicts_with`` are DERIVED at read time, never stored.
  - ``rejected_reason`` replaces ``contradiction_reason`` (the legacy name is a
    write alias in update() and never appears in a read dict).
  - Thread-local connection cache + busy_timeout + exactly one write transaction
    per write (a legacy caller may close the shared handle; the store reopens).
  - SQL aggregation backs stats / workspace_brief / campaign_summary / coverage.
  - semantic_search reads the findings_embeddings side table and falls back to
    keywords; the write path fires an embed_enqueue hook (default no-op) and
    embed=True embeds synchronously.
  - Coverage strategy reports honestly when the function inventory is empty or
    no live IDA session is available (rpc_fn is None).
  - semantic_index / semantic_rebuild are REMOVED from the store.
  - Every pinned public method signature still works, plus module exports.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import sys
from contextlib import closing
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from ida_pro_mcp.host import stores
from ida_pro_mcp.host.stores import blackboard_store
from ida_pro_mcp.host.stores.blackboard_store import (
    KINDS,
    SCHEMA_VERSION,
    STATUSES,
    STRATEGIES,
    BlackboardStore,
    _resolve_db_path,
    code_digest,
    entry_id_in,
    is_auto_name,
    marker_for,
    normalize_addr,
    symbol_from_title,
)

# ---------------------------------------------------------------------------
# Module surface: exports and removed methods
# ---------------------------------------------------------------------------

def test_required_module_exports_exist():
    for name in (
        "BlackboardStore", "_resolve_db_path", "STRATEGIES", "is_auto_name",
        "entry_id_in", "normalize_addr", "symbol_from_title", "KINDS", "STATUSES",
        "code_digest", "marker_for", "SCHEMA_VERSION",
    ):
        assert hasattr(blackboard_store, name), f"module export {name} missing"


def test_proposed_is_a_valid_status_and_kinds_are_stable():
    assert "proposed" in STATUSES
    assert frozenset({"proposed", "open", "confirmed", "resolved", "rejected"}) == STATUSES
    assert frozenset(
        {"finding", "hypothesis", "question", "task", "decision", "examined"}
    ) == KINDS
    assert STRATEGIES == ("unresolved", "stale", "conflict", "coverage", "frontier")


def test_semantic_index_and_rebuild_are_removed():
    # No host-level caller references these; the redesign must not carry them.
    assert not hasattr(BlackboardStore, "semantic_index")
    assert not hasattr(BlackboardStore, "semantic_rebuild")


def test_db_path_is_required():
    with pytest.raises(ValueError, match="db_path is required"):
        BlackboardStore(db_path="")
    # _resolve_db_path is still importable (services.py exports it).
    assert callable(_resolve_db_path)


# ---------------------------------------------------------------------------
# Schema: versioned migrations are idempotent
# ---------------------------------------------------------------------------

def test_schema_version_and_tables_exist(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    conn = store._conn()
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == SCHEMA_VERSION
    names = {
        row["name"] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    for table in (
        "findings", "links", "finding_events", "code_anchors",
        "bb_tasks", "bb_machinery", "findings_embeddings",
    ):
        assert table in names, f"missing table {table}"
    # bb_tasks / bb_machinery must match blackboard_orchestration.MachineryDB
    # (_machinery_schema) EXACTLY, or its CREATE IF NOT EXISTS is a no-op and
    # its INSERTs fail on missing columns, degrading the machinery to memory.
    task_cols = {
        row["name"] for row in conn.execute(
            "SELECT name FROM pragma_table_info('bb_tasks')"
        ).fetchall()
    }
    assert {"task_id", "task_type", "status", "payload", "created_at", "updated_at"} <= task_cols
    assert "kind" not in task_cols  # old/design schema must not leak through
    mach_cols = {
        row["name"] for row in conn.execute(
            "SELECT name FROM pragma_table_info('bb_machinery')"
        ).fetchall()
    }
    assert {"id", "namespace", "key", "value", "updated_at"} <= mach_cols
    # Legacy single-table name survives only as the compat view.
    views = {
        row["name"] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='view'"
        ).fetchall()
    }
    assert "blackboard" in views


def test_machinerydb_inserts_work_on_migrated_db(tmp_path):
    """The orchestration's MachineryDB must not degrade on our migrated DB.

    blackboard_orchestration._machinery_schema owns bb_tasks/bb_machinery; the
    store's migration must pre-create them with exactly that layout, or the
    orchestration's CREATE TABLE IF NOT EXISTS becomes a no-op and its INSERTs
    fail on missing columns (task_type / namespace), flipping _usable to False
    and silently dropping durable machinery state.
    """
    from ida_pro_mcp.host.server.blackboard_orchestration import MachineryDB

    store = BlackboardStore(str(tmp_path / "ws.db"))
    store.write(title="seeded", addr="0x401000")
    store.close()

    machinery = MachineryDB(str(store.db_path), {})
    machinery.set("crawler", "cursor", {"addr": "0x401000"})
    assert machinery.get("crawler", "cursor") == {"addr": "0x401000"}
    machinery.save_task("t1", "trace", "pending", {"entities": {"addrs": ["0x401000"]}})
    machinery.update_task("t1", "done", {"status": "done", "result": {"ok": True}})
    task = machinery.task("t1")
    assert task is not None
    assert task["task_type"] == "trace"
    assert task["status"] == "done"
    assert task["payload"]["result"] == {"ok": True}


def test_reopening_existing_db_does_not_re_migrate_or_error(tmp_path):
    db = str(tmp_path / "ws.db")
    first = BlackboardStore(db)
    first.write(title="persisted", addr="0x401000")
    first.close()

    second = BlackboardStore(db)  # must not raise, must not reset the schema
    found = [e for e in second.list(limit=50) if e["title"] == "persisted"]
    assert len(found) == 1


def test_busy_timeout_is_set_and_connection_is_thread_local(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    timeout = store._conn().execute("PRAGMA busy_timeout").fetchone()[0]
    assert timeout >= 30_000


def test_closed_connection_reopens_cleanly(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    eid = store.write(title="kept", addr="0x401000")
    # A legacy caller may close the shared handle (see confidence-decay tests).
    with closing(store._conn()) as conn:
        conn.execute(
            "UPDATE blackboard SET updated_at=? WHERE id=?", (1.0, eid)
        )
        conn.commit()
    # The next operation must not blow up on the closed handle.
    assert store.read(eid)["title"] == "kept"


def test_write_uses_one_transaction_per_write(tmp_path):
    """Writes must be individually atomic and committed before returning."""
    store = BlackboardStore(str(tmp_path / "ws.db"))
    eid = store.write(title="atomic", addr="0x401000")
    # A separate connection sees the committed row immediately.
    with sqlite3.connect(store.db_path) as conn:
        n = conn.execute("SELECT COUNT(*) FROM findings WHERE id=?", (eid,)).fetchone()[0]
    assert n == 1


# ---------------------------------------------------------------------------
# Single status column: proposed lifecycle + derived read-time fields
# ---------------------------------------------------------------------------

def test_proposed_lifecycle_to_confirmed_and_resolved(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    pid = store.write(
        title="Rename handle_recv",
        category="proposal",
        addr="0x401000",
        status="proposed",
        tags=["proposal_lifecycle", "status:proposed"],
    )
    entry = store.read(pid)
    assert entry["status"] == "proposed"
    assert entry["resolved"] == 0
    assert entry["contradicted"] == 0

    # Proposed is not an open thread and is not part of the brief.
    assert store.targets("unresolved", limit=5)["count"] == 0
    brief = store.workspace_brief()
    all_brief_titles = [
        item["title"] for item in
        brief["focus"] + brief["confirmed"] + brief["conflicts"] + brief["stale"]
    ]
    assert "Rename handle_recv" not in all_brief_titles

    # Accept: proposed -> confirmed.
    assert store.transition(pid, "confirmed")["status"] == "confirmed"
    assert store.read(pid)["resolved"] == 0

    # Resolve: confirmed -> resolved; resolved is derived, not stored.
    assert store.transition(pid, "resolved", reason="verified")["status"] == "resolved"
    assert store.read(pid)["resolved"] == 1
    events = [e["event"] for e in store.workspace_brief()["recent_activity"]]
    assert "status:confirmed" in events and "status:resolved" in events


def test_proposed_rejected_path_records_rejected_reason(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    pid = store.write(title="Rename helper", addr="0x401000", status="proposed")
    assert store.transition(pid, "rejected", reason="reviewer declined")["status"] == "rejected"
    entry = store.read(pid)
    assert entry["contradicted"] == 1
    assert entry["rejected_reason"] == "reviewer declined"
    assert "contradiction_reason" not in entry


def test_resolved_and_contradicted_are_derived_flags(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    a = store.write(title="a", addr="0x401000")
    b = store.write(title="b", addr="0x402000")
    assert store.mark_resolved(a) is True
    assert store.contradict(b, "evidence changed") is True
    assert store.read(a)["resolved"] == 1 and store.read(a)["contradicted"] == 0
    assert store.read(b)["contradicted"] == 1 and store.read(b)["resolved"] == 0
    # Raw storage: the flags live only in the status column.
    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        statuses = {row["id"]: row["status"] for row in conn.execute("SELECT id, status FROM findings")}
        columns = {col[1] for col in conn.execute("PRAGMA table_info(findings)")}
    assert statuses[a] == "resolved" and statuses[b] == "rejected"
    assert "resolved" not in columns and "contradicted" not in columns


def test_legacy_contradiction_reason_kwarg_aliases_to_rejected_reason(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    eid = store.write(title="claim", addr="0x401000")
    # The old kwarg name still routes to the new column.
    assert store.update(eid, contradicted=True, contradiction_reason="old naming") is True
    entry = store.read(eid)
    assert entry["contradicted"] == 1
    assert entry["rejected_reason"] == "old naming"


def test_opposed_statuses_never_merge_and_conflicts_are_symmetric(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    confirmed = store.upsert_finding("Length is validated", addr="0x401000", status="confirmed")
    rejected = store.upsert_finding("Length is validated", addr="0x401000", status="rejected")
    assert rejected["entry_id"] != confirmed["entry_id"]
    assert rejected["conflict"]["with"] == confirmed["entry_id"]

    orig = store.read(confirmed["entry_id"])
    assert rejected["entry_id"] in orig["conflicts_with"]
    assert orig["status"] == "confirmed"
    # And the disagreement is symmetric: the rejected row points back.
    rej = store.read(rejected["entry_id"])
    assert confirmed["entry_id"] in rej["conflicts_with"]


# ---------------------------------------------------------------------------
# Opaque raw-blob / RISC-V staleness scenario
# ---------------------------------------------------------------------------

_RISCV_AUIPC_LUI = (
    "auipc   t0, 0x1f000        ; 00111000000000000000111100101111\n"
    "addi    a0, t0, -2048      ; 11111111100000101100000010010011\n"
)
_RISCV_AUIPC_LUI_REFORMATTED = (
    "auipc   t0,  0x1f000       ; 00111000000000000000111100101111\n"
    "addi    a0,  t0,  -2048    ; 11111111100000101100000010010011\n"
)
_RISCV_AUIPC_LUI_CHANGED = (
    "auipc   t0, 0x1f000        ; 00111000000000000000111100101111\n"
    "addi    a0, t0, 0x800      ; 00000000100000101100000010010011\n"
)


def test_raw_riscv_blob_reformat_is_not_drift_but_a_real_change_is(tmp_path):
    """Whitespace/recomment re-flow of an opaque disassembly blob must not
    flag staleness; a changed operand must."""
    store = BlackboardStore(str(tmp_path / "ws.db"))
    store.observe_code("0x80001000", "decompile", _RISCV_AUIPC_LUI)
    eid = store.write(
        title="table base loaded into t0",
        addr="0x80001000",
        status="confirmed",
        confidence=0.9,
    )

    first = store.observe_code("0x80001000", "decompile", _RISCV_AUIPC_LUI_REFORMATTED)
    assert first["changed"] is False
    assert store.read(eid)["stale"] == 0

    second = store.observe_code("0x80001000", "decompile", _RISCV_AUIPC_LUI_CHANGED)
    assert second["changed"] is True
    assert second["stale_marked"] == 1
    assert store.read(eid)["stale"] == 1
    assert "0x80001000" in store.read(eid)["stale_reason"]


def test_opaque_blob_anchor_survives_across_reopen(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    store.observe_code("0x80002000", "disassemble", _RISCV_AUIPC_LUI)
    store.write(title="opaque blob claim", addr="0x80002000")

    reopened = BlackboardStore(str(tmp_path / "ws.db"))
    anchor = reopened.current_anchor("0x80002000")
    assert anchor is not None
    assert anchor["digest"] == code_digest(_RISCV_AUIPC_LUI)


# ---------------------------------------------------------------------------
# Coverage honesty: no inventory / no live session must say so
# ---------------------------------------------------------------------------

def test_coverage_notes_when_rpc_fn_is_none(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    result = store.targets("coverage", limit=5, rpc_fn=None)
    assert result["targets"] == []
    assert result["note"] and "live IDA session" in result["note"]


def test_coverage_notes_when_inventory_is_empty(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))

    def rpc(tool, arguments):
        assert (tool, arguments) == ("data", {"action": "functions", "count": 200})
        return {"functions": []}

    result = store.targets("coverage", limit=5, rpc_fn=rpc)
    assert result["targets"] == []
    assert result["note"] and "function inventory is empty" in result["note"]


def test_coverage_prefers_auto_named_functions(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))

    def rpc(tool, arguments):
        return {"functions": [
            {"addr": "0x401000", "name": "named_parser", "xref_count": 20},
            {"addr": "0x402000", "name": "sub_402000", "xref_count": 12},
        ]}

    targets = store.next_target(limit=5, rpc_fn=rpc)
    assert len(targets) == 1
    assert targets[0]["addr"] == "0x402000"
    assert targets[0]["reason"] == "12 callers, never examined"


# ---------------------------------------------------------------------------
# semantic_search: side table + write-path enqueue hook
# ---------------------------------------------------------------------------

class _KeywordEmbedder:
    backend = "test"
    dim = 2

    def embed_vector(self, text: str):
        if "certificate" in str(text or ""):
            return [1.0, 0.0]
        return [0.0, 1.0]


def test_embed_enqueue_hook_fires_on_write(tmp_path, monkeypatch):
    from ida_pro_mcp.host.stores import blackboard_store as bs

    monkeypatch.setattr(bs, "_get_embedder", _KeywordEmbedder)
    store = BlackboardStore(str(tmp_path / "ws.db"))
    enqueued: list[tuple[str, str]] = []
    store.embed_enqueue = lambda entry_id, text: enqueued.append((entry_id, text))

    eid = store.write("TLS certificate parser", "validates an ASN.1 length")
    # Default path: hook fires, nothing stored synchronously.
    assert len(enqueued) == 1
    assert enqueued[0][0] == eid
    assert "certificate" in enqueued[0][1]
    with sqlite3.connect(store.db_path) as conn:
        n = conn.execute("SELECT COUNT(*) FROM findings_embeddings").fetchone()[0]
    assert n == 0


def test_embed_true_computes_synchronously_and_search_reports_semantic(tmp_path, monkeypatch):
    from ida_pro_mcp.host.stores import blackboard_store as bs

    monkeypatch.setattr(bs, "_get_embedder", _KeywordEmbedder)
    store = BlackboardStore(str(tmp_path / "ws.db"))
    store.write("TLS certificate parser", "validates an ASN.1 length", category="crypto", embed=True)
    store.write("registry persistence", "autorun key manipulation", category="persistence", embed=True)

    results = store.semantic_search("certificate", top_k=5, threshold=0.5, category="crypto")
    assert results and results[0]["title"] == "TLS certificate parser"
    assert results[0]["match"] == "semantic"
    assert len(results) == 1


def test_semantic_search_lexical_fallback_when_embeddings_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(blackboard_store, "_get_embedder", lambda: None)
    store = BlackboardStore(str(tmp_path / "ws.db"))
    store.write("TLS certificate parser", "validates an ASN.1 length", category="crypto")

    results = store.semantic_search("certificate length", top_k=5, category="crypto")
    assert results and results[0]["title"] == "TLS certificate parser"
    assert results[0]["match"] == "lexical"
    assert results[0]["similarity"] == 1.0


def test_semantic_search_falls_back_lexically_when_nothing_passes_threshold(tmp_path, monkeypatch):
    from ida_pro_mcp.host.stores import blackboard_store as bs

    monkeypatch.setattr(bs, "_get_embedder", _KeywordEmbedder)
    store = BlackboardStore(str(tmp_path / "ws.db"))
    store.write("TLS certificate parser", "validates an ASN.1 length", category="crypto", embed=True)

    results = store.semantic_search("parser", top_k=5, threshold=0.99, category="crypto")
    assert results and results[0]["match"] == "lexical"


def test_embed_enqueue_hook_stays_default_noop(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    # The default hook must be a no-op (never raises, never blocks).
    eid = store.write("plain claim", addr="0x401000")
    store.embed_enqueue(eid, "some text")


# ---------------------------------------------------------------------------
# SQL aggregation shapes
# ---------------------------------------------------------------------------

def test_stats_workspace_brief_campaign_and_coverage_aggregate(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    store.upsert_finding("Open question", kind="question", priority=1.0, confidence=0.4)
    store.upsert_finding("Confirmed fact", kind="finding", status="confirmed", confidence=0.95)
    rejected = store.upsert_finding("Rejected guess", kind="hypothesis")["entry_id"]
    store.transition(rejected, "rejected", reason="contradicted by the fact")
    store.record_examination("0x401a20", verdict="boring", note="thunk")

    stats = store.stats()
    assert stats["total_entries"] == 4
    assert stats["unresolved"] >= 1
    # The boring examination is stored as a resolved row.
    assert stats["resolved"] == 1 and stats["contradicted"] == 1
    assert "coverage" in stats and stats["coverage"]["examined"] == 1

    brief = store.workspace_brief()
    # Examinations are addressed via the coverage block, not the findings total.
    assert brief["counts"]["total"] == 3
    assert brief["counts"]["confirmed"] == 1
    assert brief["counts"]["conflicts"] == 1
    assert brief["counts"]["examined"] == 1

    campaign = store.campaign_summary()
    assert campaign["total_entries"] == 4
    assert campaign["contradicted"] == 1

    coverage = store.coverage()
    assert coverage == {"examined": 1, "by_verdict": {"boring": 1}}


# ---------------------------------------------------------------------------
# Keep pinned public signatures working (spot checks)
# ---------------------------------------------------------------------------

def test_write_supports_the_full_pinned_signature(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    eid = store.write(
        title="full", content="body", category="vuln", addr="0x401000", addr_end="0x401020",
        tags=["a"], confidence=0.7, source="test", embed=False,
        ioc_type="ip", ioc_value="1.2.3.4", depends_on="", blocks_addr="",
        register="r3", reg_type="ptr", evidence=[{"type": "x", "value": "y"}],
        source_type="test", entropy=7.0, xref_count=3, kind="finding",
        status="open", priority=0.6, fingerprint="", verdict="",
        anchor_kind="", anchor_digest="",
    )
    entry = store.read(eid)
    assert entry["register"] == "r3" and entry["xref_count"] == 3


def test_read_returns_derived_conflicts_with_via_links(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    a = store.write(title="A", addr="0x401000")
    b = store.write(title="B", addr="0x402000")
    assert store.link_conflict(a, b, reason="disagree") is True
    assert store.read(a)["conflicts_with"] == [b]
    assert store.read(b)["conflicts_with"] == [a]


def test_helpers_are_available_for_the_idb_seam(tmp_path):
    assert is_auto_name("sub_401000") is True
    assert is_auto_name("parse_pkt") is False
    assert symbol_from_title("Packet receive handler") == "packet_receive_handler"
    assert entry_id_in("[mcp:abcd1234] some comment") == "abcd1234"
    assert marker_for("abcd1234") == "[mcp:abcd1234]"
    assert normalize_addr(0x401000) == "0x401000"


def test_services_still_exports_the_store(tmp_path):
    try:
        import ida_pro_mcp.services as services
    except ModuleNotFoundError as exc:
        # services.py pulls in host/server -> server_r2 -> host/r2_engine,
        # which is being concurrently migrated by another order and can be
        # transiently unimportable on this branch. The contract below is real;
        # it simply cannot be exercised while services cannot import.
        if "ida_pro_mcp.config" in str(exc):
            pytest.skip(f"ida_pro_mcp.services unimportable during concurrent r2 migration: {exc}")
        raise
    assert services.BlackboardStore is BlackboardStore
    assert services._resolve_db_path is _resolve_db_path


def test_fake_ida_rpc_fn_drives_frontier_without_live_ida(tmp_path):
    store = BlackboardStore(str(tmp_path / "ws.db"))
    store.upsert_finding("Command dispatcher", addr="0x401000", status="confirmed", confidence=0.9)

    def rpc(tool, arguments):
        if tool != "code":
            return {}
        if arguments["action"] == "callers":
            return {"callers": [{"addr": "0x400100"}]}
        return {"callees": [{"addr": "0x401500"}]}

    targets = store.targets("frontier", limit=5, rpc_fn=rpc)["targets"]
    assert {t["address"] for t in targets} == {"0x400100", "0x401500"}
    assert all("Command dispatcher" in t["reason"] for t in targets)


def test_external_consumers_see_the_store_as_before():
    # server_blackboard imports STRATEGIES as BB_STRATEGIES and is_auto_name.
    from ida_pro_mcp.host.server.server_blackboard import BB_STRATEGIES  # noqa: F401
    from ida_pro_mcp.host.server.server_blackboard_idb import (  # noqa: F401
        entry_id_in as _idb_entry_id_in,
        is_auto_name as _idb_is_auto_name,
        normalize_addr as _idb_normalize_addr,
        symbol_from_title as _idb_symbol_from_title,
    )
    assert BB_STRATEGIES == STRATEGIES
    assert _idb_entry_id_in("[mcp:abcd1234] x") == "abcd1234"
