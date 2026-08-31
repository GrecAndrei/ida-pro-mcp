"""Regression tests for the f10_stores swarm finding wave.

Covers the host/stores package:
- symbol_db db_path confinement (reject traversal / out-of-root directory
  creation) and default data-root resolution.
- symbol_db UNIQUE(symbol_name, fingerprint) index so concurrent upserts
  cannot insert duplicate rows.
- symbol_db confidence=0 is preserved instead of being coerced to the default.
- truncation fail-closed token scoping: an unscoped token is not unlocked by
  a scoped caller.
- truncation continuation cursor advances atomically under concurrent
  ida_continue calls.
- truncation regex search rejects catastrophic (ReDoS) patterns and bounds the
  scanned text.
- truncation recursion depth is bounded for pathologically nested responses.
- knowledge_graph read-modify-write JSON appends survive concurrent writers.
- insight_index bare-hex/0x address normalization and copied tags on
  get_function; dirty flag retained when an autosave fails.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.stores import truncation as T
from ida_pro_mcp.host.stores.insight_index import InsightIndex
from ida_pro_mcp.host.stores.knowledge_graph import KnowledgeGraph
from ida_pro_mcp.host.stores.symbol_db import SymbolDB

# ─── truncation store isolation ───────────────────────────────────────────────


def _reset_truncation_store():
    T._TRUNCATION_STORE.clear()
    T._TRUNCATION_ORDER.clear()


@pytest.fixture(autouse=True)
def _clean_truncation_store():
    _reset_truncation_store()
    yield
    _reset_truncation_store()


# ─── Finding 3: truncation token scoping fails closed ────────────────────────


def test_unscoped_token_not_unlocked_by_scoped_caller():
    token = T._store_truncation(
        {"data": list(range(10))},
        {"data": {"type": "list", "total": 10, "chunk_size": 3, "next_offset": 0}},
    )
    # The private/host-internal path that minted an unscoped token may continue it.
    assert T._get_entry(token, session_id="", owner_id="") is not None
    assert T.continue_truncated(token, session_id="", owner_id="").get("ok") is True
    # A scoped caller must never unlock an unscoped token — fail closed.
    assert T._get_entry(token, session_id="sess-a", owner_id="client-a") is None
    res = T.continue_truncated(token, session_id="sess-a", owner_id="client-a")
    assert res.get("error")
    assert res.get("code") == MCPError.TRUNCATION_TOKEN_INVALID


def test_scoped_token_requires_matching_scope():
    token = T._store_truncation(
        {"data": [1, 2, 3]},
        {"data": {"type": "list", "total": 3, "chunk_size": 2, "next_offset": 0}},
        session_id="s1",
        owner_id="client-a",
    )
    assert T._get_entry(token, session_id="s1", owner_id="client-a") is not None
    assert T._get_entry(token, session_id="s1", owner_id="client-b") is None
    assert T._get_entry(token, session_id="s2", owner_id="client-a") is None
    # Session-only tokens stay bound to their session.
    token2 = T._store_truncation(
        {"data": [1]},
        {"data": {"type": "list", "total": 1, "chunk_size": 1, "next_offset": 1}},
        session_id="s1",
    )
    assert T._get_entry(token2, session_id="s1") is not None
    assert T._get_entry(token2, session_id="s2") is None


# ─── Finding 2: continuation cursor advances atomically ──────────────────────


def test_continue_truncated_cursor_advances_atomically_under_concurrency():
    token = T._store_truncation(
        {"items": list(range(1000))},
        {"items": {"type": "list", "total": 1000, "chunk_size": 10, "next_offset": 0}},
        session_id="s",
        owner_id="o",
    )
    offsets: list[int] = []
    lock = threading.Lock()

    def worker():
        res = T.continue_truncated(token, session_id="s", owner_id="o")
        off = res.get("offset")
        assert res.get("error") is not True
        with lock:
            offsets.append(off)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 20 workers, each served a disjoint 10-item page: no overlapping chunks,
    # no lost cursor update.
    assert len(offsets) == 20
    assert len(set(offsets)) == 20
    assert all(off % 10 == 0 for off in offsets)
    # Cursor advanced exactly 200 items after 20 pages.
    entry = T._get_entry(token, session_id="s", owner_id="o")
    assert entry["fields"]["items"]["next_offset"] == 200


# ─── Finding 12: truncation recursion depth bounded ──────────────────────────


def test_truncate_recursive_depth_is_bounded():
    payload: dict = {}
    cur = payload
    for _ in range(2000):
        nxt: dict = {}
        cur["k"] = nxt
        cur = nxt
    cur["k"] = "x" * 1000
    fields: dict = {}
    result = T._truncate_recursive(payload, max_tokens=100, truncated_fields=fields)
    # Must not raise RecursionError for a pathologically deep response.
    assert isinstance(result, dict)
    assert result["k"] is not None


# ─── Finding 13: regex search rejects catastrophic patterns ──────────────────


def test_search_truncated_rejects_catastrophic_regex():
    token = T._store_truncation(
        {"data": "a" * 1000},
        {"data": {"type": "string", "total": 1000, "chunk_size": 50, "next_offset": 0}},
    )
    res = T.search_truncated(token, pattern=r"(a+)+$", is_regex=True)
    assert res.get("error")
    assert res.get("code") == MCPError.INVALID_ARGS


def test_search_truncated_regex_still_works():
    token = T._store_truncation(
        {"data": "0x401000: mov eax, ebx\n0x401004: call recv"},
        {"data": {"type": "string", "total": 100, "chunk_size": 50, "next_offset": 0}},
    )
    res = T.search_truncated(token, pattern=r"0x[0-9a-f]+:", is_regex=True)
    assert res.get("ok") is True
    assert res.get("match_count", 0) > 0


# ─── Finding 1: symbol_db db_path confinement ────────────────────────────────


def _set_data_root(monkeypatch, root: str) -> None:
    # _data_root prefers IDA_MCP_CACHE_DIR (which tests/conftest.py also sets
    # autouse), so override that one to pin the confinement root.
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", root)
    monkeypatch.setenv("IDA_MCP_DATA_DIR", root)


def test_symbol_db_rejects_path_traversal(monkeypatch):
    _set_data_root(monkeypatch, "/tmp/ida-mcp-test-data")
    with pytest.raises(ValueError):
        SymbolDB("/tmp/x/../evil.db")
    with pytest.raises(ValueError):
        SymbolDB("../../escape.db")


def test_symbol_db_rejects_directory_creation_outside_root(tmp_path, monkeypatch):
    _set_data_root(monkeypatch, str(tmp_path / "data"))
    outside = tmp_path / "brand_new_dir" / "sub" / "evil.db"
    with pytest.raises(ValueError):
        SymbolDB(str(outside))


def test_symbol_db_allows_existing_parent_outside_root(tmp_path, monkeypatch):
    _set_data_root(monkeypatch, str(tmp_path / "data"))
    existing = tmp_path / "shared"
    existing.mkdir()
    db = SymbolDB(str(existing / "sym.db"))
    assert db.db_path == str(existing / "sym.db")
    rid = db.upsert_symbol({"symbol_name": "foo", "fingerprint": "fp-ok"})
    assert rid > 0


def test_symbol_db_relative_path_resolves_under_data_root(tmp_path, monkeypatch):
    _set_data_root(monkeypatch, str(tmp_path / "data"))
    db = SymbolDB("shared.db")
    assert os.path.basename(db.db_path) == "shared.db"
    assert db.db_path.startswith(str(tmp_path / "data"))


def test_symbol_db_default_uses_data_root(tmp_path, monkeypatch):
    _set_data_root(monkeypatch, str(tmp_path / "data"))
    db = SymbolDB()
    assert db.db_path == os.path.join(str(tmp_path / "data"), "symbol_kb.db")


# ─── Finding 4: symbol_db unique (symbol_name, fingerprint) ──────────────────


def test_symbol_db_upsert_merges_same_fingerprint(tmp_path):
    db = SymbolDB(str(tmp_path / "sym.db"))
    first = db.upsert_symbol(
        {"symbol_name": "wifi_tx", "fingerprint": "fp-1", "confidence": 0.9, "strings": ["a"]}
    )
    second = db.upsert_symbol(
        {"symbol_name": "wifi_tx", "fingerprint": "fp-1", "confidence": 0.5, "strings": ["b"]}
    )
    assert first == second
    hits = db.query_symbols("wifi_tx")
    assert len(hits) == 1
    assert hits[0]["confidence"] == 0.5


def test_symbol_db_unique_index_blocks_duplicate_inserts(tmp_path):
    db = SymbolDB(str(tmp_path / "sym.db"))
    db.upsert_symbol({"symbol_name": "x", "fingerprint": "fp"})
    with pytest.raises(sqlite3.IntegrityError), contextlib.closing(db._conn()) as conn:
        conn.execute(
            "INSERT INTO symbols(symbol_name, fingerprint, created_at, updated_at) VALUES ('x','fp',1,1)"
        )


# ─── Finding 10: symbol_db confidence=0 preserved ────────────────────────────


def test_symbol_db_zero_confidence_symbol_preserved(tmp_path):
    db = SymbolDB(str(tmp_path / "sym.db"))
    db.upsert_symbol({"symbol_name": "low_conf", "fingerprint": "fp-z", "confidence": 0.0})
    hits = db.query_symbols("low_conf")
    assert hits[0]["confidence"] == 0.0


def test_symbol_db_zero_confidence_hypothesis_preserved(tmp_path):
    db = SymbolDB(str(tmp_path / "sym.db"))
    db.upsert_hypothesis(binary_hash="B" * 40, addr_offset=1, hypothesis_text="t", confidence=0.0)
    hits = db.query_hypotheses(binary_hash="B" * 40)
    assert hits[0]["confidence"] == 0.0


# ─── Finding 6: knowledge_graph atomic read-modify-write ─────────────────────


def test_kg_concurrent_appends_no_lost_update(tmp_path):
    kg = KnowledgeGraph(str(tmp_path / "kg.db"))
    sid = kg.add_struct("t", members=[{"offset": 0, "size": 4, "name": "a"}])

    def worker(i: int):
        kg.record_struct_access(sid, f"0x{i:04x}", "read", 0)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    seen = {a["addr"] for a in kg.get_struct(sid)["seen_at"]}
    assert len(seen) == 20


def test_kg_read_modify_write_methods_still_work(tmp_path):
    kg = KnowledgeGraph(str(tmp_path / "kg.db"))
    sid = kg.add_struct("t", members=[{"offset": 0, "size": 4, "name": "a"}])
    assert kg.record_struct_access(sid, "0x401000", "read", 0) is True
    sm = kg.add_state_machine("sm", "0x500000")
    assert kg.add_transition(sm, 0, 1, "0x401000") is True
    gid = kg.add_gap("expected")
    assert kg.add_gap_candidate(gid, "0x402000") is True
    pid = kg.add_peripheral("0x600000")
    assert kg.record_peripheral_access("0x600000", "0x401000", 0x10) == pid
    # Create-on-first-access path.
    pid2 = kg.record_peripheral_access("0x700000", "0x401000", 0x20)
    assert pid2
    periphs = {p["base_addr"] for p in kg.list_peripherals()}
    assert "0x700000" in periphs


def test_kg_system_crud_and_member_lookup(tmp_path):
    kg = KnowledgeGraph(str(tmp_path / "kg.db"))
    sid = kg.add_system(
        "rx pipeline",
        ["0x401000"],
        description="packet receive path",
        entry_points=["0x401000"],
        tags=["network"],
        confidence=0.8,
    )

    system = kg.get_system(sid)
    assert system["name"] == "rx pipeline"
    assert system["entry_points"] == ["0x401000"]
    assert kg.find_system_for_addr("0x401000")["id"] == sid
    assert kg.find_system_for_addr("0x499000") is None
    assert kg.add_member_to_system(sid, "0x402000") is True
    assert kg.add_member_to_system(sid, "0x402000") is True
    assert kg.get_system(sid)["members"] == ["0x401000", "0x402000"]
    assert kg.add_member_to_system("missing", "0x403000") is False
    assert kg.update_system(sid, coverage_pct=75.0, data_structs=["struct-1"]) is True
    assert kg.get_system(sid)["coverage_pct"] == 75.0
    assert kg.get_system(sid)["data_structs"] == ["struct-1"]
    assert kg.update_system(sid, unsupported=True) is False
    assert kg.update_system("missing", name="nope") is False
    assert kg.list_systems()[0]["id"] == sid


def test_kg_struct_matching_and_state_machine_listing(tmp_path):
    kg = KnowledgeGraph(str(tmp_path / "kg.db"))
    first = kg.add_struct(
        "header",
        members=[{"offset": 0, "size": 4}, {"offset": 8, "size": 4}],
    )
    second = kg.add_struct(
        "packet",
        members=[{"offset": 0, "size": 4}, {"offset": 4, "size": 4}],
        confidence=0.9,
    )

    assert kg.find_struct_by_offset_pattern([0, 8], threshold=1.0)["id"] == first
    assert kg.find_struct_by_offset_pattern([0, 8], threshold=1.01) is None
    assert kg.find_struct_by_offset_pattern([]) is None
    assert kg.find_struct_by_offset_pattern([99], threshold=0.1) is None
    assert {row["id"] for row in kg.list_structs()} == {first, second}

    sm_id = kg.add_state_machine(
        "connection state", "0x500000", states=[{"value": 0, "name": "idle"}]
    )
    assert kg.add_transition(sm_id, 0, 1, "0x401000", "packet received") is True
    sm = kg.get_state_machine(sm_id)
    assert sm["states"] == [{"value": 0, "name": "idle"}]
    assert sm["transitions"][0]["trigger_addr"] == "0x401000"
    assert kg.add_transition("missing", 0, 1, "0x0") is False
    assert kg.list_state_machines()[0]["id"] == sm_id


def test_kg_gap_attack_surface_and_peripheral_lifecycles(tmp_path):
    kg = KnowledgeGraph(str(tmp_path / "kg.db"))
    gap_id = kg.add_gap(
        "key derivation",
        why="expected in WPA firmware",
        hints=["PTK", "GTK"],
        priority=0.9,
        gap_type="security",
        binary_type="wifi_firmware",
    )
    assert kg.add_gap_candidate(gap_id, "0x401000") is True
    assert kg.add_gap_candidate(gap_id, "0x401000") is True
    assert kg.fill_gap(gap_id, "0x402000") is True
    assert kg.add_gap_candidate("missing", "0x0") is False
    assert kg.fill_gap("missing", "0x0") is False
    assert kg.list_gaps(resolved=False) == []
    assert kg.list_gaps(resolved=True)[0]["candidates"] == ["0x401000"]

    attack_id = kg.add_attack_surface(
        "0x403000", name="packet parser", reachable_from="network", call_stack=["0x401000"]
    )
    assert kg.update_attack_surface(
        attack_id,
        max_input_size=4096,
        has_length_check=1,
        parsing_depth=3,
        known_vulns=["bb-1"],
        fuzz_priority=0.9,
    ) is True
    attack = kg.list_attack_surface()[0]
    assert attack["max_input_size"] == 4096
    assert attack["known_vulns"] == ["bb-1"]
    assert kg.update_attack_surface(attack_id, unsupported=True) is False
    assert kg.update_attack_surface("missing", name="nope") is False

    peripheral_id = kg.add_peripheral(
        "0x600000", name="UART", periph_type="uart", drivers=["0x401000"]
    )
    assert kg.add_peripheral("0x600000", name="duplicate") == peripheral_id
    assert kg.record_peripheral_access("0x600000", "0x402000", 0x10, "read") == peripheral_id
    assert kg.record_peripheral_access("0x600000", "0x402000", 0x10, "write") == peripheral_id
    peripheral = kg.list_peripherals()[0]
    assert peripheral["drivers"] == ["0x401000", "0x402000"]
    assert peripheral["registers"] == [{"offset": 0x10, "name": "reg_010", "access_pattern": "read"}]

    assert kg.summary() == {
        "systems": 0,
        "structs": 0,
        "state_machines": 0,
        "gaps_open": 0,
        "gaps_filled": 1,
        "attack_surface_entries": 1,
        "peripherals": 1,
    }


# ─── Finding 11: insight_index address normalization + copied tags ───────────


def test_insight_index_bare_and_prefixed_hex_collide():
    idx = InsightIndex()
    idx.index_function("401000", {"behavior_tags": ["crypto"], "name": "enc"})
    assert idx.get_function("0x401000") is not None
    assert idx.get_function("0x000401000") is not None


def test_insight_index_get_function_returns_copied_tags():
    idx = InsightIndex()
    idx.index_function("0x401000", {"behavior_tags": ["crypto"], "name": "enc"})
    meta = idx.get_function("0x401000")
    assert meta is not None
    meta["tags"].append("mutated")
    assert idx.get_function("0x401000")["tags"] == ["crypto"]


# ─── Finding 7: insight_index dirty flag survives failed autosave ────────────


def test_insight_index_dirty_retained_on_failed_autosave(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir")
    idx = InsightIndex(str(blocker / "idx.json"))
    idx._dirty = False
    idx._last_save = 0.0
    idx.index_function("0x401000", {"behavior_tags": ["crypto"]})
    # _mark_dirty fired an autosave that failed (parent is a file); the pending
    # change must be retained so the next autosave window retries it.
    assert idx._dirty is True


def test_insight_index_rebuilds_and_persists_metadata(tmp_path):
    path = tmp_path / "insight.json"
    idx = InsightIndex(str(path))
    idx.rebuild([
        ("0x401000", {"behavior_tags": ["crypto", "Network"], "name": "encrypt"}),
        ("0x402000", {"behavior_tags": ["parser"], "tier": "L2"}),
    ])
    assert len(idx) == 2
    assert idx.stats()["total_tags"] == 3
    assert "crypto" in idx.stats()["tag_histogram"]
    assert "InsightIndex" in repr(idx)
    assert idx.get_function("not-an-address") is None
    assert idx.get_function("0x401000")["name"] == "encrypt"
    idx.save()

    restored = InsightIndex(str(path))
    assert restored.get_function("401000")["tags"] == ["crypto", "Network"]
    assert restored.get_function("0x402000")["tier"] == "L2"


def test_insight_index_corrupt_persistence_is_preserved(tmp_path):
    path = tmp_path / "insight.json"
    path.write_text("{not-json", encoding="utf-8")
    idx = InsightIndex(str(path))
    assert len(idx) == 0
    assert not path.exists()
    assert path.with_name("insight.json.corrupt").read_text(encoding="utf-8") == "{not-json"
