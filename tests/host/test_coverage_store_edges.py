"""Boundary coverage for the small persistent host stores."""

from __future__ import annotations

import json
import sqlite3

import pytest

from ida_pro_mcp.host.stores.insight_index import InsightIndex
from ida_pro_mcp.host.stores.knowledge_graph import KnowledgeGraph
from ida_pro_mcp.host.stores.symbol_db import SymbolDB


def test_knowledge_graph_missing_rows_and_adaptive_matching(tmp_path):
    graph = KnowledgeGraph(str(tmp_path / "kg.db"))
    assert graph.update_system("missing", name="still missing") is False
    assert graph.update_system("missing", unsupported=True) is False
    assert graph.get_system("missing") is None
    assert graph.add_member_to_system("missing", "0x1") is False
    assert graph.record_struct_access("missing", "0x1", "read", 0) is False
    assert graph.get_struct("missing") is None
    assert graph.add_transition("missing", 0, 1, "0x1") is False
    assert graph.get_state_machine("missing") is None
    assert graph.fill_gap("missing", "0x1") is False
    assert graph.add_gap_candidate("missing", "0x1") is False
    assert graph.update_attack_surface("missing", name="x") is False

    first = graph.add_system("first", ["0x1"])
    assert graph.add_member_to_system(first, "0x1") is True
    assert graph.add_member_to_system(first, "0x2") is True
    assert graph.find_system_for_addr("0x2")["id"] == first
    assert graph.find_system_for_addr("0x99") is None
    assert graph.update_system(first, unknown=True) is False

    graph.add_struct("one", members=[{"offset": 0}])
    graph.add_struct("two", members=[{"offset": 0, "size": 4}, {"offset": 1}])
    graph.add_struct("three", members=[
        {"offset": 0}, {"offset": 1}, {"offset": 5},
    ])
    assert graph.find_struct_by_offset_pattern([]) is None
    assert graph.find_struct_by_offset_pattern([0], threshold=1.1) is None
    assert graph.find_struct_by_offset_pattern([0], threshold=0.5) is not None
    adaptive = graph.find_struct_by_offset_pattern([0, 1, 2, 3, 4])
    assert adaptive is not None

    with pytest.raises(RuntimeError), graph._immediate_tx() as conn:
        conn.execute("SELECT 1")
        raise RuntimeError("rollback")


def test_knowledge_graph_state_gap_attack_and_peripheral_updates(tmp_path):
    graph = KnowledgeGraph(str(tmp_path / "kg.db"))
    sm_id = graph.add_state_machine("states", "0x10")
    assert graph.add_transition(sm_id, 0, 1, "0x20") is True
    assert graph.list_state_machines()[0]["transitions"]

    gap_id = graph.add_gap("missing parser", hints=["packet", "length"])
    assert graph.add_gap_candidate(gap_id, "0x30") is True
    assert graph.add_gap_candidate(gap_id, "0x30") is True
    assert graph.fill_gap(gap_id, "0x30") is True
    assert graph.list_gaps(resolved=True)[0]["candidates"] == ["0x30"]

    attack_id = graph.add_attack_surface("0x40", call_stack=["0x41"])
    assert graph.update_attack_surface(
        attack_id,
        name="parser",
        call_stack=["0x41", "0x42"],
        known_vulns=["finding-1"],
        max_input_size=128,
    ) is True
    assert graph.list_attack_surface()[0]["known_vulns"] == ["finding-1"]

    peripheral_id = graph.add_peripheral("0x4000", drivers=["0x50"])
    assert graph.add_peripheral("0x4000", name="duplicate") == peripheral_id
    assert graph.record_peripheral_access("0x4000", "0x51", 4) == peripheral_id
    assert graph.record_peripheral_access("0x4000", "0x51", 4) == peripheral_id
    assert graph.list_peripherals()[0]["drivers"] == ["0x50", "0x51"]
    assert graph.summary()["gaps_filled"] == 1


def test_insight_index_reindex_persistence_and_corrupt_recovery(tmp_path, monkeypatch):
    path = tmp_path / "insight.json"
    index = InsightIndex(str(path))
    index.index_function("401000", {"behavior_tags": ["Crypto", "network"], "name": "send"})
    index.index_function("0x401000", {"behavior_tags": ["parser"]})
    assert index.get_function("0x401000")["tags"] == ["parser"]
    assert index.get_function("missing") is None
    index.rebuild([])
    assert len(index) == 0
    index.save()
    assert json.loads(path.read_text())["func_map"] == {}
    InsightIndex().save()

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("not json")
    recovered = InsightIndex(str(corrupt))
    assert len(recovered) == 0
    assert not corrupt.exists()
    assert (tmp_path / "corrupt.json.corrupt").exists()

    broken = InsightIndex(str(tmp_path / "broken.json"))
    monkeypatch.setattr("ida_pro_mcp.host.stores.insight_index.os.replace", lambda *_args: (_ for _ in ()).throw(OSError("no replace")))
    broken.index_function("0x1", {"behavior_tags": ["crypto"]})
    assert broken._dirty is True


def test_symbol_db_upsert_race_merges_existing_row(tmp_path, monkeypatch):
    db = SymbolDB(str(tmp_path / "symbols.db"))

    class _Result:
        rowcount = 1
        lastrowid = 0

    class _RaceConnection:
        def __init__(self):
            self.selects = 0

        def execute(self, sql, _params=()):
            if sql.lstrip().startswith("SELECT id"):
                self.selects += 1
                if self.selects == 1:
                    return _ResultWithFetchone(None)
                return _ResultWithFetchone((7,))
            if "INSERT INTO symbols" in sql:
                raise sqlite3.IntegrityError("racing writer")
            return _Result()

        def commit(self):
            pass

        def close(self):
            pass

    class _ResultWithFetchone:
        def __init__(self, value):
            self.value = value

        def fetchone(self):
            return self.value

    race = _RaceConnection()
    monkeypatch.setattr(db, "_conn", lambda: race)
    assert db.upsert_symbol({"symbol_name": "memcpy", "fingerprint": "fp"}) == 7
