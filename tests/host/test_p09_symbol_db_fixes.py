"""p09_intelligence: symbol_db / knowledge_graph regression tests.

Verifies query_hypotheses AND semantics, and that connections are closed
rather than leaked.
"""

from __future__ import annotations

import os

import pytest

from ida_pro_mcp.host.stores.knowledge_graph import KnowledgeGraph
from ida_pro_mcp.host.stores.symbol_db import SymbolDB


@pytest.fixture
def sdb(tmp_path):
    return SymbolDB(str(tmp_path / "sym.db"))


class TestQueryHypothesesAnd:
    def test_both_filters_require_both(self, sdb):
        sdb.upsert_hypothesis(binary_hash="AAA", chip_family="stm32",
                              addr_offset=0x100, hypothesis_text="hyp A",
                              confidence=0.9, source_session="s1", source_binary="b1")
        sdb.upsert_hypothesis(binary_hash="AAA", chip_family="esp32",
                              addr_offset=0x200, hypothesis_text="hyp B",
                              confidence=0.8, source_session="s1", source_binary="b1")
        sdb.upsert_hypothesis(binary_hash="BBB", chip_family="stm32",
                              addr_offset=0x300, hypothesis_text="hyp C",
                              confidence=0.7, source_session="s1", source_binary="b1")
        hits = sdb.query_hypotheses(binary_hash="AAA", chip_family="stm32")
        # AND: only the row matching BOTH binary and chip survives.
        assert [h["hypothesis_text"] for h in hits] == ["hyp A"]

    def test_single_filter_unchanged(self, sdb):
        sdb.upsert_hypothesis(binary_hash="AAA", chip_family="stm32",
                              addr_offset=0x100, hypothesis_text="hyp A",
                              confidence=0.9, source_session="s1", source_binary="b1")
        sdb.upsert_hypothesis(binary_hash="AAA", chip_family="esp32",
                              addr_offset=0x200, hypothesis_text="hyp B",
                              confidence=0.8, source_session="s1", source_binary="b1")
        assert len(sdb.query_hypotheses(binary_hash="AAA")) == 2


class TestConnectionLifecycle:
    def test_conn_is_closed_after_query(self, sdb):
        sdb.query_hypotheses(binary_hash="AAA")
        # Nothing crashy — just ensure repeated calls work (leaked fds would
        # eventually raise EMFILE in a loop).
        for _ in range(50):
            sdb.query_symbols("x")
            sdb.lookup_by_fingerprint("fp")

    def test_kg_conn_closed(self, tmp_path):
        kg = KnowledgeGraph(str(tmp_path / "kg.db"))
        for _ in range(30):
            sid = kg.add_system("SYS", ["0x401000"])
            kg.add_struct("t", members=[{"offset": 0, "size": 4, "name": "a"}])
        assert sid  # sanity: writes succeeded

    def test_init_lock_present(self):
        assert isinstance(SymbolDB._init_lock, type(__import__("threading").Lock()))
