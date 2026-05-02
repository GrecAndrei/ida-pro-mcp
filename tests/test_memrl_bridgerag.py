"""Unit tests for MemRL and BridgeRAG."""

import os
import sys
import importlib.util

# Bypass ida_pro_mcp package imports
_base = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src", "ida_pro_mcp", "ida_mcp", "tools")

for mod_name, file_name in (("memrl", "memrl.py"), ("bridgerag", "bridgerag.py")):
    path = os.path.join(_base, file_name)
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)

import pytest
from memrl import MemRLBank, memrl
from bridgerag import BridgeRAGSearch, bridgerag


class TestMemRLBank:
    def test_record_and_get_q(self, tmp_path):
        db = os.path.join(tmp_path, "memrl_test.db")
        bank = MemRLBank(db_path=db)
        bank.record("intent_a", "exp_1", initial_q=0.5)
        assert bank.get_q("intent_a", "exp_1") == pytest.approx(0.5, abs=0.01)

    def test_td_update(self, tmp_path):
        db = os.path.join(tmp_path, "memrl_test.db")
        bank = MemRLBank(db_path=db)
        bank.record("intent_a", "exp_1", initial_q=0.5)
        new_q = bank.update_q("intent_a", "exp_1", reward=1.0, alpha=0.2)
        assert new_q == pytest.approx(0.6, abs=0.01)
        assert bank.get_q("intent_a", "exp_1") == pytest.approx(0.6, abs=0.01)

    def test_negative_reward(self, tmp_path):
        db = os.path.join(tmp_path, "memrl_test.db")
        bank = MemRLBank(db_path=db)
        bank.record("intent_a", "exp_1", initial_q=0.5)
        new_q = bank.update_q("intent_a", "exp_1", reward=-1.0, alpha=0.2)
        # Q_new = 0.5 + 0.2 * (-1.0 - 0.5) = 0.5 - 0.3 = 0.2
        assert new_q == pytest.approx(0.2, abs=0.01)

    def test_two_phase_rank(self, tmp_path):
        db = os.path.join(tmp_path, "memrl_test.db")
        bank = MemRLBank(db_path=db)
        # Seed Q-values: exp_1 low utility, exp_2 high utility
        bank.record("intent_q", "exp_1", initial_q=0.2)
        bank.record("intent_q", "exp_2", initial_q=0.9)

        pool = [
            {"name": "exp_1", "score": 0.95},
            {"name": "exp_2", "score": 0.80},
        ]
        ranked = bank.two_phase_retrieve("intent_q", pool, top_k=2, lambda_explore=0.5)
        # With λ=0.5, exp_2 should outrank exp_1 despite lower similarity
        assert ranked[0]["name"] == "exp_2"
        assert ranked[1]["name"] == "exp_1"

    def test_stats(self, tmp_path):
        db = os.path.join(tmp_path, "memrl_test.db")
        bank = MemRLBank(db_path=db)
        bank.record("i1", "e1")
        bank.record("i2", "e2")
        s = bank.stats()
        assert s["total_triplets"] == 2
        assert s["avg_q_value"] > 0


class TestMemRLToolInterface:
    def test_record_update_rank_cycle(self, tmp_path):
        db = os.path.join(tmp_path, "memrl_tool.db")
        r1 = memrl(action="record", intent_key="q1", experience_key="f_401000", db_path=db)
        assert r1["ok"] is True

        r2 = memrl(action="update", intent_key="q1", experience_key="f_401000", reward=1.0, db_path=db)
        assert r2["ok"] is True
        # Q_new = 0.5 + 0.15 * (1.0 - 0.5) = 0.575
        assert r2["new_q"] == pytest.approx(0.575, abs=0.01)

        r3 = memrl(action="get_q", intent_key="q1", experience_key="f_401000", db_path=db)
        assert r3["q_value"] == pytest.approx(0.575, abs=0.01)

        pool = [{"ea": "f_401000", "score": 0.9}, {"ea": "f_402000", "score": 0.8}]
        r4 = memrl(action="rank", intent_key="q1", candidate_pool=pool, lambda_explore=0.5, db_path=db)
        assert r4["ok"] is True
        assert len(r4["ranked"]) == 2


class TestBridgeRAG:
    def test_extract_bridges_requires_db(self, tmp_path):
        # BridgeRAG requires a schemaboot DB; test with empty/nonexistent
        db = os.path.join(tmp_path, "nonexistent.db")
        engine = BridgeRAGSearch(db_path=db)
        # Should return empty bridges without crashing
        bridges = engine.extract_bridges(func_ea=0x401000)
        assert bridges == {}

    def test_bridgerag_tool_unknown_action(self):
        result = bridgerag(action="unknown")
        assert result["ok"] is False

    def test_bridgerag_bridges_action_missing_params(self):
        result = bridgerag(action="bridges")
        assert result["ok"] is True
        assert result["bridges"] == {}
