"""Unit tests for the canonical preference memory bank and multi-hop bridge retrieval.

The legacy `ida_mcp.tools.memrl` module (the legacy bank class and its
MCP tool wrapper) was a duplicate of the canonical
`PreferenceMemoryBank` in
`ida_pro_mcp.host.intelligence_preference_store`. The duplicate was
removed; these tests now exercise the canonical bank.

The bridge-conditioned multi-hop retrieval engine now lives in
`ida_pro_mcp.host.intelligence_bridge_retrieval` as
`MultiHopBridgeIndex`. The thin MCP tool wrapper in
`ida_mcp.tools.bridge_search` exposes the same `bridge_search` action surface
to LLM clients.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

# Load bridge_search.py from tools/ (it is the one surviving tool, no host
# equivalent). We use spec_from_file_location to bypass the package's
# `__init__.py` which pulls in zeromcp.
_base = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "src",
    "ida_pro_mcp",
    "ida_mcp",
    "tools",
)


def _load_bridge_search():
    path = os.path.join(_base, "bridge_search.py")
    spec = importlib.util.spec_from_file_location("bridge_search", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bridge_search"] = mod
    spec.loader.exec_module(mod)
    return mod


_bridge_search = _load_bridge_search()
bridge_search = _bridge_search.bridge_search


# ---------------------------------------------------------------------------
# PreferenceMemoryBank — the canonical MemRL backend
# ---------------------------------------------------------------------------

from ida_pro_mcp.host.intelligence_preference_store import (
    DEFAULT_ALPHA,
    PreferenceMemoryBank,
    Q_CEILING,
    Q_FLOOR,
    REWARD_ACCEPT,
    REWARD_PARTIAL,
    REWARD_REJECT,
    REWARD_DANGEROUS,
    REWARD_NEUTRAL,
)


class TestPreferenceMemoryBank:
    """Tests migrated from the legacy MemRLBank (tools/memrl.py).
    Same math, same SQLite schema, canonical implementation."""

    def test_record_and_get_q(self, tmp_path):
        db = os.path.join(tmp_path, "memrl_test.db")
        bank = PreferenceMemoryBank(db_path=db)
        bank.record("intent_a", "exp_1", initial_q=0.5)
        assert bank.get_q("intent_a", "exp_1") == pytest.approx(0.5, abs=0.01)

    def test_td_update(self, tmp_path):
        db = os.path.join(tmp_path, "memrl_test.db")
        bank = PreferenceMemoryBank(db_path=db)
        bank.record("intent_a", "exp_1", initial_q=0.5)
        new_q = bank.update_q("intent_a", "exp_1", reward=1.0, alpha=0.2)
        # Q_new = 0.5 + 0.2 * (1.0 - 0.5) = 0.6
        assert new_q == pytest.approx(0.6, abs=0.01)
        assert bank.get_q("intent_a", "exp_1") == pytest.approx(0.6, abs=0.01)

    def test_negative_reward(self, tmp_path):
        db = os.path.join(tmp_path, "memrl_test.db")
        bank = PreferenceMemoryBank(db_path=db)
        bank.record("intent_a", "exp_1", initial_q=0.5)
        new_q = bank.update_q("intent_a", "exp_1", reward=-1.0, alpha=0.2)
        # Q_new = 0.5 + 0.2 * (-1.0 - 0.5) = 0.5 - 0.3 = 0.2
        assert new_q == pytest.approx(0.2, abs=0.01)

    def test_two_phase_rank_uses_q_over_sim(self, tmp_path):
        """The TD(0) two-phase retriever must rank candidates by a
        weighted blend of similarity and Q-value, not by pure
        similarity."""
        db = os.path.join(tmp_path, "memrl_test.db")
        bank = PreferenceMemoryBank(db_path=db)
        # Seed Q-values: exp_1 low utility, exp_2 high utility.
        bank.record("intent_q", "exp_1", initial_q=0.2)
        bank.record("intent_q", "exp_2", initial_q=0.9)

        # exp_1 has HIGHER similarity (0.95) but LOWER Q (0.2).
        # exp_2 has lower similarity (0.80) but HIGHER Q (0.9).
        pool = [
            {"ea": "exp_1", "score": 0.95},
            {"ea": "exp_2", "score": 0.80},
        ]
        ranked = bank.two_phase_retrieve(
            "intent_q", pool, top_k=2, lambda_explore=0.8
        )
        # With λ=0.8 (Q-weighted), exp_2 must outrank exp_1 despite
        # the lower similarity score.
        assert ranked[0]["ea"] == "exp_2"
        assert ranked[1]["ea"] == "exp_1"
        # Each result must carry the merged Q + composite score.
        for r in ranked:
            assert "q_value" in r
            assert "memrl_score" in r

    def test_stats_counts_triplets(self, tmp_path):
        db = os.path.join(tmp_path, "memrl_test.db")
        bank = PreferenceMemoryBank(db_path=db)
        bank.record("i1", "e1")
        bank.record("i2", "e2")
        s = bank.stats()
        assert s["total_triplets"] == 2
        assert s["avg_q_value"] > 0


class TestPreferenceMemoryBankConstants:
    """The reward constants must match the values documented in
        intelligence_preference_store.py and the function callers
    (modify.py uses REWARD_ACCEPT/PARTIAL/REJECT)."""

    def test_reward_constants(self):
        assert REWARD_ACCEPT == 1.0
        assert REWARD_PARTIAL == 0.5
        assert REWARD_NEUTRAL == 0.0
        assert REWARD_REJECT == -0.5
        assert REWARD_DANGEROUS == -1.0

    def test_q_bounds(self):
        assert Q_FLOOR == -1.0
        assert Q_CEILING == 1.0

    def test_default_alpha_in_unit_range(self):
        assert 0.0 < DEFAULT_ALPHA <= 1.0


class TestEmitPreferenceSuggestion:
    """emit_preference_suggestion is the canonical entry point used by
    modify.py / annotation.py / firmware_view.py / data_ops.py after
    a successful tool action. It must round-trip via PreferenceMemoryBank."""

    def test_emit_returns_suggestion_id(self, tmp_path):
        from ida_pro_mcp.host.intelligence_core import emit_preference_suggestion

        db = os.path.join(tmp_path, "memrl_emit.db")
        sid = emit_preference_suggestion(
            source_tool="modify",
            source_action="rename",
            addr="0x401000",
            value="my_function",
            db_path=db,
        )
        assert isinstance(sid, str)
        assert len(sid) > 0


# ---------------------------------------------------------------------------
# BridgeSearch — kept as-is
# ---------------------------------------------------------------------------


class TestBridgeSearch:
    def test_extract_bridges_requires_db(self, tmp_path):
        # The multi-hop bridge index requires a schemaboot DB; test with empty/nonexistent
        from ida_pro_mcp.host.intelligence_bridge_retrieval import MultiHopBridgeIndex
        db = os.path.join(tmp_path, "nonexistent.db")
        engine = MultiHopBridgeIndex(db_path=db)
        # Should return empty bridges without crashing
        bridges = engine.extract_bridges(func_ea=0x401000)
        assert bridges == {}

    def test_bridge_search_tool_unknown_action(self):
        result = bridge_search(action="unknown")
        assert result["ok"] is False

    def test_bridge_search_bridges_action_missing_params(self):
        result = bridge_search(action="bridges")
        assert result["ok"] is True
        assert result["bridges"] == {}
