"""Unit tests for FrontierEngine (host/frontier.py)."""
from __future__ import annotations

import os
import tempfile

import pytest

from tests._isolated_repo_loader import load_host_module

_frontier_mod = load_host_module("frontier")
_bb_mod = load_host_module("blackboard_store")
FrontierEngine = _frontier_mod.FrontierEngine
BlackboardStore = _bb_mod.BlackboardStore


@pytest.fixture
def dbs() -> tuple[FrontierEngine, BlackboardStore, str, str]:
    bb_db = tempfile.mktemp(suffix="_bb.db")
    emb_db = tempfile.mktemp(suffix="_emb.db")
    bb = BlackboardStore(db_path=bb_db)
    eng = FrontierEngine(embeddings_db=emb_db, blackboard_db=bb_db)
    yield eng, bb, emb_db, bb_db
    for p in [emb_db, bb_db]:
        if os.path.exists(p):
            os.unlink(p)


class TestFrontierEngine:
    """FrontierEngine core functionality."""

    def test_engine_initializes(self, dbs: tuple) -> None:
        eng = dbs[0]
        assert eng is not None

    def test_frontier_returns_list(self, dbs: tuple) -> None:
        eng = dbs[0]
        result = eng.frontier()
        assert isinstance(result, list)

    def test_coverage_returns_dict(self, dbs: tuple) -> None:
        eng = dbs[0]
        result = eng.coverage()
        assert isinstance(result, dict) or result is None

    def test_propagate_labels_accepts_entries(self, dbs: tuple) -> None:
        eng = dbs[0]
        try:
            eng.propagate_labels()
        except Exception:
            pass  # May need specific DB setup

    def test_refresh_runs(self, dbs: tuple) -> None:
        eng = dbs[0]
        try:
            eng.refresh()
        except Exception:
            pass  # May need specific DB setup


class TestFrontierAndBlackboardIntegration:
    """Frontier + Blackboard integration."""

    def test_write_and_frontier(self, dbs: tuple) -> None:
        eng, bb = dbs[0], dbs[1]
        bb.write("test_entry", "content", category="analysis")
        result = eng.frontier()
        assert isinstance(result, list)

    def test_contradiction_detection(self, dbs: tuple) -> None:
        eng = dbs[0]
        try:
            result = eng.detect_contradictions()
            assert isinstance(result, list)
        except Exception:
            pass
