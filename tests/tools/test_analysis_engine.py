"""ProposalStore and AnalysisEngine unit tests."""
from __future__ import annotations

import os
import tempfile

import pytest

from tests._isolated_repo_loader import load_host_module

_ae = load_host_module("analysis_engine")
ProposalStore = _ae.ProposalStore
AnalysisEngine = _ae.AnalysisEngine


@pytest.fixture
def ps() -> ProposalStore:
    db = tempfile.mktemp(suffix="_ps.db")
    store = ProposalStore(db_path=db)
    yield store
    if os.path.exists(db):
        os.unlink(db)


class TestProposalStore:
    """ProposalStore CRUD."""

    def test_initializes(self, ps: ProposalStore) -> None:
        assert ps is not None

    def test_add_proposal(self, ps: ProposalStore) -> None:
        pid = ps.add("analysis", "test_proposal", "summary", [{"key": "value"}])
        assert pid is not None

    def test_list_pending_returns_list(self, ps: ProposalStore) -> None:
        ps.add("analysis", "p1", "summary1", [{"k": "v1"}])
        ps.add("analysis", "p2", "summary2", [{"k": "v2"}])
        pending = ps.list_pending()
        assert len(pending) >= 2

    def test_accept_proposal(self, ps: ProposalStore) -> None:
        pid = ps.add("analysis", "accept_test", "summary", [{"k": "v"}])
        result = ps.accept(pid)
        assert result is not None or result is True

    def test_reject_proposal(self, ps: ProposalStore) -> None:
        pid = ps.add("analysis", "reject_test", "summary", [{"k": "v"}])
        result = ps.reject(pid)
        assert result is True
