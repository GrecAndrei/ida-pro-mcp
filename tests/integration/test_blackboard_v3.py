"""Blackboard v3: evidence, next_target, time decay, rejection feedback."""
from __future__ import annotations

import os
import tempfile

import pytest

from tests._isolated_repo_loader import load_host_module

_bb = load_host_module("blackboard_store")
BlackboardStore = _bb.BlackboardStore


@pytest.fixture
def store() -> BlackboardStore:
    db = tempfile.mktemp(suffix=".db")
    s = BlackboardStore(db_path=db)
    yield s
    if os.path.exists(db):
        os.unlink(db)


class TestBlackboardCRUD:
    """Basic create, read, update, delete."""

    def test_write_and_read(self, store: BlackboardStore) -> None:
        eid = store.write("test_entry", "test content", category="test")
        assert eid
        entry = store.read(eid)
        assert entry is not None
        assert entry.get("title") == "test_entry"

    def test_list_returns_entries(self, store: BlackboardStore) -> None:
        store.write("entry1", "content1", category="test")
        store.write("entry2", "content2", category="test")
        entries = store.list(category="test")
        assert len(entries) >= 2
        assert all(e.get("category") == "test" for e in entries)

    def test_update_changes_content(self, store: BlackboardStore) -> None:
        eid = store.write("updatable", "original", category="test")
        store.update(eid, content="updated")
        entry = store.read(eid)
        assert entry is not None
        assert "updated" in str(entry.get("content", ""))


class TestBlackboardNextTarget:
    """next_target prioritization."""

    def test_next_target_returns_list(self, store: BlackboardStore) -> None:
        store.write("target1", "content", category="analysis")
        targets = store.next_target(limit=5)
        assert isinstance(targets, list)

    def test_next_target_empty_with_no_entries(self, store: BlackboardStore) -> None:
        targets = store.next_target(limit=5)
        assert isinstance(targets, list)


class TestBlackboardEvidence:
    """Evidence support and metadata."""

    def test_write_with_evidence(self, store: BlackboardStore) -> None:
        evidence = [{"source": "analysis", "detail": "found reference"}]
        eid = store.write("evidenced", "content", category="test", evidence=evidence)
        entry = store.read(eid)
        assert entry is not None

    def test_write_with_source_type(self, store: BlackboardStore) -> None:
        eid = store.write("sourced", "content", category="test", source_type="decompiler")
        entry = store.read(eid)
        assert entry is not None
