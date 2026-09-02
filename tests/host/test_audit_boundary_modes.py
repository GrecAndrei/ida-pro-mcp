"""Boundary coverage for the best-effort audit logger."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from ida_pro_mcp.host.server import audit as audit_mod
from ida_pro_mcp.host.server.audit import AuditLogger


def test_audit_value_helpers_are_bounded_and_failure_proof(monkeypatch):
    class BadRepr:
        def __repr__(self):
            raise RuntimeError("repr failed")

    assert audit_mod._shallow({"a": {"b": {"c": {"d": 1}}}})["a"]["b"]["c"] == "<truncated>"
    assert audit_mod._shallow({i: i for i in range(3)}, max_items=2) == {
        "0": 0,
        "1": 1,
        "<+1>": True,
    }
    assert audit_mod._shallow([1, 2, 3], max_items=2) == [1, 2, "<+1>"]
    assert audit_mod._shallow(b"x" * 200) == ("78" * 64)
    assert audit_mod._shallow(BadRepr()) == "<unrepr>"
    assert audit_mod._bounded_result_size(None) == 0
    assert audit_mod._bounded_result_size("text") == 4
    assert audit_mod._bounded_result_size(b"text") == 4

    monkeypatch.setattr(
        audit_mod.json,
        "dumps",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TypeError("cannot encode")),
    )
    assert audit_mod._bounded_result_size({"bad": object()}) == 0
    monkeypatch.setattr(
        audit_mod,
        "_shallow",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("hash failed")),
    )
    assert audit_mod._canonical_args_hash({"x": 1}) == "<unhashable>"


def test_audit_file_rotation_pruning_and_close_errors_are_swallowed(tmp_path, monkeypatch):
    logger = AuditLogger(str(tmp_path), max_mb=1)

    class OldFile:
        def close(self):
            raise OSError("already closed")

    logger._file = OldFile()
    logger._current_path = "old"
    opened = logger._open_for_date(datetime(2026, 9, 2, tzinfo=UTC))
    assert opened is logger._file
    logger.close()

    old_month = tmp_path / "2000-01"
    old_month.mkdir()
    old_file = old_month / "audit_2000-01-01.jsonl"
    old_file.write_text("old", encoding="utf-8")
    logger.max_bytes = 1
    logger._maybe_prune_old()
    assert not old_month.exists()

    # A filesystem failure in the prune walk must never escape into a tool
    # response, even when the logger is already over its cap.
    monkeypatch.setattr(audit_mod.os, "walk", lambda *_args: (_ for _ in ()).throw(OSError("walk failed")))
    logger._maybe_prune_old()


def test_audit_log_flushes_redacts_empty_previews_and_prunes(tmp_path, monkeypatch):
    logger = AuditLogger(str(tmp_path), max_mb=1)
    monkeypatch.setattr(audit_mod.time, "monotonic", lambda: 2.0)
    pruned = []
    logger._maybe_prune_old = lambda: pruned.append(True)

    logger.log(
        tool="session",
        action="status",
        args={"idb": "/private/database.i64", "code": "secret"},
        result={"ok": True},
        latency_ms=1.25,
    )
    logger.close()
    record = json.loads(next(tmp_path.rglob("*.jsonl")).read_text())
    assert "args_preview" not in record
    assert "/private/database.i64" not in json.dumps(record)

    logger = AuditLogger(str(tmp_path / "second"), max_mb=1)
    logger._maybe_prune_old = lambda: pruned.append(True)
    logger._total_written = 1024 * 1024
    logger.log(
        tool="search",
        action="find",
        args={"query": "needle"},
        result={"ok": True},
        latency_ms=0,
    )
    logger.close()
    assert pruned == [True]


@pytest.mark.parametrize("bad_value", [object(), {1: "one", "two": 2}])
def test_audit_log_handles_unusual_argument_shapes(tmp_path, bad_value):
    logger = AuditLogger(str(tmp_path), max_mb=1)
    logger.log(
        tool="search",
        action="find",
        args=bad_value,
        result=object(),
        latency_ms=0,
    )
    logger.close()
    assert list(tmp_path.rglob("*.jsonl"))
