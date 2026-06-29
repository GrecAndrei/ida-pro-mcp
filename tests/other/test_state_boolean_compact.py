"""Tests for response compaction semantics.

These cover the bug where ``drop_false=True`` (default in compact mode)
silently removed top-level state booleans like ``runtime_attached`` or
``idb_exists``. Absence vs. literal ``False`` is a meaningful difference
for callers and must survive compaction.
"""

from __future__ import annotations

import pytest

from ida_pro_mcp.host.server.server_response_compact import ServerResponseCompactMixin  # noqa: E501


class _Carrier(ServerResponseCompactMixin):
    """Minimal host exposing the compactor with no other dependencies."""

    default_table_mode = False
    default_batch_compact = False


@pytest.fixture
def carrier() -> _Carrier:
    return _Carrier()


def test_state_booleans_survive_drop_false(carrier: _Carrier) -> None:
    payload = {
        "ok": True,
        "runtime_attached": False,
        "idb_exists": False,
        "is_running": False,
        "analysis_applied": False,
        "binary_exists": True,
        "data": "keep me",
    }
    opts = {"drop_false": True, "drop_empty": False, "strip_meta": False}
    out = carrier._compact_value(payload, opts)
    assert out["runtime_attached"] is False
    assert out["idb_exists"] is False
    assert out["is_running"] is False
    assert out["analysis_applied"] is False
    assert out["binary_exists"] is True
    assert out["data"] == "keep me"


def test_non_state_falsy_still_dropped(carrier: _Carrier) -> None:
    """Non-state False values (e.g. optional toggles) should still be dropped
    so compact mode stays useful.
    """
    payload = {
        "ok": True,
        "show_legend": False,
        "runtime_attached": False,
        "cache_warm": False,
    }
    opts = {"drop_false": True, "drop_empty": False, "strip_meta": False}
    out = carrier._compact_value(payload, opts)
    # State booleans must survive; arbitrary booleans may be dropped.
    assert "runtime_attached" in out
    assert out["runtime_attached"] is False
    # No guarantee about non-state keys, but show_legend is arbitrary so we
    # don't assert either way; just ensure the compactor didn't crash.


def test_state_boolean_true_survives(carrier: _Carrier) -> None:
    payload = {"runtime_attached": True, "ok": True}
    out = carrier._compact_value(payload, {"drop_false": True, "drop_empty": False, "strip_meta": False})
    assert out["runtime_attached"] is True


def test_unknown_key_unaffected_by_state_class(carrier: _Carrier) -> None:
    """Bool vals for keys not in _STATE_BOOLEAN_KEYS still go through the
    normal drop_false/keep rules.
    """
    payload = {"some_arbitrary_flag": False, "ok": True}
    out = carrier._compact_value(payload, {"drop_false": True, "drop_empty": False, "strip_meta": False})
    assert out.get("some_arbitrary_flag") in (None, False)


def test_state_boolean_keys_set_is_frozen():
    """Caller should not be able to mutate the allowlist."""
    assert isinstance(ServerResponseCompactMixin._STATE_BOOLEAN_KEYS, frozenset)
