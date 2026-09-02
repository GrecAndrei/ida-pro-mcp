from __future__ import annotations

from ida_pro_mcp.host.server.server_blackboard_phase import (
    _FUNCS_WRITE_ACTIONS,
    ServerBlackboardPhaseMixin,
    _strip_durable,
)


def test_strip_durable_helper() -> None:
    data = {
        "phase": "scout",
        "turn": 3,
        "_durable_ns": "phase",
        "_durable_key": "SESS-1",
    }
    stripped = _strip_durable(data)
    assert stripped == {"phase": "scout", "turn": 3}


def test_funcs_write_actions() -> None:
    assert "create" in _FUNCS_WRITE_ACTIONS
    assert "delete" in _FUNCS_WRITE_ACTIONS
    assert "change" in _FUNCS_WRITE_ACTIONS
    assert "set_flags" in _FUNCS_WRITE_ACTIONS
    assert "list" not in _FUNCS_WRITE_ACTIONS


def test_phase_state_keys() -> None:
    mixin = ServerBlackboardPhaseMixin()
    # Explicit session id
    assert mixin._bb_state_key("session_123") == "SESSION_123"
    # No session
    assert mixin._bb_state_key(None) == ""
