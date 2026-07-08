"""Tests for the blackboard phase-gate injection behavior.

By default, the phase-gate machinery must NOT inject noise into tool
responses — it's there to steer LLM agents when explicitly enabled via
the ``IDA_MCP_PHASE_GATES`` env var or via the constructor.
"""

from __future__ import annotations

import pytest

from ida_pro_mcp.host.server.server_response import ServerResponseMixin


class _Server(ServerResponseMixin):
    """Stand-in host that exercises the injectors directly."""

    _phase_gates_enabled = False


class _ServerGatesOn(ServerResponseMixin):
    _phase_gates_enabled = True


def _stub_payload() -> dict:
    return {"ok": True, "session": {"session_id": "ABC123"}}


def test_phase_followup_no_op_when_gates_disabled():
    server = _Server()
    payload = _stub_payload()
    server._inject_blackboard_phase_followup(payload, "code")
    # No phase_gate noise should leak in.
    assert "blackboard_phase_gate" not in payload
    assert "must_call_before_answer" not in payload
    assert "required_followup_call" not in payload


def test_policy_followup_no_op_when_gates_disabled():
    server = _Server()
    payload = _stub_payload()
    server._inject_blackboard_policy_followup(payload, "code", {"action": "decompile"})
    assert "blackboard_policy_gate" not in payload
    assert "must_call_before_answer" not in payload
    assert "required_followup_call" not in payload


def test_blackboard_tool_never_gated():
    """Even when gates are enabled, the blackboard tool itself must remain
    ungated so calls to it don't loop or self-reference.
    """
    # We don't have a way to drive the full policy gate here without IDAPython,
    # so just assert the early-return guard by virtue of the implementation
    # contract: if a tool is named 'blackboard', the injectors are no-ops.
    server = _ServerGatesOn()
    payload = _stub_payload()
    server._inject_blackboard_phase_followup(payload, "blackboard")
    server._inject_blackboard_policy_followup(payload, "blackboard", {})
    assert payload == _stub_payload()
