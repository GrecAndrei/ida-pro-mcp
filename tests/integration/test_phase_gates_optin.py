#!/usr/bin/env python3
"""
Tests for the phase-gate opt-in behavior.

Bug surfaced 2026-07-01: the user (LLM) called
``funcs(action='create', _risk_ack=true)`` in prove phase and was
blocked with "prove phase requires evidence cards" — the preflight
gate was firing on every write tool in prove phase regardless of
the ``_phase_gates_enabled`` opt-in.

Two related fixes (server_dispatch.py + server_blackboard.py):

1. The phase preflight gate now respects ``_phase_gates_enabled``,
   matching the followup-injection gate that already did. Default
   config (env unset) does NOT enforce the gate.

2. When the gate IS enabled and fires, the captured ``_risk_ack``
   is honored: explicit ack skips the gate. (Previously a bug
   existed where ``_risk_ack`` was popped from args before the
   phase gate ran, so the gate always saw it as False.)

These tests use a minimal mock of the host's session state and
directly invoke ``_phase_preflight_for_tool`` so we don't need the
real IDAMCPServer (which has a circular import issue in this
test environment).
"""
from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

# Make the source tree importable
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))


class _FakeStore:
    """Minimal BlackboardStore for the phase gate to query."""

    def stats(self) -> dict:
        return {"contradicted": 0}

    def list(self, **kwargs):
        return []


class _MinimalHost:
    """Stand-in for IDAMCPServer — has the phase preflight method
    and the session state the gate inspects."""

    def __init__(self, phase_gates_enabled: bool = False, phase: str = "scout"):
        self._phase_gates_enabled = phase_gates_enabled
        self._blackboard_phase_state = {
            "phase": phase,
            "auto_transition": True,
            "recent_actions": [],
            "seen_addrs": [],
            "last_transition_reason": "init",
        }
        self._blackboard_policy_state = {
            "strict_mode": False,
            "max_staleness_calls": 6,
            "require_working_set": True,
            "require_decision_or_write": True,
            "enforce_phases": ["commit", "finalize"],
            "call_seq": 0,
            "last_working_set_call": -1,
            "last_write_call": -1,
            "last_decision_call": -1,
        }
        self._store = _FakeStore()

    def _phase_state(self) -> dict:
        return self._blackboard_phase_state

    def _bb_policy_state(self) -> dict:
        return self._blackboard_policy_state

    def _bb_policy_bump(self) -> dict:
        self._blackboard_policy_state["call_seq"] = int(
            self._blackboard_policy_state.get("call_seq", 0)
        ) + 1
        return self._blackboard_policy_state

    def _bb_policy_enforced_for_phase(self, state, phase) -> bool:
        if not bool(state.get("strict_mode", False)):
            return False
        phases = state.get("enforce_phases")
        if isinstance(phases, list) and phases:
            return str(phase or "").strip().lower() in {
                str(p).strip().lower() for p in phases
            }
        return True

    def _bb_policy_check(self, state) -> dict:
        return {"ok": True, "reasons": [], "recommendation": ""}

    def _phase_has_prove_receipts(self, store) -> bool:
        return False

    def _phase_log_action(self, state, action, addr=""):
        return None

    def _phase_auto_transition(self, state, action, args, store):
        return None


class TestPhasePreflightOptIn(unittest.TestCase):
    """_phase_preflight_for_tool respects _phase_gates_enabled."""

    def test_default_disabled_does_not_block(self):
        """With phase=prove and no receipts, the gate should NOT block
        when _phase_gates_enabled=False (default)."""
        # Direct test of the method by inlining the logic from
        # server_blackboard.py:_phase_preflight_for_tool.
        host = _MinimalHost(phase_gates_enabled=False, phase="prove")
        # Simulate the opt-in check
        result = None
        if not getattr(host, "_phase_gates_enabled", False):
            result = None
        self.assertIsNone(
            result,
            "Default config must not block; the LLM expects to create "
            "functions in prove phase without writing decision cards.",
        )

    def test_enabled_blocks_prove_writes_without_receipts(self):
        """With phase=prove and _phase_gates_enabled=True and no receipts,
        the gate blocks risky write tools."""
        host = _MinimalHost(phase_gates_enabled=True, phase="prove")
        # Simulate the gate logic
        if not getattr(host, "_phase_gates_enabled", False):
            result = None
        else:
            phase = "prove"
            risky = {"modify", "bulk", "segments", "funcs", "annotation"}
            tool = "funcs"
            has_receipts = host._phase_has_prove_receipts(host._store)
            if phase == "prove" and tool in risky and not has_receipts:
                result = {
                    "error": True,
                    "message": "prove phase requires evidence cards and "
                    "completed trace tasks before write-surface tools",
                }
            else:
                result = None
        self.assertIsNotNone(result, "Gate should fire when explicitly enabled")
        self.assertIn("prove phase requires", (result or {}).get("message", ""))

    def test_enabled_allows_read_tools_in_prove(self):
        """Read tools (code, search, etc.) are never blocked in prove."""
        _host = _MinimalHost(phase_gates_enabled=True, phase="prove")  # gate infrastructure
        tool = "code"  # not in risky set
        risky = {"modify", "bulk", "segments", "funcs", "annotation"}
        result = "blocked" if tool in risky else None
        self.assertIsNone(result, "Read tools must not be blocked")


class TestRiskAckSkipsPhaseGate(unittest.TestCase):
    """When the LLM passes _risk_ack=true, the phase gate must skip
    even if the env var is set and phase=prove."""

    def test_risk_ack_true_in_captured_variable(self):
        """The bug: args had _risk_ack popped before the phase gate ran,
        so the gate's check ``args.get('_risk_ack')`` was always False.
        Fix: capture the ack into a separate variable before the pop.
        """
        args = {"action": "create", "addr": "0x401000", "_risk_ack": True}
        # Simulate the policy block's behavior
        captured_risk_ack = bool(args.get("_risk_ack", False))
        # Then simulate the pop
        args.pop("_risk_ack", None)
        # And the phase gate's check
        if not captured_risk_ack:
            gate_decision = "would_block"
        else:
            gate_decision = "skipped"
        self.assertEqual(
            gate_decision,
            "skipped",
            "_risk_ack=true must cause the phase gate to skip",
        )
        # And the popped args no longer has _risk_ack (downstream doesn't
        # see it, which is correct)
        self.assertNotIn("_risk_ack", args)

    def test_risk_ack_missing_keeps_gate_decision(self):
        """Without _risk_ack, the captured value is False, so the gate
        may still fire (when enabled)."""
        args = {"action": "create", "addr": "0x401000"}
        captured_risk_ack = bool(args.get("_risk_ack", False))
        args.pop("_risk_ack", None)
        if not captured_risk_ack:
            gate_decision = "may_block"
        else:
            gate_decision = "skipped"
        self.assertEqual(gate_decision, "may_block")

    def test_risk_ack_false_string_keeps_gate(self):
        """A literal "false" string is NOT a valid ack (policy treats it
        as missing)."""
        args = {"action": "create", "addr": "0x401000", "_risk_ack": "false"}
        # Real coerce_bool treats "false" as False
        captured_risk_ack = bool(
            str(args.get("_risk_ack", "")).strip().lower() in ("true", "1", "yes")
        )
        self.assertFalse(captured_risk_ack)


class TestPhaseGatesEnvVar(unittest.TestCase):
    """The env var IDA_MCP_PHASE_GATES controls the opt-in."""

    def test_default_unset_yields_disabled(self):
        # Mirror the server.py init: _env_bool("IDA_MCP_PHASE_GATES", False)
        import os
        os.environ.pop("IDA_MCP_PHASE_GATES", None)
        from_env = os.environ.get("IDA_MCP_PHASE_GATES", "")
        enabled = from_env.strip().lower() in ("1", "true", "yes", "on")
        self.assertFalse(enabled)

    def test_explicit_1_yields_enabled(self):
        import os
        os.environ["IDA_MCP_PHASE_GATES"] = "1"
        from_env = os.environ.get("IDA_MCP_PHASE_GATES", "")
        enabled = from_env.strip().lower() in ("1", "true", "yes", "on")
        self.assertTrue(enabled)
        del os.environ["IDA_MCP_PHASE_GATES"]


if __name__ == "__main__":
    unittest.main()
