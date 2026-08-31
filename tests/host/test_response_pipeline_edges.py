"""Behavioral tests for response guardrails and universal output filters."""

from __future__ import annotations

from ida_pro_mcp.host.server.server_response import ServerResponseMixin


def _host(**attrs):
    host = ServerResponseMixin.__new__(ServerResponseMixin)
    for key, value in attrs.items():
        setattr(host, key, value)
    return host


def test_pointer_signal_scoring_distinguishes_empty_text_math_and_addresses():
    host = _host()
    assert host._pointer_note_signal_from_text("") == 0.0
    assert host._pointer_note_signal_from_text("   ") == 0.0
    assert host._pointer_note_signal_from_text("hello") == 0.0
    assert host._pointer_note_signal_from_text("address 0x401000 + 0x20") >= 4.0
    assert host._pointer_note_signal_from_text("0x1000 0x2000") >= 2.0


def test_pointer_signal_walks_bounded_nested_values_and_caps_total():
    host = _host()
    nested = {"pointer": [0x4000, {"target": "0x401000"}]}
    assert host._pointer_note_signal_from_value(nested) > 0
    assert host._pointer_note_signal_from_value({"deep": {"a": {"b": {"addr": "0x4000"}}}}) == 0.0
    signal = host._compute_pointer_note_signal(
        "calc",
        {"_internal": "0x9999", "address": "0x401000", "query": "ptr + 0x10"},
        {"items": [{"ea": "0x402000"}], "address": "0x403000"},
    )
    assert 0 < signal <= 10.0


def test_pointer_note_gate_accumulates_threshold_and_suppresses_errors_or_throttled_notes(monkeypatch):
    host = _host(
        _pointer_note_min_signal=3.0,
        _pointer_note_pending_signal=0.0,
        _pointer_note_last_shown_at=0.0,
        _pointer_note_interval_seconds=900,
    )
    monkeypatch.setattr("ida_pro_mcp.host.server.server_response.time.time", lambda: 100.0)
    assert host._should_include_pointer_note("search", {"query": "0x401000"}, {}) is False
    assert host._pointer_note_pending_signal > 0
    assert host._should_include_pointer_note("calc", {"addr": "0x401000 + 0x20"}, {}) is True
    assert host._pointer_note_pending_signal == 0.0
    assert host._should_include_pointer_note("calc", {"addr": "0x401000 + 0x20"}, {"error": True}) is False

    host._pointer_note_last_shown_at = 100.0
    host._pointer_note_pending_signal = 0.0
    assert host._should_include_pointer_note("calc", {"addr": "0x401000 + 0x20"}, {}) is False
    assert host._pointer_note_pending_signal > 0


def test_validate_address_lockstep_reports_only_unseen_addresses():
    host = _host()
    warnings = host._validate_address_lockstep(
        {"addr": "0x1000", "related": ["0x2000", "0x1000"]},
        {"address": "0x1000"},
    )
    assert warnings == [{
        "addr": "0x2000",
        "warning": "This address was not present in the previous tool output. Verify with calc/memory before reasoning.",
        "suggested_verification": {
            "tool": "calc",
            "arguments": {"action": "deref", "addr": "0x2000", "type": "u32"},
        },
    }]
    assert host._validate_address_lockstep({}, {}) == []


def test_output_filters_extract_path_then_filter_and_pluck_list_values():
    host = _host()
    payload = {
        "result": {
            "items": [
                {"name": "alpha", "ea": "0x1"},
                {"name": "beta", "ea": "0x2"},
                {"name": "gamma", "ea": "0x3"},
            ]
        }
    }
    out = host._apply_output_filters(
        payload,
        {"output_path": "result.items", "output_grep": "BETA", "output_pluck": "ea"},
    )
    assert out == ["0x2"]


def test_output_filters_apply_ordered_skip_head_tail_and_invalid_controls_are_safe():
    host = _host()
    assert host._apply_output_filters(
        list(range(8)),
        {"output_skip": 1, "output_head": 5, "output_tail": 2},
    ) == [4, 5]
    original = ["a", "b"]
    assert host._apply_output_filters(original, {"output_grep": "["}) == original
    assert host._apply_output_filters({"missing": 1}, {"output_path": "missing.child"}) == {}


def test_output_filters_apply_grep_to_common_lists_inside_dicts():
    host = _host()
    payload = {"matches": ["alpha", "beta"], "count": 2, "scalar": "beta"}
    out = host._apply_output_filters(payload, {"output_grep": "beta"})
    assert out["matches"] == ["beta"]
    assert out["count"] == 2
    assert out["scalar"] == "beta"


def test_guardrail_mode_aliases_and_execution_directive_are_human_readable():
    host = _host()
    assert host._guardrail_mode_from_args({"_guardrail_mode": "strict"}) == "enforce"
    assert host._guardrail_mode_from_args({"_guardrail_mode": "disabled"}) == "off"
    assert host._guardrail_mode_from_args({"_guardrail_mode": "other"}) == "assist"
    assert host._guardrail_mode_from_args(None) == "assist"

    assert host._build_llm_execution_directive({}) is None
    recommended = host._build_llm_execution_directive({
        "required_followup_call": {"tool": "calc", "action": "eval"}
    })
    assert recommended.startswith("MCP_RECOMMENDED_CALL: Prefer `calc.eval`")
    required = host._build_llm_execution_directive({
        "must_call_before_answer": True,
        "required_followup_call": {"tool": "memory", "action": "read"},
    })
    assert required.startswith("MCP_REQUIRED_CALL: Execute `memory.read`")


def test_blackboard_policy_followup_selects_working_set_or_decision_card():
    payload = {}
    host = _host(
        _phase_gates_enabled=True,
        _bb_policy_state=lambda: {"strict_mode": True},
        _bb_policy_check=lambda _state: {"ok": False, "reasons": ["missing_working_set"]},
    )
    host._inject_blackboard_policy_followup(payload, "code", {})
    assert payload["must_call_before_answer"] is True
    assert payload["required_followup_call"] == {"tool": "blackboard", "action": "working_set"}

    payload = {}
    host._bb_policy_check = lambda _state: {"ok": False, "reasons": ["stale_decision_or_write"]}
    host._inject_blackboard_policy_followup(payload, "code", {})
    assert payload["required_followup_call"] == {"tool": "blackboard", "action": "decision_card"}
    untouched = {}
    host._inject_blackboard_policy_followup(untouched, "blackboard", {})
    assert untouched == {}


def test_blackboard_policy_and_phase_followups_ignore_disabled_or_invalid_states():
    host = _host(
        _phase_gates_enabled=False,
        _bb_policy_state=lambda: {"strict_mode": True},
        _bb_policy_check=lambda _state: {"ok": False},
    )
    payload = {}
    host._inject_blackboard_policy_followup(payload, "code", {})
    assert payload == {}

    host._phase_gates_enabled = True
    host._phase_followup_for_response = lambda _tool: {
        "phase_gate": {"phase": "decide"},
        "must_call_before_answer": True,
        "required_followup_call": {"tool": "blackboard", "action": "decision_card"},
    }
    host._inject_blackboard_phase_followup(payload, "code")
    assert payload["blackboard_phase_gate"] == {"phase": "decide"}
    assert payload["must_call_before_answer"] is True
    assert payload["required_followup_call"]["action"] == "decision_card"

    host._phase_followup_for_response = lambda _tool: "not-a-followup"
    second = {}
    host._inject_blackboard_phase_followup(second, "code")
    assert second == {}

