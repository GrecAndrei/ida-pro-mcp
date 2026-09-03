"""Deep offline coverage for the public agent-operation contract helpers."""

from __future__ import annotations

from ida_pro_mcp.host import agent_operations as ao
from ida_pro_mcp.host.agent_operations import (
    AgentOperation,
    _matches_schema_type,
    _public_recovery_item,
    _rewrite_public_text,
    _stamp_risk_tiers,
    _validate_schema_value,
    adapt_agent_error_payload,
    backend_risk_tier,
    get_agent_operation,
    translate_public_batch_arguments,
)
from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.policy import RiskTier


def _operation(**overrides):
    values = {
        "name": "ida_custom",
        "description": "custom operation",
        "category": "test",
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string", "minLength": 2},
                "mode": {"type": "string", "enum": ["a", "b"]},
                "nested": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"name": {"type": "string", "minLength": 1}},
                    "required": ["name"],
                },
                "items": {"type": "array", "items": {"type": "integer"}},
            },
            "required": ["value"],
            "additionalProperties": False,
        },
        "example": {"value": "ok"},
        "backend_tool": "analysis",
        "backend_action": "custom",
    }
    values.update(overrides)
    return AgentOperation(**values)


def test_agent_operation_validation_covers_shape_nested_and_ack_edges():
    operation = _operation()
    assert operation.validate([])["code"] == MCPError.INVALID_ARGS
    assert operation.validate({"unknown": 1})["code"] == MCPError.INVALID_ARGS
    assert operation.validate({})["code"] == MCPError.INVALID_ARGS
    assert operation.validate({"value": ""})["code"] == MCPError.INVALID_ARGS
    assert operation.validate({"value": 1})["code"] == MCPError.INVALID_ARGS
    assert operation.validate({"value": "ok", "mode": "bad"})["code"] == MCPError.INVALID_ARGS
    assert operation.validate({"value": "ok", "nested": {}})["code"] == MCPError.INVALID_ARGS
    assert operation.validate({"value": "ok", "nested": {"name": "x", "extra": 1}})["code"] == MCPError.INVALID_ARGS
    assert operation.validate({"value": "ok", "items": ["bad"]})["code"] == MCPError.INVALID_ARGS
    assert operation.validate({"value": "ok", "nested": {"name": "x"}, "items": [1, 2]}) is None

    acked = _operation(
        input_schema={
            "type": "object",
            "properties": {"risk_ack": {"type": "boolean"}},
            "required": ["risk_ack"],
            "additionalProperties": False,
        },
        example={"risk_ack": True},
    )
    assert acked.validate({"risk_ack": False})["code"] == MCPError.INVALID_ARGS
    assert acked.validate({"risk_ack": True}) is None
    assert operation._example_text() == "value='ok'"
    no_properties = _operation(
        input_schema={"type": "object", "properties": [], "required": []},
        example={},
    )
    assert no_properties.validate({}) is None
    non_schema = _operation(
        input_schema={"type": "object", "properties": {"value": "not-a-schema"}, "required": []},
        example={},
    )
    assert non_schema.validate({"value": "anything"}) is None


def test_schema_helper_type_and_malformed_schema_edges():
    values = [
        ("x", {"type": "string"}),
        (1, {"type": "integer"}),
        (1.5, {"type": "number"}),
        (True, {"type": "boolean"}),
        ([], {"type": "array"}),
        ({}, {"type": "object"}),
    ]
    for value, schema in values:
        assert _matches_schema_type(value, schema)
    assert _matches_schema_type(False, {"type": "integer"}) is False
    assert _matches_schema_type("x", {"type": ["integer", "string"]})
    assert _matches_schema_type("x", {})
    assert _matches_schema_type("x", {"type": "unknown"}) is False
    assert _validate_schema_value("x", {"type": "string", "minLength": "bad"}, "value") is None
    assert _validate_schema_value("", {"type": "string", "minLength": 1}, "value")
    assert _validate_schema_value("x", {"type": "string", "enum": ["y"]}, "value")
    assert _validate_schema_value({}, {"type": "object", "required": "bad"}, "object") is None
    assert _validate_schema_value({"x": 1}, {"type": "object", "properties": "bad"}, "object") is None
    assert _validate_schema_value({"x": 1}, {"type": "object", "additionalProperties": False}, "object")
    assert _validate_schema_value([], {"type": "array", "items": {}}, "items") is None
    assert _validate_schema_value({"name": ""}, {"type": "object", "properties": {"name": {"type": "string", "minLength": "bad"}}, "required": ["name"]}, "nested")
    assert _validate_schema_value({"name": ""}, {"type": "object", "properties": {"name": {"type": "string", "minLength": 0}}, "required": ["name"]}, "nested") is None
    assert _validate_schema_value({"name": 1}, {"type": "object", "properties": {"name": {"type": "string"}}}, "nested")
    assert _validate_schema_value([], {"type": "array", "items": "bad"}, "items") is None


def test_backend_translation_risk_stamping_and_recovery_rewriting():
    no_backend = _operation(backend_tool=None, backend_action=None)
    try:
        no_backend.to_backend_call({})
    except ValueError as exc:
        assert "does not dispatch" in str(exc)
    else:
        raise AssertionError("expected missing backend failure")
    operation = _operation(argument_map={"value": "_value"}, backend_defaults={"mode": "fast"})
    assert operation.to_backend_call({"value": "x"}) == ("analysis", {"action": "custom", "mode": "fast", "_value": "x"})
    assert operation.to_backend_call({"other": 1})[1]["other"] == 1

    stamped = _stamp_risk_tiers(
        (
            _operation(risk_tier=RiskTier.WRITE_IDB),
            _operation(name="ida_help_custom", help_only=True, backend_tool=None, backend_action=None),
            _operation(name="ida_read_custom", backend_tool="analysis", backend_action="info"),
        )
    )
    assert stamped[0].risk_tier is RiskTier.WRITE_IDB
    assert stamped[1].risk_tier is RiskTier.READ
    assert stamped[2].risk_tier is not None
    assert backend_risk_tier("not-a-tool", "not-an-action") is None
    assert backend_risk_tier("session", "create") is not None
    ao._OPERATIONS_BY_BACKEND["temporary-riskless", "action"] = _operation(risk_tier=None)
    assert backend_risk_tier("temporary-riskless", "action") is None
    del ao._OPERATIONS_BY_BACKEND["temporary-riskless", "action"]

    assert _rewrite_public_text("data(action='functions')", "ida_custom") == "ida_list_functions"
    rewritten = _rewrite_public_text("index_fast then index_batch", "ida_custom")
    assert "ida_index_functions" in rewritten
    assert "Use ida_help" in _rewrite_public_text("data.functions", "ida_custom")
    assert _rewrite_public_text("ordinary text", "ida_custom") == "ordinary text"


def test_public_recovery_and_error_adaptation_modes():
    assert _public_recovery_item("bad") is None
    assert _public_recovery_item({"tool": "ida_custom"}) is None
    assert _public_recovery_item({"tool": "ida_missing", "args": {}}) is None
    public = {"tool": "ida_help", "args": {"query": "x"}, "note": "ordinary"}
    assert _public_recovery_item(public) is not None
    assert _public_recovery_item({"tool": "ida_help", "args": {}})["tool"] == "ida_help"
    public_missing = {"tool": "ida_open_binary", "args": {}}
    assert _public_recovery_item(public_missing) is None
    legacy_missing = {"tool": "data", "args": {"action": "functions"}}
    assert _public_recovery_item(legacy_missing) is not None
    assert _public_recovery_item({"tool": "analysis", "args": {"action": "not-real"}}) is None
    assert _public_recovery_item({"tool": "session", "args": {"action": "create"}}) is None

    payload = {
        "error": True,
        "code": "X",
        "message": "Use data(action='functions')",
        "recovery": [legacy_missing, "bad", {"tool": "analysis", "args": {}}],
    }
    adapted = adapt_agent_error_payload(payload, "ida_custom")
    assert adapted["message"] == "Use ida_list_functions"
    assert adapted["recovery"]
    assert adapt_agent_error_payload(payload, "analysis") is payload
    assert adapt_agent_error_payload([payload], "ida_custom")[0]["error"] is True
    assert adapt_agent_error_payload("plain", "ida_custom") == "plain"
    assert adapt_agent_error_payload({"nested": payload}, "ida_custom")["nested"]["error"] is True


def test_public_batch_translation_rejects_and_translates_all_call_shapes():
    assert translate_public_batch_arguments([])[1]["code"] == MCPError.INVALID_ARGS
    assert translate_public_batch_arguments({})[1]["code"] == MCPError.BATCH_EMPTY
    assert translate_public_batch_arguments({"calls": [1]})[1]["code"] == MCPError.INVALID_ARGS
    assert translate_public_batch_arguments({"calls": [{"name": "ida_help", "arguments": []}]})[1]["code"] == MCPError.INVALID_ARGS
    assert translate_public_batch_arguments({"calls": ["not_public"]}, agent_surface=True)[1]["code"] == MCPError.TOOL_NOT_FOUND
    legacy, error = translate_public_batch_arguments({"calls": ["legacy"]}, agent_surface=False)
    assert error is None and legacy["calls"] == ["legacy"]
    nested = translate_public_batch_arguments({"calls": [{"name": "ida_batch", "arguments": {}}]})
    assert nested[1]["code"] == MCPError.INVALID_ARGS
    help_nested = translate_public_batch_arguments({"calls": [{"name": "ida_help", "arguments": {"query": "x"}}]})
    assert help_nested[1]["code"] == MCPError.INVALID_ARGS

    valid, error = translate_public_batch_arguments(
        {"action": "batch", "calls": [{"name": "ida_session_list", "arguments": {}}]},
        agent_surface=False,
    )
    assert valid is not None and error is None

    invalid_public, error = translate_public_batch_arguments(
        {"calls": [{"name": "ida_open_binary", "arguments": {}}]}, agent_surface=False
    )
    assert error is None and invalid_public["calls"][0]["_precomputed_error"]["code"] == MCPError.INVALID_ARGS

    class _BadDetailsOperation:
        name = "ida_fake"
        backend_tool = "analysis"
        backend_action = None
        help_only = False

        @staticmethod
        def validate(_arguments):
            return {"error": True, "code": MCPError.INVALID_ARGS, "details": "not-an-object"}

    original_get = ao.get_agent_operation
    ao.get_agent_operation = lambda name: _BadDetailsOperation() if name == "ida_fake" else original_get(name)
    try:
        translated, error = translate_public_batch_arguments(
            {"calls": [{"name": "ida_fake", "arguments": {}}]}, agent_surface=False
        )
    finally:
        ao.get_agent_operation = original_get
    assert error is None
    assert translated["calls"][0]["arguments"] == {}
