"""Additional public-surface contract tests for unusual client inputs."""

from __future__ import annotations

from ida_pro_mcp.host.agent_operations import (
    adapt_agent_error_payload,
    build_agent_help,
    get_agent_operation,
    render_agent_operations_markdown,
    render_agent_skill_markdown,
    translate_public_batch_arguments,
)
from ida_pro_mcp.host.errors import MCPError


def test_public_validation_checks_enums_types_and_required_empty_strings():
    search = get_agent_operation("ida_semantic_search")
    assert search is not None
    assert search.validate({"query": "x", "mode": "not-a-mode"})["code"] == MCPError.INVALID_ARGS
    assert search.validate({"query": "x", "limit": True})["code"] == MCPError.INVALID_ARGS

    decompile = get_agent_operation("ida_decompile")
    assert decompile is not None
    error = decompile.validate({"address": ""})
    assert error["code"] == MCPError.INVALID_ARGS
    assert "address" in error["message"]


def test_public_error_adapter_rewrites_legacy_recovery_and_nested_errors():
    payload = {
        "error": True,
        "code": "IDA_ERROR",
        "message": "Use search(action='find', pattern='main').",
        "hint": "Call intelligence(action='index_batch').",
        "recovery": [
            {
                "tool": "search",
                "args": {"action": "find", "pattern": "main"},
                "note": "Then call code(action='decompile').",
            },
            {"tool": "not-public", "args": {"action": "nope"}},
        ],
    }
    adapted = adapt_agent_error_payload(payload, "ida_find")
    assert adapted["message"] == "Use ida_find."
    assert adapted["hint"] == "Call ida_index_functions."
    assert adapted["recovery"] == [
        {
            "tool": "ida_find",
            "args": {"query": "main"},
            "note": "Then call ida_decompile.",
        }
    ]

    nested = adapt_agent_error_payload(
        {"items": [payload, {"ok": True, "value": 1}]}, "ida_find"
    )
    assert nested["items"][0]["error"] is True
    assert nested["items"][1] == {"ok": True, "value": 1}


def test_public_error_adapter_leaves_legacy_and_non_dict_payloads_unchanged():
    payload = {"error": True, "message": "search(action='find')"}
    assert adapt_agent_error_payload(payload, "search") is payload
    assert adapt_agent_error_payload([1, "x"], "ida_find") == [1, "x"]
    assert adapt_agent_error_payload("plain", "ida_find") == "plain"


def test_help_supports_exact_query_all_and_unknown_topics():
    exact = build_agent_help({"topic": "ida_decompile"})
    assert exact["ok"] is True
    assert exact["operation"]["inputSchema"]["required"] == ["address"]

    query = build_agent_help({"query": "semantic"})
    assert query["ok"] is True
    assert query["count"] > 0
    assert all(item["name"].startswith("ida_") for item in query["operations"])

    all_ops = build_agent_help({})
    assert all_ops["ok"] is True
    assert all_ops["count"] > 50
    unknown = build_agent_help({"topic": "ida_does_not_exist"})
    assert unknown["error"] is True
    assert unknown["code"] == MCPError.INVALID_ARGS


def test_public_batch_rejects_malformed_calls_nested_batch_and_help():
    translated, error = translate_public_batch_arguments({"calls": []})
    assert translated is None
    assert error["code"] == MCPError.BATCH_EMPTY

    translated, error = translate_public_batch_arguments(
        {"calls": [{"name": "ida_calc_eval", "arguments": "bad"}]}
    )
    assert translated is None
    assert error["code"] == MCPError.INVALID_ARGS

    translated, error = translate_public_batch_arguments(
        {"calls": [{"name": "ida_batch", "arguments": {}}]}
    )
    assert translated is None
    assert error["code"] == MCPError.INVALID_ARGS

    translated, error = translate_public_batch_arguments(
        {"calls": [{"name": "ida_help", "arguments": {}}]}
    )
    assert translated is None
    assert error["code"] == MCPError.INVALID_ARGS


def test_public_batch_accepts_string_steps_and_preserves_bindings():
    translated, error = translate_public_batch_arguments(
        {
            "calls": ["ida_overview", {"name": "ida_calc_eval", "arguments": {"expr": "2+2"}}],
            "bindings": {"answer": "step1_value"},
        }
    )
    assert error is None
    assert translated["calls"] == [
        {"name": "idb", "arguments": {"action": "overview"}},
        {"name": "calc", "arguments": {"action": "eval", "expr": "2+2"}},
    ]
    assert translated["bindings"] == {"answer": "step1_value"}


def test_generated_public_docs_contain_every_operation_once():
    from ida_pro_mcp.host.agent_operations import list_agent_operations

    names = [op.name for op in list_agent_operations()]
    skill = render_agent_skill_markdown()
    reference = render_agent_operations_markdown()
    assert "ida_decompile" in skill
    assert "ida_help" in skill
    assert all(reference.count(f"## `{name}`") == 1 for name in names)
