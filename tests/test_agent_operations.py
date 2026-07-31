"""Contract tests for the action-specific MCP surface exposed to agents."""

from __future__ import annotations

from ida_pro_mcp.host.agent_operations import (
    adapt_agent_error_payload,
    build_agent_help,
    get_agent_operation,
    list_agent_operations,
    translate_public_batch_arguments,
)
from ida_pro_mcp.host.schemas import TOOL_ARG_SCHEMAS
from ida_pro_mcp.host.server.rpc_args import prepare_rpc_args
from ida_pro_mcp.host.server.server import IDAMCPServer


def test_public_operations_have_strict_schemas_and_examples():
    operations = list_agent_operations()
    assert operations
    assert len({operation.name for operation in operations}) == len(operations)
    for operation in operations:
        schema = operation.input_schema
        assert operation.name.startswith("ida_")
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert set(operation.example) <= set(schema["properties"])
        assert not operation.validate(operation.example)


def test_find_translates_to_the_legacy_backend_without_losing_its_required_query():
    operation = get_agent_operation("ida_find")
    assert operation is not None
    assert not operation.validate({"query": "recv", "limit": 5})
    backend_tool, backend_args = operation.to_backend_call({"query": "recv", "limit": 5})
    assert backend_tool == "search"
    assert backend_args == {"action": "find", "pattern": "recv", "limit": 5}
    assert operation.validate({"limit": 5})
    assert operation.validate({"query": "recv", "pattern": "wrong field"})


def test_semantic_search_translates_address_scope_and_score_controls():
    operation = get_agent_operation("ida_semantic_search")
    assert operation is not None
    arguments = {
        "query": "packet decoder",
        "address": "0x4000",
        "radius": 1024,
        "min_score": 0.35,
        "limit": 12,
    }
    assert not operation.validate(arguments)
    assert operation.to_backend_call(arguments) == (
        "search",
        {
            "action": "nl",
            "query": "packet decoder",
            "addr": "0x4000",
            "radius": 1024,
            "semantic_min_score": 0.35,
            "limit": 12,
        },
    )


def test_function_listing_uses_the_legacy_funcs_backend_behind_a_public_operation():
    operation = get_agent_operation("ida_list_functions")
    assert operation is not None
    backend_tool, backend_args = operation.to_backend_call({"query": "recv", "limit": 5})
    assert backend_tool == "funcs"
    assert backend_args == {"action": "list", "query": "recv", "count": 5}


def test_function_create_and_change_translate_to_mutating_funcs_actions():
    create = get_agent_operation("ida_create_function")
    change = get_agent_operation("ida_change_function")
    assert create is not None and change is not None

    create_tool, create_args = create.to_backend_call(
        {"address": "0x401000", "end": "0x401080", "name": "handler", "risk_ack": True}
    )
    assert create_tool == "funcs"
    assert create_args == {
        "action": "create",
        "addr": "0x401000",
        "end": "0x401080",
        "name": "handler",
        "_risk_ack": True,
    }

    change_tool, change_args = change.to_backend_call(
        {"address": "0x401000", "end": "0x401090", "risk_ack": True}
    )
    assert change_tool == "funcs"
    assert change_args == {
        "action": "change",
        "addr": "0x401000",
        "end": "0x401090",
        "_risk_ack": True,
    }
    assert change.validate({"address": "0x401000"})


def test_calc_operations_expose_each_backend_action_with_action_specific_arguments():
    cases = {
        "ida_calc_eval": ({"expr": "0x10 + 4"}, "eval"),
        "ida_calc_offset": ({"address": "0x10", "target": "0x20"}, "offset"),
        "ida_calc_convert": ({"value": "0xff"}, "convert"),
        "ida_calc_resolve": ({"address": "0x401000", "to_va": True}, "resolve"),
        "ida_calc_deref": ({"address": "0x401000", "type": "u32"}, "deref"),
        "ida_calc_chain": ({"address": "0x401000", "offsets": ["0x10"]}, "chain"),
        "ida_calc_align": ({"value": "0x401003", "size": 16}, "align"),
        "ida_calc_bitops": ({"value": "0xff", "target": "0xf", "bit_op": "xor"}, "bitops"),
    }
    for name, (arguments, action) in cases.items():
        operation = get_agent_operation(name)
        assert operation is not None
        assert not operation.validate(arguments)
        tool, backend_args = operation.to_backend_call(arguments)
        assert tool == "calc"
        assert backend_args["action"] == action


def test_public_batch_translates_nested_ida_operations_and_rejects_invalid_nested_calls():
    translated, error = translate_public_batch_arguments(
        {
            "calls": [
                {"name": "ida_overview", "arguments": {}},
                {"name": "ida_calc_eval", "arguments": {"expr": "0x10 + 4"}},
            ],
            "continue_on_error": True,
        }
    )
    assert error is None
    assert translated == {
        "calls": [
            {"name": "idb", "arguments": {"action": "overview"}},
            {"name": "calc", "arguments": {"action": "eval", "expr": "0x10 + 4"}},
        ],
        "continue_on_error": True,
    }

    translated, error = translate_public_batch_arguments(
        {"calls": [{"name": "ida_find", "arguments": {}}]}
    )
    assert translated is None
    assert error["code"] == "INVALID_ARGS"
    assert error["details"]["batch_index"] == 0


def test_agent_tools_list_avoids_schema_unions_without_vertex_compat(monkeypatch):
    monkeypatch.delenv("IDA_MCP_VERTEX_COMPAT", raising=False)
    response = IDAMCPServer().handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }
    )

    tools = response["result"]["tools"]
    assert tools
    batch = next(tool for tool in tools if tool["name"] == "ida_batch")
    calls = batch["inputSchema"]["properties"]["calls"]
    assert calls["items"]["type"] == "object"
    assert calls["items"]["required"] == ["name"]

    chain = next(tool for tool in tools if tool["name"] == "ida_calc_chain")
    offsets = chain["inputSchema"]["properties"]["offsets"]
    assert offsets["type"] == "array"
    assert offsets["items"] == {"type": "string"}

    def assert_no_unions(value):
        if isinstance(value, dict):
            assert not isinstance(value.get("type"), list)
            assert "anyOf" not in value
            assert "any_of" not in value
            for child in value.values():
                assert_no_unions(child)
        elif isinstance(value, list):
            for child in value:
                assert_no_unions(child)

    for tool in tools:
        assert_no_unions(tool["inputSchema"])


def test_public_batch_protocol_dispatches_translated_calls(monkeypatch):
    server = IDAMCPServer()
    observed = {}

    def fake_batch(arguments):
        observed.update(arguments)
        return {"ok": True, "count": len(arguments["calls"])}

    monkeypatch.setattr(server, "_handle_batch", fake_batch)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "ida_batch",
                "arguments": {
                    "calls": [
                        {"name": "ida_overview", "arguments": {}},
                        {"name": "ida_calc_eval", "arguments": {"expr": "1 + 1"}},
                    ]
                },
            },
        }
    )

    assert response["result"]["content"][0]["text"] == "ok: true\ncount: 2"
    assert "structuredContent" not in response["result"]
    assert observed["calls"] == [
        {"name": "idb", "arguments": {"action": "overview"}},
        {"name": "calc", "arguments": {"action": "eval", "expr": "1 + 1"}},
    ]


def test_all_clients_receive_readable_tool_results_without_duplicate_data(monkeypatch):
    monkeypatch.delenv("IDA_MCP_VERTEX_COMPAT", raising=False)
    server = IDAMCPServer()
    assert server.vertex_compat is False

    expected = {
        "summary": 'found "quoted" text at C:\\temp',
        "pseudocode": 'puts("hello");\nreturn 0;',
    }
    monkeypatch.setattr(server, "_handle_batch", lambda _arguments: expected)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "ida_batch",
                "arguments": {"calls": [{"name": "ida_overview"}]},
            },
        }
    )

    result = response["result"]
    assert "structuredContent" not in result
    text = result["content"][0]["text"]
    assert 'summary: found "quoted" text at C:\\temp' in text
    assert 'puts("hello");\nreturn 0;' in text
    assert '\\"' not in text
    assert not text.startswith("{")


def test_structured_tool_results_are_opt_in(monkeypatch):
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    server = IDAMCPServer()
    expected = {"ok": True, "count": 1}
    monkeypatch.setattr(server, "_handle_batch", lambda _arguments: expected)

    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "ida_batch",
                "arguments": {"calls": [{"name": "ida_overview"}]},
            },
        }
    )

    assert response["result"]["structuredContent"] == expected


def test_full_function_indexing_has_an_explicit_resumable_contract():
    operation = get_agent_operation("ida_index_functions")
    assert operation is not None
    arguments = {
        "quality": "full",
        "limit": 500,
        "cursor": "0x401000",
        "address": "0x402000",
        "radius": 4096,
        "slice_size": 8,
    }
    assert not operation.validate(arguments)
    backend_tool, backend_args = operation.to_backend_call(arguments)
    assert backend_tool == "intelligence"
    assert backend_args == {
        "action": "index_fast",
        "_background": True,
        "mode": "full",
        "limit": 500,
        "start_after": "0x401000",
        "addr": "0x402000",
        "radius": 4096,
        "_index_slice_size": 8,
    }
    assert prepare_rpc_args(backend_tool, backend_args, TOOL_ARG_SCHEMAS) == {
        key: value for key, value in backend_args.items() if not key.startswith("_")
    }
    assert operation.validate({"quality": "lossy"})


def test_function_indexing_exposes_scopes_and_background_job_controls():
    operation = get_agent_operation("ida_index_functions")
    status = get_agent_operation("ida_index_status")
    cancel = get_agent_operation("ida_cancel_index")
    assert operation is not None and status is not None and cancel is not None
    arguments = {
        "ranges": [
            {"start": "0x1000", "end": "0x2000"},
            {"start": "0x4000", "end": "0x4800"},
        ],
        "query": "jpeg_*",
        "min_size": 16,
        "max_size": 4096,
        "background": False,
    }
    assert not operation.validate(arguments)
    tool, backend_args = operation.to_backend_call(arguments)
    assert tool == "intelligence"
    assert backend_args["ranges"] == arguments["ranges"]
    assert backend_args["_background"] is False
    assert status.to_backend_call({"task_id": "task1"}) == (
        "background",
        {"action": "status", "task_id": "task1"},
    )
    assert cancel.to_backend_call({"task_id": "task1"}) == (
        "background",
        {"action": "cancel", "task_id": "task1"},
    )


def test_continue_contract_documents_multi_field_selection():
    operation = get_agent_operation("ida_continue")
    assert operation is not None
    arguments = {"token": "ABC123", "field": "code", "offset": 0, "count": 20}
    assert not operation.validate(arguments)
    backend_tool, backend_args = operation.to_backend_call(arguments)
    assert backend_tool == "truncation"
    assert backend_args == {
        "action": "continue",
        "token": "ABC123",
        "field": "code",
        "offset": 0,
        "count": 20,
    }
    assert "field" in operation.input_schema["properties"]
    assert "more than one" in operation.description


def test_python_exposes_scoped_code_execution_with_policy_acknowledgement():
    operation = get_agent_operation("ida_python")
    assert operation is not None
    arguments = {"code": "print(idaapi.get_imagebase())", "risk_ack": True}
    assert not operation.validate(arguments)
    backend_tool, backend_args = operation.to_backend_call(arguments)
    assert backend_tool == "misc"
    assert backend_args == {
        "action": "python",
        "code": "print(idaapi.get_imagebase())",
        "_risk_ack": True,
    }
    assert operation.validate({})
    assert operation.validate({"expr": "1 + 1"})


def test_public_errors_do_not_return_legacy_recovery_syntax():
    payload = {
        "error": True,
        "code": "DECOMPILER_FAILED",
        "message": "The decompiler failed.",
        "hint": "Try code(action='disasm') for assembly.",
        "recovery": [
            {"tool": "code", "args": {"action": "disasm", "addrs": "$addr"}, "note": "Fall back"},
            {"tool": "analysis", "args": {"action": "reanalyze", "addr": "$addr"}, "note": "Retry"},
        ],
    }

    adapted = adapt_agent_error_payload(payload, "ida_decompile")

    assert adapted["hint"] == "Try ida_disassemble for assembly."
    assert adapted["recovery"] == [
        {"tool": "ida_disassemble", "args": {"address": "$addr"}, "note": "Fall back"}
    ]
    assert "action=" not in str(adapted)
    assert "code(" not in str(adapted)


def test_public_errors_replace_unavailable_legacy_guidance_with_public_help():
    adapted = adapt_agent_error_payload(
        {
            "error": True,
            "code": "FUNCTION_NOT_FOUND",
            "message": "No function.",
            "hint": "Use funcs(action='create', addr='0x401000').",
        },
        "ida_decompile",
    )

    assert adapted["hint"] == "Use ida_create_function."
    assert "funcs(" not in adapted["hint"]


def test_public_error_adapter_rewrites_nested_aggregate_errors():
    adapted = adapt_agent_error_payload(
        {
            "ok": True,
            "results": [
                {
                    "error": True,
                    "code": "FUNCTION_NOT_FOUND",
                    "message": "No function.",
                    "hint": "Use funcs(action='create', addr='0x401000').",
                }
            ],
        },
        "ida_decompile",
    )

    assert adapted["results"][0]["hint"] == "Use ida_create_function."
    assert "funcs(" not in adapted["results"][0]["hint"]


def test_public_error_adapter_passes_through_public_recovery_recipes():
    adapted = adapt_agent_error_payload(
        {
            "error": True,
            "code": "SESSION_REQUIRED",
            "message": "No session.",
            "recovery": [
                {"tool": "ida_open_binary", "args": {"binary_path": "/tmp/x"}, "note": "Create a session"}
            ],
        },
        "ida_decompile",
    )

    assert adapted["recovery"] == [
        {"tool": "ida_open_binary", "args": {"binary_path": "/tmp/x"}, "note": "Create a session"}
    ]


def test_public_error_adapter_drops_incomplete_public_recovery_recipes():
    adapted = adapt_agent_error_payload(
        {
            "error": True,
            "code": "SESSION_REQUIRED",
            "message": "No session.",
            "recovery": [
                {"tool": "ida_open_binary", "args": {}, "note": "Missing required binary_path"}
            ],
        },
        "ida_decompile",
    )

    assert "recovery" not in adapted


def test_public_protocol_adapts_backend_error_hints(monkeypatch):
    server = IDAMCPServer()
    monkeypatch.setattr(
        server,
        "_execute_tool",
        lambda _tool, _args: {
            "error": True,
            "code": "DECOMPILER_FAILED",
            "message": "The decompiler failed.",
            "hint": "Try code(action='disasm') for assembly.",
        },
    )

    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ida_decompile", "arguments": {"address": "0x401000"}},
        }
    )
    assert "hint: Try ida_disassemble for assembly." in response["result"]["content"][0]["text"]


def test_help_is_in_band_and_returns_the_exact_visible_schema():
    response = build_agent_help({"topic": "ida_decompile"})
    assert response["ok"] is True
    operation = response["operation"]
    assert operation["name"] == "ida_decompile"
    assert operation["inputSchema"]["required"] == ["address"]
    assert operation["example"] == {"address": "0x401000"}


def test_default_tools_list_exposes_agent_operations_with_required_operands(monkeypatch):
    monkeypatch.delenv("IDA_MCP_TOOL_SURFACE", raising=False)
    server = IDAMCPServer()
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    result = response["result"]
    tools = {tool["name"]: tool for tool in result["tools"]}

    assert result["surface"] == "agent"
    assert "search" not in tools
    assert tools["ida_find"]["inputSchema"]["required"] == ["query"]
    assert tools["ida_decompile"]["inputSchema"]["required"] == ["address"]
    assert tools["ida_rename"]["inputSchema"]["required"] == ["address", "name", "risk_ack"]
    assert tools["ida_comment"]["inputSchema"]["required"] == ["address", "comment", "risk_ack"]
    assert tools["ida_create_function"]["inputSchema"]["required"] == ["address", "risk_ack"]
    assert tools["ida_change_function"]["inputSchema"]["required"] == ["address", "end", "risk_ack"]
    assert tools["ida_python"]["inputSchema"]["required"] == ["code", "risk_ack"]
    assert "ida_session_health" in tools
    assert tools["ida_session_health"]["inputSchema"]["properties"]["verbose"]["type"] == "boolean"


def test_help_is_callable_through_the_public_mcp_protocol():
    server = IDAMCPServer()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ida_help", "arguments": {"topic": "ida_find"}},
        }
    )
    text = response["result"]["content"][0]["text"]
    assert "operation:" in text
    assert "name: ida_find" in text
    assert "- query" in text


def test_public_protocol_rejects_unknown_or_missing_operands_before_dispatch():
    server = IDAMCPServer()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ida_find", "arguments": {"pattern": "recv"}},
        }
    )

    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "code: INVALID_ARGS" in text
    assert "Unknown argument" in text
