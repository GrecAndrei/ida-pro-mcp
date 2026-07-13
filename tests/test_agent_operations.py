"""Contract tests for the action-specific MCP surface exposed to agents."""

from __future__ import annotations

import json

from ida_pro_mcp.host.agent_operations import build_agent_help, get_agent_operation, list_agent_operations
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


def test_full_function_indexing_has_an_explicit_resumable_contract():
    operation = get_agent_operation("ida_index_functions")
    assert operation is not None
    arguments = {"quality": "full", "limit": 16, "cursor": "0x401000"}
    assert not operation.validate(arguments)
    backend_tool, backend_args = operation.to_backend_call(arguments)
    assert backend_tool == "intelligence"
    assert backend_args == {
        "action": "index_fast",
        "mode": "full",
        "index_limit": 16,
        "start_after": "0x401000",
    }
    assert prepare_rpc_args(backend_tool, backend_args, TOOL_ARG_SCHEMAS) == backend_args
    assert operation.validate({"quality": "lossy"})


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
    assert tools["ida_rename"]["inputSchema"]["required"] == ["address", "name"]
    assert tools["ida_python"]["inputSchema"]["required"] == ["code"]


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
    content = response["result"]["content"]
    payload = json.loads(content[0]["text"])
    assert payload["operation"]["name"] == "ida_find"
    assert payload["operation"]["inputSchema"]["required"] == ["query"]


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
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["code"] == "INVALID_ARGS"
    assert "Unknown argument" in payload["message"]
