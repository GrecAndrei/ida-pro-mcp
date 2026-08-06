from __future__ import annotations

from ida_pro_mcp.host.agent_operations import (
    _public_operation_for_backend,
    get_agent_operation,
    list_agent_operations,
)


def test_mutating_operations_require_explicit_risk_ack_true():
    names = [
        "ida_rename",
        "ida_comment",
        "ida_create_function",
        "ida_change_function",
        "ida_python",
        # new full-accessibility operations
        "ida_patch_bytes",
        "ida_rename_local",
        "ida_declare_type",
        "ida_apply_type",
        "ida_add_segment",
        "ida_set_segment_attrs",
        "ida_apply_sig",
    ]
    for name in names:
        operation = get_agent_operation(name)
        assert operation is not None
        assert "risk_ack" in operation.input_schema["required"]

        args = dict(operation.example)
        assert not operation.validate(args)

        without = {key: value for key, value in args.items() if key != "risk_ack"}
        missing = operation.validate(without)
        assert missing is not None
        assert missing["code"] == "INVALID_ARGS"
        assert "risk_ack" in missing["message"]

        false_ack = dict(args)
        false_ack["risk_ack"] = False
        rejected = operation.validate(false_ack)
        assert rejected is not None
        assert "must be true" in rejected["message"]


def test_session_health_maps_to_dedicated_public_operation():
    operation = get_agent_operation("ida_session_health")
    assert operation is not None
    assert operation.backend_tool == "session"
    assert operation.backend_action == "health"
    assert _public_operation_for_backend("session", "health") is operation
    assert get_agent_operation("ida_session_status").backend_action == "status"


def test_agent_operation_catalog_includes_session_health():
    names = {operation.name for operation in list_agent_operations()}
    assert "ida_session_health" in names
    assert "ida_session_status" in names


def test_read_only_new_operations_do_not_require_risk_ack():
    names = [
        "ida_read_bytes",
        "ida_get_type",
        "ida_list_types",
        "ida_list_segments",
        "ida_callgraph",
        "ida_list_sigs",
    ]
    for name in names:
        op = get_agent_operation(name)
        assert op is not None, f"{name} not found"
        assert "risk_ack" not in op.input_schema.get("required", []), (
            f"{name} should not require risk_ack"
        )
