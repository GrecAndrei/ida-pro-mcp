"""Exhaustive offline checks for the vendored JSON-RPC parameter validator."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from tests.ida_mcp import test_p16_zeromcp as support


class _Options(TypedDict):
    enabled: bool


def _error(registry, request, code=-32602):
    response = registry.dispatch(request)
    assert response is not None
    assert response["error"]["code"] == code
    return response


def test_jsonrpc_parse_validation_notifications_and_exception_modes():
    jr, mcp = support._load_pkg()
    registry = jr.JsonRpcRegistry()

    def optional(value: int = 3):
        return value

    def required(value: int):
        return value

    def fail():
        raise RuntimeError("boom")

    registry.method(optional)
    registry.method(required)
    registry.method(fail)
    assert registry.dispatch(b"not-json")["error"]["code"] == -32700
    assert registry.dispatch(b"[]")["error"]["code"] == -32600
    assert registry.dispatch({"jsonrpc": "2.0", "method": "optional", "id": 1})["result"] == 3
    assert _error(registry, {"jsonrpc": "2.0", "method": "required", "id": 2})["error"]["message"] == "Missing required params"
    assert _error(registry, {"jsonrpc": "2.0", "method": "optional", "params": 4, "id": 3})["error"]["code"] == -32602
    assert _error(registry, {"jsonrpc": "2.0", "method": "required", "params": [1, 2], "id": 4})["error"]["code"] == -32602
    assert registry.dispatch({"jsonrpc": "2.0", "method": "required", "params": [1], "id": 5})["result"] == 1
    assert _error(registry, {"jsonrpc": "2.0", "method": "missing", "id": 6}, -32601)["error"]["code"] == -32601
    assert "RuntimeError" in registry.dispatch({"jsonrpc": "2.0", "method": "fail", "id": 7})["error"]["message"]
    registry.redact_exceptions = True
    assert "Internal Error: boom" in registry.dispatch({"jsonrpc": "2.0", "method": "fail", "id": 8})["error"]["message"]
    assert registry.dispatch({"jsonrpc": "2.0", "method": "fail"}) is None
    assert mcp.McpRpcRegistry().map_exception(mcp.McpToolError("tool"))["code"] == -32000


def test_jsonrpc_type_hints_cover_union_literal_generic_typed_dict_and_any():
    jr, _mcp = support._load_pkg()
    registry = jr.JsonRpcRegistry()

    def typed(
        number: int,
        ratio: float,
        choice: int | str,
        mode: Literal["fast", "safe"],
        names: list[str],
        values: dict[str, int],
        options: _Options,
        anything: Any,
    ):
        return {
            "number": number,
            "ratio": ratio,
            "choice": choice,
            "mode": mode,
            "names": names,
            "values": values,
            "options": options,
            "anything": anything,
        }

    registry.method(typed)
    valid = {
        "number": 2,
        "ratio": 2,
        "choice": "two",
        "mode": "fast",
        "names": ["a"],
        "values": {"a": 1},
        "options": {"enabled": True},
        "anything": object(),
    }
    # Any is intentionally passed through, but the result itself is not
    # serialized by JsonRpcRegistry, so it is safe to use an object here.
    response = registry.dispatch({"jsonrpc": "2.0", "method": "typed", "params": valid, "id": 1})
    assert response["result"]["ratio"] == 2

    invalid_cases = [
        ("number", "two"),
        ("ratio", "two"),
        ("choice", []),
        ("mode", "turbo"),
        ("names", "a"),
        ("values", []),
        ("options", []),
    ]
    for key, value in invalid_cases:
        request = dict(valid)
        request[key] = value
        response = _error(
            registry,
            {"jsonrpc": "2.0", "method": "typed", "params": request, "id": key},
        )
        assert key in response["error"]["message"]

    # The reflection cache is reused on the second valid call.
    valid["anything"] = object()
    response = registry.dispatch({"jsonrpc": "2.0", "method": "typed", "params": valid, "id": 2})
    assert response["result"]["number"] == 2


def test_jsonrpc_parameter_boundaries_and_explicit_error_payloads():
    jr, _mcp = support._load_pkg()
    registry = jr.JsonRpcRegistry()

    def one(first: int, second: int = 2):
        return first + second

    def zero():
        return "ok"

    registry.method(one)
    registry.method(zero)
    assert registry.dispatch({"jsonrpc": "2.0", "method": "one", "params": [4], "id": 1})["result"] == 6
    assert _error(registry, {"jsonrpc": "2.0", "method": "one", "params": [], "id": 2})["error"]["code"] == -32602
    assert _error(registry, {"jsonrpc": "2.0", "method": "one", "params": [1, 2, 3], "id": 3})["error"]["code"] == -32602
    assert _error(registry, {"jsonrpc": "2.0", "method": "one", "params": {"first": 1, "extra": 2}, "id": 4})["error"]["code"] == -32602
    assert _error(registry, {"jsonrpc": "2.0", "method": "one", "params": {"first": None}, "id": 5})["error"]["code"] == -32602
    assert registry.dispatch({"jsonrpc": "2.0", "method": "zero", "params": None, "id": 6})["result"] == "ok"
    assert _error(registry, {"jsonrpc": "2.0", "method": "one", "params": {"first": 1, "second": None}, "id": 7})["error"]["code"] == -32602

    assert registry._error("id", 123, "message", {"detail": True})["error"]["data"] == {"detail": True}
    assert registry._error("id", 123, "message")["error"] == {"code": 123, "message": "message"}
