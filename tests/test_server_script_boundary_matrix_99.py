"""Additional startup and protocol coverage for the IDA-side bridge."""

from __future__ import annotations

import builtins
import importlib.util
import json
import runpy
import sys
import threading
import types
from pathlib import Path
from typing import Annotated, Literal

import pytest

_SERVER_SCRIPT = Path(__file__).parents[1] / "src" / "ida_pro_mcp" / "server_script.py"


def _load_bridge(tmp_path, monkeypatch, **env):
    monkeypatch.setenv("IDA_MCP_SESSION_LOG_DIR", str(tmp_path))
    monkeypatch.delenv("IDA_MCP_SESSION_TOKEN", raising=False)
    for key, value in env.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, str(value))
    for name in ("ida_segment", "idautils", "idc"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    name = f"ida_pro_mcp_server_boundary_{id(tmp_path)}"
    spec = importlib.util.spec_from_file_location(name, _SERVER_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_import_configuration_and_trace_fallbacks(tmp_path, monkeypatch):
    bridge = _load_bridge(
        tmp_path,
        monkeypatch,
        IDA_MCP_ERROR_DETAIL_LEVEL="invalid",
        IDA_MCP_MAX_RPC_REQUEST_BYTES="bad",
        IDA_MCP_MAX_RPC_RESPONSE_BYTES="bad",
    )
    assert bridge._ERROR_DETAIL_LEVEL == "basic"
    assert bridge._MAX_RPC_REQUEST_BYTES == 1048576
    assert bridge._MAX_RPC_RESPONSE_BYTES == 256 * 1024 * 1024
    assert bridge._trim_text(5) == 5
    assert bridge._trim_text("abcdef", 3).endswith("chars)")
    assert bridge._compact_detail_value("x" * 400)[1] == 0
    assert bridge._compact_detail_value(list(range(20)))[1] == 4
    assert bridge._compact_error_details(None) is None
    assert bridge._compact_error_details({"x": 1}) == {"x": 1}
    monkeypatch.setattr(bridge, "_ERROR_DETAIL_LEVEL", "full")
    assert bridge._compact_error_details({"traceback": "kept"})["traceback"] == "kept"
    monkeypatch.setattr(bridge, "_ERROR_DETAIL_LEVEL", "none")
    assert bridge._compact_error_details({"x": 1}) is None

    callbacks = []
    monkeypatch.setattr(bridge.sys, "settrace", callbacks.append)
    monkeypatch.setattr(bridge.threading, "settrace", callbacks.append)
    monkeypatch.setenv("IDA_MCP_LIVE_COVERAGE", "1")
    monkeypatch.delenv("IDA_MCP_LIVE_TRACE_FILE", raising=False)
    monkeypatch.setenv("IDA_MCP_LIVE_COVERAGE_FILE", str(tmp_path / "coverage"))
    trace = bridge._start_live_trace()
    assert trace[0].endswith(".ida-trace") and len(callbacks) == 2
    monkeypatch.delenv("IDA_MCP_LIVE_COVERAGE_FILE", raising=False)
    assert bridge._start_live_trace() is None

    monkeypatch.setattr(bridge, "_LIVE_TRACE", (str(tmp_path / "trace"), {"x.py": {1}}))
    monkeypatch.setattr(
        builtins,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    bridge._save_live_trace()


def test_bridge_introspection_and_package_loading_fallbacks(tmp_path, monkeypatch):
    bridge = _load_bridge(tmp_path, monkeypatch)
    assert bridge._canonical_tool_name("governance") == "governance_engine"
    assert bridge._canonical_tool_name(3) == 3
    assert bridge._extract_literal(Annotated[Literal["a", "b"], "desc"]) == ["a", "b"]
    assert bridge._extract_literal(str) is None
    assert bridge._tool_signature_info(object()) == {"params": [], "required": [], "actions": []}

    def action_tool(action: Annotated[Literal["read", "write"], "action"]):
        return action

    action_tool.__annotations__ = {"action": Annotated[Literal["read", "write"], "action"]}
    info = bridge._tool_signature_info(action_tool)
    assert info["params"] == ["action"] and info["actions"] == ["read", "write"]
    assert bridge._suggest_choice("reed", ["read"]) == "read"
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", None)
    assert bridge._suggest_choice("reed", ["read"]) == "read"

    bridge.TOOLS["cached"] = lambda: {"ok": True}
    tool, name, error = bridge._try_load_single_tool("cached")
    assert tool() == {"ok": True} and name == "cached" and error is None
    existing = sys.modules.get("ida_mcp")
    if existing is None:
        existing = types.ModuleType("ida_mcp")
        monkeypatch.setitem(sys.modules, "ida_mcp", existing)
    monkeypatch.delattr(existing, "__path__", raising=False)
    bridge._ensure_ida_mcp_packages()
    assert hasattr(existing, "__path__")


def test_process_single_auth_startup_shutdown_and_result_shapes(tmp_path, monkeypatch):
    bridge = _load_bridge(tmp_path, monkeypatch)
    assert bridge.process_single(None)["code"] == "INVALID_REQUEST"
    ping = bridge.process_single({"type": "ping"})
    assert ping["pong"] is True and ping["analyzing"] is False
    assert bridge.process_single({"tool": "x", "args": {}})["code"] == "UNAUTHORIZED"
    monkeypatch.setattr(bridge, "_SESSION_TOKEN", "secret")
    assert bridge.process_single({"tool": "x", "session_token": "bad", "args": {}})["code"] == "UNAUTHORIZED"
    assert bridge.process_single({"session_token": "secret", "args": {}})["code"] == "INVALID_REQUEST"
    assert bridge.process_single({"tool": "x", "session_token": "secret", "args": []})["code"] == "INVALID_ARGS"

    bridge._STARTUP_DONE.clear()
    result = bridge.process_single({"tool": "x", "session_token": "secret", "args": {}})
    assert result["code"] == "ANALYSIS_INCOMPLETE"
    bridge._STARTUP_DONE.set()
    bridge._SHUTDOWN_EVENT.clear()
    bridge.log_ev = lambda _message: None
    loader = types.ModuleType("ida_loader")
    loader.save_database = lambda *_args: True
    monkeypatch.setitem(sys.modules, "ida_loader", loader)
    result = bridge.process_single({"type": "shutdown", "session_token": "secret"})
    assert result["saved"] is True and bridge._SHUTDOWN_EVENT.is_set()

    bridge._SHUTDOWN_EVENT.clear()
    bridge.TOOLS["user"] = lambda value=1: {"ok": True, "value": value}
    assert bridge.process_single({"tool": "user", "session_token": "secret", "args": {"value": 7}})["value"] == 7


def test_process_single_action_hints_and_exception_classification(tmp_path, monkeypatch):
    bridge = _load_bridge(tmp_path, monkeypatch)
    monkeypatch.setattr(bridge, "_SESSION_TOKEN", "secret")
    def action_tool(action):
        return {"ok": True, "action": action}
    action_tool.__annotations__ = {"action": Annotated[Literal["read", "write"], "action"]}
    bridge.TOOLS["action"] = action_tool
    result = bridge.process_single({"tool": "action", "session_token": "secret", "args": {"action": "reed"}})
    assert result["code"] == "INVALID_ARGS" and result["details"]["suggested_action"] == "read"

    def malformed(value):
        raise TypeError("unexpected keyword argument 'value'")

    bridge.TOOLS["malformed"] = malformed
    result = bridge.process_single({"tool": "malformed", "session_token": "secret", "args": {"value": 1}})
    assert result["code"] == "INVALID_ARGS"
    assert result["details"]["unexpected_arg"] == "value"

    def missing(value):
        raise TypeError("missing 1 required positional argument: 'value'")

    bridge.TOOLS["missing"] = missing
    result = bridge.process_single({"tool": "missing", "session_token": "secret", "args": {}})
    assert result["details"]["missing_arg"] == "value"

    bridge.TOOLS["raw_error"] = lambda: {"error": True, "code": "INVALID_ARGS", "details": {"raw_request": "secret", "items": list(range(20))}}
    result = bridge.process_single({"tool": "raw_error", "session_token": "secret", "args": {}})
    assert "raw_request" not in result["details"] and result["details"]["items_more"] == 4


def test_protocol_helpers_and_inline_dispatch_fallbacks(tmp_path, monkeypatch):
    bridge = _load_bridge(tmp_path, monkeypatch)
    assert bridge._recv_exact(types.SimpleNamespace(recv=lambda _n: b""), 2) is None
    assert bridge._recv_exact(types.SimpleNamespace(recv=lambda _n: b"ab"), 2) == b"ab"
    monkeypatch.setenv("IDA_MCP_PORT", "bad")
    assert bridge._resolve_port() == 13337
    monkeypatch.setenv("IDA_MCP_PORT", "70000")
    assert bridge._resolve_port() == 13337
    monkeypatch.setenv("IDA_MCP_PORT", "0")
    assert bridge._resolve_port() == 0
    assert bridge._rpc_handled_inline(None) is True
    assert bridge._rpc_handled_inline({"type": "ping"}) is True
    bridge._STARTUP_DONE.set()
    assert bridge._rpc_handled_inline({"tool": "x"}) is False

    monkeypatch.setattr(bridge, "_TOOL_DISPATCH_TIMEOUT_S", 0.001)
    result = bridge._dispatch_on_main_thread({"tool": "x"})
    assert result["code"] == "INTERNAL"
    bridge.TOOLS["queue_tool"] = lambda: {"ok": True}
    bridge._TOOL_QUEUE.put(({"tool": "queue_tool", "session_token": "", "args": {}}, __import__("queue").Queue(maxsize=1)))
    bridge._drain_tool_queue()


def test_run_main_flow_is_exercised_without_an_ida_runtime(tmp_path, monkeypatch):
    """Exercise the real ``__main__`` orchestration with inert thread/IDA fakes."""
    monkeypatch.setenv("IDA_MCP_SESSION_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("IDA_MCP_USE_EXISTING_IDB", "1")
    monkeypatch.delenv("IDA_MCP_SESSION_TOKEN", raising=False)
    for name in ("ida_segment", "idautils", "idc"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    auto = types.ModuleType("ida_auto")
    auto.auto_wait = lambda: None
    monkeypatch.setitem(sys.modules, "ida_auto", auto)
    loader = types.ModuleType("ida_loader")
    loader.save_database = lambda *_args: True
    monkeypatch.setitem(sys.modules, "ida_loader", loader)

    class InertThread:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        def start(self):
            return None

        def is_alive(self):
            return False

        def join(self, **_kwargs):
            return None

    monkeypatch.setattr(threading, "Thread", InertThread)
    original_listdir = __import__("os").listdir
    monkeypatch.setattr(
        __import__("os"),
        "listdir",
        lambda path: [] if str(path).endswith("/tools") else original_listdir(path),
    )
    namespace = runpy.run_path(str(_SERVER_SCRIPT), run_name="__main__")
    assert namespace["_STARTUP_DONE"].is_set()
