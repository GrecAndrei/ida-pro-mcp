"""Additional protocol and startup-mode coverage for the IDA bridge."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

_SERVER_SCRIPT = Path(__file__).parents[1] / "src" / "ida_pro_mcp" / "server_script.py"


@pytest.fixture
def bridge(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_MCP_SESSION_LOG_DIR", str(tmp_path))
    monkeypatch.delenv("IDA_MCP_SESSION_TOKEN", raising=False)
    for name in ("ida_segment", "idautils", "idc"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    name = "ida_pro_mcp.server_script"
    spec = importlib.util.spec_from_file_location(name, _SERVER_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_process_single_rejects_protocol_shapes_and_load_failures(bridge, monkeypatch):
    monkeypatch.setattr(bridge, "_SESSION_TOKEN", "secret")
    bridge._STARTUP_DONE.set()
    bridge.TOOLS.clear()

    assert bridge.process_single({"session_token": "secret", "args": {}})["code"] == "INVALID_REQUEST"
    assert bridge.process_single({"tool": "analysis", "session_token": "secret", "args": []})["code"] == "INVALID_ARGS"
    missing = bridge.process_single({"tool": "does_not_exist", "session_token": "secret", "args": {}})
    assert missing["code"] == "TOOL_NOT_FOUND"
    assert missing["details"]["canonical_tool"] == "does_not_exist"

    def _tool(value=1):
        return {"ok": True, "value": value}

    bridge.TOOLS["plain"] = _tool
    assert bridge.process_single({"tool": "plain", "session_token": "secret", "args": {"value": 3}}) == {
        "ok": True,
        "value": 3,
    }

    def _error(**_kwargs):
        return {"error": True, "code": "INVALID_ARGS", "message": "x", "details": "detail text"}

    bridge.TOOLS["error_tool"] = _error
    result = bridge.process_single({"tool": "error_tool", "session_token": "secret", "args": {}})
    assert result["details"] == "detail text"


def test_process_single_covers_action_and_exception_classification(bridge, monkeypatch):
    from typing import Annotated, Literal

    monkeypatch.setattr(bridge, "_SESSION_TOKEN", "secret")
    bridge._STARTUP_DONE.set()

    def action_tool(action: Annotated[Literal["read", "write"], "operation"]):
        return {"ok": True, "action": action}

    action_tool.__annotations__ = {"action": Annotated[Literal["read", "write"], "operation"]}
    bridge.TOOLS["action_tool"] = action_tool
    invalid = bridge.process_single(
        {"tool": "action_tool", "session_token": "secret", "args": {"action": "other"}}
    )
    assert invalid["code"] == "INVALID_ARGS"
    assert invalid["details"]["available_actions"] == ["read", "write"]
    assert "suggested_action" not in invalid["details"]

    def required(value):
        return value

    bridge.TOOLS["required"] = required
    missing = bridge.process_single({"tool": "required", "session_token": "secret", "args": {}})
    assert missing["code"] == "INVALID_ARGS"
    assert missing["details"]["missing_arg"] == "value"
    assert missing["details"]["required_args"] == ["value"]

    def bad_type(value):
        raise TypeError(f"bad value: {value}")

    bridge.TOOLS["bad_type"] = bad_type
    typed = bridge.process_single(
        {"tool": "bad_type", "session_token": "secret", "args": {"value": object()}}
    )
    assert typed["code"] == "INVALID_ARGS"
    assert "TypeError" in typed["hint"]

    def broken(**_kwargs):
        raise ValueError("internal details")

    bridge.TOOLS["broken"] = broken
    internal = bridge.process_single({"tool": "broken", "session_token": "secret", "args": {}})
    assert internal["code"] == "UNKNOWN_ERROR"
    assert internal["hint"].startswith("Internal server error")


def test_bridge_error_and_shutdown_failures_are_safe(bridge, monkeypatch):
    monkeypatch.setattr(bridge, "_SESSION_TOKEN", "secret")
    loader = types.ModuleType("ida_loader")
    loader.save_database = lambda *_args: (_ for _ in ()).throw(OSError("read-only"))
    monkeypatch.setitem(sys.modules, "ida_loader", loader)
    monkeypatch.setenv("IDA_MCP_IDB_PATH", "/tmp/readonly.i64")
    bridge._STARTUP_DONE.set()
    bridge._SHUTDOWN_EVENT.clear()
    bridge.log_ev = lambda _message: None
    result = bridge.process_single({"type": "shutdown", "session_token": "secret"})
    assert result["ok"] is True and result["saved"] is False

    monkeypatch.setattr(bridge, "_ERROR_DETAIL_LEVEL", "basic")
    assert bridge._compact_error_details({"x": list(range(40)), "raw_request": "secret"})["x_more"] == 24
    monkeypatch.setattr(bridge, "_ERROR_DETAIL_LEVEL", "none")
    assert bridge._build_error("bridge", "hidden", details={"x": 1})["error"] is True


def test_pre_analysis_options_invalid_and_legacy_api_modes(bridge, monkeypatch):
    monkeypatch.setenv("IDA_MCP_PRE_ANALYSIS_OPTS", "not json")
    bridge._apply_pre_analysis_options()
    monkeypatch.setenv("IDA_MCP_PRE_ANALYSIS_OPTS", "{}")
    bridge._apply_pre_analysis_options()

    ida_ida = types.ModuleType("ida_ida")
    ida_loader = types.ModuleType("ida_loader")
    idaapi = types.ModuleType("idaapi")
    idaapi.SETPROC_LOADER = 1
    idaapi.f_BIN = 0
    idaapi.get_inf_structure = lambda: types.SimpleNamespace(procname="", filetype=9)
    idaapi.set_processor_type = lambda *_args: True
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
    monkeypatch.setitem(sys.modules, "ida_loader", ida_loader)
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setitem(sys.modules, "ida_idp", types.ModuleType("ida_idp"))
    services = types.ModuleType("ida_pro_mcp.services")
    services.normalize_arch_options = lambda *_args: (_ for _ in ()).throw(RuntimeError("normalizer unavailable"))
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    monkeypatch.setenv(
        "IDA_MCP_PRE_ANALYSIS_OPTS",
        json.dumps(
            {
                "processor": "mips",
                "bitness": "bad",
                "endian": "middle",
                "stack_size": "bad",
                "processor_options": "isa=mips32",
                "memory_model": 99,
                "loader": "elf",
                "loader_options": "x=y",
            }
        ),
    )
    bridge.log_ev = lambda _message: None
    bridge._apply_pre_analysis_options()


def test_pre_analysis_options_raw_segment_failures_and_option_fallback(bridge, monkeypatch):
    calls = []
    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_set_app_bitness = lambda value: calls.append(("bitness", value))
    ida_ida.inf_set_be = lambda value: calls.append(("be", value))
    ida_ida.inf_set_ssize = lambda value: calls.append(("stack", value))
    ida_loader = types.ModuleType("ida_loader")
    ida_loader.set_loader_options = lambda *_args: (_ for _ in ()).throw(OSError("loader failed"))
    idaapi = types.ModuleType("idaapi")
    idaapi.SETPROC_LOADER = 1
    idaapi.f_BIN = 0
    idaapi.SEG_CODE = 2
    idaapi.SEGPERM_EXEC = 1
    idaapi.get_inf_structure = lambda: types.SimpleNamespace(procname="other", filetype=0)
    idaapi.set_processor_type = lambda *_args: True
    seg = types.SimpleNamespace(start_ea=0x1000, type=0, perm=0, bitness=0)
    idaapi.getseg = lambda _ea: seg
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
    monkeypatch.setitem(sys.modules, "ida_loader", ida_loader)
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setitem(sys.modules, "ida_idp", types.ModuleType("ida_idp"))
    monkeypatch.setenv(
        "IDA_MCP_PRE_ANALYSIS_OPTS",
        json.dumps(
            {
                "processor": "arm",
                "bitness": 32,
                "endian": "little",
                "stack_size": 4096,
                "processor_options": "thumb=1",
                "memory_model": 0,
                "loader": "bin",
                "loader_options": {"base": "0x1000"},
            }
        ),
    )
    monkeypatch.setattr(bridge.idautils, "Segments", lambda: iter([0x1000, 0x2000]), raising=False)
    monkeypatch.setattr(bridge.ida_segment, "get_segm_class", lambda _seg: "DATA", raising=False)
    monkeypatch.setattr(bridge.ida_segment, "set_segm_class", lambda *_args: (_ for _ in ()).throw(OSError("class failed")), raising=False)
    monkeypatch.setattr(bridge.ida_segment, "update_segm", lambda _seg: (_ for _ in ()).throw(OSError("update failed")), raising=False)
    monkeypatch.setattr(bridge.idc, "set_processor_options", lambda _value: (_ for _ in ()).throw(AttributeError("legacy missing")), raising=False)
    monkeypatch.setattr(bridge.idc, "split_sreg_range", lambda *_args: (_ for _ in ()).throw(OSError("sreg failed")), raising=False)
    bridge.log_ev = lambda _message: None
    bridge._apply_pre_analysis_options()
    assert ("bitness", 32) in calls and ("be", False) in calls and ("stack", 4096) in calls


def test_bounded_auto_wait_timeout_and_state_fallbacks(bridge, monkeypatch):
    class BrokenAuto:
        AU_NONE = 0

        def get_auto_state(self):
            raise RuntimeError("state unavailable")

        def auto_wait(self):
            raise RuntimeError("wait failed")

    monkeypatch.setitem(sys.modules, "ida_auto", BrokenAuto())
    bridge.log_ev = lambda _message: None
    bridge._bounded_auto_wait(5)

    class RunningAuto:
        AU_NONE = 0

        def get_auto_state(self):
            return 1

    monkeypatch.setitem(sys.modules, "ida_auto", RunningAuto())
    ticks = iter([0.0, 10.0, 20.0])
    monkeypatch.setattr(bridge.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(bridge.time, "sleep", lambda _seconds: None)
    bridge._bounded_auto_wait(5)
