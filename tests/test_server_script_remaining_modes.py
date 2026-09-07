"""Exercise remaining dependency-free bridge and startup boundary modes."""

from __future__ import annotations

import importlib.util
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


def test_bridge_suggestion_loader_and_error_detail_fallbacks(bridge, monkeypatch):
    assert bridge._suggest_choice("read", []) is None
    services = types.ModuleType("ida_pro_mcp.services")
    services.best_match = lambda value, choices, **_kwargs: [choices[0]] if value == "reed" else []
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    assert bridge._suggest_choice("reed", ["read"]) == "read"

    import importlib

    real_import = importlib.import_module
    empty = types.ModuleType("ida_mcp.tools.empty_tool")

    def import_tool(name):
        if name.endswith("empty_tool"):
            return empty
        if name.endswith("broken_tool"):
            raise ImportError("broken import")
        return real_import(name)

    monkeypatch.setattr(importlib, "import_module", import_tool)
    missing, canonical, error = bridge._try_load_single_tool("empty_tool")
    assert missing is None and canonical == "empty_tool" and "missing callable" in error
    missing, canonical, error = bridge._try_load_single_tool("broken_tool")
    assert missing is None and canonical == "broken_tool" and error == "broken import"

    monkeypatch.setattr(bridge, "_shared_make_error", None)
    fallback = bridge._build_error("bridge", "bad", details={"traceback": "secret", "items": list(range(20))}, hint="try")
    assert fallback["hint"] == "try" and "traceback" not in fallback["details"]
    assert bridge._compact_error_details("text") == "text"


def test_startup_timeout_and_bounded_auto_wait_modes(bridge, monkeypatch):
    monkeypatch.setenv("IDA_MCP_STARTUP_ANALYSIS_TIMEOUT", "bad")
    assert bridge._startup_analysis_timeout() == 120.0
    monkeypatch.setenv("IDA_MCP_STARTUP_ANALYSIS_TIMEOUT", "nan")
    assert bridge._startup_analysis_timeout() == 120.0
    monkeypatch.setenv("IDA_MCP_STARTUP_ANALYSIS_TIMEOUT", "1")
    assert bridge._startup_analysis_timeout() == 5.0
    monkeypatch.setenv("IDA_MCP_STARTUP_ANALYSIS_TIMEOUT", "9999")
    assert bridge._startup_analysis_timeout() == 600.0

    auto = types.ModuleType("ida_auto")
    calls = []
    auto.auto_wait = lambda: calls.append("wait")
    monkeypatch.setitem(sys.modules, "ida_auto", auto)
    bridge._bounded_auto_wait(5)
    assert calls == ["wait"]

    auto.get_auto_state = lambda: (_ for _ in ()).throw(RuntimeError("state"))
    bridge._bounded_auto_wait(5)
    assert calls == ["wait", "wait"]

    auto.AU_NONE = 0
    auto.get_auto_state = lambda: 0
    bridge._bounded_auto_wait(5)
    auto.get_auto_state = lambda: 1
    clock = iter([0.0, 0.0, 11.0])
    monkeypatch.setattr(bridge.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(bridge.time, "sleep", lambda _seconds: None)
    bridge.log_ev = lambda _message: None
    bridge._bounded_auto_wait(5)

    del auto.auto_wait
    bridge._bounded_auto_wait(5)


def test_startup_analysis_reuse_shutdown_and_import_failure_modes(bridge, monkeypatch):
    logs = []
    bridge.log_ev = logs.append
    auto = types.ModuleType("ida_auto")
    auto.auto_wait = lambda: logs.append("wait")
    monkeypatch.setitem(sys.modules, "ida_auto", auto)

    monkeypatch.setenv("IDA_MCP_USE_EXISTING_IDB", "1")
    bridge._STARTUP_ANALYSIS_ERROR = None
    bridge._SHUTDOWN_EVENT.clear()
    bridge._run_startup_analysis()
    assert bridge._STARTUP_DONE.is_set()
    assert any("reuse" in message for message in logs)

    logs.clear()
    monkeypatch.delenv("IDA_MCP_USE_EXISTING_IDB", raising=False)
    bridge._STARTUP_DONE.clear()
    bridge._SHUTDOWN_EVENT.set()
    bridge._run_startup_analysis()
    assert any("Shutdown requested" in message for message in logs)

    logs.clear()
    bridge._STARTUP_DONE.clear()
    bridge._SHUTDOWN_EVENT.clear()
    monkeypatch.delitem(sys.modules, "ida_auto", raising=False)
    bridge._run_startup_analysis()
    assert any("not importable" in message for message in logs)


def test_pre_analysis_option_warning_and_segment_failure_modes(bridge, monkeypatch):
    monkeypatch.setenv("IDA_MCP_PRE_ANALYSIS_OPTS", '{"processor":"arm", "bitness":32, "endian":"middle", "stack_size":"bad", "memory_model":9, "processor_options":"thumb=1", "loader":"bin", "loader_options":{"x": 1}}')
    monkeypatch.delenv("IDA_MCP_USE_EXISTING_IDB", raising=False)
    monkeypatch.setitem(sys.modules, "ida_ida", types.ModuleType("ida_ida"))
    monkeypatch.setitem(sys.modules, "ida_loader", types.ModuleType("ida_loader"))
    idaapi = types.ModuleType("idaapi")
    idaapi.SETPROC_LOADER = 1
    idaapi.f_BIN = 0
    idaapi.get_inf_structure = lambda: (_ for _ in ()).throw(RuntimeError("info"))
    idaapi.set_processor_type = lambda *_args: (_ for _ in ()).throw(RuntimeError("processor"))
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    services = types.ModuleType("ida_pro_mcp.services")
    services.normalize_arch_options = lambda *_args: (_ for _ in ()).throw(RuntimeError("normalize"))
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    bridge.log_ev = lambda _message: None
    bridge._apply_pre_analysis_options()

    monkeypatch.setenv("IDA_MCP_PRE_ANALYSIS_OPTS", "not json")
    bridge._apply_pre_analysis_options()
    monkeypatch.setenv("IDA_MCP_PRE_ANALYSIS_OPTS", "{}")
    bridge._apply_pre_analysis_options()
