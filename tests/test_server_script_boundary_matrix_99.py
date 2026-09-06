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
from unittest.mock import MagicMock, patch

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
    name = "ida_pro_mcp.server_script"
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


def test_tool_loading_and_introspection_edges(tmp_path, monkeypatch):
    bridge = _load_bridge(tmp_path, monkeypatch)

    # Line 267-269: module has canonical tool callable
    mod = types.ModuleType("ida_mcp.tools.fake_tool")
    mod.fake_tool = lambda: {"ok": True}
    monkeypatch.setitem(sys.modules, "ida_mcp.tools.fake_tool", mod)
    tool_func, name, err = bridge._try_load_single_tool("fake_tool")
    assert tool_func() == {"ok": True} and name == "fake_tool" and err is None

    # Line 283, 289-290, 293, 295-296: load_tools edge cases
    fake_tools_dir = tmp_path / "tools"
    fake_tools_dir.mkdir(parents=True, exist_ok=True)
    (fake_tools_dir / "not_py.txt").write_text("ignored")
    (fake_tools_dir / "__init__.py").write_text("")
    (fake_tools_dir / "broken.py").write_text("syntax error !!!")
    monkeypatch.setattr(bridge, "_tools_root", str(fake_tools_dir))
    bridge.load_tools()

    with patch("os.listdir", side_effect=RuntimeError("listdir fail")):
        bridge.load_tools()

    # Line 325-326: _tool_signature_info exception on annotations
    def valid_func(x: int = 1):
        return x

    class BadDict(dict):
        def __contains__(self, key):
            raise RuntimeError("contains err")

    valid_func.__annotations__ = BadDict()
    assert bridge._tool_signature_info(valid_func)["actions"] == []


def test_process_single_dynamic_loading_and_empty_details(tmp_path, monkeypatch):
    bridge = _load_bridge(tmp_path, monkeypatch)
    monkeypatch.setattr(bridge, "_SESSION_TOKEN", "secret")
    bridge._STARTUP_DONE.set()

    # Line 480-482: dynamically load tool inside process_single
    bridge.TOOLS.clear()
    mod = types.ModuleType("ida_mcp.tools.on_demand")
    mod.on_demand = lambda: {"ok": True, "loaded": True}
    monkeypatch.setitem(sys.modules, "ida_mcp.tools.on_demand", mod)
    res = bridge.process_single({"tool": "on_demand", "session_token": "secret", "args": {}})
    assert res.get("loaded") is True

    # Line 553: empty details dictionary popped
    bridge.TOOLS["empty_details"] = lambda: {"error": True, "code": "INVALID_ARGS", "details": {}}
    res_err = bridge.process_single({"tool": "empty_details", "session_token": "secret", "args": {}})
    assert "details" not in res_err


def test_drain_tool_queue_exception_propagation(tmp_path, monkeypatch):
    bridge = _load_bridge(tmp_path, monkeypatch)
    import queue
    q = queue.Queue(maxsize=1)
    bridge._TOOL_QUEUE.put(({"tool": "crasher"}, q))
    monkeypatch.setattr(bridge, "process_single", lambda _req: (_ for _ in ()).throw(RuntimeError("drain crash")))
    bridge._drain_tool_queue()
    err_res = q.get_nowait()
    assert err_res["code"] == "INTERNAL"


def test_apply_pre_analysis_options_exhaustive_edges(tmp_path, monkeypatch):
    bridge = _load_bridge(tmp_path, monkeypatch)
    ida_ida = types.ModuleType("ida_ida")
    ida_loader = types.ModuleType("ida_loader")
    ida_idp = types.ModuleType("ida_idp")
    idaapi = types.ModuleType("idaapi")
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
    monkeypatch.setitem(sys.modules, "ida_loader", ida_loader)
    monkeypatch.setitem(sys.modules, "ida_idp", ida_idp)
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    # Line 887-888: bitness exception
    ida_ida.inf_set_app_bitness = lambda _b: (_ for _ in ()).throw(RuntimeError("bitness err"))
    # Line 904: invalid endian
    # Line 907-908: endian exception
    # Line 919-920: stack_size exception
    ida_ida.inf_set_be = lambda _b: (_ for _ in ()).throw(RuntimeError("be err"))
    ida_ida.inf_set_ssize = lambda _s: (_ for _ in ()).throw(RuntimeError("ssize err"))
    # Line 936-937: ida_idp.process_config_directive
    ida_idp.process_config_directive = lambda _opt: True
    # Line 962-965, 971-972: inf_set_mtype
    ida_ida.inf_set_mtype = lambda _m: False

    opts = {
        "bitness": 32,
        "endian": "invalid_val",
        "stack_size": 4096,
        "processor_options": "armv8",
        "memory_model": 1,
        "loader_options": {"opt": 1},
        "loader": "bin",
        "processor": "arm",
    }
    monkeypatch.setenv("IDA_MCP_PRE_ANALYSIS_OPTS", json.dumps(opts))
    bridge._apply_pre_analysis_options()

    # Line 963: inf_set_mtype returns True
    opts_mtype = {"memory_model": 1}
    ida_ida.inf_set_mtype = lambda _m: True
    monkeypatch.setenv("IDA_MCP_PRE_ANALYSIS_OPTS", json.dumps(opts_mtype))
    bridge._apply_pre_analysis_options()

    # Test endian exception and mtype exception
    opts2 = {"endian": "be", "memory_model": 2}
    ida_ida.inf_set_mtype = lambda _m: (_ for _ in ()).throw(RuntimeError("mtype err"))
    monkeypatch.setenv("IDA_MCP_PRE_ANALYSIS_OPTS", json.dumps(opts2))
    bridge._apply_pre_analysis_options()

    # Raw load segment and thumb fixes: lines 1004, 1010-1011, 1017-1018, 1024-1025, 1032-1037, 1047-1050
    idaapi.get_inf_structure = lambda: types.SimpleNamespace(filetype=0)
    idaapi.f_BIN = 0
    idaapi.SEG_CODE = 1
    idaapi.SEGPERM_EXEC = 4

    seg_obj = types.SimpleNamespace(start_ea=0x1000, type=0, perm=0, bitness=2)
    idaapi.getseg = lambda ea: seg_obj if ea == 0x1000 else None
    idautils = sys.modules["idautils"]
    idautils.Segments = lambda: [0x1000, 0x2000]

    ida_segment = sys.modules["ida_segment"]
    ida_segment.get_segm_class = lambda _s: "DATA"
    ida_segment.set_segm_class = lambda _s, _c: (_ for _ in ()).throw(RuntimeError("class err"))
    ida_segment.update_segm = lambda _s: (_ for _ in ()).throw(RuntimeError("update err"))
    # Line 1035: set_segm_addressing succeeds
    ida_segment.set_segm_addressing = lambda _s, _b: True

    idc = sys.modules["idc"]
    idc.split_sreg_range = lambda *_a: (_ for _ in ()).throw(RuntimeError("sreg err"))

    opts_raw = {"loader": "bin", "processor": "arm", "bitness": 32}
    monkeypatch.setenv("IDA_MCP_PRE_ANALYSIS_OPTS", json.dumps(opts_raw))
    bridge._apply_pre_analysis_options()


def test_bounded_auto_wait_and_startup_analysis_edges(tmp_path, monkeypatch):
    bridge = _load_bridge(tmp_path, monkeypatch)
    ida_auto = types.ModuleType("ida_auto")
    monkeypatch.setitem(sys.modules, "ida_auto", ida_auto)

    # Line 1094-1095: auto_wait raises in no-get_auto_state
    ida_auto.auto_wait = lambda: (_ for _ in ()).throw(RuntimeError("wait err"))
    bridge._bounded_auto_wait()

    # Lines 1107-1108: get_auto_state raises and fallback auto_wait raises
    ida_auto.get_auto_state = lambda: (_ for _ in ()).throw(RuntimeError("state err"))
    bridge._bounded_auto_wait()

    # Lines 1112-1118: loop timeout
    ida_auto.AU_NONE = 0
    ida_auto.get_auto_state = lambda: 1
    bridge._bounded_auto_wait(timeout=0.01)

    # Startup analysis: Line 1143 (no auto_wait attribute)
    del ida_auto.auto_wait
    del ida_auto.get_auto_state
    bridge._run_startup_analysis()

    # Line 1155: shutdown requested during startup
    ida_auto.auto_wait = lambda: None
    bridge._SHUTDOWN_EVENT.set()
    bridge._run_startup_analysis()
    bridge._SHUTDOWN_EVENT.clear()

    # Lines 1173-1174, 1189-1194: reanalysis error and save_database
    ida_loader = types.ModuleType("ida_loader")
    ida_loader.save_database = lambda *_a: (_ for _ in ()).throw(RuntimeError("save err"))
    monkeypatch.setitem(sys.modules, "ida_loader", ida_loader)
    monkeypatch.setenv("IDA_MCP_USE_EXISTING_IDB", "0")
    monkeypatch.delenv("IDA_MCP_IDB_PATH", raising=False)
    bridge._run_startup_analysis()

    # Line 1190: save_database succeeds at empty path
    ida_loader.save_database = lambda *_a: True
    bridge._run_startup_analysis()

    # Line 1194: shutdown arrived during reanalysis
    analysis_mod = types.ModuleType("ida_pro_mcp.ida_mcp.tools.analysis")
    def _shutdown_during_reanalysis(*_args, **_kwargs):
        bridge._SHUTDOWN_EVENT.set()
        return {"scheduled": 1}

    analysis_mod._auto_reanalyze_text_segments = _shutdown_during_reanalysis
    analysis_mod._ensure_entry_point_functions = lambda: None
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.tools.analysis", analysis_mod)
    bridge._run_startup_analysis()
    bridge._SHUTDOWN_EVENT.clear()

    # Lines 1197-1199: outer exception in _run_startup_analysis
    monkeypatch.setattr(bridge, "_bounded_auto_wait", lambda: (_ for _ in ()).throw(RuntimeError("reanalysis crash")))
    bridge._run_startup_analysis()


def test_run_server_loop_socket_errors_and_batch(tmp_path, monkeypatch):
    bridge = _load_bridge(tmp_path, monkeypatch)

    # Line 690: server_sock.bind raises on port 0
    with patch("socket.socket") as mock_sock:
        mock_instance = MagicMock()
        mock_instance.bind.side_effect = OSError("port in use")
        mock_sock.return_value = mock_instance
        with pytest.raises(OSError):
            bridge.run_server()

    # Line 706-707: port file write error
    monkeypatch.setenv("IDA_MCP_PORT_FILE", str(tmp_path / "nonexistent_dir" / "port.txt"))

    # Line 717-718, 726, 764, 796-798, 803-804 in run_server:
    server_sock = MagicMock()
    conn = MagicMock()
    batch_bytes = json.dumps([{"type": "ping"}]).encode("utf-8")

    select_returns = [
        ([], [], []),
        ([server_sock], [], []),
        ([server_sock], [], []),
        ([server_sock], [], []),
        ([server_sock], [], []),
        ([server_sock], [], []),
    ]
    recv_side_effects = [
        # Iteration 2: raw_len is empty (line 726)
        b"",
        # Iteration 3: batch request (line 764)
        len(batch_bytes).to_bytes(4, "big"),
        batch_bytes,
        # Iteration 4: TimeoutError (line 796)
        TimeoutError("timed out"),
        # Iteration 5: generic Exception (line 798)
        ValueError("arbitrary error"),
        # Iteration 6: KeyboardInterrupt (line 797)
        KeyboardInterrupt(),
    ]
    conn.recv.side_effect = recv_side_effects
    conn.close.side_effect = RuntimeError("close err")  # lines 803-804
    server_sock.accept.return_value = (conn, ("127.0.0.1", 12345))

    with patch("socket.socket", return_value=server_sock), \
         patch("select.select", side_effect=select_returns):
        bridge._SHUTDOWN_EVENT.clear()
        bridge.run_server()


def test_main_execution_and_critical_module_error(tmp_path, monkeypatch):
    # Lines 99-101: Critical error importing IDA modules
    p = _SERVER_SCRIPT.resolve()
    lines = p.read_text("utf-8").splitlines()
    early_lines = "\n".join(lines[:102])
    early_code = compile(early_lines, str(p), "exec")

    class FailImport:
        def find_spec(self, name, *args):
            if name in ("ida_segment", "idautils", "idc"):
                raise ImportError("no ida")

    monkeypatch.setattr(sys, "meta_path", [FailImport()] + list(sys.meta_path))
    monkeypatch.delitem(sys.modules, "ida_segment", raising=False)
    monkeypatch.delitem(sys.modules, "idautils", raising=False)
    monkeypatch.delitem(sys.modules, "idc", raising=False)
    monkeypatch.setattr(sys, "exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))

    with pytest.raises(SystemExit):
        exec(early_code, {"__file__": str(p), "sys": sys, "os": __import__("os"), "time": __import__("time"), "log_ev": lambda _m: None})

    # Lines 1206-1250: main block execution
    for name in ("ida_segment", "idautils", "idc", "idaapi", "ida_name", "ida_auto", "ida_loader"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))

    code = compile(p.read_text("utf-8"), str(p), "exec")
    mod = types.ModuleType("ida_pro_mcp.server_script")
    mod.__file__ = str(p)
    mod.__name__ = "__main__"
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.server_script", mod)

    class InertThread:
        def __init__(self, *args, **kwargs):
            self._count = 1

        def start(self):
            pass

        def is_alive(self):
            if self._count > 0:
                self._count -= 1
                return True
            return False

        def join(self, **_kwargs):
            pass

    monkeypatch.setattr(threading, "Thread", InertThread)
    monkeypatch.setenv("IDA_MCP_USE_EXISTING_IDB", "1")
    monkeypatch.setenv("IDA_MCP_SESSION_LOG_DIR", str(tmp_path))

    exec(code, mod.__dict__)
    assert mod._STARTUP_DONE.is_set()
