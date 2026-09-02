"""Protocol-level coverage for the IDA-side bridge in every startup mode."""

from __future__ import annotations

import importlib.util
import inspect
import json
import queue
import sys
import types

import pytest

_SERVER_SCRIPT = __import__("pathlib").Path(__file__).parents[1] / "src" / "ida_pro_mcp" / "server_script.py"


@pytest.fixture
def bridge(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_MCP_SESSION_LOG_DIR", str(tmp_path))
    monkeypatch.delenv("IDA_MCP_SESSION_TOKEN", raising=False)
    for name in ("ida_segment", "idautils", "idc"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    name = f"ida_pro_mcp_server_surface_{id(tmp_path)}"
    spec = importlib.util.spec_from_file_location(name, _SERVER_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_bridge_normalizers_and_framing_cover_short_and_partial_inputs(bridge):
    assert bridge._trim_text("abc", 4) == "abc"
    assert bridge._trim_text("abcdef", 3) == "abc...(+3 chars)"
    assert bridge._compact_detail_value(list(range(20)), 3) == ([0, 1, 2], 17)
    assert bridge._compact_detail_value("x" * 400)[1] == 0
    assert bridge._canonical_tool_name("governance") == "governance_engine"
    assert bridge._canonical_tool_name(42) == 42

    class _Conn:
        def __init__(self, chunks):
            self.chunks = iter(chunks)

        def recv(self, _size):
            return next(self.chunks)

    assert bridge._recv_exact(_Conn([b"ab", b"cd"]), 4) == b"abcd"
    assert bridge._recv_exact(_Conn([b"ab", b""]), 4) is None
    assert bridge._resolve_port() == 13337

    assert bridge._rpc_handled_inline({"type": "ping"})
    bridge._STARTUP_DONE.clear()
    assert bridge._rpc_handled_inline({"tool": "analysis"})
    bridge._STARTUP_DONE.set()
    assert not bridge._rpc_handled_inline({"tool": "analysis"})
    assert bridge._rpc_handled_inline(None)


def test_process_single_auth_startup_shutdown_and_protocol_errors(bridge, monkeypatch):
    bridge._BOUND_PORT = 4321
    assert bridge.process_single({"type": "ping"})["port"] == 4321
    assert bridge.process_single(None)["code"] == "INVALID_REQUEST"
    assert bridge.process_single({"tool": "analysis"})["code"] == "UNAUTHORIZED"

    monkeypatch.setattr(bridge, "_SESSION_TOKEN", "secret")
    # Keep this protocol test independent of the real IDA module loader: the
    # fixture intentionally provides only minimal SDK stubs.
    bridge.TOOLS["analysis"] = lambda action: {"ok": True, "action": action}
    assert bridge.process_single({"tool": "analysis", "session_token": "bad"})["code"] == "UNAUTHORIZED"
    assert bridge.process_single({"tool": "analysis", "args": [], "session_token": "secret"})["code"] == "INVALID_ARGS"
    assert bridge.process_single({"tool": "analysis", "args": {}, "session_token": "secret"})["code"] == "INVALID_ARGS"
    invalid = bridge.process_single({"tool": "analysis", "args": {}, "session_token": "secret"})
    assert invalid["code"] == "INVALID_ARGS"
    assert "available_args" in invalid.get("details", {})

    bridge._STARTUP_DONE.clear()
    gated = bridge.process_single({"tool": "analysis", "args": {}, "session_token": "secret"})
    assert gated["code"] == "ANALYSIS_INCOMPLETE" and gated["recoverable"] is True
    bridge._STARTUP_DONE.set()

    saved = []
    loader = types.ModuleType("ida_loader")
    loader.save_database = lambda path, flags: saved.append((path, flags)) or True
    monkeypatch.setitem(sys.modules, "ida_loader", loader)
    monkeypatch.setenv("IDA_MCP_IDB_PATH", "/tmp/session.i64")
    shutdown = bridge.process_single({"type": "shutdown", "session_token": "secret"})
    assert shutdown == {"ok": True, "shutdown": True, "saved": True, "analysis_complete": True}
    assert saved == [("/tmp/session.i64", 0)]


def test_process_single_loads_alias_validates_actions_and_compacts_errors(bridge, monkeypatch):
    monkeypatch.setattr(bridge, "_SESSION_TOKEN", "secret")

    def _tool(action: inspect.Parameter, value=0):
        return {"ok": True, "action": action, "value": value}

    _tool.__annotations__ = {"action": __import__("typing").Literal["read", "write"]}
    bridge.TOOLS.clear()
    bridge.TOOLS["governance_engine"] = _tool
    ok = bridge.process_single({"tool": "governance", "args": {"action": "read"}, "session_token": "secret"})
    assert ok["ok"] is True
    bad = bridge.process_single({"tool": "governance", "args": {"action": "reed"}, "session_token": "secret"})
    assert bad["code"] == "INVALID_ARGS"
    assert bad["details"]["suggested_action"] == "read"

    def _bad(**_kwargs):
        return {
            "error": True,
            "code": "INVALID_ARGS",
            "message": "name required",
            "details": {"traceback": "secret", "values": list(range(30))},
        }

    bridge.TOOLS["bad"] = _bad
    result = bridge.process_single({"tool": "bad", "args": {}, "session_token": "secret"})
    assert result["details"]["values_more"] == 14
    assert "traceback" not in result["details"]
    assert result["details"]["missing_arg"] == "name"

    def _type_error(**_kwargs):
        raise TypeError("f() got an unexpected keyword argument 'vale'")

    bridge.TOOLS["typed"] = _type_error
    result = bridge.process_single({"tool": "typed", "args": {}, "session_token": "secret"})
    assert result["code"] == "INVALID_ARGS"
    assert result["details"]["unexpected_arg"] == "vale"

    def _runtime_error(**_kwargs):
        raise RuntimeError("private stack details")

    bridge.TOOLS["runtime"] = _runtime_error
    result = bridge.process_single({"tool": "runtime", "args": {}, "session_token": "secret"})
    assert result["code"] == "UNKNOWN_ERROR"
    assert "request arguments" in result["hint"]


def test_bridge_detail_modes_and_tool_loader_paths(bridge, monkeypatch, tmp_path):
    details = {"traceback": "hidden", "items": list(range(20))}
    monkeypatch.setattr(bridge, "_ERROR_DETAIL_LEVEL", "none")
    assert bridge._compact_error_details(details) is None
    monkeypatch.setattr(bridge, "_ERROR_DETAIL_LEVEL", "full")
    assert bridge._compact_error_details(details) == details
    monkeypatch.setattr(bridge, "_ERROR_DETAIL_LEVEL", "basic")
    assert "traceback" not in bridge._compact_error_details(details)

    tools_root = tmp_path / "tools"
    tools_root.mkdir()
    (tools_root / "demo.py").write_text("def demo(value=1): return {'value': value}\n", encoding="utf-8")
    (tools_root / "empty.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(bridge, "_tools_root", str(tools_root))
    import importlib

    demo_module = types.ModuleType("ida_mcp.tools.demo")
    demo_module.demo = lambda value=1: {"value": value}
    empty_module = types.ModuleType("ida_mcp.tools.empty")
    real_import_module = importlib.import_module

    def import_tool(name):
        if name.endswith(".demo"):
            return demo_module
        if name.endswith(".empty"):
            return empty_module
        return real_import_module(name)

    monkeypatch.setattr(importlib, "import_module", import_tool)
    bridge.TOOLS.clear()
    bridge.load_tools()
    assert "demo" in bridge.TOOLS
    loaded, canonical, error = bridge._try_load_single_tool("demo")
    assert loaded is bridge.TOOLS["demo"] and canonical == "demo" and error is None
    missing, _, error = bridge._try_load_single_tool("missing")
    assert missing is None and error


def test_bridge_signature_queue_and_dispatch_failures(bridge, monkeypatch):
    def sample(required, optional=1, **kwargs):
        return required

    sample.__annotations__ = {"action": __import__("typing").Literal["a", "b"]}
    info = bridge._tool_signature_info(sample)
    assert info["params"] == ["required", "optional"]
    assert info["required"] == ["required"]
    assert info["actions"] == ["a", "b"]
    assert bridge._tool_signature_info(object())["params"] == []

    bridge._TOOL_QUEUE.put(({"tool": "nope"}, queue.Queue(maxsize=1)))
    bridge._drain_tool_queue()
    assert bridge._TOOL_QUEUE.empty()

    monkeypatch.setattr(bridge, "_TOOL_DISPATCH_TIMEOUT_S", 0.001)
    result = bridge._dispatch_on_main_thread({"tool": "never-drained"})
    assert result["code"] == "INTERNAL"


def test_bridge_shutdown_startup_gate_and_json_safe_error(bridge, monkeypatch):
    bridge._STARTUP_DONE.clear()
    bridge._SHUTDOWN_EVENT.clear()
    result = bridge._handle_shutdown()
    assert result["saved"] is False and bridge._SHUTDOWN_EVENT.is_set()
    bridge._STARTUP_DONE.set()


def test_pre_analysis_options_apply_architecture_and_raw_blob_fixes(bridge, monkeypatch):
    """Exercise the complete pre-analysis option path used for raw firmware."""
    calls = []
    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_set_app_bitness = lambda value: calls.append(("bitness", value))
    ida_ida.inf_set_be = lambda value: calls.append(("be", value))
    ida_ida.inf_set_ssize = lambda value: calls.append(("stack", value))
    ida_ida.inf_set_mtype = lambda value: True
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)

    loader = types.ModuleType("ida_loader")
    loader.set_loader_options = lambda name, value: calls.append(("loader", name, value)) or True
    monkeypatch.setitem(sys.modules, "ida_loader", loader)

    info = types.SimpleNamespace(procname="metapc", filetype=0)
    seg = types.SimpleNamespace(start_ea=0x1000, type=0, perm=0, bitness=0)
    idaapi = types.ModuleType("idaapi")
    idaapi.SETPROC_LOADER = 1
    idaapi.SEG_CODE = 2
    idaapi.SEGPERM_EXEC = 1
    idaapi.f_BIN = 0
    idaapi.get_inf_structure = lambda: info
    idaapi.set_processor_type = lambda name, flags: calls.append(("processor", name, flags)) or True
    idaapi.getseg = lambda _ea: seg
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    monkeypatch.setattr(bridge.idautils, "Segments", lambda: iter([0x1000]), raising=False)
    monkeypatch.setattr(bridge.ida_segment, "get_segm_class", lambda _seg: "DATA", raising=False)
    monkeypatch.setattr(bridge.ida_segment, "set_segm_class", lambda _seg, value: calls.append(("class", value)), raising=False)
    monkeypatch.setattr(bridge.ida_segment, "update_segm", lambda _seg: calls.append(("update",)), raising=False)
    monkeypatch.setattr(bridge.idc, "set_processor_options", lambda value: calls.append(("procopts", value)), raising=False)
    monkeypatch.setattr(bridge.idc, "split_sreg_range", lambda ea, reg, value, mode: calls.append(("thumb", ea, reg, value, mode)), raising=False)
    monkeypatch.setenv(
        "IDA_MCP_PRE_ANALYSIS_OPTS",
        '{"processor":"arm", "bitness":32, "endian":"big", "stack_size":4096, '
        '"processor_options":"thumb=1", "memory_model":99, "loader":"bin", '
        '"loader_options":{"base":"0x1000", "thumb":true}}',
    )
    monkeypatch.delenv("IDA_MCP_USE_EXISTING_IDB", raising=False)

    bridge._apply_pre_analysis_options()

    assert ("processor", "arm", 1) in calls
    assert ("bitness", 32) in calls
    assert ("be", True) in calls
    assert ("stack", 4096) in calls
    assert ("procopts", "thumb=1") in calls
    assert ("loader", "bin", "base=0x1000;thumb=True") in calls
    assert ("class", "CODE") in calls
    assert ("thumb", 0x1000, "T", 1, 2) in calls


def test_pre_analysis_options_skips_reused_idb_and_handles_missing_apis(bridge, monkeypatch):
    monkeypatch.setenv("IDA_MCP_PRE_ANALYSIS_OPTS", '{"processor":"riscv", "bitness":64}')
    monkeypatch.setenv("IDA_MCP_USE_EXISTING_IDB", "1")
    monkeypatch.delenv("IDA_MCP_FORCE_PRE_ANALYSIS_OPTS", raising=False)
    bridge._apply_pre_analysis_options()

    monkeypatch.setenv("IDA_MCP_FORCE_PRE_ANALYSIS_OPTS", "1")
    monkeypatch.setitem(sys.modules, "ida_ida", types.ModuleType("ida_ida"))
    monkeypatch.setitem(sys.modules, "ida_loader", types.ModuleType("ida_loader"))
    idaapi = types.ModuleType("idaapi")
    idaapi.SETPROC_LOADER = 1
    idaapi.f_BIN = 1
    idaapi.get_inf_structure = lambda: types.SimpleNamespace(procname="riscv", filetype=9)
    idaapi.set_processor_type = lambda *_args: True
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    bridge._apply_pre_analysis_options()


def test_bounded_auto_wait_covers_import_and_legacy_fallbacks(bridge, monkeypatch):
    monkeypatch.delitem(sys.modules, "ida_auto", raising=False)
    bridge._bounded_auto_wait(5)

    class LegacyAuto:
        def auto_wait(self):
            self.called = True

    legacy = LegacyAuto()
    monkeypatch.setitem(sys.modules, "ida_auto", legacy)
    bridge._bounded_auto_wait(5)
    assert legacy.called is True

    class PollingAuto:
        AU_NONE = 0

        def __init__(self):
            self.states = iter([1, 0])

        def get_auto_state(self):
            return next(self.states)

    polling = PollingAuto()
    monkeypatch.setitem(sys.modules, "ida_auto", polling)
    monkeypatch.setattr(bridge.time, "sleep", lambda _seconds: None)
    bridge._bounded_auto_wait(5)


def test_run_startup_analysis_reanalyzes_and_saves_canonical_idb(bridge, monkeypatch):
    class Auto:
        AU_NONE = 0

        @staticmethod
        def auto_wait():
            return None

        @staticmethod
        def get_auto_state():
            return 0

    monkeypatch.setitem(sys.modules, "ida_auto", Auto())
    analysis = types.ModuleType("ida_pro_mcp.ida_mcp.tools.analysis")
    analysis._auto_reanalyze_text_segments = lambda **_kwargs: {
        "scheduled": 1,
        "functions_before": 1,
        "functions_after": 2,
        "defined_code_bytes_before": 4,
        "defined_code_bytes_after": 8,
        "coverage_pct_before": 10.0,
        "coverage_pct_after": 20.0,
    }
    analysis._ensure_entry_point_functions = lambda: None
    monkeypatch.setitem(sys.modules, analysis.__name__, analysis)
    saved = []
    loader = types.ModuleType("ida_loader")
    loader.save_database = lambda path, flags: saved.append((path, flags))
    monkeypatch.setitem(sys.modules, "ida_loader", loader)
    monkeypatch.setenv("IDA_MCP_IDB_PATH", "/tmp/canonical.i64")
    monkeypatch.delenv("IDA_MCP_USE_EXISTING_IDB", raising=False)
    bridge._SHUTDOWN_EVENT.clear()

    bridge._run_startup_analysis()

    assert saved == [("/tmp/canonical.i64", 0)]
    assert bridge._STARTUP_DONE.is_set() is True


def test_run_server_exercises_port_fallback_framing_and_response_limits(bridge, monkeypatch, tmp_path):
    payload = json.dumps({"type": "ping"}).encode("utf-8")

    class _Conn:
        def __init__(self, body):
            self.parts = iter([len(body).to_bytes(4, "big"), body])
            self.sent = []

        def settimeout(self, _seconds):
            return None

        def recv(self, _size):
            return next(self.parts, b"")

        def sendall(self, data):
            self.sent.append(data)
            bridge._SHUTDOWN_EVENT.set()

        def close(self):
            self.closed = True

    class _Socket:
        def __init__(self):
            self.bind_calls = []
            self.conn = _Conn(payload)

        def setsockopt(self, *_args):
            return None

        def setblocking(self, _value):
            return None

        def bind(self, address):
            self.bind_calls.append(address)
            if address[1] != 0:
                raise OSError("port already in use")

        def getsockname(self):
            return ("127.0.0.1", 43123)

        def listen(self, _backlog):
            return None

        def accept(self):
            return self.conn, ("127.0.0.1", 1)

    sock = _Socket()
    monkeypatch.setattr(bridge.socket, "socket", lambda *_args: sock)
    monkeypatch.setattr(bridge.select, "select", lambda *_args: ([sock], [], []))
    monkeypatch.setattr(bridge, "log_ev", lambda _msg: None)
    monkeypatch.setenv("IDA_MCP_PORT", "43122")
    port_file = tmp_path / "port"
    monkeypatch.setenv("IDA_MCP_PORT_FILE", str(port_file))
    bridge._SHUTDOWN_EVENT.clear()
    bridge._MAX_RPC_RESPONSE_BYTES = 256 * 1024 * 1024

    bridge.run_server()

    assert sock.bind_calls == [("127.0.0.1", 43122), ("127.0.0.1", 0)]
    assert bridge._BOUND_PORT == 43123
    assert port_file.read_text(encoding="ascii") == "43123"
    assert sock.conn.closed is True
    assert json.loads(sock.conn.sent[0][4:]) == bridge.process_single({"type": "ping"})


def test_run_server_handles_truncated_and_non_serializable_responses(bridge, monkeypatch):
    class _Conn:
        def __init__(self, chunks):
            self.chunks = iter(chunks)
            self.sent = []

        def settimeout(self, _seconds):
            return None

        def recv(self, _size):
            return next(self.chunks, b"")

        def sendall(self, data):
            self.sent.append(data)
            bridge._SHUTDOWN_EVENT.set()

        def close(self):
            self.closed = True

    class _Socket:
        def __init__(self, conn):
            self.conn = conn

        def setsockopt(self, *_args):
            return None

        def setblocking(self, _value):
            return None

        def bind(self, _address):
            return None

        def getsockname(self):
            return ("127.0.0.1", 43124)

        def listen(self, _backlog):
            return None

        def accept(self):
            return self.conn, ("127.0.0.1", 1)

    bridge._SHUTDOWN_EVENT.clear()
    truncated = _Conn([(20).to_bytes(4, "big"), b"short"])
    sock = _Socket(truncated)
    monkeypatch.setattr(bridge.socket, "socket", lambda *_args: sock)
    monkeypatch.setattr(bridge.select, "select", lambda *_args: ([sock], [], []))
    monkeypatch.setattr(bridge, "log_ev", lambda _msg: None)
    bridge.run_server()
    assert truncated.sent and json.loads(truncated.sent[0][4:])["code"] == "INVALID_REQUEST"

    bridge._SHUTDOWN_EVENT.clear()
    valid = json.dumps({"type": "ping"}).encode("utf-8")
    oversized = _Conn([len(valid).to_bytes(4, "big"), valid])
    sock = _Socket(oversized)
    monkeypatch.setattr(bridge.socket, "socket", lambda *_args: sock)
    bridge._MAX_RPC_RESPONSE_BYTES = 1
    bridge.run_server()
    assert json.loads(oversized.sent[0][4:])["code"] == "RESULT_TOO_LARGE"

    bridge._SHUTDOWN_EVENT.clear()
    invalid_size = _Conn([(
        bridge._MAX_RPC_REQUEST_BYTES + 1
    ).to_bytes(4, "big")])
    monkeypatch.setattr(bridge.socket, "socket", lambda *_args: _Socket(invalid_size))
    bridge._MAX_RPC_RESPONSE_BYTES = 256 * 1024 * 1024
    bridge.run_server()
    assert json.loads(invalid_size.sent[0][4:])["code"] == "REQUEST_TOO_LARGE"

    bridge._SHUTDOWN_EVENT.clear()
    serialisation_failure = _Conn([len(valid).to_bytes(4, "big"), valid])
    monkeypatch.setattr(bridge.socket, "socket", lambda *_args: _Socket(serialisation_failure))
    monkeypatch.setattr(bridge, "process_single", lambda _request: {"bad": {1}})
    bridge.run_server()
    assert json.loads(serialisation_failure.sent[0][4:])["code"] == "INTERNAL"
