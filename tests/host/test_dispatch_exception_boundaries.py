"""Cover dispatch exception, policy, and filesystem boundary behavior."""

from __future__ import annotations

from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.host.server import server_dispatch as dispatch_mod
from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin
from tests.host.test_dispatch_pipeline_modes import _DispatchHost
from tests.host.test_p04_dispatch import _Harness


def test_long_running_timeout_handles_invalid_full_index_and_requested_values(monkeypatch):
    monkeypatch.setenv("IDA_MCP_RPC_MAX_RECV_TIMEOUT", "bad")
    monkeypatch.setenv("IDA_MCP_RPC_TIMEOUT", "bad")
    monkeypatch.setenv("IDA_MCP_FULL_INDEX_RPC_TIMEOUT", "bad")
    assert dispatch_mod._long_running_sock_timeout(
        "intelligence", {"action": "index_batch"}
    ) == 600
    assert dispatch_mod._long_running_sock_timeout(
        "search", {"action": "nl", "timeout": "not-an-int"}
    ) == 120


def test_call_tool_maps_schema_connection_and_timeout_configuration_failures(monkeypatch):
    host = _DispatchHost()
    schema_error = make_error(MCPError.INVALID_ARGS, "unknown argument")
    monkeypatch.setattr(dispatch_mod, "prepare_rpc_args", lambda *_args: schema_error)
    assert host.call_tool("idb", "target", action="overview")["code"] == MCPError.INVALID_ARGS

    host = _DispatchHost()
    monkeypatch.setattr(dispatch_mod, "prepare_rpc_args", lambda _tool, args, _schemas: args)
    host._send_rpc_with_retry = lambda *_args, **_kwargs: (_ for _ in ()).throw(ConnectionResetError("closed"))
    assert host.call_tool("idb", "target", action="overview")["code"] == MCPError.RPC_CONNECTION_ERROR

    host = _DispatchHost()
    monkeypatch.setattr(dispatch_mod, "prepare_rpc_args", lambda _tool, args, _schemas: args)
    monkeypatch.setenv("IDA_MCP_RPC_TIMEOUT", "not-an-int")
    host._send_rpc_with_retry = lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("slow"))
    timeout = host.call_tool("idb", "target", action="overview")
    assert timeout["code"] == MCPError.IDA_TIMEOUT
    assert timeout["details"]["rpc_timeout_sec"] == 30


def test_call_tool_outer_wallclock_timeout_terminates_live_process(monkeypatch):
    host = _DispatchHost()
    monkeypatch.setattr(dispatch_mod, "prepare_rpc_args", lambda _tool, args, _schemas: args)
    monkeypatch.setenv("IDA_MCP_RPC_HARD_WALLCLOCK_SEC", "30")
    monkeypatch.setattr(dispatch_mod.time, "time", iter([0.0, 0.0, 40.0, 40.0]).__next__)
    host._send_rpc_with_retry = lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("hung"))
    result = host.call_tool("idb", "target", action="overview")
    assert result["code"] == MCPError.IDA_TIMEOUT
    assert host.process.terminated is True


def test_call_tool_swallows_postprocess_pipeline_failure(monkeypatch):
    host = _DispatchHost()
    host._pending_pp = {"limit": 2}
    monkeypatch.setattr(dispatch_mod, "prepare_rpc_args", lambda _tool, args, _schemas: args)
    monkeypatch.setattr(dispatch_mod, "has_post_process", lambda _pp: True)
    monkeypatch.setattr(
        dispatch_mod,
        "apply_post_processing",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad filter")),
    )
    result = host.call_tool("idb", "target", action="overview")
    assert result == {"answer": 1, "ok": True}


def test_memory_filesystem_rejects_invalid_realpath_and_symlink_after_canonicalization(
    monkeypatch, tmp_path
):
    class _MemoryHost(ServerDispatchMixin):
        def _memory_allow_root(self):
            return str(tmp_path)

    host = _MemoryHost()
    # os.path is shared by pytest itself, so scope this fault injection tightly
    # to the production call and restore it before any assertion rendering.
    with monkeypatch.context() as scoped:
        scoped.setattr(
            dispatch_mod.os.path,
            "abspath",
            lambda *_args: (_ for _ in ()).throw(ValueError("bad path")),
        )
        result = host._handle_memory_filesystem({"action": "read_file", "path": "x"})
    assert result["code"] == MCPError.INVALID_ARGS

    host = _MemoryHost()
    host._memory_path_has_symlink = lambda *_args: False
    assert host._handle_memory_filesystem({"action": "read_file", "path": "../outside"})["code"] == MCPError.INVALID_ARGS

    host = _MemoryHost()
    calls = []

    def symlink_on_canonical(*_args):
        calls.append(True)
        return len(calls) > 1

    host._memory_path_has_symlink = symlink_on_canonical
    assert host._handle_memory_filesystem({"action": "read_file", "path": "inside"})["code"] == MCPError.INVALID_ARGS
    assert len(calls) == 2


def test_dispatch_inner_handles_normalization_policy_and_guardrail_failures(monkeypatch):
    class _NormalizeError(_Harness):
        def _normalize_tool_call_args(self, _tool, _args):
            return make_error(MCPError.INVALID_ARGS, "normalization failed")

    assert _NormalizeError()._execute_tool_inner("search", "search", {})["code"] == MCPError.INVALID_ARGS

    h = _Harness()
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "assist")
    monkeypatch.setattr(
        dispatch_mod,
        "evaluate_policy",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("policy unavailable")),
    )
    denied = h._execute_tool_inner("search", "search", {"action": "find"})
    assert denied["code"] == MCPError.POLICY_DENIED

    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "off")
    h = _Harness()
    h._guardrail_strict_gate = lambda *_args: make_error(MCPError.INVALID_ARGS, "guardrail blocked")
    blocked = h._execute_tool_inner("search", "search", {"action": "find"})
    assert blocked["code"] == MCPError.INVALID_ARGS


def test_dispatch_inner_stuck_loop_gate_returns_recoverable_nudge(monkeypatch):
    class _Drift:
        def check(self, _sid):
            return [{"type": "LOOP", "severity": "warning", "message": "repeat"}]

    class _Usage:
        drift = _Drift()

        @staticmethod
        def is_running():
            return True

    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "off")
    monkeypatch.setenv("IDA_MCP_STUCK_LOOP_BLOCK", "1")
    host = _Harness()
    host._usage_intel = _Usage()
    result = host._execute_tool_inner("search", "search", {"action": "find"})
    assert result["code"] == MCPError.STUCK_LOOP
    assert result["_nudge"]["type"] == "stuck"
