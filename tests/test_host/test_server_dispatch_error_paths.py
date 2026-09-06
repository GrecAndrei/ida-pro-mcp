import os
import socket
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.host.config import _bounded_int, _coerce_bool
from ida_pro_mcp.host.errors import MCPError, is_error_result, make_error
from ida_pro_mcp.host.policy import (
    PolicyDecision,
    PolicyMode,
    ack_from_args,
    evaluate_policy,
    normalize_mode,
    strictest,
)
from ida_pro_mcp.host.server.postprocess import (
    PP_KEYS,
    apply_post_processing,
    has_post_process,
    prepare_args_for_postprocess,
)
from ida_pro_mcp.host.server.rate_limit import is_rate_limit_exempt
from ida_pro_mcp.host.server.server_args import ServerArgsMixin
from ida_pro_mcp.host.server.server_dispatch import (
    LONG_RUNNING_ACTIONS,
    SAFE_MODE_BLOCKED_ACTIONS,
    SAFE_MODE_BLOCKED_TOOLS,
    ServerDispatchMixin,
)
from ida_pro_mcp.host.server.server_runtime import RpcQueueTimeout


def test_bounded_int_and_coerce_bool() -> None:
    assert _bounded_int("10", default=5, min_value=1, max_value=20) == 10
    assert _bounded_int("100", default=5, min_value=1, max_value=20) == 20
    assert _bounded_int("-5", default=5, min_value=1, max_value=20) == 1
    assert _bounded_int("invalid", default=5, min_value=1, max_value=20) == 5

    assert _coerce_bool(True) is True
    assert _coerce_bool("true") is True
    assert _coerce_bool("1") is True
    assert _coerce_bool("yes") is True
    assert _coerce_bool(False) is False
    assert _coerce_bool("false") is False
    assert _coerce_bool("0") is False


def test_policy_tiers_and_risk_ack() -> None:
    # ack_from_args
    assert ack_from_args({"risk_ack": True}) is True
    assert ack_from_args({"risk_ack": "true"}) is True
    assert ack_from_args({"risk_ack": False}) is False
    assert ack_from_args({}) is False

    # normalize_mode
    assert normalize_mode("off") == PolicyMode.OFF
    assert normalize_mode("assist") == PolicyMode.ASSIST
    assert normalize_mode("enforce") == PolicyMode.ENFORCE

    # strictest
    assert strictest("off", "assist") == PolicyMode.ASSIST
    assert strictest("assist", "enforce") == PolicyMode.ENFORCE
    assert strictest("enforce", "off") == PolicyMode.ENFORCE


def test_postprocess_pipeline() -> None:
    assert "offset" in PP_KEYS
    assert "limit" in PP_KEYS
    assert "grep" in PP_KEYS

    args_with_pp = {"address": "0x401000", "limit": 10, "grep": "main"}
    assert has_post_process(args_with_pp) is True

    stripped_args, pp_opts = prepare_args_for_postprocess("data", args_with_pp)
    assert "limit" not in stripped_args
    assert "grep" not in stripped_args
    assert pp_opts["limit"] == 10
    assert pp_opts["grep"] == "main"

    # Apply post process to list payload
    raw_payload = [
        {"name": "func_main", "addr": "0x401000"},
        {"name": "func_sub_1", "addr": "0x401100"},
        {"name": "func_main_helper", "addr": "0x401200"},
    ]
    processed = apply_post_processing(raw_payload, {"grep": "main"})
    assert len(processed["data"]) == 2


def test_long_running_actions_and_rate_limit() -> None:
    assert ("analysis", "analyze") in LONG_RUNNING_ACTIONS
    assert ("search", "find") in LONG_RUNNING_ACTIONS

    # Rate limit exempt checks
    assert is_rate_limit_exempt("session", "health") is True
    assert is_rate_limit_exempt("bookmarks") is True
    assert is_rate_limit_exempt("random_tool", "random_action") is False


class _DispatchHarness(ServerArgsMixin, ServerDispatchMixin):
    def __init__(self):
        self.current_session = SimpleNamespace(session_id="S100", idb_path="/tmp/sample.i64")
        self.session_runtimes = {}
        self._runtime_lock = threading.Lock()
        self.default_truncate_tokens = 2000
        self._guardrail_strict_writes = False
        self._session_inflight_calls = {}
        self.audit = SimpleNamespace(log=lambda **kwargs: None)
        self.session_mgr = SimpleNamespace(discover_sessions=list)
        self.rate_limiter = SimpleNamespace(check=lambda tool: (True, ""))
        self.cache_dir = "/tmp"
        self.ida_dir = "/tmp"
        self._next_cache_ttl_seconds = 600.0
        self._next_cache = {}
        self._next_lock = threading.Lock()
        self._next_cache_lock = lambda: self._next_lock
        self._usage_intel = None
        self.routes = []

    def _resolve_session_from_idb_ref(self, _ref):
        return self.current_session

    def _ensure_client_owns_session(self, _session):
        return None

    def _runtime_record(self, sid):
        return self.session_runtimes.get(sid, {})

    def _memory_allow_root(self):
        return "/tmp"

    def _guardrail_mode_from_args(self, _args):
        return "assist"


def test_runtime_alive_edge_cases() -> None:
    assert ServerDispatchMixin._runtime_alive({"process": None}) is False
    assert ServerDispatchMixin._runtime_alive({"process": 0}) is False
    assert ServerDispatchMixin._runtime_alive("not a dict") is False
    assert ServerDispatchMixin._runtime_alive({}) is False


def test_policy_baseline_mode_unreadable_fallback(monkeypatch) -> None:
    monkeypatch.delenv("IDA_MCP_POLICY_MODE", raising=False)
    host = ServerDispatchMixin()
    monkeypatch.setattr(os, "stat", lambda _path: SimpleNamespace(st_mtime_ns=1, st_size=10))
    monkeypatch.setattr(
        ServerDispatchMixin,
        "_policy_baseline_mode_cached",
        lambda _k, _p: (_ for _ in ()).throw(RuntimeError("unreadable json")),
    )
    assert host._policy_baseline_mode() == "assist"


def test_safe_mode_gate_blocked_tools_and_actions() -> None:
    host = _DispatchHarness()
    host._safe_mode_active = lambda sid: True

    blocked_tool = next(iter(SAFE_MODE_BLOCKED_TOOLS))
    res = host._safe_mode_gate("S100", blocked_tool, "run")
    assert res is not None
    assert res["code"] == MCPError.SAFE_MODE

    blocked_tool_act, blocked_action = next(iter(SAFE_MODE_BLOCKED_ACTIONS))
    res2 = host._safe_mode_gate("S100", blocked_tool_act, blocked_action)
    assert res2 is not None
    assert res2["code"] == MCPError.SAFE_MODE

    assert host._safe_mode_gate("S100", "code", "disasm") is None

    host._safe_mode_active = lambda sid: False
    assert host._safe_mode_gate("S100", blocked_tool, "run") is None
    assert host._safe_mode_gate(None, blocked_tool, "run") is None


def test_call_tool_watchdog_queue_timeout_and_wallclock_fallback(monkeypatch) -> None:
    host = _DispatchHarness()
    proc = MagicMock()
    proc.poll.return_value = None
    proc.wait.side_effect = RuntimeError("wait timeout")
    proc.kill.side_effect = RuntimeError("kill failure")
    host.session_runtimes["S100"] = {"port": 54321, "process": proc}
    host._session_inflight_calls = {"S100": 2}

    # 1. RpcQueueTimeout
    host._send_rpc_with_retry = MagicMock(side_effect=RpcQueueTimeout("busy"))
    err = host.call_tool("code", "/tmp/sample.i64", action="disasm")
    assert err["code"] == MCPError.IDA_BUSY
    assert host._session_inflight_calls["S100"] == 2

    # 2. Wallclock watchdog cap with invalid env var and failed result
    monkeypatch.setenv("IDA_MCP_RPC_HARD_WALLCLOCK_SEC", "invalid")
    real_time = time.time
    curr_time = [1000.0]
    monkeypatch.setattr(time, "time", lambda: curr_time[0])
    def slow_rpc(*_args, **_kwargs):
        curr_time[0] += 1000.0
        return {"error": True, "code": MCPError.INTERNAL}
    host._send_rpc_with_retry = MagicMock(side_effect=slow_rpc)

    res = host.call_tool("code", "/tmp/sample.i64", action="disasm")
    assert res["code"] == MCPError.IDA_TIMEOUT
    proc.terminate.assert_called()
    proc.kill.assert_called()

    # 3. Misc python with failing image base lookup
    monkeypatch.setattr(time, "time", real_time)
    host._send_rpc_with_retry = MagicMock(return_value={"result": "ok"})
    host._get_session_imagebase = MagicMock(side_effect=RuntimeError("no imagebase"))
    misc_res = host.call_tool("misc", "/tmp/sample.i64", action="python", code="1")
    assert misc_res["_executed_in"]["image_base"] is None

    # 4. Truncation with owner id and slow threshold invalid
    monkeypatch.setenv("IDA_MCP_SLOW_CALL_SEC", "not_float")
    host._pending_truncation = {"no_truncate": False}
    host._truncation_owner_id = lambda: "owner_abc"
    host._send_rpc_with_retry = MagicMock(return_value={"data": list(range(10))})
    trunc_res = host.call_tool("data", "/tmp/sample.i64", action="functions")
    assert trunc_res is not None

    # 5. Exception path wallclock timeout
    proc.reset_mock()
    curr_time_exc = [1000.0]
    monkeypatch.setattr(time, "time", lambda: curr_time_exc[0])
    def exc_rpc(*_args, **_kwargs):
        curr_time_exc[0] += 1000.0
        raise TimeoutError("sock timeout")
    host._send_rpc_with_retry = MagicMock(side_effect=exc_rpc)
    exc_res = host.call_tool("code", "/tmp/sample.i64", action="disasm")
    assert exc_res["code"] == MCPError.IDA_TIMEOUT
    proc.terminate.assert_called()
    proc.kill.assert_called()

    # 6. Socket timeout with explicit _rpc_sock_timeout
    monkeypatch.setattr(time, "time", real_time)
    host._send_rpc_with_retry = MagicMock(side_effect=TimeoutError("sock timeout"))
    sock_res = host.call_tool("analysis", "/tmp/sample.i64", action="analyze")
    assert sock_res["code"] == MCPError.IDA_TIMEOUT
    assert sock_res["details"]["rpc_timeout_sec"] == 120


def test_handle_session_health_discovery_error() -> None:
    host = _DispatchHarness()
    host.session_mgr = SimpleNamespace(
        discover_sessions=MagicMock(side_effect=OSError("corrupted session directory"))
    )
    host.idat_exe = None
    host._resolve_wiki_root = lambda: None
    res = host._handle_session_health({"verbose": True})
    assert res["ok"] is True
    assert res["sessions"]["discovery_error"] == "corrupted session directory"


def test_memory_path_has_symlink_empty_part_and_write_file_byte_caps(tmp_path) -> None:
    assert ServerDispatchMixin._memory_path_has_symlink(str(tmp_path) + "//nested", str(tmp_path)) is False
    with patch("os.path.relpath", return_value="nested//child"):
        assert ServerDispatchMixin._memory_path_has_symlink(str(tmp_path / "nested" / "child"), str(tmp_path)) is False

    host = _DispatchHarness()
    host._MEMORY_MAX_BYTES = 4
    host._memory_allow_root = lambda: str(tmp_path)
    host._handle_memory_filesystem = ServerDispatchMixin._handle_memory_filesystem.__get__(host)

    # Binary write cap
    bin_res = host._handle_memory_filesystem({
        "action": "write_file",
        "path": "test.bin",
        "encoding": "binary",
        "content": "0102030405",  # 5 bytes > 4
    })
    assert bin_res["code"] == MCPError.INVALID_ARGS
    assert "exceeds 4 byte cap" in bin_res["message"]

    # Text write cap
    txt_res = host._handle_memory_filesystem({
        "action": "write_file",
        "path": "test.txt",
        "encoding": "utf-8",
        "content": "hello_world",
    })
    assert txt_res["code"] == MCPError.INVALID_ARGS
    assert "exceeds 4 byte cap" in txt_res["message"]


def test_handle_analysis_plugin_run_error_branches() -> None:
    host = _DispatchHarness()
    host._handle_analysis_plugin_run = ServerDispatchMixin._handle_analysis_plugin_run.__get__(host)

    # name required
    assert host._handle_analysis_plugin_run({})["code"] == MCPError.INVALID_ARGS
    assert host._handle_analysis_plugin_run({"name": ""})["code"] == MCPError.INVALID_ARGS

    # arg int conversion failure
    assert host._handle_analysis_plugin_run({"name": "plugin1", "arg": "abc"})["code"] == MCPError.INVALID_ARGS

    # idb ref resolution error
    host._resolve_session_from_idb_ref = lambda _ref: None
    assert host._handle_analysis_plugin_run({"name": "plugin1", "idb": "nonexistent"})["code"] == MCPError.FILE_NOT_FOUND

    # idb ref ownership error
    host._resolve_session_from_idb_ref = lambda _ref: SimpleNamespace(session_id="S100")
    host._ensure_client_owns_session = lambda _s: make_error(MCPError.POLICY_DENIED, "session ownership denied")
    assert host._handle_analysis_plugin_run({"name": "plugin1", "idb": "S100"})["code"] == MCPError.POLICY_DENIED

    # target is None
    host._ensure_client_owns_session = lambda _s: None
    host.current_session = None
    host._resolve_session_from_idb_ref = lambda _ref: None
    assert host._handle_analysis_plugin_run({"name": "plugin1"})["code"] == MCPError.IDA_CRASHED

    # runtime not alive
    host.current_session = SimpleNamespace(session_id="S100", idb_path="/tmp/sample.i64")
    host.session_runtimes["S100"] = {"process": None}
    assert host._handle_analysis_plugin_run({"name": "plugin1"})["code"] == MCPError.IDA_CRASHED

    # imagebase exception
    host.session_runtimes["S100"] = {"port": 1234, "process": SimpleNamespace(poll=lambda: None)}
    host._send_rpc_raw = lambda req, port: {"ok": True}
    host._get_session_imagebase = MagicMock(side_effect=RuntimeError("no base"))
    res = host._handle_analysis_plugin_run({"name": "plugin1"})
    assert res["_executed_in"]["image_base"] is None

    # target = resolved with valid idb ref (line 1039)
    host._ensure_client_owns_session = lambda _s: None
    host._resolve_session_from_idb_ref = lambda _ref: SimpleNamespace(session_id="S100", idb_path="/tmp/sample.i64")
    host._get_session_imagebase = lambda _sid: 0x400000
    res_valid = host._handle_analysis_plugin_run({"name": "plugin1", "idb": "S100"})
    assert res_valid["ok"] is True
    assert res_valid["_executed_in"]["session_id"] == "S100"


def test_continuation_and_next_token_error_paths() -> None:
    host = _DispatchHarness()
    host._next_cache = {
        "ERR_TOK": {
            "tool": "code",
            "action": "disasm",
            "args": {},
            "next_offset": 10,
            "created_at": time.time(),
            "session_id": "S100",
            "owner_id": "",
        },
        "TRUNC_TOK": {
            "tool": "data",
            "action": "functions",
            "args": {},
            "next_offset": 10,
            "tool_level": True,
            "created_at": time.time(),
            "session_id": "S100",
            "owner_id": "",
        },
    }

    # Continuation returns error result
    host.call_tool = MagicMock(return_value=make_error(MCPError.IDA_TIMEOUT, "timed out"))
    res = host._handle_next_continuation("code", "ERR_TOK", {})
    assert is_error_result(res) is True

    # Tool level token with bad offset/count
    host.call_tool = MagicMock(return_value={"truncated": True, "offset": "bad", "count": "bad"})
    res2 = host._handle_next_continuation("data", "TRUNC_TOK", {})
    assert res2.get("next_token") is None


def test_execute_tool_and_inner_error_and_gate_paths(monkeypatch) -> None:
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "off")
    host = _DispatchHarness()

    # 1. _resolve_session_from_idb_ref raises in _execute_tool
    host._resolve_session_from_idb_ref = MagicMock(side_effect=RuntimeError("resolve error"))
    host._execute_tool_inner = MagicMock(return_value={"ok": True})
    assert host._execute_tool("data", {"idb": "corrupt_idb", "action": "functions"}) == {"ok": True}

    # 2. Post-process pipeline in _execute_tool without _forwarded_offset (lines 1522)
    class _NoArgsHost(_DispatchHarness):
        @property
        def _pending_tool_args(self):
            return None
        @_pending_tool_args.setter
        def _pending_tool_args(self, v):
            pass

    no_args_host = _NoArgsHost()
    no_args_host._pending_pp = {"limit": 1}
    no_args_host._next_cache_scope = lambda a: ("S100", "")
    no_args_host._execute_tool_inner = MagicMock(return_value=[{"x": 1}, {"x": 2}])
    pp_res = no_args_host._execute_tool("data", {"action": "functions"})
    assert len(pp_res["data"]) == 1

    # 3. Post-process pipeline exception caught safely (lines 1526-1528)
    host._pending_pp = {"limit": 1}
    host._pending_tool_args = None
    with patch("ida_pro_mcp.host.server.server_dispatch.apply_post_processing", side_effect=RuntimeError("pp boom")):
        assert host._execute_tool("data", {"action": "functions"}) is not None

    # 4. Guardrail error shapes
    host._pending_pp = {}
    host._execute_tool_inner = MagicMock(
        return_value={"error": {"code": MCPError.INVALID_ARGS, "message": "guardrail blocked action"}}
    )
    assert host._execute_tool("data", {"action": "functions"})["error"]["code"] == MCPError.INVALID_ARGS

    host._execute_tool_inner = MagicMock(return_value={"error": True})
    assert host._execute_tool("data", {"action": "functions"})["error"] is True

    host._execute_tool_inner = MagicMock(
        return_value={"ok": False, "code": MCPError.INVALID_ARGS, "message": "guardrail disallowed"}
    )
    assert host._execute_tool("data", {"action": "functions"})["ok"] is False

    # 5. _blackboard_and_phase_preflight edge paths
    monkeypatch.delenv("IDA_MCP_POLICY_MODE", raising=False)
    host._phase_state = MagicMock(side_effect=RuntimeError("phase failure"))
    host._bb_policy_bump = lambda: {"strict_mode": True}
    host._bb_policy_check = lambda state: {"ok": False, "reasons": ["evidence missing"]}
    bb_err = host._blackboard_and_phase_preflight("code", {}, False)
    assert bb_err["code"] == MCPError.INVALID_ARGS

    host._bb_policy_enforced_for_phase = lambda state, phase: False
    assert host._blackboard_and_phase_preflight("code", {}, False) is None

    host._bb_policy_bump = MagicMock(side_effect=RuntimeError("governance check exception"))
    assert host._blackboard_and_phase_preflight("code", {}, False) is None

    del host._bb_policy_bump
    host._phase_preflight_for_tool = lambda tool, args: {"error": True, "message": "phase block"}
    phase_res = host._blackboard_and_phase_preflight("code", {}, False)
    assert phase_res["error"] is True

    # 6. _execute_tool_inner scope error
    host._execute_tool_inner = ServerDispatchMixin._execute_tool_inner.__get__(host)
    host._agent_scope_error = lambda tool, action: make_error(MCPError.POLICY_DENIED, "scope denied")
    assert host._execute_tool_inner("code", "code", {"action": "disasm"})["code"] == MCPError.POLICY_DENIED
    host._agent_scope_error = lambda tool, action: None

    # 7. Slice forwarding variations
    host.call_tool = MagicMock(return_value={"ok": True})
    # pure slice with head and non-int head (lines 1813-1814)
    host._execute_tool_inner("data", "data", {"action": "functions", "offset": 0, "head": "not_an_int"})
    # pure slice with native count
    host._execute_tool_inner("data", "data", {"action": "functions", "offset": 0, "count": 10})

    # 8. Next token continuation in _execute_tool_inner
    host._handle_next_continuation = MagicMock(return_value={"ok": True, "continuation": True})
    cont_res = host._execute_tool_inner("data", "data", {"action": "functions", "next_token": "TOK999"})
    assert cont_res.get("continuation") is True

    # 9. Policy evaluation BLOCK and REQUIRE_ACK decisions
    from dataclasses import replace
    base_policy = evaluate_policy("code", "disasm", mode="assist")
    with patch("ida_pro_mcp.host.server.server_dispatch.evaluate_policy") as mock_eval:
        mock_eval.return_value = replace(base_policy, decision=PolicyDecision.BLOCK, reasons=["blocked by rule"])
        block_res = host._execute_tool_inner("code", "code", {"action": "disasm"})
        assert block_res["code"] == MCPError.POLICY_DENIED
        assert "Policy blocked" in block_res["message"]

        mock_eval.return_value = replace(base_policy, decision=PolicyDecision.REQUIRE_ACK, reasons=["requires ack"])
        ack_res = host._execute_tool_inner("code", "code", {"action": "disasm"})
        assert ack_res["code"] == MCPError.POLICY_DENIED
        assert "requires explicit acknowledgement" in ack_res["message"]

    # 10. Safe mode gate and blackboard preflight blocks in _execute_tool_inner
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "off")
    host._safe_mode_gate = lambda sid, tool, action: make_error(MCPError.SAFE_MODE, "safe mode active")
    assert host._execute_tool_inner("code", "code", {"action": "disasm"})["code"] == MCPError.SAFE_MODE
    host._safe_mode_gate = lambda sid, tool, action: None

    host._blackboard_and_phase_preflight = lambda tool, args, ack: make_error(MCPError.INVALID_ARGS, "bb strict gate")
    assert host._execute_tool_inner("code", "code", {"action": "disasm"})["code"] == MCPError.INVALID_ARGS
    host._blackboard_and_phase_preflight = lambda tool, args, ack: None

    # 11. Drift detector exception swallowed
    host._usage_intel = SimpleNamespace(
        is_running=lambda: True,
        drift=SimpleNamespace(check=MagicMock(side_effect=RuntimeError("drift failure"))),
    )
    assert host._execute_tool_inner("code", "code", {"action": "disasm"})["ok"] is True

    # 12. Intelligence semantic index validation error and background missing session
    host._validate_semantic_index_scope = lambda args: make_error(MCPError.INVALID_ARGS, "scope error")
    assert host._execute_tool_inner("intelligence", "intelligence", {"action": "index_fast"})["code"] == MCPError.INVALID_ARGS
    host._validate_semantic_index_scope = lambda args: None

    host.current_session = None
    assert host._execute_tool_inner("intelligence", "intelligence", {"action": "index_fast", "_background": True})["code"] == MCPError.SESSION_REQUIRED
