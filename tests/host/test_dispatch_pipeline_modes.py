"""Exercise the real host dispatch pipeline at its IDA boundary."""

from __future__ import annotations

import socket
import threading
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.host.server import server_dispatch as dispatch_mod
from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin


class _Process:
    def __init__(self, alive=True):
        self.alive = alive
        self.terminated = False
        self.killed = False

    def poll(self):
        return None if self.alive and not self.terminated and not self.killed else 1

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        del timeout
        return 0


class _DispatchHost(ServerDispatchMixin):
    def __init__(self, *, runtime=True):
        self.session = SimpleNamespace(session_id="ABC12345", idb_path="/tmp/sample.i64")
        self.current_session = self.session
        self.process = _Process()
        self.runtime = {
            "process": self.process,
            "port": 31337,
            "stdout_log": "stdout.log",
            "stderr_log": "stderr.log",
        } if runtime else None
        self.session_runtimes = {self.session.session_id: self.runtime} if runtime else {}
        self._runtime_lock = threading.RLock()
        self._session_inflight_calls = {}
        self._pending_pp = {}
        self._pending_truncation = {"no_truncate": True}
        self.default_truncate_tokens = 1000
        self.assembler = SimpleNamespace(ensure_embedding_server=lambda: None)
        self.sent = []
        self.started = 0

    def _resolve_session_from_idb_ref(self, _ref):
        return self.session

    def _ensure_client_owns_session(self, _session):
        return None

    def _runtime_record(self, _sid):
        return self.runtime

    def _start_server(self, _session):
        self.started += 1
        return {"ok": True}

    def _send_rpc_with_retry(self, payload, port, **kwargs):
        self.sent.append((payload, port, kwargs))
        return {"answer": 1}

    def _send_rpc_raw(self, _payload, _port):
        return {"ok": True}

    def _get_session_imagebase(self, _sid):
        return 0x401000

    def _get_ida_diagnostics(self, stdout, stderr):
        return {"stdout": stdout, "stderr": stderr}

    def _truncation_owner_id(self):
        return "owner"


def test_call_tool_composes_schema_rpc_stamp_and_postprocess(monkeypatch):
    host = _DispatchHost()
    seed_calls = []
    embedding_calls = []
    postprocess_calls = []
    monkeypatch.setattr(
        dispatch_mod,
        "prepare_rpc_args",
        lambda tool, args, _schemas: {"action": args["action"], "query": args.get("query")},
    )
    host._seed_index_from_matching_binary = lambda session: seed_calls.append(session.session_id)
    host.assembler.ensure_embedding_server = lambda: embedding_calls.append(True)
    host._pending_pp = {"limit": 2, "_forwarded_offset": 1}
    monkeypatch.setattr(dispatch_mod, "has_post_process", lambda _pp: True)
    monkeypatch.setattr(
        dispatch_mod,
        "apply_post_processing",
        lambda result, args: postprocess_calls.append(args) or {**result, "processed": True},
    )
    monkeypatch.setattr(dispatch_mod, "truncate_response", lambda result, **_kwargs: result)

    result = host.call_tool(
        "intelligence",
        "target",
        action="semantic_search",
        query="packet",
    )
    assert result == {"answer": 1, "ok": True, "processed": True}
    assert seed_calls == ["ABC12345"]
    assert embedding_calls == [True]
    assert postprocess_calls == [{"limit": 2, "_forwarded_offset": 1}]
    assert host._session_inflight_calls == {}

    monkeypatch.setattr(dispatch_mod, "has_post_process", lambda _pp: False)
    stamped = host.call_tool("misc", "target", action="python", code="return 1")
    assert stamped["_executed_in"] == {
        "session_id": "ABC12345",
        "idb_path": "/tmp/sample.i64",
        "image_base": "0x401000",
    }


def test_call_tool_rejects_missing_ownership_safe_mode_reload_and_start_errors():
    host = _DispatchHost()
    host._resolve_session_from_idb_ref = lambda _ref: None
    assert host.call_tool("idb", "missing", action="overview")["code"] == MCPError.FILE_NOT_FOUND

    host = _DispatchHost()
    host._ensure_client_owns_session = lambda _session: make_error(MCPError.FILE_LOCKED, "owned elsewhere")
    assert host.call_tool("idb", "target", action="overview")["code"] == MCPError.FILE_LOCKED

    host = _DispatchHost()
    host._safe_mode_gate = lambda *_args: make_error(MCPError.SAFE_MODE, "wait")
    assert host.call_tool("idb", "target", action="overview")["code"] == MCPError.SAFE_MODE

    host = _DispatchHost()
    host._session_reload_active = lambda _sid: True
    assert host.call_tool("idb", "target", action="overview")["code"] == MCPError.IDA_BUSY

    host = _DispatchHost(runtime=False)
    host._start_server = lambda _session: make_error(MCPError.IDA_CRASHED, "spawn")
    assert host.call_tool("idb", "target", action="overview")["code"] == MCPError.IDA_CRASHED

    host = _DispatchHost(runtime=False)
    host._start_server = lambda _session: {"ok": True}
    assert host.call_tool("idb", "target", action="overview")["code"] == MCPError.IDA_CRASHED

    host = _DispatchHost()
    host.runtime["port"] = 0
    assert host.call_tool("idb", "target", action="overview")["code"] == MCPError.IDA_CRASHED


def test_call_tool_maps_rpc_timeout_and_process_exit(monkeypatch):
    host = _DispatchHost()
    monkeypatch.setattr(dispatch_mod, "prepare_rpc_args", lambda _tool, args, _schemas: args)
    host._send_rpc_with_retry = lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("slow"))
    timeout = host.call_tool("idb", "target", action="overview")
    assert timeout["code"] == MCPError.IDA_TIMEOUT
    assert timeout["recoverable"] is True

    host = _DispatchHost()
    def raise_after_start(*_args, **_kwargs):
        host.process.alive = False
        raise OSError("closed")

    host._send_rpc_with_retry = raise_after_start
    crashed = host.call_tool("idb", "target", action="overview")
    assert crashed["code"] == MCPError.IDA_CRASHED
    assert crashed["details"]["log"]["stdout"] == "stdout.log"


def test_call_tool_wallclock_cap_terminates_process_and_preserves_success(monkeypatch):
    host = _DispatchHost()
    monkeypatch.setenv("IDA_MCP_RPC_HARD_WALLCLOCK_SEC", "30")
    monkeypatch.setattr(dispatch_mod, "prepare_rpc_args", lambda _tool, args, _schemas: args)
    monkeypatch.setattr(dispatch_mod.time, "time", iter([0.0, 0.0, 40.0, 40.0]).__next__)
    host._send_rpc_with_retry = lambda *_args, **_kwargs: make_error(MCPError.RPC_CONNECTION_ERROR, "late")
    result = host.call_tool("idb", "target", action="overview")
    assert result["code"] == MCPError.IDA_TIMEOUT
    assert host.process.terminated is True

    host = _DispatchHost()
    monkeypatch.setattr(dispatch_mod.time, "time", iter([0.0, 0.0, 40.0, 40.0]).__next__)
    host._send_rpc_with_retry = lambda *_args, **_kwargs: {"ok": True, "answer": 7}
    result = host.call_tool("idb", "target", action="overview")
    assert result == {"ok": True, "answer": 7}
    assert host.process.terminated is False


def test_execute_tool_audits_rate_limits_postprocess_and_usage_modes(monkeypatch):
    class RateLimiter:
        def __init__(self, allowed):
            self.allowed = allowed

        def check(self, _tool):
            return self.allowed, "burst limit"

    class Audit:
        def __init__(self, fail=False):
            self.records = []
            self.fail = fail

        def log(self, **kwargs):
            if self.fail:
                raise OSError("audit disk full")
            self.records.append(kwargs)

    class Usage:
        def __init__(self, fail=False):
            self.fail = fail
            self.observed = []
            self.drift = SimpleNamespace(check=lambda _sid: [])

        def is_running(self):
            return True

        def observe(self, *args, **kwargs):
            if self.fail:
                raise RuntimeError("usage unavailable")
            self.observed.append((args, kwargs))

    host = _DispatchHost()
    host.rate_limiter = RateLimiter(False)
    host.audit = Audit()
    host._usage_intel = Usage()
    limited = host._execute_tool("idb", {"action": "overview"})
    assert limited["code"] == MCPError.RATE_LIMIT
    assert host.audit.records[0]["error"] == "rate_limited: burst limit"

    host = _DispatchHost()
    host.rate_limiter = RateLimiter(True)
    host.audit = Audit()
    host._usage_intel = Usage()
    host._guardrail_mode_from_args = lambda _args: "assist"

    def successful_inner(_tool, _original, _args):
        host._pending_pp = {"limit": 1, "_forwarded_offset": 3}
        host._pending_tool_args = {"action": "find", "pattern": "recv"}
        return {"ok": True, "matches": [{"name": "recv"}], "_count": 1, "_total": 2}

    host._execute_tool_inner = successful_inner
    monkeypatch.setattr(dispatch_mod, "apply_post_processing", lambda result, pp: {**result, "pp": pp})
    host._cache_post_process_next = lambda _tool, _args, _pp, result: {**result, "cached": True}
    result = host._execute_tool("search", {"action": "find", "pattern": "recv", "offset": 3, "limit": 1})
    assert result["cached"] is True
    assert result["pp"] == {"limit": 1, "_forwarded_offset": 3}
    assert host.audit.records[-1]["session_id"] == "ABC12345"
    assert host._usage_intel.observed
    assert host._pending_pp == {} and host._pending_tool_args == {}

    host = _DispatchHost()
    host.rate_limiter = RateLimiter(True)
    host.audit = Audit(fail=True)
    host._usage_intel = Usage(fail=True)
    host._guardrail_mode_from_args = lambda _args: "enforce"
    host._execute_tool_inner = lambda *_args: {
        "error": True,
        "code": MCPError.INVALID_ARGS,
        "message": "guardrail blocked write",
    }
    error = host._execute_tool("modify", {"action": "rename", "addr": "0x1000"})
    assert error["code"] == MCPError.INVALID_ARGS


def test_execute_tool_inner_forwards_pure_native_pages_and_clears_meta(monkeypatch):
    class InnerHost(ServerDispatchMixin):
        def __init__(self):
            self.current_session = SimpleNamespace(session_id="ABC12345", idb_path="/tmp/sample.i64")
            self._pending_analysis = set()
            self._guardrail_strict_writes = False
            self.calls = []

        def _normalize_tool_call_args(self, _tool, value):
            return value

        def _resolve_session_from_idb_ref(self, _ref):
            return self.current_session

        def _validate_semantic_index_scope(self, _args):
            return None

        def _handle_session(self, _args):
            return {"ok": True}

        def _handle_wiki(self, _args):
            return {"ok": True}

        def _handle_r2(self, _args):
            return {"ok": True}

        def call_tool(self, tool, idb, **kwargs):
            self.calls.append((tool, idb, kwargs))
            return {"ok": True, "items": [{"addr": "0x2000"}], "total": 4}

        def _guardrail_mode_from_args(self, _args):
            return "assist"

    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "off")
    host = InnerHost()
    result = host._execute_tool_inner(
        "data",
        "data",
        {"action": "functions", "offset": 2, "limit": 1, "agent": "worker"},
    )
    assert result["ok"] is True
    assert host.calls[0][2]["offset"] == 2
    assert host.calls[0][2]["count"] == 1
    assert host._pending_pp["_forwarded_offset"] == 2
    assert "agent" not in host.calls[0][2]

    no_session = InnerHost()
    no_session.current_session = None
    assert no_session._execute_tool_inner("data", "data", {"action": "functions"})["code"] == MCPError.SESSION_REQUIRED
