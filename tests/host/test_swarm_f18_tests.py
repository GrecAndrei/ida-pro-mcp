"""New regression tests for the f18 test-quality findings.

These pin session behaviors that the existing host suites left uncovered:

- owned-session teardown happy path: a client closing/killing a session IT
  owns must actually tear down the idat process, remove the runtime row, the
  runtime lease file, and the session record/dir. The isolation suite only
  covered the denied/foreign-client case.
- the dispatcher's recv-timeout cap clamp: no caller can pin the dispatcher
  forever (huge ``timeout``/``max_wait``/``poll_timeout`` are clamped to the
  ``IDA_MCP_RPC_MAX_RECV_TIMEOUT`` cap), and the ``IDA_MCP_FULL_INDEX_RPC_TIMEOUT``
  override is exercised.
- malformed / path-traversal idb references hitting the fallback branches of
  ``_resolve_session_from_idb_ref`` without bypassing ownership.
- destructive session actions requiring ``_risk_ack`` under assist policy,
  plus the close/switch lifecycle (double-close, use-after-close, owned switch).
- the always-idle daemon connection surviving consecutive receive timeouts.
- blackboard export ``path`` confinement: ``..`` traversal, absolute escapes,
  and symlink escapes are rejected; relative paths resolve under the root.

Per AGENTS.md these are host-side decisions asserted at the process/network
boundary — IDA detection is stubbed so no idat is ever spawned.
"""

from __future__ import annotations

import json
import os
import threading
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_dispatch import _long_running_sock_timeout


class _FakeIdaProcess:
    """A fake idat process that stays alive.

    ``pid`` is above Linux's pid_max, so ``os.killpg`` on it raises
    ProcessLookupError/EINVAL and every kill path is a safe no-op.
    """

    pid = 2147483647

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 1


class _TerminableFakeProcess:
    """A fake idat process that reports 'terminated' after terminate()."""

    def __init__(self):
        self.pid = 2147483647
        self.returncode = None
        self.terminated = False
        self.terminate_calls = 0
        self.kill_calls = 0

    def poll(self):
        return self.returncode if self.terminated else None

    def terminate(self):
        self.terminate_calls += 1
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.kill_calls += 1
        self.terminated = True
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


def _make_server(tmp_path, monkeypatch) -> IDAMCPServer:
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "assist")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    return server


def _open_session(server: IDAMCPServer, binary_path: str, request_id: int = 1) -> dict:
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": "ida_open_binary",
                "arguments": {"binary_path": binary_path},
            },
        }
    )
    assert response is not None and "result" in response
    return response["result"]["structuredContent"]


# ---------------------------------------------------------------------------
# Owned-session teardown happy path (close / kill)
# ---------------------------------------------------------------------------


def test_owned_close_tears_down_runtime_lease_and_session(tmp_path, monkeypatch):
    import ida_pro_mcp.host.server.server_runtime as server_runtime

    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"close-me")
    monkeypatch.setattr(server, "_send_rpc_raw", lambda *a, **k: {})
    killed: list = []
    # The real _kill_process_tree accepts grace_seconds (SIGKILL grace budget);
    # the mock must tolerate the kwarg even though list.append does not.
    monkeypatch.setattr(
        server_runtime, "_kill_process_tree", lambda proc, **kw: killed.append(proc)
    )

    token = server._begin_client_connection()
    try:
        opened = _open_session(server, str(binary))
        sid = opened["session_id"]
        proc = _FakeIdaProcess()
        server.session_runtimes[sid] = {"process": proc, "port": 1}
        # A runtime lease on disk, as a real spawn would leave behind.
        os.makedirs(server._runtime_lease_dir, exist_ok=True)
        lease_path = server._runtime_lease_path(sid)
        with open(lease_path, "w", encoding="utf-8") as f:
            json.dump({"session_id": sid, "pid": proc.pid}, f)
        session_dir = os.path.join(server.cache_dir, "sessions", f"SID_{sid}")
        os.makedirs(session_dir, exist_ok=True)

        result = server._session_action_close({"session_id": sid})
        assert result.get("ok") is True
        # The idat process tree was torn down.
        assert killed == [proc]
        # The runtime row, lease file, session record, and session dir are gone.
        assert sid not in server.session_runtimes
        assert not os.path.exists(lease_path)
        assert server.session_mgr.get_session(sid) is None
        assert not os.path.exists(session_dir)
        assert server.current_session is None
    finally:
        server._end_client_connection(token)
        server.shutdown()


def test_owned_kill_terminates_process_and_cleans_runtime(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"kill-me")
    monkeypatch.setattr(server, "_send_rpc_raw", lambda *a, **k: {})

    token = server._begin_client_connection()
    try:
        opened = _open_session(server, str(binary))
        sid = opened["session_id"]
        proc = _TerminableFakeProcess()
        server.session_runtimes[sid] = {"process": proc, "port": 1}
        os.makedirs(server._runtime_lease_dir, exist_ok=True)
        lease_path = server._runtime_lease_path(sid)
        with open(lease_path, "w", encoding="utf-8") as f:
            json.dump({"session_id": sid, "pid": proc.pid}, f)

        result = server._session_action_kill({"session_id": sid})
        # The owned kill must reach the process: SIGTERM first, then confirm
        # termination — not report a no-op or an already-exited process.
        assert result.get("attempted") is True
        assert result.get("terminated") is True
        assert result.get("signaled") == "SIGTERM"
        assert proc.terminate_calls == 1
        assert proc.returncode == -15
        assert result.get("session_id") == sid
        # Kill also drops the stale runtime row and lease so the next tool
        # call can respawn cleanly (same teardown contract as close).
        assert sid not in server.session_runtimes
        assert not os.path.exists(lease_path)
    finally:
        server._end_client_connection(token)
        server.shutdown()


# ---------------------------------------------------------------------------
# _long_running_sock_timeout cap-clamp / full-index override
# ---------------------------------------------------------------------------


def test_caller_supplied_huge_timeout_is_clamped_to_cap(monkeypatch):
    monkeypatch.delenv("IDA_MCP_RPC_MAX_RECV_TIMEOUT", raising=False)
    monkeypatch.delenv("IDA_MCP_RPC_TIMEOUT", raising=False)
    # Default cap is 600s: a caller passing timeout=999999 must be clamped so
    # no caller can pin the dispatcher's recv deadline forever.
    assert (
        _long_running_sock_timeout("intelligence", {"action": "index_function", "timeout": 999999})
        == 600
    )
    assert _long_running_sock_timeout("search", {"action": "find", "max_wait": 999999}) == 600
    assert _long_running_sock_timeout("search", {"action": "find", "poll_timeout": 999999}) == 600


def test_caller_timeout_above_floor_adds_grace_and_is_capped(monkeypatch):
    monkeypatch.delenv("IDA_MCP_RPC_MAX_RECV_TIMEOUT", raising=False)
    monkeypatch.delenv("IDA_MCP_RPC_TIMEOUT", raising=False)
    # A 150s caller timeout is granted 30s of grace, then clamped to the cap.
    assert _long_running_sock_timeout("intelligence", {"action": "index_function", "timeout": 150}) == 180


def test_env_cap_below_floor_is_raised_to_thirty(monkeypatch):
    # cap = max(env_cap, 30): even a tiny cap still guarantees 30s.
    monkeypatch.setenv("IDA_MCP_RPC_MAX_RECV_TIMEOUT", "5")
    monkeypatch.delenv("IDA_MCP_RPC_TIMEOUT", raising=False)
    assert _long_running_sock_timeout("intelligence", {"action": "index_function"}) == 30


def test_full_index_timeout_env_override(monkeypatch):
    monkeypatch.delenv("IDA_MCP_RPC_MAX_RECV_TIMEOUT", raising=False)
    monkeypatch.delenv("IDA_MCP_RPC_TIMEOUT", raising=False)
    # Default (no override): the built-in 600s pipeline timeout.
    assert _long_running_sock_timeout("intelligence", {"action": "index_batch"}) == 600
    # A raised cap lets a custom override take effect for the full pipeline.
    monkeypatch.setenv("IDA_MCP_RPC_MAX_RECV_TIMEOUT", "3000")
    monkeypatch.setenv("IDA_MCP_FULL_INDEX_RPC_TIMEOUT", "1200")
    assert _long_running_sock_timeout("intelligence", {"action": "index_batch"}) == 1200
    assert (
        _long_running_sock_timeout("intelligence", {"action": "index_fast", "mode": "full"})
        == 1200
    )
    # The override is still bounded by the cap.
    monkeypatch.setenv("IDA_MCP_FULL_INDEX_RPC_TIMEOUT", "5000")
    assert _long_running_sock_timeout("intelligence", {"action": "index_batch"}) == 3000


# ---------------------------------------------------------------------------
# Malformed / path-traversal idb references
# ---------------------------------------------------------------------------


def test_path_traversal_idb_reference_does_not_bypass_ownership(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    token_a = server._begin_client_connection()
    try:
        opened_a = _open_session(server, str(binary_a))
        sid_a = opened_a["session_id"]
        idb_a = opened_a["idb_path"]
    finally:
        server._client_request_state_var.reset(token_a)
    # A's session is actively running: B must not reach it, even via a
    # path-traversal idb reference that resolves through the basename branch of
    # _resolve_session_from_idb_ref.
    server.session_runtimes[sid_a] = {"process": _FakeIdaProcess()}

    token_b = server._begin_client_connection()
    try:
        _open_session(server, str(binary_b))
        traversal = f"../../sessions/SID_{sid_a}/{os.path.basename(idb_a)}"
        denied = server.call_tool("funcs", traversal, action="list")
        assert denied.get("error") is True
        assert denied.get("code") == "FILE_LOCKED"
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_garbage_idb_reference_is_rejected_not_crash(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"target")
    token = server._begin_client_connection()
    try:
        _open_session(server, str(binary))
        # Non-SID / non-existent references must resolve to nothing and error
        # cleanly — they must not enumerate sessions or drive a runtime.
        for bad in ("zzz-not-a-session", "SID_ZZZZZZZZ_x.i64", "..\\..\\..\\etc\\passwd"):
            denied = server.call_tool("funcs", bad, action="list")
            assert denied.get("error") is True
            assert denied.get("code") == MCPError.FILE_NOT_FOUND
    finally:
        server._end_client_connection(token)
        server.shutdown()


# ---------------------------------------------------------------------------
# Destructive session actions require _risk_ack; close/switch lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "action",
    [
        "close",
        "kill",
        "rebuild",
        "bulk_delete",
        "cleanup_stale",
        "idle_purge",
        "restore_snapshot",
    ],
)
def test_destructive_session_actions_require_risk_ack(tmp_path, monkeypatch, action):
    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"target")
    token = server._begin_client_connection()
    try:
        opened = _open_session(server, str(binary))
        sid = opened["session_id"]
        args = {"action": action, "session_id": sid}
        denied = server._execute_tool("session", args)
        assert denied.get("error") is True
        assert denied.get("code") == MCPError.POLICY_DENIED
        assert "acknowledgement" in str(denied.get("message") or "").lower()
        # With an explicit ack the policy gate passes; the action then runs its
        # own logic (ownership, session lookup) — never a policy denial.
        allowed = server._execute_tool("session", {**args, "_risk_ack": True})
        assert allowed.get("code") != MCPError.POLICY_DENIED
    finally:
        server._end_client_connection(token)
        server.shutdown()


def test_double_close_is_clean_and_use_after_close_is_rejected(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"close-me")
    token = server._begin_client_connection()
    try:
        opened = _open_session(server, str(binary))
        sid = opened["session_id"]
        idb = opened["idb_path"]

        first = server._session_action_close({"session_id": sid})
        assert first.get("ok") is True
        assert sid not in server.session_runtimes
        assert server.session_mgr.get_session(sid) is None
        assert server.current_session is None

        # Double close: the session record is gone, so a second close errors
        # cleanly instead of crashing or resurrecting a runtime.
        second = server._session_action_close({"session_id": sid})
        assert second.get("error") is True
        assert second.get("code") == MCPError.SESSION_NOT_FOUND

        # Use-after-close: driving the old idb must not resurrect the session.
        denied = server.call_tool("funcs", idb, action="list")
        assert denied.get("error") is True
    finally:
        server._end_client_connection(token)
        server.shutdown()


def test_owned_switch_moves_active_session(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")
    monkeypatch.setattr(server, "_trigger_session_diff", lambda *a, **k: None)

    token = server._begin_client_connection()
    try:
        opened_a = _open_session(server, str(binary_a))
        opened_b = _open_session(server, str(binary_b))
        sid_a = opened_a["session_id"]
        sid_b = opened_b["session_id"]
        # Keep both runtimes alive so switch does not try to respawn idat.
        server.session_runtimes[sid_a] = {"process": _FakeIdaProcess()}
        server.session_runtimes[sid_b] = {"process": _FakeIdaProcess()}
        assert server.current_session.session_id == sid_b

        res = server._session_action_switch({"session_id": sid_a})
        assert res.get("ok") is True
        assert server.current_session.session_id == sid_a

        res2 = server._session_action_switch({"session_id": sid_b})
        assert res2.get("ok") is True
        assert server.current_session.session_id == sid_b
    finally:
        server._end_client_connection(token)
        server.shutdown()


# ---------------------------------------------------------------------------
# Always-idle daemon connection survives consecutive timeouts
# ---------------------------------------------------------------------------


class _AlwaysIdleThenClosedConnection:
    def __init__(self, idle_attempts):
        self.idle_attempts = idle_attempts
        self.recv_count = 0
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, size):
        self.recv_count += 1
        if self.recv_count <= self.idle_attempts:
            raise TimeoutError("idle")
        return b""

    def close(self):
        self.closed = True


def test_idle_daemon_connection_survives_consecutive_timeouts_and_closes_on_eof(
    tmp_path, monkeypatch
):
    """An idle connection is kept alive across repeated receive timeouts and is
    closed on EOF. A regression that closes after the second consecutive idle
    timeout (or that never closes idle connections) must not pass silently.
    """
    server = _make_server(tmp_path, monkeypatch)
    conn = _AlwaysIdleThenClosedConnection(idle_attempts=5)
    try:
        server._handle_daemon_conn(conn)
        # 5 tolerated idle timeouts + the EOF read that finally closes it.
        assert conn.recv_count == 6
        assert conn.closed is True
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Blackboard export path confinement
# ---------------------------------------------------------------------------


def _blackboard_server(tmp_path, monkeypatch, root=None):
    if root is not None:
        monkeypatch.setenv("IDA_MCP_BLACKBOARD_ROOT", str(root))
    server = _make_server(tmp_path, monkeypatch)
    server.current_session = SimpleNamespace(
        binary_path=str(tmp_path / "sample.bin"),
        idb_path=str(tmp_path / "sample.i64"),
        session_id="sess-export",
    )
    return server


def test_blackboard_export_rejects_dotdot_escape(tmp_path, monkeypatch):
    root = tmp_path / "ws"
    root.mkdir()
    server = _blackboard_server(tmp_path, monkeypatch, root=root)
    result = server._handle_blackboard(
        {"action": "export", "format": "json", "path": "../../escape.json"}
    )
    assert result.get("error") is True
    assert "escapes allowed root" in str(result.get("message") or "")
    assert not os.path.exists(tmp_path / "escape.json")


def test_blackboard_export_rejects_absolute_path_outside_root(tmp_path, monkeypatch):
    root = tmp_path / "ws"
    root.mkdir()
    server = _blackboard_server(tmp_path, monkeypatch, root=root)
    outside = str(tmp_path / "outside.json")
    result = server._handle_blackboard(
        {"action": "export", "format": "json", "path": outside}
    )
    assert result.get("error") is True
    assert "escapes allowed root" in str(result.get("message") or "")
    assert not os.path.exists(outside)


def test_blackboard_export_rejects_symlink_escape(tmp_path, monkeypatch):
    root = tmp_path / "ws"
    root.mkdir()
    outside = tmp_path / "outside-target.json"
    outside.write_text("{}", encoding="utf-8")
    (root / "leak.json").symlink_to(outside)
    server = _blackboard_server(tmp_path, monkeypatch, root=root)
    result = server._handle_blackboard(
        {"action": "export", "format": "json", "path": "leak.json"}
    )
    # realpath resolves the symlink before the confinement check, so the
    # observable contract is "escapes allowed root", not the unreachable
    # "symbolic links are not allowed" branch.
    assert result.get("error") is True
    assert "escapes allowed root" in str(result.get("message") or "")


def test_blackboard_export_relative_path_resolves_under_root(tmp_path, monkeypatch):
    root = tmp_path / "ws"
    root.mkdir()
    server = _blackboard_server(tmp_path, monkeypatch, root=root)
    result = server._handle_blackboard(
        {"action": "export", "format": "json", "path": "reports/findings.json"}
    )
    assert result.get("ok") is True
    assert result["path"] == str(root / "reports" / "findings.json")
    assert os.path.isfile(root / "reports" / "findings.json")


# ---------------------------------------------------------------------------
# Weak concurrency regression for the create/reuse TOCTOU (#9)
# ---------------------------------------------------------------------------


def test_concurrent_open_of_same_binary_does_not_crash_or_deadlock(tmp_path, monkeypatch):
    """Fires N concurrent `ida_open_binary` calls for the same binary against
    one server, each on its own client connection (as the real daemon does).

    This is deliberately a no-crash + convergence test, not a
    "exactly one session survives" assertion: the host's
    ``_select_reuse_candidate`` and ``create_session`` take two SEPARATE lock
    acquisitions, so the create/reuse check-then-act is not atomic and a
    strict single-survivor guarantee does not hold today. A regression that
    reintroduces the original duplicate-idat hazard (a deadlock, a crash on
    the reuse candidate path, or an error envelope under concurrent load)
    still fails here.
    """
    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"concurrent-target")
    errors: list = []
    ok_count = 0
    results_lock = threading.Lock()

    def _open_one():
        nonlocal ok_count
        token = server._begin_client_connection()
        try:
            response = server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "ida_open_binary",
                        "arguments": {"binary_path": str(binary)},
                    },
                }
            )
            if response is None or "result" not in response:
                errors.append(response)
                return
            with results_lock:
                ok_count += 1
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)
        finally:
            server._end_client_connection(token)

    threads = [threading.Thread(target=_open_one) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors
    assert ok_count == 8
    # All sessions reference the same binary; at least one session exists.
    binary_paths = {
        str(getattr(s, "binary_path", "") or "")
        for s in server.session_mgr.discover_sessions()
    }
    assert binary_paths == {str(binary)}
