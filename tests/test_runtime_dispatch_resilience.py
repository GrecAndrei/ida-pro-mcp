import os
import sys
from unittest.mock import Mock

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.errors import MCPError  # noqa: E402
from ida_pro_mcp.host.server import IDAMCPServer  # noqa: E402
from ida_pro_mcp.host.session import Session  # noqa: E402


def _make_session() -> Session:
    return Session(
        session_id="A1B2C3D4",
        idb_path="/tmp/a.i64",
        binary_path="/tmp/a.bin",
    )


def test_session_health_runtime_liveness_uses_process_poll():
    server = IDAMCPServer()
    alive_proc = Mock()
    alive_proc.poll.return_value = None
    dead_proc = Mock()
    dead_proc.poll.return_value = 1
    server.session_runtimes = {
        "A1B2C3D4": {"process": alive_proc, "port": 1337},
        "E5F6A7B8": {"process": dead_proc, "port": 1338},
    }

    res = server._execute_tool("session", {"action": "health", "verbose": True})
    assert res.get("ok") is True
    rp = (((res.get("sessions") or {}).get("runtime_processes")) or {})
    assert rp.get("tracked") == 2
    assert rp.get("running") == 1
    assert rp.get("stale") == 1
    runtimes = (res.get("sessions") or {}).get("runtimes") or []
    assert len(runtimes) == 2


def test_call_tool_returns_structured_error_on_invalid_runtime_metadata():
    server = IDAMCPServer()
    session = _make_session()
    server._resolve_session_from_idb_ref = lambda _ref: session  # type: ignore[assignment]
    server.session_runtimes = {
        session.session_id: {
            "process": Mock(poll=Mock(return_value=None)),
            # malformed missing usable port
            "port": None,
        }
    }
    # Startup path should not be taken because process appears alive.
    server._start_server = Mock(return_value={"ok": True})

    res = server.call_tool("idb", session.idb_path, action="summary")
    assert res.get("error") is True
    assert res.get("code") == MCPError.IDA_CRASHED
    assert "Runtime metadata invalid" in str(res.get("message") or "")


def test_call_tool_restarts_dead_runtime_before_rpc():
    server = IDAMCPServer()
    session = _make_session()
    dead_proc = Mock()
    dead_proc.poll.return_value = 2
    alive_proc = Mock()
    alive_proc.poll.return_value = None

    server._resolve_session_from_idb_ref = lambda _ref: session  # type: ignore[assignment]
    server.session_runtimes = {session.session_id: {"process": dead_proc, "port": 12000}}

    def _start(_session):
        server.session_runtimes[session.session_id] = {
            "process": alive_proc,
            "port": 12001,
        }
        return {"ok": True}

    server._start_server = Mock(side_effect=_start)
    server._send_rpc_raw = Mock(return_value={"ok": True, "result": "pong"})
    server.default_truncate_tokens = 2000
    server._observe_preference = Mock()

    res = server.call_tool("idb", session.idb_path, action="summary")
    assert res.get("ok") is True
    server._start_server.assert_called_once()
    server._send_rpc_raw.assert_called_once()
