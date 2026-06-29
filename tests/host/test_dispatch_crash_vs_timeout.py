"""Regression: a slow RPC that times out must NOT be reported as IDA_CRASHED.

The dispatch ``call_tool`` except-block historically returned ``IDA_CRASHED``
for *any* exception, including ``socket.timeout`` from the RPC recv deadline
(``IDA_MCP_RPC_TIMEOUT``, default 30s) when the IDA process was still alive.
That was a false crash: the process hadn't exited, the call just needed more
time. These tests pin the corrected behavior:

  * alive process + socket/timeout error  -> IDA_TIMEOUT, recoverable
  * alive process + other error           -> RPC_CONNECTION_ERROR, recoverable
  * dead process (poll() is not None)     -> IDA_CRASHED (unchanged)
"""
import os
import socket
import sys
from unittest.mock import Mock

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin  # noqa: E402
from ida_pro_mcp.services import MCPError, Session  # noqa: E402


def _session() -> Session:
    return Session(
        session_id="A1B2C3D4",
        idb_path="/tmp/a.i64",
        binary_path="/tmp/a.bin",
    )


class _Dispatch(ServerDispatchMixin):
    """Minimal host stand-in exercising only the call_tool except-block."""

    def __init__(self, rpc_exc, proc_poll):
        self.default_truncate_tokens = 4096
        proc = Mock()
        proc.poll = lambda: proc_poll
        self.session_runtimes = {
            "A1B2C3D4": {
                "process": proc,
                "port": 9999,
                "stdout_log": "",
                "stderr_log": "",
            }
        }
        self._rpc_exc = rpc_exc

    # --- mocked collaborators -------------------------------------------
    def _resolve_session_from_idb_ref(self, idb_path):
        return _session()

    @staticmethod
    def _runtime_alive(runtime):
        return runtime is not None

    def _send_rpc_raw(self, payload, port, **kwargs):
        raise self._rpc_exc

    def _get_ida_diagnostics(self, *a, **k):
        return ""


def _call(rpc_exc, proc_poll):
    return _Dispatch(rpc_exc, proc_poll).call_tool("code.decompile", "any.i64")


def test_alive_socket_timeout_is_ida_timeout_not_crash():
    res = _call(TimeoutError("recv timed out"), None)
    assert res["code"] == MCPError.IDA_TIMEOUT
    assert res["recoverable"] is True
    assert res["details"]["port"] == 9999
    assert "rpc_timeout_sec" in res["details"]


def test_alive_timeouterror_is_ida_timeout():
    res = _call(TimeoutError("recv timed out"), None)
    assert res["code"] == MCPError.IDA_TIMEOUT
    assert res["recoverable"] is True


def test_alive_other_error_is_rpc_connection_error():
    res = _call(ValueError("malformed frame"), None)
    assert res["code"] == MCPError.RPC_CONNECTION_ERROR
    assert res["recoverable"] is True
    assert "process alive" in res["message"]


def test_dead_process_still_reports_crash():
    res = _call(TimeoutError("recv timed out"), 1)
    assert res["code"] == MCPError.IDA_CRASHED
    assert res["recoverable"] is False
