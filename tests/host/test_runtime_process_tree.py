import json
import threading
from unittest import mock

from ida_pro_mcp.host.server import server_runtime
from ida_pro_mcp.host.server.server_runtime_leases import ServerRuntimeLeasesMixin


def test_kill_process_tree_terminates_group_after_direct_launcher_exits(monkeypatch):
    """A surviving child in the launcher's group must not be orphaned.

    The direct idat launcher exits quickly while descendants may still be
    alive in the same process group. The function must wait for the group to
    drain (killpg(pid, 0) liveness probe) rather than returning the moment the
    direct child exits, and must not escalate to SIGKILL once the group is
    confirmed gone.
    """

    class ExitedLauncher:
        pid = 4242

        @staticmethod
        def poll():
            return 0

        @staticmethod
        def wait(*, timeout):
            assert timeout > 0
            return 0

    monkeypatch.setattr(server_runtime.sys, "platform", "linux")
    calls = []

    def _killpg(pgid, sig):
        calls.append(sig)
        if sig == server_runtime.signal.SIGTERM:
            return None
        # Liveness probe on the (draining) group: already gone, so the
        # launcher's descendants exited and no SIGKILL escalation is needed.
        raise ProcessLookupError()

    monkeypatch.setattr(server_runtime.os, "killpg", _killpg)
    server_runtime._kill_process_tree(ExitedLauncher())

    assert calls == [
        server_runtime.signal.SIGTERM,
        0,  # process-group liveness probe
    ]
    assert server_runtime.signal.SIGKILL not in calls


def test_kill_process_tree_escalates_to_sigkill_when_group_never_drains(monkeypatch):
    """Descendants that ignore SIGTERM must still be SIGKILLed."""

    class StubbornLauncher:
        pid = 4242

        @staticmethod
        def poll():
            return 0

        @staticmethod
        def wait(*, timeout):
            assert timeout > 0
            return 0

    monkeypatch.setattr(server_runtime.sys, "platform", "linux")
    calls = []
    # The process group never drains (the liveness probe keeps succeeding), so
    # after the grace budget the function must escalate to SIGKILL.
    monkeypatch.setattr(
        server_runtime.os,
        "killpg",
        lambda pgid, sig: calls.append(sig) or None,
    )
    server_runtime._kill_process_tree(StubbornLauncher(), grace_seconds=0.2)

    assert calls[0] == server_runtime.signal.SIGTERM
    assert 0 in calls  # liveness probes ran while waiting for the drain
    assert calls[-1] == server_runtime.signal.SIGKILL


def test_termination_signal_runs_cleanup_before_forced_exit():
    class Runtime:
        _shutdown_requested = False
        _lease_thread_stop = threading.Event()
        shutdown = mock.Mock()

    runtime = Runtime()
    ServerRuntimeLeasesMixin._handle_termination_signal(runtime, None, None)

    assert runtime._shutdown_requested is True
    assert runtime._lease_thread_stop.is_set()
    runtime.shutdown.assert_called_once_with()


def test_stale_lease_never_terminates_an_ida_runtime_owned_by_live_host(tmp_path):
    """A second MCP process must not reclaim a live peer's IDA runtime."""

    class Runtime(ServerRuntimeLeasesMixin):
        def __init__(self):
            self._runtime_lease_dir = str(tmp_path)
            self._runtime_lock = threading.RLock()
            self.session_runtimes = {}
            self.idat_exe = ""

        @staticmethod
        def _ida_binary_names():
            return ["idat64"]

    runtime = Runtime()
    lease_path = tmp_path / "SID_A1B2C3D4.lease.json"
    lease_path.write_text(
        json.dumps(
            {
                "session_id": "A1B2C3D4",
                "pid": 54321,
                "owner_pid": 12345,
                "updated_at": 0,
            }
        ),
        encoding="utf-8",
    )
    runtime._is_expected_ida_process = mock.Mock(return_value=True)
    runtime._kill_stale_pid = mock.Mock(return_value=True)

    # A successful signal-0 probe represents a different live MCP host.
    with mock.patch.object(server_runtime.os, "kill", return_value=None):
        runtime._cleanup_stale_runtime_leases()

    runtime._is_expected_ida_process.assert_not_called()
    runtime._kill_stale_pid.assert_not_called()
    assert lease_path.exists()
