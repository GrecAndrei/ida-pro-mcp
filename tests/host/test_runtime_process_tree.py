import threading
from unittest import mock

from ida_pro_mcp.host.server import server_runtime
from ida_pro_mcp.host.server.server_runtime_leases import ServerRuntimeLeasesMixin


def test_kill_process_tree_terminates_group_after_direct_launcher_exits(monkeypatch):
    """A surviving child in the launcher's group must not be orphaned."""

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
    with mock.patch.object(server_runtime.os, "killpg") as killpg:
        server_runtime._kill_process_tree(ExitedLauncher())

    killpg.assert_called_once_with(4242, server_runtime.signal.SIGTERM)


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
