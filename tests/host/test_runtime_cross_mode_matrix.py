"""Cross-mode runtime coverage for startup, recovery, and observability."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_runtime as runtime_mod
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin
from tests.host.test_swarm_f04_runtime import _Host as F04Host


class _Process:
    pid = 4545

    def __init__(self, exit_code=None, port_file=None):
        self.exit_code = exit_code
        self.returncode = exit_code
        if port_file:
            Path(port_file).write_text("45690", encoding="ascii")

    def poll(self):
        return self.exit_code


def _configure_launch(host, tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    logs = tmp_path / "logs"
    artifacts.mkdir(exist_ok=True)
    logs.mkdir(exist_ok=True)
    monkeypatch.setattr(host.session_mgr, "get_session_artifact_dir", lambda *_a, **_k: str(artifacts))
    monkeypatch.setattr(host.session_mgr, "get_session_log_dir", lambda *_a, **_k: str(logs))
    monkeypatch.setattr(host, "_is_executable_file", lambda _path: True)
    monkeypatch.setattr(host, "_nuclear_reset", lambda *_a, **_k: None)
    monkeypatch.setattr(host, "_cleanup_stale_idb_family", lambda *_a: None)
    monkeypatch.setattr(host, "_get_ida_diagnostics", lambda *_a, **_k: "ordinary startup output")
    monkeypatch.setattr(host, "_extract_library_init_failure", lambda _diag: None)
    monkeypatch.setattr(host, "_is_library_init_err2", lambda _diag: False)
    monkeypatch.setattr(host, "_is_orphan_locked_db_open_failure", lambda _diag: False)
    monkeypatch.setattr(runtime_mod, "_kill_process_tree", lambda *_a, **_k: None)
    return artifacts, logs


def test_startup_backend_rejections_and_ownership_release(tmp_path, monkeypatch):
    host = F04Host(tmp_path)
    session = host._make_session(tmp_path)
    host.idat_exe = ""
    monkeypatch.setattr(host, "_is_idalib_runtime", lambda: False)
    result = host._start_server_inner(session)
    assert result["error"] is True
    assert result["code"] == MCPError.FILE_NOT_FOUND

    host = F04Host(tmp_path / "idalib")
    session = host._make_session(tmp_path / "idalib")
    host.ida_dir = str(tmp_path / "missing-ida")
    monkeypatch.setattr(host, "_is_idalib_runtime", lambda: True)
    monkeypatch.setattr(host, "_idalib_python_dir", lambda: "")
    result = host._start_server_inner(session)
    assert result["error"] is True
    assert result["code"] == MCPError.FILE_NOT_FOUND

    host = F04Host(tmp_path / "ownership")
    session = host._make_session(tmp_path / "ownership")
    monkeypatch.setattr(host, "_start_server_inner", lambda _session: {"error": True, "code": "failed"})
    result = host._start_server(session)
    assert result["error"] is True
    assert not Path(host._runtime_owner_path(session.session_id)).exists()


def test_startup_crash_timeout_and_ping_retry_paths(tmp_path, monkeypatch):
    host = F04Host(tmp_path)
    session = host._make_session(tmp_path)
    _configure_launch(host, tmp_path, monkeypatch)
    monkeypatch.setattr(host, "_build_ida_command", lambda *_a, **_k: ["idat64"])
    monkeypatch.setattr(runtime_mod.subprocess, "Popen", lambda *_a, **_k: _Process(exit_code=17))
    result = host._start_server_inner(session)
    assert result["error"] is True
    assert result["code"] == MCPError.IDA_CRASHED
    assert "ordinary startup output" in result["details"]["log"]

    host = F04Host(tmp_path / "timeout")
    session = host._make_session(tmp_path / "timeout")
    _configure_launch(host, tmp_path / "timeout", monkeypatch)
    monkeypatch.setattr(host, "_build_ida_command", lambda *_a, **_k: ["idat64"])
    monkeypatch.setattr(runtime_mod.subprocess, "Popen", lambda *_a, **_k: _Process())
    monkeypatch.setattr(runtime_mod, "_resolve_startup_timeout", lambda: 1)
    monkeypatch.setattr(runtime_mod.time, "sleep", lambda *_a: None)
    clock = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(runtime_mod.time, "time", lambda: next(clock))
    result = host._start_server_inner(session)
    assert result["error"] is True
    assert result["code"] == MCPError.IDA_TIMEOUT

    host = F04Host(tmp_path / "ping")
    session = host._make_session(tmp_path / "ping")
    _configure_launch(host, tmp_path / "ping", monkeypatch)
    monkeypatch.setattr(host, "_build_ida_command", lambda *_a, **_k: ["idat64"])
    monkeypatch.setattr(runtime_mod.subprocess, "Popen", lambda _cmd, **kwargs: _Process(port_file=kwargs["env"]["IDA_MCP_PORT_FILE"]))
    monkeypatch.setattr(host, "_send_rpc_raw", lambda *_a, **_k: (_ for _ in ()).throw(ConnectionRefusedError("warming up")))
    monkeypatch.setattr(runtime_mod, "_resolve_startup_timeout", lambda: 1)
    clock = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(runtime_mod.time, "time", lambda: next(clock))
    result = host._start_server_inner(session)
    assert result["error"] is True
    assert result["code"] == MCPError.IDA_TIMEOUT


def test_idalib_launch_exports_worker_environment_and_sanitizes(tmp_path, monkeypatch):
    host = F04Host(tmp_path)
    session = host._make_session(tmp_path, packed_idb=True, analysis_options={"processor": "arm"})
    _, logs = _configure_launch(host, tmp_path, monkeypatch)
    host.ida_dir = str(tmp_path / "ida")
    host.idat_exe = str(Path(host.ida_dir) / "idat64")
    monkeypatch.setenv("IDA_MCP_RUNTIME", "idalib")
    monkeypatch.setenv("PYTHONPATH", "/contaminated")
    monkeypatch.setenv("PYTHONHOME", "/contaminated-home")
    captured = {}
    monkeypatch.setattr(host, "_idalib_python_dir", lambda: str(tmp_path / "idalib-python"))
    monkeypatch.setattr(
        host,
        "_build_idalib_command",
        lambda *_a, **_k: (["python", "-m", "worker"], {"existing": True}, str(tmp_path / "package")),
    )

    def popen(_cmd, **kwargs):
        captured.update(kwargs)
        return _Process(exit_code=3)

    monkeypatch.setattr(runtime_mod.subprocess, "Popen", popen)
    result = host._launch_and_wait(session, 0, sanitize_env=True)
    assert result["error"] is True
    assert result["code"] == MCPError.IDA_CRASHED
    env = captured["env"]
    assert env["IDA_MCP_IDALIB_PYTHON_DIR"] == str(tmp_path / "idalib-python")
    assert env["IDA_MCP_USE_EXISTING_IDB"] == "1"
    assert "PYTHONHOME" not in env
    assert env["PYTHONPATH"].startswith(str(tmp_path / "package"))
    assert (logs / "ida_stdout.log").exists()


def test_apply_options_fallbacks_and_observability_failures(tmp_path, monkeypatch):
    host = F04Host(tmp_path)
    session = host._make_session(
        tmp_path,
        analysis_options={
            "loader_options": {"format": "raw"},
            "processor": "",
            "bitness": 0,
            "flags": 0,
            "analysis_actions": [None, {}, {"action": ""}],
            "reanalyze": False,
            "apply_once": False,
        },
    )
    calls = []

    def send_rpc(request, _port, **_kwargs):
        calls.append(request)
        action = request.get("args", {}).get("action")
        if action == "import_symbols":
            raise RuntimeError("optional symbols unavailable")
        if action == "get_options":
            raise RuntimeError("options unavailable")
        return {"ok": True}

    monkeypatch.setattr(host, "_send_rpc_raw", send_rpc)
    result = host._apply_session_options(session, {"port": 45690})
    assert result["ok"] is True
    assert session.analysis_applied is False
    assert [call["args"]["action"] for call in calls] == [
        "set_loader_options",
        "import_symbols",
        "get_options",
    ]

    host._query_ida_state = lambda *_a, **_k: None
    assert host._record_analysis_checkpoint(session.session_id) is None


def test_watchdog_marks_stalled_and_active_analysis_differently(monkeypatch, tmp_path):
    class Host(ServerRuntimeMixin):
        pass

    host = Host.__new__(Host)
    host._runtime_lock = threading.RLock()
    host._analysis_watchdog_lock = threading.RLock()
    host._analysis_watchdog_stop_events = {}
    host._analysis_watchdog_threads = {}
    host.session_runtimes = {"AB12CDEF": {"process": _Process(), "port": 45690}}
    host._analysis_watchdog_interval = 0.01
    host._analysis_watchdog_stall_seconds = 0.01
    host._runtime_alive = lambda runtime: isinstance(runtime, dict)
    updates = []
    host._update_session_indexing_metadata = lambda sid, **values: updates.append((sid, values))
    states = iter(
        [
            {"analysis": {"is_ok": False, "active": False}, "inventory": {"functions_qty": 1}},
            {"analysis": {"is_ok": False, "active": True}, "inventory": {"functions_qty": 1}},
            {"analysis": {"is_ok": False, "active": False}, "inventory": {"functions_qty": "bad"}},
        ]
    )
    host._query_ida_state = lambda *_a, **_k: next(states)
    times = iter((0.0, 0.02, 0.03, 0.05, 0.06, 0.08))
    monkeypatch.setattr(runtime_mod.time, "time", lambda: next(times))

    class Event:
        def __init__(self):
            self.calls = 0

        def wait(self, _interval):
            self.calls += 1
            return self.calls > 3

        def set(self):
            return None

    class ImmediateThread:
        def __init__(self, target, **_kwargs):
            self.target = target

        def start(self):
            self.target()

        def is_alive(self):
            return False

        def join(self, **_kwargs):
            return None

    monkeypatch.setattr(runtime_mod.threading, "Event", Event)
    monkeypatch.setattr(runtime_mod.threading, "Thread", ImmediateThread)
    host._start_analysis_watchdog("AB12CDEF", 45690)
    verdicts = [row[1].get("analysis_state") for row in updates]
    assert "stalled" in verdicts
    assert "analyzing" in verdicts
    host._stop_analysis_watchdog("AB12CDEF")
