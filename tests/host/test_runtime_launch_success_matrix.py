"""Exercise successful runtime launches through both host backends."""

from __future__ import annotations

from pathlib import Path

from ida_pro_mcp.host.server import server_runtime as runtime_mod
from tests.host.test_swarm_f04_runtime import _Host


class _Process:
    pid = 4545

    def __init__(self, port_file=None):
        self.returncode = None
        if port_file:
            Path(port_file).write_text("45690", encoding="ascii")

    def poll(self):
        return None


def _configure(host, tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    logs = tmp_path / "logs"
    artifacts.mkdir(parents=True)
    logs.mkdir(parents=True)
    monkeypatch.setattr(
        host.session_mgr,
        "get_session_artifact_dir",
        lambda *_args, **_kwargs: str(artifacts),
    )
    monkeypatch.setattr(
        host.session_mgr,
        "get_session_log_dir",
        lambda *_args, **_kwargs: str(logs),
    )
    monkeypatch.setattr(host, "_is_executable_file", lambda _path: True)
    monkeypatch.setattr(host, "_nuclear_reset", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(host, "_cleanup_stale_idb_family", lambda *_args: None)
    monkeypatch.setattr(host, "_terminate_ida_processes_for_path", lambda _path: [])
    monkeypatch.setattr(host, "_start_session_background_services", lambda *_args: None)
    monkeypatch.setattr(runtime_mod, "_resolve_startup_timeout", lambda: 2)
    monkeypatch.setattr(runtime_mod.time, "sleep", lambda *_args: None)
    return artifacts, logs


def test_idat_new_database_registers_runtime_and_applies_options(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    session = host._make_session(
        tmp_path,
        analysis_options={"processor": "arm", "bitness": 32, "reanalyze": True},
    )
    artifacts, logs = _configure(host, tmp_path, monkeypatch)
    built = []
    applied = []
    monkeypatch.setattr(
        host,
        "_build_ida_command",
        lambda *args, **kwargs: built.append((args, kwargs)) or ["idat64"],
    )

    def popen(_cmd, **kwargs):
        return _Process(port_file=kwargs["env"]["IDA_MCP_PORT_FILE"])

    monkeypatch.setattr(runtime_mod.subprocess, "Popen", popen)
    monkeypatch.setattr(
        host,
        "_send_rpc_raw",
        lambda request, _port, **_kwargs: {"pong": True, "port": 45690}
        if request.get("type") == "ping"
        else {"ok": True},
    )
    monkeypatch.setattr(
        host,
        "_apply_session_options",
        lambda current, runtime: applied.append((current, runtime))
        or {"ok": True, "current_options": {"procname": "arm"}, "apply_steps": ["reanalyze"], "steps_done": 1},
    )

    result = host._start_server_inner(session)

    assert result["ok"] is True
    assert result["analysis_in_progress"] is True
    assert result["current_options"] == {"procname": "arm"}
    assert result["indexing_state"] == "disabled"
    assert built and built[0][0][3] is False
    assert applied and applied[0][1]["port"] == 45690
    assert session.session_id in host.session_runtimes
    assert not list(artifacts.glob("*.port"))
    assert (logs / "ida_stdout.log").exists()
    assert host.session_runtimes[session.session_id]["auth_token"]


def test_existing_idb_and_idalib_launch_paths_keep_open_target_explicit(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    session = host._make_session(tmp_path)
    Path(session.idb_path).parent.mkdir(parents=True, exist_ok=True)
    Path(session.idb_path).write_bytes(b"existing")
    _configure(host, tmp_path, monkeypatch)
    killed = []
    monkeypatch.setattr(host, "_terminate_ida_processes_for_path", killed.append)
    monkeypatch.setattr(host, "_build_ida_command", lambda *args, **kwargs: ["idat64"])
    monkeypatch.setattr(
        runtime_mod.subprocess,
        "Popen",
        lambda _cmd, **kwargs: _Process(port_file=kwargs["env"]["IDA_MCP_PORT_FILE"]),
    )
    monkeypatch.setattr(host, "_send_rpc_raw", lambda *_args, **_kwargs: {"pong": True, "port": 45691})
    monkeypatch.setattr(host, "_apply_session_options", lambda *_args: {"ok": True})
    result = host._start_server_inner(session)
    assert result["ok"] is True
    assert killed == [session.idb_path]

    # The worker backend uses the packed file itself as its existing target and
    # carries the open spec through the same registration handshake.
    host = _Host(tmp_path / "idalib")
    session = host._make_session(tmp_path / "idalib", packed_idb=True, analysis_options={"processor": "mips"})
    Path(session.binary_path).write_bytes(b"packed")
    _configure(host, tmp_path / "idalib", monkeypatch)
    host.ida_dir = str(tmp_path / "idalib-install")
    monkeypatch.setattr(host, "_is_idalib_runtime", lambda: True)
    monkeypatch.setattr(host, "_idalib_python_dir", lambda: str(tmp_path / "idalib-python"))
    captured = {}
    monkeypatch.setattr(
        host,
        "_build_idalib_command",
        lambda *args, **kwargs: captured.update(args=args, kwargs=kwargs)
        or (["python", "-m", "worker"], {"existing": True}, str(tmp_path)),
    )
    monkeypatch.setattr(
        runtime_mod.subprocess,
        "Popen",
        lambda _cmd, **kwargs: _Process(port_file=kwargs["env"]["IDA_MCP_PORT_FILE"]),
    )
    monkeypatch.setattr(host, "_send_rpc_raw", lambda *_args, **_kwargs: {"pong": True, "port": 45692})
    monkeypatch.setattr(host, "_apply_session_options", lambda *_args: {"ok": True})
    result = host._start_server_inner(session)
    assert result["ok"] is True
    assert captured["args"][3] == session.binary_path


def test_apply_options_records_steps_and_reports_architecture_mismatch(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    session = host._make_session(
        tmp_path,
        analysis_options={
            "options": {"max_ea": "0x2000"},
            "processor": "arm",
            "bitness": 64,
            "endian": "be",
            "value": {"format": "raw"},
            "analysis_actions": [{"action": "set_options", "options": {"min_ea": "0x10"}}, "bad"],
            "reanalyze": True,
            "apply_once": True,
        },
    )
    updates = []
    notifications = []
    calls = []
    host._update_session_indexing_metadata = lambda sid, **values: updates.append((sid, values))

    def record_notification(value):
        notifications.append(value)

    host._send_notification = record_notification

    def send_rpc(request, _port, **_kwargs):
        calls.append(request)
        if request["args"]["action"] == "get_options":
            return {"result": {"procname": "x86", "app_bitness": 32, "is_be": False}}
        return {"ok": True}

    host._send_rpc_raw = send_rpc
    result = host._apply_session_options(session, {"port": 45690})
    assert result["error"] is True
    assert "mismatches" in result["details"]
    assert session.analysis_applied is True
    assert any(item["params"]["progress"]["status"] == "done" for item in notifications)
    assert any(item[1].get("apply_progress") for item in updates)
    assert [request["args"]["action"] for request in calls] == [
        "set_options", "set_architecture", "set_loader_options", "set_options", "reanalyze", "import_symbols", "get_options"
    ]
