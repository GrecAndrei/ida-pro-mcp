"""Exercise successful IDA launch handoffs without requiring an IDA install."""

from __future__ import annotations

from pathlib import Path

from tests.host.test_swarm_f04_runtime import _Host


class _Process:
    pid = 31337

    def __init__(self, port_file=None):
        self.returncode = None
        if port_file:
            Path(port_file).write_text("45678", encoding="ascii")

    def poll(self):
        return self.returncode


def _configure_host(host, tmp_path, monkeypatch):
    logs = tmp_path / "logs"
    artifacts = tmp_path / "artifacts"
    logs.mkdir()
    artifacts.mkdir()
    monkeypatch.setattr(host, "_is_executable_file", lambda _path: True)
    monkeypatch.setattr(host, "_nuclear_reset", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(host, "_cleanup_stale_idb_family", lambda *_args: None)
    monkeypatch.setattr(host, "_terminate_ida_processes_for_path", lambda *_args: [])
    monkeypatch.setattr(host.session_mgr, "get_session_artifact_dir", lambda *_args, **_kwargs: str(artifacts), raising=False)
    monkeypatch.setattr(host.session_mgr, "get_session_log_dir", lambda *_args, **_kwargs: str(logs), raising=False)
    monkeypatch.setattr(host, "_write_runtime_lease", lambda *_args: None)
    monkeypatch.setattr(host, "_start_session_background_services", lambda *_args: None)
    monkeypatch.setattr(host, "_session_teardown_active", lambda _sid: False)
    monkeypatch.setattr(host, "_apply_session_options", lambda *_args: {"ok": True, "current_options": {}})
    monkeypatch.setattr(host, "_get_ida_diagnostics", lambda *_args: "")
    return artifacts


def test_start_server_inner_registers_fresh_runtime(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    artifacts = _configure_host(host, tmp_path, monkeypatch)
    session = host._make_session(tmp_path, analysis_options={"processor": "arm"})
    captured = {}

    def build_command(*args, **kwargs):
        captured["cmd_args"] = args
        return ["idat64", "-A", "-Sscript"]

    def start_process(_cmd, **kwargs):
        captured["env"] = kwargs["env"]
        return _Process(captured["env"]["IDA_MCP_PORT_FILE"])

    monkeypatch.setattr(host, "_build_ida_command", build_command)
    monkeypatch.setattr("ida_pro_mcp.host.server.server_runtime.subprocess.Popen", start_process)
    monkeypatch.setattr(host, "_send_rpc_raw", lambda request, port, **_kwargs: {"pong": True, "port": port})

    result = host._start_server_inner(session)

    assert result["ok"] is True
    assert result["port"] if "port" in result else result["idb_path"] == session.idb_path
    runtime = host.session_runtimes[session.session_id]
    assert runtime["port"] == 45678
    assert runtime["process"].pid == 31337
    assert captured["env"]["IDA_MCP_PORT"] == "0"
    assert captured["env"]["IDA_MCP_FORCE_PRE_ANALYSIS_OPTS"] == "1"
    assert not list(artifacts.glob("*.port"))


def test_launch_and_wait_registers_existing_and_sanitized_runtime(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    artifacts = _configure_host(host, tmp_path, monkeypatch)
    session = host._make_session(tmp_path, packed_idb=True, analysis_options={"processor": "arm"})
    captured = {}

    def build_command(*args, **kwargs):
        captured["command_args"] = args
        return ["idat64", "-A"]

    def start_process(_cmd, **kwargs):
        captured["env"] = kwargs["env"]
        return _Process(captured["env"]["IDA_MCP_PORT_FILE"])

    monkeypatch.setattr(host, "_build_ida_command", build_command)
    monkeypatch.setattr("ida_pro_mcp.host.server.server_runtime.subprocess.Popen", start_process)
    monkeypatch.setattr(host, "_send_rpc_raw", lambda request, port, **_kwargs: {"pong": True, "port": 45679})
    result = host._launch_and_wait(session, 0, sanitize_env=True)

    assert result["ok"] is True
    assert host.session_runtimes[session.session_id]["port"] == 45679
    assert captured["env"]["IDA_MCP_USE_EXISTING_IDB"] == "1"
    assert captured["env"]["IDA_MCP_FORCE_PRE_ANALYSIS_OPTS"] == "0"
    assert "PYTHONHOME" not in captured["env"]
    assert not list(artifacts.glob("*.port"))


def test_apply_options_composes_all_analysis_modes_and_verifies_architecture(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    session = host._make_session(
        tmp_path,
        analysis_options={
            "options": {"baseaddr": "0x400000"},
            "processor": "arm",
            "bitness": 64,
            "endian": "little",
            "loader": "elf",
            "value": "relocs=1",
            "analysis_actions": [{"action": "run"}, {"action": ""}, "bad"],
            "reanalyze": True,
            "start": "0x1000",
            "end": "0x2000",
            "symbol_import_limit": 7,
        },
    )
    runtime = {"port": 12345}
    calls = []
    notifications = []

    def send_rpc(request, _port, **_kwargs):
        calls.append(request)
        action = request.get("args", {}).get("action")
        if action == "import_symbols":
            return {"ok": True, "imported": 3}
        if action == "get_options":
            return {"ok": True, "result": {"procname": "arm", "app_bitness": 64, "is_be": False}}
        return {"ok": True}

    monkeypatch.setattr(host, "_send_rpc_raw", send_rpc)

    def send_notification(value):
        notifications.append(value)

    monkeypatch.setattr(host, "_send_notification", send_notification, raising=False)
    result = host._apply_session_options(session, runtime)

    assert result["ok"] is True
    assert result["bootstrap_knowledge"]["imported_symbol_count"] == 3
    assert session.analysis_applied is True
    assert result["steps_done"] >= 6
    assert any(call.get("args", {}).get("action") == "reanalyze" for call in calls)
    assert any(item["method"] == "notifications/progress" for item in notifications)

    failed = host._make_session(tmp_path, analysis_options={"options": {"baseaddr": 1}})
    monkeypatch.setattr(host, "_send_rpc_raw", lambda *_args, **_kwargs: {"error": True, "message": "rejected"})
    failure = host._apply_session_options(failed, runtime)
    assert failure["error"] is True


def test_apply_options_noop_skip_and_architecture_mismatch_modes(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    empty = host._make_session(tmp_path)
    assert host._apply_session_options(empty, {"port": 12345}) == {"ok": True}
    no_port = host._make_session(tmp_path, analysis_options={"reanalyze": True})
    assert host._apply_session_options(no_port, {})["error"] is True

    skipped = host._make_session(tmp_path, analysis_options={"options": {"baseaddr": 1}})
    skipped.analysis_applied = True
    assert host._apply_session_options(skipped, {"port": 12345})["skipped"] is True

    mismatch = host._make_session(
        tmp_path,
        analysis_options={"processor": "arm", "bitness": 64, "endian": "big"},
    )
    monkeypatch.setattr(host, "_send_rpc_raw", lambda *_args, **_kwargs: {"ok": True, "result": {"procname": "x86", "app_bitness": 32, "is_be": False}})
    result = host._apply_session_options(mismatch, {"port": 12345})
    assert result["error"] is True


def test_recovery_relaunches_packed_session_and_removes_stale_sidecars(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    session = host._make_session(
        tmp_path,
        packed_idb=True,
        analysis_options={"backup_on_recover": True, "aggressive_cleanup": False},
    )
    for suffix in (".id0", ".id1", ".nam", ".til"):
        Path(session.binary_path).with_suffix(suffix).write_text("stale", encoding="ascii")
    host._claim_runtime_ownership(session.session_id)
    monkeypatch.setattr(host, "_cleanup_runtime", host._release_runtime_ownership)
    monkeypatch.setattr(host, "_extract_library_init_failure", lambda _diag: {"error_code": 4})
    monkeypatch.setattr(host, "_is_orphan_locked_db_open_failure", lambda _diag: False)
    monkeypatch.setattr(host, "_backup_idb", lambda _path: "/tmp/recovery-backup.i64")
    cleanup = []
    monkeypatch.setattr(
        host,
        "_nuclear_reset",
        lambda path, aggressive=False: cleanup.append((path, aggressive)),
    )
    killed = []
    monkeypatch.setattr(
        host,
        "_terminate_ida_processes_for_path",
        lambda path: killed.append(path) or [123],
    )
    monkeypatch.setattr("ida_pro_mcp.host.server.server_runtime.time.sleep", lambda *_args: None)
    persisted = []
    monkeypatch.setattr(
        host,
        "_persist_session_fields",
        lambda _session, **updates: persisted.append(updates),
    )
    services = []
    monkeypatch.setattr(
        host,
        "_start_session_background_services",
        lambda _session, port: services.append(port),
    )

    def relaunch(_session, _port, sanitize_env=False):
        assert sanitize_env is False
        host.session_runtimes[session.session_id] = {
            "process": object(),
            "port": 45680,
        }
        return {"ok": True, "idb_path": session.idb_path, "port": 45680}

    monkeypatch.setattr(host, "_launch_and_wait", relaunch)
    monkeypatch.setattr(host, "_apply_session_options", lambda *_args: {"ok": True, "current_options": {}})

    result = host._attempt_session_recovery(session, "library init failed", 0)

    assert result["ok"] is True
    assert result["backup"] == "/tmp/recovery-backup.i64"
    assert cleanup == [(session.idb_path, False)]
    assert killed == [session.binary_path]
    assert persisted == [{"analysis_applied": False}]
    assert services == [45680]
    assert all(not Path(session.binary_path).with_suffix(suffix).exists() for suffix in (".id0", ".id1", ".nam", ".til"))
    assert Path(host._runtime_owner_path(session.session_id)).exists()


def test_recovery_sanitized_retry_failure_is_reported(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    session = host._make_session(tmp_path, analysis_options={"backup_on_recover": False})
    host._claim_runtime_ownership(session.session_id)
    monkeypatch.setattr(host, "_cleanup_runtime", host._release_runtime_ownership)
    monkeypatch.setattr(host, "_extract_library_init_failure", lambda _diag: {"error_code": 127})
    monkeypatch.setattr(host, "_is_orphan_locked_db_open_failure", lambda _diag: False)
    monkeypatch.setattr(host, "_nuclear_reset", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(host, "_terminate_ida_processes_for_path", lambda _path: [])
    monkeypatch.setattr(host, "_persist_session_fields", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("ida_pro_mcp.host.server.server_runtime.time.sleep", lambda *_args: None)
    attempts = []

    def failed_launch(_session, _port, sanitize_env=False):
        attempts.append(sanitize_env)
        return {"error": True, "library_init": {"error_code": 127}, "exit_code": 1}

    monkeypatch.setattr(host, "_launch_and_wait", failed_launch)
    result = host._attempt_session_recovery(session, "library init failed", 0)

    assert result["error"] is True
    assert result["code"] == "IDA_CRASHED"
    assert attempts == [False, True]
    assert result["details"]["recovery_attempted"] is True
    assert result["details"]["sanitized_retry"]["exit_code"] == 1


def test_recovery_disabled_preserves_diagnostic_categories(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    session = host._make_session(tmp_path, analysis_options={"recover": False})
    monkeypatch.setattr(host, "_extract_library_init_failure", lambda _diag: {"error_code": 4})
    monkeypatch.setattr(host, "_is_orphan_locked_db_open_failure", lambda _diag: True)

    result = host._attempt_session_recovery(session, "diagnostic", 0)

    assert result["error"] is True
    assert result["code"] == "IDA_CRASHED"
    assert result["details"] == {
        "log": "diagnostic",
        "recovery_attempted": False,
        "library_init": {"error_code": 4},
        "orphan_locked_db": True,
    }
