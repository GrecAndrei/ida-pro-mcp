"""Cover remaining server-runtime lifecycle and serialization boundaries."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server import server_runtime as runtime_mod
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin


class _Host(ServerRuntimeMixin):
    def __init__(self, tmp_path):
        self.cache_dir = str(tmp_path)
        self._runtime_lease_dir = str(tmp_path / "leases")
        Path(self._runtime_lease_dir).mkdir(parents=True)
        self._runtime_owner_id = "runtime-test-owner"
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self._session_last_activity = {}
        self._session_inflight_calls = {}
        self._activity_log = []
        self._activity_log_max = 20
        self.session_mgr = SimpleNamespace(sessions={})
        self.ida_dir = ""
        self.idat_exe = ""


class _TreeProcess:
    pid = 4123

    def __init__(self, wait_error: Exception | None = None):
        self.wait_error = wait_error

    def wait(self, **_kwargs):
        if self.wait_error:
            raise self.wait_error
        return 0


def test_kill_process_tree_handles_empty_process_and_posix_escalation(monkeypatch):
    runtime_mod._kill_process_tree(None)
    runtime_mod._kill_process_tree(SimpleNamespace(pid=None))

    monkeypatch.setattr(runtime_mod.sys, "platform", "win32")
    monkeypatch.setattr(
        runtime_mod.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("taskkill unavailable")),
    )
    runtime_mod._kill_process_tree(_TreeProcess(OSError("wait failed")), grace_seconds=0)

    monkeypatch.setattr(runtime_mod.sys, "platform", "linux")

    def gone(_pid, _sig):
        raise ProcessLookupError

    monkeypatch.setattr(runtime_mod.os, "killpg", gone)
    runtime_mod._kill_process_tree(_TreeProcess(), grace_seconds=0)

    calls = []

    def probe_error(pid, sig):
        calls.append(sig)
        if sig == 0:
            raise RuntimeError("cannot probe")

    monkeypatch.setattr(runtime_mod.os, "killpg", probe_error)
    monkeypatch.setattr(runtime_mod.time, "time", lambda: 0.0)
    runtime_mod._kill_process_tree(_TreeProcess(), grace_seconds=1)
    assert calls == [signal.SIGTERM, 0]

    calls.clear()
    values = iter([0.0, 2.0])
    monkeypatch.setattr(runtime_mod.time, "time", lambda: next(values))

    def sigkill_error(_pid, sig):
        calls.append(sig)
        if sig == signal.SIGKILL:
            raise OSError("kill denied")

    monkeypatch.setattr(runtime_mod.os, "killpg", sigkill_error)
    runtime_mod._kill_process_tree(_TreeProcess(), grace_seconds=1)
    assert calls == [signal.SIGTERM, signal.SIGKILL]


def test_runtime_state_and_ownership_recovery_modes(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    lazy = object.__new__(_Host)
    lazy.session_runtimes = {}
    lock = lazy._runtime_state_lock()
    assert lock is not None
    assert lazy._runtime_state_lock() is lock

    sid = "AB12CDEF"
    owner_path = Path(host._runtime_owner_path(sid))
    owner_path.parent.mkdir(parents=True, exist_ok=True)
    owner_path.write_text(
        json.dumps({"owner_id": "other", "owner_pid": os.getpid(), "owner_start_token": "old"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(runtime_mod, "_process_start_token", lambda _pid: "")
    assert host._claim_runtime_ownership(sid) is None

    owner_path.write_text(json.dumps({"owner_id": "other", "owner_pid": os.getpid()}), encoding="utf-8")
    assert host._claim_runtime_ownership(sid) is None

    owner_path.write_text("not-json", encoding="utf-8")
    monkeypatch.setattr(runtime_mod.os, "kill", lambda *_args: (_ for _ in ()).throw(ProcessLookupError))
    claimed = host._claim_runtime_ownership(sid)
    assert claimed == str(owner_path)
    host._release_runtime_ownership(sid)
    assert not owner_path.exists()

    host.session_runtimes = {sid: {"port": 4}, "bad": None}
    assert host._runtime_record(sid)["port"] == 4
    assert host._runtime_update(sid, auth_token="token") is True
    assert host._runtime_update("missing", port=9) is False


def test_runtime_diagnostics_and_process_termination_failure_envelopes(tmp_path):
    host = _Host(tmp_path)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    stdout = log_dir / "ida_stdout.log"
    stdout.write_text("one\ntwo\n", encoding="utf-8")
    assert host._tail_text_file(str(log_dir), 1) == ""

    class BadProcess:
        pid = 7

        def poll(self):
            raise RuntimeError("poll broken")

    class BadString:
        def __str__(self):
            raise RuntimeError("string broken")

    snap = host._collect_ida_state_snapshot(
        {"process": BadProcess(), "stdout_log": str(stdout)},
        current_args={"bad": BadString()},
        include_process_stats=True,
    )
    assert snap["process_alive"] is None
    assert snap["process_error"] == "poll broken"
    assert snap["ida_stdout_tail"] == "one\ntwo"
    assert snap["current_args"] == "<unserializable>"

    class FailingProcess:
        pid = 8

        def __init__(self):
            self.waits = 0

        def poll(self):
            raise RuntimeError("poll error")

        def terminate(self):
            raise OSError("term error")

        def kill(self):
            raise OSError("kill error")

        def wait(self, **_kwargs):
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired(["ida"], 1)
            raise OSError("final wait error")

    assert host._kill_ida_process({})["error"] == "no_process_in_runtime"
    result = host._kill_ida_process({"process": FailingProcess()})
    assert result["attempted"] is True
    assert "terminate_error" in result
    assert "kill_error" in result
    assert "final_wait_error" in result


def test_runtime_failure_classification_and_argument_normalization(tmp_path):
    host = _Host(tmp_path)
    assert host._extract_library_init_failure("") is None
    assert host._extract_library_init_failure("unrelated output") is None
    info = host._extract_library_init_failure(
        "Library initialization failed, error=2; cannot open shared object file; "
        "GLIBCXX plugin python init no space left on device"
    )
    assert info["detected"] is True
    assert info["error_code"] == 2
    assert len(info["causes"]) >= 4
    assert host._is_library_init_err2("Database init failed error 2") is True
    assert host._is_library_init_err2("plain output") is False
    assert host._is_orphan_locked_db_open_failure(
        "resource temporarily unavailable; database did not close properly"
    ) is True
    assert host._is_orphan_locked_db_open_failure("error 4") is False

    assert host._normalize_ida_args(None) == []
    assert host._normalize_ida_args("-A --foo 'bar baz'") == ["--foo", "bar baz"]
    assert host._normalize_ida_args([None, "-A", "--foo"]) == ["--foo"]
    for bad in ("-Sscript", [""], ["bad\x00arg"], 3):
        with pytest.raises(ValueError):
            host._normalize_ida_args(bad)


def test_macro_registry_json_safe_values_and_payload_rendering(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    host._macro_path = str(tmp_path / "macros.json")
    host._load_session_macros()
    assert host._session_macros == {}
    Path(host._macro_path).write_text("not-json", encoding="utf-8")
    host._load_session_macros()
    assert host._session_macros == {}
    Path(host._macro_path).write_text(
        json.dumps(
            {
                "GOOD": {"name": "Good", "data": {"action": "state"}, "updated_at": "now"},
                "bad-value": [],
                "bad-data": {"name": "bad", "data": []},
                1: {"name": "ignored", "data": {}},
            }
        ),
        encoding="utf-8",
    )
    host._load_session_macros()
    assert set(host._session_macros) == {"good", "1"}
    host._save_session_macros()
    assert Path(host._macro_path).is_file()
    monkeypatch.setattr(runtime_mod.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("replace")))
    host._save_session_macros()
    assert host._normalize_macro_name(None) is None
    assert host._normalize_macro_name("   ") is None
    assert host._normalize_macro_name(" a\t b ") == "a b"

    class BadKey:
        def __str__(self):
            raise RuntimeError("bad key")

    safe = host._json_safe_value(
        {BadKey(): b"\xff", "utf8": b"ok", "nested": bytearray(b"x"), "set": {1, 2}}
    )
    assert safe["<non_string_key>"]["_bytes_hex"] == "ff"
    rendered = host._render_payload_text(
        {"empty": {}, "values": [None, True, False, "line1\n```\nline2"], "safe": safe}
    )
    assert "empty:" in rendered and "(empty)" in rendered
    assert "```text" in rendered and "line1" in rendered


def test_nuclear_reset_and_idb_family_cleanup_keep_errors_best_effort(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    idb = tmp_path / "database.i64"
    idb.write_bytes(b"tiny")
    (tmp_path / "database.id0").write_bytes(b"sidecar")
    (tmp_path / "database.id1").write_bytes(b"sidecar")
    original_remove = runtime_mod.os.remove

    def remove(path):
        if str(path).endswith(".id0"):
            raise OSError("locked")
        original_remove(path)

    monkeypatch.setattr(runtime_mod.os, "remove", remove)
    host._nuclear_reset(str(idb), aggressive=True)
    assert idb.exists() is False
    assert (tmp_path / "database.id0").exists()
    assert not (tmp_path / "database.id1").exists()

    (tmp_path / "database.nam").write_bytes(b"stale")
    host._cleanup_stale_idb_family(str(idb))
    assert not (tmp_path / "database.nam").exists()
    assert host._backup_idb("") is None


def test_idb_reference_and_command_helpers_cover_exact_matching(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    target = str(tmp_path / "target.i64").lower()
    assert host._argv_targets_path([target], target)
    assert host._argv_targets_path(["-o=" + target], target)
    assert host._argv_targets_path(["-o", target], target)
    assert not host._argv_targets_path([target + "-other"], target)
    assert not host._argv_targets_path(["-o"], target)

    live = SimpleNamespace(pid=44, poll=lambda: None)
    broken = SimpleNamespace(pid=45, poll=lambda: (_ for _ in ()).throw(RuntimeError("gone")))
    host.session_runtimes = {"a": {"process": live}, "b": {"process": broken}, "c": {"process": None}}
    assert host._live_runtime_pids() == {44}
    assert host._terminate_ida_processes_for_path("") == []

    session = SimpleNamespace(
        binary_path=str(tmp_path / "input.bin"),
        idb_path=str(tmp_path / "output.i64"),
        ida_args=[],
        analysis_options={"skip_analysis": True},
    )
    (tmp_path / "input.bin").write_bytes(b"raw")
    host.idat_exe = "/ida/idat64"
    command = host._build_ida_command(session, "log", "script", False)
    assert command[-2:] == [f"-o{session.idb_path}", session.binary_path]
    worker, spec, _root = host._build_idalib_command(session, "script", False, log_file="log")
    assert worker[-1] == "ida_pro_mcp.idalib_worker"
    assert spec["existing"] is False and "-c" in spec["args"]

    monkeypatch.setenv("IDA_MCP_RUNTIME", "idalib")
    assert host._is_idalib_runtime() is True
    monkeypatch.delenv("IDA_MCP_RUNTIME")
    assert host._is_idalib_runtime() is False


def test_query_state_and_checkpoint_skip_and_success_modes(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    sid = "AB12CDEF"
    host._runtime_alive = lambda runtime: bool(
        runtime and runtime.get("process") and runtime["process"].poll() is None
    )
    assert host._query_ida_state(sid) is None
    host.session_runtimes[sid] = {"process": SimpleNamespace(poll=lambda: 1), "port": 7}
    host._runtime_alive = lambda runtime: bool(runtime and runtime.get("process").poll() is None)
    assert host._query_ida_state(sid) is None

    host.session_runtimes[sid] = {"process": SimpleNamespace(poll=lambda: None), "port": 7}
    host._send_rpc_raw = lambda *_args, **_kwargs: {"ok": True, "inventory": {"functions_qty": "5"}}
    assert host._query_ida_state(sid)["ok"] is True
    host._send_rpc_raw = lambda *_args, **_kwargs: {"error": "bad"}
    assert host._query_ida_state(sid) is None

    host._analysis_is_complete = lambda _sid: False
    host._run_analysis_checkpoint(sid)
    host._analysis_is_complete = lambda _sid: True
    sent = []
    host._send_rpc_raw = lambda *args, **kwargs: sent.append((args, kwargs)) or {"ok": True}
    host._record_analysis_checkpoint = lambda _sid: sent.append("recorded")
    host._run_analysis_checkpoint(sid)
    assert sent and sent[-1] == "recorded"
