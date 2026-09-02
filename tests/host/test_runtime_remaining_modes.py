"""Offline coverage for runtime discovery, command construction, and recovery."""

from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_runtime as runtime_mod
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin


class _Host(ServerRuntimeMixin):
    def __init__(self, tmp_path):
        self.cache_dir = str(tmp_path)
        self._runtime_lease_dir = str(tmp_path / "leases")
        Path(self._runtime_lease_dir).mkdir(parents=True)
        self._runtime_owner_id = "owner-a"
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self._session_last_activity = {}
        self._activity_log = []
        self._activity_log_max = 50
        self.session_mgr = SimpleNamespace(sessions={})
        self.ida_dir = ""
        self.idat_exe = ""


def test_runtime_environment_and_process_discovery_edges(monkeypatch, tmp_path):
    monkeypatch.setenv("IDA_MCP_MAX_RPC_BYTES", "bad")
    assert runtime_mod._resolve_max_rpc_bytes() == 64 * 1024 * 1024
    monkeypatch.setenv("IDA_MCP_MAX_RPC_BYTES", "1")
    assert runtime_mod._resolve_max_rpc_bytes() == 4096
    monkeypatch.setenv("IDA_MCP_MAX_RPC_BYTES", str(999 * 1024 * 1024))
    assert runtime_mod._resolve_max_rpc_bytes() == 256 * 1024 * 1024
    monkeypatch.setenv("IDA_MCP_STARTUP_TIMEOUT", "bad")
    assert runtime_mod._resolve_startup_timeout() == 240
    monkeypatch.setenv("IDA_MCP_STARTUP_TIMEOUT", "0")
    assert runtime_mod._resolve_startup_timeout() == 1
    monkeypatch.setenv("IDA_MCP_STARTUP_TIMEOUT", "12")
    assert runtime_mod._resolve_startup_timeout() == 12

    monkeypatch.setattr(runtime_mod.sys, "platform", "win32")
    assert "creationflags" in runtime_mod._popen_new_session_kwargs()
    monkeypatch.setattr(runtime_mod.sys, "platform", "linux")
    assert runtime_mod._popen_new_session_kwargs() == {"start_new_session": True}

    host = _Host(tmp_path)
    assert host._runtime_record("missing") is None
    assert host._runtime_items_snapshot() == []
    assert host._runtime_update("missing", port=4) is False
    host.session_runtimes = {"a": {"port": 1}, "bad": None}
    assert host._runtime_items_snapshot() == [("a", {"port": 1})]
    assert host._runtime_update("a", port=2)
    assert host._runtime_record("a")["port"] == 2
    assert host._ida_binary_names()[0] in {"idat", "idat64"}


def test_runtime_ownership_and_installation_discovery_paths(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    sid = "ABC12345"
    assert host._claim_runtime_ownership(sid).endswith(f"SID_{sid}.owner.json")
    assert host._claim_runtime_ownership(sid).endswith(f"SID_{sid}.owner.json")
    other = _Host(tmp_path / "other")
    other._runtime_lease_dir = host._runtime_lease_dir
    other._runtime_owner_id = "owner-b"
    assert other._claim_runtime_ownership(sid) is None
    host._release_runtime_ownership(sid)
    assert not Path(host._runtime_owner_path(sid)).exists()
    host._release_runtime_ownership(sid)
    Path(host._runtime_owner_path(sid)).write_text("not json", encoding="utf-8")
    host._release_runtime_ownership(sid)

    ida_root = tmp_path / "ida"
    ida_root.mkdir()
    idat = ida_root / "idat64"
    idat.write_text("", encoding="utf-8")
    idat.chmod(idat.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("IDADIR", str(idat))
    assert host._detect_ida_dir() == str(ida_root)
    monkeypatch.setenv("IDA_MCP_IDAT", str(idat))
    host.ida_dir = ""
    assert host._find_idat() == str(idat)
    monkeypatch.setenv("IDA_MCP_IDAT", str(tmp_path / "missing"))
    host.ida_dir = str(ida_root)
    assert host._find_idat() == str(idat)
    assert host._is_executable_file(str(idat))
    assert not host._is_executable_file("")

    monkeypatch.setattr(runtime_mod.shutil, "which", lambda _name: str(idat))
    monkeypatch.setattr(runtime_mod.glob, "glob", lambda _pattern: [])
    monkeypatch.setenv("IDADIR", str(tmp_path / "does-not-exist"))
    host.ida_dir = ""
    assert host._detect_ida_dir() == str(ida_root)


def test_runtime_logs_snapshot_diagnostics_and_error_classification(tmp_path):
    host = _Host(tmp_path)
    stdout = tmp_path / "ida_stdout_X.log"
    stderr = tmp_path / "ida_stderr_X.log"
    stdout.write_text("one\ntwo\nthree\n", encoding="utf-8")
    stderr.write_text("err\n", encoding="utf-8")
    assert host._tail_text_file(None) == ""
    assert host._tail_text_file(str(tmp_path / "nope")) == ""
    assert host._tail_text_file(str(stdout), 2) == "two\nthree"
    assert "[stdout]" in host._get_ida_diagnostics(str(stdout), str(stderr), 1)
    assert host._get_ida_diagnostics(str(tmp_path / "nope")) == "No log available."

    dead = SimpleNamespace(pid=7, poll=lambda: 9)
    snap = host._collect_ida_state_snapshot(
        {"process": dead, "stdout_log": str(stdout)},
        current_tool="code", current_args={"x": "y" * 300}, call_started_at=0,
    )
    assert snap["process_alive"] is False and snap["process_exit_code"] == 9
    assert "current_args" in snap and "ida_stdout_tail" in snap
    snap = host._collect_ida_state_snapshot({"process": None})
    assert snap["process_alive"] is False
    broken = SimpleNamespace(pid=7, poll=lambda: (_ for _ in ()).throw(RuntimeError("gone")))
    assert host._collect_ida_state_snapshot({"process": broken})["process_alive"] is None

    assert host._extract_library_init_failure("") is None
    assert host._extract_library_init_failure("ordinary output") is None
    info = host._extract_library_init_failure(
        "Library initialization failed error=2: cannot open shared object file; "
        "GLIBCXX; Qt platform plugin xcb; wrong ELF class; permission denied; "
        "plugin failed; Python init module; no space left on device"
    )
    assert info["detected"] is True and info["error_code"] == 2
    assert len(info["causes"]) >= 6
    assert host._is_library_init_err2("library init failed")
    assert not host._is_library_init_err2("ordinary")
    assert not host._is_orphan_locked_db_open_failure("resource temporarily unavailable")
    assert host._is_orphan_locked_db_open_failure("resource temporarily unavailable; database did not close properly")


def test_runtime_argument_macro_and_payload_helpers(tmp_path):
    host = _Host(tmp_path)
    assert host._normalize_ida_args(None) == []
    assert host._normalize_ida_args('"-A" -z') == ["-z"]
    assert host._normalize_ida_args([None, "-z"]) == ["-z"]
    for value in (4, [""], ["-Sbad"], ["x\x00y"], ["x\x7fy"]):
        with pytest.raises(ValueError):
            host._normalize_ida_args(value)
    assert host._pop_first({"b": 2}, ["a", "b"]) == 2
    assert host._pop_first({}, ["a"], 9) == 9
    assert host._normalize_macro_name(None) is None
    assert host._normalize_macro_name("  a   b ") == "a b"

    host._macro_path = str(tmp_path / "macros.json")
    host._session_macros = {"open": {"name": "Open", "data": {"action": "status"}}}
    host._save_session_macros()
    host._session_macros = {}
    host._load_session_macros()
    assert host._session_macros["open"]["name"] == "Open"
    Path(host._macro_path).write_text("[]", encoding="utf-8")
    host._load_session_macros()
    assert host._session_macros == {}
    Path(host._macro_path).write_text(json.dumps({"ok": {"name": "Ok", "data": {"x": 1}}, "bad": 4}), encoding="utf-8")
    host._load_session_macros()
    assert "ok" in host._session_macros

    assert host._json_safe_value(b"text") == "text"
    assert host._json_safe_value(b"\xff") == {"_bytes_hex": "ff"}
    assert host._json_safe_value(bytearray(b"x")) == "x"
    assert host._json_safe_value({1: {"a", "b"}})["1"]
    rendered = host._render_payload_text({"code": "line1\nline2", "items": [{"ok": True}], "none": None})
    assert "line1\nline2" in rendered and "```text" in rendered
    assert host._render_payload_text([]) == "(empty)"


def test_runtime_command_builders_and_filesystem_recovery(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    binary = tmp_path / "raw.bin"
    binary.write_bytes(b"raw")
    session = SimpleNamespace(
        binary_path=str(binary), idb_path=str(tmp_path / "out.i64"),
        analysis_options={"processor": "arm", "bitness": 32, "baseaddr": "0x120000", "entry_point": "0x10", "skip_analysis": True, "input_format": "bin"},
        ida_args=[],
    )
    args = host._preload_ida_args(session)
    assert "-parm" in args and "-Tbin" in args and "-b0x12000" in args and "-c" in args
    assert "-i0x10" in args
    assert host._build_ida_command(session, "log", "script", False)[-2:] == ["-o" + session.idb_path, session.binary_path]
    assert host._build_ida_command(session, "log", "script", True, "/packed.i64")[-1] == "/packed.i64"
    cmd, spec, root = host._build_idalib_command(session, "script", False, log_file="log")
    assert cmd[:3] == [runtime_mod.sys.executable, "-m", "ida_pro_mcp.idalib_worker"]
    assert spec["existing"] is False and "-Llog" in spec["args"] and root
    existing = SimpleNamespace(binary_path=str(binary), idb_path="/packed.i64", analysis_options={}, ida_args=[])
    assert host._build_idalib_command(existing, "script", True)[1]["file"] == "/packed.i64"
    assert host._runtime_backend() in {"idat", "idalib"}
    monkeypatch.setenv("IDA_MCP_RUNTIME", "IDALIB")
    assert host._is_idalib_runtime()

    idb = tmp_path / "db.i64"
    idb.write_bytes(b"bad")
    backup = host._backup_idb(str(idb))
    assert backup and Path(backup).exists() and not idb.exists()
    assert host._backup_idb(str(idb)) is None
    for ext in (".id0", ".id1", ".nam", ".til", ".i64"):
        Path(str(idb).rsplit(".", 1)[0] + ext).write_text("x", encoding="utf-8")
    host._cleanup_stale_idb_family(str(idb))
    assert not Path(str(idb).rsplit(".", 1)[0] + ".id0").exists()
    assert host._argv_targets_path(["idat", "-o", "/tmp/db.i64"], "/tmp/db.i64")
    assert host._argv_targets_path(["-o=/tmp/db.i64"], "/tmp/db.i64")
    assert not host._argv_targets_path(["/tmp/db.i64.backup"], "/tmp/db.i64")


def test_runtime_checkpoint_and_shutdown_policy_branches(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    sid = "SID12345"
    assert host._shutdown_rpc_save_timeout("bad") == 1.0
    assert host._shutdown_rpc_save_timeout(1000) == runtime_mod._SHUTDOWN_SAVE_RPC_CAP
    host.large_idb_shutdown_grace_seconds = 9
    runtime = {"idb_path": str(tmp_path / "big.i64")}
    Path(runtime["idb_path"]).write_bytes(b"x")
    assert host._shutdown_grace_seconds(sid, runtime) == 2.0
    host.session_mgr.sessions[sid] = SimpleNamespace(metadata={"analysis_state": "analyzing"})
    assert host._shutdown_grace_seconds(sid, {}) == 9
    host.checkpoint_save_seconds = -1
    assert host._checkpoint_save_interval() == 1.0
    host.checkpoint_save_seconds = "bad"
    assert host._checkpoint_save_interval() == 5.0
    host._analysis_is_complete = lambda _sid: False
    host._run_analysis_checkpoint(sid)
    host.session_runtimes[sid] = {"process": SimpleNamespace(poll=lambda: None), "port": 1, "auth_token": "t"}
    host._send_rpc_raw = lambda *_args, **_kwargs: {"error": True}
    host._analysis_is_complete = lambda _sid: True
    host._run_analysis_checkpoint(sid)
    host._send_rpc_raw = lambda *_args, **_kwargs: {"ok": True}
    host._query_ida_state = lambda *_args, **_kwargs: {"inventory": {"functions_qty": "4"}}
    updates = []
    host._update_session_indexing_metadata = lambda _sid, **kw: updates.append(kw)
    host._run_analysis_checkpoint(sid)
    assert updates and updates[-1]["analysis_progress"] == 4
    host._record_analysis_checkpoint(sid)
