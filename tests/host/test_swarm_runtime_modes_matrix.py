"""Cross-backend coverage for runtime discovery, command construction, and state."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin


class _Session:
    binary_path = "sample.bin"
    idb_path = "/tmp/sample.i64"
    ida_args = ["-A"]
    analysis_options = {
        "processor": "arm",
        "loader": "bin",
        "baseaddr": "0x80000000",
        "entry_point": "0x80001000",
        "skip_analysis": True,
    }


def _host(tmp_path):
    host = ServerRuntimeMixin.__new__(ServerRuntimeMixin)
    host._runtime_lease_dir = str(tmp_path)
    host._runtime_owner_id = "owner-a"
    host.session_runtimes = {"SID12345": {"port": 1234, "value": 1}}
    host._runtime_lock = None
    host._session_last_activity = {}
    host._activity_log = []
    host._activity_log_max = 100
    host.current_session = SimpleNamespace(session_id="SID12345")
    host._macro_path = str(tmp_path / "macros.json")
    host._session_macros = {}
    host.cache_dir = str(tmp_path)
    host.ida_dir = str(tmp_path)
    host.idat_exe = str(tmp_path / "idat64")
    return host


def test_runtime_records_ownership_and_safe_payload_rendering(tmp_path):
    host = _host(tmp_path)
    assert host._runtime_record("SID12345")["value"] == 1
    assert host._runtime_record("missing") is None
    assert host._runtime_items_snapshot() == [("SID12345", {"port": 1234, "value": 1})]
    assert host._runtime_update("SID12345", value=2) is True
    assert host._runtime_update("missing", value=2) is False

    lease = host._claim_runtime_ownership("SID12345")
    assert lease and os.path.exists(lease)
    assert host._claim_runtime_ownership("SID12345") == lease
    host._release_runtime_ownership("SID12345")
    assert not os.path.exists(lease)

    assert host._json_safe_value({1: b"utf8", 2: b"\\xff", 3: {"x", "y"}})["1"] == "utf8"
    rendered = host._render_payload_text({"code": "line 1\nline 2", "items": [True, None]})
    assert "```text" in rendered
    assert "line 2" in rendered


def test_runtime_discovery_diagnostics_and_argument_guards(tmp_path, monkeypatch):
    host = _host(tmp_path)
    exe = tmp_path / "idat64"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    exe.chmod(0o755)
    assert "idat64" in host._ida_binary_names()
    assert host._is_executable_file(str(exe)) is True
    monkeypatch.setenv("IDADIR", str(tmp_path))
    assert host._detect_ida_dir() == str(tmp_path)
    monkeypatch.setenv("IDA_MCP_IDAT", str(exe))
    assert host._find_idat() == str(exe)

    stdout = tmp_path / "ida_stdout_SID.log"
    stderr = tmp_path / "ida_stderr_SID.log"
    stdout.write_text("one\ntwo\n", encoding="utf-8")
    stderr.write_text("warning\n", encoding="utf-8")
    assert host._tail_text_file(str(stdout), 1) == "two"
    diagnostics = host._get_ida_diagnostics(str(stdout), str(stderr), tail_lines=2)
    assert "[stdout]" in diagnostics and "[stderr]" in diagnostics
    assert host._get_ida_diagnostics(str(tmp_path / "missing")) == "No log available."

    assert host._normalize_ida_args('-p arm "hello world" -A') == ["-p", "arm", "hello world"]
    for bad in (123, [""], ["-Sbad"], ["x\x00y"], ["x\x7fy"]):
        with pytest.raises(ValueError):
            host._normalize_ida_args(bad)
    mapping = {"first": 1, "second": 2}
    assert host._pop_first(mapping, ["missing", "second"]) == 2
    assert mapping == {"first": 1}


def test_runtime_preload_and_command_modes(tmp_path, monkeypatch):
    host = _host(tmp_path)
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"RAW!")
    session = _Session()
    session.binary_path = str(raw)
    session.ida_args = []
    preload = host._preload_ida_args(session)
    assert "-parm" in preload
    assert "-Tbin" in preload
    assert "-b0x8000000" in preload
    assert "-i0x80001000" in preload
    assert "-c" in preload

    elf = tmp_path / "sample.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 8)
    session.binary_path = str(elf)
    session.analysis_options = {"processor": "arm", "baseaddr": "0x80000000", "entry_point": "0x80001000", "skip_analysis": True}
    assert "-Tbin" not in host._preload_ida_args(session)
    session.analysis_options = {"input_format": "elf", "rebase_to": 0x400000}
    assert "-Telf" in host._preload_ida_args(session)
    assert "-b0x40000" in host._preload_ida_args(session)

    session.analysis_options = {}
    session.ida_args = ["-q"]
    idat_cmd = host._build_ida_command(session, "/tmp/ida.log", "/tmp/server.py", False)
    assert idat_cmd[-2:] == ["-o/tmp/sample.i64", str(elf)]
    worker_cmd, spec, root = host._build_idalib_command(session, "/tmp/server.py", False, log_file="/tmp/ida.log")
    assert worker_cmd[0] == os.sys.executable
    assert spec["file"] == str(elf)
    assert "-L/tmp/ida.log" in spec["args"]
    assert root
    monkeypatch.setenv("IDA_MCP_RUNTIME", "idalib")
    assert host._is_idalib_runtime() is True
    monkeypatch.delenv("IDA_MCP_RUNTIME")
    assert host._runtime_backend() == "idat"


def test_runtime_file_recovery_process_argument_and_activity_modes(tmp_path):
    host = _host(tmp_path)
    source = tmp_path / "db.i64"
    source.write_text("bad", encoding="utf-8")
    backup = host._backup_idb(str(source))
    assert backup and os.path.exists(backup)
    for suffix in (".id0", ".id1", ".nam", ".i64"):
        (tmp_path / ("db" + suffix)).write_text("x", encoding="utf-8")
    host._cleanup_stale_idb_family(str(source))
    assert not (tmp_path / "db.id0").exists()
    target = str(source).lower()
    assert host._argv_targets_path(["idat", "-o" + target], target)
    assert host._argv_targets_path(["idat", "-o", target], target)
    assert not host._argv_targets_path(["idat", target + ".other"], target)

    host._record_activity("code", {"action": "decompile", "session_id": "SID12345"}, {"ok": True})
    assert "SID12345" in host._session_last_activity
    host._record_activity("code", {"action": "decompile"}, {"error": True})
    assert host._normalize_macro_name("  hello   world ") == "hello world"
    host._session_macros = {"open": {"name": "Open", "data": {"action": "status"}}}
    host._save_session_macros()
    host._session_macros = {}
    host._load_session_macros()
    assert host._session_macros["open"]["name"] == "Open"
    (tmp_path / "bad.json").write_text("[]", encoding="utf-8")
    host._macro_path = str(tmp_path / "bad.json")
    host._load_session_macros()
    assert host._session_macros == {}
