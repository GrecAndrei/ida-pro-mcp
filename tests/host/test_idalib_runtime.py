"""Host tests for the idalib runtime backend (IDA_MCP_RUNTIME=idalib).

The worker process runs ``ida_pro_mcp.idalib_worker`` instead of
``idat -A -Sserver_script.py``; it imports ``idapro`` (first IDA import),
opens the target database with history enabled, then executes
server_script.py's ``__main__`` unchanged.  These tests pin the host-side
command/env contract and the worker's env contract without a live IDA.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server import server_runtime as server_runtime_mod
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin

SID = "AB12CDEF"
FAKE_PID = 2147483647


class _Host(ServerRuntimeMixin):
    """Minimal mixin instance for runtime-command tests (mirrors
    test_swarm_f04_runtime._Host)."""

    def __init__(self, tmp_path):
        self._runtime_lease_dir = str(tmp_path / "leases")
        os.makedirs(self._runtime_lease_dir, exist_ok=True)
        self._runtime_owner_id = "owner-x"
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self._session_startup_locks = {}
        self._session_last_activity = {}
        self._session_inflight_calls = {}
        self._session_teardown = set()
        self._activity_log = []
        self._activity_log_max = 4000
        self.cache_dir = str(tmp_path / "cache")
        self.ida_dir = None
        self.idat_exe = "/fake/ida/idat64"

    def _make_session(self, tmp_path, packed_idb=False, analysis_options=None):
        binary = tmp_path / f"{SID}_sample.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 16)
        return SimpleNamespace(
            session_id=SID,
            binary_path=str(binary),
            idb_path=str(tmp_path / f"SID_{SID}_sample.bin.i64"),
            analysis_options=analysis_options or {},
            analysis_applied=False,
            packed_idb=packed_idb,
            ida_args=[],
        )


@pytest.fixture
def host(tmp_path):
    return _Host(tmp_path)


@pytest.fixture
def session(tmp_path):
    h = _Host(tmp_path)
    return h._make_session(tmp_path)


# ---------------------------------------------------------------------------
# Runtime flag selection
# ---------------------------------------------------------------------------


def test_runtime_flag_defaults_to_idat(host, monkeypatch):
    monkeypatch.delenv("IDA_MCP_RUNTIME", raising=False)
    assert host._runtime_backend() == "idat"
    assert not host._is_idalib_runtime()


def test_runtime_flag_idalib(host, monkeypatch):
    monkeypatch.setenv("IDA_MCP_RUNTIME", "idalib")
    assert host._is_idalib_runtime()


def test_runtime_flag_case_insensitive(host, monkeypatch):
    monkeypatch.setenv("IDA_MCP_RUNTIME", " IDALIB ")
    assert host._is_idalib_runtime()


# ---------------------------------------------------------------------------
# _preload_ida_args extraction preserves idat command behavior
# ---------------------------------------------------------------------------


def test_preload_ida_args_matches_idat_emission(host, tmp_path):
    """The extracted _preload_ida_args must produce exactly the flags the old
    inline block appended to the idat command (processor/loader/baseaddr/
    entry/skip), so the refactor is behavior-preserving."""
    session = host._make_session(
        tmp_path,
        analysis_options={
            "processor": "metapc",
            "loader": "pe",
            "baseaddr": "0x401000",
            "entry_point": "0x401050",
            "skip_analysis": True,
        },
    )
    args = host._preload_ida_args(session)
    assert args == ["-pmetapc", "-Tpe", "-b0x40100", "-c", "-i0x401050"]


def test_preload_ida_args_raw_bin_without_loader(host, tmp_path):
    """No container magic + no loader= → -Tbin is emitted (raw blob path)."""
    session = host._make_session(tmp_path, analysis_options={"processor": "arm"})
    session.binary_path = str(tmp_path / "raw_blob.bin")
    with open(session.binary_path, "wb") as fh:
        fh.write(b"\x00" * 32)
    args = host._preload_ida_args(session)
    assert "-parm" in args
    assert "-Tbin" in args


def test_preload_ida_args_native_magic_skips_tbin(host, tmp_path):
    """ELF magic → native loader handles it, no -Tbin."""
    session = host._make_session(tmp_path, analysis_options={"processor": "arm"})
    args = host._preload_ida_args(session)
    assert "-parm" in args
    assert "-Tbin" not in args


def test_preload_ida_args_skips_existing_idb_keys(host, tmp_path):
    """processor_options/stack_size/memory_model have no idat CLI switch and
    must NOT be emitted."""
    session = host._make_session(
        tmp_path,
        analysis_options={
            "processor_options": "gp=0x80002000",
            "memory_model": 1,
            "processor": "riscv",
        },
    )
    args = host._preload_ida_args(session)
    assert "-priscv" in args
    assert not any(a.startswith(("-P", "-s", "-m")) for a in args)


# ---------------------------------------------------------------------------
# idalib worker command + open spec
# ---------------------------------------------------------------------------


def test_build_idalib_command_new_db(host, session):
    script = "/pkg/server_script.py"
    cmd, spec, package_root = host._build_idalib_command(
        session, script, use_existing_idb=False
    )
    assert cmd == [sys.executable, "-m", "ida_pro_mcp.idalib_worker"]
    assert package_root.endswith(("ida-pro-mcp", "src"))
    assert spec["file"] == session.binary_path
    assert spec["existing"] is False
    assert spec["skip_analysis"] is False
    assert spec["server_script"] == script
    assert f"-o{session.idb_path}" in spec["args"]


def test_build_idalib_command_existing_idb(host, session):
    script = "/pkg/server_script.py"
    cmd, spec, package_root = host._build_idalib_command(
        session, script, use_existing_idb=True, effective_idb_path=session.idb_path
    )
    assert spec["file"] == session.idb_path
    assert spec["existing"] is True
    # No -o (never overwrite an existing output) and no preload flags.
    assert "-o" not in spec["args"]


def test_build_idalib_command_skip_analysis_flag(host, tmp_path):
    session = host._make_session(
        tmp_path, analysis_options={"no_analysis": True}
    )
    _, spec, _ = host._build_idalib_command(
        session, "/pkg/server_script.py", use_existing_idb=False
    )
    assert spec["skip_analysis"] is True


def test_build_idalib_command_preload_args_carried(host, tmp_path):
    session = host._make_session(
        tmp_path,
        analysis_options={"processor": "riscv", "baseaddr": "0x8000"},
    )
    _, spec, _ = host._build_idalib_command(
        session, "/pkg/server_script.py", use_existing_idb=False
    )
    assert "-priscv" in spec["args"]
    assert "-b0x800" in spec["args"]


# ---------------------------------------------------------------------------
# idalib python dir discovery
# ---------------------------------------------------------------------------


def test_idalib_python_dir_detected(host, tmp_path):
    install = tmp_path / "ida-pro-9.4"
    (install / "idalib" / "python" / "idapro").mkdir(parents=True)
    host.ida_dir = str(install)
    assert host._idalib_python_dir() == str(install / "idalib" / "python")


def test_idalib_python_dir_missing(host, tmp_path):
    install = tmp_path / "ida-pro-9.2"
    install.mkdir()
    host.ida_dir = str(install)
    assert host._idalib_python_dir() == ""


# ---------------------------------------------------------------------------
# worker module contract (env-driven, no live idapro)
# ---------------------------------------------------------------------------


def test_worker_opens_database_and_runs_server_script(tmp_path, monkeypatch):
    """The worker must (1) put the idalib python dir on sys.path, (2) import
    idapro, (3) open_database(file, run_analysis, args, enable_history=True),
    (4) run server_script's __main__, (5) close_database(save=True) after."""

    class _FakeIdapro:
        def __init__(self):
            self.events = []

        def open_database(self, file, run_analysis, args=None, enable_history=False):
            self.events.append(("open", file, run_analysis, args, enable_history))
            return 0

        def close_database(self, save=True):
            self.events.append(("close", save))

    fake = _FakeIdapro()
    monkeypatch.setitem(sys.modules, "idapro", fake)

    script = tmp_path / "server_script.py"
    script.write_text("pass\n")
    spec = json.dumps(
        {
            "file": "/x/sample.bin",
            "args": "-priscv",
            "existing": False,
            "skip_analysis": False,
            "server_script": str(script),
        }
    )
    monkeypatch.setenv("IDA_MCP_IDALIB_OPEN", spec)
    monkeypatch.setenv("IDA_MCP_IDALIB_PYTHON_DIR", "/fake/idalib/python")

    from ida_pro_mcp import idalib_worker

    with pytest.raises(SystemExit):
        idalib_worker.main()

    assert "/fake/idalib/python" in sys.path
    assert fake.events[0] == ("open", "/x/sample.bin", True, "-priscv", True)
    assert fake.events[-1] == ("close", True)


def test_worker_skip_analysis_passes_run_auto_analysis_false(tmp_path, monkeypatch):
    class _FakeIdapro:
        def __init__(self):
            self.run_analysis = None

        def open_database(self, file, run_analysis, args=None, enable_history=False):
            self.run_analysis = run_analysis
            return 0

        def close_database(self, save=True):
            pass

    fake = _FakeIdapro()
    monkeypatch.setitem(sys.modules, "idapro", fake)
    script = tmp_path / "server_script.py"
    script.write_text("pass\n")
    monkeypatch.setenv(
        "IDA_MCP_IDALIB_OPEN",
        json.dumps(
            {
                "file": "/x/sample.bin",
                "args": "-c",
                "existing": False,
                "skip_analysis": True,
                "server_script": str(script),
            }
        ),
    )
    from ida_pro_mcp import idalib_worker

    with pytest.raises(SystemExit):
        idalib_worker.main()
    assert fake.run_analysis is False


def test_worker_errors_without_open_spec(tmp_path, monkeypatch):
    monkeypatch.delenv("IDA_MCP_IDALIB_OPEN", raising=False)
    from ida_pro_mcp import idalib_worker

    with pytest.raises(SystemExit) as exc:
        idalib_worker.main()
    assert exc.value.code == 3
