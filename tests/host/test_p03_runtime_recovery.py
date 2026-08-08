"""Regression tests for p03_runtime: session recovery keeps exclusive ownership.

Covers the fix in server_runtime.py where a successful recovery dropped the
runtime-ownership lease (a second MCP client could then claim the same IDB
under the recovered runtime) and never started the analysis watchdog /
semantic-index reuse background services for the recovered session.
"""

import os
import threading
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_runtime as server_runtime_mod
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin

SID = "AB12CDEF"


class _RecoveryHost(ServerRuntimeMixin):
    def __init__(self, lease_dir):
        self._runtime_lease_dir = str(lease_dir)
        self._runtime_owner_id = "owner-x"
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self._session_startup_locks = {}
        self._session_last_activity = {}
        self._session_inflight_calls = {}
        self.session_mgr = SimpleNamespace(_save_metadata=lambda s: None)

    def _make_session(self, tmp_path):
        binary = tmp_path / f"{SID}_sample.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 16)
        return SimpleNamespace(
            session_id=SID,
            binary_path=str(binary),
            idb_path=str(tmp_path / f"SID_{SID}_sample.bin.i64"),
            analysis_options={},
            analysis_applied=False,
            packed_idb=False,
        )


def test_recovery_reclaims_ownership_and_starts_background_services(tmp_path, monkeypatch):
    host = _RecoveryHost(tmp_path)
    session = host._make_session(tmp_path)
    # _start_server claims ownership before calling _start_server_inner.
    host._claim_runtime_ownership(SID)
    assert os.path.exists(host._runtime_owner_path(SID))

    monkeypatch.setattr(
        host,
        "_cleanup_runtime",
        host._release_runtime_ownership,
    )
    launched = []
    monkeypatch.setattr(
        host,
        "_launch_and_wait",
        lambda session, port, sanitize_env=False: launched.append(1) or {
            "ok": True,
            "idb_path": session.idb_path,
            "port": 9999,
        },
    )
    monkeypatch.setattr(host, "_apply_session_options", lambda session, runtime: {"ok": True})
    services = []
    monkeypatch.setattr(
        host, "_start_session_background_services", lambda session, port: services.append(port)
    )
    monkeypatch.setattr(host, "_backup_idb", lambda idb_path: None)
    monkeypatch.setattr(host, "_nuclear_reset", lambda idb_path, aggressive=False: None)
    monkeypatch.setattr(host, "_terminate_ida_processes_for_path", lambda target: [])
    monkeypatch.setattr(server_runtime_mod.time, "sleep", lambda *a: None)
    host.session_runtimes[SID] = {"process": None, "port": 9999}

    result = host._attempt_session_recovery(session, "some diag", 0)

    assert launched == [1]
    assert services == [9999]
    assert "error" not in result
    # Ownership lease re-acquired after _cleanup_runtime released it.
    assert os.path.exists(host._runtime_owner_path(SID))


def test_recovery_aborts_when_ownership_lost_during_recovery(tmp_path, monkeypatch):
    host = _RecoveryHost(tmp_path)
    other = _RecoveryHost(tmp_path)
    other._runtime_owner_id = "owner-other"
    # Another host claimed the IDB before this recovery could re-claim.
    other._claim_runtime_ownership(SID)
    session = host._make_session(tmp_path)

    monkeypatch.setattr(host, "_cleanup_runtime", lambda sid: None)
    monkeypatch.setattr(server_runtime_mod.time, "sleep", lambda *a: None)

    result = host._attempt_session_recovery(session, "diag", 0)

    assert "error" in result
    assert result.get("code") == MCPError.FILE_LOCKED
