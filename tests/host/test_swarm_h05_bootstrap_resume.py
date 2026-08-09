"""h05: session bootstrap/teardown/resume — analysis-gate persistence, restart
restore, shutdown coordination, and daemon socket/pidfile hardening.

Covers the revamped session lifecycle for large binaries:

- The per-session analysis gate is persisted in ``metadata['analysis_gate']``
  at every pending/complete transition and at shutdown, and restored in
  ``IDAMCPServer.__init__`` after ``_load_sessions``/auto-prune. A
  half-analyzed IDB resumes gated after a host restart (D3-F1); a completed
  IDB resumes ungated.
- The startup restore never spawns watcher threads — the completion watcher is
  armed on the session's first touch (``_arm_analysis_watcher_if_needed``).
- ``shutdown()`` persists the final gate, then stops analysis-completion
  watchers and background runtime spawns BEFORE h02 runtime teardown.
- Daemon socket/pidfile hardening: a live recorded pid refuses a second
  daemon; a stale pidfile/socket is reclaimed; cleanup unlinks the socket only
  when the recorded pid is still our own.
- New lifecycle knobs parse tolerantly (a bad env value falls back to the
  default instead of crashing the host at import).

Standalone unit tests: no live IDA (``_ensure_runtime_and_idb`` is stubbed).
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest

from ida_pro_mcp.host.server import server as server_mod
from ida_pro_mcp.host.server.server import IDAMCPServer

# ---------------------------------------------------------------------------
# Fake / server construction helpers
# ---------------------------------------------------------------------------


def _make_server(tmp_path, monkeypatch) -> IDAMCPServer:
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    # Blocking create must not attempt a real idat launch in a unit test.
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    return server


def _open_binary(server: IDAMCPServer, binary_path: str, request_id: int = 1) -> dict:
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": "ida_open_binary",
                "arguments": {"binary_path": binary_path},
            },
        }
    )
    assert response is not None
    return response["result"]["structuredContent"]


def _metadata_on_disk(tmp_path, sid: str) -> dict:
    meta_path = (
        Path(str(tmp_path / "runtime")) / "sessions" / f"SID_{sid}" / "metadata.json"
    )
    assert meta_path.exists(), f"metadata.json missing for {sid}"
    return json.loads(meta_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Restart restores the analysis gate
# ---------------------------------------------------------------------------


def test_restart_pending_gate_restores_safe_mode(tmp_path, monkeypatch):
    binary = tmp_path / "half-analyzed.bin"
    binary.write_bytes(b"\x00" * 1024)

    server1 = _make_server(tmp_path, monkeypatch)
    sid = _open_binary(server1, str(binary))["session_id"]
    # Opening persists 'pending' in the metadata file immediately.
    assert _metadata_on_disk(tmp_path, sid)["metadata"]["analysis_gate"] == "pending"
    assert server1._safe_mode_active(sid)
    server1.shutdown()

    # A restarted host reloads the session and rehydrates the gate.
    server2 = _make_server(tmp_path, monkeypatch)
    try:
        assert server2._safe_mode_active(sid) is True, (
            "a half-analyzed IDB must stay gated after a host restart"
        )
        assert server2._analysis_is_complete(sid) is False
    finally:
        server2.shutdown()


def test_restart_complete_gate_resumes_ungated(tmp_path, monkeypatch):
    binary = tmp_path / "done.bin"
    binary.write_bytes(b"\x00" * 1024)

    server1 = _make_server(tmp_path, monkeypatch)
    session = server1.session_mgr.create_session(str(binary))
    sid = session.session_id
    server1._mark_analysis_complete(session)
    assert _metadata_on_disk(tmp_path, sid)["metadata"]["analysis_gate"] == "complete"
    server1.shutdown()

    server2 = _make_server(tmp_path, monkeypatch)
    try:
        assert server2._analysis_is_complete(sid) is True
        assert server2._safe_mode_active(sid) is False, (
            "a completed IDB resumes ungated after a restart"
        )
    finally:
        server2.shutdown()


def test_restart_absent_gate_marks_pending_failsafe(tmp_path, monkeypatch):
    """A session with no analysis_gate record resumes gated (fail-safe)."""
    binary = tmp_path / "unverified.bin"
    binary.write_bytes(b"\x00" * 1024)

    server1 = _make_server(tmp_path, monkeypatch)
    session = server1.session_mgr.create_session(str(binary))
    sid = session.session_id
    # Never opened/tracked: no gate was written.
    assert "analysis_gate" not in _metadata_on_disk(tmp_path, sid)["metadata"]
    server1.shutdown()

    server2 = _make_server(tmp_path, monkeypatch)
    try:
        assert server2._safe_mode_active(sid) is True, (
            "an unverified IDB must never resume ungated"
        )
    finally:
        server2.shutdown()


def test_restore_does_not_spawn_watcher_at_startup(tmp_path, monkeypatch):
    """Startup restore marks pending but never spawns watcher threads."""
    binary = tmp_path / "nospawn.bin"
    binary.write_bytes(b"\x00" * 1024)

    server1 = _make_server(tmp_path, monkeypatch)
    session = server1.session_mgr.create_session(str(binary))
    server1._mark_analysis_pending(session)
    server1.shutdown()

    spawned: list[str] = []
    monkeypatch.setattr(
        server_mod.IDAMCPServer,
        "_spawn_analysis_watcher",
        lambda self, sid: spawned.append(sid),
    )
    server2 = _make_server(tmp_path, monkeypatch)
    try:
        assert spawned == [], "restoring the gate must not spawn watchers"
        assert server2._safe_mode_active(session.session_id) is True
        watchers = getattr(server2, "_analysis_watchers", None)
        assert not (isinstance(watchers, set) and session.session_id in watchers)
    finally:
        server2.shutdown()


def test_arm_watcher_on_first_touch_spawns_once(tmp_path, monkeypatch):
    """The first touch arms the watcher; a second touch is a no-op."""
    binary = tmp_path / "touch.bin"
    binary.write_bytes(b"\x00" * 1024)

    server1 = _make_server(tmp_path, monkeypatch)
    session = server1.session_mgr.create_session(str(binary))
    server1._mark_analysis_pending(session)
    sid = session.session_id
    server1.shutdown()

    spawned: list[str] = []

    def _fake_spawn(self, target_sid: str) -> None:
        spawned.append(target_sid)
        watchers = getattr(self, "_analysis_watchers", None)
        if not isinstance(watchers, set):
            self._analysis_watchers = set()
            watchers = self._analysis_watchers
        watchers.add(target_sid)

    monkeypatch.setattr(server_mod.IDAMCPServer, "_spawn_analysis_watcher", _fake_spawn)
    server2 = _make_server(tmp_path, monkeypatch)
    try:
        server2._arm_analysis_watcher_if_needed(sid)
        assert spawned == [sid]
        # Already armed: second touch must not double-spawn.
        server2._arm_analysis_watcher_if_needed(sid)
        assert spawned == [sid]
        # An ungated (complete) session never arms.
        server2._mark_analysis_complete(server2.session_mgr.sessions[sid])
        server2._arm_analysis_watcher_if_needed(sid)
        assert spawned == [sid]
    finally:
        server2.shutdown()


# ---------------------------------------------------------------------------
# Gate persistence at transitions and shutdown
# ---------------------------------------------------------------------------


def test_transition_persists_gate_to_disk(tmp_path, monkeypatch):
    binary = tmp_path / "gate.bin"
    binary.write_bytes(b"\x00" * 1024)

    server = _make_server(tmp_path, monkeypatch)
    try:
        session = server.session_mgr.create_session(str(binary))
        sid = session.session_id
        server._mark_analysis_pending(session)
        assert _metadata_on_disk(tmp_path, sid)["metadata"]["analysis_gate"] == "pending"
        server._mark_analysis_complete(server.session_mgr.sessions[sid])
        assert _metadata_on_disk(tmp_path, sid)["metadata"]["analysis_gate"] == "complete"
    finally:
        server.shutdown()


def test_shutdown_persists_final_gate(tmp_path, monkeypatch):
    """shutdown records the final gate even if a transition write was missed."""
    binary = tmp_path / "shut.bin"
    binary.write_bytes(b"\x00" * 1024)

    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session(str(binary))
    sid = session.session_id
    server._mark_analysis_pending(session)
    # Simulate a gate that never reached disk (e.g. crash before the
    # transition write): the shutdown pass must still record the final state.
    server.session_mgr.sessions[sid].metadata.pop("analysis_gate", None)
    server.shutdown()
    assert _metadata_on_disk(tmp_path, sid)["metadata"]["analysis_gate"] == "pending"


def test_shutdown_stops_watchers_and_background_spawns(tmp_path, monkeypatch):
    binary = tmp_path / "stop.bin"
    binary.write_bytes(b"\x00" * 1024)

    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session(str(binary))
    sid = session.session_id
    server._mark_analysis_pending(session)  # spawns the real watcher thread
    server._analysis_complete_in_flight = {sid}
    server._background_load_errors = {sid: {"error": True}}
    server.shutdown()

    pending = getattr(server, "_pending_analysis", None)
    assert not (isinstance(pending, set) and sid in pending)
    watchers = getattr(server, "_analysis_watchers", None)
    assert not (isinstance(watchers, set) and sid in watchers)
    assert server._analysis_complete_in_flight == set()
    assert server._background_load_errors == {}


# ---------------------------------------------------------------------------
# Daemon socket / pidfile hardening
# ---------------------------------------------------------------------------


def test_read_daemon_pidfile_tolerant(monkeypatch, tmp_path):
    pidfile = tmp_path / "daemon.pid"
    monkeypatch.setattr(server_mod, "DAEMON_PIDFILE", str(pidfile))
    assert server_mod._read_daemon_pidfile() is None  # missing
    pidfile.write_text("1234")
    assert server_mod._read_daemon_pidfile() == 1234
    pidfile.write_text("not-a-pid")
    assert server_mod._read_daemon_pidfile() is None  # garbage
    pidfile.write_text("")
    assert server_mod._read_daemon_pidfile() is None  # empty
    pidfile.write_text("0")
    assert server_mod._read_daemon_pidfile() is None  # non-positive


def test_pid_is_live_probe(monkeypatch):
    assert server_mod._pid_is_live(None) is False
    assert server_mod._pid_is_live(0) is False
    assert server_mod._pid_is_live(-5) is False
    # Alive: signal-0 to our own pid succeeds.
    assert server_mod._pid_is_live(os.getpid()) is True
    # Dead: process does not exist.
    monkeypatch.setattr(
        server_mod.os, "kill", lambda pid, sig: (_ for _ in ()).throw(ProcessLookupError())
    )
    assert server_mod._pid_is_live(123) is False
    # Exists but owned by another user.
    monkeypatch.setattr(
        server_mod.os, "kill", lambda pid, sig: (_ for _ in ()).throw(PermissionError())
    )
    assert server_mod._pid_is_live(123) is True
    # Bogus pid (e.g. above pid_max) -> EINVAL.
    monkeypatch.setattr(
        server_mod.os, "kill", lambda pid, sig: (_ for _ in ()).throw(OSError())
    )
    assert server_mod._pid_is_live(123) is False


def test_daemon_pidfile_guard_refuses_second_daemon(monkeypatch, tmp_path, capsys):
    sock = tmp_path / "daemon.sock"
    pidfile = tmp_path / "daemon.pid"
    sock.write_text("live daemon socket")
    pidfile.write_text("4242")
    monkeypatch.setattr(server_mod, "DAEMON_PIDFILE", str(pidfile))
    monkeypatch.setattr(server_mod, "DAEMON_SOCKET", str(sock))
    monkeypatch.setattr(server_mod, "_pid_is_live", lambda pid: pid == 4242)
    monkeypatch.setattr(sys, "argv", ["ida-pro-mcp", "--daemon"])

    def _boom(*a, **k):
        raise AssertionError("IDAMCPServer must not be constructed on a live daemon")

    monkeypatch.setattr(server_mod, "IDAMCPServer", _boom)

    with pytest.raises(SystemExit) as exc:
        server_mod.main()
    assert exc.value.code == 1
    assert "already running" in capsys.readouterr().err
    # A live daemon's socket and pidfile are never touched.
    assert sock.exists()
    assert pidfile.exists()


def test_daemon_stale_pidfile_and_socket_reclaimed(monkeypatch, tmp_path):
    sock = tmp_path / "daemon.sock"
    pidfile = tmp_path / "daemon.pid"
    sock.write_text("stale socket")
    pidfile.write_text("999999999")  # a dead pid
    monkeypatch.setattr(server_mod, "DAEMON_PIDFILE", str(pidfile))
    monkeypatch.setattr(server_mod, "DAEMON_SOCKET", str(sock))
    monkeypatch.setattr(sys, "argv", ["ida-pro-mcp", "--daemon"])
    # Keep the host-startup native-backend bootstrap a no-op (no .so probing
    # or env mutation in a unit test).
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.native.bootstrap_native_backend",
        lambda: {"enabled": False},
    )

    class _FakeServer:
        def __init__(self):
            self.called = True

        def run_daemon(self):
            pass

        def run(self):
            pass

    monkeypatch.setattr(server_mod, "IDAMCPServer", _FakeServer)

    server_mod.main()
    # The stale artifacts are reclaimed before the new daemon binds.
    assert not sock.exists()
    assert not pidfile.exists()


def test_daemon_cleanup_only_unlinks_own_pid(monkeypatch, tmp_path):
    sock = tmp_path / "daemon.sock"
    pidfile = tmp_path / "daemon.pid"
    monkeypatch.setattr(server_mod, "DAEMON_PIDFILE", str(pidfile))
    monkeypatch.setattr(server_mod, "DAEMON_SOCKET", str(sock))

    # Our own pid -> both artifacts are removed at exit.
    sock.write_text("x")
    pidfile.write_text("x")
    monkeypatch.setattr(server_mod, "_read_daemon_pidfile", os.getpid)
    server_mod.IDAMCPServer._cleanup_daemon()
    assert not sock.exists()
    assert not pidfile.exists()

    # A foreign pid (another live daemon) -> nothing is yanked.
    sock.write_text("x")
    pidfile.write_text("x")
    monkeypatch.setattr(server_mod, "_read_daemon_pidfile", lambda: 4242)
    server_mod.IDAMCPServer._cleanup_daemon()
    assert sock.exists()
    assert pidfile.exists()


# ---------------------------------------------------------------------------
# Lifecycle knobs: tolerant env parsing
# ---------------------------------------------------------------------------


def test_lifecycle_knobs_fall_back_on_bad_env(monkeypatch):
    import ida_pro_mcp.host.config as config

    cases = [
        ("IDA_MCP_ANALYSIS_CONFIRM_POLLS", "ANALYSIS_CONFIRM_POLLS", 2),
        ("IDA_MCP_CHECKPOINT_SAVE_SEC", "CHECKPOINT_SAVE_SECONDS", 5.0),
        (
            "IDA_MCP_LARGE_IDB_SHUTDOWN_GRACE_SEC",
            "LARGE_IDB_SHUTDOWN_GRACE_SECONDS",
            30.0,
        ),
    ]
    for env, attr, default in cases:
        monkeypatch.setenv(env, "not-a-number")
        importlib.reload(config)
        try:
            assert getattr(config, attr) == default, f"{attr} must fall back on bad env"
        finally:
            monkeypatch.delenv(env, raising=False)
            importlib.reload(config)

    # A valid value parses.
    monkeypatch.setenv("IDA_MCP_ANALYSIS_CONFIRM_POLLS", "5")
    importlib.reload(config)
    try:
        assert config.ANALYSIS_CONFIRM_POLLS == 5
    finally:
        monkeypatch.delenv("IDA_MCP_ANALYSIS_CONFIRM_POLLS", raising=False)
        importlib.reload(config)


def test_server_exposes_lifecycle_knobs(tmp_path, monkeypatch):
    """The knobs are readable as instance attributes on a constructed host,
    wired to the config constants (whose tolerant parsing is covered by
    test_lifecycle_knobs_fall_back_on_bad_env)."""
    server = _make_server(tmp_path, monkeypatch)
    try:
        assert server.analysis_confirm_polls == server_mod.ANALYSIS_CONFIRM_POLLS
        assert (
            server.checkpoint_save_seconds
            == server_mod.CHECKPOINT_SAVE_SECONDS
        )
        assert server.safe_mode_poll_seconds == server_mod.SAFE_MODE_POLL_SECONDS
        assert (
            server.safe_mode_watch_seconds
            == server_mod.SAFE_MODE_WATCH_SECONDS
        )
        assert (
            server.large_idb_shutdown_grace_seconds
            == server_mod.LARGE_IDB_SHUTDOWN_GRACE_SECONDS
        )
        assert server.analysis_confirm_polls >= 1
        assert server.safe_mode_watch_seconds >= server.safe_mode_poll_seconds
    finally:
        server.shutdown()
