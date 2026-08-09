"""Auto-background loading and safe mode for large binaries.

Large binaries must never stall the caller on upfront analysis: ida_open_binary
auto-routes them to the background path (background + auto_backgrounded +
safe_mode in the response) and ida_open_background always returns immediately.
Safe mode gates full-binary analysis/indexing/script execution until the
session's IDA auto-analysis completes; manual small-area operations stay
available.
"""

from __future__ import annotations

import threading
import time

import pytest

from ida_pro_mcp.host.config import LARGE_BINARY_THRESHOLD_BYTES
from ida_pro_mcp.host.server.server import IDAMCPServer


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    srv = IDAMCPServer()
    # Never block on an actual idat spawn.
    monkeypatch.setattr(srv, "_ensure_runtime_and_idb", lambda session: None)
    yield srv
    srv.shutdown()


def _open(server, name, arguments, request_id=1):
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    return response["result"]["structuredContent"]


def test_large_binary_open_auto_backgrounds_and_enters_safe_mode(tmp_path, server):
    large = tmp_path / "huge.bin"
    large.write_bytes(b"\x00" * (LARGE_BINARY_THRESHOLD_BYTES + 1))

    result = _open(server, "ida_open_binary", {"binary_path": str(large)})
    assert result.get("ok") is True
    # Not a blocking open: the request returns immediately with the
    # background contract and the agent is told safe mode is on.
    assert result.get("background") is True
    assert result.get("auto_backgrounded") is True
    assert result.get("safe_mode") is True
    assert result.get("analysis_complete") is False
    assert "warning" not in result
    assert "background" in str(result.get("note") or "")
    assert "safe mode" in str(result.get("note") or "").lower()


def test_small_binary_open_is_not_backgrounded(tmp_path, server):
    small = tmp_path / "small.bin"
    small.write_bytes(b"\x00" * 1024)

    result = _open(server, "ida_open_binary", {"binary_path": str(small)})
    assert result.get("ok") is True
    assert result.get("background") is not True
    assert "auto_backgrounded" not in result


def test_large_binary_with_existing_idb_opens_normally(tmp_path, server):
    """Reusing a completed IDB does not stall on analysis, so no backgrounding."""
    large = tmp_path / "huge2.bin"
    large.write_bytes(b"\x00" * (LARGE_BINARY_THRESHOLD_BYTES + 1))

    first = _open(server, "ida_open_background", {"binary_path": str(large)})
    sid = first["session_id"]
    idb = first["idb_path"]
    with open(idb, "wb") as f:
        f.write(b"IDB")

    reopened = _open(server, "ida_open_binary", {"binary_path": str(large)}, request_id=2)
    assert reopened.get("ok") is True
    assert reopened["session_id"] == sid
    assert reopened.get("background") is not True
    assert reopened.get("auto_backgrounded") is not True


def test_large_binary_background_open_returns_immediately(tmp_path, server):
    large = tmp_path / "huge.bin"
    large.write_bytes(b"\x00" * (LARGE_BINARY_THRESHOLD_BYTES + 1))
    spawns: list[str] = []

    def _spawn(session):
        spawns.append(session.session_id)

    server._spawn_runtime_background = _spawn

    result = _open(server, "ida_open_background", {"binary_path": str(large)})
    assert result.get("ok") is True
    assert result.get("background") is True
    assert result["binary_path"] == str(large)
    assert result.get("safe_mode") is True
    assert spawns == [result["session_id"]]


def test_background_open_spawns_runtime_in_a_thread(tmp_path, server):
    """The runtime is spawned on a daemon thread, not inline.

    _start_server blocks on release_spawn (never set during _open); if the
    open were synchronous the request would not return until the release
    fires, so the test would deadlock until pytest-timeout fails it.  This
    replaces an earlier hard wall-clock bound (elapsed < 0.25s) that flaked
    on loaded CI runners.
    """
    binary = tmp_path / "mid.bin"
    binary.write_bytes(b"\x00" * 4096)
    started: list[str] = []
    spawn_threads: list[threading.Thread] = []
    release_spawn = threading.Event()

    def _start_server(session):
        spawn_threads.append(threading.current_thread())
        started.append(session.session_id)
        release_spawn.wait(timeout=5)
        return {"ok": True}

    server._start_server = _start_server
    # Restore the real ensure path so the background thread reaches _start_server.
    server._ensure_runtime_and_idb = IDAMCPServer._ensure_runtime_and_idb.__get__(server)

    result = _open(server, "ida_open_background", {"binary_path": str(binary)})
    # The request returned while the spawn was still pending: release it only
    # now, then wait for the background thread to drain and verify it ran.
    release_spawn.set()
    for t in spawn_threads:
        t.join(timeout=5)

    assert result.get("ok") is True
    assert result.get("background") is True
    assert started == [result["session_id"]]
    assert spawn_threads and not any(t.is_alive() for t in spawn_threads)


def test_background_open_reuses_persisted_session(tmp_path, server):
    binary = tmp_path / "same.bin"
    binary.write_bytes(b"\x00" * 1024)

    first = _open(server, "ida_open_background", {"binary_path": str(binary)})
    first_sid = first["session_id"]
    first_idb = first["idb_path"]

    second = _open(server, "ida_open_background", {"binary_path": str(binary)}, request_id=2)
    assert second["session_id"] == first_sid
    assert second["idb_path"] == first_idb
    assert second.get("background") is True
    assert "Reusing" in str(second.get("note") or "")


def test_background_reuse_across_client_restart(tmp_path, monkeypatch):
    """A restarted client reloads the session through the background path."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    binary = tmp_path / "same.bin"
    binary.write_bytes(b"\x00" * 1024)

    server1 = IDAMCPServer()
    monkeypatch.setattr(server1, "_ensure_runtime_and_idb", lambda session: None)
    first = _open(server1, "ida_open_background", {"binary_path": str(binary)})
    sid = first["session_id"]
    idb = first["idb_path"]
    server1.shutdown()

    server2 = IDAMCPServer()
    monkeypatch.setattr(server2, "_ensure_runtime_and_idb", lambda session: None)
    # The persisted analysis_gate from server1's run is restored at startup:
    # the half-analyzed background session comes back in safe mode, which does
    # NOT change the session_id/idb_path reuse the client depends on.
    assert server2._safe_mode_active(sid) is True
    reopened = _open(server2, "ida_open_background", {"binary_path": str(binary)})
    assert reopened["session_id"] == sid
    assert reopened["idb_path"] == idb
    assert reopened["safe_mode"] is True
    server2.shutdown()


def test_background_load_error_surfaces_in_status(tmp_path, server):
    binary = tmp_path / "err.bin"
    binary.write_bytes(b"\x00" * 1024)
    errors = server._background_load_errors = {}

    def _ensure(session):
        raise RuntimeError("idat exploded")

    server._ensure_runtime_and_idb = _ensure

    result = _open(server, "ida_open_background", {"binary_path": str(binary)})
    sid = result["session_id"]

    deadline = time.time() + 5
    while time.time() < deadline and sid not in errors:
        time.sleep(0.02)
    assert sid in errors

    status = _open(server, "ida_session_status", {}, request_id=2)
    assert status.get("ok") is True
    bg_error = status["session"].get("background_error")
    assert bg_error is not None
    assert bg_error.get("error") is True
    assert "idat exploded" in str(bg_error.get("message") or "")


def test_large_binary_threshold_respects_env(tmp_path, monkeypatch, server):
    import importlib

    from ida_pro_mcp.host.server import server_session

    # Reload config with the override set so the threshold comes from the
    # real env parse path in config.py, not a copy of the formula here.
    monkeypatch.setenv("IDA_MCP_LARGE_BINARY_MB", "1")
    import ida_pro_mcp.host.config as config

    importlib.reload(config)
    monkeypatch.setattr(
        server_session,
        "LARGE_BINARY_THRESHOLD_BYTES",
        config.LARGE_BINARY_THRESHOLD_BYTES,
    )
    big = tmp_path / "just-over-1mb.bin"
    big.write_bytes(b"\x00" * (1024 * 1024 + 1))
    small = tmp_path / "under-1mb.bin"
    small.write_bytes(b"\x00" * (512 * 1024))

    server._ensure_runtime_and_idb = lambda session: None
    auto = _open(server, "ida_open_binary", {"binary_path": str(big)})
    assert auto.get("auto_backgrounded") is True
    assert auto.get("safe_mode") is True
    assert "auto_backgrounded" not in _open(
        server, "ida_open_binary", {"binary_path": str(small)}
    )
    # Restore config to the default threshold for later tests.
    monkeypatch.delenv("IDA_MCP_LARGE_BINARY_MB", raising=False)
    importlib.reload(config)
