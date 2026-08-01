"""Large-binary warning and background loading (ida_open_background).

Large binaries must not be silently loaded with a blocking upfront call that
stalls the client for the whole analysis: ida_open_binary returns a warning
with a suggestion, and ida_open_background creates the session and spawns
the IDA runtime without waiting.
"""

from __future__ import annotations

import os
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


def test_large_binary_open_warns_and_suggests_background(tmp_path, server):
    large = tmp_path / "huge.bin"
    large.write_bytes(b"\x00" * (LARGE_BINARY_THRESHOLD_BYTES + 1))

    result = _open(server, "ida_open_binary", {"binary_path": str(large)})
    assert result.get("ok") is True
    warning = result.get("warning")
    assert warning is not None
    assert warning["code"] == "large_binary"
    assert "ida_open_background" in warning["suggestion"]
    assert "MiB" in warning["message"]


def test_small_binary_open_has_no_warning(tmp_path, server):
    small = tmp_path / "small.bin"
    small.write_bytes(b"\x00" * 1024)

    result = _open(server, "ida_open_binary", {"binary_path": str(small)})
    assert result.get("ok") is True
    assert "warning" not in result


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
    warning = result.get("warning")
    assert warning is not None and warning["code"] == "large_binary"
    assert spawns == [result["session_id"]]


def test_background_open_spawns_runtime_in_a_thread(tmp_path, server):
    """The runtime is spawned on a daemon thread, not inline.

    _start_server blocks until released; if the open were synchronous the
    request would not return until the release fires (~0.3s later).
    """
    binary = tmp_path / "mid.bin"
    binary.write_bytes(b"\x00" * 4096)
    started: list[str] = []
    release_spawn = threading.Event()

    def _start_server(session):
        started.append(session.session_id)
        release_spawn.wait(timeout=5)
        return {"ok": True}

    server._start_server = _start_server
    # Restore the real ensure path so the background thread reaches _start_server.
    server._ensure_runtime_and_idb = IDAMCPServer._ensure_runtime_and_idb.__get__(server)

    timer = threading.Timer(0.3, release_spawn.set)
    timer.start()
    t0 = time.monotonic()
    result = _open(server, "ida_open_background", {"binary_path": str(binary)})
    elapsed = time.monotonic() - t0
    timer.cancel()
    release_spawn.set()

    assert result.get("ok") is True
    assert result.get("background") is True
    # The request returned while the spawn was still pending.
    assert elapsed < 0.25
    assert started == [result["session_id"]]


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
    reopened = _open(server2, "ida_open_background", {"binary_path": str(binary)})
    assert reopened["session_id"] == sid
    assert reopened["idb_path"] == idb
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
    import time

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


def test_large_binary_warning_threshold_respects_env(tmp_path, monkeypatch, server):
    from ida_pro_mcp.host.server import server_session

    monkeypatch.setenv("IDA_MCP_LARGE_BINARY_MB", "1")
    monkeypatch.setattr(
        server_session,
        "LARGE_BINARY_THRESHOLD_BYTES",
        max(1, int(os.environ.get("IDA_MCP_LARGE_BINARY_MB", "50"))) * 1024 * 1024,
    )
    big = tmp_path / "just-over-1mb.bin"
    big.write_bytes(b"\x00" * (1024 * 1024 + 1))
    small = tmp_path / "under-1mb.bin"
    small.write_bytes(b"\x00" * (512 * 1024))

    server._ensure_runtime_and_idb = lambda session: None
    warning = _open(server, "ida_open_binary", {"binary_path": str(big)}).get("warning")
    assert warning is not None and warning["code"] == "large_binary"
    assert "warning" not in _open(server, "ida_open_binary", {"binary_path": str(small)})
