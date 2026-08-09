"""Regression tests for session-blitz findings in the CLI daemon bridge.

Covers the swarm/session-blitz f17 findings on ``ida_pro_mcp.cli``:

- F1: ``_daemon_call`` must return the id-2 tools/call response, never a
  trailing ``notifications/message`` line.
- F2: daemon socket errors (ConnectionRefusedError, socket.timeout) surface as
  clean ``SystemExit`` messages, and a failed daemon boot includes stderr
  diagnostics.
- F3: the daemon bridge verifies socket ownership before connect/unlink.
- F4: ``send()`` never returns a notification (no id) as the answer, and raw
  mode injects an id so it is a real request.
- F5: explicit request ids advance the auto id counter (no duplicate ids).
- F6: ``_start_daemon`` re-verifies liveness before unlinking a socket.
"""

import json
import os
import re
import socket
import sys
import textwrap
from pathlib import Path

import pytest

from ida_pro_mcp import cli

# ---------------------------------------------------------------------------
# Fake stdio MCP server (process boundary), mirroring tests/test_cli.py
# ---------------------------------------------------------------------------

_FAKE_SERVER = textwrap.dedent(
    """\
    import json
    import sys

    for line in sys.stdin:
        req = json.loads(line)
        method = req.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": req["params"].get("protocolVersion"),
                "capabilities": {},
                "serverInfo": {"name": "fake-mcp", "version": "0"},
            }
        elif method == "tools/call":
            params = req.get("params", {})
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "ok": True,
                                "tool": params.get("name"),
                                "arguments": params.get("arguments"),
                            }
                        ),
                    }
                ],
                "isError": False,
            }
        else:
            result = {"echoed_method": method, "echoed_params": req.get("params")}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": result}) + "\\n")
        sys.stdout.flush()
    """
)


@pytest.fixture
def fake_server_cmd(tmp_path, monkeypatch):
    """Point the CLI at a fake MCP server process."""
    script = tmp_path / "fake_mcp_server.py"
    script.write_text(_FAKE_SERVER, encoding="utf-8")
    monkeypatch.setattr(cli, "_server_cmd", lambda: [sys.executable, "-u", str(script)])
    return str(script)


# ---------------------------------------------------------------------------
# Fake AF_UNIX socket plumbing for _daemon_call / _start_daemon probes
# ---------------------------------------------------------------------------


class FakeSocket:
    def __init__(self, recv_chunks=None, connect_error=None, recv_error=None):
        self._recv_chunks = list(recv_chunks or [])
        self._connect_error = connect_error
        self._recv_error = recv_error
        self.timeout = None
        self.sent = b""

    def settimeout(self, t):
        self.timeout = t

    def connect(self, path):
        if self._connect_error is not None:
            raise self._connect_error
        self.connected_path = path

    def sendall(self, data):
        self.sent += data

    def shutdown(self, how):
        self.shutdown_how = how

    def recv(self, n):
        if self._recv_error is not None:
            raise self._recv_error
        if self._recv_chunks:
            return self._recv_chunks.pop(0)
        return b""

    def close(self):
        self.closed = True


class FakeSocketModule:
    AF_UNIX = socket.AF_UNIX
    SOCK_STREAM = socket.SOCK_STREAM
    SHUT_WR = socket.SHUT_WR

    def __init__(self, sock):
        self._sock = sock

    def socket(self, *args):
        return self._sock


# ---------------------------------------------------------------------------
# Fake stdio process for MCPStdioClient unit tests
# ---------------------------------------------------------------------------


class FakeStdin:
    def __init__(self):
        self.written = []

    def write(self, s):
        self.written.append(s)

    def flush(self):
        pass


class FakeStdout:
    def __init__(self, lines):
        self._lines = list(lines)

    def readline(self):
        if not self._lines:
            return ""
        return self._lines.pop(0)


class FakeProc:
    def __init__(self, stdout_lines=None, stdin=None):
        self.stdout = FakeStdout(stdout_lines or [])
        self.stdin = stdin


def _make_client(proc):
    client = cli.MCPStdioClient.__new__(cli.MCPStdioClient)
    client.proc = proc
    client._id = 0
    client._stderr = cli._StderrTail([])
    return client


# ---------------------------------------------------------------------------
# F1: _daemon_call selects the id-2 response
# ---------------------------------------------------------------------------


def test_daemon_call_ignores_trailing_notification(monkeypatch):
    chunks = [
        b'{"jsonrpc":"2.0","id":1,"result":{"ok":"init"}}\n',
        b'{"jsonrpc":"2.0","id":2,"result":{"ok":"tool"}}\n',
        b'{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}\n',
    ]
    fake = FakeSocket(recv_chunks=chunks)
    monkeypatch.setattr(cli, "_socket_mod", FakeSocketModule(fake))
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    result = cli._daemon_call("background", {"action": "status"})
    assert result["id"] == 2
    assert result["result"]["ok"] == "tool"


def test_daemon_call_picks_request_id_over_interleaved_notifications(monkeypatch):
    chunks = [
        b'{"jsonrpc":"2.0","id":1,"result":{}}\n',
        b'{"jsonrpc":"2.0","method":"notifications/message","params":{}}\n',
        b'{"jsonrpc":"2.0","id":2,"result":{"ok":2}}\n',
        b'{"jsonrpc":"2.0","method":"notifications/message","params":{}}\n',
    ]
    fake = FakeSocket(recv_chunks=chunks)
    monkeypatch.setattr(cli, "_socket_mod", FakeSocketModule(fake))
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    result = cli._daemon_call("background", {"action": "status"})
    assert result["id"] == 2
    assert result["result"]["ok"] == 2


def test_daemon_call_without_request_response_raises(monkeypatch):
    fake = FakeSocket(recv_chunks=[b'{"jsonrpc":"2.0","id":1,"result":{}}\n'])
    monkeypatch.setattr(cli, "_socket_mod", FakeSocketModule(fake))
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    with pytest.raises(SystemExit, match="did not return a response"):
        cli._daemon_call("background", {"action": "status"})


# ---------------------------------------------------------------------------
# F2: clean socket error handling
# ---------------------------------------------------------------------------


def test_daemon_call_connect_refused_is_clean_error(monkeypatch):
    fake = FakeSocket(connect_error=ConnectionRefusedError("refused"))
    monkeypatch.setattr(cli, "_socket_mod", FakeSocketModule(fake))
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    with pytest.raises(SystemExit, match="Cannot connect to daemon"):
        cli._daemon_call("background", {"action": "status"})
    assert fake.closed


def test_daemon_call_socket_timeout_is_clean_error(monkeypatch):
    fake = FakeSocket(recv_error=TimeoutError("timed out"))
    monkeypatch.setattr(cli, "_socket_mod", FakeSocketModule(fake))
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    with pytest.raises(SystemExit, match="did not respond within"):
        cli._daemon_call("background", {"action": "status"})
    assert fake.closed


class _FakeTime:
    def __init__(self):
        self.now = 0.0

    def time(self):
        return self.now

    def sleep(self, _):
        self.now += 1.0


def test_start_daemon_timeout_includes_diagnostics(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "daemon.sock")
    monkeypatch.setattr(cli, "_DAEMON_SOCKET", sock_path)
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    monkeypatch.setattr(cli, "_daemon_is_running", lambda: False)
    monkeypatch.setattr(cli, "time", _FakeTime())

    def fake_popen(cmd, **kwargs):
        os.write(kwargs["stderr"], b"Traceback: daemon exploded\n")

    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)
    with pytest.raises(SystemExit, match="Traceback: daemon exploded"):
        cli._start_daemon()


# ---------------------------------------------------------------------------
# F3: daemon socket ownership verification
# ---------------------------------------------------------------------------


def test_daemon_socket_owned_true_for_owned_socket(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "daemon.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(sock_path)
        listener.listen(1)
        monkeypatch.setattr(cli, "_DAEMON_SOCKET", sock_path)
        assert cli._daemon_socket_owned() is True
    finally:
        listener.close()


def test_daemon_socket_owned_false_for_regular_file(monkeypatch, tmp_path):
    path = tmp_path / "not-a-socket"
    path.write_text("junk", encoding="utf-8")
    monkeypatch.setattr(cli, "_DAEMON_SOCKET", str(path))
    assert cli._daemon_socket_owned() is False


def test_daemon_socket_owned_false_for_foreign_owner(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "daemon.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(sock_path)
        listener.listen(1)
        monkeypatch.setattr(cli, "_DAEMON_SOCKET", sock_path)
        monkeypatch.setattr(os, "geteuid", lambda: 999999)
        assert cli._daemon_socket_owned() is False
    finally:
        listener.close()


def test_daemon_call_refuses_foreign_socket(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_DAEMON_SOCKET", str(tmp_path / "daemon.sock"))
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: False)
    with pytest.raises(SystemExit, match="not owned by the current user"):
        cli._daemon_call("background", {"action": "status"})


def test_start_daemon_refuses_foreign_socket_without_unlink(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "daemon.sock")
    open(sock_path, "w").close()
    monkeypatch.setattr(cli, "_DAEMON_SOCKET", sock_path)
    monkeypatch.setattr(cli, "_daemon_is_running", lambda: False)
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: False)
    with pytest.raises(SystemExit, match="not owned by the current user"):
        cli._start_daemon()
    assert os.path.exists(sock_path)  # a socket we do not own is never unlinked


# ---------------------------------------------------------------------------
# F4: notifications are never misread as the answer; raw mode injects an id
# ---------------------------------------------------------------------------


def test_send_skips_notification_before_the_response():
    stdout_lines = [
        '{"jsonrpc":"2.0","method":"notifications/message","params":{"n":1}}\n',
        '{"jsonrpc":"2.0","id":7,"result":{"ok":true}}\n',
    ]
    client = _make_client(FakeProc(stdout_lines=stdout_lines, stdin=FakeStdin()))
    resp = client.send({"jsonrpc": "2.0", "id": 7, "method": "tools/call"})
    assert resp["id"] == 7
    assert resp["result"]["ok"] is True


def test_send_never_returns_a_notification_without_id():
    stdout_lines = [
        '{"jsonrpc":"2.0","method":"notifications/message","params":{"n":1}}\n',
        '{"jsonrpc":"2.0","id":3,"result":{"ok":true}}\n',
    ]
    client = _make_client(FakeProc(stdout_lines=stdout_lines, stdin=FakeStdin()))
    # request without an id (rid is None): the id-less notification must not be
    # returned; the first id-bearing message is.
    resp = client.send({"jsonrpc": "2.0", "method": "notify"})
    assert resp["id"] == 3


def test_raw_mode_injects_id_when_missing(fake_server_cmd, capsys):
    assert cli.main(["raw", '{"method":"ping","params":{}}']) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["id"] == 2  # initialize used id 1, so the injected id is 2
    assert out["result"]["echoed_method"] == "ping"


# ---------------------------------------------------------------------------
# F5: explicit request ids advance the auto id counter
# ---------------------------------------------------------------------------


def test_call_with_explicit_request_id_advances_counter():
    seen = []

    def fake_send(request):
        seen.append(request["id"])
        return {"jsonrpc": "2.0", "id": request["id"], "result": {}}

    client = _make_client(FakeProc(stdout_lines=[], stdin=FakeStdin()))
    client.send = fake_send
    client.call("initialize", {"a": 1}, request_id=1)
    client.call("ping", {})
    assert seen == [1, 2]  # no duplicate id-1 on the same connection


# ---------------------------------------------------------------------------
# F6: _start_daemon re-verifies before unlinking a socket
# ---------------------------------------------------------------------------


def test_start_daemon_does_not_unlink_socket_that_comes_alive(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "daemon.sock")
    open(sock_path, "w").close()  # a socket path that exists but is not live
    monkeypatch.setattr(cli, "_DAEMON_SOCKET", sock_path)
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    calls = {"n": 0}

    def flaky_running():
        calls["n"] += 1
        return calls["n"] >= 2  # first probe False, re-check (and later) True

    monkeypatch.setattr(cli, "_daemon_is_running", flaky_running)
    spawned = []
    monkeypatch.setattr(
        cli.subprocess, "Popen", lambda *a, **k: spawned.append(a) or None
    )
    cli._start_daemon()
    assert os.path.exists(sock_path)  # never unlinked a socket that came alive
    assert spawned == []  # never spawned a second daemon


def test_start_daemon_unlinks_and_spawns_when_socket_still_dead(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "daemon.sock")
    open(sock_path, "w").close()
    monkeypatch.setattr(cli, "_DAEMON_SOCKET", sock_path)
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    calls = {"n": 0}

    def late_running():
        calls["n"] += 1
        return calls["n"] >= 3  # probe + re-check False, then live after spawn

    monkeypatch.setattr(cli, "_daemon_is_running", late_running)
    spawned = []
    monkeypatch.setattr(
        cli.subprocess, "Popen", lambda *a, **k: spawned.append(a) or None
    )
    cli._start_daemon()
    assert spawned  # a genuinely dead socket is unlinked and a daemon started
    assert not os.path.exists(sock_path)


# ---------------------------------------------------------------------------
# F7: the intelligence action whitelist mirrors the tool's Literal
# ---------------------------------------------------------------------------


def test_intelligence_whitelist_matches_tool_literal():
    """The CLI whitelist must mirror the action Literal in the intelligence
    tool.  Extracted statically from the source (the tool module itself is not
    importable without the IDA runtime) so drift fails loudly here."""
    intel_path = (
        Path(cli.__file__).parent / "ida_mcp" / "tools" / "intelligence.py"
    )
    source = intel_path.read_text(encoding="utf-8")
    match = re.search(r"Literal\[\s*(.*?)\s*\]", source, re.S)
    assert match is not None, "could not locate the action Literal"
    literal_members = frozenset(re.findall(r"['\"]([a-z_]+)['\"]", match.group(1)))
    assert literal_members == cli._INTELLIGENCE_ACTIONS
