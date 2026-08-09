"""Regression tests for f16_client_state audit findings.

Covers (no live IDA):
- server_semantic: ``_handle_gadgets_semantic_find`` refuses to read a foreign
  connection's session (ownership guard fires before the cached index is read
  or rebuilt); ``_semantic_index_rebuild`` returns the standard ``ok: True``
  envelope; the rebuild, cached-read, pagination and error paths are exercised.
- server_client_state: ``_end_client_connection`` does not SIGKILL a sibling
  connection's adopted live runtime (stale ownership record); teardown of the
  shared realm's ``logged_in`` runs under ``realm['lock']``; SSO ticket scopes
  are shape-validated at login.
- server_wiki: an unbalanced-quote action tail returns an INVALID_ARGS envelope
  instead of raising out of the transport.
"""

from __future__ import annotations

import os
import threading
import time

from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_client_state import mint_agent_ticket


class _FakeIdaProcess:
    """A fake idat subprocess that is always alive (poll() is None)."""

    pid = 2147483647

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 1


def _live_runtime(sid: str) -> dict:
    return {
        "process": _FakeIdaProcess(),
        "port": 12345,
        "idb_path": f"/fake/{sid}.i64",
    }


GADGET_PAYLOAD = {
    "ok": True,
    "gadgets": [
        {"addr": "0x401000", "insns": 3, "gadget": "pop rdi ; ret"},
        {"addr": "0x401005", "insns": 2, "gadget": "mov rdi, rax ; ret"},
    ],
}


def _make_server(tmp_path, monkeypatch) -> IDAMCPServer:
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    # Force deterministic token matching in the gadget scorer (no embedder).
    import ida_pro_mcp.host.server.server_semantic as server_semantic_mod
    monkeypatch.setattr(server_semantic_mod, "EMBEDDING_FIRST_MODE", False)
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    return server


def _owned_session(server: IDAMCPServer, binary: str = "/samples/alpha.bin"):
    """Create a session and record it as this connection's current/owned one."""
    session = server.session_mgr.create_session(binary)
    server.current_session = session
    return session


# ---------------------------------------------------------------------------
# server_semantic: ownership guard + envelope + path coverage
# ---------------------------------------------------------------------------

def test_semantic_index_rebuild_returns_ok_envelope(tmp_path, monkeypatch):
    """Finding 6: the rebuild success dict carries the standard ok:True key."""
    server = _make_server(tmp_path, monkeypatch)
    session = _owned_session(server)
    server.call_tool = lambda tool, idb_path, **kwargs: GADGET_PAYLOAD

    rebuilt = server._semantic_index_rebuild(
        session, ["rop"], source_limit=3000, max_insns=6
    )
    assert rebuilt.get("ok") is True
    assert rebuilt["rows_indexed"] == 2
    assert rebuilt["errors"] == []
    assert os.path.exists(rebuilt["db_path"])


def test_semantic_find_owned_session_returns_matches(tmp_path, monkeypatch):
    """Finding 1 pass-path + finding 8: an owned session is readable and the
    cached index is used once built."""
    server = _make_server(tmp_path, monkeypatch)
    session = _owned_session(server)
    server.call_tool = lambda tool, idb_path, **kwargs: GADGET_PAYLOAD

    first = server._handle_gadgets_semantic_find(
        {"query": "pop rdi", "idb": session.session_id, "source_actions": ["rop"]}
    )
    assert first.get("ok") is True
    assert first["count"] == 2
    assert first["index"]["fingerprint"]

    cached = server._handle_gadgets_semantic_find(
        {
            "query": "pop rdi",
            "idb": session.session_id,
            "source_actions": ["rop"],
            "rebuild_index": False,
        }
    )
    assert cached.get("ok") is True
    assert cached["count"] == 2
    assert "index_refresh" not in cached, "cached read must not rebuild"


def test_semantic_find_pagination(tmp_path, monkeypatch):
    """Finding 8: offset/limit pagination reports truncated + next_offset."""
    server = _make_server(tmp_path, monkeypatch)
    session = _owned_session(server)
    server.call_tool = lambda tool, idb_path, **kwargs: GADGET_PAYLOAD

    page = server._handle_gadgets_semantic_find(
        {
            "query": "rdi",
            "idb": session.session_id,
            "source_actions": ["rop"],
            "limit": 1,
            "offset": 0,
        }
    )
    assert page.get("ok") is True
    assert page["count"] == 1
    assert page["total"] == 2
    assert page["truncated"] is True
    assert page["next_offset"] == 1

    second = server._handle_gadgets_semantic_find(
        {
            "query": "rdi",
            "idb": session.session_id,
            "source_actions": ["rop"],
            "limit": 1,
            "offset": 1,
        }
    )
    assert second.get("ok") is True
    assert second["count"] == 1
    assert second["truncated"] is False
    assert second["next_offset"] is None


def test_semantic_find_rebuild_error_envelope(tmp_path, monkeypatch):
    """Finding 8: a failing rebuild surfaces the error envelope, not a raise."""
    server = _make_server(tmp_path, monkeypatch)
    session = _owned_session(server)
    server.call_tool = (
        lambda tool, idb_path, **kwargs: make_error(
            MCPError.INTERNAL, "gadgets unavailable"
        )
    )

    res = server._handle_gadgets_semantic_find(
        {"query": "pop", "idb": session.session_id}
    )
    assert res.get("error") is True
    assert res.get("code") == MCPError.INTERNAL


def test_semantic_find_refuses_foreign_locked_session(tmp_path, monkeypatch):
    """Finding 1 (high): a sibling connection cannot read a session that
    another connection is actively running — the ownership guard fires before
    the cached index is read or the artifact dir is touched."""
    server = _make_server(tmp_path, monkeypatch)
    token_a = server._begin_client_connection()
    session = _owned_session(server)
    sid = session.session_id
    # Connection A is actively running the session's runtime.
    server.session_runtimes[sid] = _live_runtime(sid)
    server.call_tool = lambda tool, idb_path, **kwargs: GADGET_PAYLOAD

    result: dict = {}

    def sibling() -> None:
        server._begin_client_connection()
        result["res"] = server._handle_gadgets_semantic_find(
            {"query": "pop", "idb": sid}
        )

    thread = threading.Thread(target=sibling)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    server._end_client_connection(token_a)

    res = result["res"]
    assert res.get("error") is True
    assert res.get("code") == MCPError.FILE_LOCKED
    assert "matches" not in res


def test_semantic_find_adopts_unlocked_recorded_session(tmp_path, monkeypatch):
    """The guard must not over-block: a session with no live runtime remains
    adoptable (the recorded-session reuse path), and the adopter may then read
    its cached index."""
    server = _make_server(tmp_path, monkeypatch)
    token_a = server._begin_client_connection()
    session = _owned_session(server)
    sid = session.session_id
    server.call_tool = lambda tool, idb_path, **kwargs: GADGET_PAYLOAD

    # A builds the cached index.
    owned = server._handle_gadgets_semantic_find(
        {"query": "rdi", "idb": sid, "source_actions": ["rop"]}
    )
    assert owned.get("ok") is True

    result: dict = {}

    def sibling() -> None:
        server._begin_client_connection()
        result["res"] = server._handle_gadgets_semantic_find(
            {"query": "rdi", "idb": sid, "source_actions": ["rop"]}
        )

    thread = threading.Thread(target=sibling)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    server._end_client_connection(token_a)

    res = result["res"]
    assert res.get("ok") is True
    assert res["count"] == 2


# ---------------------------------------------------------------------------
# server_client_state: _end_client_connection ownership re-check
# ---------------------------------------------------------------------------

def test_end_connection_does_not_kill_sibling_adopted_runtime(tmp_path, monkeypatch):
    """Finding 2 (medium): A's ownership record went stale, B adopted the
    session and started a live runtime; when A disconnects it must NOT tear
    down B's runtime."""
    server = _make_server(tmp_path, monkeypatch)
    token_a = server._begin_client_connection()
    session = _owned_session(server)
    sid = session.session_id
    # A's runtime died (no live runtime registered).

    cleaned: list[str] = []
    server._cleanup_runtime = lambda s: cleaned.append(str(s))

    def sibling() -> None:
        server._begin_client_connection()
        # B adopts the session (guard passes: nothing is running it) and
        # starts its own live runtime.
        assert server._ensure_client_owns_session(session) is None
        server.session_runtimes[sid] = _live_runtime(sid)

    thread = threading.Thread(target=sibling)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()

    server._end_client_connection(token_a)
    assert sid not in cleaned, "sibling's adopted live runtime must survive A's disconnect"


def test_end_connection_cleans_own_live_runtime(tmp_path, monkeypatch):
    """Control: a connection that actually owns a live runtime still tears it
    down on disconnect."""
    server = _make_server(tmp_path, monkeypatch)
    token = server._begin_client_connection()
    session = _owned_session(server)
    sid = session.session_id
    server.session_runtimes[sid] = _live_runtime(sid)

    cleaned: list[str] = []
    server._cleanup_runtime = lambda s: cleaned.append(str(s))

    server._end_client_connection(token)
    assert sid in cleaned


def test_end_connection_cleans_owned_session_with_no_sibling(tmp_path, monkeypatch):
    """Fallback: with no sibling adopting the session, a disconnect still cleans
    up the (dead) owned runtime record."""
    server = _make_server(tmp_path, monkeypatch)
    token = server._begin_client_connection()
    session = _owned_session(server)
    sid = session.session_id

    cleaned: list[str] = []
    server._cleanup_runtime = lambda s: cleaned.append(str(s))

    server._end_client_connection(token)
    assert sid in cleaned


def test_end_connection_drops_logged_in_agents_under_realm_lock(tmp_path, monkeypatch):
    """Finding 5: connection teardown removes the agent from the shared realm's
    logged_in registry (and does so under realm['lock'])."""
    server = _make_server(tmp_path, monkeypatch)
    token = server._begin_client_connection()
    res, err = server._sso_activate_realm(["agentA"], secret="sekret")
    assert err is None and res is not None
    ok, login_err = server._sso_agent_login(
        "agentA", mint_agent_ticket("sekret", "agentA", exp=time.time() + 3600)
    )
    assert login_err is None and ok is not None

    realm = server._sso_realm()
    assert "agentA" in realm["logged_in"]
    assert hasattr(realm["lock"], "__enter__")

    server._end_client_connection(token)
    assert "agentA" not in realm["logged_in"]


# ---------------------------------------------------------------------------
# server_client_state: SSO scope shape validation
# ---------------------------------------------------------------------------

def test_agent_login_rejects_malformed_scopes(tmp_path, monkeypatch):
    """Finding 7: a ticket whose scopes are not a list of non-empty strings is
    rejected instead of storing/echoing a misleading value."""
    server = _make_server(tmp_path, monkeypatch)
    res, err = server._sso_activate_realm(["agentA"], secret="sekret")
    assert err is None and res is not None

    for bad in (123, "read", [None, "read"]):
        ticket = mint_agent_ticket(
            "sekret", "agentA", exp=time.time() + 3600, scopes=bad
        )
        ok, login_err = server._sso_agent_login("agentA", ticket)
        assert ok is None
        assert login_err is not None
        assert login_err["code"] == MCPError.POLICY_DENIED
        assert "scopes" in str(login_err["message"])


def test_agent_login_accepts_valid_scopes(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    res, err = server._sso_activate_realm(["agentA"], secret="sekret")
    assert err is None and res is not None

    ticket = mint_agent_ticket(
        "sekret", "agentA", exp=time.time() + 3600, scopes=["read", "write"]
    )
    ok, login_err = server._sso_agent_login("agentA", ticket)
    assert login_err is None and ok is not None
    assert ok["scopes"] == ["read", "write"]


# ---------------------------------------------------------------------------
# server_wiki: unbalanced-quote action tail
# ---------------------------------------------------------------------------

def test_wiki_unbalanced_quote_returns_invalid_args(tmp_path, monkeypatch):
    """Finding 3 (medium): action="read 'tools/query" returns an INVALID_ARGS
    envelope instead of a -32000 internal error from shlex.split."""
    server = _make_server(tmp_path, monkeypatch)
    res = server._handle_wiki({"action": "read 'tools/query"})
    assert res.get("error") is True
    assert res.get("code") == MCPError.INVALID_ARGS
    assert "shlex" not in str(res.get("message", ""))
