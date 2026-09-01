"""Agent SSO: per-call identity + per-agent teardown for subagents.

Mirrors the daemon-isolation harness (no real IDA). Exercises the realm
(activate/login/logout), the per-call ``agent`` tag, two-agent session
isolation over one connection, and per-agent runtime teardown.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_client_state import mint_agent_ticket


class _FakeIdaProcess:
    """A fake idat subprocess that is always alive (poll() is None)."""

    pid = 2147483647

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 1


def _tool_call(server: IDAMCPServer, request_id: int, name: str, arguments: dict) -> dict:
    """Issue one MCP tools/call request and return its structured result."""
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    assert "structuredContent" in response["result"]
    return response["result"]["structuredContent"]


def _make_server(tmp_path, monkeypatch) -> IDAMCPServer:
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setenv("IDA_MCP_TOOL_SURFACE", "legacy")
    # Pin the realm secret so tests can mint tickets with a known value.
    monkeypatch.setenv("IDA_MCP_SSO_SECRET", "sekret")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    return server


def _binary(tmp_path, name: str, blob: bytes = b"payload"):
    path = tmp_path / name
    path.write_bytes(blob)
    return path


def _activate(server: IDAMCPServer, *agents: str) -> dict:
    return _tool_call(
        server, 100, "session", {"action": "sso_activate", "agents": list(agents)}
    )


def _login(server: IDAMCPServer, request_id: int, name: str, secret: str) -> dict:
    ticket = mint_agent_ticket(secret, name, exp=time.time() + 3600)
    return _tool_call(
        server, request_id, "session", {"action": "agent_login", "name": name, "ticket": ticket}
    )


def _login_with_scopes(
    server: IDAMCPServer,
    request_id: int,
    name: str,
    secret: str,
    scopes: list[str],
) -> dict:
    ticket = mint_agent_ticket(
        secret, name, exp=time.time() + 3600, scopes=scopes
    )
    return _tool_call(
        server,
        request_id,
        "session",
        {"action": "agent_login", "name": name, "ticket": ticket},
    )


# ---------------------------------------------------------------------------
# Realm lifecycle
# ---------------------------------------------------------------------------

def test_sso_activate_requires_at_least_one_agent(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    res = _activate(server)
    assert res.get("error") is True
    assert res.get("code") == MCPError.INVALID_ARGS


def test_sso_activate_is_one_shot(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    first = _activate(server, "agentA")
    assert first.get("ok") is True
    assert first["sso"]["agents"] == ["agentA"]
    second = _activate(server, "agentB")
    assert second.get("error") is True
    assert second.get("code") == MCPError.INVALID_ARGS


def test_agent_login_requires_activated_realm(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    res = _login(server, 1, "agentA", "sekret")
    assert res.get("error") is True
    assert res.get("code") == MCPError.POLICY_DENIED


def test_agent_login_rejects_name_outside_allowlist(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA")
    res = _login(server, 1, "agentB", "sekret")
    assert res.get("error") is True
    assert "not in the allowed agents list" in str(res.get("message", ""))


def test_agent_login_rejects_forged_signature(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA")
    ticket = mint_agent_ticket("sekret", "agentA", exp=time.time() + 3600)
    name, body, _sig = ticket.rsplit(".", 2)
    forged = f"{name}.{body}.deadbeef" + _sig[8:]
    res = _tool_call(
        server, 1, "session",
        {"action": "agent_login", "name": "agentA", "ticket": forged},
    )
    assert res.get("error") is True
    assert "signature" in str(res.get("message", ""))


def test_agent_login_rejects_expired_ticket(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA")
    ticket = mint_agent_ticket("sekret", "agentA", exp=time.time() - 5)
    res = _tool_call(
        server, 1, "session",
        {"action": "agent_login", "name": "agentA", "ticket": ticket},
    )
    assert res.get("error") is True
    assert "expired" in str(res.get("message", ""))


def test_agent_login_rejects_malformed_signed_expiry(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA")
    original = mint_agent_ticket("sekret", "agentA", exp=time.time() + 3600)
    _name, body, _signature = original.split(".")
    payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload["exp"] = "not-a-number"
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(payload_str.encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(
        b"sekret", payload_str.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    ticket = f"agentA.{encoded}.{signature}"

    res = _tool_call(
        server,
        1,
        "session",
        {"action": "agent_login", "name": "agentA", "ticket": ticket},
    )
    assert res.get("error") is True
    assert res.get("code") == MCPError.POLICY_DENIED
    assert "expiry" in str(res.get("message", ""))


def test_agent_login_success(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA")
    res = _login(server, 1, "agentA", "sekret")
    assert res.get("ok") is True
    assert res["agent"] == "agentA"
    assert "agentA" in server._client_request_state().agents_logged_in


def test_agent_ticket_scopes_gate_dispatch_but_keep_logout_available(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA")
    login = _login_with_scopes(
        server, 1, "agentA", "sekret", ["session:status"]
    )
    assert login.get("ok") is True

    allowed = _tool_call(
        server, 2, "session", {"action": "status", "agent": "agentA"}
    )
    assert allowed.get("ok") is True

    binary = _binary(tmp_path, "scoped.bin")
    denied = _tool_call(
        server,
        3,
        "session",
        {"action": "create", "binary_path": str(binary), "agent": "agentA"},
    )
    assert denied.get("error") is True
    assert denied.get("code") == MCPError.POLICY_DENIED
    assert "not authorized" in str(denied.get("message", ""))

    logout = _tool_call(
        server,
        4,
        "session",
        {"action": "agent_logout", "name": "agentA", "agent": "agentA"},
    )
    assert logout.get("ok") is True


def test_empty_agent_scope_set_denies_calls_but_allows_cleanup(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA")
    login = _login_with_scopes(server, 1, "agentA", "sekret", [])
    assert login.get("ok") is True
    assert login["scopes"] == []

    denied = _tool_call(
        server, 2, "session", {"action": "status", "agent": "agentA"}
    )
    assert denied.get("error") is True
    assert denied.get("code") == MCPError.POLICY_DENIED

    logout = _tool_call(
        server,
        3,
        "session",
        {"action": "agent_logout", "name": "agentA", "agent": "agentA"},
    )
    assert logout.get("ok") is True


# ---------------------------------------------------------------------------
# Per-call agent tag validation
# ---------------------------------------------------------------------------

def test_agent_tag_rejected_when_realm_inactive(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary = _binary(tmp_path, "alpha.bin")
    res = _tool_call(
        server, 1, "session",
        {"action": "create", "binary_path": str(binary), "agent": "agentA"},
    )
    assert res.get("error") is True
    assert res.get("code") == MCPError.POLICY_DENIED


def test_agent_tag_rejected_for_not_logged_in_agent(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA", "agentB")
    _login(server, 1, "agentA", "sekret")
    binary = _binary(tmp_path, "alpha.bin")
    res = _tool_call(
        server, 2, "session",
        {"action": "create", "binary_path": str(binary), "agent": "agentB"},
    )
    assert res.get("error") is True
    assert "not logged in" in str(res.get("message", ""))


def test_agent_tag_is_host_field_not_forwarded(tmp_path, monkeypatch):
    """A per-call agent tag must never reach the IDA arg schema."""
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA")
    _login(server, 1, "agentA", "sekret")
    res = _tool_call(
        server, 2, "session",
        {"action": "agent_logout", "name": "agentA", "agent": "agentA"},
    )
    assert res.get("ok") is True


# ---------------------------------------------------------------------------
# Two-agent isolation over one shared connection
# ---------------------------------------------------------------------------

def test_two_agents_keep_independent_sessions(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA", "agentB")
    _login(server, 1, "agentA", "sekret")
    _login(server, 2, "agentB", "sekret")

    binary_a = _binary(tmp_path, "alpha.bin")
    binary_b = _binary(tmp_path, "bravo.bin")

    create_a = _tool_call(
        server, 3, "session",
        {"action": "create", "binary_path": str(binary_a), "agent": "agentA"},
    )
    assert create_a.get("ok") is True
    sid_a = create_a["session_id"]

    # Agent B creating its own session must not clobber A's active session.
    create_b = _tool_call(
        server, 4, "session",
        {"action": "create", "binary_path": str(binary_b), "agent": "agentB"},
    )
    assert create_b.get("ok") is True
    sid_b = create_b["session_id"]
    assert sid_a != sid_b

    # A's default status still targets A's session after B created its own.
    status_a = _tool_call(server, 5, "session", {"action": "status", "agent": "agentA"})
    assert status_a.get("ok") is True
    assert status_a["session"]["session_id"] == sid_a

    status_b = _tool_call(server, 6, "session", {"action": "status", "agent": "agentB"})
    assert status_b.get("ok") is True
    assert status_b["session"]["session_id"] == sid_b

    # Ownership is agent-scoped: while A is actively running its session, B
    # cannot grab it (the session is busy). Without a live runtime the guard
    # intentionally allows adoption — that is the recorded-session reuse path.
    server.session_runtimes[sid_a] = {"process": _FakeIdaProcess(), "port": 12345}
    adopt = _tool_call(
        server, 7, "session",
        {"action": "switch", "session_id": sid_a, "agent": "agentB"},
    )
    assert adopt.get("error") is True
    assert adopt.get("code") == MCPError.FILE_LOCKED


# ---------------------------------------------------------------------------
# Per-agent teardown
# ---------------------------------------------------------------------------

def test_agent_logout_tears_down_only_its_sessions(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA", "agentB")
    _login(server, 1, "agentA", "sekret")
    _login(server, 2, "agentB", "sekret")

    binary_a = _binary(tmp_path, "alpha.bin")
    binary_b = _binary(tmp_path, "bravo.bin")

    create_a = _tool_call(
        server, 3, "session",
        {"action": "create", "binary_path": str(binary_a), "agent": "agentA"},
    )
    create_b = _tool_call(
        server, 4, "session",
        {"action": "create", "binary_path": str(binary_b), "agent": "agentB"},
    )
    sid_a = create_a["session_id"]
    sid_b = create_b["session_id"]

    cleaned: list[str] = []
    server._cleanup_runtime = lambda sid: cleaned.append(str(sid))

    logout_a = _tool_call(server, 5, "session", {"action": "agent_logout", "name": "agentA"})
    assert logout_a.get("ok") is True
    assert sid_a in cleaned
    assert sid_b not in cleaned, "agent B's runtime must survive agent A's logout"

    # A is no longer usable as a per-call identity.
    after = _tool_call(server, 6, "session", {"action": "status", "agent": "agentA"})
    assert after.get("error") is True
    assert after.get("code") == MCPError.POLICY_DENIED

    # B still works.
    status_b = _tool_call(server, 7, "session", {"action": "status", "agent": "agentB"})
    assert status_b.get("ok") is True
    assert status_b["session"]["session_id"] == sid_b


def test_background_worker_preserves_agent_scoped_session(tmp_path, monkeypatch):
    """A background task submitted by an agent must keep its agent boundary.

    The worker gets a private request state. It must not turn the agent's
    session into connection-global ownership or lose the identity before the
    queued tool call executes.
    """
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA", "agentB")
    _login(server, 1, "agentA", "sekret")
    session = SimpleNamespace(session_id="agent-session")
    state = server._client_request_state()
    state.active_agent = "agentA"
    state.owned_sessions_by_agent["agentA"] = {session.session_id}
    state.current_session_by_agent["agentA"] = session

    observed = {}

    def run(_task):
        worker_state = server._client_request_state()
        observed["agent"] = worker_state.active_agent
        observed["session"] = server.current_session
        observed["global_ownership"] = set(worker_state.owned_session_ids)
        observed["agent_ownership"] = set(
            worker_state.owned_sessions_by_agent.get("agentA", set())
        )
        return {"ok": True}

    try:
        bound = server._bind_background_run(run, session=session)
        assert bound(SimpleNamespace()) == {"ok": True}
        assert observed == {
            "agent": "agentA",
            "session": session,
            "global_ownership": set(),
            "agent_ownership": {"agent-session"},
        }
        # The submitting connection state is unchanged apart from retaining
        # the agent-scoped grant needed to query the task later.
        assert state.owned_session_ids == set()
        assert state.owned_sessions_by_agent["agentA"] == {"agent-session"}
    finally:
        server.shutdown()


def test_connection_close_releases_every_bound_agent(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    # Begin the connection scope first so logins and session ownership are
    # recorded against the same state that _end_client_connection tears down.
    token = server._begin_client_connection()
    _activate(server, "agentA", "agentB")
    _login(server, 1, "agentA", "sekret")
    _login(server, 2, "agentB", "sekret")

    create_a = _tool_call(
        server, 3, "session",
        {"action": "create", "binary_path": str(_binary(tmp_path, "alpha.bin")), "agent": "agentA"},
    )
    create_b = _tool_call(
        server, 4, "session",
        {"action": "create", "binary_path": str(_binary(tmp_path, "bravo.bin")), "agent": "agentB"},
    )
    sid_a = create_a["session_id"]
    sid_b = create_b["session_id"]

    cleaned: list[str] = []
    server._cleanup_runtime = lambda sid: cleaned.append(str(sid))

    server._end_client_connection(token)

    assert sid_a in cleaned
    assert sid_b in cleaned


# ---------------------------------------------------------------------------
# Cross-connection rejection
# ---------------------------------------------------------------------------

def test_agent_tag_rejected_from_different_connection(tmp_path, monkeypatch):
    """An agent logged in on one daemon connection cannot be impersonated
    from a sibling connection, even with the same agent name."""
    server = _make_server(tmp_path, monkeypatch)
    _activate(server, "agentA")
    _login(server, 1, "agentA", "sekret")

    # The login happened on the main thread's implicit state; a sibling
    # thread gets its own context and therefore a different connection_id.
    result: dict = {}

    def sibling() -> None:
        result["res"] = _tool_call(
            server, 99, "session",
            {"action": "status", "agent": "agentA"},
        )

    thread = threading.Thread(target=sibling)
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert result["res"].get("error") is True
    assert result["res"].get("code") == MCPError.POLICY_DENIED
    assert "different connection" in str(result["res"].get("message", ""))


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------

def test_no_agent_tag_behaves_as_before(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary = _binary(tmp_path, "alpha.bin")
    opened = _tool_call(
        server, 1, "session", {"action": "create", "binary_path": str(binary)}
    )
    assert opened.get("ok") is True
    # The connection-level active session is set and usable without SSO.
    assert server.current_session is not None
    status = _tool_call(server, 2, "session", {"action": "status"})
    assert status.get("ok") is True
    assert status["session"]["session_id"] == opened["session_id"]
