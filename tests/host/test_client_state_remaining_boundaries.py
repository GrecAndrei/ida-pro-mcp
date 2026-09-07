"""Cover connection-state and SSO ownership boundary modes."""

from __future__ import annotations

import json
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_client_state as state_mod
from ida_pro_mcp.host.server.server_client_state import ServerClientStateMixin


class _Host(ServerClientStateMixin):
    pass


def test_runtime_table_helpers_fail_closed_and_update_atomically():
    host = _Host()
    host.session_runtimes = []
    assert host._runtime_record("sid") is None
    assert host._runtime_items_snapshot() == []
    assert host._runtime_update("sid", state="dead") is False

    host.session_runtimes = {"sid": "not-a-record", "ok": {"state": "old"}}
    assert host._runtime_record("sid") is None
    assert host._runtime_items_snapshot() == [("ok", {"state": "old"})]
    assert host._runtime_update("sid", state="dead") is False
    assert host._runtime_update("ok", state="live") is True
    assert host.session_runtimes["ok"]["state"] == "live"


def test_connection_teardown_skips_sessions_adopted_by_sibling():
    host = _Host()
    token = host._begin_client_connection()
    state = host._client_request_state()
    state.agents_logged_in.add("worker")
    state.owned_sessions_by_agent["worker"] = {"AGENT001"}
    state.owned_session_ids.add("DIRECT001")
    host._connection_should_teardown = lambda *_args: False
    cleaned = []

    def cleanup(sid):
        cleaned.append(sid)

    host._cleanup_runtime = cleanup
    host._sso_realm_store = {
        "logged_in": {"worker": {"conn_id": state.connection_id}},
        "lock": None,
    }
    host._end_client_connection(token)
    assert cleaned == []
    assert host._sso_realm_store["logged_in"] == {}


def test_owner_and_spawn_helpers_cover_uninitialized_and_exception_paths():
    host = _Host()
    state = SimpleNamespace(connection_id="connection-a")
    assert host._connection_is_current_owner(state, "sid") is True
    assert host._connection_is_explicit_owner(state, "sid") is False
    assert host._connection_is_live("connection-a") is False

    host._session_current_owner = {"sid": "connection-a"}
    assert host._connection_is_current_owner(state, "sid") is True
    assert host._connection_is_current_owner(SimpleNamespace(connection_id="b"), "sid") is False
    assert host._connection_is_explicit_owner(state, "sid") is True
    assert host._connection_is_explicit_owner(SimpleNamespace(connection_id="b"), "sid") is False

    host._runtime_owner_path = lambda _sid: (_ for _ in ()).throw(OSError("owner path"))
    host._runtime_alive = lambda _record: (_ for _ in ()).throw(RuntimeError("probe"))
    host.session_runtimes = {"sid": {"process": object()}}
    assert host._runtime_spawn_in_flight("sid") is False
    host.session_runtimes = {}
    assert host._runtime_spawn_in_flight("sid") is False

    assert host._connection_should_teardown(SimpleNamespace(connection_id="b"), "sid") is False


def test_ownership_report_handles_local_runtime_and_stale_foreign_leases(tmp_path, monkeypatch):
    host = _Host()
    process = SimpleNamespace(pid=4321)
    host.session_runtimes = {"sid": {"process": process}}
    host._runtime_alive = lambda _record: True
    local = host._session_ownership_report("sid")
    assert local["locked"] is True
    assert local["holder"] == "this-host-runtime"
    assert local["idat_pid"] == 4321

    lease_path = tmp_path / "sid.lease"
    lease_path.write_text(
        json.dumps({"owner_id": "foreign", "owner_pid": 123, "pid": 456, "updated_at": "bad"}),
        encoding="utf-8",
    )
    host.session_runtimes = {}
    host._runtime_lease_path = lambda _sid: str(lease_path)
    host._lease_has_live_foreign_owner = lambda _lease: False
    monkeypatch.setattr(state_mod.os, "kill", lambda *_args: (_ for _ in ()).throw(ProcessLookupError()))
    stale = host._session_ownership_report("sid")
    assert stale["locked"] is False
    assert stale["owner_alive"] is False
    assert stale["lease_updated_at"] == "bad"

    monkeypatch.setattr(state_mod.os, "kill", lambda *_args: (_ for _ in ()).throw(OSError("permission")))
    unknown = host._session_ownership_report("sid")
    assert unknown["owner_alive"] is None

    lease_path.write_text("not-json", encoding="utf-8")
    assert host._session_ownership_report("sid")["locked"] is False


def test_ownership_guard_reports_foreign_lease_details_and_missing_identity():
    host = _Host()
    missing = host._ensure_client_owns_session(SimpleNamespace())
    assert missing["code"] == MCPError.SESSION_NOT_FOUND

    host._session_ownership_report = lambda _sid: {
        "locked": True,
        "holder": "foreign-lease",
        "owner_pid": 12,
        "owner_id": "host-b",
        "idat_pid": 34,
        "lease_age_seconds": 4.5,
        "owner_alive": True,
        "lease_updated_at": 1,
    }
    denied = host._ensure_client_owns_session(SimpleNamespace(session_id="sid"))
    assert denied["code"] == MCPError.FILE_LOCKED
    assert "host-b" in denied["hint"]
    assert "idat pid 34" in denied["hint"]


def test_sso_logout_and_binding_fail_closed_for_invalid_or_expired_entries():
    host = _Host()
    assert host._sso_agent_logout()[1]["code"] == MCPError.INVALID_ARGS
    host._begin_client_connection()
    assert host._sso_agent_logout("worker")[1]["code"] == MCPError.POLICY_DENIED
    assert host._bind_agent_call(None) is None
    assert host._bind_agent_call("   ") is None

    state = host._client_request_state()
    state.connection_id = "connection-a"
    realm = host._sso_realm()
    realm.update(active=True, agents={"worker"}, logged_in={"worker": {"conn_id": "connection-a", "exp": "bad"}})
    assert host._bind_agent_call("worker")["code"] == MCPError.POLICY_DENIED
    realm["logged_in"]["worker"]["exp"] = float("inf")
    assert host._bind_agent_call("worker")["code"] == MCPError.POLICY_DENIED
    realm["logged_in"]["worker"]["exp"] = 1
    assert host._bind_agent_call("worker")["code"] == MCPError.POLICY_DENIED


def test_agent_scope_filter_handles_empty_exact_and_all_scopes():
    host = _Host()
    host._begin_client_connection()
    state = host._client_request_state()
    state.active_agent = "worker"
    realm = host._sso_realm()
    realm.update(active=True, agents={"worker"}, logged_in={"worker": {"conn_id": state.connection_id, "exp": 0, "scopes": None}})
    assert host._agent_scope_error("session", "agent_logout") is None
    denied = host._agent_scope_error("search", "find")
    assert denied["code"] == MCPError.POLICY_DENIED
    realm["logged_in"]["worker"]["scopes"] = ["search:find"]
    assert host._agent_scope_error("search", "find") is None
    realm["logged_in"]["worker"]["scopes"] = ["all"]
    assert host._agent_scope_error("modify", "write") is None


def test_client_state_deep_edges_99(tmp_path, monkeypatch):
    import base64
    import hashlib
    import hmac
    import os
    import time

    host = _Host()
    token = host._begin_client_connection()
    state = host._client_request_state()

    # 281: current_session setter when active_agent is set and value is None
    state.active_agent = "worker"
    state.current_session_by_agent["worker"] = SimpleNamespace(session_id="S1")
    host.current_session = None
    assert "worker" not in state.current_session_by_agent

    # 355: _connection_is_live
    host._live_connections = {"c1", "c2"}
    assert host._connection_is_live("c1") is True
    assert host._connection_is_live("c99") is False

    # 376: _runtime_spawn_in_flight when _runtime_owner_path is not callable
    host._runtime_owner_path = None
    assert host._runtime_spawn_in_flight("s1") is False

    # 410, 413: _session_has_live_owner_connection
    host._session_current_owner = None
    assert host._session_has_live_owner_connection(state, "s1") is False
    host._session_current_owner = {"s1": state.connection_id}
    assert host._session_has_live_owner_connection(state, "s1") is False

    # 503: _session_ownership_report with live owner_pid
    lease_path = tmp_path / "live_pid.lease"
    lease_path.write_text(
        json.dumps({"owner_id": "other", "owner_pid": os.getpid(), "pid": 999, "updated_at": 123}),
        encoding="utf-8",
    )
    host.session_runtimes = {}
    host._runtime_lease_path = lambda _sid: str(lease_path)
    host._lease_has_live_foreign_owner = lambda _lease: False
    rep = host._session_ownership_report("live_pid")
    assert rep["owner_alive"] is True

    # 617: _ensure_client_owns_session when active_agent is set
    state.active_agent = "worker"
    host._session_ownership_report = lambda _sid: {"locked": False}
    sess = SimpleNamespace(session_id="ADOPT01")
    res = host._ensure_client_owns_session(sess)
    assert res is None
    assert "ADOPT01" in state.owned_sessions_by_agent["worker"]

    # 637: _pending_tool_args getter
    assert host._pending_tool_args == {}

    # 692: sso_activate with invalid agent name
    _, err = host._sso_activate_realm(["bad:name"])
    assert err["code"] == MCPError.INVALID_ARGS

    # 709, 737: sso_activate auto-generating secret
    monkeypatch.delenv("IDA_MCP_SSO_SECRET", raising=False)
    host._sso_realm_store = None
    ok_res, _ = host._sso_activate_realm(["agent_auto"])
    assert ok_res["ok"] is True
    assert "secret" in ok_res["sso"]
    sec = ok_res["sso"]["secret"]

    # 761, 766, 772: _sso_agent_login validation errors
    assert host._sso_agent_login("", "t")[1]["code"] == MCPError.INVALID_ARGS
    assert host._sso_agent_login("agent_auto", "malformed")[1]["code"] == MCPError.POLICY_DENIED
    assert host._sso_agent_login("agent_auto", "wrong.body.sig")[1]["code"] == MCPError.POLICY_DENIED

    # helper to make valid/custom tickets
    def make_ticket(agent, body_bytes):
        body_b64 = base64.urlsafe_b64encode(body_bytes).decode("ascii").rstrip("=")
        sig = hmac.new(sec.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        return f"{agent}.{body_b64}.{sig}"

    # 794-795: invalid ticket payload (not valid json)
    bad_json_ticket = make_ticket("agent_auto", b"not-json-data")
    assert host._sso_agent_login("agent_auto", bad_json_ticket)[1]["code"] == MCPError.POLICY_DENIED

    # 797: payload name mismatch
    mismatch_ticket = make_ticket("agent_auto", json.dumps({"name": "other_agent"}).encode("utf-8"))
    assert host._sso_agent_login("agent_auto", mismatch_ticket)[1]["code"] == MCPError.POLICY_DENIED

    # 807: exp is not finite
    nan_ticket = make_ticket("agent_auto", json.dumps({"name": "agent_auto", "exp": float("nan")}).encode("utf-8"))
    assert host._sso_agent_login("agent_auto", nan_ticket)[1]["code"] == MCPError.POLICY_DENIED

    # 814: scopes is None in ticket -> defaults to ["all"]
    valid_payload = {"name": "agent_auto", "exp": time.time() + 3600, "scopes": None}
    valid_ticket = make_ticket("agent_auto", json.dumps(valid_payload).encode("utf-8"))
    login_res, _ = host._sso_agent_login("agent_auto", valid_ticket)
    assert login_res["ok"] is True
    assert login_res["scopes"] == ["all"]

    # 829: already logged in on another connection
    realm = host._sso_realm()
    realm["logged_in"]["agent_auto"]["conn_id"] = "different-conn"
    already_err = host._sso_agent_login("agent_auto", valid_ticket)[1]
    assert already_err["code"] == MCPError.POLICY_DENIED

    # 1020-1028: _call_as_agent
    assert host._call_as_agent(None, lambda: "direct") == "direct"
    assert host._call_as_agent("not_an_agent", lambda: "direct")["code"] == MCPError.POLICY_DENIED
    realm["logged_in"]["agent_auto"]["conn_id"] = state.connection_id
    state.agents_logged_in.add("agent_auto")
    ran = host._call_as_agent("agent_auto", lambda: "from_agent")
    assert ran == "from_agent"
    assert state.active_agent is None

    host._end_client_connection(token)
