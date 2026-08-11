"""Regression tests for g01_session_bootstrap audit findings.

Covers the fixes applied to ``server_session_bootstrap.py`` (the hidden
orchestrator-only ``bootstrap_*`` dispatch):
- Mutating bootstrap branches (ingest_outcome, prune_data, run_tournament,
  simulate_batch, ...) resolve the target through ``_require_session_sid`` and
  gate it with ``_require_owned_session_id``, so a multiplexed connection can
  never mutate another client's live session (FILE_LOCKED envelope). Read-only
  branches (status/summary/list_*/history/...) only resolve the sid.
- Every ``self.session_mgr.bootstrap_*`` call is routed through
  ``_bootstrap_mgr_call``, so a missing/renamed manager method surfaces a
  classifiable NOT_IMPLEMENTED envelope instead of an AttributeError.
- Argument validation is strict: ``observed`` must be exactly 0 or 1 (no more
  silent ``int()`` truncation of floats), and ``predicted`` must be inside
  [0.0, 1.0] (no more silent manager clamping).
- Dispatch bounds match the manager clamps: run_tournament rounds <= 5000,
  simulate_batch n <= 20000.
- The vestigial ``sid_arg: Callable`` injection parameter is gone; the module
  no longer imports ``Callable``; the docstring documents the hidden
  orchestrator-only contract.

NOTE: the tests call ``server._handle_session_bootstrap(action, args)``
directly (the new two-argument signature). The raw-dispatch caller in
server_session.py is updated by Integrate; exercising the mixin method directly
keeps this suite independent of that cross-file change.
"""

from __future__ import annotations

import inspect

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_session_bootstrap import (
    ServerSessionBootstrapMixin,
)


class _FakeIdaProcess:
    """A fake idat subprocess that is always alive but cannot be killed."""

    pid = 2147483647

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 1


def _make_server(tmp_path, monkeypatch) -> IDAMCPServer:
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    # Blocking create must not attempt a real idat launch in a unit test.
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    return server


def _open(server: IDAMCPServer, binary_path: str) -> dict:
    """Open a session directly through the create action (records ownership)."""
    return server._session_action_create({"binary_path": binary_path})


def _open_two_isolated_clients(tmp_path, monkeypatch):
    """Return (server, token_b, sid_a, sid_b) with sid_a a live foreign (busy)
    session for the second connection, and sid_b owned by the second
    connection."""
    server = _make_server(tmp_path, monkeypatch)
    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    token_a = server._begin_client_connection()
    try:
        opened_a = _open(server, str(binary_a))
        sid_a = opened_a["session_id"]
    finally:
        # Drop A's connection state (keeps the session row and lets us mark it
        # busy) so B does not inherit ownership.
        server._client_request_state_var.reset(token_a)
    # A's session is actively running: it must stay protected from B.
    server.session_runtimes[sid_a] = {"process": _FakeIdaProcess()}

    token_b = server._begin_client_connection()
    try:
        opened_b = _open(server, str(binary_b))
        sid_b = opened_b["session_id"]
        return server, token_b, sid_a, sid_b
    except Exception:
        server._end_client_connection(token_b)
        server.shutdown()
        raise


# ---------------------------------------------------------------------------
# Ownership guard on mutating bootstrap branches
# ---------------------------------------------------------------------------


def test_peer_mutating_bootstrap_returns_file_locked(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        ingest = server._handle_session_bootstrap(
            "bootstrap_ingest_outcome",
            {"session_id": sid_a, "predicted": 0.5, "observed": 1},
        )
        assert ingest.get("error") is True
        assert ingest.get("code") == MCPError.FILE_LOCKED

        prune = server._handle_session_bootstrap(
            "bootstrap_prune_data", {"session_id": sid_a}
        )
        assert prune.get("error") is True
        assert prune.get("code") == MCPError.FILE_LOCKED
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_owned_mutating_bootstrap_succeeds(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        ingest = server._handle_session_bootstrap(
            "bootstrap_ingest_outcome",
            {"session_id": sid_b, "predicted": 0.5, "observed": 1},
        )
        assert ingest.get("ok") is True
        assert ingest["observed"] == 1
        assert ingest["predicted"] == 0.5
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_unknown_session_mutating_bootstrap_returns_not_found(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        res = server._handle_session_bootstrap(
            "bootstrap_ingest_outcome",
            {"session_id": "ZZZZZZZZ", "predicted": 0.5, "observed": 1},
        )
        assert res.get("error") is True
        assert res.get("code") == MCPError.SESSION_NOT_FOUND
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_read_only_bootstrap_needs_no_ownership_guard(tmp_path, monkeypatch):
    """status against a live foreign session must not be ownership-rejected."""
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        status = server._handle_session_bootstrap(
            "bootstrap_status", {"session_id": sid_a}
        )
        assert status.get("error") is not True
        assert status.get("ok") is True
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


# ---------------------------------------------------------------------------
# NOT_IMPLEMENTED fallback for missing/renamed manager methods
# ---------------------------------------------------------------------------


def test_missing_manager_method_returns_not_implemented(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        # Simulate a manager method that was removed/renamed in this build.
        monkeypatch.setattr(server.session_mgr, "bootstrap_ingest_outcome", None)
        res = server._handle_session_bootstrap(
            "bootstrap_ingest_outcome",
            {"session_id": sid_b, "predicted": 0.5, "observed": 1},
        )
        assert res.get("error") is True
        assert res.get("code") == MCPError.NOT_IMPLEMENTED
        assert "bootstrap_ingest_outcome" in res.get("message", "")
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_unknown_bootstrap_action_falls_through_to_none(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        res = server._handle_session_bootstrap(
            "bootstrap_no_such_action", {"session_id": sid_b}
        )
        assert res is None
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


# ---------------------------------------------------------------------------
# Strict argument validation (no silent coercion)
# ---------------------------------------------------------------------------


def test_observed_must_be_integer_01(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        for bad in (0.9, 2, -1, True):
            res = server._handle_session_bootstrap(
                "bootstrap_ingest_outcome",
                {"session_id": sid_b, "predicted": 0.5, "observed": bad},
            )
            assert res.get("error") is True
            assert res.get("code") == MCPError.INVALID_ARGS
            assert "observed must be an integer 0/1" in res.get("message", "")

        # resolve_dispute applies the same strict check.
        res = server._handle_session_bootstrap(
            "bootstrap_resolve_dispute",
            {"session_id": sid_b, "dispute_id": "disp_x", "observed": 0.9},
        )
        assert res.get("error") is True
        assert res.get("code") == MCPError.INVALID_ARGS
        assert "observed must be an integer 0/1" in res.get("message", "")
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_predicted_out_of_range_rejected(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        res = server._handle_session_bootstrap(
            "bootstrap_ingest_outcome",
            {"session_id": sid_b, "predicted": 1.5, "observed": 1},
        )
        assert res.get("error") is True
        assert res.get("code") == MCPError.INVALID_ARGS
        assert "predicted must be between 0.0 and 1.0" in res.get("message", "")

        res = server._handle_session_bootstrap(
            "bootstrap_open_dispute",
            {"session_id": sid_b, "claim_id": "c1", "reason": "r", "predicted": -0.1},
        )
        assert res.get("error") is True
        assert res.get("code") == MCPError.INVALID_ARGS
        assert "predicted must be between 0.0 and 1.0" in res.get("message", "")
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


# ---------------------------------------------------------------------------
# Dispatch bounds match the manager clamps
# ---------------------------------------------------------------------------


def test_run_tournament_rounds_clamped_to_5000(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        server._handle_session_bootstrap("bootstrap_init", {"session_id": sid_b})
        res = server._handle_session_bootstrap(
            "bootstrap_run_tournament",
            {"session_id": sid_b, "rounds": 50000},
        )
        assert res.get("ok") is True
        assert res["rounds"] == 5000
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_simulate_batch_n_clamped_to_20000(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        res = server._handle_session_bootstrap(
            "bootstrap_simulate_batch",
            {"session_id": sid_b, "n": 200000},
        )
        assert res.get("ok") is True
        assert res["n"] == 20000
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


# ---------------------------------------------------------------------------
# session_id resolution
# ---------------------------------------------------------------------------


def test_session_id_required_when_no_target(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    saved_current = server.current_session
    try:
        # With no session_id and no current session there is no resolvable
        # target, so the resolve must fail with INVALID_ARGS 'session_id
        # required' rather than guessing. (With a current session set, empty
        # args correctly fall back to it — that path is covered elsewhere.)
        server.current_session = None
        res = server._handle_session_bootstrap("bootstrap_status", {})
        assert res.get("error") is True
        assert res.get("code") == MCPError.INVALID_ARGS
        assert "session_id required" in res.get("message", "")
    finally:
        server.current_session = saved_current
        server._end_client_connection(token_b)
        server.shutdown()


# ---------------------------------------------------------------------------
# Dead code removed + hidden contract documented
# ---------------------------------------------------------------------------


def test_sid_arg_parameter_and_callable_import_removed():
    import ida_pro_mcp.host.server.server_session_bootstrap as mod

    sig = inspect.signature(ServerSessionBootstrapMixin._handle_session_bootstrap)
    assert "sid_arg" not in sig.parameters
    assert list(sig.parameters) == ["self", "action", "args"]
    # The vestigial Callable import must be gone from the module namespace.
    assert not hasattr(mod, "Callable")


def test_module_docstring_documents_hidden_orchestrator_contract():
    import ida_pro_mcp.host.server.server_session_bootstrap as mod

    doc = (mod.__doc__ or "").lower()
    assert "orchestrator" in doc
    assert "not advertised" in doc
    assert "raw dispatch" in doc
