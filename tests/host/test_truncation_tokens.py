from __future__ import annotations

import time

from ida_pro_mcp.host.stores.truncation import (
    _TOKEN_TTL_SEC,
    _TRUNCATION_ORDER,
    _TRUNCATION_STORE,
    _get_entry,
    _prune_expired,
    _store_truncation,
    continue_truncated,
    peek_truncated,
    truncate_response,
)


def setup_function():
    _TRUNCATION_STORE.clear()
    _TRUNCATION_ORDER.clear()


def teardown_function():
    _TRUNCATION_STORE.clear()
    _TRUNCATION_ORDER.clear()


def test_truncation_tokens_are_unique_and_urlsafe():
    tokens = {
        _store_truncation(
            {"items": [index]},
            {"items": {"type": "list", "total": 1, "chunk_size": 1, "next_offset": 1}},
            session_id="sess-a",
        )
        for index in range(25)
    }

    assert len(tokens) == 25
    for token in tokens:
        assert len(token) >= 16
        assert " " not in token


def test_truncation_token_stores_session_scope():
    token = _store_truncation(
        {"data": list(range(10))},
        {"data": {"type": "list", "total": 10, "chunk_size": 3, "next_offset": 3}},
        session_id="owned-session",
    )

    assert _get_entry(token, session_id="owned-session") is not None
    assert _get_entry(token, session_id="other-session") is None
    assert _get_entry(token, session_id="") is None


def test_truncation_token_requires_matching_owner_id():
    token = _store_truncation(
        {"data": [1, 2, 3]},
        {"data": {"type": "list", "total": 3, "chunk_size": 2, "next_offset": 2}},
        session_id="sess-a",
        owner_id="client-a",
    )

    assert _get_entry(token, session_id="sess-a", owner_id="client-a") is not None
    assert _get_entry(token, session_id="sess-a", owner_id="client-b") is None
    assert _get_entry(token, session_id="sess-a", owner_id="") is None
    assert continue_truncated(token, session_id="sess-a", owner_id="client-b").get("error")


def test_truncate_response_binds_continue_token_to_session_and_owner():
    payload = {"items": [{"id": index, "value": "x" * 200} for index in range(40)]}
    result = truncate_response(
        payload,
        max_tokens=500,
        session_id="session-42",
        owner_id="owner-42",
    )

    assert result.get("_truncated") is True
    token = result["_continue"]["token"]
    assert continue_truncated(token, session_id="session-42", owner_id="owner-42").get("ok") is True
    assert continue_truncated(token, session_id="session-42", owner_id="owner-99").get("error")
    assert continue_truncated(token, session_id="session-99", owner_id="owner-42").get("error")


def test_sliding_window_ttl_extends_on_access():
    token = _store_truncation(
        {"items": list(range(20))},
        {"items": {"type": "list", "total": 20, "chunk_size": 5, "next_offset": 5}},
    )
    entry = _TRUNCATION_STORE[token]

    # Advance time artificially past the TTL from creation, but simulate an access
    entry["created_at"] = time.time() - (_TOKEN_TTL_SEC + 50)
    # Token was accessed 10 seconds ago
    entry["last_accessed"] = time.time() - 10

    _prune_expired()
    # Token must NOT be pruned because last_accessed is fresh
    assert token in _TRUNCATION_STORE

    # Accessing via continue_truncated refreshes last_accessed
    res = continue_truncated(token, count=2)
    assert res.get("ok") is True
    assert _TRUNCATION_STORE[token]["last_accessed"] > entry["created_at"]

    # Peek shows positive ttl_remaining_sec based on sliding window
    peek_res = peek_truncated(token)
    assert peek_res.get("ok") is True
    assert peek_res["ttl_remaining_sec"] > 0


def test_continuation_has_more_and_done_flags():
    token = _store_truncation(
        {"items": [1, 2, 3, 4, 5]},
        {"items": {"type": "list", "total": 5, "chunk_size": 2, "next_offset": 0}},
    )

    # First page
    page1 = continue_truncated(token, count=2)
    assert page1.get("ok") is True
    assert page1["items"] == [1, 2]
    assert page1["has_more"] is True
    assert page1["done"] is False

    # Second page
    page2 = continue_truncated(token, count=2)
    assert page2.get("ok") is True
    assert page2["items"] == [3, 4]
    assert page2["has_more"] is True
    assert page2["done"] is False

    # Final page
    page3 = continue_truncated(token, count=2)
    assert page3.get("ok") is True
    assert page3["items"] == [5]
    assert page3["has_more"] is False
    assert page3["done"] is True


def test_lru_eviction_keeps_recently_accessed_tokens():
    from ida_pro_mcp.host.stores import truncation as T
    orig_cap = T._MAX_TRUNCATION_STORE
    try:
        T._MAX_TRUNCATION_STORE = 5
        tokens = []
        for i in range(5):
            t = _store_truncation(
                {"i": i},
                {"i": {"type": "list", "total": 1, "chunk_size": 1, "next_offset": 1}},
            )
            tokens.append(t)

        # Access token 0 to move it to the most-recently-used position
        assert _get_entry(tokens[0]) is not None

        # Add another token, triggering capacity overflow (limit is 5)
        new_token = _store_truncation(
            {"i": 99},
            {"i": {"type": "list", "total": 1, "chunk_size": 1, "next_offset": 1}},
        )

        # Token 0 was accessed, so token 1 (least recently used) should be evicted instead
        assert _get_entry(tokens[0]) is not None
        assert _get_entry(tokens[1]) is None
        assert _get_entry(new_token) is not None
    finally:
        T._MAX_TRUNCATION_STORE = orig_cap


class _FakeSession:
    def __init__(self, sid, path):
        self.session_id = sid
        self.idb_path = path


class _DispatchHarness:
    from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin
    # Mixin dispatch method into harness
    _handle_truncation = ServerDispatchMixin._handle_truncation

    def __init__(self, active_sid="session_active", owner="owner_conn:agent1"):
        self.current_session = _FakeSession(active_sid, f"/tmp/{active_sid}.idb")
        self._owner = owner

    def _truncation_owner_id(self):
        return self._owner

    def _resolve_session_from_idb_ref(self, ref):
        if ref == "sess_target":
            return _FakeSession("sess_target", "/tmp/target.idb")
        if ref == "session_1":
            return _FakeSession("session_1", "/tmp/session_1.idb")
        return None

    def _client_owns_session(self, sid):
        return True


def test_handle_truncation_unscoped_token_with_active_session():
    # Token minted unscoped (no session, no owner)
    token = _store_truncation(
        {"results": ["a", "b", "c", "d"]},
        {"results": {"type": "list", "total": 4, "chunk_size": 2, "next_offset": 0}},
    )

    harness = _DispatchHarness(active_sid="session_active", owner="conn_1")
    # Caller calls continue without idb while an active session exists
    res = harness._handle_truncation({"action": "continue", "token": token})
    assert res.get("ok") is True
    assert res["items"] == ["a", "b"]


def test_handle_truncation_cross_session_without_explicit_idb():
    # Token minted in session_1
    token = _store_truncation(
        {"items": [10, 20, 30, 40]},
        {"items": {"type": "list", "total": 4, "chunk_size": 2, "next_offset": 0}},
        session_id="session_1",
        owner_id="conn_1",
    )

    # Active session is session_2 (session switched)
    harness = _DispatchHarness(active_sid="session_2", owner="conn_1")
    # Calling continue without idb must resolve to session_1 where token was minted
    res = harness._handle_truncation({"action": "continue", "token": token})
    assert res.get("ok") is True
    assert res["items"] == [10, 20]


def test_handle_truncation_pattern_search_and_summary():
    token = _store_truncation(
        {"code": "void main() { int secret = 42; return secret; }"},
        {"code": {"type": "string", "total": 48, "chunk_size": 15, "next_offset": 0}},
        session_id="session_1",
        owner_id="conn_1",
    )

    harness = _DispatchHarness(active_sid="session_1", owner="conn_1")

    # In-flight pattern search via action="continue"
    search_res = harness._handle_truncation({
        "action": "continue",
        "token": token,
        "pattern": "secret",
    })
    assert search_res.get("ok") is True
    assert search_res["match_count"] >= 1

    # Structural summary via action="continue" with summary=True
    summary_res = harness._handle_truncation({
        "action": "continue",
        "token": token,
        "summary": True,
    })
    assert summary_res.get("ok") is True
    assert summary_res["type"] == "string"
    assert summary_res["total_chars"] == 47

    # Metadata peek via action="continue" with peek=True
    peek_res = harness._handle_truncation({
        "action": "continue",
        "token": token,
        "peek": True,
    })
    assert peek_res.get("ok") is True
    assert "code" in peek_res["fields"]
