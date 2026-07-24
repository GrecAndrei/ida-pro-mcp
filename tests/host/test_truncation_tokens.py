from __future__ import annotations

from ida_pro_mcp.host.stores.truncation import (
    _TRUNCATION_ORDER,
    _TRUNCATION_STORE,
    _get_entry,
    _store_truncation,
    continue_truncated,
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
