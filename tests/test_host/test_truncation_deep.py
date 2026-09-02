from __future__ import annotations

import pytest

from ida_pro_mcp.host.stores.truncation import (
    continue_truncated,
    search_truncated,
    truncate_response,
)


def test_truncate_response_list_and_continuation() -> None:
    # Build large list
    large_list = [f"item_{i:04d}" for i in range(500)]
    resp = {"items": large_list, "status": "ok"}

    truncated = truncate_response(resp, max_tokens=600)
    assert "_continue" in truncated
    token_info = truncated["_continue"]
    assert "token" in token_info
    assert "fields" in token_info
    assert "items" in token_info["fields"]
    assert len(truncated["items"]) < 500

    # Continue truncation
    tok = token_info["token"]
    res = continue_truncated(token=tok, field="items", offset=10, count=20)
    assert "items" in res
    assert len(res["items"]) == 20
    assert res["items"][0] == "item_0010"


def test_truncate_response_string_and_search() -> None:
    # Build large text
    large_text = "start of text " + ("middle payload " * 1000) + "TARGET_KEYWORD end of text"
    resp = {"code": large_text}

    truncated = truncate_response(resp, max_tokens=600)
    assert "_continue" in truncated
    token = truncated["_continue"]["token"]

    # Search in truncated text
    search_res = search_truncated(token=token, pattern="TARGET_KEYWORD")
    assert search_res["match_count"] >= 1
    assert "matches" in search_res

    # Empty pattern error handling
    bad_pattern = search_truncated(token=token, pattern="")
    assert bad_pattern.get("error") is True


def test_truncation_session_and_owner_isolation() -> None:
    resp = {"data": "A" * 5000}
    truncated = truncate_response(resp, max_tokens=500, session_id="sess_alpha", owner_id="user_alice")
    token = truncated["_continue"]["token"]

    # Accessing with matching session and owner succeeds
    res_ok = continue_truncated(token=token, field="data", session_id="sess_alpha", owner_id="user_alice")
    assert "text" in res_ok

    # Accessing with mismatched session fails
    res_wrong_sess = continue_truncated(token=token, field="data", session_id="sess_beta", owner_id="user_alice")
    assert res_wrong_sess.get("error") is True

    # Accessing with mismatched owner fails
    res_wrong_owner = continue_truncated(token=token, field="data", session_id="sess_alpha", owner_id="user_bob")
    assert res_wrong_owner.get("error") is True
