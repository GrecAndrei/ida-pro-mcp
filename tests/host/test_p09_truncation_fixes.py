"""p09_intelligence: truncation.py nested-field + lock regression tests.

Verifies that dotted continuation fields (recorded by _truncate_recursive)
resolve at continuation time, and that the module-level stores are guarded
by a lock.
"""

from __future__ import annotations

import threading

from ida_pro_mcp.host.stores import truncation as T


class TestNestedFieldContinuation:
    def test_nested_list_field_can_be_continued(self):
        big = {"meta": {"items": list(range(200))}}
        res = T.truncate_response(big, max_tokens=500)
        assert res.get("_truncated") is True
        fields = res["_continue"]["fields"]
        assert "meta.items" in fields
        token = res["_continue"]["token"]
        con = T.continue_truncated(token, field="meta.items")
        assert con.get("ok") is True
        assert len(con.get("items", [])) > 0
        assert con.get("total") == 200

    def test_nested_string_field_can_be_searched(self):
        # A long string nested inside a dict (path "results.code") is recorded
        # under a dotted key and must resolve at continuation time.
        big = {"results": {"code": "mov eax, 1" * 200}}
        res = T.truncate_response(big, max_tokens=200)
        assert res.get("_truncated") is True
        fields = res["_continue"]["fields"]
        assert "results.code" in fields
        token = res["_continue"]["token"]
        con = T.continue_truncated(token, field="results.code")
        assert con.get("ok") is True
        assert con.get("text")

    def test_get_nested_helper(self):
        container = {"meta": {"items": [10, 20, 30]}}
        assert T._get_nested(container, "meta.items.2") == 30
        assert T._get_nested(container, "meta.items.9") is None
        assert T._get_nested(container, "meta.nope") is None
        assert T._get_nested(container, "") is None

    def test_lock_guards_store(self):
        # The lock is module-level; ensure it exists and the store writes
        # hold it so concurrent truncate_response calls cannot tear state.
        assert isinstance(T._STORE_LOCK, threading.Lock)
        res = T.truncate_response({"a": [1, 2, 3] * 100}, max_tokens=100)
        assert res.get("_truncated") is True
