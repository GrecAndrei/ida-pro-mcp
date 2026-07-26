"""Unit tests for the post-processing helpers used by tool dispatch.

These cover the real ``extract_post_process_params``, ``has_post_process``,
``apply_post_processing``, ``_handle_next_continuation`` and
``_cache_post_process_next``, wired together by ``_Harness._simulated_dispatch``.

That harness is a stand-in for the ordering production uses, not the
production path: ``ServerDispatchMixin._execute_tool_inner`` is ~350 lines
with policy, ownership, truncation and RPC stages, and is NOT exercised
here. Do not read a pass as cover for the dispatch pipeline itself.
"""

from __future__ import annotations

import importlib
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
assert str(SRC) in sys.path or sys.path.insert(0, str(SRC)) is None

importlib.import_module("ida_pro_mcp.host")

from ida_pro_mcp.host.errors import MCPError, is_error_result, make_error  # noqa: E402
from ida_pro_mcp.host.server.postprocess import PP_KEYS, extract_post_process_params  # noqa: E402
from ida_pro_mcp.host.server.server_args import ServerArgsMixin  # noqa: E402
from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin  # noqa: E402


class _Session:
    """Minimal session mock."""
    idb_path = "/tmp/test.idb"
    session_id = "test-session"


class _Harness(ServerArgsMixin, ServerDispatchMixin):
    """Minimal object exposing dispatch + postprocess methods."""

    def __init__(self):
        self._next_cache = {}
        self._next_cache_ttl_seconds = 1800
        self._pending_pp = {}
        self.current_session = _Session()

    def call_tool(self, tool_name, idb_path, **kwargs):
        """Mock call_tool that returns a fresh copy of the canned payload."""
        import copy
        return copy.deepcopy(self._source_payload)

    def _simulated_dispatch(self, tool_name, original_tool_name, args):
        """Reproduce only the PP ordering of production dispatch.

        Deliberately not named _execute_tool_inner: overriding the production
        name made these read as tests of the real dispatcher.
        """
        from ida_pro_mcp.host.server.postprocess import apply_post_processing, has_post_process

        args = self._normalize_tool_call_args(tool_name, args)
        tool_args, self._pending_pp = extract_post_process_params(args)

        next_token = self._pending_pp.get("next_token")
        if next_token and isinstance(next_token, str) and next_token.strip():
            return self._handle_next_continuation(
                tool_name, next_token.strip(), self._pending_pp
            )

        # Simulate tool execution with stripped args
        result = self.call_tool(tool_name, "/tmp/test.idb", **tool_args)

        # Apply PP
        if self._pending_pp and has_post_process(self._pending_pp) and not is_error_result(result):
            result = apply_post_processing(result, self._pending_pp)
            result = self._cache_post_process_next(tool_name, tool_args, self._pending_pp, result)

        return result


def _make(source_payload, tool="search"):
    h = _Harness()
    h._source_payload = source_payload
    h._tool = tool
    return h


def _search_payload(n=10):
    return {
        "ok": True, "action": "find",
        "matches": [
            {"addr": 0x1000 + i, "name": f"sub_{i}", "tag": "crypto" if i % 2 == 0 else "net"}
            for i in range(n)
        ],
        "count": n, "total": n,
    }


# ---------------------------------------------------------------------------
# TestPPExtraction
# ---------------------------------------------------------------------------

class TestPPExtraction:
    def test_pp_keys_extracted_from_args(self):
        args = {"action": "find", "pattern": "recv", "grep": "memcpy", "limit": 5}
        tool_args, pp = extract_post_process_params(args)
        assert tool_args == {"action": "find", "pattern": "recv"}
        assert pp == {"grep": "memcpy", "limit": 5}

    def test_no_pp_keys_passthrough(self):
        args = {"action": "list", "count": 10}
        tool_args, pp = extract_post_process_params(args)
        assert tool_args == args
        assert pp == {}

    def test_all_pp_keys_recognized(self):
        args = dict.fromkeys(PP_KEYS, "x")
        args["action"] = "find"
        tool_args, pp = extract_post_process_params(args)
        assert "action" in tool_args
        assert all(k in pp for k in PP_KEYS)

    def test_pp_keys_not_sent_to_ida(self):
        """PP keys should be stripped before reaching call_tool."""
        h = _make(_search_payload(5))
        captured = {}

        def capture_call(tool_name, idb_path, **kwargs):
            captured.update(kwargs)
            return h._source_payload

        h.call_tool = capture_call
        h._simulated_dispatch("search", "search", {"action": "find", "pattern": "recv", "grep": "memcpy", "limit": 3})
        assert "grep" not in captured
        assert "limit" not in captured


# ---------------------------------------------------------------------------
# TestDispatchIntegration
# ---------------------------------------------------------------------------

class TestDispatchIntegration:
    def test_grep_filters_results(self):
        h = _make(_search_payload(10))
        result = h._simulated_dispatch("search", "search", {
            "action": "find", "grep": "crypto"
        })
        assert result["_count"] == 5
        assert result["_post_processed"] is True

    def test_head_slices_results(self):
        h = _make(_search_payload(10))
        result = h._simulated_dispatch("search", "search", {
            "action": "find", "head": 3
        })
        assert result["_count"] == 3

    def test_limit_with_continuation(self):
        h = _make(_search_payload(10))
        result = h._simulated_dispatch("search", "search", {
            "action": "find", "limit": 3
        })
        assert result["_count"] == 3
        assert "next_token" in result

    def test_next_token_continuation(self):
        h = _make(_search_payload(10))
        first = h._simulated_dispatch("search", "search", {
            "action": "find", "limit": 3
        })
        token = first["next_token"]
        assert token

        h._source_payload = _search_payload(10)
        # Simulate what real dispatch does: extract PP params first,
        # then call _handle_next_continuation with just the PP params.
        pp = {"next_token": token}
        second = h._handle_next_continuation("search", token, pp)
        assert second["ok"] is True
        assert second["continued_from"] == token

    def test_pick_projects_fields(self):
        h = _make(_search_payload(5))
        result = h._simulated_dispatch("search", "search", {
            "action": "find", "pick": ["ok", "matches"]
        })
        assert "ok" in result
        assert "matches" in result
        assert "count" not in result

    def test_grep_with_field(self):
        payload = {
            "ok": True, "action": "list",
            "functions": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
            "strings": ["x", "y"],
        }
        h = _make(payload)
        result = h._simulated_dispatch("data", "data", {
            "action": "functions", "grep": "a", "field": "functions"
        })
        assert result["_count"] == 1
        assert result["_field"] == "functions"

    def test_error_result_not_post_processed(self):
        h = _make(make_error(MCPError.NOT_FOUND, "not found"))
        result = h._simulated_dispatch("search", "search", {
            "action": "find", "grep": "x"
        })
        # Error results pass through without PP metadata
        assert "_post_processed" not in result


# ---------------------------------------------------------------------------
# TestCachePostProcessNext
# ---------------------------------------------------------------------------

class TestCachePostProcessNext:
    def test_caches_when_limit_set(self):
        h = _Harness()
        result = {"ok": True, "_count": 3, "_post_processed": True}
        h._cache_post_process_next("search", {"action": "find"}, {"limit": 3}, result)
        assert "next_token" in result

    def test_caches_when_head_set(self):
        h = _Harness()
        result = {"ok": True, "_count": 5, "_post_processed": True}
        h._cache_post_process_next("search", {"action": "find"}, {"head": 5}, result)
        assert "next_token" in result

    def test_no_cache_when_not_full_page(self):
        h = _Harness()
        result = {"ok": True, "_count": 2, "_post_processed": True}
        h._cache_post_process_next("search", {"action": "find"}, {"limit": 10}, result)
        assert "next_token" not in result

    def test_no_cache_for_errors(self):
        h = _Harness()
        result = {"ok": False, "error": {"code": "ERR", "message": "fail"}}
        h._cache_post_process_next("search", {"action": "find"}, {"limit": 3}, result)
        assert "next_token" not in result

    def test_cache_stores_correct_action(self):
        h = _Harness()
        result = {"ok": True, "_count": 3, "_post_processed": True}
        h._cache_post_process_next("search", {"action": "find", "pattern": "x"}, {"limit": 3}, result)
        token = result["next_token"]
        entry = h._next_cache[token]
        assert entry["tool"] == "search"
        assert entry["action"] == "find"
        assert entry["next_offset"] == 3

    def test_cache_advances_offset(self):
        h = _Harness()
        result = {"ok": True, "_count": 5, "_post_processed": True}
        h._cache_post_process_next("search", {"action": "find"}, {"limit": 5, "offset": 10}, result)
        token = result["next_token"]
        assert h._next_cache[token]["next_offset"] == 15

    def test_source_truncated_also_caches(self):
        h = _Harness()
        result = {"ok": True, "_count": 100, "truncated": True, "_post_processed": True}
        h._cache_post_process_next("search", {"action": "find"}, {}, result)
        assert "next_token" in result


# ---------------------------------------------------------------------------
# TestNextContinuation
# ---------------------------------------------------------------------------

class TestNextContinuation:
    def test_continuation_recovers_action(self):
        h = _Harness()
        h._source_payload = _search_payload(10)
        # Cache a page first
        result = {"ok": True, "_count": 3, "_post_processed": True}
        h._cache_post_process_next("search", {"action": "find", "pattern": "x"}, {"limit": 3}, result)
        token = result["next_token"]

        # Continuation should recover the action (pp_params without next_token key)
        cont = h._handle_next_continuation("search", token, {})
        assert cont["ok"] is True
        assert cont["continued_from"] == token

    def test_unknown_token_error(self):
        h = _Harness()
        result = h._handle_next_continuation("search", "NOPE", {})
        assert result.get("ok") is not True
        assert result.get("code") == "TRUNCATION_TOKEN_INVALID"

    def test_wrong_tool_error(self):
        h = _Harness()
        h._next_cache["TOKEN123"] = {
            "tool": "data", "action": "list", "args": {},
            "post_process": {}, "next_offset": 0, "created_at": time.time(),
        }
        result = h._handle_next_continuation("search", "TOKEN123", {})
        assert result.get("ok") is not True
        assert "data" in str(result.get("message", ""))

    def test_continuation_merges_pp_overrides(self):
        h = _Harness()
        h._source_payload = _search_payload(10)
        result = {"ok": True, "_count": 3, "_post_processed": True}
        h._cache_post_process_next("search", {"action": "find"}, {"limit": 3}, result)
        token = result["next_token"]

        # Override grep on continuation (pp_params without next_token)
        cont = h._handle_next_continuation("search", token, {"grep": "crypto"})
        assert cont["ok"] is True
