"""Behavioral coverage for host-side normalization and wiki contracts.

These tests stay at the host boundary: inputs are noisy JSON-like arguments
and outputs are the envelopes a client receives.  IDA itself is not involved.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server_args import ServerArgsMixin
from ida_pro_mcp.host.server.server_wiki import ServerWikiMixin


class _ArgsHost(ServerArgsMixin):
    def __init__(self):
        self._next_cache = {}
        self._next_cache_ttl_seconds = 60.0
        self.current_session = SimpleNamespace(session_id="SID_ACTIVE")

    def _truncation_owner_id(self):
        return "CLIENT_A"


class _WikiHost(ServerWikiMixin):
    def __init__(self, root):
        self.root = str(root)
        self._wiki_cache = {"root": "", "expires": 0.0, "topics": {}, "pages": []}
        self._wiki_cache_ttl = 60.0
        self._wiki_cache_lock = threading.Lock()
        self._wiki_embed_cache = {}
        self._wiki_embed_cache_max = 8
        self.default_wiki_read_limit = 3

    def _resolve_wiki_root(self):
        return self.root


def _write_wiki(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_argument_tail_parser_preserves_quoted_values_and_positional_text():
    host = _ArgsHost()
    assert host._parse_action_tail_tokens('query="two words" limit=08 bare') == {
        "query": "two words",
        "limit": "08",
        "_positional": "bare",
    }


def test_argument_normalizer_accepts_json_dict_and_subaction_shapes():
    host = _ArgsHost()
    assert host._normalize_tool_call_args(
        "search", {"action": '{"action":"find","query":"main"}'}
    ) == {"action": "find", "query": "main"}
    assert host._normalize_tool_call_args(
        "search", {"action": {"action": "find", "query": "leaf"}}
    ) == {"action": "find", "query": "leaf"}
    assert host._normalize_tool_call_args(
        "search", {"subaction": "Find"}
    ) == {"subaction": "Find", "action": "find"}


def test_argument_normalizer_parses_tails_and_scalar_wrappers():
    host = _ArgsHost()
    result = host._normalize_tool_call_args(
        "search", {"action": "FIND query='hello world' limit='08'"}
    )
    assert result == {"action": "find", "query": "hello world", "limit": 8}

    code = host._normalize_tool_call_args(
        "code", {"action": "decompile", "addrs": "[0x1000, 0x2000]"}
    )
    assert code["addrs"] == ["0x1000", "0x2000"]


def test_argument_normalizer_rejects_non_string_actions_and_bad_integer_fields():
    host = _ArgsHost()
    non_string = host._normalize_tool_call_args("search", {"action": 3})
    assert non_string["error"] is True
    assert non_string["code"] == MCPError.INVALID_ARGS

    bad_integer = host._normalize_tool_call_args(
        "search", {"action": "find", "limit": "not-a-number"}
    )
    assert bad_integer["error"] is True
    assert bad_integer["code"] == MCPError.INVALID_ARGS
    assert "limit" in bad_integer["message"]


def test_next_cache_lock_is_stable_and_page_tokens_are_scoped():
    host = _ArgsHost()
    assert host._next_cache_lock() is host._next_cache_lock()
    payload = host._cache_next_page(
        "data",
        {"action": "strings", "offset": 0, "count": 2},
        {"ok": True, "offset": 0, "count": 2, "total": 5, "truncated": True},
        scope=("SID_EXPLICIT", "CLIENT_EXPLICIT"),
    )
    token = payload["next_token"]
    assert payload["next_offset"] == 2
    assert host._next_cache[token]["session_id"] == "SID_EXPLICIT"
    assert host._next_cache[token]["owner_id"] == "CLIENT_EXPLICIT"
    assert host._next_cache[token]["args"] == {
        "action": "strings", "offset": 0, "count": 2
    }


def test_next_cache_does_not_mint_for_errors_complete_or_postprocessed_payloads():
    host = _ArgsHost()
    cases = [
        {"error": True, "code": "IDA_ERROR", "truncated": True},
        {"ok": True, "truncated": False},
        {"ok": True, "truncated": True, "_post_processed": True},
        {"ok": True, "truncated": True, "next_token": "EXISTING"},
    ]
    for payload in cases:
        original = dict(payload)
        assert host._cache_next_page(
            "data", {"action": "strings"}, payload
        ) == original
    assert host._next_cache == {}


def test_next_cache_prunes_expired_malformed_and_non_mapping_rows(monkeypatch):
    host = _ArgsHost()
    host._next_cache = {
        "fresh": {"created_at": 95.0},
        "old": {"created_at": 1.0},
        "broken": {"created_at": "nope"},
        "nan": {"created_at": float("nan")},
        "scalar": "invalid",
    }
    monkeypatch.setattr("ida_pro_mcp.host.server.server_args.time.time", lambda: 100.0)
    host._prune_next_cache()
    assert set(host._next_cache) == {"fresh"}


def test_next_cache_scope_prefers_explicit_idb_then_active_session():
    host = _ArgsHost()
    host._resolve_session_from_idb_ref = lambda value: SimpleNamespace(
        session_id=f"SID_{value}"
    )
    assert host._next_cache_scope({"idb": "other"}) == ("SID_other", "CLIENT_A")
    assert host._next_cache_scope({}) == ("SID_ACTIVE", "CLIENT_A")


def test_wiki_index_and_topic_listing_read_real_markdown(tmp_path):
    _write_wiki(
        tmp_path,
        "README.md",
        "# Project Guide\n\nOverview of the MCP server.\n## Install\nRun it.\n",
    )
    _write_wiki(
        tmp_path,
        "tools/query.md",
        "# Query Tool\n\nSearch names and strings.\n## Examples\nUse a query.\n",
    )
    host = _WikiHost(tmp_path)
    listed = host._handle_wiki({"action": "list_topics"})
    assert listed["ok"] is True
    assert listed["total_pages"] == 2
    assert listed["counts"]["tools"] == 1

    indexed = host._handle_wiki({"action": "index"})
    assert indexed["summary"]["total_pages"] == 2
    assert indexed["categories"]["root"] == ["README"]

    read = host._handle_wiki({"action": "read", "topic": "tools/query"})
    assert read["ok"] is True
    assert "Search names" in read["content"]
    assert read["_truncated"] is True
    assert read["next_offset"] == 3


def test_wiki_read_supports_action_tail_sections_and_line_windows(tmp_path):
    _write_wiki(
        tmp_path,
        "tools/query.md",
        "# Query Tool\nline two\nline three\n## Examples\nexample body\n",
    )
    host = _WikiHost(tmp_path)
    sections = host._handle_wiki(
        {"action": "sections tools/query", "verbose": True}
    )
    assert sections["ok"] is True
    assert [header["title"] for header in sections["headers"]] == [
        "Query Tool", "Examples"
    ]

    selected = host._handle_wiki(
        {"action": "read tools/query", "section": "example", "lines": "4-5"}
    )
    assert selected["ok"] is True
    assert selected["section_filter"] == "Examples"
    assert selected["content"] == "## Examples\nexample body\n"


def test_wiki_search_semantic_search_and_suggest_return_ranked_contracts(tmp_path):
    _write_wiki(
        tmp_path,
        "guides/workflow.md",
        "# Workflow\nUse the session state before analysis.\n## Search\nFind a function.\n",
    )
    _write_wiki(tmp_path, "tools/query.md", "# Query\nSearch names.\n")
    host = _WikiHost(tmp_path)
    search = host._handle_wiki(
        {
            "action": "search",
            "query": "session",
            "include_snippets": True,
            "category": "guides",
        }
    )
    assert search["ok"] is True
    assert search["matches"][0]["topic"] == "guides/workflow"
    assert search["matches"][0]["matches"]

    host._wiki_embed_text = lambda _text: None
    semantic = host._handle_wiki({"action": "semantic_search", "query": "search"})
    assert semantic["ok"] is True
    assert semantic["matches"]
    suggestion = host._handle_wiki({"action": "suggest", "query": "workfl"})
    assert suggestion["ok"] is True
    assert suggestion["suggestions"][0]["topic"] == "guides/workflow"


def test_wiki_generated_fallback_and_invalid_topics_are_explicit(tmp_path):
    host = _WikiHost(tmp_path)
    generated = host._handle_wiki(
        {"action": "read", "topic": "tools/search", "verbose": True}
    )
    assert generated["ok"] is True
    assert generated["source"] == "generated"
    assert "SEARCH Tool Manual" in generated["content"]

    traversal = host._handle_wiki({"action": "read", "topic": "../secret"})
    assert traversal["error"] is True
    assert traversal["code"] == MCPError.INVALID_ARGS

    missing = host._handle_wiki({"action": "read", "topic": "not-real"})
    assert missing["error"] is True
    assert missing["code"] == MCPError.FILE_NOT_FOUND
    assert "wiki_root" in missing["details"]


def test_wiki_rejects_bad_actions_and_malformed_quote_tails(tmp_path):
    host = _WikiHost(tmp_path)
    unknown = host._handle_wiki({"action": "not-real"})
    assert unknown["error"] is True
    assert unknown["code"] == MCPError.ACTION_NOT_FOUND

    malformed = host._handle_wiki({"action": "read 'tools/query"})
    assert malformed["error"] is True
    assert malformed["code"] == MCPError.INVALID_ARGS
