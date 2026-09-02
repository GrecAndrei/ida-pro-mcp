"""Behavior coverage for the host-side wiki mixin."""

from __future__ import annotations

import importlib
import threading

from ida_pro_mcp.host.server.server_wiki import ServerWikiMixin

wiki_server_mod = importlib.import_module("ida_pro_mcp.host.server.server_wiki")


class WikiHost(ServerWikiMixin):
    def __init__(self):
        self._wiki_cache = {}
        self._wiki_cache_lock = threading.RLock()
        self._wiki_cache_ttl = 60.0
        self._wiki_embed_cache = {}
        self._wiki_embed_cache_max = 4
        self.default_wiki_read_limit = 0


def _host(monkeypatch, tmp_path):
    root = tmp_path / "wiki"
    tools = root / "tools"
    tools.mkdir(parents=True)
    (root / "QuickStart.md").write_text(
        "# QuickStart\n\n## Open\nopen the binary\n\n## Record\nwrite a finding\n",
        encoding="utf-8",
    )
    (tools / "query.md").write_text(
        "# Query\n\n## Search\nFind functions and strings.\n\n## Filter\nNarrow the result.\n",
        encoding="utf-8",
    )
    (tools / "other.md").write_text(
        "# Other\n\n## Search\nAnother search workflow.\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("IDA_MCP_WIKI_DIR", str(root))
    monkeypatch.setattr(wiki_server_mod, "EMBEDDING_FIRST_MODE", False)
    return WikiHost(), root


def test_wiki_index_read_sections_ranges_and_related(monkeypatch, tmp_path):
    host, root = _host(monkeypatch, tmp_path)

    topics = host._handle_wiki({"action": "list_topics"})
    assert topics["ok"] is True
    assert topics["total_pages"] == 3
    assert topics["counts"]["tools"] == 2

    index = host._handle_wiki({"action": "index"})
    assert index["summary"]["category_count"] == 2
    assert index["summary"]["wiki_root"] == str(root)

    read = host._handle_wiki(
        {
            "action": "read",
            "topic": "tools/query.md",
            "section": "search",
            "verbose": True,
            "include_related": True,
        }
    )
    assert read["ok"] is True
    assert read["resolved_topic"] == "tools/query"
    assert read["section_filter"] == "Search"
    assert "Find functions" in read["content"]
    assert "tools/other" in read["related_topics"]
    assert read["source"] == "markdown"
    assert read["headers"]

    by_number = host._handle_wiki(
        {"action": "read", "topic": "QuickStart", "section": 2}
    )
    assert by_number["ok"] is True
    assert by_number["section_filter"] == "Open"

    fuzzy_section = host._handle_wiki(
        {"action": "read", "topic": "QuickStart", "section": "recrod"}
    )
    assert fuzzy_section["ok"] is True
    assert fuzzy_section["section_filter"] == "Record"

    window = host._handle_wiki(
        {"action": "read", "topic": "QuickStart", "lines": "2-4", "verbose": True}
    )
    assert window["ok"] is True
    assert window["line_range"] == "2-4"
    assert "Open" in window["content"]

    reverse_window = host._handle_wiki(
        {"action": "read", "topic": "QuickStart", "line_start": 5, "line_end": 2}
    )
    assert reverse_window["ok"] is True
    assert reverse_window["line_range"] == "2-5"

    short = host._handle_wiki({"action": "read", "topic": "QuickStart", "limit": 1})
    assert short["_truncated"] is True
    assert short["next_offset"] == 1

    bad_section = host._handle_wiki(
        {"action": "read", "topic": "QuickStart", "section": "missing", "verbose": True}
    )
    assert bad_section["error"] is True
    assert bad_section["code"] == "INVALID_ARGS"
    missing = host._handle_wiki({"action": "read", "topic": "missing"})
    assert missing["error"] is True
    assert missing["code"] == "FILE_NOT_FOUND"


def test_wiki_search_semantics_suggestions_and_argument_shapes(monkeypatch, tmp_path):
    host, _root = _host(monkeypatch, tmp_path)
    host._wiki_get_index(str(tmp_path / "wiki"))

    search = host._handle_wiki(
        {
            "action": "search",
            "query": "search",
            "category": "tools",
            "include_snippets": True,
            "context_lines": 1,
            "max_results": 1,
        }
    )
    assert search["ok"] is True
    assert search["count"] == 1
    assert search["matches"][0]["category"] == "tools"
    assert search["matches"][0]["matches"]

    semantic = host._handle_wiki(
        {"action": "semantic_search", "query": "searching", "category": ["tools"]}
    )
    assert semantic["ok"] is True
    assert semantic["count"] >= 1
    assert "semantic_overlap" in semantic["matches"][0]["matched_on"]

    suggested = host._handle_wiki({"action": "suggest", "query": "quer"})
    assert suggested["ok"] is True
    assert suggested["suggestions"]
    assert suggested["suggestions"][0]["topic"] == "tools/query"
    assert host._handle_wiki({"action": "suggest"})["error"] is True
    assert host._handle_wiki({"action": "search"})["error"] is True

    assert host._normalize_wiki_args({"action": "read tools/query 10-20"}) == {
        "action": "read",
        "topic": "tools/query",
        "lines": "10-20",
    }
    assert host._normalize_wiki_args(
        {"action": '{"action":"read","topic":"QuickStart"}'}
    ) == {"action": "read", "topic": "QuickStart"}
    assert host._normalize_wiki_args({"action": "read", "idb": "tools/query"})["topic"] == "tools/query"
    assert host._normalize_wiki_args({"action": "read", "idb": "/tmp/x.idb"}) == {
        "action": "read",
        "idb": "/tmp/x.idb",
    }

    malformed = host._handle_wiki({"action": "read 'tools/query"})
    assert malformed["error"] is True
    assert malformed["code"] == "INVALID_ARGS"
    unsupported = host._handle_wiki({"action": "nope"})
    assert unsupported["error"] is True
    assert unsupported["code"] == "ACTION_NOT_FOUND"


def test_wiki_helpers_and_generated_fallback(monkeypatch, tmp_path):
    host, _root = _host(monkeypatch, tmp_path)
    assert host._wiki_tokenize("A-B C_2") == ["a", "b", "c_2"]
    assert host._wiki_tokenize("") == []
    assert host._wiki_stem_token("tracing") == "trace"
    assert host._wiki_stem_token("files") == "fil"
    assert host._wiki_stem_token("API") == "api"
    assert host._wiki_expand_semantic_terms(["trace"]) >= {"trace", "flow"}
    assert host._wiki_match_category("QuickStart", "root") is True
    assert host._wiki_match_category("tools/query", ["tools"]) is True
    assert host._wiki_match_category("tools/query", "core") is False
    assert host._wiki_match_category("tools/query", " , ") is True
    assert host._wiki_extract_snippets("one\nneedle\nthree", "needle", ["needle"], 1)
    assert host._wiki_extract_snippets("", "needle", ["needle"], 1) == []

    page = {
        "topic": "tools/query",
        "topic_lower": "tools/query",
        "topic_basename": "query",
        "title": "Query",
        "title_lower": "query",
        "category": "tools",
        "text": "# Query\nsearch",
        "tokens": {"query", "search"},
        "stemmed_tokens": {"queri", "search"},
        "semantic_title_text": "tools/query Query",
        "semantic_body_text": "search",
    }
    assert host._wiki_score_page(page, "search", ["search"], fuzzy=False)[0] > 0
    assert host._wiki_related_topics("missing", [page]) == []
    assert host._wiki_resolve_topic("query", [page])["topic"] == "tools/query"
    assert host._wiki_resolve_topic("query", [page], strict=True) is None
    assert host._wiki_generated_tool_doc("not-a-tool") is None
    assert "Tool Manual" in host._wiki_generated_tool_doc("code")

    # An unavailable markdown root still gives callers a usable generated
    # manual for a known tool.
    monkeypatch.setattr(host, "_resolve_wiki_root", lambda: "")
    fallback = host._handle_wiki({"action": "read", "topic": "tools/code"})
    assert fallback["ok"] is True
    assert fallback["source"] == "generated" if "source" in fallback else True
    assert "CODE Tool Manual" in fallback["content"]
    fallback_list = host._handle_wiki({"action": "list_topics"})
    assert fallback_list["total_pages"] > 0
    fallback_search = host._handle_wiki({"action": "search", "query": "CODE Tool Manual"})
    assert fallback_search["count"] >= 1


def test_wiki_embedding_cache_and_fuzzy_embedding_fallback(monkeypatch, tmp_path):
    host, _root = _host(monkeypatch, tmp_path)

    class FakeEmbedder:
        calls = []

        def embed_vector(self, text):
            self.calls.append(text)
            return [1.0, 0.0]

        @staticmethod
        def cosine(_left, _right):
            return 0.1

    core = importlib.import_module("ida_pro_mcp.host.intelligence.core")
    monkeypatch.setattr(core, "BgeCodeEmbedder", FakeEmbedder)
    monkeypatch.setattr(wiki_server_mod, "EMBEDDING_FIRST_MODE", True)

    first = host._wiki_embed_text("Query text")
    second = host._wiki_embed_text("QUERY TEXT")
    assert first == second == [1.0, 0.0]
    assert FakeEmbedder.calls == ["query text"]

    host._wiki_embed_cache_max = 1
    host._wiki_embed_text("another")
    assert "query text" not in host._wiki_embed_cache
    assert "another" in host._wiki_embed_cache

    page = {
        "topic": "tools/query",
        "topic_lower": "tools/query",
        "topic_basename": "query",
        "title": "Query",
        "title_lower": "query",
        "category": "tools",
        "text": "# Query\nsearch",
        "tokens": {"query", "search"},
        "stemmed_tokens": {"queri", "search"},
        "semantic_title_text": "tools/query Query",
        "semantic_body_text": "search",
    }
    score, reasons = host._wiki_score_page(page, "quer", ["quer"], fuzzy=True)
    assert score > 0
    assert "lexical_similarity" in reasons
