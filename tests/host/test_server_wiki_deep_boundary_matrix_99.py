"""Deep offline coverage for wiki indexing, ranking, and read contracts."""

from __future__ import annotations

import builtins
import importlib
import threading
from pathlib import Path

from ida_pro_mcp.host.server.server_wiki import ServerWikiMixin

wiki_module = importlib.import_module("ida_pro_mcp.host.server.server_wiki")


class _WikiHost(ServerWikiMixin):
    def __init__(self):
        self._wiki_cache = {}
        self._wiki_cache_lock = threading.RLock()
        self._wiki_cache_ttl = 60.0
        self._wiki_embed_cache = {}
        self._wiki_embed_cache_max = 4
        self.default_wiki_read_limit = 0


def _page(topic="tools/query", text="# Query\n\n## Search\nFind functions.\n"):
    lines = text.splitlines()
    headers = _WikiHost()._wiki_parse_headers([line + "\n" for line in lines])
    title = headers[0]["text"] if headers else topic.rsplit("/", 1)[-1]
    tokens = set(_WikiHost()._wiki_tokenize(f"{topic} {title} {text}"))
    return {
        "topic": topic,
        "topic_lower": topic.lower(),
        "topic_basename": topic.rsplit("/", 1)[-1].lower(),
        "title": title,
        "title_lower": title.lower(),
        "category": topic.split("/", 1)[0] if "/" in topic else "root",
        "text": text,
        "text_lower": text.lower(),
        "line_count": len(lines),
        "headers": headers,
        "header_text_lower": " ".join(h["text"] for h in headers).lower(),
        "tokens": tokens,
        "stemmed_tokens": {token[:-1] if token.endswith("s") else token for token in tokens},
        "semantic_title_text": f"{topic} {title}",
        "semantic_body_text": text,
        "path": topic,
    }


def test_wiki_root_resolution_and_index_file_boundaries(tmp_path, monkeypatch):
    host = _WikiHost()
    with monkeypatch.context() as patch:
        patch.setenv("IDA_MCP_WIKI_DIR", str(tmp_path / "missing"))
        patch.setattr(wiki_module.os.path, "isdir", lambda _path: False)
        assert host._resolve_wiki_root() == ""
    with monkeypatch.context() as patch:
        patch.delenv("IDA_MCP_WIKI_DIR", raising=False)
        patch.setattr(wiki_module.os.path, "isdir", lambda _path: False)
        assert host._resolve_wiki_root() == ""
    with monkeypatch.context() as patch:
        patch.setenv("IDA_MCP_WIKI_DIR", str(Path(wiki_module.SCRIPT_DIR) / "docs" / "wiki"))
        patch.setattr(wiki_module.os.path, "isdir", lambda _path: False)
        assert host._resolve_wiki_root() == ""

    root = tmp_path / "wiki"
    (root / "nested").mkdir(parents=True)
    (root / "README.md").write_text("# Root\ncontent\n", encoding="utf-8")
    (root / "nested" / "page.md").write_text("## Nested\nbody\n", encoding="utf-8")
    (root / "skip.txt").write_text("not markdown", encoding="utf-8")
    index = host._wiki_get_index(str(root))
    assert index["topics"] == {"root": ["README"], "nested": ["page"]}
    assert host._wiki_get_index(str(root)) is index
    forced = host._wiki_get_index(str(root), force=True)
    assert forced["pages"]

    class _AlreadyBuilt:
        def __enter__(self):
            host._wiki_cache = {"root": str(root), "expires": 10**20, "topics": {}, "pages": []}
            return self

        def __exit__(self, *_args):
            return False

    host._wiki_cache = {}
    host._wiki_cache_build_lock = _AlreadyBuilt()
    assert host._wiki_get_index(str(root))["pages"] == []

    original_open = builtins.open

    def selective_open(path, *args, **kwargs):
        if str(path).endswith("broken.md"):
            raise OSError("unreadable")
        return original_open(path, *args, **kwargs)

    (root / "broken.md").write_text("ignored", encoding="utf-8")
    monkeypatch.setattr(builtins, "open", selective_open)
    rebuilt = host._wiki_get_index(str(root), force=True)
    assert not any(page["topic"] == "broken" for page in rebuilt["pages"])


def test_wiki_embedding_cache_waiter_failures_and_eviction(monkeypatch):
    host = _WikiHost()
    assert host._wiki_embed_text("") is None
    event = threading.Event()
    event.set()
    host._wiki_embed_inflight = {"waiting": event}
    assert host._wiki_embed_text("waiting") is None

    core = importlib.import_module("ida_pro_mcp.host.intelligence.core")
    monkeypatch.setattr(
        core,
        "BgeCodeEmbedder",
        lambda: (_ for _ in ()).throw(RuntimeError("backend unavailable")),
    )
    assert host._wiki_embed_text("failed") is None

    class _BadPop(dict):
        def pop(self, *_args, **_kwargs):
            raise RuntimeError("eviction race")

    host._wiki_embed_cache = _BadPop({"old": [0.0]})
    host._wiki_embed_cache_max = 1
    monkeypatch.setattr(core, "BgeCodeEmbedder", _GoodEmbedder)
    assert host._wiki_embed_text("new") == [1.0, 0.0]
    assert host._wiki_embed_cache["new"] == [1.0, 0.0]

    class _RacingEmbedder:
        def embed_vector(self, _text):
            host._wiki_embed_cache["same"] = [9.0]
            return [1.0]

    host._wiki_embed_cache = {}
    monkeypatch.setattr(core, "BgeCodeEmbedder", _RacingEmbedder)
    assert host._wiki_embed_text("same") == [9.0]


class _GoodEmbedder:
    def embed_vector(self, _text):
        return [1.0, 0.0]

    @staticmethod
    def cosine(_left, _right):
        return 0.4


def test_wiki_argument_normalization_and_topic_resolution(monkeypatch):
    host = _WikiHost()
    assert host._normalize_wiki_args({"action": 4}) == {"action": 4}
    assert host._normalize_wiki_args({"action": ""}) == {"action": ""}
    assert host._normalize_wiki_args({"action": "unknown topic"}) == {
        "action": "unknown topic"
    }
    assert host._normalize_wiki_args({"action": "{bad"}) == {"action": "{bad"}
    assert host._normalize_wiki_args({"action": "{bad}"}) == {"action": "{bad}"}
    assert host._normalize_wiki_args({"action": "[]"}) == {"action": "[]"}
    assert host._normalize_wiki_args({"action": '{"action":"read"}', "topic": "given"}) == {
        "action": "read",
        "topic": "given",
    }
    assert host._normalize_wiki_args(
        {"action": "read topic=tools/query topic=ignored 3-5 extra"}
    ) == {"action": "read", "topic": "tools/query", "lines": "3-5"}
    assert host._normalize_wiki_args({"action": "read topic=tools/query"})["topic"] == "tools/query"
    assert host._normalize_wiki_args({"action": "search one two"})["query"] == "one two"
    assert host._normalize_wiki_args({"action": "read", "idb": "tools/query.md"})["topic"] == "tools/query.md"
    assert host._normalize_wiki_args({"action": "read", "idb": "file.exe"}) == {
        "action": "read",
        "idb": "file.exe",
    }

    for value in (None, "/tmp/topic", "a/../b"):
        normalized, error = host._wiki_normalize_topic(value)
        assert normalized is None and error["error"] is True
    assert host._wiki_normalize_topic("tools\\query.md")[0] == "tools/query"
    with monkeypatch.context() as patch:
        patch.setattr(wiki_module.os.path, "isabs", lambda _value: False)
        assert host._wiki_normalize_topic("/tools/query")[0] == "tools/query"

    pages = [
        _page("tools/query"),
        _page("guides/query"),
        _page("guides/quick_start"),
        _page("rootpage"),
    ]
    assert host._wiki_resolve_topic("tools/query", pages)["topic"] == "tools/query"
    assert host._wiki_resolve_topic("query", pages)["topic"] == "tools/query"
    assert host._wiki_resolve_topic("quick start", pages)["topic"] == "guides/quick_start"
    assert host._wiki_resolve_topic("missing", pages) is None
    assert host._wiki_resolve_topic("anything", [], strict=False) is None
    assert host._wiki_resolve_topic("query", pages, strict=True) is None

    monkeypatch.setattr(wiki_module, "TOOLS", ("query",))
    assert host._wiki_resolve_topic("query", pages)["topic"] == "tools/query"


def test_wiki_generated_docs_categories_snippets_and_scores(monkeypatch):
    host = _WikiHost()
    assert host._wiki_generated_tool_doc(4) is None
    assert host._wiki_generated_tool_doc("tools/code.md").startswith("# CODE")
    assert host._wiki_match_category("tools/query", 4) is False
    assert host._wiki_match_category("rootpage", ["root"]) is True
    assert host._wiki_match_category("tools/query", ["root", "tools"]) is True
    assert host._wiki_match_category("tools/query", ["", " / "]) is True
    assert host._wiki_extract_snippets("needle", "", [], 1) == []
    assert len(host._wiki_extract_snippets("needle\nneedle\nneedle", "needle", ["needle"], 1, 2)) == 2

    page = _page("tools/query", "# Query\nneedle function\n")
    assert host._wiki_search_pages(
        [page, _page("guides/none", "# None\n")],
        "needle",
        max_results=5,
        category_filter="tools",
        include_snippets=True,
    )[0]["matches"]
    assert host._wiki_semantic_search_pages(
        [{**page, "stemmed_tokens": None}],
        "needle",
        max_results=5,
        include_snippets=True,
    )[0]["semantic_hits"]
    assert host._wiki_semantic_search_pages(
        [{**page, "stemmed_tokens": set()}],
        "needle",
        max_results=5,
    )[0].get("semantic_hits") is None
    assert host._wiki_related_topics("tools/query", [page, _page("tools/other"), _page("guides/x")], 1) == ["tools/other"]

    monkeypatch.setattr(wiki_module, "EMBEDDING_FIRST_MODE", True)
    core = importlib.import_module("ida_pro_mcp.host.intelligence.core")
    monkeypatch.setattr(core, "BgeCodeEmbedder", _GoodEmbedder)
    score, reasons = host._wiki_score_page(page, "query", ["query"], fuzzy=True)
    assert score > 0
    assert "embedding_title" in reasons

    class _LowSimilarityEmbedder:
        def embed_vector(self, _text):
            return [1.0]

        @staticmethod
        def cosine(_left, _right):
            return 0.1

    monkeypatch.setattr(core, "BgeCodeEmbedder", _LowSimilarityEmbedder)
    low_score, low_reasons = host._wiki_score_page(page, "zzzz", ["zzzz"], fuzzy=True)
    assert low_score == 100 and "lexical_similarity" not in low_reasons

    class _ExplodingEmbedder:
        def embed_vector(self, _text):
            return [1.0]

        @staticmethod
        def cosine(*_args):
            raise RuntimeError("bad vector")

    monkeypatch.setattr(core, "BgeCodeEmbedder", _ExplodingEmbedder)
    fallback_score, _ = host._wiki_score_page(page, "query", ["query"], fuzzy=False)
    assert fallback_score > 0

    monkeypatch.setattr(wiki_module, "TOOL_ACTIONS", {"fake": []})
    monkeypatch.setattr(wiki_module, "TOOLS", ("fake",))
    monkeypatch.setattr(wiki_module, "TOOL_ARG_SCHEMAS", {"fake": {}})
    monkeypatch.setattr(wiki_module, "TOOL_DESCRIPTIONS", {})
    assert "See tool source" in host._wiki_generated_tool_doc("fake")
    assert "- None" in host._wiki_generated_tool_doc("fake")

    # Exercise the generated-doc branches for a tool with no actions and the
    # fallback when a basename is ambiguous outside the tools category.
    guides = [_page("guides/query"), _page("reference/query")]
    assert host._wiki_resolve_topic("query", guides) is None
    assert host._wiki_resolve_topic("no-such", guides) is None
    monkeypatch.setattr(wiki_module, "TOOLS", ("query",))
    assert host._wiki_resolve_topic("query", guides) is None


def _wiki_root(tmp_path: Path) -> Path:
    root = tmp_path / "wiki"
    (root / "tools").mkdir(parents=True)
    (root / "QuickStart.md").write_text(
        "# QuickStart\n\n## Open Binary\nopen it\n\n## Record\nwrite finding\n",
        encoding="utf-8",
    )
    (root / "tools" / "query.md").write_text(
        "# Query\n\n## Search\nFind functions.\n\n### Details\nMore search.\n\n## Filter\nNarrow results.\n",
        encoding="utf-8",
    )
    (root / "empty.md").write_text("", encoding="utf-8")
    return root


def test_wiki_handle_fallback_search_suggest_and_sections(tmp_path, monkeypatch):
    host = _WikiHost()
    root = _wiki_root(tmp_path)
    monkeypatch.setenv("IDA_MCP_WIKI_DIR", str(root))
    assert host._handle_wiki({"action": "list_topics"})["total_pages"] == 3
    assert host._handle_wiki({"action": "index"})["summary"]["total_pages"] == 3

    assert host._handle_wiki({"action": "sections", "topic": "tools/query"})["sections"]
    verbose_sections = host._handle_wiki(
        {"action": "sections", "topic": "tools/query", "verbose": True}
    )
    assert verbose_sections["headers"]
    assert host._handle_wiki({"action": "read", "topic": ""})["error"] is True
    assert host._handle_wiki({"action": "read", "topic": "tools/query", "section": 99})["error"] is True
    substring = host._handle_wiki(
        {"action": "read", "topic": "QuickStart", "section": "open"}
    )
    assert substring["section_filter"] == "Open Binary"
    final_section = host._handle_wiki(
        {"action": "read", "topic": "tools/query", "section": "Filter"}
    )
    assert "Narrow results" in final_section["content"]
    nested_section = host._handle_wiki(
        {"action": "read", "topic": "tools/query", "section": "Search"}
    )
    assert "More search" in nested_section["content"]
    assert host._handle_wiki(
        {"action": "read", "topic": "tools/query", "section": "absent", "verbose": False}
    )["error"] is True
    assert host._handle_wiki(
        {"action": "read", "topic": "tools/query", "section": "zzzz", "fuzzy": False}
    )["error"] is True

    empty = host._handle_wiki(
        {"action": "read", "topic": "empty", "lines": "10-2", "verbose": True}
    )
    assert empty["content"] == ""
    assert empty["line_range"] == "1-1"

    fallback_root = host._handle_wiki({"action": "read", "topic": "tools/code", "verbose": True})
    assert fallback_root["source"] == "generated" or fallback_root["source"] == "markdown"

    monkeypatch.setattr(host, "_resolve_wiki_root", lambda: "")
    assert host._handle_wiki({"action": "index"})["summary"]["wiki_root"] is None
    fallback_list = host._handle_wiki({"action": "list_topics"})
    assert fallback_list["note"]
    fallback_suggest = host._handle_wiki({"action": "suggest", "query": "code"})
    assert fallback_suggest["suggestions"]
    fallback_search = host._handle_wiki({"action": "search", "query": "code"})
    assert fallback_search["matches"]
    missing_without_pages = host._handle_wiki({"action": "read", "topic": "not-a-tool"})
    assert missing_without_pages["code"] == "FILE_NOT_FOUND"


def test_wiki_handle_search_semantic_and_read_window_edges(tmp_path, monkeypatch):
    host = _WikiHost()
    root = _wiki_root(tmp_path)
    monkeypatch.setenv("IDA_MCP_WIKI_DIR", str(root))
    search = host._handle_wiki(
        {
            "action": "search",
            "query": "search",
            "include_snippets": True,
            "category": ["tools"],
            "fuzzy": False,
            "max_results": 1,
        }
    )
    assert search["count"] == 1
    semantic = host._handle_wiki(
        {"action": "semantic_search", "query": "searching", "include_snippets": True}
    )
    assert semantic["ok"] is True
    assert host._handle_wiki({"action": "suggest", "query": "query"})["suggestions"]
    assert host._handle_wiki({"action": "read", "topic": "tools/query", "limit": 0})["content"]

    window = host._handle_wiki(
        {
            "action": "read",
            "topic": "QuickStart",
            "line_start": 100,
            "line_end": 200,
            "include_related": True,
            "verbose": True,
        }
    )
    assert window["content"] == ""
    assert window["related_topics"]

    malformed = host._handle_wiki({"action": "not-real"})
    assert malformed["error"] is True
