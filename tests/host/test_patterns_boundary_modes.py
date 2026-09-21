"""Boundary and mode coverage for host-side matching and global facts."""

from __future__ import annotations

from ida_pro_mcp.host.analysis.patterns import (
    GlobalFactsDatabase,
    _adaptive_fuzzy_cutoff,
    _compile_semantic_matcher,
    _compile_smart_pattern_uncached,
    _is_regex,
    _normalize_semantic_token,
    _semantic_tokenize,
    byte_entropy,
    compile_smart_pattern,
    looks_like_code,
)


def test_byte_detectors_cover_empty_text_and_code_modes():
    assert byte_entropy(b"") == 0.0
    assert byte_entropy(b"aaaa") == 0.0
    assert byte_entropy(bytes(range(256))) == 8.0
    assert looks_like_code(b"") is False
    assert looks_like_code(b"\x00" * 32) is False
    assert looks_like_code(b"A" * 32) is False
    assert looks_like_code(bytes(range(1, 65))) is True
    assert looks_like_code(bytes(range(1, 65)), entropy_floor=7.9) is False


def test_semantic_tokens_matcher_and_adaptive_modes():
    assert _normalize_semantic_token("") == ""
    assert _normalize_semantic_token("decompilers") == "decompile"
    assert _normalize_semantic_token("analyses") == "analys"
    assert _semantic_tokenize("HTTPServerWorker_007") == ["http", "serv", "work", "007"]
    assert _adaptive_fuzzy_cutoff("", 0.8) == 0.8
    assert _adaptive_fuzzy_cutoff("network/http_server", 0.8) > 0.8

    assert _compile_semantic_matcher("") is None
    assert _compile_semantic_matcher("abc") is None
    numeric = _compile_semantic_matcher("agent 007")
    assert numeric is not None and numeric("agent service 007") is True
    assert numeric("agent service 008") is False
    pathlike = _compile_semantic_matcher("network/http", fuzzy_cutoff=0.95)
    assert pathlike is not None and pathlike("network HTTP server") is True
    fuzzy = _compile_semantic_matcher("decrypt buffer", fuzzy_cutoff=0.5)
    assert fuzzy is not None and fuzzy("decrpyt buffer") is True


def test_smart_match_modes_cover_regex_glob_literal_and_invalid_regex():
    assert _is_regex("") is False
    assert _is_regex("plain text") is False
    assert _is_regex("/foo/i") is True
    assert _is_regex(r"foo\\.") is True
    assert _is_regex("[^a]") is True
    assert _is_regex("[a-z]") is True

    assert _compile_smart_pattern_uncached("")("anything") is True
    assert _compile_smart_pattern_uncached("/foo/i")("FOO") is True
    assert _compile_smart_pattern_uncached("/[/")("[/") is False
    assert _compile_smart_pattern_uncached("^foo$", case_sensitive=True)("foo") is True
    assert _compile_smart_pattern_uncached("^foo$", case_sensitive=True)("FOO") is False
    assert _compile_smart_pattern_uncached("f*", case_sensitive=True)("foo") is True
    assert _compile_smart_pattern_uncached("f?o", case_sensitive=False)("Fxo") is False
    assert _compile_smart_pattern_uncached("f?o*", case_sensitive=False)("Fxo") is True
    assert _compile_smart_pattern_uncached("foo", semantic_enabled=False)("FOO") is True
    assert compile_smart_pattern("foo", fuzzy_cutoff=0.2)("FOO") is True


def test_global_facts_database_crud_filters_and_lifecycle(tmp_path):
    db = GlobalFactsDatabase(str(tmp_path / "facts.db"))
    assert db.count() > 0
    fact_id = db.add_fact("custom", "my_key", "my value", confidence=0.7, source="test")
    assert fact_id.startswith("fact_")
    assert db.add_fact("custom", "my_key", "updated", confidence=0.8, source="test") == fact_id
    rows = db.query_facts(category="custom", key_pattern="MY", limit=10)
    assert len(rows) == 1 and rows[0]["value"] == "updated"
    assert db.query_facts(category="missing") == []
    assert db.query_facts(key_pattern="socket", limit=2)
    assert "facts at" in repr(db)
    db.close()
