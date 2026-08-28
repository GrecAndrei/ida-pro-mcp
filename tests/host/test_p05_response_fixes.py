"""Regression tests for p05 (response) package fixes.

Covers the confirmed audit findings in the response pipeline:

- ``_add_address_calculations``: no RVA-rebasing when the image base is a
  64-bit address (x64 binaries); 32-bit image bases keep the documented
  section-RVA behavior.
- ``_compact_value``: the live ``next_offset`` continuation cursor survives
  compaction (previously a dedupe pass deleted it when it equaled the item
  count, breaking ``_cache_next_page`` pagination).
- ``digest_decompiled``: the anti-VM regex no longer matches ``strlen``,
  ``string``, ``struct`` (bare ``str`` fixed); complexity counters only count
  spaced Hex-Rays forms; ``file_io`` fires from the file category alone.
- ``patch_addresses``: both +/- offset signs resolve correctly and every
  base+offset reference on a line is annotated (not just the first).
- ``_parse_line_range``: non-numeric input degrades to "no line window"
  instead of raising.
- ``_pending_truncation``: per-call truncation overrides are consumed once and
  cleared so they cannot leak into the next (batch/help/error) response.
- ``_apply_output_filters``: error envelopes pass through unchanged.
- ``_extract_response_options``: backend ``mode`` is not popped (only the
  host ``_response_mode``/``response_mode``/``compact`` controls are).
"""

from __future__ import annotations

import threading

from ida_pro_mcp.host.config import _parse_line_range
from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.response_enrichment import digest_decompiled, patch_addresses
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_response_compact import (
    ServerResponseCompactMixin,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stub_server(**attrs) -> IDAMCPServer:
    """A lightweight IDAMCPServer instance without a full __init__.

    All response-pipeline methods live on the mixins, so __new__ exposes them;
    we only set the handful of instance attributes each test needs.
    """
    server = IDAMCPServer.__new__(IDAMCPServer)
    server.enable_response_enrichment = False
    server.current_session = None
    for key, value in attrs.items():
        setattr(server, key, value)
    return server


def test_runtime_table_helpers_snapshot_concurrent_churn():
    """Runtime readers must not observe a dict while teardown replaces it."""
    server = IDAMCPServer.__new__(IDAMCPServer)
    server.session_runtimes = {}
    server._runtime_lock = threading.RLock()
    errors: list[BaseException] = []

    def writer() -> None:
        try:
            for i in range(500):
                with server._runtime_lock:
                    server.session_runtimes.clear()
                    server.session_runtimes[f"SID_{i}"] = {"port": i + 1}
        except BaseException as exc:  # pragma: no cover - assertion below
            errors.append(exc)

    def reader() -> None:
        try:
            for i in range(1_000):
                server._runtime_record(f"SID_{i}")
                server._runtime_items_snapshot()
        except BaseException as exc:  # pragma: no cover - assertion below
            errors.append(exc)

    threads = [threading.Thread(target=writer)] + [
        threading.Thread(target=reader) for _ in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []


_COMPACT_OPTS = {
    "mode": "compact",
    "fields": [],
    "omit": [],
    "max_items": 100,
    "max_string": 100_000,
    "char_budget": 0,
    "drop_empty": True,
    "drop_false": True,
    "drop_ok": False,
    "dedupe_counts": True,
    "strip_meta": True,
    "table_mode": False,
    "batch_compact": True,
    "error_details": "basic",
}


# ---------------------------------------------------------------------------
# _add_address_calculations: RVA heuristic
# ---------------------------------------------------------------------------


class TestAddressCalculationsRvaHeuristic:
    def test_x64_imagebase_never_rebases_subbase_values(self):
        """0x140000000 (a 64-bit image base) must not turn 0x1000 into
        0x140001000 — a fabricated address. The old gate rebased anything
        below the image base regardless of its width."""
        server = _stub_server()
        server._get_session_imagebase = lambda session_id: 0x140000000
        compacted = {"address": "0x1000"}
        server._add_address_calculations(compacted, None)
        calc = compacted.get("llm_address_calculation", {})
        entry = calc.get("0x1000", {})
        assert "is_rva" not in entry, entry
        assert entry["decimal"] == 0x1000, entry

    def test_x64_imagebase_keeps_abs_values_absolute(self):
        server = _stub_server()
        server._get_session_imagebase = lambda session_id: 0x140000000
        compacted = {"address": "0x140001000"}
        server._add_address_calculations(compacted, None)
        entry = compacted.get("llm_address_calculation", {}).get("0x140001000", {})
        assert "is_rva" not in entry, entry
        assert entry["decimal"] == 0x140001000, entry

    def test_32bit_imagebase_still_rebases_section_rva(self):
        """Existing codified behavior (test_relocation_and_session_fixes.py):
        a 32-bit image base keeps rebasing sub-base values as section RVAs."""
        server = _stub_server()
        server._get_session_imagebase = lambda session_id: 0x400000
        compacted = {"address": "0x1000"}
        server._add_address_calculations(compacted, None)
        entry = compacted.get("llm_address_calculation", {}).get("0x1000", {})
        assert entry["is_rva"] is True, entry
        assert entry["decimal"] == 0x401000, entry


# ---------------------------------------------------------------------------
# _compact_value: next_offset continuation cursor
# ---------------------------------------------------------------------------


class TestCompactPreservesNextOffset:
    def test_next_offset_survives_compaction(self):
        stub = ServerResponseCompactMixin.__new__(ServerResponseCompactMixin)
        payload = {
            "items": [{"a": 1}, {"a": 2}],
            "next_offset": 2,
            "count": 2,
            "total": 10,
            "limit": 2,
        }
        out = stub._compact_value(payload, dict(_COMPACT_OPTS))
        assert out["next_offset"] == 2, out
        # The dedupe pass may still drop count/total when they equal the list
        # length, but must never drop the pagination cursor.
        assert "items" in out


# ---------------------------------------------------------------------------
# _compact_value: live analysis signals survive drop_false
# ---------------------------------------------------------------------------


class TestCompactKeepsLiveAnalysisSignals:
    def test_analysis_ready_and_active_survive_drop_false(self):
        """The "runtime alive but still busy" signals must survive compact
        drop_false (ready=False is the difference between 'busy' and 'unknown');
        unrelated false keys still drop."""
        stub = ServerResponseCompactMixin.__new__(ServerResponseCompactMixin)
        payload = {
            "ok": True,
            "safe_mode": False,
            "analysis_complete": False,
            "analysis_ready": False,
            "analysis_active": True,
            "is_running": True,
            "some_unrelated_flag": False,
        }
        out = stub._compact_value(payload, dict(_COMPACT_OPTS))
        assert out["analysis_ready"] is False, out
        assert out["analysis_active"] is True, out
        assert out["safe_mode"] is False, out
        assert out["analysis_complete"] is False, out
        assert out["is_running"] is True, out
        assert "some_unrelated_flag" not in out, out

    def test_live_signals_survive_when_nested_under_session(self):
        stub = ServerResponseCompactMixin.__new__(ServerResponseCompactMixin)
        payload = {
            "ok": True,
            "session": {
                "analysis_ready": False,
                "analysis_active": False,
                "safe_mode": True,
                "background": True,
                "auto_backgrounded": False,
            },
            "total_sessions": 1,
        }
        out = stub._compact_value(payload, dict(_COMPACT_OPTS))
        session = out["session"]
        assert session["analysis_ready"] is False, session
        assert session["analysis_active"] is False, session
        assert session["safe_mode"] is True, session
        assert session["background"] is True, session
        assert session["auto_backgrounded"] is False, session


# ---------------------------------------------------------------------------
# digest_decompiled: _ANTIVM, complexity counters, file_io
# ---------------------------------------------------------------------------


class TestDigestDecompiled:
    def test_antivm_no_longer_matches_str_substring(self):
        for code in ("v3 = strlen(s);", "string in buffer", "struct node *n"):
            digest = digest_decompiled(code)
            assert "Anti-VM/anti-sandbox check" not in digest["patterns"], code

    def test_antivm_still_matches_standalone_str(self):
        digest = digest_decompiled("lea rdi, str\nint 3")
        assert "Anti-VM/anti-sandbox check" in digest["patterns"]

    def test_complexity_counts_only_spaced_hexrays_forms(self):
        code = "\n".join(
            [
                "if (a) {",
                "    foo(1);",
                "}",
                "for (i = 0; i < 4; i++) {",
                "    bar(i);",
                "}",
                "while (ok) {",
                "    baz();",
                "}",
            ]
        )
        digest = digest_decompiled(code)
        c = digest["complexity"]
        # if ( once; the call's "foo(" is a call, not a branch.
        assert c["branches"] == 1, c
        assert c["loops"] == 2, c  # for ( + while (
        assert c["calls"] == 3, c  # foo, bar, baz

    def test_file_io_tag_from_file_category_alone(self):
        # CreateFile is in the "file" category but not "registry"; the old
        # file_io tag required file AND registry together.
        digest = digest_decompiled("h = CreateFile(\"x\", GENERIC_READ);")
        assert "file_io" in digest["behavior_tags"], digest["behavior_tags"]

    def test_schema_verified_api_drives_behavior_tags(self):
        # Schema-verified APIs merge into api_categories, and the network tag
        # must follow (previously the merge was dropped in the digest).
        digest = digest_decompiled(
            "/* no regex match */", schema_attrs={"apis": ["socket", "connect"]}
        )
        assert "network" in digest["behavior_tags"], digest["behavior_tags"]


# ---------------------------------------------------------------------------
# patch_addresses
# ---------------------------------------------------------------------------


class TestPatchAddresses:
    def test_lea_plus_offset_resolves(self):
        out = patch_addresses("lea rdx, [rbp+0x10]", {"rbp": 0x1000})
        assert "0x1010" in out, out
        assert "; ->" in out, out

    def test_lea_minus_offset_resolves(self):
        # The old code ignored the sign and always added the offset.
        out = patch_addresses("lea rdx, [rbp-0x10]", {"rbp": 0x1000})
        assert "0xff0" in out, out

    def test_multiple_base_offset_refs_all_annotated(self):
        line = "mov eax, [rbp+0x20]; mov ecx, [rbp+0x30]"
        out = patch_addresses(line, {"rbp": 0x1000})
        assert "rbp+0x20 -> 0x1020" in out, out
        assert "rbp+0x30 -> 0x1030" in out, out

    def test_rip_relative_lea_resolves(self):
        out = patch_addresses("lea rax, [rip+0x10]", {"rip": 0x400000})
        assert "0x400010" in out, out


# ---------------------------------------------------------------------------
# _parse_line_range: graceful non-numeric input
# ---------------------------------------------------------------------------


class TestParseLineRangeGraceful:
    def test_nonnumeric_string_returns_no_window(self):
        assert _parse_line_range("oops") == (None, None)
        assert _parse_line_range("10-x") == (10, None)
        assert _parse_line_range(["10", "oops"]) == (10, None)

    def test_numeric_forms_still_parse(self):
        assert _parse_line_range("10-40") == (10, 40)
        assert _parse_line_range("25") == (25, None)
        assert _parse_line_range(None) == (None, None)


# ---------------------------------------------------------------------------
# _handle_wiki: suggest handler + _coerce_bool
# ---------------------------------------------------------------------------


def _wiki_stub() -> IDAMCPServer:
    import threading

    server = IDAMCPServer.__new__(IDAMCPServer)
    server._resolve_wiki_root = lambda: ""
    server._wiki_cache = {"root": "", "expires": 0.0, "topics": {}, "pages": []}
    server._wiki_cache_ttl = 5.0
    server._wiki_cache_lock = threading.Lock()
    server.default_wiki_read_limit = 140
    return server


class TestWikiSuggest:
    def test_suggest_returns_suggestions_not_read_page(self):
        server = _wiki_stub()
        out = server._handle_wiki({"action": "suggest", "query": "code"})
        assert out["ok"] is True, out
        assert out["action"] == "suggest", out
        assert out["count"] >= 1, out
        assert any("code" in str(s["topic"]) for s in out["suggestions"]), out

    def test_suggest_requires_query(self):
        server = _wiki_stub()
        out = server._handle_wiki({"action": "suggest"})
        assert out.get("error") is True, out

    def test_sections_honors_string_false_verbose(self):
        # bool("false") is True; _coerce_bool("false") is False. The sections
        # action returns the compact shape when verbose is false.
        server = _wiki_stub()
        out = server._handle_wiki(
            {"action": "sections", "topic": "code", "verbose": "false"}
        )
        assert out["ok"] is True, out
        assert "headers" not in out, out
        assert "sections" in out, out

    def test_embed_singleflight_and_no_failed_cache_poison(self, monkeypatch):
        server = _wiki_stub()
        server._wiki_embed_cache = {}
        server._wiki_embed_cache_max = 8
        started = threading.Event()
        release = threading.Event()
        calls = 0
        calls_lock = threading.Lock()

        class _Embedder:
            def embed_vector(self, _text):
                nonlocal calls
                with calls_lock:
                    calls += 1
                started.set()
                release.wait(timeout=2)
                return [0.25, 0.75]

        monkeypatch.setattr(
            "ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder", _Embedder
        )
        results = []
        threads = [
            threading.Thread(
                target=lambda: results.append(server._wiki_embed_text("same query")),
                daemon=True,
            )
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        assert started.wait(timeout=2)
        release.set()
        for thread in threads:
            thread.join(timeout=2)
        assert calls == 1
        assert results == [[0.25, 0.75]] * 8

        class _Unavailable:
            def embed_vector(self, _text):
                return None

        monkeypatch.setattr(
            "ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder", _Unavailable
        )
        assert server._wiki_embed_text("failed query") is None
        assert "failed query" not in server._wiki_embed_cache

    def test_forced_index_rebuild_publishes_atomic_snapshot(self, tmp_path):
        server = _wiki_stub()
        wiki_root = tmp_path / "wiki"
        wiki_root.mkdir()
        page = wiki_root / "page.md"
        page.write_text("# Old\nold body\n", encoding="utf-8")
        old_snapshot = server._wiki_get_index(str(wiki_root))

        page.write_text("# New\nnew body\n", encoding="utf-8")
        new_snapshot = server._wiki_get_index(str(wiki_root), force=True)

        assert old_snapshot is not new_snapshot
        assert old_snapshot["pages"][0]["text"] == "# Old\nold body\n"
        assert new_snapshot["pages"][0]["text"] == "# New\nnew body\n"


# ---------------------------------------------------------------------------
# _prepare_response_payload: pending truncation consumed + cleared
# ---------------------------------------------------------------------------


class TestPendingTruncationCleared:
    def test_pending_truncation_cleared_after_response(self):
        server = _stub_server()
        server._pending_truncation = {"no_truncate": True, "trunc_limit": 5}
        # "session" is recall-exempt so the workspace-recall tail no-ops.
        out = server._prepare_response_payload(
            {"ok": True, "items": [1, 2, 3]},
            dict(_COMPACT_OPTS),
            tool_name="session",
            call_args={"action": "list"},
        )
        assert isinstance(out, dict)
        assert server._pending_truncation == {}, server._pending_truncation

    def test_pending_truncation_default_path(self):
        # A server whose _pending_truncation was never set (the property
        # returns an empty dict from per-connection state) must not crash and
        # must expose the (cleared) slot afterwards.
        server = _stub_server()
        out = server._prepare_response_payload(
            {"ok": True},
            dict(_COMPACT_OPTS),
            tool_name="session",
            call_args={},
        )
        assert isinstance(out, dict)
        assert server._pending_truncation == {}


# ---------------------------------------------------------------------------
# _apply_output_filters: error envelope pass-through
# ---------------------------------------------------------------------------


class TestApplyOutputFiltersErrorPassthrough:
    def test_error_payload_unchanged_despite_filters(self):
        server = _stub_server()
        error = {
            "error": True,
            "code": MCPError.FILE_NOT_FOUND,
            "category": "user",
            "message": "nope",
            "hint": "try again",
        }
        opts = {
            "output_path": "items",
            "output_grep": "secret",
            "output_head": 1,
            "output_tail": 1,
        }
        out = server._apply_output_filters(error, opts)
        assert out == error, out


# ---------------------------------------------------------------------------
# _extract_response_options: backend mode preserved
# ---------------------------------------------------------------------------


class TestExtractResponseOptionsPreservesMode:
    def test_backend_mode_not_popped(self):
        """mode="quick" is a backend/agent-surface control, not a host
        response option — it must survive _extract_response_options."""
        stub = _stub_server(
            default_response_mode="compact",
            default_qol_mode="balanced",
            default_compact_max_items=48,
            default_compact_max_string=1400,
            default_compact_char_budget=30_000,
            default_table_mode=False,
            default_batch_compact=True,
            default_error_detail_level="basic",
            _qol_profiles={"balanced": {"mode": "compact", "max_items": 48}},
        )
        args = {"mode": "quick", "query": "decrypt"}
        exec_args, opts = stub._extract_response_options(args)
        # Backend mode survives; the host response mode is separate.
        assert exec_args["mode"] == "quick", exec_args
        assert "query" in exec_args
        assert opts["mode"] == "compact", opts
        assert "_compact" not in exec_args and "compact" not in exec_args
