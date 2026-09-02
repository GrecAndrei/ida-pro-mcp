"""Cross-mode tests for advanced search planning and structured results."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ida_pro_mcp.ida_mcp.tools.search import advanced


def test_advanced_planning_helpers_cover_ranges_tokens_and_scoring(monkeypatch):
    assert advanced._known_const_name(0xAAAAAAAA, {}) == "PATTERN_0xaaaaaaaa"
    assert advanced._known_const_name(7, {7: "SEVEN"}) == "SEVEN"
    assert advanced._known_const_name(7, {}) == ""
    assert advanced._decompiled_query_tokens("the crypto key and key loader 42") == ["crypto", "loader", "key"]
    assert advanced._blob_matches_tokens("Crypto loader", ["crypto", "loader"])
    assert not advanced._blob_matches_tokens("only one", ["only", "missing"])
    assert advanced._coerce_ea("0x123") == 0x123
    assert advanced._coerce_ea("bad") == advanced.idaapi.BADADDR
    assert advanced._function_in_range(SimpleNamespace(start_ea=0x10, end_ea=0x30), 0x20, 0x40)
    assert not advanced._function_in_range(SimpleNamespace(start_ea=0x10, end_ea=0x20), 0x20, 0x40)
    assert advanced._spread_sample_functions([1, 2, 3, 4], set(), 2) == [2, 4]
    assert advanced._spread_sample_functions([1, 2], {1, 2}, 2) == []


def test_advanced_constants_search_real_fake_idb(monkeypatch, fresh_fake_idb):
    import ida_ua

    class _Insn:
        def __init__(self):
            self.ops = [SimpleNamespace(type=ida_ua.o_imm, value=0xAAAAAAAA)]
            self.size = 1

    monkeypatch.setattr(ida_ua, "insn_t", _Insn)
    monkeypatch.setattr(ida_ua, "decode_insn", lambda _insn, ea: 1 if ea == 0x140001000 else 0)
    monkeypatch.setattr(advanced, "resolve_scan_segments", lambda *_args, **_kwargs: ([(0x140001000, 0x140001001)], "", None))
    monkeypatch.setattr(advanced, "get_cached_constant_db", dict)
    result = advanced.search_constants(
        "PATTERN", None, None, True, 0, 10, True, timeout_ms=1000
    )
    assert result["ok"] is True
    assert result["items"][0]["value"] == "0xaaaaaaaa"
    assert result["query"] == "PATTERN"


def test_advanced_decompiled_search_scope_and_bruteforce_modes(monkeypatch, fresh_fake_idb):
    # The fake IDB supplies function/range state; use a string-renderable
    # cfunc so this exercises the same representation consumed by the real
    # decompiled search path.
    monkeypatch.setattr(advanced, "_get_intelligence_index", lambda: (None, None, ""))

    class _Cfunc:
        def __str__(self):
            return "int main() {\\n    return 1;\\n}"

    monkeypatch.setattr(advanced.ida_hexrays, "decompile", lambda _ea: _Cfunc())
    scoped = advanced.search_decompiled(
        "return", False, None, None, 0, 10, True, timeout_ms=1000, addr="0x140001000", preview_lines=1
    )
    assert scoped.get("ok") is True, scoped
    assert scoped.get("scope") == "0x140001000"
    assert scoped.get("items")
    broad = advanced.search_decompiled(
        "return", False, None, None, 0, 10, True, timeout_ms=0, max_functions=2, sample=True
    )
    assert broad.get("ok") is True, broad
    assert broad.get("candidate_strategy") in {"sample", "full", "seeded_sample", "seeded_full"}
    bad = advanced.search_decompiled("return", False, None, None, 0, 10, False, addr="missing")
    assert bad.get("error") is True


def test_advanced_structured_index_and_error_modes(monkeypatch):
    assert advanced.search_structured("bad", None, None, None, False, 0, 5, False)["error"] is True
    assert advanced.search_structured({}, None, None, None, False, 0, 5, False)["error"] is True
    monkeypatch.setattr(advanced, "_get_intelligence_index", lambda: (None, SimpleNamespace(size=0), ""))
    assert advanced.search_structured({"min_size": 4}, None, None, None, False, 0, 5, False)["error"] is True

    class _Index:
        size = 2

        def search_structured(self, constraints, query=None, top_k=None):
            assert constraints["min_size"] == 4
            assert constraints["max_bb"] == 5
            return [
                {
                    "ea": "0x1000",
                    "name": "main",
                    "func_size": 32,
                    "bb_count": 3,
                    "has_loops": True,
                    "api_count": 2,
                    "string_count": 1,
                    "segment": ".text",
                    "is_thunk": False,
                    "cyclomatic": 3,
                }
            ]

    monkeypatch.setattr(advanced, "_get_intelligence_index", lambda: (None, _Index(), ""))
    result = advanced.search_structured(
        {"min_size": 4, "max_bb": 5, "has_loops": True}, "crypto", None, None, False, 0, 5, True
    )
    assert result["ok"] is True
    assert result["items"][0]["has_loops"] is True
    assert "loops" in result["results"]
