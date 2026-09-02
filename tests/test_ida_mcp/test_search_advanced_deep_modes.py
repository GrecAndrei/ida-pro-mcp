"""Deep planner and compatibility coverage for advanced searches."""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest

from ida_pro_mcp.ida_mcp.tools.search import advanced


def test_function_range_and_intelligence_index_compatibility(monkeypatch):
    monkeypatch.setattr(advanced, "resolve_scan_segments", lambda *_args, **_kwargs: ([(10, 20), (20, 30)], "", ""))
    monkeypatch.setattr(advanced.idautils, "Functions", lambda *_args: iter([11, 11, 21]))
    assert list(advanced._iter_function_starts(10, 30)) == [11, 21]
    assert list(advanced._iter_function_starts()) == [11, 11, 21]
    assert advanced._function_in_range(None, 1, 2) is False

    service = types.ModuleType("ida_pro_mcp.services")
    assembler = SimpleNamespace(_get_index=lambda path: {"path": path})
    service.get_assembler = lambda: assembler
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", service)
    monkeypatch.delattr(advanced.idc, "get_idb_path", raising=False)
    assert advanced._get_intelligence_index() == (assembler, None, "")
    monkeypatch.setattr(advanced.idc, "get_idb_path", lambda: "/tmp/sample.i64", raising=False)
    assert advanced._get_intelligence_index() == (assembler, {"path": "/tmp/sample.i64"}, "/tmp/sample.i64")

    service.get_assembler = lambda: (_ for _ in ()).throw(RuntimeError("backend unavailable"))
    assert advanced._get_intelligence_index() == (None, None, "")


def test_seed_planner_combines_cache_names_strings_imports_and_behavior(monkeypatch, fresh_fake_idb):
    advanced._SEARCH_CACHE.clear()
    advanced._cache_set(advanced._cache_key("decomp", 0x140001050, "sig"), "crypto pseudocode")
    advanced._cache_set("not-decomp", "crypto")
    monkeypatch.setattr(
        advanced._compat,
        "get_func_info",
        lambda ea: SimpleNamespace(start_ea=ea, end_ea=ea + 16) if ea != advanced.idaapi.BADADDR else None,
    )
    monkeypatch.setattr(advanced, "_iter_function_starts", lambda *_args: iter([0x140001000, 0x140001060, 0x140001070, 0x140001080, 0x140001090]))
    monkeypatch.setattr(advanced.idc, "get_func_name", lambda ea: {0x140001000: "crypto_entry", 0x140001070: "crypto_name"}.get(ea, ""))
    monkeypatch.setattr(advanced, "get_cached_strings", lambda: [{"ea": 0x140002010, "string": "crypto string"}])
    monkeypatch.setattr(advanced, "get_cached_imports", lambda: [{"ea": 0x140002020, "name": "crypto_api"}])
    monkeypatch.setattr(
        advanced.idautils,
        "XrefsTo",
        lambda ea, *_args: [SimpleNamespace(frm=0x140001080 if ea == 0x140002010 else 0x140001090)] if ea in {0x140002010, 0x140002020} else [],
    )

    class _Classifier:
        _anchor_embs = {"crypto": object()}

        def classify(self, *_args, **_kwargs):
            return [{"behavior": "crypto_symmetric", "confidence": 0.9}]

    class _Index:
        size = 12

        def search(self, query, **_kwargs):
            if query == "crypto symmetric":
                return [{"ea": "0x140001060", "similarity": 0.8, "lexical_score": 0.2}]
            return [
                {"ea": "not-an-ea", "similarity": 0.2},
                {"ea": "0x140001000", "similarity": 0.7, "score": 0.1},
            ]

    asm = SimpleNamespace(_behavior_classifier=_Classifier)
    monkeypatch.setattr(advanced, "_get_intelligence_index", lambda: (asm, _Index(), "/tmp/idb"))
    ranked, meta = advanced._seed_decompiled_candidates(
        "crypto", lambda text: "crypto" in text.lower(), None, None, 4, 2000
    )
    assert ranked
    assert meta["intelligence_index_size"] == 12
    assert meta["expansion_queries"] == ["crypto symmetric"]
    assert meta["seed_reasons"]["intelligence"] >= 1
    assert meta["seed_reasons"]["cached"] >= 1
    assert meta["seed_reasons"]["names"] >= 1
    assert meta["seed_reasons"]["strings"] >= 1
    assert meta["seed_reasons"]["imports"] >= 1
    assert meta["seed_reasons"]["behavior"] >= 1


def test_seed_planner_timeout_and_sample_fallback(monkeypatch):
    class _Expired:
        def __init__(self, _budget):
            pass

        def check(self):
            raise TimeoutError

    monkeypatch.setattr(advanced, "SearchTimeout", _Expired)
    monkeypatch.setattr(advanced, "_get_intelligence_index", lambda: (None, None, ""))
    ranked, meta = advanced._seed_decompiled_candidates(
        "needle", lambda _text: True, None, None, 2, 0
    )
    assert ranked == []
    assert meta["planning_timed_out"] is True


def test_advanced_helpers_and_constant_error_timeout_modes(monkeypatch, fresh_fake_idb):
    monkeypatch.setattr(advanced.idc, "get_func_name", lambda _ea: "")
    monkeypatch.setattr(advanced.idc, "get_type", lambda _ea: "")
    assert advanced._decomp_cache_mod_sig(0x1000) == "|"
    monkeypatch.setattr(advanced.idc, "get_type", lambda _ea: (_ for _ in ()).throw(RuntimeError("bad")))
    assert advanced._decomp_cache_mod_sig(0x1000) == ""

    assert advanced._spread_sample_functions([1, 2], set(), 0) == []
    assert advanced.search_constants(
        "x", None, None, False, 0, 10, False, timeout_ms=0
    )["ok"] is True

    class _Expired:
        def __init__(self, _budget):
            pass

        def check(self):
            raise TimeoutError

    monkeypatch.setattr(advanced, "SearchTimeout", _Expired)
    monkeypatch.setattr(advanced, "resolve_scan_segments", lambda *_a, **_k: ([(0x1000, 0x1010)], "", None))
    result = advanced.search_constants(None, None, None, False, 0, 10, True, timeout_ms=10)
    assert result["timed_out"] is True
    assert result["items"] == []


def test_search_constants_exercises_pair_filter_and_decode_fallback(monkeypatch, fresh_fake_idb):
    import ida_ua

    class _Insn:
        def __init__(self):
            self.ops = []
            self.size = 1

    def decode(insn, ea):
        if ea == 0x1000:
            insn.ops = [SimpleNamespace(type=99, value=0)]
            return 1
        if 0x1000 <= ea <= 0x1002:
            insn.ops = []
            return 1
        return 0

    monkeypatch.setattr(ida_ua, "insn_t", _Insn)
    monkeypatch.setattr(ida_ua, "decode_insn", decode)
    monkeypatch.setattr(advanced, "resolve_scan_segments", lambda *_a, **_k: ([(0x1000, 0x1003)], "bounded", None))
    monkeypatch.setattr(advanced, "get_cached_constant_db", dict)
    monkeypatch.setattr(advanced, "riscv_lui_addi_pair", lambda *_a: (0xAAAAAAAA, 0x1001))
    monkeypatch.setattr(advanced._compat, "get_func_start", lambda _ea: None)
    monkeypatch.setattr(advanced.ida_funcs, "get_func_name", lambda _ea: "unknown")
    monkeypatch.setattr(advanced, "safe_generate_disasm_line", lambda _ea: "lui; addi")
    result = advanced.search_constants(
        "PATTERN", None, None, True, 0, 1, True, timeout_ms=1000
    )
    assert result["ok"] is True
    assert result["truncated"] is True
    assert result["items"][0]["name"] == "PATTERN_0xaaaaaaaa"
    assert "bounded" in result["note"]


def test_search_decompiled_unavailable_and_failure_envelopes(monkeypatch, fresh_fake_idb):
    monkeypatch.setattr(advanced.ida_hexrays, "init_hexrays_plugin", lambda: False)
    unavailable = advanced.search_decompiled("x", False, None, None, 0, 5, False)
    assert unavailable["code"] == "DECOMPILER_UNAVAILABLE"

    monkeypatch.setattr(advanced.ida_hexrays, "init_hexrays_plugin", lambda: True)
    monkeypatch.setattr(advanced, "_get_intelligence_index", lambda: (None, None, ""))
    monkeypatch.setattr(advanced, "_iter_function_starts", lambda *_a: iter([0x1000, 0x1001]))
    monkeypatch.setattr(advanced.ida_hexrays, "decompile", lambda ea: None if ea == 0x1000 else (_ for _ in ()).throw(RuntimeError("broken")))
    failed = advanced.search_decompiled(
        "x", False, None, None, 0, 5, False, timeout_ms="bad", max_functions="bad", preview_lines="bad"
    )
    assert failed["code"] == "DECOMPILER_FAILED"
    assert failed["details"]["failures"] == 2


def test_search_decompiled_index_backfill_preview_and_timeout_modes(monkeypatch, fresh_fake_idb):
    monkeypatch.setattr(advanced.ida_hexrays, "init_hexrays_plugin", lambda: True)
    monkeypatch.setattr(advanced, "_seed_decompiled_candidates", lambda *_a: (
        [0x1000], {"seeded_candidates": 1, "seed_reasons": {}, "tokens": ["needle"], "intelligence_index_size": 3, "expansion_queries": []}
    ))
    monkeypatch.setattr(advanced, "_iter_function_starts", lambda *_a: iter([0x1000, 0x2000]))
    monkeypatch.setattr(advanced.idc, "get_func_name", lambda ea: "entry" if ea == 0x1000 else "other")
    monkeypatch.setattr(advanced.idc, "get_type", lambda _ea: "int f(void)")
    monkeypatch.setattr(advanced._compat, "get_func_start", lambda ea: SimpleNamespace(start_ea=ea, end_ea=ea + 8))
    monkeypatch.setattr(advanced.ida_hexrays, "decompile", lambda _ea: "void f()\nneedle\nneedle")
    indexed = SimpleNamespace(size=3, _cache={}, index_async=lambda *args: None)
    monkeypatch.setattr(advanced, "_get_intelligence_index", lambda: (SimpleNamespace(), indexed, "/tmp/x"))
    result = advanced.search_decompiled(
        "needle", False, None, None, 0, 10, True, timeout_ms=999999,
        max_functions=1, preview_lines=2, intelligence_backfill=1,
    )
    assert result["ok"] is True
    assert result["items"][0]["matched_lines"] == 2
    assert result["items"][0]["context"]
    assert result["intelligence_backfilled"] == 1
    assert result["candidate_strategy"] == "seeded"

    times = iter([0.0, 1.0])
    monkeypatch.setattr(advanced._time, "time", lambda: next(times))
    monkeypatch.setattr(advanced, "_seed_decompiled_candidates", lambda *_a: ([], {"tokens": []}))
    timed = advanced.search_decompiled("needle", False, None, None, 0, 10, False, timeout_ms=250)
    assert timed["timed_out"] is True
    assert timed["analysis_truncated"] is True


def test_search_structured_maps_all_legacy_constraints_and_renders_optional_fields(monkeypatch):
    captured = {}

    class _Index:
        size = 4

        def search_structured(self, constraints, query=None, top_k=None):
            captured.update(constraints)
            captured["query"] = query
            captured["top_k"] = top_k
            return [
                {"ea": "0x1000", "name": "f", "func_size": 20, "bb_count": 3,
                 "api_count": 4, "has_loops": True, "segment": ".text",
                 "string_count": 2, "is_thunk": True, "cyclomatic": 5},
                {"ea": "0x2000", "name": "g", "func_size": 30, "bb_count": 4,
                 "api_count": 5, "has_loops": False, "segment": "", "string_count": 3,
                 "is_thunk": False, "cyclomatic": 6},
            ]

    monkeypatch.setattr(advanced, "_get_intelligence_index", lambda: (None, _Index(), ""))
    result = advanced.search_structured(
        {"min_size": 1, "max_size": 40, "bb_count": 2, "max_bb": 5,
         "has_loops": True, "api_count": 1, "max_api": 9,
         "string_count": 1, "max_strings": 9, "segment": ".text",
         "is_thunk": True, "cyclomatic": 2, "max_cyclomatic": 9,
         "apis": ["memcpy"]},
        "needle", None, None, False, 1, 1, True,
    )
    assert result["ok"] is True
    assert result["truncated"] is False
    assert result["items"][0]["is_thunk"] is False
    assert "loops" not in result["results"][0]
    assert captured["min_size"] == 1
    assert captured["max_size"] == 40
    assert captured["min_bb"] == 2
    assert captured["max_cyclomatic"] == 9
    assert captured["query"] == "needle"
    assert captured["top_k"] == 2


@pytest.mark.parametrize("constraint", [
    {"size": ("<=", 10)},
    {"min_size": 1, "size": 2},
    {"max_size": 10},
])
def test_search_structured_constraint_aliases_are_forwarded(monkeypatch, constraint):
    class _Index:
        size = 1

        def search_structured(self, constraints, **_kwargs):
            return []

    seen = {}
    monkeypatch.setattr(advanced, "_get_intelligence_index", lambda: (None, _Index(), ""))
    original = _Index.search_structured
    monkeypatch.setattr(_Index, "search_structured", lambda self, constraints, **kwargs: (seen.update(constraints) or original(self, constraints, **kwargs)))
    advanced.search_structured(constraint, None, None, None, False, 0, 2, False)
    assert seen
