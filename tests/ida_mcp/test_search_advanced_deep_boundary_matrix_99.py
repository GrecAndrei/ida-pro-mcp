"""Deep offline coverage for advanced search planning and result shaping."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_submodule  # noqa: E402


class _Func:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end


class _Xref:
    def __init__(self, frm):
        self.frm = frm


class _Insn:
    def __init__(self):
        self.ops = []
        self.size = 1


class _Timer:
    def __init__(self, fail=False, fail_after=None):
        self.fail = fail
        self.calls = 0
        self.fail_after = fail_after

    def check(self):
        self.calls += 1
        if self.fail or (self.fail_after is not None and self.calls > self.fail_after):
            raise TimeoutError("planning timeout")


def _module():
    return load_tool_submodule("search.advanced")


def _response(results, offset, limit, total, truncated, **kwargs):
    return {
        "results": results,
        "offset": offset,
        "limit": limit,
        "total": total,
        "truncated": truncated,
        **kwargs,
    }


def test_advanced_pure_helpers_cover_limits_and_fallbacks():
    adv = _module()
    adv.idaapi.BADADDR = -1
    assert adv._known_const_name(1, {1: "ONE"}) == "ONE"
    assert adv._known_const_name(0x414141, {}) == "PATTERN_0x414141"
    assert adv._known_const_name(0x010203040506, {}) == ""
    assert adv._known_const_name(0xFFFF, {}) == ""
    adv.idautils.Functions = lambda *_args: iter(())
    assert list(adv._iter_function_starts()) == []
    adv.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x1000, 0x1010)], "", "")
    adv.idautils.Functions = lambda *_args: iter([0x1000, 0x1000, 0x1004])
    assert list(adv._iter_function_starts(0x1000, 0x1010)) == [0x1000, 0x1004]
    assert adv._function_in_range(None, 0, 1) is False
    assert adv._function_in_range(_Func(0x2000, 0x2010), 0, 1) is False
    assert adv._function_in_range(_Func(0x1000, 0x1010), 0x1008, 0x1009) is True
    assert adv._decompiled_query_tokens("the Alpha alpha 123 beta_long") == ["beta_long", "alpha"]
    assert adv._blob_matches_tokens("", ["a"]) is False
    assert adv._blob_matches_tokens("alpha", []) is False
    assert adv._blob_matches_tokens("alpha", ["alpha", "beta"]) is False
    assert adv._blob_matches_tokens("alpha beta", ["alpha", "beta"]) is True
    assert adv._coerce_ea("0x10") == 16
    assert adv._coerce_ea("not-an-ea") == -1


def test_intelligence_index_resolution_covers_service_and_host_fallbacks(monkeypatch):
    adv = _module()
    service = types.ModuleType("ida_pro_mcp.services")
    service.get_assembler = lambda: SimpleNamespace(_get_index=lambda path: ("index", path))
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", service)
    adv.idc.get_idb_path = lambda: ""
    asm, idx, path = adv._get_intelligence_index()
    assert asm is not None and idx is None and path == ""
    adv.idc.get_idb_path = lambda: "/tmp/test.i64"
    asm, idx, path = adv._get_intelligence_index()
    assert idx == ("index", "/tmp/test.i64") and path == "/tmp/test.i64"

    service.get_assembler = lambda: (_ for _ in ()).throw(RuntimeError("assembler"))
    assert adv._get_intelligence_index() == (None, None, "")
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", None)
    host = types.ModuleType("host.intelligence.context")
    host.get_assembler = lambda: "host-asm"
    monkeypatch.setitem(sys.modules, "host.intelligence.context", host)
    adv.idc.get_idb_path = lambda: ""
    assert adv._get_intelligence_index() == ("host-asm", None, "")
    monkeypatch.setitem(sys.modules, "host.intelligence.context", None)
    assert adv._get_intelligence_index() == (None, None, "")


def test_seed_candidates_covers_all_sources_and_candidate_guards(monkeypatch):
    adv = _module()
    adv.idaapi.BADADDR = -1
    funcs = {i: _Func(i, i + 0x20) for i in range(0x1000, 0x1100, 0x10)}
    adv._compat.get_func_info = lambda ea: funcs.get(ea)  # noqa: PLW0108
    adv._get_intelligence_index = lambda: (None, None, "")
    adv._iter_function_starts = lambda *_args: iter([0x1020, 0x1020])
    adv.idc.get_func_name = lambda ea: "needle_fn" if ea == 0x1020 else ""
    adv.get_cached_strings = lambda: [
        {"ea": 0x2000, "string": ""},
        {"ea": 0x2001, "string": "needle literal"},
    ]
    adv.get_cached_imports = lambda: [
        {"ea": 0x3000, "name": ""},
        {"ea": 0x3001, "name": "needle_api"},
    ]
    adv.idautils.XrefsTo = lambda ea, _flow: {
        0x2001: [_Xref(0x1040)],
        0x3001: [_Xref(0x1060)],
    }.get(ea, [])
    adv._SEARCH_CACHE.clear()
    adv._SEARCH_CACHE.update({
        "other": "needle",
        "decomp:bad": "needle",
        "decomp:not-an-ea:x": "needle",
        "decomp:4096:sig": "needle pseudocode",
        "decomp:8192:sig": 123,
    })
    def matcher(value):
        return "needle" in str(value).lower()
    ranked, meta = adv._seed_decompiled_candidates("needle query", matcher, None, None, 10, 1000)
    assert ranked == [0x1000, 0x1020, 0x1040, 0x1060]
    assert meta["seed_reasons"]["cached"] == 1
    assert meta["seed_reasons"]["names"] == 1
    assert meta["seed_reasons"]["strings"] == 1
    assert meta["seed_reasons"]["imports"] == 1

    # Guard cases inside add_candidate: BADADDR, missing function, range miss,
    # and a full seed cap are all safe no-ops.
    adv._compat.get_func_info = lambda _ea: None
    ranked, _meta = adv._seed_decompiled_candidates("", matcher, 0, 1, 1, 0)
    assert ranked == []
    adv._SEARCH_CACHE["decomp:-1:sig"] = "needle"
    ranked, _meta = adv._seed_decompiled_candidates("", matcher, None, None, 1, 0)
    assert ranked == []

    # A malformed cache key and an unrelated cached document are ignored.
    adv._SEARCH_CACHE.clear()
    adv._SEARCH_CACHE.update({"decomp:": "needle", "decomp:4096:sig": "other"})
    adv._compat.get_func_info = lambda _ea: _Func(_ea, _ea + 4)
    adv._iter_function_starts = lambda *_args: iter(())
    adv.get_cached_strings = list
    adv.get_cached_imports = list
    ranked, _meta = adv._seed_decompiled_candidates("needle", lambda _v: False, None, None, 1, 1000)
    assert ranked == []


def test_seed_candidates_covers_index_behavior_expansion_and_hit_cap(monkeypatch):
    adv = _module()
    adv.idaapi.BADADDR = -1
    funcs = {i: _Func(i, i + 4) for i in range(0x1000, 0x1200, 4)}
    funcs[0x1300] = _Func(0x1300, 0x1304)
    adv._compat.get_func_info = lambda ea: funcs.get(ea)  # noqa: PLW0108
    adv.get_cached_strings = lambda: [{"ea": 0x8000, "string": "needle"}]
    adv.get_cached_imports = list
    adv._iter_function_starts = lambda *_args: iter(())
    adv.idautils.XrefsTo = lambda _ea, _flow: [_Xref(0x1100)]
    adv._SEARCH_CACHE.clear()

    class Classifier:
        def classify(self, *_args, **_kwargs):
            return [{"behavior": "file_io"}, {"behavior": ""}, {}]

    class Asm:
        def _behavior_classifier(self):
            return Classifier()

    class Index:
        size = 128
        _calls = 0

        def search(self, query, **_kwargs):
            self._calls += 1
            if self._calls == 1:
                return [
                    {"ea": "not-ea", "similarity": 0.0},
                    {"ea": "0x1000", "similarity": 0.5, "lexical_score": 0.2},
                ]
            return [{"ea": "0x1004", "similarity": 0.2, "score": 0.3}]

    index = Index()
    adv._get_intelligence_index = lambda: (Asm(), index, "idb")
    ranked, meta = adv._seed_decompiled_candidates(
        "needle query", lambda _value: True, None, None, 2, 1000
    )
    assert ranked[:2] == [0x1000, 0x1004]
    assert meta["seed_reasons"]["intelligence"] == 1
    assert meta["seed_reasons"]["behavior"] == 1
    assert meta["expansion_queries"] == ["file io"]

    # A full intelligence seed cap exercises the string-side early exits.
    index.size = 0
    adv._get_intelligence_index = lambda: (None, None, "")
    adv._compat.get_func_info = lambda ea: funcs.get(ea)  # noqa: PLW0108
    adv.get_cached_strings = lambda: [{"ea": 0x8000, "string": "needle"}]
    adv.idautils.XrefsTo = lambda _ea, _flow: [_Xref(0x1300)]
    adv._iter_function_starts = lambda *_args: iter(())
    # The cap is fixed at max(128, max_functions * 3), so seed exactly 128
    # distinct functions through cached decomp entries.
    adv._SEARCH_CACHE.clear()
    for _i, ea in enumerate(list(funcs)[:128]):
        adv._SEARCH_CACHE[f"decomp:{ea}:sig"] = "needle"
    ranked, meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert len(ranked) == 128
    assert meta["seed_reasons"]["cached"] == 128


def test_seed_candidate_timeout_and_exception_paths(monkeypatch):
    adv = _module()
    adv.idaapi.BADADDR = -1
    adv._compat.get_func_info = lambda ea: _Func(ea, ea + 4)
    adv._iter_function_starts = lambda *_args: iter([0x1000])
    adv.idc.get_func_name = lambda _ea: "needle"
    adv.get_cached_strings = lambda: [{"ea": 1, "string": "needle"}]
    adv.get_cached_imports = lambda: [{"ea": 2, "name": "needle"}]
    adv.idautils.XrefsTo = lambda _ea, _flow: []
    adv._get_intelligence_index = lambda: (None, None, "")
    adv._SEARCH_CACHE.clear()

    timers = iter((_Timer(fail=True), _Timer(fail=True), _Timer(fail=True), _Timer(fail=True)))
    adv.SearchTimeout = lambda _ms: next(timers)
    for _expected in range(4):
        _ranked, meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
        assert meta["planning_timed_out"] is True

    class BadIndex:
        size = 1

        def search(self, *_args, **_kwargs):
            raise RuntimeError("index failure")

    adv.SearchTimeout = lambda _ms: _Timer()
    adv._get_intelligence_index = lambda: (SimpleNamespace(_behavior_classifier=lambda: None), BadIndex(), "idb")
    ranked, meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert ranked == [0x1000] and meta["planning_timed_out"] is False

    class InitialTimeoutIndex:
        size = 1

        def search(self, *_args, **_kwargs):
            return [{"ea": "0x1000"}]

    adv._get_intelligence_index = lambda: (None, InitialTimeoutIndex(), "idb")
    adv.SearchTimeout = lambda _ms: _Timer(fail=True)
    ranked, meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert ranked == [] and meta["planning_timed_out"] is True

    # Timeout during the primary index scan, followed by timeout in a
    # behavior-expansion scan, exercises both bounded planner exits.
    class OneHitIndex:
        size = 1
        calls = 0

        def search(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                return [{"ea": "0x1000", "similarity": 0.1}]
            return [{"ea": "not-an-ea", "similarity": 0.1}]

    class ExpansionAsm:
        def _behavior_classifier(self):
            return SimpleNamespace(classify=lambda *_args, **_kwargs: [{"behavior": "file_io"}])

    index = OneHitIndex()
    adv._get_intelligence_index = lambda: (ExpansionAsm(), index, "idb")
    adv.SearchTimeout = lambda _ms: _Timer(fail_after=1)
    ranked, meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert ranked == [0x1000]
    assert meta["planning_timed_out"] is True

    index = OneHitIndex()
    adv._get_intelligence_index = lambda: (ExpansionAsm(), index, "idb")
    adv.SearchTimeout = lambda _ms: _Timer()
    ranked, meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert ranked == [0x1000] and meta["planning_timed_out"] is False

    # The intelligence path can also complete without an assembler and then
    # continue into cache/name planning.
    adv._get_intelligence_index = lambda: (None, OneHitIndex(), "idb")
    adv.SearchTimeout = lambda _ms: _Timer()
    ranked, _meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert ranked

    # An outer planning-source failure is isolated from the caller.
    adv._get_intelligence_index = lambda: (None, None, "")
    adv._iter_function_starts = lambda *_args: iter(())
    adv.get_cached_strings = lambda: (_ for _ in ()).throw(RuntimeError("strings"))
    ranked, meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert ranked == [] and meta["planning_timed_out"] is False


def test_seed_candidate_source_timeouts_and_xref_caps():
    adv = _module()
    adv.idaapi.BADADDR = -1
    adv._get_intelligence_index = lambda: (None, None, "")
    adv._iter_function_starts = lambda *_args: iter(())
    adv._SEARCH_CACHE.clear()
    adv.get_cached_strings = lambda: [{"ea": 1, "string": "needle"}]
    adv.get_cached_imports = list
    adv.SearchTimeout = lambda _ms: _Timer(fail=True)
    _ranked, meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert meta["planning_timed_out"] is True

    adv.get_cached_strings = list
    adv.get_cached_imports = lambda: [{"ea": 2, "name": "needle"}]
    _ranked, meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert meta["planning_timed_out"] is True

    adv.SearchTimeout = lambda _ms: _Timer()
    adv._compat.get_func_info = lambda ea: _Func(ea, ea + 4)
    adv.idautils.XrefsTo = lambda _ea, _flow: [_Xref(i) for i in range(65)]
    adv.get_cached_strings = lambda: [{"ea": 1, "string": "needle"}]
    adv.get_cached_imports = list
    ranked, meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert len(ranked) == 64

    adv.get_cached_strings = list
    adv.get_cached_imports = lambda: [{"ea": 2, "name": "needle"}]
    ranked, _meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert len(ranked) == 64

    adv._SEARCH_CACHE.clear()
    for _i, ea in enumerate(range(128)):
        adv._SEARCH_CACHE[f"decomp:{ea}:sig"] = "needle"
    adv._iter_function_starts = lambda *_args: iter(())
    adv.get_cached_strings = list
    adv.get_cached_imports = lambda: [{"ea": 2, "name": "needle"}]
    ranked, _meta = adv._seed_decompiled_candidates("needle", lambda _v: True, None, None, 1, 1000)
    assert len(ranked) == 128


def test_spread_sampling_and_constant_scan_boundaries(monkeypatch):
    adv = _module()
    assert adv._spread_sample_functions([1, 2], {1, 2}, 0) == []
    assert adv._spread_sample_functions([1, 2], {1}, 10) == [2]

    adv.idaapi.BADADDR = -1
    adv.ida_ua.insn_t = _Insn
    adv.ida_ua.o_imm = 5
    adv.resolve_scan_segments = lambda *_args, **_kwargs: ([], "", "bad range")
    assert adv.search_constants("x", None, None, False, 0, 10, False)["code"] == "NOT_FOUND"

    adv.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x1000, 0x1003)], "note", "")
    adv.get_cached_constant_db = lambda: {0x1234: "MAGIC"}
    adv._compat.get_func_start = lambda _ea: None
    adv.ida_funcs.get_func_name = lambda _ea: "unknown"
    adv.compile_smart_pattern = lambda *_args, **_kwargs: lambda _value: False
    adv.ida_ua.decode_insn = lambda insn, _ea: setattr(insn, "ops", [SimpleNamespace(type=5, value=0x1234)]) or setattr(insn, "size", 1) or 1
    adv.idc.next_head = lambda _ea, _end: -1
    assert adv.search_constants("reject", None, None, False, 0, 10, False)["count"] == 0

    # A successful known constant covers context and item shaping.
    adv.compile_smart_pattern = lambda *_args, **_kwargs: lambda _value: True
    adv._compat.get_func_start = lambda _ea: None
    adv.safe_generate_disasm_line = lambda _ea: "mov eax, 0x1234"
    adv.ida_lines.tag_remove = lambda text: text
    adv.ida_ua.decode_insn = lambda insn, _ea: setattr(insn, "ops", [SimpleNamespace(type=5, value=0x1234)]) or setattr(insn, "size", 1) or 1
    result = adv.search_constants("MAGIC", None, None, True, 0, 10, True)
    assert result["count"] == 3
    assert result["items"][0]["name"] == "MAGIC"


def test_constant_pair_error_and_badaddr_paths(monkeypatch):
    adv = _module()
    adv.idaapi.BADADDR = -1
    adv.ida_ua.insn_t = _Insn
    adv.ida_ua.o_imm = 5
    adv.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x2000, 0x2004)], "", "")
    adv.get_cached_constant_db = dict
    adv.compile_smart_pattern = lambda *_args, **_kwargs: lambda _value: True
    adv.idc.next_head = lambda *_args: -1

    class Decode:
        def __init__(self):
            self.calls = 0

        def __call__(self, insn, _ea):
            self.calls += 1
            insn.size = 1
            insn.ops = []
            return 1 if self.calls <= 2 else 0

    adv.ida_ua.decode_insn = Decode()
    adv.riscv_lui_addi_pair = lambda *_args: (0x123456, 0x2001)
    adv._known_const_name = lambda value, _known: "PATTERN" if value == 0x123456 else ""
    adv._compat.get_func_start = lambda _ea: None
    adv.ida_funcs.get_func_name = lambda _ea: "unknown"
    assert adv.search_constants(None, None, None, False, 0, 10, False)["count"] == 1

    adv.ida_ua.decode_insn = Decode()
    adv._known_const_name = lambda *_args: ""
    assert adv.search_constants(None, None, None, False, 0, 10, False)["count"] == 0
    adv.ida_ua.decode_insn = Decode()
    adv._known_const_name = lambda *_args: "PATTERN"
    adv.compile_smart_pattern = lambda *_args, **_kwargs: lambda _value: False
    assert adv.search_constants("reject", None, None, False, 0, 10, False)["count"] == 0

    adv.riscv_lui_addi_pair = lambda *_args: (_ for _ in ()).throw(RuntimeError("pair"))
    adv.ida_ua.decode_insn = lambda insn, _ea: setattr(insn, "ops", []) or setattr(insn, "size", 1) or 1
    assert adv.search_constants(None, None, None, False, 0, 10, False)["count"] == 0
    adv.ida_ua.decode_insn = lambda *_args: 0
    adv.idc.next_head = lambda *_args: -1
    assert adv.search_constants(None, None, None, False, 0, 10, False)["count"] == 0
    adv.idc.next_head = lambda ea, _end: ea + 1
    assert adv.search_constants(None, None, None, False, 0, 10, False)["count"] == 0


def test_search_decompiled_unavailable_scope_and_failure_envelopes(monkeypatch):
    adv = _module()
    adv.ida_hexrays.init_hexrays_plugin = lambda: False
    unavailable = adv.search_decompiled("x", False, None, None, 0, 10, False)
    assert unavailable["code"] == "DECOMPILER_UNAVAILABLE"

    adv.ida_hexrays.init_hexrays_plugin = lambda: True
    adv._get_intelligence_index = lambda: (None, None, "")
    adv.validate_addr = lambda _value: (-1, "bad")
    adv.idc.get_name_ea_simple = lambda _value: -1
    adv._compat.get_func_start = lambda _ea: None
    assert adv.search_decompiled("x", False, None, None, 0, 10, False, addr="bad")["code"] == "FUNCTION_NOT_FOUND"

    adv._iter_function_starts = lambda *_args: iter([0x1000, 0x2000])
    adv.ida_hexrays.decompile = lambda _ea: None
    adv.idc.get_func_name = lambda ea: f"sub_{ea:x}"
    adv.idc.get_type = lambda _ea: None
    failure = adv.search_decompiled("x", False, None, None, 0, 10, False, max_functions="bad")
    assert failure["code"] == "DECOMPILER_FAILED"
    assert failure["details"]["failures"] == 2

    adv.ida_hexrays.decompile = lambda _ea: (_ for _ in ()).throw(RuntimeError("decompile boom"))
    adv._iter_function_starts = lambda *_args: iter(range(6))
    failure = adv.search_decompiled("x", False, None, None, 0, 10, False, intelligence_backfill="bad")
    assert failure["code"] == "DECOMPILER_FAILED"
    assert failure["details"]["sample_errors"] == ["decompile boom"] * 5


def test_search_decompiled_success_cache_preview_index_and_modes(monkeypatch):
    adv = _module()
    adv.idaapi.BADADDR = -1
    adv.ida_hexrays.init_hexrays_plugin = lambda: True
    adv.compile_smart_pattern = lambda pattern, **_kwargs: lambda line: pattern.lower() in line.lower()
    adv.idc.get_func_name = lambda ea: "" if ea == 0x1000 else f"fn_{ea:x}"
    adv.idc.get_type = lambda _ea: "int fn()"
    adv._compat.get_func_start = lambda ea: ea
    adv._compat.get_func_info = lambda ea: _Func(ea, ea + 4)
    adv.ida_hexrays.decompile = lambda ea: "header\nneedle line\ntail" if ea != 0x3000 else ""
    adv._iter_function_starts = lambda *_args: iter([0x1000, 0x2000])
    adv._get_intelligence_index = lambda: (None, None, "")
    adv._SEARCH_CACHE.clear()
    result = adv.search_decompiled(
        "needle", False, None, None, 0, 10, True, timeout_ms="bad", max_functions="bad", preview_lines="bad"
    )
    assert result["count"] == 2
    assert result["items"][0].get("context") is None
    assert result["note"].startswith("No embedding index")

    # An index seeds a duplicate candidate and backfill failures are nonfatal.
    class Index:
        size = 1
        _cache = {}

        def index_async(self, *_args):
            raise RuntimeError("backfill")

    idx = Index()
    adv._get_intelligence_index = lambda: (SimpleNamespace(), idx, "idb")
    adv._seed_decompiled_candidates = lambda *_args: (
        [0x1000, 0x1000, 0x2000],
        {"seeded_candidates": 2, "seed_reasons": {}, "tokens": [], "planning_timed_out": True, "intelligence_index_size": 1, "expansion_queries": []},
    )
    adv.ida_hexrays.decompile = lambda _ea: "needle"  # noqa: ARG005
    seeded = adv.search_decompiled("needle", False, None, None, 0, 1, True, timeout_ms=0, max_functions=2)
    assert seeded["count"] == 1
    assert seeded["planning_timed_out"] is True

    mixed = _module()
    mixed.idaapi.BADADDR = -1
    mixed.ida_hexrays.init_hexrays_plugin = lambda: True
    mixed._get_intelligence_index = lambda: (None, None, "")
    mixed._iter_function_starts = lambda *_args: iter([0x1000, 0x2000])
    mixed.compile_smart_pattern = lambda *_args, **_kwargs: lambda line: "needle" in line
    mixed.idc.get_func_name = lambda ea: f"fn_{ea:x}"
    mixed.idc.get_type = lambda _ea: None
    mixed.ida_hexrays.decompile = lambda ea: "needle" if ea == 0x1000 else "no match"
    mixed._SEARCH_CACHE.clear()
    result = mixed.search_decompiled("needle", False, None, None, 0, 10, False)
    assert result["count"] == 1


def test_search_decompiled_sampling_and_timeout_hints(monkeypatch):
    adv = _module()
    adv.idaapi.BADADDR = -1
    adv.ida_hexrays.init_hexrays_plugin = lambda: True
    adv._get_intelligence_index = lambda: (None, None, "")
    adv.compile_smart_pattern = lambda *_args, **_kwargs: lambda _line: True
    adv._iter_function_starts = lambda *_args: iter([1, 2, 3, 4])
    adv._spread_sample_functions = lambda funcs, seen, remaining: [ea for ea in funcs if ea not in seen][:remaining]
    adv.idc.get_func_name = lambda ea: f"fn_{ea}"
    adv.idc.get_type = lambda _ea: None
    adv.ida_hexrays.decompile = lambda _ea: "needle"
    adv._SEARCH_CACHE.clear()
    sample = adv.search_decompiled("needle", False, None, None, 0, 10, False, sample=True, max_functions=2)
    assert sample["candidate_strategy"] == "sample"
    assert sample["analysis_truncated"] is True
    assert "Increase max_functions" in sample["hint"]

    adv._get_intelligence_index = lambda: (None, SimpleNamespace(size=1), "idb")
    adv._iter_function_starts = lambda *_args: iter([1, 2, 3])
    adv._seed_decompiled_candidates = lambda *_args: (
        [1], {"seeded_candidates": 1, "seed_reasons": {}, "tokens": [], "planning_timed_out": False, "intelligence_index_size": 1, "expansion_queries": []}
    )
    full = adv.search_decompiled("needle", False, None, None, 0, 10, False, max_functions=3)
    assert full["candidate_strategy"] == "seeded_full"

    adv._get_intelligence_index = lambda: (None, SimpleNamespace(size=1), "idb")
    adv._seed_decompiled_candidates = lambda *_args: (
        [1], {"seeded_candidates": 1, "seed_reasons": {}, "tokens": [], "planning_timed_out": True, "intelligence_index_size": 1, "expansion_queries": []}
    )
    timed = adv.search_decompiled("needle", False, None, None, 0, 10, False, timeout_ms=100, max_functions=1)
    assert timed["planning_timed_out"] is True


def test_structured_search_validates_constraints_and_shapes_rows():
    adv = _module()
    adv.idaapi.BADADDR = -1
    adv._get_intelligence_index = lambda: (None, None, "")
    assert adv.search_structured([], "x", None, None, False, 0, 5, False)["code"] == "INVALID_ARGS"
    assert adv.search_structured({}, None, None, None, False, 0, 5, False)["code"] == "INVALID_ARGS"
    empty = adv.search_structured({"min_size": 1}, None, None, None, False, 0, 5, False)
    assert empty["code"] == "NOT_FOUND"

    class Index:
        size = 2

        def __init__(self):
            self.query = None

        def search_structured(self, constraints, query=None, top_k=None):
            self.query = (constraints, query, top_k)
            return [
                {"ea": "0x1000", "name": "a", "func_size": 4, "bb_count": 2, "api_count": 1,
                 "has_loops": True, "segment": ".text", "string_count": 3, "is_thunk": False, "cyclomatic": 2},
                {"ea": "0x2000", "name": "b", "func_size": 8, "bb_count": 1, "api_count": 0,
                 "has_loops": False, "segment": "", "string_count": 0, "is_thunk": True, "cyclomatic": 1},
            ]

    index = Index()
    adv._get_intelligence_index = lambda: (None, index, "idb")
    constraints = {
        "size": (">=", 4), "max_size": 9, "bb_count": 1, "max_bb": 4,
        "has_loops": True, "api_count": 1, "max_api": 2, "string_count": 2,
        "max_strings": 4, "segment": ".text", "is_thunk": False,
        "cyclomatic": 2, "max_cyclomatic": 4, "apis": ["read"],
    }
    result = adv.search_structured(constraints, "needle", None, None, False, 1, 1, True)
    assert result["count"] == 1
    assert result["items"][0]["has_loops"] is False
    assert index.query[1:] == ("needle", 2)
