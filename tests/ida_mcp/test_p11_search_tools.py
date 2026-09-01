"""Regression tests for p11_search_tools audit fixes.

Covers search_path TypeError, next_head BADADDR hang guards, size-rule AND
semantics, search_find heap dict-comparison, query_lang tool resolution and
error envelope, search_structured envelope, decompiled preview_lines guard,
include_items, and dead-code removal.
"""

from __future__ import annotations

import re
import struct
import sys
import threading
import types
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import (  # noqa: E402
    install_common_stub,
    load_support_module,
    load_tool_submodule,
)

REPO = TESTS.parent
SEARCH = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "search"


class _Func:
    def __init__(self, start: int, end: int):
        self.start_ea = start
        self.end_ea = end

    def size(self) -> int:
        return self.end_ea - self.start_ea


def _module(modname: str):
    return load_tool_submodule(modname)


# ---------------------------------------------------------------------------
# search_path — TypeError on a found path
# ---------------------------------------------------------------------------

def test_search_path_returns_text_for_found_path():
    comb = _module("search.combinators")
    comb.idaapi.BADADDR = -1

    funcs = {0x1000: _Func(0x1000, 0x1001), 0x2000: _Func(0x2000, 0x2001)}
    comb.idaapi.get_func = funcs.get
    comb.ida_funcs.get_func = funcs.get
    comb.idc.get_func_name = lambda ea: {0x1000: "src", 0x2000: "dst"}.get(ea, "")
    comb._func_name = lambda ea: {0x1000: "src", 0x2000: "dst"}.get(ea, hex(ea))
    comb.resolve_target = lambda raw, *a, **k: (
        {"src": (0x1000, None, {}), "dst": (0x2000, None, {})}.get(raw, (-1, "not found", {}))
    )
    comb._func_callees = lambda fea: {0x1000: {0x2000}}.get(fea, set())

    resp = comb.search_path("src", "dst", 5)
    assert resp["ok"] is True
    assert resp["count"] == 2
    assert "0x1000" in resp["results"]
    assert "0x2000" in resp["results"]
    assert resp["items"][0]["addr"] == "0x1000"


# ---------------------------------------------------------------------------
# _match_size_rule — comparator preserved, range only without comparator
# ---------------------------------------------------------------------------

def _match_size_rule():
    core = _module("search.core")
    return core._match_size_rule


def test_match_size_rule_range_only_without_comparator():
    mr = _match_size_rule()
    assert mr(150, "=", 100, 200) is True
    assert mr(50, "=", 100, 200) is False
    assert mr(100, "=", 100, None) is True


def test_match_size_rule_comparator_not_dropped_by_range():
    mr = _match_size_rule()
    # >100-200 means (100, 200), not the plain range [100, 200]
    assert mr(150, ">", 100, 200) is True
    assert mr(90, ">", 100, 200) is False
    assert mr(250, ">", 100, 200) is False
    # plain comparators
    assert mr(150, ">", 100, None) is True
    assert mr(90, "<", 100, None) is True


# ---------------------------------------------------------------------------
# _prim_size — multiple size rules are AND, not OR
# ---------------------------------------------------------------------------

def test_prim_size_rules_are_and():
    comb = _module("search.combinators")
    comb.idaapi.BADADDR = -1
    funcs = {0x1: _Func(0, 50), 0x2: _Func(0, 150)}
    comb.idaapi.get_func = funcs.get
    comb.ida_funcs.get_func = funcs.get
    comb.idautils.Functions = lambda: [0x1, 0x2]

    # >100 <200: only size 150 satisfies both
    assert comb._prim_size(">100 <200") == {0x2}
    # single range [100, 200]
    assert comb._prim_size("100-200") == {0x2}
    # a comparator is not dropped when a range bound is present
    assert comb._prim_size(">100-200") == {0x2}


# ---------------------------------------------------------------------------
# search_func_by_sig — size rules are AND
# ---------------------------------------------------------------------------

def test_search_func_by_sig_size_rules_are_and():
    refs = _module("search.refs")
    refs.idaapi.BADADDR = -1
    funcs = {0x1: _Func(0, 50), 0x2: _Func(0, 150)}
    refs.idaapi.get_func = funcs.get
    refs.ida_funcs.get_func = funcs.get
    refs.idautils.Functions = lambda: [0x1, 0x2]
    refs.ida_funcs.get_func_name = lambda ea: f"f{ea}"
    refs.idautils.XrefsTo = lambda *a, **k: []
    refs.idautils.XrefsFrom = lambda *a, **k: []
    refs.compile_smart_pattern = lambda p, **k: (lambda s: p in str(s))

    resp = refs.search_func_by_sig("size:>100 size:<200", 0, 50)
    assert "0x1" not in resp["results"], "size 50 must fail the >100 rule"
    assert "0x2" in resp["results"]


# ---------------------------------------------------------------------------
# next_head BADADDR guards terminate every scan loop
# ---------------------------------------------------------------------------

def _assert_terminates(fn, *args):
    done = threading.Event()

    def _run():
        fn(*args)
        done.set()

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    assert done.wait(timeout=1), "scan loop failed to terminate on BADADDR"
    worker.join(timeout=1)
    assert not worker.is_alive()


def test_search_insns_terminates_on_badaddr():
    code = _module("search.code")
    code.idaapi.BADADDR = -1
    code.resolve_scan_segments = lambda a, b, require_exec=True: ([(0x1000, 0x1010)], "", "")
    code.idc.next_head = lambda ea, end: -1  # always BADADDR
    code.ida_bytes.is_code = lambda fl: False
    code.ida_bytes.get_flags = lambda ea: 0
    code.build_response = lambda *a, **k: {"ok": True}
    _assert_terminates(code.search_insns, "mov", None, None, False, 0, 10)


def test_search_comment_terminates_on_badaddr():
    code = _module("search.code")
    code.idaapi.BADADDR = -1
    code.iter_segments = lambda a, b, require_exec=False: [(0x1000, 0x1010)]
    code.idc.next_head = lambda ea, end: -1
    code.idc.get_cmt = lambda ea, t: None
    code.build_response = lambda *a, **k: {"ok": True}
    _assert_terminates(code.search_comment, "x", True, None, None, 0, 10)


def test_search_constants_terminates_on_badaddr():
    adv = _module("search.advanced")
    adv.idaapi.BADADDR = -1
    adv.resolve_scan_segments = lambda a, b, require_exec=True: ([(0x1000, 0x1010)], "", "")
    adv.idc.next_head = lambda ea, end: -1
    adv.ida_ua.insn_t = type("I", (), {})
    adv.ida_ua.decode_insn = lambda insn, ea: 0
    adv.get_cached_constant_db = dict
    adv.paginate_records = lambda rows, off, lim, **k: (rows, len(rows), False)
    adv.build_response = lambda *a, **k: {"ok": True}
    adv.idaapi.get_func = lambda ea: None
    adv.ida_funcs.get_func = adv.idaapi.get_func
    _assert_terminates(adv.search_constants, "x", None, None, False, 0, 10, False)


def test_prim_funcs_by_mnem_terminates_on_badaddr():
    comb = _module("search.combinators")
    comb.idaapi.BADADDR = -1
    comb.idaapi.get_func = lambda ea: _Func(0x1000, 0x1010)
    comb.ida_funcs.get_func = comb.idaapi.get_func
    comb.idautils.Functions = lambda: [0x1]
    comb.idc.next_head = lambda ea, end: -1
    comb.idc.print_insn_mnem = lambda ea: "nop"
    comb.compile_smart_pattern = lambda p, **k: (lambda s: p in str(s))
    _assert_terminates(comb._prim_funcs_by_mnem, "mov")


def test_search_immediate_terminates_on_badaddr():
    basic = _module("search.basic")
    basic.idaapi.BADADDR = -1
    basic.resolve_scan_segments = lambda a, b, require_exec=True: ([(0x1000, 0x1010)], "", "")
    basic.idc.next_head = lambda ea, end: -1
    basic.ida_ua.insn_t = type("I", (), {})
    basic.ida_ua.decode_insn = lambda insn, ea: 0
    basic.build_response = lambda *a, **k: {"ok": True}
    basic.resolve_target = lambda p, **k: (0x1234, None, {})
    _assert_terminates(basic.search_immediate, "0x1234", None, None, False, 0, 10)


# ---------------------------------------------------------------------------
# search_data_value — raw pointer-word scan (WO-S6)
# ---------------------------------------------------------------------------

def _config_data_value_ida(basic, blob, base=0x1000, end=None):
    if end is None:
        end = base + len(blob)

    def _segments(a=None, b=None, require_exec=False):
        start = base if a is None else a
        stop = end if b is None else b
        s, e = max(base, start), min(end, stop)
        return [(s, e)] if s < e else []

    sys.modules["ida_bytes"].get_bytes = (
        lambda ea, n: bytes(blob[max(0, ea - base): max(0, ea - base) + n])
    )
    sys.modules["ida_bytes"].get_flags = lambda ea: 0x0
    sys.modules["idc"].is_code = lambda f: False
    sys.modules["idc"].is_data = lambda f: False
    basic.iter_segments = _segments


def test_search_data_value_no_shifted_false_positives():
    # Regression: a byte-stepped scan of the big-endian encoding of 0x400000
    # contains a subsequence that LE-decodes back to 0x400000 at a neighbouring
    # offset (0x1013).  The pointer-word scan must step at word alignment and
    # only report the genuine 0x1010 big-endian word.
    basic = _module("search.basic")
    blob = bytearray(0x20)
    struct.pack_into(">Q", blob, 0x10, 0x400000)  # big-endian pointer at 0x1010
    _config_data_value_ida(basic, blob)

    resp = basic.search_data_value("0x400000", word_size="u64", endian="both", timeout_ms=0)
    assert resp["ok"] is True
    assert resp["count"] == 1
    assert resp["items"][0]["address"] == "0x1010"
    assert resp["items"][0]["endian"] == "be"


def test_search_data_value_empty_segment_terminates():
    basic = _module("search.basic")
    # Unmapped/BSS segment: get_bytes returns None → the chunk is empty and the
    # scan must terminate instead of looping.
    sys.modules["ida_bytes"].get_bytes = lambda ea, n: None
    sys.modules["ida_bytes"].get_flags = lambda ea: 0x0
    sys.modules["idc"].is_code = lambda f: False
    sys.modules["idc"].is_data = lambda f: False
    basic.iter_segments = lambda a=None, b=None, require_exec=False: [(0x1000, 0x2000)]
    _assert_terminates(
        basic.search_data_value, "0x400000", None, None, "both", "u64", 0, 10, 0
    )


def test_search_type_terminates_on_badaddr():
    meta = _module("search.meta")
    meta.idaapi.BADADDR = -1
    meta.iter_segments = lambda a, b, require_exec=False: [(0x1000, 0x1010)]
    meta.idc.next_head = lambda ea, end: -1
    meta.ida_typeinf.get_idati = lambda: None
    meta.ida_nalt.get_tinfo = lambda tif, ea: False
    meta.build_response = lambda *a, **k: {"ok": True}
    _assert_terminates(meta.search_type, "x", True, 0, 10, False)


# ---------------------------------------------------------------------------
# search_find — duplicate (score, ea) heap keys must not raise TypeError
# ---------------------------------------------------------------------------

def test_search_find_heap_survives_duplicate_keys():
    unified = _module("search.unified")
    unified.idaapi.BADADDR = -1
    unified.SCORE_SUBSTRING = 60.0
    unified.compile_smart_pattern = lambda p, case_sensitive=False: (
        lambda v: p.lower() in str(v).lower()
    )
    unified.looks_like_address = lambda p: False
    unified.looks_like_identifier = lambda p: False
    # name hit at 0x401000 ...
    unified.idautils.Names = lambda: [(0x401000, "foo")]
    unified.get_cached_strings = list
    unified.get_cached_imports = list
    unified.idautils.Segments = list
    # ... and an instruction hit at the SAME ea with the SAME score
    unified.resolve_scan_segments = lambda a, b, require_exec=True: ([(0x401000, 0x401100)], "", "")
    unified.iter_code = lambda a, b, force=False: [0x401000]
    unified.idc.print_insn_mnem = lambda ea: "mov"
    unified.idc.print_operand = lambda ea, i: ("foo" if i == 0 else None)
    unified.safe_generate_disasm_line = lambda ea: "mov foo"
    unified.ida_lines.tag_remove = lambda s: s
    unified.semantic_score_cheap = lambda *a, **k: 60.0  # forces exact tie
    unified.semantic_scores = lambda *a, **k: [60.0, 60.0]
    unified.idautils.XrefsTo = lambda *a, **k: []
    unified.ida_funcs.get_func_name = lambda ea: "foo"
    unified.idaapi.get_func = lambda ea: _Func(ea, ea + 1)
    unified.ida_funcs.get_func = unified.idaapi.get_func
    unified.xref_count_limited = lambda ea, **k: 0
    unified._rescore_find_ranked = lambda ranked, p: None
    unified.build_response = lambda *a, **k: {"ok": True}
    unified.make_item = lambda *a, **k: {"addr": "0x401000"}

    resp = unified.search_find("foo", True, None, None, False, False, False, 0, 10, 0)
    # Duplicate (60.0, 0x401000) keys previously crashed heapq with a
    # dict-vs-dict TypeError; the search must complete normally.
    assert resp["ok"] is True


def test_search_find_kind_restricts_to_strings():
    """kind='strings' is a dedicated string-literal search — no name hits."""
    unified = _module("search.unified")
    unified.idaapi.BADADDR = -1
    unified.SCORE_SUBSTRING = 60.0
    unified.compile_smart_pattern = lambda p, case_sensitive=False: (
        lambda v: p.lower() in str(v).lower()
    )
    unified.looks_like_address = lambda p: False
    unified.looks_like_identifier = lambda p: False
    # A name hit (0x401000) and a string hit (0x402000) both match "foo".
    unified.idautils.Names = lambda: [(0x401000, "foo")]
    unified.get_cached_strings = lambda: [{"ea": 0x402000, "string": "foo bar"}]
    unified.get_cached_imports = list
    unified.idautils.Segments = list
    unified.idautils.XrefsTo = lambda *a, **k: []
    unified.ida_funcs.get_func_name = lambda ea: "foo"
    unified.idaapi.get_func = lambda ea: _Func(ea, ea + 1)
    unified.ida_funcs.get_func = unified.idaapi.get_func
    unified.xref_count_limited = lambda ea, **k: 0
    unified.semantic_score_cheap = lambda *a, **k: 60.0
    unified.semantic_scores = lambda *a, **k: [60.0, 60.0]
    unified._rescore_find_ranked = lambda ranked, p: None
    captured = {}

    def fake_build_response(lines, offset, limit, total, is_truncated, **kw):
        captured["lines"] = lines
        return {"ok": True, "results": lines, "total": total}

    unified.build_response = fake_build_response
    unified.make_item = lambda *a, **k: {"addr": "0x1000"}

    resp = unified.search_find("foo", True, None, None, False, False, False, 0, 10, 0, kind="strings")
    assert resp["kind"] == "strings"
    assert captured["lines"], "expected only string hits"
    assert all("0x402000" in ln for ln in captured["lines"]), captured["lines"]
    assert not any("0x401000" in ln for ln in captured["lines"]), captured["lines"]


def test_search_find_kind_names_excludes_strings():
    unified = _module("search.unified")
    unified.idaapi.BADADDR = -1
    unified.SCORE_SUBSTRING = 60.0
    unified.compile_smart_pattern = lambda p, case_sensitive=False: (
        lambda v: p.lower() in str(v).lower()
    )
    unified.looks_like_address = lambda p: False
    unified.looks_like_identifier = lambda p: False
    unified.idautils.Names = lambda: [(0x401000, "foo")]
    unified.get_cached_strings = lambda: [{"ea": 0x402000, "string": "foo bar"}]
    unified.get_cached_imports = list
    unified.idautils.Segments = list
    unified.idautils.XrefsTo = lambda *a, **k: []
    unified.ida_funcs.get_func_name = lambda ea: "foo"
    unified.idaapi.get_func = lambda ea: _Func(ea, ea + 1)
    unified.ida_funcs.get_func = unified.idaapi.get_func
    unified.xref_count_limited = lambda ea, **k: 0
    unified.semantic_score_cheap = lambda *a, **k: 60.0
    unified.semantic_scores = lambda *a, **k: [60.0, 60.0]
    unified._rescore_find_ranked = lambda ranked, p: None
    captured = {}

    def fake_build_response(lines, offset, limit, total, is_truncated, **kw):
        captured["lines"] = lines
        return {"ok": True, "results": lines, "total": total}

    unified.build_response = fake_build_response
    unified.make_item = lambda *a, **k: {"addr": "0x1000"}

    resp = unified.search_find("foo", True, None, None, False, False, False, 0, 10, 0, kind="names")
    assert resp["kind"] == "names"
    assert captured["lines"]
    assert all("0x401000" in ln for ln in captured["lines"]), captured["lines"]
    assert not any("0x402000" in ln for ln in captured["lines"]), captured["lines"]


def test_search_find_unknown_kind_degrades_to_all():
    unified = _module("search.unified")
    unified.idaapi.BADADDR = -1
    unified.SCORE_SUBSTRING = 60.0
    unified.compile_smart_pattern = lambda p, case_sensitive=False: (
        lambda v: p.lower() in str(v).lower()
    )
    unified.looks_like_address = lambda p: False
    unified.looks_like_identifier = lambda p: False
    unified.idautils.Names = lambda: [(0x401000, "foo")]
    unified.get_cached_strings = lambda: [{"ea": 0x402000, "string": "foo bar"}]
    unified.get_cached_imports = list
    unified.idautils.Segments = list
    unified.idautils.XrefsTo = lambda *a, **k: []
    unified.ida_funcs.get_func_name = lambda ea: "foo"
    unified.idaapi.get_func = lambda ea: _Func(ea, ea + 1)
    unified.ida_funcs.get_func = unified.idaapi.get_func
    # Unknown kinds degrade to all categories, so the instruction scan runs and
    # compat.iter_segments walks segments via ida_segment (get_first_seg=legacy).
    unified.ida_segment.get_first_seg = lambda: None
    unified.xref_count_limited = lambda ea, **k: 0
    unified.semantic_score_cheap = lambda *a, **k: 60.0
    unified.semantic_scores = lambda *a, **k: [60.0, 60.0]
    unified._rescore_find_ranked = lambda ranked, p: None
    captured = {}

    def fake_build_response(lines, offset, limit, total, is_truncated, **kw):
        captured["lines"] = lines
        return {"ok": True, "results": lines, "total": total}

    unified.build_response = fake_build_response
    unified.make_item = lambda *a, **k: {"addr": "0x1000"}

    resp = unified.search_find("foo", True, None, None, False, False, False, 0, 10, 0, kind="bogus")
    # Unrecognized kinds degrade to all categories with a note, not an error.
    assert resp["kind_note"] and "bogus" in resp["kind_note"]
    assert any("0x401000" in ln for ln in captured["lines"]), captured["lines"]
    assert any("0x402000" in ln for ln in captured["lines"]), captured["lines"]


# ---------------------------------------------------------------------------
# query_lang — tools package resolution + error envelope
# ---------------------------------------------------------------------------

def test_query_lang_uses_real_error_envelope():
    # error_handling imports ida_mcp.compat (IDA 9.4 shims) at module load,
    # which requires the ida_* stub modules to be registered first.
    install_common_stub()
    ql = load_support_module("query_lang")
    err = ql.make_error(ql.MCPError.INVALID_ARGS, "Tool 'x' not available")
    # The real error_handling.make_error adds an ERROR_HINTS hint; the old
    # fallback stub returned a bare {"error": msg} dict with no code/hint.
    assert err["error"] is True
    assert err["code"] == "INVALID_ARGS"
    assert err["message"] == "Tool 'x' not available"
    assert "hint" in err


def test_query_lang_resolves_tools_from_tools_package():
    import importlib.util

    ql = load_support_module("query_lang")
    # Regression: _get_tool used to import .{name} relative to the support
    # package (ida_pro_mcp.ida_mcp.support.data — which does not exist).
    resolved = importlib.util.resolve_name("..tools.data", "ida_pro_mcp.ida_mcp.support")
    assert resolved == "ida_pro_mcp.ida_mcp.tools.data"

    # And resolution actually finds a tool there.
    fake = types.ModuleType("ida_pro_mcp.ida_mcp.tools.data")
    fake.data = lambda action="functions", **kw: {"ok": True, "functions": []}
    sys.modules["ida_pro_mcp.ida_mcp.tools.data"] = fake
    ql._TOOL_CACHE.clear()
    assert ql._get_tool("data") is fake.data


def test_query_lang_executes_match():
    ql = load_support_module("query_lang")
    fake = types.ModuleType("ida_pro_mcp.ida_mcp.tools.data")
    fake.data = lambda action="functions", **kw: {
        "ok": True,
        "functions": [{"addr": "0x1000", "name": "f", "size": 500}],
    }
    sys.modules["ida_pro_mcp.ida_mcp.tools.data"] = fake
    ql._TOOL_CACHE.clear()
    resp = ql.run_query_lang("MATCH function * WHERE size > 100 LIMIT 5")
    assert resp["ok"] is True
    assert resp["total"] == 1


# ---------------------------------------------------------------------------
# search_structured — sibling envelope (results/total/offset/truncated)
# ---------------------------------------------------------------------------

def test_search_structured_returns_sibling_envelope():
    adv = _module("search.advanced")
    adv.idaapi.BADADDR = -1

    class FakeIdx:
        size = 5

        @staticmethod
        def search_structured(constraints, query=None, top_k=None):  # noqa: ARG004 - fake, args unused
            return [
                {"ea": "0x1000", "name": "a", "func_size": 1, "bb_count": 1,
                 "api_count": 0, "has_loops": False, "segment": ".text",
                 "string_count": 0, "is_thunk": False, "cyclomatic": 1},
                {"ea": "0x2000", "name": "b", "func_size": 2, "bb_count": 2,
                 "api_count": 1, "has_loops": True, "segment": ".text",
                 "string_count": 0, "is_thunk": False, "cyclomatic": 2},
            ]

    adv._get_intelligence_index = lambda: (None, FakeIdx(), "/tmp/x.i64")
    resp = adv.search_structured(
        {"min_size": 1}, None, None, None, False, 0, 10, False, 0
    )
    assert resp["ok"] is True
    assert resp["action"] == "structured"
    assert "results" in resp, "structured must return 'results' like sibling actions"
    assert "matches" not in resp, "sibling contract uses 'results', not 'matches'"
    assert resp["total"] == 2
    assert resp["offset"] == 0
    assert resp["truncated"] is False
    assert len(resp["items"]) == 2


# ---------------------------------------------------------------------------
# search_decompiled — preview_lines parse guard
# ---------------------------------------------------------------------------

def test_search_decompiled_preview_lines_non_numeric_ok():
    adv = _module("search.advanced")
    adv.idaapi.BADADDR = -1
    adv.ida_hexrays.init_hexrays_plugin = lambda: True
    adv._get_intelligence_index = lambda: (None, None, "")
    adv._iter_function_starts = lambda a=None, b=None: []
    resp = adv.search_decompiled(
        "foo", True, None, None, 0, 10, False, preview_lines="abc"
    )
    # Before the fix the unguarded int("abc") raised ValueError.
    assert isinstance(resp, dict)


# ---------------------------------------------------------------------------
# search_type / search_export — include_items honored
# ---------------------------------------------------------------------------

def test_search_type_honors_include_items():
    meta = _module("search.meta")
    meta.idaapi.BADADDR = -1

    class Tif:
        def get_type_by_ordinal(self, til, idx):
            return True

        def get_type_name(self):
            return "Foo"

        def get_size(self):
            return 4

    meta.ida_typeinf.get_idati = object
    meta.ida_typeinf.get_ordinal_qty = lambda til: 1
    meta.ida_typeinf.tinfo_t = Tif
    meta.iter_segments = lambda a, b, require_exec=False: []

    with_items = meta.search_type("foo", False, 0, 10, True)
    assert with_items["ok"] is True
    assert with_items["items"] == [{"ordinal": 0, "name": "Foo", "size": 4}]

    no_items = meta.search_type("foo", False, 0, 10, False)
    assert "items" not in no_items


def test_search_export_honors_include_items():
    meta = _module("search.meta")
    meta.idaapi.BADADDR = -1
    meta.ida_nalt.get_entry_qty = lambda: 1
    meta.ida_nalt.get_entry_ordinal = lambda idx: 1
    meta.ida_nalt.get_entry = lambda ordinal: 0x1000
    meta.ida_nalt.get_entry_name = lambda ordinal: "ExportedFn"

    with_items = meta.search_export("exported", False, 0, 10, True)
    assert with_items["ok"] is True
    assert with_items["items"] == [{"addr": "0x1000", "ordinal": 1, "name": "ExportedFn"}]

    no_items = meta.search_export("exported", False, 0, 10, False)
    assert "items" not in no_items


# ---------------------------------------------------------------------------
# combinators — outlier error uses MCPError.UNKNOWN (not UNKNOWN_ERROR)
# ---------------------------------------------------------------------------

def test_search_analyze_outlier_error_uses_mcp_error_unknown():
    comb = _module("search.combinators")
    comb.idaapi.BADADDR = -1
    # Mirror the real error_handling.MCPError, which defines UNKNOWN but not
    # UNKNOWN_ERROR — the pre-fix code referenced the latter and raised
    # AttributeError instead of returning a clean envelope.
    comb.MCPError.UNKNOWN = "UNKNOWN_ERROR"
    comb.idc.get_idb_path = lambda: "/tmp/x.i64"

    services = types.ModuleType("ida_pro_mcp.services")
    services.get_assembler = type("Asm", (), {"_get_index": lambda self, p: None})
    sys.modules["ida_pro_mcp.services"] = services

    def _boom(metric):
        raise RuntimeError("index exploded")

    comb._outlier_rows_from_ida = _boom
    resp = comb.search_analyze(scope="outlier", metric="size", offset=0, limit=50)
    # Pre-fix this line raised AttributeError ('MCPError.UNKNOWN_ERROR');
    # it must now return a clean error envelope via MCPError.UNKNOWN.
    assert resp.get("code") == "UNKNOWN_ERROR"
    assert "index exploded" in resp.get("message", "")


# ---------------------------------------------------------------------------
# Dead-code removal — source no longer references the unreachable branches
# ---------------------------------------------------------------------------

def _source(name: str) -> str:
    return (SEARCH / f"{name}.py").read_text(encoding="utf-8")


def test_search_api_dead_no_results_block_removed():
    src = _source("unified")
    # The old block was guarded on api_summary being empty, which can never
    # happen after the matched_apis early-return. Removing it must not break
    # the remaining build_response call.
    assert "if not api_summary" not in src


def test_search_xrefs_to_string_dead_empty_branch_removed():
    src = _source("unified")
    assert "if not merged" not in src
    assert "String(s) found but no code xrefs" not in src


def test_combinators_no_unknown_error_attribute():
    src = _source("combinators")
    assert "MCPError.UNKNOWN_ERROR" not in src
