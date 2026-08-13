"""Regression tests for t17_search_basic fixes.

Covers:
- search_bytes: timeout_ms honored on the modern compiled_binpat_vec_t path,
  and scan stops once the limit is reached (no wasted per-segment scans).
- search_string: start/end range is honored instead of silently ignored.
- search_func_by_sig: calls-regex / leaf / no_callers keywords are anchored
  to word boundaries so plain names ('caller', 'leaflet', 'entry_point_*')
  are not misparsed as structural filters.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_submodule  # noqa: E402


class _Func:
    def __init__(self, start: int, end: int):
        self.start_ea = start
        self.end_ea = end


def _module(modname: str):
    return load_tool_submodule(modname)


def _name_matcher(pattern, **kwargs):
    return lambda s: pattern in str(s)


# ---------------------------------------------------------------------------
# search_bytes — timeout + truncation on the modern compiled_binpat_vec_t path
# ---------------------------------------------------------------------------

def test_search_bytes_stops_scanning_remaining_segments_after_limit():
    basic = _module("search.basic")
    basic.idaapi.BADADDR = -1
    basic.iter_segments = lambda a, b, require_exec=False: [(0x1000, 0x1010), (0x2000, 0x2010)]
    basic.ida_bytes.compiled_binpat_vec_t = lambda: object()  # noqa: PLW0108
    basic.ida_bytes.parse_binpat_str = lambda pt, a, b, c: 0
    basic.ida_bytes.BIN_SEARCH_FORWARD = 1
    bs = Mock(return_value=(0x1000, None))
    basic.ida_bytes.bin_search = bs

    resp = basic.search_bytes("AA", None, None, False, 0, 1, 0)
    # Limit reached in the first segment; the second segment must not be scanned.
    assert resp["ok"] is True
    assert resp["truncated"] is True
    assert resp["count"] == 1
    assert bs.call_count == 1


def test_search_bytes_timeout_on_modern_path_sets_timed_out():
    basic = _module("search.basic")
    basic.idaapi.BADADDR = -1
    basic.iter_segments = lambda a, b, require_exec=False: [(0x1000, 0x1010), (0x2000, 0x2010)]
    basic.ida_bytes.compiled_binpat_vec_t = lambda: object()  # noqa: PLW0108
    basic.ida_bytes.parse_binpat_str = lambda pt, a, b, c: 0
    basic.ida_bytes.BIN_SEARCH_FORWARD = 1
    bs = Mock(return_value=(0x1000, None))
    basic.ida_bytes.bin_search = bs

    class _Expired:
        def __init__(self, ms):
            pass

        def check(self):
            raise TimeoutError("expired")

    basic.SearchTimeout = _Expired

    resp = basic.search_bytes("AA", None, None, False, 0, 10, timeout_ms=1)
    # Pre-fix the modern path never consulted the timer; now it must stop.
    assert resp["ok"] is True
    assert resp.get("timed_out") is True
    assert bs.call_count == 1  # timeout hit before the second segment


# ---------------------------------------------------------------------------
# search_string — start/end range honored
# ---------------------------------------------------------------------------

def test_search_string_honors_range():
    basic = _module("search.basic")
    basic.idaapi.BADADDR = -1
    basic.safe_get_strlist_items = lambda: [
        SimpleNamespace(ea=0x1000),
        SimpleNamespace(ea=0x2000),
        SimpleNamespace(ea=0x3000),
    ]
    basic.safe_get_strlit_contents = lambda ea: {  # noqa: PLW0108
        0x1000: "hello world",
        0x2000: "goodbye",
        0x3000: "hello again",
    }.get(ea)
    basic.idautils.XrefsTo = lambda *a, **k: []
    basic.compile_smart_pattern = _name_matcher

    resp = basic.search_string("hello", False, False, 0, 10, 0, 0x2000, 0x4000)
    # 0x1000 ('hello world') is outside [0x2000, 0x4000) and must be dropped.
    assert "0x3000" in resp["results"]
    assert "0x1000" not in resp["results"]
    assert resp["count"] == 1


def test_search_string_default_without_range_unaffected():
    basic = _module("search.basic")
    basic.idaapi.BADADDR = -1
    basic.safe_get_strlist_items = lambda: [SimpleNamespace(ea=0x1000), SimpleNamespace(ea=0x2000)]
    basic.safe_get_strlit_contents = lambda ea: {0x1000: "hello", 0x2000: "hello"}.get(ea)  # noqa: PLW0108
    basic.idautils.XrefsTo = lambda *a, **k: []
    basic.compile_smart_pattern = _name_matcher

    resp = basic.search_string("hello", False, False, 0, 10, 0)
    assert resp["count"] == 2
    assert "0x1000" in resp["results"]
    assert "0x2000" in resp["results"]


def test_search_string_finds_literal_not_in_strlist():
    """Packed .rodata tables are often missing from IDA's string list."""
    basic = _module("search.basic")
    basic.idaapi.BADADDR = -1
    basic.safe_get_strlist_items = lambda: []
    basic.safe_get_strlit_contents = lambda ea: None
    basic.idautils.XrefsTo = lambda *a, **k: []
    basic.compile_smart_pattern = _name_matcher
    blob = b"xxxxAGENT_SURFACE_STRING_001\x00yyyy"
    basic.iter_segments = lambda a, b, require_exec=False: [(0x4000, 0x4000 + len(blob))]
    basic.ida_bytes.get_bytes = lambda ea, n: blob[ea - 0x4000:ea - 0x4000 + n]
    resp = basic.search_string("AGENT_SURFACE_STRING_001", False, False, 0, 10, 0)
    assert resp["count"] >= 1, resp
    assert "AGENT_SURFACE_STRING_001" in resp["results"]
    assert "0x4004" in resp["results"]


# ---------------------------------------------------------------------------
# search_func_by_sig — keyword word-boundary anchoring
# ---------------------------------------------------------------------------

def test_func_by_sig_name_starting_with_call_not_treated_as_calls_filter():
    refs = _module("search.refs")
    refs.idaapi.BADADDR = -1
    funcs = {0x1: _Func(0x1, 0x50), 0x2: _Func(0x2, 0x50)}
    refs.idaapi.get_func = funcs.get
    refs.ida_funcs.get_func = funcs.get
    refs.idautils.Functions = lambda: [0x1, 0x2]
    refs.ida_funcs.get_func_name = lambda ea: {0x1: "caller", 0x2: "callee_helper"}.get(ea, "")
    refs.idautils.XrefsTo = lambda *a, **k: []
    refs.idautils.XrefsFrom = lambda *a, **k: []
    refs.compile_smart_pattern = _name_matcher

    resp = refs.search_func_by_sig("caller", 0, 50)
    # Pre-fix 'call' prefix captured call_pattern='er', forcing the calls
    # filter and returning zero results; it must fall back to name search.
    assert "0x1" in resp["results"]
    assert "0x2" not in resp["results"]


def test_func_by_sig_no_callers_does_not_parse_call_pattern():
    refs = _module("search.refs")
    refs.idaapi.BADADDR = -1
    funcs = {0x1: _Func(0x1, 0x50), 0x2: _Func(0x2, 0x50)}
    refs.idaapi.get_func = funcs.get
    refs.ida_funcs.get_func = funcs.get
    refs.idautils.Functions = lambda: [0x1, 0x2]
    refs.ida_funcs.get_func_name = lambda ea: {0x1: "entry_candidate", 0x2: "busy"}.get(ea, "")
    # 0x1 has no code callers; 0x2 has one.
    refs.idautils.XrefsTo = lambda ea, flag=0: (
        [] if ea == 0x1 else [SimpleNamespace(iscode=True)]
    )
    refs.idautils.XrefsFrom = lambda *a, **k: []
    refs.compile_smart_pattern = _name_matcher

    resp = refs.search_func_by_sig("no_callers", 0, 50)
    # Pre-fix 'no_callers' also produced call_pattern='ers', so the calls
    # filter failed every function. It must act as a pure no_callers filter.
    assert "0x1" in resp["results"]
    assert "0x2" not in resp["results"]


def test_func_by_sig_name_with_leaf_substring_not_treated_as_leaf_filter():
    refs = _module("search.refs")
    refs.idaapi.BADADDR = -1
    funcs = {0x1: _Func(0x1, 0x50), 0x2: _Func(0x2, 0x50)}
    refs.idaapi.get_func = funcs.get
    refs.ida_funcs.get_func = funcs.get
    refs.idautils.Functions = lambda: [0x1, 0x2]
    refs.ida_funcs.get_func_name = lambda ea: {0x1: "leaflet", 0x2: "other"}.get(ea, "")
    refs.idautils.XrefsTo = lambda *a, **k: []
    refs.idautils.XrefsFrom = lambda *a, **k: []
    refs.compile_smart_pattern = _name_matcher

    resp = refs.search_func_by_sig("leaflet", 0, 50)
    # Pre-fix 'leaf' substring flipped want_leaf and bypassed name search,
    # returning every leaf function; now only the name match survives.
    assert "0x1" in resp["results"]
    assert "0x2" not in resp["results"]


def test_func_by_sig_calls_keyword_still_filters():
    refs = _module("search.refs")
    refs.idaapi.BADADDR = -1
    funcs = {0x1: _Func(0x1, 0x50), 0x2: _Func(0x2, 0x50)}
    refs.idaapi.get_func = funcs.get
    refs.ida_funcs.get_func = funcs.get
    refs.idautils.Functions = lambda: [0x1, 0x2]
    refs.ida_funcs.get_func_name = lambda ea: {0x1: "malloc_wrapper", 0x2: "free_wrapper"}.get(ea, "")
    refs.idautils.XrefsTo = lambda *a, **k: []
    refs.idautils.XrefsFrom = lambda ea: (
        [SimpleNamespace(type=17, to=0xAAA)] if ea == 0x1 else []
    )
    refs.idc.get_name = lambda ea: {0xAAA: "malloc"}.get(ea, "")
    refs.compile_smart_pattern = _name_matcher

    resp = refs.search_func_by_sig("calls:malloc", 0, 50)
    assert "0x1" in resp["results"]
    assert "0x2" not in resp["results"]
