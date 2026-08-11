"""Regression tests for swarm/t09_calc_graph findings.

Covers:
- calc resolve NL-sniffing must not mangle verbatim symbol-name inputs:
  a numeric substring (sub_401000) or a keyword (set_file_offset) inside a
  real addr/value must be resolved verbatim; the free-text intent sniffing
  applies only to NL queries.
- _normalize_calc_action's adaptive gate must fall back when the semantic
  scores are all zero (garbage query), instead of returning an arbitrary
  action via the collapsed gate.
- _format_graph truncation must keep the requested root and its connected
  neighborhood instead of the 500 lowest addresses, which could silently
  drop the root and every edge touching it.

Host-side tests: ida_* modules are stubbed via tests._isolated_repo_loader;
no live IDA session is required.
"""

from __future__ import annotations

import sys
import types

import pytest

from tests._isolated_repo_loader import load_tool_module

BADADDR = -1


@pytest.fixture(scope="module")
def calc_mod():
    return load_tool_module("calc")


@pytest.fixture(scope="module")
def graph_mod():
    return load_tool_module("graph")


def _stub_resolve_ida():
    """Wire the ida_* stubs the calc resolve branch touches."""
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = BADADDR
    # Only these symbols exist in the fake IDB.
    idc = sys.modules["idc"]
    idc.get_name_ea_simple = lambda name: {
        "sub_401000": 0x400000,
        "set_file_offset": 0x400050,
    }.get(name, BADADDR)
    idc.get_func_name = lambda ea: ""
    idaapi.get_fileregion_offset = lambda ea: 0x200 if ea == 0x400000 else 0x100
    idaapi.get_fileregion_ea = lambda off: {
        0x200: 0x400000,
        0x401000: 0x500000,
    }.get(off, BADADDR)
    idaapi.getseg = lambda ea: types.SimpleNamespace(
        start_ea=0x400000, end_ea=0x401000
    )
    sys.modules["ida_segment"].getseg = idaapi.getseg
    sys.modules["ida_segment"].get_segm_name = lambda seg, flags=0: ".text"
    sys.modules["idautils"].Names = list


# ---------------------------------------------------------------------------
# Finding: _normalize_calc_action gate on an all-zero score distribution
# ---------------------------------------------------------------------------

def test_normalize_garbage_action_returns_fallback(calc_mod):
    # 'zzzz' shares no token/ngram/substring signal with any action, so every
    # semantic score is 0. The adaptive gate collapses to 0 and previously
    # passed the top tie-break, silently turning calc(action='offset',
    # semantic_action='zzzz') into a random other action.
    assert calc_mod._normalize_calc_action("zzzz", fallback="offset") == "offset"
    assert calc_mod._normalize_calc_action("qqqq", fallback="convert") == "convert"


def test_normalize_clear_semantic_match_still_resolves(calc_mod):
    # A partial match (substring bonus) must still beat the gate — the zero
    # guard must not break legitimate fuzzy resolution.
    assert calc_mod._normalize_calc_action("eva", fallback="offset") == "eval"


def test_normalize_exact_and_alias_unchanged(calc_mod):
    assert calc_mod._normalize_calc_action("offset", fallback="eval") == "offset"
    assert calc_mod._normalize_calc_action("evaluate", fallback="offset") == "eval"


# ---------------------------------------------------------------------------
# Finding: resolve NL-sniffing mangles verbatim symbol inputs
# ---------------------------------------------------------------------------

def test_resolve_symbol_with_numeric_substring_not_decimalized(calc_mod):
    _stub_resolve_ida()
    # Before the fix the regex pulled '401000' out of 'sub_401000' and
    # resolved it as decimal 401000 (0x61E68) instead of the symbol's EA.
    resp = calc_mod.calc(action="resolve", addr="sub_401000")
    assert resp.get("ok") is True
    assert resp["va"] == "0x400000"
    assert resp["direction"] == "va_to_file_offset"


def test_resolve_symbol_with_keyword_name_does_not_flip_direction(calc_mod):
    _stub_resolve_ida()
    # 'set_file_offset' contains 'file'/'offset' which previously flipped the
    # mapping to reverse (file_offset_to_va) even though addr is a symbol.
    resp = calc_mod.calc(action="resolve", addr="set_file_offset")
    assert resp.get("ok") is True
    assert resp["va"] == "0x400050"
    assert resp["direction"] == "va_to_file_offset"


def test_resolve_nl_query_sniffing_still_works(calc_mod):
    _stub_resolve_ida()
    # Free-text intent queries keep the keyword/regex sniffing: 'file offset'
    # flips to reverse and '0x401000' is extracted as the file offset.
    resp = calc_mod.calc(action="resolve", intent="resolve file offset 0x401000")
    assert resp.get("ok") is True
    assert resp["file_offset"] == "0x401000"
    assert resp["va"] == "0x500000"
    assert resp["direction"] == "file_offset_to_va"


# ---------------------------------------------------------------------------
# Finding: _format_graph truncation drops the requested root
# ---------------------------------------------------------------------------

def test_format_graph_truncation_keeps_root_and_edges(graph_mod):
    # Star graph: the root (highest address) calls 550 lower functions. The
    # old address-sorted truncation kept the 500 lowest nodes, dropped the
    # root, and left every edge orphaned (500 nodes / 0 edges, root gone).
    nodes = {0x1000 + i: f"n{i}" for i in range(550)}
    root = 0xFFFF0000
    nodes[root] = "root"
    edges = [(root, 0x1000 + i) for i in range(550)]

    resp = graph_mod._format_graph(nodes, edges, "json", root_ea=root)
    assert resp["node_count"] == 500
    assert any(n["addr"] == hex(root) for n in resp["nodes"]), "root must survive"
    # Root + 499 reachable callees: edges are preserved, not orphaned.
    assert resp["edge_count"] == 499


def test_format_graph_truncation_keeps_hub_without_root_ea(graph_mod):
    # Backward compatibility: with no explicit root, degree-based relevance
    # still keeps the high-degree hub rather than arbitrary low addresses.
    nodes = {0x1000 + i: f"n{i}" for i in range(550)}
    nodes[0xFFFF0000] = "root"
    edges = [(0xFFFF0000, 0x1000 + i) for i in range(550)]
    resp = graph_mod._format_graph(nodes, edges, "json")
    assert resp["node_count"] == 500
    assert resp["edge_count"] == 499


def test_format_graph_small_graph_unaffected(graph_mod):
    resp = graph_mod._format_graph(
        {0x10: "a", 0x20: "b"}, [(0x10, 0x20)], "json"
    )
    assert resp["node_count"] == 2
    assert resp["edge_count"] == 1
