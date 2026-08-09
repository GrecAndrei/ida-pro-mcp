"""Regression tests for swarm work order s01-q05-calc-graph.

Pins the settle-wave directives for calc.py and graph.py:

calc.py
- ALL address parsing delegates to tools/_common.parse_address_canonical so a
  bare in-image token (80000000) and its 0x-prefixed spelling (0x80000000)
  resolve to the same EA; symbol-first beats any literal reading; an
  ambiguous/unmapped bare token yields ADDRESS_INVALID (never a silent
  decimal reinterpretation).
- get_fileregion_offset returning BADADDR on headerless raw blobs surfaces a
  crisp "no file mapping" error instead of a confusing offset value.

graph.py
- callgraph keeps edges to function-less targets as sub_<ea> placeholder
  nodes and reports a function_less_targets count.
- callgraph/cfg/dominators fall back to a mapped code root (iterate
  Heads / XrefsFrom WITHOUT require_func) on raw blobs with no defined
  functions, and include a note that functions were auto-defined.
- dominators is near-linear (Lengauer-Tarjan), not the O(n^3) fixpoint.
- nodes count toward max_items; cfg and dominators report pre/post
  truncation counts.

Host-side tests: ida_* modules are stubbed via tests._isolated_repo_loader;
no live IDA session is required.
"""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import load_ida_module, load_tool_module

BADADDR = -1


class _FakeXref:
    """ida_xref_t stand-in used by the callgraph tests."""

    def __init__(self, iscode=True, xtype=0, to=0):
        self.iscode = iscode
        self.type = xtype
        self.to = to


class _FakeBlock:
    """basic_block_t stand-in: start_ea, end_ea, succs()."""

    def __init__(self, start, succs=()):
        self.start_ea = start
        self.end_ea = start + 0x10
        self._succs = list(succs)

    def succs(self):
        return self._succs


def _register_fake_gdl(chart_blocks):
    """Register a fake ida_gdl module whose FlowChart yields *chart_blocks*.

    No ``calc_idom`` attribute is installed, so ``_immediate_dominators``
    exercises the pure-Python Lengauer-Tarjan fallback.
    """
    ida_gdl = types.ModuleType("ida_gdl")

    class _FakeChart:
        def __init__(self, *_args, **_kw):
            self._blocks = chart_blocks

        def __iter__(self):
            return iter(self._blocks)

    ida_gdl.FlowChart = lambda *a, **k: _FakeChart()
    sys.modules["ida_gdl"] = ida_gdl
    return ida_gdl


# ---------------------------------------------------------------------------
# calc: shared-parser delegation (hex-by-default for in-image bare tokens)
# ---------------------------------------------------------------------------

def _stub_calc_ida(symbols=None, file_offset_map=None):
    """Wire the ida_* stubs the calc offset/resolve paths touch."""
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = BADADDR
    symbols = symbols or {}
    sys.modules["idc"].get_name_ea_simple = lambda name: symbols.get(name, BADADDR)
    sys.modules["idc"].get_func_name = lambda ea: ""
    idaapi.getseg = lambda ea: types.SimpleNamespace(start_ea=0x400000, end_ea=0x401000)
    sys.modules["ida_segment"].get_segm_name = lambda seg: ".text"
    sys.modules["idautils"].Names = list
    if file_offset_map is not None:
        idaapi.get_fileregion_offset = lambda ea: file_offset_map.get(ea, BADADDR)
        idaapi.get_fileregion_ea = lambda off: BADADDR


def _load_calc_with_real_parser():
    """Load calc with the REAL parse_address_canonical wrapped in a recorder.

    The isolated-loader default stub parser is deliberately simplified; using
    the real error_handling parser pins the in-image hex-by-default /
    ADDRESS_INVALID behavior the directive asks for. Returns (module, calls).
    """
    errhand = load_ida_module("error_handling")
    calls = []
    real_parse = errhand.parse_address_canonical

    def rec_parse(s):
        calls.append(s)
        return real_parse(s)

    mod = load_tool_module("calc", common_overrides={"parse_address_canonical": rec_parse})
    return mod, calls


def test_calc_bare_and_0x_prefixed_in_image_token_same_ea():
    # A bare in-image token like 80000000 (habitual on RISC-V/opaque raw
    # blobs) and its 0x80000000 spelling must land on the same EA via the
    # shared parser — not one being read as decimal.
    mod, calls = _load_calc_with_real_parser()
    _stub_calc_ida()

    resp = mod.calc(action="offset", addr="80000000", target="0x80000000")

    assert resp.get("ok") is True
    assert resp["from"] == "0x80000000"
    assert resp["to"] == "0x80000000"
    assert resp["delta_int"] == 0
    # The bare token was delegated to the shared parser (hex-by-default).
    assert "80000000" in calls


def test_calc_symbol_first_beats_numeric_literal_reading():
    # sub_401000 is the symbol's EA (0x400000), never the decimal 401000 or
    # hex 0x401000. The parser must not even be consulted for the symbol.
    mod, calls = _load_calc_with_real_parser()
    _stub_calc_ida(symbols={"sub_401000": 0x400000})

    resp = mod.calc(action="offset", addr="sub_401000", target="0x400000")

    assert resp.get("ok") is True
    assert resp["from"] == "0x400000"
    assert resp["delta_int"] == 0
    assert "sub_401000" not in calls


def test_calc_bare_token_outside_image_is_address_invalid_not_decimal():
    # An unmapped bare token is ADDRESS_INVALID with a "use 0x prefix" hint —
    # never a silent decimal reinterpretation.
    errhand = load_ida_module("error_handling")
    errhand._image_min_ea = lambda: 0x1000
    errhand._image_max_ea = lambda: 0x2000
    mod = load_tool_module(
        "calc",
        common_overrides={"parse_address_canonical": errhand.parse_address_canonical},
    )
    _stub_calc_ida()

    resp = mod.calc(action="resolve", addr="80000000")

    assert resp.get("ok") is not True
    assert "0x prefix" in resp.get("message", "")


def test_calc_resolve_fileregion_badaddr_crisp_error_on_headerless_blob():
    # Headerless raw blobs have no segment-to-file mapping, so
    # get_fileregion_offset returns BADADDR for every VA. Surface a crisp
    # error instead of a confusing "0x... not in file" style value.
    mod = load_tool_module("calc")
    _stub_calc_ida(file_offset_map={})

    resp = mod.calc(action="resolve", addr="0x400000")

    assert resp.get("ok") is not True
    assert "no file mapping" in resp.get("message", "").lower()
    assert resp.get("hint")


# ---------------------------------------------------------------------------
# graph callgraph: function-less targets, raw-blob fallback
# ---------------------------------------------------------------------------

def _stub_graph_callgraph_ida():
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = BADADDR
    idaapi.fl_CN = 0x10
    idaapi.fl_CF = 0x20
    sys.modules["idc"].get_func_name = lambda ea: ""
    sys.modules["ida_funcs"].get_func = lambda ea: None  # raw blob: no functions


def test_callgraph_function_less_target_placeholder_and_note():
    mod = load_tool_module("graph")
    _stub_graph_callgraph_ida()
    sys.modules["idautils"].XrefsFrom = lambda item: (
        [_FakeXref(iscode=True, xtype=0x10, to=0x80000010)]
        if item == 0x80000004 else []
    )
    # Root is on a raw blob: _code_items scans mapped code heads for it.
    mod._code_items = lambda f_ea: [0x80000004] if f_ea == 0x80000000 else []

    resp = mod.graph(action="callgraph", addr="0x80000000", format="json")

    assert resp.get("ok") is True
    assert resp["function_less_targets"] == 1
    placeholder = next(n for n in resp["nodes"] if n["addr"] == "0x80000010")
    assert placeholder["name"] == "sub_80000010"
    assert "auto-defined" in resp.get("note", "")


def test_callgraph_function_less_target_kept_but_not_chased_with_real_function():
    # When the root IS a real function, function-less targets still get a
    # sub_<ea> placeholder edge, but are not chased deeper, and no
    # "auto-defined" note is emitted.
    mod = load_tool_module("graph")
    _stub_graph_callgraph_ida()
    root_func = types.SimpleNamespace(start_ea=0x400000)
    sys.modules["ida_funcs"].get_func = lambda ea: root_func if ea == 0x400000 else None
    sys.modules["idc"].get_func_name = lambda ea: "entry" if ea == 0x400000 else ""
    sys.modules["idautils"].XrefsFrom = lambda item: (
        [_FakeXref(iscode=True, xtype=0x10, to=0x80000010)]
        if item == 0x400004 else []
    )
    mod._code_items = lambda f_ea: [0x400004] if f_ea == 0x400000 else []

    resp = mod.graph(action="callgraph", addr="0x400000", format="json")

    assert resp.get("ok") is True
    assert resp["function_less_targets"] == 1
    assert any(
        n["addr"] == "0x80000010" and n["name"] == "sub_80000010"
        for n in resp["nodes"]
    )
    assert "note" not in resp


def test_code_items_scans_mapped_code_heads_without_function():
    # Raw blobs with no defined functions: _code_items must fall back to
    # iterating mapped code heads (no require_func), bounded by the segment.
    mod = load_tool_module("graph")
    sys.modules["ida_funcs"].get_func = lambda ea: None
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = BADADDR
    idaapi.getseg = lambda ea: types.SimpleNamespace(
        start_ea=0x80000000, end_ea=0x80000100
    )
    sys.modules["ida_bytes"].get_flags = lambda ea: 0
    sys.modules["ida_bytes"].is_code = lambda flags: True
    sys.modules["idc"].next_head = lambda ea, end: ea + 1

    items = mod._code_items(0x80000000)

    assert items
    assert len(items) == 0x100
    assert all(0x80000000 <= i < 0x80000100 for i in items)


# ---------------------------------------------------------------------------
# graph cfg/dominators: raw-blob fallback, near-linear idoms, truncation
# ---------------------------------------------------------------------------

def test_cfg_raw_blob_fallback_and_note():
    mod = load_tool_module("graph")
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = BADADDR
    idaapi.getseg = lambda ea: types.SimpleNamespace(
        start_ea=0x80000000, end_ea=0x80000100
    )
    sys.modules["ida_funcs"].get_func = lambda ea: None
    sys.modules["idc"].next_head = lambda ea, end: ea + 1
    sys.modules["idc"].prev_head = lambda end, start: end - 1
    sys.modules["idc"].print_insn_mnem = lambda ea: "ret"
    sys.modules["idc"].get_func_name = lambda ea: ""
    _register_fake_gdl([_FakeBlock(0x80000000), _FakeBlock(0x80000010)])

    resp = mod.graph(action="cfg", addr="0x80000000")

    assert resp.get("ok") is True
    assert resp["action"] == "cfg"
    assert resp["node_count"] == 2
    assert "auto-defined" in resp.get("note", "")


def test_cfg_truncation_counts_reported():
    mod = load_tool_module("graph")
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = BADADDR
    idaapi.getseg = lambda ea: types.SimpleNamespace(
        start_ea=0x80000000, end_ea=0x80001000
    )
    sys.modules["ida_funcs"].get_func = lambda ea: None
    sys.modules["idc"].next_head = lambda ea, end: ea + 1
    sys.modules["idc"].prev_head = lambda end, start: end - 1
    sys.modules["idc"].print_insn_mnem = lambda ea: ""
    sys.modules["idc"].get_func_name = lambda ea: ""
    b0, b1, b2 = _FakeBlock(0x80000000), _FakeBlock(0x80000010), _FakeBlock(0x80000020)
    b0._succs, b1._succs = [b1], [b2]
    _register_fake_gdl([b0, b1, b2])

    resp = mod.graph(action="cfg", addr="0x80000000", max_items=1)

    assert resp.get("ok") is True
    assert resp["nodes_before_truncation"] == 3
    assert resp["node_count"] == 1
    assert resp["edges_before_truncation"] == 2
    assert resp["edge_count"] == 0
    assert resp["truncated"] is True


def test_compute_idoms_lt_diamond():
    # Near-linear Lengauer-Tarjan must not be the O(n^3) fixpoint and must
    # give the classic diamond answer: entry is the idom of the join point.
    mod = load_tool_module("graph")
    entry = 0x10
    succ = {0x10: [0x20, 0x30], 0x20: [0x40], 0x30: [0x40], 0x40: [0x50], 0x50: []}
    pred = {0x20: [0x10], 0x30: [0x10], 0x40: [0x20, 0x30], 0x50: [0x40]}

    idoms = mod._compute_idoms_lt(entry, succ, pred, list(succ.keys()))

    assert idoms[0x10] is None
    assert idoms[0x20] == 0x10
    assert idoms[0x30] == 0x10
    assert idoms[0x40] == 0x10
    assert idoms[0x50] == 0x40


def test_compute_idoms_lt_loop():
    mod = load_tool_module("graph")
    entry = 0x10
    succ = {0x10: [0x20], 0x20: [0x30, 0x40], 0x30: [0x20], 0x40: []}
    pred = {0x20: [0x10, 0x30], 0x30: [0x20], 0x40: [0x20]}

    idoms = mod._compute_idoms_lt(entry, succ, pred, list(succ.keys()))

    assert idoms[0x10] is None
    assert idoms[0x20] == 0x10
    assert idoms[0x30] == 0x20
    assert idoms[0x40] == 0x20


def test_immediate_dominators_falls_back_to_lt_when_calc_idom_missing():
    mod = load_tool_module("graph")
    ida_gdl = _register_fake_gdl([])
    assert not hasattr(ida_gdl, "calc_idom")  # forces the pure-Python path
    b_entry, b_a, b_b, b_c, b_d = (
        _FakeBlock(0x10), _FakeBlock(0x20), _FakeBlock(0x30),
        _FakeBlock(0x40), _FakeBlock(0x50),
    )
    b_entry._succs, b_a._succs, b_b._succs, b_c._succs = [b_a, b_b], [b_c], [b_c], [b_d]
    blocks = [b_entry, b_a, b_b, b_c, b_d]

    idoms = mod._immediate_dominators(ida_gdl, None, blocks)

    assert idoms[0x10] is None
    assert idoms[0x20] == 0x10
    assert idoms[0x30] == 0x10
    assert idoms[0x40] == 0x10
    assert idoms[0x50] == 0x40


def test_dominators_raw_blob_fallback_note_and_truncation_counts():
    mod = load_tool_module("graph")
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = BADADDR
    idaapi.getseg = lambda ea: types.SimpleNamespace(
        start_ea=0x80000000, end_ea=0x80001000
    )
    sys.modules["ida_funcs"].get_func = lambda ea: None
    sys.modules["idc"].get_func_name = lambda ea: ""
    b0, b1, b2 = _FakeBlock(0x80000000), _FakeBlock(0x80000010), _FakeBlock(0x80000020)
    b0._succs, b1._succs = [b1], [b2]
    _register_fake_gdl([b0, b1, b2])

    resp = mod.graph(action="dominators", addr="0x80000000", max_items=2)

    assert resp.get("ok") is True
    assert resp["action"] == "dominators"
    assert "auto-defined" in resp.get("note", "")
    assert resp["nodes_before_truncation"] == 3
    assert resp["count"] == 2
    assert resp["truncated"] is True
    assert len(resp["dominators"]) == 2
