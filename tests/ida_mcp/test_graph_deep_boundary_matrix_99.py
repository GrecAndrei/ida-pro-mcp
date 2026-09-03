"""Deep offline coverage for graph traversal, CFG, and xref modes."""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import load_tool_module


class _Block:
    def __init__(self, start, end=None, succs=()):
        self.start_ea = start
        self.end_ea = end if end is not None else start + 4
        self._succs = list(succs)

    def succs(self):
        return list(self._succs)


def test_code_items_swallows_flag_errors_and_stops_at_badaddr():
    graph = load_tool_module("graph")
    graph.idaapi.BADADDR = -1
    graph._compat.get_func_start = lambda _ea: None
    graph._compat.get_segment = lambda _ea: types.SimpleNamespace(end_ea=0x20)
    graph.ida_bytes.get_flags = lambda _ea: (_ for _ in ()).throw(RuntimeError("flags"))
    graph.idc.next_head = lambda _ea, _end: -1

    assert graph._code_items(0x10) == []


def test_idom_fallback_handles_empty_and_unreachable_predecessors():
    graph = load_tool_module("graph")
    assert graph._compute_idoms_lt(1, {}, {}, []) == {}
    succ = {1: [2], 2: []}
    pred = {2: [1, 9999]}

    assert graph._compute_idoms_lt(1, succ, pred, [1, 2, 9999]) == {
        1: None,
        2: 1,
        9999: None,
    }


def test_callgraph_follows_real_functions_marks_cycles_and_respects_limits():
    graph = load_tool_module("graph")
    graph.idaapi.BADADDR = -1
    graph.idaapi.fl_CN = 1
    graph.idaapi.fl_CF = 2
    funcs = {0x1000: 0x1000, 0x2000: 0x2000}

    def get_func_start(ea):
        return funcs.get(ea)

    graph._compat.get_func_start = get_func_start
    graph.idc.get_func_name = lambda ea: {0x1000: "root", 0x2000: "child"}.get(ea, "")
    graph._code_items = lambda ea: [ea + 4]

    def xrefs(item):
        if item == 0x1004:
            return [
                types.SimpleNamespace(iscode=False, type=1, to=0x9999),
                types.SimpleNamespace(iscode=True, type=99, to=0x9999),
                types.SimpleNamespace(iscode=True, type=1, to=0x1000),
                types.SimpleNamespace(iscode=True, type=1, to=0x2000),
            ]
        if item == 0x2004:
            return [types.SimpleNamespace(iscode=True, type=1, to=0x1000)]
        return []

    graph.idautils.XrefsFrom = xrefs
    result = graph.graph(action="callgraph", addr="0x1000", format="mermaid")

    assert result["ok"] is True
    assert result["function_less_targets"] == 0
    assert result["node_count"] == 2
    assert "classDef cycle" in result["graph"]

    limited = graph.graph(action="callgraph", addr="0x1000", max_items=1)
    assert limited["ok"] is True
    assert limited["node_count"] == 1

    shallow = graph.graph(action="callgraph", addr="0x1000", depth=0)
    assert shallow["ok"] is True
    assert shallow["node_count"] == 2

    edge_limited = graph.graph(action="callgraph", addr="0x1000", max_items=2)
    assert edge_limited["ok"] is True
    assert edge_limited["node_count"] == 2


def test_cfg_function_path_marks_call_blocks_and_branch_edges():
    graph = load_tool_module("graph")
    graph.idaapi.BADADDR = -1
    func = types.SimpleNamespace(start_ea=0x1000)
    left = _Block(0x1000, 0x1004)
    right = _Block(0x1004, 0x1008)
    entry = _Block(0x2000, 0x2004, [left, right])
    graph._compat.get_func_info = lambda _ea: func
    graph._compat.get_flow_chart = lambda _ea: [entry, left, right]
    graph.idc.get_func_name = lambda _ea: "entry"
    graph.idc.next_head = lambda ea, end: ea + 2 if ea + 2 < end else -1
    graph.idc.prev_head = lambda end, _start: end - 1
    graph.idc.print_insn_mnem = lambda _ea: "call"

    result = graph.graph(action="cfg", addr="0x1000")

    assert result["ok"] is True
    assert result["adjacency"]["nodes"][0]["type"] == "call"
    assert result["adjacency"]["edges"][0]["type"] == "branch"

    entry._succs = [entry, entry]
    edge_limited = graph.graph(action="cfg", addr="0x1000", max_items=1)
    assert edge_limited["ok"] is True
    assert edge_limited["edge_count"] == 1


def test_dominators_empty_raw_chart_returns_placeholder_note():
    graph = load_tool_module("graph")
    graph.idaapi.BADADDR = -1
    graph._compat.get_func_info = lambda _ea: None
    graph._build_range_chart = lambda _gdl, _ea: []
    sys.modules["ida_gdl"] = types.ModuleType("ida_gdl")

    result = graph.graph(action="dominators", addr="0x1000")

    assert result == {
        "ok": True,
        "action": "dominators",
        "dominators": [],
        "note": graph._raw_blob_note(),
    }


def test_xref_graph_traverses_callers_callees_and_functionless_targets():
    graph = load_tool_module("graph")
    graph.idaapi.BADADDR = -1
    funcs = {0x1000: 0x1000, 0x2004: 0x2000}

    def get_func_start(ea):
        return funcs.get(ea)

    graph._compat.get_func_start = get_func_start
    graph.idc.get_name = lambda ea: {0x1000: "root", 0x2000: "caller"}.get(ea, "")
    graph.idautils.XrefsTo = lambda ea: (
        [types.SimpleNamespace(iscode=True, frm=0x2004, to=ea)]
        if ea == 0x1000
        else []
    )
    graph.idautils.FuncItems = lambda _ea: [0x1004]
    graph.idautils.XrefsFrom = lambda _item, _flags=0: [
        types.SimpleNamespace(iscode=False, to=0x9999),
        types.SimpleNamespace(iscode=True, to=0x3000),
    ]

    result = graph.graph(action="xref_graph", addr="0x1000", direction="both")

    assert result["ok"] is True
    assert result["node_count"] == 3
    assert {edge["to"] for edge in result["edges"]} >= {"0x1000", "0x3000"}

    up_only = graph.graph(action="xref_graph", addr="0x1000", direction="up")
    assert up_only["ok"] is True
    assert up_only["edge_count"] == 1


def test_format_graph_ignores_cycle_markers_for_missing_nodes():
    graph = load_tool_module("graph")
    result = graph._format_graph({1: "one"}, [], "mermaid", cycle_nodes={99})

    assert result["ok"] is True
    assert "classDef cycle" in result["graph"]
    assert "N_63_" not in result["graph"]


def test_graph_actions_validate_missing_and_bad_addresses():
    graph = load_tool_module("graph")
    graph.idaapi.BADADDR = -1
    graph.validate_addr = lambda _addr: (None, {"error": True, "code": "BAD"})

    for action in ("callgraph", "cfg", "dominators", "xref_graph"):
        assert graph.graph(action=action, addr=None)["error"] is True
        assert graph.graph(action=action, addr="bad")["error"] is True


def test_graph_top_level_exception_is_returned_as_error():
    graph = load_tool_module("graph")

    def fail(_ea):
        raise RuntimeError("compat failure")

    graph._compat.get_func_start = fail
    result = graph.graph(action="callgraph", addr="0x10")

    assert result["ok"] is False
    assert result["error"] == "compat failure"
