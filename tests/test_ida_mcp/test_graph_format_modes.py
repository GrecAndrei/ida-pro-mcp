"""Exercise graph output formats and IDA adapter fallback modes."""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import load_tool_module


def test_graph_formats_escape_labels_and_mark_cycles():
    graph = load_tool_module("graph")
    nodes = {0x10: 'root"\\line', 0x20: "child"}
    edges = [(0x10, 0x20), (0x20, 0x10)]
    mermaid = graph._format_graph(nodes, edges, "mermaid", cycle_nodes={0x10})
    assert mermaid["ok"] is True
    assert "classDef cycle" in mermaid["graph"]
    assert '\\"' in mermaid["graph"]
    dot = graph._format_graph(nodes, edges, "dot")
    assert dot["graph"].startswith("digraph G {")
    assert "rankdir=TB" in dot["graph"]
    json_graph = graph._format_graph(nodes, edges, "json", cycle_nodes={0x20})
    assert json_graph["nodes"][1]["cycle"] is True
    assert json_graph["edges"][0] == {"from": "0x10", "to": "0x20"}


def test_graph_range_chart_and_idom_adapter_fallbacks(monkeypatch):
    graph = load_tool_module("graph")
    graph._compat.get_segment = lambda _ea: types.SimpleNamespace(end_ea=0x2000)
    graph.idaapi.ea_range_t = lambda start, end: (start, end)
    ida_gdl = types.ModuleType("ida_gdl")
    calls = []

    class FlowChart:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))
            raise TypeError("constructor unavailable")

    ida_gdl.FlowChart = FlowChart
    sys.modules["ida_gdl"] = ida_gdl
    assert graph._build_range_chart(ida_gdl, 0x1000) is None
    assert len(calls) == 3
    assert calls[-1][1] == {"bounds": (0x1000, 0x2000)} or calls[-1][0] == (None, (0x1000, 0x2000))

    class Block:
        def __init__(self, ea):
            self.start_ea = ea

        def succs(self):
            return []

    blocks = [Block(0x10), Block(0x20)]
    ida_gdl.calc_idom = lambda _fc: [1, -1]
    assert graph._immediate_dominators(ida_gdl, object(), blocks) == {0x10: 0x20, 0x20: None}
    ida_gdl.calc_idom = lambda _fc: (_ for _ in ()).throw(RuntimeError("bad"))
    assert graph._immediate_dominators(ida_gdl, object(), blocks)[0x10] is None


def test_graph_action_aliases_and_invalid_input_modes(monkeypatch):
    graph = load_tool_module("graph")
    graph.idaapi.BADADDR = -1
    graph.idaapi.fl_CN = 1
    graph.idaapi.fl_CF = 2
    graph.validate_addr = lambda _addr: (0x1000, None)
    graph._compat.get_func_start = lambda _ea: 0x1000
    graph._code_items = lambda _ea: []
    graph.idc.get_func_name = lambda _ea: "entry"
    graph.idc.get_name = lambda _ea: "entry"
    for alias, expected in (("dot", "dot"), ("mermaid", "mermaid"), ("up", "json")):
        response = graph.graph(action=alias, addr="0x1000", format="json")
        assert response["ok"] is True
        assert response["format"] == expected
    assert graph.graph(action="callgraph", addr=None)["error"] is True
    assert graph.graph(action="unknown", addr="0x1000")["error"] is True
    graph.validate_addr = lambda _addr: (None, {"error": True, "code": "bad"})
    assert graph.graph(action="cfg", addr="bad")["error"] is True
