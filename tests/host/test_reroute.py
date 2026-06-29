"""Tests for the silent-action reroute layer in `auto_nudge.get_reroute`.

The reroute layer exists to translate common LLM-tool-call mistakes
(action name typo, tool-alias confusion) into a working call without
the caller noticing.

Bug class caught by these tests: legacy actions that were advertised on
`graph` historically but live on `xref_analysis` in the current IDA
runtime. Without the reroute, the IDA-side Literal validator rejects
`graph(action='hub_functions')` with `-32602 Invalid params`.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
from ida_pro_mcp.host.auto_nudge import (  # noqa: E402
    _REROUTE_MAP,
    get_reroute,
)


def test_graph_legacy_actions_reroute_to_xref_analysis():
    """All historical graph sub-actions must reroute to xref_analysis."""
    legacy_actions = [
        "call_chain", "common_callers", "common_callees",
        "hub_functions", "leaf_functions", "recursive",
        "dominator", "influence", "dependency_graph", "dead_functions",
    ]
    for action in legacy_actions:
        result = get_reroute("graph", action, {"addr": "0x1000", "limit": 10})
        assert result is not None, f"graph({action}) should reroute"
        new_tool, new_args = result
        assert new_tool == "xref_analysis", f"graph({action}) must route to xref_analysis, got {new_tool}"
        assert new_args.get("action") == action, "action must be preserved"
        assert new_args.get("addr") == "0x1000", "args must pass through"


def test_graph_native_actions_do_not_reroute():
    """Actions that `graph` accepts natively must NOT reroute."""
    native_actions = ["callgraph", "cfg", "dominators", "xref_graph"]
    for action in native_actions:
        result = get_reroute("graph", action, {"addr": "0x1000"})
        assert result is None, f"graph({action}) should not reroute; got {result}"


def test_search_reroutes_preserved():
    """Existing renames kept after adding graph rewrites."""
    assert get_reroute("search", "bytes", {}) == ("search", {"action": "string"})
    assert get_reroute("search", "text", {}) == ("search", {"action": "name"})
    assert get_reroute("search", "instruction", {}) == ("search", {"action": "insns"})


def test_compare_self_compare_reroutes():
    assert get_reroute("compare", "compare", {}) == ("compare", {"action": "functions"})


def test_no_reroute_default():
    """Unknown tool/action combinations must return None silently."""
    assert get_reroute("funcs", "info", {"addr": "0x1000"}) is None
    assert get_reroute("data", "functions", {}) is None


def test_reroute_map_keys_are_complete():
    """Every key in the legacy graph set must be in the reroute map."""
    needed = {
        "call_chain", "common_callers", "common_callees",
        "hub_functions", "leaf_functions", "recursive",
        "dominator", "influence", "dependency_graph", "dead_functions",
    }
    in_map = {a for (t, a) in _REROUTE_MAP if t == "graph"} - {"bytes", "text", "instruction", "compare"}
    missing = needed - in_map
    assert not missing, f"Missing graph reroutes: {missing}"
