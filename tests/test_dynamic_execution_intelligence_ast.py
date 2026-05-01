#!/usr/bin/env python3
"""
AST-level regression tests for dynamic execution intelligence actions.
"""

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRACE_ANALYSIS_PATH = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "trace_analysis.py"
HOST_PATH = ROOT / "src" / "ida_pro_mcp" / "host" / "schemas.py"


def _find_fn(module, name):
    return next((n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == name), None)


NEW_ACTIONS = {
    "execution_timeline_graph",
    "cross_run_diff",
    "runtime_taint_overlay",
    "state_replay",
    "path_unlock",
    "coverage_debug_plan",
    "exploitability_score",
    "anti_analysis_detect",
    "lifetime_map",
    "hybrid_callgraph_confidence",
}


class TestTraceAnalysisDynamicIntelAst(unittest.TestCase):
    def setUp(self):
        self.source = TRACE_ANALYSIS_PATH.read_text(encoding="utf-8")
        self.module = ast.parse(self.source)

    def test_trace_analysis_action_literal_includes_dynamic_intel_actions(self):
        fn = _find_fn(self.module, "trace_analysis")
        self.assertIsNotNone(fn)
        action_arg = next((a for a in fn.args.args if a.arg == "action"), None)
        self.assertIsNotNone(action_arg)
        ann = action_arg.annotation
        self.assertIsInstance(ann, ast.Subscript)
        literal = ann.slice.elts[0]
        values = [e.value for e in literal.slice.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        for action in NEW_ACTIONS:
            self.assertIn(action, values)

    def test_trace_analysis_has_action_branches(self):
        for action in NEW_ACTIONS:
            self.assertIn(f'elif action == "{action}":', self.source)

    def test_cross_run_diff_normalizes_inline_trace_lists(self):
        self.assertIn("raw_trace_a = kwargs.get(\"trace_a\")", self.source)
        self.assertIn("raw_trace_b = kwargs.get(\"trace_b\")", self.source)
        self.assertIn("_parse_addrs(raw_trace_a)", self.source)
        self.assertIn("_parse_addrs(raw_trace_b)", self.source)


class TestHostToolActionsDynamicIntel(unittest.TestCase):
    def test_tool_actions_trace_analysis_contains_dynamic_intel_actions(self):
        source = HOST_PATH.read_text(encoding="utf-8")
        module = ast.parse(source)
        tool_actions = None
        for node in module.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "TOOL_ACTIONS":
                        tool_actions = node.value
                        break
                if tool_actions is not None:
                    break
        self.assertIsNotNone(tool_actions)
        self.assertIsInstance(tool_actions, ast.Dict)

        keys = tool_actions.keys
        values = tool_actions.values
        trace_actions = None
        for k, v in zip(keys, values):
            if isinstance(k, ast.Constant) and k.value == "trace_analysis":
                trace_actions = v
                break
        self.assertIsNotNone(trace_actions)
        self.assertIsInstance(trace_actions, ast.List)
        action_values = {elt.value for elt in trace_actions.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)}
        for action in NEW_ACTIONS:
            self.assertIn(action, action_values)


if __name__ == "__main__":
    unittest.main()
