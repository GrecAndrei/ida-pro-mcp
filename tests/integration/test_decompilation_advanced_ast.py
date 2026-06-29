#!/usr/bin/env python3
"""
AST-level regression tests for advanced decompilation surfaces.
"""

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CODE_PATH = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "code.py"
CTREE_PATH = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "ctree.py"
MICROCODE_PATH = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "microcode.py"


def _find_fn(module, name):
    return next((n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == name), None)


class TestAdvancedCodeAst(unittest.TestCase):
    def setUp(self):
        self.source = CODE_PATH.read_text(encoding="utf-8")
        self.module = ast.parse(self.source)

    def test_code_action_literal_includes_new_advanced_actions(self):
        fn = _find_fn(self.module, "code")
        self.assertIsNotNone(fn)
        action_arg = next((a for a in fn.args.args if a.arg == "action"), None)
        self.assertIsNotNone(action_arg)
        ann = action_arg.annotation
        self.assertIsInstance(ann, ast.Subscript)
        literal = ann.slice.elts[0]
        values = [e.value for e in literal.slice.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        self.assertIn("semantic_decompile", values)
        self.assertIn("decomp_dataflow", values)

    def test_code_advanced_helper_functions_exist(self):
        expected = {
            "_compute_cfg_semantics",
            "_build_decompiler_dataflow",
            "_semantic_pseudocode_summary",
            "_collect_expr_rows_from_cfunc",
        }
        found = {n.name for n in self.module.body if isinstance(n, ast.FunctionDef)}
        self.assertTrue(expected.issubset(found))


class TestAdvancedCtreeAndMicrocodeAst(unittest.TestCase):
    def test_ctree_new_actions_and_helpers_exist(self):
        source = CTREE_PATH.read_text(encoding="utf-8")
        module = ast.parse(source)
        fn = _find_fn(module, "ctree")
        self.assertIsNotNone(fn)
        action_arg = next((a for a in fn.args.args if a.arg == "action"), None)
        self.assertIsNotNone(action_arg)
        literal = action_arg.annotation.slice.elts[0]
        values = [e.value for e in literal.slice.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        self.assertIn("dominance_map", values)
        self.assertIn("var_dependency_graph", values)
        self.assertIn("elif action == \"dominance_map\":", source)
        self.assertIn("elif action == \"var_dependency_graph\":", source)
        for helper in (
            "_ctree_build_dominance_map",
            "_ctree_build_var_dependency_graph",
            "_ctree_collect_expr_rows",
        ):
            self.assertIn(f"def {helper}(", source)

    def test_microcode_new_action_and_helper_exist(self):
        source = MICROCODE_PATH.read_text(encoding="utf-8")
        module = ast.parse(source)
        fn = _find_fn(module, "microcode")
        self.assertIsNotNone(fn)
        action_arg = next((a for a in fn.args.args if a.arg == "action"), None)
        self.assertIsNotNone(action_arg)
        literal = action_arg.annotation.slice.elts[0]
        values = [e.value for e in literal.slice.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        self.assertIn("def_use_graph", values)
        self.assertIn("elif action == \"def_use_graph\":", source)
        self.assertIn("def _microcode_def_use_graph(", source)


if __name__ == "__main__":
    unittest.main()
