#!/usr/bin/env python3
"""
Regression tests for funcs tool sync-mode routing.
"""

import ast
import unittest
from pathlib import Path


FUNCS_TOOL_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "ida_pro_mcp"
    / "ida_mcp"
    / "tools"
    / "funcs.py"
)


def _decorator_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class TestFuncsSyncRouting(unittest.TestCase):
    def setUp(self):
        self.module = ast.parse(FUNCS_TOOL_PATH.read_text(encoding="utf-8"))

    def test_funcs_has_read_and_write_dispatch_helpers(self):
        read_fn = next(
            (n for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name == "_funcs_read_dispatch"),
            None,
        )
        write_fn = next(
            (n for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name == "_funcs_write_dispatch"),
            None,
        )
        self.assertIsNotNone(read_fn)
        self.assertIsNotNone(write_fn)
        self.assertIn("idaread", {_decorator_name(d) for d in read_fn.decorator_list})
        self.assertIn("idawrite", {_decorator_name(d) for d in write_fn.decorator_list})

    def test_funcs_routes_list_and_info_to_read_dispatch(self):
        funcs_fn = next(
            (n for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name == "funcs"),
            None,
        )
        self.assertIsNotNone(funcs_fn)
        source = ast.unparse(funcs_fn)
        self.assertIn("if normalized_action in ('list', 'info')", source)
        self.assertIn("return _funcs_read_dispatch(**call_kwargs)", source)
        self.assertIn("return _funcs_write_dispatch(**call_kwargs)", source)


if __name__ == "__main__":
    unittest.main()
