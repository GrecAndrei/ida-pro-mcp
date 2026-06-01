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

    def test_funcs_no_longer_has_read_and_write_dispatch_helpers(self):
        """Step 7: the read/write dispatch helpers were removed; the
        `funcs` tool now calls `_funcs_impl` directly."""
        names = {
            n.name
            for n in self.module.body
            if isinstance(n, ast.FunctionDef)
        }
        self.assertNotIn("_funcs_read_dispatch", names)
        self.assertNotIn("_funcs_write_dispatch", names)
        # And `_funcs_impl` is still the implementation backbone.
        self.assertIn("_funcs_impl", names)

    def test_funcs_calls_impl_directly(self):
        """The `funcs` tool body ends with a single direct call to
        `_funcs_impl`, with no read/write routing."""
        funcs_fn = next(
            (n for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name == "funcs"),
            None,
        )
        self.assertIsNotNone(funcs_fn)
        decorators = {_decorator_name(d) for d in funcs_fn.decorator_list}
        self.assertIn("tool", decorators)
        # The trailing return is a direct call to _funcs_impl.
        trailing = funcs_fn.body[-1]
        self.assertIsInstance(trailing, ast.Return)
        self.assertIsInstance(trailing.value, ast.Call)
        self.assertIsInstance(trailing.value.func, ast.Name)
        self.assertEqual(trailing.value.func.id, "_funcs_impl")
        # No `if normalized_action in (...)` routing remains.
        for n in funcs_fn.body:
            self.assertFalse(
                isinstance(n, ast.If)
                and isinstance(n.test, ast.Compare)
                and isinstance(n.test.left, ast.Name)
                and n.test.left.id == "normalized_action",
                "funcs() still has a normalized_action routing block",
            )


if __name__ == "__main__":
    unittest.main()
